local njt_balancer = require("njt.balancer")
local cjson = require("cjson.safe")
local util = require("util")
local dns_lookup = require("util.dns").lookup
local configuration = require("configuration")
local round_robin = require("balancer.round_robin")
local chash = require("balancer.chash")
local chashsubset = require("balancer.chashsubset")
local sticky_balanced = require("balancer.sticky_balanced")
local sticky_persistent = require("balancer.sticky_persistent")
local string = string
local ipairs = ipairs
local table = table
local getmetatable = getmetatable
local tostring = tostring
local pairs = pairs
local math = math

-- measured in seconds
-- for an Nginx worker to pick up the new list of upstream peers
-- it will take <the delay until controller POSTed the backend object to the
-- Nginx endpoint> + BACKENDS_SYNC_INTERVAL
local BACKENDS_SYNC_INTERVAL = 1

local DEFAULT_LB_ALG = "round_robin"
local IMPLEMENTATIONS = {
  round_robin = round_robin,
  chash = chash,
  chashsubset = chashsubset,
  sticky_balanced = sticky_balanced,
  sticky_persistent = sticky_persistent,
}

local PROHIBITED_LOCALHOST_PORT = configuration.prohibited_localhost_port or '10246'
local PROHIBITED_PEER_PATTERN = "^127.*:" .. PROHIBITED_LOCALHOST_PORT .. "$"

local _M = {}
local balancers = {}
local backends_with_external_name = {}
local backends_last_synced_at = 0

local function get_implementation(backend)
  local name = backend["load-balance"] or DEFAULT_LB_ALG

  if backend["sessionAffinityConfig"] and
     backend["sessionAffinityConfig"]["name"] == "cookie" then
    if backend["sessionAffinityConfig"]["mode"] == "persistent" then
      name = "sticky_persistent"
    else
      name = "sticky_balanced"
    end

  elseif backend["upstreamHashByConfig"] and
         backend["upstreamHashByConfig"]["upstream-hash-by"] then
    if backend["upstreamHashByConfig"]["upstream-hash-by-subset"] then
      name = "chashsubset"
    else
      name = "chash"
    end
  end

  local implementation = IMPLEMENTATIONS[name]
  if not implementation then
    njt.log(njt.WARN, backend["load-balance"], "is not supported, ",
            "falling back to ", DEFAULT_LB_ALG)
    implementation = IMPLEMENTATIONS[DEFAULT_LB_ALG]
  end

  return implementation
end

local function resolve_external_names(original_backend)
  local backend = util.deepcopy(original_backend)
  local endpoints = {}
  for _, endpoint in ipairs(backend.endpoints) do
    local ips = dns_lookup(endpoint.address)
    for _, ip in ipairs(ips) do
      table.insert(endpoints, { address = ip, port = endpoint.port })
    end
  end
  backend.endpoints = endpoints
  return backend
end

local function format_ipv6_endpoints(endpoints)
  local formatted_endpoints = {}
  for _, endpoint in ipairs(endpoints) do
    local formatted_endpoint = endpoint
    if not endpoint.address:match("^%d+.%d+.%d+.%d+$") then
      formatted_endpoint.address = string.format("[%s]", endpoint.address)
    end
    table.insert(formatted_endpoints, formatted_endpoint)
  end
  return formatted_endpoints
end

local function is_backend_with_external_name(backend)
  local serv_type = backend.service and backend.service.spec
                      and backend.service.spec["type"]
  return serv_type == "ExternalName"
end

local function sync_backend(backend)
  if not backend.endpoints or #backend.endpoints == 0 then
    balancers[backend.name] = nil
    return
  end

  if is_backend_with_external_name(backend) then
    backend = resolve_external_names(backend)
  end

  backend.endpoints = format_ipv6_endpoints(backend.endpoints)

  local implementation = get_implementation(backend)
  local balancer = balancers[backend.name]

  if not balancer then
    balancers[backend.name] = implementation:new(backend)
    return
  end

  -- every implementation is the metatable of its instances (see .new(...) functions)
  -- here we check if `balancer` is the instance of `implementation`
  -- if it is not then we deduce LB algorithm has changed for the backend
  if getmetatable(balancer) ~= implementation then
    njt.log(njt.INFO,
        string.format("LB algorithm changed from %s to %s, resetting the instance",
                      balancer.name, implementation.name))
    balancers[backend.name] = implementation:new(backend)
    return
  end

  if balancer.name == "chash" and balancer.hash_by_key ~= backend["upstreamHashByConfig"]["upstream-hash-by"] then 
    njt.log(njt.NOTICE, "chash key changes, resetting the instance")
    balancers[backend.name] = implementation:new(backend)
    return
  end 

  balancer:sync(backend)
end

local function sync_backends_with_external_name()
  for _, backend_with_external_name in pairs(backends_with_external_name) do
    sync_backend(backend_with_external_name)
  end
end

local function sync_backends()
  njt.log(njt.DEBUG, "start sync_backends...")
  local raw_backends_last_synced_at = configuration.get_raw_backends_last_synced_at()
  if raw_backends_last_synced_at <= backends_last_synced_at then
    return
  end

  local backends_data = configuration.get_backends_data()
  njt.log(njt.DEBUG, "get_backends_data:", backends_data)
  if not backends_data then
    balancers = {}
    njt.log(njt.DEBUG, "backends_data is nil")
    return
  end

  local new_backends, err = cjson.decode(backends_data)
  if not new_backends then
    njt.log(njt.ERR, "could not parse backends data: ", err)
    return
  end

  local balancers_to_keep = {}
  for _, new_backend in ipairs(new_backends) do
    njt.log(njt.DEBUG, "new_backend:",cjson.encode(new_backend))
    --njt.log(njt.DEBUG, "new_backend:", tostring(new_backend))
    if is_backend_with_external_name(new_backend) then
      local backend_with_external_name = util.deepcopy(new_backend)
      backends_with_external_name[backend_with_external_name.name] = backend_with_external_name
    else
      sync_backend(new_backend)
    end
    balancers_to_keep[new_backend.name] = true
  end

  for backend_name, _ in pairs(balancers) do
    if not balancers_to_keep[backend_name] then
      balancers[backend_name] = nil
      backends_with_external_name[backend_name] = nil
    end
  end
  backends_last_synced_at = raw_backends_last_synced_at
end

local function route_to_alternative_balancer(balancer)
  njt.log(njt.DEBUG,"call route_to_alternative_balancer function...")
  if balancer.is_affinitized(balancer) then
    njt.log(njt.DEBUG,"balancer.is_affinitized:", balancer.is_affinitized(balancer))
    -- If request is already affinitized to a primary balancer, keep the primary balancer.
    return false
  end

  if not balancer.alternative_backends then
    njt.log(njt.DEBUG,"alternative_backends:", balancer.alternative_backends)
    return false
  end

  -- TODO: support traffic shaping for n > 1 alternative backends
  local backend_name = balancer.alternative_backends[1]
  if not backend_name then
    njt.log(njt.ERR, "empty alternative backend")
    return false
  end
  njt.log(njt.INFO,"alternative backend name:", backend_name)

  local alternative_balancer = balancers[backend_name]
  if not alternative_balancer then
    njt.log(njt.ERR, "no alternative balancer for backend: ",
            tostring(backend_name))
    return false
  end

  njt.log(njt.INFO,"alternative_balancer:", cjson.encode(alternative_balancer))
  if alternative_balancer.is_affinitized(alternative_balancer) then
    njt.log(njt.INFO,"alternative_balancer.is_affinitized:", alternative_balancer.is_affinitized(alternative_balancer))
    -- If request is affinitized to an alternative balancer, instruct caller to
    -- switch to alternative.
    return true
  end

  -- Use traffic shaping policy, if request didn't have affinity set.
  local traffic_shaping_policy =  alternative_balancer.traffic_shaping_policy
  if not traffic_shaping_policy then
    njt.log(njt.ERR, "traffic shaping policy is not set for balancer ",
            "of backend: ", tostring(backend_name))
    return false
  end

  local flag = false
  for _, header_pairs in ipairs(traffic_shaping_policy.headers) do
    local target_header = util.replace_special_char(header_pairs.header,
                                                      "-", "_")
      local header = njt.var["http_" .. target_header]
      njt.log(njt.INFO,"header:", header)
      if header then
        if header_pairs.headerValue
    	   and #header_pairs.headerValue > 0 then
    	  njt.log(njt.INFO,"header_pairs.headerValue:", header_pairs.headerValue)
          if header_pairs.headerValue == header then
            flag = true
          else
            flag = false
            return flag
          end
        end
      end
  end

  if flag then
    njt.log(njt.INFO,"flag:", flag)
    return flag
  end

  local target_cookie = traffic_shaping_policy.cookie
  local cookie = njt.var["cookie_" .. target_cookie]
  if cookie then
    if cookie == "always" then
      return true
    elseif cookie == "never" then
      return false
    end
  end

  local weightTotal = 100
  if traffic_shaping_policy.weightTotal ~= nil and traffic_shaping_policy.weightTotal > 100 then
    weightTotal = traffic_shaping_policy.weightTotal
  end
  if math.random(weightTotal) <= traffic_shaping_policy.weight then
    return true
  end

  return false
end

local function get_balancer_by_upstream_name(upstream_name)
  return balancers[upstream_name]
end

local function get_balancer()
  if njt.ctx.balancer then
    return njt.ctx.balancer
  end

  local backend_name = njt.var.proxy_upstream_name
  njt.log(njt.NOTICE, "proxy_upstream_name: ", backend_name)

  local balancer = balancers[backend_name]
  if not balancer then
    njt.log(njt.ERR, "proxy_upstream_name balancer nil")
    return nil
  end

  if route_to_alternative_balancer(balancer) then
    local alternative_backend_name = balancer.alternative_backends[1]
    njt.var.proxy_alternative_upstream_name = alternative_backend_name

    balancer = balancers[alternative_backend_name]
  end

  njt.ctx.balancer = balancer

  return balancer
end

function _M.init_worker()
  -- when worker starts, sync non ExternalName backends without delay
  sync_backends()
  -- we call sync_backends_with_external_name in timer because for endpoints that require
  -- DNS resolution it needs to use socket which is not available in
  -- init_worker phase
  local ok, err = njt.timer.at(0, sync_backends_with_external_name)
  if not ok then
    njt.log(njt.ERR, "failed to create timer: ", err)
  end

  ok, err = njt.timer.every(BACKENDS_SYNC_INTERVAL, sync_backends)
  if not ok then
    njt.log(njt.ERR, "error when setting up timer.every for sync_backends: ", err)
  end
  ok, err = njt.timer.every(BACKENDS_SYNC_INTERVAL, sync_backends_with_external_name)
  if not ok then
    njt.log(njt.ERR, "error when setting up timer.every for sync_backends_with_external_name: ",
            err)
  end
end

function _M.rewrite()
  local balancer = get_balancer()
  if not balancer then
    njt.status = njt.HTTP_SERVICE_UNAVAILABLE
    return njt.exit(njt.status)
  end
end

function _M.balance()
  local balancer = get_balancer()
  if not balancer then
    return
  end

  local peer = balancer:balance()
  if not peer then
    njt.log(njt.WARN, "no peer was returned, balancer: " .. balancer.name)
    return
  end

  njt.log(njt.NOTICE, "peer: ", peer)
  if peer:match(PROHIBITED_PEER_PATTERN) then
    njt.log(njt.ERR, "attempted to proxy to self, balancer: ", balancer.name, ", peer: ", peer)
    return
  end

  njt_balancer.set_more_tries(1)

  local ok, err = njt_balancer.set_current_peer(peer)
  if not ok then
    njt.log(njt.ERR, "error while setting current upstream peer ", peer,
            ": ", err)
  end
end

function _M.log()
  local balancer = get_balancer()
  if not balancer then
    return
  end

  if not balancer.after_balance then
    return
  end

  balancer:after_balance()
end

setmetatable(_M, {__index = {
  get_implementation = get_implementation,
  sync_backend = sync_backend,
  route_to_alternative_balancer = route_to_alternative_balancer,
  get_balancer = get_balancer,
  get_balancer_by_upstream_name = get_balancer_by_upstream_name,
}})

return _M
