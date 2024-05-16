local cjson = require("cjson.safe")

local io = io
local tostring = tostring
local string = string
local table = table
local pairs = pairs

-- this is the Lua representation of Configuration struct in internal/ingress/types.go
local configuration_data = njt.shared.configuration_data
local certificate_data = njt.shared.certificate_data
local certificate_servers = njt.shared.certificate_servers
local ocsp_response_cache = njt.shared.ocsp_response_cache

local EMPTY_UID = "-1"

local _M = {}

function _M.get_backends_data()
  return configuration_data:get("backends")
end

function _M.get_general_data()
  return configuration_data:get("general")
end

function _M.get_raw_backends_last_synced_at()
  local raw_backends_last_synced_at = configuration_data:get("raw_backends_last_synced_at")
  if raw_backends_last_synced_at == nil then
    raw_backends_last_synced_at = 1
  end
  return raw_backends_last_synced_at
end

local function fetch_request_body()
  njt.req.read_body()
  local body = njt.req.get_body_data()
  print("liuqi request body:", body)
  njt.log(njt.DEBUG, "---liuqi request body:", body)

  if not body then
    -- request body might've been written to tmp file if body > client_body_buffer_size
    local file_name = njt.req.get_body_file()
    local file = io.open(file_name, "rb")

    if not file then
      return nil
    end

    body = file:read("*all")
    file:close()
  end

  return body
end

local function get_pem_cert(hostname)
  local uid = certificate_servers:get(hostname)
  if not uid then
    return nil
  end

  return certificate_data:get(uid)
end

local function handle_servers()
  if njt.var.request_method ~= "POST" then
    njt.status = njt.HTTP_BAD_REQUEST
    njt.print("Only POST requests are allowed!")
    return
  end

  njt.log(njt.DEBUG, "----------------------------------fetch_request_body start")
  local raw_configuration = fetch_request_body()
  njt.log(njt.DEBUG, "raw_configuration:", raw_configuration)

  local configuration, err = cjson.decode(raw_configuration)
  njt.log(njt.DEBUG, "cjson.decode(raw_configuration):", configuration)
  if not configuration then
    njt.log(njt.ERR, "could not parse configuration: ", err)
    njt.status = njt.HTTP_BAD_REQUEST
    return
  end

  local err_buf = {}

  for server, uid in pairs(configuration.servers) do
    if uid == EMPTY_UID then
      -- notice that we do not delete certificate corresponding to this server
      -- this is because a certificate can be used by multiple servers/hostnames
      certificate_servers:delete(server)
    else
      local success, set_err, forcible = certificate_servers:set(server, uid)
      if not success then
        local err_msg = string.format("error setting certificate for %s: %s\n",
          server, tostring(set_err))
        table.insert(err_buf, err_msg)
      end
      if forcible then
        local msg = string.format("certificate_servers dictionary is full, "
          .. "LRU entry has been removed to store %s", server)
        njt.log(njt.WARN, msg)
      end
    end
  end

  for uid, cert in pairs(configuration.certificates) do
    -- don't delete the cache here, certificate_data[uid] is not replaced yet.
    -- there is small chance that nginx worker still get the old certificate,
    -- then fetch and cache the old OCSP Response
    local old_cert = certificate_data:get(uid)
    local is_renew = (old_cert ~= nil and old_cert ~= cert)

    local success, set_err, forcible = certificate_data:set(uid, cert)
    if success then
        -- delete ocsp cache after certificate_data:set succeed
        if is_renew then
            ocsp_response_cache:delete(uid)
        end
    else
      local err_msg = string.format("error setting certificate for %s: %s\n",
        uid, tostring(set_err))
      table.insert(err_buf, err_msg)
    end
    if forcible then
      local msg = string.format("certificate_data dictionary is full, "
        .. "LRU entry has been removed to store %s", uid)
      njt.log(njt.WARN, msg)
    end
  end

  if #err_buf > 0 then
    njt.log(njt.ERR, table.concat(err_buf))
    njt.status = njt.HTTP_INTERNAL_SERVER_ERROR
    return
  end

  njt.status = njt.HTTP_CREATED
end

local function handle_general()
  if njt.var.request_method == "GET" then
    njt.status = njt.HTTP_OK
    njt.print(_M.get_general_data())
    return
  end

  if njt.var.request_method ~= "POST" then
    njt.status = njt.HTTP_BAD_REQUEST
    njt.print("Only POST and GET requests are allowed!")
    return
  end

  local config = fetch_request_body()

  local success, err = configuration_data:safe_set("general", config)
  if not success then
    njt.status = njt.HTTP_INTERNAL_SERVER_ERROR
    njt.log(njt.ERR, "error setting general config: " .. tostring(err))
    return
  end

  njt.status = njt.HTTP_CREATED
end

local function handle_certs()
  if njt.var.request_method ~= "GET" then
    njt.status = njt.HTTP_BAD_REQUEST
    njt.print("Only GET requests are allowed!")
    return
  end

  local query = njt.req.get_uri_args()
  if not query["hostname"] then
    njt.status = njt.HTTP_BAD_REQUEST
    njt.print("Hostname must be specified.")
    return
  end

  local key = get_pem_cert(query["hostname"])
  if key then
    njt.status = njt.HTTP_OK
    njt.print(key)
    return
  else
    njt.status = njt.HTTP_NOT_FOUND
    njt.print("No key associated with this hostname.")
    return
  end
end


local function handle_backends()
  if njt.var.request_method == "GET" then
    njt.status = njt.HTTP_OK
    njt.print(_M.get_backends_data())
    return
  end

  local backends = fetch_request_body()
  if not backends then
    njt.log(njt.ERR, "dynamic-configuration: unable to read valid request body")
    njt.status = njt.HTTP_BAD_REQUEST
    return
  end

  local success, err = configuration_data:set("backends", backends)
  if not success then
    njt.log(njt.ERR, "dynamic-configuration: error updating configuration: " .. tostring(err))
    njt.status = njt.HTTP_BAD_REQUEST
    return
  end
  -- keep original backends configuration for health check purpose
  local success, err = configuration_data:set("hc_backends", backends)
  if not success then
    njt.log(njt.ERR, "dynamic-configuration: error updating configuration: " .. tostring(err))
    njt.status = njt.HTTP_BAD_REQUEST
    return
  end

  njt.update_time()
  local raw_backends_last_synced_at = njt.now()
  success, err = configuration_data:set("raw_backends_last_synced_at", raw_backends_last_synced_at)
  if not success then
    njt.log(njt.ERR, "dynamic-configuration: error updating when backends sync, " ..
                     "new upstream peers waiting for force syncing: " .. tostring(err))
    njt.status = njt.HTTP_BAD_REQUEST
    return
  end
  success, err = configuration_data:set("raw_hc_backends_last_synced_at", raw_backends_last_synced_at)
  if not success then
    njt.log(njt.ERR, "dynamic-configuration: error updating when backends sync, " ..
                     "new upstream peers waiting for force syncing: " .. tostring(err))
    njt.status = njt.HTTP_BAD_REQUEST
    return
  end

  njt.status = njt.HTTP_CREATED
end

function _M.call()
  if njt.var.request_method ~= "POST" and njt.var.request_method ~= "GET" then
    njt.status = njt.HTTP_BAD_REQUEST
    njt.print("Only POST and GET requests are allowed!")
    return
  end

  if njt.var.request_uri == "/configuration/servers" then
    handle_servers()
    return
  end

  if njt.var.request_uri == "/configuration/general" then
    handle_general()
    return
  end

  if njt.var.uri == "/configuration/certs" then
    handle_certs()
    return
  end

  if njt.var.request_uri == "/configuration/backends" then
    handle_backends()
    return
  end

  njt.status = njt.HTTP_NOT_FOUND
  njt.print("Not found!")
end

setmetatable(_M, {__index = { handle_servers = handle_servers }})

return _M
