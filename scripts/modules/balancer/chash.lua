local balancer_resty = require("balancer.resty")
local resty_chash = require("resty.chash")
local util = require("util")
local njt_log = njt.log
local njt_ERR = njt.ERR
local setmetatable = setmetatable

local _M = balancer_resty:new({ factory = resty_chash, name = "chash" })

function _M.new(self, backend)
  local nodes = util.get_nodes(backend.endpoints)
  local complex_val, err =
    util.parse_complex_value(backend["upstreamHashByConfig"]["upstream-hash-by"])
  if err ~= nil then
    njt_log(njt_ERR, "could not parse the value of the upstream-hash-by: ", err)
  end

  local o = {
    instance = self.factory:new(nodes),
    hash_by = complex_val,
    hash_by_key = backend["upstreamHashByConfig"]["upstream-hash-by"], 
    traffic_shaping_policy = backend.trafficShapingPolicy,
    alternative_backends = backend.alternativeBackends,
  }
  setmetatable(o, self)
  self.__index = self
  return o
end

function _M.balance(self)
  local key = util.generate_var_value(self.hash_by)
  return self.instance:find(key)
end

return _M
