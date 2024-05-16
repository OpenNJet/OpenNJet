local tostring = tostring
-- this is the Lua representation of TCP/UDP Configuration
local tcp_udp_configuration_data = njt.shared.tcp_udp_configuration_data

local _M = {}

function _M.get_backends_data()
  return tcp_udp_configuration_data:get("backends")
end

function _M.get_raw_backends_last_synced_at()
  local raw_backends_last_synced_at = tcp_udp_configuration_data:get("raw_backends_last_synced_at")
  if raw_backends_last_synced_at == nil then
    raw_backends_last_synced_at = 1
  end
  return raw_backends_last_synced_at
end

function _M.call()
  local sock, err = njt.req.socket(true)
  if not sock then
    njt.log(njt.ERR, "failed to get raw req socket: ", err)
    njt.say("error: ", err)
    return
  end

  local reader = sock:receiveuntil("\r\n")
  local backends, err_read = reader()
  if not backends then
    njt.log(njt.ERR, "failed TCP/UDP dynamic-configuration:", err_read)
    njt.say("error: ", err_read)
    return
  end

  if backends == nil or backends == "" then
    return
  end

  print("backends:", backends)
  local success, err_conf = tcp_udp_configuration_data:set("backends", backends)
  if not success then
    njt.log(njt.ERR, "dynamic-configuration: error updating configuration: " .. tostring(err_conf))
    njt.say("error: ", err_conf)
    return
  end

  local success, err_conf = tcp_udp_configuration_data:set("hc_backends", backends)
  if not success then
    njt.log(njt.ERR, "dynamic-configuration: error updating configuration: " .. tostring(err_conf))
    njt.say("error: ", err_conf)
    return
  end


  njt.update_time()
  local raw_backends_last_synced_at = njt.now()
  success, err = tcp_udp_configuration_data:set("raw_backends_last_synced_at",
                      raw_backends_last_synced_at)
  if not success then
    njt.log(njt.ERR, "dynamic-configuration: error updating when backends sync, " ..
                     "new upstream peers waiting for force syncing: " .. tostring(err))
    njt.status = njt.HTTP_BAD_REQUEST
    return
  end
  success, err = tcp_udp_configuration_data:set("raw_hc_backends_last_synced_at",
                      raw_backends_last_synced_at)
  if not success then
    njt.log(njt.ERR, "dynamic-configuration: error updating when backends sync, " ..
                     "new upstream peers waiting for force syncing: " .. tostring(err))
    njt.status = njt.HTTP_BAD_REQUEST
    return
  end
end

return _M
