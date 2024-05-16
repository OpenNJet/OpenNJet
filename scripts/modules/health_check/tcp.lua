local _M = {}

local function tcp_validator(endpoint, timeout)
   local s, e = string.find(endpoint, ":")
   local server = string.sub(endpoint, 1, s - 1)
   local port = string.sub(endpoint, e + 1, string.len(endpoint))
   local sock = njt.socket.tcp()
   sock:settimeout(timeout * 1000)
   local ok, err = sock:connect(server, port)
   if not ok then
      sock:close()
      njt.log(njt.ERR, "health check error for endpoint:"..endpoint)      
      return {false, err}
   end
   sock:close()
   return {true, "tcp check: no error"}
end

function _M.check(param)
   return tcp_validator(param.uri, param.timeout)
end

return _M
