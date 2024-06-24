local http = require("resty.http")

local _M={}

local function status_check(statusMatch, status)
  local code=tonumber(status)
  if not code or not statusMatch then
    return false
  end
  local reverse=false
  for v in string.gmatch(statusMatch, "(%S+)") do
    if v == "!" then
      reverse = true
    else
      for low, high in string.gmatch(v, "(%d+)-(%d+)") do
        if code >=tonumber(low) and code <=tonumber(high) then
          return not reverse 
        end
      end
      if code == tonumber(v) then 
         return not reverse
      end
    end
  end
  return reverse
end

function _M.check(param)

  local httpc = http.new()
  httpc:set_timeout(param.timeout*1000)
  local res,err = httpc: request_uri(param.uri, {
      ssl_verify = false,
      headers = param.headers
  })
  if not res then
      njt.log(njt.ERR, "health check error for url:"..param.uri)
      return { false, err }
   end

  local codeCheck=status_check(param.statusMatch, res.status)

   return { codeCheck, "" }
end

return _M
