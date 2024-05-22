-- Case-insenstive access to headers. Based on lua-resty-http's headers module:
-- https://github.com/pintsized/lua-resty-http/blob/v0.11/lib/resty/http_headers.lua

local str_lower = string.lower

local _M = {}

function _M.new()
  local mt = {
    normalized = {},
  }

  mt.__index = function(self, k)
    return rawget(self, mt.normalized[str_lower(k)])
  end

  mt.__newindex = function(self, key, value)
    local key_normalized = str_lower(key)
    if not mt.normalized[key_normalized] then
      mt.normalized[key_normalized] = key
      rawset(self, key, value)
    else
      rawset(self, mt.normalized[key_normalized], value)
    end
  end

  return setmetatable({}, mt)
end

return _M
