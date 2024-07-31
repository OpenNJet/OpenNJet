local ffi = require("ffi")

ffi.cdef[[
    int njt_token_get(njt_str_t *token, njt_str_t *value);
    int njt_token_set(njt_str_t *token, njt_str_t *value, int ttl);
]]

local _M={}

function _M.token_set(k, v, ttl)
    local k_str = tostring(k)
    if k_str == nil then
        return -1, "k should be a valid string"
    end
    local v_str = tostring(v)
    if v_str == nil then
        return -1, "v should be a valid string"
    end

    local token_t = ffi.new("njt_str_t[1]")
    local message_t = ffi.new("njt_str_t[1]")
    local token = token_t[0]
    local message = message_t[0]
    token.data=k_str
    token.len=#k_str
    message.data=v_str
    message.len=#v_str

    local ttl_v=tonumber(ttl)
    -- set default ttl to 10 minutes
    if not ttl_v then
	ttl_v = 600 
    end
    local rc=ffi.C.njt_token_set(token_t, message_t, ttl_v)
    if rc == 0 then 
        return 0, "value set"
    else 
        return rc, "error occuried"
    end
end

function _M.token_get(k)
    local k_str = tostring(k)
    if k_str == nil then
        return -1, "k should be a valid string"
    end

    local token_t = ffi.new("njt_str_t[1]")
    local message_t = ffi.new("njt_str_t[1]")
    local token = token_t[0]
    local message = message_t[0]
    token.data=k_str
    token.len=#k_str

    local rc=ffi.C.njt_token_get(token_t, message_t)
    local msgStr=ffi.string(message.data, message.len)
    return rc, msgStr
end

return _M
