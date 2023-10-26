local ffi = require("ffi")

ffi.cdef[[
    int njt_db_kv_get(njt_str_t *key, njt_str_t *value);
    int njt_db_kv_set(njt_str_t *key, njt_str_t *value);
    int njt_db_kv_del(njt_str_t *key);
]]

local _M={}

function _M.db_kv_set(k, v)
    local k_str = tostring(k)
    if k_str == nil then
        return -1, "k should be a valid string"
    end
    local v_str = tostring(v)
    if v_str == nil then
        return -1, "v should be a valid string"
    end

    local key_t = ffi.new("njt_str_t[1]")
    local message_t = ffi.new("njt_str_t[1]")
    local key = key_t[0]
    local message = message_t[0]
    key.data=k_str
    key.len=#k_str
    message.data=v_str
    message.len=#v_str

    local rc=ffi.C.njt_db_kv_set(key_t, message_t)
    if rc == 0 then 
        return 0, "value set"
    else 
        return rc, "error occuried"
    end
end

function _M.db_kv_get(k)
    local k_str = tostring(k)
    if k_str == nil then
        return -1, "k should be a valid string"
    end

    local key_t = ffi.new("njt_str_t[1]")
    local message_t = ffi.new("njt_str_t[1]")
    local key = key_t[0]
    local message = message_t[0]
    key.data=k_str
    key.len=#k_str

    local rc=ffi.C.njt_db_kv_get(key_t, message_t)
    local msgStr=ffi.string(message.data, message.len)
    return rc, msgStr
end

function _M.db_kv_del(k)
    local k_str = tostring(k)
    if k_str == nil then
        return -1, "k should be a valid string"
    end
    local key_t = ffi.new("njt_str_t[1]")
    local key= key_t[0]
    key.data=k_str
    key.len=#k_str
    local rc = ffi.C.njt_db_kv_del(key_t)
    if rc == 0 then 
        return 0, "key deleted"
    else 
        return 127, "key not found "
    end
end

return _M
