local ffi = require("ffi")

ffi.cdef[[
    int njt_kv_sendmsg(njt_str_t *topic, njt_str_t *content, int retain_flag);
]]

local _M={}

function _M.kv_sendmsg(topic, payload, retain_flag)
    local k_str = tostring(topic)
    if k_str == nil then
        return -1, "topic should be a valid string"
    end
    local v_str = tostring(payload)
    if v_str == nil then
        return -1, "payload should be a valid string"
    end

    local key_t = ffi.new("njt_str_t[1]")
    local message_t = ffi.new("njt_str_t[1]")
    local key = key_t[0]
    local message = message_t[0]
    key.data=k_str
    key.len=#k_str
    message.data=v_str
    message.len=#v_str

    local rc=ffi.C.njt_kv_sendmsg(key_t, message_t, retain_flag)
    if rc == 0 then 
        return 0, "msg send"
    else 
        return rc, "error occuried"
    end
end

return _M