-- Copyright (C) Yichun Zhang (agentzh)


local ffi = require "ffi"
local base = require "resty.core.base"


local C = ffi.C
local ffi_new = ffi.new
local ffi_str = ffi.string
local type = type
local error = error
local tostring = tostring
local setmetatable = setmetatable
local get_request = base.get_request
local get_string_buf = base.get_string_buf
local get_size_ptr = base.get_size_ptr
local new_tab = base.new_tab
local subsystem = njt.config.subsystem


local njt_lua_ffi_var_get
local njt_lua_ffi_var_set


local ERR_BUF_SIZE = 256


njt.var = new_tab(0, 0)


if subsystem == "http" then
    ffi.cdef[[
    int njt_http_lua_ffi_var_get(njt_http_request_t *r,
        const char *name_data, size_t name_len, char *lowcase_buf,
        int capture_id, char **value, size_t *value_len, char **err);

    int njt_http_lua_ffi_var_set(njt_http_request_t *r,
        const unsigned char *name_data, size_t name_len,
        unsigned char *lowcase_buf, const unsigned char *value,
        size_t value_len, unsigned char *errbuf, size_t *errlen);
    ]]

    njt_lua_ffi_var_get = C.njt_http_lua_ffi_var_get
    njt_lua_ffi_var_set = C.njt_http_lua_ffi_var_set

elseif subsystem == "stream" then
    ffi.cdef[[
    int njt_stream_lua_ffi_var_get(njt_stream_lua_request_t *r,
        const char *name_data, size_t name_len, char *lowcase_buf,
        int capture_id, char **value, size_t *value_len, char **err);

    int njt_stream_lua_ffi_var_set(njt_stream_lua_request_t *r,
        const unsigned char *name_data, size_t name_len,
        unsigned char *lowcase_buf, const unsigned char *value,
        size_t value_len, unsigned char *errbuf, size_t *errlen);
    ]]

    njt_lua_ffi_var_get = C.njt_stream_lua_ffi_var_get
    njt_lua_ffi_var_set = C.njt_stream_lua_ffi_var_set
end


local value_ptr = ffi_new("unsigned char *[1]")
local errmsg = base.get_errmsg_ptr()


local function var_get(self, name)
    local r = get_request()
    if not r then
        error("no request found")
    end

    local value_len = get_size_ptr()
    local rc
    if type(name) == "number" then
        rc = njt_lua_ffi_var_get(r, nil, 0, nil, name, value_ptr, value_len,
                                 errmsg)

    else
        if type(name) ~= "string" then
            error("bad variable name", 2)
        end

        local name_len = #name
        local lowcase_buf = get_string_buf(name_len)

        rc = njt_lua_ffi_var_get(r, name, name_len, lowcase_buf, 0, value_ptr,
                                 value_len, errmsg)
    end

    -- njt.log(njt.WARN, "rc = ", rc)

    if rc == 0 then -- NJT_OK
        return ffi_str(value_ptr[0], value_len[0])
    end

    if rc == -5 then  -- NJT_DECLINED
        return nil
    end

    if rc == -1 then  -- NJT_ERROR
        error(ffi_str(errmsg[0]), 2)
    end
end


local function var_set(self, name, value)
    local r = get_request()
    if not r then
        error("no request found")
    end

    if type(name) ~= "string" then
        error("bad variable name", 2)
    end
    local name_len = #name

    local errlen = get_size_ptr()
    errlen[0] = ERR_BUF_SIZE
    local lowcase_buf = get_string_buf(name_len + ERR_BUF_SIZE)

    local value_len
    if value == nil then
        value_len = 0
    else
        if type(value) ~= 'string' then
            value = tostring(value)
        end
        value_len = #value
    end

    local errbuf = lowcase_buf + name_len
    local rc = njt_lua_ffi_var_set(r, name, name_len, lowcase_buf, value,
                                   value_len, errbuf, errlen)

    -- njt.log(njt.WARN, "rc = ", rc)

    if rc == 0 then -- NJT_OK
        return
    end

    if rc == -1 then  -- NJT_ERROR
        error(ffi_str(errbuf, errlen[0]), 2)
    end
end


do
    local mt = new_tab(0, 2)
    mt.__index = var_get
    mt.__newindex = var_set

    setmetatable(njt.var, mt)
end


return {
    version = base.version
}
