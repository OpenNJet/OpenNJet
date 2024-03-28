-- Copyright (C) Yichun Zhang (agentzh)


local base = require "resty.core.base"
local ffi = require "ffi"
local os = require "os"


local C = ffi.C
local ffi_new = ffi.new
local ffi_str = ffi.string
local njt = njt
local type = type
local error = error
local rawget = rawget
local rawset = rawset
local tonumber = tonumber
local setmetatable = setmetatable
local FFI_OK = base.FFI_OK
local FFI_NO_REQ_CTX = base.FFI_NO_REQ_CTX
local FFI_BAD_CONTEXT = base.FFI_BAD_CONTEXT
local new_tab = base.new_tab
local get_request = base.get_request
local get_size_ptr = base.get_size_ptr
local get_string_buf = base.get_string_buf
local get_string_buf_size = base.get_string_buf_size
local subsystem = njt.config.subsystem


local njt_lua_ffi_get_resp_status
local njt_lua_ffi_get_conf_env
local njt_magic_key_getters
local njt_magic_key_setters


local _M = new_tab(0, 3)
local njt_mt = new_tab(0, 2)


if subsystem == "http" then
    njt_magic_key_getters = new_tab(0, 4)
    njt_magic_key_setters = new_tab(0, 2)

elseif subsystem == "stream" then
    njt_magic_key_getters = new_tab(0, 2)
    njt_magic_key_setters = new_tab(0, 1)
end


local function register_getter(key, func)
    njt_magic_key_getters[key] = func
end
_M.register_njt_magic_key_getter = register_getter


local function register_setter(key, func)
    njt_magic_key_setters[key] = func
end
_M.register_njt_magic_key_setter = register_setter


njt_mt.__index = function (tb, key)
    local f = njt_magic_key_getters[key]
    if f then
        return f()
    end
    return rawget(tb, key)
end


njt_mt.__newindex = function (tb, key, ctx)
    local f = njt_magic_key_setters[key]
    if f then
        return f(ctx)
    end
    return rawset(tb, key, ctx)
end


setmetatable(njt, njt_mt)


if subsystem == "http" then
    ffi.cdef[[
    int njt_http_lua_ffi_get_resp_status(njt_http_request_t *r);
    int njt_http_lua_ffi_set_resp_status(njt_http_request_t *r, int r);
    int njt_http_lua_ffi_is_subrequest(njt_http_request_t *r);
    int njt_http_lua_ffi_headers_sent(njt_http_request_t *r);
    int njt_http_lua_ffi_get_conf_env(const unsigned char *name,
                                      unsigned char **env_buf,
                                      size_t *name_len);
    int njt_http_lua_ffi_req_is_internal(njt_http_request_t *r);
    ]]


    njt_lua_ffi_get_resp_status = C.njt_http_lua_ffi_get_resp_status
    njt_lua_ffi_get_conf_env = C.njt_http_lua_ffi_get_conf_env


    -- njt.status


    local function set_status(status)
        local r = get_request()

        if not r then
            error("no request found")
        end

        if type(status) ~= 'number' then
            status = tonumber(status)
        end

        local rc = C.njt_http_lua_ffi_set_resp_status(r, status)

        if rc == FFI_BAD_CONTEXT then
            error("API disabled in the current context", 2)
        end
    end
    register_setter("status", set_status)


    -- njt.is_subrequest


    local function is_subreq()
        local r = get_request()

        if not r then
            error("no request found")
        end

        local rc = C.njt_http_lua_ffi_is_subrequest(r)

        if rc == FFI_BAD_CONTEXT then
            error("API disabled in the current context", 2)
        end

        return rc == 1
    end
    register_getter("is_subrequest", is_subreq)


    -- njt.headers_sent


    local function headers_sent()
        local r = get_request()

        if not r then
            error("no request found")
        end

        local rc = C.njt_http_lua_ffi_headers_sent(r)

        if rc == FFI_NO_REQ_CTX then
            error("no request ctx found")
        end

        if rc == FFI_BAD_CONTEXT then
            error("API disabled in the current context", 2)
        end

        return rc == 1
    end
    register_getter("headers_sent", headers_sent)


    -- njt.req.is_internal


    function njt.req.is_internal()
        local r = get_request()
        if not r then
            error("no request found")
        end

        local rc = C.njt_http_lua_ffi_req_is_internal(r)

        if rc == FFI_BAD_CONTEXT then
            error("API disabled in the current context")
        end

        return rc == 1
    end

elseif subsystem == "stream" then
    ffi.cdef[[
    int njt_stream_lua_ffi_get_resp_status(njt_stream_lua_request_t *r);
    int njt_stream_lua_ffi_get_conf_env(const unsigned char *name,
                                        unsigned char **env_buf,
                                        size_t *name_len);
    ]]

    njt_lua_ffi_get_resp_status = C.njt_stream_lua_ffi_get_resp_status
    njt_lua_ffi_get_conf_env = C.njt_stream_lua_ffi_get_conf_env
end


-- njt.status


local function get_status()
    local r = get_request()

    if not r then
        error("no request found")
    end

    local rc = njt_lua_ffi_get_resp_status(r)

    if rc == FFI_BAD_CONTEXT then
        error("API disabled in the current context", 2)
    end

    return rc
end
register_getter("status", get_status)


do
    local _getenv = os.getenv
    local env_ptr = ffi_new("unsigned char *[1]")

    os.getenv = function (name)
        local r = get_request()
        if r then
            -- past init_by_lua* phase now
            os.getenv = _getenv
            env_ptr = nil
            return os.getenv(name)
        end

        local size = get_string_buf_size()
        env_ptr[0] = get_string_buf(size)
        local name_len_ptr = get_size_ptr()

        local rc = njt_lua_ffi_get_conf_env(name, env_ptr, name_len_ptr)
        if rc == FFI_OK then
            return ffi_str(env_ptr[0] + name_len_ptr[0] + 1)
        end

        -- FFI_DECLINED

        local value = _getenv(name)
        if value ~= nil then
            return value
        end

        return nil
    end
end


_M._VERSION = base.version


return _M
