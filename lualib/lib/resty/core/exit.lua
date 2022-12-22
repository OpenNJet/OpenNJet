-- Copyright (C) Yichun Zhang (agentzh)


local ffi = require "ffi"
local base = require "resty.core.base"


local C = ffi.C
local ffi_string = ffi.string
local njt = njt
local error = error
local get_string_buf = base.get_string_buf
local get_size_ptr = base.get_size_ptr
local get_request = base.get_request
local co_yield = coroutine._yield
local subsystem = njt.config.subsystem


local njt_lua_ffi_exit


if subsystem == "http" then
    ffi.cdef[[
    int njt_http_lua_ffi_exit(njt_http_request_t *r, int status,
                               unsigned char *err, size_t *errlen);
    ]]

    njt_lua_ffi_exit = C.njt_http_lua_ffi_exit

elseif subsystem == "stream" then
    ffi.cdef[[
    int njt_stream_lua_ffi_exit(njt_stream_lua_request_t *r, int status,
                                unsigned char *err, size_t *errlen);
    ]]

    njt_lua_ffi_exit = C.njt_stream_lua_ffi_exit
end


local ERR_BUF_SIZE = 128
local FFI_DONE = base.FFI_DONE


njt.exit = function (rc)
    local err = get_string_buf(ERR_BUF_SIZE)
    local errlen = get_size_ptr()
    local r = get_request()
    if r == nil then
        error("no request found")
    end
    errlen[0] = ERR_BUF_SIZE
    rc = njt_lua_ffi_exit(r, rc, err, errlen)
    if rc == 0 then
        -- print("yielding...")
        return co_yield()
    end
    if rc == FFI_DONE then
        return
    end
    error(ffi_string(err, errlen[0]), 2)
end


return {
    version = base.version
}
