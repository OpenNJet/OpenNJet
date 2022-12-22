-- Copyright (C) Yichun Zhang (agentzh)
-- Copyright (C) cuiweixie
-- I hereby assign copyright in this code to the lua-resty-core project,
-- to be licensed under the same terms as the rest of the code.


local base = require "resty.core.base"
base.allows_subsystem('http', 'stream')


local ffi = require 'ffi'
local FFI_OK = base.FFI_OK
local FFI_ERROR = base.FFI_ERROR
local FFI_DECLINED = base.FFI_DECLINED
local ffi_new = ffi.new
local ffi_str = ffi.string
local ffi_gc = ffi.gc
local C = ffi.C
local type = type
local error = error
local tonumber = tonumber
local get_request = base.get_request
local get_string_buf = base.get_string_buf
local get_size_ptr = base.get_size_ptr
local setmetatable = setmetatable
local co_yield = coroutine._yield
local ERR_BUF_SIZE = 128
local subsystem = njt.config.subsystem


local errmsg = base.get_errmsg_ptr()
local psem
local njt_lua_ffi_sema_new
local njt_lua_ffi_sema_post
local njt_lua_ffi_sema_count
local njt_lua_ffi_sema_wait
local njt_lua_ffi_sema_gc


if subsystem == 'http' then
    ffi.cdef[[
        struct njt_http_lua_sema_s;
        typedef struct njt_http_lua_sema_s njt_http_lua_sema_t;

        int njt_http_lua_ffi_sema_new(njt_http_lua_sema_t **psem,
            int n, char **errmsg);

        int njt_http_lua_ffi_sema_post(njt_http_lua_sema_t *sem, int n);

        int njt_http_lua_ffi_sema_count(njt_http_lua_sema_t *sem);

        int njt_http_lua_ffi_sema_wait(njt_http_request_t *r,
            njt_http_lua_sema_t *sem, int wait_ms,
            unsigned char *errstr, size_t *errlen);

        void njt_http_lua_ffi_sema_gc(njt_http_lua_sema_t *sem);
    ]]


    psem = ffi_new("njt_http_lua_sema_t *[1]")
    njt_lua_ffi_sema_new = C.njt_http_lua_ffi_sema_new
    njt_lua_ffi_sema_post = C.njt_http_lua_ffi_sema_post
    njt_lua_ffi_sema_count = C.njt_http_lua_ffi_sema_count
    njt_lua_ffi_sema_wait = C.njt_http_lua_ffi_sema_wait
    njt_lua_ffi_sema_gc = C.njt_http_lua_ffi_sema_gc

elseif subsystem == 'stream' then
    ffi.cdef[[
        struct njt_stream_lua_sema_s;
        typedef struct njt_stream_lua_sema_s njt_stream_lua_sema_t;

        int njt_stream_lua_ffi_sema_new(njt_stream_lua_sema_t **psem,
            int n, char **errmsg);

        int njt_stream_lua_ffi_sema_post(njt_stream_lua_sema_t *sem, int n);

        int njt_stream_lua_ffi_sema_count(njt_stream_lua_sema_t *sem);

        int njt_stream_lua_ffi_sema_wait(njt_stream_lua_request_t *r,
            njt_stream_lua_sema_t *sem, int wait_ms,
            unsigned char *errstr, size_t *errlen);

        void njt_stream_lua_ffi_sema_gc(njt_stream_lua_sema_t *sem);
    ]]


    psem = ffi_new("njt_stream_lua_sema_t *[1]")
    njt_lua_ffi_sema_new = C.njt_stream_lua_ffi_sema_new
    njt_lua_ffi_sema_post = C.njt_stream_lua_ffi_sema_post
    njt_lua_ffi_sema_count = C.njt_stream_lua_ffi_sema_count
    njt_lua_ffi_sema_wait = C.njt_stream_lua_ffi_sema_wait
    njt_lua_ffi_sema_gc = C.njt_stream_lua_ffi_sema_gc
end


local _M = { version = base.version }
local mt = { __index = _M }


function _M.new(n)
    n = tonumber(n) or 0
    if n < 0 then
        error("no negative number", 2)
    end

    local ret = njt_lua_ffi_sema_new(psem, n, errmsg)
    if ret == FFI_ERROR then
        return nil, ffi_str(errmsg[0])
    end

    local sem = psem[0]

    ffi_gc(sem, njt_lua_ffi_sema_gc)

    return setmetatable({ sem = sem }, mt)
end


function _M.wait(self, seconds)
    if type(self) ~= "table" or type(self.sem) ~= "cdata" then
        error("not a semaphore instance", 2)
    end

    local r = get_request()
    if not r then
        error("no request found")
    end

    local milliseconds = tonumber(seconds) * 1000
    if milliseconds < 0 then
        error("no negative number", 2)
    end

    local cdata_sem = self.sem

    local err = get_string_buf(ERR_BUF_SIZE)
    local errlen = get_size_ptr()
    errlen[0] = ERR_BUF_SIZE

    local ret = njt_lua_ffi_sema_wait(r, cdata_sem,
                                      milliseconds, err, errlen)

    if ret == FFI_ERROR then
        return nil, ffi_str(err, errlen[0])
    end

    if ret == FFI_OK then
        return true
    end

    if ret == FFI_DECLINED then
        return nil, "timeout"
    end

    -- Note: we cannot use the tail-call form here since we
    -- might need the current function call's activation
    -- record to hold the reference to our semaphore object
    -- to prevent it from getting GC'd prematurely.
    local ok
    ok, err = co_yield()
    return ok, err
end


function _M.post(self, n)
    if type(self) ~= "table" or type(self.sem) ~= "cdata" then
        error("not a semaphore instance", 2)
    end

    local cdata_sem = self.sem

    local num = n and tonumber(n) or 1
    if num < 1 then
        error("positive number required", 2)
    end

    -- always return NJT_OK
    njt_lua_ffi_sema_post(cdata_sem, num)

    return true
end


function _M.count(self)
    if type(self) ~= "table" or type(self.sem) ~= "cdata" then
        error("not a semaphore instance", 2)
    end

    return njt_lua_ffi_sema_count(self.sem)
end


return _M
