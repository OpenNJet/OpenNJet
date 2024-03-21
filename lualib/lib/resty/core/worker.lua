-- Copyright (C) Yichun Zhang (agentzh)


local ffi = require "ffi"
local jit = require "jit"
local base = require "resty.core.base"
local ffi_cast = ffi.cast


local C = ffi.C
local new_tab = base.new_tab
local subsystem = njt.config.subsystem
local get_string_buf = base.get_string_buf
local get_size_ptr = base.get_size_ptr


local njt_lua_ffi_worker_id
local njt_lua_ffi_worker_pid
local njt_lua_ffi_worker_pids
local njt_lua_ffi_worker_count
local njt_lua_ffi_worker_exiting
local ffi_intp_type = ffi.typeof("int *")
local ffi_int_size = ffi.sizeof("int")


local is_not_windows = jit.os ~= "Windows"

if is_not_windows then
    njt.worker = new_tab(0, 5)

else
    njt.worker = new_tab(0, 4)
end


if subsystem == "http" then
    ffi.cdef[[
    int njt_http_lua_ffi_worker_id(void);
    int njt_http_lua_ffi_worker_pid(void);
    int njt_http_lua_ffi_worker_count(void);
    int njt_http_lua_ffi_worker_exiting(void);
    ]]

    njt_lua_ffi_worker_id = C.njt_http_lua_ffi_worker_id
    njt_lua_ffi_worker_pid = C.njt_http_lua_ffi_worker_pid
    njt_lua_ffi_worker_count = C.njt_http_lua_ffi_worker_count
    njt_lua_ffi_worker_exiting = C.njt_http_lua_ffi_worker_exiting

elseif subsystem == "stream" then
    ffi.cdef[[
    int njt_stream_lua_ffi_worker_id(void);
    int njt_stream_lua_ffi_worker_pid(void);
    int njt_stream_lua_ffi_worker_count(void);
    int njt_stream_lua_ffi_worker_exiting(void);
    ]]

    njt_lua_ffi_worker_id = C.njt_stream_lua_ffi_worker_id
    njt_lua_ffi_worker_pid = C.njt_stream_lua_ffi_worker_pid
    njt_lua_ffi_worker_count = C.njt_stream_lua_ffi_worker_count
    njt_lua_ffi_worker_exiting = C.njt_stream_lua_ffi_worker_exiting

end


function njt.worker.exiting()
    return njt_lua_ffi_worker_exiting() ~= 0
end


function njt.worker.pid()
    return njt_lua_ffi_worker_pid()
end


if is_not_windows then
    if subsystem == "http" then
        require "resty.core.phase"  -- for njt.get_phase

        ffi.cdef[[
        int njt_http_lua_ffi_worker_pids(int *pids, size_t *pids_len);
        ]]

        njt_lua_ffi_worker_pids = C.njt_http_lua_ffi_worker_pids

    elseif subsystem == "stream" then
        ffi.cdef[[
        int njt_stream_lua_ffi_worker_pids(int *pids, size_t *pids_len);
        ]]

        njt_lua_ffi_worker_pids = C.njt_stream_lua_ffi_worker_pids
    end

    local njt_phase = njt.get_phase

    function njt.worker.pids()
        local phase = njt_phase()
        if phase == "init" or phase == "init_worker" then
            return nil, "API disabled in the current context"
        end

        local pids = {}
        local size_ptr = get_size_ptr()
        -- the old and the new workers coexist during reloading
        local worker_cnt = njt_lua_ffi_worker_count() * 4
        if worker_cnt == 0 then
            return pids
        end

        size_ptr[0] = worker_cnt
        local pids_ptr = get_string_buf(worker_cnt * ffi_int_size)
        local intp_buf = ffi_cast(ffi_intp_type, pids_ptr)
        local res = njt_lua_ffi_worker_pids(intp_buf, size_ptr)

        if res == 0 then
            for i = 1, tonumber(size_ptr[0]) do
                pids[i] = intp_buf[i - 1]
            end
        end

        return pids
    end
end


function njt.worker.id()
    local id = njt_lua_ffi_worker_id()
    if id < 0 then
        return nil
    end

    return id
end


function njt.worker.count()
    return njt_lua_ffi_worker_count()
end


return {
    _VERSION = base.version
}
