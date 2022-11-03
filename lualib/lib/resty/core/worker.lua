-- Copyright (C) Yichun Zhang (agentzh)


local ffi = require "ffi"
local base = require "resty.core.base"


local C = ffi.C
local new_tab = base.new_tab
local subsystem = njt.config.subsystem


local njt_lua_ffi_worker_id
local njt_lua_ffi_worker_pid
local njt_lua_ffi_worker_count
local njt_lua_ffi_worker_exiting


njt.worker = new_tab(0, 4)


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
