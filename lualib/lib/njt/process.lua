-- Copyright (C) Yichun Zhang (agentzh)


local base = require "resty.core.base"
base.allows_subsystem('http', 'stream')

local ffi = require 'ffi'
local errmsg = base.get_errmsg_ptr()
local FFI_ERROR = base.FFI_ERROR
local ffi_str = ffi.string
local tonumber = tonumber
local subsystem = njt.config.subsystem

if subsystem == 'http' then
    require "resty.core.phase"  -- for njt.get_phase
end

local njt_phase = njt.get_phase

local process_type_names = {
    [0 ]  = "single",
    [1 ]  = "master",
    [2 ]  = "signaller",
    [3 ]  = "worker",
    [4 ]  = "helper",
    [99]  = "privileged agent",
}


local C = ffi.C
local _M = { version = base.version }

local njt_lua_ffi_enable_privileged_agent
local njt_lua_ffi_get_process_type
local njt_lua_ffi_process_signal_graceful_exit
local njt_lua_ffi_master_pid

if subsystem == 'http' then
    ffi.cdef[[
        int njt_http_lua_ffi_enable_privileged_agent(char **err,
            unsigned int connections);
        int njt_http_lua_ffi_get_process_type(void);
        void njt_http_lua_ffi_process_signal_graceful_exit(void);
        int njt_http_lua_ffi_master_pid(void);
    ]]

    njt_lua_ffi_enable_privileged_agent =
        C.njt_http_lua_ffi_enable_privileged_agent
    njt_lua_ffi_get_process_type = C.njt_http_lua_ffi_get_process_type
    njt_lua_ffi_process_signal_graceful_exit =
        C.njt_http_lua_ffi_process_signal_graceful_exit
    njt_lua_ffi_master_pid = C.njt_http_lua_ffi_master_pid

else
    ffi.cdef[[
        int njt_stream_lua_ffi_enable_privileged_agent(char **err,
            unsigned int connections);
        int njt_stream_lua_ffi_get_process_type(void);
        void njt_stream_lua_ffi_process_signal_graceful_exit(void);
        int njt_stream_lua_ffi_master_pid(void);
    ]]

    njt_lua_ffi_enable_privileged_agent =
        C.njt_stream_lua_ffi_enable_privileged_agent
    njt_lua_ffi_get_process_type = C.njt_stream_lua_ffi_get_process_type
    njt_lua_ffi_process_signal_graceful_exit =
        C.njt_stream_lua_ffi_process_signal_graceful_exit
    njt_lua_ffi_master_pid = C.njt_stream_lua_ffi_master_pid
end


function _M.type()
    local typ = njt_lua_ffi_get_process_type()
    return process_type_names[tonumber(typ)]
end


function _M.enable_privileged_agent(connections)
    if njt_phase() ~= "init" then
        return nil, "API disabled in the current context"
    end

    connections = connections or 512

    if type(connections) ~= "number" or connections < 0 then
        return nil, "bad 'connections' argument: " ..
            "number expected and greater than 0"
    end

    local rc = njt_lua_ffi_enable_privileged_agent(errmsg, connections)

    if rc == FFI_ERROR then
        return nil, ffi_str(errmsg[0])
    end

    return true
end


function _M.signal_graceful_exit()
    njt_lua_ffi_process_signal_graceful_exit()
end


function _M.get_master_pid()
    local pid = njt_lua_ffi_master_pid()
    if pid == FFI_ERROR then
        return nil
    end

    return tonumber(pid)
end


return _M
