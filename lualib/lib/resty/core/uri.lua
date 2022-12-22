-- Copyright (C) Yichun Zhang (agentzh)


local ffi = require "ffi"
local base = require "resty.core.base"


local C = ffi.C
local ffi_string = ffi.string
local njt = njt
local type = type
local error = error
local tostring = tostring
local get_string_buf = base.get_string_buf
local subsystem = njt.config.subsystem


local njt_lua_ffi_escape_uri
local njt_lua_ffi_unescape_uri
local njt_lua_ffi_uri_escaped_length

local NJT_ESCAPE_URI = 0
local NJT_ESCAPE_URI_COMPONENT = 2
local NJT_ESCAPE_MAIL_AUTH = 6


if subsystem == "http" then
    ffi.cdef[[
    size_t njt_http_lua_ffi_uri_escaped_length(const unsigned char *src,
                                               size_t len, int type);

    void njt_http_lua_ffi_escape_uri(const unsigned char *src, size_t len,
                                     unsigned char *dst, int type);

    size_t njt_http_lua_ffi_unescape_uri(const unsigned char *src,
                                         size_t len, unsigned char *dst);
    ]]

    njt_lua_ffi_escape_uri = C.njt_http_lua_ffi_escape_uri
    njt_lua_ffi_unescape_uri = C.njt_http_lua_ffi_unescape_uri
    njt_lua_ffi_uri_escaped_length = C.njt_http_lua_ffi_uri_escaped_length

elseif subsystem == "stream" then
    ffi.cdef[[
    size_t njt_stream_lua_ffi_uri_escaped_length(const unsigned char *src,
                                                 size_t len, int type);

    void njt_stream_lua_ffi_escape_uri(const unsigned char *src, size_t len,
                                       unsigned char *dst, int type);

    size_t njt_stream_lua_ffi_unescape_uri(const unsigned char *src,
                                           size_t len, unsigned char *dst);
    ]]

    njt_lua_ffi_escape_uri = C.njt_stream_lua_ffi_escape_uri
    njt_lua_ffi_unescape_uri = C.njt_stream_lua_ffi_unescape_uri
    njt_lua_ffi_uri_escaped_length = C.njt_stream_lua_ffi_uri_escaped_length
end


njt.escape_uri = function (s, esc_type)
    if type(s) ~= 'string' then
        if not s then
            s = ''

        else
            s = tostring(s)
        end
    end

    if esc_type == nil then
        esc_type = NJT_ESCAPE_URI_COMPONENT

    else
        if type(esc_type) ~= 'number' then
            error("\"type\" is not a number", 3)
        end

        if esc_type < NJT_ESCAPE_URI or esc_type > NJT_ESCAPE_MAIL_AUTH then
            error("\"type\" " .. esc_type .. " out of range", 3)
        end
    end

    local slen = #s
    local dlen = njt_lua_ffi_uri_escaped_length(s, slen, esc_type)

    -- print("dlen: ", tonumber(dlen))
    if dlen == slen then
        return s
    end
    local dst = get_string_buf(dlen)
    njt_lua_ffi_escape_uri(s, slen, dst, esc_type)
    return ffi_string(dst, dlen)
end


njt.unescape_uri = function (s)
    if type(s) ~= 'string' then
        if not s then
            s = ''
        else
            s = tostring(s)
        end
    end
    local slen = #s
    local dlen = slen
    local dst = get_string_buf(dlen)
    dlen = njt_lua_ffi_unescape_uri(s, slen, dst)
    return ffi_string(dst, dlen)
end


return {
    version = base.version,
}
