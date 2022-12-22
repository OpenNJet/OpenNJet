-- Copyright (C) Yichun Zhang (agentzh)


local ffi = require "ffi"
local base = require "resty.core.base"


local C = ffi.C
local ffi_new = ffi.new
local ffi_string = ffi.string
local njt = njt
local type = type
local error = error
local tostring = tostring
local subsystem = njt.config.subsystem


local njt_lua_ffi_md5
local njt_lua_ffi_md5_bin
local njt_lua_ffi_sha1_bin
local njt_lua_ffi_crc32_long
local njt_lua_ffi_crc32_short


if subsystem == "http" then
    ffi.cdef[[
    void njt_http_lua_ffi_md5_bin(const unsigned char *src, size_t len,
                                  unsigned char *dst);

    void njt_http_lua_ffi_md5(const unsigned char *src, size_t len,
                              unsigned char *dst);

    int njt_http_lua_ffi_sha1_bin(const unsigned char *src, size_t len,
                                  unsigned char *dst);

    unsigned int njt_http_lua_ffi_crc32_long(const unsigned char *src,
                                             size_t len);

    unsigned int njt_http_lua_ffi_crc32_short(const unsigned char *src,
                                              size_t len);
    ]]

    njt_lua_ffi_md5 = C.njt_http_lua_ffi_md5
    njt_lua_ffi_md5_bin = C.njt_http_lua_ffi_md5_bin
    njt_lua_ffi_sha1_bin = C.njt_http_lua_ffi_sha1_bin
    njt_lua_ffi_crc32_short = C.njt_http_lua_ffi_crc32_short
    njt_lua_ffi_crc32_long = C.njt_http_lua_ffi_crc32_long

elseif subsystem == "stream" then
    ffi.cdef[[
    void njt_stream_lua_ffi_md5_bin(const unsigned char *src, size_t len,
                                    unsigned char *dst);

    void njt_stream_lua_ffi_md5(const unsigned char *src, size_t len,
                                unsigned char *dst);

    int njt_stream_lua_ffi_sha1_bin(const unsigned char *src, size_t len,
                                    unsigned char *dst);

    unsigned int njt_stream_lua_ffi_crc32_long(const unsigned char *src,
                                               size_t len);

    unsigned int njt_stream_lua_ffi_crc32_short(const unsigned char *src,
                                                size_t len);
    ]]

    njt_lua_ffi_md5 = C.njt_stream_lua_ffi_md5
    njt_lua_ffi_md5_bin = C.njt_stream_lua_ffi_md5_bin
    njt_lua_ffi_sha1_bin = C.njt_stream_lua_ffi_sha1_bin
    njt_lua_ffi_crc32_short = C.njt_stream_lua_ffi_crc32_short
    njt_lua_ffi_crc32_long = C.njt_stream_lua_ffi_crc32_long
end


local MD5_DIGEST_LEN = 16
local md5_buf = ffi_new("unsigned char[?]", MD5_DIGEST_LEN)

njt.md5_bin = function (s)
    if type(s) ~= 'string' then
        if not s then
            s = ''
        else
            s = tostring(s)
        end
    end
    njt_lua_ffi_md5_bin(s, #s, md5_buf)
    return ffi_string(md5_buf, MD5_DIGEST_LEN)
end


local MD5_HEX_DIGEST_LEN = MD5_DIGEST_LEN * 2
local md5_hex_buf = ffi_new("unsigned char[?]", MD5_HEX_DIGEST_LEN)

njt.md5 = function (s)
    if type(s) ~= 'string' then
        if not s then
            s = ''
        else
            s = tostring(s)
        end
    end
    njt_lua_ffi_md5(s, #s, md5_hex_buf)
    return ffi_string(md5_hex_buf, MD5_HEX_DIGEST_LEN)
end


local SHA_DIGEST_LEN = 20
local sha_buf = ffi_new("unsigned char[?]", SHA_DIGEST_LEN)

njt.sha1_bin = function (s)
    if type(s) ~= 'string' then
        if not s then
            s = ''
        else
            s = tostring(s)
        end
    end
    local ok = njt_lua_ffi_sha1_bin(s, #s, sha_buf)
    if ok == 0 then
        error("SHA-1 support missing in Nginx")
    end
    return ffi_string(sha_buf, SHA_DIGEST_LEN)
end


njt.crc32_short = function (s)
    if type(s) ~= "string" then
        if not s then
            s = ""
        else
            s = tostring(s)
        end
    end

    return njt_lua_ffi_crc32_short(s, #s)
end


njt.crc32_long = function (s)
    if type(s) ~= "string" then
        if not s then
            s = ""
        else
            s = tostring(s)
        end
    end

    return njt_lua_ffi_crc32_long(s, #s)
end


return {
    version = base.version
}
