-- Copyright (C) Yichun Zhang (agentzh)


local base = require "resty.core.base"
base.allows_subsystem('http', 'stream')


local ffi = require "ffi"
local C = ffi.C
local ffi_str = ffi.string
local ffi_gc = ffi.gc
local get_request = base.get_request
local error = error
local tonumber = tonumber
local errmsg = base.get_errmsg_ptr()
local get_string_buf = base.get_string_buf
local get_size_ptr = base.get_size_ptr
local FFI_DECLINED = base.FFI_DECLINED
local FFI_OK = base.FFI_OK
local subsystem = njt.config.subsystem


local njt_lua_ffi_ssl_set_der_certificate
local njt_lua_ffi_ssl_clear_certs
local njt_lua_ffi_ssl_set_der_private_key
local njt_lua_ffi_ssl_raw_server_addr
local njt_lua_ffi_ssl_server_port
local njt_lua_ffi_ssl_server_name
local njt_lua_ffi_ssl_raw_client_addr
local njt_lua_ffi_cert_pem_to_der
local njt_lua_ffi_priv_key_pem_to_der
local njt_lua_ffi_ssl_get_tls1_version
local njt_lua_ffi_parse_pem_cert
local njt_lua_ffi_parse_pem_priv_key
local njt_lua_ffi_set_cert
local njt_lua_ffi_set_priv_key
local njt_lua_ffi_free_cert
local njt_lua_ffi_free_priv_key
local njt_lua_ffi_ssl_verify_client


if subsystem == 'http' then
    ffi.cdef[[
    int njt_http_lua_ffi_ssl_set_der_certificate(njt_http_request_t *r,
        const char *data, size_t len, char **err);

    int njt_http_lua_ffi_ssl_clear_certs(njt_http_request_t *r, char **err);

    int njt_http_lua_ffi_ssl_set_der_private_key(njt_http_request_t *r,
        const char *data, size_t len, char **err);

    int njt_http_lua_ffi_ssl_raw_server_addr(njt_http_request_t *r, char **addr,
        size_t *addrlen, int *addrtype, char **err);

    int njt_http_lua_ffi_ssl_server_port(njt_http_request_t *r,
        unsigned short *server_port, char **err);

    int njt_http_lua_ffi_ssl_server_name(njt_http_request_t *r, char **name,
        size_t *namelen, char **err);

    int njt_http_lua_ffi_ssl_raw_client_addr(njt_http_request_t *r, char **addr,
        size_t *addrlen, int *addrtype, char **err);

    int njt_http_lua_ffi_cert_pem_to_der(const unsigned char *pem,
        size_t pem_len, unsigned char *der, char **err);

    int njt_http_lua_ffi_priv_key_pem_to_der(const unsigned char *pem,
        size_t pem_len, const unsigned char *passphrase,
        unsigned char *der, char **err);

    int njt_http_lua_ffi_ssl_get_tls1_version(njt_http_request_t *r,
        char **err);

    void *njt_http_lua_ffi_parse_pem_cert(const unsigned char *pem,
        size_t pem_len, char **err);

    void *njt_http_lua_ffi_parse_pem_priv_key(const unsigned char *pem,
        size_t pem_len, char **err);

    int njt_http_lua_ffi_set_cert(void *r, void *cdata, char **err);

    int njt_http_lua_ffi_set_priv_key(void *r, void *cdata, char **err);

    void njt_http_lua_ffi_free_cert(void *cdata);

    void njt_http_lua_ffi_free_priv_key(void *cdata);

    int njt_http_lua_ffi_ssl_verify_client(void *r,
        void *cdata, int depth, char **err);
    ]]

    njt_lua_ffi_ssl_set_der_certificate =
        C.njt_http_lua_ffi_ssl_set_der_certificate
    njt_lua_ffi_ssl_clear_certs = C.njt_http_lua_ffi_ssl_clear_certs
    njt_lua_ffi_ssl_set_der_private_key =
        C.njt_http_lua_ffi_ssl_set_der_private_key
    njt_lua_ffi_ssl_raw_server_addr = C.njt_http_lua_ffi_ssl_raw_server_addr
    njt_lua_ffi_ssl_server_port = C.njt_http_lua_ffi_ssl_server_port
    njt_lua_ffi_ssl_server_name = C.njt_http_lua_ffi_ssl_server_name
    njt_lua_ffi_ssl_raw_client_addr = C.njt_http_lua_ffi_ssl_raw_client_addr
    njt_lua_ffi_cert_pem_to_der = C.njt_http_lua_ffi_cert_pem_to_der
    njt_lua_ffi_priv_key_pem_to_der = C.njt_http_lua_ffi_priv_key_pem_to_der
    njt_lua_ffi_ssl_get_tls1_version = C.njt_http_lua_ffi_ssl_get_tls1_version
    njt_lua_ffi_parse_pem_cert = C.njt_http_lua_ffi_parse_pem_cert
    njt_lua_ffi_parse_pem_priv_key = C.njt_http_lua_ffi_parse_pem_priv_key
    njt_lua_ffi_set_cert = C.njt_http_lua_ffi_set_cert
    njt_lua_ffi_set_priv_key = C.njt_http_lua_ffi_set_priv_key
    njt_lua_ffi_free_cert = C.njt_http_lua_ffi_free_cert
    njt_lua_ffi_free_priv_key = C.njt_http_lua_ffi_free_priv_key
    njt_lua_ffi_ssl_verify_client = C.njt_http_lua_ffi_ssl_verify_client

elseif subsystem == 'stream' then
    ffi.cdef[[
    int njt_stream_lua_ffi_ssl_set_der_certificate(njt_stream_lua_request_t *r,
        const char *data, size_t len, char **err);

    int njt_stream_lua_ffi_ssl_clear_certs(njt_stream_lua_request_t *r,
        char **err);

    int njt_stream_lua_ffi_ssl_set_der_private_key(njt_stream_lua_request_t *r,
        const char *data, size_t len, char **err);

    int njt_stream_lua_ffi_ssl_raw_server_addr(njt_stream_lua_request_t *r,
        char **addr, size_t *addrlen, int *addrtype, char **err);

    int njt_stream_lua_ffi_ssl_server_port(njt_stream_lua_request_t *r,
        unsigned short *server_port, char **err);

    int njt_stream_lua_ffi_ssl_server_name(njt_stream_lua_request_t *r,
        char **name, size_t *namelen, char **err);

    int njt_stream_lua_ffi_ssl_raw_client_addr(njt_stream_lua_request_t *r,
        char **addr, size_t *addrlen, int *addrtype, char **err);

    int njt_stream_lua_ffi_cert_pem_to_der(const unsigned char *pem,
        size_t pem_len, unsigned char *der, char **err);

    int njt_stream_lua_ffi_priv_key_pem_to_der(const unsigned char *pem,
        size_t pem_len, const unsigned char *passphrase,
        unsigned char *der, char **err);

    int njt_stream_lua_ffi_ssl_get_tls1_version(njt_stream_lua_request_t *r,
        char **err);

    void *njt_stream_lua_ffi_parse_pem_cert(const unsigned char *pem,
        size_t pem_len, char **err);

    void *njt_stream_lua_ffi_parse_pem_priv_key(const unsigned char *pem,
        size_t pem_len, char **err);

    int njt_stream_lua_ffi_set_cert(void *r, void *cdata, char **err);

    int njt_stream_lua_ffi_set_priv_key(void *r, void *cdata, char **err);

    void njt_stream_lua_ffi_free_cert(void *cdata);

    void njt_stream_lua_ffi_free_priv_key(void *cdata);

    int njt_stream_lua_ffi_ssl_verify_client(void *r,
        void *cdata, int depth, char **err);
    ]]

    njt_lua_ffi_ssl_set_der_certificate =
        C.njt_stream_lua_ffi_ssl_set_der_certificate
    njt_lua_ffi_ssl_clear_certs = C.njt_stream_lua_ffi_ssl_clear_certs
    njt_lua_ffi_ssl_set_der_private_key =
        C.njt_stream_lua_ffi_ssl_set_der_private_key
    njt_lua_ffi_ssl_raw_server_addr = C.njt_stream_lua_ffi_ssl_raw_server_addr
    njt_lua_ffi_ssl_server_port = C.njt_stream_lua_ffi_ssl_server_port
    njt_lua_ffi_ssl_server_name = C.njt_stream_lua_ffi_ssl_server_name
    njt_lua_ffi_ssl_raw_client_addr = C.njt_stream_lua_ffi_ssl_raw_client_addr
    njt_lua_ffi_cert_pem_to_der = C.njt_stream_lua_ffi_cert_pem_to_der
    njt_lua_ffi_priv_key_pem_to_der = C.njt_stream_lua_ffi_priv_key_pem_to_der
    njt_lua_ffi_ssl_get_tls1_version = C.njt_stream_lua_ffi_ssl_get_tls1_version
    njt_lua_ffi_parse_pem_cert = C.njt_stream_lua_ffi_parse_pem_cert
    njt_lua_ffi_parse_pem_priv_key = C.njt_stream_lua_ffi_parse_pem_priv_key
    njt_lua_ffi_set_cert = C.njt_stream_lua_ffi_set_cert
    njt_lua_ffi_set_priv_key = C.njt_stream_lua_ffi_set_priv_key
    njt_lua_ffi_free_cert = C.njt_stream_lua_ffi_free_cert
    njt_lua_ffi_free_priv_key = C.njt_stream_lua_ffi_free_priv_key
    njt_lua_ffi_ssl_verify_client = C.njt_stream_lua_ffi_ssl_verify_client
end


local _M = { version = base.version }


local charpp = ffi.new("char*[1]")
local intp = ffi.new("int[1]")
local ushortp = ffi.new("unsigned short[1]")


function _M.clear_certs()
    local r = get_request()
    if not r then
        error("no request found")
    end

    local rc = njt_lua_ffi_ssl_clear_certs(r, errmsg)
    if rc == FFI_OK then
        return true
    end

    return nil, ffi_str(errmsg[0])
end


function _M.set_der_cert(data)
    local r = get_request()
    if not r then
        error("no request found")
    end

    local rc = njt_lua_ffi_ssl_set_der_certificate(r, data, #data, errmsg)
    if rc == FFI_OK then
        return true
    end

    return nil, ffi_str(errmsg[0])
end


function _M.set_der_priv_key(data)
    local r = get_request()
    if not r then
        error("no request found")
    end

    local rc = njt_lua_ffi_ssl_set_der_private_key(r, data, #data, errmsg)
    if rc == FFI_OK then
        return true
    end

    return nil, ffi_str(errmsg[0])
end


local addr_types = {
    [0] = "unix",
    [1] = "inet",
    [2] = "inet6",
}


function _M.raw_server_addr()
    local r = get_request()
    if not r then
        error("no request found")
    end

    local sizep = get_size_ptr()

    local rc = njt_lua_ffi_ssl_raw_server_addr(r, charpp, sizep, intp, errmsg)
    if rc == FFI_OK then
        local typ = addr_types[intp[0]]
        if not typ then
            return nil, nil, "unknown address type: " .. intp[0]
        end
        return ffi_str(charpp[0], sizep[0]), typ
    end

    return nil, nil, ffi_str(errmsg[0])
end


function _M.server_port()
    local r = get_request()
    if not r then
        error("no request found")
    end

    local rc = njt_lua_ffi_ssl_server_port(r, ushortp, errmsg)
    if rc == FFI_OK then
        return ushortp[0]
    end

    return nil, ffi_str(errmsg[0])
end


function _M.server_name()
    local r = get_request()
    if not r then
        error("no request found")
    end

    local sizep = get_size_ptr()

    local rc = njt_lua_ffi_ssl_server_name(r, charpp, sizep, errmsg)
    if rc == FFI_OK then
        return ffi_str(charpp[0], sizep[0])
    end

    if rc == FFI_DECLINED then
        return nil
    end

    return nil, ffi_str(errmsg[0])
end


function _M.raw_client_addr()
    local r = get_request()
    if not r then
        error("no request found")
    end

    local sizep = get_size_ptr()

    local rc = njt_lua_ffi_ssl_raw_client_addr(r, charpp, sizep, intp, errmsg)
    if rc == FFI_OK then
        local typ = addr_types[intp[0]]
        if not typ then
            return nil, nil, "unknown address type: " .. intp[0]
        end
        return ffi_str(charpp[0], sizep[0]), typ
    end

    return nil, nil, ffi_str(errmsg[0])
end


function _M.cert_pem_to_der(pem)
    local outbuf = get_string_buf(#pem)

    local sz = njt_lua_ffi_cert_pem_to_der(pem, #pem, outbuf, errmsg)
    if sz > 0 then
        return ffi_str(outbuf, sz)
    end

    return nil, ffi_str(errmsg[0])
end


function _M.priv_key_pem_to_der(pem, passphrase)
    local outbuf = get_string_buf(#pem)

    local sz = njt_lua_ffi_priv_key_pem_to_der(pem, #pem,
                                               passphrase, outbuf, errmsg)
    if sz > 0 then
        return ffi_str(outbuf, sz)
    end

    return nil, ffi_str(errmsg[0])
end


local function get_tls1_version()

    local r = get_request()
    if not r then
        error("no request found")
    end

    local ver = njt_lua_ffi_ssl_get_tls1_version(r, errmsg)

    ver = tonumber(ver)

    if ver >= 0 then
        return ver
    end

    -- rc == FFI_ERROR

    return nil, ffi_str(errmsg[0])
end
_M.get_tls1_version = get_tls1_version


function _M.parse_pem_cert(pem)
    local cert = njt_lua_ffi_parse_pem_cert(pem, #pem, errmsg)
    if cert ~= nil then
        return ffi_gc(cert, njt_lua_ffi_free_cert)
    end

    return nil, ffi_str(errmsg[0])
end


function _M.parse_pem_priv_key(pem)
    local pkey = njt_lua_ffi_parse_pem_priv_key(pem, #pem, errmsg)
    if pkey ~= nil then
        return ffi_gc(pkey, njt_lua_ffi_free_priv_key)
    end

    return nil, ffi_str(errmsg[0])
end


function _M.set_cert(cert)
    local r = get_request()
    if not r then
        error("no request found")
    end

    local rc = njt_lua_ffi_set_cert(r, cert, errmsg)
    if rc == FFI_OK then
        return true
    end

    return nil, ffi_str(errmsg[0])
end


function _M.set_priv_key(priv_key)
    local r = get_request()
    if not r then
        error("no request found")
    end

    local rc = njt_lua_ffi_set_priv_key(r, priv_key, errmsg)
    if rc == FFI_OK then
        return true
    end

    return nil, ffi_str(errmsg[0])
end


function _M.verify_client(ca_certs, depth)
    local r = get_request()
    if not r then
        error("no request found")
    end

    if not depth then
        depth = -1
    end

    local rc = njt_lua_ffi_ssl_verify_client(r, ca_certs, depth, errmsg)
    if rc == FFI_OK then
        return true
    end

    return nil, ffi_str(errmsg[0])
end


do
    _M.SSL3_VERSION = 0x0300
    _M.TLS1_VERSION = 0x0301
    _M.TLS1_1_VERSION = 0x0302
    _M.TLS1_2_VERSION = 0x0303
    _M.TLS1_3_VERSION = 0x0304

    local map = {
        [_M.SSL3_VERSION] = "SSLv3",
        [_M.TLS1_VERSION] = "TLSv1",
        [_M.TLS1_1_VERSION] = "TLSv1.1",
        [_M.TLS1_2_VERSION] = "TLSv1.2",
        [_M.TLS1_3_VERSION] = "TLSv1.3",
    }

    function _M.get_tls1_version_str()
        local ver, err = get_tls1_version()
        if not ver then
            return nil, err
        end

        local ver_str = map[ver]
        if not ver_str then
            return nil, "unknown version"
        end

        return ver_str
    end
end


return _M
