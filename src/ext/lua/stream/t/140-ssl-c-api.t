# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;
repeat_each(3);

# All these tests need to have new openssl
my $NginxBinary = $ENV{'TEST_NGINX_BINARY'} || 'nginx';
my $openssl_version = eval { `$NginxBinary -V 2>&1` };

if ($openssl_version =~ m/built with OpenSSL (0|1\.0\.(?:0|1[^\d]|2[a-d]).*)/) {
    plan(skip_all => "too old OpenSSL, need 1.0.2e, was $1");
} else {
    plan tests => repeat_each() * (blocks() * 5 + 1);
}

$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();

#log_level 'warn';
log_level 'debug';

no_long_string();
#no_diff();

add_block_preprocessor(sub {
    my $block = shift;

    if (!defined $block->user_files) {
        $block->set_value("user_files", <<'_EOC_');
>>> defines.lua
local ffi = require "ffi"

ffi.cdef[[
    int njt_stream_lua_ffi_cert_pem_to_der(const unsigned char *pem,
        size_t pem_len, unsigned char *der, char **err);

    int njt_stream_lua_ffi_priv_key_pem_to_der(const unsigned char *pem,
        size_t pem_len, unsigned char *der, char **err);

    int njt_stream_lua_ffi_ssl_set_der_certificate(void *r,
        const char *data, size_t len, char **err);

    int njt_stream_lua_ffi_ssl_set_der_private_key(void *r,
        const char *data, size_t len, char **err);

    int njt_stream_lua_ffi_ssl_clear_certs(void *r, char **err);

    void *njt_stream_lua_ffi_parse_pem_cert(const unsigned char *pem,
        size_t pem_len, char **err);

    void *njt_stream_lua_ffi_parse_pem_priv_key(const unsigned char *pem,
        size_t pem_len, char **err);

    int njt_stream_lua_ffi_set_cert(void *r,
        void *cdata, char **err);

    int njt_stream_lua_ffi_set_priv_key(void *r,
        void *cdata, char **err);

    void njt_stream_lua_ffi_free_cert(void *cdata);

    void njt_stream_lua_ffi_free_priv_key(void *cdata);

    int njt_stream_lua_ffi_ssl_clear_certs(void *r, char **err);

    int njt_stream_lua_ffi_ssl_verify_client(void *r, void *cdata, int depth, char **err);

]]
_EOC_
    }

    my $stream_config = $block->stream_config || '';
    $stream_config .= <<'_EOC_';
lua_package_path "$prefix/html/?.lua;../lua-resty-core/lib/?.lua;;";
_EOC_
    $block->set_value("stream_config", $stream_config);
});

run_tests();

__DATA__

=== TEST 1: simple cert + private key
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_certificate_by_lua_block {
            collectgarbage()

            require "defines"
            local ffi = require "ffi"

            local errmsg = ffi.new("char *[1]")

            local r = require "resty.core.base" .get_request()
            if not r then
                njt.log(njt.ERR, "no request found")
                return
            end

            ffi.C.njt_stream_lua_ffi_ssl_clear_certs(r, errmsg)

            local f = assert(io.open("t/cert/test.crt", "rb"))
            local cert = f:read("*all")
            f:close()

            local out = ffi.new("char [?]", #cert)

            local rc = ffi.C.njt_stream_lua_ffi_cert_pem_to_der(cert, #cert, out, errmsg)
            if rc < 1 then
                njt.log(njt.ERR, "failed to parse PEM cert: ",
                        ffi.string(errmsg[0]))
                return
            end

            local cert_der = ffi.string(out, rc)

            local rc = ffi.C.njt_stream_lua_ffi_ssl_set_der_certificate(r, cert_der, #cert_der, errmsg)
            if rc ~= 0 then
                njt.log(njt.ERR, "failed to set DER cert: ",
                        ffi.string(errmsg[0]))
                return
            end

            f = assert(io.open("t/cert/test.key", "rb"))
            local pkey = f:read("*all")
            f:close()

            out = ffi.new("char [?]", #pkey)

            local rc = ffi.C.njt_stream_lua_ffi_priv_key_pem_to_der(pkey, #pkey, out, errmsg)
            if rc < 1 then
                njt.log(njt.ERR, "failed to parse PEM priv key: ",
                        ffi.string(errmsg[0]))
                return
            end

            local pkey_der = ffi.string(out, rc)

            local rc = ffi.C.njt_stream_lua_ffi_ssl_set_der_private_key(r, pkey_der, #pkey_der, errmsg)
            if rc ~= 0 then
                njt.log(njt.ERR, "failed to set DER priv key: ",
                        ffi.string(errmsg[0]))
                return
            end
        }

        ssl_certificate ../../cert/test2.crt;
        ssl_certificate_key ../../cert/test2.key;

        return 'it works!\n';
    }
--- stream_server_config
    lua_ssl_trusted_certificate ../../cert/test.crt;

    content_by_lua_block {
        do
            local sock = njt.socket.tcp()

            sock:settimeout(2000)

            local ok, err = sock:connect("unix:$TEST_NGINX_HTML_DIR/nginx.sock")
            if not ok then
                njt.say("failed to connect: ", err)
                return
            end

            njt.say("connected: ", ok)

            local sess, err = sock:sslhandshake(nil, "test.com", true)
            if not sess then
                njt.say("failed to do SSL handshake: ", err)
                return
            end

            njt.say("ssl handshake: ", type(sess))

            while true do
                local line, err = sock:receive()
                if not line then
                    -- njt.say("failed to receive response status line: ", err)
                    break
                end

                njt.say("received: ", line)
            end

            local ok, err = sock:close()
            njt.say("close: ", ok, " ", err)
        end  -- do
        -- collectgarbage()
    }

--- stream_response
connected: 1
ssl handshake: userdata
received: it works!
close: 1 nil

--- error_log
lua ssl server name: "test.com"

--- no_error_log
[error]
[alert]



=== TEST 2: ECDSA cert + private key
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_certificate_by_lua_block {
            collectgarbage()

            local ffi = require "ffi"
            require "defines"

            local errmsg = ffi.new("char *[1]")

            local r = require "resty.core.base" .get_request()
            if not r then
                njt.log(njt.ERR, "no request found")
                return
            end

            ffi.C.njt_stream_lua_ffi_ssl_clear_certs(r, errmsg)

            local f = assert(io.open("t/cert/test_ecdsa.crt", "rb"))
            local cert = f:read("*all")
            f:close()

            local out = ffi.new("char [?]", #cert)

            local rc = ffi.C.njt_stream_lua_ffi_cert_pem_to_der(cert, #cert, out, errmsg)
            if rc < 1 then
                njt.log(njt.ERR, "failed to parse PEM cert: ",
                        ffi.string(errmsg[0]))
                return
            end

            local cert_der = ffi.string(out, rc)

            local rc = ffi.C.njt_stream_lua_ffi_ssl_set_der_certificate(r, cert_der, #cert_der, errmsg)
            if rc ~= 0 then
                njt.log(njt.ERR, "failed to set DER cert: ",
                        ffi.string(errmsg[0]))
                return
            end

            f = assert(io.open("t/cert/test_ecdsa.key", "rb"))
            local pkey = f:read("*all")
            f:close()

            out = ffi.new("char [?]", #pkey)

            local rc = ffi.C.njt_stream_lua_ffi_priv_key_pem_to_der(pkey, #pkey, out, errmsg)
            if rc < 1 then
                njt.log(njt.ERR, "failed to parse PEM priv key: ",
                        ffi.string(errmsg[0]))
                return
            end

            local pkey_der = ffi.string(out, rc)

            local rc = ffi.C.njt_stream_lua_ffi_ssl_set_der_private_key(r, pkey_der, #pkey_der, errmsg)
            if rc ~= 0 then
                njt.log(njt.ERR, "failed to set DER priv key: ",
                        ffi.string(errmsg[0]))
                return
            end
        }

        ssl_certificate ../../cert/test2.crt;
        ssl_certificate_key ../../cert/test2.key;

        return 'it works!\n';
    }
--- stream_server_config
    lua_ssl_trusted_certificate ../../cert/test_ecdsa.crt;

    content_by_lua_block {
        do
            local sock = njt.socket.tcp()

            sock:settimeout(2000)

            local ok, err = sock:connect("unix:$TEST_NGINX_HTML_DIR/nginx.sock")
            if not ok then
                njt.say("failed to connect: ", err)
                return
            end

            njt.say("connected: ", ok)

            local sess, err = sock:sslhandshake(nil, "test.com", true)
            if not sess then
                njt.say("failed to do SSL handshake: ", err)
                return
            end

            njt.say("ssl handshake: ", type(sess))

            while true do
                local line, err = sock:receive()
                if not line then
                    -- njt.say("failed to receive response status line: ", err)
                    break
                end

                njt.say("received: ", line)
            end

            local ok, err = sock:close()
            njt.say("close: ", ok, " ", err)
        end  -- do
        -- collectgarbage()
    }

--- stream_response
connected: 1
ssl handshake: userdata
received: it works!
close: 1 nil

--- error_log
lua ssl server name: "test.com"

--- no_error_log
[error]
[alert]



=== TEST 3: Handshake continue when cert_pem_to_der errors
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_certificate_by_lua_block {
            collectgarbage()

            local ffi = require "ffi"
            require "defines"

            local errmsg = ffi.new("char *[1]")

            local r = require "resty.core.base" .get_request()
            if not r then
                njt.log(njt.ERR, "no request found")
                return
            end

            local cert = "garbage data"

            local out = ffi.new("char [?]", #cert)

            local rc = ffi.C.njt_stream_lua_ffi_cert_pem_to_der(cert, #cert, out, errmsg)
            if rc < 1 then
                njt.log(njt.ERR, "failed to parse PEM cert: ",
                        ffi.string(errmsg[0]))
            end

            local pkey = "garbage key data"

            out = ffi.new("char [?]", #pkey)

            local rc = ffi.C.njt_stream_lua_ffi_priv_key_pem_to_der(pkey, #pkey, out, errmsg)
            if rc < 1 then
                njt.log(njt.ERR, "failed to parse PEM priv key: ",
                        ffi.string(errmsg[0]))
            end
        }

        ssl_certificate ../../cert/test.crt;
        ssl_certificate_key ../../cert/test.key;

        return 'it works!\n';
    }
--- stream_server_config
    lua_ssl_trusted_certificate ../../cert/test.crt;

    content_by_lua_block {
        do
            local sock = njt.socket.tcp()

            sock:settimeout(2000)

            local ok, err = sock:connect("unix:$TEST_NGINX_HTML_DIR/nginx.sock")
            if not ok then
                njt.say("failed to connect: ", err)
                return
            end

            njt.say("connected: ", ok)

            local sess, err = sock:sslhandshake(nil, "test.com", true)
            if not sess then
                njt.say("failed to do SSL handshake: ", err)
                return
            end

            njt.say("ssl handshake: ", type(sess))

            while true do
                local line, err = sock:receive()
                if not line then
                    -- njt.say("failed to receive response status line: ", err)
                    break
                end

                njt.say("received: ", line)
            end

            local ok, err = sock:close()
            njt.say("close: ", ok, " ", err)
        end  -- do
        -- collectgarbage()
    }

--- stream_response
connected: 1
ssl handshake: userdata
received: it works!
close: 1 nil

--- error_log
lua ssl server name: "test.com"
failed to parse PEM cert: PEM_read_bio_X509_AUX()
failed to parse PEM priv key: PEM_read_bio_PrivateKey() failed

--- no_error_log
[alert]



=== TEST 4: simple cert + private key cdata
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_certificate_by_lua_block {
            collectgarbage()

            local ffi = require "ffi"
            require "defines"

            local errmsg = ffi.new("char *[1]")

            local r = require "resty.core.base" .get_request()
            if not r then
                njt.log(njt.ERR, "no request found")
                return
            end

            ffi.C.njt_stream_lua_ffi_ssl_clear_certs(r, errmsg)

            local f = assert(io.open("t/cert/test.crt", "rb"))
            local cert_data = f:read("*all")
            f:close()

            local cert = ffi.C.njt_stream_lua_ffi_parse_pem_cert(cert_data, #cert_data, errmsg)
            if not cert then
                njt.log(njt.ERR, "failed to parse PEM cert: ",
                        ffi.string(errmsg[0]))
                return
            end

            local rc = ffi.C.njt_stream_lua_ffi_set_cert(r, cert, errmsg)
            if rc ~= 0 then
                njt.log(njt.ERR, "failed to set cdata cert: ",
                        ffi.string(errmsg[0]))
                return
            end

            ffi.C.njt_stream_lua_ffi_free_cert(cert)

            f = assert(io.open("t/cert/test.key", "rb"))
            local pkey_data = f:read("*all")
            f:close()

            local pkey = ffi.C.njt_stream_lua_ffi_parse_pem_priv_key(pkey_data, #pkey_data, errmsg)
            if pkey == nil then
                njt.log(njt.ERR, "failed to parse PEM priv key: ",
                        ffi.string(errmsg[0]))
                return
            end

            local rc = ffi.C.njt_stream_lua_ffi_set_priv_key(r, pkey, errmsg)
            if rc ~= 0 then
                njt.log(njt.ERR, "failed to set cdata priv key: ",
                        ffi.string(errmsg[0]))
                return
            end

            ffi.C.njt_stream_lua_ffi_free_priv_key(pkey)
        }

        ssl_certificate ../../cert/test2.crt;
        ssl_certificate_key ../../cert/test2.key;

        return 'it works!\n';
    }
--- stream_server_config
    lua_ssl_trusted_certificate ../../cert/test.crt;

    content_by_lua_block {
        do
            local sock = njt.socket.tcp()

            sock:settimeout(2000)

            local ok, err = sock:connect("unix:$TEST_NGINX_HTML_DIR/nginx.sock")
            if not ok then
                njt.say("failed to connect: ", err)
                return
            end

            njt.say("connected: ", ok)

            local sess, err = sock:sslhandshake(nil, "test.com", true)
            if not sess then
                njt.say("failed to do SSL handshake: ", err)
                return
            end

            njt.say("ssl handshake: ", type(sess))

            while true do
                local line, err = sock:receive()
                if not line then
                    -- njt.say("failed to receive response status line: ", err)
                    break
                end

                njt.say("received: ", line)
            end

            local ok, err = sock:close()
            njt.say("close: ", ok, " ", err)
        end  -- do
        -- collectgarbage()
    }

--- stream_response
connected: 1
ssl handshake: userdata
received: it works!
close: 1 nil

--- error_log
lua ssl server name: "test.com"

--- no_error_log
[error]
[alert]



=== TEST 5: ECDSA cert + private key cdata
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_certificate_by_lua_block {
            collectgarbage()

            local ffi = require "ffi"
            require "defines"

            local errmsg = ffi.new("char *[1]")

            local r = require "resty.core.base" .get_request()
            if not r then
                njt.log(njt.ERR, "no request found")
                return
            end

            ffi.C.njt_stream_lua_ffi_ssl_clear_certs(r, errmsg)

            local f = assert(io.open("t/cert/test_ecdsa.crt", "rb"))
            local cert_data = f:read("*all")
            f:close()

            local cert = ffi.C.njt_stream_lua_ffi_parse_pem_cert(cert_data, #cert_data, errmsg)
            if not cert then
                njt.log(njt.ERR, "failed to parse PEM cert: ",
                        ffi.string(errmsg[0]))
                return
            end

            local rc = ffi.C.njt_stream_lua_ffi_set_cert(r, cert, errmsg)
            if rc ~= 0 then
                njt.log(njt.ERR, "failed to set cdata cert: ",
                        ffi.string(errmsg[0]))
                return
            end

            ffi.C.njt_stream_lua_ffi_free_cert(cert)

            f = assert(io.open("t/cert/test_ecdsa.key", "rb"))
            local pkey_data = f:read("*all")
            f:close()

            local pkey = ffi.C.njt_stream_lua_ffi_parse_pem_priv_key(pkey_data, #pkey_data, errmsg)
            if pkey == nil then
                njt.log(njt.ERR, "failed to parse PEM priv key: ",
                        ffi.string(errmsg[0]))
                return
            end

            local rc = ffi.C.njt_stream_lua_ffi_set_priv_key(r, pkey, errmsg)
            if rc ~= 0 then
                njt.log(njt.ERR, "failed to set cdata priv key: ",
                        ffi.string(errmsg[0]))
                return
            end

            ffi.C.njt_stream_lua_ffi_free_priv_key(pkey)
        }

        ssl_certificate ../../cert/test2.crt;
        ssl_certificate_key ../../cert/test2.key;

        return 'it works!\n';
    }
--- stream_server_config
    lua_ssl_trusted_certificate ../../cert/test_ecdsa.crt;

    content_by_lua_block {
        do
            local sock = njt.socket.tcp()

            sock:settimeout(2000)

            local ok, err = sock:connect("unix:$TEST_NGINX_HTML_DIR/nginx.sock")
            if not ok then
                njt.say("failed to connect: ", err)
                return
            end

            njt.say("connected: ", ok)

            local sess, err = sock:sslhandshake(nil, "test.com", true)
            if not sess then
                njt.say("failed to do SSL handshake: ", err)
                return
            end

            njt.say("ssl handshake: ", type(sess))

            while true do
                local line, err = sock:receive()
                if not line then
                    -- njt.say("failed to receive response status line: ", err)
                    break
                end

                njt.say("received: ", line)
            end

            local ok, err = sock:close()
            njt.say("close: ", ok, " ", err)
        end  -- do
        -- collectgarbage()
    }

--- stream_response
connected: 1
ssl handshake: userdata
received: it works!
close: 1 nil

--- error_log
lua ssl server name: "test.com"

--- no_error_log
[error]
[alert]



=== TEST 6: verify client with CA certificates
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_certificate ../../cert/test2.crt;
        ssl_certificate_key ../../cert/test2.key;

        ssl_certificate_by_lua_block {
            collectgarbage()

            local ffi = require "ffi"
            require "defines"

            local errmsg = ffi.new("char *[1]")

            local r = require "resty.core.base" .get_request()
            if not r then
                njt.log(njt.ERR, "no request found")
                return
            end

            local f = assert(io.open("t/cert/test.crt", "rb"))
            local cert_data = f:read("*all")
            f:close()

            local cert = ffi.C.njt_stream_lua_ffi_parse_pem_cert(cert_data, #cert_data, errmsg)
            if not cert then
                njt.log(njt.ERR, "failed to parse PEM cert: ",
                        ffi.string(errmsg[0]))
                return
            end

            local rc = ffi.C.njt_stream_lua_ffi_ssl_verify_client(r, cert, -1, errmsg)
            if rc ~= 0 then
                njt.log(njt.ERR, "failed to set cdata cert: ",
                        ffi.string(errmsg[0]))
                return
            end

            ffi.C.njt_stream_lua_ffi_free_cert(cert)
        }

        content_by_lua_block {
            print('client certificate subject: ', njt.var.ssl_client_s_dn)
            njt.say(njt.var.ssl_client_verify)
        }
    }
--- stream_server_config
    proxy_pass                  unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl                   on;
    proxy_ssl_certificate       ../../cert/test.crt;
    proxy_ssl_certificate_key   ../../cert/test.key;
    proxy_ssl_session_reuse     off;

--- stream_response
SUCCESS

--- error_log
client certificate subject: emailAddress=agentzh@gmail.com,CN=test.com

--- no_error_log
[error]
[alert]



=== TEST 7: verify client without CA certificates
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_certificate ../../cert/test2.crt;
        ssl_certificate_key ../../cert/test2.key;

        ssl_certificate_by_lua_block {
            collectgarbage()

            local ffi = require "ffi"
            require "defines"

            local errmsg = ffi.new("char *[1]")

            local r = require "resty.core.base" .get_request()
            if not r then
                njt.log(njt.ERR, "no request found")
                return
            end

            local rc = ffi.C.njt_stream_lua_ffi_ssl_verify_client(r, nil, -1, errmsg)
            if rc ~= 0 then
                njt.log(njt.ERR, "failed to set cdata cert: ",
                        ffi.string(errmsg[0]))
                return
            end
        }

        content_by_lua_block {
            print('client certificate subject: ', njt.var.ssl_client_s_dn)
            njt.say(njt.var.ssl_client_verify)
        }
    }
--- stream_server_config
    proxy_pass                  unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl                   on;
    proxy_ssl_certificate       ../../cert/test.crt;
    proxy_ssl_certificate_key   ../../cert/test.key;
    proxy_ssl_session_reuse     off;

--- stream_response
FAILED:self signed certificate

--- error_log
client certificate subject: emailAddress=agentzh@gmail.com,CN=test.com

--- no_error_log
[error]
[alert]



=== TEST 8: verify client but client provides no certificate
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_certificate ../../cert/test2.crt;
        ssl_certificate_key ../../cert/test2.key;

        ssl_certificate_by_lua_block {
            collectgarbage()

            local ffi = require "ffi"
            require "defines"

            local errmsg = ffi.new("char *[1]")

            local r = require "resty.core.base" .get_request()
            if not r then
                njt.log(njt.ERR, "no request found")
                return
            end

            local f = assert(io.open("t/cert/test.crt", "rb"))
            local cert_data = f:read("*all")
            f:close()

            local cert = ffi.C.njt_stream_lua_ffi_parse_pem_cert(cert_data, #cert_data, errmsg)
            if not cert then
                njt.log(njt.ERR, "failed to parse PEM cert: ",
                        ffi.string(errmsg[0]))
                return
            end

            local rc = ffi.C.njt_stream_lua_ffi_ssl_verify_client(r, cert, 1, errmsg)
            if rc ~= 0 then
                njt.log(njt.ERR, "failed to set cdata cert: ",
                        ffi.string(errmsg[0]))
                return
            end

            ffi.C.njt_stream_lua_ffi_free_cert(cert)
        }

        content_by_lua_block {
            print('client certificate subject: ', njt.var.ssl_client_s_dn)
            njt.say(njt.var.ssl_client_verify)
        }
    }
--- stream_server_config
    proxy_pass                  unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl                   on;
    proxy_ssl_session_reuse     off;

--- stream_response
NONE

--- error_log
client certificate subject: nil

--- no_error_log
[error]
[alert]
