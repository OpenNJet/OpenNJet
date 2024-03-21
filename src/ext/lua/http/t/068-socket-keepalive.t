# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua;

#repeat_each(2);

plan tests => repeat_each() * (blocks() * 4 + 34);

our $HtmlDir = html_dir;

$ENV{TEST_NGINX_MEMCACHED_PORT} ||= 11211;
$ENV{TEST_NGINX_HTML_DIR} = $HtmlDir;
$ENV{TEST_NGINX_REDIS_PORT} ||= 6379;
$ENV{TEST_NGINX_RESOLVER} ||= '8.8.8.8';

$ENV{LUA_PATH} ||=
    '/usr/local/openresty-debug/lualib/?.lua;/usr/local/openresty/lualib/?.lua;;';

no_long_string();
#no_diff();

#log_level 'warn';
log_level 'debug';

no_shuffle();

run_tests();

__DATA__

=== TEST 1: sanity
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
    location /t {
        set $port $TEST_NGINX_MEMCACHED_PORT;
        content_by_lua '
            local test = require "test"
            local port = njt.var.port
            test.go(port)
            test.go(port)
        ';
    }
--- user_files
>>> test.lua
module("test", package.seeall)

function go(port)
    local sock = njt.socket.tcp()
    local ok, err = sock:connect("127.0.0.1", port)
    if not ok then
        njt.say("failed to connect: ", err)
        return
    end

    njt.say("connected: ", ok, ", reused: ", sock:getreusedtimes())

    local req = "flush_all\r\n"

    local bytes, err = sock:send(req)
    if not bytes then
        njt.say("failed to send request: ", err)
        return
    end
    njt.say("request sent: ", bytes)

    local line, err, part = sock:receive()
    if line then
        njt.say("received: ", line)

    else
        njt.say("failed to receive a line: ", err, " [", part, "]")
    end

    local ok, err = sock:setkeepalive()
    if not ok then
        njt.say("failed to set reusable: ", err)
    end
end
--- request
GET /t
--- response_body
connected: 1, reused: 0
request sent: 11
received: OK
connected: 1, reused: 1
request sent: 11
received: OK
--- no_error_log eval
["[error]",
"lua tcp socket keepalive: free connection pool for "]
--- error_log eval
qq{lua tcp socket get keepalive peer: using connection
lua tcp socket keepalive create connection pool for key "127.0.0.1:$ENV{TEST_NGINX_MEMCACHED_PORT}"
}



=== TEST 2: free up the whole connection pool if no active connections
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
    location /t {
        set $port $TEST_NGINX_MEMCACHED_PORT;
        content_by_lua '
            local test = require "test"
            local port = njt.var.port
            test.go(port, true)
            test.go(port, false)
        ';
    }
--- request
GET /t
--- user_files
>>> test.lua
module("test", package.seeall)

function go(port, keepalive)
    local sock = njt.socket.tcp()
    local ok, err = sock:connect("127.0.0.1", port)
    if not ok then
        njt.say("failed to connect: ", err)
        return
    end

    njt.say("connected: ", ok, ", reused: ", sock:getreusedtimes())

    local req = "flush_all\r\n"

    local bytes, err = sock:send(req)
    if not bytes then
        njt.say("failed to send request: ", err)
        return
    end
    njt.say("request sent: ", bytes)

    local line, err, part = sock:receive()
    if line then
        njt.say("received: ", line)

    else
        njt.say("failed to receive a line: ", err, " [", part, "]")
    end

    if keepalive then
        local ok, err = sock:setkeepalive()
        if not ok then
            njt.say("failed to set reusable: ", err)
        end

    else
        sock:close()
    end
end
--- response_body
connected: 1, reused: 0
request sent: 11
received: OK
connected: 1, reused: 1
request sent: 11
received: OK
--- no_error_log
[error]
--- error_log eval
["lua tcp socket get keepalive peer: using connection",
"lua tcp socket keepalive: free connection pool for "]



=== TEST 3: upstream sockets close prematurely
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
   server_tokens off;
   keepalive_timeout 100ms;
   location /t {
        set $port $TEST_NGINX_SERVER_PORT;
        content_by_lua '
            local port = njt.var.port

            local sock = njt.socket.tcp()

            local ok, err = sock:connect("127.0.0.1", port)
            if not ok then
                njt.say("failed to connect: ", err)
                return
            end

            njt.say("connected: ", ok)

            local req = "GET /foo HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: keepalive\\r\\n\\r\\n"

            local bytes, err = sock:send(req)
            if not bytes then
                njt.say("failed to send request: ", err)
                return
            end

            njt.say("request sent: ", bytes)

            local reader = sock:receiveuntil("\\r\\n0\\r\\n\\r\\n")
            local data, err = reader()

            if not data then
                njt.say("failed to receive response body: ", err)
                return
            end

            njt.say("received response of ", #data, " bytes")

            local ok, err = sock:setkeepalive()
            if not ok then
                njt.say("failed to set reusable: ", err)
            end

            njt.location.capture("/sleep")

            njt.say("done")
        ';
    }

    location /foo {
        echo foo;
    }

    location /sleep {
        echo_sleep 1;
    }
--- request
GET /t
--- response_body
connected: 1
request sent: 61
received response of 156 bytes
done
--- no_error_log
[error]
--- error_log eval
["lua tcp socket keepalive close handler",
"lua tcp socket keepalive: free connection pool for "]
--- timeout: 3



=== TEST 4: http keepalive
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
   server_tokens off;
   location /t {
        keepalive_timeout 60s;

        set $port $TEST_NGINX_SERVER_PORT;
        content_by_lua '
            local port = njt.var.port

            local sock = njt.socket.tcp()

            local ok, err = sock:connect("127.0.0.1", port)
            if not ok then
                njt.say("failed to connect: ", err)
                return
            end

            njt.say("connected: ", ok)

            local req = "GET /foo HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: keepalive\\r\\n\\r\\n"

            local bytes, err = sock:send(req)
            if not bytes then
                njt.say("failed to send request: ", err)
                return
            end

            njt.say("request sent: ", bytes)

            local reader = sock:receiveuntil("\\r\\n0\\r\\n\\r\\n")
            local data, err = reader()

            if not data then
                njt.say("failed to receive response body: ", err)
                return
            end

            njt.say("received response of ", #data, " bytes")

            local ok, err = sock:setkeepalive()
            if not ok then
                njt.say("failed to set reusable: ", err)
            end

            njt.location.capture("/sleep")

            njt.say("done")
        ';
    }

    location /foo {
        echo foo;
    }

    location /sleep {
        echo_sleep 1;
    }
--- request
GET /t
--- response_body
connected: 1
request sent: 61
received response of 156 bytes
done
--- no_error_log eval
["[error]",
"lua tcp socket keepalive close handler: fd:",
"lua tcp socket keepalive: free connection pool for "]
--- timeout: 4



=== TEST 5: lua_socket_keepalive_timeout
--- config
   server_tokens off;
   location /t {
       keepalive_timeout 60s;
       lua_socket_keepalive_timeout 100ms;

        set $port $TEST_NGINX_SERVER_PORT;
        content_by_lua '
            local port = njt.var.port

            local sock = njt.socket.tcp()

            local ok, err = sock:connect("127.0.0.1", port)
            if not ok then
                njt.say("failed to connect: ", err)
                return
            end

            njt.say("connected: ", ok)

            local req = "GET /foo HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: keepalive\\r\\n\\r\\n"

            local bytes, err = sock:send(req)
            if not bytes then
                njt.say("failed to send request: ", err)
                return
            end

            njt.say("request sent: ", bytes)

            local reader = sock:receiveuntil("\\r\\n0\\r\\n\\r\\n")
            local data, res = reader()

            if not data then
                njt.say("failed to receive response body: ", err)
                return
            end

            njt.say("received response of ", #data, " bytes")

            local ok, err = sock:setkeepalive()
            if not ok then
                njt.say("failed to set reusable: ", err)
            end

            njt.location.capture("/sleep")

            njt.say("done")
        ';
    }

    location /foo {
        echo foo;
    }

    location /sleep {
        echo_sleep 1;
    }
--- request
GET /t
--- response_body
connected: 1
request sent: 61
received response of 156 bytes
done
--- no_error_log
[error]
--- error_log eval
["lua tcp socket keepalive close handler",
"lua tcp socket keepalive: free connection pool for ",
"lua tcp socket keepalive timeout: 100 ms",
qr/lua tcp socket connection pool size: 30\b/]
--- timeout: 4



=== TEST 6: lua_socket_pool_size
--- config
   server_tokens off;
   location /t {
       keepalive_timeout 60s;
       lua_socket_keepalive_timeout 100ms;
       lua_socket_pool_size 1;

        set $port $TEST_NGINX_SERVER_PORT;
        content_by_lua '
            local port = njt.var.port

            local sock = njt.socket.tcp()

            local ok, err = sock:connect("127.0.0.1", port)
            if not ok then
                njt.say("failed to connect: ", err)
                return
            end

            njt.say("connected: ", ok)

            local req = "GET /foo HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: keepalive\\r\\n\\r\\n"

            local bytes, err = sock:send(req)
            if not bytes then
                njt.say("failed to send request: ", err)
                return
            end

            njt.say("request sent: ", bytes)

            local reader = sock:receiveuntil("\\r\\n0\\r\\n\\r\\n")
            local data, res = reader()

            if not data then
                njt.say("failed to receive response body: ", err)
                return
            end

            njt.say("received response of ", #data, " bytes")

            local ok, err = sock:setkeepalive()
            if not ok then
                njt.say("failed to set reusable: ", err)
            end

            njt.location.capture("/sleep")

            njt.say("done")
        ';
    }

    location /foo {
        echo foo;
    }

    location /sleep {
        echo_sleep 1;
    }
--- request
GET /t
--- response_body
connected: 1
request sent: 61
received response of 156 bytes
done
--- no_error_log
[error]
--- error_log eval
["lua tcp socket keepalive close handler",
"lua tcp socket keepalive: free connection pool for ",
"lua tcp socket keepalive timeout: 100 ms",
qr/lua tcp socket connection pool size: 1\b/]
--- timeout: 4



=== TEST 7: "lua_socket_keepalive_timeout 0" means unlimited
--- config
   server_tokens off;
   location /t {
       keepalive_timeout 60s;
       lua_socket_keepalive_timeout 0;

        set $port $TEST_NGINX_SERVER_PORT;
        content_by_lua '
            local port = njt.var.port

            local sock = njt.socket.tcp()

            local ok, err = sock:connect("127.0.0.1", port)
            if not ok then
                njt.say("failed to connect: ", err)
                return
            end

            njt.say("connected: ", ok)

            local req = "GET /foo HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: keepalive\\r\\n\\r\\n"

            local bytes, err = sock:send(req)
            if not bytes then
                njt.say("failed to send request: ", err)
                return
            end

            njt.say("request sent: ", bytes)

            local reader = sock:receiveuntil("\\r\\n0\\r\\n\\r\\n")
            local data, res = reader()

            if not data then
                njt.say("failed to receive response body: ", err)
                return
            end

            njt.say("received response of ", #data, " bytes")

            local ok, err = sock:setkeepalive()
            if not ok then
                njt.say("failed to set reusable: ", err)
            end

            njt.location.capture("/sleep")

            njt.say("done")
        ';
    }

    location /foo {
        echo foo;
    }

    location /sleep {
        echo_sleep 1;
    }
--- request
GET /t
--- response_body
connected: 1
request sent: 61
received response of 156 bytes
done
--- no_error_log
[error]
--- error_log eval
["lua tcp socket keepalive timeout: unlimited",
qr/lua tcp socket connection pool size: 30\b/]
--- timeout: 4



=== TEST 8: setkeepalive(timeout) overrides lua_socket_keepalive_timeout
--- config
   server_tokens off;
   location /t {
        keepalive_timeout 60s;
        lua_socket_keepalive_timeout 60s;

        set $port $TEST_NGINX_SERVER_PORT;
        content_by_lua '
            local port = njt.var.port

            local sock = njt.socket.tcp()

            local ok, err = sock:connect("127.0.0.1", port)
            if not ok then
                njt.say("failed to connect: ", err)
                return
            end

            njt.say("connected: ", ok)

            local req = "GET /foo HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: keepalive\\r\\n\\r\\n"

            local bytes, err = sock:send(req)
            if not bytes then
                njt.say("failed to send request: ", err)
                return
            end

            njt.say("request sent: ", bytes)

            local reader = sock:receiveuntil("\\r\\n0\\r\\n\\r\\n")
            local data, res = reader()

            if not data then
                njt.say("failed to receive response body: ", err)
                return
            end

            njt.say("received response of ", #data, " bytes")

            local ok, err = sock:setkeepalive(123)
            if not ok then
                njt.say("failed to set reusable: ", err)
            end

            njt.location.capture("/sleep")

            njt.say("done")
        ';
    }

    location /foo {
        echo foo;
    }

    location /sleep {
        echo_sleep 1;
    }
--- request
GET /t
--- response_body
connected: 1
request sent: 61
received response of 156 bytes
done
--- no_error_log
[error]
--- error_log eval
["lua tcp socket keepalive close handler",
"lua tcp socket keepalive: free connection pool for ",
"lua tcp socket keepalive timeout: 123 ms",
qr/lua tcp socket connection pool size: 30\b/]
--- timeout: 4



=== TEST 9: sock:setkeepalive(timeout, size) overrides lua_socket_pool_size
--- config
   server_tokens off;
   location /t {
       keepalive_timeout 60s;
       lua_socket_keepalive_timeout 100ms;
       lua_socket_pool_size 100;

        set $port $TEST_NGINX_SERVER_PORT;
        content_by_lua '
            local port = njt.var.port

            local sock = njt.socket.tcp()

            local ok, err = sock:connect("127.0.0.1", port)
            if not ok then
                njt.say("failed to connect: ", err)
                return
            end

            njt.say("connected: ", ok)

            local req = "GET /foo HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: keepalive\\r\\n\\r\\n"

            local bytes, err = sock:send(req)
            if not bytes then
                njt.say("failed to send request: ", err)
                return
            end

            njt.say("request sent: ", bytes)

            local reader = sock:receiveuntil("\\r\\n0\\r\\n\\r\\n")
            local data, res = reader()

            if not data then
                njt.say("failed to receive response body: ", err)
                return
            end

            njt.say("received response of ", #data, " bytes")

            local ok, err = sock:setkeepalive(101, 25)
            if not ok then
                njt.say("failed to set reusable: ", err)
            end

            njt.location.capture("/sleep")

            njt.say("done")
        ';
    }

    location /foo {
        echo foo;
    }

    location /sleep {
        echo_sleep 1;
    }
--- request
GET /t
--- response_body
connected: 1
request sent: 61
received response of 156 bytes
done
--- no_error_log
[error]
--- error_log eval
["lua tcp socket keepalive close handler",
"lua tcp socket keepalive: free connection pool for ",
"lua tcp socket keepalive timeout: 101 ms",
qr/lua tcp socket connection pool size: 25\b/]
--- timeout: 4



=== TEST 10: setkeepalive() 'pool_size' should be greater than zero
--- config
    location /t {
        set $port $TEST_NGINX_MEMCACHED_PORT;
        content_by_lua_block {
            local sock, err = njt.socket.connect("127.0.0.1", njt.var.port)
            if not sock then
                njt.say(err)
                return
            end

            local ok, err = pcall(sock.setkeepalive, sock, 0, 0)
            if not ok then
                njt.say(err)
                return
            end
            njt.say(ok)
        }
    }
--- request
GET /t
--- response_body
bad argument #3 to '?' (bad "pool_size" option value: 0)
--- no_error_log
[error]



=== TEST 11: sock:keepalive_timeout(0) means unlimited
--- config
   server_tokens off;
   location /t {
       keepalive_timeout 60s;
       lua_socket_keepalive_timeout 1000ms;

        set $port $TEST_NGINX_SERVER_PORT;
        content_by_lua '
            local port = njt.var.port

            local sock = njt.socket.tcp()

            local ok, err = sock:connect("127.0.0.1", port)
            if not ok then
                njt.say("failed to connect: ", err)
                return
            end

            njt.say("connected: ", ok)

            local req = "GET /foo HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: keepalive\\r\\n\\r\\n"

            local bytes, err = sock:send(req)
            if not bytes then
                njt.say("failed to send request: ", err)
                return
            end

            njt.say("request sent: ", bytes)

            local reader = sock:receiveuntil("\\r\\n0\\r\\n\\r\\n")
            local data, res = reader()

            if not data then
                njt.say("failed to receive response body: ", err)
                return
            end

            njt.say("received response of ", #data, " bytes")

            local ok, err = sock:setkeepalive(0)
            if not ok then
                njt.say("failed to set reusable: ", err)
            end

            njt.location.capture("/sleep")

            njt.say("done")
        ';
    }

    location /foo {
        echo foo;
    }

    location /sleep {
        echo_sleep 1;
    }
--- request
GET /t
--- response_body
connected: 1
request sent: 61
received response of 156 bytes
done
--- no_error_log
[error]
--- error_log eval
["lua tcp socket keepalive timeout: unlimited",
qr/lua tcp socket connection pool size: 30\b/]
--- timeout: 4



=== TEST 12: sanity (uds)
--- http_config eval
"
    lua_package_path '$::HtmlDir/?.lua;./?.lua;;';
    server {
        listen unix:$::HtmlDir/nginx.sock;
        default_type 'text/plain';

        server_tokens off;
        location /foo {
            echo foo;
            more_clear_headers Date;
        }
    }
"
--- config
    location /t {
        set $port $TEST_NGINX_MEMCACHED_PORT;
        content_by_lua '
            local test = require "test"
            local path = "$TEST_NGINX_HTML_DIR/nginx.sock";
            local port = njt.var.port
            test.go(path, port)
            test.go(path, port)
        ';
    }
--- request
GET /t
--- user_files
>>> test.lua
module("test", package.seeall)

function go(path, port)
    local sock = njt.socket.tcp()
    local ok, err = sock:connect("unix:" .. path)
    if not ok then
        njt.say("failed to connect: ", err)
        return
    end

    njt.say("connected: ", ok, ", reused: ", sock:getreusedtimes())

    local req = "GET /foo HTTP/1.1\r\nHost: localhost\r\nConnection: keepalive\r\n\r\n"

    local bytes, err = sock:send(req)
    if not bytes then
        njt.say("failed to send request: ", err)
        return
    end
    njt.say("request sent: ", bytes)

    local reader = sock:receiveuntil("\r\n0\r\n\r\n")
    local data, err = reader()

    if not data then
        njt.say("failed to receive response body: ", err)
        return
    end

    njt.say("received response of ", #data, " bytes")

    local ok, err = sock:setkeepalive()
    if not ok then
        njt.say("failed to set reusable: ", err)
    end
end
--- response_body
connected: 1, reused: 0
request sent: 61
received response of 119 bytes
connected: 1, reused: 1
request sent: 61
received response of 119 bytes
--- no_error_log eval
["[error]",
"lua tcp socket keepalive: free connection pool for "]
--- error_log eval
["lua tcp socket get keepalive peer: using connection",
'lua tcp socket keepalive create connection pool for key "unix:']



=== TEST 13: github issue #108: njt.location.capture + redis.set_keepalive
--- http_config eval
    qq{
        lua_package_path "$::HtmlDir/?.lua;;";
    }
--- config
    location /t {
        default_type text/html;
        set $port $TEST_NGINX_MEMCACHED_PORT;
        #lua_code_cache off;
        lua_need_request_body on;
        content_by_lua_file html/t.lua;
    }

    location /anyurl {
        internal;
        proxy_pass http://127.0.0.1:$server_port/dummy;
    }

    location = /dummy {
        echo dummy;
    }
--- user_files
>>> t.lua
local sock, err = njt.socket.connect("127.0.0.1", njt.var.port)
if not sock then njt.say(err) return end
sock:send("flush_all\r\n")
sock:receive()
sock:setkeepalive()

sock, err = njt.socket.connect("127.0.0.1", njt.var.port)
if not sock then njt.say(err) return end
local res = njt.location.capture("/anyurl") --3

njt.say("ok")
--- request
    GET /t
--- response_body
ok
--- error_log
lua tcp socket get keepalive peer: using connection
--- no_error_log
[error]
[alert]



=== TEST 14: github issue #110: njt.exit with HTTP_NOT_FOUND causes worker process to exit
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
    error_page 404 /404.html;
    location /t {
        set $port $TEST_NGINX_MEMCACHED_PORT;
        access_by_lua '
            local test = require "test"
            local port = njt.var.port
            test.go(port)
            njt.exit(404)
        ';
        echo hello;
    }
--- user_files
>>> 404.html
Not found, dear...
>>> test.lua
module("test", package.seeall)

function go(port)
    local sock = njt.socket.tcp()
    local ok, err = sock:connect("127.0.0.1", port)
    if not ok then
        njt.log(njt.ERR, "failed to connect: ", err)
        return
    end

    local req = "flush_all\r\n"

    local bytes, err = sock:send(req)
    if not bytes then
        njt.log(njt.ERR, "failed to send request: ", err)
        return
    end

    local line, err, part = sock:receive()
    if not line then
        njt.log(njt.ERR, "failed to receive a line: ", err, " [", part, "]")
        return
    end

    -- local ok, err = sock:setkeepalive()
    -- if not ok then
        -- njt.log(njt.ERR, "failed to set reusable: ", err)
        -- return
    -- end
end
--- request
GET /t
--- response_body
Not found, dear...
--- error_code: 404
--- no_error_log
[error]



=== TEST 15: custom pools (different pool for the same host:port) - tcp
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
    location /t {
        set $port $TEST_NGINX_MEMCACHED_PORT;
        content_by_lua '
            local test = require "test"
            local port = njt.var.port
            test.go(port, "A")
            test.go(port, "B")
        ';
    }
--- user_files
>>> test.lua
module("test", package.seeall)

function go(port, pool)
    local sock = njt.socket.tcp()
    local ok, err = sock:connect("127.0.0.1", port, {pool = pool})
    if not ok then
        njt.say("failed to connect: ", err)
        return
    end

    njt.say("connected: ", ok, ", reused: ", sock:getreusedtimes())

    local ok, err = sock:setkeepalive()
    if not ok then
        njt.say("failed to set reusable: ", err)
    end
end
--- request
GET /t
--- response_body
connected: 1, reused: 0
connected: 1, reused: 0
--- no_error_log eval
["[error]",
"lua tcp socket keepalive: free connection pool for ",
"lua tcp socket get keepalive peer: using connection"
]
--- error_log
lua tcp socket keepalive create connection pool for key "A"
lua tcp socket keepalive create connection pool for key "B"



=== TEST 16: custom pools (same pool for different host:port) - tcp
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
    location /t {
        set $port $TEST_NGINX_MEMCACHED_PORT;
        content_by_lua '
            local test = require "test"
            local port = njt.var.port
            test.go($TEST_NGINX_MEMCACHED_PORT, "foo")
            test.go($TEST_NGINX_SERVER_PORT, "foo")
        ';
    }
--- user_files
>>> test.lua
module("test", package.seeall)

function go(port, pool)
    local sock = njt.socket.tcp()
    local ok, err = sock:connect("127.0.0.1", port, {pool = pool})
    if not ok then
        njt.say("failed to connect: ", err)
        return
    end

    njt.say("connected: ", ok, ", reused: ", sock:getreusedtimes())

    local ok, err = sock:setkeepalive()
    if not ok then
        njt.say("failed to set reusable: ", err)
    end
end
--- request
GET /t
--- response_body
connected: 1, reused: 0
connected: 1, reused: 1
--- no_error_log eval
["[error]",
"lua tcp socket keepalive: free connection pool for ",
]
--- error_log
lua tcp socket keepalive create connection pool for key "foo"
lua tcp socket get keepalive peer: using connection



=== TEST 17: custom pools (different pool for the same host:port) - unix
--- http_config eval
"
    lua_package_path '$::HtmlDir/?.lua;./?.lua;;';
    server {
        listen unix:$::HtmlDir/nginx.sock;
        default_type 'text/plain';

        server_tokens off;
        location /foo {
            echo foo;
            more_clear_headers Date;
        }
    }
"
--- config
    location /t {
        set $port $TEST_NGINX_MEMCACHED_PORT;
        content_by_lua '
            local test = require "test"
            local path = "$TEST_NGINX_HTML_DIR/nginx.sock";
            test.go(path, "A")
            test.go(path, "B")
        ';
    }
--- user_files
>>> test.lua
module("test", package.seeall)

function go(path, pool)
    local sock = njt.socket.tcp()
    local ok, err = sock:connect("unix:" .. path, {pool = pool})
    if not ok then
        njt.say("failed to connect: ", err)
        return
    end

    njt.say("connected: ", ok, ", reused: ", sock:getreusedtimes())

    local ok, err = sock:setkeepalive()
    if not ok then
        njt.say("failed to set reusable: ", err)
    end
end
--- request
GET /t
--- response_body
connected: 1, reused: 0
connected: 1, reused: 0
--- no_error_log eval
["[error]",
"lua tcp socket keepalive: free connection pool for ",
"lua tcp socket get keepalive peer: using connection"
]
--- error_log
lua tcp socket keepalive create connection pool for key "A"
lua tcp socket keepalive create connection pool for key "B"



=== TEST 18: custom pools (same pool for the same path) - unix
--- http_config eval
"
    lua_package_path '$::HtmlDir/?.lua;./?.lua;;';
    server {
        listen unix:$::HtmlDir/nginx.sock;
        default_type 'text/plain';

        server_tokens off;
    }
"
--- config
    location /t {
        set $port $TEST_NGINX_MEMCACHED_PORT;
        content_by_lua '
            local test = require "test"
            local path = "$TEST_NGINX_HTML_DIR/nginx.sock";
            test.go(path, "A")
            test.go(path, "A")
        ';
    }
--- user_files
>>> test.lua
module("test", package.seeall)

function go(path, pool)
    local sock = njt.socket.tcp()
    local ok, err = sock:connect("unix:" .. path, {pool = pool})
    if not ok then
        njt.say("failed to connect: ", err)
        return
    end

    njt.say("connected: ", ok, ", reused: ", sock:getreusedtimes())

    local ok, err = sock:setkeepalive()
    if not ok then
        njt.say("failed to set reusable: ", err)
    end
end
--- request
GET /t
--- response_body
connected: 1, reused: 0
connected: 1, reused: 1
--- no_error_log eval
["[error]",
"lua tcp socket keepalive: free connection pool for ",
]
--- error_log
lua tcp socket keepalive create connection pool for key "A"
lua tcp socket get keepalive peer: using connection



=== TEST 19: numeric pool option value
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
    location /t {
        set $port $TEST_NGINX_MEMCACHED_PORT;
        content_by_lua '
            local test = require "test"
            local port = njt.var.port
            test.go($TEST_NGINX_MEMCACHED_PORT, 3.14)
            test.go($TEST_NGINX_SERVER_PORT, 3.14)
        ';
    }
--- user_files
>>> test.lua
module("test", package.seeall)

function go(port, pool)
    local sock = njt.socket.tcp()
    local ok, err = sock:connect("127.0.0.1", port, {pool = pool})
    if not ok then
        njt.say("failed to connect: ", err)
        return
    end

    njt.say("connected: ", ok, ", reused: ", sock:getreusedtimes())

    local ok, err = sock:setkeepalive()
    if not ok then
        njt.say("failed to set reusable: ", err)
    end
end
--- request
GET /t
--- response_body
connected: 1, reused: 0
connected: 1, reused: 1
--- no_error_log eval
["[error]",
"lua tcp socket keepalive: free connection pool for ",
]
--- error_log
lua tcp socket keepalive create connection pool for key "3.14"
lua tcp socket get keepalive peer: using connection



=== TEST 20: nil pool option value
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
    location /t {
        set $port $TEST_NGINX_MEMCACHED_PORT;
        content_by_lua '
            local test = require "test"
            local port = njt.var.port
            test.go($TEST_NGINX_MEMCACHED_PORT, nil)
            test.go($TEST_NGINX_SERVER_PORT, nil)
        ';
    }
--- user_files
>>> test.lua
module("test", package.seeall)

function go(port, pool)
    local sock = njt.socket.tcp()
    local ok, err = sock:connect("127.0.0.1", port, {pool = pool})
    if not ok then
        njt.say("failed to connect: ", err)
        return
    end

    njt.say("connected: ", ok, ", reused: ", sock:getreusedtimes())

    local ok, err = sock:setkeepalive()
    if not ok then
        njt.say("failed to set reusable: ", err)
    end
end
--- request
GET /t
--- response_body
connected: 1, reused: 0
connected: 1, reused: 0
--- error_code: 200
--- no_error_log
[error]



=== TEST 21: (bad) table pool option value
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
    location /t {
        set $port $TEST_NGINX_MEMCACHED_PORT;
        content_by_lua '
            local test = require "test"
            local port = njt.var.port
            test.go($TEST_NGINX_MEMCACHED_PORT, {})
            test.go($TEST_NGINX_SERVER_PORT, {})
        ';
    }
--- user_files
>>> test.lua
module("test", package.seeall)

function go(port, pool)
    local sock = njt.socket.tcp()
    local ok, err = sock:connect("127.0.0.1", port, {pool = pool})
    if not ok then
        njt.say("failed to connect: ", err)
        return
    end

    njt.say("connected: ", ok, ", reused: ", sock:getreusedtimes())

    local ok, err = sock:setkeepalive()
    if not ok then
        njt.say("failed to set reusable: ", err)
    end
end
--- request
GET /t
--- response_body_like: 500 Internal Server Error
--- error_code: 500
--- error_log
bad argument #3 to 'connect' (bad "pool" option type: table)



=== TEST 22: (bad) boolean pool option value
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
    location /t {
        set $port $TEST_NGINX_MEMCACHED_PORT;
        content_by_lua '
            local test = require "test"
            local port = njt.var.port
            test.go($TEST_NGINX_MEMCACHED_PORT, true)
            test.go($TEST_NGINX_SERVER_PORT, false)
        ';
    }
--- user_files
>>> test.lua
module("test", package.seeall)

function go(port, pool)
    local sock = njt.socket.tcp()
    local ok, err = sock:connect("127.0.0.1", port, {pool = pool})
    if not ok then
        njt.say("failed to connect: ", err)
        return
    end

    njt.say("connected: ", ok, ", reused: ", sock:getreusedtimes())

    local ok, err = sock:setkeepalive()
    if not ok then
        njt.say("failed to set reusable: ", err)
    end
end
--- request
GET /t
--- response_body_like: 500 Internal Server Error
--- error_code: 500
--- error_log
bad argument #3 to 'connect' (bad "pool" option type: boolean)



=== TEST 23: clear the redis store
--- config
    location /t {
        redis2_query flushall;
        redis2_pass 127.0.0.1:$TEST_NGINX_REDIS_PORT;
    }
--- request
    GET /t
--- response_body eval
"+OK\r\n"
--- no_error_log
[error]
[alert]
[warn]



=== TEST 24: bug in send(): clear the chain writer ctx
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
    location /t {
        set $port $TEST_NGINX_REDIS_PORT;
        content_by_lua '
            local test = require "test"
            local port = njt.var.port
            test.go(port)
        ';
    }
--- user_files
>>> test.lua
module("test", package.seeall)

function go(port)
    local sock = njt.socket.tcp()
    local ok, err = sock:connect("127.0.0.1", port)
    if not ok then
        njt.say("failed to connect: ", err)
        return
    end

    local bytes, err = sock:send({})
    if err then
        njt.say("failed to send empty request: ", err)
        return
    end

    local req = "*2\r\n$3\r\nget\r\n$3\r\ndog\r\n"

    local bytes, err = sock:send(req)
    if not bytes then
        njt.say("failed to send request: ", err)
        return
    end

    local line, err, part = sock:receive()
    if line then
        njt.say("received: ", line)

    else
        njt.say("failed to receive a line: ", err, " [", part, "]")
    end

    local ok, err = sock:setkeepalive()
    if not ok then
        njt.say("failed to set reusable: ", err)
    end

    njt.say("done")
end
--- request
GET /t
--- stap2
global active
M(http-lua-socket-tcp-send-start) {
    active = 1
    printf("send [%s] %d\n", text_str(user_string_n($arg3, $arg4)), $arg4)
}
M(http-lua-socket-tcp-receive-done) {
    printf("receive [%s]\n", text_str(user_string_n($arg3, $arg4)))
}
F(njt_output_chain) {
    #printf("ctx->in: %s\n", njt_chain_dump($ctx->in))
    #printf("ctx->busy: %s\n", njt_chain_dump($ctx->busy))
    printf("output chain: %s\n", njt_chain_dump($in))
}
F(njt_linux_sendfile_chain) {
    printf("linux sendfile chain: %s\n", njt_chain_dump($in))
}
F(njt_chain_writer) {
    printf("chain writer ctx out: %p\n", $data)
    printf("nginx chain writer: %s\n", njt_chain_dump($in))
}
F(njt_http_lua_socket_tcp_setkeepalive) {
    delete active
}
M(http-lua-socket-tcp-setkeepalive-buf-unread) {
    printf("setkeepalive unread: [%s]\n", text_str(user_string_n($arg3, $arg4)))
}
probe syscall.recvfrom {
    if (active && pid() == target()) {
        printf("recvfrom(%s)", argstr)
    }
}
probe syscall.recvfrom.return {
    if (active && pid() == target()) {
        printf(" = %s, data [%s]\n", retstr, text_str(user_string_n($ubuf, $size)))
    }
}
probe syscall.writev {
    if (active && pid() == target()) {
        printf("writev(%s)", njt_iovec_dump($vec, $vlen))
        /*
        for (i = 0; i < $vlen; i++) {
            printf(" %p [%s]", $vec[i]->iov_base, text_str(user_string_n($vec[i]->iov_base, $vec[i]->iov_len)))
        }
        */
    }
}
probe syscall.writev.return {
    if (active && pid() == target()) {
        printf(" = %s\n", retstr)
    }
}
--- response_body
received: $-1
done
--- no_error_log
[error]



=== TEST 25: setkeepalive() with explicit nil args
--- config
   server_tokens off;
   location /t {
       lua_socket_keepalive_timeout 100ms;

        set $port $TEST_NGINX_SERVER_PORT;
        content_by_lua_block {
            local port = njt.var.port

            local sock = njt.socket.tcp()

            local ok, err = sock:connect("127.0.0.1", port)
            if not ok then
                njt.say("failed to connect: ", err)
                return
            end

            njt.say("connected: ", ok)

            local req = "GET /foo HTTP/1.1\r\nHost: localhost\r\nConnection: keepalive\r\n\r\n"

            local bytes, err = sock:send(req)
            if not bytes then
                njt.say("failed to send request: ", err)
                return
            end

            njt.say("request sent: ", bytes)

            local reader = sock:receiveuntil("\r\n0\r\n\r\n")
            local data, res = reader()

            if not data then
                njt.say("failed to receive response body: ", err)
                return
            end

            njt.say("received response of ", #data, " bytes")

            local ok, err = sock:setkeepalive(nil, nil)
            if not ok then
                njt.say("failed to set reusable: ", err)
            end

            njt.location.capture("/sleep")

            njt.say("done")
        }
    }

    location /foo {
        echo foo;
    }

    location /sleep {
        echo_sleep 1;
    }
--- request
GET /t
--- response_body
connected: 1
request sent: 61
received response of 156 bytes
done
--- no_error_log
[error]
--- error_log eval
["lua tcp socket keepalive close handler",
"lua tcp socket keepalive: free connection pool for ",
"lua tcp socket keepalive timeout: 100 ms",
qr/lua tcp socket connection pool size: 30\b/]
--- timeout: 4



=== TEST 26: conn queuing: connect() verifies the options for connection pool
--- config
    location /t {
        set $port $TEST_NGINX_SERVER_PORT;

        content_by_lua_block {
            local sock = njt.socket.tcp()
            local function check_opts_for_connect(opts)
                local ok, err = pcall(function()
                    sock:connect("127.0.0.1", njt.var.port, opts)
                end)
                if not ok then
                    njt.say(err)
                else
                    njt.say("ok")
                end
            end

            check_opts_for_connect({pool_size = 'a'})
            check_opts_for_connect({pool_size = 0})
            check_opts_for_connect({backlog = -1})
            check_opts_for_connect({backlog = 0})
        }
    }
--- request
GET /t
--- response_body_like
.+ 'connect' \(bad "pool_size" option type: string\)
.+ 'connect' \(bad "pool_size" option value: 0\)
.+ 'connect' \(bad "backlog" option value: -1\)
ok
--- no_error_log
[error]



=== TEST 27: conn queuing: connect() can specify 'pool_size' which overrides setkeepalive()
--- config
    location /t {
        set $port $TEST_NGINX_MEMCACHED_PORT;

        content_by_lua_block {
            local port = njt.var.port
            local function go()
                local sock = njt.socket.tcp()
                local ok, err = sock:connect("127.0.0.1", port, {pool_size = 1})
                if not ok then
                    njt.say("failed to connect: ", err)
                    return
                end

                njt.say("connected: ", ok, ", reused: ", sock:getreusedtimes())

                local req = "flush_all\r\n"
                local bytes, err = sock:send(req)
                if not bytes then
                    njt.say("failed to send request: ", err)
                    return
                end
                njt.say("request sent: ", bytes)

                local line, err, part = sock:receive()
                if line then
                    njt.say("received: ", line)
                else
                    njt.say("failed to receive a line: ", err, " [", part, "]")
                end

                local ok, err = sock:setkeepalive(0, 20)
                if not ok then
                    njt.say("failed to set reusable: ", err)
                end
            end

            -- reuse ok
            go()
            go()

            local sock1 = njt.socket.connect("127.0.0.1", port)
            local sock2 = njt.socket.connect("127.0.0.1", port)
            local ok, err = sock1:setkeepalive(0, 20)
            if not ok then
                njt.say(err)
            end
            local ok, err = sock2:setkeepalive(0, 20)
            if not ok then
                njt.say(err)
            end

            -- the pool_size is 1 instead of 20
            sock1 = njt.socket.connect("127.0.0.1", port)
            sock2 = njt.socket.connect("127.0.0.1", port)
            njt.say("reused: ", sock1:getreusedtimes())
            njt.say("reused: ", sock2:getreusedtimes())
            sock1:setkeepalive(0, 20)
            sock2:setkeepalive(0, 20)
        }
    }
--- request
GET /t
--- response_body
connected: 1, reused: 0
request sent: 11
received: OK
connected: 1, reused: 1
request sent: 11
received: OK
reused: 1
reused: 0
--- no_error_log eval
["[error]",
"lua tcp socket keepalive: free connection pool for ",
"lua tcp socket connection pool size: 20"]
--- error_log eval
[qq{lua tcp socket keepalive create connection pool for key "127.0.0.1:$ENV{TEST_NGINX_MEMCACHED_PORT}"},
"lua tcp socket connection pool size: 1",
]



=== TEST 28: conn queuing: connect() can specify 'pool_size' for unix domain socket
--- http_config eval
"
    server {
        listen unix:$::HtmlDir/nginx.sock;
    }
"
--- config
    location /t {
        content_by_lua_block {
            local path = "unix:" .. "$TEST_NGINX_HTML_DIR/nginx.sock";
            local function go()
                local sock = njt.socket.tcp()
                local ok, err = sock:connect(path, {pool_size = 1})
                if not ok then
                    njt.say("failed to connect: ", err)
                    return
                end

                njt.say("connected: ", ok, ", reused: ", sock:getreusedtimes())

                local ok, err = sock:setkeepalive(0, 20)
                if not ok then
                    njt.say("failed to set reusable: ", err)
                end
            end

            go()
            go()

            local sock1 = njt.socket.connect(path)
            local sock2 = njt.socket.connect(path)
            local ok, err = sock1:setkeepalive(0, 20)
            if not ok then
                njt.say(err)
            end
            local ok, err = sock2:setkeepalive(0, 20)
            if not ok then
                njt.say(err)
            end

            -- the pool_size is 1 instead of 20
            sock1 = njt.socket.connect(path)
            sock2 = njt.socket.connect(path)
            njt.say("reused: ", sock1:getreusedtimes())
            njt.say("reused: ", sock2:getreusedtimes())
            sock1:setkeepalive(0, 20)
            sock2:setkeepalive(0, 20)
        }
    }
--- request
GET /t
--- response_body
connected: 1, reused: 0
connected: 1, reused: 1
reused: 1
reused: 0
--- no_error_log eval
["[error]",
"lua tcp socket keepalive: free connection pool for ",
"lua tcp socket connection pool size: 20"]
--- error_log eval
["lua tcp socket get keepalive peer: using connection",
'lua tcp socket keepalive create connection pool for key "unix:',
"lua tcp socket connection pool size: 1",
]



=== TEST 29: conn queuing: connect() can specify 'pool_size' for custom pool
--- config
    location /t {
        set $port $TEST_NGINX_MEMCACHED_PORT;

        content_by_lua_block {
            local port = njt.var.port
            local function go(pool)
                local sock = njt.socket.tcp()
                local ok, err = sock:connect("127.0.0.1", port, {pool = pool, pool_size = 1})
                if not ok then
                    njt.say("failed to connect: ", err)
                    return
                end

                njt.say("connected: ", pool, ", reused: ", sock:getreusedtimes())

                local ok, err = sock:setkeepalive(0, 20)
                if not ok then
                    njt.say("failed to set reusable: ", err)
                end
            end

            go('A')
            go('B')
            go('A')
            go('B')

            local sock1 = njt.socket.connect("127.0.0.1", port, {pool = 'A'})
            local sock2 = njt.socket.connect("127.0.0.1", port, {pool = 'A'})
            local ok, err = sock1:setkeepalive(0, 20)
            if not ok then
                njt.say(err)
            end
            local ok, err = sock2:setkeepalive(0, 20)
            if not ok then
                njt.say(err)
            end

            -- the pool_size is 1 instead of 20
            sock1 = njt.socket.connect("127.0.0.1", port, {pool = 'A'})
            sock2 = njt.socket.connect("127.0.0.1", port, {pool = 'A'})
            njt.say("reused: ", sock1:getreusedtimes())
            njt.say("reused: ", sock2:getreusedtimes())
            sock1:setkeepalive(0, 20)
            sock2:setkeepalive(0, 20)
        }
    }
--- request
GET /t
--- response_body
connected: A, reused: 0
connected: B, reused: 0
connected: A, reused: 1
connected: B, reused: 1
reused: 1
reused: 0
--- no_error_log eval
["[error]",
"lua tcp socket keepalive: free connection pool for ",
"lua tcp socket connection pool size: 20"]
--- error_log eval
[qq{lua tcp socket keepalive create connection pool for key "A"},
qq{lua tcp socket keepalive create connection pool for key "B"},
"lua tcp socket connection pool size: 1",
]



=== TEST 30: conn queuing: connect() uses lua_socket_pool_size as default if 'backlog' is given
--- config
    location /t {
        set $port $TEST_NGINX_MEMCACHED_PORT;
        lua_socket_pool_size 1234;

        content_by_lua_block {
            local port = njt.var.port
            local opts = {backlog = 0}
            local sock, err = njt.socket.connect("127.0.0.1", port, opts)
            if not sock then
                njt.say(err)
            else
                njt.say("ok")
            end
        }
    }
--- request
GET /t
--- response_body
ok
--- error_log
lua tcp socket connection pool size: 1234
--- no_error_log
[error]



=== TEST 31: conn queuing: more connect operations than 'backlog' size
--- config
    location /t {
        set $port $TEST_NGINX_MEMCACHED_PORT;

        content_by_lua_block {
            local port = njt.var.port
            local opts = {pool_size = 2, backlog = 0}
            local sock = njt.socket.connect("127.0.0.1", port, opts)
            local not_reused_socket, err = njt.socket.connect("127.0.0.1", port, opts)
            if not not_reused_socket then
                njt.say(err)
                return
            end
            -- burst
            local ok, err = njt.socket.connect("127.0.0.1", port, opts)
            if not ok then
                njt.say(err)
            end

            local ok, err = sock:setkeepalive()
            if not ok then
                njt.say(err)
                return
            end

            ok, err = sock:connect("127.0.0.1", port, opts)
            if not ok then
                njt.say(err)
            end
            njt.say("reused: ", sock:getreusedtimes())
            -- both queue and pool is full
            ok, err = njt.socket.connect("127.0.0.1", port, opts)
            if not ok then
                njt.say(err)
            end
        }
    }
--- request
GET /t
--- response_body
too many waiting connect operations
reused: 1
too many waiting connect operations
--- no_error_log
[error]



=== TEST 32: conn queuing: once 'pool_size' is reached and pool has 'backlog'
--- config
    location /t {
        set $port $TEST_NGINX_MEMCACHED_PORT;

        content_by_lua_block {
            local port = njt.var.port
            local opts = {pool_size = 2, backlog = 2}
            local sock1 = njt.socket.connect("127.0.0.1", port, opts)

            njt.timer.at(0, function(premature)
                local sock2, err = njt.socket.connect("127.0.0.1", port, opts)
                if not sock2 then
                    njt.log(njt.ERR, err)
                    return
                end

                njt.log(njt.WARN, "start to handle timer")
                njt.sleep(0.1)
                sock2:close()
                -- resume connect operation
                njt.log(njt.WARN, "continue to handle timer")
            end)

            njt.sleep(0.05)
            njt.log(njt.WARN, "start to handle cosocket")
            local sock3, err = njt.socket.connect("127.0.0.1", port, opts)
            if not sock3 then
                njt.say(err)
                return
            end
            njt.log(njt.WARN, "continue to handle cosocket")

            local req = "flush_all\r\n"
            local bytes, err = sock3:send(req)
            if not bytes then
                njt.say("failed to send request: ", err)
                return
            end
            njt.say("request sent: ", bytes)

            local line, err, part = sock3:receive()
            if line then
                njt.say("received: ", line)
            else
                njt.say("failed to receive a line: ", err, " [", part, "]")
            end

            local ok, err = sock3:setkeepalive()
            if not ok then
                njt.say("failed to set reusable: ", err)
            end
            njt.say("setkeepalive: OK")
        }
    }
--- request
GET /t
--- response_body
request sent: 11
received: OK
setkeepalive: OK
--- no_error_log
[error]
--- error_log
lua tcp socket queue connect operation for connection pool "127.0.0.1
--- grep_error_log eval: qr/(start|continue) to handle \w+/
--- grep_error_log_out
start to handle timer
start to handle cosocket
continue to handle timer
continue to handle cosocket



=== TEST 33: conn queuing: do not count failed connect operations
--- config
    resolver $TEST_NGINX_RESOLVER ipv6=off;
    resolver_timeout 3s;
    location /t {
        set $port $TEST_NGINX_MEMCACHED_PORT;

        content_by_lua_block {
            local port = njt.var.port
            local opts = {pool = "test", pool_size = 1, backlog = 0}

            local sock = njt.socket.tcp()
            sock:settimeouts(100, 3000, 3000)
            local ok, err = sock:connect("127.0.0.2", 12345, opts)
            if not ok then
                njt.say(err)
            end

            local sock, err = njt.socket.connect("127.0.0.1", port, opts)
            if not sock then
                njt.say(err)
            end
            njt.say("ok")
        }
    }
--- request
GET /t
--- error_log
lua tcp socket connect timed out, when connecting to
--- response_body
timeout
ok



=== TEST 34: conn queuing: connect until backlog is reached
--- config
    location /t {
        set $port $TEST_NGINX_MEMCACHED_PORT;

        content_by_lua_block {
            local port = njt.var.port
            local opts = {pool_size = 1, backlog = 1}
            local sock1 = njt.socket.connect("127.0.0.1", port, opts)

            njt.timer.at(0.01, function(premature)
                njt.log(njt.WARN, "start to handle timer")
                local sock2, err = njt.socket.connect("127.0.0.1", port, opts)
                if not sock2 then
                    njt.log(njt.ERR, err)
                    return
                end

                njt.sleep(0.02)
                local ok, err = sock2:close()
                if not ok then
                    njt.log(njt.ERR, err)
                end
                njt.log(njt.WARN, "continue to handle timer")
            end)

            njt.sleep(0.02)
            local sock3, err = njt.socket.connect("127.0.0.1", port, opts)
            if not sock3 then
                njt.say(err)
            end
            local ok, err = sock1:setkeepalive()
            if not ok then
                njt.say(err)
                return
            end
            njt.sleep(0.01) -- run sock2

            njt.log(njt.WARN, "start to handle cosocket")
            local sock3, err = njt.socket.connect("127.0.0.1", port, opts)
            if not sock3 then
                njt.say(err)
                return
            end
            njt.log(njt.WARN, "continue to handle cosocket")

            local ok, err = sock3:setkeepalive()
            if not ok then
                njt.say(err)
            end
        }
    }
--- request
GET /t
--- response_body
too many waiting connect operations
--- no_error_log
[error]
--- error_log
lua tcp socket queue connect operation for connection pool "127.0.0.1
--- grep_error_log eval: qr/queue connect operation for connection pool|(start|continue) to handle \w+/
--- grep_error_log_out
start to handle timer
queue connect operation for connection pool
start to handle cosocket
queue connect operation for connection pool
continue to handle timer
continue to handle cosocket



=== TEST 35: conn queuing: memory reuse for host in queueing connect operation ctx
--- config
    location /t {
        set $port $TEST_NGINX_MEMCACHED_PORT;

        content_by_lua_block {
            local port = njt.var.port
            local opts = {pool = "test", pool_size = 1, backlog = 3}
            local sock = njt.socket.connect("127.0.0.1", port, opts)

            njt.timer.at(0.01, function(premature)
                local sock, err = njt.socket.connect("0.0.0.0", port, opts)
                if not sock then
                    njt.log(njt.ERR, err)
                    return
                end

                local ok, err = sock:close()
                if not ok then
                    njt.log(njt.ERR, err)
                end
            end)

            njt.timer.at(0.015, function(premature)
                local sock, err = njt.socket.connect("127.0.0.1", port, opts)
                if not sock then
                    njt.log(njt.ERR, err)
                    return
                end

                local ok, err = sock:close()
                if not ok then
                    njt.log(njt.ERR, err)
                end
            end)

            njt.timer.at(0.02, function(premature)
                local sock, err = njt.socket.connect("0.0.0.0", port, opts)
                if not sock then
                    njt.log(njt.ERR, err)
                    return
                end

                local ok, err = sock:close()
                if not ok then
                    njt.log(njt.ERR, err)
                end
            end)

            njt.sleep(0.03)
            local ok, err = sock:setkeepalive()
            if not ok then
                njt.say(err)
                return
            end
            njt.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]
--- grep_error_log eval: qr/queue connect operation for connection pool/
--- grep_error_log_out
queue connect operation for connection pool
queue connect operation for connection pool
queue connect operation for connection pool



=== TEST 36: conn queuing: connect() returns error after connect operation resumed
--- config
    location /t {
        set $port $TEST_NGINX_MEMCACHED_PORT;

        content_by_lua_block {
            local port = njt.var.port
            local opts = {pool = "test", pool_size = 1, backlog = 1}
            local sock = njt.socket.connect("127.0.0.1", port, opts)

            njt.timer.at(0, function(premature)
                local sock, err = njt.socket.connect("", port, opts)
                if not sock then
                    njt.log(njt.WARN, err)
                end
            end)

            njt.sleep(0.01)
            -- use 'close' to force parsing host instead of reusing conn
            local ok, err = sock:close()
            if not ok then
                njt.say(err)
                return
            end
            njt.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]
--- error_log
failed to parse host name
--- grep_error_log eval: qr/queue connect operation for connection pool/
--- grep_error_log_out
queue connect operation for connection pool



=== TEST 37: conn queuing: in uthread
--- config
    location /t {
        set $port $TEST_NGINX_MEMCACHED_PORT;

        content_by_lua_block {
            local port = njt.var.port
            local opts = {pool_size = 1, backlog = 2}

            local conn_sock = function()
                local sock, err = njt.socket.connect("127.0.0.1", port, opts)
                if not sock then
                    njt.say(err)
                    return
                end
                njt.say("start to handle uthread")

                njt.sleep(0.01)
                sock:close()
                njt.say("continue to handle other uthread")
            end

            local sock, err = njt.socket.connect("127.0.0.1", port, opts)
            if not sock then
                njt.log(njt.ERR, err)
                return
            end

            local co1 = njt.thread.spawn(conn_sock)
            local co2 = njt.thread.spawn(conn_sock)
            local co3 = njt.thread.spawn(conn_sock)

            local ok, err = sock:setkeepalive()
            if not ok then
                njt.log(njt.ERR, err)
            end

            njt.thread.wait(co1)
            njt.thread.wait(co2)
            njt.thread.wait(co3)
            njt.say("all uthreads ok")
        }
    }
--- request
GET /t
--- response_body
too many waiting connect operations
start to handle uthread
continue to handle other uthread
start to handle uthread
continue to handle other uthread
all uthreads ok
--- no_error_log
[error]
--- grep_error_log eval: qr/queue connect operation for connection pool/
--- grep_error_log_out
queue connect operation for connection pool
queue connect operation for connection pool



=== TEST 38: conn queuing: in access_by_lua
--- config
    location /t {
        set $port $TEST_NGINX_MEMCACHED_PORT;

        access_by_lua_block {
            local port = njt.var.port
            local opts = {pool_size = 1, backlog = 2}

            local conn_sock = function()
                local sock, err = njt.socket.connect("127.0.0.1", port, opts)
                if not sock then
                    njt.say(err)
                    return
                end
                njt.say("start to handle uthread")

                njt.sleep(0.01)
                sock:close()
                njt.say("continue to handle other uthread")
            end

            local sock, err = njt.socket.connect("127.0.0.1", port, opts)
            if not sock then
                njt.log(njt.ERR, err)
                return
            end

            local co1 = njt.thread.spawn(conn_sock)
            local co2 = njt.thread.spawn(conn_sock)
            local co3 = njt.thread.spawn(conn_sock)

            local ok, err = sock:setkeepalive()
            if not ok then
                njt.log(njt.ERR, err)
            end

            njt.thread.wait(co1)
            njt.thread.wait(co2)
            njt.thread.wait(co3)
            njt.say("all uthreads ok")
        }
    }
--- request
GET /t
--- response_body
too many waiting connect operations
start to handle uthread
continue to handle other uthread
start to handle uthread
continue to handle other uthread
all uthreads ok
--- no_error_log
[error]
--- grep_error_log eval: qr/queue connect operation for connection pool/
--- grep_error_log_out
queue connect operation for connection pool
queue connect operation for connection pool



=== TEST 39: conn queuing: in rewrite_by_lua
--- config
    location /t {
        set $port $TEST_NGINX_MEMCACHED_PORT;

        rewrite_by_lua_block {
            local port = njt.var.port
            local opts = {pool_size = 1, backlog = 2}

            local conn_sock = function()
                local sock, err = njt.socket.connect("127.0.0.1", port, opts)
                if not sock then
                    njt.say(err)
                    return
                end
                njt.say("start to handle uthread")

                njt.sleep(0.01)
                sock:close()
                njt.say("continue to handle other uthread")
            end

            local sock, err = njt.socket.connect("127.0.0.1", port, opts)
            if not sock then
                njt.log(njt.ERR, err)
                return
            end

            local co1 = njt.thread.spawn(conn_sock)
            local co2 = njt.thread.spawn(conn_sock)
            local co3 = njt.thread.spawn(conn_sock)

            local ok, err = sock:setkeepalive()
            if not ok then
                njt.log(njt.ERR, err)
            end

            njt.thread.wait(co1)
            njt.thread.wait(co2)
            njt.thread.wait(co3)
            njt.say("all uthreads ok")
        }
    }
--- request
GET /t
--- response_body
too many waiting connect operations
start to handle uthread
continue to handle other uthread
start to handle uthread
continue to handle other uthread
all uthreads ok
--- no_error_log
[error]
--- grep_error_log eval: qr/queue connect operation for connection pool/
--- grep_error_log_out
queue connect operation for connection pool
queue connect operation for connection pool



=== TEST 40: conn queuing: in subrequest
--- config
    set $port $TEST_NGINX_MEMCACHED_PORT;

    location /t {
        content_by_lua_block {
            local port = njt.var.port
            njt.timer.at(0, function()
                local opts = {pool_size = 1, backlog = 2}
                local sock, err = njt.socket.connect("127.0.0.1", port, opts)
                if not sock then
                    njt.log(njt.ERR, err)
                    return
                end

                njt.sleep(0.1)
                local ok, err = sock:setkeepalive()
                if not ok then
                    njt.log(njt.ERR, err)
                end
            end)

            njt.sleep(0.01)
            local res1, res2, res3 = njt.location.capture_multi{
                {"/conn"}, {"/conn"}, {"/conn"}
            }
            njt.say(res1.body)
            njt.say(res2.body)
            njt.say(res3.body)
        }
    }

    location /conn {
        content_by_lua_block {
            local port = njt.var.port
            local sock, err = njt.socket.connect("127.0.0.1", port)
            if not sock then
                njt.print(err)
                return
            end
            local ok, err = sock:setkeepalive()
            if not ok then
                njt.print(err)
            else
                njt.print("ok")
            end
        }
    }
--- request
GET /t
--- response_body
ok
ok
too many waiting connect operations
--- no_error_log
[error]
--- grep_error_log eval: qr/queue connect operation for connection pool/
--- grep_error_log_out
queue connect operation for connection pool
queue connect operation for connection pool



=== TEST 41: conn queuing: timeouts when 'connect_timeout' is reached
--- config
    location /t {
        set $port $TEST_NGINX_MEMCACHED_PORT;

        content_by_lua_block {
            local port = njt.var.port
            local opts = {pool_size = 1, backlog = 1}
            local sock1 = njt.socket.connect("127.0.0.1", port, opts)

            local sock2 = njt.socket.tcp()
            sock2:settimeouts(10, 3000, 3000)
            local ok, err = sock2:connect("127.0.0.1", port, opts)
            if not ok then
                njt.say(err)
            end
        }
    }
--- request
GET /t
--- response_body
timeout
--- error_log eval
"lua tcp socket queued connect timed out, when trying to connect to 127.0.0.1:$ENV{TEST_NGINX_MEMCACHED_PORT}"



=== TEST 42: conn queuing: set timeout via lua_socket_connect_timeout
--- config
    lua_socket_connect_timeout 10ms;
    location /t {
        set $port $TEST_NGINX_MEMCACHED_PORT;

        content_by_lua_block {
            local port = njt.var.port
            local opts = {pool_size = 1, backlog = 1}
            local sock1 = njt.socket.connect("127.0.0.1", port, opts)

            local sock2 = njt.socket.tcp()
            local ok, err = sock2:connect("127.0.0.1", port, opts)
            if not ok then
                njt.say(err)
            end
        }
    }
--- request
GET /t
--- response_body
timeout
--- error_log eval
"lua tcp socket queued connect timed out, when trying to connect to 127.0.0.1:$ENV{TEST_NGINX_MEMCACHED_PORT}"



=== TEST 43: conn queuing: client aborting while connect operation is queued
--- config
    location /t {
        set $port $TEST_NGINX_MEMCACHED_PORT;

        content_by_lua_block {
            local port = njt.var.port
            local opts = {pool_size = 1, backlog = 1}
            local sock1 = njt.socket.connect("127.0.0.1", port, opts)

            local sock2 = njt.socket.tcp()
            sock2:settimeouts(3000, 3000, 3000)
            local ok, err = sock2:connect("127.0.0.1", port, opts)
            if not ok then
                njt.say(err)
            end
        }
    }
--- request
GET /t
--- ignore_response
--- timeout: 0.1
--- abort
--- no_error_log
[error]



=== TEST 44: conn queuing: resume next connect operation if resumed connect failed immediately
--- config
    location /t {
        set $port $TEST_NGINX_MEMCACHED_PORT;

        content_by_lua_block {
            local port = njt.var.port
            local opts = {pool = "test", pool_size = 1, backlog = 2}

            local conn_sock = function(should_timeout)
                local sock = njt.socket.tcp()
                local ok, err
                if should_timeout then
                    ok, err = sock:connect("", port, opts)
                else
                    ok, err = sock:connect("127.0.0.1", port, opts)
                end
                if not ok then
                    njt.say(err)
                    return
                end
                njt.say("connected in uthread")
                sock:close()
            end

            local sock, err = njt.socket.connect("127.0.0.1", port, opts)
            if not sock then
                njt.log(njt.ERR, err)
                return
            end

            local co1 = njt.thread.spawn(conn_sock, true)
            local co2 = njt.thread.spawn(conn_sock)

            local ok, err = sock:close()
            if not ok then
                njt.log(njt.ERR, err)
            end

            njt.thread.wait(co1)
            njt.thread.wait(co2)
            njt.say("ok")
        }
    }
--- request
GET /t
--- response_body
failed to parse host name "": no host
connected in uthread
ok
--- no_error_log
[error]



=== TEST 45: conn queuing: resume connect operation if resumed connect failed (timeout)
--- config
    resolver $TEST_NGINX_RESOLVER ipv6=off;
    resolver_timeout 3s;
    location /t {
        set $port $TEST_NGINX_MEMCACHED_PORT;

        content_by_lua_block {
            local port = njt.var.port
            local opts = {pool = "test", pool_size = 1, backlog = 1}

            local conn_sock = function(should_timeout)
                local sock = njt.socket.tcp()
                local ok, err
                if should_timeout then
                    sock:settimeouts(100, 3000, 3000)
                    ok, err = sock:connect("127.0.0.2", 12345, opts)
                else
                    ok, err = sock:connect("127.0.0.1", port, opts)
                end
                if not ok then
                    njt.say(err)
                    return
                end
                njt.say("connected in uthread")
                sock:close()
            end

            local co1 = njt.thread.spawn(conn_sock, true)
            local co2 = njt.thread.spawn(conn_sock)

            njt.thread.wait(co1)
            njt.thread.wait(co2)
            njt.say("ok")
        }
    }
--- request
GET /t
--- response_body
timeout
connected in uthread
ok
--- error_log
queue connect operation for connection pool "test"
lua tcp socket connect timed out, when connecting to



=== TEST 46: conn queuing: resume connect operation if resumed connect failed (could not be resolved)
--- config
    resolver 127.0.0.2:12345 ipv6=off;
    resolver_timeout 1s;
    location /t {
        set $port $TEST_NGINX_MEMCACHED_PORT;

        content_by_lua_block {
            local port = njt.var.port
            local opts = {pool = "test", pool_size = 1, backlog = 1}

            local conn_sock = function(should_timeout)
                local sock = njt.socket.tcp()
                local ok, err
                if should_timeout then
                    sock:settimeouts(1, 3000, 3000)
                    ok, err = sock:connect("agentzh.org", 80, opts)
                else
                    ok, err = sock:connect("127.0.0.1", port, opts)
                end
                if not ok then
                    njt.say(err)
                    return
                end
                njt.say("connected in uthread")
                sock:close()
            end

            local co1 = njt.thread.spawn(conn_sock, true)
            local co2 = njt.thread.spawn(conn_sock)

            njt.thread.wait(co1)
            njt.thread.wait(co2)
            njt.say("ok")
        }
    }
--- request
GET /t
--- response_body
agentzh.org could not be resolved (110: Operation timed out)
connected in uthread
ok
--- error_log
queue connect operation for connection pool "test"



=== TEST 47: conn queuing: resume connect operation if resumed connect failed (connection refused)
--- config
    location /t {
        set $port $TEST_NGINX_MEMCACHED_PORT;

        content_by_lua_block {
            local port = njt.var.port
            local opts = {pool = "test", pool_size = 1, backlog = 1}

            local conn_sock = function(should_timeout)
                local sock = njt.socket.tcp()
                local ok, err
                if should_timeout then
                    sock:settimeouts(100, 3000, 3000)
                    ok, err = sock:connect("127.0.0.1", 62345, opts)
                else
                    ok, err = sock:connect("127.0.0.1", port, opts)
                end
                if not ok then
                    njt.say(err)
                    return
                end
                njt.say("connected in uthread")
                sock:close()
            end

            local co1 = njt.thread.spawn(conn_sock, true)
            local co2 = njt.thread.spawn(conn_sock)

            njt.thread.wait(co1)
            njt.thread.wait(co2)
            njt.say("ok")
        }
    }
--- request
GET /t
--- response_body
connection refused
connected in uthread
ok
--- error_log
queue connect operation for connection pool "test"



=== TEST 48: conn queuing: resume connect operation if resumed connect failed (uthread aborted while resolving)
--- http_config
    lua_package_path '../lua-resty-core/lib/?.lua;../lua-resty-lrucache/lib/?.lua;;';
--- config
    resolver 127.0.0.1 ipv6=off;
    resolver_timeout 100s;
    set $port $TEST_NGINX_MEMCACHED_PORT;

    location /sub {
        content_by_lua_block {
            local semaphore = require "njt.semaphore"
            local sem = semaphore.new()

            local function f()
                sem:wait(0.1)
                njt.exit(0)
            end

            local opts = {pool = "test", pool_size = 1, backlog = 1}
            local port = njt.var.port
            njt.timer.at(0, function()
                sem:post()
                local sock2, err = njt.socket.connect("127.0.0.1", port, opts)
                package.loaded.for_timer_to_resume:post()
                if not sock2 then
                    njt.log(njt.ALERT, "resume connect failed: ", err)
                    return
                end

                njt.log(njt.INFO, "resume success")
            end)

            njt.thread.spawn(f)
            local sock1, err = njt.socket.connect("openresty.org", 80, opts)
            if not sock1 then
                njt.say(err)
                return
            end
        }
    }

    location /t {
        content_by_lua_block {
            local semaphore = require "njt.semaphore"
            local for_timer_to_resume = semaphore.new()
            package.loaded.for_timer_to_resume = for_timer_to_resume

            njt.location.capture("/sub")
            for_timer_to_resume:wait(0.1)
        }
    }
--- request
GET /t
--- no_error_log
[alert]
--- error_log
resume success



=== TEST 49: conn queuing: resume connect operation if resumed connect failed (uthread killed while resolving)
--- config
    resolver 127.0.0.1 ipv6=off;
    resolver_timeout 100s;
    set $port $TEST_NGINX_MEMCACHED_PORT;

    location /t {
        content_by_lua_block {
            local opts = {pool = "test", pool_size = 1, backlog = 1}
            local port = njt.var.port

            local function resolve()
                local sock1, err = njt.socket.connect("openresty.org", 80, opts)
                if not sock1 then
                    njt.say(err)
                    return
                end
            end

            local th = njt.thread.spawn(resolve)
            local ok, err = njt.thread.kill(th)
            if not ok then
                njt.log(njt.ALERT, "kill thread failed: ", err)
                return
            end

            local sock2, err = njt.socket.connect("127.0.0.1", port, opts)
            if not sock2 then
                njt.log(njt.ALERT, "resume connect failed: ", err)
                return
            end

            njt.log(njt.INFO, "resume success")
        }
    }
--- request
GET /t
--- no_error_log
[alert]
--- error_log
resume success



=== TEST 50: conn queuing: increase the counter for connections created before creating the pool with setkeepalive()
--- config
    set $port $TEST_NGINX_MEMCACHED_PORT;

    location /t {
        content_by_lua_block {
            local function connect()
                local sock, err = njt.socket.connect("127.0.0.1", njt.var.port)
                if not sock then
                    error("connect failed: " .. err)
                end

                return sock
            end

            local sock1 = connect()
            local sock2 = connect()
            assert(sock1:setkeepalive())
            assert(sock2:setkeepalive())

            local sock1 = connect()
            local sock2 = connect()
            assert(sock1:close())
            assert(sock2:close())

            njt.say("ok")
        }
    }
--- request
GET /t
--- no_error_log
[error]
--- response_body
ok



=== TEST 51: conn queuing: only decrease the counter for connections which were counted by the pool
--- config
    set $port $TEST_NGINX_MEMCACHED_PORT;

    location /t {
        content_by_lua_block {
            local function connect()
                local sock, err = njt.socket.connect("127.0.0.1", njt.var.port)
                if not sock then
                    error("connect failed: " .. err)
                end

                return sock
            end

            local sock1 = connect()
            local sock2 = connect()
            assert(sock1:setkeepalive(1000, 1))
            assert(sock2:setkeepalive(1000, 1))

            local sock1 = connect()
            local sock2 = connect()
            assert(sock1:close())
            assert(sock2:close())

            njt.say("ok")
        }
    }
--- request
GET /t
--- no_error_log
[error]
--- response_body
ok



=== TEST 52: conn queuing: clean up pending connect operations which are in queue
--- config
    set $port $TEST_NGINX_MEMCACHED_PORT;

    location /sub {
        content_by_lua_block {
            local opts = {pool = "test", pool_size = 1, backlog = 1}
            local sock, err = njt.socket.connect("127.0.0.1", njt.var.port, opts)
            if not sock then
                njt.say("connect failed: " .. err)
                return
            end

            local function f()
                assert(njt.socket.connect("127.0.0.1", njt.var.port, opts))
            end

            local th = njt.thread.spawn(f)
            local ok, err = njt.thread.kill(th)
            if not ok then
                njt.log(njt.ERR, "kill thread failed: ", err)
                return
            end

            sock:close()
        }
    }

    location /t {
        content_by_lua_block {
            njt.location.capture("/sub")
            -- let pending connect operation resumes first
            njt.sleep(0)
            njt.say("ok")
        }
    }
--- request
GET /t
--- no_error_log
[error]
--- error_log
lua tcp socket abort queueing
--- response_body
ok



=== TEST 53: custom pools in third parameters for unix domain socket
--- http_config eval
"
    lua_package_path '$::HtmlDir/?.lua;./?.lua;;';
    server {
        listen unix:$::HtmlDir/nginx.sock;
        default_type 'text/plain';

        server_tokens off;
        location /foo {
            echo foo;
            more_clear_headers Date;
        }
    }
"
--- config
    location /t {
        set $port $TEST_NGINX_MEMCACHED_PORT;
        content_by_lua '
            local test = require "test"
            local path = "$TEST_NGINX_HTML_DIR/nginx.sock";
            test.go(path, "A")
            test.go(path, "B")
        ';
    }
--- user_files
>>> test.lua
module("test", package.seeall)

function go(path, pool)
    local sock = njt.socket.tcp()
    local ok, err = sock:connect("unix:" .. path, nil, {pool = pool})
    if not ok then
        njt.say("failed to connect: ", err)
        return
    end

    njt.say("connected: ", ok, ", reused: ", sock:getreusedtimes())

    local ok, err = sock:setkeepalive()
    if not ok then
        njt.say("failed to set reusable: ", err)
    end
end
--- request
GET /t
--- response_body
connected: 1, reused: 0
connected: 1, reused: 0
--- no_error_log eval
["[error]",
"lua tcp socket keepalive: free connection pool for ",
"lua tcp socket get keepalive peer: using connection"
]
--- error_log
lua tcp socket keepalive create connection pool for key "A"
lua tcp socket keepalive create connection pool for key "B"
