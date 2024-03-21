# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;

repeat_each(2);

plan tests => repeat_each() * (blocks() * 3);

our $HtmlDir = html_dir;

$ENV{TEST_NGINX_MEMCACHED_PORT} ||= 11211;

no_long_string();
#no_diff();
#log_level 'warn';

run_tests();

__DATA__

=== TEST 1: read events come when socket is idle
--- stream_server_config
    content_by_lua_block {
        local sock = njt.socket.tcp()
        local port = $TEST_NGINX_SERVER_PORT

        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            njt.say("failed to connect: ", err)
            return
        end

        njt.say("connected: ", ok)

        local req = "GET /foo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            njt.say("failed to send request: ", err)
            return
        end
        njt.say("request sent: ", bytes)

        local reader = sock:receiveuntil("foofoo\r\n")
        local line, err, part = reader()
        if line then
            njt.print("read: ", line)

        else
            njt.say("failed to read a line: ", err, " [", part, "]")
        end

        njt.sleep(0.5)

        local data, err, part = sock:receive("*a")
        if not data then
            njt.say("failed to read the 2nd part: ", err)
        else
            njt.say("2nd part: [", data, "]")
        end

        ok, err = sock:close()
        njt.say("close: ", ok, " ", err)
    }

--- config
    server_tokens off;
    location = /foo {
        echo -n foofoo;
        echo_flush;
        echo_sleep 0.3;
        echo -n barbar;
        more_clear_headers Date;
    }
--- stream_response eval
qq{connected: 1
request sent: 57
read: HTTP/1.1 200 OK\r
Server: nginx\r
Content-Type: text/plain\r
Transfer-Encoding: chunked\r
Connection: close\r
\r
6\r
2nd part: [6\r
barbar\r
0\r
\r
]
close: 1 nil
}
--- no_error_log
[error]



=== TEST 2: read timer cleared in time
--- stream_server_config
    content_by_lua_block {
        local sock = njt.socket.tcp()
        local port = $TEST_NGINX_MEMCACHED_PORT

        sock:settimeout(400)

        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            njt.say("failed to connect: ", err)
            return
        end

        njt.say("connected: ", ok)

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

        njt.sleep(0.5)

        local bytes, err = sock:send(req)
        if not bytes then
            njt.say("failed to send request: ", err)
            return
        end
        njt.say("request sent again: ", bytes)

        ok, err = sock:close()
        njt.say("close: ", ok, " ", err)
    }

--- stream_response
connected: 1
request sent: 11
received: OK
request sent again: 11
close: 1 nil
--- no_error_log
[error]



=== TEST 3: connect timer cleared in time
--- stream_server_config
    content_by_lua_block {
        local sock = njt.socket.tcp()
        local port = $TEST_NGINX_MEMCACHED_PORT

        sock:settimeout(300)

        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            njt.say("failed to connect: ", err)
            return
        end

        njt.say("connected: ", ok)

        njt.sleep(0.5)

        local req = "flush_all\r\n"
        local bytes, err = sock:send(req)
        if not bytes then
            njt.say("failed to send request: ", err)
            return
        end
        njt.say("request sent: ", bytes)

        ok, err = sock:close()
        njt.say("close: ", ok, " ", err)
    }

--- stream_response
connected: 1
request sent: 11
close: 1 nil
--- no_error_log
[error]



=== TEST 4: send timer cleared in time
--- stream_server_config
    content_by_lua_block {
        local sock = njt.socket.tcp()
        local port = $TEST_NGINX_MEMCACHED_PORT

        sock:settimeout(300)

        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            njt.say("failed to connect: ", err)
            return
        end

        njt.say("connected: ", ok)

        local req = "flush_all\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            njt.say("failed to send request: ", err)
            return
        end
        njt.say("request sent: ", bytes)

        njt.sleep(0.5)

        local line, err, part = sock:receive()
        if line then
            njt.say("received: ", line)

        else
            njt.say("failed to receive a line: ", err, " [", part, "]")
            return
        end

        ok, err = sock:close()
        njt.say("close: ", ok, " ", err)
    }

--- stream_response
connected: 1
request sent: 11
received: OK
close: 1 nil
--- no_error_log
[error]



=== TEST 5: set keepalive when system socket recv buffer has unread data
--- stream_server_config
    content_by_lua_block {
        local sock = njt.socket.tcp()
        local port = $TEST_NGINX_SERVER_PORT

        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            njt.say("failed to connect: ", err)
            return
        end

        njt.say("connected: ", ok)

        local req = "GET /foo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            njt.say("failed to send request: ", err)
            return
        end
        njt.say("request sent: ", bytes)

        local reader = sock:receiveuntil("foofoo\r\n")
        local line, err, part = reader()
        if line then
            njt.print("read: ", line)

        else
            njt.say("failed to read a line: ", err, " [", part, "]")
        end

        njt.sleep(0.5)

        local ok, err = sock:setkeepalive()
        if not ok then
            njt.say("failed to set keepalive: ", err)
        end
    }

--- config
    server_tokens off;
    location = /foo {
        echo -n foofoo;
        echo_flush;
        echo_sleep 0.3;
        echo -n barbar;
        more_clear_headers Date;
    }
--- stream_response_like eval
qr{connected: 1
request sent: 57
read: HTTP/1\.1 200 OK\r
Server: nginx\r
Content-Type: text/plain\r
Transfer-Encoding: chunked\r
Connection: close\r
\r
6\r
failed to set keepalive: (?:unread data in buffer|connection in dubious state)
}
--- no_error_log
[error]



=== TEST 6: set keepalive when cosocket recv buffer has unread data
--- stream_server_config
    content_by_lua_block {
        local sock = njt.socket.tcp()
        local port = $TEST_NGINX_MEMCACHED_PORT

        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            njt.say("failed to connect: ", err)
            return
        end

        njt.say("connected: ", ok)

        local req = "flush_all\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            njt.say("failed to send request: ", err)
            return
        end

        njt.say("request sent: ", bytes)

        local data, err = sock:receive(1)
        if not data then
            njt.say("failed to read the 1st byte: ", err)
            return
        end

        njt.say("read: ", data)

        local ok, err = sock:setkeepalive()
        if not ok then
            njt.say("failed to set keepalive: ", err)
        end
    }

--- stream_response eval
qq{connected: 1
request sent: 11
read: O
failed to set keepalive: unread data in buffer
}
--- no_error_log
[error]
