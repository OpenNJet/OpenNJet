# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;
repeat_each(2);

plan tests => repeat_each() * (blocks() * 3 + 2);

our $HtmlDir = html_dir;

$ENV{TEST_NGINX_MEMCACHED_PORT} ||= 11211;
$ENV{TEST_NGINX_RESOLVER} ||= '8.8.8.8';

#log_level 'warn';
log_level 'debug';

no_long_string();
#no_diff();
run_tests();

__DATA__

=== TEST 1: pipelined memcached requests (sent one byte at a time)
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

        local req = "flush_all\r\nget foo\r\nget bar\r\n"
        -- req = "OK"
        local send_idx = 1

        local function writer()
            local sub = string.sub
            while send_idx <= #req do
                local bytes, err = sock:send(sub(req, send_idx, send_idx))
                if not bytes then
                    njt.say("failed to send request: ", err)
                    return
                end
                -- if send_idx % 2 == 0 then
                    njt.sleep(0.001)
                -- end
                send_idx = send_idx + 1
            end
            -- njt.say("request sent.")
        end

        local ok, err = njt.thread.spawn(writer)
        if not ok then
            njt.say("failed to spawn writer thread: ", err)
            return
        end

        for i = 1, 3 do
            local line, err, part = sock:receive()
            if line then
                njt.say("received: ", line)

            else
                njt.say("failed to receive a line: ", err, " [", part, "]")
                break
            end
        end

        ok, err = sock:setkeepalive()
        njt.say("setkeepalive: ", ok, " ", err)
    }

--- config
    server_tokens off;

--- stream_response
connected: 1
received: OK
received: END
received: END
setkeepalive: 1 nil

--- no_error_log
[error]



=== TEST 2: read timeout errors won't affect writing
--- stream_server_config
    lua_socket_log_errors off;

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
        -- req = "OK"
        local send_idx = 1

        sock:settimeout(1)

        local function writer()
            local sub = string.sub
            while send_idx <= #req do
                local bytes, err = sock:send(sub(req, send_idx, send_idx))
                if not bytes then
                    njt.say("failed to send request: ", err)
                    return
                end
                njt.sleep(0.001)
                send_idx = send_idx + 1
            end
            -- njt.say("request sent.")
        end

        local ok, err = njt.thread.spawn(writer)
        if not ok then
            njt.say("failed to spawn writer thread: ", err)
            return
        end

        local data = ""
        local ntm = 0
        local done = false
        for i = 1, 300 do
            local line, err, part = sock:receive()
            if not line then
                if part then
                    data = data .. part
                end
                if err ~= "timeout" then
                    njt.say("failed to receive: ", err)
                    return
                end

                ntm = ntm + 1

            else
                data = data .. line
                njt.say("received: ", data)
                done = true
                break
            end
        end

        if not done then
            njt.say("partial read: ", data)
        end

        njt.say("read timed out: ", ntm)
        ok, err = sock:close()
        njt.say("close: ", ok, " ", err)
    }

--- config
    server_tokens off;

--- stream_response_like chop
^connected: 1
(?:received: OK|failed to send request: timeout
partial read: )
read timed out: [1-9]\d*
close: 1 nil$

--- no_error_log
[error]



=== TEST 3: writes are rejected while reads are not
--- stream_server_config
    lua_socket_log_errors off;

    content_by_lua_block {
        local sock = njt.socket.tcp()
        local port = 7658
        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            njt.say("failed to connect: ", err)
            return
        end

        njt.say("connected: ", ok)

        local req = "flush_all\r\n"
        -- req = "OK"
        local send_idx = 1

        local function writer()
            local sub = string.sub
            while send_idx <= #req do
                local bytes, err = sock:send(sub(req, send_idx, send_idx))
                if not bytes then
                    njt.say("failed to send request: ", err)
                    return
                end
                njt.sleep(0.001)
                send_idx = send_idx + 1
            end
            -- njt.say("request sent.")
        end

        local ok, err = njt.thread.spawn(writer)
        if not ok then
            njt.say("failed to spawn writer thread: ", err)
            return
        end

        local data = ""
        local ntm = 0
        local done = false
        for i = 1, 3 do
            local res, err, part = sock:receive(1)
            if not res then
                njt.say("failed to receive: ", err)
                return
            else
                data = data .. res
            end
            njt.sleep(0.001)
        end

        njt.say("received: ", data)
        ok, err = sock:close()
        njt.say("close: ", ok, " ", err)
    }

--- config
    server_tokens off;

--- stream_response_like chop
^connected: 1
received: OK!
close: (?:nil socket busy writing|1 nil
failed to send request: closed)$

--- tcp_listen: 7658
--- tcp_shutdown: 0
--- tcp_reply: OK!
--- tcp_no_close: 1
--- no_error_log
[error]



=== TEST 4: reads are rejected while writes are not
--- stream_server_config
    lua_socket_log_errors off;

    content_by_lua_block {
        local sock = njt.socket.tcp()
        local port = 7658
        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            njt.say("failed to connect: ", err)
            return
        end

        njt.say("connected: ", ok)

        local req = "flush_all\r\n"
        -- req = "OK"
        local send_idx = 1

        local function writer()
            local sub = string.sub
            while send_idx <= #req do
                local bytes, err = sock:send(sub(req, send_idx, send_idx))
                if not bytes then
                    njt.say("failed to send request: ", err)
                    return
                end
                -- njt.say("sent: ", bytes)
                njt.sleep(0.001)
                send_idx = send_idx + 1
            end
            njt.say("request sent.")
            local ok, err = sock:close()
            njt.say("close: ", ok, " ", err)
        end

        local ok, err = njt.thread.spawn(writer)
        if not ok then
            njt.say("failed to spawn writer thread: ", err)
            return
        end

        local data = ""
        local ntm = 0
        local done = false
        for i = 1, 3 do
            local res, err, part = sock:receive(1)
            if not res then
                njt.say("failed to receive: ", err)
                return
            else
                data = data .. res
            end
            njt.sleep(0.001)
        end

        njt.say("received: ", data)
    }

--- config
    server_tokens off;

--- stream_response
connected: 1
failed to receive: closed
request sent.
close: 1 nil

--- stap2
F(njt_http_lua_socket_tcp_finalize_write_part) {
    print_ubacktrace()
}
--- stap_out2
--- tcp_listen: 7658
--- tcp_shutdown: 1
--- tcp_query eval: "flush_all\r\n"
--- tcp_query_len: 11
--- no_error_log
[error]



=== TEST 5: concurrent socket operations while connecting
--- stream_server_config
    lua_socket_log_errors off;
    resolver $TEST_NGINX_RESOLVER ipv6=off;
    content_by_lua_block {
        local sock = njt.socket.tcp()

        local function f()
            njt.sleep(0.001)
            local res, err = sock:receive(1)
            njt.say("receive: ", res, " ", err)

            local bytes, err = sock:send("hello")
            njt.say("send: ", bytes, " ", err)

            local ok, err = sock:close()
            njt.say("close: ", ok, " ", err)

            local ok, err = sock:getreusedtimes()
            njt.say("getreusedtimes: ", ok, " ", err)

            local ok, err = sock:setkeepalive()
            njt.say("setkeepalive: ", ok, " ", err)

            local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_MEMCACHED_PORT)
            njt.say("connect: ", ok, " ", err)
        end

        local ok, err = njt.thread.spawn(f)
        if not ok then
            njt.say("failed to spawn writer thread: ", err)
            return
        end

        sock:settimeout(300)
        local ok, err = sock:connect("127.0.0.2", 12345)
        njt.say("connect: ", ok, " ", err)

        local ok, err = sock:close()
        njt.say("close: ", ok, " ", err)
    }

--- config
    server_tokens off;

--- stream_response
receive: nil socket busy connecting
send: nil socket busy connecting
close: nil socket busy connecting
getreusedtimes: 0 nil
setkeepalive: nil socket busy connecting
connect: nil socket busy connecting
connect: nil timeout
close: nil closed

--- no_error_log
[error]



=== TEST 6: concurrent operations while resolving
--- stream_server_config
    lua_socket_log_errors off;
    resolver 127.0.0.2:12345;
    resolver_timeout 300ms;
    content_by_lua_block {
        local sock = njt.socket.tcp()

        local function f()
            njt.sleep(0.001)
            local res, err = sock:receive(1)
            njt.say("receive: ", res, " ", err)

            local bytes, err = sock:send("hello")
            njt.say("send: ", bytes, " ", err)

            local ok, err = sock:close()
            njt.say("close: ", ok, " ", err)

            local ok, err = sock:getreusedtimes()
            njt.say("getreusedtimes: ", ok, " ", err)

            local ok, err = sock:setkeepalive()
            njt.say("setkeepalive: ", ok, " ", err)

            local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_MEMCACHED_PORT)
            njt.say("connect: ", ok, " ", err)
        end

        local ok, err = njt.thread.spawn(f)
        if not ok then
            njt.say("failed to spawn writer thread: ", err)
            return
        end

        sock:settimeout(300)
        local ok, err = sock:connect("some2.agentzh.org", 80)
        njt.say("connect: ", ok, " ", err)

        local ok, err = sock:close()
        njt.say("close: ", ok, " ", err)
    }

--- config
    server_tokens off;

--- stream_response
receive: nil closed
send: nil closed
close: nil closed
getreusedtimes: nil closed
setkeepalive: nil closed
connect: nil socket busy connecting
connect: nil some2.agentzh.org could not be resolved (110: Operation timed out)
close: nil closed

--- no_error_log
[error]



=== TEST 7: concurrent operations while reading (receive)
--- stream_server_config
    lua_socket_log_errors off;
    content_by_lua_block {
        local sock = njt.socket.tcp()
        local ready = false

        local function f()
            while not ready do
                njt.sleep(0.001)
            end

            local res, err = sock:receive(1)
            njt.say("receive: ", res, " ", err)

            local bytes, err = sock:send("flush_all")
            njt.say("send: ", bytes, " ", err)

            local ok, err = sock:close()
            njt.say("close: ", ok, " ", err)

            local ok, err = sock:getreusedtimes()
            njt.say("getreusedtimes: ", ok, " ", err)

            local ok, err = sock:setkeepalive()
            njt.say("setkeepalive: ", ok, " ", err)

            local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_MEMCACHED_PORT)
            njt.say("connect: ", ok, " ", err)
        end

        local ok, err = njt.thread.spawn(f)
        if not ok then
            njt.say("failed to spawn writer thread: ", err)
            return
        end

        sock:settimeout(300)
        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_MEMCACHED_PORT)
        njt.say("connect: ", ok, " ", err)

        ready = true

        local res, err = sock:receive(1)
        njt.say("receive: ", res, " ", err)

        local ok, err = sock:close()
        njt.say("close: ", ok, " ", err)
    }

--- config
    server_tokens off;

--- stream_response
connect: 1 nil
receive: nil socket busy reading
send: 9 nil
close: nil socket busy reading
getreusedtimes: 0 nil
setkeepalive: nil socket busy reading
connect: nil socket busy reading
receive: nil timeout
close: 1 nil

--- no_error_log
[error]



=== TEST 8: concurrent operations while reading (receiveuntil)
--- stream_server_config
    lua_socket_log_errors off;
    content_by_lua_block {
        local ready = false
        local sock = njt.socket.tcp()

        local function f()
            while not ready do
                njt.sleep(0.001)
            end

            local res, err = sock:receive(1)
            njt.say("receive: ", res, " ", err)

            local bytes, err = sock:send("flush_all")
            njt.say("send: ", bytes, " ", err)

            local ok, err = sock:close()
            njt.say("close: ", ok, " ", err)

            local ok, err = sock:getreusedtimes()
            njt.say("getreusedtimes: ", ok, " ", err)

            local ok, err = sock:setkeepalive()
            njt.say("setkeepalive: ", ok, " ", err)

            local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_MEMCACHED_PORT)
            njt.say("connect: ", ok, " ", err)
        end

        local ok, err = njt.thread.spawn(f)
        if not ok then
            njt.say("failed to spawn writer thread: ", err)
            return
        end

        sock:settimeout(300)
        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_MEMCACHED_PORT)
        njt.say("connect: ", ok, " ", err)

        ready = true

        local it, err = sock:receiveuntil("\r\n")
        if not it then
            njt.say("receiveuntil() failed: ", err)
            return
        end

        local res, err = it()
        njt.say("receiveuntil() iterator: ", res, " ", err)

        local ok, err = sock:close()
        njt.say("close: ", ok, " ", err)
    }

--- config
    server_tokens off;

--- stream_response
connect: 1 nil
receive: nil socket busy reading
send: 9 nil
close: nil socket busy reading
getreusedtimes: 0 nil
setkeepalive: nil socket busy reading
connect: nil socket busy reading
receiveuntil() iterator: nil timeout
close: 1 nil

--- no_error_log
[error]
