# vim:set ft= ts=4 sw=4 et fdm=marker:

BEGIN {
    if (!defined $ENV{LD_PRELOAD}) {
        $ENV{LD_PRELOAD} = '';
    }

    if ($ENV{LD_PRELOAD} !~ /\bmockeagain\.so\b/) {
        $ENV{LD_PRELOAD} = "mockeagain.so $ENV{LD_PRELOAD}";
    }

    if ($ENV{MOCKEAGAIN} eq 'r') {
        $ENV{MOCKEAGAIN} = 'rw';

    } else {
        $ENV{MOCKEAGAIN} = 'w';
    }

    $ENV{TEST_NGINX_EVENT_TYPE} = 'poll';
    $ENV{MOCKEAGAIN_WRITE_TIMEOUT_PATTERN} = 'get helloworld';
}

use Test::Nginx::Socket::Lua::Stream;
use t::StapThread;

our $GCScript = $t::StapThread::GCScript;
our $StapScript = $t::StapThread::StapScript;

repeat_each(2);

plan tests => repeat_each() * (blocks() * 4 + 9);

our $HtmlDir = html_dir;

$ENV{TEST_NGINX_MEMCACHED_PORT} ||= 11211;
$ENV{TEST_NGINX_RESOLVER} ||= '8.8.8.8';

log_level("debug");
no_long_string();
#no_diff();
run_tests();

__DATA__

=== TEST 1: lua_socket_connect_timeout only
--- stream_server_config
    lua_socket_connect_timeout 100ms;
    resolver $TEST_NGINX_RESOLVER ipv6=off;
    resolver_timeout 3s;
    content_by_lua_block {
        local sock = njt.socket.tcp()
        local ok, err = sock:connect("127.0.0.2", 12345)
        if not ok then
            njt.say("failed to connect: ", err)
            return
        end

        njt.say("connected: ", ok)
    }
--- stream_response
failed to connect: timeout
--- error_log
lua tcp socket connect timeout: 100
stream lua tcp socket connect timed out, when connecting to 127.0.0.2:12345
--- timeout: 10



=== TEST 2: sock:settimeout() overrides lua_socket_connect_timeout
--- stream_server_config
    lua_socket_connect_timeout 60s;
    resolver $TEST_NGINX_RESOLVER ipv6=off;
    resolver_timeout 3s;
    content_by_lua_block {
        local sock = njt.socket.tcp()
        sock:settimeout(150)
        local ok, err = sock:connect("127.0.0.2", 12345)
        if not ok then
            njt.say("failed to connect: ", err)
            return
        end

        njt.say("connected: ", ok)
    }
--- stream_response
failed to connect: timeout
--- error_log
lua tcp socket connect timeout: 150
stream lua tcp socket connect timed out, when connecting to 127.0.0.2:12345
--- timeout: 10



=== TEST 3: sock:settimeout(nil) does not override lua_socket_connect_timeout
--- stream_server_config
    lua_socket_connect_timeout 102ms;
    resolver $TEST_NGINX_RESOLVER ipv6=off;
    content_by_lua_block {
        local sock = njt.socket.tcp()
        sock:settimeout(nil)
        local ok, err = sock:connect("127.0.0.2", 12345)
        if not ok then
            njt.say("failed to connect: ", err)
            return
        end

        njt.say("connected: ", ok)
    }
--- stream_response
failed to connect: timeout
--- error_log
lua tcp socket connect timeout: 102
stream lua tcp socket connect timed out, when connecting to 127.0.0.2:12345



=== TEST 4: sock:settimeout(0) does not override lua_socket_connect_timeout
--- stream_server_config
    lua_socket_connect_timeout 102ms;
    resolver $TEST_NGINX_RESOLVER ipv6=off;
    resolver_timeout 3s;
    content_by_lua_block {
        local sock = njt.socket.tcp()
        sock:settimeout(0)
        local ok, err = sock:connect("127.0.0.2", 12345)
        if not ok then
            njt.say("failed to connect: ", err)
            return
        end

        njt.say("connected: ", ok)
    }
--- stream_response
failed to connect: timeout
--- error_log
lua tcp socket connect timeout: 102
stream lua tcp socket connect timed out, when connecting to 127.0.0.2:12345
--- timeout: 10



=== TEST 5: -1 is bad timeout value
--- stream_server_config
    lua_socket_connect_timeout 102ms;
    resolver $TEST_NGINX_RESOLVER ipv6=off;
    content_by_lua_block {
        local sock = njt.socket.tcp()
        sock:settimeout(-1)
        local ok, err = sock:connect("127.0.0.2", 12345)
        if not ok then
            njt.say("failed to connect: ", err)
            return
        end

        njt.say("connected: ", ok)
    }
--- error_log
bad timeout value
finalize stream request: 500



=== TEST 6: lua_socket_read_timeout only
--- stream_server_config
    lua_socket_read_timeout 100ms;
    resolver $TEST_NGINX_RESOLVER ipv6=off;
    content_by_lua_block {
        local sock = njt.socket.tcp()
        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_MEMCACHED_PORT)
        if not ok then
            njt.say("failed to connect: ", err)
            return
        end

        njt.say("connected: ", ok)

        local line
        line, err = sock:receive()
        if line then
            njt.say("received: ", line)
        else
            njt.say("failed to receive: ", err)
        end
    }
--- stream_response
connected: 1
failed to receive: timeout
--- error_log
lua tcp socket read timeout: 100
lua tcp socket connect timeout: 60000
lua tcp socket read timed out



=== TEST 7: sock:settimeout() overrides lua_socket_read_timeout
--- stream_server_config
    lua_socket_read_timeout 60s;
    content_by_lua_block {
        local sock = njt.socket.tcp()
        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_MEMCACHED_PORT)
        if not ok then
            njt.say("failed to connect: ", err)
            return
        end

        njt.say("connected: ", ok)

        sock:settimeout(150)

        local line
        line, err = sock:receive()
        if line then
            njt.say("received: ", line)
        else
            njt.say("failed to receive: ", err)
        end
    }
--- stream_response
connected: 1
failed to receive: timeout
--- error_log
lua tcp socket connect timeout: 60000
lua tcp socket read timeout: 150
lua tcp socket read timed out



=== TEST 8: sock:settimeout(nil) does not override lua_socket_read_timeout
--- stream_server_config
    lua_socket_read_timeout 102ms;
    content_by_lua_block {
        local sock = njt.socket.tcp()
        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_MEMCACHED_PORT)
        if not ok then
            njt.say("failed to connect: ", err)
            return
        end

        njt.say("connected: ", ok)

        sock:settimeout(nil)

        local line
        line, err = sock:receive()
        if line then
            njt.say("received: ", line)
        else
            njt.say("failed to receive: ", err)
        end
    }
--- stream_response
connected: 1
failed to receive: timeout
--- error_log
lua tcp socket connect timeout: 60000
lua tcp socket read timeout: 102
lua tcp socket read timed out



=== TEST 9: sock:settimeout(0) does not override lua_socket_read_timeout
--- stream_server_config
    lua_socket_read_timeout 102ms;
    content_by_lua_block {
        local sock = njt.socket.tcp()
        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_MEMCACHED_PORT)
        if not ok then
            njt.say("failed to connect: ", err)
            return
        end

        njt.say("connected: ", ok)

        sock:settimeout(0)

        local line
        line, err = sock:receive()
        if line then
            njt.say("received: ", line)
        else
            njt.say("failed to receive: ", err)
        end

    }
--- stream_response
connected: 1
failed to receive: timeout
--- error_log
lua tcp socket connect timeout: 60000
lua tcp socket read timeout: 102
lua tcp socket read timed out



=== TEST 10: -1 is bad timeout value
--- stream_server_config
    lua_socket_read_timeout 102ms;
    content_by_lua_block {
        local sock = njt.socket.tcp()
        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_MEMCACHED_PORT)
        if not ok then
            njt.say("failed to connect: ", err)
            return
        end

        njt.say("connected: ", ok)

        sock:settimeout(-1)

        local line
        line, err = sock:receive()
        if line then
            njt.say("received: ", line)
        else
            njt.say("failed to receive: ", err)
        end
    }
--- error_log
bad timeout value
finalize stream request: 500



=== TEST 11: lua_socket_send_timeout only
--- stream_server_config
    lua_socket_send_timeout 100ms;
    content_by_lua_block {
        local sock = njt.socket.tcp()
        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_MEMCACHED_PORT)
        if not ok then
            njt.say("failed to connect: ", err)
            return
        end

        njt.say("connected: ", ok)

        local bytes
        bytes, err = sock:send("get helloworld!")
        if bytes then
            njt.say("sent: ", bytes)
        else
            njt.say("failed to send: ", err)
        end
    }
--- stap2
global active = 0
F(njt_http_lua_socket_send) {
    active = 1
    println(probefunc())
}
probe syscall.send,
    syscall.sendto,
    syscall.writev
{
    if (active && pid() == target()) {
        println(probefunc())
    }
}
--- stream_response
connected: 1
failed to send: timeout
--- error_log
lua tcp socket send timeout: 100
lua tcp socket connect timeout: 60000
lua tcp socket write timed out



=== TEST 12: sock:settimeout() overrides lua_socket_send_timeout
--- stream_server_config
    lua_socket_send_timeout 60s;
    content_by_lua_block {
        local sock = njt.socket.tcp()
        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_MEMCACHED_PORT)
        if not ok then
            njt.say("failed to connect: ", err)
            return
        end

        njt.say("connected: ", ok)

        sock:settimeout(150)

        local bytes
        bytes, err = sock:send("get helloworld!")
        if bytes then
            njt.say("sent: ", bytes)
        else
            njt.say("failed to send: ", err)
        end
    }
--- stream_response
connected: 1
failed to send: timeout
--- error_log
lua tcp socket connect timeout: 60000
lua tcp socket send timeout: 150
lua tcp socket write timed out



=== TEST 13: sock:settimeout(nil) does not override lua_socket_send_timeout
--- stream_server_config
    lua_socket_send_timeout 102ms;
    content_by_lua_block {
        local sock = njt.socket.tcp()
        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_MEMCACHED_PORT)
        if not ok then
            njt.say("failed to connect: ", err)
            return
        end

        njt.say("connected: ", ok)

        sock:settimeout(nil)

        local bytes
        bytes, err = sock:send("get helloworld!")
        if bytes then
            njt.say("sent: ", bytes)
        else
            njt.say("failed to send: ", err)
        end
    }
--- stream_response
connected: 1
failed to send: timeout
--- error_log
lua tcp socket connect timeout: 60000
lua tcp socket send timeout: 102
lua tcp socket write timed out



=== TEST 14: sock:settimeout(0) does not override lua_socket_send_timeout
--- stream_server_config
    lua_socket_send_timeout 102ms;
    content_by_lua_block {
        local sock = njt.socket.tcp()
        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_MEMCACHED_PORT)
        if not ok then
            njt.say("failed to connect: ", err)
            return
        end

        njt.say("connected: ", ok)

        sock:settimeout(0)

        local bytes
        bytes, err = sock:send("get helloworld!")
        if bytes then
            njt.say("sent: ", bytes)
        else
            njt.say("failed to send: ", err)
        end
    }
--- stream_response
connected: 1
failed to send: timeout
--- error_log
lua tcp socket connect timeout: 60000
lua tcp socket send timeout: 102
lua tcp socket write timed out



=== TEST 15: sock:settimeout(-1) does not override lua_socket_send_timeout
--- stream_server_config
    lua_socket_send_timeout 102ms;
    content_by_lua_block {
        local sock = njt.socket.tcp()
        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_MEMCACHED_PORT)
        if not ok then
            njt.say("failed to connect: ", err)
            return
        end

        njt.say("connected: ", ok)

        sock:settimeout(-1)

        local bytes
        bytes, err = sock:send("get helloworld!")
        if bytes then
            njt.say("sent: ", bytes)
        else
            njt.say("failed to send: ", err)
        end
    }
--- error_log
bad timeout value
finalize stream request: 500



=== TEST 16: exit in user thread (entry thread is still pending on tcpsock:send)
--- stream_server_config
    content_by_lua_block {
        function f()
            njt.say("hello in thread")
            njt.sleep(0.1)
            njt.exit(0)
        end

        njt.say("before")
        njt.thread.spawn(f)
        njt.say("after")
        local sock = njt.socket.tcp()

        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_MEMCACHED_PORT)
        if not ok then
            njt.say("failed to connect: ", err)
            return
        end

        sock:settimeout(12000)

        local bytes, ok = sock:send("get helloworld!")
        if not bytes then
            njt.say("failed to send: ", err)
            return
        end

        njt.say("end")
    }
--- stap2 eval: $::StapScript
--- stap eval
<<'_EOC_' . $::GCScript;

global timers

F(njt_http_free_request) {
    println("free request")
}

M(timer-add) {
    if ($arg2 == 12000 || $arg2 == 100) {
        timers[$arg1] = $arg2
        printf("add timer %d\n", $arg2)
    }
}

M(timer-del) {
    tm = timers[$arg1]
    if (tm == 12000 || tm == 100) {
        printf("delete timer %d\n", tm)
        delete timers[$arg1]
    }
}

M(timer-expire) {
    tm = timers[$arg1]
    if (tm == 12000 || tm == 100) {
        printf("expire timer %d\n", timers[$arg1])
        delete timers[$arg1]
    }
}

F(njt_http_lua_coctx_cleanup) {
    println("lua tcp socket cleanup")
}
_EOC_

--- stap_out
create 2 in 1
spawn user thread 2 in 1
add timer 100
add timer 12000
expire timer 100
terminate 2: ok
delete thread 2
lua tcp socket cleanup
delete timer 12000
delete thread 1
free request

--- stream_response
before
hello in thread
after
--- no_error_log
[error]



=== TEST 17: re-connect after timed out
--- stream_server_config
    lua_socket_connect_timeout 100ms;
    resolver $TEST_NGINX_RESOLVER ipv6=off;
    resolver_timeout 3s;
    content_by_lua_block {
        local sock = njt.socket.tcp()
        local ok, err = sock:connect("127.0.0.2", 12345)
        if not ok then
            njt.say("1: failed to connect: ", err)

            local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_SERVER_PORT)
            if not ok then
                njt.say("2: failed to connect: ", err)
                return
            end

            njt.say("2: connected: ", ok)
            return
        end

        njt.say("1: connected: ", ok)
    }
--- stream_response
1: failed to connect: timeout
2: connected: 1
--- error_log
lua tcp socket connect timeout: 100
stream lua tcp socket connect timed out, when connecting to 127.0.0.2:12345
--- timeout: 10



=== TEST 18: re-send on the same object after a send timeout happens
--- stream_server_config
    #lua_socket_send_timeout 100ms;
    resolver $TEST_NGINX_RESOLVER ipv6=off;
    content_by_lua_block {
        local sock = njt.socket.tcp()
        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_MEMCACHED_PORT)
        if not ok then
            njt.say("failed to connect: ", err)
            return
        end

        njt.say("connected: ", ok)

        sock:settimeout(100)

        local bytes
        bytes, err = sock:send("get helloworld!")
        if bytes then
            njt.say("sent: ", bytes)
        else
            njt.say("failed to send: ", err)
            bytes, err = sock:send("blah")
            if not bytes then
                njt.say("failed to send again: ", err)
            end
        end
    }
--- stap2
global active = 0
F(njt_http_lua_socket_send) {
    active = 1
    println(probefunc())
}
probe syscall.send,
    syscall.sendto,
    syscall.writev
{
    if (active && pid() == target()) {
        println(probefunc())
    }
}
--- stream_response
connected: 1
failed to send: timeout
failed to send again: closed
--- error_log
lua tcp socket send timeout: 100
lua tcp socket connect timeout: 60000
lua tcp socket write timed out



=== TEST 19: abort when upstream sockets pending on writes
--- stream_server_config
    content_by_lua_block {
        local sock = njt.socket.tcp()
        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_MEMCACHED_PORT)
        if not ok then
            njt.say("failed to connect: ", err)
            return
        end

        njt.say("connected: ", ok)

        sock:settimeout(100)
        njt.thread.spawn(function () njt.sleep(0.001) njt.say("done") njt.exit(200) end)
        local bytes
        bytes, err = sock:send("get helloworld!")
        if bytes then
            njt.say("sent: ", bytes)
        else
            njt.say("failed to send: ", err)
        end
    }
--- stap2
global active = 0
F(njt_http_lua_socket_send) {
    active = 1
    println(probefunc())
}
probe syscall.send,
    syscall.sendto,
    syscall.writev
{
    if (active && pid() == target()) {
        println(probefunc())
    }
}
--- stream_response
connected: 1
done
--- error_log
lua tcp socket send timeout: 100
lua tcp socket connect timeout: 60000
--- no_error_log
lua tcp socket write timed out



=== TEST 20: abort when downstream socket pending on writes
--- stream_server_config
    resolver $TEST_NGINX_RESOLVER ipv6=off;
    #lua_lingering_timeout 10ms;

    content_by_lua_block {
        njt.flush(true)
        local sock, err = njt.req.socket(true)
        if not sock then
            njt.say("failed to acquire the req socket: ", err)
            return
        end

        sock:settimeout(100)
        njt.thread.spawn(function ()
            njt.sleep(0.001)
            njt.log(njt.WARN, "quitting request now")
            njt.exit(200)
        end)
        local bytes
        bytes, err = sock:send("e\r\nget helloworld!")
        if bytes then
            njt.say("sent: ", bytes)
        else
            njt.say("failed to send: ", err)
        end
    }
--- stap2
global active = 0
F(njt_http_lua_socket_send) {
    active = 1
    println(probefunc())
}
probe syscall.send,
    syscall.sendto,
    syscall.writev
{
    if (active && pid() == target()) {
        println(probefunc())
    }
}
--- stream_response_like chomp
^received [1-9]\d* bytes of response data\.$
--- log_stream_response
--- error_log
stream lua tcp socket send timeout: 100
quitting request now
--- no_error_log
lua tcp socket write timed out
[alert]



=== TEST 21: read timeout on receive(N)
--- stream_server_config
    lua_socket_read_timeout 100ms;
    resolver $TEST_NGINX_RESOLVER ipv6=off;
    content_by_lua_block {
        local sock = njt.socket.tcp()
        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_MEMCACHED_PORT)
        if not ok then
            njt.say("failed to connect: ", err)
            return
        end

        njt.say("connected: ", ok)

        sock:settimeout(10)

        local line
        line, err = sock:receive(3)
        if line then
            njt.say("received: ", line)
        else
            njt.say("failed to receive: ", err)
        end
    }
--- stream_response
connected: 1
failed to receive: timeout
--- error_log
lua tcp socket read timeout: 10
lua tcp socket connect timeout: 60000
lua tcp socket read timed out



=== TEST 22: concurrent operations while writing
--- stream_server_config
    lua_socket_log_errors off;
    content_by_lua_block {
        local sock = njt.socket.tcp()
        local ready = false

        local function f()
            while not ready do
                njt.sleep(0.001)
            end

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

            sock:settimeout(1)
            local res, err = sock:receive(1)
            njt.say("receive: ", res, " ", err)
        end

        local ok, err = njt.thread.spawn(f)
        if not ok then
            njt.say("failed to spawn writer thread: ", err)
            return
        end

        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_MEMCACHED_PORT)
        njt.say("connect: ", ok, " ", err)

        ready = true

        sock:settimeout(300)
        local bytes, err = sock:send("get helloworld!")
        if not bytes then
            njt.say("send failed: ", err)
        end

        local ok, err = sock:close()
        njt.say("close: ", ok, " ", err)
    }

--- stream_response
connect: 1 nil
send: nil socket busy writing
close: nil socket busy writing
getreusedtimes: 0 nil
setkeepalive: nil socket busy writing
connect: nil socket busy writing
receive: nil timeout
send failed: timeout
close: 1 nil

--- no_error_log
[error]
