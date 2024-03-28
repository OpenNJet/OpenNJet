# vim:set ft= ts=4 sw=4 et fdm=marker:
use Test::Nginx::Socket::Lua::Stream;
use t::StapThread;

our $GCScript = $t::StapThread::GCScript;
our $StapScript = $t::StapThread::StapScript;

#worker_connections(1014);
#master_on();
#workers(2);
#log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 8 + 45);

#no_diff();
no_long_string();

our $HtmlDir = html_dir;

$ENV{TEST_NGINX_MEMCACHED_PORT} ||= 11211;
$ENV{TEST_NGINX_HTML_DIR} = $HtmlDir;

worker_connections(1024);
run_tests();

__DATA__

=== TEST 1: simple at
--- stream_server_config
    content_by_lua_block {
        local begin = njt.now()
        local function f(premature)
            print("elapsed: ", njt.now() - begin)
            print("timer prematurely expired: ", premature)
        end
        local ok, err = njt.timer.at(0.05, f)
        if not ok then
            njt.say("failed to set timer: ", err)
            return
        end
        njt.say("registered timer")
    }

--- config
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
terminate 1: ok
delete thread 1
terminate 2: ok
delete thread 2

--- stream_response
registered timer

--- wait: 0.1
--- no_error_log
[error]
[alert]
[crit]
timer prematurely expired: true

--- error_log eval
[
qr/\[lua\] content_by_lua\(nginx\.conf:\d+\):\d+: elapsed: 0\.0(?:4[4-9]|5[0-6])\d*, context: njt\.timer, client: \d+\.\d+\.\d+\.\d+, server: 0\.0\.0\.0:\d+/,
"lua njt.timer expired",
"stream lua close fake stream connection",
"timer prematurely expired: false",
]



=== TEST 2: separated global env
--- stream_server_config
    content_by_lua_block {
        local begin = njt.now()
        local function f()
            foo = 3
            print("elapsed: ", njt.now() - begin)
        end
        local ok, err = njt.timer.at(0.05, f)
        if not ok then
            njt.say("failed to set timer: ", err)
            return
        end
        njt.say("registered timer")
        njt.sleep(0.06)
        njt.say("foo = ", foo)
    }

--- config
--- stap2
F(njt_stream_lua_timer_handler) {
    println("lua timer handler")
}

--- stream_response
registered timer
foo = 3

--- wait: 0.1
--- no_error_log
[error]
[alert]
[crit]

--- error_log eval
[
qr/\[lua\] content_by_lua\(nginx\.conf:\d+\):\d+: elapsed: 0\.0(?:4[4-9]|5[0-6])/,
"lua njt.timer expired",
"stream lua close fake stream connection"
]



=== TEST 3: lua variable sharing via upvalue
--- stream_server_config
    content_by_lua_block {
        local begin = njt.now()
        local foo
        local function f()
            foo = 3
            print("elapsed: ", njt.now() - begin)
        end
        local ok, err = njt.timer.at(0.05, f)
        if not ok then
            njt.say("failed to set timer: ", err)
            return
        end
        njt.say("registered timer")
        njt.sleep(0.06)
        njt.say("foo = ", foo)
    }

--- config
--- stap2
F(njt_stream_lua_timer_handler) {
    println("lua timer handler")
}

--- stream_response
registered timer
foo = 3

--- wait: 0.1
--- no_error_log
[error]
[alert]
[crit]

--- error_log eval
[
qr/\[lua\] content_by_lua\(nginx\.conf:\d+\):\d+: elapsed: 0\.0(?:4[4-9]|5[0-6])/,
"stream lua njt.timer expired",
"stream lua close fake stream connection"
]



=== TEST 4: simple at (sleep in the timer callback)
--- stream_server_config
    content_by_lua_block {
        local begin = njt.now()
        local function f()
            print("my lua timer handler")
            njt.sleep(0.02)
            print("elapsed: ", njt.now() - begin)
        end
        local ok, err = njt.timer.at(0.05, f)
        if not ok then
            njt.say("failed to set timer: ", err)
            return
        end
        njt.say("registered timer")
    }

--- config
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
terminate 1: ok
delete thread 1
terminate 2: ok
delete thread 2

--- stream_response
registered timer

--- wait: 0.12
--- no_error_log
[error]
[alert]
[crit]

--- error_log eval
[
qr/\[lua\] .*? my lua timer handler/,
qr/\[lua\] content_by_lua\(nginx\.conf:\d+\):\d+: elapsed: 0\.0(?:6[4-9]|7[0-9]|8[0-6])/,
"lua njt.timer expired",
"stream lua close fake stream connection"
]



=== TEST 5: tcp cosocket in timer handler (short connections)
--- stream_server_config
    content_by_lua_block {
        local begin = njt.now()
        local function fail(...)
            njt.log(njt.ERR, ...)
        end
        local function f()
            print("my lua timer handler")
            local sock = njt.socket.tcp()
            local port = $TEST_NGINX_SERVER_PORT
            local ok, err = sock:connect("127.0.0.1", port)
            if not ok then
                fail("failed to connect: ", err)
                return
            end

            print("connected: ", ok)

            local req = "GET /foo HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            -- req = "OK"

            local bytes, err = sock:send(req)
            if not bytes then
                fail("failed to send request: ", err)
                return
            end

            print("request sent: ", bytes)

            while true do
                local line, err, part = sock:receive()
                if line then
                    print("received: ", line)

                else
                    if err == "closed" then
                        break
                    end
                    fail("failed to receive a line: ", err, " [", part, "]")
                    break
                end
            end

            ok, err = sock:close()
            print("close: ", ok, " ", err)
        end
        local ok, err = njt.timer.at(0.05, f)
        if not ok then
            njt.say("failed to set timer: ", err)
            return
        end
        njt.say("registered timer")
    }

--- config
    server_tokens off;
    location = /foo {
    content_by_lua_block { njt.say("foo") }
        more_clear_headers Date;
    }

--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
terminate 1: ok
delete thread 1
terminate 1: ok
delete thread 1
terminate 2: ok
delete thread 2

--- stream_response
registered timer

--- wait: 0.2
--- no_error_log
[error]
[alert]
[crit]

--- error_log eval
[
qr/\[lua\] .*? my lua timer handler/,
"lua njt.timer expired",
"stream lua close fake stream connection",
"connected: 1",
"request sent: 57",
"received: HTTP/1.1 200 OK",
qr/received: Server: \S+/,
"received: Content-Type: text/plain",
"received: Content-Length: 4",
"received: Connection: close",
"received: foo",
"close: 1 nil",
]



=== TEST 6: tcp cosocket in timer handler (keep-alive connections)
--- stream_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"

--- stream_server_config
    content_by_lua_block {
        local begin = njt.now()
        local function f()
            print("my lua timer handler")

            local test = require "test"
            local port = $TEST_NGINX_MEMCACHED_PORT
            test.go(port)
        end
        local ok, err = njt.timer.at(0.05, f)
        if not ok then
            njt.say("failed to set timer: ", err)
            return
        end
        njt.say("registered timer")
    }

--- config

--- user_files
>>> test.lua
module("test", package.seeall)

local function fail(...)
    njt.log(njt.ERR, ...)
end

function go(port)
    local sock = njt.socket.tcp()
    local ok, err = sock:connect("127.0.0.1", port)
    if not ok then
        fail("failed to connect: ", err)
        return
    end

    print("connected: ", ok, ", reused: ", sock:getreusedtimes())

    local req = "flush_all\r\n"

    local bytes, err = sock:send(req)
    if not bytes then
        fail("failed to send request: ", err)
        return
    end
    print("request sent: ", bytes)

    local line, err, part = sock:receive()
    if line then
        print("received: ", line)

    else
        fail("failed to receive a line: ", err, " [", part, "]")
    end

    local ok, err = sock:setkeepalive()
    if not ok then
        fail("failed to set reusable: ", err)
    end
end

--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
terminate 1: ok
delete thread 1
terminate 2: ok
delete thread 2

--- stream_response
registered timer

--- wait: 0.2
--- no_error_log
[error]
[alert]
[crit]

--- error_log eval
[
qr/\[lua\] .*? my lua timer handler/,
"lua njt.timer expired",
"stream lua close fake stream connection",
qr/go\(\): connected: 1, reused: \d+/,
"go(): request sent: 11",
"go(): received: OK",
]



=== TEST 7: 0 timer
--- stream_server_config
    content_by_lua_block {
        local begin = njt.now()
        local function f()
            print("elapsed: ", njt.now() - begin)
        end
        local ok, err = njt.timer.at(0, f)
        if not ok then
            njt.say("failed to set timer: ", err)
            return
        end
        njt.say("registered timer")
    }

--- config
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
terminate 1: ok
delete thread 1
terminate 2: ok
delete thread 2

--- stream_response
registered timer

--- wait: 0.2
--- no_error_log
[error]
[alert]
[crit]

--- error_log eval
[
qr/\[lua\] content_by_lua\(nginx\.conf:\d+\):\d+: elapsed: 0(?:[^.]|\.00)/,
"lua njt.timer expired",
"stream lua close fake stream connection"
]



=== TEST 8: udp cosocket in timer handler
--- stream_server_config
    content_by_lua_block {
        local begin = njt.now()
        local function fail(...)
            njt.log(njt.ERR, ...)
        end
        local function f()
            print("my lua timer handler")
            local socket = njt.socket
            -- local socket = require "socket"

            local udp = socket.udp()

            local port = $TEST_NGINX_MEMCACHED_PORT
            udp:settimeout(1000) -- 1 sec

            local ok, err = udp:setpeername("127.0.0.1", port)
            if not ok then
                fail("failed to connect: ", err)
                return
            end

            print("connected: ", ok)

            local req = "\0\1\0\0\0\1\0\0flush_all\r\n"
            local ok, err = udp:send(req)
            if not ok then
                fail("failed to send: ", err)
                return
            end

            local data, err = udp:receive()
            if not data then
                fail("failed to receive data: ", err)
                return
            end
            print("received ", #data, " bytes: ", data)
        end
        local ok, err = njt.timer.at(0.05, f)
        if not ok then
            njt.say("failed to set timer: ", err)
            return
        end
        njt.say("registered timer")
    }

--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
terminate 1: ok
delete thread 1
terminate 2: ok
delete thread 2

--- stream_response
registered timer

--- wait: 0.2
--- no_error_log
[error]
[alert]
[crit]

--- error_log eval
[
qr/\[lua\] .*? my lua timer handler/,
"lua njt.timer expired",
"stream lua close fake stream connection",
"connected: 1",
"received 12 bytes: \x{00}\x{01}\x{00}\x{00}\x{00}\x{01}\x{00}\x{00}OK\x{0d}\x{0a}"
]



=== TEST 9: simple at (sleep in the timer callback) - log_by_lua
TODO
--- SKIP
--- stream_server_config
        echo hello world;
    log_by_lua_block {
        local begin = njt.now()
        local function f()
            print("my lua timer handler")
            njt.sleep(0.02)
            print("elapsed: ", njt.now() - begin)
        end
        local ok, err = njt.timer.at(0.05, f)
        if not ok then
            njt.log(njt.ERR, "failed to set timer: ", err)
            return
        end
        print("registered timer")
    }

--- config
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
terminate 2: ok
delete thread 2

--- stream_response
hello world

--- wait: 0.12
--- no_error_log
[error]
[alert]
[crit]

--- error_log eval
[
"registered timer",
qr/\[lua\] .*? my lua timer handler/,
qr/\[lua\] log_by_lua\(nginx\.conf:\d+\):\d+: elapsed: 0\.0(?:6[4-9]|7[0-6])/,
"lua njt.timer expired",
"stream lua close fake stream connection"
]



=== TEST 10: tcp cosocket in timer handler (keep-alive connections) - log_by_lua
TODO
--- SKIP
--- stream_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"

--- stream_server_config
    log_by_lua_block {
        local begin = njt.now()
        local function f()
            print("my lua timer handler")

            local test = require "test"
            local port = $TEST_NGINX_MEMCACHED_PORT
            test.go(port)
        end
        local ok, err = njt.timer.at(0.05, f)
        if not ok then
            njt.log(njt.ERR, "failed to set timer: ", err)
            return
        end
        print("registered timer")
    }

--- config

--- user_files
>>> test.lua
module("test", package.seeall)

local function fail(...)
    njt.log(njt.ERR, ...)
end

function go(port)
    local sock = njt.socket.tcp()
    local ok, err = sock:connect("127.0.0.1", port)
    if not ok then
        fail("failed to connect: ", err)
        return
    end

    print("connected: ", ok, ", reused: ", sock:getreusedtimes())

    local req = "flush_all\r\n"

    local bytes, err = sock:send(req)
    if not bytes then
        fail("failed to send request: ", err)
        return
    end
    print("request sent: ", bytes)

    local line, err, part = sock:receive()
    if line then
        print("received: ", line)

    else
        fail("failed to receive a line: ", err, " [", part, "]")
    end

    local ok, err = sock:setkeepalive()
    if not ok then
        fail("failed to set reusable: ", err)
    end
end

--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
terminate 2: ok
delete thread 2

--- stream_response
hello

--- wait: 0.2
--- no_error_log
[error]
[alert]
[crit]

--- error_log eval
[
"registered timer",
qr/\[lua\] .*? my lua timer handler/,
"lua njt.timer expired",
"stream lua close fake stream connection",
qr/go\(\): connected: 1, reused: \d+/,
"go(): request sent: 11",
"go(): received: OK",
]



=== TEST 11: coroutine API
--- stream_server_config
    content_by_lua_block {
        local cc, cr, cy = coroutine.create, coroutine.resume, coroutine.yield
        local function f()
            function f()
                local cnt = 0
                for i = 1, 20 do
                    print("cnt = ", cnt)
                    cy()
                    cnt = cnt + 1
                end
            end

            local c = cc(f)
            for i=1,3 do
                cr(c)
                print("after resume, i = ", i)
            end
        end
        local ok, err = njt.timer.at(0.05, f)
        if not ok then
            njt.say("failed to set timer: ", err)
            return
        end
        njt.say("registered timer")
    }

--- config
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
terminate 1: ok
delete thread 1
create 3 in 2
terminate 2: ok
delete thread 2

--- stream_response
registered timer

--- wait: 0.1
--- no_error_log
[error]
[alert]
[crit]

--- error_log eval
[
"lua njt.timer expired",
"stream lua close fake stream connection",
"cnt = 0",
"after resume, i = 1",
"cnt = 1",
"after resume, i = 2",
"cnt = 2",
"after resume, i = 3",
]



=== TEST 12: njt.thread API
--- stream_server_config
    content_by_lua_block {
        local function fail (...)
            njt.log(njt.ERR, ...)
        end
        local function handle()
            function f()
                print("hello in thread")
                return "done"
            end

            local t, err = njt.thread.spawn(f)
            if not t then
                fail("failed to spawn thread: ", err)
                return
            end

            print("thread created: ", coroutine.status(t))

            collectgarbage()

            local ok, res = njt.thread.wait(t)
            if not ok then
                fail("failed to run thread: ", res)
                return
            end

            print("wait result: ", res)
        end
        local ok, err = njt.timer.at(0.01, handle)
        if not ok then
            njt.say("failed to set timer: ", err)
            return
        end
        njt.say("registered timer")
    }

--- config
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
terminate 1: ok
delete thread 1
create 3 in 2
spawn user thread 3 in 2
terminate 3: ok
delete thread 3
terminate 2: ok
delete thread 2

--- stream_response
registered timer

--- wait: 0.1
--- no_error_log
[error]
[alert]
[crit]

--- error_log eval
[
"lua njt.timer expired",
"stream lua close fake stream connection",
"hello in thread",
"thread created: zombie",
"wait result: done",
]



=== TEST 13: shared dict
--- stream_config
    lua_shared_dict dogs 1m;
--- stream_server_config
    content_by_lua_block {
        local function f()
            local dogs = njt.shared.dogs
            dogs:set("foo", 32)
            dogs:set("bah", 10502)
            local val = dogs:get("foo")
            print("get foo: ", val, " ", type(val))
            val = dogs:get("bah")
            print("get bah: ", val, " ", type(val))
        end
        local ok, err = njt.timer.at(0.05, f)
        if not ok then
            njt.say("failed to set timer: ", err)
            return
        end
        njt.say("registered timer")
    }

--- config
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
terminate 1: ok
delete thread 1
terminate 2: ok
delete thread 2

--- stream_response
registered timer

--- wait: 0.1
--- no_error_log
[error]
[alert]
[crit]

--- error_log eval
[
"lua njt.timer expired",
"stream lua close fake stream connection",
"get foo: 32 number",
"get bah: 10502 number",
]



=== TEST 14: njt.exit(0)
--- stream_server_config
    content_by_lua_block {
        local function f()
            local function g()
                print("BEFORE njt.exit")
                njt.exit(0)
            end
            g()
            print("CANNOT REACH HERE")
        end
        local ok, err = njt.timer.at(0.05, f)
        if not ok then
            njt.say("failed to set timer: ", err)
            return
        end
        njt.say("registered timer")
    }

--- config
--- stap2
F(njt_stream_lua_timer_handler) {
    println("lua timer handler")
}

--- stream_response
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]

--- error_log eval
[
"lua njt.timer expired",
"stream lua close fake stream connection",
"BEFORE njt.exit",
]
--- no_error_log
CANNOT REACH HERE
API disabled



=== TEST 15: njt.exit(403)
--- stream_server_config
    content_by_lua_block {
        local function f()
            local function g()
                print("BEFORE njt.exit")
                njt.exit(403)
            end
            g()
            print("CANNOT REACH HERE")
        end
        local ok, err = njt.timer.at(0.05, f)
        if not ok then
            njt.say("failed to set timer: ", err)
            return
        end
        njt.say("registered timer")
    }

--- config
--- stap2
F(njt_stream_lua_timer_handler) {
    println("lua timer handler")
}

--- stream_response
registered timer

--- wait: 0.1
--- no_error_log
[error]
[alert]
[crit]
CANNOT REACH HERE
API disabled

--- error_log eval
[
"lua njt.timer expired",
"stream lua close fake stream connection",
"BEFORE njt.exit",
]



=== TEST 16: exit in user thread (entry thread is still pending on njt.sleep)
--- stream_server_config
    content_by_lua_block {
        local function handle()
            local function f()
                print("hello in thread")
                njt.sleep(0.1)
                njt.exit(0)
            end

            print("BEFORE thread spawn")
            njt.thread.spawn(f)
            print("AFTER thread spawn")
            njt.sleep(1)
            print("entry thread END")
        end
        local ok, err = njt.timer.at(0.05, handle)
        if not ok then
            njt.say("failed to set timer: ", err)
            return
        end
        njt.say("registered timer")
    }

--- config
--- stap eval
<<'_EOC_' . $::GCScript;

global timers

F(njt_stream_free_request) {
    println("free request")
}

M(timer-add) {
    if ($arg2 == 1000 || $arg2 == 100) {
        timers[$arg1] = $arg2
        printf("add timer %d\n", $arg2)
    }
}

M(timer-del) {
    tm = timers[$arg1]
    if (tm == 1000 || tm == 100) {
        printf("delete timer %d\n", tm)
        delete timers[$arg1]
    }
    /*
    if (tm == 1000) {
        print_ubacktrace()
    }
    */
}

M(timer-expire) {
    tm = timers[$arg1]
    if (tm == 1000 || tm == 100) {
        printf("expire timer %d\n", timers[$arg1])
        delete timers[$arg1]
    }
}

F(njt_stream_lua_sleep_cleanup) {
    println("lua sleep cleanup")
}
_EOC_

--- stap_out_like chop
(?:create 2 in 1
terminate 1: ok
delete thread 1
free request
create 3 in 2
spawn user thread 3 in 2
add timer 100
add timer 1000
expire timer 100
terminate 3: ok
delete thread 3
lua sleep cleanup
delete timer 1000
delete thread 2|create 2 in 1
terminate 1: ok
delete thread 1
create 3 in 2
spawn user thread 3 in 2
add timer 100
add timer 1000
free request
expire timer 100
terminate 3: ok
delete thread 3
lua sleep cleanup
delete timer 1000
delete thread 2)$

--- stream_response
registered timer

--- wait: 0.2
--- no_error_log
[error]
[alert]
[crit]
API disabled
entry thread END

--- error_log eval
[
"lua njt.timer expired",
"stream lua close fake stream connection",
"BEFORE thread spawn",
"hello in thread",
"AFTER thread spawn",
]



=== TEST 17: chained timers (0 delay)
--- stream_server_config
    content_by_lua_block {
        local s = ""

        local function fail(...)
            njt.log(njt.ERR, ...)
        end

        local function g()
            s = s .. "[g]"
            print("trace: ", s)
        end

        local function f()
            local ok, err = njt.timer.at(0, g)
            if not ok then
                fail("failed to set timer: ", err)
                return
            end
            s = s .. "[f]"
        end
        local ok, err = njt.timer.at(0, f)
        if not ok then
            njt.say("failed to set timer: ", err)
            return
        end
        njt.say("registered timer")
        s = "[m]"
    }

--- config
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
terminate 1: ok
delete thread 1
create 3 in 2
terminate 2: ok
delete thread 2
terminate 3: ok
delete thread 3

--- stream_response
registered timer

--- wait: 0.1
--- no_error_log
[error]
[alert]
[crit]

--- error_log eval
[
'lua njt.timer expired',
'stream lua close fake stream connection',
qr/trace: \[m\]\[f\]\[g\], context: njt\.timer, client: \d+\.\d+\.\d+\.\d+, server: 0\.0\.0\.0:\d+/,
]



=== TEST 18: chained timers (non-zero delay)
--- stream_server_config
    content_by_lua_block {
        local s = ""

        local function fail(...)
            njt.log(njt.ERR, ...)
        end

        local function g()
            s = s .. "[g]"
            print("trace: ", s)
        end

        local function f()
            local ok, err = njt.timer.at(0.01, g)
            if not ok then
                fail("failed to set timer: ", err)
                return
            end
            s = s .. "[f]"
        end
        local ok, err = njt.timer.at(0.01, f)
        if not ok then
            njt.say("failed to set timer: ", err)
            return
        end
        njt.say("registered timer")
        s = "[m]"
    }

--- config
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
terminate 1: ok
delete thread 1
create 3 in 2
terminate 2: ok
delete thread 2
terminate 3: ok
delete thread 3

--- stream_response
registered timer

--- wait: 0.1
--- no_error_log
[error]
[alert]
[crit]

--- error_log
lua njt.timer expired
stream lua close fake stream connection
trace: [m][f][g]



=== TEST 19: multiple parallel timers
--- stream_server_config
    content_by_lua_block {
        local s = ""

        local function fail(...)
            njt.log(njt.ERR, ...)
        end

        local function g()
            s = s .. "[g]"
            print("trace: ", s)
        end

        local function f()
            s = s .. "[f]"
        end
        local ok, err = njt.timer.at(0.01, f)
        if not ok then
            fail("failed to set timer: ", err)
            return
        end
        local ok, err = njt.timer.at(0.01, g)
        if not ok then
            fail("failed to set timer: ", err)
            return
        end
        njt.say("registered timer")
        s = "[m]"
    }

--- config
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
create 3 in 1
terminate 1: ok
delete thread 1
terminate 2: ok
delete thread 2
terminate 3: ok
delete thread 3

--- stream_response
registered timer

--- wait: 0.1
--- no_error_log
[error]
[alert]
[crit]

--- error_log
lua njt.timer expired
stream lua close fake stream connection
trace: [m][f][g]



=== TEST 20: lua_max_pending_timers
--- stream_config
    lua_max_pending_timers 1;
--- stream_server_config
    content_by_lua_block {
        local s = ""

        local function fail(...)
            njt.log(njt.ERR, ...)
        end

        local function g()
            s = s .. "[g]"
            print("trace: ", s)
        end

        local function f()
            s = s .. "[f]"
        end
        local ok, err = njt.timer.at(0.01, f)
        if not ok then
            njt.say("failed to set timer f: ", err)
            return
        end
        local ok, err = njt.timer.at(0.01, g)
        if not ok then
            njt.say("failed to set timer g: ", err)
            return
        end
        njt.say("registered timer")
        s = "[m]"
    }

--- config
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
terminate 1: ok
delete thread 1
terminate 2: ok
delete thread 2

--- stream_response
failed to set timer g: too many pending timers

--- wait: 0.1
--- no_error_log
[alert]
[crit]
[error]

--- error_log
lua njt.timer expired
stream lua close fake stream connection



=== TEST 21: lua_max_pending_timers (just not exceeding)
--- stream_config
    lua_max_pending_timers 2;
--- stream_server_config
    content_by_lua_block {
        local s = ""

        local function fail(...)
            njt.log(njt.ERR, ...)
        end

        local function g()
            s = s .. "[g]"
            print("trace: ", s)
        end

        local function f()
            s = s .. "[f]"
        end
        local ok, err = njt.timer.at(0.01, f)
        if not ok then
            njt.say("failed to set timer f: ", err)
            return
        end
        local ok, err = njt.timer.at(0.01, g)
        if not ok then
            njt.say("failed to set timer g: ", err)
            return
        end
        njt.say("registered timer")
        s = "[m]"
    }

--- config
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
create 3 in 1
terminate 1: ok
delete thread 1
terminate 2: ok
delete thread 2
terminate 3: ok
delete thread 3

--- stream_response
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]
[error]

--- error_log
lua njt.timer expired
stream lua close fake stream connection
trace: [m][f][g]



=== TEST 22: lua_max_pending_timers - chained timers (non-zero delay) - not exceeding
--- stream_config
    lua_max_pending_timers 1;

--- stream_server_config
    content_by_lua_block {
        local s = ""

        local function fail(...)
            njt.log(njt.ERR, ...)
        end

        local function g()
            s = s .. "[g]"
            print("trace: ", s)
        end

        local function f()
            local ok, err = njt.timer.at(0.01, g)
            if not ok then
                fail("failed to set timer: ", err)
                return
            end
            s = s .. "[f]"
        end
        local ok, err = njt.timer.at(0.01, f)
        if not ok then
            njt.say("failed to set timer: ", err)
            return
        end
        njt.say("registered timer")
        s = "[m]"
    }

--- config
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
terminate 1: ok
delete thread 1
create 3 in 2
terminate 2: ok
delete thread 2
terminate 3: ok
delete thread 3

--- stream_response
registered timer

--- wait: 0.1
--- no_error_log
[error]
[alert]
[crit]

--- error_log
lua njt.timer expired
stream lua close fake stream connection
trace: [m][f][g]



=== TEST 23: lua_max_pending_timers - chained timers (zero delay) - not exceeding
--- stream_config
    lua_max_pending_timers 1;

--- stream_server_config
    content_by_lua_block {
        local s = ""

        local function fail(...)
            njt.log(njt.ERR, ...)
        end

        local function g()
            s = s .. "[g]"
            print("trace: ", s)
        end

        local function f()
            local ok, err = njt.timer.at(0, g)
            if not ok then
                fail("failed to set timer: ", err)
                return
            end
            s = s .. "[f]"
        end
        local ok, err = njt.timer.at(0, f)
        if not ok then
            njt.say("failed to set timer: ", err)
            return
        end
        njt.say("registered timer")
        s = "[m]"
    }

--- config
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
terminate 1: ok
delete thread 1
create 3 in 2
terminate 2: ok
delete thread 2
terminate 3: ok
delete thread 3

--- stream_response
registered timer

--- wait: 0.1
--- no_error_log
[error]
[alert]
[crit]

--- error_log
lua njt.timer expired
stream lua close fake stream connection
trace: [m][f][g]



=== TEST 24: lua_max_running_timers (just not enough)
--- stream_config
    lua_max_running_timers 1;
--- stream_server_config
    content_by_lua_block {
        local s = ""

        local function fail(...)
            njt.log(njt.ERR, ...)
        end

        local f, g

        g = function ()
            njt.sleep(0.01)
        end

        f = function ()
            njt.sleep(0.01)
        end
        local ok, err = njt.timer.at(0, f)
        if not ok then
            njt.say("failed to set timer f: ", err)
            return
        end
        local ok, err = njt.timer.at(0, g)
        if not ok then
            njt.say("failed to set timer g: ", err)
            return
        end
        njt.say("registered timer")
        s = "[m]"
    }

--- config
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
create 3 in 1
terminate 1: ok
delete thread 1
terminate 2: ok
delete thread 2

--- stream_response
registered timer

--- wait: 0.1
--- no_error_log
[crit]
[error]

--- error_log eval
[
qr/\[alert\] .*? 1 lua_max_running_timers are not enough/,
"lua njt.timer expired",
"stream lua close fake stream connection",
]



=== TEST 25: lua_max_running_timers (just enough)
--- stream_config
    lua_max_running_timers 2;
--- stream_server_config
    content_by_lua_block {
        local s = ""

        local function fail(...)
            njt.log(njt.ERR, ...)
        end

        local f, g

        g = function ()
            njt.sleep(0.01)
        end

        f = function ()
            njt.sleep(0.01)
        end
        local ok, err = njt.timer.at(0, f)
        if not ok then
            njt.say("failed to set timer f: ", err)
            return
        end
        local ok, err = njt.timer.at(0, g)
        if not ok then
            njt.say("failed to set timer g: ", err)
            return
        end
        njt.say("registered timer")
        s = "[m]"
    }

--- config
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
create 3 in 1
terminate 1: ok
delete thread 1
terminate 2: ok
delete thread 2
terminate 3: ok
delete thread 3

--- stream_response
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]
[error]

--- error_log
lua njt.timer expired
stream lua close fake stream connection



=== TEST 26: lua_max_running_timers (just enough) - 2
--- stream_config
    lua_max_running_timers 2;
--- stream_server_config
    content_by_lua_block {
        local s = ""

        local function fail(...)
            njt.log(njt.ERR, ...)
        end

        local f, g

        g = function ()
            njt.timer.at(0.02, f)
            njt.sleep(0.01)
        end

        f = function ()
            njt.sleep(0.01)
        end
        local ok, err = njt.timer.at(0, f)
        if not ok then
            njt.say("failed to set timer f: ", err)
            return
        end
        local ok, err = njt.timer.at(0, g)
        if not ok then
            njt.say("failed to set timer g: ", err)
            return
        end
        njt.say("registered timer")
        s = "[m]"
    }

--- config
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
create 3 in 1
terminate 1: ok
delete thread 1
create 4 in 3
terminate 2: ok
delete thread 2
terminate 3: ok
delete thread 3
terminate 4: ok
delete thread 4

--- stream_response
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]
[error]

--- error_log
lua njt.timer expired
stream lua close fake stream connection



=== TEST 27: user args
--- stream_server_config
    content_by_lua_block {
        local begin = njt.now()
        local function f(premature, a, b, c)
            print("elapsed: ", njt.now() - begin)
            print("timer prematurely expired: ", premature)
            print("timer user args: ", a, " ", b, " ", c)
        end
        local ok, err = njt.timer.at(0.05, f, 1, "hello", true)
        if not ok then
            njt.say("failed to set timer: ", err)
            return
        end
        njt.say("registered timer")
    }

--- config
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
terminate 1: ok
delete thread 1
terminate 2: ok
delete thread 2

--- stream_response
registered timer

--- wait: 0.1
--- no_error_log
[error]
[alert]
[crit]
timer prematurely expired: true

--- error_log eval
[
qr/\[lua\] content_by_lua\(nginx\.conf:\d+\):\d+: elapsed: 0\.0(?:4[4-9]|5[0-6])\d*, context: njt\.timer/,
"lua njt.timer expired",
"stream lua close fake stream connection",
"timer prematurely expired: false",
"timer user args: 1 hello true",
]



=== TEST 28: use of njt.ctx
--- stream_server_config
    content_by_lua_block {
        local begin = njt.now()
        local function f(premature)
            njt.ctx.s = "hello"
            print("elapsed: ", njt.now() - begin)
            print("timer prematurely expired: ", premature)
        end
        local ok, err = njt.timer.at(0, f)
        if not ok then
            njt.say("failed to set timer: ", err)
            return
        end
        njt.say("registered timer")
    }

--- config
--- stream_response
registered timer

--- wait: 0.1
--- no_error_log
[error]
[alert]
[crit]
timer prematurely expired: true

--- error_log eval
[
qr/\[lua\] content_by_lua\(nginx\.conf:\d+\):\d+: elapsed: .*?, context: njt\.timer/,
"lua njt.timer expired",
"stream lua close fake stream connection",
"timer prematurely expired: false",
"lua release njt.ctx at ref ",
]



=== TEST 29: syslog error log
--- stream_config
    #error_log syslog:server=127.0.0.1:12345 error;
--- stream_server_config
    content_by_lua_block {
        local function f()
            njt.log(njt.ERR, "Bad bad bad")
        end
        njt.timer.at(0, f)
        njt.sleep(0.001)
        njt.say("ok")
    }

--- config
--- log_level: error
--- error_log_file: syslog:server=127.0.0.1:12345
--- udp_listen: 12345
--- udp_query eval: qr/Bad bad bad/
--- udp_reply: hello
--- wait: 0.1
--- stream_response
ok
--- error_log
Bad bad bad
--- skip_nginx: 4: < 1.7.1



=== TEST 30: log function location when failed to run a timer
--- stream_config
    lua_max_running_timers 1;
--- stream_server_config
    content_by_lua_block {
        local function g()
            njt.sleep(0.01)
        end

        local function f()
            njt.sleep(0.01)
        end

        local ok, err = njt.timer.at(0, f)
        if not ok then
            njt.say("failed to create timer f: ", err)
            return
        end

        local ok, err = njt.timer.at(0, g)
        if not ok then
            njt.say("failed to create timer g: ", err)
            return
        end

        njt.say("ok")
    }
--- stream_response
ok
--- wait: 0.1
--- error_log eval
qr/\[alert\] .*? lua failed to run timer with function defined at =content_by_lua\(nginx.conf:\d+\):2: stream lua: 1 lua_max_running_timers are not enough/
--- no_error_log
[emerg]
[crit]
[error]
[warn]



=== TEST 31: log function location when failed to run a timer (anonymous function)
--- stream_config
    lua_max_running_timers 1;
--- stream_server_config
    content_by_lua_block {
        local function f()
            njt.sleep(0.01)
        end

        local ok, err = njt.timer.at(0, f)
        if not ok then
            njt.say("failed to set timer f: ", err)
            return
        end

        local ok, err = njt.timer.at(0, function()
            njt.sleep(0.01)
        end)

        if not ok then
            njt.say("failed to set timer: ", err)
            return
        end

        njt.say("ok")
    }
--- stream_response
ok
--- wait: 0.1
--- error_log eval
qr/\[alert\] .*? lua failed to run timer with function defined at =content_by_lua\(nginx.conf:\d+\):12: stream lua: 1 lua_max_running_timers are not enough/
--- no_error_log
[emerg]
[crit]
[error]
[warn]



=== TEST 32: log function location when failed to run a timer (lua file)
--- user_files
>>> test.lua
local _M = {}

function _M.run()
    njt.sleep(0.01)
end

return _M
--- stream_config
    lua_package_path '$TEST_NGINX_HTML_DIR/?.lua;./?.lua;;';
    lua_max_running_timers 1;
--- stream_server_config
    content_by_lua_block {
        local test = require "test"

        local ok, err = njt.timer.at(0, test.run)
        if not ok then
            njt.say("failed to set timer: ", err)
            return
        end

        local ok, err = njt.timer.at(0, test.run)
        if not ok then
            njt.say("failed to set timer: ", err)
            return
        end

        njt.say("ok")
    }
--- stream_response
ok
--- wait: 0.1
--- error_log eval
qr/\[alert\] .*? lua failed to run timer with function defined at @.+\/test.lua:3: stream lua: 1 lua_max_running_timers are not enough/
--- no_error_log
[emerg]
[crit]
[error]
[warn]



=== TEST 33: log function location when failed to run a timer with arg (lua file)
--- user_files
>>> test.lua
local _M = {}

function _M.run()
    njt.sleep(0.01)
end

return _M
--- stream_config
    lua_package_path '$TEST_NGINX_HTML_DIR/?.lua;./?.lua;;';
    lua_max_running_timers 1;
--- stream_server_config
    content_by_lua_block {
        local test = require "test"

        local ok, err = njt.timer.at(0, test.run, "arg")
        if not ok then
            njt.say("failed to set timer: ", err)
            return
        end

        local ok, err = njt.timer.at(0, test.run, "arg")
        if not ok then
            njt.say("failed to set timer: ", err)
            return
        end

        njt.say("ok")
    }
--- stream_response
ok
--- wait: 0.1
--- error_log eval
qr/\[alert\] .*? lua failed to run timer with function defined at @.+\/test.lua:3: stream lua: 1 lua_max_running_timers are not enough/
--- no_error_log
[emerg]
[crit]
[error]
[warn]
