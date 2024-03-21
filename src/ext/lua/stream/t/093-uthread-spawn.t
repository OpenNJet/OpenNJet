# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;use t::StapThread;

our $GCScript = $t::StapThread::GCScript;
our $StapScript = $t::StapThread::StapScript;

repeat_each(2);

plan tests => repeat_each() * (blocks() * 4 + 1);

$ENV{TEST_NGINX_RESOLVER} ||= '8.8.8.8';
$ENV{TEST_NGINX_MEMCACHED_PORT} ||= '11211';

#no_shuffle();
worker_connections(256);
no_long_string();
run_tests();

__DATA__

=== TEST 1: simple user thread without I/O
--- stream_server_config
    content_by_lua_block {
        function f()
            njt.say("hello in thread")
        end

        njt.say("before")
        njt.thread.spawn(f)
        njt.say("after")
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
spawn user thread 2 in 1
terminate 2: ok
terminate 1: ok
delete thread 2
delete thread 1

--- stream_response
before
hello in thread
after
--- no_error_log
[error]



=== TEST 2: two simple user threads without I/O
--- stream_server_config
    content_by_lua_block {
        function f()
            njt.say("in thread 1")
        end

        function g()
            njt.say("in thread 2")
        end

        njt.say("before 1")
        njt.thread.spawn(f)
        njt.say("after 1")

        njt.say("before 2")
        njt.thread.spawn(g)
        njt.say("after 2")
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
spawn user thread 2 in 1
terminate 2: ok
create 3 in 1
spawn user thread 3 in 1
terminate 3: ok
terminate 1: ok
delete thread 2
delete thread 3
delete thread 1

--- stream_response
before 1
in thread 1
after 1
before 2
in thread 2
after 2
--- no_error_log
[error]



=== TEST 3: simple user thread with sleep
--- stream_server_config
    content_by_lua_block {
        function f()
            njt.say("before sleep")
            njt.sleep(0.1)
            njt.say("after sleep")
        end

        njt.say("before thread create")
        njt.thread.spawn(f)
        njt.say("after thread create")
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
spawn user thread 2 in 1
terminate 1: ok
delete thread 1
terminate 2: ok
delete thread 2

--- stream_response
before thread create
before sleep
after thread create
after sleep
--- no_error_log
[error]



=== TEST 4: two simple user threads with sleep
--- stream_server_config
    content_by_lua_block {
        function f()
            njt.say("1: before sleep")
            njt.sleep(0.2)
            njt.say("1: after sleep")
        end

        function g()
            njt.say("2: before sleep")
            njt.sleep(0.1)
            njt.say("2: after sleep")
        end

        njt.say("1: before thread create")
        njt.thread.spawn(f)
        njt.say("1: after thread create")

        njt.say("2: before thread create")
        njt.thread.spawn(g)
        njt.say("2: after thread create")
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
spawn user thread 2 in 1
create 3 in 1
spawn user thread 3 in 1
terminate 1: ok
delete thread 1
terminate 3: ok
delete thread 3
terminate 2: ok
delete thread 2

--- wait: 0.1
--- stream_response
1: before thread create
1: before sleep
1: after thread create
2: before thread create
2: before sleep
2: after thread create
2: after sleep
1: after sleep
--- no_error_log
[error]



=== TEST 5: error in user thread
--- stream_server_config
    content_by_lua_block {
        function f()
            njt.blah()
        end

        njt.thread.spawn(f)
        njt.say("after")
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
spawn user thread 2 in 1
terminate 2: fail
terminate 1: ok
delete thread 2
delete thread 1

--- stream_response
after
--- error_log eval
qr/stream lua user thread aborted: runtime error: content_by_lua\(nginx\.conf:\d+\):3: attempt to call field 'blah' \(a nil value\)/



=== TEST 6: nested user threads
--- stream_server_config
    content_by_lua_block {
        function f()
            njt.say("before g")
            njt.thread.spawn(g)
            njt.say("after g")
        end

        function g()
            njt.say("hello in g()")
        end

        njt.say("before f")
        njt.thread.spawn(f)
        njt.say("after f")
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
spawn user thread 2 in 1
create 3 in 2
spawn user thread 3 in 2
terminate 3: ok
terminate 1: ok
delete thread 1
terminate 2: ok
delete thread 3
delete thread 2

--- stream_response
before f
before g
hello in g()
after f
after g
--- no_error_log
[error]



=== TEST 7: nested user threads (with I/O)
--- stream_server_config
    content_by_lua_block {
        function f()
            njt.say("before g")
            njt.thread.spawn(g)
            njt.say("after g")
        end

        function g()
            njt.sleep(0.1)
            njt.say("hello in g()")
        end

        njt.say("before f")
        njt.thread.spawn(f)
        njt.say("after f")
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
spawn user thread 2 in 1
create 3 in 2
spawn user thread 3 in 2
terminate 1: ok
delete thread 1
terminate 2: ok
delete thread 2
terminate 3: ok
delete thread 3

--- stream_response
before f
before g
after f
after g
hello in g()
--- no_error_log
[error]



=== TEST 8: coroutine status of a running user thread
--- stream_server_config
    content_by_lua_block {
        local co
        function f()
            co = coroutine.running()
            njt.sleep(0.1)
        end

        njt.thread.spawn(f)
        njt.say("status: ", coroutine.status(co))
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
spawn user thread 2 in 1
terminate 1: ok
delete thread 1
terminate 2: ok
delete thread 2

--- stream_response
status: running
--- no_error_log
[error]



=== TEST 9: coroutine status of a dead user thread
--- stream_server_config
    content_by_lua_block {
        local co
        function f()
            co = coroutine.running()
        end

        njt.thread.spawn(f)
        njt.say("status: ", coroutine.status(co))
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
spawn user thread 2 in 1
terminate 2: ok
terminate 1: ok
delete thread 2
delete thread 1

--- stream_response
status: zombie
--- no_error_log
[error]



=== TEST 10: coroutine status of a "normal" user thread
--- stream_server_config
    content_by_lua_block {
        local co
        function f()
            co = coroutine.running()
            local co2 = coroutine.create(g)
            coroutine.resume(co2)
        end

        function g()
            njt.sleep(0.1)
        end

        njt.thread.spawn(f)
        njt.say("status: ", coroutine.status(co))
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
spawn user thread 2 in 1
create 3 in 2
terminate 1: ok
delete thread 1
terminate 3: ok
terminate 2: ok
delete thread 2

--- stream_response
status: normal
--- no_error_log
[error]



=== TEST 11: creating user threads in a user coroutine
--- stream_server_config
    content_by_lua_block {
        function f()
            njt.say("before g")
            njt.thread.spawn(g)
            njt.say("after g")
        end

        function g()
            njt.say("hello in g()")
        end

        njt.say("before f")
        local co = coroutine.create(f)
        coroutine.resume(co)
        njt.say("after f")
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
create 3 in 2
spawn user thread 3 in 2
terminate 3: ok
terminate 2: ok
delete thread 3
terminate 1: ok
delete thread 1

--- stream_response
before f
before g
hello in g()
after g
after f
--- no_error_log
[error]



=== TEST 12: manual time slicing between a user thread and the entry thread
--- stream_server_config
    content_by_lua_block {
        local yield = coroutine.yield

        function f()
            local self = coroutine.running()
            njt.say("f 1")
            yield(self)
            njt.say("f 2")
            yield(self)
            njt.say("f 3")
        end

        local self = coroutine.running()
        njt.say("0")
        yield(self)
        njt.say("1")
        njt.thread.spawn(f)
        njt.say("2")
        yield(self)
        njt.say("3")
        yield(self)
        njt.say("4")
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
spawn user thread 2 in 1
terminate 2: ok
terminate 1: ok
delete thread 2
delete thread 1

--- stream_response
0
1
f 1
2
f 2
3
f 3
4
--- no_error_log
[error]



=== TEST 13: manual time slicing between two user threads
--- stream_server_config
    content_by_lua_block {
        local yield = coroutine.yield

        function f()
            local self = coroutine.running()
            njt.say("f 1")
            yield(self)
            njt.say("f 2")
            yield(self)
            njt.say("f 3")
        end

        function g()
            local self = coroutine.running()
            njt.say("g 1")
            yield(self)
            njt.say("g 2")
            yield(self)
            njt.say("g 3")
        end

        njt.thread.spawn(f)
        njt.thread.spawn(g)
        njt.say("done")
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
spawn user thread 2 in 1
create 3 in 1
spawn user thread 3 in 1
terminate 1: ok
delete thread 1
terminate 2: ok
delete thread 2
terminate 3: ok
delete thread 3

--- stream_response
f 1
g 1
f 2
done
g 2
f 3
g 3
--- no_error_log
[error]



=== TEST 14: entry thread and a user thread flushing at the same time
--- stream_server_config
    content_by_lua_block {
        function f()
            njt.say("hello in thread")
            coroutine.yield(coroutine.running)
            njt.flush(true)
        end

        njt.say("before")
        njt.thread.spawn(f)
        njt.say("after")
        njt.flush(true)
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
spawn user thread 2 in 1
terminate 1: ok
delete thread 1
terminate 2: ok
delete thread 2

--- stream_response
before
hello in thread
after
--- no_error_log
[error]



=== TEST 15: two user threads flushing at the same time
--- stream_server_config
    content_by_lua_block {
        function f()
            njt.say("hello from f")
            njt.flush(true)
        end

        function g()
            njt.say("hello from g")
            njt.flush(true)
        end

        njt.thread.spawn(f)
        njt.thread.spawn(g)
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out_like
^(?:create 2 in 1
spawn user thread 2 in 1
create 3 in 1
spawn user thread 3 in 1
terminate 1: ok
delete thread 1
terminate 2: ok
delete thread 2
terminate 3: ok
delete thread 3|create 2 in 1
spawn user thread 2 in 1
terminate 2: ok
create 3 in 1
spawn user thread 3 in 1
terminate 3: ok
terminate 1: ok
delete thread 2
delete thread 3
delete thread 1)$

--- stream_response
hello from f
hello from g
--- no_error_log
[error]



=== TEST 16: user threads + njt.socket.tcp
--- stream_server_config
    content_by_lua_block {
        function f()
            local sock = njt.socket.tcp()
            local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_MEMCACHED_PORT)
            if not ok then
                njt.say("failed to connect: ", err)
                return
            end
            local bytes, err = sock:send("flush_all\r\n")
            if not bytes then
                njt.say("failed to send query: ", err)
                return
            end

            local line, err = sock:receive()
            if not line then
                njt.say("failed to receive: ", err)
                return
            end

            njt.say("received: ", line)
        end

        njt.say("before")
        njt.thread.spawn(f)
        njt.say("after")
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
spawn user thread 2 in 1
terminate 1: ok
delete thread 1
terminate 2: ok
delete thread 2

--- stream_response
before
after
received: OK
--- no_error_log
[error]



=== TEST 17: user threads + njt.socket.udp
--- stream_server_config
    content_by_lua_block {
        function f()
            local sock = njt.socket.udp()
            local ok, err = sock:setpeername("127.0.0.1", 12345)
            local bytes, err = sock:send("blah")
            if not bytes then
                njt.say("failed to send query: ", err)
                return
            end

            local line, err = sock:receive()
            if not line then
                njt.say("failed to receive: ", err)
                return
            end

            njt.say("received: ", line)
        end

        njt.say("before")
        njt.thread.spawn(f)
        njt.say("after")
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out_like chop
^(?:create 2 in 1
spawn user thread 2 in 1
terminate 1: ok
delete thread 1
terminate 2: ok
delete thread 2
|create 2 in 1
spawn user thread 2 in 1
terminate 2: ok
terminate 1: ok
delete thread 2
delete thread 1
)$

--- udp_listen: 12345
--- udp_query: blah
--- udp_reply: hello udp
--- stream_response_like chop
^(?:before
after
received: hello udp
|before
received: hello udp
after)$

--- no_error_log
[error]



=== TEST 18: simple user thread with njt.req.socket()
--- stream_server_config
    content_by_lua_block {
        function f()
            local sock = assert(njt.req.socket())
            local body, err = sock:receive(11)
            if not body then
                njt.say("failed to read body: ", err)
                return
            end

            njt.say("body: ", body)
        end

        njt.say("before")
        njt.flush(true)
        njt.thread.spawn(f)
        njt.say("after")
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out_like chop
^(?:create 2 in 1
spawn user thread 2 in 1
terminate 2: ok
terminate 1: ok
delete thread 2
delete thread 1|create 2 in 1
spawn user thread 2 in 1
terminate 1: ok
delete thread 1
terminate 2: ok
delete thread 2)$

--- stream_request chomp
hello world
--- stream_response_like chop
^(?:before
body: hello world
after|before
after
body: hello world)$

--- no_error_log
[error]



=== TEST 19: simple user thread with args
--- stream_server_config
    content_by_lua_block {
        function f(a, b)
            njt.say("hello ", a, " and ", b)
        end

        njt.say("before")
        njt.thread.spawn(f, "foo", 3.14)
        njt.say("after")
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
spawn user thread 2 in 1
terminate 2: ok
terminate 1: ok
delete thread 2
delete thread 1

--- stream_response
before
hello foo and 3.14
after
--- no_error_log
[error]



=== TEST 20: simple user thread without I/O
--- stream_server_config
    content_by_lua_block {
        function f()
            njt.sleep(0.1)
            njt.say("f")
        end

        njt.thread.spawn(f)
        collectgarbage()
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
spawn user thread 2 in 1
terminate 1: ok
delete thread 1
terminate 2: ok
delete thread 2

--- stream_response
f
--- no_error_log
[error]
