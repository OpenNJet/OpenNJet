# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;use t::StapThread;

our $GCScript = $t::StapThread::GCScript;
our $StapScript = $t::StapThread::StapScript;

repeat_each(2);

plan tests => repeat_each() * (blocks() * 4);

$ENV{TEST_NGINX_RESOLVER} ||= '8.8.8.8';
$ENV{TEST_NGINX_MEMCACHED_PORT} ||= '11211';

#no_shuffle();
no_long_string();
run_tests();

__DATA__

=== TEST 1: simple user thread wait without I/O
--- stream_server_config
    content_by_lua_block {
        function f()
            njt.say("hello in thread")
            return "done"
        end

        local t, err = njt.thread.spawn(f)
        if not t then
            njt.say("failed to spawn thread: ", err)
            return
        end

        njt.say("thread created: ", coroutine.status(t))

        collectgarbage()

        local ok, res = njt.thread.wait(t)
        if not ok then
            njt.say("failed to run thread: ", res)
            return
        end

        njt.say(res)
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
spawn user thread 2 in 1
terminate 2: ok
delete thread 2
terminate 1: ok
delete thread 1

--- stream_response
hello in thread
thread created: zombie
done
--- no_error_log
[error]



=== TEST 2: simple user thread wait with I/O
--- stream_server_config
    content_by_lua_block {
        function f()
            njt.sleep(0.1)
            njt.say("hello in thread")
            return "done"
        end

        local t, err = njt.thread.spawn(f)
        if not t then
            njt.say("failed to spawn thread: ", err)
            return
        end

        njt.say("thread created: ", coroutine.status(t))

        local ok, res = njt.thread.wait(t)
        if not ok then
            njt.say("failed to wait thread: ", res)
            return
        end

        njt.say(res)
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
spawn user thread 2 in 1
terminate 2: ok
delete thread 2
terminate 1: ok
delete thread 1

--- stream_response
thread created: running
hello in thread
done
--- no_error_log
[error]



=== TEST 3: wait on uthreads on the reversed order of their termination
--- stream_server_config
    content_by_lua_block {
        function f()
            njt.sleep(0.1)
            njt.say("f: hello")
            return "done"
        end

        function g()
            njt.sleep(0.2)
            njt.say("g: hello")
            return "done"
        end

        local tf, err = njt.thread.spawn(f)
        if not tf then
            njt.say("failed to spawn thread: ", err)
            return
        end

        njt.say("f thread created: ", coroutine.status(tf))

        local tg, err = njt.thread.spawn(g)
        if not tg then
            njt.say("failed to spawn thread: ", err)
            return
        end

        njt.say("g thread created: ", coroutine.status(tg))

        local ok, res = njt.thread.wait(tg)
        if not ok then
            njt.say("failed to wait g: ", res)
            return
        end

        njt.say("g: ", res)

        njt.say("f thread status: ", coroutine.status(tf))

        ok, res = njt.thread.wait(tf)
        if not ok then
            njt.say("failed to wait f: ", res)
            return
        end

        njt.say("f: ", res)
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
spawn user thread 2 in 1
create 3 in 1
spawn user thread 3 in 1
terminate 2: ok
terminate 3: ok
delete thread 3
delete thread 2
terminate 1: ok
delete thread 1

--- stream_response
f thread created: running
g thread created: running
f: hello
g: hello
g: done
f thread status: zombie
f: done
--- no_error_log
[error]



=== TEST 4: wait on uthreads on the exact order of their termination
--- stream_server_config
    content_by_lua_block {
        function f()
            njt.sleep(0.1)
            njt.say("f: hello")
            return "done"
        end

        function g()
            njt.sleep(0.2)
            njt.say("g: hello")
            return "done"
        end

        local tf, err = njt.thread.spawn(f)
        if not tf then
            njt.say("failed to spawn thread: ", err)
            return
        end

        njt.say("f thread created: ", coroutine.status(tf))

        local tg, err = njt.thread.spawn(g)
        if not tg then
            njt.say("failed to spawn thread: ", err)
            return
        end

        njt.say("g thread created: ", coroutine.status(tg))

        ok, res = njt.thread.wait(tf)
        if not ok then
            njt.say("failed to wait f: ", res)
            return
        end

        njt.say("f: ", res)

        njt.say("g thread status: ", coroutine.status(tg))

        local ok, res = njt.thread.wait(tg)
        if not ok then
            njt.say("failed to wait g: ", res)
            return
        end

        njt.say("g: ", res)
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
spawn user thread 2 in 1
create 3 in 1
spawn user thread 3 in 1
terminate 2: ok
delete thread 2
terminate 3: ok
delete thread 3
terminate 1: ok
delete thread 1

--- wait: 0.1
--- stream_response
f thread created: running
g thread created: running
f: hello
f: done
g thread status: running
g: hello
g: done
--- no_error_log
[error]



=== TEST 5: simple user thread wait without I/O (return multiple values)
--- stream_server_config
    content_by_lua_block {
        function f()
            njt.say("hello in thread")
            return "done", 3.14
        end

        local t, err = njt.thread.spawn(f)
        if not t then
            njt.say("failed to spawn thread: ", err)
            return
        end

        njt.say("thread created: ", coroutine.status(t))

        collectgarbage()

        local ok, res1, res2 = njt.thread.wait(t)
        if not ok then
            njt.say("failed to run thread: ", res1)
            return
        end

        njt.say("res: ", res1, " ", res2)
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
spawn user thread 2 in 1
terminate 2: ok
delete thread 2
terminate 1: ok
delete thread 1

--- stream_response
hello in thread
thread created: zombie
res: done 3.14
--- no_error_log
[error]



=== TEST 6: simple user thread wait with I/O, return multiple values
--- stream_server_config
    content_by_lua_block {
        function f()
            njt.sleep(0.1)
            njt.say("hello in thread")
            return "done", 3.14
        end

        local t, err = njt.thread.spawn(f)
        if not t then
            njt.say("failed to spawn thread: ", err)
            return
        end

        njt.say("thread created: ", coroutine.status(t))

        local ok, res1, res2 = njt.thread.wait(t)
        if not ok then
            njt.say("failed to wait thread: ", res1)
            return
        end

        njt.say("res: ", res1, " ", res2)
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
spawn user thread 2 in 1
terminate 2: ok
delete thread 2
terminate 1: ok
delete thread 1

--- stream_response
thread created: running
hello in thread
res: done 3.14
--- no_error_log
[error]



=== TEST 7: simple user thread wait without I/O, throw errors
--- stream_server_config
    content_by_lua_block {
        function f()
            njt.say("hello in thread")
            error("bad bad!")
        end

        local t, err = njt.thread.spawn(f)
        if not t then
            njt.say("failed to spawn thread: ", err)
            return
        end

        njt.say("thread created: ", coroutine.status(t))

        collectgarbage()

        local ok, res = njt.thread.wait(t)
        if not ok then
            njt.say("failed to wait thread: ", res)
            return
        end

        njt.say(res)
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
spawn user thread 2 in 1
terminate 2: fail
delete thread 2
terminate 1: ok
delete thread 1

--- stream_response
hello in thread
thread created: zombie
failed to wait thread: bad bad!
--- error_log eval
qr/lua user thread aborted: runtime error: content_by_lua\(nginx\.conf:\d+\):4: bad bad!/



=== TEST 8: simple user thread wait with I/O, throw errors
--- stream_server_config
    content_by_lua_block {
        function f()
            njt.sleep(0.1)
            njt.say("hello in thread")
            error("bad bad!")
        end

        local t, err = njt.thread.spawn(f)
        if not t then
            njt.say("failed to spawn thread: ", err)
            return
        end

        njt.say("thread created: ", coroutine.status(t))

        collectgarbage()

        local ok, res = njt.thread.wait(t)
        if not ok then
            njt.say("failed to wait thread: ", res)
            return
        end

        njt.say(res)
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
spawn user thread 2 in 1
terminate 2: fail
delete thread 2
terminate 1: ok
delete thread 1

--- stream_response
thread created: running
hello in thread
failed to wait thread: bad bad!
--- error_log eval
qr/lua user thread aborted: runtime error: content_by_lua\(nginx\.conf:\d+\):5: bad bad!/



=== TEST 9: simple user thread wait without I/O (in a user coroutine)
--- stream_server_config
    content_by_lua_block {
        function g()
            njt.say("hello in thread")
            return "done"
        end

        function f()
            local t, err = njt.thread.spawn(g)
            if not t then
                njt.say("failed to spawn thread: ", err)
                return
            end

            njt.say("thread created: ", coroutine.status(t))

            collectgarbage()

            local ok, res = njt.thread.wait(t)
            if not ok then
                njt.say("failed to run thread: ", res)
                return
            end

            njt.say(res)
        end

        local co = coroutine.create(f)
        coroutine.resume(co)
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
create 3 in 2
spawn user thread 3 in 2
terminate 3: ok
delete thread 3
terminate 2: ok
terminate 1: ok
delete thread 1

--- stream_response
hello in thread
thread created: zombie
done
--- no_error_log
[error]



=== TEST 10: simple user thread wait with I/O (in a user coroutine)
--- stream_server_config
    content_by_lua_block {
        function g()
            njt.sleep(0.1)
            njt.say("hello in thread")
            return "done"
        end

        function f()
            local t, err = njt.thread.spawn(g)
            if not t then
                njt.say("failed to spawn thread: ", err)
                return
            end

            njt.say("thread created: ", coroutine.status(t))

            collectgarbage()

            local ok, res = njt.thread.wait(t)
            if not ok then
                njt.say("failed to run thread: ", res)
                return
            end

            njt.say(res)
        end

        local co = coroutine.create(f)
        coroutine.resume(co)
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
create 3 in 2
spawn user thread 3 in 2
terminate 3: ok
delete thread 3
terminate 2: ok
terminate 1: ok
delete thread 1

--- stream_response
thread created: running
hello in thread
done
--- no_error_log
[error]



=== TEST 11: waiting on two simple user threads without I/O
--- stream_server_config
    content_by_lua_block {
        -- local out = function (...) njt.log(njt.ERR, ...) end
        local out = njt.say

        function f()
            out("f: hello")
            return "f done"
        end

        function g()
            out("g: hello")
            return "g done"
        end

        local tf, err = njt.thread.spawn(f)
        if not tf then
            out("failed to spawn thread f: ", err)
            return
        end

        out("thread f created: ", coroutine.status(tf))

        local tg, err = njt.thread.spawn(g)
        if not tg then
            out("failed to spawn thread g: ", err)
            return
        end

        out("thread g created: ", coroutine.status(tg))

        local ok, res = njt.thread.wait(tf, tg)
        if not ok then
            out("failed to wait thread: ", res)
            return
        end

        out("res: ", res)

        out("f status: ", coroutine.status(tf))
        out("g status: ", coroutine.status(tg))
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
delete thread 2
terminate 1: ok
delete thread 3
delete thread 1

--- stream_response
f: hello
thread f created: zombie
g: hello
thread g created: zombie
res: f done
f status: dead
g status: zombie

--- no_error_log
[error]



=== TEST 12: waiting on two simple user threads with I/O
--- stream_server_config
    content_by_lua_block {
        -- local out = function (...) njt.log(njt.ERR, ...) end
        local out = njt.say

        function f()
            njt.sleep(0.1)
            out("f: hello")
            return "f done"
        end

        function g()
            njt.sleep(0.2)
            out("g: hello")
            return "g done"
        end

        local tf, err = njt.thread.spawn(f)
        if not tf then
            out("failed to spawn thread f: ", err)
            return
        end

        out("thread f created: ", coroutine.status(tf))

        local tg, err = njt.thread.spawn(g)
        if not tg then
            out("failed to spawn thread g: ", err)
            return
        end

        out("thread g created: ", coroutine.status(tg))

        local ok, res = njt.thread.wait(tf, tg)
        if not ok then
            out("failed to wait thread: ", res)
            return
        end

        out("res: ", res)

        out("f status: ", coroutine.status(tf))
        out("g status: ", coroutine.status(tg))
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
spawn user thread 2 in 1
create 3 in 1
spawn user thread 3 in 1
terminate 2: ok
delete thread 2
terminate 1: ok
delete thread 1
terminate 3: ok
delete thread 3

--- stream_response
thread f created: running
thread g created: running
f: hello
res: f done
f status: dead
g status: running
g: hello

--- no_error_log
[error]



=== TEST 13: waiting on two simple user threads with I/O (uthreads completed in reversed order)
--- stream_server_config
    content_by_lua_block {
        -- local out = function (...) njt.log(njt.ERR, ...) end
        local out = njt.say

        function f()
            njt.sleep(0.2)
            out("f: hello")
            return "f done"
        end

        function g()
            njt.sleep(0.1)
            out("g: hello")
            return "g done"
        end

        local tf, err = njt.thread.spawn(f)
        if not tf then
            out("failed to spawn thread f: ", err)
            return
        end

        out("thread f created: ", coroutine.status(tf))

        local tg, err = njt.thread.spawn(g)
        if not tg then
            out("failed to spawn thread g: ", err)
            return
        end

        out("thread g created: ", coroutine.status(tg))

        local ok, res = njt.thread.wait(tf, tg)
        if not ok then
            out("failed to wait thread: ", res)
            return
        end

        out("res: ", res)

        out("f status: ", coroutine.status(tf))
        out("g status: ", coroutine.status(tg))
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
spawn user thread 2 in 1
create 3 in 1
spawn user thread 3 in 1
terminate 3: ok
delete thread 3
terminate 1: ok
delete thread 1
terminate 2: ok
delete thread 2

--- stream_response
thread f created: running
thread g created: running
g: hello
res: g done
f status: running
g status: dead
f: hello

--- no_error_log
[error]



=== TEST 14: waiting on two simple user threads without I/O, both aborted by errors
--- stream_server_config
    content_by_lua_block {
        -- local out = function (...) njt.log(njt.ERR, ...) end
        local out = njt.say

        function f()
            out("f: hello")
            error("f done")
        end

        function g()
            out("g: hello")
            error("g done")
        end

        local tf, err = njt.thread.spawn(f)
        if not tf then
            out("failed to spawn thread f: ", err)
            return
        end

        out("thread f created: ", coroutine.status(tf))

        local tg, err = njt.thread.spawn(g)
        if not tg then
            out("failed to spawn thread g: ", err)
            return
        end

        out("thread g created: ", coroutine.status(tg))

        local ok, res = njt.thread.wait(tf, tg)
        if not ok then
            out("failed to wait thread: ", res)
        else
            out("res: ", res)
        end

        out("f status: ", coroutine.status(tf))
        out("g status: ", coroutine.status(tg))
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
spawn user thread 2 in 1
terminate 2: fail
create 3 in 1
spawn user thread 3 in 1
terminate 3: fail
delete thread 2
terminate 1: ok
delete thread 3
delete thread 1

--- stream_response
f: hello
thread f created: zombie
g: hello
thread g created: zombie
failed to wait thread: f done
f status: dead
g status: zombie

--- error_log eval
qr/lua user thread aborted: runtime error: content_by_lua\(nginx\.conf:\d+\):7: f done/



=== TEST 15: waiting on two simple user threads with I/O, both aborted by errors
--- stream_server_config
    content_by_lua_block {
        -- local out = function (...) njt.log(njt.ERR, ...) end
        local out = njt.say

        function f()
            njt.sleep(0.1)
            out("f: hello")
            error("f done")
        end

        function g()
            njt.sleep(0.2)
            out("g: hello")
            error("g done")
        end

        local tf, err = njt.thread.spawn(f)
        if not tf then
            out("failed to spawn thread f: ", err)
            return
        end

        out("thread f created: ", coroutine.status(tf))

        local tg, err = njt.thread.spawn(g)
        if not tg then
            out("failed to spawn thread g: ", err)
            return
        end

        out("thread g created: ", coroutine.status(tg))

        local ok, res = njt.thread.wait(tf, tg)
        if not ok then
            out("failed to wait thread: ", res)
        else
            out("res: ", res)
        end

        out("f status: ", coroutine.status(tf))
        out("g status: ", coroutine.status(tg))
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
spawn user thread 2 in 1
create 3 in 1
spawn user thread 3 in 1
terminate 2: fail
delete thread 2
terminate 1: ok
delete thread 1
terminate 3: fail
delete thread 3

--- stream_response
thread f created: running
thread g created: running
f: hello
failed to wait thread: f done
f status: dead
g status: running
g: hello

--- error_log eval
qr/lua user thread aborted: runtime error: content_by_lua\(nginx\.conf:\d+\):8: f done/



=== TEST 16: wait on uthreads on the exact order of their termination, but exit the world early
--- stream_server_config
    content_by_lua_block {
        function f()
            njt.sleep(0.1)
            njt.say("f: hello")
            return "done"
        end

        function g()
            njt.sleep(0.2)
            njt.say("g: hello")
            return "done"
        end

        local tf, err = njt.thread.spawn(f)
        if not tf then
            njt.say("failed to spawn thread: ", err)
            return
        end

        njt.say("f thread created: ", coroutine.status(tf))

        local tg, err = njt.thread.spawn(g)
        if not tg then
            njt.say("failed to spawn thread: ", err)
            return
        end

        njt.say("g thread created: ", coroutine.status(tg))

        ok, res = njt.thread.wait(tf, tg)
        if not ok then
            njt.say("failed to wait: ", res)
            return
        end

        njt.say("res: ", res)

        njt.exit(200)
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
spawn user thread 2 in 1
create 3 in 1
spawn user thread 3 in 1
terminate 2: ok
delete thread 2
terminate 1: ok
delete thread 3
delete thread 1

--- stream_response
f thread created: running
g thread created: running
f: hello
res: done

--- no_error_log
[error]



=== TEST 17: wait on uthreads on the reversed order of their termination, but exit the world early
--- stream_server_config
    content_by_lua_block {
        function f()
            njt.sleep(0.2)
            njt.say("f: hello")
            return "f done"
        end

        function g()
            njt.sleep(0.1)
            njt.say("g: hello")
            return "g done"
        end

        local tf, err = njt.thread.spawn(f)
        if not tf then
            njt.say("failed to spawn thread f: ", err)
            return
        end

        njt.say("f thread created: ", coroutine.status(tf))

        local tg, err = njt.thread.spawn(g)
        if not tg then
            njt.say("failed to spawn thread g: ", err)
            return
        end

        njt.say("g thread created: ", coroutine.status(tg))

        ok, res = njt.thread.wait(tf, tg)
        if not ok then
            njt.say("failed to wait: ", res)
            return
        end

        njt.say("res: ", res)

        njt.exit(200)
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
spawn user thread 2 in 1
create 3 in 1
spawn user thread 3 in 1
terminate 3: ok
delete thread 3
terminate 1: ok
delete thread 2
delete thread 1

--- stream_response
f thread created: running
g thread created: running
g: hello
res: g done

--- no_error_log
[error]



=== TEST 18: entry coroutine waiting on a thread not created by itself
--- stream_server_config
    content_by_lua_block {
        local t

        function f()
            njt.sleep(0.1)
            return "done"
        end

        function g()
            t = njt.thread.spawn(f)
        end

        local co = coroutine.create(g)
        coroutine.resume(co)

        local ok, res = njt.thread.wait(t)
        if not ok then
            njt.say("failed to run thread: ", res)
            return
        end

        njt.say(res)
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
create 3 in 2
spawn user thread 3 in 2
terminate 2: ok
terminate 1: fail
delete thread 3
delete thread 1

--- stream_response
--- error_log
only the parent coroutine can wait on the thread



=== TEST 19: entry coroutine waiting on a user coroutine
--- stream_server_config
    content_by_lua_block {
        function f()
            njt.sleep(0.1)
            coroutine.yield()
            return "done"
        end

        local co = coroutine.create(f)
        coroutine.resume(co)

        local ok, res = njt.thread.wait(co)
        if not ok then
            njt.say("failed to run thread: ", res)
            return
        end

        njt.say(res)
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
terminate 1: fail
delete thread 1

--- stream_response
--- error_log eval
qr/lua entry thread aborted: runtime error: content_by_lua\(nginx\.conf:\d+\):11: attempt to wait on a coroutine that is not a user thread/



=== TEST 20: lua backtrace dumper may access dead parent coroutines
--- stream_server_config
    content_by_lua_block {
        function f()
            njt.sleep(0.1)
            collectgarbage()
            error("f done")
        end

        njt.thread.spawn(f)
        njt.say("ok")

        collectgarbage()
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
spawn user thread 2 in 1
terminate 1: ok
delete thread 1
terminate 2: fail
delete thread 2

--- stream_response
ok

--- error_log eval
qr/lua user thread aborted: runtime error: content_by_lua\(nginx\.conf:\d+\):5: f done/



=== TEST 21: waiting on a dead coroutine
--- stream_server_config
    content_by_lua_block {
        function f()
            njt.say("hello in thread")
            return "done"
        end

        local t, err = njt.thread.spawn(f)
        if not t then
            njt.say("failed to spawn thread: ", err)
            return
        end

        njt.say("thread created: ", coroutine.status(t))

        collectgarbage()

        local ok, res = njt.thread.wait(t)
        if not ok then
            njt.say("failed to run thread: ", res)
            return
        end

        local ok, res = njt.thread.wait(t)
        if not ok then
            njt.say("failed to run thread: ", res)
            return
        end

        njt.say(res)
    }
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
create 2 in 1
spawn user thread 2 in 1
terminate 2: ok
delete thread 2
terminate 1: ok
delete thread 1

--- stream_response
hello in thread
thread created: zombie
failed to run thread: already waited or killed
--- no_error_log
[error]



=== TEST 22: spawn and wait uthreads for many times
--- stream_server_config
    content_by_lua_block {
        function f()
            -- njt.say("hello in thread")
            return "done"
        end

        for i = 1, 100 do
            local t, err = njt.thread.spawn(f)
            if not t then
                njt.say("failed to spawn thread: ", err)
                break
            end

            -- njt.say("thread created: ", coroutine.status(t))

            collectgarbage()

            local ok, res = njt.thread.wait(t)
            if not ok then
                njt.say("failed to run thread: ", res)
                break
            end

            njt.say(i, ": ", res)
        end
    }
--- stream_response eval
my $s = '';
for my $i (1..100) {
    $s .= "$i: done\n";
}
$s;

--- no_error_log
[error]
[alert]



=== TEST 23: hanging bug
--- stream_server_config
    content_by_lua_block {
        local function foo()
            njt.say("ok")
        end

        njt.sleep(0.001)
        local co = njt.thread.spawn(foo)
        njt.thread.wait(co)
    }
--- stream_response
ok
--- no_error_log
[error]
[alert]
