# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;use t::StapThread;

our $GCScript = $t::StapThread::GCScript;
our $StapScript = $t::StapThread::StapScript;

repeat_each(2);

plan tests => repeat_each() * (blocks() * 4);

$ENV{TEST_NGINX_RESOLVER} ||= '8.8.8.8';
$ENV{TEST_NGINX_MEMCACHED_PORT} ||= '11211';
$ENV{TEST_NGINX_REDIS_PORT} ||= '6379';

#no_shuffle();
no_long_string();
run_tests();

__DATA__

=== TEST 1: exit in user thread (entry thread is still pending to run)
--- stream_server_config
    content_by_lua_block {
        function f()
            njt.say("hello in thread")
            njt.exit(0)
        end

        njt.say("before")
        njt.thread.spawn(f)
        njt.say("after")
        njt.sleep(1)
        njt.say("end")
    }
--- stap2 eval: $::StapScript
--- stap eval
<<'_EOC_' . $::GCScript;

global timers

M(timer-add) {
    if ($arg2 == 1000) {
        timers[$arg1] = $arg2
        printf("add timer %d\n", $arg2)
    }
}

M(timer-del) {
    tm = timers[$arg1]
    if (tm == 1000) {
        printf("delete timer %d\n", tm)
        delete timers[$arg1]
    }
}

M(timer-expire) {
    tm = timers[$arg1]
    if (tm == 1000) {
        printf("expire timer %d\n", timers[$arg1])
        delete timers[$arg1]
    }
}
_EOC_

--- stap_out
create 2 in 1
spawn user thread 2 in 1
terminate 2: ok
delete thread 2
delete thread 1

--- stream_response
before
hello in thread
--- no_error_log
[error]



=== TEST 2: exit in user thread (entry thread is still pending on njt.sleep)
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
        njt.sleep(1)
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

F(njt_http_lua_sleep_cleanup) {
    println("lua sleep cleanup")
}
_EOC_

--- stap_out
create 2 in 1
spawn user thread 2 in 1
add timer 100
add timer 1000
expire timer 100
terminate 2: ok
delete thread 2
lua sleep cleanup
delete timer 1000
delete thread 1
free request

--- stream_response
before
hello in thread
after
--- no_error_log
[error]



=== TEST 3: exit in a user thread (another user thread is still pending on njt.sleep)
--- stream_server_config
    content_by_lua_block {
        function f()
            njt.sleep(0.1)
            njt.say("f")
            njt.exit(0)
        end

        function g()
            njt.sleep(1)
            njt.say("g")
        end

        njt.thread.spawn(f)
        njt.thread.spawn(g)
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

F(njt_http_lua_sleep_cleanup) {
    println("lua sleep cleanup")
}
_EOC_

--- stap_out
create 2 in 1
spawn user thread 2 in 1
add timer 100
create 3 in 1
spawn user thread 3 in 1
add timer 1000
terminate 1: ok
delete thread 1
expire timer 100
terminate 2: ok
delete thread 2
lua sleep cleanup
delete timer 1000
delete thread 3
free request

--- stream_response
end
f
--- no_error_log
[error]



=== TEST 4: exit in user thread (entry already quits)
--- stream_server_config
    content_by_lua_block {
        function f()
            njt.sleep(0.1)
            njt.say("exiting the user thread")
            njt.exit(0)
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

--- wait: 0.1
--- stream_response
before
after
exiting the user thread
--- no_error_log
[error]



=== TEST 5: exit in user thread (entry thread is still pending on the DNS resolver for njt.socket.tcp)
--- stream_server_config
    resolver 127.0.0.2:12345;
    resolver_timeout 12s;
    content_by_lua_block {
        function f()
            njt.say("hello in thread")
            njt.sleep(0.001)
            njt.exit(0)
        end

        njt.say("before")
        njt.thread.spawn(f)
        njt.say("after")
        local sock = njt.socket.tcp()
        local ok, err = sock:connect("agentzh.org", 80)
        if not ok then
            njt.say("failed to connect: ", err)
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

F(njt_resolve_name) {
    printf("resolving %s\n", user_string_n($ctx->name->data, $ctx->name->len))
}

M(timer-add) {
    if ($arg2 == 12000 || $arg2 == 1) {
        timers[$arg1] = $arg2
        printf("add timer %d\n", $arg2)
    }
}

M(timer-del) {
    tm = timers[$arg1]
    if (tm == 12000 || tm == 1) {
        printf("delete timer %d\n", tm)
        delete timers[$arg1]
    }
    /*
    if (tm == 12000) {
        print_ubacktrace()
    }
    */
}

M(timer-expire) {
    tm = timers[$arg1]
    if (tm == 12000 || tm == 1) {
        printf("expire timer %d\n", timers[$arg1])
        delete timers[$arg1]
    }
}

F(njt_http_lua_tcp_resolve_cleanup) {
    println("lua tcp resolve cleanup")
}
_EOC_

--- stap_out
create 2 in 1
spawn user thread 2 in 1
add timer 1
resolving agentzh.org
add timer 12000
expire timer 1
terminate 2: ok
delete thread 2
lua tcp resolve cleanup
delete timer 12000
delete thread 1
free request

--- stream_response
before
hello in thread
after
--- no_error_log
[error]



=== TEST 6: exit in user thread (entry thread is still pending on the DNS resolver for njt.socket.udp)
--- stream_server_config
    resolver 127.0.0.2:12345;
    resolver_timeout 12s;
    content_by_lua_block {
        function f()
            njt.say("hello in thread")
            njt.sleep(0.001)
            njt.exit(0)
        end

        njt.say("before")
        njt.thread.spawn(f)
        njt.say("after")
        local sock = njt.socket.udp()
        local ok, err = sock:setpeername("agentzh.org", 80)
        if not ok then
            njt.say("failed to connect: ", err)
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

F(njt_resolve_name) {
    printf("resolving %s\n", user_string_n($ctx->name->data, $ctx->name->len))
}

M(timer-add) {
    if ($arg2 == 12000 || $arg2 == 1) {
        timers[$arg1] = $arg2
        printf("add timer %d\n", $arg2)
    }
}

M(timer-del) {
    tm = timers[$arg1]
    if (tm == 12000 || tm == 1) {
        printf("delete timer %d\n", tm)
        delete timers[$arg1]
    }
    /*
    if (tm == 12000) {
        print_ubacktrace()
    }
    */
}

M(timer-expire) {
    tm = timers[$arg1]
    if (tm == 12000 || tm == 1) {
        printf("expire timer %d\n", timers[$arg1])
        delete timers[$arg1]
    }
}

F(njt_http_lua_udp_resolve_cleanup) {
    println("lua udp resolve cleanup")
}
_EOC_

--- stap_out
create 2 in 1
spawn user thread 2 in 1
add timer 1
resolving agentzh.org
add timer 12000
expire timer 1
terminate 2: ok
delete thread 2
lua udp resolve cleanup
delete timer 12000
delete thread 1
free request

--- stream_response
before
hello in thread
after
--- no_error_log
[error]



=== TEST 7: exit in user thread (entry thread is still pending on tcpsock:connect)
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
        sock:settimeout(12000)
        local ok, err = sock:connect("127.0.0.2", 12345)
        if not ok then
            njt.say("failed to connect: ", err)
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
    /*
    if (tm == 12000) {
        print_ubacktrace()
    }
    */
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



=== TEST 8: exit in user thread (entry thread is still pending on tcpsock:receive)
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

        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_REDIS_PORT)
        if not ok then
            njt.say("failed to connect: ", err)
            return
        end

        local bytes, ok = sock:send("blpop not_exists 2\\r\\n")
        if not bytes then
            njt.say("failed to send: ", err)
            return
        end

        sock:settimeout(12000)

        local data, err = sock:receive()
        if not data then
            njt.say("failed to receive: ", err)
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



=== TEST 9: exit in user thread (entry thread is still pending on tcpsock:receiveuntil's iterator)
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

        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_REDIS_PORT)
        if not ok then
            njt.say("failed to connect: ", err)
            return
        end

        local bytes, ok = sock:send("blpop not_exists 2\\r\\n")
        if not bytes then
            njt.say("failed to send: ", err)
            return
        end

        local it, err = sock:receiveuntil("\\r\\n")
        if not it then
            njt.say("failed to receive until: ", err)
            return
        end

        sock:settimeout(12000)

        local data, err = it()
        if not data then
            njt.say("failed to receive: ", err)
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



=== TEST 10: exit in user thread (entry thread is still pending on udpsock:receive)
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
        local sock = njt.socket.udp()

        local ok, err = sock:setpeername("8.8.8.8", 12345)
        if not ok then
            njt.say("failed to connect: ", err)
            return
        end

        sock:settimeout(12000)

        local data, err = sock:receive()
        if not data then
            njt.say("failed to receive: ", err)
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

F(njt_http_lua_udp_socket_cleanup) {
    println("lua udp socket cleanup")
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
lua udp socket cleanup
delete timer 12000
delete thread 1
free request

--- wait: 0.1
--- stream_response
before
hello in thread
after
--- no_error_log
[error]



=== TEST 11: exit in user thread (entry thread is still pending on reqsock:receive)
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
        njt.flush(true)
        local sock = njt.req.socket()

        sock:settimeout(12000)

        local data, err = sock:receive(1024)
        if not data then
            njt.say("failed to receive: ", err)
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

--- wait: 0.1
--- stream_response
before
hello in thread
after
--- no_error_log
[error]
--- timeout: 6
