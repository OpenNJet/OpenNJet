# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;
use t::StapThread;

our $GCScript = <<_EOC_;
$t::StapThread::GCScript

F(njt_http_lua_check_broken_connection) {
    println("lua check broken conn")
}

F(njt_http_lua_request_cleanup) {
    println("lua req cleanup")
}
_EOC_

our $StapScript = $t::StapThread::StapScript;

repeat_each(2);

plan tests => repeat_each() * (blocks() * 4 - 2);

$ENV{TEST_NGINX_RESOLVER} ||= '8.8.8.8';
$ENV{TEST_NGINX_MEMCACHED_PORT} ||= '11211';
$ENV{TEST_NGINX_REDIS_PORT} ||= '6379';

#no_shuffle();
no_long_string();
run_tests();

__DATA__

=== TEST 1: sleep + stop
--- stream_server_config
    lua_check_client_abort on;
    preread_by_lua_block {
        njt.sleep(1)
    }

    return here;
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
lua check broken conn
lua req cleanup
delete thread 1

--- wait: 0.1
--- timeout: 0.2
--- abort
--- no_error_log
[error]
--- error_log
client prematurely closed connection



=== TEST 2: sleep + stop (log handler still gets called)
--- stream_server_config
    lua_check_client_abort on;
    preread_by_lua_block {
        njt.sleep(1)
    }

    log_by_lua_block {
        njt.log(njt.NOTICE, "here in log by lua")
    }

    return here;
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
lua check broken conn
lua req cleanup
delete thread 1

--- timeout: 0.2
--- abort
--- no_error_log
[error]
--- error_log
client prematurely closed connection
here in log by lua



=== TEST 3: sleep + ignore
--- stream_server_config
    lua_check_client_abort off;
    preread_by_lua_block {
        njt.sleep(1)
    }

    content_by_lua return;
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
terminate 1: ok
delete thread 1
terminate 2: ok
delete thread 2
lua req cleanup

--- wait: 1
--- timeout: 0.2
--- abort
--- no_error_log
[error]



=== TEST 4: njt.req.socket + receive() + sleep + stop
--- stream_server_config
    lua_check_client_abort on;

    preread_by_lua_block {
        local sock = njt.req.socket()
        sock:receive()
        njt.sleep(1)
    }

    return here;
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
lua check broken conn
lua req cleanup
delete thread 1

--- timeout: 0.2
--- abort
--- no_error_log
[error]
--- error_log
client prematurely closed connection



=== TEST 5: njt.req.socket + receive(N) + sleep + stop
--- stream_server_config
    lua_check_client_abort on;

    preread_by_lua_block {
        local sock = njt.req.socket()
        sock:receive(5)
        njt.sleep(1)
    }

    return here;
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
lua check broken conn
lua check broken conn
lua req cleanup
delete thread 1

--- wait: 0.1
--- timeout: 0.2
--- abort
--- no_error_log
[error]
--- error_log
client prematurely closed connection



=== TEST 6: njt.req.socket + receive(n) + sleep + stop
--- stream_server_config
    lua_check_client_abort on;

    preread_by_lua_block {
        local sock = njt.req.socket()
        sock:receive(2)
        njt.sleep(1)
    }

    content_by_lua return;
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out_like
^(?:lua check broken conn
terminate 1: ok
delete thread 1
terminate 2: ok
delete thread 2
lua req cleanup|lua check broken conn
lua req cleanup
delete thread 1)$

--- wait: 1
--- timeout: 0.2
--- abort
--- no_error_log
[error]



=== TEST 7: njt.req.socket + m * receive(n) + sleep + stop
--- stream_server_config
    lua_check_client_abort on;
    lua_socket_log_errors off;
    preread_by_lua_block {
        local sock = njt.req.socket()
        sock:receive(2)
        sock:receive(2)
        sock:receive(1)
        njt.sleep(1)
    }

    content_by_lua return;
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
lua check broken conn
lua check broken conn
lua req cleanup
delete thread 1

--- wait: 1
--- timeout: 0.2
--- abort
--- no_error_log
[error]
--- error_log
client prematurely closed connection



=== TEST 8: njt.req.socket + receiveuntil + sleep + stop
--- stream_server_config
    lua_check_client_abort on;
    preread_by_lua_block {
        local sock = njt.req.socket()
        local it = sock:receiveuntil("\\n")
        it()
        njt.sleep(1)
    }

    content_by_lua return;
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
lua check broken conn
lua req cleanup
delete thread 1

--- wait: 1
--- timeout: 0.2
--- abort
--- no_error_log
[error]
--- error_log
client prematurely closed connection



=== TEST 9: njt.req.socket + receiveuntil + it(n) + sleep + stop
--- stream_server_config
    lua_check_client_abort on;
    preread_by_lua_block {
        local sock = njt.req.socket()
        local it = sock:receiveuntil("\\n")
        it(2)
        it(3)
        njt.sleep(1)
    }

    content_by_lua return;
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
lua check broken conn
lua check broken conn
lua req cleanup
delete thread 1

--- timeout: 0.2
--- abort
--- no_error_log
[error]
--- error_log
client prematurely closed connection



=== TEST 10: cosocket + stop
--- stream_server_config
    lua_check_client_abort on;

    preread_by_lua_block {
        local sock, err = njt.socket.tcp()
        if not sock then
            njt.log(njt.ERR, "failed to get socket: ", err)
            return
        end

        ok, err = sock:connect("127.0.0.1", $TEST_NGINX_REDIS_PORT)
        if not ok then
            njt.log(njt.ERR, "failed to connect: ", err)
            return
        end

        local bytes, err = sock:send("blpop nonexist 2\\r\\n")
        if not bytes then
            njt.log(njt.ERR, "failed to send query: ", err)
            return
        end

        -- njt.log(njt.ERR, "about to receive")

        local res, err = sock:receive()
        if not res then
            njt.log(njt.ERR, "failed to receive query: ", err)
            return
        end

        njt.log(njt.ERR, "res: ", res)
    }

    content_by_lua return;
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
lua check broken conn
lua req cleanup
delete thread 1

--- wait: 1
--- timeout: 0.2
--- abort
--- no_error_log
[error]
--- error_log
client prematurely closed connection



=== TEST 11: njt.req.socket + receive n < content-length + stop
--- stream_server_config
    lua_check_client_abort on;

    preread_by_lua_block {
        local sock = njt.req.socket()
        local res, err = sock:receive("*a")
        if not res then
            njt.log(njt.NOTICE, "failed to receive: ", err)
            return
        end
        error("bad")
    }

    content_by_lua return;
--- stream_request eval
"POST /t HTTP/1.0\r
Host: localhost\r
Connection: close\r
Content-Length: 100\r
\r
hello"
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
terminate 1: ok
delete thread 1
terminate 2: ok
delete thread 2
lua req cleanup

--- timeout: 0.2
--- abort
--- no_error_log
[error]
--- error_log
failed to receive: client aborted



=== TEST 12: njt.req.socket + receive n == content-length + stop
--- stream_server_config
    lua_check_client_abort on;
    preread_by_lua_block {
        local sock = njt.req.socket()
        local res, err = sock:receive("*a")
        if not res then
            njt.log(njt.NOTICE, "failed to receive: ", err)
            return
        end
        njt.sleep(1)
        error("bad")
    }

    content_by_lua return;
--- stream_request eval
"POST /t HTTP/1.0\r
Host: localhost\r
Connection: close\r
Content-Length: 5\r
\r
hello"
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
lua check broken conn
lua check broken conn
lua req cleanup
delete thread 1

--- timeout: 0.2
--- abort
--- no_error_log
[error]



=== TEST 13: njt.req.socket + receive n == content-length + ignore
--- stream_server_config
    preread_by_lua_block {
        local sock = njt.req.socket()
        local res, err = sock:receive("*a")
        if not res then
            njt.log(njt.NOTICE, "failed to receive: ", err)
            return
        end
        njt.say("done")
    }

    content_by_lua return;
--- stream_request eval
"POST /t HTTP/1.0\r
Host: localhost\r
Connection: close\r
Content-Length: 5\r
\r
hello"
--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
terminate 1: ok
delete thread 1
terminate 2: ok
delete thread 2
lua req cleanup

--- timeout: 0.2
--- abort
--- no_error_log
[error]
[alert]
