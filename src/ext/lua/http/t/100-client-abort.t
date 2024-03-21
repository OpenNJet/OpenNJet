# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua;
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

plan tests => repeat_each() * (blocks() * 3 + 1);

$ENV{TEST_NGINX_RESOLVER} ||= '8.8.8.8';
$ENV{TEST_NGINX_MEMCACHED_PORT} ||= '11211';
$ENV{TEST_NGINX_REDIS_PORT} ||= '6379';

#no_shuffle();
no_long_string();
run_tests();

__DATA__

=== TEST 1: sleep + stop
--- config
    location /t {
        lua_check_client_abort on;
        content_by_lua '
            njt.sleep(1)
        ';
    }
--- request
GET /t

--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
lua check broken conn
lua req cleanup
delete thread 1

--- timeout: 0.2
--- abort
--- ignore_response
--- no_error_log
[error]
--- error_log
client prematurely closed connection



=== TEST 2: sleep + stop (log handler still gets called)
--- config
    location /t {
        lua_check_client_abort on;
        content_by_lua '
            njt.sleep(1)
        ';
        log_by_lua '
            njt.log(njt.NOTICE, "here in log by lua")
        ';
    }
--- request
GET /t

--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
lua check broken conn
lua req cleanup
delete thread 1

--- timeout: 0.2
--- abort
--- ignore_response
--- no_error_log
[error]
--- error_log
client prematurely closed connection
here in log by lua



=== TEST 3: sleep + ignore
--- config
    location /t {
        lua_check_client_abort off;
        content_by_lua '
            njt.sleep(1)
        ';
    }
--- request
GET /t

--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
terminate 1: ok
delete thread 1
lua req cleanup

--- wait: 1
--- timeout: 0.2
--- abort
--- ignore_response
--- no_error_log
[error]



=== TEST 4: subrequest + stop
--- config
    location /t {
        lua_check_client_abort on;
        content_by_lua '
            njt.location.capture("/sub")
            error("bad things happen")
        ';
    }

    location /sub {
        echo_sleep 1;
    }
--- request
GET /t

--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
lua check broken conn
lua req cleanup
delete thread 1

--- timeout: 0.2
--- abort
--- ignore_response
--- no_error_log
[error]
--- error_log
client prematurely closed connection



=== TEST 5: subrequest + ignore
--- config
    location /t {
        lua_check_client_abort off;
        content_by_lua '
            njt.location.capture("/sub")
            error("bad things happen")
        ';
    }

    location /sub {
        echo_sleep 1;
    }
--- request
GET /t

--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
terminate 1: fail
lua req cleanup
delete thread 1

--- wait: 1.1
--- timeout: 0.2
--- abort
--- ignore_response
--- error_log
bad things happen



=== TEST 6: subrequest + stop (proxy, ignore client abort)
--- config
    location = /t {
        lua_check_client_abort on;
        content_by_lua '
            njt.location.capture("/sub")
            error("bad things happen")
        ';
    }

    location = /sub {
        proxy_ignore_client_abort on;
        proxy_pass http://127.0.0.2:12345/;
    }

    location = /sleep {
        lua_check_client_abort on;
        content_by_lua '
            njt.sleep(1)
        ';
    }
--- request
GET /t

--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
lua check broken conn
lua req cleanup
delete thread 1

--- timeout: 0.2
--- abort
--- ignore_response
--- no_error_log
[error]
--- error_log
client prematurely closed connection



=== TEST 7: subrequest + stop (proxy, check client abort)
--- config
    location = /t {
        lua_check_client_abort on;
        content_by_lua '
            njt.location.capture("/sub")
            error("bad things happen")
        ';
    }

    location = /sub {
        proxy_ignore_client_abort off;
        proxy_pass http://127.0.0.2:12345/;
    }
--- request
GET /t

--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
lua check broken conn
lua req cleanup
delete thread 1

--- timeout: 0.2
--- abort
--- ignore_response
--- no_error_log
[error]
--- error_log
client prematurely closed connection



=== TEST 8: need body on + sleep + stop (log handler still gets called)
--- config
    location /t {
        lua_check_client_abort on;
        lua_need_request_body on;
        content_by_lua '
            njt.sleep(1)
        ';
        log_by_lua '
            njt.log(njt.NOTICE, "here in log by lua")
        ';
    }
--- request
POST /t
hello

--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
lua check broken conn
lua req cleanup
delete thread 1

--- timeout: 0.2
--- abort
--- ignore_response
--- no_error_log
[error]
--- error_log
client prematurely closed connection
here in log by lua



=== TEST 9: njt.req.read_body + sleep + stop (log handler still gets called)
--- config
    location /t {
        lua_check_client_abort on;
        content_by_lua '
            njt.req.read_body()
            njt.sleep(1)
        ';
        log_by_lua '
            njt.log(njt.NOTICE, "here in log by lua")
        ';
    }
--- request
POST /t
hello

--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
lua check broken conn
lua req cleanup
delete thread 1

--- wait: 0.1
--- timeout: 0.2
--- abort
--- ignore_response
--- no_error_log
[error]
--- error_log
client prematurely closed connection
here in log by lua



=== TEST 10: njt.req.socket + receive() + sleep + stop
--- config
    location /t {
        lua_check_client_abort on;
        content_by_lua '
            local sock = njt.req.socket()
            sock:receive()
            njt.sleep(1)
        ';
    }
--- request
POST /t
hello

--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
lua check broken conn
lua req cleanup
delete thread 1

--- timeout: 0.2
--- abort
--- ignore_response
--- no_error_log
[error]
--- error_log
client prematurely closed connection



=== TEST 11: njt.req.socket + receive(N) + sleep + stop
--- config
    location /t {
        lua_check_client_abort on;
        content_by_lua '
            local sock = njt.req.socket()
            sock:receive(5)
            njt.sleep(1)
        ';
    }
--- request
POST /t
hello

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
--- ignore_response
--- no_error_log
[error]
--- error_log
client prematurely closed connection



=== TEST 12: njt.req.socket + receive(n) + sleep + stop
--- config
    location /t {
        lua_check_client_abort on;
        content_by_lua '
            local sock = njt.req.socket()
            sock:receive(2)
            njt.sleep(1)
        ';
    }
--- request
POST /t
hello

--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out_like
^(?:lua check broken conn
terminate 1: ok
delete thread 1
lua req cleanup|lua check broken conn
lua req cleanup
delete thread 1)$

--- wait: 1
--- timeout: 0.2
--- abort
--- ignore_response
--- no_error_log
[error]



=== TEST 13: njt.req.socket + m * receive(n) + sleep + stop
--- config
    location /t {
        lua_check_client_abort on;
        content_by_lua '
            local sock = njt.req.socket()
            sock:receive(2)
            sock:receive(2)
            sock:receive(1)
            njt.sleep(1)
        ';
    }
--- request
POST /t
hello

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
--- ignore_response
--- no_error_log
[error]
--- error_log
client prematurely closed connection



=== TEST 14: njt.req.socket + receiveuntil + sleep + stop
--- config
    location /t {
        lua_check_client_abort on;
        content_by_lua '
            local sock = njt.req.socket()
            local it = sock:receiveuntil("\\n")
            it()
            njt.sleep(1)
        ';
    }
--- request
POST /t
hello

--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
lua check broken conn
lua req cleanup
delete thread 1

--- wait: 1
--- timeout: 0.2
--- abort
--- ignore_response
--- no_error_log
[error]
--- error_log
client prematurely closed connection



=== TEST 15: njt.req.socket + receiveuntil + it(n) + sleep + stop
--- config
    location /t {
        lua_check_client_abort on;
        content_by_lua '
            local sock = njt.req.socket()
            local it = sock:receiveuntil("\\n")
            it(2)
            it(3)
            njt.sleep(1)
        ';
    }
--- request
POST /t
hello

--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
lua check broken conn
lua check broken conn
lua req cleanup
delete thread 1

--- timeout: 0.2
--- wait: 0.1
--- abort
--- ignore_response
--- no_error_log
[error]
--- error_log
client prematurely closed connection



=== TEST 16: cosocket + stop
--- config
    location /t {
        lua_check_client_abort on;
        content_by_lua '
            njt.req.discard_body()

            local sock, err = njt.socket.tcp()
            if not sock then
                njt.log(njt.ERR, "failed to get socket: ", err)
                return
            end

            local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_REDIS_PORT)
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
        ';
    }
--- request
GET /t

--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
lua check broken conn
lua req cleanup
delete thread 1

--- wait: 1
--- timeout: 0.2
--- abort
--- ignore_response
--- no_error_log
[error]
--- error_log
client prematurely closed connection



=== TEST 17: njt.req.socket + receive n < content-length + ignore
--- config
    location /t {
        lua_check_client_abort off;
        content_by_lua '
            local sock = njt.req.socket()
            local res, err, part = sock:receive("*a")
            if not res then
                njt.log(njt.NOTICE, "failed to receive: ", err, ": ", part)
                return
            end
            error("bad")
        ';
    }
--- raw_request eval
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
lua req cleanup

--- timeout: 0.2
--- abort
--- ignore_response
--- no_error_log
[error]
--- error_log
failed to receive: client aborted: hello



=== TEST 18: njt.req.socket + receive n < content-length + stop
--- config
    location /t {
        lua_check_client_abort on;
        content_by_lua '
            local sock = njt.req.socket()
            local res, err, part = sock:receive("*a")
            if not res then
                njt.log(njt.NOTICE, "failed to receive: ", err, ": ", part)
                return
            end
            error("bad")
        ';
    }
--- raw_request eval
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
lua req cleanup

--- timeout: 0.2
--- abort
--- ignore_response
--- no_error_log
[error]
--- error_log
failed to receive: client aborted: hello



=== TEST 19: njt.req.socket + receive n == content-length + stop
--- config
    location /t {
        lua_check_client_abort on;
        content_by_lua '
            local sock = njt.req.socket()
            local res, err = sock:receive("*a")
            if not res then
                njt.log(njt.NOTICE, "failed to receive: ", err)
                return
            end
            njt.sleep(0.1)
            error("bad")
        ';
    }
--- raw_request eval
"POST /t HTTP/1.0\r
Host: localhost\r
Connection: close\r
Content-Length: 5\r
\r
hello"

--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out_like
^(?:lua check broken conn
terminate 1: ok
delete thread 1
lua req cleanup|lua check broken conn
lua check broken conn
lua req cleanup
delete thread 1)$

--- shutdown
--- ignore_response
--- no_error_log
[error]
--- error_log
client prematurely closed connection



=== TEST 20: njt.req.socket + receive n == content-length + ignore
--- config
    location /t {
        content_by_lua '
            local sock = njt.req.socket()
            local res, err = sock:receive("*a")
            if not res then
                njt.log(njt.NOTICE, "failed to receive: ", err)
                return
            end
            njt.say("done")
        ';
    }
--- raw_request eval
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
lua req cleanup

--- shutdown: 1
--- ignore_response
--- no_error_log
[error]
[alert]



=== TEST 21: njt.req.read_body + sleep + stop (log handler still gets called)
--- config
    location /t {
        lua_check_client_abort on;
        content_by_lua '
            njt.req.read_body()
            njt.sleep(0.1)
        ';
    }
--- request
POST /t
hello

--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
lua check broken conn
lua req cleanup
delete thread 1

--- shutdown: 1
--- ignore_response
--- no_error_log
[error]
--- error_log
client prematurely closed connection
--- SKIP



=== TEST 22: exec to lua + ignore
--- config
    location = /t {
        lua_check_client_abort on;
        content_by_lua '
            njt.exec("/t2")
        ';
    }

    location = /t2 {
        lua_check_client_abort off;
        content_by_lua '
            njt.sleep(1)
        ';
    }
--- request
GET /t

--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
terminate 1: ok
lua req cleanup
delete thread 1
terminate 2: ok
delete thread 2
lua req cleanup

--- wait: 1
--- timeout: 0.2
--- abort
--- ignore_response
--- no_error_log
[error]



=== TEST 23: exec to proxy + ignore
--- config
    location = /t {
        lua_check_client_abort on;
        content_by_lua '
            njt.exec("/t2")
        ';
    }

    location = /t2 {
        proxy_ignore_client_abort on;
        proxy_pass http://127.0.0.1:$server_port/sleep;
    }

    location = /sleep {
        echo_sleep 1;
    }
--- request
GET /t

--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
terminate 1: ok
lua req cleanup
delete thread 1

--- wait: 1
--- timeout: 0.2
--- abort
--- ignore_response
--- no_error_log
[error]
[alert]



=== TEST 24: exec (named location) to proxy + ignore
--- config
    location = /t {
        lua_check_client_abort on;
        content_by_lua '
            njt.exec("@t2")
        ';
    }

    location @t2 {
        proxy_ignore_client_abort on;
        proxy_pass http://127.0.0.1:$server_port/sleep;
    }

    location = /sleep {
        echo_sleep 1;
    }
--- request
GET /t

--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
terminate 1: ok
lua req cleanup
delete thread 1

--- wait: 1
--- timeout: 0.2
--- abort
--- ignore_response
--- no_error_log
[error]
[alert]



=== TEST 25: bug in njt_http_upstream_test_connect for kqueue
--- config
    location /t {
        proxy_pass http://127.0.0.1:1234/;
    }
--- request
GET /t
--- response_body_like: 502 Bad Gateway
--- error_code: 502
--- error_log eval
qr{connect\(\) failed \(\d+: Connection refused\) while connecting to upstream}
--- no_error_log
[alert]



=== TEST 26: sleep (default off)
--- config
    location /t {
        content_by_lua '
            njt.sleep(1)
        ';
    }
--- request
GET /t

--- stap2 eval: $::StapScript
--- stap eval: $::GCScript
--- stap_out
terminate 1: ok
delete thread 1
lua req cleanup

--- wait: 1
--- timeout: 0.2
--- abort
--- ignore_response
--- no_error_log
[error]
[alert]



=== TEST 27: njt.say
--- config
    location /t {
        postpone_output 1;
        content_by_lua '
            njt.sleep(0.2)
            local ok, err = njt.say("hello")
            if not ok then
                njt.log(njt.WARN, "say failed: ", err)
                return
            end
        ';
    }
--- request
GET /t

--- wait: 0.2
--- timeout: 0.1
--- abort
--- ignore_response
--- no_error_log
[error]
[alert]
--- error_log
say failed: nginx output filter error



=== TEST 28: njt.print
--- config
    location /t {
        postpone_output 1;
        content_by_lua '
            njt.sleep(0.2)
            local ok, err = njt.print("hello")
            if not ok then
                njt.log(njt.WARN, "print failed: ", err)
                return
            end
        ';
    }
--- request
GET /t

--- wait: 0.2
--- timeout: 0.1
--- abort
--- ignore_response
--- no_error_log
[error]
[alert]
--- error_log
print failed: nginx output filter error



=== TEST 29: njt.send_headers
--- config
    location /t {
        postpone_output 1;
        content_by_lua '
            njt.sleep(0.2)
            local ok, err = njt.send_headers()
            if not ok then
                njt.log(njt.WARN, "send headers failed: ", err)
                return
            end
            njt.log(njt.WARN, "send headers succeeded")
        ';
    }
--- request
GET /t

--- wait: 0.2
--- timeout: 0.1
--- abort
--- ignore_response
--- no_error_log
[error]
[alert]
--- error_log
send headers succeeded



=== TEST 30: njt.flush
--- config
    location /t {
        #postpone_output 1;
        content_by_lua '
            njt.say("hello")
            njt.sleep(0.2)
            local ok, err = njt.flush()
            if not ok then
                njt.log(njt.WARN, "flush failed: ", err)
                return
            end
            njt.log(njt.WARN, "flush succeeded")
        ';
    }
--- request
GET /t

--- wait: 0.2
--- timeout: 0.1
--- abort
--- ignore_response
--- no_error_log
[error]
[alert]
--- error_log
flush succeeded



=== TEST 31: njt.eof
--- config
    location /t {
        postpone_output 1;
        content_by_lua '
            njt.sleep(0.2)
            local ok, err = njt.eof()
            if not ok then
                njt.log(njt.WARN, "eof failed: ", err)
                return
            end
            njt.log(njt.WARN, "eof succeeded")
        ';
    }
--- request
GET /t

--- wait: 0.2
--- timeout: 0.1
--- abort
--- ignore_response
--- no_error_log
[error]
[alert]
eof succeeded
--- error_log
eof failed: nginx output filter error
