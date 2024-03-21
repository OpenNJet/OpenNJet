# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua;

#worker_connections(1014);
#master_on();
#workers(2);
log_level('debug');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 3 + 10);

#no_diff();
#no_long_string();
run_tests();

__DATA__

=== TEST 1: log_by_lua
--- config
    location /lua {
        echo hello;
        log_by_lua 'njt.log(njt.ERR, "Hello from log_by_lua: ", njt.var.uri)';
    }
--- request
GET /lua
--- response_body
hello
--- error_log
Hello from log_by_lua: /lua



=== TEST 2: log_by_lua_file
--- config
    location /lua {
        echo hello;
        log_by_lua_file html/a.lua;
    }
--- user_files
>>> a.lua
njt.log(njt.ERR, "Hello from log_by_lua: ", njt.var.uri)
--- request
GET /lua
--- response_body
hello
--- error_log
Hello from log_by_lua: /lua



=== TEST 3: log_by_lua_file & content_by_lua
--- config
    location /lua {
        set $counter 3;
        content_by_lua 'njt.var.counter = njt.var.counter + 1 njt.say(njt.var.counter)';
        log_by_lua_file html/a.lua;
    }
--- user_files
>>> a.lua
njt.log(njt.ERR, "Hello from log_by_lua: ", njt.var.counter * 2)
--- request
GET /lua
--- response_body
4
--- error_log
Hello from log_by_lua: 8



=== TEST 4: njt.ctx available in log_by_lua (already defined)
--- config
    location /lua {
        content_by_lua 'njt.ctx.counter = 3 njt.say(njt.ctx.counter)';
        log_by_lua 'njt.log(njt.ERR, "njt.ctx.counter: ", njt.ctx.counter)';
    }
--- request
GET /lua
--- response_body
3
--- error_log
njt.ctx.counter: 3
lua release njt.ctx



=== TEST 5: njt.ctx available in log_by_lua (not defined yet)
--- config
    location /lua {
        echo hello;
        log_by_lua '
            njt.log(njt.ERR, "njt.ctx.counter: ", njt.ctx.counter)
            njt.ctx.counter = "hello world"
        ';
    }
--- request
GET /lua
--- response_body
hello
--- error_log
njt.ctx.counter: nil
lua release njt.ctx



=== TEST 6: log_by_lua + shared dict
--- http_config
    lua_shared_dict foo 100k;
--- config
    location /lua {
        echo hello;
        log_by_lua '
            local foo = njt.shared.foo
            local key = njt.var.uri .. njt.status
            local newval, err = foo:incr(key, 1)
            if not newval then
                if err == "not found" then
                    foo:add(key, 0)
                    newval, err = foo:incr(key, 1)
                    if not newval then
                        njt.log(njt.ERR, "failed to incr ", key, ": ", err)
                        return
                    end
                else
                    njt.log(njt.ERR, "failed to incr ", key, ": ", err)
                    return
                end
            end
            print(key, ": ", foo:get(key))
        ';
    }
--- request
GET /lua
--- response_body
hello
--- error_log eval
qr{/lua200: [12]}
--- no_error_log
[error]



=== TEST 7: njt.ctx used in different locations and different ctx (1)
--- config
    location /t {
        echo hello;
        log_by_lua '
            njt.log(njt.ERR, "njt.ctx.counter: ", njt.ctx.counter)
        ';
    }

    location /t2 {
        content_by_lua '
            njt.ctx.counter = 32
            njt.say("hello")
        ';
    }
--- request
GET /t
--- response_body
hello
--- error_log
njt.ctx.counter: nil
lua release njt.ctx



=== TEST 8: njt.ctx used in different locations and different ctx (2)
--- config
    location /t {
        echo hello;
        log_by_lua '
            njt.log(njt.ERR, "njt.ctx.counter: ", njt.ctx.counter)
        ';
    }

    location /t2 {
        content_by_lua '
            njt.ctx.counter = 32
            njt.say(njt.ctx.counter)
        ';
    }
--- request
GET /t2
--- response_body
32
--- error_log
lua release njt.ctx



=== TEST 9: lua error (string)
--- config
    location /lua {
        log_by_lua 'error("Bad")';
        echo ok;
    }
--- request
GET /lua
--- response_body
ok
--- error_log eval
qr/failed to run log_by_lua\*: log_by_lua\(nginx\.conf:\d+\):1: Bad/



=== TEST 10: lua error (nil)
--- config
    location /lua {
        log_by_lua 'error(nil)';
        echo ok;
    }
--- request
GET /lua
--- response_body
ok
--- error_log
failed to run log_by_lua*: unknown reason



=== TEST 11: globals sharing
--- config
    location /lua {
        echo ok;
        log_by_lua '
            if not foo then
                foo = 1
            else
                njt.log(njt.INFO, "old foo: ", foo)
                foo = foo + 1
            end
            njt.log(njt.WARN, "foo = ", foo)
        ';
    }
--- request
GET /lua
--- response_body
ok
--- grep_error_log eval: qr/old foo: \d+/
--- grep_error_log_out eval
["", "old foo: 1\n"]



=== TEST 12: no njt.print
--- config
    location /lua {
        log_by_lua "njt.print(32) return 1";
        echo ok;
    }
--- request
GET /lua
--- response_body
ok
--- error_log
API disabled in the context of log_by_lua*



=== TEST 13: no njt.say
--- config
    location /lua {
        log_by_lua "njt.say(32) return 1";
        echo ok;
    }
--- request
GET /lua
--- response_body
ok
--- error_log
API disabled in the context of log_by_lua*



=== TEST 14: no njt.flush
--- config
    location /lua {
        log_by_lua "njt.flush()";
        echo ok;
    }
--- request
GET /lua
--- response_body
ok
--- error_log
API disabled in the context of log_by_lua*



=== TEST 15: no njt.eof
--- config
    location /lua {
        log_by_lua "njt.eof()";
        echo ok;
    }
--- request
GET /lua
--- response_body
ok
--- error_log
API disabled in the context of log_by_lua*



=== TEST 16: no njt.send_headers
--- config
    location /lua {
        log_by_lua "njt.send_headers()";
        echo ok;
    }
--- request
GET /lua
--- response_body
ok
--- error_log
API disabled in the context of log_by_lua*



=== TEST 17: no njt.location.capture
--- config
    location /lua {
        log_by_lua 'njt.location.capture("/sub")';
        echo ok;
    }

    location /sub {
        echo sub;
    }
--- request
GET /lua
--- response_body
ok
--- error_log
API disabled in the context of log_by_lua*



=== TEST 18: no njt.location.capture_multi
--- config
    location /lua {
        log_by_lua 'njt.location.capture_multi{{"/sub"}}';
        echo ok;
    }

    location /sub {
        echo sub;
    }
--- request
GET /lua
--- response_body
ok
--- error_log
API disabled in the context of log_by_lua*



=== TEST 19: no njt.exit
--- config
    location /lua {
        log_by_lua 'njt.exit(0)';
        echo ok;
    }
--- request
GET /lua
--- response_body
ok
--- error_log
API disabled in the context of log_by_lua*



=== TEST 20: no njt.redirect
--- config
    location /lua {
        log_by_lua 'njt.redirect("/blah")';
        echo ok;
    }
--- request
GET /lua
--- response_body
ok
--- error_log
API disabled in the context of log_by_lua*



=== TEST 21: no njt.exec
--- config
    location /lua {
        log_by_lua 'njt.exec("/blah")';
        echo ok;
    }
--- request
GET /lua
--- response_body
ok
--- error_log
API disabled in the context of log_by_lua*



=== TEST 22: no njt.req.set_uri(uri, true)
--- config
    location /lua {
        log_by_lua 'njt.req.set_uri("/blah", true)';
        echo ok;
    }
--- request
GET /lua
--- response_body
ok
--- error_log
API disabled in the context of log_by_lua*



=== TEST 23: njt.req.set_uri(uri) exists
--- config
    location /lua {
        log_by_lua 'njt.req.set_uri("/blah") print("log_by_lua: uri: ", njt.var.uri)';
        echo ok;
    }
--- request
GET /lua
--- response_body
ok
--- error_log
log_by_lua: uri: /blah



=== TEST 24: no njt.req.read_body()
--- config
    location /lua {
        log_by_lua 'njt.req.read_body()';
        echo ok;
    }
--- request
GET /lua
--- response_body
ok
--- error_log
API disabled in the context of log_by_lua*



=== TEST 25: no njt.req.socket()
--- config
    location /lua {
        log_by_lua 'return njt.req.socket()';
        echo ok;
    }
--- request
GET /lua
--- response_body
ok
--- error_log
API disabled in the context of log_by_lua*



=== TEST 26: no njt.socket.tcp()
--- config
    location /lua {
        log_by_lua 'return njt.socket.tcp()';
        echo ok;
    }
--- request
GET /lua
--- response_body
ok
--- error_log
API disabled in the context of log_by_lua*



=== TEST 27: no njt.socket.connect()
--- config
    location /lua {
        log_by_lua 'return njt.socket.connect("127.0.0.1", 80)';
        echo ok;
    }
--- request
GET /lua
--- response_body
ok
--- error_log
API disabled in the context of log_by_lua*



=== TEST 28: backtrace
--- config
    location /t {
        echo ok;
        log_by_lua '
            local bar
            local function foo()
                bar()
            end

            function bar()
                error("something bad happened")
            end

            foo()
        ';
    }
--- request
    GET /t
--- response_body
ok
--- error_log
something bad happened
stack traceback:
in function 'error'
in function 'bar'
in function 'foo'



=== TEST 29: Lua file does not exist
--- config
    location /lua {
        echo ok;
        log_by_lua_file html/test2.lua;
    }
--- user_files
>>> test.lua
v = njt.var["request_uri"]
njt.print("request_uri: ", v, "\n")
--- request
GET /lua?a=1&b=2
--- response_body
ok
--- error_log eval
qr/failed to load external Lua file ".*?test2\.lua": cannot open .*? No such file or directory/



=== TEST 30: log_by_lua runs before access logging (github issue #254)
--- config
    location /lua {
        echo ok;
        access_log logs/foo.log;
        log_by_lua 'print("hello")';
    }
--- request
GET /lua
--- stap
F(njt_http_log_handler) {
    println("log handler")
}
F(njt_http_lua_log_handler) {
    println("lua log handler")
}
--- stap_out
lua log handler
log handler

--- response_body
ok
--- no_error_log
[error]



=== TEST 31: reading njt.header.HEADER in log_by_lua
--- config
    location /lua {
        echo ok;
        log_by_lua 'njt.log(njt.WARN, "content-type: ", njt.header.content_type)';
    }
--- request
GET /lua

--- response_body
ok
--- error_log eval
qr{log_by_lua\(nginx\.conf:\d+\):1: content-type: text/plain}

--- no_error_log
[error]
