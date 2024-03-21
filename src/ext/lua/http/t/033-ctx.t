# vim:set ft= ts=4 sw=4 et fdm=marker:
use Test::Nginx::Socket::Lua;

#worker_connections(1014);
#master_on();
#workers(2);
#log_level('warn');

repeat_each(2);
#repeat_each(1);

plan tests => repeat_each() * (blocks() * 3 + 8);

#no_diff();
#no_long_string();
run_tests();

__DATA__

=== TEST 1: sanity
--- config
    location /lua {
        content_by_lua '
            njt.ctx.foo = 32;
            njt.say(njt.ctx.foo)
        ';
    }
--- request
GET /lua
--- response_body
32
--- no_error_log
[error]



=== TEST 2: rewrite, access, and content
--- config
    location /lua {
        rewrite_by_lua '
            print("foo = ", njt.ctx.foo)
            njt.ctx.foo = 76
        ';
        access_by_lua '
            njt.ctx.foo = njt.ctx.foo + 3
        ';
        content_by_lua '
            njt.say(njt.ctx.foo)
        ';
    }
--- request
GET /lua
--- response_body
79
--- no_error_log
[error]
--- grep_error_log eval: qr/foo = [^,]+/
--- log_level: info
--- grep_error_log_out
foo = nil



=== TEST 3: interal redirect clears njt.ctx
--- config
    location /echo {
        content_by_lua '
            njt.say(njt.ctx.foo)
        ';
    }
    location /lua {
        content_by_lua '
            njt.ctx.foo = njt.var.arg_data
            -- njt.say(njt.ctx.foo)
            njt.exec("/echo")
        ';
    }
--- request
GET /lua?data=hello
--- response_body
nil
--- no_error_log
[error]



=== TEST 4: subrequest has its own ctx
--- config
    location /sub {
        content_by_lua '
            njt.say("sub pre: ", njt.ctx.blah)
            njt.ctx.blah = 32
            njt.say("sub post: ", njt.ctx.blah)
        ';
    }
    location /main {
        content_by_lua '
            njt.ctx.blah = 73
            njt.say("main pre: ", njt.ctx.blah)
            local res = njt.location.capture("/sub")
            njt.print(res.body)
            njt.say("main post: ", njt.ctx.blah)
        ';
    }
--- request
    GET /main
--- response_body
main pre: 73
sub pre: nil
sub post: 32
main post: 73
--- no_error_log
[error]



=== TEST 5: overriding ctx
--- config
    location /lua {
        content_by_lua '
            njt.ctx = { foo = 32, bar = 54 };
            njt.say(njt.ctx.foo)
            njt.say(njt.ctx.bar)

            njt.ctx = { baz = 56  };
            njt.say(njt.ctx.foo)
            njt.say(njt.ctx.baz)
        ';
    }
--- request
GET /lua
--- response_body
32
54
nil
56
--- no_error_log
[error]



=== TEST 6: header filter
--- config
    location /lua {
        content_by_lua '
            njt.ctx.foo = 32;
            njt.say(njt.ctx.foo)
        ';
        header_filter_by_lua '
            njt.header.blah = njt.ctx.foo + 1
        ';
    }
--- request
GET /lua
--- response_headers
blah: 33
--- response_body
32
--- no_error_log
[error]



=== TEST 7: capture_multi
--- config
    location /other {
        content_by_lua '
            njt.say("dog = ", njt.ctx.dog)
        ';
    }

    location /lua {
        set $dog 'blah';
        set $cat 'foo';
        content_by_lua '
            local res1, res2 = njt.location.capture_multi{
                {"/other/1",
                    { ctx = { dog = "hello" }}
                },
                {"/other/2",
                    { ctx = { dog = "hiya" }}
                }
            };

            njt.print(res1.body)
            njt.print(res2.body)
            njt.say("parent: ", njt.ctx.dog)
        ';
    }
--- request
GET /lua
--- response_body
dog = hello
dog = hiya
parent: nil
--- no_error_log
[error]



=== TEST 8: set_by_lua
--- config
    location /lua {
        set_by_lua $bar 'njt.ctx.foo = 3 return 4';
        set_by_lua $foo 'return njt.ctx.foo';
        echo "foo = $foo, bar = $bar";
    }
--- request
GET /lua
--- response_body
foo = 3, bar = 4
--- no_error_log
[error]



=== TEST 9: njt.ctx leaks with njt.exec + log_by_lua
--- config
    location = /t {
        content_by_lua '
            njt.ctx.foo = 32;
            njt.exec("/f")
        ';
        log_by_lua 'njt.log(njt.WARN, "ctx.foo = ", njt.ctx.foo)';
    }
    location = /f {
        content_by_lua '
            njt.say(njt.ctx.foo)
        ';
    }
--- request
GET /t
--- response_body
nil
--- no_error_log
[error]
ctx.foo = 



=== TEST 10: memory leaks with njt.ctx + njt.req.set_uri + log_by_lua
--- config
    location = /t {
        rewrite_by_lua '
            njt.ctx.foo = 32;
            njt.req.set_uri("/f", true)
        ';
        log_by_lua 'njt.log(njt.WARN, "ctx.foo = ", njt.ctx.foo)';
    }
    location = /f {
        content_by_lua '
            njt.say(njt.ctx.foo)
        ';
    }
--- request
GET /t
--- response_body
nil
--- no_error_log
[error]
ctx.foo = 



=== TEST 11: njt.ctx + njt.exit(njt.ERROR) + log_by_lua
--- config
    location = /t {
        rewrite_by_lua '
            njt.ctx.foo = 32;
            njt.exit(njt.ERROR)
        ';
        log_by_lua 'njt.log(njt.WARN, "njt.ctx = ", njt.ctx.foo)';
    }
--- request
GET /t
--- ignore_response
--- no_error_log
[error]
--- error_log
njt.ctx = 32



=== TEST 12: njt.ctx + njt.exit(200) + log_by_lua
--- config
    location = /t {
        rewrite_by_lua '
            njt.ctx.foo = 32;
            njt.say(njt.ctx.foo)
            njt.exit(200)
        ';
        log_by_lua 'njt.log(njt.WARN, "ctx.foo = ", njt.ctx.foo)';
    }
--- request
GET /t
--- response_body
32
--- no_error_log
[error]
--- error_log
ctx.foo = 32



=== TEST 13: njt.ctx + njt.redirect + log_by_lua
--- config
    location = /t {
        rewrite_by_lua '
            njt.ctx.foo = 32;
            njt.redirect("/f")
        ';
        log_by_lua 'njt.log(njt.WARN, "njt.ctx.foo = ", 32)';
    }
--- request
GET /t
--- response_body_like: 302 Found
--- error_code: 302
--- error_log
ctx.foo = 32
--- no_error_log
[error]



=== TEST 14: set njt.ctx before internal redirects performed by other nginx modules
--- config
    location = /t {
        rewrite_by_lua '
            njt.ctx.foo = "hello world";
        ';
        echo_exec /foo;
    }

    location = /foo {
        echo hello;
    }
--- request
GET /t
--- response_body
hello
--- no_error_log
[error]
--- log_level: debug
--- error_log
lua release njt.ctx at ref



=== TEST 15: set njt.ctx before internal redirects performed by other nginx modules (with log_by_lua)
--- config
    location = /t {
        rewrite_by_lua '
            njt.ctx.foo = "hello world";
        ';
        echo_exec /foo;
    }

    location = /foo {
        echo hello;
        log_by_lua return;
    }
--- request
GET /t
--- response_body
hello
--- no_error_log
[error]
--- log_level: debug
--- error_log
lua release njt.ctx at ref



=== TEST 16: set njt.ctx before simple uri rewrite performed by other nginx modules
--- config
    location = /t {
        set_by_lua $a 'njt.ctx.foo = "hello world"; return 1';
        rewrite ^ /foo last;
        echo blah;
    }

    location = /foo {
        echo foo;
    }
--- request
GET /t
--- response_body
foo
--- no_error_log
[error]
--- log_level: debug
--- error_log
lua release njt.ctx at ref



=== TEST 17: njt.ctx gets prematurely released njt.exit()
--- config
    location = /t {
        rewrite_by_lua '
            njt.ctx.foo = 3
        ';
        content_by_lua '
            -- if njt.headers_sent ~= true then njt.send_headers() end
            return njt.exit(200)
        ';
        header_filter_by_lua '
            if njt.ctx.foo ~= 3 then
                njt.log(njt.ERR, "bad njt.ctx.foo: ", njt.ctx.foo)
            end
        ';
        }
--- request
    GET /t
--- response_body
--- no_error_log
[error]



=== TEST 18: njt.ctx gets prematurely released njt.exit() (lua_code_cache off)
--- config
    location = /t {
        lua_code_cache off;
        rewrite_by_lua '
            njt.ctx.foo = 3
        ';
        content_by_lua '
            -- if njt.headers_sent ~= true then njt.send_headers() end
            return njt.exit(200)
        ';
        header_filter_by_lua '
            if njt.ctx.foo ~= 3 then
                njt.log(njt.ERR, "bad njt.ctx.foo: ", njt.ctx.foo)
            end
        ';
        }
--- request
    GET /t
--- response_body
--- no_error_log
[error]
