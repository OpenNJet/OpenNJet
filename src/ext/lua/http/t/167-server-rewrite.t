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

plan tests => repeat_each() * (blocks() * 3 + 10);

#log_level("info");
#no_long_string();

run_tests();

__DATA__

=== TEST 1: server_rewrite_by_lua_block in http
--- http_config
    server_rewrite_by_lua_block {
        njt.ctx.a = "server_rewrite_by_lua_block in http"
    }
--- config
    location /lua {
        content_by_lua_block {
            njt.say(njt.ctx.a)
            njt.log(njt.INFO, njt.ctx.a)
        }
    }
--- request
GET /lua
--- response_body
server_rewrite_by_lua_block in http
--- error_log
server_rewrite_by_lua_block in http
--- no_error_log
[error]



=== TEST 2: server_rewrite_by_lua_block in server
--- config
    server_rewrite_by_lua_block {
        njt.log(njt.INFO, "server_rewrite_by_lua_block in server")
    }
    location /lua {
        content_by_lua_block {
            njt.say("OK")
        }
    }
--- request
GET /lua
--- response_body
OK
--- error_log
server_rewrite_by_lua_block in server
--- no_error_log
[error]



=== TEST 3: redirect
--- config
    server_rewrite_by_lua_block {
        njt.redirect("/foo")
    }
--- request
GET /lua
--- raw_response_headers_like eval
qr{[Ll]ocation: /foo\r\n}
--- response_body_like: 302 Found
--- error_code: 302
--- no_error_log
[error]



=== TEST 4: flush
--- config
    server_rewrite_by_lua_block {
        njt.say("foo")
        njt.flush(true)
    }
    location /lua {
        content_by_lua_block {
            njt.say("OK")
        }
    }
--- request
GET /lua
--- response_body
foo
--- no_error_log
[error]



=== TEST 5: eof
--- config
    server_rewrite_by_lua_block {
        njt.say("foo")
        njt.eof()
    }
    location /lua {
        content_by_lua_block {
            njt.say("OK")
        }
    }
--- request
GET /lua
--- response_body
foo
--- no_error_log
[error]



=== TEST 6: send_headers
--- config
    server_rewrite_by_lua_block {
        njt.header["Foox"] = {"conx1", "conx2" }
        njt.header["Fooy"] = {"cony1", "cony2" }
        njt.send_headers()
    }
    location /lua {
        content_by_lua_block {
            njt.say("OK")
        }
    }
--- request
GET /lua
--- response_body
--- response_headers
Foox: conx1, conx2
Fooy: cony1, cony2
--- no_error_log
[error]



=== TEST 7: read_body
--- config
    server_rewrite_by_lua_block {
        njt.req.read_body()
        njt.say(njt.var.request_body)
    }
--- request
POST /lua
hello, world
--- response_body
hello, world
--- no_error_log
[error]



=== TEST 8: req_sock
--- config
    server_rewrite_by_lua_block {
        local sock = njt.req.socket()
            sock:receive(2)
            sock:receive(2)
            sock:receive(1)
            njt.sleep(1)
    }
    location /lua {
        content_by_lua_block {
            njt.say("OK")
        }
    }
--- request
POST /lua
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
--- skip_eval: 2:$ENV{TEST_NGINX_USE_HTTP3}



=== TEST 9: rewrite args (not break cycle by default)
--- config
    location /bar {
        echo "bar: $uri?$args";
    }
    server_rewrite_by_lua_block {
        if njt.var.uri ~= "/bar" then
            njt.req.set_uri_args("hello")
            njt.req.set_uri("/bar", true)
        end
    }
    location /foo {

        echo "foo: $uri?$args";
    }
--- request
    GET /foo?world
--- response_body
bar: /bar?hello



=== TEST 10: server_rewrite_by_lua_block overwrite by server
--- http_config
    server_rewrite_by_lua_block {
        njt.log(njt.INFO, "server_rewrite_by_lua_block in http")
    }
--- config
    server_rewrite_by_lua_block {
        njt.log(njt.INFO, "server_rewrite_by_lua_block in server")
    }
    location /lua {
        content_by_lua_block {
            njt.say("OK")
        }
    }
--- request
GET /lua
--- response_body
OK
--- error_log
server_rewrite_by_lua_block in server
--- no_error_log
[error]



=== TEST 11: sleep
--- config
    server_rewrite_by_lua_block {
        njt.sleep(0.001)
        njt.log(njt.INFO, "server_rewrite_by_lua_block in server")
    }
    location /lua {
        content_by_lua_block {
            njt.say("OK")
        }
    }
--- request
GET /lua
--- response_body
OK
--- error_log
server_rewrite_by_lua_block in server
--- no_error_log
[error]



=== TEST 12: njt.exit(njt.OK)
--- config
    server_rewrite_by_lua_block {
        njt.log(njt.INFO, "njt.exit")
        njt.exit(njt.OK)
    }
    location /lua {
        content_by_lua_block {
        njt.say("OK")
        }
    }
--- request
GET /lua
--- response_body
OK
--- error_log
njt.exit
--- no_error_log
[error]



=== TEST 13: njt.exit(503)
--- config
    server_rewrite_by_lua_block {
        njt.exit(503)
    }
    location /lua {
        content_by_lua_block {
         njt.log(njt.ERR, "content_by_lua")
         njt.say("OK")
        }
    }
--- request
GET /lua
--- error_code: 503
--- no_error_log
[error]



=== TEST 14: subrequests
--- config
    server_rewrite_by_lua_block {
        njt.log(njt.INFO, "is_subrequest:", njt.is_subrequest)
    }

    location /lua {
        content_by_lua_block {
            local res = njt.location.capture("/sub")
            njt.print(res.body)
        }
    }

    location /sub {
        content_by_lua_block {
            njt.say("OK")
        }
    }

--- request
GET /lua
--- response_body
OK
--- error_log
is_subrequest:false
is_subrequest:true
--- no_error_log
[error]



=== TEST 15: rewrite by njt_http_rewrite_module
--- config
    server_rewrite_by_lua_block {
        njt.log(njt.INFO, "uri is ", njt.var.uri)
    }

    rewrite ^ /re;

    location /re {
        content_by_lua_block {
            njt.say("RE")
        }
    }

    location /ok {
        content_by_lua_block {
            njt.say("OK")
        }
    }

--- request
GET /lua
--- response_body
RE
--- error_log
uri is /lua
--- no_error_log
[error]



=== TEST 16: exec
--- config
    server_rewrite_by_lua_block {
        if njt.var.uri ~= "/ok" then
            njt.exec("/ok")
        end
        njt.log(njt.INFO, "uri is ", njt.var.uri)
    }

    location /ok {
        content_by_lua_block {
            njt.say("OK")
        }
    }

--- request
GET /lua
--- response_body
OK
--- error_log
uri is /ok
--- no_error_log
[error]



=== TEST 17: server_rewrite_by_lua and rewrite_by_lua
--- http_config
    server_rewrite_by_lua_block {
        njt.log(njt.INFO, "server_rewrite_by_lua_block in http")
    }
--- config
    location /lua {
        rewrite_by_lua_block {
            njt.log(njt.INFO, "rewrite_by_lua_block in location")
        }
        content_by_lua_block {
            njt.say("OK")
        }
    }
--- request
GET /lua
--- response_body
OK
--- error_log
server_rewrite_by_lua_block in http
rewrite_by_lua_block in location
--- no_error_log
[error]



=== TEST 18: server_rewrite_by_lua_file
--- http_config
    server_rewrite_by_lua_file 'html/foo.lua';
--- config
    location /lua {
        content_by_lua_block {
            njt.say("OK")
        }
    }
--- request
GET /lua
--- user_files
>>> foo.lua
njt.log(njt.INFO, "rewrite_by_lua_file in server")
--- response_body
OK
--- error_log
rewrite_by_lua_file in server
--- no_error_log
[error]



=== TEST 19: syntax error server_rewrite_by_lua_block in http
--- http_config
    server_rewrite_by_lua_block {
        'for end';
    }
--- config
    location /lua {
        content_by_lua_block {
            njt.say("OK")
        }
    }
--- request
GET /lua
--- ignore_response
--- error_log
failed to load inlined Lua code: server_rewrite_by_lua(nginx.conf:25):2: unexpected symbol near ''for end''
--- no_error_log
no_such_error



=== TEST 20: syntax error server_rewrite_by_lua_block in server
--- config
    server_rewrite_by_lua_block {
        'for end';
    }
    location /lua {
        content_by_lua_block {
            njt.say("Hello world")
        }
    }
--- request
GET /lua
--- ignore_response
--- error_log
failed to load inlined Lua code: server_rewrite_by_lua(nginx.conf:39):2: unexpected symbol near ''for end''
--- no_error_log
no_such_error
