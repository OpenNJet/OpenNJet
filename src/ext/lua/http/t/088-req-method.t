# vim:set ft= ts=4 sw=4 et fdm=marker:
use Test::Nginx::Socket::Lua;

#worker_connections(1014);
#master_on();
#workers(2);
#log_level('warn');

repeat_each(2);
#repeat_each(1);

plan tests => repeat_each() * (blocks() * 3);

#no_diff();
no_long_string();
run_tests();

__DATA__

=== TEST 1: get method name in main request
--- config
    location /t {
        content_by_lua '
            njt.say("method: [", njt.req.get_method(), "]")
        ';
    }
--- request
    GET /t
--- response_body
method: [GET]
--- no_error_log
[error]



=== TEST 2: get method name in subrequest
--- config
    location /t {
        echo_subrequest POST /sub;
    }

    location /sub {
        content_by_lua '
            njt.say("method: [", njt.req.get_method(), "]")
        ';
    }
--- request
    GET /t
--- response_body
method: [POST]
--- no_error_log
[error]



=== TEST 3: set GET to POST
--- config
    location /t {
        rewrite_by_lua '
            njt.req.set_method(njt.HTTP_POST)
        ';

        proxy_pass http://127.0.0.1:$server_port/echo;
    }

    location /echo {
        echo $request_method;
    }
--- request
GET /t
--- response_body
POST
--- no_error_log
[error]



=== TEST 4: set POST to GET
--- config
    location /t {
        rewrite_by_lua '
            njt.req.set_method(njt.HTTP_GET)
        ';

        proxy_pass http://127.0.0.1:$server_port/echo;
    }

    location /echo {
        echo $request_method;
    }
--- request
POST /t
hello world
--- response_body
GET
--- no_error_log
[error]



=== TEST 5: set POST to DELETE
--- config
    location /t {
        rewrite_by_lua '
            njt.req.set_method(njt.HTTP_DELETE)
        ';

        proxy_pass http://127.0.0.1:$server_port/echo;
    }

    location /echo {
        echo $request_method;
    }
--- request
POST /t
hello world
--- response_body
DELETE
--- no_error_log
[error]



=== TEST 6: set POST to PUT
--- config
    location /t {
        rewrite_by_lua '
            njt.req.set_method(njt.HTTP_PUT)
        ';

        proxy_pass http://127.0.0.1:$server_port/echo;
    }

    location /echo {
        echo $request_method;
    }
--- request
POST /t
hello world
--- response_body
PUT
--- no_error_log
[error]



=== TEST 7: set POST to PUT (using $requeset_method)
--- config
    location /t {
        rewrite_by_lua '
            njt.req.set_method(njt.HTTP_PUT)
        ';

        echo $request_method;
    }
--- request
POST /t
hello world
--- response_body
PUT
--- no_error_log
[error]



=== TEST 8: set GET to HEAD
--- config
    location /t {
        rewrite_by_lua '
            njt.req.set_method(njt.HTTP_HEAD)
        ';

        proxy_pass http://127.0.0.1:$server_port/echo;
        #proxy_pass http://127.0.0.1:8888/;
    }

    location /echo {
        echo $request_method;
    }
--- request
GET /t
--- response_body
--- no_error_log
[error]



=== TEST 9: set method name in subrequest
--- config
    location /t {
        echo_subrequest POST /sub;
        echo "main: $echo_request_method";
    }

    location /sub {
        content_by_lua '
            njt.req.set_method(njt.HTTP_PUT)
            njt.say("sub: ", njt.var.echo_request_method)
        ';
    }
--- request
    GET /t
--- response_body
sub: PUT
main: GET
--- no_error_log
[error]



=== TEST 10: set HEAD to GET
--- config
    location /t {
        rewrite_by_lua '
            njt.req.set_method(njt.HTTP_GET)
        ';

        echo "method: $echo_request_method";
    }
--- request
    HEAD /t
--- response_body
method: GET
--- no_error_log
[error]



=== TEST 11: set GET to WebDAV methods
--- config
    location /t {
        content_by_lua '
            local methods = {
                njt.HTTP_MKCOL,
                njt.HTTP_COPY,
                njt.HTTP_MOVE,
                njt.HTTP_PROPFIND,
                njt.HTTP_PROPPATCH,
                njt.HTTP_LOCK,
                njt.HTTP_UNLOCK,
                njt.HTTP_PATCH,
                njt.HTTP_TRACE,
            }

            for i, method in ipairs(methods) do
                njt.req.set_method(method)
                njt.say("method: ", njt.var.echo_request_method)
            end
        ';
    }
--- request
    HEAD /t
--- response_body
method: MKCOL
method: COPY
method: MOVE
method: PROPFIND
method: PROPPATCH
method: LOCK
method: UNLOCK
method: PATCH
method: TRACE
--- no_error_log
[error]
