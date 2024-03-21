# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua;

repeat_each(10);

plan tests => repeat_each() * (blocks() * 2 + 4);

#$ENV{LUA_PATH} = $ENV{HOME} . '/work/JSON4Lua-0.9.30/json/?.lua';
$ENV{TEST_NGINX_MYSQL_PORT} ||= 3306;
$ENV{TEST_NGINX_MEMCACHED_PORT} ||= 11211;

#log_level 'warn';
no_long_string();

run_tests();

__DATA__

=== TEST 1: sanity
--- config
    location /foo {
        content_by_lua '
            local res1, res2 = njt.location.capture_multi{
                { "/a" },
                { "/b" },
            }
            njt.say("res1.status = " .. res1.status)
            njt.say("res1.body = " .. res1.body)
            njt.say("res2.status = " .. res2.status)
            njt.say("res2.body = " .. res2.body)
        ';
    }
    location /a {
        echo -n a;
    }
    location /b {
        echo -n b;
    }
--- request
    GET /foo
--- response_body
res1.status = 200
res1.body = a
res2.status = 200
res2.body = b



=== TEST 2: 4 concurrent requests
--- config
    location /foo {
        content_by_lua '
            local res1, res2, res3, res4 = njt.location.capture_multi{
                { "/a" },
                { "/b" },
                { "/c" },
                { "/d" },
            }
            njt.say("res1.status = " .. res1.status)
            njt.say("res1.body = " .. res1.body)

            njt.say("res2.status = " .. res2.status)
            njt.say("res2.body = " .. res2.body)

            njt.say("res3.status = " .. res3.status)
            njt.say("res3.body = " .. res3.body)

            njt.say("res4.status = " .. res4.status)
            njt.say("res4.body = " .. res4.body)
        ';
    }
    location ~ '^/([a-d])$' {
        echo -n $1;
    }
--- request
    GET /foo
--- response_body
res1.status = 200
res1.body = a
res2.status = 200
res2.body = b
res3.status = 200
res3.body = c
res4.status = 200
res4.body = d



=== TEST 3: capture multi in series
--- config
    location /foo {
        content_by_lua '
            local res1, res2 = njt.location.capture_multi{
                { "/a" },
                { "/b" },
            }
            njt.say("res1.status = " .. res1.status)
            njt.say("res1.body = " .. res1.body)
            njt.say("res2.status = " .. res2.status)
            njt.say("res2.body = " .. res2.body)

            res1, res2 = njt.location.capture_multi{
                { "/a" },
                { "/b" },
            }
            njt.say("2 res1.status = " .. res1.status)
            njt.say("2 res1.body = " .. res1.body)
            njt.say("2 res2.status = " .. res2.status)
            njt.say("2 res2.body = " .. res2.body)

        ';
    }
    location /a {
        echo -n a;
    }
    location /b {
        echo -n b;
    }
--- request
    GET /foo
--- response_body
res1.status = 200
res1.body = a
res2.status = 200
res2.body = b
2 res1.status = 200
2 res1.body = a
2 res2.status = 200
2 res2.body = b



=== TEST 4: capture multi in subrequest
--- config
    location /foo {
        content_by_lua '
            local res1, res2 = njt.location.capture_multi{
                { "/a" },
                { "/b" },
            }

            local n = njt.var.arg_n

            njt.say(n .. " res1.status = " .. res1.status)
            njt.say(n .. " res1.body = " .. res1.body)
            njt.say(n .. " res2.status = " .. res2.status)
            njt.say(n .. " res2.body = " .. res2.body)
        ';
    }

    location /main {
        content_by_lua '
            local res = njt.location.capture("/foo?n=1")
            njt.say("top res.status = " .. res.status)
            njt.say("top res.body = [" .. res.body .. "]")
        ';
    }

    location /a {
        echo -n a;
    }

    location /b {
        echo -n b;
    }
--- request
    GET /main
--- response_body
top res.status = 200
top res.body = [1 res1.status = 200
1 res1.body = a
1 res2.status = 200
1 res2.body = b
]



=== TEST 5: capture multi in parallel
--- config
    location ~ '^/(foo|bar)$' {
        set $tag $1;
        content_by_lua '
            local res1, res2
            if njt.var.tag == "foo" then
                res1, res2 = njt.location.capture_multi{
                    { "/a" },
                    { "/b" },
                }
            else
                res1, res2 = njt.location.capture_multi{
                    { "/c" },
                    { "/d" },
                }
            end

            local n = njt.var.arg_n

            njt.say(n .. " res1.status = " .. res1.status)
            njt.say(n .. " res1.body = " .. res1.body)
            njt.say(n .. " res2.status = " .. res2.status)
            njt.say(n .. " res2.body = " .. res2.body)
        ';
    }

    location /main {
        content_by_lua '
            local res1, res2 = njt.location.capture_multi{
                { "/foo?n=1" },
                { "/bar?n=2" },
            }

            njt.say("top res1.status = " .. res1.status)
            njt.say("top res1.body = [" .. res1.body .. "]")
            njt.say("top res2.status = " .. res2.status)
            njt.say("top res2.body = [" .. res2.body .. "]")
        ';
    }

    location ~ '^/([abcd])$' {
        echo -n $1;
    }
--- request
    GET /main
--- response_body
top res1.status = 200
top res1.body = [1 res1.status = 200
1 res1.body = a
1 res2.status = 200
1 res2.body = b
]
top res2.status = 200
top res2.body = [2 res1.status = 200
2 res1.body = c
2 res2.status = 200
2 res2.body = d
]



=== TEST 6: memc sanity
--- config
    location /foo {
        content_by_lua '
            local res1, res2 = njt.location.capture_multi{
                { "/a" },
                { "/b" },
            }
            njt.say("res1.status = " .. res1.status)
            njt.say("res1.body = " .. res1.body)
            njt.say("res2.status = " .. res2.status)
            njt.say("res2.body = " .. res2.body)
        ';
    }
    location ~ '^/[ab]$' {
        set $memc_key $uri;
        set $memc_value hello;
        set $memc_cmd set;
        memc_pass 127.0.0.1:$TEST_NGINX_MEMCACHED_PORT;
    }
--- request
    GET /foo
--- response_body eval
"res1.status = 201
res1.body = STORED\r

res2.status = 201
res2.body = STORED\r

"



=== TEST 7: memc muti + multi
--- config
    location /main {
        content_by_lua '
            local res1, res2 = njt.location.capture_multi{
                { "/foo?n=1" },
                { "/bar?n=2" },
            }
            njt.say("res1.status = " .. res1.status)
            njt.say("res1.body = [" .. res1.body .. "]")
            njt.say("res2.status = " .. res2.status)
            njt.say("res2.body = [" .. res2.body .. "]")
        ';
    }
    location ~ '^/(foo|bar)$' {
        set $tag $1;
        content_by_lua '
            local res1, res2
            if njt.var.tag == "foo" then
                res1, res2 = njt.location.capture_multi{
                    { "/a" },
                    { "/b" },
                }
            else
                res1, res2 = njt.location.capture_multi{
                    { "/c" },
                    { "/d" },
                }
            end
            print("args: " .. njt.var.args)
            local n = njt.var.arg_n
            njt.say(n .. " res1.status = " .. res1.status)
            njt.say(n .. " res1.body = " .. res1.body)
            njt.say(n .. " res2.status = " .. res2.status)
            njt.say(n .. " res2.body = " .. res2.body)
        ';
    }
    location ~ '^/[abcd]$' {
        set $memc_key $uri;
        set $memc_value hello;
        set $memc_cmd set;
        memc_pass 127.0.0.1:$TEST_NGINX_MEMCACHED_PORT;
    }
--- request
    GET /main
--- response_body eval
"res1.status = 200
res1.body = [1 res1.status = 201
1 res1.body = STORED\r

1 res2.status = 201
1 res2.body = STORED\r

]
res2.status = 200
res2.body = [2 res1.status = 201
2 res1.body = STORED\r

2 res2.status = 201
2 res2.body = STORED\r

]
"



=== TEST 8: memc 4 concurrent requests
--- config
    location /foo {
        content_by_lua '
            local res1, res2, res3, res4 = njt.location.capture_multi{
                { "/a" },
                { "/b" },
                { "/c" },
                { "/d" },
            }
            njt.say("res1.status = " .. res1.status)
            njt.say("res1.body = " .. res1.body)

            njt.say("res2.status = " .. res2.status)
            njt.say("res2.body = " .. res2.body)

            njt.say("res3.status = " .. res3.status)
            njt.say("res3.body = " .. res3.body)

            njt.say("res4.status = " .. res4.status)
            njt.say("res4.body = " .. res4.body)
        ';
    }
    location ~ '^/[a-d]$' {
        set $memc_key $uri;
        set $memc_value hello;
        set $memc_cmd set;
        memc_pass 127.0.0.1:$TEST_NGINX_MEMCACHED_PORT;
    }
--- request
    GET /foo
--- response_body eval
"res1.status = 201
res1.body = STORED\r

res2.status = 201
res2.body = STORED\r

res3.status = 201
res3.body = STORED\r

res4.status = 201
res4.body = STORED\r

"



=== TEST 9: capture multi in series (more complex)
--- config
    location /foo {
        content_by_lua '
            local res1, res2 = njt.location.capture_multi{
                { "/a" },
                { "/b" },
            }
            res1, res2 = njt.location.capture_multi{
                { "/a" },
                { "/b" },
            }
            local res3, res4 = njt.location.capture_multi{
                { "/a" },
                { "/b" },
            }
            res3, res4 = njt.location.capture_multi{
                { "/a" },
                { "/b" },
            }

            njt.say("res1.status = " .. res1.status)
            njt.say("res1.body = " .. res1.body)
            njt.say("res2.status = " .. res2.status)
            njt.say("res2.body = " .. res2.body)
            njt.say("res3.status = " .. res3.status)
            njt.say("res3.body = " .. res3.body)
            njt.say("res4.status = " .. res4.status)
            njt.say("res4.body = " .. res4.body)

        ';
    }
    location /a {
        echo -n a;
    }
    location /b {
        echo -n b;
    }
    location /main {
        content_by_lua '
            local res1, res2 = njt.location.capture_multi{
                { "/foo" },
                { "/foo" },
            }
            local res3, res4 = njt.location.capture_multi{
                { "/foo" },
                { "/foo" },
            }
            njt.print(res1.body)
            njt.print(res2.body)
            njt.print(res3.body)
            njt.print(res4.body)
        ';
    }
--- request
    GET /main
--- response_body eval
"res1.status = 200
res1.body = a
res2.status = 200
res2.body = b
res3.status = 200
res3.body = a
res4.status = 200
res4.body = b
" x 4



=== TEST 10: capture multi in series (more complex, using memc)
--- config
    location /foo {
        content_by_lua '
            local res1, res2 = njt.location.capture_multi{
                { "/a" },
                { "/b" },
            }
            res1, res2 = njt.location.capture_multi{
                { "/a" },
                { "/b" },
            }
            local res3, res4 = njt.location.capture_multi{
                { "/c" },
                { "/d" },
            }
            res3, res4 = njt.location.capture_multi{
                { "/e" },
                { "/f" },
            }

            njt.say("res1.status = " .. res1.status)
            njt.say("res1.body = " .. res1.body)
            njt.say("res2.status = " .. res2.status)
            njt.say("res2.body = " .. res2.body)
            njt.say("res3.status = " .. res3.status)
            njt.say("res3.body = " .. res3.body)
            njt.say("res4.status = " .. res4.status)
            njt.say("res4.body = " .. res4.body)
        ';
    }

    location /memc {
        set $memc_key $arg_val;
        set $memc_value $arg_val;
        set $memc_cmd $arg_cmd;
        memc_pass 127.0.0.1:$TEST_NGINX_MEMCACHED_PORT;
    }

    location ~ '^/([a-f])$' {
        set $tag $1;
        content_by_lua '
            njt.location.capture("/memc?cmd=set&val=" .. njt.var.tag)
            local res = njt.location.capture("/memc?cmd=get&val=" .. njt.var.tag)
            njt.print(res.body)
        ';
    }

    location /main {
        content_by_lua '
            local res1, res2 = njt.location.capture_multi{
                { "/foo" },
                { "/foo" },
            }
            local res3, res4 = njt.location.capture_multi{
                { "/foo" },
                { "/foo" },
            }
            njt.print(res1.body)
            njt.print(res2.body)
            njt.print(res3.body)
            njt.print(res4.body)
        ';
    }
--- request
    GET /main
--- response_body2
--- response_body eval
"res1.status = 200
res1.body = a
res2.status = 200
res2.body = b
res3.status = 200
res3.body = e
res4.status = 200
res4.body = f
" x 4
--- no_error_log eval
["[error]", "[alert]"]
--- timeout: 10



=== TEST 11: a mixture of rewrite, access, content phases
--- config
    location /main {
        rewrite_by_lua '
            local res = njt.location.capture("/a")
            print("rewrite a: " .. res.body)

            res = njt.location.capture("/b")
            print("rewrite b: " .. res.body)

            res = njt.location.capture("/c")
            print("rewrite c: " .. res.body)
        ';

        access_by_lua '
            local res = njt.location.capture("/A")
            print("access A: " .. res.body)

            res = njt.location.capture("/B")
            print("access B: " .. res.body)
        ';

        content_by_lua '
            local res = njt.location.capture("/d")
            njt.say("content d: " .. res.body)

            res = njt.location.capture("/e")
            njt.say("content e: " .. res.body)

            res = njt.location.capture("/f")
            njt.say("content f: " .. res.body)
        ';
    }

    location /memc {
        set $memc_key $arg_val;
        set $memc_value $arg_val;
        set $memc_cmd $arg_cmd;
        memc_pass 127.0.0.1:$TEST_NGINX_MEMCACHED_PORT;
    }

    location ~ '^/([A-F])$' {
        echo -n $1;
    }

    location ~ '^/([a-f])$' {
        set $tag $1;
        content_by_lua '
            njt.location.capture("/memc?cmd=set&val=" .. njt.var.tag)
            local res = njt.location.capture("/memc?cmd=get&val=" .. njt.var.tag)
            njt.print(res.body)
        ';
    }
--- request
    GET /main
--- response_body
content d: d
content e: e
content f: f

--- log_level: info
--- grep_error_log eval: qr/rewrite .+?(?= while )|access .+?(?=,)/
--- grep_error_log_out
rewrite a: a
rewrite b: b
rewrite c: c
access A: A
access B: B



=== TEST 12: a mixture of rewrite, access, content phases
--- config
    location /main {
        rewrite_by_lua '
            local a, b, c = njt.location.capture_multi{
                {"/a"}, {"/b"}, {"/c"},
            }
            print("rewrite a: " .. a.body)
            print("rewrite b: " .. b.body)
            print("rewrite c: " .. c.body)
        ';

        access_by_lua '
            local A, B = njt.location.capture_multi{
                {"/A"}, {"/B"},
            }
            print("access A: " .. A.body)
            print("access B: " .. B.body)
        ';

        content_by_lua '
            local d, e, f = njt.location.capture_multi{
                {"/d"}, {"/e"}, {"/f"},
            }
            njt.say("content d: " .. d.body)
            njt.say("content e: " .. e.body)
            njt.say("content f: " .. f.body)
        ';
    }

    location /memc {
        set $memc_key $arg_val;
        set $memc_value $arg_val;
        set $memc_cmd $arg_cmd;
        memc_pass 127.0.0.1:$TEST_NGINX_MEMCACHED_PORT;
    }

    location ~ '^/([A-F])$' {
        echo -n $1;
    }

    location ~ '^/([a-f])$' {
        set $tag $1;
        content_by_lua '
            njt.location.capture("/memc?cmd=set&val=" .. njt.var.tag)
            local res = njt.location.capture("/memc?cmd=get&val=" .. njt.var.tag)
            njt.print(res.body)
        ';
    }
--- request
    GET /main
--- stap2
global delta = "  "

M(http-subrequest-start) {
    r = $arg1
    n = njt_http_subreq_depth(r)
    pr = njt_http_req_parent(r)
    printf("%sbegin %s -> %s (%d)\n", njt_indent(n, delta),
        njt_http_req_uri(pr),
        njt_http_req_uri(r),
        n)
}

F(njt_http_lua_run_thread) {
    r = $r
    uri = njt_http_req_uri(r)
    if (uri == "/main") {
        printf("run thread %s: %d\n", uri, $nret)
        #print_ubacktrace()
    }
}

M(http-lua-info) {
    uri = njt_http_req_uri($r)
    #if (uri == "/main") {
    printf("XXX info: %s: %s", uri, user_string($arg1))
    #}
}

F(njt_http_lua_post_subrequest) {
    r = $r
    n = njt_http_subreq_depth(r)
    pr = njt_http_req_parent(r)

    printf("%send %s -> %s (%d)\n", njt_indent(n, delta),
        njt_http_req_uri(r),
        njt_http_req_uri(pr),
        n)
}

F(njt_http_lua_handle_subreq_responses) {
    r = $r
    n = njt_http_subreq_depth(r)
    printf("%shandle res %s (%d)\n", njt_indent(n, delta), njt_http_req_uri(r), n)
}

--- response_body
content d: d
content e: e
content f: f
--- log_level: info
--- grep_error_log eval: qr/rewrite .+?(?= while )|access .+?(?=,)/
--- grep_error_log_out
rewrite a: a
rewrite b: b
rewrite c: c
access A: A
access B: B



=== TEST 13: proxy_cache_lock in subrequests
--- http_config
proxy_cache_lock on;
proxy_cache_lock_timeout 100ms;
proxy_connect_timeout 300ms;

proxy_cache_path conf/cache levels=1:2 keys_zone=STATIC:10m inactive=10m max_size=1m;

--- config
    location /foo {
        content_by_lua '
            local res1, res2 = njt.location.capture_multi{
                { "/proxy" },
                { "/proxy" },
                { "/proxy" },
                { "/proxy" },
            }
            njt.say("ok")
        ';
    }

    location = /proxy {
            proxy_cache STATIC;
            proxy_pass http://127.0.0.2:12345;
            proxy_cache_key $proxy_host$uri$args;
            proxy_cache_valid any 1s;
            #proxy_http_version 1.1;
    }
--- request
    GET /foo
--- response_body
ok
