# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua;

#repeat_each(20000);

repeat_each(2);

#master_on();
#workers(1);
#log_level('debug');
#log_level('warn');
#worker_connections(1024);

plan tests => repeat_each() * (blocks() * 2 + 4);

$ENV{TEST_NGINX_MEMCACHED_PORT} ||= 11211;
$ENV{TEST_NGINX_MYSQL_PORT} ||= 3306;

our $LuaCpath = $ENV{LUA_CPATH} ||
    '/usr/local/openresty-debug/lualib/?.so;/usr/local/openresty/lualib/?.so;;';

#$ENV{LUA_PATH} = $ENV{HOME} . '/work/JSON4Lua-0.9.30/json/?.lua';

no_long_string();
#no_shuffle();

run_tests();

__DATA__

=== TEST 1: throw 403
--- config
    location /lua {
        rewrite_by_lua "njt.exit(403);njt.say('hi')";
        content_by_lua 'njt.exit(njt.OK)';
    }
--- request
GET /lua
--- error_code: 403
--- response_body_like: 403 Forbidden



=== TEST 2: throw 404
--- config
    location /lua {
        rewrite_by_lua "njt.exit(404);njt.say('hi');";
        content_by_lua 'njt.exit(njt.OK)';
    }
--- request
GET /lua
--- error_code: 404
--- response_body_like: 404 Not Found



=== TEST 3: throw 404 after sending the header and partial body
--- config
    location /lua {
        rewrite_by_lua "njt.say('hi');njt.exit(404);njt.say(', you')";
        content_by_lua 'njt.exit(njt.OK)';
    }
--- request
GET /lua
--- error_log
attempt to set status 404 via njt.exit after sending out the response status 200
--- response_body
hi



=== TEST 4: working with njt_auth_request (succeeded)
--- config
    location /auth {
        rewrite_by_lua "
            if njt.var.user == 'agentzh' then
                njt.eof();
            else
                njt.exit(403)
            end";
        content_by_lua 'njt.exit(njt.OK)';
    }
    location /api {
        set $user $arg_user;
        auth_request /auth;

        echo "Logged in";
    }
--- request
GET /api?user=agentzh
--- error_code: 200
--- response_body
Logged in



=== TEST 5: working with njt_auth_request (failed)
--- config
    location /auth {
        rewrite_by_lua "
            if njt.var.user == 'agentzh' then
                njt.eof();
            else
                njt.exit(403)
            end";
        content_by_lua 'njt.exit(njt.OK)';
    }
    location /api {
        set $user $arg_user;
        auth_request /auth;

        echo "Logged in";
    }
--- request
GET /api?user=agentz
--- error_code: 403
--- response_body_like: 403 Forbidden



=== TEST 6: working with njt_auth_request (simplest form, w/o njt_memc)
--- http_config eval
"
    lua_package_cpath '$::LuaCpath';
    upstream backend {
        drizzle_server 127.0.0.1:\$TEST_NGINX_MYSQL_PORT protocol=mysql
                       dbname=njt_test user=njt_test password=njt_test;
        drizzle_keepalive max=300 mode=single overflow=ignore;
    }
"
--- config
    location /memc {
        internal;

        set $memc_key $arg_key;
        set $memc_exptime $arg_exptime;

        memc_pass 127.0.0.1:$TEST_NGINX_MEMCACHED_PORT;
    }

    location /conv-uid-mysql {
        internal;

        set $key "conv-uid-$arg_uid";

        #srcache_fetch GET /memc key=$key;
        #srcache_store PUT /memc key=$key;

        default_type 'application/json';

        drizzle_query "select new_uid as uid from conv_uid where old_uid=$arg_uid";
        drizzle_pass backend;

        rds_json on;
    }

    location /conv-uid {
        internal;
        rewrite_by_lua_file 'html/foo.lua';
        content_by_lua 'njt.exit(njt.OK)';
    }
    location /api {
        set $uid $arg_uid;
        auth_request /conv-uid;

        echo "Logged in $uid";
    }
--- user_files
>>> foo.lua
local cjson = require('cjson');
local old_uid = njt.var.uid
print('about to run sr')
local res = njt.location.capture('/conv-uid-mysql?uid=' .. old_uid)
print('just have run sr' .. res.body)
if (res.status ~= njt.HTTP_OK) then
    -- njt.exit(res.status)
end
res = cjson.decode(res.body)
if (not res or not res[1] or not res[1].uid or
        not string.match(res[1].uid, '^%d+$')) then
    njt.exit(njt.HTTP_INTERNAL_SERVER_ERROR)
end
njt.var.uid = res[1].uid;
-- print('done')
--- request
GET /api?uid=32
--- response_body
Logged in 56



=== TEST 7: working with njt_auth_request (simplest form)
--- http_config eval
"
    lua_package_cpath '$::LuaCpath';
    upstream backend {
        drizzle_server 127.0.0.1:\$TEST_NGINX_MYSQL_PORT protocol=mysql
                       dbname=njt_test user=njt_test password=njt_test;
        drizzle_keepalive max=300 mode=single overflow=ignore;
    }
"
--- config
    location /memc {
        internal;

        set $memc_key $arg_key;
        set $memc_exptime $arg_exptime;

        memc_pass 127.0.0.1:$TEST_NGINX_MEMCACHED_PORT;
    }

    location /conv-uid-mysql {
        internal;

        set $key "conv-uid-$arg_uid";

        #srcache_fetch GET /memc key=$key;
        #srcache_store PUT /memc key=$key;

        default_type 'application/json';

        drizzle_query "select new_uid as uid from conv_uid where old_uid=$arg_uid";
        drizzle_pass backend;

        rds_json on;
    }

    location /conv-uid {
        internal;
        rewrite_by_lua_file 'html/foo.lua';
        content_by_lua 'njt.exit(njt.OK)';
    }
    location /api {
        set $uid $arg_uid;
        auth_request /conv-uid;

        echo "Logged in $uid";
    }
--- user_files
>>> foo.lua
local cjson = require('cjson');
local old_uid = njt.var.uid
-- print('about to run sr')
local res = njt.location.capture('/conv-uid-mysql?uid=' .. old_uid)
-- print('just have run sr' .. res.body)
if (res.status ~= njt.HTTP_OK) then
    njt.exit(res.status)
end
res = cjson.decode(res.body)
if (not res or not res[1] or not res[1].uid or
        not string.match(res[1].uid, '^%d+$')) then
    njt.exit(njt.HTTP_INTERNAL_SERVER_ERROR)
end
njt.var.uid = res[1].uid;
-- print('done')
--- request
GET /api?uid=32
--- response_body
Logged in 56



=== TEST 8: working with njt_auth_request
--- http_config eval
"
    lua_package_cpath '$::LuaCpath';
    upstream backend {
        drizzle_server 127.0.0.1:\$TEST_NGINX_MYSQL_PORT protocol=mysql
                       dbname=njt_test user=njt_test password=njt_test;
        drizzle_keepalive max=300 mode=single overflow=ignore;
    }

    upstream memc_a {
        server 127.0.0.1:\$TEST_NGINX_MEMCACHED_PORT;
    }

    upstream memc_b {
        server 127.0.0.1:\$TEST_NGINX_MEMCACHED_PORT;
    }

    upstream_list memc_cluster memc_a memc_b;
"
--- config
    location /memc {
        internal;

        set $memc_key $arg_key;
        set $memc_exptime $arg_exptime;

        set_hashed_upstream $backend memc_cluster $arg_key;
        memc_pass $backend;
    }

    location /conv-uid-mysql {
        internal;

        set $key "conv-uid-$arg_uid";

        #srcache_fetch GET /memc key=$key;
        #srcache_store PUT /memc key=$key;

        default_type 'application/json';

        drizzle_query "select new_uid as uid from conv_uid where old_uid=$arg_uid";
        drizzle_pass backend;

        rds_json on;
    }

    location /conv-uid {
        internal;
        rewrite_by_lua_file 'html/foo.lua';
        content_by_lua 'njt.exit(njt.OK)';
    }
    location /api {
        set $uid $arg_uid;
        auth_request /conv-uid;

        echo "Logged in $uid";
    }
--- user_files
>>> foo.lua
local cjson = require('cjson');
local old_uid = njt.var.uid
-- print('about to run sr')
local res = njt.location.capture('/conv-uid-mysql?uid=' .. old_uid)
-- print('just have run sr' .. res.body)
if (res.status ~= njt.HTTP_OK) then
    njt.exit(res.status)
end
res = cjson.decode(res.body)
if (not res or not res[1] or not res[1].uid or
        not string.match(res[1].uid, '^%d+$')) then
    njt.exit(njt.HTTP_INTERNAL_SERVER_ERROR)
end
njt.var.uid = res[1].uid;
-- print('done')
--- request
GET /api?uid=32
--- response_body
Logged in 56
--- no_error_log
[error]



=== TEST 9: working with njt_auth_request
--- http_config
    upstream backend {
        drizzle_server 127.0.0.1:$TEST_NGINX_MYSQL_PORT protocol=mysql
                       dbname=njt_test user=njt_test password=njt_test;
        drizzle_keepalive max=300 mode=single overflow=ignore;
    }

    upstream memc_a {
        server 127.0.0.1:$TEST_NGINX_MEMCACHED_PORT;
        keepalive 300;
    }

    #upstream_list memc_cluster memc_a memc_b;

--- config
    location /memc {
        internal;

        set $memc_key $arg_key;
        set $memc_exptime $arg_exptime;

        #set_hashed_upstream $backend memc_cluster $arg_key;
        memc_pass memc_a;
    }

    location /conv-mysql {
        internal;

        set $key "conv-uri-$query_string";

        #srcache_fetch GET /memc key=$key;
        #srcache_store PUT /memc key=$key;

        default_type 'application/json';

        set_quote_sql_str $seo_uri $query_string;
        drizzle_query "select url from my_url_map where seo_url=$seo_uri";
        drizzle_pass backend;

        rds_json on;
    }

    location /conv-uid {
        internal;
        rewrite_by_lua_file 'html/foo.lua';
        content_by_lua 'njt.exit(njt.OK)';
    }

    location /baz {
        set $my_uri $uri;
        auth_request /conv-uid;

        echo_exec /jump $my_uri;
    }

    location /jump {
        internal;
        rewrite ^ $query_string? redirect;
    }
--- user_files
>>> foo.lua
local cjson = require('cjson');
local seo_uri = njt.var.my_uri
-- print('about to run sr')
local res = njt.location.capture('/conv-mysql?' .. seo_uri)
if (res.status ~= njt.HTTP_OK) then
    njt.exit(res.status)
end
res = cjson.decode(res.body)
if (not res or not res[1] or not res[1].url) then
    njt.exit(njt.HTTP_INTERNAL_SERVER_ERROR)
end
njt.var.my_uri = res[1].url;
-- print('done')
--- request
GET /baz
--- response_body_like: 302
--- error_code: 302
--- response_headers
Location: http://localhost:$ServerPort/foo/bar
--- SKIP



=== TEST 10: throw 0
--- config
    location /lua {
        rewrite_by_lua "njt.say('Hi'); njt.eof(); njt.exit(0);njt.say('world')";
        content_by_lua 'njt.exit(njt.OK)';
    }
--- request
GET /lua
--- error_code: 200
--- response_body
Hi



=== TEST 11: throw njt.OK does *not* skip other rewrite phase handlers
--- config
    location /lua {
        rewrite_by_lua "njt.exit(njt.OK)";
        set $foo hello;
        echo $foo;
    }
--- request
GET /lua
--- response_body
hello



=== TEST 12: throw njt.HTTP_OK *does* skip other rewrite phase handlers (by inlined code)
--- config
    location /lua {
        rewrite_by_lua "njt.exit(njt.HTTP_OK)";
        set $foo hello;
        echo $foo;
    }
--- request
GET /lua
--- response_body



=== TEST 13: throw njt.HTTP_OK *does* skip other rewrite phase handlers (by inlined code + partial output)
--- config
    location /lua {
        rewrite_by_lua "njt.say('hiya') njt.exit(njt.HTTP_OK)";
        set $foo hello;
        echo $foo;
    }
--- request
GET /lua
--- response_body
hiya



=== TEST 14: throw njt.HTTP_OK *does* skip other rewrite phase handlers (by file)
--- config
    location /lua {
        rewrite_by_lua_file html/foo.lua;
        set $foo hello;
        echo $foo;
    }
--- user_files
>>> foo.lua
njt.exit(njt.HTTP_OK)
--- request
GET /lua
--- response_body



=== TEST 15: throw njt.HTTP_OK *does* skip other rewrite phase handlers (by file + partial output)
--- config
    location /lua {
        rewrite_by_lua_file html/foo.lua;
        set $foo hello;
        echo $foo;
    }
--- user_files
>>> foo.lua
njt.say("morning")
njt.exit(njt.HTTP_OK)
--- request
GET /lua
--- response_body
morning



=== TEST 16: error page with custom body
--- config
    error_page 410 @err;
    location @err {
        echo blah blah;
    }
    location /foo {
        rewrite_by_lua '
            njt.status = njt.HTTP_GONE
            njt.say("This is our own content")
            -- to cause quit the whole request rather than the current phase handler
            njt.exit(njt.HTTP_OK)
        ';
        echo Hello;
    }
--- request
    GET /foo
--- response_body
This is our own content
--- error_code: 410



=== TEST 17: exit with 204 (HTTP 1.1)
--- config
    location = /t {
        rewrite_by_lua '
            njt.exit(204)
        ';

        proxy_pass http://127.0.0.1:$server_port/blah;
    }

    location = /blah {
        echo blah;
    }
--- request
GET /t
--- more_headers2
--- stap2
F(njt_http_send_header) {
    printf("send header\n")
    print_ubacktrace()
}
--- response_body
--- error_code: 204
--- no_error_log
[error]



=== TEST 18: exit with 204 (HTTP 1.0)
--- config
    location = /t {
        rewrite_by_lua '
            njt.exit(204)
        ';

        proxy_pass http://127.0.0.1:$server_port/blah;
    }

    location = /blah {
        echo blah;
    }
--- request
GET /t HTTP/1.0
--- more_headers2
--- stap2
F(njt_http_send_header) {
    printf("send header\n")
    print_ubacktrace()
}
--- response_body
--- error_code: 204
--- no_error_log
[error]
