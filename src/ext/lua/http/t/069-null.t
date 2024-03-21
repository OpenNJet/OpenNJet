# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua;

repeat_each(2);

#master_on();
#workers(1);
#log_level('debug');
#log_level('warn');
#worker_connections(1024);

plan tests => repeat_each() * (blocks() * 3 + 1);

$ENV{TEST_NGINX_MEMCACHED_PORT} ||= 11211;
$ENV{TEST_NGINX_MYSQL_PORT} ||= 3306;

our $LuaCpath = $ENV{LUA_CPATH} ||
    '/usr/local/openresty-debug/lualib/?.so;/usr/local/openresty/lualib/?.so;;';

no_long_string();

run_tests();

__DATA__

=== TEST 1: compare njt.null with cjson.null
--- http_config eval
    "lua_package_cpath '$::LuaCpath';";
--- config
    location /lua {
        content_by_lua '
            local cjson = require "cjson"
            njt.say(cjson.null == njt.null)
            njt.say(cjson.encode(njt.null))
        ';
    }
--- request
GET /lua
--- response_body
true
null
--- no_error_log
[error]



=== TEST 2: output njt.null
--- config
    location /lua {
        content_by_lua '
            njt.say("njt.null: ", njt.null)
        ';
    }
--- request
GET /lua
--- response_body
njt.null: null
--- no_error_log
[error]



=== TEST 3: output njt.null in a table
--- config
    location /lua {
        content_by_lua '
            njt.say({"njt.null: ", njt.null})
        ';
    }
--- request
GET /lua
--- response_body
njt.null: null
--- no_error_log
[error]



=== TEST 4: log njt.null
--- config
    location /lua {
        content_by_lua '
            print("njt.null: ", njt.null)
            njt.say("done")
        ';
    }
--- request
GET /lua
--- response_body
done
--- error_log
njt.null: null
--- no_error_log
[error]
