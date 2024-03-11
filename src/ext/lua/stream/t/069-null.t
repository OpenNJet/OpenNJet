# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;

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
--- stream_config eval
    "lua_package_cpath '$::LuaCpath';";
--- stream_server_config
    content_by_lua_block {
        local cjson = require "cjson"
        njt.say(cjson.null == njt.null)
        njt.say(cjson.encode(njt.null))
    }
--- stream_response
true
null
--- no_error_log
[error]



=== TEST 2: output njt.null
--- stream_server_config
    content_by_lua_block {
        njt.say("njt.null: ", njt.null)
    }
--- stream_response
njt.null: null
--- no_error_log
[error]



=== TEST 3: output njt.null in a table
--- stream_server_config
    content_by_lua_block {
        njt.say({"njt.null: ", njt.null})
    }
--- stream_response
njt.null: null
--- no_error_log
[error]



=== TEST 4: log njt.null
--- stream_server_config
    content_by_lua_block {
        print("njt.null: ", njt.null)
        njt.say("done")
    }
--- stream_response
done
--- error_log
njt.null: null
--- no_error_log
[error]
