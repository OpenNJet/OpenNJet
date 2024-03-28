# vim:set ft= ts=4 sw=4 et fdm=marker:
use Test::Nginx::Socket::Lua;

worker_connections(1014);
#master_on();
#workers(4);
#log_level('warn');
no_root_location();

repeat_each(2);

plan tests => repeat_each() * (blocks() * 3 + 2);

our $HtmlDir = html_dir;

#$ENV{LUA_CPATH} = "/usr/local/openresty/lualib/?.so;" . $ENV{LUA_CPATH};

no_long_string();
run_tests();

__DATA__

=== TEST 1: njt.exit(400) should abort print
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
        location = /memc_query {
            internal;
            set               $memc_cmd     $arg_cmd;
            set_unescape_uri  $memc_key     $arg_key;
            set_unescape_uri  $memc_value   $arg_value;
            set $memc_exptime $arg_exptime;

            memc_cmds_allowed get set add delete;
            memc_pass 127.0.0.1:11211;
        }

        location = /test {
            content_by_lua_file html/test.lua;
        }
--- user_files
>>> test.lua
local memd = require 'memd'
njt.exit(400)
local res = memd.query( { cmd = 'get', key = id } )
>>> memd.lua
module('memd', package.seeall)

local URL = '/memc_query'
local capture = njt.location.capture

function query(arg)
    if type(arg) ~= 'table' then
        return nil
    end

    print("HELLO WORLD")
    return capture(URL, { args = arg } )
end
--- request
GET /test?a
--- response_body_like: 400 Bad Request
--- no_error_log eval
["lua print: HELLO WORLD", q{the "$memc_key" variable is not set}]
--- error_code: 400



=== TEST 2: njt.exit(400) should abort njt.log
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
        location = /memc_query {
            internal;
            set               $memc_cmd     $arg_cmd;
            set_unescape_uri  $memc_key     $arg_key;
            set_unescape_uri  $memc_value   $arg_value;
            set $memc_exptime $arg_exptime;

            memc_cmds_allowed get set add delete;
            memc_pass 127.0.0.1:11211;
        }

        location = /test {
            content_by_lua_file html/test.lua;
        }
--- user_files
>>> test.lua
local memd = require 'memd'
njt.exit(400)
local res = memd.query( { cmd = 'get', key = id } )
>>> memd.lua
module('memd', package.seeall)

local URL = '/memc_query'
local capture = njt.location.capture
local log = njt.log
local level = njt.ERR

function query(arg)
    if type(arg) ~= 'table' then
        return nil
    end

    log(level, "HELLO WORLD")
    return capture(URL, { args = arg } )
end
--- request
GET /test?a
--- response_body_like: 400 Bad Request
--- no_error_log eval
["HELLO WORLD", q{the "$memc_key" variable is not set}]
--- error_code: 400



=== TEST 3: njt.exit(400) should abort njt.location.capture
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
        location = /memc_query {
            internal;
            set               $memc_cmd     $arg_cmd;
            set_unescape_uri  $memc_key     $arg_key;
            set_unescape_uri  $memc_value   $arg_value;
            set $memc_exptime $arg_exptime;

            memc_cmds_allowed get set add delete;
            memc_pass 127.0.0.1:11211;
        }

        location = /test {
            content_by_lua_file html/test.lua;
        }
--- user_files
>>> test.lua
local memd = require 'memd'
njt.exit(400)
local res = memd.query( { cmd = 'get', key = id } )
>>> memd.lua
module('memd', package.seeall)

local URL = '/memc_query'
local capture = njt.location.capture

function query(arg)
    if type(arg) ~= 'table' then
        return nil
    end

    return capture(URL, { args = arg } )
end
--- request
GET /test?a
--- response_body_like: 400 Bad Request
--- no_error_log
the "$memc_key" variable is not set
--- error_code: 400



=== TEST 4: njt.exit(400) should abort njt.location.capture_multi
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
        location = /memc_query {
            internal;
            set               $memc_cmd     $arg_cmd;
            set_unescape_uri  $memc_key     $arg_key;
            set_unescape_uri  $memc_value   $arg_value;
            set $memc_exptime $arg_exptime;

            memc_cmds_allowed get set add delete;
            memc_pass 127.0.0.1:11211;
        }

        location = /test {
            content_by_lua_file html/test.lua;
        }
--- user_files
>>> test.lua
local memd = require 'memd'
njt.exit(400)
local res = memd.query( { cmd = 'get', key = id } )
>>> memd.lua
module('memd', package.seeall)

local URL = '/memc_query'
local capture_multi = njt.location.capture_multi

function query(arg)
    if type(arg) ~= 'table' then
        return nil
    end

    return capture_multi{ {URL, { args = arg }} }
end
--- request
GET /test?a
--- response_body_like: 400 Bad Request
--- no_error_log
the "$memc_key" variable is not set
--- error_code: 400



=== TEST 5: njt.exit(400) should abort njt.redirect
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
        location = /test {
            content_by_lua '
                local test = require "test"
                njt.exit(400)
                test.go()
            ';
        }
--- user_files
>>> test.lua
module('test', package.seeall)

function go()
    njt.redirect("/blah")
end
--- request
GET /test
--- response_body_like: 400 Bad Request
--- no_error_log
lua redirect to "/blah" with code 302
--- error_code: 400



=== TEST 6: njt.exit(400) should abort njt.exit
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
        location = /test {
            content_by_lua '
                local test = require "test"
                njt.exit(400)
                test.go()
            ';
        }
--- user_files
>>> test.lua
module('test', package.seeall)

function go()
    njt.exit(503)
end
--- request
GET /test
--- response_body_like: 400 Bad Request
--- no_error_log
lua exit with code 503
--- error_code: 400



=== TEST 7: njt.exit(400) should abort njt.exec
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
        location = /test {
            content_by_lua '
                local test = require "test"
                njt.exit(400)
                test.go()
            ';
        }
--- user_files
>>> test.lua
module('test', package.seeall)

function go()
    njt.exec("/blah")
end
--- request
GET /test
--- response_body_like: 400 Bad Request
--- no_error_log
lua exec "/blah?"
--- error_code: 400



=== TEST 8: njt.exit(400) should abort njt.send_headers
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
        location = /test {
            content_by_lua '
                local test = require "test"
                njt.exit(400)
                test.go()
            ';
        }
--- user_files
>>> test.lua
module('test', package.seeall)

function go()
    njt.send_headers()
end
--- request
GET /test
--- response_body_like: 400 Bad Request
--- no_error_log
lua send headers
--- error_code: 400



=== TEST 9: njt.exit(400) should abort njt.print
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
        location = /test {
            content_by_lua '
                local test = require "test"
                njt.exit(400)
                test.go()
            ';
        }
--- user_files
>>> test.lua
module('test', package.seeall)

function go()
    njt.print("HELLO WORLD")
end
--- request
GET /test
--- response_body_like: 400 Bad Request
--- no_error_log
lua print response
--- error_code: 400



=== TEST 10: njt.exit(400) should abort njt.say
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
        location = /test {
            content_by_lua '
                local test = require "test"
                njt.exit(400)
                test.go()
            ';
        }
--- user_files
>>> test.lua
module('test', package.seeall)

function go()
    njt.say("HELLO WORLD")
end
--- request
GET /test
--- response_body_like: 400 Bad Request
--- no_error_log
lua say response
--- error_code: 400



=== TEST 11: njt.exit(400) should abort njt.flush
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
        location = /test {
            content_by_lua '
                local test = require "test"
                njt.exit(400)
                test.go()
            ';
        }
--- user_files
>>> test.lua
module('test', package.seeall)

function go()
    njt.flush()
end
--- request
GET /test
--- response_body_like: 400 Bad Request
--- no_error_log
lua flush asynchronously
--- error_code: 400



=== TEST 12: njt.exit(400) should abort njt.eof
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
        location = /test {
            content_by_lua '
                local test = require "test"
                njt.exit(400)
                test.go()
            ';
        }
--- user_files
>>> test.lua
module('test', package.seeall)

function go()
    njt.eof()
end
--- request
GET /test
--- response_body_like: 400 Bad Request
--- no_error_log
lua send eof
--- error_code: 400



=== TEST 13: njt.exit(400) should abort njt.re.match
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
        location = /test {
            content_by_lua '
                local test = require "test"
                njt.exit(400)
                test.go()
            ';
        }
--- user_files
>>> test.lua
module('test', package.seeall)

function go()
    njt.re.match("a", "a", "jo")
end
--- request
GET /test
--- response_body_like: 400 Bad Request
--- no_error_log
lua compiling match regex "a" with options "jo"
--- error_code: 400



=== TEST 14: njt.exit(400) should abort njt.re.gmatch
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
        location = /test {
            content_by_lua '
                local test = require "test"
                njt.exit(400)
                test.go()
            ';
        }
--- user_files
>>> test.lua
module('test', package.seeall)

function go()
    njt.re.gmatch("a", "a", "jo")
end
--- request
GET /test
--- response_body_like: 400 Bad Request
--- no_error_log
lua compiling gmatch regex "a" with options "jo"
--- error_code: 400



=== TEST 15: njt.exit(400) should abort njt.re.sub
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
        location = /test {
            content_by_lua '
                local test = require "test"
                njt.exit(400)
                test.go()
            ';
        }
--- user_files
>>> test.lua
module('test', package.seeall)

function go()
    njt.re.sub("a", "a", "", "jo")
end
--- request
GET /test
--- response_body_like: 400 Bad Request
--- no_error_log
lua compiling sub regex "a" with options "jo"
--- error_code: 400



=== TEST 16: njt.exit(400) should abort njt.re.gsub
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
        location = /test {
            content_by_lua '
                local test = require "test"
                njt.exit(400)
                test.go()
            ';
        }
--- user_files
>>> test.lua
module('test', package.seeall)

function go()
    njt.re.gsub("a", "a", "", "jo")
end
--- request
GET /test
--- response_body_like: 400 Bad Request
--- no_error_log
lua compiling gsub regex "a" with options "jo"
--- error_code: 400



=== TEST 17: njt.exit(400) should abort njt.shared.DICT (set)
--- http_config eval
    "lua_shared_dict dogs 1m; lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
        location = /test {
            content_by_lua '
                local test = require "test"
                local dogs = njt.shared.dogs
                print("foo = ", dogs:get("foo"))
                dogs:set("foo", 32)
                njt.exit(400)
                test.go(dogs)
            ';
        }
--- user_files
>>> test.lua
module('test', package.seeall)

function go(dogs)
    dogs:set("foo", 56)
end
--- request
GET /test
--- response_body_like: 400 Bad Request
--- no_error_log
foo = 56
--- error_code: 400



=== TEST 18: njt.exit(400) should abort njt.shared.DICT (replace)
--- http_config eval
    "lua_shared_dict dogs 1m; lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
        location = /test {
            content_by_lua '
                local test = require "test"
                local dogs = njt.shared.dogs
                print("foo = ", dogs:get("foo"))
                dogs:set("foo", 32)
                njt.exit(400)
                test.go(dogs)
            ';
        }
--- user_files
>>> test.lua
module('test', package.seeall)

function go(dogs)
    dogs:replace("foo", 56)
end
--- request
GET /test
--- response_body_like: 400 Bad Request
--- no_error_log
foo = 56
--- error_code: 400



=== TEST 19: njt.exit(400) should abort njt.shared.DICT (incr)
--- http_config eval
    "lua_shared_dict dogs 1m; lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
        location = /test {
            content_by_lua '
                local test = require "test"
                local dogs = njt.shared.dogs
                print("foo = ", dogs:get("foo"))
                dogs:set("foo", 32)
                njt.exit(400)
                test.go(dogs)
            ';
        }
--- user_files
>>> test.lua
module('test', package.seeall)

function go(dogs)
    dogs:incr("foo", 56)
end
--- request
GET /test
--- response_body_like: 400 Bad Request
--- no_error_log
foo = 88
--- error_code: 400



=== TEST 20: njt.exit(400) should abort njt.shared.DICT (get)
--- http_config eval
    "lua_shared_dict dogs 1m; lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
        location = /test {
            content_by_lua '
                local test = require "test"
                local dogs = njt.shared.dogs
                dogs:set("foo", 32)
                njt.exit(400)
                test.go(dogs)
            ';
        }
--- user_files
>>> test.lua
module('test', package.seeall)

function go(dogs)
    dogs:get("foo")
end
--- request
GET /test
--- response_body_like: 400 Bad Request
--- no_error_log
fetching key "foo" in shared dict "dogs"
--- error_code: 400



=== TEST 21: njt.exit(400) should skip os.execute
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
        location = /test {
            content_by_lua '
                local test = require "test"
                njt.exit(400)
                test.go()
            ';
        }
--- user_files
>>> test.lua
module('test', package.seeall)

local exec = os.execute

function go()
    exec("sleep 5")
end
--- request
GET /test
--- response_body_like: 400 Bad Request
--- error_code: 400
--- no_error_log
[error]
--- timeout: 2



=== TEST 22: njt.exit(400) should break pcall and skip os.execute
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
        location = /test {
            content_by_lua '
                local test = require "test"
                pcall(njt.exit, 400)
                test.go()
            ';
        }
--- user_files
>>> test.lua
module('test', package.seeall)

local exec = os.execute

function go()
    exec("sleep 5")
end
--- request
GET /test
--- response_body_like: 400 Bad Request
--- no_error_log
fetching key "foo" in shared dict "dogs"
--- error_code: 400
--- timeout: 2



=== TEST 23: njt.exit(400) should break pcall and skip os.execute (all in user module)
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
        location = /test {
            content_by_lua '
                local test = require "test"
                test.go()
            ';
        }
--- user_files
>>> test.lua
module('test', package.seeall)

local exec = os.execute

function go()
    pcall(njt.exit, 400)
    exec("sleep 5")
end
--- request
GET /test
--- response_body_like: 400 Bad Request
--- error_code: 400
--- no_error_log
[error]
--- timeout: 2



=== TEST 24: njt.redirect() should break pcall and skip os.execute (all in user module)
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
        location = /test {
            content_by_lua '
                local test = require "test"
                test.go()
            ';
        }
--- user_files
>>> test.lua
module('test', package.seeall)

local exec = os.execute

function go()
    pcall(njt.redirect, "/blah")
    exec("sleep 5")
end
--- request
GET /test
--- response_body_like: 302 Found
--- no_error_log
[error]
--- error_code: 302
--- timeout: 2



=== TEST 25: njt.redirect() should skip os.execute (all in user module)
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
        location = /test {
            content_by_lua '
                local test = require "test"
                test.go()
            ';
        }
--- user_files
>>> test.lua
module('test', package.seeall)

local exec = os.execute

function go()
    njt.redirect("/blah")
    exec("sleep 5")
end
--- request
GET /test
--- response_body_like: 302 Found
--- no_error_log
[error]
--- error_code: 302
--- timeout: 2



=== TEST 26: njt.exec() should break pcall and skip os.execute (all in user module)
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
        location = /test {
            content_by_lua '
                local test = require "test"
                test.go()
            ';
        }
        location = /foo {
            echo foo;
        }
--- user_files
>>> test.lua
module('test', package.seeall)

local exec = os.execute

function go()
    pcall(njt.exec, "/foo")
    exec("sleep 5")
end
--- request
GET /test
--- response_body
foo
--- no_error_log
[error]
--- timeout: 2



=== TEST 27: njt.exec() should skip os.execute (all in user module)
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
        location = /test {
            content_by_lua '
                local test = require "test"
                test.go()
            ';
        }
        location = /foo {
            echo foo;
        }
--- user_files
>>> test.lua
module('test', package.seeall)

local exec = os.execute

function go()
    njt.exec("/foo")
    exec("sleep 5")
end
--- request
GET /test
--- response_body
foo
--- no_error_log
[error]
--- timeout: 2



=== TEST 28: njt.set_uri(uri, true) should break pcall and skip os.execute (all in user module)
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
        location = /test {
            rewrite_by_lua '
                local test = require "test"
                test.go()
            ';
            echo hello;
        }
        location = /foo {
            echo foo;
        }
--- user_files
>>> test.lua
module('test', package.seeall)

local exec = os.execute

function go()
    local ok, err = pcall(njt.req.set_uri, "/foo", true)
    if not ok then
        njt.log(njt.ERR, "error: ", err)
    end

    exec("sleep 5")
end
--- request
GET /test
--- response_body
foo
--- no_error_log
[error]
--- timeout: 2



=== TEST 29: abort does not affect following coroutines
--- config
        location = /test {
            rewrite_by_lua 'njt.exit(0)';
            content_by_lua '
                pcall(njt.say, "hello world")
            ';
        }
--- request
GET /test
--- response_body
hello world
--- no_error_log
[error]
--- timeout: 2



=== TEST 30: njt.exit(400) should break xpcall and skip os.execute (all in user module)
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
        location = /test {
            content_by_lua '
                local test = require "test"
                test.go()
            ';
        }
--- user_files
>>> test.lua
module('test', package.seeall)

local exec = os.execute

function myexit()
    njt.exit(400)
end

function go()
    xpcall(myexit, function () end)
    exec("sleep 5")
end
--- request
GET /test
--- response_body_like: 400 Bad Request
--- error_code: 400
--- no_error_log
[error]
--- timeout: 2



=== TEST 31: njt.exec() should skip os.execute (all in user module)
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
        location = /test {
            content_by_lua '
                local test = require "test"
                test.go()
            ';
        }
        location = /foo {
            echo foo;
        }
--- user_files
>>> test.lua
local os_exec = os.execute
local njt_exec = njt.exec
module('test')

function go()
    njt_exec("/foo")
    os_exec("sleep 5")
end
--- request
GET /test
--- response_body
foo
--- no_error_log
[error]
--- timeout: 2



=== TEST 32: njt.exec() should break pcall and skip os.execute (all in user module)
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
        location = /test {
            content_by_lua '
                local test = require "test"
                test.go()
            ';
        }
        location = /foo {
            echo foo;
        }
--- user_files
>>> test.lua
local os_exec = os.execute
local njt_exec = njt.exec
local pcall = pcall
module('test')

function go()
    pcall(njt_exec, "/foo")
    os_exec("sleep 5")
end
--- request
GET /test
--- response_body
foo
--- no_error_log
[error]
--- timeout: 2
