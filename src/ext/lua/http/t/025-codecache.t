# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua;
use Cwd qw(abs_path realpath);
use File::Basename;

repeat_each(2);

plan tests => repeat_each() * 198;

#$ENV{LUA_PATH} = $ENV{HOME} . '/work/JSON4Lua-0.9.30/json/?.lua';
$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();
$ENV{TEST_NGINX_CERT_DIR} ||= dirname(realpath(abs_path(__FILE__)));

no_long_string();

our $HtmlDir = html_dir;

$ENV{TEST_NGINX_MEMCACHED_PORT} ||= 11211;

check_accum_error_log();
run_tests();

__DATA__

=== TEST 1: code cache on by default
--- config
    location /lua {
        content_by_lua_file html/test.lua;
    }
    location /update {
        content_by_lua '
            -- os.execute("(echo HERE; pwd) > /dev/stderr")
            local f = assert(io.open("$TEST_NGINX_SERVER_ROOT/html/test.lua", "w"))
            f:write("njt.say(101)")
            f:close()
            njt.say("updated")
        ';
    }
    location /main {
        echo_location /lua;
        echo_location /update;
        echo_location /lua;
    }
--- user_files
>>> test.lua
njt.say(32)
--- request
GET /main
--- response_body
32
updated
32
--- no_error_log
[alert]



=== TEST 2: code cache explicitly on
--- config
    location /lua {
        lua_code_cache on;
        content_by_lua_file html/test.lua;
    }
    location /update {
        content_by_lua '
            -- os.execute("(echo HERE; pwd) > /dev/stderr")
            local f = assert(io.open("$TEST_NGINX_SERVER_ROOT/html/test.lua", "w"))
            f:write("njt.say(101)")
            f:close()
            njt.say("updated")
        ';
    }
    location /main {
        echo_location /lua;
        echo_location /update;
        echo_location /lua;
    }
--- user_files
>>> test.lua
njt.say(32)
--- request
GET /main
--- response_body
32
updated
32
--- no_error_log
[alert]



=== TEST 3: code cache explicitly off
--- config
    location /lua {
        lua_code_cache off;
        content_by_lua_file html/test.lua;
    }
    location /update {
        content_by_lua '
            -- os.execute("(echo HERE; pwd) > /dev/stderr")
            local f = assert(io.open("$TEST_NGINX_SERVER_ROOT/html/test.lua", "w"))
            f:write("njt.say(101)")
            f:close()
            njt.say("updated")
        ';
    }
    location /main {
        echo_location /lua;
        echo_location /update;
        echo_location /lua;
    }
--- user_files
>>> test.lua
njt.say(32)
--- request
GET /main
--- response_body
32
updated
101
--- error_log eval
qr/\[alert\] \S+ lua_code_cache is off; this will hurt performance/



=== TEST 4: code cache explicitly off (server level)
--- config
    lua_code_cache off;

    location /lua {
        content_by_lua_file html/test.lua;
    }
    location /update {
        content_by_lua '
            -- os.execute("(echo HERE; pwd) > /dev/stderr")
            local f = assert(io.open("$TEST_NGINX_SERVER_ROOT/html/test.lua", "w"))
            f:write("njt.say(101)")
            f:close()
            njt.say("updated")
        ';
    }
    location /main {
        echo_location /lua;
        echo_location /update;
        echo_location /lua;
    }
--- user_files
>>> test.lua
njt.say(32)
--- request
GET /main
--- response_body
32
updated
101
--- error_log eval
qr/\[alert\] \S+ lua_code_cache is off; this will hurt performance/



=== TEST 5: code cache explicitly off (server level) but be overridden in the location
--- config
    lua_code_cache off;

    location /lua {
        lua_code_cache on;
        content_by_lua_file html/test.lua;
    }
    location /update {
        content_by_lua '
            -- os.execute("(echo HERE; pwd) > /dev/stderr")
            local f = assert(io.open("$TEST_NGINX_SERVER_ROOT/html/test.lua", "w"))
            f:write("njt.say(101)")
            f:close()
            njt.say("updated")
        ';
    }
    location /main {
        echo_location /lua;
        echo_location /update;
        echo_location /lua;
    }
--- user_files
>>> test.lua
njt.say(32)
--- request
GET /main
--- response_body
32
updated
32
--- error_log eval
qr/\[alert\] \S+ lua_code_cache is off; this will hurt performance/



=== TEST 6: code cache explicitly off (affects require) + content_by_lua
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
    location /lua {
        lua_code_cache off;
        content_by_lua '
            local foo = require "foo";
        ';
    }
    location /update {
        content_by_lua '
            -- os.execute("(echo HERE; pwd) > /dev/stderr")
            local f = assert(io.open("$TEST_NGINX_SERVER_ROOT/html/foo.lua", "w"))
            f:write("module(..., package.seeall); njt.say(102);")
            f:close()
            njt.say("updated")
        ';
    }
    location /main {
        echo_location /lua;
        echo_location /update;
        echo_location /lua;
    }
--- user_files
>>> foo.lua
module(..., package.seeall); njt.say(32);
--- request
GET /main
--- response_body
32
updated
102
--- error_log eval
qr/\[alert\] \S+ lua_code_cache is off; this will hurt performance/



=== TEST 7: code cache explicitly off (affects require) + content_by_lua_file
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
    location /lua {
        lua_code_cache off;
        content_by_lua_file html/test.lua;
    }
    location /update {
        content_by_lua '
            -- os.execute("(echo HERE; pwd) > /dev/stderr")
            local f = assert(io.open("$TEST_NGINX_SERVER_ROOT/html/foo.lua", "w"))
            f:write("module(..., package.seeall); njt.say(102);")
            f:close()
            njt.say("updated")
        ';
    }
    location /main {
        echo_location /lua;
        echo_location /update;
        echo_location /lua;
    }
--- user_files
>>> test.lua
local foo = require "foo";
>>> foo.lua
module(..., package.seeall); njt.say(32);
--- request
GET /main
--- response_body
32
updated
102
--- error_log eval
qr/\[alert\] \S+ lua_code_cache is off; this will hurt performance/



=== TEST 8: code cache explicitly off (affects require) + set_by_lua_file
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
    location /lua {
        lua_code_cache off;
        set_by_lua_file $a html/test.lua;
        echo $a;
    }
    location /update {
        content_by_lua '
            -- os.execute("(echo HERE; pwd) > /dev/stderr")
            local f = assert(io.open("$TEST_NGINX_SERVER_ROOT/html/foo.lua", "w"))
            f:write("module(..., package.seeall); return 102;")
            f:close()
            njt.say("updated")
        ';
    }
    location /main {
        echo_location /lua;
        echo_location /update;
        echo_location /lua;
    }
--- user_files
>>> test.lua
return require "foo"
>>> foo.lua
module(..., package.seeall); return 32;
--- request
GET /main
--- response_body
32
updated
102
--- error_log eval
qr/\[alert\] \S+ lua_code_cache is off; this will hurt performance/



=== TEST 9: code cache explicitly on (affects require) + set_by_lua_file
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
    location /lua {
        lua_code_cache on;
        set_by_lua_file $a html/test.lua;
        echo $a;
    }
    location /update {
        content_by_lua '
            -- os.execute("(echo HERE; pwd) > /dev/stderr")
            local f = assert(io.open("$TEST_NGINX_SERVER_ROOT/html/foo.lua", "w"))
            f:write("module(..., package.seeall); return 102;")
            f:close()
            njt.say("updated")
        ';
    }
    location /main {
        echo_location /lua;
        echo_location /update;
        echo_location /lua;
    }
--- user_files
>>> test.lua
return require "foo"
>>> foo.lua
module(..., package.seeall); return 32;
--- request
GET /main
--- response_body
32
updated
32
--- no_error_log
[alert]



=== TEST 10: code cache explicitly off + set_by_lua_file
--- config
    location /lua {
        lua_code_cache off;
        set_by_lua_file $a html/test.lua;
        echo $a;
    }
    location /update {
        content_by_lua '
            -- os.execute("(echo HERE; pwd) > /dev/stderr")
            local f = assert(io.open("$TEST_NGINX_SERVER_ROOT/html/test.lua", "w"))
            f:write("return 101")
            f:close()
            njt.say("updated")
        ';
    }
    location /main {
        echo_location /lua;
        echo_location /update;
        echo_location /lua;
    }
--- user_files
>>> test.lua
return 32
--- request
GET /main
--- response_body
32
updated
101
--- error_log eval
qr/\[alert\] \S+ lua_code_cache is off; this will hurt performance/



=== TEST 11: code cache explicitly on + set_by_lua_file
--- config
    location /lua {
        lua_code_cache on;
        set_by_lua_file $a html/test.lua;
        echo $a;
    }
    location /update {
        content_by_lua '
            -- os.execute("(echo HERE; pwd) > /dev/stderr")
            local f = assert(io.open("$TEST_NGINX_SERVER_ROOT/html/test.lua", "w"))
            f:write("return 101")
            f:close()
            njt.say("updated")
        ';
    }
    location /main {
        echo_location /lua;
        echo_location /update;
        echo_location /lua;
    }
--- user_files
>>> test.lua
return 32
--- request
GET /main
--- response_body
32
updated
32
--- no_error_log
[alert]



=== TEST 12: no clear builtin lib "string"
--- config
    location /lua {
        lua_code_cache off;
        content_by_lua_file html/test.lua;
    }
    location /main {
        echo_location /lua;
        echo_location /lua;
    }
--- user_files
>>> test.lua
njt.say(string.len("hello"))
njt.say(table.concat({1,2,3}, ", "))
--- request
    GET /main
--- response_body
5
1, 2, 3
5
1, 2, 3
--- error_log eval
qr/\[alert\] \S+ lua_code_cache is off; this will hurt performance/



=== TEST 13: no clear builtin lib "string"
--- config
    location /lua {
        lua_code_cache off;
        content_by_lua '
            njt.say(string.len("hello"))
            njt.say(table.concat({1,2,3}, ", "))
        ';
    }
    location /main {
        echo_location /lua;
        echo_location /lua;
    }
--- request
    GET /main
--- response_body
5
1, 2, 3
5
1, 2, 3
--- error_log eval
qr/\[alert\] \S+ lua_code_cache is off; this will hurt performance/



=== TEST 14: no clear builtin lib "string"
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
    lua_code_cache off;
    location /lua {
        content_by_lua '
            local test = require("test")
        ';
    }
    location /main {
        echo_location /lua;
        echo_location /lua;
    }
--- request
    GET /main
--- user_files
>>> test.lua
module("test", package.seeall)

string = require("string")
math = require("math")
io = require("io")
os = require("os")
table = require("table")
coroutine = require("coroutine")
package = require("package")
njt.say("OK")
--- response_body
OK
OK
--- error_log eval
qr/\[alert\] \S+ lua_code_cache is off; this will hurt performance/



=== TEST 15: do not skip luarocks
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';
     lua_code_cache off;"
--- config
    location /main {
        echo_location /load;
        echo_location /check;
        echo_location /check;
    }

    location /load {
        content_by_lua '
            package.loaded.luarocks = nil;
            local foo = require "luarocks";
            foo.hi()
        ';
    }

    location /check {
        content_by_lua '
            local foo = package.loaded.luarocks
            if foo then
                njt.say("found")
            else
                njt.say("not found")
            end
        ';
    }
--- request
GET /main
--- user_files
>>> luarocks.lua
module(..., package.seeall);

njt.say("loading");

function hi ()
    njt.say("hello, foo")
end;
--- response_body
loading
hello, foo
not found
not found
--- error_log eval
qr/\[alert\] \S+ lua_code_cache is off; this will hurt performance/



=== TEST 16: do not skip luarocks*
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';
     lua_code_cache off;"
--- config
    location /main {
        echo_location /load;
        echo_location /check;
        echo_location /check;
    }

    location /load {
        content_by_lua '
            package.loaded.luarocks2 = nil;
            local foo = require "luarocks2";
            foo.hi()
        ';
    }

    location /check {
        content_by_lua '
            local foo = package.loaded.luarocks2
            if foo then
                njt.say("found")
            else
                njt.say("not found")
            end
        ';
    }
--- request
GET /main
--- user_files
>>> luarocks2.lua
module(..., package.seeall);

njt.say("loading");

function hi ()
    njt.say("hello, foo")
end;
--- response_body
loading
hello, foo
not found
not found
--- error_log eval
qr/\[alert\] \S+ lua_code_cache is off; this will hurt performance/



=== TEST 17: clear _G table
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
    lua_code_cache off;
    location /t {
        content_by_lua '
            if not _G.foo then
                _G.foo = 1
            else
                _G.foo = _G.foo + 1
            end
            njt.say("_G.foo: ", _G.foo)
        ';
    }
--- request
    GET /t
--- response_body
_G.foo: 1
--- error_log eval
qr/\[alert\] \S+ lua_code_cache is off; this will hurt performance/



=== TEST 18: github #257: globals cleared when code cache off
--- http_config
    lua_code_cache off;
    init_by_lua '
      test = setfenv(
        function()
          njt.say(tostring(table))
        end,
        setmetatable({},
        {
          __index = function(self, key)
          return rawget(self, key) or _G[key]
        end
      }))';
--- config
    location = /t {
        content_by_lua 'test()';
    }
--- request
GET /t
--- response_body_like chop
^table: 0x\d*?[1-9a-fA-F]
--- no_error_log
[error]
--- error_log eval
qr/\[alert\] \S+ lua_code_cache is off; this will hurt performance/



=== TEST 19: lua_code_cache off + FFI-based Lua modules
--- http_config
    lua_code_cache off;
    lua_package_path "$prefix/html/?.lua;;";

--- config
    location = /t {
        content_by_lua '
            if not jit then
                njt.say("skipped for non-LuaJIT")
            else
                local test = require("test")
                njt.say("test module loaded: ", test and true or false)
                collectgarbage()
            end
        ';
    }
--- user_files
>>> test.lua
local ffi = require "ffi"

ffi.cdef[[
    int my_test_function_here(void *p);
    int my_test_function_here2(void *p);
    int my_test_function_here3(void *p);
]]

return {
}
--- request
GET /t
--- response_body_like chop
^(?:skipped for non-LuaJIT|test module loaded: true)$
--- no_error_log
[error]
--- error_log eval
qr/\[alert\] \S+ lua_code_cache is off; this will hurt performance/



=== TEST 20: njt.timer.* + ndk
--- config
    lua_code_cache off;
    location /read {
        echo ok;
        log_by_lua '
            njt.timer.at(0, function ()
                local foo = ndk.set_var.set_unescape_uri("a%20b")
                njt.log(njt.WARN, "foo = ", foo)
            end)
        ';
    }
--- request
GET /read
--- response_body
ok
--- wait: 0.1
--- no_error_log
[error]
--- error_log eval
["foo = a b",
qr/\[alert\] \S+ lua_code_cache is off; this will hurt performance/
]



=== TEST 21: set njt.ctx before internal redirects performed by other nginx modules (with log_by_lua)
--- config
    lua_code_cache off;
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
--- error_log eval
["lua release njt.ctx at ref",
qr/\[alert\] \S+ lua_code_cache is off; this will hurt performance/,
"lua close the global Lua VM",
]



=== TEST 22: set by lua file
--- config
    lua_code_cache off;
    location /lua {
        set_by_lua_file $res html/a.lua $arg_a $arg_b;
        echo $res;
    }
--- user_files
>>> a.lua
return njt.arg[1] + njt.arg[2]
--- request
GET /lua?a=5&b=2
--- response_body
7
--- no_error_log
[error]
--- error_log eval
[qr/\[alert\] \S+ lua_code_cache is off; this will hurt performance/,
"lua close the global Lua VM",
]



=== TEST 23: simple set by lua
--- config
    lua_code_cache off;
    location /lua {
        set_by_lua $res "return 1+1";
        echo $res;
    }
--- request
GET /lua
--- response_body
2
--- no_error_log
[error]
--- error_log eval
[
qr/\[alert\] \S+ lua_code_cache is off; this will hurt performance/,
"lua close the global Lua VM",
]



=== TEST 24: lua_max_pending_timers - chained timers (non-zero delay) - not exceeding
--- http_config
    lua_max_pending_timers 1;
    lua_code_cache off;

--- config
    location /t {
        content_by_lua '
            local s = ""

            local function fail(...)
                njt.log(njt.ERR, ...)
            end

            local function g()
                s = s .. "[g]"
                print("trace: ", s)
            end

            local function f()
                local ok, err = njt.timer.at(0.01, g)
                if not ok then
                    fail("failed to set timer: ", err)
                    return
                end
                s = s .. "[f]"
            end
            local ok, err = njt.timer.at(0.01, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
            s = "[m]"
        ';
    }
--- request
GET /t

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[error]
decrementing the reference count for Lua VM: 3

--- error_log eval
[
"lua njt.timer expired",
"http lua close fake http connection",
"trace: [m][f][g]",
qr/\[alert\] \S+ lua_code_cache is off; this will hurt performance/,
"lua close the global Lua VM",
"decrementing the reference count for Lua VM: 2",
"decrementing the reference count for Lua VM: 1",
]



=== TEST 25: lua variable sharing via upvalue
--- http_config
    lua_code_cache off;
--- config
    location /t {
        content_by_lua '
            local begin = njt.now()
            local foo
            local function f()
                foo = 3
                print("elapsed: ", njt.now() - begin)
            end
            local ok, err = njt.timer.at(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
            njt.sleep(0.06)
            njt.say("foo = ", foo)
        ';
    }
--- request
GET /t
--- response_body
registered timer
foo = 3

--- wait: 0.1
--- no_error_log
[error]
decrementing the reference count for Lua VM: 3

--- error_log eval
[
"lua njt.timer expired",
"http lua close fake http connection",
qr/\[alert\] \S+ lua_code_cache is off; this will hurt performance/,
"lua close the global Lua VM",
"decrementing the reference count for Lua VM: 2",
"decrementing the reference count for Lua VM: 1",
]



=== TEST 26: lua_max_running_timers (just not enough)
--- http_config
    lua_max_running_timers 1;
--- config
    lua_code_cache off;
    location /t {
        content_by_lua '
            local s = ""

            local function fail(...)
                njt.log(njt.ERR, ...)
            end

            local f, g

            g = function ()
                njt.sleep(0.01)
                collectgarbage()
            end

            f = function ()
                njt.sleep(0.01)
                collectgarbage()
            end
            local ok, err = njt.timer.at(0, f)
            if not ok then
                njt.say("failed to set timer f: ", err)
                return
            end
            local ok, err = njt.timer.at(0, g)
            if not ok then
                njt.say("failed to set timer g: ", err)
                return
            end
            njt.say("registered timer")
            s = "[m]"
        ';
    }
--- request
GET /t

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[error]

--- error_log eval
[
"1 lua_max_running_timers are not enough",
"lua njt.timer expired",
"http lua close fake http connection",
qr/\[alert\] \S+ lua_code_cache is off; this will hurt performance/,
"decrementing the reference count for Lua VM: 3",
"decrementing the reference count for Lua VM: 2",
"decrementing the reference count for Lua VM: 1",
"lua close the global Lua VM",
]



=== TEST 27: GC issue with the on_abort thread object
--- config
    lua_code_cache off;
    location = /t {
        lua_check_client_abort on;
        content_by_lua '
            njt.on_abort(function () end)
            collectgarbage()
            njt.sleep(1)
        ';
    }
--- request
    GET /t
--- abort
--- timeout: 0.2
--- wait: 1
--- ignore_response
--- no_error_log
[error]
decrementing the reference count for Lua VM: 2
decrementing the reference count for Lua VM: 3
--- error_log eval
["decrementing the reference count for Lua VM: 1",
qr/\[alert\] \S+ lua_code_cache is off; this will hurt performance/,
"lua close the global Lua VM",
]



=== TEST 28: multiple parallel timers
--- config
    lua_code_cache off;
    location /t {
        content_by_lua '
            local s = ""

            local function fail(...)
                njt.log(njt.ERR, ...)
            end

            local function g()
                s = s .. "[g]"
                print("trace: ", s)
            end

            local function f()
                s = s .. "[f]"
            end
            local ok, err = njt.timer.at(0.01, f)
            if not ok then
                fail("failed to set timer: ", err)
                return
            end
            local ok, err = njt.timer.at(0.01, g)
            if not ok then
                fail("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
            s = "[m]"
        ';
    }
--- request
GET /t

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[error]
decrementing the reference count for Lua VM: 4

--- error_log eval
[
"lua njt.timer expired",
"http lua close fake http connection",
"trace: [m][f][g]",
"decrementing the reference count for Lua VM: 3",
"decrementing the reference count for Lua VM: 2",
"decrementing the reference count for Lua VM: 1",
qr/\[alert\] \S+ lua_code_cache is off; this will hurt performance/,
"lua close the global Lua VM",
]



=== TEST 29: cosocket connection pool timeout (after Lua VM destroys)
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
    lua_code_cache off;
    location = /t {
        set $port $TEST_NGINX_MEMCACHED_PORT;
        content_by_lua '
            local test = require "test"
            local port = njt.var.port
            test.go(port)
        ';
    }
--- user_files
>>> test.lua
module("test", package.seeall)

function go(port)
    local sock = njt.socket.tcp()
    local ok, err = sock:connect("127.0.0.1", port)
    if not ok then
        njt.say("failed to connect: ", err)
        return
    end

    njt.say("connected: ", ok, ", reused: ", sock:getreusedtimes())

    local req = "flush_all\r\n"

    local bytes, err = sock:send(req)
    if not bytes then
        njt.say("failed to send request: ", err)
        return
    end
    njt.say("request sent: ", bytes)

    local line, err, part = sock:receive()
    if line then
        njt.say("received: ", line)

    else
        njt.say("failed to receive a line: ", err, " [", part, "]")
    end

    local ok, err = sock:setkeepalive(10)
    if not ok then
        njt.say("failed to set reusable: ", err)
    end
end
--- request
GET /t
--- response_body
connected: 1, reused: 0
request sent: 11
received: OK
--- no_error_log
[error]
lua tcp socket keepalive max idle timeout

--- error_log eval
[
qq{lua tcp socket keepalive create connection pool for key "127.0.0.1:$ENV{TEST_NGINX_MEMCACHED_PORT}"},
qr/\[alert\] \S+ lua_code_cache is off; this will hurt performance/,
qr/\blua tcp socket keepalive: free connection pool [0-9A-F]+ for "127.0.0.1:/,
]



=== TEST 30: cosocket connection pool timeout (before Lua VM destroys)
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
    lua_code_cache off;
    location = /t {
        set $port $TEST_NGINX_MEMCACHED_PORT;
        content_by_lua '
            local test = require "test"
            local port = njt.var.port
            test.go(port)
        ';
    }
--- user_files
>>> test.lua
module("test", package.seeall)

function go(port)
    local sock = njt.socket.tcp()
    local ok, err = sock:connect("127.0.0.1", port)
    if not ok then
        njt.say("failed to connect: ", err)
        return
    end

    njt.say("connected: ", ok, ", reused: ", sock:getreusedtimes())

    local req = "flush_all\r\n"

    local bytes, err = sock:send(req)
    if not bytes then
        njt.say("failed to send request: ", err)
        return
    end
    njt.say("request sent: ", bytes)

    local line, err, part = sock:receive()
    if line then
        njt.say("received: ", line)

    else
        njt.say("failed to receive a line: ", err, " [", part, "]")
    end

    local ok, err = sock:setkeepalive(1)
    if not ok then
        njt.say("failed to set reusable: ", err)
    end
    njt.sleep(0.01)
end
--- request
GET /t
--- response_body
connected: 1, reused: 0
request sent: 11
received: OK
--- no_error_log
[error]
--- error_log eval
[
qq{lua tcp socket keepalive create connection pool for key "127.0.0.1:$ENV{TEST_NGINX_MEMCACHED_PORT}"},
qr/\[alert\] \S+ lua_code_cache is off; this will hurt performance/,
"lua tcp socket keepalive: free connection pool for ",
"lua tcp socket keepalive max idle timeout",
]



=== TEST 31: lua_max_running_timers (just not enough, also low lua_max_pending_timers)
--- http_config
    lua_max_running_timers 1;
    lua_max_pending_timers 10;
--- config
    lua_code_cache off;
    location /t {
        content_by_lua '
            local s = ""

            local function fail(...)
                njt.log(njt.ERR, ...)
            end

            local f, g

            g = function ()
                njt.sleep(0.01)
                collectgarbage()
            end

            f = function ()
                njt.sleep(0.01)
                collectgarbage()
            end
            local ok, err = njt.timer.at(0, f)
            if not ok then
                njt.say("failed to set timer f: ", err)
                return
            end
            local ok, err = njt.timer.at(0, g)
            if not ok then
                njt.say("failed to set timer g: ", err)
                return
            end
            njt.say("registered timer")
            s = "[m]"
        ';
    }
--- request
GET /t

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[error]

--- error_log eval
[
"1 lua_max_running_timers are not enough",
"lua njt.timer expired",
"http lua close fake http connection",
qr/\[alert\] \S+ lua_code_cache is off; this will hurt performance/,
"decrementing the reference count for Lua VM: 3",
"decrementing the reference count for Lua VM: 2",
"decrementing the reference count for Lua VM: 1",
"lua close the global Lua VM",
]



=== TEST 32: make sure inline code keys are correct
GitHub issue #1428
--- config
include ../html/a/proxy.conf;
include ../html/b/proxy.conf;
include ../html/c/proxy.conf;

location /t {
    echo_location /a/;
    echo_location /b/;
    echo_location /a/;
    echo_location /c/;
}

--- user_files
>>> a/proxy.conf
location /a/ {
    content_by_lua_block { njt.say("/a/ is called") }
}

>>> b/proxy.conf
location /b/ {
    content_by_lua_block { njt.say("/b/ is called") }
}

>>> c/proxy.conf
location /c/ {
    content_by_lua_block { njt.say("/b/ is called") }
}

--- request
GET /t
--- response_body
/a/ is called
/b/ is called
/a/ is called
/b/ is called
--- grep_error_log eval: qr/code cache .*/
--- grep_error_log_out eval
[
"code cache lookup (key='content_by_lua_nhli_3c7137b8371d10bc148c8f8bb3042ee6', ref=-1)
code cache miss (key='content_by_lua_nhli_3c7137b8371d10bc148c8f8bb3042ee6', ref=-1)
code cache lookup (key='content_by_lua_nhli_1dfe09105792ef65c8d576cc486d5e04', ref=-1)
code cache miss (key='content_by_lua_nhli_1dfe09105792ef65c8d576cc486d5e04', ref=-1)
code cache lookup (key='content_by_lua_nhli_3c7137b8371d10bc148c8f8bb3042ee6', ref=1)
code cache hit (key='content_by_lua_nhli_3c7137b8371d10bc148c8f8bb3042ee6', ref=1)
code cache lookup (key='content_by_lua_nhli_1dfe09105792ef65c8d576cc486d5e04', ref=-1)
code cache setting ref (key='content_by_lua_nhli_1dfe09105792ef65c8d576cc486d5e04', ref=2)
code cache hit (key='content_by_lua_nhli_1dfe09105792ef65c8d576cc486d5e04', ref=2)
",
"code cache lookup (key='content_by_lua_nhli_3c7137b8371d10bc148c8f8bb3042ee6', ref=-1)
code cache miss (key='content_by_lua_nhli_3c7137b8371d10bc148c8f8bb3042ee6', ref=-1)
code cache lookup (key='content_by_lua_nhli_1dfe09105792ef65c8d576cc486d5e04', ref=-1)
code cache miss (key='content_by_lua_nhli_1dfe09105792ef65c8d576cc486d5e04', ref=-1)
code cache lookup (key='content_by_lua_nhli_3c7137b8371d10bc148c8f8bb3042ee6', ref=1)
code cache hit (key='content_by_lua_nhli_3c7137b8371d10bc148c8f8bb3042ee6', ref=1)
code cache lookup (key='content_by_lua_nhli_1dfe09105792ef65c8d576cc486d5e04', ref=-1)
code cache setting ref (key='content_by_lua_nhli_1dfe09105792ef65c8d576cc486d5e04', ref=2)
code cache hit (key='content_by_lua_nhli_1dfe09105792ef65c8d576cc486d5e04', ref=2)
code cache lookup (key='content_by_lua_nhli_3c7137b8371d10bc148c8f8bb3042ee6', ref=1)
code cache hit (key='content_by_lua_nhli_3c7137b8371d10bc148c8f8bb3042ee6', ref=1)
code cache lookup (key='content_by_lua_nhli_1dfe09105792ef65c8d576cc486d5e04', ref=2)
code cache hit (key='content_by_lua_nhli_1dfe09105792ef65c8d576cc486d5e04', ref=2)
code cache lookup (key='content_by_lua_nhli_3c7137b8371d10bc148c8f8bb3042ee6', ref=1)
code cache hit (key='content_by_lua_nhli_3c7137b8371d10bc148c8f8bb3042ee6', ref=1)
code cache lookup (key='content_by_lua_nhli_1dfe09105792ef65c8d576cc486d5e04', ref=2)
code cache hit (key='content_by_lua_nhli_1dfe09105792ef65c8d576cc486d5e04', ref=2)
"]
--- log_level: debug
--- no_error_log
[error]



=== TEST 33: make sure Lua code file keys are correct
GitHub issue #1428
--- config
include ../html/a/proxy.conf;
include ../html/b/proxy.conf;
include ../html/c/proxy.conf;

location /t {
    echo_location /a/;
    echo_location /b/;
    echo_location /a/;
    echo_location /c/;
}

--- user_files
>>> a.lua
njt.say("/a/ is called")

>>> b.lua
njt.say("/b/ is called")

>>> c.lua
njt.say("/b/ is called")

>>> a/proxy.conf
location /a/ {
    content_by_lua_file html/a.lua;
}

>>> b/proxy.conf
location /b/ {
    content_by_lua_file html/b.lua;
}

>>> c/proxy.conf
location /c/ {
    content_by_lua_file html/c.lua;
}

--- request
GET /t
--- response_body
/a/ is called
/b/ is called
/a/ is called
/b/ is called
--- grep_error_log eval: qr/code cache .*/
--- grep_error_log_out eval
[
"code cache lookup (key='nhlf_48a9a7def61143c003a7de1644e026e4', ref=-1)
code cache miss (key='nhlf_48a9a7def61143c003a7de1644e026e4', ref=-1)
code cache lookup (key='nhlf_68f5f4e946c3efd1cc206452b807e8b6', ref=-1)
code cache miss (key='nhlf_68f5f4e946c3efd1cc206452b807e8b6', ref=-1)
code cache lookup (key='nhlf_48a9a7def61143c003a7de1644e026e4', ref=1)
code cache hit (key='nhlf_48a9a7def61143c003a7de1644e026e4', ref=1)
code cache lookup (key='nhlf_042c9b3a136fbacbbd0e4b9ad10896b7', ref=-1)
code cache miss (key='nhlf_042c9b3a136fbacbbd0e4b9ad10896b7', ref=-1)
",
"code cache lookup (key='nhlf_48a9a7def61143c003a7de1644e026e4', ref=-1)
code cache miss (key='nhlf_48a9a7def61143c003a7de1644e026e4', ref=-1)
code cache lookup (key='nhlf_68f5f4e946c3efd1cc206452b807e8b6', ref=-1)
code cache miss (key='nhlf_68f5f4e946c3efd1cc206452b807e8b6', ref=-1)
code cache lookup (key='nhlf_48a9a7def61143c003a7de1644e026e4', ref=1)
code cache hit (key='nhlf_48a9a7def61143c003a7de1644e026e4', ref=1)
code cache lookup (key='nhlf_042c9b3a136fbacbbd0e4b9ad10896b7', ref=-1)
code cache miss (key='nhlf_042c9b3a136fbacbbd0e4b9ad10896b7', ref=-1)
code cache lookup (key='nhlf_48a9a7def61143c003a7de1644e026e4', ref=1)
code cache hit (key='nhlf_48a9a7def61143c003a7de1644e026e4', ref=1)
code cache lookup (key='nhlf_68f5f4e946c3efd1cc206452b807e8b6', ref=2)
code cache hit (key='nhlf_68f5f4e946c3efd1cc206452b807e8b6', ref=2)
code cache lookup (key='nhlf_48a9a7def61143c003a7de1644e026e4', ref=1)
code cache hit (key='nhlf_48a9a7def61143c003a7de1644e026e4', ref=1)
code cache lookup (key='nhlf_042c9b3a136fbacbbd0e4b9ad10896b7', ref=3)
code cache hit (key='nhlf_042c9b3a136fbacbbd0e4b9ad10896b7', ref=3)
"
]
--- log_level: debug
--- no_error_log
[error]



=== TEST 34: variables in set_by_lua_file's file path
--- config
    location ~ ^/lua/(.+)$ {
        set_by_lua_file $res html/$1.lua;
        echo $res;
    }

    location /main {
        echo_location /lua/a;
        echo_location /lua/b;
        echo_location /lua/a;
        echo_location /lua/a;
        echo_location /lua/b;
    }
--- user_files
>>> a.lua
return "a"
>>> b.lua
return "b"
--- request
GET /main
--- response_body
a
b
a
a
b
--- no_error_log
[error]



=== TEST 35: variables in rewrite_by_lua_file's file path
--- config
    location ~ ^/lua/(.+)$ {
        rewrite_by_lua_file html/$1.lua;
    }

    location /main {
        echo_location /lua/a;
        echo_location /lua/b;
        echo_location /lua/a;
        echo_location /lua/a;
        echo_location /lua/b;
    }
--- user_files
>>> a.lua
njt.say("a")
>>> b.lua
njt.say("b")
--- request
GET /main
--- response_body
a
b
a
a
b
--- no_error_log
[error]



=== TEST 36: variables in access_by_lua_file's file path
--- config
    location ~ ^/lua/(.+)$ {
        access_by_lua_file html/$1.lua;

        content_by_lua_block {
            return
        }
    }

    location ~ ^/proxy/(.+)$ {
        proxy_pass http://127.0.0.1:$server_port/lua/$1;
    }

    location /main {
        content_by_lua_block {
            local res1, res2, res3, res4, res5 = njt.location.capture_multi{
                { "/proxy/a" },
                { "/proxy/b" },
                { "/proxy/a" },
                { "/proxy/a" },
                { "/proxy/b" },
            }

            njt.say(res1.body)
            njt.say(res2.body)
            njt.say(res3.body)
            njt.say(res4.body)
            njt.say(res5.body)
        }
    }
--- user_files
>>> a.lua
njt.print("a")
>>> b.lua
njt.print("b")
--- request
GET /main
--- response_body
a
b
a
a
b
--- no_error_log
[error]



=== TEST 37: variables in content_by_lua_file's file path
--- config
    location ~ ^/lua/(.+)$ {
        content_by_lua_file html/$1.lua;
    }

    location /main {
        echo_location /lua/a;
        echo_location /lua/b;
        echo_location /lua/a;
        echo_location /lua/a;
        echo_location /lua/b;
    }
--- user_files
>>> a.lua
njt.say("a")
>>> b.lua
njt.say("b")
--- request
GET /main
--- response_body
a
b
a
a
b
--- no_error_log
[error]



=== TEST 38: variables in header_filter_by_lua_file's file path
--- config
    location ~ ^/lua/(.+)$ {
        return 200;

        header_filter_by_lua_file html/$1.lua;
    }

    location ~ ^/proxy/(.+)$ {
        proxy_pass http://127.0.0.1:$server_port/lua/$1;
    }

    location /main {
        content_by_lua_block {
            local res1, res2, res3, res4, res5 = njt.location.capture_multi{
                { "/proxy/a" },
                { "/proxy/b" },
                { "/proxy/a" },
                { "/proxy/a" },
                { "/proxy/b" },
            }

            njt.say(res1.header.match)
            njt.say(res2.header.match)
            njt.say(res3.header.match)
            njt.say(res4.header.match)
            njt.say(res5.header.match)
        }
    }
--- user_files
>>> a.lua
njt.header.match = "a"
>>> b.lua
njt.header.match = "b"
--- request
GET /main
--- response_body
a
b
a
a
b
--- no_error_log
[error]



=== TEST 39: variables in body_filter_by_lua_file's file path
--- config
    location ~ ^/lua/(.+)$ {
        echo hello;

        body_filter_by_lua_file html/$1.lua;
    }

    location /main {
        echo_location /lua/a;
        echo_location /lua/b;
        echo_location /lua/a;
        echo_location /lua/a;
        echo_location /lua/b;
    }
--- user_files
>>> a.lua
njt.arg[1] = "a\n"
njt.arg[2] = true
>>> b.lua
njt.arg[1] = "b\n"
njt.arg[2] = true
--- request
GET /main
--- response_body
a
b
a
a
b
--- no_error_log
[error]



=== TEST 40: variables in log_by_lua_file's file path
--- config
    log_subrequest on;

    location ~ ^/lua/(.+)$ {
        echo hello;

        log_by_lua_file html/$1.lua;
    }

    location /main {
        echo_location /lua/a;
        echo_location /lua/b;
        echo_location /lua/a;
        echo_location /lua/a;
        echo_location /lua/b;
    }
--- user_files
>>> a.lua
njt.log(njt.NOTICE, "grep me: a")
>>> b.lua
njt.log(njt.NOTICE, "grep me: b")
--- request
GET /main
--- ignore_response_body
--- grep_error_log eval: qr/grep me: ([ab])/
--- grep_error_log_out eval
[
"grep me: a
grep me: b
grep me: a
grep me: a
grep me: b
",
"grep me: a
grep me: b
grep me: a
grep me: a
grep me: b
grep me: a
grep me: b
grep me: a
grep me: a
grep me: b
"]
--- no_error_log
[error]



=== TEST 41: same chunk from different directives produces different closures
--- http_config
    ssl_session_fetch_by_lua_block { njt.log(njt.INFO, "hello") }

    ssl_session_store_by_lua_block { njt.log(njt.INFO, "hello") }

    upstream backend {
        server unix:$TEST_NGINX_HTML_DIR/nginx.sock;
        balancer_by_lua_block { njt.log(njt.INFO, "hello") }
    }

    server {
        server_name test.com;
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
        ssl_certificate $TEST_NGINX_CERT_DIR/cert/test.crt;
        ssl_certificate_key $TEST_NGINX_CERT_DIR/cert/test.key;
        ssl_session_tickets off;

        ssl_certificate_by_lua_block { njt.log(njt.INFO, "hello") }

        location /lua {
            set_by_lua_block $res { njt.log(njt.INFO, "hello") }

            rewrite_by_lua_block { njt.log(njt.INFO, "hello") }

            access_by_lua_block { njt.log(njt.INFO, "hello") }

            content_by_lua_block { njt.log(njt.INFO, "hello") }

            header_filter_by_lua_block { njt.log(njt.INFO, "hello") }

            body_filter_by_lua_block { njt.log(njt.INFO, "hello") }

            log_by_lua_block { njt.log(njt.INFO, "hello") }
        }
    }
--- config
    lua_ssl_trusted_certificate $TEST_NGINX_CERT_DIR/cert/test.crt;

    location = /proxy {
        proxy_pass http://backend;
    }

    location = /t {
        set $html_dir $TEST_NGINX_HTML_DIR;

        content_by_lua_block {
            njt.location.capture("/proxy")

            local sock = njt.socket.tcp()
            sock:settimeout(2000)

            local ok, err = sock:connect("unix:" .. njt.var.html_dir .. "/nginx.sock")
            if not ok then
                njt.log(njt.ERR, "failed to connect: ", err)
                return
            end

            local sess, err = sock:sslhandshake(nil, "test.com", true)
            if not sess then
                njt.log(njt.ERR, "failed to do SSL handshake: ", err)
                return
            end
            package.loaded.session = sess
            sock:close()

            local ok, err = sock:connect("unix:" .. njt.var.html_dir .. "/nginx.sock")
            if not ok then
                njt.log(njt.ERR, "failed to connect: ", err)
                return
            end

            local sess, err = sock:sslhandshake(package.loaded.session, "test.com", true)
            if not sess then
                njt.log(njt.ERR, "failed to do SSL handshake: ", err)
                return
            end

            local req = "GET /lua HTTP/1.0\r\nHost: test.com\r\nConnection: close\r\n\r\n"
            local bytes, err = sock:send(req)
            if not bytes then
                njt.log(njt.ERR, "failed to send http request: ", err)
                return
            end
        }
    }
--- request
GET /t
--- ignore_response_body
--- grep_error_log eval: qr/code cache .*/
--- grep_error_log_out eval
[
"code cache lookup (key='content_by_lua_nhli_56ca4388611109b6ecfdeada050c8024', ref=-1)
code cache miss (key='content_by_lua_nhli_56ca4388611109b6ecfdeada050c8024', ref=-1)
code cache lookup (key='balancer_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache miss (key='balancer_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache lookup (key='ssl_certificate_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache miss (key='ssl_certificate_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache lookup (key='ssl_session_store_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache miss (key='ssl_session_store_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache lookup (key='ssl_session_fetch_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache miss (key='ssl_session_fetch_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache lookup (key='ssl_certificate_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=3)
code cache hit (key='ssl_certificate_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=3)
code cache lookup (key='ssl_session_store_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=4)
code cache hit (key='ssl_session_store_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=4)
code cache lookup (key='set_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache miss (key='set_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache lookup (key='rewrite_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache miss (key='rewrite_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache lookup (key='access_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache miss (key='access_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache lookup (key='content_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache miss (key='content_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache lookup (key='header_filter_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache miss (key='header_filter_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache lookup (key='body_filter_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache miss (key='body_filter_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache lookup (key='log_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache miss (key='log_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
",
"code cache lookup (key='content_by_lua_nhli_56ca4388611109b6ecfdeada050c8024', ref=-1)
code cache miss (key='content_by_lua_nhli_56ca4388611109b6ecfdeada050c8024', ref=-1)
code cache lookup (key='balancer_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache miss (key='balancer_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache lookup (key='ssl_certificate_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache miss (key='ssl_certificate_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache lookup (key='ssl_session_store_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache miss (key='ssl_session_store_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache lookup (key='ssl_session_fetch_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache miss (key='ssl_session_fetch_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache lookup (key='ssl_certificate_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=3)
code cache hit (key='ssl_certificate_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=3)
code cache lookup (key='ssl_session_store_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=4)
code cache hit (key='ssl_session_store_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=4)
code cache lookup (key='set_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache miss (key='set_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache lookup (key='rewrite_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache miss (key='rewrite_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache lookup (key='access_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache miss (key='access_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache lookup (key='content_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache miss (key='content_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache lookup (key='header_filter_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache miss (key='header_filter_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache lookup (key='body_filter_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache miss (key='body_filter_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache lookup (key='log_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache miss (key='log_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=-1)
code cache lookup (key='content_by_lua_nhli_56ca4388611109b6ecfdeada050c8024', ref=1)
code cache hit (key='content_by_lua_nhli_56ca4388611109b6ecfdeada050c8024', ref=1)
code cache lookup (key='balancer_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=2)
code cache hit (key='balancer_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=2)
code cache lookup (key='ssl_certificate_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=3)
code cache hit (key='ssl_certificate_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=3)
code cache lookup (key='ssl_session_store_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=4)
code cache hit (key='ssl_session_store_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=4)
code cache lookup (key='ssl_session_fetch_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=5)
code cache hit (key='ssl_session_fetch_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=5)
code cache lookup (key='ssl_certificate_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=3)
code cache hit (key='ssl_certificate_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=3)
code cache lookup (key='ssl_session_store_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=4)
code cache hit (key='ssl_session_store_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=4)
code cache lookup (key='set_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=6)
code cache hit (key='set_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=6)
code cache lookup (key='rewrite_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=7)
code cache hit (key='rewrite_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=7)
code cache lookup (key='access_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=8)
code cache hit (key='access_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=8)
code cache lookup (key='content_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=9)
code cache hit (key='content_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=9)
code cache lookup (key='header_filter_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=10)
code cache hit (key='header_filter_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=10)
code cache lookup (key='body_filter_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=11)
code cache hit (key='body_filter_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=11)
code cache lookup (key='log_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=12)
code cache hit (key='log_by_lua_nhli_8a9441d0a30531ba8bb34ab11c55cfc3', ref=12)
"]
--- error_log eval
[
qr/balancer_by_lua:\d+: hello/,
qr/ssl_session_fetch_by_lua_block:\d+: hello/,
qr/ssl_certificate_by_lua:\d+: hello/,
qr/ssl_session_store_by_lua_block:\d+: hello/,
qr/set_by_lua:\d+: hello/,
qr/rewrite_by_lua\(nginx\.conf:\d+\):\d+: hello/,
qr/access_by_lua\(nginx\.conf:\d+\):\d+: hello/,
qr/content_by_lua\(nginx\.conf:\d+\):\d+: hello/,
qr/header_filter_by_lua:\d+: hello/,
qr/body_filter_by_lua:\d+: hello/,
qr/log_by_lua\(nginx\.conf:\d+\):\d+: hello/,
]
--- log_level: debug
--- no_error_log
[error]
