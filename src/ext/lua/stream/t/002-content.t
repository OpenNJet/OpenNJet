# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;

#worker_connections(1014);
#master_on();
#workers(2);
#log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 3 + 3);

#no_diff();
#no_long_string();
run_tests();

__DATA__

=== TEST 1: basic print
--- stream_server_config
    content_by_lua_block {
        local ok, err = njt.print("Hello, Lua!\n")
        if not ok then
            njt.log(njt.ERR, "print failed: ", err)
        end
    }
--- stream_response
Hello, Lua!
--- no_error_log
[error]



=== TEST 2: basic say
--- stream_server_config
    content_by_lua_block {
        local ok, err = njt.say("Hello, Lua!")
        if not ok then
            njt.log(njt.ERR, "say failed: ", err)
            return
        end
        local ok, err = njt.say("Yay! ", 123)
        if not ok then
            njt.log(njt.ERR, "say failed: ", err)
            return
        end
    }
--- stream_response
Hello, Lua!
Yay! 123
--- no_error_log
[error]



=== TEST 3: no njt.echo
--- stream_server_config
    content_by_lua_block { njt.echo("Hello, Lua!\n") }
--- stream_response
--- error_log eval
qr/content_by_lua\(nginx\.conf:\d+\):1: attempt to call field 'echo' \(a nil value\)/



=== TEST 4: calc expression
--- stream_server_config
    content_by_lua_file html/calc.lua;
--- user_files
>>> calc.lua
local function uri_unescape(uri)
    local function convert(hex)
        return string.char(tonumber("0x"..hex))
    end
    local s = string.gsub(uri, "%%([0-9a-fA-F][0-9a-fA-F])", convert)
    return s
end

local function eval_exp(str)
    return loadstring("return "..str)()
end

local exp_str = 1+2*math.sin(3)/math.exp(4)-math.sqrt(2)
-- print("exp: '", exp_str, "'\n")
local status, res
status, res = pcall(uri_unescape, exp_str)
if not status then
    njt.print("error: ", res, "\n")
    return
end
status, res = pcall(eval_exp, res)
if status then
    njt.print("result: ", res, "\n")
else
    njt.print("error: ", res, "\n")
end

--- stream_response
result: -0.4090441561579
--- no_error_log
[error]



=== TEST 5: nil is "nil"
--- stream_server_config
    content_by_lua_block { njt.say(nil) }
--- stream_response
nil
--- no_error_log
[error]



=== TEST 6: write boolean
--- stream_server_config
    content_by_lua_block { njt.say(true, " ", false) }
--- stream_response
true false
--- no_error_log
[error]



=== TEST 7: nginx quote sql string 1
--- stream_server_config
   content_by_lua_block { njt.say(njt.quote_sql_str('hello\n\r\'"\\')) }
--- stream_response
'hello\n\r\'\"\\'
--- no_error_log
[error]



=== TEST 8: nginx quote sql string 2
--- stream_server_config
    content_by_lua_block { njt.say(njt.quote_sql_str("hello\n\r'\"\\")) }
--- stream_response
'hello\n\r\'\"\\'
--- no_error_log
[error]



=== TEST 9: multiple eof
--- stream_server_config
    content_by_lua_block {
        njt.say("Hi")

        local ok, err = njt.eof()
        if not ok then
            njt.log(njt.WARN, "eof failed: ", err)
            return
        end

        ok, err = njt.eof()
        if not ok then
            njt.log(njt.WARN, "eof failed: ", err)
            return
        end
    }
--- stream_response
Hi
--- no_error_log
[error]
--- error_log
lua send eof
eof failed: seen eof



=== TEST 10: njt.eof before njt.say
--- stream_server_config
    content_by_lua_block {
        local ok, err = njt.eof()
        if not ok then
            njt.log(njt.ERR, "eof failed: ", err)
            return
        end

        ok, err = njt.say(njt.headers_sent)
        if not ok then
            njt.log(njt.WARN, "failed to say: ", err)
            return
        end
    }
--- stream_response
--- no_error_log
[error]
--- error_log
failed to say: seen eof



=== TEST 11: njt.print table arguments (github issue #54)
--- stream_server_config
    content_by_lua_block { njt.print({10, {0, 5}, 15}, 32) }
--- stream_response chop
10051532
--- no_error_log
[error]



=== TEST 12: njt.say table arguments (github issue #54)
--- stream_server_config
    content_by_lua_block { njt.say({10, {0, "5"}, 15}, 32) }
--- stream_response
10051532
--- no_error_log
[error]



=== TEST 13: Lua file does not exist
--- stream_server_config
    content_by_lua_file html/test2.lua;
--- user_files
>>> test.lua
v = njt.var["request_uri"]
njt.print("request_uri: ", v, "\n")
--- stream_response
--- error_log eval
qr/failed to load external Lua file ".*?test2\.lua": cannot open .*? No such file or directory/



=== TEST 14: .lua file with shebang
--- stream_server_config
    content_by_lua_file html/test.lua;
--- user_files
>>> test.lua
#!/bin/lua

njt.say("line ", debug.getinfo(1).currentline)
--- stream_response
line 3
--- no_error_log
[error]



=== TEST 15: syntax error in inlined Lua code
--- stream_server_config
    content_by_lua_block {for end}
--- stream_response
--- error_log eval
qr/failed to load inlined Lua code: /
