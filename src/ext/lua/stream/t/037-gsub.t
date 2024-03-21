# vim:set ft= ts=4 sw=4 et fdm=marker:
use Test::Nginx::Socket::Lua::Stream;

#worker_connections(1014);
#master_on();
#workers(2);
log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 2 + 14);

#no_diff();
no_long_string();
run_tests();

__DATA__

=== TEST 1: sanity
--- stream_server_config
    content_by_lua_block {
        local s, n = njt.re.gsub("[hello, world]", "[a-z]+", "howdy")
        njt.say(s)
        njt.say(n)
    }
--- stream_response
[howdy, howdy]
2



=== TEST 2: trimmed
--- stream_server_config
    content_by_lua_block {
        local s, n = njt.re.gsub("hello, world", "[a-z]+", "howdy")
        njt.say(s)
        njt.say(n)
    }
--- stream_response
howdy, howdy
2



=== TEST 3: not matched
--- stream_server_config
    content_by_lua_block {
        local s, n = njt.re.gsub("hello, world", "[A-Z]+", "howdy")
        njt.say(s)
        njt.say(n)
    }
--- stream_response
hello, world
0



=== TEST 4: replace by function (trimmed)
--- stream_server_config
    content_by_lua_block {
        local f = function (m)
            return "[" .. m[0] .. "," .. m[1] .. "]"
        end

        local s, n = njt.re.gsub("hello, world", "([a-z])[a-z]+", f)
        njt.say(s)
        njt.say(n)
    }
--- stream_response
[hello,h], [world,w]
2



=== TEST 5: replace by function (not trimmed)
--- stream_server_config
    content_by_lua_block {
        local f = function (m)
            return "[" .. m[0] .. "," .. m[1] .. "]"
        end

        local s, n = njt.re.gsub("{hello, world}", "([a-z])[a-z]+", f)
        njt.say(s)
        njt.say(n)
    }
--- stream_response
{[hello,h], [world,w]}
2



=== TEST 6: replace by script (trimmed)
--- stream_server_config
    content_by_lua_block {
        local s, n = njt.re.gsub("hello, world", "([a-z])[a-z]+", "[$0,$1]")
        njt.say(s)
        njt.say(n)
    }
--- stream_response
[hello,h], [world,w]
2



=== TEST 7: replace by script (not trimmed)
--- stream_server_config
    content_by_lua_block {
        local s, n = njt.re.gsub("{hello, world}", "([a-z])[a-z]+", "[$0,$1]")
        njt.say(s)
        njt.say(n)
    }
--- stream_response
{[hello,h], [world,w]}
2



=== TEST 8: look-behind assertion
--- stream_server_config
    content_by_lua_block {
        local s, n = njt.re.gsub("{foobarbaz}", "(?<=foo)bar|(?<=bar)baz", "h$0")
        njt.say(s)
        njt.say(n)
    }
--- stream_response
{foohbarhbaz}
2



=== TEST 9: gsub with a patch matching an empty substring (string template)
--- stream_server_config
    content_by_lua_block {
        local s, n = njt.re.gsub("hello", "a|", "b")
        njt.say("s: ", s)
        njt.say("n: ", n)
    }
--- stream_response
s: bhbeblblbob
n: 6
--- no_error_log
[error]



=== TEST 10: gsub with a patch matching an empty substring (string template, empty subj)
--- stream_server_config
    content_by_lua_block {
        local s, n = njt.re.gsub("", "a|", "b")
        njt.say("s: ", s)
        njt.say("n: ", n)
    }
--- stream_response
s: b
n: 1
--- no_error_log
[error]



=== TEST 11: gsub with a patch matching an empty substring (func)
--- stream_server_config
    content_by_lua_block {
        local s, n = njt.re.gsub("hello", "a|", function () return "b" end)
        njt.say("s: ", s)
        njt.say("n: ", n)
    }
--- stream_response
s: bhbeblblbob
n: 6
--- no_error_log
[error]



=== TEST 12: gsub with a patch matching an empty substring (func, empty subj)
--- stream_server_config
    content_by_lua_block {
        local s, n = njt.re.gsub("", "a|", function () return "b" end)
        njt.say("s: ", s)
        njt.say("n: ", n)
    }
--- stream_response
s: b
n: 1
--- no_error_log
[error]



=== TEST 13: big subject string exceeding the luabuf chunk size (with trailing unmatched data, func repl)
--- stream_server_config
    content_by_lua_block {
        local subj = string.rep("a", 8000)
            .. string.rep("b", 1000)
            .. string.rep("a", 8000)
            .. string.rep("b", 1000)
            .. "aaa"

        local function repl(m)
            return string.rep("c", string.len(m[0]))
        end

        local s, n = njt.re.gsub(subj, "b+", repl)
        njt.say(s)
        njt.say(n)
    }
--- stream_response eval
("a" x 8000) . ("c" x 1000) . ("a" x 8000) . ("c" x 1000)
. "aaa
2
"
--- no_error_log
[error]



=== TEST 14: big subject string exceeding the luabuf chunk size (without trailing unmatched data, func repl)
--- stream_server_config
    content_by_lua_block {
        local subj = string.rep("a", 8000)
            .. string.rep("b", 1000)
            .. string.rep("a", 8000)
            .. string.rep("b", 1000)

        local function repl(m)
            return string.rep("c", string.len(m[0]))
        end

        local s, n = njt.re.gsub(subj, "b+", repl)
        njt.say(s)
        njt.say(n)
    }
--- stream_response eval
("a" x 8000) . ("c" x 1000) . ("a" x 8000) . ("c" x 1000)
. "\n2\n"
--- no_error_log
[error]



=== TEST 15: big subject string exceeding the luabuf chunk size (with trailing unmatched data, str repl)
--- stream_server_config
    content_by_lua_block {
        local subj = string.rep("a", 8000)
            .. string.rep("b", 1000)
            .. string.rep("a", 8000)
            .. string.rep("b", 1000)
            .. "aaa"

        local s, n = njt.re.gsub(subj, "b(b+)(b)", "$1 $2")
        njt.say(s)
        njt.say(n)
    }
--- stream_response eval
("a" x 8000) . ("b" x 998) . " b" . ("a" x 8000) . ("b" x 998) . " baaa
2
"
--- no_error_log
[error]



=== TEST 16: big subject string exceeding the luabuf chunk size (without trailing unmatched data, str repl)
--- stream_server_config
    content_by_lua_block {
        local subj = string.rep("a", 8000)
            .. string.rep("b", 1000)
            .. string.rep("a", 8000)
            .. string.rep("b", 1000)

        local s, n = njt.re.gsub(subj, "b(b+)(b)", "$1 $2")
        njt.say(s)
        njt.say(n)
    }
--- stream_response eval
("a" x 8000) . ("b" x 998) . " b" . ("a" x 8000) . ("b" x 998) . " b\n2\n"
--- no_error_log
[error]



=== TEST 17: named pattern repl w/ callback
--- stream_server_config
    content_by_lua_block {
        local repl = function (m)
            return "[" .. m[0] .. "," .. m["first"] .. "]"
        end

        local s, n = njt.re.gsub("hello, world", "(?<first>[a-z])[a-z]+", repl)
        njt.say(s)
        njt.say(n)
    }
--- stream_response
[hello,h], [world,w]
2



=== TEST 18: $0 without parens
--- stream_server_config
    content_by_lua_block {
        local s, n = njt.re.gsub("a b c d", [[\w]], "[$0]")
        njt.say(s)
        njt.say(n)
    }
--- stream_response
[a] [b] [c] [d]
4
--- no_error_log
[error]



=== TEST 19: bad UTF-8
--- stream_server_config
    content_by_lua_block {
        local target = "你好"
        local regex = "你好"

        -- Note the D here
        local s, n, err = njt.re.gsub(string.sub(target, 1, 4), regex, "", "u")

        if s then
            njt.say(s, ": ", n)
        else
            njt.say("error: ", err)
        end
    }
--- stream_response_like chop
error: pcre_exec\(\) failed: -10

--- no_error_log
[error]



=== TEST 20: UTF-8 mode without UTF-8 sequence checks
--- stream_server_config
    content_by_lua_block {
        local s, n, err = njt.re.gsub("你好", ".", "a", "U")
        if s then
            njt.say("s: ", s)
        end
    }
--- stap
probe process("$LIBPCRE_PATH").function("pcre_compile") {
    printf("compile opts: %x\n", $options)
}

probe process("$LIBPCRE_PATH").function("pcre_exec") {
    printf("exec opts: %x\n", $options)
}

--- stap_out
compile opts: 800
exec opts: 2000
exec opts: 2000
exec opts: 2000

--- stream_response
s: aa
--- no_error_log
[error]



=== TEST 21: UTF-8 mode with UTF-8 sequence checks
--- stream_server_config
    content_by_lua_block {
        local s, n, err = njt.re.gsub("你好", ".", "a", "u")
        if s then
            njt.say("s: ", s)
        end
    }
--- stap
probe process("$LIBPCRE_PATH").function("pcre_compile") {
    printf("compile opts: %x\n", $options)
}

probe process("$LIBPCRE_PATH").function("pcre_exec") {
    printf("exec opts: %x\n", $options)
}

--- stap_out
compile opts: 800
exec opts: 0
exec opts: 0
exec opts: 0

--- stream_response
s: aa
--- no_error_log
[error]



=== TEST 22: just hit match limit
--- stream_config
    lua_regex_match_limit 5000;
--- stream_server_config
    content_by_lua_file html/a.lua;

--- user_files
>>> a.lua
local re = [==[(?i:([\s'\"`´’‘\(\)]*)?([\d\w]+)([\s'\"`´’‘\(\)]*)?(?:=|<=>|r?like|sounds\s+like|regexp)([\s'\"`´’‘\(\)]*)?\2|([\s'\"`´’‘\(\)]*)?([\d\w]+)([\s'\"`´’‘\(\)]*)?(?:!=|<=|>=|<>|<|>|\^|is\s+not|not\s+like|not\s+regexp)([\s'\"`´’‘\(\)]*)?(?!\6)([\d\w]+))]==]

s = string.rep([[ABCDEFG]], 10)

local start = njt.now()

local res, cnt, err = njt.re.gsub(s, re, "", "o")

--[[
njt.update_time()
local elapsed = njt.now() - start
njt.say(elapsed, " sec elapsed.")
]]

if err then
    njt.say("error: ", err)
    return
end
njt.say("gsub: ", cnt)

--- stream_response
error: pcre_exec() failed: -8



=== TEST 23: just not hit match limit
--- stream_config
    lua_regex_match_limit 5700;
--- stream_server_config
    content_by_lua_file html/a.lua;

--- user_files
>>> a.lua
local re = [==[(?i:([\s'\"`´’‘\(\)]*)?([\d\w]+)([\s'\"`´’‘\(\)]*)?(?:=|<=>|r?like|sounds\s+like|regexp)([\s'\"`´’‘\(\)]*)?\2|([\s'\"`´’‘\(\)]*)?([\d\w]+)([\s'\"`´’‘\(\)]*)?(?:!=|<=|>=|<>|<|>|\^|is\s+not|not\s+like|not\s+regexp)([\s'\"`´’‘\(\)]*)?(?!\6)([\d\w]+))]==]

local s = string.rep([[ABCDEFG]], 10)

local start = njt.now()

local res, cnt, err = njt.re.gsub(s, re, "", "o")

--[[
njt.update_time()
local elapsed = njt.now() - start
njt.say(elapsed, " sec elapsed.")
]]

if err then
    njt.say("error: ", err)
    return
end
njt.say("gsub: ", cnt)

--- stream_response
gsub: 0
--- timeout: 10



=== TEST 24: bug: gsub incorrectly swallowed a character is the first character
Original bad result: estCase
--- stream_server_config
    content_by_lua_block {
        local s, n = njt.re.gsub("TestCase", "^ *", "", "o")
        if s then
            njt.say(s)
        end
    }
--- stream_response
TestCase



=== TEST 25: bug: gsub incorrectly swallowed a character is not the first character
Original bad result: .b.d
--- stream_server_config
    content_by_lua_block {
        local s, n = njt.re.gsub("abcd", "a|(?=c)", ".")
        if s then
            njt.say(s)
        end
    }
--- stream_response
.b.cd
