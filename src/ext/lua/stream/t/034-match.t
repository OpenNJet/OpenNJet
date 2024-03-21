# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;

#worker_connections(1014);
#master_on();
#workers(2);
#log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 3);

#no_diff();
no_long_string();
run_tests();

__DATA__

=== TEST 1: sanity
--- stream_server_config
    content_by_lua_block {
        m = njt.re.match("hello, 1234", "([0-9]+)")
        if m then
            njt.say(m[0])
        else
            njt.say("not matched!")
        end
    }
--- stream_response
1234
--- no_error_log
[error]



=== TEST 2: escaping sequences
--- stream_server_config
    content_by_lua_block {
        m = njt.re.match("hello, 1234", [[(\d+)]])
        if m then
            njt.say(m[0])
        else
            njt.say("not matched!")
        end
    }
--- stream_response
1234
--- no_error_log
[error]



=== TEST 3: single capture
--- stream_server_config
    content_by_lua_block {
        m = njt.re.match("hello, 1234", "([0-9]{2})[0-9]+")
        if m then
            njt.say(m[0])
            njt.say(m[1])
        else
            njt.say("not matched!")
        end
    }
--- stream_response
1234
12
--- no_error_log
[error]



=== TEST 4: multiple captures
--- stream_server_config
    content_by_lua_block {
        m = njt.re.match("hello, 1234", "([a-z]+).*?([0-9]{2})[0-9]+", "")
        if m then
            njt.say(m[0])
            njt.say(m[1])
            njt.say(m[2])
        else
            njt.say("not matched!")
        end
    }
--- stream_response
hello, 1234
hello
12
--- no_error_log
[error]



=== TEST 5: multiple captures (with o)
--- stream_server_config
    content_by_lua_block {
        m = njt.re.match("hello, 1234", "([a-z]+).*?([0-9]{2})[0-9]+", "o")
        if m then
            njt.say(m[0])
            njt.say(m[1])
            njt.say(m[2])
        else
            njt.say("not matched!")
        end
    }
--- stream_response
hello, 1234
hello
12
--- no_error_log
[error]



=== TEST 6: not matched
--- stream_server_config
    content_by_lua_block {
        m = njt.re.match("hello, 1234", "foo")
        if m then
            njt.say(m[0])
        else
            njt.say("not matched: ", m)
        end
    }
--- stream_response
not matched: nil
--- no_error_log
[error]



=== TEST 7: case sensitive by default
--- stream_server_config
    content_by_lua_block {
        m = njt.re.match("hello, 1234", "HELLO")
        if m then
            njt.say(m[0])
        else
            njt.say("not matched: ", m)
        end
    }
--- stream_response
not matched: nil
--- no_error_log
[error]



=== TEST 8: case insensitive
--- stream_server_config
    content_by_lua_block {
        m = njt.re.match("hello, 1234", "HELLO", "i")
        if m then
            njt.say(m[0])
        else
            njt.say("not matched: ", m)
        end
    }
--- stream_response
hello
--- no_error_log
[error]



=== TEST 9: UTF-8 mode
--- stream_server_config
    content_by_lua_block {
        rc, err = pcall(njt.re.match, "hello章亦春", "HELLO.{2}", "iu")
        if not rc then
            njt.say("FAIL: ", err)
            return
        end
        local m = err
        if m then
            njt.say(m[0])
        else
            njt.say("not matched: ", m)
        end
    }
--- stream_response_like chop
^(?:FAIL: bad argument \#2 to '\?' \(pcre_compile\(\) failed: this version of PCRE is not compiled with PCRE_UTF8 support in "HELLO\.\{2\}" at "HELLO\.\{2\}"\)|hello章亦)$
--- no_error_log
[error]



=== TEST 10: multi-line mode (^ at line head)
--- stream_server_config
    content_by_lua_block {
        m = njt.re.match("hello\nworld", "^world", "m")
        if m then
            njt.say(m[0])
        else
            njt.say("not matched: ", m)
        end
    }
--- stream_response
world
--- no_error_log
[error]



=== TEST 11: multi-line mode (. does not match \n)
--- stream_server_config
    content_by_lua_block {
        m = njt.re.match("hello\nworld", ".*", "m")
        if m then
            njt.say(m[0])
        else
            njt.say("not matched: ", m)
        end
    }
--- stream_response
hello
--- no_error_log
[error]



=== TEST 12: single-line mode (^ as normal)
--- stream_server_config
    content_by_lua_block {
        m = njt.re.match("hello\nworld", "^world", "s")
        if m then
            njt.say(m[0])
        else
            njt.say("not matched: ", m)
        end
    }
--- stream_response
not matched: nil
--- no_error_log
[error]



=== TEST 13: single-line mode (dot all)
--- stream_server_config
    content_by_lua_block {
        m = njt.re.match("hello\nworld", ".*", "s")
        if m then
            njt.say(m[0])
        else
            njt.say("not matched: ", m)
        end
    }
--- stream_response
hello
world
--- no_error_log
[error]



=== TEST 14: extended mode (ignore whitespaces)
--- stream_server_config
    content_by_lua_block {
        m = njt.re.match("hello\nworld", [[\w     \w]], "x")
        if m then
            njt.say(m[0])
        else
            njt.say("not matched: ", m)
        end
    }
--- stream_response
he
--- no_error_log
[error]



=== TEST 15: bad pattern
--- stream_server_config
    content_by_lua_block {
        local m, err = njt.re.match("hello\nworld", "(abc")
        if m then
            njt.say(m[0])

        else
            if err then
                njt.say("error: ", err)

            else
                njt.say("not matched: ", m)
            end
        end
    }
--- stream_response
error: pcre_compile() failed: missing ) in "(abc"
--- no_error_log
[error]



=== TEST 16: bad option
--- stream_server_config
    content_by_lua_block {
        rc, m = pcall(njt.re.match, "hello\nworld", ".*", "Hm")
        if rc then
            if m then
                njt.say(m[0])
            else
                njt.say("not matched: ", m)
            end
        else
            njt.say("error: ", m)
        end
    }
--- stream_response_like chop
error: .*?unknown flag "H" \(flags "Hm"\)



=== TEST 17: extended mode (ignore whitespaces)
--- stream_server_config
    content_by_lua_block {
        m = njt.re.match("hello, world", "(world)|(hello)", "x")
        if m then
            njt.say(m[0])
            njt.say(m[1])
            njt.say(m[2])
        else
            njt.say("not matched: ", m)
        end
    }
--- stream_response
hello
false
hello
--- no_error_log
[error]



=== TEST 18: optional trailing captures
--- stream_server_config
    content_by_lua_block {
        m = njt.re.match("hello, 1234", "([0-9]+)(h?)")
        if m then
            njt.say(m[0])
            njt.say(m[1])
            njt.say(m[2])
        else
            njt.say("not matched!")
        end
    }
--- stream_response eval
"1234
1234

"
--- no_error_log
[error]



=== TEST 19: anchored match (failed)
--- stream_server_config
    content_by_lua_block {
        m = njt.re.match("hello, 1234", "([0-9]+)", "a")
        if m then
            njt.say(m[0])
        else
            njt.say("not matched!")
        end
    }
--- stream_response
not matched!
--- no_error_log
[error]



=== TEST 20: anchored match (succeeded)
--- stream_server_config
    content_by_lua_block {
        m = njt.re.match("1234, hello", "([0-9]+)", "a")
        if m then
            njt.say(m[0])
        else
            njt.say("not matched!")
        end
    }
--- stream_response
1234
--- no_error_log
[error]



=== TEST 21: match with ctx but no pos
--- stream_server_config
    content_by_lua_block {
        local ctx = {}
        m = njt.re.match("1234, hello", "([0-9]+)", "", ctx)
        if m then
            njt.say(m[0])
            njt.say(ctx.pos)
        else
            njt.say("not matched!")
            njt.say(ctx.pos)
        end
    }
--- stream_response
1234
5
--- no_error_log
[error]



=== TEST 22: match with ctx and a pos
--- stream_server_config
    content_by_lua_block {
        local ctx = { pos = 3 }
        m = njt.re.match("1234, hello", "([0-9]+)", "", ctx)
        if m then
            njt.say(m[0])
            njt.say(ctx.pos)
        else
            njt.say("not matched!")
            njt.say(ctx.pos)
        end
    }
--- stream_response
34
5
--- no_error_log
[error]



=== TEST 23: match (look-behind assertion)
--- stream_server_config
    content_by_lua_block {
        local ctx = {}
        local m = njt.re.match("{foobarbaz}", "(?<=foo)bar|(?<=bar)baz", "", ctx)
        njt.say(m and m[0])

        m = njt.re.match("{foobarbaz}", "(?<=foo)bar|(?<=bar)baz", "", ctx)
        njt.say(m and m[0])
    }
--- stream_response
bar
baz
--- no_error_log
[error]



=== TEST 24: escaping sequences
--- stream_server_config
    content_by_lua_file html/a.lua;
--- user_files
>>> a.lua
local uri = "<impact>2</impact>"
local regex = '(?:>[\\w\\s]*</?\\w{2,}>)';
njt.say("regex: ", regex)
m = njt.re.match(uri, regex, "oi")
if m then
    njt.say("[", m[0], "]")
else
    njt.say("not matched!")
end
--- stream_response
regex: (?:>[\w\s]*</?\w{2,}>)
[>2</impact>]
--- no_error_log
[error]



=== TEST 25: long brackets
--- stream_server_config
    content_by_lua_block {
        m = njt.re.match("hello, 1234", [[\d+]])
        if m then
            njt.say(m[0])
        else
            njt.say("not matched!")
        end
    }
--- stream_response
1234
--- no_error_log
[error]



=== TEST 26: bad pattern
--- stream_server_config
    content_by_lua_block {
        local m, err = njt.re.match("hello, 1234", "([0-9]+")
        if m then
            njt.say(m[0])

        else
            if err then
                njt.say("error: ", err)

            else
                njt.say("not matched!")
            end
        end
    }
--- stream_response
error: pcre_compile() failed: missing ) in "([0-9]+"

--- no_error_log
[error]



=== TEST 27: long brackets containing [...]
--- stream_server_config
    content_by_lua_block {
        m = njt.re.match("hello, 1234", [[([0-9]+)]])
        if m then
            njt.say(m[0])
        else
            njt.say("not matched!")
        end
    }
--- stream_response
1234
--- no_error_log
[error]



=== TEST 28: bug report (github issue #72)
--- stream_server_config
    content_by_lua_block {
        local m, err = njt.re.match("hello", "hello", "j")
        njt.say("done: ", m and "yes" or "no")
    }
--- stream_server_config2
    content_by_lua_block {
        njt.re.match("hello", "world", "j")
        njt.say("done: ", m and "yes" or "no")
    }
--- stream_response
done: yes
done: no
--- no_error_log
[error]



=== TEST 29: non-empty subject, empty pattern
--- stream_server_config
    content_by_lua_block {
        local ctx = {}
        local m = njt.re.match("hello, 1234", "", "", ctx)
        if m then
            njt.say("pos: ", ctx.pos)
            njt.say("m: ", m[0])
        else
            njt.say("not matched!")
        end
    }
--- stream_response
pos: 1
m: 
--- no_error_log
[error]



=== TEST 30: named subpatterns w/ extraction
--- stream_server_config
    content_by_lua_block {
        local m = njt.re.match("hello, 1234", "(?<first>[a-z]+), [0-9]+")
        if m then
            njt.say(m[0])
            njt.say(m[1])
            njt.say(m.first)
            njt.say(m.second)
        else
            njt.say("not matched!")
        end
    }
--- stream_response
hello, 1234
hello
hello
nil
--- no_error_log
[error]



=== TEST 31: duplicate named subpatterns w/ extraction
--- stream_server_config
    content_by_lua_block {
        local m = njt.re.match("hello, 1234", "(?<first>[a-z]+), (?<first>[0-9]+)", "D")
        if m then
            njt.say(m[0])
            njt.say(m[1])
            njt.say(m[2])
            njt.say(table.concat(m.first,"-"))
        else
            njt.say("not matched!")
        end
    }
--- stream_response
hello, 1234
hello
1234
hello-1234
--- no_error_log
[error]



=== TEST 32: named captures are empty strings
--- stream_server_config
    content_by_lua_block {
        local m = njt.re.match("1234", "(?<first>[a-z]*)([0-9]+)")
        if m then
            njt.say(m[0])
            njt.say(m.first)
            njt.say(m[1])
            njt.say(m[2])
        else
            njt.say("not matched!")
        end
    }
--- stream_response
1234


1234
--- no_error_log
[error]



=== TEST 33: named captures are nil
--- stream_server_config
    content_by_lua_block {
        local m = njt.re.match("hello, world", "(world)|(hello)|(?<named>howdy)")
        if m then
            njt.say(m[0])
            njt.say(m[1])
            njt.say(m[2])
            njt.say(m[3])
            njt.say(m["named"])
        else
            njt.say("not matched!")
        end
    }
--- stream_response
hello
false
hello
false
false
--- no_error_log
[error]



=== TEST 34: duplicate named subpatterns
--- stream_server_config
    content_by_lua_block {
        local m = njt.re.match("hello, world",
                               [[(?<named>\w+), (?<named>\w+)]],
                               "D")
        if m then
            njt.say(m[0])
            njt.say(m[1])
            njt.say(m[2])
            njt.say(table.concat(m.named,"-"))
        else
            njt.say("not matched!")
        end
    }
--- stream_response
hello, world
hello
world
hello-world
--- no_error_log
[error]



=== TEST 35: Javascript compatible mode
--- stream_server_config
    content_by_lua_block {
        local m = njt.re.match("章", [[\u7AE0]], "uJ")
        if m then
            njt.say("matched: ", m[0])
        else
            njt.say("not matched!")
        end
    }
--- stream_response
matched: 章
--- no_error_log
[error]



=== TEST 36: empty duplicate captures
--- stream_server_config
    content_by_lua_block {
        local target = 'test'
        local regex = '^(?:(?<group1>(?:foo))|(?<group2>(?:bar))|(?<group3>(?:test)))$'

        -- Note the D here
        local m = njt.re.match(target, regex, 'D')

        njt.say(type(m.group1))
        njt.say(type(m.group2))
    }
--- stream_response
nil
nil
--- no_error_log
[error]



=== TEST 37: bad UTF-8
--- stream_server_config
    content_by_lua_block {
        local target = "你好"
        local regex = "你好"

        -- Note the D here
        local m, err = njt.re.match(string.sub(target, 1, 4), regex, "u")

        if err then
            njt.say("error: ", err)
            return
        end

        if m then
            njt.say("matched: ", m[0])
        else
            njt.say("not matched")
        end
    }
--- stream_response_like chop
^error: pcre_exec\(\) failed: -10$

--- no_error_log
[error]



=== TEST 38: UTF-8 mode without UTF-8 sequence checks
--- stream_server_config
    content_by_lua_block {
        local m = njt.re.match("你好", ".", "U")
        if m then
            njt.say(m[0])
        else
            njt.say("not matched!")
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

--- stream_response
你
--- no_error_log
[error]



=== TEST 39: UTF-8 mode with UTF-8 sequence checks
--- stream_server_config
    content_by_lua_block {
        local m = njt.re.match("你好", ".", "u")
        if m then
            njt.say(m[0])
        else
            njt.say("not matched!")
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

--- stream_response
你
--- no_error_log
[error]



=== TEST 40: just hit match limit
--- stream_config
    lua_regex_match_limit 5000;
--- stream_server_config
    content_by_lua_file html/a.lua;

--- user_files
>>> a.lua
local re = [==[(?i:([\s'\"`´’‘\(\)]*)?([\d\w]+)([\s'\"`´’‘\(\)]*)?(?:=|<=>|r?like|sounds\s+like|regexp)([\s'\"`´’‘\(\)]*)?\2|([\s'\"`´’‘\(\)]*)?([\d\w]+)([\s'\"`´’‘\(\)]*)?(?:!=|<=|>=|<>|<|>|\^|is\s+not|not\s+like|not\s+regexp)([\s'\"`´’‘\(\)]*)?(?!\6)([\d\w]+))]==]

s = string.rep([[ABCDEFG]], 10)

local start = njt.now()

local res, err = njt.re.match(s, re, "o")

--[[
njt.update_time()
local elapsed = njt.now() - start
njt.say(elapsed, " sec elapsed.")
]]

if not res then
    if err then
        njt.say("error: ", err)
        return
    end
    njt.say("failed to match")
    return
end

--- stream_response
error: pcre_exec() failed: -8



=== TEST 41: just not hit match limit
--- stream_config
    lua_regex_match_limit 5700;
--- stream_server_config
    content_by_lua_file html/a.lua;

--- user_files
>>> a.lua
local re = [==[(?i:([\s'\"`´’‘\(\)]*)?([\d\w]+)([\s'\"`´’‘\(\)]*)?(?:=|<=>|r?like|sounds\s+like|regexp)([\s'\"`´’‘\(\)]*)?\2|([\s'\"`´’‘\(\)]*)?([\d\w]+)([\s'\"`´’‘\(\)]*)?(?:!=|<=|>=|<>|<|>|\^|is\s+not|not\s+like|not\s+regexp)([\s'\"`´’‘\(\)]*)?(?!\6)([\d\w]+))]==]

s = string.rep([[ABCDEFG]], 10)

local start = njt.now()

local res, err = njt.re.match(s, re, "o")

--[[
njt.update_time()
local elapsed = njt.now() - start
njt.say(elapsed, " sec elapsed.")
]]

if not res then
    if err then
        njt.say("error: ", err)
        return
    end
    njt.say("failed to match")
    return
end

--- stream_response
failed to match
--- no_error_log
[error]



=== TEST 42: extra table argument
--- stream_server_config
    content_by_lua_block {
        local res = {}
        local s = "hello, 1234"
        m = njt.re.match(s, [[(\d)(\d)]], "o", nil, res)
        if m then
            njt.say("1: m size: ", #m)
            njt.say("1: res size: ", #res)
        else
            njt.say("1: not matched!")
        end
        m = njt.re.match(s, [[(\d)]], "o", nil, res)
        if m then
            njt.say("2: m size: ", #m)
            njt.say("2: res size: ", #res)
        else
            njt.say("2: not matched!")
        end
    }
--- stream_response
1: m size: 2
1: res size: 2
2: m size: 2
2: res size: 2
--- no_error_log
[error]



=== TEST 43: init_by_lua
--- stream_config
    init_by_lua_block {
        m = njt.re.match("hello, 1234", [[(\d+)]])
--- stream_server_config
    content_by_lua_block {
        if m then
            njt.say(m[0])
        else
            njt.say("not matched!")
        end
    }
--- stream_response
1234
--- no_error_log
[error]
--- SKIP
