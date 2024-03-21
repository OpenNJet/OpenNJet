# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua;

#worker_connections(1014);
#master_on();
#workers(2);
#log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 2 + 16);

#no_diff();
no_long_string();
run_tests();

__DATA__

=== TEST 1: sanity
--- config
    location /re {
        content_by_lua '
            local m = njt.re.match("hello, 1234", "([0-9]+)")
            if m then
                njt.say(m[0])
            else
                njt.say("not matched!")
            end
        ';
    }
--- request
    GET /re
--- response_body
1234



=== TEST 2: escaping sequences
--- config
    location /re {
        content_by_lua '
            local m = njt.re.match("hello, 1234", "(\\\\d+)")
            if m then
                njt.say(m[0])
            else
                njt.say("not matched!")
            end
        ';
    }
--- request
    GET /re
--- response_body
1234



=== TEST 3: escaping sequences (bad)
--- config
    location /re {
        content_by_lua '
            local m = njt.re.match("hello, 1234", "(\\d+)")
            if m then
                njt.say(m[0])
            else
                njt.say("not matched!")
            end
        ';
    }
--- request
    GET /re
--- response_body_like: 500 Internal Server Error
--- error_log eval
[qr/invalid escape sequence near '"\('/]
--- error_code: 500



=== TEST 4: escaping sequences in [[ ... ]]
--- config
    location /re {
        content_by_lua '
            local m = njt.re.match("hello, 1234", "[[\\d+]]")
            if m then
                njt.say(m[0])
            else
                njt.say("not matched!")
            end
        ';
    }
--- request
    GET /re
--- response_body_like: 500 Internal Server Error
--- error_log eval
[qr/invalid escape sequence near '"\[\['/]
--- error_code: 500



=== TEST 5: single capture
--- config
    location /re {
        content_by_lua '
            local m = njt.re.match("hello, 1234", "([0-9]{2})[0-9]+")
            if m then
                njt.say(m[0])
                njt.say(m[1])
            else
                njt.say("not matched!")
            end
        ';
    }
--- request
    GET /re
--- response_body
1234
12



=== TEST 6: multiple captures
--- config
    location /re {
        content_by_lua '
            local m = njt.re.match("hello, 1234", "([a-z]+).*?([0-9]{2})[0-9]+", "")
            if m then
                njt.say(m[0])
                njt.say(m[1])
                njt.say(m[2])
            else
                njt.say("not matched!")
            end
        ';
    }
--- request
    GET /re
--- response_body
hello, 1234
hello
12



=== TEST 7: multiple captures (with o)
--- config
    location /re {
        content_by_lua '
            local m = njt.re.match("hello, 1234", "([a-z]+).*?([0-9]{2})[0-9]+", "o")
            if m then
                njt.say(m[0])
                njt.say(m[1])
                njt.say(m[2])
            else
                njt.say("not matched!")
            end
        ';
    }
--- request
    GET /re
--- response_body
hello, 1234
hello
12



=== TEST 8: not matched
--- config
    location /re {
        content_by_lua '
            local m = njt.re.match("hello, 1234", "foo")
            if m then
                njt.say(m[0])
            else
                njt.say("not matched: ", m)
            end
        ';
    }
--- request
    GET /re
--- response_body
not matched: nil



=== TEST 9: case sensitive by default
--- config
    location /re {
        content_by_lua '
            local m = njt.re.match("hello, 1234", "HELLO")
            if m then
                njt.say(m[0])
            else
                njt.say("not matched: ", m)
            end
        ';
    }
--- request
    GET /re
--- response_body
not matched: nil



=== TEST 10: case insensitive
--- config
    location /re {
        content_by_lua '
            local m = njt.re.match("hello, 1234", "HELLO", "i")
            if m then
                njt.say(m[0])
            else
                njt.say("not matched: ", m)
            end
        ';
    }
--- request
    GET /re
--- response_body
hello



=== TEST 11: UTF-8 mode
--- config
    location /re {
        content_by_lua '
            local rc, err = pcall(njt.re.match, "hello章亦春", "HELLO.{2}", "iu")
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
        ';
    }
--- request
    GET /re
--- response_body_like chop
^(?:FAIL: bad argument \#2 to '\?' \(pcre_compile\(\) failed: this version of PCRE is not compiled with PCRE_UTF8 support in "HELLO\.\{2\}" at "HELLO\.\{2\}"\)|hello章亦)$



=== TEST 12: multi-line mode (^ at line head)
--- config
    location /re {
        content_by_lua '
            local m = njt.re.match("hello\\nworld", "^world", "m")
            if m then
                njt.say(m[0])
            else
                njt.say("not matched: ", m)
            end
        ';
    }
--- request
    GET /re
--- response_body
world



=== TEST 13: multi-line mode (. does not match \n)
--- config
    location /re {
        content_by_lua '
            local m = njt.re.match("hello\\nworld", ".*", "m")
            if m then
                njt.say(m[0])
            else
                njt.say("not matched: ", m)
            end
        ';
    }
--- request
    GET /re
--- response_body
hello



=== TEST 14: single-line mode (^ as normal)
--- config
    location /re {
        content_by_lua '
            local m = njt.re.match("hello\\nworld", "^world", "s")
            if m then
                njt.say(m[0])
            else
                njt.say("not matched: ", m)
            end
        ';
    }
--- request
    GET /re
--- response_body
not matched: nil



=== TEST 15: single-line mode (dot all)
--- config
    location /re {
        content_by_lua '
            local m = njt.re.match("hello\\nworld", ".*", "s")
            if m then
                njt.say(m[0])
            else
                njt.say("not matched: ", m)
            end
        ';
    }
--- request
    GET /re
--- response_body
hello
world



=== TEST 16: extended mode (ignore whitespaces)
--- config
    location /re {
        content_by_lua '
            local m = njt.re.match("hello\\nworld", "\\\\w     \\\\w", "x")
            if m then
                njt.say(m[0])
            else
                njt.say("not matched: ", m)
            end
        ';
    }
--- request
    GET /re
--- response_body
he



=== TEST 17: bad pattern
--- config
    location /re {
        content_by_lua '
            local m, err = njt.re.match("hello\\nworld", "(abc")
            if m then
                njt.say(m[0])

            else
                if err then
                    njt.say("error: ", err)

                else
                    njt.say("not matched: ", m)
                end
            end
        ';
    }
--- request
    GET /re
--- response_body
error: pcre_compile() failed: missing ) in "(abc"
--- no_error_log
[error]



=== TEST 18: bad option
--- config
    location /re {
        content_by_lua '
            local rc, m = pcall(njt.re.match, "hello\\nworld", ".*", "Hm")
            if rc then
                if m then
                    njt.say(m[0])
                else
                    njt.say("not matched: ", m)
                end
            else
                njt.say("error: ", m)
            end
        ';
    }
--- request
    GET /re
--- response_body_like chop
error: .*?unknown flag "H" \(flags "Hm"\)



=== TEST 19: extended mode (ignore whitespaces)
--- config
    location /re {
        content_by_lua '
            local m = njt.re.match("hello, world", "(world)|(hello)", "x")
            if m then
                njt.say(m[0])
                njt.say(m[1])
                njt.say(m[2])
            else
                njt.say("not matched: ", m)
            end
        ';
    }
--- request
    GET /re
--- response_body
hello
false
hello



=== TEST 20: optional trailing captures
--- config
    location /re {
        content_by_lua '
            local m = njt.re.match("hello, 1234", "([0-9]+)(h?)")
            if m then
                njt.say(m[0])
                njt.say(m[1])
                njt.say(m[2])
            else
                njt.say("not matched!")
            end
        ';
    }
--- request
    GET /re
--- response_body eval
"1234
1234

"



=== TEST 21: anchored match (failed)
--- config
    location /re {
        content_by_lua '
            local m = njt.re.match("hello, 1234", "([0-9]+)", "a")
            if m then
                njt.say(m[0])
            else
                njt.say("not matched!")
            end
        ';
    }
--- request
    GET /re
--- response_body
not matched!



=== TEST 22: anchored match (succeeded)
--- config
    location /re {
        content_by_lua '
            local m = njt.re.match("1234, hello", "([0-9]+)", "a")
            if m then
                njt.say(m[0])
            else
                njt.say("not matched!")
            end
        ';
    }
--- request
    GET /re
--- response_body
1234



=== TEST 23: match with ctx but no pos
--- config
    location /re {
        content_by_lua '
            local ctx = {}
            local m = njt.re.match("1234, hello", "([0-9]+)", "", ctx)
            if m then
                njt.say(m[0])
                njt.say(ctx.pos)
            else
                njt.say("not matched!")
                njt.say(ctx.pos)
            end
        ';
    }
--- request
    GET /re
--- response_body
1234
5



=== TEST 24: match with ctx and a pos
--- config
    location /re {
        content_by_lua '
            local ctx = { pos = 3 }
            local m = njt.re.match("1234, hello", "([0-9]+)", "", ctx)
            if m then
                njt.say(m[0])
                njt.say(ctx.pos)
            else
                njt.say("not matched!")
                njt.say(ctx.pos)
            end
        ';
    }
--- request
    GET /re
--- response_body
34
5



=== TEST 25: sanity (set_by_lua)
--- config
    location /re {
        set_by_lua $res '
            local m = njt.re.match("hello, 1234", "([0-9]+)")
            if m then
                return m[0]
            else
                return "not matched!"
            end
        ';
        echo $res;
    }
--- request
    GET /re
--- response_body
1234



=== TEST 26: match (look-behind assertion)
--- config
    location /re {
        content_by_lua '
            local ctx = {}
            local m = njt.re.match("{foobarbaz}", "(?<=foo)bar|(?<=bar)baz", "", ctx)
            njt.say(m and m[0])

            m = njt.re.match("{foobarbaz}", "(?<=foo)bar|(?<=bar)baz", "", ctx)
            njt.say(m and m[0])
        ';
    }
--- request
    GET /re
--- response_body
bar
baz



=== TEST 27: escaping sequences
--- config
    location /re {
        content_by_lua_file html/a.lua;
    }
--- user_files
>>> a.lua
local m = njt.re.match("hello, 1234", "(\\\s+)")
if m then
    njt.say("[", m[0], "]")
else
    njt.say("not matched!")
end
--- request
    GET /re
--- response_body_like: 500 Internal Server Error
--- error_log eval
[qr/invalid escape sequence near '"\(\\'/]
--- error_code: 500



=== TEST 28: escaping sequences
--- config
    location /re {
        access_by_lua_file html/a.lua;
        content_by_lua return;
    }
--- user_files
>>> a.lua
local uri = "<impact>2</impact>"
local regex = '(?:>[\\w\\s]*</?\\w{2,}>)';
njt.say("regex: ", regex)
local m = njt.re.match(uri, regex, "oi")
if m then
    njt.say("[", m[0], "]")
else
    njt.say("not matched!")
end
--- request
    GET /re
--- response_body
regex: (?:>[\w\s]*</?\w{2,}>)
[>2</impact>]



=== TEST 29: long brackets
--- config
    location /re {
        content_by_lua '
            local m = njt.re.match("hello, 1234", [[\\d+]])
            if m then
                njt.say(m[0])
            else
                njt.say("not matched!")
            end
        ';
    }
--- request
    GET /re
--- response_body
1234



=== TEST 30: bad pattern
--- config
    location /re {
        content_by_lua '
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
        ';
    }
--- request
    GET /re
--- response_body
error: pcre_compile() failed: missing ) in "([0-9]+"

--- no_error_log
[error]



=== TEST 31: long brackets containing [...]
--- config
    location /re {
        content_by_lua '
            local m = njt.re.match("hello, 1234", [[([0-9]+)]])
            if m then
                njt.say(m[0])
            else
                njt.say("not matched!")
            end
        ';
    }
--- request
    GET /re
--- response_body
1234



=== TEST 32: bug report (github issue #72)
--- config
    location /re {
        content_by_lua '
            njt.re.match("hello", "hello", "j")
            njt.say("done")
        ';
        header_filter_by_lua '
            njt.re.match("hello", "world", "j")
        ';
    }
--- request
    GET /re
--- response_body
done



=== TEST 33: bug report (github issue #72)
--- config
    location /re {
        content_by_lua '
            njt.re.match("hello", "hello", "j")
            njt.exec("/foo")
        ';
    }

    location /foo {
        content_by_lua '
            njt.re.match("hello", "world", "j")
            njt.say("done")
        ';
    }
--- request
    GET /re
--- response_body
done



=== TEST 34: non-empty subject, empty pattern
--- config
    location /re {
        content_by_lua '
            local ctx = {}
            local m = njt.re.match("hello, 1234", "", "", ctx)
            if m then
                njt.say("pos: ", ctx.pos)
                njt.say("m: ", m[0])
            else
                njt.say("not matched!")
            end
        ';
    }
--- request
    GET /re
--- response_body
pos: 1
m: 
--- no_error_log
[error]



=== TEST 35: named subpatterns w/ extraction
--- config
    location /re {
        content_by_lua '
            local m = njt.re.match("hello, 1234", "(?<first>[a-z]+), [0-9]+")
            if m then
                njt.say(m[0])
                njt.say(m[1])
                njt.say(m.first)
                njt.say(m.second)
            else
                njt.say("not matched!")
            end
        ';
    }
--- request
    GET /re
--- response_body
hello, 1234
hello
hello
nil



=== TEST 36: duplicate named subpatterns w/ extraction
--- config
    location /re {
        content_by_lua '
            local m = njt.re.match("hello, 1234", "(?<first>[a-z]+), (?<first>[0-9]+)", "D")
            if m then
                njt.say(m[0])
                njt.say(m[1])
                njt.say(m[2])
                njt.say(table.concat(m.first,"-"))
            else
                njt.say("not matched!")
            end
        ';
    }
--- request
    GET /re
--- response_body
hello, 1234
hello
1234
hello-1234



=== TEST 37: named captures are empty strings
--- config
    location /re {
        content_by_lua '
            local m = njt.re.match("1234", "(?<first>[a-z]*)([0-9]+)")
            if m then
                njt.say(m[0])
                njt.say(m.first)
                njt.say(m[1])
                njt.say(m[2])
            else
                njt.say("not matched!")
            end
        ';
    }
--- request
    GET /re
--- response_body
1234


1234



=== TEST 38: named captures are false
--- config
    location /re {
        content_by_lua '
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
        ';
    }
--- request
    GET /re
--- response_body
hello
false
hello
false
false



=== TEST 39: duplicate named subpatterns
--- config
    location /re {
        content_by_lua '
            local m = njt.re.match("hello, world",
                                   "(?<named>\\\\w+), (?<named>\\\\w+)",
                                   "D")
            if m then
                njt.say(m[0])
                njt.say(m[1])
                njt.say(m[2])
                njt.say(table.concat(m.named,"-"))
            else
                njt.say("not matched!")
            end
        ';
    }
--- request
    GET /re
--- response_body
hello, world
hello
world
hello-world
--- no_error_log
[error]



=== TEST 40: Javascript compatible mode
--- config
    location /t {
        content_by_lua '
            local m = njt.re.match("章", [[\\u7AE0]], "uJ")
            if m then
                njt.say("matched: ", m[0])
            else
                njt.say("not matched!")
            end
        ';
    }
--- request
GET /t
--- response_body
matched: 章
--- no_error_log
[error]



=== TEST 41: empty duplicate captures
--- config
    location = /t {
        content_by_lua "
            local target = 'test'
            local regex = '^(?:(?<group1>(?:foo))|(?<group2>(?:bar))|(?<group3>(?:test)))$'

            -- Note the D here
            local m = njt.re.match(target, regex, 'D')

            njt.say(type(m.group1))
            njt.say(type(m.group2))
        ";
    }
--- request
GET /t
--- response_body
nil
nil
--- no_error_log
[error]



=== TEST 42: bad UTF-8
--- config
    location = /t {
        content_by_lua '
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
        ';
    }
--- request
GET /t
--- response_body_like chop
^error: pcre_exec\(\) failed: -10$

--- no_error_log
[error]



=== TEST 43: UTF-8 mode without UTF-8 sequence checks
--- config
    location /re {
        content_by_lua '
            local m = njt.re.match("你好", ".", "U")
            if m then
                njt.say(m[0])
            else
                njt.say("not matched!")
            end
        ';
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

--- request
    GET /re
--- response_body
你
--- no_error_log
[error]



=== TEST 44: UTF-8 mode with UTF-8 sequence checks
--- config
    location /re {
        content_by_lua '
            local m = njt.re.match("你好", ".", "u")
            if m then
                njt.say(m[0])
            else
                njt.say("not matched!")
            end
        ';
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

--- request
    GET /re
--- response_body
你
--- no_error_log
[error]



=== TEST 45: just hit match limit
--- http_config
    lua_regex_match_limit 5000;
--- config
    location /re {
        content_by_lua_file html/a.lua;
    }

--- user_files
>>> a.lua
local re = [==[(?i:([\s'\"`´’‘\(\)]*)?([\d\w]+)([\s'\"`´’‘\(\)]*)?(?:=|<=>|r?like|sounds\s+like|regexp)([\s'\"`´’‘\(\)]*)?\2|([\s'\"`´’‘\(\)]*)?([\d\w]+)([\s'\"`´’‘\(\)]*)?(?:!=|<=|>=|<>|<|>|\^|is\s+not|not\s+like|not\s+regexp)([\s'\"`´’‘\(\)]*)?(?!\6)([\d\w]+))]==]

local s = string.rep([[ABCDEFG]], 10)

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

--- request
    GET /re
--- response_body
error: pcre_exec() failed: -8



=== TEST 46: just not hit match limit
--- http_config
    lua_regex_match_limit 5100;
--- config
    location /re {
        content_by_lua_file html/a.lua;
    }

--- user_files
>>> a.lua
local re = [==[(?i:([\s'\"`´’‘\(\)]*)?([\d\w]+)([\s'\"`´’‘\(\)]*)?(?:=|<=>|r?like|sounds\s+like|regexp)([\s'\"`´’‘\(\)]*)?\2|([\s'\"`´’‘\(\)]*)?([\d\w]+)([\s'\"`´’‘\(\)]*)?(?:!=|<=|>=|<>|<|>|\^|is\s+not|not\s+like|not\s+regexp)([\s'\"`´’‘\(\)]*)?(?!\6)([\d\w]+))]==]

local s = string.rep([[ABCDEFG]], 10)

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

--- request
    GET /re
--- response_body
failed to match



=== TEST 47: extra table argument
--- config
    location /re {
        content_by_lua '
            local res = {}
            local s = "hello, 1234"
            local m = njt.re.match(s, [[(\\d)(\\d)]], "o", nil, res)
            if m then
                njt.say("1: m size: ", #m)
                njt.say("1: res size: ", #res)
            else
                njt.say("1: not matched!")
            end
            m = njt.re.match(s, [[(\\d)]], "o", nil, res)
            if m then
                njt.say("2: m size: ", #m)
                njt.say("2: res size: ", #res)
            else
                njt.say("2: not matched!")
            end
        ';
    }
--- request
    GET /re
--- response_body
1: m size: 2
1: res size: 2
2: m size: 2
2: res size: 2
--- no_error_log
[error]



=== TEST 48: init_by_lua_block
--- http_config
    init_by_lua_block {
        local m, err = njt.re.match("hello, 1234", [[(\d+)]])
        if not m then
            njt.log(njt.ERR, "failed to match: ", err)
        else
            package.loaded.m = m
        end
    }
--- config
    location /re {
        content_by_lua_block {
            local m = package.loaded.m
            if m then
                njt.say(m[0])
            else
                njt.say("not matched!")
            end
        }
    }
--- request
    GET /re
--- response_body
1234
--- no_error_log
[error]



=== TEST 49: trailing captures are false
--- config
    location /re {
        content_by_lua '
            local m = njt.re.match("hello", "(hello)(.+)?")
            if m then
                njt.say(m[0])
                njt.say(m[1])
                njt.say(m[2])
            end
        ';
    }
--- request
    GET /re
--- response_body
hello
hello
false



=== TEST 50: the 5th argument hides the 4th (GitHub #719)
--- config
    location /re {
        content_by_lua '
            local ctx, m = { pos = 5 }, {};
            local _, err = njt.re.match("20172016-11-3 03:07:09", [=[(\d\d\d\d)]=], "", ctx, m);
            if m then
                njt.say(m[0], " ", _[0], " ", ctx.pos)
            else
                njt.say("not matched!")
            end
        ';
    }
--- request
    GET /re
--- response_body
2016 2016 9
