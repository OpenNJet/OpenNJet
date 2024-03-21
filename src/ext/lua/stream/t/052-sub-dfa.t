# vim:set ft= ts=4 sw=4 et fdm=marker:
use Test::Nginx::Socket::Lua::Stream;

#worker_connections(1014);
#master_on();
#workers(2);
#log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 2 + 6);

#no_diff();
no_long_string();
run_tests();

__DATA__

=== TEST 1: matched with d
--- stream_server_config
    content_by_lua_block {
        local s, n = njt.re.sub("hello, 1234 5678", "[0-9]|[0-9][0-9]", "world", "d")
        if n then
            njt.say(s, ": ", n)
        else
            njt.say(s)
        end
    }
--- stream_response
hello, world34 5678: 1



=== TEST 2: not matched with d
--- stream_server_config
    content_by_lua_block {
        local s, n = njt.re.sub("hello, world", "[0-9]+", "hiya", "d")
        if n then
            njt.say(s, ": ", n)
        else
            njt.say(s)
        end
    }
--- stream_response
hello, world: 0



=== TEST 3: matched with do
--- stream_server_config
    content_by_lua_block {
        local s, n = njt.re.sub("hello, 1234 5678", "[0-9]|[0-9][0-9]", "world", "do")
        if n then
            njt.say(s, ": ", n)
        else
            njt.say(s)
        end
    }
--- stream_response
hello, world34 5678: 1



=== TEST 4: not matched with do
--- stream_server_config
    content_by_lua_block {
        local s, n = njt.re.sub("hello, world", "[0-9]+", "hiya", "do")
        if n then
            njt.say(s, ": ", n)
        else
            njt.say(s)
        end
    }
--- stream_response
hello, world: 0



=== TEST 5: bad pattern
--- stream_server_config
    content_by_lua_block {
        local s, n, err = njt.re.sub("hello\\nworld", "(abc", "world", "j")
        if s then
            njt.say(s, ": ", n)

        else
            njt.say("error: ", err)
        end
    }
--- stream_response
error: pcre_compile() failed: missing ) in "(abc"
--- no_error_log
[error]



=== TEST 6: bad pattern + o
--- stream_server_config
    content_by_lua_block {
        local s, n, err = njt.re.sub("hello\\nworld", "(abc", "world", "jo")
        if s then
            njt.say(s, ": ", n)

        else
            njt.say("error: ", err)
        end
    }
--- stream_response
error: pcre_compile() failed: missing ) in "(abc"
--- no_error_log
[error]



=== TEST 7: UTF-8 mode without UTF-8 sequence checks
--- stream_server_config
    content_by_lua_block {
        local s, n, err = njt.re.sub("你好", ".", "a", "Ud")
        if s then
            njt.say("s: ", s)
        end
    }
--- stap
probe process("$LIBPCRE_PATH").function("pcre_compile") {
    printf("compile opts: %x\n", $options)
}

probe process("$LIBPCRE_PATH").function("pcre_dfa_exec") {
    printf("exec opts: %x\n", $options)
}

--- stap_out
compile opts: 800
exec opts: 2000

--- stream_response
s: a好
--- no_error_log
[error]



=== TEST 8: UTF-8 mode with UTF-8 sequence checks
--- stream_server_config
    content_by_lua_block {
        local s, n, err = njt.re.sub("你好", ".", "a", "ud")
        if s then
            njt.say("s: ", s)
        end
    }
--- stap
probe process("$LIBPCRE_PATH").function("pcre_compile") {
    printf("compile opts: %x\n", $options)
}

probe process("$LIBPCRE_PATH").function("pcre_dfa_exec") {
    printf("exec opts: %x\n", $options)
}

--- stap_out
compile opts: 800
exec opts: 0

--- stream_response
s: a好
--- no_error_log
[error]
