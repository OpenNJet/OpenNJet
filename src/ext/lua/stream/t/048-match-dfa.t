# vim:set ft= ts=4 sw=4 et fdm=marker:
use Test::Nginx::Socket::Lua::Stream;

#worker_connections(1014);
#master_on();
#workers(2);
#log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 2 + 4);

#no_diff();
no_long_string();
run_tests();

__DATA__

=== TEST 1: matched with d
--- stream_server_config
    content_by_lua_block {
        m = njt.re.match("hello", "(he|hell)", "d")
        if m then
            njt.say(m[0])
        else
            njt.say("not matched!")
        end
    }
--- stream_response
hell



=== TEST 2: matched with d + j
--- stream_server_config
    content_by_lua_block {
        m = njt.re.match("hello", "(he|hell)", "jd")
        if m then
            njt.say(m[0])
        else
            njt.say("not matched!")
        end
    }
--- stream_response
hell



=== TEST 3: not matched with j
--- stream_server_config
    content_by_lua_block {
        m = njt.re.match("world", "(he|hell)", "d")
        if m then
            njt.say(m[0])
        else
            njt.say("not matched!")
        end
    }
--- stream_response
not matched!



=== TEST 4: matched with do
--- stream_server_config
    content_by_lua_block {
        m = njt.re.match("hello", "he|hell", "do")
        if m then
            njt.say(m[0])
            njt.say(m[1])
            njt.say(m[2])
        else
            njt.say("not matched!")
        end
    }
--- stream_response
hell
nil
nil



=== TEST 5: not matched with do
--- stream_server_config
    content_by_lua_block {
        m = njt.re.match("world", "([0-9]+)", "do")
        if m then
            njt.say(m[0])
        else
            njt.say("not matched!")
        end
    }
--- stream_response
not matched!



=== TEST 6: UTF-8 mode without UTF-8 sequence checks
--- stream_server_config
    content_by_lua_block {
        local m = njt.re.match("你好", ".", "Ud")
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

probe process("$LIBPCRE_PATH").function("pcre_dfa_exec") {
    printf("exec opts: %x\n", $options)
}

--- stap_out
compile opts: 800
exec opts: 2000

--- stream_response
你
--- no_error_log
[error]



=== TEST 7: UTF-8 mode with UTF-8 sequence checks
--- stream_server_config
    content_by_lua_block {
        local m = njt.re.match("你好", ".", "ud")
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

probe process("$LIBPCRE_PATH").function("pcre_dfa_exec") {
    printf("exec opts: %x\n", $options)
}

--- stap_out
compile opts: 800
exec opts: 0

--- stream_response
你
--- no_error_log
[error]
