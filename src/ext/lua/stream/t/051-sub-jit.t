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

=== TEST 1: matched with j
--- stream_server_config
    content_by_lua_block {
        local s, n = njt.re.sub("hello, 1234 5678", "([0-9]+)", "world", "j")
        if n then
            njt.say(s, ": ", n)
        else
            njt.say(s)
        end
    }
--- stream_response
hello, world 5678: 1
--- error_log
pcre JIT compiling result: 1



=== TEST 2: not matched with j
--- stream_server_config
    content_by_lua_block {
        local s, n = njt.re.sub("hello, world", "[0-9]+", "hiya", "j")
        if n then
            njt.say(s, ": ", n)
        else
            njt.say(s)
        end
    }
--- stream_response
hello, world: 0
--- error_log
pcre JIT compiling result: 1



=== TEST 3: matched with jo
--- stream_server_config
    content_by_lua_block {
        local s, n = njt.re.sub("hello, 1234 5678", "([0-9]+)", "world", "jo")
        if n then
            njt.say(s, ": ", n)
        else
            njt.say(s)
        end
    }
--- stream_response
hello, world 5678: 1

--- grep_error_log eval
qr/pcre JIT compiling result: \d+/

--- grep_error_log_out eval
["pcre JIT compiling result: 1\n", ""]



=== TEST 4: not matched with jo
--- stream_server_config
    content_by_lua_block {
        local s, n = njt.re.sub("hello, world", "[0-9]+", "hiya", "jo")
        if n then
            njt.say(s, ": ", n)
        else
            njt.say(s)
        end
    }
--- stream_response
hello, world: 0

--- grep_error_log eval
qr/pcre JIT compiling result: \d+/

--- grep_error_log_out eval
["pcre JIT compiling result: 1\n", ""]



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
        local s, n, err = njt.re.sub( "hello\\nworld", "(abc", "world", "jo")
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
