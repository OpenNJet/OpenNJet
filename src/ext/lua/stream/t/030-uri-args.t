# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;

#worker_connections(1014);
#master_on();
#workers(2);
log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 3);

no_root_location();

#no_shuffle();
#no_diff();
no_long_string();
run_tests();

__DATA__

=== TEST 1: njt.encode_args (sanity)
--- stream_server_config
    content_by_lua_block {
        local t = {a = "bar", b = "foo"}
        njt.say(njt.encode_args(t))
    }
--- stream_response eval
qr/a=bar&b=foo|b=foo&a=bar/
--- no_error_log
[error]



=== TEST 2: njt.encode_args (empty table)
--- stream_server_config
    content_by_lua_block {
        local t = {a = nil}
        njt.say("args:" .. njt.encode_args(t))
    }
--- stream_response
args:
--- no_error_log
[error]



=== TEST 3: njt.encode_args (value is table)
--- stream_server_config
    content_by_lua_block {
        local t = {a = {9, 2}, b = 3}
        njt.say("args:" .. njt.encode_args(t))
    }
--- stream_response_like
(?x) ^args:
    (?= .*? \b a=9 \b )  # 3 chars
    (?= .*? \b a=2 \b )  # 3 chars
    (?= .*? \b b=3 \b )  # 3 chars
    (?= (?: [^&]+ & ){2} [^&]+ $ )  # requires exactly 2 &'s
    (?= .{11} $ )  # requires for total 11 chars (exactly) in the string
--- no_error_log
[error]



=== TEST 4: njt.encode_args (boolean values)
--- stream_server_config
    content_by_lua_block {
        local t = {a = true, foo = 3}
        njt.say("args: " .. njt.encode_args(t))
    }
--- stream_response_like
^args: (?:a&foo=3|foo=3&a)$
--- no_error_log
[error]



=== TEST 5: njt.encode_args (boolean values, false)
--- stream_server_config
    content_by_lua_block {
        local t = {a = false, foo = 3}
        njt.say("args: " .. njt.encode_args(t))
    }
--- stream_response
args: foo=3
--- no_error_log
[error]



=== TEST 6: boolean values in njt.encode_args
--- stream_server_config
    content_by_lua_block {
        local t = {bar = {32, true}, foo = 3}
        njt.say(njt.encode_args(t))
    }
--- stream_response_like
(?x) ^
    (?= .*? \b bar=32 \b )     # 6 chars
    (?= .*? \b bar (?!=) \b )  # 3 chars
    (?= .*? \b foo=3 \b )      # 5 chars
    (?= (?: [^&]+ & ){2} [^&]+ $ )  # requires exactly 2 &'s
    (?= .{16} $ )  # requires for total 16 chars (exactly) in the string
--- no_error_log
[error]



=== TEST 7: njt.encode_args (bad user data value)
--- stream_config
    lua_shared_dict dogs 1m;
--- stream_server_config
    content_by_lua_block {
        local t = {bar = njt.shared.dogs, foo = 3}
        rc, err = pcall(njt.encode_args, t)
        njt.say("rc: ", rc, ", err: ", err)
    }
--- stream_response
rc: false, err: attempt to use userdata as query arg value
--- no_error_log
[error]



=== TEST 8: njt.encode_args (empty table)
--- stream_server_config
    content_by_lua_block {
        local t = {}
        njt.say("args: ", njt.encode_args(t))
    }
--- stream_response
args: 
--- no_error_log
[error]



=== TEST 9: njt.encode_args (bad arg)
--- stream_server_config
    content_by_lua_block {
        local rc, err = pcall(njt.encode_args, true)
        njt.say("rc: ", rc, ", err: ", err)
    }
--- stream_response
rc: false, err: bad argument #1 to '?' (table expected, got boolean)
--- no_error_log
[error]



=== TEST 10: njt.decode_args (sanity)
--- stream_server_config
    content_by_lua_block {
        local args = "a=bar&b=foo"
        args = njt.decode_args(args)
        njt.say("a = ", args.a)
        njt.say("b = ", args.b)
    }
--- stream_response
a = bar
b = foo
--- no_error_log
[error]



=== TEST 11: njt.decode_args (multi-value)
--- stream_server_config
    content_by_lua_block {
        local args = "a=bar&b=foo&a=baz"
        args = njt.decode_args(args)
        njt.say("a = ", table.concat(args.a, ", "))
        njt.say("b = ", args.b)
    }
--- stream_response
a = bar, baz
b = foo
--- no_error_log
[error]



=== TEST 12: njt.decode_args (empty string)
--- stream_server_config
    content_by_lua_block {
        local args = ""
        args = njt.decode_args(args)
        njt.say("n = ", #args)
    }
--- stream_response
n = 0
--- no_error_log
[error]



=== TEST 13: njt.decode_args (boolean args)
--- stream_server_config
    content_by_lua_block {
        local args = "a&b"
        args = njt.decode_args(args)
        njt.say("a = ", args.a)
        njt.say("b = ", args.b)
    }
--- stream_response
a = true
b = true
--- no_error_log
[error]



=== TEST 14: njt.decode_args (empty value args)
--- stream_server_config
    content_by_lua_block {
        local args = "a=&b="
        args = njt.decode_args(args)
        njt.say("a = ", args.a)
        njt.say("b = ", args.b)
    }
--- stream_response
a = 
b = 
--- no_error_log
[error]



=== TEST 15: njt.decode_args (max_args = 1)
--- stream_server_config
    content_by_lua_block {
        local args = "a=bar&b=foo"
        args = njt.decode_args(args, 1)
        njt.say("a = ", args.a)
        njt.say("b = ", args.b)
    }
--- stream_response
a = bar
b = nil
--- no_error_log
[error]



=== TEST 16: njt.decode_args (max_args = -1)
--- stream_server_config
    content_by_lua_block {
        local args = "a=bar&b=foo"
        args = njt.decode_args(args, -1)
        njt.say("a = ", args.a)
        njt.say("b = ", args.b)
    }
--- stream_response
a = bar
b = foo
--- no_error_log
[error]



=== TEST 17: njt.decode_args should not modify lua strings in place
--- stream_server_config
    content_by_lua_block {
        local s = "f+f=bar&B=foo"
        args = njt.decode_args(s)
        local arr = {}
        for k, v in pairs(args) do
            table.insert(arr, k)
        end
        table.sort(arr)
        for i, k in ipairs(arr) do
            njt.say("key: ", k)
        end
        njt.say("s = ", s)
    }
--- stream_response
key: B
key: f f
s = f+f=bar&B=foo
--- no_error_log
[error]
