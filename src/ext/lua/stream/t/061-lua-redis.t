# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;

repeat_each(2);

plan tests => repeat_each() * (blocks() * 3);

$ENV{TEST_NGINX_REDIS_PORT} ||= 6379;

#log_level "warn";
#worker_connections(1024);
#master_on();

my $pwd = `pwd`;
chomp $pwd;
$ENV{TEST_NGINX_PWD} ||= $pwd;

our $LuaCpath = $ENV{LUA_CPATH} ||
    '/usr/local/openresty-debug/lualib/?.so;/usr/local/openresty/lualib/?.so;;';

no_long_string();

run_tests();

__DATA__

=== TEST 1: sanity
--- stream_config
    lua_package_path '$TEST_NGINX_PWD/t/lib/?.lua;;';
--- stream_server_config
    content_by_lua_block {
        package.loaded["socket"] = njt.socket
        local Redis = require "Redis"

        local redis = Redis.connect("127.0.0.1", $TEST_NGINX_REDIS_PORT)

        redis:set("some_key", "hello 1234")
        local data = redis:get("some_key")
        njt.say("some_key: ", data)
    }
--- stream_response
some_key: hello 1234
--- no_error_log
[error]



=== TEST 2: coroutine-based pub/sub
--- stream_config eval
qq{
    lua_package_path '\$TEST_NGINX_PWD/t/lib/?.lua;;';
    lua_package_cpath '$::LuaCpath';
}
--- stream_server_config
    content_by_lua_block {
        package.loaded["socket"] = njt.socket
        local Redis = require "Redis"

        local ljson = require "ljson"

        local r1 = Redis.connect("127.0.0.1", $TEST_NGINX_REDIS_PORT)

        local r2 = Redis.connect("127.0.0.1", $TEST_NGINX_REDIS_PORT)

        local loop = r2:pubsub({ subscribe = "foo" })
        local msg, abort = loop()
        njt.say("msg type: ", type(msg))
        njt.say("abort: ", type(abort))

        if msg then
            njt.say("msg: ", ljson.encode(msg))
        end

        for i = 1, 3 do
            r1:publish("foo", "test " .. i)
            msg, abort = loop()
            if msg then
                njt.say("msg: ", ljson.encode(msg))
            end
            njt.say("abort: ", type(abort))
        end

        abort()

        msg, abort = loop()
        njt.say("msg type: ", type(msg))
    }
--- stap2
global ids, cur

function gen_id(k) {
    if (ids[k]) return ids[k]
    ids[k] = ++cur
    return cur
}

F(njt_http_handler) {
    delete ids
    cur = 0
}

/*
probe process("/usr/local/openresty-debug/luajit/lib/libluajit-5.1.so.2").function("lua_yield") {
    id = gen_id($L)
    printf("raw lua yield %d\n", id)
    #print_ubacktrace()
}

probe process("/usr/local/openresty-debug/luajit/lib/libluajit-5.1.so.2").function("lua_resume") {
    id = gen_id($L)
    printf("raw lua resume %d\n", id)
}
*/

/*
F(njt_http_lua_run_thread) {
    id = gen_id($ctx->cur_co)
    printf("run thread %d\n", id)
}
*/

M(http-lua-user-coroutine-resume) {
    p = gen_id($arg2)
    c = gen_id($arg3)
    printf("resume %x in %x\n", c, p)
}

M(http-lua-entry-coroutine-yield) {
    println("entry coroutine yield")
}

F(njt_http_lua_coroutine_yield) {
    printf("yield %x\n", gen_id($L))
}

/*
F(njt_http_lua_coroutine_resume) {
    printf("resume %x\n", gen_id($L))
}
*/

M(http-lua-user-coroutine-yield) {
    p = gen_id($arg2)
    c = gen_id($arg3)
    printf("yield %x in %x\n", c, p)
}

F(njt_http_lua_atpanic) {
    printf("lua atpanic(%d):", gen_id($L))
    print_ubacktrace();
}

M(http-lua-user-coroutine-create) {
    p = gen_id($arg2)
    c = gen_id($arg3)
    printf("create %x in %x\n", c, p)
}

F(njt_http_lua_njt_exec) { println("exec") }

F(njt_http_lua_njt_exit) { println("exit") }

--- stream_response
msg type: table
abort: function
msg: {"channel":"foo","kind":"subscribe","payload":1}
msg: {"channel":"foo","kind":"message","payload":"test 1"}
abort: function
msg: {"channel":"foo","kind":"message","payload":"test 2"}
abort: function
msg: {"channel":"foo","kind":"message","payload":"test 3"}
abort: function
msg type: nil
--- no_error_log
[error]
