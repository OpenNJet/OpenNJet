# vim:set ft= ts=4 sw=4 et fdm=marker:

BEGIN {
    $ENV{TEST_NGINX_POSTPONE_OUTPUT} = 1;
}

use Test::Nginx::Socket::Lua::Stream;

#worker_connections(1014);
#master_on();
#workers(2);
#log_level('warn');

repeat_each(2);

plan tests => repeat_each() * 12;

#no_diff();
no_long_string();
run_tests();

__DATA__

=== TEST 1: flush wait - content
--- stream_server_config
    content_by_lua_block {
        njt.say("hello, world")
        local ok, err = njt.flush(true)
        if not ok then
            njt.log(njt.ERR, "flush failed: ", err)
            return
        end
        njt.say("hiya")
    }
--- stream_response
hello, world
hiya
--- no_error_log
[error]
--- error_log
lua reuse free buf memory 13 >= 5



=== TEST 2: flush no wait - content
--- stream_server_config
    lua_socket_send_timeout 500ms;
    content_by_lua_block {
        njt.say("hello, world")
        local ok, err = njt.flush(false)
        if not ok then
            njt.log(njt.ERR, "flush failed: ", err)
            return
        end
        njt.say("hiya")
    }
--- stream_response
hello, world
hiya



=== TEST 3: flush wait - big data
--- stream_server_config
    content_by_lua_block {
        njt.say(string.rep("a", 1024 * 64))
        njt.flush(true)
        njt.say("hiya")
    }
--- stream_response
hello, world
hiya
--- SKIP



=== TEST 4: flush wait in a user coroutine
--- stream_server_config
    content_by_lua_block {
        function f()
            njt.say("hello, world")
            njt.flush(true)
            coroutine.yield()
            njt.say("hiya")
        end
        local c = coroutine.create(f)
        njt.say(coroutine.resume(c))
        njt.say(coroutine.resume(c))
    }
--- stap2
F(njt_http_lua_wev_handler) {
    printf("wev handler: wev:%d\n", $r->connection->write->ready)
}

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
F(njt_http_lua_run_thread) {
    id = gen_id($ctx->cur_co)
    printf("run thread %d\n", id)
}

probe process("/usr/local/openresty-debug/luajit/lib/libluajit-5.1.so.2").function("lua_resume") {
    id = gen_id($L)
    printf("lua resume %d\n", id)
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

/*
F(njt_http_lua_coroutine_yield) {
    printf("yield %x\n", gen_id($L))
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

F(njt_http_writer) { println("http writer") }

--- stream_response
hello, world
true
hiya
true
--- error_log
lua reuse free buf memory 13 >= 5



=== TEST 5: flush before sending out the header
--- stream_server_config
    content_by_lua_block {
        njt.flush()
        njt.status = 404
        njt.say("not found")
    }
--- stream_response
not found
--- no_error_log
[error]



=== TEST 6: limit_rate
TODO
--- SKIP
--- stream_server_config
        limit_rate 150;
    content_by_lua_block {
        local begin = njt.now()
        for i = 1, 2 do
            njt.print(string.rep("a", 100))
            local ok, err = njt.flush(true)
            if not ok then
                njt.log(njt.ERR, "failed to flush: ", err)
            end
        end
        local elapsed = njt.now() - begin
        njt.log(njt.WARN, "lua writes elapsed ", elapsed, " sec")
    }
--- stream_response eval
"a" x 200
--- error_log eval
[
qr/lua writes elapsed [12](?:\.\d+)? sec/,
qr/lua flush requires waiting: buffered 0x[0-9a-f]+, delayed:1/,
]

--- no_error_log
[error]
--- timeout: 4
