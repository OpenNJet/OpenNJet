# vim:set ft= ts=4 sw=4 et fdm=marker:
use Test::Nginx::Socket::Lua::Stream;

#worker_connections(1014);
#master_on();
#workers(4);
#log_level('warn');
no_root_location();

#repeat_each(2);

plan tests => repeat_each() * (blocks() * 3);

our $HtmlDir = html_dir;

#$ENV{LUA_CPATH} = "/usr/local/openresty/lualib/?.so;" . $ENV{LUA_CPATH};

no_long_string();
run_tests();

__DATA__

=== TEST 1: entries under njt. (content by lua)
--- stream_server_config
    content_by_lua_block {
        local n = 0
        for k, v in pairs(njt) do
            n = n + 1
        end
        njt.say("njt: ", n)
    }
--- stream_response
njt: 53
--- no_error_log
[error]



=== TEST 2: entries under njt.req (content by lua)
--- stream_server_config
    content_by_lua_block {
        local n = 0
        for k, v in pairs(njt.req) do
            n = n + 1
        end
        -- njt.req.socket
        -- njt.req.start_time
        njt.say("n = ", n)
    }
--- stream_response
n = 2
--- no_error_log
[error]



=== TEST 3: entries under njt.socket
--- stream_server_config
    content_by_lua_block {
        local n = 0
        for k, v in pairs(njt.socket) do
            n = n + 1
        end
        njt.say("n = ", n)
    }
--- stream_response
n = 4
--- no_error_log
[error]



=== TEST 4: entries under njt._tcp_meta
--- SKIP
--- stream_server_config
    content_by_lua_block {
        local n = 0
        for k, v in pairs(njt._tcp_meta) do
            n = n + 1
        end
        njt.say("n = ", n)
    }
--- stream_response
n = 10
--- no_error_log
[error]



=== TEST 5: entries under the metatable of req sockets
--- stream_server_config
    content_by_lua_block {
        local n = 0
        local sock, err = njt.req.socket()
        if not sock then
            njt.say("failed to get the request socket: ", err)
        end

        for k, v in pairs(getmetatable(sock)) do
            print("key: ", k)
            n = n + 1
        end
        assert(njt.say("n = ", n))
    }
--- stream_response
n = 9
--- no_error_log
[error]



=== TEST 6: shdict metatable
--- stream_config
    lua_shared_dict dogs 1m;
--- stream_server_config
    content_by_lua_block {
        local dogs = njt.shared.dogs
        local mt = dogs.__index
        local n = 0
        for k, v in pairs(mt) do
            n = n + 1
        end
        njt.say("n = ", n)
    }
--- stream_response
n = 22
--- no_error_log
[error]



=== TEST 7: entries under njt.timer
--- stream_server_config
    content_by_lua_block {
        local n = 0
        for k, v in pairs(njt.timer) do
            n = n + 1
        end
        njt.say("n = ", n)
    }
--- stream_response
n = 4
--- no_error_log
[error]



=== TEST 8: entries under njt.config
--- stream_server_config
    content_by_lua_block {
        local n = 0
        for k, v in pairs(njt.config) do
            n = n + 1
        end
        njt.say("n = ", n)
    }
--- stream_response
n = 6
--- no_error_log
[error]



=== TEST 9: entries under njt.re
--- stream_server_config
    content_by_lua_block {
        local n = 0
        for k, v in pairs(njt.re) do
            n = n + 1
        end
        njt.say("n = ", n)
    }
--- stream_response
n = 5
--- no_error_log
[error]



=== TEST 10: entries under coroutine. (content by lua)
--- stream_server_config
    content_by_lua_block {
        local n = 0
        for k, v in pairs(coroutine) do
            n = n + 1
        end
        njt.say("coroutine: ", n)
    }
--- stap2
global c
probe process("$LIBLUA_PATH").function("rehashtab") {
    c++
    printf("rehash: %d\n", c)
}
--- stap_out2
3
--- stream_response
coroutine: 16
--- no_error_log
[error]



=== TEST 11: entries under njt.thread. (content by lua)
--- stream_server_config
    content_by_lua_block {
        local n = 0
        for k, v in pairs(njt.thread) do
            n = n + 1
        end
        njt.say("thread: ", n)
    }
--- stap2
global c
probe process("$LIBLUA_PATH").function("rehashtab") {
    c++
    printf("rehash: %d\n", c)
}
--- stap_out2
--- stream_response
thread: 3
--- no_error_log
[error]



=== TEST 12: entries under njt.worker
--- stream_server_config
    content_by_lua_block {
        local n = 0
        for k, v in pairs(njt.worker) do
            n = n + 1
        end
        njt.say("worker: ", n)
    }
--- stream_response
worker: 4
--- no_error_log
[error]



=== TEST 13: entries under the metatable of tcp sockets
--- stream_server_config
    content_by_lua_block {
        local n = 0
        local sock = njt.socket.tcp()
        for k, v in pairs(getmetatable(sock)) do
            n = n + 1
        end
        njt.say("n = ", n)
    }
--- stream_response
n = 14
--- no_error_log
[error]



=== TEST 14: entries under the metatable of udp sockets
--- stream_server_config
    content_by_lua_block {
        local n = 0
        local sock = njt.socket.udp()
        for k, v in pairs(getmetatable(sock)) do
            n = n + 1
        end
        njt.say("n = ", n)
    }
--- stream_response
n = 6
--- no_error_log
[error]



=== TEST 15: entries under the metatable of req raw sockets
--- stream_server_config
    content_by_lua_block {
        local n = 0
        local sock, err = njt.req.socket(true)
        if not sock then
            njt.log(njt.ERR, "server: failed to get raw req socket: ", err)
            return
        end

        for k, v in pairs(getmetatable(sock)) do
            n = n + 1
        end

        local ok, err = sock:send("n = " .. n .. "\n")
        if not ok then
            njt.log(njt.ERR, "failed to send: ", err)
            return
        end
    }
--- stream_response
n = 9
--- no_error_log
[error]
