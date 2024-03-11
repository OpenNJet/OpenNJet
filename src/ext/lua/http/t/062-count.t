# vim:set ft= ts=4 sw=4 et fdm=marker:
use Test::Nginx::Socket::Lua;

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
--- config
        location = /test {
            content_by_lua '
                local n = 0
                for k, v in pairs(njt) do
                    n = n + 1
                end
                njt.say("njt: ", n)
            ';
        }
--- request
GET /test
--- response_body
njt: 114
--- no_error_log
[error]



=== TEST 2: entries under njt. (set by lua)
--- config
        location = /test {
            set_by_lua $n '
                local n = 0
                for k, v in pairs(njt) do
                    n = n + 1
                end
                return n;
            ';
            echo $n;
        }
--- request
GET /test
--- response_body
114
--- no_error_log
[error]



=== TEST 3: entries under njt. (header filter by lua)
--- config
        location = /test {
            set $n '';

            content_by_lua '
                njt.send_headers()
                njt.say("n = ", njt.var.n)
            ';

            header_filter_by_lua '
                local n = 0
                for k, v in pairs(njt) do
                    n = n + 1
                end

                njt.var.n = n
            ';
        }
--- request
GET /test
--- response_body
n = 114
--- no_error_log
[error]



=== TEST 4: entries under ndk. (content by lua)
--- config
        location = /test {
            content_by_lua '
                local n = 0
                for k, v in pairs(ndk) do
                    n = n + 1
                end
                njt.say("n = ", n)
            ';
        }
--- request
GET /test
--- response_body
n = 1
--- no_error_log
[error]



=== TEST 5: entries under njt.req (content by lua)
--- config
        location = /test {
            content_by_lua '
                local n = 0
                for k, v in pairs(njt.req) do
                    n = n + 1
                end
                njt.say("n = ", n)
            ';
        }
--- request
GET /test
--- response_body
n = 23
--- no_error_log
[error]



=== TEST 6: entries under njt.req (set by lua)
--- config
        location = /test {
            set_by_lua $n '
                local n = 0
                for k, v in pairs(njt.req) do
                    n = n + 1
                end
                return n
            ';

            echo "n = $n";
        }
--- request
GET /test
--- response_body
n = 23
--- no_error_log
[error]



=== TEST 7: entries under njt.req (header filter by lua)
--- config
        location = /test {
            set $n '';

            header_filter_by_lua '
                local n = 0
                for k, v in pairs(njt.req) do
                    n = n + 1
                end
                njt.var.n = n
            ';

            content_by_lua '
                njt.send_headers()
                njt.say("n = ", njt.var.n)
            ';
        }
--- request
GET /test
--- response_body
n = 23
--- no_error_log
[error]



=== TEST 8: entries under njt.location
--- config
        location = /test {
            content_by_lua '
                local n = 0
                for k, v in pairs(njt.location) do
                    n = n + 1
                end
                njt.say("n = ", n)
            ';
        }
--- request
GET /test
--- response_body
n = 2
--- no_error_log
[error]



=== TEST 9: entries under njt.socket
--- config
        location = /test {
            content_by_lua '
                local n = 0
                for k, v in pairs(njt.socket) do
                    n = n + 1
                end
                njt.say("n = ", n)
            ';
        }
--- request
GET /test
--- response_body
n = 4
--- no_error_log
[error]



=== TEST 10: entries under njt._tcp_meta
--- SKIP
--- config
        location = /test {
            content_by_lua '
                local n = 0
                for k, v in pairs(njt._tcp_meta) do
                    n = n + 1
                end
                njt.say("n = ", n)
            ';
        }
--- request
GET /test
--- response_body
n = 10
--- no_error_log
[error]



=== TEST 11: entries under the metatable of req sockets
--- config
        location = /test {
            content_by_lua '
                local n = 0
                local sock, err = njt.req.socket()
                if not sock then
                    njt.say("failed to get the request socket: ", err)
                end

                for k, v in pairs(getmetatable(sock)) do
                    n = n + 1
                end
                njt.say("n = ", n)
            ';
        }
--- request
POST /test
hello world
--- response_body
n = 6
--- no_error_log
[error]



=== TEST 12: shdict metatable
--- http_config
    lua_shared_dict dogs 1m;
--- config
    location = /test {
        content_by_lua '
            local dogs = njt.shared.dogs
            local mt = dogs.__index
            local n = 0
            for k, v in pairs(mt) do
                n = n + 1
            end
            njt.say("n = ", n)
        ';
    }
--- request
GET /test
--- response_body
n = 22
--- no_error_log
[error]



=== TEST 13: entries under njt. (log by lua)
--- config
    location = /t {
        log_by_lua '
            local n = 0
            for k, v in pairs(njt) do
                n = n + 1
            end
            njt.log(njt.ERR, "njt. entry count: ", n)
        ';
    }
--- request
GET /t
--- response_body_like: 404 Not Found
--- error_code: 404
--- error_log
njt. entry count: 114



=== TEST 14: entries under njt.timer
--- config
        location = /test {
            content_by_lua '
                local n = 0
                for k, v in pairs(njt.timer) do
                    n = n + 1
                end
                njt.say("n = ", n)
            ';
        }
--- request
GET /test
--- response_body
n = 4
--- no_error_log
[error]



=== TEST 15: entries under njt.config
--- config
        location = /test {
            content_by_lua '
                local n = 0
                for k, v in pairs(njt.config) do
                    n = n + 1
                end
                njt.say("n = ", n)
            ';
        }
--- request
GET /test
--- response_body
n = 6
--- no_error_log
[error]



=== TEST 16: entries under njt.re
--- config
        location = /test {
            content_by_lua '
                local n = 0
                for k, v in pairs(njt.re) do
                    n = n + 1
                end
                njt.say("n = ", n)
            ';
        }
--- request
GET /test
--- response_body
n = 5
--- no_error_log
[error]



=== TEST 17: entries under coroutine. (content by lua)
--- config
        location = /test {
            content_by_lua '
                local n = 0
                for k, v in pairs(coroutine) do
                    n = n + 1
                end
                njt.say("coroutine: ", n)
            ';
        }
--- request
GET /test
--- stap2
global c
probe process("$LIBLUA_PATH").function("rehashtab") {
    c++
    printf("rehash: %d\n", c)
}
--- stap_out2
3
--- response_body
coroutine: 16
--- no_error_log
[error]



=== TEST 18: entries under njt.thread. (content by lua)
--- config
        location = /test {
            content_by_lua '
                local n = 0
                for k, v in pairs(njt.thread) do
                    n = n + 1
                end
                njt.say("thread: ", n)
            ';
        }
--- request
GET /test
--- stap2
global c
probe process("$LIBLUA_PATH").function("rehashtab") {
    c++
    printf("rehash: %d\n", c)
}
--- stap_out2
--- response_body
thread: 3
--- no_error_log
[error]



=== TEST 19: entries under njt.worker
--- config
        location = /test {
            content_by_lua '
                local n = 0
                for k, v in pairs(njt.worker) do
                    n = n + 1
                end
                njt.say("worker: ", n)
            ';
        }
--- request
GET /test
--- response_body
worker: 4
--- no_error_log
[error]



=== TEST 20: entries under the metatable of tcp sockets
--- config
        location = /test {
            content_by_lua_block {
                local n = 0
                local sock = njt.socket.tcp()
                for k, v in pairs(getmetatable(sock)) do
                    n = n + 1
                end
                njt.say("n = ", n)
            }
        }
--- request
GET /test
--- response_body
n = 14
--- no_error_log
[error]



=== TEST 21: entries under the metatable of udp sockets
--- config
        location = /test {
            content_by_lua '
                local n = 0
                local sock = njt.socket.udp()
                for k, v in pairs(getmetatable(sock)) do
                    n = n + 1
                end
                njt.say("n = ", n)
            ';
        }
--- request
GET /test
--- response_body
n = 6
--- no_error_log
[error]



=== TEST 22: entries under the metatable of req raw sockets
--- config
        location = /test {
            content_by_lua '
                local n = 0
                njt.req.read_body()
                local sock, err = njt.req.socket(true)
                if not sock then
                    njt.log(njt.ERR, "server: failed to get raw req socket: ", err)
                    return
                end

                for k, v in pairs(getmetatable(sock)) do
                    n = n + 1
                end

                local ok, err = sock:send("HTTP/1.1 200 OK\\r\\nContent-Length: 6\\r\\n\\r\\nn = "..n.."\\n")
                if not ok then
                    njt.log(njt.ERR, "failed to send: ", err)
                    return
                end
            ';
        }
--- request
GET /test
--- response_body
n = 7
--- no_error_log
[error]



=== TEST 23: entries under the req raw sockets
--- config
        location = /test {
            content_by_lua_block {
                local narr = 0
                local nrec = 0
                njt.req.read_body()
                local sock, err = njt.req.socket(true)
                if not sock then
                    njt.log(njt.ERR, "server: failed to get raw req socket: ", err)
                    return
                end
                sock:settimeouts(1000, 2000, 3000)
                for k, v in ipairs(sock) do
                    narr = narr + 1
                end
                for k, v in pairs(sock) do
                    nrec = nrec + 1
                end
                -- include '__index'
                nrec = nrec - narr + 1

                local ok, err = sock:send("HTTP/1.1 200 OK\r\n\r\nnarr = "..narr.."\nnrec = "..nrec.."\n")
                if not ok then
                    njt.log(njt.ERR, "failed to send: ", err)
                    return
                end
            }
        }
--- request
GET /test
--- response_body
narr = 2
nrec = 3
--- no_error_log
[error]



=== TEST 24: entries under the req sockets
--- config
        location = /test {
            content_by_lua_block {
                local narr = 0
                local nrec = 0
                local sock, err = njt.req.socket()
                if not sock then
                    njt.log(njt.ERR, "server: failed to get req socket: ", err)
                    return
                end
                sock:settimeouts(1000, 2000, 3000)
                for k, v in ipairs(sock) do
                    narr = narr + 1
                end
                for k, v in pairs(sock) do
                    nrec = nrec + 1
                end
                -- include '__index'
                nrec = nrec - narr + 1

                njt.say("narr = "..narr.."\nnrec = "..nrec)
            }
        }
--- request
POST /test
hello world
--- response_body
narr = 2
nrec = 3
--- no_error_log
[error]
