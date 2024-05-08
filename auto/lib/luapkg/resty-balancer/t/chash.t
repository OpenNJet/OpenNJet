# vim:set ft= ts=4 sw=4 et:

use Test::Nginx::Socket::Lua;
use Cwd qw(cwd);

repeat_each(2);

plan tests => repeat_each() * (3 * blocks());

my $pwd = cwd();

$ENV{TEST_NGINX_CWD} = $pwd;

our $HttpConfig = qq{
    lua_package_path "$pwd/lib/?.lua;;";
    lua_package_cpath "$pwd/?.so;;";
};

no_long_string();
#no_diff();

run_tests();

__DATA__

=== TEST 1: find
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local resty_chash = require "resty.chash"

            local servers = {
                ["server1"] = 10,
                ["server2"] = 2,
                ["server3"] = 1,
            }

            local chash = resty_chash:new(servers)

            local res = {}
            for i = 1, 100 * 1000 do
                local id = chash:find(i)
                if res[id] then
                    res[id] = res[id] + 1
                else
                    res[id] = 1
                end
            end

            for i=1, 3 do
                local id = "server"..i
                njt.say(id..": ", res[id])
            end

            njt.say("points number: ", chash.npoints)
        }
    }
--- request
GET /t
--- response_body
server1: 77075
server2: 14743
server3: 8182
points number: 2080
--- no_error_log
[error]
--- timeout: 30



=== TEST 2: compare with nginx chash
--- http_config
    lua_package_path "$TEST_NGINX_CWD/lib/?.lua;;";
    lua_package_cpath "$TEST_NGINX_CWD/?.so;;";

    server {
        listen          1985;
        listen          1986;
        listen          1987;
        server_name     'localhost';

        location / {
            content_by_lua_block {
                njt.say(njt.var.server_port)
            }
        }
    }

    init_by_lua_block {
        local resty_chash = require "resty.chash"

        local server_list = {
            ["127.0.0.1:1985"] = 2,
            ["127.0.0.1:1986"] = 2,
            ["127.0.0.1:1987"] = 1,
        }

        local str_null = string.char(0)

        local servers, nodes = {}, {}
        for serv, weight in pairs(server_list) do
            local id = string.gsub(serv, ":", str_null)

            servers[id] = serv
            nodes[id] = weight
        end

        local chash_up = resty_chash:new(nodes)

        package.loaded.my_chash_up = chash_up
        package.loaded.my_servers = servers
    }

    upstream backend_lua {
        server 0.0.0.1;
        balancer_by_lua_block {
            print("hello from balancer by lua!")
            local b = require "njt.balancer"

            local chash_up = package.loaded.my_chash_up
            local servers = package.loaded.my_servers

            local id = chash_up:find(njt.var.arg_key)
            local server = servers[id]

            assert(b.set_current_peer(server))
        }
    }

    upstream backend_njt {
        hash $arg_key consistent;

        server 127.0.0.1:1985 weight=2;
        server 127.0.0.1:1986 weight=2;
        server 127.0.0.1:1987 weight=1;
    }
--- config
    location = /lua {
        proxy_pass http://backend_lua;
    }
    location = /njt {
        proxy_next_upstream_tries 0;
        proxy_next_upstream off;

        proxy_pass http://backend_njt;
    }
    location = /main {
        content_by_lua_block {
            math.randomseed(njt.now())
            local start = math.random(1, 1000000)

            -- njt.log(njt.ERR, start)
            for i = start + 1, start + 100 do
                local res1 = njt.location.capture("/lua?key=" .. i)
                local res2 = njt.location.capture("/njt?key=" .. i)

                -- njt.log(njt.ERR, res1.body)
                if res1.body ~= res2.body then
                    njt.log(njt.ERR, "not matched upstream, key:", i)
                end
            end
            njt.say("ok")
        }
    }
--- request
    GET /main
--- response_body
ok
--- error_code: 200
--- no_error_log
[error]
--- timeout: 10



=== TEST 3: next
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local resty_chash = require "resty.chash"

            local servers = {
                ["server1"] = 2,
                ["server2"] = 2,
                ["server3"] = 1,
            }

            local chash = resty_chash:new(servers)

            local id, idx = chash:find("foo")
            njt.say(id, ", ", idx)

            for i = 1, 100 do
                id, idx = chash:next(idx)
            end
            njt.say(id, ", ", idx)
        }
    }
--- request
GET /t
--- response_body
server1, 434
server2, 534
--- no_error_log
[error]
--- timeout: 10



=== TEST 4: up, decr
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local resty_chash = require "resty.chash"

            local servers = {
                ["server1"] = 7,
                ["server2"] = 2,
                ["server3"] = 1,
            }

            local chash = resty_chash:new(servers)

            local num = 100 * 1000

            local res1 = {}
            for i = 1, num do
                local id = chash:find(i)

                res1[i] = id
            end

            chash:incr("server1")

            local res2 = {}
            for i = 1, num do
                local id = chash:find(i)

                res2[i] = id
            end

            local same, diff = 0, 0
            for i = 1, num do
                if res1[i] == res2[i] then
                    same = same + 1
                else
                    diff = diff + 1
                end
            end

            njt.say("same: ", same)
            njt.say("diff: ", diff)

            chash:decr("server3")

            local res3 = {}
            for i = 1, num do
                local id = chash:find(i)

                res3[i] = id
            end

            local same, diff = 0, 0
            for i = 1, num do
                if res3[i] == res2[i] then
                    same = same + 1
                else
                    diff = diff + 1
                end
            end

            njt.say("same: ", same)
            njt.say("diff: ", diff)
        }
    }
--- request
GET /t
--- response_body
same: 97606
diff: 2394
same: 90255
diff: 9745
--- no_error_log
[error]
--- timeout: 30



=== TEST 5: reinit
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local resty_chash = require "resty.chash"

            local servers = {
                ["server1"] = 10,
                ["server2"] = 2,
                ["server3"] = 1,
            }

            local chash = resty_chash:new(servers)

            local success = true
            local count = 0

            for id, weight in pairs(chash.nodes) do
                count = count + 1
                if servers[id] ~= weight then
                    success = false
                end
            end
            njt.say("count: ", count)
            njt.say("success: ",success)

            njt.say("points number: ", chash.npoints)
            njt.say("size: ", chash.size)

            njt.say("reinit")

            local new_servers = {
                ["server4"] = 1,
                ["server5"] = 2,
            }
            chash:reinit(new_servers)

            count = 0
            for id, weight in pairs(chash.nodes) do
                count = count + 1
                if new_servers[id] ~= weight then
                    success = false
                end
            end
            njt.say("count: ", count)
            njt.say("success: ",success)

            njt.say("points number: ", chash.npoints)
            njt.say("size: ", chash.size)
        }
    }
--- request
GET /t
--- response_body
count: 3
success: true
points number: 2080
size: 2080
reinit
count: 2
success: true
points number: 480
size: 480
--- no_error_log
[error]
--- timeout: 30



=== TEST 6: random key fuzzer
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            math.randomseed(njt.now())

            local ffi = require "ffi"
            local resty_chash = require "resty.chash"

            local function random_string()
                local len = math.random(10, 100)
                local buf = ffi.new("char [?]", len)
                for i = 0, len - 1 do
                    buf[i] = math.random(0, 255)
                end

                return ffi.string(buf, len)
            end

            for i = 1, 30 do
                local servers = {}

                local len = math.random(1, 100)
                for j = 1, len do
                    local key = random_string()
                    servers[key] = math.random(1, 100)
                end

                local chash = resty_chash:new(servers)
            end

            njt.say("done")
        }
    }
--- request
GET /t
--- response_body
done
--- no_error_log
[error]
--- timeout: 30
