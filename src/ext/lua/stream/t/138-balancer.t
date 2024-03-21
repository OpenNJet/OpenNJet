# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;
#worker_connections(1014);
#master_on();
#workers(2);
#log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 3 + 10);

#no_diff();
no_long_string();
run_tests();

__DATA__

=== TEST 1: simple logging
--- stream_config
    upstream backend {
        server 0.0.0.1:1234;
        balancer_by_lua_block {
            print("hello from balancer by lua!")
        }
    }
--- stream_server_config
        proxy_pass backend;
--- error_log eval
[
'[lua] balancer_by_lua:2: hello from balancer by lua! while connecting to upstream,',
qr{\[crit\] .*? connect\(\) to 0\.0\.0\.1:1234 failed .*?, upstream: "0\.0\.0\.1:1234"},
]
--- no_error_log
[warn]



=== TEST 2: exit 403
--- stream_config
    upstream backend {
        server 0.0.0.1:1234;
        balancer_by_lua_block {
            print("hello from balancer by lua!")
            njt.exit(403)
        }
    }
--- stream_server_config
        proxy_pass backend;
--- error_log
[lua] balancer_by_lua:2: hello from balancer by lua! while connecting to upstream,
lua exit with code 403
proxy connect: 403
finalize stream proxy: 403
finalize stream session: 403
--- no_error_log eval
[
'[warn]',
qr{\[crit\] .*? connect\(\) to 0\.0\.0\.1:1234 failed .*?, upstream: "0\.0\.0\.1:1234"},
]



=== TEST 3: exit OK
--- stream_config
    upstream backend {
        server 0.0.0.1:1234;
        balancer_by_lua_block {
            print("hello from balancer by lua!")
            njt.exit(njt.OK)
        }
    }
--- stream_server_config
        proxy_pass backend;
--- error_log eval
[
'[lua] balancer_by_lua:2: hello from balancer by lua! while connecting to upstream,',
qr{\[crit\] .*? connect\(\) to 0\.0\.0\.1:1234 failed .*?, upstream: "0\.0\.0\.1:1234"},
]
--- no_error_log
[warn]



=== TEST 4: njt.var works
--- stream_config
    upstream backend {
        server 0.0.0.1:1234;
        balancer_by_lua_block {
            print("1: variable remote_addr = ", njt.var.remote_addr)
        }
    }
--- stream_server_config
        proxy_pass backend;
--- error_log eval
[
"1: variable remote_addr = 127.0.0.1",
qr/\[crit\] .* connect\(\) .*? failed/,
]
--- no_error_log
[warn]



=== TEST 5: simple logging (by_lua_file)
--- stream_config
    upstream backend {
        server 0.0.0.1:1234;
        balancer_by_lua_file html/a.lua;
    }
--- stream_server_config
        proxy_pass backend;
--- user_files
>>> a.lua
print("hello from balancer by lua!")
--- error_log eval
[
'[lua] a.lua:1: hello from balancer by lua! while connecting to upstream,',
qr{\[crit\] .*? connect\(\) to 0\.0\.0\.1:1234 failed .*?, upstream: "0\.0\.0\.1:1234"},
]
--- no_error_log
[warn]



=== TEST 6: cosockets are disabled
--- stream_config
    upstream backend {
        server 0.0.0.1:1234;
        balancer_by_lua_block {
            local sock, err = njt.socket.tcp()
        }
    }
--- stream_server_config
        proxy_pass backend;
--- error_log eval
qr/\[error\] .*? failed to run balancer_by_lua\*: balancer_by_lua:2: API disabled in the context of balancer_by_lua\*/



=== TEST 7: njt.sleep is disabled
--- stream_config
    upstream backend {
        server 0.0.0.1:1234;
        balancer_by_lua_block {
            njt.sleep(0.1)
        }
    }
--- stream_server_config
        proxy_pass backend;
--- error_log eval
qr/\[error\] .*? failed to run balancer_by_lua\*: balancer_by_lua:2: API disabled in the context of balancer_by_lua\*/



=== TEST 8: get_phase
--- stream_config
    upstream backend {
        server 0.0.0.1:1234;
        balancer_by_lua_block {
            print("I am in phase ", njt.get_phase())
        }
    }
--- stream_server_config
        proxy_pass backend;
--- grep_error_log eval: qr/I am in phase \w+/
--- grep_error_log_out
I am in phase balancer
--- error_log eval
qr{\[crit\] .*? connect\(\) to 0\.0\.0\.1:1234 failed .*?, upstream: "0\.0\.0\.1:1234"}
--- no_error_log
[error]



=== TEST 9: njt.log(njt.ERR, ...) github #816
--- stream_config
    upstream backend {
        server 0.0.0.1:1234;
        balancer_by_lua_block {
            njt.log(njt.ERR, "hello from balancer by lua!")
        }
    }
--- stream_server_config
        proxy_pass backend;
--- error_log eval
[
'[lua] balancer_by_lua:2: hello from balancer by lua! while connecting to upstream,',
qr{\[crit\] .*? connect\(\) to 0\.0\.0\.1:1234 failed .*?, upstream: "0\.0\.0\.1:1234"},
]
--- no_error_log
[warn]



=== TEST 10: test if execeed proxy_next_upstream_limit
--- stream_config
    lua_package_path "../lua-resty-core/lib/?.lua;;";

    proxy_next_upstream_tries 5;
    upstream backend {
        server 0.0.0.1:1234;
        balancer_by_lua_block {
            local b = require "njt.balancer"

            if not njt.ctx.tries then
                njt.ctx.tries = 0
            end

            if njt.ctx.tries >= 6 then
                njt.log(njt.ERR, "retry count exceed limit")
                njt.exit(500)
            end

            njt.ctx.tries = njt.ctx.tries + 1
            print("retry counter: ", njt.ctx.tries)

            local ok, err = b.set_more_tries(2)
            if not ok then
                return error("failed to set more tries: ", err)
            elseif err then
                njt.log(njt.WARN, "set more tries: ", err)
            end

            assert(b.set_current_peer("127.0.0.1", 81))
        }
    }
--- stream_server_config
        proxy_pass backend;
--- grep_error_log eval: qr/\bretry counter: \w+/
--- grep_error_log_out
retry counter: 1
retry counter: 2
retry counter: 3
retry counter: 4
retry counter: 5

--- error_log
set more tries: reduced tries due to limit



=== TEST 11: set_more_tries bugfix
--- stream_config
    lua_package_path "../lua-resty-core/lib/?.lua;;";
	proxy_next_upstream_tries 0;
    upstream backend {
        server 0.0.0.1:1234;
        balancer_by_lua_block {
            local balancer = require "njt.balancer"
			local ctx = njt.ctx
			if not ctx.has_run then
				ctx.has_run = true
				local _, err = balancer.set_more_tries(3)
				if err then
					njt.log(njt.ERR, "failed to set more tries: ", err)
				end
			end
			balancer.set_current_peer("127.0.0.1", 81)
        }
    }
--- stream_server_config
        proxy_pass backend;
--- grep_error_log: stream proxy next upstream
--- grep_error_log_out
stream proxy next upstream
stream proxy next upstream
stream proxy next upstream
stream proxy next upstream
--- no_error_log
failed to set more tries: reduced tries due to limit
[alert]
