# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;
#worker_connections(1014);
#master_process_enabled(1);
#log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 2 + 2);

#no_diff();
#no_long_string();
run_tests();

__DATA__

=== TEST 1: get_phase in init_by_lua
--- stream_config
    init_by_lua_block { phase = njt.get_phase() }
--- stream_server_config
    content_by_lua_block {
        njt.say(phase)
    }
--- stream_response
init



=== TEST 2: get_phase in access_by_lua
TODO
--- SKIP
--- stream_server_config
    access_by_lua_block {
        njt.say(njt.get_phase())
        njt.exit(200)
    }
--- stream_response
access



=== TEST 3: get_phase in content_by_lua
--- stream_server_config
    content_by_lua_block {
        njt.say(njt.get_phase())
    }
--- stream_response
content



=== TEST 4: get_phase in log_by_lua_block
TODO
--- SKIP
--- stream_server_config
    echo "OK";
    log_by_lua_block {
        njt.log(njt.ERR, njt.get_phase())
    }
--- error_log
log



=== TEST 5: get_phase in njt.timer callback
--- stream_server_config
    content_by_lua_block {
        local function f()
            njt.log(njt.WARN, "current phase: ", njt.get_phase())
        end
        local ok, err = njt.timer.at(0, f)
        if not ok then
            njt.log(njt.ERR, "failed to add timer: ", err)
        end
    }
--- no_error_log
[error]
--- error_log
current phase: timer



=== TEST 6: get_phase in init_worker_by_lua
--- stream_config
    init_worker_by_lua_block { phase = njt.get_phase() }
--- stream_server_config
    content_by_lua_block {
        njt.say(phase)
    }
--- stream_response
init_worker
--- no_error_log
[error]
