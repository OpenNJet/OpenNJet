# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;
#worker_connections(1014);
#master_on();
#workers(2);
#log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 3);

#no_diff();
no_long_string();
run_tests();

__DATA__

=== TEST 1: content_by_lua + njt.worker.exiting
--- stream_server_config
    content_by_lua_block {
        njt.say("worker exiting: ", njt.worker.exiting())
    }
--- stream_response
worker exiting: false
--- no_error_log
[error]



=== TEST 2: content_by_lua + njt.worker.pid
TODO
--- SKIP
--- stream_server_config
    content_by_lua_block {
        local pid = njt.worker.pid()
        njt.say("worker pid: ", pid)
        if pid ~= tonumber(njt.var.pid) then
            njt.say("worker pid is wrong.")
        else
            njt.say("worker pid is correct.")
        end
    }
--- stream_response_like
worker pid: \d+
worker pid is correct\.
--- no_error_log
[error]



=== TEST 3: content_by_lua + njt.worker.pid
--- stream_server_config
    content_by_lua_block {
        local pid = njt.worker.pid()
        njt.say("worker pid: ", pid)
    }
--- stream_response_like
^worker pid: \d+
--- no_error_log
[error]



=== TEST 4: init_worker_by_lua + njt.worker.pid
TODO
--- SKIP
--- stream_config
    init_worker_by_lua_block {
        my_pid = njt.worker.pid()
    }
--- stream_server_config
    content_by_lua_block {
        njt.say("worker pid: ", my_pid)
        if my_pid ~= tonumber(njt.var.pid) then
            njt.say("worker pid is wrong.")
        else
            njt.say("worker pid is correct.")
        end
    }
--- stream_response_like
worker pid: \d+
worker pid is correct\.
--- no_error_log
[error]



=== TEST 5: init_worker_by_lua + njt.worker.pid
--- stream_config
    init_worker_by_lua_block {
        my_pid = njt.worker.pid()
    }
--- stream_server_config
    content_by_lua_block {
        njt.say("worker pid: ", my_pid)
    }
--- stream_response_like
worker pid: \d+
--- no_error_log
[error]
