# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua;

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
--- config
    location /lua {
        content_by_lua '
            njt.say("worker exiting: ", njt.worker.exiting())
        ';
    }
--- request
GET /lua
--- response_body
worker exiting: false
--- no_error_log
[error]



=== TEST 2: content_by_lua + njt.worker.pid
--- config
    location /lua {
        content_by_lua '
            local pid = njt.worker.pid()
            njt.say("worker pid: ", pid)
            if pid ~= tonumber(njt.var.pid) then
                njt.say("worker pid is wrong.")
            else
                njt.say("worker pid is correct.")
            end
        ';
    }
--- request
GET /lua
--- response_body_like
worker pid: \d+
worker pid is correct\.
--- no_error_log
[error]



=== TEST 3: init_worker_by_lua + njt.worker.pid
--- http_config
    init_worker_by_lua '
        my_pid = njt.worker.pid()
    ';
--- config
    location /lua {
        content_by_lua '
            njt.say("worker pid: ", my_pid)
            if my_pid ~= tonumber(njt.var.pid) then
                njt.say("worker pid is wrong.")
            else
                njt.say("worker pid is correct.")
            end
        ';
    }
--- request
GET /lua
--- response_body_like
worker pid: \d+
worker pid is correct\.
--- no_error_log
[error]
