# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua;

#worker_connections(1014);
#master_process_enabled(1);
log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 2 + 1) + 2;

#no_diff();
#no_long_string();
run_tests();

__DATA__

=== TEST 1: get_phase in init_by_lua
--- http_config
    init_by_lua 'phase = njt.get_phase()';
--- config
    location /lua {
        content_by_lua '
            njt.say(phase)
        ';
    }
--- request
GET /lua
--- response_body
init



=== TEST 2: get_phase in set_by_lua
--- config
    set_by_lua $phase 'return njt.get_phase()';
    location /lua {
        content_by_lua '
            njt.say(njt.var.phase)
        ';
    }
--- request
GET /lua
--- response_body
set



=== TEST 3: get_phase in rewrite_by_lua
--- config
    location /lua {
        rewrite_by_lua '
            njt.say(njt.get_phase())
            njt.exit(200)
        ';
    }
--- request
GET /lua
--- response_body
rewrite



=== TEST 4: get_phase in access_by_lua
--- config
    location /lua {
        access_by_lua '
            njt.say(njt.get_phase())
            njt.exit(200)
        ';
    }
--- request
GET /lua
--- response_body
access



=== TEST 5: get_phase in content_by_lua
--- config
    location /lua {
        content_by_lua '
            njt.say(njt.get_phase())
        ';
    }
--- request
GET /lua
--- response_body
content



=== TEST 6: get_phase in header_filter_by_lua
--- config
    location /lua {
        echo "OK";
        header_filter_by_lua '
            njt.header.Phase = njt.get_phase()
        ';
    }
--- request
GET /lua
--- response_header
Phase: header_filter



=== TEST 7: get_phase in body_filter_by_lua
--- config
    location /lua {
        content_by_lua '
            njt.exit(200)
        ';
        body_filter_by_lua '
            njt.arg[1] = njt.get_phase()
        ';
    }
--- request
GET /lua
--- response_body chop
body_filter



=== TEST 8: get_phase in log_by_lua
--- config
    location /lua {
        echo "OK";
        log_by_lua '
            njt.log(njt.ERR, njt.get_phase())
        ';
    }
--- request
GET /lua
--- error_log
log



=== TEST 9: get_phase in njt.timer callback
--- config
    location /lua {
        echo "OK";
        log_by_lua '
            local function f()
                njt.log(njt.WARN, "current phase: ", njt.get_phase())
            end
            local ok, err = njt.timer.at(0, f)
            if not ok then
                njt.log(njt.ERR, "failed to add timer: ", err)
            end
        ';
    }
--- request
GET /lua
--- no_error_log
[error]
--- error_log
current phase: timer



=== TEST 10: get_phase in init_worker_by_lua
--- http_config
    init_worker_by_lua 'phase = njt.get_phase()';
--- config
    location /lua {
        content_by_lua '
            njt.say(phase)
        ';
    }
--- request
GET /lua
--- response_body
init_worker
--- no_error_log
[error]



=== TEST 11: get_phase in exit_worker_by_lua
--- http_config
    exit_worker_by_lua_block {
        local phase = njt.get_phase()
        njt.log(njt.ERR, phase)
        njt.log(njt.ERR, "exiting now")
    }
--- config
    location /lua {
        content_by_lua_block {
            njt.say("ok")
        }
    }
--- request
GET /lua
--- response_body
ok
--- shutdown_error_log eval
[
qr/exit_worker_by_lua:\d+: exit_worker/,
qr/exiting now$/,
]
