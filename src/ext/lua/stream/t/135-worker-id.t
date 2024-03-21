# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;
#worker_connections(1014);
#master_on();
workers(2);
#log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 3);

#no_diff();
#no_long_string();
run_tests();

__DATA__

=== TEST 1: sanity
--- stream_server_config
    content_by_lua_block {
        njt.say("worker id: ", njt.worker.id())
    }
--- stream_response_like chop
^worker id: [0-1]$
--- no_error_log
[error]
--- skip_nginx: 3: <=1.9.0
