# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;

#worker_connections(1014);
#master_process_enabled(1);
log_level('warn');

repeat_each(1);

plan tests => repeat_each() * (blocks() * 3);

#no_diff();
no_long_string();
run_tests();

__DATA__

=== TEST 1: use njt.localtime in content_by_lua
--- stream_server_config
    content_by_lua_block { njt.say(njt.localtime()) }
--- stream_response_like: ^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$
--- no_error_log
[error]



=== TEST 2: use njt.time in content_by_lua
--- stream_server_config
    content_by_lua_block { njt.say(njt.time()) }
--- stream_response_like: ^\d{10,}$
--- no_error_log
[error]



=== TEST 3: use njt.time in content_by_lua
--- stream_server_config
    content_by_lua_block {
        njt.say(njt.time())
        njt.say(njt.localtime())
        njt.say(njt.utctime())
    }
--- stream_response_like chomp
^\d{10,}
\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}
\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}
--- no_error_log
[error]



=== TEST 4: use njt.now in content_by_lua
--- stream_server_config
    content_by_lua_block { njt.say(njt.now()) }
--- stream_response_like: ^\d{10,}(\.\d{1,3})?$
--- no_error_log
[error]



=== TEST 5: use njt.update_time & njt.now in content_by_lua
--- stream_server_config
    content_by_lua_block {
        njt.update_time()
        njt.say(njt.now())
    }
--- stream_response_like: ^\d{10,}(\.\d{1,3})?$
--- no_error_log
[error]
