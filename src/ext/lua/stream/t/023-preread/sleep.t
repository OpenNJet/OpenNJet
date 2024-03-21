# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;
#worker_connections(1014);
#master_on();
#workers(2);
log_level('debug');

repeat_each(2);

plan tests => repeat_each() * 21;

#no_diff();
#no_long_string();
run_tests();

__DATA__

=== TEST 1: sleep 0.5
--- stream_server_config
    preread_by_lua_block {
            njt.update_time()
            local before = njt.now()
            njt.sleep(0.5)
            local now = njt.now()
            njt.say(now - before)
            njt.exit(200)
    }

    return here;
--- stream_response_like chop
^0\.(?:4[5-9]\d*|5[0-9]\d*|5)$
--- error_log
lua ready to sleep for
stream lua sleep timer expired



=== TEST 2: sleep ag
--- stream_server_config
    preread_by_lua_block {
            njt.update_time()
            local before = njt.now()
            njt.sleep("a")
            local now = njt.now()
            njt.say(now - before)
            njt.exit(200)
    }

    return here;
--- error_log
bad argument #1 to 'sleep'



=== TEST 3: sleep 0.5 - multi-times
--- stream_server_config
    preread_by_lua_block {
        njt.update_time()
        local start = njt.now()
        njt.sleep(0.3)
        njt.sleep(0.3)
        njt.sleep(0.3)
        njt.say(njt.now() - start)
        njt.exit(200)
    }

    return here;
--- stream_response_like chop
^0\.(?:8[5-9]\d*|9[0-9]\d*|9)$
--- error_log
lua ready to sleep for
stream lua sleep timer expired
--- no_error_log
[error]



=== TEST 4: sleep 0.5 - interleaved by njt.say() - ended by njt.sleep
--- stream_server_config
    preread_by_lua_block {
        njt.sleep(1)
        njt.say("blah")
        njt.sleep(1)
        njt.exit(200)
    }

    return here;
--- stream_response
blah
--- error_log
lua ready to sleep
stream lua sleep timer expired
--- no_error_log
[error]



=== TEST 5: sleep 0.5 - interleaved by njt.say() - not ended by njt.sleep
--- stream_server_config
    preread_by_lua_block {
        njt.sleep(0.3)
        njt.say("blah")
        njt.sleep(0.5)
        njt.say("hiya")
        njt.exit(200)
    }

    return here;
--- stream_response
blah
hiya
--- error_log
lua ready to sleep for
stream lua sleep timer expired
--- no_error_log
[error]
