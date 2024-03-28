# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua;

#worker_connections(1014);
#master_process_enabled(1);
log_level('warn');

repeat_each(1);

plan tests => repeat_each() * (blocks() * 2);

#no_diff();
no_long_string();
run_tests();

__DATA__

=== TEST 1: use njt.localtime in content_by_lua
--- config
    location = /now {
        content_by_lua 'njt.say(njt.localtime())';
    }
--- request
GET /now
--- response_body_like: ^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$



=== TEST 2: use njt.localtime in set_by_lua
--- config
    location = /now {
        set_by_lua $a 'return njt.localtime()';
        echo $a;
    }
--- request
GET /now
--- response_body_like: ^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$



=== TEST 3: use njt.time in set_by_lua
--- config
    location = /time {
        set_by_lua $a 'return njt.time()';
        echo $a;
    }
--- request
GET /time
--- response_body_like: ^\d{10,}$



=== TEST 4: use njt.time in content_by_lua
--- config
    location = /time {
        content_by_lua 'njt.say(njt.time())';
    }
--- request
GET /time
--- response_body_like: ^\d{10,}$



=== TEST 5: use njt.time in content_by_lua
--- config
    location = /time {
        content_by_lua '
            njt.say(njt.time())
            njt.say(njt.localtime())
            njt.say(njt.utctime())
            njt.say(njt.cookie_time(njt.time()))
        ';
    }
--- request
GET /time
--- response_body_like chomp
^\d{10,}
\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}
\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}
\w+, .*? GMT$



=== TEST 6: use njt.now in set_by_lua
--- config
    location = /time {
        set_by_lua $a 'return njt.now()';
        echo $a;
    }
--- request
GET /time
--- response_body_like: ^\d{10,}(\.\d{1,3})?$



=== TEST 7: use njt.now in content_by_lua
--- config
    location = /time {
        content_by_lua 'njt.say(njt.now())';
    }
--- request
GET /time
--- response_body_like: ^\d{10,}(\.\d{1,3})?$



=== TEST 8: use njt.update_time & njt.now in content_by_lua
--- config
    location = /time {
        content_by_lua '
            njt.update_time()
            njt.say(njt.now())
        ';
    }
--- request
GET /time
--- response_body_like: ^\d{10,}(\.\d{1,3})?$
