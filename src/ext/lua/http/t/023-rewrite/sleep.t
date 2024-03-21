# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua;

#worker_connections(1014);
#master_on();
#workers(2);
log_level('debug');

repeat_each(2);

plan tests => repeat_each() * 33;

#no_diff();
#no_long_string();
run_tests();

__DATA__

=== TEST 1: sleep 0.5
--- config
    location /test {
        rewrite_by_lua '
            njt.update_time()
            local before = njt.now()
            njt.sleep(0.5)
            local now = njt.now()
            njt.say(now - before)
            njt.exit(200)
        ';
    }
--- request
GET /test
--- response_body_like chop
^0\.(?:4[5-9]\d*|5[0-9]\d*|5)$
--- error_log
lua ready to sleep for
lua sleep timer expired: "/test?"



=== TEST 2: sleep ag
--- config
    location /test {
        rewrite_by_lua '
            njt.update_time()
            local before = njt.now()
            njt.sleep("a")
            local now = njt.now()
            njt.say(now - before)
            njt.exit(200)
        ';
    }
--- request
GET /test
--- error_code: 500
--- response_body_like: 500 Internal Server Error
--- error_log
bad argument #1 to 'sleep'



=== TEST 3: sleep 0.5 in subrequest
--- config
    location /test {
        rewrite_by_lua '
            njt.update_time()
            local before = njt.now()
            njt.location.capture("/sleep")
            local now = njt.now()
            local delay = now - before
            njt.say(delay)
            njt.exit(200)
        ';
    }
    location /sleep {
        rewrite_by_lua 'njt.sleep(0.5) njt.exit(200)';
    }
--- request
GET /test
--- response_body_like chop
^0\.(?:4[5-9]\d*|5[0-9]\d*|5)$
--- error_log
lua ready to sleep for
lua sleep timer expired: "/sleep?"
--- no_error_log
[error]



=== TEST 4: sleep a in subrequest with bad argument
--- config
    location /test {
        rewrite_by_lua '
            local res = njt.location.capture("/sleep");
            njt.say(res.status)
            njt.exit(200)
        ';
    }
    location /sleep {
        rewrite_by_lua 'njt.sleep("a") njt.exit(200)';
    }
--- request
GET /test
--- response_body
500
--- error_log
bad argument #1 to 'sleep'



=== TEST 5: sleep 0.5 - multi-times
--- config
    location /test {
        rewrite_by_lua '
            njt.update_time()
            local start = njt.now()
            njt.sleep(0.3)
            njt.sleep(0.3)
            njt.sleep(0.3)
            njt.say(njt.now() - start)
            njt.exit(200)
        ';
    }
--- request
GET /test
--- response_body_like chop
^0\.(?:8[5-9]\d*|9[0-9]\d*|9)$
--- error_log
lua ready to sleep for
lua sleep timer expired: "/test?"
--- no_error_log
[error]



=== TEST 6: sleep 0.5 - interleaved by njt.say() - ended by njt.sleep
--- config
    location /test {
        rewrite_by_lua '
            njt.send_headers()
            -- njt.location.capture("/sleep")
            njt.sleep(1)
            njt.say("blah")
            njt.sleep(1)
            -- njt.location.capture("/sleep")
            njt.exit(200)
        ';
    }
    location = /sleep {
        echo_sleep 0.1;
    }
--- request
GET /test
--- response_body
blah
--- error_log
lua ready to sleep
lua sleep timer expired: "/test?"
--- no_error_log
[error]



=== TEST 7: sleep 0.5 - interleaved by njt.say() - not ended by njt.sleep
--- config
    location /test {
        rewrite_by_lua '
            njt.send_headers()
            -- njt.location.capture("/sleep")
            njt.sleep(0.3)
            njt.say("blah")
            njt.sleep(0.5)
            -- njt.location.capture("/sleep")
            njt.say("hiya")
            njt.exit(200)
        ';
    }
    location = /sleep {
        echo_sleep 0.1;
    }
--- request
GET /test
--- response_body
blah
hiya
--- error_log
lua ready to sleep for
lua sleep timer expired: "/test?"
--- no_error_log
[error]



=== TEST 8: njt.location.capture before and after njt.sleep
--- config
    location /test {
        rewrite_by_lua '
            local res = njt.location.capture("/sub")
            njt.print(res.body)

            njt.sleep(0.1)

            res = njt.location.capture("/sub")
            njt.print(res.body)
            njt.exit(200)
        ';
    }
    location = /hello {
        echo hello world;
    }
    location = /sub {
        proxy_pass http://127.0.0.1:$server_port/hello;
    }
--- request
GET /test
--- response_body
hello world
hello world
--- no_error_log
[error]
