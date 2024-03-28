# vim:set ft= ts=4 sw=4 et fdm=marker:
use Test::Nginx::Socket::Lua;

#worker_connections(1014);
#master_on();
#workers(2);
#log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 7 + 2);

#no_diff();
no_long_string();

our $HtmlDir = html_dir;

$ENV{TEST_NGINX_MEMCACHED_PORT} ||= 11211;
$ENV{TEST_NGINX_HTML_DIR} = $HtmlDir;

worker_connections(1024);
run_tests();

__DATA__

=== TEST 1: simple very
--- config
    location /t {
        content_by_lua_block {
            local begin = njt.now()
            local function f(premature)
                print("elapsed: ", njt.now() - begin)
                print("timer prematurely expired: ", premature)
            end

            local ok, err = njt.timer.every(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end

            njt.say("registered timer")
        }
    }
--- request
GET /t
--- response_body
registered timer
--- wait: 0.11
--- no_error_log
[error]
[alert]
[crit]
timer prematurely expired: true
--- error_log eval
[
qr/\[lua\] content_by_lua\(nginx\.conf:\d+\):\d+: elapsed: 0\.0(?:4[4-9]|5[0-6])\d*, context: njt\.timer, client: \d+\.\d+\.\d+\.\d+, server: 0\.0\.0\.0:\d+/,
qr/\[lua\] content_by_lua\(nginx\.conf:\d+\):\d+: elapsed: 0\.(?:09|10)\d*, context: njt\.timer, client: \d+\.\d+\.\d+\.\d+, server: 0\.0\.0\.0:\d+/,
"lua njt.timer expired",
"http lua close fake http connection",
"timer prematurely expired: false",
]



=== TEST 2: shared global env
--- config
    location /t {
        content_by_lua_block {
            local begin = njt.now()
            local function f()
                foo = 3
                print("foo in timer: ", foo)
            end
            local ok, err = njt.timer.every(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.sleep(0.11)
            njt.say("foo = ", foo)
        }
    }
--- request
GET /t
--- response_body
foo = 3
--- wait: 0.12
--- no_error_log
[error]
[alert]
[crit]
--- error_log eval
[
qr/\[lua\] content_by_lua\(nginx\.conf:\d+\):\d+: foo in timer: 3/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 3: lua variable sharing via upvalue
--- config
    location /t {
        content_by_lua_block {
            local begin = njt.now()
            local foo = 0
            local function f()
                foo = foo + 3
                print("foo in timer: ", foo)
            end
            local ok, err = njt.timer.every(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
            njt.sleep(0.11)
            njt.say("foo = ", foo)
        }
    }
--- request
GET /t
--- response_body
registered timer
foo = 6
--- wait: 0.12
--- no_error_log
[error]
[alert]
[crit]
--- error_log eval
[
qr/\[lua\] content_by_lua\(nginx\.conf:\d+\):\d+: foo in timer: 3/,
qr/\[lua\] content_by_lua\(nginx\.conf:\d+\):\d+: foo in timer: 6/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 4: create the next timer immediately when timer start running
--- config
    location /t {
        content_by_lua_block {
            local begin = njt.now()
            local foo = 0
            local function f()
                foo = foo + 3
                print("foo in timer: ", foo)

                njt.sleep(0.1)
            end
            local ok, err = njt.timer.every(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
            njt.sleep(0.11)
            njt.say("foo = ", foo)
        }
    }
--- request
GET /t
--- response_body
registered timer
foo = 6
--- wait: 0.12
--- no_error_log
[error]
[alert]
[crit]
--- error_log eval
[
qr/\[lua\] content_by_lua\(nginx\.conf:\d+\):\d+: foo in timer: 3/,
qr/\[lua\] content_by_lua\(nginx\.conf:\d+\):\d+: foo in timer: 6/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 5: callback args
--- config
    location /t {
        content_by_lua_block {
            local n = 0

            local function f(premature, a, b, c)
                n = n + 1
                print("the ", n, " time, args: ", a, ", ", b, ", ", c)

                a, b, c = 0, 0, 0
            end

            local ok, err = njt.timer.every(0.05, f, 1, 2)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end

            njt.say("registered timer")
            njt.sleep(0.11)
        }
    }
--- request
GET /t
--- response_body
registered timer
--- wait: 0.12
--- no_error_log
[error]
[alert]
[crit]
--- error_log eval
[
"the 1 time, args: 1, 2, nil",
"the 2 time, args: 1, 2, nil",
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 6: memory leak check
--- config
    location /t {
        content_by_lua_block {
            local function f()
                local a = 1
                -- do nothing
            end

            for i = 1, 100 do
                local ok, err = njt.timer.every(0.1, f)
                if not ok then
                    njt.say("failed to set timer: ", err)
                    return
                end
            end

            njt.say("registered timer")

            collectgarbage("collect")
            local start = collectgarbage("count")

            njt.sleep(0.21)

            collectgarbage("collect")
            local growth1 = collectgarbage("count") - start

            njt.sleep(0.51)

            collectgarbage("collect")
            local growth2 = collectgarbage("count") - start

            njt.say("growth1 == growth2: ", growth1 == growth2)
        }
    }
--- request
GET /t
--- response_body
registered timer
growth1 == growth2: true
--- no_error_log
[error]
[alert]
[crit]
--- timeout: 8



=== TEST 7: respect lua_max_pending_timers
--- http_config
    lua_max_pending_timers 10;
--- config
    location /t {
        content_by_lua_block {
            local function f()
                local a = 1
                -- do nothing
            end

            for i = 1, 11 do
                local ok, err = njt.timer.every(0.1, f)
                if not ok then
                    njt.say("failed to set timer: ", err)
                    return
                end
            end

            njt.say("registered 10 timers")
        }
    }
--- request
GET /t
--- response_body
failed to set timer: too many pending timers
--- no_error_log
[error]
[alert]
[crit]



=== TEST 8: respect lua_max_running_timers
--- http_config
    lua_max_pending_timers 100;
    lua_max_running_timers 9;
--- config
    location /t {
        content_by_lua_block {
            local function f()
                local a = 1
                njt.sleep(0.02)
                -- do nothing
            end

            for i = 1, 10 do
                local ok, err = njt.timer.every(0.01, f)
                if not ok then
                    njt.say("failed to set timer: ", err)
                    return
                end
            end

            njt.say("registered 10 timers")

            njt.sleep(0.03)
        }
    }
--- request
GET /t
--- response_body
registered 10 timers
--- no_error_log
[error]
[crit]
--- error_log
lua_max_running_timers are not enough



=== TEST 9: lua_code_cache off
FIXME: it is know that this test case leaks memory.
so we skip it in the "check leak" testing mode.
--- http_config
    lua_code_cache off;
--- config
    location /t {
        content_by_lua_block {
            local function f()
                local a = 1
                -- do nothing
            end

            local ok, err = njt.timer.every(0.01, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end

            collectgarbage("collect")
            njt.say("registered timer")

            njt.sleep(0.03)

            collectgarbage("collect")

            njt.sleep(0.03)

            collectgarbage("collect")
            njt.say("ok")
        }
    }
--- request
GET /t
--- response_body
registered timer
ok
--- no_error_log
[error]
[crit]
--- no_check_leak
