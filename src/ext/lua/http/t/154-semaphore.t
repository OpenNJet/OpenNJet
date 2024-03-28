# vim:set ft= ts=4 sw=4 et fdm=marker:
use lib 'lib';
use Test::Nginx::Socket::Lua;

#worker_connections(10140);
#workers(1);
#log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 3) + 1;

no_long_string();
#no_diff();

add_block_preprocessor(sub {
    my $block = shift;

    my $http_config = $block->http_config || '';
    $http_config .= <<'_EOC_';
    lua_package_path "../lua-resty-core/lib/?.lua;../lua-resty-lrucache/lib/?.lua;;";

    init_by_lua_block {
        require "resty.core"
    }
_EOC_
    $block->set_value("http_config", $http_config);
});

run_tests();

__DATA__

=== TEST 1: timer + shutdown error log
--- config
    location /test {
        content_by_lua_block {
            local function test(pre)

                local semaphore = require "njt.semaphore"
                local sem = semaphore.new()

                local function sem_wait()

                    local ok, err = sem:wait(10)
                    if not ok then
                        njt.log(njt.ERR, "err: ", err)
                    else
                        njt.log(njt.ERR, "wait success")
                    end
                end

                while not njt.worker.exiting() do
                    local co = njt.thread.spawn(sem_wait)
                    njt.thread.wait(co)
                end
            end

            local ok, err = njt.timer.at(0, test)
            njt.log(njt.ERR, "hello, world")
            njt.say("time: ", ok)
        }
    }
--- request
GET /test
--- response_body
time: 1
--- grep_error_log eval: qr/hello, world|semaphore gc wait queue is not empty/
--- grep_error_log_out
hello, world
--- shutdown_error_log
--- no_shutdown_error_log
semaphore gc wait queue is not empty



=== TEST 2: timer + shutdown error log (lua code cache off)
FIXME: this test case leaks memory.
--- http_config
    lua_code_cache off;
--- config
    location /test {
        content_by_lua_block {
            local function test(pre)

                local semaphore = require "njt.semaphore"
                local sem = semaphore.new()

                local function sem_wait()

                    local ok, err = sem:wait(10)
                    if not ok then
                        njt.log(njt.ERR, "err: ", err)
                    else
                        njt.log(njt.ERR, "wait success")
                    end
                end

                while not njt.worker.exiting() do
                    local co = njt.thread.spawn(sem_wait)
                    njt.thread.wait(co)
                end
            end

            local ok, err = njt.timer.at(0, test)
            njt.log(njt.ERR, "hello, world")
            njt.say("time: ", ok)
        }
    }
--- request
GET /test
--- response_body
time: 1
--- grep_error_log eval: qr/hello, world|semaphore gc wait queue is not empty/
--- grep_error_log_out
hello, world
--- shutdown_error_log
--- no_shutdown_error_log
semaphore gc wait queue is not empty
--- SKIP



=== TEST 3: exit before post_handler was called
If gc is called before the njt_http_lua_sema_handler and free the sema memory
njt_http_lua_sema_handler would use the freed memory.
--- config
    location /up {
        content_by_lua_block {
            local semaphore = require "njt.semaphore"
            local sem = semaphore.new()

            local function sem_wait()
                njt.log(njt.ERR, "njt.sem wait start")
                local ok, err = sem:wait(10)
                if not ok then
                    njt.log(njt.ERR, "njt.sem wait err: ", err)
                else
                    njt.log(njt.ERR, "njt.sem wait success")
                end
            end
            local co = njt.thread.spawn(sem_wait)
            njt.log(njt.ERR, "njt.sem post start")
            sem:post()
            njt.log(njt.ERR, "njt.sem post end")
            njt.say("hello")
            njt.exit(200)
            njt.say("not reach here")
        }
    }

    location /t {
        content_by_lua_block {
            local res = njt.location.capture("/up")
            collectgarbage()
            njt.print(res.body)
        }
    }

--- request
GET /t
--- response_body
hello
--- grep_error_log eval: qr/(njt.sem .*?,|http close request|semaphore handler: wait queue: empty, resource count: 1|in lua gc, semaphore)/
--- grep_error_log_out
njt.sem wait start,
njt.sem post start,
njt.sem post end,
in lua gc, semaphore
http close request
