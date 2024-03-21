# vim:set ft= ts=4 sw=4 et fdm=marker:

BEGIN {
    if (!defined $ENV{LD_PRELOAD}) {
        $ENV{LD_PRELOAD} = '';
    }

    if ($ENV{LD_PRELOAD} !~ /\bmockeagain\.so\b/) {
        $ENV{LD_PRELOAD} = "mockeagain.so $ENV{LD_PRELOAD}";
    }

    if ($ENV{MOCKEAGAIN} eq 'r') {
        $ENV{MOCKEAGAIN} = 'rw';

    } else {
        $ENV{MOCKEAGAIN} = 'w';
    }

    $ENV{TEST_NGINX_EVENT_TYPE} = 'poll';
    $ENV{MOCKEAGAIN_WRITE_TIMEOUT_PATTERN} = 'slow';
}

use Test::Nginx::Socket::Lua::Stream;
log_level('debug');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 4);

run_tests();

__DATA__

=== TEST 1: raw downstream cosocket used in two different threads. See issue #481
--- stream_server_config
    lua_socket_read_timeout 1ms;
    lua_socket_send_timeout 1s;
    lua_socket_log_errors off;
    #lua_lingering_timeout 1ms;

    content_by_lua_block {
        local function reader(req_socket)
           -- First we receive in a blocking fashion so that ctx->downstream_co_ctx will be changed
           local data, err, partial = req_socket:receive(1)
           if err ~= "timeout" then
              njt.log(njt.ERR, "Did not get timeout in the receiving thread!")
              return
           end

           -- Now, sleep so that coctx->data is changed to sleep handler
           njt.sleep(1)
        end

        local function writer(req_socket)
           -- send in a slow manner with a low timeout, so that the timeout handler will be
           local bytes, err = req_socket:send("slow!!!")
           if err ~= "timeout" then
              return error("Did not get timeout in the sending thread!")
           end
        end

        local req_socket, err = njt.req.socket(true)
        if req_socket == nil then
           return error("Unable to get request socket:" .. (err or "nil"))
        end

        local writer_thread = njt.thread.spawn(writer, req_socket)
        local reader_thread = njt.thread.spawn(reader, req_socket)

        njt.thread.wait(writer_thread)
        njt.thread.wait(reader_thread)
        print("The two threads finished")
    }

--- no_error_log
[error]
--- error_log: The two threads finished
--- wait: 0.1
--- log_stream_response
--- stream_response_like chomp
^received \d+ bytes of response data\.$
--- timeout: 10



=== TEST 2: normal downstream cosocket used in two different threads. See issue #481
--- stream_server_config
    lua_socket_read_timeout 1ms;
    lua_socket_send_timeout 300ms;
    lua_socket_log_errors off;

    content_by_lua_block {
        local function reader(req_socket)
           -- First we receive in a blocking fashion so that ctx->downstream_co_ctx will be changed
           local data, err, partial = req_socket:receive(1)
           if err ~= "timeout" then
              njt.log(njt.ERR, "Did not get timeout in the receiving thread!")
              return
           end

           -- Now, sleep so that coctx->data is changed to sleep handler
           njt.sleep(0.3)
        end

        local function writer(req_socket)
           -- send in a slow manner with a low timeout, so that the timeout handler will be
           print("sleep 0.3")
           njt.sleep(0.1)
           print("say slow")
           njt.say("slow!!!")
           print("flushing")
           local ok, err = njt.flush(true)
           if not ok then
               print("flushing failed: ", err)
           end
        end

        local req_socket, err = njt.req.socket()
        if req_socket == nil then
           return error("Unable to get request socket:" .. (err or "nil"))
        end

        local writer_thread = njt.thread.spawn(writer, req_socket)
        local reader_thread = njt.thread.spawn(reader, req_socket)

        njt.thread.wait(writer_thread)
        njt.thread.wait(reader_thread)
        print("The two threads finished")
    }

--- no_error_log
[error]
--- error_log: The two threads finished
--- wait: 0.1
--- log_stream_response
--- stream_response
received 4 bytes of response data.
--- timeout: 3
