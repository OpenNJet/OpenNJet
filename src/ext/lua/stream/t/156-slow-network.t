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
}

use Test::Nginx::Socket::Lua::Stream;

repeat_each(2);

plan tests => repeat_each() * (blocks() * 4);

add_block_preprocessor(sub {
    my $block = shift;

    if (!defined $block->error_log) {
        $block->set_value("no_error_log", "[error]");
    }
});


log_level("debug");
no_long_string();
#no_diff();
run_tests();

__DATA__

=== TEST 1: receiveany returns anything once socket receives
--- config
    location = /foo {
        server_tokens off;

        content_by_lua_block {
            local resp = {
                '1',
                'hello',
            }

            local length = 0
            for _, v in ipairs(resp) do
                length = length + #v
            end

            -- flush http header
            njt.header['Content-Length'] = length
            njt.flush(true)
            njt.sleep(0.01)

            -- send http body bytes by bytes
            for _, v in ipairs(resp) do
                njt.print(v)
                njt.flush(true)
                njt.sleep(0.01)
            end
        }
    }
--- stream_server_config
    content_by_lua_block {
        local sock = njt.socket.tcp()
        sock:settimeout(500)

        assert(sock:connect("127.0.0.1", $TEST_NGINX_SERVER_PORT))
        local req = {
            'GET /foo HTTP/1.0\r\n',
            'Host: localhost\r\n',
            'Connection: close\r\n\r\n',
        }
        local ok, err = sock:send(req)
        if not ok then
            njt.say("send request failed: ", err)
            return
        end


        -- skip http header
        while true do
            local data, err, _ = sock:receive('*l')
            if err then
                njt.say('unexpected error occurs when receiving http head: ' .. err)
                return
            end
            if #data == 0 then -- read last line of head
                break
            end
        end

        -- receive http body
        while true do
            local data, err = sock:receiveany(1024)
            if err then
                if err ~= 'closed' then
                    njt.say('unexpected err: ', err)
                end
                break
            end
            njt.say(data)
        end

        sock:close()
    }
--- stream_response
1
h
e
l
l
o
--- grep_error_log eval
qr/lua tcp socket read any/
--- grep_error_log_out
lua tcp socket read any
lua tcp socket read any
lua tcp socket read any
lua tcp socket read any
lua tcp socket read any
lua tcp socket read any
lua tcp socket read any
