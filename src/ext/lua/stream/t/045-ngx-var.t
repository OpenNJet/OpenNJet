# vim:set ft= ts=4 sw=4 et fdm=marker:
use Test::Nginx::Socket::Lua::Stream;
#worker_connections(1014);
#master_process_enabled(1);
#log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 2 + 3);

#no_diff();
#no_long_string();
#master_on();
#workers(2);
run_tests();

__DATA__

=== TEST 1: pid
--- stream_server_config
    content_by_lua_block {
        local pid = njt.var.pid
        njt.say("variable pid: ", pid)
        if pid ~= tostring(njt.worker.pid()) then
            njt.say("variable pid is wrong.")
        else
            njt.say("variable pid is correct.")
        end
    }
--- stream_response_like
variable pid: \d+
variable pid is correct\.
--- no_error_log
[error]



=== TEST 2: remote_addr
--- stream_server_config
    content_by_lua_block {
        njt.say("remote_addr: ", njt.var.remote_addr)
        njt.say("type: ", type(njt.var.remote_addr))
    }
--- stream_response
remote_addr: 127.0.0.1
type: string



=== TEST 3: binary_remote_addr
--- stream_server_config
    content_by_lua_block {
        njt.say("binary_remote_addr len: ", #njt.var.binary_remote_addr)
        njt.say("type: ", type(njt.var.binary_remote_addr))
    }
--- stream_response
binary_remote_addr len: 4
type: string



=== TEST 4: server_addr & server_port
--- stream_server_config
    content_by_lua_block {
        njt.say("server_addr: ", njt.var.server_addr)
        njt.say("server_port: ", njt.var.server_port)
        njt.say(type(njt.var.server_addr))
        njt.say(type(njt.var.server_port))
    }
--- stream_response_like eval
qr/^server_addr: 127\.0\.0\.1
server_port: \d{4,}
string
string
$/



=== TEST 5: connection & njet_version
--- stream_server_config
    content_by_lua_block {
        njt.say("connection: ", njt.var.connection)
        njt.say("njet_version: ", njt.var.njet_version)
        njt.say(type(njt.var.connection))
        njt.say(type(njt.var.njet_version))
    }
--- stream_response_like eval
qr/^connection: \d+
njet_version: \d+\.\d+\.\d+.*
string
string$/



=== TEST 6: reference nonexistent variable
--- stream_server_config
    content_by_lua_block {
        njt.say("value: ", njt.var.notfound)
    }
--- stream_response
value: nil



=== TEST 7: variable name is caseless
--- stream_server_config
    content_by_lua_block {
        njt.say("value: ", njt.var.REMOTE_ADDR)
    }
--- stream_response
value: 127.0.0.1



=== TEST 8: get a bad variable name
--- stream_server_config
    content_by_lua_block {
        njt.say("value: ", njt.var[true])
    }
--- stream_response
--- error_log
bad variable name



=== TEST 9: can not set variable
--- stream_server_config
    content_by_lua_block {
        njt.var.foo = 56
    }
--- stream_response
--- error_log
variable "foo" not found for writing
