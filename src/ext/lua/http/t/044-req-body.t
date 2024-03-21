# vim:set ft= ts=4 sw=4 et fdm=marker:
use Test::Nginx::Socket::Lua;

#worker_connections(1014);
#master_process_enabled(1);
log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 4 + 52 );

#no_diff();
no_long_string();
#master_on();
#workers(2);
run_tests();

__DATA__

=== TEST 1: read buffered body
--- config
    location = /test {
        content_by_lua '
            njt.req.read_body()
            njt.say(njt.var.request_body)
        ';
    }
--- request
POST /test
hello, world
--- response_body
hello, world
--- no_error_log
[error]
[alert]



=== TEST 2: read buffered body (timed out)
--- config
    client_body_timeout 1ms;
    location = /test {
        content_by_lua '
            njt.req.read_body()
            njt.say(njt.var.request_body)
        ';
    }
--- raw_request eval
"POST /test HTTP/1.1\r
Host: localhost\r
Content-Length: 100\r
Connection: close\r
\r
hello, world"
--- response_body:
--- error_code_like: ^(?:500)?$
--- no_error_log
[error]
[alert]



=== TEST 3: read buffered body and then subrequest
--- config
    location /foo {
        echo -n foo;
    }
    location = /test {
        content_by_lua '
            njt.req.read_body()
            local res = njt.location.capture("/foo");
            njt.say(njt.var.request_body)
            njt.say("sub: ", res.body)
        ';
    }
--- request
POST /test
hello, world
--- response_body
hello, world
sub: foo
--- no_error_log
[error]
[alert]



=== TEST 4: first subrequest and then read buffered body
--- config
    location /foo {
        echo -n foo;
    }
    location = /test {
        content_by_lua '
            local res = njt.location.capture("/foo");
            njt.req.read_body()
            njt.say(njt.var.request_body)
            njt.say("sub: ", res.body)
        ';
    }
--- request
POST /test
hello, world
--- response_body
hello, world
sub: foo
--- no_error_log
[error]
[alert]



=== TEST 5: discard body
--- config
    location = /foo {
        content_by_lua '
            njt.req.discard_body()
            njt.say("body: ", njt.var.request_body)
        ';
    }
    location = /bar {
        content_by_lua '
            njt.req.read_body()
            njt.say("body: ", njt.var.request_body)
        ';

    }
--- pipelined_requests eval
["POST /foo
hello, world",
"POST /bar
hiya, world"]
--- response_body eval
["body: nil\n",
"body: hiya, world\n"]
--- no_error_log
[error]
[alert]



=== TEST 6: not discard body (content_by_lua falls through)
--- config
    location = /foo {
        content_by_lua '
            -- njt.req.discard_body()
            njt.say("body: ", njt.var.request_body)
        ';
    }
    location = /bar {
        content_by_lua '
            njt.req.read_body()
            njt.say("body: ", njt.var.request_body)
        ';
    }
--- pipelined_requests eval
["POST /foo
hello, world",
"POST /bar
hiya, world"]
--- response_body eval
["body: nil\n",
"body: hiya, world\n",
]
--- error_code eval
[200, 200]
--- no_error_log
[error]
[alert]



=== TEST 7: read buffered body and retrieve the data
--- config
    location = /test {
        content_by_lua '
            njt.req.read_body()
            njt.say(njt.req.get_body_data())
        ';
    }
--- request
POST /test
hello, world
--- response_body
hello, world
--- no_error_log
[error]
[alert]



=== TEST 8: read buffered body to file and call get_body_data
--- config
    client_body_in_file_only on;
    location = /test {
        content_by_lua '
            njt.req.read_body()
            njt.say(njt.req.get_body_data())
        ';
    }
--- request
POST /test
hello, world
--- response_body
nil
--- no_error_log
[error]
[alert]



=== TEST 9: read buffered body to file and call get_body_file
--- config
    client_body_in_file_only on;
    location = /test {
        content_by_lua '
            njt.req.read_body()
            njt.say(njt.req.get_body_file())
        ';
    }
--- request
POST /test
hello, world
--- response_body_like: client_body_temp/
--- no_error_log
[error]
[alert]



=== TEST 10: read buffered body to memory and retrieve the file
--- config
    location = /test {
        content_by_lua '
            njt.req.read_body()
            njt.say(njt.req.get_body_file())
        ';
    }
--- request
POST /test
hello, world
--- response_body
nil
--- no_error_log
[error]
[alert]



=== TEST 11: read buffered body to memory and reset it with data in memory
--- config
    location = /test {
        content_by_lua '
            njt.req.read_body()
            njt.req.set_body_data("hiya, dear")
            njt.say(njt.req.get_body_data())
            njt.say(njt.var.request_body)
            njt.say(njt.var.echo_request_body)
        ';
    }
--- request
POST /test
hello, world
--- response_body
hiya, dear
hiya, dear
hiya, dear
--- no_error_log
[error]
[alert]



=== TEST 12: read body to file and then override it with data in memory
--- config
    client_body_in_file_only on;

    location = /test {
        content_by_lua '
            njt.req.read_body()
            njt.req.set_body_data("hello, baby")
            njt.say(njt.req.get_body_data())
            njt.say(njt.var.request_body)
        ';
    }
--- request
POST /test
yeah
--- response_body
hello, baby
hello, baby
--- no_error_log
[error]
[alert]



=== TEST 13: do not read the current request body but replace it with our own in memory
--- config
    client_body_in_file_only on;

    location = /test {
        content_by_lua '
            njt.req.set_body_data("hello, baby")
            njt.say(njt.req.get_body_data())
            njt.say(njt.var.request_body)
            -- njt.location.capture("/sleep")
        ';
    }
    location = /sleep {
        echo_sleep 0.5;
    }
--- request
POST /test
yeah
--- response_body_like: 500 Internal Server Error
--- error_code: 500
--- error_log eval
qr/lua entry thread aborted: runtime error: content_by_lua\(nginx\.conf:\d+\):2: request body not read yet/
--- no_error_log
[alert]



=== TEST 14: read buffered body to file and reset it to a new file
--- config

    location = /test {
        client_body_in_file_only on;
        set $old '';
        set $new '';
        rewrite_by_lua '
            njt.req.read_body()
            njt.var.old = njt.req.get_body_file()
            njt.req.set_body_file(njt.var.realpath_root .. "/a.txt")
            njt.var.new = njt.req.get_body_file()
        ';
        #echo_request_body;
        proxy_pass http://127.0.0.1:$server_port/echo;
        #proxy_pass http://127.0.0.1:7890/echo;
        add_header X-Old $old;
        add_header X-New $new;
    }
    location /echo {
        echo_read_request_body;
        echo_request_body;
    }
--- request
POST /test
hello, world
--- user_files
>>> a.txt
Will you change this world?
--- raw_response_headers_like
X-Old: \S+/client_body_temp/\d+\r
.*?X-New: \S+/html/a\.txt\r
--- response_body
Will you change this world?
--- no_error_log
[error]
[alert]



=== TEST 15: read buffered body to file and reset it to a new file
--- config
    location = /test {
        client_body_in_file_only on;
        set $old '';
        set $new '';
        rewrite_by_lua '
            njt.req.read_body()
            njt.var.old = njt.req.get_body_file() or ""
            njt.req.set_body_file(njt.var.realpath_root .. "/a.txt")
            njt.var.new = njt.req.get_body_file()
        ';
        #echo_request_body;
        proxy_pass http://127.0.0.1:$server_port/echo;
        #proxy_pass http://127.0.0.1:7890/echo;
        add_header X-Old $old;
        add_header X-New $new;
    }
    location /echo {
        echo_read_request_body;
        echo_request_body;
    }
--- request
POST /test
hello, world!
--- user_files
>>> a.txt
Will you change this world?
--- raw_response_headers_like
X-Old: \S+/client_body_temp/\d+\r
.*?X-New: \S+/html/a\.txt\r
--- response_body
Will you change this world?
--- no_error_log
[error]
[alert]



=== TEST 16: read buffered body to file and reset it to a new file (auto-clean)
--- config
    client_body_in_file_only on;

    location = /test {
        set $old '';
        set $new '';
        content_by_lua '
            njt.req.read_body()
            njt.var.old = njt.req.get_body_file()
            local a_file = njt.var.realpath_root .. "/a.txt"
            njt.req.set_body_file(a_file, true)
            local b_file = njt.var.realpath_root .. "/b.txt"
            njt.req.set_body_file(b_file, true)
            njt.say("a.txt exists: ", io.open(a_file) and "yes" or "no")
            njt.say("b.txt exists: ", io.open(b_file) and "yes" or "no")
        ';
    }
    location /echo {
        echo_read_request_body;
        echo_request_body;
    }
--- request
POST /test
hello, world
--- user_files
>>> a.txt
Will you change this world?
>>> b.txt
Sure I will!
--- response_body
a.txt exists: no
b.txt exists: yes
--- no_error_log
[error]
[alert]



=== TEST 17: read buffered body to memory and reset it to a new file (auto-clean)
--- config
    client_body_in_file_only off;

    location = /test {
        set $old '';
        set $new '';
        rewrite_by_lua '
            njt.req.read_body()
            local a_file = njt.var.realpath_root .. "/a.txt"
            njt.req.set_body_file(a_file, true)
        ';
        echo_request_body;
    }
    location /echo {
        echo_read_request_body;
        echo_request_body;
    }
--- pipelined_requests eval
["POST /test
hello, world",
"POST /test
hey, you"]
--- user_files
>>> a.txt
Will you change this world?
--- response_body eval
["Will you change this world?\n",
qr/500 Internal Server Error/]
--- error_code eval
[200, 500]
--- no_error_log
[alert]



=== TEST 18: read buffered body to memory and reset it to a new file (no auto-clean)
--- config
    client_body_in_file_only off;

    location = /test {
        set $old '';
        set $new '';
        rewrite_by_lua '
            njt.req.read_body()
            local a_file = njt.var.realpath_root .. "/a.txt"
            njt.req.set_body_file(a_file, false)
        ';
        echo_request_body;
    }
    location /echo {
        echo_read_request_body;
        echo_request_body;
    }
--- pipelined_requests eval
["POST /test
hello, world",
"POST /test
hey, you"]
--- user_files
>>> a.txt
Will you change this world?
--- response_body eval
["Will you change this world?\n",
"Will you change this world?\n"]
--- error_code eval
[200, 200]
--- no_error_log
[error]
[alert]



=== TEST 19: request body discarded and reset it to a new file (auto-clean)
--- config
    client_body_in_file_only off;
    client_header_buffer_size 80;

    location = /test {
        set $old '';
        set $new '';
        rewrite_by_lua '
            njt.req.discard_body()
            local a_file = njt.var.realpath_root .. "/a.txt"
            njt.req.set_body_file(a_file, false)
        ';
        echo_request_body;
    }
    location /echo {
        echo_read_request_body;
        echo_request_body;
    }
--- request
POST /test
hello, world

--- user_files
>>> a.txt
Will you change this world?

--- response_body_like: 500 Internal Server Error
--- error_code: 500
--- no_error_log
[alert]



=== TEST 20: no request body and reset it to a new file (no auto-clean)
--- config
    client_body_in_file_only off;

    location = /test {
        set $old '';
        set $new '';
        rewrite_by_lua '
            local a_file = njt.var.realpath_root .. "/a.txt"
            njt.req.set_body_file(a_file, true)
        ';
        echo_request_body;
    }
    location /echo {
        echo_read_request_body;
        echo_request_body;
    }
--- request
POST /test
hello, world

--- user_files
>>> a.txt
Will you change this world?
--- response_body_like: 500 Internal Server Error
--- error_code: 500
--- error_log eval
qr/lua entry thread aborted: runtime error: rewrite_by_lua\(nginx\.conf:\d+\):3: request body not read yet/

--- no_error_log
[alert]



=== TEST 21: read buffered body to memory and reset it with data in memory + proxy
--- config
    location = /test {
        rewrite_by_lua '
            njt.req.read_body()
            njt.req.set_body_data("hiya, dear dear friend!")
        ';
        proxy_pass http://127.0.0.1:$server_port/echo;
    }
    location = /echo {
        echo_read_request_body;
        echo_request_body;
    }
--- request
POST /test
hello, world
--- response_body chomp
hiya, dear dear friend!
--- no_error_log
[error]
[alert]



=== TEST 22: discard request body and reset it to a new file (no auto-clean)
--- config
    client_body_in_file_only off;

    location = /test {
        set $old '';
        set $new '';
        rewrite_by_lua '
            njt.req.discard_body()
            local a_file = njt.var.realpath_root .. "/a.txt"
            njt.req.set_body_file(a_file, true)
        ';
        echo_request_body;
    }
    location /echo {
        echo_read_request_body;
        echo_request_body;
    }
--- request
POST /test
hello, world

--- user_files
>>> a.txt
Will you change this world?

--- response_body_like: 500 Internal Server Error
--- error_code: 500
--- no_error_log
[alert]



=== TEST 23: discard body and then read
--- config
    location = /test {
        content_by_lua '
            njt.req.discard_body()
            njt.req.read_body()
            njt.print(njt.req.get_body_data())
        ';
    }
--- pipelined_requests eval
["POST /test
hello, world",
"POST /test
hello, world"]
--- response_body eval
["nil","nil"]
--- no_error_log
[error]
[alert]



=== TEST 24: set empty request body in memory
--- config
    location = /test {
        rewrite_by_lua '
            njt.req.read_body()
            njt.req.set_body_data("")
        ';
        proxy_pass http://127.0.0.1:$server_port/echo;
    }
    location = /echo {
        content_by_lua '
            njt.req.read_body()
            njt.say("body: [", njt.req.get_body_data(), "]")
        ';
    }
--- pipelined_requests eval
["POST /test
hello, world",
"POST /test
hello, world"]
--- response_body eval
["body: [nil]\n","body: [nil]\n"]
--- no_error_log
[error]
[alert]



=== TEST 25: set empty request body in file
--- config
    location = /test {
        rewrite_by_lua '
            njt.req.read_body()
            njt.req.set_body_file(njt.var.realpath_root .. "/a.txt")
        ';
        proxy_pass http://127.0.0.1:$server_port/echo;
    }
    location = /echo {
        content_by_lua '
            njt.req.read_body()
            njt.say("body: [", njt.req.get_body_data(), "]")
        ';
    }
--- user_files
>>> a.txt
--- pipelined_requests eval
["POST /test
hello, world",
"POST /test
hello, world"]
--- response_body eval
["body: [nil]\n","body: [nil]\n"]
--- no_error_log
[error]
[alert]



=== TEST 26: read and set body
--- config
    location /test {
        lua_need_request_body on;
        access_by_lua_file html/myscript.lua;
        echo_request_body;
    }
--- user_files
>>> myscript.lua
    local data, err = njt.req.get_post_args()
    if err then
        njt.log(njt.ERR, "err: ", err)
        return njt.exit(500)
    end

    local data2 = {}
    for k, v in pairs(data) do
        if type(v) == "table" then
            for i, val in ipairs(v) do
                local s = njt.escape_uri(string.upper(k)) .. '='
                        .. njt.escape_uri(string.upper(val))
                table.insert(data2, s)
            end
        else
            local s = njt.escape_uri(string.upper(k)) .. '='
                    .. njt.escape_uri(string.upper(v))
            table.insert(data2, s)
        end
    end
    njt.req.set_body_data(table.concat(data2, "&"))
--- request
POST /test
a=1&a=2&b=hello&c=world
--- response_body
B=HELLO&A=1&A=2&C=WORLD
--- no_error_log
[error]
--- SKIP



=== TEST 27: read buffered body to memory and reset it with data in memory + proxy twice
--- config
    location = /test {
        rewrite_by_lua '
            njt.req.read_body()
            njt.req.set_body_data("hiya, dear dear friend!")
            njt.req.set_body_data("howdy, my dear little sister!")
        ';
        proxy_pass http://127.0.0.1:$server_port/echo;
    }
    location = /echo {
        echo_read_request_body;
        echo_request_body;
    }
--- request
POST /test
hello, world
--- response_body chomp
howdy, my dear little sister!
--- no_error_log
[error]
[alert]



=== TEST 28: read buffered body to memory and reset it with data in memory and then reset it to file
--- config
    location = /test {
        rewrite_by_lua '
            njt.req.read_body()
            njt.req.set_body_data("hiya, dear dear friend!")
            njt.req.set_body_file(njt.var.realpath_root .. "/a.txt")
        ';
        proxy_pass http://127.0.0.1:$server_port/echo;
    }
    location = /echo {
        echo_read_request_body;
        echo_request_body;
    }
--- user_files
>>> a.txt
howdy, my dear little sister!
--- request
POST /test
hello, world
--- response_body
howdy, my dear little sister!
--- no_error_log
[error]
[alert]



=== TEST 29: read buffered body to memory and reset it with empty string + proxy twice
--- config
    location = /test {
        rewrite_by_lua '
            njt.req.read_body()
            njt.req.set_body_data("hiya, dear dear friend!")
            njt.req.set_body_data("")
        ';
        proxy_pass http://127.0.0.1:$server_port/echo;
    }
    location = /echo {
        echo_read_request_body;
        echo_request_body;
    }
--- request
POST /test
hello, world
--- response_body chomp
--- no_error_log
[error]
[alert]



=== TEST 30: multi-buffer request body
--- config
    location /foo {
        default_type text/css;
        srcache_store POST /store;

        echo hello;
        echo world;
    }

    location /store {
        content_by_lua '
            local body = njt.req.get_body_data()
            njt.log(njt.WARN, "srcache_store: request body len: ", #body)
        ';
    }
--- request
GET /foo
--- response_body
hello
world
--- error_log
srcache_store: request body len: 55
--- no_error_log
[error]
[alert]



=== TEST 31: init & append & finish (just in buffer)
--- config
    location /t {
        content_by_lua '
            njt.req.read_body()
            njt.req.init_body(4)
            njt.req.append_body("h")
            njt.req.append_body("ell")
            njt.req.finish_body()

            njt.say("content length: ", njt.var.http_content_length)

            local data = njt.req.get_body_data()
            njt.say("body: ", data)

        ';
    }
--- request
    GET /t
--- stap2
F(njt_http_lua_write_request_body) {
    b = njt_chain_buf($body)
    println("buf: ", b,
        ", in-mem: ", njt_buf_in_memory(b),
        ", size: ", njt_buf_size(b),
        ", data: ", njt_buf_data(b))
}
--- response_body
content length: 4
body: hell
--- no_error_log
[error]
[alert]



=== TEST 32: init & append & finish (exceeding the buffer size)
--- config
    location /t {
        content_by_lua '
            njt.req.read_body()
            njt.req.init_body(4)
            njt.req.append_body("h")
            njt.req.append_body("ell")
            njt.req.append_body("o")
            njt.req.finish_body()

            njt.say("content length: ", njt.var.http_content_length)

            local data = njt.req.get_body_data()
            njt.say("body: ", data)

            local file = njt.req.get_body_file()
            if not file then
                njt.say("body file: ", file)
                return
            end

            local f, err = io.open(file, "r")
            if not f then
                njt.say("failed to open file: ", err)
                return
            end

            local data = f:read("*a")
            f:close()
            njt.say("body file: ", data)
        ';
    }
--- request
    GET /t
--- stap2
F(njt_http_lua_write_request_body) {
    b = njt_chain_buf($body)
    println("buf: ", b,
        ", in-mem: ", njt_buf_in_memory(b),
        ", size: ", njt_buf_size(b),
        ", data: ", njt_buf_data(b))
}
F(njt_open_tempfile) {
    println("open temp file ", user_string($name), ", persist: ", $persistent)
}
F(njt_pool_delete_file) {
    println("delete ", njt_pool_cleanup_file_name($data))
}
--- response_body
content length: 5
body: nil
body file: hello
--- no_error_log
[error]
[alert]
--- error_log
a client request body is buffered to a temporary file



=== TEST 33: init & append & finish (use default buffer size) - body not read yet
--- config
    location /t {
        client_body_buffer_size 4;
        content_by_lua '
            njt.req.init_body()
            njt.req.append_body("h")
            njt.req.append_body("ell")
            njt.req.finish_body()

            njt.say("content length: ", njt.var.http_content_length)

            local data = njt.req.get_body_data()
            njt.say("body: ", data)

        ';
    }
--- request
    GET /t
--- response_body_like: 500 Internal Server Error
--- error_code: 500
--- error_log eval
qr/lua entry thread aborted: runtime error: content_by_lua\(nginx\.conf:\d+\):2: request body not read yet/

--- no_error_log
[alert]



=== TEST 34: init & append & finish (use default buffer size)
--- config
    location /t {
        client_body_buffer_size 4;
        content_by_lua '
            njt.req.read_body()
            njt.req.init_body()
            njt.req.append_body("h")
            njt.req.append_body("ell")
            njt.req.finish_body()

            njt.say("content length: ", njt.var.http_content_length)

            local data = njt.req.get_body_data()
            njt.say("body: ", data)

        ';
    }
--- request
    GET /t
--- response_body
content length: 4
body: hell
--- no_error_log
[error]
[alert]
--- no_error_log
a client request body is buffered to a temporary file



=== TEST 35: init & append & finish (exceeding the buffer size, proxy)
--- config
    location /t {
        rewrite_by_lua '
            njt.req.read_body()
            njt.req.init_body(4)
            njt.req.append_body("h")
            njt.req.append_body("ell")
            njt.req.append_body("o\\n")
            njt.req.finish_body()
        ';

        proxy_pass http://127.0.0.1:$server_port/back;
    }

    location = /back {
        echo_read_request_body;
        echo_request_body;
    }
--- request
POST /t
i do like the sky

--- stap
global valid = 0

F(njt_http_handler) { valid = 1  }

probe syscall.unlink {
    if (valid && pid() == target()) {
        println(name, "(", argstr, ")")
    }
}

--- stap_out_like chop
^unlink\(".*?client_body_temp/\d+"\)$
--- response_body
hello
--- no_error_log
[error]
[alert]
--- error_log
a client request body is buffered to a temporary file



=== TEST 36: init & append & finish (just in buffer, proxy)
--- config
    location /t {
        rewrite_by_lua '
            njt.req.read_body()
            njt.req.init_body(4)
            njt.req.append_body("h")
            njt.req.append_body("ell")
            njt.req.finish_body()
        ';

        proxy_pass http://127.0.0.1:$server_port/back;
    }

    location = /back {
        echo_read_request_body;
        echo_request_body;
    }
--- request
POST /t
i do like the sky
--- response_body chop
hell
--- no_error_log
[error]
[alert]
a client request body is buffered to a temporary file



=== TEST 37: init & append & finish (exceeding buffer size, discard on-disk buffer)
--- config
    client_header_buffer_size 100;
    location /t {
        client_body_buffer_size 4;

        content_by_lua '
            njt.req.read_body()

            -- njt.say("original body: ", njt.req.get_body_data())
            -- njt.say("original body file: ", njt.req.get_body_file())

            njt.req.init_body(4)
            njt.req.append_body("h")
            njt.req.append_body("ell")
            njt.req.append_body("o")
            njt.req.finish_body()

            njt.say("content length: ", njt.var.http_content_length)

            local data = njt.req.get_body_data()
            njt.say("body: ", data)

            local file = njt.req.get_body_file()
            if not file then
                njt.say("body file: ", file)
                return
            end

            local f, err = io.open(file, "r")
            if not f then
                njt.say("failed to open file: ", err)
                return
            end

            local data = f:read("*a")
            f:close()
            njt.say("body file: ", data)
        ';
    }
--- request eval
"POST /t
" . ("howdyworld" x 15)
--- stap
/*
F(njt_http_read_client_request_body) { T() }
M(http-read-body-abort) { println("read body aborted: ", user_string($arg2)) }
M(http-read-req-header-done) { println("req header: ", njt_table_elt_key($arg2), ": ", njt_table_elt_value($arg2)) }
#probe syscall.open { if (isinstr(argstr, "temp")) { println(name, ": ", argstr) } }

probe syscall.unlink {
    println(name, ": ", argstr, " :", target(), " == ", pid(), ": ", execname())
    system(sprintf("ps aux|grep %d|grep -v grep > /dev/stderr", target()))
    system(sprintf("ps aux|grep %d|grep -v grep  > /dev/stderr", pid()))
}
*/

global valid = 0

F(njt_http_handler) { valid = 1  }
#F(njt_http_free_request) { valid = 0 }

probe syscall.unlink {
    if (valid && pid() == target()) {
        println(name, "(", argstr, ")")
        #print_ubacktrace()
    }
}

/*
probe syscall.close, syscall.open, syscall.unlink {
    if (valid && pid() == target()) {
        print(name, "(", argstr, ")")
        #print_ubacktrace()
    }
}

probe syscall.close.return, syscall.open.return, syscall.unlink.return {
    if (valid && pid() == target()) {
        println(" = ", retstr)
    }
}
*/
--- stap_out_like chop
^unlink\(".*?client_body_temp/\d+"\)
unlink\(".*?client_body_temp/\d+"\)$
--- response_body
content length: 5
body: nil
body file: hello
--- no_error_log
[error]
[alert]
--- error_log
a client request body is buffered to a temporary file



=== TEST 38: njt.req.socket + init & append & finish (requests)
--- config
    location = /t {
        client_body_buffer_size 1;
        lua_socket_buffer_size 1;
        content_by_lua '
            local sock,err = njt.req.socket()
            if not sock then
                njt.say("failed to get req socket: ", err)
                return
            end

            njt.req.init_body(100)

            while true do
                local data, err = sock:receive(1)
                if not data then
                    if err == "closed" then
                        break
                    else
                        njt.say("failed to read body: ", err)
                        return
                    end
                end
                njt.req.append_body(data)
            end

            njt.req.finish_body()

            njt.say("content length: ", njt.var.http_content_length)

            local data = njt.req.get_body_data()
            njt.say("body: ", data)

        ';
    }
--- request
POST /t
hello, my dear friend!
--- response_body
content length: 22
body: hello, my dear friend!
--- no_error_log
[error]
[alert]
--- no_error_log
a client request body is buffered to a temporary file



=== TEST 39: njt.req.socket + init & append & finish (pipelined requests, small buffer size)
--- config
    location = /t {
        client_body_buffer_size 1;
        lua_socket_buffer_size 1;
        content_by_lua '
            local sock,err = njt.req.socket()
            if not sock then
                njt.say("failed to get req socket: ", err)
                return
            end

            njt.req.init_body(100)

            while true do
                local data, err = sock:receive(1)
                if not data then
                    if err == "closed" then
                        break
                    else
                        njt.say("failed to read body: ", err)
                        return
                    end
                end
                njt.req.append_body(data)
            end

            njt.req.finish_body()

            njt.say("content length: ", njt.var.http_content_length)

            local data = njt.req.get_body_data()
            njt.say("body: ", data)

        ';
    }
--- pipelined_requests eval
["POST /t
hello, my dear friend!",
"POST /t
blah blah blah"]
--- response_body eval
["content length: 22
body: hello, my dear friend!
","content length: 14
body: blah blah blah
"]
--- no_error_log
[error]
[alert]
--- no_error_log
a client request body is buffered to a temporary file



=== TEST 40: njt.req.socket + init & append & finish (pipelined requests, big buffer size)
--- config
    location = /t {
        client_body_buffer_size 100;
        lua_socket_buffer_size 100;
        content_by_lua '
            local sock,err = njt.req.socket()
            if not sock then
                njt.say("failed to get req socket: ", err)
                return
            end

            njt.req.init_body(100)

            while true do
                local data, err, partial = sock:receive(100)
                if not data then
                    if err == "closed" then
                        njt.req.append_body(partial)
                        break
                    else
                        njt.say("failed to read body: ", err)
                        return
                    end
                end
                njt.req.append_body(data)
            end

            njt.req.finish_body()

            njt.say("content length: ", njt.var.http_content_length)

            local data = njt.req.get_body_data()
            njt.say("body: ", data)

        ';
    }
--- pipelined_requests eval
["POST /t
hello, my dear friend!",
"POST /t
blah blah blah"]
--- response_body eval
["content length: 22
body: hello, my dear friend!
","content length: 14
body: blah blah blah
"]
--- no_error_log
[error]
[alert]
--- no_error_log
a client request body is buffered to a temporary file



=== TEST 41: calling njt.req.socket after njt.req.read_body
--- config
    location = /t {
        client_body_buffer_size 100;
        lua_socket_buffer_size 100;
        content_by_lua '
            njt.req.read_body()

            local sock, err = njt.req.socket()
            if not sock then
                njt.say("failed to get req socket: ", err)
                return
            end

            njt.say("done")
        ';
    }
--- request
POST /t
hello, my dear friend!
--- response_body
failed to get req socket: request body already exists
--- no_error_log
[error]
[alert]
--- no_error_log
a client request body is buffered to a temporary file



=== TEST 42: failed to write 100 continue
--- config
    location = /test {
        content_by_lua '
            njt.req.read_body()
            njt.say(njt.var.request_body)
        ';
    }
--- request
POST /test
hello, world
--- more_headers
Expect: 100-Continue
--- ignore_response
--- no_error_log
[alert]
[error]
http finalize request: 500, "/test?" a:1, c:0



=== TEST 43: chunked support in njt.req.read_body
--- config
    location /t {
        content_by_lua '
            njt.req.read_body()
            njt.say(njt.req.get_body_data())
        ';
    }
--- raw_request eval
"POST /t HTTP/1.1\r
Host: localhost\r
Transfer-Encoding: chunked\r
Connection: close\r
\r
5\r
hello\r
1\r
,\r
1\r
 \r
5\r
world\r
0\r
\r
"

--- response_body
hello, world
--- no_error_log
[error]
[alert]
--- skip_nginx: 4: <1.3.9



=== TEST 44: zero size request body and reset it to a new file
--- config
    location = /test {
        client_body_in_file_only on;
        set $old '';
        set $new '';
        rewrite_by_lua '
            njt.req.read_body()
            njt.req.set_body_file(njt.var.realpath_root .. "/a.txt")
            njt.var.new = njt.req.get_body_file()
        ';
        #echo_request_body;
        proxy_pass http://127.0.0.1:$server_port/echo;
        #proxy_pass http://127.0.0.1:7890/echo;
        add_header X-Old $old;
        add_header X-New $new;
    }
    location /echo {
        echo_read_request_body;
        echo_request_body;
    }
--- request
POST /test
--- user_files
>>> a.txt
Will you change this world?

--- stap
probe syscall.fcntl {
    O_DIRECT = 0x4000
    if (pid() == target() && ($arg & O_DIRECT)) {
        println("fcntl(O_DIRECT)")
    }
}
--- stap_out_unlike
fcntl\(O_DIRECT\)

--- raw_response_headers_like
.*?X-New: \S+/html/a\.txt\r
--- response_body
Will you change this world?
--- no_error_log
[error]
[alert]



=== TEST 45: not discard body (content_by_lua exit 200)
--- config
    location = /foo {
        content_by_lua '
            -- njt.req.discard_body()
            njt.say("body: ", njt.var.request_body)
            njt.exit(200)
        ';
    }
    location = /bar {
        content_by_lua '
            njt.req.read_body()
            njt.say("body: ", njt.var.request_body)
        ';
    }
--- pipelined_requests eval
["POST /foo
hello, world",
"POST /bar
hiya, world"]
--- response_body eval
["body: nil\n",
"body: hiya, world\n",
]
--- error_code eval
[200, 200]
--- no_error_log
[error]
[alert]



=== TEST 46: not discard body (content_by_lua exit 201)
--- config
    location = /foo {
        content_by_lua '
            -- njt.req.discard_body()
            njt.say("body: ", njt.var.request_body)
            njt.exit(201)
        ';
    }
    location = /bar {
        content_by_lua '
            njt.req.read_body()
            njt.say("body: ", njt.var.request_body)
        ';
    }
--- pipelined_requests eval
["POST /foo
hello, world",
"POST /bar
hiya, world"]
--- response_body eval
["body: nil\n",
"body: hiya, world\n",
]
--- error_code eval
[200, 200]
--- no_error_log
[error]
[alert]



=== TEST 47: not discard body (content_by_lua exit 302)
--- config
    location = /foo {
        content_by_lua '
            -- njt.req.discard_body()
            -- njt.say("body: ", njt.var.request_body)
            njt.redirect("/blah")
        ';
    }
    location = /bar {
        content_by_lua '
            njt.req.read_body()
            njt.say("body: ", njt.var.request_body)
        ';
    }
--- pipelined_requests eval
["POST /foo
hello, world",
"POST /bar
hiya, world"]
--- response_body eval
[qr/302 Found/,
"body: hiya, world\n",
]
--- error_code eval
[302, 200]
--- no_error_log
[error]
[alert]



=== TEST 48: not discard body (custom error page)
--- config
    error_page 404 = /err;

    location = /foo {
        content_by_lua '
            njt.exit(404)
        ';
    }
    location = /err {
        content_by_lua 'njt.say("error")';
    }
--- pipelined_requests eval
["POST /foo
hello, world",
"POST /foo
hiya, world"]
--- response_body eval
["error\n",
"error\n",
]
--- error_code eval
[404, 404]
--- no_error_log
[error]
[alert]



=== TEST 49: get body data at log phase
--- config
    location = /test {
        content_by_lua_block {
            njt.req.read_body()
            njt.say(njt.req.get_body_data())
        }
        log_by_lua_block {
            njt.log(njt.WARN, "request body:", njt.req.get_body_data())
        }
    }
--- request
POST /test
hello, world
--- response_body
hello, world
--- error_log
request body:hello, world
--- no_error_log
[error]
[alert]



=== TEST 50: init & append & finish (content_length = 0)
--- config
    location /t {
        content_by_lua '
            local old_http_content_length = njt.var.http_content_length

            njt.req.read_body()
            njt.req.init_body()
            njt.req.append_body("he")
            njt.req.append_body("llo")
            njt.req.finish_body()

            njt.say("old content length: ", old_http_content_length)

            local data = njt.req.get_body_data()
            local data_file = njt.req.get_body_file()

            if not data and data_file then
                njt.say("no data in buf, go to data file")
            end

            njt.say("content length: ", njt.var.http_content_length)
        ';
    }
--- request
    GET /t
--- more_headers
Content-Length: 0
--- response_body
old content length: 0
content length: 5
--- no_error_log
[error]
[alert]



=== TEST 51: init & append & finish (init_body(0))
--- config
    location /t {
        content_by_lua '
            local old_http_content_length = njt.var.http_content_length

            njt.req.read_body()
            njt.req.init_body(0)
            njt.req.append_body("he")
            njt.req.append_body("llo")
            njt.req.finish_body()

            njt.say("old content length: ", old_http_content_length)

            local data = njt.req.get_body_data()
            local data_file = njt.req.get_body_file()

            if not data and data_file then
                njt.say("no data in buf, go to data file")
            end

            njt.say("content length: ", njt.var.http_content_length)
        ';
    }
--- request
    GET /t
--- more_headers
Content-Length: 0
--- response_body
old content length: 0
no data in buf, go to data file
content length: 5
--- no_error_log
[error]
[alert]



=== TEST 52: init & append & finish (client_body_buffer_size = 0)
--- http_config
    client_body_buffer_size 0;
--- config
    location /t {
        content_by_lua '
            njt.req.read_body()
            njt.req.init_body()
            njt.req.append_body("he")
            njt.req.append_body("llo")
            njt.req.finish_body()

            local data = njt.req.get_body_data()
            local data_file = njt.req.get_body_file()

            if not data and data_file then
                njt.say("no data in buf, go to data file")
            end

            njt.say("content length: ", njt.var.http_content_length)
        ';
    }
--- request
    GET /t
--- response_body
no data in buf, go to data file
content length: 5
--- no_error_log
[error]
[alert]
