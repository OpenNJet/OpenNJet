# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua;

#worker_connections(1014);
#master_process_enabled(1);
#log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 3 + 79);

#no_diff();
no_long_string();

run_tests();

__DATA__

=== TEST 1: set response content-type header
--- config
    location /read {
        content_by_lua '
            njt.header.content_type = "text/my-plain";
            njt.say("Hi");
        ';
    }
--- request
GET /read
--- response_headers
Content-Type: text/my-plain
--- response_body
Hi



=== TEST 2: set response content-type header
--- config
    location /read {
        content_by_lua '
            njt.header.content_length = "text/my-plain";
            njt.say("Hi");
        ';
    }
--- request
GET /read
--- response_body_like: 500 Internal Server Error
--- response_headers
Content-Type: text/html
--- error_code: 500



=== TEST 3: set response content-length header
--- config
    location /read {
        content_by_lua '
            njt.header.content_length = 3
            njt.say("Hello")
        ';
    }
--- request
GET /read
--- response_headers
Content-Length: 3
--- response_body chop
Hel



=== TEST 4: set response content-type header
--- config
    location /read {
        content_by_lua '
            njt.status = 302;
            njt.header["Location"] = "http://agentzh.org/foo";
        ';
    }
--- request
GET /read
--- response_headers
Location: http://agentzh.org/foo
--- response_body
--- error_code: 302



=== TEST 5: set response content-type header
--- config
    location /read {
        content_by_lua '
            njt.header.content_length = 3
            njt.header.content_length = nil
            njt.say("Hello")
        ';
    }
--- request
GET /read
--- response_headers
!Content-Length
--- response_body
Hello



=== TEST 6: set multi response content-type header
--- config
    location /read {
        content_by_lua '
            njt.header["X-Foo"] = {"a", "bc"}
            njt.say("Hello")
        ';
    }
--- request
GET /read
--- raw_response_headers_like chomp
X-Foo: a\r\n.*?X-Foo: bc\r\n
--- response_body
Hello



=== TEST 7: set response content-type header
--- config
    location /read {
        content_by_lua '
            njt.header.content_type = {"a", "bc"}
            njt.say("Hello")
        ';
    }
--- request
GET /read
--- response_headers
Content-Type: bc
--- response_body
Hello



=== TEST 8: set multi response content-type header and clears it
--- config
    location /read {
        content_by_lua '
            njt.header["X-Foo"] = {"a", "bc"}
            njt.header["X-Foo"] = {}
            njt.say("Hello")
        ';
    }
--- request
GET /read
--- response_headers
!X-Foo
--- response_body
Hello



=== TEST 9: set multi response content-type header and clears it
--- config
    location /read {
        content_by_lua '
            njt.header["X-Foo"] = {"a", "bc"}
            njt.header["X-Foo"] = nil
            njt.say("Hello")
        ';
    }
--- request
GET /read
--- response_headers
!X-Foo
--- response_body
Hello



=== TEST 10: set multi response content-type header (multiple times)
--- config
    location /read {
        content_by_lua '
            njt.header["X-Foo"] = {"a", "bc"}
            njt.header["X-Foo"] = {"a", "abc"}
            njt.say("Hello")
        ';
    }
--- request
GET /read
--- raw_response_headers_like chomp
X-Foo: a\r\n.*?X-Foo: abc\r\n
--- response_body
Hello



=== TEST 11: clear first, then add
--- config
    location /lua {
        content_by_lua '
            njt.header["Foo"] = {}
            njt.header["Foo"] = {"a", "b"}
            njt.send_headers()
        ';
    }
--- request
    GET /lua
--- raw_response_headers_like eval
".*Foo: a\r
Foo: b.*"
--- response_body



=== TEST 12: first add, then clear, then add again
--- config
    location /lua {
        content_by_lua '
            njt.header["Foo"] = {"c", "d"}
            njt.header["Foo"] = {}
            njt.header["Foo"] = {"a", "b"}
            njt.send_headers()
        ';
    }
--- request
    GET /lua
--- raw_response_headers_like eval
".*Foo: a\r
Foo: b.*"
--- response_body



=== TEST 13: names are the same in the beginning (one value per key)
--- config
    location /lua {
        content_by_lua '
            njt.header["Foox"] = "barx"
            njt.header["Fooy"] = "bary"
            njt.send_headers()
        ';
    }
--- request
    GET /lua
--- response_headers
Foox: barx
Fooy: bary



=== TEST 14: names are the same in the beginning (multiple values per key)
--- config
    location /lua {
        content_by_lua '
            njt.header["Foox"] = {"conx1", "conx2" }
            njt.header["Fooy"] = {"cony1", "cony2" }
            njt.send_headers()
        ';
    }
--- request
    GET /lua
--- response_headers
Foox: conx1, conx2
Fooy: cony1, cony2



=== TEST 15: set header after njt.print
--- config
    location /lua {
        default_type "text/plain";
        content_by_lua '
            njt.print("hello")
            njt.header.content_type = "text/foo"
        ';
    }
--- request
    GET /lua
--- response_body chop
hello
--- error_log
attempt to set njt.header.HEADER after sending out response headers
--- no_error_log eval
["alert", "warn"]



=== TEST 16: get content-type header after njt.print
--- config
    location /lua {
        default_type "text/my-plain";
        content_by_lua '
            njt.print("hello, ")
            njt.say(njt.header.content_type)
        ';
    }
--- request
    GET /lua
--- response_headers
Content-Type: text/my-plain
--- response_body
hello, text/my-plain



=== TEST 17: get content-length header
--- config
    location /lua {
        content_by_lua '
            njt.header.content_length = 2;
            njt.say(njt.header.content_length);
        ';
    }
--- request
    GET /lua
--- response_headers
Content-Length: 2
--- response_body
2



=== TEST 18: get content-length header
--- config
    location /lua {
        content_by_lua '
            njt.header.foo = "bar";
            njt.say(njt.header.foo);
        ';
    }
--- request
    GET /lua
--- response_headers
foo: bar
--- response_body
bar



=== TEST 19: get content-length header (proxy)
--- config
    location /main {
        set $footer '';
        proxy_pass http://127.0.0.1:$server_port/echo;
        header_filter_by_lua '
            njt.var.footer = njt.header.content_length
        ';
        echo_after_body $footer;
    }
    location /echo {
        content_by_lua 'njt.print("Hello")';
    }
--- request
    GET /main
--- response_headers
!Content-Length
--- response_body
Hello5



=== TEST 20: set and get content-length header (proxy)
--- config
    location /main {
        set $footer '';
        proxy_pass http://127.0.0.1:$server_port/echo;
        header_filter_by_lua '
            njt.header.content_length = 27
            njt.var.footer = njt.header.content_length
        ';
        echo_after_body $footer;
    }
    location /echo {
        content_by_lua 'njt.print("Hello")';
    }
--- request
    GET /main
--- response_headers
!Content-Length
--- response_body
Hello27



=== TEST 21: get content-type header (proxy)
--- config
    location /main {
        set $footer '';
        proxy_pass http://127.0.0.1:$server_port/echo;
        header_filter_by_lua '
            njt.var.footer = njt.header.content_type
        ';
        echo_after_body $footer;
    }
    location /echo {
        default_type 'abc/foo';
        content_by_lua 'njt.print("Hello")';
    }
--- request
    GET /main
--- response_headers
Content-Type: abc/foo
--- response_body
Helloabc/foo



=== TEST 22: set and get content-type header (proxy)
--- config
    location /main {
        set $footer '';
        proxy_pass http://127.0.0.1:$server_port/echo;
        header_filter_by_lua '
            njt.header.content_type = "text/blah"
            njt.var.footer = njt.header.content_type
        ';
        echo_after_body $footer;
    }
    location /echo {
        default_type 'abc/foo';
        content_by_lua 'njt.print("Hello")';
    }
--- request
    GET /main
--- response_headers
Content-Type: text/blah
--- response_body
Hellotext/blah



=== TEST 23: get user header (proxy)
--- config
    location /main {
        set $footer '';
        proxy_pass http://127.0.0.1:$server_port/echo;
        header_filter_by_lua '
            njt.var.footer = njt.header.baz
        ';
        echo_after_body $footer;
    }
    location /echo {
        content_by_lua '
            njt.header.baz = "bah"
            njt.print("Hello")
        ';
    }
--- request
    GET /main
--- response_headers
baz: bah
--- response_body
Hellobah



=== TEST 24: set and get user header (proxy)
--- config
    location /main {
        set $footer '';
        proxy_pass http://127.0.0.1:$server_port/echo;
        header_filter_by_lua '
            njt.header.baz = "foo"
            njt.var.footer = njt.header.baz
        ';
        echo_after_body $footer;
    }
    location /echo {
        content_by_lua '
            njt.header.baz = "bah"
            njt.print("Hello")
        ';
    }
--- request
    GET /main
--- response_headers
baz: foo
--- response_body
Hellofoo



=== TEST 25: get multiple user header (proxy)
--- config
    location /main {
        set $footer '';
        proxy_pass http://127.0.0.1:$server_port/echo;
        header_filter_by_lua '
            njt.var.footer = table.concat(njt.header.baz, ", ")
        ';
        echo_after_body $footer;
    }
    location /echo {
        content_by_lua '
            njt.header.baz = {"bah", "blah"}
            njt.print("Hello")
        ';
    }
--- request
    GET /main
--- raw_response_headers_like eval
"baz: bah\r
.*?baz: blah"
--- response_body
Hellobah, blah



=== TEST 26: set and get multiple user header (proxy)
--- config
    location /main {
        set $footer '';
        proxy_pass http://127.0.0.1:$server_port/echo;
        header_filter_by_lua '
            njt.header.baz = {"foo", "baz"}
            njt.var.footer = table.concat(njt.header.baz, ", ")
        ';
        echo_after_body $footer;
    }
    location /echo {
        content_by_lua '
            njt.header.baz = {"bah", "hah"}
            njt.print("Hello")
        ';
    }
--- request
    GET /main
--- raw_response_headers_like eval
"baz: foo\r
.*?baz: baz"
--- response_body
Hellofoo, baz



=== TEST 27: get non-existent header
--- config
    location /lua {
        content_by_lua '
            njt.say(njt.header.foo);
        ';
    }
--- request
    GET /lua
--- response_headers
!foo
--- response_body
nil



=== TEST 28: get non-existent header
--- config
    location /lua {
        content_by_lua '
            njt.header.foo = {"bah", "baz", "blah"}
            njt.header.foo = nil
            njt.say(njt.header.foo);
        ';
    }
--- request
    GET /lua
--- response_headers
!foo
--- response_body
nil



=== TEST 29: override domains in the cookie
--- config
    location /foo {
        echo hello;
        add_header Set-Cookie 'foo=bar; Domain=backend.int';
        add_header Set-Cookie 'baz=bah; Domain=backend.int';
    }

    location /main {
        proxy_pass http://127.0.0.1:$server_port/foo;
        header_filter_by_lua '
            local cookies = njt.header.set_cookie
            if not cookies then return end
            if type(cookies) ~= "table" then cookies = {cookies} end
            local newcookies = {}
            for i, val in ipairs(cookies) do
                local newval = string.gsub(val, "([dD]omain)=[%w_-\\\\.]+",
                          "%1=external.domain.com")
                table.insert(newcookies, newval)
            end
            njt.header.set_cookie = newcookies
        ';
    }
--- request
    GET /main
--- response_headers
Set-Cookie: foo=bar; Domain=external.domain.com, baz=bah; Domain=external.domain.com
--- response_body
hello



=== TEST 30: set single value to cache-control
--- config
    location /lua {
        content_by_lua '
            njt.header.cache_control = "private"
            njt.say("Cache-Control: ", njt.var.sent_http_cache_control)
        ';
    }
--- request
    GET /lua
--- response_headers
Cache-Control: private
--- response_body
Cache-Control: private



=== TEST 31: set multi values to cache-control
--- config
    location /lua {
        content_by_lua '
            njt.header.cache_control = { "private", "no-store" }
            njt.say("Cache-Control: ", njt.var.sent_http_cache_control)
        ';
    }
--- request
    GET /lua
--- response_headers
Cache-Control: private, no-store
--- response_body_like chop
^Cache-Control: private[;,] no-store$



=== TEST 32: set single value to Link header
--- config
    location = /t {
        content_by_lua_block {
            njt.header.link = "</foo.jpg>; rel=preload"
            njt.say("Link: ", njt.var.sent_http_link)
        }
    }
--- request
GET /t
--- response_headers
Link: </foo.jpg>; rel=preload
--- response_body
Link: </foo.jpg>; rel=preload



=== TEST 33: set multi values to Link header
--- config
    location = /t {
        content_by_lua_block {
            njt.header.link = {
                "</foo.jpg>; rel=preload",
                "</bar.css>; rel=preload; as=style"
            }

            njt.say("Link: ", njt.var.sent_http_link)
        }
    }
--- request
GET /t
--- response_headers
Link: </foo.jpg>; rel=preload, </bar.css>; rel=preload; as=style
--- response_body_like chop
^Link: </foo.jpg>; rel=preload[;,] </bar.css>; rel=preload; as=style$
--- skip_nginx: 3: < 1.13.9



=== TEST 34: set multi values to cache-control and override it with a single value
--- config
    location /lua {
        content_by_lua '
            njt.header.cache_control = { "private", "no-store" }
            njt.header.cache_control = { "no-cache" }
            njt.say("Cache-Control: ", njt.var.sent_http_cache_control)
            njt.say("Cache-Control: ", njt.header.cache_control)
        ';
    }
--- request
    GET /lua
--- response_headers
Cache-Control: no-cache
--- response_body
Cache-Control: no-cache
Cache-Control: no-cache



=== TEST 35: set multi values to Link header and override it with a single value
--- config
    location /lua {
        content_by_lua_block {
            njt.header.link = {
                "</foo.jpg>; rel=preload",
                "</bar.css>; rel=preload; as=style"
            }
            njt.header.link = "</hello.jpg>; rel=preload"
            njt.say("Link: ", njt.var.sent_http_link)
            njt.say("Link: ", njt.header.link)
        }
    }
--- request
    GET /lua
--- response_headers
Link: </hello.jpg>; rel=preload
--- response_body
Link: </hello.jpg>; rel=preload
Link: </hello.jpg>; rel=preload



=== TEST 36: set multi values to cache-control and override it with multiple values
--- config
    location /lua {
        content_by_lua '
            njt.header.cache_control = { "private", "no-store" }
            njt.header.cache_control = { "no-cache", "blah", "foo" }
            njt.say("Cache-Control: ", njt.var.sent_http_cache_control)
            njt.say("Cache-Control: ", table.concat(njt.header.cache_control, ", "))
        ';
    }
--- request
    GET /lua
--- response_headers
Cache-Control: no-cache, blah, foo
--- response_body_like chop
^Cache-Control: no-cache[;,] blah[;,] foo
Cache-Control: no-cache[;,] blah[;,] foo$
--- no_error_log
[error]



=== TEST 37: set multi values to Link header and override it with multiple values
--- config
    location /lua {
        content_by_lua_block {
            njt.header.link = {
                "</foo.jpg>; rel=preload",
                "</bar.css>; rel=preload; as=style"
            }
            njt.header.link = {
                "</foo.jpg>; rel=preload",
                "</hello.css>; rel=preload",
                "</bar.css>; rel=preload; as=style"
            }
            njt.say("Link: ", njt.var.sent_http_link)
            njt.say("Link: ", table.concat(njt.header.link, ", "))
        }
    }
--- request
    GET /lua
--- response_headers
Link: </foo.jpg>; rel=preload, </hello.css>; rel=preload, </bar.css>; rel=preload; as=style
--- response_body_like chop
^Link: </foo.jpg>; rel=preload[;,] </hello.css>; rel=preload[;,] </bar.css>; rel=preload; as=style
Link: </foo.jpg>; rel=preload[;,] </hello.css>; rel=preload[;,] </bar.css>; rel=preload; as=style$
--- no_error_log
[error]
--- skip_nginx: 4: < 1.13.9



=== TEST 38: set the www-authenticate response header
--- config
    location /lua {
        content_by_lua '
            njt.header.www_authenticate = "blah"
            njt.say("WWW-Authenticate: ", njt.var.sent_http_www_authenticate)
        ';
    }
--- request
    GET /lua
--- response_headers
WWW-Authenticate: blah
--- response_body
WWW-Authenticate: blah



=== TEST 39: set and clear the www-authenticate response header
--- config
    location /lua {
        content_by_lua '
            njt.header.foo = "blah"
            njt.header.foo = nil
            njt.say("Foo: ", njt.var.sent_http_foo)
        ';
    }
--- request
    GET /lua
--- response_headers
!Foo
--- response_body
Foo: nil



=== TEST 40: set multi values to cache-control and override it with multiple values (to reproduce a bug)
--- config
    location /lua {
        content_by_lua '
            njt.header.cache_control = { "private", "no-store", "foo", "bar", "baz" }
            njt.header.cache_control = {}
            njt.send_headers()
            njt.say("Cache-Control: ", njt.var.sent_http_cache_control)
        ';
        add_header Cache-Control "blah";
    }
--- request
    GET /lua
--- response_headers
Cache-Control: blah
--- response_body
Cache-Control: blah



=== TEST 41: set last-modified and return 304
--- config
  location /lua {
        content_by_lua '
            njt.header["Last-Modified"] = njt.http_time(1290079655)
            njt.say(njt.header["Last-Modified"])
        ';
    }
--- request
    GET /lua
--- more_headers
If-Modified-Since: Thu, 18 Nov 2010 11:27:35 GMT
--- response_headers
Last-Modified: Thu, 18 Nov 2010 11:27:35 GMT
--- error_code: 304



=== TEST 42: set last-modified and return 200
--- config
  location /lua {
        content_by_lua '
            njt.header["Last-Modified"] = njt.http_time(1290079655)
            njt.say(njt.header["Last-Modified"])
        ';
    }
--- request
    GET /lua
--- more_headers
If-Modified-Since: Thu, 18 Nov 2010 11:27:34 GMTT
--- response_headers
Last-Modified: Thu, 18 Nov 2010 11:27:35 GMT
--- response_body
Thu, 18 Nov 2010 11:27:35 GMT



=== TEST 43: set response content-encoding header should bypass njt_http_gzip_filter_module
--- config
    default_type text/plain;
    gzip             on;
    gzip_min_length  1;
    gzip_types       text/plain;
    location /read {
        content_by_lua '
            njt.header.content_encoding = "gzip";
            njt.say("Hello, world, my dear friend!");
        ';
    }
--- request
GET /read
--- more_headers
Accept-Encoding: gzip
--- response_headers
Content-Encoding: gzip
--- no_error_log
[error]
http gzip filter
--- response_body
Hello, world, my dear friend!



=== TEST 44: no transform underscores (write)
--- config
    lua_transform_underscores_in_response_headers off;
    location = /t {
        content_by_lua '
            njt.header.foo_bar = "Hello"
            njt.say(njt.header.foo_bar)
            njt.say(njt.header["foo-bar"])
        ';
    }
--- request
    GET /t
--- raw_response_headers_like eval
"\r\nfoo_bar: Hello\r\n"
--- response_body
Hello
nil



=== TEST 45: with transform underscores (write)
--- config
    lua_transform_underscores_in_response_headers on;
    location = /t {
        content_by_lua '
            njt.header.foo_bar = "Hello"
            njt.say(njt.header.foo_bar)
            njt.say(njt.header["foo-bar"])
        ';
    }
--- request
    GET /t
--- raw_response_headers_like eval
"\r\nfoo-bar: Hello\r\n"
--- response_body
Hello
Hello



=== TEST 46: github issue #199: underscores in lua variables
--- config
    location /read {
        content_by_lua '
          njt.header.content_type = "text/my-plain"

          local results = {}
          results.something = "hello"
          results.content_type = "anything"
          results.something_else = "hi"

          local arr = {}
          for k in pairs(results) do table.insert(arr, k) end
          table.sort(arr)
          for i, k in ipairs(arr) do
            njt.say(k .. ": " .. results[k])
          end
        ';
    }
--- request
GET /read
--- response_headers
Content-Type: text/my-plain

--- response_body
content_type: anything
something: hello
something_else: hi
--- no_error_log
[error]



=== TEST 47: set multiple response header
--- config
    location /read {
        content_by_lua '
            for i = 1, 50 do
                njt.header["X-Direct-" .. i] = "text/my-plain-" .. i;
            end

            njt.say(njt.header["X-Direct-50"]);
        ';
    }
--- request
GET /read
--- response_body
text/my-plain-50
--- no_error_log
[error]



=== TEST 48: set multiple response header and then reset and then clear
--- config
    location /read {
        content_by_lua '
            for i = 1, 50 do
                njt.header["X-Direct-" .. i] = "text/my-plain-" .. i;
            end

            for i = 1, 50 do
                njt.header["X-Direct-" .. i] = "text/my-plain"
            end

            for i = 1, 50 do
                njt.header["X-Direct-" .. i] = nil
            end

            njt.say("ok");
        ';
    }
--- request
GET /read
--- response_body
ok
--- no_error_log
[error]
--- timeout: 10



=== TEST 49: set response content-type header for multiple times
--- config
    location /read {
        content_by_lua '
            njt.header.content_type = "text/my-plain";
            njt.header.content_type = "text/my-plain-2";
            njt.say("Hi");
        ';
    }
--- request
GET /read
--- response_headers
Content-Type: text/my-plain-2
--- response_body
Hi



=== TEST 50: set Last-Modified response header for multiple times
--- config
    location /read {
        content_by_lua '
            njt.header.last_modified = njt.http_time(1290079655)
            njt.header.last_modified = njt.http_time(1290079654)
            njt.say("ok");
        ';
    }
--- request
GET /read
--- response_headers
Last-Modified: Thu, 18 Nov 2010 11:27:34 GMT
--- response_body
ok



=== TEST 51: set Last-Modified response header and then clear
--- config
    location /read {
        content_by_lua '
            njt.header.last_modified = njt.http_time(1290079655)
            njt.header.last_modified = nil
            njt.say("ok");
        ';
    }
--- request
GET /read
--- response_headers
!Last-Modified
--- response_body
ok



=== TEST 52: github #20: segfault caused by the nasty optimization in the nginx core (write)
--- config
    location = /t/ {
        header_filter_by_lua '
            njt.header.foo = 1
        ';
        proxy_pass http://127.0.0.1:$server_port;
    }
--- request
GET /t
--- more_headers
Foo: bar
Bah: baz
--- response_headers
Location: http://localhost:$ServerPort/t/
--- response_body_like: 301 Moved Permanently
--- error_code: 301
--- no_error_log
[error]



=== TEST 53: github #20: segfault caused by the nasty optimization in the nginx core (read)
--- config
    location = /t/ {
        header_filter_by_lua '
            local v = njt.header.foo
        ';
        proxy_pass http://127.0.0.1:$server_port;
    }
--- request
GET /t
--- more_headers
Foo: bar
Bah: baz
--- response_body_like: 301 Moved Permanently
--- response_headers
Location: http://localhost:$ServerPort/t/
--- error_code: 301
--- no_error_log
[error]



=== TEST 54: github #20: segfault caused by the nasty optimization in the nginx core (read Location)
--- config
    location = /t/ {
        header_filter_by_lua '
            njt.header.Foo = njt.header.location
        ';
        proxy_pass http://127.0.0.1:$server_port;
    }
--- request
GET /t
--- more_headers
Foo: bar
Bah: baz
--- response_headers
Location: http://localhost:$ServerPort/t/
Foo: /t/
--- response_body_like: 301 Moved Permanently
--- error_code: 301
--- no_error_log
[error]



=== TEST 55: github #20: segfault caused by the nasty optimization in the nginx core (set Foo and read Location)
--- config
    location = /t/ {
        header_filter_by_lua '
            njt.header.Foo = 3
            njt.header.Foo = njt.header.location
        ';
        proxy_pass http://127.0.0.1:$server_port;
    }
--- request
GET /t
--- more_headers
Foo: bar
Bah: baz
--- response_headers
Location: http://localhost:$ServerPort/t/
Foo: /t/
--- response_body_like: 301 Moved Permanently
--- error_code: 301
--- no_error_log
[error]



=== TEST 56: case sensitive cache-control header
--- config
    location /lua {
        content_by_lua '
            njt.header["cache-Control"] = "private"
            njt.say("Cache-Control: ", njt.var.sent_http_cache_control)
        ';
    }
--- request
    GET /lua
--- raw_response_headers_like chop
cache-Control: private
--- response_body
Cache-Control: private



=== TEST 57: case sensitive Link header
--- config
    location /lua {
        content_by_lua_block {
            njt.header["link"] = "</foo.jpg>; rel=preload"
            njt.say("Link: ", njt.var.sent_http_link)
        }
    }
--- request
    GET /lua
--- raw_response_headers_like chop
link: </foo.jpg>; rel=preload
--- response_body
Link: </foo.jpg>; rel=preload



=== TEST 58: clear Cache-Control when there was no Cache-Control
--- config
    location /lua {
        content_by_lua '
            njt.header["Cache-Control"] = nil
            njt.say("Cache-Control: ", njt.var.sent_http_cache_control)
        ';
    }
--- request
    GET /lua
--- raw_response_headers_unlike eval
qr/Cache-Control/i
--- response_body
Cache-Control: nil



=== TEST 59: clear Link header when there was no Link
--- config
    location /lua {
        content_by_lua_block {
            njt.header["Link"] = nil
            njt.say("Link: ", njt.var.sent_http_link)
        }
    }
--- request
    GET /lua
--- raw_response_headers_unlike eval
qr/Link/i
--- response_body
Link: nil



=== TEST 60: set response content-type header
--- config
    location /read {
        content_by_lua '
            local s = "content_type"
            local v = njt.header[s]
            njt.say("s = ", s)
        ';
    }
--- request
GET /read
--- response_body
s = content_type

--- no_error_log
[error]



=== TEST 61: set a number header name
--- config
    location /lua {
        content_by_lua '
            njt.header[32] = "private"
            njt.say("32: ", njt.var.sent_http_32)
        ';
    }
--- request
    GET /lua
--- response_headers
32: private
--- response_body
32: private
--- no_error_log
[error]



=== TEST 62: set a number header name (in a table value)
--- config
    location /lua {
        content_by_lua '
            njt.header.foo = {32}
            njt.say("foo: ", njt.var.sent_http_foo)
        ';
    }
--- request
    GET /lua
--- response_headers
foo: 32
--- response_body
foo: 32
--- no_error_log
[error]



=== TEST 63: random access resp headers
--- config
    location /resp-header {
        content_by_lua '
            njt.header["Foo"] = "bar"
            njt.header["Bar"] = "baz"
            local headers, err = njt.resp.get_headers()
            if err then
                njt.log(njt.ERR, "err: ", err)
                return njt.exit(500)
            end

            njt.say("Foo: ", headers["Foo"] or "nil")
            njt.say("foo: ", headers["foo"] or "nil")
            njt.say("Bar: ", headers["Bar"] or "nil")

            headers, err = njt.resp.get_headers()
            if err then
                njt.log(njt.ERR, "err: ", err)
                return njt.exit(500)
            end

            njt.say("bar: ", headers["bar"] or "nil")
        ';
    }
--- request
GET /resp-header
--- response_headers
Foo: bar
Bar: baz
--- response_body
Foo: bar
foo: bar
Bar: baz
bar: baz
--- no_error_log
[error]



=== TEST 64: iterating through raw resp headers
--- config
    location /resp-header {
        content_by_lua '
            njt.header["Foo"] = "bar"
            njt.header["Bar"] = "baz"

            local headers, err = njt.resp.get_headers(nil, true)
            if err then
                njt.log(njt.ERR, "err: ", err)
                return njt.exit(500)
            end

            local h = {}
            for k, v in pairs(headers) do
                h[k] = v
            end
            njt.say("Foo: ", h["Foo"] or "nil")
            njt.say("foo: ", h["foo"] or "nil")
            njt.say("Bar: ", h["Bar"] or "nil")
            njt.say("bar: ", h["bar"] or "nil")
        ';
    }
--- request
GET /resp-header
--- response_headers
Foo: bar
Bar: baz
--- response_body
Foo: bar
foo: nil
Bar: baz
bar: nil



=== TEST 65: removed response headers
--- config
    location /resp-header {
        content_by_lua '
            njt.header["Foo"] = "bar"
            njt.header["Foo"] = nil
            njt.header["Bar"] = "baz"

            local headers, err = njt.resp.get_headers()
            if err then
                njt.log(njt.ERR, "err: ", err)
                return njt.exit(500)
            end

            njt.say("Foo: ", headers["Foo"] or "nil")
            njt.say("foo: ", headers["foo"] or "nil")
            njt.say("Bar: ", headers["Bar"] or "nil")
            njt.say("bar: ", headers["bar"] or "nil")
        ';
    }
--- request
GET /resp-header
--- response_headers
!Foo
Bar: baz
--- response_body
Foo: nil
foo: nil
Bar: baz
bar: baz



=== TEST 66: built-in Content-Type header
--- config
    location = /t {
        content_by_lua '
            njt.say("hi")
        ';

        header_filter_by_lua '
            local hs, err = njt.resp.get_headers()
            if err then
                njt.log(njt.ERR, "err: ", err)
                return njt.exit(500)
            end

            print("my Content-Type: ", hs["Content-Type"])
            print("my content-type: ", hs["content-type"])
            print("my content_type: ", hs["content_type"])
        ';
    }
--- request
    GET /t
--- response_body
hi
--- no_error_log
[error]
[alert]
--- error_log
my Content-Type: text/plain
my content-type: text/plain
my content_type: text/plain



=== TEST 67: built-in Content-Length header
--- config
    location = /t {
        content_by_lua '
            njt.say("hi")
        ';

        header_filter_by_lua '
            local hs, err = njt.resp.get_headers()
            if err then
                njt.log(njt.ERR, "err: ", err)
                return njt.exit(500)
            end

            print("my Content-Length: ", hs["Content-Length"])
            print("my content-length: ", hs["content-length"])
            print("my content_length: ", hs.content_length)
        ';
    }
--- request
    GET /t HTTP/1.0
--- response_body
hi
--- no_error_log
[error]
[alert]
--- error_log
my Content-Length: 3
my content-length: 3
my content_length: 3



=== TEST 68: built-in Connection header
--- config
    location = /t {
        content_by_lua '
            njt.say("hi")
        ';

        header_filter_by_lua '
            local hs, err = njt.resp.get_headers()
            if err then
                njt.log(njt.ERR, "err: ", err)
                return njt.exit(500)
            end

            print("my Connection: ", hs["Connection"])
            print("my connection: ", hs["connection"])
        ';
    }
--- request
    GET /t HTTP/1.0
--- response_body
hi
--- no_error_log
[error]
[alert]
--- error_log
my Connection: close
my connection: close



=== TEST 69: built-in Transfer-Encoding header (chunked)
--- config
    location = /t {
        content_by_lua '
            njt.say("hi")
        ';

        body_filter_by_lua '
            local hs, err = njt.resp.get_headers()
            if err then
                njt.log(njt.ERR, "err: ", err)
                return njt.exit(500)
            end

            print("my Transfer-Encoding: ", hs["Transfer-Encoding"])
            print("my transfer-encoding: ", hs["transfer-encoding"])
            print("my transfer_encoding: ", hs.transfer_encoding)
        ';
    }
--- request
    GET /t
--- response_body
hi
--- no_error_log
[error]
[alert]
--- error_log
my Transfer-Encoding: chunked
my transfer-encoding: chunked



=== TEST 70: built-in Transfer-Encoding header (none)
--- config
    location = /t {
        content_by_lua '
            njt.say("hi")
        ';

        body_filter_by_lua '
            local hs, err = njt.resp.get_headers()
            if err then
                njt.log(njt.ERR, "err: ", err)
                return njt.exit(500)
            end

            print("my Transfer-Encoding: ", hs["Transfer-Encoding"])
            print("my transfer-encoding: ", hs["transfer-encoding"])
            print("my transfer_encoding: ", hs.transfer_encoding)
        ';
    }
--- request
    GET /t HTTP/1.0
--- response_body
hi
--- no_error_log
[error]
[alert]
--- error_log
my Transfer-Encoding: nil
my transfer-encoding: nil
my transfer_encoding: nil



=== TEST 71: set Location (no host)
--- config
    location = /t {
        content_by_lua '
            njt.header.location = "/foo/bar"
            return njt.exit(301)
        ';
    }
--- request
GET /t
--- response_headers
Location: /foo/bar
--- response_body_like: 301 Moved Permanently
--- error_code: 301
--- no_error_log
[error]



=== TEST 72: set Location (with host)
--- config
    location = /t {
        content_by_lua '
            njt.header.location = "http://test.com/foo/bar"
            return njt.exit(301)
        ';
    }
--- request
GET /t
--- response_headers
Location: http://test.com/foo/bar
--- response_body_like: 301 Moved Permanently
--- error_code: 301
--- no_error_log
[error]



=== TEST 73: njt.header["Content-Type"] with njt_gzip
--- config
    gzip             on;
    gzip_min_length  1;
    location = /test2 {
        content_by_lua '
            njt.header["Content-Type"] = "text/html; charset=utf-8"
            njt.say("test")
        ';
    }
--- request
GET /test2
--- more_headers
Accept-Encoding: gzip
--- response_headers
Content-Encoding: gzip
Content-Type: text/html; charset=utf-8
--- response_body_like chomp
[^[:ascii:]]+
--- no_error_log
[error]



=== TEST 74: njt.header["Content-Type"] with "; blah"
--- config
    location = /test2 {
        content_by_lua '
            njt.header["Content-Type"] = "; blah"
            njt.say("test")
        ';
    }
--- request
GET /test2
--- response_headers
!Content-Encoding
Content-Type: ; blah
--- response_body
test
--- no_error_log
[error]



=== TEST 75: exceeding max header limit (default 100)
--- config
    location /resp-header {
        content_by_lua_block {
            for i = 1, 100 do
                njt.header["Foo" .. i] = "Foo"
            end

            local headers, err = njt.resp.get_headers()
            if err then
                njt.say("err: ", err)
            end

            local cnt = 0
            for k, v in pairs(headers) do
                cnt = cnt + 1
            end

            njt.say("found ", cnt, " resp headers");
        }
    }
--- request
GET /resp-header
--- response_body
err: truncated
found 100 resp headers
--- no_error_log
[error]
--- log_level: debug
--- error_log
lua exceeding response header limit 101 > 100



=== TEST 76: NOT exceeding max header limit (default 100)
--- config
    location /resp-header {
        content_by_lua_block {
            for i = 1, 99 do
                njt.header["Foo" .. i] = "Foo"
            end

            local headers, err = njt.resp.get_headers()
            if err then
                njt.say("err: ", err)
            end

            local cnt = 0
            for k, v in pairs(headers) do
                cnt = cnt + 1
            end

            njt.say("found ", cnt, " resp headers");
        }
    }
--- request
GET /resp-header
--- response_body
found 100 resp headers
--- no_error_log
[error]
lua exceeding response header limit
--- log_level: debug



=== TEST 77: exceeding max header limit (custom limit, 3)
--- config
    location /resp-header {
        content_by_lua_block {
            for i = 1, 3 do
                njt.header["Foo" .. i] = "Foo"
            end

            local headers, err = njt.resp.get_headers(3)
            if err then
                njt.say("err: ", err)
            end

            local cnt = 0
            for k, v in pairs(headers) do
                cnt = cnt + 1
            end

            njt.say("found ", cnt, " resp headers");
        }
    }
--- request
GET /resp-header
--- response_body
err: truncated
found 3 resp headers
--- no_error_log
[error]
--- error_log
lua exceeding response header limit 4 > 3
--- log_level: debug



=== TEST 78: NOT exceeding max header limit (custom limit, 3)
--- config
    location /resp-header {
        content_by_lua_block {
            for i = 1, 2 do
                njt.header["Foo" .. i] = "Foo"
            end

            local headers, err = njt.resp.get_headers(3)
            if err then
                njt.say("err: ", err)
            end

            local cnt = 0
            for k, v in pairs(headers) do
                cnt = cnt + 1
            end

            njt.say("found ", cnt, " resp headers");
        }
    }
--- request
GET /resp-header
--- response_body
found 3 resp headers
--- no_error_log
[error]
lua exceeding response header limit



=== TEST 79: return nil if Content-Type is not set yet
--- config
    location /t {
        default_type text/html;
        content_by_lua_block {
            njt.log(njt.WARN, "Content-Type: ", njt.header["content-type"])
            njt.say("Content-Type: ", njt.header["content-type"])
        }
    }
--- request
GET /t
--- response_headers
Content-Type: text/html
--- response_body
Content-Type: nil
--- no_error_log
[error]
--- error_log
Content-Type: nil



=== TEST 80: don't generate Content-Type when setting other response header
--- config
    location = /backend {
        content_by_lua_block {
            njt.say("foo")
        }
        header_filter_by_lua_block {
            njt.header.content_type = nil
        }
    }

    location = /t {
        default_type text/html;
        rewrite_by_lua_block {
            njt.header.blah = "foo"
        }
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend;
    }
--- request
GET /t
--- response_body
foo
--- response_headers
blah: foo
!Content-Type
--- no_error_log
[error]



=== TEST 81: don't generate Content-Type when getting other response header
--- config
    location = /backend {
        content_by_lua_block {
            njt.say("foo")
        }
        header_filter_by_lua_block {
            njt.header.content_type = nil
        }
    }

    location = /t {
        default_type text/html;
        rewrite_by_lua_block {
            local h = njt.header.content_length
        }
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend;
    }
--- request
GET /t
--- response_body
foo
--- response_headers
!Content-Type
--- no_error_log
[error]



=== TEST 82: don't generate Content-Type when getting it
--- config
    location = /backend {
        content_by_lua_block {
            njt.say("foo")
        }
        header_filter_by_lua_block {
            njt.header.content_type = nil
        }
    }

    location /t {
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend;
        header_filter_by_lua_block {
            njt.log(njt.WARN, "Content-Type: ", njt.header["content-type"])
        }
    }
--- request
GET /t
--- response_body
foo
--- response_headers
!Content-Type
--- no_error_log
[error]
--- error_log
Content-Type: nil



=== TEST 83: generate default Content-Type when setting other response header
--- config
    location = /t {
        default_type text/html;
        content_by_lua_block {
            njt.header.blah = "foo"
            njt.say("foo")
        }
    }
--- request
GET /t
--- response_body
foo
--- response_headers
blah: foo
Content-Type: text/html
--- no_error_log
[error]



=== TEST 84: don't generate Content-Type when calling njt.resp.get_headers()
--- config
    location = /backend {
        content_by_lua_block {
            njt.say("foo")
        }
        header_filter_by_lua_block {
            njt.header.content_type = nil
        }
    }

    location /t {
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend;
        header_filter_by_lua_block {
            local h, err = njt.resp.get_headers()
            if err then
                njt.log(njt.ERR, "err: ", err)
                return
            end

            njt.log(njt.WARN, "Content-Type: ", h["content-type"])
        }
    }
--- request
GET /t
--- response_body
foo
--- response_headers
!Content-Type
--- no_error_log
[error]
--- error_log
Content-Type: nil



=== TEST 85: don't generate default Content-Type when Content-Type is cleared
--- config
    location = /t {
        default_type text/html;
        content_by_lua_block {
            njt.header["Content-Type"] = nil
            njt.say("foo")
        }
    }
--- request
GET /t
--- response_body
foo
--- response_headers
!Content-Type
--- no_error_log
[error]



=== TEST 86: don't generate default Content-Type when Content-Type is set
--- config
    location = /t {
        default_type text/html;
        content_by_lua_block {
            njt.header["Content-Type"] = "application/json"
            njt.say("foo")
        }
    }
--- request
GET /t
--- response_body
foo
--- response_headers
Content-Type: application/json
--- no_error_log
[error]



=== TEST 87: unsafe header value (with '\r')
--- config
    location = /t {
        content_by_lua_block {
            njt.header.header = "value\rfoo:bar\nbar:foo"
            njt.say("foo")
        }
    }
--- request
GET /t
--- response_headers
header: value%0Dfoo:bar%0Abar:foo
foo:
bar:
--- no_error_log
[error]



=== TEST 88: unsafe header value (with '\n')
--- config
    location = /t {
        content_by_lua_block {
            njt.header.header = "value\nfoo:bar\rbar:foo"
            njt.say("foo")
        }
    }
--- request
GET /t
--- response_headers
header: value%0Afoo:bar%0Dbar:foo
foo:
bar:
--- no_error_log
[error]



=== TEST 89: unsafe header name (with '\r')
--- config
    location = /t {
        content_by_lua_block {
            njt.header["header: value\rfoo:bar\nbar:foo"] = "xx"
            njt.say("foo")
        }
    }
--- request
GET /t
--- response_headers
header%3A%20value%0Dfoo%3Abar%0Abar%3Afoo: xx
header:
foo:
bar:
--- no_error_log
[error]



=== TEST 90: unsafe header name (with '\n')
--- config
    location = /t {
        content_by_lua_block {
            njt.header["header: value\nfoo:bar\rbar:foo"] = "xx"
            njt.say("foo")
        }
    }
--- request
GET /t
--- response_headers
header%3A%20value%0Afoo%3Abar%0Dbar%3Afoo: xx
header:
foo:
bar:
--- no_error_log
[error]



=== TEST 91: unsafe header name (with prefix '\r')
--- config
    location = /t {
        content_by_lua_block {
            njt.header["\rheader: value\rfoo:bar\nbar:foo"] = "xx"
            njt.say("foo")
        }
    }
--- request
GET /t
--- response_headers
%0Dheader%3A%20value%0Dfoo%3Abar%0Abar%3Afoo: xx
header:
foo:
bar:
--- no_error_log
[error]



=== TEST 92: unsafe header name (with prefix '\n')
--- config
    location = /t {
        content_by_lua_block {
            njt.header["\nheader: value\nfoo:bar\rbar:foo"] = "xx"
            njt.say("foo")
        }
    }
--- request
GET /t
--- response_headers
%0Aheader%3A%20value%0Afoo%3Abar%0Dbar%3Afoo: xx
header:
foo:
bar:
--- no_error_log
[error]



=== TEST 93: multiple unsafe header values (with '\n' and '\r')
--- config
    location = /t {
        content_by_lua_block {
            njt.header["foo"] = {
                "foo\nxx:bar",
                "bar\rxxx:foo",
            }
            njt.say("foo")
        }
    }
--- request
GET /t
--- response_headers
xx:
xxx:
--- raw_response_headers_like chomp
foo: foo%0Axx:bar\r\nfoo: bar%0Dxxx:foo\r\n
--- no_error_log
[error]



=== TEST 94: fix negative content-length number(#1791)
--- config
    location = /big-upstream {
        content_by_lua_block {
            njt.header['Content-Length'] = math.pow(2, 33) - 1
            njt.say('hi')
        }
    }

    location = /t {
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/big-upstream;
        proxy_buffering off;

        header_filter_by_lua_block {
            local hs, err = njt.resp.get_headers()
            if err then
                njt.log(njt.ERR, "err: ", err)
                return njt.exit(500)
            end

            print("my Content-Length: ", hs["Content-Length"])

            njt.header['Content-Length'] = 3
        }
    }
--- request
    GET /t
--- response_body
hi
--- no_error_log
[alert]
--- error_log
my Content-Length: 8589934591
upstream prematurely closed connection while sending to client
