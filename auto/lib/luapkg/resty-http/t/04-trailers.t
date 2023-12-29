use Test::Nginx::Socket 'no_plan';
use Cwd qw(cwd);

my $pwd = cwd();

$ENV{TEST_NGINX_RESOLVER} = '8.8.8.8';
$ENV{TEST_COVERAGE} ||= 0;

our $HttpConfig = qq{
    lua_package_path "$pwd/lib/?.lua;/usr/local/share/lua/5.1/?.lua;;";
    error_log logs/error.log debug;

    init_by_lua_block {
        if $ENV{TEST_COVERAGE} == 1 then
            jit.off()
            require("luacov.runner").init()
        end
    }
};

no_long_string();
#no_diff();

run_tests();

__DATA__
=== TEST 1: Trailers. Check Content-MD5 generated after the body is sent matches up.
--- http_config eval: $::HttpConfig
--- config
    location = /a {
        content_by_lua '
            local http = require "resty.http"
            local httpc = http.new()
            httpc:connect({
                scheme = "http",
                host = "127.0.0.1",
                port = njt.var.server_port
            })

            local res, err = httpc:request{
                path = "/b",
                headers = {
                    ["TE"] = "trailers",
                }
            }

            local body = res:read_body()
            local hash = njt.md5(body)
            res:read_trailers()

            if res.headers["Content-MD5"] == hash then
                njt.say("OK")
            else
                njt.say(res.headers["Content-MD5"])
            end
        ';
    }
    location = /b {
        content_by_lua '
            -- We use the raw socket to compose a response, since OpenResty
            -- doesnt support trailers natively.

            njt.req.read_body()
            local sock, err = njt.req.socket(true)
            if not sock then
                njt.say(err)
            end

            local res = {}
            table.insert(res, "HTTP/1.1 200 OK")
            table.insert(res, "Date: " .. njt.http_time(njt.time()))
            table.insert(res, "Transfer-Encoding: chunked")
            table.insert(res, "Trailer: Content-MD5")
            table.insert(res, "")

            local body = "Hello, World"

            table.insert(res, string.format("%x", #body))
            table.insert(res, body)
            table.insert(res, "0")
            table.insert(res, "")

            table.insert(res, "Content-MD5: " .. njt.md5(body))

            table.insert(res, "")
            table.insert(res, "")
            sock:send(table.concat(res, "\\r\\n"))
        ';
    }
--- request
GET /a
--- response_body
OK
--- no_error_log
[error]
[warn]


=== TEST 2: Advertised trailer does not exist, handled gracefully.
--- http_config eval: $::HttpConfig
--- config
    location = /a {
        content_by_lua '
            local http = require "resty.http"
            local httpc = http.new()
            httpc:connect({
                scheme = "http",
                host = "127.0.0.1",
                port = njt.var.server_port
            })

            local res, err = httpc:request{
                path = "/b",
                headers = {
                    ["TE"] = "trailers",
                }
            }

            local body = res:read_body()
            local hash = njt.md5(body)
            res:read_trailers()

            njt.say("OK")
            httpc:close()
        ';
    }
    location = /b {
        content_by_lua '
            -- We use the raw socket to compose a response, since OpenResty
            -- doesnt support trailers natively.

            njt.req.read_body()
            local sock, err = njt.req.socket(true)
            if not sock then
                njt.say(err)
            end

            local res = {}
            table.insert(res, "HTTP/1.1 200 OK")
            table.insert(res, "Date: " .. njt.http_time(njt.time()))
            table.insert(res, "Transfer-Encoding: chunked")
            table.insert(res, "Trailer: Content-MD5")
            table.insert(res, "")

            local body = "Hello, World"

            table.insert(res, string.format("%x", #body))
            table.insert(res, body)
            table.insert(res, "0")

            table.insert(res, "")
            table.insert(res, "")
            sock:send(table.concat(res, "\\r\\n"))
        ';
    }
--- request
GET /a
--- response_body
OK
--- no_error_log
[error]
[warn]
