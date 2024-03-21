# vim:set ft= ts=4 sw=4 et fdm=marker:
use Test::Nginx::Socket::Lua;

#worker_connections(1014);
#master_on();
#workers(2);
#log_level('warn');

repeat_each(2);
#repeat_each(1);

plan tests => repeat_each() * (blocks() * 6);

master_on();
workers(2);
no_root_location();
#no_diff();
#no_long_string();
run_tests();

__DATA__

=== TEST 1: 404 parallel subrequests after njt.eof()
--- config
    location = /lua {
        content_by_lua '
            njt.say(1)
            njt.eof()
            local res1, res2 = njt.location.capture_multi{
                { "/bad1" },
                { "/bad2" }
            }
            njt.log(njt.WARN, "res1: ", res1.status)
            njt.log(njt.WARN, "res2: ", res2.status)
        ';
    }
--- request
GET /lua
--- response_body
1
--- no_error_log
[alert]
--- error_log
res1: 404
res2: 404
No such file or directory



=== TEST 2: parallel normal subrequests after njt.eof()
--- config
    location = /t {
        content_by_lua '
            njt.say(1)
            njt.eof()
            local r1, r2 = njt.location.capture_multi{
                { "/proxy/tom" },
                { "/proxy/jim" }
            }
            njt.log(njt.WARN, r1.body)
            njt.log(njt.WARN, r2.body)
        ';
    }

    location ~ '^/proxy/(\w+)' {
        proxy_pass http://127.0.0.1:$server_port/hello?a=$1;
    }

    location = /hello {
        echo_sleep 0.5;
        echo -n "hello, $arg_a";
    }
--- request
GET /t
--- response_body
1
--- no_error_log
[alert]
[error]
--- error_log
hello, tom
hello, jim
