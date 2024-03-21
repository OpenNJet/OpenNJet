# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua;

repeat_each(2);

plan tests => blocks() * repeat_each() * 2;

#no_diff();
#no_long_string();

run_tests();

__DATA__

=== TEST 1: sanity
--- config
    location /read {
        content_by_lua '
            njt.say(njt.OK)
            njt.say(njt.AGAIN)
            njt.say(njt.DONE)
            njt.say(njt.ERROR)
        ';
    }
--- request
GET /read
--- response_body
0
-2
-4
-1



=== TEST 2: http constants
--- config
    location /read {
        content_by_lua '
            njt.say(njt.HTTP_GATEWAY_TIMEOUT)
        ';
    }
--- request
GET /read
--- response_body
504
