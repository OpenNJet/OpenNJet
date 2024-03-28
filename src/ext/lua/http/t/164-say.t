# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua;

repeat_each(2);

plan tests => blocks() * repeat_each() * 2;

run_tests();

__DATA__

=== TEST 1: njt.say (integer)
--- config
    location /lua {
        content_by_lua_block {
            njt.say(2)
        }
    }
--- request
GET /lua
--- response_body
2



=== TEST 2: njt.say (floating point number)
the maximum number of significant digits is 14 in lua
--- config
    location /lua {
        content_by_lua_block {
            njt.say(3.1415926)
            njt.say(3.14159265357939723846)
        }
    }
--- request
GET /lua
--- response_body
3.1415926
3.1415926535794



=== TEST 3: njt.say (table with number)
--- config
    location /lua {
        content_by_lua_block {
            local data = {123," ", 3.1415926}
            njt.say(data)
        }
    }
--- request
GET /lua
--- response_body
123 3.1415926



=== TEST 4: njt.say min int32 -2147483648
--- config
    location /lua {
        content_by_lua_block {
            njt.say(-2147483648)
        }
    }
--- request
GET /lua
--- response_body
-2147483648



=== TEST 5: njt.say big integer 2147483647
--- config
    location /lua {
        content_by_lua_block {
            njt.say(2147483647)
        }
    }
--- request
GET /lua
--- response_body
2147483647



=== TEST 6: njt.say big integer -9223372036854775808
--- config
    location /lua {
        content_by_lua_block {
            njt.say(-9223372036854775808)
        }
    }
--- request
GET /lua
--- response_body
-9.2233720368548e+18



=== TEST 7: njt.say big integer 18446744073709551615
--- config
    location /lua {
        content_by_lua_block {
            njt.say(18446744073709551615)
        }
    }
--- request
GET /lua
--- response_body
1.844674407371e+19
