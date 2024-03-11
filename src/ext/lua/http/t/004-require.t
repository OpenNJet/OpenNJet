# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua;

#worker_connections(1014);
#log_level('warn');

#master_on();
#repeat_each(120);
repeat_each(2);

plan tests => blocks() * repeat_each() * 2;

our $HtmlDir = html_dir;
#warn $html_dir;

#$ENV{LUA_PATH} = "$html_dir/?.lua";

#no_diff();
no_long_string();
run_tests();

__DATA__

=== TEST 1: sanity
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
    location /main {
        echo_location /load;
        echo_location /check;
        echo_location /check;
    }

    location /load {
        content_by_lua '
            package.loaded.foo = nil;
            collectgarbage()
            local foo = require "foo";
            foo.hi()
        ';
    }

    location /check {
        content_by_lua '
            local foo = package.loaded.foo
            if foo then
                njt.say("found")
                foo.hi()
            else
                njt.say("not found")
            end
        ';
    }
--- request
GET /main
--- user_files
>>> foo.lua
module(..., package.seeall);

njt.say("loading");

function hi ()
    njt.say("hello, foo")
end;
--- response_body
loading
hello, foo
found
hello, foo
found
hello, foo



=== TEST 2: sanity
--- http_config eval
    "lua_package_cpath '$::HtmlDir/?.so';"
--- config
    location /main {
        content_by_lua '
            njt.print(package.cpath);
        ';
    }
--- request
GET /main
--- user_files
--- response_body_like: ^[^;]+/servroot(_\d+)?/html/\?\.so$



=== TEST 3: expand default path (after)
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;;';"
--- config
    location /main {
        content_by_lua '
            njt.print(package.path);
        ';
    }
--- request
GET /main
--- response_body_like: ^[^;]+/servroot(_\d+)?/html/\?\.lua;(.+\.lua)?;*$



=== TEST 4: expand default cpath (after)
--- http_config eval
    "lua_package_cpath '$::HtmlDir/?.so;;';"
--- config
    location /main {
        content_by_lua '
            njt.print(package.cpath);
        ';
    }
--- request
GET /main
--- response_body_like: ^[^;]+/servroot(_\d+)?/html/\?\.so;(.+\.so)?;*$



=== TEST 5: expand default path (before)
--- http_config eval
    "lua_package_path ';;$::HtmlDir/?.lua';"
--- config
    location /main {
        content_by_lua '
            njt.print(package.path);
        ';
    }
--- request
GET /main
--- response_body_like: ^(.+\.lua)?;*?[^;]+/servroot(_\d+)?/html/\?\.lua$



=== TEST 6: expand default cpath (before)
--- http_config eval
    "lua_package_cpath ';;$::HtmlDir/?.so';"
--- config
    location /main {
        content_by_lua '
            njt.print(package.cpath);
        ';
    }
--- request
GET /main
--- response_body_like: ^(.+\.so)?;*?[^;]+/servroot(_\d+)?/html/\?\.so$



=== TEST 7: require "njt" (content_by_lua)
--- config
    location /njt {
        content_by_lua '
            local njt = require "njt"
            njt.say("hello, world")
        ';
    }
--- request
GET /njt
--- response_body
hello, world



=== TEST 8: require "njt" (set_by_lua)
--- config
    location /njt {
        set_by_lua $res '
            local njt = require "njt"
            return njt.escape_uri(" ")
        ';
        echo $res;
    }
--- request
GET /njt
--- response_body
%20



=== TEST 9: require "ndk" (content_by_lua)
--- config
    location /ndk {
        content_by_lua '
            local ndk = require "ndk"
            local res = ndk.set_var.set_escape_uri(" ")
            njt.say(res)
        ';
    }
--- request
GET /ndk
--- response_body
%20



=== TEST 10: require "ndk" (set_by_lua)
--- config
    location /ndk {
        set_by_lua $res '
            local ndk = require "ndk"
            return ndk.set_var.set_escape_uri(" ")
        ';
        echo $res;
    }
--- request
GET /ndk
--- response_body
%20
