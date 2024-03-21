# vim:set ft= ts=4 sw=4 et fdm=marker:

our $SkipReason;

BEGIN {
    if ($ENV{TEST_NGINX_EVENT_TYPE}
        && $ENV{TEST_NGINX_EVENT_TYPE} !~ /^kqueue|epoll|eventport$/)
    {
        $SkipReason = "unavailable for the event type '$ENV{TEST_NGINX_EVENT_TYPE}'";
    }
}

use Test::Nginx::Socket::Lua $SkipReason ? (skip_all => $SkipReason) : ();

#worker_connections(1014);
#master_on();
#workers(2);
#log_level('warn');

repeat_each(1);

plan tests => repeat_each() * (blocks() * 2);

our $HtmlDir = html_dir;

our $HttpConfig = qq{
    lua_package_path "$::HtmlDir/?.lua;./?.lua;;";
    lua_worker_thread_vm_pool_size 1;
};

#no_diff();
#no_long_string();
run_tests();

__DATA__

=== TEST 1: hello from worker thread
--- main_config
    thread_pool testpool threads=100;
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
location /hello {
    default_type 'text/plain';

    content_by_lua_block {
        local ok, hello_or_err = njt.run_worker_thread("testpool", "hello", "hello")
        njt.say(ok, " : ", hello_or_err)
    }
}
--- user_files
>>> hello.lua
local function hello()
    return "hello"
end
return {hello=hello}
--- request
GET /hello
--- response_body
true : hello



=== TEST 2: thread_pool not found
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
location /hello {
    default_type 'text/plain';

    content_by_lua_block {
        local ok, hello_or_err = njt.run_worker_thread("testpool", "hello", "hello")
        njt.say(ok, " : ", hello_or_err)
    }
}
--- user_files
>>> hello.lua
local function hello()
    return "hello"
end
return {hello=hello}
--- request
GET /hello
--- response_body
false : thread pool testpool not found



=== TEST 3: pass table
--- main_config
    thread_pool testpool threads=100;
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
location /hello {
    default_type 'text/plain';

    content_by_lua_block {
        local ok, ok_or_err = njt.run_worker_thread("testpool", "hello", "hello", {["hello"]="world", [1]={["embed"]=1}})
        njt.say(ok, " , ", ok_or_err)
    }
}
--- user_files
>>> hello.lua
local function hello(arg1)
    if arg1.hello == "world" and arg1[1].embed == 1 then
        return true
    end
    return false
end
return {hello=hello}
--- request
GET /hello
--- response_body
true , true



=== TEST 4: expecting at least 3 arguments
--- main_config
    thread_pool testpool threads=100;
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
location /hello {
    default_type 'text/plain';

    content_by_lua_block {
        local ok, err = njt.run_worker_thread("testpool")
        njt.say(ok, " : ", err)
    }
}
--- request
GET /hello
--- response_body
false : expecting at least 3 arguments



=== TEST 5: base64
--- main_config
    thread_pool testpool threads=100;
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
location /hello {
    default_type 'text/plain';

    content_by_lua_block {
        local ok, base64 = njt.run_worker_thread("testpool", "hello", "enc", "hello")
        njt.say(ok, " , ", base64 == "aGVsbG8=")
    }
}
--- user_files
>>> hello.lua
local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

local function enc(data)
    return ((data:gsub('.', function(x)
        local r,b='',x:byte()
        for i=8,1,-1 do r=r..(b%2^i-b%2^(i-1)>0 and '1' or '0') end
        return r;
    end)..'0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
        if (#x < 6) then return '' end
        local c=0
        for i=1,6 do c=c+(x:sub(i,i)=='1' and 2^(6-i) or 0) end
        return b:sub(c+1,c+1)
    end)..({ '', '==', '=' })[#data%3+1])
end

return {enc=enc}
--- request
GET /hello
--- response_body
true , true



=== TEST 6: return table
--- main_config
    thread_pool testpool threads=100;
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
location /hello {
    default_type 'text/plain';

    content_by_lua_block {
        local ok, ret = njt.run_worker_thread("testpool", "hello", "hello")
        if ret.hello == "world" and ret[1].embed == 1 then
            njt.say(ok, " , ", true)
        end
    }
}
--- user_files
>>> hello.lua
local function hello()
    return {["hello"]="world", [1]={["embed"]=1}}
end
return {hello=hello}
--- request
GET /hello
--- response_body
true , true



=== TEST 7: unsupported argument type
--- main_config
    thread_pool testpool threads=100;
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
location /hello {
    default_type 'text/plain';

    content_by_lua_block {
        local function dummy() end
        local ok, err = njt.run_worker_thread("testpool", "hello", "hello", dummy)
        njt.say(ok, " : ", err)
    }
}
--- user_files
>>> hello.lua
local function hello()
    return "hello"
end
return {hello=hello}
--- request
GET /hello
--- response_body
false : unsupported argument type



=== TEST 8: multiple return values
--- main_config
    thread_pool testpool threads=100;
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
location /hello {
    default_type 'text/plain';

    content_by_lua_block {
        local ok, res1, res2 = njt.run_worker_thread("testpool", "hello", "hello")
        njt.say(ok, " : ", res1, " , ", res2)
    }
}
--- user_files
>>> hello.lua
local function hello()
    return "hello", 200
end
return {hello=hello}
--- request
GET /hello
--- response_body
true : hello , 200



=== TEST 9: module not found
--- main_config
    thread_pool testpool threads=100;
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
location /hello {
    default_type 'text/plain';

    content_by_lua_block {
        local ok, err = njt.run_worker_thread("testpool", "hello", "hello")
        njt.say(ok, " : ", err)
    }
}
--- request
GET /hello
--- response_body_like
false : module 'hello' not found.*



=== TEST 10: the number of Lua VM exceeds the pool size
--- main_config
    thread_pool testpool threads=100;
--- http_config eval: $::HttpConfig
--- config
location /foo {
    default_type 'text/plain';

    content_by_lua_block {
        local ok, hello_or_err = njt.run_worker_thread("testpool", "hello", "hello")
        njt.say(ok, " : ", hello_or_err)
    }
}

location /bar {
    default_type 'text/plain';

    content_by_lua_block {
        local ok, foobar_or_err = njt.run_worker_thread("testpool", "foobar", "foobar")
        njt.say(ok, " : ", foobar_or_err)
    }
}

location /t {
    set $port $TEST_NGINX_SERVER_PORT;

    content_by_lua_block {
        local function t(path)
            local sock = njt.socket.tcp()
            local port = njt.var.port
            local ok, err = sock:connect("127.0.0.1", port)
            if not ok then
                njt.say("failed to connect: ", err)
                return
            end

            local req = "GET " .. path .. " HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"

            local bytes, err = sock:send(req)
            if not bytes then
                njt.say("failed to send request: ", err)
                return
            end

            local ret, err, part = sock:receive("*a")
            local _, idx = string.find(ret, "\r\n\r\n");
            idx = idx + 1
            njt.print(string.sub(ret, idx))
            ok, err = sock:close()
        end

        local t1 = njt.thread.spawn(t, "/foo")
        local t2 = njt.thread.spawn(t, "/bar")
        njt.thread.wait(t1)
        njt.thread.wait(t2)
    }
}
--- user_files
>>> hello.lua
local function hello()
    os.execute("sleep 3")
    return "hello"
end
return {hello=hello}
>>> foobar.lua
local function foobar()
    return "foobar"
end
return {foobar=foobar}
--- request
GET /t
--- response_body eval
"false : no available Lua vm\ntrue : hello\n"
--- timeout: 10



=== TEST 11: kill uthread before worker thread callback
--- main_config
    thread_pool testpool threads=100;
--- http_config eval: $::HttpConfig
--- config
location /foo {
    default_type 'text/plain';

    content_by_lua_block {
        local function t()
            local ok, hello_or_err = njt.run_worker_thread("testpool", "hello", "hello")
            njt.say(ok, " : ", hello_or_err)
        end
        local t1 = njt.thread.spawn(t)
        if njt.var.arg_kill == "kill" then
            njt.thread.kill(t1)
            njt.say("killed")
        end
    }
}

location /t {
    set $port $TEST_NGINX_SERVER_PORT;

    content_by_lua_block {
        local function t(path)
            local sock = njt.socket.tcp()
            local port = njt.var.port
            local ok, err = sock:connect("127.0.0.1", port)
            if not ok then
                njt.say("failed to connect: ", err)
                return
            end

            local req = "GET " .. path .. " HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"

            local bytes, err = sock:send(req)
            if not bytes then
                njt.say("failed to send request: ", err)
                return
            end

            local ret, err, part = sock:receive("*a")
            local _, idx = string.find(ret, "\r\n\r\n");
            idx = idx + 1
            njt.print(string.sub(ret, idx))
            ok, err = sock:close()
        end

        local t1 = njt.thread.spawn(t, "/foo?kill=kill")
        njt.thread.wait(t1)
        njt.sleep(4)
        local t2 = njt.thread.spawn(t, "/foo")
        njt.thread.wait(t2)
    }
}
--- user_files
>>> hello.lua
local function hello()
    os.execute("sleep 1")
    return "hello"
end
return {hello=hello}
>>> foobar.lua
local function foobar()
    return "foobar"
end
return {foobar=foobar}
--- request
GET /t
--- response_body eval
"killed\ntrue : hello\n"
--- timeout: 10



=== TEST 12: exit before worker thread callback
--- main_config
    thread_pool testpool threads=100;
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
location /hello {
    default_type 'text/plain';

    content_by_lua_block {
        local function t()
            local ok, hello_or_err = njt.run_worker_thread("testpool", "hello", "hello")
            njt.say(ok, " : ", hello_or_err)
        end
        njt.thread.spawn(t)
        njt.exit(200)
    }
}
--- user_files
>>> hello.lua
local function hello()
    os.execute("sleep 3")
    return "hello"
end
return {hello=hello}
--- request
GET /hello
--- response_body
--- timeout: 10



=== TEST 13: unsupported argument type in nested table
--- main_config
    thread_pool testpool threads=100;
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
location /hello {
    default_type 'text/plain';

    content_by_lua_block {
        local function dummy() end
        local ok, err = njt.run_worker_thread("testpool", "hello", "hello",
                    {["hello"]="world", [1]={["embed"]=1, ["dummy"]=dummy}})
        njt.say(ok, " : ", err)
    }
}
--- user_files
>>> hello.lua
local function hello()
    return "hello"
end
return {hello=hello}
--- request
GET /hello
--- response_body
false : unsupported argument type



=== TEST 14: return table with unsupported type
--- main_config
    thread_pool testpool threads=100;
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
location /hello {
    default_type 'text/plain';

    content_by_lua_block {
        local ok, ret = njt.run_worker_thread("testpool", "hello", "hello")
        if ok == false then
            njt.say("false", " , ", ret)
        end
        if ret.hello == "world" and ret[1].embed == 1 then
            njt.say(ok, " , ", true)
        end
    }
}
--- user_files
>>> hello.lua
local function hello()
    local function dummy() end
    return {["hello"]="world", [1]={["embed"]=1, ["dummy"]=dummy}}
end
return {hello=hello}
--- request
GET /hello
--- response_body
false , unsupported return value



=== TEST 15: the type of module name is not string
--- main_config
    thread_pool testpool threads=100;
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
location /hello {
    default_type 'text/plain';

    content_by_lua_block {
        local function dummy() end
        local ok, err = njt.run_worker_thread("testpool", dummy, "hello")
        njt.say(ok, " : ", err)
    }
}
--- user_files
>>> hello.lua
local function hello()
    return "hello"
end
return {hello=hello}
--- request
GET /hello
--- response_body
false : module name should be a string



=== TEST 16: the type of function name is not string
--- main_config
    thread_pool testpool threads=100;
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
location /hello {
    default_type 'text/plain';

    content_by_lua_block {
        local function dummy() end
        local ok, err = njt.run_worker_thread("testpool", "hello", dummy)
        njt.say(ok, " : ", err)
    }
}
--- user_files
>>> hello.lua
local function hello()
    return "hello"
end
return {hello=hello}
--- request
GET /hello
--- response_body
false : function name should be a string



=== TEST 17: the type of thread pool name is not string
--- main_config
    thread_pool testpool threads=100;
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
location /hello {
    default_type 'text/plain';

    content_by_lua_block {
        local function dummy() end
        local ok, err = njt.run_worker_thread(dummy, "hello", "hello")
        njt.say(ok, " : ", err)
    }
}
--- user_files
>>> hello.lua
local function hello()
    return "hello"
end
return {hello=hello}
--- request
GET /hello
--- response_body
false : threadpool should be a string



=== TEST 18: njt.encode_base64
--- main_config
    thread_pool testpool threads=100;
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
location /hello {
    default_type 'text/plain';

    content_by_lua_block {
        local ok, hello_or_err = njt.run_worker_thread("testpool", "hello", "hello")
        njt.say(ok, " : ", hello_or_err)
    }
}
--- user_files
>>> hello.lua
local function hello()
    return njt.encode_base64("hello")
end
return {hello=hello}
--- request
GET /hello
--- response_body
true : aGVsbG8=



=== TEST 19: njt.config.subsystem
--- main_config
    thread_pool testpool threads=100;
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
location /hello {
    default_type 'text/plain';

    content_by_lua_block {
        local ok, hello_or_err = njt.run_worker_thread("testpool", "hello", "hello")
        njt.say(ok, " : ", hello_or_err)
    }
}
--- user_files
>>> hello.lua
local function hello()
    return njt.config.subsystem
end
return {hello=hello}
--- request
GET /hello
--- response_body
true : http



=== TEST 20: njt.hmac_sha1
--- main_config
    thread_pool testpool threads=100;
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
location /hello {
    default_type 'text/plain';

    content_by_lua_block {
        local ok, hello_or_err = njt.run_worker_thread("testpool", "hello", "hello")
        njt.say(ok, " : ", hello_or_err)
    }
}
--- user_files
>>> hello.lua
local function hello()
  local key = "thisisverysecretstuff"
  local src = "some string we want to sign"
  local digest = njt.hmac_sha1(key, src)
  return njt.encode_base64(digest)
end
return {hello=hello}
--- request
GET /hello
--- response_body
true : R/pvxzHC4NLtj7S+kXFg/NePTmk=



=== TEST 21: njt.encode_args
--- main_config
    thread_pool testpool threads=100;
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
location /hello {
    default_type 'text/plain';

    content_by_lua_block {
        local ok, hello_or_err = njt.run_worker_thread("testpool", "hello", "hello")
        njt.say(ok, " : ", hello_or_err)
    }
}
--- user_files
>>> hello.lua
local function hello()
  return njt.encode_args({foo = 3, ["b r"] = "hello world"})
end
return {hello=hello}
--- request
GET /hello
--- response_body eval
qr/foo=3&b%20r=hello%20world|b%20r=hello%20world&foo=3/



=== TEST 22: njt.decode_args
--- main_config
    thread_pool testpool threads=100;
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
location /hello {
    default_type 'text/plain';

    content_by_lua_block {
        local ok, ret = njt.run_worker_thread("testpool", "hello", "hello")
        njt.say(ok, " : ", ret.a, " : ", ret.b)
    }
}
--- user_files
>>> hello.lua
local function hello()
  local args = "a=bar&b=foo"
  args = njt.decode_args(args)
  return args
end
return {hello=hello}
--- request
GET /hello
--- response_body
true : bar : foo



=== TEST 23: njt.quote_sql_str
--- main_config
    thread_pool testpool threads=100;
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
    location /hello {
        content_by_lua '
          local ok, hello_or_err = njt.run_worker_thread("testpool", "hello", "hello", "a\\026b\\026")
          njt.say(ok, " : ", hello_or_err)
        ';
    }
--- user_files
>>> hello.lua
local function hello(str)
  return njt.quote_sql_str(str)
end
return {hello=hello}
--- request
GET /hello
--- response_body
true : 'a\Zb\Z'



=== TEST 24: njt.re.match
--- main_config
    thread_pool testpool threads=100;
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
location /hello {
    default_type 'text/plain';

    content_by_lua_block {
        local ok, a, b = njt.run_worker_thread("testpool", "hello", "hello")
        njt.say(ok, " : ", a, " : ", b)
    }
}
--- user_files
>>> hello.lua
local function hello()
  local m, err = njt.re.match("hello, 1234", "([0-9])[0-9]+")
  return m[0], m[1]
end
return {hello=hello}
--- request
GET /hello
--- response_body
true : 1234 : 1



=== TEST 25: njt.re.find
--- main_config
    thread_pool testpool threads=100;
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
location /hello {
    default_type 'text/plain';

    content_by_lua_block {
        local ok, a = njt.run_worker_thread("testpool", "hello", "hello")
        njt.say(ok, " : ", a)
    }
}
--- user_files
>>> hello.lua
local function hello()
    local str = "hello, 1234"
    local from, to = njt.re.find(str, "([0-9])([0-9]+)", "jo", nil, 2)
    if from then
        return string.sub(str, from, to)
    end
end
return {hello=hello}
--- request
GET /hello
--- response_body
true : 234



=== TEST 26: njt.re.gmatch
--- main_config
    thread_pool testpool threads=100;
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
location /hello {
    default_type 'text/plain';

    content_by_lua_block {
        local ok, ret = njt.run_worker_thread("testpool", "hello", "hello")
        njt.say(ok)
        njt.say(ret[1])
        njt.say(ret[2])
    }
}
--- user_files
>>> hello.lua
local function hello()
    local ret = {}
    for m in njt.re.gmatch("hello, world", "[a-z]+", "j") do
        if m then
            table.insert(ret, m[0])
        end
    end
    return ret
end
return {hello=hello}
--- request
GET /hello
--- response_body
true
hello
world



=== TEST 27: njt.re.sub
--- main_config
    thread_pool testpool threads=100;
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
location /hello {
    default_type 'text/plain';

    content_by_lua_block {
        local ok, a, b = njt.run_worker_thread("testpool", "hello", "hello")
        njt.say(ok)
        njt.say(a)
        njt.say(b)
    }
}
--- user_files
>>> hello.lua
local function hello()
    local newstr, n = njt.re.sub("hello, 1234", "[0-9]", "$$")
    return newstr, n
end
return {hello=hello}
--- request
GET /hello
--- response_body
true
hello, $234
1



=== TEST 28: njt.re.gsub
--- main_config
    thread_pool testpool threads=100;
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
location /hello {
    default_type 'text/plain';

    content_by_lua_block {
        local ok, a, b = njt.run_worker_thread("testpool", "hello", "hello")
        njt.say(ok)
        njt.say(a)
        njt.say(b)
    }
}
--- user_files
>>> hello.lua
local function hello()
    local newstr, n, err = njt.re.gsub("hello, world", "([a-z])[a-z]+", "[$0,$1]", "i")
    return newstr, n
end
return {hello=hello}
--- request
GET /hello
--- response_body
true
[hello,h], [world,w]
2



=== TEST 29: njt.decode_base64
--- main_config
    thread_pool testpool threads=100;
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
location /hello {
    default_type 'text/plain';

    content_by_lua_block {
        local ok, hello_or_err = njt.run_worker_thread("testpool", "hello", "hello")
        njt.say(ok, " : ", hello_or_err)
    }
}
--- user_files
>>> hello.lua
local function hello()
    return njt.decode_base64("aGVsbG8=")
end
return {hello=hello}
--- request
GET /hello
--- response_body
true : hello



=== TEST 30: njt.crc32_short
--- main_config
    thread_pool testpool threads=100;
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
location /hello {
    default_type 'text/plain';

    content_by_lua_block {
        local ok, hello_or_err = njt.run_worker_thread("testpool", "hello", "hello")
        njt.say(ok, " : ", hello_or_err)
    }
}
--- user_files
>>> hello.lua
local function hello()
    return njt.crc32_short("hello, world")
end
return {hello=hello}
--- request
GET /hello
--- response_body
true : 4289425978



=== TEST 31: njt.crc32_long
--- main_config
    thread_pool testpool threads=100;
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
location /hello {
    default_type 'text/plain';

    content_by_lua_block {
        local ok, hello_or_err = njt.run_worker_thread("testpool", "hello", "hello")
        njt.say(ok, " : ", hello_or_err)
    }
}
--- user_files
>>> hello.lua
local function hello()
    return njt.crc32_long("hello, world")
end
return {hello=hello}
--- request
GET /hello
--- response_body
true : 4289425978



=== TEST 32: njt.md5_bin
--- main_config
    thread_pool testpool threads=100;
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
location /hello {
    default_type 'text/plain';

    content_by_lua_block {
        local ok, hello_or_err = njt.run_worker_thread("testpool", "hello", "hello")
        njt.say(ok, " : ", hello_or_err)
    }
}
--- user_files
>>> hello.lua
local function hello()
    local s = njt.md5_bin(45)
    s = string.gsub(s, ".", function (c)
            return string.format("%02x", string.byte(c))
        end)
    return s
end
return {hello=hello}
--- request
GET /hello
--- response_body
true : 6c8349cc7260ae62e3b1396831a8398f



=== TEST 33: njt.md5
--- main_config
    thread_pool testpool threads=100;
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
location /hello {
    default_type 'text/plain';

    content_by_lua_block {
        local ok, hello_or_err = njt.run_worker_thread("testpool", "hello", "hello")
        njt.say(ok, " : ", hello_or_err)
    }
}
--- user_files
>>> hello.lua
local function hello()
    return njt.md5("hello")
end
return {hello=hello}
--- request
GET /hello
--- response_body
true : 5d41402abc4b2a76b9719d911017c592



=== TEST 34: njt.config.debug
--- main_config
    thread_pool testpool threads=100;
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
location /hello {
    default_type 'text/plain';

    content_by_lua_block {
        local ok, hello_or_err = njt.run_worker_thread("testpool", "hello", "hello")
        njt.say(ok, " : ", hello_or_err)
    }
}
--- user_files
>>> hello.lua
local function hello()
    return njt.config.debug
end
return {hello=hello}
--- request
GET /hello
--- response_body_like chop
^true : (?:true|false)$



=== TEST 35: njt.config.prefix
--- main_config
    thread_pool testpool threads=100;
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
location /hello {
    default_type 'text/plain';

    content_by_lua_block {
        local ok, hello_or_err = njt.run_worker_thread("testpool", "hello", "hello")
        njt.say(ok, " : ", hello_or_err)
    }
}
--- user_files
>>> hello.lua
local function hello()
    return njt.config.prefix()
end
return {hello=hello}
--- request
GET /hello
--- response_body_like chop
^true : \/\S+$



=== TEST 36: njt.config.njet_version
--- main_config
    thread_pool testpool threads=100;
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
location /hello {
    default_type 'text/plain';

    content_by_lua_block {
        local ok, hello_or_err = njt.run_worker_thread("testpool", "hello", "hello")
        njt.say(ok, " : ", hello_or_err)
    }
}
--- user_files
>>> hello.lua
local function hello()
    return njt.config.njet_version
end
return {hello=hello}
--- request
GET /hello
--- response_body_like chop
^true : \d+$



=== TEST 37: njt.config.nginx_configure
--- main_config
    thread_pool testpool threads=100;
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
location /hello {
    default_type 'text/plain';

    content_by_lua_block {
        local ok, hello_or_err = njt.run_worker_thread("testpool", "hello", "hello")
        njt.say(hello_or_err)
    }
}
--- user_files
>>> hello.lua
local function hello()
    return njt.config.nginx_configure()
end
return {hello=hello}
--- request
GET /hello
--- response_body_like chop
^\s*\-\-[^-]+



=== TEST 38: njt.config.njt_lua_version
--- main_config
    thread_pool testpool threads=100;
--- http_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- config
location /hello {
    default_type 'text/plain';

    content_by_lua_block {
        local ok, hello_or_err = njt.run_worker_thread("testpool", "hello", "hello")
        njt.say(ok, " : ", hello_or_err)
    }
}
--- user_files
>>> hello.lua
local function hello()
    return njt.config.njt_lua_version
end
return {hello=hello}
--- request
GET /hello
--- response_body_like chop
^true : \d+$
