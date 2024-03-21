# vim:set ft= ts=4 sw=4 et fdm=marker:
use Test::Nginx::Socket::Lua;

#worker_connections(1014);
#master_on();
#workers(2);
#log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 7);

#no_diff();
no_long_string();
run_tests();

__DATA__

=== TEST 1: accessing nginx variables
--- config
    location /t {
        content_by_lua '
            local function f()
                print("uri: ", njt.var.uri)
            end
            local ok, err = njt.timer.at(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
        ';
    }
--- request
GET /t
--- stap2
F(njt_http_lua_timer_handler) {
    println("lua timer handler")
}

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]

--- error_log eval
[
qr/\[error\] .*? runtime error: content_by_lua\(nginx\.conf:\d+\):3: API disabled in the current context/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 2: reading njt.status
--- config
    location /t {
        content_by_lua '
            local function f()
                print("uri: ", njt.status)
            end
            local ok, err = njt.timer.at(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
        ';
    }
--- request
GET /t
--- stap2
F(njt_http_lua_timer_handler) {
    println("lua timer handler")
}

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]

--- error_log eval
[
qr/\[error\] .*? runtime error: content_by_lua\(nginx\.conf:\d+\):3: API disabled in the current context/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 3: writing njt.status
--- config
    location /t {
        content_by_lua '
            local function f()
                njt.status = 200
            end
            local ok, err = njt.timer.at(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
        ';
    }
--- request
GET /t
--- stap2
F(njt_http_lua_timer_handler) {
    println("lua timer handler")
}

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]

--- error_log eval
[
qr/\[error\] .*? runtime error: content_by_lua\(nginx\.conf:\d+\):3: API disabled in the current context/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 4: njt.req.raw_header
--- config
    location /t {
        content_by_lua '
            local function f()
                print("raw header: ", njt.req.raw_header())
            end
            local ok, err = njt.timer.at(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
        ';
    }
--- request
GET /t
--- stap2
F(njt_http_lua_timer_handler) {
    println("lua timer handler")
}

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]

--- error_log eval
[
qr/\[error\] .*? runtime error: content_by_lua\(nginx\.conf:\d+\):3: API disabled in the current context/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 5: njt.req.get_headers
--- config
    location /t {
        content_by_lua '
            local function f()
                njt.req.get_headers()
            end
            local ok, err = njt.timer.at(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
        ';
    }
--- request
GET /t
--- stap2
F(njt_http_lua_timer_handler) {
    println("lua timer handler")
}

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]

--- error_log eval
[
qr/\[error\] .*? runtime error: content_by_lua\(nginx\.conf:\d+\):3: API disabled in the current context/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 6: njt.req.set_header
--- config
    location /t {
        content_by_lua '
            local function f()
                njt.req.set_header("Foo", 32)
            end
            local ok, err = njt.timer.at(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
        ';
    }
--- request
GET /t
--- stap2
F(njt_http_lua_timer_handler) {
    println("lua timer handler")
}

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]

--- error_log eval
[
qr/\[error\] .*? runtime error: content_by_lua\(nginx\.conf:\d+\):3: API disabled in the current context/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 7: njt.req.clear_header
--- config
    location /t {
        content_by_lua '
            local function f()
                njt.req.clear_header("Foo")
            end
            local ok, err = njt.timer.at(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
        ';
    }
--- request
GET /t
--- stap2
F(njt_http_lua_timer_handler) {
    println("lua timer handler")
}

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]

--- error_log eval
[
qr/\[error\] .*? runtime error: content_by_lua\(nginx\.conf:\d+\):3: API disabled in the current context/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 8: njt.req.set_uri
--- config
    location /t {
        content_by_lua '
            local function f()
                njt.req.set_uri("/foo")
            end
            local ok, err = njt.timer.at(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
        ';
    }
--- request
GET /t
--- stap2
F(njt_http_lua_timer_handler) {
    println("lua timer handler")
}

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]

--- error_log eval
[
qr/\[error\] .*? runtime error: content_by_lua\(nginx\.conf:\d+\):3: API disabled in the current context/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 9: njt.req.set_uri_args
--- config
    location /t {
        content_by_lua '
            local function f()
                njt.req.set_uri_args("foo")
            end
            local ok, err = njt.timer.at(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
        ';
    }
--- request
GET /t
--- stap2
F(njt_http_lua_timer_handler) {
    println("lua timer handler")
}

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]

--- error_log eval
[
qr/\[error\] .*? runtime error: content_by_lua\(nginx\.conf:\d+\):3: API disabled in the current context/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 10: njt.redirect()
--- config
    location /t {
        content_by_lua '
            local function f()
                njt.redirect("/foo")
            end
            local ok, err = njt.timer.at(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
        ';
    }
--- request
GET /t
--- stap2
F(njt_http_lua_timer_handler) {
    println("lua timer handler")
}

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]

--- error_log eval
[
qr/\[error\] .*? runtime error: content_by_lua\(nginx\.conf:\d+\):3: API disabled in the context of njt\.timer/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 11: njt.exec()
--- config
    location /t {
        content_by_lua '
            local function f()
                njt.exec("/foo")
            end
            local ok, err = njt.timer.at(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
        ';
    }
--- request
GET /t
--- stap2
F(njt_http_lua_timer_handler) {
    println("lua timer handler")
}

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]

--- error_log eval
[
qr/\[error\] .*? runtime error: content_by_lua\(nginx\.conf:\d+\):3: API disabled in the context of njt\.timer/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 12: njt.say()
--- config
    location /t {
        content_by_lua '
            local function f()
                njt.say("hello")
            end
            local ok, err = njt.timer.at(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
        ';
    }
--- request
GET /t
--- stap2
F(njt_http_lua_timer_handler) {
    println("lua timer handler")
}

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]

--- error_log eval
[
qr/\[error\] .*? runtime error: content_by_lua\(nginx\.conf:\d+\):3: API disabled in the context of njt\.timer/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 13: njt.print()
--- config
    location /t {
        content_by_lua '
            local function f()
                njt.print("hello")
            end
            local ok, err = njt.timer.at(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
        ';
    }
--- request
GET /t
--- stap2
F(njt_http_lua_timer_handler) {
    println("lua timer handler")
}

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]

--- error_log eval
[
qr/\[error\] .*? runtime error: content_by_lua\(nginx\.conf:\d+\):3: API disabled in the context of njt\.timer/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 14: njt.flush()
--- config
    location /t {
        content_by_lua '
            local function f()
                njt.flush()
            end
            local ok, err = njt.timer.at(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
        ';
    }
--- request
GET /t
--- stap2
F(njt_http_lua_timer_handler) {
    println("lua timer handler")
}

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]

--- error_log eval
[
qr/\[error\] .*? runtime error: content_by_lua\(nginx\.conf:\d+\):3: API disabled in the context of njt\.timer/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 15: njt.send_headers()
--- config
    location /t {
        content_by_lua '
            local function f()
                njt.send_headers()
            end
            local ok, err = njt.timer.at(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
        ';
    }
--- request
GET /t
--- stap2
F(njt_http_lua_timer_handler) {
    println("lua timer handler")
}

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]

--- error_log eval
[
qr/\[error\] .*? runtime error: content_by_lua\(nginx\.conf:\d+\):3: API disabled in the context of njt\.timer/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 16: njt.req.get_uri_args()
--- config
    location /t {
        content_by_lua '
            local function f()
                njt.req.get_uri_args()
            end
            local ok, err = njt.timer.at(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
        ';
    }
--- request
GET /t
--- stap2
F(njt_http_lua_timer_handler) {
    println("lua timer handler")
}

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]

--- error_log eval
[
qr/\[error\] .*? runtime error: content_by_lua\(nginx\.conf:\d+\):3: API disabled in the current context/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 17: njt.req.read_body
--- config
    location /t {
        content_by_lua '
            local function f()
                njt.req.read_body()
            end
            local ok, err = njt.timer.at(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
        ';
    }
--- request
GET /t
--- stap2
F(njt_http_lua_timer_handler) {
    println("lua timer handler")
}

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]

--- error_log eval
[
qr/\[error\] .*? runtime error: content_by_lua\(nginx\.conf:\d+\):3: API disabled in the context of njt\.timer/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 18: njt.req.discard_body
--- config
    location /t {
        content_by_lua '
            local function f()
                njt.req.discard_body()
            end
            local ok, err = njt.timer.at(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
        ';
    }
--- request
GET /t
--- stap2
F(njt_http_lua_timer_handler) {
    println("lua timer handler")
}

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]

--- error_log eval
[
qr/\[error\] .*? runtime error: content_by_lua\(nginx\.conf:\d+\):3: API disabled in the current context/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 19: njt.req.init_body
--- config
    location /t {
        content_by_lua '
            local function f()
                njt.req.init_body()
            end
            local ok, err = njt.timer.at(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
        ';
    }
--- request
GET /t
--- stap2
F(njt_http_lua_timer_handler) {
    println("lua timer handler")
}

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]

--- error_log eval
[
qr/\[error\] .*? runtime error: content_by_lua\(nginx\.conf:\d+\):3: API disabled in the current context/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 20: njt.header
--- config
    location /t {
        content_by_lua '
            local function f()
                njt.header.Foo = 3
            end
            local ok, err = njt.timer.at(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
        ';
    }
--- request
GET /t
--- stap2
F(njt_http_lua_timer_handler) {
    println("lua timer handler")
}

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]

--- error_log eval
[
qr/\[error\] .*? runtime error: content_by_lua\(nginx\.conf:\d+\):3: API disabled in the current context/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 21: njt.on_abort
--- config
    location /t {
        content_by_lua '
            local function f()
                njt.on_abort(f)
            end
            local ok, err = njt.timer.at(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
        ';
    }
--- request
GET /t
--- stap2
F(njt_http_lua_timer_handler) {
    println("lua timer handler")
}

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]

--- error_log eval
[
qr/\[error\] .*? runtime error: content_by_lua\(nginx\.conf:\d+\):3: API disabled in the context of njt\.timer/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 22: njt.location.capture
--- config
    location /t {
        content_by_lua '
            local function f()
                njt.location.capture("/")
            end
            local ok, err = njt.timer.at(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
        ';
    }
--- request
GET /t
--- stap2
F(njt_http_lua_timer_handler) {
    println("lua timer handler")
}

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]

--- error_log eval
[
qr/\[error\] .*? runtime error: content_by_lua\(nginx\.conf:\d+\):3: API disabled in the context of njt\.timer/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 23: njt.location.capture_multi
--- config
    location /t {
        content_by_lua '
            local function f()
                njt.location.capture_multi{{"/"}}
            end
            local ok, err = njt.timer.at(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
        ';
    }
--- request
GET /t
--- stap2
F(njt_http_lua_timer_handler) {
    println("lua timer handler")
}

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]

--- error_log eval
[
qr/\[error\] .*? runtime error: content_by_lua\(nginx\.conf:\d+\):3: API disabled in the context of njt\.timer/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 24: njt.req.get_method
--- config
    location /t {
        content_by_lua '
            local function f()
                njt.req.get_method()
            end
            local ok, err = njt.timer.at(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
        ';
    }
--- request
GET /t
--- stap2
F(njt_http_lua_timer_handler) {
    println("lua timer handler")
}

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]

--- error_log eval
[
qr/\[error\] .*? runtime error: content_by_lua\(nginx\.conf:\d+\):3: API disabled in the current context/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 25: njt.req.set_method
--- config
    location /t {
        content_by_lua '
            local function f()
                njt.req.set_method(njt.HTTP_POST)
            end
            local ok, err = njt.timer.at(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
        ';
    }
--- request
GET /t
--- stap2
F(njt_http_lua_timer_handler) {
    println("lua timer handler")
}

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]

--- error_log eval
[
qr/\[error\] .*? runtime error: content_by_lua\(nginx\.conf:\d+\):3: API disabled in the current context/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 26: njt.req.http_version
--- config
    location /t {
        content_by_lua '
            local function f()
                njt.req.http_version()
            end
            local ok, err = njt.timer.at(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
        ';
    }
--- request
GET /t
--- stap2
F(njt_http_lua_timer_handler) {
    println("lua timer handler")
}

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]

--- error_log eval
[
qr/\[error\] .*? runtime error: content_by_lua\(nginx\.conf:\d+\):3: API disabled in the current context/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 27: njt.req.get_post_args
--- config
    location /t {
        content_by_lua '
            local function f()
                njt.req.get_post_args()
            end
            local ok, err = njt.timer.at(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
        ';
    }
--- request
GET /t
--- stap2
F(njt_http_lua_timer_handler) {
    println("lua timer handler")
}

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]

--- error_log eval
[
qr/\[error\] .*? runtime error: content_by_lua\(nginx\.conf:\d+\):3: API disabled in the current context/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 28: njt.req.get_body_data
--- config
    location /t {
        content_by_lua '
            local function f()
                njt.req.get_body_data()
            end
            local ok, err = njt.timer.at(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
        ';
    }
--- request
GET /t
--- stap2
F(njt_http_lua_timer_handler) {
    println("lua timer handler")
}

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]

--- error_log eval
[
qr/\[error\] .*? runtime error: content_by_lua\(nginx\.conf:\d+\):3: API disabled in the current context/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 29: njt.req.get_body_file
--- config
    location /t {
        content_by_lua '
            local function f()
                njt.req.get_body_file()
            end
            local ok, err = njt.timer.at(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
        ';
    }
--- request
GET /t
--- stap2
F(njt_http_lua_timer_handler) {
    println("lua timer handler")
}

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]

--- error_log eval
[
qr/\[error\] .*? runtime error: content_by_lua\(nginx\.conf:\d+\):3: API disabled in the current context/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 30: njt.req.set_body_data
--- config
    location /t {
        content_by_lua '
            local function f()
                njt.req.set_body_data("hello")
            end
            local ok, err = njt.timer.at(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
        ';
    }
--- request
GET /t
--- stap2
F(njt_http_lua_timer_handler) {
    println("lua timer handler")
}

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]

--- error_log eval
[
qr/\[error\] .*? runtime error: content_by_lua\(nginx\.conf:\d+\):3: API disabled in the current context/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 31: njt.req.set_body_file
--- config
    location /t {
        content_by_lua '
            local function f()
                njt.req.set_body_file("hello")
            end
            local ok, err = njt.timer.at(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
        ';
    }
--- request
GET /t
--- stap2
F(njt_http_lua_timer_handler) {
    println("lua timer handler")
}

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]

--- error_log eval
[
qr/\[error\] .*? runtime error: content_by_lua\(nginx\.conf:\d+\):3: API disabled in the current context/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 32: njt.req.append_body
--- config
    location /t {
        content_by_lua '
            local function f()
                njt.req.append_body("hello")
            end
            local ok, err = njt.timer.at(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
        ';
    }
--- request
GET /t
--- stap2
F(njt_http_lua_timer_handler) {
    println("lua timer handler")
}

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]

--- error_log eval
[
qr/\[error\] .*? runtime error: content_by_lua\(nginx\.conf:\d+\):3: API disabled in the current context/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 33: njt.req.finish_body
--- config
    location /t {
        content_by_lua '
            local function f()
                njt.req.finish_body()
            end
            local ok, err = njt.timer.at(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
        ';
    }
--- request
GET /t
--- stap2
F(njt_http_lua_timer_handler) {
    println("lua timer handler")
}

--- response_body
registered timer

--- wait: 0.2
--- no_error_log
[alert]
[crit]

--- error_log eval
[
qr/\[error\] .*? runtime error: content_by_lua\(nginx\.conf:\d+\):3: API disabled in the current context/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 34: njt.headers_sent
--- config
    location /t {
        content_by_lua '
            local function f()
                njt.headers_sent()
            end
            local ok, err = njt.timer.at(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
        ';
    }
--- request
GET /t
--- stap2
F(njt_http_lua_timer_handler) {
    println("lua timer handler")
}

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]

--- error_log eval
[
qr/\[error\] .*? runtime error: content_by_lua\(nginx\.conf:\d+\):3: API disabled in the current context/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 35: njt.eof
--- config
    location /t {
        content_by_lua '
            local function f()
                njt.eof()
            end
            local ok, err = njt.timer.at(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
        ';
    }
--- request
GET /t
--- stap2
F(njt_http_lua_timer_handler) {
    println("lua timer handler")
}

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]

--- error_log eval
[
qr/\[error\] .*? runtime error: content_by_lua\(nginx\.conf:\d+\):3: API disabled in the context of njt\.timer/,
"lua njt.timer expired",
"http lua close fake http connection"
]



=== TEST 36: njt.req.socket
--- config
    location /t {
        content_by_lua '
            local function f()
                local sock, err = njt.req.socket()
                if not sock then
                    njt.log(njt.ERR, "failed to get req sock: ", err)
                end
            end
            local ok, err = njt.timer.at(0.05, f)
            if not ok then
                njt.say("failed to set timer: ", err)
                return
            end
            njt.say("registered timer")
        ';
    }
--- request
GET /t
--- stap2
F(njt_http_lua_timer_handler) {
    println("lua timer handler")
}

--- response_body
registered timer

--- wait: 0.1
--- no_error_log
[alert]
[crit]

--- error_log eval
[
qr/\[error\] .*? runtime error: content_by_lua\(nginx\.conf:\d+\):3: API disabled in the context of njt\.timer/,
"lua njt.timer expired",
"http lua close fake http connection"
]
