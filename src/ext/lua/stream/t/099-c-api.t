# vim:set ft= ts=4 sw=4 et fdm=marker:
use Test::Nginx::Socket::Lua::Stream;
#worker_connections(1014);
#master_process_enabled(1);
log_level('warn');

repeat_each(3);

plan tests => repeat_each() * (blocks() * 3);

#no_diff();
no_long_string();
#master_on();
#workers(2);

run_tests();

__DATA__

=== TEST 1: find zone
--- stream_config
    lua_shared_dict dogs 1m;
--- stream_server_config
    content_by_lua_block {
        local ffi = require "ffi"

        ffi.cdef[[
            void *njt_stream_lua_find_zone(char *data, size_t len);
        ]]

        local buf = ffi.new("char[?]", 4)
        ffi.copy(buf, "foo", 3)
        local zone = ffi.C.njt_stream_lua_find_zone(buf, 3)
        njt.say("foo zone: ", tonumber(ffi.cast("long", zone)) ~= 0 and "defined" or "undef")

        ffi.copy(buf, "dogs", 4)
        zone = ffi.C.njt_stream_lua_find_zone(buf, 4)
        njt.say("dogs zone: ", tonumber(ffi.cast("long", zone)) ~= 0 and "defined" or "undef")
    }
--- stream_response
foo zone: undef
dogs zone: defined
--- no_error_log
[error]



=== TEST 2: number typed value
--- stream_config
    lua_shared_dict dogs 1m;
--- stream_server_config
    content_by_lua_block {
        local ffi = require "ffi"

        ffi.cdef[[
            typedef struct {
                size_t  len;
                char   *data;
            } njt_str_t;

            typedef struct {
                uint8_t         type;

                union {
                    int         b; /* boolean */
                    double      n; /* number */
                    njt_str_t   s; /* string */
                } value;

            } njt_stream_lua_value_t;

            void *njt_stream_lua_find_zone(char *data, size_t len);
            intptr_t njt_stream_lua_shared_dict_get(void *zone, char *kdata, size_t klen, njt_stream_lua_value_t *val);
        ]]

        local dogs = njt.shared.dogs
        dogs:set("foo", 1234567)
        dogs:set("bar", 3.14159)

        local buf = ffi.new("char[?]", 4)

        ffi.copy(buf, "dogs", 4)
        zone = ffi.C.njt_stream_lua_find_zone(buf, 4)

        local val = ffi.new("njt_stream_lua_value_t[?]", 1)

        ffi.copy(buf, "foo", 3)
        local rc = ffi.C.njt_stream_lua_shared_dict_get(zone, buf, 3, val)
        njt.say("foo: rc=", tonumber(rc),
            ", type=", val[0].type,
            ", val=", tonumber(val[0].value.n))

        ffi.copy(buf, "bar", 3)
        local rc = ffi.C.njt_stream_lua_shared_dict_get(zone, buf, 3, val)
        njt.say("bar: rc=", tonumber(rc),
            ", type=", val[0].type,
            ", val=", tonumber(val[0].value.n))
    }
--- stream_response
foo: rc=0, type=3, val=1234567
bar: rc=0, type=3, val=3.14159
--- no_error_log
[error]
--- SKIP



=== TEST 3: boolean typed value
--- SKIP
--- stream_config
    lua_shared_dict dogs 1m;
--- stream_server_config
    content_by_lua_block {
        local ffi = require "ffi"

        ffi.cdef[[
            typedef struct {
                size_t  len;
                char   *data;
            } njt_str_t;

            typedef struct {
                uint8_t         type;

                union {
                    int         b; /* boolean */
                    double      n; /* number */
                    njt_str_t   s; /* string */
                } value;

            } njt_stream_lua_value_t;

            void *njt_stream_lua_find_zone(char *data, size_t len);
            intptr_t njt_stream_lua_shared_dict_get(void *zone, char *kdata, size_t klen, njt_stream_lua_value_t *val);
        ]]

        local dogs = njt.shared.dogs
        dogs:set("foo", true)
        dogs:set("bar", false)

        local buf = ffi.new("char[?]", 4)

        ffi.copy(buf, "dogs", 4)
        zone = ffi.C.njt_stream_lua_find_zone(buf, 4)

        local val = ffi.new("njt_stream_lua_value_t[?]", 1)

        ffi.copy(buf, "foo", 3)
        local rc = ffi.C.njt_stream_lua_shared_dict_get(zone, buf, 3, val)
        njt.say("foo: rc=", tonumber(rc),
            ", type=", tonumber(val[0].type),
            ", val=", tonumber(val[0].value.b))

        local val = ffi.new("njt_stream_lua_value_t[?]", 1)
        ffi.copy(buf, "bar", 3)
        local rc = ffi.C.njt_stream_lua_shared_dict_get(zone, buf, 3, val)
        njt.say("bar: rc=", tonumber(rc),
            ", type=", tonumber(val[0].type),
            ", val=", tonumber(val[0].value.b))
    }
--- stream_response
foo: rc=0, type=1, val=1
bar: rc=0, type=1, val=0
--- no_error_log
[error]



=== TEST 4: key not found
--- stream_config
    lua_shared_dict dogs 1m;
--- stream_server_config
    content_by_lua_block {
        local ffi = require "ffi"

        ffi.cdef[[
            typedef struct {
                size_t  len;
                char   *data;
            } njt_str_t;

            typedef struct {
                uint8_t         type;

                union {
                    int         b; /* boolean */
                    double      n; /* number */
                    njt_str_t   s; /* string */
                } value;

            } njt_stream_lua_value_t;

            void *njt_stream_lua_find_zone(char *data, size_t len);
            intptr_t njt_stream_lua_shared_dict_get(void *zone, char *kdata, size_t klen, njt_stream_lua_value_t *val);
        ]]

        local dogs = njt.shared.dogs
        dogs:flush_all()

        local buf = ffi.new("char[?]", 4)

        ffi.copy(buf, "dogs", 4)
        zone = ffi.C.njt_stream_lua_find_zone(buf, 4)

        local val = ffi.new("njt_stream_lua_value_t[?]", 1)

        ffi.copy(buf, "foo", 3)
        local rc = ffi.C.njt_stream_lua_shared_dict_get(zone, buf, 3, val)
        njt.say("foo: rc=", tonumber(rc))

        local val = ffi.new("njt_stream_lua_value_t[?]", 1)
        ffi.copy(buf, "bar", 3)
        local rc = ffi.C.njt_stream_lua_shared_dict_get(zone, buf, 3, val)
        njt.say("bar: rc=", tonumber(rc))
    }
--- stream_response
foo: rc=-5
bar: rc=-5
--- no_error_log
[error]
--- SKIP



=== TEST 5: string typed value
--- stream_config
    lua_shared_dict dogs 1m;
--- stream_server_config
    content_by_lua_block {
        local ffi = require "ffi"

        ffi.cdef[[
            typedef struct {
                size_t  len;
                char   *data;
            } njt_str_t;

            typedef struct {
                uint8_t         type;

                union {
                    int         b; /* boolean */
                    double      n; /* number */
                    njt_str_t   s; /* string */
                } value;

            } njt_stream_lua_value_t;

            void *njt_stream_lua_find_zone(char *data, size_t len);
            intptr_t njt_stream_lua_shared_dict_get(void *zone, char *kdata, size_t klen, njt_stream_lua_value_t *val);
        ]]

        local dogs = njt.shared.dogs
        dogs:set("foo", "hello world")
        dogs:set("bar", "")

        local buf = ffi.new("char[?]", 4)

        ffi.copy(buf, "dogs", 4)
        zone = ffi.C.njt_stream_lua_find_zone(buf, 4)

        local s = ffi.new("char[?]", 20)

        local val = ffi.new("njt_stream_lua_value_t[?]", 1)
        val[0].value.s.len = 20
        val[0].value.s.data = s

        ffi.copy(buf, "foo", 3)
        local rc = ffi.C.njt_stream_lua_shared_dict_get(zone, buf, 3, val)
        njt.say("foo: rc=", tonumber(rc),
            ", type=", tonumber(val[0].type),
            ", val=", ffi.string(val[0].value.s.data, val[0].value.s.len),
            ", len=", tonumber(val[0].value.s.len))

        local val = ffi.new("njt_stream_lua_value_t[?]", 1)
        val[0].value.s.len = 20
        val[0].value.s.data = s

        ffi.copy(buf, "bar", 3)
        local rc = ffi.C.njt_stream_lua_shared_dict_get(zone, buf, 3, val)
        njt.say("bar: rc=", tonumber(rc),
            ", type=", tonumber(val[0].type),
            ", val=", ffi.string(val[0].value.s.data, val[0].value.s.len),
            ", len=", tonumber(val[0].value.s.len))
    }
--- stream_response
foo: rc=0, type=4, val=hello world, len=11
bar: rc=0, type=4, val=, len=0
--- no_error_log
[error]
--- SKIP



=== TEST 6: nil typed value
--- stream_config
    lua_shared_dict dogs 1m;
--- stream_server_config
    content_by_lua_block {
        local ffi = require "ffi"

        ffi.cdef[[
            typedef struct {
                size_t  len;
                char   *data;
            } njt_str_t;

            typedef struct {
                uint8_t         type;

                union {
                    int         b; /* boolean */
                    double      n; /* number */
                    njt_str_t   s; /* string */
                } value;

            } njt_stream_lua_value_t;

            void *njt_stream_lua_find_zone(char *data, size_t len);
            intptr_t njt_stream_lua_shared_dict_get(void *zone, char *kdata, size_t klen, njt_stream_lua_value_t *val);
        ]]

        local dogs = njt.shared.dogs
        dogs:set("foo", nil)

        local buf = ffi.new("char[?]", 4)

        ffi.copy(buf, "dogs", 4)
        zone = ffi.C.njt_stream_lua_find_zone(buf, 4)

        local val = ffi.new("njt_stream_lua_value_t[?]", 1)

        ffi.copy(buf, "foo", 3)
        local rc = ffi.C.njt_stream_lua_shared_dict_get(zone, buf, 3, val)
        njt.say("foo: rc=", tonumber(rc))
    }
--- stream_response
foo: rc=-5
--- no_error_log
[error]
--- SKIP



=== TEST 7: find zone (multiple zones)
--- stream_config
    lua_shared_dict dogs 1m;
    lua_shared_dict cats 1m;
--- stream_server_config
    content_by_lua_block {
        local ffi = require "ffi"

        ffi.cdef[[
            void *njt_stream_lua_find_zone(char *data, size_t len);
        ]]

        local buf = ffi.new("char[?]", 4)
        ffi.copy(buf, "cats", 4)
        local zone = ffi.C.njt_stream_lua_find_zone(buf, 4)
        local cats = tostring(zone)

        ffi.copy(buf, "dogs", 4)
        zone = ffi.C.njt_stream_lua_find_zone(buf, 4)
        local dogs = tostring(zone)

        njt.say("dogs == cats ? ", dogs == cats)
        -- njt.say("dogs: ", dogs)
        -- njt.say("cats ", cats)
    }
--- stream_response
dogs == cats ? false
--- no_error_log
[error]
