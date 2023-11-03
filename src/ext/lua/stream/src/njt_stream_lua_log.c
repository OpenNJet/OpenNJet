
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_log.c.tt2
 */


/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_stream_lua_log.h"
#include "njt_stream_lua_util.h"

#include "njt_stream_lua_log_ringbuf.h"


static int njt_stream_lua_print(lua_State *L);
static int njt_stream_lua_njt_log(lua_State *L);
static int log_wrapper(njt_log_t *log, const char *ident,
    njt_uint_t level, lua_State *L);
static void njt_stream_lua_inject_log_consts(lua_State *L);


/**
 * Wrapper of njet log functionality. Take a log level param and varargs of
 * log message params.
 *
 * @param L Lua state pointer
 * @retval always 0 (don't return values to Lua)
 * */
int
njt_stream_lua_njt_log(lua_State *L)
{
    njt_log_t                   *log;
    njt_stream_lua_request_t    *r;
    const char                  *msg;
    int                          level;

    r = njt_stream_lua_get_req(L);

    if (r && r->connection && r->connection->log) {
        log = r->connection->log;

    } else {
        log = njt_cycle->log;
    }

    level = luaL_checkint(L, 1);
    if (level < NJT_LOG_STDERR || level > NJT_LOG_DEBUG) {
        msg = lua_pushfstring(L, "bad log level: %d", level);
        return luaL_argerror(L, 1, msg);
    }

    /* remove log-level param from stack */
    lua_remove(L, 1);

    return log_wrapper(log, "stream [lua] ", (njt_uint_t) level, L);
}


/**
 * Override Lua print function, output message to njet error logs. Equal to
 * njt.log(njt.NOTICE, ...).
 *
 * @param L Lua state pointer
 * @retval always 0 (don't return values to Lua)
 * */
int
njt_stream_lua_print(lua_State *L)
{
    njt_log_t                   *log;
    njt_stream_lua_request_t    *r;

    r = njt_stream_lua_get_req(L);

    if (r && r->connection && r->connection->log) {
        log = r->connection->log;

    } else {
        log = njt_cycle->log;
    }

    return log_wrapper(log, "stream [lua] ", NJT_LOG_NOTICE, L);
}


static int
log_wrapper(njt_log_t *log, const char *ident, njt_uint_t level,
    lua_State *L)
{
    u_char              *buf;
    u_char              *p, *q;
    njt_str_t            name;
    int                  nargs, i;
    size_t               size, len;
    size_t               src_len = 0;
    int                  type;
    const char          *msg;
    lua_Debug            ar;

    if (level > log->log_level) {
        return 0;
    }

#if 1
    /* add debug info */

    lua_getstack(L, 1, &ar);
    lua_getinfo(L, "Snl", &ar);

    /* get the basename of the Lua source file path, stored in q */
    name.data = (u_char *) ar.short_src;
    if (name.data == NULL) {
        name.len = 0;

    } else {
        p = name.data;
        while (*p != '\0') {
            if (*p == '/' || *p == '\\') {
                name.data = p + 1;
            }
            p++;
        }

        name.len = p - name.data;
    }

#endif

    nargs = lua_gettop(L);

    size = name.len + NJT_INT_T_LEN + sizeof(":: ") - 1;

    if (*ar.namewhat != '\0' && *ar.what == 'L') {
        src_len = njt_strlen(ar.name);
        size += src_len + sizeof("(): ") - 1;
    }

    for (i = 1; i <= nargs; i++) {
        type = lua_type(L, i);
        switch (type) {
            case LUA_TNUMBER:
            case LUA_TSTRING:
                lua_tolstring(L, i, &len);
                size += len;
                break;

            case LUA_TNIL:
                size += sizeof("nil") - 1;
                break;

            case LUA_TBOOLEAN:
                if (lua_toboolean(L, i)) {
                    size += sizeof("true") - 1;

                } else {
                    size += sizeof("false") - 1;
                }

                break;

            case LUA_TTABLE:
                if (!luaL_callmeta(L, i, "__tostring")) {
                    return luaL_argerror(L, i, "expected table to have "
                                         "__tostring metamethod");
                }

                lua_tolstring(L, -1, &len);
                size += len;
                break;

            case LUA_TLIGHTUSERDATA:
                if (lua_touserdata(L, i) == NULL) {
                    size += sizeof("null") - 1;
                    break;
                }

                continue;

            default:
                msg = lua_pushfstring(L, "string, number, boolean, or nil "
                                      "expected, got %s",
                                      lua_typename(L, type));
                return luaL_argerror(L, i, msg);
        }
    }

    buf = lua_newuserdata(L, size);

    p = njt_copy(buf, name.data, name.len);

    *p++ = ':';

    p = njt_snprintf(p, NJT_INT_T_LEN, "%d",
                     ar.currentline > 0 ? ar.currentline : ar.linedefined);

    *p++ = ':'; *p++ = ' ';

    if (*ar.namewhat != '\0' && *ar.what == 'L') {
        p = njt_copy(p, ar.name, src_len);
        *p++ = '(';
        *p++ = ')';
        *p++ = ':';
        *p++ = ' ';
    }

    for (i = 1; i <= nargs; i++) {
        type = lua_type(L, i);
        switch (type) {
            case LUA_TNUMBER:
            case LUA_TSTRING:
                q = (u_char *) lua_tolstring(L, i, &len);
                p = njt_copy(p, q, len);
                break;

            case LUA_TNIL:
                *p++ = 'n';
                *p++ = 'i';
                *p++ = 'l';
                break;

            case LUA_TBOOLEAN:
                if (lua_toboolean(L, i)) {
                    *p++ = 't';
                    *p++ = 'r';
                    *p++ = 'u';
                    *p++ = 'e';

                } else {
                    *p++ = 'f';
                    *p++ = 'a';
                    *p++ = 'l';
                    *p++ = 's';
                    *p++ = 'e';
                }

                break;

            case LUA_TTABLE:
                luaL_callmeta(L, i, "__tostring");
                q = (u_char *) lua_tolstring(L, -1, &len);
                p = njt_copy(p, q, len);
                break;

            case LUA_TLIGHTUSERDATA:
                *p++ = 'n';
                *p++ = 'u';
                *p++ = 'l';
                *p++ = 'l';

                break;

            default:
                return luaL_error(L, "impossible to reach here");
        }
    }

    if (p - buf > (off_t) size) {
        return luaL_error(L, "buffer error: %d > %d", (int) (p - buf),
                          (int) size);
    }

    njt_log_error(level, log, 0, "%s%*s", ident, (size_t) (p - buf), buf);

    return 0;
}


void
njt_stream_lua_inject_log_api(lua_State *L)
{
    njt_stream_lua_inject_log_consts(L);

    lua_pushcfunction(L, njt_stream_lua_njt_log);
    lua_setfield(L, -2, "log");

    lua_pushcfunction(L, njt_stream_lua_print);
    lua_setglobal(L, "print");
}


static void
njt_stream_lua_inject_log_consts(lua_State *L)
{
    /* {{{ njet log level constants */
    lua_pushinteger(L, NJT_LOG_STDERR);
    lua_setfield(L, -2, "STDERR");

    lua_pushinteger(L, NJT_LOG_EMERG);
    lua_setfield(L, -2, "EMERG");

    lua_pushinteger(L, NJT_LOG_ALERT);
    lua_setfield(L, -2, "ALERT");

    lua_pushinteger(L, NJT_LOG_CRIT);
    lua_setfield(L, -2, "CRIT");

    lua_pushinteger(L, NJT_LOG_ERR);
    lua_setfield(L, -2, "ERR");

    lua_pushinteger(L, NJT_LOG_WARN);
    lua_setfield(L, -2, "WARN");

    lua_pushinteger(L, NJT_LOG_NOTICE);
    lua_setfield(L, -2, "NOTICE");

    lua_pushinteger(L, NJT_LOG_INFO);
    lua_setfield(L, -2, "INFO");

    lua_pushinteger(L, NJT_LOG_DEBUG);
    lua_setfield(L, -2, "DEBUG");
    /* }}} */
}


#ifdef HAVE_INTERCEPT_ERROR_LOG_PATCH
njt_int_t
njt_stream_lua_capture_log_handler(njt_log_t *log,
    njt_uint_t level, u_char *buf, size_t n)
{
    njt_stream_lua_log_ringbuf_t        *ringbuf;

    dd("enter");

    ringbuf = (njt_stream_lua_log_ringbuf_t  *)
                    njt_cycle->intercept_error_log_data;

    if (level > ringbuf->filter_level) {
        return NJT_OK;
    }

    njt_stream_lua_log_ringbuf_write(ringbuf, level, buf, n);

    dd("capture log: %s\n", buf);

    return NJT_OK;
}
#endif


int
njt_stream_lua_ffi_errlog_set_filter_level(int level, u_char *err,
    size_t *errlen)
{
#ifdef HAVE_INTERCEPT_ERROR_LOG_PATCH
    njt_stream_lua_log_ringbuf_t           *ringbuf;

    ringbuf = njt_cycle->intercept_error_log_data;

    if (ringbuf == NULL) {
        *errlen = njt_snprintf(err, *errlen,
                               "directive \"lua_capture_error_log\" is not set")
                  - err;
        return NJT_ERROR;
    }

    if (level > NJT_LOG_DEBUG || level < NJT_LOG_STDERR) {
        *errlen = njt_snprintf(err, *errlen, "bad log level: %d", level)
                  - err;
        return NJT_ERROR;
    }

    ringbuf->filter_level = level;
    return NJT_OK;
#else
    *errlen = njt_snprintf(err, *errlen,
                           "missing the capture error log patch for njet")
              - err;
    return NJT_ERROR;
#endif
}


int
njt_stream_lua_ffi_errlog_get_msg(char **log, int *loglevel, u_char *err,
    size_t *errlen, double *log_time)
{
#ifdef HAVE_INTERCEPT_ERROR_LOG_PATCH
    njt_uint_t           loglen;

    njt_stream_lua_log_ringbuf_t           *ringbuf;

    ringbuf = njt_cycle->intercept_error_log_data;

    if (ringbuf == NULL) {
        *errlen = njt_snprintf(err, *errlen,
                               "directive \"lua_capture_error_log\" is not set")
                  - err;
        return NJT_ERROR;
    }

    if (ringbuf->count == 0) {
        return NJT_DONE;
    }

    njt_stream_lua_log_ringbuf_read(ringbuf, loglevel, (void **) log, &loglen,
                                    log_time);
    return loglen;
#else
    *errlen = njt_snprintf(err, *errlen,
                           "missing the capture error log patch for njet")
              - err;
    return NJT_ERROR;
#endif
}


int
njt_stream_lua_ffi_errlog_get_sys_filter_level(njt_stream_lua_request_t *r)
{
    njt_log_t                   *log;
    int                          log_level;

    if (r && r->connection && r->connection->log) {
        log = r->connection->log;

    } else {
        log = njt_cycle->log;
    }

    log_level = log->log_level;
    if (log_level == NJT_LOG_DEBUG_ALL) {
        log_level = NJT_LOG_DEBUG;
    }

    return log_level;
}


int
njt_stream_lua_ffi_raw_log(njt_stream_lua_request_t *r, int level, u_char *s,
    size_t s_len)
{
    njt_log_t           *log;

    if (level > NJT_LOG_DEBUG || level < NJT_LOG_STDERR) {
        return NJT_ERROR;
    }

    if (r && r->connection && r->connection->log) {
        log = r->connection->log;

    } else {
        log = njt_cycle->log;
    }

    njt_log_error((unsigned) level, log, 0, "%*s", s_len, s);

    return NJT_OK;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
