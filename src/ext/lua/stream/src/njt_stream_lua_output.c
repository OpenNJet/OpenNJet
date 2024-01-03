
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_output.c.tt2
 */

#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_stream_lua_output.h"
#include "njt_stream_lua_util.h"
#include "njt_stream_lua_contentby.h"
#include <math.h>


static int njt_stream_lua_njt_say(lua_State *L);
static int njt_stream_lua_njt_print(lua_State *L);
static int njt_stream_lua_njt_flush(lua_State *L);
static int njt_stream_lua_njt_eof(lua_State *L);


static int njt_stream_lua_njt_echo(lua_State *L, unsigned newline);
static void njt_stream_lua_flush_cleanup(void *data);


static int
njt_stream_lua_njt_print(lua_State *L)
{
    dd("calling lua print");
    return njt_stream_lua_njt_echo(L, 0);
}


static int
njt_stream_lua_njt_say(lua_State *L)
{
    dd("calling");
    return njt_stream_lua_njt_echo(L, 1);
}


static int
njt_stream_lua_njt_echo(lua_State *L, unsigned newline)
{
    njt_stream_lua_request_t    *r;
    njt_stream_lua_ctx_t        *ctx;
    const char                  *p;
    size_t                       len;
    size_t                       size;
    njt_buf_t                   *b;
    njt_chain_t                 *cl;
    njt_int_t                    rc;
    int                          i;
    int                          nargs;
    int                          type;
    const char                  *msg;

    r = njt_stream_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request object found");
    }

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);

    if (ctx == NULL) {
        return luaL_error(L, "no request ctx found");
    }

    if (r->connection->type == SOCK_DGRAM) {
        return luaL_error(L, "API disabled in the current context");
    }

    njt_stream_lua_check_context(L, ctx, NJT_STREAM_LUA_CONTEXT_CONTENT
                                 | NJT_STREAM_LUA_CONTEXT_PREREAD);


    if (ctx->eof) {
        lua_pushnil(L);
        lua_pushliteral(L, "seen eof");
        return 2;
    }

    nargs = lua_gettop(L);
    size = 0;

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

                size += njt_stream_lua_calc_strlen_in_table(L, i, i,
                                                            0 /* strict */);
                break;

            case LUA_TLIGHTUSERDATA:

                dd("userdata: %p", lua_touserdata(L, i));

                if (lua_touserdata(L, i) == NULL) {
                    size += sizeof("null") - 1;
                    break;
                }

                continue;

            default:

                msg = lua_pushfstring(L, "string, number, boolean, nil, "
                                      "njt.null, or array table expected, "
                                      "but got %s", lua_typename(L, type));

                return luaL_argerror(L, i, msg);
        }
    }

    if (newline) {
        size += sizeof("\n") - 1;
    }

    if (size == 0) {

        lua_pushinteger(L, 1);
        return 1;
    }

    ctx->seen_body_data = 1;

    cl = njt_stream_lua_chain_get_free_buf(r->connection->log, r->pool,
                                           &ctx->free_bufs, size);

    if (cl == NULL) {
        return luaL_error(L, "no memory");
    }

    b = cl->buf;

    for (i = 1; i <= nargs; i++) {
        type = lua_type(L, i);
        switch (type) {
            case LUA_TNUMBER:
            case LUA_TSTRING:
                p = lua_tolstring(L, i, &len);
                b->last = njt_copy(b->last, (u_char *) p, len);
                break;

            case LUA_TNIL:
                *b->last++ = 'n';
                *b->last++ = 'i';
                *b->last++ = 'l';
                break;

            case LUA_TBOOLEAN:
                if (lua_toboolean(L, i)) {
                    *b->last++ = 't';
                    *b->last++ = 'r';
                    *b->last++ = 'u';
                    *b->last++ = 'e';

                } else {
                    *b->last++ = 'f';
                    *b->last++ = 'a';
                    *b->last++ = 'l';
                    *b->last++ = 's';
                    *b->last++ = 'e';
                }

                break;

            case LUA_TTABLE:
                b->last = njt_stream_lua_copy_str_in_table(L, i, b->last);
                break;

            case LUA_TLIGHTUSERDATA:
                *b->last++ = 'n';
                *b->last++ = 'u';
                *b->last++ = 'l';
                *b->last++ = 'l';
                break;

            default:
                return luaL_error(L, "impossible to reach here");
        }
    }

    if (newline) {
        *b->last++ = '\n';
    }

#if 0
    if (b->last != b->end) {
        return luaL_error(L, "buffer error: %p != %p", b->last, b->end);
    }
#endif

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   newline ? "lua say response" : "lua print response");

    rc = njt_stream_lua_send_chain_link(r, ctx, cl);

    if (rc == NJT_ERROR) {
        lua_pushnil(L);
        lua_pushliteral(L, "njet output filter error");
        return 2;
    }

    dd("downstream write: %d, buf len: %d", (int) rc,
       (int) (b->last - b->pos));

    lua_pushinteger(L, 1);
    return 1;
}


size_t
njt_stream_lua_calc_strlen_in_table(lua_State *L, int index, int arg_i,
    unsigned strict)
{
    double              key;
    int                 max;
    int                 i;
    int                 type;
    size_t              size;
    size_t              len;
    const char         *msg;

    if (index < 0) {
        index = lua_gettop(L) + index + 1;
    }

    dd("table index: %d", index);

    max = 0;

    lua_pushnil(L); /* stack: table key */
    while (lua_next(L, index) != 0) { /* stack: table key value */
        dd("key type: %s", luaL_typename(L, -2));

        if (lua_type(L, -2) == LUA_TNUMBER) {

            key = lua_tonumber(L, -2);

            dd("key value: %d", (int) key);

            if (floor(key) == key && key >= 1) {
                if (key > max) {
                    max = (int) key;
                }

                lua_pop(L, 1); /* stack: table key */
                continue;
            }
        }

        /* not an array (non positive integer key) */
        lua_pop(L, 2); /* stack: table */

        luaL_argerror(L, arg_i, "non-array table found");
        return 0;
    }

    size = 0;

    for (i = 1; i <= max; i++) {
        lua_rawgeti(L, index, i); /* stack: table value */
        type = lua_type(L, -1);

        switch (type) {
            case LUA_TNUMBER:
            case LUA_TSTRING:

                lua_tolstring(L, -1, &len);
                size += len;
                break;

            case LUA_TNIL:

                if (strict) {
                    goto bad_type;
                }

                size += sizeof("nil") - 1;
                break;

            case LUA_TBOOLEAN:

                if (strict) {
                    goto bad_type;
                }

                if (lua_toboolean(L, -1)) {
                    size += sizeof("true") - 1;

                } else {
                    size += sizeof("false") - 1;
                }

                break;

            case LUA_TTABLE:

                size += njt_stream_lua_calc_strlen_in_table(L, -1, arg_i,
                                                            strict);
                break;

            case LUA_TLIGHTUSERDATA:

                if (strict) {
                    goto bad_type;
                }

                if (lua_touserdata(L, -1) == NULL) {
                    size += sizeof("null") - 1;
                    break;
                }

                continue;

            default:

bad_type:

                msg = lua_pushfstring(L, "bad data type %s found",
                                      lua_typename(L, type));
                return luaL_argerror(L, arg_i, msg);
        }

        lua_pop(L, 1); /* stack: table */
    }

    return size;
}


u_char *
njt_stream_lua_copy_str_in_table(lua_State *L, int index, u_char *dst)
{
    double               key;
    int                  max;
    int                  i;
    int                  type;
    size_t               len;
    u_char              *p;

    if (index < 0) {
        index = lua_gettop(L) + index + 1;
    }

    max = 0;

    lua_pushnil(L); /* stack: table key */
    while (lua_next(L, index) != 0) { /* stack: table key value */
        key = lua_tonumber(L, -2);
        if (key > max) {
            max = (int) key;
        }

        lua_pop(L, 1); /* stack: table key */
    }

    for (i = 1; i <= max; i++) {
        lua_rawgeti(L, index, i); /* stack: table value */
        type = lua_type(L, -1);
        switch (type) {
            case LUA_TNUMBER:
            case LUA_TSTRING:
                p = (u_char *) lua_tolstring(L, -1, &len);
                dst = njt_copy(dst, p, len);
                break;

            case LUA_TNIL:
                *dst++ = 'n';
                *dst++ = 'i';
                *dst++ = 'l';
                break;

            case LUA_TBOOLEAN:
                if (lua_toboolean(L, -1)) {
                    *dst++ = 't';
                    *dst++ = 'r';
                    *dst++ = 'u';
                    *dst++ = 'e';

                } else {
                    *dst++ = 'f';
                    *dst++ = 'a';
                    *dst++ = 'l';
                    *dst++ = 's';
                    *dst++ = 'e';
                }

                break;

            case LUA_TTABLE:
                dst = njt_stream_lua_copy_str_in_table(L, -1, dst);
                break;

            case LUA_TLIGHTUSERDATA:

                *dst++ = 'n';
                *dst++ = 'u';
                *dst++ = 'l';
                *dst++ = 'l';
                break;

            default:
                luaL_error(L, "impossible to reach here");
                return NULL;
        }

        lua_pop(L, 1); /* stack: table */
    }

    return dst;
}


/**
 * Force flush out response content
 * */
static int
njt_stream_lua_njt_flush(lua_State *L)
{
    njt_stream_lua_request_t    *r;
    njt_stream_lua_ctx_t        *ctx;
    njt_chain_t                 *cl;
    njt_int_t                    rc;
    int                          n;
    unsigned                     wait = 0;
    njt_event_t                 *wev;

    njt_stream_lua_srv_conf_t   *cllscf;

    njt_stream_lua_co_ctx_t             *coctx;

    n = lua_gettop(L);
    if (n > 1) {
        return luaL_error(L, "attempt to pass %d arguments, but accepted 0 "
                          "or 1", n);
    }

    r = njt_stream_lua_get_req(L);

    if (n == 1) {
        luaL_checktype(L, 1, LUA_TBOOLEAN);
        wait = lua_toboolean(L, 1);
    }

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no request ctx found");
    }

    if (r->connection->type == SOCK_DGRAM) {
        return luaL_error(L, "API disabled in the current context");
    }

    njt_stream_lua_check_context(L, ctx, NJT_STREAM_LUA_CONTEXT_CONTENT
                                 | NJT_STREAM_LUA_CONTEXT_PREREAD);


    coctx = ctx->cur_co_ctx;
    if (coctx == NULL) {
        return luaL_error(L, "no co ctx found");
    }


    if (ctx->eof) {
        lua_pushnil(L);
        lua_pushliteral(L, "seen eof");
        return 2;
    }


    cl = njt_stream_lua_get_flush_chain(r, ctx);
    if (cl == NULL) {
        return luaL_error(L, "no memory");
    }

    rc = njt_stream_lua_send_chain_link(r, ctx, cl);

    dd("send chain: %d", (int) rc);

    if (rc == NJT_ERROR) {
        lua_pushnil(L);
        lua_pushliteral(L, "njet output filter error");
        return 2;
    }

    dd("wait:%d, rc:%d, buffered:0x%x", wait, (int) rc,
       r->connection->buffered);

    wev = r->connection->write;

    if (wait && (r->connection->buffered || wev->delayed))
    {
        njt_log_debug2(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                       "lua flush requires waiting: buffered 0x%uxd, "
                       "delayed:%d", (unsigned) r->connection->buffered,
                       wev->delayed);

        coctx->flushing = 1;
        ctx->flushing_coros++;

        if (ctx->entered_content_phase) {
            /* mimic njt_http_set_write_handler */
            r->write_event_handler = njt_stream_lua_content_wev_handler;

        } else {
            r->write_event_handler = njt_stream_lua_core_run_phases;
        }

        cllscf = njt_stream_lua_get_module_srv_conf(r, njt_stream_lua_module);

        if (!wev->delayed) {
            njt_add_timer(wev, cllscf->send_timeout);
        }


        if (njt_handle_write_event(wev, cllscf->send_lowat) != NJT_OK) {
            if (wev->timer_set) {
                wev->delayed = 0;
                njt_del_timer(wev);
            }

            lua_pushnil(L);
            lua_pushliteral(L, "connection broken");
            return 2;
        }

        njt_stream_lua_cleanup_pending_operation(ctx->cur_co_ctx);
        coctx->cleanup = njt_stream_lua_flush_cleanup;
        coctx->data = r;

        return lua_yield(L, 0);
    }

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "lua flush asynchronously");

    lua_pushinteger(L, 1);
    return 1;
}


/**
 * Send last_buf, terminate output stream
 * */
static int
njt_stream_lua_njt_eof(lua_State *L)
{
    njt_stream_lua_request_t    *r;
    njt_stream_lua_ctx_t        *ctx;
    njt_int_t                    rc;

    r = njt_stream_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request object found");
    }

    if (lua_gettop(L) != 0) {
        return luaL_error(L, "no argument is expected");
    }

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no ctx found");
    }


    if (ctx->eof) {
        lua_pushnil(L);
        lua_pushliteral(L, "seen eof");
        return 2;
    }

    if (r->connection->type == SOCK_DGRAM) {
        return luaL_error(L, "API disabled in the current context");
    }

    njt_stream_lua_check_context(L, ctx, NJT_STREAM_LUA_CONTEXT_CONTENT
                                 | NJT_STREAM_LUA_CONTEXT_PREREAD);

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "lua send eof");

    rc = njt_stream_lua_send_chain_link(r, ctx, NULL /* indicate last_buf */);

    dd("send chain: %d", (int) rc);

    if (rc == NJT_ERROR) {
        lua_pushnil(L);
        lua_pushliteral(L, "njet output filter error");
        return 2;
    }

    lua_pushinteger(L, 1);
    return 1;
}


void
njt_stream_lua_inject_output_api(lua_State *L)
{

    lua_pushcfunction(L, njt_stream_lua_njt_print);
    lua_setfield(L, -2, "print");

    lua_pushcfunction(L, njt_stream_lua_njt_say);
    lua_setfield(L, -2, "say");

    lua_pushcfunction(L, njt_stream_lua_njt_flush);
    lua_setfield(L, -2, "flush");

    lua_pushcfunction(L, njt_stream_lua_njt_eof);
    lua_setfield(L, -2, "eof");
}




njt_int_t
njt_stream_lua_flush_resume_helper(njt_stream_lua_request_t *r,
    njt_stream_lua_ctx_t *ctx)
{
    int                          n;
    lua_State                   *vm;
    njt_int_t                    rc;
    njt_uint_t                   nreqs;
    njt_connection_t            *c;

    c = r->connection;

    ctx->cur_co_ctx->cleanup = NULL;

    /* push the return values */

    if (c->timedout) {
        lua_pushnil(ctx->cur_co_ctx->co);
        lua_pushliteral(ctx->cur_co_ctx->co, "timeout");
        n = 2;

    } else if (c->error) {
        lua_pushnil(ctx->cur_co_ctx->co);
        lua_pushliteral(ctx->cur_co_ctx->co, "client aborted");
        n = 2;

    } else {
        lua_pushinteger(ctx->cur_co_ctx->co, 1);
        n = 1;
    }

    vm = njt_stream_lua_get_lua_vm(r, ctx);
    nreqs = c->requests;

    rc = njt_stream_lua_run_thread(vm, r, ctx, n);

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "lua run thread returned %d", rc);

    if (rc == NJT_AGAIN) {
        return njt_stream_lua_run_posted_threads(c, vm, r, ctx, nreqs);
    }

    if (rc == NJT_DONE) {
        njt_stream_lua_finalize_request(r, NJT_DONE);
        return njt_stream_lua_run_posted_threads(c, vm, r, ctx, nreqs);
    }

    /* rc == NJT_ERROR || rc >= NJT_OK */

    if (ctx->entered_content_phase) {
        njt_stream_lua_finalize_request(r, rc);
        return NJT_DONE;
    }

    return rc;
}


static void
njt_stream_lua_flush_cleanup(void *data)
{
    njt_stream_lua_request_t            *r;
    njt_event_t                         *wev;
    njt_stream_lua_ctx_t                *ctx;
    njt_stream_lua_co_ctx_t             *coctx = data;

    coctx->flushing = 0;

    r = coctx->data;
    if (r == NULL) {
        return;
    }

    wev = r->connection->write;

    if (wev && wev->timer_set) {
        njt_del_timer(wev);
    }

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
    if (ctx == NULL) {
        return;
    }

    ctx->flushing_coros--;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
