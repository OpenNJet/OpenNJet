
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_http_lua_headers.h"
#include "njt_http_lua_headers_out.h"
#include "njt_http_lua_headers_in.h"
#include "njt_http_lua_util.h"


static int njt_http_lua_njt_req_http_version(lua_State *L);
static int njt_http_lua_njt_req_raw_header(lua_State *L);
static int njt_http_lua_njt_req_header_set_helper(lua_State *L);
static int njt_http_lua_njt_resp_get_headers(lua_State *L);
static int njt_http_lua_njt_req_header_set(lua_State *L);
#if (njet_version >= 1011011)
void njt_http_lua_njt_raw_header_cleanup(void *data);
#endif


void
njt_http_lua_inject_resp_header_api(lua_State *L)
{
    lua_createtable(L, 0, 1); /* .resp */

    lua_pushcfunction(L, njt_http_lua_njt_resp_get_headers);
    lua_setfield(L, -2, "get_headers");

    lua_setfield(L, -2, "resp");
}


void
njt_http_lua_inject_req_header_api(lua_State *L)
{
    lua_pushcfunction(L, njt_http_lua_njt_req_http_version);
    lua_setfield(L, -2, "http_version");

    lua_pushcfunction(L, njt_http_lua_njt_req_raw_header);
    lua_setfield(L, -2, "raw_header");

    lua_pushcfunction(L, njt_http_lua_njt_req_header_set);
    lua_setfield(L, -2, "set_header");
}


static int
njt_http_lua_njt_req_http_version(lua_State *L)
{
    njt_http_request_t          *r;

    r = njt_http_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request object found");
    }

    njt_http_lua_check_fake_request(L, r);

    switch (r->http_version) {
    case NJT_HTTP_VERSION_9:
        lua_pushnumber(L, 0.9);
        break;

    case NJT_HTTP_VERSION_10:
        lua_pushnumber(L, 1.0);
        break;

    case NJT_HTTP_VERSION_11:
        lua_pushnumber(L, 1.1);
        break;

#ifdef NJT_HTTP_VERSION_20
    case NJT_HTTP_VERSION_20:
        lua_pushnumber(L, 2.0);
        break;
#endif

#ifdef NJT_HTTP_VERSION_30
    case NJT_HTTP_VERSION_30:
        lua_pushnumber(L, 3.0);
        break;
#endif

    default:
        lua_pushnil(L);
        break;
    }

    return 1;
}


static int
njt_http_lua_njt_req_raw_header(lua_State *L)
{
    int                          n, line_break_len;
    u_char                      *data, *p, *last, *pos;
    unsigned                     no_req_line = 0, found;
    size_t                       size;
    njt_buf_t                   *b, *first = NULL;
    njt_int_t                    i, j;
#if (njet_version >= 1011011)
    njt_buf_t                  **bb;
    njt_chain_t                 *cl;
    njt_http_lua_main_conf_t    *lmcf;
#endif
    njt_connection_t            *c;
    njt_http_request_t          *r, *mr;
    njt_http_connection_t       *hc;

    n = lua_gettop(L);
    if (n > 0) {
        no_req_line = lua_toboolean(L, 1);
    }

    dd("no req line: %d", (int) no_req_line);

    r = njt_http_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request object found");
    }

#if (njet_version >= 1011011)
    lmcf = njt_http_get_module_main_conf(r, njt_http_lua_module);
#endif

    njt_http_lua_check_fake_request(L, r);

    mr = r->main;
    hc = mr->http_connection;
    c = mr->connection;

#if (NJT_HTTP_V2)
    if (mr->stream) {
        return luaL_error(L, "http2 requests not supported yet");
    }
#endif

#if 1
    dd("hc->nbusy: %d", (int) hc->nbusy);

    if (hc->nbusy) {
#if (njet_version >= 1011011)
        dd("hc->busy: %p %p %p %p", hc->busy->buf->start, hc->busy->buf->pos,
           hc->busy->buf->last, hc->busy->buf->end);
#else
        dd("hc->busy: %p %p %p %p", hc->busy[0]->start, hc->busy[0]->pos,
           hc->busy[0]->last, hc->busy[0]->end);
#endif
    }

    dd("request line: %p %p", mr->request_line.data,
       mr->request_line.data + mr->request_line.len);

    dd("header in: %p %p %p %p", mr->header_in->start,
       mr->header_in->pos, mr->header_in->last,
       mr->header_in->end);

    dd("c->buffer: %p %p %p %p", c->buffer->start,
       c->buffer->pos, c->buffer->last,
       c->buffer->end);
#endif

    size = 0;
    b = c->buffer;

    if (mr->request_line.len == 0) {
        /* return empty string on invalid request */
        lua_pushlstring(L, "", 0);
        return 1;
    }

    if (mr->request_line.data[mr->request_line.len] == CR) {
        line_break_len = 2;

    } else {
        line_break_len = 1;
    }

    if (mr->request_line.data >= b->start
        && mr->request_line.data + mr->request_line.len
           + line_break_len <= b->pos)
    {
        first = b;
        size += b->pos - mr->request_line.data;
    }

    dd("size: %d", (int) size);

    if (hc->nbusy) {
#if (njet_version >= 1011011)
        if (hc->nbusy > lmcf->busy_buf_ptr_count) {
            if (lmcf->busy_buf_ptrs) {
                njt_free(lmcf->busy_buf_ptrs);
            }

            lmcf->busy_buf_ptrs = njt_alloc(hc->nbusy * sizeof(njt_buf_t *),
                                            r->connection->log);

            if (lmcf->busy_buf_ptrs == NULL) {
                return luaL_error(L, "no memory");
            }

            lmcf->busy_buf_ptr_count = hc->nbusy;
        }

        bb = lmcf->busy_buf_ptrs;
        for (cl = hc->busy; cl; cl = cl->next) {
            *bb++ = cl->buf;
        }
#endif
        b = NULL;

#if (njet_version >= 1011011)
        bb = lmcf->busy_buf_ptrs;
        for (i = hc->nbusy; i > 0; i--) {
            b = bb[i - 1];
#else
        for (i = 0; i < hc->nbusy; i++) {
            b = hc->busy[i];
#endif

            dd("busy buf: %d: [%.*s]", (int) i, (int) (b->pos - b->start),
               b->start);

            if (first == NULL) {
                if (mr->request_line.data >= b->pos
                    || mr->request_line.data
                       + mr->request_line.len + line_break_len
                       <= b->start)
                {
                    continue;
                }

                dd("found first at %d", (int) i);
                first = b;
            }

            dd("adding size %d", (int) (b->pos - b->start));
            size += b->pos - b->start;
        }
    }

    size++;  /* plus the null terminator, as required by the later
                njt_strstr() call */

    dd("header size: %d", (int) size);

    data = lua_newuserdata(L, size);
    last = data;

    b = c->buffer;
    found = 0;

    if (first == b) {
        found = 1;
        pos = b->pos;

        if (no_req_line) {
            last = njt_copy(data,
                            mr->request_line.data
                            + mr->request_line.len + line_break_len,
                            pos - mr->request_line.data
                            - mr->request_line.len - line_break_len);

        } else {
            last = njt_copy(data, mr->request_line.data,
                            pos - mr->request_line.data);
        }

        if (b != mr->header_in) {
            /* skip truncated header entries (if any) */
            while (last > data && last[-1] != LF && last[-1] != '\0') {
                last--;
            }
        }

        i = 0;
        for (p = data; p != last; p++) {
            if (*p == '\0') {
                i++;
                if (p + 1 != last && *(p + 1) == LF) {
                    *p = CR;

                } else if (i % 2 == 1) {
                    *p = ':';

                } else {
                    *p = LF;
                }
            }
        }
    }

    if (hc->nbusy) {

#if (njet_version >= 1011011)
        bb = lmcf->busy_buf_ptrs;
        for (i = hc->nbusy - 1; i >= 0; i--) {
            b = bb[i];
#else
        for (i = 0; i < hc->nbusy; i++) {
            b = hc->busy[i];
#endif

            if (!found) {
                if (b != first) {
                    continue;
                }

                dd("found first");
                found = 1;
            }

            p = last;

            pos = b->pos;

            if (b == first) {
                dd("request line: %.*s", (int) mr->request_line.len,
                   mr->request_line.data);

                if (no_req_line) {
                    last = njt_copy(last,
                                    mr->request_line.data
                                    + mr->request_line.len + line_break_len,
                                    pos - mr->request_line.data
                                    - mr->request_line.len - line_break_len);

                } else {
                    last = njt_copy(last,
                                    mr->request_line.data,
                                    pos - mr->request_line.data);

                }

            } else {
                last = njt_copy(last, b->start, pos - b->start);
            }

#if 1
            /* skip truncated header entries (if any) */
            while (last > p && last[-1] != LF && last[-1] != '\0') {
                last--;
            }
#endif

            j = 0;
            for (; p != last; p++) {
                if (*p == '\0') {
                    j++;
                    if (p + 1 == last) {
                        *p = LF;

                    } else if (*(p + 1) == LF) {
                        *p = CR;

                    } else if (j % 2 == 1) {
                        *p = ':';

                    } else {
                        *p = LF;
                    }
                }
            }

            if (b == mr->header_in) {
                break;
            }
        }
    }

    *last++ = '\0';

    if (last - data > (ssize_t) size) {
        return luaL_error(L, "buffer error: %d", (int) (last - data - size));
    }

    /* strip the leading part (if any) of the request body in our header.
     * the first part of the request body could slip in because njet core's
     * njt_http_request_body_length_filter and etc can move r->header_in->pos
     * in case that some of the body data has been preread into r->header_in.
     */

    if ((p = (u_char *) njt_strstr(data, CRLF CRLF)) != NULL) {
        last = p + sizeof(CRLF CRLF) - 1;

    } else if ((p = (u_char *) njt_strstr(data, CRLF "\n")) != NULL) {
        last = p + sizeof(CRLF "\n") - 1;

    } else if ((p = (u_char *) njt_strstr(data, "\n" CRLF)) != NULL) {
        last = p + sizeof("\n" CRLF) - 1;

    } else {
        for (p = last - 1; p - data >= 2; p--) {
            if (p[0] == LF && p[-1] == CR) {
                p[-1] = LF;
                last = p + 1;
                break;
            }

            if (p[0] == LF && p[-1] == LF) {
                last = p + 1;
                break;
            }
        }
    }

    lua_pushlstring(L, (char *) data, last - data);
    return 1;
}


static int
njt_http_lua_njt_resp_get_headers(lua_State *L)
{
    njt_list_part_t    *part;
    njt_table_elt_t    *header;
    njt_http_request_t *r;
    njt_http_lua_ctx_t *ctx;
    u_char             *lowcase_key = NULL;
    size_t              lowcase_key_sz = 0;
    njt_uint_t          i;
    int                 n;
    int                 max;
    int                 raw = 0;
    int                 count = 0;
    int                 truncated = 0;
    int                 extra = 0;
    u_char             *p = NULL;
    size_t              len = 0;

    n = lua_gettop(L);

    if (n >= 1) {
        if (lua_isnil(L, 1)) {
            max = NJT_HTTP_LUA_MAX_HEADERS;

        } else {
            max = luaL_checkinteger(L, 1);
        }

        if (n >= 2) {
            raw = lua_toboolean(L, 2);
        }

    } else {
        max = NJT_HTTP_LUA_MAX_HEADERS;
    }

    r = njt_http_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request object found");
    }

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no ctx found");
    }

    njt_http_lua_check_fake_request(L, r);

    part = &r->headers_out.headers.part;
    count = part->nelts;
    while (part->next != NULL) {
        part = part->next;
        count += part->nelts;
    }

    lua_createtable(L, 0, count + 2);

    if (!raw) {
        lua_pushlightuserdata(L, njt_http_lua_lightudata_mask(
                              headers_metatable_key));
        lua_rawget(L, LUA_REGISTRYINDEX);
        lua_setmetatable(L, -2);
    }

#if 1
    if (r->headers_out.content_type.len) {
        extra++;
        lua_pushliteral(L, "content-type");
        lua_pushlstring(L, (char *) r->headers_out.content_type.data,
                        r->headers_out.content_type.len);
        lua_rawset(L, -3);
    }

    if (r->headers_out.content_length == NULL
        && r->headers_out.content_length_n >= 0)
    {
        extra++;
        lua_pushliteral(L, "content-length");
        if (r->headers_out.content_length_n > NJT_MAX_INT32_VALUE) {
            p = njt_palloc(r->pool, NJT_OFF_T_LEN);
            if (p == NULL) {
                return luaL_error(L, "no memory");
            }

            len = njt_snprintf(p, NJT_OFF_T_LEN, "%O",
                               r->headers_out.content_length_n) - p;

            lua_pushlstring(L, (char *) p, len);

        } else {
            lua_pushfstring(L, "%d", (int) r->headers_out.content_length_n);
        }

        lua_rawset(L, -3);
    }

    extra++;
    lua_pushliteral(L, "connection");
    if (r->headers_out.status == NJT_HTTP_SWITCHING_PROTOCOLS) {
        lua_pushliteral(L, "upgrade");

    } else if (r->keepalive) {
        lua_pushliteral(L, "keep-alive");

    } else {
        lua_pushliteral(L, "close");
    }

    lua_rawset(L, -3);

    if (r->chunked) {
        extra++;
        lua_pushliteral(L, "transfer-encoding");
        lua_pushliteral(L, "chunked");
        lua_rawset(L, -3);
    }
#endif

    if (max > 0 && count + extra > max) {
        truncated = 1;
        njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "lua exceeding response header limit %d > %d",
                       count + extra, max);
        count = max - extra;
    }

    part = &r->headers_out.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

        dd("stack top: %d", lua_gettop(L));

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        if (raw) {
            lua_pushlstring(L, (char *) header[i].key.data, header[i].key.len);

        } else {
            /* njet does not even bother initializing output header entry's
             * "lowcase_key" field. so we cannot count on that at all. */
            if (header[i].key.len > lowcase_key_sz) {
                lowcase_key_sz = header[i].key.len * 2;

                /* we allocate via Lua's GC to prevent in-request
                 * leaks in the njet request memory pools */
                lowcase_key = lua_newuserdata(L, lowcase_key_sz);
                lua_insert(L, 1);
            }

            njt_strlow(lowcase_key, header[i].key.data, header[i].key.len);
            lua_pushlstring(L, (char *) lowcase_key, header[i].key.len);
        }

        /* stack: [udata] table key */

        lua_pushlstring(L, (char *) header[i].value.data,
                        header[i].value.len); /* stack: [udata] table key
                                                 value */

        njt_http_lua_set_multi_value_table(L, -3);

        njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "lua response header: \"%V: %V\"",
                       &header[i].key, &header[i].value);

        if (--count <= 0) {
            break;
        }
    }  /* for */

    if (truncated) {
        lua_pushliteral(L, "truncated");
        return 2;
    }

    return 1;
}


static int
njt_http_lua_njt_req_header_set(lua_State *L)
{
    if (lua_gettop(L) != 2) {
        return luaL_error(L, "expecting two arguments, but seen %d",
                          lua_gettop(L));
    }

    return njt_http_lua_njt_req_header_set_helper(L);
}


static int
njt_http_lua_njt_req_header_set_helper(lua_State *L)
{
    njt_http_request_t          *r;
    u_char                      *p;
    njt_str_t                    key;
    njt_str_t                    value;
    njt_uint_t                   i;
    size_t                       len;
    njt_int_t                    rc;
    njt_uint_t                   n;

    r = njt_http_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request object found");
    }

    njt_http_lua_check_fake_request(L, r);

    if (r->http_version < NJT_HTTP_VERSION_10) {
        return 0;
    }

    p = (u_char *) luaL_checklstring(L, 1, &len);

    dd("key: %.*s, len %d", (int) len, p, (int) len);

#if 0
    /* replace "_" with "-" */
    for (i = 0; i < len; i++) {
        if (p[i] == '_') {
            p[i] = '-';
        }
    }
#endif

    key.data = njt_palloc(r->pool, len + 1);
    if (key.data == NULL) {
        return luaL_error(L, "no memory");
    }

    njt_memcpy(key.data, p, len);

    key.data[len] = '\0';

    key.len = len;

    if (lua_type(L, 2) == LUA_TNIL) {
        njt_str_null(&value);

    } else if (lua_type(L, 2) == LUA_TTABLE) {
        n = lua_objlen(L, 2);
        if (n == 0) {
            njt_str_null(&value);

        } else {
            for (i = 1; i <= n; i++) {
                dd("header value table index %d, top: %d", (int) i,
                   lua_gettop(L));

                lua_rawgeti(L, 2, i);
                p = (u_char *) luaL_checklstring(L, -1, &len);

                /*
                 * we also copy the trailing '\0' char here because njet
                 * header values must be null-terminated
                 * */

                value.data = njt_palloc(r->pool, len + 1);
                if (value.data == NULL) {
                    return luaL_error(L, "no memory");
                }

                njt_memcpy(value.data, p, len + 1);
                value.len = len;

                rc = njt_http_lua_set_input_header(r, key, value,
                                                   i == 1 /* override */);

                if (rc == NJT_ERROR) {
                    return luaL_error(L,
                                      "failed to set header %s (error: %d)",
                                      key.data, (int) rc);
                }
            }

            return 0;
        }

    } else {

        /*
         * we also copy the trailing '\0' char here because njet
         * header values must be null-terminated
         * */

        p = (u_char *) luaL_checklstring(L, 2, &len);
        value.data = njt_palloc(r->pool, len + 1);
        if (value.data == NULL) {
            return luaL_error(L, "no memory");
        }

        njt_memcpy(value.data, p, len + 1);
        value.len = len;
    }

    dd("key: %.*s, value: %.*s",
       (int) key.len, key.data, (int) value.len, value.data);

    rc = njt_http_lua_set_input_header(r, key, value, 1 /* override */);

    if (rc == NJT_ERROR) {
        return luaL_error(L, "failed to set header %s (error: %d)",
                          key.data, (int) rc);
    }

    return 0;
}


void
njt_http_lua_create_headers_metatable(njt_log_t *log, lua_State *L)
{
    int rc;
    const char buf[] =
        "local tb, key = ...\n"
        "local new_key = string.gsub(string.lower(key), '_', '-')\n"
        "if new_key ~= key then return tb[new_key] else return nil end";

    lua_pushlightuserdata(L, njt_http_lua_lightudata_mask(
                          headers_metatable_key));

    /* metatable for njt.req.get_headers(_, true) and
     * njt.resp.get_headers(_, true) */
    lua_createtable(L, 0, 1);

    rc = luaL_loadbuffer(L, buf, sizeof(buf) - 1, "=headers metatable");
    if (rc != 0) {
        njt_log_error(NJT_LOG_ERR, log, 0,
                      "failed to load Lua code for the metamethod for "
                      "headers: %i: %s", rc, lua_tostring(L, -1));

        lua_pop(L, 3);
        return;
    }

    lua_setfield(L, -2, "__index");
    lua_rawset(L, LUA_REGISTRYINDEX);
}


int
njt_http_lua_ffi_req_get_headers_count(njt_http_request_t *r, int max,
    int *truncated)
{
    int                           count;
    njt_list_part_t              *part;
#if (NJT_HTTP_V3)
    int                           has_host = 0;
    njt_uint_t                    i;
    njt_table_elt_t              *header;
#endif

    if (r->connection->fd == (njt_socket_t) -1) {
        return NJT_HTTP_LUA_FFI_BAD_CONTEXT;
    }

    *truncated = 0;

    if (max < 0) {
        max = NJT_HTTP_LUA_MAX_HEADERS;
    }

    part = &r->headers_in.headers.part;

#if (NJT_HTTP_V3)
    count = 0;
    header = part->elts;

    if (r->http_version == NJT_HTTP_VERSION_30
        && r->headers_in.server.data != NULL)
    {
        has_host = 1;
        count++;
    }

    if (has_host == 1) {
        for (i = 0; /* void */; i++) {
            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            if (header[i].key.len == 4
                && njt_strncasecmp(header[i].key.data,
                                   (u_char *) "host", 4) == 0)
            {
                continue;
            }

            count++;
        }

    } else {
        count = part->nelts;
        while (part->next != NULL) {
            part = part->next;
            count += part->nelts;
        }
    }
#else
    count = part->nelts;
    while (part->next != NULL) {
        part = part->next;
        count += part->nelts;
    }
#endif

    if (max > 0 && count > max) {
        *truncated = 1;

        njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "lua exceeding request header limit %d > %d", count,
                       max);
        count = max;
    }

    return count;
}


int
njt_http_lua_ffi_req_get_headers(njt_http_request_t *r,
    njt_http_lua_ffi_table_elt_t *out, int count, int raw)
{
    int                           n;
    njt_uint_t                    i;
    njt_list_part_t              *part;
    njt_table_elt_t              *header;
#if (NJT_HTTP_V3)
    int                           has_host = 0;
#endif

    if (count <= 0) {
        return NJT_OK;
    }

    n = 0;

#if (NJT_HTTP_V3)
    if (r->http_version == NJT_HTTP_VERSION_30
        && r->headers_in.server.data != NULL)
    {
        out[n].key.data = (u_char *) "host";
        out[n].key.len = sizeof("host") - 1;
        out[n].value.len = r->headers_in.server.len;
        out[n].value.data = r->headers_in.server.data;
        has_host = 1;
        ++n;
    }
#endif

    part = &r->headers_in.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

#if (NJT_HTTP_V3)
        if (has_host == 1 && header[i].key.len == 4
            && njt_strncasecmp(header[i].key.data, (u_char *) "host", 4) == 0)
        {
            continue;
        }
#endif

        if (raw) {
            out[n].key.data = header[i].key.data;
            out[n].key.len = (int) header[i].key.len;

        } else {
            out[n].key.data = header[i].lowcase_key;
            out[n].key.len = (int) header[i].key.len;
        }

        out[n].value.data = header[i].value.data;
        out[n].value.len = (int) header[i].value.len;

        if (++n == count) {
            return NJT_OK;
        }
    }

    return NJT_OK;
}


int
njt_http_lua_ffi_set_resp_header(njt_http_request_t *r, const u_char *key_data,
    size_t key_len, int is_nil, const u_char *sval, size_t sval_len,
    njt_http_lua_ffi_str_t *mvals, size_t mvals_len, int override,
    char **errmsg)
{
    u_char                      *p;
    njt_str_t                    value, key;
    njt_uint_t                   i;
    size_t                       len;
    njt_http_lua_ctx_t          *ctx;
    njt_int_t                    rc;
    njt_http_lua_loc_conf_t     *llcf;

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);
    if (ctx == NULL) {
        return NJT_HTTP_LUA_FFI_NO_REQ_CTX;
    }

    if (r->connection->fd == (njt_socket_t) -1) {
        return NJT_HTTP_LUA_FFI_BAD_CONTEXT;
    }

    if (r->header_sent || ctx->header_sent) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "attempt to "
                      "set njt.header.HEADER after sending out "
                      "response headers");
        return NJT_DECLINED;
    }

    key.data = njt_palloc(r->pool, key_len + 1);
    if (key.data == NULL) {
        goto nomem;
    }

    njt_memcpy(key.data, key_data, key_len);
    key.data[key_len] = '\0';
    key.len = key_len;

    llcf = njt_http_get_module_loc_conf(r, njt_http_lua_module);

    if (llcf->transform_underscores_in_resp_headers) {
        /* replace "_" with "-" */
        p = key.data;
        for (i = 0; i < key_len; i++) {
            if (p[i] == '_') {
                p[i] = '-';
            }
        }
    }

    ctx->headers_set = 1;

    if (is_nil) {
        value.data = NULL;
        value.len = 0;

    } else if (mvals) {

        if (mvals_len == 0) {
            value.data = NULL;
            value.len = 0;

        } else {
            for (i = 0; i < mvals_len; i++) {
                dd("header value table index %d", (int) i);

                p = mvals[i].data;
                len = mvals[i].len;

                value.data = njt_palloc(r->pool, len);
                if (value.data == NULL) {
                    goto nomem;
                }

                njt_memcpy(value.data, p, len);
                value.len = len;

                rc = njt_http_lua_set_output_header(r, ctx, key, value,
                                                    override && i == 0);

                if (rc == NJT_ERROR) {
                    *errmsg = "failed to set header";
                    return NJT_ERROR;
                }
            }

            return NJT_OK;
        }

    } else {
        p = (u_char *) sval;
        value.data = njt_palloc(r->pool, sval_len);
        if (value.data == NULL) {
            goto nomem;
        }

        njt_memcpy(value.data, p, sval_len);
        value.len = sval_len;
    }

    dd("key: %.*s, value: %.*s",
       (int) key.len, key.data, (int) value.len, value.data);

    rc = njt_http_lua_set_output_header(r, ctx, key, value, override);

    if (rc == NJT_ERROR) {
        *errmsg = "failed to set header";
        return NJT_ERROR;
    }

    return 0;

nomem:

    *errmsg = "no memory";
    return NJT_ERROR;
}


int
njt_http_lua_ffi_req_set_header(njt_http_request_t *r, const u_char *key,
    size_t key_len, const u_char *value, size_t value_len,
    njt_http_lua_ffi_str_t *mvals, size_t mvals_len, int override,
    char **errmsg)
{
    u_char                      *p;
    size_t                       len;
    njt_uint_t                   i;
    njt_str_t                    k, v;

    if (r->connection->fd == (njt_socket_t) -1) {  /* fake request */
        return NJT_HTTP_LUA_FFI_BAD_CONTEXT;
    }

    if (r->http_version < NJT_HTTP_VERSION_10) {
        return NJT_DECLINED;
    }

    k.data = njt_palloc(r->pool, key_len + 1);
    if (k.data == NULL) {
        goto nomem;
    }

    njt_memcpy(k.data, key, key_len);
    k.data[key_len] = '\0';
    k.len = key_len;

    if (mvals) {
        if (mvals_len > 0) {
            for (i = 0; i < mvals_len; i++) {
                p = mvals[i].data;
                len = mvals[i].len;

                v.data = njt_palloc(r->pool, len + 1);
                if (v.data == NULL) {
                    goto nomem;
                }

                njt_memcpy(v.data, p, len);
                v.data[len] = '\0';
                v.len = len;

                if (njt_http_lua_set_input_header(r, k, v, override && i == 0)
                    != NJT_OK)
                {
                    goto failed;
                }
            }

            return NJT_OK;
        }

        v.data = NULL;
        v.len = 0;

    } else if (value) {
        v.data = njt_palloc(r->pool, value_len + 1);
        if (v.data == NULL) {
            goto nomem;
        }

        njt_memcpy(v.data, value, value_len);
        v.data[value_len] = '\0';
        v.len = value_len;

    } else {
        v.data = NULL;
        v.len = 0;
    }

    if (njt_http_lua_set_input_header(r, k, v, override) != NJT_OK) {
        goto failed;
    }

    return NJT_OK;

nomem:

    *errmsg = "no memory";
    return NJT_ERROR;

failed:

    *errmsg = "failed to set header";
    return NJT_ERROR;
}


int
njt_http_lua_ffi_get_resp_header(njt_http_request_t *r,
    const u_char *key, size_t key_len,
    u_char *key_buf, njt_http_lua_ffi_str_t *values, int max_nvalues,
    char **errmsg)
{
    int                  found;
    u_char               c, *p;
    time_t               last_modified;
    njt_uint_t           i;
    njt_table_elt_t     *h;
    njt_list_part_t     *part;
    njt_http_lua_ctx_t  *ctx;

    njt_http_lua_loc_conf_t     *llcf;

    if (r->connection->fd == (njt_socket_t) -1) {
        return NJT_HTTP_LUA_FFI_BAD_CONTEXT;
    }

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);
    if (ctx == NULL) {
        *errmsg = "no ctx found";
        return NJT_ERROR;
    }

    llcf = njt_http_get_module_loc_conf(r, njt_http_lua_module);
    if (llcf->transform_underscores_in_resp_headers
        && memchr(key, '_', key_len) != NULL)
    {
        for (i = 0; i < key_len; i++) {
            c = key[i];
            if (c == '_') {
                c = '-';
            }

            key_buf[i] = c;
        }

    } else {
        key_buf = (u_char *) key;
    }

    switch (key_len) {
    case 14:
        if (r->headers_out.content_length == NULL
            && r->headers_out.content_length_n >= 0
            && njt_strncasecmp(key_buf, (u_char *) "Content-Length", 14) == 0)
        {
            p = njt_palloc(r->pool, NJT_OFF_T_LEN);
            if (p == NULL) {
                *errmsg = "no memory";
                return NJT_ERROR;
            }

            values[0].data = p;
            values[0].len = (int) (njt_snprintf(p, NJT_OFF_T_LEN, "%O",
                                              r->headers_out.content_length_n)
                            - p);
            return 1;
        }

        break;

    case 12:
        if (njt_strncasecmp(key_buf, (u_char *) "Content-Type", 12) == 0
            && r->headers_out.content_type.len)
        {
            values[0].data = r->headers_out.content_type.data;
            values[0].len = r->headers_out.content_type.len;
            return 1;
        }

        break;

    case 13:
        if (njt_strncasecmp(key_buf, (u_char *) "Last-Modified", 13) == 0) {
            last_modified = r->headers_out.last_modified_time;
            if (last_modified >= 0) {
                p = njt_palloc(r->pool,
                               sizeof("Mon, 28 Sep 1970 06:00:00 GMT"));
                if (p == NULL) {
                    *errmsg = "no memory";
                    return NJT_ERROR;
                }

                values[0].data = p;
                values[0].len = njt_http_time(p, last_modified) - p;

                return 1;
            }

            return 0;
        }

        break;

    default:
        break;
    }

    dd("not a built-in output header");

#if 1
    if (r->headers_out.location
        && r->headers_out.location->value.len
        && r->headers_out.location->value.data[0] == '/')
    {
        /* XXX njt_http_core_find_config_phase, for example,
         * may not initialize the "key" and "hash" fields
         * for a nasty optimization purpose, and
         * we have to work-around it here */

        r->headers_out.location->hash = njt_http_lua_location_hash;
        njt_str_set(&r->headers_out.location->key, "Location");
    }
#endif

    found = 0;

    part = &r->headers_out.headers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].hash == 0) {
            continue;
        }

        dd("checking (%d) \"%.*s\"", (int) h[i].key.len, (int) h[i].key.len,
           h[i].key.data);

        if (h[i].key.len == key_len
            && njt_strncasecmp(key_buf, h[i].key.data, key_len) == 0)
        {
            values[found].data = h[i].value.data;
            values[found].len = (int) h[i].value.len;

            if (++found >= max_nvalues) {
                break;
            }
        }
    }

    return found;
}


#if (njet_version >= 1011011)
void
njt_http_lua_njt_raw_header_cleanup(void *data)
{
    njt_http_lua_main_conf_t  *lmcf;

    lmcf = (njt_http_lua_main_conf_t *) data;

    if (lmcf->busy_buf_ptrs) {
        njt_free(lmcf->busy_buf_ptrs);
        lmcf->busy_buf_ptrs = NULL;
    }
}
#endif


#if (NJT_DARWIN)
int
njt_http_lua_ffi_set_resp_header_macos(njt_http_lua_set_resp_header_params_t *p)
{
    return njt_http_lua_ffi_set_resp_header(p->r, (const u_char *) p->key_data,
                                            p->key_len, p->is_nil,
                                            (const u_char *) p->sval,
                                            p->sval_len,
                                            p->mvals, p->mvals_len,
                                            p->override, p->errmsg);
}
#endif


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
