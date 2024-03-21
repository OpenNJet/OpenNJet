/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.yy
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_http_lua_string.h"
#include "njt_http_lua_util.h"
#include "njt_http_lua_args.h"
#include "njt_crc32.h"

#if (NJT_HAVE_SHA1)
#include "njt_sha1.h"
#endif

#include "njt_md5.h"

#if (NJT_OPENSSL)
#include <openssl/evp.h>
#include <openssl/hmac.h>
#endif


static uintptr_t njt_http_lua_njt_escape_sql_str(u_char *dst, u_char *src,
    size_t size);
static int njt_http_lua_njt_quote_sql_str(lua_State *L);
static int njt_http_lua_njt_encode_args(lua_State *L);
static int njt_http_lua_njt_decode_args(lua_State *L);
#if (NJT_OPENSSL)
static int njt_http_lua_njt_hmac_sha1(lua_State *L);
#endif


void
njt_http_lua_inject_string_api(lua_State *L)
{
    lua_pushcfunction(L, njt_http_lua_njt_encode_args);
    lua_setfield(L, -2, "encode_args");

    lua_pushcfunction(L, njt_http_lua_njt_decode_args);
    lua_setfield(L, -2, "decode_args");

    lua_pushcfunction(L, njt_http_lua_njt_quote_sql_str);
    lua_setfield(L, -2, "quote_sql_str");

#if (NJT_OPENSSL)
    lua_pushcfunction(L, njt_http_lua_njt_hmac_sha1);
    lua_setfield(L, -2, "hmac_sha1");
#endif
}


static int
njt_http_lua_njt_quote_sql_str(lua_State *L)
{
    size_t                   len, dlen, escape;
    u_char                  *p;
    u_char                  *src, *dst;

    if (lua_gettop(L) != 1) {
        return luaL_error(L, "expecting one argument");
    }

    src = (u_char *) luaL_checklstring(L, 1, &len);

    if (len == 0) {
        dst = (u_char *) "''";
        dlen = sizeof("''") - 1;
        lua_pushlstring(L, (char *) dst, dlen);
        return 1;
    }

    escape = njt_http_lua_njt_escape_sql_str(NULL, src, len);

    dlen = sizeof("''") - 1 + len + escape;

    p = lua_newuserdata(L, dlen);

    dst = p;

    *p++ = '\'';

    if (escape == 0) {
        p = njt_copy(p, src, len);

    } else {
        p = (u_char *) njt_http_lua_njt_escape_sql_str(p, src, len);
    }

    *p++ = '\'';

    if (p != dst + dlen) {
        return NJT_ERROR;
    }

    lua_pushlstring(L, (char *) dst, p - dst);

    return 1;
}


static uintptr_t
njt_http_lua_njt_escape_sql_str(u_char *dst, u_char *src, size_t size)
{
    njt_uint_t               n;

    if (dst == NULL) {
        /* find the number of chars to be escaped */
        n = 0;
        while (size) {
            /* the highest bit of all the UTF-8 chars
             * is always 1 */
            if ((*src & 0x80) == 0) {
                switch (*src) {
                    case '\0':
                    case '\b':
                    case '\n':
                    case '\r':
                    case '\t':
                    case 26:  /* \Z */
                    case '\\':
                    case '\'':
                    case '"':
                        n++;
                        break;
                    default:
                        break;
                }
            }

            src++;
            size--;
        }

        return (uintptr_t) n;
    }

    while (size) {
        if ((*src & 0x80) == 0) {
            switch (*src) {
                case '\0':
                    *dst++ = '\\';
                    *dst++ = '0';
                    break;

                case '\b':
                    *dst++ = '\\';
                    *dst++ = 'b';
                    break;

                case '\n':
                    *dst++ = '\\';
                    *dst++ = 'n';
                    break;

                case '\r':
                    *dst++ = '\\';
                    *dst++ = 'r';
                    break;

                case '\t':
                    *dst++ = '\\';
                    *dst++ = 't';
                    break;

                case 26:
                    *dst++ = '\\';
                    *dst++ = 'Z';
                    break;

                case '\\':
                    *dst++ = '\\';
                    *dst++ = '\\';
                    break;

                case '\'':
                    *dst++ = '\\';
                    *dst++ = '\'';
                    break;

                case '"':
                    *dst++ = '\\';
                    *dst++ = '"';
                    break;

                default:
                    *dst++ = *src;
                    break;
            }

        } else {
            *dst++ = *src;
        }

        src++;
        size--;
    } /* while (size) */

    return (uintptr_t) dst;
}


static void
njt_http_lua_encode_base64(njt_str_t *dst, njt_str_t *src, int no_padding)
{
    u_char         *d, *s;
    size_t          len;
    static u_char   basis[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    len = src->len;
    s = src->data;
    d = dst->data;

    while (len > 2) {
        *d++ = basis[(s[0] >> 2) & 0x3f];
        *d++ = basis[((s[0] & 3) << 4) | (s[1] >> 4)];
        *d++ = basis[((s[1] & 0x0f) << 2) | (s[2] >> 6)];
        *d++ = basis[s[2] & 0x3f];

        s += 3;
        len -= 3;
    }

    if (len) {
        *d++ = basis[(s[0] >> 2) & 0x3f];

        if (len == 1) {
            *d++ = basis[(s[0] & 3) << 4];
            if (!no_padding) {
                *d++ = '=';
            }

        } else {
            *d++ = basis[((s[0] & 3) << 4) | (s[1] >> 4)];
            *d++ = basis[(s[1] & 0x0f) << 2];
        }

        if (!no_padding) {
            *d++ = '=';
        }
    }

    dst->len = d - dst->data;
}


static int
njt_http_lua_njt_encode_args(lua_State *L)
{
    njt_str_t                    args;

    if (lua_gettop(L) != 1) {
        return luaL_error(L, "expecting 1 argument but seen %d",
                          lua_gettop(L));
    }

    luaL_checktype(L, 1, LUA_TTABLE);
    njt_http_lua_process_args_option(NULL, L, 1, &args);
    lua_pushlstring(L, (char *) args.data, args.len);
    return 1;
}


static int
njt_http_lua_njt_decode_args(lua_State *L)
{
    u_char                      *buf;
    u_char                      *tmp;
    size_t                       len = 0;
    int                          n;
    int                          max;

    n = lua_gettop(L);

    if (n != 1 && n != 2) {
        return luaL_error(L, "expecting 1 or 2 arguments but seen %d", n);
    }

    buf = (u_char *) luaL_checklstring(L, 1, &len);

    if (n == 2) {
        max = luaL_checkint(L, 2);
        lua_pop(L, 1);

    } else {
        max = NJT_HTTP_LUA_MAX_ARGS;
    }

    tmp = lua_newuserdata(L, len);
    njt_memcpy(tmp, buf, len);

    lua_createtable(L, 0, 4);

    return njt_http_lua_parse_args(L, tmp, tmp + len, max);
}


#if (NJT_OPENSSL)
static int
njt_http_lua_njt_hmac_sha1(lua_State *L)
{
    u_char                  *sec, *sts;
    size_t                   lsec, lsts;
    unsigned int             md_len;
    unsigned char            md[EVP_MAX_MD_SIZE];
    const EVP_MD            *evp_md;

    if (lua_gettop(L) != 2) {
        return luaL_error(L, "expecting 2 arguments, but got %d",
                          lua_gettop(L));
    }

    sec = (u_char *) luaL_checklstring(L, 1, &lsec);
    sts = (u_char *) luaL_checklstring(L, 2, &lsts);

    evp_md = EVP_sha1();

    HMAC(evp_md, sec, lsec, sts, lsts, md, &md_len);

    lua_pushlstring(L, (char *) md, md_len);

    return 1;
}
#endif


void
njt_http_lua_ffi_md5_bin(const u_char *src, size_t len, u_char *dst)
{
    njt_md5_t     md5;

    njt_md5_init(&md5);
    njt_md5_update(&md5, src, len);
    njt_md5_final(dst, &md5);
}


void
njt_http_lua_ffi_md5(const u_char *src, size_t len, u_char *dst)
{
    njt_md5_t           md5;
    u_char              md5_buf[MD5_DIGEST_LENGTH];

    njt_md5_init(&md5);
    njt_md5_update(&md5, src, len);
    njt_md5_final(md5_buf, &md5);

    njt_hex_dump(dst, md5_buf, sizeof(md5_buf));
}


int
njt_http_lua_ffi_sha1_bin(const u_char *src, size_t len, u_char *dst)
{
#if (NJT_HAVE_SHA1)
    njt_sha1_t               sha;

    njt_sha1_init(&sha);
    njt_sha1_update(&sha, src, len);
    njt_sha1_final(dst, &sha);

    return 1;
#else
    return 0;
#endif
}


unsigned int
njt_http_lua_ffi_crc32_short(const u_char *src, size_t len)
{
    return njt_crc32_short((u_char *) src, len);
}


unsigned int
njt_http_lua_ffi_crc32_long(const u_char *src, size_t len)
{
    return njt_crc32_long((u_char *) src, len);
}


size_t
njt_http_lua_ffi_encode_base64(const u_char *src, size_t slen, u_char *dst,
    int no_padding)
{
    njt_str_t      in, out;

    in.data = (u_char *) src;
    in.len = slen;

    out.data = dst;

    njt_http_lua_encode_base64(&out, &in, no_padding);

    return out.len;
}


int
njt_http_lua_ffi_decode_base64(const u_char *src, size_t slen, u_char *dst,
    size_t *dlen)
{
    njt_int_t      rc;
    njt_str_t      in, out;

    in.data = (u_char *) src;
    in.len = slen;

    out.data = dst;

    rc = njt_decode_base64(&out, &in);

    *dlen = out.len;

    return rc == NJT_OK;
}


size_t
njt_http_lua_ffi_unescape_uri(const u_char *src, size_t len, u_char *dst)
{
    u_char      *p = dst;

    njt_http_lua_unescape_uri(&p, (u_char **) &src, len,
                              NJT_UNESCAPE_URI_COMPONENT);
    return p - dst;
}


size_t
njt_http_lua_ffi_uri_escaped_length(const u_char *src, size_t len,
    int type)
{
    return len + 2 * njt_http_lua_escape_uri(NULL, (u_char *) src, len, type);
}


void
njt_http_lua_ffi_escape_uri(const u_char *src, size_t len, u_char *dst,
    int type)
{
    njt_http_lua_escape_uri(dst, (u_char *) src, len, type);
}


void
njt_http_lua_ffi_str_replace_char(u_char *buf, size_t len, const u_char find,
    const u_char replace)
{
    while (len) {
        if (*buf == find) {
            *buf = replace;
        }

        buf++;
        len--;
    }
}


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
