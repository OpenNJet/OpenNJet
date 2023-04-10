
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


#define NJT_HTTP_CHARSET_OFF    -2
#define NJT_HTTP_NO_CHARSET     -3
#define NJT_HTTP_CHARSET_VAR    0x10000

/* 1 byte length and up to 3 bytes for the UTF-8 encoding of the UCS-2 */
#define NJT_UTF_LEN             4

#define NJT_HTML_ENTITY_LEN     (sizeof("&#1114111;") - 1)


typedef struct {
    u_char                    **tables;
    njt_str_t                   name;

    unsigned                    length:16;
    unsigned                    utf8:1;
} njt_http_charset_t;


typedef struct {
    njt_int_t                   src;
    njt_int_t                   dst;
} njt_http_charset_recode_t;


typedef struct {
    njt_int_t                   src;
    njt_int_t                   dst;
    u_char                     *src2dst;
    u_char                     *dst2src;
} njt_http_charset_tables_t;


typedef struct {
    njt_array_t                 charsets;       /* njt_http_charset_t */
    njt_array_t                 tables;         /* njt_http_charset_tables_t */
    njt_array_t                 recodes;        /* njt_http_charset_recode_t */
} njt_http_charset_main_conf_t;


typedef struct {
    njt_int_t                   charset;
    njt_int_t                   source_charset;
    njt_flag_t                  override_charset;

    njt_hash_t                  types;
    njt_array_t                *types_keys;
} njt_http_charset_loc_conf_t;


typedef struct {
    u_char                     *table;
    njt_int_t                   charset;
    njt_str_t                   charset_name;

    njt_chain_t                *busy;
    njt_chain_t                *free_bufs;
    njt_chain_t                *free_buffers;

    size_t                      saved_len;
    u_char                      saved[NJT_UTF_LEN];

    unsigned                    length:16;
    unsigned                    from_utf8:1;
    unsigned                    to_utf8:1;
} njt_http_charset_ctx_t;


typedef struct {
    njt_http_charset_tables_t  *table;
    njt_http_charset_t         *charset;
    njt_uint_t                  characters;
} njt_http_charset_conf_ctx_t;


static njt_int_t njt_http_destination_charset(njt_http_request_t *r,
    njt_str_t *name);
static njt_int_t njt_http_main_request_charset(njt_http_request_t *r,
    njt_str_t *name);
static njt_int_t njt_http_source_charset(njt_http_request_t *r,
    njt_str_t *name);
static njt_int_t njt_http_get_charset(njt_http_request_t *r, njt_str_t *name);
static njt_inline void njt_http_set_charset(njt_http_request_t *r,
    njt_str_t *charset);
static njt_int_t njt_http_charset_ctx(njt_http_request_t *r,
    njt_http_charset_t *charsets, njt_int_t charset, njt_int_t source_charset);
static njt_uint_t njt_http_charset_recode(njt_buf_t *b, u_char *table);
static njt_chain_t *njt_http_charset_recode_from_utf8(njt_pool_t *pool,
    njt_buf_t *buf, njt_http_charset_ctx_t *ctx);
static njt_chain_t *njt_http_charset_recode_to_utf8(njt_pool_t *pool,
    njt_buf_t *buf, njt_http_charset_ctx_t *ctx);

static njt_chain_t *njt_http_charset_get_buf(njt_pool_t *pool,
    njt_http_charset_ctx_t *ctx);
static njt_chain_t *njt_http_charset_get_buffer(njt_pool_t *pool,
    njt_http_charset_ctx_t *ctx, size_t size);

static char *njt_http_charset_map_block(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_charset_map(njt_conf_t *cf, njt_command_t *dummy,
    void *conf);

static char *njt_http_set_charset_slot(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static njt_int_t njt_http_add_charset(njt_array_t *charsets, njt_str_t *name);

static void *njt_http_charset_create_main_conf(njt_conf_t *cf);
static void *njt_http_charset_create_loc_conf(njt_conf_t *cf);
static char *njt_http_charset_merge_loc_conf(njt_conf_t *cf,
    void *parent, void *child);
static njt_int_t njt_http_charset_postconfiguration(njt_conf_t *cf);


static njt_str_t  njt_http_charset_default_types[] = {
    njt_string("text/html"),
    njt_string("text/xml"),
    njt_string("text/plain"),
    njt_string("text/vnd.wap.wml"),
    njt_string("application/javascript"),
    njt_string("application/rss+xml"),
    njt_null_string
};


static njt_command_t  njt_http_charset_filter_commands[] = {

    { njt_string("charset"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF
                        |NJT_HTTP_LIF_CONF|NJT_CONF_TAKE1,
      njt_http_set_charset_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_charset_loc_conf_t, charset),
      NULL },

    { njt_string("source_charset"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF
                        |NJT_HTTP_LIF_CONF|NJT_CONF_TAKE1,
      njt_http_set_charset_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_charset_loc_conf_t, source_charset),
      NULL },

    { njt_string("override_charset"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF
                        |NJT_HTTP_LIF_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_charset_loc_conf_t, override_charset),
      NULL },

    { njt_string("charset_types"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_http_types_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_charset_loc_conf_t, types_keys),
      &njt_http_charset_default_types[0] },

    { njt_string("charset_map"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_BLOCK|NJT_CONF_TAKE2,
      njt_http_charset_map_block,
      NJT_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

      njt_null_command
};


static njt_http_module_t  njt_http_charset_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    njt_http_charset_postconfiguration,    /* postconfiguration */

    njt_http_charset_create_main_conf,     /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_charset_create_loc_conf,      /* create location configuration */
    njt_http_charset_merge_loc_conf        /* merge location configuration */
};


njt_module_t  njt_http_charset_filter_module = {
    NJT_MODULE_V1,
    &njt_http_charset_filter_module_ctx,   /* module context */
    njt_http_charset_filter_commands,      /* module directives */
    NJT_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};


static njt_http_output_header_filter_pt  njt_http_next_header_filter;
static njt_http_output_body_filter_pt    njt_http_next_body_filter;


static njt_int_t
njt_http_charset_header_filter(njt_http_request_t *r)
{
    njt_int_t                      charset, source_charset;
    njt_str_t                      dst, src;
    njt_http_charset_t            *charsets;
    njt_http_charset_main_conf_t  *mcf;

    if (r == r->main) {
        charset = njt_http_destination_charset(r, &dst);

    } else {
        charset = njt_http_main_request_charset(r, &dst);
    }

    if (charset == NJT_ERROR) {
        return NJT_ERROR;
    }

    if (charset == NJT_DECLINED) {
        return njt_http_next_header_filter(r);
    }

    /* charset: charset index or NJT_HTTP_NO_CHARSET */

    source_charset = njt_http_source_charset(r, &src);

    if (source_charset == NJT_ERROR) {
        return NJT_ERROR;
    }

    /*
     * source_charset: charset index, NJT_HTTP_NO_CHARSET,
     *                 or NJT_HTTP_CHARSET_OFF
     */

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "charset: \"%V\" > \"%V\"", &src, &dst);

    if (source_charset == NJT_HTTP_CHARSET_OFF) {
        njt_http_set_charset(r, &dst);

        return njt_http_next_header_filter(r);
    }

    if (charset == NJT_HTTP_NO_CHARSET
        || source_charset == NJT_HTTP_NO_CHARSET)
    {
        if (source_charset != charset
            || njt_strncasecmp(dst.data, src.data, dst.len) != 0)
        {
            goto no_charset_map;
        }

        njt_http_set_charset(r, &dst);

        return njt_http_next_header_filter(r);
    }

    if (source_charset == charset) {
        r->headers_out.content_type.len = r->headers_out.content_type_len;

        njt_http_set_charset(r, &dst);

        return njt_http_next_header_filter(r);
    }

    /* source_charset != charset */

    if (r->headers_out.content_encoding
        && r->headers_out.content_encoding->value.len)
    {
        return njt_http_next_header_filter(r);
    }

    mcf = njt_http_get_module_main_conf(r, njt_http_charset_filter_module);
    charsets = mcf->charsets.elts;

    if (charsets[source_charset].tables == NULL
        || charsets[source_charset].tables[charset] == NULL)
    {
        goto no_charset_map;
    }

    r->headers_out.content_type.len = r->headers_out.content_type_len;

    njt_http_set_charset(r, &dst);

    return njt_http_charset_ctx(r, charsets, charset, source_charset);

no_charset_map:

    njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                  "no \"charset_map\" between the charsets \"%V\" and \"%V\"",
                  &src, &dst);

    return njt_http_next_header_filter(r);
}


static njt_int_t
njt_http_destination_charset(njt_http_request_t *r, njt_str_t *name)
{
    njt_int_t                      charset;
    njt_http_charset_t            *charsets;
    njt_http_variable_value_t     *vv;
    njt_http_charset_loc_conf_t   *mlcf;
    njt_http_charset_main_conf_t  *mcf;

    if (r->headers_out.content_type.len == 0) {
        return NJT_DECLINED;
    }

    if (r->headers_out.override_charset
        && r->headers_out.override_charset->len)
    {
        *name = *r->headers_out.override_charset;

        charset = njt_http_get_charset(r, name);

        if (charset != NJT_HTTP_NO_CHARSET) {
            return charset;
        }

        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "unknown charset \"%V\" to override", name);

        return NJT_DECLINED;
    }

    mlcf = njt_http_get_module_loc_conf(r, njt_http_charset_filter_module);
    charset = mlcf->charset;

    if (charset == NJT_HTTP_CHARSET_OFF) {
        return NJT_DECLINED;
    }

    if (r->headers_out.charset.len) {
        if (mlcf->override_charset == 0) {
            return NJT_DECLINED;
        }

    } else {
        if (njt_http_test_content_type(r, &mlcf->types) == NULL) {
            return NJT_DECLINED;
        }
    }

    if (charset < NJT_HTTP_CHARSET_VAR) {
        mcf = njt_http_get_module_main_conf(r, njt_http_charset_filter_module);
        charsets = mcf->charsets.elts;
        *name = charsets[charset].name;
        return charset;
    }

    vv = njt_http_get_indexed_variable(r, charset - NJT_HTTP_CHARSET_VAR);

    if (vv == NULL || vv->not_found) {
        return NJT_ERROR;
    }

    name->len = vv->len;
    name->data = vv->data;

    return njt_http_get_charset(r, name);
}


static njt_int_t
njt_http_main_request_charset(njt_http_request_t *r, njt_str_t *src)
{
    njt_int_t                charset;
    njt_str_t               *main_charset;
    njt_http_charset_ctx_t  *ctx;

    ctx = njt_http_get_module_ctx(r->main, njt_http_charset_filter_module);

    if (ctx) {
        *src = ctx->charset_name;
        return ctx->charset;
    }

    main_charset = &r->main->headers_out.charset;

    if (main_charset->len == 0) {
        return NJT_DECLINED;
    }

    ctx = njt_pcalloc(r->pool, sizeof(njt_http_charset_ctx_t));
    if (ctx == NULL) {
        return NJT_ERROR;
    }

    njt_http_set_ctx(r->main, ctx, njt_http_charset_filter_module);

    charset = njt_http_get_charset(r, main_charset);

    ctx->charset = charset;
    ctx->charset_name = *main_charset;
    *src = *main_charset;

    return charset;
}


static njt_int_t
njt_http_source_charset(njt_http_request_t *r, njt_str_t *name)
{
    njt_int_t                      charset;
    njt_http_charset_t            *charsets;
    njt_http_variable_value_t     *vv;
    njt_http_charset_loc_conf_t   *lcf;
    njt_http_charset_main_conf_t  *mcf;

    if (r->headers_out.charset.len) {
        *name = r->headers_out.charset;
        return njt_http_get_charset(r, name);
    }

    lcf = njt_http_get_module_loc_conf(r, njt_http_charset_filter_module);

    charset = lcf->source_charset;

    if (charset == NJT_HTTP_CHARSET_OFF) {
        name->len = 0;
        return charset;
    }

    if (charset < NJT_HTTP_CHARSET_VAR) {
        mcf = njt_http_get_module_main_conf(r, njt_http_charset_filter_module);
        charsets = mcf->charsets.elts;
        *name = charsets[charset].name;
        return charset;
    }

    vv = njt_http_get_indexed_variable(r, charset - NJT_HTTP_CHARSET_VAR);

    if (vv == NULL || vv->not_found) {
        return NJT_ERROR;
    }

    name->len = vv->len;
    name->data = vv->data;

    return njt_http_get_charset(r, name);
}


static njt_int_t
njt_http_get_charset(njt_http_request_t *r, njt_str_t *name)
{
    njt_uint_t                     i, n;
    njt_http_charset_t            *charset;
    njt_http_charset_main_conf_t  *mcf;

    mcf = njt_http_get_module_main_conf(r, njt_http_charset_filter_module);

    charset = mcf->charsets.elts;
    n = mcf->charsets.nelts;

    for (i = 0; i < n; i++) {
        if (charset[i].name.len != name->len) {
            continue;
        }

        if (njt_strncasecmp(charset[i].name.data, name->data, name->len) == 0) {
            return i;
        }
    }

    return NJT_HTTP_NO_CHARSET;
}


static njt_inline void
njt_http_set_charset(njt_http_request_t *r, njt_str_t *charset)
{
    if (r != r->main) {
        return;
    }

    if (r->headers_out.status == NJT_HTTP_MOVED_PERMANENTLY
        || r->headers_out.status == NJT_HTTP_MOVED_TEMPORARILY)
    {
        /*
         * do not set charset for the redirect because NN 4.x
         * use this charset instead of the next page charset
         */

        r->headers_out.charset.len = 0;
        return;
    }

    r->headers_out.charset = *charset;
}


static njt_int_t
njt_http_charset_ctx(njt_http_request_t *r, njt_http_charset_t *charsets,
    njt_int_t charset, njt_int_t source_charset)
{
    njt_http_charset_ctx_t  *ctx;

    ctx = njt_pcalloc(r->pool, sizeof(njt_http_charset_ctx_t));
    if (ctx == NULL) {
        return NJT_ERROR;
    }

    njt_http_set_ctx(r, ctx, njt_http_charset_filter_module);

    ctx->table = charsets[source_charset].tables[charset];
    ctx->charset = charset;
    ctx->charset_name = charsets[charset].name;
    ctx->length = charsets[charset].length;
    ctx->from_utf8 = charsets[source_charset].utf8;
    ctx->to_utf8 = charsets[charset].utf8;

    r->filter_need_in_memory = 1;

    if ((ctx->to_utf8 || ctx->from_utf8) && r == r->main) {
        njt_http_clear_content_length(r);

    } else {
        r->filter_need_temporary = 1;
    }

    return njt_http_next_header_filter(r);
}


static njt_int_t
njt_http_charset_body_filter(njt_http_request_t *r, njt_chain_t *in)
{
    njt_int_t                rc;
    njt_buf_t               *b;
    njt_chain_t             *cl, *out, **ll;
    njt_http_charset_ctx_t  *ctx;

    ctx = njt_http_get_module_ctx(r, njt_http_charset_filter_module);

    if (ctx == NULL || ctx->table == NULL) {
        return njt_http_next_body_filter(r, in);
    }

    if ((ctx->to_utf8 || ctx->from_utf8) || ctx->busy) {

        out = NULL;
        ll = &out;

        for (cl = in; cl; cl = cl->next) {
            b = cl->buf;

            if (njt_buf_size(b) == 0) {

                *ll = njt_alloc_chain_link(r->pool);
                if (*ll == NULL) {
                    return NJT_ERROR;
                }

                (*ll)->buf = b;
                (*ll)->next = NULL;

                ll = &(*ll)->next;

                continue;
            }

            if (ctx->to_utf8) {
                *ll = njt_http_charset_recode_to_utf8(r->pool, b, ctx);

            } else {
                *ll = njt_http_charset_recode_from_utf8(r->pool, b, ctx);
            }

            if (*ll == NULL) {
                return NJT_ERROR;
            }

            while (*ll) {
                ll = &(*ll)->next;
            }
        }

        rc = njt_http_next_body_filter(r, out);

        if (out) {
            if (ctx->busy == NULL) {
                ctx->busy = out;

            } else {
                for (cl = ctx->busy; cl->next; cl = cl->next) { /* void */ }
                cl->next = out;
            }
        }

        while (ctx->busy) {

            cl = ctx->busy;
            b = cl->buf;

            if (njt_buf_size(b) != 0) {
                break;
            }

            ctx->busy = cl->next;

            if (b->tag != (njt_buf_tag_t) &njt_http_charset_filter_module) {
                continue;
            }

            if (b->shadow) {
                b->shadow->pos = b->shadow->last;
            }

            if (b->pos) {
                cl->next = ctx->free_buffers;
                ctx->free_buffers = cl;
                continue;
            }

            cl->next = ctx->free_bufs;
            ctx->free_bufs = cl;
        }

        return rc;
    }

    for (cl = in; cl; cl = cl->next) {
        (void) njt_http_charset_recode(cl->buf, ctx->table);
    }

    return njt_http_next_body_filter(r, in);
}


static njt_uint_t
njt_http_charset_recode(njt_buf_t *b, u_char *table)
{
    u_char  *p, *last;

    last = b->last;

    for (p = b->pos; p < last; p++) {

        if (*p != table[*p]) {
            goto recode;
        }
    }

    return 0;

recode:

    do {
        if (*p != table[*p]) {
            *p = table[*p];
        }

        p++;

    } while (p < last);

    b->in_file = 0;

    return 1;
}


static njt_chain_t *
njt_http_charset_recode_from_utf8(njt_pool_t *pool, njt_buf_t *buf,
    njt_http_charset_ctx_t *ctx)
{
    size_t        len, size;
    u_char        c, *p, *src, *dst, *saved, **table;
    uint32_t      n;
    njt_buf_t    *b;
    njt_uint_t    i;
    njt_chain_t  *out, *cl, **ll;

    src = buf->pos;

    if (ctx->saved_len == 0) {

        for ( /* void */ ; src < buf->last; src++) {

            if (*src < 0x80) {
                continue;
            }

            len = src - buf->pos;

            if (len > 512) {
                out = njt_http_charset_get_buf(pool, ctx);
                if (out == NULL) {
                    return NULL;
                }

                b = out->buf;

                b->temporary = buf->temporary;
                b->memory = buf->memory;
                b->mmap = buf->mmap;
                b->flush = buf->flush;

                b->pos = buf->pos;
                b->last = src;

                out->buf = b;
                out->next = NULL;

                size = buf->last - src;

                saved = src;
                n = njt_utf8_decode(&saved, size);

                if (n == 0xfffffffe) {
                    /* incomplete UTF-8 symbol */

                    njt_memcpy(ctx->saved, src, size);
                    ctx->saved_len = size;

                    b->shadow = buf;

                    return out;
                }

            } else {
                out = NULL;
                size = len + buf->last - src;
                src = buf->pos;
            }

            if (size < NJT_HTML_ENTITY_LEN) {
                size += NJT_HTML_ENTITY_LEN;
            }

            cl = njt_http_charset_get_buffer(pool, ctx, size);
            if (cl == NULL) {
                return NULL;
            }

            if (out) {
                out->next = cl;

            } else {
                out = cl;
            }

            b = cl->buf;
            dst = b->pos;

            goto recode;
        }

        out = njt_alloc_chain_link(pool);
        if (out == NULL) {
            return NULL;
        }

        out->buf = buf;
        out->next = NULL;

        return out;
    }

    /* process incomplete UTF sequence from previous buffer */

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, pool->log, 0,
                   "http charset utf saved: %z", ctx->saved_len);

    p = src;

    for (i = ctx->saved_len; i < NJT_UTF_LEN; i++) {
        ctx->saved[i] = *p++;

        if (p == buf->last) {
            break;
        }
    }

    saved = ctx->saved;
    n = njt_utf8_decode(&saved, i);

    c = '\0';

    if (n < 0x10000) {
        table = (u_char **) ctx->table;
        p = table[n >> 8];

        if (p) {
            c = p[n & 0xff];
        }

    } else if (n == 0xfffffffe) {

        /* incomplete UTF-8 symbol */

        if (i < NJT_UTF_LEN) {
            out = njt_http_charset_get_buf(pool, ctx);
            if (out == NULL) {
                return NULL;
            }

            b = out->buf;

            b->pos = buf->pos;
            b->last = buf->last;
            b->sync = 1;
            b->shadow = buf;

            njt_memcpy(&ctx->saved[ctx->saved_len], src, i);
            ctx->saved_len += i;

            return out;
        }
    }

    size = buf->last - buf->pos;

    if (size < NJT_HTML_ENTITY_LEN) {
        size += NJT_HTML_ENTITY_LEN;
    }

    cl = njt_http_charset_get_buffer(pool, ctx, size);
    if (cl == NULL) {
        return NULL;
    }

    out = cl;

    b = cl->buf;
    dst = b->pos;

    if (c) {
        *dst++ = c;

    } else if (n == 0xfffffffe) {
        *dst++ = '?';

        njt_log_debug0(NJT_LOG_DEBUG_HTTP, pool->log, 0,
                       "http charset invalid utf 0");

        saved = &ctx->saved[NJT_UTF_LEN];

    } else if (n > 0x10ffff) {
        *dst++ = '?';

        njt_log_debug0(NJT_LOG_DEBUG_HTTP, pool->log, 0,
                       "http charset invalid utf 1");

    } else {
        dst = njt_sprintf(dst, "&#%uD;", n);
    }

    src += (saved - ctx->saved) - ctx->saved_len;
    ctx->saved_len = 0;

recode:

    ll = &cl->next;

    table = (u_char **) ctx->table;

    while (src < buf->last) {

        if ((size_t) (b->end - dst) < NJT_HTML_ENTITY_LEN) {
            b->last = dst;

            size = buf->last - src + NJT_HTML_ENTITY_LEN;

            cl = njt_http_charset_get_buffer(pool, ctx, size);
            if (cl == NULL) {
                return NULL;
            }

            *ll = cl;
            ll = &cl->next;

            b = cl->buf;
            dst = b->pos;
        }

        if (*src < 0x80) {
            *dst++ = *src++;
            continue;
        }

        len = buf->last - src;

        n = njt_utf8_decode(&src, len);

        if (n < 0x10000) {

            p = table[n >> 8];

            if (p) {
                c = p[n & 0xff];

                if (c) {
                    *dst++ = c;
                    continue;
                }
            }

            dst = njt_sprintf(dst, "&#%uD;", n);

            continue;
        }

        if (n == 0xfffffffe) {
            /* incomplete UTF-8 symbol */

            njt_memcpy(ctx->saved, src, len);
            ctx->saved_len = len;

            if (b->pos == dst) {
                b->sync = 1;
                b->temporary = 0;
            }

            break;
        }

        if (n > 0x10ffff) {
            *dst++ = '?';

            njt_log_debug0(NJT_LOG_DEBUG_HTTP, pool->log, 0,
                           "http charset invalid utf 2");

            continue;
        }

        /* n > 0xffff */

        dst = njt_sprintf(dst, "&#%uD;", n);
    }

    b->last = dst;

    b->last_buf = buf->last_buf;
    b->last_in_chain = buf->last_in_chain;
    b->flush = buf->flush;

    b->shadow = buf;

    return out;
}


static njt_chain_t *
njt_http_charset_recode_to_utf8(njt_pool_t *pool, njt_buf_t *buf,
    njt_http_charset_ctx_t *ctx)
{
    size_t        len, size;
    u_char       *p, *src, *dst, *table;
    njt_buf_t    *b;
    njt_chain_t  *out, *cl, **ll;

    table = ctx->table;

    for (src = buf->pos; src < buf->last; src++) {
        if (table[*src * NJT_UTF_LEN] == '\1') {
            continue;
        }

        goto recode;
    }

    out = njt_alloc_chain_link(pool);
    if (out == NULL) {
        return NULL;
    }

    out->buf = buf;
    out->next = NULL;

    return out;

recode:

    /*
     * we assume that there are about half of characters to be recoded,
     * so we preallocate "size / 2 + size / 2 * ctx->length"
     */

    len = src - buf->pos;

    if (len > 512) {
        out = njt_http_charset_get_buf(pool, ctx);
        if (out == NULL) {
            return NULL;
        }

        b = out->buf;

        b->temporary = buf->temporary;
        b->memory = buf->memory;
        b->mmap = buf->mmap;
        b->flush = buf->flush;

        b->pos = buf->pos;
        b->last = src;

        out->buf = b;
        out->next = NULL;

        size = buf->last - src;
        size = size / 2 + size / 2 * ctx->length;

    } else {
        out = NULL;

        size = buf->last - src;
        size = len + size / 2 + size / 2 * ctx->length;

        src = buf->pos;
    }

    cl = njt_http_charset_get_buffer(pool, ctx, size);
    if (cl == NULL) {
        return NULL;
    }

    if (out) {
        out->next = cl;

    } else {
        out = cl;
    }

    ll = &cl->next;

    b = cl->buf;
    dst = b->pos;

    while (src < buf->last) {

        p = &table[*src++ * NJT_UTF_LEN];
        len = *p++;

        if ((size_t) (b->end - dst) < len) {
            b->last = dst;

            size = buf->last - src;
            size = len + size / 2 + size / 2 * ctx->length;

            cl = njt_http_charset_get_buffer(pool, ctx, size);
            if (cl == NULL) {
                return NULL;
            }

            *ll = cl;
            ll = &cl->next;

            b = cl->buf;
            dst = b->pos;
        }

        while (len) {
            *dst++ = *p++;
            len--;
        }
    }

    b->last = dst;

    b->last_buf = buf->last_buf;
    b->last_in_chain = buf->last_in_chain;
    b->flush = buf->flush;

    b->shadow = buf;

    return out;
}


static njt_chain_t *
njt_http_charset_get_buf(njt_pool_t *pool, njt_http_charset_ctx_t *ctx)
{
    njt_chain_t  *cl;

    cl = ctx->free_bufs;

    if (cl) {
        ctx->free_bufs = cl->next;

        cl->buf->shadow = NULL;
        cl->next = NULL;

        return cl;
    }

    cl = njt_alloc_chain_link(pool);
    if (cl == NULL) {
        return NULL;
    }

    cl->buf = njt_calloc_buf(pool);
    if (cl->buf == NULL) {
        return NULL;
    }

    cl->next = NULL;

    cl->buf->tag = (njt_buf_tag_t) &njt_http_charset_filter_module;

    return cl;
}


static njt_chain_t *
njt_http_charset_get_buffer(njt_pool_t *pool, njt_http_charset_ctx_t *ctx,
    size_t size)
{
    njt_buf_t    *b;
    njt_chain_t  *cl, **ll;

    for (ll = &ctx->free_buffers, cl = ctx->free_buffers;
         cl;
         ll = &cl->next, cl = cl->next)
    {
        b = cl->buf;

        if ((size_t) (b->end - b->start) >= size) {
            *ll = cl->next;
            cl->next = NULL;

            b->pos = b->start;
            b->temporary = 1;
            b->shadow = NULL;

            return cl;
        }
    }

    cl = njt_alloc_chain_link(pool);
    if (cl == NULL) {
        return NULL;
    }

    cl->buf = njt_create_temp_buf(pool, size);
    if (cl->buf == NULL) {
        return NULL;
    }

    cl->next = NULL;

    cl->buf->temporary = 1;
    cl->buf->tag = (njt_buf_tag_t) &njt_http_charset_filter_module;

    return cl;
}


static char *
njt_http_charset_map_block(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_charset_main_conf_t  *mcf = conf;

    char                         *rv;
    u_char                       *p, *dst2src, **pp;
    njt_int_t                     src, dst;
    njt_uint_t                    i, n;
    njt_str_t                    *value;
    njt_conf_t                    pvcf;
    njt_http_charset_t           *charset;
    njt_http_charset_tables_t    *table;
    njt_http_charset_conf_ctx_t   ctx;

    value = cf->args->elts;

    src = njt_http_add_charset(&mcf->charsets, &value[1]);
    if (src == NJT_ERROR) {
        return NJT_CONF_ERROR;
    }

    dst = njt_http_add_charset(&mcf->charsets, &value[2]);
    if (dst == NJT_ERROR) {
        return NJT_CONF_ERROR;
    }

    if (src == dst) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "\"charset_map\" between the same charsets "
                           "\"%V\" and \"%V\"", &value[1], &value[2]);
        return NJT_CONF_ERROR;
    }

    table = mcf->tables.elts;
    for (i = 0; i < mcf->tables.nelts; i++) {
        if ((src == table->src && dst == table->dst)
             || (src == table->dst && dst == table->src))
        {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "duplicate \"charset_map\" between "
                               "\"%V\" and \"%V\"", &value[1], &value[2]);
            return NJT_CONF_ERROR;
        }
    }

    table = njt_array_push(&mcf->tables);
    if (table == NULL) {
        return NJT_CONF_ERROR;
    }

    table->src = src;
    table->dst = dst;

    if (njt_strcasecmp(value[2].data, (u_char *) "utf-8") == 0) {
        table->src2dst = njt_pcalloc(cf->pool, 256 * NJT_UTF_LEN);
        if (table->src2dst == NULL) {
            return NJT_CONF_ERROR;
        }

        table->dst2src = njt_pcalloc(cf->pool, 256 * sizeof(void *));
        if (table->dst2src == NULL) {
            return NJT_CONF_ERROR;
        }

        dst2src = njt_pcalloc(cf->pool, 256);
        if (dst2src == NULL) {
            return NJT_CONF_ERROR;
        }

        pp = (u_char **) &table->dst2src[0];
        pp[0] = dst2src;

        for (i = 0; i < 128; i++) {
            p = &table->src2dst[i * NJT_UTF_LEN];
            p[0] = '\1';
            p[1] = (u_char) i;
            dst2src[i] = (u_char) i;
        }

        for (/* void */; i < 256; i++) {
            p = &table->src2dst[i * NJT_UTF_LEN];
            p[0] = '\1';
            p[1] = '?';
        }

    } else {
        table->src2dst = njt_palloc(cf->pool, 256);
        if (table->src2dst == NULL) {
            return NJT_CONF_ERROR;
        }

        table->dst2src = njt_palloc(cf->pool, 256);
        if (table->dst2src == NULL) {
            return NJT_CONF_ERROR;
        }

        for (i = 0; i < 128; i++) {
            table->src2dst[i] = (u_char) i;
            table->dst2src[i] = (u_char) i;
        }

        for (/* void */; i < 256; i++) {
            table->src2dst[i] = '?';
            table->dst2src[i] = '?';
        }
    }

    charset = mcf->charsets.elts;

    ctx.table = table;
    ctx.charset = &charset[dst];
    ctx.characters = 0;

    pvcf = *cf;
    cf->ctx = &ctx;
    cf->handler = njt_http_charset_map;
    cf->handler_conf = conf;

    rv = njt_conf_parse(cf, NULL);

    *cf = pvcf;

    if (ctx.characters) {
        n = ctx.charset->length;
        ctx.charset->length /= ctx.characters;

        if (((n * 10) / ctx.characters) % 10 > 4) {
            ctx.charset->length++;
        }
    }

    return rv;
}


static char *
njt_http_charset_map(njt_conf_t *cf, njt_command_t *dummy, void *conf)
{
    u_char                       *p, *dst2src, **pp;
    uint32_t                      n;
    njt_int_t                     src, dst;
    njt_str_t                    *value;
    njt_uint_t                    i;
    njt_http_charset_tables_t    *table;
    njt_http_charset_conf_ctx_t  *ctx;

    if (cf->args->nelts != 2) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "invalid parameters number");
        return NJT_CONF_ERROR;
    }

    value = cf->args->elts;

    src = njt_hextoi(value[0].data, value[0].len);
    if (src == NJT_ERROR || src > 255) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid value \"%V\"", &value[0]);
        return NJT_CONF_ERROR;
    }

    ctx = cf->ctx;
    table = ctx->table;

    if (ctx->charset->utf8) {
        p = &table->src2dst[src * NJT_UTF_LEN];

        *p++ = (u_char) (value[1].len / 2);

        for (i = 0; i < value[1].len; i += 2) {
            dst = njt_hextoi(&value[1].data[i], 2);
            if (dst == NJT_ERROR || dst > 255) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid value \"%V\"", &value[1]);
                return NJT_CONF_ERROR;
            }

            *p++ = (u_char) dst;
        }

        i /= 2;

        ctx->charset->length += i;
        ctx->characters++;

        p = &table->src2dst[src * NJT_UTF_LEN] + 1;

        n = njt_utf8_decode(&p, i);

        if (n > 0xffff) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid value \"%V\"", &value[1]);
            return NJT_CONF_ERROR;
        }

        pp = (u_char **) &table->dst2src[0];

        dst2src = pp[n >> 8];

        if (dst2src == NULL) {
            dst2src = njt_pcalloc(cf->pool, 256);
            if (dst2src == NULL) {
                return NJT_CONF_ERROR;
            }

            pp[n >> 8] = dst2src;
        }

        dst2src[n & 0xff] = (u_char) src;

    } else {
        dst = njt_hextoi(value[1].data, value[1].len);
        if (dst == NJT_ERROR || dst > 255) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid value \"%V\"", &value[1]);
            return NJT_CONF_ERROR;
        }

        table->src2dst[src] = (u_char) dst;
        table->dst2src[dst] = (u_char) src;
    }

    return NJT_CONF_OK;
}


static char *
njt_http_set_charset_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char  *p = conf;

    njt_int_t                     *cp;
    njt_str_t                     *value, var;
    njt_http_charset_main_conf_t  *mcf;

    cp = (njt_int_t *) (p + cmd->offset);

    if (*cp != NJT_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cmd->offset == offsetof(njt_http_charset_loc_conf_t, charset)
        && njt_strcmp(value[1].data, "off") == 0)
    {
        *cp = NJT_HTTP_CHARSET_OFF;
        return NJT_CONF_OK;
    }


    if (value[1].data[0] == '$') {
        var.len = value[1].len - 1;
        var.data = value[1].data + 1;

        *cp = njt_http_get_variable_index(cf, &var);

        if (*cp == NJT_ERROR) {
            return NJT_CONF_ERROR;
        }

        *cp += NJT_HTTP_CHARSET_VAR;

        return NJT_CONF_OK;
    }

    mcf = njt_http_conf_get_module_main_conf(cf,
                                             njt_http_charset_filter_module);

    *cp = njt_http_add_charset(&mcf->charsets, &value[1]);
    if (*cp == NJT_ERROR) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


static njt_int_t
njt_http_add_charset(njt_array_t *charsets, njt_str_t *name)
{
    njt_uint_t           i;
    njt_http_charset_t  *c;

    c = charsets->elts;
    for (i = 0; i < charsets->nelts; i++) {
        if (name->len != c[i].name.len) {
            continue;
        }

        if (njt_strcasecmp(name->data, c[i].name.data) == 0) {
            break;
        }
    }

    if (i < charsets->nelts) {
        return i;
    }

    c = njt_array_push(charsets);
    if (c == NULL) {
        return NJT_ERROR;
    }

    c->tables = NULL;
    c->name = *name;
    c->length = 0;

    if (njt_strcasecmp(name->data, (u_char *) "utf-8") == 0) {
        c->utf8 = 1;

    } else {
        c->utf8 = 0;
    }

    return i;
}


static void *
njt_http_charset_create_main_conf(njt_conf_t *cf)
{
    njt_http_charset_main_conf_t  *mcf;

    mcf = njt_pcalloc(cf->pool, sizeof(njt_http_charset_main_conf_t));
    if (mcf == NULL) {
        return NULL;
    }

    if (njt_array_init(&mcf->charsets, cf->pool, 2, sizeof(njt_http_charset_t))
        != NJT_OK)
    {
        return NULL;
    }

    if (njt_array_init(&mcf->tables, cf->pool, 1,
                       sizeof(njt_http_charset_tables_t))
        != NJT_OK)
    {
        return NULL;
    }

    if (njt_array_init(&mcf->recodes, cf->pool, 2,
                       sizeof(njt_http_charset_recode_t))
        != NJT_OK)
    {
        return NULL;
    }

    return mcf;
}


static void *
njt_http_charset_create_loc_conf(njt_conf_t *cf)
{
    njt_http_charset_loc_conf_t  *lcf;

    lcf = njt_pcalloc(cf->pool, sizeof(njt_http_charset_loc_conf_t));
    if (lcf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     lcf->types = { NULL };
     *     lcf->types_keys = NULL;
     */

    lcf->charset = NJT_CONF_UNSET;
    lcf->source_charset = NJT_CONF_UNSET;
    lcf->override_charset = NJT_CONF_UNSET;

    return lcf;
}


static char *
njt_http_charset_merge_loc_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_charset_loc_conf_t *prev = parent;
    njt_http_charset_loc_conf_t *conf = child;

    njt_uint_t                     i;
    njt_http_charset_recode_t     *recode;
    njt_http_charset_main_conf_t  *mcf;

    if (njt_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             njt_http_charset_default_types)
        != NJT_OK)
    {
        return NJT_CONF_ERROR;
    }

    njt_conf_merge_value(conf->override_charset, prev->override_charset, 0);
    njt_conf_merge_value(conf->charset, prev->charset, NJT_HTTP_CHARSET_OFF);
    njt_conf_merge_value(conf->source_charset, prev->source_charset,
                         NJT_HTTP_CHARSET_OFF);

    if (conf->charset == NJT_HTTP_CHARSET_OFF
        || conf->source_charset == NJT_HTTP_CHARSET_OFF
        || conf->charset == conf->source_charset)
    {
        return NJT_CONF_OK;
    }

    if (conf->source_charset >= NJT_HTTP_CHARSET_VAR
        || conf->charset >= NJT_HTTP_CHARSET_VAR)
    {
        return NJT_CONF_OK;
    }

    mcf = njt_http_conf_get_module_main_conf(cf,
                                             njt_http_charset_filter_module);
    recode = mcf->recodes.elts;
    for (i = 0; i < mcf->recodes.nelts; i++) {
        if (conf->source_charset == recode[i].src
            && conf->charset == recode[i].dst)
        {
            return NJT_CONF_OK;
        }
    }

    recode = njt_array_push(&mcf->recodes);
    if (recode == NULL) {
        return NJT_CONF_ERROR;
    }

    recode->src = conf->source_charset;
    recode->dst = conf->charset;

    return NJT_CONF_OK;
}


static njt_int_t
njt_http_charset_postconfiguration(njt_conf_t *cf)
{
    u_char                       **src, **dst;
    njt_int_t                      c;
    njt_uint_t                     i, t;
    njt_http_charset_t            *charset;
    njt_http_charset_recode_t     *recode;
    njt_http_charset_tables_t     *tables;
    njt_http_charset_main_conf_t  *mcf;

    mcf = njt_http_conf_get_module_main_conf(cf,
                                             njt_http_charset_filter_module);

    recode = mcf->recodes.elts;
    tables = mcf->tables.elts;
    charset = mcf->charsets.elts;

    for (i = 0; i < mcf->recodes.nelts; i++) {

        c = recode[i].src;

        for (t = 0; t < mcf->tables.nelts; t++) {

            if (c == tables[t].src && recode[i].dst == tables[t].dst) {
                goto next;
            }

            if (c == tables[t].dst && recode[i].dst == tables[t].src) {
                goto next;
            }
        }

        njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                   "no \"charset_map\" between the charsets \"%V\" and \"%V\"",
                   &charset[c].name, &charset[recode[i].dst].name);
        return NJT_ERROR;

    next:
        continue;
    }


    for (t = 0; t < mcf->tables.nelts; t++) {

        src = charset[tables[t].src].tables;

        if (src == NULL) {
            src = njt_pcalloc(cf->pool, sizeof(u_char *) * mcf->charsets.nelts);
            if (src == NULL) {
                return NJT_ERROR;
            }

            charset[tables[t].src].tables = src;
        }

        dst = charset[tables[t].dst].tables;

        if (dst == NULL) {
            dst = njt_pcalloc(cf->pool, sizeof(u_char *) * mcf->charsets.nelts);
            if (dst == NULL) {
                return NJT_ERROR;
            }

            charset[tables[t].dst].tables = dst;
        }

        src[tables[t].dst] = tables[t].src2dst;
        dst[tables[t].src] = tables[t].dst2src;
    }

    njt_http_next_header_filter = njt_http_top_header_filter;
    njt_http_top_header_filter = njt_http_charset_header_filter;

    njt_http_next_body_filter = njt_http_top_body_filter;
    njt_http_top_body_filter = njt_http_charset_body_filter;

    return NJT_OK;
}
