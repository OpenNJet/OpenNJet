
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


typedef struct {
    njt_http_upstream_conf_t   upstream;
    njt_int_t                  index;
    njt_uint_t                 gzip_flag;
} njt_http_memcached_loc_conf_t;


typedef struct {
    size_t                     rest;
    njt_http_request_t        *request;
    njt_str_t                  key;
} njt_http_memcached_ctx_t;


static njt_int_t njt_http_memcached_create_request(njt_http_request_t *r);
static njt_int_t njt_http_memcached_reinit_request(njt_http_request_t *r);
static njt_int_t njt_http_memcached_process_header(njt_http_request_t *r);
static njt_int_t njt_http_memcached_filter_init(void *data);
static njt_int_t njt_http_memcached_filter(void *data, ssize_t bytes);
static void njt_http_memcached_abort_request(njt_http_request_t *r);
static void njt_http_memcached_finalize_request(njt_http_request_t *r,
    njt_int_t rc);

static void *njt_http_memcached_create_loc_conf(njt_conf_t *cf);
static char *njt_http_memcached_merge_loc_conf(njt_conf_t *cf,
    void *parent, void *child);

static char *njt_http_memcached_pass(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);


static njt_conf_bitmask_t  njt_http_memcached_next_upstream_masks[] = {
    { njt_string("error"), NJT_HTTP_UPSTREAM_FT_ERROR },
    { njt_string("timeout"), NJT_HTTP_UPSTREAM_FT_TIMEOUT },
    { njt_string("invalid_response"), NJT_HTTP_UPSTREAM_FT_INVALID_HEADER },
    { njt_string("not_found"), NJT_HTTP_UPSTREAM_FT_HTTP_404 },
    { njt_string("off"), NJT_HTTP_UPSTREAM_FT_OFF },
    { njt_null_string, 0 }
};


static njt_command_t  njt_http_memcached_commands[] = {

    { njt_string("memcached_pass"),
      NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE1,
      njt_http_memcached_pass,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("memcached_bind"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE12,
      njt_http_upstream_bind_set_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_memcached_loc_conf_t, upstream.local),
      NULL },

    { njt_string("memcached_socket_keepalive"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_memcached_loc_conf_t, upstream.socket_keepalive),
      NULL },

    { njt_string("memcached_connect_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_memcached_loc_conf_t, upstream.connect_timeout),
      NULL },

    { njt_string("memcached_send_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_memcached_loc_conf_t, upstream.send_timeout),
      NULL },

    { njt_string("memcached_buffer_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_memcached_loc_conf_t, upstream.buffer_size),
      NULL },

    { njt_string("memcached_read_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_memcached_loc_conf_t, upstream.read_timeout),
      NULL },

    { njt_string("memcached_next_upstream"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_conf_set_bitmask_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_memcached_loc_conf_t, upstream.next_upstream),
      &njt_http_memcached_next_upstream_masks },

    { njt_string("memcached_next_upstream_tries"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_memcached_loc_conf_t, upstream.next_upstream_tries),
      NULL },

    { njt_string("memcached_next_upstream_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_memcached_loc_conf_t, upstream.next_upstream_timeout),
      NULL },

    { njt_string("memcached_gzip_flag"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_memcached_loc_conf_t, gzip_flag),
      NULL },

      njt_null_command
};


static njt_http_module_t  njt_http_memcached_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_memcached_create_loc_conf,    /* create location configuration */
    njt_http_memcached_merge_loc_conf      /* merge location configuration */
};


njt_module_t  njt_http_memcached_module = {
    NJT_MODULE_V1,
    &njt_http_memcached_module_ctx,        /* module context */
    njt_http_memcached_commands,           /* module directives */
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


static njt_str_t  njt_http_memcached_key = njt_string("memcached_key");


#define NJT_HTTP_MEMCACHED_END   (sizeof(njt_http_memcached_end) - 1)
static u_char  njt_http_memcached_end[] = CRLF "END" CRLF;


static njt_int_t
njt_http_memcached_handler(njt_http_request_t *r)
{
    njt_int_t                       rc;
    njt_http_upstream_t            *u;
    njt_http_memcached_ctx_t       *ctx;
    njt_http_memcached_loc_conf_t  *mlcf;

    if (!(r->method & (NJT_HTTP_GET|NJT_HTTP_HEAD))) {
        return NJT_HTTP_NOT_ALLOWED;
    }

    rc = njt_http_discard_request_body(r);

    if (rc != NJT_OK) {
        return rc;
    }

    if (njt_http_set_content_type(r) != NJT_OK) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (njt_http_upstream_create(r) != NJT_OK) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    u = r->upstream;

    njt_str_set(&u->schema, "memcached://");
    u->output.tag = (njt_buf_tag_t) &njt_http_memcached_module;

    mlcf = njt_http_get_module_loc_conf(r, njt_http_memcached_module);

    u->conf = &mlcf->upstream;

    u->create_request = njt_http_memcached_create_request;
    u->reinit_request = njt_http_memcached_reinit_request;
    u->process_header = njt_http_memcached_process_header;
    u->abort_request = njt_http_memcached_abort_request;
    u->finalize_request = njt_http_memcached_finalize_request;

    ctx = njt_palloc(r->pool, sizeof(njt_http_memcached_ctx_t));
    if (ctx == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->request = r;

    njt_http_set_ctx(r, ctx, njt_http_memcached_module);

    u->input_filter_init = njt_http_memcached_filter_init;
    u->input_filter = njt_http_memcached_filter;
    u->input_filter_ctx = ctx;

    r->main->count++;

    njt_http_upstream_init(r);

    return NJT_DONE;
}


static njt_int_t
njt_http_memcached_create_request(njt_http_request_t *r)
{
    size_t                          len;
    uintptr_t                       escape;
    njt_buf_t                      *b;
    njt_chain_t                    *cl;
    njt_http_memcached_ctx_t       *ctx;
    njt_http_variable_value_t      *vv;
    njt_http_memcached_loc_conf_t  *mlcf;

    mlcf = njt_http_get_module_loc_conf(r, njt_http_memcached_module);

    vv = njt_http_get_indexed_variable(r, mlcf->index);

    if (vv == NULL || vv->not_found || vv->len == 0) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "the \"$memcached_key\" variable is not set");
        return NJT_ERROR;
    }

    escape = 2 * njt_escape_uri(NULL, vv->data, vv->len, NJT_ESCAPE_MEMCACHED);

    len = sizeof("get ") - 1 + vv->len + escape + sizeof(CRLF) - 1;

    b = njt_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NJT_ERROR;
    }

    cl = njt_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NJT_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    r->upstream->request_bufs = cl;

    *b->last++ = 'g'; *b->last++ = 'e'; *b->last++ = 't'; *b->last++ = ' ';

    ctx = njt_http_get_module_ctx(r, njt_http_memcached_module);

    ctx->key.data = b->last;

    if (escape == 0) {
        b->last = njt_copy(b->last, vv->data, vv->len);

    } else {
        b->last = (u_char *) njt_escape_uri(b->last, vv->data, vv->len,
                                            NJT_ESCAPE_MEMCACHED);
    }

    ctx->key.len = b->last - ctx->key.data;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http memcached request: \"%V\"", &ctx->key);

    *b->last++ = CR; *b->last++ = LF;

    return NJT_OK;
}


static njt_int_t
njt_http_memcached_reinit_request(njt_http_request_t *r)
{
    return NJT_OK;
}


static njt_int_t
njt_http_memcached_process_header(njt_http_request_t *r)
{
    u_char                         *p, *start;
    njt_str_t                       line;
    njt_uint_t                      flags;
    njt_table_elt_t                *h;
    njt_http_upstream_t            *u;
    njt_http_memcached_ctx_t       *ctx;
    njt_http_memcached_loc_conf_t  *mlcf;

    u = r->upstream;

    for (p = u->buffer.pos; p < u->buffer.last; p++) {
        if (*p == LF) {
            goto found;
        }
    }

    return NJT_AGAIN;

found:

    line.data = u->buffer.pos;
    line.len = p - u->buffer.pos;

    if (line.len == 0 || *(p - 1) != CR) {
        goto no_valid;
    }

    *p = '\0';
    line.len--;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "memcached: \"%V\"", &line);

    p = u->buffer.pos;

    ctx = njt_http_get_module_ctx(r, njt_http_memcached_module);
    mlcf = njt_http_get_module_loc_conf(r, njt_http_memcached_module);

    if (njt_strncmp(p, "VALUE ", sizeof("VALUE ") - 1) == 0) {

        p += sizeof("VALUE ") - 1;

        if (njt_strncmp(p, ctx->key.data, ctx->key.len) != 0) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "memcached sent invalid key in response \"%V\" "
                          "for key \"%V\"",
                          &line, &ctx->key);

            return NJT_HTTP_UPSTREAM_INVALID_HEADER;
        }

        p += ctx->key.len;

        if (*p++ != ' ') {
            goto no_valid;
        }

        /* flags */

        start = p;

        while (*p) {
            if (*p++ == ' ') {
                if (mlcf->gzip_flag) {
                    goto flags;
                } else {
                    goto length;
                }
            }
        }

        goto no_valid;

    flags:

        flags = njt_atoi(start, p - start - 1);

        if (flags == (njt_uint_t) NJT_ERROR) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "memcached sent invalid flags in response \"%V\" "
                          "for key \"%V\"",
                          &line, &ctx->key);
            return NJT_HTTP_UPSTREAM_INVALID_HEADER;
        }

        if (flags & mlcf->gzip_flag) {
            h = njt_list_push(&r->headers_out.headers);
            if (h == NULL) {
                return NJT_ERROR;
            }

            h->hash = 1;
            h->next = NULL;
            njt_str_set(&h->key, "Content-Encoding");
            njt_str_set(&h->value, "gzip");
            r->headers_out.content_encoding = h;
        }

    length:

        start = p;
        p = line.data + line.len;

        u->headers_in.content_length_n = njt_atoof(start, p - start);
        if (u->headers_in.content_length_n == NJT_ERROR) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "memcached sent invalid length in response \"%V\" "
                          "for key \"%V\"",
                          &line, &ctx->key);
            return NJT_HTTP_UPSTREAM_INVALID_HEADER;
        }

        u->headers_in.status_n = 200;
        u->state->status = 200;
        u->buffer.pos = p + sizeof(CRLF) - 1;

        return NJT_OK;
    }

    if (njt_strcmp(p, "END\x0d") == 0) {
        njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                      "key: \"%V\" was not found by memcached", &ctx->key);

        u->headers_in.content_length_n = 0;
        u->headers_in.status_n = 404;
        u->state->status = 404;
        u->buffer.pos = p + sizeof("END" CRLF) - 1;
        u->keepalive = 1;

        return NJT_OK;
    }

no_valid:

    njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                  "memcached sent invalid response: \"%V\"", &line);

    return NJT_HTTP_UPSTREAM_INVALID_HEADER;
}


static njt_int_t
njt_http_memcached_filter_init(void *data)
{
    njt_http_memcached_ctx_t  *ctx = data;

    njt_http_upstream_t  *u;

    u = ctx->request->upstream;

    if (u->headers_in.status_n != 404) {
        u->length = u->headers_in.content_length_n + NJT_HTTP_MEMCACHED_END;
        ctx->rest = NJT_HTTP_MEMCACHED_END;

    } else {
        u->length = 0;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_memcached_filter(void *data, ssize_t bytes)
{
    njt_http_memcached_ctx_t  *ctx = data;

    u_char               *last;
    njt_buf_t            *b;
    njt_chain_t          *cl, **ll;
    njt_http_upstream_t  *u;

    u = ctx->request->upstream;
    b = &u->buffer;

    if (u->length == (ssize_t) ctx->rest) {

        if (bytes > u->length
            || njt_strncmp(b->last,
                   njt_http_memcached_end + NJT_HTTP_MEMCACHED_END - ctx->rest,
                   bytes)
               != 0)
        {
            njt_log_error(NJT_LOG_ERR, ctx->request->connection->log, 0,
                          "memcached sent invalid trailer");

            u->length = 0;
            ctx->rest = 0;

            return NJT_OK;
        }

        u->length -= bytes;
        ctx->rest -= bytes;

        if (u->length == 0) {
            u->keepalive = 1;
        }

        return NJT_OK;
    }

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = njt_chain_get_free_buf(ctx->request->pool, &u->free_bufs);
    if (cl == NULL) {
        return NJT_ERROR;
    }

    cl->buf->flush = 1;
    cl->buf->memory = 1;

    *ll = cl;

    last = b->last;
    cl->buf->pos = last;
    b->last += bytes;
    cl->buf->last = b->last;
    cl->buf->tag = u->output.tag;

    njt_log_debug4(NJT_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "memcached filter bytes:%z size:%z length:%O rest:%z",
                   bytes, b->last - b->pos, u->length, ctx->rest);

    if (bytes <= (ssize_t) (u->length - NJT_HTTP_MEMCACHED_END)) {
        u->length -= bytes;
        return NJT_OK;
    }

    last += (size_t) (u->length - NJT_HTTP_MEMCACHED_END);

    if (bytes > u->length
        || njt_strncmp(last, njt_http_memcached_end, b->last - last) != 0)
    {
        njt_log_error(NJT_LOG_ERR, ctx->request->connection->log, 0,
                      "memcached sent invalid trailer");

        b->last = last;
        cl->buf->last = last;
        u->length = 0;
        ctx->rest = 0;

        return NJT_OK;
    }

    ctx->rest -= b->last - last;
    b->last = last;
    cl->buf->last = last;
    u->length = ctx->rest;

    if (u->length == 0) {
        u->keepalive = 1;
    }

    return NJT_OK;
}


static void
njt_http_memcached_abort_request(njt_http_request_t *r)
{
    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http memcached request");
    return;
}


static void
njt_http_memcached_finalize_request(njt_http_request_t *r, njt_int_t rc)
{
    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http memcached request");
    return;
}


static void *
njt_http_memcached_create_loc_conf(njt_conf_t *cf)
{
    njt_http_memcached_loc_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_memcached_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     conf->upstream.bufs.num = 0;
     *     conf->upstream.next_upstream = 0;
     *     conf->upstream.temp_path = NULL;
     */

    conf->upstream.local = NJT_CONF_UNSET_PTR;
    conf->upstream.socket_keepalive = NJT_CONF_UNSET;
    conf->upstream.next_upstream_tries = NJT_CONF_UNSET_UINT;
    conf->upstream.connect_timeout = NJT_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NJT_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NJT_CONF_UNSET_MSEC;
    conf->upstream.next_upstream_timeout = NJT_CONF_UNSET_MSEC;

    conf->upstream.buffer_size = NJT_CONF_UNSET_SIZE;

    /* the hardcoded values */
    conf->upstream.cyclic_temp_file = 0;
    conf->upstream.buffering = 0;
    conf->upstream.ignore_client_abort = 0;
    conf->upstream.send_lowat = 0;
    conf->upstream.bufs.num = 0;
    conf->upstream.busy_buffers_size = 0;
    conf->upstream.max_temp_file_size = 0;
    conf->upstream.temp_file_write_size = 0;
    conf->upstream.intercept_errors = 1;
    conf->upstream.intercept_404 = 1;
    conf->upstream.pass_request_headers = 0;
    conf->upstream.pass_request_body = 0;
    conf->upstream.force_ranges = 1;

    conf->index = NJT_CONF_UNSET;
    conf->gzip_flag = NJT_CONF_UNSET_UINT;

    return conf;
}


static char *
njt_http_memcached_merge_loc_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_memcached_loc_conf_t *prev = parent;
    njt_http_memcached_loc_conf_t *conf = child;

    njt_conf_merge_ptr_value(conf->upstream.local,
                              prev->upstream.local, NULL);

    njt_conf_merge_value(conf->upstream.socket_keepalive,
                              prev->upstream.socket_keepalive, 0);

    njt_conf_merge_uint_value(conf->upstream.next_upstream_tries,
                              prev->upstream.next_upstream_tries, 0);

    njt_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    njt_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    njt_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    njt_conf_merge_msec_value(conf->upstream.next_upstream_timeout,
                              prev->upstream.next_upstream_timeout, 0);

    njt_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) njt_pagesize);

    njt_conf_merge_bitmask_value(conf->upstream.next_upstream,
                              prev->upstream.next_upstream,
                              (NJT_CONF_BITMASK_SET
                               |NJT_HTTP_UPSTREAM_FT_ERROR
                               |NJT_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & NJT_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = NJT_CONF_BITMASK_SET
                                       |NJT_HTTP_UPSTREAM_FT_OFF;
    }

    if (conf->upstream.upstream == NULL) {
        conf->upstream.upstream = prev->upstream.upstream;
    }

    if (conf->index == NJT_CONF_UNSET) {
        conf->index = prev->index;
    }

    njt_conf_merge_uint_value(conf->gzip_flag, prev->gzip_flag, 0);

    return NJT_CONF_OK;
}


static char *
njt_http_memcached_pass(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_memcached_loc_conf_t *mlcf = conf;

    njt_str_t                 *value;
    njt_url_t                  u;
    njt_http_core_loc_conf_t  *clcf;

    if (mlcf->upstream.upstream) {
        return "is duplicate";
    }

    value = cf->args->elts;

    njt_memzero(&u, sizeof(njt_url_t));

    u.url = value[1];
    u.no_resolve = 1;

    mlcf->upstream.upstream = njt_http_upstream_add(cf, &u, 0);
    if (mlcf->upstream.upstream == NULL) {
        return NJT_CONF_ERROR;
    }

    clcf = njt_http_conf_get_module_loc_conf(cf, njt_http_core_module);

    clcf->handler = njt_http_memcached_handler;

    if (clcf->name.len && clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }

    mlcf->index = njt_http_get_variable_index(cf, &njt_http_memcached_key);

    if (mlcf->index == NJT_ERROR) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}
