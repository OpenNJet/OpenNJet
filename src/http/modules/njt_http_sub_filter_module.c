
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


typedef struct {
    njt_http_complex_value_t   match;
    njt_http_complex_value_t   value;
} njt_http_sub_pair_t;


typedef struct {
    njt_str_t                  match;
    njt_http_complex_value_t  *value;
} njt_http_sub_match_t;


typedef struct {
    njt_uint_t                 min_match_len;
    njt_uint_t                 max_match_len;

    u_char                     index[257];
    u_char                     shift[256];
} njt_http_sub_tables_t;


typedef struct {
    njt_uint_t                 dynamic; /* unsigned dynamic:1; */

    njt_array_t               *pairs;

    njt_http_sub_tables_t     *tables;

    njt_hash_t                 types;

    njt_flag_t                 once;
    njt_flag_t                 last_modified;

    njt_array_t               *types_keys;
    njt_array_t               *matches;
} njt_http_sub_loc_conf_t;


typedef struct {
    njt_str_t                  saved;
    njt_str_t                  looked;

    njt_uint_t                 once;   /* unsigned  once:1 */

    njt_buf_t                 *buf;

    u_char                    *pos;
    u_char                    *copy_start;
    u_char                    *copy_end;

    njt_chain_t               *in;
    njt_chain_t               *out;
    njt_chain_t              **last_out;
    njt_chain_t               *busy;
    njt_chain_t               *free;

    njt_str_t                 *sub;
    njt_uint_t                 applied;

    njt_int_t                  offset;
    njt_uint_t                 index;

    njt_http_sub_tables_t     *tables;
    njt_array_t               *matches;
} njt_http_sub_ctx_t;


static njt_uint_t njt_http_sub_cmp_index;


static njt_int_t njt_http_sub_output(njt_http_request_t *r,
    njt_http_sub_ctx_t *ctx);
static njt_int_t njt_http_sub_parse(njt_http_request_t *r,
    njt_http_sub_ctx_t *ctx, njt_uint_t flush);
static njt_int_t njt_http_sub_match(njt_http_sub_ctx_t *ctx, njt_int_t start,
    njt_str_t *m);

static char * njt_http_sub_filter(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static void *njt_http_sub_create_conf(njt_conf_t *cf);
static char *njt_http_sub_merge_conf(njt_conf_t *cf,
    void *parent, void *child);
static void njt_http_sub_init_tables(njt_http_sub_tables_t *tables,
    njt_http_sub_match_t *match, njt_uint_t n);
static njt_int_t njt_http_sub_cmp_matches(const void *one, const void *two);
static njt_int_t njt_http_sub_filter_init(njt_conf_t *cf);


static njt_command_t  njt_http_sub_filter_commands[] = {

    { njt_string("sub_filter"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE2,
      njt_http_sub_filter,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("sub_filter_types"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_http_types_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_sub_loc_conf_t, types_keys),
      &njt_http_html_default_types[0] },

    { njt_string("sub_filter_once"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_sub_loc_conf_t, once),
      NULL },

    { njt_string("sub_filter_last_modified"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_sub_loc_conf_t, last_modified),
      NULL },

      njt_null_command
};


static njt_http_module_t  njt_http_sub_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    njt_http_sub_filter_init,              /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_sub_create_conf,              /* create location configuration */
    njt_http_sub_merge_conf                /* merge location configuration */
};


njt_module_t  njt_http_sub_filter_module = {
    NJT_MODULE_V1,
    &njt_http_sub_filter_module_ctx,       /* module context */
    njt_http_sub_filter_commands,          /* module directives */
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
njt_http_sub_header_filter(njt_http_request_t *r)
{
    njt_str_t                *m;
    njt_uint_t                i, j, n;
    njt_http_sub_ctx_t       *ctx;
    njt_http_sub_pair_t      *pairs;
    njt_http_sub_match_t     *matches;
    njt_http_sub_loc_conf_t  *slcf;

    slcf = njt_http_get_module_loc_conf(r, njt_http_sub_filter_module);

    if (slcf->pairs == NULL
        || r->headers_out.content_length_n == 0
        || njt_http_test_content_type(r, &slcf->types) == NULL)
    {
        return njt_http_next_header_filter(r);
    }

    ctx = njt_pcalloc(r->pool, sizeof(njt_http_sub_ctx_t));
    if (ctx == NULL) {
        return NJT_ERROR;
    }

    if (slcf->dynamic == 0) {
        ctx->tables = slcf->tables;
        ctx->matches = slcf->matches;

    } else {
        pairs = slcf->pairs->elts;
        n = slcf->pairs->nelts;

        matches = njt_pcalloc(r->pool, sizeof(njt_http_sub_match_t) * n);
        if (matches == NULL) {
            return NJT_ERROR;
        }

        j = 0;
        for (i = 0; i < n; i++) {
            matches[j].value = &pairs[i].value;

            if (pairs[i].match.lengths == NULL) {
                matches[j].match = pairs[i].match.value;
                j++;
                continue;
            }

            m = &matches[j].match;
            if (njt_http_complex_value(r, &pairs[i].match, m) != NJT_OK) {
                return NJT_ERROR;
            }

            if (m->len == 0) {
                continue;
            }

            njt_strlow(m->data, m->data, m->len);
            j++;
        }

        if (j == 0) {
            return njt_http_next_header_filter(r);
        }

        ctx->matches = njt_palloc(r->pool, sizeof(njt_array_t));
        if (ctx->matches == NULL) {
            return NJT_ERROR;
        }

        ctx->matches->elts = matches;
        ctx->matches->nelts = j;

        ctx->tables = njt_palloc(r->pool, sizeof(njt_http_sub_tables_t));
        if (ctx->tables == NULL) {
            return NJT_ERROR;
        }

        njt_http_sub_init_tables(ctx->tables, ctx->matches->elts,
                                 ctx->matches->nelts);
    }

    ctx->saved.data = njt_pnalloc(r->pool, ctx->tables->max_match_len - 1);
    if (ctx->saved.data == NULL) {
        return NJT_ERROR;
    }

    ctx->looked.data = njt_pnalloc(r->pool, ctx->tables->max_match_len - 1);
    if (ctx->looked.data == NULL) {
        return NJT_ERROR;
    }

    njt_http_set_ctx(r, ctx, njt_http_sub_filter_module);

    ctx->offset = ctx->tables->min_match_len - 1;
    ctx->last_out = &ctx->out;

    r->filter_need_in_memory = 1;

    if (r == r->main) {
        njt_http_clear_content_length(r);

        if (!slcf->last_modified) {
            njt_http_clear_last_modified(r);
            njt_http_clear_etag(r);

        } else {
            njt_http_weak_etag(r);
        }
    }

    return njt_http_next_header_filter(r);
}


static njt_int_t
njt_http_sub_body_filter(njt_http_request_t *r, njt_chain_t *in)
{
    njt_int_t                  rc;
    njt_buf_t                 *b;
    njt_str_t                 *sub;
    njt_uint_t                 flush, last;
    njt_chain_t               *cl;
    njt_http_sub_ctx_t        *ctx;
    njt_http_sub_match_t      *match;
    njt_http_sub_loc_conf_t   *slcf;

    ctx = njt_http_get_module_ctx(r, njt_http_sub_filter_module);

    if (ctx == NULL) {
        return njt_http_next_body_filter(r, in);
    }

    if ((in == NULL
         && ctx->buf == NULL
         && ctx->in == NULL
         && ctx->busy == NULL))
    {
        return njt_http_next_body_filter(r, in);
    }

    if (ctx->once && (ctx->buf == NULL || ctx->in == NULL)) {

        if (ctx->busy) {
            if (njt_http_sub_output(r, ctx) == NJT_ERROR) {
                return NJT_ERROR;
            }
        }

        return njt_http_next_body_filter(r, in);
    }

    /* add the incoming chain to the chain ctx->in */

    if (in) {
        if (njt_chain_add_copy(r->pool, &ctx->in, in) != NJT_OK) {
            return NJT_ERROR;
        }
    }

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http sub filter \"%V\"", &r->uri);

    flush = 0;
    last = 0;

    while (ctx->in || ctx->buf) {

        if (ctx->buf == NULL) {
            ctx->buf = ctx->in->buf;
            ctx->in = ctx->in->next;
            ctx->pos = ctx->buf->pos;
        }

        if (ctx->buf->flush || ctx->buf->recycled) {
            flush = 1;
        }

        if (ctx->in == NULL) {
            last = flush;
        }

        b = NULL;

        while (ctx->pos < ctx->buf->last) {

            rc = njt_http_sub_parse(r, ctx, last);

            njt_log_debug4(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "parse: %i, looked: \"%V\" %p-%p",
                           rc, &ctx->looked, ctx->copy_start, ctx->copy_end);

            if (rc == NJT_ERROR) {
                return rc;
            }

            if (ctx->saved.len) {

                njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "saved: \"%V\"", &ctx->saved);

                cl = njt_chain_get_free_buf(r->pool, &ctx->free);
                if (cl == NULL) {
                    return NJT_ERROR;
                }

                b = cl->buf;

                njt_memzero(b, sizeof(njt_buf_t));

                b->pos = njt_pnalloc(r->pool, ctx->saved.len);
                if (b->pos == NULL) {
                    return NJT_ERROR;
                }

                njt_memcpy(b->pos, ctx->saved.data, ctx->saved.len);
                b->last = b->pos + ctx->saved.len;
                b->memory = 1;

                *ctx->last_out = cl;
                ctx->last_out = &cl->next;

                ctx->saved.len = 0;
            }

            if (ctx->copy_start != ctx->copy_end) {

                cl = njt_chain_get_free_buf(r->pool, &ctx->free);
                if (cl == NULL) {
                    return NJT_ERROR;
                }

                b = cl->buf;

                njt_memcpy(b, ctx->buf, sizeof(njt_buf_t));

                b->pos = ctx->copy_start;
                b->last = ctx->copy_end;
                b->shadow = NULL;
                b->last_buf = 0;
                b->last_in_chain = 0;
                b->recycled = 0;

                if (b->in_file) {
                    b->file_last = b->file_pos + (b->last - ctx->buf->pos);
                    b->file_pos += b->pos - ctx->buf->pos;
                }

                *ctx->last_out = cl;
                ctx->last_out = &cl->next;
            }

            if (rc == NJT_AGAIN) {
                continue;
            }


            /* rc == NJT_OK */

            cl = njt_chain_get_free_buf(r->pool, &ctx->free);
            if (cl == NULL) {
                return NJT_ERROR;
            }

            b = cl->buf;

            njt_memzero(b, sizeof(njt_buf_t));

            slcf = njt_http_get_module_loc_conf(r, njt_http_sub_filter_module);

            if (ctx->sub == NULL) {
                ctx->sub = njt_pcalloc(r->pool, sizeof(njt_str_t)
                                                * ctx->matches->nelts);
                if (ctx->sub == NULL) {
                    return NJT_ERROR;
                }
            }

            sub = &ctx->sub[ctx->index];

            if (sub->data == NULL) {
                match = ctx->matches->elts;

                if (njt_http_complex_value(r, match[ctx->index].value, sub)
                    != NJT_OK)
                {
                    return NJT_ERROR;
                }
            }

            if (sub->len) {
                b->memory = 1;
                b->pos = sub->data;
                b->last = sub->data + sub->len;

            } else {
                b->sync = 1;
            }

            *ctx->last_out = cl;
            ctx->last_out = &cl->next;

            ctx->index = 0;
            ctx->once = slcf->once && (++ctx->applied == ctx->matches->nelts);

            continue;
        }

        if (ctx->looked.len
            && (ctx->buf->last_buf || ctx->buf->last_in_chain))
        {
            cl = njt_chain_get_free_buf(r->pool, &ctx->free);
            if (cl == NULL) {
                return NJT_ERROR;
            }

            b = cl->buf;

            njt_memzero(b, sizeof(njt_buf_t));

            b->pos = ctx->looked.data;
            b->last = b->pos + ctx->looked.len;
            b->memory = 1;

            *ctx->last_out = cl;
            ctx->last_out = &cl->next;

            ctx->looked.len = 0;
        }

        if (ctx->buf->last_buf || ctx->buf->flush || ctx->buf->sync
            || njt_buf_in_memory(ctx->buf))
        {
            if (b == NULL) {
                cl = njt_chain_get_free_buf(r->pool, &ctx->free);
                if (cl == NULL) {
                    return NJT_ERROR;
                }

                b = cl->buf;

                njt_memzero(b, sizeof(njt_buf_t));

                b->sync = 1;

                *ctx->last_out = cl;
                ctx->last_out = &cl->next;
            }

            b->last_buf = ctx->buf->last_buf;
            b->last_in_chain = ctx->buf->last_in_chain;
            b->flush = ctx->buf->flush;
            b->shadow = ctx->buf;

            b->recycled = ctx->buf->recycled;
        }

        ctx->buf = NULL;
    }

    if (ctx->out == NULL && ctx->busy == NULL) {
        return NJT_OK;
    }

    return njt_http_sub_output(r, ctx);
}


static njt_int_t
njt_http_sub_output(njt_http_request_t *r, njt_http_sub_ctx_t *ctx)
{
    njt_int_t     rc;
    njt_buf_t    *b;
    njt_chain_t  *cl;

#if 1
    b = NULL;
    for (cl = ctx->out; cl; cl = cl->next) {
        njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "sub out: %p %p", cl->buf, cl->buf->pos);
        if (cl->buf == b) {
            njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
                          "the same buf was used in sub");
            njt_debug_point();
            return NJT_ERROR;
        }
        b = cl->buf;
    }
#endif

    rc = njt_http_next_body_filter(r, ctx->out);

    if (ctx->busy == NULL) {
        ctx->busy = ctx->out;

    } else {
        for (cl = ctx->busy; cl->next; cl = cl->next) { /* void */ }
        cl->next = ctx->out;
    }

    ctx->out = NULL;
    ctx->last_out = &ctx->out;

    while (ctx->busy) {

        cl = ctx->busy;
        b = cl->buf;

        if (njt_buf_size(b) != 0) {
            break;
        }

        if (b->shadow) {
            b->shadow->pos = b->shadow->last;
        }

        ctx->busy = cl->next;

        if (njt_buf_in_memory(b) || b->in_file) {
            /* add data bufs only to the free buf chain */

            cl->next = ctx->free;
            ctx->free = cl;
        }
    }

    if (ctx->in || ctx->buf) {
        r->buffered |= NJT_HTTP_SUB_BUFFERED;

    } else {
        r->buffered &= ~NJT_HTTP_SUB_BUFFERED;
    }

    return rc;
}


static njt_int_t
njt_http_sub_parse(njt_http_request_t *r, njt_http_sub_ctx_t *ctx,
    njt_uint_t flush)
{
    u_char                   *p, c;
    njt_str_t                *m;
    njt_int_t                 offset, start, next, end, len, rc;
    njt_uint_t                shift, i, j;
    njt_http_sub_match_t     *match;
    njt_http_sub_tables_t    *tables;
    njt_http_sub_loc_conf_t  *slcf;

    slcf = njt_http_get_module_loc_conf(r, njt_http_sub_filter_module);
    tables = ctx->tables;
    match = ctx->matches->elts;

    offset = ctx->offset;
    end = ctx->buf->last - ctx->pos;

    if (ctx->once) {
        /* sets start and next to end */
        offset = end + (njt_int_t) tables->min_match_len - 1;
        goto again;
    }

    while (offset < end) {

        c = offset < 0 ? ctx->looked.data[ctx->looked.len + offset]
                       : ctx->pos[offset];

        c = njt_tolower(c);

        shift = tables->shift[c];
        if (shift > 0) {
            offset += shift;
            continue;
        }

        /* a potential match */

        start = offset - (njt_int_t) tables->min_match_len + 1;

        i = njt_max((njt_uint_t) tables->index[c], ctx->index);
        j = tables->index[c + 1];

        while (i != j) {

            if (slcf->once && ctx->sub && ctx->sub[i].data) {
                goto next;
            }

            m = &match[i].match;

            rc = njt_http_sub_match(ctx, start, m);

            if (rc == NJT_DECLINED) {
                goto next;
            }

            ctx->index = i;

            if (rc == NJT_AGAIN) {
                goto again;
            }

            ctx->offset = offset + (njt_int_t) m->len;
            next = start + (njt_int_t) m->len;
            end = njt_max(next, 0);
            rc = NJT_OK;

            goto done;

        next:

            i++;
        }

        offset++;
        ctx->index = 0;
    }

    if (flush) {
        for ( ;; ) {
            start = offset - (njt_int_t) tables->min_match_len + 1;

            if (start >= end) {
                break;
            }

            for (i = 0; i < ctx->matches->nelts; i++) {
                m = &match[i].match;

                if (njt_http_sub_match(ctx, start, m) == NJT_AGAIN) {
                    goto again;
                }
            }

            offset++;
        }
    }

again:

    ctx->offset = offset;
    start = offset - (njt_int_t) tables->min_match_len + 1;
    next = start;
    rc = NJT_AGAIN;

done:

    /* send [ - looked.len, start ] to client */

    ctx->saved.len = ctx->looked.len + njt_min(start, 0);
    njt_memcpy(ctx->saved.data, ctx->looked.data, ctx->saved.len);

    ctx->copy_start = ctx->pos;
    ctx->copy_end = ctx->pos + njt_max(start, 0);

    /* save [ next, end ] in looked */

    len = njt_min(next, 0);
    p = ctx->looked.data;
    p = njt_movemem(p, p + ctx->looked.len + len, - len);

    len = njt_max(next, 0);
    p = njt_cpymem(p, ctx->pos + len, end - len);
    ctx->looked.len = p - ctx->looked.data;

    /* update position */

    ctx->pos += end;
    ctx->offset -= end;

    return rc;
}


static njt_int_t
njt_http_sub_match(njt_http_sub_ctx_t *ctx, njt_int_t start, njt_str_t *m)
{
    u_char  *p, *last, *pat, *pat_end;

    pat = m->data;
    pat_end = m->data + m->len;

    if (start >= 0) {
        p = ctx->pos + start;

    } else {
        last = ctx->looked.data + ctx->looked.len;
        p = last + start;

        while (p < last && pat < pat_end) {
            if (njt_tolower(*p) != *pat) {
                return NJT_DECLINED;
            }

            p++;
            pat++;
        }

        p = ctx->pos;
    }

    while (p < ctx->buf->last && pat < pat_end) {
        if (njt_tolower(*p) != *pat) {
            return NJT_DECLINED;
        }

        p++;
        pat++;
    }

    if (pat != pat_end) {
        /* partial match */
        return NJT_AGAIN;
    }

    return NJT_OK;
}


static char *
njt_http_sub_filter(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_sub_loc_conf_t *slcf = conf;

    njt_str_t                         *value;
    njt_http_sub_pair_t               *pair;
    njt_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (value[1].len == 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "empty search pattern");
        return NJT_CONF_ERROR;
    }

    if (slcf->pairs == NULL) {
        slcf->pairs = njt_array_create(cf->pool, 1,
                                       sizeof(njt_http_sub_pair_t));
        if (slcf->pairs == NULL) {
            return NJT_CONF_ERROR;
        }
    }

    if (slcf->pairs->nelts == 255) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "number of search patterns exceeds 255");
        return NJT_CONF_ERROR;
    }

    njt_strlow(value[1].data, value[1].data, value[1].len);

    pair = njt_array_push(slcf->pairs);
    if (pair == NULL) {
        return NJT_CONF_ERROR;
    }

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &pair->match;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    if (ccv.complex_value->lengths != NULL) {
        slcf->dynamic = 1;

    } else {
        njt_strlow(pair->match.value.data, pair->match.value.data,
                   pair->match.value.len);
    }

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &pair->value;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


static void *
njt_http_sub_create_conf(njt_conf_t *cf)
{
    njt_http_sub_loc_conf_t  *slcf;

    slcf = njt_pcalloc(cf->pool, sizeof(njt_http_sub_loc_conf_t));
    if (slcf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     conf->dynamic = 0;
     *     conf->pairs = NULL;
     *     conf->tables = NULL;
     *     conf->types = { NULL };
     *     conf->types_keys = NULL;
     *     conf->matches = NULL;
     */

    slcf->once = NJT_CONF_UNSET;
    slcf->last_modified = NJT_CONF_UNSET;

    return slcf;
}


static char *
njt_http_sub_merge_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_uint_t                i, n;
    njt_http_sub_pair_t      *pairs;
    njt_http_sub_match_t     *matches;
    njt_http_sub_loc_conf_t  *prev = parent;
    njt_http_sub_loc_conf_t  *conf = child;

    njt_conf_merge_value(conf->once, prev->once, 1);
    njt_conf_merge_value(conf->last_modified, prev->last_modified, 0);

    if (njt_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             njt_http_html_default_types)
        != NJT_OK)
    {
        return NJT_CONF_ERROR;
    }

    if (conf->pairs == NULL) {
        conf->dynamic = prev->dynamic;
        conf->pairs = prev->pairs;
        conf->matches = prev->matches;
        conf->tables = prev->tables;
    }

    if (conf->pairs && conf->dynamic == 0 && conf->tables == NULL) {
        pairs = conf->pairs->elts;
        n = conf->pairs->nelts;

        matches = njt_palloc(cf->pool, sizeof(njt_http_sub_match_t) * n);
        if (matches == NULL) {
            return NJT_CONF_ERROR;
        }

        for (i = 0; i < n; i++) {
            matches[i].match = pairs[i].match.value;
            matches[i].value = &pairs[i].value;
        }

        conf->matches = njt_palloc(cf->pool, sizeof(njt_array_t));
        if (conf->matches == NULL) {
            return NJT_CONF_ERROR;
        }

        conf->matches->elts = matches;
        conf->matches->nelts = n;

        conf->tables = njt_palloc(cf->pool, sizeof(njt_http_sub_tables_t));
        if (conf->tables == NULL) {
            return NJT_CONF_ERROR;
        }

        njt_http_sub_init_tables(conf->tables, conf->matches->elts,
                                 conf->matches->nelts);
    }

    return NJT_CONF_OK;
}


static void
njt_http_sub_init_tables(njt_http_sub_tables_t *tables,
    njt_http_sub_match_t *match, njt_uint_t n)
{
    u_char      c;
    njt_uint_t  i, j, min, max, ch;

    min = match[0].match.len;
    max = match[0].match.len;

    for (i = 1; i < n; i++) {
        min = njt_min(min, match[i].match.len);
        max = njt_max(max, match[i].match.len);
    }

    tables->min_match_len = min;
    tables->max_match_len = max;

    njt_http_sub_cmp_index = tables->min_match_len - 1;
    njt_sort(match, n, sizeof(njt_http_sub_match_t), njt_http_sub_cmp_matches);

    min = njt_min(min, 255);
    njt_memset(tables->shift, min, 256);

    ch = 0;

    for (i = 0; i < n; i++) {

        for (j = 0; j < min; j++) {
            c = match[i].match.data[tables->min_match_len - 1 - j];
            tables->shift[c] = njt_min(tables->shift[c], (u_char) j);
        }

        c = match[i].match.data[tables->min_match_len - 1];
        while (ch <= (njt_uint_t) c) {
            tables->index[ch++] = (u_char) i;
        }
    }

    while (ch < 257) {
        tables->index[ch++] = (u_char) n;
    }
}


static njt_int_t
njt_http_sub_cmp_matches(const void *one, const void *two)
{
    njt_int_t              c1, c2;
    njt_http_sub_match_t  *first, *second;

    first = (njt_http_sub_match_t *) one;
    second = (njt_http_sub_match_t *) two;

    c1 = first->match.data[njt_http_sub_cmp_index];
    c2 = second->match.data[njt_http_sub_cmp_index];

    return c1 - c2;
}


static njt_int_t
njt_http_sub_filter_init(njt_conf_t *cf)
{
    njt_http_next_header_filter = njt_http_top_header_filter;
    njt_http_top_header_filter = njt_http_sub_header_filter;

    njt_http_next_body_filter = njt_http_top_body_filter;
    njt_http_top_body_filter = njt_http_sub_body_filter;

    return NJT_OK;
}
