
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>


typedef struct {
    njt_stream_variable_value_t       *value;
    u_short                            start;
    u_short                            end;
} njt_stream_geo_range_t;


typedef struct {
    njt_radix_tree_t                  *tree;
#if (NJT_HAVE_INET6)
    njt_radix_tree_t                  *tree6;
#endif
} njt_stream_geo_trees_t;


typedef struct {
    njt_stream_geo_range_t           **low;
    njt_stream_variable_value_t       *default_value;
} njt_stream_geo_high_ranges_t;


typedef struct {
    njt_str_node_t                     sn;
    njt_stream_variable_value_t       *value;
    size_t                             offset;
} njt_stream_geo_variable_value_node_t;


typedef struct {
    njt_stream_variable_value_t       *value;
    njt_str_t                         *net;
    njt_stream_geo_high_ranges_t       high;
    njt_radix_tree_t                  *tree;
#if (NJT_HAVE_INET6)
    njt_radix_tree_t                  *tree6;
#endif
    njt_rbtree_t                       rbtree;
    njt_rbtree_node_t                  sentinel;
    njt_pool_t                        *pool;
    njt_pool_t                        *temp_pool;

    size_t                             data_size;

    njt_str_t                          include_name;
    njt_uint_t                         includes;
    njt_uint_t                         entries;

    unsigned                           ranges:1;
    unsigned                           outside_entries:1;
    unsigned                           allow_binary_include:1;
    unsigned                           binary_include:1;
} njt_stream_geo_conf_ctx_t;


typedef struct {
    union {
        njt_stream_geo_trees_t         trees;
        njt_stream_geo_high_ranges_t   high;
    } u;

    njt_int_t                          index;
} njt_stream_geo_ctx_t;


static njt_int_t njt_stream_geo_addr(njt_stream_session_t *s,
    njt_stream_geo_ctx_t *ctx, njt_addr_t *addr);

static char *njt_stream_geo_block(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_stream_geo(njt_conf_t *cf, njt_command_t *dummy, void *conf);
static char *njt_stream_geo_range(njt_conf_t *cf,
    njt_stream_geo_conf_ctx_t *ctx, njt_str_t *value);
static char *njt_stream_geo_add_range(njt_conf_t *cf,
    njt_stream_geo_conf_ctx_t *ctx, in_addr_t start, in_addr_t end);
static njt_uint_t njt_stream_geo_delete_range(njt_conf_t *cf,
    njt_stream_geo_conf_ctx_t *ctx, in_addr_t start, in_addr_t end);
static char *njt_stream_geo_cidr(njt_conf_t *cf,
    njt_stream_geo_conf_ctx_t *ctx, njt_str_t *value);
static char *njt_stream_geo_cidr_add(njt_conf_t *cf,
    njt_stream_geo_conf_ctx_t *ctx, njt_cidr_t *cidr, njt_str_t *value,
    njt_str_t *net);
static njt_stream_variable_value_t *njt_stream_geo_value(njt_conf_t *cf,
    njt_stream_geo_conf_ctx_t *ctx, njt_str_t *value);
static njt_int_t njt_stream_geo_cidr_value(njt_conf_t *cf, njt_str_t *net,
    njt_cidr_t *cidr);
static char *njt_stream_geo_include(njt_conf_t *cf,
    njt_stream_geo_conf_ctx_t *ctx, njt_str_t *name);
static njt_int_t njt_stream_geo_include_binary_base(njt_conf_t *cf,
    njt_stream_geo_conf_ctx_t *ctx, njt_str_t *name);
static void njt_stream_geo_create_binary_base(njt_stream_geo_conf_ctx_t *ctx);
static u_char *njt_stream_geo_copy_values(u_char *base, u_char *p,
    njt_rbtree_node_t *node, njt_rbtree_node_t *sentinel);


static njt_command_t  njt_stream_geo_commands[] = {

    { njt_string("geo"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_BLOCK|NJT_CONF_TAKE12,
      njt_stream_geo_block,
      0,
      0,
      NULL },

      njt_null_command
};


static njt_stream_module_t  njt_stream_geo_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL                                   /* merge server configuration */
};


njt_module_t  njt_stream_geo_module = {
    NJT_MODULE_V1,
    &njt_stream_geo_module_ctx,            /* module context */
    njt_stream_geo_commands,               /* module directives */
    NJT_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};


typedef struct {
    u_char    GEORNG[6];
    u_char    version;
    u_char    ptr_size;
    uint32_t  endianness;
    uint32_t  crc32;
} njt_stream_geo_header_t;


static njt_stream_geo_header_t  njt_stream_geo_header = {
    { 'G', 'E', 'O', 'R', 'N', 'G' }, 0, sizeof(void *), 0x12345678, 0
};


/* geo range is AF_INET only */

static njt_int_t
njt_stream_geo_cidr_variable(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    njt_stream_geo_ctx_t *ctx = (njt_stream_geo_ctx_t *) data;

    in_addr_t                     inaddr;
    njt_addr_t                    addr;
    struct sockaddr_in           *sin;
    njt_stream_variable_value_t  *vv;
#if (NJT_HAVE_INET6)
    u_char                       *p;
    struct in6_addr              *inaddr6;
#endif

    if (njt_stream_geo_addr(s, ctx, &addr) != NJT_OK) {
        vv = (njt_stream_variable_value_t *)
                  njt_radix32tree_find(ctx->u.trees.tree, INADDR_NONE);
        goto done;
    }

    switch (addr.sockaddr->sa_family) {

#if (NJT_HAVE_INET6)
    case AF_INET6:
        inaddr6 = &((struct sockaddr_in6 *) addr.sockaddr)->sin6_addr;
        p = inaddr6->s6_addr;

        if (IN6_IS_ADDR_V4MAPPED(inaddr6)) {
            inaddr = p[12] << 24;
            inaddr += p[13] << 16;
            inaddr += p[14] << 8;
            inaddr += p[15];

            vv = (njt_stream_variable_value_t *)
                      njt_radix32tree_find(ctx->u.trees.tree, inaddr);

        } else {
            vv = (njt_stream_variable_value_t *)
                      njt_radix128tree_find(ctx->u.trees.tree6, p);
        }

        break;
#endif

#if (NJT_HAVE_UNIX_DOMAIN)
    case AF_UNIX:
        vv = (njt_stream_variable_value_t *)
                  njt_radix32tree_find(ctx->u.trees.tree, INADDR_NONE);
        break;
#endif

    default: /* AF_INET */
        sin = (struct sockaddr_in *) addr.sockaddr;
        inaddr = ntohl(sin->sin_addr.s_addr);

        vv = (njt_stream_variable_value_t *)
                  njt_radix32tree_find(ctx->u.trees.tree, inaddr);

        break;
    }

done:

    *v = *vv;

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream geo: %v", v);

    return NJT_OK;
}


static njt_int_t
njt_stream_geo_range_variable(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    njt_stream_geo_ctx_t *ctx = (njt_stream_geo_ctx_t *) data;

    in_addr_t                inaddr;
    njt_addr_t               addr;
    njt_uint_t               n;
    struct sockaddr_in      *sin;
    njt_stream_geo_range_t  *range;
#if (NJT_HAVE_INET6)
    u_char                  *p;
    struct in6_addr         *inaddr6;
#endif

    *v = *ctx->u.high.default_value;

    if (njt_stream_geo_addr(s, ctx, &addr) == NJT_OK) {

        switch (addr.sockaddr->sa_family) {

#if (NJT_HAVE_INET6)
        case AF_INET6:
            inaddr6 = &((struct sockaddr_in6 *) addr.sockaddr)->sin6_addr;

            if (IN6_IS_ADDR_V4MAPPED(inaddr6)) {
                p = inaddr6->s6_addr;

                inaddr = p[12] << 24;
                inaddr += p[13] << 16;
                inaddr += p[14] << 8;
                inaddr += p[15];

            } else {
                inaddr = INADDR_NONE;
            }

            break;
#endif

#if (NJT_HAVE_UNIX_DOMAIN)
        case AF_UNIX:
            inaddr = INADDR_NONE;
            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) addr.sockaddr;
            inaddr = ntohl(sin->sin_addr.s_addr);
            break;
        }

    } else {
        inaddr = INADDR_NONE;
    }

    if (ctx->u.high.low) {
        range = ctx->u.high.low[inaddr >> 16];

        if (range) {
            n = inaddr & 0xffff;
            do {
                if (n >= (njt_uint_t) range->start
                    && n <= (njt_uint_t) range->end)
                {
                    *v = *range->value;
                    break;
                }
            } while ((++range)->value);
        }
    }

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream geo: %v", v);

    return NJT_OK;
}


static njt_int_t
njt_stream_geo_addr(njt_stream_session_t *s, njt_stream_geo_ctx_t *ctx,
    njt_addr_t *addr)
{
    njt_stream_variable_value_t  *v;

    if (ctx->index == -1) {
        njt_log_debug1(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "stream geo started: %V", &s->connection->addr_text);

        addr->sockaddr = s->connection->sockaddr;
        addr->socklen = s->connection->socklen;
        /* addr->name = s->connection->addr_text; */

        return NJT_OK;
    }

    v = njt_stream_get_flushed_variable(s, ctx->index);

    if (v == NULL || v->not_found) {
        njt_log_debug0(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "stream geo not found");

        return NJT_ERROR;
    }

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream geo started: %v", v);

    if (njt_parse_addr(s->connection->pool, addr, v->data, v->len) == NJT_OK) {
        return NJT_OK;
    }

    return NJT_ERROR;
}


static char *
njt_stream_geo_block(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char                       *rv;
    size_t                      len;
    njt_str_t                  *value, name;
    njt_uint_t                  i;
    njt_conf_t                  save;
    njt_pool_t                 *pool;
    njt_array_t                *a;
    njt_stream_variable_t      *var;
    njt_stream_geo_ctx_t       *geo;
    njt_stream_geo_conf_ctx_t   ctx;
#if (NJT_HAVE_INET6)
    static struct in6_addr      zero;
#endif

    value = cf->args->elts;

    geo = njt_palloc(cf->pool, sizeof(njt_stream_geo_ctx_t));
    if (geo == NULL) {
        return NJT_CONF_ERROR;
    }

    name = value[1];

    if (name.data[0] != '$') {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &name);
        return NJT_CONF_ERROR;
    }

    name.len--;
    name.data++;

    if (cf->args->nelts == 3) {

        geo->index = njt_stream_get_variable_index(cf, &name);
        if (geo->index == NJT_ERROR) {
            return NJT_CONF_ERROR;
        }

        name = value[2];

        if (name.data[0] != '$') {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid variable name \"%V\"", &name);
            return NJT_CONF_ERROR;
        }

        name.len--;
        name.data++;

    } else {
        geo->index = -1;
    }

    var = njt_stream_add_variable(cf, &name, NJT_STREAM_VAR_CHANGEABLE);
    if (var == NULL) {
        return NJT_CONF_ERROR;
    }

    pool = njt_create_pool(NJT_DEFAULT_POOL_SIZE, cf->log);
    if (pool == NULL) {
        return NJT_CONF_ERROR;
    }

    njt_memzero(&ctx, sizeof(njt_stream_geo_conf_ctx_t));

    ctx.temp_pool = njt_create_pool(NJT_DEFAULT_POOL_SIZE, cf->log);
    if (ctx.temp_pool == NULL) {
        njt_destroy_pool(pool);
        return NJT_CONF_ERROR;
    }

    njt_rbtree_init(&ctx.rbtree, &ctx.sentinel, njt_str_rbtree_insert_value);

    ctx.pool = cf->pool;
    ctx.data_size = sizeof(njt_stream_geo_header_t)
                  + sizeof(njt_stream_variable_value_t)
                  + 0x10000 * sizeof(njt_stream_geo_range_t *);
    ctx.allow_binary_include = 1;

    save = *cf;
    cf->pool = pool;
    cf->ctx = &ctx;
    cf->handler = njt_stream_geo;
    cf->handler_conf = conf;

    rv = njt_conf_parse(cf, NULL);

    *cf = save;

    if (rv != NJT_CONF_OK) {
        goto failed;
    }

    if (ctx.ranges) {

        if (ctx.high.low && !ctx.binary_include) {
            for (i = 0; i < 0x10000; i++) {
                a = (njt_array_t *) ctx.high.low[i];

                if (a == NULL) {
                    continue;
                }

                if (a->nelts == 0) {
                    ctx.high.low[i] = NULL;
                    continue;
                }

                len = a->nelts * sizeof(njt_stream_geo_range_t);

                ctx.high.low[i] = njt_palloc(cf->pool, len + sizeof(void *));
                if (ctx.high.low[i] == NULL) {
                    goto failed;
                }

                njt_memcpy(ctx.high.low[i], a->elts, len);
                ctx.high.low[i][a->nelts].value = NULL;
                ctx.data_size += len + sizeof(void *);
            }

            if (ctx.allow_binary_include
                && !ctx.outside_entries
                && ctx.entries > 100000
                && ctx.includes == 1)
            {
                njt_stream_geo_create_binary_base(&ctx);
            }
        }

        if (ctx.high.default_value == NULL) {
            ctx.high.default_value = &njt_stream_variable_null_value;
        }

        geo->u.high = ctx.high;

        var->get_handler = njt_stream_geo_range_variable;
        var->data = (uintptr_t) geo;

    } else {
        if (ctx.tree == NULL) {
            ctx.tree = njt_radix_tree_create(cf->pool, -1);
            if (ctx.tree == NULL) {
                goto failed;
            }
        }

        geo->u.trees.tree = ctx.tree;

#if (NJT_HAVE_INET6)
        if (ctx.tree6 == NULL) {
            ctx.tree6 = njt_radix_tree_create(cf->pool, -1);
            if (ctx.tree6 == NULL) {
                goto failed;
            }
        }

        geo->u.trees.tree6 = ctx.tree6;
#endif

        var->get_handler = njt_stream_geo_cidr_variable;
        var->data = (uintptr_t) geo;

        if (njt_radix32tree_insert(ctx.tree, 0, 0,
                                   (uintptr_t) &njt_stream_variable_null_value)
            == NJT_ERROR)
        {
            goto failed;
        }

        /* NJT_BUSY is okay (default was set explicitly) */

#if (NJT_HAVE_INET6)
        if (njt_radix128tree_insert(ctx.tree6, zero.s6_addr, zero.s6_addr,
                                    (uintptr_t) &njt_stream_variable_null_value)
            == NJT_ERROR)
        {
            goto failed;
        }
#endif
    }

    njt_destroy_pool(ctx.temp_pool);
    njt_destroy_pool(pool);

    return NJT_CONF_OK;

failed:

    njt_destroy_pool(ctx.temp_pool);
    njt_destroy_pool(pool);

    return NJT_CONF_ERROR;
}


static char *
njt_stream_geo(njt_conf_t *cf, njt_command_t *dummy, void *conf)
{
    char                       *rv;
    njt_str_t                  *value;
    njt_stream_geo_conf_ctx_t  *ctx;

    ctx = cf->ctx;

    value = cf->args->elts;

    if (cf->args->nelts == 1) {

        if (njt_strcmp(value[0].data, "ranges") == 0) {

            if (ctx->tree
#if (NJT_HAVE_INET6)
                || ctx->tree6
#endif
               )
            {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "the \"ranges\" directive must be "
                                   "the first directive inside \"geo\" block");
                goto failed;
            }

            ctx->ranges = 1;

            rv = NJT_CONF_OK;

            goto done;
        }
    }

    if (cf->args->nelts != 2) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid number of the geo parameters");
        goto failed;
    }

    if (njt_strcmp(value[0].data, "include") == 0) {

        rv = njt_stream_geo_include(cf, ctx, &value[1]);

        goto done;
    }

    if (ctx->ranges) {
        rv = njt_stream_geo_range(cf, ctx, value);

    } else {
        rv = njt_stream_geo_cidr(cf, ctx, value);
    }

done:

    njt_reset_pool(cf->pool);

    return rv;

failed:

    njt_reset_pool(cf->pool);

    return NJT_CONF_ERROR;
}


static char *
njt_stream_geo_range(njt_conf_t *cf, njt_stream_geo_conf_ctx_t *ctx,
    njt_str_t *value)
{
    u_char      *p, *last;
    in_addr_t    start, end;
    njt_str_t   *net;
    njt_uint_t   del;

    if (njt_strcmp(value[0].data, "default") == 0) {

        if (ctx->high.default_value) {
            njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                "duplicate default geo range value: \"%V\", old value: \"%v\"",
                &value[1], ctx->high.default_value);
        }

        ctx->high.default_value = njt_stream_geo_value(cf, ctx, &value[1]);
        if (ctx->high.default_value == NULL) {
            return NJT_CONF_ERROR;
        }

        return NJT_CONF_OK;
    }

    if (ctx->binary_include) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
            "binary geo range base \"%s\" cannot be mixed with usual entries",
            ctx->include_name.data);
        return NJT_CONF_ERROR;
    }

    if (ctx->high.low == NULL) {
        ctx->high.low = njt_pcalloc(ctx->pool,
                                    0x10000 * sizeof(njt_stream_geo_range_t *));
        if (ctx->high.low == NULL) {
            return NJT_CONF_ERROR;
        }
    }

    ctx->entries++;
    ctx->outside_entries = 1;

    if (njt_strcmp(value[0].data, "delete") == 0) {
        net = &value[1];
        del = 1;

    } else {
        net = &value[0];
        del = 0;
    }

    last = net->data + net->len;

    p = njt_strlchr(net->data, last, '-');

    if (p == NULL) {
        goto invalid;
    }

    start = njt_inet_addr(net->data, p - net->data);

    if (start == INADDR_NONE) {
        goto invalid;
    }

    start = ntohl(start);

    p++;

    end = njt_inet_addr(p, last - p);

    if (end == INADDR_NONE) {
        goto invalid;
    }

    end = ntohl(end);

    if (start > end) {
        goto invalid;
    }

    if (del) {
        if (njt_stream_geo_delete_range(cf, ctx, start, end)) {
            njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                               "no address range \"%V\" to delete", net);
        }

        return NJT_CONF_OK;
    }

    ctx->value = njt_stream_geo_value(cf, ctx, &value[1]);

    if (ctx->value == NULL) {
        return NJT_CONF_ERROR;
    }

    ctx->net = net;

    return njt_stream_geo_add_range(cf, ctx, start, end);

invalid:

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "invalid range \"%V\"", net);

    return NJT_CONF_ERROR;
}


/* the add procedure is optimized to add a growing up sequence */

static char *
njt_stream_geo_add_range(njt_conf_t *cf, njt_stream_geo_conf_ctx_t *ctx,
    in_addr_t start, in_addr_t end)
{
    in_addr_t                n;
    njt_uint_t               h, i, s, e;
    njt_array_t             *a;
    njt_stream_geo_range_t  *range;

    for (n = start; n <= end; n = (n + 0x10000) & 0xffff0000) {

        h = n >> 16;

        if (n == start) {
            s = n & 0xffff;
        } else {
            s = 0;
        }

        if ((n | 0xffff) > end) {
            e = end & 0xffff;

        } else {
            e = 0xffff;
        }

        a = (njt_array_t *) ctx->high.low[h];

        if (a == NULL) {
            a = njt_array_create(ctx->temp_pool, 64,
                                 sizeof(njt_stream_geo_range_t));
            if (a == NULL) {
                return NJT_CONF_ERROR;
            }

            ctx->high.low[h] = (njt_stream_geo_range_t *) a;
        }

        i = a->nelts;
        range = a->elts;

        while (i) {

            i--;

            if (e < (njt_uint_t) range[i].start) {
                continue;
            }

            if (s > (njt_uint_t) range[i].end) {

                /* add after the range */

                range = njt_array_push(a);
                if (range == NULL) {
                    return NJT_CONF_ERROR;
                }

                range = a->elts;

                njt_memmove(&range[i + 2], &range[i + 1],
                           (a->nelts - 2 - i) * sizeof(njt_stream_geo_range_t));

                range[i + 1].start = (u_short) s;
                range[i + 1].end = (u_short) e;
                range[i + 1].value = ctx->value;

                goto next;
            }

            if (s == (njt_uint_t) range[i].start
                && e == (njt_uint_t) range[i].end)
            {
                njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                    "duplicate range \"%V\", value: \"%v\", old value: \"%v\"",
                    ctx->net, ctx->value, range[i].value);

                range[i].value = ctx->value;

                goto next;
            }

            if (s > (njt_uint_t) range[i].start
                && e < (njt_uint_t) range[i].end)
            {
                /* split the range and insert the new one */

                range = njt_array_push(a);
                if (range == NULL) {
                    return NJT_CONF_ERROR;
                }

                range = njt_array_push(a);
                if (range == NULL) {
                    return NJT_CONF_ERROR;
                }

                range = a->elts;

                njt_memmove(&range[i + 3], &range[i + 1],
                           (a->nelts - 3 - i) * sizeof(njt_stream_geo_range_t));

                range[i + 2].start = (u_short) (e + 1);
                range[i + 2].end = range[i].end;
                range[i + 2].value = range[i].value;

                range[i + 1].start = (u_short) s;
                range[i + 1].end = (u_short) e;
                range[i + 1].value = ctx->value;

                range[i].end = (u_short) (s - 1);

                goto next;
            }

            if (s == (njt_uint_t) range[i].start
                && e < (njt_uint_t) range[i].end)
            {
                /* shift the range start and insert the new range */

                range = njt_array_push(a);
                if (range == NULL) {
                    return NJT_CONF_ERROR;
                }

                range = a->elts;

                njt_memmove(&range[i + 1], &range[i],
                           (a->nelts - 1 - i) * sizeof(njt_stream_geo_range_t));

                range[i + 1].start = (u_short) (e + 1);

                range[i].start = (u_short) s;
                range[i].end = (u_short) e;
                range[i].value = ctx->value;

                goto next;
            }

            if (s > (njt_uint_t) range[i].start
                && e == (njt_uint_t) range[i].end)
            {
                /* shift the range end and insert the new range */

                range = njt_array_push(a);
                if (range == NULL) {
                    return NJT_CONF_ERROR;
                }

                range = a->elts;

                njt_memmove(&range[i + 2], &range[i + 1],
                           (a->nelts - 2 - i) * sizeof(njt_stream_geo_range_t));

                range[i + 1].start = (u_short) s;
                range[i + 1].end = (u_short) e;
                range[i + 1].value = ctx->value;

                range[i].end = (u_short) (s - 1);

                goto next;
            }

            s = (njt_uint_t) range[i].start;
            e = (njt_uint_t) range[i].end;

            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                         "range \"%V\" overlaps \"%d.%d.%d.%d-%d.%d.%d.%d\"",
                         ctx->net,
                         h >> 8, h & 0xff, s >> 8, s & 0xff,
                         h >> 8, h & 0xff, e >> 8, e & 0xff);

            return NJT_CONF_ERROR;
        }

        /* add the first range */

        range = njt_array_push(a);
        if (range == NULL) {
            return NJT_CONF_ERROR;
        }

        range = a->elts;

        njt_memmove(&range[1], &range[0],
                    (a->nelts - 1) * sizeof(njt_stream_geo_range_t));

        range[0].start = (u_short) s;
        range[0].end = (u_short) e;
        range[0].value = ctx->value;

    next:

        if (h == 0xffff) {
            break;
        }
    }

    return NJT_CONF_OK;
}


static njt_uint_t
njt_stream_geo_delete_range(njt_conf_t *cf, njt_stream_geo_conf_ctx_t *ctx,
    in_addr_t start, in_addr_t end)
{
    in_addr_t                n;
    njt_uint_t               h, i, s, e, warn;
    njt_array_t             *a;
    njt_stream_geo_range_t  *range;

    warn = 0;

    for (n = start; n <= end; n = (n + 0x10000) & 0xffff0000) {

        h = n >> 16;

        if (n == start) {
            s = n & 0xffff;
        } else {
            s = 0;
        }

        if ((n | 0xffff) > end) {
            e = end & 0xffff;

        } else {
            e = 0xffff;
        }

        a = (njt_array_t *) ctx->high.low[h];

        if (a == NULL || a->nelts == 0) {
            warn = 1;
            goto next;
        }

        range = a->elts;
        for (i = 0; i < a->nelts; i++) {

            if (s == (njt_uint_t) range[i].start
                && e == (njt_uint_t) range[i].end)
            {
                njt_memmove(&range[i], &range[i + 1],
                           (a->nelts - 1 - i) * sizeof(njt_stream_geo_range_t));

                a->nelts--;

                break;
            }

            if (i == a->nelts - 1) {
                warn = 1;
            }
        }

    next:

        if (h == 0xffff) {
            break;
        }
    }

    return warn;
}


static char *
njt_stream_geo_cidr(njt_conf_t *cf, njt_stream_geo_conf_ctx_t *ctx,
    njt_str_t *value)
{
    char        *rv;
    njt_int_t    rc, del;
    njt_str_t   *net;
    njt_cidr_t   cidr;

    if (ctx->tree == NULL) {
        ctx->tree = njt_radix_tree_create(ctx->pool, -1);
        if (ctx->tree == NULL) {
            return NJT_CONF_ERROR;
        }
    }

#if (NJT_HAVE_INET6)
    if (ctx->tree6 == NULL) {
        ctx->tree6 = njt_radix_tree_create(ctx->pool, -1);
        if (ctx->tree6 == NULL) {
            return NJT_CONF_ERROR;
        }
    }
#endif

    if (njt_strcmp(value[0].data, "default") == 0) {
        cidr.family = AF_INET;
        cidr.u.in.addr = 0;
        cidr.u.in.mask = 0;

        rv = njt_stream_geo_cidr_add(cf, ctx, &cidr, &value[1], &value[0]);

        if (rv != NJT_CONF_OK) {
            return rv;
        }

#if (NJT_HAVE_INET6)
        cidr.family = AF_INET6;
        njt_memzero(&cidr.u.in6, sizeof(njt_in6_cidr_t));

        rv = njt_stream_geo_cidr_add(cf, ctx, &cidr, &value[1], &value[0]);

        if (rv != NJT_CONF_OK) {
            return rv;
        }
#endif

        return NJT_CONF_OK;
    }

    if (njt_strcmp(value[0].data, "delete") == 0) {
        net = &value[1];
        del = 1;

    } else {
        net = &value[0];
        del = 0;
    }

    if (njt_stream_geo_cidr_value(cf, net, &cidr) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    if (cidr.family == AF_INET) {
        cidr.u.in.addr = ntohl(cidr.u.in.addr);
        cidr.u.in.mask = ntohl(cidr.u.in.mask);
    }

    if (del) {
        switch (cidr.family) {

#if (NJT_HAVE_INET6)
        case AF_INET6:
            rc = njt_radix128tree_delete(ctx->tree6,
                                         cidr.u.in6.addr.s6_addr,
                                         cidr.u.in6.mask.s6_addr);
            break;
#endif

        default: /* AF_INET */
            rc = njt_radix32tree_delete(ctx->tree, cidr.u.in.addr,
                                        cidr.u.in.mask);
            break;
        }

        if (rc != NJT_OK) {
            njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                               "no network \"%V\" to delete", net);
        }

        return NJT_CONF_OK;
    }

    return njt_stream_geo_cidr_add(cf, ctx, &cidr, &value[1], net);
}


static char *
njt_stream_geo_cidr_add(njt_conf_t *cf, njt_stream_geo_conf_ctx_t *ctx,
    njt_cidr_t *cidr, njt_str_t *value, njt_str_t *net)
{
    njt_int_t                     rc;
    njt_stream_variable_value_t  *val, *old;

    val = njt_stream_geo_value(cf, ctx, value);

    if (val == NULL) {
        return NJT_CONF_ERROR;
    }

    switch (cidr->family) {

#if (NJT_HAVE_INET6)
    case AF_INET6:
        rc = njt_radix128tree_insert(ctx->tree6, cidr->u.in6.addr.s6_addr,
                                     cidr->u.in6.mask.s6_addr,
                                     (uintptr_t) val);

        if (rc == NJT_OK) {
            return NJT_CONF_OK;
        }

        if (rc == NJT_ERROR) {
            return NJT_CONF_ERROR;
        }

        /* rc == NJT_BUSY */

        old = (njt_stream_variable_value_t *)
                   njt_radix128tree_find(ctx->tree6,
                                         cidr->u.in6.addr.s6_addr);

        njt_conf_log_error(NJT_LOG_WARN, cf, 0,
              "duplicate network \"%V\", value: \"%v\", old value: \"%v\"",
              net, val, old);

        rc = njt_radix128tree_delete(ctx->tree6,
                                     cidr->u.in6.addr.s6_addr,
                                     cidr->u.in6.mask.s6_addr);

        if (rc == NJT_ERROR) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "invalid radix tree");
            return NJT_CONF_ERROR;
        }

        rc = njt_radix128tree_insert(ctx->tree6, cidr->u.in6.addr.s6_addr,
                                     cidr->u.in6.mask.s6_addr,
                                     (uintptr_t) val);

        break;
#endif

    default: /* AF_INET */
        rc = njt_radix32tree_insert(ctx->tree, cidr->u.in.addr,
                                    cidr->u.in.mask, (uintptr_t) val);

        if (rc == NJT_OK) {
            return NJT_CONF_OK;
        }

        if (rc == NJT_ERROR) {
            return NJT_CONF_ERROR;
        }

        /* rc == NJT_BUSY */

        old = (njt_stream_variable_value_t *)
                   njt_radix32tree_find(ctx->tree, cidr->u.in.addr);

        njt_conf_log_error(NJT_LOG_WARN, cf, 0,
              "duplicate network \"%V\", value: \"%v\", old value: \"%v\"",
              net, val, old);

        rc = njt_radix32tree_delete(ctx->tree,
                                    cidr->u.in.addr, cidr->u.in.mask);

        if (rc == NJT_ERROR) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "invalid radix tree");
            return NJT_CONF_ERROR;
        }

        rc = njt_radix32tree_insert(ctx->tree, cidr->u.in.addr,
                                    cidr->u.in.mask, (uintptr_t) val);

        break;
    }

    if (rc == NJT_OK) {
        return NJT_CONF_OK;
    }

    return NJT_CONF_ERROR;
}


static njt_stream_variable_value_t *
njt_stream_geo_value(njt_conf_t *cf, njt_stream_geo_conf_ctx_t *ctx,
    njt_str_t *value)
{
    uint32_t                               hash;
    njt_stream_variable_value_t           *val;
    njt_stream_geo_variable_value_node_t  *gvvn;

    hash = njt_crc32_long(value->data, value->len);

    gvvn = (njt_stream_geo_variable_value_node_t *)
               njt_str_rbtree_lookup(&ctx->rbtree, value, hash);

    if (gvvn) {
        return gvvn->value;
    }

    val = njt_palloc(ctx->pool, sizeof(njt_stream_variable_value_t));
    if (val == NULL) {
        return NULL;
    }

    val->len = value->len;
    val->data = njt_pstrdup(ctx->pool, value);
    if (val->data == NULL) {
        return NULL;
    }

    val->valid = 1;
    val->no_cacheable = 0;
    val->not_found = 0;

    gvvn = njt_palloc(ctx->temp_pool,
                      sizeof(njt_stream_geo_variable_value_node_t));
    if (gvvn == NULL) {
        return NULL;
    }

    gvvn->sn.node.key = hash;
    gvvn->sn.str.len = val->len;
    gvvn->sn.str.data = val->data;
    gvvn->value = val;
    gvvn->offset = 0;

    njt_rbtree_insert(&ctx->rbtree, &gvvn->sn.node);

    ctx->data_size += njt_align(sizeof(njt_stream_variable_value_t)
                                + value->len, sizeof(void *));

    return val;
}


static njt_int_t
njt_stream_geo_cidr_value(njt_conf_t *cf, njt_str_t *net, njt_cidr_t *cidr)
{
    njt_int_t  rc;

    if (njt_strcmp(net->data, "255.255.255.255") == 0) {
        cidr->family = AF_INET;
        cidr->u.in.addr = 0xffffffff;
        cidr->u.in.mask = 0xffffffff;

        return NJT_OK;
    }

    rc = njt_ptocidr(net, cidr);

    if (rc == NJT_ERROR) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "invalid network \"%V\"", net);
        return NJT_ERROR;
    }

    if (rc == NJT_DONE) {
        njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                           "low address bits of %V are meaningless", net);
    }

    return NJT_OK;
}


static char *
njt_stream_geo_include(njt_conf_t *cf, njt_stream_geo_conf_ctx_t *ctx,
    njt_str_t *name)
{
    char       *rv;
    njt_str_t   file;

    file.len = name->len + 4;
    file.data = njt_pnalloc(ctx->temp_pool, name->len + 5);
    if (file.data == NULL) {
        return NJT_CONF_ERROR;
    }

    njt_sprintf(file.data, "%V.bin%Z", name);

    if (njt_conf_full_name(cf->cycle, &file, 1) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    if (ctx->ranges) {
        njt_log_debug1(NJT_LOG_DEBUG_CORE, cf->log, 0, "include %s", file.data);

        switch (njt_stream_geo_include_binary_base(cf, ctx, &file)) {
        case NJT_OK:
            return NJT_CONF_OK;
        case NJT_ERROR:
            return NJT_CONF_ERROR;
        default:
            break;
        }
    }

    file.len -= 4;
    file.data[file.len] = '\0';

    ctx->include_name = file;

    if (ctx->outside_entries) {
        ctx->allow_binary_include = 0;
    }

    njt_log_debug1(NJT_LOG_DEBUG_CORE, cf->log, 0, "include %s", file.data);

    rv = njt_conf_parse(cf, &file);

    ctx->includes++;
    ctx->outside_entries = 0;

    return rv;
}


static njt_int_t
njt_stream_geo_include_binary_base(njt_conf_t *cf,
    njt_stream_geo_conf_ctx_t *ctx, njt_str_t *name)
{
    u_char                       *base, ch;
    time_t                        mtime;
    size_t                        size, len;
    ssize_t                       n;
    uint32_t                      crc32;
    njt_err_t                     err;
    njt_int_t                     rc;
    njt_uint_t                    i;
    njt_file_t                    file;
    njt_file_info_t               fi;
    njt_stream_geo_range_t       *range, **ranges;
    njt_stream_geo_header_t      *header;
    njt_stream_variable_value_t  *vv;

    njt_memzero(&file, sizeof(njt_file_t));
    file.name = *name;
    file.log = cf->log;

    file.fd = njt_open_file(name->data, NJT_FILE_RDONLY, NJT_FILE_OPEN, 0);

    if (file.fd == NJT_INVALID_FILE) {
        err = njt_errno;
        if (err != NJT_ENOENT) {
            njt_conf_log_error(NJT_LOG_CRIT, cf, err,
                               njt_open_file_n " \"%s\" failed", name->data);
        }
        return NJT_DECLINED;
    }

    if (ctx->outside_entries) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
            "binary geo range base \"%s\" cannot be mixed with usual entries",
            name->data);
        rc = NJT_ERROR;
        goto done;
    }

    if (ctx->binary_include) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
            "second binary geo range base \"%s\" cannot be mixed with \"%s\"",
            name->data, ctx->include_name.data);
        rc = NJT_ERROR;
        goto done;
    }

    if (njt_fd_info(file.fd, &fi) == NJT_FILE_ERROR) {
        njt_conf_log_error(NJT_LOG_CRIT, cf, njt_errno,
                           njt_fd_info_n " \"%s\" failed", name->data);
        goto failed;
    }

    size = (size_t) njt_file_size(&fi);
    mtime = njt_file_mtime(&fi);

    ch = name->data[name->len - 4];
    name->data[name->len - 4] = '\0';

    if (njt_file_info(name->data, &fi) == NJT_FILE_ERROR) {
        njt_conf_log_error(NJT_LOG_CRIT, cf, njt_errno,
                           njt_file_info_n " \"%s\" failed", name->data);
        goto failed;
    }

    name->data[name->len - 4] = ch;

    if (mtime < njt_file_mtime(&fi)) {
        njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                           "stale binary geo range base \"%s\"", name->data);
        goto failed;
    }

    base = njt_palloc(ctx->pool, size);
    if (base == NULL) {
        goto failed;
    }

    n = njt_read_file(&file, base, size, 0);

    if (n == NJT_ERROR) {
        njt_conf_log_error(NJT_LOG_CRIT, cf, njt_errno,
                           njt_read_file_n " \"%s\" failed", name->data);
        goto failed;
    }

    if ((size_t) n != size) {
        njt_conf_log_error(NJT_LOG_CRIT, cf, 0,
            njt_read_file_n " \"%s\" returned only %z bytes instead of %z",
            name->data, n, size);
        goto failed;
    }

    header = (njt_stream_geo_header_t *) base;

    if (size < 16 || njt_memcmp(&njt_stream_geo_header, header, 12) != 0) {
        njt_conf_log_error(NJT_LOG_WARN, cf, 0,
             "incompatible binary geo range base \"%s\"", name->data);
        goto failed;
    }

    njt_crc32_init(crc32);

    vv = (njt_stream_variable_value_t *)
            (base + sizeof(njt_stream_geo_header_t));

    while (vv->data) {
        len = njt_align(sizeof(njt_stream_variable_value_t) + vv->len,
                        sizeof(void *));
        njt_crc32_update(&crc32, (u_char *) vv, len);
        vv->data += (size_t) base;
        vv = (njt_stream_variable_value_t *) ((u_char *) vv + len);
    }
    njt_crc32_update(&crc32, (u_char *) vv,
                     sizeof(njt_stream_variable_value_t));
    vv++;

    ranges = (njt_stream_geo_range_t **) vv;

    for (i = 0; i < 0x10000; i++) {
        njt_crc32_update(&crc32, (u_char *) &ranges[i], sizeof(void *));
        if (ranges[i]) {
            ranges[i] = (njt_stream_geo_range_t *)
                            ((u_char *) ranges[i] + (size_t) base);
        }
    }

    range = (njt_stream_geo_range_t *) &ranges[0x10000];

    while ((u_char *) range < base + size) {
        while (range->value) {
            njt_crc32_update(&crc32, (u_char *) range,
                             sizeof(njt_stream_geo_range_t));
            range->value = (njt_stream_variable_value_t *)
                               ((u_char *) range->value + (size_t) base);
            range++;
        }
        njt_crc32_update(&crc32, (u_char *) range, sizeof(void *));
        range = (njt_stream_geo_range_t *) ((u_char *) range + sizeof(void *));
    }

    njt_crc32_final(crc32);

    if (crc32 != header->crc32) {
        njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                  "CRC32 mismatch in binary geo range base \"%s\"", name->data);
        goto failed;
    }

    njt_conf_log_error(NJT_LOG_NOTICE, cf, 0,
                       "using binary geo range base \"%s\"", name->data);

    ctx->include_name = *name;
    ctx->binary_include = 1;
    ctx->high.low = ranges;
    rc = NJT_OK;

    goto done;

failed:

    rc = NJT_DECLINED;

done:

    if (njt_close_file(file.fd) == NJT_FILE_ERROR) {
        njt_log_error(NJT_LOG_ALERT, cf->log, njt_errno,
                      njt_close_file_n " \"%s\" failed", name->data);
    }

    return rc;
}


static void
njt_stream_geo_create_binary_base(njt_stream_geo_conf_ctx_t *ctx)
{
    u_char                                *p;
    uint32_t                               hash;
    njt_str_t                              s;
    njt_uint_t                             i;
    njt_file_mapping_t                     fm;
    njt_stream_geo_range_t                *r, *range, **ranges;
    njt_stream_geo_header_t               *header;
    njt_stream_geo_variable_value_node_t  *gvvn;

    fm.name = njt_pnalloc(ctx->temp_pool, ctx->include_name.len + 5);
    if (fm.name == NULL) {
        return;
    }

    njt_sprintf(fm.name, "%V.bin%Z", &ctx->include_name);

    fm.size = ctx->data_size;
    fm.log = ctx->pool->log;

    njt_log_error(NJT_LOG_NOTICE, fm.log, 0,
                  "creating binary geo range base \"%s\"", fm.name);

    if (njt_create_file_mapping(&fm) != NJT_OK) {
        return;
    }

    p = njt_cpymem(fm.addr, &njt_stream_geo_header,
                   sizeof(njt_stream_geo_header_t));

    p = njt_stream_geo_copy_values(fm.addr, p, ctx->rbtree.root,
                                   ctx->rbtree.sentinel);

    p += sizeof(njt_stream_variable_value_t);

    ranges = (njt_stream_geo_range_t **) p;

    p += 0x10000 * sizeof(njt_stream_geo_range_t *);

    for (i = 0; i < 0x10000; i++) {
        r = ctx->high.low[i];
        if (r == NULL) {
            continue;
        }

        range = (njt_stream_geo_range_t *) p;
        ranges[i] = (njt_stream_geo_range_t *) (p - (u_char *) fm.addr);

        do {
            s.len = r->value->len;
            s.data = r->value->data;
            hash = njt_crc32_long(s.data, s.len);
            gvvn = (njt_stream_geo_variable_value_node_t *)
                        njt_str_rbtree_lookup(&ctx->rbtree, &s, hash);

            range->value = (njt_stream_variable_value_t *) gvvn->offset;
            range->start = r->start;
            range->end = r->end;
            range++;

        } while ((++r)->value);

        range->value = NULL;

        p = (u_char *) range + sizeof(void *);
    }

    header = fm.addr;
    header->crc32 = njt_crc32_long((u_char *) fm.addr
                                       + sizeof(njt_stream_geo_header_t),
                                   fm.size - sizeof(njt_stream_geo_header_t));

    njt_close_file_mapping(&fm);
}


static u_char *
njt_stream_geo_copy_values(u_char *base, u_char *p, njt_rbtree_node_t *node,
    njt_rbtree_node_t *sentinel)
{
    njt_stream_variable_value_t           *vv;
    njt_stream_geo_variable_value_node_t  *gvvn;

    if (node == sentinel) {
        return p;
    }

    gvvn = (njt_stream_geo_variable_value_node_t *) node;
    gvvn->offset = p - base;

    vv = (njt_stream_variable_value_t *) p;
    *vv = *gvvn->value;
    p += sizeof(njt_stream_variable_value_t);
    vv->data = (u_char *) (p - base);

    p = njt_cpymem(p, gvvn->sn.str.data, gvvn->sn.str.len);

    p = njt_align_ptr(p, sizeof(void *));

    p = njt_stream_geo_copy_values(base, p, node->left, sentinel);

    return njt_stream_geo_copy_values(base, p, node->right, sentinel);
}
