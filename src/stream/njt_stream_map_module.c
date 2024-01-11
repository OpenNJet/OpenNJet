
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>
#include <njt_stream_dyn_module.h>

static int njt_libc_cdecl njt_stream_map_cmp_dns_wildcards(const void *one,
    const void *two);
static void *njt_stream_map_create_conf(njt_conf_t *cf);
static char *njt_stream_map_block(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_stream_map(njt_conf_t *cf, njt_command_t *dummy, void *conf);
static njt_int_t njt_stream_map_init_worker(njt_cycle_t *cycle);
static void njt_stream_map_exit_worker(njt_cycle_t *cycle);

static njt_command_t  njt_stream_map_commands[] = {

    { njt_string("map"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_BLOCK|NJT_CONF_TAKE2,
      njt_stream_map_block,
      NJT_STREAM_MAIN_CONF_OFFSET,
      0,
      NULL },

    { njt_string("map_hash_max_size"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_STREAM_MAIN_CONF_OFFSET,
      offsetof(njt_stream_map_conf_t, hash_max_size),
      NULL },

    { njt_string("map_hash_bucket_size"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_STREAM_MAIN_CONF_OFFSET,
      offsetof(njt_stream_map_conf_t, hash_bucket_size),
      NULL },

      njt_null_command
};


static njt_stream_module_t  njt_stream_map_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    njt_stream_map_create_conf,            /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL                                   /* merge server configuration */
};


njt_module_t  njt_stream_map_module = {
    NJT_MODULE_V1,
    &njt_stream_map_module_ctx,            /* module context */
    njt_stream_map_commands,               /* module directives */
    NJT_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    njt_stream_map_init_worker,            /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    njt_stream_map_exit_worker,            /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};

static njt_int_t njt_stream_map_init_worker(njt_cycle_t *cycle)
{
#if NJT_STREAM_DYN_MAP_MODULE
    njt_uint_t i;
    njt_stream_map_conf_t *mcf;
    mcf = njt_stream_cycle_get_module_main_conf(cycle, njt_stream_map_module);
    if (mcf == NULL) {
        return NJT_OK;
    }
    njt_stream_map_var_hash_t *item = mcf->var_hash_items->elts;
    njt_stream_map_var_hash_t *old_var_hash_item;
    for (i = 0;i < mcf->var_hash_items->nelts;i++) {
        njt_lvlhsh_map_put(&mcf->var_hash, &item[i].name, (intptr_t)&item[i], (intptr_t *)&old_var_hash_item);
    }
    return NJT_OK;
#else 
    return NJT_OK;
#endif
}

static void njt_stream_map_exit_worker(njt_cycle_t *cycle)
{
#if NJT_STREAM_DYN_MAP_MODULE
    njt_uint_t i;
    njt_stream_map_conf_t *mcf;
    mcf = njt_stream_cycle_get_module_main_conf(cycle, njt_stream_map_module);
    if (mcf == NULL) {
        return;
    }
    njt_stream_map_var_hash_t *item = mcf->var_hash_items->elts;
    for (i = 0;i < mcf->var_hash_items->nelts;i++) {
        njt_lvlhsh_map_remove(&mcf->var_hash, &item[i].name);
    }
#endif
}


static njt_int_t
njt_stream_map_variable(njt_stream_session_t *s, njt_stream_variable_value_t *v,
    uintptr_t data)
{
    njt_stream_map_ctx_t  *map = (njt_stream_map_ctx_t *) data;

    njt_str_t                     val, str;
    njt_stream_complex_value_t   *cv;
    njt_stream_variable_value_t  *value;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream map started");

    if (njt_stream_complex_value(s, &map->value, &val) != NJT_OK) {
        return NJT_ERROR;
    }

    if (map->hostnames && val.len > 0 && val.data[val.len - 1] == '.') {
        val.len--;
    }

    value = njt_stream_map_find(s, &map->map, &val);

    if (value == NULL) {
        value = map->default_value;
    }

    if (!value->valid) {
        cv = (njt_stream_complex_value_t *) value->data;

        if (njt_stream_complex_value(s, cv, &str) != NJT_OK) {
            return NJT_ERROR;
        }

        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->len = str.len;
        v->data = str.data;

    } else {
        *v = *value;
    }

    njt_log_debug2(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream map: \"%V\" \"%v\"", &val, v);

    return NJT_OK;
}


static void *
njt_stream_map_create_conf(njt_conf_t *cf)
{
    njt_stream_map_conf_t  *mcf;

    mcf = njt_pcalloc(cf->pool, sizeof(njt_stream_map_conf_t));
    if (mcf == NULL) {
        return NULL;
    }

    mcf->hash_max_size = NJT_CONF_UNSET_UINT;
    mcf->hash_bucket_size = NJT_CONF_UNSET_UINT;
#if NJT_STREAM_DYN_MAP_MODULE
    mcf->var_hash_items = njt_array_create(cf->pool, 4, sizeof(njt_stream_map_var_hash_t));
    if (mcf->var_hash_items == NULL) {
        return NULL;
    }
#endif

    return mcf;
}

njt_int_t
njt_stream_map_create_hash_from_ctx(njt_stream_map_conf_t *mcf, njt_stream_map_ctx_t *map, njt_stream_map_conf_ctx_t *p_ctx, njt_pool_t *pool, njt_pool_t *temp_pool)
{
    njt_hash_init_t                    hash;
    njt_stream_map_conf_ctx_t  ctx = *p_ctx;
    map->default_value = ctx.default_value ? ctx.default_value:
                                             &njt_stream_variable_null_value;

    map->hostnames = ctx.hostnames;

    hash.key = njt_hash_key_lc;
    hash.max_size = mcf->hash_max_size;
    hash.bucket_size = mcf->hash_bucket_size;
    hash.name = "map_hash";
    hash.pool = pool;

    if (ctx.keys.keys.nelts) {
        hash.hash = &map->map.hash.hash;
        hash.temp_pool = NULL;

        if (njt_hash_init(&hash, ctx.keys.keys.elts, ctx.keys.keys.nelts)
            != NJT_OK)
        {
            njt_destroy_pool(pool);
            return NJT_ERROR;
        }
    }

    if (ctx.keys.dns_wc_head.nelts) {

        njt_qsort(ctx.keys.dns_wc_head.elts,
                  (size_t) ctx.keys.dns_wc_head.nelts,
                  sizeof(njt_hash_key_t), njt_stream_map_cmp_dns_wildcards);

        hash.hash = NULL;
        hash.temp_pool = pool;

        if (njt_hash_wildcard_init(&hash, ctx.keys.dns_wc_head.elts,
                                   ctx.keys.dns_wc_head.nelts)
            != NJT_OK)
        {
            njt_destroy_pool(pool);
            return NJT_ERROR;
        }

        map->map.hash.wc_head = (njt_hash_wildcard_t *) hash.hash;
    }

    if (ctx.keys.dns_wc_tail.nelts) {

        njt_qsort(ctx.keys.dns_wc_tail.elts,
                  (size_t) ctx.keys.dns_wc_tail.nelts,
                  sizeof(njt_hash_key_t), njt_stream_map_cmp_dns_wildcards);

        hash.hash = NULL;
        hash.temp_pool = pool;

        if (njt_hash_wildcard_init(&hash, ctx.keys.dns_wc_tail.elts,
                                   ctx.keys.dns_wc_tail.nelts)
            != NJT_OK)
        {
            njt_destroy_pool(pool);
            return NJT_ERROR;
        }

        map->map.hash.wc_tail = (njt_hash_wildcard_t *) hash.hash;
    }

#if (NJT_PCRE)
    if (ctx.regexes.nelts) {
        map->map.regex = ctx.regexes.elts;
        map->map.nregex = ctx.regexes.nelts;
    }
#endif

    return NJT_OK;
}

static char *
njt_stream_map_block(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_stream_map_conf_t  *mcf = conf;

    char                                *rv;
    njt_str_t                           *value, name;
    njt_conf_t                           save;
    njt_pool_t                          *pool;
    njt_stream_map_ctx_t                *map;
    njt_stream_variable_t               *var;
    njt_stream_map_conf_ctx_t            ctx;
    njt_stream_compile_complex_value_t   ccv;
    njt_int_t rc;

    if (mcf->hash_max_size == NJT_CONF_UNSET_UINT) {
        mcf->hash_max_size = 2048;
    }

    if (mcf->hash_bucket_size == NJT_CONF_UNSET_UINT) {
        mcf->hash_bucket_size = njt_cacheline_size;

    } else {
        mcf->hash_bucket_size = njt_align(mcf->hash_bucket_size,
                                          njt_cacheline_size);
    }

    map = njt_pcalloc(cf->pool, sizeof(njt_stream_map_ctx_t));
    if (map == NULL) {
        return NJT_CONF_ERROR;
    }

    value = cf->args->elts;

    njt_memzero(&ccv, sizeof(njt_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &map->value;

    if (njt_stream_compile_complex_value(&ccv) != NJT_OK) {
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

    var = njt_stream_add_variable(cf, &name, NJT_STREAM_VAR_CHANGEABLE);
    if (var == NULL) {
        return NJT_CONF_ERROR;
    }

    var->get_handler = njt_stream_map_variable;
    var->data = (uintptr_t) map;

    pool = njt_create_pool(NJT_DEFAULT_POOL_SIZE, cf->log);
    if (pool == NULL) {
        return NJT_CONF_ERROR;
    }

    ctx.keys.pool = cf->pool;
    ctx.keys.temp_pool = pool;
#if NJT_STREAM_DYN_MAP_MODULE
    ctx.ori_conf = njt_array_create(cf->pool, 10, sizeof(njt_stream_map_ori_conf_item_t));
    if (ctx.ori_conf == NULL) {
        njt_conf_log_error(NJT_LOG_ERR, cf, 0, "malloc error in stream map for ctx.ori_conf ");
        return NJT_CONF_ERROR;
    }
#endif

    if (njt_hash_keys_array_init(&ctx.keys, NJT_HASH_LARGE) != NJT_OK) {
        njt_destroy_pool(pool);
        return NJT_CONF_ERROR;
    }

    ctx.values_hash = njt_pcalloc(pool, sizeof(njt_array_t) * ctx.keys.hsize);
    if (ctx.values_hash == NULL) {
        njt_destroy_pool(pool);
        return NJT_CONF_ERROR;
    }

#if (NJT_PCRE)
    if (njt_array_init(&ctx.regexes, cf->pool, 2,
                       sizeof(njt_stream_map_regex_t))
        != NJT_OK)
    {
        njt_destroy_pool(pool);
        return NJT_CONF_ERROR;
    }
#endif

    ctx.default_value = NULL;
    ctx.cf = &save;
    ctx.hostnames = 0;
    ctx.no_cacheable = 0;

    save = *cf;
    cf->pool = pool;
    cf->ctx = &ctx;
    cf->handler = njt_stream_map;
    cf->handler_conf = conf;

    rv = njt_conf_parse(cf, NULL);

    *cf = save;

    if (rv != NJT_CONF_OK) {
        njt_destroy_pool(pool);
        return rv;
    }

    if (ctx.no_cacheable) {
        var->flags |= NJT_STREAM_VAR_NOCACHEABLE;
    }

    rc = njt_stream_map_create_hash_from_ctx(mcf, map, &ctx, cf->pool, pool);
    if (rc != NJT_OK) {
        rv = NJT_CONF_ERROR;
    }


#if NJT_STREAM_DYN_MAP_MODULE
    njt_stream_map_var_hash_t *var_hash_item = njt_array_push(mcf->var_hash_items);
    if (var_hash_item == NULL) {
        njt_conf_log_error(NJT_LOG_ERR, cf, 0, "malloc error in stream map for njt_stream_map_var_hash_t ");
        return NJT_CONF_ERROR;
    }

    var_hash_item->name.data = njt_pstrdup(cf->pool, &name);
    if (var_hash_item->name.data == NULL) {
        njt_conf_log_error(NJT_LOG_ERR, cf, 0, "malloc error in stream map for njt_stream_map_var_hash_t.name ");
        return NJT_CONF_ERROR;
    }
    var_hash_item->name.len = name.len;
    var_hash_item->map = map;
    var_hash_item->ori_conf = ctx.ori_conf;
    var_hash_item->dynamic = 0;;

#endif

    njt_destroy_pool(pool);

    return rv;
}


static int njt_libc_cdecl
njt_stream_map_cmp_dns_wildcards(const void *one, const void *two)
{
    njt_hash_key_t  *first, *second;

    first = (njt_hash_key_t *) one;
    second = (njt_hash_key_t *) two;

    return njt_dns_strcmp(first->key.data, second->key.data);
}


static char *
njt_stream_map(njt_conf_t *cf, njt_command_t *dummy, void *conf)
{
    u_char                              *data;
    size_t                               len;
    njt_int_t                            rv;
    njt_str_t                           *value, v;
    njt_uint_t                           i, key;
    njt_stream_map_conf_ctx_t           *ctx;
    njt_stream_complex_value_t           cv, *cvp;
    njt_stream_variable_value_t         *var, **vp;
    njt_stream_compile_complex_value_t   ccv;

    ctx = cf->ctx;

    value = cf->args->elts;

    if (cf->args->nelts == 1
        && njt_strcmp(value[0].data, "hostnames") == 0)
    {
        ctx->hostnames = 1;
        return NJT_CONF_OK;
    }

    if (cf->args->nelts == 1
        && njt_strcmp(value[0].data, "volatile") == 0)
    {
        ctx->no_cacheable = 1;
        return NJT_CONF_OK;
    }

    if (cf->args->nelts != 2) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid number of the map parameters");
        return NJT_CONF_ERROR;
    }

#if NJT_STREAM_DYN_MAP_MODULE
    njt_stream_map_ori_conf_item_t *ori_conf_item = (njt_stream_map_ori_conf_item_t *)njt_array_push(ctx->ori_conf);
    if (ori_conf_item == NULL) {
        njt_conf_log_error(NJT_LOG_ERR, cf, 0,
            "can't create ori_conf_item in njt_stream_map");
        return NJT_CONF_ERROR;
    }
    ori_conf_item->v_from.len = value[0].len;
    ori_conf_item->v_from.data = njt_pstrdup(ctx->keys.pool, &value[0]);
    ori_conf_item->v_to.len = value[1].len;
    ori_conf_item->v_to.data = njt_pstrdup(ctx->keys.pool, &value[1]);
#endif

    if (njt_strcmp(value[0].data, "include") == 0) {
        return njt_conf_include(cf, dummy, conf);
    }

    key = 0;

    for (i = 0; i < value[1].len; i++) {
        key = njt_hash(key, value[1].data[i]);
    }

    key %= ctx->keys.hsize;

    vp = ctx->values_hash[key].elts;

    if (vp) {
        for (i = 0; i < ctx->values_hash[key].nelts; i++) {

            if (vp[i]->valid) {
                data = vp[i]->data;
                len = vp[i]->len;

            } else {
                cvp = (njt_stream_complex_value_t *) vp[i]->data;
                data = cvp->value.data;
                len = cvp->value.len;
            }

            if (value[1].len != len) {
                continue;
            }

            if (njt_strncmp(value[1].data, data, len) == 0) {
                var = vp[i];
                goto found;
            }
        }

    } else {
        if (njt_array_init(&ctx->values_hash[key], cf->pool, 4,
                           sizeof(njt_stream_variable_value_t *))
            != NJT_OK)
        {
            return NJT_CONF_ERROR;
        }
    }

    var = njt_palloc(ctx->keys.pool, sizeof(njt_stream_variable_value_t));
    if (var == NULL) {
        return NJT_CONF_ERROR;
    }

    v.len = value[1].len;
    v.data = njt_pstrdup(ctx->keys.pool, &value[1]);
    if (v.data == NULL) {
        return NJT_CONF_ERROR;
    }

    njt_memzero(&ccv, sizeof(njt_stream_compile_complex_value_t));

    ccv.cf = ctx->cf;
    ccv.value = &v;
    ccv.complex_value = &cv;

    if (njt_stream_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    if (cv.lengths != NULL) {
        cvp = njt_palloc(ctx->keys.pool, sizeof(njt_stream_complex_value_t));
        if (cvp == NULL) {
            return NJT_CONF_ERROR;
        }

        *cvp = cv;

        var->len = 0;
        var->data = (u_char *) cvp;
        var->valid = 0;

    } else {
        var->len = v.len;
        var->data = v.data;
        var->valid = 1;
    }

    var->no_cacheable = 0;
    var->not_found = 0;

    vp = njt_array_push(&ctx->values_hash[key]);
    if (vp == NULL) {
        return NJT_CONF_ERROR;
    }

    *vp = var;

found:

    if (njt_strcmp(value[0].data, "default") == 0) {

        if (ctx->default_value) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "duplicate default map parameter");
            return NJT_CONF_ERROR;
        }

        ctx->default_value = var;

        return NJT_CONF_OK;
    }

#if (NJT_PCRE)

    if (value[0].len && value[0].data[0] == '~') {
        njt_regex_compile_t      rc;
        njt_stream_map_regex_t  *regex;
        u_char                   errstr[NJT_MAX_CONF_ERRSTR];

        regex = njt_array_push(&ctx->regexes);
        if (regex == NULL) {
            return NJT_CONF_ERROR;
        }

        value[0].len--;
        value[0].data++;

        njt_memzero(&rc, sizeof(njt_regex_compile_t));

        if (value[0].data[0] == '*') {
            value[0].len--;
            value[0].data++;
            rc.options = NJT_REGEX_CASELESS;
        }

        rc.pattern = value[0];
        rc.err.len = NJT_MAX_CONF_ERRSTR;
        rc.err.data = errstr;

        regex->regex = njt_stream_regex_compile(ctx->cf, &rc);
        if (regex->regex == NULL) {
            return NJT_CONF_ERROR;
        }

        regex->value = var;

        return NJT_CONF_OK;
    }

#endif

    if (value[0].len && value[0].data[0] == '\\') {
        value[0].len--;
        value[0].data++;
    }

    rv = njt_hash_add_key(&ctx->keys, &value[0], var,
                          (ctx->hostnames) ? NJT_HASH_WILDCARD_KEY : 0);

    if (rv == NJT_OK) {
        return NJT_CONF_OK;
    }

    if (rv == NJT_DECLINED) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid hostname or wildcard \"%V\"", &value[0]);
    }

    if (rv == NJT_BUSY) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "conflicting parameter \"%V\"", &value[0]);
    }

    return NJT_CONF_ERROR;
}
