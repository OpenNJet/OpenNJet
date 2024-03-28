
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#include <njt_config.h>

#include "njt_stream_server_traffic_status_module.h"
#include "njt_stream_server_traffic_status_filter.h"
#include "njt_stream_server_traffic_status_limit.h"


njt_int_t
njt_stream_server_traffic_status_limit_handler(njt_stream_session_t *s)
{
    njt_int_t                                 rc;
    njt_stream_server_traffic_status_ctx_t   *ctx;
    njt_stream_server_traffic_status_conf_t  *stscf;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream sts limit handler");

    ctx = njt_stream_get_module_main_conf(s, njt_stream_stsc_module);

    stscf = njt_stream_get_module_srv_conf(s, njt_stream_stsc_module);

    if (!stscf->limit) {
        return NJT_DECLINED;
    }

    /* limit traffic of server */
    rc = njt_stream_server_traffic_status_limit_handler_traffic(s, ctx->limit_traffics);
    if (rc != NJT_DECLINED) {
        return rc;
    }

    rc = njt_stream_server_traffic_status_limit_handler_traffic(s, stscf->limit_traffics);
    if (rc != NJT_DECLINED) {
        return rc;
    }

    /* limit traffic of filter */
    rc = njt_stream_server_traffic_status_limit_handler_traffic(s, ctx->limit_filter_traffics);
    if (rc != NJT_DECLINED) {
        return rc;
    }

    rc = njt_stream_server_traffic_status_limit_handler_traffic(s, stscf->limit_filter_traffics);
    if (rc != NJT_DECLINED) {
        return rc;
    }

    return NJT_DECLINED;
}


njt_int_t
njt_stream_server_traffic_status_limit_handler_traffic(njt_stream_session_t *s,
    njt_array_t *traffics)
{
    unsigned                                   type;
    njt_str_t                                  variable, key, dst;
    njt_int_t                                  rc;
    njt_uint_t                                 i, n;
    njt_atomic_t                               traffic_used;
    njt_slab_pool_t                           *shpool;
    njt_rbtree_node_t                         *node;
    njt_stream_server_traffic_status_node_t   *stsn;
    njt_stream_server_traffic_status_limit_t  *limits;
    njt_stream_server_traffic_status_conf_t   *stscf;

    stscf = njt_stream_get_module_srv_conf(s, njt_stream_stsc_module);

    rc = NJT_DECLINED;

    if (traffics == NULL) {
        return rc;
    }

    shpool = (njt_slab_pool_t *) stscf->shm_zone->shm.addr;

    njt_shmtx_lock(&shpool->mutex);

    limits = traffics->elts;
    n = traffics->nelts;

    for (i = 0; i < n; i++) {
        if (limits[i].variable.value.len <= 0) {
            continue;
        }

        /* init */
        traffic_used = 0;
        variable.len = 0;
        key.len = 0;
        dst.len = 0;
        type = limits[i].type;

        if (njt_stream_complex_value(s, &limits[i].variable, &variable) != NJT_OK) {
            goto done;
        }

        if (variable.len == 0) {
            continue;
        }

        /* traffic of filter */
        if (limits[i].key.value.len > 0) {
            if (njt_stream_complex_value(s, &limits[i].key, &key) != NJT_OK) {
                goto done;
            }

            if (key.len == 0) {
                continue;
            }

            node = njt_stream_server_traffic_status_find_node(s, &key, type, 0);

            if (node == NULL) {
                continue;
            }

            stscf->node_caches[type] = node;

            stsn = (njt_stream_server_traffic_status_node_t *) &node->color;

            traffic_used = (njt_atomic_t) njt_stream_server_traffic_status_node_member(stsn, &variable);

        /* traffic of server */
        } else {
            njt_stream_server_traffic_status_find_name(s, &dst);

            if (njt_stream_server_traffic_status_node_generate_key(s->connection->pool, &key, &dst, type)
                != NJT_OK || key.len == 0)
            {
                goto done;
            }

            node = njt_stream_server_traffic_status_find_node(s, &key, type, 0);

            if (node == NULL) {
                continue;
            }

            stscf->node_caches[type] = node;

            stsn = (njt_stream_server_traffic_status_node_t *) &node->color;

            traffic_used = (njt_atomic_t) njt_stream_server_traffic_status_node_member(stsn, &variable);
        }

        if (traffic_used > limits[i].size) {
            rc = limits[i].code;
            goto done;
        }
    }

done:

    njt_shmtx_unlock(&shpool->mutex);

    return rc;
}


char *
njt_stream_server_traffic_status_limit_traffic(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    njt_stream_server_traffic_status_conf_t *stscf = conf;

    u_char                                    *p;
    off_t                                      size;
    njt_str_t                                 *value, s;
    njt_array_t                               *limit_traffics;
    njt_stream_compile_complex_value_t         ccv;
    njt_stream_server_traffic_status_ctx_t    *ctx;
    njt_stream_server_traffic_status_limit_t  *traffic;

    ctx = njt_stream_conf_get_module_main_conf(cf, njt_stream_stsc_module);
    if (ctx == NULL) {
        return NJT_CONF_ERROR;
    }

    value = cf->args->elts;
    if (value[1].len == 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "limit_traffic() empty value pattern");
        return NJT_CONF_ERROR;
    }

    if (value[1].len > 5 && njt_strstrn(value[1].data, "$sts_", 5 - 1)) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "limit_traffic() $sts_* is not allowed here");
        return NJT_CONF_ERROR;
    }

    p = (u_char *) njt_strchr(value[1].data, ':');
    if (p == NULL) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "limit_traffic() empty size pattern");
        return NJT_CONF_ERROR;
    }

    s.data = p + 1;
    s.len = value[1].data + value[1].len - s.data;

    size = njt_parse_offset(&s);
    if (size == NJT_ERROR) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "limit_traffic() invalid limit size \"%V\"", &value[1]);
        return NJT_CONF_ERROR;
    }

    limit_traffics = (cf->cmd_type == NJT_STREAM_MAIN_CONF)
                     ? ctx->limit_traffics
                     : stscf->limit_traffics;
    if (limit_traffics == NULL) {
        limit_traffics = njt_array_create(cf->pool, 1,
                                          sizeof(njt_stream_server_traffic_status_limit_t));
        if (limit_traffics == NULL) {
            return NJT_CONF_ERROR;
        }
    }

    traffic = njt_array_push(limit_traffics);
    if (traffic == NULL) {
        return NJT_CONF_ERROR;
    }

    value[1].len = p - value[1].data;

    njt_memzero(&ccv, sizeof(njt_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &traffic->variable;

    if (njt_stream_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    traffic->size = (njt_atomic_t) size;

    traffic->code = (cf->args->nelts == 3)
                    ? (njt_uint_t) njt_atoi(value[2].data, value[2].len)
                    : NJT_STREAM_SERVICE_UNAVAILABLE;

    traffic->type = NJT_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_NO;

    traffic->key.value.len = 0;

    if (cf->cmd_type == NJT_STREAM_MAIN_CONF) {
        ctx->limit_traffics = limit_traffics;

    } else {
        stscf->limit_traffics = limit_traffics;
    }

    return NJT_CONF_OK;
}


char *
njt_stream_server_traffic_status_limit_traffic_by_set_key(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    njt_stream_server_traffic_status_conf_t *stscf = conf;

    u_char                                    *p;
    off_t                                      size;
    njt_str_t                                 *value, s, alpha;
    njt_array_t                               *limit_traffics;
    njt_stream_compile_complex_value_t         ccv;
    njt_stream_server_traffic_status_ctx_t    *ctx;
    njt_stream_server_traffic_status_limit_t  *traffic;

    ctx = njt_stream_conf_get_module_main_conf(cf, njt_stream_stsc_module);
    if (ctx == NULL) {
        return NJT_CONF_ERROR;
    }

    value = cf->args->elts;
    if (value[1].len == 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "limit_traffic_by_set_key() empty key pattern");
        return NJT_CONF_ERROR;
    }

    if (value[2].len == 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "limit_traffic_by_set_key() empty value pattern");
        return NJT_CONF_ERROR;
    }

    if (value[2].len > 5 && njt_strstrn(value[2].data, "$sts_", 5 - 1)) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "limit_traffic_by_set_key() $sts_* is not allowed here");
        return NJT_CONF_ERROR;
    }

    p = (u_char *) njt_strchr(value[2].data, ':');
    if (p == NULL) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "limit_traffic_by_set_key() empty size pattern");
        return NJT_CONF_ERROR;
    }

    s.data = p + 1;
    s.len = value[2].data + value[2].len - s.data;

    size = njt_parse_offset(&s);
    if (size == NJT_ERROR) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "limit_traffic_by_set_key() invalid limit size \"%V\"", &value[2]);
        return NJT_CONF_ERROR;
    }

    limit_traffics = (cf->cmd_type == NJT_STREAM_MAIN_CONF)
                     ? ctx->limit_filter_traffics
                     : stscf->limit_filter_traffics;
    if (limit_traffics == NULL) {
        limit_traffics = njt_array_create(cf->pool, 1,
                                          sizeof(njt_stream_server_traffic_status_limit_t));
        if (limit_traffics == NULL) {
            return NJT_CONF_ERROR;
        }
    }

    traffic = njt_array_push(limit_traffics);
    if (traffic == NULL) {
        return NJT_CONF_ERROR;
    }

    /* set key to be limited */
    njt_memzero(&ccv, sizeof(njt_stream_compile_complex_value_t));

    (void) njt_stream_server_traffic_status_replace_chrc(&value[1], '@',
               NJT_STREAM_SERVER_TRAFFIC_STATUS_KEY_SEPARATOR);
    njt_str_set(&alpha, "[:alpha:]");
    if (njt_stream_server_traffic_status_replace_strc(&value[1], &alpha, '@') != NJT_OK) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "limit_traffic_by_set_key()::replace_strc() failed");
    }

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &traffic->key;

    if (njt_stream_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    /* set member to be limited */
    value[2].len = p - value[2].data;

    njt_memzero(&ccv, sizeof(njt_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &traffic->variable;

    if (njt_stream_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    traffic->size = (njt_atomic_t) size;

    traffic->code = (cf->args->nelts == 4)
                    ? (njt_uint_t) njt_atoi(value[3].data, value[3].len)
                    : NJT_STREAM_SERVICE_UNAVAILABLE;

    traffic->type = njt_stream_server_traffic_status_string_to_group(value[1].data);

    if (cf->cmd_type == NJT_STREAM_MAIN_CONF) {
        ctx->limit_filter_traffics = limit_traffics;

    } else {
        stscf->limit_filter_traffics = limit_traffics;
    }

    return NJT_CONF_OK;
}


njt_int_t
njt_stream_server_traffic_status_limit_traffic_unique(njt_pool_t *pool, njt_array_t **keys)
{
    uint32_t                                         hash;
    u_char                                          *p;
    njt_str_t                                        key;
    njt_uint_t                                       i, n;
    njt_array_t                                     *uniqs, *traffic_keys;
    njt_stream_server_traffic_status_limit_t        *traffic, *traffics;
    njt_stream_server_traffic_status_filter_uniq_t  *traffic_uniqs;

    if (*keys == NULL) {
        return NJT_OK;
    }

    uniqs = njt_array_create(pool, 1,
                             sizeof(njt_stream_server_traffic_status_filter_uniq_t));
    if (uniqs == NULL) {
        return NJT_ERROR;
    }

    /* init array */
    traffic_keys = NULL;
    traffic_uniqs = NULL;

    traffics = (*keys)->elts;
    n = (*keys)->nelts;

    for (i = 0; i < n; i++) {
        key.len = traffics[i].key.value.len
                  + traffics[i].variable.value.len;
        key.data = njt_pcalloc(pool, key.len);
        if (key.data == NULL) {
            return NJT_ERROR;
        }

        p = key.data;
        p = njt_cpymem(p, traffics[i].key.value.data,
                       traffics[i].key.value.len);
        njt_memcpy(p, traffics[i].variable.value.data,
                   traffics[i].variable.value.len);
        hash = njt_crc32_short(key.data, key.len);

        traffic_uniqs = njt_array_push(uniqs);
        if (traffic_uniqs == NULL) {
            return NJT_ERROR;
        }

        traffic_uniqs->hash = hash;
        traffic_uniqs->index = i;

        if (p != NULL) {
            njt_pfree(pool, key.data);
        }
    }

    traffic_uniqs = uniqs->elts;
    n = uniqs->nelts;

    njt_qsort(traffic_uniqs, (size_t) n,
              sizeof(njt_stream_server_traffic_status_filter_uniq_t),
              njt_stream_server_traffic_status_filter_cmp_hashs);

    hash = 0;
    for (i = 0; i < n; i++) {
        if (traffic_uniqs[i].hash == hash) {
            continue;
        }

        hash = traffic_uniqs[i].hash;

        if (traffic_keys == NULL) {
            traffic_keys = njt_array_create(pool, 1,
                                            sizeof(njt_stream_server_traffic_status_limit_t));
            if (traffic_keys == NULL) {
                return NJT_ERROR;
            }
        }

        traffic = njt_array_push(traffic_keys);
        if (traffic == NULL) {
            return NJT_ERROR;
        }

        njt_memcpy(traffic, &traffics[traffic_uniqs[i].index],
                   sizeof(njt_stream_server_traffic_status_limit_t));

    }

    if ((*keys)->nelts != traffic_keys->nelts) {
        *keys = traffic_keys;
    }

    return NJT_OK;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
