
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#include <njt_config.h>

#include "njt_stream_server_traffic_status_module.h"
#include "njt_stream_server_traffic_status_filter.h"


int njt_libc_cdecl
njt_stream_server_traffic_status_filter_cmp_hashs(const void *one, const void *two)
{
    njt_stream_server_traffic_status_filter_uniq_t *first =
                           (njt_stream_server_traffic_status_filter_uniq_t *) one;
    njt_stream_server_traffic_status_filter_uniq_t *second =
                           (njt_stream_server_traffic_status_filter_uniq_t *) two;

    return (first->hash - second->hash);
}


int njt_libc_cdecl
njt_stream_server_traffic_status_filter_cmp_keys(const void *one, const void *two)
{
    njt_stream_server_traffic_status_filter_key_t *first =
                            (njt_stream_server_traffic_status_filter_key_t *) one;
    njt_stream_server_traffic_status_filter_key_t *second =
                            (njt_stream_server_traffic_status_filter_key_t *) two;

    return (int) njt_strcmp(first->key.data, second->key.data);
}


njt_int_t
njt_stream_server_traffic_status_filter_unique(njt_pool_t *pool, njt_array_t **keys)
{
    uint32_t                                         hash;
    u_char                                          *p;
    njt_str_t                                        key;
    njt_uint_t                                       i, n;
    njt_array_t                                     *uniqs, *filter_keys;
    njt_stream_server_traffic_status_filter_t       *filter, *filters;
    njt_stream_server_traffic_status_filter_uniq_t  *filter_uniqs;

    if (*keys == NULL) {
        return NJT_OK;
    }

    uniqs = njt_array_create(pool, 1,
                             sizeof(njt_stream_server_traffic_status_filter_uniq_t));
    if (uniqs == NULL) {
        return NJT_ERROR;
    }

    /* init array */
    filter_keys = NULL;
    filter_uniqs = NULL;

    filters = (*keys)->elts;
    n = (*keys)->nelts;

    for (i = 0; i < n; i++) {
        key.len = filters[i].filter_key.value.len
                  + filters[i].filter_name.value.len;
        key.data = njt_pcalloc(pool, key.len);
        if (key.data == NULL) {
            return NJT_ERROR;
        }

        p = key.data;
        p = njt_cpymem(p, filters[i].filter_key.value.data,
                       filters[i].filter_key.value.len);
        njt_memcpy(p, filters[i].filter_name.value.data,
                   filters[i].filter_name.value.len);
        hash = njt_crc32_short(key.data, key.len);

        filter_uniqs = njt_array_push(uniqs);
        if (filter_uniqs == NULL) {
            return NJT_ERROR;
        }

        filter_uniqs->hash = hash;
        filter_uniqs->index = i;

        if (p != NULL) {
            njt_pfree(pool, key.data);
        }
    }

    filter_uniqs = uniqs->elts;
    n = uniqs->nelts;

    njt_qsort(filter_uniqs, (size_t) n,
              sizeof(njt_stream_server_traffic_status_filter_uniq_t),
              njt_stream_server_traffic_status_filter_cmp_hashs);

    hash = 0;
    for (i = 0; i < n; i++) {
        if (filter_uniqs[i].hash == hash) {
            continue;
        }

        hash = filter_uniqs[i].hash;

        if (filter_keys == NULL) {
            filter_keys = njt_array_create(pool, 1,
                                           sizeof(njt_stream_server_traffic_status_filter_t));
            if (filter_keys == NULL) {
                return NJT_ERROR;
            }
        }

        filter = njt_array_push(filter_keys);
        if (filter == NULL) {
            return NJT_ERROR;
        }

        njt_memcpy(filter, &filters[filter_uniqs[i].index],
                   sizeof(njt_stream_server_traffic_status_filter_t));

    }

    if ((*keys)->nelts != filter_keys->nelts) {
        *keys = filter_keys;
    }

    return NJT_OK;
}


njt_int_t
njt_stream_server_traffic_status_filter_get_keys(njt_stream_session_t *s,
    njt_array_t **filter_keys, njt_rbtree_node_t *node)
{
    njt_int_t                                       rc;
    njt_str_t                                       key;
    njt_stream_server_traffic_status_ctx_t         *ctx;
    njt_stream_server_traffic_status_node_t        *stsn;
    njt_stream_server_traffic_status_filter_key_t  *keys;

    ctx = njt_stream_get_module_main_conf(s, njt_stream_stsc_module);

    if (node != ctx->rbtree->sentinel) {
        stsn = (njt_stream_server_traffic_status_node_t *) &node->color;

        if (stsn->stat_upstream.type == NJT_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_FG) {
            key.data = stsn->data;
            key.len = stsn->len;

            rc = njt_stream_server_traffic_status_node_position_key(&key, 1);
            if (rc != NJT_OK) {
                goto next;
            }

            if (*filter_keys == NULL) {
                *filter_keys = njt_array_create(s->connection->pool, 1,
                                   sizeof(njt_stream_server_traffic_status_filter_key_t));

                if (*filter_keys == NULL) {
                    njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                                  "filter_get_keys::njt_array_create() failed");
                    return NJT_ERROR;
                }
            }

            keys = njt_array_push(*filter_keys);
            if (keys == NULL) {
                njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                              "filter_get_keys::njt_array_push() failed");
                return NJT_ERROR;
            }

            keys->key.len = key.len;
            /* 1 byte for terminating '\0' for njt_strcmp() */
            keys->key.data = njt_pcalloc(s->connection->pool, key.len + 1);
            if (keys->key.data == NULL) {
                njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                              "filter_get_keys::njt_pcalloc() failed");
            }

            njt_memcpy(keys->key.data, key.data, key.len);
        }
next:
        rc = njt_stream_server_traffic_status_filter_get_keys(s, filter_keys, node->left);
        if (rc != NJT_OK) {
            return rc;
        }

        rc = njt_stream_server_traffic_status_filter_get_keys(s, filter_keys, node->right);
        if (rc != NJT_OK) {
            return rc;
        }
    }

    return NJT_OK;
}


njt_int_t
njt_stream_server_traffic_status_filter_get_nodes(njt_stream_session_t *s,
    njt_array_t **filter_nodes, njt_str_t *name,
    njt_rbtree_node_t *node)
{
    njt_int_t                                        rc;
    njt_str_t                                        key;
    njt_stream_server_traffic_status_ctx_t          *ctx;
    njt_stream_server_traffic_status_node_t         *stsn;
    njt_stream_server_traffic_status_filter_node_t  *nodes;

    ctx = njt_stream_get_module_main_conf(s, njt_stream_stsc_module);

    if (node != ctx->rbtree->sentinel) {
        stsn = (njt_stream_server_traffic_status_node_t *) &node->color;

        if (stsn->stat_upstream.type == NJT_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_FG) {
            key.data = stsn->data;
            key.len = stsn->len;

            rc = njt_stream_server_traffic_status_node_position_key(&key, 1);
            if (rc != NJT_OK) {
                goto next;
            }

            if (name->len != key.len) {
                goto next;
            }

            if (njt_strncmp(name->data, key.data, key.len) != 0) {
                goto next;
            }

            if (*filter_nodes == NULL) {
                *filter_nodes = njt_array_create(s->connection->pool, 1,
                                    sizeof(njt_stream_server_traffic_status_filter_node_t));

                if (*filter_nodes == NULL) {
                    njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                                  "filter_get_nodes::njt_array_create() failed");
                    return NJT_ERROR;
                }
            }

            nodes = njt_array_push(*filter_nodes);
            if (nodes == NULL) {
                njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                              "filter_get_nodes::njt_array_push() failed");
                return NJT_ERROR;
            }

            nodes->node = stsn;
        }
next:
        rc = njt_stream_server_traffic_status_filter_get_nodes(s, filter_nodes, name, node->left);
        if (rc != NJT_OK) {
            return rc;
        }

        rc = njt_stream_server_traffic_status_filter_get_nodes(s, filter_nodes, name, node->right);
        if (rc != NJT_OK) {
            return rc;
        }
    }

    return NJT_OK;
}


char *
njt_stream_server_traffic_status_filter_by_set_key(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    njt_stream_server_traffic_status_conf_t *stscf = conf;

    njt_str_t                                  *value, name;
    njt_array_t                                *filter_keys;
    njt_stream_compile_complex_value_t          ccv;
    njt_stream_server_traffic_status_ctx_t     *ctx;
    njt_stream_server_traffic_status_filter_t  *filter;

    ctx = njt_stream_conf_get_module_main_conf(cf, njt_stream_stsc_module);
    if (ctx == NULL) {
        return NJT_CONF_ERROR;
    }

    value = cf->args->elts;
    if (value[1].len == 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "empty key pattern");
        return NJT_CONF_ERROR;
    }

    filter_keys = (cf->cmd_type == NJT_STREAM_MAIN_CONF) ? ctx->filter_keys : stscf->filter_keys;
    if (filter_keys == NULL) {
        filter_keys = njt_array_create(cf->pool, 1,
                                       sizeof(njt_stream_server_traffic_status_filter_t));
        if (filter_keys == NULL) {
            return NJT_CONF_ERROR;
        }
    }

    filter = njt_array_push(filter_keys);
    if (filter == NULL) {
        return NJT_CONF_ERROR;
    }

    /* first argument process */
    njt_memzero(&ccv, sizeof(njt_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &filter->filter_key;

    if (njt_stream_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    /* second argument process */
    if (cf->args->nelts == 3) {
        name = value[2];

    } else {
        njt_str_set(&name, "");
    }

    njt_memzero(&ccv, sizeof(njt_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &name;
    ccv.complex_value = &filter->filter_name;

    if (njt_stream_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    if (cf->cmd_type == NJT_STREAM_MAIN_CONF) {
        ctx->filter_keys = filter_keys;

    } else {
        stscf->filter_keys = filter_keys;
    }

    return NJT_CONF_OK;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
