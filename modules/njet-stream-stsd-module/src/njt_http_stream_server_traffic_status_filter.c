
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#include <njt_config.h>

#include "njt_http_stream_server_traffic_status_module.h"
#include "njt_http_stream_server_traffic_status_filter.h"


int njt_libc_cdecl
njt_http_stream_server_traffic_status_filter_cmp_keys(const void *one, const void *two)
{
    njt_http_stream_server_traffic_status_filter_key_t *first =
                            (njt_http_stream_server_traffic_status_filter_key_t *) one;
    njt_http_stream_server_traffic_status_filter_key_t *second =
                            (njt_http_stream_server_traffic_status_filter_key_t *) two;

    return (int) njt_strcmp(first->key.data, second->key.data);
}


njt_int_t
njt_http_stream_server_traffic_status_filter_get_keys(njt_http_request_t *r,
    njt_array_t **filter_keys, njt_rbtree_node_t *node)
{
    njt_int_t                                            rc;
    njt_str_t                                            key;
    njt_http_stream_server_traffic_status_ctx_t         *ctx;
    njt_http_stream_server_traffic_status_node_t        *stsn;
    njt_http_stream_server_traffic_status_filter_key_t  *keys;

    ctx = njt_http_get_module_main_conf(r, njt_stream_stsd_module);

    if (node != ctx->rbtree->sentinel) {
        stsn = (njt_http_stream_server_traffic_status_node_t *) &node->color;

        if (stsn->stat_upstream.type == NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_FG) {
            key.data = stsn->data;
            key.len = stsn->len;

            rc = njt_http_stream_server_traffic_status_node_position_key(&key, 1);
            if (rc != NJT_OK) {
                goto next;
            }

            if (*filter_keys == NULL) {
                *filter_keys = njt_array_create(r->pool, 1,
                                  sizeof(njt_http_stream_server_traffic_status_filter_key_t));

                if (*filter_keys == NULL) {
                    njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                                  "filter_get_keys::njt_array_create() failed");
                    return NJT_ERROR;
                }
            }

            keys = njt_array_push(*filter_keys);
            if (keys == NULL) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "filter_get_keys::njt_array_push() failed");
                return NJT_ERROR;
            }

            keys->key.len = key.len;
            /* 1 byte for terminating '\0' for njt_strcmp() */
            keys->key.data = njt_pcalloc(r->pool, key.len + 1);
            if (keys->key.data == NULL) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "filter_get_keys::njt_pcalloc() failed");
            }

            njt_memcpy(keys->key.data, key.data, key.len);
        }
next:
        rc = njt_http_stream_server_traffic_status_filter_get_keys(r, filter_keys, node->left);
        if (rc != NJT_OK) {
            return rc;
        }

        rc = njt_http_stream_server_traffic_status_filter_get_keys(r, filter_keys, node->right);
        if (rc != NJT_OK) {
            return rc;
        }
    }

    return NJT_OK;
}


njt_int_t
njt_http_stream_server_traffic_status_filter_get_nodes(njt_http_request_t *r,
    njt_array_t **filter_nodes, njt_str_t *name,
    njt_rbtree_node_t *node)
{
    njt_int_t                                             rc;
    njt_str_t                                             key;
    njt_http_stream_server_traffic_status_ctx_t          *ctx;
    njt_http_stream_server_traffic_status_node_t         *stsn;
    njt_http_stream_server_traffic_status_filter_node_t  *nodes;

    ctx = njt_http_get_module_main_conf(r, njt_stream_stsd_module);

    if (node != ctx->rbtree->sentinel) {
        stsn = (njt_http_stream_server_traffic_status_node_t *) &node->color;

        if (stsn->stat_upstream.type == NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_FG) {
            key.data = stsn->data;
            key.len = stsn->len;

            rc = njt_http_stream_server_traffic_status_node_position_key(&key, 1);
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
                *filter_nodes = njt_array_create(r->pool, 1,
                                    sizeof(njt_http_stream_server_traffic_status_filter_node_t));

                if (*filter_nodes == NULL) {
                    njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                                  "filter_get_nodes::njt_array_create() failed");
                    return NJT_ERROR;
                }
            }

            nodes = njt_array_push(*filter_nodes);
            if (nodes == NULL) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "filter_get_nodes::njt_array_push() failed");
                return NJT_ERROR;
            }

            nodes->node = stsn;
        }
next:
        rc = njt_http_stream_server_traffic_status_filter_get_nodes(r, filter_nodes, name,
                                                                    node->left);
        if (rc != NJT_OK) {
            return rc;
        }

        rc = njt_http_stream_server_traffic_status_filter_get_nodes(r, filter_nodes, name,
                                                                    node->right);
        if (rc != NJT_OK) {
            return rc;
        }
    }

    return NJT_OK;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
