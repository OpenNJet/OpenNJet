
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#include <njt_config.h>

#include "njt_http_stream_server_traffic_status_module.h"
#include "njt_http_stream_server_traffic_status_shm.h"


void
njt_http_stream_server_traffic_status_shm_info_node(njt_http_request_t *r,
    njt_http_stream_server_traffic_status_shm_info_t *shm_info,
    njt_rbtree_node_t *node)
{
    njt_uint_t                                     size;
    njt_http_stream_server_traffic_status_ctx_t   *ctx;
    njt_http_stream_server_traffic_status_node_t  *stsn;

    ctx = njt_http_get_module_main_conf(r, njt_stream_stsd_module);

    if (node != ctx->rbtree->sentinel) {
        stsn = (njt_http_stream_server_traffic_status_node_t *) &node->color;

        size = offsetof(njt_rbtree_node_t, color)
               + offsetof(njt_http_stream_server_traffic_status_node_t, data)
               + stsn->len;

        shm_info->used_size += size;
        shm_info->used_node++;

        njt_http_stream_server_traffic_status_shm_info_node(r, shm_info, node->left);
        njt_http_stream_server_traffic_status_shm_info_node(r, shm_info, node->right);
    }
}


void
njt_http_stream_server_traffic_status_shm_info(njt_http_request_t *r,
    njt_http_stream_server_traffic_status_shm_info_t *shm_info)
{
    njt_http_stream_server_traffic_status_ctx_t  *ctx;

    ctx = njt_http_get_module_main_conf(r, njt_stream_stsd_module);

    njt_memzero(shm_info, sizeof(njt_http_stream_server_traffic_status_shm_info_t));

    shm_info->name = &ctx->shm_name;
    shm_info->max_size = ctx->shm_size;

    njt_http_stream_server_traffic_status_shm_info_node(r, shm_info, ctx->rbtree->root);
}


njt_int_t
njt_http_stream_server_traffic_status_shm_init(njt_http_request_t *r)
{
    njt_shm_zone_t                                    *shm_zone;
    njt_http_stream_server_traffic_status_ctx_t       *ctx, *sctx;
    njt_http_stream_server_traffic_status_loc_conf_t  *stscf;

    ctx = njt_http_get_module_main_conf(r, njt_stream_stsd_module);

    stscf = njt_http_get_module_loc_conf(r, njt_stream_stsd_module);

    shm_zone = njt_http_stream_server_traffic_status_shm_find_zone(r, &ctx->shm_name);
    if (shm_zone == NULL) {
        return NJT_ERROR;
    }

    sctx = shm_zone->data;

    stscf->shm_zone = shm_zone;
    ctx->rbtree = sctx->rbtree;
    ctx->filter_keys = sctx->filter_keys;
    ctx->limit_traffics = sctx->limit_traffics;
    ctx->limit_filter_traffics = sctx->limit_filter_traffics;
    ctx->shm_size = sctx->shm_size;
    ctx->upstream = sctx->upstream;

    return NJT_OK;
}


njt_shm_zone_t *
njt_http_stream_server_traffic_status_shm_find_zone(njt_http_request_t *r, njt_str_t *name)
{
    njt_uint_t                 i;
    njt_str_t                 *shm_name;
    njt_shm_zone_t            *shm_zone;
    volatile njt_list_part_t  *part;
    njt_cycle_t                *cycle;

    if (njet_master_cycle) {
        cycle = njet_master_cycle;
    } else {
        cycle = (njt_cycle_t *)njt_cycle;
    }
    part = &cycle->shared_memory.part;
    shm_zone = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            shm_zone = part->elts;
            i = 0;
        }

        if (name->len != shm_zone[i].shm.name.len) {
            continue;
        }

        shm_name = &shm_zone[i].shm.name;

        njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http stream sts shm_find_zone(): shm_name[%V], name[%V]",
                       shm_name, name);

        if (njt_strncmp(name->data, shm_name->data, name->len) == 0) {
            return &shm_zone[i];
        }
    }

    return NULL;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
