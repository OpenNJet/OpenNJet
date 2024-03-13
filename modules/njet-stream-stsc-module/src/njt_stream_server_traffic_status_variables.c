
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#include <njt_config.h>

#include "njt_stream_server_traffic_status_module.h"
#include "njt_stream_server_traffic_status_variables.h"


static njt_stream_variable_t  njt_stream_server_traffic_status_vars[] = {

    { njt_string("sts_connect_counter"), NULL,
      njt_stream_server_traffic_status_node_variable,
      offsetof(njt_stream_server_traffic_status_node_t, stat_connect_counter),
      NJT_STREAM_VAR_NOCACHEABLE, 0 },

    { njt_string("sts_in_bytes"), NULL,
      njt_stream_server_traffic_status_node_variable,
      offsetof(njt_stream_server_traffic_status_node_t, stat_in_bytes),
      NJT_STREAM_VAR_NOCACHEABLE, 0 },

    { njt_string("sts_out_bytes"), NULL,
      njt_stream_server_traffic_status_node_variable,
      offsetof(njt_stream_server_traffic_status_node_t, stat_out_bytes),
      NJT_STREAM_VAR_NOCACHEABLE, 0 },

    { njt_string("sts_1xx_counter"), NULL,
      njt_stream_server_traffic_status_node_variable,
      offsetof(njt_stream_server_traffic_status_node_t, stat_1xx_counter),
      NJT_STREAM_VAR_NOCACHEABLE, 0 },

    { njt_string("sts_2xx_counter"), NULL,
      njt_stream_server_traffic_status_node_variable,
      offsetof(njt_stream_server_traffic_status_node_t, stat_2xx_counter),
      NJT_STREAM_VAR_NOCACHEABLE, 0 },

    { njt_string("sts_3xx_counter"), NULL,
      njt_stream_server_traffic_status_node_variable,
      offsetof(njt_stream_server_traffic_status_node_t, stat_3xx_counter),
      NJT_STREAM_VAR_NOCACHEABLE, 0 },

    { njt_string("sts_4xx_counter"), NULL,
      njt_stream_server_traffic_status_node_variable,
      offsetof(njt_stream_server_traffic_status_node_t, stat_4xx_counter),
      NJT_STREAM_VAR_NOCACHEABLE, 0 },

    { njt_string("sts_5xx_counter"), NULL,
      njt_stream_server_traffic_status_node_variable,
      offsetof(njt_stream_server_traffic_status_node_t, stat_5xx_counter),
      NJT_STREAM_VAR_NOCACHEABLE, 0 },

    { njt_string("sts_session_time"), NULL,
      njt_stream_server_traffic_status_node_variable,
      offsetof(njt_stream_server_traffic_status_node_t, stat_session_time),
      NJT_STREAM_VAR_NOCACHEABLE, 0 },

    { njt_null_string, NULL, NULL, 0, 0, 0 }
};


njt_int_t
njt_stream_server_traffic_status_node_variable(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    u_char                                   *p;
    unsigned                                  type;
    njt_int_t                                 rc;
    njt_str_t                                 key, dst;
    njt_slab_pool_t                          *shpool;
    njt_rbtree_node_t                        *node;
    njt_stream_server_traffic_status_node_t  *stsn;
    njt_stream_server_traffic_status_conf_t  *stscf;

    stscf = njt_stream_get_module_srv_conf(s, njt_stream_stsc_module);

    rc = njt_stream_server_traffic_status_find_name(s, &dst);
    if (rc != NJT_OK) {
        return NJT_ERROR;
    }

    type = NJT_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_NO;

    rc = njt_stream_server_traffic_status_node_generate_key(s->connection->pool, &key, &dst, type);
    if (rc != NJT_OK) {
        return NJT_ERROR;
    }

    if (key.len == 0) {
        return NJT_ERROR;
    }

    shpool = (njt_slab_pool_t *) stscf->shm_zone->shm.addr;

    njt_shmtx_lock(&shpool->mutex);

    node = njt_stream_server_traffic_status_find_node(s, &key, type, 0);

    if (node == NULL) {
        goto not_found;
    }

    p = njt_pnalloc(s->connection->pool, NJT_ATOMIC_T_LEN);
    if (p == NULL) {
        goto not_found;
    }

    stsn = (njt_stream_server_traffic_status_node_t *) &node->color;

    v->len = njt_sprintf(p, "%uA", *((njt_atomic_t *) ((char *) stsn + data))) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    goto done;

not_found:

    v->not_found = 1;

done:

    stscf->node_caches[type] = node;

    njt_shmtx_unlock(&shpool->mutex);

    return NJT_OK;
}


njt_int_t
njt_stream_server_traffic_status_add_variables(njt_conf_t *cf)
{
    njt_stream_variable_t  *var, *v;
    
    for (v = njt_stream_server_traffic_status_vars; v->name.len; v++) {
        var = njt_stream_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NJT_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NJT_OK;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
