
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 * Copyright (C), 2021-2023, TMLake(Beijing) Technology Co., Ltd.
 */


#include "njt_http_vhost_traffic_status_module.h"
#include "njt_http_vhost_traffic_status_variables.h"


static njt_http_variable_t  njt_http_vhost_traffic_status_vars[] = {

    { njt_string("vts_request_counter"), NULL,
      njt_http_vhost_traffic_status_node_variable,
      offsetof(njt_http_vhost_traffic_status_node_t, stat_request_counter),
      NJT_HTTP_VAR_NOCACHEABLE, 0 , NJT_VAR_INIT_REF_COUNT },

    { njt_string("vts_in_bytes"), NULL,
      njt_http_vhost_traffic_status_node_variable,
      offsetof(njt_http_vhost_traffic_status_node_t, stat_in_bytes),
      NJT_HTTP_VAR_NOCACHEABLE, 0 , NJT_VAR_INIT_REF_COUNT },

    { njt_string("vts_out_bytes"), NULL,
      njt_http_vhost_traffic_status_node_variable,
      offsetof(njt_http_vhost_traffic_status_node_t, stat_out_bytes),
      NJT_HTTP_VAR_NOCACHEABLE, 0 , NJT_VAR_INIT_REF_COUNT },

    { njt_string("vts_1xx_counter"), NULL,
      njt_http_vhost_traffic_status_node_variable,
      offsetof(njt_http_vhost_traffic_status_node_t, stat_1xx_counter),
      NJT_HTTP_VAR_NOCACHEABLE, 0 , NJT_VAR_INIT_REF_COUNT },

    { njt_string("vts_2xx_counter"), NULL,
      njt_http_vhost_traffic_status_node_variable,
      offsetof(njt_http_vhost_traffic_status_node_t, stat_2xx_counter),
      NJT_HTTP_VAR_NOCACHEABLE, 0 , NJT_VAR_INIT_REF_COUNT },

    { njt_string("vts_3xx_counter"), NULL,
      njt_http_vhost_traffic_status_node_variable,
      offsetof(njt_http_vhost_traffic_status_node_t, stat_3xx_counter),
      NJT_HTTP_VAR_NOCACHEABLE, 0 , NJT_VAR_INIT_REF_COUNT },

    { njt_string("vts_4xx_counter"), NULL,
      njt_http_vhost_traffic_status_node_variable,
      offsetof(njt_http_vhost_traffic_status_node_t, stat_4xx_counter),
      NJT_HTTP_VAR_NOCACHEABLE, 0 , NJT_VAR_INIT_REF_COUNT },

    { njt_string("vts_5xx_counter"), NULL,
      njt_http_vhost_traffic_status_node_variable,
      offsetof(njt_http_vhost_traffic_status_node_t, stat_5xx_counter),
      NJT_HTTP_VAR_NOCACHEABLE, 0 , NJT_VAR_INIT_REF_COUNT },

    { njt_string("vts_request_time_counter"), NULL,
      njt_http_vhost_traffic_status_node_variable,
      offsetof(njt_http_vhost_traffic_status_node_t, stat_request_time_counter),
      NJT_HTTP_VAR_NOCACHEABLE, 0 , NJT_VAR_INIT_REF_COUNT },

    { njt_string("vts_request_time"), NULL,
      njt_http_vhost_traffic_status_node_variable,
      offsetof(njt_http_vhost_traffic_status_node_t, stat_request_time),
      NJT_HTTP_VAR_NOCACHEABLE, 0 , NJT_VAR_INIT_REF_COUNT },

#if (NJT_HTTP_CACHE)
    { njt_string("vts_cache_miss_counter"), NULL,
      njt_http_vhost_traffic_status_node_variable,
      offsetof(njt_http_vhost_traffic_status_node_t, stat_cache_miss_counter),
      NJT_HTTP_VAR_NOCACHEABLE, 0 , NJT_VAR_INIT_REF_COUNT },

    { njt_string("vts_cache_bypass_counter"), NULL,
      njt_http_vhost_traffic_status_node_variable,
      offsetof(njt_http_vhost_traffic_status_node_t, stat_cache_bypass_counter),
      NJT_HTTP_VAR_NOCACHEABLE, 0 , NJT_VAR_INIT_REF_COUNT },

    { njt_string("vts_cache_expired_counter"), NULL,
      njt_http_vhost_traffic_status_node_variable,
      offsetof(njt_http_vhost_traffic_status_node_t, stat_cache_expired_counter),
      NJT_HTTP_VAR_NOCACHEABLE, 0 , NJT_VAR_INIT_REF_COUNT },

    { njt_string("vts_cache_stale_counter"), NULL,
      njt_http_vhost_traffic_status_node_variable,
      offsetof(njt_http_vhost_traffic_status_node_t, stat_cache_stale_counter),
      NJT_HTTP_VAR_NOCACHEABLE, 0 , NJT_VAR_INIT_REF_COUNT },

    { njt_string("vts_cache_updating_counter"), NULL,
      njt_http_vhost_traffic_status_node_variable,
      offsetof(njt_http_vhost_traffic_status_node_t, stat_cache_updating_counter),
      NJT_HTTP_VAR_NOCACHEABLE, 0 , NJT_VAR_INIT_REF_COUNT },

    { njt_string("vts_cache_revalidated_counter"), NULL,
      njt_http_vhost_traffic_status_node_variable,
      offsetof(njt_http_vhost_traffic_status_node_t, stat_cache_revalidated_counter),
      NJT_HTTP_VAR_NOCACHEABLE, 0 , NJT_VAR_INIT_REF_COUNT },

    { njt_string("vts_cache_hit_counter"), NULL,
      njt_http_vhost_traffic_status_node_variable,
      offsetof(njt_http_vhost_traffic_status_node_t, stat_cache_hit_counter),
      NJT_HTTP_VAR_NOCACHEABLE, 0 , NJT_VAR_INIT_REF_COUNT },

    { njt_string("vts_cache_scarce_counter"), NULL,
      njt_http_vhost_traffic_status_node_variable,
      offsetof(njt_http_vhost_traffic_status_node_t, stat_cache_scarce_counter),
      NJT_HTTP_VAR_NOCACHEABLE, 0 , NJT_VAR_INIT_REF_COUNT },
#endif

      njt_http_null_variable
};


njt_int_t
njt_http_vhost_traffic_status_node_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    u_char                                    *p;
    unsigned                                   type;
    njt_int_t                                  rc;
    njt_str_t                                  key, dst;
    njt_slab_pool_t                           *shpool;
    njt_rbtree_node_t                         *node;
    njt_http_vhost_traffic_status_node_t      *vtsn;
    njt_http_vhost_traffic_status_loc_conf_t  *vtscf;

    vtscf = njt_http_get_module_loc_conf(r, njt_http_vhost_traffic_status_module);

    njt_http_vhost_traffic_status_find_name(r, &dst);

    type = NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO;

    rc = njt_http_vhost_traffic_status_node_generate_key(r->pool, &key, &dst, type);
    if (rc != NJT_OK) {
        return NJT_ERROR;
    }

    if (key.len == 0) {
        return NJT_ERROR;
    }

    shpool = (njt_slab_pool_t *) vtscf->shm_zone->shm.addr;

    njt_shrwlock_rdlock(&shpool->rwlock);

    node = njt_http_vhost_traffic_status_find_node(r, &key, type, 0);

    if (node == NULL) {
        goto not_found;
    }

    p = njt_pnalloc(r->pool, NJT_ATOMIC_T_LEN);
    if (p == NULL) {
        goto not_found;
    }

    vtsn = njt_http_vhost_traffic_status_get_node(node);

    v->len = njt_sprintf(p, "%uA", *((njt_atomic_t *) ((char *) vtsn + data))) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    goto done;

not_found:

    v->not_found = 1;

done:

    vtscf->node_caches[type] = node;

    njt_shrwlock_unlock(&shpool->rwlock);

    return NJT_OK;
}


njt_int_t
njt_http_vhost_traffic_status_add_variables(njt_conf_t *cf)
{
    njt_http_variable_t  *var, *v;

    for (v = njt_http_vhost_traffic_status_vars; v->name.len; v++) {
        var = njt_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NJT_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NJT_OK;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
