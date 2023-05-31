
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 * Copyright (C), 2021-2023, TMLake(Beijing) Technology Co., Ltd.
 */


#include "njt_http_vhost_traffic_status_module.h"
#include "njt_http_vhost_traffic_status_control.h"
#include "njt_http_vhost_traffic_status_display_json.h"
#include "njt_http_vhost_traffic_status_display.h"


static void njt_http_vhost_traffic_status_node_status_all(
    njt_http_vhost_traffic_status_control_t *control);
static void njt_http_vhost_traffic_status_node_status_group(
    njt_http_vhost_traffic_status_control_t *control);
static void njt_http_vhost_traffic_status_node_status_zone(
    njt_http_vhost_traffic_status_control_t *control);

static njt_int_t njt_http_vhost_traffic_status_node_delete_get_nodes(
    njt_http_vhost_traffic_status_control_t *control,
    njt_array_t **nodes, njt_rbtree_node_t *node);
static void njt_http_vhost_traffic_status_node_delete_all(
    njt_http_vhost_traffic_status_control_t *control);
static void njt_http_vhost_traffic_status_node_delete_group(
    njt_http_vhost_traffic_status_control_t *control);
static void njt_http_vhost_traffic_status_node_delete_zone(
    njt_http_vhost_traffic_status_control_t *control);

static void njt_http_vhost_traffic_status_node_reset_all(
    njt_http_vhost_traffic_status_control_t *control,
    njt_rbtree_node_t *node);
static void njt_http_vhost_traffic_status_node_reset_group(
    njt_http_vhost_traffic_status_control_t *control,
    njt_rbtree_node_t *node);
static void njt_http_vhost_traffic_status_node_reset_zone(
    njt_http_vhost_traffic_status_control_t *control);


void
njt_http_vhost_traffic_status_node_upstream_lookup(
    njt_http_vhost_traffic_status_control_t *control,
    njt_http_upstream_server_t *usn)
{
    njt_int_t                       rc;
    njt_str_t                       key, usg, ush;
    njt_uint_t                      i, j;
    njt_http_upstream_server_t     *us;
    njt_http_upstream_srv_conf_t   *uscf, **uscfp;
    njt_http_upstream_main_conf_t  *umcf;

    umcf = njt_http_cycle_get_module_main_conf(njt_http_vtsp_cycle, njt_http_upstream_module);
    uscfp = umcf->upstreams.elts;

    key = *control->zone;

    if (control->group == NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA) {

#if njet_version > 1007001
        usn->name = key;
#endif

        usn->weight = 0;
        usn->max_fails = 0;
        usn->fail_timeout = 0;
        usn->down = 0;
        usn->backup = 0;
        control->count++;
        return;
    }

    usg = ush = key;

    rc = njt_http_vhost_traffic_status_node_position_key(&usg, 0);
    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, control->r->connection->log, 0,
                      "node_upstream_lookup::node_position_key(\"%V\", 0) group not found", &usg);
        return;
    }

    rc = njt_http_vhost_traffic_status_node_position_key(&ush, 1);
    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, control->r->connection->log, 0,
                      "node_upstream_lookup::node_position_key(\"%V\", 1) host not found", &ush);
        return;
    }

    for (i = 0; i < umcf->upstreams.nelts; i++) {
        uscf = uscfp[i];

        /* nogroups */
        if (uscf->servers == NULL && uscf->port != 0) {
            continue;
        }

        /* to avoid warning a dereference of a null pointer */
        if (uscf->servers == NULL) {
            continue;
        }

        us = uscf->servers->elts;

        if (uscf->host.len == usg.len) {
            if (njt_strncmp(uscf->host.data, usg.data, usg.len) == 0) {

                for (j = 0; j < uscf->servers->nelts; j++) {
                    if (us[j].addrs->name.len == ush.len) {
                        if (njt_strncmp(us[j].addrs->name.data, ush.data, ush.len) == 0) {
                            *usn = us[j];

#if njet_version > 1007001
                            usn->name = us[j].addrs->name;
#endif

                            control->count++;
                            break;
                        }
                    }
                }

                break;
            }
        }
    }
}


void
njt_http_vhost_traffic_status_node_control_range_set(
    njt_http_vhost_traffic_status_control_t *control)
{
    njt_uint_t  state;

    if (control->group == -1) {
        state = NJT_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_ALL;

    } else {
        state = NJT_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_ZONE;

        if (control->zone->len == 0) {
            state = NJT_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_NONE;

        } else if (control->zone->len == 1) {
            if (njt_strncmp(control->zone->data, "*", 1) == 0) {
                state = NJT_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_GROUP;
            }
        }
    }

    control->range = state;
}


static void
njt_http_vhost_traffic_status_node_status_all(
    njt_http_vhost_traffic_status_control_t *control)
{
    *control->buf = njt_http_vhost_traffic_status_display_set(control->r, *control->buf);
}


static void
njt_http_vhost_traffic_status_node_status_group(
    njt_http_vhost_traffic_status_control_t *control)
{
    u_char                               *o, *s;
    njt_str_t                             key;
    njt_rbtree_node_t                    *node;
    njt_http_vhost_traffic_status_ctx_t  *ctx;

    ctx = njt_http_get_module_main_conf(control->r, njt_http_vhost_traffic_status_module);

    node = ctx->rbtree->root;

    *control->buf = njt_sprintf(*control->buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_S);

    o = s = *control->buf;

    switch(control->group) {
    case NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO:
        *control->buf = njt_sprintf(*control->buf,
                                    NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER_S);
        s = *control->buf;
        *control->buf = njt_http_vhost_traffic_status_display_set_server(
                            control->r, *control->buf, node);
        break;

    case NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA:
        njt_str_set(&key, "::nogroups");
        *control->buf = njt_sprintf(*control->buf,
                                    NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_ARRAY_S, &key);
        s = *control->buf;
        *control->buf = njt_http_vhost_traffic_status_display_set_upstream_alone(
                            control->r, *control->buf, node);
        break;

    case NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG:
        *control->buf = njt_sprintf(*control->buf,
                                    NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_UPSTREAM_S);
        s = *control->buf;
        *control->buf = njt_http_vhost_traffic_status_display_set_upstream_group(
                            control->r, *control->buf);
        break;

#if (NJT_HTTP_CACHE)
    case NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_CC:
        *control->buf = njt_sprintf(*control->buf,
                                    NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_CACHE_S);
        s = *control->buf;
        *control->buf = njt_http_vhost_traffic_status_display_set_cache(
                            control->r, *control->buf, node);
        break;
#endif

    case NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG:
        *control->buf = njt_sprintf(*control->buf,
                                    NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_FILTER_S);
        s = *control->buf;
        *control->buf = njt_http_vhost_traffic_status_display_set_filter(
                            control->r, *control->buf, node);
        break;
    }

    if (s == *control->buf) {
        *control->buf = o;

    } else {
        (*control->buf)--;

        if (control->group == NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA) {
            *control->buf = njt_sprintf(*control->buf,
                                        NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_ARRAY_E);

        } else {
            *control->buf = njt_sprintf(*control->buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_E);
        }

        control->count++;
    }

    *control->buf = njt_sprintf(*control->buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_E);
}


static void
njt_http_vhost_traffic_status_node_status_zone(
    njt_http_vhost_traffic_status_control_t *control)
{
    u_char                                *o;
    uint32_t                               hash;
    njt_int_t                              rc;
    njt_str_t                              key, dst;
    njt_rbtree_node_t                     *node;
    njt_http_upstream_server_t             us;
    njt_http_vhost_traffic_status_ctx_t   *ctx;
    njt_http_vhost_traffic_status_node_t  *vtsn;

    ctx = njt_http_get_module_main_conf(control->r, njt_http_vhost_traffic_status_module);

    if (control->group == NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO
        && control->zone->len == 6
        && njt_strncasecmp(control->zone->data, (u_char *) "::main", 6) == 0)
    {
        *control->buf = njt_sprintf(*control->buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_S);
        *control->buf = njt_http_vhost_traffic_status_display_set_main(control->r,
                            *control->buf);
        (*control->buf)--;
         *control->buf = njt_sprintf(*control->buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_E);

        control->count++;

        return;
    }

    rc = njt_http_vhost_traffic_status_node_generate_key(control->r->pool, &key, control->zone,
                                                         control->group);
    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, control->r->connection->log, 0,
                      "node_status_zone::node_generate_key(\"%V\") failed", &key);
        return;
    }

    hash = njt_crc32_short(key.data, key.len);
    node = njt_http_vhost_traffic_status_node_lookup(ctx->rbtree, &key, hash);

    if (node == NULL) {
        return;
    }

    vtsn = njt_http_vhost_traffic_status_get_node(node);

    if (control->group != NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG
        && control->group != NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA)
    {
        *control->buf = njt_sprintf(*control->buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_S);

        o = *control->buf;

    } else {
        o = *control->buf;
    }

    dst.data = vtsn->data;
    dst.len = vtsn->len;

    switch (control->group) {

    case NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO:
        *control->buf = njt_http_vhost_traffic_status_display_set_server_node(control->r,
                            *control->buf, &key, vtsn);
        break;

    case NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA:
    case NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG:
        njt_http_vhost_traffic_status_node_upstream_lookup(control, &us);
        if (control->count) {
#if njet_version > 1007001
            *control->buf = njt_http_vhost_traffic_status_display_set_upstream_node(control->r,
                                *control->buf, &us, vtsn);
#else
            (void) njt_http_vhost_traffic_status_node_position_key(&dst, 1);
            *control->buf = njt_http_vhost_traffic_status_display_set_upstream_node(control->r,
                                *control->buf, &us, vtsn, &dst);
#endif
        }
        break;

#if (NJT_HTTP_CACHE)
    case NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_CC:
        *control->buf = njt_http_vhost_traffic_status_display_set_cache_node(control->r,
                            *control->buf, vtsn);
        break;
#endif

    case NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG:
        (void) njt_http_vhost_traffic_status_node_position_key(&dst, 2);
        *control->buf = njt_http_vhost_traffic_status_display_set_server_node(control->r,
                            *control->buf, &dst, vtsn);
        break;
    }

    if (o != *control->buf) {
        (*control->buf)--;

        if (control->group != NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG
                && control->group != NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA)
        {
            *control->buf = njt_sprintf(*control->buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_E);
        }

        control->count++;
    }
}


void
njt_http_vhost_traffic_status_node_status(
    njt_http_vhost_traffic_status_control_t *control)
{
    switch (control->range) {

    case NJT_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_ALL:
        njt_http_vhost_traffic_status_node_status_all(control);
        break;

    case NJT_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_GROUP:
        njt_http_vhost_traffic_status_node_status_group(control);
        break;

    case NJT_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_ZONE:
        njt_http_vhost_traffic_status_node_status_zone(control);
        break;
    }
}


static njt_int_t
njt_http_vhost_traffic_status_node_delete_get_nodes(
    njt_http_vhost_traffic_status_control_t *control,
    njt_array_t **nodes, njt_rbtree_node_t *node)
{
    njt_int_t                                rc;
    njt_http_vhost_traffic_status_ctx_t     *ctx;
    njt_http_vhost_traffic_status_node_t    *vtsn;
    njt_http_vhost_traffic_status_delete_t  *delete;

    ctx = njt_http_get_module_main_conf(control->r, njt_http_vhost_traffic_status_module);

    if (node != ctx->rbtree->sentinel) {
        vtsn = njt_http_vhost_traffic_status_get_node(node);

        if ((njt_int_t) vtsn->stat_upstream.type == control->group) {

            if (*nodes == NULL) {
                *nodes = njt_array_create(control->r->pool, 1,
                        sizeof(njt_http_vhost_traffic_status_delete_t));

                if (*nodes == NULL) {
                    njt_log_error(NJT_LOG_ERR, control->r->connection->log, 0,
                                  "node_delete_get_nodes::njt_array_create() failed");
                    return NJT_ERROR;
                }
            }

            delete = njt_array_push(*nodes);
            if (delete == NULL) {
                njt_log_error(NJT_LOG_ERR, control->r->connection->log, 0,
                              "node_delete_get_nodes::njt_array_push() failed");
                return NJT_ERROR;
            }

            delete->node = node;
        }

        rc = njt_http_vhost_traffic_status_node_delete_get_nodes(control, nodes, node->left);
        if (rc != NJT_OK) {
            return rc;
        }

        rc = njt_http_vhost_traffic_status_node_delete_get_nodes(control, nodes, node->right);
        if (rc != NJT_OK) {
            return rc;
        }
    }

    return NJT_OK;
}


static void
njt_http_vhost_traffic_status_node_delete_all(
    njt_http_vhost_traffic_status_control_t *control)
{
    njt_slab_pool_t                           *shpool;
    njt_rbtree_node_t                         *node, *sentinel;
    njt_http_vhost_traffic_status_ctx_t       *ctx;
    njt_http_vhost_traffic_status_loc_conf_t  *vtscf;

    ctx = njt_http_get_module_main_conf(control->r, njt_http_vhost_traffic_status_module);

    vtscf = njt_http_get_module_loc_conf(control->r, njt_http_vhost_traffic_status_module);

    node = ctx->rbtree->root;
    sentinel = ctx->rbtree->sentinel;
    shpool = (njt_slab_pool_t *) vtscf->shm_zone->shm.addr;

    njt_shrwlock_rd2wrlock(&shpool->rwlock);
    while (node != sentinel) {

        njt_rbtree_delete(ctx->rbtree, node);
        njt_slab_free_locked(shpool, node);

        control->count++;

        node = ctx->rbtree->root;
    }
    njt_shrwlock_wr2rdlock(&shpool->rwlock);
}


static void
njt_http_vhost_traffic_status_node_delete_group(
    njt_http_vhost_traffic_status_control_t *control)
{
    njt_int_t                                  rc;
    njt_uint_t                                 n, i;
    njt_array_t                               *nodes;
    njt_slab_pool_t                           *shpool;
    njt_rbtree_node_t                         *node;
    njt_http_vhost_traffic_status_ctx_t       *ctx;
    njt_http_vhost_traffic_status_delete_t    *deletes;
    njt_http_vhost_traffic_status_loc_conf_t  *vtscf;

    ctx = njt_http_get_module_main_conf(control->r, njt_http_vhost_traffic_status_module);

    vtscf = njt_http_get_module_loc_conf(control->r, njt_http_vhost_traffic_status_module);

    node = ctx->rbtree->root;
    shpool = (njt_slab_pool_t *) vtscf->shm_zone->shm.addr;

    nodes = NULL;

    rc = njt_http_vhost_traffic_status_node_delete_get_nodes(control, &nodes, node);

    /* not found */
    if (nodes == NULL) {
        return;
    }

    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, control->r->connection->log, 0,
                      "node_delete_group::node_delete_get_nodes() failed");
        return;
    }

    deletes = nodes->elts;
    n = nodes->nelts;

    njt_shrwlock_rd2wrlock(&shpool->rwlock);
    for (i = 0; i < n; i++) {
        node = deletes[i].node;

        njt_rbtree_delete(ctx->rbtree, node);
        njt_slab_free_locked(shpool, node);

        control->count++;
    }
    njt_shrwlock_wr2rdlock(&shpool->rwlock);
}


static void
njt_http_vhost_traffic_status_node_delete_zone(
    njt_http_vhost_traffic_status_control_t *control)
{
    uint32_t                                   hash;
    njt_int_t                                  rc;
    njt_str_t                                  key;
    njt_slab_pool_t                           *shpool;
    njt_rbtree_node_t                         *node;
    njt_http_vhost_traffic_status_ctx_t       *ctx;
    njt_http_vhost_traffic_status_loc_conf_t  *vtscf;

    ctx = njt_http_get_module_main_conf(control->r, njt_http_vhost_traffic_status_module);

    vtscf = njt_http_get_module_loc_conf(control->r, njt_http_vhost_traffic_status_module);

    shpool = (njt_slab_pool_t *) vtscf->shm_zone->shm.addr;

    rc = njt_http_vhost_traffic_status_node_generate_key(control->r->pool, &key, control->zone,
                                                         control->group);
    if (rc != NJT_OK) {
        return;
    }

    hash = njt_crc32_short(key.data, key.len);
    node = njt_http_vhost_traffic_status_node_lookup(ctx->rbtree, &key, hash);

    njt_shrwlock_rd2wrlock(&shpool->rwlock);
    if (node != NULL) {
        njt_rbtree_delete(ctx->rbtree, node);
        njt_slab_free_locked(shpool, node);

        control->count++;
    }
    njt_shrwlock_wr2rdlock(&shpool->rwlock);
}


void
njt_http_vhost_traffic_status_node_delete(
    njt_http_vhost_traffic_status_control_t *control)
{
    switch (control->range) {

    case NJT_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_ALL:
        njt_http_vhost_traffic_status_node_delete_all(control);
        break;

    case NJT_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_GROUP:
        njt_http_vhost_traffic_status_node_delete_group(control);
        break;

    case NJT_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_ZONE:
        njt_http_vhost_traffic_status_node_delete_zone(control);
        break;
    }

    *control->buf = njt_sprintf(*control->buf,
                                NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_CONTROL,
                                njt_http_vhost_traffic_status_boolean_to_string(1),
                                control->arg_cmd, control->arg_group,
                                control->arg_zone, control->count);
}


static void
njt_http_vhost_traffic_status_node_reset_all(
    njt_http_vhost_traffic_status_control_t *control,
    njt_rbtree_node_t *node)
{
    njt_http_vhost_traffic_status_ctx_t   *ctx;
    njt_http_vhost_traffic_status_node_t  *vtsn;

    ctx = njt_http_get_module_main_conf(control->r, njt_http_vhost_traffic_status_module);

    if (node != ctx->rbtree->sentinel) {
        vtsn = njt_http_vhost_traffic_status_get_node(node);

        njt_http_vhost_traffic_status_nodes_zero(vtsn);
        control->count++;

        njt_http_vhost_traffic_status_node_reset_all(control, node->left);
        njt_http_vhost_traffic_status_node_reset_all(control, node->right);
    }
}


static void
njt_http_vhost_traffic_status_node_reset_group(
    njt_http_vhost_traffic_status_control_t *control,
    njt_rbtree_node_t *node)
{
    njt_http_vhost_traffic_status_ctx_t   *ctx;
    njt_http_vhost_traffic_status_node_t  *vtsn;

    ctx = njt_http_get_module_main_conf(control->r, njt_http_vhost_traffic_status_module);

    if (node != ctx->rbtree->sentinel) {
        vtsn = njt_http_vhost_traffic_status_get_node(node);

        if ((njt_int_t) vtsn->stat_upstream.type == control->group) {
            njt_http_vhost_traffic_status_nodes_zero(vtsn);
            control->count++;
        }

        njt_http_vhost_traffic_status_node_reset_group(control, node->left);
        njt_http_vhost_traffic_status_node_reset_group(control, node->right);
    }
}


static void
njt_http_vhost_traffic_status_node_reset_zone(
    njt_http_vhost_traffic_status_control_t *control)
{
    uint32_t                               hash;
    njt_int_t                              rc;
    njt_str_t                              key;
    njt_rbtree_node_t                     *node;
    njt_http_vhost_traffic_status_ctx_t   *ctx;
    njt_http_vhost_traffic_status_node_t  *vtsn;

    ctx = njt_http_get_module_main_conf(control->r, njt_http_vhost_traffic_status_module);

    rc = njt_http_vhost_traffic_status_node_generate_key(control->r->pool, &key, control->zone,
                                                         control->group);
    if (rc != NJT_OK) {
        return;
    }

    hash = njt_crc32_short(key.data, key.len);
    node = njt_http_vhost_traffic_status_node_lookup(ctx->rbtree, &key, hash);

    if (node != NULL) {
        vtsn = njt_http_vhost_traffic_status_get_node(node);
        njt_http_vhost_traffic_status_nodes_zero(vtsn);
        control->count++;
    }
}


void
njt_http_vhost_traffic_status_node_reset(
    njt_http_vhost_traffic_status_control_t *control)
{
    njt_rbtree_node_t                    *node;
    njt_http_vhost_traffic_status_ctx_t  *ctx;

    ctx = njt_http_get_module_main_conf(control->r, njt_http_vhost_traffic_status_module);

    node = ctx->rbtree->root;

    switch (control->range) {

    case NJT_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_ALL:
        njt_http_vhost_traffic_status_node_reset_all(control, node);
        break;

    case NJT_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_GROUP:
        njt_http_vhost_traffic_status_node_reset_group(control, node);
        break;

    case NJT_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_ZONE:
        njt_http_vhost_traffic_status_node_reset_zone(control);
        break;
    }

    *control->buf = njt_sprintf(*control->buf,
                                NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_CONTROL,
                                njt_http_vhost_traffic_status_boolean_to_string(1),
                                control->arg_cmd, control->arg_group,
                                control->arg_zone, control->count);
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
