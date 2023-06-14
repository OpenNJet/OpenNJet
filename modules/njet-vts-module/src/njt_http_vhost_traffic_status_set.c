
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 * Copyright (C), 2021-2023, TMLake(Beijing) Technology Co., Ltd.
 */


#include "njt_http_vhost_traffic_status_module.h"
#include "njt_http_vhost_traffic_status_control.h"
#include "njt_http_vhost_traffic_status_set.h"


static njt_int_t njt_http_vhost_traffic_status_set_init(njt_http_request_t *r,
    njt_http_vhost_traffic_status_control_t *control);

static njt_atomic_uint_t njt_http_vhost_traffic_status_set_by_filter_node_member(
    njt_http_vhost_traffic_status_control_t *control,
    njt_http_vhost_traffic_status_node_t *vtsn,
    njt_http_upstream_server_t *us);
static njt_int_t njt_http_vhost_traffic_status_set_by_filter_init(
    njt_http_vhost_traffic_status_control_t *control, njt_str_t *uri);
static njt_int_t njt_http_vhost_traffic_status_set_by_filter_node(
    njt_http_vhost_traffic_status_control_t *control, njt_str_t *buf);
static njt_int_t njt_http_vhost_traffic_status_set_by_filter_variable(
    njt_http_request_t *r, njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_vhost_traffic_status_set_by_filter_variables(
    njt_http_request_t *r);


njt_int_t
njt_http_vhost_traffic_status_set_handler(njt_http_request_t *r)
{
    njt_int_t                                  rc;
    njt_http_vhost_traffic_status_ctx_t       *ctx;
    njt_http_vhost_traffic_status_loc_conf_t  *vtscf;

    ctx = njt_http_get_module_main_conf(r, njt_http_vhost_traffic_status_module);

    vtscf = njt_http_get_module_loc_conf(r, njt_http_vhost_traffic_status_module);

    if (!ctx->enable || !vtscf->filter) {
        return NJT_DECLINED;
    }

    rc = njt_http_vhost_traffic_status_set_by_filter_variables(r);
    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "set_handler::set_by_filter_variables() failed");
    }

    return NJT_DECLINED;
}


static njt_int_t
njt_http_vhost_traffic_status_set_init(njt_http_request_t *r,
    njt_http_vhost_traffic_status_control_t *control)
{
    control->r = r;
    control->command = NJT_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_CMD_NONE;
    control->group = -2;
    control->zone = njt_pcalloc(r->pool, sizeof(njt_str_t));
    control->arg_group = njt_pcalloc(r->pool, sizeof(njt_str_t));
    control->arg_zone = njt_pcalloc(r->pool, sizeof(njt_str_t));
    control->arg_name = njt_pcalloc(r->pool, sizeof(njt_str_t));
    control->range = NJT_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_NONE;
    control->count = 0;

    if (control->zone == NULL || control->arg_group == NULL
        || control->arg_zone == NULL || control->arg_name == NULL)
    {
        return NJT_ERROR;
    }

    return NJT_OK;
}


static njt_atomic_uint_t
njt_http_vhost_traffic_status_set_by_filter_node_member(
    njt_http_vhost_traffic_status_control_t *control,
    njt_http_vhost_traffic_status_node_t *vtsn,
    njt_http_upstream_server_t *us)
{
    njt_str_t  *member;

    member = control->arg_name;

    if (njt_http_vhost_traffic_status_node_member_cmp(member, "requestCounter") == 0)
    {
        return vtsn->stat_request_counter;
    }
    else if (njt_http_vhost_traffic_status_node_member_cmp(member, "requestMsecCounter") == 0)
    {
        return vtsn->stat_request_time_counter;
    }
    else if (njt_http_vhost_traffic_status_node_member_cmp(member, "requestMsec") == 0)
    {
        return vtsn->stat_request_time;
    }
    else if (njt_http_vhost_traffic_status_node_member_cmp(member, "responseMsecCounter") == 0)
    {
        return vtsn->stat_upstream.response_time_counter;
    }
    else if (njt_http_vhost_traffic_status_node_member_cmp(member, "responseMsec") == 0)
    {
        return vtsn->stat_upstream.response_time;
    }
    else if (njt_http_vhost_traffic_status_node_member_cmp(member, "inBytes") == 0)
    {
        return vtsn->stat_in_bytes;
    }
    else if (njt_http_vhost_traffic_status_node_member_cmp(member, "outBytes") == 0)
    {
        return vtsn->stat_out_bytes;
    }
    else if (njt_http_vhost_traffic_status_node_member_cmp(member, "1xx") == 0)
    {
        return vtsn->stat_1xx_counter;
    }
    else if (njt_http_vhost_traffic_status_node_member_cmp(member, "2xx") == 0)
    {
        return vtsn->stat_2xx_counter;
    }
    else if (njt_http_vhost_traffic_status_node_member_cmp(member, "3xx") == 0)
    {
        return vtsn->stat_3xx_counter;
    }
    else if (njt_http_vhost_traffic_status_node_member_cmp(member, "4xx") == 0)
    {
        return vtsn->stat_4xx_counter;
    }
    else if (njt_http_vhost_traffic_status_node_member_cmp(member, "5xx") == 0)
    {
        return vtsn->stat_5xx_counter;
    }

#if (NJT_HTTP_CACHE)
    else if (njt_http_vhost_traffic_status_node_member_cmp(member, "cacheMaxSize") == 0)
    {
        return vtsn->stat_cache_max_size;
    }
    else if (njt_http_vhost_traffic_status_node_member_cmp(member, "cacheUsedSize") == 0)
    {
        return vtsn->stat_cache_used_size;
    }
    else if (njt_http_vhost_traffic_status_node_member_cmp(member, "cacheMiss") == 0)
    {
        return vtsn->stat_cache_miss_counter;
    }
    else if (njt_http_vhost_traffic_status_node_member_cmp(member, "cacheBypass") == 0)
    {
        return vtsn->stat_cache_bypass_counter;
    }
    else if (njt_http_vhost_traffic_status_node_member_cmp(member, "cacheExpired") == 0)
    {
        return vtsn->stat_cache_expired_counter;
    }
    else if (njt_http_vhost_traffic_status_node_member_cmp(member, "cacheStale") == 0)
    {
        return vtsn->stat_cache_stale_counter;
    }
    else if (njt_http_vhost_traffic_status_node_member_cmp(member, "cacheUpdating") == 0)
    {
        return vtsn->stat_cache_updating_counter;
    }
    else if (njt_http_vhost_traffic_status_node_member_cmp(member, "cacheRevalidated") == 0)
    {
        return vtsn->stat_cache_revalidated_counter;
    }
    else if (njt_http_vhost_traffic_status_node_member_cmp(member, "cacheHit") == 0)
    {
        return vtsn->stat_cache_hit_counter;
    }
    else if (njt_http_vhost_traffic_status_node_member_cmp(member, "cacheScarce") == 0)
    {
        return vtsn->stat_cache_scarce_counter;
    }
#endif

    switch (control->group) {

    case NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA:
    case NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG:

        if (njt_http_vhost_traffic_status_node_member_cmp(member, "weight") == 0)
        {
            return us->weight;
        }
        else if (njt_http_vhost_traffic_status_node_member_cmp(member, "maxFails") == 0)
        {
            return us->max_fails;
        }
        else if (njt_http_vhost_traffic_status_node_member_cmp(member, "failTimeout") == 0)
        {
            return us->fail_timeout;
        }
        else if (njt_http_vhost_traffic_status_node_member_cmp(member, "backup") == 0)
        {
            return us->backup;
        }
        else if (njt_http_vhost_traffic_status_node_member_cmp(member, "down") == 0)
        {
            return us->down;
        }

        break;
    }

    return 0;
}


static njt_int_t
njt_http_vhost_traffic_status_set_by_filter_init(
    njt_http_vhost_traffic_status_control_t *control,
    njt_str_t *uri)
{
    u_char              *p;
    njt_int_t            rc;
    njt_str_t           *arg_group, *arg_zone, *arg_name, alpha, slash;
    njt_http_request_t  *r;

    control->command = NJT_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_CMD_STATUS;
    arg_group = control->arg_group;
    arg_zone = control->arg_zone;
    arg_name = control->arg_name;

    r = control->r;

    /* parse: group */
    p = (u_char *) njt_strlchr(uri->data, uri->data + uri->len, '/');
    if (p == NULL) {
        return NJT_ERROR;
    }

    arg_group->data = uri->data;
    arg_group->len = p - uri->data;

    /* parse: zone */
    arg_zone->data = p + 1;
    p = (u_char *) njt_strlchr(arg_zone->data, arg_zone->data + arg_zone->len, '/');
    if (p == NULL) {
        return NJT_ERROR;
    }

    arg_zone->len = p - arg_zone->data;

    /* parse: name */
    arg_name->data = p + 1;
    arg_name->len = uri->data + uri->len - arg_name->data;

    /* set: control->group */
    if (arg_group->len == 6
            && njt_strncasecmp(arg_group->data, (u_char *) "server", 6) == 0)
    {
        control->group = NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO;
    }
    else if (arg_group->len == 14
            && njt_strncasecmp(arg_group->data, (u_char *) "upstream@alone", 14) == 0)
    {
        control->group = NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA;
    }
    else if (arg_group->len == 14
            && njt_strncasecmp(arg_group->data, (u_char *) "upstream@group", 14) == 0)
    {
        control->group = NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG;
    }
    else if (arg_group->len == 5
            && njt_strncasecmp(arg_group->data, (u_char *) "cache", 5) == 0)
    {
        control->group = NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_CC;
    }
    else if (arg_group->len == 6
            && njt_strncasecmp(arg_group->data, (u_char *) "filter", 6) == 0)
    {
        control->group = NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG;
    }
    else {
        return NJT_ERROR;
    }

    /* set: control->zone */
    rc = njt_http_vhost_traffic_status_copy_str(r->pool, control->zone, arg_zone);
    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "display_handler_control::copy_str() failed");
    }

    (void) njt_http_vhost_traffic_status_replace_chrc(control->zone, '@',
               NJT_HTTP_VHOST_TRAFFIC_STATUS_KEY_SEPARATOR);

    njt_str_set(&alpha, "[:alpha:]");
    rc = njt_http_vhost_traffic_status_replace_strc(control->zone, &alpha, '@');
    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "display_handler_control::replace_strc() failed");
    }

    njt_str_set(&slash, "[:slash:]");
    rc = njt_http_vhost_traffic_status_replace_strc(control->zone, &slash, '/');
    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "display_handler_control::replace_strc() failed");
    }

    return NJT_OK;
}


static njt_int_t
njt_http_vhost_traffic_status_set_by_filter_node(
    njt_http_vhost_traffic_status_control_t *control,
    njt_str_t *buf)
{
    u_char                                *p;
    njt_int_t                              rc;
    njt_str_t                              key;
    njt_rbtree_node_t                     *node;
    njt_http_request_t                    *r;
    njt_http_upstream_server_t             us;
    njt_http_vhost_traffic_status_node_t  *vtsn;

    r = control->r;

    rc = njt_http_vhost_traffic_status_node_generate_key(r->pool, &key, control->zone,
                                                         control->group);
    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "node_status_zone::node_generate_key(\"%V\") failed", &key);

        return NJT_ERROR;
    }

    node = njt_http_vhost_traffic_status_find_node(r, &key, control->group, 0);
    if (node == NULL) {
        return NJT_ERROR;
    }

    vtsn = njt_http_vhost_traffic_status_get_node(node);

    p = njt_pnalloc(r->pool, NJT_ATOMIC_T_LEN);
    if (p == NULL) {
        return NJT_ERROR;
    }

    buf->data = p;

    njt_memzero(&us, sizeof(njt_http_upstream_server_t));

    switch (control->group) {

    case NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO:
    case NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_CC:
    case NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG:
        buf->len = njt_sprintf(p, "%uA", njt_http_vhost_traffic_status_set_by_filter_node_member(
                                             control, vtsn, &us)) - p;
        break;

    case NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA:
    case NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG:
        njt_http_vhost_traffic_status_node_upstream_lookup(control, &us);
        if (control->count) {
            buf->len = njt_sprintf(p, "%uA", njt_http_vhost_traffic_status_set_by_filter_node_member(
                                                 control, vtsn, &us)) - p;
        } else {
            return NJT_ERROR;
        }
        break;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_vhost_traffic_status_set_by_filter_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "vts filter variable");

    v->not_found = 1;

    return NJT_OK;
}


static njt_int_t
njt_http_vhost_traffic_status_set_by_filter_variables(njt_http_request_t *r)
{
    njt_int_t                                         rc;
    njt_str_t                                         val, buf;
    njt_http_variable_t                              *v;
    njt_http_variable_value_t                        *vv;
    njt_http_vhost_traffic_status_control_t          *control;
    njt_http_vhost_traffic_status_loc_conf_t         *vtscf;
    njt_http_vhost_traffic_status_filter_variable_t  *fv, *last;
    njt_http_core_main_conf_t                        *cmcf;

    control = njt_pcalloc(r->pool, sizeof(njt_http_vhost_traffic_status_control_t));
    if (control == NULL) {
        return NJT_ERROR;
    }

    rc = njt_http_vhost_traffic_status_set_init(r, control);
    if (rc != NJT_OK) {
        return NJT_ERROR;
    }

    vtscf = njt_http_get_module_loc_conf(r, njt_http_vhost_traffic_status_module);

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "vts set filter variables");

    if (vtscf->filter_vars == NULL) {
        return NJT_OK;
    }

    cmcf = njt_http_get_module_main_conf(r, njt_http_core_module);
    v = cmcf->variables.elts;

    fv = vtscf->filter_vars->elts;
    last = fv + vtscf->filter_vars->nelts;

    while (fv < last) {

        vv = &r->variables[fv->index];

        if (njt_http_complex_value(r, &fv->value, &val)
            != NJT_OK)
        {
            return NJT_ERROR;
        }

        rc = njt_http_vhost_traffic_status_set_by_filter_init(control, &val);

        if (rc != NJT_OK) {
            njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "set_by_filter_variables::filter_init() failed");

            goto not_found;
        }

        njt_memzero(&buf, sizeof(njt_str_t));

        rc = njt_http_vhost_traffic_status_set_by_filter_node(control, &buf);
        if (rc != NJT_OK) {
            njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "set_by_filter_variables::filter_node() node not found");

            goto not_found;
        }

        vv->valid = 1;
        vv->not_found = 0;

        vv->data = buf.data;
        vv->len = buf.len;

        goto found;

not_found:

        vv->not_found = 1;

found:

        if (fv->set_handler) {
            fv->set_handler(r, vv, v[fv->index].data);
        }

        fv++;
    }

    return NJT_OK;
}


char *
njt_http_vhost_traffic_status_set_by_filter(njt_conf_t *cf,
    njt_command_t *cmd, void *conf)
{
    njt_http_vhost_traffic_status_loc_conf_t *vtscf = conf;

    njt_str_t                                        *value;
    njt_http_variable_t                              *v;
    njt_http_vhost_traffic_status_filter_variable_t  *fv;
    njt_http_compile_complex_value_t                  ccv;

    value = cf->args->elts;

    if (value[1].data[0] != '$') {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &value[1]);
        return NJT_CONF_ERROR;
    }

    value[1].len--;
    value[1].data++;

    if (vtscf->filter_vars == NJT_CONF_UNSET_PTR) {
        vtscf->filter_vars = njt_array_create(cf->pool, 1,
                                 sizeof(njt_http_vhost_traffic_status_filter_variable_t));
        if (vtscf->filter_vars == NULL) {
            return NJT_CONF_ERROR;
        }
    }

    fv = njt_array_push(vtscf->filter_vars);
    if (fv == NULL) {
        return NJT_CONF_ERROR;
    }

    v = njt_http_add_variable(cf, &value[1], NJT_HTTP_VAR_CHANGEABLE);
    if (v == NULL) {
        return NJT_CONF_ERROR;
    }

    fv->index = njt_http_get_variable_index(cf, &value[1]);
    if (fv->index == NJT_ERROR) {
        return NJT_CONF_ERROR;
    }

    if (v->get_handler == NULL) {
        v->get_handler = njt_http_vhost_traffic_status_set_by_filter_variable;
        v->data = (uintptr_t) fv;
    }

    fv->set_handler = v->set_handler;

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &fv->value;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
