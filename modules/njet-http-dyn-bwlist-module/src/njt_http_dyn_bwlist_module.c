/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */
#include <njt_core.h>
#include <njt_http_kv_module.h>
#include <njt_http.h>
#include <njt_json_util.h>
#include <njt_http_util.h>
#include <njt_http_dyn_module.h>
#include <njt_rpc_result_util.h>
#include "njt_http_dyn_bwlist_parser.h"

extern njt_module_t njt_http_access_module;

njt_str_t dyn_bwlist_update_srv_err_msg = njt_string("{\"code\":500,\"msg\":\"server error\"}");

static njt_int_t njt_dyn_bwlist_set_rules(njt_pool_t *pool, dynbwlist_servers_item_locations_item_t *data, njt_http_conf_ctx_t *ctx, njt_rpc_result_t *rpc_result)
{
    njt_http_access_loc_conf_t *alcf, old_cf;
    dynbwlist_locationDef_accessIpv4_item_t *accessIpv4;
    njt_http_access_rule_t *rule;
    dynbwlist_locationDef_accessIpv6_item_t *accessIpv6;
    njt_http_access_rule6_t *rule6;
    njt_int_t rc;
    njt_uint_t i;
    njt_conf_t *cf;
    u_char data_buf[1024];
    u_char *end;
    njt_str_t rpc_data_str;
    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;

    njt_conf_t cf_data = {
        .pool = pool,
        .temp_pool = pool,
        .cycle = (njt_cycle_t *)njt_cycle,
        .log = pool->log,
        .ctx = ctx,
    };
    cf = &cf_data;

    alcf = njt_http_conf_get_module_loc_conf(cf, njt_http_access_module);
    if (alcf == NULL) {
        return NJT_ERROR;
    }

    old_cf = *alcf;
    alcf->dynamic = 1;
    alcf->rules = njt_array_create(cf->pool, 4,
        sizeof(njt_http_access_rule_t));
    if (alcf->rules == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "can't create access rule arrays ");
        goto error;
    }
    alcf->rules6 = NULL;
    if (data->accessIpv4) {
        for (i = 0; i < data->accessIpv4->nelts; i++) {
            accessIpv4 = get_dynbwlist_locationDef_accessIpv4_item(data->accessIpv4, i);
            in_addr_t addr = njt_inet_addr(accessIpv4->addr.data, accessIpv4->addr.len);
            if (addr == INADDR_NONE) {
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "skipping wrong ipv4 addr: %V ", &accessIpv4->addr);
                end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " wrong ipv4 addr: %V", &accessIpv4->addr);
                rpc_data_str.len = end - data_buf;
                njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_PARTIAL_SUCCESS);
                continue;
            }
            in_addr_t mask = njt_inet_addr(accessIpv4->mask.data, accessIpv4->mask.len);
            njt_uint_t deny = 0;
            if (accessIpv4->rule == DYNBWLIST_LOCATIONDEF_ACCESSIPV4_ITEM_RULE_DENY) {
                deny = 1;
            }

            rule = njt_array_push(alcf->rules);
            if (rule == NULL) {
                goto error;
            }

            rule->mask = mask;
            rule->addr = addr;
            rule->deny = deny;
        }
    }

#if (NJT_HAVE_INET6)
    if (data->accessIpv6) {
        for (i = 0; i < data->accessIpv6->nelts; i++) {
            accessIpv6 = get_dynbwlist_locationDef_accessIpv6_item(data->accessIpv6, i);
            struct in6_addr addr;
            rc = njt_inet6_addr(accessIpv6->addr.data, accessIpv6->addr.len, addr.s6_addr);
            if (rc != NJT_OK) {
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "skipping wrong ipv6 addr: %V ", &accessIpv6->addr);
                end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " wrong ipv6 addr: %V", &accessIpv6->addr);
                rpc_data_str.len = end - data_buf;
                njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_PARTIAL_SUCCESS);
                continue;
            }
            struct in6_addr mask;
            rc = njt_inet6_addr(accessIpv6->mask.data, accessIpv6->mask.len, mask.s6_addr);
            njt_uint_t deny = 0;
            if (accessIpv6->rule == DYNBWLIST_LOCATIONDEF_ACCESSIPV6_ITEM_RULE_DENY) {
                deny = 1;
            }

            if (alcf->rules6 == NULL) {
                alcf->rules6 = njt_array_create(cf->pool, 4,
                    sizeof(njt_http_access_rule6_t));
            }
            if (alcf->rules6 == NULL) {
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "can't create access rule arrays ");
                goto error;
            }

            rule6 = njt_array_push(alcf->rules6);
            if (rule6 == NULL) {
                goto error;
            }

            rule6->mask = mask;
            rule6->addr = addr;
            rule6->deny = deny;
        }
    }
#endif

    if (old_cf.dynamic && old_cf.rules != NULL) {
        njt_destroy_pool(old_cf.rules->pool);
        old_cf.rules = NULL;
        old_cf.rules6 = NULL;
    }
    return NJT_OK;

error:
    *alcf = old_cf;
    return NJT_ERROR;
}

static njt_int_t njt_dyn_bwlist_update_locs(dynbwlist_servers_item_locations_t *locs, njt_queue_t *q, njt_http_conf_ctx_t *ctx, njt_rpc_result_t *rpc_result)
{
    njt_http_core_loc_conf_t *clcf;
    njt_http_location_queue_t *hlq;
    dynbwlist_servers_item_locations_item_t *dbwl;
    njt_uint_t j;
    njt_queue_t *tq;
    njt_int_t rc;
    u_char data_buf[1024];
    u_char *end;
    njt_str_t conf_path;
    njt_str_t parent_conf_path;
    njt_str_t *name;
    bool loc_found;
    njt_str_t rpc_data_str;
    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;

    if (locs == NULL || q == NULL) {
        return NJT_OK;
    }
    if (rpc_result) {
        parent_conf_path = rpc_result->conf_path;
    }

    for (j = 0; j < locs->nelts; ++j) {
        dbwl = get_dynbwlist_servers_item_locations_item(locs, j);
        if (dbwl == NULL || !dbwl->is_location_set) {
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " index %d not set location name", j);
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            continue;
        }

        name = get_dynbwlist_locationDef_location(dbwl);
        tq = njt_queue_head(q);
        loc_found = false;
        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, ".locations[%V]", name);
        rpc_data_str.len = end - data_buf;
        if (rpc_result) {
            rpc_result->conf_path = parent_conf_path;
        }

        njt_rpc_result_append_conf_path(rpc_result, &rpc_data_str);
        for (; tq != njt_queue_sentinel(q); tq = njt_queue_next(tq)) {
            hlq = njt_queue_data(tq, njt_http_location_queue_t, queue);
            clcf = hlq->exact == NULL ? hlq->inclusive : hlq->exact;
            if (clcf != NULL && njt_http_location_full_name_cmp(clcf->full_name, *name) == 0) {
                loc_found = true;
                ctx->loc_conf = clcf->loc_conf;
                njt_pool_t *pool = njt_create_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
                if (pool == NULL) {
                    end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " create pool error");
                    rpc_data_str.len = end - data_buf;
                    njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                    return NJT_ERROR;
                }
                rc = njt_sub_pool(clcf->pool, pool);
                if (rc != NJT_OK) {
                    end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " create pool error");
                    rpc_data_str.len = end - data_buf;
                    njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                    return NJT_ERROR;
                }
                rpc_data_str.len = 0;
                rc = njt_dyn_bwlist_set_rules(pool, dbwl, ctx, rpc_result);
                if (rc != NJT_OK) {
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " error in njt_dyn_bwlist_set_rules");
                    if (0 == rpc_data_str.len) {
                        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " njt_dyn_bwlist_set_rules error[%V];", name);
                        rpc_data_str.len = end - data_buf;
                    }
                    njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                    njt_destroy_pool(pool);
                } else {
                    njt_rpc_result_add_success_count(rpc_result);
                }

                if (dbwl->is_locations_set && dbwl->locations && dbwl->locations->nelts > 0) {
                    if (rpc_result) {
                        conf_path = rpc_result->conf_path;
                    }
                    njt_dyn_bwlist_update_locs(dbwl->locations, clcf->old_locations, ctx, rpc_result);
                    if (rpc_result) {
                        rpc_result->conf_path = conf_path;
                    }
                }
            }
        }
        if (!loc_found) {
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " location not found");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
        }
    }

    return NJT_OK;
}

static void njt_dyn_bwlist_dump_locs(njt_pool_t *pool, njt_queue_t *locations, dynbwlist_servers_item_locations_t *loc_items)
{
    dynbwlist_servers_item_locations_item_t *loc_item;
    dynbwlist_locationDef_accessIpv4_item_t *ipv4_item;
    dynbwlist_locationDef_accessIpv6_item_t *ipv6_item;
    njt_http_core_loc_conf_t *clcf;
    njt_http_location_queue_t *hlq;
    njt_queue_t *q, *tq;
    njt_http_access_loc_conf_t *alcf;
    njt_http_access_rule_t *rule;
    njt_http_access_rule6_t *rule6;
    njt_uint_t i;
    njt_str_t tmp_addmask;

    if (locations == NULL) {
        return;
    }

    q = locations;
    if (njt_queue_empty(q)) {
        return;
    }

    for (tq = njt_queue_head(q); tq != njt_queue_sentinel(q); tq = njt_queue_next(tq)) {
        hlq = njt_queue_data(tq, njt_http_location_queue_t, queue);
        clcf = hlq->exact == NULL ? hlq->inclusive : hlq->exact;
        alcf = njt_http_get_module_loc_conf(clcf, njt_http_access_module);

        loc_item = create_dynbwlist_locationDef(pool);
        set_dynbwlist_locationDef_location(loc_item,&clcf->full_name);
        add_item_dynbwlist_servers_item_locations(loc_items, loc_item);

        if (alcf->rules) {
            set_dynbwlist_locationDef_accessIpv4(loc_item, create_dynbwlist_locationDef_accessIpv4(pool, alcf->rules->nelts));
            if (loc_item->accessIpv4 == NULL) {
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "can`t create accessIpv4 rules array"
                );
                return;
            }
            rule = alcf->rules->elts;
            // iterate ipv4 access rules
            for (i = 0; i < alcf->rules->nelts; i++) {
                ipv4_item = create_dynbwlist_locationDef_accessIpv4_item(pool);
                add_item_dynbwlist_locationDef_accessIpv4(loc_item->accessIpv4, ipv4_item);
                set_dynbwlist_locationDef_accessIpv4_item_rule(ipv4_item, rule[i].deny ? DYNBWLIST_LOCATIONDEF_ACCESSIPV4_ITEM_RULE_DENY : DYNBWLIST_LOCATIONDEF_ACCESSIPV4_ITEM_RULE_ALLOW);

                tmp_addmask.data = njt_pcalloc(pool, INET_ADDRSTRLEN);
                if (tmp_addmask.data == NULL) {
                    return;
                }
                tmp_addmask.len = njt_inet_ntop(AF_INET, &rule[i].addr, tmp_addmask.data , INET_ADDRSTRLEN);
                set_dynbwlist_locationDef_accessIpv4_item_addr(ipv4_item, &tmp_addmask);

                tmp_addmask.data = njt_pcalloc(pool, INET_ADDRSTRLEN);
                if (tmp_addmask.data == NULL) {
                    return;
                }
                tmp_addmask.len = njt_inet_ntop(AF_INET, &rule[i].mask, tmp_addmask.data, INET_ADDRSTRLEN);
                set_dynbwlist_locationDef_accessIpv4_item_mask(ipv4_item, &tmp_addmask);
            }
        }
#if (NJT_HAVE_INET6)
        if (alcf->rules6) {
            set_dynbwlist_locationDef_accessIpv6(loc_item,  create_dynbwlist_locationDef_accessIpv6(pool, alcf->rules6->nelts));
            if (loc_item->accessIpv6 == NULL) {
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "can`t create accessIpv6 rules array"
                );
                return;
            }
            rule6 = alcf->rules6->elts;
            // iterate ipv6 access rules
            for (i = 0; i < alcf->rules6->nelts; i++) {
                ipv6_item = create_dynbwlist_locationDef_accessIpv6_item(pool);
                add_item_dynbwlist_locationDef_accessIpv6(loc_item->accessIpv6, ipv6_item);
                set_dynbwlist_locationDef_accessIpv6_item_rule(ipv6_item, rule6[i].deny ? DYNBWLIST_LOCATIONDEF_ACCESSIPV6_ITEM_RULE_DENY : DYNBWLIST_LOCATIONDEF_ACCESSIPV6_ITEM_RULE_ALLOW);

                tmp_addmask.data = njt_pcalloc(pool, INET6_ADDRSTRLEN);
                if (tmp_addmask.data == NULL) {
                    return;
                }
                tmp_addmask.len = njt_inet_ntop(AF_INET6, &rule6[i].addr, tmp_addmask.data, INET6_ADDRSTRLEN);
                set_dynbwlist_locationDef_accessIpv6_item_addr(ipv6_item, &tmp_addmask);
                tmp_addmask.data = njt_pcalloc(pool, INET6_ADDRSTRLEN);
                if (tmp_addmask.data == NULL) {
                    return;
                }
                tmp_addmask.len = njt_inet_ntop(AF_INET6, &rule6[i].mask, tmp_addmask.data, INET6_ADDRSTRLEN);
                set_dynbwlist_locationDef_accessIpv6_item_mask(ipv6_item, &tmp_addmask);
            }
        }
#endif

        if (clcf->old_locations) {
            set_dynbwlist_locationDef_locations(loc_item, create_dynbwlist_locationDef_locations(pool, 4));
            if (loc_item->locations != NULL) {
                njt_dyn_bwlist_dump_locs(pool, clcf->old_locations, loc_item->locations);
            } 
        }

    }

}

static njt_str_t *njt_dyn_bwlist_dump_access_conf(njt_cycle_t *cycle, njt_pool_t *pool)
{
    njt_http_core_loc_conf_t *clcf;
    njt_http_core_main_conf_t *hcmcf;
    njt_http_core_srv_conf_t **cscfp;
    njt_uint_t i, j;
    njt_array_t *array;
    njt_str_t *tmp_str;
    njt_http_server_name_t *server_name;

    dynbwlist_t dynjson_obj;
    dynbwlist_servers_item_t *server_item;

    njt_memzero(&dynjson_obj, sizeof(dynbwlist_t));
    hcmcf = njt_http_cycle_get_module_main_conf(cycle, njt_http_core_module);
    if (hcmcf == NULL) {
        goto err;
    }

    set_dynbwlist_servers(&dynjson_obj, create_dynbwlist_servers(pool, 4));
    if (dynjson_obj.servers == NULL) {
        goto err;
    }

    cscfp = hcmcf->servers.elts;
    for (i = 0; i < hcmcf->servers.nelts; i++) {
        server_item = create_dynbwlist_servers_item(pool);
        if(server_item == NULL){
            goto err;
        }

        set_dynbwlist_servers_item_listens(server_item,   create_dynbwlist_servers_item_listens(pool, 4));
        set_dynbwlist_servers_item_serverNames(server_item, create_dynbwlist_servers_item_serverNames(pool, 4));
        set_dynbwlist_servers_item_locations(server_item, create_dynbwlist_servers_item_locations(pool, 4));

        array = njt_array_create(pool, 4, sizeof(njt_str_t));
        if(array == NULL){
            goto err;
        }
        njt_http_get_listens_by_server(array, cscfp[i]);

        for (j = 0; j < array->nelts; ++j) {
            tmp_str = (njt_str_t *)(array->elts) + j;
            add_item_dynbwlist_servers_item_listens(server_item->listens, tmp_str);
        }

        server_name = cscfp[i]->server_names.elts;
        for (j = 0; j < cscfp[i]->server_names.nelts; ++j) {
            tmp_str = &server_name[j].full_name;
            add_item_dynbwlist_servers_item_serverNames(server_item->serverNames, tmp_str);
        }

        clcf = njt_http_get_module_loc_conf(cscfp[i]->ctx, njt_http_core_module);
        if(clcf != NULL){
            njt_dyn_bwlist_dump_locs(pool, clcf->old_locations, server_item->locations);
        }
        add_item_dynbwlist_servers(dynjson_obj.servers, server_item);
    }

    return to_json_dynbwlist(pool, &dynjson_obj, OMIT_NULL_ARRAY | OMIT_NULL_OBJ | OMIT_NULL_STR);

err:
    return &dyn_bwlist_update_srv_err_msg;

}

static njt_int_t njt_dyn_bwlist_update_access_conf(njt_pool_t *pool, dynbwlist_t *api_data, njt_rpc_result_t *rpc_result)
{
    njt_cycle_t *cycle;
    njt_http_core_srv_conf_t *cscf;
    njt_http_core_loc_conf_t *clcf;
    dynbwlist_servers_item_t *dsi;
    njt_str_t *port;
    njt_str_t *serverName;
    njt_uint_t i;
    njt_int_t rc;
    u_char data_buf[1024];
    u_char *end;
    njt_str_t rpc_data_str;
    rpc_data_str.data = data_buf;

    cycle = (njt_cycle_t *)njt_cycle;

    // empty path
    rpc_data_str.len = 0;
    njt_rpc_result_set_conf_path(rpc_result, &rpc_data_str);

    for (i = 0; i < api_data->servers->nelts; i++) {
        dsi = get_dynbwlist_servers_item(api_data->servers, i);
        port = get_dynbwlist_servers_item_listens_item(dsi->listens, 0);
        serverName = get_dynbwlist_servers_item_serverNames_item(dsi->serverNames, 0);
        if (dsi->listens->nelts < 1 || dsi->serverNames->nelts < 1) {
            // listens or server_names is empty
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " server parameters error, listens or serverNames is empty,at position %d", i);
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            continue;
        }

        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, "servers[%V,%V]", port, serverName);
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_set_conf_path(rpc_result, &rpc_data_str);

        cscf = njt_http_get_srv_by_port(cycle, port, serverName);
        if (cscf == NULL) {
            if (port != NULL && serverName != NULL) {
                njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "can`t find server by listen:%V server_name:%V;",
                    port, serverName);

                end = njt_snprintf(data_buf, sizeof(data_buf) - 1, "can not find server.");
                rpc_data_str.len = end - data_buf;
                njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            }
            continue;
        }

        njt_http_conf_ctx_t ctx = *cscf->ctx;
        clcf = njt_http_get_module_loc_conf(cscf->ctx, njt_http_core_module);
        rc = njt_dyn_bwlist_update_locs(dsi->locations, clcf->old_locations, &ctx, rpc_result);
        if (rc == NJT_OK) {
            njt_rpc_result_add_success_count(rpc_result);
        }
    }
    njt_rpc_result_update_code(rpc_result);
    return NJT_OK;
}

static u_char *njt_dyn_bwlist_rpc_get_handler(njt_str_t *topic, njt_str_t *request, int *len, void *data)
{
    njt_cycle_t *cycle;
    njt_str_t *msg;
    u_char *buf;
    njt_pool_t *pool = NULL;

    buf = NULL;
    cycle = (njt_cycle_t *)njt_cycle;
    *len = 0;

    pool = njt_create_pool(njt_pagesize, njt_cycle->log);
    if (pool == NULL) {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_bwlist_rpc_handler create pool error");
        goto out;
    }

    msg = njt_dyn_bwlist_dump_access_conf(cycle, pool);
    buf = njt_calloc(msg->len, cycle->log);
    if (buf == NULL) {
        goto out;
    }

    njt_memcpy(buf, msg->data, msg->len);
    *len = msg->len;

out:
    if (pool != NULL) {
        njt_destroy_pool(pool);
    }

    return buf;
}

static int njt_dyn_bwlist_change_handler_internal(njt_str_t *key, njt_str_t *value, void *data, njt_str_t *out_msg)
{
    njt_int_t rc;
    dynbwlist_t *api_data = NULL;
    njt_pool_t *pool = NULL;
    njt_json_manager json_manager;
    njt_rpc_result_t *rpc_result;
    js2c_parse_error_t  err_info;

    if (value->len < 2) {
        return NJT_OK;
    }

    njt_memzero(&json_manager, sizeof(njt_json_manager));
    pool = NULL;
    rpc_result = njt_rpc_result_create();
    if (!rpc_result) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "can't create rpc result");
        rc = NJT_ERROR;
        goto end;
    }
    njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_SUCCESS);
    pool = njt_create_pool(njt_pagesize, njt_cycle->log);
    if (pool == NULL) {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_bwlist_change_handler create pool error");
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_MEM_ALLOC);
        rc = NJT_ERROR;
        goto rpc_msg;
    }

    api_data = json_parse_dynbwlist(pool, value, &err_info);
    if (api_data == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "json_parse_dynbwlist err: %V", &err_info.err_str);
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_JSON);
        njt_rpc_result_set_msg2(rpc_result, &err_info.err_str);
        rc = NJT_ERROR;
        goto rpc_msg;
    }

    rc = njt_dyn_bwlist_update_access_conf(pool, api_data, rpc_result);

rpc_msg:
    if (out_msg) {
        njt_rpc_result_to_json_str(rpc_result, out_msg);
    }
end:
    if (pool != NULL) {
        njt_destroy_pool(pool);
    }
    if (rpc_result) {
        njt_rpc_result_destroy(rpc_result);
    }

    return rc;
}

static int njt_dyn_bwlist_change_handler(njt_str_t *key, njt_str_t *value, void *data)
{
    return njt_dyn_bwlist_change_handler_internal(key, value, data, NULL);
}

static u_char *njt_dyn_bwlist_rpc_put_handler(njt_str_t *topic, njt_str_t *request, int *len, void *data)
{
    njt_str_t err_json_msg;
    njt_str_null(&err_json_msg);
    njt_dyn_bwlist_change_handler_internal(topic, request, data, &err_json_msg);
    *len = err_json_msg.len;
    return err_json_msg.data;
}

static njt_int_t njt_http_dyn_bwlist_module_init_process(njt_cycle_t *cycle)
{
    njt_str_t bwlist_rpc_key = njt_string("http_dyn_bwlist");
    njt_kv_reg_handler_t h;
    njt_memzero(&h, sizeof(njt_kv_reg_handler_t));
    h.key = &bwlist_rpc_key;
    h.rpc_get_handler = njt_dyn_bwlist_rpc_get_handler;
    h.rpc_put_handler = njt_dyn_bwlist_rpc_put_handler;
    h.handler = njt_dyn_bwlist_change_handler;
    h.api_type = NJT_KV_API_TYPE_DECLATIVE;
    njt_kv_reg_handler(&h);

    return NJT_OK;
}

static njt_http_module_t njt_http_dyn_bwlist_module_ctx = {
    NULL, /* preconfiguration */
    NULL, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    NULL, /* create location configuration */
    NULL  /* merge location configuration */
};

njt_module_t njt_http_dyn_bwlist_module = {
    NJT_MODULE_V1,
    &njt_http_dyn_bwlist_module_ctx,         /* module context */
    NULL,                                    /* module directives */
    NJT_HTTP_MODULE,                         /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    njt_http_dyn_bwlist_module_init_process, /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NJT_MODULE_V1_PADDING };
