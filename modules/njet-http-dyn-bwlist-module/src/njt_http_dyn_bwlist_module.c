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

extern njt_module_t njt_http_access_module;

typedef struct
{
    njt_str_t rule;
    njt_str_t addr;
    njt_str_t mask;
} njt_http_dyn_bwlist_access_ipv4_t;

struct njt_http_dyn_bwlist_loc_s
{
    njt_str_t full_name;
    njt_array_t access_ipv4;
    njt_array_t locs;
};
typedef struct njt_http_dyn_bwlist_loc_s njt_http_dyn_bwlist_loc_t;

typedef struct
{
    njt_array_t listens;
    njt_array_t server_names;
    njt_array_t locs;
} njt_http_dyn_bwlist_srv_t;

typedef struct
{
    njt_array_t servers;
    njt_int_t rc;
    unsigned success : 1;
} njt_http_dyn_bwlist_main_t;

static njt_json_define_t njt_http_dyn_bwlist_access_ipv4_json_dt[] = {
    {
        njt_string("rule"),
        offsetof(njt_http_dyn_bwlist_access_ipv4_t, rule),
        0,
        NJT_JSON_STR,
        0,
        NULL,
        NULL,
    },
    {
        njt_string("addr"),
        offsetof(njt_http_dyn_bwlist_access_ipv4_t, addr),
        0,
        NJT_JSON_STR,
        0,
        NULL,
        NULL,
    },
    {
        njt_string("mask"),
        offsetof(njt_http_dyn_bwlist_access_ipv4_t, mask),
        0,
        NJT_JSON_STR,
        0,
        NULL,
        NULL,
    },
    njt_json_define_null };

static njt_json_define_t njt_http_dyn_bwlist_loc_json_dt[] = {
    {
        njt_string("location"),
        offsetof(njt_http_dyn_bwlist_loc_t, full_name),
        0,
        NJT_JSON_STR,
        0,
        NULL,
        NULL,
    },
    {
        njt_string("accessIpv4"),
        offsetof(njt_http_dyn_bwlist_loc_t, access_ipv4),
        sizeof(njt_http_dyn_bwlist_access_ipv4_t),
        NJT_JSON_ARRAY,
        NJT_JSON_OBJ,
        njt_http_dyn_bwlist_access_ipv4_json_dt,
        NULL,
    },
    {
        njt_string("locations"),
        offsetof(njt_http_dyn_bwlist_loc_t, locs),
        sizeof(njt_http_dyn_bwlist_loc_t),
        NJT_JSON_ARRAY,
        NJT_JSON_OBJ,
        njt_http_dyn_bwlist_loc_json_dt,
        NULL,
    },

    njt_json_define_null,
};

static njt_json_define_t njt_http_dyn_bwlist_srv_json_dt[] = {
    {
        njt_string("listens"),
        offsetof(njt_http_dyn_bwlist_srv_t, listens),
        sizeof(njt_str_t),
        NJT_JSON_ARRAY,
        NJT_JSON_STR,
        NULL,
        NULL,
    },

    {
        njt_string("serverNames"),
        offsetof(njt_http_dyn_bwlist_srv_t, server_names),
        sizeof(njt_str_t),
        NJT_JSON_ARRAY,
        NJT_JSON_STR,
        NULL,
        NULL,
    },

    {
        njt_string("locations"),
        offsetof(njt_http_dyn_bwlist_srv_t, locs),
        sizeof(njt_http_dyn_bwlist_loc_t),
        NJT_JSON_ARRAY,
        NJT_JSON_OBJ,
        njt_http_dyn_bwlist_loc_json_dt,
        NULL,
    },

    njt_json_define_null,
};

static njt_json_define_t njt_http_dyn_bwlist_main_json_dt[] = {
    {
        njt_string("servers"),
        offsetof(njt_http_dyn_bwlist_main_t, servers),
        sizeof(njt_http_dyn_bwlist_srv_t),
        NJT_JSON_ARRAY,
        NJT_JSON_OBJ,
        njt_http_dyn_bwlist_srv_json_dt,
        NULL,
    },

    njt_json_define_null,
};

njt_str_t dyn_bwlist_update_srv_err_msg = njt_string("{\"code\":500,\"msg\":\"server error\"}");

static njt_int_t njt_dyn_bwlist_set_rules(njt_pool_t *pool, njt_http_dyn_bwlist_loc_t *data, njt_http_conf_ctx_t *ctx, njt_rpc_result_t *rpc_result)
{
    njt_http_access_loc_conf_t *alcf, old_cf;
    njt_http_access_rule_t *rule;
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
    alcf->rules = NULL;

    if (data->access_ipv4.nelts > 0) {
        njt_http_dyn_bwlist_access_ipv4_t *access = data->access_ipv4.elts;

        for (i = 0; i < data->access_ipv4.nelts; i++) {
            in_addr_t addr = njt_inet_addr(access[i].addr.data, access[i].addr.len);
            if (addr == INADDR_NONE) {
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "skipping wrong ipv4 addr: %V ", &access[i].addr);
                end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " wrong ipv4 addr: %V", &access[i].addr);
                rpc_data_str.len = end - data_buf;
                njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_PARTIAL_SUCCESS);
                continue;
            }
            in_addr_t mask = njt_inet_addr(access[i].mask.data, access[i].mask.len);
            njt_uint_t deny = 1;
            if (access[i].rule.len == 5 && njt_strncmp(access[i].rule.data, "allow", 5) == 0) {
                deny = 0;
            }

            if (alcf->rules == NULL) {
                alcf->rules = njt_array_create(cf->pool, 4,
                    sizeof(njt_http_access_rule_t));
            }
            if (alcf->rules == NULL) {
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "can't create access rule arrays ");
                goto error;
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

    if (old_cf.rules != NULL) {
        if (old_cf.dynamic && old_cf.rules) {
            njt_destroy_pool(old_cf.rules->pool);
        }
        old_cf.rules = NULL;
    }
    return NJT_OK;

error:
    *alcf = old_cf;
    return NJT_ERROR;
}

static njt_int_t njt_dyn_bwlist_update_locs(njt_array_t *locs, njt_queue_t *q, njt_http_conf_ctx_t *ctx, njt_rpc_result_t *rpc_result)
{
    njt_http_core_loc_conf_t *clcf;
    njt_http_location_queue_t *hlq;
    njt_http_dyn_bwlist_loc_t *dbwl;
    njt_uint_t j;
    njt_queue_t *tq;
    njt_int_t rc;
    u_char data_buf[1024];
    u_char *end;
    njt_str_t conf_path;
    njt_str_t parent_conf_path;
    njt_str_t name;
    bool loc_found;
    njt_str_t rpc_data_str;
    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;

    if (q == NULL) {
        return NJT_OK;
    }
    dbwl = locs->elts;
    if (rpc_result) {
        parent_conf_path = rpc_result->conf_path;
    }

    for (j = 0; j < locs->nelts; ++j) {
        loc_found = false;
        name = dbwl[j].full_name;
        tq = njt_queue_head(q);

        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, ".locations[%V]", &name);
        rpc_data_str.len = end - data_buf;
        if (rpc_result) {
            rpc_result->conf_path = parent_conf_path;
        }

        njt_rpc_result_append_conf_path(rpc_result, &rpc_data_str);
        for (; tq != njt_queue_sentinel(q); tq = njt_queue_next(tq)) {
            hlq = njt_queue_data(tq, njt_http_location_queue_t, queue);
            clcf = hlq->exact == NULL ? hlq->inclusive : hlq->exact;
            if (name.len == clcf->full_name.len && njt_strncmp(name.data, clcf->full_name.data, name.len) == 0) {
                loc_found = true;
                ctx->loc_conf = clcf->loc_conf;
                njt_pool_t *pool = njt_create_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
                if (pool == NULL) {
                    end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " create pool error");
                    rpc_data_str.len = end - data_buf;
                    njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                    return NJT_ERROR;
                }
                rc = njt_sub_pool(njt_cycle->pool, pool);
                if (rc != NJT_OK) {
                    end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " create pool error");
                    rpc_data_str.len = end - data_buf;
                    njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                    return NJT_ERROR;
                }
                rpc_data_str.len = 0;
                njt_dyn_bwlist_set_rules(pool, &dbwl[j], ctx, rpc_result);
                if (rc != NJT_OK) {
                    njt_log_error(NJT_LOG_ERR, pool->log, 0, " error in njt_dyn_bwlist_set_rules");
                    if (0 == rpc_data_str.len) {
                        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " njt_dyn_bwlist_set_rules error[%V];", &name);
                        rpc_data_str.len = end - data_buf;
                    }
                    njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                    njt_destroy_pool(pool);
                }
                else {
                    njt_rpc_result_add_success_count(rpc_result);
                }
            }

            if (dbwl[j].locs.nelts > 0) {
                if (rpc_result) {
                    conf_path = rpc_result->conf_path;
                }
                njt_dyn_bwlist_update_locs(&dbwl[j].locs, clcf->old_locations, ctx, rpc_result);
                if (rpc_result) {
                    rpc_result->conf_path = conf_path;
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

static njt_json_element *njt_dyn_bwlist_dump_locs_json(njt_pool_t *pool, njt_queue_t *locations)
{
    njt_http_core_loc_conf_t *clcf;
    njt_http_location_queue_t *hlq;
    njt_queue_t *q, *tq;
    njt_http_access_loc_conf_t *alcf;
    njt_json_element *locs, *item, *sub, *access_ipv4, *access;
    njt_http_access_rule_t *rule;
    njt_uint_t i;

    if (locations == NULL) {
        return NULL;
    }

    locs = NULL;
    q = locations;
    if (njt_queue_empty(q)) {
        return NULL;
    }

    tq = njt_queue_head(q);
    locs = njt_json_arr_element(pool, njt_json_fast_key("locations"));
    if (locs == NULL) {
        return NULL;
    }

    for (; tq != njt_queue_sentinel(q); tq = njt_queue_next(tq)) {
        hlq = njt_queue_data(tq, njt_http_location_queue_t, queue);
        clcf = hlq->exact == NULL ? hlq->inclusive : hlq->exact;
        alcf = njt_http_get_module_loc_conf(clcf, njt_http_access_module);

        item = njt_json_obj_element(pool, njt_json_null_key);
        if (item == NULL) {
            return NULL;
        }

        sub = njt_json_str_element(pool, njt_json_fast_key("location"), &clcf->full_name);
        if (sub == NULL) {
            return NULL;
        }

        njt_struct_add(item, sub, pool);

        if (alcf->rules) {
            njt_str_t allow_str = njt_string("allow");
            njt_str_t deny_str = njt_string("deny");
            njt_str_t net_addr_str = njt_null_string;
            access_ipv4 = njt_json_arr_element(pool, njt_json_fast_key("accessIpv4"));
            if (access_ipv4 == NULL) {
                return NULL;
            }

            rule = alcf->rules->elts;
            // iterate ipv4 access rules
            for (i = 0; i < alcf->rules->nelts; i++) {
                access = njt_json_obj_element(pool, njt_json_null_key);
                if (access == NULL) {
                    return NULL;
                }
                sub = njt_json_str_element(pool, njt_json_fast_key("rule"), rule[i].deny ? &deny_str : &allow_str);
                if (sub == NULL) {
                    return NULL;
                }
                else {
                    njt_struct_add(access, sub, pool);
                }

                net_addr_str.data = njt_pcalloc(pool, INET_ADDRSTRLEN);
                if (net_addr_str.data == NULL) {
                    return NULL;
                }
                net_addr_str.len = njt_inet_ntop(AF_INET, &rule[i].addr, net_addr_str.data, INET_ADDRSTRLEN);
                sub = njt_json_str_element(pool, njt_json_fast_key("addr"), &net_addr_str);
                if (sub == NULL) {
                    return NULL;
                }
                else {
                    njt_struct_add(access, sub, pool);
                }
                net_addr_str.data = njt_pcalloc(pool, INET_ADDRSTRLEN);
                if (net_addr_str.data == NULL) {
                    return NULL;
                }
                net_addr_str.len = njt_inet_ntop(AF_INET, &rule[i].mask, net_addr_str.data, INET_ADDRSTRLEN);
                sub = njt_json_str_element(pool, njt_json_fast_key("mask"), &net_addr_str);
                if (sub == NULL) {
                    return NULL;
                }
                else {
                    njt_struct_add(access, sub, pool);
                }
                njt_struct_add(access_ipv4, access, pool);
            }
            njt_struct_add(item, access_ipv4, pool);
        }

        sub = njt_dyn_bwlist_dump_locs_json(pool, clcf->old_locations);
        if (sub != NULL) {
            njt_struct_add(item, sub, pool);
        }

        njt_struct_add(locs, item, pool);
    }

    return locs;
}

static njt_str_t njt_dyn_bwlist_dump_access_conf(njt_cycle_t *cycle, njt_pool_t *pool)
{
    njt_http_core_loc_conf_t *clcf;
    njt_http_core_main_conf_t *hcmcf;
    njt_http_core_srv_conf_t **cscfp;
    njt_uint_t i, j;
    njt_int_t rc;
    njt_array_t *array;
    njt_str_t json, *tmp_str;
    njt_http_server_name_t *server_name;
    njt_json_manager json_manager;
    njt_json_element *srvs, *srv, *subs, *sub;

    njt_memzero(&json_manager, sizeof(njt_json_manager));
    hcmcf = njt_http_cycle_get_module_main_conf(cycle, njt_http_core_module);

    srvs = njt_json_arr_element(pool, njt_json_fast_key("servers"));
    if (srvs == NULL) {
        goto err;
    }

    cscfp = hcmcf->servers.elts;
    for (i = 0; i < hcmcf->servers.nelts; i++) {
        array = njt_array_create(pool, 4, sizeof(njt_str_t));
        njt_http_get_listens_by_server(array, cscfp[i]);

        srv = njt_json_obj_element(pool, njt_json_null_key);
        if (srv == NULL) {
            goto err;
        }

        subs = njt_json_arr_element(pool, njt_json_fast_key("listens"));
        if (subs == NULL) {
            goto err;
        }

        tmp_str = array->elts;
        for (j = 0; j < array->nelts; ++j) {
            sub = njt_json_str_element(pool, njt_json_null_key, &tmp_str[j]);
            if (sub == NULL) {
                goto err;
            }
            njt_struct_add(subs, sub, pool);
        }
        njt_struct_add(srv, subs, pool);
        subs = njt_json_arr_element(pool, njt_json_fast_key("serverNames"));
        if (subs == NULL) {
            goto err;
        }

        server_name = cscfp[i]->server_names.elts;
        for (j = 0; j < cscfp[i]->server_names.nelts; ++j) {
            sub = njt_json_str_element(pool, njt_json_null_key, &server_name[j].name);
            if (sub == NULL) {
                goto err;
            }
            njt_struct_add(subs, sub, pool);
        }

        njt_struct_add(srv, subs, pool);
        clcf = njt_http_get_module_loc_conf(cscfp[i]->ctx, njt_http_core_module);
        subs = njt_dyn_bwlist_dump_locs_json(pool, clcf->old_locations);

        if (subs != NULL) {
            njt_struct_add(srv, subs, pool);
        }

        njt_struct_add(srvs, srv, pool);
    }

    rc = njt_struct_top_add(&json_manager, srvs, NJT_JSON_OBJ, pool);
    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
            "njt_struct_top_add error");
    }

    njt_memzero(&json, sizeof(njt_str_t));
    njt_structure_2_json(&json_manager, &json, pool);

    return json;

err:
    return dyn_bwlist_update_srv_err_msg;
}

static njt_int_t njt_dyn_bwlist_update_access_conf(njt_pool_t *pool, njt_http_dyn_bwlist_main_t *api_data, njt_rpc_result_t *rpc_result)
{
    njt_cycle_t *cycle;
    njt_http_core_srv_conf_t *cscf;
    njt_http_core_loc_conf_t *clcf;
    njt_http_dyn_bwlist_srv_t *daas;
    njt_str_t *p_port, *p_sname;
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

    daas = api_data->servers.elts;
    for (i = 0; i < api_data->servers.nelts; ++i) {
        p_port = (njt_str_t *)daas[i].listens.elts;
        p_sname = (njt_str_t *)daas[i].server_names.elts;
        if (daas[i].listens.nelts < 1 || daas[i].server_names.nelts < 1) {
            // listens or server_names is empty
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " server parameters error, listens or serverNames is empty,at position %d", i);
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            continue;
        }

        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, "servers[%V,%V]", (njt_str_t *)daas[i].listens.elts, (njt_str_t *)daas[i].server_names.elts);
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_set_conf_path(rpc_result, &rpc_data_str);

        cscf = njt_http_get_srv_by_port(cycle, p_port, p_sname);
        if (cscf == NULL) {
            if (daas[i].listens.elts != NULL && daas[i].server_names.elts != NULL) {
                njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "can`t find server by listen:%V server_name:%V;",
                    (njt_str_t *)daas[i].listens.elts, (njt_str_t *)daas[i].server_names.elts);

                end = njt_snprintf(data_buf, sizeof(data_buf) - 1, "can not find server.");
                rpc_data_str.len = end - data_buf;
                njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            }
            continue;
        }

        njt_http_conf_ctx_t ctx = *cscf->ctx;
        clcf = njt_http_get_module_loc_conf(cscf->ctx, njt_http_core_module);
        rc = njt_dyn_bwlist_update_locs(&daas[i].locs, clcf->old_locations, &ctx, rpc_result);
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
    njt_str_t msg;
    u_char *buf;
    njt_pool_t *pool = NULL;

    buf = NULL;
    cycle = (njt_cycle_t *)njt_cycle;
    *len = 0;

    pool = njt_create_pool(njt_pagesize, njt_cycle->log);
    if (pool == NULL) {
        njt_log_error(NJT_LOG_EMERG, pool->log, 0, "njt_dyn_bwlist_rpc_handler create pool error");
        goto out;
    }

    msg = njt_dyn_bwlist_dump_access_conf(cycle, pool);
    buf = njt_calloc(msg.len, cycle->log);
    if (buf == NULL) {
        goto out;
    }

    njt_memcpy(buf, msg.data, msg.len);
    *len = msg.len;

out:
    if (pool != NULL) {
        njt_destroy_pool(pool);
    }

    return buf;
}

static int njt_dyn_bwlist_change_handler_internal(njt_str_t *key, njt_str_t *value, void *data, njt_str_t *out_msg)
{
    njt_int_t rc;
    njt_http_dyn_bwlist_main_t *api_data = NULL;
    njt_pool_t *pool = NULL;
    njt_json_manager json_manager;
    njt_rpc_result_t *rpc_result;

    if (value->len < 2) {
        return NJT_OK;
    }

    njt_memzero(&json_manager, sizeof(njt_json_manager));
    pool = NULL;
    rpc_result = njt_rpc_result_create();
    if (!rpc_result) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "can't create rpc result");
        goto end;
    }
    njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_SUCCESS);
    pool = njt_create_pool(njt_pagesize, njt_cycle->log);
    if (pool == NULL) {
        njt_log_error(NJT_LOG_EMERG, pool->log, 0, "njt_dyn_bwlist_change_handler create pool error");
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_MEM_ALLOC);
        goto rpc_msg;
    }

    api_data = njt_pcalloc(pool, sizeof(njt_http_dyn_bwlist_main_t));
    if (api_data == NULL) {
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, pool->log, 0,
            "could not alloc buffer in function %s", __func__);
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_MEM_ALLOC);
        goto rpc_msg;
    }

    rc = njt_json_parse_data(pool, value, njt_http_dyn_bwlist_main_json_dt, api_data);
    if (rc == NJT_OK) {
        njt_dyn_bwlist_update_access_conf(pool, api_data, rpc_result);
    }
    else {
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_JSON);
        goto rpc_msg;
    }

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

    return NJT_OK;
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
    if (njt_process != NJT_PROCESS_WORKER) {
        return NJT_OK;
    }

    njt_str_t bwlist_rpc_key = njt_string("http_dyn_bwlist");
    njt_reg_kv_msg_handler(&bwlist_rpc_key, njt_dyn_bwlist_change_handler, njt_dyn_bwlist_rpc_put_handler, njt_dyn_bwlist_rpc_get_handler, NULL);

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
