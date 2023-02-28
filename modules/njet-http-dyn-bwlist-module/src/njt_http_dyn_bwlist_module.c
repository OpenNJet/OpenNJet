#include <njt_core.h>
#include <njt_http_kv_module.h>
#include <njt_http.h>
#include <njt_json_util.h>
#include <njt_http_util.h>
#include <njt_http_dyn_module.h>

extern njt_module_t njt_http_access_module;

#define njt_json_fast_key(key) (u_char *)key, sizeof(key) - 1
#define njt_json_null_key NULL, 0

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
        NULL,
        NULL,
    },
    {
        njt_string("addr"),
        offsetof(njt_http_dyn_bwlist_access_ipv4_t, addr),
        0,
        NJT_JSON_STR,
        NULL,
        NULL,
    },
    {
        njt_string("mask"),
        offsetof(njt_http_dyn_bwlist_access_ipv4_t, mask),
        0,
        NJT_JSON_STR,
        NULL,
        NULL,
    },
    njt_json_define_null};

static njt_json_define_t njt_http_dyn_bwlist_loc_json_dt[] = {
    {
        njt_string("location"),
        offsetof(njt_http_dyn_bwlist_loc_t, full_name),
        0,
        NJT_JSON_STR,
        NULL,
        NULL,
    },
    {
        njt_string("accessIpv4"),
        offsetof(njt_http_dyn_bwlist_loc_t, access_ipv4),
        sizeof(njt_http_dyn_bwlist_access_ipv4_t),
        NJT_JSON_OBJ,
        njt_http_dyn_bwlist_access_ipv4_json_dt,
        NULL,
    },
    {
        njt_string("locations"),
        offsetof(njt_http_dyn_bwlist_loc_t, locs),
        sizeof(njt_http_dyn_bwlist_loc_t),
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
        NJT_JSON_STR,
        NULL,
        NULL,
    },

    {
        njt_string("serverNames"),
        offsetof(njt_http_dyn_bwlist_srv_t, server_names),
        sizeof(njt_str_t),
        NJT_JSON_STR,
        NULL,
        NULL,
    },

    {
        njt_string("locations"),
        offsetof(njt_http_dyn_bwlist_srv_t, locs),
        sizeof(njt_http_dyn_bwlist_loc_t),
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
        NJT_JSON_OBJ,
        njt_http_dyn_bwlist_srv_json_dt,
        NULL,
    },

    njt_json_define_null,
};

njt_str_t dyn_bwlist_update_srv_err_msg = njt_string("{\"code\":500,\"msg\":\"server error\"}");

static njt_json_element *njt_json_arr_element(njt_pool_t *pool, u_char *key, njt_uint_t len)
{
    njt_json_element *element;

    element = NULL;
    element = njt_pcalloc(pool, sizeof(njt_json_element));
    if (element == NULL)
    {
        goto out;
    }

    element->type = NJT_JSON_ARRAY;
    if (key != NULL)
    {
        element->key.data = key;
        element->key.len = len;
    }

out:
    return element;
}

static njt_json_element *njt_json_obj_element(njt_pool_t *pool, u_char *key, njt_uint_t len)
{
    njt_json_element *element;

    element = NULL;
    element = njt_pcalloc(pool, sizeof(njt_json_element));
    if (element == NULL)
    {
        goto out;
    }

    element->type = NJT_JSON_OBJ;
    if (key != NULL)
    {
        element->key.data = key;
        element->key.len = len;
    }

out:
    return element;
}

static njt_json_element *njt_json_str_element(njt_pool_t *pool, u_char *key, njt_uint_t len, njt_str_t *value)
{
    njt_json_element *element;

    element = NULL;
    element = njt_pcalloc(pool, sizeof(njt_json_element));
    if (element == NULL)
    {
        goto out;
    }

    element->type = NJT_JSON_STR;
    if (key != NULL)
    {
        element->key.data = key;
        element->key.len = len;
    }

    if (value != NULL)
    {
        element->strval.data = value->data;
        element->strval.len = value->len;
    }

out:
    return element;
}

static njt_int_t njt_dyn_bwlist_update_locs(njt_array_t *locs, njt_queue_t *q)
{
    njt_http_core_loc_conf_t *clcf;
    njt_http_location_queue_t *hlq;
    njt_http_dyn_bwlist_loc_t *daal;
    njt_uint_t i, j;
    njt_queue_t *tq;
    njt_http_access_loc_conf_t *llcf;
    njt_http_access_rule_t *rule;

    if (q == NULL)
    {
        return NJT_OK;
    }

    daal = locs->elts;

    for (j = 0; j < locs->nelts; ++j)
    {
        tq = njt_queue_head(q);
        for (; tq != njt_queue_sentinel(q); tq = njt_queue_next(tq))
        {
            hlq = njt_queue_data(tq, njt_http_location_queue_t, queue);
            clcf = hlq->exact == NULL ? hlq->inclusive : hlq->exact;

            njt_str_t name = daal[j].full_name;
            if (name.len == clcf->full_name.len && njt_strncmp(name.data, clcf->full_name.data, name.len) == 0)
            {
                llcf = njt_http_get_module_loc_conf(clcf, njt_http_access_module);

                if (daal[j].access_ipv4.nelts > 0)
                {
                    njt_http_dyn_bwlist_access_ipv4_t *access = daal[j].access_ipv4.elts;

                    if (llcf->rules)
                    {
                        njt_pool_t *pool = llcf->rules->pool;
                        rule = llcf->rules->elts;
                        for (i = 0; i < llcf->rules->nelts; i++)
                        {
                            njt_pfree(pool, rule + i);
                        }
                        llcf->rules=NULL;
                    }
                    for (i = 0; i < daal[j].access_ipv4.nelts; i++)
                    {
                        in_addr_t addr = njt_inet_addr(access[i].addr.data, access[i].addr.len);
                        if (addr==INADDR_NONE) {
                            njt_log_error(NJT_LOG_ERR, njt_cycle->log , 0, "skipping wrong ipv4 addr: %v ", &access[i].addr);
                            continue;
                        }
                        in_addr_t mask = njt_inet_addr(access[i].mask.data, access[i].mask.len);
                        njt_uint_t deny = 1;
                        if (access[i].rule.len == 5 && njt_strncmp(access[i].rule.data, "allow", 5) == 0)
                        {
                            deny = 0;
                        }
                        if (llcf->rules == NULL)
                        {
                            llcf->rules = njt_array_create(njt_cycle->pool, 4,
                                                           sizeof(njt_http_access_rule_t));
                            if (llcf->rules == NULL)
                            {
                                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "can't create access rule arrays");
                                return NJT_ERROR;
                            }
                        }
                        rule = njt_array_push(llcf->rules);
                        if (rule == NULL)
                        {
                            return NJT_ERROR;
                        }

                        rule->mask = mask;
                        rule->addr = addr;
                        rule->deny = deny;
                    }
                }
            }

            if (daal[j].locs.nelts > 0)
            {
                njt_dyn_bwlist_update_locs(&daal[j].locs, clcf->old_locations);
            }
        }
    }

    return NJT_OK;
}

static njt_json_element *njt_dyn_bwlist_dump_locs_json(njt_pool_t *pool, njt_queue_t *locations)
{
    njt_http_core_loc_conf_t *clcf;
    njt_http_location_queue_t *hlq;
    njt_queue_t *q, *tq;
    njt_http_access_loc_conf_t *llcf;
    njt_json_element *locs, *item, *sub, *access_ipv4, *access;
    njt_http_access_rule_t *rule;
    njt_uint_t i;

    if (locations == NULL)
    {
        return NULL;
    }

    locs = NULL;
    q = locations;
    if (njt_queue_empty(q))
    {
        return NULL;
    }

    tq = njt_queue_head(q);
    locs = njt_json_arr_element(pool, njt_json_fast_key("locations"));
    if (locs == NULL)
    {
        return NULL;
    }

    for (; tq != njt_queue_sentinel(q); tq = njt_queue_next(tq))
    {
        hlq = njt_queue_data(tq, njt_http_location_queue_t, queue);
        clcf = hlq->exact == NULL ? hlq->inclusive : hlq->exact;
        llcf = njt_http_get_module_loc_conf(clcf, njt_http_access_module);

        item = njt_json_obj_element(pool, njt_json_null_key);
        if (item == NULL)
        {
            return NULL;
        }

        sub = njt_json_str_element(pool, njt_json_fast_key("location"), &clcf->full_name);
        if (sub == NULL)
        {
            return NULL;
        }

        njt_struct_add(item, sub, pool);

        if (llcf->rules)
        {
            njt_str_t allow_str = njt_string("allow");
            njt_str_t deny_str = njt_string("deny");
            njt_str_t net_addr_str = njt_null_string;
            access_ipv4 = njt_json_arr_element(pool, njt_json_fast_key("accessIpv4"));
            if (access_ipv4 == NULL)
            {
                return NULL;
            }

            rule = llcf->rules->elts;
            // iterate ipv4 access rules
            for (i = 0; i < llcf->rules->nelts; i++)
            {
                access = njt_json_obj_element(pool, njt_json_null_key);
                if (access == NULL)
                {
                    return NULL;
                }
                sub = njt_json_str_element(pool, njt_json_fast_key("rule"), rule[i].deny ? &deny_str : &allow_str);
                if (sub == NULL)
                {
                    return NULL;
                }
                else
                {
                    njt_struct_add(access, sub, pool);
                }

                net_addr_str.data = njt_pcalloc(pool, INET_ADDRSTRLEN);
                if (net_addr_str.data == NULL)
                {
                    return NULL;
                }
                net_addr_str.len = njt_inet_ntop(AF_INET, &rule[i].addr, net_addr_str.data, INET_ADDRSTRLEN);
                sub = njt_json_str_element(pool, njt_json_fast_key("addr"), &net_addr_str);
                if (sub == NULL)
                {
                    return NULL;
                }
                else
                {
                    njt_struct_add(access, sub, pool);
                }
                net_addr_str.data = njt_pcalloc(pool, INET_ADDRSTRLEN);
                if (net_addr_str.data == NULL)
                {
                    return NULL;
                }
                net_addr_str.len = njt_inet_ntop(AF_INET, &rule[i].mask, net_addr_str.data, INET_ADDRSTRLEN);
                sub = njt_json_str_element(pool, njt_json_fast_key("mask"), &net_addr_str);
                if (sub == NULL)
                {
                    return NULL;
                }
                else
                {
                    njt_struct_add(access, sub, pool);
                }
                njt_struct_add(access_ipv4, access, pool);
            }
            njt_struct_add(item, access_ipv4, pool);
        }

        sub = njt_dyn_bwlist_dump_locs_json(pool, clcf->old_locations);
        if (sub != NULL)
        {
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
    njt_array_t *array;
    njt_str_t json, *tmp_str;
    njt_json_manager json_manager;
    njt_json_element *root, *srvs, *srv, *subs, *sub;

    hcmcf = njt_http_cycle_get_module_main_conf(cycle, njt_http_core_module);

    json_manager.json_keyval = njt_array_create(pool, 1, sizeof(njt_json_element));
    if (json_manager.json_keyval == NULL)
    {
        goto err;
    }

    root = njt_array_push(json_manager.json_keyval);
    if (root == NULL)
    {
        goto err;
    }

    njt_memzero(root, sizeof(njt_json_element));
    root->type = NJT_JSON_OBJ;

    srvs = njt_json_arr_element(pool, njt_json_fast_key("servers"));
    if (srvs == NULL)
    {
        goto err;
    }

    cscfp = hcmcf->servers.elts;
    for (i = 0; i < hcmcf->servers.nelts; i++)
    {
        array = njt_array_create(pool, 4, sizeof(njt_str_t));
        njt_http_get_listens_by_server(array, cscfp[i]);

        srv = njt_json_obj_element(pool, njt_json_null_key);
        if (srv == NULL)
        {
            goto err;
        }

        subs = njt_json_arr_element(pool, njt_json_fast_key("listens"));
        if (subs == NULL)
        {
            goto err;
        }

        tmp_str = array->elts;
        for (j = 0; j < array->nelts; ++j)
        {
            sub = njt_json_str_element(pool, njt_json_null_key, &tmp_str[j]);
            if (sub == NULL)
            {
                goto err;
            }
            njt_struct_add(subs, sub, pool);
        }
        njt_struct_add(srv, subs, pool);
        subs = njt_json_arr_element(pool, njt_json_fast_key("serverNames"));
        if (subs == NULL)
        {
            goto err;
        }

        tmp_str = cscfp[i]->server_names.elts;
        for (j = 0; j < cscfp[i]->server_names.nelts; ++j)
        {
            sub = njt_json_str_element(pool, njt_json_null_key, &tmp_str[j]);
            if (sub == NULL)
            {
                goto err;
            }
            njt_struct_add(subs, sub, pool);
        }

        njt_struct_add(srv, subs, pool);
        clcf = njt_http_get_module_loc_conf(cscfp[i]->ctx, njt_http_core_module);
        subs = njt_dyn_bwlist_dump_locs_json(pool, clcf->old_locations);

        if (subs != NULL)
        {
            njt_struct_add(srv, subs, pool);
        }

        njt_struct_add(srvs, srv, pool);
    }

    njt_struct_add(root, srvs, pool); // top layer
    njt_memzero(&json, sizeof(njt_str_t));
    njt_structure_2_json(&json_manager, &json, pool);

    return json;

err:
    return dyn_bwlist_update_srv_err_msg;
}

static njt_int_t njt_dyn_bwlist_update_access_conf(njt_pool_t *pool, njt_http_dyn_bwlist_main_t *api_data)
{
    njt_cycle_t *cycle, *new_cycle;
    njt_http_core_srv_conf_t *cscf;
    njt_http_core_loc_conf_t *clcf;
    njt_http_dyn_bwlist_srv_t *daas;
    njt_uint_t i;
    if (njt_process == NJT_PROCESS_HELPER)
    {
        new_cycle = (njt_cycle_t *)njt_cycle;
        cycle = new_cycle->old_cycle;
    }
    else
    {
        cycle = (njt_cycle_t *)njt_cycle;
    }

    daas = api_data->servers.elts;
    for (i = 0; i < api_data->servers.nelts; ++i)
    {
        cscf = njt_http_get_srv_by_port(cycle, pool, (njt_str_t *)daas[i].listens.elts, (njt_str_t *)daas[i].server_names.elts);
        if (cscf == NULL)
        {
            njt_log_error(NJT_LOG_INFO, pool->log, 0, "can`t find server by listen:%V server_name:%V ",
                          (njt_str_t *)daas[i].listens.nelts, (njt_str_t *)daas[i].server_names.nelts);
            continue;
        }
        clcf = njt_http_get_module_loc_conf(cscf->ctx, njt_http_core_module);
        njt_dyn_bwlist_update_locs(&daas[i].locs, clcf->old_locations);
    }

    return NJT_OK;
}

static u_char *njt_dyn_bwlist_rpc_handler(njt_str_t *topic, njt_str_t *request, int *len, void *data)
{
    njt_cycle_t *cycle;
    njt_str_t msg;
    u_char *buf;
    njt_pool_t *pool = NULL;

    buf = NULL;
    cycle = (njt_cycle_t *)njt_cycle;
    *len = 0;

    pool = njt_create_pool(njt_pagesize, njt_cycle->log);
    if (pool == NULL)
    {
        njt_log_error(NJT_LOG_EMERG, pool->log, 0, "njt_dyn_bwlist_rpc_handler create pool error");
        goto out;
    }

    msg = njt_dyn_bwlist_dump_access_conf(cycle, pool);
    buf = njt_calloc(msg.len, cycle->log);
    if (buf == NULL)
    {
        goto out;
    }

    njt_log_error(NJT_LOG_INFO, pool->log, 0, "send json : %V", &msg);
    njt_memcpy(buf, msg.data, msg.len);
    *len = msg.len;

out:
    if (pool != NULL)
    {
        njt_destroy_pool(pool);
    }

    return buf;
}

static int njt_dyn_bwlist_change_handler(njt_str_t *key, njt_str_t *value, void *data)
{
    njt_int_t rc;
    njt_http_dyn_bwlist_main_t *api_data = NULL;
    njt_pool_t *pool = NULL;

    if (value->len < 2)
    {
        return NJT_OK;
    }

    pool = njt_create_pool(njt_pagesize, njt_cycle->log);
    if (pool == NULL)
    {
        njt_log_error(NJT_LOG_EMERG, pool->log, 0, "njt_dyn_bwlist_change_handler create pool error");
        return NJT_OK;
    }

    api_data = njt_pcalloc(pool, sizeof(njt_http_dyn_bwlist_main_t));
    if (api_data == NULL)
    {
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, pool->log, 0,
                       "could not alloc buffer in function %s", __func__);
        goto out;
    }

    rc = njt_json_parse_data(pool, value, njt_http_dyn_bwlist_main_json_dt, api_data);
    if (rc == NJT_OK)
    {
        njt_dyn_bwlist_update_access_conf(pool, api_data);
    }

out:
    if (pool != NULL)
    {
        njt_destroy_pool(pool);
    }

    return NJT_OK;
}

static njt_int_t njt_http_dyn_bwlist_module_init_process(njt_cycle_t *cycle)
{
    njt_str_t bwlist_rpc_key = njt_string("http_dyn_bwlist");

    njt_reg_kv_change_handler(&bwlist_rpc_key, njt_dyn_bwlist_change_handler, njt_dyn_bwlist_rpc_handler, NULL);

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
    NJT_MODULE_V1_PADDING};
