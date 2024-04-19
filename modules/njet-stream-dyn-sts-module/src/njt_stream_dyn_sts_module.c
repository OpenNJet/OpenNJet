/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */
#include <njt_core.h>
#include <njt_http_kv_module.h>
#include <njt_json_util.h>
#include <njt_rpc_result_util.h>
#include <njt_stream_dyn_module.h>
#include <njt_stream.h>
#include <njt_stream_util.h>
#include "parser_dynsts.h"
extern njt_module_t njt_stream_stsc_module;

njt_str_t dyn_sts_err_msg = njt_string("{\"code\":500,\"msg\":\"server error\"}");
static njt_str_t *njt_stream_dyn_sts_dump_conf(njt_cycle_t *cycle, njt_pool_t *pool)
{
    njt_array_t *filter_keys;
    njt_stream_server_traffic_status_filter_t *filters;
    njt_uint_t i, j, n;
    njt_int_t rc;
    njt_array_t *array;
    njt_stream_server_traffic_status_conf_t *stscf;
    njt_stream_core_srv_conf_t **servers;
    njt_stream_core_main_conf_t *cmcf;
    njt_str_t *tmp_str;
    u_char *buf;

    dynsts_t dynjson_obj;
    dynsts_servers_item_t *server_item;

    njt_memzero(&dynjson_obj, sizeof(dynsts_t));
    cmcf = njt_stream_cycle_get_module_main_conf(cycle, njt_stream_core_module);
    if (cmcf == NULL) {
        goto err;
    }

    set_dynsts_servers(&dynjson_obj, create_dynsts_servers(pool, 4));
    if (dynjson_obj.servers == NULL) {
        goto err;
    }

    servers = (njt_stream_core_srv_conf_t **)cmcf->servers.elts;
    for (i = 0; i < cmcf->servers.nelts; i++) {
        server_item = create_dynsts_servers_item(pool);
        if (server_item == NULL) {
            goto err;
        }
        set_dynsts_servers_item_listens(server_item, create_dynsts_servers_item_listens(pool, 4));
        set_dynsts_servers_item_server_traffic_status_filter_by_set_key(server_item, create_dynsts_servers_item_server_traffic_status_filter_by_set_key(pool, 4));

        array = njt_array_create(pool, 4, sizeof(njt_str_t));
        if (array == NULL) {
            goto err;
        }
        rc = njt_stream_get_listens_by_server(array, servers[i]);
        if (rc != NJT_OK) {
            goto err;
        }
        for (j = 0; j < array->nelts; ++j) {
            tmp_str = (njt_str_t *)(array->elts) + j;
            add_item_dynsts_servers_item_listens(server_item->listens, tmp_str);
        }
        stscf = njt_stream_get_module_srv_conf(servers[i]->ctx, njt_stream_stsc_module);
        if (stscf == NULL) {
            goto err;
        }
        set_dynsts_servers_item_server_traffic_status(server_item, stscf->enable);

        filter_keys = stscf->filter_keys;
        array = njt_array_create(pool, 4, sizeof(njt_str_t));
        if (array == NULL) {
            goto err;
        }
        if (filter_keys != NULL) {
            filters = filter_keys->elts;
            n = filter_keys->nelts;
            for (j = 0; j < n; j++) {
                tmp_str = njt_array_push(array);
                if (tmp_str == NULL) {
                    goto err;
                }
                tmp_str->len = filters[j].filter_key.value.len + filters[j].filter_name.value.len + 5; // "filter_key" "filter_value"
                tmp_str->data = njt_pcalloc(pool, tmp_str->len);
                buf = tmp_str->data;
                if (buf == NULL) {
                    goto err;
                }
                njt_snprintf(buf, tmp_str->len, "\"%V\" \"%V\"", &filters[j].filter_key.value, &filters[j].filter_name.value);
            }
            for (j = 0; j < array->nelts; ++j) {
                tmp_str = (njt_str_t *)(array->elts) + j;
                add_item_dynsts_servers_item_server_traffic_status_filter_by_set_key(server_item->server_traffic_status_filter_by_set_key, tmp_str);
            }
        }

        add_item_dynsts_servers(dynjson_obj.servers, server_item);
    }
    return to_json_dynsts(pool, &dynjson_obj, OMIT_NULL_ARRAY | OMIT_NULL_OBJ | OMIT_NULL_STR);

err:
    return &dyn_sts_err_msg;
}

static u_char *njt_stream_dyn_sts_get_handler(njt_str_t *topic, njt_str_t *request, int *len, void *data)
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
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_map_rpc_handler create pool error");
        goto out;
    }

    msg = njt_stream_dyn_sts_dump_conf(cycle, pool);

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

static njt_int_t  njt_dyn_sts_get_filter_token(njt_str_t *str, njt_str_t *filter_token)
{
    u_char *p, *end, tmpchar;
    njt_uint_t i;

    if (!str || !str->data || str->len == 0) {
        njt_str_set(filter_token, "");
        return NJT_OK;
    }
    end = str->data + str->len;
    for (i = 0; str->data[i] == ' ' && i < str->len; i++);
    str->data += i;
    str->len -= i;

    tmpchar = ' ';
    p = str->data;
    if (*p == '"') {
        tmpchar = '"';
        p++;
        filter_token->data = p;
    } else {
        filter_token->data = str->data;
    }
    //found the end of first string
    for (; *p != tmpchar && p < end; p++);

    if (tmpchar == '"' && *p != '"') return NJT_ERROR;
    filter_token->len = p - filter_token->data;

    if (tmpchar == '"')  p++;
    str->data = p;
    str->len = end - p;

    return NJT_OK;
}

static njt_int_t  njt_dyn_sts_get_filter_key_name(njt_str_t *filter_str, njt_str_t *filter_key, njt_str_t *filter_name)
{
    njt_str_t tmpstr;
    njt_int_t rc;

    if (!filter_str || !filter_str->data || filter_str->len == 0) {
        return NJT_ERROR;
    }
    tmpstr.data = filter_str->data;
    tmpstr.len = filter_str->len;
    rc = njt_dyn_sts_get_filter_token(&tmpstr, filter_key);
    if (rc != NJT_OK) return rc;

    return njt_dyn_sts_get_filter_token(&tmpstr, filter_name);
}

static njt_int_t njt_dyn_sts_check_filter_variable(njt_str_t *dynconf, njt_rpc_result_t *rpc_result)
{
    njt_stream_core_main_conf_t *cmcf;
    njt_uint_t                               i, flag;
    njt_str_t                                flt;
    njt_str_t                                fk;
    njt_hash_key_t *key, *pkey;
    u_char data_buf[1024];
    u_char *end;
    njt_str_t rpc_data_str;
    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;

    flt.data = dynconf->data;
    flt.len = dynconf->len;

    cmcf = njt_stream_cycle_get_module_main_conf(njt_cycle, njt_stream_core_module);
    key = cmcf->variables_keys->keys.elts;
    pkey = cmcf->prefix_variables.elts;

    while (flt.len > 0) {
        while (flt.len > 0 && *flt.data != '$') {
            flt.len--;
            flt.data++;
        }

        if (flt.len > 0 && *flt.data == '$') {
            fk.data = flt.data;
            fk.len = 1;
            flt.len--;
            flt.data++;
        } else {
            continue;
        }

        while (flt.len > 0 && ((*flt.data >= 'A' && *flt.data <= 'Z')
            || (*flt.data >= 'a' && *flt.data <= 'z')
            || (*flt.data >= '0' && *flt.data <= '9')
            || *flt.data == '_')) {
            flt.len--;
            flt.data++;
            fk.len++;
        }

        flag = 0;
        for (i = 0; i < cmcf->variables_keys->keys.nelts; i++) {
            if (fk.len - 1 == key[i].key.len && njt_strncasecmp(fk.data + 1, key[i].key.data, fk.len - 1) == 0) {
                flag = 1;
            }
        }
        if (!flag) {
            for (i = 0; i < cmcf->prefix_variables.nelts; i++) {
                if (pkey[i].key.len > 0 && pkey[i].key.len < fk.len - 1 && njt_strncasecmp(fk.data + 1, pkey[i].key.data, pkey[i].key.len) == 0) {
                    flag = 1;
                }
            }
        }

        if (!flag) {
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, "found unknown var %V in filter: %V", &fk, dynconf);
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_PARTIAL_SUCCESS);
            return NJT_ERROR;
        }
    }
    return NJT_OK;
}

static njt_int_t  njt_dyn_sts_update_filters(njt_pool_t *pool, njt_stream_server_traffic_status_conf_t *stscf, dynsts_servers_item_server_traffic_status_filter_by_set_key_t *filters, njt_rpc_result_t *rpc_result)
{
    njt_uint_t i;
    njt_int_t rc;
    njt_conf_t *cf;
    njt_str_t *filter_str;
    njt_str_t filter_key, filter_name;
    njt_str_t filter_complex_tmp;
    njt_stream_compile_complex_value_t          ccv;
    njt_stream_server_traffic_status_conf_t old_cf;
    njt_array_t *filter_keys;
    njt_stream_conf_ctx_t *conf_ctx;
    njt_stream_server_traffic_status_filter_t *filter;
    u_char data_buf[1024];
    u_char *end;
    njt_str_t rpc_data_str;
    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;

    conf_ctx = (njt_stream_conf_ctx_t *)njt_get_conf(njt_cycle->conf_ctx, njt_stream_module);
    if (conf_ctx == NULL) 
    {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "can't get stream conf context in njt_dyn_sts_update_filters");
        return NJT_ERROR;
    }
    njt_conf_t cf_data = {
        .pool = pool,
        .temp_pool = pool,
        .cycle = (njt_cycle_t *)njt_cycle,
        .log = pool->log,
        .ctx = conf_ctx ,
    };
    cf = &cf_data;

    old_cf = *stscf;

    stscf->dynamic = 1;
    stscf->dyn_pool = pool;

    if (filters && filters->nelts > 0) {
        filter_keys = njt_array_create(pool, 1,
            sizeof(njt_stream_server_traffic_status_filter_t));
        if (filter_keys == NULL) {
            goto error;
        }
        stscf->filter_keys = filter_keys;
        for (i = 0;i < filters->nelts;i++) {
            filter_str = get_dynsts_servers_item_server_traffic_status_filter_by_set_key_item(filters, i);
           // " aa$remote_add bb  $server_name"
            rc = njt_dyn_sts_check_filter_variable(filter_str, rpc_result);
            if (rc != NJT_OK) {
                continue;
            }

            rc = njt_dyn_sts_get_filter_key_name(filter_str, &filter_key, &filter_name);
            if (rc != NJT_OK) {
                end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " wrong filter: %V", filter_str);
                rpc_data_str.len = end - data_buf;
                njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_PARTIAL_SUCCESS);
                continue;
            } else {
                filter = njt_array_push(filter_keys);
                if (filter == NULL) {
                    goto error;
                }
                filter_complex_tmp.data = njt_pstrdup(pool, &filter_key);
                filter_complex_tmp.len = filter_key.len;
                njt_memzero(&ccv, sizeof(njt_stream_compile_complex_value_t));

                ccv.cf = cf;
                ccv.value = &filter_complex_tmp;
                ccv.complex_value = &filter->filter_key;
                if (njt_stream_compile_complex_value(&ccv) != NJT_OK) {
                    goto error;
                }

                filter_complex_tmp.data = njt_pstrdup(pool, &filter_name);
                filter_complex_tmp.len = filter_name.len;
                njt_memzero(&ccv, sizeof(njt_stream_compile_complex_value_t));
                ccv.cf = cf;
                ccv.value = &filter_complex_tmp;
                ccv.complex_value = &filter->filter_name;

                if (njt_stream_compile_complex_value(&ccv) != NJT_OK) {
                    goto error;
                }
            }
        }
    } else {
        stscf->filter_keys = NULL;
    }

    if (old_cf.dynamic && old_cf.dyn_pool != NULL) {
        njt_destroy_pool(old_cf.dyn_pool);
    }
    return NJT_OK;

error:
    *stscf = old_cf;
    return NJT_ERROR;
}

static njt_int_t njt_dyn_sts_update_conf(dynsts_t *api_data, njt_rpc_result_t *rpc_result)
{
    dynsts_servers_item_t *dsi;
    njt_str_t *port;
    njt_stream_core_srv_conf_t *cscf;
    njt_stream_server_traffic_status_conf_t *stscf;
    njt_uint_t i;
    njt_int_t rc;
    u_char data_buf[1024];
    u_char *end;
    njt_str_t rpc_data_str;

    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;
    njt_rpc_result_set_conf_path(rpc_result, &rpc_data_str);

    for (i = 0; i < api_data->servers->nelts; i++) {
        dsi = get_dynsts_servers_item(api_data->servers, i);
        port = get_dynsts_servers_item_listens_item(dsi->listens, 0);
        if (dsi->listens->nelts < 1) {
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " server parameters error, listens is empty,at position %d", i);
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            continue;
        }
        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, "servers[%V]", port);
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_set_conf_path(rpc_result, &rpc_data_str);
        //get stream conf
        cscf = njt_stream_get_srv_by_port((njt_cycle_t *)njt_cycle, port);
        if (cscf == NULL) {
            if (port != NULL) {
                njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "can`t find server by listen:%V;",
                    port);
                end = njt_snprintf(data_buf, sizeof(data_buf) - 1, "can not find server.");
                rpc_data_str.len = end - data_buf;
                njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            }
            continue;
        }

        stscf = njt_stream_get_module_srv_conf(cscf->ctx, njt_stream_stsc_module);
        if (stscf) {
            stscf->enable = get_dynsts_servers_item_server_traffic_status(dsi);
            dynsts_servers_item_server_traffic_status_filter_by_set_key_t *filters = get_dynsts_servers_item_server_traffic_status_filter_by_set_key(dsi);

            njt_pool_t *dyn_conf_pool = njt_create_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
            if (dyn_conf_pool == NULL) {
                end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " create pool error");
                rpc_data_str.len = end - data_buf;
                njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                return NJT_ERROR;
            }
            rc = njt_sub_pool(njt_cycle->pool, dyn_conf_pool);
            if (rc != NJT_OK) {
                end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " create pool error");
                rpc_data_str.len = end - data_buf;
                njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                njt_destroy_pool(dyn_conf_pool);
                return NJT_ERROR;
            }
            rpc_data_str.len = 0;
            rc = njt_dyn_sts_update_filters(dyn_conf_pool, stscf, filters, rpc_result);
            if (rc != NJT_OK) {
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " error in njt_dyn_sts_update_filters");
                if (0 == rpc_data_str.len) {
                    end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " njt_dyn_sts_update_filters error;");
                    rpc_data_str.len = end - data_buf;
                }
                njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                njt_destroy_pool(dyn_conf_pool);
            } else {
                njt_rpc_result_add_success_count(rpc_result);
            }
        }
    }

    return NJT_OK;
}

static int njt_stream_dyn_sts_put_handler_internal(njt_str_t *key, njt_str_t *value, void *data, njt_str_t *out_msg)
{
    njt_int_t rc;
    dynsts_t *api_data = NULL;
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
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_sts_change_handler create pool error");
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_MEM_ALLOC);
        rc = NJT_ERROR;
        goto rpc_msg;
    }

    api_data = json_parse_dynsts(pool, value, &err_info);
    if (api_data == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "json_parse_dynsts err: %V", &err_info.err_str);
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_JSON);
        njt_rpc_result_set_msg2(rpc_result, &err_info.err_str);
        rc = NJT_ERROR;
        goto rpc_msg;
    }

    rc = njt_dyn_sts_update_conf(api_data, rpc_result);

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

static int njt_stream_dyn_sts_change_handler(njt_str_t *key, njt_str_t *value, void *data)
{
    return njt_stream_dyn_sts_put_handler_internal(key, value, data, NULL);
}

static u_char *njt_stream_dyn_sts_put_handler(njt_str_t *topic, njt_str_t *request, int *len, void *data)
{
    njt_str_t err_json_msg;
    njt_str_null(&err_json_msg);
    njt_stream_dyn_sts_put_handler_internal(topic, request, data, &err_json_msg);
    *len = err_json_msg.len;
    return err_json_msg.data;
}

static njt_int_t njt_stream_dyn_sts_module_init_process(njt_cycle_t *cycle)
{
    njt_str_t rpc_key = njt_string("stream_dyn_sts");
    njt_kv_reg_handler_t h;
    njt_memzero(&h, sizeof(njt_kv_reg_handler_t));
    h.key = &rpc_key;
    h.rpc_get_handler = njt_stream_dyn_sts_get_handler;
    h.rpc_put_handler = njt_stream_dyn_sts_put_handler;
    h.handler = njt_stream_dyn_sts_change_handler;
    h.api_type = NJT_KV_API_TYPE_DECLATIVE;
    njt_kv_reg_handler(&h);

    return NJT_OK;
}

static njt_stream_module_t njt_stream_dyn_sts_module_ctx = {
    NULL, /* preconfiguration */
    NULL, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL /* merge server configuration */
};

njt_module_t njt_stream_dyn_sts_module = {
    NJT_MODULE_V1,
    &njt_stream_dyn_sts_module_ctx,       /* module context */
    NULL,                                 /* module directives */
    NJT_STREAM_MODULE,                    /* module type */
    NULL,                                 /* init master */
    NULL,                                 /* init module */
    njt_stream_dyn_sts_module_init_process, /* init process */
    NULL,                                 /* init thread */
    NULL,                                 /* exit thread */
    NULL,                                 /* exit process */
    NULL,                                 /* exit master */
    NJT_MODULE_V1_PADDING };
