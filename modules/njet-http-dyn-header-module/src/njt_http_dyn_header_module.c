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
#include "njt_http_dyn_header_parser.h"
#include <njt_http_ext_module.h>

extern njt_module_t njt_http_headers_filter_module;
extern njt_http_set_header_t  njt_http_set_headers[];
njt_str_t dyn_header_update_srv_err_msg = njt_string("{\"code\":500,\"msg\":\"server error\"}");



static njt_int_t njt_dyn_header_set_header(njt_pool_t *pool, dynheaders_servers_item_locations_item_t *data, njt_http_conf_ctx_t *ctx, njt_rpc_result_t *rpc_result)
{
    njt_http_headers_conf_t *alcf, old_cf;
    dynheaders_locationDef_headers_item_t *header_item;
    njt_http_header_val_t *hv;
    njt_http_set_header_t              *set;
    njt_http_compile_complex_value_t    ccv;
    njt_str_t    ret;
    njt_uint_t i,j;
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

    alcf = njt_http_conf_get_module_loc_conf(cf, njt_http_headers_filter_module);
    if (alcf == NULL) {
        return NJT_ERROR;
    }

    old_cf = *alcf;
    alcf->dynamic = 1;



    alcf->headers = njt_array_create(pool, 4,
        sizeof(njt_http_header_val_t));
    if (alcf->headers == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "can't create access rule arrays ");
        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, "can't create access rule arrays");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);

        goto error;
    }
    if (data->headers) {
        for (i = 0; i < data->headers->nelts; i++) {
            header_item = get_dynheaders_locationDef_headers_item(data->headers, i);
            if(header_item->key.len == 0) {
                end = njt_snprintf(data_buf, sizeof(data_buf) - 1, "header key can't null");
                rpc_data_str.len = end - data_buf;
                njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_PARTIAL_SUCCESS);
     
                goto error;
            }
            if(header_item->value.len != 0) {
                ret = njt_http_util_check_str_variable(&header_item->value);  //判段是否有，没定义的变量。
                if(ret.len != 0) {
                     end = njt_snprintf(data_buf, sizeof(data_buf) - 1, "header contains undefined variables %V",&header_item->value);
                    rpc_data_str.len = end - data_buf;
                    njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                    njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_PARTIAL_SUCCESS);
         
                    goto error;
                } 
            }
            hv = njt_array_push(alcf->headers);
            if (hv == NULL) {
                end = njt_snprintf(data_buf, sizeof(data_buf) - 1, "can't create hv");
                rpc_data_str.len = end - data_buf;
                njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_PARTIAL_SUCCESS);
                goto error;
            }
            hv->key.data = njt_pstrdup(pool,&header_item->key);
            hv->key.len  = header_item->key.len;
  
            hv->ori_value.data = njt_pstrdup(pool,&header_item->value);
            hv->ori_value.len  = header_item->value.len;

            hv->always    = (header_item->always ?1:0);
            hv->handler = NULL;
            hv->offset = 0;

            
            hv->handler = njt_http_add_header;

            set = njt_http_set_headers;
            for (j = 0; set[j].name.len; j++) {
                if (njt_strcasecmp(header_item->key.data, set[j].name.data) != 0) {
                    continue;
                }

                hv->offset = set[j].offset;
                hv->handler = set[j].handler;

                break;
            }
            if (header_item->value.len == 0) {
                njt_memzero(&hv->value, sizeof(njt_http_complex_value_t));

            } else {
                njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

                ccv.cf = cf;
                ccv.value = &hv->ori_value;
                ccv.complex_value = &hv->value;
                if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
                    end = njt_snprintf(data_buf, sizeof(data_buf) - 1, "compile[%V] complex error!",&hv->value);
                    rpc_data_str.len = end - data_buf;
                    njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                    njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_PARTIAL_SUCCESS);
                    goto error;
                }
            }
        }
    }
    if (old_cf.dynamic && old_cf.headers != NULL) {
        if(old_cf.headers->pool != NULL) {
            njt_destroy_pool(old_cf.headers->pool);
        }
    } 
    return NJT_OK;

error:
    *alcf = old_cf;
    return NJT_ERROR;
}

static njt_int_t njt_dyn_header_update_locs(dynheaders_servers_item_locations_t *locs, njt_queue_t *q, njt_http_conf_ctx_t *ctx, njt_rpc_result_t *rpc_result)
{
    njt_http_core_loc_conf_t *clcf;
    njt_http_location_queue_t *hlq;
    njt_http_headers_conf_t   *headcf;
    dynheaders_servers_item_locations_item_t *loc_item;
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
        loc_item = get_dynheaders_servers_item_locations_item(locs, j);
        if (loc_item == NULL || !loc_item->is_location_set) {
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " index %d not set location name", j);
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            continue;
        }

        name = get_dynheaders_locationDef_location(loc_item);
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

                headcf = clcf->loc_conf[njt_http_headers_filter_module.ctx_index];
                if ( !(headcf == NULL || (headcf->headers != NULL &&  headcf->headers->nelts == 0  && loc_item->headers->nelts == 0))) {
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
				njt_destroy_pool(pool);
				return NJT_ERROR;
			}
			rpc_data_str.len = 0;
			rc = njt_dyn_header_set_header(pool, loc_item, ctx, rpc_result);
			if (rc != NJT_OK) {
				njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " error in njt_dyn_header_set_header");
				if (0 == rpc_data_str.len) {
					end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " njt_dyn_header_set_header error[%V];", name);
					rpc_data_str.len = end - data_buf;
				}
				njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
				njt_destroy_pool(pool);
			} else {
				njt_rpc_result_add_success_count(rpc_result);
			}
		}

                if (loc_item->is_locations_set && loc_item->locations && loc_item->locations->nelts > 0) {
                    if (rpc_result) {
                        conf_path = rpc_result->conf_path;
                    }
                    njt_dyn_header_update_locs(loc_item->locations, clcf->old_locations, ctx, rpc_result);
                    if (rpc_result) {
                        rpc_result->conf_path = conf_path;
                    }
                }
                break;
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

static void njt_dyn_header_dump_locs(njt_pool_t *pool, njt_queue_t *locations, dynheaders_servers_item_locations_t *loc_items)
{
    dynheaders_servers_item_locations_item_t *loc_item;
    dynheaders_locationDef_headers_item_t *header_item;
    njt_http_core_loc_conf_t *clcf;
    njt_http_location_queue_t *hlq;
    njt_queue_t *q, *tq;
    njt_http_headers_conf_t *alcf;
    njt_http_header_val_t *hv;
    njt_uint_t i;
    njt_array_t          *array;

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
        alcf = njt_http_get_module_loc_conf(clcf, njt_http_headers_filter_module);

        loc_item = create_dynheaders_locationDef(pool);
        set_dynheaders_locationDef_location(loc_item,&clcf->full_name);
        add_item_dynheaders_servers_item_locations(loc_items, loc_item);
        array =  alcf->headers;
        if (array != NULL) {
            set_dynheaders_locationDef_headers(loc_item, create_dynheaders_locationDef_headers(pool, alcf->headers->nelts));
            if (loc_item->headers == NULL) {
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "can`t create headers array"
                );
                return;
            }
            hv = array->elts;
            // iterate headers 
            for (i = 0; i < alcf->headers->nelts; i++) {
                header_item = create_dynheaders_locationDef_headers_item(pool);
                add_item_dynheaders_locationDef_headers(loc_item->headers, header_item);
                set_dynheaders_locationDef_headers_item_key(header_item,&hv[i].key);
                set_dynheaders_locationDef_headers_item_value(header_item,&hv[i].ori_value);
                set_dynheaders_locationDef_headers_item_always(header_item,hv[i].always == 1?true:false);
            }
        }

        if (clcf->old_locations) {
            set_dynheaders_locationDef_locations(loc_item, create_dynheaders_locationDef_locations(pool, 4));
            if (loc_item->locations != NULL) {
                njt_dyn_header_dump_locs(pool, clcf->old_locations, loc_item->locations);
            } 
        }

    }

}

static njt_str_t *njt_dyn_header_dump_conf(njt_cycle_t *cycle, njt_pool_t *pool)
{
    njt_http_core_loc_conf_t *clcf;
    njt_http_core_main_conf_t *hcmcf;
    njt_http_core_srv_conf_t **cscfp;
    njt_uint_t i, j;
    njt_array_t *array;
    njt_str_t *tmp_str;
    njt_http_server_name_t *server_name;

    dynheaders_t dynjson_obj;
    dynheaders_servers_item_t *server_item;

    njt_memzero(&dynjson_obj, sizeof(dynheaders_t));
    hcmcf = njt_http_cycle_get_module_main_conf(cycle, njt_http_core_module);
    if (hcmcf == NULL) {
        goto err;
    }

    set_dynheaders_servers(&dynjson_obj, create_dynheaders_servers(pool, 4));
    if (dynjson_obj.servers == NULL) {
        goto err;
    }

    cscfp = hcmcf->servers.elts;
    for (i = 0; i < hcmcf->servers.nelts; i++) {
        server_item = create_dynheaders_servers_item(pool);
        if(server_item == NULL){
            goto err;
        }

        set_dynheaders_servers_item_listens(server_item,   create_dynheaders_servers_item_listens(pool, 4));
        set_dynheaders_servers_item_serverNames(server_item, create_dynheaders_servers_item_serverNames(pool, 4));
        set_dynheaders_servers_item_locations(server_item, create_dynheaders_servers_item_locations(pool, 4));

        array = njt_array_create(pool, 4, sizeof(njt_str_t));
        if(array == NULL){
            goto err;
        }
        njt_http_get_listens_by_server(array, cscfp[i]);

        for (j = 0; j < array->nelts; ++j) {
            tmp_str = (njt_str_t *)(array->elts) + j;
            add_item_dynheaders_servers_item_listens(server_item->listens, tmp_str);
        }

        server_name = cscfp[i]->server_names.elts;
        for (j = 0; j < cscfp[i]->server_names.nelts; ++j) {
            tmp_str = &server_name[j].full_name;
            add_item_dynheaders_servers_item_serverNames(server_item->serverNames, tmp_str);
        }

        clcf = njt_http_get_module_loc_conf(cscfp[i]->ctx, njt_http_core_module);
        if(clcf != NULL){
            njt_dyn_header_dump_locs(pool, clcf->old_locations, server_item->locations);
        }
        add_item_dynheaders_servers(dynjson_obj.servers, server_item);
    }

    return to_json_dynheaders(pool, &dynjson_obj, OMIT_NULL_ARRAY | OMIT_NULL_OBJ | OMIT_NULL_STR);

err:
    return &dyn_header_update_srv_err_msg;

}

static njt_int_t njt_dyn_header_update_conf(njt_pool_t *pool, dynheaders_t *api_data, njt_rpc_result_t *rpc_result)
{
    njt_cycle_t *cycle;
    njt_http_core_srv_conf_t *cscf;
    njt_http_core_loc_conf_t *clcf;
    dynheaders_servers_item_t *dsi;
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
        dsi = get_dynheaders_servers_item(api_data->servers, i);
        port = get_dynheaders_servers_item_listens_item(dsi->listens, 0);
        serverName = get_dynheaders_servers_item_serverNames_item(dsi->serverNames, 0);
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
        rc = njt_dyn_header_update_locs(dsi->locations, clcf->old_locations, &ctx, rpc_result);
        if (rc == NJT_OK) {
            njt_rpc_result_add_success_count(rpc_result);
        }
    }
    njt_http_variables_init_vars_dyn(NULL);
    njt_rpc_result_update_code(rpc_result);
    return NJT_OK;
}

static u_char *njt_dyn_header_rpc_get_handler(njt_str_t *topic, njt_str_t *request, int *len, void *data)
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
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_header_rpc_handler create pool error");
        goto out;
    }

    msg = njt_dyn_header_dump_conf(cycle, pool);
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

static int njt_dyn_header_change_handler_internal(njt_str_t *key, njt_str_t *value, void *data, njt_str_t *out_msg)
{
    njt_int_t rc;
    dynheaders_t *api_data = NULL;
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
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_header_change_handler create pool error");
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_MEM_ALLOC);
        rc = NJT_ERROR;
        goto rpc_msg;
    }

    api_data = json_parse_dynheaders(pool, value, &err_info);
    if (api_data == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "json_parse_dynheaders err: %V", &err_info.err_str);
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_JSON);
        njt_rpc_result_set_msg2(rpc_result, &err_info.err_str);
        rc = NJT_ERROR;
        goto rpc_msg;
    }

    rc = njt_dyn_header_update_conf(pool, api_data, rpc_result);

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

static int njt_dyn_header_change_handler(njt_str_t *key, njt_str_t *value, void *data)
{
    return njt_dyn_header_change_handler_internal(key, value, data, NULL);
}

static u_char *njt_dyn_header_rpc_put_handler(njt_str_t *topic, njt_str_t *request, int *len, void *data)
{
    njt_str_t err_json_msg;
    njt_str_null(&err_json_msg);
    njt_dyn_header_change_handler_internal(topic, request, data, &err_json_msg);
    *len = err_json_msg.len;
    return err_json_msg.data;
}

static njt_int_t njt_http_dyn_header_module_init_process(njt_cycle_t *cycle)
{
    njt_str_t header_rpc_key = njt_string("http_dyn_header");
    njt_str_t obj_loc_key = njt_string(LOCATION_DEL_EVENT);
    njt_str_t obj_vs_key = njt_string(VS_DEL_EVENT);
    njt_kv_reg_handler_t h;
    njt_memzero(&h, sizeof(njt_kv_reg_handler_t));
    h.key = &header_rpc_key;
    h.rpc_get_handler = njt_dyn_header_rpc_get_handler;
    h.rpc_put_handler = njt_dyn_header_rpc_put_handler;
    h.handler = njt_dyn_header_change_handler;
    h.api_type = NJT_KV_API_TYPE_DECLATIVE;
    njt_kv_reg_handler(&h);

    regist_update_fullconfig(&obj_loc_key,&header_rpc_key);
    regist_update_fullconfig(&obj_vs_key,&header_rpc_key);
    return NJT_OK;
}

static njt_http_module_t njt_http_dyn_header_module_ctx = {
    NULL, /* preconfiguration */
    NULL, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    NULL, /* create location configuration */
    NULL  /* merge location configuration */
};

njt_module_t njt_http_dyn_header_module = {
    NJT_MODULE_V1,
    &njt_http_dyn_header_module_ctx,         /* module context */
    NULL,                                    /* module directives */
    NJT_HTTP_MODULE,                         /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    njt_http_dyn_header_module_init_process, /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NJT_MODULE_V1_PADDING };
