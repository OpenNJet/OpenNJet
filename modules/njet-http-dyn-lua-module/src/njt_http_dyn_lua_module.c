/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */
#include <njt_core.h>
#include <njt_http_kv_module.h>
#include <njt_http.h>
#include <njt_json_util.h>
#include <njt_http_util.h>
#include <njt_rpc_result_util.h>
#include <njt_http_lua_common.h>
#include "njt_http_dyn_lua_parser.h"

extern njt_module_t njt_http_lua_module;
extern char njt_http_lua_code_cache_key;
extern njt_int_t njt_http_lua_content_handler_inline(njt_http_request_t *r);
extern njt_int_t njt_http_lua_content_handler(njt_http_request_t *r);
extern u_char *njt_http_lua_gen_chunk_cache_key(njt_conf_t *cf, const char *tag, const u_char *src, size_t src_len);
extern njt_int_t njt_http_lua_access_handler_inline(njt_http_request_t *r);
extern njt_int_t njt_http_lua_access_handler(njt_http_request_t *r);

njt_str_t dyn_http_server_update_srv_err_msg = njt_string("{\"code\":500,\"msg\":\"server error\"}");

static void njt_dyn_httplua_dump_locs(njt_pool_t *pool, njt_queue_t *locations, dynhttplua_servers_item_locations_t *loc_items)
{
    dynhttplua_servers_item_locations_item_t *loc_item;
    dynhttplua_locationDef_lua_t *lua_obj;
    njt_http_core_loc_conf_t *clcf;
    njt_http_location_queue_t *hlq;
    njt_queue_t *q, *tq;
    njt_http_lua_loc_conf_t *llcf;

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
        llcf = njt_http_get_module_loc_conf(clcf, njt_http_lua_module);

        loc_item = create_dynhttplua_locationDef(pool);
        set_dynhttplua_locationDef_location(loc_item, &clcf->full_name);
        add_item_dynhttplua_servers_item_locations(loc_items, loc_item);

        lua_obj = create_dynhttplua_locationDef_lua(pool);
        set_dynhttplua_locationDef_lua(loc_item, lua_obj);
        if (llcf) {
            if (llcf->content_handler == njt_http_lua_content_handler_inline
               && llcf->content_src.value.data) {
                set_dynhttplua_locationDef_lua_content_by(lua_obj, &llcf->content_src.value);
            }
            if (llcf->access_src.value.data) {
                set_dynhttplua_locationDef_lua_access_by(lua_obj, &llcf->access_src.value);
            }
        }

        if (clcf->old_locations) {
            set_dynhttplua_locationDef_locations(loc_item, create_dynhttplua_locationDef_locations(pool, 4));
            if (loc_item->locations != NULL) {
                njt_dyn_httplua_dump_locs(pool, clcf->old_locations, loc_item->locations);
            }
        }
    }
}

static njt_str_t *njt_dyn_http_lua_dump_conf(njt_cycle_t *cycle, njt_pool_t *pool)
{
    njt_http_core_loc_conf_t *clcf;
    njt_http_core_main_conf_t *hcmcf;
    njt_http_core_srv_conf_t **cscfp;
    njt_uint_t i, j;
    njt_array_t *array;
    njt_str_t *tmp_str;
    njt_http_server_name_t *server_name;

    dynhttplua_t dynjson_obj;
    dynhttplua_servers_item_t *server_item;

    njt_memzero(&dynjson_obj, sizeof(dynhttplua_t));
    hcmcf = njt_http_cycle_get_module_main_conf(cycle, njt_http_core_module);
    if (hcmcf == NULL) {
        goto err;
    }

    set_dynhttplua_servers(&dynjson_obj, create_dynhttplua_servers(pool, 4));
    if (dynjson_obj.servers == NULL) {
        goto err;
    }

    cscfp = hcmcf->servers.elts;
    for (i = 0; i < hcmcf->servers.nelts; i++) {
        server_item = create_dynhttplua_servers_item(pool);
        if (server_item == NULL) {
            goto err;
        }

        set_dynhttplua_servers_item_listens(server_item, create_dynhttplua_servers_item_listens(pool, 4));
        set_dynhttplua_servers_item_serverNames(server_item, create_dynhttplua_servers_item_serverNames(pool, 4));
        set_dynhttplua_servers_item_locations(server_item, create_dynhttplua_servers_item_locations(pool, 4));

        array = njt_array_create(pool, 4, sizeof(njt_str_t));
        if (array == NULL) {
            goto err;
        }
        njt_http_get_listens_by_server(array, cscfp[i]);

        for (j = 0; j < array->nelts; ++j) {
            tmp_str = (njt_str_t *)(array->elts) + j;
            add_item_dynhttplua_servers_item_listens(server_item->listens, tmp_str);
        }

        server_name = cscfp[i]->server_names.elts;
        for (j = 0; j < cscfp[i]->server_names.nelts; ++j) {
            tmp_str = &server_name[j].full_name;
            add_item_dynhttplua_servers_item_serverNames(server_item->serverNames, tmp_str);
        }

        clcf = njt_http_get_module_loc_conf(cscfp[i]->ctx, njt_http_core_module);
        if (clcf != NULL) {
            njt_dyn_httplua_dump_locs(pool, clcf->old_locations, server_item->locations);
        }
        add_item_dynhttplua_servers(dynjson_obj.servers, server_item);
    }

    return to_json_dynhttplua(pool, &dynjson_obj, OMIT_NULL_ARRAY | OMIT_NULL_OBJ | OMIT_NULL_STR);

err:
    return &dyn_http_server_update_srv_err_msg;

}

static njt_int_t njt_dyn_http_lua_set_lua(njt_pool_t *pool, dynhttplua_servers_item_locations_item_t *data, njt_http_conf_ctx_t *ctx, njt_rpc_result_t *rpc_result)
{
    njt_conf_t *cf;
    njt_http_lua_loc_conf_t *llcf, old_cf;
    njt_http_lua_main_conf_t *lmcf;
    njt_http_core_loc_conf_t *clcf;
    njt_http_conf_ctx_t *conf_ctx;
    dynhttplua_locationDef_lua_t *httplua_obj;
    lua_State *L;
    u_char *cache_key = NULL, *chunkname;

    njt_conf_t cf_data = {
        .pool = pool,
        .temp_pool = pool,
        .cycle = (njt_cycle_t *)njt_cycle,
        .log = pool->log,
        .ctx = ctx,
    };
    cf = &cf_data;

    llcf = njt_http_conf_get_module_loc_conf(cf, njt_http_lua_module);
    if (llcf == NULL) {
        return NJT_ERROR;
    }

    old_cf = *llcf;
    llcf->dynamic = 1;
    llcf->conf_pool = pool;

    httplua_obj = get_dynhttplua_locationDef_lua(data);
    if (httplua_obj) {
        conf_ctx = (njt_http_conf_ctx_t *)njt_get_conf(njt_cycle->conf_ctx, njt_http_module);
        lmcf = conf_ctx->main_conf[njt_http_lua_module.ctx_index];
        L = lmcf->lua;
        if (httplua_obj->is_content_by_set) {
            lmcf->requires_capture_filter = 1;
            chunkname = (u_char *)njt_pcalloc(pool, 17 + 2 * sizeof(uintptr_t));  //dyn_lua_content_%p
            njt_snprintf(chunkname, 17 + 2 * sizeof(uintptr_t), "dyn_lua_content_%p", ctx->loc_conf);
            cache_key = njt_http_lua_gen_chunk_cache_key(cf, "content_by_lua",
                httplua_obj->content_by.data,
                httplua_obj->content_by.len);
            if (cache_key == NULL) {
                goto error;
            }
            llcf->content_chunkname = chunkname;
            llcf->content_handler = njt_http_lua_content_handler_inline;
            /*  register location content handler */
            clcf = njt_http_conf_get_module_loc_conf(cf, njt_http_core_module);
            if (clcf == NULL) {
                goto error;
            }

            clcf->handler = njt_http_lua_content_handler;
            llcf->content_src.value.data = njt_pstrdup(pool, &httplua_obj->content_by);
            llcf->content_src.value.len = httplua_obj->content_by.len;
            /*  get code cache table */
            lua_pushlightuserdata(L, njt_http_lua_lightudata_mask(code_cache_key));
            lua_rawget(L, LUA_REGISTRYINDEX);   //cache
            if (llcf->content_src_key) {
                lua_pushnil(L);
                lua_setfield(L, -2, (const char *)llcf->content_src_key);
            }
            if (llcf->content_src_ref != LUA_NOREF && llcf->content_src_ref != LUA_REFNIL) {
                luaL_unref(L, -1, llcf->content_src_ref);
            }
            llcf->content_src_ref = LUA_REFNIL;
            /*  remove cache table*/
            lua_pop(L, 1);
            
            llcf->content_src_key = cache_key;
        } else {
           llcf->content_handler=NULL;
           llcf->content_src.value.data = NULL;
           llcf->content_src.value.len = 0;
           llcf->content_src_key = NULL;
        }
        if (httplua_obj->is_access_by_set) {
            lmcf->requires_capture_filter = 1;
            lmcf->requires_access = 1;
            chunkname = (u_char *)njt_pcalloc(pool, 16 + 2 * sizeof(uintptr_t));  //dyn_lua_access_%p
            njt_snprintf(chunkname, 16 + 2 * sizeof(uintptr_t), "dyn_lua_access_%p", ctx->loc_conf);
            cache_key = njt_http_lua_gen_chunk_cache_key(cf, "access_by_lua",
                httplua_obj->access_by.data,
                httplua_obj->access_by.len);
            if (cache_key == NULL) {
                goto error;
            }
            llcf->access_chunkname = chunkname;
            llcf->access_handler = njt_http_lua_access_handler_inline;
            llcf->access_src.value.data = njt_pstrdup(pool, &httplua_obj->access_by);
            llcf->access_src.value.len = httplua_obj->access_by.len;
            /*  get code cache table */
            lua_pushlightuserdata(L, njt_http_lua_lightudata_mask(code_cache_key));
            lua_rawget(L, LUA_REGISTRYINDEX);   //cache
            if (llcf->access_src_key) {
                lua_pushnil(L);
                lua_setfield(L, -2, (const char *)llcf->access_src_key);
            }
            if (llcf->access_src_ref != LUA_NOREF && llcf->access_src_ref != LUA_REFNIL) {
                luaL_unref(L, -1, llcf->access_src_ref);
            }
            llcf->access_src_ref = LUA_REFNIL;
            /*  remove cache table*/
            lua_pop(L, 1);
            
            llcf->access_src_key = cache_key;
        } else {
            llcf->access_handler = NULL;
            llcf->access_src.value.data = NULL;
            llcf->access_src.value.len = 0;
            llcf->access_src_key = NULL;
        }
    }

    if (old_cf.dynamic && old_cf.conf_pool != NULL) {
        njt_destroy_pool(old_cf.conf_pool);
    }
    return NJT_OK;

error:
    *llcf = old_cf;
    return NJT_ERROR;
}

static njt_int_t njt_dyn_http_lua_update_locs(dynhttplua_servers_item_locations_t *locs, njt_queue_t *q, njt_http_conf_ctx_t *ctx, njt_rpc_result_t *rpc_result)
{
    njt_http_core_loc_conf_t *clcf;
    njt_http_location_queue_t *hlq;
    dynhttplua_servers_item_locations_item_t *dbwl;
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
        dbwl = get_dynhttplua_servers_item_locations_item(locs, j);
        if (dbwl == NULL || !dbwl->is_location_set) {
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " index %d not set location name", j);
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            continue;
        }

        name = get_dynhttplua_locationDef_location(dbwl);
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
                rc = njt_dyn_http_lua_set_lua(pool, dbwl, ctx, rpc_result);
                if (rc != NJT_OK) {
                    njt_log_error(NJT_LOG_ERR, pool->log, 0, " error in njt_dyn_http_lua_set_lua");
                    if (0 == rpc_data_str.len) {
                        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " njt_dyn_http_lua_set_lua error[%V];", name);
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
                    njt_dyn_http_lua_update_locs(dbwl->locations, clcf->old_locations, ctx, rpc_result);
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

static njt_int_t njt_dyn_http_lua_update_conf(njt_pool_t *pool, dynhttplua_t *api_data, njt_rpc_result_t *rpc_result)
{
    njt_cycle_t *cycle;
    njt_http_core_srv_conf_t *cscf;
    njt_http_core_loc_conf_t *clcf;
    dynhttplua_servers_item_t *dsi;
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
        dsi = get_dynhttplua_servers_item(api_data->servers, i);
        port = get_dynhttplua_servers_item_listens_item(dsi->listens, 0);
        serverName = get_dynhttplua_servers_item_serverNames_item(dsi->serverNames, 0);
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
        rc = njt_dyn_http_lua_update_locs(dsi->locations, clcf->old_locations, &ctx, rpc_result);
        if (rc == NJT_OK) {
            njt_rpc_result_add_success_count(rpc_result);
        }
    }
    njt_rpc_result_update_code(rpc_result);
    return NJT_OK;
}


static u_char *njt_http_dyn_lua_get_handler(njt_str_t *topic, njt_str_t *request, int *len, void *data)
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
        njt_log_error(NJT_LOG_EMERG, pool->log, 0, "njt_http_dyn_lua_get_handler create pool error");
        goto out;
    }

    msg = njt_dyn_http_lua_dump_conf(cycle, pool);
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

static int njt_http_dyn_lua_change_handler_internal(njt_str_t *key, njt_str_t *value, void *data, njt_str_t *out_msg)
{
    njt_int_t rc;
    dynhttplua_t *api_data = NULL;
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
        njt_log_error(NJT_LOG_EMERG, pool->log, 0, "njt_dyn_http_lua_change_handler create pool error");
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_MEM_ALLOC);
        rc = NJT_ERROR;
        goto rpc_msg;
    }

    api_data = json_parse_dynhttplua(pool, value, &err_info);
    if (api_data == NULL) {
        njt_log_error(NJT_LOG_ERR, pool->log, 0, "json_parse_dynhttplua err: %V", &err_info.err_str);
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_JSON);
        njt_rpc_result_set_msg2(rpc_result, &err_info.err_str);
        rc = NJT_ERROR;
        goto rpc_msg;
    }

    rc = njt_dyn_http_lua_update_conf(pool, api_data, rpc_result);

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

static u_char *njt_http_dyn_lua_put_handler(njt_str_t *topic, njt_str_t *request, int *len, void *data)
{
    njt_str_t err_json_msg;
    njt_str_null(&err_json_msg);
    njt_http_dyn_lua_change_handler_internal(topic, request, data, &err_json_msg);
    *len = err_json_msg.len;
    return err_json_msg.data;
}

static int njt_http_dyn_lua_change_handler(njt_str_t *key, njt_str_t *value, void *data)
{
    return njt_http_dyn_lua_change_handler_internal(key, value, data, NULL);
}

static njt_int_t njt_http_dyn_lua_module_init_process(njt_cycle_t *cycle)
{
    njt_str_t rpc_key = njt_string("http_lua");
    njt_kv_reg_handler_t h;
    njt_memzero(&h, sizeof(njt_kv_reg_handler_t));
    h.key = &rpc_key;
    h.rpc_get_handler = njt_http_dyn_lua_get_handler;
    h.rpc_put_handler = njt_http_dyn_lua_put_handler;
    h.handler = njt_http_dyn_lua_change_handler;
    h.api_type = NJT_KV_API_TYPE_DECLATIVE;
    njt_kv_reg_handler(&h);

    return NJT_OK;
}

static njt_int_t
njt_http_dyn_lua_init(njt_conf_t *cf)
{
    njt_http_handler_pt        *h;
    njt_http_core_main_conf_t  *cmcf;

    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);

    h = njt_array_push(&cmcf->phases[NJT_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_http_lua_access_handler;

    return NJT_OK;
}

static njt_http_module_t njt_http_dyn_lua_module_ctx = {
    NULL, /* preconfiguration */
    njt_http_dyn_lua_init, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    NULL, /* create location configuration */
    NULL  /* merge location configuration */
};

njt_module_t njt_http_dyn_lua_module = {
    NJT_MODULE_V1,
    &njt_http_dyn_lua_module_ctx,         /* module context */
    NULL,                                 /* module directives */
    NJT_HTTP_MODULE,                      /* module type */
    NULL,                                 /* init master */
    NULL,                                 /* init module */
    njt_http_dyn_lua_module_init_process, /* init process */
    NULL,                                 /* init thread */
    NULL,                                 /* exit thread */
    NULL,                                 /* exit process */
    NULL,                                 /* exit master */
    NJT_MODULE_V1_PADDING };
