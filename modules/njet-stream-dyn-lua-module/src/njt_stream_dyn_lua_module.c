/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */
#include <njt_core.h>
#include <njt_http.h>
#include <njt_http_kv_module.h>
#include <njt_json_util.h>
#include <njt_rpc_result_util.h>
#include <njt_stream_lua_common.h>
#include <njt_stream_util.h>
#include <njt_stream_dyn_module.h>
#include "njt_stream_dyn_lua_parser.h"
#include <njt_stream.h>
#include <njt_http_ext_module.h>

extern njt_module_t njt_stream_lua_module;
extern char njt_stream_lua_code_cache_key;
extern void njt_stream_lua_content_handler(njt_stream_session_t *s);
extern njt_int_t njt_stream_lua_content_handler_inline(njt_stream_lua_request_t *r);
extern njt_int_t njt_stream_lua_preread_handler_inline(njt_stream_lua_request_t *r);
extern u_char *njt_stream_lua_digest_hex(u_char *dest, const u_char *buf, int buf_len);
extern njt_int_t njt_stream_lua_balancer_handler_inline(njt_stream_lua_request_t *r,
    njt_stream_lua_srv_conf_t *lscf, lua_State *L);

njt_str_t dyn_stream_lua_err_msg = njt_string("{\"code\":500,\"msg\":\"server error\"}");

static njt_str_t *njt_dyn_stream_lua_dump_conf(njt_cycle_t *cycle, njt_pool_t *pool)
{
    njt_uint_t i, j, k;
    njt_int_t rc;
    njt_array_t *array;
    njt_stream_core_srv_conf_t **servers;
    njt_stream_core_main_conf_t *cmcf;
    njt_str_t *tmp_str;
    njt_stream_upstream_main_conf_t *umcf;
    njt_stream_upstream_srv_conf_t **uscf_array;

    dynstreamlua_t dynjson_obj;
    dynstreamlua_servers_item_t *server_item;
    dynstreamlua_servers_item_lua_t *lua_obj;
    njt_stream_lua_srv_conf_t *lscf;
    dynstreamlua_upstreams_item_t *upstream_item;
    njt_stream_server_name_t *server_name;

    njt_memzero(&dynjson_obj, sizeof(dynstreamlua_t));
    cmcf = njt_stream_cycle_get_module_main_conf(cycle, njt_stream_core_module);
    if (cmcf == NULL) {
        goto err;
    }

    // Get the upstream module's main configuration
    umcf = njt_stream_cycle_get_module_main_conf(cycle, njt_stream_upstream_module);
    if (umcf == NULL) {
        goto err;
    }

    // Initialize the upstreams array
    set_dynstreamlua_upstreams(&dynjson_obj, create_dynstreamlua_upstreams(pool, 4));
    if (dynjson_obj.upstreams == NULL) {
        goto err;
    }

    // Iterate through upstream blocks to find balancer_by_lua configurations
    uscf_array = (njt_stream_upstream_srv_conf_t **)umcf->upstreams.elts;
    for (k = 0; k < umcf->upstreams.nelts; k++) {
        njt_stream_upstream_srv_conf_t *uscf = uscf_array[k];
        njt_stream_lua_srv_conf_t *ulscf;
        njt_str_t *balancer_by_str;

        // Create a new upstream item
        upstream_item = create_dynstreamlua_upstreams_item(pool);
        if (upstream_item == NULL) {
            goto err;
        }

        // Set the upstream name
        set_dynstreamlua_upstreams_item_name(upstream_item, &uscf->host);

        // Get the Lua module's configuration for this upstream
        ulscf = uscf->srv_conf[njt_stream_lua_module.ctx_index];

        // Check if the balancer_by_lua configuration exists.
        // If it does, use the source. Otherwise, use an empty string.
        njt_str_t empty_str = njt_string("");
        if (ulscf && ulscf->balancer.handler == njt_stream_lua_balancer_handler_inline
            && ulscf->balancer.src.data) {
            balancer_by_str = &ulscf->balancer.src;
        } else {
            balancer_by_str = &empty_str;
        }

        // Set the balancer_by_lua source
        set_dynstreamlua_upstreams_item_balancer_by(upstream_item, balancer_by_str);

        // Add the upstream item to the upstreams array
        if (add_item_dynstreamlua_upstreams(dynjson_obj.upstreams, upstream_item) != NJT_OK) {
            goto err;
        }
    }

    set_dynstreamlua_servers(&dynjson_obj, create_dynstreamlua_servers(pool, 4));
    if (dynjson_obj.servers == NULL) {
        goto err;
    }

    servers = (njt_stream_core_srv_conf_t **)cmcf->servers.elts;
    for (i = 0; i < cmcf->servers.nelts; i++) {
        server_item = create_dynstreamlua_servers_item(pool);
        if (server_item == NULL) {
            goto err;
        }
        set_dynstreamlua_servers_item_listens(server_item, create_dynstreamlua_servers_item_listens(pool, 4));
        set_dynstreamlua_servers_item_serverNames(server_item, create_dynstreamlua_servers_item_serverNames(pool, 4));

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
            add_item_dynstreamlua_servers_item_listens(server_item->listens, tmp_str);
        }

        server_name = servers[i]->server_names.elts;
        for (j = 0; j < servers[i]->server_names.nelts; ++j) {
            if (server_name[j].full_name.data) {
                tmp_str = &server_name[j].full_name;
            } else {
                tmp_str = &server_name[j].name;
            }
            add_item_dynstreamlua_servers_item_serverNames(server_item->serverNames, tmp_str);
        }

        lua_obj = create_dynstreamlua_servers_item_lua(pool);
        set_dynstreamlua_servers_item_lua(server_item, lua_obj);

        lscf = njt_stream_get_module_srv_conf(servers[i]->ctx, njt_stream_lua_module);

        if (lscf) {
            // Check for content_handler
            if (lscf->content_handler == njt_stream_lua_content_handler_inline
                && lscf->content_src.value.data) {
                set_dynstreamlua_servers_item_lua_content_by(lua_obj, &lscf->content_src.value);
            }

            // Check for preread_handler
            if (lscf->preread_handler == njt_stream_lua_preread_handler_inline
                && lscf->preread_src.value.data) {
                set_dynstreamlua_servers_item_lua_preread_by(lua_obj, &lscf->preread_src.value);
            }
        }
        add_item_dynstreamlua_servers(dynjson_obj.servers, server_item);
    }
    return to_json_dynstreamlua(pool, &dynjson_obj, OMIT_NULL_ARRAY | OMIT_NULL_OBJ | OMIT_NULL_STR);

err:
    return &dyn_stream_lua_err_msg;
}

static u_char *njt_dyn_stream_lua_gen_chunk_cache_key(njt_pool_t *pool, const char *tag,
    const u_char *src, size_t src_len)
{
    u_char *p, *out;
    size_t       tag_len;

    tag_len = njt_strlen(tag);
    out = njt_palloc(pool,
        tag_len + NJT_STREAM_LUA_INLINE_KEY_LEN + 1);
    if (out == NULL) {
        return NULL;
    }
    p = njt_copy(out, tag, tag_len);
    p = njt_copy(p, NJT_STREAM_LUA_INLINE_TAG,
        NJT_STREAM_LUA_INLINE_TAG_LEN);
    p = njt_stream_lua_digest_hex(p, src, src_len);
    *p = '\0';
    return out;
}

static njt_int_t njt_dyn_stream_lua_set_lua(njt_pool_t *pool, dynstreamlua_servers_item_t *data, njt_stream_conf_ctx_t *ctx, njt_rpc_result_t *rpc_result)
{
    njt_conf_t *cf;
    njt_stream_lua_srv_conf_t *lscf, old_cf;
    njt_stream_core_srv_conf_t *cscf;
    njt_stream_conf_ctx_t *conf_ctx;
    dynstreamlua_servers_item_lua_t *lua_obj;
    lua_State *L;
    u_char *cache_key = NULL;

    njt_conf_t cf_data = {
        .pool = pool,
        .temp_pool = pool,
        .cycle = (njt_cycle_t *)njt_cycle,
        .log = pool->log,
        .ctx = ctx,
    };
    cf = &cf_data;


    lscf = njt_stream_conf_get_module_srv_conf(cf, njt_stream_lua_module);
    if (lscf == NULL) {
        njt_log_error(NJT_LOG_ERR, pool->log, 0, "failed to get stream lua srv conf");
        return NJT_ERROR;
    }


    old_cf = *lscf;
    lscf->dynamic = 1;
    lscf->conf_pool = pool;

    lua_obj = get_dynstreamlua_servers_item_lua(data);
    if (lua_obj) {
        conf_ctx = (njt_stream_conf_ctx_t *)njt_get_conf(njt_cycle->conf_ctx, njt_stream_module);
        L = ((njt_stream_lua_main_conf_t *)conf_ctx->main_conf[njt_stream_lua_module.ctx_index])->lua;
        if (L == NULL) {
            njt_log_error(NJT_LOG_ERR, pool->log, 0, "failed to get lua state");
            goto error;
        }

        if (lua_obj->is_content_by_set) {
            cache_key = njt_dyn_stream_lua_gen_chunk_cache_key(pool, "content_by_lua", lua_obj->content_by.data, lua_obj->content_by.len);
            if (cache_key == NULL) {
                njt_log_error(NJT_LOG_ERR, pool->log, 0, "failed to generate chunk name for content_by_lua");
                goto error;
            }
            lscf->content_handler = njt_stream_lua_content_handler_inline;
            cscf = njt_stream_conf_get_module_srv_conf(cf, njt_stream_core_module);
            if (cscf == NULL) {
                njt_log_error(NJT_LOG_ERR, pool->log, 0, "failed to get stream core srv conf");
                goto error;
            }
            cscf->handler = njt_stream_lua_content_handler;
            lscf->content_src.value.data = njt_pstrdup(pool, &lua_obj->content_by);
            lscf->content_src.value.len = lua_obj->content_by.len;
            lua_pushlightuserdata(L, njt_stream_lua_lightudata_mask(code_cache_key));
            lua_rawget(L, LUA_REGISTRYINDEX); // cache
            if (lscf->content_src_key) {
                lua_pushnil(L);
                lua_setfield(L, -2, (const char *)lscf->content_src_key);
            }
            lua_pop(L, 1);
            lscf->content_src_key = cache_key;
        } else {
            if (lscf->content_handler == njt_stream_lua_content_handler_inline) {
                lscf->content_handler = NULL;
                lscf->content_src.value.data = NULL;
                lscf->content_src.value.len = 0;
                lscf->content_src_key = NULL;
            }
        }

        if (lua_obj->is_preread_by_set) {
            cache_key = njt_dyn_stream_lua_gen_chunk_cache_key(pool, "preread_by_lua", lua_obj->preread_by.data, lua_obj->preread_by.len);
            if (cache_key == NULL) {
                njt_log_error(NJT_LOG_ERR, pool->log, 0, "failed to generate chunk name for preread_by_lua");
                goto error;
            }
            lscf->preread_handler = njt_stream_lua_preread_handler_inline;
            lscf->preread_src.value.data = njt_pstrdup(pool, &lua_obj->preread_by);
            lscf->preread_src.value.len = lua_obj->preread_by.len;
            lua_pushlightuserdata(L, njt_stream_lua_lightudata_mask(code_cache_key));
            lua_rawget(L, LUA_REGISTRYINDEX); // cache
            if (lscf->preread_src_key) {
                lua_pushnil(L);
                lua_setfield(L, -2, (const char *)lscf->preread_src_key);
            }
            lua_pop(L, 1);
            lscf->preread_src_key = cache_key;
        } else {
            if (lscf->preread_handler == njt_stream_lua_preread_handler_inline) {
                lscf->preread_handler = NULL;
                lscf->preread_src.value.data = NULL;
                lscf->preread_src.value.len = 0;
                lscf->preread_src_key = NULL;
            }
        }
    }

    if (old_cf.dynamic && old_cf.conf_pool != NULL) {
        njt_destroy_pool(old_cf.conf_pool);
    }
    return NJT_OK;

error:
    *lscf = old_cf;
    return NJT_ERROR;
}

static njt_int_t njt_dyn_stream_lua_update_upstreams(dynstreamlua_upstreams_t *upstreams, njt_rpc_result_t *rpc_result)
{
    njt_stream_upstream_main_conf_t *umcf;
    njt_stream_upstream_srv_conf_t **uscf_array;
    njt_stream_lua_srv_conf_t *ulscf, old_cf;
    dynstreamlua_upstreams_item_t *upstream_item;
    njt_uint_t k, i;
    u_char data_buf[1024];
    u_char *end;
    njt_int_t rc;
    njt_str_t conf_path;
    njt_str_t rpc_data_str;
    bool upstream_found;
    njt_str_t *name;
    u_char *cache_key = NULL;
    njt_stream_conf_ctx_t *conf_ctx;
    njt_pool_t *pool;
    lua_State *L;

    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;

    if (upstreams == NULL) {
        return NJT_OK;
    }

    umcf = njt_stream_cycle_get_module_main_conf(njt_cycle, njt_stream_upstream_module);
    if (umcf == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "failed to get stream upstream main conf");
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
        njt_rpc_result_set_msg(rpc_result, (u_char *)"failed to get stream upstream main conf");
        return NJT_ERROR;
    }

    conf_ctx = (njt_stream_conf_ctx_t *)njt_get_conf(njt_cycle->conf_ctx, njt_stream_module);
    L = ((njt_stream_lua_main_conf_t *)conf_ctx->main_conf[njt_stream_lua_module.ctx_index])->lua;
    if (L == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "failed to get lua state");
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
        njt_rpc_result_set_msg(rpc_result, (u_char *)"failed to get lua state");
        return NJT_ERROR;
    }

    uscf_array = (njt_stream_upstream_srv_conf_t **)umcf->upstreams.elts;
    for (k = 0; k < upstreams->nelts; k++) {
        upstream_item = get_dynstreamlua_upstreams_item(upstreams, k);
        if (upstream_item == NULL || !upstream_item->is_name_set) {
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, "index %d not set upstream name", k);
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            continue;
        }

        name = get_dynstreamlua_upstreams_item_name(upstream_item);
        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, "upstreams[%V]", name);
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_append_conf_path(rpc_result, &rpc_data_str);

        upstream_found = false;
        for (i = 0; i < umcf->upstreams.nelts; i++) {
            njt_stream_upstream_srv_conf_t *uscf = uscf_array[i];
            if (njt_strcmp(name->data, uscf->host.data) == 0 && name->len == uscf->host.len) {
                upstream_found = true;

                ulscf = uscf->srv_conf[njt_stream_lua_module.ctx_index];
                if (ulscf == NULL) {
                    end = njt_snprintf(data_buf, sizeof(data_buf) - 1, "failed to get lua srv conf for upstream %V", name);
                    rpc_data_str.len = end - data_buf;
                    njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                    break;
                }
                old_cf = *ulscf;
                if (upstream_item->is_balancer_by_set && upstream_item->balancer_by.len > 0) {
                    pool = njt_create_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
                    if (pool == NULL) {
                        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " create pool error");
                        rpc_data_str.len = end - data_buf;
                        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                        return NJT_ERROR;
                    }
                    rc = njt_sub_pool(uscf->pool, pool);
                    if (rc != NJT_OK) {
                        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " create pool error");
                        rpc_data_str.len = end - data_buf;
                        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                        njt_destroy_pool(pool);
                        return NJT_ERROR;
                    }

                    ulscf->dynamic = 1;
                    ulscf->conf_pool = pool;

                    cache_key = njt_dyn_stream_lua_gen_chunk_cache_key(pool, "balancer_by_lua", upstream_item->balancer_by.data, upstream_item->balancer_by.len);
                    if (cache_key == NULL) {
                        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, "failed to generate chunk name for balancer_by_lua");
                        rpc_data_str.len = end - data_buf;
                        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                        break;
                    }
                    ulscf->balancer.handler = njt_stream_lua_balancer_handler_inline;
                    ulscf->balancer.src.data = njt_pstrdup(pool, &upstream_item->balancer_by);
                    ulscf->balancer.src.len = upstream_item->balancer_by.len;
                    lua_pushlightuserdata(L, njt_stream_lua_lightudata_mask(code_cache_key));
                    lua_rawget(L, LUA_REGISTRYINDEX); // cache
                    if (ulscf->balancer.src_key) {
                        lua_pushnil(L);
                        lua_setfield(L, -2, (const char *)ulscf->balancer.src_key);
                    }
                    lua_pop(L, 1);
                    ulscf->balancer.src_key = cache_key;
                } else {
                    if (ulscf->balancer.handler == njt_stream_lua_balancer_handler_inline) {
                        ulscf->balancer.handler = NULL;
                        ulscf->balancer.src.data = NULL;
                        ulscf->balancer.src.len = 0;
                        ulscf->balancer.src_key = NULL;
                    }
                }

                if (old_cf.dynamic && old_cf.conf_pool != NULL) {
                    njt_destroy_pool(old_cf.conf_pool);
                }

                njt_rpc_result_add_success_count(rpc_result);
                break;
            }
        }

        if (!upstream_found) {
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, "upstream not found");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
        }

        if (rpc_result) {
            conf_path = rpc_result->conf_path;
            njt_rpc_result_set_conf_path(rpc_result, &conf_path);
        }
    }

    return NJT_OK;
}

static njt_int_t njt_dyn_stream_lua_update_conf(dynstreamlua_t *api_data, njt_rpc_result_t *rpc_result)
{
    njt_stream_core_srv_conf_t *cscf;
    dynstreamlua_servers_item_t *dsi;
    njt_str_t *port;
    njt_str_t *server_name;
    njt_str_t addr_port;
    njt_uint_t i;
    njt_pool_t *pool;
    njt_int_t rc;
    u_char tmp_buf[1024];
    u_char *end;
    u_char data_buf[1024];

    njt_str_t rpc_data_str;


    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;

    // Empty path
    njt_rpc_result_set_conf_path(rpc_result, &rpc_data_str);

    // Update upstreams
    if (njt_dyn_stream_lua_update_upstreams(api_data->upstreams, rpc_result) != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "failed to update upstreams");
    }

    // Update servers
    for (i = 0; i < api_data->servers->nelts; i++) {
        dsi = get_dynstreamlua_servers_item(api_data->servers, i);
        port = get_dynstreamlua_servers_item_listens_item(dsi->listens, 0);
        if (dsi->listens->nelts < 1) {
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, "server parameters error, listens is empty, at position %d", i);
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            continue;
        }

        addr_port.data = tmp_buf;
        end = njt_snprintf(tmp_buf, sizeof(tmp_buf) - 1, "%V", port);
        addr_port.len = end - tmp_buf;

        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, "servers[%V]", port);
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_set_conf_path(rpc_result, &rpc_data_str);

        server_name = get_dynstreamlua_servers_item_serverNames_item(dsi->serverNames, 0);
        cscf = njt_stream_get_srv_by_port((njt_cycle_t *)njt_cycle, &addr_port, server_name);
        if (cscf == NULL) {
            njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "cannot find server by listen:%V", port);
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, "cannot find server");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            continue;
        }

        njt_stream_conf_ctx_t ctx = *cscf->ctx;

        pool = njt_create_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
        if (pool == NULL) {
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " create pool error");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            return NJT_ERROR;
        }
        rc = njt_sub_pool(cscf->pool, pool);
        if (rc != NJT_OK) {
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " create pool error");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            njt_destroy_pool(pool);
            return NJT_ERROR;
        }

        rpc_data_str.len = 0;
        if (njt_dyn_stream_lua_set_lua(pool, dsi, &ctx, rpc_result) == NJT_OK) {
            njt_rpc_result_add_success_count(rpc_result);
        } else {
            njt_log_error(NJT_LOG_ERR, pool->log, 0, "error in njt_dyn_stream_lua_set_lua for server %V", port);
            if (0 == rpc_data_str.len) {
                end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " njt_dyn_stream_lua_set_lua error[%d];", i);
                rpc_data_str.len = end - data_buf;
            }
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            njt_destroy_pool(pool);

        }
    }

    njt_rpc_result_update_code(rpc_result);
    return NJT_OK;
}

static int njt_stream_dyn_lua_change_handler_internal(njt_str_t *key, njt_str_t *value, void *data, njt_str_t *out_msg)
{
    njt_int_t rc;
    dynstreamlua_t *api_data = NULL;
    njt_pool_t *pool = NULL;
    njt_json_manager json_manager;
    njt_rpc_result_t *rpc_result = NULL;
    js2c_parse_error_t err_info;

    if (value->len < 2) {
        return NJT_OK;
    }

    njt_memzero(&json_manager, sizeof(njt_json_manager));
    pool = njt_create_pool(njt_pagesize, njt_cycle->log);
    if (pool == NULL) {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_stream_dyn_lua_change_handler create pool error");
        rc = NJT_ERROR;
        goto end;
    }

    rpc_result = njt_rpc_result_create();
    if (!rpc_result) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "cannot create rpc result");
        rc = NJT_ERROR;
        goto end;
    }
    njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_SUCCESS);

    api_data = json_parse_dynstreamlua(pool, value, &err_info);
    if (api_data == NULL) {
        njt_log_error(NJT_LOG_ERR, pool->log, 0, "json_parse_dynstreamlua err: %V", &err_info.err_str);
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_JSON);
        njt_rpc_result_set_msg2(rpc_result, &err_info.err_str);
        rc = NJT_ERROR;
        goto rpc_msg;
    }

    rc = njt_dyn_stream_lua_update_conf(api_data, rpc_result);

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

static u_char *njt_stream_dyn_lua_get_handler(njt_str_t *topic, njt_str_t *request, int *len, void *data)
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
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_stream_dyn_lua_get_handler create pool error");
        goto out;
    }

    msg = njt_dyn_stream_lua_dump_conf(cycle, pool);
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

static u_char *njt_stream_dyn_lua_put_handler(njt_str_t *topic, njt_str_t *request, int *len, void *data)
{
    njt_str_t err_json_msg;
    njt_str_null(&err_json_msg);
    njt_stream_dyn_lua_change_handler_internal(topic, request, data, &err_json_msg);
    *len = err_json_msg.len;
    return err_json_msg.data;
}

static int njt_stream_dyn_lua_change_handler(njt_str_t *key, njt_str_t *value, void *data)
{
    return njt_stream_dyn_lua_change_handler_internal(key, value, data, NULL);
}

static int njt_stream_dyn_lua_package_clean_internal(njt_str_t *key, njt_str_t *value, void *data, njt_str_t *out_msg)
{
    njt_stream_lua_main_conf_t *lmcf;
    njt_stream_conf_ctx_t *conf_ctx;
    lua_State *L;
    char *module_name;
    njt_int_t rc;
    njt_rpc_result_t *rpc_result = NULL;
    njt_str_t worker_str = njt_string("/worker_a");
    njt_str_t new_key;

    if (value == NULL || value->len == 0 || value->data == NULL) {
        // Ignore empty payload
        return NJT_OK;
    }

    rpc_result = njt_rpc_result_create();
    if (!rpc_result) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "can't create rpc result");
        rc = NJT_ERROR;
        goto end;
    }
    njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_SUCCESS);
    conf_ctx = (njt_stream_conf_ctx_t *)njt_get_conf(njt_cycle->conf_ctx, njt_stream_module);
    if (conf_ctx == NULL) {
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
        njt_rpc_result_set_msg(rpc_result, (u_char *)"can't get stream conf_ctx");
        rc = NJT_ERROR;
        goto rpc_msg;
    }
    lmcf = conf_ctx->main_conf[njt_stream_lua_module.ctx_index];
    if (lmcf == NULL) {
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
        njt_rpc_result_set_msg(rpc_result, (u_char *)"can't get stream_lua conf_ctx");
        rc = NJT_ERROR;
        goto rpc_msg;
    }
    L = lmcf->lua;
    if (L == NULL) {
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
        njt_rpc_result_set_msg(rpc_result, (u_char *)"lua vm is empty");
        rc = NJT_ERROR;
        goto rpc_msg;
    }

    // Parse JSON string array using njt_json
    njt_json_doc *doc = njt_json_read((const char *)value->data, value->len, 0);
    if (doc == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "Failed to parse JSON string array");
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
        njt_rpc_result_set_msg(rpc_result, (u_char *)"Failed to parse JSON string array");
        rc = NJT_ERROR;
        goto rpc_msg;
    }

    njt_json_val *root = njt_json_doc_get_root(doc);
    if (!njt_json_is_arr(root)) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "JSON payload is not an array");
        njt_json_doc_free(doc);
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
        njt_rpc_result_set_msg(rpc_result, (u_char *)"JSON payload is not an array");
        rc = NJT_ERROR;
        goto rpc_msg;
    }

    // Iterate over the JSON array
    njt_json_val *val;
    njt_json_arr_iter iter;
    njt_json_arr_iter_init(root, &iter);
    while ((val = njt_json_arr_iter_next(&iter))) {
        if (!njt_json_is_str(val)) {
            njt_log_error(NJT_LOG_WARN, njt_cycle->log, 0, "Skipping non-string element in JSON array");
            continue;
        }

        const char *module = njt_json_get_str(val);
        size_t module_len = strlen(module);

        // Allocate memory for module_name
        module_name = njt_calloc(module_len + 1, njt_cycle->log);
        if (module_name == NULL) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "Failed to allocate memory for module_name");
            njt_json_doc_free(doc);
            njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
            njt_rpc_result_set_msg(rpc_result, (u_char *)"Failed to allocate memory for module_name");
            rc = NJT_ERROR;
            goto rpc_msg;
        }

        njt_memcpy(module_name, module, module_len);
        module_name[module_len] = '\0'; // Add null terminator

        // Get the global table
        lua_pushvalue(L, LUA_GLOBALSINDEX);
        // Push "package" onto the stack
        lua_getfield(L, -1, "package"); // stack: _G, package_table
        // Push "loaded" onto the stack
        lua_getfield(L, -1, "loaded"); // stack: _G, package_table, package.loaded_table
        // Check if package.loaded is actually a table
        if (lua_istable(L, -1)) {
            // Push nil
            lua_pushnil(L); // stack: _G, package_table, package.loaded_table, nil
            // Set package.loaded[module_name] = nil
            lua_setfield(L, -2, module_name); // stack: _G, package_table, package.loaded_table
            njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "Lua cache cleared for module: \"%s\"", module_name);
        } else {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "Lua package.loaded is not a table, cannot clear cache.");
        }
        // Pop the tables from the stack (package.loaded_table, package_table, _G)
        lua_pop(L, 3);
        njt_free(module_name);
    }

    // Free the JSON document
    njt_json_doc_free(doc);
    rc = NJT_OK;

rpc_msg:
    if (out_msg) {
        njt_rpc_result_to_json_str(rpc_result, out_msg);
    }

end:
    if (rpc_result) {
        njt_rpc_result_destroy(rpc_result);
    }

    // If sent to /worker_a, broadcast to other workers
    if (rc == NJT_OK && key->len > worker_str.len && njt_strncmp(key->data, worker_str.data, worker_str.len) == 0) {
        njt_str_set(&new_key, "");
        new_key.data = key->data + worker_str.len;
        new_key.len = key->len - worker_str.len;
        njt_kv_sendmsg(&new_key, value, 0);
    }

    return rc;
}

static int njt_stream_dyn_lua_package_clean(njt_str_t *key, njt_str_t *value, void *data)
{
    return njt_stream_dyn_lua_package_clean_internal(key, value, data, NULL);
}

static u_char *njt_stream_dyn_lua_put_package_clean(njt_str_t *key, njt_str_t *value, int *len, void *data)
{
    njt_str_t err_json_msg;
    njt_str_null(&err_json_msg);
    njt_stream_dyn_lua_package_clean_internal(key, value, data, &err_json_msg);
    *len = err_json_msg.len;
    return err_json_msg.data;
}

static u_char *njt_stream_dyn_lua_get_package_clean(njt_str_t *topic, njt_str_t *request, int *len, void *data)
{
    char *msg = "please use put to invoke this api\n";
    *len = njt_strlen(msg);
    u_char *msg2;
    msg2 = njt_calloc(*len + 1, njt_cycle->log);
    njt_memcpy(msg2, msg, *len);
    return msg2;
}

static void njt_stream_dyn_lua_del_vs_callback(void *data)
{
    njt_stream_lua_srv_conf_t *slsc = data;
    njt_stream_lua_main_conf_t *lmcf;
    njt_stream_conf_ctx_t *conf_ctx;
    lua_State *L;

    if (slsc) {
        // Get the main configuration and Lua state
        conf_ctx = (njt_stream_conf_ctx_t *)njt_get_conf(njt_cycle->conf_ctx, njt_stream_module);
        if (conf_ctx == NULL) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "failed to get stream conf_ctx in del_vs_callback");
            return;
        }

        lmcf = conf_ctx->main_conf[njt_stream_lua_module.ctx_index];
        if (lmcf == NULL) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "failed to get stream_lua main conf in del_vs_callback");
            return;
        }

        L = lmcf->lua;
        if (L == NULL) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "lua vm is empty in del_vs_callback");
            return;
        }

        // Clean content_by_lua
        if (slsc->content_src_key) {
            // Get code cache table
            lua_pushlightuserdata(L, njt_stream_lua_lightudata_mask(code_cache_key));
            lua_rawget(L, LUA_REGISTRYINDEX); // cache

            lua_pushnil(L);
            lua_setfield(L, -2, (const char *)slsc->content_src_key);

            // Remove cache table
            lua_pop(L, 1);

            slsc->content_src_key = NULL;
        }

        // Clean preread_by_lua
        if (slsc->preread_src_key) {
            // Get code cache table
            lua_pushlightuserdata(L, njt_stream_lua_lightudata_mask(code_cache_key));
            lua_rawget(L, LUA_REGISTRYINDEX); // cache

            lua_pushnil(L);
            lua_setfield(L, -2, (const char *)slsc->preread_src_key);

            // Remove cache table
            lua_pop(L, 1);

            slsc->preread_src_key = NULL;
        }

        // Clean up the configuration pool if it was dynamically allocated
        if (slsc->dynamic && slsc->conf_pool != NULL) {
            njt_destroy_pool(slsc->conf_pool);
            slsc->conf_pool = NULL;
        }
    }
}

static void njt_stream_dyn_lua_del_upstream_callback(void *data)
{
    njt_stream_upstream_srv_conf_t *uscf = data;
    njt_stream_lua_srv_conf_t *ulscf;
    njt_stream_lua_main_conf_t *lmcf;
    njt_stream_conf_ctx_t *conf_ctx;
    lua_State *L;

    if (uscf == NULL) {
        return;
    }

    ulscf = uscf->srv_conf[njt_stream_lua_module.ctx_index];
    if (ulscf == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "failed to get stream lua srv conf for upstream in del_upstream_callback");
        return;
    }

    // Get the main configuration and Lua state
    conf_ctx = (njt_stream_conf_ctx_t *)njt_get_conf(njt_cycle->conf_ctx, njt_stream_module);
    if (conf_ctx == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "failed to get stream conf_ctx in del_upstream_callback");
        return;
    }

    lmcf = conf_ctx->main_conf[njt_stream_lua_module.ctx_index];
    if (lmcf == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "failed to get stream_lua main conf in del_upstream_callback");
        return;
    }

    L = lmcf->lua;
    if (L == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "lua vm is empty in del_upstream_callback");
        return;
    }

    // Clean balancer_by_lua
    if (ulscf->balancer.src_key) {
        // Get code cache table
        lua_pushlightuserdata(L, njt_stream_lua_lightudata_mask(code_cache_key));
        lua_rawget(L, LUA_REGISTRYINDEX); // cache

        // Set package.loaded[src_key] = nil
        lua_pushnil(L);
        lua_setfield(L, -2, (const char *)ulscf->balancer.src_key);

        // Remove cache table
        lua_pop(L, 1);

        ulscf->balancer.src_key = NULL;
    }

    // Clean up the configuration pool if it was dynamically allocated
    if (ulscf->dynamic && ulscf->conf_pool != NULL) {
        njt_destroy_pool(ulscf->conf_pool);
        ulscf->conf_pool = NULL;
    }
}

static njt_int_t njt_stream_dyn_lua_module_init_process(njt_cycle_t *cycle)
{
    njt_str_t rpc_key = njt_string("stream_dyn_lua");
    njt_kv_reg_handler_t h;
    njt_memzero(&h, sizeof(njt_kv_reg_handler_t));
    h.key = &rpc_key;
    h.rpc_get_handler = njt_stream_dyn_lua_get_handler;
    h.rpc_put_handler = njt_stream_dyn_lua_put_handler;
    h.handler = njt_stream_dyn_lua_change_handler;
    h.api_type = NJT_KV_API_TYPE_DECLATIVE;
    njt_kv_reg_handler(&h);

    njt_str_t rpc_key_2 = njt_string("stream_lua_package_clean");
    njt_memzero(&h, sizeof(njt_kv_reg_handler_t));
    h.key = &rpc_key_2;
    h.handler = njt_stream_dyn_lua_package_clean;
    h.rpc_get_handler = njt_stream_dyn_lua_get_package_clean;
    h.rpc_put_handler = njt_stream_dyn_lua_put_package_clean;
    h.api_type = NJT_KV_API_TYPE_INSTRUCTIONAL;
    njt_kv_reg_handler(&h);

#if (NJT_STREAM_DYNAMIC_SERVER)   
    njt_str_t obj_vs_key = njt_string(VS_DEL_STREAM_EVENT);
    if (NJT_OK != njt_regist_update_fullconfig(&obj_vs_key,
        &rpc_key)) {
        return NJT_ERROR;
    }
    njt_str_t keyy = njt_string(STREAM_VS_OBJ);
    njt_http_object_change_reg_info_t reg;
    njt_memzero(&reg, sizeof(njt_http_object_change_reg_info_t));
    reg.add_handler = NULL;
    reg.del_handler = njt_stream_dyn_lua_del_vs_callback;
    reg.update_handler = NULL;
    njt_http_object_register_notice(&keyy, &reg);
#endif

#if (NJT_STREAM_ADD_DYNAMIC_UPSTREAM)
    njt_str_t obj_upstream_key = njt_string(UPS_DEL_STREAM_EVENT);
    if (NJT_OK != njt_regist_update_fullconfig(&obj_upstream_key,
        &rpc_key)) {
        return NJT_ERROR;
    }
    njt_str_t key_s = njt_string(STREAM_UPSTREAM_OBJ);
    njt_http_object_change_reg_info_t reg2;
    njt_memzero(&reg2, sizeof(njt_http_object_change_reg_info_t));
    reg.add_handler = NULL;
    reg.del_handler = njt_stream_dyn_lua_del_upstream_callback;
    reg.update_handler = NULL;

    njt_http_object_register_notice(&key_s, &reg2);
#endif

    return NJT_OK;
}

static njt_stream_module_t njt_stream_dyn_lua_module_ctx = {
    NULL, /* preconfiguration */
    NULL, /* postconfiguration */
    NULL, /* create main configuration */
    NULL, /* init main configuration */
    NULL, /* create server configuration */
    NULL  /* merge server configuration */
};

njt_module_t njt_stream_dyn_lua_module = {
    NJT_MODULE_V1,
    &njt_stream_dyn_lua_module_ctx,       /* module context */
    NULL,                                 /* module directives */
    NJT_STREAM_MODULE,                    /* module type */
    NULL,                                 /* init master */
    NULL,                                 /* init module */
    njt_stream_dyn_lua_module_init_process, /* init process */
    NULL,                                 /* init thread */
    NULL,                                 /* exit thread */
    NULL,                                 /* exit process */
    NULL,                                 /* exit master */
    NJT_MODULE_V1_PADDING
};