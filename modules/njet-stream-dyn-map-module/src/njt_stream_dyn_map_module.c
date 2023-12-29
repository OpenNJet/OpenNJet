/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */
#include <njt_core.h>
#include <njt_http_kv_module.h>
#include <njt_json_util.h>
#include <njt_rpc_result_util.h>
#include <njt_stream_dyn_module.h>
#include "njt_stream_dyn_map_parser.h"
#include <njt_stream.h>

extern njt_module_t njt_stream_map_module;
extern njt_int_t
njt_stream_map_create_hash_from_ctx(njt_stream_map_conf_t *mcf, njt_stream_map_ctx_t *map, njt_stream_map_conf_ctx_t *p_ctx, njt_pool_t *pool, njt_pool_t *temp_pool);

static njt_str_t *njt_stream_dyn_map_dump_maps(njt_cycle_t *cycle, njt_pool_t *pool)
{
    streammap_t dynjson_obj;
    njt_stream_variable_t *v;
    njt_stream_core_main_conf_t *cmcf;
    njt_uint_t i, j;
    njt_stream_map_conf_t *mcf;
    njt_stream_map_var_hash_t *var_hash_item;
    njt_stream_map_ctx_t *map;
    streammap_maps_item_t *item;
    njt_str_t *keyTo;
    streammap_maps_item_values_t *values;
    njt_array_t *ori_conf;

    njt_memzero(&dynjson_obj, sizeof(streammap_t));
    set_streammap_maps(&dynjson_obj, create_streammap_maps(pool, 4));
    cmcf = njt_stream_cycle_get_module_main_conf(cycle, njt_stream_core_module);
    if (cmcf == NULL) {
        goto out;
    }

    mcf = njt_stream_cycle_get_module_main_conf(cycle, njt_stream_map_module);
    if (mcf == NULL) {
        goto out;
    }

    v = cmcf->variables.elts;
    if (v == NULL) {
        goto out;
    } else {
        for (i = 0; i < cmcf->variables.nelts; i++) {
            if (njt_lvlhsh_map_get(&mcf->var_hash, &v[i].name, (intptr_t *)&var_hash_item) == NJT_OK) {
                map = var_hash_item->map;
                item = create_streammap_maps_item(pool);
                keyTo = njt_pcalloc(pool, sizeof(njt_str_t));
                keyTo->len = v[i].name.len + 1;
                keyTo->data = njt_pcalloc(pool, keyTo->len);
                njt_memcpy(keyTo->data, "$", 1);
                njt_memcpy(keyTo->data + 1, v[i].name.data, v[i].name.len);
                set_streammap_maps_item_keyTo(item, keyTo);
                set_streammap_maps_item_keyFrom(item, &map->value.value);
                set_streammap_maps_item_isVolatile(item, v[i].flags & NJT_STREAM_VAR_NOCACHEABLE ? true : false);
                set_streammap_maps_item_hostnames(item, map->hostnames ? true : false);
                values = create_streammap_maps_item_values(pool, 4);
                set_streammap_maps_item_values(item, values);
                ori_conf = var_hash_item->ori_conf;
                if (ori_conf) {
                    njt_stream_map_ori_conf_item_t *oci = ori_conf->elts;
                    for (j = 0;j < ori_conf->nelts;j++) {
                        streammap_maps_item_values_item_t *value_item = create_streammap_maps_item_values_item(pool);
                        set_streammap_maps_item_values_item_valueFrom(value_item, &oci[j].v_from);
                        set_streammap_maps_item_values_item_valueTo(value_item, &oci[j].v_to);
                        add_item_streammap_maps_item_values(values, value_item);
                    }
                }
                add_item_streammap_maps(dynjson_obj.maps, item);
            }
        }
    }

out:
    return to_json_streammap(pool, &dynjson_obj, OMIT_NULL_ARRAY | OMIT_NULL_OBJ | OMIT_NULL_STR);
}

static u_char *njt_stream_dyn_map_get_handler(njt_str_t *topic, njt_str_t *request, int *len, void *data)
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

    msg = njt_stream_dyn_map_dump_maps(cycle, pool);
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

static njt_int_t njt_stream_map_create_ctx_from_apidata(njt_stream_map_conf_t *mcf, streammap_maps_item_t *item, njt_stream_map_conf_ctx_t *ctx, njt_pool_t *pool, njt_pool_t *temp_pool)
{
    njt_uint_t                         i, j, key;
    njt_stream_variable_value_t *var, **vp;
    u_char *data;
    njt_str_t  v;
    size_t                             len;
    njt_stream_complex_value_t           cv, *cvp;
    njt_stream_compile_complex_value_t   ccv;
    njt_int_t rv;
    njt_str_t value[2];
    streammap_maps_item_values_item_t *vi;
    streammap_maps_item_values_item_valueFrom_t *from;
    streammap_maps_item_values_item_valueTo_t *to;
    njt_stream_map_ori_conf_item_t *ori_conf_item;
    njt_str_t empty_string = njt_string("");

    ctx->no_cacheable = get_streammap_maps_item_isVolatile(item) ? 1 : 0;
    ctx->hostnames = get_streammap_maps_item_hostnames(item) ? 1 : 0;
    for (j = 0; j < item->values->nelts;j++) {
        vi = get_streammap_maps_item_values_item(item->values, j);
        from = get_streammap_maps_item_values_item_valueFrom(vi);
        to = get_streammap_maps_item_values_item_valueTo(vi);
        value[0] = *from;
        value[1] = *to;
        if (from->len == 0 && from->data == NULL) {
            value[0].data = empty_string.data;
        }
        if (to->len == 0 && to->data == NULL) {
            value[1].data = empty_string.data;
        }

        ori_conf_item = (njt_stream_map_ori_conf_item_t *)njt_array_push(ctx->ori_conf);
        if (ori_conf_item == NULL) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "can't create ori_conf_item in njt_stream_map");
            return NJT_ERROR;
        }
        ori_conf_item->v_from.len = value[0].len;
        ori_conf_item->v_from.data = njt_pstrdup(ctx->keys.pool, &value[0]);
        ori_conf_item->v_to.len = value[1].len;
        ori_conf_item->v_to.data = njt_pstrdup(ctx->keys.pool, &value[1]);

        key = 0;
        for (i = 0; i < value[1].len; i++) {
            key = njt_hash(key, value[1].data[i]);
        }

        key %= ctx->keys.hsize;
        vp = ctx->values_hash[key].elts;

        if (vp) {
            for (i = 0; i < ctx->values_hash[key].nelts; i++) {
                if (vp[i]->valid) {
                    data = vp[i]->data;
                    len = vp[i]->len;
                } else {
                    cvp = (njt_stream_complex_value_t *)vp[i]->data;
                    data = cvp->value.data;
                    len = cvp->value.len;
                }

                if (value[1].len != len) {
                    continue;
                }

                if (njt_strncmp(value[1].data, data, len) == 0) {
                    var = vp[i];
                    goto found;
                }
            }

        } else {
            if (njt_array_init(&ctx->values_hash[key], pool, 4,
                sizeof(njt_stream_variable_value_t *))
                != NJT_OK) {
                return NJT_ERROR;
            }
        }

        var = njt_palloc(ctx->keys.pool, sizeof(njt_stream_variable_value_t));
        if (var == NULL) {
            return NJT_ERROR;
        }

        v.len = value[1].len;
        v.data = njt_pstrdup(ctx->keys.pool, &value[1]);
        if (v.data == NULL) {
            return NJT_ERROR;
        }

        njt_memzero(&ccv, sizeof(njt_stream_compile_complex_value_t));

        ccv.cf = ctx->cf;
        ccv.value = &v;
        ccv.complex_value = &cv;

        if (njt_stream_compile_complex_value(&ccv) != NJT_OK) {
            return NJT_ERROR;
        }

        if (cv.lengths != NULL) {
            cvp = njt_palloc(ctx->keys.pool, sizeof(njt_stream_complex_value_t));
            if (cvp == NULL) {
                return NJT_ERROR;
            }

            *cvp = cv;

            var->len = 0;
            var->data = (u_char *)cvp;
            var->valid = 0;

        } else {
            var->len = v.len;
            var->data = v.data;
            var->valid = 1;
        }

        var->no_cacheable = 0;
        var->not_found = 0;

        vp = njt_array_push(&ctx->values_hash[key]);
        if (vp == NULL) {
            return NJT_ERROR;
        }

        *vp = var;
    found:
        if (njt_strcmp(value[0].data, "default") == 0) {
            ctx->default_value = var;
            continue;
        }

#if (NJT_PCRE)

        if (value[0].len && value[0].data[0] == '~') {
            njt_regex_compile_t    rc;
            njt_stream_map_regex_t *regex;
            u_char                 errstr[NJT_MAX_CONF_ERRSTR];

            regex = njt_array_push(&ctx->regexes);
            if (regex == NULL) {
                return NJT_ERROR;
            }

            value[0].len--;
            value[0].data++;

            njt_memzero(&rc, sizeof(njt_regex_compile_t));

            if (value[0].data[0] == '*') {
                value[0].len--;
                value[0].data++;
                rc.options = NJT_REGEX_CASELESS;
            }

            rc.pattern = value[0];
            rc.err.len = NJT_MAX_CONF_ERRSTR;
            rc.err.data = errstr;

            regex->regex = njt_stream_regex_compile(ctx->cf, &rc);
            if (regex->regex == NULL) {
                return NJT_ERROR;
            }

            regex->value = var;

            continue;
        }

#endif

        if (value[0].len && value[0].data[0] == '\\') {
            value[0].len--;
            value[0].data++;
        }

        rv = njt_hash_add_key(&ctx->keys, &value[0], var,
            (ctx->hostnames) ? NJT_HASH_WILDCARD_KEY : 0);

        if (rv != NJT_OK) {
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}

static njt_int_t njt_stream_dyn_map_update_existed_var(njt_pool_t *pool, njt_pool_t *temp_pool, njt_stream_conf_ctx_t *conf_ctx, streammap_maps_item_t *item, njt_stream_map_conf_t *mcf,
    njt_stream_map_var_hash_t *var_hash_item, njt_rpc_result_t *rpc_result)
{
    njt_stream_variable_t *v;
    njt_stream_core_main_conf_t *cmcf;
    njt_uint_t i;
    njt_stream_map_conf_t old_cf;
    njt_stream_map_conf_ctx_t            ctx;
    njt_stream_map_ctx_t *map = var_hash_item->map;
    njt_int_t rc;
    njt_conf_t *cf;
    njt_conf_t cf_data = {
        .pool = pool,
        .temp_pool = temp_pool,
        .cycle = (njt_cycle_t *)njt_cycle,
        .log = pool->log,
        .ctx = conf_ctx,
    };
    cf = &cf_data;

    old_cf = *mcf;

    njt_memzero(&ctx, sizeof(njt_stream_map_conf_ctx_t));
    ctx.cf = cf;
    ctx.keys.pool = pool;
    ctx.keys.temp_pool = temp_pool;
    ctx.ori_conf = njt_array_create(pool, 10, sizeof(njt_stream_map_ori_conf_item_t));
    if (ctx.ori_conf == NULL) {
        goto error;
    }

    if (njt_hash_keys_array_init(&ctx.keys, NJT_HASH_LARGE) != NJT_OK) {
        goto error;
    }

    ctx.values_hash = njt_pcalloc(temp_pool, sizeof(njt_array_t) * ctx.keys.hsize);
    if (ctx.values_hash == NULL) {
        goto error;
    }

#if (NJT_PCRE)
    if (njt_array_init(&ctx.regexes, pool, 2, sizeof(njt_stream_map_regex_t))
        != NJT_OK) {
        goto error;
    }
#endif

    ctx.default_value = NULL;
    ctx.hostnames = 0;
    ctx.no_cacheable = 0;

    rc = njt_stream_map_create_ctx_from_apidata(mcf, item, &ctx, pool, temp_pool);
    if (rc != NJT_OK) {
        goto error;
    }

    if (ctx.no_cacheable) {
        cmcf = njt_stream_cycle_get_module_main_conf(njt_cycle, njt_stream_core_module);
        if (cmcf != NULL) {
            v = cmcf->variables.elts;
            if (v != NULL) {
                for (i = 0; i < cmcf->variables.nelts; i++) {
                    if (var_hash_item->name.len == v[i].name.len && njt_strncmp(var_hash_item->name.data, v[i].name.data, v[i].name.len) == 0) {
                        v[i].flags |= NJT_STREAM_VAR_NOCACHEABLE;
                        break;
                    }
                }
            }
        }
    }

    rc = njt_stream_map_create_hash_from_ctx(mcf, map, &ctx, pool, temp_pool);
    if (rc != NJT_OK) {
        goto error;
    }
    if (ctx.keys.keys.nelts == 0 ) {
        njt_memzero(&map->map.hash.hash, sizeof(njt_hash_t));
    }

    if (var_hash_item->dynamic && var_hash_item->ori_conf->pool) {
        njt_destroy_pool(var_hash_item->ori_conf->pool);
    }
    var_hash_item->dynamic = 1;
    var_hash_item->ori_conf = ctx.ori_conf;
    return NJT_OK;

error:
    *mcf = old_cf;
    return NJT_ERROR;
}

static njt_int_t njt_stream_dyn_map_validate_value(njt_str_t *value)
{
    njt_uint_t   i, j, bracket;
    u_char       ch;
    njt_str_t    name;
    njt_stream_core_main_conf_t *cmcf;
    njt_stream_variable_t *v;
    bool var_defined;

    if (!value || value->len == 0) {
        return NJT_OK;
    }
    cmcf = njt_stream_cycle_get_module_main_conf(njt_cycle, njt_stream_core_module);
    if (cmcf == NULL) {
        return NJT_OK;
    }
    v = cmcf->variables.elts;
    if (v == NULL) {
        return NJT_OK;
    }

    for (i = 0; i < value->len; i++) {
        name.len = 0;
        if (value->data[i] == '$') {
            if (++i == value->len) {
                goto invalid_variable;
            }
            if (value->data[i] == '{') {
                bracket = 1;
                if (++i == value->len) {
                    goto invalid_variable;
                }
                name.data = &value->data[i];
            } else {
                bracket = 0;
                name.data = &value->data[i];
            }

            for ( /* void */; i < value->len; i++, name.len++) {
                ch = value->data[i];
                if (ch == '}' && bracket) {
                    i++;
                    bracket = 0;
                    break;
                }
                if ((ch >= 'A' && ch <= 'Z')
                    || (ch >= 'a' && ch <= 'z')
                    || (ch >= '0' && ch <= '9')
                    || ch == '_') {
                    continue;
                }
                break;
            }
            if (bracket) {
                goto invalid_variable;
            }
            if (name.len == 0) {
                goto invalid_variable;
            }
            //check if variable is existed
            var_defined = false;
            for (j = 0; j < cmcf->variables.nelts; j++) {
                if (njt_strncmp(v[j].name.data, name.data, name.len) == 0) {
                    var_defined = true;
                    break;
                }
            }
            if (!var_defined) {
                goto invalid_variable;
            }
        }
    }

    return NJT_OK;

invalid_variable:
    return NJT_ERROR;
}

static njt_int_t njt_stream_dyn_map_validate_values(streammap_maps_item_values_t *values, njt_str_t **tmp_var_str)
{
    njt_uint_t i;
    streammap_maps_item_values_item_t *vi;
    njt_str_t *from, *to;

    for (i = 0; i < values->nelts;i++) {
        vi = get_streammap_maps_item_values_item(values, i);
        from = get_streammap_maps_item_values_item_valueFrom(vi);
        to = get_streammap_maps_item_values_item_valueTo(vi);

        if (njt_stream_dyn_map_validate_value(from) != NJT_OK) {
            *tmp_var_str = from;
            return NJT_ERROR;
        }
        if (njt_stream_dyn_map_validate_value(to) != NJT_OK) {
            *tmp_var_str = to;
            return NJT_ERROR;
        }
    }
    return NJT_OK;
}

static njt_int_t njt_dyn_map_update_values(njt_pool_t *temp_pool, streammap_t *api_data, njt_rpc_result_t *rpc_result)
{
    njt_stream_conf_ctx_t *conf_ctx;
    njt_stream_map_conf_t *mcf;
    njt_stream_map_var_hash_t *var_hash_item;
    njt_int_t rc;
    njt_uint_t i;
    u_char data_buf[1024] = { 0 };
    u_char *end;
    njt_str_t rpc_data_str;
    njt_str_t *tmp_var_str;
    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;

    conf_ctx = (njt_stream_conf_ctx_t *)njt_get_conf(njt_cycle->conf_ctx, njt_stream_module);
    if (!conf_ctx) {
        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "stream section not found, cannot use stream dyn map");
        return NJT_ERROR;
    }
    mcf = conf_ctx->main_conf[njt_stream_map_module.ctx_index];

    if (mcf == NULL) {
        return NJT_ERROR;
    }

    for (i = 0;i < api_data->maps->nelts;i++) {
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

        streammap_maps_item_t *item = get_streammap_maps_item(api_data->maps, i);
        njt_str_t *keyTo = (njt_str_t *)get_streammap_maps_item_keyTo(item);
        if (keyTo->data[0] == '$') {
            keyTo->data++;
            keyTo->len--;
            rc = njt_lvlhsh_map_get(&mcf->var_hash, keyTo, (intptr_t *)&var_hash_item);
            if (rc == NJT_OK) {
                rc = njt_stream_dyn_map_validate_values(get_streammap_maps_item_values(item), &tmp_var_str);
                if (rc != NJT_OK) {
                    end = njt_snprintf(data_buf, sizeof(data_buf) - 1, "invalid variable in string: %V", tmp_var_str);
                    rpc_data_str.len = end - data_buf;
                    njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_PARTIAL_SUCCESS);
                    njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                    njt_destroy_pool(pool);
                    continue;
                }
                rc = njt_stream_dyn_map_update_existed_var(pool, temp_pool, conf_ctx, item, mcf, var_hash_item, rpc_result);
                if (rc != NJT_OK) {
                    end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " njt_dyn_map_update_values error");
                    rpc_data_str.len = end - data_buf;
                    njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_PARTIAL_SUCCESS);
                    njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                    njt_destroy_pool(pool);
                }
            } else {
                //TODO: need to support dynamicly add a stream variable
                end = njt_snprintf(data_buf, sizeof(data_buf) - 1, "keyTo $%V not found in conf", keyTo);
                rpc_data_str.len = end - data_buf;
                njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_PARTIAL_SUCCESS);
                njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                njt_destroy_pool(pool);
            }
        } else {
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, "keyTo %V is invalid, it should start with $", keyTo);
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_PARTIAL_SUCCESS);
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            njt_destroy_pool(pool);
        }
    }

    return NJT_OK;
}

static int njt_stream_dyn_map_put_handler_internal(njt_str_t *key, njt_str_t *value, void *data, njt_str_t *out_msg)
{
    njt_int_t rc;
    streammap_t *api_data = NULL;
    njt_pool_t *temp_pool = NULL;
    njt_json_manager json_manager;
    njt_rpc_result_t *rpc_result;
    js2c_parse_error_t  err_info;

    if (value->len < 2) {
        return NJT_OK;
    }

    njt_memzero(&json_manager, sizeof(njt_json_manager));
    rpc_result = njt_rpc_result_create();
    if (!rpc_result) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "stream_dyn_map can't create rpc result");
        rc = NJT_ERROR;
        goto end;
    }
    njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_SUCCESS);
    temp_pool = njt_create_pool(njt_pagesize, njt_cycle->log);
    if (temp_pool == NULL) {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "stream_dyn_map create pool error");
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_MEM_ALLOC);
        rc = NJT_ERROR;
        goto rpc_msg;
    }

    api_data = json_parse_streammap(temp_pool, value, &err_info);
    if (api_data == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "stream_dyn_map json parse error: %V", &err_info.err_str);
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_JSON);
        njt_rpc_result_set_msg2(rpc_result, &err_info.err_str);
        rc = NJT_ERROR;
        goto rpc_msg;
    }

    rc = njt_dyn_map_update_values(temp_pool, api_data, rpc_result);

rpc_msg:
    if (out_msg) {
        njt_rpc_result_to_json_str(rpc_result, out_msg);
    }
end:
    if (temp_pool != NULL) {
        njt_destroy_pool(temp_pool);
    }
    if (rpc_result) {
        njt_rpc_result_destroy(rpc_result);
    }

    return rc;
}

static int njt_stream_dyn_map_change_handler(njt_str_t *key, njt_str_t *value, void *data)
{
    return njt_stream_dyn_map_put_handler_internal(key, value, data, NULL);
}

static u_char *njt_stream_dyn_map_put_handler(njt_str_t *topic, njt_str_t *request, int *len, void *data)
{
    njt_str_t err_json_msg;
    njt_str_null(&err_json_msg);
    njt_stream_dyn_map_put_handler_internal(topic, request, data, &err_json_msg);
    *len = err_json_msg.len;
    return err_json_msg.data;
}

static njt_int_t njt_stream_dyn_map_module_init_process(njt_cycle_t *cycle)
{
    njt_str_t rpc_key = njt_string("stream_dyn_map");
    njt_kv_reg_handler_t h;
    njt_memzero(&h, sizeof(njt_kv_reg_handler_t));
    h.key = &rpc_key;
    h.rpc_get_handler = njt_stream_dyn_map_get_handler;
    h.rpc_put_handler = njt_stream_dyn_map_put_handler;
    h.handler = njt_stream_dyn_map_change_handler;
    h.api_type = NJT_KV_API_TYPE_DECLATIVE;
    njt_kv_reg_handler(&h);

    return NJT_OK;
}

static njt_stream_module_t njt_stream_dyn_map_module_ctx = {
    NULL, /* preconfiguration */
    NULL, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL /* merge server configuration */
};

njt_module_t njt_stream_dyn_map_module = {
    NJT_MODULE_V1,
    &njt_stream_dyn_map_module_ctx,       /* module context */
    NULL,                                 /* module directives */
    NJT_STREAM_MODULE,                    /* module type */
    NULL,                                 /* init master */
    NULL,                                 /* init module */
    njt_stream_dyn_map_module_init_process, /* init process */
    NULL,                                 /* init thread */
    NULL,                                 /* exit thread */
    NULL,                                 /* exit process */
    NULL,                                 /* exit master */
    NJT_MODULE_V1_PADDING };
