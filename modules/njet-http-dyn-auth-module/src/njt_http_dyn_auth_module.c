/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */
#include <njt_core.h>
#include <njt_http_kv_module.h>
#include <njt_http.h>
#include <njt_http_util.h>
#include <njt_http_dyn_module.h>

#include "njt_http_dyn_auth_parser.h"
#include <njt_rpc_result_util.h>

extern njt_module_t njt_http_auth_basic_module;



njt_str_t dyn_auth_update_srv_err_msg = njt_string("{\"code\":500,\"msg\":\"server error\"}");


njt_int_t njt_dyn_auth_check_var(njt_conf_t *cf, njt_str_t *var){
    njt_http_core_main_conf_t  *cmcf;
    njt_http_variable_t        *v;
    njt_uint_t                  i;
    size_t                      var_len;
    bool                        found = false;

    if(var == NULL || var->len < 1){
        return NJT_ERROR;
    }

    if(var->data[0] == ' '){
        return NJT_ERROR;
    } 

    if(var->data[0] != '$'){
        return NJT_OK;
    }

    if(var->len < 2){
        return NJT_ERROR;
    }

    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);
    if(cmcf == NULL){
        return NJT_ERROR;
    }
    v = cmcf->variables.elts;
    var_len = var->len - 1;
    for (i = 0; i < cmcf->variables.nelts; i++) {
        if(v[i].name.len == var_len
            && njt_strncmp(v[i].name.data, var->data + 1, v[i].name.len)
              == 0)
        {
            if (v[i].get_handler == NULL) {
                njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                    "njt_dyn_auth_rate unknown \"%V\" variable", &v[i].name);
                
                return NJT_ERROR;
            }

            found = true;
        }
    }

    if(found){
        return NJT_OK;
    }

    return NJT_ERROR;
}

//if modify return NJT_OK, not modify return NJT_ERROR
static njt_int_t njt_dyn_auth_check_modify(dyn_auth_servers_item_locations_item_t *data, 
    njt_http_auth_basic_loc_conf_t      *alcf){
    //off -> off, as not modify
    if(data->auth_basic.len == 3 && njt_strncmp(data->auth_basic.data, "off", 3) == 0){
        if (alcf->realm == NULL 
            || (alcf->realm->value.len == 3 && njt_strncmp(data->auth_basic.data, "off", 3) == 0))
        {
            return NJT_ERROR;
        }

        return NJT_OK;
    }

    if(alcf->realm == NULL  || data->auth_basic.len != alcf->realm->value.len
        || njt_strncmp(data->auth_basic.data, alcf->realm->value.data, data->auth_basic.len) != 0){
        return NJT_OK;
    }

    if(data->auth_type.len == 4){
        if(alcf->user_file == NULL){
            return NJT_OK;
        }

        if(alcf->user_file->value.len != data->auth_param.len
            || njt_strncmp(data->auth_param.data, alcf->user_file->value.data, data->auth_param.len) != 0){
            return NJT_OK;
        }

        return NJT_ERROR;
    }

    if(data->auth_type.len == 2){
        if(alcf->kv_prefix == NULL){
            return NJT_OK;
        }

        if(alcf->kv_prefix->value.len != data->auth_param.len
            || njt_strncmp(data->auth_param.data, alcf->kv_prefix->value.data, data->auth_param.len) != 0){
            return NJT_OK;
        }

        return NJT_ERROR;
    }


    return NJT_ERROR;
}


static njt_int_t njt_dyn_auth_set_auth_config(njt_http_core_loc_conf_t *clcf, 
        dyn_auth_servers_item_locations_item_t *data, njt_http_conf_ctx_t *ctx,
        njt_rpc_result_t *rpc_result)
{
    njt_conf_t                          *cf;
    njt_http_auth_basic_loc_conf_t      *alcf, old_alcf;
    njt_int_t                            rc;
    u_char                               data_buf[1024];
    u_char                              *end;
    njt_str_t                            tmp_str;
    njt_str_t                            rpc_data_str;
    njt_pool_t                          *pool;
    njt_http_compile_complex_value_t     ccv;

    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;

    //check param valid
    if(!data->is_auth_basic_set){
        return NJT_OK;
    }

    if(data->auth_basic.len < 1){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, 
            "auth_basic should not be empty str");
    
        end = njt_snprintf(data_buf,sizeof(data_buf) - 1," auth_basic should not be empty str");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

        return NJT_ERROR;
    }

    //if auth_basic not off, then must set auth_type and auth_param
    if(data->auth_basic.len != 3 || njt_strncmp(data->auth_basic.data, "off", 3) != 0){
        if(!data->is_auth_type_set || !data->is_auth_param_set
            || data->auth_type.len < 1 || data->auth_param.len < 1){
            njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, 
                "auth_type and auth_param must set");
        
            end = njt_snprintf(data_buf,sizeof(data_buf) - 1," auth_type and auth_param must set");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

            return NJT_ERROR;
        }

        //auth type must file or kv
        if((data->auth_type.len != 2 && data->auth_type.len != 4)
            || (data->auth_type.len == 2 && njt_strncmp(data->auth_type.data, "kv", 2) != 0)
            || (data->auth_type.len == 4 && njt_strncmp(data->auth_type.data, "file", 4) != 0)){
            njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, 
                "auth_type should be file or kv");
        
            end = njt_snprintf(data_buf,sizeof(data_buf) - 1," auth_type should be file or kv");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

            return NJT_ERROR;  
        }
    }

    njt_conf_t cf_data = {
        .cycle = (njt_cycle_t *)njt_cycle,
        .log = njt_cycle->log,
        .ctx = ctx,
    };
    cf = &cf_data;

    alcf = njt_http_conf_get_module_loc_conf(cf, njt_http_auth_basic_module);
    if(alcf == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, 
            "njt_dyn_auth_set_auth_config get module config error");
        
        end = njt_snprintf(data_buf,sizeof(data_buf) - 1," dyn auth conn get module config error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

		return NJT_ERROR;
	}

    //check wether has modify, if not modify, return NJT_OK
    if(NJT_ERROR == njt_dyn_auth_check_modify(data, alcf)){
        return NJT_OK;
    }

    pool = njt_create_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
    if (NULL == pool) {
        end = njt_snprintf(data_buf,sizeof(data_buf) - 1," create pool error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

        return NJT_ERROR;
    }

    rc = njt_sub_pool(clcf->pool,pool);

    if(NJT_OK != rc){
        njt_destroy_pool(pool);

        end = njt_snprintf(data_buf,sizeof(data_buf) - 1," add sub pool error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

        return NJT_ERROR;
    }

    old_alcf = *alcf;
    njt_memzero(alcf, sizeof(njt_http_auth_basic_loc_conf_t));
    cf->pool = pool;
    cf->temp_pool = pool;
    cf->dynamic = 1;
    alcf->dynamic = 1;
    alcf->pool = pool;

    alcf->realm = njt_pcalloc(pool, sizeof(njt_http_complex_value_t));
    if (alcf->realm == NULL) {
        end = njt_snprintf(data_buf,sizeof(data_buf) - 1," realm malloc error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

        goto auth_config_fail;
    }

    tmp_str.len = data->auth_basic.len;
    tmp_str.data = njt_pcalloc(pool, data->auth_basic.len);
    if (tmp_str.data == NULL) {
        end = njt_snprintf(data_buf,sizeof(data_buf) - 1," realm data malloc error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

        goto auth_config_fail;
    }
    njt_memcpy(tmp_str.data, data->auth_basic.data,  data->auth_basic.len);

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));
    ccv.cf = cf;
    ccv.value = &tmp_str;
    ccv.complex_value = alcf->realm;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        end = njt_snprintf(data_buf,sizeof(data_buf) - 1," realm compile error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

        goto auth_config_fail;
    }

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));
    ccv.cf = cf;
    if(data->auth_type.len == 4){
        alcf->user_file = njt_pcalloc(pool, sizeof(njt_http_complex_value_t));
        if (alcf->user_file == NULL) {
            end = njt_snprintf(data_buf,sizeof(data_buf) - 1," user_file malloc error");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

            goto auth_config_fail;
        }

        ccv.zero = 1;
        ccv.conf_prefix = 1;
        ccv.complex_value = alcf->user_file;
    }
    else{
        alcf->kv_prefix = njt_pcalloc(pool, sizeof(njt_http_complex_value_t));
        if (alcf->kv_prefix == NULL) {
            end = njt_snprintf(data_buf,sizeof(data_buf) - 1," kv_prefix malloc error");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

            goto auth_config_fail;
        }

        ccv.complex_value = alcf->kv_prefix;
    }

    tmp_str.len = data->auth_param.len;
    tmp_str.data = njt_pcalloc(pool, data->auth_param.len);
    if (tmp_str.data == NULL) {
        end = njt_snprintf(data_buf,sizeof(data_buf) - 1," user_file or kv malloc error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

        goto auth_config_fail;
    }

    njt_memcpy(tmp_str.data, data->auth_param.data,  data->auth_param.len);
    ccv.value = &tmp_str;
    
    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        end = njt_snprintf(data_buf,sizeof(data_buf) - 1," user_file or kv compile error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

        goto auth_config_fail;
    }

    if(old_alcf.dynamic == 1){
        if(old_alcf.pool != NULL){
            njt_destroy_pool(old_alcf.pool);
        }
    }

    return NJT_OK;
 
auth_config_fail:
    if(pool != NULL){
        njt_destroy_pool(pool);
    }

    *alcf = old_alcf;

    return NJT_ERROR;
}


static njt_int_t njt_dyn_auth_update_locs(njt_array_t *locs, njt_queue_t *q, njt_http_conf_ctx_t *ctx,
                njt_rpc_result_t *rpc_result)
{
    njt_http_core_loc_conf_t            *clcf;
    njt_http_location_queue_t           *hlq;
    dyn_auth_servers_item_locations_item_t            *dlil;
    njt_uint_t                           j;
    njt_queue_t                         *tq;
    njt_int_t                            rc;
    u_char                               data_buf[1024];
    u_char                              *end;
    njt_str_t                            parent_conf_path;
    njt_str_t                            rpc_data_str;
    bool                                 found = false;
    njt_str_t                           *name;

    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;

    if (q == NULL)
    {
        return NJT_OK;
    }

    if(rpc_result){
        parent_conf_path = rpc_result->conf_path;
    }

    for (j = 0; j < locs->nelts; ++j)
    {
        dlil = get_dyn_auth_servers_item_locations_item(locs, j);
        if(dlil == NULL || !dlil->is_location_set){
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " index %d not set location name", j);
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            continue;
        }

        name = get_dyn_auth_locationDef_location(dlil);

        tq = njt_queue_head(q);
        found = false;
        for (; tq != njt_queue_sentinel(q); tq = njt_queue_next(tq))
        {
            hlq = njt_queue_data(tq, njt_http_location_queue_t, queue);
            clcf = hlq->exact == NULL ? hlq->inclusive : hlq->exact;
            if (clcf != NULL && njt_http_location_full_name_cmp(clcf->full_name, *name) == 0) {
                if(rpc_result){
                    njt_rpc_result_set_conf_path(rpc_result, &parent_conf_path);
                    end = njt_snprintf(data_buf,sizeof(data_buf) - 1, ".locations[%V]", &clcf->full_name);
                    rpc_data_str.len = end - data_buf;
                    njt_rpc_result_append_conf_path(rpc_result, &rpc_data_str);
                }

                ctx->loc_conf = clcf->loc_conf;

                found = true;
                //set auth_conns
                rc = njt_dyn_auth_set_auth_config(clcf, dlil, ctx, rpc_result);
                if (rc != NJT_OK)
                {
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "error in njt_dyn_auth_set_auth_config");
                }

                if (dlil->is_locations_set && dlil->locations && dlil->locations->nelts > 0) {
                    njt_dyn_auth_update_locs(dlil->locations, clcf->old_locations, ctx, rpc_result);
                }
            }
        }

        if(!found){
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " location[%V] not found", name);
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
        }
    }

    return NJT_OK;
}

static void njt_dyn_auth_dump_locs_json(njt_pool_t *pool, 
        njt_queue_t *locations, dyn_auth_servers_item_locations_t *loc_items)
{
    njt_http_core_loc_conf_t      *clcf;
    njt_http_location_queue_t     *hlq;
    njt_queue_t                   *q, *tq;
    njt_http_auth_basic_loc_conf_t *alcf;
    njt_str_t                     tmp_str;
    dyn_auth_servers_item_locations_item_t *loc_item;

    // njt_http_access_rule_t *rule;
    if (locations == NULL)
    {
        return;
    }

    q = locations;
    if (njt_queue_empty(q))
    {
        return;
    }

    tq = njt_queue_head(q);
    for (; tq != njt_queue_sentinel(q); tq = njt_queue_next(tq))
    {
        hlq = njt_queue_data(tq, njt_http_location_queue_t, queue);
        clcf = hlq->exact == NULL ? hlq->inclusive : hlq->exact;
        if(clcf == NULL){
            continue;
        }

        alcf = njt_http_get_module_loc_conf(clcf, njt_http_auth_basic_module);

        loc_item = create_dyn_auth_locationDef(pool);
        if(loc_item == NULL){
            continue;
        }
        set_dyn_auth_locationDef_location(loc_item, &clcf->full_name);

        if(alcf == NULL || alcf->realm == NULL){
            njt_str_set(&tmp_str, "off");
            set_dyn_auth_locationDef_auth_basic(loc_item, &tmp_str);
        }

        if(alcf != NULL)
        {
            if(alcf->realm == NULL){
                njt_str_set(&tmp_str, "off");
                set_dyn_auth_locationDef_auth_basic(loc_item, &tmp_str);
            }else{
                set_dyn_auth_locationDef_auth_basic(loc_item, &alcf->realm->value);
            }

            if(alcf->user_file != NULL){
                njt_str_set(&tmp_str, "file");
                set_dyn_auth_locationDef_auth_type(loc_item, &tmp_str);
                set_dyn_auth_locationDef_auth_param(loc_item, &alcf->user_file->value);
            }

            if(alcf->kv_prefix != NULL){
                njt_str_set(&tmp_str, "kv");
                set_dyn_auth_locationDef_auth_type(loc_item, &tmp_str);
                set_dyn_auth_locationDef_auth_param(loc_item, &alcf->kv_prefix->value);
            }
        }

        if (clcf->old_locations) {
            set_dyn_auth_locationDef_locations(loc_item, create_dyn_auth_locationDef_locations(pool, 4));
            if(loc_item->locations != NULL){
                njt_dyn_auth_dump_locs_json(pool, clcf->old_locations, loc_item->locations);
            }
        }

        add_item_dyn_auth_servers_item_locations(loc_items, loc_item);
    }
}

static njt_str_t *njt_dyn_auth_dump_auth_conf(njt_cycle_t *cycle, njt_pool_t *pool)
{
    njt_http_core_loc_conf_t        *clcf;
    njt_http_core_main_conf_t       *hcmcf;
    njt_http_core_srv_conf_t        **cscfp;
    njt_uint_t                      i, j;
    njt_array_t                     *array;
    njt_str_t                       *tmp_str;
    njt_http_server_name_t          *server_name;
    dyn_auth_t                       dynjson_obj;
    dyn_auth_servers_item_t         *server_item;

    njt_memzero(&dynjson_obj, sizeof(dyn_auth_t));
    hcmcf = njt_http_cycle_get_module_main_conf(cycle, njt_http_core_module);
    if(hcmcf == NULL){
        goto err;
    }

    set_dyn_auth_servers(&dynjson_obj, create_dyn_auth_servers(pool, 4));
    if(dynjson_obj.servers == NULL){
        goto err;
    }

    cscfp = hcmcf->servers.elts;
    for (i = 0; i < hcmcf->servers.nelts; i++)
    {
        server_item = create_dyn_auth_servers_item(pool);
        if(server_item == NULL){
            goto err;
        }

        set_dyn_auth_servers_item_listens(server_item, create_dyn_auth_servers_item_listens(pool, 4));
        set_dyn_auth_servers_item_serverNames(server_item, create_dyn_auth_servers_item_serverNames(pool, 4));
        set_dyn_auth_servers_item_locations(server_item, create_dyn_auth_servers_item_locations(pool, 4));

        array = njt_array_create(pool, 4, sizeof(njt_str_t));
        if(array == NULL){
            goto err;
        }
        njt_http_get_listens_by_server(array, cscfp[i]);

        for (j = 0; j < array->nelts; ++j) {
            tmp_str = (njt_str_t *)(array->elts)+ j;
            add_item_dyn_auth_servers_item_listens(server_item->listens, tmp_str);
        }

        server_name = cscfp[i]->server_names.elts;
        for (j = 0; j < cscfp[i]->server_names.nelts; ++j) {
            tmp_str = &server_name[j].full_name;
            add_item_dyn_auth_servers_item_serverNames(server_item->serverNames, tmp_str);
        }

        clcf = njt_http_get_module_loc_conf(cscfp[i]->ctx, njt_http_core_module);
        if(clcf != NULL){
            njt_dyn_auth_dump_locs_json(pool, clcf->old_locations, server_item->locations);
        }

        add_item_dyn_auth_servers(dynjson_obj.servers, server_item);
    }

    return to_json_dyn_auth(pool, &dynjson_obj, OMIT_NULL_ARRAY | OMIT_NULL_OBJ | OMIT_NULL_STR);

err:
    return &dyn_auth_update_srv_err_msg;
}

static njt_int_t njt_dyn_auth_update_auth_conf(njt_pool_t *pool, dyn_auth_t *api_data,
                        njt_rpc_result_t *rpc_result)
{
    njt_cycle_t                         *cycle;
    njt_http_core_srv_conf_t            *cscf;
    njt_http_core_loc_conf_t            *clcf;
    dyn_auth_servers_item_t             *dsi;
    njt_str_t                           *port, *serverName;
    njt_uint_t                           i;
    njt_int_t                            rc;
    u_char                               data_buf[1024];
    u_char                              *end;
    njt_str_t                            rpc_data_str;


    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;

    cycle = (njt_cycle_t *)njt_cycle;

    if(api_data->is_servers_set && api_data->servers != NULL){
        for (i = 0; i < api_data->servers->nelts; ++i)
        {
            dsi = get_dyn_auth_servers_item(api_data->servers, i);
            if (dsi == NULL || !dsi->is_listens_set || !dsi->is_serverNames_set 
                    || dsi->listens->nelts < 1 
                    || dsi->serverNames->nelts < 1) {
                // listens or server_names is empty
                end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
                    " server parameters error, listens or serverNames is empty,at position %d", i);
                rpc_data_str.len = end - data_buf;
                njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                continue;
            }

            port = get_dyn_auth_servers_item_listens_item(dsi->listens, 0);
            serverName = get_dyn_auth_servers_item_serverNames_item(dsi->serverNames, 0);
            njt_str_null(&rpc_result->conf_path);

            cscf = njt_http_get_srv_by_port(cycle, port, serverName);
            if (cscf == NULL)
            {
                njt_log_error(NJT_LOG_INFO, pool->log, 0, "can`t find server by listen:%V server_name:%V ",
                            port, serverName);
                end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
                    " can`t find server by listen[%V] server_name[%V]", port, serverName);
                rpc_data_str.len = end - data_buf;
                njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                continue;
            }

            njt_log_error(NJT_LOG_INFO, pool->log, 0, "dynauth start update listen:%V server_name:%V",
                    port, serverName);

            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, "listen[%V] server_name[%V]", port, serverName);
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_set_conf_path(rpc_result, &rpc_data_str);
                    
            njt_http_conf_ctx_t ctx = *cscf->ctx;
            clcf = njt_http_get_module_loc_conf(cscf->ctx, njt_http_core_module);
            if(clcf == NULL){
                njt_log_error(NJT_LOG_INFO, pool->log, 0, "can`t find location config by listen:%V server_name:%V ",
                            port, serverName);
                end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " can`t find location config by listen[%V] server_name[%V]", port, serverName);
                rpc_data_str.len = end - data_buf;
                njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                continue;
            }

            if(dsi->is_locations_set && dsi->locations->nelts > 0){
                rc = njt_dyn_auth_update_locs(dsi->locations, clcf->old_locations, &ctx, rpc_result);
                if(rc != NJT_OK){
                    njt_log_error(NJT_LOG_INFO, pool->log, 0, "update auth error, listen:%V server_name:%V",
                        port, serverName);
                }
            }
        }
    }

    return NJT_OK;
}

static u_char *njt_dyn_auth_rpc_handler(njt_str_t *topic, njt_str_t *request, int *len, void *data)
{
    njt_cycle_t *cycle;
    njt_str_t   *msg;
    u_char      *buf;
    njt_pool_t  *pool = NULL;

    buf = NULL;
    cycle = (njt_cycle_t *)njt_cycle;
    *len = 0;

    pool = njt_create_pool(njt_pagesize, njt_cycle->log);
    if (pool == NULL)
    {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_auth_rpc_handler create pool error");
        goto out;
    }

    msg = njt_dyn_auth_dump_auth_conf(cycle, pool);
    buf = njt_calloc(msg->len, cycle->log);
    if (buf == NULL)
    {
        goto out;
    }

    njt_log_error(NJT_LOG_INFO, pool->log, 0, "send json : %V", msg);
    njt_memcpy(buf, msg->data, msg->len);
    *len = msg->len;

out:
    if (pool != NULL)
    {
        njt_destroy_pool(pool);
    }

    return buf;
}

static int njt_dyn_auth_update_handler(njt_str_t *key, njt_str_t *value, void *data, njt_str_t *out_msg)
{
    njt_int_t                            rc = NJT_OK;
    dyn_auth_t                         *api_data = NULL;
    njt_pool_t                          *pool = NULL;
    njt_rpc_result_t                    *rpc_result = NULL;
    js2c_parse_error_t                  err_info;

    rpc_result = njt_rpc_result_create();
    if(!rpc_result){
        if(out_msg != NULL){
            njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
            njt_rpc_result_set_msg(rpc_result, (u_char *)" create rpc_result error");
        }
        rc = NJT_ERROR;

        goto end;
    }

    if(value->len < 2 ){
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_INPUT_PARAM);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" input param not valid, less then 2 byte");
        rc = NJT_ERROR;

        goto end;
    }

    pool = njt_create_pool(njt_pagesize, njt_cycle->log);
    if (pool == NULL)
    {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_auth_change_handler create pool error");
        
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_MEM_ALLOC);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" update handler create pool error");
        rc = NJT_ERROR;

        goto end;
    }

    api_data = json_parse_dyn_auth(pool, value, &err_info);
    if (api_data == NULL)
    {
        njt_log_error(NJT_LOG_ERR, pool->log, 0, 
                "json_parse_dyn_auth err: %V",  &err_info.err_str);
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_JSON);
        njt_rpc_result_set_msg2(rpc_result, &err_info.err_str);

        rc = NJT_ERROR;
        goto err_msg;
    }

    njt_rpc_result_set_code(rpc_result,NJT_RPC_RSP_SUCCESS);

    rc = njt_dyn_auth_update_auth_conf(pool, api_data, rpc_result);
    if(rc != NJT_OK){
        njt_rpc_result_set_code(rpc_result,NJT_RPC_RSP_ERR);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" auth update fail");
    }else{
        if(rpc_result->data != NULL && rpc_result->data->nelts > 0){
            njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_PARTIAL_SUCCESS);
        }
    }

err_msg:
    if (rc != NJT_OK) {
        njt_str_t msg = njt_string("");
        njt_kv_sendmsg(key,&msg, 0);
    }

end:
    if(out_msg){
        njt_rpc_result_to_json_str(rpc_result,out_msg);
    }

    if (pool != NULL)
    {
        njt_destroy_pool(pool);
    }

    if(rpc_result){
        njt_rpc_result_destroy(rpc_result);
    }
    return rc;
}

static int  njt_dyn_auth_change_handler(njt_str_t *key, njt_str_t *value, void *data){
    return njt_dyn_auth_update_handler(key, value, data, NULL);
}

static u_char* njt_dyn_auth_put_handler(njt_str_t *topic, njt_str_t *request, int* len, void *data){
    njt_str_t err_json_msg;
    njt_str_null(&err_json_msg);
    njt_dyn_auth_update_handler(topic, request, data, &err_json_msg);
    *len = err_json_msg.len;
    return err_json_msg.data;
}

static njt_int_t njt_http_dyn_auth_module_init_process(njt_cycle_t *cycle)
{
    njt_str_t auth_rpc_key = njt_string("http_dyn_auth");
    njt_kv_reg_handler_t h;
    njt_memzero(&h, sizeof(njt_kv_reg_handler_t));
    h.key = &auth_rpc_key;
    h.rpc_get_handler = njt_dyn_auth_rpc_handler;
    h.rpc_put_handler = njt_dyn_auth_put_handler;
    h.handler = njt_dyn_auth_change_handler;
    h.api_type = NJT_KV_API_TYPE_DECLATIVE;
    njt_kv_reg_handler(&h);

    return NJT_OK;
}

static njt_http_module_t njt_http_dyn_auth_module_ctx = {
    NULL, /* preconfiguration */
    NULL, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    NULL, /* create location configuration */
    NULL  /* merge location configuration */
};

njt_module_t njt_http_dyn_auth_module = {
    NJT_MODULE_V1,
    &njt_http_dyn_auth_module_ctx,         /* module context */
    NULL,                                    /* module directives */
    NJT_HTTP_MODULE,                         /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    njt_http_dyn_auth_module_init_process, /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NJT_MODULE_V1_PADDING};
