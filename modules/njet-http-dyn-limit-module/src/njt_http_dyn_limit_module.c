/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */
#include <njt_core.h>
#include <njt_http_kv_module.h>
#include <njt_http.h>
// #include <njt_json_util.h>
#include <njt_http_util.h>
#include <njt_http_dyn_module.h>

#include "njt_http_dyn_limit_parser.h"
#include <njt_rpc_result_util.h>

extern njt_module_t njt_http_limit_conn_module;
extern njt_module_t njt_http_limit_req_module;


// static njt_conf_enum_t  njt_http_dyn_limit_conn_log_levels[] = {
//     { njt_string("info"), NJT_LOG_INFO },
//     { njt_string("notice"), NJT_LOG_NOTICE },
//     { njt_string("warn"), NJT_LOG_WARN },
//     { njt_string("error"), NJT_LOG_ERR },
//     { njt_null_string, 0 }
// };

// static njt_conf_enum_t  njt_http_dyn_limit_req_log_levels[] = {
//     { njt_string("info"), NJT_LOG_INFO },
//     { njt_string("notice"), NJT_LOG_NOTICE },
//     { njt_string("warn"), NJT_LOG_WARN },
//     { njt_string("error"), NJT_LOG_ERR },
//     { njt_null_string, 0 }
// };

static njt_command_t limit_rate_cmd = {
      njt_string("limit_rate"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_CONF_TAKE1,
      njt_http_set_complex_value_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, limit_rate),
      NULL
};

static njt_command_t limit_rate_after_cmd = {
      njt_string("limit_rate_after"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_CONF_TAKE1,
      njt_http_set_complex_value_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, limit_rate_after),
      NULL
};


njt_str_t dyn_limit_update_srv_err_msg = njt_string("{\"code\":500,\"msg\":\"server error\"}");


njt_int_t njt_dyn_limit_check_var(njt_conf_t *cf, njt_str_t *var){
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
                    "njt_dyn_limit_rate unknown \"%V\" variable", &v[i].name);
                
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


njt_int_t njt_dyn_limit_check_zone(njt_conf_t *cf, njt_str_t *name, void *tag, njt_rpc_result_t *rpc_result){
    njt_uint_t        i;
    njt_shm_zone_t   *shm_zone;
    njt_list_part_t  *part;
    bool              found = false;
    u_char                               data_buf[1024];
    u_char                              *end;
    njt_str_t                            rpc_data_str;

    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;

    part = &cf->cycle->shared_memory.part;
    shm_zone = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            shm_zone = part->elts;
            i = 0;
        }

        if (name->len != shm_zone[i].shm.name.len) {
            continue;
        }

        if (njt_strncmp(name->data, shm_zone[i].shm.name.data, name->len)
            != 0)
        {
            continue;
        }

        if (tag != shm_zone[i].tag) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                "type error, the shared memory zone \"%V\" is "
                "already declared for a different use",
                &shm_zone[i].shm.name);

            end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
                    " type error, the shared memory zone \"%V\" is"
                    "already declared for a different use",
                    &shm_zone[i].shm.name);
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

            return NJT_ERROR;
        }

        found = true;
        break;
    }

    if(found){
        return NJT_OK;
    }

    end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " zone \"%V\" is not exist",
            name);
    rpc_data_str.len = end - data_buf;
    njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

    return NJT_ERROR;
}


static njt_int_t njt_dyn_limit_set_limit_conns(dyn_limit_servers_item_locations_item_t *data, njt_http_conf_ctx_t *ctx,
                    njt_rpc_result_t *rpc_result)
{
    njt_conf_t                          *cf;
    njt_http_limit_conn_conf_t          *lccf;
    njt_http_limit_conn_limit_t         *limit, *limits;
    dyn_limit_locationDef_limit_conns_item_t      *data_limit;
    njt_uint_t                           i, j;
    bool                                 found = false;
    njt_shm_zone_t                      *shm_zone;
    njt_int_t                            rc;
    u_char                               data_buf[1024];
    u_char                              *end;
    njt_str_t                            rpc_data_str;
    dyn_limit_locationDef_limit_conns_t           *limit_conns;

    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;


    if(!data->is_limit_conns_set || data->limit_conns->nelts < 1){
        return NJT_OK;
    }

    if(!data->is_limit_conns_scope_set){
        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, 
                 "dyn limit conns not set scope, so not update");
        
        end = njt_snprintf(data_buf,sizeof(data_buf) - 1," dyn limit conn not set scope, so not update");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

        return NJT_OK;
    }

    if(data->limit_conns_scope == DYN_LIMIT_LOCATIONDEF_LIMIT_CONNS_SCOPE_UP_SHARE){
        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, 
                 "dyn limit conn is up_share scope, so not update");
        
        end = njt_snprintf(data_buf,sizeof(data_buf) - 1," dyn limit conn is up_share scope, so not update");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

        return NJT_OK;
    }

    njt_conf_t cf_data = {
        .cycle = (njt_cycle_t *)njt_cycle,
        .log = njt_cycle->log,
        .ctx = ctx,
    };
    cf = &cf_data;

    lccf = njt_http_conf_get_module_loc_conf(cf, njt_http_limit_conn_module);
    if(lccf == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, 
            "njt_dyn_limit_set_limit_conns get module config error");
        
        end = njt_snprintf(data_buf,sizeof(data_buf) - 1," dyn limit conn get module config error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

		return NJT_ERROR;
	}

    if(lccf->from_up == 1){
        lccf->limits.elts = NULL;
        lccf->from_up = 0;
    }

    limits = lccf->limits.elts;
    if (limits == NULL) {
        if (njt_array_init(&lccf->limits, njt_cycle->pool, 1,
                           sizeof(njt_http_limit_conn_limit_t))
            != NJT_OK)
        {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
                 "njt_dyn_limit_set_limit_conns limits array init error");
            end = njt_snprintf(data_buf,sizeof(data_buf) - 1," limits array init error");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            return NJT_ERROR;
        }
    }

    limit_conns = get_dyn_limit_locationDef_limit_conns(data);
    for (i = 0; i < data->limit_conns->nelts; i++) {
        data_limit = get_dyn_limit_locationDef_limit_conns_item(limit_conns, i);
        if(data_limit == NULL || !data_limit->is_zone_set || data_limit->zone.len < 1){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
                 "njt_dyn_limit_set_limit_conns zone name is empty");

            end = njt_snprintf(data_buf,sizeof(data_buf) - 1," zone name is empty");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

            continue;
        }

        if(!data_limit->is_conn_set || data_limit->conn <= 0 || data_limit->conn > 65535){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
                 "njt_dyn_limit_set_limit_conns zone:%V conn number is invalid, should >0 and <= 65535",
                 &data_limit->zone);
            
            end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
                    " zone:%V conn number is invalid, should >0 and <= 65535",
                    &data_limit->zone);
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

            continue;
        }

        found = false;
        limits = lccf->limits.elts;
        for (j = 0; j < lccf->limits.nelts; j++){
            if(limits[j].shm_zone == NULL)
            {
                njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, 
                    "njt_dyn_limit_set_limit_conns limit conn zone is null");

                end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
                        " limit conn zone is null");
                rpc_data_str.len = end - data_buf;
                njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

                continue;
            }
            
            if(data_limit->zone.len == limits[j].shm_zone->shm.name.len
               && njt_strncmp(data_limit->zone.data, limits[j].shm_zone->shm.name.data, data_limit->zone.len) == 0){
                //found
                found = true;
                //update
                limits[j].conn = data_limit->conn;
                break;
            }
        }

        if(!found){
            //check zone whether exist
            rc = njt_dyn_limit_check_zone(cf, &data_limit->zone, &njt_http_limit_conn_module, rpc_result);
            if(rc != NJT_OK){
                njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0,
                    "njt_dyn_limit_set_limit_conns zone:%V not valid", &data_limit->zone);

                continue;
            }
            //add
            shm_zone = njt_shared_memory_add(cf, &data_limit->zone, 0,
                                     &njt_http_limit_conn_module);
            if (shm_zone == NULL) {
                njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0,
                  "njt_dyn_limit_set_limit_conns shared_memory_add error, zone:%V", &data_limit->zone);
                
                end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
                    " shared_memory_add error, zone:%V",
                    &data_limit->zone);
                rpc_data_str.len = end - data_buf;
                njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                
                continue;
            }

            limit = njt_array_push(&lccf->limits);
            if (limit == NULL) {
                njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, 
                    "njt_dyn_limit_set_limit_conns limit conn push error");

                end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
                    " limit conn push error, zone:%V",
                    &data_limit->zone);
                rpc_data_str.len = end - data_buf;
                njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

                return NJT_ERROR;
            }

            limit->conn = data_limit->conn;
            limit->shm_zone = shm_zone;
        }
    }

 
    return NJT_OK;
}

static njt_int_t njt_dyn_limit_set_limit_reqs(dyn_limit_servers_item_locations_item_t *data, njt_http_conf_ctx_t *ctx,
                njt_rpc_result_t *rpc_result)
{
    njt_conf_t                  *cf;
    njt_http_limit_req_conf_t   *lrcf;
    njt_http_limit_req_limit_t  *limit, *limits;
    dyn_limit_locationDef_limit_reqs_item_t    *data_limit;
    njt_uint_t                   i, j;
    bool                         found = false;
    njt_shm_zone_t              *shm_zone;
    njt_int_t                    rc;
    njt_uint_t                   delay = 0;
    njt_int_t                    tmp_delay;
    u_char                       data_buf[1024];
    u_char                      *end;
    njt_str_t                    rpc_data_str;
    dyn_limit_locationDef_limit_reqs_t    *limit_reqs;

    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;


    if(!data->is_limit_reqs_set || data->limit_reqs == NULL || data->limit_reqs->nelts < 1){
        return NJT_OK;
    }

    if(!data->is_limit_reqs_scope_set){
        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, 
                 "dyn limit req scope is not set, so not update");

        end = njt_snprintf(data_buf,sizeof(data_buf) - 1," dyn limit req scope is not set, so not update");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

        return NJT_OK;
    }

    if(data->limit_reqs_scope == DYN_LIMIT_LOCATIONDEF_LIMIT_REQS_SCOPE_UP_SHARE){
        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, 
                 "dyn limit req is up_share scope, so not update");

        end = njt_snprintf(data_buf,sizeof(data_buf) - 1," dyn limit req is up_share scope, so not update");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

        return NJT_OK;
    } 

    njt_conf_t cf_data = {
        .cycle = (njt_cycle_t *)njt_cycle,
        .log = njt_cycle->log,
        .ctx = ctx,
    };
    cf = &cf_data;

    lrcf = njt_http_conf_get_module_loc_conf(cf, njt_http_limit_req_module);
    if(lrcf == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, 
            "njt_dyn_limit_set_limit_reqs get module config error");
        
        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " dyn limit get module config error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

		return NJT_ERROR;
	}

    if(lrcf->from_up == 1){
        lrcf->limits.elts = NULL;
        lrcf->from_up = 0;
    }

    limits = lrcf->limits.elts;
    if (limits == NULL) {
        if (njt_array_init(&lrcf->limits, njt_cycle->pool, 1,
                           sizeof(njt_http_limit_req_limit_t))
            != NJT_OK)
        {
            njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, 
                "njt_dyn_limit_set_limit_reqs limit arrary init error");

            end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
                " dyn limit arrary init error");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

            return NJT_ERROR;
        }
    }

    limit_reqs = get_dyn_limit_locationDef_limit_reqs(data);
    for (i = 0; i < data->limit_reqs->nelts; i++) {
        data_limit = get_dyn_limit_locationDef_limit_reqs_item(limit_reqs, i);
        if(data_limit == NULL || !data_limit->is_zone_set || data_limit->zone.len < 1){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
                 "njt_dyn_limit_set_limit_reqs zone name is empty");

            end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
                " dyn limit zone name is empty");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            continue;
        }

        if((data_limit->is_burst_set && data_limit->burst < 0)
            || (data_limit->is_delay_set && data_limit->delay.len < 1)){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
                 "njt_dyn_limit_set_limit_reqs zone:%V burst or delay shoud > 0 or nodelay",
                 &data_limit->zone);

            end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
                " dyn limit zone:%V burst or delay shoud > 0 or nodelay",
                &data_limit->zone);
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

            continue;
        }

        //check delay
        //nodelay len=7
        if(data_limit->is_delay_set){
            if(data_limit->delay.len == 7
                && njt_strncmp(data_limit->delay.data, "nodelay", 7) == 0){
                delay = NJT_MAX_INT_T_VALUE / 1000;
            }else{
                tmp_delay = njt_atoi(data_limit->delay.data, data_limit->delay.len);
                if (tmp_delay < 0) {
                    njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0,
                        "njt_dyn_limit_set_limit_reqs zone:%V delay format invalid", &data_limit->zone);
                    end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
                        " dyn limit zone:%V delay format invalid",
                        &data_limit->zone);
                    rpc_data_str.len = end - data_buf;
                    njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

                    continue;
                }
                delay = tmp_delay;
            }
        }

        found = false;
        limits = lrcf->limits.elts;
        for (j = 0; j < lrcf->limits.nelts; j++){
            if(limits[j].shm_zone == NULL)
            {
                njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, 
                    "njt_dyn_limit_set_limit_reqs limit req zone is null");

                end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
                    " dyn limit req zone is null");
                rpc_data_str.len = end - data_buf;
                njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                continue;
            }
            
            if(data_limit->zone.len == limits[j].shm_zone->shm.name.len
               && njt_strncmp(data_limit->zone.data, limits[j].shm_zone->shm.name.data, data_limit->zone.len) == 0){
                //found
                found = true;
                //update
                if(data_limit->is_burst_set){
                    limits[j].burst = data_limit->burst * 1000;
                }
                
                if(data_limit->is_delay_set){
                    limits[j].delay = delay * 1000;
                }
                break;
            }
        }

        if(!found){
            //check zone whether exist
            rc = njt_dyn_limit_check_zone(cf, &data_limit->zone, &njt_http_limit_req_module, rpc_result);
            if(rc != NJT_OK){
                njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0,
                    "njt_dyn_limit_set_limit_reqs zone:%V not valid", &data_limit->zone);

                continue;
            }
            //add
            shm_zone = njt_shared_memory_add(cf, &data_limit->zone, 0,
                                     &njt_http_limit_req_module);
            if (shm_zone == NULL) {
                njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0,
                  "njt_dyn_limit_set_limit_reqs shared_memory_add error, zone:%V", &data_limit->zone);

                end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
                    " dyn limit req shared_memory_add error, zone:%V",
                    &data_limit->zone);
                rpc_data_str.len = end - data_buf;
                njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

                continue;
            }

            limit = njt_array_push(&lrcf->limits);
            if (limit == NULL) {
                njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, 
                    "njt_dyn_limit_set_limit_reqs limit req push error");

                end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
                    " dyn limit req push error");
                rpc_data_str.len = end - data_buf;
                njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

                return NJT_ERROR;
            }
            if(data_limit->is_burst_set){
                limit->burst = data_limit->burst * 1000;
            }
            
            if(data_limit->is_delay_set){
                limit->delay = delay * 1000;
            }
            
            limit->shm_zone = shm_zone;
        }
    }

 
    return NJT_OK;
}



static njt_int_t njt_dyn_limit_set_limit_rate(dyn_limit_servers_item_locations_item_t *data,
            njt_http_conf_ctx_t *ctx, njt_rpc_result_t *rpc_result)
{
    njt_http_core_loc_conf_t    *clcf;
    njt_http_complex_value_t    *old_limit_rate;
    njt_int_t                    rc;
    char                        *rv;
    njt_conf_t                  *cf;
    njt_pool_t                  *pool = NULL;
    njt_str_t                   *rate;
    njt_str_t                   *rate_name;
    u_char                       data_buf[1024];
    u_char                      *end;
    njt_str_t                    rpc_data_str;

    // if(1){
    //     return NJT_OK;
    // }
    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;

    if(!data->is_limit_rate_set || data->limit_rate.len < 1){
        return NJT_OK;
    }

    njt_conf_t cf_data = {
        .cycle = (njt_cycle_t *)njt_cycle,
        .log = njt_cycle->log,
        .ctx = ctx,
    };
    cf = &cf_data;

    //if variable, need check variable table
    rc = njt_dyn_limit_check_var(cf, &data->limit_rate);
    if(rc != NJT_OK){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
            "njt_dyn_limit_set_limit_rate var not exist or format error");

        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " dyn limit rate var not exist or format error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

        return NJT_ERROR;
    }

    clcf = njt_http_conf_get_module_loc_conf(cf, njt_http_core_module);
    if(clcf == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0,
            "njt_dyn_limit_set_limit_rate get core module config error");

        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " dyn limit rate get core module config error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

		return NJT_ERROR;
	}

    //create dyn pool             
    pool = njt_create_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
    if (pool == NULL)
    {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_limit_set_limit_rate create pool error");
        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " dyn limit rate create pool error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
        
        return NJT_ERROR;
    }
    rc = njt_sub_pool(clcf->pool, pool);
    if (rc != NJT_OK)
    {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_limit_set_limit_rate add sub pool error");
        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " dyn limit rate add sub pool error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
        njt_destroy_pool(pool);
        return NJT_ERROR;
    }   

    cf->pool = pool;
    cf->temp_pool = pool;

    old_limit_rate = clcf->limit_rate;
    clcf->limit_rate = NULL;

    //set limit_rate
    //create cf
    cf->args = njt_array_create(pool, 10, sizeof(njt_str_t));
    if (cf->args == NULL) {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_limit_set_limit_rate arrry create error");

        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " dyn limit rate arrry create error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

        goto err;
    }
 
    rate_name = njt_array_push(cf->args);
    njt_str_set(rate_name, "limit_rate");

    rate = njt_array_push(cf->args);
    rate->len = data->limit_rate.len;
    rate->data = njt_pcalloc(pool, data->limit_rate.len);
    if(rate->data == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_limit_set_limit_rate malloc error");

        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " dyn limit rate malloc error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

        goto err;
    }

    njt_memcpy(rate->data, data->limit_rate.data, data->limit_rate.len);

    cf->limit_dynamic = 1;

    //set limit_rate
    rv = njt_http_set_complex_value_size_slot(cf, &limit_rate_cmd, clcf);
    if (rv != NJT_CONF_OK) {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_limit_set_limit_rate complex set error");

        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " dyn limit rate complex set error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
        goto err;
    }

    //destroy old dyn pool
    if(old_limit_rate != NULL && old_limit_rate->dynamic == 1){
        njt_destroy_pool(old_limit_rate->pool);
    }

    return NJT_OK;

err:
    if(pool != NULL){
        njt_destroy_pool(pool);
        pool = NULL;
    }

    clcf->limit_rate = old_limit_rate;

    return NJT_ERROR;
}


static njt_int_t njt_dyn_limit_set_limit_rate_after(dyn_limit_servers_item_locations_item_t *data, njt_http_conf_ctx_t *ctx,
                njt_rpc_result_t *rpc_result)
{
    njt_http_core_loc_conf_t    *clcf;
    njt_http_complex_value_t    *old_limit_rate_after;
    njt_int_t                    rc;
    char                        *rv;
    njt_conf_t                  *cf;
    njt_pool_t                  *pool = NULL;
    njt_str_t                   *rate_after;
    njt_str_t                   *rate_after_name;
    u_char                       data_buf[1024];
    u_char                      *end;
    njt_str_t                    rpc_data_str;

    // if(1){
    //     return NJT_OK;
    // }
    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;

    if(!data->is_limit_rate_after_set || data->limit_rate_after.len < 1){
        return NJT_OK;
    }

    njt_conf_t cf_data = {
        .cycle = (njt_cycle_t *)njt_cycle,
        .log = njt_cycle->log,
        .ctx = ctx,
    };
    cf = &cf_data;

    //if variable, need check variable table
    rc = njt_dyn_limit_check_var(cf, &data->limit_rate_after);
    if(rc != NJT_OK){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
            "njt_dyn_limit_set_limit_rate_after var not exist or format error");

        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " dyn limit rate_after var not exist or format error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

        return NJT_ERROR;
    }

    clcf = njt_http_conf_get_module_loc_conf(cf, njt_http_core_module);
    if(clcf == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0,
            "njt_dyn_limit_set_limit_rate_after get core module config error");

        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " dyn limit rate_after get core module config error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

		return NJT_ERROR;
	}

    //create dyn pool             
    pool = njt_create_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
    if (pool == NULL)
    {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, 
            "njt_dyn_limit_set_limit_rate_after create pool error");
        
        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " dyn limit rate_after create pool error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

        return NJT_ERROR;
    }
    rc = njt_sub_pool(clcf->pool, pool);
    if (rc != NJT_OK)
    {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, 
            "njt_dyn_limit_set_limit_rate_after add sub pool error");
        
        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " dyn limit rate_after add sub pool error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
        njt_destroy_pool(pool);
        return NJT_ERROR;
    }   

    cf->pool = pool;
    cf->temp_pool = pool;

    old_limit_rate_after = clcf->limit_rate_after;
    clcf->limit_rate_after = NULL;

    //set limit_rate_after
    //create cf
    cf->args = njt_array_create(pool, 10, sizeof(njt_str_t));
    if (cf->args == NULL) {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0,
            "njt_dyn_limit_set_limit_rate_after array create error");
        
        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " dyn limit rate_after array create error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
        goto err;
    }
 
    rate_after_name = njt_array_push(cf->args);
    njt_str_set(rate_after_name, "limit_rate_after");

    rate_after = njt_array_push(cf->args);
    rate_after->len = data->limit_rate_after.len;
    rate_after->data = njt_pcalloc(pool, data->limit_rate_after.len);
    if(rate_after->data == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_limit_set_limit_rate_after palloc error");
        
        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " dyn limit rate_after palloc error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
        goto err;
    }

    njt_memcpy(rate_after->data, data->limit_rate_after.data, data->limit_rate_after.len);

    cf->limit_dynamic = 1;

    //set limit_rate_after
    rv = njt_http_set_complex_value_size_slot(cf, &limit_rate_after_cmd, clcf);
    if (rv != NJT_CONF_OK) {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0,
            "njt_dyn_limit_set_limit_rate_after set complex error");
        
        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " dyn limit rate_after set complex errorc");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
        goto err;
    }

    //destroy old dyn pool
    if(old_limit_rate_after != NULL && old_limit_rate_after->dynamic == 1){
        njt_destroy_pool(old_limit_rate_after->pool);
    }

    return NJT_OK;

err:
    if(pool != NULL){
        njt_destroy_pool(pool);
        pool = NULL;
    }

    clcf->limit_rate_after = old_limit_rate_after;

    return NJT_ERROR;
}


static njt_int_t njt_dyn_limit_set_limit_conn_status(dyn_limit_servers_item_locations_item_t *data, njt_http_conf_ctx_t *ctx,
                njt_rpc_result_t *rpc_result)
{
    njt_conf_t                  *cf;
    njt_http_limit_conn_conf_t  *lccf;
    u_char                       data_buf[1024];
    u_char                      *end;
    njt_str_t                    rpc_data_str;

    if(!data->is_limit_conn_status_set){
        return NJT_OK;
    }

    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;


    if(data->limit_conn_status < 1){
        return NJT_OK;
    }

    if(data->limit_conn_status >= 400 &&
       data->limit_conn_status <= 599){

    }else{
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, 
           "njt_dyn_limit_set_limit_conn_status status invalid, shoudld [400, 599]");

        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " dyn limit conn_status invalid, shoudld [400, 599]");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

        return NJT_ERROR;
    }

    njt_conf_t cf_data = {
        .cycle = (njt_cycle_t *)njt_cycle,
        .log = njt_cycle->log,
        .ctx = ctx,
    };
    cf = &cf_data;

    lccf = njt_http_conf_get_module_loc_conf(cf, njt_http_limit_conn_module);
    if(lccf == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, 
            "njt_dyn_limit_set_limit_conn_status get module config error");

        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " dyn limit conn_status get module config error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
		return NJT_ERROR;
	}

    lccf->status_code = data->limit_conn_status;

 
    return NJT_OK;
}


static njt_int_t njt_dyn_limit_set_limit_req_status(dyn_limit_servers_item_locations_item_t *data, njt_http_conf_ctx_t *ctx,
                    njt_rpc_result_t *rpc_result)
{
    njt_conf_t                  *cf;
    njt_http_limit_req_conf_t   *lrcf;
    u_char                       data_buf[1024];
    u_char                      *end;
    njt_str_t                    rpc_data_str;

    if(!data->is_limit_req_status_set){
        return NJT_OK;
    }

    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;    

    if(data->limit_req_status < 1){
        return NJT_OK;
    }

    if(data->limit_req_status >= 400 &&
       data->limit_req_status <= 599){

    }else{
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, 
           "njt_dyn_limit_set_limit_req_status status invalid, shoudld [400, 599]");

        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " dyn limit req_status invalid, shoudld [400, 599]");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

        return NJT_ERROR;
    }

    njt_conf_t cf_data = {
        .cycle = (njt_cycle_t *)njt_cycle,
        .log = njt_cycle->log,
        .ctx = ctx,
    };
    cf = &cf_data;

    lrcf = njt_http_conf_get_module_loc_conf(cf, njt_http_limit_req_module);
    if(lrcf == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, 
            "njt_dyn_limit_set_limit_req_status get module config error");

        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " dyn limit req_status get module config error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

		return NJT_ERROR;
	}

    lrcf->status_code = data->limit_req_status;

 
    return NJT_OK;
}


static njt_int_t njt_dyn_limit_set_limit_conn_log_level(dyn_limit_servers_item_locations_item_t *data,
                    njt_http_conf_ctx_t *ctx,
                    njt_rpc_result_t *rpc_result)
{
    njt_conf_t                  *cf;
    njt_http_limit_conn_conf_t  *lccf;
    u_char                       data_buf[1024];
    u_char                      *end;
    njt_str_t                    rpc_data_str;

    if(!data->is_limit_conn_log_level_set){
        return NJT_OK;
    }

    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0; 

    njt_conf_t cf_data = {
        .cycle = (njt_cycle_t *)njt_cycle,
        .log = njt_cycle->log,
        .ctx = ctx,
    };
    cf = &cf_data;

    lccf = njt_http_conf_get_module_loc_conf(cf, njt_http_limit_conn_module);
    if(lccf == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0,
            "njt_dyn_limit_set_limit_conn_log_level get module config error");
		
        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " dyn limit conn_log_level get module config error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
        return NJT_ERROR;
	}
 
    switch (data->limit_conn_log_level)
    {
    case DYN_LIMIT_LOCATIONDEF_LIMIT_CONN_LOG_LEVEL_INFO:
        lccf->log_level = NJT_LOG_INFO;
        break;
    case DYN_LIMIT_LOCATIONDEF_LIMIT_CONN_LOG_LEVEL_NOTICE:
        lccf->log_level = NJT_LOG_NOTICE;
        break;
    case DYN_LIMIT_LOCATIONDEF_LIMIT_CONN_LOG_LEVEL_WARN:
        lccf->log_level = NJT_LOG_WARN;
        break;
    case DYN_LIMIT_LOCATIONDEF_LIMIT_CONN_LOG_LEVEL_ERROR:
        lccf->log_level = NJT_LOG_ERR;
        break;    
    }

    return NJT_OK;
}


static njt_int_t njt_dyn_limit_set_limit_req_log_level(dyn_limit_servers_item_locations_item_t *data,
            njt_http_conf_ctx_t *ctx,
            njt_rpc_result_t *rpc_result)
{
    njt_conf_t                  *cf;
    njt_http_limit_req_conf_t   *lrcf;
    u_char                       data_buf[1024];
    u_char                      *end;
    njt_str_t                    rpc_data_str;

    if(!data->is_limit_req_log_level_set){
        return NJT_OK;
    }

    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0; 

    njt_conf_t cf_data = {
        .cycle = (njt_cycle_t *)njt_cycle,
        .log = njt_cycle->log,
        .ctx = ctx,
    };
    cf = &cf_data;

    lrcf = njt_http_conf_get_module_loc_conf(cf, njt_http_limit_req_module);
    if(lrcf == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_limit_set_limit_req_log_level get module config error");
		
        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " dyn limit req_log_level get module config error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
        
        return NJT_ERROR;
	}

    switch (data->limit_req_log_level)
    {
    case DYN_LIMIT_LOCATIONDEF_LIMIT_REQ_LOG_LEVEL_INFO:
        lrcf->limit_log_level = NJT_LOG_INFO;
        break;
    case DYN_LIMIT_LOCATIONDEF_LIMIT_REQ_LOG_LEVEL_NOTICE:
        lrcf->limit_log_level = NJT_LOG_NOTICE;
        break;
    case DYN_LIMIT_LOCATIONDEF_LIMIT_REQ_LOG_LEVEL_WARN:
        lrcf->limit_log_level = NJT_LOG_WARN;
        break;
    case DYN_LIMIT_LOCATIONDEF_LIMIT_REQ_LOG_LEVEL_ERROR:
        lrcf->limit_log_level = NJT_LOG_ERR;
        break;
    }

    lrcf->delay_log_level = (lrcf->limit_log_level == NJT_LOG_INFO) ?
                                NJT_LOG_INFO : lrcf->limit_log_level + 1;
 
    return NJT_OK;
}


static njt_int_t njt_dyn_limit_set_limit_conn_dry_run(dyn_limit_servers_item_locations_item_t *data,
                njt_http_conf_ctx_t *ctx,
                njt_rpc_result_t *rpc_result)
{
    njt_conf_t                  *cf;
    njt_flag_t                   dry_run;
    njt_http_limit_conn_conf_t  *lccf;
    u_char                       data_buf[1024];
    u_char                      *end;
    njt_str_t                    rpc_data_str;

    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0; 

    if(!data->is_limit_conn_dry_run_set){
        return NJT_OK;
    }

    if(data->limit_conn_dry_run == DYN_LIMIT_LOCATIONDEF_LIMIT_CONN_DRY_RUN_ON){
        dry_run = 1;
    }else if (data->limit_conn_dry_run == DYN_LIMIT_LOCATIONDEF_LIMIT_CONN_DRY_RUN_OFF) {
        dry_run = 0;
    } else {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_limit_set_limit_conn_dry_run format error");
        
        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " dyn limit conn_dry_run format error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str); 

        return NJT_ERROR;
    }

    njt_conf_t cf_data = {
        .cycle = (njt_cycle_t *)njt_cycle,
        .log = njt_cycle->log,
        .ctx = ctx,
    };
    cf = &cf_data;

    lccf = njt_http_conf_get_module_loc_conf(cf, njt_http_limit_conn_module);
    if(lccf == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_limit_set_limit_conn_dry_run get module config error");
		
        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " dyn limit conn_dry_run get module config error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str); 
        
        return NJT_ERROR;
	}

    lccf->dry_run = dry_run;
 
    return NJT_OK;
}


static njt_int_t njt_dyn_limit_set_limit_req_dry_run(dyn_limit_servers_item_locations_item_t *data,
            njt_http_conf_ctx_t *ctx,
            njt_rpc_result_t *rpc_result)
{
    njt_conf_t                  *cf;
    njt_flag_t                   dry_run;
    njt_http_limit_req_conf_t   *lrcf;
    u_char                       data_buf[1024];
    u_char                      *end;
    njt_str_t                    rpc_data_str;

    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0; 

    if(!data->is_limit_req_dry_run_set){
        return NJT_OK;
    }

    if(data->limit_req_dry_run == DYN_LIMIT_LOCATIONDEF_LIMIT_REQ_DRY_RUN_ON){
        dry_run = 1;
    }else if (data->limit_req_dry_run == DYN_LIMIT_LOCATIONDEF_LIMIT_REQ_DRY_RUN_OFF) {
        dry_run = 0;
    } else {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_limit_set_limit_req_dry_run format error");
        
        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " dyn limit req_dry_run format error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str); 
        
        return NJT_ERROR;
    }

    njt_conf_t cf_data = {
        .cycle = (njt_cycle_t *)njt_cycle,
        .log = njt_cycle->log,
        .ctx = ctx,
    };
    cf = &cf_data;

    lrcf = njt_http_conf_get_module_loc_conf(cf, njt_http_limit_req_module);
    if(lrcf == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_limit_set_limit_req_dry_run get module config error");
		
        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " dyn limit req_dry_run get module config error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str); 
        
        return NJT_ERROR;
	}

    lrcf->dry_run = dry_run;
 
    return NJT_OK;
}

static njt_int_t njt_dyn_limit_update_rps(njt_cycle_t *cycle, dyn_limit_limit_rps_item_t *rps_date,
                njt_rpc_result_t *rpc_result){
    njt_uint_t                           i;
    njt_uint_t                           index = 0;
    njt_shm_zone_t                      *shm_zone;
    njt_list_part_t                     *part;
    size_t                               len;
    u_char                              *p;
    njt_int_t                            rate, scale;
    bool                                 found = false;
    bool                                 tag_match = true;
    void                                *rps_tag = &njt_http_limit_req_module;
    njt_http_limit_req_ctx_t            *req_ctx;
    u_char                               data_buf[1024];
    u_char                              *end;
    njt_str_t                            rpc_data_str;

    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;

    part = &cycle->shared_memory.part;
    shm_zone = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            shm_zone = part->elts;
            i = 0;
        }

        if (rps_date->zone.len != shm_zone[i].shm.name.len) {
            continue;
        }

        if (njt_strncmp(rps_date->zone.data, shm_zone[i].shm.name.data, rps_date->zone.len)
            != 0)
        {
            continue;
        }

        found = true;
        if (rps_tag != shm_zone[i].tag) {
            tag_match = false;
            continue;
        }

        index = i;
        break;
    }

    if(!found){
        njt_log_error(NJT_LOG_ERR, cycle->log, 0, " update rps zone:%V  is not exist", &rps_date->zone);
        
        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " update rps zone:%V  is not exist", 
            &rps_date->zone);
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);  

        return NJT_ERROR;
    }

    if(!tag_match){
        njt_log_error(NJT_LOG_ERR, cycle->log, 0, " update rps zone:%V  tag error", &rps_date->zone);

        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " update rps zone:%V  tag error", 
            &rps_date->zone);
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
        return NJT_ERROR;
    }

    rate = 1;
    scale = 1;
    len = rps_date->rate.len;
    p = rps_date->rate.data + len - 3;
    if (njt_strncmp(p, "r/s", 3) == 0) {
        scale = 1;
        len -= 3;

    } else if (njt_strncmp(p, "r/m", 3) == 0) {
        scale = 60;
        len -= 3;
    }

    rate = njt_atoi(rps_date->rate.data, len);
    if (rate <= 0) {
        njt_log_error(NJT_LOG_ERR, cycle->log, 0, " update rps zone:%V  rate invalid", &rps_date->zone);
        
        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " update rps zone:%V  rate invalid", 
            &rps_date->zone);
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
        return NJT_ERROR;
    }

    req_ctx = shm_zone[index].data;
    if(req_ctx == NULL){
        njt_log_error(NJT_LOG_EMERG, cycle->log, 0, " update rps zone:%V  zone data is null", &rps_date->zone);
        
        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " update rps zone:%V  zone data is null", 
            &rps_date->zone);
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
        return NJT_ERROR;
    }

    req_ctx->rate = rate * 1000 / scale;
    req_ctx->ori_rate = rate;
    req_ctx->scale = scale;

    return NJT_OK;
}

static njt_int_t njt_dyn_limit_update_locs(njt_array_t *locs, njt_queue_t *q, njt_http_conf_ctx_t *ctx,
                njt_rpc_result_t *rpc_result)
{
    njt_http_core_loc_conf_t            *clcf;
    njt_http_location_queue_t           *hlq;
    dyn_limit_servers_item_locations_item_t            *dlil;
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
        dlil = get_dyn_limit_servers_item_locations_item(locs, j);
        if(dlil == NULL || !dlil->is_location_set){
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " index %d not set location name", j);
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            continue;
        }

        name = get_dyn_limit_locationDef_location(dlil);

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
                njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "dynlimit start set location:%V", &clcf->full_name);
                
                found = true;
                //set limit_conns
                rc = njt_dyn_limit_set_limit_conns(dlil, ctx, rpc_result);
                if (rc != NJT_OK)
                {
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "error in njt_dyn_limit_set_limit_conns");
                }

                //set limit_reqs
                rc = njt_dyn_limit_set_limit_reqs(dlil, ctx, rpc_result);
                if (rc != NJT_OK)
                {
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "error in njt_dyn_limit_set_limit_reqs");
                }
                
                //set limit_rate
                rc = njt_dyn_limit_set_limit_rate(dlil, ctx, rpc_result);
                if (rc != NJT_OK)
                {
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " error in njt_dyn_limit_set_limit_rate");
                }

                //set limit_rate_after
                rc = njt_dyn_limit_set_limit_rate_after(dlil, ctx, rpc_result);
                if (rc != NJT_OK)
                {
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " error in njt_dyn_limit_set_limit_rate_after");
                }

                //set limit_conn_dry_run
                rc = njt_dyn_limit_set_limit_conn_dry_run(dlil, ctx, rpc_result);
                if (rc != NJT_OK)
                {
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " error in njt_dyn_limit_set_limit_conn_dry_run");
                }

                //set limit_req_dry_run
                rc = njt_dyn_limit_set_limit_req_dry_run(dlil, ctx, rpc_result);
                if (rc != NJT_OK)
                {
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " error in njt_dyn_limit_set_limit_req_dry_run");
                }  

                //set limit_conn_log_level
                rc = njt_dyn_limit_set_limit_conn_log_level(dlil, ctx, rpc_result);
                if (rc != NJT_OK)
                {
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " error in njt_dyn_limit_set_limit_conn_log_level");
                }

                //set limit_req_log_level
                rc = njt_dyn_limit_set_limit_req_log_level(dlil, ctx, rpc_result);
                if (rc != NJT_OK)
                {
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " error in njt_dyn_limit_set_limit_req_log_level");
                }

                //set limit_conn_status
                rc = njt_dyn_limit_set_limit_conn_status(dlil, ctx, rpc_result);
                if (rc != NJT_OK)
                {
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " error in njt_dyn_limit_set_limit_conn_status");
                }

                //set limit_req_status
                rc = njt_dyn_limit_set_limit_req_status(dlil, ctx, rpc_result);
                if (rc != NJT_OK)
                {
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " error in njt_dyn_limit_set_limit_req_status");
                }

                if (dlil->is_locations_set && dlil->locations && dlil->locations->nelts > 0) {
                    njt_dyn_limit_update_locs(dlil->locations, clcf->old_locations, ctx, rpc_result);
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

static void njt_dyn_limit_dump_locs_json(njt_pool_t *pool, 
        njt_queue_t *locations, dyn_limit_servers_item_locations_t *loc_items)
{
    njt_http_core_loc_conf_t      *clcf;
    njt_http_location_queue_t     *hlq;
    njt_queue_t                   *q, *tq;
    njt_http_limit_conn_conf_t    *lccf;
    njt_http_limit_req_conf_t     *lrcf;
    njt_uint_t                     i;
    njt_http_limit_conn_limit_t   *conn_limits;
    njt_http_limit_req_limit_t    *req_limits;
    njt_uint_t                     delay;
    njt_uint_t                     delay_max_comp;
    njt_str_t                      *delay_str;
    u_char                        *p; 
    njt_int_t                      delay_max_len = 100;
    dyn_limit_servers_item_locations_item_t *loc_item;
    dyn_limit_locationDef_limit_conns_item_t *limit_conn_item;
    dyn_limit_locationDef_limit_reqs_item_t  *limit_req_item;

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

        lccf = njt_http_get_module_loc_conf(clcf, njt_http_limit_conn_module);
        lrcf = njt_http_get_module_loc_conf(clcf, njt_http_limit_req_module);

        loc_item = create_dyn_limit_locationDef(pool);
        if(loc_item == NULL){
            continue;
        }
        set_dyn_limit_locationDef_location(loc_item, &clcf->full_name);

        if(clcf->limit_rate){
            set_dyn_limit_locationDef_limit_rate(loc_item, &clcf->limit_rate->value);
        }

        if(clcf->limit_rate_after){
            set_dyn_limit_locationDef_limit_rate_after(loc_item, &clcf->limit_rate_after->value);
        }

        if(lccf != NULL)
        {
            if(lccf->from_up == 1){
                set_dyn_limit_locationDef_limit_conns_scope(loc_item, DYN_LIMIT_LOCATIONDEF_LIMIT_CONNS_SCOPE_UP_SHARE);
            }else{
                set_dyn_limit_locationDef_limit_conns_scope(loc_item, DYN_LIMIT_LOCATIONDEF_LIMIT_CONNS_SCOPE_LOCATION);
            }

            set_dyn_limit_locationDef_limit_conns(loc_item, create_dyn_limit_locationDef_limit_conns(pool, 4));
            if(loc_item->limit_conns == NULL){
                return;
            }

            if(lccf->limits.nelts > 0){
                conn_limits = lccf->limits.elts;
                for (i = 0; i < lccf->limits.nelts; i++) {
                    limit_conn_item = create_dyn_limit_locationDef_limit_conns_item(pool);
                    if(limit_conn_item == NULL){
                        return;
                    }

                    set_dyn_limit_locationDef_limit_conns_item_zone(limit_conn_item, &conn_limits[i].shm_zone->shm.name);
                    set_dyn_limit_locationDef_limit_conns_item_conn(limit_conn_item, conn_limits[i].conn);

                    add_item_dyn_limit_locationDef_limit_conns(loc_item->limit_conns, limit_conn_item);
                }
            }

            if(lccf->dry_run == 1){
                set_dyn_limit_locationDef_limit_conn_dry_run(loc_item, DYN_LIMIT_LOCATIONDEF_LIMIT_CONN_DRY_RUN_ON);
            }else{
                set_dyn_limit_locationDef_limit_conn_dry_run(loc_item, DYN_LIMIT_LOCATIONDEF_LIMIT_CONN_DRY_RUN_OFF);
            }

            switch (lccf->log_level)
            {
            case NJT_LOG_INFO:
                set_dyn_limit_locationDef_limit_conn_log_level(loc_item, DYN_LIMIT_LOCATIONDEF_LIMIT_CONN_LOG_LEVEL_INFO);
                break;
            case NJT_LOG_NOTICE:
                set_dyn_limit_locationDef_limit_conn_log_level(loc_item, DYN_LIMIT_LOCATIONDEF_LIMIT_CONN_LOG_LEVEL_NOTICE);
                break;
            case NJT_LOG_WARN:
                set_dyn_limit_locationDef_limit_conn_log_level(loc_item, DYN_LIMIT_LOCATIONDEF_LIMIT_CONN_LOG_LEVEL_WARN);
                break;
            case NJT_LOG_ERR:
                set_dyn_limit_locationDef_limit_conn_log_level(loc_item, DYN_LIMIT_LOCATIONDEF_LIMIT_CONN_LOG_LEVEL_ERROR);
                break;
            default:
                set_dyn_limit_locationDef_limit_conn_log_level(loc_item, DYN_LIMIT_LOCATIONDEF_LIMIT_CONN_LOG_LEVEL_INFO);
                break;
            }

            set_dyn_limit_locationDef_limit_conn_status(loc_item, lccf->status_code);
        }

        if(lrcf != NULL)
        {
            if(lrcf->from_up == 1){
                set_dyn_limit_locationDef_limit_reqs_scope(loc_item, DYN_LIMIT_LOCATIONDEF_LIMIT_REQS_SCOPE_UP_SHARE);
            }else{
                set_dyn_limit_locationDef_limit_reqs_scope(loc_item, DYN_LIMIT_LOCATIONDEF_LIMIT_REQS_SCOPE_LOCATION);
            }
            
            set_dyn_limit_locationDef_limit_reqs(loc_item, create_dyn_limit_locationDef_limit_reqs(pool, 4));
            if(loc_item->limit_reqs == NULL){
                return;
            }

            if(lrcf->limits.nelts > 0){
                req_limits = lrcf->limits.elts;
                for (i = 0; i < lrcf->limits.nelts; i++) {
                    limit_req_item = create_dyn_limit_locationDef_limit_reqs_item(pool);
                    if(limit_req_item == NULL){
                        return;
                    }

                    set_dyn_limit_locationDef_limit_reqs_item_zone(limit_req_item, &req_limits[i].shm_zone->shm.name);
                    set_dyn_limit_locationDef_limit_reqs_item_burst(limit_req_item, req_limits[i].burst / 1000);

                    delay_max_comp = NJT_MAX_INT_T_VALUE / 1000;
                    delay_max_comp *= 1000;

                    delay_str = njt_pcalloc(pool, sizeof(njt_str_t));
                    if(delay_str == NULL){
                        return;
                    }

                    delay_str->data = njt_pcalloc(pool, delay_max_len);
                    if(delay_str->data == NULL){
                        return;
                    }

                    njt_memzero(delay_str->data, delay_max_len);
                    if(req_limits[i].delay == delay_max_comp){
                        delay_str->len = sizeof("nodelay");
                        njt_memcpy(delay_str->data, "nodelay", delay_str->len);
                    }else{
                        delay = req_limits[i].delay / 1000;
                        
                        p = njt_snprintf(delay_str->data, delay_max_len, "%d", delay);
                        delay_str->len = p - delay_str->data;
                    }
                    set_dyn_limit_locationDef_limit_reqs_item_delay(limit_req_item, delay_str);

                    add_item_dyn_limit_locationDef_limit_reqs(loc_item->limit_reqs, limit_req_item);
                }
            }

            if(lrcf->dry_run == 1){
                set_dyn_limit_locationDef_limit_req_dry_run(loc_item, DYN_LIMIT_LOCATIONDEF_LIMIT_REQ_DRY_RUN_ON);
            }else{
                set_dyn_limit_locationDef_limit_req_dry_run(loc_item, DYN_LIMIT_LOCATIONDEF_LIMIT_REQ_DRY_RUN_OFF);
            }

            switch (lrcf->limit_log_level)
            {
            case NJT_LOG_INFO:
                set_dyn_limit_locationDef_limit_req_log_level(loc_item, DYN_LIMIT_LOCATIONDEF_LIMIT_REQ_LOG_LEVEL_INFO);
                break;
            case NJT_LOG_NOTICE:
                set_dyn_limit_locationDef_limit_req_log_level(loc_item, DYN_LIMIT_LOCATIONDEF_LIMIT_REQ_LOG_LEVEL_NOTICE);
                break;
            case NJT_LOG_WARN:
                set_dyn_limit_locationDef_limit_req_log_level(loc_item, DYN_LIMIT_LOCATIONDEF_LIMIT_REQ_LOG_LEVEL_WARN);
                break;
            case NJT_LOG_ERR:
                set_dyn_limit_locationDef_limit_req_log_level(loc_item, DYN_LIMIT_LOCATIONDEF_LIMIT_REQ_LOG_LEVEL_ERROR);
                break;
            default:
                set_dyn_limit_locationDef_limit_req_log_level(loc_item, DYN_LIMIT_LOCATIONDEF_LIMIT_REQ_LOG_LEVEL_INFO);
                break;
            }

            set_dyn_limit_locationDef_limit_req_status(loc_item, lrcf->status_code);
        }

        if (clcf->old_locations) {
            set_dyn_limit_locationDef_locations(loc_item, create_dyn_limit_locationDef_locations(pool, 4));
            if(loc_item->locations != NULL){
                njt_dyn_limit_dump_locs_json(pool, clcf->old_locations, loc_item->locations);
            }
        }

        add_item_dyn_limit_servers_item_locations(loc_items, loc_item);
    }
}

static njt_str_t *njt_dyn_limit_dump_limit_conf(njt_cycle_t *cycle, njt_pool_t *pool)
{
    njt_http_core_loc_conf_t        *clcf;
    njt_http_core_main_conf_t       *hcmcf;
    njt_http_core_srv_conf_t        **cscfp;
    njt_uint_t                      i, j;
    njt_array_t                     *array;
    njt_str_t                       *tmp_str, rate_str;
    njt_http_server_name_t          *server_name;
    njt_list_part_t                 *part;
    njt_int_t                       tmp_rate;
    njt_shm_zone_t                  *shm_zone;
    u_char                          *p; 
    njt_http_limit_req_ctx_t        *req_ctx;
    void                            *rps_tag = &njt_http_limit_req_module;
    njt_int_t                       rate_max_len = 100;
    dyn_limit_t                     dynjson_obj;
    dyn_limit_servers_item_t        *server_item;
    dyn_limit_limit_rps_item_t      *rps_item;

    njt_memzero(&dynjson_obj, sizeof(dyn_limit_t));
    hcmcf = njt_http_cycle_get_module_main_conf(cycle, njt_http_core_module);
    if(hcmcf == NULL){
        goto err;
    }

    set_dyn_limit_servers(&dynjson_obj, create_dyn_limit_servers(pool, 4));
    if(dynjson_obj.servers == NULL){
        goto err;
    }

    cscfp = hcmcf->servers.elts;
    for (i = 0; i < hcmcf->servers.nelts; i++)
    {
        server_item = create_dyn_limit_servers_item(pool);
        if(server_item == NULL){
            goto err;
        }

        set_dyn_limit_servers_item_listens(server_item, create_dyn_limit_servers_item_listens(pool, 4));
        set_dyn_limit_servers_item_serverNames(server_item, create_dyn_limit_servers_item_serverNames(pool, 4));
        set_dyn_limit_servers_item_locations(server_item, create_dyn_limit_servers_item_locations(pool, 4));

        array = njt_array_create(pool, 4, sizeof(njt_str_t));
        if(array == NULL){
            goto err;
        }
        njt_http_get_listens_by_server(array, cscfp[i]);

        for (j = 0; j < array->nelts; ++j) {
            tmp_str = (njt_str_t *)(array->elts)+ j;
            add_item_dyn_limit_servers_item_listens(server_item->listens, tmp_str);
        }

        server_name = cscfp[i]->server_names.elts;
        for (j = 0; j < cscfp[i]->server_names.nelts; ++j) {
            tmp_str = &server_name[j].full_name;
            add_item_dyn_limit_servers_item_serverNames(server_item->serverNames, tmp_str);
        }

        clcf = njt_http_get_module_loc_conf(cscfp[i]->ctx, njt_http_core_module);
        if(clcf != NULL){
            njt_dyn_limit_dump_locs_json(pool, clcf->old_locations, server_item->locations);
        }

        add_item_dyn_limit_servers(dynjson_obj.servers, server_item);
    }

    set_dyn_limit_limit_rps(&dynjson_obj, create_dyn_limit_limit_rps(pool, 4));
    if(dynjson_obj.limit_rps == NULL){
        goto err;
    }

    part = &cycle->shared_memory.part;
    shm_zone = part->elts;
    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            shm_zone = part->elts;
            i = 0;
        }

        if (rps_tag != shm_zone[i].tag) {
            continue;
        }

        rps_item = create_dyn_limit_limit_rps_item(pool);
        if (rps_item == NULL)
        {
            goto err;
        }

        set_dyn_limit_limit_rps_item_zone(rps_item, &shm_zone[i].shm.name);

        req_ctx = shm_zone[i].data;
        if(req_ctx == NULL){
            rate_str.len = sizeof("0r/s");
            rate_str.data = njt_pcalloc(pool, rate_str.len);
            njt_memcpy(rate_str.data, "0r/s", rate_str.len);
        }else{
            tmp_rate = req_ctx->ori_rate;
            rate_str.data = njt_pcalloc(pool, rate_max_len);
            // njt_memzero(rate_str.data, rate_max_len);
            if(60 == req_ctx->scale){
                p = njt_snprintf(rate_str.data, rate_max_len, "%dr/m", tmp_rate);
            }else{
                p = njt_snprintf(rate_str.data, rate_max_len, "%dr/s", tmp_rate);
            }

            rate_str.len = p - rate_str.data;
        }

        set_dyn_limit_limit_rps_item_rate(rps_item, &rate_str);

        add_item_dyn_limit_limit_rps(dynjson_obj.limit_rps, rps_item);
    }

    return to_json_dyn_limit(pool, &dynjson_obj, OMIT_NULL_ARRAY | OMIT_NULL_OBJ | OMIT_NULL_STR);

err:
    return &dyn_limit_update_srv_err_msg;
}

static njt_int_t njt_dyn_limit_update_limit_conf(njt_pool_t *pool, dyn_limit_t *api_data,
                        njt_rpc_result_t *rpc_result)
{
    njt_cycle_t                         *cycle;
    njt_http_core_srv_conf_t            *cscf;
    njt_http_core_loc_conf_t            *clcf;
    dyn_limit_servers_item_t            *dsi;
    dyn_limit_limit_rps_item_t          *rps_datas;
    njt_str_t                           *port, *serverName;
    njt_uint_t                           i;
    njt_int_t                            rc;
    u_char                               data_buf[1024];
    u_char                              *end;
    njt_str_t                            rpc_data_str;


    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;

    cycle = (njt_cycle_t *)njt_cycle;

    //update rps
    if(api_data->is_limit_rps_set && api_data->limit_rps != NULL){
        for(i = 0; i < api_data->limit_rps->nelts; ++i){
            rps_datas = get_dyn_limit_limit_rps_item(api_data->limit_rps, i);
            njt_str_null(&rpc_result->conf_path);

            if(rps_datas == NULL || !rps_datas->is_zone_set 
                || !rps_datas->is_rate_set || rps_datas->zone.len < 1 
                || rps_datas->rate.len < 3){
                njt_log_error(NJT_LOG_INFO, pool->log, 0, 
                    "update limit rps error, format invalid, zone:%V  rate:%V",
                    &rps_datas->zone, &rps_datas->rate);

                end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
                    " update limit rps error, format invalid, zone:%V  rate:%V", 
                    &rps_datas->zone, &rps_datas->rate);
                rpc_data_str.len = end - data_buf;
                njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);    
                continue;
            }
            rc = njt_dyn_limit_update_rps(cycle, rps_datas, rpc_result);
            if(rc != NJT_OK){
                njt_log_error(NJT_LOG_INFO, pool->log, 0, "update limit rps error, zone:%V",
                    &rps_datas->zone);
            }
        }
    }

    if(api_data->is_servers_set && api_data->servers != NULL){
        for (i = 0; i < api_data->servers->nelts; ++i)
        {
            dsi = get_dyn_limit_servers_item(api_data->servers, i);
            if (dsi == NULL || !dsi->is_listens_set || !dsi->is_serverNames_set 
                    || dsi->listens->nelts < 1 
                    || dsi->serverNames->nelts < 1) {
                // listens or server_names is empty
                end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
                    " server parameters error, listens or serverNames or locations is empty,at position %d", i);
                rpc_data_str.len = end - data_buf;
                njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                continue;
            }

            port = get_dyn_limit_servers_item_listens_item(dsi->listens, 0);
            serverName = get_dyn_limit_servers_item_serverNames_item(dsi->serverNames, 0);
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

            njt_log_error(NJT_LOG_INFO, pool->log, 0, "dynlimit start update listen:%V server_name:%V",
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
                rc = njt_dyn_limit_update_locs(dsi->locations, clcf->old_locations, &ctx, rpc_result);
                if(rc != NJT_OK){
                    njt_log_error(NJT_LOG_INFO, pool->log, 0, "update limit error, listen:%V server_name:%V",
                        port, serverName);
                }
            }
        }
    }

    return NJT_OK;
}

static u_char *njt_dyn_limit_rpc_handler(njt_str_t *topic, njt_str_t *request, int *len, void *data)
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
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_limit_rpc_handler create pool error");
        goto out;
    }

    msg = njt_dyn_limit_dump_limit_conf(cycle, pool);
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

static int njt_dyn_limit_update_handler(njt_str_t *key, njt_str_t *value, void *data, njt_str_t *out_msg)
{
    njt_int_t                            rc = NJT_OK;
    dyn_limit_t                         *api_data = NULL;
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
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_limit_change_handler create pool error");
        
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_MEM_ALLOC);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" update handler create pool error");
        rc = NJT_ERROR;

        goto end;
    }

    api_data = json_parse_dyn_limit(pool, value, &err_info);
    if (api_data == NULL)
    {
        njt_log_error(NJT_LOG_ERR, pool->log, 0, 
                "json_parse_dyn_limit err: %V",  &err_info.err_str);
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_JSON);
        njt_rpc_result_set_msg2(rpc_result, &err_info.err_str);

        rc = NJT_ERROR;
        goto err_msg;
    }

    njt_rpc_result_set_code(rpc_result,NJT_RPC_RSP_SUCCESS);

    rc = njt_dyn_limit_update_limit_conf(pool, api_data, rpc_result);
    if(rc != NJT_OK){
        njt_rpc_result_set_code(rpc_result,NJT_RPC_RSP_ERR);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" limit update fail");
    }else{
        if(rpc_result->data != NULL && rpc_result->data->nelts > 0){
            njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_PARTIAL_SUCCESS);
        }
    }

err_msg:
    if (rc != NJT_OK) {
        njt_str_t msg=njt_string("");
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

static int  njt_dyn_limit_change_handler(njt_str_t *key, njt_str_t *value, void *data){
    return njt_dyn_limit_update_handler(key, value, data, NULL);
}

static u_char* njt_dyn_limit_put_handler(njt_str_t *topic, njt_str_t *request, int* len, void *data){
    njt_str_t err_json_msg;
    njt_str_null(&err_json_msg);
    njt_dyn_limit_update_handler(topic, request, data, &err_json_msg);
    *len = err_json_msg.len;
    return err_json_msg.data;
}

static njt_int_t njt_http_dyn_limit_module_init_process(njt_cycle_t *cycle)
{
    njt_str_t limit_rpc_key = njt_string("http_dyn_limit");
    njt_kv_reg_handler_t h;
    njt_memzero(&h, sizeof(njt_kv_reg_handler_t));
    h.key = &limit_rpc_key;
    h.rpc_get_handler = njt_dyn_limit_rpc_handler;
    h.rpc_put_handler = njt_dyn_limit_put_handler;
    h.handler = njt_dyn_limit_change_handler;
    h.api_type = NJT_KV_API_TYPE_DECLATIVE;
    njt_kv_reg_handler(&h);

    return NJT_OK;
}

static njt_http_module_t njt_http_dyn_limit_module_ctx = {
    NULL, /* preconfiguration */
    NULL, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    NULL, /* create location configuration */
    NULL  /* merge location configuration */
};

njt_module_t njt_http_dyn_limit_module = {
    NJT_MODULE_V1,
    &njt_http_dyn_limit_module_ctx,         /* module context */
    NULL,                                    /* module directives */
    NJT_HTTP_MODULE,                         /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    njt_http_dyn_limit_module_init_process, /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NJT_MODULE_V1_PADDING};
