/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */
#include <njt_core.h>
#include <njt_http_kv_module.h>
#include <njt_http.h>
#include <njt_json_util.h>
#include <njt_http_util.h>
#include <njt_http_dyn_module.h>

#include "njt_http_dyn_fault_inject_parser.h"
#include "njt_http_fault_inject_module.h"

#include <njt_rpc_result_util.h>

extern njt_module_t njt_http_fault_inject_module;



njt_str_t dyn_fault_inject_update_srv_err_msg = njt_string("{\"code\":500,\"msg\":\"server error\"}");


static njt_int_t njt_dyn_fault_inject_set_conf_by_none(
            njt_pool_t *pool, 
            dyn_fault_inject_servers_item_locations_item_t *data,
            njt_http_conf_ctx_t *ctx,
            njt_rpc_result_t *rpc_result)
{
    njt_conf_t                  *cf;
    njt_http_fault_inject_conf_t   *ficf;
    u_char                       data_buf[1024];
    u_char                      *end;
    njt_str_t                    rpc_data_str;

    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;

    njt_conf_t cf_data = {
        .cycle = (njt_cycle_t *)njt_cycle,
        .log = njt_cycle->log,
        .ctx = ctx,
    };
    cf = &cf_data;

    ficf = njt_http_conf_get_module_loc_conf(cf, njt_http_fault_inject_module);
    if(ficf == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_fault_inject_set_conf_by_none get module config error");
		
        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " dyn fault_inject none type get module config error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str); 
        
        return NJT_ERROR;
	}

    //set default value
    ficf->abort_percent = 100;
    ficf->delay_percent = 100;
    ficf->duration = 0;
    njt_str_null(&ficf->str_duration);
    ficf->fault_inject_type = NJT_HTTP_FAULT_INJECT_NONE;
    ficf->status_code = 200;

    if(ficf->dynamic){
        njt_destroy_pool(ficf->pool);
    }

    ficf->dynamic = 1;
    ficf->pool = pool;

    ficf->str_duration.data = NULL;
    ficf->str_duration.len = 0;

    return NJT_OK;
}


static njt_int_t njt_dyn_fault_inject_set_conf_by_delay(
            njt_pool_t *pool, 
            dyn_fault_inject_servers_item_locations_item_t *data,
            njt_http_conf_ctx_t *ctx,
            njt_rpc_result_t *rpc_result)
{
    njt_conf_t                  *cf;
    njt_http_fault_inject_conf_t   *ficf;
    njt_http_fault_inject_conf_t   new_ficf;
    u_char                       data_buf[1024];
    u_char                      *end;
    njt_str_t                    rpc_data_str;

    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;

    njt_conf_t cf_data = {
        .cycle = (njt_cycle_t *)njt_cycle,
        .log = njt_cycle->log,
        .ctx = ctx,
    };
    cf = &cf_data;

    ficf = njt_http_conf_get_module_loc_conf(cf, njt_http_fault_inject_module);
    if(ficf == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, 
            "njt_dyn_fault_inject_set_conf_by_delay get module config error");
		
        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " dyn fault_inject delay type get module config error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str); 
        
        return NJT_ERROR;
	}

    //set default value
    new_ficf.abort_percent = 100;
    new_ficf.delay_percent = 100;
    new_ficf.duration = 0;
    njt_str_null(&new_ficf.str_duration);
    new_ficf.fault_inject_type = NJT_HTTP_FAULT_INJECT_DELAY;
    new_ficf.status_code = 200;

    if(!data->is_delay_duration_set){
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
            " dyn fault inject, delay_duration must set, should 1h/1m/1s/1ms format");

        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " dyn fault inject, delay_duration must set, should 1h/1m/1s/1ms format");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str); 

        return NJT_ERROR;
    }

    //check delay_percent
    if (data->is_delay_percentage_set && (data->delay_percentage < 1 || data->delay_percentage > 100)) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
            " dyn fault inject, invalid delay_percent, shoud [1,100]");

        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " dyn fault inject, invalid delay_percent, shoud [1,100]");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str); 
        return NJT_ERROR;
	}

    if(data->is_delay_percentage_set){
        new_ficf.delay_percent = data->delay_percentage;
    }  

    if(data->is_delay_duration_set){
        //check duration
        new_ficf.duration = njt_parse_time(&data->delay_duration, 0);
        if (new_ficf.duration == (njt_msec_t) NJT_ERROR) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                " dyn fault inject, invalid delay_duration, should 1h/1m/1s/1ms format");

            end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
                " dyn fault inject, invalid delay_duration, should 1h/1m/1s/1ms format");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str); 

            return NJT_ERROR;
        }

        if (new_ficf.duration < 1) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                " dyn fault inject, delay_duration should not less than 1ms");

            end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
                " dyn fault inject, delay_duration should not less than 1ms");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str); 

            return NJT_ERROR;
        }

        new_ficf.str_duration.len = data->delay_duration.len;
        new_ficf.str_duration.data = njt_pcalloc(pool, data->delay_duration.len);
        if(new_ficf.str_duration.data == NULL){
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                " dyn fault inject, duration malloc error");

            end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
                " dyn fault inject, duration malloc error");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str); 

            return NJT_ERROR;  
        }
        njt_memcpy(new_ficf.str_duration.data, data->delay_duration.data, data->delay_duration.len);
    }

    if(ficf->dynamic){
        njt_destroy_pool(ficf->pool);
    }
    
    //check ok, update config
    *ficf = new_ficf;

    ficf->dynamic = 1;
    ficf->pool = pool;

    return NJT_OK;
}


static njt_int_t njt_dyn_fault_inject_set_conf_by_abort(
            njt_pool_t *pool, 
            dyn_fault_inject_servers_item_locations_item_t *data,
            njt_http_conf_ctx_t *ctx,
            njt_rpc_result_t *rpc_result)
{
    njt_conf_t                  *cf;
    njt_http_fault_inject_conf_t   *ficf;
    njt_http_fault_inject_conf_t   new_ficf;
    u_char                       data_buf[1024];
    u_char                      *end;
    njt_str_t                    rpc_data_str;

    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;

    njt_conf_t cf_data = {
        .cycle = (njt_cycle_t *)njt_cycle,
        .log = njt_cycle->log,
        .ctx = ctx,
    };
    cf = &cf_data;

    ficf = njt_http_conf_get_module_loc_conf(cf, njt_http_fault_inject_module);
    if(ficf == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_fault_inject_set_conf_by_abort get module config error");
		
        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " dyn fault_inject delay type get module config error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str); 
        
        return NJT_ERROR;
	}

    //set default value
    new_ficf.abort_percent = 100;
    new_ficf.delay_percent = 100;
    new_ficf.duration = 0;
    njt_str_null(&new_ficf.str_duration);
    new_ficf.fault_inject_type = NJT_HTTP_FAULT_INJECT_ABORT;
    new_ficf.status_code = 200;

    //check abort_percent
    if (data->is_abort_percentage_set && (data->abort_percentage < 1 || data->abort_percentage > 100)) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
            " dyn fault inject, invalid abort_percent, shoud [1,100]");

        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " dyn fault inject, invalid abort_percent, shoud [1,100]");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

        return NJT_ERROR;
	}
    if (data->is_abort_percentage_set){
        new_ficf.abort_percent = data->abort_percentage;
    }

    if (data->is_status_code_set && (data->status_code < 200 || data->status_code > 600)) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
            " dyn fault inject, status_code should [200, 600]");

        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " dyn fault inject, status_code should [200, 600]");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str); 

        return NJT_ERROR;
    }
    if (data->is_status_code_set){
        new_ficf.status_code = data->status_code;
    }

    if(ficf->dynamic){
        njt_destroy_pool(ficf->pool);
    }
    //check ok, update config
    *ficf = new_ficf;

    ficf->dynamic = 1;
    ficf->pool = pool;

    ficf->str_duration.data = NULL;
    ficf->str_duration.len = 0;

    return NJT_OK;
}


static njt_int_t njt_dyn_fault_inject_set_conf_by_delay_abort(
            njt_pool_t *pool, 
            dyn_fault_inject_servers_item_locations_item_t *data,
            njt_http_conf_ctx_t *ctx,
            njt_rpc_result_t *rpc_result)
{
    njt_conf_t                  *cf;
    njt_http_fault_inject_conf_t   *ficf;
    njt_http_fault_inject_conf_t   new_ficf;
    u_char                       data_buf[1024];
    u_char                      *end;
    njt_str_t                    rpc_data_str;

    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;

    njt_conf_t cf_data = {
        .cycle = (njt_cycle_t *)njt_cycle,
        .log = njt_cycle->log,
        .ctx = ctx,
    };
    cf = &cf_data;

    ficf = njt_http_conf_get_module_loc_conf(cf, njt_http_fault_inject_module);
    if(ficf == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_fault_inject_set_conf_by_delay get module config error");
		
        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " dyn fault_inject delay type get module config error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str); 
        
        return NJT_ERROR;
	}

    //set default value
    new_ficf.abort_percent = 100;
    new_ficf.delay_percent = 100;
    new_ficf.duration = 0;
    njt_str_null(&new_ficf.str_duration);
    new_ficf.fault_inject_type = NJT_HTTP_FAULT_INJECT_DELAY_ABORT;
    new_ficf.status_code = 200;

    //check delay_percent
    if (data->is_delay_percentage_set && (data->delay_percentage < 1 || data->delay_percentage > 100)) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
            " dyn fault inject, invalid delay_percent, shoud [1,100]");

        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " dyn fault inject, invalid delay_percent, shoud [1,100]");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str); 
        return NJT_ERROR;
	}
    if (data->is_delay_percentage_set){
        new_ficf.delay_percent = data->delay_percentage;
    }

    if(data->is_delay_duration_set){
        //check duration
        new_ficf.duration = njt_parse_time(&data->delay_duration, 0);
        if (new_ficf.duration == (njt_msec_t) NJT_ERROR) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                " dyn fault inject, invalid delay_duration, should 1h/1m/1s/1ms format");

            end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
                " dyn fault inject, invalid delay_duration, should 1h/1m/1s/1ms format");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str); 

            return NJT_ERROR;
        }

        if (new_ficf.duration < 1) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                " dyn fault inject, delay_duration should not less than 1ms");

            end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
                " dyn fault inject, delay_duration should not less than 1ms");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str); 

            return NJT_ERROR;
        }

        new_ficf.str_duration.len = data->delay_duration.len;
        new_ficf.str_duration.data = njt_pcalloc(pool, data->delay_duration.len);
        if(new_ficf.str_duration.data == NULL){
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                " dyn fault inject, duration malloc error");

            end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
                " dyn fault inject, duration malloc error");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str); 

            return NJT_ERROR;  
        }
        njt_memcpy(new_ficf.str_duration.data, data->delay_duration.data, data->delay_duration.len);
    }

    //check abort_percent
    if (data->is_abort_percentage_set && (data->abort_percentage < 1 || data->abort_percentage > 100)) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
            " dyn fault inject, invalid abort_percent, shoud [1,100]");

        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " dyn fault inject, invalid abort_percent, shoud [1,100]");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

        return NJT_ERROR;
	}
    if (data->is_abort_percentage_set){
        new_ficf.abort_percent = data->abort_percentage;
    }

    if (data->is_status_code_set && (data->status_code < 200 || data->status_code > 600)) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
            " dyn fault inject, status_code should [200, 600]");

        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " dyn fault inject, status_code should [200, 600]");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str); 

        return NJT_ERROR;
    }
    if (data->is_status_code_set){
        new_ficf.status_code = data->status_code;
    }

    if(ficf->dynamic){
        njt_destroy_pool(ficf->pool);
    }
    
    //check ok, update config
    *ficf = new_ficf;

    ficf->dynamic = 1;
    ficf->pool = pool;

    return NJT_OK;
}


static njt_int_t njt_dyn_fault_inject_set_conf(njt_pool_t *pool,
            dyn_fault_inject_servers_item_locations_item_t *data,
            njt_http_conf_ctx_t *ctx,
            njt_rpc_result_t *rpc_result)
{
    u_char                       data_buf[1024];
    u_char                      *end;
    njt_str_t                    rpc_data_str;
    njt_int_t                    rc = NJT_OK;

    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0; 

    if(!data->is_fault_inject_type_set){
        return NJT_OK;
    }

    //check type
    switch (data->fault_inject_type)
    {
    case DYN_FAULT_INJECT_LOCATIONDEF_FAULT_INJECT_TYPE_NONE:
        rc = njt_dyn_fault_inject_set_conf_by_none(pool, data, ctx, rpc_result);
        break;
    case DYN_FAULT_INJECT_LOCATIONDEF_FAULT_INJECT_TYPE_DELAY:
        rc = njt_dyn_fault_inject_set_conf_by_delay(pool, data, ctx, rpc_result);
        break;
    case DYN_FAULT_INJECT_LOCATIONDEF_FAULT_INJECT_TYPE_ABORT:
        rc = njt_dyn_fault_inject_set_conf_by_abort(pool, data, ctx, rpc_result);
        break;
    case DYN_FAULT_INJECT_LOCATIONDEF_FAULT_INJECT_TYPE_DELAY_ABORT:
        rc = njt_dyn_fault_inject_set_conf_by_delay_abort(pool, data, ctx, rpc_result);
        /* code */
        break;    
    default:
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, 
                "dyn fault_inject type error");
        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,
            " dyn fault_inject type error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

        rc = NJT_ERROR;
        break;
    }

    return rc;
}


static njt_int_t njt_dyn_fault_inject_update_locs(njt_array_t *locs, njt_queue_t *q, njt_http_conf_ctx_t *ctx,
                njt_rpc_result_t *rpc_result)
{
    njt_http_core_loc_conf_t            *clcf;
    njt_http_location_queue_t           *hlq;
    dyn_fault_inject_servers_item_locations_item_t *dfil;
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
        dfil = get_dyn_fault_inject_servers_item_locations_item(locs, j);
        if(dfil == NULL || !dfil->is_location_set){
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " index %d not set location name", j);
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            continue;
        }

        name = get_dyn_fault_inject_locationDef_location(dfil);

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
                njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "dynfault_inject start set location:%V", &clcf->full_name);
                
                found = true;

                njt_pool_t *pool = njt_create_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
                if (pool == NULL) {
                    end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " dyn fault inject create pool error");
                    rpc_data_str.len = end - data_buf;
                    njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                    return NJT_ERROR;
                }
                rc = njt_sub_pool(clcf->pool, pool);
                if (rc != NJT_OK) {
                    end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " dyn fault inject create pool error");
                    rpc_data_str.len = end - data_buf;
                    njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                    return NJT_ERROR;
                }

                //set fault_inject_config
                rc = njt_dyn_fault_inject_set_conf(pool, dfil, ctx, rpc_result);
                if (rc != NJT_OK)
                {
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " error in njt_dyn_fault_inject_set_conf");
                    njt_destroy_pool(pool);
                } else {
                    njt_rpc_result_add_success_count(rpc_result);
                }

                if (dfil->is_locations_set && dfil->locations && dfil->locations->nelts > 0) {
                    njt_dyn_fault_inject_update_locs(dfil->locations, clcf->old_locations, ctx, rpc_result);
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

static void njt_dyn_fault_inject_dump_locs(njt_pool_t *pool, 
    njt_queue_t *locations, dyn_fault_inject_servers_item_locations_t *loc_items)
{
    njt_http_core_loc_conf_t      *clcf;
    njt_http_location_queue_t     *hlq;
    njt_queue_t                   *q, *tq;
    njt_http_fault_inject_conf_t  *ficf;
    dyn_fault_inject_servers_item_locations_item_t *loc_item;

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

        ficf = njt_http_get_module_loc_conf(clcf, njt_http_fault_inject_module);
        if(ficf == NULL){
            continue;
        }    

        loc_item = create_dyn_fault_inject_locationDef(pool);
        if(loc_item == NULL){
            continue;
        }
        
        set_dyn_fault_inject_locationDef_location(loc_item, &clcf->full_name);

        switch (ficf->fault_inject_type)
        {
        case NJT_HTTP_FAULT_INJECT_NONE:
            set_dyn_fault_inject_locationDef_fault_inject_type(loc_item, DYN_FAULT_INJECT_LOCATIONDEF_FAULT_INJECT_TYPE_NONE);
            break;
        case NJT_HTTP_FAULT_INJECT_DELAY:
            set_dyn_fault_inject_locationDef_fault_inject_type(loc_item, DYN_FAULT_INJECT_LOCATIONDEF_FAULT_INJECT_TYPE_DELAY);
            set_dyn_fault_inject_locationDef_delay_percentage(loc_item, ficf->delay_percent);
            set_dyn_fault_inject_locationDef_delay_duration(loc_item, &ficf->str_duration);
            break;
        case NJT_HTTP_FAULT_INJECT_ABORT:
            set_dyn_fault_inject_locationDef_fault_inject_type(loc_item, DYN_FAULT_INJECT_LOCATIONDEF_FAULT_INJECT_TYPE_ABORT);
            set_dyn_fault_inject_locationDef_abort_percentage(loc_item, ficf->abort_percent);
            set_dyn_fault_inject_locationDef_status_code(loc_item, ficf->status_code);
            break;
        case NJT_HTTP_FAULT_INJECT_DELAY_ABORT:
            set_dyn_fault_inject_locationDef_fault_inject_type(loc_item, DYN_FAULT_INJECT_LOCATIONDEF_FAULT_INJECT_TYPE_DELAY_ABORT);
            set_dyn_fault_inject_locationDef_delay_percentage(loc_item, ficf->delay_percent);
            set_dyn_fault_inject_locationDef_delay_duration(loc_item, &ficf->str_duration);
            set_dyn_fault_inject_locationDef_abort_percentage(loc_item, ficf->abort_percent);
            set_dyn_fault_inject_locationDef_status_code(loc_item, ficf->status_code);
            break;    
        default:
            set_dyn_fault_inject_locationDef_fault_inject_type(loc_item, DYN_FAULT_INJECT_LOCATIONDEF_FAULT_INJECT_TYPE_NONE);
            break;
        }

        add_item_dyn_fault_inject_servers_item_locations(loc_items, loc_item);

        if (clcf->old_locations) {
            set_dyn_fault_inject_locationDef_locations(loc_item, create_dyn_fault_inject_locationDef_locations(pool, 4));
            if(loc_item->locations != NULL){
                njt_dyn_fault_inject_dump_locs(pool, clcf->old_locations, loc_item->locations);
            }
        }
    }
}

static njt_str_t *njt_dyn_fault_inject_dump_conf(njt_cycle_t *cycle, njt_pool_t *pool)
{
    njt_http_core_loc_conf_t        *clcf;
    njt_http_core_main_conf_t       *hcmcf;
    njt_http_core_srv_conf_t        **cscfp;
    njt_uint_t                      i, j;
    njt_array_t                     *array;
    njt_str_t                       *tmp_str;
    njt_http_server_name_t          *server_name;
    dyn_fault_inject_t              dynjson_obj;
    dyn_fault_inject_servers_item_t *server_item;

    njt_memzero(&dynjson_obj, sizeof(dyn_fault_inject_t));

    hcmcf = njt_http_cycle_get_module_main_conf(cycle, njt_http_core_module);
    if(hcmcf == NULL){
        goto err;
    }

    set_dyn_fault_inject_servers(&dynjson_obj, create_dyn_fault_inject_servers(pool, 4));
    if(dynjson_obj.servers == NULL){
        goto err;
    }

    if (hcmcf && hcmcf->servers.nelts > 0) {
        cscfp = hcmcf->servers.elts;
        for (i = 0; i < hcmcf->servers.nelts; i++) {
            server_item = create_dyn_fault_inject_servers_item(pool);
            if(server_item == NULL){
                goto err;
            }

            set_dyn_fault_inject_servers_item_listens(server_item, create_dyn_fault_inject_servers_item_listens(pool, 4));
            set_dyn_fault_inject_servers_item_serverNames(server_item, create_dyn_fault_inject_servers_item_serverNames(pool, 4));
            set_dyn_fault_inject_servers_item_locations(server_item, create_dyn_fault_inject_servers_item_locations(pool, 4));

            array = njt_array_create(pool, 4, sizeof(njt_str_t));
            if(array == NULL){
                goto err;
            }
            njt_http_get_listens_by_server(array, cscfp[i]);

            for (j = 0; j < array->nelts; ++j) {
                tmp_str = (njt_str_t *)(array->elts)+ j;
                add_item_dyn_fault_inject_servers_item_listens(server_item->listens, tmp_str);
            }

            server_name = cscfp[i]->server_names.elts;
            for (j = 0; j < cscfp[i]->server_names.nelts; ++j) {
              tmp_str = &server_name[j].full_name;
              add_item_dyn_fault_inject_servers_item_serverNames(server_item->serverNames,tmp_str);
            }

            clcf = njt_http_get_module_loc_conf(cscfp[i]->ctx, njt_http_core_module);
            if(clcf != NULL){
                njt_dyn_fault_inject_dump_locs(pool, clcf->old_locations, server_item->locations);
            }

            add_item_dyn_fault_inject_servers(dynjson_obj.servers, server_item);
        }
    }

    return to_json_dyn_fault_inject(pool, &dynjson_obj, OMIT_NULL_ARRAY | OMIT_NULL_OBJ | OMIT_NULL_STR);

err:
    return &dyn_fault_inject_update_srv_err_msg;
}

static njt_int_t njt_dyn_fault_inject_update_conf(njt_pool_t *pool, dyn_fault_inject_t *api_data,
                        njt_rpc_result_t *rpc_result)
{
    njt_cycle_t                         *cycle;
    njt_http_core_srv_conf_t            *cscf;
    njt_http_core_loc_conf_t            *clcf;
    dyn_fault_inject_servers_item_t     *dsi;
    njt_str_t                           *port;
    njt_str_t                           *serverName;
    njt_uint_t                           i;
    njt_int_t                            rc;
    u_char                               data_buf[1024];
    u_char                              *end;
    njt_str_t                            rpc_data_str;


    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;

    cycle = (njt_cycle_t *)njt_cycle;

    if(api_data->is_servers_set && api_data->servers != NULL){
        for (i = 0; i < api_data->servers->nelts; i++)
        {
            dsi = get_dyn_fault_inject_servers_item(api_data->servers, i);
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

            port = get_dyn_fault_inject_servers_item_listens_item(dsi->listens, 0);
            serverName = get_dyn_fault_inject_servers_item_serverNames_item(dsi->serverNames, 0);
            njt_str_null(&rpc_result->conf_path);

            cscf = njt_http_get_srv_by_port(cycle, port, serverName);
            if (cscf == NULL)
            {
                njt_log_error(NJT_LOG_INFO, pool->log, 0, "can`t find server by listen:%V server_name:%V ",
                            port, serverName);
                end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " can`t find server by listen[%V] server_name[%V]", port, serverName);
                rpc_data_str.len = end - data_buf;
                njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                continue;
            }

            njt_log_error(NJT_LOG_INFO, pool->log, 0, "dynfault_inject start update listen:%V server_name:%V",
                    port, serverName);

            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, "listen[%V] server_name[%V]", port, serverName);
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_set_conf_path(rpc_result, &rpc_data_str);
                    
            njt_http_conf_ctx_t ctx = *cscf->ctx;
            clcf = njt_http_get_module_loc_conf(cscf->ctx, njt_http_core_module);
            if(clcf == NULL){
                njt_log_error(NJT_LOG_INFO, pool->log, 0, 
                    "can`t find location config by listen:%V server_name:%V ",
                    port, serverName);
                end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
                        " can`t find location config by listen[%V] server_name[%V]", port, serverName);
                rpc_data_str.len = end - data_buf;
                njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                continue;
            }

            rc = njt_dyn_fault_inject_update_locs(dsi->locations, clcf->old_locations, &ctx, rpc_result);
            if(rc != NJT_OK){
                njt_log_error(NJT_LOG_INFO, pool->log, 0, 
                    "update fault_inject error, listen:%V server_name:%V",
                    port, serverName);
            }
        }
    }

    return NJT_OK;
}

static u_char *njt_dyn_fault_inject_rpc_handler(njt_str_t *topic, njt_str_t *request, int *len, void *data)
{
    njt_cycle_t *cycle;
    njt_str_t *msg;
    u_char *buf;
    njt_pool_t *pool = NULL;

    buf = NULL;
    cycle = (njt_cycle_t *)njt_cycle;
    *len = 0;

    pool = njt_create_pool(njt_pagesize, njt_cycle->log);
    if (pool == NULL)
    {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_fault_inject_rpc_handler create pool error");
        goto out;
    }

    msg = njt_dyn_fault_inject_dump_conf(cycle, pool);
    buf = njt_calloc(msg->len, cycle->log);
    if (buf == NULL)
    {
        goto out;
    }

    njt_log_error(NJT_LOG_INFO, pool->log, 0, " dyn_fault_inject send json : %V", msg);
    njt_memcpy(buf, msg->data, msg->len);
    *len = msg->len;

out:
    if (pool != NULL)
    {
        njt_destroy_pool(pool);
    }

    return buf;
}

static int njt_dyn_fault_inject_update_handler(njt_str_t *key, njt_str_t *value, void *data, njt_str_t *out_msg)
{
    njt_int_t                            rc = NJT_OK;
    dyn_fault_inject_t                  *api_data = NULL;
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
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_fault_inject_change_handler create pool error");
        
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_MEM_ALLOC);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" update handler create pool error");
        rc = NJT_ERROR;

        goto end;
    }

    api_data = json_parse_dyn_fault_inject(pool, value, &err_info);
    if (api_data == NULL)
    {
        njt_log_error(NJT_LOG_ERR, pool->log, 0, 
                "json_parse_dyn_fault_inject err: %V",  &err_info.err_str);
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_JSON);
        njt_rpc_result_set_msg2(rpc_result, &err_info.err_str);

        rc = NJT_ERROR;
        goto err_msg;
    }

    njt_rpc_result_set_code(rpc_result,NJT_RPC_RSP_SUCCESS);
    rc = njt_dyn_fault_inject_update_conf(pool, api_data, rpc_result);
    if(rc != NJT_OK){
        njt_rpc_result_set_code(rpc_result,NJT_RPC_RSP_ERR);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" fault_inject update fail");
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

static int  njt_dyn_fault_inject_change_handler(njt_str_t *key, njt_str_t *value, void *data){
    return njt_dyn_fault_inject_update_handler(key, value, data, NULL);
}

static u_char* njt_dyn_fault_inject_put_handler(njt_str_t *topic, njt_str_t *request, int* len, void *data){
    njt_str_t err_json_msg;
    njt_str_null(&err_json_msg);
    njt_dyn_fault_inject_update_handler(topic, request, data, &err_json_msg);
    *len = err_json_msg.len;
    return err_json_msg.data;
}

static njt_int_t njt_http_dyn_fault_inject_module_init_process(njt_cycle_t *cycle)
{
    njt_str_t fault_inject_rpc_key = njt_string("http_dyn_fault_inject");
    njt_kv_reg_handler_t h;
    njt_memzero(&h, sizeof(njt_kv_reg_handler_t));
    h.key = &fault_inject_rpc_key;
    h.rpc_get_handler = njt_dyn_fault_inject_rpc_handler;
    h.rpc_put_handler = njt_dyn_fault_inject_put_handler;
    h.handler = njt_dyn_fault_inject_change_handler;
    h.api_type = NJT_KV_API_TYPE_DECLATIVE;
    njt_kv_reg_handler(&h);

    return NJT_OK;
}

static njt_http_module_t njt_http_dyn_fault_inject_module_ctx = {
    NULL, /* preconfiguration */
    NULL, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    NULL, /* create location configuration */
    NULL  /* merge location configuration */
};

njt_module_t njt_http_dyn_fault_inject_module = {
    NJT_MODULE_V1,
    &njt_http_dyn_fault_inject_module_ctx,         /* module context */
    NULL,                                    /* module directives */
    NJT_HTTP_MODULE,                         /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    njt_http_dyn_fault_inject_module_init_process, /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NJT_MODULE_V1_PADDING};
