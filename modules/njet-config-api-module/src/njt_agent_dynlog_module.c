/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */
#include <njt_core.h>
#include <njt_http_kv_module.h>
#include <njt_http.h>
// #include <njt_json_util.h>
#include <njt_rpc_result_util.h>
#include <njt_http_util.h>
#include "njt_dynlog_module.h"
#include "njt_str_util.h"

#define NJT_HTTP_DYN_LOG 1


static njt_http_dyn_access_api_loc_t * njt_api_loc_with_loc_item(njt_pool_t *pool, dynlog_locationDef_t *loc_item){
    njt_http_dyn_access_api_loc_t   *aal = NULL;
    njt_http_dyn_access_log_conf_t  *lc = NULL;
    dynlog_accessLog_t              *log;
    njt_int_t                       rc;
    njt_uint_t                      i;

    if(!loc_item) return NULL;
    aal = njt_pcalloc(pool,sizeof(njt_http_dyn_access_api_loc_t));
    if(!aal) return NULL;

    if(loc_item->is_location_set){
        aal->full_name = *get_dynlog_locationDef_location(loc_item);
    }

    if(loc_item->is_accessLogOn_set){
        aal->log_on = get_dynlog_locationDef_accessLogOn(loc_item);
    }

    if(loc_item->is_accessLogs_set && loc_item->accessLogs != NULL && loc_item->accessLogs->nelts>0){
        rc = njt_array_init(&aal->logs, pool, sizeof(njt_http_dyn_access_api_loc_t), loc_item->accessLogs->nelts);
        if(rc != NJT_OK) return NULL;
        lc = njt_array_push_n(&aal->logs, loc_item->accessLogs->nelts);
        for(i=0; i < loc_item->accessLogs->nelts; i++){
            log = get_dynlog_locationDef_accessLogs_item(loc_item->accessLogs, i);
            lc[i].format = log->formatName;
            lc[i].path = log->path;
        }
    } else {
        njt_array_init(&aal->logs, pool, sizeof(njt_http_dyn_access_api_loc_t), 0);
    }
    return aal;
}

static njt_int_t njt_dynlog_update_locs_log(dynlog_servers_item_locations_t *locs,njt_queue_t *q,njt_http_conf_ctx_t *ctx,njt_rpc_result_t *rpc_result){
    njt_http_core_loc_conf_t            *clcf;
    njt_http_location_queue_t           *hlq;
    njt_http_dyn_access_api_loc_t       *aal;
    dynlog_locationDef_t                *daal;
    njt_uint_t                          j;
    u_char                              data_buf[1024];
    u_char                              *end;
    njt_queue_t                         *tq;
    njt_int_t                           rc;
    njt_str_t                           *name;
    njt_str_t                           conf_path;
    njt_str_t                           parent_conf_path;
    bool                                loc_found ;
    njt_str_t                           rpc_data_str;


    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;
    if(q == NULL){
        return NJT_OK;
    }
    if(rpc_result){
        parent_conf_path = rpc_result->conf_path;
    }

    for( j = 0; j < locs->nelts ; ++j ){
        tq = njt_queue_head(q);
        loc_found = false;
        daal = get_dynlog_servers_item_locations_item(locs,j);
        if(daal == NULL || !daal->is_location_set){
            end = njt_snprintf(data_buf,sizeof(data_buf) - 1," index %d location name is not set", j);
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            continue;
        }

        name = get_dynlog_locationDef_location(daal);
        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,".locations[%V]",name);
        rpc_data_str.len = end - data_buf;

        if(rpc_result){
            rpc_result->conf_path = parent_conf_path;
        }

        njt_rpc_result_append_conf_path(rpc_result, &rpc_data_str);

        for (;tq!= njt_queue_sentinel(q);tq = njt_queue_next(tq)) {
            hlq = njt_queue_data(tq, njt_http_location_queue_t, queue);
            clcf = hlq->exact == NULL ? hlq->inclusive : hlq->exact;
            if (clcf != NULL && njt_http_location_full_name_cmp(clcf->full_name, *name) == 0) {
                aal = njt_api_loc_with_loc_item(locs->pool, daal);
                if(!aal){
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,"njt_api_loc_with_loc_item error");
                    continue;
                }

                loc_found = true;
                ctx->loc_conf = clcf->loc_conf;
                njt_pool_t *pool = njt_create_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
                if (NULL == pool) {
//                if (NULL == pool || NJT_OK != njt_sub_pool(njt_cycle->pool, pool)) {
                    end = njt_snprintf(data_buf,sizeof(data_buf) - 1," create pool error");
                    rpc_data_str.len = end - data_buf;
                    njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

                    return NJT_ERROR;
                }
//                rc = njt_sub_pool(njt_cycle->pool,pool);
//                if (rc != NJT_OK) {
//                    return NJT_ERROR;
//                }
                rpc_data_str.len = 0;
                rc = njt_http_log_dyn_set_log(pool, aal,ctx,&rpc_data_str,sizeof(data_buf));
                if(rc != NJT_OK){
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,"njt_http_log_dyn_set_log error free pool");
                    if(0 == rpc_data_str.len){
                        dynlog_locationDef_location_t *loc = get_dynlog_locationDef_location(daal);
                        end = njt_snprintf(data_buf,sizeof(data_buf) - 1," set dyn log error[%V];", loc);
                        rpc_data_str.len = end - data_buf;
                    }
                    njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

                    njt_destroy_pool(pool);
                } else {
                    njt_rpc_result_add_success_count(rpc_result);
                }
           
                if(daal->is_locations_set && daal->locations != NULL && daal->locations->nelts > 0){
                    if(rpc_result){
                        conf_path = rpc_result->conf_path;
                    }
                    njt_dynlog_update_locs_log(daal->locations, clcf->old_locations, ctx, rpc_result);
                    if(rpc_result){
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
// Not using deep copy
static njt_http_dyn_access_log_format_t *
njt_log_format_with_accessLogFormat_t(njt_pool_t *pool, dynlog_accessLogFormat_t *fmt){
    njt_http_dyn_access_log_format_t * alf;
    alf = njt_pcalloc(pool,sizeof(njt_http_dyn_access_log_format_t));
    if(!alf) return NULL;
    dynlog_accessLogFormat_format_t *format = get_dynlog_accessLogFormat_format(fmt);
    
    dynlog_accessLogFormat_name_t *name = get_dynlog_accessLogFormat_name(fmt);
    if(format != NULL){
        alf->format = *format;
    }
    
    if(fmt->is_escape_set){
        dynlog_accessLogFormat_escape_t escape = get_dynlog_accessLogFormat_escape(fmt);
        switch (escape) {
            case DYNLOG_ACCESSLOGFORMAT_ESCAPE_DEFAULT:
                njt_str_set(&alf->escape,"default");
                break;
            case DYNLOG_ACCESSLOGFORMAT_ESCAPE_JSON:
                njt_str_set(&alf->escape,"json");
                break;
            case DYNLOG_ACCESSLOGFORMAT_ESCAPE_NONE:
                njt_str_set(&alf->escape,"none");
                break;
        }
    }
    alf->name = *name;
    return alf;
}


static njt_int_t
njt_dynlog_update_access_log(njt_pool_t *pool, dynlog_t *api_data, njt_rpc_result_t *rpc_result) {
    njt_cycle_t                 *cycle;
    njt_http_core_srv_conf_t    *cscf;
    njt_http_core_loc_conf_t    *clcf;
    dynlog_accessLogFormat_t    *fmt;
    dynlog_servers_item_t       *server_item;
    njt_http_dyn_access_log_format_t *alf = NULL;
    u_char                      data_buf[1024];
    u_char                      *end;
    njt_int_t                   rc;

    njt_str_t rpc_data_str;
    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;
    njt_uint_t i;

    cycle = (njt_cycle_t*)njt_cycle;

    if(api_data->is_accessLogFormats_set){
        dynlog_accessLogFormats_t *formats = get_dynlog_accessLogFormats(api_data);
        if(formats){
            for(i = 0; i < formats->nelts; ++i){
                fmt = get_dynlog_accessLogFormats_item(formats, i);
                if(fmt == NULL){
                    continue;
                }

                dynlog_accessLogFormat_name_t *name = get_dynlog_accessLogFormat_name(fmt);
                // 设置当前路径
                end = njt_snprintf(data_buf,sizeof(data_buf) - 1," accessLogFormats[%V]", name);
                rpc_data_str.len = end - data_buf;
                njt_rpc_result_set_conf_path(rpc_result,&rpc_data_str);
                alf = njt_log_format_with_accessLogFormat_t(pool, fmt);
                rc = NJT_ERROR;
                if(alf) {
                    rc = njt_http_log_dyn_set_format(alf);
                }


                if(rc != NJT_OK) {
                    end = njt_snprintf(data_buf,sizeof(data_buf) - 1," set format error");
                    rpc_data_str.len = end - data_buf;
                    njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                } else {
                    njt_rpc_result_add_success_count(rpc_result);
                }
            }
        }
    }

    // empty path
    rpc_data_str.len = 0;
    njt_rpc_result_set_conf_path(rpc_result,&rpc_data_str);

    if(api_data->is_servers_set && api_data->servers != NULL){
        dynlog_servers_t *servers = get_dynlog_servers(api_data);
        if(servers){
            for(i = 0; i < servers->nelts; ++i){
                server_item = get_dynlog_servers_item(servers, i);
                if(server_item == NULL){
                    continue;
                }

                if(!server_item->is_listens_set || !server_item->is_serverNames_set || server_item->listens == NULL
                     || server_item->serverNames == NULL || server_item->listens->nelts < 1 || server_item->serverNames->nelts < 1 ){
                    // listens 与server_names都为空
                    end = njt_snprintf(data_buf,sizeof(data_buf) - 1," server parameters error, listens or serverNames is empty,at position %ui",i);
                    rpc_data_str.len = end - data_buf;
                    njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                    continue;
                }

                dynlog_servers_item_listens_t *listens = get_dynlog_servers_item_listens(server_item);
                dynlog_servers_item_serverNames_t *server_names = get_dynlog_servers_item_serverNames(server_item);

                njt_str_t *first_lis = get_dynlog_servers_item_listens_item(listens, 0);
                njt_str_t *first_server_name = get_dynlog_servers_item_serverNames_item(server_names,0);

                end = njt_snprintf(data_buf,sizeof(data_buf) - 1,"servers[%V,%V]", first_lis, first_server_name);
                rpc_data_str.len = end - data_buf;
                njt_rpc_result_set_conf_path(rpc_result,&rpc_data_str);

                cscf = njt_http_get_srv_by_port(cycle,first_lis,first_server_name);
                if(cscf == NULL){
                    if(listens->elts != NULL && server_names->elts != NULL ){
                        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "can`t find server by listen:%V server_name:%V ",
                                    first_lis,first_server_name);
                        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,"can not find server.");
                        rpc_data_str.len = end - data_buf;
                        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                    }

                    continue;
                }
                njt_http_conf_ctx_t ctx = *cscf->ctx;
                clcf = njt_http_get_module_loc_conf(cscf->ctx,njt_http_core_module);
                if(clcf != NULL && server_item->is_locations_set 
                    && server_item->locations != NULL && server_item->locations->nelts > 0){
                    rc = njt_dynlog_update_locs_log(server_item->locations, clcf->old_locations, &ctx, rpc_result);
                } else {
                    rc = NJT_OK;
                }

                if (rc == NJT_OK) {
                    njt_rpc_result_add_success_count(rpc_result);
                }

            }
        }
    }

    njt_rpc_result_update_code(rpc_result);
    return NJT_OK;
}


static void njt_dynlog_dump_log_cf_json(njt_pool_t *pool,
            njt_array_t *logs, dynlog_locationDef_accessLogs_t *accesslogs_items) {
    njt_uint_t      i;
    njt_http_log_t *log;
    dynlog_locationDef_accessLogs_item_t *accesslogs_item;

    if(logs == NULL || logs->nelts < 1){
        return;
    }

    log = logs->elts;
    for(i = 0 ; i < logs->nelts ; ++i ){
        accesslogs_item = create_dynlog_accessLog(pool);
        if(accesslogs_item == NULL){
            continue;
        }

        if( log[i].path.len > 0){
            set_dynlog_accessLog_path(accesslogs_item, &log[i].path);
        }
        if(log[i].format != NULL && log[i].format->name.len > 0 ){
            set_dynlog_accessLog_formatName(accesslogs_item, &log[i].format->name);
        }

        add_item_dynlog_locationDef_accessLogs(accesslogs_items, accesslogs_item);
    }
}

static void njt_dynlog_dump_locs_json(njt_pool_t *pool,
            njt_queue_t *locations, dynlog_servers_item_locations_t *loc_items){
    njt_http_core_loc_conf_t                *clcf;
    njt_http_location_queue_t               *hlq;
    njt_queue_t                             *q,*tq;
    njt_http_log_loc_conf_t                 *llcf;
    dynlog_servers_item_locations_item_t *loc_item;

    if(locations == NULL){
        return;
    }

    q = locations;
    if(njt_queue_empty(q)){
        return;
    }

    tq = njt_queue_head(q);
    for (;tq!= njt_queue_sentinel(q);tq = njt_queue_next(tq)){
        hlq = njt_queue_data(tq,njt_http_location_queue_t,queue);
        clcf = hlq->exact == NULL ? hlq->inclusive : hlq->exact;
        if(clcf == NULL){
            continue;
        }

        llcf = njt_http_get_module_loc_conf(clcf,njt_http_log_module);

        loc_item = create_dynlog_locationDef(pool);
        if(loc_item == NULL){
            continue;
        }

        set_dynlog_locationDef_location(loc_item, &clcf->full_name);
        if(llcf->off){
            set_dynlog_locationDef_accessLogOn(loc_item, 0);
        }else{
            set_dynlog_locationDef_accessLogOn(loc_item, 1);
        }    

        if(!llcf->off){
            set_dynlog_locationDef_accessLogs(loc_item, create_dynlog_locationDef_accessLogs(pool, 4));
            if(loc_item->accessLogs != NULL){
                njt_dynlog_dump_log_cf_json(pool, llcf->logs, loc_item->accessLogs);
            }
        }

        if (clcf->old_locations) {
            set_dynlog_locationDef_locations(loc_item, create_dynlog_locationDef_locations(pool, 4));
            if(loc_item->locations != NULL){
                njt_dynlog_dump_locs_json(pool, clcf->old_locations, loc_item->locations);
            }
        }
        
        add_item_dynlog_servers_item_locations(loc_items, loc_item);
    }
}

njt_str_t dynlog_update_srv_err_msg=njt_string("{\"code\":500,\"msg\":\"server error\"}");


static njt_str_t *njt_dynlog_dump_log_conf(njt_cycle_t *cycle,njt_pool_t *pool){
    njt_http_core_loc_conf_t    *clcf;
    njt_http_core_main_conf_t   *hcmcf;
    njt_http_core_srv_conf_t    **cscfp;
    njt_http_log_main_conf_t    *lmcf;
    njt_http_log_fmt_t          *fmt;
    njt_uint_t                  i,j;
    njt_array_t                 *array;
    njt_str_t                   *tmp_str;
    njt_http_server_name_t      *server_name;
    dynlog_t                    dynjson_obj;
    dynlog_servers_item_t       *server_item;
    dynlog_accessLogFormats_item_t *accessLog_formats_item;

    njt_memzero(&dynjson_obj, sizeof(dynlog_t));
    hcmcf = njt_http_cycle_get_module_main_conf(cycle, njt_http_core_module);
    if(hcmcf == NULL){
        goto err;
    }

    set_dynlog_servers(&dynjson_obj, create_dynlog_servers(pool, 4));
    if(dynjson_obj.servers == NULL){
        goto err;
    }

    cscfp = hcmcf->servers.elts;
    for (i = 0; i < hcmcf->servers.nelts; i++)
    {
        server_item = create_dynlog_servers_item(pool);
        if(server_item == NULL){
            goto err;
        }

        set_dynlog_servers_item_listens(server_item, create_dynlog_servers_item_listens(pool, 4));
        set_dynlog_servers_item_serverNames(server_item, create_dynlog_servers_item_serverNames(pool, 4));
        set_dynlog_servers_item_locations(server_item, create_dynlog_servers_item_locations(pool, 4));

        array = njt_array_create(pool, 4, sizeof(njt_str_t));
        if(array == NULL){
            goto err;
        }
        njt_http_get_listens_by_server(array, cscfp[i]);

        for (j = 0; j < array->nelts; ++j) {
            tmp_str = (njt_str_t *)(array->elts)+ j;
            add_item_dynlog_servers_item_listens(server_item->listens, tmp_str);
        }

        server_name = cscfp[i]->server_names.elts;
        for (j = 0; j < cscfp[i]->server_names.nelts; ++j) {
            tmp_str = &server_name[j].full_name;
            add_item_dynlog_servers_item_serverNames(server_item->serverNames,tmp_str);
        }

        clcf = njt_http_get_module_loc_conf(cscfp[i]->ctx, njt_http_core_module);
        if(clcf != NULL){
            njt_dynlog_dump_locs_json(pool, clcf->old_locations, server_item->locations);
        }

        add_item_dynlog_servers(dynjson_obj.servers, server_item);
    }


    lmcf = njt_http_cycle_get_module_main_conf(cycle,njt_http_log_module);
    if(lmcf == NULL ){
        goto err;
    }

    set_dynlog_accessLogFormats(&dynjson_obj, create_dynlog_accessLogFormats(pool, 4));
    if(dynjson_obj.accessLogFormats == NULL){
        goto err;
    }

    fmt = lmcf->formats.elts;
    for( i = 0; i < lmcf->formats.nelts; i++){
        accessLog_formats_item = njt_pcalloc(pool, sizeof(dynlog_accessLogFormats_item_t));
        if(accessLog_formats_item == NULL){
            goto err;
        }

        if( fmt[i].name.len > 0 ) {
            set_dynlog_accessLogFormat_name(accessLog_formats_item, &fmt[i].name);
        }
        if( fmt[i].escape.len > 0 ){
            if(fmt[i].escape.len == 7 && njt_strncmp(fmt[i].escape.data, "default", 7) ==0){
                set_dynlog_accessLogFormat_escape(accessLog_formats_item, DYNLOG_ACCESSLOGFORMAT_ESCAPE_DEFAULT);
            }else if (fmt[i].escape.len == 4 && njt_strncmp(fmt[i].escape.data, "json", 4) ==0)
            {
                set_dynlog_accessLogFormat_escape(accessLog_formats_item, DYNLOG_ACCESSLOGFORMAT_ESCAPE_JSON);
            }
            else if (fmt[i].escape.len == 4 && njt_strncmp(fmt[i].escape.data, "none", 4) ==0)
            {
                set_dynlog_accessLogFormat_escape(accessLog_formats_item, DYNLOG_ACCESSLOGFORMAT_ESCAPE_NONE);
            }
        }
        if(fmt[i].format.len){
            set_dynlog_accessLogFormat_format(accessLog_formats_item, &fmt[i].format);
        }

        add_item_dynlog_accessLogFormats(dynjson_obj.accessLogFormats, accessLog_formats_item);
    }
    
    return to_json_dynlog(pool, &dynjson_obj, OMIT_NULL_ARRAY | OMIT_NULL_OBJ | OMIT_NULL_STR);

    err:
    return &dynlog_update_srv_err_msg;
}


static u_char* njt_agent_dynlog_rpc_handler(njt_str_t *topic, njt_str_t *request, int* len, void *data){
    njt_cycle_t     *cycle;
    njt_str_t       *msg;
    u_char          *buf;

    buf = NULL;
    cycle = (njt_cycle_t*) njt_cycle;
    *len = 0 ;
    njt_pool_t *pool = NULL;
    pool = njt_create_pool(njt_pagesize,njt_cycle->log);
    if(pool == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_agent_dynlog_change_handler create pool error");
        goto end;
    }
    msg = njt_dynlog_dump_log_conf(cycle,pool);
    buf = njt_calloc(msg->len,cycle->log);
    if(buf == NULL){
        goto end;
    }
    njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "send json : %V", msg);
    njt_memcpy(buf, msg->data, msg->len);
    *len = msg->len;

    end:
    if(pool != NULL){
        njt_destroy_pool(pool);
    }

    return buf;
}

static int  njt_agent_dynlog_change_handler_internal(njt_str_t *key, njt_str_t *value, void *data,njt_str_t *out_msg){
    njt_int_t               rc = NJT_OK;
    dynlog_t                *api_data = NULL;
    njt_pool_t              *pool = NULL;
    njt_str_t               empty_msg = njt_string("");
    njt_rpc_result_t        *rpc_result = NULL;
    js2c_parse_error_t      err_info;

    if(value->len < 2 ){
        return NJT_OK;
    }
    rpc_result = njt_rpc_result_create();
    if(!rpc_result){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "can't create rpc result");
        goto end;
    }
    njt_rpc_result_set_code(rpc_result,NJT_RPC_RSP_SUCCESS);
    pool = njt_create_pool(njt_pagesize,njt_cycle->log);
    if(pool == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_dynlog_change_handler create pool error");
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_MEM_ALLOC);
        rc = NJT_ERROR;
        goto rpc_msg;
    }

    api_data = json_parse_dynlog(pool, value, &err_info);
//    api_data =  njt_pcalloc(pool,sizeof (njt_http_dyn_access_api_main_t));
    if(api_data == NULL){
//        njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
//                       "could not alloc buffer in function %s", __func__);
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "dynlog parse json error in function %V", &err_info.err_str);
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_JSON);
        njt_rpc_result_set_msg2(rpc_result,  &err_info.err_str);
        rc = NJT_ERROR;
        njt_kv_sendmsg(key,&empty_msg,0);
        goto rpc_msg;
    }
//    rc =njt_json_parse_data(pool,value,njt_http_dyn_access_api_main_json_dt,api_data);
    rc = njt_dynlog_update_access_log(pool, api_data, rpc_result);

    if(rc != NJT_OK ){
        // 解析json失败
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" dynlog update fail");
    }else{
        if(rpc_result->data != NULL && rpc_result->data->nelts > 0){
            njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_PARTIAL_SUCCESS);
        }
    }


    if(rpc_result->success_count == 0) {
        njt_kv_sendmsg(key,&empty_msg,0);
    }

    rpc_msg:
    if (out_msg) {
        njt_rpc_result_to_json_str(rpc_result, out_msg);
    }
    end:
    if(pool != NULL){
        njt_destroy_pool(pool);
    }
    if(rpc_result){
        njt_rpc_result_destroy(rpc_result);
    }
    return rc;
}

static int  njt_agent_dynlog_change_handler(njt_str_t *key, njt_str_t *value, void *data){
    return  njt_agent_dynlog_change_handler_internal(key,value,data,NULL);
}
static u_char* njt_agent_dynlog_put_handler(njt_str_t *topic, njt_str_t *request, int* len, void *data) {
    njt_str_t err_json_msg;
    njt_str_null(&err_json_msg);
    njt_agent_dynlog_change_handler_internal(topic,request,data,&err_json_msg);
    *len = err_json_msg.len;
    return err_json_msg.data;

}
static njt_int_t njt_agent_dynlog_init_process(njt_cycle_t* cycle){
    njt_str_t  rpc_key = njt_string("http_log");
    njt_kv_reg_handler_t h;
    njt_memzero(&h, sizeof(njt_kv_reg_handler_t));
    h.key = &rpc_key;
    h.rpc_get_handler = njt_agent_dynlog_rpc_handler;
    h.rpc_put_handler = njt_agent_dynlog_put_handler;
    h.handler = njt_agent_dynlog_change_handler;
    h.api_type = NJT_KV_API_TYPE_DECLATIVE;
    njt_kv_reg_handler(&h);
    return NJT_OK;
}


static njt_http_module_t njt_agent_dynlog_module_ctx = {
        NULL,                                   /* preconfiguration */
        NULL,                                   /* postconfiguration */

        NULL,                                   /* create main configuration */
        NULL,                                  /* init main configuration */

        NULL,                                  /* create server configuration */
        NULL,                                  /* merge server configuration */

        NULL,                                   /* create location configuration */
        NULL                                    /* merge location configuration */
};

njt_module_t njt_agent_dynlog_module = {
        NJT_MODULE_V1,
        &njt_agent_dynlog_module_ctx,                 /* module context */
        NULL,                                   /* module directives */
        NJT_HTTP_MODULE,                        /* module type */
        NULL,                                   /* init master */
        NULL,                                   /* init module */
        njt_agent_dynlog_init_process,          /* init process */
        NULL,                                   /* init thread */
        NULL,                                   /* exit thread */
        NULL,                                   /* exit process */
        NULL,                                   /* exit master */
        NJT_MODULE_V1_PADDING
};


