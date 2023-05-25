/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */
#include <njt_core.h>
#include <njt_http_kv_module.h>
#include <njt_http.h>
#include <njt_json_util.h>
#include <njt_rpc_result_util.h>
#include <njt_http_util.h>
#include "njt_dynlog_module.h"
#include "njt_str_util.h"

#define NJT_HTTP_DYN_LOG 1

static njt_json_define_t njt_http_dyn_access_log_conf_json_dt[] = {
        {
                njt_string("formatName"),
                offsetof(njt_http_dyn_access_log_conf_t, format),
                0,
                NJT_JSON_STR,
                0,
                NULL,
                NULL,
        },
        {
                njt_string("path"),
                offsetof(njt_http_dyn_access_log_conf_t, path),
                0,
                NJT_JSON_STR,
                0,
                NULL,
                NULL,
        },
        njt_json_define_null,
};

static njt_json_define_t njt_http_dyn_access_api_loc_json_dt[] ={
        {
                njt_string("location"),
                offsetof(njt_http_dyn_access_api_loc_t, full_name),
                0,
                NJT_JSON_STR,
                0,
                NULL,
                NULL,
        },
        {
                njt_string("accessLogOn"),
                offsetof(njt_http_dyn_access_api_loc_t, log_on),
                0,
                NJT_JSON_BOOL,
                0,
                NULL,
                NULL,
        },
        {
                njt_string("accessLogs"),
                offsetof(njt_http_dyn_access_api_loc_t, logs),
                sizeof(njt_http_dyn_access_log_conf_t),
                NJT_JSON_ARRAY,
                NJT_JSON_OBJ,
                njt_http_dyn_access_log_conf_json_dt,
                NULL,
        },
        {
                njt_string("locations"),
                offsetof(njt_http_dyn_access_api_loc_t, locs),
                sizeof(njt_http_dyn_access_api_loc_t),
                NJT_JSON_ARRAY,
                NJT_JSON_OBJ,
                njt_http_dyn_access_api_loc_json_dt,
                NULL,
        },
        njt_json_define_null,
};

static njt_json_define_t njt_http_dyn_access_api_srv_json_dt[] ={
        {
                njt_string("listens"),
                offsetof(njt_http_dyn_access_api_srv_t, listens),
                sizeof(njt_str_t),
                NJT_JSON_ARRAY,
                NJT_JSON_STR,
                NULL,
                NULL,
        },
        {
                njt_string("serverNames"),
                offsetof(njt_http_dyn_access_api_srv_t, server_names),
                sizeof(njt_str_t),
                NJT_JSON_ARRAY,
                NJT_JSON_STR,
                NULL,
                NULL,
        },
        {
                njt_string("locations"),
                offsetof(njt_http_dyn_access_api_srv_t, locs),
                sizeof(njt_http_dyn_access_api_loc_t),
                NJT_JSON_ARRAY,
                NJT_JSON_OBJ,
                njt_http_dyn_access_api_loc_json_dt,
                NULL,
        },
        njt_json_define_null,
};
#if (NJT_HTTP_DYN_LOG)


static njt_json_define_t njt_http_dyn_access_log_format_json_dt[] ={
        {
                njt_string("name"),
                offsetof(njt_http_dyn_access_log_format_t, name),
                0,
                NJT_JSON_STR,
                0,
                NULL,
                NULL,
        },
        {
                njt_string("format"),
                offsetof(njt_http_dyn_access_log_format_t, format),
                0,
                NJT_JSON_STR,
                0,
                NULL,
                NULL,
        },
        {
                njt_string("escape"),
                offsetof(njt_http_dyn_access_log_format_t, escape),
                0,
                NJT_JSON_STR,
                0,
                NULL,
                NULL,
        },
        njt_json_define_null,
};
#endif

static njt_json_define_t njt_http_dyn_access_api_main_json_dt[] ={
        {
                njt_string("servers"),
                offsetof(njt_http_dyn_access_api_main_t, servers),
                sizeof(njt_http_dyn_access_api_srv_t),
                NJT_JSON_ARRAY,
                NJT_JSON_OBJ,
                njt_http_dyn_access_api_srv_json_dt,
                NULL,
        },
#if (NJT_HTTP_DYN_LOG)

        {
                njt_string("accessLogFormats"),
                offsetof(njt_http_dyn_access_api_main_t, log_formats),
                sizeof(njt_http_dyn_access_log_format_t),
                NJT_JSON_ARRAY,
                NJT_JSON_OBJ,
                njt_http_dyn_access_log_format_json_dt,
                NULL,
        },
#endif
        njt_json_define_null,
};


static njt_int_t njt_dynlog_update_locs_log(njt_array_t *locs,njt_queue_t *q,njt_http_conf_ctx_t *ctx,njt_rpc_result_t *rpc_result){
    njt_http_core_loc_conf_t  *clcf;
    njt_http_location_queue_t *hlq;
    njt_http_dyn_access_api_loc_t *daal;
    njt_uint_t j;
    u_char data_buf[1024];
    u_char * end;
    njt_queue_t *tq;
    njt_int_t rc;
    njt_str_t name;
    njt_str_t conf_path;
    njt_str_t parent_conf_path;
    bool loc_found ;
    njt_str_t rpc_data_str;
    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;
    if(q == NULL){
        return NJT_OK;
    }
    daal = locs->elts;
    if(rpc_result){
        parent_conf_path = rpc_result->conf_path;
    }

    for( j = 0; j < locs->nelts ; ++j ){
        tq = njt_queue_head(q);
        loc_found = false;
        name = daal[j].full_name;

        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,".locations[%V]",&name);
        rpc_data_str.len = end - data_buf;

        if(rpc_result){
            rpc_result->conf_path = parent_conf_path;
        }

        njt_rpc_result_append_conf_path(rpc_result, &rpc_data_str);


        for (;tq!= njt_queue_sentinel(q);tq = njt_queue_next(tq)) {
            hlq = njt_queue_data(tq, njt_http_location_queue_t, queue);
            clcf = hlq->exact == NULL ? hlq->inclusive : hlq->exact;
            if (name.len == clcf->full_name.len && njt_strncmp(name.data, clcf->full_name.data, name.len) == 0) {
                loc_found = true;
                ctx->loc_conf = clcf->loc_conf;
                njt_pool_t *pool = njt_create_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
                if (NULL == pool || NJT_OK != njt_sub_pool(njt_cycle->pool, pool)) {
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
                rc = njt_http_log_dyn_set_log(pool, &daal[j],ctx,&rpc_data_str,sizeof(data_buf));
                if(rc != NJT_OK){
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,"njt_http_log_dyn_set_log error free pool");
                    if(0 == rpc_data_str.len){
                        end = njt_snprintf(data_buf,sizeof(data_buf) - 1," set dyn log error[%V];",&daal[j].full_name);
                        rpc_data_str.len = end - data_buf;
                    }
                    njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

                    njt_destroy_pool(pool);
                } else {
                    njt_rpc_result_add_success_count(rpc_result);
                }
            }
            if(daal[j].locs.nelts > 0){
                if(rpc_result){
                    conf_path = rpc_result->conf_path;
                }
                njt_dynlog_update_locs_log(&daal[j].locs,clcf->old_locations,ctx,rpc_result);
                if(rpc_result){
                    rpc_result->conf_path = conf_path;
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

static njt_int_t
njt_dynlog_update_access_log(njt_pool_t *pool, njt_http_dyn_access_api_main_t *api_data, njt_rpc_result_t *rpc_result) {

    njt_cycle_t *cycle;
    njt_http_core_srv_conf_t  *cscf;
    njt_http_core_loc_conf_t  *clcf;
    njt_http_dyn_access_api_srv_t *daas;
    njt_http_dyn_access_log_format_t *fmt;
    u_char data_buf[1024];
    u_char * end;
    njt_int_t rc;

    njt_str_t rpc_data_str;
    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;
    njt_uint_t i;

    cycle = (njt_cycle_t*)njt_cycle;


    fmt = api_data->log_formats.elts;
    for(i = 0; i < api_data->log_formats.nelts; ++i){
        // 设置当前路径
        end = njt_snprintf(data_buf,sizeof(data_buf) - 1," accessLogFormats[%V]",&fmt[i].name);
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_set_conf_path(rpc_result,&rpc_data_str);

        rc = njt_http_log_dyn_set_format(&fmt[i]);


        if(rc != NJT_OK) {
            end = njt_snprintf(data_buf,sizeof(data_buf) - 1," set format error");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
        } else {
            njt_rpc_result_add_success_count(rpc_result);
        }
    }

    // empty path
    rpc_data_str.len = 0;
    njt_rpc_result_set_conf_path(rpc_result,&rpc_data_str);


    daas = api_data->servers.elts;
    for(i = 0; i < api_data->servers.nelts; ++i){
        if( daas[i].listens.nelts < 1 || daas[i].server_names.nelts < 1 ){
            // listens 与server_names都为空
            end = njt_snprintf(data_buf,sizeof(data_buf) - 1," server parameters error, listens or serverNames is empty,at position %ui",i);
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            continue;
        }
        end = njt_snprintf(data_buf,sizeof(data_buf) - 1,"servers[%V,%V]",(njt_str_t*)daas[i].listens.elts,(njt_str_t*)daas[i].server_names.elts);
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_set_conf_path(rpc_result,&rpc_data_str);

        cscf = njt_http_get_srv_by_port(cycle,(njt_str_t*)daas[i].listens.elts,(njt_str_t*)daas[i].server_names.elts);
        if(cscf == NULL){
            if(daas[i].listens.elts != NULL && daas[i].server_names.elts != NULL ){
                njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "can`t find server by listen:%V server_name:%V ",
                              (njt_str_t*)daas[i].listens.elts,(njt_str_t*)daas[i].server_names.elts);

                end = njt_snprintf(data_buf,sizeof(data_buf) - 1,"can not find server.");
                rpc_data_str.len = end - data_buf;
                njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            }

            continue;
        }
        njt_http_conf_ctx_t ctx = *cscf->ctx;
        clcf = njt_http_get_module_loc_conf(cscf->ctx,njt_http_core_module);
        rc = njt_dynlog_update_locs_log(&daas[i].locs,clcf->old_locations,&ctx,rpc_result);

        if (rc == NJT_OK) {
            njt_rpc_result_add_success_count(rpc_result);
        }

    }
    njt_rpc_result_update_code(rpc_result);
    return NJT_OK;
}


static njt_json_element* njt_dynlog_dump_log_cf_json(njt_pool_t *pool,njt_array_t *logs) {
    njt_uint_t i;
    njt_http_log_t *log;
    njt_json_element *arr,*obj,*path,*format;

    if(logs == NULL || logs->nelts < 1){
        return NULL;
    }

    arr = njt_json_arr_element(pool, njt_json_fast_key("accessLogs"));
    if(arr == NULL){
        return NULL;
    }
    log = logs->elts;
    for(i = 0 ; i < logs->nelts ; ++i ){

        obj = njt_json_obj_element(pool,njt_json_null_key);
        if(obj == NULL){
            continue;
        }
        if( log[i].path.len > 0){
            path = njt_json_str_element(pool, njt_json_fast_key("path"),&log[i].path);
            if(path == NULL){
                continue;
            }
            njt_struct_add(obj,path,pool);
        }
        if(log[i].format != NULL && log[i].format->name.len > 0 ){
            format = njt_json_str_element(pool, njt_json_fast_key("formatName"),&log[i].format->name);
            if(format == NULL){
                continue;
            }
            njt_struct_add(obj,format,pool);
        }
        njt_struct_add(arr,obj,pool);
    }
    return arr;
}

static njt_json_element* njt_dynlog_dump_locs_json(njt_pool_t *pool,njt_queue_t *locations){
    njt_http_core_loc_conf_t  *clcf;
    njt_http_location_queue_t *hlq;
    njt_queue_t *q,*tq;
    njt_http_log_loc_conf_t *llcf;
    njt_json_element *locs,*item,*sub;

    if(locations == NULL){
        return NULL;
    }
    locs = NULL;
    q = locations;
    if(njt_queue_empty(q)){
        return NULL;
    }

    tq = njt_queue_head(q);
    locs = njt_json_arr_element(pool,njt_json_fast_key("locations"));
    if(locs == NULL){
        return NULL;
    }
    for (;tq!= njt_queue_sentinel(q);tq = njt_queue_next(tq)){
        hlq = njt_queue_data(tq,njt_http_location_queue_t,queue);
        clcf = hlq->exact == NULL ? hlq->inclusive : hlq->exact;
        llcf = njt_http_get_module_loc_conf(clcf,njt_http_log_module);

        item = njt_json_obj_element(pool,njt_json_null_key);
        if(item == NULL){
            return NULL;
        }
        sub = njt_json_str_element(pool,njt_json_fast_key("location"),&clcf->full_name);
        if(sub == NULL){
            return NULL;
        }
        njt_struct_add(item,sub,pool);

        sub = njt_json_bool_element(pool,njt_json_fast_key("accessLogOn"),llcf->off?0:1);
        if(sub == NULL){
            return NULL;
        }
        njt_struct_add(item,sub,pool);
        if(!llcf->off){
            sub = njt_dynlog_dump_log_cf_json(pool,llcf->logs);
            if(sub != NULL){
                njt_struct_add(item,sub,pool);
            }
        }
        sub = njt_dynlog_dump_locs_json(pool,clcf->old_locations);
        if(sub != NULL){
            njt_struct_add(item,sub,pool);
        }
        njt_struct_add(locs,item,pool);
    }
    return locs;
}

njt_str_t dynlog_update_srv_err_msg=njt_string("{\"code\":500,\"msg\":\"server error\"}");


static njt_str_t njt_dynlog_dump_log_conf(njt_cycle_t *cycle,njt_pool_t *pool){
    njt_http_core_loc_conf_t  *clcf;
    njt_http_core_main_conf_t *hcmcf;
    njt_http_core_srv_conf_t  **cscfp;
    njt_http_log_main_conf_t *lmcf;
    njt_http_log_fmt_t  *fmt;

    njt_uint_t i,j;
    njt_array_t *array;
    njt_str_t json,*tmp_str;
    njt_http_server_name_t *server_name;
    njt_json_manager json_manager;
    njt_json_element *srvs,*srv,*subs,*sub,*fmts;
    njt_int_t rc;

    njt_memzero(&json_manager, sizeof(njt_json_manager));
    hcmcf = njt_http_cycle_get_module_main_conf(cycle,njt_http_core_module);
    lmcf = njt_http_cycle_get_module_main_conf(cycle,njt_http_log_module);

    srvs =  njt_json_arr_element(pool,njt_json_fast_key("servers"));
    if(srvs == NULL ){
        goto err;
    }

    cscfp = hcmcf->servers.elts;
    for( i = 0; i < hcmcf->servers.nelts; i++){
        array = njt_array_create(pool,4, sizeof(njt_str_t));
        rc = njt_http_get_listens_by_server(array,cscfp[i]);
        if(rc != NJT_OK){
            goto err;
        }
        srv =  njt_json_obj_element(pool,njt_json_null_key);
        if(srv == NULL ){
            goto err;
        }

        subs =  njt_json_arr_element(pool,njt_json_fast_key("listens"));
        if(subs == NULL ){
            goto err;
        }

        tmp_str = array->elts;
        for(j = 0 ; j < array->nelts ; ++j ){
            sub =  njt_json_str_element(pool,njt_json_null_key,&tmp_str[j]);
            if(sub == NULL ){
                goto err;
            }
            njt_struct_add(subs,sub,pool);
        }
        njt_struct_add(srv,subs,pool);
        subs =  njt_json_arr_element(pool,njt_json_fast_key("serverNames"));
        if(subs == NULL ){
            goto err;
        }
        server_name = cscfp[i]->server_names.elts;
        for(j = 0 ; j < cscfp[i]->server_names.nelts ; ++j ){
            sub =  njt_json_str_element(pool,njt_json_null_key,&server_name[j].name);
            if(sub == NULL ){
                goto err;
            }
            njt_struct_add(subs,sub,pool);
        }
        njt_struct_add(srv,subs,pool);
        clcf = njt_http_get_module_loc_conf(cscfp[i]->ctx,njt_http_core_module);
        subs = njt_dynlog_dump_locs_json(pool,clcf->old_locations);
        if(subs != NULL){
            njt_struct_add(srv,subs,pool);
        }
        njt_struct_add(srvs,srv,pool);
    }

    rc = njt_struct_top_add(&json_manager, srvs, NJT_JSON_OBJ, pool);
    if(rc != NJT_OK){
        njt_log_error(NJT_LOG_ALERT, cycle->log, 0,"njt_struct_top_add error");
    }
    fmts =  njt_json_arr_element(pool,njt_json_fast_key("accessLogFormats"));
    if(fmts == NULL ){
        goto err;
    }
    fmt = lmcf->formats.elts;
    for( i = 0; i < lmcf->formats.nelts; i++){
        subs =  njt_json_obj_element(pool,njt_json_null_key);
        if(subs == NULL ){
            goto err;
        }
        if( fmt[i].name.len > 0 ) {
            sub = njt_json_str_element(pool, njt_json_fast_key("name"), &fmt[i].name);
            if (sub == NULL) {
                goto err;
            }
            njt_struct_add(subs, sub, pool);
        }
        if( fmt[i].escape.len > 0 ){
            sub = njt_json_str_element(pool, njt_json_fast_key("escape"),&fmt[i].escape);
            if(sub == NULL ){
                goto err;
            }
            njt_struct_add(subs,sub,pool);
        }
        if(fmt[i].format.len){
            sub = njt_json_str_element(pool, njt_json_fast_key("format"),&fmt[i].format);
            if(sub == NULL ){
                goto err;
            }
            njt_struct_add(subs,sub,pool);
        }

        njt_struct_add(fmts,subs,pool);
    }
    rc = njt_struct_top_add(&json_manager, fmts, NJT_JSON_OBJ, pool);
    if(rc != NJT_OK){
        njt_log_error(NJT_LOG_ALERT, cycle->log, 0,"njt_struct_top_add error");
    }
    njt_memzero(&json, sizeof(njt_str_t));
    njt_structure_2_json(&json_manager, &json, pool);

    return json;

    err:
    return dynlog_update_srv_err_msg;
}
static u_char* njt_agent_dynlog_rpc_handler(njt_str_t *topic, njt_str_t *request, int* len, void *data){
    njt_cycle_t *cycle;
    njt_str_t msg;
    u_char *buf;

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
    buf = njt_calloc(msg.len,cycle->log);
    if(buf == NULL){
        goto end;
    }
    njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "send json : %V",&msg);
    njt_memcpy(buf,msg.data,msg.len);
    *len = msg.len;

    end:
    if(pool != NULL){
        njt_destroy_pool(pool);
    }

    return buf;
}

static int  njt_agent_dynlog_change_handler_internal(njt_str_t *key, njt_str_t *value, void *data,njt_str_t *out_msg){
    njt_int_t rc;
    njt_http_dyn_access_api_main_t *api_data = NULL;
    njt_pool_t *pool = NULL;
    njt_rpc_result_t * rpc_result;
    if(value->len < 2 ){
        return NJT_OK;
    }
    pool = njt_create_pool(njt_pagesize,njt_cycle->log);
    if(pool == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_agent_dynlog_change_handler create pool error");
        return NJT_OK;
    }
    api_data = njt_pcalloc(pool,sizeof (njt_http_dyn_access_api_main_t));
    if(api_data == NULL){
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "could not alloc buffer in function %s", __func__);
        goto end;
    }
    rpc_result = njt_rpc_result_create();
    if(!rpc_result){
        goto end;
    }
    njt_rpc_result_set_code(rpc_result,NJT_RPC_RSP_SUCCESS);
    rc =njt_json_parse_data(pool,value,njt_http_dyn_access_api_main_json_dt,api_data);
    if(rc == NJT_OK ){
        rc = njt_dynlog_update_access_log(pool, api_data, rpc_result);
    } else {
        // 解析json失败
        njt_rpc_result_set_code(rpc_result,NJT_RPC_RSP_ERR_JSON);
    }
    if(out_msg){
        njt_rpc_result_to_json_str(rpc_result,out_msg);
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
    if (njt_process == NJT_PROCESS_WORKER) {
        njt_str_t  rpc_key = njt_string("http_log");
//        njt_reg_kv_change_handler(&rpc_key, njt_agent_dynlog_change_handler,njt_agent_dynlog_rpc_handler, NULL);
        njt_reg_kv_msg_handler(&rpc_key, njt_agent_dynlog_change_handler, njt_agent_dynlog_put_handler, njt_agent_dynlog_rpc_handler, NULL);
    }
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
