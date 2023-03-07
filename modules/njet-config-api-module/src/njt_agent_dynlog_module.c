/*************************************************************************************
 Copyright (C), 2021-2023, TMLake(Beijing) Technology Ltd.,
 File name    : njt_agent_dynlog_module.c
 Version      : 1.0
 Author       : ChengXu
 Date         : 2023/2/20/020 
 Description  : 
 Other        :
 History      :
 <author>       <time>          <version >      <desc>
 ChengXu        2023/2/20/020       1.1             
***********************************************************************************/
//
// Created by Administrator on 2023/2/20/020.
//
#include <njt_core.h>
#include <njt_http_kv_module.h>
#include <njt_http.h>
#include <njt_json_util.h>
#include <njt_http_util.h>
#include "njt_dynlog_module.h"



static njt_json_define_t njt_http_dyn_access_api_loc_json_dt[] ={
        {
                njt_string("location"),
                offsetof(njt_http_dyn_access_api_loc_t, full_name),
                0,
                NJT_JSON_STR,
                NULL,
                NULL,
        },
        {
                njt_string("accessLogOn"),
                offsetof(njt_http_dyn_access_api_loc_t, log_on),
                0,
                NJT_JSON_BOOL,
                NULL,
                NULL,
        },
        {
                njt_string("locations"),
                offsetof(njt_http_dyn_access_api_loc_t, locs),
                sizeof(njt_http_dyn_access_api_loc_t),
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
                NJT_JSON_STR,
                NULL,
                NULL,
        },
        {
                njt_string("serverNames"),
                offsetof(njt_http_dyn_access_api_srv_t, server_names),
                sizeof(njt_str_t),
                NJT_JSON_STR,
                NULL,
                NULL,
        },
        {
                njt_string("locations"),
                offsetof(njt_http_dyn_access_api_srv_t, locs),
                sizeof(njt_http_dyn_access_api_loc_t),
                NJT_JSON_OBJ,
                njt_http_dyn_access_api_loc_json_dt,
                NULL,
        },
        njt_json_define_null,
};

static njt_json_define_t njt_http_dyn_access_api_main_json_dt[] ={
        {
                njt_string("servers"),
                offsetof(njt_http_dyn_access_api_main_t, servers),
                sizeof(njt_http_dyn_access_api_srv_t),
                NJT_JSON_OBJ,
                njt_http_dyn_access_api_srv_json_dt,
                NULL,
        },
        njt_json_define_null,
};


static njt_int_t njt_dynlog_update_locs_log(njt_array_t *locs,njt_queue_t *q){
    njt_http_core_loc_conf_t  *clcf;
    njt_http_location_queue_t *hlq;
    njt_http_dyn_access_api_loc_t *daal;
    njt_uint_t j;
    njt_queue_t *tq;
    njt_http_log_loc_conf_t *llcf;

    if(q == NULL){
        return NJT_OK;
    }
    daal = locs->elts;
    for( j = 0; j < locs->nelts ; ++j ){
        tq = njt_queue_head(q);
        for (;tq!= njt_queue_sentinel(q);tq = njt_queue_next(tq)) {
            hlq = njt_queue_data(tq, njt_http_location_queue_t, queue);
            clcf = hlq->exact == NULL ? hlq->inclusive : hlq->exact;
            njt_str_t name = daal[j].full_name;
            if (name.len == clcf->full_name.len && njt_strncmp(name.data, clcf->full_name.data, name.len) == 0) {
                llcf = njt_http_get_module_loc_conf(clcf, njt_http_log_module);
                llcf->off = daal[j].log_on?0:1;
                njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "change location %V log to %i",&daal[j].full_name,daal[j].log_on);
            }
            if(daal[j].locs.nelts > 0){
                njt_dynlog_update_locs_log(&daal[j].locs,clcf->old_locations);
            }
        }
    }
    return NJT_OK;
}

static njt_int_t njt_dynlog_update_access_log(njt_pool_t *pool,njt_http_dyn_access_api_main_t *api_data){

    njt_cycle_t *cycle;
    njt_http_core_srv_conf_t  *cscf;
    njt_http_core_loc_conf_t  *clcf;
    njt_http_dyn_access_api_srv_t *daas;
    njt_uint_t i;

    cycle = (njt_cycle_t*)njt_cycle;

    daas = api_data->servers.elts;
    for(i = 0; i < api_data->servers.nelts; ++i){
        cscf = njt_http_get_srv_by_port(cycle,(njt_str_t*)daas[i].listens.elts,(njt_str_t*)daas[i].server_names.elts);
        if(cscf == NULL){
            njt_log_error(NJT_LOG_INFO, pool->log, 0, "can`t find server by listen:%V server_name:%V ",
                          (njt_str_t*)daas[i].listens.elts,(njt_str_t*)daas[i].server_names.elts);
            continue;
        }
        clcf = njt_http_get_module_loc_conf(cscf->ctx,njt_http_core_module);
        njt_dynlog_update_locs_log(&daas[i].locs,clcf->old_locations);

    }
    return NJT_OK;
}


#define njt_json_fast_key(key) (u_char*)key,sizeof(key)-1
#define njt_json_null_key NULL,0

static njt_json_element* njt_json_str_element(njt_pool_t *pool,u_char *key,njt_uint_t len,njt_str_t *value){
    njt_json_element *element;

    element = NULL;
    element = njt_pcalloc(pool,sizeof (njt_json_element));
    if(element == NULL ){
        goto end;
    }
    element->type = NJT_JSON_STR;
    if(key != NULL){
        element->key.data = key;
        element->key.len = len;
    }
    if(value != NULL){
        element->strval = *value;
    }
    end:
    return element;
}
static njt_json_element* njt_json_bool_element(njt_pool_t *pool, u_char *key,njt_uint_t len,bool value){
    njt_json_element *element;

    element = NULL;
    element = njt_pcalloc(pool,sizeof (njt_json_element));
    if(element == NULL ){
        goto end;
    }
    element->type = NJT_JSON_BOOL;
    if(key != NULL){
        element->key.data = key;
        element->key.len = len;
    }
    element->bval = value;

    end:
    return element;
}

static njt_json_element* njt_json_obj_element(njt_pool_t *pool,u_char *key,njt_uint_t len){
    njt_json_element *element;

    element = NULL;
    element = njt_pcalloc(pool,sizeof (njt_json_element));
    if(element == NULL ){
        goto end;
    }
    element->type = NJT_JSON_OBJ;
    if(key != NULL){
        element->key.data = key;
        element->key.len = len;
    }
    end:
    return element;
}

static njt_json_element* njt_json_arr_element(njt_pool_t *pool,u_char *key,njt_uint_t len){
    njt_json_element *element;

    element = NULL;
    element = njt_pcalloc(pool,sizeof (njt_json_element));
    if(element == NULL ){
        goto end;
    }
    element->type = NJT_JSON_ARRAY;
    if(key != NULL){
        element->key.data = key;
        element->key.len = len;
    }
    end:
    return element;
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
    njt_uint_t i,j;
    njt_array_t *array;
    njt_str_t json,*tmp_str;
    njt_http_server_name_t *server_name;
    njt_json_manager json_manager;
    njt_json_element *srvs,*srv,*subs,*sub;
    njt_int_t rc;

    hcmcf = njt_http_cycle_get_module_main_conf(cycle,njt_http_core_module);

    srvs =  njt_json_arr_element(pool,njt_json_fast_key("servers"));
    if(srvs == NULL ){
        goto err;
    }

    cscfp = hcmcf->servers.elts;
    for( i = 0; i < hcmcf->servers.nelts; i++){
        array = njt_array_create(pool,4, sizeof(njt_str_t));
        njt_http_get_listens_by_server(array,cscfp[i]);

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
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                      "njt_struct_top_add error");
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
        njt_log_error(NJT_LOG_EMERG, pool->log, 0, "njt_agent_dynlog_change_handler create pool error");
        goto end;
    }
    msg = njt_dynlog_dump_log_conf(cycle,pool);
    buf = njt_calloc(msg.len,cycle->log);
    if(buf == NULL){
        goto end;
    }
    njt_log_error(NJT_LOG_INFO, pool->log, 0, "send json : %V",&msg);
    njt_memcpy(buf,msg.data,msg.len);
    *len = msg.len;

    end:
    if(pool != NULL){
        njt_destroy_pool(pool);
    }

    return buf;
}

static int  njt_agent_dynlog_change_handler(njt_str_t *key, njt_str_t *value, void *data){
    njt_int_t rc;
    njt_http_dyn_access_api_main_t *api_data = NULL;
    njt_pool_t *pool = NULL;
    if(value->len < 2 ){
        return NJT_OK;
    }
    pool = njt_create_pool(njt_pagesize,njt_cycle->log);
    if(pool == NULL){
        njt_log_error(NJT_LOG_EMERG, pool->log, 0, "njt_agent_dynlog_change_handler create pool error");
        return NJT_OK;
    }
    api_data = njt_pcalloc(pool,sizeof (njt_http_dyn_access_api_main_t));
    if(api_data == NULL){
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, pool->log, 0,
                       "could not alloc buffer in function %s", __func__);
        goto end;
    }

    rc =njt_json_parse_data(pool,value,njt_http_dyn_access_api_main_json_dt,api_data);
    if(rc == NJT_OK ){
        njt_dynlog_update_access_log(pool,api_data);
    }

    end:
    if(pool != NULL){
        njt_destroy_pool(pool);
    }
    return NJT_OK;
}

static njt_int_t njt_agent_dynlog_init_process(njt_cycle_t* cycle){
    njt_str_t  rpc_key = njt_string("http_log");
    njt_reg_kv_change_handler(&rpc_key, njt_agent_dynlog_change_handler,njt_agent_dynlog_rpc_handler, NULL);
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