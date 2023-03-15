/*************************************************************************************
 Copyright (C), 2021-2023, TMLake(Beijing) Technology Ltd.,
 File name    : njt_dyn_ssl_module.c
 Version      : 1.0
 Author       : ChengXu
 Date         : 2023/3/2/002 
 Description  : 
 Other        :
 History      :
 <author>       <time>          <version >      <desc>
 ChengXu        2023/3/2/002       1.1             
***********************************************************************************/
//
// Created by Administrator on 2023/3/2/002.
//
#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njet.h>
#include "njt_http_kv_module.h"
#include "njt_json_util.h"
#include "njt_http_util.h"
#include "njt_str_util.h"

typedef struct  {
    njt_str_t certificate;
    njt_str_t certificate_key;
}njt_http_dyn_ssl_cert_group_t;

typedef struct {
    njt_array_t listens;
    njt_array_t server_names;
    njt_array_t certificates;
}njt_http_dyn_ssl_api_srv_t;
typedef struct {
    njt_array_t servers;
}njt_http_dyn_ssl_api_main_t;


static njt_json_define_t njt_http_dyn_ssl_cert_group_json_dt[] ={
        {
                njt_string("certificate"),
                offsetof(njt_http_dyn_ssl_cert_group_t, certificate),
                0,
                NJT_JSON_STR,
                NULL,
                NULL,
        },
        {
                njt_string("certificateKey"),
                offsetof(njt_http_dyn_ssl_cert_group_t, certificate_key),
                0,
                NJT_JSON_STR,
                NULL,
                NULL,
        },
        njt_json_define_null,
};

static njt_json_define_t njt_http_dyn_ssl_api_srv_json_dt[] ={
        {
                njt_string("listens"),
                offsetof(njt_http_dyn_ssl_api_srv_t, listens),
                sizeof(njt_str_t),
                NJT_JSON_STR,
                NULL,
                NULL,
        },
        {
                njt_string("serverNames"),
                offsetof(njt_http_dyn_ssl_api_srv_t, server_names),
                sizeof(njt_str_t),
                NJT_JSON_STR,
                NULL,
                NULL,
        },
        {
                njt_string("certificates"),
                offsetof(njt_http_dyn_ssl_api_srv_t, certificates),
                sizeof(njt_http_dyn_ssl_cert_group_t),
                NJT_JSON_OBJ,
                njt_http_dyn_ssl_cert_group_json_dt,
                NULL,
        },
        njt_json_define_null,
};

static njt_json_define_t njt_http_dyn_ssl_api_main_json_dt[] ={
        {
                njt_string("servers"),
                offsetof(njt_http_dyn_ssl_api_main_t, servers),
                sizeof(njt_http_dyn_ssl_api_srv_t),
                NJT_JSON_OBJ,
                njt_http_dyn_ssl_api_srv_json_dt,
                NULL,
        },
        njt_json_define_null,
};



static njt_int_t njt_http_update_server_ssl(njt_pool_t *pool,njt_http_dyn_ssl_api_main_t *api_data){
    njt_cycle_t *cycle;
    njt_http_core_srv_conf_t *cscf;
    njt_http_ssl_srv_conf_t  *hsscf;
    njt_http_dyn_ssl_api_srv_t *daas;
    njt_http_dyn_ssl_cert_group_t *cert;
    njt_str_t *tmp_str;
    njt_uint_t i,j;
    njt_conf_t cf;


    njt_memzero(&cf,sizeof(njt_conf_t));
    cf.pool = pool;
    cf.log = njt_cycle->log;
    cf.cycle = (njt_cycle_t *)njt_cycle;

    cycle = (njt_cycle_t*)njt_cycle;

    daas = api_data->servers.elts;
    for(i = 0; i < api_data->servers.nelts; ++i){
        cscf = njt_http_get_srv_by_port(cycle,(njt_str_t*)daas[i].listens.elts,(njt_str_t*)daas[i].server_names.elts);
        if(cscf == NULL){
            njt_log_error(NJT_LOG_INFO, pool->log, 0, "can`t find server by listen:%V server_name:%V ",
                          (njt_str_t*)daas[i].listens.elts,(njt_str_t*)daas[i].server_names.elts);
            continue;
        }
        hsscf = njt_http_get_module_srv_conf(cscf->ctx,njt_http_ssl_module);
        if(hsscf == NULL){
            continue;
        }
        cert =  daas[i].certificates.elts;
        for(j = 0 ; j < daas[i].certificates.nelts; ++j ){
            //todo 此处内存泄露
            if (njt_ssl_certificate(&cf, &hsscf->ssl, &cert[j].certificate, &cert[j].certificate_key,NULL,NULL, NULL)
                != NJT_OK)
            {
                njt_log_error(NJT_LOG_EMERG, pool->log, 0,"njt_ssl_certificate error");
                return NJT_ERROR;
            }
            tmp_str =njt_array_push(hsscf->certificates);
            if(tmp_str != NULL){
                njt_str_copy_pool(hsscf->certificates->pool,(*tmp_str),cert[j].certificate, continue;);
            }
            tmp_str =njt_array_push(hsscf->certificate_keys);
            if(tmp_str != NULL){
                njt_str_copy_pool(hsscf->certificate_keys->pool,(*tmp_str),cert[j].certificate_key, continue;);
            }
        }
    }
    return NJT_OK;
}


static int  njt_http_ssl_change_handler(njt_str_t *key, njt_str_t *value, void *data){
    njt_int_t rc;
    njt_http_dyn_ssl_api_main_t *api_data = NULL;
    njt_pool_t *pool = NULL;
    if(value->len < 2 ){
        return NJT_OK;
    }
    pool = njt_create_pool(njt_pagesize,njt_cycle->log);
    if(pool == NULL){
        njt_log_error(NJT_LOG_EMERG, pool->log, 0, "njt_http_ssl_change_handler create pool error");
        return NJT_OK;
    }
    api_data = njt_pcalloc(pool,sizeof (njt_http_dyn_ssl_api_main_t));
    if(api_data == NULL){
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, pool->log, 0,
                       "could not alloc buffer in function %s", __func__);
        goto end;
    }

    rc =njt_json_parse_data(pool,value,njt_http_dyn_ssl_api_main_json_dt,api_data);
    if(rc == NJT_OK ){
        njt_http_update_server_ssl(pool,api_data);
    }

    end:
    if(pool != NULL){
        njt_destroy_pool(pool);
    }
    return NJT_OK;
}
njt_str_t njt_http_dyn_ssl_srv_err_msg=njt_string("{\"code\":500,\"msg\":\"server error\"}");

static njt_str_t njt_http_dyn_ssl_dump_conf(njt_cycle_t *cycle,njt_pool_t *pool){
    njt_http_ssl_srv_conf_t *hsscf;
    njt_http_core_main_conf_t *hcmcf;
    njt_http_core_srv_conf_t  **cscfp;
    njt_uint_t i,j;
    njt_array_t *array;
    njt_str_t json,*tmp_str;
    njt_http_server_name_t *server_name;
    njt_json_manager json_manager;
    njt_json_element *srvs,*srv,*subs,*sub,*item;
    njt_str_t *key,*cert;
    njt_http_complex_value_t *var_key,*var_cert;

    hcmcf = njt_http_cycle_get_module_main_conf(cycle,njt_http_core_module);

    njt_memzero(&json_manager, sizeof(njt_json_manager));

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
        hsscf = njt_http_get_module_srv_conf(cscfp[i]->ctx,njt_http_ssl_module);
        if(hsscf == NULL){
            goto next;
        }
        if(hsscf->certificate_values == NULL){
            if(hsscf->certificates == NULL){
                goto next;
            }
            subs =  njt_json_arr_element(pool,njt_json_fast_key("certificates"));
            if(subs == NULL ){
                goto err;
            }
            cert = hsscf->certificates->elts;
            key = hsscf->certificate_keys->elts;
            for(j = 0 ; j < hsscf->certificates->nelts ; ++j ){
                sub =  njt_json_obj_element(pool,njt_json_null_key);
                if(sub == NULL ){
                    goto err;
                }
                item = njt_json_str_element(pool,njt_json_fast_key("certificate"),&cert[j]);
                if(item == NULL ){
                    goto err;
                }
                njt_struct_add(sub,item,pool);
                item = njt_json_str_element(pool,njt_json_fast_key("certificateKey"),&key[j]);
                if(item == NULL ){
                    goto err;
                }
                njt_struct_add(sub,item,pool);
                njt_struct_add(subs,sub,pool);
            }
            njt_struct_add(srv,subs,pool);
        }else{
            subs =  njt_json_arr_element(pool,njt_json_fast_key("certificates"));
            if(subs == NULL ){
                goto err;
            }
            var_cert = hsscf->certificate_values->elts;
            var_key = hsscf->certificate_key_values->elts;
            for(j = 0 ; j < hsscf->certificate_values->nelts ; ++j ){
                sub =  njt_json_obj_element(pool,njt_json_null_key);
                if(sub == NULL ){
                    goto err;
                }
                item = njt_json_str_element(pool,njt_json_fast_key("certificates"),&var_cert[j].value);
                if(item == NULL ){
                    goto err;
                }
                njt_struct_add(sub,item,pool);
                item = njt_json_str_element(pool,njt_json_fast_key("certificateKey"),&var_key[j].value);
                if(item == NULL ){
                    goto err;
                }
                njt_struct_add(sub,item,pool);
                njt_struct_add(subs,sub,pool);
            }
            njt_struct_add(srv,subs,pool);
        }
        next:
        njt_struct_add(srvs,srv,pool);
    }

    njt_struct_top_add(&json_manager,srvs,NJT_JSON_OBJ,pool);
    njt_memzero(&json, sizeof(njt_str_t));
    njt_structure_2_json(&json_manager, &json, pool);

    return json;

    err:
    return njt_http_dyn_ssl_srv_err_msg;
}

static u_char* njt_http_dyn_ssl_rpc_handler(njt_str_t *topic, njt_str_t *request, int* len, void *data){
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
    msg = njt_http_dyn_ssl_dump_conf(cycle,pool);
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

static njt_int_t njt_http_dyn_ssl_init_process(njt_cycle_t* cycle){
    njt_str_t  rpc_key = njt_string("http_ssl");
    njt_reg_kv_change_handler(&rpc_key, njt_http_ssl_change_handler,njt_http_dyn_ssl_rpc_handler, NULL);
    return NJT_OK;
}





static njt_http_module_t njt_dyn_ssl_module_ctx = {
        NULL,                                   /* preconfiguration */
        NULL,                                   /* postconfiguration */

        NULL,                                   /* create main configuration */
        NULL,                                  /* init main configuration */

        NULL,                                  /* create server configuration */
        NULL,                                  /* merge server configuration */

        NULL,                                   /* create location configuration */
        NULL                                    /* merge location configuration */
};

njt_module_t njt_dyn_ssl_module = {
        NJT_MODULE_V1,
        &njt_dyn_ssl_module_ctx,                /* module context */
        NULL,                                   /* module directives */
        NJT_HTTP_MODULE,                        /* module type */
        NULL,                                   /* init master */
        NULL,                                   /* init module */
        njt_http_dyn_ssl_init_process,          /* init process */
        NULL,                                   /* init thread */
        NULL,                                   /* exit thread */
        NULL,                                   /* exit process */
        NULL,                                   /* exit master */
        NJT_MODULE_V1_PADDING
};

