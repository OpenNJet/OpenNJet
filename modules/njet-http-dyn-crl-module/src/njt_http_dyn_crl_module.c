/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */
#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njet.h>
#include "njt_http_kv_module.h"

#include "njt_http_util.h"
#include "njt_str_util.h"
#include <njt_rpc_result_util.h>
#include "njt_http_dyn_crl_api_parser.h"
#include "njt_http_dyn_crl_parser.h"


static njt_int_t njt_http_update_server_crl(njt_pool_t *pool, dyn_crl_api_t *api_data,
                njt_rpc_result_t *rpc_result){
    njt_cycle_t                     *cycle;
    njt_http_core_srv_conf_t        *cscf;
    njt_http_ssl_srv_conf_t         *hsscf;
    njt_conf_t                       cf;
    u_char                           data_buf[1024];
    u_char                          *end;
    njt_str_t                        rpc_data_str;
    njt_str_t                       *port;
    njt_str_t                       *serverName;
    njt_uint_t                       j;
    njt_str_t                       *tmp_crl_path;
    njt_flag_t                       crl_exist = 0;
    
    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;

    njt_memzero(&cf,sizeof(njt_conf_t));
    cf.pool = pool;
    cf.log = njt_cycle->log;
    cf.cycle = (njt_cycle_t *)njt_cycle;

    cycle = (njt_cycle_t*)njt_cycle;
    njt_str_null(&rpc_result->conf_path);

    if (!api_data->is_listens_set || !api_data->is_serverNames_set 
        || !api_data->is_ssl_crl_set || api_data->ssl_crl.len <= 0
        || api_data->listens->nelts < 1 || api_data->serverNames->nelts < 1) {
        // params is empty
        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
            " server parameters error, listens or serverNames or ssl_crl is empty");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
        return NJT_ERROR;
    }

    port = get_dyn_crl_api_listens_item(api_data->listens, 0);
    serverName = get_dyn_crl_api_listens_item(api_data->serverNames, 0);

    cscf = njt_http_get_srv_by_port(cycle, port, serverName);
    if (cscf == NULL)
    {
        njt_log_error(NJT_LOG_INFO, pool->log, 0, "can`t find server by listen:%V server_name:%V ",
                        port, serverName);
        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " can`t find server by listen[%V] server_name[%V]", port, serverName);
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
        return NJT_ERROR;
    }

    njt_log_error(NJT_LOG_INFO, pool->log, 0, "dyncrl start update listen:%V server_name:%V",
            port, serverName);

    hsscf = njt_http_get_module_srv_conf(cscf->ctx, njt_http_ssl_module);
    if(hsscf == NULL){
        njt_log_error(NJT_LOG_ERR, pool->log, 0, 
            " dyn crl, get njt_http_ssl_module config error, can`t find server by listen:%V server_name:%V ",
            port, serverName);

        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " get njt_http_crl_module config error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

        return NJT_ERROR;
    }

    if(hsscf->verify == 0){
        njt_log_error(NJT_LOG_ERR, pool->log, 0, 
            " ssl_verify_client  is off, you could not set ssl_crl, listen:%V server_name:%V",
            port, serverName);

        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
            " ssl_verify_client  is off, you could not set ssl_crl, listen:%V server_name:%V",
            port, serverName);
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

        return NJT_ERROR;
    }    

    end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " listen[%V] server_name[%V]", port, serverName);
    rpc_data_str.len = end - data_buf;
    njt_rpc_result_set_conf_path(rpc_result, &rpc_data_str);

    //call load dyn crl_file
    if (njt_dyn_ssl_crl(&cf, &hsscf->ssl, &api_data->ssl_crl) != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, pool->log, 0, 
            " njt_dyn_ssl_crl error, listen:%V server_name:%V ",
            port, serverName);

        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
            " njt_dyn_ssl_crl error, listen:%V server_name:%V",
            port, serverName);
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

        return NJT_ERROR;
    }

    if(hsscf->crl.len == api_data->ssl_crl.len
        && njt_strncmp(hsscf->crl.data, api_data->ssl_crl.data, api_data->ssl_crl.len) == 0){
        crl_exist = 1;
    }

    tmp_crl_path = hsscf->crls_path->elts;
    for(j = 0 ; j < hsscf->crls_path->nelts ; ++j ){
        if(tmp_crl_path[j].len == api_data->ssl_crl.len
            && njt_strncmp(tmp_crl_path[j].data, api_data->ssl_crl.data, api_data->ssl_crl.len) == 0){
                crl_exist = 1;
                break;
            }
    }

    if(!crl_exist){
        //save crl_path
        tmp_crl_path = njt_array_push(hsscf->crls_path);
        if (tmp_crl_path == NULL) {
            njt_log_error(NJT_LOG_ERR, pool->log, 0, 
                " crls_path array malloc error, listen:%V server_name:%V",
                port, serverName);

            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
                " crls_path array malloc error, listen:%V server_name:%V",
                port, serverName);
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

            return NJT_ERROR;
        }

        njt_str_copy_pool(hsscf->crls_path->pool, (*tmp_crl_path), (api_data->ssl_crl), return NJT_ERROR;);
    }

    return NJT_OK;
}


static int  njt_http_crl_update_handler(njt_str_t *key, njt_str_t *value, void *data, njt_str_t *out_msg){
    njt_int_t                            rc = NJT_OK;
    dyn_crl_api_t                       *api_data = NULL;
    njt_pool_t                          *pool = NULL;
    njt_rpc_result_t                    *rpc_result = NULL;
    js2c_parse_error_t                  err_info;
    njt_str_t                           worker_str = njt_string("/worker_a");
    njt_str_t                           new_key;


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

    pool = njt_create_pool(njt_pagesize,njt_cycle->log);
    if(pool == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_http_crl_change_handler create pool error");
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_MEM_ALLOC);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" update handler create pool error");
        rc = NJT_ERROR;

        goto end;
    }

    api_data = json_parse_dyn_crl_api(pool, value, &err_info);
    if (api_data == NULL)
    {
        njt_log_error(NJT_LOG_ERR, pool->log, 0, 
                "json_parse_dyn_crl_api err: %V",  &err_info.err_str);
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_JSON);
        njt_rpc_result_set_msg2(rpc_result, &err_info.err_str);

        rc = NJT_ERROR;
        njt_str_t msg = njt_string("");
        njt_kv_sendmsg(key,&msg,0);
        goto end;
    }

    njt_rpc_result_set_code(rpc_result,NJT_RPC_RSP_SUCCESS);
    rc = njt_http_update_server_crl(pool,api_data, rpc_result);
    if(rc != NJT_OK){
        njt_str_t msg = njt_string("");
        njt_kv_sendmsg(key,&msg,0);
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" dyn crl update fail");
    }else{
        if(key->len > worker_str.len && njt_strncmp(key->data,worker_str.data,worker_str.len) == 0) {
        	new_key.data = key->data + worker_str.len;
        	new_key.len  = key->len - worker_str.len;
        	njt_kv_sendmsg(&new_key,value,1);
        }

        if(rpc_result->data != NULL && rpc_result->data->nelts > 0){
            njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_PARTIAL_SUCCESS);
        }
    }

    end:
    if(out_msg){
        njt_rpc_result_to_json_str(rpc_result,out_msg);
    }

    if(pool != NULL){
        njt_destroy_pool(pool);
    }

    if(rpc_result){
        njt_rpc_result_destroy(rpc_result);
    }

    return rc;
}


njt_str_t njt_http_dyn_crl_srv_err_msg=njt_string("{\"code\":500,\"msg\":\"server error\"}");

static njt_str_t *njt_http_dyn_crl_dump_conf(njt_cycle_t *cycle,njt_pool_t *pool){
    njt_http_ssl_srv_conf_t        *hsscf;
    njt_http_core_main_conf_t      *hcmcf;
    njt_http_core_srv_conf_t      **cscfp;
    njt_uint_t                      i,j;
    njt_array_t                    *array;
    njt_str_t                      *tmp_str;
    njt_http_server_name_t         *server_name;
    dyn_crl_t                       dynjson_obj;
    dyn_crl_servers_item_t         *server_item;
    njt_str_t                       ssl_crl_item;
    njt_str_t                      *crls_path;

    njt_memzero(&dynjson_obj, sizeof(dyn_crl_t));
    hcmcf = njt_http_cycle_get_module_main_conf(cycle,njt_http_core_module);
    if(hcmcf == NULL){
        goto err;
    }

    set_dyn_crl_servers(&dynjson_obj, create_dyn_crl_servers(pool, 4));
    if(dynjson_obj.servers == NULL){
        goto err;
    }

    cscfp = hcmcf->servers.elts;
    for( i = 0; i < hcmcf->servers.nelts; i++){
        server_item = njt_pcalloc(pool, sizeof(dyn_crl_servers_item_t));
        if(server_item == NULL){
            goto err;
        }

        set_dyn_crl_servers_item_listens(server_item, create_dyn_crl_servers_item_listens(pool, 4));
        set_dyn_crl_servers_item_serverNames(server_item, create_dyn_crl_servers_item_serverNames(pool, 4));

        array = njt_array_create(pool, 4, sizeof(njt_str_t));
        if(array == NULL){
            goto err;
        }
        njt_http_get_listens_by_server(array, cscfp[i]);

        for (j = 0; j < array->nelts; ++j) {
            tmp_str = (njt_str_t *)(array->elts)+ j;
            add_item_dyn_crl_servers_item_listens(server_item->listens, tmp_str);
        }

        server_name = cscfp[i]->server_names.elts;
        for (j = 0; j < cscfp[i]->server_names.nelts; ++j) {
            tmp_str = &server_name[j].full_name;
            add_item_dyn_crl_servers_item_serverNames(server_item->serverNames,tmp_str);
        }

        hsscf = njt_http_get_module_srv_conf(cscfp[i]->ctx, njt_http_ssl_module);
        if(hsscf == NULL){
            goto next;
        }
        if(hsscf->verify){
            set_dyn_crl_servers_item_ssl_crls(server_item, create_dyn_crl_servers_item_ssl_crls(pool, 4));
            if(server_item->ssl_crls == NULL ){
                goto err;
            }

            //get static crl file
            if(hsscf->crl.len > 0){
                ssl_crl_item.data = njt_pcalloc(pool, hsscf->crl.len);
                if(ssl_crl_item.data == NULL){
                    goto err;
                }

                njt_memcpy(ssl_crl_item.data, hsscf->crl.data, hsscf->crl.len);
                ssl_crl_item.len = hsscf->crl.len;

                add_item_dyn_crl_servers_item_ssl_crls(server_item->ssl_crls, &ssl_crl_item);
            }
            
            //get dyn crl file
            crls_path = hsscf->crls_path->elts;
            for(j = 0 ; j < hsscf->crls_path->nelts ; ++j ){
                if(crls_path[j].len <= 0){
                    continue;
                }

                ssl_crl_item.data = njt_pcalloc(pool, crls_path[j].len);
                if(ssl_crl_item.data == NULL){
                    goto err;
                }

                njt_memcpy(ssl_crl_item.data, crls_path[j].data, crls_path[j].len);
                ssl_crl_item.len = crls_path[j].len;

                add_item_dyn_crl_servers_item_ssl_crls(server_item->ssl_crls, &ssl_crl_item);
            }
        }

        next:
        add_item_dyn_crl_servers(dynjson_obj.servers, server_item);
    }

    return to_json_dyn_crl(pool, &dynjson_obj, OMIT_NULL_ARRAY | OMIT_NULL_OBJ | OMIT_NULL_STR);

err:
    return &njt_http_dyn_crl_srv_err_msg;
}

static u_char* njt_http_dyn_crl_rpc_handler(njt_str_t *topic, njt_str_t *request, int* len, void *data){
    njt_cycle_t     *cycle;
    njt_str_t       *msg;
    u_char          *buf;

    buf = NULL;
    cycle = (njt_cycle_t*) njt_cycle;
    *len = 0 ;
    njt_pool_t *pool = NULL;
    pool = njt_create_pool(njt_pagesize,njt_cycle->log);
    if(pool == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_http_dyn_crl_rpc_handler create pool error");
        goto end;
    }
    msg = njt_http_dyn_crl_dump_conf(cycle, pool);
    buf = njt_calloc(msg->len,cycle->log);
    if(buf == NULL){
        goto end;
    }
    njt_log_error(NJT_LOG_INFO, pool->log, 0, "send json : %V",msg);
    njt_memcpy(buf, msg->data, msg->len);
    *len = msg->len;

    end:
    if(pool != NULL){
        njt_destroy_pool(pool);
    }

    return buf;
}


static int  njt_http_crl_change_handler(njt_str_t *key, njt_str_t *value, void *data){
    return njt_http_crl_update_handler(key, value, data, NULL);
}

static u_char* njt_http_crl_put_handler(njt_str_t *topic, njt_str_t *request, int* len, void *data){
    njt_str_t err_json_msg;
    njt_str_null(&err_json_msg);
    njt_http_crl_update_handler(topic, request, data, &err_json_msg);
    *len = err_json_msg.len;
    return err_json_msg.data;
}

static njt_int_t njt_http_dyn_crl_init_process(njt_cycle_t* cycle){
    njt_str_t  rpc_key = njt_string("crl");
    njt_kv_reg_handler_t h;
    njt_memzero(&h, sizeof(njt_kv_reg_handler_t));
    h.key = &rpc_key;
    h.rpc_get_handler = njt_http_dyn_crl_rpc_handler;
    h.rpc_put_handler = njt_http_crl_put_handler;
    h.handler = njt_http_crl_change_handler;
    h.api_type = NJT_KV_API_TYPE_INSTRUCTIONAL;
    njt_kv_reg_handler(&h);

    return NJT_OK;
}


static njt_http_module_t njt_http_dyn_crl_module_ctx = {
        NULL,                                   /* preconfiguration */
        NULL,                                   /* postconfiguration */

        NULL,                                   /* create main configuration */
        NULL,                                  /* init main configuration */

        NULL,                                  /* create server configuration */
        NULL,                                  /* merge server configuration */

        NULL,                                   /* create location configuration */
        NULL                                    /* merge location configuration */
};

njt_module_t njt_http_dyn_crl_module = {
        NJT_MODULE_V1,
        &njt_http_dyn_crl_module_ctx,                /* module context */
        NULL,                                   /* module directives */
        NJT_HTTP_MODULE,                        /* module type */
        NULL,                                   /* init master */
        NULL,                                   /* init module */
        njt_http_dyn_crl_init_process,          /* init process */
        NULL,                                   /* init thread */
        NULL,                                   /* exit thread */
        NULL,                                   /* exit process */
        NULL,                                   /* exit master */
        NJT_MODULE_V1_PADDING
};

