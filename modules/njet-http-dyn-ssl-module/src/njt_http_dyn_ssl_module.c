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
#include "njt_http_dyn_ssl_module.h"



static njt_int_t njt_http_update_server_ssl(njt_pool_t *pool, njt_http_dyn_ssl_put_api_main_t *api_data,
                njt_rpc_result_t *rpc_result){
    njt_cycle_t                     *cycle;
    njt_http_core_srv_conf_t        *cscf;
    njt_http_ssl_srv_conf_t         *hsscf;
    njt_http_dyn_ssl_cert_group_t   *cert;
    njt_str_t                        cert_sign_str;
    njt_str_t                        key_sign_str;
    njt_str_t                        cert_enc_str;
    njt_str_t                        key_enc_str;
    njt_str_t                       *tmp_str;
    njt_conf_t                       cf;
    u_char                          *data;
    njt_str_t                       *p_port;
    njt_str_t                       *p_sname;
    u_char                           data_buf[1024];
    u_char                          *end;
    njt_str_t                        rpc_data_str;
    
    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;

    njt_memzero(&cf,sizeof(njt_conf_t));
    cf.pool = pool;
    cf.log = njt_cycle->log;
    cf.cycle = (njt_cycle_t *)njt_cycle;

    cycle = (njt_cycle_t*)njt_cycle;

    p_port = (njt_str_t*)api_data->listens.elts;
    p_sname = (njt_str_t*)api_data->server_names.elts;

    if(p_port == NULL || p_sname == NULL){
        njt_log_error(NJT_LOG_ERR, pool->log, 0, "listen or server_name is NULL, just continue");            
        if(p_port != NULL){
            end = njt_snprintf(data_buf,sizeof(data_buf) - 1," listen[%V] server_name is NULL", p_port);
        }else if(p_sname != NULL){
            end = njt_snprintf(data_buf,sizeof(data_buf) - 1," server_name[%V] listen ipport is NULL", p_sname);
        }else{
            end = njt_snprintf(data_buf,sizeof(data_buf) - 1," listen server_name all NULL");
        }
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

        return NJT_ERROR;
    }

    cscf = njt_http_get_srv_by_port(cycle,(njt_str_t*)api_data->listens.elts,(njt_str_t*)api_data->server_names.elts);
    if(cscf == NULL){
        njt_log_error(NJT_LOG_ERR, pool->log, 0, "dyn ssl, can`t find server by listen:%V server_name:%V ",
                        (njt_str_t*)api_data->listens.elts,(njt_str_t*)api_data->server_names.elts);

        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " can`t find server by listen[%V] server_name[%V]", p_port, p_sname);
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

        return NJT_ERROR;
    }

    hsscf = njt_http_get_module_srv_conf(cscf->ctx,njt_http_ssl_module);
    if(hsscf == NULL || hsscf->ssl.ctx == NULL){
        njt_log_error(NJT_LOG_ERR, pool->log, 0, " dyn ssl, get njt_http_ssl_module config error, can`t find server by listen:%V server_name:%V ",
                        (njt_str_t*)api_data->listens.elts,(njt_str_t*)api_data->server_names.elts);

        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " get njt_http_ssl_module config error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

        return NJT_ERROR;
    }

    end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " listen[%V] server_name[%V]", p_port, p_sname);
    rpc_data_str.len = end - data_buf;
    njt_rpc_result_set_conf_path(rpc_result, &rpc_data_str);

    cert =  &api_data->cert_info;
    //todo 此处内存泄露
    hsscf->ssl.log = njt_cycle->log;
    //check param is ntls or regular cert, if empty, default regular
    if( cert->cert_type.len < 1 ||
        (cert->cert_type.len == 7 && njt_strncmp(cert->cert_type.data, "regular", 7) == 0)){
        if (njt_ssl_certificate(&cf, &hsscf->ssl, &cert->certificate, &cert->certificate_key, NULL)
            != NJT_OK)
        {
            njt_log_error(NJT_LOG_EMERG, pool->log, 0,"njt_ssl_certificate error");
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " njt_ssl_certificate error");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            return NJT_ERROR;
        }

        tmp_str =njt_array_push(hsscf->certificates);
        if(tmp_str != NULL){
            njt_str_copy_pool(hsscf->certificates->pool,(*tmp_str),cert->certificate, return NJT_ERROR;);
        }
        tmp_str =njt_array_push(hsscf->certificate_keys);
        if(tmp_str != NULL){
            njt_str_copy_pool(hsscf->certificate_keys->pool,(*tmp_str),cert->certificate_key, return NJT_ERROR;);
        }
    }else if(cert->cert_type.len == 4 && njt_strncmp(cert->cert_type.data, "ntls", 4) == 0){
#if (NJT_HAVE_NTLS)
        //check valid
        if(cert->certificate.len < 1 || cert->certificate_enc.len < 1
            || cert->certificate_key.len < 1 || cert->certificate_key_enc.len < 1){
            njt_log_error(NJT_LOG_EMERG, pool->log, 0,
                "dyn ssl, njt_ssl_certificate params size should > 0");
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
                "dyn ssl, njt_ssl_certificate params size should > 0");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

            return NJT_ERROR;
        }

        //update sign
        tmp_str = &cert_sign_str;                
        tmp_str->len = sizeof("sign:") - 1 + cert->certificate.len;
        tmp_str->data = njt_pcalloc(hsscf->certificates->pool, tmp_str->len + 1);
        if (tmp_str->data == NULL) {
            njt_log_error(NJT_LOG_EMERG, pool->log, 0,
                "dyn ssl, njt_ssl_certificate sign cert calloc error");
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
                "dyn ssl, njt_ssl_certificate sign cert calloc error");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            return NJT_ERROR;
        }
        data = njt_cpymem(tmp_str->data, "sign:", sizeof("sign:") - 1);
        njt_memcpy(data, cert->certificate.data, cert->certificate.len);

        tmp_str = &key_sign_str;                
        tmp_str->len = sizeof("sign:") - 1 + cert->certificate_key.len;
        tmp_str->data = njt_pcalloc(hsscf->certificate_keys->pool, tmp_str->len + 1);
        if (tmp_str->data == NULL) {
            njt_log_error(NJT_LOG_EMERG, pool->log, 0,
                "dyn ssl, njt_ssl_certificate key sign cert calloc error");
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
                "dyn ssl, njt_ssl_certificate key sign cert calloc error");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            return NJT_ERROR;
        }
        data = njt_cpymem(tmp_str->data, "sign:", sizeof("sign:") - 1);
        njt_memcpy(data, cert->certificate_key.data, cert->certificate_key.len);

        if (njt_ssl_certificate(&cf, &hsscf->ssl, &cert_sign_str, &key_sign_str, NULL)
            != NJT_OK)
        {
            njt_log_error(NJT_LOG_EMERG, pool->log, 0,"dyn ssl, sign certificate error");
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
                "dyn ssl, sign certificate error");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            return NJT_ERROR;
        }

        

        //update enc
        tmp_str = &cert_enc_str;                
        tmp_str->len = sizeof("enc:") - 1 + cert->certificate_enc.len;
        tmp_str->data = njt_pcalloc(hsscf->certificates->pool, tmp_str->len + 1);
        if (tmp_str->data == NULL) {
            njt_log_error(NJT_LOG_EMERG, pool->log, 0,
                "dyn ssl, njt_ssl_certificate enc cert calloc error");
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
                "dyn ssl, njt_ssl_certificate enc cert calloc error");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str); 
            return NJT_ERROR;
        }
        data = njt_cpymem(tmp_str->data, "enc:", sizeof("enc:") - 1);
        njt_memcpy(data, cert->certificate_enc.data, cert->certificate_enc.len);

        tmp_str = &key_enc_str;                
        tmp_str->len = sizeof("enc:") - 1 + cert->certificate_key_enc.len;
        tmp_str->data = njt_pcalloc(hsscf->certificate_keys->pool, tmp_str->len + 1);
        if (tmp_str->data == NULL) {
            njt_log_error(NJT_LOG_EMERG, pool->log, 0,
                "dyn ssl, njt_ssl_certificate key sign cert calloc error");
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
                "dyn ssl, njt_ssl_certificate key sign cert calloc error");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str); 
            return NJT_ERROR;
        }
        data = njt_cpymem(tmp_str->data, "enc:", sizeof("enc:") - 1);
        njt_memcpy(data, cert->certificate_key_enc.data, cert->certificate_key_enc.len);

        if (njt_ssl_certificate(&cf, &hsscf->ssl, &cert_enc_str, &key_enc_str, NULL)
            != NJT_OK)
        {
            njt_log_error(NJT_LOG_EMERG, pool->log, 0,"dyn ssl, enc certificate error");
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
                "dyn ssl, enc certificate error");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str); 
            return NJT_ERROR;
        }

        tmp_str =njt_array_push(hsscf->certificates);
        if(tmp_str != NULL){
            njt_str_copy_pool(hsscf->certificates->pool,(*tmp_str),cert_sign_str, return NJT_ERROR;);
        }else{
            njt_log_error(NJT_LOG_EMERG, pool->log, 0,
                "dyn ssl, njt_ssl_certificate cert sign arrary push error");
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
                "dyn ssl, njt_ssl_certificate cert sign arrary push error");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);    
            return NJT_ERROR;
        }

        tmp_str =njt_array_push(hsscf->certificate_keys);
        if(tmp_str != NULL){
            njt_str_copy_pool(hsscf->certificate_keys->pool,(*tmp_str),key_sign_str, return NJT_ERROR;);
        }else{
            njt_log_error(NJT_LOG_EMERG, pool->log, 0,
                "dyn ssl, njt_ssl_certificate key sign arrary push error");
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
                "dyn ssl, njt_ssl_certificate key sign arrary push error");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);       
            return NJT_ERROR;
        }


        tmp_str =njt_array_push(hsscf->certificates);
        if(tmp_str != NULL){
            njt_str_copy_pool(hsscf->certificates->pool,(*tmp_str),cert_enc_str, return NJT_ERROR;);
        }else{
            njt_log_error(NJT_LOG_EMERG, pool->log, 0,
                "dyn ssl, njt_ssl_certificate cert enc arrary push error");
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
                "dyn ssl, njt_ssl_certificate cert enc arrary push error");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);     
            return NJT_ERROR;
        }

        tmp_str =njt_array_push(hsscf->certificate_keys);
        if(tmp_str != NULL){
            njt_str_copy_pool(hsscf->certificate_keys->pool,(*tmp_str),key_enc_str, return NJT_ERROR;);
        }else{
            njt_log_error(NJT_LOG_EMERG, pool->log, 0,
                "dyn ssl, njt_ssl_certificate key enc arrary push error");
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
                "dyn ssl, njt_ssl_certificate key enc arrary push error");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);    
            return NJT_ERROR;
        }
#else

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "dyn ssl, NTLS support is not enabled, dual certs not supported");
                    end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
                        "dyn ssl, NTLS support is not enabled, dual certs not supported");
                    rpc_data_str.len = end - data_buf;
                    njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);  
    return NJT_CONF_ERROR;

#endif
    }else{
        njt_log_error(NJT_LOG_EMERG, pool->log, 0,
            "dyn ssl, njt_ssl_certificate cert_type not support, should ntls or regular");
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
                "dyn ssl, njt_ssl_certificate cert_type not support, should ntls or regular");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str); 
    }

    return NJT_OK;
}


static int  njt_http_ssl_update_handler(njt_str_t *key, njt_str_t *value, void *data, njt_str_t *out_msg){
    njt_int_t                            rc = NJT_OK;
    njt_http_dyn_ssl_put_api_main_t     *api_data = NULL;
    njt_pool_t                          *pool = NULL;
    njt_rpc_result_t                    *rpc_result = NULL;
	// njt_str_t                           worker_str = njt_string("/worker_0");
    // njt_str_t                           new_key;
	// njt_uint_t                          from_api_add = 0;


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
        njt_log_error(NJT_LOG_EMERG, pool->log, 0, "njt_http_ssl_change_handler create pool error");
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_MEM_ALLOC);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" update handler create pool error");
        rc = NJT_ERROR;

        goto end;
    }

    api_data = njt_pcalloc(pool,sizeof (njt_http_dyn_ssl_put_api_main_t));
    if(api_data == NULL){
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, pool->log, 0,
                       "could not alloc buffer in function %s", __func__);
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_MEM_ALLOC);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" api_data malloc error");
        rc = NJT_ERROR;
 
        goto end;
    }

    njt_rpc_result_set_code(rpc_result,NJT_RPC_RSP_SUCCESS);
    rc = njt_json_parse_data(pool,value,njt_http_dyn_ssl_api_put_json_dt,api_data);
    if(rc == NJT_OK ){
		// if(key->len > worker_str.len && njt_strncmp(key->data,worker_str.data,worker_str.len) == 0) {
		// 	from_api_add = 1;
		// } 
        rc = njt_http_update_server_ssl(pool,api_data, rpc_result);
        if(rc != NJT_OK){
            njt_str_t msg = njt_string("");
            njt_kv_sendmsg(key,&msg,0);
			// if(from_api_add == 0){
			// 	njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "add topic_kv_change_handler error key=%V,value=%V",key,value);
			// 	njt_str_t msg = njt_string("");
            //     njt_kv_sendmsg(key,&msg,0);
			// }

            njt_rpc_result_set_code(rpc_result,NJT_RPC_RSP_ERR);
            njt_rpc_result_set_msg(rpc_result, (u_char *)" dyn ssl update fail");
        }else{
			// if(key->len > worker_str.len && njt_strncmp(key->data,worker_str.data,worker_str.len) == 0) {
			// 	new_key.data = key->data + worker_str.len;
			// 	new_key.len  = key->len - worker_str.len;
			// 	njt_kv_sendmsg(&new_key,value,1);
			// }
            // njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "add topic_kv_change_handler succ key=%V,value=%V",key,value);

            if(rpc_result->data != NULL && rpc_result->data->nelts > 0){
                njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_PARTIAL_SUCCESS);
            }
        }
    }else{
        njt_str_t msg = njt_string("");
        njt_kv_sendmsg(key,&msg,0);
        njt_rpc_result_set_code(rpc_result,NJT_RPC_RSP_ERR_JSON);
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


njt_str_t njt_http_dyn_ssl_srv_err_msg=njt_string("{\"code\":500,\"msg\":\"server error\"}");

static njt_str_t njt_http_dyn_ssl_dump_conf(njt_cycle_t *cycle,njt_pool_t *pool){
    njt_http_ssl_srv_conf_t        *hsscf;
    njt_http_core_main_conf_t      *hcmcf;
    njt_http_core_srv_conf_t      **cscfp;
    njt_uint_t                      i,j;
    njt_array_t                    *array;
    njt_str_t                       json,*tmp_str;
    njt_str_t                       tmp_value_str;
    njt_http_server_name_t         *server_name;
    njt_json_manager                json_manager;
    njt_json_element               *srvs,*srv,*subs,*sub,*item;
    njt_str_t                      *key,*cert;
    njt_http_complex_value_t       *var_key,*var_cert;
    njt_uint_t                      type;
    njt_str_t                       trip_str;

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
#if (NJT_HAVE_NTLS)
                type = njt_ssl_ntls_type(&cert[j]);
                // key_type = njt_ssl_ntls_type(&key[j]);
                // if(type != key_type){
                //     njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "dyn ssl, error: cert type and key type not equal");
                //     continue;
                // }

                if (type == NJT_SSL_NTLS_CERT_SIGN) {
                    njt_str_set(&tmp_value_str, "ntls");
                    item = njt_json_str_element(pool,njt_json_fast_key("cert_type"), &tmp_value_str);
                    if(item == NULL ){
                        goto err;
                    }
                    njt_struct_add(sub,item,pool);

                    trip_str = cert[j];
                    njt_ssl_ntls_prefix_strip(&trip_str);
                    item = njt_json_str_element(pool,njt_json_fast_key("certificate"),&trip_str);
                    if(item == NULL ){
                        goto err;
                    }
                    njt_struct_add(sub,item,pool);
                                    
                    trip_str = key[j];
                    njt_ssl_ntls_prefix_strip(&trip_str);
                    item = njt_json_str_element(pool,njt_json_fast_key("certificateKey"),&trip_str);
                    if(item == NULL ){
                        goto err;
                    }
                    njt_struct_add(sub,item,pool);

                    //next must be have and must be enc
                    if(j == (hsscf->certificates->nelts - 1)){
                        njt_struct_add(subs,sub,pool);
                        //after sign must has enc
                        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "dyn ssl, error: end sign cerst loss enc");
                        continue;
                    }

                    //j+1 type must be enc
                    type = njt_ssl_ntls_type(&cert[j+1]);
                    // key_type = njt_ssl_ntls_type(&key[j+1]);
                    // if(type != NJT_SSL_NTLS_CERT_ENC || key_type != NJT_SSL_NTLS_CERT_ENC){
                    if(type != NJT_SSL_NTLS_CERT_ENC){
                        njt_struct_add(subs,sub,pool);
                        // njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "dyn ssl, error: after sign must has enc");
                        continue;
                    }

                    trip_str = cert[j+1];
                    njt_ssl_ntls_prefix_strip(&trip_str);
                    item = njt_json_str_element(pool,njt_json_fast_key("certificateEnc"),&trip_str);
                    if(item == NULL ){
                        goto err;
                    }
                    njt_struct_add(sub,item,pool);

                    trip_str = key[j+1];
                    njt_ssl_ntls_prefix_strip(&trip_str);
                    item = njt_json_str_element(pool,njt_json_fast_key("certificateKeyEnc"),&trip_str);
                    if(item == NULL ){
                        goto err;
                    }
                    njt_struct_add(sub,item,pool);

                    njt_struct_add(subs,sub,pool);
                    j++;
                }else if (type == NJT_SSL_NTLS_CERT_ENC){
                    njt_str_set(&tmp_value_str, "ntls");
                    item = njt_json_str_element(pool,njt_json_fast_key("cert_type"), &tmp_value_str);
                    if(item == NULL ){
                        goto err;
                    }
                    njt_struct_add(sub,item,pool);

                    trip_str = cert[j];
                    njt_ssl_ntls_prefix_strip(&trip_str);
                    item = njt_json_str_element(pool,njt_json_fast_key("certificateEnc"),&trip_str);
                    if(item == NULL ){
                        goto err;
                    }
                    njt_struct_add(sub,item,pool);

                    trip_str = key[j];
                    njt_ssl_ntls_prefix_strip(&trip_str);
                    item = njt_json_str_element(pool,njt_json_fast_key("certificateKeyEnc"),&trip_str);
                    if(item == NULL ){
                        goto err;
                    }
                    njt_struct_add(sub,item,pool);

                    njt_struct_add(subs,sub,pool);
                    //should not get enc before sign
                    // njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "dyn ssl, error: should not get enc before sign");
                    continue;
                }else{
                    njt_str_set(&tmp_value_str, "regular");
                    item = njt_json_str_element(pool,njt_json_fast_key("cert_type"), &tmp_value_str);
                    if(item == NULL ){
                        goto err;
                    }
                    njt_struct_add(sub,item,pool);
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
#else
                njt_str_set(&tmp_value_str, "regular");
                item = njt_json_str_element(pool,njt_json_fast_key("cert_type"), &njt_str_set);
                if(item == NULL ){
                    goto err;
                }
                njt_struct_add(sub,item,pool);
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
#endif
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
#if (NJT_HAVE_NTLS)
                type = njt_ssl_ntls_type(&var_cert[j].value);
                // key_type = njt_ssl_ntls_type(&var_key[j].value);
                // if(type != key_type){
                //     njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "dyn ssl, error: cert type and key type not equal");
                //     continue;
                // }

                if (type == NJT_SSL_NTLS_CERT_SIGN) {
                    njt_str_set(&tmp_value_str, "ntls");
                    item = njt_json_str_element(pool,njt_json_fast_key("cert_type"), &tmp_value_str);
                    if(item == NULL ){
                        goto err;
                    }
                    njt_struct_add(sub,item,pool);

                    trip_str = var_cert[j].value;
                    njt_ssl_ntls_prefix_strip(&trip_str);
                    item = njt_json_str_element(pool,njt_json_fast_key("certificate"),&trip_str);
                    if(item == NULL ){
                        goto err;
                    }
                    njt_struct_add(sub,item,pool);

                    trip_str = var_key[j].value;
                    njt_ssl_ntls_prefix_strip(&trip_str);
                    item = njt_json_str_element(pool,njt_json_fast_key("certificateKey"),&trip_str);
                    if(item == NULL ){
                        goto err;
                    }
                    njt_struct_add(sub,item,pool);

                    //next must be have and must be enc
                    if(j == (hsscf->certificates->nelts - 1)){
                        njt_struct_add(subs,sub,pool);
                        //after sign must has enc
                        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "dyn ssl, error: end sign cerst loss enc");
                        continue;
                    }

                    //j+1 type must be enc
                    type = njt_ssl_ntls_type(&var_cert[j+1].value);
                    // key_type = njt_ssl_ntls_type(&var_key[j+1].value);
                    // if(type != NJT_SSL_NTLS_CERT_ENC || key_type != NJT_SSL_NTLS_CERT_ENC){
                    if(type != NJT_SSL_NTLS_CERT_ENC){
                        njt_struct_add(subs,sub,pool);
                        // njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "dyn ssl, error: after sign must has enc");
                        continue;
                    }

                    trip_str = var_cert[j+1].value;
                    njt_ssl_ntls_prefix_strip(&trip_str);
                    item = njt_json_str_element(pool,njt_json_fast_key("certificateEnc"),&trip_str);
                    if(item == NULL ){
                        goto err;
                    }
                    njt_struct_add(sub,item,pool);

                    trip_str = var_key[j+1].value;
                    njt_ssl_ntls_prefix_strip(&trip_str);
                    item = njt_json_str_element(pool,njt_json_fast_key("certificateKeyEnc"),&trip_str);
                    if(item == NULL ){
                        goto err;
                    }
                    njt_struct_add(sub,item,pool);

                    njt_struct_add(subs,sub,pool);
                    j++;
                }else if (type == NJT_SSL_NTLS_CERT_ENC){
                    njt_str_set(&tmp_value_str, "ntls");
                    item = njt_json_str_element(pool,njt_json_fast_key("cert_type"), &tmp_value_str);
                    if(item == NULL ){
                        goto err;
                    }
                    njt_struct_add(sub,item,pool);

                    trip_str = var_cert[j].value;
                    njt_ssl_ntls_prefix_strip(&trip_str);
                    item = njt_json_str_element(pool,njt_json_fast_key("certificateEnc"),&trip_str);
                    if(item == NULL ){
                        goto err;
                    }
                    njt_struct_add(sub,item,pool);

                    trip_str = var_key[j].value;
                    njt_ssl_ntls_prefix_strip(&trip_str);
                    item = njt_json_str_element(pool,njt_json_fast_key("certificateKeyEnc"),&trip_str);
                    if(item == NULL ){
                        goto err;
                    }
                    njt_struct_add(sub,item,pool);

                    njt_struct_add(subs,sub,pool);
                    //should not get enc before sign
                    // njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "dyn ssl, error: should not get enc before sign");
                }else{
                    njt_str_set(&tmp_value_str, "regular");
                    item = njt_json_str_element(pool,njt_json_fast_key("cert_type"), &tmp_value_str);
                    if(item == NULL ){
                        goto err;
                    }
                    njt_struct_add(sub,item,pool);
                    item = njt_json_str_element(pool,njt_json_fast_key("certificate"),&var_cert[j].value);
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
#else
                njt_str_set(&tmp_value_str, "regular");
                item = njt_json_str_element(pool,njt_json_fast_key("cert_type"), &tmp_value_str);
                if(item == NULL ){
                    goto err;
                }
                njt_struct_add(sub,item,pool);
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
#endif
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


static int  njt_http_ssl_change_handler(njt_str_t *key, njt_str_t *value, void *data){
    return njt_http_ssl_update_handler(key, value, data, NULL);
}

static u_char* njt_http_ssl_put_handler(njt_str_t *topic, njt_str_t *request, int* len, void *data){
    njt_str_t err_json_msg;
    njt_str_null(&err_json_msg);
    njt_http_ssl_update_handler(topic, request, data, &err_json_msg);
    *len = err_json_msg.len;
    return err_json_msg.data;
}



static njt_int_t njt_http_dyn_ssl_init_process(njt_cycle_t* cycle){
    njt_str_t  rpc_key = njt_string("ssl");
    // njt_reg_kv_change_handler(&rpc_key, njt_http_ssl_change_handler,njt_http_dyn_ssl_rpc_handler, NULL);
    njt_reg_kv_msg_handler(&rpc_key, njt_http_ssl_change_handler, njt_http_ssl_put_handler, njt_http_dyn_ssl_rpc_handler, NULL);

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

