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
#include "njt_http_dyn_ssl_api_parser.h"
#include "njt_http_dyn_ssl_parser.h"


static njt_int_t njt_http_update_server_ssl(njt_pool_t *pool, dyn_ssl_api_t *api_data,
                njt_rpc_result_t *rpc_result){
    njt_cycle_t                     *cycle;
    njt_http_core_srv_conf_t        *cscf;
    njt_http_ssl_srv_conf_t         *hsscf;
    dyn_ssl_api_cert_info_t         *cert;
    njt_str_t                        cert_sign_str;
    njt_str_t                        key_sign_str;
    njt_str_t                        cert_enc_str;
    njt_str_t                        key_enc_str;
    njt_str_t                       *tmp_str;
    njt_conf_t                       cf;
    u_char                          *data;
    u_char                           data_buf[1024];
    u_char                          *end;
    njt_str_t                        rpc_data_str;
    njt_str_t                       *port;
    njt_str_t                       *serverName;
    uint32_t                         crc32, *crc32_item;
    njt_uint_t                       j;
    njt_uint_t                       real_type;
    dyn_ssl_api_cert_info_cert_type_t *cert_type_item;
    
    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;

    njt_memzero(&cf,sizeof(njt_conf_t));
    cf.pool = pool;
    cf.log = njt_cycle->log;
    cf.cycle = (njt_cycle_t *)njt_cycle;

    cycle = (njt_cycle_t*)njt_cycle;
    njt_str_null(&rpc_result->conf_path);

    if (!api_data->is_listens_set || !api_data->is_serverNames_set 
        || !api_data->is_type_set || !api_data->is_cert_info_set
        || api_data->listens->nelts < 1 || api_data->serverNames->nelts < 1) {
        // params is empty
        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
            " server parameters error, listens or serverNames or type or cert_info is empty");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
        return NJT_ERROR;
    }

    port = get_dyn_ssl_api_listens_item(api_data->listens, 0);
    serverName = get_dyn_ssl_api_listens_item(api_data->serverNames, 0);

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

    njt_log_error(NJT_LOG_INFO, pool->log, 0, "dynssl start update listen:%V server_name:%V",
            port, serverName);

    hsscf = njt_http_get_module_srv_conf(cscf->ctx, njt_http_ssl_module);
    if(hsscf == NULL || hsscf->ssl.ctx == NULL){
        njt_log_error(NJT_LOG_ERR, pool->log, 0, 
            " dyn ssl, get njt_http_ssl_module config error, can`t find server by listen:%V server_name:%V ",
            port, serverName);

        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " get njt_http_ssl_module config error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

        return NJT_ERROR;
    }

    if(hsscf->certificate_values){
        njt_log_error(NJT_LOG_ERR, pool->log, 0, 
            " dyn ssl, certificate has variable, not support dyn update, listen:%V server_name:%V",
            port, serverName);

        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " dyn ssl, certificate has variable, not support dyn update");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

        return NJT_ERROR;
    }    

    end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " listen[%V] server_name[%V]", port, serverName);
    rpc_data_str.len = end - data_buf;
    njt_rpc_result_set_conf_path(rpc_result, &rpc_data_str);

    cert =  api_data->cert_info;
    hsscf->ssl.log = njt_cycle->log;

    if(!cert->is_cert_type_set){
        cert->cert_type = DYN_SSL_API_CERT_INFO_CERT_TYPE_RSA;
    }

    njt_crc32_init(crc32);
    njt_crc32_update(&crc32, cert->certificate.data, cert->certificate.len);
    njt_crc32_update(&crc32, cert->certificateKey.data, cert->certificateKey.len);
    if(cert->cert_type == DYN_SSL_API_CERT_INFO_CERT_TYPE_NTLS){
        njt_crc32_update(&crc32, (u_char*)"ntls", 4);
        if(cert->certificateEnc.len > 0){
            njt_crc32_update(&crc32, cert->certificateEnc.data, cert->certificateEnc.len);
        }
        if(cert->certificateKeyEnc.len > 0){
            njt_crc32_update(&crc32, cert->certificateKeyEnc.data, cert->certificateKeyEnc.len);
        }
    }else if(cert->cert_type == DYN_SSL_API_CERT_INFO_CERT_TYPE_RSA){
        njt_crc32_update(&crc32, (u_char*)"rsa", 3);
    }else{
        njt_crc32_update(&crc32, (u_char*)"ecc", 3);
    }
    njt_crc32_final(crc32);

    //check same cert, if has exist, should return cert repeated info
    if(hsscf->dyn_cert_crc32 != NULL){
        //get crc32 of current cert
        //compare
        crc32_item = hsscf->dyn_cert_crc32->elts;
        for(j = 0 ; j < hsscf->dyn_cert_crc32->nelts ; ++j ){
            if(crc32 == crc32_item[j]){
                //if exist, return repeated error
                return NJT_DECLINED;
            }
        }
    }

    if(hsscf->cert_types == NULL){
        hsscf->cert_types = njt_array_create(hsscf->certificates->pool, 4, sizeof(njt_uint_t));
        if(hsscf->cert_types == NULL){
            njt_log_error(NJT_LOG_EMERG, pool->log, 0,
                " cert_type create error");

            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
                "dyn ssl, cert_type create error");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

            return NJT_ERROR;
        }
    }


    if(!cert->is_certificate_set || !cert->is_certificateKey_set){
        njt_log_error(NJT_LOG_EMERG, pool->log, 0," cert or key is empty");
        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " cert or key is empty");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

        return NJT_ERROR;
    }

    if(cert->cert_type == DYN_SSL_API_CERT_INFO_CERT_TYPE_RSA ||
        cert->cert_type == DYN_SSL_API_CERT_INFO_CERT_TYPE_ECC){
        //get cert type
        if(NJT_ERROR == njt_ssl_get_certificate_type(&cf, &hsscf->ssl, &cert->certificate, &cert->certificateKey, &real_type)){
            njt_log_error(NJT_LOG_EMERG, pool->log, 0," get cert type error from certinfo");
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " get cert type error from certinfo");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

            return NJT_ERROR;
        }

        switch (real_type)
        {
        case 0:
            // RSA type
            if(cert->cert_type != DYN_SSL_API_CERT_INFO_CERT_TYPE_RSA){
                njt_log_error(NJT_LOG_EMERG, pool->log, 0,
                    " certinfo shows real type is rsa, please check certinfo and type");

                return NJT_ERROR;
            }
            
            break;
        // case 1:
        //     // NTLS type
        //     if(cert->cert_type != DYN_SSL_API_CERT_INFO_CERT_TYPE_NTLS){
        //         njt_log_error(NJT_LOG_EMERG, pool->log, 0,
        //             " certinfo shows real type is NTLS, so treat as ntls type");

        //         cert->cert_type = DYN_SSL_API_CERT_INFO_CERT_TYPE_NTLS;
        //     }
            
        //     break;
        case 2:
            // ECC type
            if(cert->cert_type != DYN_SSL_API_CERT_INFO_CERT_TYPE_ECC){
                njt_log_error(NJT_LOG_EMERG, pool->log, 0,
                    " certinfo shows real type is ecc, please check certinfo and type");

                return NJT_ERROR;
            }
            
            break;
        default:
            /* unknown type */
            njt_log_error(NJT_LOG_EMERG, pool->log, 0,
                    " certinfo and type is not match, please check certinfo and type");
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
                    " certinfo and type is not match, please check certinfo and type");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            
            return NJT_ERROR;
        }
    }

    //check param is ntls or rsa or ecc cert, if empty, default rsa
    if(cert->cert_type == DYN_SSL_API_CERT_INFO_CERT_TYPE_RSA ||
        cert->cert_type == DYN_SSL_API_CERT_INFO_CERT_TYPE_ECC){
        if(!cert->is_certificate_set || !cert->is_certificateKey_set){
            njt_log_error(NJT_LOG_EMERG, pool->log, 0," cert or key is empty");
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " cert or key is empty");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

            return NJT_ERROR;
        }

        if (njt_ssl_certificate(&cf, &hsscf->ssl, &cert->certificate, &cert->certificateKey, NULL)
            != NJT_OK)
        {
            njt_log_error(NJT_LOG_EMERG, pool->log, 0,"njt_ssl_certificate error");
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " njt_ssl_certificate error");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            return NJT_ERROR;
        }

        tmp_str = njt_array_push(hsscf->certificates);
        if(tmp_str != NULL){
            njt_str_copy_pool(hsscf->certificates->pool, (*tmp_str), (cert->certificate), return NJT_ERROR;);
        }
        tmp_str = njt_array_push(hsscf->certificate_keys);
        if(tmp_str != NULL){
            njt_str_copy_pool(hsscf->certificate_keys->pool,(*tmp_str), (cert->certificateKey), return NJT_ERROR;);
        }

        //udpate cert type
        cert_type_item = njt_array_push(hsscf->cert_types);
        if(cert_type_item != NULL){
            *cert_type_item = cert->cert_type;
        }

    }else if(cert->cert_type == DYN_SSL_API_CERT_INFO_CERT_TYPE_NTLS){
#if (NJT_HAVE_NTLS)
        //check valid
        if(!cert->is_certificate_set || !cert->is_certificateEnc_set
            || !cert->is_certificateKey_set || !cert->is_certificateKeyEnc_set
            || cert->certificate.len < 1 || cert->certificateEnc.len < 1 
            || cert->certificateKey.len < 1 || cert->certificateKeyEnc.len < 1){
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
        tmp_str->len = sizeof("sign:") - 1 + cert->certificateKey.len;
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
        njt_memcpy(data, cert->certificateKey.data, cert->certificateKey.len);

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
        tmp_str->len = sizeof("enc:") - 1 + cert->certificateEnc.len;
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
        njt_memcpy(data, cert->certificateEnc.data, cert->certificateEnc.len);

        tmp_str = &key_enc_str;                
        tmp_str->len = sizeof("enc:") - 1 + cert->certificateKeyEnc.len;
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
        njt_memcpy(data, cert->certificateKeyEnc.data, cert->certificateKeyEnc.len);

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
    
        //udpate cert type
        cert_type_item = njt_array_push(hsscf->cert_types);
        if(cert_type_item != NULL){
            *cert_type_item = cert->cert_type;
        }

        //udpate cert type
        cert_type_item = njt_array_push(hsscf->cert_types);
        if(cert_type_item != NULL){
            *cert_type_item = cert->cert_type;
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
            "dyn ssl, njt_ssl_certificate cert_type not support, should ntls or rsa or ecc");
        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
            "dyn ssl, njt_ssl_certificate cert_type not support, should ntls or rsa or ecc");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

        return NJT_ERROR;
    }

    //save new cert's crc32
    if(hsscf->dyn_cert_crc32 == NULL){
        hsscf->dyn_cert_crc32 = njt_array_create(hsscf->certificates->pool, 4, sizeof(uint32_t));
        if(hsscf->dyn_cert_crc32 == NULL){
            njt_log_error(NJT_LOG_EMERG, pool->log, 0,
                " dyn_cert_crc32 create error");

            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
                "dyn ssl, dyn_cert_crc32 create error");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

            return NJT_ERROR;
        }

        crc32_item = njt_array_push(hsscf->dyn_cert_crc32);
        if(crc32_item == NULL){
            njt_log_error(NJT_LOG_EMERG, pool->log, 0,
                " dyn_cert_crc32 array push error");

            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
                "dyn ssl, dyn_cert_crc32 array push error");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

            return NJT_ERROR;
        }

        *crc32_item = crc32;
    }

    return NJT_OK;
}


static int  njt_http_ssl_update_handler(njt_str_t *key, njt_str_t *value, void *data, njt_str_t *out_msg){
    njt_int_t                            rc = NJT_OK;
    dyn_ssl_api_t                       *api_data = NULL;
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
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_http_ssl_change_handler create pool error");
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_MEM_ALLOC);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" update handler create pool error");
        rc = NJT_ERROR;

        goto end;
    }

    api_data = json_parse_dyn_ssl_api(pool, value, &err_info);
    if (api_data == NULL)
    {
        njt_log_error(NJT_LOG_ERR, pool->log, 0, 
                "json_parse_dyn_ssl_api err: %V",  &err_info.err_str);
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_JSON);
        njt_rpc_result_set_msg2(rpc_result, &err_info.err_str);

        rc = NJT_ERROR;
        njt_str_t msg = njt_string("");
        njt_kv_sendmsg(key,&msg,0);
        goto end;
    }

    njt_rpc_result_set_code(rpc_result,NJT_RPC_RSP_SUCCESS);
    rc = njt_http_update_server_ssl(pool,api_data, rpc_result);
    if(rc != NJT_OK){
        // if(from_api_add == 0){
        // 	njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "add topic_kv_change_handler error key=%V,value=%V",key,value);
        // 	njt_str_t msg = njt_string("");
        //     njt_kv_sendmsg(key,&msg,0);
        // }

        if(rc == NJT_DECLINED){
            njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_CERT_REPEATED);
            njt_rpc_result_set_msg(rpc_result, (u_char *)" dyn ssl cert repeated");
        }else{
            njt_str_t msg = njt_string("");
            njt_kv_sendmsg(key,&msg,0);
            njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
            njt_rpc_result_set_msg(rpc_result, (u_char *)" dyn ssl update fail");
        }
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


njt_str_t njt_http_dyn_ssl_srv_err_msg=njt_string("{\"code\":500,\"msg\":\"server error\"}");

static njt_str_t *njt_http_dyn_ssl_dump_conf(njt_cycle_t *cycle,njt_pool_t *pool){
    njt_http_ssl_srv_conf_t        *hsscf;
    njt_http_core_main_conf_t      *hcmcf;
    njt_http_core_srv_conf_t      **cscfp;
    njt_uint_t                      i,j;
    njt_array_t                    *array;
    njt_str_t                      *tmp_str;
    njt_http_server_name_t         *server_name;
    njt_str_t                      *key,*cert;
    njt_uint_t                     *cert_type;
    njt_http_complex_value_t       *var_key,*var_cert;
    njt_uint_t                      type;
    njt_str_t                       trip_str;
    dyn_ssl_t                       dynjson_obj;
    dyn_ssl_servers_item_t          *server_item;
    dyn_ssl_servers_item_certificates_item_t *cert_item;

    njt_memzero(&dynjson_obj, sizeof(dyn_ssl_t));
    hcmcf = njt_http_cycle_get_module_main_conf(cycle,njt_http_core_module);
    if(hcmcf == NULL){
        goto err;
    }

    set_dyn_ssl_servers(&dynjson_obj, create_dyn_ssl_servers(pool, 4));
    if(dynjson_obj.servers == NULL){
        goto err;
    }

    cscfp = hcmcf->servers.elts;
    for( i = 0; i < hcmcf->servers.nelts; i++){
        server_item = njt_pcalloc(pool, sizeof(dyn_ssl_servers_item_t));
        if(server_item == NULL){
            goto err;
        }

        set_dyn_ssl_servers_item_listens(server_item, create_dyn_ssl_servers_item_listens(pool, 4));
        set_dyn_ssl_servers_item_serverNames(server_item, create_dyn_ssl_servers_item_serverNames(pool, 4));

        array = njt_array_create(pool, 4, sizeof(njt_str_t));
        if(array == NULL){
            goto err;
        }
        njt_http_get_listens_by_server(array, cscfp[i]);

        for (j = 0; j < array->nelts; ++j) {
            tmp_str = (njt_str_t *)(array->elts)+ j;
            add_item_dyn_ssl_servers_item_listens(server_item->listens, tmp_str);
        }

        server_name = cscfp[i]->server_names.elts;
        for (j = 0; j < cscfp[i]->server_names.nelts; ++j) {
            tmp_str = &server_name[j].full_name;
            add_item_dyn_ssl_servers_item_serverNames(server_item->serverNames,tmp_str);
        }

        hsscf = njt_http_get_module_srv_conf(cscfp[i]->ctx, njt_http_ssl_module);
        if(hsscf == NULL){
            goto next;
        }
        if(hsscf->certificate_values == NULL){
            if(hsscf->certificates == NULL){
                goto next;
            }

            set_dyn_ssl_servers_item_certificates(server_item, create_dyn_ssl_servers_item_certificates(pool, 4));
            if(server_item->certificates == NULL ){
                goto err;
            }

            cert = hsscf->certificates->elts;
            key = hsscf->certificate_keys->elts;
            cert_type = hsscf->cert_types->elts;
            for(j = 0 ; j < hsscf->certificates->nelts ; ++j ){
                cert_item = create_dyn_ssl_servers_item_certificates_item(pool);
                if(cert_item == NULL ){
                    goto err;
                }
#if (NJT_HAVE_NTLS)
                type = njt_ssl_ntls_type(&cert[j]);
                if (type == NJT_SSL_NTLS_CERT_SIGN) {
                    set_dyn_ssl_servers_item_certificates_item_cert_type(cert_item, DYN_SSL_SERVERS_ITEM_CERTIFICATES_ITEM_CERT_TYPE_NTLS);

                    trip_str = cert[j];
                    njt_ssl_ntls_prefix_strip(&trip_str);
                    set_dyn_ssl_servers_item_certificates_item_certificate(cert_item, &trip_str);
                                    
                    trip_str = key[j];
                    njt_ssl_ntls_prefix_strip(&trip_str);
                    set_dyn_ssl_servers_item_certificates_item_certificateKey(cert_item, &trip_str);

                    //next must be have and must be enc
                    if(j == (hsscf->certificates->nelts - 1)){
                        add_item_dyn_ssl_servers_item_certificates(server_item->certificates, cert_item);
                        //after sign must has enc
                        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "dyn ssl, error: end sign cerst loss enc");
                        continue;
                    }

                    //j+1 type must be enc
                    type = njt_ssl_ntls_type(&cert[j+1]);
                    // key_type = njt_ssl_ntls_type(&key[j+1]);
                    // if(type != NJT_SSL_NTLS_CERT_ENC || key_type != NJT_SSL_NTLS_CERT_ENC){
                    if(type != NJT_SSL_NTLS_CERT_ENC){
                        add_item_dyn_ssl_servers_item_certificates(server_item->certificates, cert_item);
                        // njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "dyn ssl, error: after sign must has enc");
                        continue;
                    }

                    trip_str = cert[j+1];
                    njt_ssl_ntls_prefix_strip(&trip_str);
                    set_dyn_ssl_servers_item_certificates_item_certificateEnc(cert_item, &trip_str);

                    trip_str = key[j+1];
                    njt_ssl_ntls_prefix_strip(&trip_str);
                    set_dyn_ssl_servers_item_certificates_item_certificateKeyEnc(cert_item, &trip_str);

                    add_item_dyn_ssl_servers_item_certificates(server_item->certificates, cert_item);
                    j++;
                }else if (type == NJT_SSL_NTLS_CERT_ENC){
                    set_dyn_ssl_servers_item_certificates_item_cert_type(cert_item, DYN_SSL_SERVERS_ITEM_CERTIFICATES_ITEM_CERT_TYPE_NTLS);

                    trip_str = cert[j];
                    njt_ssl_ntls_prefix_strip(&trip_str);
                    set_dyn_ssl_servers_item_certificates_item_certificateEnc(cert_item, &trip_str);

                    trip_str = key[j];
                    njt_ssl_ntls_prefix_strip(&trip_str);
                    set_dyn_ssl_servers_item_certificates_item_certificateKeyEnc(cert_item, &trip_str);

                    add_item_dyn_ssl_servers_item_certificates(server_item->certificates, cert_item);
                    //should not get enc before sign
                    // njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "dyn ssl, error: should not get enc before sign");
                    continue;
                }else{
                    // set_dyn_ssl_servers_item_certificates_item_cert_type(cert_item, DYN_SSL_SERVERS_ITEM_CERTIFICATES_ITEM_CERT_TYPE_RSA);
                    set_dyn_ssl_servers_item_certificates_item_cert_type(cert_item, cert_type[j]);
                    set_dyn_ssl_servers_item_certificates_item_certificate(cert_item, &cert[j]);
                    set_dyn_ssl_servers_item_certificates_item_certificateKey(cert_item, &key[j]);

                    add_item_dyn_ssl_servers_item_certificates(server_item->certificates, cert_item);
                }
#else
                set_dyn_ssl_servers_item_certificates_item_cert_type(cert_item, cert_type[j]);

                set_dyn_ssl_servers_item_certificates_item_certificate(cert_item, &cert[j]);
                set_dyn_ssl_servers_item_certificates_item_certificateKey(cert_item, &key[j]);

                add_item_dyn_ssl_servers_item_certificates(server_item->certificates, cert_item);
#endif
            }
        }else{
            set_dyn_ssl_servers_item_certificates(server_item, create_dyn_ssl_servers_item_certificates(pool, 4));
            if(server_item->certificates == NULL ){
                goto err;
            }
            var_cert = hsscf->certificate_values->elts;
            var_key = hsscf->certificate_key_values->elts;
            //because has variable cert, so not suport certtype, set to other
            // cert_type = hsscf->cert_types->elts;
            for(j = 0 ; j < hsscf->certificate_values->nelts ; ++j ){
                cert_item = create_dyn_ssl_servers_item_certificates_item(pool);
                if(cert_item == NULL ){
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
                    set_dyn_ssl_servers_item_certificates_item_cert_type(cert_item, DYN_SSL_SERVERS_ITEM_CERTIFICATES_ITEM_CERT_TYPE_NTLS);

                    trip_str = var_cert[j].value;
                    njt_ssl_ntls_prefix_strip(&trip_str);
                    set_dyn_ssl_servers_item_certificates_item_certificate(cert_item, &trip_str);

                    trip_str = var_key[j].value;
                    njt_ssl_ntls_prefix_strip(&trip_str);
                    set_dyn_ssl_servers_item_certificates_item_certificateKey(cert_item, &trip_str);

                    //next must be have and must be enc
                    if(j == (hsscf->certificates->nelts - 1)){
                        add_item_dyn_ssl_servers_item_certificates(server_item->certificates, cert_item);
                        //after sign must has enc
                        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "dyn ssl, error: end sign cerst loss enc");
                        continue;
                    }

                    //j+1 type must be enc
                    type = njt_ssl_ntls_type(&var_cert[j+1].value);
                    // key_type = njt_ssl_ntls_type(&var_key[j+1].value);
                    // if(type != NJT_SSL_NTLS_CERT_ENC || key_type != NJT_SSL_NTLS_CERT_ENC){
                    if(type != NJT_SSL_NTLS_CERT_ENC){
                        add_item_dyn_ssl_servers_item_certificates(server_item->certificates, cert_item);
                        // njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "dyn ssl, error: after sign must has enc");
                        continue;
                    }

                    trip_str = var_cert[j+1].value;
                    njt_ssl_ntls_prefix_strip(&trip_str);
                    set_dyn_ssl_servers_item_certificates_item_certificateEnc(cert_item, &trip_str);

                    trip_str = var_key[j+1].value;
                    njt_ssl_ntls_prefix_strip(&trip_str);
                    set_dyn_ssl_servers_item_certificates_item_certificateKeyEnc(cert_item, &trip_str);

                    add_item_dyn_ssl_servers_item_certificates(server_item->certificates, cert_item);
                    j++;
                }else if (type == NJT_SSL_NTLS_CERT_ENC){
                    set_dyn_ssl_servers_item_certificates_item_cert_type(cert_item, DYN_SSL_SERVERS_ITEM_CERTIFICATES_ITEM_CERT_TYPE_NTLS);

                    trip_str = var_cert[j].value;
                    njt_ssl_ntls_prefix_strip(&trip_str);
                    set_dyn_ssl_servers_item_certificates_item_certificateEnc(cert_item, &trip_str);

                    trip_str = var_key[j].value;
                    njt_ssl_ntls_prefix_strip(&trip_str);
                    set_dyn_ssl_servers_item_certificates_item_certificateKeyEnc(cert_item, &trip_str);

                    add_item_dyn_ssl_servers_item_certificates(server_item->certificates, cert_item);
                    //should not get enc before sign
                    // njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "dyn ssl, error: should not get enc before sign");
                }else{
                    // set_dyn_ssl_servers_item_certificates_item_cert_type(cert_item, DYN_SSL_SERVERS_ITEM_CERTIFICATES_ITEM_CERT_TYPE_RSA);
                    set_dyn_ssl_servers_item_certificates_item_cert_type(cert_item, DYN_SSL_SERVERS_ITEM_CERTIFICATES_ITEM_CERT_TYPE_OTHER);

                    set_dyn_ssl_servers_item_certificates_item_certificate(cert_item, &var_cert[j].value);
                    set_dyn_ssl_servers_item_certificates_item_certificateKey(cert_item, &var_key[j].value);

                    add_item_dyn_ssl_servers_item_certificates(server_item->certificates, cert_item);
                }
#else
                set_dyn_ssl_servers_item_certificates_item_cert_type(cert_item, DYN_SSL_SERVERS_ITEM_CERTIFICATES_ITEM_CERT_TYPE_OTHER);
                set_dyn_ssl_servers_item_certificates_item_certificate(cert_item, &var_cert[j].value);
                set_dyn_ssl_servers_item_certificates_item_certificateKey(cert_item, &var_key[j].value);
                add_item_dyn_ssl_servers_item_certificates(server_item->certificates, cert_item);
#endif
            }
        }

        next:
        add_item_dyn_ssl_servers(dynjson_obj.servers, server_item);
    }

    return to_json_dyn_ssl(pool, &dynjson_obj, OMIT_NULL_ARRAY | OMIT_NULL_OBJ | OMIT_NULL_STR);

err:
    return &njt_http_dyn_ssl_srv_err_msg;
}

static u_char* njt_http_dyn_ssl_rpc_handler(njt_str_t *topic, njt_str_t *request, int* len, void *data){
    njt_cycle_t     *cycle;
    njt_str_t       *msg;
    u_char          *buf;

    buf = NULL;
    cycle = (njt_cycle_t*) njt_cycle;
    *len = 0 ;
    njt_pool_t *pool = NULL;
    pool = njt_create_pool(njt_pagesize,njt_cycle->log);
    if(pool == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_http_dyn_ssl_rpc_handler create pool error");
        goto end;
    }
    msg = njt_http_dyn_ssl_dump_conf(cycle, pool);
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
    njt_kv_reg_handler_t h;
    njt_memzero(&h, sizeof(njt_kv_reg_handler_t));
    h.key = &rpc_key;
    h.rpc_get_handler = njt_http_dyn_ssl_rpc_handler;
    h.rpc_put_handler = njt_http_ssl_put_handler;
    h.handler = njt_http_ssl_change_handler;
    h.api_type = NJT_KV_API_TYPE_INSTRUCTIONAL;
    njt_kv_reg_handler(&h);

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

