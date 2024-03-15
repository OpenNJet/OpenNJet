/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */
#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_crypt.h>
#include <njt_http_kv_module.h>
#include <njt_rpc_result_util.h>
#include <njt_http_util.h>
#include "njt_http_api_register_module.h"
#include "njt_http_parser_auth_patch.h"
#include "njt_http_parser_auth_put.h"


#define MIN_CONFIG_BODY_LEN 2
#define MAX_CONFIG_BODY_LEN 5242880
#define NJT_HTTP_AUTH_API_PATH_BUF_SIZE 2048



static njt_int_t
njt_http_auth_api_init_worker(njt_cycle_t *cycle);

static njt_int_t njt_http_auth_api_init_module(njt_cycle_t *cycle);

static njt_int_t
njt_http_auth_api_init(njt_conf_t *cf);

static njt_int_t
njt_http_auth_api_handler(njt_http_request_t *r);

static njt_http_module_t njt_http_auth_api_module_ctx = {
        NULL,                              /* preconfiguration */
        njt_http_auth_api_init,            /* postconfiguration */

        NULL,                              /* create main configuration */
        NULL,                              /* init main configuration */

        NULL,                              /* create server configuration */
        NULL,                              /* merge server configuration */

        NULL,                              /* create location configuration */
        NULL                               /* merge location configuration */
};

njt_module_t njt_http_auth_api_module = {
        NJT_MODULE_V1,
        &njt_http_auth_api_module_ctx, /* module context */
        NULL,                               /* module directives */
        NJT_HTTP_MODULE,                    /* module type */
        NULL,                               /* init master */
        njt_http_auth_api_init_module,      /* init module */
        njt_http_auth_api_init_worker,      /* init process */
        NULL,                               /* init thread */
        NULL,                               /* exit thread */
        NULL,                               /* exit process */
        NULL,                               /* exit master */
        NJT_MODULE_V1_PADDING
};


static njt_int_t njt_http_auth_api_init_module(njt_cycle_t *cycle) {

    return NJT_OK;
}


static njt_int_t
njt_http_auth_api_init(njt_conf_t *cf) {
    njt_http_api_reg_info_t             h;
    njt_str_t  module_key = njt_string("/v1/auth_kv");

    njt_memzero(&h, sizeof(njt_http_api_reg_info_t));
    h.key = &module_key;
    h.handler = njt_http_auth_api_handler;
    njt_http_api_module_reg_handler(&h);

    return NJT_OK;
}




static njt_int_t njt_http_auth_api_conf_out_handler(
            njt_http_request_t *r, njt_rpc_result_t *rpc_result) {
    njt_buf_t       *buf;
    njt_chain_t     out;
    njt_int_t       rc;
    njt_str_t       tmp_str;

    switch (rpc_result->code) {
        case NJT_RPC_RSP_SUCCESS:
            r->headers_out.status = NJT_HTTP_OK;
            break;
        case NJT_RPC_RSP_ERR_MEM_ALLOC:
        case NJT_RPC_RSP_ERR:
            r->headers_out.status = NJT_HTTP_INTERNAL_SERVER_ERROR;
            break;
        case NJT_RPC_RSP_ERR_JSON:
            r->headers_out.status = NJT_HTTP_BAD_REQUEST;
            break;
        default:
            r->headers_out.status = NJT_HTTP_INTERNAL_SERVER_ERROR;
            break;
    }

    njt_rpc_result_to_json_str(rpc_result, &tmp_str);
    buf = njt_create_temp_buf(r->pool, tmp_str.len);
    if (buf == NULL) {
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "could not alloc buffer in function %s", __func__);
        return NJT_ERROR;
    }

    njt_memcpy(buf->last, tmp_str.data, tmp_str.len);
    buf->last += tmp_str.len;

    njt_str_t type = njt_string("application/json");
    r->headers_out.content_type = type;
    r->headers_out.content_length_n = buf->last - buf->pos;
    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }
    rc = njt_http_send_header(r);

    // r->header_only  when method is HEAD ,header_only is set.
    if (rc == NJT_ERROR || rc > NJT_OK) {
        return rc;
    }

    buf->last_buf = 1;
    out.buf = buf;
    out.next = NULL;
    return njt_http_output_filter(r, &out);
}


static void njt_http_auth_api_api_read_data(njt_http_request_t *r){
    njt_str_t                   json_str;
    njt_chain_t                 *body_chain, *tmp_chain;
    njt_int_t                   rc = NJT_OK;
    auth_passwd_put_api_t       *api_put_data = NULL;
    auth_passwd_patch_api_t     *api_patch_data = NULL;
    njt_uint_t                  len, size;
    js2c_parse_error_t          err_info;
    njt_rpc_result_t            *rpc_result = NULL;
    njt_array_t                 *path;
    njt_str_t                   *uri;
    njt_str_t                   auth_key, auth_passwd;
    u_char                      *p, *encrypted;
    u_char                      buf[NJT_HTTP_AUTH_API_PATH_BUF_SIZE];


    rpc_result = njt_rpc_result_create();
    if(!rpc_result){
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, 
                " auth api create rpc_result error");
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" auth api create rpc_result error");

        rc = NJT_ERROR;
        goto end;
    }

    njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_SUCCESS);

    body_chain = r->request_body->bufs;
    /*check the sanity of the json body*/
    if(NULL == body_chain){
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, 
                " auth api input body error");
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" input body error");

        rc = NJT_ERROR;
        goto out;
    }

    len = 0;
    tmp_chain = body_chain;
    while (tmp_chain != NULL) {
        len += tmp_chain->buf->last - tmp_chain->buf->pos;
        tmp_chain = tmp_chain->next;
    }

    json_str.len = len;
    json_str.data = njt_pcalloc(r->pool, len);
    if (json_str.data == NULL) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, 
                " auth api malloc error");
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_MEM_ALLOC);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" malloc error");

        rc = NJT_ERROR;
        goto out;
    }

    len = 0;
    tmp_chain = r->request_body->bufs;
    while (tmp_chain != NULL) {
        size = tmp_chain->buf->last - tmp_chain->buf->pos;
        njt_memcpy(json_str.data + len, tmp_chain->buf->pos, size);
        tmp_chain = tmp_chain->next;
        len += size;
    }



    if(r->method == NJT_HTTP_PUT){
        api_put_data = json_parse_auth_passwd_put_api(r->pool, &json_str, &err_info);
        if(api_put_data == NULL){
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0, 
                " auth put api json parse error:%V json:%V", &err_info.err_str, &json_str);

            njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_JSON);
            njt_rpc_result_set_msg2(rpc_result, &err_info.err_str);

            rc = NJT_ERROR;
            goto out;
        }

        if(api_put_data->prefix.len < 1 || api_put_data->user_name.len < 1
            || api_put_data->password.len < 1){
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0, 
                " prefix, user_name and password should not be empty");

            njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_JSON);
            njt_rpc_result_set_msg(rpc_result, (u_char *)" prefix, user_name and password should not be empty");

            rc = NJT_ERROR;
            goto out;
        }

        njt_http_set_ctx(r, api_put_data, njt_http_auth_api_module);

        //set
        p = njt_snprintf(buf, NJT_HTTP_AUTH_API_PATH_BUF_SIZE, 
            "auth_basic:%V:%V", &api_put_data->prefix, &api_put_data->user_name);
        if (p == NULL) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0, 
                " njt_snprintf error, auth_basic:%V:%V", &api_put_data->prefix, &api_put_data->user_name);

            rc = NJT_ERROR;
            goto out;
        }

        auth_key.len = p - buf;
        auth_key.data = buf;

        if(NJT_OK == njt_db_kv_get(&auth_key, &auth_passwd)){
            njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
            njt_rpc_result_set_msg(rpc_result, (u_char *)" user existed");

            njt_log_error(NJT_LOG_ERR, r->connection->log, 0, 
                "user:[%V:%V] existed", &api_put_data->prefix, &api_put_data->user_name);

            rc = NJT_ERROR;
            goto out;
        }

        rc = njt_crypt(r->pool, api_put_data->password.data, (u_char *)"{SHA}",
                   &encrypted);
        
        if (rc != NJT_OK) {
            njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
            njt_rpc_result_set_msg(rpc_result, (u_char *)" password encrypt error");

            njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "password encrypt error");

            rc = NJT_ERROR;
            goto out;
        }

        auth_passwd.len = strlen((char *)encrypted);
        auth_passwd.data = encrypted;

        if(NJT_OK != njt_db_kv_set(&auth_key, &auth_passwd)){
            njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
            njt_rpc_result_set_msg(rpc_result, (u_char *)" set error");

            rc = NJT_ERROR;
            goto out;
        }
    }else if(r->method == NJT_HTTP_PATCH){
        api_patch_data = json_parse_auth_passwd_patch_api(r->pool, &json_str, &err_info);
        if(api_patch_data == NULL){
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0, 
                " auth patch api json parse error:%V json:%V", &err_info.err_str, &json_str);

            njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_JSON);
            njt_rpc_result_set_msg2(rpc_result, &err_info.err_str);

            rc = NJT_ERROR;
            goto out;
        }

        if(api_patch_data->password.len < 1){
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0, 
                " password should not be empty");

            njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_JSON);
            njt_rpc_result_set_msg(rpc_result, (u_char *)" password should not be empty");

            rc = NJT_ERROR;
            goto out;
        }

        njt_http_set_ctx(r, api_patch_data, njt_http_auth_api_module);

        //parse url
        path = njt_array_create(r->pool, 4, sizeof(njt_str_t));
        if (path == NULL) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "array init of path error.");
            rc = NJT_ERROR;

            goto out;
        }

        rc = njt_http_parse_path(r->uri, path);
        if(rc != NJT_OK){
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "url parse error.");
            rc = NJT_ERROR;

            goto out;
        }
        uri = path->elts;

        p = njt_snprintf(buf, NJT_HTTP_AUTH_API_PATH_BUF_SIZE, 
            "auth_basic:%V:%V", &uri[4], &uri[5]);
        if (p == NULL) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0, 
                " njt_snprintf error, auth_basic:%V:%V", &uri[4], &uri[5]);

            rc = NJT_ERROR;
            goto out;
        }

        auth_key.len = p - buf;
        auth_key.data = buf;


        if(NJT_OK != njt_db_kv_get(&auth_key, &auth_passwd)){
            njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
            njt_rpc_result_set_msg(rpc_result, (u_char *)" user is not exist");

            njt_log_error(NJT_LOG_ERR, r->connection->log, 0, 
                "user:[%V:%V] is not exist", &uri[4], &uri[5]);

            rc = NJT_ERROR;
            goto out;
        }

        rc = njt_crypt(r->pool, api_patch_data->password.data, (u_char *)"{SHA}",
                   &encrypted);
        
        if (rc != NJT_OK) {
            njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
            njt_rpc_result_set_msg(rpc_result, (u_char *)" password encrypt error");

            njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "password encrypt error");

            rc = NJT_ERROR;
            goto out;
        }

        auth_passwd.len = strlen((char *)encrypted);
        auth_passwd.data = encrypted;

        if(NJT_OK != njt_db_kv_set(&auth_key, &auth_passwd)){
            njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
            njt_rpc_result_set_msg(rpc_result, (u_char *)" modify password error");

            rc = NJT_ERROR;
            goto out;
        }
    }

out:
    rc = njt_http_auth_api_conf_out_handler(r, rpc_result);

end:
    if(rpc_result){
        njt_rpc_result_destroy(rpc_result);
        rpc_result = NULL;
    }
    njt_http_finalize_request(r, rc);
}


static njt_int_t
njt_http_auth_api_handler(njt_http_request_t *r) {
    njt_int_t                       rc = NJT_OK;
    njt_rpc_result_t                *rpc_result = NULL;
    njt_array_t                     *path;
    njt_str_t                       *uri;
    njt_str_t                       auth_key, auth_passwd;
    u_char                          *p;
    u_char                          buf[NJT_HTTP_AUTH_API_PATH_BUF_SIZE];

    rpc_result = njt_rpc_result_create();
    if(!rpc_result){
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, 
                " auth api create rpc_result error");
        return NJT_ERROR;
    }
    njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_SUCCESS);

    //parse url
    path = njt_array_create(r->pool, 4, sizeof(njt_str_t));
    if (path == NULL) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "array init of path error.");
        return NJT_ERROR;
    }

    rc = njt_http_parse_path(r->uri, path);
    if(rc != NJT_OK){
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "url parse error.");
        return NJT_ERROR;
    }
    uri = path->elts;

    if(path->nelts < 4 || uri[3].len != 8 || njt_strncmp(uri[3].data, "password", 8) != 0){
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" url path not allowed");

        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, 
            "%V url path not allowed", &r->uri);

        goto out;
    }

    if(r->method == NJT_HTTP_PUT) {
        if(path->nelts != 4){
            njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
            njt_rpc_result_set_msg(rpc_result, (u_char *)" url path not allowed");

            njt_log_error(NJT_LOG_ERR, r->connection->log, 0, 
                "%V url path not allowed", &r->uri);
            goto out;
        }

        rc = njt_http_read_client_request_body(r, njt_http_auth_api_api_read_data);

        if (rc == NJT_ERROR || rc >= NJT_HTTP_SPECIAL_RESPONSE) {
            if(rpc_result != NULL){
                njt_rpc_result_destroy(rpc_result);
                rpc_result = NULL;
            }
            return rc;
        }

        if(rpc_result != NULL){
            njt_rpc_result_destroy(rpc_result);
            rpc_result = NULL;
        }

        return NJT_DONE;
    } else if(r->method == NJT_HTTP_PATCH) {
        if(path->nelts != 6){
            njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
            njt_rpc_result_set_msg(rpc_result, (u_char *)" url path not allowed");

            njt_log_error(NJT_LOG_ERR, r->connection->log, 0, 
                "%V url path not allowed", &r->uri);
            goto out;
        }

        rc = njt_http_read_client_request_body(r, njt_http_auth_api_api_read_data);
        if (rc == NJT_ERROR || rc >= NJT_HTTP_SPECIAL_RESPONSE) {
            if(rpc_result != NULL){
                njt_rpc_result_destroy(rpc_result);
                rpc_result = NULL;
            }
            return rc;
        }

        if(rpc_result != NULL){
            njt_rpc_result_destroy(rpc_result);
            rpc_result = NULL;
        }
        return NJT_DONE;
    } else if(r->method == NJT_HTTP_DELETE) {
        if(path->nelts != 6){
            njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
            njt_rpc_result_set_msg(rpc_result, (u_char *)" url path not allowed");

            njt_log_error(NJT_LOG_ERR, r->connection->log, 0, 
                "%V url path not allowed", &r->uri);
            goto out;
        }

        //delete
        p = njt_snprintf(buf, NJT_HTTP_AUTH_API_PATH_BUF_SIZE, "auth_basic:%V:%V", &uri[4], &uri[5]);
        if (p == NULL) {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        auth_key.len = p - buf;
        auth_key.data = buf;

        if(NJT_OK != njt_db_kv_get(&auth_key, &auth_passwd)){
            njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
            njt_rpc_result_set_msg(rpc_result, (u_char *)" user is not exist");

            njt_log_error(NJT_LOG_ERR, r->connection->log, 0, 
                "user:[%V:%V] is not exist", &uri[4], &uri[5]);

            goto out;
        }

        if(NJT_OK != njt_db_kv_del(&auth_key)){
            njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
            njt_rpc_result_set_msg(rpc_result, (u_char *)" delete error");

            goto out;
        }
    }else {
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" method not allowed");
    }

out:
    rc = njt_http_auth_api_conf_out_handler(r, rpc_result);

    if(rpc_result != NULL){
        njt_rpc_result_destroy(rpc_result);
    }

    return rc;
}


static njt_int_t
njt_http_auth_api_init_worker(njt_cycle_t *cycle) {
    return NJT_OK;
}

