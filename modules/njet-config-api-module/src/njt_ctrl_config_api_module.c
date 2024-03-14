/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */
#include <njt_core.h>
#include <njt_http.h>
#include "njt_dynlog_module.h"
#include "njt_http_sendmsg_module.h"
#include <njt_str_util.h>
#include <njt_http_util.h>
#include "njt_http_api_register_module.h"

#define MIN_CONFIG_BODY_LEN 2
#define MAX_CONFIG_BODY_LEN 5242880

typedef struct {
    njt_http_request_t **reqs;
    njt_int_t size;
}njt_ctrl_dynlog_main_cf_t;


typedef struct {
    njt_http_request_t *req;
    njt_int_t index;
    njt_ctrl_dynlog_main_cf_t *dlmcf;
}njt_ctrl_dynlog_rpc_ctx_t;

typedef struct {
    njt_int_t code;
    njt_str_t msg;
    void* data;
    unsigned success:1;
}njt_ctrl_dynlog_request_err_ctx_t;


extern njt_module_t njt_ctrl_config_api_module;

static njt_int_t njt_ctrl_dynlog_get_free_index(njt_ctrl_dynlog_main_cf_t *dlmcf){
    njt_int_t i;

    for(i = 0 ; i < dlmcf->size; ++i ){
        if(dlmcf->reqs[i] == NULL){
            return i;
        }
    }
    return -1;
}
static void njt_ctrl_dynlog_cleanup_handler(void *data){
    njt_ctrl_dynlog_rpc_ctx_t *ctx;

    ctx = data;
    if(ctx->dlmcf->size > ctx->index && ctx->dlmcf->reqs[ctx->index] == ctx->req){
        ctx->dlmcf->reqs[ctx->index] = NULL;
    }
}

static int njt_ctrl_dynlog_request_output(njt_http_request_t *r,njt_int_t code, njt_str_t *msg){
    njt_int_t rc;
    njt_buf_t *buf;
    njt_chain_t out;


    if(code == NJT_OK){
        if(msg == NULL || msg->len == 0){
            r->headers_out.status = NJT_HTTP_NO_CONTENT;
        } else{
            r->headers_out.status = NJT_HTTP_OK;
        }
    }else{
        r->headers_out.status = code;
    }
    r->headers_out.content_length_n = 0;
    if(msg != NULL && msg->len > 0){
        njt_str_t type=njt_string("application/json");
        r->headers_out.content_type = type;
        r->headers_out.content_length_n = msg->len;
    }
    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }
    rc = njt_http_send_header(r);
    if(rc == NJT_ERROR || rc > NJT_OK || r->header_only || msg == NULL ||msg->len < 1 ){
        return rc;
    }
    buf = njt_create_temp_buf(r->pool,msg->len);
    if(buf == NULL){
        return NJT_ERROR;
    }
    njt_memcpy(buf->pos,msg->data, msg->len);
    buf->last = buf->pos + msg->len;
    buf->last_buf = 1;
    out.buf = buf;
    out.next = NULL;
    return njt_http_output_filter(r, &out);


}

static int njt_ctrl_dynlog_rpc_msg_handler(njt_dyn_rpc_res_t* res, njt_str_t *msg){
    njt_ctrl_dynlog_rpc_ctx_t *ctx;
    njt_http_request_t *req;
    njt_int_t rc;

    rc = NJT_ERROR;
    njt_str_t err_msg = njt_string("{\n"
                                   "  \"code\": 500,\n"
                                   "  \"msg\": \"rpc timeout\"\n"
                                   "}");
    ctx = res->data;
    njt_log_error(NJT_LOG_INFO,njt_cycle->log, 0, "hand rpc time : %M",njt_current_msec);
    if( ctx->dlmcf->size > ctx->index && ctx->dlmcf->reqs[ctx->index] == ctx->req){
        req =  ctx->req;
        if(res->rc == RPC_RC_OK){
            rc = njt_ctrl_dynlog_request_output(req,NJT_OK,msg);
        }
        if(res->rc == RPC_RC_TIMEOUT){
            rc = njt_ctrl_dynlog_request_output(req,NJT_HTTP_INTERNAL_SERVER_ERROR,&err_msg);
        }
	njt_log_error(NJT_LOG_INFO,njt_cycle->log, 0, " njt_ctrl_dynlog_rpc_msg_handler  r->main->count : %p,%i",req->main,req->main->count);
        njt_http_finalize_request(req,rc);
    }
    return NJT_OK;
}

static njt_int_t njt_ctrl_dynlog_rpc_send(njt_http_request_t *r,njt_str_t *module_name,njt_str_t *msg, int retain){
    njt_ctrl_dynlog_main_cf_t *dlmcf;
    njt_int_t index;
    njt_int_t rc;
    njt_ctrl_dynlog_rpc_ctx_t *ctx;
    njt_pool_cleanup_t *cleanup;

    r->write_event_handler = njt_http_request_empty_handler;
    dlmcf = njt_http_get_module_main_conf(r,njt_ctrl_config_api_module);
    index = njt_ctrl_dynlog_get_free_index(dlmcf);
    if(index == -1 ){
        njt_log_error(NJT_LOG_ERR, r->pool->log, 0, "not find request free index ");
        goto err;
    } else {
        njt_log_error(NJT_LOG_INFO, r->pool->log, 0, "use index :%i ",index);
    }
    ctx = njt_pcalloc(r->pool, sizeof(njt_ctrl_dynlog_rpc_ctx_t));
    if(ctx == NULL){
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "could not alloc mem in function %s", __func__);
        goto err;
    }
    ctx->index = index;
    ctx->req = r;
    ctx->dlmcf = dlmcf;
    cleanup = njt_pool_cleanup_add(r->pool,0);
    if(cleanup == NULL){
        njt_log_error(NJT_LOG_ERR, r->pool->log, 0, "request cleanup error ");
        goto err;
    }
    cleanup->handler = njt_ctrl_dynlog_cleanup_handler;
    cleanup->data = ctx;
    njt_log_error(NJT_LOG_INFO, r->pool->log, 0, "send rpc time : %M",njt_current_msec);
    rc = njt_dyn_rpc(module_name,msg, retain, index, njt_ctrl_dynlog_rpc_msg_handler, ctx);
    if(rc == NJT_OK){
        dlmcf->reqs[index] = r;
    }
    return rc;

    err:
    return NJT_ERROR;
}

/*!
    路由解析
*/
static njt_int_t
njt_http_api_parse_path(njt_http_request_t *r, njt_array_t *path)
{
    u_char                              *p,*end, *sub_p;
    njt_uint_t                          len;
    njt_str_t                           *item;
    njt_http_core_loc_conf_t            *clcf;
    njt_str_t                           uri;

    /*the uri is parsed and delete all the duplidated '/' characters.
     * for example, "/api//7//http///upstreams///////" will be parse to
     * "/api/7/http/upstreams/" already*/

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    uri = r->uri;
    p = uri.data + clcf->name.len;
    end = uri.data + uri.len;
    len = uri.len - clcf->name.len;

    if (len != 0 && *p != '/') {
        return NJT_HTTP_NOT_FOUND;
    }
    if (*p == '/') {
        len --;
        p ++;
    }

    while (len > 0) {
        item = njt_array_push(path);
        if (item == NULL) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "zack: array item of path push error.");
            return NJT_ERROR;
        }

        item->data = p;
        sub_p = (u_char *)njt_strlchr(p, end, '/');

        if (sub_p == NULL || (njt_uint_t)(sub_p - uri.data) > uri.len) {
            item->len = uri.data + uri.len - p;
            break;

        } else {
            item->len = sub_p - p;
        }

        len -= item->len;
        p += item->len;

        if (*p == '/') {
            len --;
            p ++;
        }

    }
    return NJT_OK;
}

static void njt_ctrl_dyn_access_log_read_body(njt_http_request_t *r){
    njt_str_t json_str;
    njt_chain_t *body_chain;
    njt_int_t rc;
    njt_ctrl_dynlog_request_err_ctx_t *err_ctx;
    njt_array_t *path;
    njt_str_t *uri,topic;
    // njt_json_manager json_manager;
    rc = NJT_ERROR;
    path = njt_array_create( r->pool, 4, sizeof(njt_str_t));
    if (path == NULL) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,"array init of path error.");
        goto err;
    }
    rc = njt_http_api_parse_path(r,path);
    if(rc != NJT_OK || path->nelts != 3 ){
        goto err;
    }
    uri = path->elts;


   body_chain = r->request_body->bufs;
    if(body_chain == NULL){
        goto err;
    }
   
    rc = njt_http_util_read_request_body(r, &json_str, MIN_CONFIG_BODY_LEN, MAX_CONFIG_BODY_LEN);
    if(rc!=NJT_OK){
        goto err;
    }

    njt_str_t  key_prf_2 = njt_string("/worker_a/dyn/");
    njt_str_concat(r->pool,topic,key_prf_2,uri[2],return );
    rc = njt_ctrl_dynlog_rpc_send(r,&topic,&json_str, 0);
    
    if(rc == NJT_OK){
        // 在回调中返回
         ++r->main->count;
        goto out;
    }

    err:
    err_ctx = njt_pcalloc(r->pool, sizeof(njt_ctrl_dynlog_request_err_ctx_t));
    err_ctx->success = 0;
    err_ctx->code = rc;
    njt_http_set_ctx(r, err_ctx, njt_ctrl_config_api_module);

    njt_str_t bad_req = njt_string("{\"code\":400,\"msg\":\"Request body should be a valid JSON object and less than 5MB\"}");
    rc= NJT_HTTP_BAD_REQUEST;
    njt_ctrl_dynlog_request_output(r,NJT_HTTP_BAD_REQUEST,&bad_req);

    out:
    njt_http_finalize_request(r, rc);
    return;
}

// /api/v1/config/{module_name}
static njt_int_t njt_dynlog_http_handler(njt_http_request_t *r){
    njt_int_t rc;
    njt_array_t *path;
    njt_str_t msg,*uri,topic;


    njt_str_null(&msg);
    rc= NJT_OK;
    njt_str_t srv_err = njt_string("{\"code\":500,\"msg\":\"server error\"}");
    njt_str_t not_found_err = njt_string("{\"code\":404,\"msg\":\"not found error\"}");
    njt_str_t rpc_pre = njt_string("/worker_a/rpc/");

    path = njt_array_create( r->pool, 4, sizeof(njt_str_t));
    if (path == NULL) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,"array init of path error.");
        goto err;
    }
    rc = njt_http_api_parse_path(r,path);
    if(rc != NJT_OK || path->nelts <= 0 ){
        rc = NJT_HTTP_NOT_FOUND;
        goto out;
    }
    uri = path->elts;
    if(path->nelts < 2 ){
        rc = NJT_HTTP_NOT_FOUND;
        goto out;
    }
    if(r->method == NJT_HTTP_PUT && path->nelts == 3){
        rc = njt_http_read_client_request_body(r, njt_ctrl_dyn_access_log_read_body);
        if (rc == NJT_ERROR || rc >= NJT_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        if (rc == NJT_AGAIN || rc == NJT_OK) {
            return NJT_DONE;
        }
    }
    if(r->method == NJT_HTTP_GET){
        njt_str_t smsg = njt_string("{\"method\":\"GET\"}");
        if(path->nelts == 2){
            njt_str_t  key = njt_string("njt_http_kv_module");
            njt_str_concat(r->pool,topic,rpc_pre,key, goto err);
        } else if(path->nelts == 3){
            njt_str_concat(r->pool,topic,rpc_pre,uri[2], goto err);
        } else {
            rc = NJT_HTTP_NOT_FOUND;
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,"%V not found.",&r->uri);
            goto out;
        }
        rc = njt_ctrl_dynlog_rpc_send(r,&topic,&smsg, 0);
        if(rc != NJT_OK){
 	    //njt_log_error(NJT_LOG_INFO,njt_cycle->log, 0, "error r->main->count : %p,%i,uri=%V,%V",r->main,r->main->count,&r->uri,&r->connection->addr_text);
            goto err;
        }
        ++r->main->count;
	//njt_log_error(NJT_LOG_INFO,njt_cycle->log, 0, "r->main->count : %p,%i,uri=%V,%V",r->main,r->main->count,&r->uri,&r->connection->addr_text);
        return NJT_OK;
    }
    rc = NJT_HTTP_NOT_FOUND;

    out:
    if(rc ==  NJT_HTTP_NOT_FOUND ){
        msg = not_found_err;
    }
    if(rc ==  NJT_HTTP_INTERNAL_SERVER_ERROR ){
        msg = srv_err;
    }
    return njt_ctrl_dynlog_request_output(r,rc,&msg);


    err:

    return njt_ctrl_dynlog_request_output(r,NJT_HTTP_INTERNAL_SERVER_ERROR,&srv_err);
}

static njt_command_t njt_dynlog_module_commands[] = {
        {
                njt_string("config_req_pool_size"),
                NJT_HTTP_MAIN_CONF| NJT_CONF_TAKE1,
                njt_conf_set_num_slot,
                NJT_HTTP_MAIN_CONF_OFFSET,
                offsetof(njt_ctrl_dynlog_main_cf_t,size),
                NULL
        },
        njt_null_command
};

static njt_int_t   njt_ctrl_dynlog_postconfiguration(njt_conf_t *cf){
    njt_ctrl_dynlog_main_cf_t *dlmcf;

    dlmcf = njt_http_conf_get_module_main_conf(cf,njt_ctrl_config_api_module);
    if(dlmcf->size == NJT_CONF_UNSET){
        dlmcf->size = 500;
    }
    dlmcf->reqs = njt_pcalloc(cf->pool, sizeof(njt_http_request_t*)*dlmcf->size);
    if(dlmcf->reqs == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_ctrl_dynlog_postconfiguration alloc mem error");
        return NJT_ERROR;
    }

    // njt_http_core_main_conf_t  *cmcf;
    // njt_http_handler_pt        *h;
    // cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);
    // //njt_http_upstream_api_handler
    // h = njt_array_push(&cmcf->phases[NJT_HTTP_CONTENT_PHASE].handlers);
    // if (h == NULL) {
    //     return NJT_ERROR;
    // }

    // *h = njt_dynlog_http_handler;

    njt_http_api_reg_info_t             h;

    njt_str_t  module_key = njt_string("/v1/config");
    njt_memzero(&h, sizeof(njt_http_api_reg_info_t));
    h.key = &module_key;
    h.handler = njt_dynlog_http_handler;
    njt_http_api_module_reg_handler(&h);

    return NJT_OK;
}

static void * njt_ctrl_dynlog_create_main_conf(njt_conf_t *cf){
    njt_ctrl_dynlog_main_cf_t *dlmcf;
    dlmcf = njt_pcalloc(cf->pool,sizeof (njt_ctrl_dynlog_main_cf_t));
    if(dlmcf == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_ctrl_dynlog_create_main_conf alloc mem error");
        return NULL;
    }
    dlmcf->size = NJT_CONF_UNSET;
    return dlmcf;
}
static njt_http_module_t njt_ctrl_dynlog_module_ctx = {
        NULL,                                   /* preconfiguration */
        njt_ctrl_dynlog_postconfiguration,     /* postconfiguration */

        njt_ctrl_dynlog_create_main_conf,      /* create main configuration */
        NULL,                                  /* init main configuration */

        NULL,                                  /* create server configuration */
        NULL,                                  /* merge server configuration */

        NULL,                                  /* create location configuration */
        NULL                                   /* merge location configuration */
};

njt_module_t njt_ctrl_config_api_module = {
        NJT_MODULE_V1,
        &njt_ctrl_dynlog_module_ctx,        /* module context */
        njt_dynlog_module_commands,          /* module directives */
        NJT_HTTP_MODULE,                        /* module type */
        NULL,                                   /* init master */
        NULL,                                   /* init module */
        NULL,                                   /* init process */
        NULL,                                   /* init thread */
        NULL,                                   /* exit thread */
        NULL,                                   /* exit process */
        NULL,                                   /* exit master */
        NJT_MODULE_V1_PADDING
};
