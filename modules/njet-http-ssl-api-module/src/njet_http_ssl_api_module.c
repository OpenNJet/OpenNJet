/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */
#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_stream.h>
#include <njt_json_api.h>
#include <njt_str_util.h>
#include <math.h>
#include <njt_http_kv_module.h>
#include <njt_http_sendmsg_module.h>
#include <njt_rpc_result_util.h>
#include <njt_http_util.h>

#include "njt_http_dyn_ssl_api_parser.h"


#define MIN_CONFIG_BODY_LEN 2
#define MAX_CONFIG_BODY_LEN 5242880

extern njt_uint_t njt_worker;
extern njt_module_t  njt_http_rewrite_module;
extern njt_cycle_t *njet_master_cycle;

static void
njt_http_dyn_ssl_read_data(njt_http_request_t *r);

static njt_int_t
njt_http_dyn_ssl_handler(njt_http_request_t *r);

static njt_int_t
njt_http_dyn_ssl_init_worker(njt_cycle_t *cycle);

static void *
njt_http_dyn_ssl_create_loc_conf(njt_conf_t *cf);

static char *njt_http_dyn_ssl_merge_loc_conf(njt_conf_t *cf,
                                              void *parent, void *child);

static void *
njt_http_dyn_ssl_create_main_conf(njt_conf_t *cf);

static njt_int_t
njt_http_dyn_ssl_init(njt_conf_t *cf);

extern njt_int_t
njt_http_init_static_location_trees(njt_conf_t *cf,
                                    njt_http_core_loc_conf_t *pclcf);

extern njt_int_t njt_http_init_locations(njt_conf_t *cf,
                                         njt_http_core_srv_conf_t *cscf, njt_http_core_loc_conf_t *pclcf);

static njt_int_t njt_http_dyn_ssl_rpc_send(njt_http_request_t *r,njt_str_t *module_name,njt_str_t *msg, int retain);

static int njt_http_dyn_ssl_request_output(njt_http_request_t *r,njt_int_t code, njt_str_t *msg);

static char *
njt_http_dyn_ssl_api(njt_conf_t *cf, njt_command_t *cmd, void *conf);

typedef struct njt_http_dyn_ssl_ctx_s {
} njt_http_dyn_ssl_ctx_t, njt_stream_http_dyn_ssl_ctx_t;


typedef struct njt_http_dyn_ssl_main_conf_s {  //njt_http_dyn_ssl_main_cf_t
	njt_http_request_t **reqs;
    njt_int_t size;
} njt_http_dyn_ssl_main_conf_t;

typedef struct njt_http_dyn_ssl_loc_conf_s {  //njt_http_dyn_ssl_main_cf_t
    njt_flag_t dyn_ssl_enable;
}njt_http_dyn_ssl_loc_conf_t;


typedef struct {
    njt_http_request_t *req;
    njt_int_t index;
    njt_http_dyn_ssl_main_conf_t *dlmcf;
}njt_http_dyn_ssl_rpc_ctx_t;


typedef struct {
    njt_int_t code;
    njt_str_t msg;
    void* data;
    unsigned success:1;
}njt_http_ssl_request_err_ctx_t;


static njt_command_t njt_http_dyn_ssl_commands[] = {
        {
                njt_string("dyn_ssl_api"),
                NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_ANY,
                njt_http_dyn_ssl_api,
                NJT_HTTP_LOC_CONF_OFFSET,
                offsetof(njt_http_dyn_ssl_loc_conf_t, dyn_ssl_enable),
                NULL
        },
        njt_null_command
};


static njt_http_module_t njt_http_ssl_api_module_ctx = {
        NULL,                              /* preconfiguration */
        njt_http_dyn_ssl_init,                              /* postconfiguration */

        njt_http_dyn_ssl_create_main_conf,                              /* create main configuration */
        NULL,                              /* init main configuration */

        NULL,                              /* create server configuration */
        NULL,                              /* merge server configuration */

        njt_http_dyn_ssl_create_loc_conf, /* create location configuration */
        njt_http_dyn_ssl_merge_loc_conf   /* merge location configuration */
};

njt_module_t njt_http_ssl_api_module = {
        NJT_MODULE_V1,
        &njt_http_ssl_api_module_ctx, /* module context */
        njt_http_dyn_ssl_commands,    /* module directives */
        NJT_HTTP_MODULE,                    /* module type */
        NULL,                               /* init master */
        NULL,                               /* init module */
        njt_http_dyn_ssl_init_worker, /* init process */
        NULL,                               /* init thread */
        NULL,                               /* exit thread */
        NULL,                               /* exit process */
        NULL,                               /* exit master */
        NJT_MODULE_V1_PADDING
};


static char *
njt_http_dyn_ssl_api(njt_conf_t *cf, njt_command_t *cmd, void *conf) {
    
	njt_http_dyn_ssl_loc_conf_t   *clcf = conf;

    clcf->dyn_ssl_enable = 1;
    return NJT_CONF_OK;
}


static njt_int_t
njt_http_dyn_ssl_init(njt_conf_t *cf) {
    njt_http_core_main_conf_t *cmcf;
    njt_http_handler_pt *h;

	 njt_http_dyn_ssl_main_conf_t *dlmcf;

    dlmcf = njt_http_conf_get_module_main_conf(cf,njt_http_ssl_api_module);
    if(dlmcf == NULL){
        return NJT_ERROR;
    }

    if(dlmcf->size == NJT_CONF_UNSET){
        dlmcf->size = 500;
    }

    dlmcf->reqs = njt_pcalloc(cf->pool, sizeof(njt_http_request_t*)*dlmcf->size);
    if(dlmcf->reqs == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_http_dyn_ssl_postconfiguration alloc mem error");
        return NJT_ERROR;
    }

    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);
	if(cmcf == NULL) {
		return NJT_ERROR;
	}
    //njt_http_dyn_ssl_handler
    h = njt_array_push(&cmcf->phases[NJT_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_http_dyn_ssl_handler;
    return NJT_OK;
}


static void *
njt_http_dyn_ssl_create_loc_conf(njt_conf_t *cf) {
    //ssize_t size;
    //njt_str_t zone = njt_string("api_dy_server");
    njt_http_dyn_ssl_loc_conf_t *uclcf;
    //size = (ssize_t)(10 * njt_pagesize);
    uclcf = njt_pcalloc(cf->pool, sizeof(njt_http_dyn_ssl_loc_conf_t));
    if (uclcf == NULL) {
        njt_log_error(NJT_LOG_ERR, cf->log, 0, "malloc uclcf eror");
        return NULL;
    }
    uclcf->dyn_ssl_enable = NJT_CONF_UNSET;
    return uclcf;
}

static void *
njt_http_dyn_ssl_create_main_conf(njt_conf_t *cf) {
    //ssize_t size;
    //njt_str_t zone = njt_string("api_dy_server");

    njt_http_dyn_ssl_main_conf_t *uclcf;

    //size = (ssize_t)(10 * njt_pagesize);
    uclcf = njt_pcalloc(cf->pool, sizeof(njt_http_dyn_ssl_main_conf_t));
    if (uclcf == NULL) {
        njt_log_error(NJT_LOG_ERR, cf->log, 0, "malloc njt_http_dyn_ssl_main_conf_t eror");
        return NULL;
    }
	uclcf->size = NJT_CONF_UNSET;
    return uclcf;
}


static char *njt_http_dyn_ssl_merge_loc_conf(njt_conf_t *cf,
                                              void *parent, void *child) {
    njt_http_dyn_ssl_loc_conf_t *prev = parent;
    njt_http_dyn_ssl_loc_conf_t *conf = child;

    njt_conf_merge_value(conf->dyn_ssl_enable, prev->dyn_ssl_enable, 0);

    return NJT_CONF_OK;
}


static int njt_http_dyn_ssl_request_output(njt_http_request_t *r,njt_int_t code, njt_str_t *msg){
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

// static njt_int_t
// njt_http_api_parse_path(njt_http_request_t *r, njt_array_t *path)
// {
//     u_char                              *p, *sub_p;
//     njt_uint_t                          len;
//     njt_str_t                           *item;
//     njt_http_core_loc_conf_t            *clcf;
//     njt_str_t                           uri;

//     /*the uri is parsed and delete all the duplidated '/' characters.
//      * for example, "/api//7//http///upstreams///////" will be parse to
//      * "/api/7/http/upstreams/" already*/

//     clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

//     uri = r->uri;
//     p = uri.data + clcf->name.len;
//     len = uri.len - clcf->name.len;

//     if (len != 0 && *p != '/') {
//         return NJT_HTTP_NOT_FOUND;
//     }
//     if (*p == '/') {
//         len --;
//         p ++;
//     }

//     while (len > 0) {
//         item = njt_array_push(path);
//         if (item == NULL) {
//             njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
//                           "zack: array item of path push error.");
//             return NJT_ERROR;
//         }

//         item->data = p;
//         sub_p = (u_char *)njt_strchr(p, '/');

//         if (sub_p == NULL || (njt_uint_t)(sub_p - uri.data) > uri.len) {
//             item->len = uri.data + uri.len - p;
//             break;

//         } else {
//             item->len = sub_p - p;
//         }

//         len -= item->len;
//         p += item->len;

//         if (*p == '/') {
//             len --;
//             p ++;
//         }

//     }
//     return NJT_OK;
// }

static njt_int_t
njt_http_dyn_ssl_handler(njt_http_request_t *r) {
    njt_int_t                       rc = NJT_OK;
    njt_http_dyn_ssl_loc_conf_t     *loc;
    // njt_array_t                     *path;
    njt_str_t                       msg,topic;
    
    loc = njt_http_get_module_loc_conf(r, njt_http_ssl_api_module);
    if (loc && loc->dyn_ssl_enable) {
        //printf("11");
    } else {
        //printf("NJT_DECLINED");
        return NJT_DECLINED;
    }

    njt_str_null(&msg);
    njt_str_t srv_err = njt_string("{\"code\":500,\"msg\":\"server error\"}");
    // njt_str_t not_found_err = njt_string("{\"code\":404,\"msg\":\"not found error\"}");
    // njt_str_t rpc_pre = njt_string("/worker_a/rpc/");
    // path = njt_array_create( r->pool, 4, sizeof(njt_str_t));
    // if (path == NULL) {
    //     njt_log_error(NJT_LOG_ERR, r->connection->log, 0,"array init of path error.");
    //     goto err;
    // }
    // rc = njt_http_api_parse_path(r, path);
    // if(rc != NJT_OK || path->nelts <= 0 ){
    //     rc = NJT_HTTP_NOT_FOUND;
    //     goto out;
    // }
    // uri = path->elts;
    // // 增加版本2  www
    // if(path->nelts != 1){
    //     rc = NJT_HTTP_NOT_FOUND;
    //     goto out;
    // }

    if(r->method == NJT_HTTP_PUT){
        rc = njt_http_read_client_request_body(r, njt_http_dyn_ssl_read_data);
        if (rc == NJT_ERROR || rc >= NJT_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        if (rc == NJT_AGAIN || rc == NJT_OK) {
            return NJT_DONE;
        }
    }

    if(r->method == NJT_HTTP_GET){
        njt_str_t smsg = njt_string("{\"method\":\"GET\"}");
        // njt_str_concat(r->pool,topic, rpc_pre, uri[0], goto err);
        njt_str_set(&topic, "/worker_a/rpc/ssl");

        rc = njt_http_dyn_ssl_rpc_send(r, &topic, &smsg, 0);
        if(rc != NJT_OK){
            goto err;
        }
        ++r->main->count;
        return NJT_DONE;
    }
    rc = NJT_HTTP_NOT_FOUND;

    // out:
    // if(rc ==  NJT_HTTP_NOT_FOUND ){
    //     msg = not_found_err;
    // }
    // if(rc ==  NJT_HTTP_INTERNAL_SERVER_ERROR ){
    //     msg = srv_err;
    // }
    // return njt_http_dyn_ssl_request_output(r,rc,&msg);

    err:
    return njt_http_dyn_ssl_request_output(r, NJT_HTTP_INTERNAL_SERVER_ERROR, &srv_err);
}


static njt_int_t
njt_http_dyn_ssl_init_worker(njt_cycle_t *cycle) {

    return NJT_OK;
}

static njt_int_t njt_http_dyn_ssl_get_free_index(njt_http_dyn_ssl_main_conf_t *dlmcf){
    njt_int_t i;

    for(i = 0 ; i < dlmcf->size; ++i ){
        if(dlmcf->reqs[i] == NULL){
            return i;
        }
    }
    return -1;
}

static void njt_http_dyn_ssl_cleanup_handler(void *data){
    njt_http_dyn_ssl_rpc_ctx_t *ctx;

    ctx = data;
    if(ctx->dlmcf->size > ctx->index && ctx->dlmcf->reqs[ctx->index] == ctx->req){
        ctx->dlmcf->reqs[ctx->index] = NULL;
    }
}


static int njt_http_dyn_ssl_rpc_msg_handler(njt_dyn_rpc_res_t* res, njt_str_t *msg){
    njt_http_dyn_ssl_rpc_ctx_t          *ctx;
    njt_http_request_t                  *req;
    njt_int_t                           rc;

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
            rc = njt_http_dyn_ssl_request_output(req,NJT_OK,msg);
        }
        if(res->rc == RPC_RC_TIMEOUT){
            rc = njt_http_dyn_ssl_request_output(req,NJT_HTTP_INTERNAL_SERVER_ERROR,&err_msg);
        }
        njt_http_finalize_request(req,rc);
    }

    return NJT_OK;
}


static njt_int_t njt_http_dyn_ssl_rpc_send(njt_http_request_t *r,njt_str_t *module_name,njt_str_t *msg, int retain){
    njt_http_dyn_ssl_main_conf_t    *dlmcf;
    njt_int_t                       index;
    njt_int_t                       rc;
    njt_http_dyn_ssl_rpc_ctx_t      *ctx;
    njt_pool_cleanup_t              *cleanup;
    r->write_event_handler = njt_http_request_empty_handler;
    dlmcf = njt_http_get_module_main_conf(r,njt_http_ssl_api_module);
    if(dlmcf == NULL){
        goto err;
    }
    index = njt_http_dyn_ssl_get_free_index(dlmcf);
    if(index == -1 ){
        njt_log_error(NJT_LOG_ERR, r->pool->log, 0, "not find request free index ");
        goto err;
    } else {
        njt_log_error(NJT_LOG_INFO, r->pool->log, 0, "use index :%i ",index);
    }
    ctx = njt_pcalloc(r->pool, sizeof(njt_http_dyn_ssl_rpc_ctx_t));
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
    cleanup->handler = njt_http_dyn_ssl_cleanup_handler;
    cleanup->data = ctx;
    njt_log_error(NJT_LOG_INFO, r->pool->log, 0, "send rpc time : %M",njt_current_msec);
    rc = njt_dyn_rpc(module_name,msg, retain, index, njt_http_dyn_ssl_rpc_msg_handler, ctx);
    if(rc == NJT_OK){
        dlmcf->reqs[index] = r;
    }
    return rc;

    err:
    return NJT_ERROR;
}


static void
njt_http_dyn_ssl_read_data(njt_http_request_t *r){
	njt_str_t                           json_str;
    njt_int_t                           rc;
    njt_rpc_result_t                    *rpc_result = NULL;
    dyn_ssl_api_t                       *api_data = NULL;
    u_char                              *p;
    njt_uint_t                           i;
    njt_pool_t                          *pool = NULL;
    uint32_t                            crc32;
    uint32_t						    topic_len = NJT_INT64_LEN  + 2 + 256; ///ins/ssl/l_
    njt_str_t							topic_name;
    njt_http_ssl_request_err_ctx_t      *err_ctx;
    js2c_parse_error_t                  err_info;
    njt_str_t                           *serverName;
    njt_str_t                           *listen_str;
    

    rpc_result = njt_rpc_result_create();
    if(rpc_result == NULL){
       njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "rpc_result allocate null");
       rc = NJT_ERROR;
       goto out;
    }

    rc = njt_http_util_read_request_body(r, &json_str, MIN_CONFIG_BODY_LEN, MAX_CONFIG_BODY_LEN);
    if(rc!=NJT_OK){
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "request_body error in function %s", __func__);
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" request_body error");
        goto err;
    }
	
	if(json_str.len < 2 ){
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "json len is too short in function %s", __func__);
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" json len is too short");
        rc = NJT_ERROR;
        goto err;
    }


    pool = njt_create_pool(njt_pagesize,njt_cycle->log);
    if(pool == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_http_ssl_change_handler create pool error");
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_MEM_ALLOC);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" update handler create pool error");
        rc = NJT_ERROR;

        goto err;
    }

    njt_rpc_result_set_code(rpc_result,NJT_RPC_RSP_SUCCESS);
    api_data = json_parse_dyn_ssl_api(pool, &json_str, &err_info);
    if (api_data == NULL)
    {
        njt_log_error(NJT_LOG_ERR, pool->log, 0, 
                "json_parse_dyn_ssl err: %V",  &err_info.err_str);
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_JSON);
        njt_rpc_result_set_msg2(rpc_result, &err_info.err_str);

        rc = NJT_ERROR;
        goto err;
    }

    //check format
    if(!api_data->is_cert_info_set || api_data->cert_info->certificate.len < 1 
        || api_data->cert_info->certificateKey.len < 1){
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, pool->log, 0,
                       "cert or cert key is empty in function %s", __func__);
        njt_rpc_result_set_code(rpc_result,NJT_RPC_RSP_ERR_JSON);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" cert or cert key is empty");
        rc = NJT_ERROR;
 
        goto err;
    }

	njt_crc32_init(crc32);
	for (i = 0; i < api_data->serverNames->nelts; i++){
        serverName = get_dyn_ssl_api_serverNames_item(api_data->serverNames, i);
        if(serverName->len > 0){
            njt_crc32_update(&crc32, serverName->data, serverName->len);
        }
	}

	for(i = 0; i < api_data->listens->nelts; i++){
        listen_str = get_dyn_ssl_api_listens_item(api_data->listens, i);
        if(listen_str->len > 0){
            njt_crc32_update(&crc32, listen_str->data, listen_str->len);
        }
	}

    if(api_data->cert_info->cert_type == DYN_SSL_API_CERT_INFO_CERT_TYPE_NTLS){
        njt_crc32_update(&crc32, (u_char*)"ntls", 4);
    }else if(api_data->cert_info->cert_type == DYN_SSL_API_CERT_INFO_CERT_TYPE_RSA){
        njt_crc32_update(&crc32, (u_char *)"rsa", 3);
    }else{
        njt_crc32_update(&crc32, (u_char *)"ecc", 3);
    }

	njt_crc32_final(crc32);

	topic_name.data = njt_pcalloc(r->pool,topic_len);
	if (topic_name.data == NULL) {
        njt_log_debug1(NJT_LOG_ERR, pool->log, 0,
                       "topic_name njt_pcalloc error in function %s", __func__);
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_MEM_ALLOC);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" topic_name njt_pcalloc error");
        rc = NJT_ERROR;
        goto err;
    }
	
	njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                      " dyn ssl, type:[%V]  crc32:%ui", &api_data->type, crc32);    

	if(api_data->type == DYN_SSL_API_TYPE_DEL){
		p = njt_snprintf(topic_name.data,topic_len,"/ins/ssl/l_%ui",crc32);
        topic_name.len = p - topic_name.data;

        //just delete from broker or db
        njt_str_t msg = njt_string("");
        njt_dyn_sendmsg(&topic_name, &msg, 0);
		njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                      " just delete ssl cert from broker, topic:%V", &topic_name);

        rc = NJT_HTTP_OK;
        njt_str_t httpmsg = njt_string("{\"code\":200,\"msg\":\" del success\"}");
        njt_http_dyn_ssl_request_output(r, NJT_HTTP_OK, &httpmsg);

        goto out;
	} else {
		// p = njt_snprintf(topic_name.data,topic_len,"/worker_a/ins/ssl/l_%ui",crc32);
        p = njt_snprintf(topic_name.data,topic_len,"/worker_a/ins/ssl/l_%ui",crc32);
	}

	topic_name.len = p - topic_name.data;
	rc = njt_http_dyn_ssl_rpc_send(r, &topic_name, &json_str, 0);
	if(rc == NJT_OK) {
		++r->main->count;
	}
	
    goto out;

	
err:
    err_ctx = njt_pcalloc(r->pool, sizeof(njt_http_ssl_request_err_ctx_t));
    err_ctx->success = 0;
    err_ctx->code = rc;
    njt_http_set_ctx(r, err_ctx, njt_http_ssl_api_module);

    njt_str_t bad_req = njt_string("{\"code\":400,\"msg\":\"read body error\"}");
    if(rpc_result != NULL){
        njt_rpc_result_to_json_str(rpc_result,&bad_req);
    }
    rc = NJT_HTTP_BAD_REQUEST;
    njt_http_dyn_ssl_request_output(r, NJT_HTTP_BAD_REQUEST, &bad_req);

out:
    if(pool != NULL){
        njt_destroy_pool(pool);
        pool = NULL;
    }
	njt_http_finalize_request(r, rc);
    if(rpc_result){
        njt_rpc_result_destroy(rpc_result);
        rpc_result = NULL;
    }

    return;
}










