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

#include "njt_http_dyn_range_api_parser.h"
#include "njt_http_api_register_module.h"


#define MIN_CONFIG_BODY_LEN 2
#define MAX_CONFIG_BODY_LEN 5242880

extern njt_uint_t njt_worker;
extern njt_module_t  njt_http_rewrite_module;
extern njt_cycle_t *njet_master_cycle;

static void
njt_dyn_range_read_data(njt_http_request_t *r);

static njt_int_t
njt_dyn_range_handler(njt_http_request_t *r);

static njt_int_t
njt_dyn_range_init_worker(njt_cycle_t *cycle);

static void *
njt_dyn_range_create_main_conf(njt_conf_t *cf);

static njt_int_t
njt_dyn_range_init(njt_conf_t *cf);

extern njt_int_t
njt_http_init_static_location_trees(njt_conf_t *cf,
                                    njt_http_core_loc_conf_t *pclcf);

extern njt_int_t njt_http_init_locations(njt_conf_t *cf,
                                         njt_http_core_srv_conf_t *cscf, njt_http_core_loc_conf_t *pclcf);

static njt_int_t njt_dyn_range_rpc_send(njt_http_request_t *r,njt_str_t *module_name,njt_str_t *msg, int retain);

static int njt_dyn_range_request_output(njt_http_request_t *r,njt_int_t code, njt_str_t *msg);

typedef struct njt_dyn_range_ctx_s {
} njt_dyn_range_ctx_t, njt_stream_dyn_range_ctx_t;


typedef struct njt_dyn_range_main_conf_s {  //njt_dyn_range_main_cf_t
	njt_http_request_t **reqs;
    njt_int_t size;
} njt_dyn_range_main_conf_t;


typedef struct {
    njt_http_request_t *req;
    njt_int_t index;
    njt_dyn_range_main_conf_t *dlmcf;
}njt_dyn_range_rpc_ctx_t;


typedef struct {
    njt_int_t code;
    njt_str_t msg;
    void* data;
    unsigned success:1;
}njt_http_range_request_err_ctx_t;


static njt_http_module_t njt_http_range_api_module_ctx = {
        NULL,                              /* preconfiguration */
        njt_dyn_range_init,                /* postconfiguration */
        njt_dyn_range_create_main_conf,    /* create main configuration */
        NULL,                              /* init main configuration */
        NULL,                              /* create server configuration */
        NULL,                              /* merge server configuration */
        NULL,                              /* create location configuration */
        NULL                               /* merge location configuration */
};


njt_module_t njt_http_range_api_module = {
        NJT_MODULE_V1,
        &njt_http_range_api_module_ctx, /* module context */
        NULL,                               /* module directives */
        NJT_HTTP_MODULE,                    /* module type */
        NULL,                               /* init master */
        NULL,                               /* init module */
        njt_dyn_range_init_worker, /* init process */
        NULL,                               /* init thread */
        NULL,                               /* exit thread */
        NULL,                               /* exit process */
        NULL,                               /* exit master */
        NJT_MODULE_V1_PADDING
};


static njt_int_t
njt_dyn_range_init(njt_conf_t *cf) {
    njt_http_api_reg_info_t             h;
	njt_dyn_range_main_conf_t           *dlmcf;

    dlmcf = njt_http_conf_get_module_main_conf(cf,njt_http_range_api_module);
    if(dlmcf == NULL){
        return NJT_ERROR;
    }

    if(dlmcf->size == NJT_CONF_UNSET){
        dlmcf->size = 500;
    }

    dlmcf->reqs = njt_pcalloc(cf->pool, sizeof(njt_http_request_t*)*dlmcf->size);
    if(dlmcf->reqs == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_range_postconfiguration alloc mem error");
        return NJT_ERROR;
    }

    njt_str_t  module_key = njt_string("/v1/range");
    njt_memzero(&h, sizeof(njt_http_api_reg_info_t));
    h.key = &module_key;
    h.handler = njt_dyn_range_handler;
    njt_http_api_module_reg_handler(&h);

    return NJT_OK;
}


static void *
njt_dyn_range_create_main_conf(njt_conf_t *cf) {
    njt_dyn_range_main_conf_t *uclcf;

    uclcf = njt_pcalloc(cf->pool, sizeof(njt_dyn_range_main_conf_t));
    if (uclcf == NULL) {
        njt_log_error(NJT_LOG_ERR, cf->log, 0, "malloc njt_dyn_range_main_conf_t eror");
        return NULL;
    }
	uclcf->size = NJT_CONF_UNSET;
    return uclcf;
}


static int njt_dyn_range_request_output(njt_http_request_t *r,njt_int_t code, njt_str_t *msg){
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


static njt_int_t
njt_dyn_range_handler(njt_http_request_t *r) {
    njt_int_t                       rc = NJT_OK;
    njt_str_t                       msg,topic;

    njt_str_null(&msg);
    njt_str_t srv_err = njt_string("{\"code\":500,\"msg\":\"server error\"}");

    if(r->method == NJT_HTTP_PUT){
        rc = njt_http_read_client_request_body(r, njt_dyn_range_read_data);
        if (rc == NJT_ERROR || rc >= NJT_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        if (rc == NJT_AGAIN || rc == NJT_OK) {
            return NJT_DONE;
        }
    }

    if(r->method == NJT_HTTP_GET){
        njt_str_t smsg = njt_string("{\"method\":\"GET\"}");
        njt_str_set(&topic, "/worker_a/rpc/range");

        rc = njt_dyn_range_rpc_send(r, &topic, &smsg, 0);
        if(rc != NJT_OK){
            goto err;
        }
        ++r->main->count;
        return NJT_DONE;
    }
    rc = NJT_HTTP_NOT_FOUND;

    err:
    return njt_dyn_range_request_output(r, NJT_HTTP_INTERNAL_SERVER_ERROR, &srv_err);
}


static njt_int_t
njt_dyn_range_init_worker(njt_cycle_t *cycle) {

    return NJT_OK;
}

static njt_int_t njt_dyn_range_get_free_index(njt_dyn_range_main_conf_t *dlmcf){
    njt_int_t i;

    for(i = 0 ; i < dlmcf->size; ++i ){
        if(dlmcf->reqs[i] == NULL){
            return i;
        }
    }
    return -1;
}

static void njt_dyn_range_cleanup_handler(void *data){
    njt_dyn_range_rpc_ctx_t *ctx;

    ctx = data;
    if(ctx->dlmcf->size > ctx->index && ctx->dlmcf->reqs[ctx->index] == ctx->req){
        ctx->dlmcf->reqs[ctx->index] = NULL;
    }
}


static int njt_dyn_range_rpc_msg_handler(njt_dyn_rpc_res_t* res, njt_str_t *msg){
    njt_dyn_range_rpc_ctx_t          *ctx;
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
            rc = njt_dyn_range_request_output(req,NJT_OK,msg);
        }
        if(res->rc == RPC_RC_TIMEOUT){
            rc = njt_dyn_range_request_output(req,NJT_HTTP_INTERNAL_SERVER_ERROR,&err_msg);
        }
        njt_http_finalize_request(req,rc);
    }

    return NJT_OK;
}


static njt_int_t njt_dyn_range_rpc_send(njt_http_request_t *r,njt_str_t *module_name,njt_str_t *msg, int retain){
    njt_dyn_range_main_conf_t    *dlmcf;
    njt_int_t                       index;
    njt_int_t                       rc;
    njt_dyn_range_rpc_ctx_t      *ctx;
    njt_pool_cleanup_t              *cleanup;
    
    r->write_event_handler = njt_http_request_empty_handler;
    dlmcf = njt_http_get_module_main_conf(r,njt_http_range_api_module);
    if(dlmcf == NULL){
        goto err;
    }
    index = njt_dyn_range_get_free_index(dlmcf);
    if(index == -1 ){
        njt_log_error(NJT_LOG_ERR, r->pool->log, 0, "not find request free index ");
        goto err;
    } else {
        njt_log_error(NJT_LOG_INFO, r->pool->log, 0, "use index :%i ",index);
    }
    ctx = njt_pcalloc(r->pool, sizeof(njt_dyn_range_rpc_ctx_t));
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
    cleanup->handler = njt_dyn_range_cleanup_handler;
    cleanup->data = ctx;
    njt_log_error(NJT_LOG_INFO, r->pool->log, 0, "send rpc time : %M",njt_current_msec);
    rc = njt_dyn_rpc(module_name,msg, retain, index, njt_dyn_range_rpc_msg_handler, ctx);
    if(rc == NJT_OK){
        dlmcf->reqs[index] = r;
    }
    return rc;

    err:
    return NJT_ERROR;
}


static void
njt_dyn_range_read_data(njt_http_request_t *r){
	njt_str_t                           json_str;
    njt_int_t                           rc;
    njt_rpc_result_t                    *rpc_result = NULL;
    dyn_range_api_t                     *api_data = NULL;
    u_char                              *p;
    njt_pool_t                          *pool = NULL;
    uint32_t                            crc32;
    uint32_t						    topic_len = NJT_INT64_LEN  + 2 + 256; ///ins/range/l_
    njt_str_t							topic_name;
    njt_http_range_request_err_ctx_t    *err_ctx;
    js2c_parse_error_t                  err_info;
    u_char                              dst_port_buf[100];
    u_char                              *end;


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
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_http_range_change_handler create pool error");
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_MEM_ALLOC);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" update handler create pool error");
        rc = NJT_ERROR;

        goto err;
    }

    njt_rpc_result_set_code(rpc_result,NJT_RPC_RSP_SUCCESS);
    api_data = json_parse_dyn_range_api(pool, &json_str, &err_info);
    if (api_data == NULL)
    {
        njt_log_error(NJT_LOG_ERR, pool->log, 0, 
                "json_parse_dyn_range err: %V",  &err_info.err_str);
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_JSON);
        njt_rpc_result_set_msg2(rpc_result, &err_info.err_str);

        rc = NJT_ERROR;
        goto err;
    }

    if (!api_data->is_action_set || !api_data->is_type_set 
        || !api_data->is_src_ports_set || !api_data->is_dst_port_set) {
        njt_log_error(NJT_LOG_ERR, pool->log, 0,
                       "parameters error, action or type or src_ports or dst_port is empty");

        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_JSON);
        njt_rpc_result_set_msg(rpc_result, 
            (u_char *)" parameters error, action or type or src_ports or dst_port is empty");

        rc = NJT_ERROR;
        goto err;
    }


    njt_crc32_init(crc32);

    if(api_data->type == DYN_RANGE_API_TYPE_TCP){
        njt_crc32_update(&crc32, (u_char*)"tcp", 3);
    }else if(api_data->type == DYN_RANGE_API_TYPE_UDP){
        njt_crc32_update(&crc32, (u_char*)"udp", 3);
    }else{
        njt_crc32_update(&crc32, (u_char*)"tcp", 3);
    }

    //falimy
    if(api_data->is_family_set){
        if(DYN_RANGE_API_FAMILY_IPV_4 == api_data->family){
            njt_crc32_update(&crc32, (u_char*)"ipv4", 4);
        }else{
            njt_crc32_update(&crc32, (u_char*)"ipv6", 4);
        }
    }else{
        njt_crc32_update(&crc32, (u_char*)"ipv4", 4);
    }
    njt_crc32_update(&crc32, api_data->src_ports.data, api_data->src_ports.len);
    njt_memzero(dst_port_buf, 100);
    end = njt_snprintf(dst_port_buf, 100, "%d", api_data->dst_port);
    njt_crc32_update(&crc32, dst_port_buf, end - dst_port_buf);

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
            " dyn range, type:%d family:%d crc32:%ui", api_data->type, api_data->family, crc32);    

    p = njt_snprintf(topic_name.data,topic_len,"/worker_a/ins/range/l_%ui",crc32);
	topic_name.len = p - topic_name.data;
	rc = njt_dyn_range_rpc_send(r, &topic_name, &json_str, 1);
	if(rc == NJT_OK) {
		++r->main->count;
	}
	
    goto out;

	
err:
    err_ctx = njt_pcalloc(r->pool, sizeof(njt_http_range_request_err_ctx_t));
    err_ctx->success = 0;
    err_ctx->code = rc;
    njt_http_set_ctx(r, err_ctx, njt_http_range_api_module);

    njt_str_t bad_req = njt_string("{\"code\":400,\"msg\":\"read body error\"}");
    if(rpc_result != NULL){
        njt_rpc_result_to_json_str(rpc_result,&bad_req);
    }
    rc = NJT_HTTP_BAD_REQUEST;
    njt_dyn_range_request_output(r, NJT_HTTP_BAD_REQUEST, &bad_req);

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