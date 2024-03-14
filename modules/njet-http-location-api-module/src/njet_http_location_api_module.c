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
#include <math.h>
#include <njt_http_kv_module.h>
#include <njt_http_sendmsg_module.h>
#include <njt_http_location_module.h>
#include <njt_rpc_result_util.h>
#include <njt_http_util.h>
#define LOCATION_MIN_BODY_LEN 10  
#define LOCATION_MAX_BODY_LEN 5242880
#include "njt_http_api_register_module.h"

extern njt_uint_t njt_worker;
extern njt_module_t  njt_http_rewrite_module;
extern njt_cycle_t *njet_master_cycle;

static void
njt_http_location_read_data(njt_http_request_t *r);


static njt_int_t
njt_http_location_handler(njt_http_request_t *r);



static njt_int_t
njt_http_location_init_worker(njt_cycle_t *cycle);

static void *
njt_http_location_create_loc_conf(njt_conf_t *cf);

static char *njt_http_location_merge_loc_conf(njt_conf_t *cf,
                                              void *parent, void *child);

static void *
njt_http_location_create_main_conf(njt_conf_t *cf);

static njt_int_t
njt_http_location_init(njt_conf_t *cf);


extern njt_int_t njt_http_init_locations(njt_conf_t *cf,
                                         njt_http_core_srv_conf_t *cscf, njt_http_core_loc_conf_t *pclcf);


typedef struct njt_http_location_ctx_s {
} njt_http_location_ctx_t, njt_stream_http_location_ctx_t;


typedef struct njt_http_location_main_conf_s {  //njt_http_location_main_cf_t
	njt_http_request_t **reqs;
    njt_int_t size;
} njt_http_location_main_conf_t;



typedef struct {
    njt_http_request_t *req;
    njt_int_t index;
    njt_http_location_main_conf_t *dlmcf;
}njt_http_location_rpc_ctx_t;





static njt_command_t njt_http_location_commands[] = {
        njt_null_command
};


static njt_http_module_t njt_http_location_api_module_ctx = {
        NULL,                              /* preconfiguration */
        njt_http_location_init,                              /* postconfiguration */

        njt_http_location_create_main_conf,                              /* create main configuration */
        NULL,                              /* init main configuration */

        NULL,                              /* create server configuration */
        NULL,                              /* merge server configuration */

        njt_http_location_create_loc_conf, /* create location configuration */
        njt_http_location_merge_loc_conf   /* merge location configuration */
};

njt_module_t njt_http_location_api_module = {
        NJT_MODULE_V1,
        &njt_http_location_api_module_ctx, /* module context */
        njt_http_location_commands,    /* module directives */
        NJT_HTTP_MODULE,                    /* module type */
        NULL,                               /* init master */
        NULL,                               /* init module */
        njt_http_location_init_worker, /* init process */
        NULL,                               /* init thread */
        NULL,                               /* exit thread */
        NULL,                               /* exit process */
        NULL,                               /* exit master */
        NJT_MODULE_V1_PADDING
};

static njt_int_t
njt_http_location_init(njt_conf_t *cf) {
    njt_http_api_reg_info_t h;

	 njt_http_location_main_conf_t *dlmcf;

    dlmcf = njt_http_conf_get_module_main_conf(cf,njt_http_location_api_module);
    if(dlmcf->size == NJT_CONF_UNSET){
        dlmcf->size = 500;
    }
    dlmcf->reqs = njt_pcalloc(cf->pool, sizeof(njt_http_request_t*)*dlmcf->size);
    if(dlmcf->reqs == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_http_location_postconfiguration alloc mem error");
        return NJT_ERROR;
    }


    njt_str_t  module_key = njt_string("/v1/dyn_loc");
    njt_memzero(&h, sizeof(njt_http_api_reg_info_t));
    h.key = &module_key;
    h.handler = njt_http_location_handler;
    njt_http_api_module_reg_handler(&h);

    return NJT_OK;
}


static void *
njt_http_location_create_loc_conf(njt_conf_t *cf) {
    //ssize_t size;
    //njt_str_t zone = njt_string("api_dy_server");
    njt_http_location_loc_conf_t *uclcf;
    //size = (ssize_t)(10 * njt_pagesize);
    uclcf = njt_pcalloc(cf->pool, sizeof(njt_http_location_loc_conf_t));
    if (uclcf == NULL) {
        njt_log_error(NJT_LOG_ERR, cf->log, 0, "malloc uclcf eror");
        return NULL;
    }
    uclcf->dyn_location_enable = NJT_CONF_UNSET;
    return uclcf;
}

static void *
njt_http_location_create_main_conf(njt_conf_t *cf) {
    //ssize_t size;
    //njt_str_t zone = njt_string("api_dy_server");

    njt_http_location_main_conf_t *uclcf;

    //size = (ssize_t)(10 * njt_pagesize);
    uclcf = njt_pcalloc(cf->pool, sizeof(njt_http_location_main_conf_t));
    if (uclcf == NULL) {
        njt_log_error(NJT_LOG_ERR, cf->log, 0, "malloc njt_http_location_main_conf_t eror");
        return NULL;
    }
	uclcf->size = NJT_CONF_UNSET;
    return uclcf;
}


static char *njt_http_location_merge_loc_conf(njt_conf_t *cf,
                                              void *parent, void *child) {
    njt_http_location_loc_conf_t *prev = parent;
    njt_http_location_loc_conf_t *conf = child;

    njt_conf_merge_value(conf->dyn_location_enable, prev->dyn_location_enable, 0);

    return NJT_CONF_OK;
}

static njt_buf_t *
njt_http_location_api_get_out_buf(njt_http_request_t *r, ssize_t len,
                                  njt_chain_t *out) {
    njt_buf_t *b;
    njt_chain_t *last_chain, *new_chain;


    if ((njt_uint_t) len > njt_pagesize) {
        /*The string len is larger than one buf*/

        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "buffer size is beyond one pagesize.");
        return NULL;
    }

    last_chain = out;
    while (out->next) {
        out->buf->last_buf = 0;
        out->buf->last_in_chain = 0;

        last_chain = out->next;
        out = out->next;
    }

    b = last_chain->buf;
    if (b == NULL) {

        b = njt_create_temp_buf(r->pool, njt_pagesize);
        if (b == NULL) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "couldn't allocate the temp buffer.");
            return NULL;
        }

        last_chain->buf = b;
        last_chain->next = NULL;

        b->last_buf = 1;
        b->last_in_chain = 1;
        b->memory = 1;

        return b;
    }

    /*if the buf's left size is big enough to hold one server*/

    if ((b->end - b->last) < len) {

        new_chain = njt_pcalloc(r->pool, sizeof(njt_chain_t));
        if (new_chain == NULL) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "couldn't allocate the chain.");
            return NULL;
        }

        b = njt_create_temp_buf(r->pool, njt_pagesize);
        if (b == NULL) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "couldn't allocate temp buffer.");
            return NULL;
        }
        new_chain->buf = b;
        new_chain->next = NULL;

        last_chain->buf->last_buf = 0;
        last_chain->buf->last_in_chain = 0;

        new_chain->buf->last_buf = 1;
        new_chain->buf->last_in_chain = 1;

        last_chain->next = new_chain;
    }

    return b;
}

static njt_int_t
njt_http_location_api_insert_out_str(njt_http_request_t *r,
                                     njt_chain_t *out, njt_str_t *str) {
    njt_buf_t *b;

    if (str->len == 0) {
        return NJT_OK;
    }
    if (str == NULL || str->data == NULL) {
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "parameter error in function %s", __func__);
        return NJT_ERROR;
    }

    b = njt_http_location_api_get_out_buf(r, str->len, out);
    if (b == NULL) {
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "could not alloc buffer in function %s", __func__);
        return NJT_ERROR;
    }

    b->last = njt_snprintf(b->last, str->len, "%V", str);

    return NJT_OK;
}

static ssize_t
njt_http_location_api_out_len(njt_chain_t *out) {
    ssize_t len;

    len = 0;
    while (out) {

        if (out->buf) {
            len += out->buf->last - out->buf->pos;
        }

        out = out->next;
    }

    return len;
}

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

static int njt_http_location_request_output(njt_http_request_t *r,njt_int_t code, njt_str_t *msg){
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
njt_http_location_handler(njt_http_request_t *r) {
    njt_int_t rc = NJT_OK;
    njt_array_t *path;
    njt_str_t msg;
    njt_str_t not_found_err = njt_string("{\"code\":404,\"msg\":\"not found error\"}");
    njt_str_t srv_err = njt_string("{\"code\":500,\"msg\":\"server error\"}");

    njt_str_null(&msg);
    path = njt_array_create( r->pool, 4, sizeof(njt_str_t));
    if (path == NULL) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,"array init of path error.");
        goto err;
    }
    rc = njt_http_api_parse_path(r,path);
    if(rc != NJT_OK || path->nelts <  2 ){
        rc = NJT_HTTP_NOT_FOUND;
        goto out;
    }
   


    njt_log_debug0(NJT_LOG_DEBUG_ALLOC, r->pool->log, 0, "1 read_client_request_body start +++++++++++++++");

    if((r->method == NJT_HTTP_PUT || r->method == NJT_HTTP_POST) && path->nelts == 2) {
        rc = njt_http_read_client_request_body(r, njt_http_location_read_data);
        //location_info = njt_http_get_module_ctx(r, njt_http_location_api_module);
        // zyg  error: njt_log_debug0(NJT_LOG_DEBUG_ALLOC, r->pool->log, 0, "2 read_client_request_body end +++++++++++++++");

        if (rc >= NJT_HTTP_SPECIAL_RESPONSE) {
            /* error */
            return rc;
        }

        return NJT_DONE;
    }

    rc = NJT_HTTP_NOT_FOUND;
out:
    if(rc ==  NJT_HTTP_NOT_FOUND ){
        msg = not_found_err;
    }
    if(rc ==  NJT_HTTP_INTERNAL_SERVER_ERROR ){
        msg = srv_err;
    }
    return njt_http_location_request_output(r,rc,&msg);
err:

    return njt_http_location_request_output(r,NJT_HTTP_INTERNAL_SERVER_ERROR,&srv_err);


    
}


static njt_int_t
njt_http_location_init_worker(njt_cycle_t *cycle) {

    return NJT_OK;
}

static njt_int_t njt_http_location_get_free_index(njt_http_location_main_conf_t *dlmcf){
    njt_int_t i;

    for(i = 0 ; i < dlmcf->size; ++i ){
        if(dlmcf->reqs[i] == NULL){
            return i;
        }
    }
    return -1;
}

static void njt_http_location_cleanup_handler(void *data){
    njt_http_location_rpc_ctx_t *ctx;

    ctx = data;
    if(ctx->dlmcf->size > ctx->index && ctx->dlmcf->reqs[ctx->index] == ctx->req){
        ctx->dlmcf->reqs[ctx->index] = NULL;
    }
}

static int njt_http_location_rpc_msg_handler(njt_dyn_rpc_res_t* res, njt_str_t *msg){
    njt_http_location_rpc_ctx_t *ctx;
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
            rc = njt_http_location_request_output(req,NJT_OK,msg);
        }
        if(res->rc == RPC_RC_TIMEOUT){
            rc = njt_http_location_request_output(req,NJT_HTTP_INTERNAL_SERVER_ERROR,&err_msg);
        }
        njt_http_finalize_request(req,rc);
    }
    return NJT_OK;
}


static njt_int_t njt_http_location_rpc_send(njt_http_request_t *r,njt_str_t *module_name,njt_str_t *msg, int retain){
    njt_http_location_main_conf_t *dlmcf;
    njt_int_t index;
    njt_int_t rc;
    njt_http_location_rpc_ctx_t *ctx;
    njt_pool_cleanup_t *cleanup;

    r->write_event_handler = njt_http_request_empty_handler;
    dlmcf = njt_http_get_module_main_conf(r,njt_http_location_api_module);
    index = njt_http_location_get_free_index(dlmcf);
    if(index == -1 ){
        njt_log_error(NJT_LOG_ERR, r->pool->log, 0, "not find request free index ");
        goto err;
    } else {
        njt_log_error(NJT_LOG_INFO, r->pool->log, 0, "use index :%i ",index);
    }
    ctx = njt_pcalloc(r->pool, sizeof(njt_http_location_rpc_ctx_t));
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
    cleanup->handler = njt_http_location_cleanup_handler;
    cleanup->data = ctx;
    njt_log_error(NJT_LOG_INFO, r->pool->log, 0, "send rpc time : %M",njt_current_msec);
    rc = njt_dyn_rpc(module_name,msg, retain, index, njt_http_location_rpc_msg_handler, ctx);
    if(rc == NJT_OK){
        dlmcf->reqs[index] = r;
    }
    return rc;

    err:
    return NJT_ERROR;
}


static void
njt_http_location_read_data(njt_http_request_t *r){
	njt_str_t json_str;
    njt_int_t rc;
    njt_uint_t len;
    njt_chain_t out;
    njt_str_t insert;
    njt_http_location_info_t *location_info;
    njt_rpc_result_t * rpc_result;
    njt_http_sub_location_info_t  *sub_location, *loc;
    u_char *p;
    uint32_t                                      crc32;
    uint32_t									   topic_len = NJT_INT64_LEN  + 2 + 256; ///ins/loc/l_
    njt_str_t									   topic_name,location_rule,location;
    njt_str_t  add = njt_string("add");
    njt_str_t  del = njt_string("del");
   
    location_info = NULL;
    rpc_result = NULL;
    
    rc = njt_http_util_read_request_body(r, &json_str, LOCATION_MIN_BODY_LEN, LOCATION_MAX_BODY_LEN);
    /*check the sanity of the json body*/

	if(json_str.len < LOCATION_MIN_BODY_LEN ){
        goto err;
    }





	location_info = njt_http_parser_location_data(json_str,r->method);
	if(location_info == NULL) {
		 goto err;
	}
	


	if(location_info->msg.len != 0) {
		 goto err;
	}
	if(location_info->type.len == add.len && njt_strncmp(location_info->type.data,add.data,location_info->type.len) == 0 ) {
		sub_location = location_info->location_array->elts;
		loc = &sub_location[0];
		location_rule = loc->location_rule;
		location = loc->location;
	} else {
		location_rule = location_info->location_rule;
		location = location_info->location;
	}


	

	njt_crc32_init(crc32);
	njt_crc32_update(&crc32,location_info->addr_port.data,location_info->addr_port.len);
	if (location_info->server_name.len > 0) {
		njt_crc32_update(&crc32,location_info->server_name.data,location_info->server_name.len);
	}
	if (location_rule.len > 0) {
		njt_crc32_update(&crc32,location_rule.data,location_rule.len);
	}
	njt_crc32_update(&crc32,location.data,location.len);
	njt_crc32_final(crc32);

   
	topic_name.data = njt_pcalloc(r->pool,topic_len);
	 if (topic_name.data == NULL) {
		 njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "topic_name njt_pcalloc error.");
        goto err;
    }
	
	
	if(location_info->type.len == del.len && njt_strncmp(location_info->type.data,del.data,location_info->type.len) == 0 ){
		p = njt_snprintf(topic_name.data,topic_len,"/worker_a/ins/loc/l_%ui",crc32);
	} else  if(location_info->type.len == add.len && njt_strncmp(location_info->type.data,add.data,location_info->type.len) == 0 ){
		p = njt_snprintf(topic_name.data,topic_len,"/worker_a/ins/loc/l_%ui",crc32);
	} else {
		njt_str_set(&location_info->msg, "type error!!!");
		goto err;
	}
	topic_name.len = p - topic_name.data;
	rc = njt_http_location_rpc_send(r,&topic_name,&json_str,0);
	if(rc == NJT_OK) {
		++r->main->count;
	}
	njt_log_error(NJT_LOG_DEBUG, r->connection->log, 0, "1 send topic retain_flag=%V, key=%V,value=%V",&location_info->type,&topic_name,&json_str);
	if(location_info != NULL) {
                njt_destroy_pool(location_info->pool);
    }

	goto out;

	
err:
    out.next = NULL;
    out.buf = NULL;
     rpc_result = njt_rpc_result_create();
    if(rpc_result == NULL){
	    if(location_info != NULL) {
		    njt_destroy_pool(location_info->pool);
	    }
       njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "rpc_result allocate null");
       rc = NJT_ERROR;
       goto out;
    }
	
    if (location_info != NULL && location_info->msg.len ==  0) {
        //njt_str_set(&insert, "Success");
	njt_rpc_result_set_code(rpc_result,NJT_RPC_RSP_SUCCESS);
    	r->headers_out.status = NJT_HTTP_OK;
    } else {
		 njt_rpc_result_set_code(rpc_result,NJT_RPC_RSP_ERR);
		r->headers_out.status = 400;
		if(location_info == NULL) {
		   njt_str_set(&insert, "json parser error!");
           njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "json parser error=%V",&json_str);
		} else {
			insert = location_info->msg;
		}
		njt_rpc_result_set_msg2(rpc_result,&insert);
        
    }
    njt_str_null(&insert);
    njt_rpc_result_to_json_str(rpc_result,&insert);

    r->headers_out.content_type_len = sizeof("text/plain") - 1;
    njt_str_set(&r->headers_out.content_type, "text/plain");
    r->headers_out.content_type_lowcase = NULL;
    rc =  njt_http_location_api_insert_out_str(r, &out, &insert);
    len = njt_http_location_api_out_len(&out);
    r->headers_out.content_length_n = len;
    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }
	if(location_info != NULL) {
                njt_destroy_pool(location_info->pool);
    }

    rc = njt_http_send_header(r);
	if (rc == NJT_ERROR || rc > NJT_OK || r->header_only) {
        //njt_http_finalize_request(r, rc);
        //return;
	goto out;
    }
   
    rc = njt_http_output_filter(r, &out);

out:
    njt_http_finalize_request(r, rc);
    if(rpc_result){
	if(insert.data != NULL && insert.len != 0) {
		njt_free(insert.data);
	}
        njt_rpc_result_destroy(rpc_result);

    }
    return;

}










