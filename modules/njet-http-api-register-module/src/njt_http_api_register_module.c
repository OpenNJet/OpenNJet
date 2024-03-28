/*
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */
#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_hash_util.h>

#include "njt_http_api_register_module.h"


static njt_lvlhash_map_t *njt_http_api_module_handler_hashmap = NULL;
static njt_queue_t njt_http_api_module_handler_queue;

typedef struct
{
    njt_http_api_reg_info_t callbacks;
    njt_queue_t queue;
} njt_http_api_module_handler_t;

static njt_int_t
njt_http_api_module_register_handler(njt_http_request_t *r);

static njt_int_t
njt_http_api_module_register_init_worker(njt_cycle_t *cycle);

static void *
njt_http_api_module_register_create_loc_conf(njt_conf_t *cf);

static char *njt_http_api_module_register_merge_loc_conf(njt_conf_t *cf,
                                              void *parent, void *child);

static njt_int_t
njt_http_api_module_register_init(njt_conf_t *cf);

static void njt_http_api_module_exit_worker(njt_cycle_t *cycle);

static api_module_handler
njt_http_api_module_find_handler(njt_str_t *module_key);

static njt_int_t njt_http_api_module_register_request_output(njt_http_request_t *r,njt_int_t code, njt_str_t *msg);

static char *
njt_dyn_module_api(njt_conf_t *cf, njt_command_t *cmd, void *conf);

njt_int_t
http_api_module_register_lvlhsh_test(njt_lvlhsh_query_t *lhq, void *data);


typedef struct njt_http_api_module_register_loc_conf_s {  //njt_http_api_module_register_main_cf_t
    njt_flag_t http_api_module_register_enable;
}njt_http_api_module_register_loc_conf_t;



static njt_command_t njt_http_api_register_commands[] = {
        {
                njt_string("dyn_module_api"),
                NJT_HTTP_LOC_CONF|NJT_CONF_NOARGS,
                njt_dyn_module_api,
                NJT_HTTP_LOC_CONF_OFFSET,
                offsetof(njt_http_api_module_register_loc_conf_t, http_api_module_register_enable),
                NULL
        },
        njt_null_command
};


static njt_http_module_t njt_http_api_register_module_ctx = {
        NULL,                                   /* preconfiguration */
        njt_http_api_module_register_init,      /* postconfiguration */

        NULL,                              /* create main configuration */
        NULL,                              /* init main configuration */

        NULL,                              /* create server configuration */
        NULL,                              /* merge server configuration */

        njt_http_api_module_register_create_loc_conf, /* create location configuration */
        njt_http_api_module_register_merge_loc_conf   /* merge location configuration */
};


njt_module_t njt_http_api_register_module = {
        NJT_MODULE_V1,
        &njt_http_api_register_module_ctx, /* module context */
        njt_http_api_register_commands,    /* module directives */
        NJT_HTTP_MODULE,                    /* module type */
        NULL,                               /* init master */
        NULL,                               /* init module */
        njt_http_api_module_register_init_worker, /* init process */
        NULL,                               /* init thread */
        NULL,                               /* exit thread */
        njt_http_api_module_exit_worker,                               /* exit process */
        NULL,                               /* exit master */
        NJT_MODULE_V1_PADDING
};


static char *
njt_dyn_module_api(njt_conf_t *cf, njt_command_t *cmd, void *conf) {
    // njt_http_core_loc_conf_t   *clcf;
	njt_http_api_module_register_loc_conf_t   *arcf = conf;

    arcf->http_api_module_register_enable = 1;

    // clcf = njt_http_conf_get_module_loc_conf(cf, njt_http_core_module);
    // clcf->handler = njt_http_api_module_register_handler;

    return NJT_CONF_OK;
}


static njt_int_t
njt_http_api_module_register_init(njt_conf_t *cf) {
    njt_http_core_main_conf_t *cmcf;
    njt_http_handler_pt *h;

    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);
	if(cmcf == NULL) {
		return NJT_ERROR;
	}

    h = njt_array_push(&cmcf->phases[NJT_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_http_api_module_register_handler;

    return NJT_OK;
}


static void *
njt_http_api_module_register_create_loc_conf(njt_conf_t *cf) {
    njt_http_api_module_register_loc_conf_t *uclcf;

    uclcf = njt_pcalloc(cf->pool, sizeof(njt_http_api_module_register_loc_conf_t));
    if (uclcf == NULL) {
        njt_log_error(NJT_LOG_ERR, cf->log, 0, "malloc uclcf eror");
        return NULL;
    }
    uclcf->http_api_module_register_enable = NJT_CONF_UNSET;

    return uclcf;
}


static char *njt_http_api_module_register_merge_loc_conf(njt_conf_t *cf,
                                              void *parent, void *child) {
    njt_http_api_module_register_loc_conf_t *prev = parent;
    njt_http_api_module_register_loc_conf_t *conf = child;

    njt_conf_merge_value(conf->http_api_module_register_enable, prev->http_api_module_register_enable, 0);

    return NJT_CONF_OK;
}


static njt_int_t njt_http_api_module_register_request_output(njt_http_request_t *r,njt_int_t code, njt_str_t *msg){
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

static api_module_handler
njt_http_api_module_find_handler(njt_str_t *module_key){
    njt_int_t rc;
    njt_http_api_module_handler_t *module_handler;

    if (njt_http_api_module_handler_hashmap) {
        rc = njt_lvlhsh_map_get(njt_http_api_module_handler_hashmap, module_key, (intptr_t *)&module_handler);
        if (rc == NJT_OK && module_handler->callbacks.handler) {
            return module_handler->callbacks.handler;
        }
    }

    return NULL;
}


static njt_int_t
njt_http_api_module_register_handler(njt_http_request_t *r) {
    njt_http_api_module_register_loc_conf_t     *loc;
    u_char                          *p, *end;
    u_char                          *second_part, *third_part, *four_part;
    njt_uint_t                      len;
    njt_str_t                       module_key;
    api_module_handler              module_handler;
    njt_str_t srv_err = njt_string("{\"code\":404,\"msg\":\" not register api module\"}");
    
    loc = njt_http_get_module_loc_conf(r, njt_http_api_register_module);
    if (loc && loc->http_api_module_register_enable) {
    } else {
        return NJT_DECLINED;
    }

    //parse url, such as /api/v1/dyn_loc/other
    len = r->uri.len;
    p = r->uri.data + 1;
    end = r->uri.data + len;

    second_part = (u_char *) njt_strlchr(p, end, '/');
    if(second_part == NULL){
        goto uri_err;
    }
    
    module_key.data = second_part;
    p = second_part + 1;
    third_part = (u_char *) njt_strlchr(p, end, '/');
    if(third_part == NULL){
        goto uri_err;
    }

    p = third_part + 1;
    four_part = (u_char *) njt_strlchr(p, end, '/');
    if(four_part == NULL){
        module_key.len = end - module_key.data;
    }else{
        module_key.len = four_part - module_key.data;
    }

    //find handler by url
    module_handler = njt_http_api_module_find_handler(&module_key);

    //if find , call handler
    if(module_handler != NULL){
        return module_handler(r);
    }

//if not found, then return 404 to client
uri_err:
    return njt_http_api_module_register_request_output(r, NJT_HTTP_NOT_FOUND, &srv_err);
}


static njt_int_t
njt_http_api_module_register_init_worker(njt_cycle_t *cycle) {

    return NJT_OK;
}


njt_int_t njt_http_api_module_reg_handler(njt_http_api_reg_info_t *reg_info){
    //check param
    if(reg_info == NULL || reg_info->key == NULL 
        || reg_info->key->len < 1 || reg_info->handler == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
                    " api module register error, param error");

        return NJT_ERROR;
    }

    njt_http_api_module_handler_t *module_handler, *old_handler;
    if (njt_http_api_module_handler_hashmap == NULL) {
        njt_http_api_module_handler_hashmap = njt_calloc(sizeof(njt_lvlhash_map_t), njt_cycle->log);
        njt_queue_init(&njt_http_api_module_handler_queue);
    }
    module_handler = njt_calloc(sizeof(njt_http_api_module_handler_t), njt_cycle->log);

    if (module_handler == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
            "can't not malloc handler's memory while api module reg handler for key :%V ", reg_info->key);

        return NJT_ERROR;
    }

    module_handler->callbacks.key = njt_calloc(sizeof(njt_str_t), njt_cycle->log);
    if (module_handler->callbacks.key == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
            "can't not malloc handler key's memory while api module reg handler for key :%V ", reg_info->key);

        return NJT_ERROR;
    }
    module_handler->callbacks.key->data = (u_char *)njt_calloc(reg_info->key->len, njt_cycle->log);
    if (module_handler->callbacks.key->data == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
            "can't not malloc handler key's memory while api module reg handler for key :%V ", reg_info->key);

        return NJT_ERROR;
    }
    njt_memcpy(module_handler->callbacks.key->data, reg_info->key->data, reg_info->key->len);
    module_handler->callbacks.key->len = reg_info->key->len;
    module_handler->callbacks.handler = reg_info->handler;

    njt_queue_insert_tail(&njt_http_api_module_handler_queue, &module_handler->queue);
    njt_lvlhsh_map_put(njt_http_api_module_handler_hashmap, module_handler->callbacks.key, (intptr_t)module_handler, (intptr_t *)&old_handler);
    // if handler existed with the same key in the hashmap
    if (old_handler && old_handler != module_handler) {
        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, 
            "Key :%V has been registered in api module, please double check", reg_info->key);
        njt_free(old_handler->callbacks.key->data);
        njt_free(old_handler);
    }

    return NJT_OK;
}


static void njt_http_api_module_exit_worker(njt_cycle_t *cycle)
{
    njt_queue_t *q;
    njt_http_api_module_handler_t *handler;
    if (njt_http_api_module_handler_hashmap) {
        q = njt_queue_head(&njt_http_api_module_handler_queue);
        while (q != njt_queue_sentinel(&njt_http_api_module_handler_queue)) {
            handler = njt_queue_data(q, njt_http_api_module_handler_t, queue);
            q = njt_queue_next(q);
            njt_lvlhsh_map_remove(njt_http_api_module_handler_hashmap, handler->callbacks.key);
            njt_free(handler->callbacks.key->data);
            njt_free(handler->callbacks.key);
            njt_free(handler);
        }
        njt_free(njt_http_api_module_handler_hashmap);
    }
}
