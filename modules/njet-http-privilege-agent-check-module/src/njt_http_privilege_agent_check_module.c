/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */
#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_http_kv_module.h>
#include "njt_http_api_register_module.h"

#define PRIVILEGE_AGENT_CYCLE_ADDR_TOPIC_REG_KEY "njt_cycle_addr"

extern njt_cycle_t *njet_master_cycle;

typedef struct
{
    int agent_ready;
} njt_http_privilege_agent_check_conf_t;

static void *njt_http_privilege_agent_check_create_conf(njt_conf_t *cf);
static int njt_http_privilege_agent_check_msg_handler(njt_str_t *key, njt_str_t *msg, void *data);
static njt_int_t njt_http_privilege_agent_check_init_worker(njt_cycle_t *cycle);
static njt_int_t njt_http_privilege_agent_check_content_handler(njt_http_request_t *r);
static njt_int_t   njt_http_privilege_agent_check_postconfiguration(njt_conf_t *cf);

static njt_http_module_t njt_http_privilege_agent_check_module_ctx = {
    NULL, /* preconfiguration */
    njt_http_privilege_agent_check_postconfiguration, /* postconfiguration */

    njt_http_privilege_agent_check_create_conf, /* create main configuration */
    NULL,                                /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    NULL, /* create location configuration */
    NULL  /* merge location configuration */
};

njt_module_t njt_http_privilege_agent_check_module = {
    NJT_MODULE_V1,
    &njt_http_privilege_agent_check_module_ctx,     /* module context */
    NULL,                                          /* module directives */
    NJT_HTTP_MODULE,                               /* module type */
    NULL,                                          /* init master */
    NULL,                                          /* init module */
    njt_http_privilege_agent_check_init_worker,     /* init process */
    NULL,                                          /* init thread */
    NULL,                                          /* exit thread */
    NULL,                                          /* exit process */
    NULL,                                          /* exit master */
    NJT_MODULE_V1_PADDING };

static void *njt_http_privilege_agent_check_create_conf(njt_conf_t *cf)
{
    njt_http_privilege_agent_check_conf_t *conf;
    conf = njt_pcalloc(cf->pool, sizeof(njt_http_privilege_agent_check_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    return conf;
}

static int njt_http_privilege_agent_check_msg_handler(njt_str_t *key, njt_str_t *msg, void *data)
{
    njt_http_privilege_agent_check_conf_t *pacf = data;

    u_char      cmsg[20];
    njt_str_t   cmsg_str;
    njt_memzero(cmsg, 20);
    njt_snprintf(cmsg, 19, "%p", njet_master_cycle);
    cmsg_str.data = cmsg;
    cmsg_str.len = njt_strlen(cmsg);

    //when privilege agent is up and running, it will send the msg with njt_cycle address in it
    //compare received address with master cycle because this api is running in ctrl panel 
    if (njt_strncmp(msg->data, cmsg_str.data, msg->len) == 0) {
        pacf->agent_ready = 1;
    } else {
        pacf->agent_ready = 0;
    }

    return NJT_OK;
}

static njt_int_t njt_http_privilege_agent_check_init_worker(njt_cycle_t *cycle)
{
    njt_http_conf_ctx_t *conf_ctx;
    njt_http_privilege_agent_check_conf_t *pacf;

    // return when there is no http configuraton
    if (njt_http_privilege_agent_check_module.ctx_index == NJT_CONF_UNSET_UINT) {
        return NJT_OK;
    }
    conf_ctx = (njt_http_conf_ctx_t *)njt_get_conf(cycle->conf_ctx, njt_http_module);
    if (!conf_ctx) {
        return NJT_OK;
    }
    pacf = conf_ctx->main_conf[njt_http_privilege_agent_check_module.ctx_index];

    if (!pacf) {
        return NJT_OK;
    }
    //register msg callback
    njt_str_t rpc_key = njt_string(PRIVILEGE_AGENT_CYCLE_ADDR_TOPIC_REG_KEY);
    njt_kv_reg_handler_t h;
    njt_memzero(&h, sizeof(njt_kv_reg_handler_t));
    h.key = &rpc_key;
    h.handler = njt_http_privilege_agent_check_msg_handler;
    h.data = pacf;
    h.api_type = NJT_KV_API_TYPE_DECLATIVE;
    njt_kv_reg_handler(&h);

    return NJT_OK;
}

//right now, request url is not checked because only ready message will be sent, 
//all the url begin with /api/v1/privilege_agent will return ready status
static njt_int_t njt_http_privilege_agent_check_content_handler(njt_http_request_t *r)
{
    njt_buf_t *b;
    njt_chain_t out;
    char *resp_start = "{\"ready\":";
    char *resp_end = "}";
    njt_http_privilege_agent_check_conf_t *pacf;

    u_char *njt_ready_str = njt_pcalloc(r->pool, njt_strlen(resp_start) + njt_strlen(resp_end) + 6);  // true|false, max len is 5
    u_char *p = njt_ready_str;

    p = njt_cpystrn(p, (u_char *)resp_start, njt_strlen(resp_start) + 1);
    pacf = njt_http_cycle_get_module_main_conf(njt_cycle, njt_http_privilege_agent_check_module);
    if (pacf->agent_ready) {
        p = njt_cpystrn(p, (u_char *)"true", 5);
    } else {
        p = njt_cpystrn(p, (u_char *)"false", 6);
    }

    p = njt_cpystrn(p, (u_char *)resp_end, njt_strlen(resp_end) + 1);
    /* Set the Content-Type header. */
    r->headers_out.content_type.len = sizeof("application/json") - 1;
    r->headers_out.content_type.data = (u_char *)"application/json";

    /* Allocate a new buffer for sending out the reply. */
    b = njt_pcalloc(r->pool, sizeof(njt_buf_t));

    /* Insertion in the buffer chain. */
    out.buf = b;
    out.next = NULL; /* just one buffer */

    b->pos = njt_ready_str; /* first position in memory of the data */
    b->last = njt_ready_str + njt_strlen(njt_ready_str); /* last position in memory of the data */
    b->memory = 1; /* content is in read-only memory */
    b->last_buf = 1; /* there will be no more buffers in the request */

    /* Sending the headers for the reply. */
    r->headers_out.status = NJT_HTTP_OK; /* 200 status code */
    r->headers_out.content_length_n = njt_strlen(njt_ready_str);
    njt_http_send_header(r); /* Send the headers */

    return njt_http_output_filter(r, &out);
}

static njt_int_t   njt_http_privilege_agent_check_postconfiguration(njt_conf_t *cf)
{
    njt_http_api_reg_info_t             h;

    njt_str_t  module_key = njt_string("/v1/privilege_agent");
    njt_memzero(&h, sizeof(njt_http_api_reg_info_t));
    h.key = &module_key;
    h.handler = njt_http_privilege_agent_check_content_handler;
    njt_http_api_module_reg_handler(&h);

    return NJT_OK;
}

