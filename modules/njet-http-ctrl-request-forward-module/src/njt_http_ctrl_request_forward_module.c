/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */
#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_http_kv_module.h>

#define GOSSIP_NODEINFO_TOPIC_REG_KEY "nodeinfo"
#define GOSSIP_NODEINFO_MASTER_IP_FIELD "master_ip:"
#define GOSSIP_NODEINFO_LOCAL_IP_FIELD "local_ip:"
#define GOSSIP_NODEINFO_CTRL_PORT_FIELD "ctrl_port:"

typedef struct
{
    u_char masterIP[16];
    u_char localIP[16];
    u_char masterCtrlPort[6];
} njt_http_ctrl_request_forward_conf_t;

static void *njt_http_ctrl_request_forward_create_conf(njt_conf_t *cf);
static int njt_http_ctrl_request_forward_msg_handler(njt_str_t *key, njt_str_t *value, void *data);
static njt_int_t njt_http_ctrl_request_forward_init_worker(njt_cycle_t *cycle);
static njt_int_t njt_http_ctrl_request_forward_add_variables(njt_conf_t *cf);

static njt_http_module_t njt_http_ctrl_request_forward_module_ctx = {
    njt_http_ctrl_request_forward_add_variables, /* preconfiguration */
    NULL, /* postconfiguration */

    njt_http_ctrl_request_forward_create_conf, /* create main configuration */
    NULL,                                /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    NULL, /* create location configuration */
    NULL  /* merge location configuration */
};

njt_module_t njt_http_ctrl_request_forward_module = {
    NJT_MODULE_V1,
    &njt_http_ctrl_request_forward_module_ctx,     /* module context */
    NULL,                                          /* module directives */
    NJT_HTTP_MODULE,                               /* module type */
    NULL,                                          /* init master */
    NULL,                                          /* init module */
    njt_http_ctrl_request_forward_init_worker,     /* init process */
    NULL,                                          /* init thread */
    NULL,                                          /* exit thread */
    NULL,                                          /* exit process */
    NULL,                                          /* exit master */
    NJT_MODULE_V1_PADDING };


static void *njt_http_ctrl_request_forward_create_conf(njt_conf_t *cf)
{
    njt_http_ctrl_request_forward_conf_t *conf;
    conf = njt_pcalloc(cf->pool, sizeof(njt_http_ctrl_request_forward_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    return conf;
}

static void njt_http_ctrl_request_forward_get_field(njt_str_t *msg, njt_str_t *fieldName, njt_str_t *fieldValue)
{
    if (msg == NULL || msg->len < fieldName->len) return;

    u_char *pfs = njt_strstrn(msg->data, (char *)fieldName->data, fieldName->len-1);
    if (pfs == NULL) return;

    u_char *pvs = pfs + fieldName->len;
    if (pvs >= msg->data + msg->len) return;

    u_char *pc1;
    for (pc1 = pvs; pc1 < msg->data + msg->len && (*pc1 == ' ' || *pc1 == '{'); pc1++);
    pvs = pc1;
    for (pc1 = pvs; pc1 < msg->data + msg->len && *pc1 != ',' && *pc1 != '}'; pc1++);
    fieldValue->data = pvs;
    fieldValue->len = pc1 - pvs;
}

static int njt_http_ctrl_request_forward_msg_handler(njt_str_t *key, njt_str_t *msg, void *data)
{
    njt_http_ctrl_request_forward_conf_t *crfcf = data;
    njt_str_t fieldName;
    njt_str_t fieldValue;

    //once nodeinfo msg has been received, replace all the corresponding values in module's conf 
    //try to get master ip
    njt_memzero(crfcf->masterIP, 16);
    njt_str_set(&fieldName, GOSSIP_NODEINFO_MASTER_IP_FIELD);
    njt_str_set(&fieldValue, "");
    njt_http_ctrl_request_forward_get_field(msg, &fieldName, &fieldValue);
    //ipv4 max ip len is 15
    if (fieldValue.len <= 15) {
        njt_memcpy(crfcf->masterIP, fieldValue.data, fieldValue.len);
    }

    //try to get local  ip
    njt_memzero(crfcf->localIP, 16);
    njt_str_set(&fieldName, GOSSIP_NODEINFO_LOCAL_IP_FIELD);
    njt_str_set(&fieldValue, "");
    njt_http_ctrl_request_forward_get_field(msg, &fieldName, &fieldValue);
    //ipv4 max ip len is 15
    if (fieldValue.len <= 15) {
        njt_memcpy(crfcf->localIP, fieldValue.data, fieldValue.len);
    }

    //try to get ctrl port
    njt_memzero(crfcf->masterCtrlPort, 16);
    njt_str_set(&fieldName, GOSSIP_NODEINFO_CTRL_PORT_FIELD);
    njt_str_set(&fieldValue, "");
    njt_http_ctrl_request_forward_get_field(msg, &fieldName, &fieldValue);
    //max port length is 5
    if (fieldValue.len <= 5) {
        njt_memcpy(crfcf->masterCtrlPort, fieldValue.data, fieldValue.len);
    }
    return NJT_OK;
}

static njt_int_t njt_http_ctrl_request_forward_init_worker(njt_cycle_t *cycle)
{
    njt_http_conf_ctx_t *conf_ctx;
    njt_http_ctrl_request_forward_conf_t *crfcf;

    // return when there is no http configuraton
    if (njt_http_ctrl_request_forward_module.ctx_index == NJT_CONF_UNSET_UINT) {
        return NJT_OK;
    }
    conf_ctx = (njt_http_conf_ctx_t *)njt_get_conf(cycle->conf_ctx, njt_http_module);
    if (!conf_ctx) {
        return NJT_OK;
    }
    crfcf = conf_ctx->main_conf[njt_http_ctrl_request_forward_module.ctx_index];

    if (!crfcf) {
        return NJT_OK;
    }
    //register msg callback
    njt_str_t rpc_key = njt_string(GOSSIP_NODEINFO_TOPIC_REG_KEY);
    njt_kv_reg_handler_t h;
    njt_memzero(&h, sizeof(njt_kv_reg_handler_t));
    h.key = &rpc_key;
    h.handler = njt_http_ctrl_request_forward_msg_handler;
    h.data = crfcf;
    h.api_type = NJT_KV_API_TYPE_DECLATIVE;
    njt_kv_reg_handler(&h);

    return NJT_OK;
}

njt_int_t njt_http_ctrl_request_forward_get_master_ip(njt_http_request_t *r, njt_http_variable_value_t *v, uintptr_t data)
{
    njt_http_ctrl_request_forward_conf_t *crfcf;
    njt_str_t masterIP;
    crfcf = njt_http_cycle_get_module_main_conf(njt_cycle, njt_http_ctrl_request_forward_module);

    //get master ip from value in conf
    if (crfcf != NULL) {
        masterIP.data = crfcf->masterIP;
        masterIP.len = njt_strlen(crfcf->masterIP);
        v->valid = 1;
        v->no_cacheable = 1;
        v->not_found = 0;
        v->len = masterIP.len;
        v->data = njt_pstrdup(r->pool, &masterIP);
        return NJT_OK;
    }

    v->valid = 0;
    v->not_found = 1;
    v->len = 0;
    return NJT_ERROR;

}

njt_int_t njt_http_ctrl_request_forward_get_master_ctrl_port(njt_http_request_t *r, njt_http_variable_value_t *v, uintptr_t data)
{
    njt_http_ctrl_request_forward_conf_t *crfcf;
    njt_str_t ctrlPort;
    crfcf = njt_http_cycle_get_module_main_conf(njt_cycle, njt_http_ctrl_request_forward_module);

    //get master ip from value in conf
    if (crfcf != NULL) {
        ctrlPort.data = crfcf->masterCtrlPort;
        ctrlPort.len = njt_strlen(crfcf->masterCtrlPort);
        v->valid = 1;
        v->no_cacheable = 1;
        v->not_found = 0;
        v->len = ctrlPort.len;
        v->data = njt_pstrdup(r->pool, &ctrlPort);
        return NJT_OK;
    }

    v->valid = 0;
    v->not_found = 1;
    v->len = 0;
    return NJT_ERROR;

}


njt_int_t njt_http_ctrl_request_forward_get_local_ip(njt_http_request_t *r, njt_http_variable_value_t *v, uintptr_t data)
{
    njt_http_ctrl_request_forward_conf_t *crfcf;
    njt_str_t localIP;
    crfcf = njt_http_cycle_get_module_main_conf(njt_cycle, njt_http_ctrl_request_forward_module);

    //get master ip from value in conf
    if (crfcf != NULL) {
        localIP.data = crfcf->localIP;
        localIP.len = njt_strlen(crfcf->localIP);
        v->valid = 1;
        v->no_cacheable = 1;
        v->not_found = 0;
        v->len = localIP.len;
        v->data = njt_pstrdup(r->pool, &localIP);
        return NJT_OK;
    }

    v->valid = 0;
    v->not_found = 1;
    v->len = 0;
    return NJT_ERROR;

}


static njt_http_variable_t njt_http_ctrl_request_forward_cluster_vars[] = {
    {njt_string("cluster_master_ip"), NULL, njt_http_ctrl_request_forward_get_master_ip, 0, NJT_HTTP_VAR_NOCACHEABLE , 0, NJT_VAR_INIT_REF_COUNT},
    {njt_string("cluster_master_ctrl_port"), NULL, njt_http_ctrl_request_forward_get_master_ctrl_port, 0, NJT_HTTP_VAR_NOCACHEABLE , 0, NJT_VAR_INIT_REF_COUNT},
    {njt_string("cluster_local_ip"), NULL, njt_http_ctrl_request_forward_get_local_ip, 0, NJT_HTTP_VAR_NOCACHEABLE , 0, NJT_VAR_INIT_REF_COUNT}, 
    njt_http_null_variable };

static njt_int_t njt_http_ctrl_request_forward_add_variables(njt_conf_t *cf)
{
    njt_http_variable_t *var, *v;

    for (v = njt_http_ctrl_request_forward_cluster_vars; v->name.len; v++) {
        var = njt_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NJT_ERROR;
        }
        var->get_handler = v->get_handler;
        var->data = v->data;
    }
    return NJT_OK;
}