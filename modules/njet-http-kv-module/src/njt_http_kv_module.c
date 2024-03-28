/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */
#include <stdbool.h>
#include <njt_config.h>
#include <njt_http.h>

#include "njet_iot_emb.h"
#include "njt_http_kv_module.h"
#include <njt_mqconf_module.h>
#include <njt_hash_util.h>

#define IOT_HELPER_NAME "iot"
#define IOT_HELPER_NAME_LEN 3

#define DYN_TOPIC_PREFIX "/dyn/"
#define DYN_TOPIC_PREFIX_LEN 5
#define RPC_TOPIC_PREFIX "/rpc/"
#define RPC_TOPIC_PREFIX_LEN 5
#define RPC_HANDLER_TOPIC_PREFIX_LEN 5 // rpc handler topic start with /rpc/ or /dyn/
#define WORKER_TOPIC_PREFIX "/worker_"
#define WORKER_TOPIC_PREFIX_LEN 8
#define RETAIN_MSG_QOS 16

typedef struct
{
    njt_kv_reg_handler_t callbacks;
    njt_queue_t queue;
} kv_change_handler_t;

typedef struct
{
    u_char color;
    u_char len;
    njt_str_t *val;
    u_char data[1];
} njt_http_kv_node_t;

typedef struct
{
    njt_str_t conf_file;
    njt_uint_t off;
} njt_http_kv_conf_t;

static void njt_http_kv_iot_conn_timeout(njt_event_t *ev);
static void njt_http_kv_iot_set_timer(njt_event_handler_pt h, int interval, struct evt_ctx_t *ctx);
static void njt_http_kv_loop_mqtt(njt_event_t *ev);
static void njt_http_kv_iot_register_outside_reader(njt_event_handler_pt h, struct evt_ctx_t *ctx);
static njt_int_t njt_http_kv_add_variables(njt_conf_t *cf);
static void invoke_kv_change_handler(njt_str_t *key, njt_str_t *value);
static void invoke_topic_msg_handler(const char *topic, const char *msg, int msg_len);
static u_char *invoke_rpc_handler(const char *topic, const char *msg, int msg_len, int *len);
static njt_int_t kv_init_worker(njt_cycle_t *cycle);
static void kv_exit_worker(njt_cycle_t *cycle);
static void *njt_http_kv_create_conf(njt_conf_t *cf);
static char *njt_dyn_conf_set(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static u_char *njt_http_kv_module_rpc_handler(njt_str_t *topic, njt_str_t *request, int *len, void *data);

static njt_rbtree_t kv_tree;
static njt_rbtree_node_t kv_sentinel;

static struct evt_ctx_t *kv_evt_ctx;
static char mqtt_kv_topic[128];
static njt_str_t cluster_name;

static njt_lvlhash_map_t *kv_handler_hashmap = NULL;
static njt_queue_t kv_handler_queue;

static njt_http_module_t njt_http_kv_module_ctx = {
    njt_http_kv_add_variables, /* preconfiguration */
    NULL,                      /* postconfiguration */

    njt_http_kv_create_conf, /* create main configuration */
    NULL,                    /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    NULL, /* create location configuration */
    NULL  /* merge location configuration */
};

static njt_command_t njt_kv_commands[] = {

    {njt_string("dyn_kv_conf"),
     NJT_HTTP_MAIN_CONF | NJT_CONF_NOARGS | NJT_CONF_TAKE1,
     njt_dyn_conf_set,
     0,
     0,
     NULL},
    njt_null_command /* command termination */
};

njt_module_t njt_http_kv_module = {
    NJT_MODULE_V1,
    &njt_http_kv_module_ctx, /* module context */
    njt_kv_commands,         /* module directives */
    NJT_HTTP_MODULE,         /* module type */
    NULL,                    /* init master */
    NULL,                    /* init module */
    kv_init_worker,          /* init process */
    NULL,                    /* init thread */
    NULL,                    /* exit thread */
    kv_exit_worker,          /* exit process */
    NULL,                    /* exit master */
    NJT_MODULE_V1_PADDING };

static void
njt_http_kv_rbtree_insert_value(njt_rbtree_node_t *temp,
    njt_rbtree_node_t *node, njt_rbtree_node_t *sentinel)
{
    njt_rbtree_node_t **p;
    njt_http_kv_node_t *lcn, *lcnt;

    for (;;) {

        if (node->key < temp->key) {
            p = &temp->left;
        } else if (node->key > temp->key) {
            p = &temp->right;
        } else { /* node->key == temp->key */
            lcn = (njt_http_kv_node_t *)&node->color;
            lcnt = (njt_http_kv_node_t *)&temp->color;
            p = (njt_memn2cmp(lcn->data, lcnt->data, lcn->len, lcnt->len) < 0)
                ? &temp->left
                : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    njt_rbt_red(node);
}
static njt_rbtree_node_t *
njt_http_kv_rbtree_lookup(njt_rbtree_t *rbtree, njt_str_t *key, uint32_t hash)
{
    njt_int_t rc;
    njt_rbtree_node_t *node, *sentinel;
    njt_http_kv_node_t *lcn;

    node = rbtree->root;
    sentinel = rbtree->sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        lcn = (njt_http_kv_node_t *)&node->color;

        rc = njt_memn2cmp(key->data, lcn->data, key->len, (size_t)lcn->len);

        if (rc == 0) {
            return node;
        }

        node = (rc < 0) ? node->left : node->right;
    }
    return NULL;
}

static void njt_http_kv_loop_mqtt(njt_event_t *ev)
{
    int ret;
    njt_connection_t *c = (njt_connection_t *)ev->data;
    struct evt_ctx_t *ctx = (struct evt_ctx_t *)c->data;
    if (ev->timer_set) {
        njt_del_timer(ev);
    }
    ret = njet_iot_client_run(ctx);
    switch (ret) {
    case 0:
        njt_add_timer(ev, 50);
        return;
    case 4:  // no connection
    case 19: // lost keepalive
    case 7:  // lost connection
        njt_http_kv_iot_set_timer(njt_http_kv_iot_conn_timeout, 10, ctx);
        njt_del_event(ev, NJT_READ_EVENT, NJT_CLOSE_EVENT);
        break;
    default:
        njt_log_error(NJT_LOG_ERR, ev->log, 0, "mqtt client run:%d, what todo ?", ret);
        njt_http_kv_iot_set_timer(njt_http_kv_iot_conn_timeout, 10, ctx);
        njt_del_event(ev, NJT_READ_EVENT, NJT_CLOSE_EVENT);
    }
    return;
}
static void njt_http_kv_iot_conn_timeout(njt_event_t *ev)
{
    njt_connection_t *c = (njt_connection_t *)ev->data;
    struct evt_ctx_t *ctx = (struct evt_ctx_t *)c->data;
    int ret;
    if (ev->timedout) {
        ret = njet_iot_client_connect(3, 5, ctx);
        if (ret != 0) {
            if (ret == -5) {
                //client is connecting or has connected
                return;
            }
            njt_add_timer(ev, 1000);
        } else {
            //connect ok, register io
            njt_http_kv_iot_register_outside_reader(njt_http_kv_loop_mqtt, ctx);
        }
    }
}

static void njt_http_kv_iot_register_outside_reader(njt_event_handler_pt h, struct evt_ctx_t *ctx)
{
    int fd;
    njt_event_t *rev, *wev;
    fd = njet_iot_client_socket(ctx);
    njt_connection_t *c = njt_palloc(njt_cycle->pool, sizeof(njt_connection_t));
    njt_memzero(c, sizeof(njt_connection_t));

    rev = njt_palloc(njt_cycle->pool, sizeof(njt_event_t));
    njt_memzero(rev, sizeof(njt_event_t));
    wev = njt_palloc(njt_cycle->pool, sizeof(njt_event_t));
    njt_memzero(wev, sizeof(njt_event_t));

    rev->log = njt_cycle->log;
    rev->handler = h;
    rev->data = c;
    rev->cancelable = 1;
    wev->data = c;
    wev->log = njt_cycle->log;
    wev->ready = 1;

    c->fd = (njt_socket_t)fd;
    // c->data=cycle;
    c->data = ctx;

    c->read = rev;
    c->write = wev;

    njt_log_error(NJT_LOG_NOTICE, rev->log, 0, "kv module connect ok, register socket:%d", fd);
    if (njt_add_event(rev, NJT_READ_EVENT, 0) != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, rev->log, 0, "add io event for mqtt failed");
        return;
    }
    njt_add_timer(rev, 1000); // tips: trigger every 1s at least, to process misc things like ping/pong
}

static void njt_http_kv_iot_set_timer(njt_event_handler_pt h, int interval, struct evt_ctx_t *ctx)
{
    njt_event_t *ev;
    njt_connection_t *c = njt_palloc(njt_cycle->pool, sizeof(njt_connection_t));
    njt_memzero(c, sizeof(njt_connection_t));

    ev = njt_palloc(njt_cycle->pool, sizeof(njt_event_t));
    njt_memzero(ev, sizeof(njt_event_t));
    ev->log = njt_cycle->log;
    ev->handler = h;
    ev->cancelable = 1;
    ev->data = c;
    c->fd = (njt_socket_t)-1;
    c->data = ctx;
    njt_add_timer(ev, interval);
}

static char *kv_rr_callback(const char *topic, int is_reply, const char *msg, int msg_len, int session_id, int *out_len)
{
    njt_str_t topic_str, msg_str;

    if (njt_exiting || njt_terminate) {
        //when process is exiting or terminate, skip msg processing
        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "process is existing, skip kv handling");
        u_char exitMsg[] = "{\"code\":-2, \"msg\":\"process is existing\"}";
        u_char *pchar = njt_calloc(41, njt_cycle->log);
        njt_memcpy(pchar, exitMsg, 41);
        *out_len = 41;
        return (char *)pchar;
    }
    topic_str.data = (u_char *)topic;
    topic_str.len = strlen(topic);
    msg_str.data = (u_char *)msg;
    msg_str.len = msg_len;

    //to avoid unused-but-set-variable warning
    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "kv got rr msg, topic: %V, msg:%V, seesion_id: %d", &topic_str, &msg_str, session_id);
    return (char *)invoke_rpc_handler(topic, msg, msg_len, out_len);
}
static int msg_callback(const char *topic, const char *msg, int msg_len, void *out_data)
{
    njt_rbtree_node_t *node;
    njt_http_kv_node_t *lc;
    njt_str_t kv_key, kv_value;
    njt_cycle_t *cycle = (njt_cycle_t *)out_data;
    njt_uint_t hash;

    if (njt_exiting || njt_terminate) {
        //when process is exiting or terminate, skip msg processing
        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "process is existing, skip kv handling");
        return NJT_OK;
    }

    // tips: 1 means message should be processed in lua
    int kv_topic_l = strlen(mqtt_kv_topic);
    int topic_l = strlen(topic);

    if (topic_l >= kv_topic_l && 0 == memcmp(topic, mqtt_kv_topic, kv_topic_l)) {
        const void *key, *val;
        int key_l, val_l;
        const char *p;
        // tips: assume payload is c strings, key \0 val
        p = msg;
        p += sizeof(int); // skip msg id
        key = p;
        key_l = strlen(key);
        p += key_l + 1;
        val = p;
        val_l = strlen(val);

        kv_key.data = njt_palloc(cycle->pool, key_l + 8); // sizeof "kv_http_"
        memcpy(kv_key.data, "kv_http_", 8);
        memcpy(kv_key.data + 8, key, key_l);
        kv_key.len = key_l + 8;

        kv_value.data = (u_char *)val;
        kv_value.len = val_l;

        invoke_kv_change_handler(&kv_key, &kv_value);

        hash = njt_crc32_short(kv_key.data, kv_key.len);
        node = njt_http_kv_rbtree_lookup(&kv_tree, &kv_key, hash);
        if (node == NULL) {
            int n;
            njt_str_t *node_val = njt_palloc(cycle->pool, sizeof(njt_str_t));
            n = offsetof(njt_rbtree_node_t, color) + offsetof(njt_http_kv_node_t, data) + kv_key.len;
            node = njt_palloc(cycle->pool, n);

            node->key = hash;
            lc = (njt_http_kv_node_t *)&node->color;
            lc->len = (u_char)kv_key.len;
            lc->val = node_val;

            node_val->data = njt_palloc(cycle->pool, val_l);
            memcpy(node_val->data, val, val_l);
            node_val->len = val_l;

            memcpy(lc->data, kv_key.data, kv_key.len);

            njt_rbtree_insert(&kv_tree, node);
        } else {
            lc = (njt_http_kv_node_t *)&node->color;
            njt_str_t *node_val = lc->val;
            // njt_pfree(node_val->data);
            // todo: do we need free

            node_val->data = njt_palloc(cycle->pool, val_l);
            memcpy(node_val->data, val, val_l);
            node_val->len = val_l;
        }
        return 0;
    }

    invoke_topic_msg_handler(topic, msg, msg_len);
    return 1;
}

static u_char *njt_http_kv_module_rpc_handler(njt_str_t *topic, njt_str_t *request, int *len, void *data)
{
    njt_uint_t str_len = 0;
    njt_queue_t *q;
    kv_change_handler_t *handler;

    str_len++; // [
    if (kv_handler_hashmap) {
        for (q = njt_queue_head(&kv_handler_queue);
            q != njt_queue_sentinel(&kv_handler_queue);
            q = njt_queue_next(q)) {
            handler = njt_queue_data(q, kv_change_handler_t, queue);
            if (handler->callbacks.rpc_get_handler && handler->callbacks.api_type == NJT_KV_API_TYPE_DECLATIVE) {
                str_len += handler->callbacks.key->len + 3; // "KEY_NAME",
            }
        }
    }

    u_char *msg, *pmsg;
    msg = njt_calloc(str_len, njt_cycle->log);
    pmsg = msg;
    msg[0] = '[';
    msg++;
    if (kv_handler_hashmap) {
        for (q = njt_queue_head(&kv_handler_queue);
            q != njt_queue_sentinel(&kv_handler_queue);
            q = njt_queue_next(q)) {
            handler = njt_queue_data(q, kv_change_handler_t, queue);
            if (handler->callbacks.rpc_get_handler && handler->callbacks.api_type == NJT_KV_API_TYPE_DECLATIVE) {
                *msg++ = '"';
                njt_memcpy(msg, handler->callbacks.key->data, handler->callbacks.key->len);
                msg += handler->callbacks.key->len;
                *msg++ = '"';
                *msg++ = ',';
            }
        }
    }
    pmsg[str_len - 1] = ']';
    *len = str_len;
    return pmsg;
}

static njt_int_t kv_init_worker(njt_cycle_t *cycle)
{
    njt_http_conf_ctx_t *conf_ctx;
    njt_http_kv_conf_t *kvcf;
    njt_uint_t i;
    int ret;
    njt_mqconf_conf_t *mqconf = NULL;
    char client_id[128] = { 0 };
    char log[1024] = { 0 };
    char localcfg[1024] = { 0 };
    char worker_topic[32] = { 0 };
    // return when there is no http configuraton
    if (njt_http_kv_module.ctx_index == NJT_CONF_UNSET_UINT) {
        return NJT_OK;
    }

    for (i = 0; i < cycle->modules_n; i++) {
        if (njt_strcmp(cycle->modules[i]->name, "njt_mqconf_module") != 0)
            continue;
        mqconf = (njt_mqconf_conf_t *)(cycle->conf_ctx[cycle->modules[i]->index]);
    }
    if (!mqconf || !mqconf->cluster_name.data || !mqconf->node_name.data) {
        njt_log_error(NJT_LOG_INFO, cycle->log, 0, "mqconf check failed, dyn_kv module is not loaded");
        return NJT_OK;
    } else if (mqconf->cluster_name.len >= 4 && 0 == memcmp(mqconf->cluster_name.data, "CTRL", 4)) {
        njt_log_error(NJT_LOG_INFO, cycle->log, 0, "no need dyn_kv module in control plane");
        return NJT_OK;
    }
    conf_ctx = (njt_http_conf_ctx_t *)njt_get_conf(cycle->conf_ctx, njt_http_module);
    if (!conf_ctx) {
        njt_log_error(NJT_LOG_INFO, cycle->log, 0, "http section not found, kv module is configured as off");
        return NJT_OK;
    }
    kvcf = conf_ctx->main_conf[njt_http_kv_module.ctx_index];
    if (!kvcf || kvcf->off) {
        njt_log_error(NJT_LOG_INFO, cycle->log, 0, "kv module is configured as off");
        return NJT_OK;
    }

    njt_str_t rhk = njt_string("njt_http_kv_module");
    njt_kv_reg_handler_t h;
    njt_memzero(&h, sizeof(njt_kv_reg_handler_t));
    h.key = &rhk;
    h.rpc_get_handler = njt_http_kv_module_rpc_handler;
    h.api_type = NJT_KV_API_TYPE_DECLATIVE;
    ret = njt_kv_reg_handler(&h);

    if (ret != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, cycle->log, 0, "can't reg rpc handler for kv module");
        return NJT_ERROR;
    }

    memcpy(client_id, mqconf->node_name.data, mqconf->node_name.len);
    sprintf(client_id + mqconf->node_name.len, "_w_%d", njt_pid);

    memcpy(log, njt_cycle->prefix.data, njt_cycle->prefix.len);
    if (njt_process != NJT_PROCESS_HELPER) {
        sprintf(log + njt_cycle->prefix.len, "logs/work_iot_%d", (int)njt_worker);
    } else {
        sprintf(log + njt_cycle->prefix.len, "logs/helper_iot");
    }
    memcpy(mqtt_kv_topic, "/cluster/", 9);
    memcpy(mqtt_kv_topic + 9, mqconf->cluster_name.data, mqconf->cluster_name.len);
    strcpy(mqtt_kv_topic + 9 + mqconf->cluster_name.len, "/kv_set/");

    memcpy(localcfg, kvcf->conf_file.data, kvcf->conf_file.len);
    localcfg[kvcf->conf_file.len] = '\0';

    cluster_name.data = njt_pstrdup(cycle->pool, &mqconf->cluster_name);
    cluster_name.len = mqconf->cluster_name.len;

    char *prefix;
    prefix = njt_calloc(cycle->prefix.len + 1, cycle->log);
    njt_memcpy(prefix, cycle->prefix.data, cycle->prefix.len);
    prefix[cycle->prefix.len] = '\0';
    kv_evt_ctx = njet_iot_client_init(prefix, localcfg, kv_rr_callback, msg_callback, client_id, log, cycle);
    njt_free(prefix);
    if (kv_evt_ctx == NULL) {
        njt_log_error(NJT_LOG_ERR, cycle->log, 0, "init local mqtt client failed, exiting");
        njet_iot_client_exit(kv_evt_ctx);
        return NJT_ERROR;
    };

    if (njt_process != NJT_PROCESS_HELPER) {
        // add default subscribed topics, the ordering of subscribed topic list is important.
        // when restarting njet instance, all the retained message received from broker will be in this order
        // /ins/# is for instructional api, it should be before /dyn/# 
        njet_iot_client_add_topic(kv_evt_ctx, "/cluster/+/kv_set/#");
        njet_iot_client_add_topic(kv_evt_ctx, "/ins/srv/#");
        njet_iot_client_add_topic(kv_evt_ctx, "/ins/loc/#");
        njet_iot_client_add_topic(kv_evt_ctx, "/ins/ssl/#");
        njet_iot_client_add_topic(kv_evt_ctx, "/dyn/#");
        njet_iot_client_add_topic(kv_evt_ctx, "$share/njet//rpc/#");
        snprintf(worker_topic, 31, "/worker_%d/#", (int)njt_worker);
        njet_iot_client_add_topic(kv_evt_ctx, worker_topic);
    } else if (njt_process == NJT_PROCESS_HELPER && njt_is_privileged_agent) {
        njet_iot_client_add_topic(kv_evt_ctx, "/ins/srv/#");
        njet_iot_client_add_topic(kv_evt_ctx, "/ins/loc/#");
        njet_iot_client_add_topic(kv_evt_ctx, "/ins/ssl/#");
        njet_iot_client_add_topic(kv_evt_ctx, "/dyn/#");
        snprintf(worker_topic, 31, "/worker_a/#");
        njet_iot_client_add_topic(kv_evt_ctx, worker_topic);
    }
    ret = njet_iot_client_connect(3, 5, kv_evt_ctx);
    if (0 != ret) {
        njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "worker mqtt client connect failed, schedule:%d", ret);
        njt_http_kv_iot_set_timer(njt_http_kv_iot_conn_timeout, 2000, kv_evt_ctx);
    } else {
        njt_http_kv_iot_register_outside_reader(njt_http_kv_loop_mqtt, kv_evt_ctx);
    };

    return NJT_OK;
};

static void kv_exit_worker(njt_cycle_t *cycle)
{
    njt_queue_t *q;
    kv_change_handler_t *handler;
    njet_iot_client_exit(kv_evt_ctx);
    if (kv_handler_hashmap) {
        q = njt_queue_head(&kv_handler_queue);
        while (q != njt_queue_sentinel(&kv_handler_queue)) {
            handler = njt_queue_data(q, kv_change_handler_t, queue);
            q = njt_queue_next(q);
            njt_lvlhsh_map_remove(kv_handler_hashmap, handler->callbacks.key);
            njt_free(handler->callbacks.key->data);
            njt_free(handler->callbacks.key);
            njt_free(handler);
        }
        njt_free(kv_handler_hashmap);
    }
}

njt_int_t njt_http_kv_get(njt_http_request_t *r, njt_http_variable_value_t *v, uintptr_t data)
{
    njt_str_t *var;
    njt_str_t dbm_val;
    u_int32_t val_len = 0;

    if (kv_evt_ctx == NULL) {
        v->not_found = 1;
        return NJT_OK;
    }
    // todo: assume data is variable name:
    var = (njt_str_t *)data;

    int ret = njet_iot_client_kv_get(var->data, var->len, (void **)&dbm_val.data, &val_len, kv_evt_ctx);
    if (ret != 0) {
        v->not_found = 1;
        return NJT_OK;
    }
    dbm_val.len = val_len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = val_len;
    v->data = njt_pstrdup(r->pool, &dbm_val);
    return NJT_OK;
}

static void *
njt_http_kv_create_conf(njt_conf_t *cf)
{
    njt_http_kv_conf_t *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_kv_conf_t));

    if (conf == NULL) {
        return NULL;
    }

    conf->conf_file.data = NULL;
    conf->conf_file.len = 0;
    return conf;
}

static char *
njt_dyn_conf_set(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_str_t *value;
    njt_http_kv_conf_t *kvcf;
    njt_str_t dst;
    u_char *p;
    value = cf->args->elts;
    kvcf = (njt_http_kv_conf_t *)conf;

    kv_evt_ctx = NULL;
    if (cf->args->nelts <= 1) {
        //helper process's kv module default is off
        if (njt_process == NJT_PROCESS_HELPER) {
            kvcf->off = 1;
        } else {
            kvcf->off = 0;
        }
        kvcf->conf_file.data = NULL;
        kvcf->conf_file.len = 0;
        return NJT_CONF_OK;
    }

    if (njt_strcmp(value[1].data, "off") == 0) {
        kvcf->off = 1;
        return NJT_CONF_OK;
    }

    kvcf->off = 0;
    dst.data = njt_pnalloc(cf->pool, value[1].len + 1);
    if (dst.data == NULL) {
        return NJT_CONF_ERROR;
    }
    dst.len = value[1].len;
    p = njt_copy(dst.data, value[1].data, value[1].len);
    *p = '\0';

    if (njt_get_full_name(cf->pool, (njt_str_t *)&njt_cycle->prefix, &dst) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    kvcf->conf_file.data = dst.data;
    kvcf->conf_file.len = dst.len;
    return NJT_CONF_OK;
}

static njt_http_variable_t njt_http_kv_vars[] = {
    {njt_string("kv_http_"), NULL, njt_http_kv_get, 0, NJT_HTTP_VAR_NOCACHEABLE | NJT_HTTP_VAR_PREFIX, 0, NJT_VAR_INIT_REF_COUNT},
    njt_http_null_variable };

static njt_int_t
njt_http_kv_add_variables(njt_conf_t *cf)
{
    njt_http_variable_t *var, *v;

    njt_rbtree_init(&kv_tree, &kv_sentinel,
        njt_http_kv_rbtree_insert_value);
    for (v = njt_http_kv_vars; v->name.len; v++) {
        var = njt_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NJT_ERROR;
        }
        var->get_handler = v->get_handler;
        var->data = v->data;
    }
    return NJT_OK;
}

int njt_kv_reg_handler(njt_kv_reg_handler_t *h)
{
    if (!h || !h->key || h->key->len == 0) {
        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "kv handler registering key is empty");
        return NJT_OK;
    }
    kv_change_handler_t *kv_handler, *old_handler;
    if (kv_handler_hashmap == NULL) {
        kv_handler_hashmap = njt_calloc(sizeof(njt_lvlhash_map_t), njt_cycle->log);
        njt_queue_init(&kv_handler_queue);
    }
    kv_handler = njt_calloc(sizeof(kv_change_handler_t), njt_cycle->log);

    if (kv_handler == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "can't not malloc handler's memory while reg kv handler for key :%V ", h->key);
        return NJT_ERROR;
    }
    kv_handler->callbacks.api_type = h->api_type;
    kv_handler->callbacks.key = njt_calloc(sizeof(njt_str_t), njt_cycle->log);
    if (kv_handler->callbacks.key == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "can't not malloc handler key's memory while reg kv handler for key :%V ", h->key);
        return NJT_ERROR;
    }
    kv_handler->callbacks.key->data = (u_char *)njt_calloc(h->key->len, njt_cycle->log);
    if (kv_handler->callbacks.key->data == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "can't not malloc handler key's memory while reg kv handler for key :%V ", h->key);
        return NJT_ERROR;
    }
    njt_memcpy(kv_handler->callbacks.key->data, h->key->data, h->key->len);
    kv_handler->callbacks.key->len = h->key->len;

    kv_handler->callbacks.data = h->data;
    kv_handler->callbacks.handler = h->handler;
    kv_handler->callbacks.rpc_get_handler = h->rpc_get_handler;
    kv_handler->callbacks.rpc_put_handler = h->rpc_put_handler;
    njt_queue_insert_tail(&kv_handler_queue, &kv_handler->queue);
    njt_lvlhsh_map_put(kv_handler_hashmap, kv_handler->callbacks.key, (intptr_t)kv_handler, (intptr_t *)&old_handler);
    // if handler existed with the same key in the hashmap
    if (old_handler && old_handler != kv_handler) {
        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "Key :%V has been registered, please double check", h->key);
        njt_free(old_handler->callbacks.key->data);
        njt_free(old_handler);
    }
    return NJT_OK;
}

static void invoke_kv_change_handler(njt_str_t *key, njt_str_t *value)
{
    njt_int_t rc;
    kv_change_handler_t *kv_handler;
    if (value == NULL || value->len == 0) {
        return;
    }
 
    if (kv_handler_hashmap) {
        rc = njt_lvlhsh_map_get(kv_handler_hashmap, key, (intptr_t *)&kv_handler);
        if (rc == NJT_OK && kv_handler->callbacks.handler) {
            kv_handler->callbacks.handler(key, value, kv_handler->callbacks.data);
        }
    }
}

static njt_int_t njt_kv_get_hashkey_from_topic(const char *topic, njt_str_t *hash_key)
{
    njt_uint_t i, s;
    njt_uint_t index[5] = { 0 };  //max 5 level in topic
    if (njt_strncmp(topic, WORKER_TOPIC_PREFIX, WORKER_TOPIC_PREFIX_LEN) == 0) {
        //  found third field, /worker_n/dyn/loc/l_12323, third  field is "loc", length is 3
        s = 1;
        for (i = WORKER_TOPIC_PREFIX_LEN; i < strlen(topic); i++) {
            if (topic[i] == '/') {
                index[s] = i;
                s++;
            }
            if (s == 4) break;
        }
        if (s <= 2) {
            return NJT_ERROR;
        }

        hash_key->len = i - index[2] - 1;
        hash_key->data = (u_char *)topic + index[2] + 1;
        return NJT_OK;
    }
    if (strlen(topic) > DYN_TOPIC_PREFIX_LEN && njt_strncmp(topic, "/", 1) == 0) {
        //  found second field, /prefix/log, second  field is "log", length is 3
        s = 1;
        for (i = 1; i < strlen(topic); i++) {
            if (topic[i] == '/') {
                index[s] = i;
                s++;
            }
            if (s == 3) break;
        }
        if (s <= 1) {
            return NJT_ERROR;
        }

        hash_key->len = i - index[1] - 1;
        hash_key->data = (u_char *)topic + index[1] + 1;
        return NJT_OK;
    }

    return NJT_ERROR;
}

static void invoke_topic_msg_handler(const char *topic, const char *msg, int msg_len)
{
    njt_str_t nstr_topic;
    njt_str_t nstr_msg;
    njt_str_t hash_key;
    njt_int_t rc;
    kv_change_handler_t *tm_handler;
    // a zero length msg is sent to clear retained message, so skip zero length msg
    if (msg == NULL || msg_len == 0) {
        return;
    }
    if (kv_handler_hashmap) {
        rc = njt_kv_get_hashkey_from_topic(topic, &hash_key);
        if (rc == NJT_OK) {
            rc = njt_lvlhsh_map_get(kv_handler_hashmap, &hash_key, (intptr_t *)&tm_handler);
            if (rc == NJT_OK && tm_handler->callbacks.handler) {
                nstr_topic.data = (u_char *)topic;
                nstr_topic.len = strlen(topic);
                nstr_msg.data = (u_char *)msg;
                nstr_msg.len = msg_len;
                tm_handler->callbacks.handler(&nstr_topic, &nstr_msg, tm_handler->callbacks.data);
            }
        }
    }
}

static u_char *invoke_rpc_handler(const char *topic, const char *msg, int msg_len, int *len)
{
    njt_str_t nstr_topic;
    njt_str_t hash_key;
    njt_str_t nstr_msg;
    njt_int_t rc;
    kv_change_handler_t *kv_handler;
    bool send_full_conf;
    njt_str_t send_topic;
    njt_str_t full_conf;
    njt_str_t get_data = njt_string("");
    int full_conf_len;

    if (strlen(topic) <= 5) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "in njt_http_kv_module, got wrong topic:%s ", topic);
        *len = 0;
        return NULL;
    }
    if (kv_handler_hashmap) {
        rc = njt_kv_get_hashkey_from_topic(topic, &hash_key);
        if (rc == NJT_OK) {
            rc = njt_lvlhsh_map_get(kv_handler_hashmap, &hash_key, (intptr_t *)&kv_handler);
            if (rc == NJT_OK) {
                nstr_topic.data = (u_char *)topic;
                nstr_topic.len = strlen(topic);
                nstr_msg.data = (u_char *)msg;
                nstr_msg.len = msg_len;
                if (njt_strstr(topic, RPC_TOPIC_PREFIX) != NULL
                    && kv_handler->callbacks.rpc_get_handler) {
                    return kv_handler->callbacks.rpc_get_handler(&nstr_topic, &nstr_msg, len, kv_handler->callbacks.data);
                } else if (kv_handler->callbacks.rpc_put_handler) {
                    u_char *ret_str = kv_handler->callbacks.rpc_put_handler(&nstr_topic, &nstr_msg, len, kv_handler->callbacks.data);
                    send_full_conf = false;
                    //if it is declative api and it is in worker_a, get the full configuration and broadcast it
                    if (kv_handler->callbacks.api_type == NJT_KV_API_TYPE_DECLATIVE
                        && kv_handler->callbacks.rpc_get_handler
                        && strlen(topic) > 10 
                        && (njt_strncmp(topic, "/worker_a/", 10) == 0 || njt_strncmp(topic, "/worker_p/", 10) == 0) ) {
                        send_full_conf = true;
                        // remove prefix /worker_{a,p} 
                        send_topic.len = strlen(topic) - 9;
                        send_topic.data = njt_calloc(send_topic.len, njt_cycle->log);
                        if (send_topic.data == NULL) {
                            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "can't malloc memory for send_topic in kv handler");
                            send_full_conf = false;
                        }
                        njt_memcpy(send_topic.data, (u_char *)topic + 9, strlen(topic) - 9);
                    }
                    // instructional api
                    if (kv_handler->callbacks.api_type == NJT_KV_API_TYPE_INSTRUCTIONAL
                        && kv_handler->callbacks.rpc_get_handler
                        && strlen(topic) > 14 
                        && (njt_strncmp(topic, "/worker_a/ins/", 14) == 0 || njt_strncmp(topic, "/worker_p/ins/", 14) == 0) ) {
                        //change topic /worker_{a,p}/ins/# -> /dyn/# 
                        send_full_conf = true;
                        send_topic.len = 5 + hash_key.len; // /dyn/${hash_key}
                        send_topic.data = njt_calloc(send_topic.len, njt_cycle->log);
                        if (send_topic.data == NULL) {
                            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "can't malloc memory for send_topic in kv handler");
                            send_full_conf = false;
                        } else {
                            njt_memcpy(send_topic.data, "/dyn/", 5);
                            njt_memcpy(send_topic.data + 5, hash_key.data, hash_key.len);
                        }
                    }
                    if (send_full_conf) {
                        //get full configuration, all rpc get handler should response to empty get string
                        full_conf.data = kv_handler->callbacks.rpc_get_handler(&send_topic, &get_data, &full_conf_len, kv_handler->callbacks.data);
                        full_conf.len = full_conf_len;
                        if (full_conf.data) {
                            //send out the full configuration with retain flag 
                            njt_kv_sendmsg(&send_topic, &full_conf, 1);
                            njt_free(full_conf.data);
                        }
                        njt_free(send_topic.data);
                    }
                    return ret_str;
                }
            }
        }
    }
    //if there is no rpc handler found in hashmap
    u_char nohandler[] = "{\"code\":-1, \"msg\":\"no rpc handler registered\"}";
    u_char *pchar = njt_calloc(46, njt_cycle->log);
    njt_memcpy(pchar, nohandler, 46);
    *len = 46;
    return pchar;
}

int njt_kv_sendmsg(njt_str_t *topic, njt_str_t *content, int retain_flag)
{
    int ret = 0;
    int qos = 0;
    if (retain_flag)
        qos = RETAIN_MSG_QOS;

    u_char *t;
    t = njt_calloc(topic->len + 1, njt_cycle->log);
    if (t == NULL) {
        return NJT_ERROR;
    }
    njt_memcpy(t, topic->data, topic->len);
    t[topic->len] = '\0';
    // if it is a normal message, send zero length retain msg to same topic to delete it
    if (!retain_flag) {
        ret = njet_iot_client_sendmsg((const char *)t, "", 0, RETAIN_MSG_QOS, kv_evt_ctx);
    }
    if (ret < 0) {
        goto error;
    }
    ret = njet_iot_client_sendmsg((const char *)t, (const char *)content->data, (int)content->len, qos, kv_evt_ctx);
    if (ret < 0) {
        goto error;
    }
    njt_free(t);
    return NJT_OK;
error:
    njt_free(t);
    return NJT_ERROR;
}

int njt_db_kv_get(njt_str_t *key, njt_str_t *value)
{
    uint32_t val_len = 0;
    if (key == NULL || key->data == NULL || value == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "njt_db_kv_get got wrong key:value data");
        return NJT_ERROR;
    }
    // type of njt_str_t.len is size_t, in 64bit arch, it is not uint32_t,  
    // force type conversion will not work in big-endian arch, 
    // and even in little-endian arch, if value->len is not initialized, only low bytes will be set
    // so use temporary variable when invoke lib api, and then assign to value->len 
    int ret = njet_iot_client_kv_get((void *)key->data, key->len, (void **)&value->data, &val_len, kv_evt_ctx);
    value->len=val_len;

    if (ret < 0) {
        return NJT_ERROR;
    }
    return NJT_OK;
}
int njt_db_kv_set(njt_str_t *key, njt_str_t *value)
{
    if (key == NULL || value == NULL || key->data == NULL || value->data == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "njt_db_kv_set got wrong key:value data");
        return NJT_ERROR;
    }
    int ret = njet_iot_client_kv_set(key->data, key->len, value->data, value->len, NULL, kv_evt_ctx);
    if (ret < 0) {
        return NJT_ERROR;
    }
    return NJT_OK;
}
int njt_db_kv_del(njt_str_t *key)
{
    if (key->data == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "njt_db_kv_del got wrong key data");
        return NJT_ERROR;
    }
    int ret = njet_iot_client_kv_del(key->data, key->len, NULL, 0, kv_evt_ctx);
    if (ret < 0) {
        return NJT_ERROR;
    }
    return NJT_OK;
}
