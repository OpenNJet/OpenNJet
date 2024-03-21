/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */
#include <njt_config.h>
#include <njt_http.h>
#include <njt_json_api.h>

#include "njet_iot_emb.h"
#include "njt_http_sendmsg_module.h"
#include <njt_mqconf_module.h>
#include <njt_hash_util.h>
#include "njt_http_api_register_module.h"

#define RPC_TOPIC_PREFIX "/dyn/"
#define RPC_TOPIC_PREFIX_LEN 5
#define RPC_DEFAULT_TIMEOUT_MS 2000
#define RETAIN_MSG_QOS 16

typedef struct
{
    void *data;
    int session_id;  //mqtt session_id
    int invoker_session_id; //dyn rpc method invoker session_id
    njt_str_t key;
    rpc_msg_handler handler;
    njt_event_t *ev;
} rpc_msg_handler_t;

typedef struct
{
    njt_str_t conf_file;
    njt_uint_t off;
    njt_msec_t rpc_timeout;
} njt_http_sendmsg_conf_t;

typedef struct
{
    unsigned waiting_request_body : 1;
    unsigned request_body_done : 1;
} njt_http_sendmsg_ctx_t;

typedef struct
{
    njt_str_t key;
    njt_str_t value;
    njt_pool_t *pool;
    njt_int_t code;
} njt_http_sendmsg_post_data_t;

// sendmsg module is running in ctrl panel, should be able to get njet_master_cycle from njet_helper_ctrl_module
extern njt_cycle_t *njet_master_cycle;
static void njt_http_sendmsg_iot_conn_timeout(njt_event_t *ev);
static void njt_http_sendmsg_iot_set_timer(njt_event_handler_pt h, int interval, struct evt_ctx_t *ctx);
static void njt_http_sendmsg_loop_mqtt(njt_event_t *ev);
static void njt_http_sendmsg_iot_register_outside_reader(njt_event_handler_pt h, struct evt_ctx_t *ctx);
static njt_int_t sendmsg_init_worker(njt_cycle_t *cycle);
static void sendmsg_exit_worker(njt_cycle_t *cycle);
static char *njt_dyn_sendmsg_conf_set(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static char *njt_dyn_sendmsg_rpc_timeout_set(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static njt_int_t njt_http_sendmsg_init(njt_conf_t *cf);
static njt_int_t njt_http_sendmsg_handler(njt_http_request_t *r);
static void *njt_http_sendmsg_create_conf(njt_conf_t *cf);
static int njt_reg_rpc_msg_handler(int msg_session_id, int invoker_session_id, rpc_msg_handler handler, void *data, njt_event_t *ev);
static void invoke_rpc_msg_handler(int rc, int session_id, const char *msg, int msg_len);
static void sendmsg_get_session_id_str(int session_id, njt_str_t *sk);

static njt_lvlhash_map_t *rpc_msg_handler_hashmap = NULL;
static struct evt_ctx_t *sendmsg_mqtt_ctx;

static njt_http_module_t njt_http_sendmsg_module_ctx = {
    NULL,                  /* preconfiguration */
    njt_http_sendmsg_init, /* postconfiguration */

    njt_http_sendmsg_create_conf, /* create main configuration */
    NULL,                         /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    NULL, /* create location configuration */
    NULL  /* merge location configuration */
};

static njt_command_t njt_sendmsg_commands[] = {

    {njt_string("dyn_sendmsg_conf"),
     NJT_HTTP_MAIN_CONF | NJT_CONF_NOARGS | NJT_CONF_TAKE1,
     njt_dyn_sendmsg_conf_set,
     0,
     0,
     NULL},
    {njt_string("dyn_sendmsg_rpc_timeout"),
     NJT_HTTP_MAIN_CONF | NJT_CONF_TAKE1,
     njt_dyn_sendmsg_rpc_timeout_set,
     0,
     0,
     NULL},
    njt_null_command /* command termination */
};

njt_module_t njt_http_sendmsg_module = {
    NJT_MODULE_V1,
    &njt_http_sendmsg_module_ctx, /* module context */
    njt_sendmsg_commands,         /* module directives */
    NJT_HTTP_MODULE,              /* module type */
    NULL,                         /* init master */
    NULL,                         /* init module */
    sendmsg_init_worker,          /* init process */
    NULL,                         /* init thread */
    NULL,                         /* exit thread */
    sendmsg_exit_worker,          /* exit process */
    NULL,                         /* exit master */
    NJT_MODULE_V1_PADDING};

static void njt_http_sendmsg_loop_mqtt(njt_event_t *ev)
{
    int ret;
    njt_connection_t *c = (njt_connection_t *)ev->data;
    struct evt_ctx_t *ctx = (struct evt_ctx_t *)c->data;
    if (ev->timer_set)
    {
        njt_del_timer(ev);
    }
    ret = njet_iot_client_run(ctx);
    switch (ret)
    {
    case 0:
        njt_add_timer(ev, 50);
        return;
    case 4:  // no connection
    case 19: // lost keepalive
    case 7:  // lost connection
        njt_http_sendmsg_iot_set_timer(njt_http_sendmsg_iot_conn_timeout, 10, ctx);
        njt_del_event(ev, NJT_READ_EVENT, NJT_CLOSE_EVENT);
        break;
    default:
        njt_log_error(NJT_LOG_ERR, ev->log, 0, "mqtt client run:%d, what todo ?", ret);
        njt_http_sendmsg_iot_set_timer(njt_http_sendmsg_iot_conn_timeout, 10, ctx);
        njt_del_event(ev, NJT_READ_EVENT, NJT_CLOSE_EVENT);
    }
    return;
}
static void njt_http_sendmsg_iot_conn_timeout(njt_event_t *ev)
{
    njt_connection_t *c = (njt_connection_t *)ev->data;
    struct evt_ctx_t *ctx = (struct evt_ctx_t *)c->data;
    int ret;
    if (ev->timedout)
    {
        ret = njet_iot_client_connect(3, 5, ctx);
        if (ret != 0)
        {
            if (ret == -5)
            {
                //client is connecting or has connected
                return;
            }
            njt_add_timer(ev, 1000);
        }
        else
        {
            //connect ok, register io
            njt_http_sendmsg_iot_register_outside_reader(njt_http_sendmsg_loop_mqtt, ctx);
        }
    }
}

static void njt_http_sendmsg_iot_register_outside_reader(njt_event_handler_pt h, struct evt_ctx_t *ctx)
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
    rev->cancelable = 1;
    rev->data = c;

    wev->data = c;
    wev->log = njt_cycle->log;
    wev->ready = 1;

    c->fd = (njt_socket_t)fd;
    // c->data=cycle;
    c->data = ctx;

    c->read = rev;
    c->write = wev;

    njt_log_error(NJT_LOG_NOTICE, rev->log, 0, "sendmsg module connect ok, register socket:%d", fd);
    if (njt_add_event(rev, NJT_READ_EVENT, 0) != NJT_OK)
    {
        njt_log_error(NJT_LOG_ERR, rev->log, 0, "add io event for mqtt failed");
        return;
    }
    njt_add_timer(rev, 1000); // tips: trigger every 1s at least, to process misc things like ping/pong
}

static void njt_http_sendmsg_iot_set_timer(njt_event_handler_pt h, int interval, struct evt_ctx_t *ctx)
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

static njt_int_t
njt_http_sendmsg_init(njt_conf_t *cf)
{
    njt_http_api_reg_info_t             h;

    njt_str_t  module_key = njt_string("/v1/kv");
    njt_memzero(&h, sizeof(njt_http_api_reg_info_t));
    h.key = &module_key;
    h.handler = njt_http_sendmsg_handler;
    njt_http_api_module_reg_handler(&h);

    return NJT_OK;
}

static njt_int_t sendmsg_api_get_handler(njt_http_request_t *r)
{
    njt_buf_t *b;
    njt_chain_t out;
    njt_str_t key, lmdb_key;
    njt_str_t value;
    njt_int_t ok;

    value.len = 0;
    value.data = NULL;
    if (r->args.len)
    {
        if (njt_http_arg(r, (u_char *)"key", 3, &key) == NJT_OK)
        {

            lmdb_key.data = njt_pcalloc(r->pool, key.len + 8); // lmdb's prefix is kv_http_
            if (lmdb_key.data == NULL)
            {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "dyn_sendmsg_kv njt_pcalloc topic name error.");
                njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
                return NJT_DONE;
            }
            njt_memcpy(lmdb_key.data, "kv_http_", 8);
            njt_memcpy(lmdb_key.data + 8, key.data, key.len);
            lmdb_key.len = key.len + 8;

            ok = njt_dyn_kv_get(&lmdb_key, &value);
            if (ok == NJT_OK)
            {
                njt_log_error(NJT_LOG_INFO, r->connection->log, 0, "key %V found, value: %V", &lmdb_key, &value);
            }
            else
            {
                njt_log_error(NJT_LOG_INFO, r->connection->log, 0, "key %V not found", &lmdb_key, &value);
            }
        }
    }

    r->headers_out.content_type_len = sizeof("text/plain") - 1;
    njt_str_set(&r->headers_out.content_type, "text/plain");

    b = njt_pcalloc(r->pool, sizeof(njt_buf_t));
    out.buf = b;
    out.next = NULL;
    b->memory = 1;
    b->last_buf = 1;

    char *not_found = "key is not existed in db\n";
    if (value.len > 0)
    {
        b->pos = value.data;
        b->last = value.data + value.len;
        r->headers_out.status = NJT_HTTP_OK;
        r->headers_out.content_length_n = value.len;
    }
    else
    {
        b->pos = (u_char *)not_found;
        b->last = (u_char *)(not_found + strlen(not_found));
        r->headers_out.status = NJT_HTTP_NOT_FOUND;
        r->headers_out.content_length_n = strlen(not_found);
    }

    njt_http_send_header(r);

    return njt_http_output_filter(r, &out);
}

static njt_int_t sendmsg_api_del_handler(njt_http_request_t *r)
{
    njt_buf_t *b;
    njt_chain_t out;
    njt_str_t key, lmdb_key;
    njt_int_t ok = NJT_ERROR;

    if (r->args.len)
    {
        if (njt_http_arg(r, (u_char *)"key", 3, &key) == NJT_OK)
        {

            lmdb_key.data = njt_pcalloc(r->pool, key.len + 8); // lmdb's prefix is kv_http_
            if (lmdb_key.data == NULL)
            {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "dyn_sendmsg_kv njt_pcalloc topic name error.");
                njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
                return NJT_DONE;
            }
            njt_memcpy(lmdb_key.data, "kv_http_", 8);
            njt_memcpy(lmdb_key.data + 8, key.data, key.len);
            lmdb_key.len = key.len + 8;

            ok = njt_dyn_kv_del(&lmdb_key);
            if (ok != NJT_OK)
            {
                njt_log_error(NJT_LOG_INFO, r->connection->log, 0, "key %V not found", &lmdb_key);
            }
        }
    }

    r->headers_out.content_type_len = sizeof("text/plain") - 1;
    njt_str_set(&r->headers_out.content_type, "text/plain");

    b = njt_pcalloc(r->pool, sizeof(njt_buf_t));
    out.buf = b;
    out.next = NULL;
    b->memory = 1;
    b->last_buf = 1;

    char *not_found = "key is not existed in db\n";
    char *del_ok = "key is deleted from db\n";
    if (ok == NJT_OK)
    {
        b->pos = (u_char *)del_ok;
        b->last = (u_char *)(del_ok + strlen(del_ok));
        r->headers_out.status = NJT_HTTP_OK;
        r->headers_out.content_length_n = strlen(del_ok);
    }
    else
    {
        b->pos = (u_char *)not_found;
        b->last = (u_char *)(not_found + strlen(not_found));
        r->headers_out.status = NJT_HTTP_NOT_FOUND;
        r->headers_out.content_length_n = strlen(not_found);
    }

    njt_http_send_header(r);

    return njt_http_output_filter(r, &out);
}

static njt_http_sendmsg_post_data_t *njt_http_parser_sendmsg_data(njt_str_t json_str)
{
    njt_json_manager json_body;
    njt_pool_t *sendmsg_pool;
    njt_http_sendmsg_post_data_t *postdata;
    njt_int_t rc;

    sendmsg_pool = njt_create_pool(NJT_DEFAULT_POOL_SIZE, njt_cycle->log);
    if (sendmsg_pool == NULL)
    {
        return NULL;
    }

    rc = njt_json_2_structure(&json_str, &json_body, sendmsg_pool);
    if (rc != NJT_OK)
    {
        rc = NJT_ERROR;
        njt_destroy_pool(sendmsg_pool);
        return NULL;
    }
    postdata = njt_pcalloc(sendmsg_pool, sizeof(njt_http_sendmsg_post_data_t));
    if (postdata == NULL)
    {
        njt_destroy_pool(sendmsg_pool);
        return NULL;
        ;
    }

    postdata->pool = sendmsg_pool;
    postdata->code = 0;

    njt_str_t key;
    njt_str_set(&key, "key");
    njt_json_element *out_element;
    rc = njt_struct_top_find(&json_body, &key, &out_element);
    if (rc != NJT_OK)
    {
        njt_destroy_pool(sendmsg_pool);
        return NULL;
    }

    if (out_element->type != NJT_JSON_STR)
    {
        postdata->code = 1; // key error
    }
    else
    {
        postdata->key = out_element->strval;
    }

    // find value
    njt_str_set(&key, "value");

    rc = njt_struct_top_find(&json_body, &key, &out_element);
    if (rc != NJT_OK)
    {
        njt_destroy_pool(sendmsg_pool);
        return NULL;
    }
    else
    {
        if (out_element->type != NJT_JSON_STR)
        {
            postdata->code = 2; // value error
        }
        else
        {
            postdata->value = out_element->strval;
        }
    }

    return postdata;
}

static void sendmsg_api_post_handler(njt_http_request_t *r)
{
    njt_uint_t status;
    njt_str_t json_str, topic_name, lmdb_name;
    njt_chain_t *body_chain;
    njt_http_sendmsg_post_data_t *postdata;

    if (r->request_body == NULL || r->request_body->bufs == NULL)
    {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "POST request body is unavailable");
        njt_http_finalize_request(r, NJT_HTTP_BAD_REQUEST);
        return;
    }
    body_chain = r->request_body->bufs;
    if (body_chain && body_chain->next)
    {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "dyn_sendmsg_kv error, post data is too large");
        njt_http_finalize_request(r, NJT_HTTP_BAD_REQUEST);
        return;
    }

    /*check the sanity of the json body*/
    json_str.data = body_chain->buf->pos;
    json_str.len = body_chain->buf->last - body_chain->buf->pos;
    postdata = njt_http_parser_sendmsg_data(json_str);
    if (postdata == NULL)
    {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "dyn_sendmsg_kv error, post data is not valid");
        njt_http_finalize_request(r, NJT_HTTP_BAD_REQUEST);
        return;
    }

    if (postdata->code != 0)
    {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "dyn_sendmsg_kv error, post data is not valid");
        njt_destroy_pool(postdata->pool);
        njt_http_finalize_request(r, NJT_HTTP_BAD_REQUEST);
        return;
    }

    topic_name.data = njt_pcalloc(r->pool, postdata->key.len + 13); // topic's prefix is /dyn/kv_http_
    if (topic_name.data == NULL)
    {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "dyn_sendmsg_kv njt_pcalloc topic name error.");
        njt_destroy_pool(postdata->pool);
        njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    njt_memcpy(topic_name.data, "/dyn/kv_http_", 13);
    njt_memcpy(topic_name.data + 13, postdata->key.data, postdata->key.len);
    topic_name.len = postdata->key.len + 13;
    lmdb_name.data = topic_name.data + 5; // lmdb key prefix is kv_http_
    lmdb_name.len = topic_name.len - 5;

    njt_dyn_sendmsg(&topic_name, &postdata->value, 1);
    njt_dyn_kv_set(&lmdb_name, &postdata->value);
    if (njt_strncmp(postdata->key.data, "__master_", 9)==0) {
        kill(njt_parent, SIGCONF);
    }

    njt_destroy_pool(postdata->pool);
    status = NJT_HTTP_OK;
    r->headers_out.content_length_n = 0;
    r->headers_out.status = status;
    r->header_only = 1;

    njt_http_finalize_request(r, njt_http_send_header(r));
    return;
}

static njt_int_t
njt_http_sendmsg_handler(njt_http_request_t *r)
{
    njt_int_t rc;

    if (r->method == NJT_HTTP_GET)
    {
        njt_http_discard_request_body(r);
        return sendmsg_api_get_handler(r);
    }
    if (r->method == NJT_HTTP_POST)
    {
        rc = njt_http_read_client_request_body(r, sendmsg_api_post_handler);

        if (rc >= NJT_HTTP_SPECIAL_RESPONSE)
        {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "dyn_sendmsg_kv handler error: read_client_request_body");

            return rc;
        }

        return NJT_DONE;
    } 
    if (r->method == NJT_HTTP_DELETE)
    {
        njt_http_discard_request_body(r);
        return sendmsg_api_del_handler(r);
    } 
    return NJT_DECLINED;
}

static char *sendmsg_rr_callback(const char *topic, int is_reply, const char *msg, int msg_len, int session_id, int *out_len)
{
    njt_str_t topic_str, msg_str;
    topic_str.data = (u_char *)topic;
    topic_str.len = strlen(topic);
    msg_str.data = (u_char *)msg;
    msg_str.len = msg_len;

    //to avoid unused-but-set-variable warning
    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "sendmsg got msg, topic: %V, msg:%V, seesion_id: %d", &topic_str, &msg_str, session_id);

    if (is_reply)
    {
        invoke_rpc_msg_handler(RPC_RC_OK, session_id, msg, msg_len);
    }

    *out_len = 0;
    return NULL;
}

static njt_int_t sendmsg_init_worker(njt_cycle_t *cycle)
{
    njt_http_conf_ctx_t *conf_ctx;
    njt_http_sendmsg_conf_t *smcf;
    njt_uint_t i;
    int ret;
    njt_mqconf_conf_t *mqconf = NULL;
    char client_id[128] = {0};
    char log[1024] = {0};
    char localcfg[1024] = {0};
    // return when there is no http configuraton
    if (njt_http_sendmsg_module.ctx_index == NJT_CONF_UNSET_UINT)
    {
        return NJT_OK;
    }
    njt_cycle_t *mq_cycle = cycle;
    if (njet_master_cycle)
    {
        mq_cycle = njet_master_cycle;
    }
    for (i = 0; i < mq_cycle->modules_n; i++)
    {
        if (njt_strcmp(mq_cycle->modules[i]->name, "njt_mqconf_module") != 0)
            continue;
        mqconf = (njt_mqconf_conf_t *)(mq_cycle->conf_ctx[mq_cycle->modules[i]->index]);
        break;
    }
    if (!mqconf || !mqconf->cluster_name.data || !mqconf->node_name.data)
    {
        njt_log_error(NJT_LOG_INFO, cycle->log, 0, "mqconf check failed, sendmsg module is not loaded");
        return NJT_OK;
    }

    conf_ctx = (njt_http_conf_ctx_t *)njt_get_conf(cycle->conf_ctx, njt_http_module);
    if (!conf_ctx) {
        njt_log_error(NJT_LOG_INFO, cycle->log, 0, "http section not found, sendmsg module is configured as off");
        return NJT_OK;
    }
    smcf = conf_ctx->main_conf[njt_http_sendmsg_module.ctx_index];
    if (!smcf || smcf->off) {
        njt_log_error(NJT_LOG_INFO, cycle->log, 0, "sendmsg module is configured as off");
        return NJT_OK;  
    }
    memcpy(client_id, mqconf->node_name.data, mqconf->node_name.len);
    sprintf(client_id + mqconf->node_name.len, "_msg_%d", njt_pid);

    memcpy(log, njt_cycle->prefix.data, njt_cycle->prefix.len);
    sprintf(log + njt_cycle->prefix.len, "logs/sendmsg_%d", (int)njt_process_slot);

    memcpy(localcfg, smcf->conf_file.data, smcf->conf_file.len);
    localcfg[smcf->conf_file.len] = '\0';

    char *prefix;
    prefix = njt_calloc(cycle->prefix.len + 1, cycle->log);
    njt_memcpy(prefix, cycle->prefix.data, cycle->prefix.len);
    prefix[cycle->prefix.len] = '\0';
    sendmsg_mqtt_ctx = njet_iot_client_init(prefix, localcfg, sendmsg_rr_callback, NULL, client_id, log, cycle);
    njt_free(prefix);
    if (sendmsg_mqtt_ctx == NULL)
    {
        njt_log_error(NJT_LOG_ERR, cycle->log, 0, "init local mqtt client failed, exiting");
        njet_iot_client_exit(sendmsg_mqtt_ctx);
        return NJT_ERROR;
    };
    ret = njet_iot_client_connect(3, 5, sendmsg_mqtt_ctx);
    if (0 != ret)
    {
        njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "worker mqtt client connect failed, schedule:%d", ret);
        njt_http_sendmsg_iot_set_timer(njt_http_sendmsg_iot_conn_timeout, 2000, sendmsg_mqtt_ctx);
    }
    else
    {
        njt_http_sendmsg_iot_register_outside_reader(njt_http_sendmsg_loop_mqtt, sendmsg_mqtt_ctx);
    };

    return NJT_OK;
};

static void sendmsg_exit_worker(njt_cycle_t *cycle)
{
    if(rpc_msg_handler_hashmap) {
       njt_free(rpc_msg_handler_hashmap);
    }
    njet_iot_client_exit(sendmsg_mqtt_ctx);
}

static void *
njt_http_sendmsg_create_conf(njt_conf_t *cf)
{
    njt_http_sendmsg_conf_t *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_sendmsg_conf_t));

    if (conf == NULL)
    {
        return NULL;
    }

    conf->conf_file.data = NULL;
    conf->conf_file.len = 0;
    conf->rpc_timeout = RPC_DEFAULT_TIMEOUT_MS;
    return conf;
}

static char *njt_dyn_sendmsg_rpc_timeout_set(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_str_t *value;
    njt_msec_t ms;
    njt_http_sendmsg_conf_t *smcf;
    smcf = (njt_http_sendmsg_conf_t *)conf;

    value = cf->args->elts;

    ms = njt_parse_time(&value[1], 0);
    if (ms == (njt_msec_t)NJT_ERROR)
    {
        return NJT_CONF_ERROR;
    }

    smcf->rpc_timeout = ms;
    return NJT_CONF_OK;
}

static char *
njt_dyn_sendmsg_conf_set(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_str_t *value;
    njt_http_sendmsg_conf_t *smcf;
    njt_str_t dst;
    u_char *p;

    value = cf->args->elts;
    smcf = (njt_http_sendmsg_conf_t *)conf;

    sendmsg_mqtt_ctx = NULL;
    if (cf->args->nelts <= 1)
    {
        smcf->off = 0;
        smcf->conf_file.data = NULL;
        smcf->conf_file.len = 0;
        return NJT_CONF_OK;
    }
    if (njt_strcmp(value[1].data, "off") == 0) {
        smcf->off = 1;
        return NJT_CONF_OK;
    }

    smcf->off = 0;
    dst.data = njt_pnalloc(cf->pool, value[1].len + 1);
    if (dst.data == NULL)
    {
        return NJT_CONF_ERROR;
    }
    dst.len = value[1].len;
    p = njt_copy(dst.data, value[1].data, value[1].len);
    *p = '\0';

    if (njt_get_full_name(cf->pool, (njt_str_t *)&njt_cycle->prefix, &dst) != NJT_OK)
    {
        return NJT_CONF_ERROR;
    }

    smcf->conf_file.data = dst.data;
    smcf->conf_file.len = dst.len;
    return NJT_CONF_OK;
}

int njt_dyn_sendmsg(njt_str_t *topic, njt_str_t *content, int retain_flag)
{
    int ret = 0;
    int qos = 0;
    if (retain_flag)
        qos = RETAIN_MSG_QOS;

    u_char *t;
    t = njt_calloc(topic->len + 1, njt_cycle->log);
    if (t == NULL)
    {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "in njt_dyn_sendmsg, can't alloc memory");
        return NJT_ERROR;
    }
    njt_memcpy(t, topic->data, topic->len);
    t[topic->len] = '\0';
    // if it is a normal message, send zero length retain msg to same topic to delete it
    if (!retain_flag)
    {
        ret = njet_iot_client_sendmsg((const char *)t, "", 0, RETAIN_MSG_QOS, sendmsg_mqtt_ctx);
    }
    if (ret < 0)
    {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "in njt_dyn_sendmsg, error when sending zero len retain msg");
        goto error;
    }
    ret = njet_iot_client_sendmsg((const char *)t, (const char *)content->data, (int)content->len, qos, sendmsg_mqtt_ctx);
    if (ret < 0)
    {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "in njt_dyn_sendmsg, error when sending msg");

        goto error;
    }
    njt_free(t);
    return NJT_OK;
error:
    njt_free(t);
    return NJT_ERROR;
}

static void njt_sendmsg_rpc_timer_fired(njt_event_t *ev)
{
    rpc_msg_handler_t *h, *rpc_handler;
    njt_int_t rc;
    njt_str_t nstr_key;
    if (ev->timedout)
    {
        h = (rpc_msg_handler_t *)ev->data;
        invoke_rpc_msg_handler(RPC_RC_TIMEOUT, h->session_id, "", 0);

        sendmsg_get_session_id_str(h->session_id, &nstr_key);

        if (nstr_key.data == NULL)
        {
            goto end;
        }

        rc = njt_lvlhsh_map_get(rpc_msg_handler_hashmap, &nstr_key, (intptr_t *)&rpc_handler);
        if (rc == NJT_OK)
        {
            // remove session_id from hash map
            njt_lvlhsh_map_remove(rpc_msg_handler_hashmap, &nstr_key);
            njt_free(rpc_handler->key.data);
            njt_free(rpc_handler);
        }
        njt_free(nstr_key.data);
    end:
        njt_free(ev->data);
        njt_free(ev);
    }
}

int njt_dyn_rpc(njt_str_t *topic, njt_str_t *content, int retain_flag, int session_id, rpc_msg_handler handler, void *data)
{
    static njt_int_t  njt_sendmsg_rr_session_id = 1;
    int ret=0;
    int qos = 0;
    njt_event_t *rpc_timer_ev;
    rpc_msg_handler_t *rpc_data;
    u_char *t;

    if (retain_flag)
        qos = RETAIN_MSG_QOS;
    t = njt_calloc(topic->len + 1, njt_cycle->log);
    if (t == NULL)
    {
        return NJT_ERROR;
    }
    njt_memcpy(t, topic->data, topic->len);
    t[topic->len] = '\0';

    if (!retain_flag)
    {
        ret = njet_iot_client_sendmsg((const char *)t, "", 0, RETAIN_MSG_QOS, sendmsg_mqtt_ctx);
    }
    if (ret < 0)
    {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "in njt_dyn_sendmsg, error when sending zero len retain msg");
        goto error;
    }

    njt_sendmsg_rr_session_id++;
    ret = njet_iot_client_sendmsg_rr((const char *)t, (const char *)content->data, (int)content->len, qos, njt_sendmsg_rr_session_id, 0, sendmsg_mqtt_ctx);
    // add timer
    rpc_timer_ev = njt_calloc(sizeof(njt_event_t), njt_cycle->log);
    rpc_data = njt_calloc(sizeof(rpc_msg_handler_t), njt_cycle->log);
    rpc_data->session_id = njt_sendmsg_rr_session_id;
    rpc_data->invoker_session_id = session_id;
    rpc_timer_ev->handler = njt_sendmsg_rpc_timer_fired;
    rpc_timer_ev->log = njt_cycle->log;
    rpc_timer_ev->data = rpc_data;

    njt_http_conf_ctx_t *conf_ctx = (njt_http_conf_ctx_t *)njt_get_conf(njt_cycle->conf_ctx, njt_http_module);
    njt_http_sendmsg_conf_t *smcf = conf_ctx->main_conf[njt_http_sendmsg_module.ctx_index];
    if (!smcf || smcf->rpc_timeout == 0)
    {
        njt_add_timer(rpc_timer_ev, RPC_DEFAULT_TIMEOUT_MS);
    }
    else
    {
        njt_add_timer(rpc_timer_ev, smcf->rpc_timeout);
    }

    njt_reg_rpc_msg_handler(njt_sendmsg_rr_session_id, session_id, handler, data, rpc_timer_ev);
    njt_free(t);
    return NJT_OK;

error:
    njt_free(t);
    return NJT_ERROR;
}

int njt_dyn_kv_get(njt_str_t *key, njt_str_t *value)
{
    uint32_t val_len = 0;
    if (key == NULL || key->data == NULL || value == NULL)
    {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "njt_dyn_kv_get got wrong key:value data");
        return NJT_ERROR;
    }
    // type of njt_str_t.len is size_t, in 64bit arch, it is not uint32_t,  
    // force type conversion will not work in big-endian arch, 
    // and even in little-endian arch, if value->len is not initialized, only low bytes will be set
    // so use temporary variable when invoke lib api, and then assign to value->len 
    int ret = njet_iot_client_kv_get((void *)key->data, key->len, (void **)&value->data, &val_len, sendmsg_mqtt_ctx);
    value->len=val_len;

    if (ret < 0)
    {
        return NJT_ERROR;
    }
    return NJT_OK;
}
int njt_dyn_kv_set(njt_str_t *key, njt_str_t *value)
{
    if (key->data == NULL || value->data == NULL)
    {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "njt_dyn_kv_set got wrong key:value data");
        return NJT_ERROR;
    }
    int ret = njet_iot_client_kv_set(key->data, key->len, value->data, value->len, NULL, sendmsg_mqtt_ctx);
    if (ret < 0)
    {
        return NJT_ERROR;
    }
    return NJT_OK;
}
int njt_dyn_kv_del(njt_str_t *key)
{
    if (key->data == NULL)
    {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "njt_dyn_kv_del got wrong key data");
        return NJT_ERROR;
    }
    int ret = njet_iot_client_kv_del(key->data, key->len, NULL, 0, sendmsg_mqtt_ctx);
    if (ret < 0)
    {
        return NJT_ERROR;
    }
    return NJT_OK;
}

static void sendmsg_get_session_id_str(int session_id, njt_str_t *sk)
{
    njt_uint_t sess_len;
    u_char sess_str[24] = {0};
    u_char *end;
    end = njt_snprintf(sess_str, 24, "%d", session_id);
    sess_len = end - sess_str;
    sk->len = sess_len;
    sk->data = njt_calloc(sess_len, njt_cycle->log);
    if (sk->data != NULL)
    {
        njt_memcpy(sk->data, sess_str, sess_len);
    }
    return;
}

static int njt_reg_rpc_msg_handler(int msg_session_id, int invoker_session_id, rpc_msg_handler handler, void *data, njt_event_t *ev)
{
    rpc_msg_handler_t *rpc_handler, *old_handler;
    if (rpc_msg_handler_hashmap == NULL)
    {
        rpc_msg_handler_hashmap = njt_calloc(sizeof(njt_lvlhash_map_t), njt_cycle->log);
    }

    rpc_handler = njt_calloc(sizeof(rpc_msg_handler_t), njt_cycle->log);

    if (rpc_handler == NULL)
    {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "can't not malloc handler's memory while reg rpc handler for sessio_id :%d", msg_session_id);
        return NJT_ERROR;
    }

    rpc_handler->session_id = msg_session_id;
    rpc_handler->invoker_session_id = invoker_session_id;
    rpc_handler->data = data;
    rpc_handler->handler = handler;
    rpc_handler->ev = ev;

    sendmsg_get_session_id_str(msg_session_id, &rpc_handler->key);
    if (rpc_handler->key.data == NULL)
    {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "can't not malloc handler's memory while reg rpc handler for sessio_id :%d", msg_session_id);
        return NJT_ERROR;
    }

    njt_lvlhsh_map_put(rpc_msg_handler_hashmap, &rpc_handler->key, (intptr_t)rpc_handler, (intptr_t *)&old_handler);
    // if handler existed with the same key in the hashmap
    if (old_handler && old_handler != rpc_handler)
    {
        ev = old_handler->ev;
        if (ev && ev->timer_set)
        {
            njt_del_timer(ev);
            njt_free(ev->data);
            njt_free(ev);
        }
        njt_free(old_handler->key.data);
        njt_free(old_handler);
    }
    return NJT_OK;
}

static void invoke_rpc_msg_handler(int rc, int session_id, const char *msg, int msg_len)
{
    njt_int_t hash_rc;
    njt_str_t nstr_msg, nstr_key;
    njt_dyn_rpc_res_t res;
    njt_event_t *ev;
    rpc_msg_handler_t *rpc_handler;

    if (rpc_msg_handler_hashmap)
    {
        sendmsg_get_session_id_str(session_id, &nstr_key);
        if (nstr_key.data == NULL)
        {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "can't not malloc handler's memory while reg rpc handler for sessio_id :%d", session_id);
            return;
        }

        hash_rc = njt_lvlhsh_map_get(rpc_msg_handler_hashmap, &nstr_key, (intptr_t *)&rpc_handler);
        if (hash_rc == NJT_OK)
        {
            nstr_msg.data = (u_char *)msg;
            nstr_msg.len = msg_len;
            res.session_id = rpc_handler->invoker_session_id;
            res.data = rpc_handler->data;
            res.rc = rc;
            rpc_handler->handler(&res, &nstr_msg);
            // remove timer
            ev = rpc_handler->ev;
            if (ev && ev->timer_set)
            {
                njt_del_timer(ev);
                njt_free(ev->data);
                njt_free(ev);
            }
            // remove session_id from hash map
            njt_lvlhsh_map_remove(rpc_msg_handler_hashmap, &nstr_key);
            njt_free(rpc_handler->key.data);
            njt_free(rpc_handler);
        }
        njt_free(nstr_key.data);
    }
}
