#include <njt_config.h>
#include <njt_http.h>
#include <njt_json_api.h>

#include "mosquitto_emb.h"
#include "njt_http_sendmsg_module.h"
#include <njt_mqconf_module.h>

#define RPC_TOPIC_PREFIX "/dyn/"
#define RPC_TOPIC_PREFIX_LEN 5

typedef struct
{
    void *data;
    int session_id;
    rpc_msg_handler handler;
} rpc_msg_handler_t;

typedef struct
{
    njt_str_t conf_file;
    njt_flag_t kv_api_enabled;
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

static void mqtt_connect_timeout(njt_event_t *ev);
static void mqtt_set_timer(njt_event_handler_pt h, int interval, struct mqtt_ctx_t *ctx);
static void mqtt_loop_mqtt(njt_event_t *ev);
static void mqtt_register_outside_reader(njt_event_handler_pt h, struct mqtt_ctx_t *ctx);
static njt_int_t sendmsg_init_worker(njt_cycle_t *cycle);
static void sendmsg_exit_worker(njt_cycle_t *cycle);
static void *njt_http_sendmsg_create_conf(njt_conf_t *cf);
static char *njt_dyn_conf_set(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static njt_int_t njt_http_sendmsg_init(njt_conf_t *cf);
static njt_int_t njt_http_sendmsg_handler(njt_http_request_t *r);
static void *njt_http_sendmsg_create_loc_conf(njt_conf_t *cf);
static char *njt_dyn_kv_api_set(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static int njt_reg_rpc_msg_handler(int session_id, rpc_msg_handler handler, void *data); static void invoke_rpc_msg_handler(int session_id, const char *msg, int msg_len);

static njt_array_t *rpc_msg_handler_fac = NULL;
static struct mqtt_ctx_t *sendmsg_mqtt_ctx;

static njt_http_module_t njt_http_sendmsg_module_ctx = {
    NULL,                  /* preconfiguration */
    njt_http_sendmsg_init, /* postconfiguration */

    njt_http_sendmsg_create_conf, /* create main configuration */
    NULL,                         /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    njt_http_sendmsg_create_loc_conf, /* create location configuration */
    NULL                              /* merge location configuration */
};

static njt_command_t njt_sendmsg_commands[] = {

    {njt_string("dyn_sendmsg_conf"),
     NJT_HTTP_MAIN_CONF | NJT_CONF_TAKE1,
     njt_dyn_conf_set,
     0,
     0,
     NULL},
    {njt_string("dyn_sendmsg_kv"),
     NJT_HTTP_LOC_CONF | NJT_CONF_NOARGS,
     njt_dyn_kv_api_set,
     NJT_HTTP_LOC_CONF_OFFSET,
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

static void mqtt_loop_mqtt(njt_event_t *ev)
{
    int ret;
    njt_connection_t *c = (njt_connection_t *)ev->data;
    struct mqtt_ctx_t *ctx = (struct mqtt_ctx_t *)c->data;
    if (ev->timer_set)
    {
        njt_del_timer(ev);
    }
    ret = mqtt_client_run(ctx);
    switch (ret)
    {
    case 0:
        break;
    case 4:  // lost connection
    case 19: // lost keepalive
    case 7:
        mqtt_set_timer(mqtt_connect_timeout, 10, ctx);
        njt_del_event(ev, NJT_READ_EVENT, NJT_CLOSE_EVENT);
        break;
    default:
        mqtt_set_timer(mqtt_connect_timeout, 10, ctx);
        njt_del_event(ev, NJT_READ_EVENT, NJT_CLOSE_EVENT);
        njt_log_error(NJT_LOG_ERR, ev->log, 0, "mqtt client run:%d, what todo ?", ret);
    }

    if (!njt_exiting)
    {
        njt_add_timer(ev, 1000);
    }
}
static void mqtt_connect_timeout(njt_event_t *ev)
{
    njt_connection_t *c = (njt_connection_t *)ev->data;
    struct mqtt_ctx_t *ctx = (struct mqtt_ctx_t *)c->data;
    int ret;
    njt_log_error(NJT_LOG_DEBUG, ev->log, 0, "Event fired!,try connect again");
    if (ev->timedout)
    {
        ret = mqtt_client_connect(3, 5, ctx);
        if (ret != 0)
        {
            njt_log_error(NJT_LOG_DEBUG, ev->log, 0, "connect iot failed:%d", ret);
            njt_add_timer(ev, 1000);
        }
        else
        {
            njt_log_error(NJT_LOG_DEBUG, ev->log, 0, "connect:%d, registe io", ret);
            mqtt_register_outside_reader(mqtt_loop_mqtt, ctx);
        }
    }
}

static void mqtt_register_outside_reader(njt_event_handler_pt h, struct mqtt_ctx_t *ctx)
{
    int fd;
    njt_event_t *rev, *wev;
    fd = mqtt_client_socket(ctx);
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

static void mqtt_set_timer(njt_event_handler_pt h, int interval, struct mqtt_ctx_t *ctx)
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
    njt_http_core_main_conf_t *cmcf;
    njt_http_handler_pt *h;

    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);
    h = njt_array_push(&cmcf->phases[NJT_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL)
    {
        return NJT_ERROR;
    }

    *h = njt_http_sendmsg_handler;
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
        r->headers_out.status = NJT_HTTP_OK;
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
    njt_uint_t i;
    njt_json_element *items;

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

    items = json_body.json_keyval->elts;
    for (i = 0; i < json_body.json_keyval->nelts; i++)
    {
        if (njt_strncmp(items[i].key.data, "key", 3) == 0 && items[i].key.len == 3)
        {

            if (items[i].type != NJT_JSON_STR)
            {
                postdata->code = 1; // key error
                break;
            }

            postdata->key = items[i].strval;

            continue;
        }
        else if (njt_strncmp(items[i].key.data, "value", 5) == 0 && items[i].key.len == 5)
        {

            if (items[i].type != NJT_JSON_STR)
            {
                postdata->code = 2; // value error
                break;
            }

            postdata->value = items[i].strval;
            continue;
        }
    }
    if (postdata->key.len == 0)
    {
        postdata->code = 1; // key error
    }
    else if (postdata->value.len == 0)
    {
        postdata->code = 2; // value error
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
    njt_log_error(NJT_LOG_DEBUG, r->connection->log, 0,
                  "dyn_sendmsg_kv parse ok, key:%V, value: %V", &postdata->key, &postdata->value);

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

    njt_http_sendmsg_conf_t *smcf = njt_http_get_module_loc_conf(r, njt_http_sendmsg_module);

    if (!smcf || smcf->kv_api_enabled != 1)
    {
        return NJT_DECLINED;
    }

    if (r->method == NJT_HTTP_GET)
    {
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

    return NJT_DECLINED;
}

static char *sendmsg_rr_callback(const char *topic, int is_reply, const char *msg, int msg_len, int session_id, int *out_len)
{
    njt_str_t topic_str, msg_str;
    topic_str.data = (u_char *)topic;
    topic_str.len = strlen(topic);
    msg_str.data = (u_char *)msg;
    msg_str.len = msg_len;

    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "sendmsg got response msg, topic: %V, msg:%V, seesion_id: %d", &topic_str, &msg_str, session_id);

    if (is_reply)
    {
        invoke_rpc_msg_handler(session_id, msg, msg_len);
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
    char client_id[128]={0};
    char log[1024]={0};
    char localcfg[1024]={0};
    // return when there is no http configuraton
    if (njt_http_sendmsg_module.ctx_index == NJT_CONF_UNSET_UINT)
    {
        return NJT_OK;
    }
    for (i = 0; i < cycle->modules_n; i++)
    {
        if (njt_strcmp(cycle->modules[i]->name, "njt_mqconf_module") != 0)
            continue;
        mqconf = (njt_mqconf_conf_t *)(cycle->conf_ctx[cycle->modules[i]->index]);
    }
    if (!mqconf || !mqconf->cluster_name.data || !mqconf->node_name.data)
    {
        njt_log_error(NJT_LOG_INFO, cycle->log, 0, "mqconf check failed, sendmsg module is not loaded");
        return NJT_OK;
    }

    conf_ctx = (njt_http_conf_ctx_t *)njt_get_conf(cycle->conf_ctx, njt_http_module);
    smcf = conf_ctx->main_conf[njt_http_sendmsg_module.ctx_index];

    if (smcf->conf_file.len == 0)
    {
        njt_log_error(NJT_LOG_INFO, cycle->log, 0, "dyn_sendmsg_conf directive not found, sendmsg module is not loaded");
        return NJT_OK;
    }

    memcpy(client_id, mqconf->node_name.data, mqconf->node_name.len);
    sprintf(client_id + mqconf->node_name.len, "_msg_%d", njt_pid);

    memcpy(log, njt_cycle->prefix.data, njt_cycle->prefix.len);
    sprintf(log + njt_cycle->prefix.len, "logs/sendmsg_%d", (int)njt_process_slot);

    memcpy(localcfg, smcf->conf_file.data, smcf->conf_file.len);
    localcfg[smcf->conf_file.len] = '\0';

    njt_log_error(NJT_LOG_DEBUG, cycle->log, 0, "module http_sendmsg init worker");
    sendmsg_mqtt_ctx = mqtt_client_init(localcfg, sendmsg_rr_callback, NULL, client_id, log, cycle);

    if (sendmsg_mqtt_ctx == NULL)
    {
        njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "init local mqtt client failed, exiting");
        mqtt_client_exit(sendmsg_mqtt_ctx);
        return NJT_ERROR;
    };
    ret = mqtt_client_connect(3, 5, sendmsg_mqtt_ctx);
    if (0 != ret)
    {
        njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "worker mqtt client connect failed, schedule:%d", ret);
        mqtt_set_timer(mqtt_connect_timeout, 2000, sendmsg_mqtt_ctx);
    }
    else
    {
        mqtt_register_outside_reader(mqtt_loop_mqtt, sendmsg_mqtt_ctx);
    };

    return NJT_OK;
};

static void sendmsg_exit_worker(njt_cycle_t *cycle)
{
    mqtt_client_exit(sendmsg_mqtt_ctx);
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
    return conf;
}

static void *
njt_http_sendmsg_create_loc_conf(njt_conf_t *cf)
{
    njt_http_sendmsg_conf_t *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_sendmsg_conf_t));

    if (conf == NULL)
    {
        return NULL;
    }

    conf->kv_api_enabled = NJT_CONF_UNSET;
    return conf;
}

static char *
njt_dyn_conf_set(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_str_t *value;
    njt_http_sendmsg_conf_t *smcf;

    value = cf->args->elts;
    smcf = (njt_http_sendmsg_conf_t *)conf;

    u_char *dst;
    size_t vl = value[1].len + njt_cycle->prefix.len;
    dst = njt_pnalloc(cf->pool, vl);
    if (dst == NULL)
    {
        return NJT_CONF_ERROR;
    }
    njt_memcpy(dst, njt_cycle->prefix.data, njt_cycle->prefix.len);
    njt_memcpy(dst + njt_cycle->prefix.len, value[1].data, value[1].len);

    smcf->conf_file.data = dst;
    smcf->conf_file.len = vl;
    return NJT_CONF_OK;
}

static char *
njt_dyn_kv_api_set(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_sendmsg_conf_t *smcf = conf;
    smcf->kv_api_enabled = 1;
    return NJT_CONF_OK;
}

int njt_dyn_sendmsg(njt_str_t *topic, njt_str_t *content, int retain_flag)
{
    int ret;
    int qos = 0;
    if (retain_flag)
        qos = 16;

    u_char *t;
    t = njt_pcalloc(njt_cycle->pool, topic->len + 1);
    if (t == NULL)
    {
        return NJT_ERROR;
    }
    njt_memcpy(t, topic->data, topic->len);
    t[topic->len] = '\0';
    ret = mqtt_client_sendmsg((const char *)t, (const char *)content->data, (int)content->len, qos, sendmsg_mqtt_ctx);
    njt_pfree(njt_cycle->pool, t);
    if (ret < 0)
    {
        return NJT_ERROR;
    }
    return NJT_OK;
}

int dyn_rpc(njt_str_t *topic, njt_str_t *content, int session_id, rpc_msg_handler handler, void *data)
{
    int ret;
    int qos = 0;

    u_char *t;
    t = njt_pcalloc(njt_cycle->pool, topic->len + 1);
    if (t == NULL)
    {
        return NJT_ERROR;
    }
    njt_memcpy(t, topic->data, topic->len);
    t[topic->len] = '\0';

    njt_reg_rpc_msg_handler(session_id, handler, data);
    ret = mqtt_client_sendmsg_rr((const char *)t, (const char *)content->data, (int)content->len, qos, session_id, 0, sendmsg_mqtt_ctx);
    njt_pfree(njt_cycle->pool, t);
    // TODO: unreg msg handler
    if (ret < 0)
    {
        return NJT_ERROR;
    }
    return NJT_OK;
}

int njt_dyn_kv_get(njt_str_t *key, njt_str_t *value)
{
    if (key->data == NULL)
    {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "njt_dyn_kv_get got wrong key:value data");
        return NJT_ERROR;
    }
    int ret = mqtt_client_kv_get((void *)key->data, key->len, (void **)&value->data, (uint32_t *)&value->len, sendmsg_mqtt_ctx);
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
    int ret = mqtt_client_kv_set(key->data, key->len, value->data, value->len, NULL, sendmsg_mqtt_ctx);
    if (ret < 0)
    {
        return NJT_ERROR;
    }
    return NJT_OK;
}

static int njt_reg_rpc_msg_handler(int session_id, rpc_msg_handler handler, void *data)
{
    njt_uint_t i;
    if (rpc_msg_handler_fac == NULL)
        rpc_msg_handler_fac = njt_array_create(njt_cycle->pool, 4, sizeof(rpc_msg_handler_t));

    rpc_msg_handler_t *tm_handler = rpc_msg_handler_fac->elts;
    for (i = 0; i < rpc_msg_handler_fac->nelts; i++)
    {
        if (tm_handler[i].session_id == session_id)
        {
            tm_handler[i].handler = handler;
            return NJT_OK;
        }
    }

    rpc_msg_handler_t *rpc_handle = njt_array_push(rpc_msg_handler_fac);
    rpc_handle->session_id = session_id;
    rpc_handle->data = data;
    rpc_handle->handler = handler;
    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "add rpc handler for session_id:%d", &session_id);
    return NJT_OK;
}

static void invoke_rpc_msg_handler(int session_id, const char *msg, int msg_len)
{
    njt_uint_t i;
    njt_str_t nstr_msg;
    if (rpc_msg_handler_fac)
    {
        rpc_msg_handler_t *tm_handler = rpc_msg_handler_fac->elts;
        for (i = 0; i < rpc_msg_handler_fac->nelts; i++)
        {
            if (tm_handler[i].session_id == session_id)
            {
                nstr_msg.data = (u_char *)msg;
                nstr_msg.len = msg_len;
                tm_handler[i].handler(session_id, &nstr_msg, tm_handler[i].data);
                break;
            }
        }
    }
}
