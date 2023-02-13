#include <njt_config.h>
#include <njt_http.h>

#include "mosquitto_emb.h"
#include "njt_http_sendmsg_module.h"
#include <njt_mqconf_module.h>

typedef struct
{
    njt_str_t conf_file;
} njt_http_sendmsg_conf_t;

static void mqtt_connect_timeout(njt_event_t *ev);
static void mqtt_set_timer(njt_event_handler_pt h, int interval, struct mqtt_ctx_t *ctx);
static void mqtt_loop_mqtt(njt_event_t *ev);
static void mqtt_register_outside_reader(njt_event_handler_pt h, struct mqtt_ctx_t *ctx);
static njt_int_t sendmsg_init_worker(njt_cycle_t *cycle);
static void *njt_http_sendmsg_create_conf(njt_conf_t *cf);
static char *njt_dyn_conf_set(njt_conf_t *cf, njt_command_t *cmd, void *conf);

static struct mqtt_ctx_t *sendmsg_mqtt_ctx;

static njt_http_module_t njt_http_sendmsg_module_ctx = {
    NULL, /* preconfiguration */
    NULL,                      /* postconfiguration */

    njt_http_sendmsg_create_conf, /* create main configuration */
    NULL,                    /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    NULL, /* create location configuration */
    NULL  /* merge location configuration */
};

static njt_command_t njt_sendmsg_commands[] = {

    {njt_string("dyn_sendmsg_conf"),
     NJT_HTTP_MAIN_CONF | NJT_CONF_TAKE1,
     njt_dyn_conf_set,
     0,
     0,
     NULL},
    njt_null_command /* command termination */
};

njt_module_t njt_http_sendmsg_module = {
    NJT_MODULE_V1,
    &njt_http_sendmsg_module_ctx, /* module context */
    njt_sendmsg_commands,         /* module directives */
    NJT_HTTP_MODULE,         /* module type */
    NULL,                    /* init master */
    NULL,                    /* init module */
    sendmsg_init_worker,          /* init process */
    NULL,                    /* init thread */
    NULL,                    /* exit thread */
    NULL,                    /* exit process */
    NULL,                    /* exit master */
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

static njt_int_t sendmsg_init_worker(njt_cycle_t *cycle)
{
    njt_http_conf_ctx_t *conf_ctx;
    njt_http_sendmsg_conf_t *kvcf;
    njt_uint_t i;
    int ret;
    njt_mqconf_conf_t *mqconf = NULL;
    char client_id[128];
    char log[1024];
    char localcfg[1024];
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
    kvcf = conf_ctx->main_conf[njt_http_sendmsg_module.ctx_index];

    if (kvcf->conf_file.len == 0)
    {
        njt_log_error(NJT_LOG_INFO, cycle->log, 0, "dyn_sendmsg_conf directive not found, sendmsg module is not loaded");
        return NJT_OK;
    }

    memcpy(client_id, mqconf->node_name.data, mqconf->node_name.len);
    sprintf(client_id + mqconf->node_name.len, "_msg_%d", njt_pid);

    memcpy(log, njt_cycle->prefix.data, njt_cycle->prefix.len);
    sprintf(log + njt_cycle->prefix.len, "logs/sendmsg_%d", (int)njt_process_slot);
  

    memcpy(localcfg, kvcf->conf_file.data, kvcf->conf_file.len);
    localcfg[kvcf->conf_file.len] = '\0';

    njt_log_error(NJT_LOG_INFO, cycle->log, 0, "module http_sendmsg init worker");
    sendmsg_mqtt_ctx = mqtt_client_init(localcfg, NULL, NULL, client_id, log, cycle);

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

static char *
njt_dyn_conf_set(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_str_t *value;
    njt_http_sendmsg_conf_t *kvcf;

    value = cf->args->elts;
    kvcf = (njt_http_sendmsg_conf_t *)conf;

    u_char *dst;
    size_t vl = value[1].len + njt_cycle->prefix.len;
    dst = njt_pnalloc(cf->pool, vl);
    if (dst == NULL)
    {
        return NJT_CONF_ERROR;
    }
    njt_memcpy(dst, njt_cycle->prefix.data, njt_cycle->prefix.len);
    njt_memcpy(dst + njt_cycle->prefix.len, value[1].data, value[1].len);

    kvcf->conf_file.data = dst;
    kvcf->conf_file.len = vl;
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

int njt_dyn_kv_get(njt_str_t *key, njt_str_t *value)
{
    if (key->data == NULL )
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
