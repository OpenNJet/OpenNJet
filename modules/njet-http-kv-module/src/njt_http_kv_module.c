
#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>

#include "mosquitto_emb.h"
#include "njt_http_kv_module.h"
#include <njt_mqconf_module.h>

#define IOT_HELPER_NAME "iot"
#define IOT_HELPER_NAME_LEN 3

typedef struct
{
    void *data;
    njt_str_t key;
    kv_change_handler handler;
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
} njt_http_kv_conf_t;

static void mqtt_connect_timeout(njt_event_t *ev);
static void mqtt_set_timer(njt_event_handler_pt h, int interval, struct mqtt_ctx_t *ctx);
static void mqtt_loop_mqtt(njt_event_t *ev);
static void mqtt_register_outside_reader(njt_event_handler_pt h, struct mqtt_ctx_t *ctx);
static njt_int_t njt_http_kv_add_variables(njt_conf_t *cf);
static void invoke_kv_change_handler(njt_str_t *key, njt_str_t *value);
static void invoke_topic_msg_handler(const char *topic, const char *msg, int msg_len);
static njt_int_t kv_init_worker(njt_cycle_t *cycle);
static void *njt_http_kv_create_conf(njt_conf_t *cf);
static char *njt_dyn_conf_set(njt_conf_t *cf, njt_command_t *cmd, void *conf);

static njt_rbtree_t kv_tree;
static njt_rbtree_node_t kv_sentinel;

static struct mqtt_ctx_t *local_mqtt_ctx;
static char mqtt_kv_topic[128];
static njt_str_t cluster_name;
static njt_array_t *kv_change_handler_fac = NULL;

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
     NJT_HTTP_MAIN_CONF | NJT_CONF_TAKE1,
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
    NULL,                    /* exit process */
    NULL,                    /* exit master */
    NJT_MODULE_V1_PADDING};

static void
njt_http_kv_rbtree_insert_value(njt_rbtree_node_t *temp,
                                njt_rbtree_node_t *node, njt_rbtree_node_t *sentinel)
{
    njt_rbtree_node_t **p;
    njt_http_kv_node_t *lcn, *lcnt;

    for (;;)
    {

        if (node->key < temp->key)
        {
            p = &temp->left;
        }
        else if (node->key > temp->key)
        {
            p = &temp->right;
        }
        else
        { /* node->key == temp->key */
            lcn = (njt_http_kv_node_t *)&node->color;
            lcnt = (njt_http_kv_node_t *)&temp->color;
            p = (njt_memn2cmp(lcn->data, lcnt->data, lcn->len, lcnt->len) < 0)
                    ? &temp->left
                    : &temp->right;
        }

        if (*p == sentinel)
        {
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

    while (node != sentinel)
    {

        if (hash < node->key)
        {
            node = node->left;
            continue;
        }

        if (hash > node->key)
        {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        lcn = (njt_http_kv_node_t *)&node->color;

        rc = njt_memn2cmp(key->data, lcn->data, key->len, (size_t)lcn->len);

        if (rc == 0)
        {
            return node;
        }

        node = (rc < 0) ? node->left : node->right;
    }
    return NULL;
}

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
    rev->data = c;

    wev->data = c;
    wev->log = njt_cycle->log;
    wev->ready = 1;

    c->fd = (njt_socket_t)fd;
    // c->data=cycle;
    c->data = ctx;

    c->read = rev;
    c->write = wev;

    njt_log_error(NJT_LOG_NOTICE, rev->log, 0, "kv module connect ok, register socket:%d", fd);
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
    ev->data = c;
    c->fd = (njt_socket_t)-1;
    c->data = ctx;
    njt_add_timer(ev, interval);
}
static int msg_callback(const char *topic, const char *msg, int msg_len, void *out_data)
{
    njt_rbtree_node_t *node;
    njt_http_kv_node_t *lc;
    njt_str_t kv_key, kv_value;
    njt_cycle_t *cycle = (njt_cycle_t *)out_data;
    njt_uint_t hash;
    // tips: 1 means message should be processed in lua
    int kv_topic_l = strlen(mqtt_kv_topic);
    int topic_l = strlen(topic);

    if (topic_l >= kv_topic_l && 0 == memcmp(topic, mqtt_kv_topic, kv_topic_l))
    {
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
        if (node == NULL)
        {
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
        }
        else
        {
            lc = (njt_http_kv_node_t *)&node->color;
            njt_str_t *node_val = lc->val;
            // njt_pfree(node_val->data);
            // todo: do we need free

            node_val->data = njt_palloc(cycle->pool, val_l);
            memcpy(node_val->data, val, val_l);
            node_val->len = val_l;
        }
        njt_log_error(NJT_LOG_DEBUG, cycle->log, 0, "worker write kv in local kv tree:%s,%V", key, &kv_key);
        return 0;
    }
    else if (njt_strncmp(topic, "/dyn", 4) == 0)
    {
        invoke_topic_msg_handler(topic, msg, msg_len);
    }

    return 1;
}

static njt_int_t kv_init_worker(njt_cycle_t *cycle)
{
    njt_http_conf_ctx_t *conf_ctx;
    njt_http_kv_conf_t *kvcf;
    njt_uint_t i;
    int ret;
    njt_mqconf_conf_t *mqconf = NULL;
    char client_id[128];
    char log[1024];
    char localcfg[1024];
    // return when there is no http configuraton
    if (njt_http_kv_module.ctx_index == NJT_CONF_UNSET_UINT)
    {
        return NJT_OK;
    }
    if (njt_process == NJT_PROCESS_HELPER)
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
        njt_log_error(NJT_LOG_INFO, cycle->log, 0, "mqconf check failed, dyn_kv module is not loade");
        return NJT_OK;
    }
    else if (mqconf->cluster_name.len >= 4 && 0 == memcmp(mqconf->cluster_name.data, "CTRL", 4))
    {
        njt_log_error(NJT_LOG_INFO, cycle->log, 0, "no need dyn_kv module in control plane");
        return NJT_OK;
    }
    conf_ctx = (njt_http_conf_ctx_t *)njt_get_conf(cycle->conf_ctx, njt_http_module);
    kvcf = conf_ctx->main_conf[njt_http_kv_module.ctx_index];

    if (kvcf->conf_file.len == 0)
    {
        njt_log_error(NJT_LOG_INFO, cycle->log, 0, "dyn_kv_conf directive not found, dyn_kv module is not loaded");
        return NJT_OK;
    }

    memcpy(client_id, mqconf->node_name.data, mqconf->node_name.len);
    sprintf(client_id + mqconf->node_name.len, "_w_%d", njt_pid);

    memcpy(log, njt_cycle->prefix.data, njt_cycle->prefix.len);
    sprintf(log + njt_cycle->prefix.len, "logs/work_iot_%d", (int)njt_worker);
    memcpy(mqtt_kv_topic, "/cluster/", 9);
    memcpy(mqtt_kv_topic + 9, mqconf->cluster_name.data, mqconf->cluster_name.len);
    strcpy(mqtt_kv_topic + 9 + mqconf->cluster_name.len, "/kv_set/");

    memcpy(localcfg, kvcf->conf_file.data, kvcf->conf_file.len);
    localcfg[kvcf->conf_file.len] = '\0';

    cluster_name.data = njt_pstrdup(cycle->pool, &mqconf->cluster_name);
    cluster_name.len = mqconf->cluster_name.len;

    njt_log_error(NJT_LOG_INFO, cycle->log, 0, "module http_kv init worker");
    local_mqtt_ctx = mqtt_client_init(localcfg, NULL, msg_callback, client_id, log, cycle);

    if (local_mqtt_ctx == NULL)
    {
        njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "init local mqtt client failed, exiting");
        mqtt_client_exit(local_mqtt_ctx);
        return NJT_ERROR;
    };
    ret = mqtt_client_connect(3, 5, local_mqtt_ctx);
    if (0 != ret)
    {
        njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "worker mqtt client connect failed, schedule:%d", ret);
        mqtt_set_timer(mqtt_connect_timeout, 2000, local_mqtt_ctx);
    }
    else
    {
        mqtt_register_outside_reader(mqtt_loop_mqtt, local_mqtt_ctx);
    };

    return NJT_OK;
};

njt_int_t njt_http_kv_get(njt_http_request_t *r, njt_http_variable_value_t *v, uintptr_t data)
{
    uint32_t hash;
    njt_rbtree_node_t *node;
    njt_http_kv_node_t *lc;
    njt_str_t *var;
    njt_str_t dbm_val;

    if (local_mqtt_ctx == NULL)
    {
        v->not_found = 1;
        return NJT_OK;
    }
    // todo: assume data is variable name:
    var = (njt_str_t *)data;
    hash = njt_crc32_short(var->data, var->len);
    njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "get key:%V", var);
    node = njt_http_kv_rbtree_lookup(&kv_tree, var, hash);
    if (node == NULL)
    {
        // tips:lookup in dbm, in rbtree map is kv_http_{var}: {val}, while in mdb, map is {cluster_name}_{var}:{val}
        int n;
        u_int32_t ret_len;
        njt_str_t mdb_key;
        mdb_key.len = cluster_name.len + 1 + var->len - 8;

        mdb_key.data = njt_palloc(r->pool, mdb_key.len);

        memcpy(mdb_key.data, cluster_name.data, cluster_name.len);
        mdb_key.data[cluster_name.len] = '_';
        memcpy(mdb_key.data + cluster_name.len + 1, var->data + 8, var->len - 8);

        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "get keyin db:%V", &mdb_key);
        int ret = mqtt_client_kv_get(mdb_key.data, mdb_key.len, (void **)&dbm_val.data, &ret_len, local_mqtt_ctx);
        dbm_val.len = ret_len;
        if (ret != 0)
        {
            v->not_found = 1;
            return NJT_OK;
        }
        njt_str_t *node_val = njt_palloc(njt_cycle->pool, sizeof(njt_str_t));
        n = offsetof(njt_rbtree_node_t, color) + offsetof(njt_http_kv_node_t, data) + var->len;
        node = njt_palloc(njt_cycle->pool, n);

        node->key = hash;
        lc = (njt_http_kv_node_t *)&node->color;
        lc->len = (u_char)var->len;
        lc->val = node_val;
        node_val->data = njt_pstrdup(njt_cycle->pool, &dbm_val);
        node_val->len = dbm_val.len;

        memcpy(lc->data, var->data, var->len);

        njt_rbtree_insert(&kv_tree, node);
    }
    lc = (njt_http_kv_node_t *)&node->color;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    // tips: not copy/mv data, use ptr directly
    // todo: do we need to copy the data, because kvset would update lc->value.data?
    v->len = lc->val->len;
    v->data = lc->val->data;
    return NJT_OK;
}

static void *
njt_http_kv_create_conf(njt_conf_t *cf)
{
    njt_http_kv_conf_t *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_kv_conf_t));

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
    njt_http_kv_conf_t *kvcf;

    value = cf->args->elts;
    kvcf = (njt_http_kv_conf_t *)conf;

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

static njt_http_variable_t njt_http_kv_vars[] = {
    {njt_string("kv_http_"), NULL, njt_http_kv_get, 0, NJT_HTTP_VAR_NOCACHEABLE | NJT_HTTP_VAR_PREFIX, 0, NJT_VAR_INIT_REF_COUNT},
    njt_http_null_variable};

static njt_int_t
njt_http_kv_add_variables(njt_conf_t *cf)
{
    njt_http_variable_t *var, *v;

    njt_rbtree_init(&kv_tree, &kv_sentinel,
                    njt_http_kv_rbtree_insert_value);
    for (v = njt_http_kv_vars; v->name.len; v++)
    {
        var = njt_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL)
        {
            return NJT_ERROR;
        }
        var->get_handler = v->get_handler;
        var->data = v->data;
    }
    return NJT_OK;
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
    ret = mqtt_client_sendmsg((const char *)t, (const char *)content->data, (int)content->len, qos, local_mqtt_ctx);
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
    int ret = mqtt_client_kv_get((void *)key->data, key->len, (void **)&value->data, (uint32_t *)&value->len, local_mqtt_ctx);
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
    int ret = mqtt_client_kv_set(key->data, key->len, value->data, value->len, NULL, local_mqtt_ctx);
    if (ret < 0)
    {
        return NJT_ERROR;
    }
    return NJT_OK;
}

int njt_reg_kv_change_handler(njt_str_t *key, kv_change_handler handler, void *data)
{
    if (kv_change_handler_fac == NULL)
        kv_change_handler_fac = njt_array_create(njt_cycle->pool, 4, sizeof(kv_change_handler_t));

    kv_change_handler_t *kv_handle = njt_array_push(kv_change_handler_fac);

    kv_handle->key.data = (u_char *)njt_pcalloc(njt_cycle->pool, key->len);
    njt_memcpy(kv_handle->key.data, key->data, key->len);
    kv_handle->key.len = key->len;

    kv_handle->data = data;
    kv_handle->handler = handler;
    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "add kv handler for key:%v", &kv_handle->key);
    return NJT_OK;
}

static void invoke_kv_change_handler(njt_str_t *key, njt_str_t *value)
{
    njt_uint_t i;
    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "invoke kv change for key:%v value:%v", key, value);
    if (kv_change_handler_fac)
    {
        kv_change_handler_t *kv_handle = kv_change_handler_fac->elts;
        for (i = 0; i < kv_change_handler_fac->nelts; i++)
        {
            // key is "kv_http_", handler key is with "$" as prefix
            if (kv_handle[i].handler &&
                njt_strncmp(key->data, kv_handle[i].key.data + 1, kv_handle[i].key.len - 1) == 0)
            {
                kv_handle[i].handler(&kv_handle[i].key, value, kv_handle[i].data);
            }
        }
    }
}

static void invoke_topic_msg_handler(const char *topic, const char *msg, int msg_len)
{
    njt_uint_t i;
    njt_str_t nstr_topic;
    njt_str_t nstr_msg;
    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "invoke topic msg handler for topic:%s ", topic);
    if (kv_change_handler_fac)
    {
        kv_change_handler_t *tm_handler = kv_change_handler_fac->elts;
        for (i = 0; i < kv_change_handler_fac->nelts; i++)
        {
            if (tm_handler[i].handler &&
                njt_strncmp(topic, tm_handler[i].key.data, tm_handler[i].key.len) == 0)
            {
                nstr_topic.data = (u_char *)topic;
                nstr_topic.len = strlen(topic);
                nstr_msg.data = (u_char *)msg;
                nstr_msg.len = msg_len;
                tm_handler[i].handler(&nstr_topic, &nstr_msg, tm_handler[i].data);
            }
        }
    }
}
