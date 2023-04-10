
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


typedef struct {
    njt_uint_t                         max_cached;
    njt_uint_t                         requests;
    njt_msec_t                         time;
    njt_msec_t                         timeout;

    njt_queue_t                        cache;
    njt_queue_t                        free;

    njt_http_upstream_init_pt          original_init_upstream;
    njt_http_upstream_init_peer_pt     original_init_peer;

} njt_http_upstream_keepalive_srv_conf_t;


typedef struct {
    njt_http_upstream_keepalive_srv_conf_t  *conf;

    njt_queue_t                        queue;
    njt_connection_t                  *connection;

    socklen_t                          socklen;
    njt_sockaddr_t                     sockaddr;

} njt_http_upstream_keepalive_cache_t;


typedef struct {
    njt_http_upstream_keepalive_srv_conf_t  *conf;

    njt_http_upstream_t               *upstream;

    void                              *data;

    njt_event_get_peer_pt              original_get_peer;
    njt_event_free_peer_pt             original_free_peer;

#if (NJT_HTTP_SSL)
    njt_event_set_peer_session_pt      original_set_session;
    njt_event_save_peer_session_pt     original_save_session;
#endif

} njt_http_upstream_keepalive_peer_data_t;


static njt_int_t njt_http_upstream_init_keepalive_peer(njt_http_request_t *r,
    njt_http_upstream_srv_conf_t *us);
static njt_int_t njt_http_upstream_get_keepalive_peer(njt_peer_connection_t *pc,
    void *data);
static void njt_http_upstream_free_keepalive_peer(njt_peer_connection_t *pc,
    void *data, njt_uint_t state);

static void njt_http_upstream_keepalive_dummy_handler(njt_event_t *ev);
static void njt_http_upstream_keepalive_close_handler(njt_event_t *ev);
static void njt_http_upstream_keepalive_close(njt_connection_t *c);

#if (NJT_HTTP_SSL)
static njt_int_t njt_http_upstream_keepalive_set_session(
    njt_peer_connection_t *pc, void *data);
static void njt_http_upstream_keepalive_save_session(njt_peer_connection_t *pc,
    void *data);
#endif

static void *njt_http_upstream_keepalive_create_conf(njt_conf_t *cf);
static char *njt_http_upstream_keepalive(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);


static njt_command_t  njt_http_upstream_keepalive_commands[] = {

    { njt_string("keepalive"),
      NJT_HTTP_UPS_CONF|NJT_CONF_TAKE1,
      njt_http_upstream_keepalive,
      NJT_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("keepalive_time"),
      NJT_HTTP_UPS_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_upstream_keepalive_srv_conf_t, time),
      NULL },

    { njt_string("keepalive_timeout"),
      NJT_HTTP_UPS_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_upstream_keepalive_srv_conf_t, timeout),
      NULL },

    { njt_string("keepalive_requests"),
      NJT_HTTP_UPS_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_upstream_keepalive_srv_conf_t, requests),
      NULL },

      njt_null_command
};


static njt_http_module_t  njt_http_upstream_keepalive_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    njt_http_upstream_keepalive_create_conf, /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


njt_module_t  njt_http_upstream_keepalive_module = {
    NJT_MODULE_V1,
    &njt_http_upstream_keepalive_module_ctx, /* module context */
    njt_http_upstream_keepalive_commands,    /* module directives */
    NJT_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};


static njt_int_t
njt_http_upstream_init_keepalive(njt_conf_t *cf,
    njt_http_upstream_srv_conf_t *us)
{
    njt_uint_t                               i;
    njt_http_upstream_keepalive_srv_conf_t  *kcf;
    njt_http_upstream_keepalive_cache_t     *cached;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, cf->log, 0,
                   "init keepalive");

    kcf = njt_http_conf_upstream_srv_conf(us,
                                          njt_http_upstream_keepalive_module);

    njt_conf_init_msec_value(kcf->time, 3600000);
    njt_conf_init_msec_value(kcf->timeout, 60000);
    njt_conf_init_uint_value(kcf->requests, 1000);

    if (kcf->original_init_upstream(cf, us) != NJT_OK) {
        return NJT_ERROR;
    }

    kcf->original_init_peer = us->peer.init;

    us->peer.init = njt_http_upstream_init_keepalive_peer;

    /* allocate cache items and add to free queue */

    cached = njt_pcalloc(cf->pool,
                sizeof(njt_http_upstream_keepalive_cache_t) * kcf->max_cached);
    if (cached == NULL) {
        return NJT_ERROR;
    }

    njt_queue_init(&kcf->cache);
    njt_queue_init(&kcf->free);

    for (i = 0; i < kcf->max_cached; i++) {
        njt_queue_insert_head(&kcf->free, &cached[i].queue);
        cached[i].conf = kcf;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_init_keepalive_peer(njt_http_request_t *r,
    njt_http_upstream_srv_conf_t *us)
{
    njt_http_upstream_keepalive_peer_data_t  *kp;
    njt_http_upstream_keepalive_srv_conf_t   *kcf;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "init keepalive peer");

    kcf = njt_http_conf_upstream_srv_conf(us,
                                          njt_http_upstream_keepalive_module);

    kp = njt_palloc(r->pool, sizeof(njt_http_upstream_keepalive_peer_data_t));
    if (kp == NULL) {
        return NJT_ERROR;
    }

    if (kcf->original_init_peer(r, us) != NJT_OK) {
        return NJT_ERROR;
    }

    kp->conf = kcf;
    kp->upstream = r->upstream;
    kp->data = r->upstream->peer.data;
    kp->original_get_peer = r->upstream->peer.get;
    kp->original_free_peer = r->upstream->peer.free;

    r->upstream->peer.data = kp;
    r->upstream->peer.get = njt_http_upstream_get_keepalive_peer;
    r->upstream->peer.free = njt_http_upstream_free_keepalive_peer;

#if (NJT_HTTP_SSL)
    kp->original_set_session = r->upstream->peer.set_session;
    kp->original_save_session = r->upstream->peer.save_session;
    r->upstream->peer.set_session = njt_http_upstream_keepalive_set_session;
    r->upstream->peer.save_session = njt_http_upstream_keepalive_save_session;
#endif

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_get_keepalive_peer(njt_peer_connection_t *pc, void *data)
{
    njt_http_upstream_keepalive_peer_data_t  *kp = data;
    njt_http_upstream_keepalive_cache_t      *item;

    njt_int_t          rc;
    njt_queue_t       *q, *cache;
    njt_connection_t  *c;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, pc->log, 0,
                   "get keepalive peer");

    /* ask balancer */

    rc = kp->original_get_peer(pc, kp->data);

    if (rc != NJT_OK) {
        return rc;
    }

    /* search cache for suitable connection */

    cache = &kp->conf->cache;

    for (q = njt_queue_head(cache);
         q != njt_queue_sentinel(cache);
         q = njt_queue_next(q))
    {
        item = njt_queue_data(q, njt_http_upstream_keepalive_cache_t, queue);
        c = item->connection;

        if (njt_memn2cmp((u_char *) &item->sockaddr, (u_char *) pc->sockaddr,
                         item->socklen, pc->socklen)
            == 0)
        {
            njt_queue_remove(q);
            njt_queue_insert_head(&kp->conf->free, q);

            goto found;
        }
    }

    return NJT_OK;

found:

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, pc->log, 0,
                   "get keepalive peer: using connection %p", c);

    c->idle = 0;
    c->sent = 0;
    c->data = NULL;
    c->log = pc->log;
    c->read->log = pc->log;
    c->write->log = pc->log;
    c->pool->log = pc->log;

    if (c->read->timer_set) {
        njt_del_timer(c->read);
    }

    pc->connection = c;
    pc->cached = 1;

    return NJT_DONE;
}


static void
njt_http_upstream_free_keepalive_peer(njt_peer_connection_t *pc, void *data,
    njt_uint_t state)
{
    njt_http_upstream_keepalive_peer_data_t  *kp = data;
    njt_http_upstream_keepalive_cache_t      *item;

    njt_queue_t          *q;
    njt_connection_t     *c;
    njt_http_upstream_t  *u;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, pc->log, 0,
                   "free keepalive peer");

    /* cache valid connections */

    u = kp->upstream;
    c = pc->connection;

    if (state & NJT_PEER_FAILED
        || c == NULL
        || c->read->eof
        || c->read->error
        || c->read->timedout
        || c->write->error
        || c->write->timedout)
    {
        goto invalid;
    }

    if (c->requests >= kp->conf->requests) {
        goto invalid;
    }

    if (njt_current_msec - c->start_time > kp->conf->time) {
        goto invalid;
    }

    if (!u->keepalive) {
        goto invalid;
    }

    if (!u->request_body_sent) {
        goto invalid;
    }

    if (njt_terminate || njt_exiting) {
        goto invalid;
    }

    if (njt_handle_read_event(c->read, 0) != NJT_OK) {
        goto invalid;
    }

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, pc->log, 0,
                   "free keepalive peer: saving connection %p", c);

    if (njt_queue_empty(&kp->conf->free)) {

        q = njt_queue_last(&kp->conf->cache);
        njt_queue_remove(q);

        item = njt_queue_data(q, njt_http_upstream_keepalive_cache_t, queue);

        njt_http_upstream_keepalive_close(item->connection);

    } else {
        q = njt_queue_head(&kp->conf->free);
        njt_queue_remove(q);

        item = njt_queue_data(q, njt_http_upstream_keepalive_cache_t, queue);
    }

    njt_queue_insert_head(&kp->conf->cache, q);

    item->connection = c;

    pc->connection = NULL;

    c->read->delayed = 0;
    njt_add_timer(c->read, kp->conf->timeout);

    if (c->write->timer_set) {
        njt_del_timer(c->write);
    }

    c->write->handler = njt_http_upstream_keepalive_dummy_handler;
    c->read->handler = njt_http_upstream_keepalive_close_handler;

    c->data = item;
    c->idle = 1;
    c->log = njt_cycle->log;
    c->read->log = njt_cycle->log;
    c->write->log = njt_cycle->log;
    c->pool->log = njt_cycle->log;

    item->socklen = pc->socklen;
    njt_memcpy(&item->sockaddr, pc->sockaddr, pc->socklen);

    if (c->read->ready) {
        njt_http_upstream_keepalive_close_handler(c->read);
    }

invalid:

    kp->original_free_peer(pc, kp->data, state);
}


static void
njt_http_upstream_keepalive_dummy_handler(njt_event_t *ev)
{
    njt_log_debug0(NJT_LOG_DEBUG_HTTP, ev->log, 0,
                   "keepalive dummy handler");
}


static void
njt_http_upstream_keepalive_close_handler(njt_event_t *ev)
{
    njt_http_upstream_keepalive_srv_conf_t  *conf;
    njt_http_upstream_keepalive_cache_t     *item;

    int                n;
    char               buf[1];
    njt_connection_t  *c;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, ev->log, 0,
                   "keepalive close handler");

    c = ev->data;

    if (c->close || c->read->timedout) {
        goto close;
    }

    n = recv(c->fd, buf, 1, MSG_PEEK);

    if (n == -1 && njt_socket_errno == NJT_EAGAIN) {
        ev->ready = 0;

        if (njt_handle_read_event(c->read, 0) != NJT_OK) {
            goto close;
        }

        return;
    }

close:

    item = c->data;
    conf = item->conf;

    njt_http_upstream_keepalive_close(c);

    njt_queue_remove(&item->queue);
    njt_queue_insert_head(&conf->free, &item->queue);
}


static void
njt_http_upstream_keepalive_close(njt_connection_t *c)
{

#if (NJT_HTTP_SSL)

    if (c->ssl) {
        c->ssl->no_wait_shutdown = 1;
        c->ssl->no_send_shutdown = 1;

        if (njt_ssl_shutdown(c) == NJT_AGAIN) {
            c->ssl->handler = njt_http_upstream_keepalive_close;
            return;
        }
    }

#endif

    njt_destroy_pool(c->pool);
    njt_close_connection(c);
}


#if (NJT_HTTP_SSL)

static njt_int_t
njt_http_upstream_keepalive_set_session(njt_peer_connection_t *pc, void *data)
{
    njt_http_upstream_keepalive_peer_data_t  *kp = data;

    return kp->original_set_session(pc, kp->data);
}


static void
njt_http_upstream_keepalive_save_session(njt_peer_connection_t *pc, void *data)
{
    njt_http_upstream_keepalive_peer_data_t  *kp = data;

    kp->original_save_session(pc, kp->data);
    return;
}

#endif


static void *
njt_http_upstream_keepalive_create_conf(njt_conf_t *cf)
{
    njt_http_upstream_keepalive_srv_conf_t  *conf;

    conf = njt_pcalloc(cf->pool,
                       sizeof(njt_http_upstream_keepalive_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     conf->original_init_upstream = NULL;
     *     conf->original_init_peer = NULL;
     *     conf->max_cached = 0;
     */

    conf->time = NJT_CONF_UNSET_MSEC;
    conf->timeout = NJT_CONF_UNSET_MSEC;
    conf->requests = NJT_CONF_UNSET_UINT;

    return conf;
}


static char *
njt_http_upstream_keepalive(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_upstream_srv_conf_t            *uscf;
    njt_http_upstream_keepalive_srv_conf_t  *kcf = conf;

    njt_int_t    n;
    njt_str_t   *value;

    if (kcf->max_cached) {
        return "is duplicate";
    }

    /* read options */

    value = cf->args->elts;

    n = njt_atoi(value[1].data, value[1].len);

    if (n == NJT_ERROR || n == 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid value \"%V\" in \"%V\" directive",
                           &value[1], &cmd->name);
        return NJT_CONF_ERROR;
    }

    kcf->max_cached = n;

    /* init upstream handler */

    uscf = njt_http_conf_get_module_srv_conf(cf, njt_http_upstream_module);

    kcf->original_init_upstream = uscf->peer.init_upstream
                                  ? uscf->peer.init_upstream
                                  : njt_http_upstream_init_round_robin;

    uscf->peer.init_upstream = njt_http_upstream_init_keepalive;

    return NJT_CONF_OK;
}
