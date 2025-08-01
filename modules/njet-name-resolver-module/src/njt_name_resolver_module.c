
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_str_util.h>
#include <njt_http.h>
#include <njt_http_util.h>
#include <njt_conf_ext_module.h>
#include <njt_name_resolver_module.h>
#include <njt_http_upstream_dynamic_servers.h>
#include <njt_stream_upstream_dynamic_servers.h>
#include <njt_http_ext_module.h>

extern njt_cycle_t *njet_master_cycle;
#if (NJT_HTTP_ADD_DYNAMIC_UPSTREAM)
static void njt_http_upstream_dynamic_server_delete_upstream(void *data);
#endif
#if (NJT_STREAM_ADD_DYNAMIC_UPSTREAM)
static void njt_stream_upstream_dynamic_server_delete_upstream(void *data);
#endif
static njt_int_t njt_name_resolver_init_process(
    njt_cycle_t *cycle);
static njt_int_t njt_http_upstream_dynamic_servers_cache_server(njt_cycle_t *cycle);
static void njt_http_upstream_dynamic_server_resolve(njt_event_t *ev);
static void njt_http_upstream_dynamic_server_resolve_handler(
    njt_resolver_ctx_t *ctx);
static njt_http_upstream_rr_peer_t *
njt_http_upstream_zone_copy_parent_peer(njt_http_upstream_rr_peers_t *peers,
                                        njt_http_upstream_server_t *us, njt_int_t alloc_id);
static njt_int_t
njt_http_resolve_cmp_nodes(const void *one, const void *two);
static njt_http_upstream_rr_peer_t *
njt_http_upstream_zone_copy_peer(njt_http_upstream_rr_peers_t *peers,
                                 njt_str_t *server,
                                 njt_str_t *host, in_port_t port, struct sockaddr *sockaddr, socklen_t socklen, njt_str_t route);
static void njt_http_upstream_modify_dynamic_server(njt_http_upstream_srv_conf_t *upstream_conf,
                                                    njt_http_upstream_rr_peer_t *peer, njt_int_t lock);
static void njt_http_upstream_free_dynamic_server(njt_http_upstream_srv_conf_t *upstream_conf,
                                                  njt_str_t server, njt_int_t id, njt_int_t lock);
static njt_http_upstream_dynamic_server_conf_t *njt_http_upstream_allocate_dynamic_server();
static void njt_http_upstream_dynamic_server_delete_server(
    njt_http_upstream_dynamic_server_conf_t *dynamic_server, njt_int_t lock);
////////stream///
static njt_int_t njt_stream_upstream_dynamic_servers_cache_server(njt_cycle_t *cycle);
static void njt_stream_upstream_dynamic_server_resolve(njt_event_t *ev);
static njt_stream_upstream_rr_peer_t *
njt_stream_upstream_zone_copy_parent_peer(njt_stream_upstream_rr_peers_t *peers,
                                          njt_stream_upstream_server_t *us, njt_int_t alloc_id);
static void njt_stream_upstream_dynamic_server_resolve_handler(
    njt_resolver_ctx_t *ctx);
static void njt_stream_upstream_modify_dynamic_server(njt_stream_upstream_srv_conf_t *upstream_conf,
                                                      njt_stream_upstream_rr_peer_t *peer, njt_int_t lock);
static void njt_stream_upstream_free_dynamic_server(njt_stream_upstream_srv_conf_t *upstream_conf,
                                                    njt_str_t server, njt_int_t id, njt_int_t lock);
static njt_stream_upstream_rr_peer_t *
njt_stream_upstream_zone_copy_peer(njt_stream_upstream_rr_peers_t *peers,
                                   njt_str_t *server,
                                   njt_str_t *host, in_port_t port, struct sockaddr *sockaddr, socklen_t socklen);
static njt_stream_upstream_dynamic_server_conf_t *njt_stream_upstream_allocate_dynamic_server();
static njt_int_t
njt_stream_resolve_cmp_nodes(const void *one, const void *two);
static void njt_stream_upstream_dynamic_server_delete_server(
    njt_stream_upstream_dynamic_server_conf_t *dynamic_server, njt_int_t lock);
static void njt_http_upstream_check_dynamic_server(njt_event_t *ev);
static void njt_stream_upstream_check_dynamic_server(njt_event_t *ev);
static void *njt_name_resolver_main_conf(njt_conf_t *cf);
static njt_http_upstream_rr_peer_t *
njt_http_upstream_copy_parent_peer(njt_http_upstream_srv_conf_t *upstream_conf,
                                   njt_http_upstream_server_t *us, njt_int_t alloc_id);
static njt_stream_upstream_rr_peer_t *
njt_stream_upstream_copy_parent_peer(njt_stream_upstream_srv_conf_t *upstream_conf,
                                     njt_stream_upstream_server_t *us, njt_int_t alloc_id);
static void
njt_http_upstream_remove_parent_node(njt_http_upstream_srv_conf_t *upstream,
                                     njt_http_upstream_dynamic_server_conf_t *dynamic_server);
static void
njt_stream_upstream_remove_parent_node(njt_stream_upstream_srv_conf_t *upstream,
                                       njt_stream_upstream_dynamic_server_conf_t *dynamic_server);

static njt_command_t njt_name_resolver_commands[] = {
    njt_null_command};

static njt_http_module_t njt_name_resolver_module_ctx = {
    NULL,                        /* preconfiguration */
    NULL,                        /* postconfiguration */
    njt_name_resolver_main_conf, /* create main configuration */
    NULL,                        /* init main configuration */
    NULL,                        /* create server configuration */
    NULL,                        /* merge server configuration */

    NULL, /* create location configuration */
    NULL  /* merge location configuration */
};

njt_module_t njt_name_resolver_module = {
    NJT_MODULE_V1,
    &njt_name_resolver_module_ctx,  /* module context */
    njt_name_resolver_commands,     /* module directives */
    NJT_HTTP_MODULE,                /* module type */
    NULL,                           /* init master */
    NULL,                           /* init module */
    njt_name_resolver_init_process, /* init process */
    NULL,                           /* init thread */
    NULL,                           /* exit thread */
    NULL,                           /* exit process */
    NULL,                           /* exit master */
    NJT_MODULE_V1_PADDING};

static void *njt_name_resolver_main_conf(njt_conf_t *cf)
{
    njt_name_resolver_main_conf_t *mcf;
    mcf = njt_pcalloc(cf->pool,
                      sizeof(njt_name_resolver_main_conf_t));
    if (mcf == NULL)
    {
        return NULL;
    }
    return mcf;
}

static njt_int_t njt_name_resolver_init_process_stream(
    njt_cycle_t *cycle)
{
    njt_stream_upstream_dynamic_server_main_conf_t *udsmcf;
    njt_stream_upstream_dynamic_server_conf_t *dynamic_server;
    njt_uint_t i;
    njt_list_part_t *part;
    njt_event_t *timer = NULL;
    njt_uint_t refresh_in;
    njt_cycle_t *curr_njt_cycle;
    njt_stream_conf_ctx_t *conf_ctx;

    if (njet_master_cycle != NULL)
    {
        curr_njt_cycle = njet_master_cycle;
    }
    else
    {
        curr_njt_cycle = cycle;
    }
    conf_ctx = (njt_stream_conf_ctx_t *)njt_get_conf(curr_njt_cycle->conf_ctx, njt_stream_module);
    if (conf_ctx == NULL)
    {
        return NJT_OK;
    }
    njt_stream_upstream_dynamic_servers_cache_server(curr_njt_cycle);
    udsmcf = njt_stream_cycle_get_module_main_conf(curr_njt_cycle,
                                                   njt_stream_upstream_dynamic_servers_module);
    if (udsmcf == NULL)
    {
        return NJT_OK;
    }

    njt_log_debug(NJT_LOG_DEBUG_CORE, cycle->log, 0,
                  "start stream name_resolver!");
    part = &udsmcf->dynamic_servers->part;
    dynamic_server = (njt_stream_upstream_dynamic_server_conf_t *)part->elts;

    for (i = 0;; i++)
    {
        if (i >= part->nelts)
        {
            if (part->next == NULL)
                break;
            part = part->next;
            dynamic_server = part->elts;
            i = 0;
        }
        // dynamic_server[i].parent_id = -1;
        if (njet_master_cycle != NULL && dynamic_server[i].upstream_conf->resolver->log != njt_cycle->log)
        {
            dynamic_server[i].upstream_conf->resolver->log = njt_cycle->log;
        }
        dynamic_server[i].valid = dynamic_server[i].upstream_conf->valid;
        timer = &dynamic_server[i].timer;
        timer->handler = njt_stream_upstream_dynamic_server_resolve;
        timer->log = njt_cycle->log;
        timer->data = &dynamic_server[i];
        timer->cancelable = 1;
        refresh_in = njt_random() % 1000;
        njt_log_debug(NJT_LOG_DEBUG_CORE, cycle->log, 0,
                      "stream upstream-dynamic-servers: Initial DNS refresh of '%V' in %ims",
                      &dynamic_server[i].host, refresh_in);
        njt_add_timer(timer, refresh_in);
    }

    timer = &udsmcf->timer;
    timer->handler = njt_stream_upstream_check_dynamic_server;
    timer->log = njt_cycle->log;
    timer->data = cycle;
    timer->cancelable = 1;
    refresh_in = njt_random() % 1000;
    njt_add_timer(timer, refresh_in);

    return NJT_OK;
}
static njt_int_t njt_name_resolver_init_process_http(
    njt_cycle_t *cycle)
{

    njt_http_upstream_dynamic_server_main_conf_t *udsmcf;
    njt_http_upstream_dynamic_server_conf_t *dynamic_server;
    njt_uint_t i;
    njt_list_part_t *part;
    njt_event_t *timer = NULL;
    njt_uint_t refresh_in;
    njt_cycle_t *curr_njt_cycle;
    njt_http_conf_ctx_t *conf_ctx;
    if (njet_master_cycle != NULL)
    {
        curr_njt_cycle = njet_master_cycle;
    }
    else
    {
        curr_njt_cycle = (njt_cycle_t *)njt_cycle;
    }
    conf_ctx = (njt_http_conf_ctx_t *)njt_get_conf(curr_njt_cycle->conf_ctx, njt_http_module);
    if (conf_ctx == NULL)
    {
        return NJT_OK;
    }
#if (NJT_HTTP_ADD_DYNAMIC_UPSTREAM)
    // register dyn upstream handler
    njt_str_t keyy = njt_string(UPSTREAM_OBJ);
    njt_http_object_change_reg_info_t reg;
    njt_memzero(&reg, sizeof(njt_http_object_change_reg_info_t));
    reg.del_handler = njt_http_upstream_dynamic_server_delete_upstream;
    njt_http_object_register_notice(&keyy, &reg);
#endif
#if (NJT_STREAM_ADD_DYNAMIC_UPSTREAM)
    // register dyn upstream handler
    njt_str_t keyy_ups = njt_string(STREAM_UPSTREAM_OBJ);
    njt_http_object_change_reg_info_t reg_ups;
    njt_memzero(&reg_ups, sizeof(njt_http_object_change_reg_info_t));
    reg_ups.del_handler = njt_stream_upstream_dynamic_server_delete_upstream;
    njt_http_object_register_notice(&keyy_ups, &reg_ups);
#endif

    njt_http_upstream_dynamic_servers_cache_server(curr_njt_cycle);
    udsmcf = njt_http_cycle_get_module_main_conf(curr_njt_cycle,
                                                 njt_http_upstream_dynamic_servers_module);

    if (udsmcf == NULL)
        return NJT_OK;
    njt_log_debug(NJT_LOG_DEBUG_CORE, cycle->log, 0,
                  "start http name_resolver!");

    part = &udsmcf->dynamic_servers->part;
    dynamic_server = (njt_http_upstream_dynamic_server_conf_t *)part->elts;

    for (i = 0;; i++)
    {
        if (i >= part->nelts)
        {
            if (part->next == NULL)
                break;
            part = part->next;
            dynamic_server = part->elts;
            i = 0;
        }
        // dynamic_server[i].parent_id = -1;
        if (njet_master_cycle != NULL && dynamic_server[i].upstream_conf->resolver->log != njt_cycle->log)
        {
            dynamic_server[i].upstream_conf->resolver->log = njt_cycle->log;
        }
        dynamic_server[i].valid = dynamic_server[i].upstream_conf->valid;
        timer = &dynamic_server[i].timer;
        timer->handler = njt_http_upstream_dynamic_server_resolve;
        timer->log = njt_cycle->log;
        timer->data = &dynamic_server[i];
        timer->cancelable = 1;
        refresh_in = njt_random() % 1000;
        njt_log_debug(NJT_LOG_DEBUG_CORE, cycle->log, 0,
                      "http upstream-dynamic-servers: Initial DNS refresh of '%V' in %ims[%d],id=%d",
                      &dynamic_server[i].host, refresh_in, dynamic_server[i].valid, dynamic_server[i].us->parent_id);
        njt_add_timer(timer, refresh_in);
    }
    timer = &udsmcf->timer;
    timer->handler = njt_http_upstream_check_dynamic_server;
    timer->log = njt_cycle->log;
    timer->data = cycle;
    timer->cancelable = 1;
    refresh_in = njt_random() % 1000;
    njt_add_timer(timer, refresh_in);

    return NJT_OK;
}
static njt_int_t njt_name_resolver_init_process(
    njt_cycle_t *cycle)
{
    njt_conf_ext_t *mcf;
    if (njet_master_cycle != NULL)
    {
        mcf = (njt_conf_ext_t *)njt_get_conf(njet_master_cycle->conf_ctx, njt_conf_ext_module);
    }
    else
    {
        mcf = (njt_conf_ext_t *)njt_get_conf(njt_cycle->conf_ctx, njt_conf_ext_module);
    }
    if (njet_master_cycle == NULL && (mcf->enabled == 0 || mcf->enabled == NJT_CONF_UNSET))
    { // worker 不做
        return NJT_OK;
    }
    if (njet_master_cycle == NULL)
    {
        if ((njt_process != NJT_PROCESS_WORKER && njt_process != NJT_PROCESS_SINGLE) || njt_worker != 0)
        {
            /*only works in the worker 0 prcess.*/
            return NJT_OK;
        }
    }
    if (njet_master_cycle != NULL)
    {
        if (mcf != NULL && mcf->enabled == 1)
        {
            return NJT_OK;
        }
    }
    njt_name_resolver_init_process_http(cycle);
    njt_name_resolver_init_process_stream(cycle);
    return NJT_OK;
}

#if (NJT_HTTP_ADD_DYNAMIC_UPSTREAM)
static void njt_http_upstream_dynamic_server_delete_upstream(void *data)
{
    njt_http_upstream_dynamic_server_main_conf_t *udsmcf;
    njt_list_part_t *part;
    njt_uint_t i;
    njt_cycle_t *curr_njt_cycle;
    njt_http_upstream_dynamic_server_conf_t *dynamic_server;
    njt_http_upstream_srv_conf_t *upstream = data;

    if (njet_master_cycle != NULL)
    {
        curr_njt_cycle = njet_master_cycle;
    }
    else
    {
        curr_njt_cycle = (njt_cycle_t *)njt_cycle;
    }

    udsmcf = njt_http_cycle_get_module_main_conf(curr_njt_cycle,
                                                 njt_http_upstream_dynamic_servers_module);

    if (udsmcf == NULL)
        return;
    part = &udsmcf->dynamic_servers->part;
    dynamic_server = (njt_http_upstream_dynamic_server_conf_t *)part->elts;

    for (i = 0;; i++)
    {
        if (i >= part->nelts)
        {
            if (part->next == NULL)
                break;
            part = part->next;
            dynamic_server = part->elts;
            i = 0;
        }
        if (upstream == dynamic_server[i].upstream_conf)
        {
            if (dynamic_server[i].timer.timer_set)
            {
                njt_del_timer(&dynamic_server[i].timer);

                njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0,
                              "del name_resolver=%V", &dynamic_server[i].host);
            }
            //dynamic_server[i].upstream_conf = NULL;
            //dynamic_server[i].parent_node = NULL;
            //dynamic_server[i].crc32 = 0;
            if (dynamic_server[i].ctx != NULL)
            {
                njt_resolve_name_done(dynamic_server[i].ctx);
                dynamic_server[i].ctx = NULL;
            }
            njt_memzero(&dynamic_server[i],sizeof(njt_http_upstream_dynamic_server_conf_t));
        }
    }
    return;
}
#endif

static njt_int_t njt_http_upstream_dynamic_servers_cache_server(njt_cycle_t *cycle)
{
    njt_uint_t i;
    njt_flag_t have;
    njt_http_upstream_rr_peers_t *peers;
    njt_http_upstream_main_conf_t *umcf;
    njt_http_upstream_srv_conf_t **uscfp;
    njt_http_upstream_srv_conf_t *uscf;
    // njt_http_upstream_srv_conf_t                  *upstream_conf;
    njt_http_upstream_dynamic_server_main_conf_t *udsmcf;
    njt_url_t u;
    njt_http_upstream_dynamic_server_conf_t *dynamic_server = NULL;
    njt_http_upstream_server_t *us;
    njt_http_upstream_rr_peer_t *peer;

    umcf = njt_http_cycle_get_module_main_conf(cycle, njt_http_upstream_module);
    udsmcf = njt_http_cycle_get_module_main_conf(cycle,
                                                 njt_http_upstream_dynamic_servers_module);

    have = 0;
    if (umcf == NULL || udsmcf == NULL)
        return have;

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++)
    {
        uscf = uscfp[i];
        peers = uscf->peer.data;
        if (peers->parent_node != NULL)
        {
            njt_log_debug(NJT_LOG_DEBUG_CORE, cycle->log, 0,
                          "upstream-dynamic-servers: parent_node not null line=%d", __LINE__);

            njt_http_upstream_rr_peers_wlock(peers);
            for (peer = peers->parent_node; peer; peer = peer->next)
            {

                if (peer->parent_id == -1)
                    continue;
                have = 1;
                dynamic_server = njt_list_push(&udsmcf->cache_servers);
                njt_memzero(dynamic_server, sizeof(njt_http_upstream_dynamic_server_conf_t));

                njt_memzero(&u, sizeof(njt_url_t));
                us = njt_pcalloc(uscf->pool, sizeof(njt_http_upstream_server_t));
                njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0, "new us=%p,row=%d", us, __LINE__);
                if (us == NULL)
                {
                    udsmcf->dynamic_servers = &udsmcf->cache_servers;
                    return have;
                }
                us->name.data = njt_pcalloc(uscf->pool, peer->server.len);
                if (us->name.data == NULL)
                    continue;
                us->name.len = peer->server.len;
                us->route.data = njt_pcalloc(uscf->pool, peer->route.len);
                if (us->route.data == NULL)
                    continue;
                us->route.len = peer->route.len;

                njt_memcpy(us->name.data, peer->server.data, peer->server.len);
                njt_memcpy(us->route.data, peer->route.data, peer->route.len);

                u.url = us->name;
                u.default_port = 80;
                u.no_resolve = 1;
                njt_parse_url(uscf->pool, &u);

                us->backup = peer->set_backup;
                us->down = peer->down;
                us->addrs = NULL;
                us->naddrs = 0;
                us->weight = peer->weight;
                us->max_conns = peer->max_conns;
                us->max_fails = peer->max_fails;
                us->fail_timeout = peer->fail_timeout;
                us->slow_start = peer->slow_start;

                if (peer->service.len != 0)
                {
                    us->service.data = njt_pcalloc(uscf->pool, peer->service.len);
                    if (us->service.data == NULL)
                        continue;
                    us->service.len = peer->service.len;
                    njt_memcpy(us->service.data, peer->service.data, peer->service.len);
                }
                dynamic_server->us = us;
                dynamic_server->free_us = 1;
                dynamic_server->upstream_conf = uscf;

                dynamic_server->parent_node = peer;

                dynamic_server->host = u.host;
                dynamic_server->port = (in_port_t)(u.no_port ? u.default_port : u.port);
            }
            njt_http_upstream_rr_peers_unlock(peers);
        }
    }
    if (have)
    {
        udsmcf->dynamic_servers = &udsmcf->cache_servers;
        njt_log_debug(NJT_LOG_DEBUG_CORE, cycle->log, 0,
                      "upstream-dynamic-servers: have line=%d", __LINE__);
    }
    return have;
}
static void njt_http_upstream_dynamic_server_resolve(njt_event_t *ev)
{

    // njt_http_upstream_dynamic_server_main_conf_t  *udsmcf;
    njt_http_upstream_dynamic_server_conf_t *dynamic_server;
    njt_resolver_ctx_t *ctx;
    njt_http_upstream_srv_conf_t *upstream_conf;
    // njt_http_upstream_rr_peer_t                   *parent_peer;
    njt_http_upstream_server_t *us;

    dynamic_server = ev->data;
    upstream_conf = dynamic_server->upstream_conf;
    if (upstream_conf->resolver == NULL)
    {
        njt_log_error(NJT_LOG_ALERT, ev->log, 0,
                      "upstream-dynamic-servers: resolver null for '%V'",
                      &dynamic_server->host);
        return;
    }

    us = dynamic_server->us;
    if (dynamic_server->parent_node == NULL)
    {
        dynamic_server->parent_node = njt_http_upstream_copy_parent_peer(upstream_conf, us, 0);
        if (dynamic_server->parent_node == NULL)
        {
            njt_log_error(NJT_LOG_ALERT, ev->log, 0,
                          "allocate njt_http_upstream_copy_parent_peer error for '%V'",
                          &dynamic_server->host);
            return;
        }
        dynamic_server->parent_node->id = us->parent_id;
        dynamic_server->parent_node->parent_id = us->parent_id;

        dynamic_server->parent_node->fail_timeout = us->fail_timeout;
        dynamic_server->parent_node->max_conns = us->max_conns;
        dynamic_server->parent_node->max_fails = us->max_fails;
        dynamic_server->parent_node->slow_start = us->slow_start;
        dynamic_server->parent_node->weight = us->weight;
        dynamic_server->parent_node->down = us->down;
        dynamic_server->parent_node->set_backup = us->backup;

        // dynamic_server->parent_node->set_down = us->down;
        dynamic_server->parent_node->hc_down = (upstream_conf->hc_type == 0 ? 0 : 2); //(upstream_conf->hc_type == 0 ?0:2)
    }
    ctx = njt_resolve_start(upstream_conf->resolver, NULL);
    if (ctx == NULL)
    {
        njt_log_error(NJT_LOG_ALERT, ev->log, 0,
                      "upstream-dynamic-servers: resolver start error for '%V'",
                      &dynamic_server->host);
        return;
    }

    if (ctx == NJT_NO_RESOLVER)
    {
        njt_log_error(NJT_LOG_ALERT, ev->log, 0,
                      "upstream-dynamic-servers: no resolver defined to resolve '%V'",
                      &dynamic_server->host);
        return;
    }
    dynamic_server->ctx = ctx;
    ctx->name = dynamic_server->host;
    ctx->handler = njt_http_upstream_dynamic_server_resolve_handler;
    ctx->data = dynamic_server;
    ctx->service = dynamic_server->us->service;
    ctx->timeout = upstream_conf->resolver_timeout;
    njt_log_debug(NJT_LOG_DEBUG_CORE, ev->log, 0,
                  "njt_http_upstream_dynamic_server_resolve host=%V", &dynamic_server->host);
    if (njt_resolve_name(ctx) != NJT_OK)
    {
        njt_log_error(NJT_LOG_ALERT, ev->log, 0,
                      "upstream-dynamic-servers: njt_resolve_name failed for '%V'", &ctx->name);

        dynamic_server->ctx = NULL;
        njt_add_timer(&dynamic_server->timer, 1000);
    }
}

#define njt_http_upstream_zone_addr_marked(addr) \
    ((uintptr_t)(addr)->sockaddr & 1)

#define njt_http_upstream_zone_mark_addr(addr) \
    (addr)->sockaddr = (struct sockaddr *)((uintptr_t)(addr)->sockaddr | 1)

#define njt_http_upstream_zone_unmark_addr(addr) \
    (addr)->sockaddr =                           \
        (struct sockaddr *)((uintptr_t)(addr)->sockaddr & ~((uintptr_t)1))

static void njt_http_upstream_dynamic_server_resolve_handler(
    njt_resolver_ctx_t *ctx)
{
    njt_http_upstream_dynamic_server_conf_t *dynamic_server;
    njt_http_upstream_srv_conf_t *upstream;
    njt_uint_t i, naddrs;
    struct sockaddr *sockaddr;
    uint32_t refresh_in;
    time_t fail_timeout;
    njt_int_t weight, max_conns, max_fails, slow_start, down, hc_down;
    njt_str_t *server;
    in_port_t port;
    njt_http_upstream_rr_peer_t *peer, *next, *prev, *tail_peer;
    njt_http_upstream_rr_peers_t *peers, *peers_data;
    uint32_t crc32;
    njt_int_t rc = NJT_OK;
    njt_msec_t now_time;

    njt_resolver_addr_t *addr;
    u_short min_priority;
    njt_uint_t backup, addr_backup;
    njt_event_t *event;
    njt_resolver_srv_name_t *srv;

    backup = 0;
    min_priority = 65535;
    if (njt_quit || njt_exiting || njt_terminate)
    {
        njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0,
                      "upstream-dynamic-servers: worker is about to exit, do not set the timer again");
        return;
    }
    dynamic_server = ctx->data;
    event = &dynamic_server->timer;
    njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0,
                  "http upstream-dynamic-servers: Finished resolving '%V' mtime=%d", &ctx->name, dynamic_server->valid);

    for (i = 0; i < ctx->nsrvs; i++)
    {
        srv = &ctx->srvs[i];

        if (srv->state)
        {
            njt_log_error(NJT_LOG_ERR, event->log, 0,
                          "%V could not be resolved (%i: %s) "
                          "while resolving service %V of %V",
                          &srv->name, srv->state,
                          njt_resolver_strerror(srv->state), &ctx->service,
                          &ctx->name);
        }
    }
    if (ctx->state)
    {
        if (ctx->service.len)
        {
            njt_log_error(NJT_LOG_ERR, event->log, 0,
                          "service %V of %V could  not be resolved (%i: %s)",
                          &ctx->service, &ctx->name, ctx->state,
                          njt_resolver_strerror(ctx->state));
        }
        else
        {
            njt_log_error(NJT_LOG_ERR, event->log, 0,
                          "%V could not be resolved (%i: %s)",
                          &ctx->name, ctx->state,
                          njt_resolver_strerror(ctx->state));
        }
        if (ctx->state != NJT_RESOLVE_NXDOMAIN)
        {
            njt_resolve_name_done(ctx);

            njt_add_timer(event, njt_max(dynamic_server->upstream_conf->resolver_timeout, 1000));
            return;
        }
        ctx->naddrs = 0;
    }
    naddrs = ctx->naddrs;
    if (naddrs == 0)
    {
        goto operation;
    }
    if (ctx->naddrs == 0 || ctx->addrs == NULL || ctx->state)
    {
        /*reset the recorded data*/

        dynamic_server->count = 0;
        dynamic_server->crc32 = 0;
        if (dynamic_server->count != 0 || dynamic_server->crc32 != 0)
        {
            /*Try to delete all the peers of the resolver name*/
            goto operation;
        }

        njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0,
                      "naddrs and dns state %d %d.", ctx->naddrs, ctx->state);
        // goto end;
    }

    /* check if the result changed or not*/
    sockaddr = njt_calloc(ctx->naddrs * sizeof(struct sockaddr),
                          njt_cycle->log);
    if (sockaddr == NULL)
    {
        goto end;
    }

    for (i = 0; i < naddrs; i++)
    {

        switch (ctx->addrs[i].sockaddr->sa_family)
        {
        case AF_INET6:
            if (dynamic_server->us->service.len == 0)
            {
                ((struct sockaddr_in6 *)ctx->addrs[i].sockaddr)->sin6_port = htons((u_short)
                                                                                       dynamic_server->port);
            }
            break;

        default:
            if (dynamic_server->us->service.len == 0)
            {
                ((struct sockaddr_in *)ctx->addrs[i].sockaddr)->sin_port = htons((u_short)dynamic_server->port);
            }
        }

        njt_memcpy(&sockaddr[i], ctx->addrs[i].sockaddr, sizeof(struct sockaddr));
    }

    /*calculate the crc*/
    njt_sort((void *)sockaddr, ctx->naddrs, sizeof(struct sockaddr),
             njt_http_resolve_cmp_nodes);
    njt_crc32_init(crc32);
    for (i = 0; i < naddrs; i++)
    {
        njt_crc32_update(&crc32, (u_char *)&sockaddr[i], sizeof(struct sockaddr));
    }
    njt_crc32_final(crc32);
    njt_free(sockaddr);

    /*further compare the value*/
    if (dynamic_server->count == naddrs && dynamic_server->crc32 == crc32)
    {
        // njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,
        //             "upstream-dynamic-servers: DNS result isn't changed '%V'", &ctx->name);
        goto end;
    }
    else
    {
        njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                      "http upstream-dynamic-servers: DNS result is changed '%V' num=%d", &ctx->name, naddrs);
    }

    dynamic_server->count = naddrs;
    dynamic_server->crc32 = crc32;
    for (i = 0; i < ctx->naddrs; i++)
    {
        min_priority = njt_min(ctx->addrs[i].priority, min_priority);
    }
#if (NJT_DEBUG)
    {
        u_char text[NJT_SOCKADDR_STRLEN];
        size_t len;

        for (i = 0; i < ctx->naddrs; i++)
        {
            len = njt_sock_ntop(ctx->addrs[i].sockaddr, ctx->addrs[i].socklen,
                                text, NJT_SOCKADDR_STRLEN, 1);

            njt_log_debug7(NJT_LOG_DEBUG_HTTP, event->log, 0,
                           "name %V was resolved to %*s "
                           "s:\"%V\" n:\"%V\" w:%d %s",
                           &ctx->name, len, text, &ctx->service,
                           &ctx->addrs[i].name, ctx->addrs[i].weight,
                           ctx->addrs[i].priority != min_priority ? "backup" : "");
        }
    }
#endif

operation:

    upstream = dynamic_server->upstream_conf;
    peers = upstream->peer.data;

    /*resolve must coexist with share memory*/
    if (peers->shpool)
    {
        /*Try to copy the peers to the shared memory zone*/
        rc = NJT_OK;
        fail_timeout = dynamic_server->parent_node->fail_timeout;
        weight = dynamic_server->parent_node->weight;
        max_conns = dynamic_server->parent_node->max_conns;
        max_fails = dynamic_server->parent_node->max_fails;
        slow_start = dynamic_server->parent_node->slow_start;
        down = dynamic_server->parent_node->down;
        // name = ctx->name;

        port = dynamic_server->port;
        hc_down = dynamic_server->parent_node->hc_down;

        if (upstream->mandatory == 1)
        { // zyg use upstream  hc_type
            hc_down = 2;
        }

        peers_data = (dynamic_server->us->backup > 0 ? peers->next : peers);

        njt_http_upstream_rr_peers_wlock(peers);
        for (peer = peers_data->peer, prev = NULL; peer; peer = next)
        {

            next = peer->next;
            rc = NJT_OK;

            if (peer->parent_id != (njt_int_t)dynamic_server->parent_node->id)
            {
                prev = peer;
                continue;
            }
            for (i = 0; i < naddrs; ++i)
            {
                addr = &ctx->addrs[i];

                addr_backup = (addr->priority != min_priority);
                if (addr_backup != backup)
                {
                    // continue;
                }

                if (njt_http_upstream_zone_addr_marked(addr))
                {
                    continue;
                }

                if (njt_cmp_sockaddr(peer->sockaddr, peer->socklen,
                                     addr->sockaddr, addr->socklen,
                                     1) != NJT_OK)
                {
                    continue;
                }

                if (dynamic_server->us->service.len)
                {
                    if (addr->name.len != peer->server.len && njt_strncmp(addr->name.data, peer->server.data,
                                                                          addr->name.len))
                    {
                        continue;
                    }
                }

                njt_http_upstream_zone_mark_addr(addr); // 找到了要保留。

                prev = peer;
                goto skip_del;
            }
            if (peer->down == 0 && peer->del_pending == 0 && peers_data->tries > 0)
            {
                peers_data->tries--;
            }
            peers_data->number--;
            peers_data->total_weight -= peer->weight;
            peers_data->single = (peers_data->number <= 1);
            peers_data->weighted = (peers_data->total_weight != peers_data->number);

            /*The IP is not exists, down or free this peer.*/
            if (peer->conns > 0)
            {
                peer->down = 1;
                peer->del_pending = 1;
            }
            else
            {
                if (prev == NULL)
                {
                    peers_data->peer = next;
                }
                else
                {
                    prev->next = next;
                }
                njt_shmtx_lock(&peers_data->shpool->mutex);
                if (upstream->peer.ups_srv_handlers != NULL && upstream->peer.ups_srv_handlers->update_handler)
                {
                    upstream->peer.ups_srv_handlers->del_handler(upstream, peers->shpool, peer);
                }
                njt_http_upstream_free_peer_memory(peers_data->shpool, peer);
                njt_shmtx_unlock(&peers_data->shpool->mutex);
            }
        skip_del:
            continue;
        }
        if (rc != NJT_ERROR && dynamic_server->parent_node->parent_id != -1)
        {

            now_time = njt_time();
            for (i = 0; i < naddrs; ++i)
            {
                addr = &ctx->addrs[i];
                addr_backup = (addr->priority != min_priority);
                if (addr_backup != backup)
                {
                    // continue;
                }

                if (njt_http_upstream_zone_addr_marked(addr))
                {
                    njt_http_upstream_zone_unmark_addr(addr);
                    continue;
                }
                server = dynamic_server->us->service.len ? &addr->name : &dynamic_server->parent_node->server;

                if (dynamic_server->us->service.len != 0)
                {
                    port = njt_inet_get_port(ctx->addrs[i].sockaddr);
                    // njt_inet_set_port(peer->sockaddr, port);
                }
                peer = njt_http_upstream_zone_copy_peer(peers, NULL, server, port,
                                                        ctx->addrs[i].sockaddr, ctx->addrs[i].socklen, dynamic_server->parent_node->route);
                if (peer == NULL)
                {
                    continue;
                }
                peer->fail_timeout = fail_timeout;
                peer->max_conns = max_conns;
                peer->max_fails = max_fails;
                peer->slow_start = slow_start;
                // peer->dynamic = 1;
                peer->id = peers->next_order++;
                peer->weight = weight;
                peer->effective_weight = weight;
                peer->rr_effective_weight = weight * NJT_WEIGHT_POWER;
                peer->current_weight = 0;
                peer->rr_current_weight = 0;
                peer->down = down;
                peer->hc_down = hc_down;
                peer->hc_upstart = now_time;
                peer->next = NULL;
                peer->parent_id = dynamic_server->parent_node->id;
                peers_data->number++;
                if (peer->down == 0)
                {
                    peers_data->tries++;
                }
                peers_data->total_weight += weight;
                if (peers_data->peer == NULL)
                {
                    peers_data->peer = peer;
                }
                else
                {
                    for (tail_peer = peers_data->peer; tail_peer->next != NULL; tail_peer = tail_peer->next)
                        ;
                    tail_peer->next = peer;
                    if (upstream->peer.ups_srv_handlers != NULL && upstream->peer.ups_srv_handlers->update_handler)
                    {
                        upstream->peer.ups_srv_handlers->add_handler(upstream, peers->shpool, peer, dynamic_server->parent_node->app_data);
                    }
                }
            }
        }
        peers_data->single = (peers_data->number <= 1);
        peers->single = (peers->number + (peers->next != NULL ? peers->next->number : 0) <= 1);
        peers->update_id++;
        njt_http_upstream_rr_peers_unlock(peers);
    }

end:

    refresh_in = 1000;
    if (ctx->valid)
    {
        refresh_in = ctx->valid - njt_time();
        refresh_in *= 1000;
        refresh_in = refresh_in > 1000 ? refresh_in : 1000;
        if (dynamic_server->valid != 0)
        {
            refresh_in = dynamic_server->valid * 1000;
        }
    }
    else
    {
        if (dynamic_server->valid != 0)
        {
            refresh_in = dynamic_server->valid * 1000;
        }
    }
    if (rc != NJT_ERROR)
    {
        njt_add_timer(&dynamic_server->timer, refresh_in);
    }

    while (++i < ctx->naddrs)
    {
        njt_http_upstream_zone_unmark_addr(&ctx->addrs[i]);
    }
    njt_resolve_name_done(ctx);
    dynamic_server->ctx = NULL;

    return;
}

static njt_http_upstream_rr_peer_t *
njt_http_upstream_zone_copy_parent_peer(njt_http_upstream_rr_peers_t *peers,
                                        njt_http_upstream_server_t *us, njt_int_t alloc_id)
{
    njt_slab_pool_t *pool;
    njt_http_upstream_rr_peer_t *dst;

    pool = peers->shpool;
    if (pool == NULL)
    {
        return NULL;
    }

    njt_shmtx_lock(&pool->mutex);
    dst = njt_slab_calloc_locked(pool, sizeof(njt_http_upstream_rr_peer_t));
    if (dst == NULL)
    {
        njt_shmtx_unlock(&pool->mutex);
        return NULL;
    }

    dst->server.len = us->name.len;
    dst->server.data = njt_slab_calloc_locked(pool, dst->server.len);
    if (dst->server.data == NULL)
    {
        goto failed;
    }
    njt_memcpy(dst->server.data, us->name.data, us->name.len);

    dst->route.len = us->route.len;
    if (dst->route.len > 0)
    {
        dst->route.data = njt_slab_calloc_locked(pool, dst->route.len);
        if (dst->route.data == NULL)
        {
            goto failed;
        }
        njt_memcpy(dst->route.data, us->route.data, us->route.len);
    }
    dst->service.len = us->service.len;
    if (dst->service.len > 0)
    {
        dst->service.data = njt_slab_calloc_locked(pool, dst->service.len);
        if (dst->service.data == NULL)
        {
            goto failed;
        }
        njt_memcpy(dst->service.data, us->service.data, us->service.len);
    }
    if (alloc_id == 1)
    {
        dst->id = peers->next_order++;
    }
    dst->next = NULL;
    if (peers->parent_node == NULL)
    {
        peers->parent_node = dst;
    }
    else
    {
        dst->next = peers->parent_node;
        peers->parent_node = dst;
    }
    njt_shmtx_unlock(&pool->mutex);
    return dst;

failed:
    njt_http_upstream_free_peer_memory(pool, dst);
    njt_shmtx_unlock(&pool->mutex);

    return NULL;
}
static njt_http_upstream_rr_peer_t *
njt_http_upstream_copy_parent_peer(njt_http_upstream_srv_conf_t *upstream_conf,
                                   njt_http_upstream_server_t *us, njt_int_t alloc_id)
{
    njt_http_upstream_rr_peers_t *peers;

    peers = upstream_conf->peer.data;
    return njt_http_upstream_zone_copy_parent_peer(peers, us, alloc_id);
}
static njt_int_t
njt_http_resolve_cmp_nodes(const void *one, const void *two)
{
    return njt_memcmp(one, two, sizeof(struct sockaddr));
}

static njt_http_upstream_rr_peer_t *
njt_http_upstream_zone_copy_peer(njt_http_upstream_rr_peers_t *peers,
                                 njt_str_t *server,
                                 njt_str_t *host, in_port_t port, struct sockaddr *sockaddr, socklen_t socklen, njt_str_t route)
{
    // size_t                        plen;
    njt_slab_pool_t *pool;
    njt_http_upstream_rr_peer_t *dst;

    pool = peers->shpool;
    if (pool == NULL)
    {
        return NULL;
    }

    njt_shmtx_lock(&pool->mutex);
    dst = njt_slab_calloc_locked(pool, sizeof(njt_http_upstream_rr_peer_t));
    if (dst == NULL)
    {
        njt_shmtx_unlock(&pool->mutex);
        return NULL;
    }

    dst->socklen = socklen;
    dst->sockaddr = NULL;
    dst->name.data = NULL;
    dst->server.data = NULL;

    if (server == NULL)
    {
        dst->server.len = host->len;
    }
    else
    {
        dst->server.len = server->len;
    }

    dst->sockaddr = njt_slab_calloc_locked(pool, sizeof(njt_sockaddr_t));
    if (dst->sockaddr == NULL)
    {
        goto failed;
    }

    dst->name.data = njt_slab_calloc_locked(pool, NJT_SOCKADDR_STRLEN);
    if (dst->name.data == NULL)
    {
        goto failed;
    }

    njt_memcpy(dst->sockaddr, sockaddr, socklen);
    njt_inet_set_port(dst->sockaddr, port);

    // if (host->service.len == 0) {
    //     port = njt_inet_get_port(template->sockaddr);
    //     njt_inet_set_port(peer->sockaddr, port);
    // }
    dst->name.len = njt_sock_ntop(dst->sockaddr, socklen, dst->name.data,
                                  NJT_SOCKADDR_STRLEN, 1);
    dst->route.len = route.len;
    if (dst->route.len > 0)
    {
        dst->route.data = njt_slab_calloc_locked(pool, dst->route.len);
        if (dst->route.data == NULL)
        {
            goto failed;
        }
        njt_memcpy(dst->route.data, route.data, route.len);
    }
    dst->server.data = njt_slab_calloc_locked(pool, dst->server.len);
    if (dst->server.data == NULL)
    {
        goto failed;
    }

    if (server == NULL)
    {
        njt_memcpy(dst->server.data, host->data, host->len);
        // njt_sprintf(dst->server.data + host->len, ":%d", port);
    }
    else
    {
        njt_memcpy(dst->server.data, server->data, server->len);
    }

    njt_shmtx_unlock(&pool->mutex);
    return dst;

failed:
    njt_http_upstream_free_peer_memory(pool, dst);
    njt_shmtx_unlock(&pool->mutex);

    return NULL;
}

static void njt_http_upstream_modify_dynamic_server(njt_http_upstream_srv_conf_t *upstream_conf,
                                                    njt_http_upstream_rr_peer_t *peer, njt_int_t lock)
{
    njt_uint_t i;
    njt_http_upstream_dynamic_server_conf_t *dynamic_server, *p;
    njt_http_upstream_dynamic_server_main_conf_t *udsmcf;
    // njt_http_upstream_rr_peers_t *peers;
    njt_list_part_t *part;
    njt_str_t service;
    njt_cycle_t *curr_njt_cycle;

    if (njet_master_cycle != NULL)
    {
        curr_njt_cycle = njet_master_cycle;
    }
    else
    {
        curr_njt_cycle = (njt_cycle_t *)njt_cycle;
    }

    udsmcf = njt_http_cycle_get_module_main_conf(curr_njt_cycle,
                                                 njt_http_upstream_dynamic_servers_module);
    if (udsmcf == NULL)
    {
        return;
    }

    part = &udsmcf->dynamic_servers->part;
    dynamic_server = (njt_http_upstream_dynamic_server_conf_t *)part->elts;

    for (i = 0;; i++)
    {
        if (i >= part->nelts)
        {
            if (part->next == NULL)
                break;
            part = part->next;
            dynamic_server = part->elts;
            i = 0;
        }
        p = &dynamic_server[i];
        if (p->upstream_conf == upstream_conf && peer->parent_id == (njt_int_t)p->parent_node->id)
        {

            if (peer->service.len == 0) // delete
            {
                if (p->us->service.len > 0)
                {
                    njt_pfree(p->upstream_conf->pool, p->us->service.data);
                    p->us->service.len = 0;
                    p->us->service.data = NULL;
                }
            }
            else
            {
                if (peer->service.len > p->us->service.len) // 释放旧值
                {
                    service.data = njt_pcalloc(p->upstream_conf->pool, peer->service.len);
                    if (service.data == NULL)
                    {
                        return;
                    }
                    service.len = peer->service.len;
                    njt_memcpy(service.data, peer->service.data, peer->service.len);
                    njt_pfree(p->upstream_conf->pool, p->us->service.data);
                }
                else
                {
                    service = p->us->service;
                    njt_memcpy(service.data, peer->service.data, peer->service.len);
                    service.len = peer->service.len;
                }
                p->us->service = service;
            }

            return;
        }
    }
}
static void njt_http_upstream_free_dynamic_server(njt_http_upstream_srv_conf_t *upstream_conf,
                                                  njt_str_t server, njt_int_t id, njt_int_t lock)
{

    njt_uint_t i;
    njt_http_upstream_dynamic_server_conf_t *dynamic_server, *p;
    njt_http_upstream_dynamic_server_main_conf_t *udsmcf;
    njt_list_part_t *part;
    njt_cycle_t *curr_njt_cycle;
    if (njet_master_cycle != NULL)
    {
        curr_njt_cycle = njet_master_cycle;
    }
    else
    {
        curr_njt_cycle = (njt_cycle_t *)njt_cycle;
    }

    udsmcf = njt_http_cycle_get_module_main_conf(curr_njt_cycle,
                                                 njt_http_upstream_dynamic_servers_module);
    if (udsmcf == NULL)
    {
        return;
    }
    part = &udsmcf->dynamic_servers->part;
    dynamic_server = (njt_http_upstream_dynamic_server_conf_t *)part->elts;

    // dynamic_server = udsmcf->dynamic_servers.elts;

    for (i = 0;; i++)
    {
        if (i >= part->nelts)
        {
            if (part->next == NULL)
                break;
            part = part->next;
            dynamic_server = part->elts;
            i = 0;
        }
        p = &dynamic_server[i];
        if (p->upstream_conf == upstream_conf && id == (njt_int_t)p->parent_node->id)
        {

            if (p->timer.timer_set)
            {
                njt_del_timer(&p->timer);
            }
            if (p->ctx != NULL)
            {
                njt_resolve_name_done(p->ctx);
                p->ctx = NULL;
            }

            njt_http_upstream_dynamic_server_delete_server(p, lock);
            if (p->us->name.len > 0)
            {
                njt_pfree(dynamic_server->upstream_conf->pool, p->us->name.data);
                p->us->name.len = 0;
                p->us->name.data = 0;
            }
            if (p->us->route.len > 0)
            {
                njt_pfree(dynamic_server->upstream_conf->pool, p->us->route.data);
                p->us->route.len = 0;
                p->us->route.data = 0;
            }
            if (dynamic_server[i].free_us == 1)
            {
                njt_pfree(upstream_conf->pool, p->us);
            }
            njt_memzero(p,sizeof(njt_http_upstream_dynamic_server_conf_t));
            break;
        }
    }
}
static njt_http_upstream_dynamic_server_conf_t *njt_http_upstream_allocate_dynamic_server()
{
    njt_uint_t i;
    njt_http_upstream_dynamic_server_conf_t *dynamic_server;
    njt_http_upstream_dynamic_server_main_conf_t *udsmcf;
    njt_list_part_t *part;
    njt_cycle_t *curr_njt_cycle;
    if (njet_master_cycle != NULL)
    {
        curr_njt_cycle = njet_master_cycle;
    }
    else
    {
        curr_njt_cycle = (njt_cycle_t *)njt_cycle;
    }
    udsmcf = njt_http_cycle_get_module_main_conf(curr_njt_cycle,
                                                 njt_http_upstream_dynamic_servers_module);
    if (udsmcf == NULL)
    {
        return NULL;
    }
    part = &udsmcf->dynamic_servers->part;
    dynamic_server = (njt_http_upstream_dynamic_server_conf_t *)part->elts;

    for (i = 0;; i++)
    {
        if (i >= part->nelts)
        {
            if (part->next == NULL)
                break;
            part = part->next;
            dynamic_server = part->elts;
            i = 0;
        }
        if (dynamic_server[i].upstream_conf == NULL)
        {
            njt_memzero(&dynamic_server[i], sizeof(njt_http_upstream_dynamic_server_conf_t));
            return &dynamic_server[i];
        }
    }

    dynamic_server = (njt_http_upstream_dynamic_server_conf_t *)njt_list_push(udsmcf->dynamic_servers);
    if (dynamic_server != NULL)
    {
        njt_memzero(dynamic_server, sizeof(njt_http_upstream_dynamic_server_conf_t));
    }

    return dynamic_server;
}
static void njt_http_upstream_dynamic_server_delete_server(
    njt_http_upstream_dynamic_server_conf_t *dynamic_server, njt_int_t lock)
{

    njt_http_upstream_srv_conf_t *upstream;
    njt_http_upstream_rr_peer_t *peer, *next, *prev;
    njt_http_upstream_rr_peers_t *peers;
    upstream = dynamic_server->upstream_conf;
    peers = upstream->peer.data;

    /*resolve must coexist with share memory*/
    if (peers->shpool)
    {
        if (lock)
        {
            njt_http_upstream_rr_peers_wlock(peers);
        }
        for (peer = peers->peer, prev = NULL; peer; peer = next)
        {

            next = peer->next;
            /*
            if (peer->host != dynamic_server)
            {
                prev = peer;
                continue;
            }*/

            if (peer->parent_id != (njt_int_t)dynamic_server->parent_node->id)
            {
                prev = peer;
                continue;
            }
            if (peer->down == 0 && peer->del_pending == 0 && peers->tries > 0)
            {
                peers->tries--;
            }
            peers->number--;
            peers->total_weight -= peer->weight;
            peers->single = (peers->number <= 1);
            peers->weighted = (peers->total_weight != peers->number);
            /*The IP is not exists, down or free this peer.*/
            if (peer->conns > 0)
            {
                peer->down = 1;
                peer->del_pending = 1;
                prev = peer;
                continue;
            }
            if (prev == NULL)
            {
                peers->peer = next;
            }
            else
            {
                prev->next = next;
            }
            njt_shmtx_lock(&peers->shpool->mutex);
            if (upstream->peer.ups_srv_handlers != NULL && upstream->peer.ups_srv_handlers->update_handler)
            {
                upstream->peer.ups_srv_handlers->del_handler(upstream, peers->shpool, peer);
            }
            njt_http_upstream_free_peer_memory(peers->shpool, peer);
            njt_shmtx_unlock(&peers->shpool->mutex);
        }
        peers->single = (peers->number + (peers->next != NULL ? peers->next->number : 0) <= 1);
        peers->update_id++;

        // remove parent_node
        njt_http_upstream_remove_parent_node(upstream, dynamic_server);
        if (lock)
        {
            njt_http_upstream_rr_peers_unlock(peers);
        }
    }
    return;
}
static void njt_http_upstream_check_dynamic_server(njt_event_t *ev)
{
    njt_http_upstream_dynamic_server_main_conf_t *udsmcf;
    njt_http_upstream_srv_conf_t *upstream_conf;
    njt_http_upstream_rr_peer_t *peer, *pre;
    njt_http_upstream_rr_peers_t *peers;
    njt_http_upstream_server_t *us;
    njt_url_t u;
    njt_uint_t i;
    njt_event_t *timer;
    njt_http_upstream_rr_peer_t *parent_node;
    njt_http_upstream_main_conf_t *umcf;
    njt_http_upstream_srv_conf_t **uscfp;
    njt_http_upstream_dynamic_server_conf_t *dynamic_server = NULL;
    njt_http_upstream_srv_conf_t *uscf;
    njt_uint_t refresh_in;
    njt_cycle_t *curr_njt_cycle;
    if (njet_master_cycle != NULL)
    {
        curr_njt_cycle = njet_master_cycle;
    }
    else
    {
        curr_njt_cycle = (njt_cycle_t *)njt_cycle;
    }

    udsmcf = njt_http_cycle_get_module_main_conf(curr_njt_cycle,
                                                 njt_http_upstream_dynamic_servers_module);
    if (udsmcf == NULL)
    {
        return;
    }
    // upstream_conf = ev->data;
    // peers = upstream_conf->peer.data;
    if (udsmcf->peers != NULL)
    {
        peers = udsmcf->peers;
        pre = NULL;
        njt_http_upstream_rr_peers_wlock(peers);
        for (peer = peers->peer; peer; peer = peer->next)
        {
            if (pre != NULL)
            {
                njt_http_upstream_free_peer_memory(peers->shpool, pre);
                pre = NULL;
            }
            upstream_conf = NULL;
            if (peer->name.len > 0)
            { // zone name !!!!!!!!!!
                umcf = njt_http_cycle_get_module_main_conf(curr_njt_cycle, njt_http_upstream_module);
                uscfp = umcf->upstreams.elts;
                for (i = 0; i < umcf->upstreams.nelts; i++)
                {
                    uscf = uscfp[i];
                    if (uscf->host.len == peer->name.len && njt_strncmp(uscf->host.data, peer->name.data, peer->name.len) == 0)
                    {
                        upstream_conf = uscf;
                        break;
                    }
                }
            }
            if (upstream_conf == NULL)
            {
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "no find upstream=%V", &peer->name);
                pre = peer;
                continue; //
            }
            if (peer->parent_id == (njt_int_t)peer->id && peer->server.data == 0)
            { // patch
                njt_http_upstream_modify_dynamic_server(upstream_conf, peer, 1);
                pre = peer;
                continue; //
            }
            else if (peer->parent_id != (njt_int_t)peer->id)
            { // delete
                njt_http_upstream_free_dynamic_server(upstream_conf, peer->server, peer->id, 1);
                pre = peer;
                continue; //
            }
            else
            {
                dynamic_server = njt_http_upstream_allocate_dynamic_server(); // njt_array_push(&udsmcf->dynamic_servers);
                if (dynamic_server == NULL)
                {
                    pre = peer;
                    continue;
                }
                us = njt_pcalloc(upstream_conf->pool, sizeof(njt_http_upstream_server_t));
                njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0, "new us=%p,row=%d", us, __LINE__);
                if (us == NULL)
                {
                    pre = peer;
                    continue; //
                }
                us->parent_id = peer->parent_id;
                if (peer->service.len > 0)
                {
                    us->service.data = njt_pcalloc(upstream_conf->pool, peer->service.len);
                    if (us->service.data == NULL)
                    {
                        pre = peer;
                        continue;
                    }
                    us->service.len = peer->service.len;
                    njt_memcpy(us->service.data, peer->service.data, peer->service.len);
                }

                us->name.data = njt_pcalloc(upstream_conf->pool, peer->server.len);
                us->name.len = peer->server.len;
                if (us->name.data == NULL)
                {
                    break;
                }
                us->route.data = njt_pcalloc(upstream_conf->pool, peer->route.len);
                us->route.len = peer->route.len;
                if (us->route.data == NULL)
                {
                    pre = peer;
                    continue;
                }
                njt_memcpy(us->name.data, peer->server.data, peer->server.len);
                njt_memcpy(us->route.data, peer->route.data, peer->route.len);

                njt_memzero(&u, sizeof(njt_url_t));
                u.url = us->name;
                u.default_port = 80;
                u.no_resolve = 1;
                u.naddrs = 0;
                u.addrs = NULL;
                njt_parse_url(upstream_conf->pool, &u);

                us->addrs = NULL; // u.addrs;
                us->naddrs = 0;   // u.naddrs;
                us->weight = peer->weight;
                us->max_fails = peer->max_fails;
                us->fail_timeout = peer->fail_timeout;
                us->max_conns = peer->max_conns;
                us->slow_start = peer->slow_start;
                us->backup = peer->set_backup;
                us->down = peer->down;

                parent_node = dynamic_server->parent_node;
                if (parent_node == NULL)
                {
                    parent_node = njt_http_upstream_copy_parent_peer(upstream_conf, us, 0);
                }
                else
                { 
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                                  "http upstream-dynamic-servers: parent_node is no null", __LINE__);
                }
                if (parent_node == NULL)
                {
                    pre = peer;
                    continue;
                }
                parent_node->id = peer->parent_id;
                parent_node->parent_id = peer->parent_id;

                njt_memzero(dynamic_server, sizeof(njt_http_upstream_dynamic_server_conf_t));
                dynamic_server->us = us;
                dynamic_server->free_us = 1;

                dynamic_server->upstream_conf = upstream_conf;
                dynamic_server->host = u.host;
                dynamic_server->port = (in_port_t)(u.no_port ? u.default_port : u.port);
                dynamic_server->parent_node = parent_node;

                dynamic_server->parent_node->fail_timeout = us->fail_timeout;
                dynamic_server->parent_node->max_conns = us->max_conns;
                dynamic_server->parent_node->max_fails = us->max_fails;
                dynamic_server->parent_node->slow_start = us->slow_start;
                dynamic_server->parent_node->weight = us->weight;
                dynamic_server->parent_node->down = us->down;
                // dynamic_server->parent_node->set_down = us->down;
                dynamic_server->parent_node->set_backup = us->backup;
                dynamic_server->parent_node->hc_down = peer->hc_down;
                dynamic_server->valid = upstream_conf->valid;

                timer = &dynamic_server->timer;
                if (timer->handler == NULL)
                {

                    timer->handler = njt_http_upstream_dynamic_server_resolve;
                    timer->log = njt_cycle->log;
                    timer->data = dynamic_server;
                    timer->cancelable = 1;
                    refresh_in = njt_random() % 1000;

                    njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0,
                                  "upstream-dynamic-servers: parent_node->id=%d,row=%d", dynamic_server->parent_node->id, __LINE__);

                    njt_http_upstream_dynamic_server_resolve(timer);
                }
            }

            pre = peer;
        }
        if (pre != NULL)
        {
            njt_http_upstream_free_peer_memory(peers->shpool, pre);
        }
        peers->peer = NULL;
        peers->number = 0;
        njt_http_upstream_rr_peers_unlock(peers);
    }
    refresh_in = njt_random() % 1000;
    njt_add_timer(&udsmcf->timer, refresh_in);
}
//////////////////////////stream ////////////////////
static njt_int_t njt_stream_upstream_dynamic_servers_cache_server(njt_cycle_t *cycle)
{
    njt_uint_t i;
    njt_flag_t have;
    njt_stream_upstream_rr_peers_t *peers;
    njt_stream_upstream_main_conf_t *umcf;
    njt_stream_upstream_srv_conf_t **uscfp;
    njt_stream_upstream_srv_conf_t *uscf;
    // njt_stream_upstream_srv_conf_t                  *upstream_conf;
    njt_stream_upstream_dynamic_server_main_conf_t *udsmcf;
    njt_url_t u;
    njt_stream_upstream_dynamic_server_conf_t *dynamic_server = NULL;
    njt_stream_upstream_server_t *us;
    njt_stream_upstream_rr_peer_t *peer;

    umcf = njt_stream_cycle_get_module_main_conf(cycle, njt_stream_upstream_module);
    udsmcf = njt_stream_cycle_get_module_main_conf(cycle,
                                                   njt_stream_upstream_dynamic_servers_module);

    have = 0;
    if (umcf == NULL || udsmcf == NULL)
        return have;
    uscfp = umcf->upstreams.elts;
    for (i = 0; i < umcf->upstreams.nelts; i++)
    {
        uscf = uscfp[i];
        peers = uscf->peer.data;
        if (peers->parent_node != NULL)
        {
            if (uscf->pool == NULL)
            {
                uscf->pool = njt_create_dynamic_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
                if (uscf->pool == NULL)
                {
                    uscf->pool = cycle->pool;
                }
            }
            njt_stream_upstream_rr_peers_wlock(peers);
            for (peer = peers->parent_node; peer; peer = peer->next)
            {

                if (peer->parent_id == -1)
                    continue;
                have = 1;
                dynamic_server = njt_list_push(&udsmcf->cache_servers);
                njt_memzero(dynamic_server, sizeof(njt_stream_upstream_dynamic_server_conf_t));

                njt_memzero(&u, sizeof(njt_url_t));

                us = njt_pcalloc(uscf->pool, sizeof(njt_stream_upstream_server_t));
                njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0, "new us=%p,row=%d", us, __LINE__);
                if (us == NULL)
                {
                    continue;
                }
                us->parent_id = peer->parent_id;
                us->name.data = njt_pcalloc(uscf->pool, peer->server.len);
                if (us->name.data == NULL)
                    continue;
                us->name.len = peer->server.len;

                njt_memcpy(us->name.data, peer->server.data, peer->server.len);

                u.url = us->name;
                u.default_port = 80;
                u.no_resolve = 1;
                njt_parse_url(uscf->pool, &u);

                us->backup = peer->set_backup;
                us->down = peer->down;
                us->addrs = NULL;
                us->naddrs = 0;
                us->weight = peer->weight;
                us->max_conns = peer->max_conns;
                us->max_fails = peer->max_fails;
                us->fail_timeout = peer->fail_timeout;
                us->slow_start = peer->slow_start;

                if (peer->service.len != 0)
                {
                    us->service.data = njt_pcalloc(uscf->pool, peer->service.len);
                    if (us->service.data == NULL)
                        continue;
                    us->service.len = peer->service.len;
                    njt_memcpy(us->service.data, peer->service.data, peer->service.len);
                }
                dynamic_server->us = us;
                dynamic_server->free_us = 1;
                dynamic_server->upstream_conf = uscf;

                dynamic_server->parent_node = peer;

                dynamic_server->host = u.host;
                dynamic_server->port = (in_port_t)(u.no_port ? u.default_port : u.port);

                njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0,
                              "upstream-dynamic-servers: parent_node->id=%d,row=%d", dynamic_server[i].parent_node->id, __LINE__);
            }
            njt_stream_upstream_rr_peers_unlock(peers);
        }
    }
    if (have)
    {
        udsmcf->dynamic_servers = &udsmcf->cache_servers;
    }
    return have;
}
static void njt_stream_upstream_dynamic_server_resolve(njt_event_t *ev)
{

    // njt_stream_upstream_dynamic_server_main_conf_t  *udsmcf;
    njt_stream_upstream_dynamic_server_conf_t *dynamic_server;
    njt_resolver_ctx_t *ctx;
    njt_stream_upstream_srv_conf_t *upstream_conf;
    // njt_stream_upstream_rr_peer_t                   *parent_peer;
    njt_stream_upstream_server_t *us;

    dynamic_server = ev->data;
    upstream_conf = dynamic_server->upstream_conf;
    if (upstream_conf->resolver == NULL)
    {
        njt_log_error(NJT_LOG_ALERT, ev->log, 0,
                      "upstream-dynamic-servers: resolver null for '%V'",
                      &dynamic_server->host);
        return;
    }

    us = dynamic_server->us;
    if (dynamic_server->parent_node == NULL)
    {
        dynamic_server->parent_node = njt_stream_upstream_copy_parent_peer(upstream_conf, us, 0);
        if (dynamic_server->parent_node == NULL)
        {
            njt_log_error(NJT_LOG_ALERT, ev->log, 0,
                          "allocate njt_stream_upstream_copy_parent_peer error for '%V'",
                          &dynamic_server->host);
            return;
        }
        dynamic_server->parent_node->id = us->parent_id;
        dynamic_server->parent_node->parent_id = us->parent_id;

        dynamic_server->parent_node->fail_timeout = us->fail_timeout;
        dynamic_server->parent_node->max_conns = us->max_conns;
        dynamic_server->parent_node->max_fails = us->max_fails;
        dynamic_server->parent_node->slow_start = us->slow_start;
        dynamic_server->parent_node->weight = us->weight;
        dynamic_server->parent_node->down = us->down;
        dynamic_server->parent_node->set_backup = us->backup;

        // dynamic_server->parent_node->set_down = us->down;
        dynamic_server->parent_node->hc_down = (upstream_conf->hc_type == 0 ? 0 : 2);
    }

    ctx = njt_resolve_start(upstream_conf->resolver, NULL);
    if (ctx == NULL)
    {
        njt_log_error(NJT_LOG_ALERT, ev->log, 0,
                      "upstream-dynamic-servers: resolver start error for '%V'",
                      &dynamic_server->host);
        return;
    }

    if (ctx == NJT_NO_RESOLVER)
    {
        njt_log_error(NJT_LOG_ALERT, ev->log, 0,
                      "upstream-dynamic-servers: no resolver defined to resolve '%V'",
                      &dynamic_server->host);
        return;
    }
    dynamic_server->ctx = ctx;
    ctx->name = dynamic_server->host;
    ctx->handler = njt_stream_upstream_dynamic_server_resolve_handler;
    ctx->data = dynamic_server;
    ctx->service = dynamic_server->us->service;
    ctx->timeout = upstream_conf->resolver_timeout;

    njt_log_debug(NJT_LOG_DEBUG_CORE, ev->log, 0,
                  "stream upstream-dynamic-servers: Resolving '%V'", &ctx->name);
    if (njt_resolve_name(ctx) != NJT_OK)
    {
        njt_log_error(NJT_LOG_ALERT, ev->log, 0,
                      "upstream-dynamic-servers: njt_resolve_name failed for '%V'", &ctx->name);
        dynamic_server->ctx = NULL;
        njt_add_timer(&dynamic_server->timer, 1000);
    }
}
static njt_stream_upstream_rr_peer_t *
njt_stream_upstream_zone_copy_parent_peer(njt_stream_upstream_rr_peers_t *peers,
                                          njt_stream_upstream_server_t *us, njt_int_t alloc_id)
{
    // njt_stream_upstream_rr_peer_t        *tail_peer;
    njt_slab_pool_t *pool;
    njt_stream_upstream_rr_peer_t *dst;

    pool = peers->shpool;
    if (pool == NULL)
    {
        return NULL;
    }

    njt_shmtx_lock(&pool->mutex);
    dst = njt_slab_calloc_locked(pool, sizeof(njt_stream_upstream_rr_peer_t));
    if (dst == NULL)
    {
        njt_shmtx_unlock(&pool->mutex);
        return NULL;
    }

    dst->server.len = us->name.len;
    dst->server.data = njt_slab_calloc_locked(pool, dst->server.len);
    if (dst->server.data == NULL)
    {
        goto failed;
    }
    njt_memcpy(dst->server.data, us->name.data, us->name.len);

    dst->service.len = us->service.len;
    dst->service.data = njt_slab_calloc_locked(pool, dst->service.len);
    if (dst->service.data == NULL)
    {
        goto failed;
    }
    njt_memcpy(dst->service.data, us->service.data, us->service.len);

    if (alloc_id == 1)
    {
        dst->id = peers->next_order++;
    }
    dst->next = NULL;
    if (peers->parent_node == NULL)
    {
        peers->parent_node = dst;
    }
    else
    {
        dst->next = peers->parent_node;
        peers->parent_node = dst;
    }
    njt_shmtx_unlock(&pool->mutex);
    return dst;

failed:
    njt_stream_upstream_del_round_robin_peer(pool, dst);
    njt_shmtx_unlock(&pool->mutex);

    return NULL;
}
static njt_stream_upstream_rr_peer_t *
njt_stream_upstream_copy_parent_peer(njt_stream_upstream_srv_conf_t *upstream_conf,
                                     njt_stream_upstream_server_t *us, njt_int_t alloc_id)
{
    njt_stream_upstream_rr_peers_t *peers;

    peers = upstream_conf->peer.data;
    return njt_stream_upstream_zone_copy_parent_peer(peers, us, alloc_id);
}

#define njt_stream_upstream_zone_addr_marked(addr) \
    ((uintptr_t)(addr)->sockaddr & 1)

#define njt_stream_upstream_zone_mark_addr(addr) \
    (addr)->sockaddr = (struct sockaddr *)((uintptr_t)(addr)->sockaddr | 1)

#define njt_stream_upstream_zone_unmark_addr(addr) \
    (addr)->sockaddr =                             \
        (struct sockaddr *)((uintptr_t)(addr)->sockaddr & ~((uintptr_t)1))

static void njt_stream_upstream_dynamic_server_resolve_handler(
    njt_resolver_ctx_t *ctx)
{
    njt_stream_upstream_dynamic_server_conf_t *dynamic_server;
    njt_stream_upstream_srv_conf_t *upstream;
    njt_uint_t i, naddrs;
    struct sockaddr *sockaddr;
    uint32_t refresh_in;
    time_t fail_timeout;
    njt_int_t weight, max_conns, max_fails, slow_start, down, hc_down;
    njt_str_t *server;
    in_port_t port;
    njt_stream_upstream_rr_peer_t *peer, *next, *prev, *tail_peer;
    njt_stream_upstream_rr_peers_t *peers, *peers_data;
    uint32_t crc32;
    njt_int_t rc = NJT_OK;
    njt_msec_t now_time;

    njt_resolver_addr_t *addr;
    u_short min_priority;
    njt_uint_t backup, addr_backup;
    njt_event_t *event;
    njt_resolver_srv_name_t *srv;

    backup = 0;
    min_priority = 65535;
    if (njt_quit || njt_exiting || njt_terminate)
    {
        njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0,
                      "upstream-dynamic-servers: worker is about to exit, do not set the timer again");
        return;
    }

    njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0,
                  "stream upstream-dynamic-servers: Finished resolving '%V'", &ctx->name);

    dynamic_server = ctx->data;
    event = &dynamic_server->timer;
    for (i = 0; i < ctx->nsrvs; i++)
    {
        srv = &ctx->srvs[i];

        if (srv->state)
        {
            njt_log_error(NJT_LOG_ERR, event->log, 0,
                          "%V could not be resolved (%i: %s) "
                          "while resolving service %V of %V",
                          &srv->name, srv->state,
                          njt_resolver_strerror(srv->state), &ctx->service,
                          &ctx->name);
        }
    }

    if (ctx->state)
    {
        if (ctx->service.len)
        {
            njt_log_error(NJT_LOG_ERR, event->log, 0,
                          "service %V of %V could not be resolved (%i: %s)",
                          &ctx->service, &ctx->name, ctx->state,
                          njt_resolver_strerror(ctx->state));
        }
        else
        {
            njt_log_error(NJT_LOG_ERR, event->log, 0,
                          "%V could not be resolved (%i: %s)",
                          &ctx->name, ctx->state,
                          njt_resolver_strerror(ctx->state));
        }

        if (ctx->state != NJT_RESOLVE_NXDOMAIN)
        {
            // 放在这里不对，因为还没有调用 njt_stream_upstream_rr_peers_wlock(peers);
            // njt_http_upstream_rr_peers_unlock(peers);

            njt_resolve_name_done(ctx);

            njt_add_timer(event, njt_max(dynamic_server->upstream_conf->resolver_timeout, 1000));
            return;
        }

        /* NJT_RESOLVE_NXDOMAIN */

        ctx->naddrs = 0;
    }

    naddrs = ctx->naddrs;
    if (naddrs == 0)
    {
        goto operation;
    }
    if (ctx->naddrs == 0 || ctx->addrs == NULL || ctx->state)
    {

        njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0,
                      "naddrs and dns state %d %d.", ctx->naddrs, ctx->state);
        /*reset the recorded data*/

        dynamic_server->count = 0;
        dynamic_server->crc32 = 0;
        if (dynamic_server->count != 0 || dynamic_server->crc32 != 0)
        {
            /*Try to delete all the peers of the resolver name*/
            goto operation;
        }

        goto end;
    }

    /* check if the result changed or not*/
    sockaddr = njt_calloc(ctx->naddrs * sizeof(struct sockaddr),
                          njt_cycle->log);
    if (sockaddr == NULL)
    {
        goto end;
    }

    for (i = 0; i < naddrs; i++)
    {

        switch (ctx->addrs[i].sockaddr->sa_family)
        {
        case AF_INET6:
            if (dynamic_server->us->service.len == 0)
            {
                ((struct sockaddr_in6 *)ctx->addrs[i].sockaddr)->sin6_port = htons((u_short)
                                                                                       dynamic_server->port);
            }
            break;

        default:
            if (dynamic_server->us->service.len == 0)
            {
                ((struct sockaddr_in *)ctx->addrs[i].sockaddr)->sin_port = htons((u_short)dynamic_server->port);
            }
        }

        njt_memcpy(&sockaddr[i], ctx->addrs[i].sockaddr, sizeof(struct sockaddr));
    }

    /*calculate the crc*/
    njt_sort((void *)sockaddr, ctx->naddrs, sizeof(struct sockaddr),
             njt_stream_resolve_cmp_nodes);
    njt_crc32_init(crc32);
    for (i = 0; i < naddrs; i++)
    {
        njt_crc32_update(&crc32, (u_char *)&sockaddr[i], sizeof(struct sockaddr));
    }
    njt_crc32_final(crc32);
    njt_free(sockaddr);

    /*further compare the value*/
    if (dynamic_server->count == naddrs && dynamic_server->crc32 == crc32)
    {
        // njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,
        //             "upstream-dynamic-servers: DNS result isn't changed '%V'", &ctx->name);
        goto end;
    }
    else
    {
        njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                      "stream upstream-dynamic-servers: DNS result is changed '%V' num=%d", &ctx->name, naddrs);
    }

    dynamic_server->count = naddrs;
    dynamic_server->crc32 = crc32;

    for (i = 0; i < ctx->naddrs; i++)
    {
        min_priority = njt_min(ctx->addrs[i].priority, min_priority);
    }
#if (NJT_DEBUG)
    {
        u_char text[NJT_SOCKADDR_STRLEN];
        size_t len;

        for (i = 0; i < ctx->naddrs; i++)
        {
            len = njt_sock_ntop(ctx->addrs[i].sockaddr, ctx->addrs[i].socklen,
                                text, NJT_SOCKADDR_STRLEN, 1);

            njt_log_debug7(NJT_LOG_DEBUG_HTTP, event->log, 0,
                           "name %V was resolved to %*s "
                           "s:\"%V\" n:\"%V\" w:%d %s",
                           &ctx->name, len, text, &ctx->service,
                           &ctx->addrs[i].name, ctx->addrs[i].weight,
                           ctx->addrs[i].priority != min_priority ? "backup" : "");
        }
    }
#endif
operation:

    upstream = dynamic_server->upstream_conf;
    peers = upstream->peer.data;

    /*resolve must coexist with share memory*/
    if (peers->shpool)
    {
        /*Try to copy the peers to the shared memory zone*/
        rc = NJT_OK;
        fail_timeout = dynamic_server->parent_node->fail_timeout;
        weight = dynamic_server->parent_node->weight;
        max_conns = dynamic_server->parent_node->max_conns;
        max_fails = dynamic_server->parent_node->max_fails;
        slow_start = dynamic_server->parent_node->slow_start;
        down = dynamic_server->parent_node->down;
        // name = ctx->name;

        port = dynamic_server->port;
        hc_down = dynamic_server->parent_node->hc_down;
        if (upstream->mandatory == 1)
        { // zyg use upstream  hc_type
            hc_down = 2;
        }

        peers_data = (dynamic_server->us->backup > 0 ? peers->next : peers);

        njt_stream_upstream_rr_peers_wlock(peers);
        for (peer = peers_data->peer, prev = NULL; peer; peer = next)
        {

            next = peer->next;
            rc = NJT_OK;

            if (peer->parent_id != (njt_int_t)dynamic_server->parent_node->id)
            {
                prev = peer;
                continue;
            }
            for (i = 0; i < naddrs; ++i)
            {
                addr = &ctx->addrs[i];

                addr_backup = (addr->priority != min_priority);
                if (addr_backup != backup)
                {
                    // continue;
                }

                if (njt_http_upstream_zone_addr_marked(addr))
                {
                    continue;
                }

                if (njt_cmp_sockaddr(peer->sockaddr, peer->socklen,
                                     addr->sockaddr, addr->socklen,
                                     1) != NJT_OK)
                {
                    continue;
                }

                if (dynamic_server->us->service.len)
                {
                    if (addr->name.len != peer->server.len || njt_strncmp(addr->name.data, peer->server.data,
                                                                          addr->name.len))
                    {
                        continue;
                    }
                }

                njt_stream_upstream_zone_mark_addr(addr);

                prev = peer;
                goto skip_del;
            }
            if (peer->down == 0 && peer->del_pending == 0 && peers_data->tries > 0)
            {
                peers_data->tries--;
            }
            peers_data->number--;
            peers_data->total_weight -= peer->weight;
            peers_data->single = (peers_data->number <= 1);
            peers_data->weighted = (peers_data->total_weight != peers_data->number);

            /*The IP is not exists, down or free this peer.*/
            if (peer->conns > 0)
            {
                peer->down = 1;
                peer->del_pending = 1;
            }
            else
            {
                if (prev == NULL)
                {
                    peers_data->peer = next;
                }
                else
                {
                    prev->next = next;
                }
                njt_shmtx_lock(&peers_data->shpool->mutex);
                njt_stream_upstream_del_round_robin_peer(peers_data->shpool, peer);
                njt_shmtx_unlock(&peers_data->shpool->mutex);
            }
        skip_del:
            continue;
        }
        if (rc != NJT_ERROR && dynamic_server->parent_node->parent_id != -1)
        {

            now_time = njt_time();

            for (i = 0; i < naddrs; ++i)
            {
                addr = &ctx->addrs[i];
                addr_backup = (addr->priority != min_priority);
                if (addr_backup != backup)
                {
                    // continue;
                }

                if (njt_stream_upstream_zone_addr_marked(addr))
                {
                    njt_stream_upstream_zone_unmark_addr(addr);
                    continue;
                }
                if (dynamic_server->us->service.len != 0)
                {
                    port = njt_inet_get_port(ctx->addrs[i].sockaddr);
                }

                server = dynamic_server->us->service.len ? &addr->name : &dynamic_server->parent_node->server;
                peer = njt_stream_upstream_zone_copy_peer(peers, NULL, server, port,
                                                          ctx->addrs[i].sockaddr, ctx->addrs[i].socklen);
                if (peer == NULL)
                {
                    continue;
                }
                peer->fail_timeout = fail_timeout;
                peer->max_conns = max_conns;
                peer->max_fails = max_fails;
                peer->slow_start = slow_start;
                // peer->dynamic = 1;
                peer->id = peers->next_order++;
                peer->weight = weight;
                peer->effective_weight = weight;
                peer->rr_effective_weight = weight * NJT_WEIGHT_POWER;
                peer->current_weight = 0;
                peer->rr_current_weight = 0;
                peer->down = down;
                // peer->set_down = down;
                peer->hc_down = hc_down;
                peer->hc_upstart = now_time;
                peer->next = NULL;

                peer->parent_id = dynamic_server->parent_node->id;
                peers_data->number++;
                if (peer->down == 0)
                {
                    peers_data->tries++;
                }
                peers_data->total_weight += weight;
                // peers_data->empty = (peers_data->number == 0);
                if (peers_data->peer == NULL)
                {
                    peers_data->peer = peer;
                }
                else
                {
                    for (tail_peer = peers_data->peer; tail_peer->next != NULL; tail_peer = tail_peer->next)
                        ;
                    tail_peer->next = peer;
                }
            }
        }
        peers_data->single = (peers_data->number <= 1);
        peers->single = (peers->number + (peers->next != NULL ? peers->next->number : 0) <= 1);
        peers->update_id++;
        njt_stream_upstream_rr_peers_unlock(peers);
    }

end:

    refresh_in = 1000;
    if (ctx->valid)
    {
        refresh_in = ctx->valid - njt_time();
        refresh_in *= 1000;
        refresh_in = refresh_in > 1000 ? refresh_in : 1000;
        if (dynamic_server->valid != 0)
        {
            refresh_in = dynamic_server->valid * 1000;
        }
    }
    else
    {
        if (dynamic_server->valid != 0)
        {
            refresh_in = dynamic_server->valid * 1000;
        }
    }
    if (rc != NJT_ERROR)
    {
        njt_add_timer(&dynamic_server->timer, refresh_in);
    }

    while (++i < ctx->naddrs)
    {
        njt_stream_upstream_zone_unmark_addr(&ctx->addrs[i]);
    }
    njt_resolve_name_done(ctx);
    dynamic_server->ctx = NULL;

    return;
}
static void njt_stream_upstream_modify_dynamic_server(njt_stream_upstream_srv_conf_t *upstream_conf,
                                                      njt_stream_upstream_rr_peer_t *peer, njt_int_t lock)
{
    njt_uint_t i;
    njt_stream_upstream_dynamic_server_conf_t *dynamic_server, *p;
    njt_stream_upstream_dynamic_server_main_conf_t *udsmcf;
    // njt_stream_upstream_rr_peers_t *peers;
    njt_list_part_t *part;
    njt_cycle_t *curr_njt_cycle;
    njt_str_t service;
    if (njet_master_cycle != NULL)
    {
        curr_njt_cycle = njet_master_cycle;
    }
    else
    {
        curr_njt_cycle = (njt_cycle_t *)njt_cycle;
    }

    udsmcf = njt_stream_cycle_get_module_main_conf(curr_njt_cycle,
                                                   njt_stream_upstream_dynamic_servers_module);
    // dynamic_server = udsmcf->dynamic_servers.elts;

    part = &udsmcf->dynamic_servers->part;
    dynamic_server = (njt_stream_upstream_dynamic_server_conf_t *)part->elts;

    for (i = 0;; i++)
    {
        if (i >= part->nelts)
        {
            if (part->next == NULL)
                break;
            part = part->next;
            dynamic_server = part->elts;
            i = 0;
        }
        p = &dynamic_server[i];
        if (p->upstream_conf == upstream_conf && peer->parent_id == (njt_int_t)p->parent_node->id)
        {

            if (peer->service.len == 0) // delete
            {
                if (p->us->service.len > 0)
                {
                    njt_pfree(p->upstream_conf->pool, p->us->service.data);
                    p->us->service.len = 0;
                    p->us->service.data = NULL;
                }
            }
            else
            {
                if (peer->service.len > p->us->service.len) // 释放旧值
                {
                    service.data = njt_pcalloc(p->upstream_conf->pool, peer->service.len);
                    if (service.data == NULL)
                    {
                        return;
                    }
                    service.len = peer->service.len;
                    njt_memcpy(service.data, peer->service.data, peer->service.len);
                    njt_pfree(p->upstream_conf->pool, p->us->service.data);
                }
                else
                {
                    service = p->us->service;
                    njt_memcpy(service.data, peer->service.data, peer->service.len);
                    service.len = peer->service.len;
                }
                p->us->service = service;
            }

            return;
        }
    }
}
static void njt_stream_upstream_free_dynamic_server(njt_stream_upstream_srv_conf_t *upstream_conf,
                                                    njt_str_t server, njt_int_t id, njt_int_t lock)
{

    njt_uint_t i;
    njt_stream_upstream_dynamic_server_conf_t *dynamic_server, *p;
    njt_stream_upstream_dynamic_server_main_conf_t *udsmcf;
    njt_list_part_t *part;
    njt_cycle_t *curr_njt_cycle;
    if (njet_master_cycle != NULL)
    {
        curr_njt_cycle = njet_master_cycle;
    }
    else
    {
        curr_njt_cycle = (njt_cycle_t *)njt_cycle;
    }

    udsmcf = njt_stream_cycle_get_module_main_conf(curr_njt_cycle,
                                                   njt_stream_upstream_dynamic_servers_module);

    part = &udsmcf->dynamic_servers->part;
    dynamic_server = (njt_stream_upstream_dynamic_server_conf_t *)part->elts;

    // dynamic_server = udsmcf->dynamic_servers.elts;

    for (i = 0;; i++)
    {
        if (i >= part->nelts)
        {
            if (part->next == NULL)
                break;
            part = part->next;
            dynamic_server = part->elts;
            i = 0;
        }
        p = &dynamic_server[i];
        if (p->upstream_conf == upstream_conf && id == (njt_int_t)p->parent_node->id)
        {
            if (p->timer.timer_set)
            {
                njt_del_timer(&p->timer);
            }
            if (p->ctx != NULL)
            {
                njt_resolve_name_done(p->ctx);
                p->ctx = NULL;
            }
            njt_stream_upstream_dynamic_server_delete_server(p, lock);
            if (p->us->name.len > 0)
            {
                njt_pfree(upstream_conf->pool, p->us->name.data);
                p->us->name.len = 0;
                p->us->name.data = 0;
            }

            if (dynamic_server[i].free_us == 1)
            {
                njt_pfree(upstream_conf->pool, p->us);
                p->us = NULL;
            }
            njt_memzero(p,sizeof(njt_stream_upstream_dynamic_server_conf_t));
            break;
        }
    }
}
static njt_stream_upstream_rr_peer_t *
njt_stream_upstream_zone_copy_peer(njt_stream_upstream_rr_peers_t *peers,
                                   njt_str_t *server,
                                   njt_str_t *host, in_port_t port, struct sockaddr *sockaddr, socklen_t socklen)
{
    // size_t                        plen;
    njt_slab_pool_t *pool;
    njt_stream_upstream_rr_peer_t *dst;

    pool = peers->shpool;
    if (pool == NULL)
    {
        return NULL;
    }

    njt_shmtx_lock(&pool->mutex);
    dst = njt_slab_calloc_locked(pool, sizeof(njt_stream_upstream_rr_peer_t));
    if (dst == NULL)
    {
        njt_shmtx_unlock(&pool->mutex);
        return NULL;
    }

    dst->socklen = socklen;
    dst->sockaddr = NULL;
    dst->name.data = NULL;
    dst->server.data = NULL;

    if (server == NULL)
    {
        dst->server.len = host->len;
    }
    else
    {
        dst->server.len = server->len;
    }

    dst->sockaddr = njt_slab_calloc_locked(pool, sizeof(njt_sockaddr_t));
    if (dst->sockaddr == NULL)
    {
        goto failed;
    }

    dst->name.data = njt_slab_calloc_locked(pool, NJT_SOCKADDR_STRLEN);
    if (dst->name.data == NULL)
    {
        goto failed;
    }

    njt_memcpy(dst->sockaddr, sockaddr, socklen);
    njt_inet_set_port(dst->sockaddr, port);

    // if (host->service.len == 0) {
    //     port = njt_inet_get_port(template->sockaddr);
    //     njt_inet_set_port(peer->sockaddr, port);
    // }
    dst->name.len = njt_sock_ntop(dst->sockaddr, socklen, dst->name.data,
                                  NJT_SOCKADDR_STRLEN, 1);
    dst->server.data = njt_slab_calloc_locked(pool, dst->server.len);
    if (dst->server.data == NULL)
    {
        goto failed;
    }
    if (server == NULL)
    {
        njt_memcpy(dst->server.data, host->data, host->len);
        // njt_sprintf(dst->server.data + host->len, ":%d", port);
    }
    else
    {
        njt_memcpy(dst->server.data, server->data, server->len);
    }
    njt_shmtx_unlock(&pool->mutex);
    return dst;

failed:
    njt_stream_upstream_del_round_robin_peer(pool, dst);
    njt_shmtx_unlock(&pool->mutex);

    return NULL;
}
static njt_stream_upstream_dynamic_server_conf_t *njt_stream_upstream_allocate_dynamic_server()
{
    njt_uint_t i;
    njt_stream_upstream_dynamic_server_conf_t *dynamic_server;
    njt_stream_upstream_dynamic_server_main_conf_t *udsmcf;
    njt_list_part_t *part;
    njt_cycle_t *curr_njt_cycle;
    if (njet_master_cycle != NULL)
    {
        curr_njt_cycle = njet_master_cycle;
    }
    else
    {
        curr_njt_cycle = (njt_cycle_t *)njt_cycle;
    }
    udsmcf = njt_stream_cycle_get_module_main_conf(curr_njt_cycle,
                                                   njt_stream_upstream_dynamic_servers_module);

    part = &udsmcf->dynamic_servers->part;
    dynamic_server = (njt_stream_upstream_dynamic_server_conf_t *)part->elts;

    for (i = 0;; i++)
    {
        if (i >= part->nelts)
        {
            if (part->next == NULL)
                break;
            part = part->next;
            dynamic_server = part->elts;
            i = 0;
        }
        if (dynamic_server[i].upstream_conf == NULL)
        {
            njt_memzero(&dynamic_server[i], sizeof(njt_stream_upstream_dynamic_server_conf_t));
            return &dynamic_server[i];
        }
    }

    dynamic_server = (njt_stream_upstream_dynamic_server_conf_t *)njt_list_push(udsmcf->dynamic_servers);
    if (dynamic_server != NULL)
    {
        njt_memzero(dynamic_server, sizeof(njt_stream_upstream_dynamic_server_conf_t));
    }

    return dynamic_server;
}
static njt_int_t
njt_stream_resolve_cmp_nodes(const void *one, const void *two)
{
    return njt_memcmp(one, two, sizeof(struct sockaddr));
}
static void njt_stream_upstream_dynamic_server_delete_server(
    njt_stream_upstream_dynamic_server_conf_t *dynamic_server, njt_int_t lock)
{
    njt_stream_upstream_srv_conf_t *upstream;
    njt_stream_upstream_rr_peer_t *peer, *next, *prev;
    njt_stream_upstream_rr_peers_t *peers;
    upstream = dynamic_server->upstream_conf;
    peers = upstream->peer.data;

    /*resolve must coexist with share memory*/
    if (peers->shpool)
    {
        if (lock)
        {
            njt_stream_upstream_rr_peers_wlock(peers);
        }
        for (peer = peers->peer, prev = NULL; peer; peer = next)
        {

            next = peer->next;
            if (peer->parent_id != (njt_int_t)dynamic_server->parent_node->id)
            {
                prev = peer;
                continue;
            }
            if (peer->down == 0 && peer->del_pending == 0 && peers->tries > 0)
            {
                peers->tries--;
            }
            peers->number--;
            peers->total_weight -= peer->weight;
            peers->single = (peers->number <= 1);
            peers->weighted = (peers->total_weight != peers->number);
            /*The IP is not exists, down or free this peer.*/
            if (peer->conns > 0)
            {
                peer->down = 1;
                peer->del_pending = 1;
                prev = peer;
                continue;
            }
            if (prev == NULL)
            {
                peers->peer = next;
            }
            else
            {
                prev->next = next;
            }
            njt_shmtx_lock(&peers->shpool->mutex);
            njt_stream_upstream_del_round_robin_peer(peers->shpool, peer);
            njt_shmtx_unlock(&peers->shpool->mutex);
        }
        peers->single = (peers->number + (peers->next != NULL ? peers->next->number : 0) <= 1);
        peers->update_id++;

        // remove parent_node
        njt_stream_upstream_remove_parent_node(upstream, dynamic_server);
        if (lock)
        {
            njt_stream_upstream_rr_peers_unlock(peers);
        }
    }
    return;
}

static void njt_stream_upstream_check_dynamic_server(njt_event_t *ev)
{
    njt_stream_upstream_dynamic_server_main_conf_t *udsmcf;
    njt_stream_upstream_srv_conf_t *upstream_conf;
    njt_stream_upstream_rr_peer_t *peer, *pre;
    njt_stream_upstream_rr_peers_t *peers;
    njt_stream_upstream_server_t *us;
    njt_url_t u;
    njt_uint_t i;
    njt_event_t *timer;
    njt_stream_upstream_rr_peer_t *parent_node;
    njt_stream_upstream_main_conf_t *umcf;
    njt_stream_upstream_srv_conf_t **uscfp;
    njt_stream_upstream_dynamic_server_conf_t *dynamic_server = NULL;
    njt_stream_upstream_srv_conf_t *uscf;
    njt_uint_t refresh_in;
    njt_cycle_t *curr_njt_cycle;
    if (njet_master_cycle != NULL)
    {
        curr_njt_cycle = njet_master_cycle;
    }
    else
    {
        curr_njt_cycle = (njt_cycle_t *)njt_cycle;
    }

    udsmcf = njt_stream_cycle_get_module_main_conf(curr_njt_cycle,
                                                   njt_stream_upstream_dynamic_servers_module);

    // upstream_conf = ev->data;
    // peers = upstream_conf->peer.data;
    if (udsmcf->peers != NULL)
    {
        peers = udsmcf->peers;
        pre = NULL;
        njt_stream_upstream_rr_peers_wlock(peers);
        for (peer = peers->peer; peer; peer = peer->next)
        {
            if (pre != NULL)
            {
                // njt_stream_upstream_free_peer_memory(peers->shpool,pre);
                njt_stream_upstream_del_round_robin_peer(peers->shpool, pre);
                pre = NULL;
            }
            upstream_conf = NULL;
            if (peer->name.len > 0)
            { // zone name !!!!!!!!!!
                umcf = njt_stream_cycle_get_module_main_conf(curr_njt_cycle, njt_stream_upstream_module);
                uscfp = umcf->upstreams.elts;
                for (i = 0; i < umcf->upstreams.nelts; i++)
                {
                    uscf = uscfp[i];
                    if (uscf->host.len == peer->name.len && njt_strncmp(uscf->host.data, peer->name.data, peer->name.len) == 0)
                    {
                        upstream_conf = uscf;
                        break;
                    }
                }
            }
            if (upstream_conf == NULL)
            {
                pre = peer;
                continue; //
            }
            njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0,
                          "get a domain message id=%d,parent_id=%d,name=%V,zone=%V!", peer->id, peer->parent_id, &peer->server, &peer->name);
            if (peer->parent_id == (njt_int_t)peer->id && peer->server.data == 0)
            { // patch
                njt_stream_upstream_modify_dynamic_server(upstream_conf, peer, 1);
                pre = peer;
                continue; //
            }
            else if (peer->parent_id != (njt_int_t)peer->id)
            { // delete
                njt_stream_upstream_free_dynamic_server(upstream_conf, peer->server, peer->id, 1);
                pre = peer;
                continue; //
            }
            else
            {
                dynamic_server = njt_stream_upstream_allocate_dynamic_server(); // njt_array_push(&udsmcf->dynamic_servers);
                if (dynamic_server == NULL)
                {
                    pre = peer;
                    continue;
                }

                us = njt_pcalloc(upstream_conf->pool, sizeof(njt_stream_upstream_server_t));
                njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0, "new us=%p,row=%d", us, __LINE__);
                if (us == NULL)
                {
                    pre = peer;
                    continue; //
                }
                us->name.data = njt_pcalloc(upstream_conf->pool, peer->server.len);
                us->name.len = peer->server.len;
                if (us->name.data == NULL)
                {
                    break;
                }
                njt_memcpy(us->name.data, peer->server.data, peer->server.len);
                if (peer->service.len > 0)
                {
                    us->service.data = njt_pcalloc(upstream_conf->pool, peer->service.len);
                    if (us->service.data == NULL)
                    {
                        pre = peer;
                        continue;
                    }
                    us->service.len = peer->service.len;
                    njt_memcpy(us->service.data, peer->service.data, peer->service.len);
                }

                njt_memzero(&u, sizeof(njt_url_t));
                u.url = us->name;
                u.default_port = 80;
                u.no_resolve = 1;
                u.naddrs = 0;
                u.addrs = NULL;
                njt_parse_url(upstream_conf->pool, &u);

                us->addrs = NULL; // u.addrs;
                us->naddrs = 0;   // u.naddrs;
                us->weight = peer->weight;
                us->max_fails = peer->max_fails;
                us->fail_timeout = peer->fail_timeout;
                us->max_conns = peer->max_conns;
                us->slow_start = peer->slow_start;
                us->backup = peer->set_backup;
                us->down = peer->down;

                parent_node = dynamic_server->parent_node;
                if (parent_node == NULL)
                { 
                    parent_node = njt_stream_upstream_copy_parent_peer(upstream_conf, us, 0);
                }
                else
                {
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                                  "stream upstream-dynamic-servers: parent_node is no null", __LINE__);
                    
                }
                if (parent_node == NULL)
                {
                    pre = peer;
                    continue;
                }
                parent_node->id = peer->parent_id;
                parent_node->parent_id = peer->parent_id;

                njt_memzero(dynamic_server, sizeof(njt_stream_upstream_dynamic_server_conf_t));
                dynamic_server->us = us;
                dynamic_server->free_us = 1;

                dynamic_server->upstream_conf = upstream_conf;
                dynamic_server->host = u.host;
                dynamic_server->port = (in_port_t)(u.no_port ? u.default_port : u.port);
                dynamic_server->parent_node = parent_node;

                dynamic_server->parent_node->fail_timeout = us->fail_timeout;
                dynamic_server->parent_node->max_conns = us->max_conns;
                dynamic_server->parent_node->max_fails = us->max_fails;
                dynamic_server->parent_node->slow_start = us->slow_start;
                dynamic_server->parent_node->weight = us->weight;
                dynamic_server->parent_node->down = us->down;
                // dynamic_server->parent_node->set_down = us->down;
                dynamic_server->parent_node->set_backup = us->backup;
                dynamic_server->parent_node->hc_down = peer->hc_down;

                timer = &dynamic_server->timer;
                if (timer->handler == NULL)
                {

                    timer->handler = njt_stream_upstream_dynamic_server_resolve;
                    timer->log = njt_cycle->log;
                    timer->data = dynamic_server;
                    timer->cancelable = 1;
                    refresh_in = njt_random() % 1000;
                    njt_stream_upstream_dynamic_server_resolve(timer);
                }
            }

            pre = peer;
        }
        if (pre != NULL)
        {
            // njt_stream_upstream_free_peer_memory(peers->shpool,pre);
            njt_stream_upstream_del_round_robin_peer(peers->shpool, pre);
        }
        peers->peer = NULL;
        peers->number = 0;
        njt_stream_upstream_rr_peers_unlock(peers);
    }
    refresh_in = njt_random() % 1000;
    njt_add_timer(&udsmcf->timer, refresh_in);
}

njt_int_t njt_http_upstream_add_name_resolve(njt_http_upstream_srv_conf_t *upstream)
{
    njt_uint_t i;
    njt_flag_t have, add; //
    njt_http_upstream_rr_peers_t *peers;
    njt_http_upstream_main_conf_t *umcf;
    njt_http_upstream_srv_conf_t **uscfp;
    njt_http_upstream_srv_conf_t *uscf;
    njt_list_part_t *part;
    njt_event_t *timer = NULL;
    njt_uint_t refresh_in;
    njt_http_upstream_server_t *server;
    njt_http_upstream_dynamic_server_main_conf_t *udsmcf;
    njt_url_t u;
    njt_http_upstream_dynamic_server_conf_t *dynamic_server = NULL;
    njt_http_upstream_server_t *us;
    njt_http_upstream_rr_peer_t *peer;
    njt_conf_ext_t *mcf;
    njt_cycle_t *njet_curr_cycle = (njt_cycle_t *)njt_cycle;
    if (njet_master_cycle != NULL)
    {
        njet_curr_cycle = njet_master_cycle;
    }

    if (njet_master_cycle != NULL)
    {
        mcf = (njt_conf_ext_t *)njt_get_conf(njet_master_cycle->conf_ctx, njt_conf_ext_module);
    }
    else
    {
        mcf = (njt_conf_ext_t *)njt_get_conf(njt_cycle->conf_ctx, njt_conf_ext_module);
    }
    if (njet_master_cycle == NULL && (mcf->enabled == 0 || mcf->enabled == NJT_CONF_UNSET))
    { // worker 不做
        njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0, "cache_upstream return row=%d", __LINE__);
        return NJT_OK;
    }
    if (njet_master_cycle == NULL)
    {
        if ((njt_process != NJT_PROCESS_WORKER && njt_process != NJT_PROCESS_SINGLE) || njt_worker != 0)
        {
            /*only works in the worker 0 prcess.*/
            njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0, "cache_upstream return row=%d", __LINE__);
            return NJT_OK;
        }
    }
    if (njet_master_cycle != NULL)
    {
        if (mcf != NULL && mcf->enabled == 1)
        {
            njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0, "cache_upstream return row=%d", __LINE__);
            return NJT_OK;
        }
    }

    njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0, "upstream add domain name start!");

    umcf = njt_http_cycle_get_module_main_conf(njet_curr_cycle, njt_http_upstream_module);
    udsmcf = njt_http_cycle_get_module_main_conf(njet_curr_cycle,
                                                 njt_http_upstream_dynamic_servers_module);

    have = 0;
    add = 0;
    if (umcf == NULL || udsmcf == NULL)
        return NJT_ERROR;

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++)
    {
        uscf = uscfp[i];
        if (uscf != upstream)
        {
            continue;
        }
        peers = uscf->peer.data;
        if (peers == NULL || peers->parent_node == NULL)
        {
            break;
        }

        njt_http_upstream_rr_peers_wlock(peers);
        for (peer = peers->parent_node; peer; peer = peer->next)
        {
            have = 1;
            if (peer->parent_id == -1)
                continue;

            dynamic_server = njt_list_push(udsmcf->dynamic_servers);
            njt_memzero(dynamic_server, sizeof(njt_http_upstream_dynamic_server_conf_t));

            njt_memzero(&u, sizeof(njt_url_t));

            us = njt_pcalloc(uscf->pool, sizeof(njt_http_upstream_server_t));
            njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0, "new us=%p,row=%d", us, __LINE__);
            if (us == NULL)
            {
                return NJT_ERROR;
            }

            if (peer->server.len != 0)
            {
                us->name.data = njt_pcalloc(uscf->pool, peer->server.len);
                if (us->name.data == NULL)
                {
                    return NJT_ERROR;
                }
            }
            us->name.len = peer->server.len;

            if (peer->route.len != 0)
            {
                us->route.data = njt_pcalloc(uscf->pool, peer->route.len);
                if (us->route.data == NULL)
                {
                    return NJT_ERROR;
                }
            }
            us->route.len = peer->route.len;

            if (peer->service.len != 0)
            {
                us->service.data = njt_pcalloc(uscf->pool, peer->service.len);
                if (us->service.data == NULL)
                {
                    return NJT_ERROR;
                }
            }
            us->service.len = peer->service.len;

            njt_memcpy(us->name.data, peer->server.data, peer->server.len);
            njt_memcpy(us->route.data, peer->route.data, peer->route.len);
            njt_memcpy(us->service.data, peer->service.data, peer->service.len);

            u.url = us->name;
            u.default_port = 80;
            u.no_resolve = 1;
            njt_parse_url(uscf->pool, &u);

            us->backup = peer->set_backup;
            us->down = peer->down;
            us->addrs = NULL;
            us->naddrs = 0;
            us->weight = peer->weight;
            us->max_conns = peer->max_conns;
            us->max_fails = peer->max_fails;
            us->fail_timeout = peer->fail_timeout;
            us->slow_start = peer->slow_start;
            us->parent_id = peer->id;
            dynamic_server->us = us;
            dynamic_server->free_us = 1;
            dynamic_server->upstream_conf = uscf;

            dynamic_server->parent_node = peer;

            dynamic_server->host = u.host;
            dynamic_server->port = (in_port_t)(u.no_port ? u.default_port : u.port);
            add = 1;
        }
        njt_http_upstream_rr_peers_unlock(peers);
    }
    if (have == 0)
    {
        server = upstream->servers->elts;
        peers = upstream->peer.data;
        for (i = 0; i < upstream->servers->nelts; i++)
        {
            if (server[i].dynamic == 1)
            {

                njt_memzero(&u, sizeof(njt_url_t));
                us = njt_pcalloc(upstream->pool, sizeof(njt_http_upstream_server_t));
                njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0, "new us=%p,row=%d", us, __LINE__);
                if (us == NULL)
                {
                    return NJT_ERROR;
                }

                us->name.data = njt_pcalloc(upstream->pool, server[i].name.len);
                if (us->name.data == NULL)
                {
                    return NJT_ERROR;
                }
                us->parent_id = server[i].parent_id; //(njt_int_t)peers->next_order++;
                us->name.len = server[i].name.len;
                if (server[i].route.len > 0)
                {
                    us->route.data = njt_pcalloc(upstream->pool, server[i].route.len);
                    if (us->route.data == NULL)
                    {
                        return NJT_ERROR;
                    }
                }
                us->route.len = server[i].route.len;

                if (server[i].service.len > 0)
                {
                    us->service.data = njt_pcalloc(upstream->pool, server[i].service.len);
                    if (us->service.data == NULL)
                    {
                        return NJT_ERROR;
                    }
                }
                us->service.len = server[i].service.len;

                njt_memcpy(us->name.data, server[i].name.data, server[i].name.len);
                njt_memcpy(us->route.data, server[i].route.data, server[i].route.len);
                njt_memcpy(us->service.data, server[i].service.data, server[i].service.len);

                u.url = us->name;
                u.default_port = 80;
                u.no_resolve = 1;
                njt_parse_url(upstream->pool, &u);

                us->backup = server[i].backup;
                us->down = server[i].down;
                us->addrs = NULL;
                us->naddrs = 0;
                us->weight = server[i].weight;
                us->max_conns = server[i].max_conns;
                us->max_fails = server[i].max_fails;
                us->fail_timeout = server[i].fail_timeout;
                us->slow_start = server[i].slow_start;

                dynamic_server = njt_list_push(udsmcf->dynamic_servers);
                njt_memzero(dynamic_server, sizeof(njt_http_upstream_dynamic_server_conf_t));

                dynamic_server->us = us;
                dynamic_server->free_us = 1;
                dynamic_server->upstream_conf = upstream;
                dynamic_server->host = u.host;
                dynamic_server->port = (in_port_t)(u.no_port ? u.default_port : u.port);
                add = 1;
            }
        }
    }
    if (add == 1)
    {
        part = &udsmcf->dynamic_servers->part;
        dynamic_server = (njt_http_upstream_dynamic_server_conf_t *)part->elts;

        for (i = 0;; i++)
        {
            if (i >= part->nelts)
            {
                if (part->next == NULL)
                    break;
                part = part->next;
                dynamic_server = part->elts;
                i = 0;
            }
            if (dynamic_server[i].upstream_conf != upstream)
            {
                continue;
            }
            // dynamic_server[i].parent_id = -1;
            if (njet_master_cycle != NULL && dynamic_server[i].upstream_conf->resolver->log != njt_cycle->log)
            {
                dynamic_server[i].upstream_conf->resolver->log = njt_cycle->log;
            }
            dynamic_server[i].valid = dynamic_server[i].upstream_conf->valid;
            timer = &dynamic_server[i].timer;
            timer->handler = njt_http_upstream_dynamic_server_resolve;
            timer->log = njt_cycle->log;
            timer->data = &dynamic_server[i];
            timer->cancelable = 1;
            refresh_in = njt_random() % 1000;

            njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0,
                          "http cache_upstream: Initial DNS refresh of '%V' in %ims[%d]",
                          &dynamic_server[i].host, refresh_in, dynamic_server[i].valid);
            njt_add_timer(timer, refresh_in);
        }
    }

    return NJT_OK;
}

static void
njt_http_upstream_remove_parent_node(njt_http_upstream_srv_conf_t *upstream,njt_http_upstream_dynamic_server_conf_t *dynamic_server
                                     )
{
    njt_http_upstream_rr_peer_t *peer, *next, *prev;
    njt_http_upstream_rr_peers_t *peers;
    njt_http_upstream_rr_peer_t *delpeer = dynamic_server->parent_node;
    peers = upstream->peer.data;
    for (peer = peers->parent_node, prev = NULL; peer; peer = next)
    {

        next = peer->next;

        if (peer->id != delpeer->id || peer->parent_id != (njt_int_t)delpeer->parent_id)
        {
            prev = peer;
            continue;
        }
        if (prev == NULL)
        {
            peers->parent_node = next;
        }
        else
        {
            prev->next = next;
        }
    }
    peer = delpeer;
    if (peer->server.data)
    {
        njt_slab_free_locked(peers->shpool, peer->server.data);
    }

    if (peer->name.data)
    {
        njt_slab_free_locked(peers->shpool, peer->name.data);
    }

    if (peer->sockaddr)
    {
        njt_slab_free_locked(peers->shpool, peer->sockaddr);
    }
    if (peer->route.data)
    {
        njt_slab_free_locked(peers->shpool, peer->route.data);
    }
    if (peer->service.data)
    {
        njt_slab_free_locked(peers->shpool, peer->service.data);
    }
    njt_slab_free_locked(peers->shpool, peer);
    dynamic_server->parent_node = NULL;
    //njt_memzero(peer, sizeof(njt_http_upstream_rr_peer_t));
    return;
}

static void
njt_stream_upstream_remove_parent_node(njt_stream_upstream_srv_conf_t *upstream,njt_stream_upstream_dynamic_server_conf_t *dynamic_server
                                       )
{
    njt_stream_upstream_rr_peer_t *peer, *next, *prev;
    njt_stream_upstream_rr_peers_t *peers;
    njt_stream_upstream_rr_peer_t *delpeer = dynamic_server->parent_node;
    peers = upstream->peer.data;
    for (peer = peers->parent_node, prev = NULL; peer; peer = next)
    {

        next = peer->next;

        if (peer->id != delpeer->id || peer->parent_id != (njt_int_t)delpeer->parent_id)
        {
            prev = peer;
            continue;
        }
        if (prev == NULL)
        {
            peers->parent_node = next;
        }
        else
        {
            prev->next = next;
        }
    }
    peer = delpeer;
    if (peer->server.data)
    {
        njt_slab_free_locked(peers->shpool, peer->server.data);
    }

    if (peer->name.data)
    {
        njt_slab_free_locked(peers->shpool, peer->name.data);
    }

    if (peer->sockaddr)
    {
        njt_slab_free_locked(peers->shpool, peer->sockaddr);
    }
    if (peer->service.data)
    {
        njt_slab_free_locked(peers->shpool, peer->service.data);
    }
    //njt_memzero(peer, sizeof(njt_stream_upstream_rr_peer_t));
    njt_slab_free_locked(peers->shpool,peer);
    dynamic_server->parent_node = NULL;

    return;
}

njt_int_t njt_stream_upstream_add_name_resolve(njt_stream_upstream_srv_conf_t *upstream)
{
    njt_uint_t i;
    njt_flag_t have, add; //
    njt_stream_upstream_rr_peers_t *peers;
    njt_stream_upstream_main_conf_t *umcf;
    njt_stream_upstream_srv_conf_t **uscfp;
    njt_stream_upstream_srv_conf_t *uscf;
    njt_list_part_t *part;
    njt_event_t *timer = NULL;
    njt_uint_t refresh_in;
    njt_stream_upstream_server_t *server;
    njt_stream_upstream_dynamic_server_main_conf_t *udsmcf;
    njt_url_t u;
    njt_stream_upstream_dynamic_server_conf_t *dynamic_server = NULL;
    njt_stream_upstream_server_t *us;
    njt_stream_upstream_rr_peer_t *peer;
    njt_conf_ext_t *mcf;
    njt_cycle_t *njet_curr_cycle = (njt_cycle_t *)njt_cycle;
    if (njet_master_cycle != NULL)
    {
        njet_curr_cycle = njet_master_cycle;
    }

    if (njet_master_cycle != NULL)
    {
        mcf = (njt_conf_ext_t *)njt_get_conf(njet_master_cycle->conf_ctx, njt_conf_ext_module);
    }
    else
    {
        mcf = (njt_conf_ext_t *)njt_get_conf(njt_cycle->conf_ctx, njt_conf_ext_module);
    }
    if (njet_master_cycle == NULL && (mcf->enabled == 0 || mcf->enabled == NJT_CONF_UNSET))
    { // worker 不做
        njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0, "stream cache_upstream return row=%d", __LINE__);
        return NJT_OK;
    }
    if (njet_master_cycle == NULL)
    {
        if ((njt_process != NJT_PROCESS_WORKER && njt_process != NJT_PROCESS_SINGLE) || njt_worker != 0)
        {
            /*only works in the worker 0 prcess.*/
            njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0, "stream cache_upstream return row=%d", __LINE__);
            return NJT_OK;
        }
    }
    if (njet_master_cycle != NULL)
    {
        if (mcf != NULL && mcf->enabled == 1)
        {
            njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0, "stream cache_upstream return row=%d", __LINE__);
            return NJT_OK;
        }
    }

    njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0, "stream upstream add domain name start!");

    umcf = njt_stream_cycle_get_module_main_conf(njet_curr_cycle, njt_stream_upstream_module);
    udsmcf = njt_stream_cycle_get_module_main_conf(njet_curr_cycle,
                                                 njt_stream_upstream_dynamic_servers_module);

    have = 0;
    add = 0;
    if (umcf == NULL || udsmcf == NULL)
        return NJT_ERROR;

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++)
    {
        uscf = uscfp[i];
        if (uscf != upstream)
        {
            continue;
        }
        peers = uscf->peer.data;
        if (peers == NULL || peers->parent_node == NULL)
        {
            break;
        }

        njt_stream_upstream_rr_peers_wlock(peers);
        for (peer = peers->parent_node; peer; peer = peer->next)
        {
            have = 1;
            if (peer->parent_id == -1)
                continue;

            dynamic_server = njt_list_push(udsmcf->dynamic_servers);
            njt_memzero(dynamic_server, sizeof(njt_stream_upstream_dynamic_server_conf_t));

            njt_memzero(&u, sizeof(njt_url_t));

            us = njt_pcalloc(uscf->pool, sizeof(njt_stream_upstream_server_t));
            njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0, "new us=%p,row=%d", us, __LINE__);
            if (us == NULL)
            {
                return NJT_ERROR;
            }

            if (peer->server.len != 0)
            {
                us->name.data = njt_pcalloc(uscf->pool, peer->server.len);
                if (us->name.data == NULL)
                {
                    return NJT_ERROR;
                }
            }
            us->name.len = peer->server.len;

            if (peer->service.len != 0)
            {
                us->service.data = njt_pcalloc(uscf->pool, peer->service.len);
                if (us->service.data == NULL)
                {
                    return NJT_ERROR;
                }
            }
            us->service.len = peer->service.len;

            njt_memcpy(us->name.data, peer->server.data, peer->server.len);
            njt_memcpy(us->service.data, peer->service.data, peer->service.len);

            u.url = us->name;
            u.default_port = 80;
            u.no_resolve = 1;
            njt_parse_url(uscf->pool, &u);

            us->backup = peer->set_backup;
            us->down = peer->down;
            us->addrs = NULL;
            us->naddrs = 0;
            us->weight = peer->weight;
            us->max_conns = peer->max_conns;
            us->max_fails = peer->max_fails;
            us->fail_timeout = peer->fail_timeout;
            us->slow_start = peer->slow_start;
            us->parent_id = peer->id;
            dynamic_server->us = us;
            dynamic_server->free_us = 1;
            dynamic_server->upstream_conf = uscf;

            dynamic_server->parent_node = peer;

            dynamic_server->host = u.host;
            dynamic_server->port = (in_port_t)(u.no_port ? u.default_port : u.port);
            add = 1;
        }
        njt_stream_upstream_rr_peers_unlock(peers);
    }
    if (have == 0)
    {
        server = upstream->servers->elts;
        peers = upstream->peer.data;
        for (i = 0; i < upstream->servers->nelts; i++)
        {
            if (server[i].dynamic == 1)
            {

                njt_memzero(&u, sizeof(njt_url_t));
                us = njt_pcalloc(upstream->pool, sizeof(njt_stream_upstream_server_t));
                njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0, "new us=%p,row=%d", us, __LINE__);
                if (us == NULL)
                {
                    return NJT_ERROR;
                }

                us->name.data = njt_pcalloc(upstream->pool, server[i].name.len);
                if (us->name.data == NULL)
                {
                    return NJT_ERROR;
                }
                us->parent_id = server[i].parent_id; //(njt_int_t)peers->next_order++;
                us->name.len = server[i].name.len;

                if (server[i].service.len > 0)
                {
                    us->service.data = njt_pcalloc(upstream->pool, server[i].service.len);
                    if (us->service.data == NULL)
                    {
                        return NJT_ERROR;
                    }
                }
                us->service.len = server[i].service.len;

                njt_memcpy(us->name.data, server[i].name.data, server[i].name.len);
                njt_memcpy(us->service.data, server[i].service.data, server[i].service.len);

                u.url = us->name;
                u.default_port = 80;
                u.no_resolve = 1;
                njt_parse_url(upstream->pool, &u);

                us->backup = server[i].backup;
                us->down = server[i].down;
                us->addrs = NULL;
                us->naddrs = 0;
                us->weight = server[i].weight;
                us->max_conns = server[i].max_conns;
                us->max_fails = server[i].max_fails;
                us->fail_timeout = server[i].fail_timeout;
                us->slow_start = server[i].slow_start;

                dynamic_server = njt_list_push(udsmcf->dynamic_servers);
                njt_memzero(dynamic_server, sizeof(njt_stream_upstream_dynamic_server_conf_t));

                dynamic_server->us = us;
                dynamic_server->free_us = 1;
                dynamic_server->upstream_conf = upstream;
                dynamic_server->host = u.host;
                dynamic_server->port = (in_port_t)(u.no_port ? u.default_port : u.port);
                add = 1;
            }
        }
    }
    if (add == 1)
    {
        part = &udsmcf->dynamic_servers->part;
        dynamic_server = (njt_stream_upstream_dynamic_server_conf_t *)part->elts;

        for (i = 0;; i++)
        {
            if (i >= part->nelts)
            {
                if (part->next == NULL)
                    break;
                part = part->next;
                dynamic_server = part->elts;
                i = 0;
            }
            if (dynamic_server[i].upstream_conf != upstream)
            {
                continue;
            }
            // dynamic_server[i].parent_id = -1;
            if (njet_master_cycle != NULL && dynamic_server[i].upstream_conf->resolver->log != njt_cycle->log)
            {
                dynamic_server[i].upstream_conf->resolver->log = njt_cycle->log;
            }
            dynamic_server[i].valid = dynamic_server[i].upstream_conf->valid;
            timer = &dynamic_server[i].timer;
            timer->handler = njt_stream_upstream_dynamic_server_resolve;
            timer->log = njt_cycle->log;
            timer->data = &dynamic_server[i];
            timer->cancelable = 1;
            refresh_in = njt_random() % 1000;

            njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0,
                          "stream cache_upstream: Initial DNS refresh of '%V' in %ims[%d]",
                          &dynamic_server[i].host, refresh_in, dynamic_server[i].valid);
            njt_add_timer(timer, refresh_in);
        }
    }

    return NJT_OK;
}

#if (NJT_STREAM_ADD_DYNAMIC_UPSTREAM)
static void njt_stream_upstream_dynamic_server_delete_upstream(void *data)
{
    njt_stream_upstream_dynamic_server_main_conf_t *udsmcf;
    njt_list_part_t *part;
    njt_uint_t i;
    njt_cycle_t *curr_njt_cycle;
    njt_stream_upstream_dynamic_server_conf_t *dynamic_server;
    njt_stream_upstream_srv_conf_t *upstream = data;

    if (njet_master_cycle != NULL)
    {
        curr_njt_cycle = njet_master_cycle;
    }
    else
    {
        curr_njt_cycle = (njt_cycle_t *)njt_cycle;
    }

    udsmcf = njt_stream_cycle_get_module_main_conf(curr_njt_cycle,
                                                 njt_stream_upstream_dynamic_servers_module);

    if (udsmcf == NULL)
        return;
    part = &udsmcf->dynamic_servers->part;
    dynamic_server = (njt_stream_upstream_dynamic_server_conf_t *)part->elts;

    for (i = 0;; i++)
    {
        if (i >= part->nelts)
        {
            if (part->next == NULL)
                break;
            part = part->next;
            dynamic_server = part->elts;
            i = 0;
        }
        if (upstream == dynamic_server[i].upstream_conf)
        {
            if (dynamic_server[i].timer.timer_set)
            {
                njt_del_timer(&dynamic_server[i].timer);

                njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0,
                              "del name_resolver=%V", &dynamic_server[i].host);
            }
            //dynamic_server[i].upstream_conf = NULL;
            //dynamic_server[i].parent_node = NULL;
            //dynamic_server[i].crc32 = 0;
            if (dynamic_server[i].ctx != NULL)
            {
                njt_resolve_name_done(dynamic_server[i].ctx);
                dynamic_server[i].ctx = NULL;
            }
            njt_memzero(&dynamic_server[i],sizeof(njt_stream_upstream_dynamic_server_conf_t));
        }
    }
    return;
}
#endif