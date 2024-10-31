/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>
#include <sys/socket.h>
#include "njt_sha1.h"
#include "njt_stream_proto_server_module.h"
#include <njt_stream_proxy_module.h>
#include <njt_http_sendmsg_module.h>
#include <njt_http_kv_module.h>
#include <njet_iot_emb.h>
#include <njt_hash_util.h>
#include <njt_mqconf_module.h>
#include <ucontext.h>
#if (NJT_STREAM_PROTOCOL_V2)
#include <njt_stream_proxy_protocol_tlv_module.h>
#endif
#if (NJT_STREAM_FTP_PROXY)
#include <njt_stream_ftp_proxy_module.h>
#endif

#define SESSION_LEN_BYTE 2
#define MSG_TYPE_BROADCAST 0
#define MSG_TYPE_OTHER 1
#define MSG_TYPE_1V1 2

#define MTASK_DEFAULT_STACK_SIZE 65536
#define MTASK_DEFAULT_TIMEOUT 10000
#define MTASK_WAKE_TIMEDOUT 0x01
#define MTASK_WAKE_NOFINALIZE 0x02

static njt_stream_session_t *mtask_req;

#define mtask_current (mtask_req)

#define mtask_setcurrent(s) (mtask_req = (s))

#define mtask_resetcurrent() mtask_setcurrent(NULL)

#define mtask_have_scheduled (mtask_current != NULL)

extern njt_module_t njt_mqconf_module;
extern njt_int_t njt_stream_proxy_process(njt_stream_session_t *s, njt_uint_t from_upstream,
                                          njt_uint_t do_write, njt_uint_t internal);
static char *njt_stream_proto_server_set(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static njt_int_t njt_stream_proto_server_init(njt_conf_t *cf);
static void *njt_stream_proto_server_create_srv_conf(njt_conf_t *cf);
static char *njt_stream_proto_server_merge_srv_conf(njt_conf_t *cf, void *parent, void *child);
static void njt_stream_proto_server_handler(njt_stream_session_t *s);
static void
njt_stream_proto_server_write_handler(njt_event_t *ev);
static void
njt_stream_proto_server_read_handler(njt_event_t *ev);
static njt_int_t njt_stream_proto_server_process(njt_cycle_t *cycle);
static void *njt_stream_proto_server_create_main_conf(njt_conf_t *cf);
static njt_int_t njt_stream_proto_server_del_session(njt_stream_session_t *s, njt_uint_t code, njt_uint_t close_session);
static void njt_stream_proto_server_update_in_buf(tcc_buf_t *b, size_t used_len);
static int proto_server_proxy_send(tcc_stream_request_t *r, njt_uint_t from_upstream, char *data, size_t len);
static char *njt_stream_proto_upstream_set(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static char *
njt_stream_proto_pass(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static void njt_stream_proto_handler(njt_stream_session_t *s);
static void
njt_stream_proto_resolve_handler(njt_resolver_ctx_t *ctx);
static void
njt_stream_proto_downstream_handler(njt_event_t *ev);
static void
njt_stream_proto_process_connection(njt_event_t *ev, njt_uint_t from_upstream);
static void
njt_stream_proto_connect(njt_stream_session_t *s);
static void
njt_stream_proto_connect_handler(njt_event_t *ev);
static void
njt_stream_proto_init_upstream(njt_stream_session_t *s);
static void
njt_stream_proto_ssl_init_connection(njt_stream_session_t *s);
static u_char *
njt_stream_proto_log_error(njt_log_t *log, u_char *buf, size_t len);
static njt_int_t
njt_stream_proto_set_local(njt_stream_session_t *s, njt_stream_upstream_t *u,
                           njt_stream_upstream_local_t *local);
static njt_int_t
njt_stream_proto_eval(njt_stream_session_t *s,
                      njt_stream_proxy_srv_conf_t *pscf);
static njt_int_t njt_stream_proto_process(njt_stream_session_t *s, njt_uint_t from_upstream,
                                          njt_uint_t do_write, njt_uint_t internal);
static njt_int_t
njt_stream_proto_test_finalize(njt_stream_session_t *s,
                               njt_uint_t from_upstream);
static void
njt_stream_proto_next_upstream(njt_stream_session_t *s);
static njt_int_t
njt_stream_proto_test_connect(njt_connection_t *c);
static njt_int_t
njt_stream_proto_send_proxy_protocol(njt_stream_session_t *s);
static njt_int_t
njt_proto_write_filter(njt_stream_session_t *s, njt_chain_t *in, njt_uint_t from_upstream);

extern u_char *
njt_proxy_protocol_v2_write(njt_stream_session_t *s, u_char *buf, u_char *last);

static void
njt_stream_proto_upstream_handler(njt_event_t *ev);

static njt_int_t
njt_stream_proto_ssl_name(njt_stream_session_t *s);

static njt_int_t
njt_stream_proto_ssl_certificates(njt_stream_session_t *s);

static void
njt_stream_proto_ssl_save_session(njt_connection_t *c);

static void
njt_stream_proto_ssl_handshake(njt_connection_t *pc);
static void *
njt_prealloc(njt_pool_t *pool, void *p, size_t size);
static void *
njt_realloc(void *ptr, size_t size, njt_log_t *log);
static void
njt_stream_proto_finalize(njt_stream_session_t *s, njt_uint_t rc);

static void mtask_event_handler(njt_event_t *ev);
static int eval_script(tcc_stream_request_t *r, njt_proto_process_msg_handler_pt handler);
static void *njt_stream_get_ctx_by_zone(njt_cycle_t *cycle, njt_str_t *zone_name);
tcc_str_t *cli_get_session(tcc_stream_request_t *r);
tcc_stream_request_t *cli_local_find_by_session(tcc_stream_server_ctx *srv_ctx, tcc_str_t *session);
static void njt_stream_proto_add_client_hash(tcc_stream_server_ctx *srv_ctx,tcc_stream_request_t *r);
static int proto_server_send_local(tcc_stream_server_ctx *srv_ctx, char *data, size_t len);
static int proto_server_send_local_others(tcc_stream_request_t *sender, char *data, size_t len);
static int proto_server_send_other_worker(tcc_str_t *sender_session, tcc_stream_server_ctx *srv_ctx, char *data, size_t len);
static int topic_will_change_handler(njt_str_t *key, njt_str_t *value, void *data);
static char *njt_conf_set_session_zone(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static njt_int_t njt_stream_proto_server_init_module(njt_cycle_t *cycle);
static void njt_stream_proto_remove_session(tcc_stream_server_ctx *srv_ctx, tcc_str_t *session);
static int proto_server_send_mqtt(njt_int_t type, tcc_stream_server_ctx *srv_ctx, tcc_str_t *session, njt_str_t *prefix, njt_str_t *service, njt_str_t *reg_key, njt_str_t *data);
static njt_stream_proto_session_node_t *njt_stream_proto_find_session(tcc_stream_server_ctx *srv_ctx, tcc_str_t *session);
static void njt_stream_proto_remove_session_by_pid(tcc_stream_server_ctx *srv_ctx, njt_pid_t pid);
static void njt_stream_proto_remove_client_hash(tcc_stream_server_ctx *srv_ctx,tcc_str_t *session);
static njt_str_t *proto_server_get_service_name(tcc_stream_server_ctx *srv_ctx);
/**
 * This module provide callback to istio for http traffic
 *
 */
static njt_command_t njt_stream_proto_server_commands[] = {
    {njt_string("proto_server"),
     NJT_STREAM_SRV_CONF | NJT_CONF_FLAG,
     njt_stream_proto_server_set,
     NJT_STREAM_SRV_CONF_OFFSET,
     0,
     NULL},
    {njt_string("proto_buffer_size"),
     NJT_STREAM_MAIN_CONF | NJT_STREAM_SRV_CONF | NJT_CONF_TAKE1,
     njt_conf_set_size_slot,
     NJT_STREAM_SRV_CONF_OFFSET,
     offsetof(njt_stream_proto_server_srv_conf_t, buffer_size),
     NULL},
    {njt_string("proto_session_max_mem_size"),
     NJT_STREAM_MAIN_CONF | NJT_STREAM_SRV_CONF | NJT_CONF_TAKE1,
     njt_conf_set_size_slot,
     NJT_STREAM_SRV_CONF_OFFSET,
     offsetof(njt_stream_proto_server_srv_conf_t, session_max_mem_size),
     NULL},
    {njt_string("proto_server_code_file"),
     NJT_STREAM_MAIN_CONF | NJT_STREAM_SRV_CONF | NJT_CONF_TAKE1,
     njt_conf_set_str_array_slot, // do custom config
     NJT_STREAM_SRV_CONF_OFFSET,
     offsetof(njt_stream_proto_server_srv_conf_t, tcc_files),
     NULL},
    {njt_string("proto_server_idle_timeout"),
     NJT_STREAM_MAIN_CONF | NJT_STREAM_SRV_CONF | NJT_CONF_TAKE1,
     njt_conf_set_msec_slot,
     NJT_STREAM_SRV_CONF_OFFSET,
     offsetof(njt_stream_proto_server_srv_conf_t, connect_timeout),
     NULL},
    {njt_string("proto_server_client_update_interval"),
     NJT_STREAM_MAIN_CONF | NJT_STREAM_SRV_CONF | NJT_CONF_TAKE1,
     njt_conf_set_msec_slot,
     NJT_STREAM_SRV_CONF_OFFSET,
     offsetof(njt_stream_proto_server_srv_conf_t, client_update_interval),
     NULL},
    {njt_string("proto_server_update_interval"),
     NJT_STREAM_MAIN_CONF | NJT_STREAM_SRV_CONF | NJT_CONF_TAKE1,
     njt_conf_set_msec_slot,
     NJT_STREAM_SRV_CONF_OFFSET,
     offsetof(njt_stream_proto_server_srv_conf_t, server_update_interval),
     NULL},
    {njt_string("proto_upstream"),
     NJT_STREAM_UPS_CONF | NJT_CONF_FLAG,
     njt_stream_proto_upstream_set,
     NJT_STREAM_SRV_CONF_OFFSET,
     0,
     NULL},
    {njt_string("proto_pass"),
     NJT_STREAM_SRV_CONF | NJT_CONF_TAKE1,
     njt_stream_proto_pass,
     NJT_STREAM_SRV_CONF_OFFSET,
     0,
     NULL},
    {njt_string("proto_mtask_stack"),
     NJT_STREAM_MAIN_CONF | NJT_STREAM_SRV_CONF | NJT_CONF_TAKE1,
     njt_conf_set_size_slot,
     NJT_STREAM_SRV_CONF_OFFSET,
     offsetof(njt_stream_proto_server_srv_conf_t, stack_size),
     NULL},

    {njt_string("proto_mtask_timeout"),
     NJT_STREAM_MAIN_CONF | NJT_STREAM_SRV_CONF | NJT_CONF_TAKE1,
     njt_conf_set_msec_slot,
     NJT_STREAM_SRV_CONF_OFFSET,
     offsetof(njt_stream_proto_server_srv_conf_t, mtask_timeout),
     NULL},
    {njt_string("proto_session_len"),
     NJT_STREAM_MAIN_CONF | NJT_STREAM_SRV_CONF | NJT_CONF_TAKE1,
     njt_conf_set_msec_slot,
     NJT_STREAM_SRV_CONF_OFFSET,
     offsetof(njt_stream_proto_server_srv_conf_t, session_size),
     NULL},
    {njt_string("proto_session_zone"),
     NJT_STREAM_MAIN_CONF | NJT_STREAM_SRV_CONF | NJT_CONF_TAKE2,
     njt_conf_set_session_zone,
     NJT_STREAM_SRV_CONF_OFFSET,
     0,
     NULL},
    njt_null_command /* command termination */
};

/* The module context. */
static njt_stream_module_t njt_stream_proto_server_module_ctx = {
    NULL,                         /* preconfiguration */
    njt_stream_proto_server_init, /* postconfiguration */
    &njt_stream_proto_server_create_main_conf,
    NULL,                                    /* init main configuration */
    njt_stream_proto_server_create_srv_conf, /* create server configuration */
    njt_stream_proto_server_merge_srv_conf   /* merge server configuration */

};

/* Module definition. */
njt_module_t njt_stream_proto_server_module = {
    NJT_MODULE_V1,
    &njt_stream_proto_server_module_ctx,  /* module context */
    njt_stream_proto_server_commands,     /* module directives */
    NJT_STREAM_MODULE,                    /* module type */
    NULL,                                 /* init master */
    &njt_stream_proto_server_init_module, /* init module */
    &njt_stream_proto_server_process,     /* init process */
    NULL,                                 /* init thread */
    NULL,                                 /* exit thread */
    NULL,                                 /* exit process */
    NULL,                                 /* exit master */
    NJT_MODULE_V1_PADDING};

static njt_int_t njt_stream_proto_server_init_module(njt_cycle_t *cycle)
{

    njt_stream_proto_server_main_conf_t *proto_cmf;
    njt_uint_t i, j;
    njt_slab_pool_t *shpool;
    njt_stream_proto_server_srv_conf_t *sscf, **sscfp;

    proto_cmf = njt_stream_cycle_get_module_main_conf(cycle, njt_stream_proto_server_module);
    if (proto_cmf == NULL)
    {
        return NJT_OK;
    }
    sscfp = proto_cmf->srv_info.elts;
    for (i = 0; i < proto_cmf->srv_info.nelts; i++)
    {
        sscf = sscfp[i];
        if (sscf->zone_name.len != 0)
        {
            shpool = njt_share_slab_get_pool(&sscf->zone_name, sscf->zone_size, 1);
            if (shpool == NULL)
            {
                njt_log_error(NJT_LOG_EMERG, cycle->log, 0,
                              "create proto_session_zone pool \"%V\" error!", &sscf->zone_name);
                return NJT_ERROR;
            }
            sscf->session_shm = njt_slab_alloc(shpool, sizeof(njt_stream_proto_session_shctx_t));
            if (sscf->session_shm == NULL)
            {
                njt_log_error(NJT_LOG_EMERG, cycle->log, 0,
                              "create proto_session_zone ctx \"%V\" error!", &sscf->zone_name);
                return NJT_ERROR;
            }
            sscf->session_shm->shpool = shpool;
            njt_queue_init(&sscf->session_shm->session_queue);
            shpool->data = sscf->session_shm;

            for (j = i + 1; j < proto_cmf->srv_info.nelts; j++)
            {
                if (sscfp[j]->zone_name.len == sscf->zone_name.len && njt_memcmp(sscf->zone_name.data, sscfp[j]->zone_name.data, sscfp[j]->zone_name.len) == 0)
                {
                    njt_log_error(NJT_LOG_EMERG, cycle->log, 0,
                                  "duplicate proto_session_zone name \"%V\"", &sscf->zone_name);
                    return NJT_ERROR;
                }
            }
        }
    }
    return NJT_OK;
}
static char *
njt_conf_set_session_zone(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{

    njt_str_t *value;
    ssize_t size;
    njt_stream_proto_server_srv_conf_t *uscf = conf;

    value = cf->args->elts;
    if (!value[1].len)
    {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid zone name \"%V\"", &value[1]);
        return NJT_CONF_ERROR;
    }
    uscf->zone_name = value[1];
    if (cf->args->nelts == 3)
    {
        size = njt_parse_size(&value[2]);

        if (size == NJT_ERROR)
        {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid zone size \"%V\"", &value[2]);
            return NJT_CONF_ERROR;
        }

        if (size < (ssize_t)(8 * njt_pagesize))
        {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "zone \"%V\" is too small", &value[1]);
            return NJT_CONF_ERROR;
        }
        uscf->zone_size = size;
    }
    return NJT_CONF_OK;
}
static void *njt_stream_proto_server_create_main_conf(njt_conf_t *cf)
{
    njt_stream_proto_server_main_conf_t *cmf;

    njt_log_debug(NJT_LOG_DEBUG_EVENT, njt_cycle->log, 0, "stream_proto create main config");

    cmf = njt_pcalloc(cf->pool, sizeof(njt_stream_proto_server_main_conf_t));
    if (cmf == NULL)
    {
        return NULL;
    }
    njt_array_init(&cmf->srv_info, cf->pool, 1, sizeof(njt_stream_proto_server_srv_conf_t *));

    return cmf;
}
static njt_int_t njt_stream_script_upstream_get_peer(njt_peer_connection_t *pc,
                                                     void *data)
{

    njt_int_t rc;
    njt_int_t peer_num;
    njt_stream_upstream_rr_peer_data_t *rrp;
    njt_stream_proto_upstream_peer_data_t *sp = data;
    njt_stream_proto_server_srv_conf_t *sscf;
    njt_stream_upstream_rr_peer_t *peer;
    njt_stream_upstream_rr_peer_t *selected;
    tcc_stream_client_upstream_data_t peer_data;
    njt_stream_upstream_rr_peers_t *back_peers;
    /* try to select a peer */

    rrp = sp->data;
    sscf = njt_stream_get_module_srv_conf(sp->s, njt_stream_proto_server_module);
    njt_stream_upstream_rr_peers_rlock(rrp->peers);
    back_peers = rrp->peers->next;
    peer_num = rrp->peers->number;
    if (back_peers != NULL)
    {
        peer_num = peer_num + back_peers->number;
    }

    pc->cached = 0;
    pc->connection = NULL;

    /* goto the current session */
    peer = rrp->peers->peer;
    selected = NULL;

    peer_data.cli_addr_text = (tcc_str_t *)&sp->s->connection->addr_text;
    peer_data.peer_list = njt_pcalloc(sp->s->connection->pool, sizeof(tcc_stream_upstream_rr_peer_t) * peer_num);
    if (peer_data.peer_list == NULL)
    {
        return NJT_ERROR;
    }
    peer_num = 0;
    /* find the proposed peer */
    while (peer != NULL)
    {
        if (njt_stream_upstream_pre_handle_peer(peer) == NJT_ERROR)
        {
            peer = peer->next;
            continue;
        }
        peer_data.peer_list[peer_num].name = (tcc_str_t *)&peer->name;
        peer_data.peer_list[peer_num].server = (tcc_str_t *)&peer->server;
        peer_data.peer_list[peer_num].peer = peer;
        peer_num++;
        peer = peer->next;
    }
    peer = NULL;
    if (back_peers != NULL)
    {
        peer = back_peers->peer;
    }

    while (peer != NULL)
    {
        if (njt_stream_upstream_pre_handle_peer(peer) == NJT_ERROR)
        {
            peer = peer->next;
            continue;
        }
        peer_data.peer_list[peer_num].name = (tcc_str_t *)&peer->name;
        peer_data.peer_list[peer_num].server = (tcc_str_t *)&peer->server;
        peer_data.peer_list[peer_num].peer = peer;
        peer_num++;
        peer = peer->next;
    }

    if (peer_num > 0)
    {
        peer_data.peer_num = peer_num;
        selected = sscf->check_upstream_peer_handler(&peer_data);
    }

    /* apply the peer */
    if (selected == NULL)
    {
        goto round_robin;
    }
    selected->selected_time = ((njt_timeofday())->sec) * 1000 + (njt_uint_t)((njt_timeofday())->msec);
    rrp->current = selected;

    pc->sockaddr = selected->sockaddr;
    pc->socklen = selected->socklen;
    pc->name = &selected->name;

    selected->conns++;
    selected->requests++;

    njt_stream_upstream_rr_peers_unlock(rrp->peers);

    return NJT_OK;

round_robin:
    njt_stream_upstream_rr_peers_unlock(rrp->peers);

    // rc = njt_stream_upstream_get_round_robin_peer(pc, rrp);
    rc = NJT_BUSY;
    return rc;
}

static void
njt_stream_proto_upstream_notify_peer(njt_peer_connection_t *pc,
                                      void *data, njt_uint_t type)
{
    njt_stream_upstream_rr_peer_data_t *rrp;
    njt_stream_proto_upstream_peer_data_t *sp = data;
    rrp = sp->data;
    if (sp->original_notify != NULL)
    {
        sp->original_notify(pc, rrp, type);
    }
}
static void njt_stream_proto_upstream_free_peer(njt_peer_connection_t *pc, void *data,
                                                njt_uint_t state)
{
    njt_stream_upstream_rr_peer_data_t *rrp;
    njt_stream_proto_upstream_peer_data_t *sp = data;
    rrp = sp->data;
    if (sp->original_free_peer != NULL)
    {
        sp->original_free_peer(pc, rrp, state);
    }
}

static njt_int_t njt_stream_proto_upstream_init_peer(njt_stream_session_t *s,
                                                     njt_stream_upstream_srv_conf_t *us)
{

    njt_stream_proto_server_srv_conf_t *ups, *scf;
    njt_stream_proto_upstream_peer_data_t *sp;

    ups = njt_stream_conf_upstream_srv_conf(us, njt_stream_proto_server_module);
    if (ups->original_init_peer(s, us) != NJT_OK)
    {
        return NJT_ERROR;
    }
    scf = njt_stream_get_module_srv_conf(s, njt_stream_proto_server_module);
    if (scf->check_upstream_peer_handler == NULL)
    {
        return NJT_OK;
    }
    sp = njt_palloc(s->connection->pool, sizeof(njt_stream_proto_upstream_peer_data_t));
    if (sp == NULL)
    {
        return NJT_ERROR;
    }

    sp->conf = ups;
    sp->s = s;
    sp->data = s->upstream->peer.data;
    sp->original_free_peer = s->upstream->peer.free;
    sp->original_notify = s->upstream->peer.notify;
    sp->original_get_peer = s->upstream->peer.get;
    s->upstream->peer.get = njt_stream_script_upstream_get_peer;
    s->upstream->peer.notify = njt_stream_proto_upstream_notify_peer;
    s->upstream->peer.data = sp;
    s->upstream->peer.free = njt_stream_proto_upstream_free_peer;

    return NJT_OK;
}

static njt_int_t njt_stream_proto_upstream_init(njt_conf_t *cf,
                                                njt_stream_upstream_srv_conf_t *us)
{
    njt_stream_proto_server_srv_conf_t *scf;
    scf = njt_stream_conf_upstream_srv_conf(us,
                                            njt_stream_proto_server_module);

    if (scf->original_init_upstream(cf, us) != NJT_OK)
    {
        return NJT_ERROR;
    }

    scf->original_init_peer = us->peer.init;

    us->peer.init = njt_stream_proto_upstream_init_peer;

    return NJT_OK;
}

static char *
njt_stream_proto_upstream_set(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_stream_proto_server_srv_conf_t *sscf = conf;
    njt_stream_upstream_srv_conf_t *uscf;

    njt_str_t *value;
    if (sscf->proto_upstream_enabled != NJT_CONF_UNSET)
    {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (njt_strcasecmp(value[1].data, (u_char *)"on") == 0)
    {
        sscf->proto_upstream_enabled = 1;
    }
    else if (njt_strcasecmp(value[1].data, (u_char *)"off") == 0)
    {
        sscf->proto_upstream_enabled = 0;
    }
    else
    {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid value \"%s\" in \"%s\" directive, "
                           "it must be \"on\" or \"off\"",
                           value[1].data, cmd->name.data);
        return NJT_CONF_ERROR;
    }
    if (sscf->proto_upstream_enabled == 1)
    {
        uscf = njt_stream_conf_get_module_srv_conf(cf, njt_stream_upstream_module);
        sscf->original_init_upstream = uscf->peer.init_upstream
                                           ? uscf->peer.init_upstream
                                           : njt_stream_upstream_init_round_robin;

        uscf->peer.init_upstream = njt_stream_proto_upstream_init;
    }

    return NJT_CONF_OK;
}

static void njt_stream_proto_server_update(njt_event_t *ev)
{
    njt_stream_proto_server_srv_conf_t *sscf;
    sscf = ev->data;
    if (sscf->server_update_handler)
    {
        sscf->server_update_handler(&sscf->srv_ctx);
        if (sscf->server_update_interval > 0)
        {
            njt_add_timer(&sscf->timer, sscf->server_update_interval);
        }
    }
    return;
}
static void njt_stream_proto_client_update(njt_event_t *ev)
{
    tcc_stream_request_t *r;
    njt_stream_proto_server_client_ctx_t *ctx;
    njt_stream_proto_server_srv_conf_t *sscf;
    njt_connection_t *c;
    njt_stream_session_t *s;
    njt_int_t rc = NJT_OK;
    tcc_str_t msg;
    size_t max_len, len;

    ctx = ev->data;
    s = ctx->r.s;
    c = s->connection;
    r = &ctx->r;
    sscf = njt_stream_get_module_srv_conf((njt_stream_session_t *)r->s, njt_stream_proto_server_module);
    if (sscf->client_update_handler)
    {
        msg.data = ctx->r.in_buf.pos;
        msg.len = ctx->r.in_buf.last - ctx->r.in_buf.pos;
        ctx->r.used_len = 0;
        rc = sscf->client_update_handler(&ctx->r, &msg);
        if (rc == NJT_ERROR || ctx->r.status == TCC_SESSION_CLOSING)
        {
            ctx->r.status = TCC_SESSION_CLOSING;
            goto end;
        }
        njt_stream_proto_server_update_in_buf(&ctx->r.in_buf, ctx->r.used_len);
        max_len = ctx->r.in_buf.end - ctx->r.in_buf.start;
        len = ctx->r.in_buf.last - ctx->r.in_buf.pos;
        if (max_len == sscf->buffer_size && max_len == len && max_len > 0)
        {
            ctx->r.status = TCC_SESSION_CLOSING; // 没空间了。
        }
        if (ctx->r.status == TCC_SESSION_CLOSING)
        {
            goto end;
        }
        if (sscf->client_update_interval > 0)
        {
            njt_add_timer(&ctx->timer, sscf->client_update_interval);
        }
    }
    return;
end:
    njt_log_error(NJT_LOG_INFO, c->log, 0, "close client");
    njt_stream_proto_server_del_session(s, NJT_STREAM_OK, 1);
    return;
}
static int topic_change_handler_internal(njt_str_t *key, njt_str_t *value, void *data, njt_str_t *out_msg)
{
    // worker_all   /worker_pid_111
    // mqconf = (njt_mqconf_conf_t*)njt_get_conf(cf->cycle->conf_ctx,njt_mqconf_module); node_name
    // send:/worker_pid_/0.0.0.0:80/session/session_value/0
    njt_str_t zone_name;
    tcc_str_t session;
    njt_uint_t i, num;
    njt_int_t msg_type;
    tcc_stream_request_t *r;
    njt_stream_proto_server_srv_conf_t *sscf;
    njt_str_t topic = njt_string("/worker_all");
    njt_log_debug(NJT_LOG_DEBUG_STREAM, njt_cycle->log, 0, "get mqtt=%V", key);
    if (value == NULL && value->len == 0)
    {
        return NJT_ERROR;
    }
    njt_str_null(&zone_name);
    njt_str_null(&session);
    msg_type = -1;
    num = 0;
    for (i = 0; i < key->len; i++)
    {
        if (key->data[i] == '/')
        {
            num++;
        }
        else if (num == 4 && zone_name.data == NULL)
        {
            zone_name.data = key->data + i;
        }
        else if (num == 5 && session.data == NULL)
        {
            session.data = key->data + i;
        }
        if (num == 5 && zone_name.len == 0)
        {
            zone_name.len = key->data + i - zone_name.data;
        }
        else if (num == 6 && session.len == 0)
        {
            session.len = key->data + i - session.data;
            break;
        }
    }
    if (key->len > topic.len && njt_memcmp(key->data, topic.data, topic.len) == 0 && key->data[key->len - 1] == '0')
    {
        msg_type = MSG_TYPE_BROADCAST;
    }
    else if (key->len > topic.len && njt_memcmp(key->data, topic.data, topic.len) == 0 && key->data[key->len - 1] == '1')
    {
        msg_type = MSG_TYPE_OTHER;
    }
    if (zone_name.data == NULL)
    {
        return NJT_ERROR;
    }
    sscf = njt_stream_get_ctx_by_zone((njt_cycle_t *)njt_cycle, &zone_name);
    if (sscf)
    {
        if (msg_type == MSG_TYPE_BROADCAST)
        {
            proto_server_send_local(&sscf->srv_ctx, (char *)value->data, value->len);
        }
        else
        {
            r = cli_local_find_by_session(&sscf->srv_ctx, &session);
            if (msg_type == MSG_TYPE_OTHER)
            {
                if (r != NULL)
                {
                    proto_server_send_others(&r->session, r->tcc_server, (char *)value->data, value->len);
                }
                else
                {
                    proto_server_send_local(&sscf->srv_ctx, (char *)value->data, value->len);
                }
            }
            else
            { // 1v1
                if (r != NULL)
                {
                    proto_server_send(r, (char *)value->data, value->len);
                }
            }
        }
    }
    return NJT_OK;
}
static int topic_change_handler(njt_str_t *key, njt_str_t *value, void *data)
{
    return topic_change_handler_internal(key, value, data, NULL);
}

static int topic_will_change_handler(njt_str_t *key, njt_str_t *value, void *data)
{
    njt_stream_proto_server_main_conf_t *cmf;
    njt_uint_t i;
    njt_stream_proto_server_srv_conf_t *sscf, **sscfp;

    cmf = njt_stream_cycle_get_module_main_conf(njt_cycle, njt_stream_proto_server_module);
    if (cmf == NULL)
    {
        return NJT_OK;
    }
    sscfp = cmf->srv_info.elts;
    for (i = 0; i < cmf->srv_info.nelts; i++)
    {
        sscf = sscfp[i];
        if (sscf->session_shm != NULL)
        {
            njt_stream_proto_remove_session_by_pid(&sscf->srv_ctx, njt_atoi(value->data, value->len));
        }
    }

    njt_log_debug(NJT_LOG_DEBUG_STREAM, njt_cycle->log, 0, "get will mqtt=%V,value=%V", key, value);
    //

    return NJT_OK;
}

static njt_int_t njt_stream_proto_server_process(njt_cycle_t *cycle)
{
    njt_stream_proto_server_main_conf_t *cmf;
    njt_uint_t i;
    njt_stream_proto_server_srv_conf_t *sscf, **sscfp;
    njt_str_t key = njt_string("session");
    njt_str_t key2 = njt_string("stream_proto");
    njt_kv_reg_handler_t h;

    cmf = njt_stream_cycle_get_module_main_conf(cycle, njt_stream_proto_server_module);
    if (cmf == NULL)
    {
        return NJT_OK;
    }
    sscfp = cmf->srv_info.elts;
    for (i = 0; i < cmf->srv_info.nelts; i++)
    {
        sscf = sscfp[i];
        if (sscf->server_update_interval != 0 && sscf->server_update_handler != NULL)
        {
            sscf->timer.handler = njt_stream_proto_server_update;
            sscf->timer.log = cycle->log;
            sscf->timer.data = sscf;
            sscf->timer.cancelable = 1;
            if (sscf->server_update_interval > 0 && sscf->server_update_handler != NULL)
            {
                njt_add_timer(&sscf->timer, (njt_random() % 1000));
            }
        }
    }

    njt_memzero(&h, sizeof(njt_kv_reg_handler_t));
    h.key = &key;
    h.handler = topic_change_handler;
    h.api_type = NJT_KV_API_TYPE_DECLATIVE;
    njt_kv_reg_handler(&h);

    njt_memzero(&h, sizeof(njt_kv_reg_handler_t));
    h.key = &key2;
    h.handler = topic_will_change_handler;
    h.api_type = NJT_KV_API_TYPE_DECLATIVE;
    njt_kv_reg_handler(&h);
    return NJT_OK;
}

static char *
njt_stream_proto_server_set(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_stream_proto_server_srv_conf_t *sscf = conf;
    njt_stream_core_srv_conf_t *cscf;

    njt_str_t *value;
    if (sscf->proto_server_enabled != NJT_CONF_UNSET)
    {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (njt_strcasecmp(value[1].data, (u_char *)"on") == 0)
    {
        sscf->proto_server_enabled = 1;
    }
    else if (njt_strcasecmp(value[1].data, (u_char *)"off") == 0)
    {
        sscf->proto_server_enabled = 0;
    }
    else
    {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid value \"%s\" in \"%s\" directive, "
                           "it must be \"on\" or \"off\"",
                           value[1].data, cmd->name.data);
        return NJT_CONF_ERROR;
    }
    if (sscf->proto_server_enabled == 1)
    {
        cscf = njt_stream_conf_get_module_srv_conf(cf, njt_stream_core_module);
        cscf->handler = njt_stream_proto_server_handler;
    }

    return NJT_CONF_OK;
}

static void
njt_stream_proto_server_delete_tcc(void *data)
{
    TCCState *tcc = data;
    tcc_delete(tcc);
}

static TCCState *njt_stream_proto_server_create_tcc(njt_conf_t *cf)
{
    u_char *p;
    njt_pool_cleanup_t *cln;
    njt_str_t full_path, path = njt_string("lib/tcc");
    njt_str_t full_path_include, path_include = njt_string("lib/tcc/include");

    TCCState *tcc = tcc_new();
    if (tcc == NULL)
    {
        return NULL;
    }
    cln = njt_pool_cleanup_add(cf->cycle->pool, 0);
    if (cln == NULL)
    {
        return NJT_CONF_ERROR;
    }
    cln->handler = njt_stream_proto_server_delete_tcc;
    cln->data = tcc;

    full_path.len = cf->cycle->prefix.len + path.len + 10;
    full_path.data = njt_pcalloc(cf->pool, full_path.len);
    if (full_path.data == NULL)
    {
        return NULL;
    }
    p = njt_snprintf(full_path.data, full_path.len, "%V%V\0", &cf->cycle->prefix, &path);
    full_path.len = p - full_path.data;

    full_path_include.len = cf->cycle->prefix.len + path_include.len + 10;
    full_path_include.data = njt_pcalloc(cf->pool, full_path_include.len);
    if (full_path_include.data == NULL)
    {
        return NULL;
    }
    p = njt_snprintf(full_path_include.data, full_path_include.len, "%V%V\0", &cf->cycle->prefix, &path_include);
    full_path_include.len = p - full_path_include.data;

    tcc_set_options(tcc, "-Werror -g");
    tcc_set_output_type(tcc, TCC_OUTPUT_MEMORY);
    // tcc_set_options(tcc, "-Werror ");
    tcc_set_lib_path(tcc, (const char *)full_path.data);
    tcc_add_include_path(tcc, (const char *)full_path_include.data);
    tcc_add_sysinclude_path(tcc, (const char *)full_path.data);
    return tcc;
}
static void *njt_stream_proto_server_create_srv_conf(njt_conf_t *cf)
{
    njt_stream_proto_server_srv_conf_t *conf;

    njt_log_debug(NJT_LOG_DEBUG_EVENT, njt_cycle->log, 0, "stream_proto create serv config");

    conf = njt_pcalloc(cf->pool, sizeof(njt_stream_proto_server_srv_conf_t));
    if (conf == NULL)
    {
        return NULL;
    }
    conf->proto_server_enabled = NJT_CONF_UNSET;
    conf->proto_upstream_enabled = NJT_CONF_UNSET;
    conf->s = NJT_CONF_UNSET_PTR;
    conf->tcc_files = NJT_CONF_UNSET_PTR;
    conf->connect_timeout = NJT_CONF_UNSET_MSEC;
    conf->client_update_interval = NJT_CONF_UNSET_MSEC;
    conf->server_update_interval = NJT_CONF_UNSET_MSEC;
    conf->buffer_size = NJT_CONF_UNSET_SIZE;
    conf->session_max_mem_size = NJT_CONF_UNSET_SIZE;

    conf->stack_size = NJT_CONF_UNSET_SIZE;
    conf->session_size = NJT_CONF_UNSET_SIZE;
    conf->mtask_timeout = NJT_CONF_UNSET_MSEC;
    conf->eval_script = &eval_script;

    return conf;
}

static char *njt_stream_proto_server_merge_srv_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_str_t *pp, value;
    char *filename;
    njt_uint_t i;
    int filetype;
    njt_str_t full_name;
    njt_int_t rc;
    njt_stream_proto_server_main_conf_t *cmf;
    njt_stream_proto_server_srv_conf_t **psscf;

    njt_stream_proto_server_srv_conf_t *prev = parent;
    njt_stream_proto_server_srv_conf_t *conf = child;
    njt_conf_merge_value(conf->proto_server_enabled, prev->proto_server_enabled, 0);
    njt_conf_merge_value(conf->zone_size, prev->zone_size, 16384);
    njt_conf_merge_size_value(conf->buffer_size,
                              prev->buffer_size, 16384);
    njt_conf_merge_size_value(conf->session_max_mem_size,
                              prev->session_max_mem_size, 16384);
    njt_conf_merge_msec_value(conf->connect_timeout,
                              prev->connect_timeout, 60000);
    njt_conf_merge_msec_value(conf->client_update_interval,
                              prev->client_update_interval, 60000);
    njt_conf_merge_msec_value(conf->server_update_interval,
                              prev->server_update_interval, 60000);
    njt_conf_merge_size_value(conf->stack_size,
                              prev->stack_size,
                              (size_t)MTASK_DEFAULT_STACK_SIZE);
    njt_conf_merge_msec_value(conf->mtask_timeout,
                              prev->mtask_timeout,
                              MTASK_DEFAULT_TIMEOUT);
    njt_conf_merge_size_value(conf->session_size,
                              prev->session_size,
                              (INET_ADDRSTRLEN + 20));
    if (conf->proto_pass_enabled && !conf->proto_server_enabled)
    {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "proto_pass: need proto_server directive!");
    }
    if (conf->proto_server_enabled && conf->s == NJT_CONF_UNSET_PTR && conf->tcc_files != NJT_CONF_UNSET_PTR)
    {
        conf->s = njt_stream_proto_server_create_tcc(cf); // todo
        if (conf->s == NULL)
        {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "njt_stream_proto_server_create_tcc   error!");
            return NJT_CONF_ERROR;
        }

        pp = conf->tcc_files->elts;
        for (i = 0; i < conf->tcc_files->nelts; i++)
        {
            value = pp[i];

            full_name = value;
            if (njt_conf_full_name((void *)cf->cycle, &full_name, 0) != NJT_OK)
            {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "sniffer_filter_file \"%V\", njt_conf_full_name error!", &full_name);
                return NJT_CONF_ERROR;
            }

            filename = njt_pcalloc(cf->pool, full_name.len + 1);
            if (filename == NULL)
            {
                return NJT_CONF_ERROR;
            }
            njt_memcpy(filename, full_name.data, full_name.len);
            filetype = TCC_FILETYPE_C;
            if (tcc_add_file(conf->s, filename, filetype) < 0)
            {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "tcc_add_file   error!");
                return NJT_CONF_ERROR;
            }
        }
        if (tcc_relocate(conf->s, TCC_RELOCATE_AUTO) < 0)
        {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "tcc_relocate   error!");
            return NJT_CONF_ERROR;
        }
    }
    if (conf->proto_server_enabled && conf->s != NJT_CONF_UNSET_PTR)
    {
        conf->srv_ctx.client_list = njt_pcalloc(cf->pool, sizeof(njt_array_t));
        conf->srv_ctx.hashmap = njt_pcalloc(cf->pool, sizeof(njt_lvlhash_map_t));
        if (conf->srv_ctx.client_list == NULL || conf->srv_ctx.hashmap == NULL)
        {
            return NULL;
        }
        conf->srv_ctx.tcc_pool = njt_create_dynamic_pool(njt_pagesize, njt_cycle->log);
        if (conf->srv_ctx.tcc_pool == NULL)
        {
            return NULL;
        }
        rc = njt_sub_pool(cf->cycle->pool, conf->srv_ctx.tcc_pool);
        if (rc == NJT_ERROR)
        {
            return NULL;
        }
        njt_array_init(conf->srv_ctx.client_list, cf->pool, 1, sizeof(tcc_stream_request_t *));

        conf = njt_stream_conf_get_module_srv_conf(cf, njt_stream_proto_server_module);
        conf->connection_handler = tcc_get_symbol(conf->s, "proto_server_process_connection");
        conf->preread_handler = tcc_get_symbol(conf->s, "proto_server_process_preread");
        conf->log_handler = tcc_get_symbol(conf->s, "proto_server_process_log");
        conf->message_handler = tcc_get_symbol(conf->s, "proto_server_process_message");
        conf->abort_handler = tcc_get_symbol(conf->s, "proto_server_process_connection_close");
        conf->client_update_handler = tcc_get_symbol(conf->s, "proto_server_process_client_update");
        conf->server_update_handler = tcc_get_symbol(conf->s, "proto_server_update");
        conf->server_init_handler = tcc_get_symbol(conf->s, "proto_server_init");
        conf->build_proto_message = tcc_get_symbol(conf->s, "proto_server_create_message");
        conf->upstream_message_handler = tcc_get_symbol(conf->s, "proto_server_upstream_message");
        conf->check_upstream_peer_handler = tcc_get_symbol(conf->s, "proto_server_check_upstream_peer");
        conf->build_client_message = tcc_get_symbol(conf->s, "create_proto_msg");
        conf->run_proto_message = tcc_get_symbol(conf->s, "run_proto_msg");
        conf->has_proto_message = tcc_get_symbol(conf->s, "has_proto_msg");
        conf->destroy_message = tcc_get_symbol(conf->s, "destroy_proto_msg");
        conf->set_session_handler = tcc_get_symbol(conf->s, "proto_set_session_info");

        if (conf->proto_pass_enabled != 1)
        {
            if (conf->build_client_message == NULL)
            {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "no find create_proto_msg function!");
                return NJT_CONF_ERROR;
            }
            if (conf->run_proto_message == NULL)
            {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "no find run_proto_msg function!");
                return NJT_CONF_ERROR;
            }
            if (conf->has_proto_message == NULL)
            {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "no find has_proto_msg function!");
                return NJT_CONF_ERROR;
            }
            if (conf->destroy_message == NULL)
            {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "no find destroy_proto_msg function!");
                return NJT_CONF_ERROR;
            }
        }
        conf->upstream_abort_handler = tcc_get_symbol(conf->s, "proto_server_upstream_connection_close");
        if (conf->server_init_handler)
        {
            conf->server_init_handler(&conf->srv_ctx);
        }
        cmf = njt_stream_conf_get_module_main_conf(cf, njt_stream_proto_server_module);
        psscf = njt_array_push(&cmf->srv_info);
        *psscf = conf;
    }
    njt_log_debug(NJT_LOG_DEBUG_EVENT, njt_cycle->log, 0, "stream_proto merge serv config");
    return NJT_CONF_OK;
}

static njt_int_t njt_stream_proto_server_access_handler(njt_stream_session_t *s)
{
    njt_stream_proto_server_srv_conf_t *sscf;
    njt_stream_proto_server_client_ctx_t *ctx;
    njt_connection_t *c;
    njt_int_t rc;
    u_char *p;
    njt_uint_t port;

    c = s->connection;
    sscf = njt_stream_get_module_srv_conf(s, njt_stream_proto_server_module);
    if (!sscf->proto_server_enabled)
    {
        return NJT_DECLINED;
    }
    ctx = njt_pcalloc(c->pool, sizeof(njt_stream_proto_server_client_ctx_t));
    if (ctx == NULL)
    {
        goto end;
    }
    ctx->r.session.data = njt_pcalloc(c->pool, sscf->session_size);
    if (ctx->r.session.data == NULL)
    {
        goto end;
    }
    if (ctx->out_buf.start == NULL)
    {
        p = njt_pcalloc(c->pool, sscf->buffer_size);
        if (p == NULL)
        {
            goto end;
        }

        ctx->out_buf.start = p;
        ctx->out_buf.end = p + sscf->buffer_size;
        ctx->out_buf.pos = p;
        ctx->out_buf.last = p;
    }
    ctx->r.s = s;
    ctx->r.tcc_server = &sscf->srv_ctx;
    ctx->r.addr_text = (tcc_str_t *)&s->connection->addr_text;
    port = njt_inet_get_port(s->connection->sockaddr);
    ctx->r.session.len = njt_snprintf(ctx->r.session.data, sscf->session_size, "%d_%V:%ui", njt_getpid(), &s->connection->addr_text, port) - ctx->r.session.data;
    ctx->r.tcc_pool = njt_create_dynamic_pool(njt_pagesize, njt_cycle->log);
    if (ctx->r.tcc_pool == NULL)
    {
        goto end;
    }
    rc = njt_sub_pool(c->pool, ctx->r.tcc_pool);
    if (rc == NJT_ERROR)
    {
        goto end;
    }
    njt_stream_set_ctx(s, ctx, njt_stream_proto_server_module);
    rc = NJT_DECLINED;
    if (sscf->connection_handler)
    {
        rc = sscf->connection_handler(&ctx->r);
        if (rc == NJT_ERROR || ctx->r.status == TCC_SESSION_CLOSING)
        {
            return NJT_STREAM_FORBIDDEN;
        }
    }
    return rc;
end:
    return NJT_DECLINED;
}
static void njt_stream_proto_server_update_in_buf(tcc_buf_t *b, size_t used_len)
{
    njt_uint_t len;
    if (used_len <= 0)
    {
        if (b->last == b->end && b->pos > b->start)
        { // 收到结尾，但不够一个包，移动位置。
            len = b->last - b->pos;
            if (len > 0)
            {
                njt_memmove(b->start, b->pos, len);
            }
            b->pos = b->start;
            b->last = b->start + len;
        }
        return;
    }
    b->pos = b->pos + used_len;
    if (b->pos >= b->last)
    {
        // 消费完，重置。
        b->pos = b->start;
        b->last = b->start;
    }
}
static njt_int_t njt_stream_proto_server_preread_handler(njt_stream_session_t *s)
{

    njt_stream_proto_server_srv_conf_t *sscf;
    njt_stream_proto_server_client_ctx_t *ctx;
    njt_connection_t *c;
    njt_int_t rc = NJT_DECLINED;
    tcc_str_t msg;
    size_t max_len, len;

    c = s->connection;

    sscf = njt_stream_get_module_srv_conf(s, njt_stream_proto_server_module);
    if (!sscf->proto_server_enabled)
    {
        return NJT_DECLINED;
    }
    if (sscf->preread_handler)
    {
        ctx = njt_stream_get_module_ctx(s, njt_stream_proto_server_module);
        ctx->r.s = s;
        ctx->r.addr_text = (tcc_str_t *)&s->connection->addr_text;
        if (c->buffer != NULL && ctx->r.in_buf.pos == NULL)
        {
            ctx->r.in_buf.end = c->buffer->end;
            ctx->r.in_buf.start = c->buffer->start;
            ctx->r.in_buf.pos = c->buffer->pos;
            ctx->r.in_buf.last = c->buffer->last;
        }
        else if (c->buffer != NULL)
        {
            ctx->r.in_buf.last = c->buffer->last;
        }
        // tcc_stream_request_t *r,void *data,size_t len,size_t *used_len
        msg.data = ctx->r.in_buf.pos;
        msg.len = ctx->r.in_buf.last - ctx->r.in_buf.pos;
        ctx->r.used_len = 0;
        rc = sscf->preread_handler(&ctx->r, &msg);
        // njt_stream_proto_server_update_in_buf(&ctx->r.in_buf, ctx->r.used_len);
        if (ctx->r.in_buf.last - ctx->r.in_buf.pos >= ctx->r.used_len)
        {
            ctx->r.in_buf.pos = ctx->r.in_buf.pos + ctx->r.used_len;
        }
        max_len = ctx->r.in_buf.end - ctx->r.in_buf.start;
        len = ctx->r.in_buf.last - ctx->r.in_buf.pos;
        if (rc == NJT_AGAIN && max_len == len && max_len > 0)
        {
            rc = NJT_ERROR; // 没空间了。
        }
    }
    return rc;
}
static njt_int_t njt_stream_proto_server_log_handler(njt_stream_session_t *s)
{

    njt_stream_proto_server_srv_conf_t *sscf;
    njt_stream_proto_server_client_ctx_t *ctx;
    njt_int_t rc = NJT_OK;

    sscf = njt_stream_get_module_srv_conf(s, njt_stream_proto_server_module);
    if (!sscf->proto_server_enabled)
    {
        return NJT_OK;
    }
    ctx = njt_stream_get_module_ctx(s, njt_stream_proto_server_module);
    ctx->r.s = s;
    ctx->r.addr_text = (tcc_str_t *)&s->connection->addr_text;

    njt_stream_proto_server_del_session(s, NJT_STREAM_OK, 0);
    if (s->upstream && sscf->upstream_abort_handler)
    {
        rc = sscf->upstream_abort_handler(&ctx->r);
    }
    if (sscf->abort_handler)
    {
        rc = sscf->abort_handler(&ctx->r);
    }
    if (sscf->log_handler)
    {
        rc = sscf->log_handler(&ctx->r);
    }
    return rc;
}
static void njt_stream_proto_server_handler(njt_stream_session_t *s)
{
    njt_connection_t *c;
    njt_stream_proto_server_client_ctx_t *ctx;
    njt_uint_t flags;
    njt_stream_proto_server_srv_conf_t *sscf;
    tcc_stream_request_t **r;

    c = s->connection;

    c->log->action = "proto_server_handler";
    ctx = njt_stream_get_module_ctx(s, njt_stream_proto_server_module);
    sscf = njt_stream_get_module_srv_conf(s, njt_stream_proto_server_module);

    if (c->buffer != NULL)
    {
        ctx->r.in_buf.end = c->buffer->end;
        ctx->r.in_buf.start = c->buffer->start;
        ctx->r.in_buf.pos = c->buffer->pos;
        ctx->r.in_buf.last = c->buffer->last;
    }

    ctx->timer.handler = njt_stream_proto_client_update;
    ctx->timer.log = njt_cycle->log;
    ctx->timer.data = ctx;
    ctx->timer.cancelable = 1;

    flags = s->connection->read->eof ? NJT_CLOSE_EVENT : 0;

    if (njt_handle_read_event(s->connection->read, flags) != NJT_OK)
    {
        goto end;
    }

    c->write->handler = njt_stream_proto_server_write_handler;
    c->read->handler = njt_stream_proto_server_read_handler;

    if (c->read->ready)
    {
        njt_post_event(c->read, &njt_posted_events);
    }
    if (sscf->connect_timeout != NJT_CONF_UNSET_MSEC && sscf->connect_timeout > 0)
    {
        njt_add_timer(c->read, sscf->connect_timeout);
    }
    r = njt_array_push(sscf->srv_ctx.client_list);
    *r = &ctx->r;

    if (sscf->client_update_interval > 0 && sscf->client_update_handler != NULL)
    {
        njt_add_timer(&ctx->timer, sscf->client_update_interval);
    }
    njt_stream_proto_add_client_hash(&sscf->srv_ctx,*r);
    njt_stream_proto_server_read_handler(c->read);
    return;
end:
    njt_stream_proto_server_del_session(s, NJT_STREAM_INTERNAL_SERVER_ERROR, 1);
    return;
}
static void mtask_proc()
{
    njt_stream_session_t *s;
    njt_stream_proto_server_client_ctx_t *ctx;

    s = mtask_current;
    ctx = njt_stream_get_module_ctx(s, njt_stream_proto_server_module);

    if (ctx->r.status != TCC_SESSION_CLOSING)
    {
        ctx->result = ctx->msg_handler(&ctx->r); // sleep
        njt_log_debug(NJT_LOG_DEBUG_STREAM, s->connection->log, 0, "tcc mtask_proc=%d,ctx->res=%d!", ctx->result, ctx->result);
    }
}

static int mtask_wake(njt_stream_session_t *s, int flags)
{

    njt_stream_proto_server_client_ctx_t *ctx;

    njt_log_debug(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                  "mtask wake");

    ctx = njt_stream_get_module_ctx(s, njt_stream_proto_server_module);

    mtask_setcurrent(s);
    if (flags & MTASK_WAKE_TIMEDOUT)
        ctx->mtask_timeout = 1;
    swapcontext(&ctx->main_ctx, &ctx->runctx);
    mtask_resetcurrent();

    return 0;
}
static int eval_script(tcc_stream_request_t *r, njt_proto_process_msg_handler_pt handler)
{
    njt_int_t run = APP_DECLINED;
    njt_stream_proto_server_client_ctx_t *ctx;
    njt_connection_t *c;
    njt_stream_proto_server_srv_conf_t *sscf;
    njt_stream_session_t *s = r->s;

    c = s->connection;
    sscf = njt_stream_get_module_srv_conf(s, njt_stream_proto_server_module);
    ctx = njt_stream_get_module_ctx(s, njt_stream_proto_server_module);
    if (handler == NULL && ctx == NULL)
    {
        njt_log_debug(NJT_LOG_DEBUG_STREAM, s->connection->log, 0, "tcc eval_script:handler=null");
        return run;
    }
    if (ctx->result == APP_AGAIN)
    {
        swapcontext(&ctx->main_ctx, &ctx->runctx);
    }
    else
    {
        if (ctx->runctx.uc_stack.ss_sp == NULL)
        {
            ctx->run_stak = njt_palloc(c->pool, sscf->stack_size);
            ctx->runctx.uc_stack.ss_size = sscf->stack_size;
            ctx->runctx.uc_stack.ss_flags = 0;
            ctx->runctx.uc_link = NULL;
        }
        ctx->msg_handler = handler;
        ctx->result = APP_AGAIN;

        getcontext(&ctx->runctx);
        ctx->runctx.uc_stack.ss_sp = ctx->run_stak;
        ctx->runctx.uc_stack.ss_size = MTASK_DEFAULT_STACK_SIZE;
        ctx->runctx.uc_link = &ctx->main_ctx;
        mtask_setcurrent(s);
        makecontext(&ctx->runctx, &mtask_proc, 0); // 写协程
        swapcontext(&ctx->main_ctx, &ctx->runctx);
    }

    njt_log_debug(NJT_LOG_DEBUG_STREAM, s->connection->log, 0, "tcc eval_script=%d", ctx->result);
    return ctx->result;
}
static void
njt_stream_proto_server_read_handler(njt_event_t *ev)
{
    njt_stream_session_t *s;
    njt_connection_t *c;
    njt_stream_proto_server_client_ctx_t *ctx;
    u_char *p;
    size_t size, len, max_len;
    tcc_buf_t *b;
    ssize_t n;
    njt_stream_proto_server_srv_conf_t *sscf;
    tcc_str_t msg;
    njt_int_t rc = NJT_OK;
    njt_int_t msg_rc, has, run;
    njt_uint_t code = NJT_STREAM_OK;

    c = ev->data;
    s = c->data;
    has = APP_FALSE;
    sscf = njt_stream_get_module_srv_conf(s, njt_stream_proto_server_module);
    ctx = njt_stream_get_module_ctx(s, njt_stream_proto_server_module);

    if (ev->timedout)
    {
        njt_log_debug(NJT_LOG_DEBUG_STREAM, c->log, NJT_ETIMEDOUT, "client timed out");

        if (ctx->timer.timer_set)
        {
            njt_del_timer(&ctx->timer);
        }
        code = NJT_STREAM_OK;
        goto end;
    }

    if (ctx->r.status == TCC_SESSION_CLOSING)
    {
        njt_log_debug(NJT_LOG_DEBUG_STREAM, c->log, 0, "tcc close client");
        code = NJT_STREAM_OK;
        goto end;
    }
    for (;;)
    {
        for (;;)
        {
            if (ctx->r.in_buf.start == NULL)
            {
                p = njt_pcalloc(c->pool, sscf->buffer_size);
                if (p == NULL)
                {
                    code = NJT_STREAM_INTERNAL_SERVER_ERROR;
                    goto end;
                }

                ctx->r.in_buf.start = p;
                ctx->r.in_buf.end = p + sscf->buffer_size;
                ctx->r.in_buf.pos = p;
                ctx->r.in_buf.last = p;
            }
            b = &ctx->r.in_buf;
            size = b->end - b->last;
            if (size && c != NULL && c->read->ready && !c->read->delayed)
            {
                n = c->recv(c, b->last, size);
                if (n == 0)
                {
                    code = NJT_STREAM_OK;
                    rc = NJT_ERROR;
                    ctx->r.status = TCC_SESSION_CLOSING;
                    break;
                }
                if (n == NJT_AGAIN)
                {
                    break;
                }
                if (n == NJT_ERROR)
                {
                    c->read->eof = 1;
                    n = 0;
                }
                b->last += n;
                continue;
            }
            break;
        }
        msg.data = ctx->r.in_buf.pos;
        msg.len = ctx->r.in_buf.last - ctx->r.in_buf.pos;
        for (;;)
        {
            ctx->r.used_len = 0;
            msg_rc = APP_DECLINED;
            run = APP_DECLINED;
            if (ctx->r.status == TCC_SESSION_CONNECT)
            {
                if (sscf->build_client_message)
                {
                    if (sscf->has_proto_message && sscf->eval_script)
                    {
                        njt_log_debug(NJT_LOG_DEBUG_STREAM, c->log, 0, "has_proto_message line=%d!", __LINE__);
                        has = sscf->has_proto_message(&ctx->r);
                        if (has == APP_TRUE && sscf->run_proto_message)
                        {
                            run = sscf->eval_script(&ctx->r, sscf->run_proto_message);
                            if (run == APP_AGAIN)
                            {
                                return;
                            }

                            if (run == APP_OK || run == APP_ERROR)
                            {
                                njt_log_debug(NJT_LOG_DEBUG_STREAM, c->log, 0, "destroy_message line=%d!", __LINE__);
                                if (sscf->destroy_message)
                                {
                                    sscf->destroy_message(&ctx->r);
                                }
                                if (run == APP_ERROR)
                                {
                                    code = NJT_STREAM_OK;
                                    goto end;
                                }
                            }
                        }
                    }
                    if (msg.len > 0)
                    {
                        has = APP_FALSE;
                        msg_rc = sscf->build_client_message(&ctx->r, &msg);
                        if (msg_rc == APP_OK)
                        {
                            njt_log_debug(NJT_LOG_DEBUG_STREAM, c->log, 0, "has_proto_message line=%d!", __LINE__);
                            has = sscf->has_proto_message(&ctx->r);
                        }
                        if (has == APP_TRUE && sscf->run_proto_message)
                        {
                            run = sscf->eval_script(&ctx->r, sscf->run_proto_message);
                            if (run == APP_OK || run == APP_ERROR)
                            {
                                njt_log_debug(NJT_LOG_DEBUG_STREAM, c->log, 0, "destroy_message line=%d!", __LINE__);
                                if (sscf->destroy_message)
                                {
                                    sscf->destroy_message(&ctx->r);
                                }
                                if (run == APP_ERROR)
                                {
                                    code = NJT_STREAM_OK;
                                    goto end;
                                }
                            }
                        }
                    }
                }
                else
                {
                    // msg_rc = sscf->message_handler(&ctx->r, &msg);
                    njt_log_error(NJT_LOG_INFO, c->log, 0, "no find create_proto_msg function!");
                }
            }
            if (ctx->r.status == TCC_SESSION_CLOSING || msg_rc == NJT_ERROR)
            {
                code = NJT_STREAM_OK;
                goto end;
            }
            if (ctx->r.used_len == 0)
            {
                break;
            }
            njt_stream_proto_server_update_in_buf(&ctx->r.in_buf, ctx->r.used_len);
            max_len = ctx->r.in_buf.end - ctx->r.in_buf.start;
            len = ctx->r.in_buf.last - ctx->r.in_buf.pos;
            if (max_len == sscf->buffer_size && max_len == len && max_len > 0)
            {
                ctx->r.status = TCC_SESSION_CLOSING; // 没空间了。
            }
            if (max_len != sscf->buffer_size && ctx->r.in_buf.pos == ctx->r.in_buf.last)
            {
                ctx->r.in_buf.start = NULL; // by zyg,由之前的预读阶段buffer 大小，切换为本模块的定义大小。
            }
            if (ctx->r.in_buf.start != NULL)
            {
                msg.data = ctx->r.in_buf.pos;
                msg.len = ctx->r.in_buf.last - ctx->r.in_buf.pos;
                if (run == APP_AGAIN)
                {
                    return;
                }
                continue;
            }
            if (run == APP_AGAIN)
            {
                return;
            }
            break;
        }

        if (rc == NJT_ERROR)
        {
            njt_log_error(NJT_LOG_INFO, c->log, 0, "tcc close client");
            code = NJT_STREAM_OK;
            goto end;
        }
        if (c->read->ready && ((ctx->r.in_buf.start == NULL) || (ctx->r.in_buf.end - ctx->r.in_buf.last > 0)))
        {
            continue;
        }
        break;
    }
    if (sscf->connect_timeout != NJT_CONF_UNSET_MSEC && sscf->connect_timeout > 0)
    {
        njt_add_timer(ev, sscf->connect_timeout);
    }
    return;
end:
    njt_stream_proto_server_del_session(s, code, 1);
    return;
}
static njt_int_t
njt_stream_proto_server_write_data(njt_event_t *ev)
{
    njt_connection_t *c;
    njt_stream_session_t *s;
    njt_chain_t **busy;
    njt_stream_proto_server_client_ctx_t *ctx;

    c = ev->data;
    s = c->data;
    if (ev->timedout)
    {
        ev->timedout = 0;
        if (njt_handle_write_event(ev, 0) != NJT_OK)
        {
            return NJT_ERROR;
        }
        return NJT_OK;
    }

    ctx = njt_stream_get_module_ctx(s, njt_stream_proto_server_module);
    busy = &ctx->out_busy;
    if (ctx->out_chain || *busy || s->connection->buffered)
    {
        if (njt_proto_write_filter(s, ctx->out_chain, 1) == NJT_ERROR)
        {
            return NJT_ERROR;
        }
        njt_chain_update_chains(c->pool, &ctx->free, busy, &ctx->out_chain,
                                (njt_buf_tag_t)&njt_stream_proto_server_module);

        if (*busy == NULL)
        {
            ctx->out_buf.pos = ctx->out_buf.start;
            ctx->out_buf.last = ctx->out_buf.start;
            njt_log_debug(NJT_LOG_DEBUG_STREAM, c->log, 0, "tcc send out ok!");
        }
        else
        {
            njt_log_debug(NJT_LOG_DEBUG_STREAM, c->log, 0, "tcc send out busy!");
        }
    }

    if (njt_handle_write_event(ev, 0) != NJT_OK)
    {
        return NJT_ERROR;
    }

    // njt_add_timer(ev, 5000);
    return NJT_OK;
}
static void
njt_stream_proto_server_write_handler(njt_event_t *ev)
{
    njt_int_t rc;
    njt_connection_t *c;
    njt_stream_session_t *s;

    rc = njt_stream_proto_server_write_data(ev);
    if (rc == NJT_ERROR)
    {
        c = ev->data;
        s = c->data;
        njt_stream_proto_server_del_session(s, NJT_STREAM_INTERNAL_SERVER_ERROR, 1);
    }
}
// add handler to pre-access
// otherwise, handler can't be add as part of config handler if proxy handler is involved.

static njt_int_t njt_stream_proto_server_init(njt_conf_t *cf)
{
    njt_stream_handler_pt *h;
    njt_stream_core_main_conf_t *cmcf;

    njt_log_debug(NJT_LOG_DEBUG_EVENT, njt_cycle->log, 0, "ngin proto_server init invoked");

    cmcf = njt_stream_conf_get_module_main_conf(cf, njt_stream_core_module);

    h = njt_array_push(&cmcf->phases[NJT_STREAM_ACCESS_PHASE].handlers);
    if (h == NULL)
    {
        return NJT_ERROR;
    }

    *h = njt_stream_proto_server_access_handler;

    h = njt_array_push(&cmcf->phases[NJT_STREAM_PREREAD_PHASE].handlers);
    if (h == NULL)
    {
        return NJT_ERROR;
    }

    *h = njt_stream_proto_server_preread_handler;

    h = njt_array_push(&cmcf->phases[NJT_STREAM_LOG_PHASE].handlers);
    if (h == NULL)
    {
        return NJT_ERROR;
    }

    *h = njt_stream_proto_server_log_handler;
    return NJT_OK;
}
int proto_server_sendto(tcc_stream_server_ctx *srv_ctx, tcc_str_t *receiver_session, char *data, size_t len)
{

    njt_str_t prefix = njt_string("/worker_pid_"); //  /worker_n/{topic_prefix}/{reg_key}/{data}，
    njt_str_t reg_key = njt_string("session");
    njt_str_t msg;
    njt_str_t *service; 

    tcc_stream_request_t *r = cli_local_find_by_session(srv_ctx, receiver_session);
    if (r != NULL)
    {
        return proto_server_send(r, data, len);
    }
    else
    {
        service = proto_server_get_service_name(srv_ctx);
        if (service != NULL)
        {   
            msg.len = len;
            msg.data = (u_char *)data;
            proto_server_send_mqtt(MSG_TYPE_1V1, srv_ctx, receiver_session, &prefix, service, &reg_key, &msg);
        }
    }

    return len;
}
int proto_server_send(tcc_stream_request_t *r, char *data, size_t len)
{

    njt_connection_t *c;
    njt_stream_proto_server_client_ctx_t *ctx;
    njt_chain_t *cl;
    njt_int_t rc;
    njt_stream_proto_server_srv_conf_t *sscf;
    njt_stream_session_t *s = r->s;
    // size_t size;

    c = s->connection;
    if (s->upstream != NULL)
    {
        rc = proto_server_proxy_send(r, 1, data, len);
        return rc;
    }
    sscf = njt_stream_get_module_srv_conf(s, njt_stream_proto_server_module);
    ctx = njt_stream_get_module_ctx(s, njt_stream_proto_server_module);
    if (ctx->r.status == TCC_SESSION_CLOSING)
    {
        return NJT_ERROR;
    }
    if (ctx->r.session_max_mem_size + len > sscf->session_max_mem_size)
    {
        len = sscf->session_max_mem_size - ctx->r.session_max_mem_size;
    }
    if (len > 0)
    {
        cl = njt_chain_get_free_buf(c->pool, &ctx->free);
        if (cl == NULL)
        {
            return NJT_ERROR;
        }

        // njt_memcpy(ctx->out_buf.last, data, size);

        cl->buf->tag = (njt_buf_tag_t)&njt_stream_proto_server_module;
        cl->buf->memory = 1;
        cl->buf->flush = 1;
        cl->buf->pos = njt_pcalloc(ctx->r.tcc_pool, len);
        if (cl->buf->pos == NULL)
        {
            return NJT_ERROR;
        }
        cl->buf->start = cl->buf->pos;
        cl->buf->end = cl->buf->pos + len;
        njt_memcpy(cl->buf->pos, data, len);
        cl->buf->last = cl->buf->pos + len;
        cl->buf->last_buf = 1;
        cl->next = ctx->out_chain;
        ctx->out_chain = cl;
        ctx->r.session_max_mem_size = ctx->r.session_max_mem_size + len;

        njt_stream_proto_server_write_data(c->write);
    }
    else
    {
        rc = len;
    }
    rc = len;
    return rc;
}
static int proto_server_send_mqtt(njt_int_t type, tcc_stream_server_ctx *srv_ctx, tcc_str_t *session, njt_str_t *prefix, njt_str_t *service, njt_str_t *reg_key, njt_str_t *data)
{ // send:/worker_all/0.0.0.0:80/session/0
    // send:/worker_pid_/0.0.0.0:80/session/0
    // njt_str_t prefix = njt_string("/worker_all");  //  /worker_n/{topic_prefix}/{reg_key}/{data}，
    // njt_str_t topic_prefix;  //= r->s->connection->listening->addr_text; //njt_string("/c/");
    // njt_str_t reg_key = njt_string("session/0");
    size_t topic_len;
    njt_str_t topic_name, content;
    njt_str_t node_info = njt_string("");
    tcc_str_t sys_session = njt_string("system");
    u_char *p;
    njt_pid_t  worker_pid;
    njt_stream_proto_session_node_t *node;
    njt_stream_proto_server_srv_conf_t *sscf;
    njt_stream_proto_session_shctx_t *sh_ctx;
    njt_slab_pool_t *shpool;
    
    njt_mqconf_conf_t *mqconf = (njt_mqconf_conf_t *)njt_get_conf(njt_cycle->conf_ctx, njt_mqconf_module);

    if (mqconf != NULL)
    {
        node_info = mqconf->node_name;
    }
    sscf = (njt_stream_proto_server_srv_conf_t *)((u_char *)srv_ctx - offsetof(njt_stream_proto_server_srv_conf_t, srv_ctx));
    sh_ctx = sscf->session_shm;
    shpool = sh_ctx->shpool;
    njt_shmtx_lock(&shpool->mutex);
    node = njt_stream_proto_find_session(srv_ctx, session);
    if (node == NULL && type != MSG_TYPE_BROADCAST)
    {   njt_shmtx_unlock(&shpool->mutex);
        return data->len;
    }
    worker_pid = node->worker_pid;
    njt_shmtx_unlock(&shpool->mutex);
    topic_len = prefix->len + service->len + reg_key->len + node_info.len + 20 + session->len;
    topic_name.data = njt_pcalloc(srv_ctx->tcc_pool, topic_len);
    if (topic_name.data == NULL)
    {
        return APP_ERROR;
    }
    if (type == MSG_TYPE_1V1)
    {
        p = njt_snprintf(topic_name.data, topic_len, "%V%d/%V/%V/%V/%V/\0", prefix,worker_pid, &node_info, reg_key, service, session);
    }
    else
    {
        if(session == NULL) {
            session = &sys_session;
        }
        p = njt_snprintf(topic_name.data, topic_len, "%V/%V/%V/%V/%V/%d\0", prefix, &node_info, reg_key, service, session, type);
    }
    topic_name.len = p - topic_name.data;
    if (type != MSG_TYPE_BROADCAST)
    {
        content.data = data->data;
        content.len = data->len;
    }
    else
    {
        content.data = data->data;
        content.len = data->len;
    }

    njt_log_debug(NJT_LOG_DEBUG_STREAM, njt_cycle->log, 0, "send mqtt=%V", &topic_name);
    njt_kv_sendmsg(&topic_name, &content, 0);

    njt_pfree(srv_ctx->tcc_pool, topic_name.data);
    return data->len;
}
int proto_server_send_broadcast(tcc_str_t *sender_session, tcc_stream_server_ctx *srv_ctx, char *data, size_t len)
{
    proto_server_send_local(srv_ctx, data, len);
    return proto_server_send_other_worker(sender_session, srv_ctx, data, len);
}
static njt_str_t *proto_server_get_service_name(tcc_stream_server_ctx *srv_ctx)
{
    njt_stream_proto_server_srv_conf_t *sscf;
    sscf = (njt_stream_proto_server_srv_conf_t *)((u_char *)srv_ctx - offsetof(njt_stream_proto_server_srv_conf_t, srv_ctx));

    return &sscf->zone_name;
}
static int proto_server_send_other_worker(tcc_str_t *sender_session, tcc_stream_server_ctx *srv_ctx, char *data, size_t len)
{
    njt_str_t msg;
    njt_str_t prefix = njt_string("/worker_all"); //  /worker_n/{topic_prefix}/{reg_key}/{data}，
    njt_str_t *service;                           //= r->s->connection->listening->addr_text; //njt_string("/c/");
    njt_str_t reg_key = njt_string("session");

    msg.data = (u_char *)data;
    msg.len = len;
    service = proto_server_get_service_name(srv_ctx);
    if (service != NULL)
    {
        proto_server_send_mqtt(MSG_TYPE_BROADCAST, srv_ctx, sender_session, &prefix, service, &reg_key, &msg);
    }
    return len;
}

static int proto_server_send_local(tcc_stream_server_ctx *srv_ctx, char *data, size_t len)
{

    tcc_stream_request_t **pr, *r;
    njt_uint_t i;
    njt_array_t *client_list;
    njt_int_t rc;

    client_list = srv_ctx->client_list;
    pr = client_list->elts;

    for (i = 0; i < client_list->nelts; i++)
    {
        r = pr[i];
        rc = proto_server_send(r, data, len);
        if (rc != (njt_int_t)len)
        {
            cli_close(r);
        }
    }
    return len;
}
int proto_server_send_others(tcc_str_t *sender_session, tcc_stream_server_ctx *srv_ctx, char *data, size_t len)
{
    tcc_stream_request_t *r = cli_local_find_by_session(srv_ctx, sender_session);
    proto_server_send_local_others(r, data, len);
    proto_server_send_other_worker(sender_session, srv_ctx, data, len);

    return len;
}
static int proto_server_send_local_others(tcc_stream_request_t *sender, char *data, size_t len)
{

    tcc_stream_request_t **pr, *r;
    njt_uint_t i;
    njt_int_t rc;
    njt_array_t *client_list;
    tcc_stream_server_ctx *srv_ctx = sender->tcc_server;

    client_list = srv_ctx->client_list;
    pr = client_list->elts;

    for (i = 0; i < client_list->nelts; i++)
    {
        r = pr[i];
        if (r != sender)
        {
            rc = proto_server_send(r, data, len);
            if (rc != (njt_int_t)len)
            {
                cli_close(r);
            }
        }
    }
    return len;
}

static njt_int_t njt_stream_proto_server_del_session(njt_stream_session_t *s, njt_uint_t code, njt_uint_t close_session)
{
    njt_array_t *client_list;
    njt_stream_proto_server_srv_conf_t *sscf;
    tcc_stream_request_t **pr, *r;
    njt_uint_t i;
    njt_stream_proto_server_client_ctx_t *ctx;
    njt_int_t rc, has;

    rc = NJT_ERROR;
    has = APP_FALSE;
    sscf = njt_stream_get_module_srv_conf(s, njt_stream_proto_server_module);
    ctx = njt_stream_get_module_ctx(s, njt_stream_proto_server_module);

    client_list = sscf->srv_ctx.client_list;
    pr = client_list->elts;
    for (i = 0; i < client_list->nelts; i++)
    {
        r = pr[i];
        if (r->s == s)
        {
            njt_array_delete_idx(client_list, i);
            if (ctx->timer.timer_set)
            {
                njt_del_timer(&ctx->timer);
            }
            njt_stream_proto_remove_client_hash(r->tcc_server, &r->session);
            njt_stream_proto_remove_session(r->tcc_server, &r->session);
            rc = NJT_OK;
            break;
        }
    }
    if (rc == NJT_OK && close_session == 1)
    {
        if (sscf->has_proto_message)
        {
            // has = sscf->has_proto_message(&ctx->r);
        }
        if (has == APP_TRUE && sscf->destroy_message)
        {
            sscf->destroy_message(&ctx->r);
        }
        if (ctx->wake.timer_set)
        {
            njt_del_timer(&ctx->wake);
        }

        if (s->upstream)
        {
            njt_stream_proto_finalize(s, code);
        }
        else
        {
            njt_stream_finalize_session(s, code);
        }
    }
    return NJT_OK;
}

void cli_close(tcc_stream_request_t *r)
{
    if (r != NULL)
    {
        r->status = TCC_SESSION_CLOSING;
    }
    return;
}

tcc_str_t cli_get_variable(tcc_stream_request_t *r, char *name)
{
    njt_conf_t conf;
    njt_uint_t var_index;
    njt_str_t var;
    njt_stream_variable_value_t *value;
    tcc_str_t ret_val = njt_string("");
    njt_stream_core_main_conf_t *cmcf;
    njt_uint_t i;
    njt_stream_variable_t *v;
    njt_stream_session_t *s = r->s;
    if (name == NULL)
    {
        return ret_val;
    }
    var.data = (u_char *)name;
    var.len = njt_strlen(name);

    cmcf = njt_stream_cycle_get_module_main_conf(njt_cycle, njt_stream_core_module);
    v = cmcf->variables.elts;
    for (i = 0; i < cmcf->variables.nelts; i++)
    {
        if (var.len != v[i].name.len || njt_strncasecmp(var.data, v[i].name.data, var.len) != 0)
        {
            continue;
        }

        break;
    }
    if (i == cmcf->variables.nelts)
    {
        return ret_val;
    }

    njt_memzero(&conf, sizeof(njt_conf_t));
    conf.pool = s->connection->pool;
    conf.temp_pool = s->connection->pool;
    conf.module_type = NJT_STREAM_MODULE;
    conf.cycle = (njt_cycle_t *)njt_cycle;
    conf.ctx = njt_get_conf(njt_cycle->conf_ctx, njt_stream_module);
    conf.log = njt_cycle->log;

    var_index = njt_stream_get_variable_index(&conf, &var);
    value = njt_stream_get_indexed_variable(s, var_index);
    if (value != NULL && value->not_found == 0)
    {
        ret_val.data = value->data;
        ret_val.len = value->len;
    }

    return ret_val;
}
size_t srv_get_client_num(tcc_stream_server_ctx *srv)
{
    njt_array_t *client_list;
    if (srv != NULL && srv->client_list != NULL)
    {
        client_list = srv->client_list;
        return client_list->nelts;
    }
    return 0; // tcc_stream_request_t *
}
tcc_stream_request_t *srv_get_client_index(tcc_stream_server_ctx *srv, size_t index)
{
    njt_array_t *client_list;
    tcc_stream_request_t **pr;
    if (srv != NULL && srv->client_list != NULL)
    {
        client_list = srv->client_list;
        if (index < client_list->nelts)
        {
            pr = client_list->elts;
            return pr[index];
        }
    }
    return NULL;
}

void *proto_malloc(void *ctx, int len)
{
    u_char **ptr;
    njt_pool_t *pool;
    if (ctx != NULL)
    {
        ptr = (u_char **)ctx;
        pool = (njt_pool_t *)*ptr;
        return njt_pcalloc(pool, len);
    }
    return NULL;
}
void proto_free(void *ctx, void *p)
{
    u_char **ptr;
    njt_pool_t *pool;
    if (ctx != NULL)
    {
        ptr = (u_char **)ctx;
        pool = (njt_pool_t *)*ptr;
        njt_pfree(pool, p);
    }
    return;
}
void *proto_realloc(void *ctx, void *p, int len)
{
    u_char **ptr;
    njt_pool_t *pool;
    if (ctx != NULL)
    {
        ptr = (u_char **)ctx;
        pool = (njt_pool_t *)*ptr;
        return njt_prealloc(pool, p, len);
    }
    return NULL;
}
int proto_server_send_upstream(tcc_stream_request_t *r, char *data, size_t len)
{
    njt_int_t rc;
    rc = proto_server_proxy_send(r, 0, data, len);
    return rc;
}
static int proto_server_proxy_send(tcc_stream_request_t *r, njt_uint_t from_upstream, char *data, size_t len)
{

    char *recv_action;
    size_t n;
    njt_chain_t *cl, **ll, **out;
    njt_connection_t *c, *pc, *src, *dst;
    njt_stream_upstream_t *u;
    njt_stream_session_t *s;
    njt_int_t rc;
    njt_stream_proto_server_client_ctx_t *ctx;
    njt_stream_proto_server_srv_conf_t *sscf;

    s = r->s;
    u = s->upstream;
    c = s->connection;
    if (u == NULL)
    {
        return 0;
    }
    pc = u->connected ? u->peer.connection : NULL;
    n = 0;
    sscf = njt_stream_get_module_srv_conf(s, njt_stream_proto_server_module);
    ctx = njt_stream_get_module_ctx(s, njt_stream_proto_server_module);
    if (from_upstream)
    {
        if (ctx->r.session_max_mem_size + len > sscf->session_max_mem_size)
        {
            len = sscf->session_max_mem_size - ctx->r.session_max_mem_size;
        }
        src = pc;
        dst = c;
        out = &u->downstream_out;
        recv_action = "proto_server_proxy_send from upstream";
    }
    else
    {
        if (ctx->r.session_up_max_mem_size + len > sscf->session_max_mem_size)
        {
            len = sscf->session_max_mem_size - ctx->r.session_up_max_mem_size;
        }
        src = c;
        dst = pc;
        out = &u->upstream_out;
        recv_action = "proto_server_proxy_send from client";
    }

    if (src != NULL)
    {

        c->log->action = recv_action;
        n = len;
        if (n > 0)
        {
            cl = njt_chain_get_free_buf(c->pool, &u->free);
            if (cl == NULL)
            {
                return NJT_ERROR;
            }
            cl->buf->pos = njt_pcalloc(ctx->r.tcc_pool, len);
            if (cl->buf->pos == NULL)
            {
                return NJT_ERROR;
            }

            if (from_upstream)
            {
                if (u->state->first_byte_time == (njt_msec_t)-1)
                {
                    u->state->first_byte_time = njt_current_msec - u->start_time;
                }
                ctx->r.session_max_mem_size = ctx->r.session_max_mem_size + len;
            }
            else
            {
                ctx->r.session_up_max_mem_size = ctx->r.session_up_max_mem_size + len;
            }
            for (ll = out; *ll; ll = &(*ll)->next)
            { /* void */
            }

            *ll = cl;
            njt_memcpy(cl->buf->pos, data, len);
            cl->buf->start = cl->buf->pos;
            cl->buf->end = cl->buf->pos + len;
            cl->buf->last = cl->buf->pos + len;
            cl->buf->tag = (njt_buf_tag_t)&njt_stream_proto_server_module;

            cl->buf->temporary = (n ? 1 : 0);
            cl->buf->last_buf = 0;
            cl->buf->flush = 1;
        }
    }
    c->log->action = "proto_server_proxy_send";
    if (dst)
    {
        if (njt_handle_write_event(dst->write, 0) != NJT_OK)
        {
            // njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return NJT_ERROR;
        }
        rc = njt_stream_proto_process(s, from_upstream, 1, 0);
        if (rc != NJT_OK)
        {

            if (ctx)
            {
                ctx->r.status = TCC_SESSION_CLOSING;
                return NJT_ERROR;
            }
        }
    }
    return n;
}

njt_int_t njt_stream_proto_server_init_upstream(njt_stream_session_t *s)
{
    njt_stream_proto_server_srv_conf_t *sscf;
    njt_stream_proto_server_client_ctx_t *ctx;
    u_char *p;
    size_t len, len2;
    tcc_str_t msg;
    njt_connection_t *c = s->connection;

    sscf = njt_stream_get_module_srv_conf(s, njt_stream_proto_server_module);
    if (sscf && sscf->message_handler != NULL)
    {
        ctx = njt_stream_get_module_ctx(s, njt_stream_proto_server_module);
        len = ctx->r.in_buf.end - ctx->r.in_buf.start;
        if (ctx->r.in_buf.start == NULL || len != sscf->buffer_size)
        {
            p = njt_pcalloc(c->pool, sscf->buffer_size);
            if (p == NULL)
            {
                return NJT_ERROR;
            }

            ctx->r.in_buf.start = p;
            ctx->r.in_buf.end = p + sscf->buffer_size;
            ctx->r.in_buf.pos = p;
            ctx->r.in_buf.last = p;
        }
        if (c->buffer != NULL)
        {
            len = c->buffer->last - c->buffer->pos;
            len2 = ctx->r.in_buf.end - ctx->r.in_buf.last;
            if (len2 >= len)
            {
                njt_memcpy(ctx->r.in_buf.last, c->buffer->pos, len);
                ctx->r.in_buf.last = ctx->r.in_buf.last + len;
                msg.data = ctx->r.in_buf.pos;
                msg.len = ctx->r.in_buf.last - ctx->r.in_buf.pos;
                sscf->message_handler(&ctx->r, &msg);
                njt_stream_proto_server_update_in_buf(&ctx->r.in_buf, ctx->r.used_len);
            }
            else
            {
                njt_log_error(NJT_LOG_INFO, c->log, 0, "stream proxy add preread buffer error!");
                return NJT_ERROR;
            }
        }
        return NJT_OK;
    }
    return NJT_DECLINED;
}

njt_int_t njt_stream_proto_server_process_proxy_message(njt_stream_session_t *s, njt_buf_t *b, njt_uint_t from_upstream)
{
    njt_stream_proto_server_srv_conf_t *sscf;
    njt_stream_proto_server_client_ctx_t *ctx;
    tcc_str_t msg;
    njt_int_t rc;
    njt_uint_t code;

    sscf = njt_stream_get_module_srv_conf(s, njt_stream_proto_server_module);
    ctx = njt_stream_get_module_ctx(s, njt_stream_proto_server_module);
    rc = NJT_OK;
    if (ctx != NULL)
    {
        msg.data = b->pos;
        msg.len = b->last - b->pos;
        if (msg.len == 0)
        {
            return NJT_OK;
        }
        ctx->r.used_len = 0;
        if (from_upstream)
        {
            if (sscf->upstream_message_handler != NULL)
            {
                rc = sscf->upstream_message_handler(&ctx->r, &msg);
            }
        }
        else
        {
            if (sscf->message_handler != NULL)
            {
                rc = sscf->message_handler(&ctx->r, &msg);
            }
        }
        if (rc == NJT_ERROR || ctx->r.status == TCC_SESSION_CLOSING)
        {
            code = NJT_STREAM_INTERNAL_SERVER_ERROR;
            goto end;
        }
        njt_stream_proto_server_update_in_buf((tcc_buf_t *)b, ctx->r.used_len);
    }
    return NJT_OK;
end:
    njt_stream_proto_server_del_session(s, code, 0);
    return NJT_ERROR;
}
tcc_int_t proto_get_peer_weight(void *peer)
{
    njt_stream_upstream_rr_peer_t *p = peer;
    return p->weight;
}
tcc_int_t proto_get_peer_conns(void *peer)
{
    njt_stream_upstream_rr_peer_t *p = peer;
    return p->conns;
}
tcc_uint_t proto_get_peer_fails(void *peer)
{
    njt_stream_upstream_rr_peer_t *p = peer;
    return p->fails;
}

void tcc_encode_base64(tcc_str_t *dst, tcc_str_t *src)
{
    njt_encode_base64((njt_str_t *)dst, (njt_str_t *)src);
}
void tcc_encode_base64url(tcc_str_t *dst, tcc_str_t *src)
{
    njt_encode_base64url((njt_str_t *)dst, (njt_str_t *)src);
}
tcc_int_t tcc_decode_base64(tcc_str_t *dst, tcc_str_t *src)
{
    return njt_decode_base64((njt_str_t *)dst, (njt_str_t *)src);
}
tcc_int_t tcc_decode_base64url(tcc_str_t *dst, tcc_str_t *src)
{
    return njt_decode_base64url((njt_str_t *)dst, (njt_str_t *)src);
}
void tcc_sha1_init(tcc_sha1_t *ctx)
{
    njt_sha1_init((njt_sha1_t *)ctx);
}
void tcc_sha1_update(tcc_sha1_t *ctx, const void *data, size_t size)
{
    njt_sha1_update((njt_sha1_t *)ctx, data, size);
}
void tcc_sha1_final(u_char result[20], tcc_sha1_t *ctx)
{
    njt_sha1_final(result, (njt_sha1_t *)ctx);
}

static char *
njt_stream_proto_pass(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_stream_proxy_srv_conf_t *pscf;

    njt_url_t u;
    njt_str_t *value, *url;
    njt_stream_complex_value_t cv;
    njt_stream_core_srv_conf_t *cscf;
    njt_stream_compile_complex_value_t ccv;
    njt_stream_proto_server_srv_conf_t *sscf = conf;

    pscf = njt_stream_conf_get_module_srv_conf(cf, njt_stream_proxy_module);
    if (pscf->upstream || pscf->upstream_value)
    {
        return "is duplicate";
    }

    cscf = njt_stream_conf_get_module_srv_conf(cf, njt_stream_core_module);

    cscf->handler = njt_stream_proto_handler;
    sscf->proto_pass_enabled = 1;
    value = cf->args->elts;

    url = &value[1];

    njt_memzero(&ccv, sizeof(njt_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = url;
    ccv.complex_value = &cv;

    if (njt_stream_compile_complex_value(&ccv) != NJT_OK)
    {
        return NJT_CONF_ERROR;
    }

    if (cv.lengths)
    {
        pscf->upstream_value = njt_palloc(cf->pool,
                                          sizeof(njt_stream_complex_value_t));
        if (pscf->upstream_value == NULL)
        {
            return NJT_CONF_ERROR;
        }

        *pscf->upstream_value = cv;

        return NJT_CONF_OK;
    }

    njt_memzero(&u, sizeof(njt_url_t));

    u.url = *url;
    u.no_resolve = 1;

    pscf->upstream = njt_stream_upstream_add(cf, &u, 0);
    if (pscf->upstream == NULL)
    {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}

static void njt_stream_proto_handler(njt_stream_session_t *s)
{
    u_char *p;
    njt_str_t *host;
    njt_uint_t i;
    njt_connection_t *c;
    njt_resolver_ctx_t *ctx, temp;
    njt_stream_upstream_t *u;
    njt_stream_core_srv_conf_t *cscf;
    njt_stream_proxy_srv_conf_t *pscf;
    njt_stream_upstream_srv_conf_t *uscf, **uscfp;
    njt_stream_upstream_main_conf_t *umcf;
    njt_stream_proxy_ctx_t *pctx; // openresty patch

    c = s->connection;

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_proxy_module);

    // openresty patch
    pctx = njt_palloc(c->pool, sizeof(njt_stream_proxy_ctx_t));
    if (pctx == NULL)
    {
        njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    pctx->connect_timeout = pscf->connect_timeout;
    pctx->timeout = pscf->timeout;

    njt_stream_set_ctx(s, pctx, njt_stream_proxy_module);
    // openresty patch end

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, c->log, 0,
                   "proxy connection handler");

    u = njt_pcalloc(c->pool, sizeof(njt_stream_upstream_t));
    if (u == NULL)
    {
        njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    s->upstream = u;

    s->log_handler = njt_stream_proto_log_error;

    u->requests = 1;

    u->peer.log = c->log;
    u->peer.log_error = NJT_ERROR_ERR;

    if (njt_stream_proto_set_local(s, u, pscf->local) != NJT_OK)
    {
        njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (pscf->socket_keepalive)
    {
        u->peer.so_keepalive = 1;
    }

    u->peer.type = c->type;
    u->start_sec = njt_time();

    c->write->handler = njt_stream_proto_downstream_handler;
    c->read->handler = njt_stream_proto_downstream_handler;

    s->upstream_states = njt_array_create(c->pool, 1,
                                          sizeof(njt_stream_upstream_state_t));
    if (s->upstream_states == NULL)
    {
        njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    p = njt_pnalloc(c->pool, pscf->buffer_size);
    if (p == NULL)
    {
        njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    u->downstream_buf.start = p;
    u->downstream_buf.end = p + pscf->buffer_size;
    u->downstream_buf.pos = p;
    u->downstream_buf.last = p;

    if (c->read->ready)
    {
        njt_post_event(c->read, &njt_posted_events);
    }

    if (pscf->upstream_value)
    {
        if (njt_stream_proto_eval(s, pscf) != NJT_OK)
        {
            njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (u->resolved == NULL)
    {
#if (NJT_STREAM_FTP_PROXY)
        if (NJT_OK != njt_stream_ftp_proxy_replace_upstream(s, &uscf))
        {
            uscf = pscf->upstream;
        }
#else
        uscf = pscf->upstream;
#endif
    }
    else
    {

#if (NJT_STREAM_SSL)
        u->ssl_name = u->resolved->host;
#endif

        host = &u->resolved->host;

        umcf = njt_stream_get_module_main_conf(s, njt_stream_upstream_module);

        uscfp = umcf->upstreams.elts;

        for (i = 0; i < umcf->upstreams.nelts; i++)
        {

            uscf = uscfp[i];

            if (uscf->host.len == host->len && ((uscf->port == 0 && u->resolved->no_port) || uscf->port == u->resolved->port) && njt_strncasecmp(uscf->host.data, host->data, host->len) == 0)
            {
                goto found;
            }
        }

        if (u->resolved->sockaddr)
        {

            if (u->resolved->port == 0 && u->resolved->sockaddr->sa_family != AF_UNIX)
            {
                njt_log_error(NJT_LOG_ERR, c->log, 0,
                              "no port in upstream \"%V\"", host);
                njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
                return;
            }

            if (njt_stream_upstream_create_round_robin_peer(s, u->resolved) != NJT_OK)
            {
                njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
                return;
            }

            njt_stream_proto_connect(s);

            return;
        }

        if (u->resolved->port == 0)
        {
            njt_log_error(NJT_LOG_ERR, c->log, 0,
                          "no port in upstream \"%V\"", host);
            njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        temp.name = *host;

        cscf = njt_stream_get_module_srv_conf(s, njt_stream_core_module);

        ctx = njt_resolve_start(cscf->resolver, &temp);
        if (ctx == NULL)
        {
            njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        if (ctx == NJT_NO_RESOLVER)
        {
            njt_log_error(NJT_LOG_ERR, c->log, 0,
                          "no resolver defined to resolve %V", host);
            njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        ctx->name = *host;
        ctx->handler = njt_stream_proto_resolve_handler;
        ctx->data = s;
        ctx->timeout = cscf->resolver_timeout;

        u->resolved->ctx = ctx;

        if (njt_resolve_name(ctx) != NJT_OK)
        {
            u->resolved->ctx = NULL;
            njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        return;
    }

found:

    if (uscf == NULL)
    {
        njt_log_error(NJT_LOG_ALERT, c->log, 0, "no upstream configuration");
        njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    u->upstream = uscf;

#if (NJT_STREAM_SSL)
    u->ssl_name = uscf->host;
#endif

    if (uscf->peer.init(s, uscf) != NJT_OK)
    {
        njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    u->peer.start_time = njt_current_msec;

    if (pscf->next_upstream_tries && u->peer.tries > pscf->next_upstream_tries)
    {
        u->peer.tries = pscf->next_upstream_tries;
    }

    njt_stream_proto_connect(s);
}

static void
njt_stream_proto_resolve_handler(njt_resolver_ctx_t *ctx)
{
    njt_stream_session_t *s;
    njt_stream_upstream_t *u;
    njt_stream_proxy_srv_conf_t *pscf;
    njt_stream_upstream_resolved_t *ur;

    s = ctx->data;

    u = s->upstream;
    ur = u->resolved;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream upstream resolve");

    if (ctx->state)
    {
        njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                      "%V could not be resolved (%i: %s)",
                      &ctx->name, ctx->state,
                      njt_resolver_strerror(ctx->state));

        njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ur->naddrs = ctx->naddrs;
    ur->addrs = ctx->addrs;

#if (NJT_DEBUG)
    {
        u_char text[NJT_SOCKADDR_STRLEN];
        njt_str_t addr;
        njt_uint_t i;

        addr.data = text;

        for (i = 0; i < ctx->naddrs; i++)
        {
            addr.len = njt_sock_ntop(ur->addrs[i].sockaddr, ur->addrs[i].socklen,
                                     text, NJT_SOCKADDR_STRLEN, 0);

            njt_log_debug1(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                           "name was resolved to %V", &addr);
        }
    }
#endif

    if (njt_stream_upstream_create_round_robin_peer(s, ur) != NJT_OK)
    {
        njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    njt_resolve_name_done(ctx);
    ur->ctx = NULL;

    u->peer.start_time = njt_current_msec;

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_proxy_module);

    if (pscf->next_upstream_tries && u->peer.tries > pscf->next_upstream_tries)
    {
        u->peer.tries = pscf->next_upstream_tries;
    }

    njt_stream_proto_connect(s);
}

static void
njt_stream_proto_downstream_handler(njt_event_t *ev)
{
    njt_stream_proto_process_connection(ev, ev->write);
}

static void
njt_stream_proto_process_connection(njt_event_t *ev, njt_uint_t from_upstream)
{
    njt_connection_t *c, *pc;
    njt_log_handler_pt handler;
    njt_stream_session_t *s;
    njt_stream_upstream_t *u;
    njt_stream_proxy_srv_conf_t *pscf;
    njt_stream_proxy_ctx_t *ctx; // openresty patch

    c = ev->data;
    s = c->data;
    u = s->upstream;

    if (c->close)
    {
        njt_log_error(NJT_LOG_INFO, c->log, 0, "shutdown timeout");
        njt_stream_proto_finalize(s, NJT_STREAM_OK);
        return;
    }

    ctx = njt_stream_get_module_ctx(s, njt_stream_proxy_module); // openresty patch

    c = s->connection;
    pc = u->peer.connection;

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_proxy_module);

    if (ev->timedout)
    {
        ev->timedout = 0;

        if (ev->delayed)
        {
            ev->delayed = 0;

            if (!ev->ready)
            {
                if (njt_handle_read_event(ev, 0) != NJT_OK)
                {
                    njt_stream_proto_finalize(s,
                                              NJT_STREAM_INTERNAL_SERVER_ERROR);
                    return;
                }

                if (u->connected && !c->read->delayed && !pc->read->delayed)
                {
                    // njt_add_timer(c->write, pscf->timeout); openresty patch
                    njt_add_timer(c->write, ctx->timeout); // openresty patch
                }

                return;
            }
        }
        else
        {
            if (s->connection->type == SOCK_DGRAM)
            {

                if (pscf->responses == NJT_MAX_INT32_VALUE || (u->responses >= pscf->responses * u->requests))
                {

                    /*
                     * successfully terminate timed out UDP session
                     * if expected number of responses was received
                     */

                    handler = c->log->handler;
                    c->log->handler = NULL;

                    njt_log_error(NJT_LOG_INFO, c->log, 0,
                                  "udp timed out"
                                  ", packets from/to client:%ui/%ui"
                                  ", bytes from/to client:%O/%O"
                                  ", bytes from/to upstream:%O/%O",
                                  u->requests, u->responses,
                                  s->received, c->sent, u->received,
                                  pc ? pc->sent : 0);

                    c->log->handler = handler;

                    njt_stream_proto_finalize(s, NJT_STREAM_OK);
                    return;
                }

                njt_connection_error(pc, NJT_ETIMEDOUT, "upstream timed out");

                pc->read->error = 1;

                njt_stream_proto_finalize(s, NJT_STREAM_BAD_GATEWAY);

                return;
            }

            njt_connection_error(c, NJT_ETIMEDOUT, "connection timed out");

            njt_stream_proto_finalize(s, NJT_STREAM_OK);

            return;
        }
    }
    else if (ev->delayed)
    {

        njt_log_debug0(NJT_LOG_DEBUG_STREAM, c->log, 0,
                       "stream connection delayed");

        if (njt_handle_read_event(ev, 0) != NJT_OK)
        {
            njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        }

        return;
    }

    if (from_upstream && !u->connected)
    {
        return;
    }

    njt_stream_proto_process(s, from_upstream, ev->write, 1);
}

static njt_int_t njt_stream_proto_process(njt_stream_session_t *s, njt_uint_t from_upstream,
                                          njt_uint_t do_write, njt_uint_t internal)
{
    char *recv_action, *send_action;
    off_t *received, limit;
    size_t size, limit_rate;
    ssize_t n;
    njt_buf_t *b;
    njt_int_t rc;
    njt_uint_t flags, *packets;
    njt_msec_t delay;
    njt_chain_t *cl, **ll, **out, **busy;
    njt_connection_t *c, *pc, *src, *dst;
    njt_log_handler_pt handler;
    njt_stream_upstream_t *u;
    njt_stream_proxy_srv_conf_t *pscf;
    njt_stream_proxy_ctx_t *ctx; // openresty patch
#if (NJT_STREAM_PROTOCOL_SERVER_MODULE)
    njt_stream_proto_server_srv_conf_t *sscf_proto;
    njt_stream_proto_server_client_ctx_t *proto_ctx;
    size_t avail_size;
    njt_buf_t *senb;
    sscf_proto = njt_stream_get_module_srv_conf(s, njt_stream_proto_server_module);
    proto_ctx = njt_stream_get_module_ctx(s, njt_stream_proto_server_module);
#endif

    ctx = njt_stream_get_module_ctx(s, njt_stream_proxy_module); // openresty patch

    u = s->upstream;

    c = s->connection;
    pc = u->connected ? u->peer.connection : NULL;

    if (c->type == SOCK_DGRAM && (njt_terminate || njt_exiting))
    {

        /* socket is already closed on worker shutdown */

        handler = c->log->handler;
        c->log->handler = NULL;

        njt_log_error(NJT_LOG_INFO, c->log, 0, "disconnected on shutdown");

        c->log->handler = handler;
        if (internal == 1)
            njt_stream_proto_finalize(s, NJT_STREAM_OK);
        return NJT_STREAM_OK;
    }

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_proxy_module);

    if (from_upstream)
    {
        src = pc;
        dst = c;
        b = &u->upstream_buf;
#if (NJT_STREAM_PROTOCOL_SERVER_MODULE)
        senb = b;
        if (sscf_proto && proto_ctx && sscf_proto->upstream_message_handler)
        {
            b = &proto_ctx->out_buf;
        }

#endif
        limit_rate = u->download_rate;
        received = &u->received;
        packets = &u->responses;
        out = &u->downstream_out;
        busy = &u->downstream_busy;
        recv_action = "proto_proxying and reading from upstream";
        send_action = "proto_proxying and sending to client";
    }
    else
    {
        src = c;
        dst = pc;
        b = &u->downstream_buf;
#if (NJT_STREAM_PROTOCOL_SERVER_MODULE)
        senb = b;
        if (sscf_proto && proto_ctx && sscf_proto->message_handler)
        {
            b = (njt_buf_t *)&proto_ctx->r.in_buf; //
        }

#endif
        limit_rate = u->upload_rate;
        received = &s->received;
        packets = &u->requests;
        out = &u->upstream_out;
        busy = &u->upstream_busy;
        recv_action = "proto_proxying and reading from client";
        send_action = "proto_proxying and sending to upstream";
    }

    for (;;)
    {

        if (do_write && dst)
        {

            if (*out || *busy || dst->buffered)
            {
                c->log->action = send_action;

                rc = njt_proto_write_filter(s, *out, from_upstream);

                if (rc == NJT_ERROR)
                {
                    if (internal == 1)
                        njt_stream_proto_finalize(s, NJT_STREAM_OK);
                    return NJT_STREAM_OK;
                }

                njt_chain_update_chains(c->pool, &u->free, busy, out,
                                        (njt_buf_tag_t)&njt_stream_proto_server_module);

                if (*busy == NULL)
                {
#if (NJT_STREAM_PROTOCOL_SERVER_MODULE)
                    if (b == senb)
                    {
                        senb->pos = senb->start;
                        senb->last = senb->start;
                    }
#else
                    b->pos = b->start;
                    b->last = b->start;
#endif
                }
            }
        }

        size = b->end - b->last;
#if (NJT_STREAM_PROTOCOL_SERVER_MODULE)
        if (internal == 0)
        {
            return NJT_OK;
        }
        if (b == senb)
        {
            avail_size = senb->end - senb->last;
        }
        else
        {
            if (from_upstream)
            {
                avail_size = sscf_proto->session_max_mem_size - proto_ctx->r.session_max_mem_size;
                // njt_log_debug2(NJT_LOG_DEBUG, c->log, 0,"proto_ctx->r.session_max_mem_size=%d,tcc have client=%d!",proto_ctx->r.session_max_mem_size,avail_size);
            }
            else
            {
                avail_size = sscf_proto->session_max_mem_size - proto_ctx->r.session_up_max_mem_size;
            }
        }

        size = (size > avail_size) ? avail_size : size;
#endif
        if (size && src != NULL && src->read->ready && !src->read->delayed)
        {

            if (limit_rate)
            {
                limit = (off_t)limit_rate * (njt_time() - u->start_sec + 1) - *received;

                if (limit <= 0)
                {
                    src->read->delayed = 1;
                    delay = (njt_msec_t)(-limit * 1000 / limit_rate + 1);
                    njt_add_timer(src->read, delay);
                    break;
                }

                if (c->type == SOCK_STREAM && (off_t)size > limit)
                {
                    size = (size_t)limit;
                }
            }

            c->log->action = recv_action;

            n = src->recv(src, b->last, size);

            if (n == NJT_AGAIN)
            {
                break;
            }

            if (n == NJT_ERROR)
            {
                src->read->eof = 1;
                n = 0;
            }

            if (n >= 0)
            {
#ifdef NJT_STREAM_FTP_PROXY
                // if ftp_proxy, need replace data port
                if (from_upstream)
                {
                    njt_stream_ftp_proxy_filter_pasv(s, b->last, &n);
                }
#endif

                if (limit_rate)
                {
                    delay = (njt_msec_t)(n * 1000 / limit_rate);

                    if (delay > 0)
                    {
                        src->read->delayed = 1;
                        njt_add_timer(src->read, delay);
                    }
                }

                if (from_upstream)
                {
                    if (u->state->first_byte_time == (njt_msec_t)-1)
                    {
                        u->state->first_byte_time = njt_current_msec - u->start_time;
                    }
                }
#if (NJT_STREAM_PROTOCOL_SERVER_MODULE)
                if (proto_ctx == NULL || (sscf_proto->upstream_message_handler == NULL && from_upstream == 1) || (sscf_proto->message_handler == NULL && from_upstream == 0))
                {
#endif
                    for (ll = out; *ll; ll = &(*ll)->next)
                    { /* void */
                    }

                    cl = njt_chain_get_free_buf(c->pool, &u->free);
                    if (cl == NULL)
                    {
                        if (internal == 1)
                            njt_stream_proto_finalize(s,
                                                      NJT_STREAM_INTERNAL_SERVER_ERROR);
                        return NJT_STREAM_INTERNAL_SERVER_ERROR;
                    }

                    *ll = cl;

                    cl->buf->pos = b->last;
                    cl->buf->last = b->last + n;
                    cl->buf->tag = (njt_buf_tag_t)&njt_stream_proto_server_module;

                    cl->buf->temporary = (n ? 1 : 0);
                    cl->buf->last_buf = src->read->eof;
                    cl->buf->flush = !src->read->eof;
                    do_write = 1;
                    (*packets)++;
                    *received += n;
                    b->last += n;
#if (NJT_STREAM_PROTOCOL_SERVER_MODULE)
                }
                else
                {
                    (*packets)++;
                    *received += n;
                    b->last += n;
                    do_write = 1;
                    rc = njt_stream_proto_server_process_proxy_message(s, b, from_upstream);
                    if (rc == NJT_ERROR)
                    {
                        break;
                    }
                }
#endif
                continue;
            }
        }

        break;
    }

    c->log->action = "proto_proxying connection";

    if (njt_stream_proto_test_finalize(s, from_upstream) == NJT_OK)
    {
        return NJT_OK;
    }
    if (src == NULL || src->read == NULL)
    {
        njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                      "src or src->read is null");
        return NJT_OK;
    }
    flags = src->read->eof ? NJT_CLOSE_EVENT : 0;

    if (njt_handle_read_event(src->read, flags) != NJT_OK)
    {
        if (internal == 1)
            njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return NJT_STREAM_INTERNAL_SERVER_ERROR;
    }

    if (dst)
    {

        if (dst->type == SOCK_STREAM && pscf->half_close && src != NULL && src->read->eof && !u->half_closed && !dst->buffered)
        {

            if (njt_shutdown_socket(dst->fd, NJT_WRITE_SHUTDOWN) == -1)
            {
                njt_connection_error(c, njt_socket_errno,
                                     njt_shutdown_socket_n " failed");
                if (internal == 1)
                    njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
                return NJT_STREAM_INTERNAL_SERVER_ERROR;
            }

            u->half_closed = 1;
            njt_log_debug1(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                           "stream proxy %s socket shutdown",
                           from_upstream ? "client" : "upstream");
        }

        if (njt_handle_write_event(dst->write, 0) != NJT_OK)
        {
            if (internal == 1)
                njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return NJT_STREAM_INTERNAL_SERVER_ERROR;
        }

        if (!c->read->delayed && !pc->read->delayed)
        {
            // njt_add_timer(c->write, pscf->timeout); openresty patch
            njt_add_timer(c->write, ctx->timeout); // openresty patch
        }
        else if (c->write->timer_set)
        {
            njt_del_timer(c->write);
        }
    }
    return NJT_OK;
}

static void
njt_stream_proto_connect(njt_stream_session_t *s)
{
    njt_int_t rc;
    njt_connection_t *c, *pc;
    njt_stream_upstream_t *u;
    njt_stream_proxy_srv_conf_t *pscf;
    njt_stream_proxy_ctx_t *ctx; // openresty patch
#if (NJT_STREAM_PROTOCOL_V2)
    njt_flag_t flag;
    njt_stream_variable_value_t *value;
    njt_stream_proxy_protocol_tlv_srv_conf_t *scf = njt_stream_get_module_srv_conf(s, njt_stream_proxy_protocol_tlv_module);
    flag = NJT_CONF_UNSET;
    if (scf != NULL && scf->var_index != NJT_CONF_UNSET_UINT)
    {
        value = njt_stream_get_indexed_variable(s, scf->var_index);
        if (value != NULL && value->not_found == 0 && value->len == 1 && value->data[0] == '1')
        {
            flag = 1;
        }
        else
        {
            flag = 0;
        }
    }
#endif

    c = s->connection;

    c->log->action = "connecting to upstream";

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_proxy_module);

    ctx = njt_stream_get_module_ctx(s, njt_stream_proxy_module); // openresty patch

    u = s->upstream;

    u->connected = 0;
    u->proxy_protocol = pscf->proxy_protocol;
#if (NJT_STREAM_PROTOCOL_V2)
    u->proxy_protocol = (flag != NJT_CONF_UNSET ? flag : pscf->proxy_protocol);
#endif

    if (u->state)
    {
        u->state->response_time = njt_current_msec - u->start_time;
    }

    u->state = njt_array_push(s->upstream_states);
    if (u->state == NULL)
    {
        njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    njt_memzero(u->state, sizeof(njt_stream_upstream_state_t));

    u->start_time = njt_current_msec;

    u->state->connect_time = (njt_msec_t)-1;
    u->state->first_byte_time = (njt_msec_t)-1;
    u->state->response_time = (njt_msec_t)-1;

    rc = njt_event_connect_peer(&u->peer);

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0, "proxy connect: %i", rc);

    if (rc == NJT_ERROR)
    {
        njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    // openresy patch
    if (rc >= NJT_STREAM_SPECIAL_RESPONSE)
    {
        njt_stream_proto_finalize(s, rc);
        return;
    }
    // openresy patch end

    u->state->peer = u->peer.name;

    if (rc == NJT_BUSY)
    {
        njt_log_error(NJT_LOG_ERR, c->log, 0, "no live upstreams");
        njt_stream_proto_finalize(s, NJT_STREAM_BAD_GATEWAY);
        return;
    }

    if (rc == NJT_DECLINED)
    {
        njt_stream_proto_next_upstream(s);
        return;
    }

    /* rc == NJT_OK || rc == NJT_AGAIN || rc == NJT_DONE */

    pc = u->peer.connection;

    pc->data = s;
    pc->log = c->log;
    pc->pool = c->pool;
    pc->read->log = c->log;
    pc->write->log = c->log;

    if (rc != NJT_AGAIN)
    {
        njt_stream_proto_init_upstream(s);
        return;
    }

    pc->read->handler = njt_stream_proto_connect_handler;
    pc->write->handler = njt_stream_proto_connect_handler;

    // njt_add_timer(pc->write, pscf->connect_timeout); openresty patch
    njt_add_timer(pc->write, ctx->connect_timeout); // openresty patch
}

static void
njt_stream_proto_connect_handler(njt_event_t *ev)
{
    njt_connection_t *c;
    njt_stream_session_t *s;

    c = ev->data;
    s = c->data;

    if (ev->timedout)
    {
        njt_log_error(NJT_LOG_ERR, c->log, NJT_ETIMEDOUT, "upstream timed out");
        njt_stream_proto_next_upstream(s);
        return;
    }

    njt_del_timer(c->write);

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, c->log, 0,
                   "stream proxy connect upstream");

    if (njt_stream_proto_test_connect(c) != NJT_OK)
    {
        njt_stream_proto_next_upstream(s);
        return;
    }

    njt_stream_proto_init_upstream(s);
}

static void
njt_stream_proto_init_upstream(njt_stream_session_t *s)
{
    u_char *p;
    njt_chain_t *cl;
    njt_connection_t *c, *pc;
    njt_log_handler_pt handler;
    njt_stream_upstream_t *u;
    njt_stream_core_srv_conf_t *cscf;
    njt_stream_proxy_srv_conf_t *pscf;
#if (NJT_STREAM_PROTOCOL_SERVER_MODULE)
    njt_int_t rc;

#endif

    u = s->upstream;
    pc = u->peer.connection;

    cscf = njt_stream_get_module_srv_conf(s, njt_stream_core_module);

    if (pc->type == SOCK_STREAM && cscf->tcp_nodelay && njt_tcp_nodelay(pc) != NJT_OK)
    {
        njt_stream_proto_next_upstream(s);
        return;
    }

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_proxy_module);

#if (NJT_STREAM_SSL)

    if (pc->type == SOCK_STREAM && pscf->ssl_enable)
    {

        if (u->proxy_protocol)
        {
            if (njt_stream_proto_send_proxy_protocol(s) != NJT_OK)
            {
                return;
            }

            u->proxy_protocol = 0;
        }

        if (pc->ssl == NULL)
        {
            njt_stream_proto_ssl_init_connection(s);
            return;
        }
    }

#endif

    c = s->connection;

    if (c->log->log_level >= NJT_LOG_INFO)
    {
        njt_str_t str;
        u_char addr[NJT_SOCKADDR_STRLEN];

        str.len = NJT_SOCKADDR_STRLEN;
        str.data = addr;

        if (njt_connection_local_sockaddr(pc, &str, 1) == NJT_OK)
        {
            handler = c->log->handler;
            c->log->handler = NULL;

            njt_log_error(NJT_LOG_INFO, c->log, 0,
                          "%sproxy %V connected to %V",
                          pc->type == SOCK_DGRAM ? "udp " : "",
                          &str, u->peer.name);

            c->log->handler = handler;
        }
    }

    u->state->connect_time = njt_current_msec - u->start_time;

    if (u->peer.notify)
    {
        u->peer.notify(&u->peer, u->peer.data,
                       NJT_STREAM_UPSTREAM_NOTIFY_CONNECT);
    }

    if (u->upstream_buf.start == NULL)
    {
        p = njt_pnalloc(c->pool, pscf->buffer_size);
        if (p == NULL)
        {
            njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        u->upstream_buf.start = p;
        u->upstream_buf.end = p + pscf->buffer_size;
        u->upstream_buf.pos = p;
        u->upstream_buf.last = p;
    }
#if (NJT_STREAM_PROTOCOL_SERVER_MODULE)
    rc = njt_stream_proto_server_init_upstream(s);
    if (rc == NJT_OK)
    {
        goto next;
    }
    else if (rc == NJT_ERROR)
    {
        njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }
#endif
    if (c->buffer && c->buffer->pos <= c->buffer->last)
    {
        njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0,
                       "stream proxy add preread buffer: %uz",
                       c->buffer->last - c->buffer->pos);
        cl = njt_chain_get_free_buf(c->pool, &u->free);
        if (cl == NULL)
        {
            njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        *cl->buf = *c->buffer;

        cl->buf->tag = (njt_buf_tag_t)&njt_stream_proto_server_module;
        cl->buf->temporary = (cl->buf->pos == cl->buf->last) ? 0 : 1;
        cl->buf->flush = 1;

        cl->next = u->upstream_out;
        u->upstream_out = cl;
    }
next:
    if (u->proxy_protocol)
    {
        njt_log_debug0(NJT_LOG_DEBUG_STREAM, c->log, 0,
                       "stream proxy add PROXY protocol header");

        cl = njt_chain_get_free_buf(c->pool, &u->free);
        if (cl == NULL)
        {
            njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        p = njt_pnalloc(c->pool, NJT_PROXY_PROTOCOL_MAX_HEADER);
        if (p == NULL)
        {
            njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        cl->buf->pos = p;

        p = njt_proxy_protocol_v2_write(s, p, p + NJT_PROXY_PROTOCOL_MAX_HEADER);
        if (p == NULL)
        {
            njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        cl->buf->last = p;
        cl->buf->temporary = 1;
        cl->buf->flush = 0;
        cl->buf->last_buf = 0;
        cl->buf->tag = (njt_buf_tag_t)&njt_stream_proto_server_module;

        cl->next = u->upstream_out;
        u->upstream_out = cl;

        u->proxy_protocol = 0;
    }

    u->upload_rate = njt_stream_complex_value_size(s, pscf->upload_rate, 0);
    u->download_rate = njt_stream_complex_value_size(s, pscf->download_rate, 0);

    u->connected = 1;

    pc->read->handler = njt_stream_proto_upstream_handler;
    pc->write->handler = njt_stream_proto_upstream_handler;

    if (pc->read->ready)
    {
        njt_post_event(pc->read, &njt_posted_events);
    }

    njt_stream_proto_process(s, 0, 1, 1);
}

static void
njt_stream_proto_upstream_handler(njt_event_t *ev)
{
    njt_stream_proto_process_connection(ev, !ev->write);
}

static void
njt_stream_proto_ssl_init_connection(njt_stream_session_t *s)
{
    njt_int_t rc;
    njt_connection_t *pc;
    njt_stream_upstream_t *u;
    njt_stream_proxy_srv_conf_t *pscf;
    njt_stream_proxy_ctx_t *ctx; // openresy patch

    ctx = njt_stream_get_module_ctx(s, njt_stream_proxy_module); // openresty patch

    u = s->upstream;

    pc = u->peer.connection;

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_proxy_module);

#if (NJT_HAVE_NTLS)
    if (pscf->ssl_ntls)
    {

        SSL_CTX_set_ssl_version(pscf->ssl->ctx, NTLS_method());
        SSL_CTX_set_cipher_list(pscf->ssl->ctx,
                                (char *)pscf->ssl_ciphers.data);
        SSL_CTX_enable_ntls(pscf->ssl->ctx);
    }
#endif

    if (njt_ssl_create_connection(pscf->ssl, pc, NJT_SSL_BUFFER | NJT_SSL_CLIENT) != NJT_OK)
    {
        njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (pscf->ssl_server_name || pscf->ssl_verify)
    {
        if (njt_stream_proto_ssl_name(s) != NJT_OK)
        {
            njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

#if (NJT_STREAM_MULTICERT)

    if (pscf->ssl_certificate_values)
    {
        if (njt_stream_proto_ssl_certificates(s) != NJT_OK)
        {
            njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

#else

    if (pscf->ssl_certificate && pscf->ssl_certificate->value.len && (pscf->ssl_certificate->lengths || pscf->ssl_certificate_key->lengths))
    {
        if (njt_stream_proto_ssl_certificate(s) != NJT_OK)
        {
            njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

#endif

    if (pscf->ssl_session_reuse)
    {
        pc->ssl->save_session = njt_stream_proto_ssl_save_session;

        if (u->peer.set_session(&u->peer, u->peer.data) != NJT_OK)
        {
            njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    s->connection->log->action = "SSL handshaking to upstream";

    rc = njt_ssl_handshake(pc);

    if (rc == NJT_AGAIN)
    {

        if (!pc->write->timer_set)
        {
            // njt_add_timer(pc->write, pscf->connect_timeout); openresty patch
            njt_add_timer(pc->write, ctx->connect_timeout); // openresty patch
        }

        pc->ssl->handler = njt_stream_proto_ssl_handshake;
        return;
    }

    njt_stream_proto_ssl_handshake(pc);
}

static u_char *
njt_stream_proto_log_error(njt_log_t *log, u_char *buf, size_t len)
{
    u_char *p;
    njt_connection_t *pc;
    njt_stream_session_t *s;
    njt_stream_upstream_t *u;

    s = log->data;

    u = s->upstream;

    p = buf;

    if (u->peer.name)
    {
        p = njt_snprintf(p, len, ", upstream: \"%V\"", u->peer.name);
        len -= p - buf;
    }

    pc = u->peer.connection;

    p = njt_snprintf(p, len,
                     ", bytes from/to client:%O/%O"
                     ", bytes from/to upstream:%O/%O",
                     s->received, s->connection->sent,
                     u->received, pc ? pc->sent : 0);

    return p;
}

static njt_int_t
njt_stream_proto_set_local(njt_stream_session_t *s, njt_stream_upstream_t *u,
                           njt_stream_upstream_local_t *local)
{
    njt_int_t rc;
    njt_str_t val;
    njt_addr_t *addr;

    if (local == NULL)
    {
        u->peer.local = NULL;
        return NJT_OK;
    }

#if (NJT_HAVE_TRANSPARENT_PROXY)
    u->peer.transparent = local->transparent;
#endif

    if (local->value == NULL)
    {
        u->peer.local = local->addr;
        return NJT_OK;
    }

    if (njt_stream_complex_value(s, local->value, &val) != NJT_OK)
    {
        return NJT_ERROR;
    }

    if (val.len == 0)
    {
        return NJT_OK;
    }

    addr = njt_palloc(s->connection->pool, sizeof(njt_addr_t));
    if (addr == NULL)
    {
        return NJT_ERROR;
    }

    rc = njt_parse_addr_port(s->connection->pool, addr, val.data, val.len);
    if (rc == NJT_ERROR)
    {
        return NJT_ERROR;
    }

    if (rc != NJT_OK)
    {
        njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                      "invalid local address \"%V\"", &val);
        return NJT_OK;
    }

    addr->name = val;
    u->peer.local = addr;

    return NJT_OK;
}
static njt_int_t
njt_stream_proto_eval(njt_stream_session_t *s,
                      njt_stream_proxy_srv_conf_t *pscf)
{
    njt_str_t host;
    njt_url_t url;
    njt_stream_upstream_t *u;

    if (njt_stream_complex_value(s, pscf->upstream_value, &host) != NJT_OK)
    {
        return NJT_ERROR;
    }

    njt_memzero(&url, sizeof(njt_url_t));

    url.url = host;
    url.no_resolve = 1;

    if (njt_parse_url(s->connection->pool, &url) != NJT_OK)
    {
        if (url.err)
        {
            njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                          "%s in upstream \"%V\"", url.err, &url.url);
        }

        return NJT_ERROR;
    }

    u = s->upstream;

    u->resolved = njt_pcalloc(s->connection->pool,
                              sizeof(njt_stream_upstream_resolved_t));
    if (u->resolved == NULL)
    {
        return NJT_ERROR;
    }

    if (url.addrs)
    {
        u->resolved->sockaddr = url.addrs[0].sockaddr;
        u->resolved->socklen = url.addrs[0].socklen;
        u->resolved->name = url.addrs[0].name;
        u->resolved->naddrs = 1;
    }

    u->resolved->host = url.host;
    u->resolved->port = url.port;
    u->resolved->no_port = url.no_port;

    return NJT_OK;
}

static njt_int_t
njt_stream_proto_test_finalize(njt_stream_session_t *s,
                               njt_uint_t from_upstream)
{
    njt_connection_t *c, *pc;
    njt_log_handler_pt handler;
    njt_stream_upstream_t *u;
    njt_stream_proxy_srv_conf_t *pscf;

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_proxy_module);

    c = s->connection;
    u = s->upstream;
    pc = u->connected ? u->peer.connection : NULL;

    if (c->type == SOCK_DGRAM)
    {

        if (pscf->requests && u->requests < pscf->requests)
        {
            return NJT_DECLINED;
        }

        if (pscf->requests)
        {
            njt_delete_udp_connection(c);
        }

        if (pscf->responses == NJT_MAX_INT32_VALUE || u->responses < pscf->responses * u->requests)
        {
            return NJT_DECLINED;
        }

        if (pc == NULL || c->buffered || pc->buffered)
        {
            return NJT_DECLINED;
        }

        handler = c->log->handler;
        c->log->handler = NULL;

        njt_log_error(NJT_LOG_INFO, c->log, 0,
                      "udp done"
                      ", packets from/to client:%ui/%ui"
                      ", bytes from/to client:%O/%O"
                      ", bytes from/to upstream:%O/%O",
                      u->requests, u->responses,
                      s->received, c->sent, u->received, pc ? pc->sent : 0);

        c->log->handler = handler;

        njt_stream_proto_finalize(s, NJT_STREAM_OK);

        return NJT_OK;
    }

    /* c->type == SOCK_STREAM */
    // njt_log_error(NJT_LOG_INFO, c->log, 0,"c->read->eof=%d,pc->read->eof=%d,c->buffered=%d,pc->buffered=%d",c->read->eof,pc->read->eof,c->buffered,pc->buffered);
    if (pc == NULL || (!c->read->eof && !pc->read->eof) || (!c->read->eof && c->buffered) || (!pc->read->eof && pc->buffered))
    {
        return NJT_DECLINED;
    }

    if (pscf->half_close)
    {
        /* avoid closing live connections until both read ends get EOF */
        if (!(c->read->eof && pc->read->eof && !c->buffered && !pc->buffered))
        {
            return NJT_DECLINED;
        }
    }

    handler = c->log->handler;
    c->log->handler = NULL;

    njt_log_error(NJT_LOG_INFO, c->log, 0,
                  "%s disconnected"
                  ", bytes from/to client:%O/%O"
                  ", bytes from/to upstream:%O/%O",
                  from_upstream ? "upstream" : "client",
                  s->received, c->sent, u->received, pc ? pc->sent : 0);

    c->log->handler = handler;

    njt_stream_proto_finalize(s, NJT_STREAM_OK);

    return NJT_OK;
}
static void
njt_stream_proto_next_upstream(njt_stream_session_t *s)
{
    njt_msec_t timeout;
    njt_connection_t *pc;
    njt_stream_upstream_t *u;
    njt_stream_proxy_srv_conf_t *pscf;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream proxy next upstream");

    u = s->upstream;
    pc = u->peer.connection;

    if (pc && pc->buffered)
    {
        njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                      "buffered data on next upstream");
        njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (s->connection->type == SOCK_DGRAM)
    {
        u->upstream_out = NULL;
    }

    if (u->peer.sockaddr)
    {
        u->peer.free(&u->peer, u->peer.data, NJT_PEER_FAILED);
        u->peer.sockaddr = NULL;
    }

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_proxy_module);

    timeout = pscf->next_upstream_timeout;

    if (u->peer.tries == 0 || !pscf->next_upstream || (timeout && njt_current_msec - u->peer.start_time >= timeout))
    {
        njt_stream_proto_finalize(s, NJT_STREAM_BAD_GATEWAY);
        return;
    }

    if (pc)
    {
        njt_log_debug1(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "close proxy upstream connection: %d", pc->fd);

#if (NJT_STREAM_SSL)
        if (pc->ssl)
        {
            pc->ssl->no_wait_shutdown = 1;
            pc->ssl->no_send_shutdown = 1;

            (void)njt_ssl_shutdown(pc);
        }
#endif

        u->state->bytes_received = u->received;
        u->state->bytes_sent = pc->sent;

        njt_close_connection(pc);
        u->peer.connection = NULL;
    }

    njt_stream_proto_connect(s);
}

static njt_int_t
njt_stream_proto_test_connect(njt_connection_t *c)
{
    int err;
    socklen_t len;

#if (NJT_HAVE_KQUEUE)

    if (njt_event_flags & NJT_USE_KQUEUE_EVENT)
    {
        err = c->write->kq_errno ? c->write->kq_errno : c->read->kq_errno;

        if (err)
        {
            (void)njt_connection_error(c, err,
                                       "kevent() reported that connect() failed");
            return NJT_ERROR;
        }
    }
    else
#endif
    {
        err = 0;
        len = sizeof(int);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *)&err, &len) == -1)
        {
            err = njt_socket_errno;
        }

        if (err)
        {
            (void)njt_connection_error(c, err, "connect() failed");
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}

static njt_int_t
njt_stream_proto_send_proxy_protocol(njt_stream_session_t *s)
{
    // openresty patch
    // u_char                       *p;
    // ssize_t                       n, size;
    // njt_connection_t             *c, *pc;
    // njt_stream_upstream_t        *u;
    // njt_stream_proxy_srv_conf_t  *pscf;
    // u_char                        buf[NJT_PROXY_PROTOCOL_MAX_HEADER];
    u_char *p;
    u_char buf[NJT_PROXY_PROTOCOL_MAX_HEADER];
    ssize_t n, size;
    njt_connection_t *c, *pc;
    njt_stream_upstream_t *u;
    njt_stream_proxy_ctx_t *ctx;

    ctx = njt_stream_get_module_ctx(s, njt_stream_proxy_module);
    // openresty patch end

    c = s->connection;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, c->log, 0,
                   "stream proxy send PROXY protocol header");

    p = njt_proxy_protocol_v2_write(s, buf, buf + NJT_PROXY_PROTOCOL_MAX_HEADER);
    if (p == NULL)
    {
        njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return NJT_ERROR;
    }

    u = s->upstream;

    pc = u->peer.connection;

    size = p - buf;

    n = pc->send(pc, buf, size);

    if (n == NJT_AGAIN)
    {
        if (njt_handle_write_event(pc->write, 0) != NJT_OK)
        {
            njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return NJT_ERROR;
        }

        // openresty patch
        // pscf = njt_stream_get_module_srv_conf(s, njt_stream_proxy_module);

        // njt_add_timer(pc->write, pscf->timeout);
        njt_add_timer(pc->write, ctx->timeout);
        // openresty patch end

        pc->write->handler = njt_stream_proto_connect_handler;

        return NJT_AGAIN;
    }

    if (n == NJT_ERROR)
    {
        njt_stream_proto_finalize(s, NJT_STREAM_OK);
        return NJT_ERROR;
    }

    if (n != size)
    {

        /*
         * PROXY protocol specification:
         * The sender must always ensure that the header
         * is sent at once, so that the transport layer
         * maintains atomicity along the path to the receiver.
         */

        njt_log_error(NJT_LOG_ERR, c->log, 0,
                      "could not send PROXY protocol header at once");

        njt_stream_proto_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);

        return NJT_ERROR;
    }

    return NJT_OK;
}

static njt_int_t
njt_stream_proto_ssl_name(njt_stream_session_t *s)
{
    u_char *p, *last;
    njt_str_t name;
    njt_stream_upstream_t *u;
    njt_stream_proxy_srv_conf_t *pscf;

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_proxy_module);

    u = s->upstream;

    if (pscf->ssl_name)
    {
        if (njt_stream_complex_value(s, pscf->ssl_name, &name) != NJT_OK)
        {
            return NJT_ERROR;
        }
    }
    else
    {
        name = u->ssl_name;
    }

    if (name.len == 0)
    {
        goto done;
    }

    /*
     * ssl name here may contain port, strip it for compatibility
     * with the http module
     */

    p = name.data;
    last = name.data + name.len;

    if (*p == '[')
    {
        p = njt_strlchr(p, last, ']');

        if (p == NULL)
        {
            p = name.data;
        }
    }

    p = njt_strlchr(p, last, ':');

    if (p != NULL)
    {
        name.len = p - name.data;
    }

    if (!pscf->ssl_server_name)
    {
        goto done;
    }

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME

    /* as per RFC 6066, literal IPv4 and IPv6 addresses are not permitted */

    if (name.len == 0 || *name.data == '[')
    {
        goto done;
    }

    if (njt_inet_addr(name.data, name.len) != INADDR_NONE)
    {
        goto done;
    }

    /*
     * SSL_set_tlsext_host_name() needs a null-terminated string,
     * hence we explicitly null-terminate name here
     */

    p = njt_pnalloc(s->connection->pool, name.len + 1);
    if (p == NULL)
    {
        return NJT_ERROR;
    }

    (void)njt_cpystrn(p, name.data, name.len + 1);

    name.data = p;

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "upstream SSL server name: \"%s\"", name.data);

    if (SSL_set_tlsext_host_name(u->peer.connection->ssl->connection,
                                 (char *)name.data) == 0)
    {
        njt_ssl_error(NJT_LOG_ERR, s->connection->log, 0,
                      "SSL_set_tlsext_host_name(\"%s\") failed", name.data);
        return NJT_ERROR;
    }

#endif

done:

    u->ssl_name = name;

    return NJT_OK;
}

#if (NJT_STREAM_MULTICERT)

static njt_int_t
njt_stream_proto_ssl_certificates(njt_stream_session_t *s)
{
    njt_str_t *certp, *keyp, cert, key;
    njt_uint_t i, nelts;
#if (NJT_HAVE_NTLS)
    njt_str_t tcert, tkey;
#endif
    njt_connection_t *c;
    njt_stream_complex_value_t *certs, *keys;
    njt_stream_proxy_srv_conf_t *pscf;

    c = s->upstream->peer.connection;

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_proxy_module);

    nelts = pscf->ssl_certificate_values->nelts;
    certs = pscf->ssl_certificate_values->elts;
    keys = pscf->ssl_certificate_key_values->elts;

    for (i = 0; i < nelts; i++)
    {
        certp = &cert;
        keyp = &key;

        if (njt_stream_complex_value(s, &certs[i], certp) != NJT_OK)
        {
            return NJT_ERROR;
        }

#if (NJT_HAVE_NTLS)
        tcert = *certp;
        njt_ssl_ntls_prefix_strip(&tcert);
        certp = &cert;
#endif

        if (*certp->data == 0)
        {
            continue;
        }

        njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0,
                       "stream upstream ssl cert: \"%s\"", certp->data);

        if (njt_stream_complex_value(s, &keys[i], keyp) != NJT_OK)
        {
            return NJT_ERROR;
        }

#if (NJT_HAVE_NTLS)
        tkey = *keyp;
        njt_ssl_ntls_prefix_strip(&tkey);
        keyp = &key;
#endif

        njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0,
                       "stream upstream ssl key: \"%s\"", keyp->data);

        if (njt_ssl_connection_certificate(c, s->connection->pool, certp, keyp,
                                           pscf->ssl_passwords) != NJT_OK)
        {
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}

#else

static njt_int_t
njt_stream_proto_ssl_certificate(njt_stream_session_t *s)
{
    njt_str_t cert, key;
    njt_connection_t *c;
    njt_stream_proxy_srv_conf_t *pscf;

    c = s->upstream->peer.connection;

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_proxy_module);

    if (njt_stream_complex_value(s, pscf->ssl_certificate, &cert) != NJT_OK)
    {
        return NJT_ERROR;
    }

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0,
                   "stream upstream ssl cert: \"%s\"", cert.data);

    if (*cert.data == '\0')
    {
        return NJT_OK;
    }

    if (njt_stream_complex_value(s, pscf->ssl_certificate_key, &key) != NJT_OK)
    {
        return NJT_ERROR;
    }

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0,
                   "stream upstream ssl key: \"%s\"", key.data);

    if (njt_ssl_connection_certificate(c, c->pool, &cert, &key,
                                       pscf->ssl_passwords) != NJT_OK)
    {
        return NJT_ERROR;
    }

    return NJT_OK;
}

#endif

static void
njt_stream_proto_ssl_save_session(njt_connection_t *c)
{
    njt_stream_session_t *s;
    njt_stream_upstream_t *u;

    s = c->data;
    u = s->upstream;

    u->peer.save_session(&u->peer, u->peer.data);
}

static void
njt_stream_proto_ssl_handshake(njt_connection_t *pc)
{
    long rc;
    njt_stream_session_t *s;
    njt_stream_upstream_t *u;
    njt_stream_proxy_srv_conf_t *pscf;

    s = pc->data;

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_proxy_module);

    if (pc->ssl->handshaked)
    {

        if (pscf->ssl_verify)
        {
            rc = SSL_get_verify_result(pc->ssl->connection);

            if (rc != X509_V_OK)
            {
                njt_log_error(NJT_LOG_ERR, pc->log, 0,
                              "upstream SSL certificate verify error: (%l:%s)",
                              rc, X509_verify_cert_error_string(rc));
                goto failed;
            }

            u = s->upstream;

            if (njt_ssl_check_host(pc, &u->ssl_name) != NJT_OK)
            {
                njt_log_error(NJT_LOG_ERR, pc->log, 0,
                              "upstream SSL certificate does not match \"%V\"",
                              &u->ssl_name);
                goto failed;
            }
        }

        if (pc->write->timer_set)
        {
            njt_del_timer(pc->write);
        }

        njt_stream_proto_init_upstream(s);

        return;
    }

failed:

    njt_stream_proto_next_upstream(s);
}

void proto_server_log(int level, const char *fmt, ...)
{
    u_char buf[NJT_MAX_ERROR_STR] = {0};
    va_list args;
    u_char *p;
    njt_str_t msg;

    va_start(args, fmt);
    p = njt_vslprintf(buf, buf + NJT_MAX_ERROR_STR, fmt, args);
    va_end(args);

    msg.data = buf;
    msg.len = p - buf;

    njt_log_error((njt_uint_t)level, njt_cycle->log, 0, "[tcc]%V", &msg);
}
static void *
njt_prealloc(njt_pool_t *pool, void *p, size_t size)
{
    njt_pool_large_t **l, *large;
    void *ptr;

    if (p == NULL)
    {
        return njt_palloc(pool, size);
    }
    pool->log = njt_cycle->log;
    for (l = &pool->large; *l;)
    {
        // by zyg
        if (pool->dynamic)
        {
            void *fp = (*l)->alloc;
            void *data = ((njt_pool_large_t *)p) - 1;
            if (data == fp)
            {
                *l = (*l)->next;
                if (size == 0)
                {
                    njt_free(fp);
                    return NJT_OK;
                }
                ptr = njt_realloc(fp, size + sizeof(njt_pool_large_t), pool->log);
                if (ptr == NULL)
                {
                    return NULL;
                }
                large = ptr;
                large->alloc = ptr;
                large->next = pool->large;
                pool->large = large;
                return (void *)(large + 1);
            }
        }
        l = &(*l)->next;
    }
    njt_log_debug1(NJT_LOG_DEBUG_ALLOC, pool->log, 0,
                   "free error: %p", p);
    return NULL;
}
static void
njt_stream_proto_finalize(njt_stream_session_t *s, njt_uint_t rc)
{
    njt_uint_t state;
    njt_connection_t *pc;
    njt_stream_upstream_t *u;

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "finalize stream proxy: %i", rc);

    u = s->upstream;

    if (u == NULL)
    {
        goto noupstream;
    }

    if (u->resolved && u->resolved->ctx)
    {
        njt_resolve_name_done(u->resolved->ctx);
        u->resolved->ctx = NULL;
    }

    pc = u->peer.connection;

    if (u->state)
    {
        if (u->state->response_time == (njt_msec_t)-1)
        {
            u->state->response_time = njt_current_msec - u->start_time;
        }

        if (pc)
        {
            u->state->bytes_received = u->received;
            u->state->bytes_sent = pc->sent;
        }
    }

    if (u->peer.free && u->peer.sockaddr)
    {
        state = 0;

        if (pc && pc->type == SOCK_DGRAM && (pc->read->error || pc->write->error))
        {
            state = NJT_PEER_FAILED;
        }

        u->peer.free(&u->peer, u->peer.data, state);
        u->peer.sockaddr = NULL;
    }

    if (pc)
    {
        njt_log_debug1(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "close stream proxy upstream connection: %d", pc->fd);

#if (NJT_STREAM_SSL)
        if (pc->ssl)
        {
            pc->ssl->no_wait_shutdown = 1;
            (void)njt_ssl_shutdown(pc);
        }
#endif

        njt_close_connection(pc);
        u->peer.connection = NULL;
    }

noupstream:

    njt_stream_finalize_session(s, rc);
}

static void *
njt_realloc(void *ptr, size_t size, njt_log_t *log)
{
    void *p;

    p = realloc(ptr, size);
    if (p == NULL)
    {
        njt_log_error(NJT_LOG_EMERG, log, njt_errno,
                      "realloc(%uz) failed", size);
    }

    // njt_log_debug2(NJT_LOG_DEBUG_ALLOC, log, 0, "malloc: %p:%uz", p, size);

    return p;
}

static njt_int_t
njt_proto_write_filter(njt_stream_session_t *s, njt_chain_t *in,
                       njt_uint_t from_upstream)
{
    off_t size;
    njt_uint_t last, flush, sync;
    njt_chain_t *cl, *ln, **ll, **out, *chain;
    njt_connection_t *c;
    // njt_stream_write_filter_ctx_t  *ctx;
    njt_stream_proto_server_client_ctx_t *ctx;

    ctx = njt_stream_get_module_ctx(s, njt_stream_proto_server_module);

    if (ctx == NULL)
    {
        ctx = njt_pcalloc(s->connection->pool,
                          sizeof(njt_stream_proto_server_client_ctx_t));
        if (ctx == NULL)
        {
            return NJT_ERROR;
        }

        njt_stream_set_ctx(s, ctx, njt_stream_proto_server_module);
    }

    if (from_upstream)
    {
        c = s->connection;
        out = &ctx->from_upstream;
    }
    else
    {
        c = s->upstream->peer.connection;
        out = &ctx->from_downstream;
    }

    if (c->error)
    {
        return NJT_ERROR;
    }

    size = 0;
    flush = 0;
    sync = 0;
    last = 0;
    ll = out;

    /* find the size, the flush point and the last link of the saved chain */

    for (cl = *out; cl; cl = cl->next)
    {
        ll = &cl->next;
        if (njt_buf_size(cl->buf) == 0 && !njt_buf_special(cl->buf))
        {
            njt_log_error(NJT_LOG_ALERT, c->log, 0,
                          "zero size buf in writer "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            njt_debug_point();
            return NJT_ERROR;
        }

        if (njt_buf_size(cl->buf) < 0)
        {
            njt_log_error(NJT_LOG_ALERT, c->log, 0,
                          "negative size buf in writer "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            njt_debug_point();
            return NJT_ERROR;
        }

        size += njt_buf_size(cl->buf);

        if (cl->buf->flush || cl->buf->recycled)
        {
            flush = 1;
        }

        if (cl->buf->sync)
        {
            sync = 1;
        }

        if (cl->buf->last_buf)
        {
            last = 1;
        }
    }

    /* add the new chain to the existent one */

    for (ln = in; ln; ln = ln->next)
    {
        cl = njt_alloc_chain_link(c->pool);
        if (cl == NULL)
        {
            return NJT_ERROR;
        }

        cl->buf = ln->buf;
        *ll = cl;
        ll = &cl->next;

        if (njt_buf_size(cl->buf) == 0 && !njt_buf_special(cl->buf))
        {
            njt_log_error(NJT_LOG_ALERT, c->log, 0,
                          "zero size buf in writer "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            njt_debug_point();
            return NJT_ERROR;
        }

        if (njt_buf_size(cl->buf) < 0)
        {
            njt_log_error(NJT_LOG_ALERT, c->log, 0,
                          "negative size buf in writer "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            njt_debug_point();
            return NJT_ERROR;
        }

        size += njt_buf_size(cl->buf);

        if (cl->buf->flush || cl->buf->recycled)
        {
            flush = 1;
        }

        if (cl->buf->sync)
        {
            sync = 1;
        }

        if (cl->buf->last_buf)
        {
            last = 1;
        }
    }

    *ll = NULL;

    njt_log_debug3(NJT_LOG_DEBUG_STREAM, c->log, 0,
                   "stream write filter: l:%ui f:%ui s:%O", last, flush, size);

    if (size == 0 && !(c->buffered & NJT_LOWLEVEL_BUFFERED) && !(last && c->need_last_buf) && !(flush && c->need_flush_buf))
    {
        if (last || flush || sync)
        {
            for (cl = *out; cl; /* void */)
            {
                ln = cl;
                cl = cl->next;
                njt_free_chain(c->pool, ln);
                if (from_upstream)
                {
                    ctx->r.session_max_mem_size = ctx->r.session_max_mem_size - (ln->buf->end - ln->buf->start);
                    // njt_log_debug2(NJT_LOG_DEBUG, c->log, 0,"proto_ctx->r.session_max_mem_size=%d,tcc free client=%d!",ctx->r.session_max_mem_size,(ln->buf->end - ln->buf->start));
                }
                else
                {
                    ctx->r.session_up_max_mem_size = ctx->r.session_up_max_mem_size - (ln->buf->end - ln->buf->start);
                }
                if (ln->buf->start != NULL)
                {
                    njt_pfree(ctx->r.tcc_pool, ln->buf->start);
                }
            }

            *out = NULL;
            c->buffered &= ~NJT_STREAM_WRITE_BUFFERED;

            return NJT_OK;
        }

        njt_log_error(NJT_LOG_ALERT, c->log, 0,
                      "the stream output chain is empty");

        njt_debug_point();

        return NJT_ERROR;
    }

    chain = c->send_chain(c, *out, 0);

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0,
                   "stream write filter %p", chain);

    if (chain == NJT_CHAIN_ERROR)
    {
        c->error = 1;
        return NJT_ERROR;
    }

    for (cl = *out; cl && cl != chain; /* void */)
    {
        ln = cl;
        cl = cl->next;
        njt_free_chain(c->pool, ln);
        if (from_upstream)
        {
            ctx->r.session_max_mem_size = ctx->r.session_max_mem_size - (ln->buf->end - ln->buf->start);
            // njt_log_debug2(NJT_LOG_DEBUG, c->log, 0,"proto_ctx->r.session_max_mem_size=%d,tcc free client=%d!",ctx->r.session_max_mem_size,(ln->buf->end - ln->buf->start));
        }
        else
        {
            ctx->r.session_up_max_mem_size = ctx->r.session_up_max_mem_size - (ln->buf->end - ln->buf->start);
        }
        if (ln->buf->start != NULL)
        {
            njt_pfree(ctx->r.tcc_pool, ln->buf->start);
        }
    }

    *out = chain;

    if (chain)
    {
        if (c->shared)
        {
            njt_log_error(NJT_LOG_ALERT, c->log, 0,
                          "shared connection is busy");
            return NJT_ERROR;
        }

        c->buffered |= NJT_STREAM_WRITE_BUFFERED;
        return NJT_AGAIN;
    }

    c->buffered &= ~NJT_STREAM_WRITE_BUFFERED;

    if (c->buffered & NJT_LOWLEVEL_BUFFERED)
    {
        return NJT_AGAIN;
    }

    return NJT_OK;
}

int proto_server_build_message(tcc_stream_request_t *r, void *in_data, tcc_str_t *out_data)
{
    njt_stream_proto_server_srv_conf_t *sscf;
    njt_stream_session_t *s;

    s = (njt_stream_session_t *)r->s;
    sscf = njt_stream_get_module_srv_conf(s, njt_stream_proto_server_module);

    if (sscf->build_proto_message)
    {
        sscf->build_proto_message((tcc_stream_server_ctx *)r->tcc_server, in_data, out_data);
        return 0;
    }

    return -1;
}
int proto_destroy_pool(void *pool)
{
    njt_destroy_pool(pool);
    return NJT_OK;
}
u_char *proto_util_sha1(tcc_stream_request_t *r, u_char *src, size_t len, size_t dst_len)
{
    u_char *dst = proto_malloc(r, dst_len);
    njt_sha1_t sha;
    njt_sha1_init(&sha);
    njt_sha1_update(&sha, src, len);
    njt_sha1_final(dst, &sha);
    return dst;
}
void proto_util_base64(tcc_stream_request_t *r, u_char *s, size_t s_l, u_char **dst, size_t *d_l)
{
    njt_str_t src;
    njt_str_t res;
    src.len = s_l;
    src.data = s;

    res.len = njt_base64_encoded_length(s_l);
    res.data = proto_malloc(r, res.len);

    njt_encode_base64(&res, &src);
    *dst = res.data;
    *d_l = res.len;
}
njt_int_t
njt_tcc_yield(njt_stream_proto_server_client_ctx_t *ctx)
{
    if (swapcontext(&ctx->runctx, &ctx->main_ctx) == -1)
    {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                      "swapcontext error!");
    }

    return NJT_OK;
}
void njt_tcc_wakeup(njt_stream_proto_server_client_ctx_t *ctx)
{
    njt_stream_session_t *s;
    s = ctx->r.s;
    njt_post_event(s->connection->read, &njt_posted_events);
    // njt_log_debug2(NJT_LOG_DEBUG_CORE, ctx->log, 0, "python wakeup,with ctx:%p,wake event:%p",ctx,ctx->wake);
    /*
    njt_stream_session_t *s;
    s = ctx->r.s;
    mtask_setcurrent(s);
    if (swapcontext(&ctx->main_ctx, &ctx->runctx) == -1)
    {
       njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                   "swapcontext error!");
    }
    njt_post_event(s->connection->read, &njt_posted_events);
    mtask_resetcurrent();
    */
}

static void
njt_tcc_sleep_handler(njt_event_t *ev)
{
    njt_connection_t *c;
    njt_stream_proto_server_client_ctx_t *ctx;

    c = ev->data;
    ctx = c->data;
    njt_log_debug(NJT_LOG_DEBUG_STREAM, njt_cycle->log, 0,
                  "tcc.sleep() event handler");
    // ctx->pending = NJT_OK;

    njt_tcc_wakeup(ctx);
}

int tcc_sleep(unsigned int seconds)
{

    njt_connection_t c;
    // njt_event_t       event;
    if (seconds == 0)
    {
        return NJT_OK;
    }
    njt_stream_proto_server_client_ctx_t *ctx;
    njt_stream_session_t *s = mtask_current;
    if (s)
    {
        ctx = njt_stream_get_module_ctx(s, njt_stream_proto_server_module);
        if (ctx)
        {
            njt_log_debug(NJT_LOG_DEBUG_STREAM, njt_cycle->log, 0,
                          "tcc.sleep=%d", seconds);

            njt_memzero(&c, sizeof(njt_connection_t));
            njt_memzero(&ctx->wake, sizeof(njt_event_t));
            c.data = ctx;
            ctx->wake.data = &c;
            ctx->wake.handler = njt_tcc_sleep_handler;
            ctx->wake.log = njt_cycle->log;
            njt_add_timer(&ctx->wake, seconds * 1000);
            do
            {
                if (njt_tcc_yield(ctx) != NJT_OK)
                {
                    njt_del_timer(&ctx->wake);
                    return NJT_ERROR;
                }

            } while (!ctx->wake.timedout);
            // tips: because socket io may wake the sleep again and again, so we need to yield repeatly , until timeout
            return NJT_OK;
        }
    }
    return NJT_ERROR;
}

/* returns 1 on timeout */
static int mtask_yield(int fd, njt_int_t event)
{
    njt_stream_proto_server_client_ctx_t *ctx;
    njt_connection_t *c;
    njt_event_t *e;
    njt_stream_proto_server_srv_conf_t *mlcf;

    mlcf = njt_stream_get_module_srv_conf(mtask_current, njt_stream_proto_server_module);
    ctx = njt_stream_get_module_ctx(mtask_current, njt_stream_proto_server_module);
    c = njt_get_connection(fd, mtask_current->connection->log);
    c->data = mtask_current;
    if (event == NJT_READ_EVENT)
        e = c->read;
    else
        e = c->write;

    e->data = c;
    e->handler = &mtask_event_handler;
    e->log = mtask_current->connection->log;

    if (mlcf->mtask_timeout != NJT_CONF_UNSET_MSEC)
        njt_add_timer(e, mlcf->mtask_timeout);

    njt_add_event(e, event, 0);
    ctx->mtask_timeout = 0;
    if (njt_tcc_yield(ctx) != NJT_OK)
    {
        njt_del_timer(e);
        return NJT_ERROR;
    }

    if (e->timer_set)
        njt_del_timer(e);

    njt_del_event(e, event, 0);
    njt_free_connection(c);
    return ctx->mtask_timeout;
}
int tcc_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{

    ssize_t ret;
    int flags;
    socklen_t len;

    if (mtask_have_scheduled)
    {
        flags = fcntl(sockfd, F_GETFL, 0);
        if (!(flags & O_NONBLOCK))
            fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
    }
    ret = connect(sockfd, addr, addrlen);
    if (!mtask_have_scheduled || ret != -1 || errno != EINPROGRESS)
        return ret;

    for (;;)
    {
        if (mtask_yield(sockfd, NJT_WRITE_EVENT))
        {
            errno = ETIMEDOUT;
            return -1;
        }
        len = sizeof(flags);
        flags = 0;
        ret = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &flags, &len);
        if (ret == -1 || !len)
            return -1;
        if (!flags)
            return 0;
        if (flags != EINPROGRESS)
        {
            errno = flags;
            return -1;
        }
    }
}
ssize_t tcc_recv(int sockfd, void *buf, size_t len, int flags)
{

    ssize_t ret;

    for (;;)
    {
        ret = recv(sockfd, buf, len, flags);
        if (!mtask_have_scheduled || ret != -1 || errno != EAGAIN)
            return ret;
        if (mtask_yield(sockfd, NJT_READ_EVENT))
        {
            errno = ECONNRESET;
            return -1;
        }
    }
}
ssize_t tcc_write(int fd, const void *buf, size_t count)
{
    ssize_t ret;

    for (;;)
    {
        ret = write(fd, buf, count);
        if (!mtask_have_scheduled || ret != -1 || errno != EAGAIN)
            return ret;
        if (mtask_yield(fd, NJT_WRITE_EVENT))
        {
            errno = ECONNRESET;
            return -1;
        }
    }
}

ssize_t tcc_send(int sockfd, const void *buf, size_t len, int flags)
{
    ssize_t ret;

    for (;;)
    {
        ret = send(sockfd, buf, len, flags);
        if (!mtask_have_scheduled || ret != -1 || errno != EAGAIN)
            return ret;
        if (mtask_yield(sockfd, NJT_WRITE_EVENT))
        {
            errno = ECONNREFUSED;
            return -1;
        }
    }
}

static void mtask_event_handler(njt_event_t *ev)
{
    njt_stream_session_t *r;
    njt_connection_t *c;
    int wf = 0;

    c = ev->data;
    r = c->data;
    if (ev->timedout)
    {
        wf |= MTASK_WAKE_TIMEDOUT;
    }
    mtask_wake(r, wf);
}
tcc_str_t *cli_get_session(tcc_stream_request_t *r)
{
    return &r->session;
}
static njt_stream_proto_session_shctx_t *njt_stream_proto_get_session_shpool(tcc_stream_request_t *r)
{
    njt_stream_proto_server_srv_conf_t *sscf;
    sscf = (njt_stream_proto_server_srv_conf_t *)((u_char *)r->tcc_server - offsetof(njt_stream_proto_server_srv_conf_t, srv_ctx));
    if (sscf->set_session_handler)
    {
        return sscf->session_shm;
    }
    return NULL;
}
static njt_stream_proto_session_node_t *njt_stream_proto_find_session(tcc_stream_server_ctx *srv_ctx, tcc_str_t *session)
{
    njt_queue_t *q;
    njt_stream_proto_session_shctx_t *sh_ctx;
    njt_stream_proto_session_node_t *node;
    njt_stream_proto_server_srv_conf_t *sscf;
    sscf = (njt_stream_proto_server_srv_conf_t *)((u_char *)srv_ctx - offsetof(njt_stream_proto_server_srv_conf_t, srv_ctx));

    sh_ctx = sscf->session_shm;
    if (sh_ctx == NULL)
    {
        return NULL;
    }

    q = njt_queue_head(&sh_ctx->session_queue);
    for (; q != njt_queue_sentinel(&sh_ctx->session_queue); q = njt_queue_next(q))
    {
        node = njt_queue_data(q, njt_stream_proto_session_node_t, queue);
        if (node && node->session.len == session->len && njt_memcmp(node->session.data, session->data, session->len) == 0)
        {
            return node;
        }
    }
    return NULL;
}
static void njt_stream_proto_remove_session(tcc_stream_server_ctx *srv_ctx, tcc_str_t *session)
{
    njt_stream_proto_server_srv_conf_t *sscf;
    njt_stream_proto_session_node_t *node;
    njt_slab_pool_t *shpool;
    njt_stream_proto_session_shctx_t *sh_ctx;
    sscf = (njt_stream_proto_server_srv_conf_t *)((u_char *)srv_ctx - offsetof(njt_stream_proto_server_srv_conf_t, srv_ctx));

    njt_log_debug(NJT_LOG_DEBUG_STREAM, njt_cycle->log, 0, "1 tcc remove session=%V", session);
    if (sscf->set_session_handler == NULL || sscf->session_shm == NULL)
    {
        return;
    }
    sh_ctx = sscf->session_shm;
    shpool = sh_ctx->shpool;
    if (shpool == NULL)
    {
        return;
    }
    njt_shmtx_lock(&shpool->mutex);
    node = njt_stream_proto_find_session(srv_ctx, session);
    if (node)
    {
        njt_log_debug(NJT_LOG_DEBUG_STREAM, njt_cycle->log, 0, "2 tcc remove session=%V", session);
        njt_queue_remove(&node->queue);
        if (node->session.data)
        {
            njt_slab_free_locked(shpool, node->session.data);
        }
        if (node->session_data.data)
        {
            njt_slab_free_locked(shpool, node->session_data.data);
        }
        njt_slab_free_locked(shpool, node);
    }
    njt_shmtx_unlock(&shpool->mutex);
    return;
}
static void njt_stream_proto_remove_session_by_pid(tcc_stream_server_ctx *srv_ctx, njt_pid_t pid)
{
    njt_stream_proto_server_srv_conf_t *sscf;
    njt_stream_proto_session_node_t *node;
    njt_slab_pool_t *shpool;
    njt_queue_t *q;
    njt_stream_proto_session_shctx_t *sh_ctx;
    sscf = (njt_stream_proto_server_srv_conf_t *)((u_char *)srv_ctx - offsetof(njt_stream_proto_server_srv_conf_t, srv_ctx));

    if (sscf->set_session_handler == NULL || sscf->session_shm == NULL)
    {
        return;
    }
    sh_ctx = sscf->session_shm;
    shpool = sh_ctx->shpool;
    if (shpool == NULL)
    {
        return;
    }
    njt_shmtx_lock(&shpool->mutex);
    q = njt_queue_head(&sh_ctx->session_queue);
    for (; q != njt_queue_sentinel(&sh_ctx->session_queue);)
    {
        node = njt_queue_data(q, njt_stream_proto_session_node_t, queue);
        q = njt_queue_next(q);
        if (node && node->worker_pid == pid)
        {
            njt_queue_remove(&node->queue);
        }
        if (node->session.data)
        {
            njt_slab_free_locked(shpool, node->session.data);
        }
        if (node->session_data.data)
        {
            njt_slab_free_locked(shpool, node->session_data.data);
        }
        njt_slab_free_locked(shpool, node);
    }
    njt_shmtx_unlock(&shpool->mutex);
    return;
}

njt_int_t njt_stream_proto_update_session(tcc_stream_server_ctx *srv_ctx, tcc_str_t *session, tcc_str_t *data)
{
    njt_stream_proto_server_srv_conf_t *sscf;
    njt_stream_proto_session_node_t *node,*old_node;
    njt_slab_pool_t *shpool;
    sscf = (njt_stream_proto_server_srv_conf_t *)((u_char *)srv_ctx - offsetof(njt_stream_proto_server_srv_conf_t, srv_ctx));

    njt_stream_proto_session_shctx_t *sh_ctx = sscf->session_shm;
    if (sh_ctx == NULL)
    {
        return NJT_OK;
    }
    shpool = sh_ctx->shpool;
    if (shpool == NULL)
    {
        return NJT_ERROR;
    }
    njt_shmtx_lock(&shpool->mutex);
    old_node = njt_stream_proto_find_session(srv_ctx, session);
    node = old_node;
    if (node == NULL)
    {
        node = njt_slab_calloc_locked(shpool, sizeof(njt_stream_proto_session_node_t));
    }
    else
    {
        if (node->session_data.data != NULL)
        {
            njt_slab_free_locked(shpool, node->session_data.data);
            node->session_data.len = 0;
        }
    }
    if (node == NULL)
    {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0,
                              "could not allocate node in proto_session_zone \"%V\" error!", &sscf->zone_name);
        njt_shmtx_unlock(&shpool->mutex);
        return NJT_ERROR;
    }
    node->worker_pid = njt_pid;
    if (node->session.data == NULL)
    { // 如果不为空，说明存在，只更新data 数据。
        node->session.len = session->len;
        node->session.data = njt_slab_calloc_locked(shpool, node->session.len);
        if (node->session.data == NULL)
        {
            njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0,
                              "could not allocate session in proto_session_zone \"%V\" error!", &sscf->zone_name);
            njt_slab_free_locked(shpool, node);
            njt_shmtx_unlock(&shpool->mutex);
            return NJT_ERROR;
        }
        njt_memcpy(node->session.data, session->data, session->len);
    }
    if (data != NULL)
    {
        node->session_data.len = data->len;
        node->session_data.data = njt_slab_calloc_locked(shpool, node->session_data.len);
        if (node->session_data.data == NULL)
        {
            njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0,
                              "could not allocate session_data in proto_session_zone \"%V\" error!", &sscf->zone_name);

            njt_slab_free_locked(shpool, node->session.data);
            njt_slab_free_locked(shpool, node);
            if(old_node == node) {
                njt_queue_remove(&node->queue);
            }
            njt_shmtx_unlock(&shpool->mutex);
            return NJT_ERROR;
        }
        njt_memcpy(node->session_data.data, data->data, data->len);
    }

    njt_queue_insert_tail(&sh_ctx->session_queue, &node->queue);
    njt_shmtx_unlock(&shpool->mutex);
    return NJT_OK;
}
void cli_session_foreach(tcc_stream_server_ctx *srv_ctx, njt_proto_session_foreach_pt foreach_handler, void *data)
{
    njt_stream_proto_server_srv_conf_t *sscf;
    njt_slab_pool_t *shpool;
    njt_queue_t *q;
    njt_stream_proto_session_node_t *node;
    njt_stream_proto_session_shctx_t *sh_ctx;
    njt_array_t *client_list;
    tcc_stream_request_t **pr;
    njt_uint_t i;
    njt_int_t rc;

    sscf = (njt_stream_proto_server_srv_conf_t *)((u_char *)srv_ctx - offsetof(njt_stream_proto_server_srv_conf_t, srv_ctx));
    if (sscf->session_shm && sscf->set_session_handler)
    {
        shpool = sscf->session_shm->shpool;
        sh_ctx = sscf->session_shm;
        njt_shmtx_lock(&shpool->mutex);

        q = njt_queue_head(&sh_ctx->session_queue);
        for (; q != njt_queue_sentinel(&sh_ctx->session_queue); q = njt_queue_next(q))
        {
            node = njt_queue_data(q, njt_stream_proto_session_node_t, queue);

            njt_log_debug(NJT_LOG_DEBUG_STREAM, njt_cycle->log, 0, "tcc shm cli_session_foreach=%V", &node->session);
            rc = foreach_handler(srv_ctx, data, &node->session, &node->session_data);
            if (rc != APP_OK)
            {
                njt_shmtx_unlock(&shpool->mutex);
                return;
            }
        }

        njt_shmtx_unlock(&shpool->mutex);
    }
    else
    {

        if (srv_ctx != NULL && srv_ctx->client_list != NULL)
        {
            client_list = srv_ctx->client_list;
            for (i = 0; i < client_list->nelts; i++)
            {
                pr = client_list->elts;
                njt_log_debug(NJT_LOG_DEBUG_STREAM, njt_cycle->log, 0, "tcc mem cli_session_foreach=%V", &pr[i]->session);
                rc = foreach_handler(srv_ctx, data, &pr[i]->session, &pr[i]->session_data);
                if (rc != APP_OK)
                {
                    return;
                }
            }
        }
    }
}
int cli_set_session(tcc_stream_request_t *r, tcc_str_t *session, tcc_str_t *data)
{
    njt_stream_proto_session_shctx_t *sh_ctx;
    njt_stream_proto_server_srv_conf_t *sscf;
    njt_stream_session_t *s;
    njt_int_t  rc;

    if (session == NULL || session->len == 0 || session->data == NULL)
    {
        njt_log_debug(NJT_LOG_DEBUG_STREAM, njt_cycle->log, 0, "cli_set_session session null!");
        return APP_ERROR;
    }
    s = (njt_stream_session_t *)r->s;
    sscf = njt_stream_get_module_srv_conf(s, njt_stream_proto_server_module);
    if (sscf->session_size < session->len)
    {
        njt_log_debug(NJT_LOG_DEBUG_STREAM, njt_cycle->log, 0, "cli_set_session session too length!");
        return APP_ERROR;
    }
    njt_memcpy(r->session.data, session->data, session->len);
    r->session.len = session->len;
    if (data)
    {
        if (r->session_data.len < data->len)
        {
            proto_free(r, r->session_data.data);
            njt_str_null(&r->session_data);
        }
        r->session_data.data = proto_malloc(r, data->len);
        if (r->session_data.data == NULL)
        {
            return APP_ERROR;
        }
        njt_memcpy(r->session_data.data, data->data, data->len);
    }

    sh_ctx = njt_stream_proto_get_session_shpool(r);
    if (sh_ctx != NULL)
    {
        rc = njt_stream_proto_update_session(r->tcc_server, session, data);
        if(rc == NJT_ERROR) {
            cli_close(r);
        }
    }
    return APP_OK;
}

static void *njt_stream_get_ctx_by_zone(njt_cycle_t *cycle, njt_str_t *zone_name)
{
    njt_stream_proto_server_main_conf_t *proto_cmf;
    njt_uint_t i;
    njt_stream_proto_server_srv_conf_t *sscf, **sscfp;

    proto_cmf = njt_stream_cycle_get_module_main_conf(cycle, njt_stream_proto_server_module);
    if (proto_cmf == NULL)
    {
        return NULL;
    }
    sscfp = proto_cmf->srv_info.elts;
    for (i = 0; i < proto_cmf->srv_info.nelts; i++)
    {
        sscf = sscfp[i];
        if (sscf->zone_name.len == zone_name->len && njt_memcmp(sscf->zone_name.data, zone_name->data, zone_name->len) == 0)
        {
            return sscf;
        }
    }
    return NULL;
}
static void njt_stream_proto_remove_client_hash(tcc_stream_server_ctx *srv_ctx,tcc_str_t *session)
{
    njt_lvlhash_map_t *var_hash = srv_ctx->hashmap;
    njt_lvlhsh_map_remove(var_hash,(njt_str_t *)session);
}

static void njt_stream_proto_add_client_hash(tcc_stream_server_ctx *srv_ctx,tcc_stream_request_t *r)
{
    tcc_stream_request_t *old_var_hash_item;
    njt_lvlhash_map_t *var_hash = srv_ctx->hashmap;
    njt_lvlhsh_map_put(var_hash, (njt_str_t *)&r->session, (intptr_t)r, (intptr_t *)&old_var_hash_item);
}
tcc_stream_request_t *cli_local_find_by_session(tcc_stream_server_ctx *srv_ctx, tcc_str_t *session)
{
    tcc_stream_request_t *r = NULL;
    njt_lvlhash_map_t *var_hash = srv_ctx->hashmap;
    if (session == NULL)
    {
        njt_log_debug(NJT_LOG_DEBUG_STREAM, njt_cycle->log, 0, "tcc no find session=%V", session);
        return NULL;
    }
    if (njt_lvlhsh_map_get(var_hash, (njt_str_t *)session, (intptr_t *)&r) == NJT_OK)
    {
        njt_log_debug(NJT_LOG_DEBUG_STREAM, njt_cycle->log, 0, "tcc find session=%V", session);
        return r;
    }
    njt_log_debug(NJT_LOG_DEBUG_STREAM, njt_cycle->log, 0, "tcc no find session=%V", session);
    return NULL;
}
