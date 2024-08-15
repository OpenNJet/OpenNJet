/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>
#include <sys/socket.h>
#include "njt_stream_proto_server_module.h"
#include "libtcc.h"
#include "njt_tcc.h"

typedef int (*njt_proto_server_handler_pt)(tcc_stream_request_t *r);
typedef int (*njt_proto_server_data_handler_pt)(tcc_stream_request_t *r, tcc_str_t *msg);
typedef int (*njt_proto_server_update_pt)(tcc_stream_server_ctx *srv_ctx);

typedef struct
{
    njt_chain_t *out_chain;
    njt_chain_t *out_busy;
    njt_buf_t out_buf;
    tcc_stream_request_t r;
    njt_chain_t *free;
    njt_event_t timer;
} njt_stream_proto_server_client_ctx_t;
typedef struct
{
    njt_array_t srv_info;

} njt_stream_proto_server_main_conf_t;

typedef struct
{
    njt_flag_t proto_server_enabled;
    TCCState *s;
    njt_array_t  *tcc_files;
    tcc_stream_server_ctx srv_ctx;
    njt_event_t timer;
    size_t buffer_size;
    njt_msec_t connect_timeout;
    njt_msec_t client_update_interval;
    njt_msec_t server_update_interval;
    njt_proto_server_handler_pt connection_handler;
    njt_proto_server_data_handler_pt preread_handler;
    njt_proto_server_handler_pt log_handler;
    njt_proto_server_data_handler_pt message_handler;
    njt_proto_server_handler_pt abort_handler;
    njt_proto_server_update_pt server_update_handler;
    njt_proto_server_update_pt server_init_handler;
    njt_proto_server_data_handler_pt client_update_handler;

} njt_stream_proto_server_srv_conf_t;

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
static void njt_stream_proto_server_update_in_buf(njt_stream_proto_server_client_ctx_t *ctx, size_t used_len);

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
     {njt_string("proto_server_code_file"),
     NJT_STREAM_MAIN_CONF | NJT_STREAM_SRV_CONF | NJT_CONF_TAKE1,
     njt_conf_set_str_array_slot, // do custom config
     NJT_STREAM_SRV_CONF_OFFSET,
     offsetof(njt_stream_proto_server_srv_conf_t,tcc_files),
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
    &njt_stream_proto_server_module_ctx, /* module context */
    njt_stream_proto_server_commands,    /* module directives */
    NJT_STREAM_MODULE,                   /* module type */
    NULL,                                /* init master */
    NULL,                                /* init module */
    &njt_stream_proto_server_process,    /* init process */
    NULL,                                /* init thread */
    NULL,                                /* exit thread */
    NULL,                                /* exit process */
    NULL,                                /* exit master */
    NJT_MODULE_V1_PADDING};

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
        njt_stream_proto_server_update_in_buf(ctx, ctx->r.used_len);
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
static njt_int_t njt_stream_proto_server_process(njt_cycle_t *cycle)
{
    njt_stream_proto_server_main_conf_t *cmf;
    njt_uint_t i;
    njt_stream_proto_server_srv_conf_t *sscf, **sscfp;

    cmf = njt_stream_cycle_get_module_main_conf(cycle, njt_stream_proto_server_module);
    if (cmf == NULL)
    {
        return NJT_OK;
    }
    sscfp = cmf->srv_info.elts;

    for (i = 0; i < cmf->srv_info.nelts; i++)
    {
        sscf = sscfp[i];
        sscf->timer.handler = njt_stream_proto_server_update;
        sscf->timer.log = cycle->log;
        sscf->timer.data = sscf;
        sscf->timer.cancelable = 1;
        if (sscf->server_update_interval > 0 && sscf->server_update_handler != NULL)
        {
            njt_add_timer(&sscf->timer, sscf->server_update_interval);
        }
    }
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

    tcc_set_output_type(tcc, TCC_OUTPUT_MEMORY);
    tcc_set_options(tcc, "-Werror");
    tcc_set_lib_path(tcc, (const char *)full_path.data);
    tcc_add_include_path(tcc, (const char *)full_path.data);
    tcc_add_sysinclude_path(tcc, (const char *)full_path.data);
    return tcc;
}
static void *njt_stream_proto_server_create_srv_conf(njt_conf_t *cf)
{
    njt_stream_proto_server_srv_conf_t *conf;
    njt_int_t rc;

    njt_log_debug(NJT_LOG_DEBUG_EVENT, njt_cycle->log, 0, "stream_proto create serv config");

    conf = njt_pcalloc(cf->pool, sizeof(njt_stream_proto_server_srv_conf_t));
    if (conf == NULL)
    {
        return NULL;
    }
    conf->proto_server_enabled = NJT_CONF_UNSET;
    conf->s = NJT_CONF_UNSET_PTR;
    conf->tcc_files = NJT_CONF_UNSET_PTR;
    conf->connect_timeout = NJT_CONF_UNSET_MSEC;
    conf->client_update_interval = NJT_CONF_UNSET_MSEC;
    conf->server_update_interval = NJT_CONF_UNSET_MSEC;
    conf->buffer_size = NJT_CONF_UNSET_SIZE;
    conf->srv_ctx.client_list = njt_pcalloc(cf->pool, sizeof(njt_array_t));
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
    return conf;
}

static char *njt_stream_proto_server_merge_srv_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_str_t         *pp, value;
    char *filename;
    njt_uint_t          i;
    int filetype;
    njt_stream_proto_server_main_conf_t *cmf;
    njt_stream_proto_server_srv_conf_t **psscf;


    njt_stream_proto_server_srv_conf_t *prev = parent;
    njt_stream_proto_server_srv_conf_t *conf = child;
    njt_conf_merge_value(conf->proto_server_enabled, prev->proto_server_enabled, 0);
    njt_conf_merge_size_value(conf->buffer_size,
                              prev->buffer_size, 16384);
    njt_conf_merge_msec_value(conf->connect_timeout,
                              prev->connect_timeout, 60000);
    njt_conf_merge_msec_value(conf->client_update_interval,
                              prev->client_update_interval, 60000);
    njt_conf_merge_msec_value(conf->server_update_interval,
                              prev->server_update_interval, 60000);

    if (conf->proto_server_enabled && conf->s == NJT_CONF_UNSET_PTR && conf->tcc_files != NJT_CONF_UNSET_PTR) {
        conf->s = njt_stream_proto_server_create_tcc(cf); // todo
        if (conf->s == NULL)
        {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                            "njt_stream_proto_server_create_tcc   error!");
            return NJT_CONF_ERROR;
        }

        pp = conf->tcc_files->elts;
        for (i = 0; i < conf->tcc_files->nelts; i++) {
            value = pp[i];
            filename = njt_pcalloc(cf->pool,value.len + 1);
            if(filename == NULL) {
                return NJT_CONF_ERROR;
            }
            njt_memcpy(filename,value.data,value.len);
            filetype = TCC_FILETYPE_C;
            if (tcc_add_file(conf->s, filename, filetype) < 0) {
                 njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                            "tcc_add_file   error!");
                return NJT_CONF_ERROR;
            }
        }
        if (tcc_relocate(conf->s, TCC_RELOCATE_AUTO) < 0) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                            "tcc_relocate   error!");
                return NJT_CONF_ERROR;
        }
    }
    if (conf->proto_server_enabled && conf->s != NJT_CONF_UNSET_PTR)
    {
        conf = njt_stream_conf_get_module_srv_conf(cf, njt_stream_proto_server_module);
        conf->connection_handler = tcc_get_symbol(conf->s, "proto_server_process_connetion");
        conf->preread_handler = tcc_get_symbol(conf->s, "proto_server_process_preread");
        conf->log_handler = tcc_get_symbol(conf->s, "proto_server_process_log");
        conf->message_handler = tcc_get_symbol(conf->s, "proto_server_process_message");
        conf->abort_handler = tcc_get_symbol(conf->s, "proto_server_process_connection_close");
        conf->client_update_handler = tcc_get_symbol(conf->s, "proto_server_process_client_update");
        conf->server_update_handler = tcc_get_symbol(conf->s, "proto_server_update");
        conf->server_init_handler = tcc_get_symbol(conf->s, "proto_server_init");

        if (conf->server_init_handler)
        {
            conf->server_init_handler(&conf->srv_ctx);
        }
        if (conf->server_update_interval != 0 && conf->server_update_handler != NULL)
        {
            cmf = njt_stream_conf_get_module_main_conf(cf, njt_stream_proto_server_module);
            psscf = njt_array_push(&cmf->srv_info);
            *psscf = conf;
        }
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
    ctx->r.s = s;
    ctx->r.tcc_server = &sscf->srv_ctx;
    ctx->r.addr_text = (tcc_str_t *)&s->connection->addr_text;
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
static void njt_stream_proto_server_update_in_buf(njt_stream_proto_server_client_ctx_t *ctx, size_t used_len)
{
    if (used_len <= 0)
    {
        return;
    }
    ctx->r.in_buf.pos = ctx->r.in_buf.pos + used_len;
    if (ctx->r.in_buf.pos >= ctx->r.in_buf.last)
    {
        // 消费完，重置。
        ctx->r.in_buf.pos = ctx->r.in_buf.start;
        ctx->r.in_buf.last = ctx->r.in_buf.start;
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

    ctx = njt_stream_get_module_ctx(s, njt_stream_proto_server_module);
    sscf = njt_stream_get_module_srv_conf(s, njt_stream_proto_server_module);
    if (!sscf->proto_server_enabled || ctx == NULL)
    {
        return NJT_DECLINED;
    }
    if (sscf->preread_handler)
    {
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
        njt_stream_proto_server_update_in_buf(ctx, ctx->r.used_len);

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
    ctx = njt_stream_get_module_ctx(s, njt_stream_proto_server_module);
    sscf = njt_stream_get_module_srv_conf(s, njt_stream_proto_server_module);
    if (!sscf->proto_server_enabled || ctx == NULL)
    {
        return NJT_OK;
    }
    ctx->r.s = s;
    ctx->r.addr_text = (tcc_str_t *)&s->connection->addr_text;

    njt_stream_proto_server_del_session(s, NJT_STREAM_OK, 0);
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
    if (sscf->connect_timeout != NJT_CONF_UNSET_MSEC)
    {
        njt_add_timer(c->read, sscf->connect_timeout);
    }
    r = njt_array_push(sscf->srv_ctx.client_list);
    *r = &ctx->r;

    if (sscf->client_update_interval > 0 && sscf->client_update_handler != NULL)
    {
        njt_add_timer(&ctx->timer, sscf->client_update_interval);
    }

    njt_stream_proto_server_read_handler(c->read);
    return;
end:
    njt_stream_proto_server_del_session(s, NJT_STREAM_INTERNAL_SERVER_ERROR, 1);
    return;
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
    njt_int_t msg_rc;
    njt_uint_t code = NJT_STREAM_OK;

    c = ev->data;
    s = c->data;
    sscf = njt_stream_get_module_srv_conf(s, njt_stream_proto_server_module);
    ctx = njt_stream_get_module_ctx(s, njt_stream_proto_server_module);
    if (ev->timedout)
    {
        njt_log_error(NJT_LOG_INFO, c->log, NJT_ETIMEDOUT, "client timed out");

        if (ctx->timer.timer_set)
        {
            njt_del_timer(&ctx->timer);
        }
        code = NJT_STREAM_OK;
        goto end;
    }

    if (ctx->r.status == TCC_SESSION_CLOSING)
    {
        njt_log_error(NJT_LOG_INFO, c->log, 0, "tcc close client");
        code = NJT_STREAM_OK;
        goto end;
    }

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
    if (sscf->message_handler)
    {
        for (;msg.len > 0;) {
            ctx->r.used_len = 0;
            msg_rc = NJT_OK;
            if (ctx->r.status == TCC_SESSION_CONNECT)
            {
                msg_rc = sscf->message_handler(&ctx->r, &msg);
            }
            if (ctx->r.status == TCC_SESSION_CLOSING || msg_rc == NJT_ERROR)
            {
                code = NJT_STREAM_OK;
                goto end;
            }
            if( ctx->r.used_len == 0) {
                break;
            }
            njt_stream_proto_server_update_in_buf(ctx,ctx->r.used_len);
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
            if(ctx->r.in_buf.start != NULL && msg_rc == NJT_AGAIN) {
                msg.data = ctx->r.in_buf.pos;
                msg.len = ctx->r.in_buf.last - ctx->r.in_buf.pos;
                continue;
            }
            break;
        }
    }
    if(rc == NJT_ERROR) {
        njt_log_error(NJT_LOG_INFO, c->log, 0, "tcc close client");
        code = NJT_STREAM_OK;
        goto end;
    }
    if (sscf->connect_timeout != NJT_CONF_UNSET_MSEC)
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

    if (njt_stream_top_filter(s, ctx->out_chain, 1) == NJT_ERROR)
    {
        return NJT_ERROR;
    }
    njt_chain_update_chains(c->pool, &ctx->free, busy, &ctx->out_chain,
                            (njt_buf_tag_t)&njt_stream_proto_server_module);

    if (*busy == NULL)
    {
        ctx->out_buf.pos = ctx->out_buf.start;
        ctx->out_buf.last = ctx->out_buf.start;
        njt_log_error(NJT_LOG_DEBUG, c->log, 0, "tcc send out ok!");
    }
    else
    {
        njt_log_error(NJT_LOG_DEBUG, c->log, 0, "tcc send out busy!");
    }

    if (njt_handle_write_event(ev, 0) != NJT_OK)
    {
        return NJT_ERROR;
    }

    njt_add_timer(ev, 5000);
    return NJT_OK;
}
static void
njt_stream_proto_server_write_handler(njt_event_t *ev)
{
    njt_int_t rc;
    njt_connection_t *c;
    njt_stream_session_t *s;

    rc = njt_stream_proto_server_write_data(ev);
    if (rc == NJT_ERROR) {
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

    njt_log_error((njt_uint_t)level, njt_cycle->log, 0, "%V", &msg);
}

int proto_server_send(tcc_stream_request_t *r, char *data, size_t len)
{

    njt_connection_t *c;
    njt_stream_proto_server_client_ctx_t *ctx;
    njt_stream_proto_server_srv_conf_t *sscf;
    njt_chain_t *cl;
    njt_int_t rc;
    njt_stream_session_t *s = r->s;
    u_char *p;
    size_t size;

    c = s->connection;
    sscf = njt_stream_get_module_srv_conf(s, njt_stream_proto_server_module);
    ctx = njt_stream_get_module_ctx(s, njt_stream_proto_server_module);
    if(ctx->r.status == TCC_SESSION_CLOSING) {
        return NJT_OK;
    }
    if (ctx->out_buf.start == 0)
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
    size = ctx->out_buf.end - ctx->out_buf.last;
    if (size < len)
    {
        return NJT_AGAIN;
    }
    else if (len > sscf->buffer_size)
    {
        njt_log_error(NJT_LOG_ERR, c->log, 0, "proto_buffer_size too small!");
        goto end;
    }
    cl = njt_chain_get_free_buf(c->pool, &ctx->free);
    if (cl == NULL)
    {
        goto end;
    }
    njt_memcpy(ctx->out_buf.last, data, len);
    ctx->out_buf.last = ctx->out_buf.last + len;
    cl->buf->tag = (njt_buf_tag_t)&njt_stream_proto_server_module;
    cl->buf->memory = 1;
    cl->buf->pos = ctx->out_buf.last - len;
    cl->buf->last = ctx->out_buf.last;
    cl->buf->last_buf = 1;
    cl->next = ctx->out_chain;
    ctx->out_chain = cl;

    rc = njt_stream_proto_server_write_data(c->write);
    return rc;
end:
    return NJT_ERROR;
}

int proto_server_send_broadcast(tcc_stream_server_ctx *srv_ctx, char *data, size_t len)
{

    tcc_stream_request_t **pr, *r;
    njt_uint_t i;
    njt_array_t *client_list;

    client_list = srv_ctx->client_list;
    pr = client_list->elts;

    for (i = 0; i < client_list->nelts; i++)
    {
        r = pr[i];
        proto_server_send(r, data, len);
    }
    return NJT_OK;
}
int proto_server_send_others(tcc_stream_request_t *sender, char *data, size_t len)
{

    tcc_stream_request_t **pr, *r;
    njt_uint_t i;
    njt_array_t *client_list;
    tcc_stream_server_ctx *srv_ctx = sender->tcc_server;

    client_list = srv_ctx->client_list;
    pr = client_list->elts;

    for (i = 0; i < client_list->nelts; i++)
    {
        r = pr[i];
        if(r != sender) {
            proto_server_send(r, data, len);
        }
    }
    return NJT_OK;
}

static njt_int_t njt_stream_proto_server_del_session(njt_stream_session_t *s, njt_uint_t code, njt_uint_t close_session)
{

    njt_array_t *client_list;
    njt_stream_proto_server_srv_conf_t *sscf;
    tcc_stream_request_t **pr, *r;
    njt_uint_t i;
    njt_stream_proto_server_client_ctx_t *ctx;
    njt_int_t rc;

    rc = NJT_ERROR;
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
            rc = NJT_OK;
        }
    }
    if (rc == NJT_OK && close_session == 1)
    {
        njt_stream_finalize_session(s, code);
    }
    return NJT_OK;
}

void *cli_malloc(tcc_stream_request_t *r, int len)
{
    if (r != NULL)
    {
        return njt_palloc(r->tcc_pool, len);
    }
    return NULL;
}
void cli_free(tcc_stream_request_t *r, void *p)
{
    if (r != NULL)
    {
        njt_pfree(r->tcc_pool, p);
    }
    return;
}
void *cli_realloc(tcc_stream_request_t *r, void *p, int len)
{
    if (r != NULL)
    {
        return njt_prealloc(r->tcc_pool, p, len);
    }
    return NULL;
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

void *srv_malloc(tcc_stream_server_ctx *srv, int len)
{
    if (srv != NULL)
    {
        return njt_palloc(srv->tcc_pool, len);
    }
    return NULL;
}
void srv_free(tcc_stream_server_ctx *srv, void *p)
{
    if (srv != NULL)
    {
        njt_pfree(srv->tcc_pool, p);
    }
    return;
}
void *srv_realloc(tcc_stream_server_ctx *srv, void *p, int len)
{
    if (srv != NULL)
    {
        return njt_prealloc(srv->tcc_pool, p, len);
    }
    return NULL;
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