
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>


typedef struct {
    njt_stream_complex_value_t   text;
} njt_stream_return_srv_conf_t;


typedef struct {
    njt_chain_t                 *out;
} njt_stream_return_ctx_t;


static void njt_stream_return_handler(njt_stream_session_t *s);
static void njt_stream_return_write_handler(njt_event_t *ev);

static void *njt_stream_return_create_srv_conf(njt_conf_t *cf);
static char *njt_stream_return(njt_conf_t *cf, njt_command_t *cmd, void *conf);


static njt_command_t  njt_stream_return_commands[] = {

    { njt_string("return"),
      NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_stream_return,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      njt_null_command
};


static njt_stream_module_t  njt_stream_return_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    njt_stream_return_create_srv_conf,     /* create server configuration */
    NULL                                   /* merge server configuration */
};


njt_module_t  njt_stream_return_module = {
    NJT_MODULE_V1,
    &njt_stream_return_module_ctx,         /* module context */
    njt_stream_return_commands,            /* module directives */
    NJT_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};


static void
njt_stream_return_handler(njt_stream_session_t *s)
{
    njt_str_t                      text;
    njt_buf_t                     *b;
    njt_connection_t              *c;
    njt_stream_return_ctx_t       *ctx;
    njt_stream_return_srv_conf_t  *rscf;

    c = s->connection;

    c->log->action = "returning text";

    rscf = njt_stream_get_module_srv_conf(s, njt_stream_return_module);

    if (njt_stream_complex_value(s, &rscf->text, &text) != NJT_OK) {
        njt_stream_finalize_session(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0,
                   "stream return text: \"%V\"", &text);

    if (text.len == 0) {
        njt_stream_finalize_session(s, NJT_STREAM_OK);
        return;
    }

    ctx = njt_pcalloc(c->pool, sizeof(njt_stream_return_ctx_t));
    if (ctx == NULL) {
        njt_stream_finalize_session(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    njt_stream_set_ctx(s, ctx, njt_stream_return_module);

    b = njt_calloc_buf(c->pool);
    if (b == NULL) {
        njt_stream_finalize_session(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    b->memory = 1;
    b->pos = text.data;
    b->last = text.data + text.len;
    b->last_buf = 1;

    ctx->out = njt_alloc_chain_link(c->pool);
    if (ctx->out == NULL) {
        njt_stream_finalize_session(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->out->buf = b;
    ctx->out->next = NULL;

    c->write->handler = njt_stream_return_write_handler;

    njt_stream_return_write_handler(c->write);
}


static void
njt_stream_return_write_handler(njt_event_t *ev)
{
    njt_connection_t         *c;
    njt_stream_session_t     *s;
    njt_stream_return_ctx_t  *ctx;

    c = ev->data;
    s = c->data;

    if (ev->timedout) {
        njt_connection_error(c, NJT_ETIMEDOUT, "connection timed out");
        njt_stream_finalize_session(s, NJT_STREAM_OK);
        return;
    }

    ctx = njt_stream_get_module_ctx(s, njt_stream_return_module);

    if (njt_stream_top_filter(s, ctx->out, 1) == NJT_ERROR) {
        njt_stream_finalize_session(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->out = NULL;

    if (!c->buffered) {
        njt_log_debug0(NJT_LOG_DEBUG_STREAM, c->log, 0,
                       "stream return done sending");
        njt_stream_finalize_session(s, NJT_STREAM_OK);
        return;
    }

    if (njt_handle_write_event(ev, 0) != NJT_OK) {
        njt_stream_finalize_session(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    njt_add_timer(ev, 5000);
}


static void *
njt_stream_return_create_srv_conf(njt_conf_t *cf)
{
    njt_stream_return_srv_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_stream_return_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static char *
njt_stream_return(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_stream_return_srv_conf_t *rscf = conf;

    njt_str_t                           *value;
    njt_stream_core_srv_conf_t          *cscf;
    njt_stream_compile_complex_value_t   ccv;

    if (rscf->text.value.data) {
        return "is duplicate";
    }

    value = cf->args->elts;

    njt_memzero(&ccv, sizeof(njt_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &rscf->text;

    if (njt_stream_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    cscf = njt_stream_conf_get_module_srv_conf(cf, njt_stream_core_module);

    cscf->handler = njt_stream_return_handler;

    return NJT_CONF_OK;
}
