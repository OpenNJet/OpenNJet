
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


typedef struct {
    njt_bufs_t  bufs;
} njt_http_copy_filter_conf_t;


#if (NJT_HAVE_FILE_AIO)
static void njt_http_copy_aio_handler(njt_output_chain_ctx_t *ctx,
    njt_file_t *file);
static void njt_http_copy_aio_event_handler(njt_event_t *ev);
#endif
#if (NJT_THREADS)
static njt_int_t njt_http_copy_thread_handler(njt_thread_task_t *task,
    njt_file_t *file);
static void njt_http_copy_thread_event_handler(njt_event_t *ev);
#endif

static void *njt_http_copy_filter_create_conf(njt_conf_t *cf);
static char *njt_http_copy_filter_merge_conf(njt_conf_t *cf,
    void *parent, void *child);
static njt_int_t njt_http_copy_filter_init(njt_conf_t *cf);


static njt_command_t  njt_http_copy_filter_commands[] = {

    { njt_string("output_buffers"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE2,
      njt_conf_set_bufs_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_copy_filter_conf_t, bufs),
      NULL },

      njt_null_command
};


static njt_http_module_t  njt_http_copy_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    njt_http_copy_filter_init,             /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_copy_filter_create_conf,      /* create location configuration */
    njt_http_copy_filter_merge_conf        /* merge location configuration */
};


njt_module_t  njt_http_copy_filter_module = {
    NJT_MODULE_V1,
    &njt_http_copy_filter_module_ctx,      /* module context */
    njt_http_copy_filter_commands,         /* module directives */
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


static njt_http_output_body_filter_pt    njt_http_next_body_filter;


static njt_int_t
njt_http_copy_filter(njt_http_request_t *r, njt_chain_t *in)
{
    njt_int_t                     rc;
    njt_connection_t             *c;
    njt_output_chain_ctx_t       *ctx;
    njt_http_core_loc_conf_t     *clcf;
    njt_http_copy_filter_conf_t  *conf;

    c = r->connection;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http copy filter: \"%V?%V\"", &r->uri, &r->args);

    ctx = njt_http_get_module_ctx(r, njt_http_copy_filter_module);

    if (ctx == NULL) {
        ctx = njt_pcalloc(r->pool, sizeof(njt_output_chain_ctx_t));
        if (ctx == NULL) {
            return NJT_ERROR;
        }

        njt_http_set_ctx(r, ctx, njt_http_copy_filter_module);

        conf = njt_http_get_module_loc_conf(r, njt_http_copy_filter_module);
        clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

        ctx->sendfile = c->sendfile;
        ctx->need_in_memory = r->main_filter_need_in_memory
                              || r->filter_need_in_memory;
        ctx->need_in_temp = r->filter_need_temporary;

        ctx->alignment = clcf->directio_alignment;

        ctx->pool = r->pool;
        ctx->bufs = conf->bufs;
        ctx->tag = (njt_buf_tag_t) &njt_http_copy_filter_module;

        ctx->output_filter = (njt_output_chain_filter_pt)
                                  njt_http_next_body_filter;
        ctx->filter_ctx = r;

#if (NJT_HAVE_FILE_AIO)
        if (njt_file_aio && clcf->aio == NJT_HTTP_AIO_ON) {
            ctx->aio_handler = njt_http_copy_aio_handler;
        }
#endif

#if (NJT_THREADS)
        if (clcf->aio == NJT_HTTP_AIO_THREADS) {
            ctx->thread_handler = njt_http_copy_thread_handler;
        }
#endif

        if (in && in->buf && njt_buf_size(in->buf)) {
            r->request_output = 1;
        }
    }

#if (NJT_HAVE_FILE_AIO || NJT_THREADS)
    ctx->aio = r->aio;
#endif

    rc = njt_output_chain(ctx, in);

    if (ctx->in == NULL) {
        r->buffered &= ~NJT_HTTP_COPY_BUFFERED;

    } else {
        r->buffered |= NJT_HTTP_COPY_BUFFERED;
    }

    njt_log_debug3(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http copy filter: %i \"%V?%V\"", rc, &r->uri, &r->args);

    return rc;
}


#if (NJT_HAVE_FILE_AIO)

static void
njt_http_copy_aio_handler(njt_output_chain_ctx_t *ctx, njt_file_t *file)
{
    njt_http_request_t *r;

    r = ctx->filter_ctx;

    file->aio->data = r;
    file->aio->handler = njt_http_copy_aio_event_handler;

    r->main->blocked++;
    r->aio = 1;
    ctx->aio = 1;
}


static void
njt_http_copy_aio_event_handler(njt_event_t *ev)
{
    njt_event_aio_t     *aio;
    njt_connection_t    *c;
    njt_http_request_t  *r;

    aio = ev->data;
    r = aio->data;
    c = r->connection;

    njt_http_set_log_request(c->log, r);

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http aio: \"%V?%V\"", &r->uri, &r->args);

    r->main->blocked--;
    r->aio = 0;

    r->write_event_handler(r);

    njt_http_run_posted_requests(c);
}

#endif


#if (NJT_THREADS)

static njt_int_t
njt_http_copy_thread_handler(njt_thread_task_t *task, njt_file_t *file)
{
    njt_str_t                  name;
    njt_connection_t          *c;
    njt_thread_pool_t         *tp;
    njt_http_request_t        *r;
    njt_output_chain_ctx_t    *ctx;
    njt_http_core_loc_conf_t  *clcf;

    r = file->thread_ctx;

    if (r->aio) {
        /*
         * tolerate sendfile() calls if another operation is already
         * running; this can happen due to subrequests, multiple calls
         * of the next body filter from a filter, or in HTTP/2 due to
         * a write event on the main connection
         */

        c = r->connection;

#if (NJT_HTTP_V2)
        if (r->stream) {
            c = r->stream->connection->connection;
        }
#endif

        if (task == c->sendfile_task) {
            return NJT_OK;
        }
    }

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);
    tp = clcf->thread_pool;

    if (tp == NULL) {
        if (njt_http_complex_value(r, clcf->thread_pool_value, &name)
            != NJT_OK)
        {
            return NJT_ERROR;
        }

        tp = njt_thread_pool_get((njt_cycle_t *) njt_cycle, &name);

        if (tp == NULL) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "thread pool \"%V\" not found", &name);
            return NJT_ERROR;
        }
    }

    task->event.data = r;
    task->event.handler = njt_http_copy_thread_event_handler;

    if (njt_thread_task_post(tp, task) != NJT_OK) {
        return NJT_ERROR;
    }

    r->main->blocked++;
    r->aio = 1;

    ctx = njt_http_get_module_ctx(r, njt_http_copy_filter_module);
    ctx->aio = 1;

    return NJT_OK;
}


static void
njt_http_copy_thread_event_handler(njt_event_t *ev)
{
    njt_connection_t    *c;
    njt_http_request_t  *r;

    r = ev->data;
    c = r->connection;

    njt_http_set_log_request(c->log, r);

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http thread: \"%V?%V\"", &r->uri, &r->args);

    r->main->blocked--;
    r->aio = 0;

#if (NJT_HTTP_V2)

    if (r->stream) {
        /*
         * for HTTP/2, update write event to make sure processing will
         * reach the main connection to handle sendfile() in threads
         */

        c->write->ready = 1;
        c->write->active = 0;
    }

#endif

    if (r->done) {
        /*
         * trigger connection event handler if the subrequest was
         * already finalized; this can happen if the handler is used
         * for sendfile() in threads
         */

        c->write->handler(c->write);

    } else {
        r->write_event_handler(r);
        njt_http_run_posted_requests(c);
    }
}

#endif


static void *
njt_http_copy_filter_create_conf(njt_conf_t *cf)
{
    njt_http_copy_filter_conf_t *conf;

    conf = njt_palloc(cf->pool, sizeof(njt_http_copy_filter_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->bufs.num = 0;

    return conf;
}


static char *
njt_http_copy_filter_merge_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_copy_filter_conf_t *prev = parent;
    njt_http_copy_filter_conf_t *conf = child;

    njt_conf_merge_bufs_value(conf->bufs, prev->bufs, 2, 32768);

    return NULL;
}


static njt_int_t
njt_http_copy_filter_init(njt_conf_t *cf)
{
    njt_http_next_body_filter = njt_http_top_body_filter;
    njt_http_top_body_filter = njt_http_copy_filter;

    return NJT_OK;
}

