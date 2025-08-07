
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>
#include <njt_stream_util.h>

static njt_uint_t njt_stream_preread_can_peek(njt_connection_t *c);
static njt_int_t njt_stream_preread_peek(njt_stream_session_t *s,
    njt_stream_phase_handler_t *ph);
static njt_int_t njt_stream_preread(njt_stream_session_t *s,
    njt_stream_phase_handler_t *ph);
static njt_int_t njt_stream_core_preconfiguration(njt_conf_t *cf);
static void *njt_stream_core_create_main_conf(njt_conf_t *cf);
static char *njt_stream_core_init_main_conf(njt_conf_t *cf, void *conf);
static void *njt_stream_core_create_srv_conf(njt_conf_t *cf);
static char *njt_stream_core_merge_srv_conf(njt_conf_t *cf, void *parent,
    void *child);
static char *njt_stream_core_error_log(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_stream_core_server(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_stream_core_listen(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_stream_core_server_name(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_stream_core_resolver(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);


static njt_command_t  njt_stream_core_commands[] = {

    { njt_string("variables_hash_max_size"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_STREAM_MAIN_CONF_OFFSET,
      offsetof(njt_stream_core_main_conf_t, variables_hash_max_size),
      NULL },

    { njt_string("variables_hash_bucket_size"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_STREAM_MAIN_CONF_OFFSET,
      offsetof(njt_stream_core_main_conf_t, variables_hash_bucket_size),
      NULL },

      { njt_string("server_names_hash_max_size"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_STREAM_MAIN_CONF_OFFSET,
      offsetof(njt_stream_core_main_conf_t, server_names_hash_max_size),
      NULL },

    { njt_string("server_names_hash_bucket_size"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_STREAM_MAIN_CONF_OFFSET,
      offsetof(njt_stream_core_main_conf_t, server_names_hash_bucket_size),
      NULL },

    { njt_string("server"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_BLOCK|NJT_CONF_NOARGS,
      njt_stream_core_server,
      0,
      0,
      NULL },

    { njt_string("listen"),
      NJT_STREAM_SRV_CONF|NJT_CONF_1MORE,
      njt_stream_core_listen,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      { njt_string("server_name"),
      NJT_STREAM_SRV_CONF|NJT_CONF_1MORE,
      njt_stream_core_server_name,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("error_log"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_1MORE,
      njt_stream_core_error_log,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("resolver"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_1MORE,
      njt_stream_core_resolver,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("resolver_timeout"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_core_srv_conf_t, resolver_timeout),
      NULL },

    { njt_string("proxy_protocol_timeout"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_core_srv_conf_t, proxy_protocol_timeout),
      NULL },

    { njt_string("tcp_nodelay"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_core_srv_conf_t, tcp_nodelay),
      NULL },

    { njt_string("preread_buffer_size"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_core_srv_conf_t, preread_buffer_size),
      NULL },

    { njt_string("preread_timeout"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_core_srv_conf_t, preread_timeout),
      NULL },

      njt_null_command
};


static njt_stream_module_t  njt_stream_core_module_ctx = {
    njt_stream_core_preconfiguration,      /* preconfiguration */
    NULL,                                  /* postconfiguration */

    njt_stream_core_create_main_conf,      /* create main configuration */
    njt_stream_core_init_main_conf,        /* init main configuration */

    njt_stream_core_create_srv_conf,       /* create server configuration */
    njt_stream_core_merge_srv_conf         /* merge server configuration */
};


njt_module_t  njt_stream_core_module = {
    NJT_MODULE_V1,
    &njt_stream_core_module_ctx,           /* module context */
    njt_stream_core_commands,              /* module directives */
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


void
njt_stream_core_run_phases(njt_stream_session_t *s)
{
    njt_int_t                     rc;
    njt_stream_phase_handler_t   *ph;
    njt_stream_core_main_conf_t  *cmcf;

    cmcf = njt_stream_get_module_main_conf(s, njt_stream_core_module);

    ph = cmcf->phase_engine.handlers;

    while (ph[s->phase_handler].checker) {

        rc = ph[s->phase_handler].checker(s, &ph[s->phase_handler]);

        if (rc == NJT_OK) {
            return;
        }
    }
}


njt_int_t
njt_stream_core_generic_phase(njt_stream_session_t *s,
    njt_stream_phase_handler_t *ph)
{
    njt_int_t  rc;

    /*
     * generic phase checker,
     * used by all phases, except for preread and content
     */

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "generic phase: %ui", s->phase_handler);

    rc = ph->handler(s);

    if (rc == NJT_OK) {
        s->phase_handler = ph->next;
        return NJT_AGAIN;
    }

    if (rc == NJT_DECLINED) {
        s->phase_handler++;
        return NJT_AGAIN;
    }

    if (rc == NJT_AGAIN || rc == NJT_DONE) {
        return NJT_OK;
    }

    if (rc == NJT_ERROR) {
        rc = NJT_STREAM_INTERNAL_SERVER_ERROR;
    }

    njt_stream_finalize_session(s, rc);

    return NJT_OK;
}


njt_int_t
njt_stream_core_preread_phase(njt_stream_session_t *s,
    njt_stream_phase_handler_t *ph)
{
    njt_int_t                    rc;
    njt_connection_t            *c;
    njt_stream_core_srv_conf_t  *cscf;

    c = s->connection;

    c->log->action = "prereading client data";

    cscf = njt_stream_get_module_srv_conf(s, njt_stream_core_module);

    if (c->read->timedout) {
        rc = NJT_STREAM_OK;
        goto done;
    }

    if (!c->read->timer_set) {
        rc = ph->handler(s);
        if (rc != NJT_AGAIN) {
            goto done;
        }
    }

    if (c->buffer == NULL) {
        c->buffer = njt_create_temp_buf(c->pool, cscf->preread_buffer_size);
        if (c->buffer == NULL) {
            rc = NJT_ERROR;
            goto done;
        }
    }

    if (njt_stream_preread_can_peek(c)) {
        rc = njt_stream_preread_peek(s, ph);

    } else {
        rc = njt_stream_preread(s, ph);
    }

done:

    if (rc == NJT_AGAIN) {
        if (njt_handle_read_event(c->read, 0) != NJT_OK) {
            njt_stream_finalize_session(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return NJT_OK;
        }

        if (!c->read->timer_set) {
            njt_add_timer(c->read, cscf->preread_timeout);
        }

        c->read->handler = njt_stream_session_handler;

        return NJT_OK;
    }

    if (c->read->timer_set) {
        njt_del_timer(c->read);
    }

    if (rc == NJT_OK) {
        s->phase_handler = ph->next;
        return NJT_AGAIN;
    }

    if (rc == NJT_DECLINED) {
        s->phase_handler++;
        return NJT_AGAIN;
    }

    if (rc == NJT_DONE) {
        return NJT_OK;
    }

    if (rc == NJT_ERROR) {
        rc = NJT_STREAM_INTERNAL_SERVER_ERROR;
    }

    njt_stream_finalize_session(s, rc);

    return NJT_OK;
}


static njt_uint_t
njt_stream_preread_can_peek(njt_connection_t *c)
{
#if (NJT_STREAM_SSL)
    if (c->ssl) {
        return 0;
    }
#endif

    if ((njt_event_flags & NJT_USE_CLEAR_EVENT) == 0) {
        return 0;
    }

#if (NJT_HAVE_KQUEUE)
    if (njt_event_flags & NJT_USE_KQUEUE_EVENT) {
        return 1;
    }
#endif

#if (NJT_HAVE_EPOLLRDHUP)
    if ((njt_event_flags & NJT_USE_EPOLL_EVENT) && njt_use_epoll_rdhup) {
        return 1;
    }
#endif

    return 0;
}


static njt_int_t
njt_stream_preread_peek(njt_stream_session_t *s, njt_stream_phase_handler_t *ph)
{
    ssize_t            n;
    njt_int_t          rc;
    njt_err_t          err;
    njt_connection_t  *c;

    c = s->connection;

    n = recv(c->fd, (char *) c->buffer->last,
             c->buffer->end - c->buffer->last, MSG_PEEK);

    err = njt_socket_errno;

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0, "stream recv(): %z", n);

    if (n == -1) {
        if (err == NJT_EAGAIN) {
            c->read->ready = 0;
            return NJT_AGAIN;
        }

        njt_connection_error(c, err, "recv() failed");
        return NJT_STREAM_OK;
    }

    if (n == 0) {
        return NJT_STREAM_OK;
    }

    c->buffer->last += n;

    rc = ph->handler(s);

    if (rc != NJT_AGAIN) {
        c->buffer->last = c->buffer->pos;
        return rc;
    }

    if (c->buffer->last == c->buffer->end) {
        njt_log_error(NJT_LOG_ERR, c->log, 0, "preread buffer full");
        return NJT_STREAM_BAD_REQUEST;
    }

    if (c->read->pending_eof) {
        return NJT_STREAM_OK;
    }

    c->buffer->last = c->buffer->pos;

    return NJT_AGAIN;
}


static njt_int_t
njt_stream_preread(njt_stream_session_t *s, njt_stream_phase_handler_t *ph)
{
    ssize_t            n;
    njt_int_t          rc;
    njt_connection_t  *c;

    c = s->connection;

    while (c->read->ready) {

        n = c->recv(c, c->buffer->last, c->buffer->end - c->buffer->last);

        if (n == NJT_AGAIN) {
            return NJT_AGAIN;
        }

        if (n == NJT_ERROR || n == 0) {
            return NJT_STREAM_OK;
        }

        c->buffer->last += n;

        rc = ph->handler(s);

        if (rc != NJT_AGAIN) {
            return rc;
        }

        if (c->buffer->last == c->buffer->end) {
            njt_log_error(NJT_LOG_ERR, c->log, 0, "preread buffer full");
            return NJT_STREAM_BAD_REQUEST;
        }
    }

    return NJT_AGAIN;
}


njt_int_t
njt_stream_core_content_phase(njt_stream_session_t *s,
    njt_stream_phase_handler_t *ph)
{
    njt_connection_t            *c;
    njt_stream_core_srv_conf_t  *cscf;

    c = s->connection;

    c->log->action = NULL;

    cscf = njt_stream_get_module_srv_conf(s, njt_stream_core_module);

    if (c->type == SOCK_STREAM
        && cscf->tcp_nodelay
        && njt_tcp_nodelay(c) != NJT_OK)
    {
        njt_stream_finalize_session(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return NJT_OK;
    }

    if (cscf->handler == NULL) {
        njt_log_debug0(NJT_LOG_DEBUG_STREAM, c->log, 0,
                       "no handler for server");
        njt_stream_finalize_session(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return NJT_OK;
    }

    cscf->handler(s);

    return NJT_OK;
}


njt_int_t
njt_stream_validate_host(njt_str_t *host, njt_pool_t *pool, njt_uint_t alloc)
{
    u_char  *h, ch;
    size_t   i, dot_pos, host_len;

    enum {
        sw_usual = 0,
        sw_literal,
        sw_rest
    } state;

    dot_pos = host->len;
    host_len = host->len;

    h = host->data;

    state = sw_usual;

    for (i = 0; i < host->len; i++) {
        ch = h[i];

        switch (ch) {

        case '.':
            if (dot_pos == i - 1) {
                return NJT_DECLINED;
            }
            dot_pos = i;
            break;

        case ':':
            if (state == sw_usual) {
                host_len = i;
                state = sw_rest;
            }
            break;

        case '[':
            if (i == 0) {
                state = sw_literal;
            }
            break;

        case ']':
            if (state == sw_literal) {
                host_len = i + 1;
                state = sw_rest;
            }
            break;

        default:

            if (njt_path_separator(ch)) {
                return NJT_DECLINED;
            }

            if (ch <= 0x20 || ch == 0x7f) {
                return NJT_DECLINED;
            }

            if (ch >= 'A' && ch <= 'Z') {
                alloc = 1;
            }

            break;
        }
    }

    if (dot_pos == host_len - 1) {
        host_len--;
    }

    if (host_len == 0) {
        return NJT_DECLINED;
    }

    if (alloc) {
        host->data = njt_pnalloc(pool, host_len);
        if (host->data == NULL) {
            return NJT_ERROR;
        }

        njt_strlow(host->data, h, host_len);
    }

    host->len = host_len;

    return NJT_OK;
}


njt_int_t
njt_stream_find_virtual_server(njt_stream_session_t *s,
    njt_str_t *host, njt_stream_core_srv_conf_t **cscfp)
{
    njt_stream_core_srv_conf_t  *cscf;

    if (s->virtual_names == NULL) {
        return NJT_DECLINED;
    }

    cscf = njt_hash_find_combined(&s->virtual_names->names,
                                  njt_hash_key(host->data, host->len),
                                  host->data, host->len);

    if (cscf) {
        *cscfp = cscf;
        return NJT_OK;
    }

#if (NJT_PCRE)

    if (host->len && s->virtual_names->nregex) {
        njt_int_t                  n;
        njt_uint_t                 i;
        njt_stream_server_name_t  *sn;

        sn = s->virtual_names->regex;

        for (i = 0; i < s->virtual_names->nregex; i++) {

            n = njt_stream_regex_exec(s, sn[i].regex, host);

            if (n == NJT_DECLINED) {
                continue;
            }

            if (n == NJT_OK) {
                *cscfp = sn[i].server;
                return NJT_OK;
            }

            return NJT_ERROR;
        }
    }

#endif /* NJT_PCRE */

    return NJT_DECLINED;
}


static njt_int_t
njt_stream_core_preconfiguration(njt_conf_t *cf)
{
    return njt_stream_variables_add_core_vars(cf);
}


static void *
njt_stream_core_create_main_conf(njt_conf_t *cf)
{
    njt_stream_core_main_conf_t  *cmcf;

    cmcf = njt_pcalloc(cf->pool, sizeof(njt_stream_core_main_conf_t));
    if (cmcf == NULL) {
        return NULL;
    }

    if (njt_array_init(&cmcf->servers, cf->pool, 4,
                       sizeof(njt_stream_core_srv_conf_t *))
        != NJT_OK)
    {
        return NULL;
    }

    cmcf->server_names_hash_max_size = NJT_CONF_UNSET_UINT;
    cmcf->server_names_hash_bucket_size = NJT_CONF_UNSET_UINT;

    cmcf->variables_hash_max_size = NJT_CONF_UNSET_UINT;
    cmcf->variables_hash_bucket_size = NJT_CONF_UNSET_UINT;

    return cmcf;
}


static char *
njt_stream_core_init_main_conf(njt_conf_t *cf, void *conf)
{
    njt_stream_core_main_conf_t *cmcf = conf;

    njt_conf_init_uint_value(cmcf->server_names_hash_max_size, 512);
    njt_conf_init_uint_value(cmcf->server_names_hash_bucket_size,
                             njt_cacheline_size);

    cmcf->server_names_hash_bucket_size =
            njt_align(cmcf->server_names_hash_bucket_size, njt_cacheline_size);


    njt_conf_init_uint_value(cmcf->variables_hash_max_size, 1024);
    njt_conf_init_uint_value(cmcf->variables_hash_bucket_size, 64);

    cmcf->variables_hash_bucket_size =
               njt_align(cmcf->variables_hash_bucket_size, njt_cacheline_size);

    if (cmcf->ncaptures) {
        cmcf->ncaptures = (cmcf->ncaptures + 1) * 3;
    }

    return NJT_CONF_OK;
}


static void *
njt_stream_core_create_srv_conf(njt_conf_t *cf)
{
    njt_stream_core_srv_conf_t  *cscf;

    cscf = njt_pcalloc(cf->pool, sizeof(njt_stream_core_srv_conf_t));
    if (cscf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     cscf->handler = NULL;
     *     cscf->error_log = NULL;
     */

    if (njt_array_init(&cscf->server_names, cf->temp_pool, 4,
                       sizeof(njt_stream_server_name_t))
        != NJT_OK)
    {
        return NULL;
    }

    cscf->file_name = cf->conf_file->file.name.data;
    cscf->line = cf->conf_file->line;
    cscf->resolver_timeout = NJT_CONF_UNSET_MSEC;
    cscf->proxy_protocol_timeout = NJT_CONF_UNSET_MSEC;
    cscf->tcp_nodelay = NJT_CONF_UNSET;
    cscf->preread_buffer_size = NJT_CONF_UNSET_SIZE;
    cscf->preread_timeout = NJT_CONF_UNSET_MSEC;
#if (NJT_STREAM_DYNAMIC_SERVER)
    cscf->pool=cf->pool;  // cx 澶勭悊鍐呭瓨閲婃斁
#endif
    return cscf;
}


static char *
njt_stream_core_merge_srv_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_stream_core_srv_conf_t *prev = parent;
    njt_stream_core_srv_conf_t *conf = child;

    njt_str_t                  name;
    njt_stream_server_name_t  *sn;

    njt_conf_merge_msec_value(conf->resolver_timeout,
                              prev->resolver_timeout, 30000);

    if (conf->resolver == NULL) {

        if (prev->resolver == NULL) {

            /*
             * create dummy resolver in stream {} context
             * to inherit it in all servers
             */

            prev->resolver = njt_resolver_create(cf, NULL, 0);
            if (prev->resolver == NULL) {
                return NJT_CONF_ERROR;
            }
        }

        conf->resolver = prev->resolver;
    }

    if (conf->error_log == NULL) {
        if (prev->error_log) {
            conf->error_log = prev->error_log;
        } else {
            conf->error_log = &cf->cycle->new_log;
        }
    }

    njt_conf_merge_msec_value(conf->proxy_protocol_timeout,
                              prev->proxy_protocol_timeout, 30000);

    njt_conf_merge_value(conf->tcp_nodelay, prev->tcp_nodelay, 1);

    njt_conf_merge_size_value(conf->preread_buffer_size,
                              prev->preread_buffer_size, 16384);

    njt_conf_merge_msec_value(conf->preread_timeout,
                              prev->preread_timeout, 30000);

    if (conf->server_names.nelts == 0) {
        /* the array has 4 empty preallocated elements, so push cannot fail */
        sn = njt_array_push(&conf->server_names);
#if (NJT_PCRE)
        sn->regex = NULL;
#endif
        sn->server = conf;
        njt_str_set(&sn->name, "");
#if (NJT_STREAM_DYNAMIC_SERVER) 
        sn->full_name = sn->name;
#endif
    }

    sn = conf->server_names.elts;
    name = sn[0].name;

#if (NJT_PCRE)
    if (sn->regex) {
        name.len++;
        name.data--;
    } else
#endif

    if (name.data[0] == '.') {
        name.len--;
        name.data++;
    }

    conf->server_name.len = name.len;
    conf->server_name.data = njt_pstrdup(cf->pool, &name);
    if (conf->server_name.data == NULL) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


static char *
njt_stream_core_error_log(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_stream_core_srv_conf_t  *cscf = conf;

    return njt_log_set_log(cf, &cscf->error_log);
}


static char *
njt_stream_core_server(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char                         *rv;
    void                         *mconf;
    njt_uint_t                    m;
    njt_conf_t                    pcf;
    njt_stream_module_t          *module;
    njt_stream_conf_ctx_t        *ctx, *stream_ctx;
    njt_stream_core_srv_conf_t   *cscf, **cscfp;
    njt_stream_core_main_conf_t  *cmcf;

#if (NJT_STREAM_DYNAMIC_SERVER)
    njt_int_t rc;
    njt_pool_t *old_server_pool,*new_server_pool,*old_server_temp_pool;
    old_server_pool = cf->pool;
    old_server_temp_pool = cf->temp_pool;
    new_server_pool = njt_create_dynamic_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
    if (new_server_pool == NULL) {
        return NJT_CONF_ERROR;
    }
    rc = njt_sub_pool(cf->cycle->pool,new_server_pool);
    if (rc != NJT_OK) {
        njt_destroy_pool(new_server_pool);
        return NJT_CONF_ERROR;
    }
    cf->pool = new_server_pool;
    cf->temp_pool = new_server_pool;

     njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                          "create server=%p",cf->pool);
#endif

    ctx = njt_pcalloc(cf->pool, sizeof(njt_stream_conf_ctx_t));
    if (ctx == NULL) {
        return NJT_CONF_ERROR;
    }

    stream_ctx = cf->ctx;
    ctx->main_conf = stream_ctx->main_conf;

    /* the server{}'s srv_conf */

    ctx->srv_conf = njt_pcalloc(cf->pool,
                                sizeof(void *) * njt_stream_max_module);
    if (ctx->srv_conf == NULL) {
        return NJT_CONF_ERROR;
    }

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NJT_STREAM_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        if (module->create_srv_conf) {
            mconf = module->create_srv_conf(cf);
            if (mconf == NULL) {
                return NJT_CONF_ERROR;
            }

            ctx->srv_conf[cf->cycle->modules[m]->ctx_index] = mconf;
        }
    }

    /* the server configuration context */

    cscf = ctx->srv_conf[njt_stream_core_module.ctx_index];
    cscf->ctx = ctx;

    cmcf = ctx->main_conf[njt_stream_core_module.ctx_index];

    cscfp = njt_array_push(&cmcf->servers);
    if (cscfp == NULL) {
        return NJT_CONF_ERROR;
    }

    *cscfp = cscf;


    /* parse inside server{} */

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NJT_STREAM_SRV_CONF;

    rv = njt_conf_parse(cf, NULL);

    *cf = pcf;

#if (NJT_STREAM_DYNAMIC_SERVER)
    cscf->pool = new_server_pool;
    cscf->dynamic = cf->dynamic;
    cscf->dynamic_status = cf->dynamic;  // 1 
    cf->pool = old_server_pool;
    cf->temp_pool = old_server_temp_pool;
#endif
    if (rv == NJT_CONF_OK && !cscf->listen) {
        njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                      "no \"listen\" is defined for server in %s:%ui",
                      cscf->file_name, cscf->line);
        return NJT_CONF_ERROR;
    }

    return rv;
}


static char *
njt_stream_core_listen(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_stream_core_srv_conf_t  *cscf = conf;

    njt_str_t                *value, size;
    njt_url_t                 u;
    njt_uint_t                i, n, backlog;
    njt_stream_listen_opt_t   lsopt;

    cscf->listen = 1;

    value = cf->args->elts;

    njt_memzero(&u, sizeof(njt_url_t));

    u.url = value[1];
    u.listen = 1;

    if (njt_parse_url(cf->pool, &u) != NJT_OK) {
        if (u.err) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "%s in \"%V\" of the \"listen\" directive",
                               u.err, &u.url);
        }

        return NJT_CONF_ERROR;
    }

    njt_memzero(&lsopt, sizeof(njt_stream_listen_opt_t));

    lsopt.backlog = NJT_LISTEN_BACKLOG;
    lsopt.type = SOCK_STREAM;
    lsopt.rcvbuf = -1;
    lsopt.sndbuf = -1;
#if (NJT_HAVE_SETFIB)
    lsopt.setfib = -1;
#endif
#if (NJT_HAVE_TCP_FASTOPEN)
    lsopt.fastopen = -1;
#endif
#if (NJT_HAVE_INET6)
    lsopt.ipv6only = 1;
#endif

    backlog = 0;

    for (i = 2; i < cf->args->nelts; i++) {

        if (njt_strcmp(value[i].data, "default_server") == 0) {
            lsopt.default_server = 1;
            continue;
        }

#if !(NJT_WIN32)
        if (njt_strcmp(value[i].data, "udp") == 0) {
            lsopt.type = SOCK_DGRAM;
            continue;
        }
#endif

        if (njt_strcmp(value[i].data, "bind") == 0) {
            lsopt.set = 1;
            lsopt.bind = 1;
            continue;
        }

        //add by clb, used for udp and tcp traffic hack
        if (njt_strcmp(value[i].data, "mesh") == 0) {
            lsopt.mesh = 1;
            continue;
        }
        //end add by clb

#if (NJT_HAVE_SETFIB)
        if (njt_strncmp(value[i].data, "setfib=", 7) == 0) {
            lsopt.setfib = njt_atoi(value[i].data + 7, value[i].len - 7);
            lsopt.set = 1;
            lsopt.bind = 1;

            if (lsopt.setfib == NJT_ERROR) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid setfib \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            continue;
        }
#endif

#if (NJT_HAVE_TCP_FASTOPEN)
        if (njt_strncmp(value[i].data, "fastopen=", 9) == 0) {
            lsopt.fastopen = njt_atoi(value[i].data + 9, value[i].len - 9);
            lsopt.set = 1;
            lsopt.bind = 1;

            if (lsopt.fastopen == NJT_ERROR) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid fastopen \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            continue;
        }
#endif

        if (njt_strncmp(value[i].data, "backlog=", 8) == 0) {
            lsopt.backlog = njt_atoi(value[i].data + 8, value[i].len - 8);
            lsopt.set = 1;
            lsopt.bind = 1;

            if (lsopt.backlog == NJT_ERROR || lsopt.backlog == 0) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid backlog \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            backlog = 1;

            continue;
        }

        if (njt_strncmp(value[i].data, "rcvbuf=", 7) == 0) {
            size.len = value[i].len - 7;
            size.data = value[i].data + 7;

            lsopt.rcvbuf = njt_parse_size(&size);
            lsopt.set = 1;
            lsopt.bind = 1;

            if (lsopt.rcvbuf == NJT_ERROR) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid rcvbuf \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "sndbuf=", 7) == 0) {
            size.len = value[i].len - 7;
            size.data = value[i].data + 7;

            lsopt.sndbuf = njt_parse_size(&size);
            lsopt.set = 1;
            lsopt.bind = 1;

            if (lsopt.sndbuf == NJT_ERROR) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid sndbuf \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "accept_filter=", 14) == 0) {
#if (NJT_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
            lsopt.accept_filter = (char *) &value[i].data[14];
            lsopt.set = 1;
            lsopt.bind = 1;
#else
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "accept filters \"%V\" are not supported "
                               "on this platform, ignored",
                               &value[i]);
#endif
            continue;
        }

        if (njt_strcmp(value[i].data, "deferred") == 0) {
#if (NJT_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
            lsopt.deferred_accept = 1;
            lsopt.set = 1;
            lsopt.bind = 1;
#else
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "the deferred accept is not supported "
                               "on this platform, ignored");
#endif
            continue;
        }

        if (njt_strncmp(value[i].data, "ipv6only=o", 10) == 0) {
#if (NJT_HAVE_INET6 && defined IPV6_V6ONLY)
            if (njt_strcmp(&value[i].data[10], "n") == 0) {
                lsopt.ipv6only = 1;

            } else if (njt_strcmp(&value[i].data[10], "ff") == 0) {
                lsopt.ipv6only = 0;

            } else {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid ipv6only flags \"%s\"",
                                   &value[i].data[9]);
                return NJT_CONF_ERROR;
            }

            lsopt.set = 1;
            lsopt.bind = 1;
            continue;
#else
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "ipv6only is not supported "
                               "on this platform");
            return NJT_CONF_ERROR;
#endif
        }

        if (njt_strcmp(value[i].data, "reuseport") == 0) {
#if (NJT_HAVE_REUSEPORT)
            lsopt.reuseport = 1;
            lsopt.set = 1;
            lsopt.bind = 1;
#else
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "reuseport is not supported "
                               "on this platform, ignored");
#endif
            continue;
        }

        if (njt_strcmp(value[i].data, "ssl") == 0) {
#if (NJT_STREAM_SSL)
            lsopt.ssl = 1;
            continue;
#else
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "the \"ssl\" parameter requires "
                               "njt_stream_ssl_module");
            return NJT_CONF_ERROR;
#endif
        }

        if (njt_strncmp(value[i].data, "so_keepalive=", 13) == 0) {

            if (njt_strcmp(&value[i].data[13], "on") == 0) {
                lsopt.so_keepalive = 1;

            } else if (njt_strcmp(&value[i].data[13], "off") == 0) {
                lsopt.so_keepalive = 2;

            } else {

#if (NJT_HAVE_KEEPALIVE_TUNABLE)
                u_char     *p, *end;
                njt_str_t   s;

                end = value[i].data + value[i].len;
                s.data = value[i].data + 13;

                p = njt_strlchr(s.data, end, ':');
                if (p == NULL) {
                    p = end;
                }

                if (p > s.data) {
                    s.len = p - s.data;

                    lsopt.tcp_keepidle = njt_parse_time(&s, 1);
                    if (lsopt.tcp_keepidle == (time_t) NJT_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                s.data = (p < end) ? (p + 1) : end;

                p = njt_strlchr(s.data, end, ':');
                if (p == NULL) {
                    p = end;
                }

                if (p > s.data) {
                    s.len = p - s.data;

                    lsopt.tcp_keepintvl = njt_parse_time(&s, 1);
                    if (lsopt.tcp_keepintvl == (time_t) NJT_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                s.data = (p < end) ? (p + 1) : end;

                if (s.data < end) {
                    s.len = end - s.data;

                    lsopt.tcp_keepcnt = njt_atoi(s.data, s.len);
                    if (lsopt.tcp_keepcnt == NJT_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                if (lsopt.tcp_keepidle == 0 && lsopt.tcp_keepintvl == 0
                    && lsopt.tcp_keepcnt == 0)
                {
                    goto invalid_so_keepalive;
                }

                lsopt.so_keepalive = 1;

#else

                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "the \"so_keepalive\" parameter accepts "
                                   "only \"on\" or \"off\" on this platform");
                return NJT_CONF_ERROR;

#endif
            }

            lsopt.set = 1;
            lsopt.bind = 1;

            continue;

#if (NJT_HAVE_KEEPALIVE_TUNABLE)
        invalid_so_keepalive:

            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid so_keepalive value: \"%s\"",
                               &value[i].data[13]);
            return NJT_CONF_ERROR;
#endif
        }

        if (njt_strcmp(value[i].data, "proxy_protocol") == 0) {
            lsopt.proxy_protocol = 1;
            continue;
        }

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NJT_CONF_ERROR;
    }

    if (lsopt.type == SOCK_DGRAM) {
#if (NJT_HAVE_TCP_FASTOPEN)
        if (lsopt.fastopen != -1) {
            return "\"fastopen\" parameter is incompatible with \"udp\"";
        }
#endif

        if (backlog) {
            return "\"backlog\" parameter is incompatible with \"udp\"";
        }

#if (NJT_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
        if (lsopt.accept_filter) {
            return "\"accept_filter\" parameter is incompatible with \"udp\"";
        }

#endif

#if (NJT_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
        if (lsopt.deferred_accept) {
            return "\"deferred\" parameter is incompatible with \"udp\"";
        }
#endif

#if (NJT_STREAM_SSL)
        if (lsopt.ssl) {
            return "\"ssl\" parameter is incompatible with \"udp\"";
        }
#endif

        if (lsopt.so_keepalive) {
            return "\"so_keepalive\" parameter is incompatible with \"udp\"";
        }

        if (lsopt.proxy_protocol) {
            return "\"proxy_protocol\" parameter is incompatible with \"udp\"";
        }
    }

    for (n = 0; n < u.naddrs; n++) {

        for (i = 0; i < n; i++) {
            if (njt_cmp_sockaddr(u.addrs[n].sockaddr, u.addrs[n].socklen,
                                 u.addrs[i].sockaddr, u.addrs[i].socklen, 1)
                == NJT_OK)
            {
                goto next;
            }
        }

        lsopt.sockaddr = u.addrs[n].sockaddr;
        lsopt.socklen = u.addrs[n].socklen;
        lsopt.addr_text = u.addrs[n].name;
        lsopt.wildcard = njt_inet_wildcard(lsopt.sockaddr);

        if (njt_stream_add_listen(cf, cscf, &lsopt) != NJT_OK) {
            return NJT_CONF_ERROR;
        }

    next:
        continue;
    }

    return NJT_CONF_OK;
}


static char *
njt_stream_core_server_name(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_stream_core_srv_conf_t *cscf = conf;

    u_char                     ch;
    njt_str_t                 *value;
    njt_uint_t                 i;
    njt_stream_server_name_t  *sn;
#if (NJT_STREAM_DYNAMIC_SERVER) 
     njt_str_t                 *ori_value;
      ori_value = cf->ori_args->elts;
#endif
    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        ch = value[i].data[0];

        if ((ch == '*' && (value[i].len < 3 || value[i].data[1] != '.'))
            || (ch == '.' && value[i].len < 2))
        {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "server name \"%V\" is invalid", &value[i]);
            return NJT_CONF_ERROR;
        }

        if (njt_strchr(value[i].data, '/')) {
            njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                               "server name \"%V\" has suspicious symbols",
                               &value[i]);
        }
#if (NJT_STREAM_DYNAMIC_SERVER) 
         if(cf->dynamic == 1  && cscf->server_names.nelts >= 1) {
             njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "dynamic server only support one name!");
            return NJT_CONF_ERROR;
        }
#endif
        sn = njt_array_push(&cscf->server_names);
        if (sn == NULL) {
            return NJT_CONF_ERROR;
        }

#if (NJT_PCRE)
        sn->regex = NULL;
#endif
        sn->server = cscf;

        if (njt_strcasecmp(value[i].data, (u_char *) "$hostname") == 0) {
            sn->name = cf->cycle->hostname;
#if (NJT_STREAM_DYNAMIC_SERVER) 
        sn->full_name = sn->name;
#endif
        } else {
            sn->name = value[i];
#if (NJT_STREAM_DYNAMIC_SERVER) 
        sn->full_name = ori_value[i];
#endif
        }

        if (value[i].data[0] != '~') {
            njt_strlow(sn->name.data, sn->name.data, sn->name.len);
            continue;
        }

#if (NJT_PCRE)
        {
        u_char               *p;
        njt_regex_compile_t   rc;
        u_char                errstr[NJT_MAX_CONF_ERRSTR];

        if (value[i].len == 1) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "empty regex in server name \"%V\"", &value[i]);
            return NJT_CONF_ERROR;
        }

        value[i].len--;
        value[i].data++;

        njt_memzero(&rc, sizeof(njt_regex_compile_t));

        rc.pattern = value[i];
        rc.err.len = NJT_MAX_CONF_ERRSTR;
        rc.err.data = errstr;

        for (p = value[i].data; p < value[i].data + value[i].len; p++) {
            if (*p >= 'A' && *p <= 'Z') {
                rc.options = NJT_REGEX_CASELESS;
                break;
            }
        }

        sn->regex = njt_stream_regex_compile(cf, &rc);
        if (sn->regex == NULL) {
            return NJT_CONF_ERROR;
        }

        sn->name = value[i];
        cscf->captures = (rc.captures > 0);
        }
#else
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "using regex \"%V\" "
                           "requires PCRE library", &value[i]);

        return NJT_CONF_ERROR;
#endif
    }

    return NJT_CONF_OK;
}

static char *
njt_stream_core_resolver(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_stream_core_srv_conf_t  *cscf = conf;

    njt_str_t  *value;

    if (cscf->resolver) {
        return "is duplicate";
    }

    value = cf->args->elts;

    cscf->resolver = njt_resolver_create(cf, &value[1], cf->args->nelts - 1);
    if (cscf->resolver == NULL) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}
void njt_stream_server_delete_dyn_var(njt_stream_core_srv_conf_t *cscf)
{
	return;
}

static void njt_stream_core_free_srv_ctx(void *data) {
    njt_stream_core_srv_conf_t *cscf;
    njt_stream_session_t *s;
    u_char *p = data;
    njt_memcpy(&cscf, p, sizeof(njt_stream_core_srv_conf_t *));
    njt_memcpy(&s, p + sizeof(njt_stream_core_srv_conf_t *), sizeof(njt_stream_session_t *));

    if(s->upstream != NULL && s->upstream->upstream != NULL){
           // njt_stream_upstream_del((njt_cycle_t  *)njt_cycle,s->upstream->upstream);
    }
    --cscf->ref_count;
    if (cscf->disable == 1 && cscf->ref_count == 0)
    {
        njt_stream_server_delete_dyn_var(cscf);
        njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "njt_stream_core_free_srv_ctx server %V,ref_count=%d!", &cscf->server_name, cscf->ref_count);
        njt_destroy_pool(cscf->pool); 
    }
}
void njt_stream_set_virtual_server(njt_stream_session_t *s,njt_stream_core_srv_conf_t *cscf)
{
    njt_pool_cleanup_t *cln;
    u_char *pt;
    njt_connection_t            *c = s->connection;
    if(cscf == NULL) {
        return;
    }
    cln = njt_pool_cleanup_add(c->pool, sizeof(njt_stream_core_srv_conf_t *) + sizeof(njt_stream_session_t *));
    if (cln == NULL) {
       return;
    }
    s->srv_conf = cscf->ctx->srv_conf;
    cscf->ref_count++;
    pt = cln->data;
    njt_memcpy(pt,&cscf,sizeof(njt_stream_core_srv_conf_t *));
    njt_memcpy(pt+sizeof(njt_stream_core_srv_conf_t *),&s,sizeof(njt_stream_session_t *));
    cln->handler = njt_stream_core_free_srv_ctx;
}
