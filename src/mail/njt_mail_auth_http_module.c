
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>
#include <njt_event_connect.h>
#include <njt_mail.h>


typedef struct {
    njt_addr_t                     *peer;

    njt_msec_t                      timeout;
    njt_flag_t                      pass_client_cert;

    njt_str_t                       host_header;
    njt_str_t                       uri;
    njt_str_t                       header;

    njt_array_t                    *headers;

    u_char                         *file;
    njt_uint_t                      line;
} njt_mail_auth_http_conf_t;


typedef struct njt_mail_auth_http_ctx_s  njt_mail_auth_http_ctx_t;

typedef void (*njt_mail_auth_http_handler_pt)(njt_mail_session_t *s,
    njt_mail_auth_http_ctx_t *ctx);

struct njt_mail_auth_http_ctx_s {
    njt_buf_t                      *request;
    njt_buf_t                      *response;
    njt_peer_connection_t           peer;

    njt_mail_auth_http_handler_pt   handler;

    njt_uint_t                      state;

    u_char                         *header_name_start;
    u_char                         *header_name_end;
    u_char                         *header_start;
    u_char                         *header_end;

    njt_str_t                       addr;
    njt_str_t                       port;
    njt_str_t                       err;
    njt_str_t                       errmsg;
    njt_str_t                       errcode;

    time_t                          sleep;

    njt_pool_t                     *pool;
};


static void njt_mail_auth_http_write_handler(njt_event_t *wev);
static void njt_mail_auth_http_read_handler(njt_event_t *rev);
static void njt_mail_auth_http_ignore_status_line(njt_mail_session_t *s,
    njt_mail_auth_http_ctx_t *ctx);
static void njt_mail_auth_http_process_headers(njt_mail_session_t *s,
    njt_mail_auth_http_ctx_t *ctx);
static void njt_mail_auth_sleep_handler(njt_event_t *rev);
static njt_int_t njt_mail_auth_http_parse_header_line(njt_mail_session_t *s,
    njt_mail_auth_http_ctx_t *ctx);
static void njt_mail_auth_http_block_read(njt_event_t *rev);
static void njt_mail_auth_http_dummy_handler(njt_event_t *ev);
static njt_buf_t *njt_mail_auth_http_create_request(njt_mail_session_t *s,
    njt_pool_t *pool, njt_mail_auth_http_conf_t *ahcf);
static njt_int_t njt_mail_auth_http_escape(njt_pool_t *pool, njt_str_t *text,
    njt_str_t *escaped);

static void *njt_mail_auth_http_create_conf(njt_conf_t *cf);
static char *njt_mail_auth_http_merge_conf(njt_conf_t *cf, void *parent,
    void *child);
static char *njt_mail_auth_http(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static char *njt_mail_auth_http_header(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);


static njt_command_t  njt_mail_auth_http_commands[] = {

    { njt_string("auth_http"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_TAKE1,
      njt_mail_auth_http,
      NJT_MAIL_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("auth_http_timeout"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_auth_http_conf_t, timeout),
      NULL },

    { njt_string("auth_http_header"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_TAKE2,
      njt_mail_auth_http_header,
      NJT_MAIL_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("auth_http_pass_client_cert"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_auth_http_conf_t, pass_client_cert),
      NULL },

      njt_null_command
};


static njt_mail_module_t  njt_mail_auth_http_module_ctx = {
    NULL,                                  /* protocol */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    njt_mail_auth_http_create_conf,        /* create server configuration */
    njt_mail_auth_http_merge_conf          /* merge server configuration */
};


njt_module_t  njt_mail_auth_http_module = {
    NJT_MODULE_V1,
    &njt_mail_auth_http_module_ctx,        /* module context */
    njt_mail_auth_http_commands,           /* module directives */
    NJT_MAIL_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};


static njt_str_t   njt_mail_auth_http_method[] = {
    njt_string("plain"),
    njt_string("plain"),
    njt_string("plain"),
    njt_string("apop"),
    njt_string("cram-md5"),
    njt_string("external"),
    njt_string("none")
};

static njt_str_t   njt_mail_smtp_errcode = njt_string("535 5.7.0");


void
njt_mail_auth_http_init(njt_mail_session_t *s)
{
    njt_int_t                   rc;
    njt_pool_t                 *pool;
    njt_mail_auth_http_ctx_t   *ctx;
    njt_mail_auth_http_conf_t  *ahcf;

    s->connection->log->action = "in http auth state";

    pool = njt_create_pool(2048, s->connection->log);
    if (pool == NULL) {
        njt_mail_session_internal_server_error(s);
        return;
    }

    ctx = njt_pcalloc(pool, sizeof(njt_mail_auth_http_ctx_t));
    if (ctx == NULL) {
        njt_destroy_pool(pool);
        njt_mail_session_internal_server_error(s);
        return;
    }

    ctx->pool = pool;

    ahcf = njt_mail_get_module_srv_conf(s, njt_mail_auth_http_module);

    ctx->request = njt_mail_auth_http_create_request(s, pool, ahcf);
    if (ctx->request == NULL) {
        njt_destroy_pool(ctx->pool);
        njt_mail_session_internal_server_error(s);
        return;
    }

    njt_mail_set_ctx(s, ctx, njt_mail_auth_http_module);

    ctx->peer.sockaddr = ahcf->peer->sockaddr;
    ctx->peer.socklen = ahcf->peer->socklen;
    ctx->peer.name = &ahcf->peer->name;
    ctx->peer.get = njt_event_get_peer;
    ctx->peer.log = s->connection->log;
    ctx->peer.log_error = NJT_ERROR_ERR;

    rc = njt_event_connect_peer(&ctx->peer);

    if (rc == NJT_ERROR || rc == NJT_BUSY || rc == NJT_DECLINED) {
        if (ctx->peer.connection) {
            njt_close_connection(ctx->peer.connection);
        }

        njt_destroy_pool(ctx->pool);
        njt_mail_session_internal_server_error(s);
        return;
    }

    ctx->peer.connection->data = s;
    ctx->peer.connection->pool = s->connection->pool;

    s->connection->read->handler = njt_mail_auth_http_block_read;
    ctx->peer.connection->read->handler = njt_mail_auth_http_read_handler;
    ctx->peer.connection->write->handler = njt_mail_auth_http_write_handler;

    ctx->handler = njt_mail_auth_http_ignore_status_line;

    njt_add_timer(ctx->peer.connection->read, ahcf->timeout);
    njt_add_timer(ctx->peer.connection->write, ahcf->timeout);

    if (rc == NJT_OK) {
        njt_mail_auth_http_write_handler(ctx->peer.connection->write);
        return;
    }
}


static void
njt_mail_auth_http_write_handler(njt_event_t *wev)
{
    ssize_t                     n, size;
    njt_connection_t           *c;
    njt_mail_session_t         *s;
    njt_mail_auth_http_ctx_t   *ctx;
    njt_mail_auth_http_conf_t  *ahcf;

    c = wev->data;
    s = c->data;

    ctx = njt_mail_get_module_ctx(s, njt_mail_auth_http_module);

    njt_log_debug0(NJT_LOG_DEBUG_MAIL, wev->log, 0,
                   "mail auth http write handler");

    if (wev->timedout) {
        njt_log_error(NJT_LOG_ERR, wev->log, NJT_ETIMEDOUT,
                      "auth http server %V timed out", ctx->peer.name);
        njt_close_connection(c);
        njt_destroy_pool(ctx->pool);
        njt_mail_session_internal_server_error(s);
        return;
    }

    size = ctx->request->last - ctx->request->pos;

    n = njt_send(c, ctx->request->pos, size);

    if (n == NJT_ERROR) {
        njt_close_connection(c);
        njt_destroy_pool(ctx->pool);
        njt_mail_session_internal_server_error(s);
        return;
    }

    if (n > 0) {
        ctx->request->pos += n;

        if (n == size) {
            wev->handler = njt_mail_auth_http_dummy_handler;

            if (wev->timer_set) {
                njt_del_timer(wev);
            }

            if (njt_handle_write_event(wev, 0) != NJT_OK) {
                njt_close_connection(c);
                njt_destroy_pool(ctx->pool);
                njt_mail_session_internal_server_error(s);
            }

            return;
        }
    }

    if (!wev->timer_set) {
        ahcf = njt_mail_get_module_srv_conf(s, njt_mail_auth_http_module);
        njt_add_timer(wev, ahcf->timeout);
    }
}


static void
njt_mail_auth_http_read_handler(njt_event_t *rev)
{
    ssize_t                     n, size;
    njt_connection_t          *c;
    njt_mail_session_t        *s;
    njt_mail_auth_http_ctx_t  *ctx;

    c = rev->data;
    s = c->data;

    njt_log_debug0(NJT_LOG_DEBUG_MAIL, rev->log, 0,
                   "mail auth http read handler");

    ctx = njt_mail_get_module_ctx(s, njt_mail_auth_http_module);

    if (rev->timedout) {
        njt_log_error(NJT_LOG_ERR, rev->log, NJT_ETIMEDOUT,
                      "auth http server %V timed out", ctx->peer.name);
        njt_close_connection(c);
        njt_destroy_pool(ctx->pool);
        njt_mail_session_internal_server_error(s);
        return;
    }

    if (ctx->response == NULL) {
        ctx->response = njt_create_temp_buf(ctx->pool, 1024);
        if (ctx->response == NULL) {
            njt_close_connection(c);
            njt_destroy_pool(ctx->pool);
            njt_mail_session_internal_server_error(s);
            return;
        }
    }

    size = ctx->response->end - ctx->response->last;

    n = njt_recv(c, ctx->response->pos, size);

    if (n > 0) {
        ctx->response->last += n;

        ctx->handler(s, ctx);
        return;
    }

    if (n == NJT_AGAIN) {
        return;
    }

    njt_close_connection(c);
    njt_destroy_pool(ctx->pool);
    njt_mail_session_internal_server_error(s);
}


static void
njt_mail_auth_http_ignore_status_line(njt_mail_session_t *s,
    njt_mail_auth_http_ctx_t *ctx)
{
    u_char  *p, ch;
    enum  {
        sw_start = 0,
        sw_H,
        sw_HT,
        sw_HTT,
        sw_HTTP,
        sw_skip,
        sw_almost_done
    } state;

    njt_log_debug0(NJT_LOG_DEBUG_MAIL, s->connection->log, 0,
                   "mail auth http process status line");

    state = ctx->state;

    for (p = ctx->response->pos; p < ctx->response->last; p++) {
        ch = *p;

        switch (state) {

        /* "HTTP/" */
        case sw_start:
            if (ch == 'H') {
                state = sw_H;
                break;
            }
            goto next;

        case sw_H:
            if (ch == 'T') {
                state = sw_HT;
                break;
            }
            goto next;

        case sw_HT:
            if (ch == 'T') {
                state = sw_HTT;
                break;
            }
            goto next;

        case sw_HTT:
            if (ch == 'P') {
                state = sw_HTTP;
                break;
            }
            goto next;

        case sw_HTTP:
            if (ch == '/') {
                state = sw_skip;
                break;
            }
            goto next;

        /* any text until end of line */
        case sw_skip:
            switch (ch) {
            case CR:
                state = sw_almost_done;

                break;
            case LF:
                goto done;
            }
            break;

        /* end of status line */
        case sw_almost_done:
            if (ch == LF) {
                goto done;
            }

            njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                          "auth http server %V sent invalid response",
                          ctx->peer.name);
            njt_close_connection(ctx->peer.connection);
            njt_destroy_pool(ctx->pool);
            njt_mail_session_internal_server_error(s);
            return;
        }
    }

    ctx->response->pos = p;
    ctx->state = state;

    return;

next:

    p = ctx->response->start - 1;

done:

    ctx->response->pos = p + 1;
    ctx->state = 0;
    ctx->handler = njt_mail_auth_http_process_headers;
    ctx->handler(s, ctx);
}


static void
njt_mail_auth_http_process_headers(njt_mail_session_t *s,
    njt_mail_auth_http_ctx_t *ctx)
{
    u_char      *p;
    time_t       timer;
    size_t       len, size;
    njt_int_t    rc, port, n;
    njt_addr_t  *peer;

    njt_log_debug0(NJT_LOG_DEBUG_MAIL, s->connection->log, 0,
                   "mail auth http process headers");

    for ( ;; ) {
        rc = njt_mail_auth_http_parse_header_line(s, ctx);

        if (rc == NJT_OK) {

#if (NJT_DEBUG)
            {
            njt_str_t  key, value;

            key.len = ctx->header_name_end - ctx->header_name_start;
            key.data = ctx->header_name_start;
            value.len = ctx->header_end - ctx->header_start;
            value.data = ctx->header_start;

            njt_log_debug2(NJT_LOG_DEBUG_MAIL, s->connection->log, 0,
                           "mail auth http header: \"%V: %V\"",
                           &key, &value);
            }
#endif

            len = ctx->header_name_end - ctx->header_name_start;

            if (len == sizeof("Auth-Status") - 1
                && njt_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-Status",
                                   sizeof("Auth-Status") - 1)
                   == 0)
            {
                len = ctx->header_end - ctx->header_start;

                if (len == 2
                    && ctx->header_start[0] == 'O'
                    && ctx->header_start[1] == 'K')
                {
                    continue;
                }

                if (len == 4
                    && ctx->header_start[0] == 'W'
                    && ctx->header_start[1] == 'A'
                    && ctx->header_start[2] == 'I'
                    && ctx->header_start[3] == 'T')
                {
                    s->auth_wait = 1;
                    continue;
                }

                ctx->errmsg.len = len;
                ctx->errmsg.data = ctx->header_start;

                switch (s->protocol) {

                case NJT_MAIL_POP3_PROTOCOL:
                    size = sizeof("-ERR ") - 1 + len + sizeof(CRLF) - 1;
                    break;

                case NJT_MAIL_IMAP_PROTOCOL:
                    size = s->tag.len + sizeof("NO ") - 1 + len
                           + sizeof(CRLF) - 1;
                    break;

                default: /* NJT_MAIL_SMTP_PROTOCOL */
                    ctx->err = ctx->errmsg;
                    continue;
                }

                p = njt_pnalloc(s->connection->pool, size);
                if (p == NULL) {
                    njt_close_connection(ctx->peer.connection);
                    njt_destroy_pool(ctx->pool);
                    njt_mail_session_internal_server_error(s);
                    return;
                }

                ctx->err.data = p;

                switch (s->protocol) {

                case NJT_MAIL_POP3_PROTOCOL:
                    *p++ = '-'; *p++ = 'E'; *p++ = 'R'; *p++ = 'R'; *p++ = ' ';
                    break;

                case NJT_MAIL_IMAP_PROTOCOL:
                    p = njt_cpymem(p, s->tag.data, s->tag.len);
                    *p++ = 'N'; *p++ = 'O'; *p++ = ' ';
                    break;

                default: /* NJT_MAIL_SMTP_PROTOCOL */
                    break;
                }

                p = njt_cpymem(p, ctx->header_start, len);
                *p++ = CR; *p++ = LF;

                ctx->err.len = p - ctx->err.data;

                continue;
            }

            if (len == sizeof("Auth-Server") - 1
                && njt_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-Server",
                                   sizeof("Auth-Server") - 1)
                    == 0)
            {
                ctx->addr.len = ctx->header_end - ctx->header_start;
                ctx->addr.data = ctx->header_start;

                continue;
            }

            if (len == sizeof("Auth-Port") - 1
                && njt_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-Port",
                                   sizeof("Auth-Port") - 1)
                   == 0)
            {
                ctx->port.len = ctx->header_end - ctx->header_start;
                ctx->port.data = ctx->header_start;

                continue;
            }

            if (len == sizeof("Auth-User") - 1
                && njt_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-User",
                                   sizeof("Auth-User") - 1)
                   == 0)
            {
                s->login.len = ctx->header_end - ctx->header_start;

                s->login.data = njt_pnalloc(s->connection->pool, s->login.len);
                if (s->login.data == NULL) {
                    njt_close_connection(ctx->peer.connection);
                    njt_destroy_pool(ctx->pool);
                    njt_mail_session_internal_server_error(s);
                    return;
                }

                njt_memcpy(s->login.data, ctx->header_start, s->login.len);

                continue;
            }

            if (len == sizeof("Auth-Pass") - 1
                && njt_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-Pass",
                                   sizeof("Auth-Pass") - 1)
                   == 0)
            {
                s->passwd.len = ctx->header_end - ctx->header_start;

                s->passwd.data = njt_pnalloc(s->connection->pool,
                                             s->passwd.len);
                if (s->passwd.data == NULL) {
                    njt_close_connection(ctx->peer.connection);
                    njt_destroy_pool(ctx->pool);
                    njt_mail_session_internal_server_error(s);
                    return;
                }

                njt_memcpy(s->passwd.data, ctx->header_start, s->passwd.len);

                continue;
            }

            if (len == sizeof("Auth-Wait") - 1
                && njt_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-Wait",
                                   sizeof("Auth-Wait") - 1)
                   == 0)
            {
                n = njt_atoi(ctx->header_start,
                             ctx->header_end - ctx->header_start);

                if (n != NJT_ERROR) {
                    ctx->sleep = n;
                }

                continue;
            }

            if (len == sizeof("Auth-Error-Code") - 1
                && njt_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-Error-Code",
                                   sizeof("Auth-Error-Code") - 1)
                   == 0)
            {
                ctx->errcode.len = ctx->header_end - ctx->header_start;

                ctx->errcode.data = njt_pnalloc(s->connection->pool,
                                                ctx->errcode.len);
                if (ctx->errcode.data == NULL) {
                    njt_close_connection(ctx->peer.connection);
                    njt_destroy_pool(ctx->pool);
                    njt_mail_session_internal_server_error(s);
                    return;
                }

                njt_memcpy(ctx->errcode.data, ctx->header_start,
                           ctx->errcode.len);

                continue;
            }

            /* ignore other headers */

            continue;
        }

        if (rc == NJT_DONE) {
            njt_log_debug0(NJT_LOG_DEBUG_MAIL, s->connection->log, 0,
                           "mail auth http header done");

            njt_close_connection(ctx->peer.connection);

            if (ctx->err.len) {

                njt_log_error(NJT_LOG_INFO, s->connection->log, 0,
                              "client login failed: \"%V\"", &ctx->errmsg);

                if (s->protocol == NJT_MAIL_SMTP_PROTOCOL) {

                    if (ctx->errcode.len == 0) {
                        ctx->errcode = njt_mail_smtp_errcode;
                    }

                    ctx->err.len = ctx->errcode.len + ctx->errmsg.len
                                   + sizeof(" " CRLF) - 1;

                    p = njt_pnalloc(s->connection->pool, ctx->err.len);
                    if (p == NULL) {
                        njt_destroy_pool(ctx->pool);
                        njt_mail_session_internal_server_error(s);
                        return;
                    }

                    ctx->err.data = p;

                    p = njt_cpymem(p, ctx->errcode.data, ctx->errcode.len);
                    *p++ = ' ';
                    p = njt_cpymem(p, ctx->errmsg.data, ctx->errmsg.len);
                    *p++ = CR; *p = LF;
                }

                s->out = ctx->err;
                timer = ctx->sleep;

                njt_destroy_pool(ctx->pool);

                if (timer == 0) {
                    s->quit = 1;
                    njt_mail_send(s->connection->write);
                    return;
                }

                njt_add_timer(s->connection->read, (njt_msec_t) (timer * 1000));

                s->connection->read->handler = njt_mail_auth_sleep_handler;

                return;
            }

            if (s->auth_wait) {
                timer = ctx->sleep;

                njt_destroy_pool(ctx->pool);

                if (timer == 0) {
                    njt_mail_auth_http_init(s);
                    return;
                }

                njt_add_timer(s->connection->read, (njt_msec_t) (timer * 1000));

                s->connection->read->handler = njt_mail_auth_sleep_handler;

                return;
            }

            if (ctx->addr.len == 0 || ctx->port.len == 0) {
                njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                              "auth http server %V did not send server or port",
                              ctx->peer.name);
                njt_destroy_pool(ctx->pool);
                njt_mail_session_internal_server_error(s);
                return;
            }

            if (s->passwd.data == NULL
                && s->protocol != NJT_MAIL_SMTP_PROTOCOL)
            {
                njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                              "auth http server %V did not send password",
                              ctx->peer.name);
                njt_destroy_pool(ctx->pool);
                njt_mail_session_internal_server_error(s);
                return;
            }

            peer = njt_pcalloc(s->connection->pool, sizeof(njt_addr_t));
            if (peer == NULL) {
                njt_destroy_pool(ctx->pool);
                njt_mail_session_internal_server_error(s);
                return;
            }

            rc = njt_parse_addr(s->connection->pool, peer,
                                ctx->addr.data, ctx->addr.len);

            switch (rc) {
            case NJT_OK:
                break;

            case NJT_DECLINED:
                njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                              "auth http server %V sent invalid server "
                              "address:\"%V\"",
                              ctx->peer.name, &ctx->addr);
                /* fall through */

            default:
                njt_destroy_pool(ctx->pool);
                njt_mail_session_internal_server_error(s);
                return;
            }

            port = njt_atoi(ctx->port.data, ctx->port.len);
            if (port == NJT_ERROR || port < 1 || port > 65535) {
                njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                              "auth http server %V sent invalid server "
                              "port:\"%V\"",
                              ctx->peer.name, &ctx->port);
                njt_destroy_pool(ctx->pool);
                njt_mail_session_internal_server_error(s);
                return;
            }

            njt_inet_set_port(peer->sockaddr, (in_port_t) port);

            len = ctx->addr.len + 1 + ctx->port.len;

            peer->name.len = len;

            peer->name.data = njt_pnalloc(s->connection->pool, len);
            if (peer->name.data == NULL) {
                njt_destroy_pool(ctx->pool);
                njt_mail_session_internal_server_error(s);
                return;
            }

            len = ctx->addr.len;

            njt_memcpy(peer->name.data, ctx->addr.data, len);

            peer->name.data[len++] = ':';

            njt_memcpy(peer->name.data + len, ctx->port.data, ctx->port.len);

            njt_destroy_pool(ctx->pool);
            njt_mail_proxy_init(s, peer);

            return;
        }

        if (rc == NJT_AGAIN ) {
            return;
        }

        /* rc == NJT_ERROR */

        njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                      "auth http server %V sent invalid header in response",
                      ctx->peer.name);
        njt_close_connection(ctx->peer.connection);
        njt_destroy_pool(ctx->pool);
        njt_mail_session_internal_server_error(s);

        return;
    }
}


static void
njt_mail_auth_sleep_handler(njt_event_t *rev)
{
    njt_connection_t          *c;
    njt_mail_session_t        *s;
    njt_mail_core_srv_conf_t  *cscf;

    njt_log_debug0(NJT_LOG_DEBUG_MAIL, rev->log, 0, "mail auth sleep handler");

    c = rev->data;
    s = c->data;

    if (rev->timedout) {

        rev->timedout = 0;

        if (s->auth_wait) {
            s->auth_wait = 0;
            njt_mail_auth_http_init(s);
            return;
        }

        cscf = njt_mail_get_module_srv_conf(s, njt_mail_core_module);

        rev->handler = cscf->protocol->auth_state;

        s->mail_state = 0;
        s->auth_method = NJT_MAIL_AUTH_PLAIN;

        c->log->action = "in auth state";

        njt_mail_send(c->write);

        if (c->destroyed) {
            return;
        }

        njt_add_timer(rev, cscf->timeout);

        if (rev->ready) {
            rev->handler(rev);
            return;
        }

        if (njt_handle_read_event(rev, 0) != NJT_OK) {
            njt_mail_close_connection(c);
        }

        return;
    }

    if (rev->active) {
        if (njt_handle_read_event(rev, 0) != NJT_OK) {
            njt_mail_close_connection(c);
        }
    }
}


static njt_int_t
njt_mail_auth_http_parse_header_line(njt_mail_session_t *s,
    njt_mail_auth_http_ctx_t *ctx)
{
    u_char      c, ch, *p;
    enum {
        sw_start = 0,
        sw_name,
        sw_space_before_value,
        sw_value,
        sw_space_after_value,
        sw_almost_done,
        sw_header_almost_done
    } state;

    state = ctx->state;

    for (p = ctx->response->pos; p < ctx->response->last; p++) {
        ch = *p;

        switch (state) {

        /* first char */
        case sw_start:

            switch (ch) {
            case CR:
                ctx->header_end = p;
                state = sw_header_almost_done;
                break;
            case LF:
                ctx->header_end = p;
                goto header_done;
            default:
                state = sw_name;
                ctx->header_name_start = p;

                c = (u_char) (ch | 0x20);
                if (c >= 'a' && c <= 'z') {
                    break;
                }

                if (ch >= '0' && ch <= '9') {
                    break;
                }

                return NJT_ERROR;
            }
            break;

        /* header name */
        case sw_name:
            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'z') {
                break;
            }

            if (ch == ':') {
                ctx->header_name_end = p;
                state = sw_space_before_value;
                break;
            }

            if (ch == '-') {
                break;
            }

            if (ch >= '0' && ch <= '9') {
                break;
            }

            if (ch == CR) {
                ctx->header_name_end = p;
                ctx->header_start = p;
                ctx->header_end = p;
                state = sw_almost_done;
                break;
            }

            if (ch == LF) {
                ctx->header_name_end = p;
                ctx->header_start = p;
                ctx->header_end = p;
                goto done;
            }

            return NJT_ERROR;

        /* space* before header value */
        case sw_space_before_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                ctx->header_start = p;
                ctx->header_end = p;
                state = sw_almost_done;
                break;
            case LF:
                ctx->header_start = p;
                ctx->header_end = p;
                goto done;
            default:
                ctx->header_start = p;
                state = sw_value;
                break;
            }
            break;

        /* header value */
        case sw_value:
            switch (ch) {
            case ' ':
                ctx->header_end = p;
                state = sw_space_after_value;
                break;
            case CR:
                ctx->header_end = p;
                state = sw_almost_done;
                break;
            case LF:
                ctx->header_end = p;
                goto done;
            }
            break;

        /* space* before end of header line */
        case sw_space_after_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            default:
                state = sw_value;
                break;
            }
            break;

        /* end of header line */
        case sw_almost_done:
            switch (ch) {
            case LF:
                goto done;
            default:
                return NJT_ERROR;
            }

        /* end of header */
        case sw_header_almost_done:
            switch (ch) {
            case LF:
                goto header_done;
            default:
                return NJT_ERROR;
            }
        }
    }

    ctx->response->pos = p;
    ctx->state = state;

    return NJT_AGAIN;

done:

    ctx->response->pos = p + 1;
    ctx->state = sw_start;

    return NJT_OK;

header_done:

    ctx->response->pos = p + 1;
    ctx->state = sw_start;

    return NJT_DONE;
}


static void
njt_mail_auth_http_block_read(njt_event_t *rev)
{
    njt_connection_t          *c;
    njt_mail_session_t        *s;
    njt_mail_auth_http_ctx_t  *ctx;

    njt_log_debug0(NJT_LOG_DEBUG_MAIL, rev->log, 0,
                   "mail auth http block read");

    if (njt_handle_read_event(rev, 0) != NJT_OK) {
        c = rev->data;
        s = c->data;

        ctx = njt_mail_get_module_ctx(s, njt_mail_auth_http_module);

        njt_close_connection(ctx->peer.connection);
        njt_destroy_pool(ctx->pool);
        njt_mail_session_internal_server_error(s);
    }
}


static void
njt_mail_auth_http_dummy_handler(njt_event_t *ev)
{
    njt_log_debug0(NJT_LOG_DEBUG_MAIL, ev->log, 0,
                   "mail auth http dummy handler");
}


static njt_buf_t *
njt_mail_auth_http_create_request(njt_mail_session_t *s, njt_pool_t *pool,
    njt_mail_auth_http_conf_t *ahcf)
{
    size_t                     len;
    njt_buf_t                 *b;
    njt_str_t                  login, passwd;
    njt_connection_t          *c;
#if (NJT_MAIL_SSL)
    njt_str_t                  protocol, cipher, verify, subject, issuer,
                               serial, fingerprint, raw_cert, cert;
    njt_mail_ssl_conf_t       *sslcf;
#endif
    njt_mail_core_srv_conf_t  *cscf;

    if (njt_mail_auth_http_escape(pool, &s->login, &login) != NJT_OK) {
        return NULL;
    }

    if (njt_mail_auth_http_escape(pool, &s->passwd, &passwd) != NJT_OK) {
        return NULL;
    }

    c = s->connection;

#if (NJT_MAIL_SSL)

    if (c->ssl) {

        if (njt_ssl_get_protocol(c, pool, &protocol) != NJT_OK) {
            return NULL;
        }

        protocol.len = njt_strlen(protocol.data);

        if (njt_ssl_get_cipher_name(c, pool, &cipher) != NJT_OK) {
            return NULL;
        }

        cipher.len = njt_strlen(cipher.data);

    } else {
        njt_str_null(&protocol);
        njt_str_null(&cipher);
    }

    sslcf = njt_mail_get_module_srv_conf(s, njt_mail_ssl_module);

    if (c->ssl && sslcf->verify) {

        /* certificate details */

        if (njt_ssl_get_client_verify(c, pool, &verify) != NJT_OK) {
            return NULL;
        }

        if (njt_ssl_get_subject_dn(c, pool, &subject) != NJT_OK) {
            return NULL;
        }

        if (njt_ssl_get_issuer_dn(c, pool, &issuer) != NJT_OK) {
            return NULL;
        }

        if (njt_ssl_get_serial_number(c, pool, &serial) != NJT_OK) {
            return NULL;
        }

        if (njt_ssl_get_fingerprint(c, pool, &fingerprint) != NJT_OK) {
            return NULL;
        }

        if (ahcf->pass_client_cert) {

            /* certificate itself, if configured */

            if (njt_ssl_get_raw_certificate(c, pool, &raw_cert) != NJT_OK) {
                return NULL;
            }

            if (njt_mail_auth_http_escape(pool, &raw_cert, &cert) != NJT_OK) {
                return NULL;
            }

        } else {
            njt_str_null(&cert);
        }

    } else {
        njt_str_null(&verify);
        njt_str_null(&subject);
        njt_str_null(&issuer);
        njt_str_null(&serial);
        njt_str_null(&fingerprint);
        njt_str_null(&cert);
    }

#endif

    cscf = njt_mail_get_module_srv_conf(s, njt_mail_core_module);

    len = sizeof("GET ") - 1 + ahcf->uri.len + sizeof(" HTTP/1.0" CRLF) - 1
          + sizeof("Host: ") - 1 + ahcf->host_header.len + sizeof(CRLF) - 1
          + sizeof("Auth-Method: ") - 1
                + njt_mail_auth_http_method[s->auth_method].len
                + sizeof(CRLF) - 1
          + sizeof("Auth-User: ") - 1 + login.len + sizeof(CRLF) - 1
          + sizeof("Auth-Pass: ") - 1 + passwd.len + sizeof(CRLF) - 1
          + sizeof("Auth-Salt: ") - 1 + s->salt.len
          + sizeof("Auth-Protocol: ") - 1 + cscf->protocol->name.len
                + sizeof(CRLF) - 1
          + sizeof("Auth-Login-Attempt: ") - 1 + NJT_INT_T_LEN
                + sizeof(CRLF) - 1
          + sizeof("Client-IP: ") - 1 + s->connection->addr_text.len
                + sizeof(CRLF) - 1
          + sizeof("Client-Host: ") - 1 + s->host.len + sizeof(CRLF) - 1
          + ahcf->header.len
          + sizeof(CRLF) - 1;

    if (c->proxy_protocol) {
        len += sizeof("Proxy-Protocol-Addr: ") - 1
                     + c->proxy_protocol->src_addr.len + sizeof(CRLF) - 1
               + sizeof("Proxy-Protocol-Port: ") - 1
                     + sizeof("65535") - 1 + sizeof(CRLF) - 1
               + sizeof("Proxy-Protocol-Server-Addr: ") - 1
                     + c->proxy_protocol->dst_addr.len + sizeof(CRLF) - 1
               + sizeof("Proxy-Protocol-Server-Port: ") - 1
                     + sizeof("65535") - 1 + sizeof(CRLF) - 1;
    }

    if (s->auth_method == NJT_MAIL_AUTH_NONE) {
        len += sizeof("Auth-SMTP-Helo: ") - 1 + s->smtp_helo.len
                     + sizeof(CRLF) - 1
               + sizeof("Auth-SMTP-From: ") - 1 + s->smtp_from.len
                     + sizeof(CRLF) - 1
               + sizeof("Auth-SMTP-To: ") - 1 + s->smtp_to.len
                     + sizeof(CRLF) - 1;
    }

#if (NJT_MAIL_SSL)

    if (c->ssl) {
        len += sizeof("Auth-SSL: on" CRLF) - 1
               + sizeof("Auth-SSL-Protocol: ") - 1 + protocol.len
                     + sizeof(CRLF) - 1
               + sizeof("Auth-SSL-Cipher: ") - 1 + cipher.len
                     + sizeof(CRLF) - 1
               + sizeof("Auth-SSL-Verify: ") - 1 + verify.len
                     + sizeof(CRLF) - 1
               + sizeof("Auth-SSL-Subject: ") - 1 + subject.len
                     + sizeof(CRLF) - 1
               + sizeof("Auth-SSL-Issuer: ") - 1 + issuer.len
                     + sizeof(CRLF) - 1
               + sizeof("Auth-SSL-Serial: ") - 1 + serial.len
                     + sizeof(CRLF) - 1
               + sizeof("Auth-SSL-Fingerprint: ") - 1 + fingerprint.len
                     + sizeof(CRLF) - 1
               + sizeof("Auth-SSL-Cert: ") - 1 + cert.len
                     + sizeof(CRLF) - 1;
    }

#endif

    b = njt_create_temp_buf(pool, len);
    if (b == NULL) {
        return NULL;
    }

    b->last = njt_cpymem(b->last, "GET ", sizeof("GET ") - 1);
    b->last = njt_copy(b->last, ahcf->uri.data, ahcf->uri.len);
    b->last = njt_cpymem(b->last, " HTTP/1.0" CRLF,
                         sizeof(" HTTP/1.0" CRLF) - 1);

    b->last = njt_cpymem(b->last, "Host: ", sizeof("Host: ") - 1);
    b->last = njt_copy(b->last, ahcf->host_header.data,
                         ahcf->host_header.len);
    *b->last++ = CR; *b->last++ = LF;

    b->last = njt_cpymem(b->last, "Auth-Method: ",
                         sizeof("Auth-Method: ") - 1);
    b->last = njt_cpymem(b->last,
                         njt_mail_auth_http_method[s->auth_method].data,
                         njt_mail_auth_http_method[s->auth_method].len);
    *b->last++ = CR; *b->last++ = LF;

    b->last = njt_cpymem(b->last, "Auth-User: ", sizeof("Auth-User: ") - 1);
    b->last = njt_copy(b->last, login.data, login.len);
    *b->last++ = CR; *b->last++ = LF;

    b->last = njt_cpymem(b->last, "Auth-Pass: ", sizeof("Auth-Pass: ") - 1);
    b->last = njt_copy(b->last, passwd.data, passwd.len);
    *b->last++ = CR; *b->last++ = LF;

    if (s->auth_method != NJT_MAIL_AUTH_PLAIN && s->salt.len) {
        b->last = njt_cpymem(b->last, "Auth-Salt: ", sizeof("Auth-Salt: ") - 1);
        b->last = njt_copy(b->last, s->salt.data, s->salt.len);

        s->passwd.data = NULL;
    }

    b->last = njt_cpymem(b->last, "Auth-Protocol: ",
                         sizeof("Auth-Protocol: ") - 1);
    b->last = njt_cpymem(b->last, cscf->protocol->name.data,
                         cscf->protocol->name.len);
    *b->last++ = CR; *b->last++ = LF;

    b->last = njt_sprintf(b->last, "Auth-Login-Attempt: %ui" CRLF,
                          s->login_attempt);

    b->last = njt_cpymem(b->last, "Client-IP: ", sizeof("Client-IP: ") - 1);
    b->last = njt_copy(b->last, s->connection->addr_text.data,
                       s->connection->addr_text.len);
    *b->last++ = CR; *b->last++ = LF;

    if (s->host.len) {
        b->last = njt_cpymem(b->last, "Client-Host: ",
                             sizeof("Client-Host: ") - 1);
        b->last = njt_copy(b->last, s->host.data, s->host.len);
        *b->last++ = CR; *b->last++ = LF;
    }

    if (c->proxy_protocol) {
        b->last = njt_cpymem(b->last, "Proxy-Protocol-Addr: ",
                             sizeof("Proxy-Protocol-Addr: ") - 1);
        b->last = njt_copy(b->last, c->proxy_protocol->src_addr.data,
                           c->proxy_protocol->src_addr.len);
        *b->last++ = CR; *b->last++ = LF;

        b->last = njt_sprintf(b->last, "Proxy-Protocol-Port: %d" CRLF,
                              c->proxy_protocol->src_port);

        b->last = njt_cpymem(b->last, "Proxy-Protocol-Server-Addr: ",
                             sizeof("Proxy-Protocol-Server-Addr: ") - 1);
        b->last = njt_copy(b->last, c->proxy_protocol->dst_addr.data,
                           c->proxy_protocol->dst_addr.len);
        *b->last++ = CR; *b->last++ = LF;

        b->last = njt_sprintf(b->last, "Proxy-Protocol-Server-Port: %d" CRLF,
                              c->proxy_protocol->dst_port);
    }

    if (s->auth_method == NJT_MAIL_AUTH_NONE) {

        /* HELO, MAIL FROM, and RCPT TO can't contain CRLF, no need to escape */

        b->last = njt_cpymem(b->last, "Auth-SMTP-Helo: ",
                             sizeof("Auth-SMTP-Helo: ") - 1);
        b->last = njt_copy(b->last, s->smtp_helo.data, s->smtp_helo.len);
        *b->last++ = CR; *b->last++ = LF;

        b->last = njt_cpymem(b->last, "Auth-SMTP-From: ",
                             sizeof("Auth-SMTP-From: ") - 1);
        b->last = njt_copy(b->last, s->smtp_from.data, s->smtp_from.len);
        *b->last++ = CR; *b->last++ = LF;

        b->last = njt_cpymem(b->last, "Auth-SMTP-To: ",
                             sizeof("Auth-SMTP-To: ") - 1);
        b->last = njt_copy(b->last, s->smtp_to.data, s->smtp_to.len);
        *b->last++ = CR; *b->last++ = LF;

    }

#if (NJT_MAIL_SSL)

    if (c->ssl) {
        b->last = njt_cpymem(b->last, "Auth-SSL: on" CRLF,
                             sizeof("Auth-SSL: on" CRLF) - 1);

        if (protocol.len) {
            b->last = njt_cpymem(b->last, "Auth-SSL-Protocol: ",
                                 sizeof("Auth-SSL-Protocol: ") - 1);
            b->last = njt_copy(b->last, protocol.data, protocol.len);
            *b->last++ = CR; *b->last++ = LF;
        }

        if (cipher.len) {
            b->last = njt_cpymem(b->last, "Auth-SSL-Cipher: ",
                                 sizeof("Auth-SSL-Cipher: ") - 1);
            b->last = njt_copy(b->last, cipher.data, cipher.len);
            *b->last++ = CR; *b->last++ = LF;
        }

        if (verify.len) {
            b->last = njt_cpymem(b->last, "Auth-SSL-Verify: ",
                                 sizeof("Auth-SSL-Verify: ") - 1);
            b->last = njt_copy(b->last, verify.data, verify.len);
            *b->last++ = CR; *b->last++ = LF;
        }

        if (subject.len) {
            b->last = njt_cpymem(b->last, "Auth-SSL-Subject: ",
                                 sizeof("Auth-SSL-Subject: ") - 1);
            b->last = njt_copy(b->last, subject.data, subject.len);
            *b->last++ = CR; *b->last++ = LF;
        }

        if (issuer.len) {
            b->last = njt_cpymem(b->last, "Auth-SSL-Issuer: ",
                                 sizeof("Auth-SSL-Issuer: ") - 1);
            b->last = njt_copy(b->last, issuer.data, issuer.len);
            *b->last++ = CR; *b->last++ = LF;
        }

        if (serial.len) {
            b->last = njt_cpymem(b->last, "Auth-SSL-Serial: ",
                                 sizeof("Auth-SSL-Serial: ") - 1);
            b->last = njt_copy(b->last, serial.data, serial.len);
            *b->last++ = CR; *b->last++ = LF;
        }

        if (fingerprint.len) {
            b->last = njt_cpymem(b->last, "Auth-SSL-Fingerprint: ",
                                 sizeof("Auth-SSL-Fingerprint: ") - 1);
            b->last = njt_copy(b->last, fingerprint.data, fingerprint.len);
            *b->last++ = CR; *b->last++ = LF;
        }

        if (cert.len) {
            b->last = njt_cpymem(b->last, "Auth-SSL-Cert: ",
                                 sizeof("Auth-SSL-Cert: ") - 1);
            b->last = njt_copy(b->last, cert.data, cert.len);
            *b->last++ = CR; *b->last++ = LF;
        }
    }

#endif

    if (ahcf->header.len) {
        b->last = njt_copy(b->last, ahcf->header.data, ahcf->header.len);
    }

    /* add "\r\n" at the header end */
    *b->last++ = CR; *b->last++ = LF;

#if (NJT_DEBUG_MAIL_PASSWD)
    njt_log_debug2(NJT_LOG_DEBUG_MAIL, s->connection->log, 0,
                   "mail auth http header:%N\"%*s\"",
                   (size_t) (b->last - b->pos), b->pos);
#endif

    return b;
}


static njt_int_t
njt_mail_auth_http_escape(njt_pool_t *pool, njt_str_t *text, njt_str_t *escaped)
{
    u_char     *p;
    uintptr_t   n;

    n = njt_escape_uri(NULL, text->data, text->len, NJT_ESCAPE_MAIL_AUTH);

    if (n == 0) {
        *escaped = *text;
        return NJT_OK;
    }

    escaped->len = text->len + n * 2;

    p = njt_pnalloc(pool, escaped->len);
    if (p == NULL) {
        return NJT_ERROR;
    }

    (void) njt_escape_uri(p, text->data, text->len, NJT_ESCAPE_MAIL_AUTH);

    escaped->data = p;

    return NJT_OK;
}


static void *
njt_mail_auth_http_create_conf(njt_conf_t *cf)
{
    njt_mail_auth_http_conf_t  *ahcf;

    ahcf = njt_pcalloc(cf->pool, sizeof(njt_mail_auth_http_conf_t));
    if (ahcf == NULL) {
        return NULL;
    }

    ahcf->timeout = NJT_CONF_UNSET_MSEC;
    ahcf->pass_client_cert = NJT_CONF_UNSET;

    ahcf->file = cf->conf_file->file.name.data;
    ahcf->line = cf->conf_file->line;

    return ahcf;
}


static char *
njt_mail_auth_http_merge_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_mail_auth_http_conf_t *prev = parent;
    njt_mail_auth_http_conf_t *conf = child;

    u_char           *p;
    size_t            len;
    njt_uint_t        i;
    njt_table_elt_t  *header;

    if (conf->peer == NULL) {
        conf->peer = prev->peer;
        conf->host_header = prev->host_header;
        conf->uri = prev->uri;

        if (conf->peer == NULL) {
            njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                          "no \"auth_http\" is defined for server in %s:%ui",
                          conf->file, conf->line);

            return NJT_CONF_ERROR;
        }
    }

    njt_conf_merge_msec_value(conf->timeout, prev->timeout, 60000);

    njt_conf_merge_value(conf->pass_client_cert, prev->pass_client_cert, 0);

    if (conf->headers == NULL) {
        conf->headers = prev->headers;
        conf->header = prev->header;
    }

    if (conf->headers && conf->header.len == 0) {
        len = 0;
        header = conf->headers->elts;
        for (i = 0; i < conf->headers->nelts; i++) {
            len += header[i].key.len + 2 + header[i].value.len + 2;
        }

        p = njt_pnalloc(cf->pool, len);
        if (p == NULL) {
            return NJT_CONF_ERROR;
        }

        conf->header.len = len;
        conf->header.data = p;

        for (i = 0; i < conf->headers->nelts; i++) {
            p = njt_cpymem(p, header[i].key.data, header[i].key.len);
            *p++ = ':'; *p++ = ' ';
            p = njt_cpymem(p, header[i].value.data, header[i].value.len);
            *p++ = CR; *p++ = LF;
        }
    }

    return NJT_CONF_OK;
}


static char *
njt_mail_auth_http(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_mail_auth_http_conf_t *ahcf = conf;

    njt_str_t  *value;
    njt_url_t   u;

    value = cf->args->elts;

    njt_memzero(&u, sizeof(njt_url_t));

    u.url = value[1];
    u.default_port = 80;
    u.uri_part = 1;

    if (njt_strncmp(u.url.data, "http://", 7) == 0) {
        u.url.len -= 7;
        u.url.data += 7;
    }

    if (njt_parse_url(cf->pool, &u) != NJT_OK) {
        if (u.err) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "%s in auth_http \"%V\"", u.err, &u.url);
        }

        return NJT_CONF_ERROR;
    }

    ahcf->peer = u.addrs;

    if (u.family != AF_UNIX) {
        ahcf->host_header = u.host;

    } else {
        njt_str_set(&ahcf->host_header, "localhost");
    }

    ahcf->uri = u.uri;

    if (ahcf->uri.len == 0) {
        njt_str_set(&ahcf->uri, "/");
    }

    return NJT_CONF_OK;
}


static char *
njt_mail_auth_http_header(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_mail_auth_http_conf_t *ahcf = conf;

    njt_str_t        *value;
    njt_table_elt_t  *header;

    if (ahcf->headers == NULL) {
        ahcf->headers = njt_array_create(cf->pool, 1, sizeof(njt_table_elt_t));
        if (ahcf->headers == NULL) {
            return NJT_CONF_ERROR;
        }
    }

    header = njt_array_push(ahcf->headers);
    if (header == NULL) {
        return NJT_CONF_ERROR;
    }

    value = cf->args->elts;

    header->key = value[1];
    header->value = value[2];

    return NJT_CONF_OK;
}
