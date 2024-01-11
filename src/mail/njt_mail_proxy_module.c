
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
    njt_flag_t  enable;
    njt_flag_t  pass_error_message;
    njt_flag_t  xclient;
    njt_flag_t  smtp_auth;
    njt_flag_t  proxy_protocol;
    size_t      buffer_size;
    njt_msec_t  timeout;
} njt_mail_proxy_conf_t;


static void njt_mail_proxy_block_read(njt_event_t *rev);
static void njt_mail_proxy_pop3_handler(njt_event_t *rev);
static void njt_mail_proxy_imap_handler(njt_event_t *rev);
static void njt_mail_proxy_smtp_handler(njt_event_t *rev);
static void njt_mail_proxy_write_handler(njt_event_t *wev);
static njt_int_t njt_mail_proxy_send_proxy_protocol(njt_mail_session_t *s);
static njt_int_t njt_mail_proxy_read_response(njt_mail_session_t *s,
    njt_uint_t state);
static void njt_mail_proxy_handler(njt_event_t *ev);
static void njt_mail_proxy_upstream_error(njt_mail_session_t *s);
static void njt_mail_proxy_internal_server_error(njt_mail_session_t *s);
static void njt_mail_proxy_close_session(njt_mail_session_t *s);
static void *njt_mail_proxy_create_conf(njt_conf_t *cf);
static char *njt_mail_proxy_merge_conf(njt_conf_t *cf, void *parent,
    void *child);


static njt_command_t  njt_mail_proxy_commands[] = {

    { njt_string("proxy"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_proxy_conf_t, enable),
      NULL },

    { njt_string("proxy_buffer"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_proxy_conf_t, buffer_size),
      NULL },

    { njt_string("proxy_timeout"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_proxy_conf_t, timeout),
      NULL },

    { njt_string("proxy_pass_error_message"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_proxy_conf_t, pass_error_message),
      NULL },

    { njt_string("xclient"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_proxy_conf_t, xclient),
      NULL },

    { njt_string("proxy_smtp_auth"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_proxy_conf_t, smtp_auth),
      NULL },

    { njt_string("proxy_protocol"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_proxy_conf_t, proxy_protocol),
      NULL },

      njt_null_command
};


static njt_mail_module_t  njt_mail_proxy_module_ctx = {
    NULL,                                  /* protocol */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    njt_mail_proxy_create_conf,            /* create server configuration */
    njt_mail_proxy_merge_conf              /* merge server configuration */
};


njt_module_t  njt_mail_proxy_module = {
    NJT_MODULE_V1,
    &njt_mail_proxy_module_ctx,            /* module context */
    njt_mail_proxy_commands,               /* module directives */
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


static u_char  smtp_auth_ok[] = "235 2.0.0 OK" CRLF;


void
njt_mail_proxy_init(njt_mail_session_t *s, njt_addr_t *peer)
{
    njt_int_t                  rc;
    njt_mail_proxy_ctx_t      *p;
    njt_mail_proxy_conf_t     *pcf;
    njt_mail_core_srv_conf_t  *cscf;

    s->connection->log->action = "connecting to upstream";

    cscf = njt_mail_get_module_srv_conf(s, njt_mail_core_module);

    p = njt_pcalloc(s->connection->pool, sizeof(njt_mail_proxy_ctx_t));
    if (p == NULL) {
        njt_mail_session_internal_server_error(s);
        return;
    }

    s->proxy = p;

    p->upstream.sockaddr = peer->sockaddr;
    p->upstream.socklen = peer->socklen;
    p->upstream.name = &peer->name;
    p->upstream.get = njt_event_get_peer;
    p->upstream.log = s->connection->log;
    p->upstream.log_error = NJT_ERROR_ERR;

    rc = njt_event_connect_peer(&p->upstream);

    if (rc == NJT_ERROR || rc == NJT_BUSY || rc == NJT_DECLINED) {
        njt_mail_proxy_internal_server_error(s);
        return;
    }

    njt_add_timer(p->upstream.connection->read, cscf->timeout);

    p->upstream.connection->data = s;
    p->upstream.connection->pool = s->connection->pool;

    s->connection->read->handler = njt_mail_proxy_block_read;
    p->upstream.connection->write->handler = njt_mail_proxy_write_handler;

    pcf = njt_mail_get_module_srv_conf(s, njt_mail_proxy_module);

    s->proxy->buffer = njt_create_temp_buf(s->connection->pool,
                                           pcf->buffer_size);
    if (s->proxy->buffer == NULL) {
        njt_mail_proxy_internal_server_error(s);
        return;
    }

    s->proxy->proxy_protocol = pcf->proxy_protocol;

    s->out.len = 0;

    switch (s->protocol) {

    case NJT_MAIL_POP3_PROTOCOL:
        p->upstream.connection->read->handler = njt_mail_proxy_pop3_handler;
        s->mail_state = njt_pop3_start;
        break;

    case NJT_MAIL_IMAP_PROTOCOL:
        p->upstream.connection->read->handler = njt_mail_proxy_imap_handler;
        s->mail_state = njt_imap_start;
        break;

    default: /* NJT_MAIL_SMTP_PROTOCOL */
        p->upstream.connection->read->handler = njt_mail_proxy_smtp_handler;
        s->mail_state = njt_smtp_start;
        break;
    }

    if (rc == NJT_AGAIN) {
        return;
    }

    njt_mail_proxy_write_handler(p->upstream.connection->write);
}


static void
njt_mail_proxy_block_read(njt_event_t *rev)
{
    njt_connection_t    *c;
    njt_mail_session_t  *s;

    njt_log_debug0(NJT_LOG_DEBUG_MAIL, rev->log, 0, "mail proxy block read");

    if (njt_handle_read_event(rev, 0) != NJT_OK) {
        c = rev->data;
        s = c->data;

        njt_mail_proxy_close_session(s);
    }
}


static void
njt_mail_proxy_pop3_handler(njt_event_t *rev)
{
    u_char                 *p;
    njt_int_t               rc;
    njt_str_t               line;
    njt_connection_t       *c;
    njt_mail_session_t     *s;
    njt_mail_proxy_conf_t  *pcf;

    njt_log_debug0(NJT_LOG_DEBUG_MAIL, rev->log, 0,
                   "mail proxy pop3 auth handler");

    c = rev->data;
    s = c->data;

    if (rev->timedout) {
        njt_log_error(NJT_LOG_INFO, c->log, NJT_ETIMEDOUT,
                      "upstream timed out");
        c->timedout = 1;
        njt_mail_proxy_internal_server_error(s);
        return;
    }

    if (s->proxy->proxy_protocol) {
        njt_log_debug0(NJT_LOG_DEBUG_MAIL, c->log, 0, "mail proxy pop3 busy");

        if (njt_handle_read_event(c->read, 0) != NJT_OK) {
            njt_mail_proxy_internal_server_error(s);
            return;
        }

        return;
    }

    rc = njt_mail_proxy_read_response(s, 0);

    if (rc == NJT_AGAIN) {
        if (njt_handle_read_event(c->read, 0) != NJT_OK) {
            njt_mail_proxy_internal_server_error(s);
            return;
        }

        return;
    }

    if (rc == NJT_ERROR) {
        njt_mail_proxy_upstream_error(s);
        return;
    }

    switch (s->mail_state) {

    case njt_pop3_start:
        njt_log_debug0(NJT_LOG_DEBUG_MAIL, rev->log, 0, "mail proxy send user");

        s->connection->log->action = "sending user name to upstream";

        line.len = sizeof("USER ")  - 1 + s->login.len + 2;
        line.data = njt_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            njt_mail_proxy_internal_server_error(s);
            return;
        }

        p = njt_cpymem(line.data, "USER ", sizeof("USER ") - 1);
        p = njt_cpymem(p, s->login.data, s->login.len);
        *p++ = CR; *p = LF;

        s->mail_state = njt_pop3_user;
        break;

    case njt_pop3_user:
        njt_log_debug0(NJT_LOG_DEBUG_MAIL, rev->log, 0, "mail proxy send pass");

        s->connection->log->action = "sending password to upstream";

        line.len = sizeof("PASS ")  - 1 + s->passwd.len + 2;
        line.data = njt_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            njt_mail_proxy_internal_server_error(s);
            return;
        }

        p = njt_cpymem(line.data, "PASS ", sizeof("PASS ") - 1);
        p = njt_cpymem(p, s->passwd.data, s->passwd.len);
        *p++ = CR; *p = LF;

        s->mail_state = njt_pop3_passwd;
        break;

    case njt_pop3_passwd:
        s->connection->read->handler = njt_mail_proxy_handler;
        s->connection->write->handler = njt_mail_proxy_handler;
        rev->handler = njt_mail_proxy_handler;
        c->write->handler = njt_mail_proxy_handler;

        pcf = njt_mail_get_module_srv_conf(s, njt_mail_proxy_module);
        njt_add_timer(s->connection->read, pcf->timeout);
        njt_del_timer(c->read);

        c->log->action = NULL;
        njt_log_error(NJT_LOG_INFO, c->log, 0, "client logged in");

        if (s->buffer->pos < s->buffer->last
            || s->connection->read->ready)
        {
            njt_post_event(c->write, &njt_posted_events);
        }

        njt_mail_proxy_handler(s->connection->write);

        return;

    default:
#if (NJT_SUPPRESS_WARN)
        njt_str_null(&line);
#endif
        break;
    }

    if (c->send(c, line.data, line.len) < (ssize_t) line.len) {
        /*
         * we treat the incomplete sending as NJT_ERROR
         * because it is very strange here
         */
        njt_mail_proxy_internal_server_error(s);
        return;
    }

    if (njt_handle_read_event(c->read, 0) != NJT_OK) {
        njt_mail_proxy_internal_server_error(s);
        return;
    }

    s->proxy->buffer->pos = s->proxy->buffer->start;
    s->proxy->buffer->last = s->proxy->buffer->start;
}


static void
njt_mail_proxy_imap_handler(njt_event_t *rev)
{
    u_char                 *p;
    njt_int_t               rc;
    njt_str_t               line;
    njt_connection_t       *c;
    njt_mail_session_t     *s;
    njt_mail_proxy_conf_t  *pcf;

    njt_log_debug0(NJT_LOG_DEBUG_MAIL, rev->log, 0,
                   "mail proxy imap auth handler");

    c = rev->data;
    s = c->data;

    if (rev->timedout) {
        njt_log_error(NJT_LOG_INFO, c->log, NJT_ETIMEDOUT,
                      "upstream timed out");
        c->timedout = 1;
        njt_mail_proxy_internal_server_error(s);
        return;
    }

    if (s->proxy->proxy_protocol) {
        njt_log_debug0(NJT_LOG_DEBUG_MAIL, c->log, 0, "mail proxy imap busy");

        if (njt_handle_read_event(c->read, 0) != NJT_OK) {
            njt_mail_proxy_internal_server_error(s);
            return;
        }

        return;
    }

    rc = njt_mail_proxy_read_response(s, s->mail_state);

    if (rc == NJT_AGAIN) {
        if (njt_handle_read_event(c->read, 0) != NJT_OK) {
            njt_mail_proxy_internal_server_error(s);
            return;
        }

        return;
    }

    if (rc == NJT_ERROR) {
        njt_mail_proxy_upstream_error(s);
        return;
    }

    switch (s->mail_state) {

    case njt_imap_start:
        njt_log_debug0(NJT_LOG_DEBUG_MAIL, rev->log, 0,
                       "mail proxy send login");

        s->connection->log->action = "sending LOGIN command to upstream";

        line.len = s->tag.len + sizeof("LOGIN ") - 1
                   + 1 + NJT_SIZE_T_LEN + 1 + 2;
        line.data = njt_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            njt_mail_proxy_internal_server_error(s);
            return;
        }

        line.len = njt_sprintf(line.data, "%VLOGIN {%uz}" CRLF,
                               &s->tag, s->login.len)
                   - line.data;

        s->mail_state = njt_imap_login;
        break;

    case njt_imap_login:
        njt_log_debug0(NJT_LOG_DEBUG_MAIL, rev->log, 0, "mail proxy send user");

        s->connection->log->action = "sending user name to upstream";

        line.len = s->login.len + 1 + 1 + NJT_SIZE_T_LEN + 1 + 2;
        line.data = njt_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            njt_mail_proxy_internal_server_error(s);
            return;
        }

        line.len = njt_sprintf(line.data, "%V {%uz}" CRLF,
                               &s->login, s->passwd.len)
                   - line.data;

        s->mail_state = njt_imap_user;
        break;

    case njt_imap_user:
        njt_log_debug0(NJT_LOG_DEBUG_MAIL, rev->log, 0,
                       "mail proxy send passwd");

        s->connection->log->action = "sending password to upstream";

        line.len = s->passwd.len + 2;
        line.data = njt_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            njt_mail_proxy_internal_server_error(s);
            return;
        }

        p = njt_cpymem(line.data, s->passwd.data, s->passwd.len);
        *p++ = CR; *p = LF;

        s->mail_state = njt_imap_passwd;
        break;

    case njt_imap_passwd:
        s->connection->read->handler = njt_mail_proxy_handler;
        s->connection->write->handler = njt_mail_proxy_handler;
        rev->handler = njt_mail_proxy_handler;
        c->write->handler = njt_mail_proxy_handler;

        pcf = njt_mail_get_module_srv_conf(s, njt_mail_proxy_module);
        njt_add_timer(s->connection->read, pcf->timeout);
        njt_del_timer(c->read);

        c->log->action = NULL;
        njt_log_error(NJT_LOG_INFO, c->log, 0, "client logged in");

        if (s->buffer->pos < s->buffer->last
            || s->connection->read->ready)
        {
            njt_post_event(c->write, &njt_posted_events);
        }

        njt_mail_proxy_handler(s->connection->write);

        return;

    default:
#if (NJT_SUPPRESS_WARN)
        njt_str_null(&line);
#endif
        break;
    }

    if (c->send(c, line.data, line.len) < (ssize_t) line.len) {
        /*
         * we treat the incomplete sending as NJT_ERROR
         * because it is very strange here
         */
        njt_mail_proxy_internal_server_error(s);
        return;
    }

    if (njt_handle_read_event(c->read, 0) != NJT_OK) {
        njt_mail_proxy_internal_server_error(s);
        return;
    }

    s->proxy->buffer->pos = s->proxy->buffer->start;
    s->proxy->buffer->last = s->proxy->buffer->start;
}


static void
njt_mail_proxy_smtp_handler(njt_event_t *rev)
{
    u_char                    *p;
    njt_int_t                  rc;
    njt_str_t                  line, auth, encoded;
    njt_buf_t                 *b;
    njt_connection_t          *c;
    njt_mail_session_t        *s;
    njt_mail_proxy_conf_t     *pcf;
    njt_mail_core_srv_conf_t  *cscf;

    njt_log_debug0(NJT_LOG_DEBUG_MAIL, rev->log, 0,
                   "mail proxy smtp auth handler");

    c = rev->data;
    s = c->data;

    if (rev->timedout) {
        njt_log_error(NJT_LOG_INFO, c->log, NJT_ETIMEDOUT,
                      "upstream timed out");
        c->timedout = 1;
        njt_mail_proxy_internal_server_error(s);
        return;
    }

    if (s->proxy->proxy_protocol) {
        njt_log_debug0(NJT_LOG_DEBUG_MAIL, c->log, 0, "mail proxy smtp busy");

        if (njt_handle_read_event(c->read, 0) != NJT_OK) {
            njt_mail_proxy_internal_server_error(s);
            return;
        }

        return;
    }

    rc = njt_mail_proxy_read_response(s, s->mail_state);

    if (rc == NJT_AGAIN) {
        if (njt_handle_read_event(c->read, 0) != NJT_OK) {
            njt_mail_proxy_internal_server_error(s);
            return;
        }

        return;
    }

    if (rc == NJT_ERROR) {
        njt_mail_proxy_upstream_error(s);
        return;
    }

    switch (s->mail_state) {

    case njt_smtp_start:
        njt_log_debug0(NJT_LOG_DEBUG_MAIL, rev->log, 0, "mail proxy send ehlo");

        s->connection->log->action = "sending HELO/EHLO to upstream";

        cscf = njt_mail_get_module_srv_conf(s, njt_mail_core_module);

        line.len = sizeof("HELO ")  - 1 + cscf->server_name.len + 2;
        line.data = njt_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            njt_mail_proxy_internal_server_error(s);
            return;
        }

        pcf = njt_mail_get_module_srv_conf(s, njt_mail_proxy_module);

        p = njt_cpymem(line.data,
                       ((s->esmtp || pcf->xclient) ? "EHLO " : "HELO "),
                       sizeof("HELO ") - 1);

        p = njt_cpymem(p, cscf->server_name.data, cscf->server_name.len);
        *p++ = CR; *p = LF;

        if (pcf->xclient) {
            s->mail_state = njt_smtp_helo_xclient;

        } else if (s->auth_method == NJT_MAIL_AUTH_NONE) {
            s->mail_state = njt_smtp_helo_from;

        } else if (pcf->smtp_auth) {
            s->mail_state = njt_smtp_helo_auth;

        } else {
            s->mail_state = njt_smtp_helo;
        }

        break;

    case njt_smtp_helo_xclient:
        njt_log_debug0(NJT_LOG_DEBUG_MAIL, rev->log, 0,
                       "mail proxy send xclient");

        s->connection->log->action = "sending XCLIENT to upstream";

        line.len = sizeof("XCLIENT ADDR= LOGIN= NAME="
                          CRLF) - 1
                   + s->connection->addr_text.len + s->login.len + s->host.len;

#if (NJT_HAVE_INET6)
        if (s->connection->sockaddr->sa_family == AF_INET6) {
            line.len += sizeof("IPV6:") - 1;
        }
#endif

        line.data = njt_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            njt_mail_proxy_internal_server_error(s);
            return;
        }

        p = njt_cpymem(line.data, "XCLIENT ADDR=", sizeof("XCLIENT ADDR=") - 1);

#if (NJT_HAVE_INET6)
        if (s->connection->sockaddr->sa_family == AF_INET6) {
            p = njt_cpymem(p, "IPV6:", sizeof("IPV6:") - 1);
        }
#endif

        p = njt_copy(p, s->connection->addr_text.data,
                     s->connection->addr_text.len);

        pcf = njt_mail_get_module_srv_conf(s, njt_mail_proxy_module);

        if (s->login.len && !pcf->smtp_auth) {
            p = njt_cpymem(p, " LOGIN=", sizeof(" LOGIN=") - 1);
            p = njt_copy(p, s->login.data, s->login.len);
        }

        p = njt_cpymem(p, " NAME=", sizeof(" NAME=") - 1);
        p = njt_copy(p, s->host.data, s->host.len);

        *p++ = CR; *p++ = LF;

        line.len = p - line.data;

        if (s->smtp_helo.len) {
            s->mail_state = njt_smtp_xclient_helo;

        } else if (s->auth_method == NJT_MAIL_AUTH_NONE) {
            s->mail_state = njt_smtp_xclient_from;

        } else if (pcf->smtp_auth) {
            s->mail_state = njt_smtp_xclient_auth;

        } else {
            s->mail_state = njt_smtp_xclient;
        }

        break;

    case njt_smtp_xclient_helo:
        njt_log_debug0(NJT_LOG_DEBUG_MAIL, rev->log, 0,
                       "mail proxy send client ehlo");

        s->connection->log->action = "sending client HELO/EHLO to upstream";

        line.len = sizeof("HELO " CRLF) - 1 + s->smtp_helo.len;

        line.data = njt_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            njt_mail_proxy_internal_server_error(s);
            return;
        }

        line.len = njt_sprintf(line.data,
                       ((s->esmtp) ? "EHLO %V" CRLF : "HELO %V" CRLF),
                       &s->smtp_helo)
                   - line.data;

        pcf = njt_mail_get_module_srv_conf(s, njt_mail_proxy_module);

        if (s->auth_method == NJT_MAIL_AUTH_NONE) {
            s->mail_state = njt_smtp_helo_from;

        } else if (pcf->smtp_auth) {
            s->mail_state = njt_smtp_helo_auth;

        } else {
            s->mail_state = njt_smtp_helo;
        }

        break;

    case njt_smtp_helo_auth:
    case njt_smtp_xclient_auth:
        njt_log_debug0(NJT_LOG_DEBUG_MAIL, rev->log, 0,
                       "mail proxy send auth");

        s->connection->log->action = "sending AUTH to upstream";

        if (s->passwd.data == NULL) {
            njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                          "no password available");
            njt_mail_proxy_internal_server_error(s);
            return;
        }

        auth.len = 1 + s->login.len + 1 + s->passwd.len;
        auth.data = njt_pnalloc(c->pool, auth.len);
        if (auth.data == NULL) {
            njt_mail_proxy_internal_server_error(s);
            return;
        }

        auth.len = njt_sprintf(auth.data, "%Z%V%Z%V", &s->login, &s->passwd)
                   - auth.data;

        line.len = sizeof("AUTH PLAIN " CRLF) - 1
                   + njt_base64_encoded_length(auth.len);

        line.data = njt_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            njt_mail_proxy_internal_server_error(s);
            return;
        }

        encoded.data = njt_cpymem(line.data, "AUTH PLAIN ",
                                  sizeof("AUTH PLAIN ") - 1);

        njt_encode_base64(&encoded, &auth);

        p = encoded.data + encoded.len;
        *p++ = CR; *p = LF;

        s->mail_state = njt_smtp_auth_plain;

        break;

    case njt_smtp_helo_from:
    case njt_smtp_xclient_from:
        njt_log_debug0(NJT_LOG_DEBUG_MAIL, rev->log, 0,
                       "mail proxy send mail from");

        s->connection->log->action = "sending MAIL FROM to upstream";

        line.len = s->smtp_from.len + sizeof(CRLF) - 1;
        line.data = njt_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            njt_mail_proxy_internal_server_error(s);
            return;
        }

        p = njt_cpymem(line.data, s->smtp_from.data, s->smtp_from.len);
        *p++ = CR; *p = LF;

        s->mail_state = njt_smtp_from;

        break;

    case njt_smtp_from:
        njt_log_debug0(NJT_LOG_DEBUG_MAIL, rev->log, 0,
                       "mail proxy send rcpt to");

        s->connection->log->action = "sending RCPT TO to upstream";

        line.len = s->smtp_to.len + sizeof(CRLF) - 1;
        line.data = njt_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            njt_mail_proxy_internal_server_error(s);
            return;
        }

        p = njt_cpymem(line.data, s->smtp_to.data, s->smtp_to.len);
        *p++ = CR; *p = LF;

        s->mail_state = njt_smtp_to;

        break;

    case njt_smtp_helo:
    case njt_smtp_xclient:
    case njt_smtp_auth_plain:
    case njt_smtp_to:

        b = s->proxy->buffer;

        if (s->auth_method == NJT_MAIL_AUTH_NONE) {
            b->pos = b->start;

        } else {
            njt_memcpy(b->start, smtp_auth_ok, sizeof(smtp_auth_ok) - 1);
            b->last = b->start + sizeof(smtp_auth_ok) - 1;
        }

        s->connection->read->handler = njt_mail_proxy_handler;
        s->connection->write->handler = njt_mail_proxy_handler;
        rev->handler = njt_mail_proxy_handler;
        c->write->handler = njt_mail_proxy_handler;

        pcf = njt_mail_get_module_srv_conf(s, njt_mail_proxy_module);
        njt_add_timer(s->connection->read, pcf->timeout);
        njt_del_timer(c->read);

        c->log->action = NULL;
        njt_log_error(NJT_LOG_INFO, c->log, 0, "client logged in");

        if (s->buffer->pos < s->buffer->last
            || s->connection->read->ready)
        {
            njt_post_event(c->write, &njt_posted_events);
        }

        njt_mail_proxy_handler(s->connection->write);

        return;

    default:
#if (NJT_SUPPRESS_WARN)
        njt_str_null(&line);
#endif
        break;
    }

    if (c->send(c, line.data, line.len) < (ssize_t) line.len) {
        /*
         * we treat the incomplete sending as NJT_ERROR
         * because it is very strange here
         */
        njt_mail_proxy_internal_server_error(s);
        return;
    }

    if (njt_handle_read_event(c->read, 0) != NJT_OK) {
        njt_mail_proxy_internal_server_error(s);
        return;
    }

    s->proxy->buffer->pos = s->proxy->buffer->start;
    s->proxy->buffer->last = s->proxy->buffer->start;
}


static void
njt_mail_proxy_write_handler(njt_event_t *wev)
{
    njt_connection_t    *c;
    njt_mail_session_t  *s;

    njt_log_debug0(NJT_LOG_DEBUG_MAIL, wev->log, 0, "mail proxy write handler");

    c = wev->data;
    s = c->data;

    if (s->proxy->proxy_protocol) {
        if (njt_mail_proxy_send_proxy_protocol(s) != NJT_OK) {
            return;
        }

        s->proxy->proxy_protocol = 0;
    }

    if (njt_handle_write_event(wev, 0) != NJT_OK) {
        njt_mail_proxy_internal_server_error(s);
    }

    if (c->read->ready) {
        njt_post_event(c->read, &njt_posted_events);
    }
}


static njt_int_t
njt_mail_proxy_send_proxy_protocol(njt_mail_session_t *s)
{
    u_char            *p;
    ssize_t            n, size;
    njt_connection_t  *c;
    u_char             buf[NJT_PROXY_PROTOCOL_V1_MAX_HEADER];

    s->connection->log->action = "sending PROXY protocol header to upstream";

    njt_log_debug0(NJT_LOG_DEBUG_MAIL, s->connection->log, 0,
                   "mail proxy send PROXY protocol header");

    p = njt_proxy_protocol_write(s->connection, buf,
                                 buf + NJT_PROXY_PROTOCOL_V1_MAX_HEADER);
    if (p == NULL) {
        njt_mail_proxy_internal_server_error(s);
        return NJT_ERROR;
    }

    c = s->proxy->upstream.connection;

    size = p - buf;

    n = c->send(c, buf, size);

    if (n == NJT_AGAIN) {
        if (njt_handle_write_event(c->write, 0) != NJT_OK) {
            njt_mail_proxy_internal_server_error(s);
            return NJT_ERROR;
        }

        return NJT_AGAIN;
    }

    if (n == NJT_ERROR) {
        njt_mail_proxy_internal_server_error(s);
        return NJT_ERROR;
    }

    if (n != size) {

        /*
         * PROXY protocol specification:
         * The sender must always ensure that the header
         * is sent at once, so that the transport layer
         * maintains atomicity along the path to the receiver.
         */

        njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                      "could not send PROXY protocol header at once");

        njt_mail_proxy_internal_server_error(s);

        return NJT_ERROR;
    }

    return NJT_OK;
}


static njt_int_t
njt_mail_proxy_read_response(njt_mail_session_t *s, njt_uint_t state)
{
    u_char                 *p, *m;
    ssize_t                 n;
    njt_buf_t              *b;
    njt_mail_proxy_conf_t  *pcf;

    s->connection->log->action = "reading response from upstream";

    b = s->proxy->buffer;

    n = s->proxy->upstream.connection->recv(s->proxy->upstream.connection,
                                            b->last, b->end - b->last);

    if (n == NJT_ERROR || n == 0) {
        return NJT_ERROR;
    }

    if (n == NJT_AGAIN) {
        return NJT_AGAIN;
    }

    b->last += n;

    if (b->last - b->pos < 4) {
        return NJT_AGAIN;
    }

    if (*(b->last - 2) != CR || *(b->last - 1) != LF) {
        if (b->last == b->end) {
            *(b->last - 1) = '\0';
            njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                          "upstream sent too long response line: \"%s\"",
                          b->pos);
            return NJT_ERROR;
        }

        return NJT_AGAIN;
    }

    p = b->pos;

    switch (s->protocol) {

    case NJT_MAIL_POP3_PROTOCOL:
        if (p[0] == '+' && p[1] == 'O' && p[2] == 'K') {
            return NJT_OK;
        }
        break;

    case NJT_MAIL_IMAP_PROTOCOL:
        switch (state) {

        case njt_imap_start:
            if (p[0] == '*' && p[1] == ' ' && p[2] == 'O' && p[3] == 'K') {
                return NJT_OK;
            }
            break;

        case njt_imap_login:
        case njt_imap_user:
            if (p[0] == '+') {
                return NJT_OK;
            }
            break;

        case njt_imap_passwd:
            if (njt_strncmp(p, s->tag.data, s->tag.len) == 0) {
                p += s->tag.len;
                if (p[0] == 'O' && p[1] == 'K') {
                    return NJT_OK;
                }
            }
            break;
        }

        break;

    default: /* NJT_MAIL_SMTP_PROTOCOL */

        if (p[3] == '-') {
            /* multiline reply, check if we got last line */

            m = b->last - (sizeof(CRLF "200" CRLF) - 1);

            while (m > p) {
                if (m[0] == CR && m[1] == LF) {
                    break;
                }

                m--;
            }

            if (m <= p || m[5] == '-') {
                return NJT_AGAIN;
            }
        }

        switch (state) {

        case njt_smtp_start:
            if (p[0] == '2' && p[1] == '2' && p[2] == '0') {
                return NJT_OK;
            }
            break;

        case njt_smtp_helo:
        case njt_smtp_helo_xclient:
        case njt_smtp_helo_from:
        case njt_smtp_helo_auth:
        case njt_smtp_from:
            if (p[0] == '2' && p[1] == '5' && p[2] == '0') {
                return NJT_OK;
            }
            break;

        case njt_smtp_xclient:
        case njt_smtp_xclient_from:
        case njt_smtp_xclient_helo:
        case njt_smtp_xclient_auth:
            if (p[0] == '2' && (p[1] == '2' || p[1] == '5') && p[2] == '0') {
                return NJT_OK;
            }
            break;

        case njt_smtp_auth_plain:
            if (p[0] == '2' && p[1] == '3' && p[2] == '5') {
                return NJT_OK;
            }
            break;

        case njt_smtp_to:
            return NJT_OK;
        }

        break;
    }

    pcf = njt_mail_get_module_srv_conf(s, njt_mail_proxy_module);

    if (pcf->pass_error_message == 0) {
        *(b->last - 2) = '\0';
        njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                      "upstream sent invalid response: \"%s\"", p);
        return NJT_ERROR;
    }

    s->out.len = b->last - p - 2;
    s->out.data = p;

    njt_log_error(NJT_LOG_INFO, s->connection->log, 0,
                  "upstream sent invalid response: \"%V\"", &s->out);

    s->out.len = b->last - b->pos;
    s->out.data = b->pos;

    return NJT_ERROR;
}


static void
njt_mail_proxy_handler(njt_event_t *ev)
{
    char                   *action, *recv_action, *send_action;
    size_t                  size;
    ssize_t                 n;
    njt_buf_t              *b;
    njt_uint_t              do_write;
    njt_connection_t       *c, *src, *dst;
    njt_mail_session_t     *s;
    njt_mail_proxy_conf_t  *pcf;

    c = ev->data;
    s = c->data;

    if (ev->timedout || c->close) {
        c->log->action = "proxying";

        if (c->close) {
            njt_log_error(NJT_LOG_INFO, c->log, 0, "shutdown timeout");

        } else if (c == s->connection) {
            njt_log_error(NJT_LOG_INFO, c->log, NJT_ETIMEDOUT,
                          "client timed out");
            c->timedout = 1;

        } else {
            njt_log_error(NJT_LOG_INFO, c->log, NJT_ETIMEDOUT,
                          "upstream timed out");
        }

        njt_mail_proxy_close_session(s);
        return;
    }

    if (c == s->connection) {
        if (ev->write) {
            recv_action = "proxying and reading from upstream";
            send_action = "proxying and sending to client";
            src = s->proxy->upstream.connection;
            dst = c;
            b = s->proxy->buffer;

        } else {
            recv_action = "proxying and reading from client";
            send_action = "proxying and sending to upstream";
            src = c;
            dst = s->proxy->upstream.connection;
            b = s->buffer;
        }

    } else {
        if (ev->write) {
            recv_action = "proxying and reading from client";
            send_action = "proxying and sending to upstream";
            src = s->connection;
            dst = c;
            b = s->buffer;

        } else {
            recv_action = "proxying and reading from upstream";
            send_action = "proxying and sending to client";
            src = c;
            dst = s->connection;
            b = s->proxy->buffer;
        }
    }

    do_write = ev->write ? 1 : 0;

    njt_log_debug3(NJT_LOG_DEBUG_MAIL, ev->log, 0,
                   "mail proxy handler: %ui, #%d > #%d",
                   do_write, src->fd, dst->fd);

    for ( ;; ) {

        if (do_write) {

            size = b->last - b->pos;

            if (size && dst->write->ready) {
                c->log->action = send_action;

                n = dst->send(dst, b->pos, size);

                if (n == NJT_ERROR) {
                    njt_mail_proxy_close_session(s);
                    return;
                }

                if (n > 0) {
                    b->pos += n;

                    if (b->pos == b->last) {
                        b->pos = b->start;
                        b->last = b->start;
                    }
                }
            }
        }

        size = b->end - b->last;

        if (size && src->read->ready) {
            c->log->action = recv_action;

            n = src->recv(src, b->last, size);

            if (n == NJT_AGAIN || n == 0) {
                break;
            }

            if (n > 0) {
                do_write = 1;
                b->last += n;

                continue;
            }

            if (n == NJT_ERROR) {
                src->read->eof = 1;
            }
        }

        break;
    }

    c->log->action = "proxying";

    if ((s->connection->read->eof && s->buffer->pos == s->buffer->last)
        || (s->proxy->upstream.connection->read->eof
            && s->proxy->buffer->pos == s->proxy->buffer->last)
        || (s->connection->read->eof
            && s->proxy->upstream.connection->read->eof))
    {
        action = c->log->action;
        c->log->action = NULL;
        njt_log_error(NJT_LOG_INFO, c->log, 0, "proxied session done");
        c->log->action = action;

        njt_mail_proxy_close_session(s);
        return;
    }

    if (njt_handle_write_event(dst->write, 0) != NJT_OK) {
        njt_mail_proxy_close_session(s);
        return;
    }

    if (njt_handle_read_event(dst->read, 0) != NJT_OK) {
        njt_mail_proxy_close_session(s);
        return;
    }

    if (njt_handle_write_event(src->write, 0) != NJT_OK) {
        njt_mail_proxy_close_session(s);
        return;
    }

    if (njt_handle_read_event(src->read, 0) != NJT_OK) {
        njt_mail_proxy_close_session(s);
        return;
    }

    if (c == s->connection) {
        pcf = njt_mail_get_module_srv_conf(s, njt_mail_proxy_module);
        njt_add_timer(c->read, pcf->timeout);
    }
}


static void
njt_mail_proxy_upstream_error(njt_mail_session_t *s)
{
    if (s->proxy->upstream.connection) {
        njt_log_debug1(NJT_LOG_DEBUG_MAIL, s->connection->log, 0,
                       "close mail proxy connection: %d",
                       s->proxy->upstream.connection->fd);

        njt_close_connection(s->proxy->upstream.connection);
    }

    if (s->out.len == 0) {
        njt_mail_session_internal_server_error(s);
        return;
    }

    s->quit = 1;
    njt_mail_send(s->connection->write);
}


static void
njt_mail_proxy_internal_server_error(njt_mail_session_t *s)
{
    if (s->proxy->upstream.connection) {
        njt_log_debug1(NJT_LOG_DEBUG_MAIL, s->connection->log, 0,
                       "close mail proxy connection: %d",
                       s->proxy->upstream.connection->fd);

        njt_close_connection(s->proxy->upstream.connection);
    }

    njt_mail_session_internal_server_error(s);
}


static void
njt_mail_proxy_close_session(njt_mail_session_t *s)
{
    if (s->proxy->upstream.connection) {
        njt_log_debug1(NJT_LOG_DEBUG_MAIL, s->connection->log, 0,
                       "close mail proxy connection: %d",
                       s->proxy->upstream.connection->fd);

        njt_close_connection(s->proxy->upstream.connection);
    }

    njt_mail_close_connection(s->connection);
}


static void *
njt_mail_proxy_create_conf(njt_conf_t *cf)
{
    njt_mail_proxy_conf_t  *pcf;

    pcf = njt_pcalloc(cf->pool, sizeof(njt_mail_proxy_conf_t));
    if (pcf == NULL) {
        return NULL;
    }

    pcf->enable = NJT_CONF_UNSET;
    pcf->pass_error_message = NJT_CONF_UNSET;
    pcf->xclient = NJT_CONF_UNSET;
    pcf->smtp_auth = NJT_CONF_UNSET;
    pcf->proxy_protocol = NJT_CONF_UNSET;
    pcf->buffer_size = NJT_CONF_UNSET_SIZE;
    pcf->timeout = NJT_CONF_UNSET_MSEC;

    return pcf;
}


static char *
njt_mail_proxy_merge_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_mail_proxy_conf_t *prev = parent;
    njt_mail_proxy_conf_t *conf = child;

    njt_conf_merge_value(conf->enable, prev->enable, 0);
    njt_conf_merge_value(conf->pass_error_message, prev->pass_error_message, 0);
    njt_conf_merge_value(conf->xclient, prev->xclient, 1);
    njt_conf_merge_value(conf->smtp_auth, prev->smtp_auth, 0);
    njt_conf_merge_value(conf->proxy_protocol, prev->proxy_protocol, 0);
    njt_conf_merge_size_value(conf->buffer_size, prev->buffer_size,
                              (size_t) njt_pagesize);
    njt_conf_merge_msec_value(conf->timeout, prev->timeout, 24 * 60 * 60000);

    return NJT_CONF_OK;
}
