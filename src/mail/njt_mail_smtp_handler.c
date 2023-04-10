
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>
#include <njt_mail.h>
#include <njt_mail_smtp_module.h>


static void njt_mail_smtp_resolve_addr_handler(njt_resolver_ctx_t *ctx);
static void njt_mail_smtp_resolve_name(njt_event_t *rev);
static void njt_mail_smtp_resolve_name_handler(njt_resolver_ctx_t *ctx);
static void njt_mail_smtp_block_reading(njt_event_t *rev);
static void njt_mail_smtp_greeting(njt_mail_session_t *s, njt_connection_t *c);
static void njt_mail_smtp_invalid_pipelining(njt_event_t *rev);
static njt_int_t njt_mail_smtp_create_buffer(njt_mail_session_t *s,
    njt_connection_t *c);

static njt_int_t njt_mail_smtp_helo(njt_mail_session_t *s, njt_connection_t *c);
static njt_int_t njt_mail_smtp_auth(njt_mail_session_t *s, njt_connection_t *c);
static njt_int_t njt_mail_smtp_mail(njt_mail_session_t *s, njt_connection_t *c);
static njt_int_t njt_mail_smtp_starttls(njt_mail_session_t *s,
    njt_connection_t *c);
static njt_int_t njt_mail_smtp_rset(njt_mail_session_t *s, njt_connection_t *c);
static njt_int_t njt_mail_smtp_rcpt(njt_mail_session_t *s, njt_connection_t *c);

static njt_int_t njt_mail_smtp_discard_command(njt_mail_session_t *s,
    njt_connection_t *c, char *err);
static void njt_mail_smtp_log_rejected_command(njt_mail_session_t *s,
    njt_connection_t *c, char *err);


static u_char  smtp_ok[] = "250 2.0.0 OK" CRLF;
static u_char  smtp_bye[] = "221 2.0.0 Bye" CRLF;
static u_char  smtp_starttls[] = "220 2.0.0 Start TLS" CRLF;
static u_char  smtp_next[] = "334 " CRLF;
static u_char  smtp_username[] = "334 VXNlcm5hbWU6" CRLF;
static u_char  smtp_password[] = "334 UGFzc3dvcmQ6" CRLF;
static u_char  smtp_invalid_command[] = "500 5.5.1 Invalid command" CRLF;
static u_char  smtp_invalid_pipelining[] =
    "503 5.5.0 Improper use of SMTP command pipelining" CRLF;
static u_char  smtp_invalid_argument[] = "501 5.5.4 Invalid argument" CRLF;
static u_char  smtp_auth_required[] = "530 5.7.1 Authentication required" CRLF;
static u_char  smtp_bad_sequence[] = "503 5.5.1 Bad sequence of commands" CRLF;


static njt_str_t  smtp_unavailable = njt_string("[UNAVAILABLE]");
static njt_str_t  smtp_tempunavail = njt_string("[TEMPUNAVAIL]");


void
njt_mail_smtp_init_session(njt_mail_session_t *s, njt_connection_t *c)
{
    njt_resolver_ctx_t        *ctx;
    njt_mail_core_srv_conf_t  *cscf;

    cscf = njt_mail_get_module_srv_conf(s, njt_mail_core_module);

    if (cscf->resolver == NULL) {
        s->host = smtp_unavailable;
        njt_mail_smtp_greeting(s, c);
        return;
    }

#if (NJT_HAVE_UNIX_DOMAIN)
    if (c->sockaddr->sa_family == AF_UNIX) {
        s->host = smtp_tempunavail;
        njt_mail_smtp_greeting(s, c);
        return;
    }
#endif

    c->log->action = "in resolving client address";

    ctx = njt_resolve_start(cscf->resolver, NULL);
    if (ctx == NULL) {
        njt_mail_close_connection(c);
        return;
    }

    ctx->addr.sockaddr = c->sockaddr;
    ctx->addr.socklen = c->socklen;
    ctx->handler = njt_mail_smtp_resolve_addr_handler;
    ctx->data = s;
    ctx->timeout = cscf->resolver_timeout;

    s->resolver_ctx = ctx;
    c->read->handler = njt_mail_smtp_block_reading;

    if (njt_resolve_addr(ctx) != NJT_OK) {
        njt_mail_close_connection(c);
    }
}


static void
njt_mail_smtp_resolve_addr_handler(njt_resolver_ctx_t *ctx)
{
    njt_connection_t    *c;
    njt_mail_session_t  *s;

    s = ctx->data;
    c = s->connection;

    if (ctx->state) {
        njt_log_error(NJT_LOG_ERR, c->log, 0,
                      "%V could not be resolved (%i: %s)",
                      &c->addr_text, ctx->state,
                      njt_resolver_strerror(ctx->state));

        if (ctx->state == NJT_RESOLVE_NXDOMAIN) {
            s->host = smtp_unavailable;

        } else {
            s->host = smtp_tempunavail;
        }

        njt_resolve_addr_done(ctx);

        njt_mail_smtp_greeting(s, s->connection);

        return;
    }

    c->log->action = "in resolving client hostname";

    s->host.data = njt_pstrdup(c->pool, &ctx->name);
    if (s->host.data == NULL) {
        njt_resolve_addr_done(ctx);
        njt_mail_close_connection(c);
        return;
    }

    s->host.len = ctx->name.len;

    njt_resolve_addr_done(ctx);

    njt_log_debug1(NJT_LOG_DEBUG_MAIL, c->log, 0,
                   "address resolved: %V", &s->host);

    c->read->handler = njt_mail_smtp_resolve_name;

    njt_post_event(c->read, &njt_posted_events);
}


static void
njt_mail_smtp_resolve_name(njt_event_t *rev)
{
    njt_connection_t          *c;
    njt_mail_session_t        *s;
    njt_resolver_ctx_t        *ctx;
    njt_mail_core_srv_conf_t  *cscf;

    c = rev->data;
    s = c->data;

    cscf = njt_mail_get_module_srv_conf(s, njt_mail_core_module);

    ctx = njt_resolve_start(cscf->resolver, NULL);
    if (ctx == NULL) {
        njt_mail_close_connection(c);
        return;
    }

    ctx->name = s->host;
    ctx->handler = njt_mail_smtp_resolve_name_handler;
    ctx->data = s;
    ctx->timeout = cscf->resolver_timeout;

    s->resolver_ctx = ctx;
    c->read->handler = njt_mail_smtp_block_reading;

    if (njt_resolve_name(ctx) != NJT_OK) {
        njt_mail_close_connection(c);
    }
}


static void
njt_mail_smtp_resolve_name_handler(njt_resolver_ctx_t *ctx)
{
    njt_uint_t           i;
    njt_connection_t    *c;
    njt_mail_session_t  *s;

    s = ctx->data;
    c = s->connection;

    if (ctx->state) {
        njt_log_error(NJT_LOG_ERR, c->log, 0,
                      "\"%V\" could not be resolved (%i: %s)",
                      &ctx->name, ctx->state,
                      njt_resolver_strerror(ctx->state));

        if (ctx->state == NJT_RESOLVE_NXDOMAIN) {
            s->host = smtp_unavailable;

        } else {
            s->host = smtp_tempunavail;
        }

    } else {

#if (NJT_DEBUG)
        {
        u_char     text[NJT_SOCKADDR_STRLEN];
        njt_str_t  addr;

        addr.data = text;

        for (i = 0; i < ctx->naddrs; i++) {
            addr.len = njt_sock_ntop(ctx->addrs[i].sockaddr,
                                     ctx->addrs[i].socklen,
                                     text, NJT_SOCKADDR_STRLEN, 0);

            njt_log_debug1(NJT_LOG_DEBUG_MAIL, c->log, 0,
                           "name was resolved to %V", &addr);
        }
        }
#endif

        for (i = 0; i < ctx->naddrs; i++) {
            if (njt_cmp_sockaddr(ctx->addrs[i].sockaddr, ctx->addrs[i].socklen,
                                 c->sockaddr, c->socklen, 0)
                == NJT_OK)
            {
                goto found;
            }
        }

        s->host = smtp_unavailable;
    }

found:

    njt_resolve_name_done(ctx);

    njt_mail_smtp_greeting(s, c);
}


static void
njt_mail_smtp_block_reading(njt_event_t *rev)
{
    njt_connection_t    *c;
    njt_mail_session_t  *s;
    njt_resolver_ctx_t  *ctx;

    c = rev->data;
    s = c->data;

    njt_log_debug0(NJT_LOG_DEBUG_MAIL, c->log, 0, "smtp reading blocked");

    if (njt_handle_read_event(rev, 0) != NJT_OK) {

        if (s->resolver_ctx) {
            ctx = s->resolver_ctx;

            if (ctx->handler == njt_mail_smtp_resolve_addr_handler) {
                njt_resolve_addr_done(ctx);

            } else if (ctx->handler == njt_mail_smtp_resolve_name_handler) {
                njt_resolve_name_done(ctx);
            }

            s->resolver_ctx = NULL;
        }

        njt_mail_close_connection(c);
    }
}


static void
njt_mail_smtp_greeting(njt_mail_session_t *s, njt_connection_t *c)
{
    njt_msec_t                 timeout;
    njt_mail_core_srv_conf_t  *cscf;
    njt_mail_smtp_srv_conf_t  *sscf;

    njt_log_debug1(NJT_LOG_DEBUG_MAIL, c->log, 0,
                   "smtp greeting for \"%V\"", &s->host);

    cscf = njt_mail_get_module_srv_conf(s, njt_mail_core_module);
    sscf = njt_mail_get_module_srv_conf(s, njt_mail_smtp_module);

    timeout = sscf->greeting_delay ? sscf->greeting_delay : cscf->timeout;
    njt_add_timer(c->read, timeout);

    if (njt_handle_read_event(c->read, 0) != NJT_OK) {
        njt_mail_close_connection(c);
    }

    if (c->read->ready) {
        njt_post_event(c->read, &njt_posted_events);
    }

    if (sscf->greeting_delay) {
         c->read->handler = njt_mail_smtp_invalid_pipelining;
         return;
    }

    c->read->handler = njt_mail_smtp_init_protocol;

    s->out = sscf->greeting;

    njt_mail_send(c->write);
}


static void
njt_mail_smtp_invalid_pipelining(njt_event_t *rev)
{
    njt_connection_t          *c;
    njt_mail_session_t        *s;
    njt_mail_core_srv_conf_t  *cscf;
    njt_mail_smtp_srv_conf_t  *sscf;

    c = rev->data;
    s = c->data;

    c->log->action = "in delay pipelining state";

    if (rev->timedout) {

        njt_log_debug0(NJT_LOG_DEBUG_MAIL, c->log, 0, "delay greeting");

        rev->timedout = 0;

        cscf = njt_mail_get_module_srv_conf(s, njt_mail_core_module);

        c->read->handler = njt_mail_smtp_init_protocol;

        njt_add_timer(c->read, cscf->timeout);

        if (njt_handle_read_event(c->read, 0) != NJT_OK) {
            njt_mail_close_connection(c);
            return;
        }

        sscf = njt_mail_get_module_srv_conf(s, njt_mail_smtp_module);

        s->out = sscf->greeting;

    } else {

        njt_log_debug0(NJT_LOG_DEBUG_MAIL, c->log, 0, "invalid pipelining");

        if (s->buffer == NULL) {
            if (njt_mail_smtp_create_buffer(s, c) != NJT_OK) {
                return;
            }
        }

        if (njt_mail_smtp_discard_command(s, c,
                                "client was rejected before greeting: \"%V\"")
            != NJT_OK)
        {
            return;
        }

        njt_str_set(&s->out, smtp_invalid_pipelining);
        s->quit = 1;
    }

    njt_mail_send(c->write);
}


void
njt_mail_smtp_init_protocol(njt_event_t *rev)
{
    njt_connection_t    *c;
    njt_mail_session_t  *s;

    c = rev->data;

    c->log->action = "in auth state";

    if (rev->timedout) {
        njt_log_error(NJT_LOG_INFO, c->log, NJT_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        njt_mail_close_connection(c);
        return;
    }

    s = c->data;

    if (s->buffer == NULL) {
        if (njt_mail_smtp_create_buffer(s, c) != NJT_OK) {
            return;
        }
    }

    s->mail_state = njt_smtp_start;
    c->read->handler = njt_mail_smtp_auth_state;

    njt_mail_smtp_auth_state(rev);
}


static njt_int_t
njt_mail_smtp_create_buffer(njt_mail_session_t *s, njt_connection_t *c)
{
    njt_mail_smtp_srv_conf_t  *sscf;

    if (njt_array_init(&s->args, c->pool, 2, sizeof(njt_str_t)) == NJT_ERROR) {
        njt_mail_session_internal_server_error(s);
        return NJT_ERROR;
    }

    sscf = njt_mail_get_module_srv_conf(s, njt_mail_smtp_module);

    s->buffer = njt_create_temp_buf(c->pool, sscf->client_buffer_size);
    if (s->buffer == NULL) {
        njt_mail_session_internal_server_error(s);
        return NJT_ERROR;
    }

    return NJT_OK;
}


void
njt_mail_smtp_auth_state(njt_event_t *rev)
{
    njt_int_t            rc;
    njt_connection_t    *c;
    njt_mail_session_t  *s;

    c = rev->data;
    s = c->data;

    njt_log_debug0(NJT_LOG_DEBUG_MAIL, c->log, 0, "smtp auth state");

    if (rev->timedout) {
        njt_log_error(NJT_LOG_INFO, c->log, NJT_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        njt_mail_close_connection(c);
        return;
    }

    if (s->out.len) {
        njt_log_debug0(NJT_LOG_DEBUG_MAIL, c->log, 0, "smtp send handler busy");
        s->blocked = 1;

        if (njt_handle_read_event(c->read, 0) != NJT_OK) {
            njt_mail_close_connection(c);
            return;
        }

        return;
    }

    s->blocked = 0;

    rc = njt_mail_read_command(s, c);

    if (rc == NJT_AGAIN) {
        if (njt_handle_read_event(c->read, 0) != NJT_OK) {
            njt_mail_session_internal_server_error(s);
            return;
        }

        return;
    }

    if (rc == NJT_ERROR) {
        return;
    }

    njt_str_set(&s->out, smtp_ok);

    if (rc == NJT_OK) {
        switch (s->mail_state) {

        case njt_smtp_start:

            switch (s->command) {

            case NJT_SMTP_HELO:
            case NJT_SMTP_EHLO:
                rc = njt_mail_smtp_helo(s, c);
                break;

            case NJT_SMTP_AUTH:
                rc = njt_mail_smtp_auth(s, c);
                break;

            case NJT_SMTP_QUIT:
                s->quit = 1;
                njt_str_set(&s->out, smtp_bye);
                break;

            case NJT_SMTP_MAIL:
                rc = njt_mail_smtp_mail(s, c);
                break;

            case NJT_SMTP_RCPT:
                rc = njt_mail_smtp_rcpt(s, c);
                break;

            case NJT_SMTP_RSET:
                rc = njt_mail_smtp_rset(s, c);
                break;

            case NJT_SMTP_NOOP:
                break;

            case NJT_SMTP_STARTTLS:
                rc = njt_mail_smtp_starttls(s, c);
                njt_str_set(&s->out, smtp_starttls);
                break;

            default:
                rc = NJT_MAIL_PARSE_INVALID_COMMAND;
                break;
            }

            break;

        case njt_smtp_auth_login_username:
            rc = njt_mail_auth_login_username(s, c, 0);

            njt_str_set(&s->out, smtp_password);
            s->mail_state = njt_smtp_auth_login_password;
            break;

        case njt_smtp_auth_login_password:
            rc = njt_mail_auth_login_password(s, c);
            break;

        case njt_smtp_auth_plain:
            rc = njt_mail_auth_plain(s, c, 0);
            break;

        case njt_smtp_auth_cram_md5:
            rc = njt_mail_auth_cram_md5(s, c);
            break;

        case njt_smtp_auth_external:
            rc = njt_mail_auth_external(s, c, 0);
            break;
        }
    }

    if (s->buffer->pos < s->buffer->last) {
        s->blocked = 1;
    }

    switch (rc) {

    case NJT_DONE:
        njt_mail_auth(s, c);
        return;

    case NJT_ERROR:
        njt_mail_session_internal_server_error(s);
        return;

    case NJT_MAIL_PARSE_INVALID_COMMAND:
        s->mail_state = njt_smtp_start;
        s->state = 0;
        njt_str_set(&s->out, smtp_invalid_command);

        /* fall through */

    case NJT_OK:
        s->args.nelts = 0;

        if (s->buffer->pos == s->buffer->last) {
            s->buffer->pos = s->buffer->start;
            s->buffer->last = s->buffer->start;
        }

        if (s->state) {
            s->arg_start = s->buffer->pos;
        }

        if (njt_handle_read_event(c->read, 0) != NJT_OK) {
            njt_mail_session_internal_server_error(s);
            return;
        }

        njt_mail_send(c->write);
    }
}


static njt_int_t
njt_mail_smtp_helo(njt_mail_session_t *s, njt_connection_t *c)
{
    njt_str_t                 *arg;
    njt_mail_smtp_srv_conf_t  *sscf;

    if (s->args.nelts != 1) {
        njt_str_set(&s->out, smtp_invalid_argument);
        s->state = 0;
        return NJT_OK;
    }

    arg = s->args.elts;

    s->smtp_helo.len = arg[0].len;

    s->smtp_helo.data = njt_pnalloc(c->pool, arg[0].len);
    if (s->smtp_helo.data == NULL) {
        return NJT_ERROR;
    }

    njt_memcpy(s->smtp_helo.data, arg[0].data, arg[0].len);

    njt_str_null(&s->smtp_from);
    njt_str_null(&s->smtp_to);

    sscf = njt_mail_get_module_srv_conf(s, njt_mail_smtp_module);

    if (s->command == NJT_SMTP_HELO) {
        s->out = sscf->server_name;

    } else {
        s->esmtp = 1;

#if (NJT_MAIL_SSL)

        if (c->ssl == NULL) {
            njt_mail_ssl_conf_t  *sslcf;

            sslcf = njt_mail_get_module_srv_conf(s, njt_mail_ssl_module);

            if (sslcf->starttls == NJT_MAIL_STARTTLS_ON) {
                s->out = sscf->starttls_capability;
                return NJT_OK;
            }

            if (sslcf->starttls == NJT_MAIL_STARTTLS_ONLY) {
                s->out = sscf->starttls_only_capability;
                return NJT_OK;
            }
        }
#endif

        s->out = sscf->capability;
    }

    return NJT_OK;
}


static njt_int_t
njt_mail_smtp_auth(njt_mail_session_t *s, njt_connection_t *c)
{
    njt_int_t                  rc;
    njt_mail_core_srv_conf_t  *cscf;
    njt_mail_smtp_srv_conf_t  *sscf;

#if (NJT_MAIL_SSL)
    if (njt_mail_starttls_only(s, c)) {
        return NJT_MAIL_PARSE_INVALID_COMMAND;
    }
#endif

    if (s->args.nelts == 0) {
        njt_str_set(&s->out, smtp_invalid_argument);
        s->state = 0;
        return NJT_OK;
    }

    sscf = njt_mail_get_module_srv_conf(s, njt_mail_smtp_module);

    rc = njt_mail_auth_parse(s, c);

    switch (rc) {

    case NJT_MAIL_AUTH_LOGIN:

        njt_str_set(&s->out, smtp_username);
        s->mail_state = njt_smtp_auth_login_username;

        return NJT_OK;

    case NJT_MAIL_AUTH_LOGIN_USERNAME:

        njt_str_set(&s->out, smtp_password);
        s->mail_state = njt_smtp_auth_login_password;

        return njt_mail_auth_login_username(s, c, 1);

    case NJT_MAIL_AUTH_PLAIN:

        njt_str_set(&s->out, smtp_next);
        s->mail_state = njt_smtp_auth_plain;

        return NJT_OK;

    case NJT_MAIL_AUTH_CRAM_MD5:

        if (!(sscf->auth_methods & NJT_MAIL_AUTH_CRAM_MD5_ENABLED)) {
            return NJT_MAIL_PARSE_INVALID_COMMAND;
        }

        if (s->salt.data == NULL) {
            cscf = njt_mail_get_module_srv_conf(s, njt_mail_core_module);

            if (njt_mail_salt(s, c, cscf) != NJT_OK) {
                return NJT_ERROR;
            }
        }

        if (njt_mail_auth_cram_md5_salt(s, c, "334 ", 4) == NJT_OK) {
            s->mail_state = njt_smtp_auth_cram_md5;
            return NJT_OK;
        }

        return NJT_ERROR;

    case NJT_MAIL_AUTH_EXTERNAL:

        if (!(sscf->auth_methods & NJT_MAIL_AUTH_EXTERNAL_ENABLED)) {
            return NJT_MAIL_PARSE_INVALID_COMMAND;
        }

        njt_str_set(&s->out, smtp_username);
        s->mail_state = njt_smtp_auth_external;

        return NJT_OK;
    }

    return rc;
}


static njt_int_t
njt_mail_smtp_mail(njt_mail_session_t *s, njt_connection_t *c)
{
    njt_str_t                 *arg, cmd;
    njt_mail_smtp_srv_conf_t  *sscf;

    sscf = njt_mail_get_module_srv_conf(s, njt_mail_smtp_module);

    if (!(sscf->auth_methods & NJT_MAIL_AUTH_NONE_ENABLED)) {
        njt_mail_smtp_log_rejected_command(s, c, "client was rejected: \"%V\"");
        njt_str_set(&s->out, smtp_auth_required);
        return NJT_OK;
    }

    /* auth none */

    if (s->smtp_from.len) {
        njt_str_set(&s->out, smtp_bad_sequence);
        return NJT_OK;
    }

    if (s->args.nelts == 0) {
        njt_str_set(&s->out, smtp_invalid_argument);
        return NJT_OK;
    }

    arg = s->args.elts;
    arg += s->args.nelts - 1;

    cmd.len = arg->data + arg->len - s->cmd.data;
    cmd.data = s->cmd.data;

    s->smtp_from.len = cmd.len;

    s->smtp_from.data = njt_pnalloc(c->pool, cmd.len);
    if (s->smtp_from.data == NULL) {
        return NJT_ERROR;
    }

    njt_memcpy(s->smtp_from.data, cmd.data, cmd.len);

    njt_log_debug1(NJT_LOG_DEBUG_MAIL, c->log, 0,
                   "smtp mail from:\"%V\"", &s->smtp_from);

    njt_str_set(&s->out, smtp_ok);

    return NJT_OK;
}


static njt_int_t
njt_mail_smtp_rcpt(njt_mail_session_t *s, njt_connection_t *c)
{
    njt_str_t  *arg, cmd;

    if (s->smtp_from.len == 0) {
        njt_str_set(&s->out, smtp_bad_sequence);
        return NJT_OK;
    }

    if (s->args.nelts == 0) {
        njt_str_set(&s->out, smtp_invalid_argument);
        return NJT_OK;
    }

    arg = s->args.elts;
    arg += s->args.nelts - 1;

    cmd.len = arg->data + arg->len - s->cmd.data;
    cmd.data = s->cmd.data;

    s->smtp_to.len = cmd.len;

    s->smtp_to.data = njt_pnalloc(c->pool, cmd.len);
    if (s->smtp_to.data == NULL) {
        return NJT_ERROR;
    }

    njt_memcpy(s->smtp_to.data, cmd.data, cmd.len);

    njt_log_debug1(NJT_LOG_DEBUG_MAIL, c->log, 0,
                   "smtp rcpt to:\"%V\"", &s->smtp_to);

    s->auth_method = NJT_MAIL_AUTH_NONE;

    return NJT_DONE;
}


static njt_int_t
njt_mail_smtp_rset(njt_mail_session_t *s, njt_connection_t *c)
{
    njt_str_null(&s->smtp_from);
    njt_str_null(&s->smtp_to);
    njt_str_set(&s->out, smtp_ok);

    return NJT_OK;
}


static njt_int_t
njt_mail_smtp_starttls(njt_mail_session_t *s, njt_connection_t *c)
{
#if (NJT_MAIL_SSL)
    njt_mail_ssl_conf_t  *sslcf;

    if (c->ssl == NULL) {
        sslcf = njt_mail_get_module_srv_conf(s, njt_mail_ssl_module);
        if (sslcf->starttls) {

            /*
             * RFC3207 requires us to discard any knowledge
             * obtained from client before STARTTLS.
             */

            njt_str_null(&s->smtp_helo);
            njt_str_null(&s->smtp_from);
            njt_str_null(&s->smtp_to);

            s->buffer->pos = s->buffer->start;
            s->buffer->last = s->buffer->start;

            c->read->handler = njt_mail_starttls_handler;
            return NJT_OK;
        }
    }

#endif

    return NJT_MAIL_PARSE_INVALID_COMMAND;
}


static njt_int_t
njt_mail_smtp_discard_command(njt_mail_session_t *s, njt_connection_t *c,
    char *err)
{
    ssize_t    n;

    n = c->recv(c, s->buffer->last, s->buffer->end - s->buffer->last);

    if (n == NJT_ERROR || n == 0) {
        njt_mail_close_connection(c);
        return NJT_ERROR;
    }

    if (n > 0) {
        s->buffer->last += n;
    }

    if (n == NJT_AGAIN) {
        if (njt_handle_read_event(c->read, 0) != NJT_OK) {
            njt_mail_session_internal_server_error(s);
            return NJT_ERROR;
        }

        return NJT_AGAIN;
    }

    njt_mail_smtp_log_rejected_command(s, c, err);

    s->buffer->pos = s->buffer->start;
    s->buffer->last = s->buffer->start;

    return NJT_OK;
}


static void
njt_mail_smtp_log_rejected_command(njt_mail_session_t *s, njt_connection_t *c,
    char *err)
{
    u_char      ch;
    njt_str_t   cmd;
    njt_uint_t  i;

    if (c->log->log_level < NJT_LOG_INFO) {
        return;
    }

    cmd.len = s->buffer->last - s->buffer->start;
    cmd.data = s->buffer->start;

    for (i = 0; i < cmd.len; i++) {
        ch = cmd.data[i];

        if (ch != CR && ch != LF) {
            continue;
        }

        cmd.data[i] = '_';
    }

    cmd.len = i;

    njt_log_error(NJT_LOG_INFO, c->log, 0, err, &cmd);
}
