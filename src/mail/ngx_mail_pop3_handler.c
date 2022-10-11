
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_mail.h>
#include <ngx_mail_pop3_module.h>


static ngx_int_t ngx_mail_pop3_user(ngx_mail_session_t *s, ngx_connection_t *c);
static ngx_int_t ngx_mail_pop3_pass(ngx_mail_session_t *s, ngx_connection_t *c);
static ngx_int_t ngx_mail_pop3_capa(ngx_mail_session_t *s, ngx_connection_t *c,
    ngx_int_t stls);
static ngx_int_t ngx_mail_pop3_stls(ngx_mail_session_t *s, ngx_connection_t *c);
static ngx_int_t ngx_mail_pop3_apop(ngx_mail_session_t *s, ngx_connection_t *c);
static ngx_int_t ngx_mail_pop3_auth(ngx_mail_session_t *s, ngx_connection_t *c);


static u_char  pop3_greeting[] = "+OK POP3 ready" CRLF;
static u_char  pop3_ok[] = "+OK" CRLF;
static u_char  pop3_next[] = "+ " CRLF;
static u_char  pop3_username[] = "+ VXNlcm5hbWU6" CRLF;
static u_char  pop3_password[] = "+ UGFzc3dvcmQ6" CRLF;
static u_char  pop3_invalid_command[] = "-ERR invalid command" CRLF;


void
ngx_mail_pop3_init_session(ngx_mail_session_t *s, ngx_connection_t *c)
{
    u_char                    *p;
    ngx_mail_core_srv_conf_t  *cscf;
    ngx_mail_pop3_srv_conf_t  *pscf;

    pscf = ngx_mail_get_module_srv_conf(s, ngx_mail_pop3_module);
    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

    if (pscf->auth_methods
        & (NJT_MAIL_AUTH_APOP_ENABLED|NJT_MAIL_AUTH_CRAM_MD5_ENABLED))
    {
        if (ngx_mail_salt(s, c, cscf) != NJT_OK) {
            ngx_mail_session_internal_server_error(s);
            return;
        }

        s->out.data = ngx_pnalloc(c->pool, sizeof(pop3_greeting) + s->salt.len);
        if (s->out.data == NULL) {
            ngx_mail_session_internal_server_error(s);
            return;
        }

        p = ngx_cpymem(s->out.data, pop3_greeting, sizeof(pop3_greeting) - 3);
        *p++ = ' ';
        p = ngx_cpymem(p, s->salt.data, s->salt.len);

        s->out.len = p - s->out.data;

    } else {
        ngx_str_set(&s->out, pop3_greeting);
    }

    c->read->handler = ngx_mail_pop3_init_protocol;

    ngx_add_timer(c->read, cscf->timeout);

    if (ngx_handle_read_event(c->read, 0) != NJT_OK) {
        ngx_mail_close_connection(c);
    }

    ngx_mail_send(c->write);
}


void
ngx_mail_pop3_init_protocol(ngx_event_t *rev)
{
    ngx_connection_t    *c;
    ngx_mail_session_t  *s;

    c = rev->data;

    c->log->action = "in auth state";

    if (rev->timedout) {
        ngx_log_error(NJT_LOG_INFO, c->log, NJT_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_mail_close_connection(c);
        return;
    }

    s = c->data;

    if (s->buffer == NULL) {
        if (ngx_array_init(&s->args, c->pool, 2, sizeof(ngx_str_t))
            == NJT_ERROR)
        {
            ngx_mail_session_internal_server_error(s);
            return;
        }

        s->buffer = ngx_create_temp_buf(c->pool, 128);
        if (s->buffer == NULL) {
            ngx_mail_session_internal_server_error(s);
            return;
        }
    }

    s->mail_state = ngx_pop3_start;
    c->read->handler = ngx_mail_pop3_auth_state;

    ngx_mail_pop3_auth_state(rev);
}


void
ngx_mail_pop3_auth_state(ngx_event_t *rev)
{
    ngx_int_t            rc;
    ngx_connection_t    *c;
    ngx_mail_session_t  *s;

    c = rev->data;
    s = c->data;

    ngx_log_debug0(NJT_LOG_DEBUG_MAIL, c->log, 0, "pop3 auth state");

    if (rev->timedout) {
        ngx_log_error(NJT_LOG_INFO, c->log, NJT_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_mail_close_connection(c);
        return;
    }

    if (s->out.len) {
        ngx_log_debug0(NJT_LOG_DEBUG_MAIL, c->log, 0, "pop3 send handler busy");
        s->blocked = 1;

        if (ngx_handle_read_event(c->read, 0) != NJT_OK) {
            ngx_mail_close_connection(c);
            return;
        }

        return;
    }

    s->blocked = 0;

    rc = ngx_mail_read_command(s, c);

    if (rc == NJT_AGAIN) {
        if (ngx_handle_read_event(c->read, 0) != NJT_OK) {
            ngx_mail_session_internal_server_error(s);
            return;
        }

        return;
    }

    if (rc == NJT_ERROR) {
        return;
    }

    ngx_str_set(&s->out, pop3_ok);

    if (rc == NJT_OK) {
        switch (s->mail_state) {

        case ngx_pop3_start:

            switch (s->command) {

            case NJT_POP3_USER:
                rc = ngx_mail_pop3_user(s, c);
                break;

            case NJT_POP3_CAPA:
                rc = ngx_mail_pop3_capa(s, c, 1);
                break;

            case NJT_POP3_APOP:
                rc = ngx_mail_pop3_apop(s, c);
                break;

            case NJT_POP3_AUTH:
                rc = ngx_mail_pop3_auth(s, c);
                break;

            case NJT_POP3_QUIT:
                s->quit = 1;
                break;

            case NJT_POP3_NOOP:
                break;

            case NJT_POP3_STLS:
                rc = ngx_mail_pop3_stls(s, c);
                break;

            default:
                rc = NJT_MAIL_PARSE_INVALID_COMMAND;
                break;
            }

            break;

        case ngx_pop3_user:

            switch (s->command) {

            case NJT_POP3_PASS:
                rc = ngx_mail_pop3_pass(s, c);
                break;

            case NJT_POP3_CAPA:
                rc = ngx_mail_pop3_capa(s, c, 0);
                break;

            case NJT_POP3_QUIT:
                s->quit = 1;
                break;

            case NJT_POP3_NOOP:
                break;

            default:
                rc = NJT_MAIL_PARSE_INVALID_COMMAND;
                break;
            }

            break;

        /* suppress warnings */
        case ngx_pop3_passwd:
            break;

        case ngx_pop3_auth_login_username:
            rc = ngx_mail_auth_login_username(s, c, 0);

            ngx_str_set(&s->out, pop3_password);
            s->mail_state = ngx_pop3_auth_login_password;
            break;

        case ngx_pop3_auth_login_password:
            rc = ngx_mail_auth_login_password(s, c);
            break;

        case ngx_pop3_auth_plain:
            rc = ngx_mail_auth_plain(s, c, 0);
            break;

        case ngx_pop3_auth_cram_md5:
            rc = ngx_mail_auth_cram_md5(s, c);
            break;

        case ngx_pop3_auth_external:
            rc = ngx_mail_auth_external(s, c, 0);
            break;
        }
    }

    if (s->buffer->pos < s->buffer->last) {
        s->blocked = 1;
    }

    switch (rc) {

    case NJT_DONE:
        ngx_mail_auth(s, c);
        return;

    case NJT_ERROR:
        ngx_mail_session_internal_server_error(s);
        return;

    case NJT_MAIL_PARSE_INVALID_COMMAND:
        s->mail_state = ngx_pop3_start;
        s->state = 0;

        ngx_str_set(&s->out, pop3_invalid_command);

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

        if (ngx_handle_read_event(c->read, 0) != NJT_OK) {
            ngx_mail_session_internal_server_error(s);
            return;
        }

        ngx_mail_send(c->write);
    }
}

static ngx_int_t
ngx_mail_pop3_user(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_str_t  *arg;

#if (NJT_MAIL_SSL)
    if (ngx_mail_starttls_only(s, c)) {
        return NJT_MAIL_PARSE_INVALID_COMMAND;
    }
#endif

    if (s->args.nelts != 1) {
        return NJT_MAIL_PARSE_INVALID_COMMAND;
    }

    arg = s->args.elts;
    s->login.len = arg[0].len;
    s->login.data = ngx_pnalloc(c->pool, s->login.len);
    if (s->login.data == NULL) {
        return NJT_ERROR;
    }

    ngx_memcpy(s->login.data, arg[0].data, s->login.len);

    ngx_log_debug1(NJT_LOG_DEBUG_MAIL, c->log, 0,
                   "pop3 login: \"%V\"", &s->login);

    s->mail_state = ngx_pop3_user;

    return NJT_OK;
}


static ngx_int_t
ngx_mail_pop3_pass(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_str_t  *arg;

    if (s->args.nelts != 1) {
        return NJT_MAIL_PARSE_INVALID_COMMAND;
    }

    arg = s->args.elts;
    s->passwd.len = arg[0].len;
    s->passwd.data = ngx_pnalloc(c->pool, s->passwd.len);
    if (s->passwd.data == NULL) {
        return NJT_ERROR;
    }

    ngx_memcpy(s->passwd.data, arg[0].data, s->passwd.len);

#if (NJT_DEBUG_MAIL_PASSWD)
    ngx_log_debug1(NJT_LOG_DEBUG_MAIL, c->log, 0,
                   "pop3 passwd: \"%V\"", &s->passwd);
#endif

    return NJT_DONE;
}


static ngx_int_t
ngx_mail_pop3_capa(ngx_mail_session_t *s, ngx_connection_t *c, ngx_int_t stls)
{
    ngx_mail_pop3_srv_conf_t  *pscf;

    pscf = ngx_mail_get_module_srv_conf(s, ngx_mail_pop3_module);

#if (NJT_MAIL_SSL)

    if (stls && c->ssl == NULL) {
        ngx_mail_ssl_conf_t  *sslcf;

        sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);

        if (sslcf->starttls == NJT_MAIL_STARTTLS_ON) {
            s->out = pscf->starttls_capability;
            return NJT_OK;
        }

        if (sslcf->starttls == NJT_MAIL_STARTTLS_ONLY) {
            s->out = pscf->starttls_only_capability;
            return NJT_OK;
        }
    }

#endif

    s->out = pscf->capability;
    return NJT_OK;
}


static ngx_int_t
ngx_mail_pop3_stls(ngx_mail_session_t *s, ngx_connection_t *c)
{
#if (NJT_MAIL_SSL)
    ngx_mail_ssl_conf_t  *sslcf;

    if (c->ssl == NULL) {
        sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);
        if (sslcf->starttls) {
            s->buffer->pos = s->buffer->start;
            s->buffer->last = s->buffer->start;
            c->read->handler = ngx_mail_starttls_handler;
            return NJT_OK;
        }
    }

#endif

    return NJT_MAIL_PARSE_INVALID_COMMAND;
}


static ngx_int_t
ngx_mail_pop3_apop(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_str_t                 *arg;
    ngx_mail_pop3_srv_conf_t  *pscf;

#if (NJT_MAIL_SSL)
    if (ngx_mail_starttls_only(s, c)) {
        return NJT_MAIL_PARSE_INVALID_COMMAND;
    }
#endif

    if (s->args.nelts != 2) {
        return NJT_MAIL_PARSE_INVALID_COMMAND;
    }

    pscf = ngx_mail_get_module_srv_conf(s, ngx_mail_pop3_module);

    if (!(pscf->auth_methods & NJT_MAIL_AUTH_APOP_ENABLED)) {
        return NJT_MAIL_PARSE_INVALID_COMMAND;
    }

    arg = s->args.elts;

    s->login.len = arg[0].len;
    s->login.data = ngx_pnalloc(c->pool, s->login.len);
    if (s->login.data == NULL) {
        return NJT_ERROR;
    }

    ngx_memcpy(s->login.data, arg[0].data, s->login.len);

    s->passwd.len = arg[1].len;
    s->passwd.data = ngx_pnalloc(c->pool, s->passwd.len);
    if (s->passwd.data == NULL) {
        return NJT_ERROR;
    }

    ngx_memcpy(s->passwd.data, arg[1].data, s->passwd.len);

    ngx_log_debug2(NJT_LOG_DEBUG_MAIL, c->log, 0,
                   "pop3 apop: \"%V\" \"%V\"", &s->login, &s->passwd);

    s->auth_method = NJT_MAIL_AUTH_APOP;

    return NJT_DONE;
}


static ngx_int_t
ngx_mail_pop3_auth(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_int_t                  rc;
    ngx_mail_pop3_srv_conf_t  *pscf;

#if (NJT_MAIL_SSL)
    if (ngx_mail_starttls_only(s, c)) {
        return NJT_MAIL_PARSE_INVALID_COMMAND;
    }
#endif

    pscf = ngx_mail_get_module_srv_conf(s, ngx_mail_pop3_module);

    if (s->args.nelts == 0) {
        s->out = pscf->auth_capability;
        s->state = 0;

        return NJT_OK;
    }

    rc = ngx_mail_auth_parse(s, c);

    switch (rc) {

    case NJT_MAIL_AUTH_LOGIN:

        ngx_str_set(&s->out, pop3_username);
        s->mail_state = ngx_pop3_auth_login_username;

        return NJT_OK;

    case NJT_MAIL_AUTH_LOGIN_USERNAME:

        ngx_str_set(&s->out, pop3_password);
        s->mail_state = ngx_pop3_auth_login_password;

        return ngx_mail_auth_login_username(s, c, 1);

    case NJT_MAIL_AUTH_PLAIN:

        ngx_str_set(&s->out, pop3_next);
        s->mail_state = ngx_pop3_auth_plain;

        return NJT_OK;

    case NJT_MAIL_AUTH_CRAM_MD5:

        if (!(pscf->auth_methods & NJT_MAIL_AUTH_CRAM_MD5_ENABLED)) {
            return NJT_MAIL_PARSE_INVALID_COMMAND;
        }

        if (ngx_mail_auth_cram_md5_salt(s, c, "+ ", 2) == NJT_OK) {
            s->mail_state = ngx_pop3_auth_cram_md5;
            return NJT_OK;
        }

        return NJT_ERROR;

    case NJT_MAIL_AUTH_EXTERNAL:

        if (!(pscf->auth_methods & NJT_MAIL_AUTH_EXTERNAL_ENABLED)) {
            return NJT_MAIL_PARSE_INVALID_COMMAND;
        }

        ngx_str_set(&s->out, pop3_username);
        s->mail_state = ngx_pop3_auth_external;

        return NJT_OK;
    }

    return rc;
}
