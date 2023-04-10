
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>
#include <njt_mail.h>
#include <njt_mail_imap_module.h>


static njt_int_t njt_mail_imap_login(njt_mail_session_t *s,
    njt_connection_t *c);
static njt_int_t njt_mail_imap_authenticate(njt_mail_session_t *s,
    njt_connection_t *c);
static njt_int_t njt_mail_imap_capability(njt_mail_session_t *s,
    njt_connection_t *c);
static njt_int_t njt_mail_imap_starttls(njt_mail_session_t *s,
    njt_connection_t *c);


static u_char  imap_greeting[] = "* OK IMAP4 ready" CRLF;
static u_char  imap_star[] = "* ";
static u_char  imap_ok[] = "OK completed" CRLF;
static u_char  imap_next[] = "+ OK" CRLF;
static u_char  imap_plain_next[] = "+ " CRLF;
static u_char  imap_username[] = "+ VXNlcm5hbWU6" CRLF;
static u_char  imap_password[] = "+ UGFzc3dvcmQ6" CRLF;
static u_char  imap_bye[] = "* BYE" CRLF;
static u_char  imap_invalid_command[] = "BAD invalid command" CRLF;


void
njt_mail_imap_init_session(njt_mail_session_t *s, njt_connection_t *c)
{
    njt_mail_core_srv_conf_t  *cscf;

    cscf = njt_mail_get_module_srv_conf(s, njt_mail_core_module);

    njt_str_set(&s->out, imap_greeting);

    c->read->handler = njt_mail_imap_init_protocol;

    njt_add_timer(c->read, cscf->timeout);

    if (njt_handle_read_event(c->read, 0) != NJT_OK) {
        njt_mail_close_connection(c);
    }

    njt_mail_send(c->write);
}


void
njt_mail_imap_init_protocol(njt_event_t *rev)
{
    njt_connection_t          *c;
    njt_mail_session_t        *s;
    njt_mail_imap_srv_conf_t  *iscf;

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
        if (njt_array_init(&s->args, c->pool, 2, sizeof(njt_str_t))
            == NJT_ERROR)
        {
            njt_mail_session_internal_server_error(s);
            return;
        }

        iscf = njt_mail_get_module_srv_conf(s, njt_mail_imap_module);

        s->buffer = njt_create_temp_buf(c->pool, iscf->client_buffer_size);
        if (s->buffer == NULL) {
            njt_mail_session_internal_server_error(s);
            return;
        }
    }

    s->mail_state = njt_imap_start;
    c->read->handler = njt_mail_imap_auth_state;

    njt_mail_imap_auth_state(rev);
}


void
njt_mail_imap_auth_state(njt_event_t *rev)
{
    u_char              *p;
    njt_int_t            rc;
    njt_uint_t           tag;
    njt_connection_t    *c;
    njt_mail_session_t  *s;

    c = rev->data;
    s = c->data;

    njt_log_debug0(NJT_LOG_DEBUG_MAIL, c->log, 0, "imap auth state");

    if (rev->timedout) {
        njt_log_error(NJT_LOG_INFO, c->log, NJT_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        njt_mail_close_connection(c);
        return;
    }

    if (s->out.len) {
        njt_log_debug0(NJT_LOG_DEBUG_MAIL, c->log, 0, "imap send handler busy");
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

    tag = 1;
    s->text.len = 0;
    njt_str_set(&s->out, imap_ok);

    if (rc == NJT_OK) {

        njt_log_debug1(NJT_LOG_DEBUG_MAIL, c->log, 0, "imap auth command: %i",
                       s->command);

        switch (s->mail_state) {

        case njt_imap_start:

            switch (s->command) {

            case NJT_IMAP_LOGIN:
                rc = njt_mail_imap_login(s, c);
                break;

            case NJT_IMAP_AUTHENTICATE:
                rc = njt_mail_imap_authenticate(s, c);
                tag = (rc != NJT_OK);
                break;

            case NJT_IMAP_CAPABILITY:
                rc = njt_mail_imap_capability(s, c);
                break;

            case NJT_IMAP_LOGOUT:
                s->quit = 1;
                njt_str_set(&s->text, imap_bye);
                break;

            case NJT_IMAP_NOOP:
                break;

            case NJT_IMAP_STARTTLS:
                rc = njt_mail_imap_starttls(s, c);
                break;

            default:
                rc = NJT_MAIL_PARSE_INVALID_COMMAND;
                break;
            }

            break;

        case njt_imap_auth_login_username:
            rc = njt_mail_auth_login_username(s, c, 0);

            tag = 0;
            njt_str_set(&s->out, imap_password);
            s->mail_state = njt_imap_auth_login_password;

            break;

        case njt_imap_auth_login_password:
            rc = njt_mail_auth_login_password(s, c);
            break;

        case njt_imap_auth_plain:
            rc = njt_mail_auth_plain(s, c, 0);
            break;

        case njt_imap_auth_cram_md5:
            rc = njt_mail_auth_cram_md5(s, c);
            break;

        case njt_imap_auth_external:
            rc = njt_mail_auth_external(s, c, 0);
            break;
        }

    } else if (rc == NJT_IMAP_NEXT) {
        tag = 0;
        njt_str_set(&s->out, imap_next);
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
        s->state = 0;
        njt_str_set(&s->out, imap_invalid_command);
        s->mail_state = njt_imap_start;
        break;
    }

    if (tag) {
        if (s->tag.len == 0) {
            njt_str_set(&s->tag, imap_star);
        }

        if (s->tagged_line.len < s->tag.len + s->text.len + s->out.len) {
            s->tagged_line.len = s->tag.len + s->text.len + s->out.len;
            s->tagged_line.data = njt_pnalloc(c->pool, s->tagged_line.len);
            if (s->tagged_line.data == NULL) {
                njt_mail_close_connection(c);
                return;
            }
        }

        p = s->tagged_line.data;

        if (s->text.len) {
            p = njt_cpymem(p, s->text.data, s->text.len);
        }

        p = njt_cpymem(p, s->tag.data, s->tag.len);
        njt_memcpy(p, s->out.data, s->out.len);

        s->out.len = s->text.len + s->tag.len + s->out.len;
        s->out.data = s->tagged_line.data;
    }

    if (rc != NJT_IMAP_NEXT) {
        s->args.nelts = 0;

        if (s->state) {
            /* preserve tag */
            s->arg_start = s->buffer->pos;

        } else {
            if (s->buffer->pos == s->buffer->last) {
                s->buffer->pos = s->buffer->start;
                s->buffer->last = s->buffer->start;
            }

            s->tag.len = 0;
        }
    }

    if (njt_handle_read_event(c->read, 0) != NJT_OK) {
        njt_mail_session_internal_server_error(s);
        return;
    }

    njt_mail_send(c->write);
}


static njt_int_t
njt_mail_imap_login(njt_mail_session_t *s, njt_connection_t *c)
{
    njt_str_t  *arg;

#if (NJT_MAIL_SSL)
    if (njt_mail_starttls_only(s, c)) {
        return NJT_MAIL_PARSE_INVALID_COMMAND;
    }
#endif

    arg = s->args.elts;

    if (s->args.nelts != 2 || arg[0].len == 0) {
        return NJT_MAIL_PARSE_INVALID_COMMAND;
    }

    s->login.len = arg[0].len;
    s->login.data = njt_pnalloc(c->pool, s->login.len);
    if (s->login.data == NULL) {
        return NJT_ERROR;
    }

    njt_memcpy(s->login.data, arg[0].data, s->login.len);

    s->passwd.len = arg[1].len;
    s->passwd.data = njt_pnalloc(c->pool, s->passwd.len);
    if (s->passwd.data == NULL) {
        return NJT_ERROR;
    }

    njt_memcpy(s->passwd.data, arg[1].data, s->passwd.len);

#if (NJT_DEBUG_MAIL_PASSWD)
    njt_log_debug2(NJT_LOG_DEBUG_MAIL, c->log, 0,
                   "imap login:\"%V\" passwd:\"%V\"",
                   &s->login, &s->passwd);
#else
    njt_log_debug1(NJT_LOG_DEBUG_MAIL, c->log, 0,
                   "imap login:\"%V\"", &s->login);
#endif

    return NJT_DONE;
}


static njt_int_t
njt_mail_imap_authenticate(njt_mail_session_t *s, njt_connection_t *c)
{
    njt_int_t                  rc;
    njt_mail_core_srv_conf_t  *cscf;
    njt_mail_imap_srv_conf_t  *iscf;

#if (NJT_MAIL_SSL)
    if (njt_mail_starttls_only(s, c)) {
        return NJT_MAIL_PARSE_INVALID_COMMAND;
    }
#endif

    iscf = njt_mail_get_module_srv_conf(s, njt_mail_imap_module);

    rc = njt_mail_auth_parse(s, c);

    switch (rc) {

    case NJT_MAIL_AUTH_LOGIN:

        njt_str_set(&s->out, imap_username);
        s->mail_state = njt_imap_auth_login_username;

        return NJT_OK;

    case NJT_MAIL_AUTH_LOGIN_USERNAME:

        njt_str_set(&s->out, imap_password);
        s->mail_state = njt_imap_auth_login_password;

        return njt_mail_auth_login_username(s, c, 1);

    case NJT_MAIL_AUTH_PLAIN:

        njt_str_set(&s->out, imap_plain_next);
        s->mail_state = njt_imap_auth_plain;

        return NJT_OK;

    case NJT_MAIL_AUTH_CRAM_MD5:

        if (!(iscf->auth_methods & NJT_MAIL_AUTH_CRAM_MD5_ENABLED)) {
            return NJT_MAIL_PARSE_INVALID_COMMAND;
        }

        if (s->salt.data == NULL) {
            cscf = njt_mail_get_module_srv_conf(s, njt_mail_core_module);

            if (njt_mail_salt(s, c, cscf) != NJT_OK) {
                return NJT_ERROR;
            }
        }

        if (njt_mail_auth_cram_md5_salt(s, c, "+ ", 2) == NJT_OK) {
            s->mail_state = njt_imap_auth_cram_md5;
            return NJT_OK;
        }

        return NJT_ERROR;

    case NJT_MAIL_AUTH_EXTERNAL:

        if (!(iscf->auth_methods & NJT_MAIL_AUTH_EXTERNAL_ENABLED)) {
            return NJT_MAIL_PARSE_INVALID_COMMAND;
        }

        njt_str_set(&s->out, imap_username);
        s->mail_state = njt_imap_auth_external;

        return NJT_OK;
    }

    return rc;
}


static njt_int_t
njt_mail_imap_capability(njt_mail_session_t *s, njt_connection_t *c)
{
    njt_mail_imap_srv_conf_t  *iscf;

    iscf = njt_mail_get_module_srv_conf(s, njt_mail_imap_module);

#if (NJT_MAIL_SSL)

    if (c->ssl == NULL) {
        njt_mail_ssl_conf_t  *sslcf;

        sslcf = njt_mail_get_module_srv_conf(s, njt_mail_ssl_module);

        if (sslcf->starttls == NJT_MAIL_STARTTLS_ON) {
            s->text = iscf->starttls_capability;
            return NJT_OK;
        }

        if (sslcf->starttls == NJT_MAIL_STARTTLS_ONLY) {
            s->text = iscf->starttls_only_capability;
            return NJT_OK;
        }
    }
#endif

    s->text = iscf->capability;

    return NJT_OK;
}


static njt_int_t
njt_mail_imap_starttls(njt_mail_session_t *s, njt_connection_t *c)
{
#if (NJT_MAIL_SSL)
    njt_mail_ssl_conf_t  *sslcf;

    if (c->ssl == NULL) {
        sslcf = njt_mail_get_module_srv_conf(s, njt_mail_ssl_module);
        if (sslcf->starttls) {
            s->buffer->pos = s->buffer->start;
            s->buffer->last = s->buffer->start;
            c->read->handler = njt_mail_starttls_handler;
            return NJT_OK;
        }
    }

#endif

    return NJT_MAIL_PARSE_INVALID_COMMAND;
}
