
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>
#include <njt_mail.h>


static void njt_mail_proxy_protocol_handler(njt_event_t *rev);
static void njt_mail_init_session_handler(njt_event_t *rev);
static void njt_mail_init_session(njt_connection_t *c);

#if (NJT_MAIL_SSL)
static void njt_mail_ssl_init_connection(njt_ssl_t *ssl, njt_connection_t *c);
static void njt_mail_ssl_handshake_handler(njt_connection_t *c);
static njt_int_t njt_mail_verify_cert(njt_mail_session_t *s,
    njt_connection_t *c);
#endif


void
njt_mail_init_connection(njt_connection_t *c)
{
    size_t                     len;
    njt_uint_t                 i;
    njt_event_t               *rev;
    njt_mail_port_t           *port;
    struct sockaddr           *sa;
    struct sockaddr_in        *sin;
    njt_mail_log_ctx_t        *ctx;
    njt_mail_in_addr_t        *addr;
    njt_mail_session_t        *s;
    njt_mail_addr_conf_t      *addr_conf;
    njt_mail_core_srv_conf_t  *cscf;
    u_char                     text[NJT_SOCKADDR_STRLEN];
#if (NJT_HAVE_INET6)
    struct sockaddr_in6       *sin6;
    njt_mail_in6_addr_t       *addr6;
#endif


    /* find the server configuration for the address:port */

    port = c->listening->servers;

    if (port->naddrs > 1) {

        /*
         * There are several addresses on this port and one of them
         * is the "*:port" wildcard so getsockname() is needed to determine
         * the server address.
         *
         * AcceptEx() already gave this address.
         */

        if (njt_connection_local_sockaddr(c, NULL, 0) != NJT_OK) {
            njt_mail_close_connection(c);
            return;
        }

        sa = c->local_sockaddr;

        switch (sa->sa_family) {

#if (NJT_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) sa;

            addr6 = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (njt_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16) == 0) {
                    break;
                }
            }

            addr_conf = &addr6[i].conf;

            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) sa;

            addr = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (addr[i].addr == sin->sin_addr.s_addr) {
                    break;
                }
            }

            addr_conf = &addr[i].conf;

            break;
        }

    } else {
        switch (c->local_sockaddr->sa_family) {

#if (NJT_HAVE_INET6)
        case AF_INET6:
            addr6 = port->addrs;
            addr_conf = &addr6[0].conf;
            break;
#endif

        default: /* AF_INET */
            addr = port->addrs;
            addr_conf = &addr[0].conf;
            break;
        }
    }

    s = njt_pcalloc(c->pool, sizeof(njt_mail_session_t));
    if (s == NULL) {
        njt_mail_close_connection(c);
        return;
    }

    s->signature = NJT_MAIL_MODULE;

    s->main_conf = addr_conf->ctx->main_conf;
    s->srv_conf = addr_conf->ctx->srv_conf;

#if (NJT_MAIL_SSL)
    s->ssl = addr_conf->ssl;
#endif

    s->addr_text = &addr_conf->addr_text;

    c->data = s;
    s->connection = c;

    cscf = njt_mail_get_module_srv_conf(s, njt_mail_core_module);

    njt_set_connection_log(c, cscf->error_log);

    len = njt_sock_ntop(c->sockaddr, c->socklen, text, NJT_SOCKADDR_STRLEN, 1);

    njt_log_error(NJT_LOG_INFO, c->log, 0, "*%uA client %*s connected to %V",
                  c->number, len, text, s->addr_text);

    ctx = njt_palloc(c->pool, sizeof(njt_mail_log_ctx_t));
    if (ctx == NULL) {
        njt_mail_close_connection(c);
        return;
    }

    ctx->client = &c->addr_text;
    ctx->session = s;

    c->log->connection = c->number;
    c->log->handler = njt_mail_log_error;
    c->log->data = ctx;
    c->log->action = "sending client greeting line";

    c->log_error = NJT_ERROR_INFO;

    rev = c->read;
    rev->handler = njt_mail_init_session_handler;

    if (addr_conf->proxy_protocol) {
        c->log->action = "reading PROXY protocol";

        rev->handler = njt_mail_proxy_protocol_handler;

        if (!rev->ready) {
            njt_add_timer(rev, cscf->timeout);

            if (njt_handle_read_event(rev, 0) != NJT_OK) {
                njt_mail_close_connection(c);
            }

            return;
        }
    }

    if (njt_use_accept_mutex) {
        njt_post_event(rev, &njt_posted_events);
        return;
    }

    rev->handler(rev);
}


static void
njt_mail_proxy_protocol_handler(njt_event_t *rev)
{
    u_char                    *p, buf[NJT_PROXY_PROTOCOL_MAX_HEADER];
    size_t                     size;
    ssize_t                    n;
    njt_err_t                  err;
    njt_connection_t          *c;
    njt_mail_session_t        *s;
    njt_mail_core_srv_conf_t  *cscf;

    c = rev->data;
    s = c->data;

    njt_log_debug0(NJT_LOG_DEBUG_MAIL, c->log, 0,
                   "mail PROXY protocol handler");

    if (rev->timedout) {
        njt_log_error(NJT_LOG_INFO, c->log, NJT_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        njt_mail_close_connection(c);
        return;
    }

    n = recv(c->fd, (char *) buf, sizeof(buf), MSG_PEEK);

    err = njt_socket_errno;

    njt_log_debug1(NJT_LOG_DEBUG_MAIL, c->log, 0, "recv(): %z", n);

    if (n == -1) {
        if (err == NJT_EAGAIN) {
            rev->ready = 0;

            if (!rev->timer_set) {
                cscf = njt_mail_get_module_srv_conf(s, njt_mail_core_module);
                njt_add_timer(rev, cscf->timeout);
            }

            if (njt_handle_read_event(rev, 0) != NJT_OK) {
                njt_mail_close_connection(c);
            }

            return;
        }

        njt_connection_error(c, err, "recv() failed");

        njt_mail_close_connection(c);
        return;
    }

    p = njt_proxy_protocol_read(c, buf, buf + n);

    if (p == NULL) {
        njt_mail_close_connection(c);
        return;
    }

    size = p - buf;

    if (c->recv(c, buf, size) != (ssize_t) size) {
        njt_mail_close_connection(c);
        return;
    }

    if (njt_mail_realip_handler(s) != NJT_OK) {
        njt_mail_close_connection(c);
        return;
    }

    njt_mail_init_session_handler(rev);
}


static void
njt_mail_init_session_handler(njt_event_t *rev)
{
    njt_connection_t  *c;

    c = rev->data;

#if (NJT_MAIL_SSL)
    {
    njt_mail_session_t   *s;
    njt_mail_ssl_conf_t  *sslcf;

    s = c->data;


    if (s->ssl) {
        c->log->action = "SSL handshaking";

        sslcf = njt_mail_get_module_srv_conf(s, njt_mail_ssl_module);
        njt_mail_ssl_init_connection(&sslcf->ssl, c);
        return;
    }

    }
#endif

    njt_mail_init_session(c);
}


#if (NJT_MAIL_SSL)

void
njt_mail_starttls_handler(njt_event_t *rev)
{
    njt_connection_t     *c;
    njt_mail_session_t   *s;
    njt_mail_ssl_conf_t  *sslcf;

    c = rev->data;
    s = c->data;
    s->starttls = 1;

    c->log->action = "in starttls state";

    sslcf = njt_mail_get_module_srv_conf(s, njt_mail_ssl_module);

    njt_mail_ssl_init_connection(&sslcf->ssl, c);
}


static void
njt_mail_ssl_init_connection(njt_ssl_t *ssl, njt_connection_t *c)
{
    njt_mail_session_t        *s;
    njt_mail_core_srv_conf_t  *cscf;

    if (njt_ssl_create_connection(ssl, c, 0) != NJT_OK) {
        njt_mail_close_connection(c);
        return;
    }

    if (njt_ssl_handshake(c) == NJT_AGAIN) {

        s = c->data;

        if (!c->read->timer_set) {
            cscf = njt_mail_get_module_srv_conf(s, njt_mail_core_module);
            njt_add_timer(c->read, cscf->timeout);
        }

        c->ssl->handler = njt_mail_ssl_handshake_handler;

        return;
    }

    njt_mail_ssl_handshake_handler(c);
}


static void
njt_mail_ssl_handshake_handler(njt_connection_t *c)
{
    njt_mail_session_t        *s;
    njt_mail_core_srv_conf_t  *cscf;

    if (c->ssl->handshaked) {

        s = c->data;

        if (njt_mail_verify_cert(s, c) != NJT_OK) {
            return;
        }

        if (s->starttls) {
            cscf = njt_mail_get_module_srv_conf(s, njt_mail_core_module);

            c->read->handler = cscf->protocol->init_protocol;
            c->write->handler = njt_mail_send;

            cscf->protocol->init_protocol(c->read);

            return;
        }

        c->read->ready = 0;

        njt_mail_init_session(c);
        return;
    }

    njt_mail_close_connection(c);
}


static njt_int_t
njt_mail_verify_cert(njt_mail_session_t *s, njt_connection_t *c)
{
    long                       rc;
    X509                      *cert;
    njt_mail_ssl_conf_t       *sslcf;
    njt_mail_core_srv_conf_t  *cscf;

    sslcf = njt_mail_get_module_srv_conf(s, njt_mail_ssl_module);

    if (!sslcf->verify) {
        return NJT_OK;
    }

    rc = SSL_get_verify_result(c->ssl->connection);

    if (rc != X509_V_OK
        && (sslcf->verify != 3 || !njt_ssl_verify_error_optional(rc)))
    {
        njt_log_error(NJT_LOG_INFO, c->log, 0,
                      "client SSL certificate verify error: (%l:%s)",
                      rc, X509_verify_cert_error_string(rc));

        njt_ssl_remove_cached_session(c->ssl->session_ctx,
                                      (SSL_get0_session(c->ssl->connection)));

        cscf = njt_mail_get_module_srv_conf(s, njt_mail_core_module);

        s->out = cscf->protocol->cert_error;
        s->quit = 1;

        c->write->handler = njt_mail_send;

        njt_mail_send(s->connection->write);
        return NJT_ERROR;
    }

    if (sslcf->verify == 1) {
        cert = SSL_get_peer_certificate(c->ssl->connection);

        if (cert == NULL) {
            njt_log_error(NJT_LOG_INFO, c->log, 0,
                          "client sent no required SSL certificate");

            njt_ssl_remove_cached_session(c->ssl->session_ctx,
                                       (SSL_get0_session(c->ssl->connection)));

            cscf = njt_mail_get_module_srv_conf(s, njt_mail_core_module);

            s->out = cscf->protocol->no_cert;
            s->quit = 1;

            c->write->handler = njt_mail_send;

            njt_mail_send(s->connection->write);
            return NJT_ERROR;
        }

        X509_free(cert);
    }

    return NJT_OK;
}

#endif


static void
njt_mail_init_session(njt_connection_t *c)
{
    njt_mail_session_t        *s;
    njt_mail_core_srv_conf_t  *cscf;

    s = c->data;

    c->log->action = "sending client greeting line";

    cscf = njt_mail_get_module_srv_conf(s, njt_mail_core_module);

    s->protocol = cscf->protocol->type;

    s->ctx = njt_pcalloc(c->pool, sizeof(void *) * njt_mail_max_module);
    if (s->ctx == NULL) {
        njt_mail_session_internal_server_error(s);
        return;
    }

    c->write->handler = njt_mail_send;

    cscf->protocol->init_session(s, c);
}


njt_int_t
njt_mail_salt(njt_mail_session_t *s, njt_connection_t *c,
    njt_mail_core_srv_conf_t *cscf)
{
    s->salt.data = njt_pnalloc(c->pool,
                               sizeof(" <18446744073709551616.@>" CRLF) - 1
                               + NJT_TIME_T_LEN
                               + cscf->server_name.len);
    if (s->salt.data == NULL) {
        return NJT_ERROR;
    }

    s->salt.len = njt_sprintf(s->salt.data, "<%ul.%T@%V>" CRLF,
                              njt_random(), njt_time(), &cscf->server_name)
                  - s->salt.data;

    return NJT_OK;
}


#if (NJT_MAIL_SSL)

njt_int_t
njt_mail_starttls_only(njt_mail_session_t *s, njt_connection_t *c)
{
    njt_mail_ssl_conf_t  *sslcf;

    if (c->ssl) {
        return 0;
    }

    sslcf = njt_mail_get_module_srv_conf(s, njt_mail_ssl_module);

    if (sslcf->starttls == NJT_MAIL_STARTTLS_ONLY) {
        return 1;
    }

    return 0;
}

#endif


njt_int_t
njt_mail_auth_plain(njt_mail_session_t *s, njt_connection_t *c, njt_uint_t n)
{
    u_char     *p, *last;
    njt_str_t  *arg, plain;

    arg = s->args.elts;

#if (NJT_DEBUG_MAIL_PASSWD)
    njt_log_debug1(NJT_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth plain: \"%V\"", &arg[n]);
#endif

    plain.data = njt_pnalloc(c->pool, njt_base64_decoded_length(arg[n].len));
    if (plain.data == NULL) {
        return NJT_ERROR;
    }

    if (njt_decode_base64(&plain, &arg[n]) != NJT_OK) {
        njt_log_error(NJT_LOG_INFO, c->log, 0,
            "client sent invalid base64 encoding in AUTH PLAIN command");
        return NJT_MAIL_PARSE_INVALID_COMMAND;
    }

    p = plain.data;
    last = p + plain.len;

    while (p < last && *p++) { /* void */ }

    if (p == last) {
        njt_log_error(NJT_LOG_INFO, c->log, 0,
                      "client sent invalid login in AUTH PLAIN command");
        return NJT_MAIL_PARSE_INVALID_COMMAND;
    }

    s->login.data = p;

    while (p < last && *p) { p++; }

    if (p == last) {
        njt_log_error(NJT_LOG_INFO, c->log, 0,
                      "client sent invalid password in AUTH PLAIN command");
        return NJT_MAIL_PARSE_INVALID_COMMAND;
    }

    s->login.len = p++ - s->login.data;

    s->passwd.len = last - p;
    s->passwd.data = p;

#if (NJT_DEBUG_MAIL_PASSWD)
    njt_log_debug2(NJT_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth plain: \"%V\" \"%V\"", &s->login, &s->passwd);
#endif

    return NJT_DONE;
}


njt_int_t
njt_mail_auth_login_username(njt_mail_session_t *s, njt_connection_t *c,
    njt_uint_t n)
{
    njt_str_t  *arg;

    arg = s->args.elts;

    njt_log_debug1(NJT_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth login username: \"%V\"", &arg[n]);

    s->login.data = njt_pnalloc(c->pool, njt_base64_decoded_length(arg[n].len));
    if (s->login.data == NULL) {
        return NJT_ERROR;
    }

    if (njt_decode_base64(&s->login, &arg[n]) != NJT_OK) {
        njt_log_error(NJT_LOG_INFO, c->log, 0,
            "client sent invalid base64 encoding in AUTH LOGIN command");
        return NJT_MAIL_PARSE_INVALID_COMMAND;
    }

    njt_log_debug1(NJT_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth login username: \"%V\"", &s->login);

    return NJT_OK;
}


njt_int_t
njt_mail_auth_login_password(njt_mail_session_t *s, njt_connection_t *c)
{
    njt_str_t  *arg;

    arg = s->args.elts;

#if (NJT_DEBUG_MAIL_PASSWD)
    njt_log_debug1(NJT_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth login password: \"%V\"", &arg[0]);
#endif

    s->passwd.data = njt_pnalloc(c->pool,
                                 njt_base64_decoded_length(arg[0].len));
    if (s->passwd.data == NULL) {
        return NJT_ERROR;
    }

    if (njt_decode_base64(&s->passwd, &arg[0]) != NJT_OK) {
        njt_log_error(NJT_LOG_INFO, c->log, 0,
            "client sent invalid base64 encoding in AUTH LOGIN command");
        return NJT_MAIL_PARSE_INVALID_COMMAND;
    }

#if (NJT_DEBUG_MAIL_PASSWD)
    njt_log_debug1(NJT_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth login password: \"%V\"", &s->passwd);
#endif

    return NJT_DONE;
}


njt_int_t
njt_mail_auth_cram_md5_salt(njt_mail_session_t *s, njt_connection_t *c,
    char *prefix, size_t len)
{
    u_char      *p;
    njt_str_t    salt;
    njt_uint_t   n;

    p = njt_pnalloc(c->pool, len + njt_base64_encoded_length(s->salt.len) + 2);
    if (p == NULL) {
        return NJT_ERROR;
    }

    salt.data = njt_cpymem(p, prefix, len);
    s->salt.len -= 2;

    njt_encode_base64(&salt, &s->salt);

    s->salt.len += 2;
    n = len + salt.len;
    p[n++] = CR; p[n++] = LF;

    s->out.len = n;
    s->out.data = p;

    return NJT_OK;
}


njt_int_t
njt_mail_auth_cram_md5(njt_mail_session_t *s, njt_connection_t *c)
{
    u_char     *p, *last;
    njt_str_t  *arg;

    arg = s->args.elts;

    njt_log_debug1(NJT_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth cram-md5: \"%V\"", &arg[0]);

    s->login.data = njt_pnalloc(c->pool, njt_base64_decoded_length(arg[0].len));
    if (s->login.data == NULL) {
        return NJT_ERROR;
    }

    if (njt_decode_base64(&s->login, &arg[0]) != NJT_OK) {
        njt_log_error(NJT_LOG_INFO, c->log, 0,
            "client sent invalid base64 encoding in AUTH CRAM-MD5 command");
        return NJT_MAIL_PARSE_INVALID_COMMAND;
    }

    p = s->login.data;
    last = p + s->login.len;

    while (p < last) {
        if (*p++ == ' ') {
            s->login.len = p - s->login.data - 1;
            s->passwd.len = last - p;
            s->passwd.data = p;
            break;
        }
    }

    if (s->passwd.len != 32) {
        njt_log_error(NJT_LOG_INFO, c->log, 0,
            "client sent invalid CRAM-MD5 hash in AUTH CRAM-MD5 command");
        return NJT_MAIL_PARSE_INVALID_COMMAND;
    }

    njt_log_debug2(NJT_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth cram-md5: \"%V\" \"%V\"", &s->login, &s->passwd);

    s->auth_method = NJT_MAIL_AUTH_CRAM_MD5;

    return NJT_DONE;
}


njt_int_t
njt_mail_auth_external(njt_mail_session_t *s, njt_connection_t *c,
    njt_uint_t n)
{
    njt_str_t  *arg, external;

    arg = s->args.elts;

    njt_log_debug1(NJT_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth external: \"%V\"", &arg[n]);

    external.data = njt_pnalloc(c->pool, njt_base64_decoded_length(arg[n].len));
    if (external.data == NULL) {
        return NJT_ERROR;
    }

    if (njt_decode_base64(&external, &arg[n]) != NJT_OK) {
        njt_log_error(NJT_LOG_INFO, c->log, 0,
            "client sent invalid base64 encoding in AUTH EXTERNAL command");
        return NJT_MAIL_PARSE_INVALID_COMMAND;
    }

    s->login.len = external.len;
    s->login.data = external.data;

    njt_log_debug1(NJT_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth external: \"%V\"", &s->login);

    s->auth_method = NJT_MAIL_AUTH_EXTERNAL;

    return NJT_DONE;
}


void
njt_mail_send(njt_event_t *wev)
{
    njt_int_t                  n;
    njt_connection_t          *c;
    njt_mail_session_t        *s;
    njt_mail_core_srv_conf_t  *cscf;

    c = wev->data;
    s = c->data;

    if (wev->timedout) {
        njt_log_error(NJT_LOG_INFO, c->log, NJT_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        njt_mail_close_connection(c);
        return;
    }

    if (s->out.len == 0) {
        if (njt_handle_write_event(c->write, 0) != NJT_OK) {
            njt_mail_close_connection(c);
        }

        return;
    }

    n = c->send(c, s->out.data, s->out.len);

    if (n > 0) {
        s->out.data += n;
        s->out.len -= n;

        if (s->out.len != 0) {
            goto again;
        }

        if (wev->timer_set) {
            njt_del_timer(wev);
        }

        if (s->quit) {
            njt_mail_close_connection(c);
            return;
        }

        if (s->blocked) {
            c->read->handler(c->read);
        }

        return;
    }

    if (n == NJT_ERROR) {
        njt_mail_close_connection(c);
        return;
    }

    /* n == NJT_AGAIN */

again:

    cscf = njt_mail_get_module_srv_conf(s, njt_mail_core_module);

    njt_add_timer(c->write, cscf->timeout);

    if (njt_handle_write_event(c->write, 0) != NJT_OK) {
        njt_mail_close_connection(c);
        return;
    }
}


njt_int_t
njt_mail_read_command(njt_mail_session_t *s, njt_connection_t *c)
{
    ssize_t                    n;
    njt_int_t                  rc;
    njt_str_t                  l;
    njt_mail_core_srv_conf_t  *cscf;

    if (s->buffer->last < s->buffer->end) {

        n = c->recv(c, s->buffer->last, s->buffer->end - s->buffer->last);

        if (n == NJT_ERROR || n == 0) {
            njt_mail_close_connection(c);
            return NJT_ERROR;
        }

        if (n > 0) {
            s->buffer->last += n;
        }

        if (n == NJT_AGAIN) {
            if (s->buffer->pos == s->buffer->last) {
                return NJT_AGAIN;
            }
        }
    }

    cscf = njt_mail_get_module_srv_conf(s, njt_mail_core_module);

    rc = cscf->protocol->parse_command(s);

    if (rc == NJT_AGAIN) {

        if (s->buffer->last < s->buffer->end) {
            return rc;
        }

        l.len = s->buffer->last - s->buffer->start;
        l.data = s->buffer->start;

        njt_log_error(NJT_LOG_INFO, c->log, 0,
                      "client sent too long command \"%V\"", &l);

        s->quit = 1;

        return NJT_MAIL_PARSE_INVALID_COMMAND;
    }

    if (rc == NJT_MAIL_PARSE_INVALID_COMMAND) {

        s->errors++;

        if (s->errors >= cscf->max_errors) {
            njt_log_error(NJT_LOG_INFO, c->log, 0,
                          "client sent too many invalid commands");
            s->quit = 1;
        }

        return rc;
    }

    if (rc == NJT_IMAP_NEXT) {
        return rc;
    }

    if (rc == NJT_ERROR) {
        njt_mail_close_connection(c);
        return NJT_ERROR;
    }

    return NJT_OK;
}


void
njt_mail_auth(njt_mail_session_t *s, njt_connection_t *c)
{
    s->args.nelts = 0;

    if (s->buffer->pos == s->buffer->last) {
        s->buffer->pos = s->buffer->start;
        s->buffer->last = s->buffer->start;
    }

    s->state = 0;

    if (c->read->timer_set) {
        njt_del_timer(c->read);
    }

    s->login_attempt++;

    njt_mail_auth_http_init(s);
}


void
njt_mail_session_internal_server_error(njt_mail_session_t *s)
{
    njt_mail_core_srv_conf_t  *cscf;

    cscf = njt_mail_get_module_srv_conf(s, njt_mail_core_module);

    s->out = cscf->protocol->internal_server_error;
    s->quit = 1;

    njt_mail_send(s->connection->write);
}


void
njt_mail_close_connection(njt_connection_t *c)
{
    njt_pool_t  *pool;

    njt_log_debug1(NJT_LOG_DEBUG_MAIL, c->log, 0,
                   "close mail connection: %d", c->fd);

#if (NJT_MAIL_SSL)

    if (c->ssl) {
        if (njt_ssl_shutdown(c) == NJT_AGAIN) {
            c->ssl->handler = njt_mail_close_connection;
            return;
        }
    }

#endif

#if (NJT_STAT_STUB)
    (void) njt_atomic_fetch_add(njt_stat_active, -1);
#endif

    c->destroyed = 1;

    pool = c->pool;

    njt_close_connection(c);

    njt_destroy_pool(pool);
}


u_char *
njt_mail_log_error(njt_log_t *log, u_char *buf, size_t len)
{
    u_char              *p;
    njt_mail_session_t  *s;
    njt_mail_log_ctx_t  *ctx;

    if (log->action) {
        p = njt_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    ctx = log->data;

    p = njt_snprintf(buf, len, ", client: %V", ctx->client);
    len -= p - buf;
    buf = p;

    s = ctx->session;

    if (s == NULL) {
        return p;
    }

    p = njt_snprintf(buf, len, "%s, server: %V",
                     s->starttls ? " using starttls" : "",
                     s->addr_text);
    len -= p - buf;
    buf = p;

    if (s->login.len == 0) {
        return p;
    }

    p = njt_snprintf(buf, len, ", login: \"%V\"", &s->login);
    len -= p - buf;
    buf = p;

    if (s->proxy == NULL) {
        return p;
    }

    p = njt_snprintf(buf, len, ", upstream: %V", s->proxy->upstream.name);

    return p;
}
