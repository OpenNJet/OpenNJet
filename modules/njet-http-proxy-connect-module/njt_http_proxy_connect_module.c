/*
 * Copyright (C) 2010-2013 Alibaba Group Holding Limited
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njet.h>


#define NJT_HTTP_PROXY_CONNECT_ESTABLISTHED     \
    "HTTP/1.1 200 Connection Established\r\n"   \
    "Proxy-agent: njet\r\n\r\n"


typedef struct njt_http_proxy_connect_upstream_s
    njt_http_proxy_connect_upstream_t;
typedef struct njt_http_proxy_connect_address_s
    njt_http_proxy_connect_address_t;

typedef void (*njt_http_proxy_connect_upstream_handler_pt)(
    njt_http_request_t *r, njt_http_proxy_connect_upstream_t *u);


typedef struct {
    njt_flag_t                           accept_connect;
    njt_flag_t                           allow_port_all;
    njt_array_t                         *allow_ports;

    njt_msec_t                           data_timeout;
    njt_msec_t                           send_timeout;
    njt_msec_t                           connect_timeout;

    size_t                               send_lowat;
    size_t                               buffer_size;

    njt_http_complex_value_t            *address;
    njt_http_proxy_connect_address_t    *local;

    njt_http_complex_value_t            *response;
} njt_http_proxy_connect_loc_conf_t;


typedef struct {
    njt_msec_t                       resolve_time;
    njt_msec_t                       connect_time;
    njt_msec_t                       first_byte_time;

    /* TODO:
    off_t                            bytes_received;
    off_t                            bytes_sent;
    */
} njt_http_proxy_connect_upstream_state_t;


struct njt_http_proxy_connect_upstream_s {
    njt_http_proxy_connect_loc_conf_t             *conf;

    njt_http_proxy_connect_upstream_handler_pt     read_event_handler;
    njt_http_proxy_connect_upstream_handler_pt     write_event_handler;

    njt_peer_connection_t                          peer;

    njt_http_request_t                            *request;

    njt_http_upstream_resolved_t                  *resolved;

    njt_buf_t                                      from_client;

    njt_output_chain_ctx_t                         output;

    njt_buf_t                                      buffer;

    /* 1: DNS resolving succeeded */
    njt_flag_t                                     _resolved;

    /* 1: connection established */
    njt_flag_t                                     connected;

    njt_msec_t                                     start_time;

    njt_http_proxy_connect_upstream_state_t        state;
};

struct njt_http_proxy_connect_address_s {
    njt_addr_t                      *addr;
    njt_http_complex_value_t        *value;
#if (NJT_HAVE_TRANSPARENT_PROXY)
    njt_uint_t                       transparent; /* unsigned  transparent:1; */
#endif
};

typedef struct {
    njt_http_proxy_connect_upstream_t           *u;

    njt_flag_t                      send_established;
    njt_flag_t                      send_established_done;

    njt_buf_t                       buf;    /* CONNECT response */

    njt_msec_t                      connect_timeout;
    njt_msec_t                      send_timeout;
    njt_msec_t                      data_timeout;

} njt_http_proxy_connect_ctx_t;


static njt_int_t njt_http_proxy_connect_init(njt_conf_t *cf);
static njt_int_t njt_http_proxy_connect_add_variables(njt_conf_t *cf);
static njt_int_t njt_http_proxy_connect_connect_addr_variable(
    njt_http_request_t *r, njt_http_variable_value_t *v, uintptr_t data);
static char *njt_http_proxy_connect(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_proxy_connect_allow(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static void *njt_http_proxy_connect_create_loc_conf(njt_conf_t *cf);
static char *njt_http_proxy_connect_merge_loc_conf(njt_conf_t *cf, void *parent,
    void *child);
static void njt_http_proxy_connect_write_downstream(njt_http_request_t *r);
static void njt_http_proxy_connect_read_downstream(njt_http_request_t *r);
static void njt_http_proxy_connect_send_handler(njt_http_request_t *r);
static njt_int_t njt_http_proxy_connect_allow_handler(njt_http_request_t *r,
    njt_http_proxy_connect_loc_conf_t *plcf);
static char* njt_http_proxy_connect_bind(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static njt_int_t njt_http_proxy_connect_set_local(njt_http_request_t *r,
  njt_http_proxy_connect_upstream_t *u, njt_http_proxy_connect_address_t *local);
static njt_int_t njt_http_proxy_connect_variable_get_time(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static void njt_http_proxy_connect_variable_set_time(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_proxy_connect_resolve_time_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_proxy_connect_connect_time_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_proxy_connect_first_byte_time_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_proxy_connect_variable_get_response(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static void njt_http_proxy_connect_variable_set_response(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);

static njt_int_t njt_http_proxy_connect_sock_ntop(njt_http_request_t *r,
    njt_http_proxy_connect_upstream_t *u);
static njt_int_t njt_http_proxy_connect_create_peer(njt_http_request_t *r,
    njt_http_upstream_resolved_t *ur);



static njt_command_t  njt_http_proxy_connect_commands[] = {

    { njt_string("proxy_connect"),
      NJT_HTTP_SRV_CONF|NJT_CONF_NOARGS,
      njt_http_proxy_connect,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_connect_loc_conf_t, accept_connect),
      NULL },

    { njt_string("proxy_connect_allow"),
      NJT_HTTP_SRV_CONF|NJT_CONF_1MORE,
      njt_http_proxy_connect_allow,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("proxy_connect_data_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_connect_loc_conf_t, data_timeout),
      NULL },

    { njt_string("proxy_connect_read_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_connect_loc_conf_t, data_timeout),
      NULL },

    { njt_string("proxy_connect_send_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_connect_loc_conf_t, send_timeout),
      NULL },

    { njt_string("proxy_connect_connect_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_connect_loc_conf_t, connect_timeout),
      NULL },

    { njt_string("proxy_connect_send_lowat"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_connect_loc_conf_t, send_lowat),
      NULL },

    { njt_string("proxy_connect_address"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_http_set_complex_value_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_connect_loc_conf_t, address),
      NULL },

    { njt_string("proxy_connect_bind"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE12,
      njt_http_proxy_connect_bind,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_connect_loc_conf_t, local),
      NULL },

    { njt_string("proxy_connect_response"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_http_set_complex_value_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_connect_loc_conf_t, response),
      NULL },

    njt_null_command
};


static njt_http_module_t  njt_http_proxy_connect_module_ctx = {
    njt_http_proxy_connect_add_variables,   /* preconfiguration */
    njt_http_proxy_connect_init,            /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    njt_http_proxy_connect_create_loc_conf, /* create location configuration */
    njt_http_proxy_connect_merge_loc_conf   /* merge location configuration */
};


njt_module_t  njt_http_proxy_connect_module = {
    NJT_MODULE_V1,
    &njt_http_proxy_connect_module_ctx,     /* module context */
    njt_http_proxy_connect_commands,        /* module directives */
    NJT_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NJT_MODULE_V1_PADDING
};


static njt_http_variable_t  njt_http_proxy_connect_vars[] = {

    { njt_string("connect_addr"), NULL,
      njt_http_proxy_connect_connect_addr_variable,
      0, NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("proxy_connect_connect_timeout"),
      njt_http_proxy_connect_variable_set_time,
      njt_http_proxy_connect_variable_get_time,
      offsetof(njt_http_proxy_connect_ctx_t, connect_timeout),
      NJT_HTTP_VAR_NOCACHEABLE|NJT_HTTP_VAR_CHANGEABLE, 0,
      NJT_VAR_INIT_REF_COUNT },

    { njt_string("proxy_connect_data_timeout"),
      njt_http_proxy_connect_variable_set_time,
      njt_http_proxy_connect_variable_get_time,
      offsetof(njt_http_proxy_connect_ctx_t, data_timeout),
      NJT_HTTP_VAR_NOCACHEABLE|NJT_HTTP_VAR_CHANGEABLE, 0,
      NJT_VAR_INIT_REF_COUNT },

    { njt_string("proxy_connect_read_timeout"),
      njt_http_proxy_connect_variable_set_time,
      njt_http_proxy_connect_variable_get_time,
      offsetof(njt_http_proxy_connect_ctx_t, data_timeout),
      NJT_HTTP_VAR_NOCACHEABLE|NJT_HTTP_VAR_CHANGEABLE, 0,
      NJT_VAR_INIT_REF_COUNT },

    { njt_string("proxy_connect_send_timeout"),
      njt_http_proxy_connect_variable_set_time,
      njt_http_proxy_connect_variable_get_time,
      offsetof(njt_http_proxy_connect_ctx_t, send_timeout),
      NJT_HTTP_VAR_NOCACHEABLE|NJT_HTTP_VAR_CHANGEABLE, 0,
      NJT_VAR_INIT_REF_COUNT },

    { njt_string("proxy_connect_resolve_time"), NULL,
      njt_http_proxy_connect_resolve_time_variable, 0,
      NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("proxy_connect_connect_time"), NULL,
      njt_http_proxy_connect_connect_time_variable, 0,
      NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("proxy_connect_first_byte_time"), NULL,
      njt_http_proxy_connect_first_byte_time_variable, 0,
      NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("proxy_connect_response"),
      njt_http_proxy_connect_variable_set_response,
      njt_http_proxy_connect_variable_get_response,
      offsetof(njt_http_proxy_connect_ctx_t, buf),
      NJT_HTTP_VAR_NOCACHEABLE|NJT_HTTP_VAR_CHANGEABLE, 0,
      NJT_VAR_INIT_REF_COUNT },

    { njt_null_string, NULL, NULL, 0, 0, 0, NJT_VAR_INIT_REF_COUNT }
};


#if 1

#if defined(njet_version) && njet_version >= 1005008
#define __njt_sock_ntop njt_sock_ntop
#else
#define __njt_sock_ntop(sa, slen, p, len, port) njt_sock_ntop(sa, p, len, port)
#endif

/*
 * #if defined(njet_version) && njet_version <= 1009015
 *
 * from src/core/njt_inet.c: njt_inet_set_port & njt_parse_addr_port
 *
 * redefined to __njt_inet_set_port & __njt_parse_addr_port to
 * avoid too many `#if njet_version > ...` macro
 */
static void
__njt_inet_set_port(struct sockaddr *sa, in_port_t port)
{
    struct sockaddr_in   *sin;
#if (NJT_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    switch (sa->sa_family) {

#if (NJT_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) sa;
        sin6->sin6_port = htons(port);
        break;
#endif

#if (NJT_HAVE_UNIX_DOMAIN)
    case AF_UNIX:
        break;
#endif

    default: /* AF_INET */
        sin = (struct sockaddr_in *) sa;
        sin->sin_port = htons(port);
        break;
    }
}


static njt_int_t
__njt_parse_addr_port(njt_pool_t *pool, njt_addr_t *addr, u_char *text,
    size_t len)
{
    u_char     *p, *last;
    size_t      plen;
    njt_int_t   rc, port;

    rc = njt_parse_addr(pool, addr, text, len);

    if (rc != NJT_DECLINED) {
        return rc;
    }

    last = text + len;

#if (NJT_HAVE_INET6)
    if (len && text[0] == '[') {

        p = njt_strlchr(text, last, ']');

        if (p == NULL || p == last - 1 || *++p != ':') {
            return NJT_DECLINED;
        }

        text++;
        len -= 2;

    } else
#endif

    {
        p = njt_strlchr(text, last, ':');

        if (p == NULL) {
            return NJT_DECLINED;
        }
    }

    p++;
    plen = last - p;

    port = njt_atoi(p, plen);

    if (port < 1 || port > 65535) {
        return NJT_DECLINED;
    }

    len -= plen + 1;

    rc = njt_parse_addr(pool, addr, text, len);

    if (rc != NJT_OK) {
        return rc;
    }

    __njt_inet_set_port(addr->sockaddr, (in_port_t) port);

    return NJT_OK;
}

#endif


static njt_int_t
njt_http_proxy_connect_get_peer(njt_peer_connection_t *pc, void *data)
{
    return NJT_OK;
}


static njt_int_t
njt_http_proxy_connect_test_connect(njt_connection_t *c)
{
    int        err;
    socklen_t  len;

#if (NJT_HAVE_KQUEUE)

    if (njt_event_flags & NJT_USE_KQUEUE_EVENT)  {
        if (c->write->pending_eof || c->read->pending_eof) {
            if (c->write->pending_eof) {
                err = c->write->kq_errno;

            } else {
                err = c->read->kq_errno;
            }

            c->log->action = "connecting to upstream";
            (void) njt_connection_error(c, err,
                              "proxy_connet: upstream connect failed (kevent)");
            return NJT_ERROR;
        }

    } else
#endif
    {
        err = 0;
        len = sizeof(int);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = njt_errno;
        }

        if (err) {
            c->log->action = "connecting to upstream";
            (void) njt_connection_error(c, err,
                                      "proxy_connect: upstream connect failed");
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}


static void
njt_http_proxy_connect_finalize_request(njt_http_request_t *r,
    njt_http_proxy_connect_upstream_t *u, njt_int_t rc)
{
    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "proxy_connect: finalize upstream request: %i", rc);

    r->keepalive = 0;

    if (u->resolved && u->resolved->ctx) {
        njt_resolve_name_done(u->resolved->ctx);
        u->resolved->ctx = NULL;
    }

    if (u->peer.free && u->peer.sockaddr) {
        u->peer.free(&u->peer, u->peer.data, 0);
        u->peer.sockaddr = NULL;
    }

    if (u->peer.connection) {

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "proxy_connect: close upstream connection: %d",
                       u->peer.connection->fd);

        if (u->peer.connection->pool) {
            njt_destroy_pool(u->peer.connection->pool);
        }

        njt_close_connection(u->peer.connection);
    }

    u->peer.connection = NULL;

    if (rc == NJT_DECLINED) {
        return;
    }

    r->connection->log->action = "sending to client";

    if (rc == NJT_HTTP_REQUEST_TIME_OUT
        || rc == NJT_HTTP_CLIENT_CLOSED_REQUEST)
    {
        njt_http_finalize_request(r, rc);
        return;
    }

    if (u->connected && rc >= NJT_HTTP_SPECIAL_RESPONSE) {
        rc = NJT_ERROR;
    }

    njt_http_finalize_request(r, rc);
}


static void
njt_http_proxy_connect_send_connection_established(njt_http_request_t *r)
{
    njt_int_t                              n;
    njt_buf_t                             *b;
    njt_connection_t                      *c;
    njt_http_core_loc_conf_t              *clcf;
    njt_http_proxy_connect_upstream_t     *u;
    njt_http_proxy_connect_ctx_t          *ctx;

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_connect_module);
    c = r->connection;
    u = ctx->u;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "proxy_connect: send 200 connection established");

    u->connected = 1;

    if (u->state.connect_time == (njt_msec_t) -1) {
        u->state.connect_time = njt_current_msec - u->start_time;
    }

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    b = &ctx->buf;

    /* modify CONNECT response via proxy_connect_response directive */
    {
    njt_str_t                               resp;
    njt_http_proxy_connect_loc_conf_t      *plcf;

    plcf = njt_http_get_module_loc_conf(r, njt_http_proxy_connect_module);

    if (plcf->response
        && njt_http_complex_value(r, plcf->response, &resp) == NJT_OK)
    {
        if (resp.len > 0) {
            b->pos = resp.data;
            b->last = b->pos + resp.len;
        }
    }
    }

    ctx->send_established = 1;

    for (;;) {
        n = c->send(c, b->pos, b->last - b->pos);

        if (n >= 0) {

            r->headers_out.status = 200;    /* fixed that $status is 000 */

            b->pos += n;

            if (b->pos == b->last) {
                njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                              "proxy_connect: sent 200 connection established");

                if (c->write->timer_set) {
                    njt_del_timer(c->write);
                }

                ctx->send_established_done = 1;

                r->write_event_handler =
                                        njt_http_proxy_connect_write_downstream;
                r->read_event_handler = njt_http_proxy_connect_read_downstream;

                if (njt_handle_write_event(c->write, clcf->send_lowat)
                    != NJT_OK)
                {
                    njt_http_proxy_connect_finalize_request(r, u,
                                                NJT_HTTP_INTERNAL_SERVER_ERROR);
                    return;
                }

                if (r->header_in->last > r->header_in->pos || c->read->ready) {
                    r->read_event_handler(r);
                    return;
                }

                return;
            }

            /* keep sending more data */
            continue;
        }

        /* NJT_ERROR || NJT_AGAIN */
        break;
    }

    if (n == NJT_ERROR) {
        njt_http_proxy_connect_finalize_request(r, u, NJT_ERROR);
        return;
    }

    /* n == NJT_AGAIN */

    r->write_event_handler = njt_http_proxy_connect_send_handler;

    njt_add_timer(c->write, ctx->data_timeout);

    if (njt_handle_write_event(c->write, clcf->send_lowat) != NJT_OK) {
        njt_http_proxy_connect_finalize_request(r, u,
                                                NJT_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    return;
}


static void
njt_http_proxy_connect_tunnel(njt_http_request_t *r,
    njt_uint_t from_upstream, njt_uint_t do_write)
{
    char                               *recv_action, *send_action;
    size_t                              size;
    ssize_t                             n;
    njt_buf_t                          *b;
    njt_uint_t                          flags;
    njt_connection_t                   *c, *pc, *dst, *src;
    njt_http_proxy_connect_ctx_t       *ctx;
    njt_http_proxy_connect_upstream_t  *u;

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_connect_module);

    c = r->connection;
    u = ctx->u;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "proxy_connect: tunnel fu:%ui write:%ui",
                   from_upstream, do_write);

    pc = u->peer.connection;

    if (from_upstream) {
        src = pc;
        dst = c;
        b = &u->buffer;
        recv_action = "proxying and reading from upstream";
        send_action = "proxying and sending to client";

    } else {
        src = c;
        dst = pc;
        b = &u->from_client;

        if (r->header_in->last > r->header_in->pos) {
            b = r->header_in;
            b->end = b->last;
            do_write = 1;
        }

        if (b->start == NULL) {
            b->start = njt_palloc(r->pool, u->conf->buffer_size);
            if (b->start == NULL) {
                njt_http_proxy_connect_finalize_request(r, u, NJT_ERROR);
                return;
            }

            b->pos = b->start;
            b->last = b->start;
            b->end = b->start + u->conf->buffer_size;
            b->temporary = 1;
        }
        recv_action = "proxying and reading from client";
        send_action = "proxying and sending to upstream";
    }

    for ( ;; ) {

        if (do_write) {

            size = b->last - b->pos;

            if (size && dst->write->ready) {
                c->log->action = send_action;

                n = dst->send(dst, b->pos, size);

                if (n == NJT_AGAIN) {
                    break;
                }

                if (n == NJT_ERROR) {
                    njt_http_proxy_connect_finalize_request(r, u, NJT_ERROR);
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

                if (from_upstream) {
                    if (u->state.first_byte_time == (njt_msec_t) -1) {
                        u->state.first_byte_time = njt_current_msec
                            - u->start_time;
                    }
                }

                continue;
            }

            if (n == NJT_ERROR) {
                src->read->eof = 1;
            }
        }

        break;
    }

    c->log->action = "proxying connection";

    /* test finalize */

    if ((pc->read->eof && u->buffer.pos == u->buffer.last)
        || (c->read->eof && u->from_client.pos == u->from_client.last)
        || (c->read->eof && pc->read->eof))
    {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "proxy_connect: tunnel done");
        njt_http_proxy_connect_finalize_request(r, u, 0);
        return;
    }

    flags = src->read->eof ? NJT_CLOSE_EVENT : 0;

    if (njt_handle_read_event(src->read, flags) != NJT_OK) {
        njt_http_proxy_connect_finalize_request(r, u, NJT_ERROR);
        return;
    }

    if (dst) {
        if (njt_handle_write_event(dst->write, 0) != NJT_OK) {
            njt_http_proxy_connect_finalize_request(r, u, NJT_ERROR);
            return;
        }

        if (!c->read->delayed && !pc->read->delayed) {
            njt_add_timer(c->write, ctx->data_timeout);

        } else if (c->write->timer_set) {
            njt_del_timer(c->write);
        }
    }
}


static void
njt_http_proxy_connect_read_downstream(njt_http_request_t *r)
{
    njt_http_proxy_connect_ctx_t       *ctx;


    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "proxy connect read downstream");

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_connect_module);

    if (r->connection->read->timedout) {
        r->connection->timedout = 1;
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "proxy_connect: client read timed out");
        njt_http_proxy_connect_finalize_request(r, ctx->u,
                                                NJT_HTTP_REQUEST_TIME_OUT);
        return;
    }

    njt_http_proxy_connect_tunnel(r, 0, 0);
}


static void
njt_http_proxy_connect_write_downstream(njt_http_request_t *r)
{
    njt_http_proxy_connect_ctx_t       *ctx;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "proxy connect write downstream");

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_connect_module);

    if (r->connection->write->timedout) {
        r->connection->timedout = 1;
        njt_connection_error(r->connection, NJT_ETIMEDOUT,
                             "proxy_connect: connection timed out");
        njt_http_proxy_connect_finalize_request(r, ctx->u,
                                                NJT_HTTP_REQUEST_TIME_OUT);
        return;
    }

    njt_http_proxy_connect_tunnel(r, 1, 1);
}


static void
njt_http_proxy_connect_read_upstream(njt_http_request_t *r,
    njt_http_proxy_connect_upstream_t *u)
{
    njt_connection_t                    *c;
    njt_http_proxy_connect_ctx_t        *ctx;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "proxy_connect: upstream read handler");

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_connect_module);

    c = u->peer.connection;

    if (c->read->timedout) {
        njt_log_error(NJT_LOG_ERR, c->log, 0,
                      "proxy_connect: upstream read timed out (peer:%V)",
                      u->peer.name);
        njt_http_proxy_connect_finalize_request(r, u, NJT_HTTP_GATEWAY_TIME_OUT);
        return;
    }

    if (!ctx->send_established &&
        njt_http_proxy_connect_test_connect(c) != NJT_OK)
    {
        njt_http_proxy_connect_finalize_request(r, u, NJT_HTTP_BAD_GATEWAY);
        return;
    }

    if (u->buffer.start == NULL) {
        u->buffer.start = njt_palloc(r->pool, u->conf->buffer_size);
        if (u->buffer.start == NULL) {
            njt_http_proxy_connect_finalize_request(r, u,
                                               NJT_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        u->buffer.pos = u->buffer.start;
        u->buffer.last = u->buffer.start;
        u->buffer.end = u->buffer.start + u->conf->buffer_size;
        u->buffer.temporary = 1;
    }

    if (!ctx->send_established_done) {
        if (njt_handle_read_event(c->read, 0) != NJT_OK) {
            njt_http_proxy_connect_finalize_request(r, u,
                                               NJT_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        return;
    }

    njt_http_proxy_connect_tunnel(r, 1, 0);
}


static void
njt_http_proxy_connect_write_upstream(njt_http_request_t *r,
    njt_http_proxy_connect_upstream_t *u)
{
    njt_connection_t  *c;
    njt_http_proxy_connect_ctx_t          *ctx;

    c = u->peer.connection;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "proxy_connect: upstream write handler %s",
                   u->connected ? "" : "(connect)");

    if (c->write->timedout) {
        njt_log_error(NJT_LOG_ERR, c->log, 0,
                      "proxy_connect: upstream %s timed out (peer:%V)",
                      u->connected ? "write" : "connect", u->peer.name);
        njt_http_proxy_connect_finalize_request(r, u,
                                                NJT_HTTP_GATEWAY_TIME_OUT);
        return;
    }

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_connect_module);

    if (c->write->timer_set) {
        njt_del_timer(c->write);
    }

    if (!ctx->send_established &&
        njt_http_proxy_connect_test_connect(c) != NJT_OK)
    {
        njt_http_proxy_connect_finalize_request(r, u, NJT_HTTP_BAD_GATEWAY);
        return;
    }

    if (!ctx->send_established) {
        njt_http_proxy_connect_send_connection_established(r);
        return;
    }

    if (!ctx->send_established_done) {
        if (njt_handle_write_event(c->write, 0) != NJT_OK) {
            njt_http_proxy_connect_finalize_request(r, u,
                                               NJT_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        return;
    }

    njt_http_proxy_connect_tunnel(r, 0, 1);
}


static void
njt_http_proxy_connect_send_handler(njt_http_request_t *r)
{
    njt_connection_t                 *c;
    njt_http_proxy_connect_ctx_t     *ctx;

    c = r->connection;
    ctx = njt_http_get_module_ctx(r, njt_http_proxy_connect_module);

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "proxy_connect: send connection established handler");

    if (c->write->timedout) {
        c->timedout = 1;
        njt_log_error(NJT_LOG_ERR, c->log, 0,
                      "proxy_connect: client write timed out");
        njt_http_proxy_connect_finalize_request(r, ctx->u,
                                                NJT_HTTP_REQUEST_TIME_OUT);
        return;
    }

    if (ctx->buf.pos != ctx->buf.last) {
        njt_http_proxy_connect_send_connection_established(r);
    }
}


static void
njt_http_proxy_connect_upstream_handler(njt_event_t *ev)
{
    njt_connection_t                    *c;
    njt_http_request_t                  *r;
    njt_http_log_ctx_t                  *lctx;
    njt_http_proxy_connect_upstream_t   *u;

    c = ev->data;
    u = c->data;

    r = u->request;
    c = r->connection;

    lctx = c->log->data;
    lctx->current_request = r;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "proxy_connect: upstream handler: \"%V:%V\"",
                   &r->connect_host, &r->connect_port);

    if (ev->write) {
        u->write_event_handler(r, u);

    } else {
        u->read_event_handler(r, u);
    }

    njt_http_run_posted_requests(c);
}


static void
njt_http_proxy_connect_process_connect(njt_http_request_t *r,
    njt_http_proxy_connect_upstream_t *u)
{
    njt_int_t                        rc;
    njt_connection_t                *c;
    njt_peer_connection_t           *pc;
    njt_http_upstream_resolved_t    *ur;
    njt_http_proxy_connect_ctx_t    *ctx;

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_connect_module);

    r->connection->log->action = "connecting to upstream";

    if (njt_http_proxy_connect_set_local(r, u, u->conf->local) != NJT_OK) {
        njt_http_proxy_connect_finalize_request(r, u, NJT_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    pc = &u->peer;
    ur = u->resolved;

    pc->sockaddr = ur->sockaddr;
    pc->socklen = ur->socklen;
    pc->name = &ur->host;

    pc->get = njt_http_proxy_connect_get_peer;

    u->start_time = njt_current_msec;
    u->state.connect_time = (njt_msec_t) -1;
    u->state.first_byte_time = (njt_msec_t) -1;

    rc = njt_event_connect_peer(&u->peer);

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "proxy_connect: njt_event_connect_peer() returns %i", rc);

    /*
     * We do not retry next upstream if current connecting fails.
     * So there is no njt_http_proxy_connect_upstream_next() function
     */

    if (rc == NJT_ERROR) {
        njt_http_proxy_connect_finalize_request(r, u,
                                                NJT_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (rc == NJT_BUSY) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "proxy_connect: no live connection");
        njt_http_proxy_connect_finalize_request(r, u, NJT_HTTP_BAD_GATEWAY);
        return;
    }

    if (rc == NJT_DECLINED) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "proxy_connect: connection error");
        njt_http_proxy_connect_finalize_request(r, u, NJT_HTTP_BAD_GATEWAY);
        return;
    }

    /* rc == NJT_OK || rc == NJT_AGAIN || rc == NJT_DONE */

    c = pc->connection;

    c->data = u;

    c->write->handler = njt_http_proxy_connect_upstream_handler;
    c->read->handler = njt_http_proxy_connect_upstream_handler;

    u->write_event_handler = njt_http_proxy_connect_write_upstream;
    u->read_event_handler = njt_http_proxy_connect_read_upstream;

    c->sendfile &= r->connection->sendfile;
    c->log = r->connection->log;

    if (c->pool == NULL) {

        c->pool = njt_create_pool(128, r->connection->log);
        if (c->pool == NULL) {
            njt_http_proxy_connect_finalize_request(r, u,
                                                NJT_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    c->pool->log = c->log;
    c->read->log = c->log;
    c->write->log = c->log;

    if (rc == NJT_AGAIN) {
        njt_add_timer(c->write, ctx->connect_timeout);
        return;
    }

    njt_http_proxy_connect_send_connection_established(r);
}


static void
njt_http_proxy_connect_resolve_handler(njt_resolver_ctx_t *ctx)
{
    njt_connection_t                            *c;
    njt_http_request_t                          *r;
    njt_http_upstream_resolved_t                *ur;
    njt_http_proxy_connect_upstream_t           *u;

#if defined(njet_version) && njet_version >= 1013002
    njt_uint_t run_posted = ctx->async;
#endif

    u = ctx->data;
    r = u->request;
    ur = u->resolved;
    c = r->connection;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "proxy_connect: resolve handler");

    if (ctx->state) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "proxy_connect: %V could not be resolved (%i: %s)",
                      &ctx->name, ctx->state,
                      njt_resolver_strerror(ctx->state));

        njt_http_proxy_connect_finalize_request(r, u, NJT_HTTP_BAD_GATEWAY);
        goto failed;
    }

    ur->naddrs = ctx->naddrs;
    ur->addrs = ctx->addrs;

#if (NJT_DEBUG)
    {
#   if defined(njet_version) && njet_version >= 1005008
    njt_uint_t  i;
    njt_str_t   addr;
    u_char      text[NJT_SOCKADDR_STRLEN];

    addr.data = text;

    for (i = 0; i < ctx->naddrs; i++) {
        addr.len = njt_sock_ntop(ur->addrs[i].sockaddr, ur->addrs[i].socklen,
                                 text, NJT_SOCKADDR_STRLEN, 0);

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "proxy_connect: name was resolved to %V", &addr);
    }
#   else
    njt_uint_t  i;
    in_addr_t   addr;

    for (i = 0; i < ctx->naddrs; i++) {
        addr = ntohl(ctx->addrs[i]);

        njt_log_debug4(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "proxy_connect: name was resolved to %ud.%ud.%ud.%ud",
                       (addr >> 24) & 0xff, (addr >> 16) & 0xff,
                       (addr >> 8) & 0xff, addr & 0xff);
    }
#   endif
    }
#endif

    if (njt_http_proxy_connect_create_peer(r, ur) != NJT_OK) {
        njt_http_proxy_connect_finalize_request(r, u,
                                                NJT_HTTP_INTERNAL_SERVER_ERROR);
        goto failed;
    }

    njt_resolve_name_done(ctx);
    ur->ctx = NULL;

    u->_resolved = 1;

    if (u->state.resolve_time == (njt_msec_t) -1) {
        u->state.resolve_time = njt_current_msec - u->start_time;
    }

    njt_http_proxy_connect_process_connect(r, u);

failed:

#if defined(njet_version) && njet_version >= 1013002
    if (run_posted) {
        njt_http_run_posted_requests(c);
    }
#else
    njt_http_run_posted_requests(c);
#endif
}


static njt_int_t
njt_http_proxy_connect_create_peer(njt_http_request_t *r,
    njt_http_upstream_resolved_t *ur)
{
    u_char                                      *p;
    njt_int_t                                    i, len;
    socklen_t                                    socklen;
    struct sockaddr                             *sockaddr;

    i = njt_random() % ur->naddrs;  /* i<-0 for ur->naddrs == 1 */

#if defined(njet_version) && njet_version >= 1005008

    socklen = ur->addrs[i].socklen;

    sockaddr = njt_palloc(r->pool, socklen);
    if (sockaddr == NULL) {
        return NJT_ERROR;
    }

    njt_memcpy(sockaddr, ur->addrs[i].sockaddr, socklen);

    switch (sockaddr->sa_family) {
#if (NJT_HAVE_INET6)
    case AF_INET6:
        ((struct sockaddr_in6 *) sockaddr)->sin6_port = htons(ur->port);
        break;
#endif
    default: /* AF_INET */
        ((struct sockaddr_in *) sockaddr)->sin_port = htons(ur->port);
    }

#else
    /* for njet older than 1.5.8 */

    socklen = sizeof(struct sockaddr_in);

    sockaddr = njt_pcalloc(r->pool, socklen);
    if (sockaddr == NULL) {
        return NJT_ERROR;
    }

    ((struct sockaddr_in *) sockaddr)->sin_family = AF_INET;
    ((struct sockaddr_in *) sockaddr)->sin_addr.s_addr = ur->addrs[i];
    ((struct sockaddr_in *) sockaddr)->sin_port = htons(ur->port);

#endif

    p = njt_pnalloc(r->pool, NJT_SOCKADDR_STRLEN);
    if (p == NULL) {
        return NJT_ERROR;
    }

    len = __njt_sock_ntop(sockaddr, socklen, p, NJT_SOCKADDR_STRLEN, 1);

    ur->sockaddr = sockaddr;
    ur->socklen = socklen;

    ur->host.data = p;
    ur->host.len = len;
    ur->naddrs = 1;

    return NJT_OK;
}


static njt_int_t
njt_http_proxy_connect_upstream_create(njt_http_request_t *r,
    njt_http_proxy_connect_ctx_t *ctx)
{
    njt_http_proxy_connect_upstream_t       *u;

    u = njt_pcalloc(r->pool, sizeof(njt_http_proxy_connect_upstream_t));
    if (u == NULL) {
        return NJT_ERROR;
    }

    ctx->u = u;

    u->peer.log = r->connection->log;
    u->peer.log_error = NJT_ERROR_ERR;

    u->request = r;

    return NJT_OK;
}


static void
njt_http_proxy_connect_check_broken_connection(njt_http_request_t *r,
    njt_event_t *ev)
{
    int                                 n;
    char                                buf[1];
    njt_err_t                           err;
    njt_int_t                           event;
    njt_connection_t                   *c;
    njt_http_proxy_connect_ctx_t       *ctx;
    njt_http_proxy_connect_upstream_t  *u;

    njt_log_debug3(NJT_LOG_DEBUG_HTTP, ev->log, 0,
                   "proxy_connect: check client, write event:%d, \"%V:%V\"",
                   ev->write, &r->connect_host, &r->connect_port);

    c = r->connection;
    ctx = njt_http_get_module_ctx(r, njt_http_proxy_connect_module);
    u = ctx->u;

    if (c->error) {
        if ((njt_event_flags & NJT_USE_LEVEL_EVENT) && ev->active) {

            event = ev->write ? NJT_WRITE_EVENT : NJT_READ_EVENT;

            if (njt_del_event(ev, event, 0) != NJT_OK) {
                njt_http_proxy_connect_finalize_request(r, u,
                                               NJT_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
        }

        njt_http_proxy_connect_finalize_request(r, u,
                                               NJT_HTTP_CLIENT_CLOSED_REQUEST);

        return;
    }

#if (NJT_HAVE_KQUEUE)

    if (njt_event_flags & NJT_USE_KQUEUE_EVENT) {

        if (!ev->pending_eof) {
            return;
        }

        ev->eof = 1;
        c->error = 1;

        if (ev->kq_errno) {
            ev->error = 1;
        }

        if (u->peer.connection) {
            njt_log_error(NJT_LOG_INFO, ev->log, ev->kq_errno,
                          "proxy_connect: kevent() reported that client "
                          "prematurely closed connection, so upstream "
                          " connection is closed too");
            njt_http_proxy_connect_finalize_request(r, u,
                                               NJT_HTTP_CLIENT_CLOSED_REQUEST);
            return;
        }

        njt_log_error(NJT_LOG_INFO, ev->log, ev->kq_errno,
                      "proxy_connect: kevent() reported that client "
                      "prematurely closed connection");

        if (u->peer.connection == NULL) {
            njt_http_proxy_connect_finalize_request(r, u,
                                               NJT_HTTP_CLIENT_CLOSED_REQUEST);
        }

        return;
    }

#endif

    n = recv(c->fd, buf, 1, MSG_PEEK);

    err = njt_socket_errno;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, ev->log, err,
                   "proxy_connect: client recv(): %d", n);

    if (ev->write && (n >= 0 || err == NJT_EAGAIN)) {
        return;
    }

    if ((njt_event_flags & NJT_USE_LEVEL_EVENT) && ev->active) {

        event = ev->write ? NJT_WRITE_EVENT : NJT_READ_EVENT;

        if (njt_del_event(ev, event, 0) != NJT_OK) {
            njt_http_proxy_connect_finalize_request(r, u,
                                               NJT_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (n > 0) {
        return;
    }

    if (n == -1) {
        if (err == NJT_EAGAIN) {
            return;
        }

        ev->error = 1;

    } else { /* n == 0 */
        err = 0;
    }

    ev->eof = 1;
    c->error = 1;

    if (u->peer.connection) {
        njt_log_error(NJT_LOG_INFO, ev->log, err,
                      "proxy_connect: client prematurely closed connection, "
                      "so upstream connection is closed too");
        njt_http_proxy_connect_finalize_request(r, u,
                                           NJT_HTTP_CLIENT_CLOSED_REQUEST);
        return;
    }

    njt_log_error(NJT_LOG_INFO, ev->log, err,
                  "proxy_connect: client prematurely closed connection");

    if (u->peer.connection == NULL) {
        njt_http_proxy_connect_finalize_request(r, u,
                                           NJT_HTTP_CLIENT_CLOSED_REQUEST);
    }
}


static void
njt_http_proxy_connect_rd_check_broken_connection(njt_http_request_t *r)
{
    njt_http_proxy_connect_check_broken_connection(r, r->connection->read);
}


static void
njt_http_proxy_connect_wr_check_broken_connection(njt_http_request_t *r)
{
    njt_http_proxy_connect_check_broken_connection(r, r->connection->write);
}


static njt_int_t
njt_http_proxy_connect_handler(njt_http_request_t *r)
{
    njt_url_t                            url;
    njt_int_t                            rc;
    njt_resolver_ctx_t                  *rctx, temp;
    njt_http_core_loc_conf_t            *clcf;
    njt_http_proxy_connect_ctx_t        *ctx;
    njt_http_proxy_connect_upstream_t   *u;
    njt_http_proxy_connect_loc_conf_t   *plcf;

    plcf = njt_http_get_module_loc_conf(r, njt_http_proxy_connect_module);

    if (r->method != NJT_HTTP_CONNECT || !plcf->accept_connect) {
        return NJT_DECLINED;
    }

    rc = njt_http_proxy_connect_allow_handler(r, plcf);

    if (rc != NJT_OK) {
        return rc;
    }

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_connect_module);;

    if (njt_http_proxy_connect_upstream_create(r, ctx) != NJT_OK) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    u = ctx->u;

    u->conf = plcf;

    njt_memzero(&url, sizeof(njt_url_t));

    if (plcf->address) {
        if (njt_http_complex_value(r, plcf->address, &url.url) != NJT_OK) {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (url.url.len == 0 || url.url.data == NULL) {
            url.url.len = r->connect_host.len;
            url.url.data = r->connect_host.data;
        }

    } else {
        url.url.len = r->connect_host.len;
        url.url.data = r->connect_host.data;
    }

    url.default_port = r->connect_port_n;
    url.no_resolve = 1;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "proxy_connect: connect handler: parse url: %V" , &url.url);

    if (njt_parse_url(r->pool, &url) != NJT_OK) {
        if (url.err) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "proxy_connect: %s in connect host \"%V\"",
                          url.err, &url.url);
            return NJT_HTTP_FORBIDDEN;
        }

        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->read_event_handler = njt_http_proxy_connect_rd_check_broken_connection;
    r->write_event_handler = njt_http_proxy_connect_wr_check_broken_connection;

    /* NOTE:
     *   We use only one address in u->resolved,
     *   and u->resolved.host is "<address:port>" format.
     */

    u->resolved = njt_pcalloc(r->pool, sizeof(njt_http_upstream_resolved_t));
    if (u->resolved == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* rc = NJT_DECLINED */

    if (url.addrs) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "proxy_connect: upstream address given directly");

        u->resolved->sockaddr = url.addrs[0].sockaddr;
        u->resolved->socklen = url.addrs[0].socklen;
#if defined(njet_version) && njet_version >= 1011007
        u->resolved->name = url.addrs[0].name;
#endif
        u->resolved->naddrs = 1;
    }

    u->resolved->host = url.host;
    u->resolved->port = (in_port_t) (url.no_port ? r->connect_port_n : url.port);
    u->resolved->no_port = url.no_port;

    if (u->resolved->sockaddr) {

        rc = njt_http_proxy_connect_sock_ntop(r, u);

        if (rc != NJT_OK) {
            return rc;
        }

        r->main->count++;

        njt_http_proxy_connect_process_connect(r, u);

        return NJT_DONE;
    }

    njt_str_t *host = &url.host;

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);
    temp.name = *host;

    u->start_time = njt_current_msec;
    u->state.resolve_time = (njt_msec_t) -1;

    rctx = njt_resolve_start(clcf->resolver, &temp);
    if (rctx == NULL) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "proxy_connect: failed to start the resolver");
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (rctx == NJT_NO_RESOLVER) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "proxy_connect: no resolver defined to resolve %V",
                      &r->connect_host);
        return NJT_HTTP_BAD_GATEWAY;
    }

    rctx->name = *host;
#if !defined(njet_version) || njet_version < 1005008
    rctx->type = NJT_RESOLVE_A;
#endif
    rctx->handler = njt_http_proxy_connect_resolve_handler;
    rctx->data = u;
    rctx->timeout = clcf->resolver_timeout;

    u->resolved->ctx = rctx;

    r->main->count++;

    if (njt_resolve_name(rctx) != NJT_OK) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "proxy_connect: fail to run resolver immediately");

        u->resolved->ctx = NULL;
        r->main->count--;
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NJT_DONE;
}


static njt_int_t
njt_http_proxy_connect_sock_ntop(njt_http_request_t *r,
    njt_http_proxy_connect_upstream_t *u)
{
    u_char                          *p;
    njt_int_t                        len;
    njt_http_upstream_resolved_t    *ur;

    ur = u->resolved;

    /* fix u->resolved->host to "<address:port>" format */

    p = njt_pnalloc(r->pool, NJT_SOCKADDR_STRLEN);
    if (p == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    len = __njt_sock_ntop(ur->sockaddr, ur->socklen, p, NJT_SOCKADDR_STRLEN, 1);

    u->resolved->host.data = p;
    u->resolved->host.len = len;

    return NJT_OK;
}


static njt_int_t
njt_http_proxy_connect_allow_handler(njt_http_request_t *r,
    njt_http_proxy_connect_loc_conf_t *plcf)
{
    njt_uint_t  i, allow;
    in_port_t   (*ports)[2];

    allow = 0;

    if (plcf->allow_port_all) {
        allow = 1;

    } else if (plcf->allow_ports) {
        ports = plcf->allow_ports->elts;

        for (i = 0; i < plcf->allow_ports->nelts; i++) {
            /*
             * connect_port == port
             * OR
             * port <= connect_port <= eport
             */
            if ((ports[i][1] == 0 && r->connect_port_n == ports[i][0])
                || (ports[i][0] <= r->connect_port_n && r->connect_port_n <= ports[i][1]))
            {
                allow = 1;
                break;
            }
        }

    } else {
        if (r->connect_port_n == 443 || r->connect_port_n == 563) {
            allow = 1;
        }
    }

    if (allow == 0) {
        return NJT_HTTP_FORBIDDEN;
    }

    return NJT_OK;
}


static char *
njt_http_proxy_connect_allow(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    u_char                              *p;
    in_port_t                           *ports;
    njt_int_t                            port, eport;
    njt_uint_t                           i;
    njt_str_t                           *value;
    njt_http_proxy_connect_loc_conf_t   *plcf = conf;

    if (plcf->allow_ports != NJT_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    plcf->allow_ports = njt_array_create(cf->pool, 2, sizeof(in_port_t[2]));
    if (plcf->allow_ports == NULL) {
        return NJT_CONF_ERROR;
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (value[i].len == 3 && njt_strncmp(value[i].data, "all", 3) == 0) {
            plcf->allow_port_all = 1;
            continue;
        }

        p = njt_strlchr(value[i].data, value[i].data + value[i].len, '-');

        if (p != NULL) {
            port = njt_atoi(value[i].data, p - value[i].data);
            p++;
            eport = njt_atoi(p, value[i].data + value[i].len - p);

            if (port == NJT_ERROR || port < 1 || port > 65535
                || eport == NJT_ERROR || eport < 1 || eport > 65535
                || port > eport)
            {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid port range \"%V\" in \"%V\" directive",
                                   &value[i], &cmd->name);
                return  NJT_CONF_ERROR;
            }

        } else {

            port = njt_atoi(value[i].data, value[i].len);

            if (port == NJT_ERROR || port < 1 || port > 65535) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid value \"%V\" in \"%V\" directive",
                                   &value[i], &cmd->name);
                return  NJT_CONF_ERROR;
            }

            eport = 0;
        }

        ports = njt_array_push(plcf->allow_ports);
        if (ports == NULL) {
            return NJT_CONF_ERROR;
        }

        ports[0] = port;
        ports[1] = eport;
    }

    return NJT_CONF_OK;
}


static char *
njt_http_proxy_connect(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_core_loc_conf_t            *clcf;
    njt_http_proxy_connect_loc_conf_t   *pclcf;

    clcf = njt_http_conf_get_module_loc_conf(cf, njt_http_core_module);
    clcf->handler = njt_http_proxy_connect_handler;

    pclcf = njt_http_conf_get_module_loc_conf(cf, njt_http_proxy_connect_module);
    pclcf->accept_connect = 1;

    return NJT_CONF_OK;
}


char *
njt_http_proxy_connect_bind(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    char  *p = conf;

    njt_int_t                           rc;
    njt_str_t                          *value;
    njt_http_complex_value_t            cv;
    njt_http_proxy_connect_address_t  **plocal, *local;
    njt_http_compile_complex_value_t    ccv;

    plocal = (njt_http_proxy_connect_address_t **) (p + cmd->offset);

    if (*plocal != NJT_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cf->args->nelts == 2 && njt_strcmp(value[1].data, "off") == 0) {
        *plocal = NULL;
        return NJT_CONF_OK;
    }

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    local = njt_pcalloc(cf->pool, sizeof(njt_http_proxy_connect_address_t));
    if (local == NULL) {
        return NJT_CONF_ERROR;
    }

    *plocal = local;

    if (cv.lengths) {
        local->value = njt_palloc(cf->pool, sizeof(njt_http_complex_value_t));
        if (local->value == NULL) {
            return NJT_CONF_ERROR;
        }

        *local->value = cv;

    } else {
        local->addr = njt_palloc(cf->pool, sizeof(njt_addr_t));
        if (local->addr == NULL) {
            return NJT_CONF_ERROR;
        }

        rc = __njt_parse_addr_port(cf->pool, local->addr, value[1].data,
                                   value[1].len);

        switch (rc) {
        case NJT_OK:
            local->addr->name = value[1];
            break;

        case NJT_DECLINED:
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid address \"%V\"", &value[1]);
            /* fall through */

        default:
            return NJT_CONF_ERROR;
        }
    }

    if (cf->args->nelts > 2) {
        if (njt_strcmp(value[2].data, "transparent") == 0) {
#if (NJT_HAVE_TRANSPARENT_PROXY)
            local->transparent = 1;
#else
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "transparent proxying is not supported "
                               "on this platform, ignored");
#endif
        } else {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[2]);
            return NJT_CONF_ERROR;
        }
    }

    return NJT_CONF_OK;
}


static njt_int_t
njt_http_proxy_connect_set_local(njt_http_request_t *r,
    njt_http_proxy_connect_upstream_t *u, njt_http_proxy_connect_address_t *local)
{
    njt_int_t    rc;
    njt_str_t    val;
    njt_addr_t  *addr;

    if (local == NULL) {
        u->peer.local = NULL;
        return NJT_OK;
    }

#if (NJT_HAVE_TRANSPARENT_PROXY)
    u->peer.transparent = local->transparent;
#endif

    if (local->value == NULL) {
        u->peer.local = local->addr;
        return NJT_OK;
    }

    if (njt_http_complex_value(r, local->value, &val) != NJT_OK) {
        return NJT_ERROR;
    }

    if (val.len == 0) {
        return NJT_OK;
    }

    addr = njt_palloc(r->pool, sizeof(njt_addr_t));
    if (addr == NULL) {
        return NJT_ERROR;
    }

    rc = __njt_parse_addr_port(r->pool, addr, val.data, val.len);
    if (rc == NJT_ERROR) {
        return NJT_ERROR;
    }

    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "proxy_connect: invalid local address \"%V\"", &val);
        return NJT_OK;
    }

    addr->name = val;
    u->peer.local = addr;

    return NJT_OK;
}


static void *
njt_http_proxy_connect_create_loc_conf(njt_conf_t *cf)
{
    njt_http_proxy_connect_loc_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_proxy_connect_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     conf->address = NULL;
     */

    conf->accept_connect = NJT_CONF_UNSET;
    conf->allow_port_all = NJT_CONF_UNSET;
    conf->allow_ports = NJT_CONF_UNSET_PTR;

    conf->connect_timeout = NJT_CONF_UNSET_MSEC;
    conf->send_timeout = NJT_CONF_UNSET_MSEC;
    conf->data_timeout = NJT_CONF_UNSET_MSEC;

    conf->send_lowat = NJT_CONF_UNSET_SIZE;
    conf->buffer_size = NJT_CONF_UNSET_SIZE;

    conf->local = NJT_CONF_UNSET_PTR;

    return conf;
}


static char *
njt_http_proxy_connect_merge_loc_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_proxy_connect_loc_conf_t    *prev = parent;
    njt_http_proxy_connect_loc_conf_t    *conf = child;

    njt_conf_merge_value(conf->accept_connect, prev->accept_connect, 0);
    njt_conf_merge_value(conf->allow_port_all, prev->allow_port_all, 0);
    njt_conf_merge_ptr_value(conf->allow_ports, prev->allow_ports, NULL);

    njt_conf_merge_msec_value(conf->connect_timeout,
                              prev->connect_timeout, 60000);

    njt_conf_merge_msec_value(conf->send_timeout, prev->send_timeout, 60000);

    njt_conf_merge_msec_value(conf->data_timeout, prev->data_timeout, 60000);

    njt_conf_merge_size_value(conf->send_lowat, prev->send_lowat, 0);

    njt_conf_merge_size_value(conf->buffer_size, prev->buffer_size, 16384);

    if (conf->address == NULL) {
        conf->address = prev->address;
    }

    njt_conf_merge_ptr_value(conf->local, prev->local, NULL);

    return NJT_CONF_OK;
}


static njt_int_t
njt_http_proxy_connect_connect_addr_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{

    njt_http_proxy_connect_upstream_t     *u;
    njt_http_proxy_connect_ctx_t          *ctx;

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_connect_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NJT_OK;
    }

    u = ctx->u;

    if (u == NULL || u->peer.name == NULL) {
        v->not_found = 1;
        return NJT_OK;
    }

    v->len = u->peer.name->len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = u->peer.name->data;

    return NJT_OK;
}


static njt_int_t
njt_http_proxy_connect_variable_get_time(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    u_char                          *p;
    njt_msec_t                      *msp, ms;
    njt_http_proxy_connect_ctx_t    *ctx;

    if (r->method != NJT_HTTP_CONNECT) {
        return NJT_OK;
    }

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_connect_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NJT_OK;
    }

    msp = (njt_msec_t *) ((char *) ctx + data);
    ms = *msp;

    p = njt_pnalloc(r->pool, NJT_TIME_T_LEN);
    if (p == NULL) {
        return NJT_ERROR;
    }

    v->len = njt_sprintf(p, "%M", ms) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NJT_OK;
}


static void
njt_http_proxy_connect_variable_set_time(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    njt_str_t                        s;
    njt_msec_t                      *msp, ms;
    njt_http_proxy_connect_ctx_t    *ctx;

    if (r->method != NJT_HTTP_CONNECT) {
        return;
    }

    s.len = v->len;
    s.data = v->data;

    ms = njt_parse_time(&s, 0);

    if (ms == (njt_msec_t) NJT_ERROR) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "proxy_connect: invalid msec \"%V\" (ctx offset=%ui)",
                      &s, data);
        return;
    }

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_connect_module);

    if (ctx == NULL) {
#if 0
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "proxy_connect: no ctx found");
#endif
        return;
    }

    msp = (njt_msec_t *) ((char *) ctx + data);

    *msp = ms;
}


static njt_int_t
njt_http_proxy_connect_resolve_time_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    u_char                             *p;
    size_t                              len;
    njt_msec_int_t                      ms;
    njt_http_proxy_connect_ctx_t       *ctx;
    njt_http_proxy_connect_upstream_t  *u;

    if (r->method != NJT_HTTP_CONNECT) {
        return NJT_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_connect_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NJT_OK;
    }

    u = ctx->u;

    if (u == NULL || !u->resolved) {
        v->not_found = 1;
        return NJT_OK;
    }

    len = NJT_TIME_T_LEN + 4;

    p = njt_pnalloc(r->pool, len);
    if (p == NULL) {
        return NJT_ERROR;
    }

    v->data = p;

    ms = u->state.resolve_time;

    if (ms != -1) {
        ms = njt_max(ms, 0);
        p = njt_sprintf(p, "%T.%03M", (time_t) ms / 1000, ms % 1000);

    } else {
        *p++ = '-';
    }

    v->len = p - v->data;

    return NJT_OK;
}


static njt_int_t
njt_http_proxy_connect_connect_time_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    u_char                             *p;
    size_t                              len;
    njt_msec_int_t                      ms;
    njt_http_proxy_connect_ctx_t       *ctx;
    njt_http_proxy_connect_upstream_t  *u;

    if (r->method != NJT_HTTP_CONNECT) {
        return NJT_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_connect_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NJT_OK;
    }

    u = ctx->u;

    if (u == NULL || !u->connected) {
        v->not_found = 1;
        return NJT_OK;
    }

    len = NJT_TIME_T_LEN + 4;

    p = njt_pnalloc(r->pool, len);
    if (p == NULL) {
        return NJT_ERROR;
    }

    v->data = p;

    ms = u->state.connect_time;

    if (ms != -1) {
        ms = njt_max(ms, 0);
        p = njt_sprintf(p, "%T.%03M", (time_t) ms / 1000, ms % 1000);

    } else {
        *p++ = '-';
    }

    v->len = p - v->data;

    return NJT_OK;
}


static njt_int_t
njt_http_proxy_connect_first_byte_time_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    u_char                             *p;
    size_t                              len;
    njt_msec_int_t                      ms;
    njt_http_proxy_connect_ctx_t       *ctx;
    njt_http_proxy_connect_upstream_t  *u;

    if (r->method != NJT_HTTP_CONNECT) {
        return NJT_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_connect_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NJT_OK;
    }

    u = ctx->u;

    if (u == NULL || !u->connected) {
        v->not_found = 1;
        return NJT_OK;
    }

    len = NJT_TIME_T_LEN + 4;

    p = njt_pnalloc(r->pool, len);
    if (p == NULL) {
        return NJT_ERROR;
    }

    v->data = p;

    ms = u->state.first_byte_time;

    if (ms != -1) {
        ms = njt_max(ms, 0);
        p = njt_sprintf(p, "%T.%03M", (time_t) ms / 1000, ms % 1000);

    } else {
        *p++ = '-';
    }

    v->len = p - v->data;

    return NJT_OK;
}


static njt_int_t
njt_http_proxy_connect_variable_get_response(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    njt_http_proxy_connect_ctx_t       *ctx;

    if (r->method != NJT_HTTP_CONNECT) {
        return NJT_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_connect_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NJT_OK;
    }

    v->data = ctx->buf.pos;
    v->len = ctx->buf.last - ctx->buf.pos;

    return NJT_OK;
}


static void
njt_http_proxy_connect_variable_set_response(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    njt_http_proxy_connect_ctx_t       *ctx;

    if (r->method != NJT_HTTP_CONNECT) {
        return;
    }

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_connect_module);

    if (ctx == NULL) {
        return;
    }

    ctx->buf.pos = (u_char *) v->data;
    ctx->buf.last = ctx->buf.pos + v->len;
}

static njt_int_t
njt_http_proxy_connect_add_variables(njt_conf_t *cf)
{
    njt_http_variable_t  *var, *v;

    for (v = njt_http_proxy_connect_vars; v->name.len; v++) {
        var = njt_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NJT_ERROR;
        }

        *var = *v;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_proxy_connect_post_read_handler(njt_http_request_t *r)
{
    njt_http_proxy_connect_ctx_t      *ctx;
    njt_http_proxy_connect_loc_conf_t *pclcf;

    if (r->method == NJT_HTTP_CONNECT) {

        pclcf = njt_http_get_module_loc_conf(r, njt_http_proxy_connect_module);

        if (!pclcf->accept_connect) {
            njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                          "proxy_connect: client sent connect method");
            return NJT_HTTP_NOT_ALLOWED;
        }

        /* init ctx */

        ctx = njt_pcalloc(r->pool, sizeof(njt_http_proxy_connect_ctx_t));
        if (ctx == NULL) {
            return NJT_ERROR;
        }

        ctx->buf.pos = (u_char *) NJT_HTTP_PROXY_CONNECT_ESTABLISTHED;
        ctx->buf.last = ctx->buf.pos +
                        sizeof(NJT_HTTP_PROXY_CONNECT_ESTABLISTHED) - 1;
        ctx->buf.memory = 1;

        ctx->connect_timeout = pclcf->connect_timeout;
        ctx->send_timeout = pclcf->send_timeout;
        ctx->data_timeout = pclcf->data_timeout;

        njt_http_set_ctx(r, ctx, njt_http_proxy_connect_module);
    }

    return NJT_DECLINED;
}


static njt_int_t
njt_http_proxy_connect_init(njt_conf_t *cf)
{
    njt_http_core_main_conf_t  *cmcf;
    njt_http_handler_pt        *h;

    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);

    h = njt_array_push(&cmcf->phases[NJT_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_http_proxy_connect_post_read_handler;

    return NJT_OK;
}
