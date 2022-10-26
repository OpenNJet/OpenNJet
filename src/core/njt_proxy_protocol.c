
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) TMLake, Inc.
 */


#include <njt_config.h>
#include <njt_core.h>


#define NJT_PROXY_PROTOCOL_AF_INET          1
#define NJT_PROXY_PROTOCOL_AF_INET6         2


#define njt_proxy_protocol_parse_uint16(p)  ((p)[0] << 8 | (p)[1])


typedef struct {
    u_char                                  signature[12];
    u_char                                  version_command;
    u_char                                  family_transport;
    u_char                                  len[2];
} njt_proxy_protocol_header_t;


typedef struct {
    u_char                                  src_addr[4];
    u_char                                  dst_addr[4];
    u_char                                  src_port[2];
    u_char                                  dst_port[2];
} njt_proxy_protocol_inet_addrs_t;


typedef struct {
    u_char                                  src_addr[16];
    u_char                                  dst_addr[16];
    u_char                                  src_port[2];
    u_char                                  dst_port[2];
} njt_proxy_protocol_inet6_addrs_t;


static u_char *njt_proxy_protocol_read_addr(njt_connection_t *c, u_char *p,
    u_char *last, njt_str_t *addr);
static u_char *njt_proxy_protocol_read_port(u_char *p, u_char *last,
    in_port_t *port, u_char sep);
static u_char *njt_proxy_protocol_v2_read(njt_connection_t *c, u_char *buf,
    u_char *last);


u_char *
njt_proxy_protocol_read(njt_connection_t *c, u_char *buf, u_char *last)
{
    size_t                 len;
    u_char                *p;
    njt_proxy_protocol_t  *pp;

    static const u_char signature[] = "\r\n\r\n\0\r\nQUIT\n";

    p = buf;
    len = last - buf;

    if (len >= sizeof(njt_proxy_protocol_header_t)
        && memcmp(p, signature, sizeof(signature) - 1) == 0)
    {
        return njt_proxy_protocol_v2_read(c, buf, last);
    }

    if (len < 8 || njt_strncmp(p, "PROXY ", 6) != 0) {
        goto invalid;
    }

    p += 6;
    len -= 6;

    if (len >= 7 && njt_strncmp(p, "UNKNOWN", 7) == 0) {
        njt_log_debug0(NJT_LOG_DEBUG_CORE, c->log, 0,
                       "PROXY protocol unknown protocol");
        p += 7;
        goto skip;
    }

    if (len < 5 || njt_strncmp(p, "TCP", 3) != 0
        || (p[3] != '4' && p[3] != '6') || p[4] != ' ')
    {
        goto invalid;
    }

    p += 5;

    pp = njt_pcalloc(c->pool, sizeof(njt_proxy_protocol_t));
    if (pp == NULL) {
        return NULL;
    }

    p = njt_proxy_protocol_read_addr(c, p, last, &pp->src_addr);
    if (p == NULL) {
        goto invalid;
    }

    p = njt_proxy_protocol_read_addr(c, p, last, &pp->dst_addr);
    if (p == NULL) {
        goto invalid;
    }

    p = njt_proxy_protocol_read_port(p, last, &pp->src_port, ' ');
    if (p == NULL) {
        goto invalid;
    }

    p = njt_proxy_protocol_read_port(p, last, &pp->dst_port, CR);
    if (p == NULL) {
        goto invalid;
    }

    if (p == last) {
        goto invalid;
    }

    if (*p++ != LF) {
        goto invalid;
    }

    njt_log_debug4(NJT_LOG_DEBUG_CORE, c->log, 0,
                   "PROXY protocol src: %V %d, dst: %V %d",
                   &pp->src_addr, pp->src_port, &pp->dst_addr, pp->dst_port);

    c->proxy_protocol = pp;

    return p;

skip:

    for ( /* void */ ; p < last - 1; p++) {
        if (p[0] == CR && p[1] == LF) {
            return p + 2;
        }
    }

invalid:

    njt_log_error(NJT_LOG_ERR, c->log, 0,
                  "broken header: \"%*s\"", (size_t) (last - buf), buf);

    return NULL;
}


static u_char *
njt_proxy_protocol_read_addr(njt_connection_t *c, u_char *p, u_char *last,
    njt_str_t *addr)
{
    size_t  len;
    u_char  ch, *pos;

    pos = p;

    for ( ;; ) {
        if (p == last) {
            return NULL;
        }

        ch = *p++;

        if (ch == ' ') {
            break;
        }

        if (ch != ':' && ch != '.'
            && (ch < 'a' || ch > 'f')
            && (ch < 'A' || ch > 'F')
            && (ch < '0' || ch > '9'))
        {
            return NULL;
        }
    }

    len = p - pos - 1;

    addr->data = njt_pnalloc(c->pool, len);
    if (addr->data == NULL) {
        return NULL;
    }

    njt_memcpy(addr->data, pos, len);
    addr->len = len;

    return p;
}


static u_char *
njt_proxy_protocol_read_port(u_char *p, u_char *last, in_port_t *port,
    u_char sep)
{
    size_t      len;
    u_char     *pos;
    njt_int_t   n;

    pos = p;

    for ( ;; ) {
        if (p == last) {
            return NULL;
        }

        if (*p++ == sep) {
            break;
        }
    }

    len = p - pos - 1;

    n = njt_atoi(pos, len);
    if (n < 0 || n > 65535) {
        return NULL;
    }

    *port = (in_port_t) n;

    return p;
}


u_char *
njt_proxy_protocol_write(njt_connection_t *c, u_char *buf, u_char *last)
{
    njt_uint_t  port, lport;

    if (last - buf < NJT_PROXY_PROTOCOL_MAX_HEADER) {
        return NULL;
    }

    if (njt_connection_local_sockaddr(c, NULL, 0) != NJT_OK) {
        return NULL;
    }

    switch (c->sockaddr->sa_family) {

    case AF_INET:
        buf = njt_cpymem(buf, "PROXY TCP4 ", sizeof("PROXY TCP4 ") - 1);
        break;

#if (NJT_HAVE_INET6)
    case AF_INET6:
        buf = njt_cpymem(buf, "PROXY TCP6 ", sizeof("PROXY TCP6 ") - 1);
        break;
#endif

    default:
        return njt_cpymem(buf, "PROXY UNKNOWN" CRLF,
                          sizeof("PROXY UNKNOWN" CRLF) - 1);
    }

    buf += njt_sock_ntop(c->sockaddr, c->socklen, buf, last - buf, 0);

    *buf++ = ' ';

    buf += njt_sock_ntop(c->local_sockaddr, c->local_socklen, buf, last - buf,
                         0);

    port = njt_inet_get_port(c->sockaddr);
    lport = njt_inet_get_port(c->local_sockaddr);

    return njt_slprintf(buf, last, " %ui %ui" CRLF, port, lport);
}


static u_char *
njt_proxy_protocol_v2_read(njt_connection_t *c, u_char *buf, u_char *last)
{
    u_char                             *end;
    size_t                              len;
    socklen_t                           socklen;
    njt_uint_t                          version, command, family, transport;
    njt_sockaddr_t                      src_sockaddr, dst_sockaddr;
    njt_proxy_protocol_t               *pp;
    njt_proxy_protocol_header_t        *header;
    njt_proxy_protocol_inet_addrs_t    *in;
#if (NJT_HAVE_INET6)
    njt_proxy_protocol_inet6_addrs_t   *in6;
#endif

    header = (njt_proxy_protocol_header_t *) buf;

    buf += sizeof(njt_proxy_protocol_header_t);

    version = header->version_command >> 4;

    if (version != 2) {
        njt_log_error(NJT_LOG_ERR, c->log, 0,
                      "unknown PROXY protocol version: %ui", version);
        return NULL;
    }

    len = njt_proxy_protocol_parse_uint16(header->len);

    if ((size_t) (last - buf) < len) {
        njt_log_error(NJT_LOG_ERR, c->log, 0, "header is too large");
        return NULL;
    }

    end = buf + len;

    command = header->version_command & 0x0f;

    /* only PROXY is supported */
    if (command != 1) {
        njt_log_debug1(NJT_LOG_DEBUG_CORE, c->log, 0,
                       "PROXY protocol v2 unsupported command %ui", command);
        return end;
    }

    transport = header->family_transport & 0x0f;

    /* only STREAM is supported */
    if (transport != 1) {
        njt_log_debug1(NJT_LOG_DEBUG_CORE, c->log, 0,
                       "PROXY protocol v2 unsupported transport %ui",
                       transport);
        return end;
    }

    pp = njt_pcalloc(c->pool, sizeof(njt_proxy_protocol_t));
    if (pp == NULL) {
        return NULL;
    }

    family = header->family_transport >> 4;

    switch (family) {

    case NJT_PROXY_PROTOCOL_AF_INET:

        if ((size_t) (end - buf) < sizeof(njt_proxy_protocol_inet_addrs_t)) {
            return NULL;
        }

        in = (njt_proxy_protocol_inet_addrs_t *) buf;

        src_sockaddr.sockaddr_in.sin_family = AF_INET;
        src_sockaddr.sockaddr_in.sin_port = 0;
        memcpy(&src_sockaddr.sockaddr_in.sin_addr, in->src_addr, 4);

        dst_sockaddr.sockaddr_in.sin_family = AF_INET;
        dst_sockaddr.sockaddr_in.sin_port = 0;
        memcpy(&dst_sockaddr.sockaddr_in.sin_addr, in->dst_addr, 4);

        pp->src_port = njt_proxy_protocol_parse_uint16(in->src_port);
        pp->dst_port = njt_proxy_protocol_parse_uint16(in->dst_port);

        socklen = sizeof(struct sockaddr_in);

        buf += sizeof(njt_proxy_protocol_inet_addrs_t);

        break;

#if (NJT_HAVE_INET6)

    case NJT_PROXY_PROTOCOL_AF_INET6:

        if ((size_t) (end - buf) < sizeof(njt_proxy_protocol_inet6_addrs_t)) {
            return NULL;
        }

        in6 = (njt_proxy_protocol_inet6_addrs_t *) buf;

        src_sockaddr.sockaddr_in6.sin6_family = AF_INET6;
        src_sockaddr.sockaddr_in6.sin6_port = 0;
        memcpy(&src_sockaddr.sockaddr_in6.sin6_addr, in6->src_addr, 16);

        dst_sockaddr.sockaddr_in6.sin6_family = AF_INET6;
        dst_sockaddr.sockaddr_in6.sin6_port = 0;
        memcpy(&dst_sockaddr.sockaddr_in6.sin6_addr, in6->dst_addr, 16);

        pp->src_port = njt_proxy_protocol_parse_uint16(in6->src_port);
        pp->dst_port = njt_proxy_protocol_parse_uint16(in6->dst_port);

        socklen = sizeof(struct sockaddr_in6);

        buf += sizeof(njt_proxy_protocol_inet6_addrs_t);

        break;

#endif

    default:
        njt_log_debug1(NJT_LOG_DEBUG_CORE, c->log, 0,
                       "PROXY protocol v2 unsupported address family %ui",
                       family);
        return end;
    }

    pp->src_addr.data = njt_pnalloc(c->pool, NJT_SOCKADDR_STRLEN);
    if (pp->src_addr.data == NULL) {
        return NULL;
    }

    pp->src_addr.len = njt_sock_ntop(&src_sockaddr.sockaddr, socklen,
                                     pp->src_addr.data, NJT_SOCKADDR_STRLEN, 0);

    pp->dst_addr.data = njt_pnalloc(c->pool, NJT_SOCKADDR_STRLEN);
    if (pp->dst_addr.data == NULL) {
        return NULL;
    }

    pp->dst_addr.len = njt_sock_ntop(&dst_sockaddr.sockaddr, socklen,
                                     pp->dst_addr.data, NJT_SOCKADDR_STRLEN, 0);

    njt_log_debug4(NJT_LOG_DEBUG_CORE, c->log, 0,
                   "PROXY protocol v2 src: %V %d, dst: %V %d",
                   &pp->src_addr, pp->src_port, &pp->dst_addr, pp->dst_port);

    if (buf < end) {
        njt_log_debug1(NJT_LOG_DEBUG_CORE, c->log, 0,
                       "PROXY protocol v2 %z bytes of tlv ignored", end - buf);
    }

    c->proxy_protocol = pp;

    return end;
}
