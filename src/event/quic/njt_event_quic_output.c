
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>
#include <njt_event_quic_connection.h>


#define NJT_QUIC_MAX_UDP_SEGMENT_BUF  65487 /* 65K - IPv6 header */
#define NJT_QUIC_MAX_SEGMENTS            64 /* UDP_MAX_SEGMENTS */

#define NJT_QUIC_RETRY_TOKEN_LIFETIME     3 /* seconds */
#define NJT_QUIC_NEW_TOKEN_LIFETIME     600 /* seconds */
#define NJT_QUIC_RETRY_BUFFER_SIZE      256
    /* 1 flags + 4 version + 3 x (1 + 20) s/o/dcid + itag + token(64) */

/*
 * RFC 9000, 10.3.  Stateless Reset
 *
 * Endpoints MUST discard packets that are too small to be valid QUIC
 * packets.  With the set of AEAD functions defined in [QUIC-TLS],
 * short header packets that are smaller than 21 bytes are never valid.
 */
#define NJT_QUIC_MIN_PKT_LEN             21

#define NJT_QUIC_MIN_SR_PACKET           43 /* 5 rand + 16 srt + 22 padding */
#define NJT_QUIC_MAX_SR_PACKET         1200

#define NJT_QUIC_CC_MIN_INTERVAL       1000 /* 1s */

#define NJT_QUIC_SOCKET_RETRY_DELAY      10 /* ms, for NJT_AGAIN on write */


#define njt_quic_log_packet(log, pkt)                                         \
    njt_log_debug6(NJT_LOG_DEBUG_EVENT, log, 0,                               \
                   "quic packet tx %s bytes:%ui need_ack:%d"                  \
                   " number:%L encoded nl:%d trunc:0x%xD",                    \
                   njt_quic_level_name((pkt)->level), (pkt)->payload.len,     \
                   (pkt)->need_ack, (pkt)->number, (pkt)->num_len,            \
                    (pkt)->trunc);


static njt_int_t njt_quic_create_datagrams(njt_connection_t *c);
static void njt_quic_commit_send(njt_connection_t *c, njt_quic_send_ctx_t *ctx);
static void njt_quic_revert_send(njt_connection_t *c, njt_quic_send_ctx_t *ctx,
    uint64_t pnum);
#if ((NJT_HAVE_UDP_SEGMENT) && (NJT_HAVE_MSGHDR_MSG_CONTROL))
static njt_uint_t njt_quic_allow_segmentation(njt_connection_t *c);
static njt_int_t njt_quic_create_segments(njt_connection_t *c);
static ssize_t njt_quic_send_segments(njt_connection_t *c, u_char *buf,
    size_t len, struct sockaddr *sockaddr, socklen_t socklen, size_t segment);
#endif
static ssize_t njt_quic_output_packet(njt_connection_t *c,
    njt_quic_send_ctx_t *ctx, u_char *data, size_t max, size_t min);
static void njt_quic_init_packet(njt_connection_t *c, njt_quic_send_ctx_t *ctx,
    njt_quic_header_t *pkt, njt_quic_path_t *path);
static njt_uint_t njt_quic_get_padding_level(njt_connection_t *c);
static ssize_t njt_quic_send(njt_connection_t *c, u_char *buf, size_t len,
    struct sockaddr *sockaddr, socklen_t socklen);
static void njt_quic_set_packet_number(njt_quic_header_t *pkt,
    njt_quic_send_ctx_t *ctx);


njt_int_t
njt_quic_output(njt_connection_t *c)
{
    size_t                  in_flight;
    njt_int_t               rc;
    njt_quic_congestion_t  *cg;
    njt_quic_connection_t  *qc;

    c->log->action = "sending frames";

    qc = njt_quic_get_connection(c);
    cg = &qc->congestion;

    in_flight = cg->in_flight;

#if ((NJT_HAVE_UDP_SEGMENT) && (NJT_HAVE_MSGHDR_MSG_CONTROL))
    if (njt_quic_allow_segmentation(c)) {
        rc = njt_quic_create_segments(c);
    } else
#endif
    {
        rc = njt_quic_create_datagrams(c);
    }

    if (rc != NJT_OK) {
        return NJT_ERROR;
    }

    if (in_flight == cg->in_flight || qc->closing) {
        /* no ack-eliciting data was sent or we are done */
        return NJT_OK;
    }

    if (!qc->send_timer_set) {
        qc->send_timer_set = 1;
        njt_add_timer(c->read, qc->tp.max_idle_timeout);
    }

    njt_quic_set_lost_timer(c);

    return NJT_OK;
}


static njt_int_t
njt_quic_create_datagrams(njt_connection_t *c)
{
    size_t                  len, min;
    ssize_t                 n;
    u_char                 *p;
    uint64_t                preserved_pnum[NJT_QUIC_SEND_CTX_LAST];
    njt_uint_t              i, pad;
    njt_quic_path_t        *path;
    njt_quic_send_ctx_t    *ctx;
    njt_quic_congestion_t  *cg;
    njt_quic_connection_t  *qc;
    static u_char           dst[NJT_QUIC_MAX_UDP_PAYLOAD_SIZE];

    qc = njt_quic_get_connection(c);
    cg = &qc->congestion;
    path = qc->path;

    while (cg->in_flight < cg->window) {

        p = dst;

        len = njt_quic_path_limit(c, path, path->mtu);

        pad = njt_quic_get_padding_level(c);

        for (i = 0; i < NJT_QUIC_SEND_CTX_LAST; i++) {

            ctx = &qc->send_ctx[i];

            preserved_pnum[i] = ctx->pnum;

            if (njt_quic_generate_ack(c, ctx) != NJT_OK) {
                return NJT_ERROR;
            }

            min = (i == pad && p - dst < NJT_QUIC_MIN_INITIAL_SIZE)
                  ? NJT_QUIC_MIN_INITIAL_SIZE - (p - dst) : 0;

            if (min > len) {
                /* padding can't be applied - avoid sending the packet */

                while (i-- > 0) {
                    ctx = &qc->send_ctx[i];
                    njt_quic_revert_send(c, ctx, preserved_pnum[i]);
                }

                return NJT_OK;
            }

            n = njt_quic_output_packet(c, ctx, p, len, min);
            if (n == NJT_ERROR) {
                return NJT_ERROR;
            }

            p += n;
            len -= n;
        }

        len = p - dst;
        if (len == 0) {
            break;
        }

        n = njt_quic_send(c, dst, len, path->sockaddr, path->socklen);

        if (n == NJT_ERROR) {
            return NJT_ERROR;
        }

        if (n == NJT_AGAIN) {
            for (i = 0; i < NJT_QUIC_SEND_CTX_LAST; i++) {
                njt_quic_revert_send(c, &qc->send_ctx[i], preserved_pnum[i]);
            }

            njt_add_timer(&qc->push, NJT_QUIC_SOCKET_RETRY_DELAY);
            break;
        }

        for (i = 0; i < NJT_QUIC_SEND_CTX_LAST; i++) {
            njt_quic_commit_send(c, &qc->send_ctx[i]);
        }

        path->sent += len;
    }

    return NJT_OK;
}


static void
njt_quic_commit_send(njt_connection_t *c, njt_quic_send_ctx_t *ctx)
{
    njt_queue_t            *q;
    njt_quic_frame_t       *f;
    njt_quic_congestion_t  *cg;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    cg = &qc->congestion;

    while (!njt_queue_empty(&ctx->sending)) {

        q = njt_queue_head(&ctx->sending);
        f = njt_queue_data(q, njt_quic_frame_t, queue);

        njt_queue_remove(q);

        if (f->pkt_need_ack && !qc->closing) {
            njt_queue_insert_tail(&ctx->sent, q);

            cg->in_flight += f->plen;

        } else {
            njt_quic_free_frame(c, f);
        }
    }

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic congestion send if:%uz", cg->in_flight);
}


static void
njt_quic_revert_send(njt_connection_t *c, njt_quic_send_ctx_t *ctx,
    uint64_t pnum)
{
    njt_queue_t  *q;

    while (!njt_queue_empty(&ctx->sending)) {

        q = njt_queue_last(&ctx->sending);
        njt_queue_remove(q);
        njt_queue_insert_head(&ctx->frames, q);
    }

    ctx->pnum = pnum;
}


#if ((NJT_HAVE_UDP_SEGMENT) && (NJT_HAVE_MSGHDR_MSG_CONTROL))

static njt_uint_t
njt_quic_allow_segmentation(njt_connection_t *c)
{
    size_t                  bytes, len;
    njt_queue_t            *q;
    njt_quic_frame_t       *f;
    njt_quic_send_ctx_t    *ctx;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    if (!qc->conf->gso_enabled) {
        return 0;
    }

    if (!qc->path->validated) {
        /* don't even try to be faster on non-validated paths */
        return 0;
    }

    ctx = njt_quic_get_send_ctx(qc, ssl_encryption_initial);
    if (!njt_queue_empty(&ctx->frames)) {
        return 0;
    }

    ctx = njt_quic_get_send_ctx(qc, ssl_encryption_handshake);
    if (!njt_queue_empty(&ctx->frames)) {
        return 0;
    }

    ctx = njt_quic_get_send_ctx(qc, ssl_encryption_application);

    bytes = 0;
    len = njt_min(qc->path->mtu, NJT_QUIC_MAX_UDP_SEGMENT_BUF);

    for (q = njt_queue_head(&ctx->frames);
         q != njt_queue_sentinel(&ctx->frames);
         q = njt_queue_next(q))
    {
        f = njt_queue_data(q, njt_quic_frame_t, queue);

        bytes += f->len;

        if (bytes > len * 3) {
            /* require at least ~3 full packets to batch */
            return 1;
        }
    }

    return 0;
}


static njt_int_t
njt_quic_create_segments(njt_connection_t *c)
{
    size_t                  len, segsize;
    ssize_t                 n;
    u_char                 *p, *end;
    uint64_t                preserved_pnum;
    njt_uint_t              nseg;
    njt_quic_path_t        *path;
    njt_quic_send_ctx_t    *ctx;
    njt_quic_congestion_t  *cg;
    njt_quic_connection_t  *qc;
    static u_char           dst[NJT_QUIC_MAX_UDP_SEGMENT_BUF];

    qc = njt_quic_get_connection(c);
    cg = &qc->congestion;
    path = qc->path;

    ctx = njt_quic_get_send_ctx(qc, ssl_encryption_application);

    if (njt_quic_generate_ack(c, ctx) != NJT_OK) {
        return NJT_ERROR;
    }

    segsize = njt_min(path->mtu, NJT_QUIC_MAX_UDP_SEGMENT_BUF);
    p = dst;
    end = dst + sizeof(dst);

    nseg = 0;

    preserved_pnum = ctx->pnum;

    for ( ;; ) {

        len = njt_min(segsize, (size_t) (end - p));

        if (len && cg->in_flight + (p - dst) < cg->window) {

            n = njt_quic_output_packet(c, ctx, p, len, len);
            if (n == NJT_ERROR) {
                return NJT_ERROR;
            }

            if (n) {
                p += n;
                nseg++;
            }

        } else {
            n = 0;
        }

        if (p == dst) {
            break;
        }

        if (n == 0 || nseg == NJT_QUIC_MAX_SEGMENTS) {
            n = njt_quic_send_segments(c, dst, p - dst, path->sockaddr,
                                       path->socklen, segsize);
            if (n == NJT_ERROR) {
                return NJT_ERROR;
            }

            if (n == NJT_AGAIN) {
                njt_quic_revert_send(c, ctx, preserved_pnum);

                njt_add_timer(&qc->push, NJT_QUIC_SOCKET_RETRY_DELAY);
                break;
            }

            njt_quic_commit_send(c, ctx);

            path->sent += n;

            p = dst;
            nseg = 0;
            preserved_pnum = ctx->pnum;
        }
    }

    return NJT_OK;
}


static ssize_t
njt_quic_send_segments(njt_connection_t *c, u_char *buf, size_t len,
    struct sockaddr *sockaddr, socklen_t socklen, size_t segment)
{
    size_t           clen;
    ssize_t          n;
    uint16_t        *valp;
    struct iovec     iov;
    struct msghdr    msg;
    struct cmsghdr  *cmsg;

#if (NJT_HAVE_ADDRINFO_CMSG)
    char             msg_control[CMSG_SPACE(sizeof(uint16_t))
                             + CMSG_SPACE(sizeof(njt_addrinfo_t))];
#else
    char             msg_control[CMSG_SPACE(sizeof(uint16_t))];
#endif

    njt_memzero(&msg, sizeof(struct msghdr));
    njt_memzero(msg_control, sizeof(msg_control));

    iov.iov_len = len;
    iov.iov_base = buf;

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    msg.msg_name = sockaddr;
    msg.msg_namelen = socklen;

    msg.msg_control = msg_control;
    msg.msg_controllen = sizeof(msg_control);

    cmsg = CMSG_FIRSTHDR(&msg);

    cmsg->cmsg_level = SOL_UDP;
    cmsg->cmsg_type = UDP_SEGMENT;
    cmsg->cmsg_len = CMSG_LEN(sizeof(uint16_t));

    clen = CMSG_SPACE(sizeof(uint16_t));

    valp = (void *) CMSG_DATA(cmsg);
    *valp = segment;

#if (NJT_HAVE_ADDRINFO_CMSG)
    if (c->listening && c->listening->wildcard && c->local_sockaddr) {
        cmsg = CMSG_NXTHDR(&msg, cmsg);
        clen += njt_set_srcaddr_cmsg(cmsg, c->local_sockaddr);
    }
#endif

    msg.msg_controllen = clen;

    n = njt_sendmsg(c, &msg, 0);
    if (n < 0) {
        return n;
    }

    c->sent += n;

    return n;
}

#endif



static njt_uint_t
njt_quic_get_padding_level(njt_connection_t *c)
{
    njt_uint_t              i;
    njt_queue_t            *q;
    njt_quic_frame_t       *f;
    njt_quic_send_ctx_t    *ctx;
    njt_quic_connection_t  *qc;

    /*
     * RFC 9000, 14.1.  Initial Datagram Size
     *
     * Similarly, a server MUST expand the payload of all UDP datagrams
     * carrying ack-eliciting Initial packets to at least the smallest
     * allowed maximum datagram size of 1200 bytes.
     */

    qc = njt_quic_get_connection(c);
    ctx = njt_quic_get_send_ctx(qc, ssl_encryption_initial);

    for (q = njt_queue_head(&ctx->frames);
         q != njt_queue_sentinel(&ctx->frames);
         q = njt_queue_next(q))
    {
        f = njt_queue_data(q, njt_quic_frame_t, queue);

        if (f->need_ack) {
            for (i = 0; i + 1 < NJT_QUIC_SEND_CTX_LAST; i++) {
                ctx = &qc->send_ctx[i + 1];

                if (njt_queue_empty(&ctx->frames)) {
                    break;
                }
            }

            return i;
        }
    }

    return NJT_QUIC_SEND_CTX_LAST;
}


static ssize_t
njt_quic_output_packet(njt_connection_t *c, njt_quic_send_ctx_t *ctx,
    u_char *data, size_t max, size_t min)
{
    size_t                  len, pad, min_payload, max_payload;
    u_char                 *p;
    ssize_t                 flen;
    njt_str_t               res;
    njt_int_t               rc;
    njt_uint_t              nframes;
    njt_msec_t              now;
    njt_queue_t            *q;
    njt_quic_frame_t       *f;
    njt_quic_header_t       pkt;
    njt_quic_connection_t  *qc;
    static u_char           src[NJT_QUIC_MAX_UDP_PAYLOAD_SIZE];

    if (njt_queue_empty(&ctx->frames)) {
        return 0;
    }

    njt_log_debug3(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic output %s packet max:%uz min:%uz",
                   njt_quic_level_name(ctx->level), max, min);

    qc = njt_quic_get_connection(c);

    if (!njt_quic_keys_available(qc->keys, ctx->level, 1)) {
        njt_log_error(NJT_LOG_ALERT, c->log, 0, "quic %s write keys discarded",
                      njt_quic_level_name(ctx->level));

        while (!njt_queue_empty(&ctx->frames)) {
            q = njt_queue_head(&ctx->frames);
            njt_queue_remove(q);

            f = njt_queue_data(q, njt_quic_frame_t, queue);
            njt_quic_free_frame(c, f);
        }

        return 0;
    }

    njt_quic_init_packet(c, ctx, &pkt, qc->path);

    min_payload = njt_quic_payload_size(&pkt, min);
    max_payload = njt_quic_payload_size(&pkt, max);

    /* RFC 9001, 5.4.2.  Header Protection Sample */
    pad = 4 - pkt.num_len;
    min_payload = njt_max(min_payload, pad);

    if (min_payload > max_payload) {
        return 0;
    }

    now = njt_current_msec;
    nframes = 0;
    p = src;
    len = 0;

    for (q = njt_queue_head(&ctx->frames);
         q != njt_queue_sentinel(&ctx->frames);
         q = njt_queue_next(q))
    {
        f = njt_queue_data(q, njt_quic_frame_t, queue);

        if (len >= max_payload) {
            break;
        }

        if (len + f->len > max_payload) {
            rc = njt_quic_split_frame(c, f, max_payload - len);

            if (rc == NJT_ERROR) {
                return NJT_ERROR;
            }

            if (rc == NJT_DECLINED) {
                break;
            }
        }

        if (f->need_ack) {
            pkt.need_ack = 1;
        }

        f->pnum = ctx->pnum;
        f->send_time = now;
        f->plen = 0;

        njt_quic_log_frame(c->log, f, 1);

        flen = njt_quic_create_frame(p, f);
        if (flen == -1) {
            return NJT_ERROR;
        }

        len += flen;
        p += flen;

        nframes++;
    }

    if (nframes == 0) {
        return 0;
    }

    if (len < min_payload) {
        njt_memset(p, NJT_QUIC_FT_PADDING, min_payload - len);
        len = min_payload;
    }

    pkt.payload.data = src;
    pkt.payload.len = len;

    res.data = data;

    njt_quic_log_packet(c->log, &pkt);

    if (njt_quic_encrypt(&pkt, &res) != NJT_OK) {
        return NJT_ERROR;
    }

    ctx->pnum++;

    if (pkt.need_ack) {
        q = njt_queue_head(&ctx->frames);
        f = njt_queue_data(q, njt_quic_frame_t, queue);

        f->plen = res.len;
    }

    while (nframes--) {
        q = njt_queue_head(&ctx->frames);
        f = njt_queue_data(q, njt_quic_frame_t, queue);

        f->pkt_need_ack = pkt.need_ack;

        njt_queue_remove(q);
        njt_queue_insert_tail(&ctx->sending, q);
    }

    return res.len;
}


static void
njt_quic_init_packet(njt_connection_t *c, njt_quic_send_ctx_t *ctx,
    njt_quic_header_t *pkt, njt_quic_path_t *path)
{
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    njt_memzero(pkt, sizeof(njt_quic_header_t));

    pkt->flags = NJT_QUIC_PKT_FIXED_BIT;

    if (ctx->level == ssl_encryption_initial) {
        pkt->flags |= NJT_QUIC_PKT_LONG | NJT_QUIC_PKT_INITIAL;

    } else if (ctx->level == ssl_encryption_handshake) {
        pkt->flags |= NJT_QUIC_PKT_LONG | NJT_QUIC_PKT_HANDSHAKE;

    } else {
        if (qc->key_phase) {
            pkt->flags |= NJT_QUIC_PKT_KPHASE;
        }
    }

    pkt->dcid.data = path->cid->id;
    pkt->dcid.len = path->cid->len;

    pkt->scid = qc->tp.initial_scid;

    pkt->version = qc->version;
    pkt->log = c->log;
    pkt->level = ctx->level;

    pkt->keys = qc->keys;

    njt_quic_set_packet_number(pkt, ctx);
}


static ssize_t
njt_quic_send(njt_connection_t *c, u_char *buf, size_t len,
    struct sockaddr *sockaddr, socklen_t socklen)
{
    ssize_t          n;
    struct iovec     iov;
    struct msghdr    msg;
#if (NJT_HAVE_ADDRINFO_CMSG)
    struct cmsghdr  *cmsg;
    char             msg_control[CMSG_SPACE(sizeof(njt_addrinfo_t))];
#endif

    njt_memzero(&msg, sizeof(struct msghdr));

    iov.iov_len = len;
    iov.iov_base = buf;

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    msg.msg_name = sockaddr;
    msg.msg_namelen = socklen;

#if (NJT_HAVE_ADDRINFO_CMSG)
    if (c->listening && c->listening->wildcard && c->local_sockaddr) {

        msg.msg_control = msg_control;
        msg.msg_controllen = sizeof(msg_control);
        njt_memzero(msg_control, sizeof(msg_control));

        cmsg = CMSG_FIRSTHDR(&msg);

        msg.msg_controllen = njt_set_srcaddr_cmsg(cmsg, c->local_sockaddr);
    }
#endif

    n = njt_sendmsg(c, &msg, 0);
    if (n < 0) {
        return n;
    }

    c->sent += n;

    return n;
}


static void
njt_quic_set_packet_number(njt_quic_header_t *pkt, njt_quic_send_ctx_t *ctx)
{
    uint64_t  delta;

    delta = ctx->pnum - ctx->largest_ack;
    pkt->number = ctx->pnum;

    if (delta <= 0x7F) {
        pkt->num_len = 1;
        pkt->trunc = ctx->pnum & 0xff;

    } else if (delta <= 0x7FFF) {
        pkt->num_len = 2;
        pkt->flags |= 0x1;
        pkt->trunc = ctx->pnum & 0xffff;

    } else if (delta <= 0x7FFFFF) {
        pkt->num_len = 3;
        pkt->flags |= 0x2;
        pkt->trunc = ctx->pnum & 0xffffff;

    } else {
        pkt->num_len = 4;
        pkt->flags |= 0x3;
        pkt->trunc = ctx->pnum & 0xffffffff;
    }
}


njt_int_t
njt_quic_negotiate_version(njt_connection_t *c, njt_quic_header_t *inpkt)
{
    size_t             len;
    njt_quic_header_t  pkt;
    static u_char      buf[NJT_QUIC_MAX_UDP_PAYLOAD_SIZE];

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "sending version negotiation packet");

    pkt.log = c->log;
    pkt.flags = NJT_QUIC_PKT_LONG | NJT_QUIC_PKT_FIXED_BIT;
    pkt.dcid = inpkt->scid;
    pkt.scid = inpkt->dcid;

    len = njt_quic_create_version_negotiation(&pkt, buf);

#ifdef NJT_QUIC_DEBUG_PACKETS
    njt_log_debug3(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic vnego packet to send len:%uz %*xs", len, len, buf);
#endif

    (void) njt_quic_send(c, buf, len, c->sockaddr, c->socklen);

    return NJT_DONE;
}


njt_int_t
njt_quic_send_stateless_reset(njt_connection_t *c, njt_quic_conf_t *conf,
    njt_quic_header_t *pkt)
{
    u_char    *token;
    size_t     len, max;
    uint16_t   rndbytes;
    u_char     buf[NJT_QUIC_MAX_SR_PACKET];

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic handle stateless reset output");

    if (pkt->len <= NJT_QUIC_MIN_PKT_LEN) {
        return NJT_DECLINED;
    }

    if (pkt->len <= NJT_QUIC_MIN_SR_PACKET) {
        len = pkt->len - 1;

    } else {
        max = njt_min(NJT_QUIC_MAX_SR_PACKET, pkt->len * 3);

        if (RAND_bytes((u_char *) &rndbytes, sizeof(rndbytes)) != 1) {
            return NJT_ERROR;
        }

        len = (rndbytes % (max - NJT_QUIC_MIN_SR_PACKET + 1))
              + NJT_QUIC_MIN_SR_PACKET;
    }

    if (RAND_bytes(buf, len - NJT_QUIC_SR_TOKEN_LEN) != 1) {
        return NJT_ERROR;
    }

    buf[0] &= ~NJT_QUIC_PKT_LONG;
    buf[0] |= NJT_QUIC_PKT_FIXED_BIT;

    token = &buf[len - NJT_QUIC_SR_TOKEN_LEN];

    if (njt_quic_new_sr_token(c, &pkt->dcid, conf->sr_token_key, token)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    (void) njt_quic_send(c, buf, len, c->sockaddr, c->socklen);

    return NJT_DECLINED;
}


njt_int_t
njt_quic_send_cc(njt_connection_t *c)
{
    njt_quic_frame_t       *frame;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    if (qc->draining) {
        return NJT_OK;
    }

    if (qc->closing
        && njt_current_msec - qc->last_cc < NJT_QUIC_CC_MIN_INTERVAL)
    {
        /* dot not send CC too often */
        return NJT_OK;
    }

    frame = njt_quic_alloc_frame(c);
    if (frame == NULL) {
        return NJT_ERROR;
    }

    frame->level = qc->error_level;
    frame->type = qc->error_app ? NJT_QUIC_FT_CONNECTION_CLOSE_APP
                                : NJT_QUIC_FT_CONNECTION_CLOSE;
    frame->u.close.error_code = qc->error;
    frame->u.close.frame_type = qc->error_ftype;

    if (qc->error_reason) {
        frame->u.close.reason.len = njt_strlen(qc->error_reason);
        frame->u.close.reason.data = (u_char *) qc->error_reason;
    }

    frame->ignore_congestion = 1;

    qc->last_cc = njt_current_msec;

    return njt_quic_frame_sendto(c, frame, 0, qc->path);
}


njt_int_t
njt_quic_send_early_cc(njt_connection_t *c, njt_quic_header_t *inpkt,
    njt_uint_t err, const char *reason)
{
    ssize_t            len;
    njt_str_t          res;
    njt_quic_keys_t    keys;
    njt_quic_frame_t   frame;
    njt_quic_header_t  pkt;

    static u_char       src[NJT_QUIC_MAX_UDP_PAYLOAD_SIZE];
    static u_char       dst[NJT_QUIC_MAX_UDP_PAYLOAD_SIZE];

    njt_memzero(&frame, sizeof(njt_quic_frame_t));
    njt_memzero(&pkt, sizeof(njt_quic_header_t));

    frame.level = inpkt->level;
    frame.type = NJT_QUIC_FT_CONNECTION_CLOSE;
    frame.u.close.error_code = err;

    frame.u.close.reason.data = (u_char *) reason;
    frame.u.close.reason.len = njt_strlen(reason);

    njt_quic_log_frame(c->log, &frame, 1);

    len = njt_quic_create_frame(NULL, &frame);
    if (len > NJT_QUIC_MAX_UDP_PAYLOAD_SIZE) {
        return NJT_ERROR;
    }

    len = njt_quic_create_frame(src, &frame);
    if (len == -1) {
        return NJT_ERROR;
    }

    njt_memzero(&keys, sizeof(njt_quic_keys_t));

    pkt.keys = &keys;

    if (njt_quic_keys_set_initial_secret(pkt.keys, &inpkt->dcid, c->log)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    pkt.flags = NJT_QUIC_PKT_FIXED_BIT | NJT_QUIC_PKT_LONG
                | NJT_QUIC_PKT_INITIAL;

    pkt.num_len = 1;
    /*
     * pkt.num = 0;
     * pkt.trunc = 0;
     */

    pkt.version = inpkt->version;
    pkt.log = c->log;
    pkt.level = inpkt->level;
    pkt.dcid = inpkt->scid;
    pkt.scid = inpkt->dcid;
    pkt.payload.data = src;
    pkt.payload.len = len;

    res.data = dst;

    njt_quic_log_packet(c->log, &pkt);

    if (njt_quic_encrypt(&pkt, &res) != NJT_OK) {
        njt_quic_keys_cleanup(pkt.keys);
        return NJT_ERROR;
    }

    if (njt_quic_send(c, res.data, res.len, c->sockaddr, c->socklen) < 0) {
        njt_quic_keys_cleanup(pkt.keys);
        return NJT_ERROR;
    }

    njt_quic_keys_cleanup(pkt.keys);

    return NJT_DONE;
}


njt_int_t
njt_quic_send_retry(njt_connection_t *c, njt_quic_conf_t *conf,
    njt_quic_header_t *inpkt)
{
    time_t             expires;
    ssize_t            len;
    njt_str_t          res, token;
    njt_quic_header_t  pkt;

    u_char             buf[NJT_QUIC_RETRY_BUFFER_SIZE];
    u_char             dcid[NJT_QUIC_SERVER_CID_LEN];
    u_char             tbuf[NJT_QUIC_TOKEN_BUF_SIZE];

    expires = njt_time() + NJT_QUIC_RETRY_TOKEN_LIFETIME;

    token.data = tbuf;
    token.len = NJT_QUIC_TOKEN_BUF_SIZE;

    if (njt_quic_new_token(c->log, c->sockaddr, c->socklen, conf->av_token_key,
                           &token, &inpkt->dcid, expires, 1)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    njt_memzero(&pkt, sizeof(njt_quic_header_t));
    pkt.flags = NJT_QUIC_PKT_FIXED_BIT | NJT_QUIC_PKT_LONG | NJT_QUIC_PKT_RETRY;
    pkt.version = inpkt->version;
    pkt.log = c->log;

    pkt.odcid = inpkt->dcid;
    pkt.dcid = inpkt->scid;

    /* TODO: generate routable dcid */
    if (RAND_bytes(dcid, NJT_QUIC_SERVER_CID_LEN) != 1) {
        return NJT_ERROR;
    }

    pkt.scid.len = NJT_QUIC_SERVER_CID_LEN;
    pkt.scid.data = dcid;

    pkt.token = token;

    res.data = buf;

    if (njt_quic_encrypt(&pkt, &res) != NJT_OK) {
        return NJT_ERROR;
    }

#ifdef NJT_QUIC_DEBUG_PACKETS
    njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic packet to send len:%uz %xV", res.len, &res);
#endif

    len = njt_quic_send(c, res.data, res.len, c->sockaddr, c->socklen);
    if (len < 0) {
        return NJT_ERROR;
    }

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic retry packet sent to %xV", &pkt.dcid);

    /*
     * RFC 9000, 17.2.5.1.  Sending a Retry Packet
     *
     * A server MUST NOT send more than one Retry
     * packet in response to a single UDP datagram.
     * NJT_DONE will stop quic_input() from processing further
     */
    return NJT_DONE;
}


njt_int_t
njt_quic_send_new_token(njt_connection_t *c, njt_quic_path_t *path)
{
    time_t                  expires;
    njt_str_t               token;
    njt_chain_t            *out;
    njt_quic_frame_t       *frame;
    njt_quic_connection_t  *qc;

    u_char                  tbuf[NJT_QUIC_TOKEN_BUF_SIZE];

    qc = njt_quic_get_connection(c);

    expires = njt_time() + NJT_QUIC_NEW_TOKEN_LIFETIME;

    token.data = tbuf;
    token.len = NJT_QUIC_TOKEN_BUF_SIZE;

    if (njt_quic_new_token(c->log, path->sockaddr, path->socklen,
                           qc->conf->av_token_key, &token, NULL, expires, 0)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    out = njt_quic_copy_buffer(c, token.data, token.len);
    if (out == NJT_CHAIN_ERROR) {
        return NJT_ERROR;
    }

    frame = njt_quic_alloc_frame(c);
    if (frame == NULL) {
        return NJT_ERROR;
    }

    frame->level = ssl_encryption_application;
    frame->type = NJT_QUIC_FT_NEW_TOKEN;
    frame->data = out;
    frame->u.token.length = token.len;

    njt_quic_queue_frame(qc, frame);

    return NJT_OK;
}


njt_int_t
njt_quic_send_ack(njt_connection_t *c, njt_quic_send_ctx_t *ctx)
{
    size_t                  len, left;
    uint64_t                ack_delay;
    njt_buf_t              *b;
    njt_uint_t              i;
    njt_chain_t            *cl, **ll;
    njt_quic_frame_t       *frame;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    ack_delay = njt_current_msec - ctx->largest_received;
    ack_delay *= 1000;
    ack_delay >>= qc->tp.ack_delay_exponent;

    frame = njt_quic_alloc_frame(c);
    if (frame == NULL) {
        return NJT_ERROR;
    }

    ll = &frame->data;
    b = NULL;

    for (i = 0; i < ctx->nranges; i++) {
        len = njt_quic_create_ack_range(NULL, ctx->ranges[i].gap,
                                        ctx->ranges[i].range);

        left = b ? b->end - b->last : 0;

        if (left < len) {
            cl = njt_quic_alloc_chain(c);
            if (cl == NULL) {
                return NJT_ERROR;
            }

            *ll = cl;
            ll = &cl->next;

            b = cl->buf;
            left = b->end - b->last;

            if (left < len) {
                return NJT_ERROR;
            }
        }

        b->last += njt_quic_create_ack_range(b->last, ctx->ranges[i].gap,
                                             ctx->ranges[i].range);

        frame->u.ack.ranges_length += len;
    }

    *ll = NULL;

    frame->level = ctx->level;
    frame->type = NJT_QUIC_FT_ACK;
    frame->u.ack.largest = ctx->largest_range;
    frame->u.ack.delay = ack_delay;
    frame->u.ack.range_count = ctx->nranges;
    frame->u.ack.first_range = ctx->first_range;
    frame->len = njt_quic_create_frame(NULL, frame);

    njt_queue_insert_head(&ctx->frames, &frame->queue);

    return NJT_OK;
}


njt_int_t
njt_quic_send_ack_range(njt_connection_t *c, njt_quic_send_ctx_t *ctx,
    uint64_t smallest, uint64_t largest)
{
    njt_quic_frame_t       *frame;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    frame = njt_quic_alloc_frame(c);
    if (frame == NULL) {
        return NJT_ERROR;
    }

    frame->level = ctx->level;
    frame->type = NJT_QUIC_FT_ACK;
    frame->u.ack.largest = largest;
    frame->u.ack.delay = 0;
    frame->u.ack.range_count = 0;
    frame->u.ack.first_range = largest - smallest;

    njt_quic_queue_frame(qc, frame);

    return NJT_OK;
}


njt_int_t
njt_quic_frame_sendto(njt_connection_t *c, njt_quic_frame_t *frame,
    size_t min, njt_quic_path_t *path)
{
    size_t                  max, max_payload, min_payload, pad;
    ssize_t                 len, sent;
    njt_str_t               res;
    njt_msec_t              now;
    njt_quic_header_t       pkt;
    njt_quic_send_ctx_t    *ctx;
    njt_quic_congestion_t  *cg;
    njt_quic_connection_t  *qc;

    static u_char           src[NJT_QUIC_MAX_UDP_PAYLOAD_SIZE];
    static u_char           dst[NJT_QUIC_MAX_UDP_PAYLOAD_SIZE];

    qc = njt_quic_get_connection(c);
    cg = &qc->congestion;
    ctx = njt_quic_get_send_ctx(qc, frame->level);

    now = njt_current_msec;

    max = njt_quic_path_limit(c, path, path->mtu);

    njt_log_debug3(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic sendto %s packet max:%uz min:%uz",
                   njt_quic_level_name(ctx->level), max, min);

    if (cg->in_flight >= cg->window && !frame->ignore_congestion) {
        njt_quic_free_frame(c, frame);
        return NJT_AGAIN;
    }

    njt_quic_init_packet(c, ctx, &pkt, path);

    min_payload = njt_quic_payload_size(&pkt, min);
    max_payload = njt_quic_payload_size(&pkt, max);

    /* RFC 9001, 5.4.2.  Header Protection Sample */
    pad = 4 - pkt.num_len;
    min_payload = njt_max(min_payload, pad);

    if (min_payload > max_payload) {
        njt_quic_free_frame(c, frame);
        return NJT_AGAIN;
    }

#if (NJT_DEBUG)
    frame->pnum = pkt.number;
#endif

    njt_quic_log_frame(c->log, frame, 1);

    len = njt_quic_create_frame(NULL, frame);
    if ((size_t) len > max_payload) {
        njt_quic_free_frame(c, frame);
        return NJT_AGAIN;
    }

    len = njt_quic_create_frame(src, frame);
    if (len == -1) {
        njt_quic_free_frame(c, frame);
        return NJT_ERROR;
    }

    if (len < (ssize_t) min_payload) {
        njt_memset(src + len, NJT_QUIC_FT_PADDING, min_payload - len);
        len = min_payload;
    }

    pkt.payload.data = src;
    pkt.payload.len = len;

    res.data = dst;

    njt_quic_log_packet(c->log, &pkt);

    if (njt_quic_encrypt(&pkt, &res) != NJT_OK) {
        njt_quic_free_frame(c, frame);
        return NJT_ERROR;
    }

    frame->pnum = ctx->pnum;
    frame->send_time = now;
    frame->plen = res.len;

    ctx->pnum++;

    sent = njt_quic_send(c, res.data, res.len, path->sockaddr, path->socklen);
    if (sent < 0) {
        njt_quic_free_frame(c, frame);
        return sent;
    }

    path->sent += sent;

    if (frame->need_ack && !qc->closing) {
        njt_queue_insert_tail(&ctx->sent, &frame->queue);

        cg->in_flight += frame->plen;

    } else {
        njt_quic_free_frame(c, frame);
        return NJT_OK;
    }

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic congestion send if:%uz", cg->in_flight);

    if (!qc->send_timer_set) {
        qc->send_timer_set = 1;
        njt_add_timer(c->read, qc->tp.max_idle_timeout);
    }

    njt_quic_set_lost_timer(c);

    return NJT_OK;
}


size_t
njt_quic_path_limit(njt_connection_t *c, njt_quic_path_t *path, size_t size)
{
    off_t  max;

    if (!path->validated) {
        max = path->received * 3;
        max = (path->sent >= max) ? 0 : max - path->sent;

        if ((off_t) size > max) {
            return max;
        }
    }

    return size;
}
