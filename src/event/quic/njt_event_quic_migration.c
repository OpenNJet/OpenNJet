
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>
#include <njt_event_quic_connection.h>


#define NJT_QUIC_PATH_MTU_DELAY       100
#define NJT_QUIC_PATH_MTU_PRECISION   16


static void njt_quic_set_connection_path(njt_connection_t *c,
    njt_quic_path_t *path);
static njt_int_t njt_quic_validate_path(njt_connection_t *c,
    njt_quic_path_t *path);
static njt_int_t njt_quic_send_path_challenge(njt_connection_t *c,
    njt_quic_path_t *path);
static void njt_quic_set_path_timer(njt_connection_t *c);
static njt_int_t njt_quic_expire_path_validation(njt_connection_t *c,
    njt_quic_path_t *path);
static njt_int_t njt_quic_expire_path_mtu_delay(njt_connection_t *c,
    njt_quic_path_t *path);
static njt_int_t njt_quic_expire_path_mtu_discovery(njt_connection_t *c,
    njt_quic_path_t *path);
static njt_quic_path_t *njt_quic_get_path(njt_connection_t *c, njt_uint_t tag);
static njt_int_t njt_quic_send_path_mtu_probe(njt_connection_t *c,
    njt_quic_path_t *path);


njt_int_t
njt_quic_handle_path_challenge_frame(njt_connection_t *c,
    njt_quic_header_t *pkt, njt_quic_path_challenge_frame_t *f)
{
    size_t                  min;
    njt_quic_frame_t       *fp;
    njt_quic_connection_t  *qc;

    if (pkt->level != ssl_encryption_application || pkt->path_challenged) {
        njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "quic ignoring PATH_CHALLENGE");
        return NJT_OK;
    }

    pkt->path_challenged = 1;

    qc = njt_quic_get_connection(c);

    fp = njt_quic_alloc_frame(c);
    if (fp == NULL) {
        return NJT_ERROR;
    }

    fp->level = ssl_encryption_application;
    fp->type = NJT_QUIC_FT_PATH_RESPONSE;
    fp->u.path_response = *f;

    /*
     * RFC 9000, 8.2.2.  Path Validation Responses
     *
     * A PATH_RESPONSE frame MUST be sent on the network path where the
     * PATH_CHALLENGE frame was received.
     */

    /*
     * An endpoint MUST expand datagrams that contain a PATH_RESPONSE frame
     * to at least the smallest allowed maximum datagram size of 1200 bytes.
     * ...
     * However, an endpoint MUST NOT expand the datagram containing the
     * PATH_RESPONSE if the resulting data exceeds the anti-amplification limit.
     */

    min = (njt_quic_path_limit(c, pkt->path, 1200) < 1200) ? 0 : 1200;

    if (njt_quic_frame_sendto(c, fp, min, pkt->path) == NJT_ERROR) {
        return NJT_ERROR;
    }

    if (pkt->path == qc->path) {
        /*
         * RFC 9000, 9.3.3.  Off-Path Packet Forwarding
         *
         * An endpoint that receives a PATH_CHALLENGE on an active path SHOULD
         * send a non-probing packet in response.
         */

        fp = njt_quic_alloc_frame(c);
        if (fp == NULL) {
            return NJT_ERROR;
        }

        fp->level = ssl_encryption_application;
        fp->type = NJT_QUIC_FT_PING;

        njt_quic_queue_frame(qc, fp);
    }

    return NJT_OK;
}


njt_int_t
njt_quic_handle_path_response_frame(njt_connection_t *c,
    njt_quic_path_challenge_frame_t *f)
{
    njt_uint_t              rst;
    njt_queue_t            *q;
    njt_quic_path_t        *path, *prev;
    njt_quic_send_ctx_t    *ctx;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    /*
     * RFC 9000, 8.2.3.  Successful Path Validation
     *
     * A PATH_RESPONSE frame received on any network path validates the path
     * on which the PATH_CHALLENGE was sent.
     */

    for (q = njt_queue_head(&qc->paths);
         q != njt_queue_sentinel(&qc->paths);
         q = njt_queue_next(q))
    {
        path = njt_queue_data(q, njt_quic_path_t, queue);

        if (path->state != NJT_QUIC_PATH_VALIDATING) {
            continue;
        }

        if (njt_memcmp(path->challenge[0], f->data, sizeof(f->data)) == 0
            || njt_memcmp(path->challenge[1], f->data, sizeof(f->data)) == 0)
        {
            goto valid;
        }
    }

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic stale PATH_RESPONSE ignored");

    return NJT_OK;

valid:

    /*
     * RFC 9000, 9.4.  Loss Detection and Congestion Control
     *
     * On confirming a peer's ownership of its new address,
     * an endpoint MUST immediately reset the congestion controller
     * and round-trip time estimator for the new path to initial values
     * unless the only change in the peer's address is its port number.
     */

    rst = 1;

    prev = njt_quic_get_path(c, NJT_QUIC_PATH_BACKUP);

    if (prev != NULL) {

        if (njt_cmp_sockaddr(prev->sockaddr, prev->socklen,
                             path->sockaddr, path->socklen, 0)
            == NJT_OK)
        {
            /* address did not change */
            rst = 0;

            path->mtu = prev->mtu;
            path->max_mtu = prev->max_mtu;
            path->mtu_unvalidated = 0;
        }
    }

    if (rst) {
        /* prevent old path packets contribution to congestion control */

        ctx = njt_quic_get_send_ctx(qc, ssl_encryption_application);
        qc->rst_pnum = ctx->pnum;

        njt_memzero(&qc->congestion, sizeof(njt_quic_congestion_t));

        qc->congestion.window = njt_min(10 * qc->tp.max_udp_payload_size,
                                   njt_max(2 * qc->tp.max_udp_payload_size,
                                           14720));
        qc->congestion.ssthresh = (size_t) -1;
        qc->congestion.recovery_start = njt_current_msec;

        njt_quic_init_rtt(qc);
    }

    path->validated = 1;

    if (path->mtu_unvalidated) {
        path->mtu_unvalidated = 0;
        return njt_quic_validate_path(c, path);
    }

    /*
     * RFC 9000, 9.3.  Responding to Connection Migration
     *
     *  After verifying a new client address, the server SHOULD
     *  send new address validation tokens (Section 8) to the client.
     */

    if (njt_quic_send_new_token(c, path) != NJT_OK) {
        return NJT_ERROR;
    }

    njt_log_error(NJT_LOG_INFO, c->log, 0,
                  "quic path seq:%uL addr:%V successfully validated",
                  path->seqnum, &path->addr_text);

    njt_quic_path_dbg(c, "is validated", path);

    njt_quic_discover_path_mtu(c, path);

    return NJT_OK;
}


njt_quic_path_t *
njt_quic_new_path(njt_connection_t *c,
    struct sockaddr *sockaddr, socklen_t socklen, njt_quic_client_id_t *cid)
{
    njt_queue_t            *q;
    njt_quic_path_t        *path;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    if (!njt_queue_empty(&qc->free_paths)) {

        q = njt_queue_head(&qc->free_paths);
        path = njt_queue_data(q, njt_quic_path_t, queue);

        njt_queue_remove(&path->queue);

        njt_memzero(path, sizeof(njt_quic_path_t));

    } else {

        path = njt_pcalloc(c->pool, sizeof(njt_quic_path_t));
        if (path == NULL) {
            return NULL;
        }
    }

    njt_queue_insert_tail(&qc->paths, &path->queue);

    path->cid = cid;
    cid->used = 1;

    path->seqnum = qc->path_seqnum++;

    path->sockaddr = &path->sa.sockaddr;
    path->socklen = socklen;
    njt_memcpy(path->sockaddr, sockaddr, socklen);

    path->addr_text.data = path->text;
    path->addr_text.len = njt_sock_ntop(sockaddr, socklen, path->text,
                                        NJT_SOCKADDR_STRLEN, 1);

    path->mtu = NJT_QUIC_MIN_INITIAL_SIZE;

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic path seq:%uL created addr:%V",
                   path->seqnum, &path->addr_text);
    return path;
}


static njt_quic_path_t *
njt_quic_get_path(njt_connection_t *c, njt_uint_t tag)
{
    njt_queue_t            *q;
    njt_quic_path_t        *path;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    for (q = njt_queue_head(&qc->paths);
         q != njt_queue_sentinel(&qc->paths);
         q = njt_queue_next(q))
    {
        path = njt_queue_data(q, njt_quic_path_t, queue);

        if (path->tag == tag) {
            return path;
        }
    }

    return NULL;
}


njt_int_t
njt_quic_set_path(njt_connection_t *c, njt_quic_header_t *pkt)
{
    off_t                   len;
    njt_queue_t            *q;
    njt_quic_path_t        *path, *probe;
    njt_quic_socket_t      *qsock;
    njt_quic_send_ctx_t    *ctx;
    njt_quic_client_id_t   *cid;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);
    qsock = njt_quic_get_socket(c);

    len = pkt->raw->last - pkt->raw->start;

    if (c->udp->buffer == NULL) {
        /* first ever packet in connection, path already exists  */
        path = qc->path;
        goto update;
    }

    probe = NULL;

    for (q = njt_queue_head(&qc->paths);
         q != njt_queue_sentinel(&qc->paths);
         q = njt_queue_next(q))
    {
        path = njt_queue_data(q, njt_quic_path_t, queue);

        if (njt_cmp_sockaddr(&qsock->sockaddr.sockaddr, qsock->socklen,
                             path->sockaddr, path->socklen, 1)
            == NJT_OK)
        {
            goto update;
        }

        if (path->tag == NJT_QUIC_PATH_PROBE) {
            probe = path;
        }
    }

    /* packet from new path, drop current probe, if any */

    ctx = njt_quic_get_send_ctx(qc, pkt->level);

    /*
     * only accept highest-numbered packets to prevent connection id
     * exhaustion by excessive probing packets from unknown paths
     */
    if (pkt->pn != ctx->largest_pn) {
        return NJT_DONE;
    }

    if (probe && njt_quic_free_path(c, probe) != NJT_OK) {
        return NJT_ERROR;
    }

    /* new path requires new client id */
    cid = njt_quic_next_client_id(c);
    if (cid == NULL) {
        njt_log_error(NJT_LOG_INFO, c->log, 0,
                      "quic no available client ids for new path");
        /* stop processing of this datagram */
        return NJT_DONE;
    }

    path = njt_quic_new_path(c, &qsock->sockaddr.sockaddr, qsock->socklen, cid);
    if (path == NULL) {
        return NJT_ERROR;
    }

    path->tag = NJT_QUIC_PATH_PROBE;

    /*
     * client arrived using new path and previously seen DCID,
     * this indicates NAT rebinding (or bad client)
     */
    if (qsock->used) {
        pkt->rebound = 1;
    }

update:

    qsock->used = 1;
    pkt->path = path;

    /* TODO: this may be too late in some cases;
     *       for example, if error happens during decrypt(), we cannot
     *       send CC, if error happens in 1st packet, due to amplification
     *       limit, because path->received = 0
     *
     *       should we account garbage as received or only decrypting packets?
     */
    path->received += len;

    njt_log_debug3(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic packet len:%O via sock seq:%L path seq:%uL",
                   len, (int64_t) qsock->sid.seqnum, path->seqnum);
    njt_quic_path_dbg(c, "status", path);

    return NJT_OK;
}


njt_int_t
njt_quic_free_path(njt_connection_t *c, njt_quic_path_t *path)
{
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    njt_queue_remove(&path->queue);
    njt_queue_insert_head(&qc->free_paths, &path->queue);

    /*
     * invalidate CID that is no longer usable for any other path;
     * this also requests new CIDs from client
     */
    if (path->cid) {
        if (njt_quic_free_client_id(c, path->cid) != NJT_OK) {
            return NJT_ERROR;
        }
    }

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic path seq:%uL addr:%V retired",
                   path->seqnum, &path->addr_text);

    return NJT_OK;
}


static void
njt_quic_set_connection_path(njt_connection_t *c, njt_quic_path_t *path)
{
    njt_memcpy(c->sockaddr, path->sockaddr, path->socklen);
    c->socklen = path->socklen;

    if (c->addr_text.data) {
        c->addr_text.len = njt_sock_ntop(c->sockaddr, c->socklen,
                                         c->addr_text.data,
                                         c->listening->addr_text_max_len, 0);
    }

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic send path set to seq:%uL addr:%V",
                   path->seqnum, &path->addr_text);
}


njt_int_t
njt_quic_handle_migration(njt_connection_t *c, njt_quic_header_t *pkt)
{
    njt_quic_path_t        *next, *bkp;
    njt_quic_send_ctx_t    *ctx;
    njt_quic_connection_t  *qc;

    /* got non-probing packet via non-active path */

    qc = njt_quic_get_connection(c);

    ctx = njt_quic_get_send_ctx(qc, pkt->level);

    /*
     * RFC 9000, 9.3.  Responding to Connection Migration
     *
     * An endpoint only changes the address to which it sends packets in
     * response to the highest-numbered non-probing packet.
     */
    if (pkt->pn != ctx->largest_pn) {
        return NJT_OK;
    }

    next = pkt->path;

    /*
     * RFC 9000, 9.3.3:
     *
     * In response to an apparent migration, endpoints MUST validate the
     * previously active path using a PATH_CHALLENGE frame.
     */
    if (pkt->rebound) {

        /* NAT rebinding: client uses new path with old SID */
        if (njt_quic_validate_path(c, qc->path) != NJT_OK) {
            return NJT_ERROR;
        }
    }

    if (qc->path->validated) {

        if (next->tag != NJT_QUIC_PATH_BACKUP) {
            /* can delete backup path, if any */
            bkp = njt_quic_get_path(c, NJT_QUIC_PATH_BACKUP);

            if (bkp && njt_quic_free_path(c, bkp) != NJT_OK) {
                return NJT_ERROR;
            }
        }

        qc->path->tag = NJT_QUIC_PATH_BACKUP;
        njt_quic_path_dbg(c, "is now backup", qc->path);

    } else {
        if (njt_quic_free_path(c, qc->path) != NJT_OK) {
            return NJT_ERROR;
        }
    }

    /* switch active path to migrated */
    qc->path = next;
    qc->path->tag = NJT_QUIC_PATH_ACTIVE;

    njt_quic_set_connection_path(c, next);

    if (!next->validated && next->state != NJT_QUIC_PATH_VALIDATING) {
        if (njt_quic_validate_path(c, next) != NJT_OK) {
            return NJT_ERROR;
        }
    }

    njt_log_error(NJT_LOG_INFO, c->log, 0,
                  "quic migrated to path seq:%uL addr:%V",
                  qc->path->seqnum, &qc->path->addr_text);

    njt_quic_path_dbg(c, "is now active", qc->path);

    return NJT_OK;
}


static njt_int_t
njt_quic_validate_path(njt_connection_t *c, njt_quic_path_t *path)
{
    njt_msec_t              pto;
    njt_quic_send_ctx_t    *ctx;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic initiated validation of path seq:%uL", path->seqnum);

    path->tries = 0;

    if (RAND_bytes((u_char *) path->challenge, sizeof(path->challenge)) != 1) {
        return NJT_ERROR;
    }

    (void) njt_quic_send_path_challenge(c, path);

    ctx = njt_quic_get_send_ctx(qc, ssl_encryption_application);
    pto = njt_max(njt_quic_pto(c, ctx), 1000);

    path->expires = njt_current_msec + pto;
    path->state = NJT_QUIC_PATH_VALIDATING;

    njt_quic_set_path_timer(c);

    return NJT_OK;
}


static njt_int_t
njt_quic_send_path_challenge(njt_connection_t *c, njt_quic_path_t *path)
{
    size_t             min;
    njt_uint_t         n;
    njt_quic_frame_t  *frame;

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic path seq:%uL send path_challenge tries:%ui",
                   path->seqnum, path->tries);

    for (n = 0; n < 2; n++) {

        frame = njt_quic_alloc_frame(c);
        if (frame == NULL) {
            return NJT_ERROR;
        }

        frame->level = ssl_encryption_application;
        frame->type = NJT_QUIC_FT_PATH_CHALLENGE;

        njt_memcpy(frame->u.path_challenge.data, path->challenge[n], 8);
    
        /*
        * RFC 9000, 8.2.1.  Initiating Path Validation
        *
        * An endpoint MUST expand datagrams that contain a PATH_CHALLENGE frame
        * to at least the smallest allowed maximum datagram size of 1200 bytes,
        * unless the anti-amplification limit for the path does not permit
        * sending a datagram of this size.
        */

        if (path->mtu_unvalidated
            || njt_quic_path_limit(c, path, 1200) < 1200)
        {
            min = 0;
            path->mtu_unvalidated = 1;

        } else {
            min = 1200;
        }

        if (njt_quic_frame_sendto(c, frame, min, path) == NJT_ERROR) {
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}

void
njt_quic_discover_path_mtu(njt_connection_t *c, njt_quic_path_t *path)
{
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    if (path->max_mtu) {
        if (path->max_mtu - path->mtu <= NJT_QUIC_PATH_MTU_PRECISION) {
            path->state = NJT_QUIC_PATH_IDLE;
            njt_quic_set_path_timer(c);
            return;
        }

        path->mtud = (path->mtu + path->max_mtu) / 2;

    } else {
        path->mtud = path->mtu * 2;

        if (path->mtud >= qc->ctp.max_udp_payload_size) {
            path->mtud = qc->ctp.max_udp_payload_size;
            path->max_mtu = qc->ctp.max_udp_payload_size;
        }
    }

    path->state = NJT_QUIC_PATH_WAITING;
    path->expires = njt_current_msec + NJT_QUIC_PATH_MTU_DELAY;

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic path seq:%uL schedule mtu:%uz",
                   path->seqnum, path->mtud);

    njt_quic_set_path_timer(c);
}


static void
njt_quic_set_path_timer(njt_connection_t *c)
{
    njt_msec_t              now;
    njt_queue_t            *q;
    njt_msec_int_t          left, next;
    njt_quic_path_t        *path;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    now = njt_current_msec;
    next = -1;

    for (q = njt_queue_head(&qc->paths);
         q != njt_queue_sentinel(&qc->paths);
         q = njt_queue_next(q))
    {
        path = njt_queue_data(q, njt_quic_path_t, queue);

        if (path->state == NJT_QUIC_PATH_IDLE) {
            continue;
        }

        left = path->expires - now;
        left = njt_max(left, 1);

        if (next == -1 || left < next) {
            next = left;
        }
    }

    if (next != -1) {
        njt_add_timer(&qc->path_validation, next);

    } else if (qc->path_validation.timer_set) {
        njt_del_timer(&qc->path_validation);
    }
}


void
njt_quic_path_handler(njt_event_t *ev)
{
    njt_msec_t              now;
    njt_queue_t            *q;
    njt_msec_int_t          left;
    njt_quic_path_t        *path;
    njt_connection_t       *c;
    njt_quic_connection_t  *qc;

    c = ev->data;
    qc = njt_quic_get_connection(c);

    now = njt_current_msec;

    q = njt_queue_head(&qc->paths);

    while (q != njt_queue_sentinel(&qc->paths)) {

        path = njt_queue_data(q, njt_quic_path_t, queue);
        q = njt_queue_next(q);

        if (path->state == NJT_QUIC_PATH_IDLE) {
            continue;
        }

        left = path->expires - now;

        if (left > 0) {
            continue;
        }

        switch (path->state) {
        case NJT_QUIC_PATH_VALIDATING:
            if (njt_quic_expire_path_validation(c, path) != NJT_OK) {
                goto failed;
            }
            break;
        
        case NJT_QUIC_PATH_WAITING:
            if (njt_quic_expire_path_mtu_delay(c, path) != NJT_OK) {
                goto failed;
            }

            break;

        case NJT_QUIC_PATH_MTUD:
            if (njt_quic_expire_path_mtu_discovery(c, path) != NJT_OK) {
                goto failed;
            }
            break;
        
        default:
            break;
        }
    }
    njt_quic_set_path_timer(c);

    return;

failed:

    njt_quic_close_connection(c, NJT_ERROR);
}


static njt_int_t
njt_quic_expire_path_validation(njt_connection_t *c, njt_quic_path_t *path)
{
    njt_msec_int_t          pto;
    njt_quic_path_t        *bkp;
    njt_quic_send_ctx_t    *ctx;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);
    ctx = njt_quic_get_send_ctx(qc, ssl_encryption_application);

    if (++path->tries < NJT_QUIC_PATH_RETRIES) {
        pto = njt_max(njt_quic_pto(c, ctx), 1000) << path->tries;
        path->expires = njt_current_msec + pto;

        (void) njt_quic_send_path_challenge(c, path);

        return NJT_OK;
    }

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic path seq:%uL validation failed", path->seqnum);

    /* found expired path */

    path->validated = 0;


    /* RFC 9000, 9.3.2.  On-Path Address Spoofing
     *
     * To protect the connection from failing due to such a spurious
     * migration, an endpoint MUST revert to using the last validated
     * peer address when validation of a new peer address fails.
     */

    if (qc->path == path) {
        /* active path validation failed */

        bkp = njt_quic_get_path(c, NJT_QUIC_PATH_BACKUP);

        if (bkp == NULL) {
            qc->error = NJT_QUIC_ERR_NO_VIABLE_PATH;
            qc->error_reason = "no viable path";
            return NJT_ERROR;
        }

        qc->path = bkp;
        qc->path->tag = NJT_QUIC_PATH_ACTIVE;

        njt_quic_set_connection_path(c, qc->path);

        njt_log_error(NJT_LOG_INFO, c->log, 0,
                      "quic path seq:%uL addr:%V is restored from backup",
                      qc->path->seqnum, &qc->path->addr_text);

        njt_quic_path_dbg(c, "is active", qc->path);
    }

    return njt_quic_free_path(c, path);
}


static njt_int_t
njt_quic_expire_path_mtu_delay(njt_connection_t *c, njt_quic_path_t *path)
{
    njt_int_t               rc;
    njt_uint_t              i;
    njt_msec_t              pto;
    njt_quic_send_ctx_t    *ctx;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);
    ctx = njt_quic_get_send_ctx(qc, ssl_encryption_application);

    path->tries = 0;

    for ( ;; ) {

        for (i = 0; i < NJT_QUIC_PATH_RETRIES; i++) {
            path->mtu_pnum[i] = NJT_QUIC_UNSET_PN;
        }

        rc = njt_quic_send_path_mtu_probe(c, path);

        if (rc == NJT_ERROR) {
            return NJT_ERROR;
        }

        if (rc == NJT_OK) {
            pto = njt_quic_pto(c, ctx);
            path->expires = njt_current_msec + pto;
            path->state = NJT_QUIC_PATH_MTUD;
            return NJT_OK;
        }

        /* rc == NJT_DECLINED */

        path->max_mtu = path->mtud;

        if (path->max_mtu - path->mtu <= NJT_QUIC_PATH_MTU_PRECISION) {
            path->state = NJT_QUIC_PATH_IDLE;
            return NJT_OK;
        }

        path->mtud = (path->mtu + path->max_mtu) / 2;
    }
}


static njt_int_t
njt_quic_expire_path_mtu_discovery(njt_connection_t *c, njt_quic_path_t *path)
{
    njt_int_t               rc;
    njt_msec_int_t          pto;
    njt_quic_send_ctx_t    *ctx;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);
    ctx = njt_quic_get_send_ctx(qc, ssl_encryption_application);

    if (++path->tries < NJT_QUIC_PATH_RETRIES) {
        rc = njt_quic_send_path_mtu_probe(c, path);

        if (rc == NJT_ERROR) {
            return NJT_ERROR;
        }

        if (rc == NJT_OK) {
            pto = njt_quic_pto(c, ctx) << path->tries;
            path->expires = njt_current_msec + pto;
            return NJT_OK;
        }

        /* rc == NJT_DECLINED */
    }

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic path seq:%uL expired mtu:%uz",
                   path->seqnum, path->mtud);

    path->max_mtu = path->mtud;

    njt_quic_discover_path_mtu(c, path);

    return NJT_OK;
}


static njt_int_t
njt_quic_send_path_mtu_probe(njt_connection_t *c, njt_quic_path_t *path)
{
    size_t                  mtu;
    njt_int_t               rc;
    njt_uint_t              log_error;
    njt_quic_frame_t       *frame;
    njt_quic_send_ctx_t    *ctx;
    njt_quic_connection_t  *qc;

    frame = njt_quic_alloc_frame(c);
    if (frame == NULL) {
        return NJT_ERROR;
    }

    frame->level = ssl_encryption_application;
    frame->type = NJT_QUIC_FT_PING;

    qc = njt_quic_get_connection(c);
    ctx = njt_quic_get_send_ctx(qc, ssl_encryption_application);
    path->mtu_pnum[path->tries] = ctx->pnum;

    njt_log_debug4(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic path seq:%uL send probe "
                   "mtu:%uz pnum:%uL tries:%ui",
                   path->seqnum, path->mtud, ctx->pnum, path->tries);

    log_error = c->log_error;
    c->log_error = NJT_ERROR_IGNORE_EMSGSIZE;

    mtu = path->mtu;
    path->mtu = path->mtud;

    rc = njt_quic_frame_sendto(c, frame, path->mtud, path);

    path->mtu = mtu;
    c->log_error = log_error;

    if (rc == NJT_ERROR) {
        if (c->write->error) {
            c->write->error = 0;

            njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                           "quic path seq:%uL rejected mtu:%uz",
                           path->seqnum, path->mtud);

            return NJT_DECLINED;
        }

        return NJT_ERROR;
    }

    return NJT_OK;
}


njt_int_t
njt_quic_handle_path_mtu(njt_connection_t *c, njt_quic_path_t *path,
    uint64_t min, uint64_t max)
{
    uint64_t    pnum;
    njt_uint_t  i;

    if (path->state != NJT_QUIC_PATH_MTUD) {
        return NJT_OK;
    }

    for (i = 0; i < NJT_QUIC_PATH_RETRIES; i++) {
        pnum = path->mtu_pnum[i];

        if (pnum == NJT_QUIC_UNSET_PN) {
            break;
        }

        if (pnum < min || pnum > max) {
            continue;
        }

        path->mtu = path->mtud;

        njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "quic path seq:%uL ack mtu:%uz",
                       path->seqnum, path->mtu);

        njt_quic_discover_path_mtu(c, path);

        break;
    }

    return NJT_OK;
}
