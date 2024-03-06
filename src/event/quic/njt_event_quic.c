
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>
#include <njt_event_quic_connection.h>


static njt_quic_connection_t *njt_quic_new_connection(njt_connection_t *c,
    njt_quic_conf_t *conf, njt_quic_header_t *pkt);
static njt_int_t njt_quic_handle_stateless_reset(njt_connection_t *c,
    njt_quic_header_t *pkt);
static void njt_quic_input_handler(njt_event_t *rev);
static void njt_quic_close_handler(njt_event_t *ev);

static njt_int_t njt_quic_handle_datagram(njt_connection_t *c, njt_buf_t *b,
    njt_quic_conf_t *conf);
static njt_int_t njt_quic_handle_packet(njt_connection_t *c,
    njt_quic_conf_t *conf, njt_quic_header_t *pkt);
static njt_int_t njt_quic_handle_payload(njt_connection_t *c,
    njt_quic_header_t *pkt);
static njt_int_t njt_quic_check_csid(njt_quic_connection_t *qc,
    njt_quic_header_t *pkt);
static njt_int_t njt_quic_handle_frames(njt_connection_t *c,
    njt_quic_header_t *pkt);

static void njt_quic_push_handler(njt_event_t *ev);


static njt_core_module_t  njt_quic_module_ctx = {
    njt_string("quic"),
    NULL,
    NULL
};


njt_module_t  njt_quic_module = {
    NJT_MODULE_V1,
    &njt_quic_module_ctx,                  /* module context */
    NULL,                                  /* module directives */
    NJT_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};


#if (NJT_DEBUG)

void
njt_quic_connstate_dbg(njt_connection_t *c)
{
    u_char                 *p, *last;
    njt_quic_connection_t  *qc;
    u_char                  buf[NJT_MAX_ERROR_STR];

    p = buf;
    last = p + sizeof(buf);

    qc = njt_quic_get_connection(c);

    p = njt_slprintf(p, last, "state:");

    if (qc) {

        if (qc->error != (njt_uint_t) -1) {
            p = njt_slprintf(p, last, "%s", qc->error_app ? " app" : "");
            p = njt_slprintf(p, last, " error:%ui", qc->error);

            if (qc->error_reason) {
                p = njt_slprintf(p, last, " \"%s\"", qc->error_reason);
            }
        }

        p = njt_slprintf(p, last, "%s", qc->shutdown ? " shutdown" : "");
        p = njt_slprintf(p, last, "%s", qc->closing ? " closing" : "");
        p = njt_slprintf(p, last, "%s", qc->draining ? " draining" : "");
        p = njt_slprintf(p, last, "%s", qc->key_phase ? " kp" : "");

    } else {
        p = njt_slprintf(p, last, " early");
    }

    if (c->read->timer_set) {
        p = njt_slprintf(p, last,
                         qc && qc->send_timer_set ? " send:%M" : " read:%M",
                         c->read->timer.key - njt_current_msec);
    }

    if (qc) {

        if (qc->push.timer_set) {
            p = njt_slprintf(p, last, " push:%M",
                             qc->push.timer.key - njt_current_msec);
        }

        if (qc->pto.timer_set) {
            p = njt_slprintf(p, last, " pto:%M",
                             qc->pto.timer.key - njt_current_msec);
        }

        if (qc->close.timer_set) {
            p = njt_slprintf(p, last, " close:%M",
                             qc->close.timer.key - njt_current_msec);
        }
    }

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic %*s", p - buf, buf);
}

#endif


njt_int_t
njt_quic_apply_transport_params(njt_connection_t *c, njt_quic_tp_t *ctp)
{
    njt_str_t               scid;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    scid.data = qc->path->cid->id;
    scid.len = qc->path->cid->len;

    if (scid.len != ctp->initial_scid.len
        || njt_memcmp(scid.data, ctp->initial_scid.data, scid.len) != 0)
    {
        njt_log_error(NJT_LOG_INFO, c->log, 0,
                      "quic client initial_source_connection_id mismatch");
        return NJT_ERROR;
    }

    if (ctp->max_udp_payload_size < NJT_QUIC_MIN_INITIAL_SIZE
        || ctp->max_udp_payload_size > NJT_QUIC_MAX_UDP_PAYLOAD_SIZE)
    {
        qc->error = NJT_QUIC_ERR_TRANSPORT_PARAMETER_ERROR;
        qc->error_reason = "invalid maximum packet size";

        njt_log_error(NJT_LOG_INFO, c->log, 0,
                      "quic maximum packet size is invalid");
        return NJT_ERROR;
    }

    if (ctp->active_connection_id_limit < 2) {
        qc->error = NJT_QUIC_ERR_TRANSPORT_PARAMETER_ERROR;
        qc->error_reason = "invalid active_connection_id_limit";

        njt_log_error(NJT_LOG_INFO, c->log, 0,
                      "quic active_connection_id_limit is invalid");
        return NJT_ERROR;
    }

    if (ctp->ack_delay_exponent > 20) {
        qc->error = NJT_QUIC_ERR_TRANSPORT_PARAMETER_ERROR;
        qc->error_reason = "invalid ack_delay_exponent";

        njt_log_error(NJT_LOG_INFO, c->log, 0,
                      "quic ack_delay_exponent is invalid");
        return NJT_ERROR;
    }

    if (ctp->max_ack_delay >= 16384) {
        qc->error = NJT_QUIC_ERR_TRANSPORT_PARAMETER_ERROR;
        qc->error_reason = "invalid max_ack_delay";

        njt_log_error(NJT_LOG_INFO, c->log, 0,
                      "quic max_ack_delay is invalid");
        return NJT_ERROR;
    }

    if (ctp->max_idle_timeout > 0
        && ctp->max_idle_timeout < qc->tp.max_idle_timeout)
    {
        qc->tp.max_idle_timeout = ctp->max_idle_timeout;
    }

    qc->streams.server_max_streams_bidi = ctp->initial_max_streams_bidi;
    qc->streams.server_max_streams_uni = ctp->initial_max_streams_uni;

    njt_memcpy(&qc->ctp, ctp, sizeof(njt_quic_tp_t));

    return NJT_OK;
}


void
njt_quic_run(njt_connection_t *c, njt_quic_conf_t *conf)
{
    njt_int_t               rc;
    njt_quic_connection_t  *qc;

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0, "quic run");

    rc = njt_quic_handle_datagram(c, c->buffer, conf);
    if (rc != NJT_OK) {
        njt_quic_close_connection(c, rc);
        return;
    }

    /* quic connection is now created */
    qc = njt_quic_get_connection(c);

    njt_add_timer(c->read, qc->tp.max_idle_timeout);
    njt_add_timer(&qc->close, qc->conf->handshake_timeout);

    njt_quic_connstate_dbg(c);

    c->read->handler = njt_quic_input_handler;

    return;
}


static njt_quic_connection_t *
njt_quic_new_connection(njt_connection_t *c, njt_quic_conf_t *conf,
    njt_quic_header_t *pkt)
{
    njt_uint_t              i;
    njt_quic_tp_t          *ctp;
    njt_quic_connection_t  *qc;

    qc = njt_pcalloc(c->pool, sizeof(njt_quic_connection_t));
    if (qc == NULL) {
        return NULL;
    }

    qc->keys = njt_pcalloc(c->pool, sizeof(njt_quic_keys_t));
    if (qc->keys == NULL) {
        return NULL;
    }

    qc->version = pkt->version;

    njt_rbtree_init(&qc->streams.tree, &qc->streams.sentinel,
                    njt_quic_rbtree_insert_stream);

    for (i = 0; i < NJT_QUIC_SEND_CTX_LAST; i++) {
        njt_queue_init(&qc->send_ctx[i].frames);
        njt_queue_init(&qc->send_ctx[i].sending);
        njt_queue_init(&qc->send_ctx[i].sent);
        qc->send_ctx[i].largest_pn = NJT_QUIC_UNSET_PN;
        qc->send_ctx[i].largest_ack = NJT_QUIC_UNSET_PN;
        qc->send_ctx[i].largest_range = NJT_QUIC_UNSET_PN;
        qc->send_ctx[i].pending_ack = NJT_QUIC_UNSET_PN;
    }

    qc->send_ctx[0].level = ssl_encryption_initial;
    qc->send_ctx[1].level = ssl_encryption_handshake;
    qc->send_ctx[2].level = ssl_encryption_application;

    njt_queue_init(&qc->free_frames);

    njt_quic_init_rtt(qc);

    qc->pto.log = c->log;
    qc->pto.data = c;
    qc->pto.handler = njt_quic_pto_handler;

    qc->push.log = c->log;
    qc->push.data = c;
    qc->push.handler = njt_quic_push_handler;

    qc->close.log = c->log;
    qc->close.data = c;
    qc->close.handler = njt_quic_close_handler;

    qc->path_validation.log = c->log;
    qc->path_validation.data = c;
    qc->path_validation.handler = njt_quic_path_handler;

    qc->key_update.log = c->log;
    qc->key_update.data = c;
    qc->key_update.handler = njt_quic_keys_update;

    qc->conf = conf;

    if (njt_quic_init_transport_params(&qc->tp, conf) != NJT_OK) {
        return NULL;
    }

    ctp = &qc->ctp;

    /* defaults to be used before actual client parameters are received */
    ctp->max_udp_payload_size = NJT_QUIC_MAX_UDP_PAYLOAD_SIZE;
    ctp->ack_delay_exponent = NJT_QUIC_DEFAULT_ACK_DELAY_EXPONENT;
    ctp->max_ack_delay = NJT_QUIC_DEFAULT_MAX_ACK_DELAY;
    ctp->active_connection_id_limit = 2;

    njt_queue_init(&qc->streams.uninitialized);
    njt_queue_init(&qc->streams.free);

    qc->streams.recv_max_data = qc->tp.initial_max_data;
    qc->streams.recv_window = qc->streams.recv_max_data;

    qc->streams.client_max_streams_uni = qc->tp.initial_max_streams_uni;
    qc->streams.client_max_streams_bidi = qc->tp.initial_max_streams_bidi;

    qc->congestion.window = njt_min(10 * qc->tp.max_udp_payload_size,
                                    njt_max(2 * qc->tp.max_udp_payload_size,
                                            14720));
    qc->congestion.ssthresh = (size_t) -1;
    qc->congestion.recovery_start = njt_current_msec;

    if (pkt->validated && pkt->retried) {
        qc->tp.retry_scid.len = pkt->dcid.len;
        qc->tp.retry_scid.data = njt_pstrdup(c->pool, &pkt->dcid);
        if (qc->tp.retry_scid.data == NULL) {
            return NULL;
        }
    }

    if (njt_quic_keys_set_initial_secret(qc->keys, &pkt->dcid, c->log)
        != NJT_OK)
    {
        return NULL;
    }

    qc->validated = pkt->validated;

    if (njt_quic_open_sockets(c, qc, pkt) != NJT_OK) {
        njt_quic_keys_cleanup(qc->keys);
        return NULL;
    }

    c->idle = 1;
    njt_reusable_connection(c, 1);

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic connection created");

    return qc;
}


static njt_int_t
njt_quic_handle_stateless_reset(njt_connection_t *c, njt_quic_header_t *pkt)
{
    u_char                 *tail, ch;
    njt_uint_t              i;
    njt_queue_t            *q;
    njt_quic_client_id_t   *cid;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    /* A stateless reset uses an entire UDP datagram */
    if (!pkt->first) {
        return NJT_DECLINED;
    }

    tail = pkt->raw->last - NJT_QUIC_SR_TOKEN_LEN;

    for (q = njt_queue_head(&qc->client_ids);
         q != njt_queue_sentinel(&qc->client_ids);
         q = njt_queue_next(q))
    {
        cid = njt_queue_data(q, njt_quic_client_id_t, queue);

        if (cid->seqnum == 0 || !cid->used) {
            /*
             * No stateless reset token in initial connection id.
             * Don't accept a token from an unused connection id.
             */
            continue;
        }

        /* constant time comparison */

        for (ch = 0, i = 0; i < NJT_QUIC_SR_TOKEN_LEN; i++) {
            ch |= tail[i] ^ cid->sr_token[i];
        }

        if (ch == 0) {
            return NJT_OK;
        }
    }

    return NJT_DECLINED;
}


static void
njt_quic_input_handler(njt_event_t *rev)
{
    njt_int_t               rc;
    njt_buf_t              *b;
    njt_connection_t       *c;
    njt_quic_connection_t  *qc;

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, rev->log, 0, "quic input handler");

    c = rev->data;
    qc = njt_quic_get_connection(c);

    c->log->action = "handling quic input";

    if (rev->timedout) {
        njt_log_error(NJT_LOG_INFO, c->log, NJT_ETIMEDOUT,
                      "quic client timed out");
        njt_quic_close_connection(c, NJT_DONE);
        return;
    }

    if (c->close) {
        c->close = 0;

        if (!njt_exiting || !qc->streams.initialized) {
            qc->error = NJT_QUIC_ERR_NO_ERROR;
            qc->error_reason = "graceful shutdown";
            njt_quic_close_connection(c, NJT_ERROR);
            return;
        }

        if (!qc->closing && qc->conf->shutdown) {
            qc->conf->shutdown(c);
        }

        return;
    }

    b = c->udp->buffer;
    if (b == NULL) {
        return;
    }

    rc = njt_quic_handle_datagram(c, b, NULL);

    if (rc == NJT_ERROR) {
        njt_quic_close_connection(c, NJT_ERROR);
        return;
    }

    if (rc == NJT_DONE) {
        return;
    }

    /* rc == NJT_OK */

    qc->send_timer_set = 0;
    njt_add_timer(rev, qc->tp.max_idle_timeout);

    njt_quic_connstate_dbg(c);
}


void
njt_quic_close_connection(njt_connection_t *c, njt_int_t rc)
{
    njt_uint_t              i;
    njt_pool_t             *pool;
    njt_quic_send_ctx_t    *ctx;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    if (qc == NULL) {
        njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "quic packet rejected rc:%i, cleanup connection", rc);
        goto quic_done;
    }

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic close %s rc:%i",
                   qc->closing ? "resumed": "initiated", rc);

    if (!qc->closing) {

        /* drop packets from retransmit queues, no ack is expected */
        for (i = 0; i < NJT_QUIC_SEND_CTX_LAST; i++) {
            njt_quic_free_frames(c, &qc->send_ctx[i].frames);
            njt_quic_free_frames(c, &qc->send_ctx[i].sent);
        }

        if (qc->close.timer_set) {
            njt_del_timer(&qc->close);
        }

        if (rc == NJT_DONE) {

            /*
             * RFC 9000, 10.1.  Idle Timeout
             *
             *  If a max_idle_timeout is specified by either endpoint in its
             *  transport parameters (Section 18.2), the connection is silently
             *  closed and its state is discarded when it remains idle
             */

            /* this case also handles some errors from njt_quic_run() */

            njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                           "quic close silent drain:%d timedout:%d",
                           qc->draining, c->read->timedout);
        } else {

            /*
             * RFC 9000, 10.2.  Immediate Close
             *
             *  An endpoint sends a CONNECTION_CLOSE frame (Section 19.19)
             *  to terminate the connection immediately.
             */

            if (qc->error == (njt_uint_t) -1) {
                qc->error = NJT_QUIC_ERR_INTERNAL_ERROR;
                qc->error_app = 0;
            }

            njt_log_debug5(NJT_LOG_DEBUG_EVENT, c->log, 0,
                           "quic close immediate term:%d drain:%d "
                           "%serror:%ui \"%s\"",
                           rc == NJT_ERROR ? 1 : 0, qc->draining,
                           qc->error_app ? "app " : "", qc->error,
                           qc->error_reason ? qc->error_reason : "");

            for (i = 0; i < NJT_QUIC_SEND_CTX_LAST; i++) {
                ctx = &qc->send_ctx[i];

                if (!njt_quic_keys_available(qc->keys, ctx->level, 1)) {
                    continue;
                }

                qc->error_level = ctx->level;
                (void) njt_quic_send_cc(c);

                if (rc == NJT_OK) {
                    njt_add_timer(&qc->close, 3 * njt_quic_pto(c, ctx));
                }
            }
        }

        qc->closing = 1;
    }

    if (rc == NJT_ERROR && qc->close.timer_set) {
        /* do not wait for timer in case of fatal error */
        njt_del_timer(&qc->close);
    }

    if (njt_quic_close_streams(c, qc) == NJT_AGAIN) {
        return;
    }

    if (qc->push.timer_set) {
        njt_del_timer(&qc->push);
    }

    if (qc->pto.timer_set) {
        njt_del_timer(&qc->pto);
    }

    if (qc->path_validation.timer_set) {
        njt_del_timer(&qc->path_validation);
    }

    if (qc->push.posted) {
        njt_delete_posted_event(&qc->push);
    }

    if (qc->key_update.posted) {
        njt_delete_posted_event(&qc->key_update);
    }

    if (qc->close.timer_set) {
        return;
    }

    if (qc->close.posted) {
        njt_delete_posted_event(&qc->close);
    }

    njt_quic_close_sockets(c);

    njt_quic_keys_cleanup(qc->keys);

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0, "quic close completed");

    /* may be tested from SSL callback during SSL shutdown */
    c->udp = NULL;

quic_done:

    if (c->ssl) {
        (void) njt_ssl_shutdown(c);
    }

    if (c->read->timer_set) {
        njt_del_timer(c->read);
    }

#if (NJT_STAT_STUB)
    (void) njt_atomic_fetch_add(njt_stat_active, -1);
#endif

    c->destroyed = 1;

    pool = c->pool;

    njt_close_connection(c);

    njt_destroy_pool(pool);
}


void
njt_quic_finalize_connection(njt_connection_t *c, njt_uint_t err,
    const char *reason)
{
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    if (qc->closing) {
        return;
    }

    qc->error = err;
    qc->error_reason = reason;
    qc->error_app = 1;
    qc->error_ftype = 0;

    njt_post_event(&qc->close, &njt_posted_events);
}


void
njt_quic_shutdown_connection(njt_connection_t *c, njt_uint_t err,
    const char *reason)
{
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);
    qc->shutdown = 1;
    qc->shutdown_code = err;
    qc->shutdown_reason = reason;

    njt_quic_shutdown_quic(c);
}


static void
njt_quic_close_handler(njt_event_t *ev)
{
    njt_connection_t  *c;

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, ev->log, 0, "quic close handler");

    c = ev->data;

    njt_quic_close_connection(c, NJT_OK);
}


static njt_int_t
njt_quic_handle_datagram(njt_connection_t *c, njt_buf_t *b,
    njt_quic_conf_t *conf)
{
    size_t                  size;
    u_char                 *p, *start;
    njt_int_t               rc;
    njt_uint_t              good;
    njt_quic_path_t        *path;
    njt_quic_header_t       pkt;
    njt_quic_connection_t  *qc;

    good = 0;
    path = NULL;

    size = b->last - b->pos;

    p = start = b->pos;

    while (p < b->last) {

        njt_memzero(&pkt, sizeof(njt_quic_header_t));
        pkt.raw = b;
        pkt.data = p;
        pkt.len = b->last - p;
        pkt.log = c->log;
        pkt.first = (p == start) ? 1 : 0;
        pkt.path = path;
        pkt.flags = p[0];
        pkt.raw->pos++;

        rc = njt_quic_handle_packet(c, conf, &pkt);

#if (NJT_DEBUG)
        if (pkt.parsed) {
            njt_log_debug5(NJT_LOG_DEBUG_EVENT, c->log, 0,
                           "quic packet done rc:%i level:%s"
                           " decr:%d pn:%L perr:%ui",
                           rc, njt_quic_level_name(pkt.level),
                           pkt.decrypted, pkt.pn, pkt.error);
        } else {
            njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                           "quic packet done rc:%i parse failed", rc);
        }
#endif

        if (rc == NJT_ERROR || rc == NJT_DONE) {
            return rc;
        }

        if (rc == NJT_OK) {
            good = 1;
        }

        path = pkt.path; /* preserve packet path from 1st packet */

        /* NJT_OK || NJT_DECLINED */

        /*
         * we get NJT_DECLINED when there are no keys [yet] available
         * to decrypt packet.
         * Instead of queueing it, we ignore it and rely on the sender's
         * retransmission:
         *
         * RFC 9000, 12.2.  Coalescing Packets
         *
         * For example, if decryption fails (because the keys are
         * not available or for any other reason), the receiver MAY either
         * discard or buffer the packet for later processing and MUST
         * attempt to process the remaining packets.
         *
         * We also skip packets that don't match connection state
         * or cannot be parsed properly.
         */

        /* b->pos is at header end, adjust by actual packet length */
        b->pos = pkt.data + pkt.len;

        p = b->pos;
    }

    if (!good) {
        return NJT_DONE;
    }

    qc = njt_quic_get_connection(c);

    if (qc) {
        qc->received += size;

        if ((uint64_t) (c->sent + qc->received) / 8 >
            (qc->streams.sent + qc->streams.recv_last) + 1048576)
        {
            njt_log_error(NJT_LOG_INFO, c->log, 0, "quic flood detected");

            qc->error = NJT_QUIC_ERR_NO_ERROR;
            qc->error_reason = "QUIC flood detected";
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}


static njt_int_t
njt_quic_handle_packet(njt_connection_t *c, njt_quic_conf_t *conf,
    njt_quic_header_t *pkt)
{
    njt_int_t               rc;
    njt_quic_socket_t      *qsock;
    njt_quic_connection_t  *qc;

    c->log->action = "parsing quic packet";

    rc = njt_quic_parse_packet(pkt);

    if (rc == NJT_ERROR) {
        return NJT_DECLINED;
    }

    pkt->parsed = 1;

    c->log->action = "handling quic packet";

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic packet rx dcid len:%uz %xV",
                   pkt->dcid.len, &pkt->dcid);

#if (NJT_DEBUG)
    if (pkt->level != ssl_encryption_application) {
        njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "quic packet rx scid len:%uz %xV",
                       pkt->scid.len, &pkt->scid);
    }

    if (pkt->level == ssl_encryption_initial) {
        njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "quic address validation token len:%uz %xV",
                       pkt->token.len, &pkt->token);
    }
#endif

    qc = njt_quic_get_connection(c);

    if (qc) {

        if (rc == NJT_ABORT) {
            njt_log_error(NJT_LOG_INFO, c->log, 0,
                          "quic unsupported version: 0x%xD", pkt->version);
            return NJT_DECLINED;
        }

        if (pkt->level != ssl_encryption_application) {

            if (pkt->version != qc->version) {
                njt_log_error(NJT_LOG_INFO, c->log, 0,
                              "quic version mismatch: 0x%xD", pkt->version);
                return NJT_DECLINED;
            }

            if (pkt->first) {
                qsock = njt_quic_get_socket(c);

                if (njt_cmp_sockaddr(&qsock->sockaddr.sockaddr, qsock->socklen,
                                     qc->path->sockaddr, qc->path->socklen, 1)
                    != NJT_OK)
                {
                    /* packet comes from unknown path, possibly migration */
                    njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0,
                                   "quic too early migration attempt");
                    return NJT_DONE;
                }
            }

            if (njt_quic_check_csid(qc, pkt) != NJT_OK) {
                return NJT_DECLINED;
            }

        }

        rc = njt_quic_handle_payload(c, pkt);

        if (rc == NJT_DECLINED && pkt->level == ssl_encryption_application) {
            if (njt_quic_handle_stateless_reset(c, pkt) == NJT_OK) {
                njt_log_error(NJT_LOG_INFO, c->log, 0,
                              "quic stateless reset packet detected");

                qc->draining = 1;
                njt_post_event(&qc->close, &njt_posted_events);

                return NJT_OK;
            }
        }

        return rc;
    }

    /* packet does not belong to a connection */

    if (rc == NJT_ABORT) {
        return njt_quic_negotiate_version(c, pkt);
    }

    if (pkt->level == ssl_encryption_application) {
        return njt_quic_send_stateless_reset(c, conf, pkt);
    }

    if (pkt->level != ssl_encryption_initial) {
        njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "quic expected initial, got handshake");
        return NJT_ERROR;
    }

    c->log->action = "handling initial packet";

    if (pkt->dcid.len < NJT_QUIC_CID_LEN_MIN) {
        /* RFC 9000, 7.2.  Negotiating Connection IDs */
        njt_log_error(NJT_LOG_INFO, c->log, 0,
                      "quic too short dcid in initial"
                      " packet: len:%i", pkt->dcid.len);
        return NJT_ERROR;
    }

    /* process retry and initialize connection IDs */

    if (pkt->token.len) {

        rc = njt_quic_validate_token(c, conf->av_token_key, pkt);

        if (rc == NJT_ERROR) {
            /* internal error */
            return NJT_ERROR;

        } else if (rc == NJT_ABORT) {
            /* token cannot be decrypted */
            return njt_quic_send_early_cc(c, pkt,
                                          NJT_QUIC_ERR_INVALID_TOKEN,
                                          "cannot decrypt token");
        } else if (rc == NJT_DECLINED) {
            /* token is invalid */

            if (pkt->retried) {
                /* invalid address validation token */
                return njt_quic_send_early_cc(c, pkt,
                                          NJT_QUIC_ERR_INVALID_TOKEN,
                                          "invalid address validation token");
            } else if (conf->retry) {
                /* invalid NEW_TOKEN */
                return njt_quic_send_retry(c, conf, pkt);
            }
        }

        /* NJT_OK */

    } else if (conf->retry) {
        return njt_quic_send_retry(c, conf, pkt);

    } else {
        pkt->odcid = pkt->dcid;
    }

    if (njt_terminate || njt_exiting) {
        if (conf->retry) {
            return njt_quic_send_retry(c, conf, pkt);
        }

        return NJT_ERROR;
    }

    c->log->action = "creating quic connection";

    qc = njt_quic_new_connection(c, conf, pkt);
    if (qc == NULL) {
        return NJT_ERROR;
    }

    return njt_quic_handle_payload(c, pkt);
}


static njt_int_t
njt_quic_handle_payload(njt_connection_t *c, njt_quic_header_t *pkt)
{
    njt_int_t               rc;
    njt_quic_send_ctx_t    *ctx;
    njt_quic_connection_t  *qc;
    static u_char           buf[NJT_QUIC_MAX_UDP_PAYLOAD_SIZE];

    qc = njt_quic_get_connection(c);

    qc->error = (njt_uint_t) -1;
    qc->error_reason = 0;

    c->log->action = "decrypting packet";

    if (!njt_quic_keys_available(qc->keys, pkt->level, 0)) {
        njt_log_error(NJT_LOG_INFO, c->log, 0,
                      "quic no %s keys, ignoring packet",
                      njt_quic_level_name(pkt->level));
        return NJT_DECLINED;
    }

#if !defined (OPENSSL_IS_BORINGSSL)
    /* OpenSSL provides read keys for an application level before it's ready */

    if (pkt->level == ssl_encryption_application && !c->ssl->handshaked) {
        njt_log_error(NJT_LOG_INFO, c->log, 0,
                      "quic no %s keys ready, ignoring packet",
                      njt_quic_level_name(pkt->level));
        return NJT_DECLINED;
    }
#endif

    pkt->keys = qc->keys;
    pkt->key_phase = qc->key_phase;
    pkt->plaintext = buf;

    ctx = njt_quic_get_send_ctx(qc, pkt->level);

    rc = njt_quic_decrypt(pkt, &ctx->largest_pn);
    if (rc != NJT_OK) {
        qc->error = pkt->error;
        qc->error_reason = "failed to decrypt packet";
        return rc;
    }

    pkt->decrypted = 1;

    c->log->action = "handling decrypted packet";

    if (pkt->path == NULL) {
        rc = njt_quic_set_path(c, pkt);
        if (rc != NJT_OK) {
            return rc;
        }
    }

    if (c->ssl == NULL) {
        if (njt_quic_init_connection(c) != NJT_OK) {
            return NJT_ERROR;
        }
    }

    if (pkt->level == ssl_encryption_handshake) {
        /*
         * RFC 9001, 4.9.1.  Discarding Initial Keys
         *
         * The successful use of Handshake packets indicates
         * that no more Initial packets need to be exchanged
         */
        njt_quic_discard_ctx(c, ssl_encryption_initial);

        if (!qc->path->validated) {
            qc->path->validated = 1;
            njt_quic_path_dbg(c, "in handshake", qc->path);
            njt_post_event(&qc->push, &njt_posted_events);
        }
    }

    if (qc->closing) {
        /*
         * RFC 9000, 10.2.  Immediate Close
         *
         * ... delayed or reordered packets are properly discarded.
         *
         *  In the closing state, an endpoint retains only enough information
         *  to generate a packet containing a CONNECTION_CLOSE frame and to
         *  identify packets as belonging to the connection.
         */

        qc->error_level = pkt->level;
        qc->error = NJT_QUIC_ERR_NO_ERROR;
        qc->error_reason = "connection is closing, packet discarded";
        qc->error_ftype = 0;
        qc->error_app = 0;

        return njt_quic_send_cc(c);
    }

    pkt->received = njt_current_msec;

    c->log->action = "handling payload";

    if (pkt->level != ssl_encryption_application) {
        return njt_quic_handle_frames(c, pkt);
    }

    if (!pkt->key_update) {
        return njt_quic_handle_frames(c, pkt);
    }

    /* switch keys and generate next on Key Phase change */

    qc->key_phase ^= 1;
    njt_quic_keys_switch(c, qc->keys);

    rc = njt_quic_handle_frames(c, pkt);
    if (rc != NJT_OK) {
        return rc;
    }

    njt_post_event(&qc->key_update, &njt_posted_events);

    return NJT_OK;
}


void
njt_quic_discard_ctx(njt_connection_t *c, enum ssl_encryption_level_t level)
{
    njt_queue_t            *q;
    njt_quic_frame_t       *f;
    njt_quic_socket_t      *qsock;
    njt_quic_send_ctx_t    *ctx;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    if (!njt_quic_keys_available(qc->keys, level, 0)
        && !njt_quic_keys_available(qc->keys, level, 1))
    {
        return;
    }

    njt_quic_keys_discard(qc->keys, level);

    qc->pto_count = 0;

    ctx = njt_quic_get_send_ctx(qc, level);

    njt_quic_free_buffer(c, &ctx->crypto);

    while (!njt_queue_empty(&ctx->sent)) {
        q = njt_queue_head(&ctx->sent);
        njt_queue_remove(q);

        f = njt_queue_data(q, njt_quic_frame_t, queue);
        njt_quic_congestion_ack(c, f);
        njt_quic_free_frame(c, f);
    }

    while (!njt_queue_empty(&ctx->frames)) {
        q = njt_queue_head(&ctx->frames);
        njt_queue_remove(q);

        f = njt_queue_data(q, njt_quic_frame_t, queue);
        njt_quic_free_frame(c, f);
    }

    if (level == ssl_encryption_initial) {
        /* close temporary listener with initial dcid */
        qsock = njt_quic_find_socket(c, NJT_QUIC_UNSET_PN);
        if (qsock) {
            njt_quic_close_socket(c, qsock);
        }
    }

    ctx->send_ack = 0;

    njt_quic_set_lost_timer(c);
}


static njt_int_t
njt_quic_check_csid(njt_quic_connection_t *qc, njt_quic_header_t *pkt)
{
    njt_queue_t           *q;
    njt_quic_client_id_t  *cid;

    for (q = njt_queue_head(&qc->client_ids);
         q != njt_queue_sentinel(&qc->client_ids);
         q = njt_queue_next(q))
    {
        cid = njt_queue_data(q, njt_quic_client_id_t, queue);

        if (pkt->scid.len == cid->len
            && njt_memcmp(pkt->scid.data, cid->id, cid->len) == 0)
        {
            return NJT_OK;
        }
    }

    njt_log_error(NJT_LOG_INFO, pkt->log, 0, "quic unexpected quic scid");
    return NJT_ERROR;
}


static njt_int_t
njt_quic_handle_frames(njt_connection_t *c, njt_quic_header_t *pkt)
{
    u_char                 *end, *p;
    ssize_t                 len;
    njt_buf_t               buf;
    njt_uint_t              do_close, nonprobing;
    njt_chain_t             chain;
    njt_quic_frame_t        frame;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    p = pkt->payload.data;
    end = p + pkt->payload.len;

    do_close = 0;
    nonprobing = 0;

    while (p < end) {

        c->log->action = "parsing frames";

        njt_memzero(&frame, sizeof(njt_quic_frame_t));
        njt_memzero(&buf, sizeof(njt_buf_t));
        buf.temporary = 1;

        chain.buf = &buf;
        chain.next = NULL;
        frame.data = &chain;

        len = njt_quic_parse_frame(pkt, p, end, &frame);

        if (len < 0) {
            qc->error = pkt->error;
            return NJT_ERROR;
        }

        njt_quic_log_frame(c->log, &frame, 0);

        c->log->action = "handling frames";

        p += len;

        switch (frame.type) {
        /* probing frames */
        case NJT_QUIC_FT_PADDING:
        case NJT_QUIC_FT_PATH_CHALLENGE:
        case NJT_QUIC_FT_PATH_RESPONSE:
        case NJT_QUIC_FT_NEW_CONNECTION_ID:
            break;

        /* non-probing frames */
        default:
            nonprobing = 1;
            break;
        }

        switch (frame.type) {

        case NJT_QUIC_FT_ACK:
            if (njt_quic_handle_ack_frame(c, pkt, &frame) != NJT_OK) {
                return NJT_ERROR;
            }

            continue;

        case NJT_QUIC_FT_PADDING:
            /* no action required */
            continue;

        case NJT_QUIC_FT_CONNECTION_CLOSE:
        case NJT_QUIC_FT_CONNECTION_CLOSE_APP:
            do_close = 1;
            continue;
        }

        /* got there with ack-eliciting packet */
        pkt->need_ack = 1;

        switch (frame.type) {

        case NJT_QUIC_FT_CRYPTO:

            if (njt_quic_handle_crypto_frame(c, pkt, &frame) != NJT_OK) {
                return NJT_ERROR;
            }

            break;

        case NJT_QUIC_FT_PING:
            break;

        case NJT_QUIC_FT_STREAM:

            if (njt_quic_handle_stream_frame(c, pkt, &frame) != NJT_OK) {
                return NJT_ERROR;
            }

            break;

        case NJT_QUIC_FT_MAX_DATA:

            if (njt_quic_handle_max_data_frame(c, &frame.u.max_data) != NJT_OK)
            {
                return NJT_ERROR;
            }

            break;

        case NJT_QUIC_FT_STREAMS_BLOCKED:
        case NJT_QUIC_FT_STREAMS_BLOCKED2:

            if (njt_quic_handle_streams_blocked_frame(c, pkt,
                                                      &frame.u.streams_blocked)
                != NJT_OK)
            {
                return NJT_ERROR;
            }

            break;

        case NJT_QUIC_FT_DATA_BLOCKED:

            if (njt_quic_handle_data_blocked_frame(c, pkt,
                                                   &frame.u.data_blocked)
                != NJT_OK)
            {
                return NJT_ERROR;
            }

            break;

        case NJT_QUIC_FT_STREAM_DATA_BLOCKED:

            if (njt_quic_handle_stream_data_blocked_frame(c, pkt,
                                                  &frame.u.stream_data_blocked)
                != NJT_OK)
            {
                return NJT_ERROR;
            }

            break;

        case NJT_QUIC_FT_MAX_STREAM_DATA:

            if (njt_quic_handle_max_stream_data_frame(c, pkt,
                                                      &frame.u.max_stream_data)
                != NJT_OK)
            {
                return NJT_ERROR;
            }

            break;

        case NJT_QUIC_FT_RESET_STREAM:

            if (njt_quic_handle_reset_stream_frame(c, pkt,
                                                   &frame.u.reset_stream)
                != NJT_OK)
            {
                return NJT_ERROR;
            }

            break;

        case NJT_QUIC_FT_STOP_SENDING:

            if (njt_quic_handle_stop_sending_frame(c, pkt,
                                                   &frame.u.stop_sending)
                != NJT_OK)
            {
                return NJT_ERROR;
            }

            break;

        case NJT_QUIC_FT_MAX_STREAMS:
        case NJT_QUIC_FT_MAX_STREAMS2:

            if (njt_quic_handle_max_streams_frame(c, pkt, &frame.u.max_streams)
                != NJT_OK)
            {
                return NJT_ERROR;
            }

            break;

        case NJT_QUIC_FT_PATH_CHALLENGE:

            if (njt_quic_handle_path_challenge_frame(c, pkt,
                                                     &frame.u.path_challenge)
                != NJT_OK)
            {
                return NJT_ERROR;
            }

            break;

        case NJT_QUIC_FT_PATH_RESPONSE:

            if (njt_quic_handle_path_response_frame(c, &frame.u.path_response)
                != NJT_OK)
            {
                return NJT_ERROR;
            }

            break;

        case NJT_QUIC_FT_NEW_CONNECTION_ID:

            if (njt_quic_handle_new_connection_id_frame(c, &frame.u.ncid)
                != NJT_OK)
            {
                return NJT_ERROR;
            }

            break;

        case NJT_QUIC_FT_RETIRE_CONNECTION_ID:

            if (njt_quic_handle_retire_connection_id_frame(c,
                                                           &frame.u.retire_cid)
                != NJT_OK)
            {
                return NJT_ERROR;
            }

            break;

        default:
            njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0,
                           "quic missing frame handler");
            return NJT_ERROR;
        }
    }

    if (p != end) {
        njt_log_error(NJT_LOG_INFO, c->log, 0,
                      "quic trailing garbage in payload:%ui bytes", end - p);

        qc->error = NJT_QUIC_ERR_FRAME_ENCODING_ERROR;
        return NJT_ERROR;
    }

    if (do_close) {
        qc->draining = 1;
        njt_post_event(&qc->close, &njt_posted_events);
    }

    if (pkt->path != qc->path && nonprobing) {

        /*
         * RFC 9000, 9.2.  Initiating Connection Migration
         *
         * An endpoint can migrate a connection to a new local
         * address by sending packets containing non-probing frames
         * from that address.
         */
        if (njt_quic_handle_migration(c, pkt) != NJT_OK) {
            return NJT_ERROR;
        }
    }

    if (njt_quic_ack_packet(c, pkt) != NJT_OK) {
        return NJT_ERROR;
    }

    return NJT_OK;
}


static void
njt_quic_push_handler(njt_event_t *ev)
{
    njt_connection_t  *c;

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, ev->log, 0, "quic push handler");

    c = ev->data;

    if (njt_quic_output(c) != NJT_OK) {
        njt_quic_close_connection(c, NJT_ERROR);
        return;
    }

    njt_quic_connstate_dbg(c);
}


void
njt_quic_shutdown_quic(njt_connection_t *c)
{
    njt_quic_connection_t  *qc;

    if (c->reusable) {
        qc = njt_quic_get_connection(c);
        njt_quic_finalize_connection(c, qc->shutdown_code, qc->shutdown_reason);
    }
}
