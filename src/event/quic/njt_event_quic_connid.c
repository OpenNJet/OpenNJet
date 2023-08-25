
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>
#include <njt_event_quic_connection.h>

#define NJT_QUIC_MAX_SERVER_IDS   8


#if (NJT_QUIC_BPF)
static njt_int_t njt_quic_bpf_attach_id(njt_connection_t *c, u_char *id);
#endif
static njt_int_t njt_quic_retire_client_id(njt_connection_t *c,
    njt_quic_client_id_t *cid);
static njt_quic_client_id_t *njt_quic_alloc_client_id(njt_connection_t *c,
    njt_quic_connection_t *qc);
static njt_int_t njt_quic_send_server_id(njt_connection_t *c,
    njt_quic_server_id_t *sid);


njt_int_t
njt_quic_create_server_id(njt_connection_t *c, u_char *id)
{
    if (RAND_bytes(id, NJT_QUIC_SERVER_CID_LEN) != 1) {
        return NJT_ERROR;
    }

#if (NJT_QUIC_BPF)
    if (njt_quic_bpf_attach_id(c, id) != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, c->log, 0,
                      "quic bpf failed to generate socket key");
        /* ignore error, things still may work */
    }
#endif

    return NJT_OK;
}


#if (NJT_QUIC_BPF)

static njt_int_t
njt_quic_bpf_attach_id(njt_connection_t *c, u_char *id)
{
    int        fd;
    uint64_t   cookie;
    socklen_t  optlen;

    fd = c->listening->fd;

    optlen = sizeof(cookie);

    if (getsockopt(fd, SOL_SOCKET, SO_COOKIE, &cookie, &optlen) == -1) {
        njt_log_error(NJT_LOG_ERR, c->log, njt_socket_errno,
                      "quic getsockopt(SO_COOKIE) failed");

        return NJT_ERROR;
    }

    njt_quic_dcid_encode_key(id, cookie);

    return NJT_OK;
}

#endif


njt_int_t
njt_quic_handle_new_connection_id_frame(njt_connection_t *c,
    njt_quic_new_conn_id_frame_t *f)
{
    njt_str_t               id;
    njt_queue_t            *q;
    njt_quic_frame_t       *frame;
    njt_quic_client_id_t   *cid, *item;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    if (f->seqnum < qc->max_retired_seqnum) {
        /*
         * RFC 9000, 19.15.  NEW_CONNECTION_ID Frame
         *
         *  An endpoint that receives a NEW_CONNECTION_ID frame with
         *  a sequence number smaller than the Retire Prior To field
         *  of a previously received NEW_CONNECTION_ID frame MUST send
         *  a corresponding RETIRE_CONNECTION_ID frame that retires
         *  the newly received connection ID, unless it has already
         *  done so for that sequence number.
         */

        frame = njt_quic_alloc_frame(c);
        if (frame == NULL) {
            return NJT_ERROR;
        }

        frame->level = ssl_encryption_application;
        frame->type = NJT_QUIC_FT_RETIRE_CONNECTION_ID;
        frame->u.retire_cid.sequence_number = f->seqnum;

        njt_quic_queue_frame(qc, frame);

        goto retire;
    }

    cid = NULL;

    for (q = njt_queue_head(&qc->client_ids);
         q != njt_queue_sentinel(&qc->client_ids);
         q = njt_queue_next(q))
    {
        item = njt_queue_data(q, njt_quic_client_id_t, queue);

        if (item->seqnum == f->seqnum) {
            cid = item;
            break;
        }
    }

    if (cid) {
        /*
         * Transmission errors, timeouts, and retransmissions might cause the
         * same NEW_CONNECTION_ID frame to be received multiple times.
         */

        if (cid->len != f->len
            || njt_strncmp(cid->id, f->cid, f->len) != 0
            || njt_strncmp(cid->sr_token, f->srt, NJT_QUIC_SR_TOKEN_LEN) != 0)
        {
            /*
             * ..if a sequence number is used for different connection IDs,
             * the endpoint MAY treat that receipt as a connection error
             * of type PROTOCOL_VIOLATION.
             */
            qc->error = NJT_QUIC_ERR_PROTOCOL_VIOLATION;
            qc->error_reason = "seqnum refers to different connection id/token";
            return NJT_ERROR;
        }

    } else {

        id.data = f->cid;
        id.len = f->len;

        if (njt_quic_create_client_id(c, &id, f->seqnum, f->srt) == NULL) {
            return NJT_ERROR;
        }
    }

retire:

    if (qc->max_retired_seqnum && f->retire <= qc->max_retired_seqnum) {
        /*
         * Once a sender indicates a Retire Prior To value, smaller values sent
         * in subsequent NEW_CONNECTION_ID frames have no effect.  A receiver
         * MUST ignore any Retire Prior To fields that do not increase the
         * largest received Retire Prior To value.
         */
        goto done;
    }

    qc->max_retired_seqnum = f->retire;

    q = njt_queue_head(&qc->client_ids);

    while (q != njt_queue_sentinel(&qc->client_ids)) {

        cid = njt_queue_data(q, njt_quic_client_id_t, queue);
        q = njt_queue_next(q);

        if (cid->seqnum >= f->retire) {
            continue;
        }

        if (njt_quic_retire_client_id(c, cid) != NJT_OK) {
            return NJT_ERROR;
        }
    }

done:

    if (qc->nclient_ids > qc->tp.active_connection_id_limit) {
        /*
         * RFC 9000, 5.1.1.  Issuing Connection IDs
         *
         * After processing a NEW_CONNECTION_ID frame and
         * adding and retiring active connection IDs, if the number of active
         * connection IDs exceeds the value advertised in its
         * active_connection_id_limit transport parameter, an endpoint MUST
         * close the connection with an error of type CONNECTION_ID_LIMIT_ERROR.
         */
        qc->error = NJT_QUIC_ERR_CONNECTION_ID_LIMIT_ERROR;
        qc->error_reason = "too many connection ids received";
        return NJT_ERROR;
    }

    return NJT_OK;
}


static njt_int_t
njt_quic_retire_client_id(njt_connection_t *c, njt_quic_client_id_t *cid)
{
    njt_queue_t            *q;
    njt_quic_path_t        *path;
    njt_quic_client_id_t   *new_cid;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    if (!cid->used) {
        return njt_quic_free_client_id(c, cid);
    }

    /* we are going to retire client id which is in use */

    q = njt_queue_head(&qc->paths);

    while (q != njt_queue_sentinel(&qc->paths)) {

        path = njt_queue_data(q, njt_quic_path_t, queue);
        q = njt_queue_next(q);

        if (path->cid != cid) {
            continue;
        }

        if (path == qc->path) {
            /* this is the active path: update it with new CID */
            new_cid = njt_quic_next_client_id(c);
            if (new_cid == NULL) {
                return NJT_ERROR;
            }

            qc->path->cid = new_cid;
            new_cid->used = 1;

            return njt_quic_free_client_id(c, cid);
        }

        return njt_quic_free_path(c, path);
    }

    return NJT_OK;
}


static njt_quic_client_id_t *
njt_quic_alloc_client_id(njt_connection_t *c, njt_quic_connection_t *qc)
{
    njt_queue_t           *q;
    njt_quic_client_id_t  *cid;

    if (!njt_queue_empty(&qc->free_client_ids)) {

        q = njt_queue_head(&qc->free_client_ids);
        cid = njt_queue_data(q, njt_quic_client_id_t, queue);

        njt_queue_remove(&cid->queue);

        njt_memzero(cid, sizeof(njt_quic_client_id_t));

    } else {

        cid = njt_pcalloc(c->pool, sizeof(njt_quic_client_id_t));
        if (cid == NULL) {
            return NULL;
        }
    }

    return cid;
}


njt_quic_client_id_t *
njt_quic_create_client_id(njt_connection_t *c, njt_str_t *id,
    uint64_t seqnum, u_char *token)
{
    njt_quic_client_id_t   *cid;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    cid = njt_quic_alloc_client_id(c, qc);
    if (cid == NULL) {
        return NULL;
    }

    cid->seqnum = seqnum;

    cid->len = id->len;
    njt_memcpy(cid->id, id->data, id->len);

    if (token) {
        njt_memcpy(cid->sr_token, token, NJT_QUIC_SR_TOKEN_LEN);
    }

    njt_queue_insert_tail(&qc->client_ids, &cid->queue);
    qc->nclient_ids++;

    if (seqnum > qc->client_seqnum) {
        qc->client_seqnum = seqnum;
    }

    njt_log_debug5(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic cid seq:%uL received id:%uz:%xV:%*xs",
                    cid->seqnum, id->len, id,
                    (size_t) NJT_QUIC_SR_TOKEN_LEN, cid->sr_token);

    return cid;
}


njt_quic_client_id_t *
njt_quic_next_client_id(njt_connection_t *c)
{
    njt_queue_t            *q;
    njt_quic_client_id_t   *cid;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    for (q = njt_queue_head(&qc->client_ids);
         q != njt_queue_sentinel(&qc->client_ids);
         q = njt_queue_next(q))
    {
        cid = njt_queue_data(q, njt_quic_client_id_t, queue);

        if (!cid->used) {
            return cid;
        }
    }

    return NULL;
}


njt_int_t
njt_quic_handle_retire_connection_id_frame(njt_connection_t *c,
    njt_quic_retire_cid_frame_t *f)
{
    njt_quic_socket_t      *qsock;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    if (f->sequence_number >= qc->server_seqnum) {
        /*
         * RFC 9000, 19.16.
         *
         *  Receipt of a RETIRE_CONNECTION_ID frame containing a sequence
         *  number greater than any previously sent to the peer MUST be
         *  treated as a connection error of type PROTOCOL_VIOLATION.
         */
        qc->error = NJT_QUIC_ERR_PROTOCOL_VIOLATION;
        qc->error_reason = "sequence number of id to retire was never issued";

        return NJT_ERROR;
    }

    qsock = njt_quic_get_socket(c);

    if (qsock->sid.seqnum == f->sequence_number) {

        /*
         * RFC 9000, 19.16.
         *
         * The sequence number specified in a RETIRE_CONNECTION_ID frame MUST
         * NOT refer to the Destination Connection ID field of the packet in
         * which the frame is contained.  The peer MAY treat this as a
         * connection error of type PROTOCOL_VIOLATION.
         */

        qc->error = NJT_QUIC_ERR_PROTOCOL_VIOLATION;
        qc->error_reason = "sequence number of id to retire refers DCID";

        return NJT_ERROR;
    }

    qsock = njt_quic_find_socket(c, f->sequence_number);
    if (qsock == NULL) {
        return NJT_OK;
    }

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic socket seq:%uL is retired", qsock->sid.seqnum);

    njt_quic_close_socket(c, qsock);

    /* restore socket count up to a limit after deletion */
    if (njt_quic_create_sockets(c) != NJT_OK) {
        return NJT_ERROR;
    }

    return NJT_OK;
}


njt_int_t
njt_quic_create_sockets(njt_connection_t *c)
{
    njt_uint_t              n;
    njt_quic_socket_t      *qsock;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    n = njt_min(NJT_QUIC_MAX_SERVER_IDS, qc->ctp.active_connection_id_limit);

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic create sockets has:%ui max:%ui", qc->nsockets, n);

    while (qc->nsockets < n) {

        qsock = njt_quic_create_socket(c, qc);
        if (qsock == NULL) {
            return NJT_ERROR;
        }

        if (njt_quic_listen(c, qc, qsock) != NJT_OK) {
            return NJT_ERROR;
        }

        if (njt_quic_send_server_id(c, &qsock->sid) != NJT_OK) {
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}


static njt_int_t
njt_quic_send_server_id(njt_connection_t *c, njt_quic_server_id_t *sid)
{
    njt_str_t               dcid;
    njt_quic_frame_t       *frame;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    dcid.len = sid->len;
    dcid.data = sid->id;

    frame = njt_quic_alloc_frame(c);
    if (frame == NULL) {
        return NJT_ERROR;
    }

    frame->level = ssl_encryption_application;
    frame->type = NJT_QUIC_FT_NEW_CONNECTION_ID;
    frame->u.ncid.seqnum = sid->seqnum;
    frame->u.ncid.retire = 0;
    frame->u.ncid.len = NJT_QUIC_SERVER_CID_LEN;
    njt_memcpy(frame->u.ncid.cid, sid->id, NJT_QUIC_SERVER_CID_LEN);

    if (njt_quic_new_sr_token(c, &dcid, qc->conf->sr_token_key,
                              frame->u.ncid.srt)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    njt_quic_queue_frame(qc, frame);

    return NJT_OK;
}


njt_int_t
njt_quic_free_client_id(njt_connection_t *c, njt_quic_client_id_t *cid)
{
    njt_quic_frame_t       *frame;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    frame = njt_quic_alloc_frame(c);
    if (frame == NULL) {
        return NJT_ERROR;
    }

    frame->level = ssl_encryption_application;
    frame->type = NJT_QUIC_FT_RETIRE_CONNECTION_ID;
    frame->u.retire_cid.sequence_number = cid->seqnum;

    njt_quic_queue_frame(qc, frame);

    /* we are no longer going to use this client id */

    njt_queue_remove(&cid->queue);
    njt_queue_insert_head(&qc->free_client_ids, &cid->queue);

    qc->nclient_ids--;

    return NJT_OK;
}
