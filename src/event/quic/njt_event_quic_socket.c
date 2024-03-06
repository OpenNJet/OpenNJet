
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>
#include <njt_event_quic_connection.h>


njt_int_t
njt_quic_open_sockets(njt_connection_t *c, njt_quic_connection_t *qc,
    njt_quic_header_t *pkt)
{
    njt_quic_socket_t     *qsock, *tmp;
    njt_quic_client_id_t  *cid;

    /*
     * qc->path = NULL
     *
     * qc->nclient_ids = 0
     * qc->nsockets = 0
     * qc->max_retired_seqnum = 0
     * qc->client_seqnum = 0
     */

    njt_queue_init(&qc->sockets);
    njt_queue_init(&qc->free_sockets);

    njt_queue_init(&qc->paths);
    njt_queue_init(&qc->free_paths);

    njt_queue_init(&qc->client_ids);
    njt_queue_init(&qc->free_client_ids);

    qc->tp.original_dcid.len = pkt->odcid.len;
    qc->tp.original_dcid.data = njt_pstrdup(c->pool, &pkt->odcid);
    if (qc->tp.original_dcid.data == NULL) {
        return NJT_ERROR;
    }

    /* socket to use for further processing (id auto-generated) */
    qsock = njt_quic_create_socket(c, qc);
    if (qsock == NULL) {
        return NJT_ERROR;
    }

    /* socket is listening at new server id */
    if (njt_quic_listen(c, qc, qsock) != NJT_OK) {
        return NJT_ERROR;
    }

    qsock->used = 1;

    qc->tp.initial_scid.len = qsock->sid.len;
    qc->tp.initial_scid.data = njt_pnalloc(c->pool, qsock->sid.len);
    if (qc->tp.initial_scid.data == NULL) {
        goto failed;
    }
    njt_memcpy(qc->tp.initial_scid.data, qsock->sid.id, qsock->sid.len);

    /* for all packets except first, this is set at udp layer */
    c->udp = &qsock->udp;

    /* njt_quic_get_connection(c) macro is now usable */

    /* we have a client identified by scid */
    cid = njt_quic_create_client_id(c, &pkt->scid, 0, NULL);
    if (cid == NULL) {
        goto failed;
    }

    /* path of the first packet is our initial active path */
    qc->path = njt_quic_new_path(c, c->sockaddr, c->socklen, cid);
    if (qc->path == NULL) {
        goto failed;
    }

    qc->path->tag = NJT_QUIC_PATH_ACTIVE;

    if (pkt->validated) {
        qc->path->validated = 1;
    }

    njt_quic_path_dbg(c, "set active", qc->path);

    tmp = njt_pcalloc(c->pool, sizeof(njt_quic_socket_t));
    if (tmp == NULL) {
        goto failed;
    }

    tmp->sid.seqnum = NJT_QUIC_UNSET_PN; /* temporary socket */

    njt_memcpy(tmp->sid.id, pkt->dcid.data, pkt->dcid.len);
    tmp->sid.len = pkt->dcid.len;

    if (njt_quic_listen(c, qc, tmp) != NJT_OK) {
        goto failed;
    }

    return NJT_OK;

failed:

    njt_rbtree_delete(&c->listening->rbtree, &qsock->udp.node);
    c->udp = NULL;

    return NJT_ERROR;
}


njt_quic_socket_t *
njt_quic_create_socket(njt_connection_t *c, njt_quic_connection_t *qc)
{
    njt_queue_t        *q;
    njt_quic_socket_t  *sock;

    if (!njt_queue_empty(&qc->free_sockets)) {

        q = njt_queue_head(&qc->free_sockets);
        sock = njt_queue_data(q, njt_quic_socket_t, queue);

        njt_queue_remove(&sock->queue);

        njt_memzero(sock, sizeof(njt_quic_socket_t));

    } else {

        sock = njt_pcalloc(c->pool, sizeof(njt_quic_socket_t));
        if (sock == NULL) {
            return NULL;
        }
    }

    sock->sid.len = NJT_QUIC_SERVER_CID_LEN;
    if (njt_quic_create_server_id(c, sock->sid.id) != NJT_OK) {
        return NULL;
    }

    sock->sid.seqnum = qc->server_seqnum++;

    return sock;
}


void
njt_quic_close_socket(njt_connection_t *c, njt_quic_socket_t *qsock)
{
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    njt_queue_remove(&qsock->queue);
    njt_queue_insert_head(&qc->free_sockets, &qsock->queue);

    njt_rbtree_delete(&c->listening->rbtree, &qsock->udp.node);
    qc->nsockets--;

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic socket seq:%L closed nsock:%ui",
                   (int64_t) qsock->sid.seqnum, qc->nsockets);
}


njt_int_t
njt_quic_listen(njt_connection_t *c, njt_quic_connection_t *qc,
    njt_quic_socket_t *qsock)
{
    njt_str_t              id;
    njt_quic_server_id_t  *sid;

    sid = &qsock->sid;

    id.data = sid->id;
    id.len = sid->len;

    qsock->udp.connection = c;
    qsock->udp.node.key = njt_crc32_long(id.data, id.len);
    qsock->udp.key = id;

    //udp traffic hack, init real_sock to -1
    qsock->udp.real_sock = (njt_socket_t)-1;

    njt_rbtree_insert(&c->listening->rbtree, &qsock->udp.node);

    njt_queue_insert_tail(&qc->sockets, &qsock->queue);

    qc->nsockets++;
    qsock->quic = qc;

    njt_log_debug3(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic socket seq:%L listening at sid:%xV nsock:%ui",
                   (int64_t) sid->seqnum, &id, qc->nsockets);

    return NJT_OK;
}


void
njt_quic_close_sockets(njt_connection_t *c)
{
    njt_queue_t            *q;
    njt_quic_socket_t      *qsock;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    while (!njt_queue_empty(&qc->sockets)) {
        q = njt_queue_head(&qc->sockets);
        qsock = njt_queue_data(q, njt_quic_socket_t, queue);

        njt_quic_close_socket(c, qsock);
    }
}


njt_quic_socket_t *
njt_quic_find_socket(njt_connection_t *c, uint64_t seqnum)
{
    njt_queue_t            *q;
    njt_quic_socket_t      *qsock;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    for (q = njt_queue_head(&qc->sockets);
         q != njt_queue_sentinel(&qc->sockets);
         q = njt_queue_next(q))
    {
        qsock = njt_queue_data(q, njt_quic_socket_t, queue);

        if (qsock->sid.seqnum == seqnum) {
            return qsock;
        }
    }

    return NULL;
}
