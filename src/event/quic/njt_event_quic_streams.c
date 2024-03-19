
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>
#include <njt_event_quic_connection.h>


#define NJT_QUIC_STREAM_GONE     (void *) -1


static njt_int_t njt_quic_do_reset_stream(njt_quic_stream_t *qs,
    njt_uint_t err);
static njt_int_t njt_quic_shutdown_stream_send(njt_connection_t *c);
static njt_int_t njt_quic_shutdown_stream_recv(njt_connection_t *c);
static njt_quic_stream_t *njt_quic_get_stream(njt_connection_t *c, uint64_t id);
static njt_int_t njt_quic_reject_stream(njt_connection_t *c, uint64_t id);
static void njt_quic_init_stream_handler(njt_event_t *ev);
static void njt_quic_init_streams_handler(njt_connection_t *c);
static njt_int_t njt_quic_do_init_streams(njt_connection_t *c);
static njt_quic_stream_t *njt_quic_create_stream(njt_connection_t *c,
    uint64_t id);
static void njt_quic_empty_handler(njt_event_t *ev);
static ssize_t njt_quic_stream_recv(njt_connection_t *c, u_char *buf,
    size_t size);
static ssize_t njt_quic_stream_send(njt_connection_t *c, u_char *buf,
    size_t size);
static njt_chain_t *njt_quic_stream_send_chain(njt_connection_t *c,
    njt_chain_t *in, off_t limit);
static njt_int_t njt_quic_stream_flush(njt_quic_stream_t *qs);
static void njt_quic_stream_cleanup_handler(void *data);
static njt_int_t njt_quic_close_stream(njt_quic_stream_t *qs);
static njt_int_t njt_quic_can_shutdown(njt_connection_t *c);
static njt_int_t njt_quic_control_flow(njt_quic_stream_t *qs, uint64_t last);
static njt_int_t njt_quic_update_flow(njt_quic_stream_t *qs, uint64_t last);
static njt_int_t njt_quic_update_max_stream_data(njt_quic_stream_t *qs);
static njt_int_t njt_quic_update_max_data(njt_connection_t *c);
static void njt_quic_set_event(njt_event_t *ev);


njt_connection_t *
njt_quic_open_stream(njt_connection_t *c, njt_uint_t bidi)
{
    uint64_t                id;
    njt_connection_t       *pc, *sc;
    njt_quic_stream_t      *qs;
    njt_quic_connection_t  *qc;

    pc = c->quic ? c->quic->parent : c;
    qc = njt_quic_get_connection(pc);

    if (qc->closing) {
        return NULL;
    }

    if (bidi) {
        if (qc->streams.server_streams_bidi
            >= qc->streams.server_max_streams_bidi)
        {
            njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                           "quic too many server bidi streams:%uL",
                           qc->streams.server_streams_bidi);
            return NULL;
        }

        id = (qc->streams.server_streams_bidi << 2)
             | NJT_QUIC_STREAM_SERVER_INITIATED;

        njt_log_debug3(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "quic creating server bidi stream"
                       " streams:%uL max:%uL id:0x%xL",
                       qc->streams.server_streams_bidi,
                       qc->streams.server_max_streams_bidi, id);

        qc->streams.server_streams_bidi++;

    } else {
        if (qc->streams.server_streams_uni
            >= qc->streams.server_max_streams_uni)
        {
            njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                           "quic too many server uni streams:%uL",
                           qc->streams.server_streams_uni);
            return NULL;
        }

        id = (qc->streams.server_streams_uni << 2)
             | NJT_QUIC_STREAM_SERVER_INITIATED
             | NJT_QUIC_STREAM_UNIDIRECTIONAL;

        njt_log_debug3(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "quic creating server uni stream"
                       " streams:%uL max:%uL id:0x%xL",
                       qc->streams.server_streams_uni,
                       qc->streams.server_max_streams_uni, id);

        qc->streams.server_streams_uni++;
    }

    qs = njt_quic_create_stream(pc, id);
    if (qs == NULL) {
        return NULL;
    }

    sc = qs->connection;

    sc->write->active = 1;
    sc->write->ready = 1;

    if (bidi) {
        sc->read->active = 1;
    }

    return sc;
}


void
njt_quic_rbtree_insert_stream(njt_rbtree_node_t *temp,
    njt_rbtree_node_t *node, njt_rbtree_node_t *sentinel)
{
    njt_rbtree_node_t  **p;
    njt_quic_stream_t   *qn, *qnt;

    for ( ;; ) {
        qn = (njt_quic_stream_t *) node;
        qnt = (njt_quic_stream_t *) temp;

        p = (qn->id < qnt->id) ? &temp->left : &temp->right;

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    njt_rbt_red(node);
}


njt_quic_stream_t *
njt_quic_find_stream(njt_rbtree_t *rbtree, uint64_t id)
{
    njt_rbtree_node_t  *node, *sentinel;
    njt_quic_stream_t  *qn;

    node = rbtree->root;
    sentinel = rbtree->sentinel;

    while (node != sentinel) {
        qn = (njt_quic_stream_t *) node;

        if (id == qn->id) {
            return qn;
        }

        node = (id < qn->id) ? node->left : node->right;
    }

    return NULL;
}


njt_int_t
njt_quic_close_streams(njt_connection_t *c, njt_quic_connection_t *qc)
{
    njt_pool_t         *pool;
    njt_queue_t        *q;
    njt_rbtree_t       *tree;
    njt_connection_t   *sc;
    njt_rbtree_node_t  *node;
    njt_quic_stream_t  *qs;

    while (!njt_queue_empty(&qc->streams.uninitialized)) {
        q = njt_queue_head(&qc->streams.uninitialized);
        njt_queue_remove(q);

        qs = njt_queue_data(q, njt_quic_stream_t, queue);
        pool = qs->connection->pool;

        njt_close_connection(qs->connection);
        njt_destroy_pool(pool);
    }

    tree = &qc->streams.tree;

    if (tree->root == tree->sentinel) {
        return NJT_OK;
    }

    node = njt_rbtree_min(tree->root, tree->sentinel);

    while (node) {
        qs = (njt_quic_stream_t *) node;
        node = njt_rbtree_next(tree, node);
        sc = qs->connection;

        qs->recv_state = NJT_QUIC_STREAM_RECV_RESET_RECVD;
        qs->send_state = NJT_QUIC_STREAM_SEND_RESET_SENT;

        if (sc == NULL) {
            njt_quic_close_stream(qs);
            continue;
        }

        sc->read->error = 1;
        sc->write->error = 1;

        njt_quic_set_event(sc->read);
        njt_quic_set_event(sc->write);

        sc->close = 1;
        sc->read->handler(sc->read);
    }

    if (tree->root == tree->sentinel) {
        return NJT_OK;
    }

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic connection has active streams");

    return NJT_AGAIN;
}


njt_int_t
njt_quic_reset_stream(njt_connection_t *c, njt_uint_t err)
{
    return njt_quic_do_reset_stream(c->quic, err);
}


static njt_int_t
njt_quic_do_reset_stream(njt_quic_stream_t *qs, njt_uint_t err)
{
    njt_connection_t       *pc;
    njt_quic_frame_t       *frame;
    njt_quic_connection_t  *qc;

    if (qs->send_state == NJT_QUIC_STREAM_SEND_DATA_RECVD
        || qs->send_state == NJT_QUIC_STREAM_SEND_RESET_SENT
        || qs->send_state == NJT_QUIC_STREAM_SEND_RESET_RECVD)
    {
        return NJT_OK;
    }

    qs->send_state = NJT_QUIC_STREAM_SEND_RESET_SENT;
    qs->send_final_size = qs->send_offset;

    if (qs->connection) {
        qs->connection->write->error = 1;
    }

    pc = qs->parent;
    qc = njt_quic_get_connection(pc);

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, pc->log, 0,
                   "quic stream id:0x%xL reset", qs->id);

    frame = njt_quic_alloc_frame(pc);
    if (frame == NULL) {
        return NJT_ERROR;
    }

    frame->level = ssl_encryption_application;
    frame->type = NJT_QUIC_FT_RESET_STREAM;
    frame->u.reset_stream.id = qs->id;
    frame->u.reset_stream.error_code = err;
    frame->u.reset_stream.final_size = qs->send_offset;

    njt_quic_queue_frame(qc, frame);

    njt_quic_free_buffer(pc, &qs->send);

    return NJT_OK;
}


njt_int_t
njt_quic_shutdown_stream(njt_connection_t *c, int how)
{
    if (how == NJT_RDWR_SHUTDOWN || how == NJT_WRITE_SHUTDOWN) {
        if (njt_quic_shutdown_stream_send(c) != NJT_OK) {
            return NJT_ERROR;
        }
    }

    if (how == NJT_RDWR_SHUTDOWN || how == NJT_READ_SHUTDOWN) {
        if (njt_quic_shutdown_stream_recv(c) != NJT_OK) {
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}


static njt_int_t
njt_quic_shutdown_stream_send(njt_connection_t *c)
{
    njt_quic_stream_t  *qs;

    qs = c->quic;

    if (qs->send_state != NJT_QUIC_STREAM_SEND_READY
        && qs->send_state != NJT_QUIC_STREAM_SEND_SEND)
    {
        return NJT_OK;
    }

    qs->send_state = NJT_QUIC_STREAM_SEND_SEND;
    qs->send_final_size = c->sent;

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, qs->parent->log, 0,
                   "quic stream id:0x%xL send shutdown", qs->id);

    return njt_quic_stream_flush(qs);
}


static njt_int_t
njt_quic_shutdown_stream_recv(njt_connection_t *c)
{
    njt_connection_t       *pc;
    njt_quic_frame_t       *frame;
    njt_quic_stream_t      *qs;
    njt_quic_connection_t  *qc;

    qs = c->quic;

    if (qs->recv_state != NJT_QUIC_STREAM_RECV_RECV
        && qs->recv_state != NJT_QUIC_STREAM_RECV_SIZE_KNOWN)
    {
        return NJT_OK;
    }

    pc = qs->parent;
    qc = njt_quic_get_connection(pc);

    if (qc->conf->stream_close_code == 0) {
        return NJT_OK;
    }

    frame = njt_quic_alloc_frame(pc);
    if (frame == NULL) {
        return NJT_ERROR;
    }

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, pc->log, 0,
                   "quic stream id:0x%xL recv shutdown", qs->id);

    frame->level = ssl_encryption_application;
    frame->type = NJT_QUIC_FT_STOP_SENDING;
    frame->u.stop_sending.id = qs->id;
    frame->u.stop_sending.error_code = qc->conf->stream_close_code;

    njt_quic_queue_frame(qc, frame);

    return NJT_OK;
}


static njt_quic_stream_t *
njt_quic_get_stream(njt_connection_t *c, uint64_t id)
{
    uint64_t                min_id;
    njt_event_t            *rev;
    njt_quic_stream_t      *qs;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    qs = njt_quic_find_stream(&qc->streams.tree, id);

    if (qs) {
        return qs;
    }

    if (qc->shutdown || qc->closing) {
        return NJT_QUIC_STREAM_GONE;
    }

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic stream id:0x%xL is missing", id);

    if (id & NJT_QUIC_STREAM_UNIDIRECTIONAL) {

        if (id & NJT_QUIC_STREAM_SERVER_INITIATED) {
            if ((id >> 2) < qc->streams.server_streams_uni) {
                return NJT_QUIC_STREAM_GONE;
            }

            qc->error = NJT_QUIC_ERR_STREAM_STATE_ERROR;
            return NULL;
        }

        if ((id >> 2) < qc->streams.client_streams_uni) {
            return NJT_QUIC_STREAM_GONE;
        }

        if ((id >> 2) >= qc->streams.client_max_streams_uni) {
            qc->error = NJT_QUIC_ERR_STREAM_LIMIT_ERROR;
            return NULL;
        }

        min_id = (qc->streams.client_streams_uni << 2)
                 | NJT_QUIC_STREAM_UNIDIRECTIONAL;
        qc->streams.client_streams_uni = (id >> 2) + 1;

    } else {

        if (id & NJT_QUIC_STREAM_SERVER_INITIATED) {
            if ((id >> 2) < qc->streams.server_streams_bidi) {
                return NJT_QUIC_STREAM_GONE;
            }

            qc->error = NJT_QUIC_ERR_STREAM_STATE_ERROR;
            return NULL;
        }

        if ((id >> 2) < qc->streams.client_streams_bidi) {
            return NJT_QUIC_STREAM_GONE;
        }

        if ((id >> 2) >= qc->streams.client_max_streams_bidi) {
            qc->error = NJT_QUIC_ERR_STREAM_LIMIT_ERROR;
            return NULL;
        }

        min_id = (qc->streams.client_streams_bidi << 2);
        qc->streams.client_streams_bidi = (id >> 2) + 1;
    }

    /*
     * RFC 9000, 2.1.  Stream Types and Identifiers
     *
     * successive streams of each type are created with numerically increasing
     * stream IDs.  A stream ID that is used out of order results in all
     * streams of that type with lower-numbered stream IDs also being opened.
     */

#if (NJT_SUPPRESS_WARN)
    qs = NULL;
#endif

    for ( /* void */ ; min_id <= id; min_id += 0x04) {

        qs = njt_quic_create_stream(c, min_id);

        if (qs == NULL) {
            if (njt_quic_reject_stream(c, min_id) != NJT_OK) {
                return NULL;
            }

            continue;
        }

        njt_queue_insert_tail(&qc->streams.uninitialized, &qs->queue);

        rev = qs->connection->read;
        rev->handler = njt_quic_init_stream_handler;

        if (qc->streams.initialized) {
            njt_post_event(rev, &njt_posted_events);

            if (qc->push.posted) {
                /*
                 * The posted stream can produce output immediately.
                 * By postponing the push event, we coalesce the stream
                 * output with queued frames in one UDP datagram.
                 */

                njt_delete_posted_event(&qc->push);
                njt_post_event(&qc->push, &njt_posted_events);
            }
        }
    }

    if (qs == NULL) {
        return NJT_QUIC_STREAM_GONE;
    }

    return qs;
}


static njt_int_t
njt_quic_reject_stream(njt_connection_t *c, uint64_t id)
{
    uint64_t                code;
    njt_quic_frame_t       *frame;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    code = (id & NJT_QUIC_STREAM_UNIDIRECTIONAL)
           ? qc->conf->stream_reject_code_uni
           : qc->conf->stream_reject_code_bidi;

    if (code == 0) {
        return NJT_DECLINED;
    }

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic stream id:0x%xL reject err:0x%xL", id, code);

    frame = njt_quic_alloc_frame(c);
    if (frame == NULL) {
        return NJT_ERROR;
    }

    frame->level = ssl_encryption_application;
    frame->type = NJT_QUIC_FT_RESET_STREAM;
    frame->u.reset_stream.id = id;
    frame->u.reset_stream.error_code = code;
    frame->u.reset_stream.final_size = 0;

    njt_quic_queue_frame(qc, frame);

    frame = njt_quic_alloc_frame(c);
    if (frame == NULL) {
        return NJT_ERROR;
    }

    frame->level = ssl_encryption_application;
    frame->type = NJT_QUIC_FT_STOP_SENDING;
    frame->u.stop_sending.id = id;
    frame->u.stop_sending.error_code = code;

    njt_quic_queue_frame(qc, frame);

    return NJT_OK;
}


static void
njt_quic_init_stream_handler(njt_event_t *ev)
{
    njt_connection_t   *c;
    njt_quic_stream_t  *qs;

    c = ev->data;
    qs = c->quic;

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0, "quic init stream");

    if ((qs->id & NJT_QUIC_STREAM_UNIDIRECTIONAL) == 0) {
        c->write->active = 1;
        c->write->ready = 1;
    }

    c->read->active = 1;

    njt_queue_remove(&qs->queue);

    c->listening->handler(c);
}


njt_int_t
njt_quic_init_streams(njt_connection_t *c)
{
    njt_int_t               rc;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    if (qc->streams.initialized) {
        return NJT_OK;
    }

    rc = njt_ssl_ocsp_validate(c);

    if (rc == NJT_ERROR) {
        return NJT_ERROR;
    }

    if (rc == NJT_AGAIN) {
        c->ssl->handler = njt_quic_init_streams_handler;
        return NJT_OK;
    }

    return njt_quic_do_init_streams(c);
}


static void
njt_quic_init_streams_handler(njt_connection_t *c)
{
    if (njt_quic_do_init_streams(c) != NJT_OK) {
        njt_quic_close_connection(c, NJT_ERROR);
    }
}


static njt_int_t
njt_quic_do_init_streams(njt_connection_t *c)
{
    njt_queue_t            *q;
    njt_quic_stream_t      *qs;
    njt_quic_connection_t  *qc;

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0, "quic init streams");

    qc = njt_quic_get_connection(c);

    if (qc->conf->init) {
        if (qc->conf->init(c) != NJT_OK) {
            return NJT_ERROR;
        }
    }

    for (q = njt_queue_head(&qc->streams.uninitialized);
         q != njt_queue_sentinel(&qc->streams.uninitialized);
         q = njt_queue_next(q))
    {
        qs = njt_queue_data(q, njt_quic_stream_t, queue);
        njt_post_event(qs->connection->read, &njt_posted_events);
    }

    qc->streams.initialized = 1;

    if (!qc->closing && qc->close.timer_set) {
        njt_del_timer(&qc->close);
    }

    return NJT_OK;
}


static njt_quic_stream_t *
njt_quic_create_stream(njt_connection_t *c, uint64_t id)
{
    njt_str_t               addr_text;
    njt_log_t              *log;
    njt_pool_t             *pool;
    njt_uint_t              reusable;
    njt_queue_t            *q;
    struct sockaddr        *sockaddr;
    njt_connection_t       *sc;
    njt_quic_stream_t      *qs;
    njt_pool_cleanup_t     *cln;
    njt_quic_connection_t  *qc;

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic stream id:0x%xL create", id);

    qc = njt_quic_get_connection(c);

    if (!njt_queue_empty(&qc->streams.free)) {
        q = njt_queue_head(&qc->streams.free);
        qs = njt_queue_data(q, njt_quic_stream_t, queue);
        njt_queue_remove(&qs->queue);

    } else {
        /*
         * the number of streams is limited by transport
         * parameters and application requirements
         */

        qs = njt_palloc(c->pool, sizeof(njt_quic_stream_t));
        if (qs == NULL) {
            return NULL;
        }
    }

    njt_memzero(qs, sizeof(njt_quic_stream_t));

    qs->node.key = id;
    qs->parent = c;
    qs->id = id;
    qs->send_final_size = (uint64_t) -1;
    qs->recv_final_size = (uint64_t) -1;

    pool = njt_create_pool(NJT_DEFAULT_POOL_SIZE, c->log);
    if (pool == NULL) {
        njt_queue_insert_tail(&qc->streams.free, &qs->queue);
        return NULL;
    }

    log = njt_palloc(pool, sizeof(njt_log_t));
    if (log == NULL) {
        njt_destroy_pool(pool);
        njt_queue_insert_tail(&qc->streams.free, &qs->queue);
        return NULL;
    }

    *log = *c->log;
    pool->log = log;

    sockaddr = njt_palloc(pool, c->socklen);
    if (sockaddr == NULL) {
        njt_destroy_pool(pool);
        njt_queue_insert_tail(&qc->streams.free, &qs->queue);
        return NULL;
    }

    njt_memcpy(sockaddr, c->sockaddr, c->socklen);

    if (c->addr_text.data) {
        addr_text.data = njt_pnalloc(pool, c->addr_text.len);
        if (addr_text.data == NULL) {
            njt_destroy_pool(pool);
            njt_queue_insert_tail(&qc->streams.free, &qs->queue);
            return NULL;
        }

        njt_memcpy(addr_text.data, c->addr_text.data, c->addr_text.len);
        addr_text.len = c->addr_text.len;

    } else {
        addr_text.len = 0;
        addr_text.data = NULL;
    }


    reusable = c->reusable;
    njt_reusable_connection(c, 0);

    sc = njt_get_connection(c->fd, log);
    if (sc == NULL) {
        njt_destroy_pool(pool);
        njt_queue_insert_tail(&qc->streams.free, &qs->queue);
        njt_reusable_connection(c, reusable);
        return NULL;
    }

    qs->connection = sc;

    sc->quic = qs;
    sc->shared = 1;
    sc->type = SOCK_STREAM;
    sc->pool = pool;
    sc->ssl = c->ssl;
    sc->sockaddr = sockaddr;
    sc->socklen = c->socklen;
    sc->listening = c->listening;
    sc->addr_text = addr_text;
    sc->local_sockaddr = c->local_sockaddr;
    sc->local_socklen = c->local_socklen;
    sc->number = njt_atomic_fetch_add(njt_connection_counter, 1);
    sc->start_time = c->start_time;
    sc->tcp_nodelay = NJT_TCP_NODELAY_DISABLED;

    sc->recv = njt_quic_stream_recv;
    sc->send = njt_quic_stream_send;
    sc->send_chain = njt_quic_stream_send_chain;

    sc->read->log = log;
    sc->write->log = log;

    sc->read->handler = njt_quic_empty_handler;
    sc->write->handler = njt_quic_empty_handler;

    log->connection = sc->number;

    if (id & NJT_QUIC_STREAM_UNIDIRECTIONAL) {
        if (id & NJT_QUIC_STREAM_SERVER_INITIATED) {
            qs->send_max_data = qc->ctp.initial_max_stream_data_uni;
            qs->recv_state = NJT_QUIC_STREAM_RECV_DATA_READ;
            qs->send_state = NJT_QUIC_STREAM_SEND_READY;

        } else {
            qs->recv_max_data = qc->tp.initial_max_stream_data_uni;
            qs->recv_state = NJT_QUIC_STREAM_RECV_RECV;
            qs->send_state = NJT_QUIC_STREAM_SEND_DATA_RECVD;
        }

    } else {
        if (id & NJT_QUIC_STREAM_SERVER_INITIATED) {
            qs->send_max_data = qc->ctp.initial_max_stream_data_bidi_remote;
            qs->recv_max_data = qc->tp.initial_max_stream_data_bidi_local;

        } else {
            qs->send_max_data = qc->ctp.initial_max_stream_data_bidi_local;
            qs->recv_max_data = qc->tp.initial_max_stream_data_bidi_remote;
        }

        qs->recv_state = NJT_QUIC_STREAM_RECV_RECV;
        qs->send_state = NJT_QUIC_STREAM_SEND_READY;
    }

    qs->recv_window = qs->recv_max_data;

    cln = njt_pool_cleanup_add(pool, 0);
    if (cln == NULL) {
        njt_close_connection(sc);
        njt_destroy_pool(pool);
        njt_queue_insert_tail(&qc->streams.free, &qs->queue);
        njt_reusable_connection(c, reusable);
        return NULL;
    }

    cln->handler = njt_quic_stream_cleanup_handler;
    cln->data = sc;

    njt_rbtree_insert(&qc->streams.tree, &qs->node);

    return qs;
}


void
njt_quic_cancelable_stream(njt_connection_t *c)
{
    njt_connection_t       *pc;
    njt_quic_stream_t      *qs;
    njt_quic_connection_t  *qc;

    qs = c->quic;
    pc = qs->parent;
    qc = njt_quic_get_connection(pc);

    if (!qs->cancelable) {
        qs->cancelable = 1;

        if (njt_quic_can_shutdown(pc) == NJT_OK) {
            njt_reusable_connection(pc, 1);

            if (qc->shutdown) {
                njt_quic_shutdown_quic(pc);
            }
        }
    }
}


static void
njt_quic_empty_handler(njt_event_t *ev)
{
}


static ssize_t
njt_quic_stream_recv(njt_connection_t *c, u_char *buf, size_t size)
{
    ssize_t             len;
    njt_buf_t          *b;
    njt_chain_t        *cl, *in;
    njt_event_t        *rev;
    njt_connection_t   *pc;
    njt_quic_stream_t  *qs;

    qs = c->quic;
    pc = qs->parent;
    rev = c->read;

    if (qs->recv_state == NJT_QUIC_STREAM_RECV_RESET_RECVD
        || qs->recv_state == NJT_QUIC_STREAM_RECV_RESET_READ)
    {
        qs->recv_state = NJT_QUIC_STREAM_RECV_RESET_READ;
        return NJT_ERROR;
    }

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, pc->log, 0,
                   "quic stream id:0x%xL recv buf:%uz", qs->id, size);

    if (size == 0) {
        return 0;
    }

    in = njt_quic_read_buffer(pc, &qs->recv, size);
    if (in == NJT_CHAIN_ERROR) {
        return NJT_ERROR;
    }

    len = 0;

    for (cl = in; cl; cl = cl->next) {
        b = cl->buf;
        len += b->last - b->pos;
        buf = njt_cpymem(buf, b->pos, b->last - b->pos);
    }

    njt_quic_free_chain(pc, in);

    if (len == 0) {
        rev->ready = 0;

        if (qs->recv_state == NJT_QUIC_STREAM_RECV_DATA_RECVD
            && qs->recv_offset == qs->recv_final_size)
        {
            qs->recv_state = NJT_QUIC_STREAM_RECV_DATA_READ;
        }

        if (qs->recv_state == NJT_QUIC_STREAM_RECV_DATA_READ) {
            rev->eof = 1;
            return 0;
        }

        njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "quic stream id:0x%xL recv() not ready", qs->id);
        return NJT_AGAIN;
    }

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic stream id:0x%xL recv len:%z", qs->id, len);

    if (njt_quic_update_flow(qs, qs->recv_offset + len) != NJT_OK) {
        return NJT_ERROR;
    }

    return len;
}


static ssize_t
njt_quic_stream_send(njt_connection_t *c, u_char *buf, size_t size)
{
    njt_buf_t    b;
    njt_chain_t  cl;

    njt_memzero(&b, sizeof(njt_buf_t));

    b.memory = 1;
    b.pos = buf;
    b.last = buf + size;

    cl.buf = &b;
    cl.next = NULL;

    if (njt_quic_stream_send_chain(c, &cl, 0) == NJT_CHAIN_ERROR) {
        return NJT_ERROR;
    }

    if (b.pos == buf) {
        return NJT_AGAIN;
    }

    return b.pos - buf;
}


static njt_chain_t *
njt_quic_stream_send_chain(njt_connection_t *c, njt_chain_t *in, off_t limit)
{
    uint64_t                n, flow;
    njt_event_t            *wev;
    njt_connection_t       *pc;
    njt_quic_stream_t      *qs;
    njt_quic_connection_t  *qc;

    qs = c->quic;
    pc = qs->parent;
    qc = njt_quic_get_connection(pc);
    wev = c->write;

    if (qs->send_state != NJT_QUIC_STREAM_SEND_READY
        && qs->send_state != NJT_QUIC_STREAM_SEND_SEND)
    {
        wev->error = 1;
        return NJT_CHAIN_ERROR;
    }

    qs->send_state = NJT_QUIC_STREAM_SEND_SEND;

    flow = qs->acked + qc->conf->stream_buffer_size - qs->sent;

    if (flow == 0) {
        wev->ready = 0;
        return in;
    }

    if (limit == 0 || limit > (off_t) flow) {
        limit = flow;
    }

    n = qs->send.size;

    in = njt_quic_write_buffer(pc, &qs->send, in, limit, qs->sent);
    if (in == NJT_CHAIN_ERROR) {
        return NJT_CHAIN_ERROR;
    }

    n = qs->send.size - n;
    c->sent += n;
    qs->sent += n;
    qc->streams.sent += n;

    if (flow == n) {
        wev->ready = 0;
    }

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic send_chain sent:%uL", n);

    if (njt_quic_stream_flush(qs) != NJT_OK) {
        return NJT_CHAIN_ERROR;
    }

    return in;
}


static njt_int_t
njt_quic_stream_flush(njt_quic_stream_t *qs)
{
    off_t                   limit, len;
    njt_uint_t              last;
    njt_chain_t            *out;
    njt_quic_frame_t       *frame;
    njt_connection_t       *pc;
    njt_quic_connection_t  *qc;

    if (qs->send_state != NJT_QUIC_STREAM_SEND_SEND) {
        return NJT_OK;
    }

    pc = qs->parent;
    qc = njt_quic_get_connection(pc);

    if (qc->streams.send_max_data == 0) {
        qc->streams.send_max_data = qc->ctp.initial_max_data;
    }

    limit = njt_min(qc->streams.send_max_data - qc->streams.send_offset,
                    qs->send_max_data - qs->send_offset);

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, pc->log, 0,
                   "quic stream id:0x%xL flush limit:%O", qs->id, limit);

    len = qs->send.offset;

    out = njt_quic_read_buffer(pc, &qs->send, limit);
    if (out == NJT_CHAIN_ERROR) {
        return NJT_ERROR;
    }

    len = qs->send.offset - len;
    last = 0;

    if (qs->send_final_size != (uint64_t) -1
        && qs->send_final_size == qs->send.offset)
    {
        qs->send_state = NJT_QUIC_STREAM_SEND_DATA_SENT;
        last = 1;
    }

    if (len == 0 && !last) {
        return NJT_OK;
    }

    frame = njt_quic_alloc_frame(pc);
    if (frame == NULL) {
        return NJT_ERROR;
    }

    frame->level = ssl_encryption_application;
    frame->type = NJT_QUIC_FT_STREAM;
    frame->data = out;

    frame->u.stream.off = 1;
    frame->u.stream.len = 1;
    frame->u.stream.fin = last;

    frame->u.stream.stream_id = qs->id;
    frame->u.stream.offset = qs->send_offset;
    frame->u.stream.length = len;

    njt_quic_queue_frame(qc, frame);

    qs->send_offset += len;
    qc->streams.send_offset += len;

    njt_log_debug3(NJT_LOG_DEBUG_EVENT, pc->log, 0,
                   "quic stream id:0x%xL flush len:%O last:%ui",
                   qs->id, len, last);

    if (qs->connection == NULL) {
        return njt_quic_close_stream(qs);
    }

    return NJT_OK;
}


static void
njt_quic_stream_cleanup_handler(void *data)
{
    njt_connection_t *c = data;

    njt_quic_stream_t      *qs;
    njt_quic_connection_t  *qc;

    qs = c->quic;

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, qs->parent->log, 0,
                   "quic stream id:0x%xL cleanup", qs->id);

    if (njt_quic_shutdown_stream(c, NJT_RDWR_SHUTDOWN) != NJT_OK) {
        goto failed;
    }

    qs->connection = NULL;

    if (njt_quic_close_stream(qs) != NJT_OK) {
        goto failed;
    }

    return;

failed:

    qc = njt_quic_get_connection(qs->parent);
    qc->error = NJT_QUIC_ERR_INTERNAL_ERROR;

    njt_post_event(&qc->close, &njt_posted_events);
}


static njt_int_t
njt_quic_close_stream(njt_quic_stream_t *qs)
{
    njt_connection_t       *pc;
    njt_quic_frame_t       *frame;
    njt_quic_connection_t  *qc;

    pc = qs->parent;
    qc = njt_quic_get_connection(pc);

    if (!qc->closing) {
        /* make sure everything is sent and final size is received */

        if (qs->recv_state == NJT_QUIC_STREAM_RECV_RECV) {
            return NJT_OK;
        }

        if (qs->send_state != NJT_QUIC_STREAM_SEND_DATA_RECVD
            && qs->send_state != NJT_QUIC_STREAM_SEND_RESET_RECVD)
        {
            return NJT_OK;
        }
    }

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, pc->log, 0,
                   "quic stream id:0x%xL close", qs->id);

    njt_quic_free_buffer(pc, &qs->send);
    njt_quic_free_buffer(pc, &qs->recv);

    njt_rbtree_delete(&qc->streams.tree, &qs->node);
    njt_queue_insert_tail(&qc->streams.free, &qs->queue);

    if (qc->closing) {
        /* schedule handler call to continue njt_quic_close_connection() */
        njt_post_event(&qc->close, &njt_posted_events);
        return NJT_OK;
    }

    if (!pc->reusable && njt_quic_can_shutdown(pc) == NJT_OK) {
        njt_reusable_connection(pc, 1);
    }

    if (qc->shutdown) {
        njt_quic_shutdown_quic(pc);
        return NJT_OK;
    }

    if ((qs->id & NJT_QUIC_STREAM_SERVER_INITIATED) == 0) {
        frame = njt_quic_alloc_frame(pc);
        if (frame == NULL) {
            return NJT_ERROR;
        }

        frame->level = ssl_encryption_application;
        frame->type = NJT_QUIC_FT_MAX_STREAMS;

        if (qs->id & NJT_QUIC_STREAM_UNIDIRECTIONAL) {
            frame->u.max_streams.limit = ++qc->streams.client_max_streams_uni;
            frame->u.max_streams.bidi = 0;

        } else {
            frame->u.max_streams.limit = ++qc->streams.client_max_streams_bidi;
            frame->u.max_streams.bidi = 1;
        }

        njt_quic_queue_frame(qc, frame);
    }

    return NJT_OK;
}


static njt_int_t
njt_quic_can_shutdown(njt_connection_t *c)
{
    njt_rbtree_t           *tree;
    njt_rbtree_node_t      *node;
    njt_quic_stream_t      *qs;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    tree = &qc->streams.tree;

    if (tree->root != tree->sentinel) {
        for (node = njt_rbtree_min(tree->root, tree->sentinel);
             node;
             node = njt_rbtree_next(tree, node))
        {
            qs = (njt_quic_stream_t *) node;

            if (!qs->cancelable) {
                return NJT_DECLINED;
            }
        }
    }

    return NJT_OK;
}


njt_int_t
njt_quic_handle_stream_frame(njt_connection_t *c, njt_quic_header_t *pkt,
    njt_quic_frame_t *frame)
{
    uint64_t                  last;
    njt_quic_stream_t        *qs;
    njt_quic_connection_t    *qc;
    njt_quic_stream_frame_t  *f;

    qc = njt_quic_get_connection(c);
    f = &frame->u.stream;

    if ((f->stream_id & NJT_QUIC_STREAM_UNIDIRECTIONAL)
        && (f->stream_id & NJT_QUIC_STREAM_SERVER_INITIATED))
    {
        qc->error = NJT_QUIC_ERR_STREAM_STATE_ERROR;
        return NJT_ERROR;
    }

    /* no overflow since both values are 62-bit */
    last = f->offset + f->length;

    qs = njt_quic_get_stream(c, f->stream_id);

    if (qs == NULL) {
        return NJT_ERROR;
    }

    if (qs == NJT_QUIC_STREAM_GONE) {
        return NJT_OK;
    }

    if (qs->recv_state != NJT_QUIC_STREAM_RECV_RECV
        && qs->recv_state != NJT_QUIC_STREAM_RECV_SIZE_KNOWN)
    {
        return NJT_OK;
    }

    if (njt_quic_control_flow(qs, last) != NJT_OK) {
        return NJT_ERROR;
    }

    if (qs->recv_final_size != (uint64_t) -1 && last > qs->recv_final_size) {
        qc->error = NJT_QUIC_ERR_FINAL_SIZE_ERROR;
        return NJT_ERROR;
    }

    if (last < qs->recv_offset) {
        return NJT_OK;
    }

    if (f->fin) {
        if (qs->recv_final_size != (uint64_t) -1 && qs->recv_final_size != last)
        {
            qc->error = NJT_QUIC_ERR_FINAL_SIZE_ERROR;
            return NJT_ERROR;
        }

        if (qs->recv_last > last) {
            qc->error = NJT_QUIC_ERR_FINAL_SIZE_ERROR;
            return NJT_ERROR;
        }

        qs->recv_final_size = last;
        qs->recv_state = NJT_QUIC_STREAM_RECV_SIZE_KNOWN;
    }

    if (njt_quic_write_buffer(c, &qs->recv, frame->data, f->length, f->offset)
        == NJT_CHAIN_ERROR)
    {
        return NJT_ERROR;
    }

    if (qs->recv_state == NJT_QUIC_STREAM_RECV_SIZE_KNOWN
        && qs->recv.size == qs->recv_final_size)
    {
        qs->recv_state = NJT_QUIC_STREAM_RECV_DATA_RECVD;
    }

    if (qs->connection == NULL) {
        return njt_quic_close_stream(qs);
    }

    if (f->offset <= qs->recv_offset) {
        njt_quic_set_event(qs->connection->read);
    }

    return NJT_OK;
}


njt_int_t
njt_quic_handle_max_data_frame(njt_connection_t *c,
    njt_quic_max_data_frame_t *f)
{
    njt_rbtree_t           *tree;
    njt_rbtree_node_t      *node;
    njt_quic_stream_t      *qs;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);
    tree = &qc->streams.tree;

    if (f->max_data <= qc->streams.send_max_data) {
        return NJT_OK;
    }

    if (tree->root == tree->sentinel
        || qc->streams.send_offset < qc->streams.send_max_data)
    {
        /* not blocked on MAX_DATA */
        qc->streams.send_max_data = f->max_data;
        return NJT_OK;
    }

    qc->streams.send_max_data = f->max_data;
    node = njt_rbtree_min(tree->root, tree->sentinel);

    while (node && qc->streams.send_offset < qc->streams.send_max_data) {

        qs = (njt_quic_stream_t *) node;
        node = njt_rbtree_next(tree, node);

        if (njt_quic_stream_flush(qs) != NJT_OK) {
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}


njt_int_t
njt_quic_handle_streams_blocked_frame(njt_connection_t *c,
    njt_quic_header_t *pkt, njt_quic_streams_blocked_frame_t *f)
{
    return NJT_OK;
}


njt_int_t
njt_quic_handle_data_blocked_frame(njt_connection_t *c,
    njt_quic_header_t *pkt, njt_quic_data_blocked_frame_t *f)
{
    return njt_quic_update_max_data(c);
}


njt_int_t
njt_quic_handle_stream_data_blocked_frame(njt_connection_t *c,
    njt_quic_header_t *pkt, njt_quic_stream_data_blocked_frame_t *f)
{
    njt_quic_stream_t      *qs;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    if ((f->id & NJT_QUIC_STREAM_UNIDIRECTIONAL)
        && (f->id & NJT_QUIC_STREAM_SERVER_INITIATED))
    {
        qc->error = NJT_QUIC_ERR_STREAM_STATE_ERROR;
        return NJT_ERROR;
    }

    qs = njt_quic_get_stream(c, f->id);

    if (qs == NULL) {
        return NJT_ERROR;
    }

    if (qs == NJT_QUIC_STREAM_GONE) {
        return NJT_OK;
    }

    return njt_quic_update_max_stream_data(qs);
}


njt_int_t
njt_quic_handle_max_stream_data_frame(njt_connection_t *c,
    njt_quic_header_t *pkt, njt_quic_max_stream_data_frame_t *f)
{
    njt_quic_stream_t      *qs;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    if ((f->id & NJT_QUIC_STREAM_UNIDIRECTIONAL)
        && (f->id & NJT_QUIC_STREAM_SERVER_INITIATED) == 0)
    {
        qc->error = NJT_QUIC_ERR_STREAM_STATE_ERROR;
        return NJT_ERROR;
    }

    qs = njt_quic_get_stream(c, f->id);

    if (qs == NULL) {
        return NJT_ERROR;
    }

    if (qs == NJT_QUIC_STREAM_GONE) {
        return NJT_OK;
    }

    if (f->limit <= qs->send_max_data) {
        return NJT_OK;
    }

    if (qs->send_offset < qs->send_max_data) {
        /* not blocked on MAX_STREAM_DATA */
        qs->send_max_data = f->limit;
        return NJT_OK;
    }

    qs->send_max_data = f->limit;

    return njt_quic_stream_flush(qs);
}


njt_int_t
njt_quic_handle_reset_stream_frame(njt_connection_t *c,
    njt_quic_header_t *pkt, njt_quic_reset_stream_frame_t *f)
{
    njt_event_t            *rev;
    njt_quic_stream_t      *qs;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    if ((f->id & NJT_QUIC_STREAM_UNIDIRECTIONAL)
        && (f->id & NJT_QUIC_STREAM_SERVER_INITIATED))
    {
        qc->error = NJT_QUIC_ERR_STREAM_STATE_ERROR;
        return NJT_ERROR;
    }

    qs = njt_quic_get_stream(c, f->id);

    if (qs == NULL) {
        return NJT_ERROR;
    }

    if (qs == NJT_QUIC_STREAM_GONE) {
        return NJT_OK;
    }

    if (qs->recv_state == NJT_QUIC_STREAM_RECV_RESET_RECVD
        || qs->recv_state == NJT_QUIC_STREAM_RECV_RESET_READ)
    {
        return NJT_OK;
    }

    qs->recv_state = NJT_QUIC_STREAM_RECV_RESET_RECVD;

    if (njt_quic_control_flow(qs, f->final_size) != NJT_OK) {
        return NJT_ERROR;
    }

    if (qs->recv_final_size != (uint64_t) -1
        && qs->recv_final_size != f->final_size)
    {
        qc->error = NJT_QUIC_ERR_FINAL_SIZE_ERROR;
        return NJT_ERROR;
    }

    if (qs->recv_last > f->final_size) {
        qc->error = NJT_QUIC_ERR_FINAL_SIZE_ERROR;
        return NJT_ERROR;
    }

    qs->recv_final_size = f->final_size;

    if (njt_quic_update_flow(qs, qs->recv_final_size) != NJT_OK) {
        return NJT_ERROR;
    }

    if (qs->connection == NULL) {
        return njt_quic_close_stream(qs);
    }

    rev = qs->connection->read;
    rev->error = 1;

    njt_quic_set_event(rev);

    return NJT_OK;
}


njt_int_t
njt_quic_handle_stop_sending_frame(njt_connection_t *c,
    njt_quic_header_t *pkt, njt_quic_stop_sending_frame_t *f)
{
    njt_quic_stream_t      *qs;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    if ((f->id & NJT_QUIC_STREAM_UNIDIRECTIONAL)
        && (f->id & NJT_QUIC_STREAM_SERVER_INITIATED) == 0)
    {
        qc->error = NJT_QUIC_ERR_STREAM_STATE_ERROR;
        return NJT_ERROR;
    }

    qs = njt_quic_get_stream(c, f->id);

    if (qs == NULL) {
        return NJT_ERROR;
    }

    if (qs == NJT_QUIC_STREAM_GONE) {
        return NJT_OK;
    }

    if (njt_quic_do_reset_stream(qs, f->error_code) != NJT_OK) {
        return NJT_ERROR;
    }

    if (qs->connection == NULL) {
        return njt_quic_close_stream(qs);
    }

    njt_quic_set_event(qs->connection->write);

    return NJT_OK;
}


njt_int_t
njt_quic_handle_max_streams_frame(njt_connection_t *c,
    njt_quic_header_t *pkt, njt_quic_max_streams_frame_t *f)
{
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    if (f->bidi) {
        if (qc->streams.server_max_streams_bidi < f->limit) {
            qc->streams.server_max_streams_bidi = f->limit;

            njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                           "quic max_streams_bidi:%uL", f->limit);
        }

    } else {
        if (qc->streams.server_max_streams_uni < f->limit) {
            qc->streams.server_max_streams_uni = f->limit;

            njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                           "quic max_streams_uni:%uL", f->limit);
        }
    }

    return NJT_OK;
}


void
njt_quic_handle_stream_ack(njt_connection_t *c, njt_quic_frame_t *f)
{
    uint64_t                acked;
    njt_quic_stream_t      *qs;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    switch (f->type) {

    case NJT_QUIC_FT_RESET_STREAM:

        qs = njt_quic_find_stream(&qc->streams.tree, f->u.reset_stream.id);
        if (qs == NULL) {
            return;
        }

        qs->send_state = NJT_QUIC_STREAM_SEND_RESET_RECVD;

        njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "quic stream id:0x%xL ack reset final_size:%uL",
                       qs->id, f->u.reset_stream.final_size);

        break;

    case NJT_QUIC_FT_STREAM:

        qs = njt_quic_find_stream(&qc->streams.tree, f->u.stream.stream_id);
        if (qs == NULL) {
            return;
        }

        acked = qs->acked;
        qs->acked += f->u.stream.length;

        if (f->u.stream.fin) {
            qs->fin_acked = 1;
        }

        if (qs->send_state == NJT_QUIC_STREAM_SEND_DATA_SENT
            && qs->acked == qs->sent && qs->fin_acked)
        {
            qs->send_state = NJT_QUIC_STREAM_SEND_DATA_RECVD;
        }

        njt_log_debug4(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "quic stream id:0x%xL ack len:%uL fin:%d unacked:%uL",
                       qs->id, f->u.stream.length, f->u.stream.fin,
                       qs->sent - qs->acked);

        if (qs->connection
            && qs->sent - acked == qc->conf->stream_buffer_size
            && f->u.stream.length > 0)
        {
            njt_quic_set_event(qs->connection->write);
        }

        break;

    default:
        return;
    }

    if (qs->connection == NULL) {
        njt_quic_close_stream(qs);
    }
}


static njt_int_t
njt_quic_control_flow(njt_quic_stream_t *qs, uint64_t last)
{
    uint64_t                len;
    njt_connection_t       *pc;
    njt_quic_connection_t  *qc;

    pc = qs->parent;
    qc = njt_quic_get_connection(pc);

    if (last <= qs->recv_last) {
        return NJT_OK;
    }

    len = last - qs->recv_last;

    njt_log_debug5(NJT_LOG_DEBUG_EVENT, pc->log, 0,
                   "quic stream id:0x%xL flow control msd:%uL/%uL md:%uL/%uL",
                   qs->id, last, qs->recv_max_data, qc->streams.recv_last + len,
                   qc->streams.recv_max_data);

    qs->recv_last += len;

    if (qs->recv_state == NJT_QUIC_STREAM_RECV_RECV
        && qs->recv_last > qs->recv_max_data)
    {
        qc->error = NJT_QUIC_ERR_FLOW_CONTROL_ERROR;
        return NJT_ERROR;
    }

    qc->streams.recv_last += len;

    if (qc->streams.recv_last > qc->streams.recv_max_data) {
        qc->error = NJT_QUIC_ERR_FLOW_CONTROL_ERROR;
        return NJT_ERROR;
    }

    return NJT_OK;
}


static njt_int_t
njt_quic_update_flow(njt_quic_stream_t *qs, uint64_t last)
{
    uint64_t                len;
    njt_connection_t       *pc;
    njt_quic_connection_t  *qc;

    pc = qs->parent;
    qc = njt_quic_get_connection(pc);

    if (last <= qs->recv_offset) {
        return NJT_OK;
    }

    len = last - qs->recv_offset;

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, pc->log, 0,
                   "quic stream id:0x%xL flow update %uL", qs->id, last);

    qs->recv_offset += len;

    if (qs->recv_max_data <= qs->recv_offset + qs->recv_window / 2) {
        if (njt_quic_update_max_stream_data(qs) != NJT_OK) {
            return NJT_ERROR;
        }
    }

    qc->streams.recv_offset += len;

    if (qc->streams.recv_max_data
        <= qc->streams.recv_offset + qc->streams.recv_window / 2)
    {
        if (njt_quic_update_max_data(pc) != NJT_OK) {
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}


static njt_int_t
njt_quic_update_max_stream_data(njt_quic_stream_t *qs)
{
    uint64_t                recv_max_data;
    njt_connection_t       *pc;
    njt_quic_frame_t       *frame;
    njt_quic_connection_t  *qc;

    pc = qs->parent;
    qc = njt_quic_get_connection(pc);

    if (qs->recv_state != NJT_QUIC_STREAM_RECV_RECV) {
        return NJT_OK;
    }

    recv_max_data = qs->recv_offset + qs->recv_window;

    if (qs->recv_max_data == recv_max_data) {
        return NJT_OK;
    }

    qs->recv_max_data = recv_max_data;

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, pc->log, 0,
                   "quic stream id:0x%xL flow update msd:%uL",
                   qs->id, qs->recv_max_data);

    frame = njt_quic_alloc_frame(pc);
    if (frame == NULL) {
        return NJT_ERROR;
    }

    frame->level = ssl_encryption_application;
    frame->type = NJT_QUIC_FT_MAX_STREAM_DATA;
    frame->u.max_stream_data.id = qs->id;
    frame->u.max_stream_data.limit = qs->recv_max_data;

    njt_quic_queue_frame(qc, frame);

    return NJT_OK;
}


static njt_int_t
njt_quic_update_max_data(njt_connection_t *c)
{
    uint64_t                recv_max_data;
    njt_quic_frame_t       *frame;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    recv_max_data = qc->streams.recv_offset + qc->streams.recv_window;

    if (qc->streams.recv_max_data == recv_max_data) {
        return NJT_OK;
    }

    qc->streams.recv_max_data = recv_max_data;

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic flow update md:%uL", qc->streams.recv_max_data);

    frame = njt_quic_alloc_frame(c);
    if (frame == NULL) {
        return NJT_ERROR;
    }

    frame->level = ssl_encryption_application;
    frame->type = NJT_QUIC_FT_MAX_DATA;
    frame->u.max_data.max_data = qc->streams.recv_max_data;

    njt_quic_queue_frame(qc, frame);

    return NJT_OK;
}


static void
njt_quic_set_event(njt_event_t *ev)
{
    ev->ready = 1;

    if (ev->active) {
        njt_post_event(ev, &njt_posted_events);
    }
}
