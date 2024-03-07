/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>
#include <njt_event_quic_connection.h>


#define NJT_QUIC_BUFFER_SIZE  4096

#define njt_quic_buf_refs(b)         (b)->shadow->num
#define njt_quic_buf_inc_refs(b)     njt_quic_buf_refs(b)++
#define njt_quic_buf_dec_refs(b)     njt_quic_buf_refs(b)--
#define njt_quic_buf_set_refs(b, v)  njt_quic_buf_refs(b) = v


static njt_buf_t *njt_quic_alloc_buf(njt_connection_t *c);
static void njt_quic_free_buf(njt_connection_t *c, njt_buf_t *b);
static njt_buf_t *njt_quic_clone_buf(njt_connection_t *c, njt_buf_t *b);
static njt_int_t njt_quic_split_chain(njt_connection_t *c, njt_chain_t *cl,
    off_t offset);


static njt_buf_t *
njt_quic_alloc_buf(njt_connection_t *c)
{
    u_char                 *p;
    njt_buf_t              *b;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    b = qc->free_bufs;

    if (b) {
        qc->free_bufs = b->shadow;
        p = b->start;

    } else {
        b = qc->free_shadow_bufs;

        if (b) {
            qc->free_shadow_bufs = b->shadow;

#ifdef NJT_QUIC_DEBUG_ALLOC
            njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                           "quic use shadow buffer n:%ui %ui",
                           ++qc->nbufs, --qc->nshadowbufs);
#endif

        } else {
            b = njt_palloc(c->pool, sizeof(njt_buf_t));
            if (b == NULL) {
                return NULL;
            }

#ifdef NJT_QUIC_DEBUG_ALLOC
            njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                           "quic new buffer n:%ui", ++qc->nbufs);
#endif
        }

        p = njt_pnalloc(c->pool, NJT_QUIC_BUFFER_SIZE);
        if (p == NULL) {
            return NULL;
        }
    }

#ifdef NJT_QUIC_DEBUG_ALLOC
    njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0, "quic alloc buffer %p", b);
#endif

    njt_memzero(b, sizeof(njt_buf_t));

    b->tag = (njt_buf_tag_t) &njt_quic_alloc_buf;
    b->temporary = 1;
    b->shadow = b;

    b->start = p;
    b->pos = p;
    b->last = p;
    b->end = p + NJT_QUIC_BUFFER_SIZE;

    njt_quic_buf_set_refs(b, 1);

    return b;
}


static void
njt_quic_free_buf(njt_connection_t *c, njt_buf_t *b)
{
    njt_buf_t              *shadow;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    njt_quic_buf_dec_refs(b);

#ifdef NJT_QUIC_DEBUG_ALLOC
    njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic free buffer %p r:%ui",
                   b, (njt_uint_t) njt_quic_buf_refs(b));
#endif

    shadow = b->shadow;

    if (njt_quic_buf_refs(b) == 0) {
        shadow->shadow = qc->free_bufs;
        qc->free_bufs = shadow;
    }

    if (b != shadow) {
        b->shadow = qc->free_shadow_bufs;
        qc->free_shadow_bufs = b;
    }

}


static njt_buf_t *
njt_quic_clone_buf(njt_connection_t *c, njt_buf_t *b)
{
    njt_buf_t              *nb;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    nb = qc->free_shadow_bufs;

    if (nb) {
        qc->free_shadow_bufs = nb->shadow;

    } else {
        nb = njt_palloc(c->pool, sizeof(njt_buf_t));
        if (nb == NULL) {
            return NULL;
        }

#ifdef NJT_QUIC_DEBUG_ALLOC
        njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "quic new shadow buffer n:%ui", ++qc->nshadowbufs);
#endif
    }

    *nb = *b;

    njt_quic_buf_inc_refs(b);

#ifdef NJT_QUIC_DEBUG_ALLOC
    njt_log_debug3(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic clone buffer %p %p r:%ui",
                   b, nb, (njt_uint_t) njt_quic_buf_refs(b));
#endif

    return nb;
}


static njt_int_t
njt_quic_split_chain(njt_connection_t *c, njt_chain_t *cl, off_t offset)
{
    njt_buf_t    *b, *tb;
    njt_chain_t  *tail;

    b = cl->buf;

    tail = njt_alloc_chain_link(c->pool);
    if (tail == NULL) {
        return NJT_ERROR;
    }

    tb = njt_quic_clone_buf(c, b);
    if (tb == NULL) {
        return NJT_ERROR;
    }

    tail->buf = tb;

    tb->pos += offset;

    b->last = tb->pos;
    b->last_buf = 0;

    tail->next = cl->next;
    cl->next = tail;

    return NJT_OK;
}


njt_quic_frame_t *
njt_quic_alloc_frame(njt_connection_t *c)
{
    njt_queue_t            *q;
    njt_quic_frame_t       *frame;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    if (!njt_queue_empty(&qc->free_frames)) {

        q = njt_queue_head(&qc->free_frames);
        frame = njt_queue_data(q, njt_quic_frame_t, queue);

        njt_queue_remove(&frame->queue);

#ifdef NJT_QUIC_DEBUG_ALLOC
        njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "quic reuse frame n:%ui", qc->nframes);
#endif

    } else if (qc->nframes < 10000) {
        frame = njt_palloc(c->pool, sizeof(njt_quic_frame_t));
        if (frame == NULL) {
            return NULL;
        }

        ++qc->nframes;

#ifdef NJT_QUIC_DEBUG_ALLOC
        njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "quic alloc frame n:%ui", qc->nframes);
#endif

    } else {
        njt_log_error(NJT_LOG_INFO, c->log, 0, "quic flood detected");
        return NULL;
    }

    njt_memzero(frame, sizeof(njt_quic_frame_t));

    return frame;
}


void
njt_quic_free_frame(njt_connection_t *c, njt_quic_frame_t *frame)
{
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    if (frame->data) {
        njt_quic_free_chain(c, frame->data);
    }

    njt_queue_insert_head(&qc->free_frames, &frame->queue);

#ifdef NJT_QUIC_DEBUG_ALLOC
    njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic free frame n:%ui", qc->nframes);
#endif
}


void
njt_quic_free_chain(njt_connection_t *c, njt_chain_t *in)
{
    njt_chain_t  *cl;

    while (in) {
        cl = in;
        in = in->next;

        njt_quic_free_buf(c, cl->buf);
        njt_free_chain(c->pool, cl);
    }
}


void
njt_quic_free_frames(njt_connection_t *c, njt_queue_t *frames)
{
    njt_queue_t       *q;
    njt_quic_frame_t  *f;

    do {
        q = njt_queue_head(frames);

        if (q == njt_queue_sentinel(frames)) {
            break;
        }

        njt_queue_remove(q);

        f = njt_queue_data(q, njt_quic_frame_t, queue);

        njt_quic_free_frame(c, f);
    } while (1);
}


void
njt_quic_queue_frame(njt_quic_connection_t *qc, njt_quic_frame_t *frame)
{
    njt_quic_send_ctx_t  *ctx;

    ctx = njt_quic_get_send_ctx(qc, frame->level);

    njt_queue_insert_tail(&ctx->frames, &frame->queue);

    frame->len = njt_quic_create_frame(NULL, frame);
    /* always succeeds */

    if (qc->closing) {
        return;
    }

    njt_post_event(&qc->push, &njt_posted_events);
}


njt_int_t
njt_quic_split_frame(njt_connection_t *c, njt_quic_frame_t *f, size_t len)
{
    size_t                     shrink;
    njt_chain_t               *out;
    njt_quic_frame_t          *nf;
    njt_quic_buffer_t          qb;
    njt_quic_ordered_frame_t  *of, *onf;

    switch (f->type) {
    case NJT_QUIC_FT_CRYPTO:
    case NJT_QUIC_FT_STREAM:
        break;

    default:
        return NJT_DECLINED;
    }

    if ((size_t) f->len <= len) {
        return NJT_OK;
    }

    shrink = f->len - len;

    njt_log_debug3(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic split frame now:%uz need:%uz shrink:%uz",
                   f->len, len, shrink);

    of = &f->u.ord;

    if (of->length <= shrink) {
        return NJT_DECLINED;
    }

    of->length -= shrink;
    f->len = njt_quic_create_frame(NULL, f);

    if ((size_t) f->len > len) {
        njt_log_error(NJT_LOG_ERR, c->log, 0, "could not split QUIC frame");
        return NJT_ERROR;
    }

    njt_memzero(&qb, sizeof(njt_quic_buffer_t));
    qb.chain = f->data;

    out = njt_quic_read_buffer(c, &qb, of->length);
    if (out == NJT_CHAIN_ERROR) {
        return NJT_ERROR;
    }

    f->data = out;

    nf = njt_quic_alloc_frame(c);
    if (nf == NULL) {
        return NJT_ERROR;
    }

    *nf = *f;
    onf = &nf->u.ord;
    onf->offset += of->length;
    onf->length = shrink;
    nf->len = njt_quic_create_frame(NULL, nf);
    nf->data = qb.chain;

    if (f->type == NJT_QUIC_FT_STREAM) {
        f->u.stream.fin = 0;
    }

    njt_queue_insert_after(&f->queue, &nf->queue);

    return NJT_OK;
}


njt_chain_t *
njt_quic_copy_buffer(njt_connection_t *c, u_char *data, size_t len)
{
    njt_buf_t          buf;
    njt_chain_t        cl, *out;
    njt_quic_buffer_t  qb;

    njt_memzero(&buf, sizeof(njt_buf_t));

    buf.pos = data;
    buf.last = buf.pos + len;
    buf.temporary = 1;

    cl.buf = &buf;
    cl.next = NULL;

    njt_memzero(&qb, sizeof(njt_quic_buffer_t));

    if (njt_quic_write_buffer(c, &qb, &cl, len, 0) == NJT_CHAIN_ERROR) {
        return NJT_CHAIN_ERROR;
    }

    out = njt_quic_read_buffer(c, &qb, len);
    if (out == NJT_CHAIN_ERROR) {
        return NJT_CHAIN_ERROR;
    }

    njt_quic_free_buffer(c, &qb);

    return out;
}


njt_chain_t *
njt_quic_read_buffer(njt_connection_t *c, njt_quic_buffer_t *qb, uint64_t limit)
{
    uint64_t      n;
    njt_buf_t    *b;
    njt_chain_t  *out, **ll;

    out = qb->chain;

    for (ll = &out; *ll; ll = &(*ll)->next) {
        b = (*ll)->buf;

        if (b->sync) {
            /* hole */
            break;
        }

        if (limit == 0) {
            break;
        }

        n = b->last - b->pos;

        if (n > limit) {
            if (njt_quic_split_chain(c, *ll, limit) != NJT_OK) {
                return NJT_CHAIN_ERROR;
            }

            n = limit;
        }

        limit -= n;
        qb->offset += n;
    }

    if (qb->offset >= qb->last_offset) {
        qb->last_chain = NULL;
    }

    qb->chain = *ll;
    *ll = NULL;

    return out;
}


void
njt_quic_skip_buffer(njt_connection_t *c, njt_quic_buffer_t *qb,
    uint64_t offset)
{
    size_t        n;
    njt_buf_t    *b;
    njt_chain_t  *cl;

    while (qb->chain) {
        if (qb->offset >= offset) {
            break;
        }

        cl = qb->chain;
        b = cl->buf;
        n = b->last - b->pos;

        if (qb->offset + n > offset) {
            n = offset - qb->offset;
            b->pos += n;
            qb->offset += n;
            break;
        }

        qb->offset += n;
        qb->chain = cl->next;

        cl->next = NULL;
        njt_quic_free_chain(c, cl);
    }

    if (qb->chain == NULL) {
        qb->offset = offset;
    }

    if (qb->offset >= qb->last_offset) {
        qb->last_chain = NULL;
    }
}


njt_chain_t *
njt_quic_alloc_chain(njt_connection_t *c)
{
    njt_chain_t  *cl;

    cl = njt_alloc_chain_link(c->pool);
    if (cl == NULL) {
        return NULL;
    }

    cl->buf = njt_quic_alloc_buf(c);
    if (cl->buf == NULL) {
        return NULL;
    }

    return cl;
}


njt_chain_t *
njt_quic_write_buffer(njt_connection_t *c, njt_quic_buffer_t *qb,
    njt_chain_t *in, uint64_t limit, uint64_t offset)
{
    u_char       *p;
    uint64_t      n, base;
    njt_buf_t    *b;
    njt_chain_t  *cl, **chain;

    if (qb->last_chain && offset >= qb->last_offset) {
        base = qb->last_offset;
        chain = &qb->last_chain;

    } else {
        base = qb->offset;
        chain = &qb->chain;
    }

    while (in && limit) {

        if (offset < base) {
            n = njt_min((uint64_t) (in->buf->last - in->buf->pos),
                        njt_min(base - offset, limit));

            in->buf->pos += n;
            offset += n;
            limit -= n;

            if (in->buf->pos == in->buf->last) {
                in = in->next;
            }

            continue;
        }

        cl = *chain;

        if (cl == NULL) {
            cl = njt_quic_alloc_chain(c);
            if (cl == NULL) {
                return NJT_CHAIN_ERROR;
            }

            cl->buf->last = cl->buf->end;
            cl->buf->sync = 1; /* hole */
            cl->next = NULL;
            *chain = cl;
        }

        b = cl->buf;
        n = b->last - b->pos;

        if (base + n <= offset) {
            base += n;
            chain = &cl->next;
            continue;
        }

        if (b->sync && offset > base) {
            if (njt_quic_split_chain(c, cl, offset - base) != NJT_OK) {
                return NJT_CHAIN_ERROR;
            }

            continue;
        }

        p = b->pos + (offset - base);

        while (in) {

            if (!njt_buf_in_memory(in->buf) || in->buf->pos == in->buf->last) {
                in = in->next;
                continue;
            }

            if (p == b->last || limit == 0) {
                break;
            }

            n = njt_min(b->last - p, in->buf->last - in->buf->pos);
            n = njt_min(n, limit);

            if (b->sync) {
                njt_memcpy(p, in->buf->pos, n);
                qb->size += n;
            }

            p += n;
            in->buf->pos += n;
            offset += n;
            limit -= n;
        }

        if (b->sync && p == b->last) {
            b->sync = 0;
            continue;
        }

        if (b->sync && p != b->pos) {
            if (njt_quic_split_chain(c, cl, p - b->pos) != NJT_OK) {
                return NJT_CHAIN_ERROR;
            }

            b->sync = 0;
        }
    }

    qb->last_offset = base;
    qb->last_chain = *chain;

    return in;
}


void
njt_quic_free_buffer(njt_connection_t *c, njt_quic_buffer_t *qb)
{
    njt_quic_free_chain(c, qb->chain);

    qb->chain = NULL;
}


#if (NJT_DEBUG)

void
njt_quic_log_frame(njt_log_t *log, njt_quic_frame_t *f, njt_uint_t tx)
{
    u_char      *p, *last, *pos, *end;
    ssize_t      n;
    uint64_t     gap, range, largest, smallest;
    njt_uint_t   i;
    u_char       buf[NJT_MAX_ERROR_STR];

    p = buf;
    last = buf + sizeof(buf);

    switch (f->type) {

    case NJT_QUIC_FT_CRYPTO:
        p = njt_slprintf(p, last, "CRYPTO len:%uL off:%uL",
                         f->u.crypto.length, f->u.crypto.offset);

#ifdef NJT_QUIC_DEBUG_FRAMES
        {
            njt_chain_t  *cl;

            p = njt_slprintf(p, last, " data:");

            for (cl = f->data; cl; cl = cl->next) {
                p = njt_slprintf(p, last, "%*xs",
                                 cl->buf->last - cl->buf->pos, cl->buf->pos);
            }
        }
#endif

        break;

    case NJT_QUIC_FT_PADDING:
        p = njt_slprintf(p, last, "PADDING");
        break;

    case NJT_QUIC_FT_ACK:
    case NJT_QUIC_FT_ACK_ECN:

        p = njt_slprintf(p, last, "ACK n:%ui delay:%uL ",
                         f->u.ack.range_count, f->u.ack.delay);

        if (f->data) {
            pos = f->data->buf->pos;
            end = f->data->buf->last;

        } else {
            pos = NULL;
            end = NULL;
        }

        largest = f->u.ack.largest;
        smallest = f->u.ack.largest - f->u.ack.first_range;

        if (largest == smallest) {
            p = njt_slprintf(p, last, "%uL", largest);

        } else {
            p = njt_slprintf(p, last, "%uL-%uL", largest, smallest);
        }

        for (i = 0; i < f->u.ack.range_count; i++) {
            n = njt_quic_parse_ack_range(log, pos, end, &gap, &range);
            if (n == NJT_ERROR) {
                break;
            }

            pos += n;

            largest = smallest - gap - 2;
            smallest = largest - range;

            if (largest == smallest) {
                p = njt_slprintf(p, last, " %uL", largest);

            } else {
                p = njt_slprintf(p, last, " %uL-%uL", largest, smallest);
            }
        }

        if (f->type == NJT_QUIC_FT_ACK_ECN) {
            p = njt_slprintf(p, last, " ECN counters ect0:%uL ect1:%uL ce:%uL",
                             f->u.ack.ect0, f->u.ack.ect1, f->u.ack.ce);
        }
        break;

    case NJT_QUIC_FT_PING:
        p = njt_slprintf(p, last, "PING");
        break;

    case NJT_QUIC_FT_NEW_CONNECTION_ID:
        p = njt_slprintf(p, last,
                         "NEW_CONNECTION_ID seq:%uL retire:%uL len:%ud",
                         f->u.ncid.seqnum, f->u.ncid.retire, f->u.ncid.len);
        break;

    case NJT_QUIC_FT_RETIRE_CONNECTION_ID:
        p = njt_slprintf(p, last, "RETIRE_CONNECTION_ID seqnum:%uL",
                         f->u.retire_cid.sequence_number);
        break;

    case NJT_QUIC_FT_CONNECTION_CLOSE:
    case NJT_QUIC_FT_CONNECTION_CLOSE_APP:
        p = njt_slprintf(p, last, "CONNECTION_CLOSE%s err:%ui",
                         f->type == NJT_QUIC_FT_CONNECTION_CLOSE ? "" : "_APP",
                         f->u.close.error_code);

        if (f->u.close.reason.len) {
            p = njt_slprintf(p, last, " %V", &f->u.close.reason);
        }

        if (f->type == NJT_QUIC_FT_CONNECTION_CLOSE) {
            p = njt_slprintf(p, last, " ft:%ui", f->u.close.frame_type);
        }

        break;

    case NJT_QUIC_FT_STREAM:
        p = njt_slprintf(p, last, "STREAM id:0x%xL", f->u.stream.stream_id);

        if (f->u.stream.off) {
            p = njt_slprintf(p, last, " off:%uL", f->u.stream.offset);
        }

        if (f->u.stream.len) {
            p = njt_slprintf(p, last, " len:%uL", f->u.stream.length);
        }

        if (f->u.stream.fin) {
            p = njt_slprintf(p, last, " fin:1");
        }

#ifdef NJT_QUIC_DEBUG_FRAMES
        {
            njt_chain_t  *cl;

            p = njt_slprintf(p, last, " data:");

            for (cl = f->data; cl; cl = cl->next) {
                p = njt_slprintf(p, last, "%*xs",
                                 cl->buf->last - cl->buf->pos, cl->buf->pos);
            }
        }
#endif

        break;

    case NJT_QUIC_FT_MAX_DATA:
        p = njt_slprintf(p, last, "MAX_DATA max_data:%uL on recv",
                         f->u.max_data.max_data);
        break;

    case NJT_QUIC_FT_RESET_STREAM:
        p = njt_slprintf(p, last, "RESET_STREAM"
                        " id:0x%xL error_code:0x%xL final_size:0x%xL",
                        f->u.reset_stream.id, f->u.reset_stream.error_code,
                        f->u.reset_stream.final_size);
        break;

    case NJT_QUIC_FT_STOP_SENDING:
        p = njt_slprintf(p, last, "STOP_SENDING id:0x%xL err:0x%xL",
                         f->u.stop_sending.id, f->u.stop_sending.error_code);
        break;

    case NJT_QUIC_FT_STREAMS_BLOCKED:
    case NJT_QUIC_FT_STREAMS_BLOCKED2:
        p = njt_slprintf(p, last, "STREAMS_BLOCKED limit:%uL bidi:%ui",
                         f->u.streams_blocked.limit, f->u.streams_blocked.bidi);
        break;

    case NJT_QUIC_FT_MAX_STREAMS:
    case NJT_QUIC_FT_MAX_STREAMS2:
        p = njt_slprintf(p, last, "MAX_STREAMS limit:%uL bidi:%ui",
                         f->u.max_streams.limit, f->u.max_streams.bidi);
        break;

    case NJT_QUIC_FT_MAX_STREAM_DATA:
        p = njt_slprintf(p, last, "MAX_STREAM_DATA id:0x%xL limit:%uL",
                         f->u.max_stream_data.id, f->u.max_stream_data.limit);
        break;


    case NJT_QUIC_FT_DATA_BLOCKED:
        p = njt_slprintf(p, last, "DATA_BLOCKED limit:%uL",
                         f->u.data_blocked.limit);
        break;

    case NJT_QUIC_FT_STREAM_DATA_BLOCKED:
        p = njt_slprintf(p, last, "STREAM_DATA_BLOCKED id:0x%xL limit:%uL",
                         f->u.stream_data_blocked.id,
                         f->u.stream_data_blocked.limit);
        break;

    case NJT_QUIC_FT_PATH_CHALLENGE:
        p = njt_slprintf(p, last, "PATH_CHALLENGE data:0x%*xs",
                         sizeof(f->u.path_challenge.data),
                         f->u.path_challenge.data);
        break;

    case NJT_QUIC_FT_PATH_RESPONSE:
        p = njt_slprintf(p, last, "PATH_RESPONSE data:0x%*xs",
                         sizeof(f->u.path_challenge.data),
                         f->u.path_challenge.data);
        break;

    case NJT_QUIC_FT_NEW_TOKEN:
        p = njt_slprintf(p, last, "NEW_TOKEN");

#ifdef NJT_QUIC_DEBUG_FRAMES
        {
            njt_chain_t  *cl;

            p = njt_slprintf(p, last, " token:");

            for (cl = f->data; cl; cl = cl->next) {
                p = njt_slprintf(p, last, "%*xs",
                                 cl->buf->last - cl->buf->pos, cl->buf->pos);
            }
        }
#endif

        break;

    case NJT_QUIC_FT_HANDSHAKE_DONE:
        p = njt_slprintf(p, last, "HANDSHAKE DONE");
        break;

    default:
        p = njt_slprintf(p, last, "unknown type 0x%xi", f->type);
        break;
    }

    njt_log_debug5(NJT_LOG_DEBUG_EVENT, log, 0, "quic frame %s %s:%uL %*s",
                   tx ? "tx" : "rx", njt_quic_level_name(f->level), f->pnum,
                   p - buf, buf);
}

#endif
