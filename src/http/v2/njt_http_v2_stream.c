/*
 * Copyright (C) 2024 JD Technology Information Technology Co., Ltd
 */

#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


#define NJT_HTTP_V2_BUFFER_SIZE  4096

#define njt_http_v2_buf_refs(b)         (b)->shadow->num
#define njt_http_v2_buf_inc_refs(b)     njt_http_v2_buf_refs(b)++
#define njt_http_v2_buf_dec_refs(b)     njt_http_v2_buf_refs(b)--
#define njt_http_v2_buf_set_refs(b, v)  njt_http_v2_buf_refs(b) = v


static njt_buf_t *njt_http_v2_alloc_buf(njt_connection_t *c);
static void njt_http_v2_free_buf(njt_connection_t *c, njt_buf_t *b);
static njt_buf_t *njt_http_v2_clone_buf(njt_connection_t *c, njt_buf_t *b);
static njt_int_t njt_http_v2_split_chain(njt_connection_t *c, njt_chain_t *cl,
    off_t offset);
njt_chain_t *njt_http_v2_write_buffer_chain(njt_connection_t *c, njt_http_v2_stream_buffer_t *qb,
    njt_chain_t *in, uint64_t limit, uint64_t offset);

static njt_buf_t *
njt_http_v2_alloc_buf(njt_connection_t *c)
{
    u_char                 *p;
    njt_buf_t              *b;
    njt_http_v2_connection_t  *h2c;

    h2c = njt_http_v2_get_connection(c);

    b = h2c->free_bufs;

    if (b) {
        h2c->free_bufs = b->shadow;
        p = b->start;

    } else {
        b = h2c->free_shadow_bufs;

        if (b) {
            h2c->free_shadow_bufs = b->shadow;

#ifdef NJT_HTTP_V2_DEBUG_ALLOC
            njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                           "quic use shadow buffer n:%ui %ui",
                           ++h2c->nbufs, --h2c->nshadowbufs);
#endif

        } else {
            b = njt_palloc(h2c->pool, sizeof(njt_buf_t));
            if (b == NULL) {
                return NULL;
            }

#ifdef NJT_HTTP_V2_DEBUG_ALLOC
            njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                           "quic new buffer n:%ui", ++h2c->nbufs);
#endif
        }

        p = njt_pnalloc(h2c->pool, NJT_HTTP_V2_BUFFER_SIZE);
        if (p == NULL) {
            return NULL;
        }
    }

#ifdef NJT_HTTP_V2_DEBUG_ALLOC
    njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0, "quic alloc buffer %p", b);
#endif

    njt_memzero(b, sizeof(njt_buf_t));

    b->tag = (njt_buf_tag_t) &njt_http_v2_alloc_buf;
    b->temporary = 1;
    b->shadow = b;

    b->start = p;
    b->pos = p;
    b->last = p;
    b->end = p + NJT_HTTP_V2_BUFFER_SIZE;

    njt_http_v2_buf_set_refs(b, 1);

    return b;
}


static void
njt_http_v2_free_buf(njt_connection_t *c, njt_buf_t *b)
{
    njt_buf_t              *shadow;
    njt_http_v2_connection_t  *h2c;

    h2c = njt_http_v2_get_connection(c);

    njt_http_v2_buf_dec_refs(b);

#ifdef NJT_HTTP_V2_DEBUG_ALLOC
    njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic free buffer %p r:%ui",
                   b, (njt_uint_t) njt_http_v2_buf_refs(b));
#endif

    shadow = b->shadow;

    if (njt_http_v2_buf_refs(b) == 0) {
        shadow->shadow = h2c->free_bufs;
        h2c->free_bufs = shadow;
    }

    if (b != shadow) {
        b->shadow = h2c->free_shadow_bufs;
        h2c->free_shadow_bufs = b;
    }

}


static njt_buf_t *
njt_http_v2_clone_buf(njt_connection_t *c, njt_buf_t *b)
{
    njt_buf_t              *nb;
    njt_http_v2_connection_t  *h2c;

    h2c = njt_http_v2_get_connection(c);

    nb = h2c->free_shadow_bufs;

    if (nb) {
        h2c->free_shadow_bufs = nb->shadow;

    } else {
        nb = njt_palloc(h2c->pool, sizeof(njt_buf_t));
        if (nb == NULL) {
            return NULL;
        }

#ifdef NJT_HTTP_V2_DEBUG_ALLOC
        njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "quic new shadow buffer n:%ui", ++h2c->nshadowbufs);
#endif
    }

    *nb = *b;

    njt_http_v2_buf_inc_refs(b);

#ifdef NJT_HTTP_V2_DEBUG_ALLOC
    njt_log_debug3(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic clone buffer %p %p r:%ui",
                   b, nb, (njt_uint_t) njt_http_v2_buf_refs(b));
#endif

    return nb;
}

static njt_int_t
njt_http_v2_split_chain(njt_connection_t *c, njt_chain_t *cl, off_t offset)
{
    njt_buf_t    *b, *tb;
    njt_chain_t  *tail;

    b = cl->buf;

    tail = njt_alloc_chain_link(c->pool);
    if (tail == NULL) {
        return NJT_ERROR;
    }

    tb = njt_http_v2_clone_buf(c, b);
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

/*void 
njt_http_v2_out_chain( njt_chain_t  *out, int w)
{
     njt_chain_t  *cl;  
     int i = 0;
     while (out) {
        cl = out;
        out = out->next;
        printf("%s:%d -- cl:%p, next:%p , pnext:%p, buf:%p, sync:%d, len:%ld\n",
            w ==1 ? "write":"read",i++, cl,cl->next,&cl->next,cl->buf,cl->buf->sync, 
            cl->buf->last - cl->buf->pos);
    }    
}*/

njt_chain_t *
njt_http_v2_read_buffer(njt_connection_t *c, njt_http_v2_stream_buffer_t *qb, uint64_t limit)
{
    uint64_t      n;
    njt_buf_t    *b;
    njt_chain_t  *out, **ll;

    out = qb->chain;
    for (ll = &out; *ll; ll = &(*ll)->next) {
        b = (*ll)->buf;

        if (b->sync) {
            /*not used*/
            break;;
        }
        if (limit == 0) {
            break;
        }

        n = b->last - b->pos;

        if (n > limit) {
            if (njt_http_v2_split_chain(c, *ll, limit) != NJT_OK) {
                return NJT_CHAIN_ERROR;
            }
            if (qb->last_chain == &(*ll)->next) {
                qb->last_chain = &(*ll)->next->next;
            }
            n = limit;  
        }

        qb->size -= n;
        limit -= n;
    }

    if (*ll == NULL || qb->last_chain == ll) {
        qb->last_chain = &qb->chain;
    }

    qb->chain = *ll;
    *ll = NULL;
   
    if (out && out->buf->sync) {
        return NULL;
    }

    return out;
}

njt_chain_t *
njt_http_v2_alloc_chain(njt_connection_t *c)
{
    njt_chain_t  *cl;

    cl = njt_alloc_chain_link(c->pool);
    if (cl == NULL) {
        return NULL;
    }

    cl->buf = njt_http_v2_alloc_buf(c);
    if (cl->buf == NULL) {
        return NULL;
    }

    return cl;
}

njt_int_t 
njt_http_v2_write_buffer(njt_connection_t *c, u_char *data,size_t len) {
    njt_buf_t          buf;
    njt_chain_t        cl;
    njt_http_v2_stream_t *stream;

    stream = c->stream;

    njt_memzero(&buf, sizeof(njt_buf_t));

    buf.pos = data;
    buf.last = buf.pos + len;
    buf.temporary = 1;

    cl.buf = &buf;
    cl.next = NULL;

    if (njt_http_v2_write_chain(c, &stream->recv, &cl, len) == NJT_CHAIN_ERROR) {
        return NJT_ERROR;
    }
    return NJT_OK;
}


njt_chain_t *
njt_http_v2_write_chain(njt_connection_t *c, njt_http_v2_stream_buffer_t *qb,
    njt_chain_t *in, uint64_t limit)
{
    u_char       *p;
    uint64_t      n;
    njt_buf_t    *b;
    njt_chain_t  *cl, **chain;

    chain = qb->last_chain;
    while (in && limit) {       

        cl = *chain;
        if (cl == NULL) {
            cl = njt_http_v2_alloc_chain(c);
            if (cl == NULL) {
                return NJT_CHAIN_ERROR;
            }

            cl->buf->last = cl->buf->end;
            cl->buf->sync = 1; /* not used */
            cl->next = NULL;
            *chain = cl;
        }

        b = cl->buf;       
        p = b->pos;       
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

            
            njt_memcpy(p, in->buf->pos, n);
            qb->size += n;            

            p += n;
            in->buf->pos += n;            
            limit -= n;
        }

        if (b->sync && p == b->last) { 
            b->sync = 0;
            chain = &cl->next;        
            continue;
        }

        if (b->sync && p != b->pos) {
            if (njt_http_v2_split_chain(c, cl, p - b->pos) != NJT_OK) {
                return NJT_CHAIN_ERROR;
            }
            b->sync = 0;
            chain = &cl->next;           
        }
    }  
    qb->last_chain = chain;
    return in;
}

void
njt_http_v2_free_chain(njt_connection_t *c, njt_chain_t *in)
{
    njt_chain_t  *cl;
    njt_http_v2_connection_t  *h2c;

    h2c = njt_http_v2_get_connection(c);

    while (in) {
        cl = in;
        in = in->next;

        njt_http_v2_free_buf(c, cl->buf);
        njt_free_chain(h2c->pool, cl);
    }
}

void
njt_http_v2_free_buffer(njt_connection_t *c, njt_http_v2_stream_buffer_t *qb)
{
    njt_http_v2_free_chain(c, qb->chain);

    qb->chain = NULL;
}

ssize_t
njt_http_v2_stream_recv(njt_connection_t *c, u_char *buf, size_t size)
{
    ssize_t                len;
    njt_buf_t              *b;
    njt_chain_t            *cl, *in;
    njt_event_t            *rev;
    njt_http_v2_stream_t   *stream;
    njt_http_v2_connection_t  *h2c;

    stream = c->stream;
    h2c = stream->connection;
    rev = c->read;

    if (c->error) {
        njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "http2 stream id:0x%xL bad recv state", 
                       stream->node->id);
         return NJT_ERROR;
    }

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "http2 stream id:0x%xL expected recv buf:%uz", 
                   stream->node->id, size);

    if (size == 0) {
        return 0;
    }

    in = njt_http_v2_read_buffer(c, &stream->recv, size);
    if (in == NJT_CHAIN_ERROR) {
        return NJT_ERROR;
    }

    len = 0;

    for (cl = in; cl; cl = cl->next) {
        b = cl->buf;
        len += b->last - b->pos;
        buf = njt_cpymem(buf, b->pos, b->last - b->pos);
    }

    njt_http_v2_free_chain(c, in);

    if (len == 0) {
        rev->ready = 0;

        if (stream->in_closed) {
            rev->eof = 1;
            return 0;
        }

        njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "http2 stream id:0x%xL recv() not ready", stream->node->id);
        return NJT_AGAIN;
    }

    if (njt_http_v2_send_window_update(stream->connection,
                                           stream->node->id, len)
            == NJT_ERROR)
    {
        stream->skip_data = 1;
        return NJT_ERROR;
    }

    h2c = stream->connection;

    if (!h2c->blocked) {
        if (njt_http_v2_send_output_queue(h2c) == NJT_ERROR) {
            stream->skip_data = 1;
            return NJT_ERROR;
        }
    }

    stream->recv_window += len;
 
    njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "http2 stream id:0x%xL actual recv len:%z", stream->node->id, len);

    return len;
}

ssize_t
njt_http_v2_stream_send(njt_connection_t *c, u_char *buf, size_t size)
{
    njt_log_error(NJT_LOG_ERR,c->log,0,"call njt_http_v2_stream_send error");
    return 0;
}


static void
ng_http_v2_copy_chain_data(njt_chain_t *dst_chain, njt_chain_t *src_chain)
{
    u_char       *rpos, *wpos;
    size_t        data_size, buf_size, len;
    njt_chain_t  *src, *dst;

    src = src_chain;
    dst = dst_chain;

    rpos = src->buf->pos;
    wpos = dst->buf->last;

    while (src && dst) {

        data_size = src->buf->last - rpos;
        buf_size = dst->buf->end - wpos;

        len = njt_min(data_size, buf_size);

        njt_memcpy(wpos, rpos, len);

        rpos += len;
        wpos += len;

        if (rpos == src->buf->last) {
            src = src->next;
            if (src) {
                rpos = src->buf->pos;
            }
        }

        if (wpos == dst->buf->end) {
            dst = dst->next;
            if (dst) {
                wpos = dst->buf->last;
            }
        }
    }
}

ssize_t 
njt_http_v2_recv_chain(njt_connection_t *fc, njt_chain_t *in, off_t limit) {
    size_t                      len;
    njt_buf_t                   *b;
    njt_chain_t                 *cl, *out;
    njt_event_t                 *rev;
    njt_http_v2_stream_t        *stream;
    njt_http_v2_connection_t    *h2c;

    stream = fc->stream;
    h2c = stream->connection;
    rev = fc->read;

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, fc->log, 0,
                   "http2 stream id:0x%xL recv chain", stream->node->id);

    len = 0;
    for (cl = in; cl; cl = cl->next) {
        len += cl->buf->end - cl->buf->last;
    }

    if (limit && len > (size_t) limit) {
        len = limit;
    }

    out = njt_http_v2_read_buffer(fc, &stream->recv, len);
    if (out == NJT_CHAIN_ERROR) {
        return NJT_ERROR;
    }

    len = 0;

    for (cl = out; cl; cl = cl->next) {
        b = cl->buf;
        len += b->last - b->pos;
    }

    if (len == 0) {
        rev->ready = 0;

        if (stream->in_closed) {
            rev->eof = 1;
            return 0;
        }

        njt_log_debug1(NJT_LOG_DEBUG_EVENT, fc->log, 0,
                       "http2 stream id:0x%xL recv chain() not ready", stream->node->id);
        return NJT_AGAIN;
    }

    ng_http_v2_copy_chain_data(in, out);

    njt_http_v2_free_chain(fc, out);

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, fc->log, 0,
                   "http2 stream id:0x%xL actual recv chain len:%z", stream->node->id, len);

      if (njt_http_v2_send_window_update(stream->connection,
                                           stream->node->id, len)
            == NJT_ERROR)
    {
        stream->skip_data = 1;
        return NJT_ERROR;
    }

    h2c = stream->connection;

    if (!h2c->blocked) {
        if (njt_http_v2_send_output_queue(h2c) == NJT_ERROR) {
            stream->skip_data = 1;
            return NJT_ERROR;
        }
    }

    stream->recv_window += len;
    return len;

}

/*const int MAX_BUFF_SIZE = 1024*20;
const int MAX_RECV_SIZE = 5000;
const int MAX_RECV_4096 = 4096;

njt_int_t
njt_http_v2_stream_buf_test_rand() 
{
    njt_pool_t *pool;
    njt_connection_t *conn;
    njt_chain_t            *cl, *in;
    njt_http_v2_stream_t   *stream;
    njt_buf_t    *b;
    njt_http_v2_stream_buffer_t *qb;
    njt_http_v2_connection_t *h2c;

    // 使用当前时间作为随机数种子
    srand(time(0));
    u_char wr[MAX_BUFF_SIZE+10];
    u_char rd[MAX_BUFF_SIZE+10];  

    pool = njt_create_pool(1024, njt_cycle->log);
    if (pool == NULL) {
        return 0;
    }

    h2c = njt_pcalloc(pool, sizeof(njt_http_v2_connection_t));
    if (h2c == NULL) {
        return 0;
    }

    conn = njt_palloc(pool, sizeof(njt_connection_t));
    if (conn == NULL) {
        return 0;
    }
    conn->pool = pool;
    h2c->connection = conn;
    conn->data = h2c;
    h2c->pool = pool;


    stream = njt_pcalloc(pool, sizeof(njt_http_v2_stream_t));
    if (stream == NULL) {        
        return 0;
    }

    stream->connection = h2c;
    stream->recv.last_chain = &stream->recv.chain;
    conn->stream = stream;
    stream->fc = conn;
    qb = &stream->recv;

    size_t len, i = 0;
    size_t recv_stat = 0, send_stat = 0 ,actual_read = 0, actual_write = 0;
    size_t expect_read = 0, expecpt_write = 0;

    while (1) {
        int w = rand() % 20 + 2;
        actual_read = 0;
        actual_write = 0;
        expect_read = 0;
        expecpt_write = 0;
        while(w--) {
            size_t size = (rand() % MAX_BUFF_SIZE) + 1;
            char ch = 'a' + i++ % 26;
            memset(wr,ch,size);
            njt_http_v2_write_buffer(conn,wr,size);
            send_stat += size;
            actual_write += size;
            expecpt_write += size;
        }
       
        int r = rand() % 20 + 6;
        while(r--) {
            size_t size = rand() % MAX_BUFF_SIZE + 1;
            
            in = njt_http_v2_read_buffer(conn, &stream->recv, size);
            if (in == NJT_CHAIN_ERROR) {
                return 0;
            }

            len = 0;
            u_char *buf = rd;
            for (cl = in; cl; cl = cl->next) {
                b = cl->buf;
                len += b->last - b->pos;
                buf = njt_cpymem(buf, b->pos, b->last - b->pos);
            }
           

            recv_stat += len;
            actual_read += len;
            expect_read += size;
            njt_http_v2_free_chain(conn, in);

            njt_chain_t *out = qb->chain;
            len = 0;
            while (out) {
                cl = out;
                if (!cl->buf->sync) {
                    len += cl->buf->last - cl->buf->pos;
                }
                out = out->next;
            }

            if (len != qb->size) {
                printf("qb->size:%ld, buf：%ld\n", qb->size, len);
                return 0;
            }
        }
       
        printf("recv:%ld, send:%ld, buf:%ld, expecpt_write:%ld, actual_write:%ld, expecpt_read:%ld, actual_read:%ld\n",
             recv_stat, send_stat, qb->size, expecpt_write, actual_write,expect_read,actual_read);
        njt_http_v2_out_chain(qb->chain,0);
        printf("last_chain:%p, last_chain**:%p\n", *qb->last_chain, qb->last_chain);
        njt_http_v2_out_chain(*qb->last_chain,0);
        printf("----------------------------------\n\n");

        if (send_stat != recv_stat + qb->size) {
            printf("recv:%ld, send:%ld, buf：%ld\n", recv_stat, send_stat, qb->size);
            return 0;
        }

        njt_chain_t *out = qb->chain;
        len = 0;
        while (out) {
            cl = out;
            if (!cl->buf->sync) {
                len += cl->buf->last - cl->buf->pos;
            }
            out = out->next;
        }

        if (len != qb->size) {
            printf("qb->size:%ld, buf：%ld\n", qb->size, len);
            return 0;
        }        
    }
    
    return 0;
}

njt_int_t
njt_http_v2_stream_buf_test_4096() 
{
    njt_pool_t *pool;
    njt_connection_t *conn;
    njt_chain_t            *cl, *in;
    njt_http_v2_stream_t   *stream;
    njt_buf_t    *b;
    njt_http_v2_stream_buffer_t *qb;
    njt_http_v2_connection_t *h2c;

    // 使用当前时间作为随机数种子
    srand(time(0));
    u_char wr[MAX_BUFF_SIZE+10];
    u_char rd[MAX_BUFF_SIZE+10];  

    pool = njt_create_pool(1024, njt_cycle->log);
    if (pool == NULL) {
        return 0;
    }

    h2c = njt_pcalloc(pool, sizeof(njt_http_v2_connection_t));
    if (h2c == NULL) {
        return 0;
    }


    conn = njt_palloc(pool, sizeof(njt_connection_t));
    if (conn == NULL) {
        return 0;
    }
    conn->pool = pool;
    h2c->connection = conn;
    conn->data = h2c;
    h2c->pool = pool;


    stream = njt_pcalloc(pool, sizeof(njt_http_v2_stream_t));
    if (stream == NULL) {        
        return 0;
    }

    stream->connection = h2c;
    stream->recv.last_chain = &stream->recv.chain;
    conn->stream = stream;
    stream->fc = conn;
    qb = &stream->recv;

    size_t len, i = 0;
    size_t recv_stat = 0, send_stat = 0 ,actual_read = 0, actual_write = 0;
    size_t expect_read = 0, expecpt_write = 0;   

    while (1) {
        int w = rand() % 20 + 2;
        actual_read = 0;
        actual_write = 0;
        expect_read = 0;
        expecpt_write = 0;
        while(w--) {
            size_t size = MAX_RECV_4096;
            char ch = 'a' + i++ % 26;
            memset(wr,ch,size);
            njt_http_v2_write_buffer(conn,wr,size);
            send_stat += size;
            actual_write += size;
            expecpt_write += size;
        }
      
        int r = rand() % 20 + 6;
        while(r--) {
            size_t size = MAX_RECV_4096;
            
            in = njt_http_v2_read_buffer(conn, &stream->recv, size);
            if (in == NJT_CHAIN_ERROR) {
                return 0;
            }

            len = 0;
            u_char *buf = rd;
            for (cl = in; cl; cl = cl->next) {
                b = cl->buf;
                len += b->last - b->pos;
                buf = njt_cpymem(buf, b->pos, b->last - b->pos);
            }
           

            recv_stat += len;
            actual_read += len;
            expect_read += size;
            njt_http_v2_free_chain(conn, in);

            njt_chain_t *out = qb->chain;
            len = 0;
            while (out) {
                cl = out;
                if (!cl->buf->sync) {
                    len += cl->buf->last - cl->buf->pos;
                }
                out = out->next;
            }

            if (len != qb->size) {
                printf("qb->size:%ld, buf：%ld\n", qb->size, len);
                return 0;
            }
        }
       
        printf("recv:%ld, send:%ld, buf:%ld, expecpt_write:%ld, actual_write:%ld, expecpt_read:%ld, actual_read:%ld\n",
             recv_stat, send_stat, qb->size, expecpt_write, actual_write,expect_read,actual_read);
        njt_http_v2_out_chain(qb->chain,0);
        printf("last_chain:%p, last_chain**:%p\n", *qb->last_chain, qb->last_chain);
        njt_http_v2_out_chain(*qb->last_chain,0);
        printf("----------------------------------\n\n");

        if (send_stat != recv_stat + qb->size) {
            printf("recv:%ld, send:%ld, buf：%ld\n", recv_stat, send_stat, qb->size);
            return 0;
        }

        njt_chain_t *out = qb->chain;
        len = 0;
        while (out) {
            cl = out;
            if (!cl->buf->sync) {
                len += cl->buf->last - cl->buf->pos;
            }
            out = out->next;
        }

        if (len != qb->size) {
            printf("qb->size:%ld, buf：%ld\n", qb->size, len);
            return 0;
        }        
    }
    
    return 0;
}

njt_int_t
njt_http_v2_stream_buf_test() {
    njt_http_v2_stream_buf_test_4096();
    njt_http_v2_stream_buf_test_rand();
    return 0;
}
*/