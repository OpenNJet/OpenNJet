
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


static void njt_http_read_client_request_body_handler(njt_http_request_t *r);
static njt_int_t njt_http_do_read_client_request_body(njt_http_request_t *r);
static njt_int_t njt_http_copy_pipelined_header(njt_http_request_t *r,
    njt_buf_t *buf);
static njt_int_t njt_http_write_request_body(njt_http_request_t *r);
static njt_int_t njt_http_read_discarded_request_body(njt_http_request_t *r);
static njt_int_t njt_http_discard_request_body_filter(njt_http_request_t *r,
    njt_buf_t *b);
static njt_int_t njt_http_test_expect(njt_http_request_t *r);

static njt_int_t njt_http_request_body_filter(njt_http_request_t *r,
    njt_chain_t *in);
static njt_int_t njt_http_request_body_length_filter(njt_http_request_t *r,
    njt_chain_t *in);
static njt_int_t njt_http_request_body_chunked_filter(njt_http_request_t *r,
    njt_chain_t *in);


njt_int_t
njt_http_read_client_request_body(njt_http_request_t *r,
    njt_http_client_body_handler_pt post_handler)
{
    size_t                     preread;
    ssize_t                    size;
    njt_int_t                  rc;
    njt_buf_t                 *b;
    njt_chain_t                out;
    njt_http_request_body_t   *rb;
    njt_http_core_loc_conf_t  *clcf;

    r->main->count++;

    if (r != r->main || r->request_body || r->discard_body) {
        r->request_body_no_buffering = 0;
        post_handler(r);
        return NJT_OK;
    }

    if (njt_http_test_expect(r) != NJT_OK) {
        rc = NJT_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

    rb = njt_pcalloc(r->pool, sizeof(njt_http_request_body_t));
    if (rb == NULL) {
        rc = NJT_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

    /*
     * set by njt_pcalloc():
     *
     *     rb->temp_file = NULL;
     *     rb->bufs = NULL;
     *     rb->buf = NULL;
     *     rb->free = NULL;
     *     rb->busy = NULL;
     *     rb->chunked = NULL;
     *     rb->received = 0;
     *     rb->filter_need_buffering = 0;
     *     rb->last_sent = 0;
     *     rb->last_saved = 0;
     */

    rb->rest = -1;
    rb->post_handler = post_handler;

    r->request_body = rb;

    if (r->headers_in.content_length_n < 0 && !r->headers_in.chunked) {
        r->request_body_no_buffering = 0;
        post_handler(r);
        return NJT_OK;
    }

#if (NJT_HTTP_V2)
    if (r->stream) {
        rc = njt_http_v2_read_request_body(r);
        goto done;
    }
#endif

#if (NJT_HTTP_V3)
    if (r->http_version == NJT_HTTP_VERSION_30) {
        rc = njt_http_v3_read_request_body(r);
        goto done;
    }
#endif

    preread = r->header_in->last - r->header_in->pos;

    if (preread) {

        /* there is the pre-read part of the request body */

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http client request body preread %uz", preread);

        out.buf = r->header_in;
        out.next = NULL;

        rc = njt_http_request_body_filter(r, &out);

        if (rc != NJT_OK) {
            goto done;
        }

        r->request_length += preread - (r->header_in->last - r->header_in->pos);

        if (!r->headers_in.chunked
            && rb->rest > 0
            && rb->rest <= (off_t) (r->header_in->end - r->header_in->last))
        {
            /* the whole request body may be placed in r->header_in */

            b = njt_calloc_buf(r->pool);
            if (b == NULL) {
                rc = NJT_HTTP_INTERNAL_SERVER_ERROR;
                goto done;
            }

            b->temporary = 1;
            b->start = r->header_in->pos;
            b->pos = r->header_in->pos;
            b->last = r->header_in->last;
            b->end = r->header_in->end;

            rb->buf = b;

            r->read_event_handler = njt_http_read_client_request_body_handler;
            r->write_event_handler = njt_http_request_empty_handler;

            rc = njt_http_do_read_client_request_body(r);
            goto done;
        }

    } else {
        /* set rb->rest */

        rc = njt_http_request_body_filter(r, NULL);

        if (rc != NJT_OK) {
            goto done;
        }
    }

    if (rb->rest == 0 && rb->last_saved) {
        /* the whole request body was pre-read */
        r->request_body_no_buffering = 0;
        post_handler(r);
        return NJT_OK;
    }

    if (rb->rest < 0) {
        njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
                      "negative request body rest");
        rc = NJT_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    size = clcf->client_body_buffer_size;
    size += size >> 2;

    /* TODO: honor r->request_body_in_single_buf */

    if (!r->headers_in.chunked && rb->rest < size) {
        size = (ssize_t) rb->rest;

        if (r->request_body_in_single_buf) {
            size += preread;
        }

        if (size == 0) {
            size++;
        }

    } else {
        size = clcf->client_body_buffer_size;
    }

    rb->buf = njt_create_temp_buf(r->pool, size);
    if (rb->buf == NULL) {
        rc = NJT_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

    r->read_event_handler = njt_http_read_client_request_body_handler;
    r->write_event_handler = njt_http_request_empty_handler;

    rc = njt_http_do_read_client_request_body(r);

done:

    if (r->request_body_no_buffering
        && (rc == NJT_OK || rc == NJT_AGAIN))
    {
        if (rc == NJT_OK) {
            r->request_body_no_buffering = 0;

        } else {
            /* rc == NJT_AGAIN */
            r->reading_body = 1;
        }

        r->read_event_handler = njt_http_block_reading;
        post_handler(r);
    }

    if (rc >= NJT_HTTP_SPECIAL_RESPONSE) {
        r->main->count--;
    }

    return rc;
}


njt_int_t
njt_http_read_unbuffered_request_body(njt_http_request_t *r)
{
    njt_int_t  rc;

#if (NJT_HTTP_V2)
    if (r->stream) {
        rc = njt_http_v2_read_unbuffered_request_body(r);

        if (rc == NJT_OK) {
            r->reading_body = 0;
        }

        return rc;
    }
#endif

#if (NJT_HTTP_V3)
    if (r->http_version == NJT_HTTP_VERSION_30) {
        rc = njt_http_v3_read_unbuffered_request_body(r);

        if (rc == NJT_OK) {
            r->reading_body = 0;
        }

        return rc;
    }
#endif

    if (r->connection->read->timedout) {
        r->connection->timedout = 1;
        return NJT_HTTP_REQUEST_TIME_OUT;
    }

    rc = njt_http_do_read_client_request_body(r);

    if (rc == NJT_OK) {
        r->reading_body = 0;
    }

    return rc;
}


static void
njt_http_read_client_request_body_handler(njt_http_request_t *r)
{
    njt_int_t  rc;

    if (r->connection->read->timedout) {
        r->connection->timedout = 1;
        njt_http_finalize_request(r, NJT_HTTP_REQUEST_TIME_OUT);
        return;
    }

    rc = njt_http_do_read_client_request_body(r);

    if (rc >= NJT_HTTP_SPECIAL_RESPONSE) {
        njt_http_finalize_request(r, rc);
    }
}


static njt_int_t
njt_http_do_read_client_request_body(njt_http_request_t *r)
{
    off_t                      rest;
    size_t                     size;
    ssize_t                    n;
    njt_int_t                  rc;
    njt_uint_t                 flush;
    njt_chain_t                out;
    njt_connection_t          *c;
    njt_http_request_body_t   *rb;
    njt_http_core_loc_conf_t  *clcf;

    c = r->connection;
    rb = r->request_body;
    flush = 1;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http read client request body");

    for ( ;; ) {
        for ( ;; ) {
            if (rb->rest == 0) {
                break;
            }

            if (rb->buf->last == rb->buf->end) {

                /* update chains */

                rc = njt_http_request_body_filter(r, NULL);

                if (rc != NJT_OK) {
                    return rc;
                }

                if (rb->busy != NULL) {
                    if (r->request_body_no_buffering) {
                        if (c->read->timer_set) {
                            njt_del_timer(c->read);
                        }

                        if (njt_handle_read_event(c->read, 0) != NJT_OK) {
                            return NJT_HTTP_INTERNAL_SERVER_ERROR;
                        }

                        return NJT_AGAIN;
                    }

                    if (rb->filter_need_buffering) {
                        clcf = njt_http_get_module_loc_conf(r,
                                                         njt_http_core_module);
                        njt_add_timer(c->read, clcf->client_body_timeout);

                        if (njt_handle_read_event(c->read, 0) != NJT_OK) {
                            return NJT_HTTP_INTERNAL_SERVER_ERROR;
                        }

                        return NJT_AGAIN;
                    }

                    njt_log_error(NJT_LOG_ALERT, c->log, 0,
                                  "busy buffers after request body flush");

                    return NJT_HTTP_INTERNAL_SERVER_ERROR;
                }

                flush = 0;
                rb->buf->pos = rb->buf->start;
                rb->buf->last = rb->buf->start;
            }

            size = rb->buf->end - rb->buf->last;
            rest = rb->rest - (rb->buf->last - rb->buf->pos);

            if ((off_t) size > rest) {
                size = (size_t) rest;
            }

            if (size == 0) {
                break;
            }

            n = c->recv(c, rb->buf->last, size);

            njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                           "http client request body recv %z", n);

            if (n == NJT_AGAIN) {
                break;
            }

            if (n == 0) {
                njt_log_error(NJT_LOG_INFO, c->log, 0,
                              "client prematurely closed connection");
            }

            if (n == 0 || n == NJT_ERROR) {
                c->error = 1;
                return NJT_HTTP_BAD_REQUEST;
            }

            rb->buf->last += n;
            r->request_length += n;

            /* pass buffer to request body filter chain */

            flush = 0;
            out.buf = rb->buf;
            out.next = NULL;

            rc = njt_http_request_body_filter(r, &out);

            if (rc != NJT_OK) {
                return rc;
            }

            if (rb->rest == 0) {
                break;
            }

            if (rb->buf->last < rb->buf->end) {
                break;
            }
        }

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "http client request body rest %O", rb->rest);

        if (flush) {
            rc = njt_http_request_body_filter(r, NULL);

            if (rc != NJT_OK) {
                return rc;
            }
        }

        if (rb->rest == 0 && rb->last_saved) {
            break;
        }

        if (!c->read->ready || rb->rest == 0) {

            clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);
            njt_add_timer(c->read, clcf->client_body_timeout);

            if (njt_handle_read_event(c->read, 0) != NJT_OK) {
                return NJT_HTTP_INTERNAL_SERVER_ERROR;
            }

            return NJT_AGAIN;
        }
    }

    if (njt_http_copy_pipelined_header(r, rb->buf) != NJT_OK) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (c->read->timer_set) {
        njt_del_timer(c->read);
    }

    if (!r->request_body_no_buffering) {
        r->read_event_handler = njt_http_block_reading;
        rb->post_handler(r);
    }

    return NJT_OK;
}


static njt_int_t
njt_http_copy_pipelined_header(njt_http_request_t *r, njt_buf_t *buf)
{
    size_t                     n;
    njt_buf_t                 *b;
    njt_chain_t               *cl;
    njt_http_connection_t     *hc;
    njt_http_core_srv_conf_t  *cscf;

    b = r->header_in;
    n = buf->last - buf->pos;

    if (buf == b || n == 0) {
        return NJT_OK;
    }

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http body pipelined header: %uz", n);

    /*
     * if there is a pipelined request in the client body buffer,
     * copy it to the r->header_in buffer if there is enough room,
     * or allocate a large client header buffer
     */

    if (n > (size_t) (b->end - b->last)) {

        hc = r->http_connection;

        if (hc->free) {
            cl = hc->free;
            hc->free = cl->next;

            b = cl->buf;

            njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http large header free: %p %uz",
                           b->pos, b->end - b->last);

        } else {
            cscf = njt_http_get_module_srv_conf(r, njt_http_core_module);

            b = njt_create_temp_buf(r->connection->pool,
                                    cscf->large_client_header_buffers.size);
            if (b == NULL) {
                return NJT_ERROR;
            }

            cl = njt_alloc_chain_link(r->connection->pool);
            if (cl == NULL) {
                return NJT_ERROR;
            }

            cl->buf = b;

            njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http large header alloc: %p %uz",
                           b->pos, b->end - b->last);
        }

        cl->next = hc->busy;
        hc->busy = cl;
        hc->nbusy++;

        r->header_in = b;

        if (n > (size_t) (b->end - b->last)) {
            njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
                          "too large pipelined header after reading body");
            return NJT_ERROR;
        }
    }

    njt_memcpy(b->last, buf->pos, n);

    b->last += n;
    r->request_length -= n;

    return NJT_OK;
}


static njt_int_t
njt_http_write_request_body(njt_http_request_t *r)
{
    ssize_t                    n;
    njt_chain_t               *cl, *ln;
    njt_temp_file_t           *tf;
    njt_http_request_body_t   *rb;
    njt_http_core_loc_conf_t  *clcf;

    rb = r->request_body;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http write client request body, bufs %p", rb->bufs);

    if (rb->temp_file == NULL) {
        tf = njt_pcalloc(r->pool, sizeof(njt_temp_file_t));
        if (tf == NULL) {
            return NJT_ERROR;
        }

        clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

        tf->file.fd = NJT_INVALID_FILE;
        tf->file.log = r->connection->log;
        tf->path = clcf->client_body_temp_path;
        tf->pool = r->pool;
        tf->warn = "a client request body is buffered to a temporary file";
        tf->log_level = r->request_body_file_log_level;
        tf->persistent = r->request_body_in_persistent_file;
        tf->clean = r->request_body_in_clean_file;

        if (r->request_body_file_group_access) {
            tf->access = 0660;
        }

        rb->temp_file = tf;

        if (rb->bufs == NULL) {
            /* empty body with r->request_body_in_file_only */

            if (njt_create_temp_file(&tf->file, tf->path, tf->pool,
                                     tf->persistent, tf->clean, tf->access)
                != NJT_OK)
            {
                return NJT_ERROR;
            }

            return NJT_OK;
        }
    }

    if (rb->bufs == NULL) {
        return NJT_OK;
    }

    n = njt_write_chain_to_temp_file(rb->temp_file, rb->bufs);

    /* TODO: n == 0 or not complete and level event */

    if (n == NJT_ERROR) {
        return NJT_ERROR;
    }

    rb->temp_file->offset += n;

    /* mark all buffers as written */

    for (cl = rb->bufs; cl; /* void */) {

        cl->buf->pos = cl->buf->last;

        ln = cl;
        cl = cl->next;
        njt_free_chain(r->pool, ln);
    }

    rb->bufs = NULL;

    return NJT_OK;
}


njt_int_t
njt_http_discard_request_body(njt_http_request_t *r)
{
    ssize_t       size;
    njt_int_t     rc;
    njt_event_t  *rev;

    if (r != r->main || r->discard_body || r->request_body) {
        return NJT_OK;
    }

#if (NJT_HTTP_V2)
    if (r->stream) {
        r->stream->skip_data = 1;
        return NJT_OK;
    }
#endif

#if (NJT_HTTP_V3)
    if (r->http_version == NJT_HTTP_VERSION_30) {
        return NJT_OK;
    }
#endif

    if (njt_http_test_expect(r) != NJT_OK) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    rev = r->connection->read;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, rev->log, 0, "http set discard body");

    if (rev->timer_set) {
        njt_del_timer(rev);
    }

    if (r->headers_in.content_length_n <= 0 && !r->headers_in.chunked) {
        return NJT_OK;
    }

    size = r->header_in->last - r->header_in->pos;

    if (size || r->headers_in.chunked) {
        rc = njt_http_discard_request_body_filter(r, r->header_in);

        if (rc != NJT_OK) {
            return rc;
        }

        if (r->headers_in.content_length_n == 0) {
            return NJT_OK;
        }
    }

    rc = njt_http_read_discarded_request_body(r);

    if (rc == NJT_OK) {
        r->lingering_close = 0;
        return NJT_OK;
    }

    if (rc >= NJT_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    /* rc == NJT_AGAIN */

    r->read_event_handler = njt_http_discarded_request_body_handler;

    if (njt_handle_read_event(rev, 0) != NJT_OK) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->count++;
    r->discard_body = 1;

    return NJT_OK;
}


void
njt_http_discarded_request_body_handler(njt_http_request_t *r)
{
    njt_int_t                  rc;
    njt_msec_t                 timer;
    njt_event_t               *rev;
    njt_connection_t          *c;
    njt_http_core_loc_conf_t  *clcf;

    c = r->connection;
    rev = c->read;

    if (rev->timedout) {
        c->timedout = 1;
        c->error = 1;
        njt_http_finalize_request(r, NJT_ERROR);
        return;
    }

    if (r->lingering_time) {
        timer = (njt_msec_t) r->lingering_time - (njt_msec_t) njt_time();

        if ((njt_msec_int_t) timer <= 0) {
            r->discard_body = 0;
            r->lingering_close = 0;
            njt_http_finalize_request(r, NJT_ERROR);
            return;
        }

    } else {
        timer = 0;
    }

    rc = njt_http_read_discarded_request_body(r);

    if (rc == NJT_OK) {
        r->discard_body = 0;
        r->lingering_close = 0;
        r->lingering_time = 0;
        njt_http_finalize_request(r, NJT_DONE);
        return;
    }

    if (rc >= NJT_HTTP_SPECIAL_RESPONSE) {
        c->error = 1;
        njt_http_finalize_request(r, NJT_ERROR);
        return;
    }

    /* rc == NJT_AGAIN */

    if (njt_handle_read_event(rev, 0) != NJT_OK) {
        c->error = 1;
        njt_http_finalize_request(r, NJT_ERROR);
        return;
    }

    if (timer) {

        clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

        timer *= 1000;

        if (timer > clcf->lingering_timeout) {
            timer = clcf->lingering_timeout;
        }

        njt_add_timer(rev, timer);
    }
}


static njt_int_t
njt_http_read_discarded_request_body(njt_http_request_t *r)
{
    size_t     size;
    ssize_t    n;
    njt_int_t  rc;
    njt_buf_t  b;
    u_char     buffer[NJT_HTTP_DISCARD_BUFFER_SIZE];

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http read discarded body");

    njt_memzero(&b, sizeof(njt_buf_t));

    b.temporary = 1;

    for ( ;; ) {
        if (r->headers_in.content_length_n == 0) {
            break;
        }

        if (!r->connection->read->ready) {
            return NJT_AGAIN;
        }

        size = (size_t) njt_min(r->headers_in.content_length_n,
                                NJT_HTTP_DISCARD_BUFFER_SIZE);

        n = r->connection->recv(r->connection, buffer, size);

        if (n == NJT_ERROR) {
            r->connection->error = 1;
            return NJT_OK;
        }

        if (n == NJT_AGAIN) {
            return NJT_AGAIN;
        }

        if (n == 0) {
            return NJT_OK;
        }

        b.pos = buffer;
        b.last = buffer + n;

        rc = njt_http_discard_request_body_filter(r, &b);

        if (rc != NJT_OK) {
            return rc;
        }
    }

    if (njt_http_copy_pipelined_header(r, &b) != NJT_OK) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->read_event_handler = njt_http_block_reading;

    return NJT_OK;
}


static njt_int_t
njt_http_discard_request_body_filter(njt_http_request_t *r, njt_buf_t *b)
{
    size_t                     size;
    njt_int_t                  rc;
    njt_http_request_body_t   *rb;
    njt_http_core_srv_conf_t  *cscf;

    if (r->headers_in.chunked) {

        rb = r->request_body;

        if (rb == NULL) {

            rb = njt_pcalloc(r->pool, sizeof(njt_http_request_body_t));
            if (rb == NULL) {
                return NJT_HTTP_INTERNAL_SERVER_ERROR;
            }

            rb->chunked = njt_pcalloc(r->pool, sizeof(njt_http_chunked_t));
            if (rb->chunked == NULL) {
                return NJT_HTTP_INTERNAL_SERVER_ERROR;
            }

            r->request_body = rb;
        }

        for ( ;; ) {

            rc = njt_http_parse_chunked(r, b, rb->chunked);

            if (rc == NJT_OK) {

                /* a chunk has been parsed successfully */

                size = b->last - b->pos;

                if ((off_t) size > rb->chunked->size) {
                    b->pos += (size_t) rb->chunked->size;
                    rb->chunked->size = 0;

                } else {
                    rb->chunked->size -= size;
                    b->pos = b->last;
                }

                continue;
            }

            if (rc == NJT_DONE) {

                /* a whole response has been parsed successfully */

                r->headers_in.content_length_n = 0;
                break;
            }

            if (rc == NJT_AGAIN) {

                /* set amount of data we want to see next time */

                cscf = njt_http_get_module_srv_conf(r, njt_http_core_module);

                r->headers_in.content_length_n = njt_max(rb->chunked->length,
                               (off_t) cscf->large_client_header_buffers.size);
                break;
            }

            /* invalid */

            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "client sent invalid chunked body");

            return NJT_HTTP_BAD_REQUEST;
        }

    } else {
        size = b->last - b->pos;

        if ((off_t) size > r->headers_in.content_length_n) {
            b->pos += (size_t) r->headers_in.content_length_n;
            r->headers_in.content_length_n = 0;

        } else {
            b->pos = b->last;
            r->headers_in.content_length_n -= size;
        }
    }

    return NJT_OK;
}


static njt_int_t
njt_http_test_expect(njt_http_request_t *r)
{
    njt_int_t   n;
    njt_str_t  *expect;

    if (r->expect_tested
        || r->headers_in.expect == NULL
        || r->http_version < NJT_HTTP_VERSION_11
#if (NJT_HTTP_V2)
        || r->stream != NULL
#endif
#if (NJT_HTTP_V3)
        || r->connection->quic != NULL
#endif
       )
    {
        return NJT_OK;
    }

    r->expect_tested = 1;

    expect = &r->headers_in.expect->value;

    if (expect->len != sizeof("100-continue") - 1
        || njt_strncasecmp(expect->data, (u_char *) "100-continue",
                           sizeof("100-continue") - 1)
           != 0)
    {
        return NJT_OK;
    }

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "send 100 Continue");

    n = r->connection->send(r->connection,
                            (u_char *) "HTTP/1.1 100 Continue" CRLF CRLF,
                            sizeof("HTTP/1.1 100 Continue" CRLF CRLF) - 1);

    if (n == sizeof("HTTP/1.1 100 Continue" CRLF CRLF) - 1) {
        return NJT_OK;
    }

    /* we assume that such small packet should be send successfully */

    r->connection->error = 1;

    return NJT_ERROR;
}


static njt_int_t
njt_http_request_body_filter(njt_http_request_t *r, njt_chain_t *in)
{
    if (r->headers_in.chunked) {
        return njt_http_request_body_chunked_filter(r, in);

    } else {
        return njt_http_request_body_length_filter(r, in);
    }
}


static njt_int_t
njt_http_request_body_length_filter(njt_http_request_t *r, njt_chain_t *in)
{
    size_t                     size;
    njt_int_t                  rc;
    njt_buf_t                 *b;
    njt_chain_t               *cl, *tl, *out, **ll;
    njt_http_request_body_t   *rb;

    rb = r->request_body;

    out = NULL;
    ll = &out;

    if (rb->rest == -1) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http request body content length filter");

        rb->rest = r->headers_in.content_length_n;

        if (rb->rest == 0) {

            tl = njt_chain_get_free_buf(r->pool, &rb->free);
            if (tl == NULL) {
                return NJT_HTTP_INTERNAL_SERVER_ERROR;
            }

            b = tl->buf;

            njt_memzero(b, sizeof(njt_buf_t));

            b->last_buf = 1;

            *ll = tl;
            ll = &tl->next;
        }
    }

    for (cl = in; cl; cl = cl->next) {

        if (rb->rest == 0) {
            break;
        }

        tl = njt_chain_get_free_buf(r->pool, &rb->free);
        if (tl == NULL) {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        b = tl->buf;

        njt_memzero(b, sizeof(njt_buf_t));

        b->temporary = 1;
        b->tag = (njt_buf_tag_t) &njt_http_read_client_request_body;
        b->start = cl->buf->pos;
        b->pos = cl->buf->pos;
        b->last = cl->buf->last;
        b->end = cl->buf->end;
        b->flush = r->request_body_no_buffering;

        size = cl->buf->last - cl->buf->pos;

        if ((off_t) size < rb->rest) {
            cl->buf->pos = cl->buf->last;
            rb->rest -= size;

        } else {
            cl->buf->pos += (size_t) rb->rest;
            rb->rest = 0;
            b->last = cl->buf->pos;
            b->last_buf = 1;
        }

        *ll = tl;
        ll = &tl->next;
    }

    rc = njt_http_top_request_body_filter(r, out);

    njt_chain_update_chains(r->pool, &rb->free, &rb->busy, &out,
                            (njt_buf_tag_t) &njt_http_read_client_request_body);

    return rc;
}


static njt_int_t
njt_http_request_body_chunked_filter(njt_http_request_t *r, njt_chain_t *in)
{
    size_t                     size;
    njt_int_t                  rc;
    njt_buf_t                 *b;
    njt_chain_t               *cl, *out, *tl, **ll;
    njt_http_request_body_t   *rb;
    njt_http_core_loc_conf_t  *clcf;
    njt_http_core_srv_conf_t  *cscf;

    rb = r->request_body;

    out = NULL;
    ll = &out;

    if (rb->rest == -1) {

        njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http request body chunked filter");

        rb->chunked = njt_pcalloc(r->pool, sizeof(njt_http_chunked_t));
        if (rb->chunked == NULL) {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        cscf = njt_http_get_module_srv_conf(r, njt_http_core_module);

        r->headers_in.content_length_n = 0;
        rb->rest = cscf->large_client_header_buffers.size;
    }

    for (cl = in; cl; cl = cl->next) {

        b = NULL;

        for ( ;; ) {

            njt_log_debug7(NJT_LOG_DEBUG_EVENT, r->connection->log, 0,
                           "http body chunked buf "
                           "t:%d f:%d %p, pos %p, size: %z file: %O, size: %O",
                           cl->buf->temporary, cl->buf->in_file,
                           cl->buf->start, cl->buf->pos,
                           cl->buf->last - cl->buf->pos,
                           cl->buf->file_pos,
                           cl->buf->file_last - cl->buf->file_pos);

            rc = njt_http_parse_chunked(r, cl->buf, rb->chunked);

            if (rc == NJT_OK) {

                /* a chunk has been parsed successfully */

                clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

                if (clcf->client_max_body_size
                    && clcf->client_max_body_size
                       - r->headers_in.content_length_n < rb->chunked->size)
                {
                    njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                                  "client intended to send too large chunked "
                                  "body: %O+%O bytes",
                                  r->headers_in.content_length_n,
                                  rb->chunked->size);

                    r->lingering_close = 1;

                    return NJT_HTTP_REQUEST_ENTITY_TOO_LARGE;
                }

                if (b
                    && rb->chunked->size <= 128
                    && cl->buf->last - cl->buf->pos >= rb->chunked->size)
                {
                    r->headers_in.content_length_n += rb->chunked->size;

                    if (rb->chunked->size < 8) {

                        while (rb->chunked->size) {
                            *b->last++ = *cl->buf->pos++;
                            rb->chunked->size--;
                        }

                    } else {
                        njt_memmove(b->last, cl->buf->pos, rb->chunked->size);
                        b->last += rb->chunked->size;
                        cl->buf->pos += rb->chunked->size;
                        rb->chunked->size = 0;
                    }

                    continue;
                }

                tl = njt_chain_get_free_buf(r->pool, &rb->free);
                if (tl == NULL) {
                    return NJT_HTTP_INTERNAL_SERVER_ERROR;
                }

                b = tl->buf;

                njt_memzero(b, sizeof(njt_buf_t));

                b->temporary = 1;
                b->tag = (njt_buf_tag_t) &njt_http_read_client_request_body;
                b->start = cl->buf->pos;
                b->pos = cl->buf->pos;
                b->last = cl->buf->last;
                b->end = cl->buf->end;
                b->flush = r->request_body_no_buffering;

                *ll = tl;
                ll = &tl->next;

                size = cl->buf->last - cl->buf->pos;

                if ((off_t) size > rb->chunked->size) {
                    cl->buf->pos += (size_t) rb->chunked->size;
                    r->headers_in.content_length_n += rb->chunked->size;
                    rb->chunked->size = 0;

                } else {
                    rb->chunked->size -= size;
                    r->headers_in.content_length_n += size;
                    cl->buf->pos = cl->buf->last;
                }

                b->last = cl->buf->pos;

                continue;
            }

            if (rc == NJT_DONE) {

                /* a whole response has been parsed successfully */

                rb->rest = 0;

                tl = njt_chain_get_free_buf(r->pool, &rb->free);
                if (tl == NULL) {
                    return NJT_HTTP_INTERNAL_SERVER_ERROR;
                }

                b = tl->buf;

                njt_memzero(b, sizeof(njt_buf_t));

                b->last_buf = 1;

                *ll = tl;
                ll = &tl->next;

                break;
            }

            if (rc == NJT_AGAIN) {

                /* set rb->rest, amount of data we want to see next time */

                cscf = njt_http_get_module_srv_conf(r, njt_http_core_module);

                rb->rest = njt_max(rb->chunked->length,
                               (off_t) cscf->large_client_header_buffers.size);

                break;
            }

            /* invalid */

            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "client sent invalid chunked body");

            return NJT_HTTP_BAD_REQUEST;
        }
    }

    rc = njt_http_top_request_body_filter(r, out);

    njt_chain_update_chains(r->pool, &rb->free, &rb->busy, &out,
                            (njt_buf_tag_t) &njt_http_read_client_request_body);

    return rc;
}


njt_int_t
njt_http_request_body_save_filter(njt_http_request_t *r, njt_chain_t *in)
{
    njt_buf_t                 *b;
    njt_chain_t               *cl, *tl, **ll;
    njt_http_request_body_t   *rb;

    rb = r->request_body;

    ll = &rb->bufs;

    for (cl = rb->bufs; cl; cl = cl->next) {

#if 0
        njt_log_debug7(NJT_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "http body old buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
#endif

        ll = &cl->next;
    }

    for (cl = in; cl; cl = cl->next) {

        njt_log_debug7(NJT_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "http body new buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

        if (cl->buf->last_buf) {

            if (rb->last_saved) {
                njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
                              "duplicate last buf in save filter");
                *ll = NULL;
                return NJT_HTTP_INTERNAL_SERVER_ERROR;
            }

            rb->last_saved = 1;
        }

        tl = njt_alloc_chain_link(r->pool);
        if (tl == NULL) {
            *ll = NULL;
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        tl->buf = cl->buf;
        *ll = tl;
        ll = &tl->next;
    }

    *ll = NULL;

    if (r->request_body_no_buffering) {
        return NJT_OK;
    }

    if (rb->rest > 0) {

        if (rb->bufs && rb->buf && rb->buf->last == rb->buf->end
            && njt_http_write_request_body(r) != NJT_OK)
        {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        return NJT_OK;
    }

    if (!rb->last_saved) {
        return NJT_OK;
    }

    if (rb->temp_file || r->request_body_in_file_only) {

        if (rb->bufs && rb->bufs->buf->in_file) {
            njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
                          "body already in file");
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (njt_http_write_request_body(r) != NJT_OK) {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (rb->temp_file != NULL && rb->temp_file->file.offset != 0) {

            cl = njt_chain_get_free_buf(r->pool, &rb->free);
            if (cl == NULL) {
                return NJT_HTTP_INTERNAL_SERVER_ERROR;
            }

            b = cl->buf;

            njt_memzero(b, sizeof(njt_buf_t));

            b->in_file = 1;
            b->file_last = rb->temp_file->file.offset;
            b->file = &rb->temp_file->file;

            rb->bufs = cl;
        }
    }

    return NJT_OK;
}
