
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>

// //add by clb
// #if (NJT_HTTP_LIMIT_RATE_MULTI)
// #include <njt_http_limit_rate_multi_module.h>

// extern njt_module_t njt_http_limit_rate_multi_module;
// #endif
//end add by clb

static njt_int_t njt_http_write_filter_init(njt_conf_t *cf);


static njt_http_module_t  njt_http_write_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    njt_http_write_filter_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL,                                  /* merge location configuration */
};


njt_module_t  njt_http_write_filter_module = {
    NJT_MODULE_V1,
    &njt_http_write_filter_module_ctx,     /* module context */
    NULL,                                  /* module directives */
    NJT_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};


njt_int_t
njt_http_write_filter(njt_http_request_t *r, njt_chain_t *in)
{
    off_t                      size, sent, nsent, limit;
    njt_uint_t                 last, flush, sync;
    njt_msec_t                 delay;
    njt_chain_t               *cl, *ln, **ll, *chain;
    njt_connection_t          *c;
    njt_http_core_loc_conf_t  *clcf;
//add by clb
// #if (NJT_HTTP_LIMIT_RATE_MULTI)
//     njt_http_limit_rate_multi_local_conf_t  *lrcf;
//     njt_flag_t                 limit_rate_multi_flag = 0;
    njt_msec_t                 now = njt_current_msec;
// #endif
//end add by clb

    c = r->connection;

    if (c->error) {
        return NJT_ERROR;
    }

    size = 0;
    flush = 0;
    sync = 0;
    last = 0;
    ll = &r->out;

    /* find the size, the flush point and the last link of the saved chain */

    for (cl = r->out; cl; cl = cl->next) {
        ll = &cl->next;

        njt_log_debug7(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "write old buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

        if (njt_buf_size(cl->buf) == 0 && !njt_buf_special(cl->buf)) {
            njt_log_error(NJT_LOG_ALERT, c->log, 0,
                          "zero size buf in writer "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            njt_debug_point();
            return NJT_ERROR;
        }

        if (njt_buf_size(cl->buf) < 0) {
            njt_log_error(NJT_LOG_ALERT, c->log, 0,
                          "negative size buf in writer "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            njt_debug_point();
            return NJT_ERROR;
        }

        size += njt_buf_size(cl->buf);

        if (cl->buf->flush || cl->buf->recycled) {
            flush = 1;
        }

        if (cl->buf->sync) {
            sync = 1;
        }

        if (cl->buf->last_buf) {
            last = 1;
        }
    }

    /* add the new chain to the existent one */

    for (ln = in; ln; ln = ln->next) {
        cl = njt_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NJT_ERROR;
        }

        cl->buf = ln->buf;
        *ll = cl;
        ll = &cl->next;

        njt_log_debug7(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "write new buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

        if (njt_buf_size(cl->buf) == 0 && !njt_buf_special(cl->buf)) {
            njt_log_error(NJT_LOG_ALERT, c->log, 0,
                          "zero size buf in writer "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            njt_debug_point();
            return NJT_ERROR;
        }

        if (njt_buf_size(cl->buf) < 0) {
            njt_log_error(NJT_LOG_ALERT, c->log, 0,
                          "negative size buf in writer "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            njt_debug_point();
            return NJT_ERROR;
        }

        size += njt_buf_size(cl->buf);

        if (cl->buf->flush || cl->buf->recycled) {
            flush = 1;
        }

        if (cl->buf->sync) {
            sync = 1;
        }

        if (cl->buf->last_buf) {
            last = 1;
        }
    }

    *ll = NULL;

    njt_log_debug3(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http write filter: l:%ui f:%ui s:%O", last, flush, size);

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    /*
     * avoid the output if there are no last buf, no flush point,
     * there are the incoming bufs and the size of all bufs
     * is smaller than "postpone_output" directive
     */

    if (!last && !flush && in && size < (off_t) clcf->postpone_output) {
        return NJT_OK;
    }

    if (c->write->delayed) {
        c->buffered |= NJT_HTTP_WRITE_BUFFERED;
        return NJT_AGAIN;
    }

    if (size == 0
        && !(c->buffered & NJT_LOWLEVEL_BUFFERED)
        && !(last && c->need_last_buf)
        && !(flush && c->need_flush_buf))
    {
        if (last || flush || sync) {
            for (cl = r->out; cl; /* void */) {
                ln = cl;
                cl = cl->next;
                njt_free_chain(r->pool, ln);
            }

            r->out = NULL;
            c->buffered &= ~NJT_HTTP_WRITE_BUFFERED;

            if (last) {
                r->response_sent = 1;
            }

            return NJT_OK;
        }

        njt_log_error(NJT_LOG_ALERT, c->log, 0,
                      "the http output chain is empty");

        njt_debug_point();

        return NJT_ERROR;
    }

    if (!r->limit_rate_set) {
        r->limit_rate = njt_http_complex_value_size(r, clcf->limit_rate, 0);
        r->limit_rate_set = 1;
    }

//add by clb
// #if (NJT_HTTP_LIMIT_RATE_MULTI)
//     lrcf = njt_http_get_module_loc_conf(r, njt_http_limit_rate_multi_module);
//     if(lrcf->redis.len > 0){
//         limit_rate_multi_flag = 1;
//         if(r->limit_rate_multi == NULL){
//             r->limit_rate_multi = njt_pcalloc(r->pool, sizeof(njt_http_request_limit_rate_multi_t));
//             if(r->limit_rate_multi == NULL){
//                 njt_log_error(NJT_LOG_ALERT, c->log, 0,
//                 "the http limit rate multi malloc error");

//                 return NJT_ERROR;   
//             }
//         }
//     }

    if(clcf->limit_rate_multi){
        if(r->limit_rate_multi == NULL){
            r->limit_rate_multi = njt_pcalloc(r->pool, sizeof(njt_http_request_limit_rate_multi_t));
            if(r->limit_rate_multi == NULL){
                njt_log_error(NJT_LOG_ALERT, c->log, 0,
                "the http limit rate multi malloc error");

                return NJT_ERROR;   
            }
        }
        //check wether has valid rate date
        if(now >= r->limit_rate_multi->start_time
            && now < r->limit_rate_multi->end_time){
            njt_log_error(NJT_LOG_ALERT, c->log, 0,
                "==================now is in current time:%T  starttime:%T endtime:%T");
            if(r->limit_rate_multi->already_send < r->limit_rate_multi->could_send){
                //calc limit
                limit = r->limit_rate_multi->could_send - r->limit_rate_multi->already_send;
                njt_log_error(NJT_LOG_ALERT, c->log, 0,
                    "==================already send:%d could_send:%d  limit:%d",
                    r->limit_rate_multi->already_send,
                    r->limit_rate_multi->could_send,
                    limit);

            }else{
                //need wati to end_time
                c->write->delayed = 1;
                delay = (njt_msec_t) (r->limit_rate_multi->end_time - now);
                njt_add_timer(c->write, delay);

                njt_log_error(NJT_LOG_ALERT, c->log, 0,
                    "==================now time period has no rate, wait:%d", delay);

                c->buffered |= NJT_HTTP_WRITE_BUFFERED;

                return NJT_AGAIN;
            }

        }else{
            //need request new rate
            //todo: get rate from redis
            //need sent last_time_period_send


            //todo if IsNextTime is 1, then need wait. too


            //now just use rand
            //clear some data
            r->limit_rate_multi->rate = 10 * (rand()%3);     //[0, 40] bytes/sec
            r->limit_rate_multi->start_time = now;
            r->limit_rate_multi->end_time = now + 10;  //use 10 sec as interval
            r->limit_rate_multi->could_send = 0;
            r->limit_rate_multi->already_send = 0;
            njt_log_error(NJT_LOG_ALERT, c->log, 0,
                "==================get rate from redis rate:%d  starttime:%T endtime:%T",
                r->limit_rate_multi->rate,
                r->limit_rate_multi->start_time,
                r->limit_rate_multi->end_time);
            //calc could send
            if(r->limit_rate_multi->rate > 0){
                r->limit_rate_multi->could_send = r->limit_rate_multi->rate * (r->limit_rate_multi->end_time - r->limit_rate_multi->start_time);
                limit = r->limit_rate_multi->could_send;
            }else if(r->limit_rate_multi->rate == 0){
                //need wati to end_time
                c->write->delayed = 1;
                delay = (njt_msec_t) (r->limit_rate_multi->end_time - now);
                njt_add_timer(c->write, delay);

                c->buffered |= NJT_HTTP_WRITE_BUFFERED;
                njt_log_error(NJT_LOG_ALERT, c->log, 0,
                    "==================now rate is 0, wait:%d", delay);

                return NJT_AGAIN;
            }else{
                //not limit
                limit = clcf->sendfile_max_chunk;
                njt_log_error(NJT_LOG_ALERT, c->log, 0,
                    "==================now rate is less than 0, not limit");
            }
        }
    }else if(r->limit_rate){
// #else
//     if (r->limit_rate) {
// #endif
//end add by clb
        if (!r->limit_rate_after_set) {
            r->limit_rate_after = njt_http_complex_value_size(r,
                                                    clcf->limit_rate_after, 0);
            r->limit_rate_after_set = 1;
        }

        limit = (off_t) r->limit_rate * (njt_time() - r->start_sec + 1)
                - (c->sent - r->limit_rate_after);

        if (limit <= 0) {
            c->write->delayed = 1;
            delay = (njt_msec_t) (- limit * 1000 / r->limit_rate + 1);
            njt_add_timer(c->write, delay);

            c->buffered |= NJT_HTTP_WRITE_BUFFERED;

            return NJT_AGAIN;
        }

        if (clcf->sendfile_max_chunk
            && (off_t) clcf->sendfile_max_chunk < limit)
        {
            limit = clcf->sendfile_max_chunk;
        }

    } else {
        limit = clcf->sendfile_max_chunk;
    }


    sent = c->sent;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http write filter limit %O", limit);

    chain = c->send_chain(c, r->out, limit);

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http write filter %p", chain);

    if (chain == NJT_CHAIN_ERROR) {
        c->error = 1;
        return NJT_ERROR;
    }

//add by clb
// #if (NJT_HTTP_LIMIT_RATE_MULTI)
    if(clcf->limit_rate_multi){
        //calc alread send
        r->limit_rate_multi->already_send += (c->sent - sent);
        njt_log_error(NJT_LOG_ALERT, c->log, 0,
            "==================current time already send:%d  this time send:%d",
            r->limit_rate_multi->already_send,
            c->sent - sent);

    }else if(r->limit_rate){
// #else
//     if (r->limit_rate) {
// #endif
//end add by clb

        nsent = c->sent;

        if (r->limit_rate_after) {

            sent -= r->limit_rate_after;
            if (sent < 0) {
                sent = 0;
            }

            nsent -= r->limit_rate_after;
            if (nsent < 0) {
                nsent = 0;
            }
        }

        delay = (njt_msec_t) ((nsent - sent) * 1000 / r->limit_rate);

        if (delay > 0) {
            c->write->delayed = 1;
            njt_add_timer(c->write, delay);
        }
    }

    if (chain && c->write->ready && !c->write->delayed) {
        njt_post_event(c->write, &njt_posted_next_events);
    }

    for (cl = r->out; cl && cl != chain; /* void */) {
        ln = cl;
        cl = cl->next;
        njt_free_chain(r->pool, ln);
    }

    r->out = chain;

    if (chain) {
        c->buffered |= NJT_HTTP_WRITE_BUFFERED;
        return NJT_AGAIN;
    }

    c->buffered &= ~NJT_HTTP_WRITE_BUFFERED;

    if (last) {
        r->response_sent = 1;
    }

    if ((c->buffered & NJT_LOWLEVEL_BUFFERED) && r->postponed == NULL) {
        return NJT_AGAIN;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_write_filter_init(njt_conf_t *cf)
{
    njt_http_top_body_filter = njt_http_write_filter;

    return NJT_OK;
}
