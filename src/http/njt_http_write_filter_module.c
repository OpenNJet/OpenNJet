
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


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

//add by clb
#define NJT_HTTP_LIMIT_RATE_USERID "LIMIT_RATE_USER_ID"
#define NJT_HTTP_LIMIT_RATE_USERID_MAX_LEN 100
#define NJT_HTTP_LIMIT_RATE_LIMIT_CMD_ARG_MAX_LEN (NJT_HTTP_LIMIT_RATE_USERID_MAX_LEN + 100)

typedef enum {
    limit_rate_multi_parse_state_skipp_auth = 0,
    limit_rate_multi_parse_state_param_num,
    limit_rate_multi_parse_state_starttime_len,
    limit_rate_multi_parse_state_starttime,
    limit_rate_multi_parse_state_endtime_len,
    limit_rate_multi_parse_state_endtime,
    limit_rate_multi_parse_state_rate_len,
    limit_rate_multi_parse_state_rate,
    limit_rate_multi_parse_state_end
}njt_http_limit_rate_multi_parse_state;


// static off_t njt_http_limit_rate_multi_get_buffer_size(njt_chain_t *in){
//     off_t              size, total = 0;

//     for ( /* void */ ; in; in = in->next) {

//         if (njt_buf_special(in->buf)) {
//             continue;
//         }

//         if (in->buf->in_file) {
//             if(total > 0){
//                 return total;
//             }else{
//                 return (in->buf->file_last - in->buf->file_pos);
//             }
//         }

//         if (njt_buf_in_memory(in->buf)) {
//             size = njt_buf_size(in->buf);
//             total += size;
//         }
//     }

//     return total;
// }

static njt_int_t njt_http_limit_rate_multi_subrequest_parse_data(
        njt_http_request_limit_rate_multi_t *limit_rate_multi,
        u_char *data_start, u_char *data_end)
{
    u_char                          *index_start, *index_end;
    njt_http_limit_rate_multi_parse_state state = limit_rate_multi_parse_state_param_num;

    time_t                           start_time = 0, end_time = 0;
    njt_int_t                        rate = 0, last_not_use_rate = 0;


    if(data_start == NULL || data_end == NULL || data_start >= data_end){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
            "limit rate multi redis response data is null");
        return NJT_ERROR;
    }

    index_start = data_start;
    index_end =  data_start;

    while(index_end < data_end){
        //maybe frist auth return ok, skipp
        if(*index_end == '+'){
            state = limit_rate_multi_parse_state_skipp_auth;
        }

        //find \r\n
        if(*index_end == '\r'){
            switch (state)
            {
            case limit_rate_multi_parse_state_skipp_auth:

                state++;
                break;
            case limit_rate_multi_parse_state_param_num:
                if(*index_start != '*'
                    || index_end != index_start + 2
                    || 3 != *(index_end-1) - '0'){
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "limit rate multi redis response data format error, should be *3");

                    return NJT_ERROR;
                }

                state++;
                break;
            case limit_rate_multi_parse_state_starttime_len:
                if(*index_start != '$'){
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "limit rate multi redis response data starttime_len format error, should be $ start");

                    return NJT_ERROR;
                }

                state++;
                break;
            case limit_rate_multi_parse_state_starttime:
                start_time = njt_atotm(index_start, index_end - index_start);
                if(NJT_ERROR == start_time){
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "limit rate multi redis response data starttime format error");

                    return NJT_ERROR;
                }

                state++;
                break;
            case limit_rate_multi_parse_state_endtime_len:
                if(*index_start != '$'){
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "limit rate multi redis response data endtime_len format error, should be $ start");

                    return NJT_ERROR;
                }

                state++;
                break;
            case limit_rate_multi_parse_state_endtime:
                end_time = njt_atotm(index_start, index_end - index_start);
                if(NJT_ERROR == end_time){
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "limit rate multi redis response data endtime format error");

                    return NJT_ERROR;
                }

                state++;
                break;
            case limit_rate_multi_parse_state_rate_len:
                if(*index_start != '$'){
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "limit rate multi redis response data rate_len format error, should be $ start");

                    return NJT_ERROR;
                }

                state++;
                break;
            case limit_rate_multi_parse_state_rate:
                if(*index_start == '-'){
                    limit_rate_multi->rate = -1;
                    limit_rate_multi->could_send = 0;
                }else if(*index_start == '0'){
                    limit_rate_multi->rate = 0;
                    //need add last rate of not use
                    last_not_use_rate = limit_rate_multi->could_send - limit_rate_multi->already_send;
                    if(last_not_use_rate > 0){
                        limit_rate_multi->rate += last_not_use_rate;
                    }

                    limit_rate_multi->could_send = limit_rate_multi->rate;
                }else{
                    rate = njt_atoi(index_start, index_end - index_start);
                    if(NJT_ERROR == end_time){
                        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                            "limit rate multi redis response data endtime format error");

                        return NJT_ERROR;
                    }

                    limit_rate_multi->rate = rate;
                    //need add last rate of not use
                    last_not_use_rate = limit_rate_multi->could_send - limit_rate_multi->already_send;
                    if(last_not_use_rate > 0){
                        limit_rate_multi->rate += last_not_use_rate;
                    }
                    limit_rate_multi->could_send = limit_rate_multi->rate;
                }

                limit_rate_multi->already_send = 0;
                limit_rate_multi->start_time = start_time;
                limit_rate_multi->end_time = end_time;

                njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                    "limit rate multi parse use rate:%d last not use rate:%d starttime:%d  endtime:%d could_send:%d already_send:%d",
                    limit_rate_multi->rate,
                    last_not_use_rate,
                    limit_rate_multi->start_time,
                    limit_rate_multi->end_time,
                    limit_rate_multi->could_send,
                    limit_rate_multi->already_send);


                state++;
                break;
            default:
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                    "limit rate multi redis response data state error");

                return NJT_ERROR;                
            }

            if(limit_rate_multi_parse_state_end == state){
                break;
            }

            if(index_end + 1 >= data_end){
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                    "limit rate multi redis response data format error");

                return NJT_ERROR;
            }

            index_end += 2; //skip \r\n
            index_start = index_end;
        }else{
            index_end++;
        }
    }

    if(limit_rate_multi_parse_state_end != state){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
            "limit rate multi redis response data parse not normal end");

        return NJT_ERROR;
    }

    return NJT_OK;
}

static njt_int_t njt_http_limit_rate_multi_subrequest_post_handler(njt_http_request_t *r, void *data, njt_int_t rc)
{
    njt_http_request_t          *pr = r->parent;
    njt_str_t                   sub_data;
    njt_time_t					*tmptime;
    // time_t                      sec;
    time_t                      now;
    // struct timeval   tv;



    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
        "limit rate multi call subrequest handler, status:%d", r->headers_out.status);

    pr->headers_out.status = r->headers_out.status;
 
    if(r->headers_out.status == NJT_HTTP_OK){
        pr->limit_rate_multi->state = NJT_HTTPLIMIT_RATE_MULTI_REQUEST_INIT;
        njt_buf_t* pRecvBuf = &r->upstream->buffer;
 
        sub_data.data = pRecvBuf->pos;
        sub_data.len  = pRecvBuf->last - pRecvBuf->pos; //接收返回数据
 
        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0,
            "limit rate multi limit rate multi sub request response:%V", &sub_data);

        // njt_str_set(&sub_data, "*3\r\n$10\r\n1729827463\r\n$10\r\n1729832463\r\n$3\r\n100\r\n");

        //todo parse data
        // if(NJT_ERROR == njt_http_limit_rate_multi_subrequest_parse_data(pr->limit_rate_multi, pRecvBuf->pos, pRecvBuf->last)){
        if(NJT_ERROR == njt_http_limit_rate_multi_subrequest_parse_data(pr->limit_rate_multi, sub_data.data, sub_data.data + sub_data.len)){
            njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,
                "limit rate multi limit rate multi parse redis response data error:%V, just not limit", &sub_data);

            //if error, not limit 
            //clear some data
            // njt_gettimeofday(&tv);

            // sec = tv.tv_sec;
            // msec = tv.tv_usec / 1000;

            tmptime = njt_timeofday();
            now = tmptime->sec * 1000 + tmptime->msec;

            pr->limit_rate_multi->rate = -1;     //[0, 40] bytes/sec
            pr->limit_rate_multi->start_time = now;
            pr->limit_rate_multi->end_time = pr->limit_rate_multi->start_time + 2 * 1000;  //use 2 sec as interval
            pr->limit_rate_multi->could_send = 0;
            pr->limit_rate_multi->already_send = 0;
            njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                "limit rate multi userid:%V sec:%d  msec:%d  starttime:%d get rate from redis rate:%d  starttime:%T endtime:%T",
                &pr->limit_rate_multi->userid,
                tmptime->sec,
                tmptime->msec,
                pr->limit_rate_multi->start_time,
                pr->limit_rate_multi->rate,
                pr->limit_rate_multi->start_time,
                pr->limit_rate_multi->end_time);
        }

    }else{
        njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0,
                "limit rate multi, userid:%V request fail of send to redis ", &pr->limit_rate_multi->userid);

        //todo, delete after,just for test
        pr->limit_rate_multi->state = NJT_HTTPLIMIT_RATE_MULTI_REQUEST_FAIL;
    }

    return NJT_OK;
}

njt_int_t
njt_http_limit_rate_multi_create_subrequest(njt_http_request_t *r, njt_connection_t *c,
        off_t size, njt_uint_t last){
    njt_http_post_subrequest_t          *psr;
    njt_http_request_t                  *sr;
    njt_str_t                           sub_location;
    njt_str_t                           redis_arg;
    u_char                              *end_buf;   
    u_char                              redis_arg_buff[NJT_HTTP_LIMIT_RATE_LIMIT_CMD_ARG_MAX_LEN];

    //need request new rate
    psr = njt_palloc(r->pool, sizeof(njt_http_post_subrequest_t));
    if(psr == NULL)
    {
        njt_log_error(NJT_LOG_ALERT, c->log, 0,
            "limit_rate_multi malloc subrequest error");

        return NJT_ERROR;
    }

    psr->handler = njt_http_limit_rate_multi_subrequest_post_handler;

    psr->data = r;

    njt_str_set(&sub_location, "/limit_rate_redis");

    end_buf = njt_snprintf(redis_arg_buff, NJT_HTTP_LIMIT_RATE_LIMIT_CMD_ARG_MAX_LEN,
            "userid=%V&waitsend=%z&last=%d",
            &r->limit_rate_multi->userid,
            size,
            last);

    // end_buf = njt_snprintf(redis_arg_buff, NJT_HTTP_LIMIT_RATE_LIMIT_CMD_ARG_MAX_LEN,
    //         "userid=%V&totaldata=%d&sentdata=%d&last=%d",
    //         &r->limit_rate_multi->userid,
    //         total_data,
    //         r->limit_rate_multi->already_send,
    //         last);

    redis_arg.data = redis_arg_buff;
    redis_arg.len = end_buf - redis_arg_buff;

    redis_arg.data = njt_pcalloc(r->pool, redis_arg.len);
    if(redis_arg.data == NULL)
    {
        njt_log_error(NJT_LOG_ALERT, c->log, 0,
            "limit_rate_multi malloc subrequest args error");

        return NJT_ERROR;
    }

    njt_memcpy(redis_arg.data, redis_arg_buff, redis_arg.len);

    if(NJT_OK == njt_http_subrequest(r, &sub_location, &redis_arg, &sr, psr, 
            NJT_HTTP_SUBREQUEST_IN_MEMORY)){
        return NJT_AGAIN;
    }

    //create sub request fail
    return NJT_DECLINED;
}


//end add by clb

njt_int_t
njt_http_write_filter(njt_http_request_t *r, njt_chain_t *in)
{
    off_t                      size, sent, nsent, limit = 0;
    njt_uint_t                 last, flush, sync;
    njt_msec_t                 delay;
    njt_chain_t               *cl, *ln, **ll, *chain;
    njt_connection_t          *c;
    njt_http_core_loc_conf_t  *clcf;
//add by clb
    njt_int_t                   subreq_rc;
    time_t                      now;
    njt_time_t					*tmptime;
    njt_uint_t                  key;
    njt_str_t                   userid;
    njt_http_variable_value_t   *vv;
    u_char                      userid_buf[NJT_HTTP_LIMIT_RATE_USERID_MAX_LEN];
    off_t                       left_rate_len;


    userid.data = userid_buf;
    njt_memzero(userid_buf, NJT_HTTP_LIMIT_RATE_USERID_MAX_LEN);
    njt_memcpy(userid.data, NJT_HTTP_LIMIT_RATE_USERID, strlen(NJT_HTTP_LIMIT_RATE_USERID));
    userid.len = strlen(NJT_HTTP_LIMIT_RATE_USERID);
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
    if(clcf->limit_rate_multi){
        if(r->limit_rate_multi == NULL){
            r->limit_rate_multi = njt_pcalloc(r->pool, sizeof(njt_http_request_limit_rate_multi_t));
            if(r->limit_rate_multi == NULL){
                njt_log_error(NJT_LOG_ALERT, c->log, 0,
                "the http limit rate multi malloc error");

                return NJT_ERROR;
            }
        }

        //check wether has userid, if no userid, not limit
        if(r->limit_rate_multi->userid.len == 0){
            key = njt_hash_strlow(userid.data, userid.data, userid.len);
            vv = njt_http_get_variable(r, &userid, key);
            if (vv == NULL || vv->not_found || vv->len < 1) {
                njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                    "hos no userid, not limit rate");

                limit = clcf->sendfile_max_chunk;

                r->limit_rate_multi->rate = -1;

                r->limit_rate_multi->start_time = 0;
                r->limit_rate_multi->end_time = 0;
                r->limit_rate_multi->could_send = 0;
                r->limit_rate_multi->already_send = 0;
            }else{
                r->limit_rate_multi->userid.data = vv->data;
                r->limit_rate_multi->userid.len = vv->len;
            }
        }

        limit = clcf->sendfile_max_chunk;
        if(r->limit_rate_multi->userid.len > 0){
            //get wait send data len
            left_rate_len = r->limit_rate_multi->could_send - r->limit_rate_multi->already_send;
            if(left_rate_len > (off_t)0){
                //if has rate left, now use left rate first
                limit = left_rate_len;
                njt_log_error(NJT_LOG_INFO, c->log, 0,
                    "=================use left:%z  limit:%d",
                left_rate_len, limit);
            }else{
                // njt_gettimeofday(&tv);

                // sec = tv.tv_sec;
                // msec = tv.tv_usec / 1000;
                // now = sec * 1000 + msec;
                tmptime = njt_timeofday();
                now = tmptime->sec *1000 + tmptime->msec;

                njt_log_error(NJT_LOG_DEBUG, c->log, 0,
                    "limit rate multi now:%T starttime:%T  endtime:%T",
                now,
                r->limit_rate_multi->start_time,
                r->limit_rate_multi->end_time);
                //check wether has valid rate date
                if(now >= r->limit_rate_multi->start_time
                    && now < r->limit_rate_multi->end_time){
                    if(r->limit_rate_multi->rate > 0 && r->limit_rate_multi->already_send < r->limit_rate_multi->could_send){
                        //calc limit
                        limit = r->limit_rate_multi->could_send - r->limit_rate_multi->already_send;
                        njt_log_error(NJT_LOG_INFO, c->log, 0,
                            "limit rate multi userid:%V already send:%d could_send:%d  limit:%d",
                            &r->limit_rate_multi->userid,
                            r->limit_rate_multi->already_send,
                            r->limit_rate_multi->could_send,
                            limit);
                    }else if(r->limit_rate_multi->rate < 0){
                        limit = clcf->sendfile_max_chunk;
                        njt_log_error(NJT_LOG_INFO, c->log, 0,
                            "limit rate multi now:%T userid:%V rate less than 0, not limit",
                            now,
                            &r->limit_rate_multi->userid);
                    }else{
                        //need wati to end_time
                        c->write->delayed = 1;
                        delay = (njt_msec_t) (r->limit_rate_multi->end_time - now);
                        njt_add_timer(c->write, delay);

                        njt_log_error(NJT_LOG_INFO, c->log, 0,
                            "limit rate multi userid:%V now time period has no rate left, wait:%d ms",
                        &r->limit_rate_multi->userid,
                        delay);

                        c->buffered |= NJT_HTTP_WRITE_BUFFERED;

                        return NJT_AGAIN;
                    }
                }else if(now < r->limit_rate_multi->start_time){
                    //has next time ratge, need wati to next start_time
                    c->write->delayed = 1;
                    delay = (njt_msec_t) (r->limit_rate_multi->start_time - now);
                    njt_add_timer(c->write, delay);

                    njt_log_error(NJT_LOG_INFO, c->log, 0,
                        "limit rate multi userid:%V need wait next time period, starttime:%T  now:%T wait:%d ms",
                    &r->limit_rate_multi->userid,
                    r->limit_rate_multi->start_time,
                    now,
                    delay);

                    c->buffered |= NJT_HTTP_WRITE_BUFFERED;

                    return NJT_AGAIN;
                }else{
                    //check wether has request in this write, if has fail, not limit
                    if(NJT_HTTPLIMIT_RATE_MULTI_REQUEST_FAIL == r->limit_rate_multi->state){
                        r->limit_rate_multi->state = NJT_HTTPLIMIT_RATE_MULTI_REQUEST_INIT;
                        njt_log_error(NJT_LOG_NOTICE, c->log, 0,
                            "limit_rate_multi subrequest fail, not limit");
                        limit = clcf->sendfile_max_chunk;
                    }else{

                        subreq_rc = njt_http_limit_rate_multi_create_subrequest(r, c, size, last);
                        if(subreq_rc == NJT_ERROR){
                            return NJT_ERROR;
                        }

                        if(subreq_rc == NJT_AGAIN){
                            //just return, wait wakeup by subrequest
                            njt_log_error(NJT_LOG_DEBUG, c->log, 0,
                                "limit_rate_multi create subrequest ok, wait callback");
                            c->buffered |= NJT_HTTP_WRITE_BUFFERED;

                            return NJT_AGAIN;
                        }

                        //other case, not limit
                        njt_log_error(NJT_LOG_ALERT, c->log, 0,
                            "limit_rate_multi create subrequest fail, just not limit");
                        limit = clcf->sendfile_max_chunk;
                    }
                }
            }
        }
    }else if(r->limit_rate){
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
        // njt_log_error(NJT_LOG_INFO, c->log, 0,
        //     "==================limit:%d  realsend:%d",
        //     limit,
        //     c->sent - sent);
    njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http write filter %p", chain);

    if (chain == NJT_CHAIN_ERROR) {
        c->error = 1;
        return NJT_ERROR;
    }

//add by clb
    if(clcf->limit_rate_multi){
        //calc alread send
        r->limit_rate_multi->already_send += (c->sent - sent);
        njt_log_error(NJT_LOG_INFO, c->log, 0,
            "limit rate multi userid:%V current time already send:%d  this time send:%d  totalsend:%d limit:%d",
            &r->limit_rate_multi->userid,
            r->limit_rate_multi->already_send,
            c->sent - sent,
            c->sent,
            limit);
    }else if(r->limit_rate){
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
