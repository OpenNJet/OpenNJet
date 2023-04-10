
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_EVENT_PIPE_H_INCLUDED_
#define _NJT_EVENT_PIPE_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


typedef struct njt_event_pipe_s  njt_event_pipe_t;

typedef njt_int_t (*njt_event_pipe_input_filter_pt)(njt_event_pipe_t *p,
                                                    njt_buf_t *buf);
typedef njt_int_t (*njt_event_pipe_output_filter_pt)(void *data,
                                                     njt_chain_t *chain);


struct njt_event_pipe_s {
    njt_connection_t  *upstream;
    njt_connection_t  *downstream;

    njt_chain_t       *free_raw_bufs;
    njt_chain_t       *in;
    njt_chain_t      **last_in;

    njt_chain_t       *writing;

    njt_chain_t       *out;
    njt_chain_t       *free;
    njt_chain_t       *busy;

    /*
     * the input filter i.e. that moves HTTP/1.1 chunks
     * from the raw bufs to an incoming chain
     */

    njt_event_pipe_input_filter_pt    input_filter;
    void                             *input_ctx;

    njt_event_pipe_output_filter_pt   output_filter;
    void                             *output_ctx;

#if (NJT_THREADS || NJT_COMPAT)
    njt_int_t                       (*thread_handler)(njt_thread_task_t *task,
                                                      njt_file_t *file);
    void                             *thread_ctx;
    njt_thread_task_t                *thread_task;
#endif

    unsigned           read:1;
    unsigned           cacheable:1;
    unsigned           single_buf:1;
    unsigned           free_bufs:1;
    unsigned           upstream_done:1;
    unsigned           upstream_error:1;
    unsigned           upstream_eof:1;
    unsigned           upstream_blocked:1;
    unsigned           downstream_done:1;
    unsigned           downstream_error:1;
    unsigned           cyclic_temp_file:1;
    unsigned           aio:1;

    njt_int_t          allocated;
    njt_bufs_t         bufs;
    njt_buf_tag_t      tag;

    ssize_t            busy_size;

    off_t              read_length;
    off_t              length;

    off_t              max_temp_file_size;
    ssize_t            temp_file_write_size;

    njt_msec_t         read_timeout;
    njt_msec_t         send_timeout;
    ssize_t            send_lowat;

    njt_pool_t        *pool;
    njt_log_t         *log;

    njt_chain_t       *preread_bufs;
    size_t             preread_size;
    njt_buf_t         *buf_to_file;

    size_t             limit_rate;
    time_t             start_sec;

    njt_temp_file_t   *temp_file;

    /* STUB */ int     num;
};


njt_int_t njt_event_pipe(njt_event_pipe_t *p, njt_int_t do_write);
njt_int_t njt_event_pipe_copy_input_filter(njt_event_pipe_t *p, njt_buf_t *buf);
njt_int_t njt_event_pipe_add_free_buf(njt_event_pipe_t *p, njt_buf_t *b);


#endif /* _NJT_EVENT_PIPE_H_INCLUDED_ */
