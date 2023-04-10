
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_CHANNEL_H_INCLUDED_
#define _NJT_CHANNEL_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


typedef struct {
    njt_uint_t  command;
    njt_pid_t   pid;
    njt_int_t   slot;
    njt_fd_t    fd;
} njt_channel_t;


njt_int_t njt_write_channel(njt_socket_t s, njt_channel_t *ch, size_t size,
    njt_log_t *log);
njt_int_t njt_read_channel(njt_socket_t s, njt_channel_t *ch, size_t size,
    njt_log_t *log);
njt_int_t njt_add_channel_event(njt_cycle_t *cycle, njt_fd_t fd,
    njt_int_t event, njt_event_handler_pt handler);
void njt_close_channel(njt_fd_t *fd, njt_log_t *log);


#endif /* _NJT_CHANNEL_H_INCLUDED_ */
