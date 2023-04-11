
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_EVENT_CONNECT_H_INCLUDED_
#define _NJT_EVENT_CONNECT_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


#define NJT_PEER_KEEPALIVE           1
#define NJT_PEER_NEXT                2
#define NJT_PEER_FAILED              4


typedef struct njt_peer_connection_s  njt_peer_connection_t;

typedef njt_int_t (*njt_event_get_peer_pt)(njt_peer_connection_t *pc,
    void *data);
typedef void (*njt_event_free_peer_pt)(njt_peer_connection_t *pc, void *data,
    njt_uint_t state);
typedef void (*njt_event_notify_peer_pt)(njt_peer_connection_t *pc,
    void *data, njt_uint_t type);
typedef njt_int_t (*njt_event_set_peer_session_pt)(njt_peer_connection_t *pc,
    void *data);
typedef void (*njt_event_save_peer_session_pt)(njt_peer_connection_t *pc,
    void *data);


struct njt_peer_connection_s {
    njt_connection_t                *connection;

    struct sockaddr                 *sockaddr;
    socklen_t                        socklen;
    njt_str_t                       *name;

    njt_uint_t                       tries;
    njt_msec_t                       start_time;

    njt_event_get_peer_pt            get;
    njt_event_free_peer_pt           free;
    njt_event_notify_peer_pt         notify;
    void                            *data;

#if (NJT_SSL || NJT_COMPAT)
    njt_event_set_peer_session_pt    set_session;
    njt_event_save_peer_session_pt   save_session;
#endif

    njt_addr_t                      *local;

    int                              type;
    int                              rcvbuf;

    njt_log_t                       *log;

    unsigned                         cached:1;
    unsigned                         transparent:1;
    unsigned                         so_keepalive:1;
    unsigned                         down:1;

                                     /* njt_connection_log_error_e */
    unsigned                         log_error:2;

    NJT_COMPAT_BEGIN(2)
    NJT_COMPAT_END
};


njt_int_t njt_event_connect_peer(njt_peer_connection_t *pc);
njt_int_t njt_event_get_peer(njt_peer_connection_t *pc, void *data);


#endif /* _NJT_EVENT_CONNECT_H_INCLUDED_ */
