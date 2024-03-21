
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_STREAM_UPSTREAM_H_INCLUDED_
#define _NJT_STREAM_UPSTREAM_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>
#include <njt_event_connect.h>


#define NJT_STREAM_UPSTREAM_CREATE        0x0001
#define NJT_STREAM_UPSTREAM_WEIGHT        0x0002
#define NJT_STREAM_UPSTREAM_MAX_FAILS     0x0004
#define NJT_STREAM_UPSTREAM_FAIL_TIMEOUT  0x0008
#define NJT_STREAM_UPSTREAM_DOWN          0x0010
#define NJT_STREAM_UPSTREAM_BACKUP        0x0020
#define NJT_STREAM_UPSTREAM_MAX_CONNS     0x0100
#define NJT_STREAM_UPSTREAM_SLOW_START    0x0200

#define NJT_STREAM_UPSTREAM_NOTIFY_CONNECT     0x1


typedef struct {
    njt_array_t                        upstreams;
                                           /* njt_stream_upstream_srv_conf_t */
} njt_stream_upstream_main_conf_t;


typedef struct njt_stream_upstream_srv_conf_s  njt_stream_upstream_srv_conf_t;


typedef njt_int_t (*njt_stream_upstream_init_pt)(njt_conf_t *cf,
    njt_stream_upstream_srv_conf_t *us);
typedef njt_int_t (*njt_stream_upstream_init_peer_pt)(njt_stream_session_t *s,
    njt_stream_upstream_srv_conf_t *us);


typedef struct {
    njt_stream_upstream_init_pt        init_upstream;
    njt_stream_upstream_init_peer_pt   init;
    void                              *data;
} njt_stream_upstream_peer_t;


typedef struct {
    njt_str_t                          name;
    njt_addr_t                        *addrs;
    njt_uint_t                         naddrs;
    njt_uint_t                         weight;
    njt_uint_t                         max_conns;
    njt_uint_t                         max_fails;
    time_t                             fail_timeout;
    njt_msec_t                         slow_start;
    njt_uint_t                         down;

    unsigned                           backup:1;
#if (NJT_HTTP_UPSTREAM_DYNAMIC_SERVER)
    unsigned                          dynamic:1;
    njt_int_t                          parent_id;
#endif
    NJT_COMPAT_BEGIN(4)
    NJT_COMPAT_END
} njt_stream_upstream_server_t;


struct njt_stream_upstream_srv_conf_s {
    njt_stream_upstream_peer_t         peer;
    void                             **srv_conf;

    njt_array_t                       *servers;
                                              /* njt_stream_upstream_server_t */

    njt_uint_t                         flags;
    njt_str_t                          host;
    u_char                            *file_name;
    njt_uint_t                         line;
    in_port_t                          port;
    njt_uint_t                         no_port;  /* unsigned no_port:1 */

#if (NJT_STREAM_UPSTREAM_ZONE)
    njt_shm_zone_t                    *shm_zone;
    njt_uint_t                        update_id;
#endif

#if (NJT_STREAM_FTP_PROXY)
    njt_pool_t                         *ftp_url_pool; 
#endif

#if (NJT_HTTP_UPSTREAM_DYNAMIC_SERVER)
    njt_str_t                       state_file;
    njt_resolver_t                 *resolver;/* resolver */
    njt_msec_t                      resolver_timeout;
    time_t                    valid;
    unsigned                         hc_type:2;
    unsigned                         reload:1;
    unsigned                         persistent:1;
    unsigned                         mandatory:1;
#endif
};


typedef struct {
    njt_msec_t                         response_time;
    njt_msec_t                         connect_time;
    njt_msec_t                         first_byte_time;
    off_t                              bytes_sent;
    off_t                              bytes_received;

    njt_str_t                         *peer;
} njt_stream_upstream_state_t;


typedef struct {
    njt_str_t                          host;
    in_port_t                          port;
    njt_uint_t                         no_port; /* unsigned no_port:1 */

    njt_uint_t                         naddrs;
    njt_resolver_addr_t               *addrs;

    struct sockaddr                   *sockaddr;
    socklen_t                          socklen;
    njt_str_t                          name;

    njt_resolver_ctx_t                *ctx;
} njt_stream_upstream_resolved_t;


typedef struct {
    njt_peer_connection_t              peer;

    njt_buf_t                          downstream_buf;
    njt_buf_t                          upstream_buf;

    njt_chain_t                       *free;
    njt_chain_t                       *upstream_out;
    njt_chain_t                       *upstream_busy;
    njt_chain_t                       *downstream_out;
    njt_chain_t                       *downstream_busy;

    off_t                              received;
    time_t                             start_sec;
    njt_uint_t                         requests;
    njt_uint_t                         responses;
    njt_msec_t                         start_time;

    size_t                             upload_rate;
    size_t                             download_rate;

    njt_str_t                          ssl_name;

    njt_stream_upstream_srv_conf_t    *upstream;
    njt_stream_upstream_resolved_t    *resolved;
    njt_stream_upstream_state_t       *state;
    unsigned                           connected:1;
    unsigned                           proxy_protocol:1;
    unsigned                           half_closed:1;
} njt_stream_upstream_t;


njt_stream_upstream_srv_conf_t *njt_stream_upstream_add(njt_conf_t *cf,
    njt_url_t *u, njt_uint_t flags);


#define njt_stream_conf_upstream_srv_conf(uscf, module)                       \
    uscf->srv_conf[module.ctx_index]


extern njt_module_t  njt_stream_upstream_module;

#ifndef HAVE_BALANCER_STATUS_CODE_PATCH
#define HAVE_BALANCER_STATUS_CODE_PATCH
#endif


#endif /* _NJT_STREAM_UPSTREAM_H_INCLUDED_ */
