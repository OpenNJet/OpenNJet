/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */
#ifndef NJT_STREAM_UPSTREAM_DYNAMIC_SERVER_H_
#define NJT_STREAM_UPSTREAM_DYNAMIC_SERVER_H_
#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>

typedef struct {
    njt_stream_upstream_server_t   *us;
    njt_stream_upstream_srv_conf_t *upstream_conf;
    njt_str_t                     host;
    in_port_t                     port;
    njt_event_t                   timer;
    njt_uint_t                    count;
    uint32_t                      crc32;
	time_t                        valid;
    njt_int_t                     free_us;
	njt_stream_upstream_rr_peer_t  *parent_node;
} njt_stream_upstream_dynamic_server_conf_t;

typedef struct {
    njt_list_t                   *dynamic_servers;
	njt_list_t                   dy_servers;
	njt_list_t                   cache_servers;
    njt_stream_conf_ctx_t          *conf_ctx;
	njt_event_t                   timer;
	njt_shm_zone_t *shm_zone;
	njt_stream_upstream_rr_peers_t *peers;
	njt_stream_upstream_srv_conf_t *upstream_conf;
} njt_stream_upstream_dynamic_server_main_conf_t;

extern njt_module_t njt_stream_upstream_dynamic_servers_module;
#endif
