/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */
#ifndef NJT_NAME_RESOLVER_MODULE_H_
#define NJT_NAME_RESOLVER_MODULE_H_
#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_stream.h>
extern njt_module_t njt_conf_ext_module;
extern njt_module_t njt_name_resolver_module;
typedef njt_int_t (*http_add_name_resolver_peer_pt)(njt_http_upstream_srv_conf_t *upstream, njt_http_upstream_rr_peer_t *peer, njt_flag_t backup);
typedef njt_int_t (*stream_add_name_resolver_peer_pt)(njt_stream_upstream_srv_conf_t *upstream, njt_stream_upstream_rr_peer_t *peer, njt_flag_t backup);
njt_int_t njt_http_upstream_add_name_resolve(njt_http_upstream_srv_conf_t *upstream);

typedef struct {
    http_add_name_resolver_peer_pt http_add_resolver_handle;
    stream_add_name_resolver_peer_pt stream_add_resolver_handle;
} njt_name_resolver_main_conf_t;
#endif
