/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */
#ifndef NJT_NAME_RESLOVER_MODULE_H_
#define NJT_NAME_RESLOVER_MODULE_H_
#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_stream.h>
extern njt_module_t njt_conf_ext_module;
void njt_http_upstream_notice_name_reslover(njt_http_upstream_srv_conf_t *uscf,njt_http_upstream_rr_peer_t *peer);
void njt_stream_upstream_notice_name_reslover(njt_stream_upstream_srv_conf_t *uscf,njt_stream_upstream_rr_peer_t *peer);
#endif
