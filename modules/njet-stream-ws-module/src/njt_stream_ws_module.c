/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_stream.h>

/* The module context. */
static njt_stream_module_t njt_stream_ws_module_ctx = {
    NULL, /* preconfiguration */
    NULL, /* postconfiguration */
    NULL,
    NULL, /* init main configuration */
    NULL, /* create server configuration */
    NULL /* merge server configuration */

};

/* Module definition. */
njt_module_t njt_stream_ws_module = {
    NJT_MODULE_V1,
    &njt_stream_ws_module_ctx, /* module context */
    NULL, /* module directives */
    NJT_STREAM_MODULE, /* module type */
    NULL, /* init master */
    NULL, /* init module */
    NULL, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    NULL, /* exit master */
    NJT_MODULE_V1_PADDING
};