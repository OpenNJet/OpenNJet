
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 * Copyright (C) Valentin V. Bartenev
 */


#ifndef _NJT_HTTP_V2_MODULE_H_INCLUDED_
#define _NJT_HTTP_V2_MODULE_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


typedef struct {
    size_t                          recv_buffer_size;
    u_char                         *recv_buffer;
} njt_http_v2_main_conf_t;


typedef struct {
    size_t                          chunk_size;
} njt_http_v2_loc_conf_t;


extern njt_module_t  njt_http_v2_module;


extern njt_module_t  njt_http_v2_module;


#endif /* _NJT_HTTP_V2_MODULE_H_INCLUDED_ */
