
/*
 * Copyright (C) Nginx, Inc.
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
    size_t                          pool_size;
    njt_uint_t                      concurrent_streams;
    njt_uint_t                      concurrent_pushes;
    size_t                          preread_size;
    njt_uint_t                      streams_index_mask;
} njt_http_v2_srv_conf_t;


typedef struct {
    size_t                          chunk_size;

    njt_flag_t                      push_preload;

    njt_flag_t                      push;
    njt_array_t                    *pushes;
} njt_http_v2_loc_conf_t;


extern njt_module_t  njt_http_v2_module;


#endif /* _NJT_HTTP_V2_MODULE_H_INCLUDED_ */
