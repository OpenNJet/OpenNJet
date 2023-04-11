
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_CONFIG_H_INCLUDED_
#define _NJT_HTTP_CONFIG_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


typedef struct {
    void        **main_conf;
    void        **srv_conf;
    void        **loc_conf;
} njt_http_conf_ctx_t;


typedef struct {
    njt_int_t   (*preconfiguration)(njt_conf_t *cf);
    njt_int_t   (*postconfiguration)(njt_conf_t *cf);

    void       *(*create_main_conf)(njt_conf_t *cf);
    char       *(*init_main_conf)(njt_conf_t *cf, void *conf);

    void       *(*create_srv_conf)(njt_conf_t *cf);
    char       *(*merge_srv_conf)(njt_conf_t *cf, void *prev, void *conf);

    void       *(*create_loc_conf)(njt_conf_t *cf);
    char       *(*merge_loc_conf)(njt_conf_t *cf, void *prev, void *conf);
} njt_http_module_t;


#define NJT_HTTP_MODULE           0x50545448   /* "HTTP" */

#define NJT_HTTP_MAIN_CONF        0x02000000
#define NJT_HTTP_SRV_CONF         0x04000000
#define NJT_HTTP_LOC_CONF         0x08000000
#define NJT_HTTP_UPS_CONF         0x10000000
#define NJT_HTTP_SIF_CONF         0x20000000
#define NJT_HTTP_LIF_CONF         0x40000000
#define NJT_HTTP_LMT_CONF         0x80000000


#define NJT_HTTP_MAIN_CONF_OFFSET  offsetof(njt_http_conf_ctx_t, main_conf)
#define NJT_HTTP_SRV_CONF_OFFSET   offsetof(njt_http_conf_ctx_t, srv_conf)
#define NJT_HTTP_LOC_CONF_OFFSET   offsetof(njt_http_conf_ctx_t, loc_conf)


#define njt_http_get_module_main_conf(r, module)                             \
    (r)->main_conf[module.ctx_index]
#define njt_http_get_module_srv_conf(r, module)  (r)->srv_conf[module.ctx_index]
#define njt_http_get_module_loc_conf(r, module)  (r)->loc_conf[module.ctx_index]


#define njt_http_conf_get_module_main_conf(cf, module)                        \
    ((njt_http_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define njt_http_conf_get_module_srv_conf(cf, module)                         \
    ((njt_http_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]
#define njt_http_conf_get_module_loc_conf(cf, module)                         \
    ((njt_http_conf_ctx_t *) cf->ctx)->loc_conf[module.ctx_index]

#define njt_http_cycle_get_module_main_conf(cycle, module)                    \
    (cycle->conf_ctx[njt_http_module.index] ?                                 \
        ((njt_http_conf_ctx_t *) cycle->conf_ctx[njt_http_module.index])      \
            ->main_conf[module.ctx_index]:                                    \
        NULL)


#endif /* _NJT_HTTP_CONFIG_H_INCLUDED_ */
