
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_IOCP_MODULE_H_INCLUDED_
#define _NJT_IOCP_MODULE_H_INCLUDED_


typedef struct {
    int  threads;
    int  post_acceptex;
    int  acceptex_read;
} njt_iocp_conf_t;


extern njt_module_t  njt_iocp_module;


#endif /* _NJT_IOCP_MODULE_H_INCLUDED_ */
