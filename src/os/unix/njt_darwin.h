
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_DARWIN_H_INCLUDED_
#define _NJT_DARWIN_H_INCLUDED_


void njt_debug_init(void);
njt_chain_t *njt_darwin_sendfile_chain(njt_connection_t *c, njt_chain_t *in,
    off_t limit);

extern int       njt_darwin_kern_osreldate;
extern int       njt_darwin_hw_ncpu;
extern u_long    njt_darwin_net_inet_tcp_sendspace;

extern njt_uint_t  njt_debug_malloc;


#endif /* _NJT_DARWIN_H_INCLUDED_ */
