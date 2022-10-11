
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NJET_LINUX_H_INCLUDED_
#define _NJET_LINUX_H_INCLUDED_


ngx_chain_t *ngx_linux_sendfile_chain(ngx_connection_t *c, ngx_chain_t *in,
    off_t limit);


#endif /* _NJET_LINUX_H_INCLUDED_ */
