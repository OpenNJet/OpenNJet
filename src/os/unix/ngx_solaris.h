
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NJT_SOLARIS_H_INCLUDED_
#define _NJT_SOLARIS_H_INCLUDED_


ngx_chain_t *ngx_solaris_sendfilev_chain(ngx_connection_t *c, ngx_chain_t *in,
    off_t limit);


#endif /* _NJT_SOLARIS_H_INCLUDED_ */
