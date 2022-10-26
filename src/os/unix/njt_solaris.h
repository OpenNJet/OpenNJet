
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) TMLake, Inc.
 */


#ifndef _NJT_SOLARIS_H_INCLUDED_
#define _NJT_SOLARIS_H_INCLUDED_


njt_chain_t *njt_solaris_sendfilev_chain(njt_connection_t *c, njt_chain_t *in,
    off_t limit);


#endif /* _NJT_SOLARIS_H_INCLUDED_ */
