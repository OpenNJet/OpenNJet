
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_LINUX_H_INCLUDED_
#define _NJT_LINUX_H_INCLUDED_


njt_chain_t *njt_linux_sendfile_chain(njt_connection_t *c, njt_chain_t *in,
    off_t limit);


#endif /* _NJT_LINUX_H_INCLUDED_ */
