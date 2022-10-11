
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NJT_PROXY_PROTOCOL_H_INCLUDED_
#define _NJT_PROXY_PROTOCOL_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


#define NJT_PROXY_PROTOCOL_MAX_HEADER  107


struct njt_proxy_protocol_s {
    njt_str_t           src_addr;
    njt_str_t           dst_addr;
    in_port_t           src_port;
    in_port_t           dst_port;
};


u_char *njt_proxy_protocol_read(njt_connection_t *c, u_char *buf,
    u_char *last);
u_char *njt_proxy_protocol_write(njt_connection_t *c, u_char *buf,
    u_char *last);


#endif /* _NJT_PROXY_PROTOCOL_H_INCLUDED_ */
