
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_PROXY_PROTOCOL_H_INCLUDED_
#define _NJT_PROXY_PROTOCOL_H_INCLUDED_

#define NJT_PROXY_PROTOCOL_V1_MAX_HEADER  107
#define NJT_PROXY_PROTOCOL_MAX_HEADER     4096


struct njt_proxy_protocol_s {
    njt_str_t           src_addr;
    njt_str_t           dst_addr;
    in_port_t           src_port;
    in_port_t           dst_port;
    njt_str_t           tlvs;
};

typedef struct {
    u_char                                  signature[12];
    u_char                                  version_command;
    u_char                                  family_transport;
    u_char                                  len[2];
} njt_proxy_protocol_header_t;

u_char *njt_proxy_protocol_read(njt_connection_t *c, u_char *buf,
    u_char *last);
u_char *njt_proxy_protocol_write(njt_connection_t *c, u_char *buf,
    u_char *last);
njt_int_t njt_proxy_protocol_get_tlv(njt_connection_t *c, njt_str_t *name,
    njt_str_t *value);


#endif /* _NJT_PROXY_PROTOCOL_H_INCLUDED_ */
