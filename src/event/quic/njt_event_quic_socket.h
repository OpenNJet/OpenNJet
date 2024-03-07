
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_EVENT_QUIC_SOCKET_H_INCLUDED_
#define _NJT_EVENT_QUIC_SOCKET_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


njt_int_t njt_quic_open_sockets(njt_connection_t *c,
    njt_quic_connection_t *qc, njt_quic_header_t *pkt);
void njt_quic_close_sockets(njt_connection_t *c);

njt_quic_socket_t *njt_quic_create_socket(njt_connection_t *c,
    njt_quic_connection_t *qc);
njt_int_t njt_quic_listen(njt_connection_t *c, njt_quic_connection_t *qc,
    njt_quic_socket_t *qsock);
void njt_quic_close_socket(njt_connection_t *c, njt_quic_socket_t *qsock);

njt_quic_socket_t *njt_quic_find_socket(njt_connection_t *c, uint64_t seqnum);


#endif /* _NJT_EVENT_QUIC_SOCKET_H_INCLUDED_ */
