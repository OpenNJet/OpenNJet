
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_EVENT_QUIC_CONNID_H_INCLUDED_
#define _NJT_EVENT_QUIC_CONNID_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


njt_int_t njt_quic_handle_retire_connection_id_frame(njt_connection_t *c,
    njt_quic_retire_cid_frame_t *f);
njt_int_t njt_quic_handle_new_connection_id_frame(njt_connection_t *c,
    njt_quic_new_conn_id_frame_t *f);

njt_int_t njt_quic_create_sockets(njt_connection_t *c);
njt_int_t njt_quic_create_server_id(njt_connection_t *c, u_char *id);

njt_quic_client_id_t *njt_quic_create_client_id(njt_connection_t *c,
    njt_str_t *id, uint64_t seqnum, u_char *token);
njt_quic_client_id_t *njt_quic_next_client_id(njt_connection_t *c);
njt_int_t njt_quic_free_client_id(njt_connection_t *c,
    njt_quic_client_id_t *cid);

#endif /* _NJT_EVENT_QUIC_CONNID_H_INCLUDED_ */