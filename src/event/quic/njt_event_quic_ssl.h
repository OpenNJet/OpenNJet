
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_EVENT_QUIC_SSL_H_INCLUDED_
#define _NJT_EVENT_QUIC_SSL_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>

njt_int_t njt_quic_init_connection(njt_connection_t *c);

njt_int_t njt_quic_handle_crypto_frame(njt_connection_t *c,
    njt_quic_header_t *pkt, njt_quic_frame_t *frame);

#endif /* _NJT_EVENT_QUIC_SSL_H_INCLUDED_ */
