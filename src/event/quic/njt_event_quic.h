
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_EVENT_QUIC_H_INCLUDED_
#define _NJT_EVENT_QUIC_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


#define NJT_QUIC_MAX_UDP_PAYLOAD_SIZE        65527

#define NJT_QUIC_DEFAULT_ACK_DELAY_EXPONENT  3
#define NJT_QUIC_DEFAULT_MAX_ACK_DELAY       25
#define NJT_QUIC_DEFAULT_HOST_KEY_LEN        32
#define NJT_QUIC_SR_KEY_LEN                  32
#define NJT_QUIC_AV_KEY_LEN                  32

#define NJT_QUIC_SR_TOKEN_LEN                16

#define NJT_QUIC_MIN_INITIAL_SIZE            1200

#define NJT_QUIC_STREAM_SERVER_INITIATED     0x01
#define NJT_QUIC_STREAM_UNIDIRECTIONAL       0x02


typedef njt_int_t (*njt_quic_init_pt)(njt_connection_t *c);
typedef void (*njt_quic_shutdown_pt)(njt_connection_t *c);


typedef enum {
    NJT_QUIC_STREAM_SEND_READY = 0,
    NJT_QUIC_STREAM_SEND_SEND,
    NJT_QUIC_STREAM_SEND_DATA_SENT,
    NJT_QUIC_STREAM_SEND_DATA_RECVD,
    NJT_QUIC_STREAM_SEND_RESET_SENT,
    NJT_QUIC_STREAM_SEND_RESET_RECVD
} njt_quic_stream_send_state_e;


typedef enum {
    NJT_QUIC_STREAM_RECV_RECV = 0,
    NJT_QUIC_STREAM_RECV_SIZE_KNOWN,
    NJT_QUIC_STREAM_RECV_DATA_RECVD,
    NJT_QUIC_STREAM_RECV_DATA_READ,
    NJT_QUIC_STREAM_RECV_RESET_RECVD,
    NJT_QUIC_STREAM_RECV_RESET_READ
} njt_quic_stream_recv_state_e;


typedef struct {
    uint64_t                       size;
    uint64_t                       offset;
    uint64_t                       last_offset;
    njt_chain_t                   *chain;
    njt_chain_t                   *last_chain;
} njt_quic_buffer_t;


typedef struct {
    njt_ssl_t                     *ssl;

    njt_flag_t                     retry;
    njt_flag_t                     gso_enabled;
    njt_flag_t                     disable_active_migration;
    njt_msec_t                     handshake_timeout;
    njt_msec_t                     idle_timeout;
    njt_str_t                      host_key;
    size_t                         stream_buffer_size;
    njt_uint_t                     max_concurrent_streams_bidi;
    njt_uint_t                     max_concurrent_streams_uni;
    njt_uint_t                     active_connection_id_limit;
    njt_int_t                      stream_close_code;
    njt_int_t                      stream_reject_code_uni;
    njt_int_t                      stream_reject_code_bidi;

    njt_quic_init_pt               init;
    njt_quic_shutdown_pt           shutdown;

    u_char                         av_token_key[NJT_QUIC_AV_KEY_LEN];
    u_char                         sr_token_key[NJT_QUIC_SR_KEY_LEN];
} njt_quic_conf_t;


struct njt_quic_stream_s {
    njt_rbtree_node_t              node;
    njt_queue_t                    queue;
    njt_connection_t              *parent;
    njt_connection_t              *connection;
    uint64_t                       id;
    uint64_t                       sent;
    uint64_t                       acked;
    uint64_t                       send_max_data;
    uint64_t                       send_offset;
    uint64_t                       send_final_size;
    uint64_t                       recv_max_data;
    uint64_t                       recv_offset;
    uint64_t                       recv_window;
    uint64_t                       recv_last;
    uint64_t                       recv_final_size;
    njt_quic_buffer_t              send;
    njt_quic_buffer_t              recv;
    njt_quic_stream_send_state_e   send_state;
    njt_quic_stream_recv_state_e   recv_state;
    unsigned                       cancelable:1;
    unsigned                       fin_acked:1;
};


void njt_quic_recvmsg(njt_event_t *ev);
void njt_quic_run(njt_connection_t *c, njt_quic_conf_t *conf);
njt_connection_t *njt_quic_open_stream(njt_connection_t *c, njt_uint_t bidi);
void njt_quic_finalize_connection(njt_connection_t *c, njt_uint_t err,
    const char *reason);
void njt_quic_shutdown_connection(njt_connection_t *c, njt_uint_t err,
    const char *reason);
njt_int_t njt_quic_reset_stream(njt_connection_t *c, njt_uint_t err);
njt_int_t njt_quic_shutdown_stream(njt_connection_t *c, int how);
void njt_quic_cancelable_stream(njt_connection_t *c);
njt_int_t njt_quic_get_packet_dcid(njt_log_t *log, u_char *data, size_t len,
    njt_str_t *dcid);
njt_int_t njt_quic_derive_key(njt_log_t *log, const char *label,
    njt_str_t *secret, njt_str_t *salt, u_char *out, size_t len);

#endif /* _NJT_EVENT_QUIC_H_INCLUDED_ */
