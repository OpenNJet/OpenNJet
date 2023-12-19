/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_EVENT_QUIC_CONNECTION_H_INCLUDED_
#define _NJT_EVENT_QUIC_CONNECTION_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


/* #define NJT_QUIC_DEBUG_PACKETS */  /* dump packet contents */
/* #define NJT_QUIC_DEBUG_FRAMES */   /* dump frames contents */
/* #define NJT_QUIC_DEBUG_ALLOC */    /* log frames and bufs alloc */
/* #define NJT_QUIC_DEBUG_CRYPTO */

typedef struct njt_quic_connection_s  njt_quic_connection_t;
typedef struct njt_quic_server_id_s   njt_quic_server_id_t;
typedef struct njt_quic_client_id_s   njt_quic_client_id_t;
typedef struct njt_quic_send_ctx_s    njt_quic_send_ctx_t;
typedef struct njt_quic_socket_s      njt_quic_socket_t;
typedef struct njt_quic_path_s        njt_quic_path_t;
typedef struct njt_quic_keys_s        njt_quic_keys_t;

#if (NJT_QUIC_OPENSSL_COMPAT)
#include <njt_event_quic_openssl_compat.h>
#endif
#include <njt_event_quic_transport.h>
#include <njt_event_quic_protection.h>
#include <njt_event_quic_frames.h>
#include <njt_event_quic_migration.h>
#include <njt_event_quic_connid.h>
#include <njt_event_quic_streams.h>
#include <njt_event_quic_ssl.h>
#include <njt_event_quic_tokens.h>
#include <njt_event_quic_ack.h>
#include <njt_event_quic_output.h>
#include <njt_event_quic_socket.h>


/* RFC 9002, 6.2.2.  Handshakes and New Paths: kInitialRtt */
#define NJT_QUIC_INITIAL_RTT                 333 /* ms */

#define NJT_QUIC_UNSET_PN                    (uint64_t) -1

#define NJT_QUIC_SEND_CTX_LAST               (NJT_QUIC_ENCRYPTION_LAST - 1)

/*  0-RTT and 1-RTT data exist in the same packet number space,
 *  so we have 3 packet number spaces:
 *
 *  0 - Initial
 *  1 - Handshake
 *  2 - 0-RTT and 1-RTT
 */
#define njt_quic_get_send_ctx(qc, level)                                      \
    ((level) == ssl_encryption_initial) ? &((qc)->send_ctx[0])                \
        : (((level) == ssl_encryption_handshake) ? &((qc)->send_ctx[1])       \
                                                 : &((qc)->send_ctx[2]))

#define njt_quic_get_connection(c)                                            \
    (((c)->udp) ? (((njt_quic_socket_t *)((c)->udp))->quic) : NULL)

#define njt_quic_get_socket(c)               ((njt_quic_socket_t *)((c)->udp))

#define njt_quic_init_rtt(qc)                                                 \
    (qc)->avg_rtt = NJT_QUIC_INITIAL_RTT;                                     \
    (qc)->rttvar = NJT_QUIC_INITIAL_RTT / 2;                                  \
    (qc)->min_rtt = NJT_TIMER_INFINITE;                                       \
    (qc)->first_rtt = NJT_TIMER_INFINITE;                                     \
    (qc)->latest_rtt = 0;


typedef enum {
    NJT_QUIC_PATH_IDLE = 0,
    NJT_QUIC_PATH_VALIDATING,
    NJT_QUIC_PATH_WAITING,
    NJT_QUIC_PATH_MTUD
} njt_quic_path_state_e;

struct njt_quic_client_id_s {
    njt_queue_t                       queue;
    uint64_t                          seqnum;
    size_t                            len;
    u_char                            id[NJT_QUIC_CID_LEN_MAX];
    u_char                            sr_token[NJT_QUIC_SR_TOKEN_LEN];
    njt_uint_t                        used;  /* unsigned  used:1; */
};


struct njt_quic_server_id_s {
    uint64_t                          seqnum;
    size_t                            len;
    u_char                            id[NJT_QUIC_CID_LEN_MAX];
};


struct njt_quic_path_s {
    njt_queue_t                       queue;
    struct sockaddr                  *sockaddr;
    njt_sockaddr_t                    sa;
    socklen_t                         socklen;
    njt_quic_client_id_t             *cid;
    njt_quic_path_state_e             state;
    njt_msec_t                        expires;
    njt_uint_t                        tries;
    njt_uint_t                        tag;
    size_t                            mtu;
    size_t                            mtud;
    size_t                            max_mtu;
    off_t                             sent;
    off_t                             received;
    u_char                            challenge[2][8];
    uint64_t                          seqnum;
    uint64_t                          mtu_pnum[NJT_QUIC_PATH_RETRIES];
    njt_str_t                         addr_text;
    u_char                            text[NJT_SOCKADDR_STRLEN];
    unsigned                          validated:1;
    unsigned                          mtu_unvalidated:1;
};


struct njt_quic_socket_s {
    njt_udp_connection_t              udp;
    njt_quic_connection_t            *quic;
    njt_queue_t                       queue;
    njt_quic_server_id_t              sid;
    njt_sockaddr_t                    sockaddr;
    socklen_t                         socklen;
    njt_uint_t                        used; /* unsigned  used:1; */
};


typedef struct {
    njt_rbtree_t                      tree;
    njt_rbtree_node_t                 sentinel;

    njt_queue_t                       uninitialized;
    njt_queue_t                       free;

    uint64_t                          sent;
    uint64_t                          recv_offset;
    uint64_t                          recv_window;
    uint64_t                          recv_last;
    uint64_t                          recv_max_data;
    uint64_t                          send_offset;
    uint64_t                          send_max_data;

    uint64_t                          server_max_streams_uni;
    uint64_t                          server_max_streams_bidi;
    uint64_t                          server_streams_uni;
    uint64_t                          server_streams_bidi;

    uint64_t                          client_max_streams_uni;
    uint64_t                          client_max_streams_bidi;
    uint64_t                          client_streams_uni;
    uint64_t                          client_streams_bidi;

    njt_uint_t                        initialized;
                                                 /* unsigned  initialized:1; */
} njt_quic_streams_t;


typedef struct {
    size_t                            in_flight;
    size_t                            window;
    size_t                            ssthresh;
    njt_msec_t                        recovery_start;
} njt_quic_congestion_t;


/*
 * RFC 9000, 12.3.  Packet Numbers
 *
 *  Conceptually, a packet number space is the context in which a packet
 *  can be processed and acknowledged.  Initial packets can only be sent
 *  with Initial packet protection keys and acknowledged in packets that
 *  are also Initial packets.
 */
struct njt_quic_send_ctx_s {
    enum ssl_encryption_level_t       level;

    njt_quic_buffer_t                 crypto;
    uint64_t                          crypto_sent;

    uint64_t                          pnum;        /* to be sent */
    uint64_t                          largest_ack; /* received from peer */
    uint64_t                          largest_pn;  /* received from peer */

    njt_queue_t                       frames;      /* generated frames */
    njt_queue_t                       sending;     /* frames assigned to pkt */
    njt_queue_t                       sent;        /* frames waiting ACK */

    uint64_t                          pending_ack; /* non sent ack-eliciting */
    uint64_t                          largest_range;
    uint64_t                          first_range;
    njt_msec_t                        largest_received;
    njt_msec_t                        ack_delay_start;
    njt_uint_t                        nranges;
    njt_quic_ack_range_t              ranges[NJT_QUIC_MAX_RANGES];
    njt_uint_t                        send_ack;
};


struct njt_quic_connection_s {
    uint32_t                          version;

    njt_quic_path_t                  *path;

    njt_queue_t                       sockets;
    njt_queue_t                       paths;
    njt_queue_t                       client_ids;
    njt_queue_t                       free_sockets;
    njt_queue_t                       free_paths;
    njt_queue_t                       free_client_ids;

    njt_uint_t                        nsockets;
    njt_uint_t                        nclient_ids;
    uint64_t                          max_retired_seqnum;
    uint64_t                          client_seqnum;
    uint64_t                          server_seqnum;
    uint64_t                          path_seqnum;

    njt_quic_tp_t                     tp;
    njt_quic_tp_t                     ctp;

    njt_quic_send_ctx_t               send_ctx[NJT_QUIC_SEND_CTX_LAST];

    njt_quic_keys_t                  *keys;

    njt_quic_conf_t                  *conf;

    njt_event_t                       push;
    njt_event_t                       pto;
    njt_event_t                       close;
    njt_event_t                       path_validation;
    njt_event_t                       key_update;

    njt_msec_t                        last_cc;

    njt_msec_t                        first_rtt;
    njt_msec_t                        latest_rtt;
    njt_msec_t                        avg_rtt;
    njt_msec_t                        min_rtt;
    njt_msec_t                        rttvar;

    njt_uint_t                        pto_count;

    njt_queue_t                       free_frames;
    njt_buf_t                        *free_bufs;
    njt_buf_t                        *free_shadow_bufs;

    njt_uint_t                        nframes;
#ifdef NJT_QUIC_DEBUG_ALLOC
    njt_uint_t                        nbufs;
    njt_uint_t                        nshadowbufs;
#endif

#if (NJT_QUIC_OPENSSL_COMPAT)
    njt_quic_compat_t                *compat;
#endif

    njt_quic_streams_t                streams;
    njt_quic_congestion_t             congestion;

    uint64_t                          rst_pnum;    /* first on validated path */

    off_t                             received;

    njt_uint_t                        error;
    enum ssl_encryption_level_t       error_level;
    njt_uint_t                        error_ftype;
    const char                       *error_reason;

    njt_uint_t                        shutdown_code;
    const char                       *shutdown_reason;

    unsigned                          error_app:1;
    unsigned                          send_timer_set:1;
    unsigned                          closing:1;
    unsigned                          shutdown:1;
    unsigned                          draining:1;
    unsigned                          key_phase:1;
    unsigned                          validated:1;
    unsigned                          client_tp_done:1;
};


njt_int_t njt_quic_apply_transport_params(njt_connection_t *c,
    njt_quic_tp_t *ctp);
void njt_quic_discard_ctx(njt_connection_t *c,
    enum ssl_encryption_level_t level);
void njt_quic_close_connection(njt_connection_t *c, njt_int_t rc);
void njt_quic_shutdown_quic(njt_connection_t *c);

#if (NJT_DEBUG)
void njt_quic_connstate_dbg(njt_connection_t *c);
#else
#define njt_quic_connstate_dbg(c)
#endif

#endif /* _NJT_EVENT_QUIC_CONNECTION_H_INCLUDED_ */
