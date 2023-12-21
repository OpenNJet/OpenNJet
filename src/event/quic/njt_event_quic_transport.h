
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_EVENT_QUIC_TRANSPORT_H_INCLUDED_
#define _NJT_EVENT_QUIC_TRANSPORT_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


/*
 * RFC 9000, 17.2.  Long Header Packets
 *           17.3.  Short Header Packets
 *
 * QUIC flags in first byte
 */
#define NJT_QUIC_PKT_LONG       0x80  /* header form */
#define NJT_QUIC_PKT_FIXED_BIT  0x40
#define NJT_QUIC_PKT_TYPE       0x30  /* in long packet */
#define NJT_QUIC_PKT_KPHASE     0x04  /* in short packet */

#define njt_quic_long_pkt(flags)  ((flags) & NJT_QUIC_PKT_LONG)
#define njt_quic_short_pkt(flags)  (((flags) & NJT_QUIC_PKT_LONG) == 0)

/* Long packet types */
#define NJT_QUIC_PKT_INITIAL    0x00
#define NJT_QUIC_PKT_ZRTT       0x10
#define NJT_QUIC_PKT_HANDSHAKE  0x20
#define NJT_QUIC_PKT_RETRY      0x30

#define njt_quic_pkt_in(flags)                                                \
    (((flags) & NJT_QUIC_PKT_TYPE) == NJT_QUIC_PKT_INITIAL)
#define njt_quic_pkt_zrtt(flags)                                              \
    (((flags) & NJT_QUIC_PKT_TYPE) == NJT_QUIC_PKT_ZRTT)
#define njt_quic_pkt_hs(flags)                                                \
    (((flags) & NJT_QUIC_PKT_TYPE) == NJT_QUIC_PKT_HANDSHAKE)
#define njt_quic_pkt_retry(flags)                                             \
    (((flags) & NJT_QUIC_PKT_TYPE) == NJT_QUIC_PKT_RETRY)

#define njt_quic_pkt_rb_mask(flags)                                           \
    (njt_quic_long_pkt(flags) ? 0x0C : 0x18)
#define njt_quic_pkt_hp_mask(flags)                                           \
    (njt_quic_long_pkt(flags) ? 0x0F : 0x1F)

#define njt_quic_level_name(lvl)                                              \
    (lvl == ssl_encryption_application) ? "app"                               \
        : (lvl == ssl_encryption_initial) ? "init"                            \
            : (lvl == ssl_encryption_handshake) ? "hs" : "early"

#define NJT_QUIC_MAX_CID_LEN                             20
#define NJT_QUIC_SERVER_CID_LEN                          NJT_QUIC_MAX_CID_LEN

/* 12.4.  Frames and Frame Types */
#define NJT_QUIC_FT_PADDING                              0x00
#define NJT_QUIC_FT_PING                                 0x01
#define NJT_QUIC_FT_ACK                                  0x02
#define NJT_QUIC_FT_ACK_ECN                              0x03
#define NJT_QUIC_FT_RESET_STREAM                         0x04
#define NJT_QUIC_FT_STOP_SENDING                         0x05
#define NJT_QUIC_FT_CRYPTO                               0x06
#define NJT_QUIC_FT_NEW_TOKEN                            0x07
#define NJT_QUIC_FT_STREAM                               0x08
#define NJT_QUIC_FT_STREAM1                              0x09
#define NJT_QUIC_FT_STREAM2                              0x0A
#define NJT_QUIC_FT_STREAM3                              0x0B
#define NJT_QUIC_FT_STREAM4                              0x0C
#define NJT_QUIC_FT_STREAM5                              0x0D
#define NJT_QUIC_FT_STREAM6                              0x0E
#define NJT_QUIC_FT_STREAM7                              0x0F
#define NJT_QUIC_FT_MAX_DATA                             0x10
#define NJT_QUIC_FT_MAX_STREAM_DATA                      0x11
#define NJT_QUIC_FT_MAX_STREAMS                          0x12
#define NJT_QUIC_FT_MAX_STREAMS2                         0x13
#define NJT_QUIC_FT_DATA_BLOCKED                         0x14
#define NJT_QUIC_FT_STREAM_DATA_BLOCKED                  0x15
#define NJT_QUIC_FT_STREAMS_BLOCKED                      0x16
#define NJT_QUIC_FT_STREAMS_BLOCKED2                     0x17
#define NJT_QUIC_FT_NEW_CONNECTION_ID                    0x18
#define NJT_QUIC_FT_RETIRE_CONNECTION_ID                 0x19
#define NJT_QUIC_FT_PATH_CHALLENGE                       0x1A
#define NJT_QUIC_FT_PATH_RESPONSE                        0x1B
#define NJT_QUIC_FT_CONNECTION_CLOSE                     0x1C
#define NJT_QUIC_FT_CONNECTION_CLOSE_APP                 0x1D
#define NJT_QUIC_FT_HANDSHAKE_DONE                       0x1E

#define NJT_QUIC_FT_LAST  NJT_QUIC_FT_HANDSHAKE_DONE

/* 22.5.  QUIC Transport Error Codes Registry */
#define NJT_QUIC_ERR_NO_ERROR                            0x00
#define NJT_QUIC_ERR_INTERNAL_ERROR                      0x01
#define NJT_QUIC_ERR_CONNECTION_REFUSED                  0x02
#define NJT_QUIC_ERR_FLOW_CONTROL_ERROR                  0x03
#define NJT_QUIC_ERR_STREAM_LIMIT_ERROR                  0x04
#define NJT_QUIC_ERR_STREAM_STATE_ERROR                  0x05
#define NJT_QUIC_ERR_FINAL_SIZE_ERROR                    0x06
#define NJT_QUIC_ERR_FRAME_ENCODING_ERROR                0x07
#define NJT_QUIC_ERR_TRANSPORT_PARAMETER_ERROR           0x08
#define NJT_QUIC_ERR_CONNECTION_ID_LIMIT_ERROR           0x09
#define NJT_QUIC_ERR_PROTOCOL_VIOLATION                  0x0A
#define NJT_QUIC_ERR_INVALID_TOKEN                       0x0B
#define NJT_QUIC_ERR_APPLICATION_ERROR                   0x0C
#define NJT_QUIC_ERR_CRYPTO_BUFFER_EXCEEDED              0x0D
#define NJT_QUIC_ERR_KEY_UPDATE_ERROR                    0x0E
#define NJT_QUIC_ERR_AEAD_LIMIT_REACHED                  0x0F
#define NJT_QUIC_ERR_NO_VIABLE_PATH                      0x10

#define NJT_QUIC_ERR_CRYPTO_ERROR                       0x100

#define NJT_QUIC_ERR_CRYPTO(e)  (NJT_QUIC_ERR_CRYPTO_ERROR + (e))


/* 22.3.  QUIC Transport Parameters Registry */
#define NJT_QUIC_TP_ORIGINAL_DCID                        0x00
#define NJT_QUIC_TP_MAX_IDLE_TIMEOUT                     0x01
#define NJT_QUIC_TP_SR_TOKEN                             0x02
#define NJT_QUIC_TP_MAX_UDP_PAYLOAD_SIZE                 0x03
#define NJT_QUIC_TP_INITIAL_MAX_DATA                     0x04
#define NJT_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL   0x05
#define NJT_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE  0x06
#define NJT_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI          0x07
#define NJT_QUIC_TP_INITIAL_MAX_STREAMS_BIDI             0x08
#define NJT_QUIC_TP_INITIAL_MAX_STREAMS_UNI              0x09
#define NJT_QUIC_TP_ACK_DELAY_EXPONENT                   0x0A
#define NJT_QUIC_TP_MAX_ACK_DELAY                        0x0B
#define NJT_QUIC_TP_DISABLE_ACTIVE_MIGRATION             0x0C
#define NJT_QUIC_TP_PREFERRED_ADDRESS                    0x0D
#define NJT_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT           0x0E
#define NJT_QUIC_TP_INITIAL_SCID                         0x0F
#define NJT_QUIC_TP_RETRY_SCID                           0x10

#define NJT_QUIC_CID_LEN_MIN                                8
#define NJT_QUIC_CID_LEN_MAX                               20

#define NJT_QUIC_MAX_RANGES                                10


typedef struct {
    uint64_t                                    gap;
    uint64_t                                    range;
} njt_quic_ack_range_t;


typedef struct {
    uint64_t                                    largest;
    uint64_t                                    delay;
    uint64_t                                    range_count;
    uint64_t                                    first_range;
    uint64_t                                    ect0;
    uint64_t                                    ect1;
    uint64_t                                    ce;
    uint64_t                                    ranges_length;
} njt_quic_ack_frame_t;


typedef struct {
    uint64_t                                    seqnum;
    uint64_t                                    retire;
    uint8_t                                     len;
    u_char                                      cid[NJT_QUIC_CID_LEN_MAX];
    u_char                                      srt[NJT_QUIC_SR_TOKEN_LEN];
} njt_quic_new_conn_id_frame_t;


typedef struct {
    uint64_t                                    length;
} njt_quic_new_token_frame_t;

/*
 * common layout for CRYPTO and STREAM frames;
 * conceptually, CRYPTO frame is also a stream
 * frame lacking some properties
 */
typedef struct {
    uint64_t                                    offset;
    uint64_t                                    length;
} njt_quic_ordered_frame_t;

typedef njt_quic_ordered_frame_t  njt_quic_crypto_frame_t;


typedef struct {
    /* initial fields same as in njt_quic_ordered_frame_t */
    uint64_t                                    offset;
    uint64_t                                    length;

    uint64_t                                    stream_id;
    unsigned                                    off:1;
    unsigned                                    len:1;
    unsigned                                    fin:1;
} njt_quic_stream_frame_t;


typedef struct {
    uint64_t                                    max_data;
} njt_quic_max_data_frame_t;


typedef struct {
    uint64_t                                    error_code;
    uint64_t                                    frame_type;
    njt_str_t                                   reason;
} njt_quic_close_frame_t;


typedef struct {
    uint64_t                                    id;
    uint64_t                                    error_code;
    uint64_t                                    final_size;
} njt_quic_reset_stream_frame_t;


typedef struct {
    uint64_t                                    id;
    uint64_t                                    error_code;
} njt_quic_stop_sending_frame_t;


typedef struct {
    uint64_t                                    limit;
    njt_uint_t                                  bidi;  /* unsigned: bidi:1 */
} njt_quic_streams_blocked_frame_t;


typedef struct {
    uint64_t                                    limit;
    njt_uint_t                                  bidi;  /* unsigned: bidi:1 */
} njt_quic_max_streams_frame_t;


typedef struct {
    uint64_t                                    id;
    uint64_t                                    limit;
} njt_quic_max_stream_data_frame_t;


typedef struct {
    uint64_t                                    limit;
} njt_quic_data_blocked_frame_t;


typedef struct {
    uint64_t                                    id;
    uint64_t                                    limit;
} njt_quic_stream_data_blocked_frame_t;


typedef struct {
    uint64_t                                    sequence_number;
} njt_quic_retire_cid_frame_t;


typedef struct {
    u_char                                      data[8];
} njt_quic_path_challenge_frame_t;


typedef struct njt_quic_frame_s                 njt_quic_frame_t;

struct njt_quic_frame_s {
    njt_uint_t                                  type;
    enum ssl_encryption_level_t                 level;
    njt_queue_t                                 queue;
    uint64_t                                    pnum;
    size_t                                      plen;
    njt_msec_t                                  send_time;
    ssize_t                                     len;
    unsigned                                    need_ack:1;
    unsigned                                    pkt_need_ack:1;
    unsigned                                    ignore_congestion:1;

    njt_chain_t                                *data;
    union {
        njt_quic_ack_frame_t                    ack;
        njt_quic_crypto_frame_t                 crypto;
        njt_quic_ordered_frame_t                ord;
        njt_quic_new_conn_id_frame_t            ncid;
        njt_quic_new_token_frame_t              token;
        njt_quic_stream_frame_t                 stream;
        njt_quic_max_data_frame_t               max_data;
        njt_quic_close_frame_t                  close;
        njt_quic_reset_stream_frame_t           reset_stream;
        njt_quic_stop_sending_frame_t           stop_sending;
        njt_quic_streams_blocked_frame_t        streams_blocked;
        njt_quic_max_streams_frame_t            max_streams;
        njt_quic_max_stream_data_frame_t        max_stream_data;
        njt_quic_data_blocked_frame_t           data_blocked;
        njt_quic_stream_data_blocked_frame_t    stream_data_blocked;
        njt_quic_retire_cid_frame_t             retire_cid;
        njt_quic_path_challenge_frame_t         path_challenge;
        njt_quic_path_challenge_frame_t         path_response;
    } u;
};


typedef struct {
    njt_log_t                                  *log;
    njt_quic_path_t                            *path;

    njt_quic_keys_t                            *keys;

    njt_msec_t                                  received;
    uint64_t                                    number;
    uint8_t                                     num_len;
    uint32_t                                    trunc;
    uint8_t                                     flags;
    uint32_t                                    version;
    njt_str_t                                   token;
    enum ssl_encryption_level_t                 level;
    njt_uint_t                                  error;

    /* filled in by parser */
    njt_buf_t                                  *raw;   /* udp datagram */

    u_char                                     *data;  /* quic packet */
    size_t                                      len;

    /* cleartext fields */
    njt_str_t                                   odcid; /* retry packet tag */
    u_char                                      odcid_buf[NJT_QUIC_MAX_CID_LEN];
    njt_str_t                                   dcid;
    njt_str_t                                   scid;
    uint64_t                                    pn;
    u_char                                     *plaintext;
    njt_str_t                                   payload; /* decrypted data */

    unsigned                                    need_ack:1;
    unsigned                                    key_phase:1;
    unsigned                                    key_update:1;
    unsigned                                    parsed:1;
    unsigned                                    decrypted:1;
    unsigned                                    validated:1;
    unsigned                                    retried:1;
    unsigned                                    first:1;
    unsigned                                    rebound:1;
    unsigned                                    path_challenged:1;
} njt_quic_header_t;


typedef struct {
    njt_msec_t                 max_idle_timeout;
    njt_msec_t                 max_ack_delay;

    size_t                     max_udp_payload_size;
    size_t                     initial_max_data;
    size_t                     initial_max_stream_data_bidi_local;
    size_t                     initial_max_stream_data_bidi_remote;
    size_t                     initial_max_stream_data_uni;
    njt_uint_t                 initial_max_streams_bidi;
    njt_uint_t                 initial_max_streams_uni;
    njt_uint_t                 ack_delay_exponent;
    njt_uint_t                 active_connection_id_limit;
    njt_flag_t                 disable_active_migration;

    njt_str_t                  original_dcid;
    njt_str_t                  initial_scid;
    njt_str_t                  retry_scid;
    u_char                     sr_token[NJT_QUIC_SR_TOKEN_LEN];

    /* TODO */
    void                      *preferred_address;
} njt_quic_tp_t;


njt_int_t njt_quic_parse_packet(njt_quic_header_t *pkt);

size_t njt_quic_create_version_negotiation(njt_quic_header_t *pkt, u_char *out);

size_t njt_quic_payload_size(njt_quic_header_t *pkt, size_t pkt_len);

size_t njt_quic_create_header(njt_quic_header_t *pkt, u_char *out,
    u_char **pnp);

size_t njt_quic_create_retry_itag(njt_quic_header_t *pkt, u_char *out,
    u_char **start);

ssize_t njt_quic_parse_frame(njt_quic_header_t *pkt, u_char *start, u_char *end,
    njt_quic_frame_t *frame);
ssize_t njt_quic_create_frame(u_char *p, njt_quic_frame_t *f);

ssize_t njt_quic_parse_ack_range(njt_log_t *log, u_char *start,
    u_char *end, uint64_t *gap, uint64_t *range);
size_t njt_quic_create_ack_range(u_char *p, uint64_t gap, uint64_t range);

njt_int_t njt_quic_init_transport_params(njt_quic_tp_t *tp,
    njt_quic_conf_t *qcf);
njt_int_t njt_quic_parse_transport_params(u_char *p, u_char *end,
    njt_quic_tp_t *tp, njt_log_t *log);
ssize_t njt_quic_create_transport_params(u_char *p, u_char *end,
    njt_quic_tp_t *tp, size_t *clen);

void njt_quic_dcid_encode_key(u_char *dcid, uint64_t key);

#endif /* _NJT_EVENT_QUIC_TRANSPORT_H_INCLUDED_ */
