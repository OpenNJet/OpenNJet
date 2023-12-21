
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>
#include <njt_event_quic_connection.h>


#define NJT_QUIC_LONG_DCID_LEN_OFFSET  5
#define NJT_QUIC_LONG_DCID_OFFSET      6
#define NJT_QUIC_SHORT_DCID_OFFSET     1

#define NJT_QUIC_STREAM_FRAME_FIN      0x01
#define NJT_QUIC_STREAM_FRAME_LEN      0x02
#define NJT_QUIC_STREAM_FRAME_OFF      0x04


#if (NJT_HAVE_NONALIGNED)

#define njt_quic_parse_uint16(p)  ntohs(*(uint16_t *) (p))
#define njt_quic_parse_uint32(p)  ntohl(*(uint32_t *) (p))

#define njt_quic_write_uint16  njt_quic_write_uint16_aligned
#define njt_quic_write_uint32  njt_quic_write_uint32_aligned

#else

#define njt_quic_parse_uint16(p)  ((p)[0] << 8 | (p)[1])
#define njt_quic_parse_uint32(p)                                              \
    ((uint32_t) (p)[0] << 24 | (p)[1] << 16 | (p)[2] << 8 | (p)[3])

#define njt_quic_write_uint16(p, s)                                           \
    ((p)[0] = (u_char) ((s) >> 8),                                            \
     (p)[1] = (u_char)  (s),                                                  \
     (p) + sizeof(uint16_t))

#define njt_quic_write_uint32(p, s)                                           \
    ((p)[0] = (u_char) ((s) >> 24),                                           \
     (p)[1] = (u_char) ((s) >> 16),                                           \
     (p)[2] = (u_char) ((s) >> 8),                                            \
     (p)[3] = (u_char)  (s),                                                  \
     (p) + sizeof(uint32_t))

#endif

#define njt_quic_write_uint64(p, s)                                           \
    ((p)[0] = (u_char) ((s) >> 56),                                           \
     (p)[1] = (u_char) ((s) >> 48),                                           \
     (p)[2] = (u_char) ((s) >> 40),                                           \
     (p)[3] = (u_char) ((s) >> 32),                                           \
     (p)[4] = (u_char) ((s) >> 24),                                           \
     (p)[5] = (u_char) ((s) >> 16),                                           \
     (p)[6] = (u_char) ((s) >> 8),                                            \
     (p)[7] = (u_char)  (s),                                                  \
     (p) + sizeof(uint64_t))

#define njt_quic_write_uint24(p, s)                                           \
    ((p)[0] = (u_char) ((s) >> 16),                                           \
     (p)[1] = (u_char) ((s) >> 8),                                            \
     (p)[2] = (u_char)  (s),                                                  \
     (p) + 3)

#define njt_quic_write_uint16_aligned(p, s)                                   \
    (*(uint16_t *) (p) = htons((uint16_t) (s)), (p) + sizeof(uint16_t))

#define njt_quic_write_uint32_aligned(p, s)                                   \
    (*(uint32_t *) (p) = htonl((uint32_t) (s)), (p) + sizeof(uint32_t))

#define njt_quic_build_int_set(p, value, len, bits)                           \
    (*(p)++ = ((value >> ((len) * 8)) & 0xff) | ((bits) << 6))


static u_char *njt_quic_parse_int(u_char *pos, u_char *end, uint64_t *out);
static njt_uint_t njt_quic_varint_len(uint64_t value);
static void njt_quic_build_int(u_char **pos, uint64_t value);

static u_char *njt_quic_read_uint8(u_char *pos, u_char *end, uint8_t *value);
static u_char *njt_quic_read_uint32(u_char *pos, u_char *end, uint32_t *value);
static u_char *njt_quic_read_bytes(u_char *pos, u_char *end, size_t len,
    u_char **out);
static u_char *njt_quic_copy_bytes(u_char *pos, u_char *end, size_t len,
    u_char *dst);

static njt_int_t njt_quic_parse_short_header(njt_quic_header_t *pkt,
    size_t dcid_len);
static njt_int_t njt_quic_parse_long_header(njt_quic_header_t *pkt);
static njt_int_t njt_quic_supported_version(uint32_t version);
static njt_int_t njt_quic_parse_long_header_v1(njt_quic_header_t *pkt);

static size_t njt_quic_create_long_header(njt_quic_header_t *pkt, u_char *out,
    u_char **pnp);
static size_t njt_quic_create_short_header(njt_quic_header_t *pkt, u_char *out,
    u_char **pnp);

static njt_int_t njt_quic_frame_allowed(njt_quic_header_t *pkt,
    njt_uint_t frame_type);
static size_t njt_quic_create_ping(u_char *p);
static size_t njt_quic_create_ack(u_char *p, njt_quic_ack_frame_t *ack,
    njt_chain_t *ranges);
static size_t njt_quic_create_reset_stream(u_char *p,
    njt_quic_reset_stream_frame_t *rs);
static size_t njt_quic_create_stop_sending(u_char *p,
    njt_quic_stop_sending_frame_t *ss);
static size_t njt_quic_create_crypto(u_char *p,
    njt_quic_crypto_frame_t *crypto, njt_chain_t *data);
static size_t njt_quic_create_hs_done(u_char *p);
static size_t njt_quic_create_new_token(u_char *p,
    njt_quic_new_token_frame_t *token, njt_chain_t *data);
static size_t njt_quic_create_stream(u_char *p, njt_quic_stream_frame_t *sf,
    njt_chain_t *data);
static size_t njt_quic_create_max_streams(u_char *p,
    njt_quic_max_streams_frame_t *ms);
static size_t njt_quic_create_max_stream_data(u_char *p,
    njt_quic_max_stream_data_frame_t *ms);
static size_t njt_quic_create_max_data(u_char *p,
    njt_quic_max_data_frame_t *md);
static size_t njt_quic_create_path_challenge(u_char *p,
    njt_quic_path_challenge_frame_t *pc);
static size_t njt_quic_create_path_response(u_char *p,
    njt_quic_path_challenge_frame_t *pc);
static size_t njt_quic_create_new_connection_id(u_char *p,
    njt_quic_new_conn_id_frame_t *rcid);
static size_t njt_quic_create_retire_connection_id(u_char *p,
    njt_quic_retire_cid_frame_t *rcid);
static size_t njt_quic_create_close(u_char *p, njt_quic_frame_t *f);

static njt_int_t njt_quic_parse_transport_param(u_char *p, u_char *end,
    uint16_t id, njt_quic_tp_t *dst);


uint32_t  njt_quic_versions[] = {
    /* QUICv1 */
    0x00000001,
};

#define NJT_QUIC_NVERSIONS \
    (sizeof(njt_quic_versions) / sizeof(njt_quic_versions[0]))


static njt_inline u_char *
njt_quic_parse_int(u_char *pos, u_char *end, uint64_t *out)
{
    u_char      *p;
    uint64_t     value;
    njt_uint_t   len;

    if (pos >= end) {
        return NULL;
    }

    p = pos;
    len = 1 << (*p >> 6);

    value = *p++ & 0x3f;

    if ((size_t)(end - p) < (len - 1)) {
        return NULL;
    }

    while (--len) {
        value = (value << 8) + *p++;
    }

    *out = value;

    return p;
}


static njt_inline u_char *
njt_quic_read_uint8(u_char *pos, u_char *end, uint8_t *value)
{
    if ((size_t)(end - pos) < 1) {
        return NULL;
    }

    *value = *pos;

    return pos + 1;
}


static njt_inline u_char *
njt_quic_read_uint32(u_char *pos, u_char *end, uint32_t *value)
{
    if ((size_t)(end - pos) < sizeof(uint32_t)) {
        return NULL;
    }

    *value = njt_quic_parse_uint32(pos);

    return pos + sizeof(uint32_t);
}


static njt_inline u_char *
njt_quic_read_bytes(u_char *pos, u_char *end, size_t len, u_char **out)
{
    if ((size_t)(end - pos) < len) {
        return NULL;
    }

    *out = pos;

    return pos + len;
}


static u_char *
njt_quic_copy_bytes(u_char *pos, u_char *end, size_t len, u_char *dst)
{
    if ((size_t)(end - pos) < len) {
        return NULL;
    }

    njt_memcpy(dst, pos, len);

    return pos + len;
}


static njt_inline njt_uint_t
njt_quic_varint_len(uint64_t value)
{
    if (value < (1 << 6)) {
        return 1;
    }

    if (value < (1 << 14)) {
        return 2;
    }

    if (value < (1 << 30)) {
        return 4;
    }

    return 8;
}


static njt_inline void
njt_quic_build_int(u_char **pos, uint64_t value)
{
    u_char  *p;

    p = *pos;

    if (value < (1 << 6)) {
        njt_quic_build_int_set(p, value, 0, 0);

    } else if (value < (1 << 14)) {
        njt_quic_build_int_set(p, value, 1, 1);
        njt_quic_build_int_set(p, value, 0, 0);

    } else if (value < (1 << 30)) {
        njt_quic_build_int_set(p, value, 3, 2);
        njt_quic_build_int_set(p, value, 2, 0);
        njt_quic_build_int_set(p, value, 1, 0);
        njt_quic_build_int_set(p, value, 0, 0);

    } else {
        njt_quic_build_int_set(p, value, 7, 3);
        njt_quic_build_int_set(p, value, 6, 0);
        njt_quic_build_int_set(p, value, 5, 0);
        njt_quic_build_int_set(p, value, 4, 0);
        njt_quic_build_int_set(p, value, 3, 0);
        njt_quic_build_int_set(p, value, 2, 0);
        njt_quic_build_int_set(p, value, 1, 0);
        njt_quic_build_int_set(p, value, 0, 0);
    }

    *pos = p;
}


njt_int_t
njt_quic_parse_packet(njt_quic_header_t *pkt)
{
    if (!njt_quic_long_pkt(pkt->flags)) {
        pkt->level = ssl_encryption_application;

        if (njt_quic_parse_short_header(pkt, NJT_QUIC_SERVER_CID_LEN) != NJT_OK)
        {
            return NJT_ERROR;
        }

        return NJT_OK;
    }

    if (njt_quic_parse_long_header(pkt) != NJT_OK) {
        return NJT_ERROR;
    }

    if (!njt_quic_supported_version(pkt->version)) {
        return NJT_ABORT;
    }

    if (njt_quic_parse_long_header_v1(pkt) != NJT_OK) {
        return NJT_ERROR;
    }

    return NJT_OK;
}


static njt_int_t
njt_quic_parse_short_header(njt_quic_header_t *pkt, size_t dcid_len)
{
    u_char  *p, *end;

    p = pkt->raw->pos;
    end = pkt->data + pkt->len;

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, pkt->log, 0,
                   "quic packet rx short flags:%xd", pkt->flags);

    if (!(pkt->flags & NJT_QUIC_PKT_FIXED_BIT)) {
        njt_log_error(NJT_LOG_INFO, pkt->log, 0, "quic fixed bit is not set");
        return NJT_ERROR;
    }

    pkt->dcid.len = dcid_len;

    p = njt_quic_read_bytes(p, end, dcid_len, &pkt->dcid.data);
    if (p == NULL) {
        njt_log_error(NJT_LOG_INFO, pkt->log, 0,
                      "quic packet is too small to read dcid");
        return NJT_ERROR;
    }

    pkt->raw->pos = p;

    return NJT_OK;
}


static njt_int_t
njt_quic_parse_long_header(njt_quic_header_t *pkt)
{
    u_char   *p, *end;
    uint8_t   idlen;

    p = pkt->raw->pos;
    end = pkt->data + pkt->len;

    p = njt_quic_read_uint32(p, end, &pkt->version);
    if (p == NULL) {
        njt_log_error(NJT_LOG_INFO, pkt->log, 0,
                      "quic packet is too small to read version");
        return NJT_ERROR;
    }

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, pkt->log, 0,
                   "quic packet rx long flags:%xd version:%xD",
                   pkt->flags, pkt->version);

    if (!(pkt->flags & NJT_QUIC_PKT_FIXED_BIT)) {
        njt_log_error(NJT_LOG_INFO, pkt->log, 0, "quic fixed bit is not set");
        return NJT_ERROR;
    }

    p = njt_quic_read_uint8(p, end, &idlen);
    if (p == NULL) {
        njt_log_error(NJT_LOG_INFO, pkt->log, 0,
                      "quic packet is too small to read dcid len");
        return NJT_ERROR;
    }

    if (idlen > NJT_QUIC_CID_LEN_MAX) {
        njt_log_error(NJT_LOG_INFO, pkt->log, 0,
                      "quic packet dcid is too long");
        return NJT_ERROR;
    }

    pkt->dcid.len = idlen;

    p = njt_quic_read_bytes(p, end, idlen, &pkt->dcid.data);
    if (p == NULL) {
        njt_log_error(NJT_LOG_INFO, pkt->log, 0,
                      "quic packet is too small to read dcid");
        return NJT_ERROR;
    }

    p = njt_quic_read_uint8(p, end, &idlen);
    if (p == NULL) {
        njt_log_error(NJT_LOG_INFO, pkt->log, 0,
                      "quic packet is too small to read scid len");
        return NJT_ERROR;
    }

    if (idlen > NJT_QUIC_CID_LEN_MAX) {
        njt_log_error(NJT_LOG_INFO, pkt->log, 0,
                      "quic packet scid is too long");
        return NJT_ERROR;
    }

    pkt->scid.len = idlen;

    p = njt_quic_read_bytes(p, end, idlen, &pkt->scid.data);
    if (p == NULL) {
        njt_log_error(NJT_LOG_INFO, pkt->log, 0,
                      "quic packet is too small to read scid");
        return NJT_ERROR;
    }

    pkt->raw->pos = p;

    return NJT_OK;
}


static njt_int_t
njt_quic_supported_version(uint32_t version)
{
    njt_uint_t  i;

    for (i = 0; i < NJT_QUIC_NVERSIONS; i++) {
        if (njt_quic_versions[i] == version) {
            return 1;
        }
    }

    return 0;
}


static njt_int_t
njt_quic_parse_long_header_v1(njt_quic_header_t *pkt)
{
    u_char    *p, *end;
    uint64_t   varint;

    p = pkt->raw->pos;
    end = pkt->raw->last;

    pkt->log->action = "parsing quic long header";

    if (njt_quic_pkt_in(pkt->flags)) {

        if (pkt->len < NJT_QUIC_MIN_INITIAL_SIZE) {
            njt_log_error(NJT_LOG_INFO, pkt->log, 0,
                          "quic UDP datagram is too small for initial packet");
            return NJT_DECLINED;
        }

        p = njt_quic_parse_int(p, end, &varint);
        if (p == NULL) {
            njt_log_error(NJT_LOG_INFO, pkt->log, 0,
                          "quic failed to parse token length");
            return NJT_ERROR;
        }

        pkt->token.len = varint;

        p = njt_quic_read_bytes(p, end, pkt->token.len, &pkt->token.data);
        if (p == NULL) {
            njt_log_error(NJT_LOG_INFO, pkt->log, 0,
                          "quic packet too small to read token data");
            return NJT_ERROR;
        }

        pkt->level = ssl_encryption_initial;

    } else if (njt_quic_pkt_zrtt(pkt->flags)) {
        pkt->level = ssl_encryption_early_data;

    } else if (njt_quic_pkt_hs(pkt->flags)) {
        pkt->level = ssl_encryption_handshake;

    } else {
        njt_log_error(NJT_LOG_INFO, pkt->log, 0,
                      "quic bad packet type");
        return NJT_DECLINED;
    }

    p = njt_quic_parse_int(p, end, &varint);
    if (p == NULL) {
        njt_log_error(NJT_LOG_INFO, pkt->log, 0, "quic bad packet length");
        return NJT_ERROR;
    }

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, pkt->log, 0,
                   "quic packet rx %s len:%uL",
                   njt_quic_level_name(pkt->level), varint);

    if (varint > (uint64_t) ((pkt->data + pkt->len) - p)) {
        njt_log_error(NJT_LOG_INFO, pkt->log, 0, "quic truncated %s packet",
                      njt_quic_level_name(pkt->level));
        return NJT_ERROR;
    }

    pkt->raw->pos = p;
    pkt->len = p + varint - pkt->data;

    return NJT_OK;
}


njt_int_t
njt_quic_get_packet_dcid(njt_log_t *log, u_char *data, size_t n,
    njt_str_t *dcid)
{
    size_t  len, offset;

    if (n == 0) {
        goto failed;
    }

    if (njt_quic_long_pkt(*data)) {
        if (n < NJT_QUIC_LONG_DCID_LEN_OFFSET + 1) {
            goto failed;
        }

        len = data[NJT_QUIC_LONG_DCID_LEN_OFFSET];
        offset = NJT_QUIC_LONG_DCID_OFFSET;

    } else {
        len = NJT_QUIC_SERVER_CID_LEN;
        offset = NJT_QUIC_SHORT_DCID_OFFSET;
    }

    if (n < len + offset) {
        goto failed;
    }

    dcid->len = len;
    dcid->data = &data[offset];

    return NJT_OK;

failed:

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, log, 0, "quic malformed packet");

    return NJT_ERROR;
}


size_t
njt_quic_create_version_negotiation(njt_quic_header_t *pkt, u_char *out)
{
    u_char      *p, *start;
    njt_uint_t   i;

    p = start = out;

    *p++ = pkt->flags;

    /*
     * The Version field of a Version Negotiation packet
     * MUST be set to 0x00000000
     */
    p = njt_quic_write_uint32(p, 0);

    *p++ = pkt->dcid.len;
    p = njt_cpymem(p, pkt->dcid.data, pkt->dcid.len);

    *p++ = pkt->scid.len;
    p = njt_cpymem(p, pkt->scid.data, pkt->scid.len);

    for (i = 0; i < NJT_QUIC_NVERSIONS; i++) {
        p = njt_quic_write_uint32(p, njt_quic_versions[i]);
    }

    return p - start;
}


/* returns the amount of payload quic packet of "pkt_len" size may fit or 0 */
size_t
njt_quic_payload_size(njt_quic_header_t *pkt, size_t pkt_len)
{
    size_t  len;

    if (njt_quic_short_pkt(pkt->flags)) {

        len = 1 + pkt->dcid.len + pkt->num_len + NJT_QUIC_TAG_LEN;
        if (len > pkt_len) {
            return 0;
        }

        return pkt_len - len;
    }

    /* flags, version, dcid and scid with lengths and zero-length token */
    len = 5 + 2 + pkt->dcid.len + pkt->scid.len
          + (pkt->level == ssl_encryption_initial ? 1 : 0);

    if (len > pkt_len) {
        return 0;
    }

    /* (pkt_len - len) is 'remainder' packet length (see RFC 9000, 17.2) */
    len += njt_quic_varint_len(pkt_len - len)
           + pkt->num_len + NJT_QUIC_TAG_LEN;

    if (len > pkt_len) {
        return 0;
    }

    return pkt_len - len;
}


size_t
njt_quic_create_header(njt_quic_header_t *pkt, u_char *out, u_char **pnp)
{
    return njt_quic_short_pkt(pkt->flags)
           ? njt_quic_create_short_header(pkt, out, pnp)
           : njt_quic_create_long_header(pkt, out, pnp);
}


static size_t
njt_quic_create_long_header(njt_quic_header_t *pkt, u_char *out,
    u_char **pnp)
{
    size_t   rem_len;
    u_char  *p, *start;

    rem_len = pkt->num_len + pkt->payload.len + NJT_QUIC_TAG_LEN;

    if (out == NULL) {
        return 5 + 2 + pkt->dcid.len + pkt->scid.len
               + njt_quic_varint_len(rem_len) + pkt->num_len
               + (pkt->level == ssl_encryption_initial ? 1 : 0);
    }

    p = start = out;

    *p++ = pkt->flags;

    p = njt_quic_write_uint32(p, pkt->version);

    *p++ = pkt->dcid.len;
    p = njt_cpymem(p, pkt->dcid.data, pkt->dcid.len);

    *p++ = pkt->scid.len;
    p = njt_cpymem(p, pkt->scid.data, pkt->scid.len);

    if (pkt->level == ssl_encryption_initial) {
        njt_quic_build_int(&p, 0);
    }

    njt_quic_build_int(&p, rem_len);

    *pnp = p;

    switch (pkt->num_len) {
    case 1:
        *p++ = pkt->trunc;
        break;
    case 2:
        p = njt_quic_write_uint16(p, pkt->trunc);
        break;
    case 3:
        p = njt_quic_write_uint24(p, pkt->trunc);
        break;
    case 4:
        p = njt_quic_write_uint32(p, pkt->trunc);
        break;
    }

    return p - start;
}


static size_t
njt_quic_create_short_header(njt_quic_header_t *pkt, u_char *out,
    u_char **pnp)
{
    u_char  *p, *start;

    if (out == NULL) {
        return 1 + pkt->dcid.len + pkt->num_len;
    }

    p = start = out;

    *p++ = pkt->flags;

    p = njt_cpymem(p, pkt->dcid.data, pkt->dcid.len);

    *pnp = p;

    switch (pkt->num_len) {
    case 1:
        *p++ = pkt->trunc;
        break;
    case 2:
        p = njt_quic_write_uint16(p, pkt->trunc);
        break;
    case 3:
        p = njt_quic_write_uint24(p, pkt->trunc);
        break;
    case 4:
        p = njt_quic_write_uint32(p, pkt->trunc);
        break;
    }

    return p - start;
}


size_t
njt_quic_create_retry_itag(njt_quic_header_t *pkt, u_char *out,
    u_char **start)
{
    u_char  *p;

    p = out;

    *p++ = pkt->odcid.len;
    p = njt_cpymem(p, pkt->odcid.data, pkt->odcid.len);

    *start = p;

    *p++ = 0xff;

    p = njt_quic_write_uint32(p, pkt->version);

    *p++ = pkt->dcid.len;
    p = njt_cpymem(p, pkt->dcid.data, pkt->dcid.len);

    *p++ = pkt->scid.len;
    p = njt_cpymem(p, pkt->scid.data, pkt->scid.len);

    p = njt_cpymem(p, pkt->token.data, pkt->token.len);

    return p - out;
}


ssize_t
njt_quic_parse_frame(njt_quic_header_t *pkt, u_char *start, u_char *end,
    njt_quic_frame_t *f)
{
    u_char      *p;
    uint64_t     varint;
    njt_buf_t   *b;
    njt_uint_t   i;

    b = f->data->buf;

    p = start;

    p = njt_quic_parse_int(p, end, &varint);
    if (p == NULL) {
        pkt->error = NJT_QUIC_ERR_FRAME_ENCODING_ERROR;
        njt_log_error(NJT_LOG_INFO, pkt->log, 0,
                      "quic failed to obtain quic frame type");
        return NJT_ERROR;
    }

    if (varint > NJT_QUIC_FT_LAST) {
        pkt->error = NJT_QUIC_ERR_FRAME_ENCODING_ERROR;
        njt_log_error(NJT_LOG_INFO, pkt->log, 0,
                      "quic unknown frame type 0x%xL", varint);
        return NJT_ERROR;
    }

    f->type = varint;

    if (njt_quic_frame_allowed(pkt, f->type) != NJT_OK) {
        pkt->error = NJT_QUIC_ERR_PROTOCOL_VIOLATION;
        return NJT_ERROR;
    }

    switch (f->type) {

    case NJT_QUIC_FT_CRYPTO:

        p = njt_quic_parse_int(p, end, &f->u.crypto.offset);
        if (p == NULL) {
            goto error;
        }

        p = njt_quic_parse_int(p, end, &f->u.crypto.length);
        if (p == NULL) {
            goto error;
        }

        p = njt_quic_read_bytes(p, end, f->u.crypto.length, &b->pos);
        if (p == NULL) {
            goto error;
        }

        b->last = p;

        break;

    case NJT_QUIC_FT_PADDING:

        while (p < end && *p == NJT_QUIC_FT_PADDING) {
            p++;
        }

        break;

    case NJT_QUIC_FT_ACK:
    case NJT_QUIC_FT_ACK_ECN:

        p = njt_quic_parse_int(p, end, &f->u.ack.largest);
        if (p == NULL) {
            goto error;
        }

        p = njt_quic_parse_int(p, end, &f->u.ack.delay);
        if (p == NULL) {
            goto error;
        }

        p = njt_quic_parse_int(p, end, &f->u.ack.range_count);
        if (p == NULL) {
            goto error;
        }

        p = njt_quic_parse_int(p, end, &f->u.ack.first_range);
        if (p == NULL) {
            goto error;
        }

        b->pos = p;

        /* process all ranges to get bounds, values are ignored */
        for (i = 0; i < f->u.ack.range_count; i++) {

            p = njt_quic_parse_int(p, end, &varint);
            if (p == NULL) {
                goto error;
            }

            p = njt_quic_parse_int(p, end, &varint);
            if (p == NULL) {
                goto error;
            }
        }

        b->last = p;

        f->u.ack.ranges_length = b->last - b->pos;

        if (f->type == NJT_QUIC_FT_ACK_ECN) {

            p = njt_quic_parse_int(p, end, &f->u.ack.ect0);
            if (p == NULL) {
                goto error;
            }

            p = njt_quic_parse_int(p, end, &f->u.ack.ect1);
            if (p == NULL) {
                goto error;
            }

            p = njt_quic_parse_int(p, end, &f->u.ack.ce);
            if (p == NULL) {
                goto error;
            }

            njt_log_debug3(NJT_LOG_DEBUG_EVENT, pkt->log, 0,
                           "quic ACK ECN counters ect0:%uL ect1:%uL ce:%uL",
                           f->u.ack.ect0, f->u.ack.ect1, f->u.ack.ce);
        }

        break;

    case NJT_QUIC_FT_PING:
        break;

    case NJT_QUIC_FT_NEW_CONNECTION_ID:

        p = njt_quic_parse_int(p, end, &f->u.ncid.seqnum);
        if (p == NULL) {
            goto error;
        }

        p = njt_quic_parse_int(p, end, &f->u.ncid.retire);
        if (p == NULL) {
            goto error;
        }

        if (f->u.ncid.retire > f->u.ncid.seqnum) {
            goto error;
        }

        p = njt_quic_read_uint8(p, end, &f->u.ncid.len);
        if (p == NULL) {
            goto error;
        }

        if (f->u.ncid.len < 1 || f->u.ncid.len > NJT_QUIC_CID_LEN_MAX) {
            goto error;
        }

        p = njt_quic_copy_bytes(p, end, f->u.ncid.len, f->u.ncid.cid);
        if (p == NULL) {
            goto error;
        }

        p = njt_quic_copy_bytes(p, end, NJT_QUIC_SR_TOKEN_LEN, f->u.ncid.srt);
        if (p == NULL) {
            goto error;
        }

        break;

    case NJT_QUIC_FT_RETIRE_CONNECTION_ID:

        p = njt_quic_parse_int(p, end, &f->u.retire_cid.sequence_number);
        if (p == NULL) {
            goto error;
        }

        break;

    case NJT_QUIC_FT_CONNECTION_CLOSE:
    case NJT_QUIC_FT_CONNECTION_CLOSE_APP:

        p = njt_quic_parse_int(p, end, &f->u.close.error_code);
        if (p == NULL) {
            goto error;
        }

        if (f->type == NJT_QUIC_FT_CONNECTION_CLOSE) {
            p = njt_quic_parse_int(p, end, &f->u.close.frame_type);
            if (p == NULL) {
                goto error;
            }
        }

        p = njt_quic_parse_int(p, end, &varint);
        if (p == NULL) {
            goto error;
        }

        f->u.close.reason.len = varint;

        p = njt_quic_read_bytes(p, end, f->u.close.reason.len,
                                &f->u.close.reason.data);
        if (p == NULL) {
            goto error;
        }

        break;

    case NJT_QUIC_FT_STREAM:
    case NJT_QUIC_FT_STREAM1:
    case NJT_QUIC_FT_STREAM2:
    case NJT_QUIC_FT_STREAM3:
    case NJT_QUIC_FT_STREAM4:
    case NJT_QUIC_FT_STREAM5:
    case NJT_QUIC_FT_STREAM6:
    case NJT_QUIC_FT_STREAM7:

        f->u.stream.fin = (f->type & NJT_QUIC_STREAM_FRAME_FIN) ? 1 : 0;

        p = njt_quic_parse_int(p, end, &f->u.stream.stream_id);
        if (p == NULL) {
            goto error;
        }

        if (f->type & NJT_QUIC_STREAM_FRAME_OFF) {
            f->u.stream.off = 1;

            p = njt_quic_parse_int(p, end, &f->u.stream.offset);
            if (p == NULL) {
                goto error;
            }

        } else {
            f->u.stream.off = 0;
            f->u.stream.offset = 0;
        }

        if (f->type & NJT_QUIC_STREAM_FRAME_LEN) {
            f->u.stream.len = 1;

            p = njt_quic_parse_int(p, end, &f->u.stream.length);
            if (p == NULL) {
                goto error;
            }

        } else {
            f->u.stream.len = 0;
            f->u.stream.length = end - p; /* up to packet end */
        }

        p = njt_quic_read_bytes(p, end, f->u.stream.length, &b->pos);
        if (p == NULL) {
            goto error;
        }

        b->last = p;

        f->type = NJT_QUIC_FT_STREAM;
        break;

    case NJT_QUIC_FT_MAX_DATA:

        p = njt_quic_parse_int(p, end, &f->u.max_data.max_data);
        if (p == NULL) {
            goto error;
        }

        break;

    case NJT_QUIC_FT_RESET_STREAM:

        p = njt_quic_parse_int(p, end, &f->u.reset_stream.id);
        if (p == NULL) {
            goto error;
        }

        p = njt_quic_parse_int(p, end, &f->u.reset_stream.error_code);
        if (p == NULL) {
            goto error;
        }

        p = njt_quic_parse_int(p, end, &f->u.reset_stream.final_size);
        if (p == NULL) {
            goto error;
        }

        break;

    case NJT_QUIC_FT_STOP_SENDING:

        p = njt_quic_parse_int(p, end, &f->u.stop_sending.id);
        if (p == NULL) {
            goto error;
        }

        p = njt_quic_parse_int(p, end, &f->u.stop_sending.error_code);
        if (p == NULL) {
            goto error;
        }

        break;

    case NJT_QUIC_FT_STREAMS_BLOCKED:
    case NJT_QUIC_FT_STREAMS_BLOCKED2:

        p = njt_quic_parse_int(p, end, &f->u.streams_blocked.limit);
        if (p == NULL) {
            goto error;
        }

        if (f->u.streams_blocked.limit > 0x1000000000000000) {
            goto error;
        }

        f->u.streams_blocked.bidi =
                              (f->type == NJT_QUIC_FT_STREAMS_BLOCKED) ? 1 : 0;
        break;

    case NJT_QUIC_FT_MAX_STREAMS:
    case NJT_QUIC_FT_MAX_STREAMS2:

        p = njt_quic_parse_int(p, end, &f->u.max_streams.limit);
        if (p == NULL) {
            goto error;
        }

        if (f->u.max_streams.limit > 0x1000000000000000) {
            goto error;
        }

        f->u.max_streams.bidi = (f->type == NJT_QUIC_FT_MAX_STREAMS) ? 1 : 0;

        break;

    case NJT_QUIC_FT_MAX_STREAM_DATA:

        p = njt_quic_parse_int(p, end, &f->u.max_stream_data.id);
        if (p == NULL) {
            goto error;
        }

        p = njt_quic_parse_int(p, end, &f->u.max_stream_data.limit);
        if (p == NULL) {
            goto error;
        }

        break;

    case NJT_QUIC_FT_DATA_BLOCKED:

        p = njt_quic_parse_int(p, end, &f->u.data_blocked.limit);
        if (p == NULL) {
            goto error;
        }

        break;

    case NJT_QUIC_FT_STREAM_DATA_BLOCKED:

        p = njt_quic_parse_int(p, end, &f->u.stream_data_blocked.id);
        if (p == NULL) {
            goto error;
        }

        p = njt_quic_parse_int(p, end, &f->u.stream_data_blocked.limit);
        if (p == NULL) {
            goto error;
        }

        break;

    case NJT_QUIC_FT_PATH_CHALLENGE:

        p = njt_quic_copy_bytes(p, end, 8, f->u.path_challenge.data);
        if (p == NULL) {
            goto error;
        }

        break;

    case NJT_QUIC_FT_PATH_RESPONSE:

        p = njt_quic_copy_bytes(p, end, 8, f->u.path_response.data);
        if (p == NULL) {
            goto error;
        }

        break;

    default:
        njt_log_error(NJT_LOG_INFO, pkt->log, 0,
                      "quic unknown frame type 0x%xi", f->type);
        return NJT_ERROR;
    }

    f->level = pkt->level;
#if (NJT_DEBUG)
    f->pnum = pkt->pn;
#endif

    return p - start;

error:

    pkt->error = NJT_QUIC_ERR_FRAME_ENCODING_ERROR;

    njt_log_error(NJT_LOG_INFO, pkt->log, 0,
                  "quic failed to parse frame type:0x%xi", f->type);

    return NJT_ERROR;
}


static njt_int_t
njt_quic_frame_allowed(njt_quic_header_t *pkt, njt_uint_t frame_type)
{
    uint8_t  ptype;

    /*
     * RFC 9000, 12.4. Frames and Frame Types: Table 3
     *
     * Frame permissions per packet: 4 bits: IH01
     */
    static uint8_t njt_quic_frame_masks[] = {
         /* PADDING  */              0xF,
         /* PING */                  0xF,
         /* ACK */                   0xD,
         /* ACK_ECN */               0xD,
         /* RESET_STREAM */          0x3,
         /* STOP_SENDING */          0x3,
         /* CRYPTO */                0xD,
         /* NEW_TOKEN */             0x0, /* only sent by server */
         /* STREAM */                0x3,
         /* STREAM1 */               0x3,
         /* STREAM2 */               0x3,
         /* STREAM3 */               0x3,
         /* STREAM4 */               0x3,
         /* STREAM5 */               0x3,
         /* STREAM6 */               0x3,
         /* STREAM7 */               0x3,
         /* MAX_DATA */              0x3,
         /* MAX_STREAM_DATA */       0x3,
         /* MAX_STREAMS */           0x3,
         /* MAX_STREAMS2 */          0x3,
         /* DATA_BLOCKED */          0x3,
         /* STREAM_DATA_BLOCKED */   0x3,
         /* STREAMS_BLOCKED */       0x3,
         /* STREAMS_BLOCKED2 */      0x3,
         /* NEW_CONNECTION_ID */     0x3,
         /* RETIRE_CONNECTION_ID */  0x3,
         /* PATH_CHALLENGE */        0x3,
         /* PATH_RESPONSE */         0x1,
         /* CONNECTION_CLOSE */      0xF,
         /* CONNECTION_CLOSE2 */     0x3,
         /* HANDSHAKE_DONE */        0x0, /* only sent by server */
    };

    if (njt_quic_long_pkt(pkt->flags)) {

        if (njt_quic_pkt_in(pkt->flags)) {
            ptype = 8; /* initial */

        } else if (njt_quic_pkt_hs(pkt->flags)) {
            ptype = 4; /* handshake */

        } else {
            ptype = 2; /* zero-rtt */
        }

    } else {
        ptype = 1; /* application data */
    }

    if (ptype & njt_quic_frame_masks[frame_type]) {
        return NJT_OK;
    }

    njt_log_error(NJT_LOG_INFO, pkt->log, 0,
                  "quic frame type 0x%xi is not "
                  "allowed in packet with flags 0x%xd",
                  frame_type, pkt->flags);

    return NJT_DECLINED;
}


ssize_t
njt_quic_parse_ack_range(njt_log_t *log, u_char *start, u_char *end,
    uint64_t *gap, uint64_t *range)
{
    u_char  *p;

    p = start;

    p = njt_quic_parse_int(p, end, gap);
    if (p == NULL) {
        njt_log_error(NJT_LOG_INFO, log, 0,
                      "quic failed to parse ack frame gap");
        return NJT_ERROR;
    }

    p = njt_quic_parse_int(p, end, range);
    if (p == NULL) {
        njt_log_error(NJT_LOG_INFO, log, 0,
                      "quic failed to parse ack frame range");
        return NJT_ERROR;
    }

    return p - start;
}


size_t
njt_quic_create_ack_range(u_char *p, uint64_t gap, uint64_t range)
{
    size_t   len;
    u_char  *start;

    if (p == NULL) {
        len = njt_quic_varint_len(gap);
        len += njt_quic_varint_len(range);
        return len;
    }

    start = p;

    njt_quic_build_int(&p, gap);
    njt_quic_build_int(&p, range);

    return p - start;
}


ssize_t
njt_quic_create_frame(u_char *p, njt_quic_frame_t *f)
{
    /*
     *  RFC 9002, 2.  Conventions and Definitions
     *
     *  Ack-eliciting frames:  All frames other than ACK, PADDING, and
     *  CONNECTION_CLOSE are considered ack-eliciting.
     */
    f->need_ack = 1;

    switch (f->type) {
    case NJT_QUIC_FT_PING:
        return njt_quic_create_ping(p);

    case NJT_QUIC_FT_ACK:
        f->need_ack = 0;
        return njt_quic_create_ack(p, &f->u.ack, f->data);

    case NJT_QUIC_FT_RESET_STREAM:
        return njt_quic_create_reset_stream(p, &f->u.reset_stream);

    case NJT_QUIC_FT_STOP_SENDING:
        return njt_quic_create_stop_sending(p, &f->u.stop_sending);

    case NJT_QUIC_FT_CRYPTO:
        return njt_quic_create_crypto(p, &f->u.crypto, f->data);

    case NJT_QUIC_FT_HANDSHAKE_DONE:
        return njt_quic_create_hs_done(p);

    case NJT_QUIC_FT_NEW_TOKEN:
        return njt_quic_create_new_token(p, &f->u.token, f->data);

    case NJT_QUIC_FT_STREAM:
        return njt_quic_create_stream(p, &f->u.stream, f->data);

    case NJT_QUIC_FT_CONNECTION_CLOSE:
    case NJT_QUIC_FT_CONNECTION_CLOSE_APP:
        f->need_ack = 0;
        return njt_quic_create_close(p, f);

    case NJT_QUIC_FT_MAX_STREAMS:
        return njt_quic_create_max_streams(p, &f->u.max_streams);

    case NJT_QUIC_FT_MAX_STREAM_DATA:
        return njt_quic_create_max_stream_data(p, &f->u.max_stream_data);

    case NJT_QUIC_FT_MAX_DATA:
        return njt_quic_create_max_data(p, &f->u.max_data);

    case NJT_QUIC_FT_PATH_CHALLENGE:
        return njt_quic_create_path_challenge(p, &f->u.path_challenge);

    case NJT_QUIC_FT_PATH_RESPONSE:
        return njt_quic_create_path_response(p, &f->u.path_response);

    case NJT_QUIC_FT_NEW_CONNECTION_ID:
        return njt_quic_create_new_connection_id(p, &f->u.ncid);

    case NJT_QUIC_FT_RETIRE_CONNECTION_ID:
        return njt_quic_create_retire_connection_id(p, &f->u.retire_cid);

    default:
        /* BUG: unsupported frame type generated */
        return NJT_ERROR;
    }
}


static size_t
njt_quic_create_ping(u_char *p)
{
    u_char  *start;

    if (p == NULL) {
        return njt_quic_varint_len(NJT_QUIC_FT_PING);
    }

    start = p;

    njt_quic_build_int(&p, NJT_QUIC_FT_PING);

    return p - start;
}


static size_t
njt_quic_create_ack(u_char *p, njt_quic_ack_frame_t *ack, njt_chain_t *ranges)
{
    size_t      len;
    u_char     *start;
    njt_buf_t  *b;

    if (p == NULL) {
        len = njt_quic_varint_len(NJT_QUIC_FT_ACK);
        len += njt_quic_varint_len(ack->largest);
        len += njt_quic_varint_len(ack->delay);
        len += njt_quic_varint_len(ack->range_count);
        len += njt_quic_varint_len(ack->first_range);
        len += ack->ranges_length;

        return len;
    }

    start = p;

    njt_quic_build_int(&p, NJT_QUIC_FT_ACK);
    njt_quic_build_int(&p, ack->largest);
    njt_quic_build_int(&p, ack->delay);
    njt_quic_build_int(&p, ack->range_count);
    njt_quic_build_int(&p, ack->first_range);

    while (ranges) {
        b = ranges->buf;
        p = njt_cpymem(p, b->pos, b->last - b->pos);
        ranges = ranges->next;
    }

    return p - start;
}


static size_t
njt_quic_create_reset_stream(u_char *p, njt_quic_reset_stream_frame_t *rs)
{
    size_t   len;
    u_char  *start;

    if (p == NULL) {
        len = njt_quic_varint_len(NJT_QUIC_FT_RESET_STREAM);
        len += njt_quic_varint_len(rs->id);
        len += njt_quic_varint_len(rs->error_code);
        len += njt_quic_varint_len(rs->final_size);
        return len;
    }

    start = p;

    njt_quic_build_int(&p, NJT_QUIC_FT_RESET_STREAM);
    njt_quic_build_int(&p, rs->id);
    njt_quic_build_int(&p, rs->error_code);
    njt_quic_build_int(&p, rs->final_size);

    return p - start;
}


static size_t
njt_quic_create_stop_sending(u_char *p, njt_quic_stop_sending_frame_t *ss)
{
    size_t   len;
    u_char  *start;

    if (p == NULL) {
        len = njt_quic_varint_len(NJT_QUIC_FT_STOP_SENDING);
        len += njt_quic_varint_len(ss->id);
        len += njt_quic_varint_len(ss->error_code);
        return len;
    }

    start = p;

    njt_quic_build_int(&p, NJT_QUIC_FT_STOP_SENDING);
    njt_quic_build_int(&p, ss->id);
    njt_quic_build_int(&p, ss->error_code);

    return p - start;
}


static size_t
njt_quic_create_crypto(u_char *p, njt_quic_crypto_frame_t *crypto,
    njt_chain_t *data)
{
    size_t      len;
    u_char     *start;
    njt_buf_t  *b;

    if (p == NULL) {
        len = njt_quic_varint_len(NJT_QUIC_FT_CRYPTO);
        len += njt_quic_varint_len(crypto->offset);
        len += njt_quic_varint_len(crypto->length);
        len += crypto->length;

        return len;
    }

    start = p;

    njt_quic_build_int(&p, NJT_QUIC_FT_CRYPTO);
    njt_quic_build_int(&p, crypto->offset);
    njt_quic_build_int(&p, crypto->length);

    while (data) {
        b = data->buf;
        p = njt_cpymem(p, b->pos, b->last - b->pos);
        data = data->next;
    }

    return p - start;
}


static size_t
njt_quic_create_hs_done(u_char *p)
{
    u_char  *start;

    if (p == NULL) {
        return njt_quic_varint_len(NJT_QUIC_FT_HANDSHAKE_DONE);
    }

    start = p;

    njt_quic_build_int(&p, NJT_QUIC_FT_HANDSHAKE_DONE);

    return p - start;
}


static size_t
njt_quic_create_new_token(u_char *p, njt_quic_new_token_frame_t *token,
    njt_chain_t *data)
{
    size_t      len;
    u_char     *start;
    njt_buf_t  *b;

    if (p == NULL) {
        len = njt_quic_varint_len(NJT_QUIC_FT_NEW_TOKEN);
        len += njt_quic_varint_len(token->length);
        len += token->length;

        return len;
    }

    start = p;

    njt_quic_build_int(&p, NJT_QUIC_FT_NEW_TOKEN);
    njt_quic_build_int(&p, token->length);

    while (data) {
        b = data->buf;
        p = njt_cpymem(p, b->pos, b->last - b->pos);
        data = data->next;
    }

    return p - start;
}


static size_t
njt_quic_create_stream(u_char *p, njt_quic_stream_frame_t *sf,
    njt_chain_t *data)
{
    size_t      len;
    u_char     *start, type;
    njt_buf_t  *b;

    type = NJT_QUIC_FT_STREAM;

    if (sf->off) {
        type |= NJT_QUIC_STREAM_FRAME_OFF;
    }

    if (sf->len) {
        type |= NJT_QUIC_STREAM_FRAME_LEN;
    }

    if (sf->fin) {
        type |= NJT_QUIC_STREAM_FRAME_FIN;
    }

    if (p == NULL) {
        len = njt_quic_varint_len(type);
        len += njt_quic_varint_len(sf->stream_id);

        if (sf->off) {
            len += njt_quic_varint_len(sf->offset);
        }

        if (sf->len) {
            len += njt_quic_varint_len(sf->length);
        }

        len += sf->length;

        return len;
    }

    start = p;

    njt_quic_build_int(&p, type);
    njt_quic_build_int(&p, sf->stream_id);

    if (sf->off) {
        njt_quic_build_int(&p, sf->offset);
    }

    if (sf->len) {
        njt_quic_build_int(&p, sf->length);
    }

    while (data) {
        b = data->buf;
        p = njt_cpymem(p, b->pos, b->last - b->pos);
        data = data->next;
    }

    return p - start;
}


static size_t
njt_quic_create_max_streams(u_char *p, njt_quic_max_streams_frame_t *ms)
{
    size_t       len;
    u_char      *start;
    njt_uint_t   type;

    type = ms->bidi ? NJT_QUIC_FT_MAX_STREAMS : NJT_QUIC_FT_MAX_STREAMS2;

    if (p == NULL) {
        len = njt_quic_varint_len(type);
        len += njt_quic_varint_len(ms->limit);
        return len;
    }

    start = p;

    njt_quic_build_int(&p, type);
    njt_quic_build_int(&p, ms->limit);

    return p - start;
}


static njt_int_t
njt_quic_parse_transport_param(u_char *p, u_char *end, uint16_t id,
    njt_quic_tp_t *dst)
{
    uint64_t   varint;
    njt_str_t  str;

    varint = 0;
    njt_str_null(&str);

    switch (id) {

    case NJT_QUIC_TP_DISABLE_ACTIVE_MIGRATION:
        /* zero-length option */
        if (end - p != 0) {
            return NJT_ERROR;
        }
        dst->disable_active_migration = 1;
        return NJT_OK;

    case NJT_QUIC_TP_MAX_IDLE_TIMEOUT:
    case NJT_QUIC_TP_MAX_UDP_PAYLOAD_SIZE:
    case NJT_QUIC_TP_INITIAL_MAX_DATA:
    case NJT_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
    case NJT_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
    case NJT_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI:
    case NJT_QUIC_TP_INITIAL_MAX_STREAMS_BIDI:
    case NJT_QUIC_TP_INITIAL_MAX_STREAMS_UNI:
    case NJT_QUIC_TP_ACK_DELAY_EXPONENT:
    case NJT_QUIC_TP_MAX_ACK_DELAY:
    case NJT_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT:

        p = njt_quic_parse_int(p, end, &varint);
        if (p == NULL) {
            return NJT_ERROR;
        }
        break;

    case NJT_QUIC_TP_INITIAL_SCID:

        str.len = end - p;
        str.data = p;
        break;

    default:
        return NJT_DECLINED;
    }

    switch (id) {

    case NJT_QUIC_TP_MAX_IDLE_TIMEOUT:
        dst->max_idle_timeout = varint;
        break;

    case NJT_QUIC_TP_MAX_UDP_PAYLOAD_SIZE:
        dst->max_udp_payload_size = varint;
        break;

    case NJT_QUIC_TP_INITIAL_MAX_DATA:
        dst->initial_max_data = varint;
        break;

    case NJT_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
        dst->initial_max_stream_data_bidi_local = varint;
        break;

    case NJT_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
        dst->initial_max_stream_data_bidi_remote = varint;
        break;

    case NJT_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI:
        dst->initial_max_stream_data_uni = varint;
        break;

    case NJT_QUIC_TP_INITIAL_MAX_STREAMS_BIDI:
        dst->initial_max_streams_bidi = varint;
        break;

    case NJT_QUIC_TP_INITIAL_MAX_STREAMS_UNI:
        dst->initial_max_streams_uni = varint;
        break;

    case NJT_QUIC_TP_ACK_DELAY_EXPONENT:
        dst->ack_delay_exponent = varint;
        break;

    case NJT_QUIC_TP_MAX_ACK_DELAY:
        dst->max_ack_delay = varint;
        break;

    case NJT_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT:
        dst->active_connection_id_limit = varint;
        break;

    case NJT_QUIC_TP_INITIAL_SCID:
        dst->initial_scid = str;
        break;

    default:
        return NJT_ERROR;
    }

    return NJT_OK;
}


njt_int_t
njt_quic_parse_transport_params(u_char *p, u_char *end, njt_quic_tp_t *tp,
    njt_log_t *log)
{
    uint64_t   id, len;
    njt_int_t  rc;

    while (p < end) {
        p = njt_quic_parse_int(p, end, &id);
        if (p == NULL) {
            njt_log_error(NJT_LOG_INFO, log, 0,
                          "quic failed to parse transport param id");
            return NJT_ERROR;
        }

        switch (id) {
        case NJT_QUIC_TP_ORIGINAL_DCID:
        case NJT_QUIC_TP_PREFERRED_ADDRESS:
        case NJT_QUIC_TP_RETRY_SCID:
        case NJT_QUIC_TP_SR_TOKEN:
            njt_log_error(NJT_LOG_INFO, log, 0,
                          "quic client sent forbidden transport param"
                          " id:0x%xL", id);
            return NJT_ERROR;
        }

        p = njt_quic_parse_int(p, end, &len);
        if (p == NULL) {
            njt_log_error(NJT_LOG_INFO, log, 0,
                          "quic failed to parse"
                          " transport param id:0x%xL length", id);
            return NJT_ERROR;
        }

        rc = njt_quic_parse_transport_param(p, p + len, id, tp);

        if (rc == NJT_ERROR) {
            njt_log_error(NJT_LOG_INFO, log, 0,
                          "quic failed to parse"
                          " transport param id:0x%xL data", id);
            return NJT_ERROR;
        }

        if (rc == NJT_DECLINED) {
            njt_log_error(NJT_LOG_INFO, log, 0,
                          "quic %s transport param id:0x%xL, skipped",
                          (id % 31 == 27) ? "reserved" : "unknown", id);
        }

        p += len;
    }

    if (p != end) {
        njt_log_error(NJT_LOG_INFO, log, 0,
                      "quic trailing garbage in"
                      " transport parameters: bytes:%ui",
                      end - p);
        return NJT_ERROR;
    }

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, log, 0,
                   "quic transport parameters parsed ok");

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, log, 0,
                   "quic tp disable active migration: %ui",
                   tp->disable_active_migration);

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, log, 0, "quic tp idle_timeout:%ui",
                   tp->max_idle_timeout);

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, log, 0,
                   "quic tp max_udp_payload_size:%ui",
                   tp->max_udp_payload_size);

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, log, 0, "quic tp max_data:%ui",
                   tp->initial_max_data);

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, log, 0,
                   "quic tp max_stream_data_bidi_local:%ui",
                   tp->initial_max_stream_data_bidi_local);

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, log, 0,
                   "quic tp max_stream_data_bidi_remote:%ui",
                   tp->initial_max_stream_data_bidi_remote);

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, log, 0,
                   "quic tp max_stream_data_uni:%ui",
                   tp->initial_max_stream_data_uni);

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, log, 0,
                   "quic tp initial_max_streams_bidi:%ui",
                   tp->initial_max_streams_bidi);

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, log, 0,
                   "quic tp initial_max_streams_uni:%ui",
                   tp->initial_max_streams_uni);

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, log, 0,
                   "quic tp ack_delay_exponent:%ui",
                   tp->ack_delay_exponent);

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, log, 0, "quic tp max_ack_delay:%ui",
                   tp->max_ack_delay);

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, log, 0,
                   "quic tp active_connection_id_limit:%ui",
                   tp->active_connection_id_limit);

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, log, 0,
                   "quic tp initial source_connection_id len:%uz %xV",
                   tp->initial_scid.len, &tp->initial_scid);

    return NJT_OK;
}


static size_t
njt_quic_create_max_stream_data(u_char *p, njt_quic_max_stream_data_frame_t *ms)
{
    size_t   len;
    u_char  *start;

    if (p == NULL) {
        len = njt_quic_varint_len(NJT_QUIC_FT_MAX_STREAM_DATA);
        len += njt_quic_varint_len(ms->id);
        len += njt_quic_varint_len(ms->limit);
        return len;
    }

    start = p;

    njt_quic_build_int(&p, NJT_QUIC_FT_MAX_STREAM_DATA);
    njt_quic_build_int(&p, ms->id);
    njt_quic_build_int(&p, ms->limit);

    return p - start;
}


static size_t
njt_quic_create_max_data(u_char *p, njt_quic_max_data_frame_t *md)
{
    size_t   len;
    u_char  *start;

    if (p == NULL) {
        len = njt_quic_varint_len(NJT_QUIC_FT_MAX_DATA);
        len += njt_quic_varint_len(md->max_data);
        return len;
    }

    start = p;

    njt_quic_build_int(&p, NJT_QUIC_FT_MAX_DATA);
    njt_quic_build_int(&p, md->max_data);

    return p - start;
}


static size_t
njt_quic_create_path_challenge(u_char *p, njt_quic_path_challenge_frame_t *pc)
{
    size_t   len;
    u_char  *start;

    if (p == NULL) {
        len = njt_quic_varint_len(NJT_QUIC_FT_PATH_CHALLENGE);
        len += sizeof(pc->data);
        return len;
    }

    start = p;

    njt_quic_build_int(&p, NJT_QUIC_FT_PATH_CHALLENGE);
    p = njt_cpymem(p, &pc->data, sizeof(pc->data));

    return p - start;
}


static size_t
njt_quic_create_path_response(u_char *p, njt_quic_path_challenge_frame_t *pc)
{
    size_t   len;
    u_char  *start;

    if (p == NULL) {
        len = njt_quic_varint_len(NJT_QUIC_FT_PATH_RESPONSE);
        len += sizeof(pc->data);
        return len;
    }

    start = p;

    njt_quic_build_int(&p, NJT_QUIC_FT_PATH_RESPONSE);
    p = njt_cpymem(p, &pc->data, sizeof(pc->data));

    return p - start;
}


static size_t
njt_quic_create_new_connection_id(u_char *p, njt_quic_new_conn_id_frame_t *ncid)
{
    size_t   len;
    u_char  *start;

    if (p == NULL) {
        len = njt_quic_varint_len(NJT_QUIC_FT_NEW_CONNECTION_ID);
        len += njt_quic_varint_len(ncid->seqnum);
        len += njt_quic_varint_len(ncid->retire);
        len++;
        len += ncid->len;
        len += NJT_QUIC_SR_TOKEN_LEN;
        return len;
    }

    start = p;

    njt_quic_build_int(&p, NJT_QUIC_FT_NEW_CONNECTION_ID);
    njt_quic_build_int(&p, ncid->seqnum);
    njt_quic_build_int(&p, ncid->retire);
    *p++ = ncid->len;
    p = njt_cpymem(p, ncid->cid, ncid->len);
    p = njt_cpymem(p, ncid->srt, NJT_QUIC_SR_TOKEN_LEN);

    return p - start;
}


static size_t
njt_quic_create_retire_connection_id(u_char *p,
    njt_quic_retire_cid_frame_t *rcid)
{
    size_t   len;
    u_char  *start;

    if (p == NULL) {
        len = njt_quic_varint_len(NJT_QUIC_FT_RETIRE_CONNECTION_ID);
        len += njt_quic_varint_len(rcid->sequence_number);
        return len;
    }

    start = p;

    njt_quic_build_int(&p, NJT_QUIC_FT_RETIRE_CONNECTION_ID);
    njt_quic_build_int(&p, rcid->sequence_number);

    return p - start;
}


njt_int_t
njt_quic_init_transport_params(njt_quic_tp_t *tp, njt_quic_conf_t *qcf)
{
    njt_uint_t  nstreams;

    njt_memzero(tp, sizeof(njt_quic_tp_t));

    /*
     * set by njt_memzero():
     *
     *     tp->disable_active_migration = 0;
     *     tp->original_dcid = { 0, NULL };
     *     tp->initial_scid = { 0, NULL };
     *     tp->retry_scid = { 0, NULL };
     *     tp->sr_token = { 0 }
     *     tp->sr_enabled = 0
     *     tp->preferred_address = NULL
     */

    tp->max_idle_timeout = qcf->idle_timeout;

    tp->max_udp_payload_size = NJT_QUIC_MAX_UDP_PAYLOAD_SIZE;

    nstreams = qcf->max_concurrent_streams_bidi
               + qcf->max_concurrent_streams_uni;

    tp->initial_max_data = nstreams * qcf->stream_buffer_size;
    tp->initial_max_stream_data_bidi_local = qcf->stream_buffer_size;
    tp->initial_max_stream_data_bidi_remote = qcf->stream_buffer_size;
    tp->initial_max_stream_data_uni = qcf->stream_buffer_size;

    tp->initial_max_streams_bidi = qcf->max_concurrent_streams_bidi;
    tp->initial_max_streams_uni = qcf->max_concurrent_streams_uni;

    tp->max_ack_delay = NJT_QUIC_DEFAULT_MAX_ACK_DELAY;
    tp->ack_delay_exponent = NJT_QUIC_DEFAULT_ACK_DELAY_EXPONENT;

    tp->active_connection_id_limit = qcf->active_connection_id_limit;
    tp->disable_active_migration = qcf->disable_active_migration;

    return NJT_OK;
}


ssize_t
njt_quic_create_transport_params(u_char *pos, u_char *end, njt_quic_tp_t *tp,
    size_t *clen)
{
    u_char  *p;
    size_t   len;

#define njt_quic_tp_len(id, value)                                            \
    njt_quic_varint_len(id)                                                   \
    + njt_quic_varint_len(value)                                              \
    + njt_quic_varint_len(njt_quic_varint_len(value))

#define njt_quic_tp_vint(id, value)                                           \
    do {                                                                      \
        njt_quic_build_int(&p, id);                                           \
        njt_quic_build_int(&p, njt_quic_varint_len(value));                   \
        njt_quic_build_int(&p, value);                                        \
    } while (0)

#define njt_quic_tp_strlen(id, value)                                         \
    njt_quic_varint_len(id)                                                   \
    + njt_quic_varint_len(value.len)                                          \
    + value.len

#define njt_quic_tp_str(id, value)                                            \
    do {                                                                      \
        njt_quic_build_int(&p, id);                                           \
        njt_quic_build_int(&p, value.len);                                    \
        p = njt_cpymem(p, value.data, value.len);                             \
    } while (0)

    len = njt_quic_tp_len(NJT_QUIC_TP_INITIAL_MAX_DATA, tp->initial_max_data);

    len += njt_quic_tp_len(NJT_QUIC_TP_INITIAL_MAX_STREAMS_UNI,
                           tp->initial_max_streams_uni);

    len += njt_quic_tp_len(NJT_QUIC_TP_INITIAL_MAX_STREAMS_BIDI,
                           tp->initial_max_streams_bidi);

    len += njt_quic_tp_len(NJT_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                           tp->initial_max_stream_data_bidi_local);

    len += njt_quic_tp_len(NJT_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                           tp->initial_max_stream_data_bidi_remote);

    len += njt_quic_tp_len(NJT_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI,
                           tp->initial_max_stream_data_uni);

    len += njt_quic_tp_len(NJT_QUIC_TP_MAX_IDLE_TIMEOUT,
                           tp->max_idle_timeout);

    len += njt_quic_tp_len(NJT_QUIC_TP_MAX_UDP_PAYLOAD_SIZE,
                           tp->max_udp_payload_size);

    if (tp->disable_active_migration) {
        len += njt_quic_varint_len(NJT_QUIC_TP_DISABLE_ACTIVE_MIGRATION);
        len += njt_quic_varint_len(0);
    }

    len += njt_quic_tp_len(NJT_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT,
                           tp->active_connection_id_limit);

    /* transport parameters listed above will be saved in 0-RTT context */
    if (clen) {
        *clen = len;
    }

    len += njt_quic_tp_len(NJT_QUIC_TP_MAX_ACK_DELAY,
                           tp->max_ack_delay);

    len += njt_quic_tp_len(NJT_QUIC_TP_ACK_DELAY_EXPONENT,
                           tp->ack_delay_exponent);

    len += njt_quic_tp_strlen(NJT_QUIC_TP_ORIGINAL_DCID, tp->original_dcid);
    len += njt_quic_tp_strlen(NJT_QUIC_TP_INITIAL_SCID, tp->initial_scid);

    if (tp->retry_scid.len) {
        len += njt_quic_tp_strlen(NJT_QUIC_TP_RETRY_SCID, tp->retry_scid);
    }

    len += njt_quic_varint_len(NJT_QUIC_TP_SR_TOKEN);
    len += njt_quic_varint_len(NJT_QUIC_SR_TOKEN_LEN);
    len += NJT_QUIC_SR_TOKEN_LEN;

    if (pos == NULL) {
        return len;
    }

    p = pos;

    njt_quic_tp_vint(NJT_QUIC_TP_INITIAL_MAX_DATA,
                     tp->initial_max_data);

    njt_quic_tp_vint(NJT_QUIC_TP_INITIAL_MAX_STREAMS_UNI,
                     tp->initial_max_streams_uni);

    njt_quic_tp_vint(NJT_QUIC_TP_INITIAL_MAX_STREAMS_BIDI,
                     tp->initial_max_streams_bidi);

    njt_quic_tp_vint(NJT_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                     tp->initial_max_stream_data_bidi_local);

    njt_quic_tp_vint(NJT_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                     tp->initial_max_stream_data_bidi_remote);

    njt_quic_tp_vint(NJT_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI,
                     tp->initial_max_stream_data_uni);

    njt_quic_tp_vint(NJT_QUIC_TP_MAX_IDLE_TIMEOUT,
                     tp->max_idle_timeout);

    njt_quic_tp_vint(NJT_QUIC_TP_MAX_UDP_PAYLOAD_SIZE,
                     tp->max_udp_payload_size);

    if (tp->disable_active_migration) {
        njt_quic_build_int(&p, NJT_QUIC_TP_DISABLE_ACTIVE_MIGRATION);
        njt_quic_build_int(&p, 0);
    }

    njt_quic_tp_vint(NJT_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT,
                     tp->active_connection_id_limit);

    njt_quic_tp_vint(NJT_QUIC_TP_MAX_ACK_DELAY,
                     tp->max_ack_delay);

    njt_quic_tp_vint(NJT_QUIC_TP_ACK_DELAY_EXPONENT,
                     tp->ack_delay_exponent);

    njt_quic_tp_str(NJT_QUIC_TP_ORIGINAL_DCID, tp->original_dcid);
    njt_quic_tp_str(NJT_QUIC_TP_INITIAL_SCID, tp->initial_scid);

    if (tp->retry_scid.len) {
        njt_quic_tp_str(NJT_QUIC_TP_RETRY_SCID, tp->retry_scid);
    }

    njt_quic_build_int(&p, NJT_QUIC_TP_SR_TOKEN);
    njt_quic_build_int(&p, NJT_QUIC_SR_TOKEN_LEN);
    p = njt_cpymem(p, tp->sr_token, NJT_QUIC_SR_TOKEN_LEN);

    return p - pos;
}


static size_t
njt_quic_create_close(u_char *p, njt_quic_frame_t *f)
{
    size_t                   len;
    u_char                  *start;
    njt_quic_close_frame_t  *cl;

    cl = &f->u.close;

    if (p == NULL) {
        len = njt_quic_varint_len(f->type);
        len += njt_quic_varint_len(cl->error_code);

        if (f->type != NJT_QUIC_FT_CONNECTION_CLOSE_APP) {
            len += njt_quic_varint_len(cl->frame_type);
        }

        len += njt_quic_varint_len(cl->reason.len);
        len += cl->reason.len;

        return len;
    }

    start = p;

    njt_quic_build_int(&p, f->type);
    njt_quic_build_int(&p, cl->error_code);

    if (f->type != NJT_QUIC_FT_CONNECTION_CLOSE_APP) {
        njt_quic_build_int(&p, cl->frame_type);
    }

    njt_quic_build_int(&p, cl->reason.len);
    p = njt_cpymem(p, cl->reason.data, cl->reason.len);

    return p - start;
}


void
njt_quic_dcid_encode_key(u_char *dcid, uint64_t key)
{
    (void) njt_quic_write_uint64(dcid, key);
}
