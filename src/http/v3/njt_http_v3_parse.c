
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


#define njt_http_v3_is_v2_frame(type)                                         \
    ((type) == 0x02 || (type) == 0x06 || (type) == 0x08 || (type) == 0x09)


static void njt_http_v3_parse_start_local(njt_buf_t *b, njt_buf_t *loc,
    njt_uint_t n);
static void njt_http_v3_parse_end_local(njt_buf_t *b, njt_buf_t *loc,
    njt_uint_t *n);
static njt_int_t njt_http_v3_parse_skip(njt_buf_t *b, njt_uint_t *length);

static njt_int_t njt_http_v3_parse_varlen_int(njt_connection_t *c,
    njt_http_v3_parse_varlen_int_t *st, njt_buf_t *b);
static njt_int_t njt_http_v3_parse_prefix_int(njt_connection_t *c,
    njt_http_v3_parse_prefix_int_t *st, njt_uint_t prefix, njt_buf_t *b);

static njt_int_t njt_http_v3_parse_field_section_prefix(njt_connection_t *c,
    njt_http_v3_parse_field_section_prefix_t *st, njt_buf_t *b);
static njt_int_t njt_http_v3_parse_field_rep(njt_connection_t *c,
    njt_http_v3_parse_field_rep_t *st, njt_uint_t base, njt_buf_t *b);
static njt_int_t njt_http_v3_parse_literal(njt_connection_t *c,
    njt_http_v3_parse_literal_t *st, njt_buf_t *b);
static njt_int_t njt_http_v3_parse_field_ri(njt_connection_t *c,
    njt_http_v3_parse_field_t *st, njt_buf_t *b);
static njt_int_t njt_http_v3_parse_field_lri(njt_connection_t *c,
    njt_http_v3_parse_field_t *st, njt_buf_t *b);
static njt_int_t njt_http_v3_parse_field_l(njt_connection_t *c,
    njt_http_v3_parse_field_t *st, njt_buf_t *b);
static njt_int_t njt_http_v3_parse_field_pbi(njt_connection_t *c,
    njt_http_v3_parse_field_t *st, njt_buf_t *b);
static njt_int_t njt_http_v3_parse_field_lpbi(njt_connection_t *c,
    njt_http_v3_parse_field_t *st, njt_buf_t *b);

static njt_int_t njt_http_v3_parse_control(njt_connection_t *c,
    njt_http_v3_parse_control_t *st, njt_buf_t *b);
static njt_int_t njt_http_v3_parse_settings(njt_connection_t *c,
    njt_http_v3_parse_settings_t *st, njt_buf_t *b);

static njt_int_t njt_http_v3_parse_encoder(njt_connection_t *c,
    njt_http_v3_parse_encoder_t *st, njt_buf_t *b);
static njt_int_t njt_http_v3_parse_field_inr(njt_connection_t *c,
    njt_http_v3_parse_field_t *st, njt_buf_t *b);
static njt_int_t njt_http_v3_parse_field_iln(njt_connection_t *c,
    njt_http_v3_parse_field_t *st, njt_buf_t *b);

static njt_int_t njt_http_v3_parse_decoder(njt_connection_t *c,
    njt_http_v3_parse_decoder_t *st, njt_buf_t *b);

static njt_int_t njt_http_v3_parse_lookup(njt_connection_t *c,
    njt_uint_t dynamic, njt_uint_t index, njt_str_t *name, njt_str_t *value);


static void
njt_http_v3_parse_start_local(njt_buf_t *b, njt_buf_t *loc, njt_uint_t n)
{
    *loc = *b;

    if ((size_t) (loc->last - loc->pos) > n) {
        loc->last = loc->pos + n;
    }
}


static void
njt_http_v3_parse_end_local(njt_buf_t *b, njt_buf_t *loc, njt_uint_t *pn)
{
    *pn -= loc->pos - b->pos;
    b->pos = loc->pos;
}


static njt_int_t
njt_http_v3_parse_skip(njt_buf_t *b, njt_uint_t *length)
{
    if ((size_t) (b->last - b->pos) < *length) {
        *length -= b->last - b->pos;
        b->pos = b->last;
        return NJT_AGAIN;
    }

    b->pos += *length;
    return NJT_DONE;
}


static njt_int_t
njt_http_v3_parse_varlen_int(njt_connection_t *c,
    njt_http_v3_parse_varlen_int_t *st, njt_buf_t *b)
{
    u_char  ch;
    enum {
        sw_start = 0,
        sw_length_2,
        sw_length_3,
        sw_length_4,
        sw_length_5,
        sw_length_6,
        sw_length_7,
        sw_length_8
    };

    for ( ;; ) {

        if (b->pos == b->last) {
            return NJT_AGAIN;
        }

        ch = *b->pos++;

        switch (st->state) {

        case sw_start:

            st->value = ch;
            if (st->value & 0xc0) {
                st->state = sw_length_2;
                break;
            }

            goto done;

        case sw_length_2:

            st->value = (st->value << 8) + ch;
            if ((st->value & 0xc000) == 0x4000) {
                st->value &= 0x3fff;
                goto done;
            }

            st->state = sw_length_3;
            break;

        case sw_length_4:

            st->value = (st->value << 8) + ch;
            if ((st->value & 0xc0000000) == 0x80000000) {
                st->value &= 0x3fffffff;
                goto done;
            }

            st->state = sw_length_5;
            break;

        case sw_length_3:
        case sw_length_5:
        case sw_length_6:
        case sw_length_7:

            st->value = (st->value << 8) + ch;
            st->state++;
            break;

        case sw_length_8:

            st->value = (st->value << 8) + ch;
            st->value &= 0x3fffffffffffffff;
            goto done;
        }
    }

done:

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse varlen int %uL", st->value);

    st->state = sw_start;
    return NJT_DONE;
}


static njt_int_t
njt_http_v3_parse_prefix_int(njt_connection_t *c,
    njt_http_v3_parse_prefix_int_t *st, njt_uint_t prefix, njt_buf_t *b)
{
    u_char      ch;
    njt_uint_t  mask;
    enum {
        sw_start = 0,
        sw_value
    };

    for ( ;; ) {

        if (b->pos == b->last) {
            return NJT_AGAIN;
        }

        ch = *b->pos++;

        switch (st->state) {

        case sw_start:

            mask = (1 << prefix) - 1;
            st->value = ch & mask;

            if (st->value != mask) {
                goto done;
            }

            st->shift = 0;
            st->state = sw_value;
            break;

        case sw_value:

            st->value += (uint64_t) (ch & 0x7f) << st->shift;

            if (st->shift == 56
                && ((ch & 0x80) || (st->value & 0xc000000000000000)))
            {
                njt_log_error(NJT_LOG_INFO, c->log, 0,
                              "client exceeded integer size limit");
                return NJT_HTTP_V3_ERR_EXCESSIVE_LOAD;
            }

            if (ch & 0x80) {
                st->shift += 7;
                break;
            }

            goto done;
        }
    }

done:

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse prefix int %uL", st->value);

    st->state = sw_start;
    return NJT_DONE;
}


njt_int_t
njt_http_v3_parse_headers(njt_connection_t *c, njt_http_v3_parse_headers_t *st,
    njt_buf_t *b)
{
    njt_buf_t  loc;
    njt_int_t  rc;
    enum {
        sw_start = 0,
        sw_type,
        sw_length,
        sw_skip,
        sw_prefix,
        sw_verify,
        sw_field_rep,
        sw_done
    };

    for ( ;; ) {

        switch (st->state) {

        case sw_start:

            njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                           "http3 parse headers");

            st->state = sw_type;

            /* fall through */

        case sw_type:

            rc = njt_http_v3_parse_varlen_int(c, &st->vlint, b);
            if (rc != NJT_DONE) {
                return rc;
            }

            st->type = st->vlint.value;

            if (njt_http_v3_is_v2_frame(st->type)
                || st->type == NJT_HTTP_V3_FRAME_DATA
                || st->type == NJT_HTTP_V3_FRAME_GOAWAY
                || st->type == NJT_HTTP_V3_FRAME_SETTINGS
                || st->type == NJT_HTTP_V3_FRAME_MAX_PUSH_ID
                || st->type == NJT_HTTP_V3_FRAME_CANCEL_PUSH
                || st->type == NJT_HTTP_V3_FRAME_PUSH_PROMISE)
            {
                return NJT_HTTP_V3_ERR_FRAME_UNEXPECTED;
            }

            st->state = sw_length;
            break;

        case sw_length:

            rc = njt_http_v3_parse_varlen_int(c, &st->vlint, b);
            if (rc != NJT_DONE) {
                return rc;
            }

            st->length = st->vlint.value;

            njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                           "http3 parse headers type:%ui, len:%ui",
                           st->type, st->length);

            if (st->type != NJT_HTTP_V3_FRAME_HEADERS) {
                st->state = st->length > 0 ? sw_skip : sw_type;
                break;
            }

            if (st->length == 0) {
                return NJT_HTTP_V3_ERR_FRAME_ERROR;
            }

            st->state = sw_prefix;
            break;

        case sw_skip:

            rc = njt_http_v3_parse_skip(b, &st->length);
            if (rc != NJT_DONE) {
                return rc;
            }

            st->state = sw_type;
            break;

        case sw_prefix:

            njt_http_v3_parse_start_local(b, &loc, st->length);

            rc = njt_http_v3_parse_field_section_prefix(c, &st->prefix, &loc);

            njt_http_v3_parse_end_local(b, &loc, &st->length);

            if (st->length == 0 && rc == NJT_AGAIN) {
                return NJT_HTTP_V3_ERR_FRAME_ERROR;
            }

            if (rc != NJT_DONE) {
                return rc;
            }

            st->state = sw_verify;
            break;

        case sw_verify:

            rc = njt_http_v3_check_insert_count(c, st->prefix.insert_count);
            if (rc != NJT_OK) {
                return rc;
            }

            st->state = sw_field_rep;

            /* fall through */

        case sw_field_rep:

            njt_http_v3_parse_start_local(b, &loc, st->length);

            rc = njt_http_v3_parse_field_rep(c, &st->field_rep, st->prefix.base,
                                             &loc);

            njt_http_v3_parse_end_local(b, &loc, &st->length);

            if (st->length == 0 && rc == NJT_AGAIN) {
                return NJT_HTTP_V3_ERR_FRAME_ERROR;
            }

            if (rc != NJT_DONE) {
                return rc;
            }

            if (st->length == 0) {
                goto done;
            }

            return NJT_OK;
        }
    }

done:

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0, "http3 parse headers done");

    if (st->prefix.insert_count > 0) {
        if (njt_http_v3_send_ack_section(c, c->quic->id) != NJT_OK) {
            return NJT_ERROR;
        }

        njt_http_v3_ack_insert_count(c, st->prefix.insert_count);
    }

    st->state = sw_start;
    return NJT_DONE;
}


static njt_int_t
njt_http_v3_parse_field_section_prefix(njt_connection_t *c,
    njt_http_v3_parse_field_section_prefix_t *st, njt_buf_t *b)
{
    u_char     ch;
    njt_int_t  rc;
    enum {
        sw_start = 0,
        sw_req_insert_count,
        sw_delta_base,
        sw_read_delta_base
    };

    for ( ;; ) {

        switch (st->state) {

        case sw_start:

            njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                           "http3 parse field section prefix");

            st->state = sw_req_insert_count;

            /* fall through */

        case sw_req_insert_count:

            rc = njt_http_v3_parse_prefix_int(c, &st->pint, 8, b);
            if (rc != NJT_DONE) {
                return rc;
            }

            st->insert_count = st->pint.value;
            st->state = sw_delta_base;
            break;

        case sw_delta_base:

            if (b->pos == b->last) {
                return NJT_AGAIN;
            }

            ch = *b->pos;

            st->sign = (ch & 0x80) ? 1 : 0;
            st->state = sw_read_delta_base;

            /* fall through */

        case sw_read_delta_base:

            rc = njt_http_v3_parse_prefix_int(c, &st->pint, 7, b);
            if (rc != NJT_DONE) {
                return rc;
            }

            st->delta_base = st->pint.value;
            goto done;
        }
    }

done:

    rc = njt_http_v3_decode_insert_count(c, &st->insert_count);
    if (rc != NJT_OK) {
        return rc;
    }

    if (st->sign) {
        if (st->insert_count <= st->delta_base) {
            njt_log_error(NJT_LOG_INFO, c->log, 0, "client sent negative base");
            return NJT_HTTP_V3_ERR_DECOMPRESSION_FAILED;
        }

        st->base = st->insert_count - st->delta_base - 1;

    } else {
        st->base = st->insert_count + st->delta_base;
    }

    njt_log_debug4(NJT_LOG_DEBUG_HTTP, c->log, 0,
                  "http3 parse field section prefix done "
                  "insert_count:%ui, sign:%ui, delta_base:%ui, base:%ui",
                  st->insert_count, st->sign, st->delta_base, st->base);

    st->state = sw_start;
    return NJT_DONE;
}


static njt_int_t
njt_http_v3_parse_field_rep(njt_connection_t *c,
    njt_http_v3_parse_field_rep_t *st, njt_uint_t base, njt_buf_t *b)
{
    u_char     ch;
    njt_int_t  rc;
    enum {
        sw_start = 0,
        sw_field_ri,
        sw_field_lri,
        sw_field_l,
        sw_field_pbi,
        sw_field_lpbi
    };

    if (st->state == sw_start) {

        njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 parse field representation");

        if (b->pos == b->last) {
            return NJT_AGAIN;
        }

        ch = *b->pos;

        njt_memzero(&st->field, sizeof(njt_http_v3_parse_field_t));

        st->field.base = base;

        if (ch & 0x80) {
            /* Indexed Field Line */

            st->state = sw_field_ri;

        } else if (ch & 0x40) {
            /* Literal Field Line With Name Reference */

            st->state = sw_field_lri;

        } else if (ch & 0x20) {
            /* Literal Field Line With Literal Name */

            st->state = sw_field_l;

        } else if (ch & 0x10) {
            /* Indexed Field Line With Post-Base Index */

            st->state = sw_field_pbi;

        } else {
            /* Literal Field Line With Post-Base Name Reference */

            st->state = sw_field_lpbi;
        }
    }

    switch (st->state) {

    case sw_field_ri:
        rc = njt_http_v3_parse_field_ri(c, &st->field, b);
        break;

    case sw_field_lri:
        rc = njt_http_v3_parse_field_lri(c, &st->field, b);
        break;

    case sw_field_l:
        rc = njt_http_v3_parse_field_l(c, &st->field, b);
        break;

    case sw_field_pbi:
        rc = njt_http_v3_parse_field_pbi(c, &st->field, b);
        break;

    case sw_field_lpbi:
        rc = njt_http_v3_parse_field_lpbi(c, &st->field, b);
        break;

    default:
        rc = NJT_OK;
    }

    if (rc != NJT_DONE) {
        return rc;
    }

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse field representation done");

    st->state = sw_start;
    return NJT_DONE;
}


static njt_int_t
njt_http_v3_parse_literal(njt_connection_t *c, njt_http_v3_parse_literal_t *st,
    njt_buf_t *b)
{
    u_char                     ch;
    njt_uint_t                 n;
    njt_http_core_srv_conf_t  *cscf;
    enum {
        sw_start = 0,
        sw_value
    };

    for ( ;; ) {

        switch (st->state) {

        case sw_start:

            njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                           "http3 parse literal huff:%ui, len:%ui",
                           st->huffman, st->length);

            n = st->length;

            cscf = njt_http_v3_get_module_srv_conf(c, njt_http_core_module);

            if (n > cscf->large_client_header_buffers.size) {
                njt_log_error(NJT_LOG_INFO, c->log, 0,
                              "client sent too large field line");
                return NJT_HTTP_V3_ERR_EXCESSIVE_LOAD;
            }

            if (st->huffman) {
                n = n * 8 / 5;
                st->huffstate = 0;
            }

            st->last = njt_pnalloc(c->pool, n + 1);
            if (st->last == NULL) {
                return NJT_ERROR;
            }

            st->value.data = st->last;
            st->state = sw_value;

            /* fall through */

        case sw_value:

            if (b->pos == b->last) {
                return NJT_AGAIN;
            }

            ch = *b->pos++;

            if (st->huffman) {
                if (njt_http_huff_decode(&st->huffstate, &ch, 1, &st->last,
                                         st->length == 1, c->log)
                    != NJT_OK)
                {
                    njt_log_error(NJT_LOG_INFO, c->log, 0,
                                  "client sent invalid encoded field line");
                    return NJT_ERROR;
                }

            } else {
                *st->last++ = ch;
            }

            if (--st->length) {
                break;
            }

            st->value.len = st->last - st->value.data;
            *st->last = '\0';
            goto done;
        }
    }

done:

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse literal done \"%V\"", &st->value);

    st->state = sw_start;
    return NJT_DONE;
}


static njt_int_t
njt_http_v3_parse_field_ri(njt_connection_t *c, njt_http_v3_parse_field_t *st,
    njt_buf_t *b)
{
    u_char     ch;
    njt_int_t  rc;
    enum {
        sw_start = 0,
        sw_index
    };

    for ( ;; ) {

        switch (st->state) {

        case sw_start:

            njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                           "http3 parse field ri");

            if (b->pos == b->last) {
                return NJT_AGAIN;
            }

            ch = *b->pos;

            st->dynamic = (ch & 0x40) ? 0 : 1;
            st->state = sw_index;

            /* fall through */

        case sw_index:

            rc = njt_http_v3_parse_prefix_int(c, &st->pint, 6, b);
            if (rc != NJT_DONE) {
                return rc;
            }

            st->index = st->pint.value;
            goto done;
        }
    }

done:

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse field ri done %s%ui]",
                   st->dynamic ? "dynamic[-" : "static[", st->index);

    if (st->dynamic) {
        st->index = st->base - st->index - 1;
    }

    rc = njt_http_v3_parse_lookup(c, st->dynamic, st->index, &st->name,
                                  &st->value);
    if (rc != NJT_OK) {
        return rc;
    }

    st->state = sw_start;
    return NJT_DONE;
}


static njt_int_t
njt_http_v3_parse_field_lri(njt_connection_t *c,
    njt_http_v3_parse_field_t *st, njt_buf_t *b)
{
    u_char     ch;
    njt_int_t  rc;
    enum {
        sw_start = 0,
        sw_index,
        sw_value_len,
        sw_read_value_len,
        sw_value
    };

    for ( ;; ) {

        switch (st->state) {

        case sw_start:

            njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                           "http3 parse field lri");

            if (b->pos == b->last) {
                return NJT_AGAIN;
            }

            ch = *b->pos;

            st->dynamic = (ch & 0x10) ? 0 : 1;
            st->state = sw_index;

            /* fall through */

        case sw_index:

            rc = njt_http_v3_parse_prefix_int(c, &st->pint, 4, b);
            if (rc != NJT_DONE) {
                return rc;
            }

            st->index = st->pint.value;
            st->state = sw_value_len;
            break;

        case sw_value_len:

            if (b->pos == b->last) {
                return NJT_AGAIN;
            }

            ch = *b->pos;

            st->literal.huffman = (ch & 0x80) ? 1 : 0;
            st->state = sw_read_value_len;

            /* fall through */

        case sw_read_value_len:

            rc = njt_http_v3_parse_prefix_int(c, &st->pint, 7, b);
            if (rc != NJT_DONE) {
                return rc;
            }

            st->literal.length = st->pint.value;
            if (st->literal.length == 0) {
                goto done;
            }

            st->state = sw_value;
            break;

        case sw_value:

            rc = njt_http_v3_parse_literal(c, &st->literal, b);
            if (rc != NJT_DONE) {
                return rc;
            }

            st->value = st->literal.value;
            goto done;
        }
    }

done:

    njt_log_debug3(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse field lri done %s%ui] \"%V\"",
                   st->dynamic ? "dynamic[-" : "static[",
                   st->index, &st->value);

    if (st->dynamic) {
        st->index = st->base - st->index - 1;
    }

    rc = njt_http_v3_parse_lookup(c, st->dynamic, st->index, &st->name, NULL);
    if (rc != NJT_OK) {
        return rc;
    }

    st->state = sw_start;
    return NJT_DONE;
}


static njt_int_t
njt_http_v3_parse_field_l(njt_connection_t *c,
    njt_http_v3_parse_field_t *st, njt_buf_t *b)
{
    u_char     ch;
    njt_int_t  rc;
    enum {
        sw_start = 0,
        sw_name_len,
        sw_name,
        sw_value_len,
        sw_read_value_len,
        sw_value
    };

    for ( ;; ) {

        switch (st->state) {

        case sw_start:

            njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                           "http3 parse field l");

            if (b->pos == b->last) {
                return NJT_AGAIN;
            }

            ch = *b->pos;

            st->literal.huffman = (ch & 0x08) ? 1 : 0;
            st->state = sw_name_len;

            /* fall through */

        case sw_name_len:

            rc = njt_http_v3_parse_prefix_int(c, &st->pint, 3, b);
            if (rc != NJT_DONE) {
                return rc;
            }

            st->literal.length = st->pint.value;
            if (st->literal.length == 0) {
                return NJT_ERROR;
            }

            st->state = sw_name;
            break;

        case sw_name:

            rc = njt_http_v3_parse_literal(c, &st->literal, b);
            if (rc != NJT_DONE) {
                return rc;
            }

            st->name = st->literal.value;
            st->state = sw_value_len;
            break;

        case sw_value_len:

            if (b->pos == b->last) {
                return NJT_AGAIN;
            }

            ch = *b->pos;

            st->literal.huffman = (ch & 0x80) ? 1 : 0;
            st->state = sw_read_value_len;

            /* fall through */

        case sw_read_value_len:

            rc = njt_http_v3_parse_prefix_int(c, &st->pint, 7, b);
            if (rc != NJT_DONE) {
                return rc;
            }

            st->literal.length = st->pint.value;
            if (st->literal.length == 0) {
                goto done;
            }

            st->state = sw_value;
            break;

        case sw_value:

            rc = njt_http_v3_parse_literal(c, &st->literal, b);
            if (rc != NJT_DONE) {
                return rc;
            }

            st->value = st->literal.value;
            goto done;
        }
    }

done:

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse field l done \"%V\" \"%V\"",
                   &st->name, &st->value);

    st->state = sw_start;
    return NJT_DONE;
}


static njt_int_t
njt_http_v3_parse_field_pbi(njt_connection_t *c,
    njt_http_v3_parse_field_t *st, njt_buf_t *b)
{
    njt_int_t  rc;
    enum {
        sw_start = 0,
        sw_index
    };

    for ( ;; ) {

        switch (st->state) {

        case sw_start:

            njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                           "http3 parse field pbi");

            st->state = sw_index;

            /* fall through */

        case sw_index:

            rc = njt_http_v3_parse_prefix_int(c, &st->pint, 4, b);
            if (rc != NJT_DONE) {
                return rc;
            }

            st->index = st->pint.value;
            goto done;
        }
    }

done:

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse field pbi done dynamic[+%ui]", st->index);

    rc = njt_http_v3_parse_lookup(c, 1, st->base + st->index, &st->name,
                                  &st->value);
    if (rc != NJT_OK) {
        return rc;
    }

    st->state = sw_start;
    return NJT_DONE;
}


static njt_int_t
njt_http_v3_parse_field_lpbi(njt_connection_t *c,
    njt_http_v3_parse_field_t *st, njt_buf_t *b)
{
    u_char     ch;
    njt_int_t  rc;
    enum {
        sw_start = 0,
        sw_index,
        sw_value_len,
        sw_read_value_len,
        sw_value
    };

    for ( ;; ) {

        switch (st->state) {

        case sw_start:

            njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                           "http3 parse field lpbi");

            st->state = sw_index;

            /* fall through */

        case sw_index:

            rc = njt_http_v3_parse_prefix_int(c, &st->pint, 3, b);
            if (rc != NJT_DONE) {
                return rc;
            }

            st->index = st->pint.value;
            st->state = sw_value_len;
            break;

        case sw_value_len:

            if (b->pos == b->last) {
                return NJT_AGAIN;
            }

            ch = *b->pos;

            st->literal.huffman = (ch & 0x80) ? 1 : 0;
            st->state = sw_read_value_len;

            /* fall through */

        case sw_read_value_len:

            rc = njt_http_v3_parse_prefix_int(c, &st->pint, 7, b);
            if (rc != NJT_DONE) {
                return rc;
            }

            st->literal.length = st->pint.value;
            if (st->literal.length == 0) {
                goto done;
            }

            st->state = sw_value;
            break;

        case sw_value:

            rc = njt_http_v3_parse_literal(c, &st->literal, b);
            if (rc != NJT_DONE) {
                return rc;
            }

            st->value = st->literal.value;
            goto done;
        }
    }

done:

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse field lpbi done dynamic[+%ui] \"%V\"",
                   st->index, &st->value);

    rc = njt_http_v3_parse_lookup(c, 1, st->base + st->index, &st->name, NULL);
    if (rc != NJT_OK) {
        return rc;
    }

    st->state = sw_start;
    return NJT_DONE;
}


static njt_int_t
njt_http_v3_parse_lookup(njt_connection_t *c, njt_uint_t dynamic,
    njt_uint_t index, njt_str_t *name, njt_str_t *value)
{
    u_char  *p;

    if (!dynamic) {
        if (njt_http_v3_lookup_static(c, index, name, value) != NJT_OK) {
            return NJT_HTTP_V3_ERR_DECOMPRESSION_FAILED;
        }

        return NJT_OK;
    }

    if (njt_http_v3_lookup(c, index, name, value) != NJT_OK) {
        return NJT_HTTP_V3_ERR_DECOMPRESSION_FAILED;
    }

    if (name) {
        p = njt_pnalloc(c->pool, name->len + 1);
        if (p == NULL) {
            return NJT_ERROR;
        }

        njt_memcpy(p, name->data, name->len);
        p[name->len] = '\0';
        name->data = p;
    }

    if (value) {
        p = njt_pnalloc(c->pool, value->len + 1);
        if (p == NULL) {
            return NJT_ERROR;
        }

        njt_memcpy(p, value->data, value->len);
        p[value->len] = '\0';
        value->data = p;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_v3_parse_control(njt_connection_t *c, njt_http_v3_parse_control_t *st,
    njt_buf_t *b)
{
    njt_buf_t  loc;
    njt_int_t  rc;
    enum {
        sw_start = 0,
        sw_first_type,
        sw_type,
        sw_length,
        sw_settings,
        sw_skip
    };

    for ( ;; ) {

        switch (st->state) {

        case sw_start:

            njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                           "http3 parse control");

            st->state = sw_first_type;

            /* fall through */

        case sw_first_type:
        case sw_type:

            rc = njt_http_v3_parse_varlen_int(c, &st->vlint, b);
            if (rc != NJT_DONE) {
                return rc;
            }

            st->type = st->vlint.value;

            njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                           "http3 parse frame type:%ui", st->type);

            if (st->state == sw_first_type
                && st->type != NJT_HTTP_V3_FRAME_SETTINGS)
            {
                return NJT_HTTP_V3_ERR_MISSING_SETTINGS;
            }

            if (st->state != sw_first_type
                && st->type == NJT_HTTP_V3_FRAME_SETTINGS)
            {
                return NJT_HTTP_V3_ERR_FRAME_UNEXPECTED;
            }

            if (njt_http_v3_is_v2_frame(st->type)
                || st->type == NJT_HTTP_V3_FRAME_DATA
                || st->type == NJT_HTTP_V3_FRAME_HEADERS
                || st->type == NJT_HTTP_V3_FRAME_PUSH_PROMISE)
            {
                return NJT_HTTP_V3_ERR_FRAME_UNEXPECTED;
            }

            if (st->type == NJT_HTTP_V3_FRAME_CANCEL_PUSH) {
                return NJT_HTTP_V3_ERR_ID_ERROR;
            }

            st->state = sw_length;
            break;

        case sw_length:

            rc = njt_http_v3_parse_varlen_int(c, &st->vlint, b);
            if (rc != NJT_DONE) {
                return rc;
            }

            njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                           "http3 parse frame len:%uL", st->vlint.value);

            st->length = st->vlint.value;
            if (st->length == 0) {
                st->state = sw_type;
                break;
            }

            switch (st->type) {

            case NJT_HTTP_V3_FRAME_SETTINGS:
                st->state = sw_settings;
                break;

            default:
                njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                               "http3 parse skip unknown frame");
                st->state = sw_skip;
            }

            break;

        case sw_settings:

            njt_http_v3_parse_start_local(b, &loc, st->length);

            rc = njt_http_v3_parse_settings(c, &st->settings, &loc);

            njt_http_v3_parse_end_local(b, &loc, &st->length);

            if (st->length == 0 && rc == NJT_AGAIN) {
                return NJT_HTTP_V3_ERR_SETTINGS_ERROR;
            }

            if (rc != NJT_DONE) {
                return rc;
            }

            if (st->length == 0) {
                st->state = sw_type;
            }

            break;

        case sw_skip:

            rc = njt_http_v3_parse_skip(b, &st->length);
            if (rc != NJT_DONE) {
                return rc;
            }

            st->state = sw_type;
            break;
        }
    }
}


static njt_int_t
njt_http_v3_parse_settings(njt_connection_t *c,
    njt_http_v3_parse_settings_t *st, njt_buf_t *b)
{
    njt_int_t  rc;
    enum {
        sw_start = 0,
        sw_id,
        sw_value
    };

    for ( ;; ) {

        switch (st->state) {

        case sw_start:

            njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                           "http3 parse settings");

            st->state = sw_id;

            /* fall through */

        case sw_id:

            rc = njt_http_v3_parse_varlen_int(c, &st->vlint, b);
            if (rc != NJT_DONE) {
                return rc;
            }

            st->id = st->vlint.value;
            st->state = sw_value;
            break;

        case sw_value:

            rc = njt_http_v3_parse_varlen_int(c, &st->vlint, b);
            if (rc != NJT_DONE) {
                return rc;
            }

            if (njt_http_v3_set_param(c, st->id, st->vlint.value) != NJT_OK) {
                return NJT_HTTP_V3_ERR_SETTINGS_ERROR;
            }

            goto done;
        }
    }

done:

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0, "http3 parse settings done");

    st->state = sw_start;
    return NJT_DONE;
}


static njt_int_t
njt_http_v3_parse_encoder(njt_connection_t *c, njt_http_v3_parse_encoder_t *st,
    njt_buf_t *b)
{
    u_char     ch;
    njt_int_t  rc;
    enum {
        sw_start = 0,
        sw_inr,
        sw_iln,
        sw_capacity,
        sw_duplicate
    };

    for ( ;; ) {

        if (st->state == sw_start) {

            njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                           "http3 parse encoder instruction");

            if (b->pos == b->last) {
                return NJT_AGAIN;
            }

            ch = *b->pos;

            if (ch & 0x80) {
                /* Insert With Name Reference */

                st->state = sw_inr;

            } else if (ch & 0x40) {
                /* Insert With Literal Name */

                st->state = sw_iln;

            } else if (ch & 0x20) {
                /* Set Dynamic Table Capacity */

                st->state = sw_capacity;

            } else {
                /* Duplicate */

                st->state = sw_duplicate;
            }
        }

        switch (st->state) {

        case sw_inr:

            rc = njt_http_v3_parse_field_inr(c, &st->field, b);
            if (rc != NJT_DONE) {
                return rc;
            }

            st->state = sw_start;
            break;

        case sw_iln:

            rc = njt_http_v3_parse_field_iln(c, &st->field, b);
            if (rc != NJT_DONE) {
                return rc;
            }

            st->state = sw_start;
            break;

        case sw_capacity:

            rc = njt_http_v3_parse_prefix_int(c, &st->pint, 5, b);
            if (rc != NJT_DONE) {
                return rc;
            }

            rc = njt_http_v3_set_capacity(c, st->pint.value);
            if (rc != NJT_OK) {
                return rc;
            }

            st->state = sw_start;
            break;

        default: /* sw_duplicate */

            rc = njt_http_v3_parse_prefix_int(c, &st->pint, 5, b);
            if (rc != NJT_DONE) {
                return rc;
            }

            rc = njt_http_v3_duplicate(c, st->pint.value);
            if (rc != NJT_OK) {
                return rc;
            }

            st->state = sw_start;
            break;
        }
    }
}


static njt_int_t
njt_http_v3_parse_field_inr(njt_connection_t *c,
    njt_http_v3_parse_field_t *st, njt_buf_t *b)
{
    u_char     ch;
    njt_int_t  rc;
    enum {
        sw_start = 0,
        sw_name_index,
        sw_value_len,
        sw_read_value_len,
        sw_value
    };

    for ( ;; ) {

        switch (st->state) {

        case sw_start:

            njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                           "http3 parse field inr");

            if (b->pos == b->last) {
                return NJT_AGAIN;
            }

            ch = *b->pos;

            st->dynamic = (ch & 0x40) ? 0 : 1;
            st->state = sw_name_index;

            /* fall through */

        case sw_name_index:

            rc = njt_http_v3_parse_prefix_int(c, &st->pint, 6, b);
            if (rc != NJT_DONE) {
                return rc;
            }

            st->index = st->pint.value;
            st->state = sw_value_len;
            break;

        case sw_value_len:

            if (b->pos == b->last) {
                return NJT_AGAIN;
            }

            ch = *b->pos;

            st->literal.huffman = (ch & 0x80) ? 1 : 0;
            st->state = sw_read_value_len;

            /* fall through */

        case sw_read_value_len:

            rc = njt_http_v3_parse_prefix_int(c, &st->pint, 7, b);
            if (rc != NJT_DONE) {
                return rc;
            }

            st->literal.length = st->pint.value;
            if (st->literal.length == 0) {
                st->value.len = 0;
                goto done;
            }

            st->state = sw_value;
            break;

        case sw_value:

            rc = njt_http_v3_parse_literal(c, &st->literal, b);
            if (rc != NJT_DONE) {
                return rc;
            }

            st->value = st->literal.value;
            goto done;
        }
    }

done:

    njt_log_debug3(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse field inr done %s[%ui] \"%V\"",
                   st->dynamic ? "dynamic" : "static",
                   st->index, &st->value);

    rc = njt_http_v3_ref_insert(c, st->dynamic, st->index, &st->value);
    if (rc != NJT_OK) {
        return rc;
    }

    st->state = sw_start;
    return NJT_DONE;
}


static njt_int_t
njt_http_v3_parse_field_iln(njt_connection_t *c,
    njt_http_v3_parse_field_t *st, njt_buf_t *b)
{
    u_char     ch;
    njt_int_t  rc;
    enum {
        sw_start = 0,
        sw_name_len,
        sw_name,
        sw_value_len,
        sw_read_value_len,
        sw_value
    };

    for ( ;; ) {

        switch (st->state) {

        case sw_start:

            njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                           "http3 parse field iln");

            if (b->pos == b->last) {
                return NJT_AGAIN;
            }

            ch = *b->pos;

            st->literal.huffman = (ch & 0x20) ? 1 : 0;
            st->state = sw_name_len;

            /* fall through */

        case sw_name_len:

            rc = njt_http_v3_parse_prefix_int(c, &st->pint, 5, b);
            if (rc != NJT_DONE) {
                return rc;
            }

            st->literal.length = st->pint.value;
            if (st->literal.length == 0) {
                return NJT_ERROR;
            }

            st->state = sw_name;
            break;

        case sw_name:

            rc = njt_http_v3_parse_literal(c, &st->literal, b);
            if (rc != NJT_DONE) {
                return rc;
            }

            st->name = st->literal.value;
            st->state = sw_value_len;
            break;

        case sw_value_len:

            if (b->pos == b->last) {
                return NJT_AGAIN;
            }

            ch = *b->pos;

            st->literal.huffman = (ch & 0x80) ? 1 : 0;
            st->state = sw_read_value_len;

            /* fall through */

        case sw_read_value_len:

            rc = njt_http_v3_parse_prefix_int(c, &st->pint, 7, b);
            if (rc != NJT_DONE) {
                return rc;
            }

            st->literal.length = st->pint.value;
            if (st->literal.length == 0) {
                st->value.len = 0;
                goto done;
            }

            st->state = sw_value;
            break;

        case sw_value:

            rc = njt_http_v3_parse_literal(c, &st->literal, b);
            if (rc != NJT_DONE) {
                return rc;
            }

            st->value = st->literal.value;
            goto done;
        }
    }

done:

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse field iln done \"%V\":\"%V\"",
                   &st->name, &st->value);

    rc = njt_http_v3_insert(c, &st->name, &st->value);
    if (rc != NJT_OK) {
        return rc;
    }

    st->state = sw_start;
    return NJT_DONE;
}


static njt_int_t
njt_http_v3_parse_decoder(njt_connection_t *c, njt_http_v3_parse_decoder_t *st,
    njt_buf_t *b)
{
    u_char     ch;
    njt_int_t  rc;
    enum {
        sw_start = 0,
        sw_ack_section,
        sw_cancel_stream,
        sw_inc_insert_count
    };

    for ( ;; ) {

        if (st->state == sw_start) {

            njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                           "http3 parse decoder instruction");

            if (b->pos == b->last) {
                return NJT_AGAIN;
            }

            ch = *b->pos;

            if (ch & 0x80) {
                /* Section Acknowledgment */

                st->state = sw_ack_section;

            } else if (ch & 0x40) {
                /*  Stream Cancellation */

                st->state = sw_cancel_stream;

            }  else {
                /*  Insert Count Increment */

                st->state = sw_inc_insert_count;
            }
        }

        switch (st->state) {

        case sw_ack_section:

            rc = njt_http_v3_parse_prefix_int(c, &st->pint, 7, b);
            if (rc != NJT_DONE) {
                return rc;
            }

            rc = njt_http_v3_ack_section(c, st->pint.value);
            if (rc != NJT_OK) {
                return rc;
            }

            st->state = sw_start;
            break;

        case sw_cancel_stream:

            rc = njt_http_v3_parse_prefix_int(c, &st->pint, 6, b);
            if (rc != NJT_DONE) {
                return rc;
            }

            rc = njt_http_v3_cancel_stream(c, st->pint.value);
            if (rc != NJT_OK) {
                return rc;
            }

            st->state = sw_start;
            break;

        case sw_inc_insert_count:

            rc = njt_http_v3_parse_prefix_int(c, &st->pint, 6, b);
            if (rc != NJT_DONE) {
                return rc;
            }

            rc = njt_http_v3_inc_insert_count(c, st->pint.value);
            if (rc != NJT_OK) {
                return rc;
            }

            st->state = sw_start;
            break;
        }
    }
}


njt_int_t
njt_http_v3_parse_data(njt_connection_t *c, njt_http_v3_parse_data_t *st,
    njt_buf_t *b)
{
    njt_int_t  rc;
    enum {
        sw_start = 0,
        sw_type,
        sw_length,
        sw_skip
    };

    for ( ;; ) {

        switch (st->state) {

        case sw_start:

            njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0, "http3 parse data");

            st->state = sw_type;

            /* fall through */

        case sw_type:

            rc = njt_http_v3_parse_varlen_int(c, &st->vlint, b);
            if (rc != NJT_DONE) {
                return rc;
            }

            st->type = st->vlint.value;

            if (st->type == NJT_HTTP_V3_FRAME_HEADERS) {
                /* trailers */
                goto done;
            }

            if (njt_http_v3_is_v2_frame(st->type)
                || st->type == NJT_HTTP_V3_FRAME_GOAWAY
                || st->type == NJT_HTTP_V3_FRAME_SETTINGS
                || st->type == NJT_HTTP_V3_FRAME_MAX_PUSH_ID
                || st->type == NJT_HTTP_V3_FRAME_CANCEL_PUSH
                || st->type == NJT_HTTP_V3_FRAME_PUSH_PROMISE)
            {
                return NJT_HTTP_V3_ERR_FRAME_UNEXPECTED;
            }

            st->state = sw_length;
            break;

        case sw_length:

            rc = njt_http_v3_parse_varlen_int(c, &st->vlint, b);
            if (rc != NJT_DONE) {
                return rc;
            }

            st->length = st->vlint.value;

            njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                           "http3 parse data type:%ui, len:%ui",
                           st->type, st->length);

            if (st->type != NJT_HTTP_V3_FRAME_DATA && st->length > 0) {
                st->state = sw_skip;
                break;
            }

            st->state = sw_type;
            return NJT_OK;

        case sw_skip:

            rc = njt_http_v3_parse_skip(b, &st->length);
            if (rc != NJT_DONE) {
                return rc;
            }

            st->state = sw_type;
            break;
        }
    }

done:

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0, "http3 parse data done");

    st->state = sw_start;
    return NJT_DONE;
}


njt_int_t
njt_http_v3_parse_uni(njt_connection_t *c, njt_http_v3_parse_uni_t *st,
    njt_buf_t *b)
{
    njt_int_t  rc;
    enum {
        sw_start = 0,
        sw_type,
        sw_control,
        sw_encoder,
        sw_decoder,
        sw_unknown
    };

    for ( ;; ) {

        switch (st->state) {
        case sw_start:

            njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0, "http3 parse uni");

            st->state = sw_type;

            /* fall through */

        case sw_type:

            rc = njt_http_v3_parse_varlen_int(c, &st->vlint, b);
            if (rc != NJT_DONE) {
                return rc;
            }

            rc = njt_http_v3_register_uni_stream(c, st->vlint.value);
            if (rc != NJT_OK) {
                return rc;
            }

            switch (st->vlint.value) {
            case NJT_HTTP_V3_STREAM_CONTROL:
                st->state = sw_control;
                break;

            case NJT_HTTP_V3_STREAM_ENCODER:
                st->state = sw_encoder;
                break;

            case NJT_HTTP_V3_STREAM_DECODER:
                st->state = sw_decoder;
                break;

            default:
                st->state = sw_unknown;
            }

            break;

        case sw_control:

            return njt_http_v3_parse_control(c, &st->u.control, b);

        case sw_encoder:

            return njt_http_v3_parse_encoder(c, &st->u.encoder, b);

        case sw_decoder:

            return njt_http_v3_parse_decoder(c, &st->u.decoder, b);

        case sw_unknown:

            b->pos = b->last;
            return NJT_AGAIN;
        }
    }
}
