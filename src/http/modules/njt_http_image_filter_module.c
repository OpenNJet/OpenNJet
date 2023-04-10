
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>

#include <gd.h>


#define NJT_HTTP_IMAGE_OFF       0
#define NJT_HTTP_IMAGE_TEST      1
#define NJT_HTTP_IMAGE_SIZE      2
#define NJT_HTTP_IMAGE_RESIZE    3
#define NJT_HTTP_IMAGE_CROP      4
#define NJT_HTTP_IMAGE_ROTATE    5


#define NJT_HTTP_IMAGE_START     0
#define NJT_HTTP_IMAGE_READ      1
#define NJT_HTTP_IMAGE_PROCESS   2
#define NJT_HTTP_IMAGE_PASS      3
#define NJT_HTTP_IMAGE_DONE      4


#define NJT_HTTP_IMAGE_NONE      0
#define NJT_HTTP_IMAGE_JPEG      1
#define NJT_HTTP_IMAGE_GIF       2
#define NJT_HTTP_IMAGE_PNG       3
#define NJT_HTTP_IMAGE_WEBP      4


#define NJT_HTTP_IMAGE_BUFFERED  0x08


typedef struct {
    njt_uint_t                   filter;
    njt_uint_t                   width;
    njt_uint_t                   height;
    njt_uint_t                   angle;
    njt_uint_t                   jpeg_quality;
    njt_uint_t                   webp_quality;
    njt_uint_t                   sharpen;

    njt_flag_t                   transparency;
    njt_flag_t                   interlace;

    njt_http_complex_value_t    *wcv;
    njt_http_complex_value_t    *hcv;
    njt_http_complex_value_t    *acv;
    njt_http_complex_value_t    *jqcv;
    njt_http_complex_value_t    *wqcv;
    njt_http_complex_value_t    *shcv;

    size_t                       buffer_size;
} njt_http_image_filter_conf_t;


typedef struct {
    u_char                      *image;
    u_char                      *last;

    size_t                       length;

    njt_uint_t                   width;
    njt_uint_t                   height;
    njt_uint_t                   max_width;
    njt_uint_t                   max_height;
    njt_uint_t                   angle;

    njt_uint_t                   phase;
    njt_uint_t                   type;
    njt_uint_t                   force;
} njt_http_image_filter_ctx_t;


static njt_int_t njt_http_image_send(njt_http_request_t *r,
    njt_http_image_filter_ctx_t *ctx, njt_chain_t *in);
static njt_uint_t njt_http_image_test(njt_http_request_t *r, njt_chain_t *in);
static njt_int_t njt_http_image_read(njt_http_request_t *r, njt_chain_t *in);
static njt_buf_t *njt_http_image_process(njt_http_request_t *r);
static njt_buf_t *njt_http_image_json(njt_http_request_t *r,
    njt_http_image_filter_ctx_t *ctx);
static njt_buf_t *njt_http_image_asis(njt_http_request_t *r,
    njt_http_image_filter_ctx_t *ctx);
static void njt_http_image_length(njt_http_request_t *r, njt_buf_t *b);
static njt_int_t njt_http_image_size(njt_http_request_t *r,
    njt_http_image_filter_ctx_t *ctx);

static njt_buf_t *njt_http_image_resize(njt_http_request_t *r,
    njt_http_image_filter_ctx_t *ctx);
static gdImagePtr njt_http_image_source(njt_http_request_t *r,
    njt_http_image_filter_ctx_t *ctx);
static gdImagePtr njt_http_image_new(njt_http_request_t *r, int w, int h,
    int colors);
static u_char *njt_http_image_out(njt_http_request_t *r, njt_uint_t type,
    gdImagePtr img, int *size);
static void njt_http_image_cleanup(void *data);
static njt_uint_t njt_http_image_filter_get_value(njt_http_request_t *r,
    njt_http_complex_value_t *cv, njt_uint_t v);
static njt_uint_t njt_http_image_filter_value(njt_str_t *value);


static void *njt_http_image_filter_create_conf(njt_conf_t *cf);
static char *njt_http_image_filter_merge_conf(njt_conf_t *cf, void *parent,
    void *child);
static char *njt_http_image_filter(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_image_filter_jpeg_quality(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);
static char *njt_http_image_filter_webp_quality(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);
static char *njt_http_image_filter_sharpen(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static njt_int_t njt_http_image_filter_init(njt_conf_t *cf);


static njt_command_t  njt_http_image_filter_commands[] = {

    { njt_string("image_filter"),
      NJT_HTTP_LOC_CONF|NJT_CONF_TAKE123,
      njt_http_image_filter,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("image_filter_jpeg_quality"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_image_filter_jpeg_quality,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("image_filter_webp_quality"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_image_filter_webp_quality,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("image_filter_sharpen"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_image_filter_sharpen,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("image_filter_transparency"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_image_filter_conf_t, transparency),
      NULL },

    { njt_string("image_filter_interlace"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_image_filter_conf_t, interlace),
      NULL },

    { njt_string("image_filter_buffer"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_image_filter_conf_t, buffer_size),
      NULL },

      njt_null_command
};


static njt_http_module_t  njt_http_image_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    njt_http_image_filter_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_image_filter_create_conf,     /* create location configuration */
    njt_http_image_filter_merge_conf       /* merge location configuration */
};


njt_module_t  njt_http_image_filter_module = {
    NJT_MODULE_V1,
    &njt_http_image_filter_module_ctx,     /* module context */
    njt_http_image_filter_commands,        /* module directives */
    NJT_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};


static njt_http_output_header_filter_pt  njt_http_next_header_filter;
static njt_http_output_body_filter_pt    njt_http_next_body_filter;


static njt_str_t  njt_http_image_types[] = {
    njt_string("image/jpeg"),
    njt_string("image/gif"),
    njt_string("image/png"),
    njt_string("image/webp")
};


static njt_int_t
njt_http_image_header_filter(njt_http_request_t *r)
{
    off_t                          len;
    njt_http_image_filter_ctx_t   *ctx;
    njt_http_image_filter_conf_t  *conf;

    if (r->headers_out.status == NJT_HTTP_NOT_MODIFIED) {
        return njt_http_next_header_filter(r);
    }

    ctx = njt_http_get_module_ctx(r, njt_http_image_filter_module);

    if (ctx) {
        njt_http_set_ctx(r, NULL, njt_http_image_filter_module);
        return njt_http_next_header_filter(r);
    }

    conf = njt_http_get_module_loc_conf(r, njt_http_image_filter_module);

    if (conf->filter == NJT_HTTP_IMAGE_OFF) {
        return njt_http_next_header_filter(r);
    }

    if (r->headers_out.content_type.len
            >= sizeof("multipart/x-mixed-replace") - 1
        && njt_strncasecmp(r->headers_out.content_type.data,
                           (u_char *) "multipart/x-mixed-replace",
                           sizeof("multipart/x-mixed-replace") - 1)
           == 0)
    {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "image filter: multipart/x-mixed-replace response");

        return NJT_ERROR;
    }

    ctx = njt_pcalloc(r->pool, sizeof(njt_http_image_filter_ctx_t));
    if (ctx == NULL) {
        return NJT_ERROR;
    }

    njt_http_set_ctx(r, ctx, njt_http_image_filter_module);

    len = r->headers_out.content_length_n;

    if (len != -1 && len > (off_t) conf->buffer_size) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "image filter: too big response: %O", len);

        return NJT_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    if (len == -1) {
        ctx->length = conf->buffer_size;

    } else {
        ctx->length = (size_t) len;
    }

    if (r->headers_out.refresh) {
        r->headers_out.refresh->hash = 0;
    }

    r->main_filter_need_in_memory = 1;
    r->allow_ranges = 0;

    return NJT_OK;
}


static njt_int_t
njt_http_image_body_filter(njt_http_request_t *r, njt_chain_t *in)
{
    njt_int_t                      rc;
    njt_str_t                     *ct;
    njt_chain_t                    out;
    njt_http_image_filter_ctx_t   *ctx;
    njt_http_image_filter_conf_t  *conf;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0, "image filter");

    if (in == NULL) {
        return njt_http_next_body_filter(r, in);
    }

    ctx = njt_http_get_module_ctx(r, njt_http_image_filter_module);

    if (ctx == NULL) {
        return njt_http_next_body_filter(r, in);
    }

    switch (ctx->phase) {

    case NJT_HTTP_IMAGE_START:

        ctx->type = njt_http_image_test(r, in);

        conf = njt_http_get_module_loc_conf(r, njt_http_image_filter_module);

        if (ctx->type == NJT_HTTP_IMAGE_NONE) {

            if (conf->filter == NJT_HTTP_IMAGE_SIZE) {
                out.buf = njt_http_image_json(r, NULL);

                if (out.buf) {
                    out.next = NULL;
                    ctx->phase = NJT_HTTP_IMAGE_DONE;

                    return njt_http_image_send(r, ctx, &out);
                }
            }

            return njt_http_filter_finalize_request(r,
                                              &njt_http_image_filter_module,
                                              NJT_HTTP_UNSUPPORTED_MEDIA_TYPE);
        }

        /* override content type */

        ct = &njt_http_image_types[ctx->type - 1];
        r->headers_out.content_type_len = ct->len;
        r->headers_out.content_type = *ct;
        r->headers_out.content_type_lowcase = NULL;

        if (conf->filter == NJT_HTTP_IMAGE_TEST) {
            ctx->phase = NJT_HTTP_IMAGE_PASS;

            return njt_http_image_send(r, ctx, in);
        }

        ctx->phase = NJT_HTTP_IMAGE_READ;

        /* fall through */

    case NJT_HTTP_IMAGE_READ:

        rc = njt_http_image_read(r, in);

        if (rc == NJT_AGAIN) {
            return NJT_OK;
        }

        if (rc == NJT_ERROR) {
            return njt_http_filter_finalize_request(r,
                                              &njt_http_image_filter_module,
                                              NJT_HTTP_UNSUPPORTED_MEDIA_TYPE);
        }

        /* fall through */

    case NJT_HTTP_IMAGE_PROCESS:

        out.buf = njt_http_image_process(r);

        if (out.buf == NULL) {
            return njt_http_filter_finalize_request(r,
                                              &njt_http_image_filter_module,
                                              NJT_HTTP_UNSUPPORTED_MEDIA_TYPE);
        }

        out.next = NULL;
        ctx->phase = NJT_HTTP_IMAGE_PASS;

        return njt_http_image_send(r, ctx, &out);

    case NJT_HTTP_IMAGE_PASS:

        return njt_http_next_body_filter(r, in);

    default: /* NJT_HTTP_IMAGE_DONE */

        rc = njt_http_next_body_filter(r, NULL);

        /* NJT_ERROR resets any pending data */
        return (rc == NJT_OK) ? NJT_ERROR : rc;
    }
}


static njt_int_t
njt_http_image_send(njt_http_request_t *r, njt_http_image_filter_ctx_t *ctx,
    njt_chain_t *in)
{
    njt_int_t  rc;

    rc = njt_http_next_header_filter(r);

    if (rc == NJT_ERROR || rc > NJT_OK || r->header_only) {
        return NJT_ERROR;
    }

    rc = njt_http_next_body_filter(r, in);

    if (ctx->phase == NJT_HTTP_IMAGE_DONE) {
        /* NJT_ERROR resets any pending data */
        return (rc == NJT_OK) ? NJT_ERROR : rc;
    }

    return rc;
}


static njt_uint_t
njt_http_image_test(njt_http_request_t *r, njt_chain_t *in)
{
    u_char  *p;

    p = in->buf->pos;

    if (in->buf->last - p < 16) {
        return NJT_HTTP_IMAGE_NONE;
    }

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "image filter: \"%c%c\"", p[0], p[1]);

    if (p[0] == 0xff && p[1] == 0xd8) {

        /* JPEG */

        return NJT_HTTP_IMAGE_JPEG;

    } else if (p[0] == 'G' && p[1] == 'I' && p[2] == 'F' && p[3] == '8'
               && p[5] == 'a')
    {
        if (p[4] == '9' || p[4] == '7') {
            /* GIF */
            return NJT_HTTP_IMAGE_GIF;
        }

    } else if (p[0] == 0x89 && p[1] == 'P' && p[2] == 'N' && p[3] == 'G'
               && p[4] == 0x0d && p[5] == 0x0a && p[6] == 0x1a && p[7] == 0x0a)
    {
        /* PNG */

        return NJT_HTTP_IMAGE_PNG;

    } else if (p[0] == 'R' && p[1] == 'I' && p[2] == 'F' && p[3] == 'F'
               && p[8] == 'W' && p[9] == 'E' && p[10] == 'B' && p[11] == 'P')
    {
        /* WebP */

        return NJT_HTTP_IMAGE_WEBP;
    }

    return NJT_HTTP_IMAGE_NONE;
}


static njt_int_t
njt_http_image_read(njt_http_request_t *r, njt_chain_t *in)
{
    u_char                       *p;
    size_t                        size, rest;
    njt_buf_t                    *b;
    njt_chain_t                  *cl;
    njt_http_image_filter_ctx_t  *ctx;

    ctx = njt_http_get_module_ctx(r, njt_http_image_filter_module);

    if (ctx->image == NULL) {
        ctx->image = njt_palloc(r->pool, ctx->length);
        if (ctx->image == NULL) {
            return NJT_ERROR;
        }

        ctx->last = ctx->image;
    }

    p = ctx->last;

    for (cl = in; cl; cl = cl->next) {

        b = cl->buf;
        size = b->last - b->pos;

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "image buf: %uz", size);

        rest = ctx->image + ctx->length - p;

        if (size > rest) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "image filter: too big response");
            return NJT_ERROR;
        }

        p = njt_cpymem(p, b->pos, size);
        b->pos += size;

        if (b->last_buf) {
            ctx->last = p;
            return NJT_OK;
        }
    }

    ctx->last = p;
    r->connection->buffered |= NJT_HTTP_IMAGE_BUFFERED;

    return NJT_AGAIN;
}


static njt_buf_t *
njt_http_image_process(njt_http_request_t *r)
{
    njt_int_t                      rc;
    njt_http_image_filter_ctx_t   *ctx;
    njt_http_image_filter_conf_t  *conf;

    r->connection->buffered &= ~NJT_HTTP_IMAGE_BUFFERED;

    ctx = njt_http_get_module_ctx(r, njt_http_image_filter_module);

    rc = njt_http_image_size(r, ctx);

    conf = njt_http_get_module_loc_conf(r, njt_http_image_filter_module);

    if (conf->filter == NJT_HTTP_IMAGE_SIZE) {
        return njt_http_image_json(r, rc == NJT_OK ? ctx : NULL);
    }

    ctx->angle = njt_http_image_filter_get_value(r, conf->acv, conf->angle);

    if (conf->filter == NJT_HTTP_IMAGE_ROTATE) {

        if (ctx->angle != 90 && ctx->angle != 180 && ctx->angle != 270) {
            return NULL;
        }

        return njt_http_image_resize(r, ctx);
    }

    ctx->max_width = njt_http_image_filter_get_value(r, conf->wcv, conf->width);
    if (ctx->max_width == 0) {
        return NULL;
    }

    ctx->max_height = njt_http_image_filter_get_value(r, conf->hcv,
                                                      conf->height);
    if (ctx->max_height == 0) {
        return NULL;
    }

    if (rc == NJT_OK
        && ctx->width <= ctx->max_width
        && ctx->height <= ctx->max_height
        && ctx->angle == 0
        && !ctx->force)
    {
        return njt_http_image_asis(r, ctx);
    }

    return njt_http_image_resize(r, ctx);
}


static njt_buf_t *
njt_http_image_json(njt_http_request_t *r, njt_http_image_filter_ctx_t *ctx)
{
    size_t      len;
    njt_buf_t  *b;

    b = njt_calloc_buf(r->pool);
    if (b == NULL) {
        return NULL;
    }

    b->memory = 1;
    b->last_buf = 1;

    njt_http_clean_header(r);

    r->headers_out.status = NJT_HTTP_OK;
    r->headers_out.content_type_len = sizeof("application/json") - 1;
    njt_str_set(&r->headers_out.content_type, "application/json");
    r->headers_out.content_type_lowcase = NULL;

    if (ctx == NULL) {
        b->pos = (u_char *) "{}" CRLF;
        b->last = b->pos + sizeof("{}" CRLF) - 1;

        njt_http_image_length(r, b);

        return b;
    }

    len = sizeof("{ \"img\" : "
                 "{ \"width\": , \"height\": , \"type\": \"jpeg\" } }" CRLF) - 1
          + 2 * NJT_SIZE_T_LEN;

    b->pos = njt_pnalloc(r->pool, len);
    if (b->pos == NULL) {
        return NULL;
    }

    b->last = njt_sprintf(b->pos,
                          "{ \"img\" : "
                                       "{ \"width\": %uz,"
                                        " \"height\": %uz,"
                                        " \"type\": \"%s\" } }" CRLF,
                          ctx->width, ctx->height,
                          njt_http_image_types[ctx->type - 1].data + 6);

    njt_http_image_length(r, b);

    return b;
}


static njt_buf_t *
njt_http_image_asis(njt_http_request_t *r, njt_http_image_filter_ctx_t *ctx)
{
    njt_buf_t  *b;

    b = njt_calloc_buf(r->pool);
    if (b == NULL) {
        return NULL;
    }

    b->pos = ctx->image;
    b->last = ctx->last;
    b->memory = 1;
    b->last_buf = 1;

    njt_http_image_length(r, b);

    return b;
}


static void
njt_http_image_length(njt_http_request_t *r, njt_buf_t *b)
{
    r->headers_out.content_length_n = b->last - b->pos;

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
    }

    r->headers_out.content_length = NULL;
}


static njt_int_t
njt_http_image_size(njt_http_request_t *r, njt_http_image_filter_ctx_t *ctx)
{
    u_char      *p, *last;
    size_t       len, app;
    njt_uint_t   width, height;

    p = ctx->image;

    switch (ctx->type) {

    case NJT_HTTP_IMAGE_JPEG:

        p += 2;
        last = ctx->image + ctx->length - 10;
        width = 0;
        height = 0;
        app = 0;

        while (p < last) {

            if (p[0] == 0xff && p[1] != 0xff) {

                njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "JPEG: %02xd %02xd", p[0], p[1]);

                p++;

                if ((*p == 0xc0 || *p == 0xc1 || *p == 0xc2 || *p == 0xc3
                     || *p == 0xc9 || *p == 0xca || *p == 0xcb)
                    && (width == 0 || height == 0))
                {
                    width = p[6] * 256 + p[7];
                    height = p[4] * 256 + p[5];
                }

                njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "JPEG: %02xd %02xd", p[1], p[2]);

                len = p[1] * 256 + p[2];

                if (*p >= 0xe1 && *p <= 0xef) {
                    /* application data, e.g., EXIF, Adobe XMP, etc. */
                    app += len;
                }

                p += len;

                continue;
            }

            p++;
        }

        if (width == 0 || height == 0) {
            return NJT_DECLINED;
        }

        if (ctx->length / 20 < app) {
            /* force conversion if application data consume more than 5% */
            ctx->force = 1;
            njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "app data size: %uz", app);
        }

        break;

    case NJT_HTTP_IMAGE_GIF:

        if (ctx->length < 10) {
            return NJT_DECLINED;
        }

        width = p[7] * 256 + p[6];
        height = p[9] * 256 + p[8];

        break;

    case NJT_HTTP_IMAGE_PNG:

        if (ctx->length < 24) {
            return NJT_DECLINED;
        }

        width = p[18] * 256 + p[19];
        height = p[22] * 256 + p[23];

        break;

    case NJT_HTTP_IMAGE_WEBP:

        if (ctx->length < 30) {
            return NJT_DECLINED;
        }

        if (p[12] != 'V' || p[13] != 'P' || p[14] != '8') {
            return NJT_DECLINED;
        }

        switch (p[15]) {

        case ' ':
            if (p[20] & 1) {
                /* not a key frame */
                return NJT_DECLINED;
            }

            if (p[23] != 0x9d || p[24] != 0x01 || p[25] != 0x2a) {
                /* invalid start code */
                return NJT_DECLINED;
            }

            width = (p[26] | p[27] << 8) & 0x3fff;
            height = (p[28] | p[29] << 8) & 0x3fff;

            break;

        case 'L':
            if (p[20] != 0x2f) {
                /* invalid signature */
                return NJT_DECLINED;
            }

            width = ((p[21] | p[22] << 8) & 0x3fff) + 1;
            height = ((p[22] >> 6 | p[23] << 2 | p[24] << 10) & 0x3fff) + 1;

            break;

        case 'X':
            width = (p[24] | p[25] << 8 | p[26] << 16) + 1;
            height = (p[27] | p[28] << 8 | p[29] << 16) + 1;
            break;

        default:
            return NJT_DECLINED;
        }

        break;

    default:

        return NJT_DECLINED;
    }

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "image size: %d x %d", (int) width, (int) height);

    ctx->width = width;
    ctx->height = height;

    return NJT_OK;
}


static njt_buf_t *
njt_http_image_resize(njt_http_request_t *r, njt_http_image_filter_ctx_t *ctx)
{
    int                            sx, sy, dx, dy, ox, oy, ax, ay, size,
                                   colors, palette, transparent, sharpen,
                                   red, green, blue, t;
    u_char                        *out;
    njt_buf_t                     *b;
    njt_uint_t                     resize;
    gdImagePtr                     src, dst;
    njt_pool_cleanup_t            *cln;
    njt_http_image_filter_conf_t  *conf;

    src = njt_http_image_source(r, ctx);

    if (src == NULL) {
        return NULL;
    }

    sx = gdImageSX(src);
    sy = gdImageSY(src);

    conf = njt_http_get_module_loc_conf(r, njt_http_image_filter_module);

    if (!ctx->force
        && ctx->angle == 0
        && (njt_uint_t) sx <= ctx->max_width
        && (njt_uint_t) sy <= ctx->max_height)
    {
        gdImageDestroy(src);
        return njt_http_image_asis(r, ctx);
    }

    colors = gdImageColorsTotal(src);

    if (colors && conf->transparency) {
        transparent = gdImageGetTransparent(src);

        if (transparent != -1) {
            palette = colors;
            red = gdImageRed(src, transparent);
            green = gdImageGreen(src, transparent);
            blue = gdImageBlue(src, transparent);

            goto transparent;
        }
    }

    palette = 0;
    transparent = -1;
    red = 0;
    green = 0;
    blue = 0;

transparent:

    gdImageColorTransparent(src, -1);

    dx = sx;
    dy = sy;

    if (conf->filter == NJT_HTTP_IMAGE_RESIZE) {

        if ((njt_uint_t) dx > ctx->max_width) {
            dy = dy * ctx->max_width / dx;
            dy = dy ? dy : 1;
            dx = ctx->max_width;
        }

        if ((njt_uint_t) dy > ctx->max_height) {
            dx = dx * ctx->max_height / dy;
            dx = dx ? dx : 1;
            dy = ctx->max_height;
        }

        resize = 1;

    } else if (conf->filter == NJT_HTTP_IMAGE_ROTATE) {

        resize = 0;

    } else { /* NJT_HTTP_IMAGE_CROP */

        resize = 0;

        if ((double) dx / dy < (double) ctx->max_width / ctx->max_height) {
            if ((njt_uint_t) dx > ctx->max_width) {
                dy = dy * ctx->max_width / dx;
                dy = dy ? dy : 1;
                dx = ctx->max_width;
                resize = 1;
            }

        } else {
            if ((njt_uint_t) dy > ctx->max_height) {
                dx = dx * ctx->max_height / dy;
                dx = dx ? dx : 1;
                dy = ctx->max_height;
                resize = 1;
            }
        }
    }

    if (resize) {
        dst = njt_http_image_new(r, dx, dy, palette);
        if (dst == NULL) {
            gdImageDestroy(src);
            return NULL;
        }

        if (colors == 0) {
            gdImageSaveAlpha(dst, 1);
            gdImageAlphaBlending(dst, 0);
        }

        gdImageCopyResampled(dst, src, 0, 0, 0, 0, dx, dy, sx, sy);

        if (colors) {
            gdImageTrueColorToPalette(dst, 1, 256);
        }

        gdImageDestroy(src);

    } else {
        dst = src;
    }

    if (ctx->angle) {
        src = dst;

        ax = (dx % 2 == 0) ? 1 : 0;
        ay = (dy % 2 == 0) ? 1 : 0;

        switch (ctx->angle) {

        case 90:
        case 270:
            dst = njt_http_image_new(r, dy, dx, palette);
            if (dst == NULL) {
                gdImageDestroy(src);
                return NULL;
            }
            if (ctx->angle == 90) {
                ox = dy / 2 + ay;
                oy = dx / 2 - ax;

            } else {
                ox = dy / 2 - ay;
                oy = dx / 2 + ax;
            }

            gdImageCopyRotated(dst, src, ox, oy, 0, 0,
                               dx + ax, dy + ay, ctx->angle);
            gdImageDestroy(src);

            t = dx;
            dx = dy;
            dy = t;
            break;

        case 180:
            dst = njt_http_image_new(r, dx, dy, palette);
            if (dst == NULL) {
                gdImageDestroy(src);
                return NULL;
            }
            gdImageCopyRotated(dst, src, dx / 2 - ax, dy / 2 - ay, 0, 0,
                               dx + ax, dy + ay, ctx->angle);
            gdImageDestroy(src);
            break;
        }
    }

    if (conf->filter == NJT_HTTP_IMAGE_CROP) {

        src = dst;

        if ((njt_uint_t) dx > ctx->max_width) {
            ox = dx - ctx->max_width;

        } else {
            ox = 0;
        }

        if ((njt_uint_t) dy > ctx->max_height) {
            oy = dy - ctx->max_height;

        } else {
            oy = 0;
        }

        if (ox || oy) {

            dst = njt_http_image_new(r, dx - ox, dy - oy, colors);

            if (dst == NULL) {
                gdImageDestroy(src);
                return NULL;
            }

            ox /= 2;
            oy /= 2;

            njt_log_debug4(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "image crop: %d x %d @ %d x %d",
                           dx, dy, ox, oy);

            if (colors == 0) {
                gdImageSaveAlpha(dst, 1);
                gdImageAlphaBlending(dst, 0);
            }

            gdImageCopy(dst, src, 0, 0, ox, oy, dx - ox, dy - oy);

            if (colors) {
                gdImageTrueColorToPalette(dst, 1, 256);
            }

            gdImageDestroy(src);
        }
    }

    if (transparent != -1 && colors) {
        gdImageColorTransparent(dst, gdImageColorExact(dst, red, green, blue));
    }

    sharpen = njt_http_image_filter_get_value(r, conf->shcv, conf->sharpen);
    if (sharpen > 0) {
        gdImageSharpen(dst, sharpen);
    }

    gdImageInterlace(dst, (int) conf->interlace);

    out = njt_http_image_out(r, ctx->type, dst, &size);

    njt_log_debug3(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "image: %d x %d %d", sx, sy, colors);

    gdImageDestroy(dst);
    njt_pfree(r->pool, ctx->image);

    if (out == NULL) {
        return NULL;
    }

    cln = njt_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        gdFree(out);
        return NULL;
    }

    b = njt_calloc_buf(r->pool);
    if (b == NULL) {
        gdFree(out);
        return NULL;
    }

    cln->handler = njt_http_image_cleanup;
    cln->data = out;

    b->pos = out;
    b->last = out + size;
    b->memory = 1;
    b->last_buf = 1;

    njt_http_image_length(r, b);
    njt_http_weak_etag(r);

    return b;
}


static gdImagePtr
njt_http_image_source(njt_http_request_t *r, njt_http_image_filter_ctx_t *ctx)
{
    char        *failed;
    gdImagePtr   img;

    img = NULL;

    switch (ctx->type) {

    case NJT_HTTP_IMAGE_JPEG:
        img = gdImageCreateFromJpegPtr(ctx->length, ctx->image);
        failed = "gdImageCreateFromJpegPtr() failed";
        break;

    case NJT_HTTP_IMAGE_GIF:
        img = gdImageCreateFromGifPtr(ctx->length, ctx->image);
        failed = "gdImageCreateFromGifPtr() failed";
        break;

    case NJT_HTTP_IMAGE_PNG:
        img = gdImageCreateFromPngPtr(ctx->length, ctx->image);
        failed = "gdImageCreateFromPngPtr() failed";
        break;

    case NJT_HTTP_IMAGE_WEBP:
#if (NJT_HAVE_GD_WEBP)
        img = gdImageCreateFromWebpPtr(ctx->length, ctx->image);
        failed = "gdImageCreateFromWebpPtr() failed";
#else
        failed = "njet was built without GD WebP support";
#endif
        break;

    default:
        failed = "unknown image type";
        break;
    }

    if (img == NULL) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, failed);
    }

    return img;
}


static gdImagePtr
njt_http_image_new(njt_http_request_t *r, int w, int h, int colors)
{
    gdImagePtr  img;

    if (colors == 0) {
        img = gdImageCreateTrueColor(w, h);

        if (img == NULL) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "gdImageCreateTrueColor() failed");
            return NULL;
        }

    } else {
        img = gdImageCreate(w, h);

        if (img == NULL) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "gdImageCreate() failed");
            return NULL;
        }
    }

    return img;
}


static u_char *
njt_http_image_out(njt_http_request_t *r, njt_uint_t type, gdImagePtr img,
    int *size)
{
    char                          *failed;
    u_char                        *out;
    njt_int_t                      q;
    njt_http_image_filter_conf_t  *conf;

    out = NULL;

    switch (type) {

    case NJT_HTTP_IMAGE_JPEG:
        conf = njt_http_get_module_loc_conf(r, njt_http_image_filter_module);

        q = njt_http_image_filter_get_value(r, conf->jqcv, conf->jpeg_quality);
        if (q <= 0) {
            return NULL;
        }

        out = gdImageJpegPtr(img, size, q);
        failed = "gdImageJpegPtr() failed";
        break;

    case NJT_HTTP_IMAGE_GIF:
        out = gdImageGifPtr(img, size);
        failed = "gdImageGifPtr() failed";
        break;

    case NJT_HTTP_IMAGE_PNG:
        out = gdImagePngPtr(img, size);
        failed = "gdImagePngPtr() failed";
        break;

    case NJT_HTTP_IMAGE_WEBP:
#if (NJT_HAVE_GD_WEBP)
        conf = njt_http_get_module_loc_conf(r, njt_http_image_filter_module);

        q = njt_http_image_filter_get_value(r, conf->wqcv, conf->webp_quality);
        if (q <= 0) {
            return NULL;
        }

        out = gdImageWebpPtrEx(img, size, q);
        failed = "gdImageWebpPtrEx() failed";
#else
        failed = "njet was built without GD WebP support";
#endif
        break;

    default:
        failed = "unknown image type";
        break;
    }

    if (out == NULL) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, failed);
    }

    return out;
}


static void
njt_http_image_cleanup(void *data)
{
    gdFree(data);
}


static njt_uint_t
njt_http_image_filter_get_value(njt_http_request_t *r,
    njt_http_complex_value_t *cv, njt_uint_t v)
{
    njt_str_t  val;

    if (cv == NULL) {
        return v;
    }

    if (njt_http_complex_value(r, cv, &val) != NJT_OK) {
        return 0;
    }

    return njt_http_image_filter_value(&val);
}


static njt_uint_t
njt_http_image_filter_value(njt_str_t *value)
{
    njt_int_t  n;

    if (value->len == 1 && value->data[0] == '-') {
        return (njt_uint_t) -1;
    }

    n = njt_atoi(value->data, value->len);

    if (n > 0) {
        return (njt_uint_t) n;
    }

    return 0;
}


static void *
njt_http_image_filter_create_conf(njt_conf_t *cf)
{
    njt_http_image_filter_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_image_filter_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     conf->width = 0;
     *     conf->height = 0;
     *     conf->angle = 0;
     *     conf->wcv = NULL;
     *     conf->hcv = NULL;
     *     conf->acv = NULL;
     *     conf->jqcv = NULL;
     *     conf->wqcv = NULL;
     *     conf->shcv = NULL;
     */

    conf->filter = NJT_CONF_UNSET_UINT;
    conf->jpeg_quality = NJT_CONF_UNSET_UINT;
    conf->webp_quality = NJT_CONF_UNSET_UINT;
    conf->sharpen = NJT_CONF_UNSET_UINT;
    conf->transparency = NJT_CONF_UNSET;
    conf->interlace = NJT_CONF_UNSET;
    conf->buffer_size = NJT_CONF_UNSET_SIZE;

    return conf;
}


static char *
njt_http_image_filter_merge_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_image_filter_conf_t *prev = parent;
    njt_http_image_filter_conf_t *conf = child;

    if (conf->filter == NJT_CONF_UNSET_UINT) {

        if (prev->filter == NJT_CONF_UNSET_UINT) {
            conf->filter = NJT_HTTP_IMAGE_OFF;

        } else {
            conf->filter = prev->filter;
            conf->width = prev->width;
            conf->height = prev->height;
            conf->angle = prev->angle;
            conf->wcv = prev->wcv;
            conf->hcv = prev->hcv;
            conf->acv = prev->acv;
        }
    }

    if (conf->jpeg_quality == NJT_CONF_UNSET_UINT) {

        /* 75 is libjpeg default quality */
        njt_conf_merge_uint_value(conf->jpeg_quality, prev->jpeg_quality, 75);

        if (conf->jqcv == NULL) {
            conf->jqcv = prev->jqcv;
        }
    }

    if (conf->webp_quality == NJT_CONF_UNSET_UINT) {

        /* 80 is libwebp default quality */
        njt_conf_merge_uint_value(conf->webp_quality, prev->webp_quality, 80);

        if (conf->wqcv == NULL) {
            conf->wqcv = prev->wqcv;
        }
    }

    if (conf->sharpen == NJT_CONF_UNSET_UINT) {
        njt_conf_merge_uint_value(conf->sharpen, prev->sharpen, 0);

        if (conf->shcv == NULL) {
            conf->shcv = prev->shcv;
        }
    }

    njt_conf_merge_value(conf->transparency, prev->transparency, 1);

    njt_conf_merge_value(conf->interlace, prev->interlace, 0);

    njt_conf_merge_size_value(conf->buffer_size, prev->buffer_size,
                              1 * 1024 * 1024);

    return NJT_CONF_OK;
}


static char *
njt_http_image_filter(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_image_filter_conf_t *imcf = conf;

    njt_str_t                         *value;
    njt_int_t                          n;
    njt_uint_t                         i;
    njt_http_complex_value_t           cv;
    njt_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    i = 1;

    if (cf->args->nelts == 2) {
        if (njt_strcmp(value[i].data, "off") == 0) {
            imcf->filter = NJT_HTTP_IMAGE_OFF;

        } else if (njt_strcmp(value[i].data, "test") == 0) {
            imcf->filter = NJT_HTTP_IMAGE_TEST;

        } else if (njt_strcmp(value[i].data, "size") == 0) {
            imcf->filter = NJT_HTTP_IMAGE_SIZE;

        } else {
            goto failed;
        }

        return NJT_CONF_OK;

    } else if (cf->args->nelts == 3) {

        if (njt_strcmp(value[i].data, "rotate") == 0) {
            if (imcf->filter != NJT_HTTP_IMAGE_RESIZE
                && imcf->filter != NJT_HTTP_IMAGE_CROP)
            {
                imcf->filter = NJT_HTTP_IMAGE_ROTATE;
            }

            njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &value[++i];
            ccv.complex_value = &cv;

            if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
                return NJT_CONF_ERROR;
            }

            if (cv.lengths == NULL) {
                n = njt_http_image_filter_value(&value[i]);

                if (n != 90 && n != 180 && n != 270) {
                    goto failed;
                }

                imcf->angle = (njt_uint_t) n;

            } else {
                imcf->acv = njt_palloc(cf->pool,
                                       sizeof(njt_http_complex_value_t));
                if (imcf->acv == NULL) {
                    return NJT_CONF_ERROR;
                }

                *imcf->acv = cv;
            }

            return NJT_CONF_OK;

        } else {
            goto failed;
        }
    }

    if (njt_strcmp(value[i].data, "resize") == 0) {
        imcf->filter = NJT_HTTP_IMAGE_RESIZE;

    } else if (njt_strcmp(value[i].data, "crop") == 0) {
        imcf->filter = NJT_HTTP_IMAGE_CROP;

    } else {
        goto failed;
    }

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[++i];
    ccv.complex_value = &cv;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    if (cv.lengths == NULL) {
        n = njt_http_image_filter_value(&value[i]);

        if (n == 0) {
            goto failed;
        }

        imcf->width = (njt_uint_t) n;

    } else {
        imcf->wcv = njt_palloc(cf->pool, sizeof(njt_http_complex_value_t));
        if (imcf->wcv == NULL) {
            return NJT_CONF_ERROR;
        }

        *imcf->wcv = cv;
    }

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[++i];
    ccv.complex_value = &cv;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    if (cv.lengths == NULL) {
        n = njt_http_image_filter_value(&value[i]);

        if (n == 0) {
            goto failed;
        }

        imcf->height = (njt_uint_t) n;

    } else {
        imcf->hcv = njt_palloc(cf->pool, sizeof(njt_http_complex_value_t));
        if (imcf->hcv == NULL) {
            return NJT_CONF_ERROR;
        }

        *imcf->hcv = cv;
    }

    return NJT_CONF_OK;

failed:

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "invalid parameter \"%V\"",
                       &value[i]);

    return NJT_CONF_ERROR;
}


static char *
njt_http_image_filter_jpeg_quality(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    njt_http_image_filter_conf_t *imcf = conf;

    njt_str_t                         *value;
    njt_int_t                          n;
    njt_http_complex_value_t           cv;
    njt_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    if (cv.lengths == NULL) {
        n = njt_http_image_filter_value(&value[1]);

        if (n <= 0) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid value \"%V\"", &value[1]);
            return NJT_CONF_ERROR;
        }

        imcf->jpeg_quality = (njt_uint_t) n;

    } else {
        imcf->jqcv = njt_palloc(cf->pool, sizeof(njt_http_complex_value_t));
        if (imcf->jqcv == NULL) {
            return NJT_CONF_ERROR;
        }

        *imcf->jqcv = cv;
    }

    return NJT_CONF_OK;
}


static char *
njt_http_image_filter_webp_quality(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    njt_http_image_filter_conf_t *imcf = conf;

    njt_str_t                         *value;
    njt_int_t                          n;
    njt_http_complex_value_t           cv;
    njt_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    if (cv.lengths == NULL) {
        n = njt_http_image_filter_value(&value[1]);

        if (n <= 0) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid value \"%V\"", &value[1]);
            return NJT_CONF_ERROR;
        }

        imcf->webp_quality = (njt_uint_t) n;

    } else {
        imcf->wqcv = njt_palloc(cf->pool, sizeof(njt_http_complex_value_t));
        if (imcf->wqcv == NULL) {
            return NJT_CONF_ERROR;
        }

        *imcf->wqcv = cv;
    }

    return NJT_CONF_OK;
}


static char *
njt_http_image_filter_sharpen(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    njt_http_image_filter_conf_t *imcf = conf;

    njt_str_t                         *value;
    njt_int_t                          n;
    njt_http_complex_value_t           cv;
    njt_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    if (cv.lengths == NULL) {
        n = njt_http_image_filter_value(&value[1]);

        if (n < 0) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid value \"%V\"", &value[1]);
            return NJT_CONF_ERROR;
        }

        imcf->sharpen = (njt_uint_t) n;

    } else {
        imcf->shcv = njt_palloc(cf->pool, sizeof(njt_http_complex_value_t));
        if (imcf->shcv == NULL) {
            return NJT_CONF_ERROR;
        }

        *imcf->shcv = cv;
    }

    return NJT_CONF_OK;
}


static njt_int_t
njt_http_image_filter_init(njt_conf_t *cf)
{
    njt_http_next_header_filter = njt_http_top_header_filter;
    njt_http_top_header_filter = njt_http_image_header_filter;

    njt_http_next_body_filter = njt_http_top_body_filter;
    njt_http_top_body_filter = njt_http_image_body_filter;

    return NJT_OK;
}
