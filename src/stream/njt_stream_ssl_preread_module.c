
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>


typedef struct {
    njt_flag_t      enabled;
} njt_stream_ssl_preread_srv_conf_t;


typedef struct {
    size_t          left;
    size_t          size;
    size_t          ext;
    u_char         *pos;
    u_char         *dst;
    u_char          buf[4];
    u_char          version[2];
    njt_str_t       host;
    njt_str_t       alpn;
    njt_log_t      *log;
    njt_pool_t     *pool;
    njt_uint_t      state;
} njt_stream_ssl_preread_ctx_t;


static njt_int_t njt_stream_ssl_preread_handler(njt_stream_session_t *s);
static njt_int_t njt_stream_ssl_preread_parse_record(
    njt_stream_ssl_preread_ctx_t *ctx, u_char *pos, u_char *last);
static njt_int_t njt_stream_ssl_preread_protocol_variable(
    njt_stream_session_t *s, njt_stream_variable_value_t *v, uintptr_t data);
static njt_int_t njt_stream_ssl_preread_server_name_variable(
    njt_stream_session_t *s, njt_stream_variable_value_t *v, uintptr_t data);
static njt_int_t njt_stream_ssl_preread_alpn_protocols_variable(
    njt_stream_session_t *s, njt_stream_variable_value_t *v, uintptr_t data);
static njt_int_t njt_stream_ssl_preread_add_variables(njt_conf_t *cf);
static void *njt_stream_ssl_preread_create_srv_conf(njt_conf_t *cf);
static char *njt_stream_ssl_preread_merge_srv_conf(njt_conf_t *cf, void *parent,
    void *child);
static njt_int_t njt_stream_ssl_preread_init(njt_conf_t *cf);


static njt_command_t  njt_stream_ssl_preread_commands[] = {

    { njt_string("ssl_preread"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_ssl_preread_srv_conf_t, enabled),
      NULL },

      njt_null_command
};


static njt_stream_module_t  njt_stream_ssl_preread_module_ctx = {
    njt_stream_ssl_preread_add_variables,   /* preconfiguration */
    njt_stream_ssl_preread_init,            /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    njt_stream_ssl_preread_create_srv_conf, /* create server configuration */
    njt_stream_ssl_preread_merge_srv_conf   /* merge server configuration */
};


njt_module_t  njt_stream_ssl_preread_module = {
    NJT_MODULE_V1,
    &njt_stream_ssl_preread_module_ctx,     /* module context */
    njt_stream_ssl_preread_commands,        /* module directives */
    NJT_STREAM_MODULE,                      /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NJT_MODULE_V1_PADDING
};


static njt_stream_variable_t  njt_stream_ssl_preread_vars[] = {

    { njt_string("ssl_preread_protocol"), NULL,
      njt_stream_ssl_preread_protocol_variable, 0, 0, 0 },

    { njt_string("ssl_preread_server_name"), NULL,
      njt_stream_ssl_preread_server_name_variable, 0, 0, 0 },

    { njt_string("ssl_preread_alpn_protocols"), NULL,
      njt_stream_ssl_preread_alpn_protocols_variable, 0, 0, 0 },

      njt_stream_null_variable
};


static njt_int_t
njt_stream_ssl_preread_handler(njt_stream_session_t *s)
{
    u_char                             *last, *p;
    size_t                              len;
    njt_int_t                           rc;
    njt_connection_t                   *c;
    njt_stream_ssl_preread_ctx_t       *ctx;
    njt_stream_ssl_preread_srv_conf_t  *sscf;

    c = s->connection;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, c->log, 0, "ssl preread handler");

    sscf = njt_stream_get_module_srv_conf(s, njt_stream_ssl_preread_module);

    if (!sscf->enabled) {
        return NJT_DECLINED;
    }

    if (c->type != SOCK_STREAM) {
        return NJT_DECLINED;
    }

    if (c->buffer == NULL) {
        return NJT_AGAIN;
    }

    ctx = njt_stream_get_module_ctx(s, njt_stream_ssl_preread_module);
    if (ctx == NULL) {
        ctx = njt_pcalloc(c->pool, sizeof(njt_stream_ssl_preread_ctx_t));
        if (ctx == NULL) {
            return NJT_ERROR;
        }

        njt_stream_set_ctx(s, ctx, njt_stream_ssl_preread_module);

        ctx->pool = c->pool;
        ctx->log = c->log;
        ctx->pos = c->buffer->pos;
    }

    p = ctx->pos;
    last = c->buffer->last;

    while (last - p >= 5) {

        if ((p[0] & 0x80) && p[2] == 1 && (p[3] == 0 || p[3] == 3)) {
            njt_log_debug0(NJT_LOG_DEBUG_STREAM, ctx->log, 0,
                           "ssl preread: version 2 ClientHello");
            ctx->version[0] = p[3];
            ctx->version[1] = p[4];
            return NJT_OK;
        }

        if (p[0] != 0x16) {
            njt_log_debug0(NJT_LOG_DEBUG_STREAM, ctx->log, 0,
                           "ssl preread: not a handshake");
            njt_stream_set_ctx(s, NULL, njt_stream_ssl_preread_module);
            return NJT_DECLINED;
        }

        if (p[1] != 3) {
            njt_log_debug0(NJT_LOG_DEBUG_STREAM, ctx->log, 0,
                           "ssl preread: unsupported SSL version");
            njt_stream_set_ctx(s, NULL, njt_stream_ssl_preread_module);
            return NJT_DECLINED;
        }

        len = (p[3] << 8) + p[4];

        /* read the whole record before parsing */
        if ((size_t) (last - p) < len + 5) {
            break;
        }

        p += 5;

        rc = njt_stream_ssl_preread_parse_record(ctx, p, p + len);

        if (rc == NJT_DECLINED) {
            njt_stream_set_ctx(s, NULL, njt_stream_ssl_preread_module);
            return NJT_DECLINED;
        }

        if (rc != NJT_AGAIN) {
            // return rc; openresty patch
            return rc == NJT_OK ? NJT_DECLINED : rc; // openresty patch
        }

        p += len;
    }

    ctx->pos = p;

    return NJT_AGAIN;
}


static njt_int_t
njt_stream_ssl_preread_parse_record(njt_stream_ssl_preread_ctx_t *ctx,
    u_char *pos, u_char *last)
{
    size_t   left, n, size, ext;
    u_char  *dst, *p;

    enum {
        sw_start = 0,
        sw_header,          /* handshake msg_type, length */
        sw_version,         /* client_version */
        sw_random,          /* random */
        sw_sid_len,         /* session_id length */
        sw_sid,             /* session_id */
        sw_cs_len,          /* cipher_suites length */
        sw_cs,              /* cipher_suites */
        sw_cm_len,          /* compression_methods length */
        sw_cm,              /* compression_methods */
        sw_ext,             /* extension */
        sw_ext_header,      /* extension_type, extension_data length */
        sw_sni_len,         /* SNI length */
        sw_sni_host_head,   /* SNI name_type, host_name length */
        sw_sni_host,        /* SNI host_name */
        sw_alpn_len,        /* ALPN length */
        sw_alpn_proto_len,  /* ALPN protocol_name length */
        sw_alpn_proto_data, /* ALPN protocol_name */
        sw_supver_len       /* supported_versions length */
    } state;

    njt_log_debug2(NJT_LOG_DEBUG_STREAM, ctx->log, 0,
                   "ssl preread: state %ui left %z", ctx->state, ctx->left);

    state = ctx->state;
    size = ctx->size;
    left = ctx->left;
    ext = ctx->ext;
    dst = ctx->dst;
    p = ctx->buf;

    for ( ;; ) {
        n = njt_min((size_t) (last - pos), size);

        if (dst) {
            dst = njt_cpymem(dst, pos, n);
        }

        pos += n;
        size -= n;
        left -= n;

        if (size != 0) {
            break;
        }

        switch (state) {

        case sw_start:
            state = sw_header;
            dst = p;
            size = 4;
            left = size;
            break;

        case sw_header:
            if (p[0] != 1) {
                njt_log_debug0(NJT_LOG_DEBUG_STREAM, ctx->log, 0,
                               "ssl preread: not a client hello");
                return NJT_DECLINED;
            }

            state = sw_version;
            dst = ctx->version;
            size = 2;
            left = (p[1] << 16) + (p[2] << 8) + p[3];
            break;

        case sw_version:
            state = sw_random;
            dst = NULL;
            size = 32;
            break;

        case sw_random:
            state = sw_sid_len;
            dst = p;
            size = 1;
            break;

        case sw_sid_len:
            state = sw_sid;
            dst = NULL;
            size = p[0];
            break;

        case sw_sid:
            state = sw_cs_len;
            dst = p;
            size = 2;
            break;

        case sw_cs_len:
            state = sw_cs;
            dst = NULL;
            size = (p[0] << 8) + p[1];
            break;

        case sw_cs:
            state = sw_cm_len;
            dst = p;
            size = 1;
            break;

        case sw_cm_len:
            state = sw_cm;
            dst = NULL;
            size = p[0];
            break;

        case sw_cm:
            if (left == 0) {
                /* no extensions */
                return NJT_OK;
            }

            state = sw_ext;
            dst = p;
            size = 2;
            break;

        case sw_ext:
            if (left == 0) {
                return NJT_OK;
            }

            state = sw_ext_header;
            dst = p;
            size = 4;
            break;

        case sw_ext_header:
            if (p[0] == 0 && p[1] == 0 && ctx->host.data == NULL) {
                /* SNI extension */
                state = sw_sni_len;
                dst = p;
                size = 2;
                break;
            }

            if (p[0] == 0 && p[1] == 16 && ctx->alpn.data == NULL) {
                /* ALPN extension */
                state = sw_alpn_len;
                dst = p;
                size = 2;
                break;
            }

            if (p[0] == 0 && p[1] == 43) {
                /* supported_versions extension */
                state = sw_supver_len;
                dst = p;
                size = 1;
                break;
            }

            state = sw_ext;
            dst = NULL;
            size = (p[2] << 8) + p[3];
            break;

        case sw_sni_len:
            ext = (p[0] << 8) + p[1];
            state = sw_sni_host_head;
            dst = p;
            size = 3;
            break;

        case sw_sni_host_head:
            if (p[0] != 0) {
                njt_log_debug0(NJT_LOG_DEBUG_STREAM, ctx->log, 0,
                               "ssl preread: SNI hostname type is not DNS");
                return NJT_DECLINED;
            }

            size = (p[1] << 8) + p[2];

            if (ext < 3 + size) {
                njt_log_debug0(NJT_LOG_DEBUG_STREAM, ctx->log, 0,
                               "ssl preread: SNI format error");
                return NJT_DECLINED;
            }
            ext -= 3 + size;

            ctx->host.data = njt_pnalloc(ctx->pool, size);
            if (ctx->host.data == NULL) {
                return NJT_ERROR;
            }

            state = sw_sni_host;
            dst = ctx->host.data;
            break;

        case sw_sni_host:
            ctx->host.len = (p[1] << 8) + p[2];

            njt_log_debug1(NJT_LOG_DEBUG_STREAM, ctx->log, 0,
                           "ssl preread: SNI hostname \"%V\"", &ctx->host);

            state = sw_ext;
            dst = NULL;
            size = ext;
            break;

        case sw_alpn_len:
            ext = (p[0] << 8) + p[1];

            ctx->alpn.data = njt_pnalloc(ctx->pool, ext);
            if (ctx->alpn.data == NULL) {
                return NJT_ERROR;
            }

            state = sw_alpn_proto_len;
            dst = p;
            size = 1;
            break;

        case sw_alpn_proto_len:
            size = p[0];

            if (size == 0) {
                njt_log_debug0(NJT_LOG_DEBUG_STREAM, ctx->log, 0,
                               "ssl preread: ALPN empty protocol");
                return NJT_DECLINED;
            }

            if (ext < 1 + size) {
                njt_log_debug0(NJT_LOG_DEBUG_STREAM, ctx->log, 0,
                               "ssl preread: ALPN format error");
                return NJT_DECLINED;
            }
            ext -= 1 + size;

            state = sw_alpn_proto_data;
            dst = ctx->alpn.data + ctx->alpn.len;
            break;

        case sw_alpn_proto_data:
            ctx->alpn.len += p[0];

            njt_log_debug1(NJT_LOG_DEBUG_STREAM, ctx->log, 0,
                           "ssl preread: ALPN protocols \"%V\"", &ctx->alpn);

            if (ext && ctx->alpn.data != NULL) {
                ctx->alpn.data[ctx->alpn.len++] = ',';

                state = sw_alpn_proto_len;
                dst = p;
                size = 1;
                break;
            }

            state = sw_ext;
            dst = NULL;
            size = 0;
            break;

        case sw_supver_len:
            njt_log_debug0(NJT_LOG_DEBUG_STREAM, ctx->log, 0,
                           "ssl preread: supported_versions");

            /* set TLSv1.3 */
            ctx->version[0] = 3;
            ctx->version[1] = 4;

            state = sw_ext;
            dst = NULL;
            size = p[0];
            break;
        }

        if (left < size) {
            njt_log_debug0(NJT_LOG_DEBUG_STREAM, ctx->log, 0,
                           "ssl preread: failed to parse handshake");
            return NJT_DECLINED;
        }
    }

    ctx->state = state;
    ctx->size = size;
    ctx->left = left;
    ctx->ext = ext;
    ctx->dst = dst;

    return NJT_AGAIN;
}


static njt_int_t
njt_stream_ssl_preread_protocol_variable(njt_stream_session_t *s,
    njt_variable_value_t *v, uintptr_t data)
{
    njt_str_t                      version;
    njt_stream_ssl_preread_ctx_t  *ctx;

    ctx = njt_stream_get_module_ctx(s, njt_stream_ssl_preread_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NJT_OK;
    }

    /* SSL_get_version() format */

    njt_str_null(&version);

    switch (ctx->version[0]) {
    case 0:
        switch (ctx->version[1]) {
        case 2:
            njt_str_set(&version, "SSLv2");
            break;
        }
        break;
    case 3:
        switch (ctx->version[1]) {
        case 0:
            njt_str_set(&version, "SSLv3");
            break;
        case 1:
            njt_str_set(&version, "TLSv1");
            break;
        case 2:
            njt_str_set(&version, "TLSv1.1");
            break;
        case 3:
            njt_str_set(&version, "TLSv1.2");
            break;
        case 4:
            njt_str_set(&version, "TLSv1.3");
            break;
        }
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = version.len;
    v->data = version.data;

    return NJT_OK;
}


static njt_int_t
njt_stream_ssl_preread_server_name_variable(njt_stream_session_t *s,
    njt_variable_value_t *v, uintptr_t data)
{
    njt_stream_ssl_preread_ctx_t  *ctx;

    ctx = njt_stream_get_module_ctx(s, njt_stream_ssl_preread_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NJT_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = ctx->host.len;
    v->data = ctx->host.data;

    return NJT_OK;
}


static njt_int_t
njt_stream_ssl_preread_alpn_protocols_variable(njt_stream_session_t *s,
    njt_variable_value_t *v, uintptr_t data)
{
    njt_stream_ssl_preread_ctx_t  *ctx;

    ctx = njt_stream_get_module_ctx(s, njt_stream_ssl_preread_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NJT_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = ctx->alpn.len;
    v->data = ctx->alpn.data;

    return NJT_OK;
}


static njt_int_t
njt_stream_ssl_preread_add_variables(njt_conf_t *cf)
{
    njt_stream_variable_t  *var, *v;

    for (v = njt_stream_ssl_preread_vars; v->name.len; v++) {
        var = njt_stream_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NJT_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NJT_OK;
}


static void *
njt_stream_ssl_preread_create_srv_conf(njt_conf_t *cf)
{
    njt_stream_ssl_preread_srv_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_stream_ssl_preread_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enabled = NJT_CONF_UNSET;

    return conf;
}


static char *
njt_stream_ssl_preread_merge_srv_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_stream_ssl_preread_srv_conf_t *prev = parent;
    njt_stream_ssl_preread_srv_conf_t *conf = child;

    njt_conf_merge_value(conf->enabled, prev->enabled, 0);

    return NJT_CONF_OK;
}


static njt_int_t
njt_stream_ssl_preread_init(njt_conf_t *cf)
{
    njt_stream_handler_pt        *h;
    njt_stream_core_main_conf_t  *cmcf;

    cmcf = njt_stream_conf_get_module_main_conf(cf, njt_stream_core_module);

    h = njt_array_push(&cmcf->phases[NJT_STREAM_PREREAD_PHASE].handlers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_stream_ssl_preread_handler;

    return NJT_OK;
}
