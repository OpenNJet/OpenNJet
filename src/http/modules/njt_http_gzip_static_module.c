
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


#define NJT_HTTP_GZIP_STATIC_OFF     0
#define NJT_HTTP_GZIP_STATIC_ON      1
#define NJT_HTTP_GZIP_STATIC_ALWAYS  2


typedef struct {
    njt_uint_t  enable;
} njt_http_gzip_static_conf_t;


static njt_int_t njt_http_gzip_static_handler(njt_http_request_t *r);
static void *njt_http_gzip_static_create_conf(njt_conf_t *cf);
static char *njt_http_gzip_static_merge_conf(njt_conf_t *cf, void *parent,
    void *child);
static njt_int_t njt_http_gzip_static_init(njt_conf_t *cf);


static njt_conf_enum_t  njt_http_gzip_static[] = {
    { njt_string("off"), NJT_HTTP_GZIP_STATIC_OFF },
    { njt_string("on"), NJT_HTTP_GZIP_STATIC_ON },
    { njt_string("always"), NJT_HTTP_GZIP_STATIC_ALWAYS },
    { njt_null_string, 0 }
};


static njt_command_t  njt_http_gzip_static_commands[] = {

    { njt_string("gzip_static"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_enum_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_gzip_static_conf_t, enable),
      &njt_http_gzip_static },

      njt_null_command
};


static njt_http_module_t  njt_http_gzip_static_module_ctx = {
    NULL,                                  /* preconfiguration */
    njt_http_gzip_static_init,             /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_gzip_static_create_conf,      /* create location configuration */
    njt_http_gzip_static_merge_conf        /* merge location configuration */
};


njt_module_t  njt_http_gzip_static_module = {
    NJT_MODULE_V1,
    &njt_http_gzip_static_module_ctx,      /* module context */
    njt_http_gzip_static_commands,         /* module directives */
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


static njt_int_t
njt_http_gzip_static_handler(njt_http_request_t *r)
{
    u_char                       *p;
    size_t                        root;
    njt_str_t                     path;
    njt_int_t                     rc;
    njt_uint_t                    level;
    njt_log_t                    *log;
    njt_buf_t                    *b;
    njt_chain_t                   out;
    njt_table_elt_t              *h;
    njt_open_file_info_t          of;
    njt_http_core_loc_conf_t     *clcf;
    njt_http_gzip_static_conf_t  *gzcf;

    if (!(r->method & (NJT_HTTP_GET|NJT_HTTP_HEAD))) {
        return NJT_DECLINED;
    }

    if (r->uri.data[r->uri.len - 1] == '/') {
        return NJT_DECLINED;
    }

    gzcf = njt_http_get_module_loc_conf(r, njt_http_gzip_static_module);

    if (gzcf->enable == NJT_HTTP_GZIP_STATIC_OFF) {
        return NJT_DECLINED;
    }

    if (gzcf->enable == NJT_HTTP_GZIP_STATIC_ON) {
        rc = njt_http_gzip_ok(r);

    } else {
        /* always */
        rc = NJT_OK;
    }

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    if (!clcf->gzip_vary && rc != NJT_OK) {
        return NJT_DECLINED;
    }

    log = r->connection->log;

    p = njt_http_map_uri_to_path(r, &path, &root, sizeof(".gz") - 1);
    if (p == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    *p++ = '.';
    *p++ = 'g';
    *p++ = 'z';
    *p = '\0';

    path.len = p - path.data;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, log, 0,
                   "http filename: \"%s\"", path.data);

    njt_memzero(&of, sizeof(njt_open_file_info_t));

    of.read_ahead = clcf->read_ahead;
    of.directio = clcf->directio;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;

    if (njt_http_set_disable_symlinks(r, clcf, &path, &of) != NJT_OK) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (njt_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
        != NJT_OK)
    {
        switch (of.err) {

        case 0:
            return NJT_HTTP_INTERNAL_SERVER_ERROR;

        case NJT_ENOENT:
        case NJT_ENOTDIR:
        case NJT_ENAMETOOLONG:

            return NJT_DECLINED;

        case NJT_EACCES:
#if (NJT_HAVE_OPENAT)
        case NJT_EMLINK:
        case NJT_ELOOP:
#endif

            level = NJT_LOG_ERR;
            break;

        default:

            level = NJT_LOG_CRIT;
            break;
        }

        njt_log_error(level, log, of.err,
                      "%s \"%s\" failed", of.failed, path.data);

        return NJT_DECLINED;
    }

    if (gzcf->enable == NJT_HTTP_GZIP_STATIC_ON) {
        r->gzip_vary = 1;

        if (rc != NJT_OK) {
            return NJT_DECLINED;
        }
    }

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, log, 0, "http static fd: %d", of.fd);

    if (of.is_dir) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, log, 0, "http dir");
        return NJT_DECLINED;
    }

#if !(NJT_WIN32) /* the not regular files are probably Unix specific */

    if (!of.is_file) {
        njt_log_error(NJT_LOG_CRIT, log, 0,
                      "\"%s\" is not a regular file", path.data);

        return NJT_HTTP_NOT_FOUND;
    }

#endif

    r->root_tested = !r->error_page;

    rc = njt_http_discard_request_body(r);

    if (rc != NJT_OK) {
        return rc;
    }

    log->action = "sending response to client";

    r->headers_out.status = NJT_HTTP_OK;
    r->headers_out.content_length_n = of.size;
    r->headers_out.last_modified_time = of.mtime;

    if (njt_http_set_etag(r) != NJT_OK) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (njt_http_set_content_type(r) != NJT_OK) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    h = njt_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    h->hash = 1;
    h->next = NULL;
    njt_str_set(&h->key, "Content-Encoding");
    njt_str_set(&h->value, "gzip");
    r->headers_out.content_encoding = h;

    r->allow_ranges = 1;

    /* we need to allocate all before the header would be sent */

    b = njt_calloc_buf(r->pool);
    if (b == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->file = njt_pcalloc(r->pool, sizeof(njt_file_t));
    if (b->file == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = njt_http_send_header(r);

    if (rc == NJT_ERROR || rc > NJT_OK || r->header_only) {
        return rc;
    }

    b->file_pos = 0;
    b->file_last = of.size;

    b->in_file = b->file_last ? 1 : 0;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;
    b->sync = (b->last_buf || b->in_file) ? 0 : 1;

    b->file->fd = of.fd;
    b->file->name = path;
    b->file->log = log;
    b->file->directio = of.is_directio;

    out.buf = b;
    out.next = NULL;

    return njt_http_output_filter(r, &out);
}


static void *
njt_http_gzip_static_create_conf(njt_conf_t *cf)
{
    njt_http_gzip_static_conf_t  *conf;

    conf = njt_palloc(cf->pool, sizeof(njt_http_gzip_static_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NJT_CONF_UNSET_UINT;

    return conf;
}


static char *
njt_http_gzip_static_merge_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_gzip_static_conf_t *prev = parent;
    njt_http_gzip_static_conf_t *conf = child;

    njt_conf_merge_uint_value(conf->enable, prev->enable,
                              NJT_HTTP_GZIP_STATIC_OFF);

    return NJT_CONF_OK;
}


static njt_int_t
njt_http_gzip_static_init(njt_conf_t *cf)
{
    njt_http_handler_pt        *h;
    njt_http_core_main_conf_t  *cmcf;

    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);

    h = njt_array_push(&cmcf->phases[NJT_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_http_gzip_static_handler;

    return NJT_OK;
}
