
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


static char *njt_http_flv(njt_conf_t *cf, njt_command_t *cmd, void *conf);

static njt_command_t  njt_http_flv_commands[] = {

    { njt_string("flv"),
      NJT_HTTP_LOC_CONF|NJT_CONF_NOARGS,
      njt_http_flv,
      0,
      0,
      NULL },

      njt_null_command
};


static u_char  njt_flv_header[] = "FLV\x1\x5\0\0\0\x9\0\0\0\0";


static njt_http_module_t  njt_http_flv_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    NULL,                          /* create location configuration */
    NULL                           /* merge location configuration */
};


njt_module_t  njt_http_flv_module = {
    NJT_MODULE_V1,
    &njt_http_flv_module_ctx,      /* module context */
    njt_http_flv_commands,         /* module directives */
    NJT_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NJT_MODULE_V1_PADDING
};


static njt_int_t
njt_http_flv_handler(njt_http_request_t *r)
{
    u_char                    *last;
    off_t                      start, len;
    size_t                     root;
    njt_int_t                  rc;
    njt_uint_t                 level, i;
    njt_str_t                  path, value;
    njt_log_t                 *log;
    njt_buf_t                 *b;
    njt_chain_t                out[2];
    njt_open_file_info_t       of;
    njt_http_core_loc_conf_t  *clcf;

    if (!(r->method & (NJT_HTTP_GET|NJT_HTTP_HEAD))) {
        return NJT_HTTP_NOT_ALLOWED;
    }

    if (r->uri.data[r->uri.len - 1] == '/') {
        return NJT_DECLINED;
    }

    rc = njt_http_discard_request_body(r);

    if (rc != NJT_OK) {
        return rc;
    }

    last = njt_http_map_uri_to_path(r, &path, &root, 0);
    if (last == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    log = r->connection->log;

    path.len = last - path.data;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, log, 0,
                   "http flv filename: \"%V\"", &path);

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

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

            level = NJT_LOG_ERR;
            rc = NJT_HTTP_NOT_FOUND;
            break;

        case NJT_EACCES:
#if (NJT_HAVE_OPENAT)
        case NJT_EMLINK:
        case NJT_ELOOP:
#endif

            level = NJT_LOG_ERR;
            rc = NJT_HTTP_FORBIDDEN;
            break;

        default:

            level = NJT_LOG_CRIT;
            rc = NJT_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        if (rc != NJT_HTTP_NOT_FOUND || clcf->log_not_found) {
            njt_log_error(level, log, of.err,
                          "%s \"%s\" failed", of.failed, path.data);
        }

        return rc;
    }

    if (!of.is_file) {
        return NJT_DECLINED;
    }

    r->root_tested = !r->error_page;

    start = 0;
    len = of.size;
    i = 1;

    if (r->args.len) {

        if (njt_http_arg(r, (u_char *) "start", 5, &value) == NJT_OK) {

            start = njt_atoof(value.data, value.len);

            if (start == NJT_ERROR || start >= len) {
                start = 0;
            }

            if (start) {
                len = sizeof(njt_flv_header) - 1 + len - start;
                i = 0;
            }
        }
    }

    log->action = "sending flv to client";

    r->headers_out.status = NJT_HTTP_OK;
    r->headers_out.content_length_n = len;
    r->headers_out.last_modified_time = of.mtime;

    if (njt_http_set_etag(r) != NJT_OK) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (njt_http_set_content_type(r) != NJT_OK) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (i == 0) {
        b = njt_calloc_buf(r->pool);
        if (b == NULL) {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        b->pos = njt_flv_header;
        b->last = njt_flv_header + sizeof(njt_flv_header) - 1;
        b->memory = 1;

        out[0].buf = b;
        out[0].next = &out[1];
    }


    b = njt_calloc_buf(r->pool);
    if (b == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->file = njt_pcalloc(r->pool, sizeof(njt_file_t));
    if (b->file == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->allow_ranges = 1;

    rc = njt_http_send_header(r);

    if (rc == NJT_ERROR || rc > NJT_OK || r->header_only) {
        return rc;
    }

    b->file_pos = start;
    b->file_last = of.size;

    b->in_file = b->file_last ? 1 : 0;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;
    b->sync = (b->last_buf || b->in_file) ? 0 : 1;

    b->file->fd = of.fd;
    b->file->name = path;
    b->file->log = log;
    b->file->directio = of.is_directio;

    out[1].buf = b;
    out[1].next = NULL;

    return njt_http_output_filter(r, &out[i]);
}


static char *
njt_http_flv(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_core_loc_conf_t  *clcf;

    clcf = njt_http_conf_get_module_loc_conf(cf, njt_http_core_module);
    clcf->handler = njt_http_flv_handler;

    return NJT_CONF_OK;
}
