
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


static njt_int_t njt_http_static_handler(njt_http_request_t *r);
static njt_int_t njt_http_static_init(njt_conf_t *cf);


static njt_http_module_t  njt_http_static_module_ctx = {
    NULL,                                  /* preconfiguration */
    njt_http_static_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


njt_module_t  njt_http_static_module = {
    NJT_MODULE_V1,
    &njt_http_static_module_ctx,           /* module context */
    NULL,                                  /* module directives */
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
njt_http_static_handler(njt_http_request_t *r)
{
    u_char                    *last, *location;
    size_t                     root, len;
    uintptr_t                  escape;
    njt_str_t                  path;
    njt_int_t                  rc;
    njt_uint_t                 level;
    njt_log_t                 *log;
    njt_buf_t                 *b;
    njt_chain_t                out;
    njt_open_file_info_t       of;
    njt_http_core_loc_conf_t  *clcf;

    if (!(r->method & (NJT_HTTP_GET|NJT_HTTP_HEAD|NJT_HTTP_POST))) {
        return NJT_HTTP_NOT_ALLOWED;
    }

    if (r->uri.data[r->uri.len - 1] == '/') {
        return NJT_DECLINED;
    }

    log = r->connection->log;

    /*
     * njt_http_map_uri_to_path() allocates memory for terminating '\0'
     * so we do not need to reserve memory for '/' for possible redirect
     */

    last = njt_http_map_uri_to_path(r, &path, &root, 0);
    if (last == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    path.len = last - path.data;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, log, 0,
                   "http filename: \"%s\"", path.data);

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

    r->root_tested = !r->error_page;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, log, 0, "http static fd: %d", of.fd);

    if (of.is_dir) {

        njt_log_debug0(NJT_LOG_DEBUG_HTTP, log, 0, "http dir");

        njt_http_clear_location(r);

        r->headers_out.location = njt_list_push(&r->headers_out.headers);
        if (r->headers_out.location == NULL) {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        escape = 2 * njt_escape_uri(NULL, r->uri.data, r->uri.len,
                                    NJT_ESCAPE_URI);

        if (!clcf->alias && r->args.len == 0 && escape == 0) {
            len = r->uri.len + 1;
            location = path.data + root;

            *last = '/';

        } else {
            len = r->uri.len + escape + 1;

            if (r->args.len) {
                len += r->args.len + 1;
            }

            location = njt_pnalloc(r->pool, len);
            if (location == NULL) {
                njt_http_clear_location(r);
                return NJT_HTTP_INTERNAL_SERVER_ERROR;
            }

            if (escape) {
                last = (u_char *) njt_escape_uri(location, r->uri.data,
                                                 r->uri.len, NJT_ESCAPE_URI);

            } else {
                last = njt_copy(location, r->uri.data, r->uri.len);
            }

            *last = '/';

            if (r->args.len) {
                *++last = '?';
                njt_memcpy(++last, r->args.data, r->args.len);
            }
        }

        r->headers_out.location->hash = 1;
        r->headers_out.location->next = NULL;
        njt_str_set(&r->headers_out.location->key, "Location");
        r->headers_out.location->value.len = len;
        r->headers_out.location->value.data = location;

        return NJT_HTTP_MOVED_PERMANENTLY;
    }

#if !(NJT_WIN32) /* the not regular files are probably Unix specific */

    if (!of.is_file) {
        njt_log_error(NJT_LOG_CRIT, log, 0,
                      "\"%s\" is not a regular file", path.data);

        return NJT_HTTP_NOT_FOUND;
    }

#endif

    if (r->method == NJT_HTTP_POST) {
        return NJT_HTTP_NOT_ALLOWED;
    }

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


static njt_int_t
njt_http_static_init(njt_conf_t *cf)
{
    njt_http_handler_pt        *h;
    njt_http_core_main_conf_t  *cmcf;

    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);

    h = njt_array_push(&cmcf->phases[NJT_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_http_static_handler;

    return NJT_OK;
}
