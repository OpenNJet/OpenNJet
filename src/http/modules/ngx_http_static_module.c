
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static ngx_int_t ngx_http_static_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_static_init(ngx_conf_t *cf);


static ngx_http_module_t  ngx_http_static_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_static_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_static_module = {
    NJET_MODULE_V1,
    &ngx_http_static_module_ctx,           /* module context */
    NULL,                                  /* module directives */
    NJET_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJET_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_static_handler(ngx_http_request_t *r)
{
    u_char                    *last, *location;
    size_t                     root, len;
    uintptr_t                  escape;
    ngx_str_t                  path;
    ngx_int_t                  rc;
    ngx_uint_t                 level;
    ngx_log_t                 *log;
    ngx_buf_t                 *b;
    ngx_chain_t                out;
    ngx_open_file_info_t       of;
    ngx_http_core_loc_conf_t  *clcf;

    if (!(r->method & (NJET_HTTP_GET|NJET_HTTP_HEAD|NJET_HTTP_POST))) {
        return NJET_HTTP_NOT_ALLOWED;
    }

    if (r->uri.data[r->uri.len - 1] == '/') {
        return NJET_DECLINED;
    }

    log = r->connection->log;

    /*
     * ngx_http_map_uri_to_path() allocates memory for terminating '\0'
     * so we do not need to reserve memory for '/' for possible redirect
     */

    last = ngx_http_map_uri_to_path(r, &path, &root, 0);
    if (last == NULL) {
        return NJET_HTTP_INTERNAL_SERVER_ERROR;
    }

    path.len = last - path.data;

    ngx_log_debug1(NJET_LOG_DEBUG_HTTP, log, 0,
                   "http filename: \"%s\"", path.data);

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_memzero(&of, sizeof(ngx_open_file_info_t));

    of.read_ahead = clcf->read_ahead;
    of.directio = clcf->directio;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;

    if (ngx_http_set_disable_symlinks(r, clcf, &path, &of) != NJET_OK) {
        return NJET_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
        != NJET_OK)
    {
        switch (of.err) {

        case 0:
            return NJET_HTTP_INTERNAL_SERVER_ERROR;

        case NJET_ENOENT:
        case NJET_ENOTDIR:
        case NJET_ENAMETOOLONG:

            level = NJET_LOG_ERR;
            rc = NJET_HTTP_NOT_FOUND;
            break;

        case NJET_EACCES:
#if (NJET_HAVE_OPENAT)
        case NJET_EMLINK:
        case NJET_ELOOP:
#endif

            level = NJET_LOG_ERR;
            rc = NJET_HTTP_FORBIDDEN;
            break;

        default:

            level = NJET_LOG_CRIT;
            rc = NJET_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        if (rc != NJET_HTTP_NOT_FOUND || clcf->log_not_found) {
            ngx_log_error(level, log, of.err,
                          "%s \"%s\" failed", of.failed, path.data);
        }

        return rc;
    }

    r->root_tested = !r->error_page;

    ngx_log_debug1(NJET_LOG_DEBUG_HTTP, log, 0, "http static fd: %d", of.fd);

    if (of.is_dir) {

        ngx_log_debug0(NJET_LOG_DEBUG_HTTP, log, 0, "http dir");

        ngx_http_clear_location(r);

        r->headers_out.location = ngx_list_push(&r->headers_out.headers);
        if (r->headers_out.location == NULL) {
            return NJET_HTTP_INTERNAL_SERVER_ERROR;
        }

        escape = 2 * ngx_escape_uri(NULL, r->uri.data, r->uri.len,
                                    NJET_ESCAPE_URI);

        if (!clcf->alias && r->args.len == 0 && escape == 0) {
            len = r->uri.len + 1;
            location = path.data + root;

            *last = '/';

        } else {
            len = r->uri.len + escape + 1;

            if (r->args.len) {
                len += r->args.len + 1;
            }

            location = ngx_pnalloc(r->pool, len);
            if (location == NULL) {
                ngx_http_clear_location(r);
                return NJET_HTTP_INTERNAL_SERVER_ERROR;
            }

            if (escape) {
                last = (u_char *) ngx_escape_uri(location, r->uri.data,
                                                 r->uri.len, NJET_ESCAPE_URI);

            } else {
                last = ngx_copy(location, r->uri.data, r->uri.len);
            }

            *last = '/';

            if (r->args.len) {
                *++last = '?';
                ngx_memcpy(++last, r->args.data, r->args.len);
            }
        }

        r->headers_out.location->hash = 1;
        r->headers_out.location->next = NULL;
        ngx_str_set(&r->headers_out.location->key, "Location");
        r->headers_out.location->value.len = len;
        r->headers_out.location->value.data = location;

        return NJET_HTTP_MOVED_PERMANENTLY;
    }

#if !(NJET_WIN32) /* the not regular files are probably Unix specific */

    if (!of.is_file) {
        ngx_log_error(NJET_LOG_CRIT, log, 0,
                      "\"%s\" is not a regular file", path.data);

        return NJET_HTTP_NOT_FOUND;
    }

#endif

    if (r->method == NJET_HTTP_POST) {
        return NJET_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NJET_OK) {
        return rc;
    }

    log->action = "sending response to client";

    r->headers_out.status = NJET_HTTP_OK;
    r->headers_out.content_length_n = of.size;
    r->headers_out.last_modified_time = of.mtime;

    if (ngx_http_set_etag(r) != NJET_OK) {
        return NJET_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_set_content_type(r) != NJET_OK) {
        return NJET_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (r != r->main && of.size == 0) {
        return ngx_http_send_header(r);
    }

    r->allow_ranges = 1;

    /* we need to allocate all before the header would be sent */

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NJET_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (b->file == NULL) {
        return NJET_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_send_header(r);

    if (rc == NJET_ERROR || rc > NJET_OK || r->header_only) {
        return rc;
    }

    b->file_pos = 0;
    b->file_last = of.size;

    b->in_file = b->file_last ? 1: 0;
    b->last_buf = (r == r->main) ? 1: 0;
    b->last_in_chain = 1;

    b->file->fd = of.fd;
    b->file->name = path;
    b->file->log = log;
    b->file->directio = of.is_directio;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


static ngx_int_t
ngx_http_static_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NJET_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NJET_ERROR;
    }

    *h = ngx_http_static_handler;

    return NJET_OK;
}
