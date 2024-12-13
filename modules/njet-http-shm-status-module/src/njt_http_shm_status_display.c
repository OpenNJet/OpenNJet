
/*
 * Copyright (C), 2021-2024, TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_config.h>
#include <njt_core.h>
#include "njt_http_shm_status_module.h"
#include "njt_http_shm_status_display_json.h"

static njt_int_t njt_http_shm_status_display_handler(njt_http_request_t *r);
static njt_int_t njt_http_shm_status_display_handler_default(njt_http_request_t *r);


char *
njt_http_shm_status_display(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_core_loc_conf_t  *clcf;


    clcf = njt_http_conf_get_module_loc_conf(cf, njt_http_core_module);
    clcf->handler = njt_http_shm_status_display_handler;

    return NJT_CONF_OK;
}


static njt_int_t
njt_http_shm_status_display_handler(njt_http_request_t *r)
{
    // size_t                                     len;
    // u_char                                    *p;
    njt_int_t                                  rc;


    if (!njt_shm_status_summary) {
        return NJT_HTTP_NOT_IMPLEMENTED;
    }

    if (r->method != NJT_HTTP_GET && r->method != NJT_HTTP_HEAD) {
        return NJT_HTTP_NOT_ALLOWED;
    }

    // len = 0;

    // p = (u_char *) njt_strlchr(r->uri.data, r->uri.data + r->uri.len, '/');

    // if (p) {
        // p = (u_char *) njt_strlchr(p + 1, r->uri.data + r->uri.len, '/');
        // len = r->uri.len - (p - r->uri.data);
    // }

    /* control processing handler */
    // if (p && len >= sizeof("/control") - 1) {
    //     p = r->uri.data + r->uri.len - sizeof("/control") + 1;
    //     if (njt_strncasecmp(p, (u_char *) "/control", sizeof("/control") - 1) == 0) {
    //         rc = njt_http_shm_status_display_handler_control(r);
    //         goto done;
    //     }
    // }

    /* default processing handler */
    rc = njt_http_shm_status_display_handler_default(r);

// done:

    return rc;
}


njt_int_t
njt_http_shm_status_display_get_size(njt_http_request_t *r,
    njt_int_t format)
{
    njt_uint_t        size, zone_count, pool_count;

// name api_dy_server, size 40960, pool counts 1, used_pages 0  mark_delete 0
// slots_2048:, use 0, free 0, reqs 1, fails 0
// "slot_2048":{"use":,"free":,"reqs":,"fails"},
    if (njt_shm_status_summary == NULL) {
        return NJT_ERROR;
    }
    njt_shmtx_lock(&njt_shm_status_pool->mutex);
    zone_count = njt_shm_status_summary->total_zone_counts;
    pool_count = njt_shm_status_summary->total_dyn_zone_pool_counts
                 + njt_shm_status_summary->total_static_zone_pool_counts;
    njt_shmtx_unlock(&njt_shm_status_pool->mutex);
    //        zones               pools               summary, etc
    size = zone_count * 256 + pool_count * 10 * 128 + 4096; 
    return size;
}

static njt_int_t
njt_http_shm_status_display_handler_default(njt_http_request_t *r)
{
    size_t                                     len;
    u_char                                    *o, *s; //, *p;
    size_t                                     olen;
    njt_str_t                                  uri, type;
    njt_int_t                                  size, format, rc;
    njt_buf_t                                 *b;
    njt_chain_t                                out;
    njt_slab_pool_t                           *shpool;
    njt_http_shm_status_loc_conf_t            *sscf;

    sscf = njt_http_get_module_loc_conf(r, njt_http_shm_status_module);

    if (r->method != NJT_HTTP_GET && r->method != NJT_HTTP_HEAD) {
        return NJT_HTTP_NOT_ALLOWED;
    }

    uri = r->uri;

    format = NJT_HTTP_SHM_STATUS_FORMAT_NONE;

    if (uri.len == 1) {
        if (njt_strncmp(uri.data, "/", 1) == 0) {
            uri.len = 0;
        }
    }

    o = (u_char *) r->uri.data;
    olen =  r->uri.len;
    s = o;

    len = r->uri.len;

    while(sizeof("/format/type") - 1 <= len) {
        if (njt_strncasecmp(s, (u_char *) "/format/", sizeof("/format/") - 1) == 0) {
            uri.data = o;
            uri.len = (o == s) ? 0 : (size_t) (s - o);

            s += sizeof("/format/") - 1;

            if (njt_strncasecmp(s, (u_char *) "jsonp", sizeof("jsonp") - 1) == 0) {
                format = NJT_HTTP_SHM_STATUS_FORMAT_JSONP;

            } else if (njt_strncasecmp(s, (u_char *) "json", sizeof("json") - 1) == 0) {
                format = NJT_HTTP_SHM_STATUS_FORMAT_JSON;

            } else if (njt_strncasecmp(s, (u_char *) "html", sizeof("html") - 1) == 0) {
                format = NJT_HTTP_SHM_STATUS_FORMAT_HTML;

            } else if (njt_strncasecmp(s, (u_char *) "prometheus", sizeof("prometheus") - 1) == 0) {
                format = NJT_HTTP_SHM_STATUS_FORMAT_PROMETHEUS;

            } else {
                s -= 2;
            }

            if (format != NJT_HTTP_SHM_STATUS_FORMAT_NONE) {
                break;
            }
        }

        if ((s = (u_char *) njt_strlchr(++s, o + olen, '/')) == NULL) {
            break;
        }

        if (r->uri.len <= (size_t) (s - o)) {
            break;
        }

        len = r->uri.len - (size_t) (s - o);
    }

    format = (format == NJT_HTTP_SHM_STATUS_FORMAT_NONE) ? sscf->format : format;

    if (format != NJT_HTTP_SHM_STATUS_FORMAT_JSON) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "only json format is supported now");
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = njt_http_discard_request_body(r);
    if (rc != NJT_OK) {
        return rc;
    }

    if (format == NJT_HTTP_SHM_STATUS_FORMAT_JSON) {
        njt_str_set(&type, "application/json");

    } else if (format == NJT_HTTP_SHM_STATUS_FORMAT_JSONP) {
        njt_str_set(&type, "application/javascript");

    } else if (format == NJT_HTTP_SHM_STATUS_FORMAT_PROMETHEUS) {
        njt_str_set(&type, "text/plain");

    } else {
        njt_str_set(&type, "text/html");
    }

    r->headers_out.content_type_len = type.len;
    r->headers_out.content_type = type;

    if (r->method == NJT_HTTP_HEAD) {
        r->headers_out.status = NJT_HTTP_OK;

        rc = njt_http_send_header(r);

        if (rc == NJT_ERROR || rc > NJT_OK || r->header_only) {
            return rc;
        }
    }

    size = njt_http_shm_status_display_get_size(r, format);
    if (size == NJT_ERROR) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "display_handler_default::display_get_size() failed");
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    b = njt_create_temp_buf(r->pool, size);
    if (b == NULL) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "display_handler_default::njt_create_temp_buf() failed");
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (format == NJT_HTTP_SHM_STATUS_FORMAT_JSON) {
        shpool = njt_shm_status_pool;
        njt_shmtx_lock(&shpool->mutex);
        b->last = njt_http_shm_status_display_set(r, b->last);
        njt_shmtx_unlock(&shpool->mutex);
        njt_shm_status_print_all();

        if (b->last == b->pos) {
            b->last = njt_sprintf(b->last, "{}");
        }

    // } else if (format == NJT_HTTP_SHM_STATUS_FORMAT_JSONP) {
    //     shpool = (njt_slab_pool_t *) vtscf->shm_zone->shm.addr;
    //     njt_shrwlock_rdlock(&shpool->rwlock);
    //     b->last = njt_sprintf(b->last, "%V", &vtscf->jsonp);
    //     b->last = njt_sprintf(b->last, "(");
    //     b->last = njt_http_vhost_traffic_status_display_set(r, b->last);
    //     b->last = njt_sprintf(b->last, ")");
    //     njt_shrwlock_unlock(&shpool->rwlock);

    // } else if (format == NJT_HTTP_SHM_STATUS_FORMAT_PROMETHEUS) {
    //     shpool = (njt_slab_pool_t *) vtscf->shm_zone->shm.addr;
    //     njt_shrwlock_rdlock(&shpool->rwlock);
    //     b->last = njt_http_vhost_traffic_status_display_prometheus_set(r, b->last);
    //     njt_shrwlock_unlock(&shpool->rwlock);

    //     if (b->last == b->pos) {
    //         b->last = njt_sprintf(b->last, "#");
    //     }

    // }
    // else {
    //     euri = uri;
    //     len = njt_escape_html(NULL, uri.data, uri.len);

    //     if (len) {
    //         p = njt_pnalloc(r->pool, uri.len + len);
    //         if (p == NULL) {
    //             njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
    //                           "display_handler_default::njt_pnalloc() failed");
    //             return NJT_HTTP_INTERNAL_SERVER_ERROR;
    //         }

    //         (void) njt_escape_html(p, uri.data, uri.len);
    //         euri.data = p;
    //         euri.len = uri.len + len;
    //     }

    //     b->last = njt_sprintf(b->last, NJT_HTTP_VHOST_TRAFFIC_STATUS_HTML_DATA, &euri, &euri);
    }

    r->headers_out.status = NJT_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = (r == r->main) ? 1 : 0; /* if subrequest 0 else 1 */
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    rc = njt_http_send_header(r);
    if (rc == NJT_ERROR || rc > NJT_OK || r->header_only) {
        return rc;
    }

    return njt_http_output_filter(r, &out);
}
