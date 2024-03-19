
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#include <njt_config.h>

#include "njt_http_stream_server_traffic_status_module_html.h"
#include "njt_http_stream_server_traffic_status_module.h"
#include "njt_http_stream_server_traffic_status_shm.h"
#include "njt_http_stream_server_traffic_status_display_prometheus.h"
#include "njt_http_stream_server_traffic_status_display_json.h"
#include "njt_http_stream_server_traffic_status_display.h"
#include "njt_http_stream_server_traffic_status_control.h"


static njt_int_t njt_http_stream_server_traffic_status_display_handler(
    njt_http_request_t *r);
static njt_int_t njt_http_stream_server_traffic_status_display_handler_control(
    njt_http_request_t *r);
static njt_int_t njt_http_stream_server_traffic_status_display_handler_default(
    njt_http_request_t *r);


static njt_int_t
njt_http_stream_server_traffic_status_display_handler(njt_http_request_t *r)
{
    size_t                                        len;
    u_char                                       *p;
    njt_int_t                                     rc;
    njt_http_stream_server_traffic_status_ctx_t  *ctx;

    ctx = njt_http_get_module_main_conf(r, njt_stream_stsd_module);

    if (!ctx->enable) {
        return NJT_HTTP_NOT_IMPLEMENTED;
    }

    if (r->method != NJT_HTTP_GET && r->method != NJT_HTTP_HEAD) {
        return NJT_HTTP_NOT_ALLOWED;
    }

    rc = njt_http_stream_server_traffic_status_shm_init(r);
    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "display_handler::shm_init() failed");
        return NJT_HTTP_SERVICE_UNAVAILABLE;
    }

    len = 0;

    p = (u_char *) njt_strchr(r->uri.data, '/');

    if (p) {
        p = (u_char *) njt_strchr(p + 1, '/');
        len = r->uri.len - (p - r->uri.data);
    }

    /* control processing handler */
    if (p && len >= sizeof("/control") - 1) {
        p = r->uri.data + r->uri.len - sizeof("/control") + 1;
        if (njt_strncasecmp(p, (u_char *) "/control", sizeof("/control") - 1) == 0) {
            rc = njt_http_stream_server_traffic_status_display_handler_control(r);
            goto done;
        }
    }

    /* default processing handler */
    rc = njt_http_stream_server_traffic_status_display_handler_default(r);

done:

    return rc;
}


static njt_int_t
njt_http_stream_server_traffic_status_display_handler_control(njt_http_request_t *r)
{
    size_t                                             size;
    njt_int_t                                          rc;
    njt_str_t                                          type, alpha, arg_cmd, arg_group, arg_zone;
    njt_buf_t                                         *b;
    njt_chain_t                                        out;
    njt_slab_pool_t                                   *shpool;
    njt_http_stream_server_traffic_status_ctx_t       *ctx;
    njt_http_stream_server_traffic_status_control_t   *control;
    njt_http_stream_server_traffic_status_loc_conf_t  *stscf;

    ctx = njt_http_get_module_main_conf(r, njt_stream_stsd_module);

    stscf = njt_http_get_module_loc_conf(r, njt_stream_stsd_module);

    /* init control */
    control = njt_pcalloc(r->pool, sizeof(njt_http_stream_server_traffic_status_control_t));
    control->r = r;
    control->command = NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_CONTROL_CMD_NONE;
    control->group = -2;
    control->zone = njt_pcalloc(r->pool, sizeof(njt_str_t));
    control->arg_cmd = &arg_cmd;
    control->arg_group = &arg_group;
    control->arg_zone = &arg_zone;
    control->range = NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_CONTROL_RANGE_NONE;
    control->count = 0;

    arg_cmd.len = 0;
    arg_group.len = 0;
    arg_zone.len = 0;

    if (r->args.len) {

        if (njt_http_arg(r, (u_char *) "cmd", 3, &arg_cmd) == NJT_OK) {

            if (arg_cmd.len == 6 && njt_strncmp(arg_cmd.data, "status", 6) == 0)
            {
                control->command = NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_CONTROL_CMD_STATUS;
            }
            else if (arg_cmd.len == 6 && njt_strncmp(arg_cmd.data, "delete", 6) == 0)
            {
                control->command = NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_CONTROL_CMD_DELETE;
            }
            else if (arg_cmd.len == 5 && njt_strncmp(arg_cmd.data, "reset", 5) == 0)
            {
                control->command = NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_CONTROL_CMD_RESET;
            }
            else
            {
                control->command = NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_CONTROL_CMD_NONE;
            }
        }

        if (njt_http_arg(r, (u_char *) "group", 5, &arg_group) == NJT_OK) {

            if (arg_group.len == 1 && njt_strncmp(arg_group.data, "*", 1) == 0)
            {
                control->group = -1;
            }
            else if (arg_group.len == 6
                     && njt_strncasecmp(arg_group.data, (u_char *) "server", 6) == 0)
            {
                control->group = NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_NO;
            }
            else if (arg_group.len == 14
                     && njt_strncasecmp(arg_group.data, (u_char *) "upstream@alone", 14) == 0)
            {
                control->group = NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_UA;
            }
            else if (arg_group.len == 14
                     && njt_strncasecmp(arg_group.data, (u_char *) "upstream@group", 14) == 0)
            {
                control->group = NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_UG;
            }
            else if (arg_group.len == 6
                     && njt_strncasecmp(arg_group.data, (u_char *) "filter", 6) == 0)
            {
                control->group = NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_FG;
            }
            else {
                control->command = NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_CONTROL_CMD_NONE;
            }
        }

        if (njt_http_arg(r, (u_char *) "zone", 4, &arg_zone) != NJT_OK) {
            if (control->group != -1) {
                control->command = NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_CONTROL_CMD_NONE;
            }

        } else {
            rc = njt_http_stream_server_traffic_status_copy_str(r->pool, control->zone, &arg_zone);
            if (rc != NJT_OK) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "display_handler_control::copy_str() failed");
            }

            (void) njt_http_stream_server_traffic_status_replace_chrc(control->zone, '@',
                       NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_KEY_SEPARATOR);

            njt_str_set(&alpha, "[:alpha:]");

            rc = njt_http_stream_server_traffic_status_replace_strc(control->zone, &alpha, '@');
            if (rc != NJT_OK) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "display_handler_control::replace_strc() failed");
            }
        }

        njt_http_stream_server_traffic_status_node_control_range_set(control);
    }

    if (control->command == NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_CONTROL_CMD_STATUS) {
        size = ctx->shm_size;

    } else {
        size = sizeof(NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_CONTROL)
               + arg_cmd.len + arg_group.len + arg_zone.len + 256;
    }

    njt_str_set(&type, "application/json");

    r->headers_out.content_type_len = type.len;
    r->headers_out.content_type = type;

    if (r->method == NJT_HTTP_HEAD) {
        r->headers_out.status = NJT_HTTP_OK;

        rc = njt_http_send_header(r);

        if (rc == NJT_ERROR || rc > NJT_OK || r->header_only) {
            return rc;
        }
    }

    b = njt_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    control->buf = &b->last;

    shpool = (njt_slab_pool_t *) stscf->shm_zone->shm.addr;

    njt_shmtx_lock(&shpool->mutex);

    switch (control->command) {

    case NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_CONTROL_CMD_STATUS:
        njt_http_stream_server_traffic_status_node_status(control);
        break;

    case NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_CONTROL_CMD_DELETE:
        njt_http_stream_server_traffic_status_node_delete(control);
        break;

    case NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_CONTROL_CMD_RESET:
        njt_http_stream_server_traffic_status_node_reset(control);
        break;

    default:
        *control->buf = njt_sprintf(*control->buf,
                                    NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_CONTROL,
                                    njt_http_stream_server_traffic_status_boolean_to_string(0),
                                    control->arg_cmd, control->arg_group,
                                    control->arg_zone, control->count);
        break;
    }

    njt_shmtx_unlock(&shpool->mutex);

    if (b->last == b->pos) {
        b->last = njt_sprintf(b->last, "{}");
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


static njt_int_t
njt_http_stream_server_traffic_status_display_handler_default(njt_http_request_t *r)
{
    size_t                                             len;
    u_char                                            *o, *s;
    njt_str_t                                          uri, type;
    njt_int_t                                          size, format, rc;
    njt_buf_t                                         *b;
    njt_chain_t                                        out;
    njt_slab_pool_t                                   *shpool;
    njt_http_stream_server_traffic_status_ctx_t       *ctx;
    njt_http_stream_server_traffic_status_loc_conf_t  *stscf;

    ctx = njt_http_get_module_main_conf(r, njt_stream_stsd_module);

    stscf = njt_http_get_module_loc_conf(r, njt_stream_stsd_module);

    if (!ctx->enable) {
        return NJT_HTTP_NOT_IMPLEMENTED;
    }

    if (r->method != NJT_HTTP_GET && r->method != NJT_HTTP_HEAD) {
        return NJT_HTTP_NOT_ALLOWED;
    }

    uri = r->uri;

    format = NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_FORMAT_NONE;

    if (uri.len == 1) {
        if (njt_strncmp(uri.data, "/", 1) == 0) {
            uri.len = 0;
        }
    }

    o = (u_char *) r->uri.data;
    s = o;

    len = r->uri.len;

    while(sizeof("/format/type") - 1 <= len) {
        if (njt_strncasecmp(s, (u_char *) "/format/", sizeof("/format/") - 1) == 0) {
            uri.data = o;
            uri.len = (o == s) ? 0 : (size_t) (s - o);

            s += sizeof("/format/") - 1;

            if (njt_strncasecmp(s, (u_char *) "jsonp", sizeof("jsonp") - 1) == 0) {
                format = NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_FORMAT_JSONP;

            } else if (njt_strncasecmp(s, (u_char *) "json", sizeof("json") - 1) == 0) {
                format = NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_FORMAT_JSON;

            } else if (njt_strncasecmp(s, (u_char *) "html", sizeof("html") - 1) == 0) {
                format = NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_FORMAT_HTML;

            } else if (njt_strncasecmp(s, (u_char *) "prometheus", sizeof("prometheus") - 1) == 0) {
                format = NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_FORMAT_PROMETHEUS;

            } else {
                s -= 2;
            }

            if (format != NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_FORMAT_NONE) {
                break;
            }
        }

        if ((s = (u_char *) njt_strchr(++s, '/')) == NULL) {
            break;
        }

        if (r->uri.len <= (size_t) (s - o)) {
            break;
        }

        len = r->uri.len - (size_t) (s - o);
    }

    format = (format == NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_FORMAT_NONE) ? stscf->format : format;

    rc = njt_http_discard_request_body(r);
    if (rc != NJT_OK) {
        return rc;
    }

    if (format == NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_FORMAT_JSON) {
        njt_str_set(&type, "application/json");

    } else if (format == NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_FORMAT_JSONP) {
        njt_str_set(&type, "application/javascript");

    } else if (format == NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_FORMAT_PROMETHEUS) {
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

    size = njt_http_stream_server_traffic_status_display_get_size(r, format);
    if (size == NJT_ERROR) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "display_handler_default::display_get_size() failed");
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    b = njt_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (format == NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_FORMAT_JSON) {
        shpool = (njt_slab_pool_t *) stscf->shm_zone->shm.addr;
        njt_shmtx_lock(&shpool->mutex);
        b->last = njt_http_stream_server_traffic_status_display_set(r, b->last);
        njt_shmtx_unlock(&shpool->mutex);

        if (b->last == b->pos) {
            b->last = njt_sprintf(b->last, "{}");
        }

    } else if (format == NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_FORMAT_JSONP) {
        shpool = (njt_slab_pool_t *) stscf->shm_zone->shm.addr;
        njt_shmtx_lock(&shpool->mutex);
        b->last = njt_sprintf(b->last, "%V", &stscf->jsonp);
        b->last = njt_sprintf(b->last, "(");
        b->last = njt_http_stream_server_traffic_status_display_set(r, b->last);
        b->last = njt_sprintf(b->last, ")");
        njt_shmtx_unlock(&shpool->mutex);

    } else if (format == NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_FORMAT_PROMETHEUS) {
        shpool = (njt_slab_pool_t *) stscf->shm_zone->shm.addr;
        njt_shmtx_lock(&shpool->mutex);
        b->last = njt_http_stream_server_traffic_status_display_prometheus_set(r, b->last);
        njt_shmtx_unlock(&shpool->mutex);

        if (b->last == b->pos) {
            b->last = njt_sprintf(b->last, "#");
        }

    } else {
        b->last = njt_sprintf(b->last, NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_HTML_DATA, &uri, &uri);
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


njt_int_t
njt_http_stream_server_traffic_status_display_get_upstream_nelts(njt_http_request_t *r) 
{
    njt_uint_t                                    i, j, n;
    njt_stream_upstream_server_t                 *us;
#if (NJT_STREAM_UPSTREAM_ZONE)
    njt_stream_upstream_rr_peer_t                *peer;
    njt_stream_upstream_rr_peers_t               *peers;
#endif
    njt_stream_upstream_srv_conf_t               *uscf, **uscfp;
    njt_stream_upstream_main_conf_t              *umcf;
    njt_http_stream_server_traffic_status_ctx_t  *ctx;

    ctx = njt_http_get_module_main_conf(r, njt_stream_stsd_module);
    umcf = ctx->upstream;
    uscfp = umcf->upstreams.elts;

    for (i = 0, j = 0, n = 0; i < umcf->upstreams.nelts; i++) {

        uscf = uscfp[i];

        /* groups */
        if (uscf->servers && !uscf->port) {
            us = uscf->servers->elts;

#if (NJT_HTTP_UPSTREAM_ZONE)
            if (uscf->shm_zone == NULL) {
                goto not_supported;
            }   

            peers = uscf->peer.data;

            njt_http_upstream_rr_peers_rlock(peers);

            for (peer = peers->peer; peer; peer = peer->next) {
                n++;
            }   

            njt_http_upstream_rr_peers_unlock(peers);

not_supported:

#endif

            for (j = 0; j < uscf->servers->nelts; j++) {
                n += us[j].naddrs;
            }
        }   
    }   

    return n;
}


njt_int_t
njt_http_stream_server_traffic_status_display_get_size(njt_http_request_t *r,
    njt_int_t format)
{
    njt_uint_t                                         size, un;
    njt_slab_pool_t                                   *shpool;
    njt_http_stream_server_traffic_status_loc_conf_t  *stscf;
    njt_http_stream_server_traffic_status_shm_info_t  *shm_info;

    stscf = njt_http_get_module_loc_conf(r, njt_stream_stsd_module);
    shpool = (njt_slab_pool_t *) stscf->shm_zone->shm.addr;

    shm_info = njt_pcalloc(r->pool, sizeof(njt_http_stream_server_traffic_status_shm_info_t));
    if (shm_info == NULL) {
        return NJT_ERROR;
    }

    /* Caveat: Do not use duplicate njt_shmtx_lock() before this function. */
    njt_shmtx_lock(&shpool->mutex);

    njt_http_stream_server_traffic_status_shm_info(r, shm_info);

    njt_shmtx_unlock(&shpool->mutex);

    /* allocate memory for the upstream groups even if upstream node not exists */
    un = shm_info->used_node
         + (njt_uint_t) njt_http_stream_server_traffic_status_display_get_upstream_nelts(r);

    size = 0;

    switch (format) {

    case NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_FORMAT_JSON:
    case NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_FORMAT_JSONP:
        size = sizeof(njt_http_stream_server_traffic_status_node_t) / NJT_PTR_SIZE
               * NJT_ATOMIC_T_LEN * un  /* values size */
               + (un * 1024)            /* names  size */
               + 4096;                  /* main   size */
        break;

    case NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_FORMAT_HTML:
        size = sizeof(NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_HTML_DATA) + njt_pagesize;
        break;
    }

    if (size <= 0) {
        size = shm_info->max_size;
    }

    njt_log_debug3(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "sts::display_get_size(): size[%ui] used_size[%ui], used_node[%ui]",
                   size, shm_info->used_size, shm_info->used_node);

    return size;
}


u_char *
njt_http_stream_server_traffic_status_display_get_time_queue(
    njt_http_request_t *r,
    njt_http_stream_server_traffic_status_node_time_queue_t *q,
    njt_uint_t offset
    )
{
    u_char     *p, *s;
    njt_int_t   i;

    if (q->front == q->rear) {
        return (u_char *) "";
    }

    p = njt_pcalloc(r->pool, q->len * NJT_INT_T_LEN);

    s = p;

    for (i = q->front; i != q->rear; i = (i + 1) % q->len) {
        s = njt_sprintf(s, "%M,", *((njt_msec_t *) ((char *) &(q->times[i]) + offset)));
    }

    if (s > p) {
       *(s - 1) = '\0';
    }

    return p;
}


u_char *
njt_http_stream_server_traffic_status_display_get_time_queue_times(
    njt_http_request_t *r,
    njt_http_stream_server_traffic_status_node_time_queue_t *q)
{
    return njt_http_stream_server_traffic_status_display_get_time_queue(r, q,
               offsetof(njt_http_stream_server_traffic_status_node_time_t, time));
}


u_char *
njt_http_stream_server_traffic_status_display_get_time_queue_msecs(
    njt_http_request_t *r,
    njt_http_stream_server_traffic_status_node_time_queue_t *q)
{
    return njt_http_stream_server_traffic_status_display_get_time_queue(r, q,
               offsetof(njt_http_stream_server_traffic_status_node_time_t, msec));
}


u_char *
njt_http_stream_server_traffic_status_display_get_histogram_bucket(
    njt_http_request_t *r,
    njt_http_stream_server_traffic_status_node_histogram_bucket_t *b,
    njt_uint_t offset,
    const char *fmt)
{
    char        *dst;
    u_char      *p, *s;
    njt_uint_t   i, n;

    n = b->len;

    if (n == 0) {
        return (u_char *) "";
    }

    p = njt_pcalloc(r->pool, n * NJT_INT_T_LEN);
    if (p == NULL) {
        return (u_char *) "";
    }

    s = p;

    for (i = 0; i < n; i++) {
        dst = (char *) &(b->buckets[i]) + offset;

        if (njt_strncmp(fmt, "%M", 2) == 0) {
            s = njt_sprintf(s, fmt, *((njt_msec_t *) dst));

        } else if (njt_strncmp(fmt, "%uA", 3) == 0) {
            s = njt_sprintf(s, fmt, *((njt_atomic_uint_t *) dst));
        }
    }

    if (s > p) {
       *(s - 1) = '\0';
    }

    return p;
}


u_char *
njt_http_stream_server_traffic_status_display_get_histogram_bucket_msecs(
    njt_http_request_t *r,
    njt_http_stream_server_traffic_status_node_histogram_bucket_t *b)
{
    return njt_http_stream_server_traffic_status_display_get_histogram_bucket(r, b,
               offsetof(njt_http_stream_server_traffic_status_node_histogram_t, msec), "%M,");
}


u_char *
njt_http_stream_server_traffic_status_display_get_histogram_bucket_counters(
    njt_http_request_t *r,
    njt_http_stream_server_traffic_status_node_histogram_bucket_t *b)
{
    return njt_http_stream_server_traffic_status_display_get_histogram_bucket(r, b,
               offsetof(njt_http_stream_server_traffic_status_node_histogram_t, counter), "%uA,");
}


char *
njt_http_stream_server_traffic_status_display(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_core_loc_conf_t  *clcf;

    clcf = njt_http_conf_get_module_loc_conf(cf, njt_http_core_module);
    clcf->handler = njt_http_stream_server_traffic_status_display_handler;

    return NJT_CONF_OK;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
