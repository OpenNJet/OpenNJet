
/*
 * Copyright (C), 2021-2024, TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>
#include "njt_http_shm_status_module.h"
#include "njt_http_shm_status_module_html.h"
#include "njt_http_shm_status_display_json.h"
#include "njt_http_shm_status_display_prometheus.h"

static njt_int_t njt_http_shm_status_display_handler(njt_http_request_t *r);
static njt_int_t njt_http_shm_status_display_handler_default(njt_http_request_t *r);
extern njt_cycle_t *njet_master_cycle;

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


njt_uint_t njt_http_shm_status_display_http_upstream_peer_count(){
    njt_uint_t              http_peer_count = 0;

    //calc all stream peer count
    njt_uint_t                      i;
    njt_http_upstream_main_conf_t   *umcf;
    njt_http_upstream_srv_conf_t    *uscf;
    njt_http_upstream_srv_conf_t    **uscfp;
    njt_http_upstream_rr_peers_t    *peers = NULL;
    njt_http_upstream_rr_peer_t     *peer;
    njt_http_upstream_rr_peers_t    *backup;
    
    umcf = njt_http_cycle_get_module_main_conf(njet_master_cycle ,
        njt_http_upstream_module);
    
    if(umcf != NULL && umcf->upstreams.nelts > 0){
        uscfp = umcf->upstreams.elts;
        //add all http upstream server state
        for (i = 0; i < umcf->upstreams.nelts; i++) {
            uscf = uscfp[i];
            if(uscf == NULL){
                continue;
            }

            peers = (njt_http_upstream_rr_peers_t *)uscf->peer.data;
            if(peers == NULL || !(peers->shpool)){
                continue;
            }
            njt_http_upstream_rr_peers_rlock(peers);
            
            //upstream name use uscf->host
            //loop peers
            for (peer = peers->peer; peer != NULL; peer = peer->next) {
                http_peer_count++;
            }
        
            backup = peers->next;
            if (backup != NULL) {
                for (peer = backup->peer; peer != NULL; peer = peer->next) {
                    http_peer_count++;
                }
            }
        
            njt_http_upstream_rr_peers_unlock(peers);
        }
    }

    return http_peer_count;
}


njt_uint_t njt_http_shm_status_display_stream_upstream_peer_count(){
    njt_uint_t              stream_peer_count = 0;

    //calc all stream peer count
    njt_uint_t                      i;
    njt_stream_upstream_main_conf_t   *umcf;
    njt_stream_upstream_srv_conf_t    *uscf;
    njt_stream_upstream_srv_conf_t    **uscfp;
    njt_stream_upstream_rr_peers_t    *peers = NULL;
    njt_stream_upstream_rr_peer_t     *peer;
    njt_stream_upstream_rr_peers_t    *backup;
    
    umcf = njt_stream_cycle_get_module_main_conf(njet_master_cycle ,
        njt_stream_upstream_module);
    
    if(umcf != NULL && umcf->upstreams.nelts > 0){
        uscfp = umcf->upstreams.elts;
        //add all stream upstream server state
        for (i = 0; i < umcf->upstreams.nelts; i++) {
            uscf = uscfp[i];
            if(uscf == NULL){
                continue;
            }

            peers = (njt_stream_upstream_rr_peers_t *)uscf->peer.data;
            if(peers == NULL || !(peers->shpool)){
                continue;
            }
            njt_stream_upstream_rr_peers_rlock(peers);
            
            //upstream name use uscf->host
            //loop peers
            for (peer = peers->peer; peer != NULL; peer = peer->next) {
                stream_peer_count++;
            }
        
            backup = peers->next;
            if (backup != NULL) {
                for (peer = backup->peer; peer != NULL; peer = peer->next) {
                    stream_peer_count++;
                }
            }
        
            njt_stream_upstream_rr_peers_unlock(peers);
        }
    }

    return stream_peer_count;
}


njt_int_t
njt_http_shm_status_display_get_size(njt_http_request_t *r,
    njt_int_t format)
{
    njt_http_shm_status_main_conf_t *sscf;
    njt_uint_t                      size, zone_count, pool_count;
    njt_uint_t                      stream_peer_count;
    njt_uint_t                      http_peer_count;

    size = 0;

    if (njt_shm_status_summary == NULL) {
        return NJT_ERROR;
    }

    sscf = (njt_http_shm_status_main_conf_t *)njt_get_conf(njt_cycle->conf_ctx, njt_http_shm_status_module);

    njt_shmtx_lock(&njt_shm_status_pool->mutex);
    zone_count = njt_shm_status_summary->total_zone_counts;
    pool_count = njt_shm_status_summary->total_dyn_zone_pool_counts
                 + njt_shm_status_summary->total_static_zone_pool_counts;
    njt_shmtx_unlock(&njt_shm_status_pool->mutex);

    switch (format) {
    case NJT_HTTP_SHM_STATUS_FORMAT_JSON:
    case NJT_HTTP_SHM_STATUS_FORMAT_JSONP:
        size = zone_count * 256 + pool_count * 10 * 128 + 4096;

        //add cpu and mem info of
        if(sscf != NULL){
            size += 20 + 20;
            size += sscf->sys_info.process_count * (20 + 20 + 20);
        }

        break;

    case NJT_HTTP_SHM_STATUS_FORMAT_PROMETHEUS:
        // 这里需要重新计算长度
        size = zone_count * 256 + pool_count * 10 * 128 + 4096;

        //add cpu and mem info of
        if(sscf != NULL){
            size += 20 + 20;
            size += sscf->sys_info.process_count * (20 + 20 + 20);
        }

        break;
    case NJT_HTTP_SHM_STATUS_FORMAT_HTML:
        // 这里需要重新计算长度
        size = sizeof(NJT_HTTP_SHM_STATUS_HTML_DATA) + njt_pagesize;
        break;

    default:
        break;
    }

    //add all peer state size
    //add all stream peer state size
    stream_peer_count = njt_http_shm_status_display_stream_upstream_peer_count();
    http_peer_count = njt_http_shm_status_display_http_upstream_peer_count();

    size += (stream_peer_count + http_peer_count) * (256 + 30 + 10);
    //add all http peer state size 

    return size;
}

static njt_int_t
njt_http_shm_status_display_handler_default(njt_http_request_t *r)
{
    size_t                                     len;
    u_char                                    *o, *s, *p;
    size_t                                     olen;
    njt_str_t                                  uri, euri, type;
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

    // if (format != NJT_HTTP_SHM_STATUS_FORMAT_JSON && format != NJT_HTTP_SHM_STATUS_FORMAT_PROMETHEUS) {
    //     njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
    //                   "only json or prometheus format is supported now");
    //     return NJT_HTTP_INTERNAL_SERVER_ERROR;
    // }

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
        // njt_shm_status_print_all();

        if (b->last == b->pos) {
            b->last = njt_sprintf(b->last, "{}");
        }

    } else if (format == NJT_HTTP_SHM_STATUS_FORMAT_JSONP) {
        shpool = njt_shm_status_pool;
        njt_shmtx_lock(&shpool->mutex);
        b->last = njt_sprintf(b->last, "%s", NJT_HTTP_SHM_STATUS_DEFAULT_JSONP);
        b->last = njt_sprintf(b->last, "(");
        b->last = njt_http_shm_status_display_set(r, b->last);
        b->last = njt_sprintf(b->last, ")");
        njt_shmtx_unlock(&shpool->mutex);

    } else if (format == NJT_HTTP_SHM_STATUS_FORMAT_PROMETHEUS) {
        shpool = njt_shm_status_pool;
        njt_shmtx_lock(&shpool->mutex);
        b->last = njt_http_shm_status_display_prometheus_set(r, b->last);
        njt_shmtx_unlock(&shpool->mutex);

        if (b->last == b->pos) {
            b->last = njt_sprintf(b->last, "#");
        }

    } else {
        euri = uri;
        len = njt_escape_html(NULL, uri.data, uri.len);

        if (len) {
            p = njt_pnalloc(r->pool, uri.len + len);
            if (p == NULL) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "display_handler_default::njt_pnalloc() failed");
                return NJT_HTTP_INTERNAL_SERVER_ERROR;
            }

            (void) njt_escape_html(p, uri.data, uri.len);
            euri.data = p;
            euri.len = uri.len + len;
        }


        b->last = njt_sprintf(b->last, NJT_HTTP_SHM_STATUS_HTML_DATA, &euri, &euri);
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
