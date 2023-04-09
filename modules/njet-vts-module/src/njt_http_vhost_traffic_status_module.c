
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 * Copyright (C), 2021-2023, TMLake(Beijing) Technology Co., Ltd.
 */


#include "njt_http_vhost_traffic_status_module.h"
#include "njt_http_vhost_traffic_status_variables.h"
#include "njt_http_vhost_traffic_status_shm.h"
#include "njt_http_vhost_traffic_status_filter.h"
#include "njt_http_vhost_traffic_status_limit.h"
#include "njt_http_vhost_traffic_status_display.h"
#include "njt_http_vhost_traffic_status_set.h"
#include "njt_http_vhost_traffic_status_dump.h"


njt_msec_int_t
njt_http_vhost_traffic_status_upstream_response_time(njt_http_request_t *r)
{
    njt_uint_t                  i;
    njt_msec_int_t              ms;
    njt_http_upstream_state_t  *state;

    state = r->upstream_states->elts;

    i = 0;
    ms = 0;
    for ( ;; ) {
        if (state[i].status) {

#if !defined(njet_version) || njet_version < 1009001
            ms += (njt_msec_int_t)
                  (state[i].response_sec * 1000 + state[i].response_msec);
#else
            ms += state[i].response_time;
#endif

        }
        if (++i == r->upstream_states->nelts) {
            break;
        }
    }
    return njt_max(ms, 0);
}


njt_msec_int_t
njt_http_vhost_traffic_status_request_time(njt_http_request_t *r)
{
    njt_time_t      *tp;
    njt_msec_int_t   ms;

    tp = njt_timeofday();

    ms = (njt_msec_int_t)
             ((tp->sec - r->start_sec) * 1000 + (tp->msec - r->start_msec));
    return njt_max(ms, 0);
}


njt_msec_t
njt_http_vhost_traffic_status_current_msec(void)
{
    time_t           sec;
    njt_uint_t       msec;
    struct timeval   tv;

    njt_gettimeofday(&tv);

    sec = tv.tv_sec;
    msec = tv.tv_usec / 1000;

    return (njt_msec_t) sec * 1000 + msec;
}


static njt_http_module_t njt_http_vhost_traffic_status_module_ctx = {
    NULL,               /* preconfiguration */
    NULL,               /* postconfiguration */

    NULL,               /* create main configuration */
    NULL,               /* init main configuration */

    NULL,               /* create server configuration */
    NULL,               /* merge server configuration */

    NULL,               /* create location configuration */
    NULL,               /* merge location configuration */
};


njt_module_t njt_http_vts_module = {
    NJT_MODULE_V1,
    &njt_http_vhost_traffic_status_module_ctx,  /* module context */
    NULL,                                       /* module directives */
    NJT_HTTP_MODULE,                            /* module type */
    NULL,                                       /* init master */
    NULL,                                       /* init module */
    NULL,                                       /* init process */
    NULL,                                       /* init thread */
    NULL,                                       /* exit thread */
    NULL,                                       /* exit process */
    NULL,                                       /* exit master */
    NJT_MODULE_V1_PADDING
};

njt_module_t *njt_http_vtsp_module = &njt_http_vts_module;
njt_module_t *njt_http_vtscp_module = NULL;
njt_module_t *njt_http_vtsdp_module = NULL;
njt_flag_t njt_http_vts_enable = 0;
njt_shm_zone_t *njt_http_vts_shm_zone = NULL;
njt_rbtree_t *njt_http_vts_rbtree = NULL;
njt_str_t njt_http_vts_shm_name;
ssize_t njt_http_vts_shm_size;
njt_cycle_t *njt_http_vtsp_cycle;
