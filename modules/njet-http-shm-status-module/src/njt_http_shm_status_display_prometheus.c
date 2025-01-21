
/*
 * Copyright (C), 2021-2024, TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_config.h>
#include <njt_core.h>
#include "njt_http_shm_status_display_prometheus.h"
#include <njt_shm_status_module.h>


u_char *njt_http_shm_status_display_static_zones_prometheus_set(njt_queue_t *head,
    u_char *buf)
{
    njt_queue_t                               *zone;
    njt_shm_status_zone_record_t              *rec;

    buf = njt_sprintf(buf, NJT_HTTP_SHM_STATUS_PROMETHEUS_FMT_SERVER_HEADER);

    for (zone = njt_queue_next(head); zone!=head; zone = njt_queue_next(zone)) {
        rec = njt_queue_data(zone, njt_shm_status_zone_record_t, queue);
        njt_uint_t autoscale = rec->autoscale;
        buf = njt_sprintf(buf, NJT_HTTP_SHM_STATUS_PROMETHEUS_FMT_SERVER,
                          &rec->name, autoscale, rec->size,
                          &rec->name, autoscale, rec->pool_count,
                          &rec->name, autoscale, rec->total_pages,
                          &rec->name, autoscale, rec->used_pages);
    }

    return buf;
}


u_char *njt_http_shm_status_display_dyn_zones_prometheus_set(njt_queue_t *head,
    u_char *buf)
{
    njt_queue_t                               *zone;
    njt_shm_status_zone_record_t              *rec;

    buf = njt_sprintf(buf, NJT_HTTP_SHM_STATUS_PROMETHEUS_FMT_DYN_SERVER_HEADER);

    for (zone = njt_queue_next(head); zone!=head; zone = njt_queue_next(zone)) {
        rec = njt_queue_data(zone, njt_shm_status_zone_record_t, queue);

        njt_uint_t del = rec->del;
        if (del) {
            continue;
        }

        njt_uint_t autoscale = rec->autoscale;
        buf = njt_sprintf(buf, NJT_HTTP_SHM_STATUS_PROMETHEUS_FMT_DYN_SERVER,
                          &rec->name, autoscale, rec->size,
                          &rec->name, autoscale, rec->pool_count,
                          &rec->name, autoscale, rec->total_pages,
                          &rec->name, autoscale, rec->used_pages);
    }

    return buf;
}


u_char *njt_http_shm_status_display_prometheus_set(njt_http_request_t *r,
    u_char *buf)
{
    njt_shm_status_summary_t                  *summary;

    // request is useless in this func;
    if (njt_shm_status_summary == NULL) {
        return buf;
    }

    summary = njt_shm_status_summary;
    buf = njt_sprintf(buf, NJT_HTTP_SHM_STATUS_PROMETHEUS_FMT_MAIN,
                           &njt_cycle->hostname, NJT_VERSION,
                           summary->total_zone_counts,
                           summary->total_static_zone_counts,
                           summary->total_static_zone_pool_counts,
                           summary->total_static_zone_pages,
                           summary->total_static_zone_used_pages,
                           summary->total_dyn_pages,
                           summary->total_used_dyn_pages,
                           summary->total_dyn_zone_counts,
                           summary->total_dyn_zone_pool_counts,
                           summary->total_dyn_zone_pages,
                           summary->total_dyn_zone_used_pages);


    buf = njt_http_shm_status_display_static_zones_prometheus_set(&summary->zones, buf);
    buf = njt_http_shm_status_display_dyn_zones_prometheus_set(&summary->dyn_zones, buf);

    return buf;
}