

/*
 * Copyright (C), 2021-2024, TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_config.h>
#include <njt_core.h>
#include "njt_http_shm_status_display_json.h"
#include <njt_shm_status_module.h>




u_char *njt_http_shm_status_display_slots_set(njt_shm_status_slot_rec_t *slots,
    u_char *buf)
{
    njt_shm_status_slot_rec_t               rec;
    njt_uint_t                              i;

    buf = njt_sprintf(buf, NJT_HTTP_SHM_STATUS_JSON_FMT_SLOTS_OBJ_S);

    for (i = 0; i < 9; i++) {
        rec = slots[i];
        buf = njt_sprintf(buf, NJT_HTTP_SHM_STATUS_JSON_FMT_SLOT_OBJ_S,
                          8<<i, rec.used, rec.free, rec.reqs, rec.fails);
        // buf = njt_sprintf(buf, NJT_HTTP_SHM_STATUS_JSON_FMT_NEXT);
    }

    buf--; // 9 slots
    buf = njt_sprintf(buf, NJT_HTTP_SHM_STATUS_JSON_FMT_OBJECT_E);
    return buf;
}


u_char *njt_http_shm_status_display_pools_set(njt_queue_t *head,
    u_char *buf)
{
    njt_queue_t                               *pool;
    njt_shm_status_slab_record_t              *rec;
    njt_uint_t                                 count;

    buf = njt_sprintf(buf, NJT_HTTP_SHM_STATUS_JSON_FMT_POOL_ARRAY_S);

    for (pool = njt_queue_next(head), count = 0; pool!=head; pool = njt_queue_next(pool), count++) {
        rec = njt_queue_data(pool, njt_shm_status_slab_record_t, queue);
        buf = njt_sprintf(buf, NJT_HTTP_SHM_STATUS_JSON_FMT_POOL_OBJ_S,
                          count, rec->total_pages, rec->used_pages);
        buf = njt_http_shm_status_display_slots_set(rec->slots, buf);
        buf = njt_sprintf(buf, NJT_HTTP_SHM_STATUS_JSON_FMT_OBJECT_E);
        buf = njt_sprintf(buf, NJT_HTTP_SHM_STATUS_JSON_FMT_NEXT);
    }

    buf--; // at least one pool exists
    buf = njt_sprintf(buf, NJT_HTTP_SHM_STATUS_JSON_FMT_ARRAY_E);
    return buf;
}


u_char *njt_http_shm_status_display_static_zones_set(njt_queue_t *head,
    u_char *buf)
{
    njt_queue_t                               *zone;
    njt_shm_status_zone_record_t              *rec;
    buf = njt_sprintf(buf, NJT_HTTP_SHM_STATUS_JSON_FMT_ZONE_ARRAY_S);

    for (zone = njt_queue_next(head); zone!=head; zone = njt_queue_next(zone)) {
        rec = njt_queue_data(zone, njt_shm_status_zone_record_t, queue);
        njt_uint_t autoscale = rec->autoscale;
        buf = njt_sprintf(buf, NJT_HTTP_SHM_STATUS_JSON_FMT_ZONE_OBJ_S,
                          &rec->name, rec->size, rec->pool_count, rec->total_pages, rec->used_pages, autoscale);
        buf = njt_http_shm_status_display_pools_set(&rec->pools, buf);
        buf = njt_sprintf(buf, NJT_HTTP_SHM_STATUS_JSON_FMT_OBJECT_E);
        buf = njt_sprintf(buf, NJT_HTTP_SHM_STATUS_JSON_FMT_NEXT);
    }


    if (head->next != head) {
        buf--;
    }
    buf = njt_sprintf(buf, NJT_HTTP_SHM_STATUS_JSON_FMT_ARRAY_E);
    return buf;
}


u_char *njt_http_shm_status_display_dyn_zones_set(njt_queue_t *head,
    u_char *buf)
{
    njt_queue_t                               *zone;
    njt_shm_status_zone_record_t              *rec;
    buf = njt_sprintf(buf, NJT_HTTP_SHM_STATUS_JSON_FMT_DYN_ZONE_ARRAY_S);

    for (zone = njt_queue_next(head); zone!=head; zone = njt_queue_next(zone)) {
        rec = njt_queue_data(zone, njt_shm_status_zone_record_t, queue);
        njt_uint_t autoscale = rec->autoscale;
        njt_uint_t del = rec->del;
        buf = njt_sprintf(buf, NJT_HTTP_SHM_STATUS_JSON_FMT_DYN_ZONE_OBJ_S,
                          &rec->name, rec->size, rec->pool_count, 
                          rec->total_pages, rec->used_pages, del, autoscale);
        buf = njt_http_shm_status_display_pools_set(&rec->pools, buf);
        buf = njt_sprintf(buf, NJT_HTTP_SHM_STATUS_JSON_FMT_OBJECT_E);
        buf = njt_sprintf(buf, NJT_HTTP_SHM_STATUS_JSON_FMT_NEXT);
    }

    if (head->next != head) {
        buf--;
    }
    buf = njt_sprintf(buf, NJT_HTTP_SHM_STATUS_JSON_FMT_ARRAY_E);
    return buf;
}


u_char *njt_http_shm_status_display_set(njt_http_request_t *r,
    u_char *buf)
{
    njt_shm_status_summary_t                  *summary;


    // request is useless in this func;

    if (njt_shm_status_summary == NULL) {
        return buf;
    }

    summary = njt_shm_status_summary;
    buf = njt_sprintf(buf, NJT_HTTP_SHM_STATUS_JSON_FMT_S);
    buf = njt_sprintf(buf, NJT_HTTP_SHM_STATUS_JSON_FMT_SUMMARY, 
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


    buf = njt_http_shm_status_display_static_zones_set(&summary->zones, buf);
    buf = njt_sprintf(buf, NJT_HTTP_SHM_STATUS_JSON_FMT_NEXT);
    buf = njt_http_shm_status_display_dyn_zones_set(&summary->dyn_zones, buf);
    
    buf = njt_sprintf(buf, NJT_HTTP_SHM_STATUS_JSON_FMT_E);

    return buf;
}
