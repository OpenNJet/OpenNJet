

/*
 * Copyright (C), 2021-2024, TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_config.h>
#include <njt_core.h>
#include "njt_http_shm_status_module.h"
#include "njt_http_shm_status_display_json.h"
#include <njt_shm_status_module.h>


extern njt_lvlhsh_proto_t  njt_http_shm_status_sysinfo_lvlhsh_proto;

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


u_char *njt_http_shm_status_display_cpu_mem_set(njt_http_shm_status_sysinfo *sysinfo,
    u_char *buf)
{
    njt_str_t                       s_pid;
    njt_uint_t                      i;
    njt_uint_t                      rc;
    njt_lvlhsh_query_t              lhq;
    u_char                          *pid_start, *pid_index;
    njt_str_t                       *pids_v = &sysinfo->old_pids;
    njt_http_shm_status_process_sysinfo *process_sysinfo;

    buf = njt_sprintf(buf, NJT_HTTP_SHM_STATUS_JSON_FMT_SYSINFO_ARRAY_S);

    pid_start = pids_v->data;
    pid_index = pids_v->data;
    for(i = 0; i < pids_v->len; i++){
        if(pids_v->data[i] != '_'){
            pid_index++;
        }else{
            s_pid.data = pid_start;
            s_pid.len = pid_index - pid_start;

            pid_index++;
            pid_start = pid_index;

            lhq.key = s_pid;
            lhq.key_hash = njt_murmur_hash2(lhq.key.data, lhq.key.len);
            lhq.proto = &njt_http_shm_status_sysinfo_lvlhsh_proto;
            lhq.pool = sysinfo->pool;
            //find
            rc = njt_lvlhsh_find(&sysinfo->prev_pids_work, &lhq);
            if(rc == NJT_OK){
                //find
                process_sysinfo = (njt_http_shm_status_process_sysinfo *)lhq.value;
                buf = njt_sprintf(buf, NJT_HTTP_SHM_STATUS_JSON_FMT_SYSINFO_OBJ_S,
                    &process_sysinfo->pid, process_sysinfo->cpu_cpu_usage, process_sysinfo->memory_use*1024);

                buf = njt_sprintf(buf, NJT_HTTP_SHM_STATUS_JSON_FMT_OBJECT_E);
                buf = njt_sprintf(buf, NJT_HTTP_SHM_STATUS_JSON_FMT_NEXT);
            }
        }
    }

    if(sysinfo->process_count > 0){
        buf--;
    }

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
    njt_http_shm_status_main_conf_t           *sscf;


    // request is useless in this func;

    if (njt_shm_status_summary == NULL) {
        return buf;
    }

    sscf = (njt_http_shm_status_main_conf_t *)njt_get_conf(njt_cycle->conf_ctx, njt_http_shm_status_module);

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
                           summary->total_dyn_zone_used_pages,
                           sscf == NULL ? 0:sscf->sys_info.process_total_cpu,
                           sscf == NULL ? 0:sscf->sys_info.process_total_mem*1024);


    //add cpu and mem info of process
    if(sscf){
        buf = njt_http_shm_status_display_cpu_mem_set(&sscf->sys_info, buf);
        buf = njt_sprintf(buf, NJT_HTTP_SHM_STATUS_JSON_FMT_NEXT);
    }

    buf = njt_http_shm_status_display_static_zones_set(&summary->zones, buf);
    buf = njt_sprintf(buf, NJT_HTTP_SHM_STATUS_JSON_FMT_NEXT);
    buf = njt_http_shm_status_display_dyn_zones_set(&summary->dyn_zones, buf);
    
    buf = njt_sprintf(buf, NJT_HTTP_SHM_STATUS_JSON_FMT_E);

    return buf;
}
