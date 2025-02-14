
/*
 * Copyright (C), 2021-2024, TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_config.h>
#include <njt_core.h>
#include "njt_http_shm_status_module.h"
#include "njt_http_shm_status_display_prometheus.h"
#include <njt_shm_status_module.h>

extern njt_lvlhsh_proto_t  njt_http_shm_status_sysinfo_lvlhsh_proto;

u_char *njt_http_shm_status_display_sysinfo_prometheus_set(njt_http_shm_status_sysinfo *sysinfo,
    u_char *buf)
{
    njt_str_t                       s_pid;
    njt_uint_t                      i;
    njt_uint_t                      rc;
    njt_lvlhsh_query_t              lhq;
    u_char                          *pid_start, *pid_index;
    njt_str_t                       *pids_v = &sysinfo->old_pids;
    njt_http_shm_status_process_sysinfo *process_sysinfo;

    buf = njt_sprintf(buf, NJT_HTTP_SHM_STATUS_PROMETHEUS_FMT_SYSINFO_HEADER);

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
                buf = njt_sprintf(buf, NJT_HTTP_SHM_STATUS_PROMETHEUS_FMT_SYSINFO,
                    &process_sysinfo->pid,
                    process_sysinfo->cpu_cpu_usage,
                    &process_sysinfo->pid,
                    process_sysinfo->memory_use);
            }
        }
    }


    return buf;
}


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
    njt_http_shm_status_main_conf_t           *sscf;

    // request is useless in this func;
    if (njt_shm_status_summary == NULL) {
        return buf;
    }

    sscf = (njt_http_shm_status_main_conf_t *)njt_get_conf(njt_cycle->conf_ctx, njt_http_shm_status_module);

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
                           summary->total_dyn_zone_used_pages,
                           sscf == NULL ? 0:sscf->sys_info.process_total_cpu,
                           sscf == NULL ? 0:sscf->sys_info.process_total_mem);

    if(sscf != NULL){
        buf = njt_http_shm_status_display_sysinfo_prometheus_set(&sscf->sys_info, buf);
    }

    buf = njt_http_shm_status_display_static_zones_prometheus_set(&summary->zones, buf);
    buf = njt_http_shm_status_display_dyn_zones_prometheus_set(&summary->dyn_zones, buf);

    return buf;
}