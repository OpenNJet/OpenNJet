
/*
 * Copyright (C), 2021-2024, TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_SHM_STATUS_DISPLAY_JSON_H_INCLUDED_
#define _NJT_HTTP_SHM_STATUS_DISPLAY_JSON_H_INCLUDED_

#include <njt_http.h>

#define NJT_HTTP_SHM_STATUS_JSON_FMT_S           "{"
#define NJT_HTTP_SHM_STATUS_JSON_FMT_OBJECT_S    "\"%V\":{"
#define NJT_HTTP_SHM_STATUS_JSON_FMT_ARRAY_S     "\"%V\":["

#define NJT_HTTP_SHM_STATUS_JSON_FMT_ARRAY_E     "]"
#define NJT_HTTP_SHM_STATUS_JSON_FMT_OBJECT_E    "}"
#define NJT_HTTP_SHM_STATUS_JSON_FMT_E           "}"
#define NJT_HTTP_SHM_STATUS_JSON_FMT_NEXT        ","

#define NJT_HTTP_SHM_STATUS_JSON_FMT_SUMMARY "\"total_zone_count\":%ui,"         \
    "\"total_static_zone_count\":%ui,"                                           \
    "\"total_static_zone_pool_count\":%ui,"                                      \
    "\"total_static_zone_pages\":%ui,"                                           \
    "\"total_static_zone_used_pages\":%ui,"                                      \
    "\"total_dyn_pages\":%ui,"                                                   \
    "\"total_dyn_used_pages\":%ui,"                                              \
    "\"total_dyn_zone_count\":%ui,"                                              \
    "\"total_dyn_zone_pool_count\":%ui,"                                         \
    "\"total_dyn_zone_pages\":%ui,"                                              \
    "\"total_dyn_zone_used_pages\":%ui,"                                         \
    "\"total_cpu_usage\":%ui,"                                                   \
    "\"total_memory_usage\":%ui"                                                 \
    ","

#define NJT_HTTP_SHM_STATUS_JSON_FMT_SYSINFO_ARRAY_S "\"sysinfo\":["
#define NJT_HTTP_SHM_STATUS_JSON_FMT_ZONE_ARRAY_S "\"static_zones\":["
#define NJT_HTTP_SHM_STATUS_JSON_FMT_DYN_ZONE_ARRAY_S "\"dyn_zones\":["
#define NJT_HTTP_SHM_STATUS_JSON_FMT_ZONE_OBJ_S "{\"name\":\"%V\","              \
    "\"size\":%ui,"                                                              \
    "\"pool_count\":%ui,"                                                        \
    "\"total_pages\":%ui,"                                                       \
    "\"used_pages\":%ui,"                                                        \
    "\"auto_scale\":%ui,"

#define NJT_HTTP_SHM_STATUS_JSON_FMT_SYSINFO_OBJ_S "{\"pid\":\"%V\","            \
    "\"cpu_usage\":%ui,"                                                         \
    "\"memory_usage\":%ui"

#define NJT_HTTP_SHM_STATUS_JSON_FMT_DYN_ZONE_OBJ_S "{\"name\":\"%V\","          \
    "\"size\":%ui,"                                                              \
    "\"pool_count\":%ui,"                                                        \
    "\"total_pages\":%ui,"                                                       \
    "\"used_pages\":%ui,"                                                        \
    "\"marked_del\":%ui,"                                                        \
    "\"auto_scale\":%ui,"

#define NJT_HTTP_SHM_STATUS_JSON_FMT_POOL_ARRAY_S "\"pools\":["
#define NJT_HTTP_SHM_STATUS_JSON_FMT_POOL_OBJ_S "{\"id\": %ui,"                  \
    "\"total_pages\":%ui,"                                                       \
    "\"used_pages\":%ui,"

#define NJT_HTTP_SHM_STATUS_JSON_FMT_SLOTS_OBJ_S "\"slots\":{"
#define NJT_HTTP_SHM_STATUS_JSON_FMT_SLOT_OBJ_S "\"%ui\":{"                      \
    "\"use\":%ui,"                                                               \
    "\"free\":%ui,"                                                              \
    "\"reqs\":%ui,"                                                              \
    "\"fails\":%ui"                                                              \
    "},"    


u_char *njt_http_shm_status_display_set(njt_http_request_t *r,
    u_char *buf);


#endif /* _NJT_HTTP_SHM_STATUS_DISPLAY_JSON_H_INCLUDED_ */
