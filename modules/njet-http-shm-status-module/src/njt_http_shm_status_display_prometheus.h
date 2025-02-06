
/*
 * Copyright (C), 2021-2024, TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_SHM_STATUS_DISPLAY_PROMETHEUS_H_INCLUDED_
#define _NJT_HTTP_SHM_STATUS_DISPLAY_PROMETHEUS_H_INCLUDED_

#include <njt_http.h>

#define NJT_HTTP_SHM_STATUS_PROMETHEUS_FMT_MAIN                     \
    "# HELP njet_shm_status_info NJet info\n"                       \
    "# TYPE njet_shm_status_info gauge\n"                           \
    "njet_sts_info{hostname=\"%V\",version=\"%s\"} 1\n"             \
    "# HELP njet_shm_total NJet SHM summary \n"                     \
    "# TYPE njet_shm_total gauge\n"                                 \
    "njet_shm_total{type=\"zone_count\"} %ui\n"                     \
    "njet_shm_total{type=\"static_zone_count\"} %ui\n"              \
    "njet_shm_total{type=\"static_zone_pool_count\"} %ui\n"         \
    "njet_shm_total{type=\"static_zone_pages\"} %ui\n"              \
    "njet_shm_total{type=\"static_zone_used_pages\"} %ui\n"         \
    "njet_shm_total{type=\"dynamic_pages\"} %ui\n"                  \
    "njet_shm_total{type=\"dynamic_used_pages\"} %ui\n"             \
    "njet_shm_total{type=\"dynamic_zone_count\"} %ui\n"             \
    "njet_shm_total{type=\"dynamic_zone_pool_count\"} %ui\n"        \
    "njet_shm_total{type=\"dynamic_zone_pages\"} %ui\n"             \
    "njet_shm_total{type=\"dynamic_zone_used_pages\"} %ui\n"



#define NJT_HTTP_SHM_STATUS_PROMETHEUS_FMT_SERVER                                \
    "njet_shm_static_zone_size {name=\"%V\", auto_scale=\"%ui\"} %ui\n"          \
    "njet_shm_static_zone_pool_count {name=\"%V\", auto_scale=\"%ui\"} %ui\n"    \
    "njet_shm_static_zone_total_pages {name=\"%V\", auto_scale=\"%ui\"} %ui\n"   \
    "njet_shm_static_zone_used_pages {name=\"%V\", auto_scale=\"%ui\"} %ui\n"  

#define NJT_HTTP_SHM_STATUS_PROMETHEUS_FMT_DYN_SERVER                             \
    "njet_shm_dynamic_zone_size {name=\"%V\", auto_scale=\"%ui\"} %ui\n"          \
    "njet_shm_dynamic_zone_pool_count {name=\"%V\", auto_scale=\"%ui\"} %ui\n"    \
    "njet_shm_dynamic_zone_total_pages {name=\"%V\", auto_scale=\"%ui\"} %ui\n"   \
    "njet_shm_dynamic_zone_used_pages {name=\"%V\", auto_scale=\"%ui\"} %ui\n"  

#define NJT_HTTP_SHM_STATUS_PROMETHEUS_FMT_SERVER_HEADER                           \
    "# HELP njet_shm_static_zone_size NJet shm static zone size \n"                \
    "# TYPE njet_shm_static_zone_size gauge\n"                                     \
    "# HELP njet_shm_static_zone_pool_count NJet shm static zone pool count \n"    \
    "# TYPE njet_shm_static_zone_pool_count gauge\n"                               \
    "# HELP njet_shm_static_zone_total_pages NJet shm static zone total pages \n"  \
    "# TYPE njet_shm_static_zone_total_pages gauge\n"                              \
    "# HELP njet_shm_static_zone_used_pages NJet shm static zone used pages \n"    \
    "# TYPE njet_shm_static_zone_used_pages gauge\n"                           


#define NJT_HTTP_SHM_STATUS_PROMETHEUS_FMT_DYN_SERVER_HEADER          \
    "# HELP njet_shm_dynamic_zone_size NJet shm dynamic zone size \n"                \
    "# TYPE njet_shm_dynamic_zone_size gauge\n"                                      \
    "# HELP njet_shm_dynamic_zone_pool_count NJet shm dynamic zone pool count \n"    \
    "# TYPE njet_shm_dynamic_zone_pool_count gauge\n"                                \
    "# HELP njet_shm_dynamic_zone_total_pages NJet shm dynamic zone total pages \n"  \
    "# TYPE njet_shm_dynamic_zone_total_pages gauge\n"                               \
    "# HELP njet_shm_dynamic_zone_used_pages NJet shm dynamic zone used pages \n"    \
    "# TYPE njet_shm_dynamic_zone_used_pages gauge\n"                           



u_char *njt_http_shm_status_display_prometheus_set(
    njt_http_request_t *r, u_char *buf);
#endif /* _NJT_HTTP_SHM_STATUS_DISPLAY_PROMETHEUS_H_INCLUDED_ */

