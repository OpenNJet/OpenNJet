
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 * Copyright (C), 2021-2023, TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_VTS_DISPLAY_PROMETHEUS_H_INCLUDED_
#define _NJT_HTTP_VTS_DISPLAY_PROMETHEUS_H_INCLUDED_


#define NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_MAIN                      \
    "# HELP njet_vts_info Njet info\n"                                       \
    "# TYPE njet_vts_info gauge\n"                                            \
    "njet_vts_info{hostname=\"%V\",module_version=\"%s\",version=\"%s\"} 1\n" \
    "# HELP njet_vts_start_time_seconds Njet start time\n"                   \
    "# TYPE njet_vts_start_time_seconds gauge\n"                              \
    "njet_vts_start_time_seconds %.3f\n"                                      \
    "# HELP njet_vts_main_connections Njet connections\n"                    \
    "# TYPE njet_vts_main_connections gauge\n"                                \
    "njet_vts_main_connections{status=\"accepted\"} %uA\n"                    \
    "njet_vts_main_connections{status=\"active\"} %uA\n"                      \
    "njet_vts_main_connections{status=\"handled\"} %uA\n"                     \
    "njet_vts_main_connections{status=\"reading\"} %uA\n"                     \
    "njet_vts_main_connections{status=\"requests\"} %uA\n"                    \
    "njet_vts_main_connections{status=\"waiting\"} %uA\n"                     \
    "njet_vts_main_connections{status=\"writing\"} %uA\n"                     \
    "# HELP njet_vts_main_shm_usage_bytes Shared memory [%V] info\n"          \
    "# TYPE njet_vts_main_shm_usage_bytes gauge\n"                            \
    "njet_vts_main_shm_usage_bytes{shared=\"max_size\"} %ui\n"                \
    "njet_vts_main_shm_usage_bytes{shared=\"used_size\"} %ui\n"               \
    "njet_vts_main_shm_usage_bytes{shared=\"used_node\"} %ui\n"

#define NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_S                  \
    "# HELP njet_vts_server_bytes_total The request/response bytes\n"         \
    "# TYPE njet_vts_server_bytes_total counter\n"                            \
    "# HELP njet_vts_server_requests_total The requests counter\n"            \
    "# TYPE njet_vts_server_requests_total counter\n"                         \
    "# HELP njet_vts_server_request_seconds_total The request processing "    \
    "time in seconds\n"                                                        \
    "# TYPE njet_vts_server_request_seconds_total counter\n"                  \
    "# HELP njet_vts_server_request_seconds The average of request "          \
    "processing times in seconds\n"                                            \
    "# TYPE njet_vts_server_request_seconds gauge\n"                          \
    "# HELP njet_vts_server_request_duration_seconds The histogram of "       \
    "request processing time\n"                                                \
    "# TYPE njet_vts_server_request_duration_seconds histogram\n"

#define NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER                    \
    "njet_vts_server_bytes_total{host=\"%V\",direction=\"in\"} %uA\n"         \
    "njet_vts_server_bytes_total{host=\"%V\",direction=\"out\"} %uA\n"        \
    "njet_vts_server_requests_total{host=\"%V\",code=\"1xx\"} %uA\n"          \
    "njet_vts_server_requests_total{host=\"%V\",code=\"2xx\"} %uA\n"          \
    "njet_vts_server_requests_total{host=\"%V\",code=\"3xx\"} %uA\n"          \
    "njet_vts_server_requests_total{host=\"%V\",code=\"4xx\"} %uA\n"          \
    "njet_vts_server_requests_total{host=\"%V\",code=\"5xx\"} %uA\n"          \
    "njet_vts_server_request_seconds_total{host=\"%V\"} %.3f\n"               \
    "njet_vts_server_request_seconds{host=\"%V\"} %.3f\n"

#define NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_HISTOGRAM_BUCKET   \
    "njet_vts_server_request_duration_seconds_bucket{host=\"%V\","            \
    "le=\"%.3f\"} %uA\n"

#define NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_HISTOGRAM_BUCKET_E \
    "njet_vts_server_request_duration_seconds_bucket{host=\"%V\","            \
    "le=\"+Inf\"} %uA\n"

#define NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_HISTOGRAM_SUM      \
    "njet_vts_server_request_duration_seconds_sum{host=\"%V\"} %.3f\n"

#define NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_HISTOGRAM_COUNT    \
    "njet_vts_server_request_duration_seconds_count{host=\"%V\"} %uA\n"

#if (NJT_HTTP_CACHE)
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_CACHE_S            \
    "# HELP njet_vts_server_cache_total The requests cache counter\n"         \
    "# TYPE njet_vts_server_cache_total counter\n"
 
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_CACHE              \
    "njet_vts_server_cache_total{host=\"%V\",status=\"miss\"} %uA\n"          \
    "njet_vts_server_cache_total{host=\"%V\",status=\"bypass\"} %uA\n"        \
    "njet_vts_server_cache_total{host=\"%V\",status=\"expired\"} %uA\n"       \
    "njet_vts_server_cache_total{host=\"%V\",status=\"stale\"} %uA\n"         \
    "njet_vts_server_cache_total{host=\"%V\",status=\"updating\"} %uA\n"      \
    "njet_vts_server_cache_total{host=\"%V\",status=\"revalidated\"} %uA\n"   \
    "njet_vts_server_cache_total{host=\"%V\",status=\"hit\"} %uA\n"           \
    "njet_vts_server_cache_total{host=\"%V\",status=\"scarce\"} %uA\n"
#endif

#define NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_S                  \
    "# HELP njet_vts_filter_bytes_total The request/response bytes\n"         \
    "# TYPE njet_vts_filter_bytes_total counter\n"                            \
    "# HELP njet_vts_filter_requests_total The requests counter\n"            \
    "# TYPE njet_vts_filter_requests_total counter\n"                         \
    "# HELP njet_vts_filter_request_seconds_total The request processing "    \
    "time in seconds counter\n"                                                \
    "# TYPE njet_vts_filter_request_seconds_total counter\n"                  \
    "# HELP njet_vts_filter_request_seconds The average of request "          \
    "processing times in seconds\n"                                            \
    "# TYPE njet_vts_filter_request_seconds gauge\n"                          \
    "# HELP njet_vts_filter_request_duration_seconds The histogram of "       \
    "request processing time\n"                                                \
    "# TYPE njet_vts_filter_request_duration_seconds histogram\n"

#define NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER                    \
    "njet_vts_filter_bytes_total{filter=\"%V\",filter_name=\"%V\","           \
    "direction=\"in\"} %uA\n"                                                  \
    "njet_vts_filter_bytes_total{filter=\"%V\",filter_name=\"%V\","           \
    "direction=\"out\"} %uA\n"                                                 \
    "njet_vts_filter_requests_total{filter=\"%V\",filter_name=\"%V\","        \
    "code=\"1xx\"} %uA\n"                                                      \
    "njet_vts_filter_requests_total{filter=\"%V\",filter_name=\"%V\","        \
    "code=\"2xx\"} %uA\n"                                                      \
    "njet_vts_filter_requests_total{filter=\"%V\",filter_name=\"%V\","        \
    "code=\"3xx\"} %uA\n"                                                      \
    "njet_vts_filter_requests_total{filter=\"%V\",filter_name=\"%V\","        \
    "code=\"4xx\"} %uA\n"                                                      \
    "njet_vts_filter_requests_total{filter=\"%V\",filter_name=\"%V\","        \
    "code=\"5xx\"} %uA\n"                                                      \
    "njet_vts_filter_request_seconds_total{filter=\"%V\","                    \
    "filter_name=\"%V\"} %.3f\n"                                               \
    "njet_vts_filter_request_seconds{filter=\"%V\",filter_name=\"%V\"} %.3f\n"

#define NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_HISTOGRAM_BUCKET   \
    "njet_vts_filter_request_duration_seconds_bucket{filter=\"%V\","          \
    "filter_name=\"%V\",le=\"%.3f\"} %uA\n"

#define NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_HISTOGRAM_BUCKET_E \
    "njet_vts_filter_request_duration_seconds_bucket{filter=\"%V\","          \
    "filter_name=\"%V\",le=\"+Inf\"} %uA\n"

#define NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_HISTOGRAM_SUM      \
    "njet_vts_filter_request_duration_seconds_sum{filter=\"%V\","             \
    "filter_name=\"%V\"} %.3f\n"

#define NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_HISTOGRAM_COUNT    \
    "njet_vts_filter_request_duration_seconds_count{filter=\"%V\","           \
    "filter_name=\"%V\"} %uA\n"

#if (NJT_HTTP_CACHE)
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_CACHE_S            \
    "# HELP njet_vts_filter_cache_total The requests cache counter\n"         \
    "# TYPE njet_vts_filter_cache_total counter\n"
 
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_CACHE              \
    "njet_vts_filter_cache_total{filter=\"%V\",filter_name=\"%V\","           \
    "status=\"miss\"} %uA\n"                                                   \
    "njet_vts_filter_cache_total{filter=\"%V\",filter_name=\"%V\","           \
    "status=\"bypass\"} %uA\n"                                                 \
    "njet_vts_filter_cache_total{filter=\"%V\",filter_name=\"%V\","           \
    "status=\"expired\"} %uA\n"                                                \
    "njet_vts_filter_cache_total{filter=\"%V\",filter_name=\"%V\","           \
    "status=\"stale\"} %uA\n"                                                  \
    "njet_vts_filter_cache_total{filter=\"%V\",filter_name=\"%V\","           \
    "status=\"updating\"} %uA\n"                                               \
    "njet_vts_filter_cache_total{filter=\"%V\",filter_name=\"%V\","           \
    "status=\"revalidated\"} %uA\n"                                            \
    "njet_vts_filter_cache_total{filter=\"%V\",filter_name=\"%V\","           \
    "status=\"hit\"} %uA\n"                                                    \
    "njet_vts_filter_cache_total{filter=\"%V\",filter_name=\"%V\","           \
    "status=\"scarce\"} %uA\n"
#endif

#define NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_S                \
    "# HELP njet_vts_upstream_bytes_total The request/response bytes\n"       \
    "# TYPE njet_vts_upstream_bytes_total counter\n"                          \
    "# HELP njet_vts_upstream_requests_total The upstream requests counter\n" \
    "# TYPE njet_vts_upstream_requests_total counter\n"                       \
    "# HELP njet_vts_upstream_request_seconds_total The request Processing "  \
    "time including upstream in seconds\n"                                     \
    "# TYPE njet_vts_upstream_request_seconds_total counter\n"                \
    "# HELP njet_vts_upstream_request_seconds The average of request "        \
    "processing times including upstream in seconds\n"                         \
    "# TYPE njet_vts_upstream_request_seconds gauge\n"                        \
    "# HELP njet_vts_upstream_response_seconds_total The only upstream "      \
    "response processing time in seconds\n"                                    \
    "# TYPE njet_vts_upstream_response_seconds_total counter\n"               \
    "# HELP njet_vts_upstream_response_seconds The average of only "          \
    "upstream response processing times in seconds\n"                          \
    "# TYPE njet_vts_upstream_response_seconds gauge\n"                       \
    "# HELP njet_vts_upstream_request_duration_seconds The histogram of "     \
    "request processing time including upstream\n"                             \
    "# TYPE njet_vts_upstream_request_duration_seconds histogram\n"           \
    "# HELP njet_vts_upstream_response_duration_seconds The histogram of "    \
    "only upstream response processing time\n"                                 \
    "# TYPE njet_vts_upstream_response_duration_seconds histogram\n"

#define NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_HDR_S                \
    "# HELP njet_vts_upstream_hdr Upstream HDR\n"       \
    "# TYPE njet_vts_upstream_hdr gauge\n"                          

#define NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_HDR              \
    "njet_vts_upstream_hdr{code=\"p50reqdelayMsecr\"} %uA\n"                   \
    "njet_vts_upstream_hdr{code=\"p99reqdelayMsecr\"} %uA\n"                   \
    "njet_vts_upstream_hdr{code=\"p999reqdelayMsecr\"} %uA\n"                  \
    "njet_vts_upstream_hdr{code=\"p9999reqdelayMsecr\"} %uA\n"                 \
    "njet_vts_upstream_hdr{code=\"p9999reqdelayMsecr\"} %uA\n"

#define NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM                  \
    "njet_vts_upstream_bytes_total{upstream=\"%V\",backend=\"%V\","           \
    "direction=\"in\"} %uA\n"                                                  \
    "njet_vts_upstream_bytes_total{upstream=\"%V\",backend=\"%V\","           \
    "direction=\"out\"} %uA\n"                                                 \
    "njet_vts_upstream_requests_total{upstream=\"%V\",backend=\"%V\","        \
    "code=\"1xx\"} %uA\n"                                                      \
    "njet_vts_upstream_requests_total{upstream=\"%V\",backend=\"%V\","        \
    "code=\"2xx\"} %uA\n"                                                      \
    "njet_vts_upstream_requests_total{upstream=\"%V\",backend=\"%V\","        \
    "code=\"3xx\"} %uA\n"                                                      \
    "njet_vts_upstream_requests_total{upstream=\"%V\",backend=\"%V\","        \
    "code=\"4xx\"} %uA\n"                                                      \
    "njet_vts_upstream_requests_total{upstream=\"%V\",backend=\"%V\","        \
    "code=\"5xx\"} %uA\n"                                                      \
    "njet_vts_upstream_requests_total{upstream=\"%V\",backend=\"%V\","        \
    "code=\"timeout\"} %uA\n"                                                 \
    "njet_vts_upstream_request_seconds_total{upstream=\"%V\","                \
    "backend=\"%V\"} %.3f\n"                                                   \
    "njet_vts_upstream_request_seconds{upstream=\"%V\","                      \
    "backend=\"%V\"} %.3f\n"                                                   \
    "njet_vts_upstream_response_seconds_total{upstream=\"%V\","               \
    "backend=\"%V\"} %.3f\n"                                                   \
    "njet_vts_upstream_response_seconds{upstream=\"%V\","                     \
    "backend=\"%V\"} %.3f\n"

#define NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_HISTOGRAM_BUCKET \
    "njet_vts_upstream_%V_duration_seconds_bucket{upstream=\"%V\","           \
    "backend=\"%V\",le=\"%.3f\"} %uA\n"

#define                                                                        \
    NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_HISTOGRAM_BUCKET_E   \
    "njet_vts_upstream_%V_duration_seconds_bucket{upstream=\"%V\","           \
    "backend=\"%V\",le=\"+Inf\"} %uA\n"

#define NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_HISTOGRAM_SUM    \
    "njet_vts_upstream_%V_duration_seconds_sum{upstream=\"%V\","              \
    "backend=\"%V\"} %.3f\n"

#define NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_HISTOGRAM_COUNT  \
    "njet_vts_upstream_%V_duration_seconds_count{upstream=\"%V\","            \
    "backend=\"%V\"} %uA\n"


#if (NJT_HTTP_CACHE)
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_CACHE_S                   \
    "# HELP njet_vts_cache_usage_bytes THe cache zones info\n"                \
    "# TYPE njet_vts_cache_usage_bytes gauge\n"                               \
    "# HELP njet_vts_cache_bytes_total The cache zones request/response "     \
    "bytes\n"                                                                  \
    "# TYPE njet_vts_cache_bytes_total counter\n"                             \
    "# HELP njet_vts_cache_requests_total The cache requests counter\n"       \
    "# TYPE njet_vts_cache_requests_total counter\n"

#define NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_CACHE                     \
    "njet_vts_cache_usage_bytes{cache_zone=\"%V\",cache_size=\"max\"} %uA\n"  \
    "njet_vts_cache_usage_bytes{cache_zone=\"%V\",cache_size=\"used\"} %uA\n" \
    "njet_vts_cache_bytes_total{cache_zone=\"%V\",direction=\"in\"} %uA\n"    \
    "njet_vts_cache_bytes_total{cache_zone=\"%V\",direction=\"out\"} %uA\n"   \
    "njet_vts_cache_requests_total{cache_zone=\"%V\",status=\"miss\"} %uA\n"  \
    "njet_vts_cache_requests_total{cache_zone=\"%V\","                        \
    "status=\"bypass\"} %uA\n"                                                 \
    "njet_vts_cache_requests_total{cache_zone=\"%V\","                        \
    "status=\"expired\"} %uA\n"                                                \
    "njet_vts_cache_requests_total{cache_zone=\"%V\","                        \
    "status=\"stale\"} %uA\n"                                                  \
    "njet_vts_cache_requests_total{cache_zone=\"%V\","                        \
    "status=\"updating\"} %uA\n"                                               \
    "njet_vts_cache_requests_total{cache_zone=\"%V\","                        \
    "status=\"revalidated\"} %uA\n"                                            \
    "njet_vts_cache_requests_total{cache_zone=\"%V\",status=\"hit\"} %uA\n"   \
    "njet_vts_cache_requests_total{cache_zone=\"%V\",status=\"scarce\"} %uA\n"
#endif


u_char *njt_http_vhost_traffic_status_display_prometheus_set_main(
    njt_http_request_t *r, u_char *buf);
u_char *njt_http_vhost_traffic_status_display_prometheus_set_server_node(
    njt_http_request_t *r,
    u_char *buf, njt_str_t *key,
    njt_http_vhost_traffic_status_node_t *vtsn);
u_char *njt_http_vhost_traffic_status_display_prometheus_set_server(
    njt_http_request_t *r, u_char *buf,
    njt_rbtree_node_t *node);
u_char *njt_http_vhost_traffic_status_display_prometheus_set_filter_node(
    njt_http_request_t *r,
    u_char *buf, njt_str_t *key,
    njt_http_vhost_traffic_status_node_t *vtsn);
u_char *njt_http_vhost_traffic_status_display_prometheus_set_filter(
    njt_http_request_t *r, u_char *buf,
    njt_rbtree_node_t *node);
u_char *njt_http_vhost_traffic_status_display_prometheus_set_upstream_node(
    njt_http_request_t *r,
    u_char *buf, njt_str_t *key,
    njt_http_vhost_traffic_status_node_t *vtsn);
u_char *njt_http_vhost_traffic_status_display_prometheus_set_upstream(
    njt_http_request_t *r, u_char *buf,
    njt_rbtree_node_t *node);

#if (NJT_HTTP_CACHE)
u_char *njt_http_vhost_traffic_status_display_prometheus_set_cache_node(
    njt_http_request_t *r,
    u_char *buf, njt_str_t *key,
    njt_http_vhost_traffic_status_node_t *vtsn);
u_char *njt_http_vhost_traffic_status_display_prometheus_set_cache(
    njt_http_request_t *r, u_char *buf,
    njt_rbtree_node_t *node);
#endif

u_char *njt_http_vhost_traffic_status_display_prometheus_set(njt_http_request_t *r,
    u_char *buf);


#endif /* _NJT_HTTP_VTS_DISPLAY_PROMETHEUS_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
