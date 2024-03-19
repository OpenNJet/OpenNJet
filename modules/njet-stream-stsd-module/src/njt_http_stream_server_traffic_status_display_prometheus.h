
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#ifndef _NJT_HTTP_STREAM_STS_DISPLAY_PROMETHEUS_H_INCLUDED_
#define _NJT_HTTP_STREAM_STS_DISPLAY_PROMETHEUS_H_INCLUDED_


#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_MAIN              \
    "# HELP njet_sts_info NJet info\n"                                       \
    "# TYPE njet_sts_info gauge\n"                                            \
    "njet_sts_info{hostname=\"%V\",version=\"%s\"} 1\n"                       \
    "# HELP njet_sts_start_time_seconds NJet start time\n"                   \
    "# TYPE njet_sts_start_time_seconds gauge\n"                              \
    "njet_sts_start_time_seconds %.3f\n"                                      \
    "# HELP njet_sts_main_connections NJet connections\n"                    \
    "# TYPE njet_sts_main_connections gauge\n"                                \
    "njet_sts_main_connections{status=\"accepted\"} %uA\n"                    \
    "njet_sts_main_connections{status=\"active\"} %uA\n"                      \
    "njet_sts_main_connections{status=\"handled\"} %uA\n"                     \
    "njet_sts_main_connections{status=\"reading\"} %uA\n"                     \
    "njet_sts_main_connections{status=\"requests\"} %uA\n"                    \
    "njet_sts_main_connections{status=\"waiting\"} %uA\n"                     \
    "njet_sts_main_connections{status=\"writing\"} %uA\n"                     \
    "# HELP njet_sts_main_shm_usage_bytes Shared memory [%V] info\n"          \
    "# TYPE njet_sts_main_shm_usage_bytes gauge\n"                            \
    "njet_sts_main_shm_usage_bytes{shared=\"max_size\"} %ui\n"                \
    "njet_sts_main_shm_usage_bytes{shared=\"used_size\"} %ui\n"               \
    "njet_sts_main_shm_usage_bytes{shared=\"used_node\"} %ui\n"

#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_S          \
    "# HELP njet_sts_server_bytes_total The request/response bytes\n"         \
    "# TYPE njet_sts_server_bytes_total counter\n"                            \
    "# HELP njet_sts_server_connects_total The connects counter\n"            \
    "# TYPE njet_sts_server_connects_total counter\n"                         \
    "# HELP njet_sts_server_session_seconds_total The session duration "      \
    "time\n"                                                                   \
    "# TYPE njet_sts_server_session_seconds_total counter\n"                  \
    "# HELP njet_sts_server_session_seconds The average of session duration " \
    "time in seconds\n"                                                        \
    "# TYPE njet_sts_server_session_seconds gauge\n"                          \
    "# HELP njet_sts_server_session_duration_seconds The histogram of "       \
    "session duration in seconds\n"                                            \
    "# TYPE njet_sts_server_session_duration_seconds histogram\n"

#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER            \
    "njet_sts_server_bytes_total{listen=\"%V\",port=\"%ui\","                 \
    "protocol=\"%V\",direction=\"in\"} %uA\n"                                  \
    "njet_sts_server_bytes_total{listen=\"%V\",port=\"%ui\","                 \
    "protocol=\"%V\",direction=\"out\"} %uA\n"                                 \
    "njet_sts_server_connects_total{listen=\"%V\",port=\"%ui\","              \
    "protocol=\"%V\",code=\"1xx\"} %uA\n"                                      \
    "njet_sts_server_connects_total{listen=\"%V\",port=\"%ui\","              \
    "protocol=\"%V\",code=\"2xx\"} %uA\n"                                      \
    "njet_sts_server_connects_total{listen=\"%V\",port=\"%ui\","              \
    "protocol=\"%V\",code=\"3xx\"} %uA\n"                                      \
    "njet_sts_server_connects_total{listen=\"%V\",port=\"%ui\","              \
    "protocol=\"%V\",code=\"4xx\"} %uA\n"                                      \
    "njet_sts_server_connects_total{listen=\"%V\",port=\"%ui\","              \
    "protocol=\"%V\",code=\"5xx\"} %uA\n"                                      \
    "njet_sts_server_connects_total{listen=\"%V\",port=\"%ui\","              \
    "protocol=\"%V\",code=\"total\"} %uA\n"                                    \
    "njet_sts_server_session_seconds_total{listen=\"%V\",port=\"%ui\","       \
    "protocol=\"%V\"} %.3f\n"                                                  \
    "njet_sts_server_session_seconds{listen=\"%V\",port=\"%ui\","             \
    "protocol=\"%V\"} %.3f\n"

#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_HISTOGRAM_BUCKET     \
    "njet_sts_server_session_duration_seconds_bucket{listen=\"%V\",port=\"%ui\""        \
    ",protocol=\"%V\",le=\"%.3f\"} %uA\n"

#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_HISTOGRAM_BUCKET_E   \
    "njet_sts_server_session_duration_seconds_bucket{listen=\"%V\",port=\"%ui\","       \
    "protocol=\"%V\",le=\"+Inf\"} %uA\n"

#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_HISTOGRAM_SUM        \
    "njet_sts_server_session_duration_seconds_sum{listen=\"%V\",port=\"%ui\","          \
    "protocol=\"%V\"} %.3f\n"

#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_HISTOGRAM_COUNT      \
    "njet_sts_server_session_duration_seconds_count{listen=\"%V\",port=\"%ui\","        \
    "protocol=\"%V\"} %uA\n"

#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_S          \
    "# HELP njet_sts_filter_bytes_total The request/response bytes\n"         \
    "# TYPE njet_sts_filter_bytes_total counter\n"                            \
    "# HELP njet_sts_filter_connects_total The connects counter\n"            \
    "# TYPE njet_sts_filter_connects_total counter\n"                         \
    "# HELP njet_sts_filter_session_seconds_total The session duration time " \
    "in seconds\n"                                                             \
    "# TYPE njet_sts_filter_session_seconds_total counter\n"                  \
    "# HELP njet_sts_filter_session_seconds The average of session duration " \
    "time in seconds\n"                                                        \
    "# TYPE njet_sts_filter_session_seconds gauge\n"                          \
    "# HELP njet_sts_filter_session_duration_seconds The histogram of "       \
    "session duration time in seconds\n"                                       \
    "# TYPE njet_sts_filter_session_duration_seconds histogram\n"

#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER            \
    "njet_sts_filter_bytes_total{filter=\"%V\",filter_name=\"%V\","           \
    "direction=\"in\"} %uA\n"                                                  \
    "njet_sts_filter_bytes_total{filter=\"%V\",filter_name=\"%V\","           \
    "direction=\"out\"} %uA\n"                                                 \
    "njet_sts_filter_connects_total{filter=\"%V\",filter_name=\"%V\","        \
    "direction=\"1xx\"} %uA\n"                                                 \
    "njet_sts_filter_connects_total{filter=\"%V\",filter_name=\"%V\","        \
    "direction=\"2xx\"} %uA\n"                                                 \
    "njet_sts_filter_connects_total{filter=\"%V\",filter_name=\"%V\","        \
    "direction=\"3xx\"} %uA\n"                                                 \
    "njet_sts_filter_connects_total{filter=\"%V\",filter_name=\"%V\","        \
    "direction=\"4xx\"} %uA\n"                                                 \
    "njet_sts_filter_connects_total{filter=\"%V\",filter_name=\"%V\","        \
    "direction=\"5xx\"} %uA\n"                                                 \
    "njet_sts_filter_connects_total{filter=\"%V\",filter_name=\"%V\","        \
    "direction=\"total\"} %uA\n"                                               \
    "njet_sts_filter_session_seconds_total{filter=\"%V\","                    \
    "filter_name=\"%V\"} %.3f\n"                                               \
    "njet_sts_filter_session_seconds{filter=\"%V\",filter_name=\"%V\"} %.3f\n"

#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_HISTOGRAM_BUCKET     \
    "njet_sts_filter_session_duration_seconds_bucket{filter=\"%V\","                    \
    "filter_name=\"%V\",le=\"%.3f\"} %uA\n"

#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_HISTOGRAM_BUCKET_E   \
    "njet_sts_filter_session_duration_seconds_bucket{filter=\"%V\","                    \
    "filter_name=\"%V\",le=\"+Inf\"} %uA\n"

#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_HISTOGRAM_SUM        \
    "njet_sts_filter_session_duration_seconds_sum{filter=\"%V\","                       \
    "filter_name=\"%V\"} %.3f\n"

#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_HISTOGRAM_COUNT      \
    "njet_sts_filter_session_duration_seconds_count{filter=\"%V\","                     \
    "filter_name=\"%V\"} %uA\n"

#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_S        \
    "# HELP njet_sts_upstream_bytes_total The request/response bytes\n"       \
    "# TYPE njet_sts_upstream_bytes_total counter\n"                          \
    "# HELP njet_sts_upstream_connects_total The upstream connects counter\n" \
    "# TYPE njet_sts_upstream_connects_total counter\n"                       \
    "# HELP njet_sts_upstream_session_seconds_total The session duration "    \
    "time in seconds\n"                                                        \
    "# TYPE njet_sts_upstream_session_seconds_total counter\n"                \
    "# HELP njet_sts_upstream_session_seconds The average of session "        \
    "duration in seconds\n"                                                    \
    "# TYPE njet_sts_upstream_session_seconds gauge\n"                        \
    "# HELP njet_sts_upstream_response_connect_seconds_total The time to "    \
    "connect to the upstream server\n"                                         \
    "# TYPE njet_sts_upstream_response_connect_seconds_total counter\n"       \
    "# HELP njet_sts_upstream_response_connect_seconds The average of time "  \
    "to connect to the upstream server\n"                                      \
    "# TYPE njet_sts_upstream_response_connect_seconds gauge\n"               \
    "# HELP njet_sts_upstream_response_firstbyte_seconds_total The time to "  \
    "receive the first byte of data\n"                                         \
    "# TYPE njet_sts_upstream_response_firstbyte_seconds_total counter\n"     \
    "# HELP njet_sts_upstream_response_firstbyte_seconds The average of "     \
    "time to receive the first byte of data \n"                                \
    "# TYPE njet_sts_upstream_response_firstbyte_seconds gauge\n"             \
    "# HELP njet_sts_upstream_response_session_seconds_total The session "    \
    "duration time to the upstream server\n"                                   \
    "# TYPE njet_sts_upstream_response_session_seconds_total counter\n"       \
    "# HELP njet_sts_upstream_response_session_seconds The average of "       \
    "session duration time to the upstream server\n"                           \
    "# TYPE njet_sts_upstream_response_session_seconds gauge\n"               \
    "# HELP njet_sts_upstream_session_duration_seconds The histogram of "     \
    "session duration time in seconds\n"                                       \
    "# TYPE njet_sts_upstream_session_duration_seconds histogram\n"           \
    "# HELP njet_sts_upstream_response_connect_duration_seconds The "         \
    " histogram of time to connect to the upstream server\n"                   \
    "# TYPE njet_sts_upstream_response_connect_duration_seconds histogram\n"  \
    "# HELP njet_sts_upstream_response_firstbyte_duration_seconds The "       \
    "histogram of time to receive the first byte of data\n"                    \
    "# TYPE njet_sts_upstream_response_firstbyte_duration_seconds "           \
    "histogram\n"                                                              \
    "# HELP njet_sts_upstream_response_session_duration_seconds The "         \
    "histogram of session duration time to the upstream server\n"              \
    "# TYPE njet_sts_upstream_response_session_duration_seconds histogram\n"

#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM          \
    "njet_sts_upstream_bytes_total{upstream=\"%V\",backend=\"%V\","           \
    "direction=\"in\"} %uA\n"                                                  \
    "njet_sts_upstream_bytes_total{upstream=\"%V\",backend=\"%V\","           \
    "direction=\"out\"} %uA\n"                                                 \
    "njet_sts_upstream_connects_total{upstream=\"%V\",backend=\"%V\","        \
    "code=\"1xx\"} %uA\n"                                                      \
    "njet_sts_upstream_connects_total{upstream=\"%V\",backend=\"%V\","        \
    "code=\"2xx\"} %uA\n"                                                      \
    "njet_sts_upstream_connects_total{upstream=\"%V\",backend=\"%V\","        \
    "code=\"3xx\"} %uA\n"                                                      \
    "njet_sts_upstream_connects_total{upstream=\"%V\",backend=\"%V\","        \
    "code=\"4xx\"} %uA\n"                                                      \
    "njet_sts_upstream_connects_total{upstream=\"%V\",backend=\"%V\","        \
    "code=\"5xx\"} %uA\n"                                                      \
    "njet_sts_upstream_connects_total{upstream=\"%V\",backend=\"%V\","        \
    "code=\"total\"} %uA\n"                                                    \
    "njet_sts_upstream_session_seconds_total{upstream=\"%V\","                \
    "backend=\"%V\"} %.3f\n"                                                   \
    "njet_sts_upstream_session_seconds{upstream=\"%V\","                      \
    "backend=\"%V\"} %.3f\n"                                                   \
    "njet_sts_upstream_response_connect_seconds_total{upstream=\"%V\","       \
    "backend=\"%V\"} %.3f\n"                                                   \
    "njet_sts_upstream_response_connect_seconds{upstream=\"%V\","             \
    "backend=\"%V\"} %.3f\n"                                                   \
    "njet_sts_upstream_response_firstbyte_seconds_total{upstream=\"%V\","     \
    "backend=\"%V\"} %.3f\n"                                                   \
    "njet_sts_upstream_response_firstbyte_seconds{upstream=\"%V\","           \
    "backend=\"%V\"} %.3f\n"                                                   \
    "njet_sts_upstream_response_session_seconds_total{upstream=\"%V\","       \
    "backend=\"%V\"} %.3f\n"                                                   \
    "njet_sts_upstream_response_session_seconds{upstream=\"%V\","             \
    "backend=\"%V\"} %.3f\n"

#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_HISTOGRAM_BUCKET   \
    "njet_sts_upstream_%V_duration_seconds_bucket{upstream=\"%V\","                     \
    "backend=\"%V\",le=\"%.3f\"} %uA\n"

#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_HISTOGRAM_BUCKET_E \
    "njet_sts_upstream_%V_duration_seconds_bucket{upstream=\"%V\","                     \
    "backend=\"%V\",le=\"+Inf\"} %uA\n"

#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_HISTOGRAM_SUM      \
    "njet_sts_upstream_%V_duration_seconds_sum{upstream=\"%V\","                        \
    "backend=\"%V\"} %.3f\n"

#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_HISTOGRAM_COUNT    \
    "njet_sts_upstream_%V_duration_seconds_count{upstream=\"%V\","                      \
    "backend=\"%V\"} %uA\n"


u_char *njt_http_stream_server_traffic_status_display_prometheus_set_main(
    njt_http_request_t *r, u_char *buf);
u_char *njt_http_stream_server_traffic_status_display_prometheus_set_server_node(
    njt_http_request_t *r, u_char *buf,
    njt_http_stream_server_traffic_status_node_t *stsn);
u_char *njt_http_stream_server_traffic_status_display_prometheus_set_server(
    njt_http_request_t *r, u_char *buf,
    njt_rbtree_node_t *node);
u_char *njt_http_stream_server_traffic_status_display_prometheus_set_filter_node(
    njt_http_request_t *r, u_char *buf,
    njt_http_stream_server_traffic_status_node_t *stsn);
u_char *njt_http_stream_server_traffic_status_display_prometheus_set_filter(
    njt_http_request_t *r, u_char *buf,
    njt_rbtree_node_t *node);
u_char *njt_http_stream_server_traffic_status_display_prometheus_set_upstream_node(
    njt_http_request_t *r, u_char *buf,
    njt_http_stream_server_traffic_status_node_t *stsn);
u_char *njt_http_stream_server_traffic_status_display_prometheus_set_upstream(
    njt_http_request_t *r, u_char *buf,
    njt_rbtree_node_t *node);

u_char *njt_http_stream_server_traffic_status_display_prometheus_set(
    njt_http_request_t *r, u_char *buf);


#endif /* _NJT_HTTP_STREAM_STS_DISPLAY_PROMETHEUS_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
