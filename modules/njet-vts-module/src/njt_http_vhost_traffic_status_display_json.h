
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 * Copyright (C), 2021-2023, TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_VTS_DISPLAY_JSON_H_INCLUDED_
#define _NJT_HTTP_VTS_DISPLAY_JSON_H_INCLUDED_


#define NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_S           "{"
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_OBJECT_S    "\"%V\":{"
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_ARRAY_S     "\"%V\":["

#define NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_ARRAY_E     "]"
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_OBJECT_E    "}"
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_E           "}"
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_NEXT        ","

#define NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_MAIN "\"hostName\":\"%V\","     \
    "\"moduleVersion\":\"%s\","                                                \
    "\"njetVersion\":\"%s\","                                                 \
    "\"loadMsec\":%M,"                                                         \
    "\"nowMsec\":%M,"                                                          \
    "\"connections\":{"                                                        \
    "\"active\":%uA,"                                                          \
    "\"reading\":%uA,"                                                         \
    "\"writing\":%uA,"                                                         \
    "\"waiting\":%uA,"                                                         \
    "\"accepted\":%uA,"                                                        \
    "\"handled\":%uA,"                                                         \
    "\"requests\":%uA"                                                         \
    "},"                                                                       \
    "\"sharedZones\":{"                                                        \
    "\"name\":\"%V\","                                                         \
    "\"maxSize\":%ui,"                                                         \
    "\"usedSize\":%ui,"                                                        \
    "\"usedNode\":%ui"                                                         \
    "},"

#define NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER_S "\"serverZones\":{"

#if (NJT_HTTP_CACHE)
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER "\"%V\":{"               \
    "\"requestCounter\":%uA,"                                                  \
    "\"inBytes\":%uA,"                                                         \
    "\"outBytes\":%uA,"                                                        \
    "\"responses\":{"                                                          \
    "\"1xx\":%uA,"                                                             \
    "\"2xx\":%uA,"                                                             \
    "\"3xx\":%uA,"                                                             \
    "\"4xx\":%uA,"                                                             \
    "\"5xx\":%uA,"                                                             \
    "\"miss\":%uA,"                                                            \
    "\"bypass\":%uA,"                                                          \
    "\"expired\":%uA,"                                                         \
    "\"stale\":%uA,"                                                           \
    "\"updating\":%uA,"                                                        \
    "\"revalidated\":%uA,"                                                     \
    "\"hit\":%uA,"                                                             \
    "\"scarce\":%uA"                                                           \
    "},"                                                                       \
    "\"requestMsecCounter\":%uA,"                                              \
    "\"requestMsec\":%M,"                                                      \
    "\"requestMsecs\":{"                                                       \
    "\"times\":[%s],"                                                          \
    "\"msecs\":[%s]"                                                           \
    "},"                                                                       \
    "\"requestBuckets\":{"                                                     \
    "\"msecs\":[%s],"                                                          \
    "\"counters\":[%s]"                                                        \
    "},"                                                                       \
    "\"overCounts\":{"                                                         \
    "\"maxIntegerSize\":%s,"                                                   \
    "\"requestCounter\":%uA,"                                                  \
    "\"inBytes\":%uA,"                                                         \
    "\"outBytes\":%uA,"                                                        \
    "\"1xx\":%uA,"                                                             \
    "\"2xx\":%uA,"                                                             \
    "\"3xx\":%uA,"                                                             \
    "\"4xx\":%uA,"                                                             \
    "\"5xx\":%uA,"                                                             \
    "\"miss\":%uA,"                                                            \
    "\"bypass\":%uA,"                                                          \
    "\"expired\":%uA,"                                                         \
    "\"stale\":%uA,"                                                           \
    "\"updating\":%uA,"                                                        \
    "\"revalidated\":%uA,"                                                     \
    "\"hit\":%uA,"                                                             \
    "\"scarce\":%uA,"                                                          \
    "\"requestMsecCounter\":%uA"                                               \
    "}"                                                                        \
    "},"
#else
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER "\"%V\":{"               \
    "\"requestCounter\":%uA,"                                                  \
    "\"inBytes\":%uA,"                                                         \
    "\"outBytes\":%uA,"                                                        \
    "\"responses\":{"                                                          \
    "\"1xx\":%uA,"                                                             \
    "\"2xx\":%uA,"                                                             \
    "\"3xx\":%uA,"                                                             \
    "\"4xx\":%uA,"                                                             \
    "\"5xx\":%uA"                                                              \
    "},"                                                                       \
    "\"requestMsecCounter\":%uA,"                                              \
    "\"requestMsec\":%M,"                                                      \
    "\"requestMsecs\":{"                                                       \
    "\"times\":[%s],"                                                          \
    "\"msecs\":[%s]"                                                           \
    "},"                                                                       \
    "\"requestBuckets\":{"                                                     \
    "\"msecs\":[%s],"                                                          \
    "\"counters\":[%s]"                                                        \
    "},"                                                                       \
    "\"overCounts\":{"                                                         \
    "\"maxIntegerSize\":%s,"                                                   \
    "\"requestCounter\":%uA,"                                                  \
    "\"inBytes\":%uA,"                                                         \
    "\"outBytes\":%uA,"                                                        \
    "\"1xx\":%uA,"                                                             \
    "\"2xx\":%uA,"                                                             \
    "\"3xx\":%uA,"                                                             \
    "\"4xx\":%uA,"                                                             \
    "\"5xx\":%uA,"                                                             \
    "\"requestMsecCounter\":%uA"                                               \
    "}"                                                                        \
    "},"
#endif

#define NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_FILTER_S "\"filterZones\":{"

#define NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_UPSTREAM_S "\"upstreamZones\":{"
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_UPSTREAM "{\"server\":\"%V\","  \
    "\"requestCounter\":%uA,"                                                  \
    "\"inBytes\":%uA,"                                                         \
    "\"outBytes\":%uA,"                                                        \
    "\"responses\":{"                                                          \
    "\"1xx\":%uA,"                                                             \
    "\"2xx\":%uA,"                                                             \
    "\"3xx\":%uA,"                                                             \
    "\"4xx\":%uA,"                                                             \
    "\"5xx\":%uA,"                                                             \
    "\"timeout\":%uA"                                                         \
    "},"                                                                       \
    "\"requestMsecCounter\":%uA,"                                              \
    "\"requestMsec\":%M,"                                                      \
    "\"requestMsecs\":{"                                                       \
    "\"times\":[%s],"                                                          \
    "\"msecs\":[%s]"                                                           \
    "},"                                                                       \
    "\"requestBuckets\":{"                                                     \
    "\"msecs\":[%s],"                                                          \
    "\"counters\":[%s]"                                                        \
    "},"                                                                       \
    "\"responseMsecCounter\":%uA,"                                             \
    "\"responseMsec\":%M,"                                                     \
    "\"responseMsecs\":{"                                                      \
    "\"times\":[%s],"                                                          \
    "\"msecs\":[%s]"                                                           \
    "},"                                                                       \
    "\"responseBuckets\":{"                                                    \
    "\"msecs\":[%s],"                                                          \
    "\"counters\":[%s]"                                                        \
    "},"                                                                       \
    "\"weight\":%ui,"                                                          \
    "\"maxFails\":%ui,"                                                        \
    "\"failTimeout\":%T,"                                                      \
    "\"backup\":%s,"                                                           \
    "\"down\":%s,"                                                             \
    "\"overCounts\":{"                                                         \
    "\"maxIntegerSize\":%s,"                                                   \
    "\"requestCounter\":%uA,"                                                  \
    "\"inBytes\":%uA,"                                                         \
    "\"outBytes\":%uA,"                                                        \
    "\"1xx\":%uA,"                                                             \
    "\"2xx\":%uA,"                                                             \
    "\"3xx\":%uA,"                                                             \
    "\"4xx\":%uA,"                                                             \
    "\"5xx\":%uA,"                                                             \
    "\"requestMsecCounter\":%uA,"                                              \
    "\"responseMsecCounter\":%uA"                                              \
    "}"                                                                        \
    "},"

#define NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_UPSTREAM_REQDELAY               \
    "\"p50reqdelayMsecr\":%uA, "                                               \
    "\"p99reqdelayMsecr\":%uA, "                                               \
    "\"p999reqdelayMsecr\":%uA, "                                              \
    "\"p9999reqdelayMsecr\":%uA, "                                             \
    "\"p99999reqdelayMsecr\":%uA, "


#if (NJT_HTTP_CACHE)
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_CACHE_S "\"cacheZones\":{"
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_CACHE "\"%V\":{"                \
    "\"maxSize\":%uA,"                                                         \
    "\"usedSize\":%uA,"                                                        \
    "\"inBytes\":%uA,"                                                         \
    "\"outBytes\":%uA,"                                                        \
    "\"responses\":{"                                                          \
    "\"miss\":%uA,"                                                            \
    "\"bypass\":%uA,"                                                          \
    "\"expired\":%uA,"                                                         \
    "\"stale\":%uA,"                                                           \
    "\"updating\":%uA,"                                                        \
    "\"revalidated\":%uA,"                                                     \
    "\"hit\":%uA,"                                                             \
    "\"scarce\":%uA"                                                           \
    "},"                                                                       \
    "\"overCounts\":{"                                                         \
    "\"maxIntegerSize\":%s,"                                                   \
    "\"inBytes\":%uA,"                                                         \
    "\"outBytes\":%uA,"                                                        \
    "\"miss\":%uA,"                                                            \
    "\"bypass\":%uA,"                                                          \
    "\"expired\":%uA,"                                                         \
    "\"stale\":%uA,"                                                           \
    "\"updating\":%uA,"                                                        \
    "\"revalidated\":%uA,"                                                     \
    "\"hit\":%uA,"                                                             \
    "\"scarce\":%uA"                                                           \
    "}"                                                                        \
    "},"
#endif


u_char *njt_http_vhost_traffic_status_display_set_main(
    njt_http_request_t *r, u_char *buf);
u_char *njt_http_vhost_traffic_status_display_set_server_node(
    njt_http_request_t *r,
    u_char *buf, njt_str_t *key,
    njt_http_vhost_traffic_status_node_t *vtsn);
u_char *njt_http_vhost_traffic_status_display_set_server(
    njt_http_request_t *r, u_char *buf,
    njt_rbtree_node_t *node);
u_char *njt_http_vhost_traffic_status_display_set_filter_node(
    njt_http_request_t *r, u_char *buf,
    njt_http_vhost_traffic_status_node_t *vtsn);
u_char *njt_http_vhost_traffic_status_display_set_filter(
    njt_http_request_t *r, u_char *buf,
    njt_rbtree_node_t *node);
u_char *njt_http_vhost_traffic_status_display_set_upstream_node(
    njt_http_request_t *r, u_char *buf,
    njt_http_upstream_server_t *us,
#if njet_version > 1007001
    njt_http_vhost_traffic_status_node_t *vtsn
#else
    njt_http_vhost_traffic_status_node_t *vtsn, njt_str_t *name
#endif
    );
u_char *njt_http_vhost_traffic_status_display_set_upstream_alone(
    njt_http_request_t *r, u_char *buf, njt_rbtree_node_t *node);
u_char *njt_http_vhost_traffic_status_display_set_upstream_group(
    njt_http_request_t *r, u_char *buf);

#if (NJT_HTTP_CACHE)
u_char *njt_http_vhost_traffic_status_display_set_cache_node(
    njt_http_request_t *r, u_char *buf,
    njt_http_vhost_traffic_status_node_t *vtsn);
u_char *njt_http_vhost_traffic_status_display_set_cache(
    njt_http_request_t *r, u_char *buf,
    njt_rbtree_node_t *node);
#endif

u_char *njt_http_vhost_traffic_status_display_set(njt_http_request_t *r,
    u_char *buf);


#endif /* _NJT_HTTP_VTS_DISPLAY_JSON_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
