
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#ifndef _NJT_HTTP_STREAM_STS_DISPLAY_JSON_H_INCLUDED_
#define _NJT_HTTP_STREAM_STS_DISPLAY_JSON_H_INCLUDED_


#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_S           "{"
#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_OBJECT_S    "\"%V\":{"
#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_ARRAY_S     "\"%V\":["

#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_ARRAY_E     "]"
#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_OBJECT_E    "}"
#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_E           "}"
#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_NEXT        ","

#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_MAIN                    \
    "\"hostName\":\"%V\","                                                     \
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

#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_SERVER_S                \
    "\"streamServerZones\":{"

#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_SERVER "\"%V\":{"       \
    "\"port\":%ui,"                                                            \
    "\"protocol\":\"%V\","                                                     \
    "\"connectCounter\":%uA,"                                                  \
    "\"inBytes\":%uA,"                                                         \
    "\"outBytes\":%uA,"                                                        \
    "\"responses\":{"                                                          \
    "\"1xx\":%uA,"                                                             \
    "\"2xx\":%uA,"                                                             \
    "\"3xx\":%uA,"                                                             \
    "\"4xx\":%uA,"                                                             \
    "\"5xx\":%uA"                                                              \
    "},"                                                                       \
    "\"sessionMsecCounter\":%uA,"                                              \
    "\"sessionMsec\":%M,"                                                      \
    "\"sessionMsecs\":{"                                                       \
    "\"times\":[%s],"                                                          \
    "\"msecs\":[%s]"                                                           \
    "},"                                                                       \
    "\"sessionBuckets\":{"                                                     \
    "\"msecs\":[%s],"                                                          \
    "\"counters\":[%s]"                                                        \
    "},"                                                                       \
    "\"overCounts\":{"                                                         \
    "\"maxIntegerSize\":%s,"                                                   \
    "\"connectCounter\":%uA,"                                                  \
    "\"inBytes\":%uA,"                                                         \
    "\"outBytes\":%uA,"                                                        \
    "\"1xx\":%uA,"                                                             \
    "\"2xx\":%uA,"                                                             \
    "\"3xx\":%uA,"                                                             \
    "\"4xx\":%uA,"                                                             \
    "\"5xx\":%uA,"                                                             \
    "\"sessionMsecCounter\":%uA"                                               \
    "}"                                                                        \
    "},"

#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_FILTER_S                \
    "\"streamFilterZones\":{"

#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_UPSTREAM_S              \
    "\"streamUpstreamZones\":{"
#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_UPSTREAM                \
    "{\"server\":\"%V\","                                                      \
    "\"connectCounter\":%uA,"                                                  \
    "\"inBytes\":%uA,"                                                         \
    "\"outBytes\":%uA,"                                                        \
    "\"responses\":{"                                                          \
    "\"1xx\":%uA,"                                                             \
    "\"2xx\":%uA,"                                                             \
    "\"3xx\":%uA,"                                                             \
    "\"4xx\":%uA,"                                                             \
    "\"5xx\":%uA"                                                              \
    "},"                                                                       \
    "\"sessionMsecCounter\":%uA,"                                              \
    "\"sessionMsec\":%M,"                                                      \
    "\"sessionMsecs\":{"                                                       \
    "\"times\":[%s],"                                                          \
    "\"msecs\":[%s]"                                                           \
    "},"                                                                       \
    "\"sessionBuckets\":{"                                                     \
    "\"msecs\":[%s],"                                                          \
    "\"counters\":[%s]"                                                        \
    "},"                                                                       \
    "\"uSessionMsecCounter\":%uA,"                                             \
    "\"uSessionMsec\":%M,"                                                     \
    "\"uSessionMsecs\":{"                                                      \
    "\"times\":[%s],"                                                          \
    "\"msecs\":[%s]"                                                           \
    "},"                                                                       \
    "\"uSessionBuckets\":{"                                                    \
    "\"msecs\":[%s],"                                                          \
    "\"counters\":[%s]"                                                        \
    "},"                                                                       \
    "\"uConnectMsecCounter\":%uA,"                                             \
    "\"uConnectMsec\":%M,"                                                     \
    "\"uConnectMsecs\":{"                                                      \
    "\"times\":[%s],"                                                          \
    "\"msecs\":[%s]"                                                           \
    "},"                                                                       \
    "\"uConnectBuckets\":{"                                                    \
    "\"msecs\":[%s],"                                                          \
    "\"counters\":[%s]"                                                        \
    "},"                                                                       \
    "\"uFirstByteMsecCounter\":%uA,"                                           \
    "\"uFirstByteMsec\":%M,"                                                   \
    "\"uFirstByteMsecs\":{"                                                    \
    "\"times\":[%s],"                                                          \
    "\"msecs\":[%s]"                                                           \
    "},"                                                                       \
    "\"uFirstByteBuckets\":{"                                                  \
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
    "\"connectCounter\":%uA,"                                                  \
    "\"inBytes\":%uA,"                                                         \
    "\"outBytes\":%uA,"                                                        \
    "\"1xx\":%uA,"                                                             \
    "\"2xx\":%uA,"                                                             \
    "\"3xx\":%uA,"                                                             \
    "\"4xx\":%uA,"                                                             \
    "\"5xx\":%uA,"                                                             \
    "\"sessionMsecCounter\":%uA,"                                              \
    "\"uSessionMsecCounter\":%uA,"                                             \
    "\"uConnectMsecCounter\":%uA,"                                             \
    "\"uFirstByteMsecCounter\":%uA"                                            \
    "}"                                                                        \
    "},"


u_char *njt_http_stream_server_traffic_status_display_set_main(
    njt_http_request_t *r, u_char *buf);
u_char *njt_http_stream_server_traffic_status_display_set_server_node(
    njt_http_request_t *r,
    u_char *buf, njt_str_t *key,
    njt_http_stream_server_traffic_status_node_t *stsn);
u_char *njt_http_stream_server_traffic_status_display_set_server(
    njt_http_request_t *r, u_char *buf,
    njt_rbtree_node_t *node);

u_char *njt_http_stream_server_traffic_status_display_set_filter_node(
    njt_http_request_t *r, u_char *buf,
    njt_http_stream_server_traffic_status_node_t *stsn);
u_char *njt_http_stream_server_traffic_status_display_set_filter(
    njt_http_request_t *r, u_char *buf,
    njt_rbtree_node_t *node);

u_char *njt_http_stream_server_traffic_status_display_set_upstream_node(
    njt_http_request_t *r, u_char *buf,
    njt_stream_upstream_server_t *us,
    njt_http_stream_server_traffic_status_node_t *stsn, 
    njt_str_t *name
    );
u_char *njt_http_stream_server_traffic_status_display_set_upstream_alone(
    njt_http_request_t *r, u_char *buf, njt_rbtree_node_t *node);
u_char *njt_http_stream_server_traffic_status_display_set_upstream_group(
    njt_http_request_t *r, u_char *buf);

u_char *njt_http_stream_server_traffic_status_display_set(njt_http_request_t *r,
    u_char *buf);


#endif /* _NJT_HTTP_STREAM_STS_DISPLAY_JSON_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
