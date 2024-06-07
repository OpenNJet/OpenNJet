/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */

#ifndef _NJT_MQTT_MODULE_H_
#define _NJT_MQTT_MODULE_H_

#include <njet.h>
#include <njt_core.h>
#include <njt_http.h>


extern njt_module_t  njt_http_mqtt_module;


typedef struct {
    njt_http_script_code_pt             code;
    njt_uint_t                          empty;
} njt_http_mqtt_escape_t;

typedef struct {
    njt_uint_t                          key;
    njt_str_t                           sv;
    njt_http_complex_value_t           *cv;
} njt_http_mqtt_mixed_t;
;

typedef struct {
    in_port_t                           port;
    njt_str_t                           user;
    njt_str_t                           password;                      
} njt_http_mqtt_upstream_server_t;

typedef struct {
    struct sockaddr                    *sockaddr;
    socklen_t                           socklen;
    njt_str_t                           name;
    njt_str_t                           host;
    in_port_t                           port;
    // njt_str_t                           dbname;
    njt_str_t                           user;
    njt_str_t                           password;
} njt_http_mqtt_upstream_peer_t;

typedef struct {
    njt_uint_t                          single;
    njt_uint_t                          number;
    njt_str_t                          *name;
    njt_http_mqtt_upstream_peer_t        peer[1];
} njt_http_mqtt_upstream_peers_t;

typedef struct {
    njt_http_mqtt_upstream_peers_t      *peers;
    njt_uint_t                          current;
    njt_array_t                        *servers;
    njt_pool_t                         *pool;
    /* keepalive */
    njt_flag_t                          single;
    njt_queue_t                         free;
    njt_queue_t                         cache;
    njt_uint_t                          active_conns;
    njt_uint_t                          max_cached;
    njt_uint_t                          retry_times;
    njt_uint_t                          reject;
    size_t                              send_buffer_size;
    size_t                              recv_buffer_size;
    njt_msec_t                          ping_time;
    njt_msec_t                          read_timeout;

} njt_http_mqtt_upstream_srv_conf_t;

typedef struct {
    /* upstream */
    njt_http_upstream_conf_t            upstream;
    njt_http_complex_value_t           *upstream_cv;

    njt_str_t                           topic;
} njt_http_mqtt_loc_conf_t;

typedef struct {
    njt_chain_t                        *response;
    njt_int_t                           status;
} njt_http_mqtt_ctx_t;



void *njt_http_mqtt_create_upstream_srv_conf(njt_conf_t *);
char *njt_http_mqtt_merge_upstream_srv_conf(njt_conf_t *cf, void *parent, void *child);
void *njt_http_mqtt_create_loc_conf(njt_conf_t *);
char *njt_http_mqtt_merge_loc_conf(njt_conf_t *, void *, void *);
char *njt_http_mqtt_conf_server(njt_conf_t *, njt_command_t *, void *);
char *njt_http_mqtt_conf_keepalive(njt_conf_t *, njt_command_t *, void *);
char *njt_http_mqtt_conf_retry_times(njt_conf_t *cf, njt_command_t *cmd, void *conf);
char *njt_http_mqtt_conf_send_buffer_size(njt_conf_t *cf, njt_command_t *cmd, void *conf);
char *njt_http_mqtt_conf_recv_buffer_size(njt_conf_t *cf, njt_command_t *cmd, void *conf);
char *njt_http_mqtt_conf_ping_time(njt_conf_t *cf, njt_command_t *cmd, void *conf);
char *njt_http_mqtt_conf_read_time(njt_conf_t *cf, njt_command_t *cmd, void *conf);
char *njt_http_mqtt_conf_pass(njt_conf_t *, njt_command_t *, void *);
char *njt_http_mqtt_set_topic(njt_conf_t *cf, njt_command_t *cmd, void *conf);

njt_http_upstream_srv_conf_t  *njt_http_mqtt_find_upstream(njt_http_request_t *,
                                   njt_url_t *);

#endif /* _NJT_MQTT_MODULE_H_ */
