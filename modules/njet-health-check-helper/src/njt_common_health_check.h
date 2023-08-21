/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */

#ifndef NJET_MAIN_NJT_COMMON_HEALTH_CHECK_H
#define NJET_MAIN_NJT_COMMON_HEALTH_CHECK_H

#include <njt_config.h>
#include <njt_core.h>
#include <njet.h>
#include <njt_event.h>
#include <njt_json_api.h>
#include <njt_json_util.h>
#include <njt_http.h>
// #include <njt_hc_parser.h>

#define NJT_HC_HTTP_TYPE 0
#define NJT_HC_STREAM_TYPE 1

extern njt_cycle_t *njet_master_cycle;

typedef struct {
    njt_queue_t hc_queue; // 健康检查列表
   // njt_event_t check_upstream; //
    unsigned first:1;
} njt_helper_main_conf_t;

#if (NJT_OPENSSL)
typedef struct njt_helper_hc_ssl_conf_s {
    njt_flag_t ssl_enable;
    njt_flag_t ntls_enable;
    njt_flag_t ssl_session_reuse;
    njt_uint_t ssl_protocols;
    njt_str_t ssl_protocol_str;
    njt_str_t ssl_ciphers;
    njt_str_t ssl_name;
    njt_flag_t ssl_server_name;
    njt_flag_t ssl_verify;
    njt_int_t ssl_verify_depth;
    njt_str_t ssl_trusted_certificate;
    njt_str_t ssl_crl;
    njt_str_t ssl_certificate;
    njt_str_t ssl_certificate_key;
    njt_str_t ssl_enc_certificate;
    njt_str_t ssl_enc_certificate_key;
    njt_array_t *ssl_passwords;
    njt_array_t *ssl_conf_commands;
    njt_ssl_t *ssl;
} njt_helper_hc_ssl_conf_t;
#endif


typedef struct {
    njt_http_upstream_rr_peer_t *peer;   //current peer
    njt_queue_t  datas;     //other peers which has same servername of the current peer
} njt_hc_http_same_peer_t;

typedef struct {
    njt_stream_upstream_rr_peer_t *peer;   //current peer
    njt_queue_t  datas;     //other peers which has same servername of the current peer
} njt_hc_stream_same_peer_t;

typedef struct njt_helper_health_check_conf_s {
    njt_pool_t *pool;
    njt_log_t *log;
    njt_queue_t queue;
    njt_uint_t type;
    njt_str_t type_str;
    njt_uint_t curr_delay;
    njt_uint_t curr_frame;
    njt_str_t upstream_name;
    njt_msec_t interval;
    njt_msec_t jitter;
    njt_msec_t timeout;
    njt_uint_t protocol;
    njt_uint_t port;
    njt_uint_t passes;
    njt_uint_t fails;
#if (NJT_OPENSSL)
    njt_helper_hc_ssl_conf_t ssl;
#endif
    njt_event_t hc_timer;
    void *ctx;    // http 或stream 特异化字段
    njt_int_t ref_count;
    unsigned persistent: 1;
    unsigned mandatory: 1;
    unsigned disable: 1;
    unsigned first: 1;              //if first, need recreate map

    njt_lvlhsh_t    servername_to_peers; //1 vs more, key:servername value: peers which hash same servername
    njt_uint_t      update_id;           //modified when upstream is modified
    njt_pool_t      *map_pool;           //used for map
} njt_helper_health_check_conf_t;

typedef struct {
    njt_str_t uri;
    njt_str_t status;
    njt_array_t headers;
    njt_str_t body;
    njt_str_t grpc_service;
    njt_int_t grpc_status;
} njt_helper_hc_http_add_data_t;

typedef struct {
    njt_str_t send;
    njt_str_t expect;
} njt_helper_hc_stream_add_data_t;

#if (NJT_OPENSSL)
typedef struct {
    bool ssl_enable;
    bool ntls_enable;
    bool ssl_session_reuse;
    njt_int_t ssl_protocols;
    njt_str_t ssl_protocols_str;
    njt_str_t ssl_ciphers;
    njt_str_t ssl_name;
    bool ssl_server_name;
    bool ssl_verify;
    njt_int_t ssl_verify_depth;
    njt_str_t ssl_trusted_certificate;
    njt_str_t ssl_crl;
    njt_str_t ssl_certificate;
    njt_str_t ssl_certificate_key;
    njt_str_t ssl_enc_certificate;
    njt_str_t ssl_enc_certificate_key;
    njt_str_t ssl_passwords;
    njt_str_t ssl_conf_commands;
} njt_helper_hc_ssl_add_data_t;
#endif



// typedef struct {
//     njt_str_t upstream_name;
//     njt_str_t hc_type;
// } njt_helper_hc_list_item_t;

// /* by zhaokang */
// typedef struct {
//     njt_array_t    *list; /* njt_helper_hc_list_item_t */
// } njt_helper_hc_list_t;

#define HTTP_HEALTH_CHECK_SEPARATOR "$"
#define HTTP_UPSTREAM_KEYS "helper_hc_http_upstreams"
#define UPSTREAM_NAME_PREFIX "helper_hc_http_upstream" HTTP_HEALTH_CHECK_SEPARATOR
#define HTTP_HEALTH_CHECK_CONFS "helper_hc_confs"
#define HTTP_HEALTH_CHECK_CONF_INFO "helper_hc_conf_info" HTTP_HEALTH_CHECK_SEPARATOR

/* by zhaokang */
#define STREAM_HEALTH_CHECK_SEPARATOR     "$"
#define STREAM_UPSTREAM_KEYS              "stream_helper_hc_stream_upstreams"
#define STREAM_UPSTREAM_NAME_PREFIX       "stream_helper_hc_stream_upstream"     STREAM_HEALTH_CHECK_SEPARATOR
#define STREAM_HEALTH_CHECK_CONFS         "stream_helper_hc_confs"
#define STREAM_HEALTH_CHECK_CONF_INFO     "stream_helper_hc_conf_info"             STREAM_HEALTH_CHECK_SEPARATOR



// njt_int_t njt_json_parse_msec(njt_json_element *el, njt_json_define_t *def, void *data);

// njt_int_t njt_json_parse_data(njt_pool_t *pool, njt_str_t *str, njt_json_define_t *def, void *data);

#if (NJT_OPENSSL)

njt_int_t njt_json_parse_ssl_protocols(njt_str_t value, njt_uint_t *np);

njt_int_t njt_helper_hc_set_ssl(njt_helper_health_check_conf_t *hhccf, njt_helper_hc_ssl_conf_t *hcscf);

#endif

njt_http_upstream_srv_conf_t* njt_http_find_upstream_by_name(njt_cycle_t *cycle,njt_str_t *name);

#endif //NJET_MAIN_NJT_COMMON_HEALTH_CHECK_H
