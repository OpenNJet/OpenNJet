/*************************************************************************************
 Copyright (C), 2021-2023, TMLake(Beijing) Technology Ltd.,
 File name    : njt_common_health_check.h
 Version      : 1.0
 Author       : ChengXu
 Date         : 2023/2/2/002 
 Description  : 
 Other        :
 History      :
 <author>       <time>          <version >      <desc>
 ChengXu        2023/2/2/002       1.1             
***********************************************************************************/
//
// Created by Administrator on 2023/2/2/002.
//

#ifndef NJET_MAIN_NJT_COMMON_HEALTH_CHECK_H
#define NJET_MAIN_NJT_COMMON_HEALTH_CHECK_H

#include <njt_config.h>
#include <njt_core.h>
#include <njet.h>
#include <njt_event.h>
#include <njt_json_api.h>

#define njt_str_copy_pool(pool,desc,src,err)    \
    desc.data = njt_pcalloc(pool,src.len);      \
        if(desc.data == NULL){                  \
            err ;                               \
        }                                       \
    njt_memcpy(desc.data,src.data,src.len);     \
    desc.len = src.len


typedef struct {
    njt_queue_t hc_queue; // 健康检查列表
} njt_helper_main_conf_t;
#if (NJT_OPENSSL)
typedef struct njt_helper_hc_ssl_conf_s {
    njt_flag_t ssl_enable;
    njt_flag_t ssl_session_reuse;
    njt_uint_t ssl_protocols;
    njt_str_t ssl_ciphers;
    njt_str_t ssl_name;
    njt_flag_t ssl_server_name;
    njt_flag_t ssl_verify;
    njt_int_t ssl_verify_depth;
    njt_str_t ssl_trusted_certificate;
    njt_str_t ssl_crl;
    njt_str_t ssl_certificate;
    njt_str_t ssl_certificate_key;
    njt_array_t *ssl_passwords;
    njt_array_t *ssl_conf_commands;
    njt_ssl_t *ssl;
} njt_helper_hc_ssl_conf_t;
#endif

typedef struct njt_helper_health_check_conf_s {
    njt_pool_t *pool;
    njt_log_t *log;
    njt_queue_t queue;
    njt_uint_t type;
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
    unsigned persistent: 1;
    unsigned mandatory: 1;
    unsigned disable:1;
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
    bool ssl_session_reuse;
    njt_int_t ssl_protocols;
    njt_str_t ssl_ciphers;
    njt_str_t ssl_name;
    bool ssl_server_name;
    bool ssl_verify;
    njt_int_t ssl_verify_depth;
    njt_str_t ssl_trusted_certificate;
    njt_str_t ssl_crl;
    njt_str_t ssl_certificate;
    njt_str_t ssl_certificate_key;
    njt_str_t ssl_passwords;
    njt_str_t ssl_conf_commands;
} njt_helper_hc_ssl_add_data_t;
#endif
typedef struct {
    njt_str_t upstream_name;
    njt_str_t hc_type;
    njt_msec_t interval;
    njt_msec_t jitter;
    njt_msec_t timeout;
    njt_int_t port;
    njt_int_t passes;
    njt_int_t fails;
    njt_helper_hc_http_add_data_t http;
    njt_helper_hc_stream_add_data_t stream;
#if (NJT_OPENSSL)
    njt_helper_hc_ssl_add_data_t ssl;
#endif
    bool persistent;
    bool mandatory;
    unsigned success: 1;
    njt_int_t rc;
} njt_helper_hc_api_data_t;

typedef struct njt_json_define_s njt_json_define_t;

typedef njt_int_t (*njt_parse_item_handler)(njt_json_element *el, njt_json_define_t *def, void *data);

struct njt_json_define_s {
    njt_str_t name;
    njt_int_t offset;
    int8_t type;
    njt_json_define_t *sub;
    njt_parse_item_handler parse;
};
#define njt_json_define_null {njt_null_string,0,NJT_JSON_ERROR,NULL,NULL}

njt_int_t njt_json_parse_msec(njt_json_element *el, njt_json_define_t *def, void *data);

njt_int_t njt_json_parse_data(njt_pool_t *pool, njt_str_t *str, njt_json_define_t *def, void *data);

#if (NJT_OPENSSL)
njt_int_t njt_json_parse_ssl_protocols(njt_json_element *el,njt_json_define_t *def,void *data);
njt_int_t njt_helper_hc_set_ssl(njt_helper_health_check_conf_t *hhccf, njt_helper_hc_ssl_conf_t *hcscf);
#endif

njt_int_t njt_str_split(njt_str_t *src,njt_array_t *array,char sign);
njt_int_t njt_json_parse_str_list(njt_json_element *el,njt_json_define_t *def,void *data);

#endif //NJET_MAIN_NJT_COMMON_HEALTH_CHECK_H
