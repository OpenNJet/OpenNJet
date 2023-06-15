/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */
#ifndef NJT_HTTP_DYN_SSL_MODULE_H_
#define NJT_HTTP_DYN_SSL_MODULE_H_
#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>

#include "njt_json_util.h"

typedef struct  {
    njt_str_t cert_type;              //ntls  or regular
    njt_str_t certificate;
    njt_str_t certificate_enc;        //if type is ntls, should not empty 
    njt_str_t certificate_key;
    njt_str_t certificate_key_enc;    //if type is ntls, should not empty
}njt_http_dyn_ssl_cert_group_t;

typedef struct {
    njt_array_t listens;
    njt_array_t server_names;
    njt_array_t certificates;
}njt_http_dyn_ssl_api_srv_t;
typedef struct {
    njt_array_t servers;
}njt_http_dyn_ssl_api_main_t;



typedef struct {
    njt_array_t                         listens;
    njt_array_t                         server_names;
    njt_str_t                           type;
    njt_http_dyn_ssl_cert_group_t       cert_info;
}njt_http_dyn_ssl_put_api_main_t;



njt_json_define_t njt_http_dyn_ssl_cert_group_json_dt[] ={
        {
                njt_string("cert_type"),
                offsetof(njt_http_dyn_ssl_cert_group_t, cert_type),
                0,
                NJT_JSON_STR,
                0,
                NULL,
                NULL,
        },
        {
                njt_string("certificate"),
                offsetof(njt_http_dyn_ssl_cert_group_t, certificate),
                0,
                NJT_JSON_STR,
                0,
                NULL,
                NULL,
        },
        {
                njt_string("certificateEnc"),
                offsetof(njt_http_dyn_ssl_cert_group_t, certificate_enc),
                0,
                NJT_JSON_STR,
                0,
                NULL,
                NULL,
        },
        {
                njt_string("certificateKey"),
                offsetof(njt_http_dyn_ssl_cert_group_t, certificate_key),
                0,
                NJT_JSON_STR,
                0,
                NULL,
                NULL,
        },
        {
                njt_string("certificateKeyEnc"),
                offsetof(njt_http_dyn_ssl_cert_group_t, certificate_key_enc),
                0,
                NJT_JSON_STR,
                0,
                NULL,
                NULL,
        },
        njt_json_define_null,
};

njt_json_define_t njt_http_dyn_ssl_api_srv_json_dt[] ={
        {
                njt_string("listens"),
                offsetof(njt_http_dyn_ssl_api_srv_t, listens),
                sizeof(njt_str_t),
                NJT_JSON_ARRAY,
                NJT_JSON_STR,
                NULL,
                NULL,
        },
        {
                njt_string("serverNames"),
                offsetof(njt_http_dyn_ssl_api_srv_t, server_names),
                sizeof(njt_str_t),
                NJT_JSON_ARRAY,
                NJT_JSON_STR,
                NULL,
                NULL,
        },
        {
                njt_string("certificates"),
                offsetof(njt_http_dyn_ssl_api_srv_t, certificates),
                sizeof(njt_http_dyn_ssl_cert_group_t),
                NJT_JSON_ARRAY,
                NJT_JSON_OBJ,
                njt_http_dyn_ssl_cert_group_json_dt,
                NULL,
        },
        njt_json_define_null,
};

njt_json_define_t njt_http_dyn_ssl_api_main_json_dt[] ={
        {
                njt_string("servers"),
                offsetof(njt_http_dyn_ssl_api_main_t, servers),
                sizeof(njt_http_dyn_ssl_api_srv_t),
                NJT_JSON_ARRAY,
                NJT_JSON_OBJ,
                njt_http_dyn_ssl_api_srv_json_dt,
                NULL,
        },

        njt_json_define_null,
};


njt_json_define_t njt_http_dyn_ssl_api_put_json_dt[] ={
        {
                njt_string("listens"),
                offsetof(njt_http_dyn_ssl_put_api_main_t, listens),
                sizeof(njt_str_t),
                NJT_JSON_ARRAY,
                NJT_JSON_STR,
                NULL,
                NULL,
        },
        {
                njt_string("serverNames"),
                offsetof(njt_http_dyn_ssl_put_api_main_t, server_names),
                sizeof(njt_str_t),
                NJT_JSON_ARRAY,
                NJT_JSON_STR,
                NULL,
                NULL,
        },
        {
                njt_string("type"),
                offsetof(njt_http_dyn_ssl_put_api_main_t, type),
                0,
                NJT_JSON_STR,
                0,
                NULL,
                NULL,
        },
        {
                njt_string("cert_info"),
                offsetof(njt_http_dyn_ssl_put_api_main_t, cert_info),
                sizeof(njt_http_dyn_ssl_cert_group_t),
                NJT_JSON_OBJ,
                0,
                njt_http_dyn_ssl_cert_group_json_dt,
                NULL,
        },
        njt_json_define_null,
};

#endif
