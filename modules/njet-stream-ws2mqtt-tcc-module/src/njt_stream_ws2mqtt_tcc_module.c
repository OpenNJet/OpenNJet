/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_stream.h>
#include <njt_stream_proto_server_module.h>
#include "ws2mqtt_jit.c"

static njt_stream_proto_tcc_handler_t  njt_stream_ws2mqtt_handle = {
    proto_server_process_connection,  /*njt_proto_server_handler_pt connection_handler;*/
    NULL,  /*njt_proto_server_data_handler_pt preread_handler;*/
    NULL,  /*njt_proto_server_handler_pt log_handler;*/
    proto_server_process_message,/*njt_proto_server_data_handler_pt message_handler;*/
    proto_server_process_connection_close,/*njt_proto_server_handler_pt abort_handler;*/
    NULL, /*njt_proto_server_data_handler_pt client_update_handler;*/
    NULL, /*njt_proto_server_update_pt server_update_handler;*/
    NULL, /*njt_proto_server_update_pt server_init_handler;*/
    NULL, /*njt_proto_server_build_message_pt  build_proto_message;*/
    proto_server_upstream_message,/*njt_proto_server_data_handler_pt upstream_message_handler;*/
    NULL, /*njt_script_upstream_peer_pt check_upstream_peer_handler;*/
    create_proto_msg,/*njt_proto_create_msg_handler_pt    build_client_message;*/
    run_proto_msg,/*njt_proto_process_msg_handler_pt   run_proto_message;*/
    has_proto_msg,/*njt_proto_process_msg_handler_pt   has_proto_message;*/
    destroy_proto_msg,/*njt_proto_process_msg_handler_pt   destroy_message;*/
    NULL, /*njt_proto_set_session_handler_pt  set_session_handler;*/
    NULL, /*njt_proto_server_update_pt server_process_init_handler;*/
    NULL, /*njt_proto_server_update_pt server_process_exit_handler;*/
    NULL, /*njt_proto_server_handler_pt upstream_abort_handler;*/
}; 

njt_stream_proto_tcc_handler_t *njt_stream_ws2mqtt_tcc_module_so[] = {
    &njt_stream_ws2mqtt_handle,
    NULL
};

static njt_int_t
njt_stream_ws2mqtt_tcc_module_preconfiguration(njt_conf_t *cf){
     njt_conf_log_error(NJT_LOG_ERR, cf,0,"can`t load tcc 'njt_stream_ws2mqtt_tcc_module.so'!");
     return NJT_ERROR;
}
/* The module context. */
static njt_stream_module_t njt_stream_ws2mqtt_tcc_module_ctx = {
    njt_stream_ws2mqtt_tcc_module_preconfiguration,                         /* preconfiguration */
    NULL, /* postconfiguration */
    NULL,
    NULL,                                    /* init main configuration */
    NULL, /* create server configuration */
    NULL   /* merge server configuration */

};

/* Module definition. */
njt_module_t njt_stream_ws2mqtt_tcc_module = {
    NJT_MODULE_V1,
    &njt_stream_ws2mqtt_tcc_module_ctx, /* module context */
    NULL, /* module directives */
    NJT_STREAM_MODULE, /* module type */
    NULL, /* init master */
    NULL, /* init module */
    NULL, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    NULL, /* exit master */
    NJT_MODULE_V1_PADDING
};
