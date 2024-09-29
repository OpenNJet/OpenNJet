/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */
#ifndef NJT_STREAM_PROTO_SERVER_MODULE_H_   
#define NJT_STREAM_PROTO_SERVER_MODULE_H_
#include <njt_core.h>
#include "libtcc.h"
#include "njt_tcc.h"

extern njt_module_t  njt_stream_proto_server_module;
typedef int (*njt_proto_server_handler_pt)(tcc_stream_request_t *r);
typedef int (*njt_proto_server_data_handler_pt)(tcc_stream_request_t *r, tcc_str_t *msg);
typedef int (*njt_proto_server_update_pt)(tcc_stream_server_ctx *srv_ctx);
typedef int (*njt_proto_server_build_message_pt)(tcc_stream_server_ctx *srv_ctx,void *in_data,tcc_str_t *out_data);
typedef void* (*njt_script_upstream_peer_pt)(tcc_stream_client_upstream_data_t *cli_ups_info);
njt_int_t  njt_stream_proto_server_init_upstream(njt_stream_session_t *s);
njt_int_t njt_stream_proto_server_process_proxy_message(njt_stream_session_t *s, njt_buf_t *b, njt_uint_t from_upstream);
typedef int (*njt_proto_create_msg_handler_pt)(tcc_stream_request_t *r, tcc_str_t *msg);  //create
typedef int (*njt_proto_process_msg_handler_pt)(tcc_stream_request_t *r, void *ctx);
typedef int (*njt_proto_destory_msg_handler_pt)(tcc_stream_request_t *r);



typedef struct
{
    njt_chain_t *out_chain;
    njt_chain_t  *from_upstream;
    njt_chain_t  *from_downstream;
    njt_chain_t *out_busy;
    njt_buf_t out_buf;
    tcc_stream_request_t r;
    njt_chain_t *free;
    njt_event_t timer;
    ucontext_t runctx, main_ctx;
    u_char *run_stak;
    njt_int_t  pending; //没有：NJT_DECLINED  pending：NJT_AGAIN, 超时回调：NJT_OK
    njt_event_t  wake;
    njt_msec_t mtask_timeout;
} njt_stream_proto_server_client_ctx_t;
typedef struct
{
    njt_array_t srv_info;

} njt_stream_proto_server_main_conf_t;

typedef struct
{
    njt_flag_t proto_server_enabled;
    TCCState *s;
    njt_array_t  *tcc_files;
    tcc_stream_server_ctx srv_ctx;
    njt_event_t timer;
    size_t buffer_size;
    size_t session_max_mem_size;
    njt_msec_t connect_timeout;
    njt_msec_t client_update_interval;
    njt_msec_t server_update_interval;
    njt_proto_server_handler_pt connection_handler;
    njt_proto_server_data_handler_pt preread_handler;
    njt_proto_server_handler_pt log_handler;
    njt_proto_server_data_handler_pt message_handler;
    njt_proto_server_handler_pt abort_handler;
    njt_proto_server_update_pt server_update_handler;
    njt_proto_server_update_pt server_init_handler;
    njt_proto_server_data_handler_pt client_update_handler;
    njt_proto_server_build_message_pt  build_proto_message;

    njt_proto_create_msg_handler_pt    build_client_message;
    njt_proto_process_msg_handler_pt   run_proto_message;
    njt_proto_process_msg_handler_pt   has_proto_message;
    njt_proto_destory_msg_handler_pt   destroy_message;
    
   
    //upstream
    njt_flag_t proto_upstream_enabled;
    njt_flag_t proto_pass_enabled;
    njt_stream_upstream_init_pt original_init_upstream;
    njt_stream_upstream_init_peer_pt original_init_peer;
    njt_script_upstream_peer_pt check_upstream_peer_handler;
     njt_proto_server_data_handler_pt upstream_message_handler;
    njt_proto_server_handler_pt upstream_abort_handler;

    //mtask
    size_t stack_size;

	njt_msec_t mtask_timeout;

} njt_stream_proto_server_srv_conf_t;

typedef struct
{
    void *data;
    njt_stream_proto_server_srv_conf_t *conf;
    njt_stream_session_t *s;
    njt_event_free_peer_pt original_free_peer;
    njt_event_get_peer_pt original_get_peer; //njt_event_notify_peer_pt         notify;
    njt_event_notify_peer_pt original_notify;

} njt_stream_proto_upstream_peer_data_t;
#endif
