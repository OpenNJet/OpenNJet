/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */
#ifndef NJT_STREAM_PROXY_PROTOCOL_TLV_MODULE_H_   
#define NJT_STREAM_PROXY_PROTOCOL_TLV_MODULE_H_
#include <njt_core.h>

typedef struct {
    njt_int_t                   index;
    njt_stream_set_variable_pt  set_handler;
    uintptr_t                   data;
    njt_stream_complex_value_t  value;
    njt_str_t                   name;
} njt_stream_proxy_protocol_tlv_cmd_t;


typedef struct {
    njt_flag_t     enable;
    njt_array_t    commands;
    njt_uint_t     var_index;
} njt_stream_proxy_protocol_tlv_srv_conf_t;

extern njt_module_t  njt_stream_proxy_protocol_tlv_module;
#endif
