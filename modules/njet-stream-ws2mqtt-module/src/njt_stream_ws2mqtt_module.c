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

extern njt_module_t njt_stream_proto_server_module;
typedef struct {
    njt_flag_t      ws2mqtt_enabled;
}njt_stream_ws2mqtt_srv_conf_t;

static void *njt_stream_ws2mqtt_create_srv_conf(njt_conf_t *cf)
{
    njt_stream_ws2mqtt_srv_conf_t  *conf;
    conf = njt_pcalloc(cf->pool, sizeof(njt_stream_ws2mqtt_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    conf->ws2mqtt_enabled = NJT_CONF_UNSET;
    return conf;
}
static char *njt_stream_ws2mqtt_merge_srv_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_stream_ws2mqtt_srv_conf_t *prev = parent;
    njt_stream_ws2mqtt_srv_conf_t *conf = child;
    njt_stream_proto_server_srv_conf_t *proto_sscf;
    njt_conf_merge_value(conf->ws2mqtt_enabled, prev->ws2mqtt_enabled, 0);
    if (conf->ws2mqtt_enabled == 1)
    {
        proto_sscf = njt_stream_conf_get_module_srv_conf(cf, njt_stream_proto_server_module);
        if (proto_sscf)
        {
            if(proto_sscf->tcc_files != NJT_CONF_UNSET_PTR){
                 njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "conflict with proto_server_code_file direct!");
                return NJT_CONF_ERROR;
            }
            proto_sscf->connection_handler = proto_server_process_connection;
            proto_sscf->message_handler = proto_server_process_message;
            proto_sscf->abort_handler = proto_server_process_connection_close;
            proto_sscf->upstream_message_handler = proto_server_upstream_message;
            proto_sscf->build_client_message = create_proto_msg;
            proto_sscf->run_proto_message = run_proto_msg;
            proto_sscf->has_proto_message = has_proto_msg;
            proto_sscf->destroy_message = destroy_proto_msg;
        }
    }
    return NJT_CONF_OK;
}

static njt_command_t njt_stream_ws2mqtt_commands[] = {
    { njt_string("ws2mqtt"),
      NJT_STREAM_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_ws2mqtt_srv_conf_t, ws2mqtt_enabled),
      NULL },
    njt_null_command /* command termination */
};

/* The module context. */
static njt_stream_module_t njt_stream_ws2mqtt_module_ctx = {
    NULL, /* preconfiguration */
    NULL, /* postconfiguration */
    NULL,
    NULL, /* init main configuration */
    njt_stream_ws2mqtt_create_srv_conf, /* create server configuration */
    njt_stream_ws2mqtt_merge_srv_conf /* merge server configuration */

};

/* Module definition. */
njt_module_t njt_stream_ws2mqtt_module = {
    NJT_MODULE_V1,
    &njt_stream_ws2mqtt_module_ctx, /* module context */
    njt_stream_ws2mqtt_commands, /* module directives */
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
