
/*
 * Copyright (C) Pavel Pautov
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>
#include "njt_stream_proxy_protocol_tlv_module.h"



static njt_int_t njt_stream_proxy_protocol_tlv_handler(njt_stream_session_t *s);
static njt_int_t njt_stream_proxy_protocol_tlv_var(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data);
static njt_int_t njt_stream_proxy_protocol_tlv_init(njt_conf_t *cf);
static void *njt_stream_proxy_protocol_tlv_create_srv_conf(njt_conf_t *cf);
static char *njt_stream_proxy_protocol_set_tlv(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static char *
njt_stream_proxy_protocol_tlv_merge_srv_conf(njt_conf_t *cf, void *parent, void *child);
static char *proxy_session_protocol_var(njt_conf_t *cf, njt_command_t *cmd,
                                   void *conf);

static njt_command_t  njt_stream_proxy_protocol_tlv_commands[] = {

    { njt_string("proxy_pp2_set_tlv"),
      NJT_STREAM_SRV_CONF|NJT_CONF_TAKE2,
      njt_stream_proxy_protocol_set_tlv,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },
      { njt_string("proxy_pp2"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_proxy_protocol_tlv_srv_conf_t, enable),
      NULL },
       { njt_string("proxy_session_protocol_enable"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      proxy_session_protocol_var,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      njt_null_command
};


static njt_stream_module_t  njt_stream_proxy_protocol_tlv_module_ctx = {
    NULL,                                  /* preconfiguration */
    njt_stream_proxy_protocol_tlv_init,                   /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    njt_stream_proxy_protocol_tlv_create_srv_conf,        /* create server configuration */
    njt_stream_proxy_protocol_tlv_merge_srv_conf                                  /* merge server configuration */
};


njt_module_t  njt_stream_proxy_protocol_tlv_module = {
    NJT_MODULE_V1,
    &njt_stream_proxy_protocol_tlv_module_ctx,            /* module context */
    njt_stream_proxy_protocol_tlv_commands,               /* module directives */
    NJT_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};

static char *
njt_stream_proxy_protocol_tlv_merge_srv_conf(njt_conf_t *cf, void *parent, void *child) {

    njt_stream_proxy_protocol_tlv_srv_conf_t *prev = parent;
    njt_stream_proxy_protocol_tlv_srv_conf_t *conf = child;

    if (conf->enable == NJT_CONF_UNSET) {
        if (prev->enable == NJT_CONF_UNSET) {
            conf->enable = 0;

        } else {
            conf->enable = prev->enable;
        }
    }
    if (conf->commands.elts != NULL && conf->enable == 0){
         njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                          "no configure proxy_pp2  on,for proxy_pp2_set_tlv");
            return NJT_CONF_ERROR;
    }
     return NJT_CONF_OK;

}
static njt_int_t
njt_stream_proxy_protocol_tlv_handler(njt_stream_session_t *s)
{
    njt_str_t                     str;
    njt_uint_t                    i;
    njt_stream_proxy_protocol_tlv_cmd_t         *cmds;
    njt_stream_proxy_protocol_tlv_srv_conf_t    *scf;
    njt_stream_variable_value_t   vv;

    scf = njt_stream_get_module_srv_conf(s, njt_stream_proxy_protocol_tlv_module);
    cmds = scf->commands.elts;
    vv = njt_stream_variable_null_value;

    for (i = 0; i < scf->commands.nelts; i++) {
        if (njt_stream_complex_value(s, &cmds[i].value, &str) != NJT_OK) {
            return NJT_ERROR;
        }

        if (cmds[i].set_handler != NULL) {
            vv.len = str.len;
            vv.data = str.data;
            cmds[i].set_handler(s, &vv, cmds[i].data);

        } else {
            s->variables[cmds[i].index].len = str.len;
            s->variables[cmds[i].index].valid = 1;
            s->variables[cmds[i].index].no_cacheable = 0;
            s->variables[cmds[i].index].not_found = 0;
            s->variables[cmds[i].index].data = str.data;
        }
    }

    return NJT_DECLINED;
}


static njt_int_t
njt_stream_proxy_protocol_tlv_var(njt_stream_session_t *s, njt_stream_variable_value_t *v,
    uintptr_t data)
{
    *v = njt_stream_variable_null_value;

    return NJT_OK;
}


static njt_int_t
njt_stream_proxy_protocol_tlv_init(njt_conf_t *cf)
{
    njt_stream_handler_pt        *h;
    njt_stream_core_main_conf_t  *cmcf;

    cmcf = njt_stream_conf_get_module_main_conf(cf, njt_stream_core_module);

    h = njt_array_push(&cmcf->phases[NJT_STREAM_PREREAD_PHASE].handlers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_stream_proxy_protocol_tlv_handler;

    return NJT_OK;
}


static void *
njt_stream_proxy_protocol_tlv_create_srv_conf(njt_conf_t *cf)
{
    njt_stream_proxy_protocol_tlv_srv_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_stream_proxy_protocol_tlv_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    conf->enable = NJT_CONF_UNSET;
    conf->var_index = NJT_CONF_UNSET_UINT;
    /*
     * set by njt_pcalloc():
     *
     *     conf->commands = { NULL };
     */

    return conf;
}


static char *
njt_stream_proxy_protocol_set_tlv(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_stream_proxy_protocol_tlv_srv_conf_t  *scf = conf;

    njt_str_t                           *args;
    njt_int_t                            index;
    njt_stream_proxy_protocol_tlv_cmd_t                *set_cmd;
    njt_stream_variable_t               *v;
    njt_stream_compile_complex_value_t   ccv;
    njt_int_t                        type;
    args = cf->args->elts;

    if(args[1].len != 4) {
         njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                          "key:%V, must be in 0x00 -- 0xFF",&args[1]);
        return NJT_CONF_ERROR;
    }
     type = njt_hextoi(args[1].data+2,args[1].len -2);
       if (type == NJT_ERROR) {
             njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                          "key:%V, must be in 0x00 -- 0xFF",&args[1]);
            return NJT_CONF_ERROR;
        }

    v = njt_stream_add_variable(cf, &args[1],
                                NJT_STREAM_VAR_CHANGEABLE|NJT_STREAM_VAR_WEAK);
    if (v == NULL) {
        return NJT_CONF_ERROR;
    }

    index = njt_stream_get_variable_index(cf, &args[1]);
    if (index == NJT_ERROR) {
        return NJT_CONF_ERROR;
    }

    if (v->get_handler == NULL) {
        v->get_handler = njt_stream_proxy_protocol_tlv_var;
    }

    if (scf->commands.elts == NULL) {
        if (njt_array_init(&scf->commands, cf->pool, 1,
                           sizeof(njt_stream_proxy_protocol_tlv_cmd_t))
            != NJT_OK)
        {
            return NJT_CONF_ERROR;
        }
    }

    set_cmd = njt_array_push(&scf->commands);
    if (set_cmd == NULL) {
        return NJT_CONF_ERROR;
    }

    set_cmd->index = index;
    set_cmd->set_handler = v->set_handler;
    set_cmd->data = v->data;
    set_cmd->name = args[1];

    njt_memzero(&ccv, sizeof(njt_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &args[2];
    ccv.complex_value = &set_cmd->value;

    if (njt_stream_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}

static char *proxy_session_protocol_var(njt_conf_t *cf, njt_command_t *cmd,
                                   void *conf) {
    njt_str_t *value;
    njt_str_t variable;
    njt_stream_proxy_protocol_tlv_srv_conf_t *scf = conf;

    value = cf->args->elts;


     if ((u_char *)njt_strstr(value[1].data, "$") == value[1].data) {
         if (value[1].len <= sizeof("$") - 1) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "a variable must be indicated under "
                                   "\"name\" parameter.");
                return NJT_CONF_ERROR;
            }
            /* get the name of the variable */
            variable.len = value[1].len - sizeof("$") + 1;
            variable.data = value[1].data + sizeof("$") - 1;
            scf->var_index  = njt_stream_get_variable_index(cf, &variable);

     } else {
         njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "unknown parameter \"%V\"",
                           &value[0]);
        return NJT_CONF_ERROR;
     }

 //njt_stream_variable_value_t  *value;

    //value = njt_stream_get_indexed_variable(s, data);

    return NJT_CONF_OK;
}