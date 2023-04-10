
/*
 * Copyright (C) Pavel Pautov
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>


typedef struct {
    njt_int_t                   index;
    njt_stream_set_variable_pt  set_handler;
    uintptr_t                   data;
    njt_stream_complex_value_t  value;
} njt_stream_set_cmd_t;


typedef struct {
    njt_array_t                 commands;
} njt_stream_set_srv_conf_t;


static njt_int_t njt_stream_set_handler(njt_stream_session_t *s);
static njt_int_t njt_stream_set_var(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data);
static njt_int_t njt_stream_set_init(njt_conf_t *cf);
static void *njt_stream_set_create_srv_conf(njt_conf_t *cf);
static char *njt_stream_set(njt_conf_t *cf, njt_command_t *cmd, void *conf);


static njt_command_t  njt_stream_set_commands[] = {

    { njt_string("set"),
      NJT_STREAM_SRV_CONF|NJT_CONF_TAKE2,
      njt_stream_set,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      njt_null_command
};


static njt_stream_module_t  njt_stream_set_module_ctx = {
    NULL,                                  /* preconfiguration */
    njt_stream_set_init,                   /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    njt_stream_set_create_srv_conf,        /* create server configuration */
    NULL                                   /* merge server configuration */
};


njt_module_t  njt_stream_set_module = {
    NJT_MODULE_V1,
    &njt_stream_set_module_ctx,            /* module context */
    njt_stream_set_commands,               /* module directives */
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


static njt_int_t
njt_stream_set_handler(njt_stream_session_t *s)
{
    njt_str_t                     str;
    njt_uint_t                    i;
    njt_stream_set_cmd_t         *cmds;
    njt_stream_set_srv_conf_t    *scf;
    njt_stream_variable_value_t   vv;

    scf = njt_stream_get_module_srv_conf(s, njt_stream_set_module);
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
njt_stream_set_var(njt_stream_session_t *s, njt_stream_variable_value_t *v,
    uintptr_t data)
{
    *v = njt_stream_variable_null_value;

    return NJT_OK;
}


static njt_int_t
njt_stream_set_init(njt_conf_t *cf)
{
    njt_stream_handler_pt        *h;
    njt_stream_core_main_conf_t  *cmcf;

    cmcf = njt_stream_conf_get_module_main_conf(cf, njt_stream_core_module);

    h = njt_array_push(&cmcf->phases[NJT_STREAM_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_stream_set_handler;

    return NJT_OK;
}


static void *
njt_stream_set_create_srv_conf(njt_conf_t *cf)
{
    njt_stream_set_srv_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_stream_set_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     conf->commands = { NULL };
     */

    return conf;
}


static char *
njt_stream_set(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_stream_set_srv_conf_t  *scf = conf;

    njt_str_t                           *args;
    njt_int_t                            index;
    njt_stream_set_cmd_t                *set_cmd;
    njt_stream_variable_t               *v;
    njt_stream_compile_complex_value_t   ccv;

    args = cf->args->elts;

    if (args[1].data[0] != '$') {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &args[1]);
        return NJT_CONF_ERROR;
    }

    args[1].len--;
    args[1].data++;

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
        v->get_handler = njt_stream_set_var;
    }

    if (scf->commands.elts == NULL) {
        if (njt_array_init(&scf->commands, cf->pool, 1,
                           sizeof(njt_stream_set_cmd_t))
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

    njt_memzero(&ccv, sizeof(njt_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &args[2];
    ccv.complex_value = &set_cmd->value;

    if (njt_stream_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}
