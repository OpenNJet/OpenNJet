
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_conf_ext_module.h>
#include <njt_hash_util.h>

static void *
njt_conf_ext_create_main(njt_cycle_t *cycle)
{
    njt_conf_ext_t *conf;

    conf = njt_pcalloc(cycle->pool, sizeof(njt_conf_ext_t));
    if (conf == NULL)
    {
        return NULL;
    }
    conf->enabled = NJT_CONF_UNSET;
    return conf;
}

static njt_command_t njt_conf_ext_commands[] = {

    {njt_string("name_resolver"),
     NJT_MAIN_CONF |NJT_DIRECT_CONF|NJT_CONF_FLAG,
     njt_conf_set_flag_slot,
     0,
     offsetof(njt_conf_ext_t, enabled),
     NULL},
    njt_null_command};

static njt_core_module_t njt_conf_ext_module_ctx = {
    njt_string("name_resolver"),
    njt_conf_ext_create_main,
    NULL
};
njt_module_t njt_conf_ext_module = {
    NJT_MODULE_V1,
    &njt_conf_ext_module_ctx,  /* module context */
    njt_conf_ext_commands,     /* module directives */
    NJT_CORE_MODULE,                /* module type */
    NULL,                           /* init master */
    NULL,                           /* init module */
    NULL, /* init process */
    NULL,                           /* init thread */
    NULL,                           /* exit thread */
    NULL,                           /* exit process */
    NULL,                           /* exit master */
    NJT_MODULE_V1_PADDING};
