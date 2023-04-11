
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


typedef struct {
    size_t      sbrk_size;
} njt_http_degradation_main_conf_t;


typedef struct {
    njt_uint_t  degrade;
} njt_http_degradation_loc_conf_t;


static njt_conf_enum_t  njt_http_degrade[] = {
    { njt_string("204"), 204 },
    { njt_string("444"), 444 },
    { njt_null_string, 0 }
};


static void *njt_http_degradation_create_main_conf(njt_conf_t *cf);
static void *njt_http_degradation_create_loc_conf(njt_conf_t *cf);
static char *njt_http_degradation_merge_loc_conf(njt_conf_t *cf, void *parent,
    void *child);
static char *njt_http_degradation(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static njt_int_t njt_http_degradation_init(njt_conf_t *cf);


static njt_command_t  njt_http_degradation_commands[] = {

    { njt_string("degradation"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_TAKE1,
      njt_http_degradation,
      NJT_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { njt_string("degrade"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_enum_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_degradation_loc_conf_t, degrade),
      &njt_http_degrade },

      njt_null_command
};


static njt_http_module_t  njt_http_degradation_module_ctx = {
    NULL,                                  /* preconfiguration */
    njt_http_degradation_init,             /* postconfiguration */

    njt_http_degradation_create_main_conf, /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_degradation_create_loc_conf,  /* create location configuration */
    njt_http_degradation_merge_loc_conf    /* merge location configuration */
};


njt_module_t  njt_http_degradation_module = {
    NJT_MODULE_V1,
    &njt_http_degradation_module_ctx,      /* module context */
    njt_http_degradation_commands,         /* module directives */
    NJT_HTTP_MODULE,                       /* module type */
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
njt_http_degradation_handler(njt_http_request_t *r)
{
    njt_http_degradation_loc_conf_t  *dlcf;

    dlcf = njt_http_get_module_loc_conf(r, njt_http_degradation_module);

    if (dlcf->degrade && njt_http_degraded(r)) {
        return dlcf->degrade;
    }

    return NJT_DECLINED;
}


njt_uint_t
njt_http_degraded(njt_http_request_t *r)
{
    time_t                             now;
    njt_uint_t                         log;
    static size_t                      sbrk_size;
    static time_t                      sbrk_time;
    njt_http_degradation_main_conf_t  *dmcf;

    dmcf = njt_http_get_module_main_conf(r, njt_http_degradation_module);

    if (dmcf->sbrk_size) {

        log = 0;
        now = njt_time();

        /* lock mutex */

        if (now != sbrk_time) {

            /*
             * ELF/i386 is loaded at 0x08000000, 128M
             * ELF/amd64 is loaded at 0x00400000, 4M
             *
             * use a function address to subtract the loading address
             */

            sbrk_size = (size_t) sbrk(0) - ((uintptr_t) njt_palloc & ~0x3FFFFF);
            sbrk_time = now;
            log = 1;
        }

        /* unlock mutex */

        if (sbrk_size >= dmcf->sbrk_size) {
            if (log) {
                njt_log_error(NJT_LOG_NOTICE, r->connection->log, 0,
                              "degradation sbrk:%uzM",
                              sbrk_size / (1024 * 1024));
            }

            return 1;
        }
    }

    return 0;
}


static void *
njt_http_degradation_create_main_conf(njt_conf_t *cf)
{
    njt_http_degradation_main_conf_t  *dmcf;

    dmcf = njt_pcalloc(cf->pool, sizeof(njt_http_degradation_main_conf_t));
    if (dmcf == NULL) {
        return NULL;
    }

    return dmcf;
}


static void *
njt_http_degradation_create_loc_conf(njt_conf_t *cf)
{
    njt_http_degradation_loc_conf_t  *conf;

    conf = njt_palloc(cf->pool, sizeof(njt_http_degradation_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->degrade = NJT_CONF_UNSET_UINT;

    return conf;
}


static char *
njt_http_degradation_merge_loc_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_degradation_loc_conf_t  *prev = parent;
    njt_http_degradation_loc_conf_t  *conf = child;

    njt_conf_merge_uint_value(conf->degrade, prev->degrade, 0);

    return NJT_CONF_OK;
}


static char *
njt_http_degradation(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_degradation_main_conf_t  *dmcf = conf;

    njt_str_t  *value, s;

    value = cf->args->elts;

    if (njt_strncmp(value[1].data, "sbrk=", 5) == 0) {

        s.len = value[1].len - 5;
        s.data = value[1].data + 5;

        dmcf->sbrk_size = njt_parse_size(&s);
        if (dmcf->sbrk_size == (size_t) NJT_ERROR) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid sbrk size \"%V\"", &value[1]);
            return NJT_CONF_ERROR;
        }

        return NJT_CONF_OK;
    }

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\"", &value[1]);

    return NJT_CONF_ERROR;
}


static njt_int_t
njt_http_degradation_init(njt_conf_t *cf)
{
    njt_http_handler_pt        *h;
    njt_http_core_main_conf_t  *cmcf;

    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);

    h = njt_array_push(&cmcf->phases[NJT_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_http_degradation_handler;

    return NJT_OK;
}
