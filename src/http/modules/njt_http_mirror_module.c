
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


typedef struct {
    njt_array_t  *mirror;
    njt_flag_t    request_body;
} njt_http_mirror_loc_conf_t;


typedef struct {
    njt_int_t     status;
} njt_http_mirror_ctx_t;


static njt_int_t njt_http_mirror_handler(njt_http_request_t *r);
static void njt_http_mirror_body_handler(njt_http_request_t *r);
static njt_int_t njt_http_mirror_handler_internal(njt_http_request_t *r);
static void *njt_http_mirror_create_loc_conf(njt_conf_t *cf);
static char *njt_http_mirror_merge_loc_conf(njt_conf_t *cf, void *parent,
    void *child);
static char *njt_http_mirror(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static njt_int_t njt_http_mirror_init(njt_conf_t *cf);


static njt_command_t  njt_http_mirror_commands[] = {

    { njt_string("mirror"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_mirror,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("mirror_request_body"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_mirror_loc_conf_t, request_body),
      NULL },

      njt_null_command
};


static njt_http_module_t  njt_http_mirror_module_ctx = {
    NULL,                                  /* preconfiguration */
    njt_http_mirror_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_mirror_create_loc_conf,       /* create location configuration */
    njt_http_mirror_merge_loc_conf         /* merge location configuration */
};


njt_module_t  njt_http_mirror_module = {
    NJT_MODULE_V1,
    &njt_http_mirror_module_ctx,           /* module context */
    njt_http_mirror_commands,              /* module directives */
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
njt_http_mirror_handler(njt_http_request_t *r)
{
    njt_int_t                    rc;
    njt_http_mirror_ctx_t       *ctx;
    njt_http_mirror_loc_conf_t  *mlcf;

    if (r != r->main) {
        return NJT_DECLINED;
    }

    mlcf = njt_http_get_module_loc_conf(r, njt_http_mirror_module);

    if (mlcf->mirror == NULL) {
        return NJT_DECLINED;
    }

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0, "mirror handler");

    if (mlcf->request_body) {
        ctx = njt_http_get_module_ctx(r, njt_http_mirror_module);

        if (ctx) {
            return ctx->status;
        }

        ctx = njt_pcalloc(r->pool, sizeof(njt_http_mirror_ctx_t));
        if (ctx == NULL) {
            return NJT_ERROR;
        }

        ctx->status = NJT_DONE;

        njt_http_set_ctx(r, ctx, njt_http_mirror_module);

        rc = njt_http_read_client_request_body(r, njt_http_mirror_body_handler);
        if (rc >= NJT_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        njt_http_finalize_request(r, NJT_DONE);
        return NJT_DONE;
    }

    return njt_http_mirror_handler_internal(r);
}


static void
njt_http_mirror_body_handler(njt_http_request_t *r)
{
    njt_http_mirror_ctx_t  *ctx;

    ctx = njt_http_get_module_ctx(r, njt_http_mirror_module);

    ctx->status = njt_http_mirror_handler_internal(r);

    r->preserve_body = 1;

    r->write_event_handler = njt_http_core_run_phases;
    njt_http_core_run_phases(r);
}


static njt_int_t
njt_http_mirror_handler_internal(njt_http_request_t *r)
{
    njt_str_t                   *name;
    njt_uint_t                   i;
    njt_http_request_t          *sr;
    njt_http_mirror_loc_conf_t  *mlcf;

    mlcf = njt_http_get_module_loc_conf(r, njt_http_mirror_module);

    name = mlcf->mirror->elts;

    for (i = 0; i < mlcf->mirror->nelts; i++) {
        if (njt_http_subrequest(r, &name[i], &r->args, &sr, NULL,
                                NJT_HTTP_SUBREQUEST_BACKGROUND)
            != NJT_OK)
        {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        sr->header_only = 1;
        sr->method = r->method;
        sr->method_name = r->method_name;
    }

    return NJT_DECLINED;
}


static void *
njt_http_mirror_create_loc_conf(njt_conf_t *cf)
{
    njt_http_mirror_loc_conf_t  *mlcf;

    mlcf = njt_pcalloc(cf->pool, sizeof(njt_http_mirror_loc_conf_t));
    if (mlcf == NULL) {
        return NULL;
    }

    mlcf->mirror = NJT_CONF_UNSET_PTR;
    mlcf->request_body = NJT_CONF_UNSET;

    return mlcf;
}


static char *
njt_http_mirror_merge_loc_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_mirror_loc_conf_t *prev = parent;
    njt_http_mirror_loc_conf_t *conf = child;

    njt_conf_merge_ptr_value(conf->mirror, prev->mirror, NULL);
    njt_conf_merge_value(conf->request_body, prev->request_body, 1);

    return NJT_CONF_OK;
}


static char *
njt_http_mirror(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_mirror_loc_conf_t *mlcf = conf;

    njt_str_t  *value, *s;

    value = cf->args->elts;

    if (njt_strcmp(value[1].data, "off") == 0) {
        if (mlcf->mirror != NJT_CONF_UNSET_PTR) {
            return "is duplicate";
        }

        mlcf->mirror = NULL;
        return NJT_CONF_OK;
    }

    if (mlcf->mirror == NULL) {
        return "is duplicate";
    }

    if (mlcf->mirror == NJT_CONF_UNSET_PTR) {
        mlcf->mirror = njt_array_create(cf->pool, 4, sizeof(njt_str_t));
        if (mlcf->mirror == NULL) {
            return NJT_CONF_ERROR;
        }
    }

    s = njt_array_push(mlcf->mirror);
    if (s == NULL) {
        return NJT_CONF_ERROR;
    }

    *s = value[1];

    return NJT_CONF_OK;
}


static njt_int_t
njt_http_mirror_init(njt_conf_t *cf)
{
    njt_http_handler_pt        *h;
    njt_http_core_main_conf_t  *cmcf;

    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);

    h = njt_array_push(&cmcf->phases[NJT_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_http_mirror_handler;

    return NJT_OK;
}
