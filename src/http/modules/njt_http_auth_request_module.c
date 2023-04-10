
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


typedef struct {
    njt_str_t                 uri;
    njt_array_t              *vars;
} njt_http_auth_request_conf_t;


typedef struct {
    njt_uint_t                done;
    njt_uint_t                status;
    njt_http_request_t       *subrequest;
} njt_http_auth_request_ctx_t;


typedef struct {
    njt_int_t                 index;
    njt_http_complex_value_t  value;
    njt_http_set_variable_pt  set_handler;
} njt_http_auth_request_variable_t;


static njt_int_t njt_http_auth_request_handler(njt_http_request_t *r);
static njt_int_t njt_http_auth_request_done(njt_http_request_t *r,
    void *data, njt_int_t rc);
static njt_int_t njt_http_auth_request_set_variables(njt_http_request_t *r,
    njt_http_auth_request_conf_t *arcf, njt_http_auth_request_ctx_t *ctx);
static njt_int_t njt_http_auth_request_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static void *njt_http_auth_request_create_conf(njt_conf_t *cf);
static char *njt_http_auth_request_merge_conf(njt_conf_t *cf,
    void *parent, void *child);
static njt_int_t njt_http_auth_request_init(njt_conf_t *cf);
static char *njt_http_auth_request(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_auth_request_set(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);


static njt_command_t  njt_http_auth_request_commands[] = {

    { njt_string("auth_request"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_auth_request,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("auth_request_set"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE2,
      njt_http_auth_request_set,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      njt_null_command
};


static njt_http_module_t  njt_http_auth_request_module_ctx = {
    NULL,                                  /* preconfiguration */
    njt_http_auth_request_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_auth_request_create_conf,     /* create location configuration */
    njt_http_auth_request_merge_conf       /* merge location configuration */
};


njt_module_t  njt_http_auth_request_module = {
    NJT_MODULE_V1,
    &njt_http_auth_request_module_ctx,     /* module context */
    njt_http_auth_request_commands,        /* module directives */
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
njt_http_auth_request_handler(njt_http_request_t *r)
{
    njt_table_elt_t               *h, *ho, **ph;
    njt_http_request_t            *sr;
    njt_http_post_subrequest_t    *ps;
    njt_http_auth_request_ctx_t   *ctx;
    njt_http_auth_request_conf_t  *arcf;

    arcf = njt_http_get_module_loc_conf(r, njt_http_auth_request_module);

    if (arcf->uri.len == 0) {
        return NJT_DECLINED;
    }

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth request handler");

    ctx = njt_http_get_module_ctx(r, njt_http_auth_request_module);

    if (ctx != NULL) {
        if (!ctx->done) {
            return NJT_AGAIN;
        }

        /*
         * as soon as we are done - explicitly set variables to make
         * sure they will be available after internal redirects
         */

        if (njt_http_auth_request_set_variables(r, arcf, ctx) != NJT_OK) {
            return NJT_ERROR;
        }

        /* return appropriate status */

        if (ctx->status == NJT_HTTP_FORBIDDEN) {
            return ctx->status;
        }

        if (ctx->status == NJT_HTTP_UNAUTHORIZED) {
            sr = ctx->subrequest;

            h = sr->headers_out.www_authenticate;

            if (!h && sr->upstream) {
                h = sr->upstream->headers_in.www_authenticate;
            }

            ph = &r->headers_out.www_authenticate;

            while (h) {
                ho = njt_list_push(&r->headers_out.headers);
                if (ho == NULL) {
                    return NJT_ERROR;
                }

                *ho = *h;
                ho->next = NULL;

                *ph = ho;
                ph = &ho->next;

                h = h->next;
            }

            return ctx->status;
        }

        if (ctx->status >= NJT_HTTP_OK
            && ctx->status < NJT_HTTP_SPECIAL_RESPONSE)
        {
            return NJT_OK;
        }

        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "auth request unexpected status: %ui", ctx->status);

        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = njt_pcalloc(r->pool, sizeof(njt_http_auth_request_ctx_t));
    if (ctx == NULL) {
        return NJT_ERROR;
    }

    ps = njt_palloc(r->pool, sizeof(njt_http_post_subrequest_t));
    if (ps == NULL) {
        return NJT_ERROR;
    }

    ps->handler = njt_http_auth_request_done;
    ps->data = ctx;

    if (njt_http_subrequest(r, &arcf->uri, NULL, &sr, ps,
                            NJT_HTTP_SUBREQUEST_WAITED)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    /*
     * allocate fake request body to avoid attempts to read it and to make
     * sure real body file (if already read) won't be closed by upstream
     */

    sr->request_body = njt_pcalloc(r->pool, sizeof(njt_http_request_body_t));
    if (sr->request_body == NULL) {
        return NJT_ERROR;
    }

    sr->header_only = 1;

    ctx->subrequest = sr;

    njt_http_set_ctx(r, ctx, njt_http_auth_request_module);

    return NJT_AGAIN;
}


static njt_int_t
njt_http_auth_request_done(njt_http_request_t *r, void *data, njt_int_t rc)
{
    njt_http_auth_request_ctx_t   *ctx = data;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth request done s:%ui", r->headers_out.status);

    ctx->done = 1;
    ctx->status = r->headers_out.status;

    return rc;
}


static njt_int_t
njt_http_auth_request_set_variables(njt_http_request_t *r,
    njt_http_auth_request_conf_t *arcf, njt_http_auth_request_ctx_t *ctx)
{
    njt_str_t                          val;
    njt_http_variable_t               *v;
    njt_http_variable_value_t         *vv;
    njt_http_auth_request_variable_t  *av, *last;
    njt_http_core_main_conf_t         *cmcf;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth request set variables");

    if (arcf->vars == NULL) {
        return NJT_OK;
    }

    cmcf = njt_http_get_module_main_conf(r, njt_http_core_module);
    v = cmcf->variables.elts;

    av = arcf->vars->elts;
    last = av + arcf->vars->nelts;

    while (av < last) {
        /*
         * explicitly set new value to make sure it will be available after
         * internal redirects
         */

        vv = &r->variables[av->index];

        if (njt_http_complex_value(ctx->subrequest, &av->value, &val)
            != NJT_OK)
        {
            return NJT_ERROR;
        }

        vv->valid = 1;
        vv->not_found = 0;
        vv->data = val.data;
        vv->len = val.len;

        if (av->set_handler) {
            /*
             * set_handler only available in cmcf->variables_keys, so we store
             * it explicitly
             */

            av->set_handler(r, vv, v[av->index].data);
        }

        av++;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_auth_request_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth request variable");

    v->not_found = 1;

    return NJT_OK;
}


static void *
njt_http_auth_request_create_conf(njt_conf_t *cf)
{
    njt_http_auth_request_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_auth_request_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     conf->uri = { 0, NULL };
     */

    conf->vars = NJT_CONF_UNSET_PTR;

    return conf;
}


static char *
njt_http_auth_request_merge_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_auth_request_conf_t *prev = parent;
    njt_http_auth_request_conf_t *conf = child;

    njt_conf_merge_str_value(conf->uri, prev->uri, "");
    njt_conf_merge_ptr_value(conf->vars, prev->vars, NULL);

    return NJT_CONF_OK;
}


static njt_int_t
njt_http_auth_request_init(njt_conf_t *cf)
{
    njt_http_handler_pt        *h;
    njt_http_core_main_conf_t  *cmcf;

    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);

    h = njt_array_push(&cmcf->phases[NJT_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_http_auth_request_handler;

    return NJT_OK;
}


static char *
njt_http_auth_request(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_auth_request_conf_t *arcf = conf;

    njt_str_t        *value;

    if (arcf->uri.data != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (njt_strcmp(value[1].data, "off") == 0) {
        arcf->uri.len = 0;
        arcf->uri.data = (u_char *) "";

        return NJT_CONF_OK;
    }

    arcf->uri = value[1];

    return NJT_CONF_OK;
}


static char *
njt_http_auth_request_set(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_auth_request_conf_t *arcf = conf;

    njt_str_t                         *value;
    njt_http_variable_t               *v;
    njt_http_auth_request_variable_t  *av;
    njt_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (value[1].data[0] != '$') {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &value[1]);
        return NJT_CONF_ERROR;
    }

    value[1].len--;
    value[1].data++;

    if (arcf->vars == NJT_CONF_UNSET_PTR) {
        arcf->vars = njt_array_create(cf->pool, 1,
                                      sizeof(njt_http_auth_request_variable_t));
        if (arcf->vars == NULL) {
            return NJT_CONF_ERROR;
        }
    }

    av = njt_array_push(arcf->vars);
    if (av == NULL) {
        return NJT_CONF_ERROR;
    }

    v = njt_http_add_variable(cf, &value[1], NJT_HTTP_VAR_CHANGEABLE);
    if (v == NULL) {
        return NJT_CONF_ERROR;
    }

    av->index = njt_http_get_variable_index(cf, &value[1]);
    if (av->index == NJT_ERROR) {
        return NJT_CONF_ERROR;
    }

    if (v->get_handler == NULL) {
        v->get_handler = njt_http_auth_request_variable;
        v->data = (uintptr_t) av;
    }

    av->set_handler = v->set_handler;

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &av->value;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}
