
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>





static void *njt_http_rewrite_create_loc_conf(njt_conf_t *cf);
static char *njt_http_rewrite_merge_loc_conf(njt_conf_t *cf,
    void *parent, void *child);
static njt_int_t njt_http_rewrite_init(njt_conf_t *cf);
static char *njt_http_rewrite(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static char *njt_http_rewrite_return(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_rewrite_break(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_rewrite_if(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char * njt_http_rewrite_if_condition(njt_conf_t *cf,
    njt_http_rewrite_loc_conf_t *lcf);
static char *njt_http_rewrite_variable(njt_conf_t *cf,
    njt_http_rewrite_loc_conf_t *lcf, njt_str_t *value);
static char *njt_http_rewrite_set(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char * njt_http_rewrite_value(njt_conf_t *cf,
    njt_http_rewrite_loc_conf_t *lcf, njt_str_t *value);


static njt_command_t  njt_http_rewrite_commands[] = {

    { njt_string("rewrite"),
      NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                       |NJT_CONF_TAKE23,
      njt_http_rewrite,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("return"),
      NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                       |NJT_CONF_TAKE12,
      njt_http_rewrite_return,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("break"),
      NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                       |NJT_CONF_NOARGS,
      njt_http_rewrite_break,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("if"),
      NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_BLOCK|NJT_CONF_1MORE,
      njt_http_rewrite_if,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("set"),
      NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                       |NJT_CONF_TAKE2,
      njt_http_rewrite_set,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("rewrite_log"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF|NJT_HTTP_LOC_CONF
                        |NJT_HTTP_LIF_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_rewrite_loc_conf_t, log),
      NULL },

    { njt_string("uninitialized_variable_warn"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF|NJT_HTTP_LOC_CONF
                        |NJT_HTTP_LIF_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_rewrite_loc_conf_t, uninitialized_variable_warn),
      NULL },

      njt_null_command
};


static njt_http_module_t  njt_http_rewrite_module_ctx = {
    NULL,                                  /* preconfiguration */
    njt_http_rewrite_init,                 /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_rewrite_create_loc_conf,      /* create location configuration */
    njt_http_rewrite_merge_loc_conf        /* merge location configuration */
};


njt_module_t  njt_http_rewrite_module = {
    NJT_MODULE_V1,
    &njt_http_rewrite_module_ctx,          /* module context */
    njt_http_rewrite_commands,             /* module directives */
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
njt_http_rewrite_handler(njt_http_request_t *r)
{
    njt_int_t                     index;
    njt_http_script_code_pt       code;
    njt_http_script_engine_t     *e;
    njt_http_core_srv_conf_t     *cscf;
    njt_http_core_main_conf_t    *cmcf;
    njt_http_rewrite_loc_conf_t  *rlcf;

    cmcf = njt_http_get_module_main_conf(r, njt_http_core_module);
    cscf = njt_http_get_module_srv_conf(r, njt_http_core_module);
    index = cmcf->phase_engine.location_rewrite_index;

    if (r->phase_handler == index && r->loc_conf == cscf->ctx->loc_conf) {
        /* skipping location rewrite phase for server null location */
        return NJT_DECLINED;
    }

    rlcf = njt_http_get_module_loc_conf(r, njt_http_rewrite_module);

    if (rlcf->codes == NULL) {
        return NJT_DECLINED;
    }

    e = njt_pcalloc(r->pool, sizeof(njt_http_script_engine_t));
    if (e == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    e->sp = njt_pcalloc(r->pool,
                        rlcf->stack_size * sizeof(njt_http_variable_value_t));
    if (e->sp == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    e->ip = rlcf->codes->elts;
    e->request = r;
    e->quote = 1;
    e->log = rlcf->log;
    e->status = NJT_DECLINED;

    while (*(uintptr_t *) e->ip) {
        code = *(njt_http_script_code_pt *) e->ip;
        code(e);
    }

    return e->status;
}


static njt_int_t
njt_http_rewrite_var(njt_http_request_t *r, njt_http_variable_value_t *v,
    uintptr_t data)
{
    njt_http_variable_t          *var;
    njt_http_core_main_conf_t    *cmcf;
    njt_http_rewrite_loc_conf_t  *rlcf;

    rlcf = njt_http_get_module_loc_conf(r, njt_http_rewrite_module);

    if (rlcf->uninitialized_variable_warn == 0) {
        *v = njt_http_variable_null_value;
        return NJT_OK;
    }

    cmcf = njt_http_get_module_main_conf(r, njt_http_core_module);

    var = cmcf->variables.elts;

    /*
     * the njt_http_rewrite_module sets variables directly in r->variables,
     * and they should be handled by njt_http_get_indexed_variable(),
     * so the handler is called only if the variable is not initialized
     */

    njt_log_error(NJT_LOG_WARN, r->connection->log, 0,
                  "using uninitialized \"%V\" variable", &var[data].name);

    *v = njt_http_variable_null_value;

    return NJT_OK;
}


static void *
njt_http_rewrite_create_loc_conf(njt_conf_t *cf)
{
    njt_http_rewrite_loc_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_rewrite_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->stack_size = NJT_CONF_UNSET_UINT;
    conf->log = NJT_CONF_UNSET;
    conf->uninitialized_variable_warn = NJT_CONF_UNSET;

    return conf;
}


static char *
njt_http_rewrite_merge_loc_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_rewrite_loc_conf_t *prev = parent;
    njt_http_rewrite_loc_conf_t *conf = child;

    uintptr_t  *code;

    njt_conf_merge_value(conf->log, prev->log, 0);
    njt_conf_merge_value(conf->uninitialized_variable_warn,
                         prev->uninitialized_variable_warn, 1);
    njt_conf_merge_uint_value(conf->stack_size, prev->stack_size, 10);

    if (conf->codes == NULL) {
        return NJT_CONF_OK;
    }

    if (conf->codes == prev->codes) {
        return NJT_CONF_OK;
    }

    code = njt_array_push_n(conf->codes, sizeof(uintptr_t));
    if (code == NULL) {
        return NJT_CONF_ERROR;
    }

    *code = (uintptr_t) NULL;

    return NJT_CONF_OK;
}


static njt_int_t
njt_http_rewrite_init(njt_conf_t *cf)
{
    njt_http_handler_pt        *h;
    njt_http_core_main_conf_t  *cmcf;

    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);

    h = njt_array_push(&cmcf->phases[NJT_HTTP_SERVER_REWRITE_PHASE].handlers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_http_rewrite_handler;

    h = njt_array_push(&cmcf->phases[NJT_HTTP_REWRITE_PHASE].handlers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_http_rewrite_handler;

    return NJT_OK;
}


static char *
njt_http_rewrite(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_rewrite_loc_conf_t  *lcf = conf;

    njt_str_t                         *value;
    njt_uint_t                         last;
    njt_regex_compile_t                rc;
    njt_http_script_code_pt           *code;
    njt_http_script_compile_t          sc;
    njt_http_script_regex_code_t      *regex;
    njt_http_script_regex_end_code_t  *regex_end;
    u_char                             errstr[NJT_MAX_CONF_ERRSTR];

    regex = njt_http_script_start_code(cf->pool, &lcf->codes,
                                       sizeof(njt_http_script_regex_code_t));
    if (regex == NULL) {
        return NJT_CONF_ERROR;
    }

    njt_memzero(regex, sizeof(njt_http_script_regex_code_t));

    value = cf->args->elts;

    if (value[2].len == 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "empty replacement");
        return NJT_CONF_ERROR;
    }

    njt_memzero(&rc, sizeof(njt_regex_compile_t));

    rc.pattern = value[1];
    rc.err.len = NJT_MAX_CONF_ERRSTR;
    rc.err.data = errstr;

    /* TODO: NJT_REGEX_CASELESS */

    regex->regex = njt_http_regex_compile(cf, &rc);
    if (regex->regex == NULL) {
        return NJT_CONF_ERROR;
    }

    regex->code = njt_http_script_regex_start_code;
    regex->uri = 1;
    regex->name = value[1];

    if (value[2].data[value[2].len - 1] == '?') {

        /* the last "?" drops the original arguments */
        value[2].len--;

    } else {
        regex->add_args = 1;
    }

    last = 0;

    if (njt_strncmp(value[2].data, "http://", sizeof("http://") - 1) == 0
        || njt_strncmp(value[2].data, "https://", sizeof("https://") - 1) == 0
        || njt_strncmp(value[2].data, "$scheme", sizeof("$scheme") - 1) == 0)
    {
        regex->status = NJT_HTTP_MOVED_TEMPORARILY;
        regex->redirect = 1;
        last = 1;
    }

    if (cf->args->nelts == 4) {
        if (njt_strcmp(value[3].data, "last") == 0) {
            last = 1;

        } else if (njt_strcmp(value[3].data, "break") == 0) {
            regex->break_cycle = 1;
            last = 1;

        } else if (njt_strcmp(value[3].data, "redirect") == 0) {
            regex->status = NJT_HTTP_MOVED_TEMPORARILY;
            regex->redirect = 1;
            last = 1;

        } else if (njt_strcmp(value[3].data, "permanent") == 0) {
            regex->status = NJT_HTTP_MOVED_PERMANENTLY;
            regex->redirect = 1;
            last = 1;

        } else {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[3]);
            return NJT_CONF_ERROR;
        }
    }

    njt_memzero(&sc, sizeof(njt_http_script_compile_t));

    sc.cf = cf;
    sc.source = &value[2];
    sc.lengths = &regex->lengths;
    sc.values = &lcf->codes;
    sc.variables = njt_http_script_variables_count(&value[2]);
    sc.main = regex;
    sc.complete_lengths = 1;
    sc.compile_args = !regex->redirect;

    if (njt_http_script_compile(&sc) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    regex = sc.main;

    regex->size = sc.size;
    regex->args = sc.args;

    if (sc.variables == 0 && !sc.dup_capture) {
        regex->lengths = NULL;
    }

    regex_end = njt_http_script_add_code(lcf->codes,
                                      sizeof(njt_http_script_regex_end_code_t),
                                      &regex);
    if (regex_end == NULL) {
        return NJT_CONF_ERROR;
    }

    regex_end->code = njt_http_script_regex_end_code;
    regex_end->uri = regex->uri;
    regex_end->args = regex->args;
    regex_end->add_args = regex->add_args;
    regex_end->redirect = regex->redirect;

    if (last) {
        code = njt_http_script_add_code(lcf->codes, sizeof(uintptr_t), &regex);
        if (code == NULL) {
            return NJT_CONF_ERROR;
        }

        *code = NULL;
    }

    regex->next = (u_char *) lcf->codes->elts + lcf->codes->nelts
                                              - (u_char *) regex;

    return NJT_CONF_OK;
}


static char *
njt_http_rewrite_return(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_rewrite_loc_conf_t  *lcf = conf;

    u_char                            *p;
    njt_str_t                         *value, *v;
    njt_http_script_return_code_t     *ret;
    njt_http_compile_complex_value_t   ccv;

    ret = njt_http_script_start_code(cf->pool, &lcf->codes,
                                     sizeof(njt_http_script_return_code_t));
    if (ret == NULL) {
        return NJT_CONF_ERROR;
    }

    value = cf->args->elts;

    njt_memzero(ret, sizeof(njt_http_script_return_code_t));

    ret->code = njt_http_script_return_code;

    p = value[1].data;

    ret->status = njt_atoi(p, value[1].len);

    if (ret->status == (uintptr_t) NJT_ERROR) {

        if (cf->args->nelts == 2
            && (njt_strncmp(p, "http://", sizeof("http://") - 1) == 0
                || njt_strncmp(p, "https://", sizeof("https://") - 1) == 0
                || njt_strncmp(p, "$scheme", sizeof("$scheme") - 1) == 0))
        {
            ret->status = NJT_HTTP_MOVED_TEMPORARILY;
            v = &value[1];

        } else {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid return code \"%V\"", &value[1]);
            return NJT_CONF_ERROR;
        }

    } else {

        if (ret->status > 999) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid return code \"%V\"", &value[1]);
            return NJT_CONF_ERROR;
        }

        if (cf->args->nelts == 2) {
            return NJT_CONF_OK;
        }

        v = &value[2];
    }

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = v;
    ccv.complex_value = &ret->text;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


static char *
njt_http_rewrite_break(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_rewrite_loc_conf_t *lcf = conf;

    njt_http_script_code_pt  *code;

    code = njt_http_script_start_code(cf->pool, &lcf->codes, sizeof(uintptr_t));
    if (code == NULL) {
        return NJT_CONF_ERROR;
    }

    *code = njt_http_script_break_code;

    return NJT_CONF_OK;
}


static char *
njt_http_rewrite_if(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_rewrite_loc_conf_t  *lcf = conf;

    void                         *mconf;
    char                         *rv;
    u_char                       *elts;
    njt_uint_t                    i;
    njt_conf_t                    save;
    njt_http_module_t            *module;
    njt_http_conf_ctx_t          *ctx, *pctx;
    njt_http_core_loc_conf_t     *clcf, *pclcf;
    njt_http_script_if_code_t    *if_code;
    njt_http_rewrite_loc_conf_t  *nlcf;
    // by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
    njt_pool_t *old_pool,*new_pool,*old_temp_pool;
    njt_int_t rc;

    old_pool = cf->pool;
    old_temp_pool = cf->temp_pool;
    new_pool = njt_create_dynamic_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
    if (new_pool == NULL) {
        return NJT_CONF_ERROR;
    }
    rc = njt_sub_pool(cf->cycle->pool,new_pool);
    if (rc != NJT_OK) {
        return NJT_CONF_ERROR;
    }
    cf->pool = new_pool;
    cf->temp_pool = new_pool;
#endif
    //end
    ctx = njt_pcalloc(cf->pool, sizeof(njt_http_conf_ctx_t));
    if (ctx == NULL) {
        return NJT_CONF_ERROR;
    }

    pctx = cf->ctx;
    ctx->main_conf = pctx->main_conf;
    ctx->srv_conf = pctx->srv_conf;

    ctx->loc_conf = njt_pcalloc(cf->pool, sizeof(void *) * njt_http_max_module);
    if (ctx->loc_conf == NULL) {
        return NJT_CONF_ERROR;
    }

    for (i = 0; cf->cycle->modules[i]; i++) {
        if (cf->cycle->modules[i]->type != NJT_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[i]->ctx;

        if (module->create_loc_conf) {

            mconf = module->create_loc_conf(cf);
            if (mconf == NULL) {
                return NJT_CONF_ERROR;
            }

            ctx->loc_conf[cf->cycle->modules[i]->ctx_index] = mconf;
        }

    }
    pclcf = pctx->loc_conf[njt_http_core_module.ctx_index];

    clcf = ctx->loc_conf[njt_http_core_module.ctx_index];
    clcf->loc_conf = ctx->loc_conf;
    clcf->name = pclcf->name;
    clcf->noname = 1;

    if(cf->dynamic != 1){
		if (njt_http_add_location_pre_process(cf,&pclcf->locations,pclcf->pool) != NJT_OK || njt_http_add_location(cf, &pclcf->locations, clcf) != NJT_OK) {
		    return NJT_CONF_ERROR;
	    } 
    } else {
			 clcf->dynamic_status = 1;  // 1 
	}
    if (njt_http_add_location_pre_process(cf,&pclcf->old_locations,pclcf->pool) != NJT_OK || njt_http_add_location(cf, &pclcf->old_locations, clcf) != NJT_OK) {
		    return NJT_CONF_ERROR;
	}

    if (njt_http_rewrite_if_condition(cf, lcf) != NJT_CONF_OK) {
        return NJT_CONF_ERROR;
    }

    if_code = njt_array_push_n(lcf->codes, sizeof(njt_http_script_if_code_t));
    if (if_code == NULL) {
        return NJT_CONF_ERROR;
    }

    if_code->code = njt_http_script_if_code;

    elts = lcf->codes->elts;


    /* the inner directives must be compiled to the same code array */

    nlcf = ctx->loc_conf[njt_http_rewrite_module.ctx_index];
    nlcf->codes = lcf->codes;


    save = *cf;
    cf->ctx = ctx;

    if (cf->cmd_type == NJT_HTTP_SRV_CONF) {
        if_code->loc_conf = NULL;
        cf->cmd_type = NJT_HTTP_SIF_CONF;

    } else {
        if_code->loc_conf = ctx->loc_conf;
        cf->cmd_type = NJT_HTTP_LIF_CONF;
    }
    // by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
    cf->pool = new_pool;
    cf->temp_pool = new_pool;
#endif
    //end
    rv = njt_conf_parse(cf, NULL);
    // by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
    cf->pool = old_pool;
    cf->temp_pool = old_temp_pool;
#endif
    //end


    *cf = save;

    if (rv != NJT_CONF_OK) {
        return rv;
    }


    if (elts != lcf->codes->elts) {
        if_code = (njt_http_script_if_code_t *)
                   ((u_char *) if_code + ((u_char *) lcf->codes->elts - elts));
    }

    if_code->next = (u_char *) lcf->codes->elts + lcf->codes->nelts
                                                - (u_char *) if_code;

    /* the code array belong to parent block */

    nlcf->codes = NULL;

    return NJT_CONF_OK;
}


 char *
njt_http_rewrite_if_condition(njt_conf_t *cf, njt_http_rewrite_loc_conf_t *lcf)
{
    u_char                        *p;
    size_t                         len;
    njt_str_t                     *value;
    njt_uint_t                     cur, last;
    njt_regex_compile_t            rc;
    njt_http_script_code_pt       *code;
    njt_http_script_file_code_t   *fop;
    njt_http_script_regex_code_t  *regex;
    u_char                         errstr[NJT_MAX_CONF_ERRSTR];

    value = cf->args->elts;
    last = cf->args->nelts - 1;

    if (value[1].len < 1 || value[1].data[0] != '(') {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid condition \"%V\"", &value[1]);
        return NJT_CONF_ERROR;
    }

    if (value[1].len == 1) {
        cur = 2;

    } else {
        cur = 1;
        value[1].len--;
        value[1].data++;
    }

    if (value[last].len < 1 || value[last].data[value[last].len - 1] != ')') {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid condition \"%V\"", &value[last]);
        return NJT_CONF_ERROR;
    }

    if (value[last].len == 1) {
        last--;

    } else {
        value[last].len--;
        value[last].data[value[last].len] = '\0';
    }

    len = value[cur].len;
    p = value[cur].data;

    if (len > 1 && p[0] == '$') {

        if (cur != last && cur + 2 != last) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid condition \"%V\"", &value[cur]);
            return NJT_CONF_ERROR;
        }

        if (njt_http_rewrite_variable(cf, lcf, &value[cur]) != NJT_CONF_OK) {
            return NJT_CONF_ERROR;
        }

        if (cur == last) {
            return NJT_CONF_OK;
        }

        cur++;

        len = value[cur].len;
        p = value[cur].data;

        if (len == 1 && p[0] == '=') {

            if (njt_http_rewrite_value(cf, lcf, &value[last]) != NJT_CONF_OK) {
                return NJT_CONF_ERROR;
            }

            code = njt_http_script_start_code(cf->pool, &lcf->codes,
                                              sizeof(uintptr_t));
            if (code == NULL) {
                return NJT_CONF_ERROR;
            }

            *code = njt_http_script_equal_code;

            return NJT_CONF_OK;
        }

        if (len == 2 && p[0] == '!' && p[1] == '=') {

            if (njt_http_rewrite_value(cf, lcf, &value[last]) != NJT_CONF_OK) {
                return NJT_CONF_ERROR;
            }

            code = njt_http_script_start_code(cf->pool, &lcf->codes,
                                              sizeof(uintptr_t));
            if (code == NULL) {
                return NJT_CONF_ERROR;
            }

            *code = njt_http_script_not_equal_code;
            return NJT_CONF_OK;
        }

        if ((len == 1 && p[0] == '~')
            || (len == 2 && p[0] == '~' && p[1] == '*')
            || (len == 2 && p[0] == '!' && p[1] == '~')
            || (len == 3 && p[0] == '!' && p[1] == '~' && p[2] == '*'))
        {
            regex = njt_http_script_start_code(cf->pool, &lcf->codes,
                                         sizeof(njt_http_script_regex_code_t));
            if (regex == NULL) {
                return NJT_CONF_ERROR;
            }

            njt_memzero(regex, sizeof(njt_http_script_regex_code_t));

            njt_memzero(&rc, sizeof(njt_regex_compile_t));

            rc.pattern = value[last];
            rc.options = (p[len - 1] == '*') ? NJT_REGEX_CASELESS : 0;
            rc.err.len = NJT_MAX_CONF_ERRSTR;
            rc.err.data = errstr;

            regex->regex = njt_http_regex_compile(cf, &rc);
            if (regex->regex == NULL) {
                return NJT_CONF_ERROR;
            }

            regex->code = njt_http_script_regex_start_code;
            regex->next = sizeof(njt_http_script_regex_code_t);
            regex->test = 1;
            if (p[0] == '!') {
                regex->negative_test = 1;
            }
            regex->name = value[last];

            return NJT_CONF_OK;
        }

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "unexpected \"%V\" in condition", &value[cur]);
        return NJT_CONF_ERROR;

    } else if ((len == 2 && p[0] == '-')
               || (len == 3 && p[0] == '!' && p[1] == '-'))
    {
        if (cur + 1 != last) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid condition \"%V\"", &value[cur]);
            return NJT_CONF_ERROR;
        }

        value[last].data[value[last].len] = '\0';
        value[last].len++;

        if (njt_http_rewrite_value(cf, lcf, &value[last]) != NJT_CONF_OK) {
            return NJT_CONF_ERROR;
        }

        fop = njt_http_script_start_code(cf->pool, &lcf->codes,
                                          sizeof(njt_http_script_file_code_t));
        if (fop == NULL) {
            return NJT_CONF_ERROR;
        }

        fop->code = njt_http_script_file_code;

        if (p[1] == 'f') {
            fop->op = njt_http_script_file_plain;
            return NJT_CONF_OK;
        }

        if (p[1] == 'd') {
            fop->op = njt_http_script_file_dir;
            return NJT_CONF_OK;
        }

        if (p[1] == 'e') {
            fop->op = njt_http_script_file_exists;
            return NJT_CONF_OK;
        }

        if (p[1] == 'x') {
            fop->op = njt_http_script_file_exec;
            return NJT_CONF_OK;
        }

        if (p[0] == '!') {
            if (p[2] == 'f') {
                fop->op = njt_http_script_file_not_plain;
                return NJT_CONF_OK;
            }

            if (p[2] == 'd') {
                fop->op = njt_http_script_file_not_dir;
                return NJT_CONF_OK;
            }

            if (p[2] == 'e') {
                fop->op = njt_http_script_file_not_exists;
                return NJT_CONF_OK;
            }

            if (p[2] == 'x') {
                fop->op = njt_http_script_file_not_exec;
                return NJT_CONF_OK;
            }
        }

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid condition \"%V\"", &value[cur]);
        return NJT_CONF_ERROR;
    }

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "invalid condition \"%V\"", &value[cur]);

    return NJT_CONF_ERROR;
}


static char *
njt_http_rewrite_variable(njt_conf_t *cf, njt_http_rewrite_loc_conf_t *lcf,
    njt_str_t *value)
{
    njt_int_t                    index;
    njt_http_script_var_code_t  *var_code;

    value->len--;
    value->data++;

    index = njt_http_get_variable_index(cf, value);

    if (index == NJT_ERROR) {
        return NJT_CONF_ERROR;
    }

    var_code = njt_http_script_start_code(cf->pool, &lcf->codes,
                                          sizeof(njt_http_script_var_code_t));
    if (var_code == NULL) {
        return NJT_CONF_ERROR;
    }

    var_code->code = njt_http_script_var_code;
    var_code->index = index;

    return NJT_CONF_OK;
}


static char *
njt_http_rewrite_set(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_rewrite_loc_conf_t  *lcf = conf;

    njt_int_t                            index;
    njt_str_t                           *value;
    njt_http_variable_t                 *v;
    njt_http_script_var_code_t          *vcode;
    njt_http_script_var_handler_code_t  *vhcode;

    value = cf->args->elts;

    if (value[1].data[0] != '$') {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &value[1]);
        return NJT_CONF_ERROR;
    }

    value[1].len--;
    value[1].data++;

    v = njt_http_add_variable(cf, &value[1],
                              NJT_HTTP_VAR_CHANGEABLE|NJT_HTTP_VAR_WEAK);
    if (v == NULL) {
        return NJT_CONF_ERROR;
    }

    index = njt_http_get_variable_index(cf, &value[1]);
    if (index == NJT_ERROR) {
        return NJT_CONF_ERROR;
    }

    if (v->get_handler == NULL) {
        v->get_handler = njt_http_rewrite_var;
        v->data = index;
    }
    if (njt_http_rewrite_value(cf, lcf, &value[2]) != NJT_CONF_OK) {
        return NJT_CONF_ERROR;
    }

    if (v->set_handler) {
        vhcode = njt_http_script_start_code(cf->pool, &lcf->codes,
                                   sizeof(njt_http_script_var_handler_code_t));
        if (vhcode == NULL) {
            return NJT_CONF_ERROR;
        }

        vhcode->code = njt_http_script_var_set_handler_code;
        vhcode->handler = v->set_handler;
        vhcode->data = v->data;

        goto end;
    }

    vcode = njt_http_script_start_code(cf->pool, &lcf->codes,
                                       sizeof(njt_http_script_var_code_t));
    if (vcode == NULL) {
        return NJT_CONF_ERROR;
    }

    vcode->code = njt_http_script_set_var_code;
    vcode->index = (uintptr_t) index;

end:
#if (NJT_HTTP_DYNAMIC_LOC)
	if(lcf->var_names.pool == NULL) {
			if (njt_array_init(&lcf->var_names, cf->pool, 4,
                           sizeof(njt_http_variable_t *))
            != NJT_OK)
			{
				return NJT_CONF_ERROR;
			}
		} 
			njt_http_variable_t **v_name = njt_array_push(&lcf->var_names);
			if(v_name != NULL) {
				*v_name = v;
			}
		
#endif

    return NJT_CONF_OK;
}


static char *
njt_http_rewrite_value(njt_conf_t *cf, njt_http_rewrite_loc_conf_t *lcf,
    njt_str_t *value)
{
    njt_int_t                              n;
    njt_http_script_compile_t              sc;
    njt_http_script_value_code_t          *val;
    njt_http_script_complex_value_code_t  *complex;

    n = njt_http_script_variables_count(value);

    if (n == 0) {
        val = njt_http_script_start_code(cf->pool, &lcf->codes,
                                         sizeof(njt_http_script_value_code_t));
        if (val == NULL) {
            return NJT_CONF_ERROR;
        }

        n = njt_atoi(value->data, value->len);

        if (n == NJT_ERROR) {
            n = 0;
        }

        val->code = njt_http_script_value_code;
        val->value = (uintptr_t) n;
        val->text_len = (uintptr_t) value->len;
        val->text_data = (uintptr_t) value->data;

        return NJT_CONF_OK;
    }

    complex = njt_http_script_start_code(cf->pool, &lcf->codes,
                                 sizeof(njt_http_script_complex_value_code_t));
    if (complex == NULL) {
        return NJT_CONF_ERROR;
    }

    complex->code = njt_http_script_complex_value_code;
    complex->lengths = NULL;

    njt_memzero(&sc, sizeof(njt_http_script_compile_t));

    sc.cf = cf;
    sc.source = value;
    sc.lengths = &complex->lengths;
    sc.values = &lcf->codes;
    sc.variables = n;
    sc.complete_lengths = 1;

    if (njt_http_script_compile(&sc) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}
