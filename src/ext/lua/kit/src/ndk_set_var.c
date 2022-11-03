#include    <ndk.h>


typedef struct {
    njt_http_script_code_pt     code;
    void                       *func;
} ndk_set_var_code_t;


typedef struct {
    njt_http_script_code_pt     code;
    void                       *func;
    size_t                      size;
} ndk_set_var_size_code_t;


typedef struct {
    njt_http_script_code_pt     code;
    void                       *func;
    void                       *data;
} ndk_set_var_data_code_t;


typedef struct {
    njt_http_script_code_pt     code;
    void                       *func;
    size_t                      size;
    void                       *data;
} ndk_set_var_size_data_code_t;


typedef struct {
    njt_int_t                        index;
    njt_str_t                       *value;
    njt_http_variable_t             *v;
    njt_conf_t                      *cf;
    ndk_http_rewrite_loc_conf_t     *rlcf;
} ndk_set_var_info_t;


static void     ndk_set_var_code           (njt_http_script_engine_t *e);
static void     ndk_set_var_hash_code      (njt_http_script_engine_t *e);
static void     ndk_set_var_value_code     (njt_http_script_engine_t *e);


static njt_inline void
ndk_set_var_code_finalize(njt_http_script_engine_t *e, njt_int_t rc,
                                njt_http_variable_value_t *v, njt_str_t *str)
{
    switch (rc) {

    case NJT_OK:

        v->data = str->data;
        v->len = str->len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                        "http script value (post filter): \"%v\"", v);
        break;

    case NJT_DECLINED:

        v->valid = 0;
        v->not_found = 1;
        v->no_cacheable = 1;
        break;

    case NJT_ERROR:

        e->ip = ndk_http_script_exit;
        e->status = NJT_HTTP_INTERNAL_SERVER_ERROR;
        break;
    }
}



static void
ndk_set_var_code(njt_http_script_engine_t *e)
{
    njt_int_t                    rc;
    njt_str_t                    str;
    njt_http_variable_value_t   *v;
    ndk_set_var_code_t          *sv;
    ndk_set_var_pt               func;

    sv = (ndk_set_var_code_t *) e->ip;

    e->ip += sizeof(ndk_set_var_code_t);

    v = e->sp++;

    func = (ndk_set_var_pt) sv->func;

    rc = func(e->request, &str);

    ndk_set_var_code_finalize(e, rc, v, &str);
}


static void
ndk_set_var_data_code(njt_http_script_engine_t *e)
{
    njt_int_t                    rc;
    njt_str_t                    str;
    njt_http_variable_value_t   *v;
    ndk_set_var_data_code_t     *svd;
    ndk_set_var_data_pt          func;

    svd = (ndk_set_var_data_code_t *) e->ip;

    e->ip += sizeof(ndk_set_var_data_code_t);

    v = e->sp++;

    func = (ndk_set_var_data_pt) svd->func;

    rc = func(e->request, &str, svd->data);

    ndk_set_var_code_finalize(e, rc, v, &str);
}


static void
ndk_set_var_value_code(njt_http_script_engine_t *e)
{
    njt_int_t                    rc;
    njt_str_t                    str;
    njt_http_variable_value_t   *v;
    ndk_set_var_code_t          *sv;
    ndk_set_var_value_pt         func;

    sv = (ndk_set_var_code_t *) e->ip;

    e->ip += sizeof(ndk_set_var_code_t);

    v = e->sp - 1;

    func = (ndk_set_var_value_pt) sv->func;

    rc = func(e->request, &str, v);

    ndk_set_var_code_finalize(e, rc, v, &str);
}


static void
ndk_set_var_value_data_code(njt_http_script_engine_t *e)
{
    njt_int_t                    rc;
    njt_str_t                    str;
    njt_http_variable_value_t   *v;
    ndk_set_var_data_code_t     *svd;
    ndk_set_var_value_data_pt    func;

    svd = (ndk_set_var_data_code_t *) e->ip;

    e->ip += sizeof(ndk_set_var_data_code_t);

    v = e->sp - 1;

    func = (ndk_set_var_value_data_pt) svd->func;

    rc = func(e->request, &str, v, svd->data);

    ndk_set_var_code_finalize(e, rc, v, &str);
}


static void
ndk_set_var_multi_value_code(njt_http_script_engine_t *e)
{
    njt_int_t                    rc;
    njt_str_t                    str;
    njt_http_variable_value_t   *v;
    ndk_set_var_size_code_t     *svs;
    ndk_set_var_value_pt         func;

    svs = (ndk_set_var_size_code_t *) e->ip;

    e->ip += sizeof(ndk_set_var_size_code_t);

    v = e->sp - svs->size;
    e->sp = v + 1;

    func = (ndk_set_var_value_pt) svs->func;

    rc = func(e->request, &str, v);

    ndk_set_var_code_finalize(e, rc, v, &str);
}


static void
ndk_set_var_multi_value_data_code(njt_http_script_engine_t *e)
{
    njt_int_t                        rc;
    njt_str_t                        str;
    njt_http_variable_value_t       *v;
    ndk_set_var_size_data_code_t    *svsd;
    ndk_set_var_value_data_pt        func;

    svsd = (ndk_set_var_size_data_code_t *) e->ip;

    e->ip += sizeof(ndk_set_var_size_data_code_t);

    v = e->sp - svsd->size;
    e->sp = v + 1;

    func = (ndk_set_var_value_data_pt) svsd->func;

    rc = func(e->request, &str, v, svsd->data);

    ndk_set_var_code_finalize(e, rc, v, &str);
}


static void
ndk_set_var_hash_code(njt_http_script_engine_t *e)
{
    u_char                      *p;
    njt_http_variable_value_t   *v;
    ndk_set_var_size_code_t     *svs;
    ndk_set_var_hash_pt          func;

    svs = (ndk_set_var_size_code_t *) e->ip;

    e->ip += sizeof(ndk_set_var_size_code_t);

    p = njt_palloc(e->request->pool, svs->size);
    if (p == NULL) {
        e->ip = ndk_http_script_exit;
        e->status = NJT_HTTP_INTERNAL_SERVER_ERROR;
        return;
    }

    v = e->sp - 1;

    func = (ndk_set_var_hash_pt) svs->func;

    func(p, (char *) v->data, v->len);

    v->data = (u_char *) p;
    v->len = svs->size;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script hashed value: \"%v\"", v);
}



static char *
ndk_set_var_name(ndk_set_var_info_t *info, njt_str_t *varname)
{
    njt_int_t                        index;
    njt_http_variable_t             *v;
    njt_conf_t                      *cf;
    ndk_http_rewrite_loc_conf_t     *rlcf;
    njt_str_t                        name;

    name = *varname;

    cf = info->cf;
    rlcf = njt_http_conf_get_module_loc_conf(cf, njt_http_rewrite_module);

    if (name.data[0] != '$') {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &name);
        return NJT_CONF_ERROR;
    }

    name.len--;
    name.data++;

    v = njt_http_add_variable(cf, &name, NJT_HTTP_VAR_CHANGEABLE);
    if (v == NULL) {
        return NJT_CONF_ERROR;
    }

    index = njt_http_get_variable_index(cf, &name);
    if (index == NJT_ERROR) {
        return NJT_CONF_ERROR;
    }

    if (v->get_handler == NULL
        && njt_strncasecmp(name.data, (u_char *) "arg_", 4) != 0
        && njt_strncasecmp(name.data, (u_char *) "cookie_", 7) != 0
        && njt_strncasecmp(name.data, (u_char *) "http_", 5) != 0
        && njt_strncasecmp(name.data, (u_char *) "sent_http_", 10) != 0
        && njt_strncasecmp(name.data, (u_char *) "upstream_http_", 14) != 0)
    {
        v->get_handler = ndk_http_rewrite_var;
        v->data = index;
    }

    info->v = v;
    info->index = index;
    info->rlcf = rlcf;

    return NJT_CONF_OK;
}



static void
ndk_set_variable_value_space(ndk_http_rewrite_loc_conf_t *rlcf, njt_uint_t count)
{
    /* if the number of variable values that will be used is greater than 10,
     * make sure there is enough space allocated on the rewrite value stack
     */

    if (count <= 10)
        return;

    if (rlcf->stack_size == NJT_CONF_UNSET_UINT) {
        rlcf->stack_size = count;
        return;
    }

    if (rlcf->stack_size < count)
        rlcf->stack_size = count;
}



static char *
ndk_set_var_filter(njt_conf_t *cf, ndk_http_rewrite_loc_conf_t *rlcf,
    ndk_set_var_t *filter)
{
    ndk_set_var_code_t             *sv;
    ndk_set_var_size_code_t        *svs;
    ndk_set_var_data_code_t        *svd;
    ndk_set_var_size_data_code_t   *svsd;

    if (filter == NULL) {
        return "no filter set";
    }

    switch (filter->type) {
    case NDK_SET_VAR_BASIC:

        sv = njt_http_script_start_code(cf->pool, &rlcf->codes,
                                         sizeof(ndk_set_var_code_t));
        if (sv == NULL) {
            return NJT_CONF_ERROR;
        }

        sv->code = ndk_set_var_code;
        sv->func = filter->func;
        break;

    case NDK_SET_VAR_DATA:

        svd = njt_http_script_start_code(cf->pool, &rlcf->codes,
                                         sizeof(ndk_set_var_data_code_t));
        if (svd == NULL) {
            return NJT_CONF_ERROR;
        }

        svd->code = ndk_set_var_data_code;
        svd->func = filter->func;
        svd->data = filter->data;
        break;

    case NDK_SET_VAR_VALUE:

        sv = njt_http_script_start_code(cf->pool, &rlcf->codes,
                                         sizeof(ndk_set_var_code_t));
        if (sv == NULL) {
            return NJT_CONF_ERROR;
        }

        sv->code = ndk_set_var_value_code;
        sv->func = filter->func;
        break;

    case NDK_SET_VAR_VALUE_DATA:

        svd = njt_http_script_start_code(cf->pool, &rlcf->codes,
                                         sizeof(ndk_set_var_data_code_t));
        if (svd == NULL) {
            return NJT_CONF_ERROR;
        }

        svd->code = ndk_set_var_value_data_code;
        svd->func = filter->func;
        svd->data = filter->data;
        break;

    case NDK_SET_VAR_MULTI_VALUE:

        svs = njt_http_script_start_code(cf->pool, &rlcf->codes,
                                          sizeof(ndk_set_var_size_code_t));
        if (svs == NULL) {
            return NJT_CONF_ERROR;
        }

        svs->code = ndk_set_var_multi_value_code;
        svs->func = filter->func;
        svs->size = filter->size;

        ndk_set_variable_value_space(rlcf, svs->size);
        break;

    case NDK_SET_VAR_MULTI_VALUE_DATA:

        svsd = njt_http_script_start_code(cf->pool, &rlcf->codes,
                                          sizeof(ndk_set_var_size_data_code_t));
        if (svsd == NULL) {
            return NJT_CONF_ERROR;
        }

        svsd->code = ndk_set_var_multi_value_data_code;
        svsd->func = filter->func;
        svsd->size = filter->size;
        svsd->data = filter->data;

        ndk_set_variable_value_space(rlcf, svsd->size);
        break;


    case NDK_SET_VAR_HASH:

        svs = njt_http_script_start_code(cf->pool, &rlcf->codes,
                                          sizeof(ndk_set_var_size_code_t));
        if (svs == NULL) {
            return NJT_CONF_ERROR;
        }

        svs->code = ndk_set_var_hash_code;
        svs->func = filter->func;
        svs->size = filter->size;
        break;

    default:
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid filter type \"%ul\"", filter->type);
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


static char *
ndk_set_var_filter_value(ndk_set_var_info_t *info, ndk_set_var_t *filter)
{
    njt_conf_t                          *cf;
    njt_http_variable_t                 *v;
    ndk_http_rewrite_loc_conf_t         *rlcf;
    njt_http_script_var_code_t          *vcode;
    njt_http_script_var_handler_code_t  *vhcode;

    v = info->v;
    cf = info->cf;
    rlcf = info->rlcf;

    if (ndk_set_var_filter(cf, rlcf, filter) != NJT_CONF_OK) {
        return NJT_CONF_ERROR;
    }

    if (v->set_handler) {
        vhcode = njt_http_script_start_code(cf->pool, &rlcf->codes,
                                   sizeof(njt_http_script_var_handler_code_t));
        if (vhcode == NULL) {
            return NJT_CONF_ERROR;
        }

        vhcode->code = njt_http_script_var_set_handler_code;
        vhcode->handler = v->set_handler;
        vhcode->data = v->data;

        return NJT_CONF_OK;
    }

    vcode = njt_http_script_start_code(cf->pool, &rlcf->codes,
                                       sizeof(njt_http_script_var_code_t));
    if (vcode == NULL) {
        return NJT_CONF_ERROR;
    }

    vcode->code = njt_http_script_set_var_code;
    vcode->index = (uintptr_t) info->index;

    return NJT_CONF_OK;
}


char *
ndk_set_var_core(njt_conf_t *cf, njt_str_t *name, ndk_set_var_t *filter)
{
    char                    *p;
    ndk_set_var_info_t       info;

    info.cf = cf;

    p = ndk_set_var_name(&info, name);
    if (p != NJT_CONF_OK) {
        return p;
    }

    return ndk_set_var_filter_value(&info, filter);
}


char *
ndk_set_var_value_core(njt_conf_t *cf, njt_str_t *name, njt_str_t *value, ndk_set_var_t *filter)
{
    char                    *p;
    ndk_set_var_info_t       info;

    info.cf = cf;

    p = ndk_set_var_name(&info, name);
    if (p != NJT_CONF_OK) {
        return p;
    }

    p = ndk_http_rewrite_value(cf, info.rlcf, value);
    if (p != NJT_CONF_OK) {
        return p;
    }

    return ndk_set_var_filter_value(&info, filter);
}


char *
ndk_set_var_multi_value_core(njt_conf_t *cf, njt_str_t *name,
        njt_str_t *value, ndk_set_var_t *filter)
{
    char                    *p;
    ndk_set_var_info_t       info;
    njt_int_t                i;

    info.cf = cf;

    p = ndk_set_var_name(&info, name);
    if (p != NJT_CONF_OK) {
        return p;
    }

    for (i = filter->size; i; i--, value++) {

        p = ndk_http_rewrite_value(cf, info.rlcf, value);
        if (p != NJT_CONF_OK) {
            return p;
        }
    }

    return ndk_set_var_filter_value(&info, filter);
}


char *
ndk_set_var(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_str_t               *value;
    ndk_set_var_t      *filter;

    value = cf->args->elts;
    value++;

    filter = (ndk_set_var_t *) cmd->post;

    return ndk_set_var_core(cf, value, filter);
}


char *
ndk_set_var_value(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_str_t               *value;
    ndk_set_var_t           *filter;

    value = cf->args->elts;
    value++;

    filter = (ndk_set_var_t *) cmd->post;

    return ndk_set_var_value_core(cf, value,
            cf->args->nelts == 1 + 1 ? value : value + 1, filter);
}


char *
ndk_set_var_multi_value(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_str_t               *value;
    ndk_set_var_t      *filter;

    value = cf->args->elts;
    value++;

    filter = (ndk_set_var_t *) cmd->post;

    return ndk_set_var_multi_value_core(cf, value, value + 1, filter);
}

