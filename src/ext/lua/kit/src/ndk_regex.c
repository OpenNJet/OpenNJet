

char *
ndk_conf_set_regex_slot (njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char  *p = conf;

    njt_str_t               *value;
    njt_conf_post_t         *post;
    njt_regex_elt_t         *re;   
    njt_regex_compile_t      rc;
    u_char                   errstr[NJT_MAX_CONF_ERRSTR];

    re = (njt_regex_elt_t *) (p + cmd->offset);

    if (re->name) {
        return  "is duplicate";
    }

    value = cf->args->elts;
    value++;

    ndk_zerov (rc);

    rc.pool = cf->pool;
    rc.err.len = NJT_MAX_CONF_ERRSTR;
    rc.err.data = errstr;
    rc.pattern = *value;

    if (njt_regex_compile(&rc) != NJT_OK) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "%V", &rc.err);
        return NJT_CONF_ERROR;
    }

    re->regex = rc.regex;
    re->name = value->data;

    if (cmd->post) {
        post = cmd->post;
        return  post->post_handler (cf, post, re);
    }

    return  NJT_CONF_OK;
}
 

char *
ndk_conf_set_regex_caseless_slot (njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char  *p = conf;

    njt_str_t               *value;
    njt_conf_post_t         *post;
    njt_regex_elt_t         *re;   
    njt_regex_compile_t      rc;
    u_char                   errstr[NJT_MAX_CONF_ERRSTR];

    re = (njt_regex_elt_t *) (p + cmd->offset);

    if (re->name) {
        return  "is duplicate";
    }

    value = cf->args->elts;
    value++;

    ndk_zerov (rc);

    rc.pool = cf->pool;
    rc.err.len = NJT_MAX_CONF_ERRSTR;
    rc.err.data = errstr;
    rc.pattern = *value;
    rc.options = NJT_REGEX_CASELESS;

    if (njt_regex_compile(&rc) != NJT_OK) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "%V", &rc.err);
        return NJT_CONF_ERROR;
    }

    re->regex = rc.regex;
    re->name = value->data;

    if (cmd->post) {
        post = cmd->post;
        return  post->post_handler (cf, post, re);
    }

    return  NJT_CONF_OK;
}



char *
ndk_conf_set_regex_array_slot (njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char  *p = conf;

    njt_str_t               *value;
    njt_conf_post_t         *post;
    njt_array_t            **a;
    njt_regex_elt_t         *re;   
    njt_regex_compile_t      rc;
    njt_uint_t               i, n = 0;
    u_char                   errstr[NJT_MAX_CONF_ERRSTR];

    a = (njt_array_t **) (p + cmd->offset);

    if (*a != NJT_CONF_UNSET_PTR) {

        n = cf->args->nelts > 4 ? cf->args->nelts : 4;

        *a = njt_array_create (cf->pool, n, sizeof (njt_regex_elt_t));
        if (*a == NULL) {
            return  NJT_CONF_ERROR;
        }
    }

    ndk_zerov (rc);

    rc.pool = cf->pool;
    rc.err.len = NJT_MAX_CONF_ERRSTR;
    rc.err.data = errstr;

    value = cf->args->elts;
    value++;

    for (i=0; i<n; i++, value++) {

        re = njt_array_push (*a);
        if (re == NULL)
            return  NJT_CONF_ERROR;

        rc.pattern = *value;

        if (njt_regex_compile(&rc) != NJT_OK) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "%V", &rc.err);
            return NJT_CONF_ERROR;
        }

        re->regex = rc.regex;
        re->name = value->data;
    }


    if (cmd->post) {
        post = cmd->post;
        return  post->post_handler (cf, post, a);
    }

    return  NJT_CONF_OK;
}



char *
ndk_conf_set_regex_array_caseless_slot (njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char  *p = conf;

    njt_str_t               *value;
    njt_conf_post_t         *post;
    njt_array_t            **a;
    njt_regex_elt_t         *re;   
    njt_regex_compile_t      rc;
    njt_uint_t               i, n = 0;
    u_char                   errstr[NJT_MAX_CONF_ERRSTR];

    a = (njt_array_t **) (p + cmd->offset);

    if (*a != NJT_CONF_UNSET_PTR) {

        n = cf->args->nelts > 4 ? cf->args->nelts : 4;

        *a = njt_array_create (cf->pool, n, sizeof (njt_regex_elt_t));
        if (*a == NULL) {
            return  NJT_CONF_ERROR;
        }
    }

    ndk_zerov (rc);

    rc.pool = cf->pool;
    rc.err.len = NJT_MAX_CONF_ERRSTR;
    rc.err.data = errstr;

    value = cf->args->elts;
    value++;

    for (i=0; i<n; i++, value++) {

        re = njt_array_push (*a);
        if (re == NULL)
            return  NJT_CONF_ERROR;

        rc.pattern = *value;
        rc.options = NJT_REGEX_CASELESS;

        if (njt_regex_compile(&rc) != NJT_OK) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "%V", &rc.err);
            return NJT_CONF_ERROR;
        }

        re->regex = rc.regex;
        re->name = value->data;
    }


    if (cmd->post) {
        post = cmd->post;
        return  post->post_handler (cf, post, a);
    }

    return  NJT_CONF_OK;
}

