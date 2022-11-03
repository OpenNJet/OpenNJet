


njt_int_t
ndk_http_complex_value_compile (njt_conf_t *cf, njt_http_complex_value_t *cv, njt_str_t *value)
{
    njt_http_compile_complex_value_t   ccv;

    njt_memzero (&ccv, sizeof(njt_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = value;
    ccv.complex_value = cv;

    return  njt_http_compile_complex_value (&ccv);
}




njt_array_t *
ndk_http_complex_value_array_create (njt_conf_t *cf, char **s, njt_int_t n)
{
    njt_int_t                    i;
    njt_http_complex_value_t    *cv;
    njt_array_t                 *a;
    njt_str_t                    value;

    a = njt_array_create (cf->pool, n, sizeof (njt_http_complex_value_t));
    if (a == NULL)
        return  NULL;


    for (i=0; i<n; i++, s++) {

        cv = njt_array_push (a);

        value.data = (u_char *) *s;
        value.len = strlen (*s);

        if (ndk_http_complex_value_compile (cf, cv, &value))
            return  NULL;
    }

    return  a;
}



njt_int_t
ndk_http_complex_value_array_compile (njt_conf_t *cf, njt_array_t *a)
{
    njt_uint_t                  i;
    njt_http_complex_value_t   *cv;

    if (a == NULL || a == NJT_CONF_UNSET_PTR) {
        return  NJT_ERROR;
    }

    cv = a->elts;

    for (i=0; i<a->nelts; i++, cv++) {

        if (ndk_http_complex_value_compile (cf, cv, &cv->value))
            return  NJT_ERROR;
    }

    return  NJT_OK;
}



char *
ndk_conf_set_http_complex_value_slot (njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char  *p = conf;

    njt_http_complex_value_t    *cv;
    njt_str_t                   *value;
    njt_conf_post_t             *post;

    cv = (njt_http_complex_value_t *) (p + cmd->offset);

    if (cv->value.data) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ndk_http_complex_value_compile (cf, cv, value + 1))
        return  NJT_CONF_ERROR;

    if (cmd->post) {
        post = cmd->post;
        return  post->post_handler (cf, post, cv);
    }

    return  NJT_CONF_OK;
}



char *
ndk_conf_set_http_complex_value_array_slot (njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char *p = conf;

    njt_str_t                   *value;
    njt_http_complex_value_t    *cv;
    njt_array_t                **a;
    njt_conf_post_t             *post;
    njt_uint_t                   i, alloc;

    a = (njt_array_t **) (p + cmd->offset);

    if (*a == NULL || *a == NJT_CONF_UNSET_PTR) {

        alloc = cf->args->nelts > 4 ? cf->args->nelts : 4;

        *a = njt_array_create (cf->pool, alloc, sizeof (njt_http_complex_value_t));
        if (*a == NULL) {
            return  NJT_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    for (i=1; i<cf->args->nelts; i++) {

        cv = njt_array_push (*a);
        if (cv == NULL) {
            return  NJT_CONF_ERROR;
        }

        if (ndk_http_complex_value_compile (cf, cv, &value[i]) == NJT_ERROR)
            return  NJT_CONF_ERROR;
    }


    if (cmd->post) {
        post = cmd->post;
        return  post->post_handler (cf, post, a);
    }

    return  NJT_CONF_OK;
}


char *
ndk_conf_set_http_complex_keyval_slot (njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char *p = conf;

    njt_str_t                   *value;
    ndk_http_complex_keyval_t   *ckv;
    njt_array_t                **a;
    njt_conf_post_t             *post;
    njt_int_t                    alloc;

    a = (njt_array_t **) (p + cmd->offset);

    if (*a == NULL || *a == NJT_CONF_UNSET_PTR) {

        alloc = cf->args->nelts > 4 ? cf->args->nelts : 4;

        *a = njt_array_create (cf->pool, alloc, sizeof (ndk_http_complex_keyval_t));
        if (*a == NULL) {
            return  NJT_CONF_ERROR;
        }
    }

    ckv = njt_array_push (*a);
    if (ckv == NULL) {
        return  NJT_CONF_ERROR;
    }

    value = cf->args->elts;

    ckv->key = value[1];

    if (ndk_http_complex_value_compile (cf, &ckv->value, &value[2]) == NJT_ERROR)
        return  NJT_CONF_ERROR;

    if (cmd->post) {
        post = cmd->post;
        return  post->post_handler (cf, post, a);
    }

    return  NJT_CONF_OK;
}

/* TODO : complex keyval1 */
