

ndk_http_complex_path_value_t     ndk_empty_http_complex_path_value = {{0,NULL},0};


njt_int_t
ndk_http_complex_path_value_compile (njt_conf_t *cf, njt_http_complex_value_t *cv, njt_str_t *value, njt_uint_t prefix)
{
    njt_http_compile_complex_value_t   ccv;

    njt_memzero (&ccv, sizeof(njt_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = value;
    ccv.complex_value = cv;

    switch (prefix) {

    case    1 :
        ccv.root_prefix = 1;
        break;

    case    2 :
        ccv.conf_prefix = 1;
        break;
    }

    ndk_path_to_dir_safe (value, 1, 0);

    if (!value->len)
        return  NJT_OK;

    return  njt_http_compile_complex_value (&ccv);
}



njt_array_t *
ndk_http_complex_path_create_compile (njt_conf_t *cf, njt_str_t *path, njt_uint_t prefix)
{
    ndk_http_complex_path_elt_t     *cpe;
    njt_array_t                     *a;
    njt_int_t                        n;
    u_char                          *m, *s, *e;
    njt_str_t                        value;

    n = ndk_strcntc (path, ':') + 1;

    a = njt_array_create (cf->pool, n, sizeof (ndk_http_complex_path_elt_t));
    if (a == NULL) {
        return  NULL;
    }

    s = path->data;
    e = s + path->len;


    while (s < e) {

        m = s;

        while (m < e && *m != ':') m++;

        if (m == s) {
            s = m+1;
            continue;
        }

        cpe = njt_array_push (a);
        if (cpe == NULL) {
            return  NULL;
        }

        if (*s == '#') {
            s++;
            cpe->dynamic = 1;
        } else {
            cpe->dynamic = 0;
        }

        value.data = s;
        value.len = m - s;

        if (ndk_http_complex_path_value_compile (cf, &cpe->val, &value, prefix) == NJT_ERROR)
            return  NULL;

        s = m+1;
    }

    return  a;
}




char *
ndk_conf_set_http_complex_path_slot (njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char  *p = conf;

    njt_str_t                   *path;
    njt_conf_post_t             *post;
    ndk_http_complex_path_t     *cp;

    cp = (ndk_http_complex_path_t *) (p + cmd->offset);

    if (cp->a != NJT_CONF_UNSET_PTR) {
        return  "is duplicate";
    }

    path = cf->args->elts;
    path++;

    cp->a = ndk_http_complex_path_create_compile (cf, path, cp->prefix);
    if (cp->a == NULL) {
        /* TODO : log */
        return  NJT_CONF_ERROR;
    }

    if (cmd->post) {
        post = cmd->post;
        return  post->post_handler (cf, post, cp->a);
    }

    return  NJT_CONF_OK;
}



