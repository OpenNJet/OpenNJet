

/* NOTE : you will find other conf_set functions in the following files :
 *
 * complex_value.c
 * encoding.c
 * path.c
 *
 */


char *
ndk_conf_set_true_slot (njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char  *p = conf;

    njt_flag_t       *fp;
    njt_conf_post_t  *post;

    fp = (njt_flag_t*) (p + cmd->offset);

    if (*fp != NJT_CONF_UNSET) {
        return  "is duplicate";
    }

    *fp = 1;

    if (cmd->post) {
        post = cmd->post;
        return  post->post_handler (cf, post, fp);
    }

    return  NJT_CONF_OK;
}



char *
ndk_conf_set_false_slot (njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char  *p = conf;

    njt_flag_t       *fp;
    njt_conf_post_t  *post;

    fp = (njt_flag_t*) (p + cmd->offset);

    if (*fp != NJT_CONF_UNSET) {
        return  "is duplicate";
    }

    *fp = 0;

    if (cmd->post) {
        post = cmd->post;
        return  post->post_handler (cf, post, fp);
    }

    return  NJT_CONF_OK;
}




char *
ndk_conf_set_ptr_slot (njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char  *p = conf;

    void  **ptr;

    ptr = (void**) (p + cmd->offset);

    if (*ptr != NJT_CONF_UNSET_PTR) {
        return  "is duplicate";
    }

    *ptr = cmd->post;

    return  NJT_CONF_OK;
}



char *
ndk_conf_set_null_slot (njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char  *p = conf;

    void            **pp;
    njt_conf_post_t  *post;

    pp = (void **) (p + cmd->offset);

    if (*pp != NJT_CONF_UNSET_PTR) {
        return  "is duplicate";
    }

    *pp = NULL;

    if (cmd->post) {
        post = cmd->post;
        return  post->post_handler (cf, post, pp);
    }

    return  NJT_CONF_OK;
}


char *
ndk_conf_set_num64_slot (njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char  *p = conf;

    int64_t          *np;
    njt_str_t        *value;
    njt_conf_post_t  *post;


    np = (int64_t *) (p + cmd->offset);

    if (*np != NJT_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;
    *np = ndk_atoi64 (value[1].data, value[1].len);
    if (*np == NJT_ERROR) {
        return "invalid number";
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, np);
    }

    return NJT_CONF_OK;
}


char *
ndk_conf_set_str_array_multi_slot (njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char  *p = conf;

    njt_str_t         *value, *s;
    njt_array_t      **a;
    njt_conf_post_t   *post;
    njt_uint_t         i;

    a = (njt_array_t **) (p + cmd->offset);

    if (*a == NJT_CONF_UNSET_PTR) {
        *a = njt_array_create(cf->pool, 4, sizeof(njt_str_t));
        if (*a == NULL) {
            return NJT_CONF_ERROR;
        }
    }

    s = NULL;

    for (i=cf->args->nelts-1; i; i--) {

        s = njt_array_push(*a);
        if (s == NULL) {
            return NJT_CONF_ERROR;
        }

        value = cf->args->elts;

        *s = value[i];
    }

    if (cmd->post) {
        post = cmd->post;
        return  post->post_handler(cf, post, s);
    }

    return NJT_CONF_OK;
}



char *
ndk_conf_set_keyval1_slot (njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char  *p = conf;

    njt_str_t           *value;
    njt_keyval_t        *kv;
    njt_conf_post_t     *post;

    kv = (njt_keyval_t *) (p + cmd->offset);

    if (kv->key.data)
        return  "is duplicate";

    value = cf->args->elts;

    kv->key = value[1];
    kv->value = value[2];

    if (cmd->post) {
        post = cmd->post;
        return  post->post_handler (cf, post, kv);
    }

    return  NJT_CONF_OK;
}



char *
ndk_conf_set_num_flag_slot (njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char  *p = conf;

    njt_int_t        *np;
    njt_str_t        *value;
    njt_conf_post_t  *post;

    np = (njt_int_t *) (p + cmd->offset);

    if (*np != NJT_CONF_UNSET) {
        return  "is duplicate";
    }

    value = cf->args->elts;

    if (njt_strcasecmp (value[1].data, (u_char *) "on") == 0) {
        *np = NDK_CONF_SET_TRUE;

    } else if (njt_strcasecmp (value[1].data, (u_char *) "off") == 0) {
        *np = NDK_CONF_SET_FALSE;

    } else {
        *np = njt_atoi (value[1].data, value[1].len);
        if (*np == NJT_ERROR) {
            return  "invalid number and not 'on'/'off'";
        }
    }

    if (cmd->post) {
        post = cmd->post;
        return  post->post_handler (cf, post, np);
    }

    return  NJT_CONF_OK;
}



char *
ndk_conf_set_sec_flag_slot (njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char  *p = conf;

    time_t              *tp;
    njt_str_t           *value;
    njt_conf_post_t     *post;

    tp = (time_t *) (p + cmd->offset);

    if (*tp != NJT_CONF_UNSET) {
        return  "is duplicate";
    }

    value = cf->args->elts;

    if (njt_strcasecmp (value[1].data, (u_char *) "on") == 0) {
        *tp = NDK_CONF_SET_TRUE;

    } else if (njt_strcasecmp (value[1].data, (u_char *) "off") == 0) {
        *tp = NDK_CONF_SET_FALSE;

    } else {
        *tp = njt_parse_time (&value[1], 1);
        if (*tp == NJT_ERROR) {
            return  "has an invalid time and not 'on'/'off'";
        }
    }

    if (cmd->post) {
        post = cmd->post;
        return  post->post_handler (cf, post, tp);
    }

    return  NJT_CONF_OK;
}



njt_http_conf_ctx_t *
ndk_conf_create_http_location (njt_conf_t *cf)
{
    njt_http_conf_ctx_t          *ctx, *pctx;
    void                         *mconf;
    njt_http_core_loc_conf_t     *clcf, *pclcf;
    njt_uint_t                    i;
    njt_http_module_t            *module;

    ndk_pcallocp_rce (ctx, cf->pool);

    pctx = cf->ctx;
    ctx->main_conf = pctx->main_conf;
    ctx->srv_conf = pctx->srv_conf;

    ndk_pcalloc_rce (ctx->loc_conf, cf->pool, sizeof(void *) * njt_http_max_module);


    for (i = 0; njt_modules[i]; i++) {
        if (njt_modules[i]->type != NJT_HTTP_MODULE) {
            continue;
        }

        module = njt_modules[i]->ctx;

        if (module->create_loc_conf) {

            mconf = module->create_loc_conf(cf);
            if (mconf == NULL) {
                 return NJT_CONF_ERROR;
            }

            ctx->loc_conf[njt_modules[i]->ctx_index] = mconf;
        }
    }

    pclcf = pctx->loc_conf[njt_http_core_module.ctx_index];

    clcf = ctx->loc_conf[njt_http_core_module.ctx_index];
    clcf->loc_conf = ctx->loc_conf;
    clcf->name = pclcf->name;
    clcf->noname = 1;

    if (njt_http_add_location(cf, &pclcf->locations, clcf) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    return  ctx;
}


njt_http_conf_ctx_t *
njt_conf_create_http_named_location (njt_conf_t *cf, njt_str_t *name)
{
    njt_http_conf_ctx_t          *ctx;
    njt_http_core_loc_conf_t     *clcf;

    ctx = ndk_conf_create_http_location (cf);
    if (ctx == NJT_CONF_ERROR)
        return  NJT_CONF_ERROR;

    clcf = ctx->loc_conf[njt_http_core_module.ctx_index];

    /* in case the developer forgets to add '@' at the beginning of the named location */

    if (name->data[0] != '@' && ndk_catstrf (cf->pool, name, "sS", "@", name) == NULL)
        return  NJT_CONF_ERROR;

    clcf->name = *name;     /* TODO : copy? */
    clcf->noname = 0;
    clcf->named = 1;

    return  ctx;
}


njt_int_t
ndk_replace_command (njt_command_t *new_cmd, njt_uint_t module_type)
{
    njt_uint_t       i;
    njt_command_t   *cmd;

    for (i = 0; njt_modules[i]; i++) {

        if (njt_modules[i]->type != module_type)
            continue;

        cmd = njt_modules[i]->commands;
        if (cmd == NULL) {
            continue;
        }

        for ( /* void */ ; cmd->name.len; cmd++) {

            if (ndk_cmpstr (&new_cmd->name, &cmd->name) == 0) {

                ndk_memcpyp (cmd, new_cmd);
                return  NJT_OK;
            }
        }
    }

    return  NJT_DECLINED;
}
