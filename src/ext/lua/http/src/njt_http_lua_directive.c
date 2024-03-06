
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_http_lua_common.h"
#include "njt_http_lua_directive.h"
#include "njt_http_lua_util.h"
#include "njt_http_lua_cache.h"
#include "njt_http_lua_contentby.h"
#include "njt_http_lua_accessby.h"
#include "njt_http_lua_server_rewriteby.h"
#include "njt_http_lua_rewriteby.h"
#include "njt_http_lua_logby.h"
#include "njt_http_lua_headerfilterby.h"
#include "njt_http_lua_bodyfilterby.h"
#include "njt_http_lua_initby.h"
#include "njt_http_lua_initworkerby.h"
#include "njt_http_lua_exitworkerby.h"
#include "njt_http_lua_shdict.h"
#include "njt_http_lua_ssl_certby.h"
#include "njt_http_lua_lex.h"
#include "api/njt_http_lua_api.h"
#include "njt_http_lua_log_ringbuf.h"
#include "njt_http_lua_log.h"


/* the max length is 60, after deducting the fixed four characters "=(:)"
 * only 56 left.
 */
#define LJ_CHUNKNAME_MAX_LEN 56


typedef struct njt_http_lua_block_parser_ctx_s
    njt_http_lua_block_parser_ctx_t;


#if defined(NDK) && NDK
#include "njt_http_lua_setby.h"


static njt_int_t njt_http_lua_set_by_lua_init(njt_http_request_t *r);
#endif

static njt_int_t njt_http_lua_conf_read_lua_token(njt_conf_t *cf,
    njt_http_lua_block_parser_ctx_t *ctx);
static u_char *njt_http_lua_strlstrn(u_char *s1, u_char *last, u_char *s2,
    size_t n);


struct njt_http_lua_block_parser_ctx_s {
    njt_uint_t  start_line;
    int         token_len;
};


enum {
    FOUND_LEFT_CURLY = 0,
    FOUND_RIGHT_CURLY,
    FOUND_LEFT_LBRACKET_STR,
    FOUND_LBRACKET_STR = FOUND_LEFT_LBRACKET_STR,
    FOUND_LEFT_LBRACKET_CMT,
    FOUND_LBRACKET_CMT = FOUND_LEFT_LBRACKET_CMT,
    FOUND_RIGHT_LBRACKET,
    FOUND_COMMENT_LINE,
    FOUND_DOUBLE_QUOTED,
    FOUND_SINGLE_QUOTED,
};


char *
njt_http_lua_shared_dict(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_lua_main_conf_t   *lmcf = conf;

    njt_str_t                  *value, name;
    njt_shm_zone_t             *zone;
    njt_shm_zone_t            **zp;
    njt_http_lua_shdict_ctx_t  *ctx;
    ssize_t                     size;

    if (lmcf->shdict_zones == NULL) {
        lmcf->shdict_zones = njt_palloc(cf->pool, sizeof(njt_array_t));
        if (lmcf->shdict_zones == NULL) {
            return NJT_CONF_ERROR;
        }

        if (njt_array_init(lmcf->shdict_zones, cf->pool, 2,
                           sizeof(njt_shm_zone_t *))
            != NJT_OK)
        {
            return NJT_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    ctx = NULL;

    if (value[1].len == 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid lua shared dict name \"%V\"", &value[1]);
        return NJT_CONF_ERROR;
    }

    name = value[1];

    size = njt_parse_size(&value[2]);

    if (size <= 8191) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid lua shared dict size \"%V\"", &value[2]);
        return NJT_CONF_ERROR;
    }

    ctx = njt_pcalloc(cf->pool, sizeof(njt_http_lua_shdict_ctx_t));
    if (ctx == NULL) {
        return NJT_CONF_ERROR;
    }

    ctx->name = name;
    ctx->main_conf = lmcf;
    ctx->log = &cf->cycle->new_log;

    zone = njt_http_lua_shared_memory_add(cf, &name, (size_t) size,
                                          &njt_http_lua_module);
    if (zone == NULL) {
        return NJT_CONF_ERROR;
    }

    if (zone->data) {
        ctx = zone->data;

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "lua_shared_dict \"%V\" is already defined as "
                           "\"%V\"", &name, &ctx->name);
        return NJT_CONF_ERROR;
    }

    zone->init = njt_http_lua_shdict_init_zone;
    zone->data = ctx;

    zp = njt_array_push(lmcf->shdict_zones);
    if (zp == NULL) {
        return NJT_CONF_ERROR;
    }

    *zp = zone;

    lmcf->requires_shm = 1;

    return NJT_CONF_OK;
}


char *
njt_http_lua_code_cache(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char             *p = conf;
    njt_flag_t       *fp;
    char             *ret;

    ret = njt_conf_set_flag_slot(cf, cmd, conf);
    if (ret != NJT_CONF_OK) {
        return ret;
    }

    fp = (njt_flag_t *) (p + cmd->offset);

    if (!*fp) {
        njt_conf_log_error(NJT_LOG_ALERT, cf, 0,
                           "lua_code_cache is off; this will hurt "
                           "performance");
    }

    return NJT_CONF_OK;
}


char *
njt_http_lua_load_resty_core(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                       "lua_load_resty_core is deprecated (the lua-resty-core "
                       "library is required since njt_lua v0.10.16)");

    return NJT_CONF_OK;
}


char *
njt_http_lua_package_cpath(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_lua_main_conf_t *lmcf = conf;
    njt_str_t                *value;

    if (lmcf->lua_cpath.len != 0) {
        return "is duplicate";
    }

    dd("enter");

    value = cf->args->elts;

    lmcf->lua_cpath.len = value[1].len;
    lmcf->lua_cpath.data = value[1].data;

    return NJT_CONF_OK;
}


char *
njt_http_lua_package_path(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_lua_main_conf_t *lmcf = conf;
    njt_str_t                *value;

    if (lmcf->lua_path.len != 0) {
        return "is duplicate";
    }

    dd("enter");

    value = cf->args->elts;

    lmcf->lua_path.len = value[1].len;
    lmcf->lua_path.data = value[1].data;

    return NJT_CONF_OK;
}


char *
njt_http_lua_regex_cache_max_entries(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
#if (NJT_PCRE)
    return njt_conf_set_num_slot(cf, cmd, conf);
#else
    return NJT_CONF_OK;
#endif
}


char *
njt_http_lua_regex_match_limit(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
#if (NJT_PCRE)
    return njt_conf_set_num_slot(cf, cmd, conf);
#else
    return NJT_CONF_OK;
#endif
}


#if defined(NDK) && NDK
char *
njt_http_lua_set_by_lua_block(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    char        *rv;
    njt_conf_t   save;

    save = *cf;
    cf->handler = njt_http_lua_set_by_lua;
    cf->handler_conf = conf;

    rv = njt_http_lua_conf_lua_block_parse(cf, cmd);

    *cf = save;

    return rv;
}


char *
njt_http_lua_set_by_lua(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    size_t               chunkname_len;
    u_char              *chunkname;
    u_char              *cache_key;
    njt_str_t           *value;
    njt_str_t            target;
    ndk_set_var_t        filter;

    njt_http_lua_set_var_data_t     *filter_data;

    /*
     * value[0] = "set_by_lua"
     * value[1] = target variable name
     * value[2] = lua script source to be executed
     * value[3..] = real params
     * */
    value = cf->args->elts;
    target = value[1];

    filter.type = NDK_SET_VAR_MULTI_VALUE_DATA;
    filter.func = cmd->post;
    filter.size = cf->args->nelts - 3;    /*  get number of real params */

    filter_data = njt_palloc(cf->pool, sizeof(njt_http_lua_set_var_data_t));
    if (filter_data == NULL) {
        return NJT_CONF_ERROR;
    }

    cache_key = njt_http_lua_gen_chunk_cache_key(cf, "set_by_lua",
                                                 value[2].data,
                                                 value[2].len);
    if (cache_key == NULL) {
        return NJT_CONF_ERROR;
    }

    chunkname = njt_http_lua_gen_chunk_name(cf, "set_by_lua",
                                            sizeof("set_by_lua") - 1,
                                            &chunkname_len);
    if (chunkname == NULL) {
        return NJT_CONF_ERROR;
    }

    filter_data->key = cache_key;
    filter_data->chunkname = chunkname;
    filter_data->ref = LUA_REFNIL;
    filter_data->script = value[2];
    filter_data->size = filter.size;

    filter.data = filter_data;

    return ndk_set_var_multi_value_core(cf, &target, &value[3], &filter);
}


char *
njt_http_lua_set_by_lua_file(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    u_char              *cache_key = NULL;
    njt_str_t           *value;
    njt_str_t            target;
    ndk_set_var_t        filter;

    njt_http_lua_set_var_data_t           *filter_data;
    njt_http_complex_value_t               cv;
    njt_http_compile_complex_value_t       ccv;

    /*
     * value[0] = "set_by_lua_file"
     * value[1] = target variable name
     * value[2] = lua script file path to be executed
     * value[3..] = real params
     * */
    value = cf->args->elts;
    target = value[1];

    filter.type = NDK_SET_VAR_MULTI_VALUE_DATA;
    filter.func = cmd->post;
    filter.size = cf->args->nelts - 2;    /*  get number of real params and
                                              lua script */

    filter_data = njt_palloc(cf->pool, sizeof(njt_http_lua_set_var_data_t));
    if (filter_data == NULL) {
        return NJT_CONF_ERROR;
    }

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));
    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &cv;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    if (cv.lengths == NULL) {
        /* no variable found */
        cache_key = njt_http_lua_gen_file_cache_key(cf, value[2].data,
                                                    value[2].len);
        if (cache_key == NULL) {
            return NJT_CONF_ERROR;
        }
    }

    filter_data->key = cache_key;
    filter_data->ref = LUA_REFNIL;
    filter_data->size = filter.size;
    filter_data->chunkname = NULL;

    njt_str_null(&filter_data->script);

    filter.data = filter_data;

    return ndk_set_var_multi_value_core(cf, &target, &value[2], &filter);
}


njt_int_t
njt_http_lua_filter_set_by_lua_inline(njt_http_request_t *r, njt_str_t *val,
    njt_http_variable_value_t *v, void *data)
{
    lua_State                   *L;
    njt_int_t                    rc;

    njt_http_lua_set_var_data_t     *filter_data = data;

    if (njt_http_lua_set_by_lua_init(r) != NJT_OK) {
        return NJT_ERROR;
    }

    L = njt_http_lua_get_lua_vm(r, NULL);

    /*  load Lua inline script (w/ cache)        sp = 1 */
    rc = njt_http_lua_cache_loadbuffer(r->connection->log, L,
                                       filter_data->script.data,
                                       filter_data->script.len,
                                       &filter_data->ref,
                                       filter_data->key,
                                       (const char *) filter_data->chunkname);
    if (rc != NJT_OK) {
        return NJT_ERROR;
    }

    rc = njt_http_lua_set_by_chunk(L, r, val, v, filter_data->size,
                                   &filter_data->script);
    if (rc != NJT_OK) {
        return NJT_ERROR;
    }

    return NJT_OK;
}


njt_int_t
njt_http_lua_filter_set_by_lua_file(njt_http_request_t *r, njt_str_t *val,
    njt_http_variable_value_t *v, void *data)
{
    lua_State                   *L;
    njt_int_t                    rc;
    u_char                      *script_path;
    size_t                       nargs;

    njt_http_lua_set_var_data_t     *filter_data = data;

    dd("set by lua file");

    if (njt_http_lua_set_by_lua_init(r) != NJT_OK) {
        return NJT_ERROR;
    }

    filter_data->script.data = v[0].data;
    filter_data->script.len = v[0].len;

    /* skip the lua file path argument */
    v++;
    nargs = filter_data->size - 1;

    dd("script: %.*s", (int) filter_data->script.len, filter_data->script.data);
    dd("nargs: %d", (int) nargs);

    script_path = njt_http_lua_rebase_path(r->pool, filter_data->script.data,
                                           filter_data->script.len);
    if (script_path == NULL) {
        return NJT_ERROR;
    }

    L = njt_http_lua_get_lua_vm(r, NULL);

    /*  load Lua script file (w/ cache)        sp = 1 */
    rc = njt_http_lua_cache_loadfile(r->connection->log, L, script_path,
                                     &filter_data->ref,
                                     filter_data->key);
    if (rc != NJT_OK) {
        return NJT_ERROR;
    }

    rc = njt_http_lua_set_by_chunk(L, r, val, v, nargs, &filter_data->script);
    if (rc != NJT_OK) {
        return NJT_ERROR;
    }

    return NJT_OK;
}
#endif /* defined(NDK) && NDK */


char *
njt_http_lua_rewrite_by_lua_block(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    char        *rv;
    njt_conf_t   save;

    save = *cf;
    cf->handler = njt_http_lua_rewrite_by_lua;
    cf->handler_conf = conf;

    rv = njt_http_lua_conf_lua_block_parse(cf, cmd);

    *cf = save;

    return rv;
}


char *
njt_http_lua_rewrite_by_lua(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    size_t                       chunkname_len;
    u_char                      *cache_key = NULL, *chunkname;
    njt_str_t                   *value;
    njt_http_lua_main_conf_t    *lmcf;
    njt_http_lua_loc_conf_t     *llcf = conf;

    njt_http_compile_complex_value_t         ccv;

    dd("enter");

    /*  must specify a content handler */
    if (cmd->post == NULL) {
        return NJT_CONF_ERROR;
    }

    if (llcf->rewrite_handler) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (value[1].len == 0) {
        /*  Oops...Invalid location conf */
        njt_conf_log_error(NJT_LOG_ERR, cf, 0,
                           "invalid location config: no runnable Lua code");

        return NJT_CONF_ERROR;
    }

    if (cmd->post == njt_http_lua_rewrite_handler_inline) {
        chunkname = njt_http_lua_gen_chunk_name(cf, "rewrite_by_lua",
                                                sizeof("rewrite_by_lua") - 1,
                                                &chunkname_len);
        if (chunkname == NULL) {
            return NJT_CONF_ERROR;
        }

        cache_key = njt_http_lua_gen_chunk_cache_key(cf, "rewrite_by_lua",
                                                     value[1].data,
                                                     value[1].len);
        if (cache_key == NULL) {
            return NJT_CONF_ERROR;
        }

        /* Don't eval njet variables for inline lua code */
        llcf->rewrite_src.value = value[1];
        llcf->rewrite_chunkname = chunkname;

    } else {
        njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));
        ccv.cf = cf;
        ccv.value = &value[1];
        ccv.complex_value = &llcf->rewrite_src;

        if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
            return NJT_CONF_ERROR;
        }

        if (llcf->rewrite_src.lengths == NULL) {
            /* no variable found */
            cache_key = njt_http_lua_gen_file_cache_key(cf, value[1].data,
                                                        value[1].len);
            if (cache_key == NULL) {
                return NJT_CONF_ERROR;
            }
        }
    }

    llcf->rewrite_src_key = cache_key;
    llcf->rewrite_handler = (njt_http_handler_pt) cmd->post;

    lmcf = njt_http_conf_get_module_main_conf(cf, njt_http_lua_module);

    lmcf->requires_rewrite = 1;
    lmcf->requires_capture_filter = 1;

    return NJT_CONF_OK;
}


char *
njt_http_lua_server_rewrite_by_lua_block(njt_conf_t *cf,
    njt_command_t *cmd, void *conf)
{
    char        *rv;
    njt_conf_t   save;
    save = *cf;
    cf->handler = njt_http_lua_server_rewrite_by_lua;
    cf->handler_conf = conf;

    rv = njt_http_lua_conf_lua_block_parse(cf, cmd);

    *cf = save;

    return rv;
}


char *
njt_http_lua_server_rewrite_by_lua(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    size_t                       chunkname_len;
    u_char                      *cache_key = NULL, *chunkname;
    njt_str_t                   *value;
    njt_http_lua_main_conf_t    *lmcf;
    njt_http_lua_srv_conf_t     *lscf = conf;

    njt_http_compile_complex_value_t         ccv;

    dd("enter");

    /*  must specify a content handler */
    if (cmd->post == NULL) {
        return NJT_CONF_ERROR;
    }

    if (lscf->srv.server_rewrite_handler) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (value[1].len == 0) {
        /*  Oops...Invalid location conf */
        njt_conf_log_error(NJT_LOG_ERR, cf, 0,
                           "invalid location config: no runnable Lua code");

        return NJT_CONF_ERROR;
    }

    if (cmd->post == njt_http_lua_server_rewrite_handler_inline) {
        chunkname =
            njt_http_lua_gen_chunk_name(cf, "server_rewrite_by_lua",
                                        sizeof("server_rewrite_by_lua") - 1,
                                        &chunkname_len);
        if (chunkname == NULL) {
            return NJT_CONF_ERROR;
        }

        cache_key =
            njt_http_lua_gen_chunk_cache_key(cf, "server_rewrite_by_lua",
                                             value[1].data,
                                             value[1].len);
        if (cache_key == NULL) {
            return NJT_CONF_ERROR;
        }

        /* Don't eval njet variables for inline lua code */
        lscf->srv.server_rewrite_src.value = value[1];
        lscf->srv.server_rewrite_chunkname = chunkname;

    } else {
        njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));
        ccv.cf = cf;
        ccv.value = &value[1];
        ccv.complex_value = &lscf->srv.server_rewrite_src;

        if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
            return NJT_CONF_ERROR;
        }

        if (lscf->srv.server_rewrite_src.lengths == NULL) {
            /* no variable found */
            cache_key = njt_http_lua_gen_file_cache_key(cf, value[1].data,
                                                        value[1].len);
            if (cache_key == NULL) {
                return NJT_CONF_ERROR;
            }
        }
    }

    lscf->srv.server_rewrite_src_key = cache_key;
    lscf->srv.server_rewrite_handler =
                                  (njt_http_lua_srv_conf_handler_pt) cmd->post;

    lmcf = njt_http_conf_get_module_main_conf(cf, njt_http_lua_module);

    lmcf->requires_server_rewrite = 1;
    lmcf->requires_capture_filter = 1;

    return NJT_CONF_OK;
}


char *
njt_http_lua_access_by_lua_block(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    char        *rv;
    njt_conf_t   save;

    save = *cf;
    cf->handler = njt_http_lua_access_by_lua;
    cf->handler_conf = conf;

    rv = njt_http_lua_conf_lua_block_parse(cf, cmd);

    *cf = save;

    return rv;
}


char *
njt_http_lua_access_by_lua(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    size_t                       chunkname_len;
    u_char                      *cache_key = NULL, *chunkname;
    njt_str_t                   *value;
    njt_http_lua_main_conf_t    *lmcf;
    njt_http_lua_loc_conf_t     *llcf = conf;

    njt_http_compile_complex_value_t         ccv;

    dd("enter");

    /*  must specify a content handler */
    if (cmd->post == NULL) {
        return NJT_CONF_ERROR;
    }

    if (llcf->access_handler) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (value[1].len == 0) {
        /*  Oops...Invalid location conf */
        njt_conf_log_error(NJT_LOG_ERR, cf, 0,
                           "invalid location config: no runnable Lua code");

        return NJT_CONF_ERROR;
    }

    if (cmd->post == njt_http_lua_access_handler_inline) {
        chunkname = njt_http_lua_gen_chunk_name(cf, "access_by_lua",
                                                sizeof("access_by_lua") - 1,
                                                &chunkname_len);
        if (chunkname == NULL) {
            return NJT_CONF_ERROR;
        }

        cache_key = njt_http_lua_gen_chunk_cache_key(cf, "access_by_lua",
                                                     value[1].data,
                                                     value[1].len);
        if (cache_key == NULL) {
            return NJT_CONF_ERROR;
        }

        /* Don't eval njet variables for inline lua code */
        llcf->access_src.value = value[1];
        llcf->access_chunkname = chunkname;

    } else {
        njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));
        ccv.cf = cf;
        ccv.value = &value[1];
        ccv.complex_value = &llcf->access_src;

        if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
            return NJT_CONF_ERROR;
        }

        if (llcf->access_src.lengths == NULL) {
            /* no variable found */
            cache_key = njt_http_lua_gen_file_cache_key(cf, value[1].data,
                                                        value[1].len);
            if (cache_key == NULL) {
                return NJT_CONF_ERROR;
            }
        }
    }

    llcf->access_src_key = cache_key;
    llcf->access_handler = (njt_http_handler_pt) cmd->post;

    lmcf = njt_http_conf_get_module_main_conf(cf, njt_http_lua_module);

    lmcf->requires_access = 1;
    lmcf->requires_capture_filter = 1;

    return NJT_CONF_OK;
}


char *
njt_http_lua_content_by_lua_block(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    char        *rv;
    njt_conf_t   save;

    save = *cf;
    cf->handler = njt_http_lua_content_by_lua;
    cf->handler_conf = conf;

    rv = njt_http_lua_conf_lua_block_parse(cf, cmd);

    *cf = save;

    return rv;
}


char *
njt_http_lua_content_by_lua(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    size_t                       chunkname_len;
    u_char                      *cache_key = NULL, *chunkname;
    njt_str_t                   *value;
    njt_http_core_loc_conf_t    *clcf;
    njt_http_lua_main_conf_t    *lmcf;
    njt_http_lua_loc_conf_t     *llcf = conf;

    njt_http_compile_complex_value_t         ccv;

    dd("enter");

    /*  must specify a content handler */
    if (cmd->post == NULL) {
        return NJT_CONF_ERROR;
    }

    if (llcf->content_handler) {
        return "is duplicate";
    }

    value = cf->args->elts;

    dd("value[0]: %.*s", (int) value[0].len, value[0].data);
    dd("value[1]: %.*s", (int) value[1].len, value[1].data);

    if (value[1].len == 0) {
        /*  Oops...Invalid location conf */
        njt_conf_log_error(NJT_LOG_ERR, cf, 0,
                           "invalid location config: no runnable Lua code");
        return NJT_CONF_ERROR;
    }

    if (cmd->post == njt_http_lua_content_handler_inline) {
        chunkname = njt_http_lua_gen_chunk_name(cf, "content_by_lua",
                                                sizeof("content_by_lua") - 1,
                                                &chunkname_len);
        if (chunkname == NULL) {
            return NJT_CONF_ERROR;
        }

        cache_key = njt_http_lua_gen_chunk_cache_key(cf, "content_by_lua",
                                                     value[1].data,
                                                     value[1].len);
        if (cache_key == NULL) {
            return NJT_CONF_ERROR;
        }

        /* Don't eval njet variables for inline lua code */
        llcf->content_src.value = value[1];
        llcf->content_chunkname = chunkname;

    } else {
        njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));
        ccv.cf = cf;
        ccv.value = &value[1];
        ccv.complex_value = &llcf->content_src;

        if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
            return NJT_CONF_ERROR;
        }

        if (llcf->content_src.lengths == NULL) {
            /* no variable found */
            cache_key = njt_http_lua_gen_file_cache_key(cf, value[1].data,
                                                        value[1].len);
            if (cache_key == NULL) {
                return NJT_CONF_ERROR;
            }
        }
    }

    llcf->content_src_key = cache_key;
    llcf->content_handler = (njt_http_handler_pt) cmd->post;

    lmcf = njt_http_conf_get_module_main_conf(cf, njt_http_lua_module);

    lmcf->requires_capture_filter = 1;

    /*  register location content handler */
    clcf = njt_http_conf_get_module_loc_conf(cf, njt_http_core_module);
    if (clcf == NULL) {
        return NJT_CONF_ERROR;
    }

    clcf->handler = njt_http_lua_content_handler;

    return NJT_CONF_OK;
}


char *
njt_http_lua_log_by_lua_block(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    char        *rv;
    njt_conf_t   save;

    save = *cf;
    cf->handler = njt_http_lua_log_by_lua;
    cf->handler_conf = conf;

    rv = njt_http_lua_conf_lua_block_parse(cf, cmd);

    *cf = save;

    return rv;
}


char *
njt_http_lua_log_by_lua(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    size_t                       chunkname_len;
    u_char                      *cache_key = NULL, *chunkname;
    njt_str_t                   *value;
    njt_http_lua_main_conf_t    *lmcf;
    njt_http_lua_loc_conf_t     *llcf = conf;

    njt_http_compile_complex_value_t         ccv;

    dd("enter");

    /*  must specify a content handler */
    if (cmd->post == NULL) {
        return NJT_CONF_ERROR;
    }

    if (llcf->log_handler) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (value[1].len == 0) {
        /*  Oops...Invalid location conf */
        njt_conf_log_error(NJT_LOG_ERR, cf, 0,
                           "invalid location config: no runnable Lua code");

        return NJT_CONF_ERROR;
    }

    if (cmd->post == njt_http_lua_log_handler_inline) {
        chunkname = njt_http_lua_gen_chunk_name(cf, "log_by_lua",
                                                sizeof("log_by_lua") - 1,
                                                &chunkname_len);
        if (chunkname == NULL) {
            return NJT_CONF_ERROR;
        }

        cache_key = njt_http_lua_gen_chunk_cache_key(cf, "log_by_lua",
                                                     value[1].data,
                                                     value[1].len);
        if (cache_key == NULL) {
            return NJT_CONF_ERROR;
        }

        /* Don't eval njet variables for inline lua code */
        llcf->log_src.value = value[1];
        llcf->log_chunkname = chunkname;

    } else {
        njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));
        ccv.cf = cf;
        ccv.value = &value[1];
        ccv.complex_value = &llcf->log_src;

        if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
            return NJT_CONF_ERROR;
        }

        if (llcf->log_src.lengths == NULL) {
            /* no variable found */
            cache_key = njt_http_lua_gen_file_cache_key(cf, value[1].data,
                                                        value[1].len);
            if (cache_key == NULL) {
                return NJT_CONF_ERROR;
            }
        }
    }

    llcf->log_src_key = cache_key;
    llcf->log_handler = (njt_http_handler_pt) cmd->post;

    lmcf = njt_http_conf_get_module_main_conf(cf, njt_http_lua_module);

    lmcf->requires_log = 1;

    return NJT_CONF_OK;
}


char *
njt_http_lua_header_filter_by_lua_block(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    char        *rv;
    njt_conf_t   save;

    save = *cf;
    cf->handler = njt_http_lua_header_filter_by_lua;
    cf->handler_conf = conf;

    rv = njt_http_lua_conf_lua_block_parse(cf, cmd);

    *cf = save;

    return rv;
}


char *
njt_http_lua_header_filter_by_lua(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    size_t                       chunkname_len;
    u_char                      *cache_key = NULL, *chunkname;
    njt_str_t                   *value;
    njt_http_lua_main_conf_t    *lmcf;
    njt_http_lua_loc_conf_t     *llcf = conf;

    njt_http_compile_complex_value_t         ccv;

    dd("enter");

    /*  must specify a content handler */
    if (cmd->post == NULL) {
        return NJT_CONF_ERROR;
    }

    if (llcf->header_filter_handler) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (value[1].len == 0) {
        /*  Oops...Invalid location conf */
        njt_conf_log_error(NJT_LOG_ERR, cf, 0,
                           "invalid location config: no runnable Lua code");
        return NJT_CONF_ERROR;
    }

    if (cmd->post == njt_http_lua_header_filter_inline) {
        cache_key = njt_http_lua_gen_chunk_cache_key(cf, "header_filter_by_lua",
                                                     value[1].data,
                                                     value[1].len);
        if (cache_key == NULL) {
            return NJT_CONF_ERROR;
        }

        chunkname = njt_http_lua_gen_chunk_name(cf, "header_filter_by_lua",
                            sizeof("header_filter_by_lua") - 1, &chunkname_len);
        if (chunkname == NULL) {
            return NJT_CONF_ERROR;
        }

        /* Don't eval njet variables for inline lua code */
        llcf->header_filter_src.value = value[1];
        llcf->header_filter_chunkname = chunkname;

    } else {
        njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));
        ccv.cf = cf;
        ccv.value = &value[1];
        ccv.complex_value = &llcf->header_filter_src;

        if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
            return NJT_CONF_ERROR;
        }

        if (llcf->header_filter_src.lengths == NULL) {
            /* no variable found */
            cache_key = njt_http_lua_gen_file_cache_key(cf, value[1].data,
                                                        value[1].len);
            if (cache_key == NULL) {
                return NJT_CONF_ERROR;
            }
        }
    }

    llcf->header_filter_src_key = cache_key;
    llcf->header_filter_handler = (njt_http_handler_pt) cmd->post;

    lmcf = njt_http_conf_get_module_main_conf(cf, njt_http_lua_module);

    lmcf->requires_header_filter = 1;

    return NJT_CONF_OK;
}


char *
njt_http_lua_body_filter_by_lua_block(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    char        *rv;
    njt_conf_t   save;

    save = *cf;
    cf->handler = njt_http_lua_body_filter_by_lua;
    cf->handler_conf = conf;

    rv = njt_http_lua_conf_lua_block_parse(cf, cmd);

    *cf = save;

    return rv;
}


char *
njt_http_lua_body_filter_by_lua(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    size_t                       chunkname_len;
    u_char                      *cache_key = NULL, *chunkname;
    njt_str_t                   *value;
    njt_http_lua_main_conf_t    *lmcf;
    njt_http_lua_loc_conf_t     *llcf = conf;

    njt_http_compile_complex_value_t         ccv;

    dd("enter");

    /*  must specify a content handler */
    if (cmd->post == NULL) {
        return NJT_CONF_ERROR;
    }

    if (llcf->body_filter_handler) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (value[1].len == 0) {
        /*  Oops...Invalid location conf */
        njt_conf_log_error(NJT_LOG_ERR, cf, 0,
                           "invalid location config: no runnable Lua code");
        return NJT_CONF_ERROR;
    }

    if (cmd->post == njt_http_lua_body_filter_inline) {
        cache_key = njt_http_lua_gen_chunk_cache_key(cf, "body_filter_by_lua",
                                                     value[1].data,
                                                     value[1].len);
        if (cache_key == NULL) {
            return NJT_CONF_ERROR;
        }

        chunkname = njt_http_lua_gen_chunk_name(cf, "body_filter_by_lua",
                              sizeof("body_filter_by_lua") - 1, &chunkname_len);
        if (chunkname == NULL) {
            return NJT_CONF_ERROR;
        }


        /* Don't eval njet variables for inline lua code */
        llcf->body_filter_src.value = value[1];
        llcf->body_filter_chunkname = chunkname;

    } else {
        njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));
        ccv.cf = cf;
        ccv.value = &value[1];
        ccv.complex_value = &llcf->body_filter_src;

        if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
            return NJT_CONF_ERROR;
        }

        if (llcf->body_filter_src.lengths == NULL) {
            /* no variable found */
            cache_key = njt_http_lua_gen_file_cache_key(cf, value[1].data,
                                                        value[1].len);
            if (cache_key == NULL) {
                return NJT_CONF_ERROR;
            }
        }
    }

    llcf->body_filter_src_key = cache_key;
    llcf->body_filter_handler = (njt_http_output_body_filter_pt) cmd->post;

    lmcf = njt_http_conf_get_module_main_conf(cf, njt_http_lua_module);

    lmcf->requires_body_filter = 1;
    lmcf->requires_header_filter = 1;

    return NJT_CONF_OK;
}


char *
njt_http_lua_init_by_lua_block(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    char        *rv;
    njt_conf_t   save;

    save = *cf;
    cf->handler = njt_http_lua_init_by_lua;
    cf->handler_conf = conf;

    rv = njt_http_lua_conf_lua_block_parse(cf, cmd);

    *cf = save;

    return rv;
}


char *
njt_http_lua_init_by_lua(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    u_char                      *name;
    njt_str_t                   *value;
    njt_http_lua_main_conf_t    *lmcf = conf;
    size_t                       chunkname_len;
    u_char                      *chunkname;

    dd("enter");

    /*  must specify a content handler */
    if (cmd->post == NULL) {
        return NJT_CONF_ERROR;
    }

    if (lmcf->init_handler) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (value[1].len == 0) {
        /*  Oops...Invalid location conf */
        njt_conf_log_error(NJT_LOG_ERR, cf, 0,
                           "invalid location config: no runnable Lua code");
        return NJT_CONF_ERROR;
    }

    lmcf->init_handler = (njt_http_lua_main_conf_handler_pt) cmd->post;

    if (cmd->post == njt_http_lua_init_by_file) {
        name = njt_http_lua_rebase_path(cf->pool, value[1].data,
                                        value[1].len);
        if (name == NULL) {
            return NJT_CONF_ERROR;
        }

        lmcf->init_src.data = name;
        lmcf->init_src.len = njt_strlen(name);

    } else {
        lmcf->init_src = value[1];

        chunkname = njt_http_lua_gen_chunk_name(cf, "init_by_lua",
                                                sizeof("init_by_lua") - 1,
                                                &chunkname_len);
        if (chunkname == NULL) {
            return NJT_CONF_ERROR;
        }

        lmcf->init_chunkname = chunkname;
    }

    return NJT_CONF_OK;
}


char *
njt_http_lua_init_worker_by_lua_block(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    char        *rv;
    njt_conf_t   save;

    save = *cf;
    cf->handler = njt_http_lua_init_worker_by_lua;
    cf->handler_conf = conf;

    rv = njt_http_lua_conf_lua_block_parse(cf, cmd);

    *cf = save;

    return rv;
}


char *
njt_http_lua_init_worker_by_lua(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    u_char                      *name;
    njt_str_t                   *value;
    njt_http_lua_main_conf_t    *lmcf = conf;
    size_t                       chunkname_len;
    u_char                      *chunkname;

    dd("enter");

    /*  must specify a content handler */
    if (cmd->post == NULL) {
        return NJT_CONF_ERROR;
    }

    if (lmcf->init_worker_handler) {
        return "is duplicate";
    }

    value = cf->args->elts;

    lmcf->init_worker_handler = (njt_http_lua_main_conf_handler_pt) cmd->post;

    if (cmd->post == njt_http_lua_init_worker_by_file) {
        name = njt_http_lua_rebase_path(cf->pool, value[1].data,
                                        value[1].len);
        if (name == NULL) {
            return NJT_CONF_ERROR;
        }

        lmcf->init_worker_src.data = name;
        lmcf->init_worker_src.len = njt_strlen(name);

    } else {
        lmcf->init_worker_src = value[1];

        chunkname = njt_http_lua_gen_chunk_name(cf, "init_worker_by_lua",
                              sizeof("init_worker_by_lua") - 1, &chunkname_len);
        if (chunkname == NULL) {
            return NJT_CONF_ERROR;
        }

        lmcf->init_worker_chunkname = chunkname;
    }

    return NJT_CONF_OK;
}


char *
njt_http_lua_exit_worker_by_lua_block(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    char        *rv;
    njt_conf_t   save;

    save = *cf;
    cf->handler = njt_http_lua_exit_worker_by_lua;
    cf->handler_conf = conf;

    rv = njt_http_lua_conf_lua_block_parse(cf, cmd);

    *cf = save;

    return rv;
}


char *
njt_http_lua_exit_worker_by_lua(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    u_char                      *name;
    njt_str_t                   *value;
    njt_http_lua_main_conf_t    *lmcf = conf;
    size_t                       chunkname_len;
    u_char                      *chunkname;

    /*  must specify a content handler */
    if (cmd->post == NULL) {
        return NJT_CONF_ERROR;
    }

    if (lmcf->exit_worker_handler) {
        return "is duplicate";
    }

    value = cf->args->elts;

    lmcf->exit_worker_handler = (njt_http_lua_main_conf_handler_pt) cmd->post;

    if (cmd->post == njt_http_lua_exit_worker_by_file) {
        name = njt_http_lua_rebase_path(cf->pool, value[1].data,
                                        value[1].len);
        if (name == NULL) {
            return NJT_CONF_ERROR;
        }

        lmcf->exit_worker_src.data = name;
        lmcf->exit_worker_src.len = njt_strlen(name);

    } else {
        lmcf->exit_worker_src = value[1];

        chunkname = njt_http_lua_gen_chunk_name(cf, "exit_worker_by_lua",
                                                sizeof("exit_worker_by_lua")- 1,
                                                &chunkname_len);
        if (chunkname == NULL) {
            return NJT_CONF_ERROR;
        }

        lmcf->exit_worker_chunkname = chunkname;
    }

    return NJT_CONF_OK;
}


#if defined(NDK) && NDK
static njt_int_t
njt_http_lua_set_by_lua_init(njt_http_request_t *r)
{
    lua_State                   *L;
    njt_http_lua_ctx_t          *ctx;
    njt_pool_cleanup_t          *cln;

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);
    if (ctx == NULL) {
        ctx = njt_http_lua_create_ctx(r);
        if (ctx == NULL) {
            return NJT_ERROR;
        }

    } else {
        L = njt_http_lua_get_lua_vm(r, ctx);
        njt_http_lua_reset_ctx(r, L, ctx);
    }

    if (ctx->cleanup == NULL) {
        cln = njt_pool_cleanup_add(r->pool, 0);
        if (cln == NULL) {
            return NJT_ERROR;
        }

        cln->handler = njt_http_lua_request_cleanup_handler;
        cln->data = ctx;
        ctx->cleanup = &cln->handler;
    }

    ctx->context = NJT_HTTP_LUA_CONTEXT_SET;
    return NJT_OK;
}
#endif


u_char *
njt_http_lua_gen_chunk_name(njt_conf_t *cf, const char *tag, size_t tag_len,
    size_t *chunkname_len)
{
    u_char      *p, *out;
    size_t       len;
    njt_uint_t   start_line;
    njt_str_t   *conf_prefix;
    njt_str_t   *filename;
    u_char      *filename_end;
    const char  *pre_str = "";
    njt_uint_t   reserve_len;

    njt_http_lua_main_conf_t    *lmcf;

    len = sizeof("=(:)") - 1 + tag_len + cf->conf_file->file.name.len
          + NJT_INT64_LEN + 1;

    out = njt_palloc(cf->pool, len);
    if (out == NULL) {
        return NULL;
    }

    lmcf = njt_http_conf_get_module_main_conf(cf, njt_http_lua_module);
    start_line = lmcf->directive_line > 0
        ? lmcf->directive_line : cf->conf_file->line;
    p = njt_snprintf(out, len, "%d", start_line);
    reserve_len = tag_len + p - out;

    filename = &cf->conf_file->file.name;
    filename_end = filename->data + filename->len;
    if (filename->len > 0) {
        if (filename->len >= 11) {
            p = filename_end - 11;
            if ((*p == '/' || *p == '\\')
                && njt_memcmp(p, "/njet.conf", 11) == 0)
            {
                p++; /* now p is njet.conf */
                goto found;
            }
        }

        conf_prefix = &cf->cycle->conf_prefix;
        p = filename->data + conf_prefix->len;
        if ((conf_prefix->len < filename->len)
            && njt_memcmp(conf_prefix->data,
                          filename->data, conf_prefix->len) == 0)
        {
            /* files in conf_prefix directory, use the relative path */
            if (filename_end - p + reserve_len > LJ_CHUNKNAME_MAX_LEN) {
                p = filename_end - LJ_CHUNKNAME_MAX_LEN + reserve_len + 3;
                pre_str = "...";
            }

            goto found;
        }
    }

    p = filename->data;

    if (filename->len + reserve_len <= LJ_CHUNKNAME_MAX_LEN) {
        goto found;
    }

    p = filename_end - LJ_CHUNKNAME_MAX_LEN + reserve_len + 3;
    pre_str = "...";

found:


    p = njt_snprintf(out, len, "=%*s(%s%*s:%d)%Z",
                     tag_len, tag, pre_str, filename_end - p,
                     p, start_line);

    *chunkname_len = p - out - 1;  /* exclude the trailing '\0' byte */

    return out;
}


/* a specialized version of the standard njt_conf_parse() function */
char *
njt_http_lua_conf_lua_block_parse(njt_conf_t *cf, njt_command_t *cmd)
{
    njt_http_lua_main_conf_t           *lmcf;
    njt_http_lua_block_parser_ctx_t     ctx;

    int               level = 1;
    char             *rv;
    u_char           *p;
    size_t            len;
    njt_str_t        *src, *dst;
    njt_int_t         rc;
    njt_uint_t        i, start_line;
    njt_array_t      *saved;
    enum {
        parse_block = 0,
        parse_param,
    } type;

    if (cf->conf_file->file.fd != NJT_INVALID_FILE) {

        type = parse_block;

    } else {
        type = parse_param;
    }

    saved = cf->args;

    cf->args = njt_array_create(cf->temp_pool, 4, sizeof(njt_str_t));
    if (cf->args == NULL) {
        return NJT_CONF_ERROR;
    }

    ctx.token_len = 0;
    start_line = cf->conf_file->line;

    lmcf = njt_http_conf_get_module_main_conf(cf, njt_http_lua_module);
    lmcf->directive_line = start_line;

    dd("init start line: %d", (int) start_line);

    ctx.start_line = start_line;

    for ( ;; ) {
        rc = njt_http_lua_conf_read_lua_token(cf, &ctx);

        dd("parser start line: %d", (int) start_line);

        switch (rc) {

        case NJT_ERROR:
            goto done;

        case FOUND_LEFT_CURLY:

            ctx.start_line = cf->conf_file->line;

            if (type == parse_param) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "block directives are not supported "
                                   "in -g option");
                goto failed;
            }

            level++;
            dd("seen block start: level=%d", (int) level);
            break;

        case FOUND_RIGHT_CURLY:

            level--;
            dd("seen block done: level=%d", (int) level);

            if (type != parse_block || level < 0) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "unexpected \"}\": level %d, "
                                   "starting at line %ui", level,
                                   start_line);
                goto failed;
            }

            if (level == 0) {
                njt_http_lua_assert(cf->handler);

                src = cf->args->elts;

                for (len = 0, i = 0; i < cf->args->nelts; i++) {
                    len += src[i].len;
                }

                dd("saved nelts: %d", (int) saved->nelts);
                dd("temp nelts: %d", (int) cf->args->nelts);
#if 0
                njt_http_lua_assert(saved->nelts == 1);
#endif

                dst = njt_array_push(saved);
                if (dst == NULL) {
                    return NJT_CONF_ERROR;
                }

                dst->len = len;
                dst->len--;  /* skip the trailing '}' block terminator */

                p = njt_palloc(cf->pool, len);
                if (p == NULL) {
                    return NJT_CONF_ERROR;
                }

                dst->data = p;

                for (i = 0; i < cf->args->nelts; i++) {
                    p = njt_copy(p, src[i].data, src[i].len);
                }

                p[-1] = '\0';  /* override the last '}' char to null */

                cf->args = saved;

                rv = (*cf->handler)(cf, cmd, cf->handler_conf);
                if (rv == NJT_CONF_OK) {
                    goto done;
                }

                if (rv == NJT_CONF_ERROR) {
                    goto failed;
                }

                njt_conf_log_error(NJT_LOG_EMERG, cf, 0, rv);

                goto failed;
            }

            break;

        case FOUND_LBRACKET_STR:
        case FOUND_LBRACKET_CMT:
        case FOUND_RIGHT_LBRACKET:
        case FOUND_COMMENT_LINE:
        case FOUND_DOUBLE_QUOTED:
        case FOUND_SINGLE_QUOTED:
            break;

        default:

            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "unknown return value from the lexer: %i", rc);
            goto failed;
        }
    }

failed:

    rc = NJT_ERROR;

done:

    lmcf->directive_line = 0;

    if (rc == NJT_ERROR) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


static njt_int_t
njt_http_lua_conf_read_lua_token(njt_conf_t *cf,
    njt_http_lua_block_parser_ctx_t *ctx)
{
    enum {
        OVEC_SIZE = 2,
    };
    int          i, rc;
    int          ovec[OVEC_SIZE];
    u_char      *start, *p, *q, ch;
    off_t        file_size;
    size_t       len, buf_size;
    ssize_t      n, size;
    njt_uint_t   start_line;
    njt_str_t   *word;
    njt_buf_t   *b;
#if (njet_version >= 1009002)
    njt_buf_t   *dump;
#endif

    b = cf->conf_file->buffer;
#if (njet_version >= 1009002)
    dump = cf->conf_file->dump;
#endif
    start = b->pos;
    start_line = cf->conf_file->line;
    buf_size = b->end - b->start;

    dd("lexer start line: %d", (int) start_line);

    file_size = njt_file_size(&cf->conf_file->file.info);

    for ( ;; ) {

        if (b->pos >= b->last
            || (b->last - b->pos < (b->end - b->start) / 2
                && cf->conf_file->file.offset < file_size))
        {

            if (cf->conf_file->file.offset >= file_size) {

                cf->conf_file->line = ctx->start_line;

                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "unexpected end of file, expecting "
                                   "terminating characters for lua code "
                                   "block");
                return NJT_ERROR;
            }

            len = b->last - start;

            if (len == buf_size) {

                cf->conf_file->line = start_line;

                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "too long lua code block, probably "
                                   "missing terminating characters");

                return NJT_ERROR;
            }

            if (len) {
                njt_memmove(b->start, start, len);
            }

            size = (ssize_t) (file_size - cf->conf_file->file.offset);

            if (size > b->end - (b->start + len)) {
                size = b->end - (b->start + len);
            }

            n = njt_read_file(&cf->conf_file->file, b->start + len, size,
                              cf->conf_file->file.offset);

            if (n == NJT_ERROR) {
                return NJT_ERROR;
            }

            if (n != size) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   njt_read_file_n " returned "
                                   "only %z bytes instead of %z",
                                   n, size);
                return NJT_ERROR;
            }

            b->pos = b->start + (b->pos - start);
            b->last = b->start + len + n;
            start = b->start;

#if (njet_version >= 1009002)
            if (dump) {
                dump->last = njt_cpymem(dump->last, b->start + len, size);
            }
#endif
        }

        rc = njt_http_lua_lex(b->pos, b->last - b->pos, ovec);

        if (rc < 0) {  /* no match */
            /* alas. the lexer does not yet support streaming processing. need
             * more work below */

            if (cf->conf_file->file.offset >= file_size) {

                cf->conf_file->line = ctx->start_line;

                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "unexpected end of file, expecting "
                                   "terminating characters for lua code "
                                   "block");
                return NJT_ERROR;
            }

            len = b->last - b->pos;

            if (len == buf_size) {

                cf->conf_file->line = start_line;

                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "too long lua code block, probably "
                                   "missing terminating characters");

                return NJT_ERROR;
            }

            if (len) {
                njt_memmove(b->start, b->pos, len);
            }

            size = (ssize_t) (file_size - cf->conf_file->file.offset);

            if (size > b->end - (b->start + len)) {
                size = b->end - (b->start + len);
            }

            n = njt_read_file(&cf->conf_file->file, b->start + len, size,
                              cf->conf_file->file.offset);

            if (n == NJT_ERROR) {
                return NJT_ERROR;
            }

            if (n != size) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   njt_read_file_n " returned "
                                   "only %z bytes instead of %z",
                                   n, size);
                return NJT_ERROR;
            }

            b->pos = b->start + len;
            b->last = b->pos + n;
            start = b->start;

            continue;
        }

        if (rc == FOUND_LEFT_LBRACKET_STR || rc == FOUND_LEFT_LBRACKET_CMT) {

            /* we update the line numbers for best error messages when the
             * closing long bracket is missing */

            for (i = 0; i < ovec[0]; i++) {
                ch = b->pos[i];
                if (ch == LF) {
                    cf->conf_file->line++;
                }
            }

            b->pos += ovec[0];
            ovec[1] -= ovec[0];
            ovec[0] = 0;

            if (rc == FOUND_LEFT_LBRACKET_CMT) {
                p = &b->pos[2];     /* we skip the leading "--" prefix */
                rc = FOUND_LBRACKET_CMT;

            } else {
                p = b->pos;
                rc = FOUND_LBRACKET_STR;
            }

            /* we temporarily rewrite [=*[ in the input buffer to ]=*] to
             * construct the pattern for the corresponding closing long
             * bracket without additional buffers. */

            njt_http_lua_assert(p[0] == '[');
            p[0] = ']';

            njt_http_lua_assert(b->pos[ovec[1] - 1] == '[');
            b->pos[ovec[1] - 1] = ']';

            /* search for the corresponding closing bracket */

            dd("search pattern for the closing long bracket: \"%.*s\" (len=%d)",
               (int) (b->pos + ovec[1] - p), p, (int) (b->pos + ovec[1] - p));

            q = njt_http_lua_strlstrn(b->pos + ovec[1], b->last, p,
                                      b->pos + ovec[1] - p - 1);

            if (q == NULL) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "Lua code block missing the closing "
                                   "long bracket \"%*s\", "
                                   "the inlined Lua code may be too long",
                                   b->pos + ovec[1] - p, p);
                return NJT_ERROR;
            }

            /* restore the original opening long bracket */

            p[0] = '[';
            b->pos[ovec[1] - 1] = '[';

            ovec[1] = q - b->pos + b->pos + ovec[1] - p;

            dd("found long bracket token: \"%.*s\"",
               (int) (ovec[1] - ovec[0]), b->pos + ovec[0]);
        }

        for (i = 0; i < ovec[1]; i++) {
            ch = b->pos[i];
            if (ch == LF) {
                cf->conf_file->line++;
            }
        }

        b->pos += ovec[1];
        ctx->token_len = ovec[1] - ovec[0];

        break;
    }

    word = njt_array_push(cf->args);
    if (word == NULL) {
        return NJT_ERROR;
    }

    word->data = njt_pnalloc(cf->temp_pool, b->pos - start);
    if (word->data == NULL) {
        return NJT_ERROR;
    }

    len = b->pos - start;
    njt_memcpy(word->data, start, len);
    word->len = len;

    return rc;
}


char *
njt_http_lua_capture_error_log(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
#ifndef HAVE_INTERCEPT_ERROR_LOG_PATCH
    return "not found: missing the capture error log patch for njet";
#else
    njt_str_t                     *value;
    ssize_t                        size;
    u_char                        *data;
    njt_cycle_t                   *cycle;
    njt_http_lua_main_conf_t      *lmcf = conf;
    njt_http_lua_log_ringbuf_t    *ringbuf;

    value = cf->args->elts;
    cycle = cf->cycle;

    if (lmcf->requires_capture_log) {
        return "is duplicate";
    }

    if (value[1].len == 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid capture error log size \"%V\"",
                           &value[1]);
        return NJT_CONF_ERROR;
    }

    size = njt_parse_size(&value[1]);

    if (size < NJT_MAX_ERROR_STR) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid capture error log size \"%V\", "
                           "minimum size is %d", &value[1],
                           NJT_MAX_ERROR_STR);
        return NJT_CONF_ERROR;
    }

    if (cycle->intercept_error_log_handler) {
        return "capture error log handler has been hooked";
    }

    ringbuf = (njt_http_lua_log_ringbuf_t *)
              njt_palloc(cf->pool, sizeof(njt_http_lua_log_ringbuf_t));
    if (ringbuf == NULL) {
        return NJT_CONF_ERROR;
    }

    data = njt_palloc(cf->pool, size);
    if (data == NULL) {
        return NJT_CONF_ERROR;
    }

    njt_http_lua_log_ringbuf_init(ringbuf, data, size);

    lmcf->requires_capture_log = 1;
    cycle->intercept_error_log_handler = (njt_log_intercept_pt)
                                         njt_http_lua_capture_log_handler;
    cycle->intercept_error_log_data = ringbuf;

    return NJT_CONF_OK;
#endif
}


/*
 * njt_http_lua_strlstrn() is intended to search for static substring
 * with known length in string until the argument last. The argument n
 * must be length of the second substring - 1.
 */

static u_char *
njt_http_lua_strlstrn(u_char *s1, u_char *last, u_char *s2, size_t n)
{
    njt_uint_t  c1, c2;

    c2 = (njt_uint_t) *s2++;
    last -= n;

    do {
        do {
            if (s1 >= last) {
                return NULL;
            }

            c1 = (njt_uint_t) *s1++;

            dd("testing char '%c' vs '%c'", (int) c1, (int) c2);

        } while (c1 != c2);

        dd("testing against pattern \"%.*s\"", (int) n, s2);

    } while (njt_strncmp(s1, s2, n) != 0);

    return --s1;
}


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
