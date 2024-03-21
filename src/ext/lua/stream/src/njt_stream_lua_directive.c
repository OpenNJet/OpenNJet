
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_directive.c.tt2
 */


/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_stream_lua_common.h"
#include "njt_stream_lua_directive.h"
#include "njt_stream_lua_util.h"
#include "njt_stream_lua_cache.h"
#include "njt_stream_lua_contentby.h"
#include "njt_stream_lua_logby.h"
#include "njt_stream_lua_initby.h"
#include "njt_stream_lua_initworkerby.h"
#include "njt_stream_lua_shdict.h"
#include "njt_stream_lua_lex.h"
#include "njt_stream_lua_log.h"
#include "njt_stream_lua_log_ringbuf.h"
#include "api/njt_stream_lua_api.h"

#include "njt_stream_lua_prereadby.h"


typedef struct njt_stream_lua_block_parser_ctx_s
    njt_stream_lua_block_parser_ctx_t;



static u_char *njt_stream_lua_gen_chunk_name(njt_conf_t *cf, const char *tag,
    size_t tag_len, size_t *chunkname_len);
static njt_int_t njt_stream_lua_conf_read_lua_token(njt_conf_t *cf,
    njt_stream_lua_block_parser_ctx_t *ctx);
static u_char *njt_stream_lua_strlstrn(u_char *s1, u_char *last, u_char *s2,
    size_t n);


struct njt_stream_lua_block_parser_ctx_s {
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
    FOUND_SINGLE_QUOTED
};


char *
njt_stream_lua_shared_dict(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_stream_lua_main_conf_t         *lmcf = conf;
    njt_str_t                          *value, name;
    njt_shm_zone_t                     *zone;
    njt_shm_zone_t                    **zp;
    njt_stream_lua_shdict_ctx_t        *ctx;
    ssize_t                             size;

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

    ctx = njt_pcalloc(cf->pool, sizeof(njt_stream_lua_shdict_ctx_t));
    if (ctx == NULL) {
        return NJT_CONF_ERROR;
    }

    ctx->name = name;
    ctx->main_conf = lmcf;
    ctx->log = &cf->cycle->new_log;

    zone = njt_stream_lua_shared_memory_add(cf, &name, (size_t) size,
                                            &njt_stream_lua_module);
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

    zone->init = njt_stream_lua_shdict_init_zone;
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
njt_stream_lua_code_cache(njt_conf_t *cf, njt_command_t *cmd, void *conf)
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
                           "stream lua_code_cache is off; this will hurt "
                           "performance");
    }

    return NJT_CONF_OK;
}


char *
njt_stream_lua_load_resty_core(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                       "lua_load_resty_core is deprecated (the lua-resty-core "
                       "library is required since "
                       "njt_stream_lua v0.0.8)");

    return NJT_CONF_OK;
}


char *
njt_stream_lua_package_cpath(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_stream_lua_main_conf_t       *lmcf = conf;

    njt_str_t        *value;

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
njt_stream_lua_package_path(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_stream_lua_main_conf_t       *lmcf = conf;

    njt_str_t         *value;

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
njt_stream_lua_preread_by_lua_block(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    char        *rv;
    njt_conf_t   save;

    save = *cf;
    cf->handler = njt_stream_lua_preread_by_lua;
    cf->handler_conf = conf;

    rv = njt_stream_lua_conf_lua_block_parse(cf, cmd);

    *cf = save;

    return rv;
}


char *
njt_stream_lua_preread_by_lua(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    size_t                                 chunkname_len;
    u_char                                *p, *chunkname;
    njt_str_t                             *value;
    njt_stream_lua_main_conf_t            *lmcf;
    njt_stream_lua_srv_conf_t             *lscf = conf;

    njt_stream_compile_complex_value_t     ccv;

    dd("enter");

    /*  must specify a content handler */
    if (cmd->post == NULL) {
        return NJT_CONF_ERROR;
    }

    if (lscf->preread_handler) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (value[1].len == 0) {
        /*  Oops...Invalid server conf */
        njt_conf_log_error(NJT_LOG_ERR, cf, 0,
                           "invalid server config: no runnable Lua code");

        return NJT_CONF_ERROR;
    }

    if (cmd->post == njt_stream_lua_preread_handler_inline) {
        chunkname = njt_stream_lua_gen_chunk_name(cf, "preread_by_lua",
                                                  sizeof("preread_by_lua") - 1,
                                                  &chunkname_len);
        if (chunkname == NULL) {
            return NJT_CONF_ERROR;
        }

        lscf->preread_chunkname = chunkname;

        /* Don't eval njet variables for inline lua code */

        lscf->preread_src.value = value[1];

        p = njt_palloc(cf->pool,
                       chunkname_len + NJT_STREAM_LUA_INLINE_KEY_LEN + 1);
        if (p == NULL) {
            return NJT_CONF_ERROR;
        }

        lscf->preread_src_key = p;

        p = njt_copy(p, chunkname, chunkname_len);
        p = njt_copy(p, NJT_STREAM_LUA_INLINE_TAG,
                     NJT_STREAM_LUA_INLINE_TAG_LEN);
        p = njt_stream_lua_digest_hex(p, value[1].data, value[1].len);
        *p = '\0';

    } else {
        njt_memzero(&ccv, sizeof(njt_stream_compile_complex_value_t));
        ccv.cf = cf;
        ccv.value = &value[1];
        ccv.complex_value = &lscf->preread_src;

        if (njt_stream_compile_complex_value(&ccv) != NJT_OK) {
            return NJT_CONF_ERROR;
        }

        if (lscf->preread_src.lengths == NULL) {
            /* no variable found */
            p = njt_palloc(cf->pool, NJT_STREAM_LUA_FILE_KEY_LEN + 1);
            if (p == NULL) {
                return NJT_CONF_ERROR;
            }

            lscf->preread_src_key = p;

            p = njt_copy(p, NJT_STREAM_LUA_FILE_TAG,
                         NJT_STREAM_LUA_FILE_TAG_LEN);
            p = njt_stream_lua_digest_hex(p, value[1].data, value[1].len);
            *p = '\0';
        }
    }

    lscf->preread_handler = (njt_stream_lua_handler_pt) cmd->post;

    lmcf = njt_stream_conf_get_module_main_conf(cf, njt_stream_lua_module);

    lmcf->requires_preread = 1;

    return NJT_CONF_OK;
}

char *
njt_stream_lua_content_by_lua_block(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    char        *rv;
    njt_conf_t   save;

    save = *cf;
    cf->handler = njt_stream_lua_content_by_lua;
    cf->handler_conf = conf;

    rv = njt_stream_lua_conf_lua_block_parse(cf, cmd);

    *cf = save;

    return rv;
}


char *
njt_stream_lua_content_by_lua(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    size_t                         chunkname_len;
    u_char                        *p;
    u_char                        *chunkname;
    njt_str_t                     *value;

    njt_stream_core_srv_conf_t    *cxcf;


    njt_stream_compile_complex_value_t               ccv;

    njt_stream_lua_loc_conf_t             *llcf = conf;

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

    if (cmd->post == njt_stream_lua_content_handler_inline) {
        chunkname = njt_stream_lua_gen_chunk_name(cf, "content_by_lua",
                                                  sizeof("content_by_lua") - 1,
                                                  &chunkname_len);
        if (chunkname == NULL) {
            return NJT_CONF_ERROR;
        }

        llcf->content_chunkname = chunkname;

        dd("chunkname: %s", chunkname);

        /* Don't eval njet variables for inline lua code */

        llcf->content_src.value = value[1];

        p = njt_palloc(cf->pool,
                       chunkname_len + NJT_STREAM_LUA_INLINE_KEY_LEN + 1);
        if (p == NULL) {
            return NJT_CONF_ERROR;
        }

        llcf->content_src_key = p;

        p = njt_copy(p, chunkname, chunkname_len);
        p = njt_copy(p, NJT_STREAM_LUA_INLINE_TAG,
                     NJT_STREAM_LUA_INLINE_TAG_LEN);
        p = njt_stream_lua_digest_hex(p, value[1].data, value[1].len);
        *p = '\0';

    } else {

        njt_memzero(&ccv, sizeof(njt_stream_compile_complex_value_t));
        ccv.cf = cf;
        ccv.value = &value[1];
        ccv.complex_value = &llcf->content_src;

        if (njt_stream_compile_complex_value(&ccv) != NJT_OK) {
            return NJT_CONF_ERROR;
        }

        if (llcf->content_src.lengths == NULL) {
            /* no variable found */
            p = njt_palloc(cf->pool, NJT_STREAM_LUA_FILE_KEY_LEN + 1);
            if (p == NULL) {
                return NJT_CONF_ERROR;
            }

            llcf->content_src_key = p;

            p = njt_copy(p, NJT_STREAM_LUA_FILE_TAG,
                         NJT_STREAM_LUA_FILE_TAG_LEN);
            p = njt_stream_lua_digest_hex(p, value[1].data, value[1].len);
            *p = '\0';
        }
    }

    llcf->content_handler = (njt_stream_lua_handler_pt) cmd->post;


    /*  register location content handler */
    cxcf = njt_stream_conf_get_module_srv_conf(cf, njt_stream_core_module);
    if (cxcf == NULL) {
        return NJT_CONF_ERROR;
    }

    cxcf->handler = njt_stream_lua_content_handler;

    return NJT_CONF_OK;
}


char *
njt_stream_lua_log_by_lua_block(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    char        *rv;
    njt_conf_t   save;

    save = *cf;
    cf->handler = njt_stream_lua_log_by_lua;
    cf->handler_conf = conf;

    rv = njt_stream_lua_conf_lua_block_parse(cf, cmd);

    *cf = save;

    return rv;
}


char *
njt_stream_lua_log_by_lua(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    size_t                                     chunkname_len;
    u_char                                    *p, *chunkname;
    njt_str_t                                 *value;
    njt_stream_lua_main_conf_t                *lmcf;
    njt_stream_lua_loc_conf_t                 *llcf = conf;
    njt_stream_compile_complex_value_t         ccv;

    dd("enter");

    /*  must specify a log handler */
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

    if (cmd->post == njt_stream_lua_log_handler_inline) {
        chunkname = njt_stream_lua_gen_chunk_name(cf, "log_by_lua",
                                                  sizeof("log_by_lua") - 1,
                                                  &chunkname_len);
        if (chunkname == NULL) {
            return NJT_CONF_ERROR;
        }

        llcf->log_chunkname = chunkname;

        /* Don't eval njet variables for inline lua code */

        llcf->log_src.value = value[1];

        p = njt_palloc(cf->pool,
                       chunkname_len + NJT_STREAM_LUA_INLINE_KEY_LEN + 1);
        if (p == NULL) {
            return NJT_CONF_ERROR;
        }

        llcf->log_src_key = p;

        p = njt_copy(p, chunkname, chunkname_len);
        p = njt_copy(p, NJT_STREAM_LUA_INLINE_TAG,
                     NJT_STREAM_LUA_INLINE_TAG_LEN);
        p = njt_stream_lua_digest_hex(p, value[1].data, value[1].len);
        *p = '\0';

    } else {
        njt_memzero(&ccv, sizeof(njt_stream_compile_complex_value_t));
        ccv.cf = cf;
        ccv.value = &value[1];
        ccv.complex_value = &llcf->log_src;

        if (njt_stream_compile_complex_value(&ccv) != NJT_OK) {
            return NJT_CONF_ERROR;
        }

        if (llcf->log_src.lengths == NULL) {
            /* no variable found */
            p = njt_palloc(cf->pool, NJT_STREAM_LUA_FILE_KEY_LEN + 1);
            if (p == NULL) {
                return NJT_CONF_ERROR;
            }

            llcf->log_src_key = p;

            p = njt_copy(p, NJT_STREAM_LUA_FILE_TAG,
                         NJT_STREAM_LUA_FILE_TAG_LEN);
            p = njt_stream_lua_digest_hex(p, value[1].data, value[1].len);
            *p = '\0';
        }
    }

    llcf->log_handler = (njt_stream_lua_handler_pt) cmd->post;

    lmcf = njt_stream_conf_get_module_main_conf(cf, njt_stream_lua_module);

    lmcf->requires_log = 1;

    return NJT_CONF_OK;
}




char *
njt_stream_lua_init_by_lua_block(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    char        *rv;
    njt_conf_t   save;

    save = *cf;
    cf->handler = njt_stream_lua_init_by_lua;
    cf->handler_conf = conf;

    rv = njt_stream_lua_conf_lua_block_parse(cf, cmd);

    *cf = save;

    return rv;
}


char *
njt_stream_lua_init_by_lua(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    u_char                              *name;
    njt_str_t                           *value;
    njt_stream_lua_main_conf_t          *lmcf = conf;

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

    lmcf->init_handler = (njt_stream_lua_main_conf_handler_pt) cmd->post;

    if (cmd->post == njt_stream_lua_init_by_file) {
        name = njt_stream_lua_rebase_path(cf->pool, value[1].data,
                                          value[1].len);
        if (name == NULL) {
            return NJT_CONF_ERROR;
        }

        lmcf->init_src.data = name;
        lmcf->init_src.len = njt_strlen(name);

    } else {
        lmcf->init_src = value[1];
    }

    return NJT_CONF_OK;
}


char *
njt_stream_lua_init_worker_by_lua_block(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    char        *rv;
    njt_conf_t   save;

    save = *cf;
    cf->handler = njt_stream_lua_init_worker_by_lua;
    cf->handler_conf = conf;

    rv = njt_stream_lua_conf_lua_block_parse(cf, cmd);

    *cf = save;

    return rv;
}


char *
njt_stream_lua_init_worker_by_lua(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    u_char                      *name;
    njt_str_t                   *value;

    njt_stream_lua_main_conf_t          *lmcf = conf;

    dd("enter");

    /*  must specify a content handler */
    if (cmd->post == NULL) {
        return NJT_CONF_ERROR;
    }

    if (lmcf->init_worker_handler) {
        return "is duplicate";
    }

    value = cf->args->elts;

    lmcf->init_worker_handler = (njt_stream_lua_main_conf_handler_pt) cmd->post;

    if (cmd->post == njt_stream_lua_init_worker_by_file) {
        name = njt_stream_lua_rebase_path(cf->pool, value[1].data,
                                          value[1].len);
        if (name == NULL) {
            return NJT_CONF_ERROR;
        }

        lmcf->init_worker_src.data = name;
        lmcf->init_worker_src.len = njt_strlen(name);

    } else {
        lmcf->init_worker_src = value[1];
    }

    return NJT_CONF_OK;
}




static u_char *
njt_stream_lua_gen_chunk_name(njt_conf_t *cf, const char *tag, size_t tag_len,
    size_t *chunkname_len)
{
    u_char      *p, *out;
    size_t       len;

    len = sizeof("=(:)") - 1 + tag_len + cf->conf_file->file.name.len
          + NJT_INT64_LEN + 1;

    out = njt_palloc(cf->pool, len);
    if (out == NULL) {
        return NULL;
    }

    if (cf->conf_file->file.name.len) {
        p = cf->conf_file->file.name.data + cf->conf_file->file.name.len;
        while (--p >= cf->conf_file->file.name.data) {
            if (*p == '/' || *p == '\\') {
                p++;
                goto found;
            }
        }

        p++;

    } else {
        p = cf->conf_file->file.name.data;
    }

found:

    p = njt_snprintf(out, len, "=%*s(%*s:%d)%Z",
                     tag_len, tag, cf->conf_file->file.name.data
                     + cf->conf_file->file.name.len - p,
                     p, cf->conf_file->line);

    *chunkname_len = p - out - 1;  /* exclude the trailing '\0' byte */

    return out;
}


/* a specialized version of the standard njt_conf_parse() function */
char *
njt_stream_lua_conf_lua_block_parse(njt_conf_t *cf, njt_command_t *cmd)
{
    njt_stream_lua_block_parser_ctx_t           ctx;

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
        parse_param
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

    dd("init start line: %d", (int) start_line);

    ctx.start_line = start_line;

    for ( ;; ) {
        rc = njt_stream_lua_conf_read_lua_token(cf, &ctx);

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
                njt_stream_lua_assert(cf->handler);

                src = cf->args->elts;

                for (len = 0, i = 0; i < cf->args->nelts; i++) {
                    len += src[i].len;
                }

                dd("saved nelts: %d", (int) saved->nelts);
                dd("temp nelts: %d", (int) cf->args->nelts);
#if 0
                njt_stream_lua_assert(saved->nelts == 1);
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

    if (rc == NJT_ERROR) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


static njt_int_t
njt_stream_lua_conf_read_lua_token(njt_conf_t *cf,
    njt_stream_lua_block_parser_ctx_t *ctx)
{
    enum {
        OVEC_SIZE = 2
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
#if defined(njet_version) && njet_version >= 1009002
    njt_buf_t   *dump;
#endif

    b = cf->conf_file->buffer;
#if defined(njet_version) && njet_version >= 1009002
    dump = cf->conf_file->dump;
#endif
    start = b->pos;
    start_line = cf->conf_file->line;
    buf_size = b->end - b->start;

    dd("lexer start line: %d", (int) start_line);

    file_size = njt_file_size(&cf->conf_file->file.info);

    for ( ;; ) {

        if (b->pos >= b->last
            || (b->last - b->pos < (b->end - b->start) / 3
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

#if defined(njet_version) && njet_version >= 1009002
            if (dump) {
                dump->last = njt_cpymem(dump->last, b->start + len, size);
            }
#endif
        }

        rc = njt_stream_lua_lex(b->pos, b->last - b->pos, ovec);

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
                njt_memcpy(b->start, b->pos, len);
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

            njt_stream_lua_assert(p[0] == '[');
            p[0] = ']';

            njt_stream_lua_assert(b->pos[ovec[1] - 1] == '[');
            b->pos[ovec[1] - 1] = ']';

            /* search for the corresponding closing bracket */

            dd("search pattern for the closing long bracket: \"%.*s\" (len=%d)",
               (int) (b->pos + ovec[1] - p), p, (int) (b->pos + ovec[1] - p));

            q = njt_stream_lua_strlstrn(b->pos + ovec[1], b->last, p,
                                        b->pos + ovec[1] - p - 1);

            if (q == NULL) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "Lua code block missing the closing "
                                   "long bracket \"%*s\"",
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
njt_stream_lua_capture_error_log(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
#ifndef HAVE_INTERCEPT_ERROR_LOG_PATCH
    return "not found: missing the capture error log patch for njet";
#else
    njt_str_t                     *value;
    ssize_t                        size;
    u_char                        *data;
    njt_cycle_t                   *cycle;

    njt_stream_lua_main_conf_t            *lmcf = conf;
    njt_stream_lua_log_ringbuf_t          *ringbuf;

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

    ringbuf = (njt_stream_lua_log_ringbuf_t *)
              njt_palloc(cf->pool, sizeof(njt_stream_lua_log_ringbuf_t));
    if (ringbuf == NULL) {
        return NJT_CONF_ERROR;
    }

    data = njt_palloc(cf->pool, size);
    if (data == NULL) {
        return NJT_CONF_ERROR;
    }

    njt_stream_lua_log_ringbuf_init(ringbuf, data, size);

    lmcf->requires_capture_log = 1;
    cycle->intercept_error_log_handler = (njt_log_intercept_pt)
                                         njt_stream_lua_capture_log_handler;
    cycle->intercept_error_log_data = ringbuf;

    return NJT_CONF_OK;
#endif
}


/*
 * njt_stream_lua_strlstrn() is intended to search for static substring
 * with known length in string until the argument last. The argument n
 * must be length of the second substring - 1.
 */

static u_char *
njt_stream_lua_strlstrn(u_char *s1, u_char *last, u_char *s2, size_t n)
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


static njt_int_t
njt_stream_lua_undefined_var(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    v->not_found = 1;

    return NJT_OK;
}


char *
njt_stream_lua_add_variable(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    njt_stream_variable_t           *var;
    njt_str_t                       *value;
    njt_int_t                        ret;

    value = cf->args->elts;

    if (value[1].data[0] != '$') {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &value[1]);
        return NJT_CONF_ERROR;
    }

    value[1].len--;
    value[1].data++;

    var = njt_stream_add_variable(cf, value + 1, NJT_STREAM_VAR_CHANGEABLE
                                  |NJT_STREAM_VAR_WEAK);
    if (var == NULL) {
        return NJT_CONF_ERROR;
    }

    if (var->get_handler == NULL) {
        var->get_handler = njt_stream_lua_undefined_var;
    }

    ret = njt_stream_get_variable_index(cf, value + 1);
    if (ret == NJT_ERROR) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
