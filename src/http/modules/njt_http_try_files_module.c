
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


typedef struct {
    njt_array_t           *lengths;
    njt_array_t           *values;
    njt_str_t              name;

    unsigned               code:10;
    unsigned               test_dir:1;
} njt_http_try_file_t;


typedef struct {
    njt_http_try_file_t   *try_files;
} njt_http_try_files_loc_conf_t;


static njt_int_t njt_http_try_files_handler(njt_http_request_t *r);
static char *njt_http_try_files(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static void *njt_http_try_files_create_loc_conf(njt_conf_t *cf);
static njt_int_t njt_http_try_files_init(njt_conf_t *cf);


static njt_command_t  njt_http_try_files_commands[] = {

    { njt_string("try_files"),
      NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_2MORE,
      njt_http_try_files,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      njt_null_command
};


static njt_http_module_t  njt_http_try_files_module_ctx = {
    NULL,                                  /* preconfiguration */
    njt_http_try_files_init,               /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_try_files_create_loc_conf,    /* create location configuration */
    NULL                                   /* merge location configuration */
};


njt_module_t  njt_http_try_files_module = {
    NJT_MODULE_V1,
    &njt_http_try_files_module_ctx,        /* module context */
    njt_http_try_files_commands,           /* module directives */
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
njt_http_try_files_handler(njt_http_request_t *r)
{
    size_t                          len, root, alias, reserve, allocated;
    u_char                         *p, *name;
    njt_str_t                       path, args;
    njt_uint_t                      test_dir;
    njt_http_try_file_t            *tf;
    njt_open_file_info_t            of;
    njt_http_script_code_pt         code;
    njt_http_script_engine_t        e;
    njt_http_core_loc_conf_t       *clcf;
    njt_http_script_len_code_pt     lcode;
    njt_http_try_files_loc_conf_t  *tlcf;

    tlcf = njt_http_get_module_loc_conf(r, njt_http_try_files_module);

    if (tlcf->try_files == NULL) {
        return NJT_DECLINED;
    }

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "try files handler");

    allocated = 0;
    root = 0;
    name = NULL;
    /* suppress MSVC warning */
    path.data = NULL;

    tf = tlcf->try_files;

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    alias = clcf->alias;

    for ( ;; ) {

        if (tf->lengths) {
            njt_memzero(&e, sizeof(njt_http_script_engine_t));

            e.ip = tf->lengths->elts;
            e.request = r;

            /* 1 is for terminating '\0' as in static names */
            len = 1;

            while (*(uintptr_t *) e.ip) {
                lcode = *(njt_http_script_len_code_pt *) e.ip;
                len += lcode(&e);
            }

        } else {
            len = tf->name.len;
        }

        if (!alias) {
            reserve = len > r->uri.len ? len - r->uri.len : 0;

        } else if (alias == NJT_MAX_SIZE_T_VALUE) {
            reserve = len;

        } else {
            reserve = len > r->uri.len - alias ? len - (r->uri.len - alias) : 0;
        }

        if (reserve > allocated || !allocated) {

            /* 16 bytes are preallocation */
            allocated = reserve + 16;

            if (njt_http_map_uri_to_path(r, &path, &root, allocated) == NULL) {
                return NJT_HTTP_INTERNAL_SERVER_ERROR;
            }

            name = path.data + root;
        }

        if (tf->values == NULL) {

            /* tf->name.len includes the terminating '\0' */

            njt_memcpy(name, tf->name.data, tf->name.len);

            path.len = (name + tf->name.len - 1) - path.data;

        } else {
            e.ip = tf->values->elts;
            e.pos = name;
            e.flushed = 1;

            while (*(uintptr_t *) e.ip) {
                code = *(njt_http_script_code_pt *) e.ip;
                code((njt_http_script_engine_t *) &e);
            }

            path.len = e.pos - path.data;

            *e.pos = '\0';

            if (alias && alias != NJT_MAX_SIZE_T_VALUE
                && njt_strncmp(name, r->uri.data, alias) == 0)
            {
                njt_memmove(name, name + alias, len - alias);
                path.len -= alias;
            }
        }

        test_dir = tf->test_dir;

        tf++;

        njt_log_debug3(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "trying to use %s: \"%s\" \"%s\"",
                       test_dir ? "dir" : "file", name, path.data);

        if (tf->lengths == NULL && tf->name.len == 0) {

            if (tf->code) {
                return tf->code;
            }

            path.len -= root;
            path.data += root;

            if (path.data[0] == '@') {
                (void) njt_http_named_location(r, &path);

            } else {
                njt_http_split_args(r, &path, &args);

                (void) njt_http_internal_redirect(r, &path, &args);
            }

            njt_http_finalize_request(r, NJT_DONE);
            return NJT_DONE;
        }

        njt_memzero(&of, sizeof(njt_open_file_info_t));

        of.read_ahead = clcf->read_ahead;
        of.directio = clcf->directio;
        of.valid = clcf->open_file_cache_valid;
        of.min_uses = clcf->open_file_cache_min_uses;
        of.test_only = 1;
        of.errors = clcf->open_file_cache_errors;
        of.events = clcf->open_file_cache_events;

        if (njt_http_set_disable_symlinks(r, clcf, &path, &of) != NJT_OK) {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (njt_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
            != NJT_OK)
        {
            if (of.err == 0) {
                return NJT_HTTP_INTERNAL_SERVER_ERROR;
            }

            if (of.err != NJT_ENOENT
                && of.err != NJT_ENOTDIR
                && of.err != NJT_ENAMETOOLONG)
            {
                njt_log_error(NJT_LOG_CRIT, r->connection->log, of.err,
                              "%s \"%s\" failed", of.failed, path.data);
            }

            continue;
        }

        if (of.is_dir != test_dir) {
            continue;
        }

        path.len -= root;
        path.data += root;

        if (!alias) {
            r->uri = path;

        } else if (alias == NJT_MAX_SIZE_T_VALUE) {
            if (!test_dir) {
                r->uri = path;
                r->add_uri_to_alias = 1;
            }

        } else {
            name = r->uri.data;

            r->uri.len = alias + path.len;
            r->uri.data = njt_pnalloc(r->pool, r->uri.len);
            if (r->uri.data == NULL) {
                r->uri.len = 0;
                return NJT_HTTP_INTERNAL_SERVER_ERROR;
            }

            p = njt_copy(r->uri.data, name, alias);
            njt_memcpy(p, path.data, path.len);
        }

        njt_http_set_exten(r);

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "try file uri: \"%V\"", &r->uri);

        return NJT_DECLINED;
    }

    /* not reached */
}


static char *
njt_http_try_files(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_try_files_loc_conf_t *tlcf = conf;

    njt_str_t                  *value;
    njt_int_t                   code;
    njt_uint_t                  i, n;
    njt_http_try_file_t        *tf;
    njt_http_script_compile_t   sc;

    if (tlcf->try_files) {
        return "is duplicate";
    }

    tf = njt_pcalloc(cf->pool, cf->args->nelts * sizeof(njt_http_try_file_t));
    if (tf == NULL) {
        return NJT_CONF_ERROR;
    }

    tlcf->try_files = tf;

    value = cf->args->elts;

    for (i = 0; i < cf->args->nelts - 1; i++) {

        tf[i].name = value[i + 1];

        if (tf[i].name.len > 0
            && tf[i].name.data[tf[i].name.len - 1] == '/'
            && i + 2 < cf->args->nelts)
        {
            tf[i].test_dir = 1;
            tf[i].name.len--;
            tf[i].name.data[tf[i].name.len] = '\0';
        }

        n = njt_http_script_variables_count(&tf[i].name);

        if (n) {
            njt_memzero(&sc, sizeof(njt_http_script_compile_t));

            sc.cf = cf;
            sc.source = &tf[i].name;
            sc.lengths = &tf[i].lengths;
            sc.values = &tf[i].values;
            sc.variables = n;
            sc.complete_lengths = 1;
            sc.complete_values = 1;

            if (njt_http_script_compile(&sc) != NJT_OK) {
                return NJT_CONF_ERROR;
            }

        } else {
            /* add trailing '\0' to length */
            tf[i].name.len++;
        }
    }

    if (tf[i - 1].name.data[0] == '=') {

        code = njt_atoi(tf[i - 1].name.data + 1, tf[i - 1].name.len - 2);

        if (code == NJT_ERROR || code > 999) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid code \"%*s\"",
                               tf[i - 1].name.len - 1, tf[i - 1].name.data);
            return NJT_CONF_ERROR;
        }

        tf[i].code = code;
    }

    return NJT_CONF_OK;
}


static void *
njt_http_try_files_create_loc_conf(njt_conf_t *cf)
{
    njt_http_try_files_loc_conf_t  *tlcf;

    tlcf = njt_pcalloc(cf->pool, sizeof(njt_http_try_files_loc_conf_t));
    if (tlcf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     tlcf->try_files = NULL;
     */

    return tlcf;
}


static njt_int_t
njt_http_try_files_init(njt_conf_t *cf)
{
    njt_http_handler_pt        *h;
    njt_http_core_main_conf_t  *cmcf;

    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);

    h = njt_array_push(&cmcf->phases[NJT_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_http_try_files_handler;

    return NJT_OK;
}
