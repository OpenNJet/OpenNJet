
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


typedef struct {
    njt_str_t                name;
    njt_array_t             *lengths;
    njt_array_t             *values;
} njt_http_index_t;


typedef struct {
    njt_array_t             *indices;    /* array of njt_http_index_t */
    size_t                   max_index_len;
} njt_http_index_loc_conf_t;


#define NJT_HTTP_DEFAULT_INDEX   "index.html"


static njt_int_t njt_http_index_test_dir(njt_http_request_t *r,
    njt_http_core_loc_conf_t *clcf, u_char *path, u_char *last);
static njt_int_t njt_http_index_error(njt_http_request_t *r,
    njt_http_core_loc_conf_t *clcf, u_char *file, njt_err_t err);

static njt_int_t njt_http_index_init(njt_conf_t *cf);
static void *njt_http_index_create_loc_conf(njt_conf_t *cf);
static char *njt_http_index_merge_loc_conf(njt_conf_t *cf,
    void *parent, void *child);
static char *njt_http_index_set_index(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);


static njt_command_t  njt_http_index_commands[] = {

    { njt_string("index"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_http_index_set_index,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      njt_null_command
};


static njt_http_module_t  njt_http_index_module_ctx = {
    NULL,                                  /* preconfiguration */
    njt_http_index_init,                   /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_index_create_loc_conf,        /* create location configuration */
    njt_http_index_merge_loc_conf          /* merge location configuration */
};


njt_module_t  njt_http_index_module = {
    NJT_MODULE_V1,
    &njt_http_index_module_ctx,            /* module context */
    njt_http_index_commands,               /* module directives */
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


/*
 * Try to open/test the first index file before the test of directory
 * existence because valid requests should prevail over invalid ones.
 * If open()/stat() of a file will fail then stat() of a directory
 * should be faster because kernel may have already cached some data.
 * Besides, Win32 may return ERROR_PATH_NOT_FOUND (NJT_ENOTDIR) at once.
 * Unix has ENOTDIR error; however, it's less helpful than Win32's one:
 * it only indicates that path points to a regular file, not a directory.
 */

static njt_int_t
njt_http_index_handler(njt_http_request_t *r)
{
    u_char                       *p, *name;
    size_t                        len, root, reserve, allocated;
    njt_int_t                     rc;
    njt_str_t                     path, uri;
    njt_uint_t                    i, dir_tested;
    njt_http_index_t             *index;
    njt_open_file_info_t          of;
    njt_http_script_code_pt       code;
    njt_http_script_engine_t      e;
    njt_http_core_loc_conf_t     *clcf;
    njt_http_index_loc_conf_t    *ilcf;
    njt_http_script_len_code_pt   lcode;

    if (r->uri.data[r->uri.len - 1] != '/') {
        return NJT_DECLINED;
    }

    if (!(r->method & (NJT_HTTP_GET|NJT_HTTP_HEAD|NJT_HTTP_POST))) {
        return NJT_DECLINED;
    }

    ilcf = njt_http_get_module_loc_conf(r, njt_http_index_module);
    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    allocated = 0;
    root = 0;
    dir_tested = 0;
    name = NULL;
    /* suppress MSVC warning */
    path.data = NULL;

    index = ilcf->indices->elts;
    for (i = 0; i < ilcf->indices->nelts; i++) {

        if (index[i].lengths == NULL) {

            if (index[i].name.data[0] == '/') {
                return njt_http_internal_redirect(r, &index[i].name, &r->args);
            }

            reserve = ilcf->max_index_len;
            len = index[i].name.len;

        } else {
            njt_memzero(&e, sizeof(njt_http_script_engine_t));

            e.ip = index[i].lengths->elts;
            e.request = r;
            e.flushed = 1;

            /* 1 is for terminating '\0' as in static names */
            len = 1;

            while (*(uintptr_t *) e.ip) {
                lcode = *(njt_http_script_len_code_pt *) e.ip;
                len += lcode(&e);
            }

            /* 16 bytes are preallocation */

            reserve = len + 16;
        }

        if (reserve > allocated) {

            name = njt_http_map_uri_to_path(r, &path, &root, reserve);
            if (name == NULL) {
                return NJT_HTTP_INTERNAL_SERVER_ERROR;
            }

            allocated = path.data + path.len - name;
        }

        if (index[i].values == NULL) {

            /* index[i].name.len includes the terminating '\0' */
	    if (name == NULL) {
                return NJT_HTTP_INTERNAL_SERVER_ERROR;
            }
            njt_memcpy(name, index[i].name.data, index[i].name.len);

            path.len = (name + index[i].name.len - 1) - path.data;

        } else {
            e.ip = index[i].values->elts;
            e.pos = name;

            while (*(uintptr_t *) e.ip) {
                code = *(njt_http_script_code_pt *) e.ip;
                code((njt_http_script_engine_t *) &e);
            }
	    if (name == NULL) {
                return NJT_HTTP_INTERNAL_SERVER_ERROR;
            }

            if (*name == '/') {
                uri.len = len - 1;
                uri.data = name;
                return njt_http_internal_redirect(r, &uri, &r->args);
            }

            path.len = e.pos - path.data;

            *e.pos = '\0';
        }

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "open index \"%V\"", &path);

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

            njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, of.err,
                           "%s \"%s\" failed", of.failed, path.data);

#if (NJT_HAVE_OPENAT)
            if (of.err == NJT_EMLINK
                || of.err == NJT_ELOOP)
            {
                return NJT_HTTP_FORBIDDEN;
            }
#endif

            if (of.err == NJT_ENOTDIR
                || of.err == NJT_ENAMETOOLONG
                || of.err == NJT_EACCES)
            {
                return njt_http_index_error(r, clcf, path.data, of.err);
            }

            if (!dir_tested) {
                rc = njt_http_index_test_dir(r, clcf, path.data, name - 1);

                if (rc != NJT_OK) {
                    return rc;
                }

                dir_tested = 1;
            }

            if (of.err == NJT_ENOENT) {
                continue;
            }

            njt_log_error(NJT_LOG_CRIT, r->connection->log, of.err,
                          "%s \"%s\" failed", of.failed, path.data);

            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        uri.len = r->uri.len + len - 1;

        if (!clcf->alias) {
            uri.data = path.data + root;

        } else {
            uri.data = njt_pnalloc(r->pool, uri.len);
            if (uri.data == NULL) {
                return NJT_HTTP_INTERNAL_SERVER_ERROR;
            }

            p = njt_copy(uri.data, r->uri.data, r->uri.len);
            njt_memcpy(p, name, len - 1);
        }

        return njt_http_internal_redirect(r, &uri, &r->args);
    }

    return NJT_DECLINED;
}


static njt_int_t
njt_http_index_test_dir(njt_http_request_t *r, njt_http_core_loc_conf_t *clcf,
    u_char *path, u_char *last)
{
    u_char                c;
    njt_str_t             dir;
    njt_open_file_info_t  of;
    c = *last;
    if (c != '/' || path == last) {
        /* "alias" without trailing slash */
        c = *(++last);
    }
    *last = '\0';

    dir.len = last - path;
    dir.data = path;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http index check dir: \"%V\"", &dir);

    njt_memzero(&of, sizeof(njt_open_file_info_t));

    of.test_dir = 1;
    of.test_only = 1;
    of.valid = clcf->open_file_cache_valid;
    of.errors = clcf->open_file_cache_errors;

    if (njt_http_set_disable_symlinks(r, clcf, &dir, &of) != NJT_OK) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (njt_open_cached_file(clcf->open_file_cache, &dir, &of, r->pool)
        != NJT_OK)
    {
        if (of.err) {

#if (NJT_HAVE_OPENAT)
            if (of.err == NJT_EMLINK
                || of.err == NJT_ELOOP)
            {
                return NJT_HTTP_FORBIDDEN;
            }
#endif

            if (of.err == NJT_ENOENT) {
                *last = c;
                return njt_http_index_error(r, clcf, dir.data, NJT_ENOENT);
            }

            if (of.err == NJT_EACCES) {

                *last = c;

                /*
                 * njt_http_index_test_dir() is called after the first index
                 * file testing has returned an error distinct from NJT_EACCES.
                 * This means that directory searching is allowed.
                 */

                return NJT_OK;
            }

            njt_log_error(NJT_LOG_CRIT, r->connection->log, of.err,
                          "%s \"%s\" failed", of.failed, dir.data);
        }

        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    *last = c;

    if (of.is_dir) {
        return NJT_OK;
    }

    njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
                  "\"%s\" is not a directory", dir.data);

    return NJT_HTTP_INTERNAL_SERVER_ERROR;
}


static njt_int_t
njt_http_index_error(njt_http_request_t *r, njt_http_core_loc_conf_t  *clcf,
    u_char *file, njt_err_t err)
{
    if (err == NJT_EACCES) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, err,
                      "\"%s\" is forbidden", file);

        return NJT_HTTP_FORBIDDEN;
    }

    if (clcf->log_not_found) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, err,
                      "\"%s\" is not found", file);
    }

    return NJT_HTTP_NOT_FOUND;
}


static void *
njt_http_index_create_loc_conf(njt_conf_t *cf)
{
    njt_http_index_loc_conf_t  *conf;

    conf = njt_palloc(cf->pool, sizeof(njt_http_index_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->indices = NULL;
    conf->max_index_len = 0;

    return conf;
}


static char *
njt_http_index_merge_loc_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_index_loc_conf_t  *prev = parent;
    njt_http_index_loc_conf_t  *conf = child;

    njt_http_index_t  *index;

    if (conf->indices == NULL) {
        conf->indices = prev->indices;
        conf->max_index_len = prev->max_index_len;
    }

    if (conf->indices == NULL) {
        conf->indices = njt_array_create(cf->pool, 1, sizeof(njt_http_index_t));
        if (conf->indices == NULL) {
            return NJT_CONF_ERROR;
        }

        index = njt_array_push(conf->indices);
        if (index == NULL) {
            return NJT_CONF_ERROR;
        }

        index->name.len = sizeof(NJT_HTTP_DEFAULT_INDEX);
        index->name.data = (u_char *) NJT_HTTP_DEFAULT_INDEX;
        index->lengths = NULL;
        index->values = NULL;

        conf->max_index_len = sizeof(NJT_HTTP_DEFAULT_INDEX);

        return NJT_CONF_OK;
    }

    return NJT_CONF_OK;
}


static njt_int_t
njt_http_index_init(njt_conf_t *cf)
{
    njt_http_handler_pt        *h;
    njt_http_core_main_conf_t  *cmcf;

    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);

    h = njt_array_push(&cmcf->phases[NJT_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_http_index_handler;

    return NJT_OK;
}


/* TODO: warn about duplicate indices */

static char *
njt_http_index_set_index(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_index_loc_conf_t *ilcf = conf;

    njt_str_t                  *value;
    njt_uint_t                  i, n;
    njt_http_index_t           *index;
    njt_http_script_compile_t   sc;

    if (ilcf->indices == NULL) {
        ilcf->indices = njt_array_create(cf->pool, 2, sizeof(njt_http_index_t));
        if (ilcf->indices == NULL) {
            return NJT_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (value[i].data[0] == '/' && i != cf->args->nelts - 1) {
            njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                               "only the last index in \"index\" directive "
                               "should be absolute");
        }

        if (value[i].len == 0) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "index \"%V\" in \"index\" directive is invalid",
                               &value[1]);
            return NJT_CONF_ERROR;
        }

        index = njt_array_push(ilcf->indices);
        if (index == NULL) {
            return NJT_CONF_ERROR;
        }

        index->name.len = value[i].len;
        index->name.data = value[i].data;
        index->lengths = NULL;
        index->values = NULL;

        n = njt_http_script_variables_count(&value[i]);

        if (n == 0) {
            if (ilcf->max_index_len < index->name.len) {
                ilcf->max_index_len = index->name.len;
            }

            if (index->name.data[0] == '/') {
                continue;
            }

            /* include the terminating '\0' to the length to use njt_memcpy() */
            index->name.len++;

            continue;
        }

        njt_memzero(&sc, sizeof(njt_http_script_compile_t));

        sc.cf = cf;
        sc.source = &value[i];
        sc.lengths = &index->lengths;
        sc.values = &index->values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (njt_http_script_compile(&sc) != NJT_OK) {
            return NJT_CONF_ERROR;
        }
    }

    return NJT_CONF_OK;
}
