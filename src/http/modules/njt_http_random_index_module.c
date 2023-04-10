
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


typedef struct {
    njt_flag_t  enable;
} njt_http_random_index_loc_conf_t;


#define NJT_HTTP_RANDOM_INDEX_PREALLOCATE  50


static njt_int_t njt_http_random_index_error(njt_http_request_t *r,
    njt_dir_t *dir, njt_str_t *name);
static njt_int_t njt_http_random_index_init(njt_conf_t *cf);
static void *njt_http_random_index_create_loc_conf(njt_conf_t *cf);
static char *njt_http_random_index_merge_loc_conf(njt_conf_t *cf,
    void *parent, void *child);


static njt_command_t  njt_http_random_index_commands[] = {

    { njt_string("random_index"),
      NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_random_index_loc_conf_t, enable),
      NULL },

      njt_null_command
};


static njt_http_module_t  njt_http_random_index_module_ctx = {
    NULL,                                  /* preconfiguration */
    njt_http_random_index_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_random_index_create_loc_conf, /* create location configuration */
    njt_http_random_index_merge_loc_conf   /* merge location configuration */
};


njt_module_t  njt_http_random_index_module = {
    NJT_MODULE_V1,
    &njt_http_random_index_module_ctx,     /* module context */
    njt_http_random_index_commands,        /* module directives */
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
njt_http_random_index_handler(njt_http_request_t *r)
{
    u_char                            *last, *filename;
    size_t                             len, allocated, root;
    njt_err_t                          err;
    njt_int_t                          rc;
    njt_str_t                          path, uri, *name;
    njt_dir_t                          dir;
    njt_uint_t                         n, level;
    njt_array_t                        names;
    njt_http_random_index_loc_conf_t  *rlcf;

    if (r->uri.data[r->uri.len - 1] != '/') {
        return NJT_DECLINED;
    }

    if (!(r->method & (NJT_HTTP_GET|NJT_HTTP_HEAD|NJT_HTTP_POST))) {
        return NJT_DECLINED;
    }

    rlcf = njt_http_get_module_loc_conf(r, njt_http_random_index_module);

    if (!rlcf->enable) {
        return NJT_DECLINED;
    }

#if (NJT_HAVE_D_TYPE)
    len = 0;
#else
    len = NJT_HTTP_RANDOM_INDEX_PREALLOCATE;
#endif

    last = njt_http_map_uri_to_path(r, &path, &root, len);
    if (last == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    allocated = path.len;

    path.len = last - path.data - 1;
    path.data[path.len] = '\0';

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http random index: \"%s\"", path.data);

    if (njt_open_dir(&path, &dir) == NJT_ERROR) {
        err = njt_errno;

        if (err == NJT_ENOENT
            || err == NJT_ENOTDIR
            || err == NJT_ENAMETOOLONG)
        {
            level = NJT_LOG_ERR;
            rc = NJT_HTTP_NOT_FOUND;

        } else if (err == NJT_EACCES) {
            level = NJT_LOG_ERR;
            rc = NJT_HTTP_FORBIDDEN;

        } else {
            level = NJT_LOG_CRIT;
            rc = NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        njt_log_error(level, r->connection->log, err,
                      njt_open_dir_n " \"%s\" failed", path.data);

        return rc;
    }

    if (njt_array_init(&names, r->pool, 32, sizeof(njt_str_t)) != NJT_OK) {
        return njt_http_random_index_error(r, &dir, &path);
    }

    filename = path.data;
    filename[path.len] = '/';

    for ( ;; ) {
        njt_set_errno(0);

        if (njt_read_dir(&dir) == NJT_ERROR) {
            err = njt_errno;

            if (err != NJT_ENOMOREFILES) {
                njt_log_error(NJT_LOG_CRIT, r->connection->log, err,
                              njt_read_dir_n " \"%V\" failed", &path);
                return njt_http_random_index_error(r, &dir, &path);
            }

            break;
        }

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http random index file: \"%s\"", njt_de_name(&dir));

        if (njt_de_name(&dir)[0] == '.') {
            continue;
        }

        len = njt_de_namelen(&dir);

        if (dir.type == 0 || njt_de_is_link(&dir)) {

            /* 1 byte for '/' and 1 byte for terminating '\0' */

            if (path.len + 1 + len + 1 > allocated) {
                allocated = path.len + 1 + len + 1
                                     + NJT_HTTP_RANDOM_INDEX_PREALLOCATE;

                filename = njt_pnalloc(r->pool, allocated);
                if (filename == NULL) {
                    return njt_http_random_index_error(r, &dir, &path);
                }

                last = njt_cpystrn(filename, path.data, path.len + 1);
                *last++ = '/';
            }

            njt_cpystrn(last, njt_de_name(&dir), len + 1);

            if (njt_de_info(filename, &dir) == NJT_FILE_ERROR) {
                err = njt_errno;

                if (err != NJT_ENOENT) {
                    njt_log_error(NJT_LOG_CRIT, r->connection->log, err,
                                  njt_de_info_n " \"%s\" failed", filename);
                    return njt_http_random_index_error(r, &dir, &path);
                }

                if (njt_de_link_info(filename, &dir) == NJT_FILE_ERROR) {
                    njt_log_error(NJT_LOG_CRIT, r->connection->log, njt_errno,
                                  njt_de_link_info_n " \"%s\" failed",
                                  filename);
                    return njt_http_random_index_error(r, &dir, &path);
                }
            }
        }

        if (!njt_de_is_file(&dir)) {
            continue;
        }

        name = njt_array_push(&names);
        if (name == NULL) {
            return njt_http_random_index_error(r, &dir, &path);
        }

        name->len = len;

        name->data = njt_pnalloc(r->pool, len);
        if (name->data == NULL) {
            return njt_http_random_index_error(r, &dir, &path);
        }

        njt_memcpy(name->data, njt_de_name(&dir), len);
    }

    if (njt_close_dir(&dir) == NJT_ERROR) {
        njt_log_error(NJT_LOG_ALERT, r->connection->log, njt_errno,
                      njt_close_dir_n " \"%V\" failed", &path);
    }

    n = names.nelts;

    if (n == 0) {
        return NJT_DECLINED;
    }

    name = names.elts;

    n = (njt_uint_t) (((uint64_t) njt_random() * n) / 0x80000000);

    uri.len = r->uri.len + name[n].len;

    uri.data = njt_pnalloc(r->pool, uri.len);
    if (uri.data == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    last = njt_copy(uri.data, r->uri.data, r->uri.len);
    njt_memcpy(last, name[n].data, name[n].len);

    return njt_http_internal_redirect(r, &uri, &r->args);
}


static njt_int_t
njt_http_random_index_error(njt_http_request_t *r, njt_dir_t *dir,
    njt_str_t *name)
{
    if (njt_close_dir(dir) == NJT_ERROR) {
        njt_log_error(NJT_LOG_ALERT, r->connection->log, njt_errno,
                      njt_close_dir_n " \"%V\" failed", name);
    }

    return NJT_HTTP_INTERNAL_SERVER_ERROR;
}


static void *
njt_http_random_index_create_loc_conf(njt_conf_t *cf)
{
    njt_http_random_index_loc_conf_t  *conf;

    conf = njt_palloc(cf->pool, sizeof(njt_http_random_index_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NJT_CONF_UNSET;

    return conf;
}


static char *
njt_http_random_index_merge_loc_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_random_index_loc_conf_t *prev = parent;
    njt_http_random_index_loc_conf_t *conf = child;

    njt_conf_merge_value(conf->enable, prev->enable, 0);

    return NJT_CONF_OK;
}


static njt_int_t
njt_http_random_index_init(njt_conf_t *cf)
{
    njt_http_handler_pt        *h;
    njt_http_core_main_conf_t  *cmcf;

    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);

    h = njt_array_push(&cmcf->phases[NJT_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_http_random_index_handler;

    return NJT_OK;
}
