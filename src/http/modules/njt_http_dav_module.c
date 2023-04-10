
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


#define NJT_HTTP_DAV_OFF             2


#define NJT_HTTP_DAV_NO_DEPTH        -3
#define NJT_HTTP_DAV_INVALID_DEPTH   -2
#define NJT_HTTP_DAV_INFINITY_DEPTH  -1


typedef struct {
    njt_uint_t  methods;
    njt_uint_t  access;
    njt_uint_t  min_delete_depth;
    njt_flag_t  create_full_put_path;
} njt_http_dav_loc_conf_t;


typedef struct {
    njt_str_t   path;
    size_t      len;
} njt_http_dav_copy_ctx_t;


static njt_int_t njt_http_dav_handler(njt_http_request_t *r);

static void njt_http_dav_put_handler(njt_http_request_t *r);

static njt_int_t njt_http_dav_delete_handler(njt_http_request_t *r);
static njt_int_t njt_http_dav_delete_path(njt_http_request_t *r,
    njt_str_t *path, njt_uint_t dir);
static njt_int_t njt_http_dav_delete_dir(njt_tree_ctx_t *ctx, njt_str_t *path);
static njt_int_t njt_http_dav_delete_file(njt_tree_ctx_t *ctx, njt_str_t *path);
static njt_int_t njt_http_dav_noop(njt_tree_ctx_t *ctx, njt_str_t *path);

static njt_int_t njt_http_dav_mkcol_handler(njt_http_request_t *r,
    njt_http_dav_loc_conf_t *dlcf);

static njt_int_t njt_http_dav_copy_move_handler(njt_http_request_t *r);
static njt_int_t njt_http_dav_copy_dir(njt_tree_ctx_t *ctx, njt_str_t *path);
static njt_int_t njt_http_dav_copy_dir_time(njt_tree_ctx_t *ctx,
    njt_str_t *path);
static njt_int_t njt_http_dav_copy_tree_file(njt_tree_ctx_t *ctx,
    njt_str_t *path);

static njt_int_t njt_http_dav_depth(njt_http_request_t *r, njt_int_t dflt);
static njt_int_t njt_http_dav_error(njt_log_t *log, njt_err_t err,
    njt_int_t not_found, char *failed, u_char *path);
static njt_int_t njt_http_dav_location(njt_http_request_t *r);
static void *njt_http_dav_create_loc_conf(njt_conf_t *cf);
static char *njt_http_dav_merge_loc_conf(njt_conf_t *cf,
    void *parent, void *child);
static njt_int_t njt_http_dav_init(njt_conf_t *cf);


static njt_conf_bitmask_t  njt_http_dav_methods_mask[] = {
    { njt_string("off"), NJT_HTTP_DAV_OFF },
    { njt_string("put"), NJT_HTTP_PUT },
    { njt_string("delete"), NJT_HTTP_DELETE },
    { njt_string("mkcol"), NJT_HTTP_MKCOL },
    { njt_string("copy"), NJT_HTTP_COPY },
    { njt_string("move"), NJT_HTTP_MOVE },
    { njt_null_string, 0 }
};


static njt_command_t  njt_http_dav_commands[] = {

    { njt_string("dav_methods"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_conf_set_bitmask_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_dav_loc_conf_t, methods),
      &njt_http_dav_methods_mask },

    { njt_string("create_full_put_path"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_dav_loc_conf_t, create_full_put_path),
      NULL },

    { njt_string("min_delete_depth"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_dav_loc_conf_t, min_delete_depth),
      NULL },

    { njt_string("dav_access"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE123,
      njt_conf_set_access_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_dav_loc_conf_t, access),
      NULL },

      njt_null_command
};


static njt_http_module_t  njt_http_dav_module_ctx = {
    NULL,                                  /* preconfiguration */
    njt_http_dav_init,                     /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_dav_create_loc_conf,          /* create location configuration */
    njt_http_dav_merge_loc_conf            /* merge location configuration */
};


njt_module_t  njt_http_dav_module = {
    NJT_MODULE_V1,
    &njt_http_dav_module_ctx,              /* module context */
    njt_http_dav_commands,                 /* module directives */
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
njt_http_dav_handler(njt_http_request_t *r)
{
    njt_int_t                 rc;
    njt_http_dav_loc_conf_t  *dlcf;

    dlcf = njt_http_get_module_loc_conf(r, njt_http_dav_module);

    if (!(r->method & dlcf->methods)) {
        return NJT_DECLINED;
    }

    switch (r->method) {

    case NJT_HTTP_PUT:

        if (r->uri.data[r->uri.len - 1] == '/') {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "cannot PUT to a collection");
            return NJT_HTTP_CONFLICT;
        }

        if (r->headers_in.content_range) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "PUT with range is unsupported");
            return NJT_HTTP_NOT_IMPLEMENTED;
        }

        r->request_body_in_file_only = 1;
        r->request_body_in_persistent_file = 1;
        r->request_body_in_clean_file = 1;
        r->request_body_file_group_access = 1;
        r->request_body_file_log_level = 0;

        rc = njt_http_read_client_request_body(r, njt_http_dav_put_handler);

        if (rc >= NJT_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        return NJT_DONE;

    case NJT_HTTP_DELETE:

        return njt_http_dav_delete_handler(r);

    case NJT_HTTP_MKCOL:

        return njt_http_dav_mkcol_handler(r, dlcf);

    case NJT_HTTP_COPY:

        return njt_http_dav_copy_move_handler(r);

    case NJT_HTTP_MOVE:

        return njt_http_dav_copy_move_handler(r);
    }

    return NJT_DECLINED;
}


static void
njt_http_dav_put_handler(njt_http_request_t *r)
{
    size_t                    root;
    time_t                    date;
    njt_str_t                *temp, path;
    njt_uint_t                status;
    njt_file_info_t           fi;
    njt_ext_rename_file_t     ext;
    njt_http_dav_loc_conf_t  *dlcf;

    if (r->request_body == NULL) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "PUT request body is unavailable");
        njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (r->request_body->temp_file == NULL) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "PUT request body must be in a file");
        njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (njt_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
        njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    path.len--;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http put filename: \"%s\"", path.data);

    temp = &r->request_body->temp_file->file.name;

    if (njt_file_info(path.data, &fi) == NJT_FILE_ERROR) {
        status = NJT_HTTP_CREATED;

    } else {
        status = NJT_HTTP_NO_CONTENT;

        if (njt_is_dir(&fi)) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, NJT_EISDIR,
                          "\"%s\" could not be created", path.data);

            if (njt_delete_file(temp->data) == NJT_FILE_ERROR) {
                njt_log_error(NJT_LOG_CRIT, r->connection->log, njt_errno,
                              njt_delete_file_n " \"%s\" failed",
                              temp->data);
            }

            njt_http_finalize_request(r, NJT_HTTP_CONFLICT);
            return;
        }
    }

    dlcf = njt_http_get_module_loc_conf(r, njt_http_dav_module);

    ext.access = dlcf->access;
    ext.path_access = dlcf->access;
    ext.time = -1;
    ext.create_path = dlcf->create_full_put_path;
    ext.delete_file = 1;
    ext.log = r->connection->log;

    if (r->headers_in.date) {
        date = njt_parse_http_time(r->headers_in.date->value.data,
                                   r->headers_in.date->value.len);

        if (date != NJT_ERROR) {
            ext.time = date;
            ext.fd = r->request_body->temp_file->file.fd;
        }
    }

    if (njt_ext_rename_file(temp, &path, &ext) != NJT_OK) {
        njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (status == NJT_HTTP_CREATED) {
        if (njt_http_dav_location(r) != NJT_OK) {
            njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        r->headers_out.content_length_n = 0;
    }

    r->headers_out.status = status;
    r->header_only = 1;

    njt_http_finalize_request(r, njt_http_send_header(r));
    return;
}


static njt_int_t
njt_http_dav_delete_handler(njt_http_request_t *r)
{
    size_t                    root;
    njt_err_t                 err;
    njt_int_t                 rc, depth;
    njt_uint_t                i, d, dir;
    njt_str_t                 path;
    njt_file_info_t           fi;
    njt_http_dav_loc_conf_t  *dlcf;

    if (r->headers_in.content_length_n > 0 || r->headers_in.chunked) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "DELETE with body is unsupported");
        return NJT_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    dlcf = njt_http_get_module_loc_conf(r, njt_http_dav_module);

    if (dlcf->min_delete_depth) {
        d = 0;

        for (i = 0; i < r->uri.len; /* void */) {
            if (r->uri.data[i++] == '/') {
                if (++d >= dlcf->min_delete_depth && i < r->uri.len) {
                    goto ok;
                }
            }
        }

        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "insufficient URI depth:%i to DELETE", d);
        return NJT_HTTP_CONFLICT;
    }

ok:

    if (njt_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http delete filename: \"%s\"", path.data);

    if (njt_link_info(path.data, &fi) == NJT_FILE_ERROR) {
        err = njt_errno;

        rc = (err == NJT_ENOTDIR) ? NJT_HTTP_CONFLICT : NJT_HTTP_NOT_FOUND;

        return njt_http_dav_error(r->connection->log, err,
                                  rc, njt_link_info_n, path.data);
    }

    if (njt_is_dir(&fi)) {

        if (r->uri.data[r->uri.len - 1] != '/') {
            njt_log_error(NJT_LOG_ERR, r->connection->log, NJT_EISDIR,
                          "DELETE \"%s\" failed", path.data);
            return NJT_HTTP_CONFLICT;
        }

        depth = njt_http_dav_depth(r, NJT_HTTP_DAV_INFINITY_DEPTH);

        if (depth != NJT_HTTP_DAV_INFINITY_DEPTH) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "\"Depth\" header must be infinity");
            return NJT_HTTP_BAD_REQUEST;
        }

        path.len -= 2;  /* omit "/\0" */

        dir = 1;

    } else {

        /*
         * we do not need to test (r->uri.data[r->uri.len - 1] == '/')
         * because njt_link_info("/file/") returned NJT_ENOTDIR above
         */

        depth = njt_http_dav_depth(r, 0);

        if (depth != 0 && depth != NJT_HTTP_DAV_INFINITY_DEPTH) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "\"Depth\" header must be 0 or infinity");
            return NJT_HTTP_BAD_REQUEST;
        }

        dir = 0;
    }

    rc = njt_http_dav_delete_path(r, &path, dir);

    if (rc == NJT_OK) {
        return NJT_HTTP_NO_CONTENT;
    }

    return rc;
}


static njt_int_t
njt_http_dav_delete_path(njt_http_request_t *r, njt_str_t *path, njt_uint_t dir)
{
    char            *failed;
    njt_tree_ctx_t   tree;

    if (dir) {

        tree.init_handler = NULL;
        tree.file_handler = njt_http_dav_delete_file;
        tree.pre_tree_handler = njt_http_dav_noop;
        tree.post_tree_handler = njt_http_dav_delete_dir;
        tree.spec_handler = njt_http_dav_delete_file;
        tree.data = NULL;
        tree.alloc = 0;
        tree.log = r->connection->log;

        /* TODO: 207 */

        if (njt_walk_tree(&tree, path) != NJT_OK) {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (njt_delete_dir(path->data) != NJT_FILE_ERROR) {
            return NJT_OK;
        }

        failed = njt_delete_dir_n;

    } else {

        if (njt_delete_file(path->data) != NJT_FILE_ERROR) {
            return NJT_OK;
        }

        failed = njt_delete_file_n;
    }

    return njt_http_dav_error(r->connection->log, njt_errno,
                              NJT_HTTP_NOT_FOUND, failed, path->data);
}


static njt_int_t
njt_http_dav_delete_dir(njt_tree_ctx_t *ctx, njt_str_t *path)
{
    njt_log_debug1(NJT_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http delete dir: \"%s\"", path->data);

    if (njt_delete_dir(path->data) == NJT_FILE_ERROR) {

        /* TODO: add to 207 */

        (void) njt_http_dav_error(ctx->log, njt_errno, 0, njt_delete_dir_n,
                                  path->data);
    }

    return NJT_OK;
}


static njt_int_t
njt_http_dav_delete_file(njt_tree_ctx_t *ctx, njt_str_t *path)
{
    njt_log_debug1(NJT_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http delete file: \"%s\"", path->data);

    if (njt_delete_file(path->data) == NJT_FILE_ERROR) {

        /* TODO: add to 207 */

        (void) njt_http_dav_error(ctx->log, njt_errno, 0, njt_delete_file_n,
                                  path->data);
    }

    return NJT_OK;
}


static njt_int_t
njt_http_dav_noop(njt_tree_ctx_t *ctx, njt_str_t *path)
{
    return NJT_OK;
}


static njt_int_t
njt_http_dav_mkcol_handler(njt_http_request_t *r, njt_http_dav_loc_conf_t *dlcf)
{
    u_char    *p;
    size_t     root;
    njt_str_t  path;

    if (r->headers_in.content_length_n > 0 || r->headers_in.chunked) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "MKCOL with body is unsupported");
        return NJT_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    if (r->uri.data[r->uri.len - 1] != '/') {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "MKCOL can create a collection only");
        return NJT_HTTP_CONFLICT;
    }

    p = njt_http_map_uri_to_path(r, &path, &root, 0);
    if (p == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    *(p - 1) = '\0';

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http mkcol path: \"%s\"", path.data);

    if (njt_create_dir(path.data, njt_dir_access(dlcf->access))
        != NJT_FILE_ERROR)
    {
        if (njt_http_dav_location(r) != NJT_OK) {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        return NJT_HTTP_CREATED;
    }

    return njt_http_dav_error(r->connection->log, njt_errno,
                              NJT_HTTP_CONFLICT, njt_create_dir_n, path.data);
}


static njt_int_t
njt_http_dav_copy_move_handler(njt_http_request_t *r)
{
    u_char                   *p, *host, *last, ch;
    size_t                    len, root;
    njt_err_t                 err;
    njt_int_t                 rc, depth;
    njt_uint_t                overwrite, slash, dir, flags;
    njt_str_t                 path, uri, duri, args;
    njt_tree_ctx_t            tree;
    njt_copy_file_t           cf;
    njt_file_info_t           fi;
    njt_table_elt_t          *dest, *over;
    njt_ext_rename_file_t     ext;
    njt_http_dav_copy_ctx_t   copy;
    njt_http_dav_loc_conf_t  *dlcf;

    if (r->headers_in.content_length_n > 0 || r->headers_in.chunked) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "COPY and MOVE with body are unsupported");
        return NJT_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    dest = r->headers_in.destination;

    if (dest == NULL) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "client sent no \"Destination\" header");
        return NJT_HTTP_BAD_REQUEST;
    }

    p = dest->value.data;
    /* there is always '\0' even after empty header value */
    if (p[0] == '/') {
        last = p + dest->value.len;
        goto destination_done;
    }

    len = r->headers_in.server.len;

    if (len == 0) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "client sent no \"Host\" header");
        return NJT_HTTP_BAD_REQUEST;
    }

#if (NJT_HTTP_SSL)

    if (r->connection->ssl) {
        if (njt_strncmp(dest->value.data, "https://", sizeof("https://") - 1)
            != 0)
        {
            goto invalid_destination;
        }

        host = dest->value.data + sizeof("https://") - 1;

    } else
#endif
    {
        if (njt_strncmp(dest->value.data, "http://", sizeof("http://") - 1)
            != 0)
        {
            goto invalid_destination;
        }

        host = dest->value.data + sizeof("http://") - 1;
    }

    if (njt_strncmp(host, r->headers_in.server.data, len) != 0) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "\"Destination\" URI \"%V\" is handled by "
                      "different repository than the source URI",
                      &dest->value);
        return NJT_HTTP_BAD_REQUEST;
    }

    last = dest->value.data + dest->value.len;

    for (p = host + len; p < last; p++) {
        if (*p == '/') {
            goto destination_done;
        }
    }

invalid_destination:

    njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                  "client sent invalid \"Destination\" header: \"%V\"",
                  &dest->value);
    return NJT_HTTP_BAD_REQUEST;

destination_done:

    duri.len = last - p;
    duri.data = p;
    flags = NJT_HTTP_LOG_UNSAFE;

    if (njt_http_parse_unsafe_uri(r, &duri, &args, &flags) != NJT_OK) {
        goto invalid_destination;
    }

    if ((r->uri.data[r->uri.len - 1] == '/' && *(last - 1) != '/')
        || (r->uri.data[r->uri.len - 1] != '/' && *(last - 1) == '/'))
    {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "both URI \"%V\" and \"Destination\" URI \"%V\" "
                      "should be either collections or non-collections",
                      &r->uri, &dest->value);
        return NJT_HTTP_CONFLICT;
    }

    depth = njt_http_dav_depth(r, NJT_HTTP_DAV_INFINITY_DEPTH);

    if (depth != NJT_HTTP_DAV_INFINITY_DEPTH) {

        if (r->method == NJT_HTTP_COPY) {
            if (depth != 0) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "\"Depth\" header must be 0 or infinity");
                return NJT_HTTP_BAD_REQUEST;
            }

        } else {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "\"Depth\" header must be infinity");
            return NJT_HTTP_BAD_REQUEST;
        }
    }

    over = r->headers_in.overwrite;

    if (over) {
        if (over->value.len == 1) {
            ch = over->value.data[0];

            if (ch == 'T' || ch == 't') {
                overwrite = 1;
                goto overwrite_done;
            }

            if (ch == 'F' || ch == 'f') {
                overwrite = 0;
                goto overwrite_done;
            }

        }

        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "client sent invalid \"Overwrite\" header: \"%V\"",
                      &over->value);
        return NJT_HTTP_BAD_REQUEST;
    }

    overwrite = 1;

overwrite_done:

    if (njt_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http copy from: \"%s\"", path.data);

    uri = r->uri;
    r->uri = duri;

    if (njt_http_map_uri_to_path(r, &copy.path, &root, 0) == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->uri = uri;

    copy.path.len--;  /* omit "\0" */

    if (copy.path.data[copy.path.len - 1] == '/') {
        slash = 1;
        copy.path.len--;
        copy.path.data[copy.path.len] = '\0';

    } else {
        slash = 0;
    }

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http copy to: \"%s\"", copy.path.data);

    if (njt_link_info(copy.path.data, &fi) == NJT_FILE_ERROR) {
        err = njt_errno;

        if (err != NJT_ENOENT) {
            return njt_http_dav_error(r->connection->log, err,
                                      NJT_HTTP_NOT_FOUND, njt_link_info_n,
                                      copy.path.data);
        }

        /* destination does not exist */

        overwrite = 0;
        dir = 0;

    } else {

        /* destination exists */

        if (njt_is_dir(&fi) && !slash) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "\"%V\" could not be %Ved to collection \"%V\"",
                          &r->uri, &r->method_name, &dest->value);
            return NJT_HTTP_CONFLICT;
        }

        if (!overwrite) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, NJT_EEXIST,
                          "\"%s\" could not be created", copy.path.data);
            return NJT_HTTP_PRECONDITION_FAILED;
        }

        dir = njt_is_dir(&fi);
    }

    if (njt_link_info(path.data, &fi) == NJT_FILE_ERROR) {
        return njt_http_dav_error(r->connection->log, njt_errno,
                                  NJT_HTTP_NOT_FOUND, njt_link_info_n,
                                  path.data);
    }

    if (njt_is_dir(&fi)) {

        if (r->uri.data[r->uri.len - 1] != '/') {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "\"%V\" is collection", &r->uri);
            return NJT_HTTP_BAD_REQUEST;
        }

        if (overwrite) {
            njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http delete: \"%s\"", copy.path.data);

            rc = njt_http_dav_delete_path(r, &copy.path, dir);

            if (rc != NJT_OK) {
                return rc;
            }
        }
    }

    if (njt_is_dir(&fi)) {

        path.len -= 2;  /* omit "/\0" */

        if (r->method == NJT_HTTP_MOVE) {
            if (njt_rename_file(path.data, copy.path.data) != NJT_FILE_ERROR) {
                return NJT_HTTP_CREATED;
            }
        }

        if (njt_create_dir(copy.path.data, njt_file_access(&fi))
            == NJT_FILE_ERROR)
        {
            return njt_http_dav_error(r->connection->log, njt_errno,
                                      NJT_HTTP_NOT_FOUND,
                                      njt_create_dir_n, copy.path.data);
        }

        copy.len = path.len;

        tree.init_handler = NULL;
        tree.file_handler = njt_http_dav_copy_tree_file;
        tree.pre_tree_handler = njt_http_dav_copy_dir;
        tree.post_tree_handler = njt_http_dav_copy_dir_time;
        tree.spec_handler = njt_http_dav_noop;
        tree.data = &copy;
        tree.alloc = 0;
        tree.log = r->connection->log;

        if (njt_walk_tree(&tree, &path) == NJT_OK) {

            if (r->method == NJT_HTTP_MOVE) {
                rc = njt_http_dav_delete_path(r, &path, 1);

                if (rc != NJT_OK) {
                    return rc;
                }
            }

            return NJT_HTTP_CREATED;
        }

    } else {

        if (r->method == NJT_HTTP_MOVE) {

            dlcf = njt_http_get_module_loc_conf(r, njt_http_dav_module);

            ext.access = 0;
            ext.path_access = dlcf->access;
            ext.time = -1;
            ext.create_path = 1;
            ext.delete_file = 0;
            ext.log = r->connection->log;

            if (njt_ext_rename_file(&path, &copy.path, &ext) == NJT_OK) {
                return NJT_HTTP_NO_CONTENT;
            }

            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        cf.size = njt_file_size(&fi);
        cf.buf_size = 0;
        cf.access = njt_file_access(&fi);
        cf.time = njt_file_mtime(&fi);
        cf.log = r->connection->log;

        if (njt_copy_file(path.data, copy.path.data, &cf) == NJT_OK) {
            return NJT_HTTP_NO_CONTENT;
        }
    }

    return NJT_HTTP_INTERNAL_SERVER_ERROR;
}


static njt_int_t
njt_http_dav_copy_dir(njt_tree_ctx_t *ctx, njt_str_t *path)
{
    u_char                   *p, *dir;
    size_t                    len;
    njt_http_dav_copy_ctx_t  *copy;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http copy dir: \"%s\"", path->data);

    copy = ctx->data;

    len = copy->path.len + path->len;

    dir = njt_alloc(len + 1, ctx->log);
    if (dir == NULL) {
        return NJT_ABORT;
    }

    p = njt_cpymem(dir, copy->path.data, copy->path.len);
    (void) njt_cpystrn(p, path->data + copy->len, path->len - copy->len + 1);

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http copy dir to: \"%s\"", dir);

    if (njt_create_dir(dir, njt_dir_access(ctx->access)) == NJT_FILE_ERROR) {
        (void) njt_http_dav_error(ctx->log, njt_errno, 0, njt_create_dir_n,
                                  dir);
    }

    njt_free(dir);

    return NJT_OK;
}


static njt_int_t
njt_http_dav_copy_dir_time(njt_tree_ctx_t *ctx, njt_str_t *path)
{
    u_char                   *p, *dir;
    size_t                    len;
    njt_http_dav_copy_ctx_t  *copy;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http copy dir time: \"%s\"", path->data);

    copy = ctx->data;

    len = copy->path.len + path->len;

    dir = njt_alloc(len + 1, ctx->log);
    if (dir == NULL) {
        return NJT_ABORT;
    }

    p = njt_cpymem(dir, copy->path.data, copy->path.len);
    (void) njt_cpystrn(p, path->data + copy->len, path->len - copy->len + 1);

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http copy dir time to: \"%s\"", dir);

#if (NJT_WIN32)
    {
    njt_fd_t  fd;

    fd = njt_open_file(dir, NJT_FILE_RDWR, NJT_FILE_OPEN, 0);

    if (fd == NJT_INVALID_FILE) {
        (void) njt_http_dav_error(ctx->log, njt_errno, 0, njt_open_file_n, dir);
        goto failed;
    }

    if (njt_set_file_time(NULL, fd, ctx->mtime) != NJT_OK) {
        njt_log_error(NJT_LOG_ALERT, ctx->log, njt_errno,
                      njt_set_file_time_n " \"%s\" failed", dir);
    }

    if (njt_close_file(fd) == NJT_FILE_ERROR) {
        njt_log_error(NJT_LOG_ALERT, ctx->log, njt_errno,
                      njt_close_file_n " \"%s\" failed", dir);
    }
    }

failed:

#else

    if (njt_set_file_time(dir, 0, ctx->mtime) != NJT_OK) {
        njt_log_error(NJT_LOG_ALERT, ctx->log, njt_errno,
                      njt_set_file_time_n " \"%s\" failed", dir);
    }

#endif

    njt_free(dir);

    return NJT_OK;
}


static njt_int_t
njt_http_dav_copy_tree_file(njt_tree_ctx_t *ctx, njt_str_t *path)
{
    u_char                   *p, *file;
    size_t                    len;
    njt_copy_file_t           cf;
    njt_http_dav_copy_ctx_t  *copy;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http copy file: \"%s\"", path->data);

    copy = ctx->data;

    len = copy->path.len + path->len;

    file = njt_alloc(len + 1, ctx->log);
    if (file == NULL) {
        return NJT_ABORT;
    }

    p = njt_cpymem(file, copy->path.data, copy->path.len);
    (void) njt_cpystrn(p, path->data + copy->len, path->len - copy->len + 1);

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http copy file to: \"%s\"", file);

    cf.size = ctx->size;
    cf.buf_size = 0;
    cf.access = ctx->access;
    cf.time = ctx->mtime;
    cf.log = ctx->log;

    (void) njt_copy_file(path->data, file, &cf);

    njt_free(file);

    return NJT_OK;
}


static njt_int_t
njt_http_dav_depth(njt_http_request_t *r, njt_int_t dflt)
{
    njt_table_elt_t  *depth;

    depth = r->headers_in.depth;

    if (depth == NULL) {
        return dflt;
    }

    if (depth->value.len == 1) {

        if (depth->value.data[0] == '0') {
            return 0;
        }

        if (depth->value.data[0] == '1') {
            return 1;
        }

    } else {

        if (depth->value.len == sizeof("infinity") - 1
            && njt_strcmp(depth->value.data, "infinity") == 0)
        {
            return NJT_HTTP_DAV_INFINITY_DEPTH;
        }
    }

    njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                  "client sent invalid \"Depth\" header: \"%V\"",
                  &depth->value);

    return NJT_HTTP_DAV_INVALID_DEPTH;
}


static njt_int_t
njt_http_dav_error(njt_log_t *log, njt_err_t err, njt_int_t not_found,
    char *failed, u_char *path)
{
    njt_int_t   rc;
    njt_uint_t  level;

    if (err == NJT_ENOENT || err == NJT_ENOTDIR || err == NJT_ENAMETOOLONG) {
        level = NJT_LOG_ERR;
        rc = not_found;

    } else if (err == NJT_EACCES || err == NJT_EPERM) {
        level = NJT_LOG_ERR;
        rc = NJT_HTTP_FORBIDDEN;

    } else if (err == NJT_EEXIST) {
        level = NJT_LOG_ERR;
        rc = NJT_HTTP_NOT_ALLOWED;

    } else if (err == NJT_ENOSPC) {
        level = NJT_LOG_CRIT;
        rc = NJT_HTTP_INSUFFICIENT_STORAGE;

    } else {
        level = NJT_LOG_CRIT;
        rc = NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    njt_log_error(level, log, err, "%s \"%s\" failed", failed, path);

    return rc;
}


static njt_int_t
njt_http_dav_location(njt_http_request_t *r)
{
    u_char     *p;
    size_t      len;
    uintptr_t   escape;

    r->headers_out.location = njt_list_push(&r->headers_out.headers);
    if (r->headers_out.location == NULL) {
        return NJT_ERROR;
    }

    r->headers_out.location->hash = 1;
    r->headers_out.location->next = NULL;
    njt_str_set(&r->headers_out.location->key, "Location");

    escape = 2 * njt_escape_uri(NULL, r->uri.data, r->uri.len, NJT_ESCAPE_URI);

    if (escape) {
        len = r->uri.len + escape;

        p = njt_pnalloc(r->pool, len);
        if (p == NULL) {
            njt_http_clear_location(r);
            return NJT_ERROR;
        }

        r->headers_out.location->value.len = len;
        r->headers_out.location->value.data = p;

        njt_escape_uri(p, r->uri.data, r->uri.len, NJT_ESCAPE_URI);

    } else {
        r->headers_out.location->value = r->uri;
    }

    return NJT_OK;
}


static void *
njt_http_dav_create_loc_conf(njt_conf_t *cf)
{
    njt_http_dav_loc_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_dav_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     conf->methods = 0;
     */

    conf->min_delete_depth = NJT_CONF_UNSET_UINT;
    conf->access = NJT_CONF_UNSET_UINT;
    conf->create_full_put_path = NJT_CONF_UNSET;

    return conf;
}


static char *
njt_http_dav_merge_loc_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_dav_loc_conf_t  *prev = parent;
    njt_http_dav_loc_conf_t  *conf = child;

    njt_conf_merge_bitmask_value(conf->methods, prev->methods,
                         (NJT_CONF_BITMASK_SET|NJT_HTTP_DAV_OFF));

    njt_conf_merge_uint_value(conf->min_delete_depth,
                         prev->min_delete_depth, 0);

    njt_conf_merge_uint_value(conf->access, prev->access, 0600);

    njt_conf_merge_value(conf->create_full_put_path,
                         prev->create_full_put_path, 0);

    return NJT_CONF_OK;
}


static njt_int_t
njt_http_dav_init(njt_conf_t *cf)
{
    njt_http_handler_pt        *h;
    njt_http_core_main_conf_t  *cmcf;

    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);

    h = njt_array_push(&cmcf->phases[NJT_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_http_dav_handler;

    return NJT_OK;
}
