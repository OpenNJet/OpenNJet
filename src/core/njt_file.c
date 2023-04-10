
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>


static njt_int_t njt_test_full_name(njt_str_t *name);


static njt_atomic_t   temp_number = 0;
njt_atomic_t         *njt_temp_number = &temp_number;
njt_atomic_int_t      njt_random_number = 123456;


njt_int_t
njt_get_full_name(njt_pool_t *pool, njt_str_t *prefix, njt_str_t *name)
{
    size_t      len;
    u_char     *p, *n;
    njt_int_t   rc;

    rc = njt_test_full_name(name);

    if (rc == NJT_OK) {
        return rc;
    }

    len = prefix->len;

#if (NJT_WIN32)

    if (rc == 2) {
        len = rc;
    }

#endif

    n = njt_pnalloc(pool, len + name->len + 1);
    if (n == NULL) {
        return NJT_ERROR;
    }

    p = njt_cpymem(n, prefix->data, len);
    njt_cpystrn(p, name->data, name->len + 1);

    name->len += len;
    name->data = n;

    return NJT_OK;
}


static njt_int_t
njt_test_full_name(njt_str_t *name)
{
#if (NJT_WIN32)
    u_char  c0, c1;

    c0 = name->data[0];

    if (name->len < 2) {
        if (c0 == '/') {
            return 2;
        }

        return NJT_DECLINED;
    }

    c1 = name->data[1];

    if (c1 == ':') {
        c0 |= 0x20;

        if ((c0 >= 'a' && c0 <= 'z')) {
            return NJT_OK;
        }

        return NJT_DECLINED;
    }

    if (c1 == '/') {
        return NJT_OK;
    }

    if (c0 == '/') {
        return 2;
    }

    return NJT_DECLINED;

#else

    if (name->data[0] == '/') {
        return NJT_OK;
    }

    return NJT_DECLINED;

#endif
}


ssize_t
njt_write_chain_to_temp_file(njt_temp_file_t *tf, njt_chain_t *chain)
{
    njt_int_t  rc;

    if (tf->file.fd == NJT_INVALID_FILE) {
        rc = njt_create_temp_file(&tf->file, tf->path, tf->pool,
                                  tf->persistent, tf->clean, tf->access);

        if (rc != NJT_OK) {
            return rc;
        }

        if (tf->log_level) {
            njt_log_error(tf->log_level, tf->file.log, 0, "%s %V",
                          tf->warn, &tf->file.name);
        }
    }

#if (NJT_THREADS && NJT_HAVE_PWRITEV)

    if (tf->thread_write) {
        return njt_thread_write_chain_to_file(&tf->file, chain, tf->offset,
                                              tf->pool);
    }

#endif

    return njt_write_chain_to_file(&tf->file, chain, tf->offset, tf->pool);
}


njt_int_t
njt_create_temp_file(njt_file_t *file, njt_path_t *path, njt_pool_t *pool,
    njt_uint_t persistent, njt_uint_t clean, njt_uint_t access)
{
    size_t                    levels;
    u_char                   *p;
    uint32_t                  n;
    njt_err_t                 err;
    njt_str_t                 name;
    njt_uint_t                prefix;
    njt_pool_cleanup_t       *cln;
    njt_pool_cleanup_file_t  *clnf;

    if (file->name.len) {
        name = file->name;
        levels = 0;
        prefix = 1;

    } else {
        name = path->name;
        levels = path->len;
        prefix = 0;
    }

    file->name.len = name.len + 1 + levels + 10;

    file->name.data = njt_pnalloc(pool, file->name.len + 1);
    if (file->name.data == NULL) {
        return NJT_ERROR;
    }

#if 0
    for (i = 0; i < file->name.len; i++) {
        file->name.data[i] = 'X';
    }
#endif

    p = njt_cpymem(file->name.data, name.data, name.len);

    if (prefix) {
        *p = '.';
    }

    p += 1 + levels;

    n = (uint32_t) njt_next_temp_number(0);

    cln = njt_pool_cleanup_add(pool, sizeof(njt_pool_cleanup_file_t));
    if (cln == NULL) {
        return NJT_ERROR;
    }

    for ( ;; ) {
        (void) njt_sprintf(p, "%010uD%Z", n);

        if (!prefix) {
            njt_create_hashed_filename(path, file->name.data, file->name.len);
        }

        njt_log_debug1(NJT_LOG_DEBUG_CORE, file->log, 0,
                       "hashed path: %s", file->name.data);

        file->fd = njt_open_tempfile(file->name.data, persistent, access);

        njt_log_debug1(NJT_LOG_DEBUG_CORE, file->log, 0,
                       "temp fd:%d", file->fd);

        if (file->fd != NJT_INVALID_FILE) {

            cln->handler = clean ? njt_pool_delete_file : njt_pool_cleanup_file;
            clnf = cln->data;

            clnf->fd = file->fd;
            clnf->name = file->name.data;
            clnf->log = pool->log;

            return NJT_OK;
        }

        err = njt_errno;

        if (err == NJT_EEXIST_FILE) {
            n = (uint32_t) njt_next_temp_number(1);
            continue;
        }

        if ((path->level[0] == 0) || (err != NJT_ENOPATH)) {
            njt_log_error(NJT_LOG_CRIT, file->log, err,
                          njt_open_tempfile_n " \"%s\" failed",
                          file->name.data);
            return NJT_ERROR;
        }

        if (njt_create_path(file, path) == NJT_ERROR) {
            return NJT_ERROR;
        }
    }
}


void
njt_create_hashed_filename(njt_path_t *path, u_char *file, size_t len)
{
    size_t      i, level;
    njt_uint_t  n;

    i = path->name.len + 1;

    file[path->name.len + path->len]  = '/';

    for (n = 0; n < NJT_MAX_PATH_LEVEL; n++) {
        level = path->level[n];

        if (level == 0) {
            break;
        }

        len -= level;
        file[i - 1] = '/';
        njt_memcpy(&file[i], &file[len], level);
        i += level + 1;
    }
}


njt_int_t
njt_create_path(njt_file_t *file, njt_path_t *path)
{
    size_t      pos;
    njt_err_t   err;
    njt_uint_t  i;

    pos = path->name.len;

    for (i = 0; i < NJT_MAX_PATH_LEVEL; i++) {
        if (path->level[i] == 0) {
            break;
        }

        pos += path->level[i] + 1;

        file->name.data[pos] = '\0';

        njt_log_debug1(NJT_LOG_DEBUG_CORE, file->log, 0,
                       "temp file: \"%s\"", file->name.data);

        if (njt_create_dir(file->name.data, 0700) == NJT_FILE_ERROR) {
            err = njt_errno;
            if (err != NJT_EEXIST) {
                njt_log_error(NJT_LOG_CRIT, file->log, err,
                              njt_create_dir_n " \"%s\" failed",
                              file->name.data);
                return NJT_ERROR;
            }
        }

        file->name.data[pos] = '/';
    }

    return NJT_OK;
}


njt_err_t
njt_create_full_path(u_char *dir, njt_uint_t access)
{
    u_char     *p, ch;
    njt_err_t   err;

    err = 0;

#if (NJT_WIN32)
    p = dir + 3;
#else
    p = dir + 1;
#endif

    for ( /* void */ ; *p; p++) {
        ch = *p;

        if (ch != '/') {
            continue;
        }

        *p = '\0';

        if (njt_create_dir(dir, access) == NJT_FILE_ERROR) {
            err = njt_errno;

            switch (err) {
            case NJT_EEXIST:
                err = 0;
            case NJT_EACCES:
                break;

            default:
                return err;
            }
        }

        *p = '/';
    }

    return err;
}


njt_atomic_uint_t
njt_next_temp_number(njt_uint_t collision)
{
    njt_atomic_uint_t  n, add;

    add = collision ? njt_random_number : 1;

    n = njt_atomic_fetch_add(njt_temp_number, add);

    return n + add;
}


char *
njt_conf_set_path_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char  *p = conf;

    ssize_t      level;
    njt_str_t   *value;
    njt_uint_t   i, n;
    njt_path_t  *path, **slot;

    slot = (njt_path_t **) (p + cmd->offset);

    if (*slot) {
        return "is duplicate";
    }

    path = njt_pcalloc(cf->pool, sizeof(njt_path_t));
    if (path == NULL) {
        return NJT_CONF_ERROR;
    }

    value = cf->args->elts;

    path->name = value[1];

    if (path->name.data[path->name.len - 1] == '/') {
        path->name.len--;
    }

    if (njt_conf_full_name(cf->cycle, &path->name, 0) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    path->conf_file = cf->conf_file->file.name.data;
    path->line = cf->conf_file->line;

    for (i = 0, n = 2; n < cf->args->nelts; i++, n++) {
        level = njt_atoi(value[n].data, value[n].len);
        if (level == NJT_ERROR || level == 0) {
            return "invalid value";
        }

        path->level[i] = level;
        path->len += level + 1;
    }

    if (path->len > 10 + i) {
        return "invalid value";
    }

    *slot = path;

    if (njt_add_path(cf, slot) == NJT_ERROR) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


char *
njt_conf_merge_path_value(njt_conf_t *cf, njt_path_t **path, njt_path_t *prev,
    njt_path_init_t *init)
{
    njt_uint_t  i;

    if (*path) {
        return NJT_CONF_OK;
    }

    if (prev) {
        *path = prev;
        return NJT_CONF_OK;
    }

    *path = njt_pcalloc(cf->pool, sizeof(njt_path_t));
    if (*path == NULL) {
        return NJT_CONF_ERROR;
    }

    (*path)->name = init->name;

    if (njt_conf_full_name(cf->cycle, &(*path)->name, 0) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    for (i = 0; i < NJT_MAX_PATH_LEVEL; i++) {
        (*path)->level[i] = init->level[i];
        (*path)->len += init->level[i] + (init->level[i] ? 1 : 0);
    }

    if (njt_add_path(cf, path) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


char *
njt_conf_set_access_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char  *confp = conf;

    u_char      *p;
    njt_str_t   *value;
    njt_uint_t   i, right, shift, *access, user;

    access = (njt_uint_t *) (confp + cmd->offset);

    if (*access != NJT_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;

    *access = 0;
    user = 0600;

    for (i = 1; i < cf->args->nelts; i++) {

        p = value[i].data;

        if (njt_strncmp(p, "user:", sizeof("user:") - 1) == 0) {
            shift = 6;
            p += sizeof("user:") - 1;
            user = 0;

        } else if (njt_strncmp(p, "group:", sizeof("group:") - 1) == 0) {
            shift = 3;
            p += sizeof("group:") - 1;

        } else if (njt_strncmp(p, "all:", sizeof("all:") - 1) == 0) {
            shift = 0;
            p += sizeof("all:") - 1;

        } else {
            goto invalid;
        }

        if (njt_strcmp(p, "rw") == 0) {
            right = 6;

        } else if (njt_strcmp(p, "r") == 0) {
            right = 4;

        } else {
            goto invalid;
        }

        *access |= right << shift;
    }

    *access |= user;

    return NJT_CONF_OK;

invalid:

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "invalid value \"%V\"", &value[i]);

    return NJT_CONF_ERROR;
}


njt_int_t
njt_add_path(njt_conf_t *cf, njt_path_t **slot)
{
    njt_uint_t   i, n;
    njt_path_t  *path, **p;

    path = *slot;

    p = cf->cycle->paths.elts;
    for (i = 0; i < cf->cycle->paths.nelts; i++) {
        if (p[i]->name.len == path->name.len
            && njt_strcmp(p[i]->name.data, path->name.data) == 0)
        {
            if (p[i]->data != path->data) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "the same path name \"%V\" "
                                   "used in %s:%ui and",
                                   &p[i]->name, p[i]->conf_file, p[i]->line);
                return NJT_ERROR;
            }

            for (n = 0; n < NJT_MAX_PATH_LEVEL; n++) {
                if (p[i]->level[n] != path->level[n]) {
                    if (path->conf_file == NULL) {
                        if (p[i]->conf_file == NULL) {
                            njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                                      "the default path name \"%V\" has "
                                      "the same name as another default path, "
                                      "but the different levels, you need to "
                                      "redefine one of them in http section",
                                      &p[i]->name);
                            return NJT_ERROR;
                        }

                        njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                                      "the path name \"%V\" in %s:%ui has "
                                      "the same name as default path, but "
                                      "the different levels, you need to "
                                      "define default path in http section",
                                      &p[i]->name, p[i]->conf_file, p[i]->line);
                        return NJT_ERROR;
                    }

                    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                      "the same path name \"%V\" in %s:%ui "
                                      "has the different levels than",
                                      &p[i]->name, p[i]->conf_file, p[i]->line);
                    return NJT_ERROR;
                }

                if (p[i]->level[n] == 0) {
                    break;
                }
            }

            *slot = p[i];

            return NJT_OK;
        }
    }

    p = njt_array_push(&cf->cycle->paths);
    if (p == NULL) {
        return NJT_ERROR;
    }

    *p = path;

    return NJT_OK;
}


njt_int_t
njt_create_paths(njt_cycle_t *cycle, njt_uid_t user)
{
    njt_err_t         err;
    njt_uint_t        i;
    njt_path_t      **path;

    path = cycle->paths.elts;
    for (i = 0; i < cycle->paths.nelts; i++) {

        if (njt_create_dir(path[i]->name.data, 0700) == NJT_FILE_ERROR) {
            err = njt_errno;
            if (err != NJT_EEXIST) {
                njt_log_error(NJT_LOG_EMERG, cycle->log, err,
                              njt_create_dir_n " \"%s\" failed",
                              path[i]->name.data);
                return NJT_ERROR;
            }
        }

        if (user == (njt_uid_t) NJT_CONF_UNSET_UINT) {
            continue;
        }

#if !(NJT_WIN32)
        {
        njt_file_info_t   fi;

        if (njt_file_info(path[i]->name.data, &fi) == NJT_FILE_ERROR) {
            njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                          njt_file_info_n " \"%s\" failed", path[i]->name.data);
            return NJT_ERROR;
        }

        if (fi.st_uid != user) {
            if (chown((const char *) path[i]->name.data, user, -1) == -1) {
                njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                              "chown(\"%s\", %d) failed",
                              path[i]->name.data, user);
                return NJT_ERROR;
            }
        }

        if ((fi.st_mode & (S_IRUSR|S_IWUSR|S_IXUSR))
                                                  != (S_IRUSR|S_IWUSR|S_IXUSR))
        {
            fi.st_mode |= (S_IRUSR|S_IWUSR|S_IXUSR);

            if (chmod((const char *) path[i]->name.data, fi.st_mode) == -1) {
                njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                              "chmod() \"%s\" failed", path[i]->name.data);
                return NJT_ERROR;
            }
        }
        }
#endif
    }

    return NJT_OK;
}


njt_int_t
njt_ext_rename_file(njt_str_t *src, njt_str_t *to, njt_ext_rename_file_t *ext)
{
    u_char           *name;
    njt_err_t         err;
    njt_copy_file_t   cf;

#if !(NJT_WIN32)

    if (ext->access) {
        if (njt_change_file_access(src->data, ext->access) == NJT_FILE_ERROR) {
            njt_log_error(NJT_LOG_CRIT, ext->log, njt_errno,
                          njt_change_file_access_n " \"%s\" failed", src->data);
            err = 0;
            goto failed;
        }
    }

#endif

    if (ext->time != -1) {
        if (njt_set_file_time(src->data, ext->fd, ext->time) != NJT_OK) {
            njt_log_error(NJT_LOG_CRIT, ext->log, njt_errno,
                          njt_set_file_time_n " \"%s\" failed", src->data);
            err = 0;
            goto failed;
        }
    }

    if (njt_rename_file(src->data, to->data) != NJT_FILE_ERROR) {
        return NJT_OK;
    }

    err = njt_errno;

    if (err == NJT_ENOPATH) {

        if (!ext->create_path) {
            goto failed;
        }

        err = njt_create_full_path(to->data, njt_dir_access(ext->path_access));

        if (err) {
            njt_log_error(NJT_LOG_CRIT, ext->log, err,
                          njt_create_dir_n " \"%s\" failed", to->data);
            err = 0;
            goto failed;
        }

        if (njt_rename_file(src->data, to->data) != NJT_FILE_ERROR) {
            return NJT_OK;
        }

        err = njt_errno;
    }

#if (NJT_WIN32)

    if (err == NJT_EEXIST || err == NJT_EEXIST_FILE) {
        err = njt_win32_rename_file(src, to, ext->log);

        if (err == 0) {
            return NJT_OK;
        }
    }

#endif

    if (err == NJT_EXDEV) {

        cf.size = -1;
        cf.buf_size = 0;
        cf.access = ext->access;
        cf.time = ext->time;
        cf.log = ext->log;

        name = njt_alloc(to->len + 1 + 10 + 1, ext->log);
        if (name == NULL) {
            return NJT_ERROR;
        }

        (void) njt_sprintf(name, "%*s.%010uD%Z", to->len, to->data,
                           (uint32_t) njt_next_temp_number(0));

        if (njt_copy_file(src->data, name, &cf) == NJT_OK) {

            if (njt_rename_file(name, to->data) != NJT_FILE_ERROR) {
                njt_free(name);

                if (njt_delete_file(src->data) == NJT_FILE_ERROR) {
                    njt_log_error(NJT_LOG_CRIT, ext->log, njt_errno,
                                  njt_delete_file_n " \"%s\" failed",
                                  src->data);
                    return NJT_ERROR;
                }

                return NJT_OK;
            }

            njt_log_error(NJT_LOG_CRIT, ext->log, njt_errno,
                          njt_rename_file_n " \"%s\" to \"%s\" failed",
                          name, to->data);

            if (njt_delete_file(name) == NJT_FILE_ERROR) {
                njt_log_error(NJT_LOG_CRIT, ext->log, njt_errno,
                              njt_delete_file_n " \"%s\" failed", name);

            }
        }

        njt_free(name);

        err = 0;
    }

failed:

    if (ext->delete_file) {
        if (njt_delete_file(src->data) == NJT_FILE_ERROR) {
            njt_log_error(NJT_LOG_CRIT, ext->log, njt_errno,
                          njt_delete_file_n " \"%s\" failed", src->data);
        }
    }

    if (err) {
        njt_log_error(NJT_LOG_CRIT, ext->log, err,
                      njt_rename_file_n " \"%s\" to \"%s\" failed",
                      src->data, to->data);
    }

    return NJT_ERROR;
}


njt_int_t
njt_copy_file(u_char *from, u_char *to, njt_copy_file_t *cf)
{
    char             *buf;
    off_t             size;
    time_t            time;
    size_t            len;
    ssize_t           n;
    njt_fd_t          fd, nfd;
    njt_int_t         rc;
    njt_uint_t        access;
    njt_file_info_t   fi;

    rc = NJT_ERROR;
    buf = NULL;
    nfd = NJT_INVALID_FILE;

    fd = njt_open_file(from, NJT_FILE_RDONLY, NJT_FILE_OPEN, 0);

    if (fd == NJT_INVALID_FILE) {
        njt_log_error(NJT_LOG_CRIT, cf->log, njt_errno,
                      njt_open_file_n " \"%s\" failed", from);
        goto failed;
    }

    if (cf->size != -1 && cf->access != 0 && cf->time != -1) {
        size = cf->size;
        access = cf->access;
        time = cf->time;

    } else {
        if (njt_fd_info(fd, &fi) == NJT_FILE_ERROR) {
            njt_log_error(NJT_LOG_ALERT, cf->log, njt_errno,
                          njt_fd_info_n " \"%s\" failed", from);

            goto failed;
        }

        size = (cf->size != -1) ? cf->size : njt_file_size(&fi);
        access = cf->access ? cf->access : njt_file_access(&fi);
        time = (cf->time != -1) ? cf->time : njt_file_mtime(&fi);
    }

    len = cf->buf_size ? cf->buf_size : 65536;

    if ((off_t) len > size) {
        len = (size_t) size;
    }

    buf = njt_alloc(len, cf->log);
    if (buf == NULL) {
        goto failed;
    }

    nfd = njt_open_file(to, NJT_FILE_WRONLY, NJT_FILE_TRUNCATE, access);

    if (nfd == NJT_INVALID_FILE) {
        njt_log_error(NJT_LOG_CRIT, cf->log, njt_errno,
                      njt_open_file_n " \"%s\" failed", to);
        goto failed;
    }

    while (size > 0) {

        if ((off_t) len > size) {
            len = (size_t) size;
        }

        n = njt_read_fd(fd, buf, len);

        if (n == -1) {
            njt_log_error(NJT_LOG_ALERT, cf->log, njt_errno,
                          njt_read_fd_n " \"%s\" failed", from);
            goto failed;
        }

        if ((size_t) n != len) {
            njt_log_error(NJT_LOG_ALERT, cf->log, 0,
                          njt_read_fd_n " has read only %z of %O from %s",
                          n, size, from);
            goto failed;
        }

        n = njt_write_fd(nfd, buf, len);

        if (n == -1) {
            njt_log_error(NJT_LOG_ALERT, cf->log, njt_errno,
                          njt_write_fd_n " \"%s\" failed", to);
            goto failed;
        }

        if ((size_t) n != len) {
            njt_log_error(NJT_LOG_ALERT, cf->log, 0,
                          njt_write_fd_n " has written only %z of %O to %s",
                          n, size, to);
            goto failed;
        }

        size -= n;
    }

    if (njt_set_file_time(to, nfd, time) != NJT_OK) {
        njt_log_error(NJT_LOG_ALERT, cf->log, njt_errno,
                      njt_set_file_time_n " \"%s\" failed", to);
        goto failed;
    }

    rc = NJT_OK;

failed:

    if (nfd != NJT_INVALID_FILE) {
        if (njt_close_file(nfd) == NJT_FILE_ERROR) {
            njt_log_error(NJT_LOG_ALERT, cf->log, njt_errno,
                          njt_close_file_n " \"%s\" failed", to);
        }
    }

    if (fd != NJT_INVALID_FILE) {
        if (njt_close_file(fd) == NJT_FILE_ERROR) {
            njt_log_error(NJT_LOG_ALERT, cf->log, njt_errno,
                          njt_close_file_n " \"%s\" failed", from);
        }
    }

    if (buf) {
        njt_free(buf);
    }

    return rc;
}


/*
 * ctx->init_handler() - see ctx->alloc
 * ctx->file_handler() - file handler
 * ctx->pre_tree_handler() - handler is called before entering directory
 * ctx->post_tree_handler() - handler is called after leaving directory
 * ctx->spec_handler() - special (socket, FIFO, etc.) file handler
 *
 * ctx->data - some data structure, it may be the same on all levels, or
 *     reallocated if ctx->alloc is nonzero
 *
 * ctx->alloc - a size of data structure that is allocated at every level
 *     and is initialized by ctx->init_handler()
 *
 * ctx->log - a log
 *
 * on fatal (memory) error handler must return NJT_ABORT to stop walking tree
 */

njt_int_t
njt_walk_tree(njt_tree_ctx_t *ctx, njt_str_t *tree)
{
    void       *data, *prev;
    u_char     *p, *name;
    size_t      len;
    njt_int_t   rc;
    njt_err_t   err;
    njt_str_t   file, buf;
    njt_dir_t   dir;

    njt_str_null(&buf);

    njt_log_debug1(NJT_LOG_DEBUG_CORE, ctx->log, 0,
                   "walk tree \"%V\"", tree);

    if (njt_open_dir(tree, &dir) == NJT_ERROR) {
        njt_log_error(NJT_LOG_CRIT, ctx->log, njt_errno,
                      njt_open_dir_n " \"%s\" failed", tree->data);
        return NJT_ERROR;
    }

    prev = ctx->data;

    if (ctx->alloc) {
        data = njt_alloc(ctx->alloc, ctx->log);
        if (data == NULL) {
            goto failed;
        }

        if (ctx->init_handler(data, prev) == NJT_ABORT) {
            goto failed;
        }

        ctx->data = data;

    } else {
        data = NULL;
    }

    for ( ;; ) {

        njt_set_errno(0);

        if (njt_read_dir(&dir) == NJT_ERROR) {
            err = njt_errno;

            if (err == NJT_ENOMOREFILES) {
                rc = NJT_OK;

            } else {
                njt_log_error(NJT_LOG_CRIT, ctx->log, err,
                              njt_read_dir_n " \"%s\" failed", tree->data);
                rc = NJT_ERROR;
            }

            goto done;
        }

        len = njt_de_namelen(&dir);
        name = njt_de_name(&dir);

        njt_log_debug2(NJT_LOG_DEBUG_CORE, ctx->log, 0,
                      "tree name %uz:\"%s\"", len, name);

        if (len == 1 && name[0] == '.') {
            continue;
        }

        if (len == 2 && name[0] == '.' && name[1] == '.') {
            continue;
        }

        file.len = tree->len + 1 + len;

        if (file.len > buf.len) {

            if (buf.len) {
                njt_free(buf.data);
            }

            buf.len = tree->len + 1 + len;

            buf.data = njt_alloc(buf.len + 1, ctx->log);
            if (buf.data == NULL) {
                goto failed;
            }
        }

        p = njt_cpymem(buf.data, tree->data, tree->len);
        *p++ = '/';
        njt_memcpy(p, name, len + 1);

        file.data = buf.data;

        njt_log_debug1(NJT_LOG_DEBUG_CORE, ctx->log, 0,
                       "tree path \"%s\"", file.data);

        if (!dir.valid_info) {
            if (njt_de_info(file.data, &dir) == NJT_FILE_ERROR) {
                njt_log_error(NJT_LOG_CRIT, ctx->log, njt_errno,
                              njt_de_info_n " \"%s\" failed", file.data);
                continue;
            }
        }

        if (njt_de_is_file(&dir)) {

            njt_log_debug1(NJT_LOG_DEBUG_CORE, ctx->log, 0,
                           "tree file \"%s\"", file.data);

            ctx->size = njt_de_size(&dir);
            ctx->fs_size = njt_de_fs_size(&dir);
            ctx->access = njt_de_access(&dir);
            ctx->mtime = njt_de_mtime(&dir);

            if (ctx->file_handler(ctx, &file) == NJT_ABORT) {
                goto failed;
            }

        } else if (njt_de_is_dir(&dir)) {

            njt_log_debug1(NJT_LOG_DEBUG_CORE, ctx->log, 0,
                           "tree enter dir \"%s\"", file.data);

            ctx->access = njt_de_access(&dir);
            ctx->mtime = njt_de_mtime(&dir);

            rc = ctx->pre_tree_handler(ctx, &file);

            if (rc == NJT_ABORT) {
                goto failed;
            }

            if (rc == NJT_DECLINED) {
                njt_log_debug1(NJT_LOG_DEBUG_CORE, ctx->log, 0,
                               "tree skip dir \"%s\"", file.data);
                continue;
            }

            if (njt_walk_tree(ctx, &file) == NJT_ABORT) {
                goto failed;
            }

            ctx->access = njt_de_access(&dir);
            ctx->mtime = njt_de_mtime(&dir);

            if (ctx->post_tree_handler(ctx, &file) == NJT_ABORT) {
                goto failed;
            }

        } else {

            njt_log_debug1(NJT_LOG_DEBUG_CORE, ctx->log, 0,
                           "tree special \"%s\"", file.data);

            if (ctx->spec_handler(ctx, &file) == NJT_ABORT) {
                goto failed;
            }
        }
    }

failed:

    rc = NJT_ABORT;

done:

    if (buf.len) {
        njt_free(buf.data);
    }

    if (data) {
        njt_free(data);
        ctx->data = prev;
    }

    if (njt_close_dir(&dir) == NJT_ERROR) {
        njt_log_error(NJT_LOG_CRIT, ctx->log, njt_errno,
                      njt_close_dir_n " \"%s\" failed", tree->data);
    }

    return rc;
}
