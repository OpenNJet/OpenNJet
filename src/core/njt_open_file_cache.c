
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


/*
 * open file cache caches
 *    open file handles with stat() info;
 *    directories stat() info;
 *    files and directories errors: not found, access denied, etc.
 */


#define NJT_MIN_READ_AHEAD  (128 * 1024)


static void njt_open_file_cache_cleanup(void *data);
#if (NJT_HAVE_OPENAT)
static njt_fd_t njt_openat_file_owner(njt_fd_t at_fd, const u_char *name,
    njt_int_t mode, njt_int_t create, njt_int_t access, njt_log_t *log);
#if (NJT_HAVE_O_PATH)
static njt_int_t njt_file_o_path_info(njt_fd_t fd, njt_file_info_t *fi,
    njt_log_t *log);
#endif
#endif
static njt_fd_t njt_open_file_wrapper(njt_str_t *name,
    njt_open_file_info_t *of, njt_int_t mode, njt_int_t create,
    njt_int_t access, njt_log_t *log);
static njt_int_t njt_file_info_wrapper(njt_str_t *name,
    njt_open_file_info_t *of, njt_file_info_t *fi, njt_log_t *log);
static njt_int_t njt_open_and_stat_file(njt_str_t *name,
    njt_open_file_info_t *of, njt_log_t *log);
static void njt_open_file_add_event(njt_open_file_cache_t *cache,
    njt_cached_open_file_t *file, njt_open_file_info_t *of, njt_log_t *log);
static void njt_open_file_cleanup(void *data);
static void njt_close_cached_file(njt_open_file_cache_t *cache,
    njt_cached_open_file_t *file, njt_uint_t min_uses, njt_log_t *log);
static void njt_open_file_del_event(njt_cached_open_file_t *file);
static void njt_expire_old_cached_files(njt_open_file_cache_t *cache,
    njt_uint_t n, njt_log_t *log);
static void njt_open_file_cache_rbtree_insert_value(njt_rbtree_node_t *temp,
    njt_rbtree_node_t *node, njt_rbtree_node_t *sentinel);
static njt_cached_open_file_t *
    njt_open_file_lookup(njt_open_file_cache_t *cache, njt_str_t *name,
    uint32_t hash);
static void njt_open_file_cache_remove(njt_event_t *ev);


njt_open_file_cache_t *
njt_open_file_cache_init(njt_pool_t *pool, njt_uint_t max, time_t inactive)
{
    njt_pool_cleanup_t     *cln;
    njt_open_file_cache_t  *cache;

    cache = njt_palloc(pool, sizeof(njt_open_file_cache_t));
    if (cache == NULL) {
        return NULL;
    }

    njt_rbtree_init(&cache->rbtree, &cache->sentinel,
                    njt_open_file_cache_rbtree_insert_value);

    njt_queue_init(&cache->expire_queue);

    cache->current = 0;
    cache->max = max;
    cache->inactive = inactive;

    cln = njt_pool_cleanup_add(pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = njt_open_file_cache_cleanup;
    cln->data = cache;

    return cache;
}


static void
njt_open_file_cache_cleanup(void *data)
{
    njt_open_file_cache_t  *cache = data;

    njt_queue_t             *q;
    njt_cached_open_file_t  *file;

    njt_log_debug0(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0,
                   "open file cache cleanup");

    for ( ;; ) {

        if (njt_queue_empty(&cache->expire_queue)) {
            break;
        }

        q = njt_queue_last(&cache->expire_queue);

        file = njt_queue_data(q, njt_cached_open_file_t, queue);

        njt_queue_remove(q);

        njt_rbtree_delete(&cache->rbtree, &file->node);

        cache->current--;

        njt_log_debug1(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0,
                       "delete cached open file: %s", file->name);

        if (!file->err && !file->is_dir) {
            file->close = 1;
            file->count = 0;
            njt_close_cached_file(cache, file, 0, njt_cycle->log);

        } else {
            njt_free(file->name);
            njt_free(file);
        }
    }

    if (cache->current) {
        njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,
                      "%ui items still left in open file cache",
                      cache->current);
    }

    if (cache->rbtree.root != cache->rbtree.sentinel) {
        njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,
                      "rbtree still is not empty in open file cache");

    }
}


njt_int_t
njt_open_cached_file(njt_open_file_cache_t *cache, njt_str_t *name,
    njt_open_file_info_t *of, njt_pool_t *pool)
{
    time_t                          now;
    uint32_t                        hash;
    njt_int_t                       rc;
    njt_file_info_t                 fi;
    njt_pool_cleanup_t             *cln;
    njt_cached_open_file_t         *file;
    njt_pool_cleanup_file_t        *clnf;
    njt_open_file_cache_cleanup_t  *ofcln;

    of->fd = NJT_INVALID_FILE;
    of->err = 0;

    if (cache == NULL) {

        if (of->test_only) {

            if (njt_file_info_wrapper(name, of, &fi, pool->log)
                == NJT_FILE_ERROR)
            {
                return NJT_ERROR;
            }

            of->uniq = njt_file_uniq(&fi);
            of->mtime = njt_file_mtime(&fi);
            of->size = njt_file_size(&fi);
            of->fs_size = njt_file_fs_size(&fi);
            of->is_dir = njt_is_dir(&fi);
            of->is_file = njt_is_file(&fi);
            of->is_link = njt_is_link(&fi);
            of->is_exec = njt_is_exec(&fi);

            return NJT_OK;
        }

        cln = njt_pool_cleanup_add(pool, sizeof(njt_pool_cleanup_file_t));
        if (cln == NULL) {
            return NJT_ERROR;
        }

        rc = njt_open_and_stat_file(name, of, pool->log);

        if (rc == NJT_OK && !of->is_dir) {
            cln->handler = njt_pool_cleanup_file;
            clnf = cln->data;

            clnf->fd = of->fd;
            clnf->name = name->data;
            clnf->log = pool->log;
        }

        return rc;
    }

    cln = njt_pool_cleanup_add(pool, sizeof(njt_open_file_cache_cleanup_t));
    if (cln == NULL) {
        return NJT_ERROR;
    }

    now = njt_time();

    hash = njt_crc32_long(name->data, name->len);

    file = njt_open_file_lookup(cache, name, hash);

    if (file) {

        file->uses++;

        njt_queue_remove(&file->queue);

        if (file->fd == NJT_INVALID_FILE && file->err == 0 && !file->is_dir) {

            /* file was not used often enough to keep open */

            rc = njt_open_and_stat_file(name, of, pool->log);

            if (rc != NJT_OK && (of->err == 0 || !of->errors)) {
                goto failed;
            }

            goto add_event;
        }

        if (file->use_event
            || (file->event == NULL
                && (of->uniq == 0 || of->uniq == file->uniq)
                && now - file->created < of->valid
#if (NJT_HAVE_OPENAT)
                && of->disable_symlinks == file->disable_symlinks
                && of->disable_symlinks_from == file->disable_symlinks_from
#endif
            ))
        {
            if (file->err == 0) {

                of->fd = file->fd;
                of->uniq = file->uniq;
                of->mtime = file->mtime;
                of->size = file->size;

                of->is_dir = file->is_dir;
                of->is_file = file->is_file;
                of->is_link = file->is_link;
                of->is_exec = file->is_exec;
                of->is_directio = file->is_directio;

                if (!file->is_dir) {
                    file->count++;
                    njt_open_file_add_event(cache, file, of, pool->log);
                }

            } else {
                of->err = file->err;
#if (NJT_HAVE_OPENAT)
                of->failed = file->disable_symlinks ? njt_openat_file_n
                                                    : njt_open_file_n;
#else
                of->failed = njt_open_file_n;
#endif
            }

            goto found;
        }

        njt_log_debug4(NJT_LOG_DEBUG_CORE, pool->log, 0,
                       "retest open file: %s, fd:%d, c:%d, e:%d",
                       file->name, file->fd, file->count, file->err);

        if (file->is_dir) {

            /*
             * chances that directory became file are very small
             * so test_dir flag allows to use a single syscall
             * in njt_file_info() instead of three syscalls
             */

            of->test_dir = 1;
        }

        of->fd = file->fd;
        of->uniq = file->uniq;

        rc = njt_open_and_stat_file(name, of, pool->log);

        if (rc != NJT_OK && (of->err == 0 || !of->errors)) {
            goto failed;
        }

        if (of->is_dir) {

            if (file->is_dir || file->err) {
                goto update;
            }

            /* file became directory */

        } else if (of->err == 0) {  /* file */

            if (file->is_dir || file->err) {
                goto add_event;
            }

            if (of->uniq == file->uniq) {

                if (file->event) {
                    file->use_event = 1;
                }

                of->is_directio = file->is_directio;

                goto update;
            }

            /* file was changed */

        } else { /* error to cache */

            if (file->err || file->is_dir) {
                goto update;
            }

            /* file was removed, etc. */
        }

        if (file->count == 0) {

            njt_open_file_del_event(file);

            if (njt_close_file(file->fd) == NJT_FILE_ERROR) {
                njt_log_error(NJT_LOG_ALERT, pool->log, njt_errno,
                              njt_close_file_n " \"%V\" failed", name);
            }

            goto add_event;
        }

        njt_rbtree_delete(&cache->rbtree, &file->node);

        cache->current--;

        file->close = 1;

        goto create;
    }

    /* not found */

    rc = njt_open_and_stat_file(name, of, pool->log);

    if (rc != NJT_OK && (of->err == 0 || !of->errors)) {
        goto failed;
    }

create:

    if (cache->current >= cache->max) {
        njt_expire_old_cached_files(cache, 0, pool->log);
    }

    file = njt_alloc(sizeof(njt_cached_open_file_t), pool->log);

    if (file == NULL) {
        goto failed;
    }

    file->name = njt_alloc(name->len + 1, pool->log);

    if (file->name == NULL) {
        njt_free(file);
        file = NULL;
        goto failed;
    }

    njt_cpystrn(file->name, name->data, name->len + 1);

    file->node.key = hash;

    njt_rbtree_insert(&cache->rbtree, &file->node);

    cache->current++;

    file->uses = 1;
    file->count = 0;
    file->use_event = 0;
    file->event = NULL;

add_event:

    njt_open_file_add_event(cache, file, of, pool->log);

update:

    file->fd = of->fd;
    file->err = of->err;
#if (NJT_HAVE_OPENAT)
    file->disable_symlinks = of->disable_symlinks;
    file->disable_symlinks_from = of->disable_symlinks_from;
#endif

    if (of->err == 0) {
        file->uniq = of->uniq;
        file->mtime = of->mtime;
        file->size = of->size;

        file->close = 0;

        file->is_dir = of->is_dir;
        file->is_file = of->is_file;
        file->is_link = of->is_link;
        file->is_exec = of->is_exec;
        file->is_directio = of->is_directio;

        if (!of->is_dir) {
            file->count++;
        }
    }

    file->created = now;

found:

    file->accessed = now;

    njt_queue_insert_head(&cache->expire_queue, &file->queue);

    njt_log_debug5(NJT_LOG_DEBUG_CORE, pool->log, 0,
                   "cached open file: %s, fd:%d, c:%d, e:%d, u:%d",
                   file->name, file->fd, file->count, file->err, file->uses);

    if (of->err == 0) {

        if (!of->is_dir) {
            cln->handler = njt_open_file_cleanup;
            ofcln = cln->data;

            ofcln->cache = cache;
            ofcln->file = file;
            ofcln->min_uses = of->min_uses;
            ofcln->log = pool->log;
        }

        return NJT_OK;
    }

    return NJT_ERROR;

failed:

    if (file) {
        njt_rbtree_delete(&cache->rbtree, &file->node);

        cache->current--;

        if (file->count == 0) {

            if (file->fd != NJT_INVALID_FILE) {
                if (njt_close_file(file->fd) == NJT_FILE_ERROR) {
                    njt_log_error(NJT_LOG_ALERT, pool->log, njt_errno,
                                  njt_close_file_n " \"%s\" failed",
                                  file->name);
                }
            }

            njt_free(file->name);
            njt_free(file);

        } else {
            file->close = 1;
        }
    }

    if (of->fd != NJT_INVALID_FILE) {
        if (njt_close_file(of->fd) == NJT_FILE_ERROR) {
            njt_log_error(NJT_LOG_ALERT, pool->log, njt_errno,
                          njt_close_file_n " \"%V\" failed", name);
        }
    }

    return NJT_ERROR;
}


#if (NJT_HAVE_OPENAT)

static njt_fd_t
njt_openat_file_owner(njt_fd_t at_fd, const u_char *name,
    njt_int_t mode, njt_int_t create, njt_int_t access, njt_log_t *log)
{
    njt_fd_t         fd;
    njt_err_t        err;
    njt_file_info_t  fi, atfi;

    /*
     * To allow symlinks with the same owner, use openat() (followed
     * by fstat()) and fstatat(AT_SYMLINK_NOFOLLOW), and then compare
     * uids between fstat() and fstatat().
     *
     * As there is a race between openat() and fstatat() we don't
     * know if openat() in fact opened symlink or not.  Therefore,
     * we have to compare uids even if fstatat() reports the opened
     * component isn't a symlink (as we don't know whether it was
     * symlink during openat() or not).
     */

    fd = njt_openat_file(at_fd, name, mode, create, access);

    if (fd == NJT_INVALID_FILE) {
        return NJT_INVALID_FILE;
    }

    if (njt_file_at_info(at_fd, name, &atfi, AT_SYMLINK_NOFOLLOW)
        == NJT_FILE_ERROR)
    {
        err = njt_errno;
        goto failed;
    }

#if (NJT_HAVE_O_PATH)
    if (njt_file_o_path_info(fd, &fi, log) == NJT_ERROR) {
        err = njt_errno;
        goto failed;
    }
#else
    if (njt_fd_info(fd, &fi) == NJT_FILE_ERROR) {
        err = njt_errno;
        goto failed;
    }
#endif

    if (fi.st_uid != atfi.st_uid) {
        err = NJT_ELOOP;
        goto failed;
    }

    return fd;

failed:

    if (njt_close_file(fd) == NJT_FILE_ERROR) {
        njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                      njt_close_file_n " \"%s\" failed", name);
    }

    njt_set_errno(err);

    return NJT_INVALID_FILE;
}


#if (NJT_HAVE_O_PATH)

static njt_int_t
njt_file_o_path_info(njt_fd_t fd, njt_file_info_t *fi, njt_log_t *log)
{
    static njt_uint_t  use_fstat = 1;

    /*
     * In Linux 2.6.39 the O_PATH flag was introduced that allows to obtain
     * a descriptor without actually opening file or directory.  It requires
     * less permissions for path components, but till Linux 3.6 fstat() returns
     * EBADF on such descriptors, and fstatat() with the AT_EMPTY_PATH flag
     * should be used instead.
     *
     * Three scenarios are handled in this function:
     *
     * 1) The kernel is newer than 3.6 or fstat() with O_PATH support was
     *    backported by vendor.  Then fstat() is used.
     *
     * 2) The kernel is newer than 2.6.39 but older than 3.6.  In this case
     *    the first call of fstat() returns EBADF and we fallback to fstatat()
     *    with AT_EMPTY_PATH which was introduced at the same time as O_PATH.
     *
     * 3) The kernel is older than 2.6.39 but njet was build with O_PATH
     *    support.  Since descriptors are opened with O_PATH|O_RDONLY flags
     *    and O_PATH is ignored by the kernel then the O_RDONLY flag is
     *    actually used.  In this case fstat() just works.
     */

    if (use_fstat) {
        if (njt_fd_info(fd, fi) != NJT_FILE_ERROR) {
            return NJT_OK;
        }

        if (njt_errno != NJT_EBADF) {
            return NJT_ERROR;
        }

        njt_log_error(NJT_LOG_NOTICE, log, 0,
                      "fstat(O_PATH) failed with EBADF, "
                      "switching to fstatat(AT_EMPTY_PATH)");

        use_fstat = 0;
    }

    if (njt_file_at_info(fd, "", fi, AT_EMPTY_PATH) != NJT_FILE_ERROR) {
        return NJT_OK;
    }

    return NJT_ERROR;
}

#endif

#endif /* NJT_HAVE_OPENAT */


static njt_fd_t
njt_open_file_wrapper(njt_str_t *name, njt_open_file_info_t *of,
    njt_int_t mode, njt_int_t create, njt_int_t access, njt_log_t *log)
{
    njt_fd_t  fd;

#if !(NJT_HAVE_OPENAT)

    fd = njt_open_file(name->data, mode, create, access);

    if (fd == NJT_INVALID_FILE) {
        of->err = njt_errno;
        of->failed = njt_open_file_n;
        return NJT_INVALID_FILE;
    }

    return fd;

#else

    u_char           *p, *cp, *end;
    njt_fd_t          at_fd;
    njt_str_t         at_name;

    if (of->disable_symlinks == NJT_DISABLE_SYMLINKS_OFF) {
        fd = njt_open_file(name->data, mode, create, access);

        if (fd == NJT_INVALID_FILE) {
            of->err = njt_errno;
            of->failed = njt_open_file_n;
            return NJT_INVALID_FILE;
        }

        return fd;
    }

    p = name->data;
    end = p + name->len;

    at_name = *name;

    if (of->disable_symlinks_from) {

        cp = p + of->disable_symlinks_from;

        *cp = '\0';

        at_fd = njt_open_file(p, NJT_FILE_SEARCH|NJT_FILE_NONBLOCK,
                              NJT_FILE_OPEN, 0);

        *cp = '/';

        if (at_fd == NJT_INVALID_FILE) {
            of->err = njt_errno;
            of->failed = njt_open_file_n;
            return NJT_INVALID_FILE;
        }

        at_name.len = of->disable_symlinks_from;
        p = cp + 1;

    } else if (*p == '/') {

        at_fd = njt_open_file("/",
                              NJT_FILE_SEARCH|NJT_FILE_NONBLOCK,
                              NJT_FILE_OPEN, 0);

        if (at_fd == NJT_INVALID_FILE) {
            of->err = njt_errno;
            of->failed = njt_openat_file_n;
            return NJT_INVALID_FILE;
        }

        at_name.len = 1;
        p++;

    } else {
        at_fd = NJT_AT_FDCWD;
    }

    for ( ;; ) {
        cp = njt_strlchr(p, end, '/');
        if (cp == NULL) {
            break;
        }

        if (cp == p) {
            p++;
            continue;
        }

        *cp = '\0';

        if (of->disable_symlinks == NJT_DISABLE_SYMLINKS_NOTOWNER) {
            fd = njt_openat_file_owner(at_fd, p,
                                       NJT_FILE_SEARCH|NJT_FILE_NONBLOCK,
                                       NJT_FILE_OPEN, 0, log);

        } else {
            fd = njt_openat_file(at_fd, p,
                           NJT_FILE_SEARCH|NJT_FILE_NONBLOCK|NJT_FILE_NOFOLLOW,
                           NJT_FILE_OPEN, 0);
        }

        *cp = '/';

        if (fd == NJT_INVALID_FILE) {
            of->err = njt_errno;
            of->failed = njt_openat_file_n;
            goto failed;
        }

        if (at_fd != NJT_AT_FDCWD && njt_close_file(at_fd) == NJT_FILE_ERROR) {
            njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                          njt_close_file_n " \"%V\" failed", &at_name);
        }

        p = cp + 1;
        at_fd = fd;
        at_name.len = cp - at_name.data;
    }

    if (p == end) {

        /*
         * If pathname ends with a trailing slash, assume the last path
         * component is a directory and reopen it with requested flags;
         * if not, fail with ENOTDIR as per POSIX.
         *
         * We cannot rely on O_DIRECTORY in the loop above to check
         * that the last path component is a directory because
         * O_DIRECTORY doesn't work on FreeBSD 8.  Fortunately, by
         * reopening a directory, we don't depend on it at all.
         */

        fd = njt_openat_file(at_fd, ".", mode, create, access);
        goto done;
    }

    if (of->disable_symlinks == NJT_DISABLE_SYMLINKS_NOTOWNER
        && !(create & (NJT_FILE_CREATE_OR_OPEN|NJT_FILE_TRUNCATE)))
    {
        fd = njt_openat_file_owner(at_fd, p, mode, create, access, log);

    } else {
        fd = njt_openat_file(at_fd, p, mode|NJT_FILE_NOFOLLOW, create, access);
    }

done:

    if (fd == NJT_INVALID_FILE) {
        of->err = njt_errno;
        of->failed = njt_openat_file_n;
    }

failed:

    if (at_fd != NJT_AT_FDCWD && njt_close_file(at_fd) == NJT_FILE_ERROR) {
        njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                      njt_close_file_n " \"%V\" failed", &at_name);
    }

    return fd;
#endif
}


static njt_int_t
njt_file_info_wrapper(njt_str_t *name, njt_open_file_info_t *of,
    njt_file_info_t *fi, njt_log_t *log)
{
    njt_int_t  rc;

#if !(NJT_HAVE_OPENAT)

    rc = njt_file_info(name->data, fi);

    if (rc == NJT_FILE_ERROR) {
        of->err = njt_errno;
        of->failed = njt_file_info_n;
        return NJT_FILE_ERROR;
    }

    return rc;

#else

    njt_fd_t  fd;

    if (of->disable_symlinks == NJT_DISABLE_SYMLINKS_OFF) {

        rc = njt_file_info(name->data, fi);

        if (rc == NJT_FILE_ERROR) {
            of->err = njt_errno;
            of->failed = njt_file_info_n;
            return NJT_FILE_ERROR;
        }

        return rc;
    }

    fd = njt_open_file_wrapper(name, of, NJT_FILE_RDONLY|NJT_FILE_NONBLOCK,
                               NJT_FILE_OPEN, 0, log);

    if (fd == NJT_INVALID_FILE) {
        return NJT_FILE_ERROR;
    }

    rc = njt_fd_info(fd, fi);

    if (rc == NJT_FILE_ERROR) {
        of->err = njt_errno;
        of->failed = njt_fd_info_n;
    }

    if (njt_close_file(fd) == NJT_FILE_ERROR) {
        njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                      njt_close_file_n " \"%V\" failed", name);
    }

    return rc;
#endif
}


static njt_int_t
njt_open_and_stat_file(njt_str_t *name, njt_open_file_info_t *of,
    njt_log_t *log)
{
    njt_fd_t         fd;
    njt_file_info_t  fi;

    if (of->fd != NJT_INVALID_FILE) {

        if (njt_file_info_wrapper(name, of, &fi, log) == NJT_FILE_ERROR) {
            of->fd = NJT_INVALID_FILE;
            return NJT_ERROR;
        }

        if (of->uniq == njt_file_uniq(&fi)) {
            goto done;
        }

    } else if (of->test_dir) {

        if (njt_file_info_wrapper(name, of, &fi, log) == NJT_FILE_ERROR) {
            of->fd = NJT_INVALID_FILE;
            return NJT_ERROR;
        }

        if (njt_is_dir(&fi)) {
            goto done;
        }
    }

    if (!of->log) {

        /*
         * Use non-blocking open() not to hang on FIFO files, etc.
         * This flag has no effect on a regular files.
         */

        fd = njt_open_file_wrapper(name, of, NJT_FILE_RDONLY|NJT_FILE_NONBLOCK,
                                   NJT_FILE_OPEN, 0, log);

    } else {
        fd = njt_open_file_wrapper(name, of, NJT_FILE_APPEND,
                                   NJT_FILE_CREATE_OR_OPEN,
                                   NJT_FILE_DEFAULT_ACCESS, log);
    }

    if (fd == NJT_INVALID_FILE) {
        of->fd = NJT_INVALID_FILE;
        return NJT_ERROR;
    }

    if (njt_fd_info(fd, &fi) == NJT_FILE_ERROR) {
        njt_log_error(NJT_LOG_CRIT, log, njt_errno,
                      njt_fd_info_n " \"%V\" failed", name);

        if (njt_close_file(fd) == NJT_FILE_ERROR) {
            njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                          njt_close_file_n " \"%V\" failed", name);
        }

        of->fd = NJT_INVALID_FILE;

        return NJT_ERROR;
    }

    if (njt_is_dir(&fi)) {
        if (njt_close_file(fd) == NJT_FILE_ERROR) {
            njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                          njt_close_file_n " \"%V\" failed", name);
        }

        of->fd = NJT_INVALID_FILE;

    } else {
        of->fd = fd;

        if (of->read_ahead && njt_file_size(&fi) > NJT_MIN_READ_AHEAD) {
            if (njt_read_ahead(fd, of->read_ahead) == NJT_ERROR) {
                njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                              njt_read_ahead_n " \"%V\" failed", name);
            }
        }

        if (of->directio <= njt_file_size(&fi)) {
            if (njt_directio_on(fd) == NJT_FILE_ERROR) {
                njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                              njt_directio_on_n " \"%V\" failed", name);

            } else {
                of->is_directio = 1;
            }
        }
    }

done:

    of->uniq = njt_file_uniq(&fi);
    of->mtime = njt_file_mtime(&fi);
    of->size = njt_file_size(&fi);
    of->fs_size = njt_file_fs_size(&fi);
    of->is_dir = njt_is_dir(&fi);
    of->is_file = njt_is_file(&fi);
    of->is_link = njt_is_link(&fi);
    of->is_exec = njt_is_exec(&fi);

    return NJT_OK;
}


/*
 * we ignore any possible event setting error and
 * fallback to usual periodic file retests
 */

static void
njt_open_file_add_event(njt_open_file_cache_t *cache,
    njt_cached_open_file_t *file, njt_open_file_info_t *of, njt_log_t *log)
{
    njt_open_file_cache_event_t  *fev;

    if (!(njt_event_flags & NJT_USE_VNODE_EVENT)
        || !of->events
        || file->event
        || of->fd == NJT_INVALID_FILE
        || file->uses < of->min_uses)
    {
        return;
    }

    file->use_event = 0;

    file->event = njt_calloc(sizeof(njt_event_t), log);
    if (file->event== NULL) {
        return;
    }

    fev = njt_alloc(sizeof(njt_open_file_cache_event_t), log);
    if (fev == NULL) {
        njt_free(file->event);
        file->event = NULL;
        return;
    }

    fev->fd = of->fd;
    fev->file = file;
    fev->cache = cache;

    file->event->handler = njt_open_file_cache_remove;
    file->event->data = fev;

    /*
     * although vnode event may be called while njt_cycle->poll
     * destruction, however, cleanup procedures are run before any
     * memory freeing and events will be canceled.
     */

    file->event->log = njt_cycle->log;

    if (njt_add_event(file->event, NJT_VNODE_EVENT, NJT_ONESHOT_EVENT)
        != NJT_OK)
    {
        njt_free(file->event->data);
        njt_free(file->event);
        file->event = NULL;
        return;
    }

    /*
     * we do not set file->use_event here because there may be a race
     * condition: a file may be deleted between opening the file and
     * adding event, so we rely upon event notification only after
     * one file revalidation on next file access
     */

    return;
}


static void
njt_open_file_cleanup(void *data)
{
    njt_open_file_cache_cleanup_t  *c = data;

    c->file->count--;

    njt_close_cached_file(c->cache, c->file, c->min_uses, c->log);

    /* drop one or two expired open files */
    njt_expire_old_cached_files(c->cache, 1, c->log);
}


static void
njt_close_cached_file(njt_open_file_cache_t *cache,
    njt_cached_open_file_t *file, njt_uint_t min_uses, njt_log_t *log)
{
    njt_log_debug5(NJT_LOG_DEBUG_CORE, log, 0,
                   "close cached open file: %s, fd:%d, c:%d, u:%d, %d",
                   file->name, file->fd, file->count, file->uses, file->close);

    if (!file->close) {

        file->accessed = njt_time();

        njt_queue_remove(&file->queue);

        njt_queue_insert_head(&cache->expire_queue, &file->queue);

        if (file->uses >= min_uses || file->count) {
            return;
        }
    }

    njt_open_file_del_event(file);

    if (file->count) {
        return;
    }

    if (file->fd != NJT_INVALID_FILE) {

        if (njt_close_file(file->fd) == NJT_FILE_ERROR) {
            njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                          njt_close_file_n " \"%s\" failed", file->name);
        }

        file->fd = NJT_INVALID_FILE;
    }

    if (!file->close) {
        return;
    }

    njt_free(file->name);
    njt_free(file);
}


static void
njt_open_file_del_event(njt_cached_open_file_t *file)
{
    if (file->event == NULL) {
        return;
    }

    (void) njt_del_event(file->event, NJT_VNODE_EVENT,
                         file->count ? NJT_FLUSH_EVENT : NJT_CLOSE_EVENT);

    njt_free(file->event->data);
    njt_free(file->event);
    file->event = NULL;
    file->use_event = 0;
}


static void
njt_expire_old_cached_files(njt_open_file_cache_t *cache, njt_uint_t n,
    njt_log_t *log)
{
    time_t                   now;
    njt_queue_t             *q;
    njt_cached_open_file_t  *file;

    now = njt_time();

    /*
     * n == 1 deletes one or two inactive files
     * n == 0 deletes least recently used file by force
     *        and one or two inactive files
     */

    while (n < 3) {

        if (njt_queue_empty(&cache->expire_queue)) {
            return;
        }

        q = njt_queue_last(&cache->expire_queue);

        file = njt_queue_data(q, njt_cached_open_file_t, queue);

        if (n++ != 0 && now - file->accessed <= cache->inactive) {
            return;
        }

        njt_queue_remove(q);

        njt_rbtree_delete(&cache->rbtree, &file->node);

        cache->current--;

        njt_log_debug1(NJT_LOG_DEBUG_CORE, log, 0,
                       "expire cached open file: %s", file->name);

        if (!file->err && !file->is_dir) {
            file->close = 1;
            njt_close_cached_file(cache, file, 0, log);

        } else {
            njt_free(file->name);
            njt_free(file);
        }
    }
}


static void
njt_open_file_cache_rbtree_insert_value(njt_rbtree_node_t *temp,
    njt_rbtree_node_t *node, njt_rbtree_node_t *sentinel)
{
    njt_rbtree_node_t       **p;
    njt_cached_open_file_t    *file, *file_temp;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            file = (njt_cached_open_file_t *) node;
            file_temp = (njt_cached_open_file_t *) temp;

            p = (njt_strcmp(file->name, file_temp->name) < 0)
                    ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    njt_rbt_red(node);
}


static njt_cached_open_file_t *
njt_open_file_lookup(njt_open_file_cache_t *cache, njt_str_t *name,
    uint32_t hash)
{
    njt_int_t                rc;
    njt_rbtree_node_t       *node, *sentinel;
    njt_cached_open_file_t  *file;

    node = cache->rbtree.root;
    sentinel = cache->rbtree.sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        file = (njt_cached_open_file_t *) node;

        rc = njt_strcmp(name->data, file->name);

        if (rc == 0) {
            return file;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


static void
njt_open_file_cache_remove(njt_event_t *ev)
{
    njt_cached_open_file_t       *file;
    njt_open_file_cache_event_t  *fev;

    fev = ev->data;
    file = fev->file;

    njt_queue_remove(&file->queue);

    njt_rbtree_delete(&fev->cache->rbtree, &file->node);

    fev->cache->current--;

    /* NJT_ONESHOT_EVENT was already deleted */
    file->event = NULL;
    file->use_event = 0;

    file->close = 1;

    njt_close_cached_file(fev->cache, file, 0, ev->log);

    /* free memory only when fev->cache and fev->file are already not needed */

    njt_free(ev->data);
    njt_free(ev);
}
