
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>


#if (NJT_THREADS)
#include <njt_thread_pool.h>
static void njt_thread_read_handler(void *data, njt_log_t *log);
static void njt_thread_write_chain_to_file_handler(void *data, njt_log_t *log);
#endif

static njt_chain_t *njt_chain_to_iovec(njt_iovec_t *vec, njt_chain_t *cl);
static ssize_t njt_writev_file(njt_file_t *file, njt_iovec_t *vec,
    off_t offset);


#if (NJT_HAVE_FILE_AIO)

njt_uint_t  njt_file_aio = 1;

#endif


ssize_t
njt_read_file(njt_file_t *file, u_char *buf, size_t size, off_t offset)
{
    ssize_t  n;

    njt_log_debug4(NJT_LOG_DEBUG_CORE, file->log, 0,
                   "read: %d, %p, %uz, %O", file->fd, buf, size, offset);

#if (NJT_HAVE_PREAD)

    n = pread(file->fd, buf, size, offset);

    if (n == -1) {
        njt_log_error(NJT_LOG_CRIT, file->log, njt_errno,
                      "pread() \"%s\" failed", file->name.data);
        return NJT_ERROR;
    }

#else

    if (file->sys_offset != offset) {
        if (lseek(file->fd, offset, SEEK_SET) == -1) {
            njt_log_error(NJT_LOG_CRIT, file->log, njt_errno,
                          "lseek() \"%s\" failed", file->name.data);
            return NJT_ERROR;
        }

        file->sys_offset = offset;
    }

    n = read(file->fd, buf, size);

    if (n == -1) {
        njt_log_error(NJT_LOG_CRIT, file->log, njt_errno,
                      "read() \"%s\" failed", file->name.data);
        return NJT_ERROR;
    }

    file->sys_offset += n;

#endif

    file->offset += n;

    return n;
}


#if (NJT_THREADS)

typedef struct {
    njt_fd_t       fd;
    njt_uint_t     write;   /* unsigned  write:1; */

    u_char        *buf;
    size_t         size;
    njt_chain_t   *chain;
    off_t          offset;

    size_t         nbytes;
    njt_err_t      err;
} njt_thread_file_ctx_t;


ssize_t
njt_thread_read(njt_file_t *file, u_char *buf, size_t size, off_t offset,
    njt_pool_t *pool)
{
    njt_thread_task_t      *task;
    njt_thread_file_ctx_t  *ctx;

    njt_log_debug4(NJT_LOG_DEBUG_CORE, file->log, 0,
                   "thread read: %d, %p, %uz, %O",
                   file->fd, buf, size, offset);

    task = file->thread_task;

    if (task == NULL) {
        task = njt_thread_task_alloc(pool, sizeof(njt_thread_file_ctx_t));
        if (task == NULL) {
            return NJT_ERROR;
        }

        file->thread_task = task;
    }

    ctx = task->ctx;

    if (task->event.complete) {
        task->event.complete = 0;

        if (ctx->write) {
            njt_log_error(NJT_LOG_ALERT, file->log, 0,
                          "invalid thread call, read instead of write");
            return NJT_ERROR;
        }

        if (ctx->err) {
            njt_log_error(NJT_LOG_CRIT, file->log, ctx->err,
                          "pread() \"%s\" failed", file->name.data);
            return NJT_ERROR;
        }

        return ctx->nbytes;
    }

    task->handler = njt_thread_read_handler;

    ctx->write = 0;

    ctx->fd = file->fd;
    ctx->buf = buf;
    ctx->size = size;
    ctx->offset = offset;

    if (file->thread_handler(task, file) != NJT_OK) {
        return NJT_ERROR;
    }

    return NJT_AGAIN;
}


#if (NJT_HAVE_PREAD)

static void
njt_thread_read_handler(void *data, njt_log_t *log)
{
    njt_thread_file_ctx_t *ctx = data;

    ssize_t  n;

    njt_log_debug0(NJT_LOG_DEBUG_CORE, log, 0, "thread read handler");

    n = pread(ctx->fd, ctx->buf, ctx->size, ctx->offset);

    if (n == -1) {
        ctx->err = njt_errno;

    } else {
        ctx->nbytes = n;
        ctx->err = 0;
    }

#if 0
    njt_time_update();
#endif

    njt_log_debug4(NJT_LOG_DEBUG_CORE, log, 0,
                   "pread: %z (err: %d) of %uz @%O",
                   n, ctx->err, ctx->size, ctx->offset);
}

#else

#error pread() is required!

#endif

#endif /* NJT_THREADS */


ssize_t
njt_write_file(njt_file_t *file, u_char *buf, size_t size, off_t offset)
{
    ssize_t    n, written;
    njt_err_t  err;

    njt_log_debug4(NJT_LOG_DEBUG_CORE, file->log, 0,
                   "write: %d, %p, %uz, %O", file->fd, buf, size, offset);

    written = 0;

#if (NJT_HAVE_PWRITE)

    for ( ;; ) {
        n = pwrite(file->fd, buf + written, size, offset);

        if (n == -1) {
            err = njt_errno;

            if (err == NJT_EINTR) {
                njt_log_debug0(NJT_LOG_DEBUG_CORE, file->log, err,
                               "pwrite() was interrupted");
                continue;
            }

            njt_log_error(NJT_LOG_CRIT, file->log, err,
                          "pwrite() \"%s\" failed", file->name.data);
            return NJT_ERROR;
        }

        file->offset += n;
        written += n;

        if ((size_t) n == size) {
            return written;
        }

        offset += n;
        size -= n;
    }

#else

    if (file->sys_offset != offset) {
        if (lseek(file->fd, offset, SEEK_SET) == -1) {
            njt_log_error(NJT_LOG_CRIT, file->log, njt_errno,
                          "lseek() \"%s\" failed", file->name.data);
            return NJT_ERROR;
        }

        file->sys_offset = offset;
    }

    for ( ;; ) {
        n = write(file->fd, buf + written, size);

        if (n == -1) {
            err = njt_errno;

            if (err == NJT_EINTR) {
                njt_log_debug0(NJT_LOG_DEBUG_CORE, file->log, err,
                               "write() was interrupted");
                continue;
            }

            njt_log_error(NJT_LOG_CRIT, file->log, err,
                          "write() \"%s\" failed", file->name.data);
            return NJT_ERROR;
        }

        file->sys_offset += n;
        file->offset += n;
        written += n;

        if ((size_t) n == size) {
            return written;
        }

        size -= n;
    }
#endif
}


njt_fd_t
njt_open_tempfile(u_char *name, njt_uint_t persistent, njt_uint_t access)
{
    njt_fd_t  fd;

    fd = open((const char *) name, O_CREAT|O_EXCL|O_RDWR,
              access ? access : 0600);

    if (fd != -1 && !persistent) {
        (void) unlink((const char *) name);
    }

    return fd;
}


ssize_t
njt_write_chain_to_file(njt_file_t *file, njt_chain_t *cl, off_t offset,
    njt_pool_t *pool)
{
    ssize_t        total, n;
    njt_iovec_t    vec;
    struct iovec   iovs[NJT_IOVS_PREALLOCATE];

    /* use pwrite() if there is the only buf in a chain */

    if (cl->next == NULL) {
        return njt_write_file(file, cl->buf->pos,
                              (size_t) (cl->buf->last - cl->buf->pos),
                              offset);
    }

    total = 0;

    vec.iovs = iovs;
    vec.nalloc = NJT_IOVS_PREALLOCATE;

    do {
        /* create the iovec and coalesce the neighbouring bufs */
        cl = njt_chain_to_iovec(&vec, cl);

        /* use pwrite() if there is the only iovec buffer */

        if (vec.count == 1) {
            n = njt_write_file(file, (u_char *) iovs[0].iov_base,
                               iovs[0].iov_len, offset);

            if (n == NJT_ERROR) {
                return n;
            }

            return total + n;
        }

        n = njt_writev_file(file, &vec, offset);

        if (n == NJT_ERROR) {
            return n;
        }

        offset += n;
        total += n;

    } while (cl);

    return total;
}


static njt_chain_t *
njt_chain_to_iovec(njt_iovec_t *vec, njt_chain_t *cl)
{
    size_t         total, size;
    u_char        *prev;
    njt_uint_t     n;
    struct iovec  *iov;

    iov = NULL;
    prev = NULL;
    total = 0;
    n = 0;

    for ( /* void */ ; cl; cl = cl->next) {

        if (njt_buf_special(cl->buf)) {
            continue;
        }

        size = cl->buf->last - cl->buf->pos;

        if (prev == cl->buf->pos && iov != NULL) {
            iov->iov_len += size;

        } else {
            if (n == vec->nalloc) {
                break;
            }

            iov = &vec->iovs[n++];

            iov->iov_base = (void *) cl->buf->pos;
            iov->iov_len = size;
        }

        prev = cl->buf->pos + size;
        total += size;
    }

    vec->count = n;
    vec->size = total;

    return cl;
}


static ssize_t
njt_writev_file(njt_file_t *file, njt_iovec_t *vec, off_t offset)
{
    ssize_t    n;
    njt_err_t  err;

    njt_log_debug3(NJT_LOG_DEBUG_CORE, file->log, 0,
                   "writev: %d, %uz, %O", file->fd, vec->size, offset);

#if (NJT_HAVE_PWRITEV)

eintr:

    n = pwritev(file->fd, vec->iovs, vec->count, offset);

    if (n == -1) {
        err = njt_errno;

        if (err == NJT_EINTR) {
            njt_log_debug0(NJT_LOG_DEBUG_CORE, file->log, err,
                           "pwritev() was interrupted");
            goto eintr;
        }

        njt_log_error(NJT_LOG_CRIT, file->log, err,
                      "pwritev() \"%s\" failed", file->name.data);
        return NJT_ERROR;
    }

    if ((size_t) n != vec->size) {
        njt_log_error(NJT_LOG_CRIT, file->log, 0,
                      "pwritev() \"%s\" has written only %z of %uz",
                      file->name.data, n, vec->size);
        return NJT_ERROR;
    }

#else

    if (file->sys_offset != offset) {
        if (lseek(file->fd, offset, SEEK_SET) == -1) {
            njt_log_error(NJT_LOG_CRIT, file->log, njt_errno,
                          "lseek() \"%s\" failed", file->name.data);
            return NJT_ERROR;
        }

        file->sys_offset = offset;
    }

eintr:

    n = writev(file->fd, vec->iovs, vec->count);

    if (n == -1) {
        err = njt_errno;

        if (err == NJT_EINTR) {
            njt_log_debug0(NJT_LOG_DEBUG_CORE, file->log, err,
                           "writev() was interrupted");
            goto eintr;
        }

        njt_log_error(NJT_LOG_CRIT, file->log, err,
                      "writev() \"%s\" failed", file->name.data);
        return NJT_ERROR;
    }

    if ((size_t) n != vec->size) {
        njt_log_error(NJT_LOG_CRIT, file->log, 0,
                      "writev() \"%s\" has written only %z of %uz",
                      file->name.data, n, vec->size);
        return NJT_ERROR;
    }

    file->sys_offset += n;

#endif

    file->offset += n;

    return n;
}


#if (NJT_THREADS)

ssize_t
njt_thread_write_chain_to_file(njt_file_t *file, njt_chain_t *cl, off_t offset,
    njt_pool_t *pool)
{
    njt_thread_task_t      *task;
    njt_thread_file_ctx_t  *ctx;

    njt_log_debug3(NJT_LOG_DEBUG_CORE, file->log, 0,
                   "thread write chain: %d, %p, %O",
                   file->fd, cl, offset);

    task = file->thread_task;

    if (task == NULL) {
        task = njt_thread_task_alloc(pool,
                                     sizeof(njt_thread_file_ctx_t));
        if (task == NULL) {
            return NJT_ERROR;
        }

        file->thread_task = task;
    }

    ctx = task->ctx;

    if (task->event.complete) {
        task->event.complete = 0;

        if (!ctx->write) {
            njt_log_error(NJT_LOG_ALERT, file->log, 0,
                          "invalid thread call, write instead of read");
            return NJT_ERROR;
        }

        if (ctx->err || ctx->nbytes == 0) {
            njt_log_error(NJT_LOG_CRIT, file->log, ctx->err,
                          "pwritev() \"%s\" failed", file->name.data);
            return NJT_ERROR;
        }

        file->offset += ctx->nbytes;
        return ctx->nbytes;
    }

    task->handler = njt_thread_write_chain_to_file_handler;

    ctx->write = 1;

    ctx->fd = file->fd;
    ctx->chain = cl;
    ctx->offset = offset;

    if (file->thread_handler(task, file) != NJT_OK) {
        return NJT_ERROR;
    }

    return NJT_AGAIN;
}


static void
njt_thread_write_chain_to_file_handler(void *data, njt_log_t *log)
{
    njt_thread_file_ctx_t *ctx = data;

#if (NJT_HAVE_PWRITEV)

    off_t          offset;
    ssize_t        n;
    njt_err_t      err;
    njt_chain_t   *cl;
    njt_iovec_t    vec;
    struct iovec   iovs[NJT_IOVS_PREALLOCATE];

    vec.iovs = iovs;
    vec.nalloc = NJT_IOVS_PREALLOCATE;

    cl = ctx->chain;
    offset = ctx->offset;

    ctx->nbytes = 0;
    ctx->err = 0;

    do {
        /* create the iovec and coalesce the neighbouring bufs */
        cl = njt_chain_to_iovec(&vec, cl);

eintr:

        n = pwritev(ctx->fd, iovs, vec.count, offset);

        if (n == -1) {
            err = njt_errno;

            if (err == NJT_EINTR) {
                njt_log_debug0(NJT_LOG_DEBUG_CORE, log, err,
                               "pwritev() was interrupted");
                goto eintr;
            }

            ctx->err = err;
            return;
        }

        if ((size_t) n != vec.size) {
            ctx->nbytes = 0;
            return;
        }

        ctx->nbytes += n;
        offset += n;
    } while (cl);

#else

    ctx->err = NJT_ENOSYS;
    return;

#endif
}

#endif /* NJT_THREADS */


njt_int_t
njt_set_file_time(u_char *name, njt_fd_t fd, time_t s)
{
    struct timeval  tv[2];

    tv[0].tv_sec = njt_time();
    tv[0].tv_usec = 0;
    tv[1].tv_sec = s;
    tv[1].tv_usec = 0;

    if (utimes((char *) name, tv) != -1) {
        return NJT_OK;
    }

    return NJT_ERROR;
}


njt_int_t
njt_create_file_mapping(njt_file_mapping_t *fm)
{
    fm->fd = njt_open_file(fm->name, NJT_FILE_RDWR, NJT_FILE_TRUNCATE,
                           NJT_FILE_DEFAULT_ACCESS);

    if (fm->fd == NJT_INVALID_FILE) {
        njt_log_error(NJT_LOG_CRIT, fm->log, njt_errno,
                      njt_open_file_n " \"%s\" failed", fm->name);
        return NJT_ERROR;
    }

    if (ftruncate(fm->fd, fm->size) == -1) {
        njt_log_error(NJT_LOG_CRIT, fm->log, njt_errno,
                      "ftruncate() \"%s\" failed", fm->name);
        goto failed;
    }

    fm->addr = mmap(NULL, fm->size, PROT_READ|PROT_WRITE, MAP_SHARED,
                    fm->fd, 0);
    if (fm->addr != MAP_FAILED) {
        return NJT_OK;
    }

    njt_log_error(NJT_LOG_CRIT, fm->log, njt_errno,
                  "mmap(%uz) \"%s\" failed", fm->size, fm->name);

failed:

    if (njt_close_file(fm->fd) == NJT_FILE_ERROR) {
        njt_log_error(NJT_LOG_ALERT, fm->log, njt_errno,
                      njt_close_file_n " \"%s\" failed", fm->name);
    }

    return NJT_ERROR;
}


void
njt_close_file_mapping(njt_file_mapping_t *fm)
{
    if (munmap(fm->addr, fm->size) == -1) {
        njt_log_error(NJT_LOG_CRIT, fm->log, njt_errno,
                      "munmap(%uz) \"%s\" failed", fm->size, fm->name);
    }

    if (njt_close_file(fm->fd) == NJT_FILE_ERROR) {
        njt_log_error(NJT_LOG_ALERT, fm->log, njt_errno,
                      njt_close_file_n " \"%s\" failed", fm->name);
    }
}


njt_int_t
njt_open_dir(njt_str_t *name, njt_dir_t *dir)
{
    dir->dir = opendir((const char *) name->data);

    if (dir->dir == NULL) {
        return NJT_ERROR;
    }

    dir->valid_info = 0;

    return NJT_OK;
}


njt_int_t
njt_read_dir(njt_dir_t *dir)
{
    dir->de = readdir(dir->dir);

    if (dir->de) {
#if (NJT_HAVE_D_TYPE)
        dir->type = dir->de->d_type;
#else
        dir->type = 0;
#endif
        return NJT_OK;
    }

    return NJT_ERROR;
}


njt_int_t
njt_open_glob(njt_glob_t *gl)
{
    int  n;

    n = glob((char *) gl->pattern, 0, NULL, &gl->pglob);

    if (n == 0) {
        return NJT_OK;
    }

#ifdef GLOB_NOMATCH

    if (n == GLOB_NOMATCH && gl->test) {
        return NJT_OK;
    }

#endif

    return NJT_ERROR;
}


njt_int_t
njt_read_glob(njt_glob_t *gl, njt_str_t *name)
{
    size_t  count;

#ifdef GLOB_NOMATCH
    count = (size_t) gl->pglob.gl_pathc;
#else
    count = (size_t) gl->pglob.gl_matchc;
#endif

    if (gl->n < count) {

        name->len = (size_t) njt_strlen(gl->pglob.gl_pathv[gl->n]);
        name->data = (u_char *) gl->pglob.gl_pathv[gl->n];
        gl->n++;

        return NJT_OK;
    }

    return NJT_DONE;
}


void
njt_close_glob(njt_glob_t *gl)
{
    globfree(&gl->pglob);
}


njt_err_t
njt_trylock_fd(njt_fd_t fd)
{
    struct flock  fl;

    njt_memzero(&fl, sizeof(struct flock));
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;

    if (fcntl(fd, F_SETLK, &fl) == -1) {
        return njt_errno;
    }

    return 0;
}


njt_err_t
njt_lock_fd(njt_fd_t fd)
{
    struct flock  fl;

    njt_memzero(&fl, sizeof(struct flock));
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;

    if (fcntl(fd, F_SETLKW, &fl) == -1) {
        return njt_errno;
    }

    return 0;
}


njt_err_t
njt_unlock_fd(njt_fd_t fd)
{
    struct flock  fl;

    njt_memzero(&fl, sizeof(struct flock));
    fl.l_type = F_UNLCK;
    fl.l_whence = SEEK_SET;

    if (fcntl(fd, F_SETLK, &fl) == -1) {
        return  njt_errno;
    }

    return 0;
}


#if (NJT_HAVE_POSIX_FADVISE) && !(NJT_HAVE_F_READAHEAD)

njt_int_t
njt_read_ahead(njt_fd_t fd, size_t n)
{
    int  err;

    err = posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);

    if (err == 0) {
        return 0;
    }

    njt_set_errno(err);
    return NJT_FILE_ERROR;
}

#endif


#if (NJT_HAVE_O_DIRECT)

njt_int_t
njt_directio_on(njt_fd_t fd)
{
    int  flags;

    flags = fcntl(fd, F_GETFL);

    if (flags == -1) {
        return NJT_FILE_ERROR;
    }

    return fcntl(fd, F_SETFL, flags | O_DIRECT);
}


njt_int_t
njt_directio_off(njt_fd_t fd)
{
    int  flags;

    flags = fcntl(fd, F_GETFL);

    if (flags == -1) {
        return NJT_FILE_ERROR;
    }

    return fcntl(fd, F_SETFL, flags & ~O_DIRECT);
}

#endif


#if (NJT_HAVE_STATFS)

size_t
njt_fs_bsize(u_char *name)
{
    struct statfs  fs;

    if (statfs((char *) name, &fs) == -1) {
        return 512;
    }

    if ((fs.f_bsize % 512) != 0) {
        return 512;
    }

#if (NJT_LINUX)
    if ((size_t) fs.f_bsize > njt_pagesize) {
        return 512;
    }
#endif

    return (size_t) fs.f_bsize;
}


off_t
njt_fs_available(u_char *name)
{
    struct statfs  fs;

    if (statfs((char *) name, &fs) == -1) {
        return NJT_MAX_OFF_T_VALUE;
    }

    return (off_t) fs.f_bavail * fs.f_bsize;
}

#elif (NJT_HAVE_STATVFS)

size_t
njt_fs_bsize(u_char *name)
{
    struct statvfs  fs;

    if (statvfs((char *) name, &fs) == -1) {
        return 512;
    }

    if ((fs.f_frsize % 512) != 0) {
        return 512;
    }

#if (NJT_LINUX)
    if ((size_t) fs.f_frsize > njt_pagesize) {
        return 512;
    }
#endif

    return (size_t) fs.f_frsize;
}


off_t
njt_fs_available(u_char *name)
{
    struct statvfs  fs;

    if (statvfs((char *) name, &fs) == -1) {
        return NJT_MAX_OFF_T_VALUE;
    }

    return (off_t) fs.f_bavail * fs.f_frsize;
}

#else

size_t
njt_fs_bsize(u_char *name)
{
    return 512;
}


off_t
njt_fs_available(u_char *name)
{
    return NJT_MAX_OFF_T_VALUE;
}

#endif
