
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) TMLake, Inc.
 */


#include <njt_config.h>
#include <njt_core.h>


#define NJT_UTF16_BUFLEN  256

static njt_int_t njt_win32_check_filename(u_char *name, u_short *u,
    size_t len);
static u_short *njt_utf8_to_utf16(u_short *utf16, u_char *utf8, size_t *len);


/* FILE_FLAG_BACKUP_SEMANTICS allows to obtain a handle to a directory */

njt_fd_t
njt_open_file(u_char *name, u_long mode, u_long create, u_long access)
{
    size_t      len;
    u_short    *u;
    njt_fd_t    fd;
    njt_err_t   err;
    u_short     utf16[NJT_UTF16_BUFLEN];

    len = NJT_UTF16_BUFLEN;
    u = njt_utf8_to_utf16(utf16, name, &len);

    if (u == NULL) {
        return INVALID_HANDLE_VALUE;
    }

    fd = INVALID_HANDLE_VALUE;

    if (create == NJT_FILE_OPEN
        && njt_win32_check_filename(name, u, len) != NJT_OK)
    {
        goto failed;
    }

    fd = CreateFileW(u, mode,
                     FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                     NULL, create, FILE_FLAG_BACKUP_SEMANTICS, NULL);

failed:

    if (u != utf16) {
        err = njt_errno;
        njt_free(u);
        njt_set_errno(err);
    }

    return fd;
}


ssize_t
njt_read_file(njt_file_t *file, u_char *buf, size_t size, off_t offset)
{
    u_long      n;
    njt_err_t   err;
    OVERLAPPED  ovlp, *povlp;

    ovlp.Internal = 0;
    ovlp.InternalHigh = 0;
    ovlp.Offset = (u_long) offset;
    ovlp.OffsetHigh = (u_long) (offset >> 32);
    ovlp.hEvent = NULL;

    povlp = &ovlp;

    if (ReadFile(file->fd, buf, size, &n, povlp) == 0) {
        err = njt_errno;

        if (err == ERROR_HANDLE_EOF) {
            return 0;
        }

        njt_log_error(NJT_LOG_ERR, file->log, err,
                      "ReadFile() \"%s\" failed", file->name.data);
        return NJT_ERROR;
    }

    file->offset += n;

    return n;
}


ssize_t
njt_write_file(njt_file_t *file, u_char *buf, size_t size, off_t offset)
{
    u_long      n;
    OVERLAPPED  ovlp, *povlp;

    ovlp.Internal = 0;
    ovlp.InternalHigh = 0;
    ovlp.Offset = (u_long) offset;
    ovlp.OffsetHigh = (u_long) (offset >> 32);
    ovlp.hEvent = NULL;

    povlp = &ovlp;

    if (WriteFile(file->fd, buf, size, &n, povlp) == 0) {
        njt_log_error(NJT_LOG_ERR, file->log, njt_errno,
                      "WriteFile() \"%s\" failed", file->name.data);
        return NJT_ERROR;
    }

    if (n != size) {
        njt_log_error(NJT_LOG_CRIT, file->log, 0,
                      "WriteFile() \"%s\" has written only %ul of %uz",
                      file->name.data, n, size);
        return NJT_ERROR;
    }

    file->offset += n;

    return n;
}


ssize_t
njt_write_chain_to_file(njt_file_t *file, njt_chain_t *cl, off_t offset,
    njt_pool_t *pool)
{
    u_char   *buf, *prev;
    size_t    size;
    ssize_t   total, n;

    total = 0;

    while (cl) {
        buf = cl->buf->pos;
        prev = buf;
        size = 0;

        /* coalesce the neighbouring bufs */

        while (cl && prev == cl->buf->pos) {
            size += cl->buf->last - cl->buf->pos;
            prev = cl->buf->last;
            cl = cl->next;
        }

        n = njt_write_file(file, buf, size, offset);

        if (n == NJT_ERROR) {
            return NJT_ERROR;
        }

        total += n;
        offset += n;
    }

    return total;
}


ssize_t
njt_read_fd(njt_fd_t fd, void *buf, size_t size)
{
    u_long  n;

    if (ReadFile(fd, buf, size, &n, NULL) != 0) {
        return (size_t) n;
    }

    return -1;
}


ssize_t
njt_write_fd(njt_fd_t fd, void *buf, size_t size)
{
    u_long  n;

    if (WriteFile(fd, buf, size, &n, NULL) != 0) {
        return (size_t) n;
    }

    return -1;
}


ssize_t
njt_write_console(njt_fd_t fd, void *buf, size_t size)
{
    u_long  n;

    (void) CharToOemBuff(buf, buf, size);

    if (WriteFile(fd, buf, size, &n, NULL) != 0) {
        return (size_t) n;
    }

    return -1;
}


njt_err_t
njt_win32_rename_file(njt_str_t *from, njt_str_t *to, njt_log_t *log)
{
    u_char             *name;
    njt_err_t           err;
    njt_uint_t          collision;
    njt_atomic_uint_t   num;

    name = njt_alloc(to->len + 1 + NJT_ATOMIC_T_LEN + 1 + sizeof("DELETE"),
                     log);
    if (name == NULL) {
        return NJT_ENOMEM;
    }

    njt_memcpy(name, to->data, to->len);

    collision = 0;

    /* mutex_lock() (per cache or single ?) */

    for ( ;; ) {
        num = njt_next_temp_number(collision);

        njt_sprintf(name + to->len, ".%0muA.DELETE%Z", num);

        if (MoveFile((const char *) to->data, (const char *) name) != 0) {
            break;
        }

        collision = 1;

        njt_log_error(NJT_LOG_CRIT, log, njt_errno,
                      "MoveFile() \"%s\" to \"%s\" failed", to->data, name);
    }

    if (MoveFile((const char *) from->data, (const char *) to->data) == 0) {
        err = njt_errno;

    } else {
        err = 0;
    }

    if (DeleteFile((const char *) name) == 0) {
        njt_log_error(NJT_LOG_CRIT, log, njt_errno,
                      "DeleteFile() \"%s\" failed", name);
    }

    /* mutex_unlock() */

    njt_free(name);

    return err;
}


njt_int_t
njt_file_info(u_char *file, njt_file_info_t *sb)
{
    size_t                      len;
    long                        rc;
    u_short                    *u;
    njt_err_t                   err;
    WIN32_FILE_ATTRIBUTE_DATA   fa;
    u_short                     utf16[NJT_UTF16_BUFLEN];

    len = NJT_UTF16_BUFLEN;

    u = njt_utf8_to_utf16(utf16, file, &len);

    if (u == NULL) {
        return NJT_FILE_ERROR;
    }

    rc = NJT_FILE_ERROR;

    if (njt_win32_check_filename(file, u, len) != NJT_OK) {
        goto failed;
    }

    rc = GetFileAttributesExW(u, GetFileExInfoStandard, &fa);

    sb->dwFileAttributes = fa.dwFileAttributes;
    sb->ftCreationTime = fa.ftCreationTime;
    sb->ftLastAccessTime = fa.ftLastAccessTime;
    sb->ftLastWriteTime = fa.ftLastWriteTime;
    sb->nFileSizeHigh = fa.nFileSizeHigh;
    sb->nFileSizeLow = fa.nFileSizeLow;

failed:

    if (u != utf16) {
        err = njt_errno;
        njt_free(u);
        njt_set_errno(err);
    }

    return rc;
}


njt_int_t
njt_set_file_time(u_char *name, njt_fd_t fd, time_t s)
{
    uint64_t  intervals;
    FILETIME  ft;

    /* 116444736000000000 is commented in src/os/win32/njt_time.c */

    intervals = s * 10000000 + 116444736000000000;

    ft.dwLowDateTime = (DWORD) intervals;
    ft.dwHighDateTime = (DWORD) (intervals >> 32);

    if (SetFileTime(fd, NULL, NULL, &ft) != 0) {
        return NJT_OK;
    }

    return NJT_ERROR;
}


njt_int_t
njt_create_file_mapping(njt_file_mapping_t *fm)
{
    LARGE_INTEGER  size;

    fm->fd = njt_open_file(fm->name, NJT_FILE_RDWR, NJT_FILE_TRUNCATE,
                           NJT_FILE_DEFAULT_ACCESS);

    if (fm->fd == NJT_INVALID_FILE) {
        njt_log_error(NJT_LOG_CRIT, fm->log, njt_errno,
                      njt_open_file_n " \"%s\" failed", fm->name);
        return NJT_ERROR;
    }

    fm->handle = NULL;

    size.QuadPart = fm->size;

    if (SetFilePointerEx(fm->fd, size, NULL, FILE_BEGIN) == 0) {
        njt_log_error(NJT_LOG_CRIT, fm->log, njt_errno,
                      "SetFilePointerEx(\"%s\", %uz) failed",
                      fm->name, fm->size);
        goto failed;
    }

    if (SetEndOfFile(fm->fd) == 0) {
        njt_log_error(NJT_LOG_CRIT, fm->log, njt_errno,
                      "SetEndOfFile() \"%s\" failed", fm->name);
        goto failed;
    }

    fm->handle = CreateFileMapping(fm->fd, NULL, PAGE_READWRITE,
                                   (u_long) ((off_t) fm->size >> 32),
                                   (u_long) ((off_t) fm->size & 0xffffffff),
                                   NULL);
    if (fm->handle == NULL) {
        njt_log_error(NJT_LOG_CRIT, fm->log, njt_errno,
                      "CreateFileMapping(%s, %uz) failed",
                      fm->name, fm->size);
        goto failed;
    }

    fm->addr = MapViewOfFile(fm->handle, FILE_MAP_WRITE, 0, 0, 0);

    if (fm->addr != NULL) {
        return NJT_OK;
    }

    njt_log_error(NJT_LOG_CRIT, fm->log, njt_errno,
                  "MapViewOfFile(%uz) of file mapping \"%s\" failed",
                  fm->size, fm->name);

failed:

    if (fm->handle) {
        if (CloseHandle(fm->handle) == 0) {
            njt_log_error(NJT_LOG_ALERT, fm->log, njt_errno,
                          "CloseHandle() of file mapping \"%s\" failed",
                          fm->name);
        }
    }

    if (njt_close_file(fm->fd) == NJT_FILE_ERROR) {
        njt_log_error(NJT_LOG_ALERT, fm->log, njt_errno,
                      njt_close_file_n " \"%s\" failed", fm->name);
    }

    return NJT_ERROR;
}


void
njt_close_file_mapping(njt_file_mapping_t *fm)
{
    if (UnmapViewOfFile(fm->addr) == 0) {
        njt_log_error(NJT_LOG_ALERT, fm->log, njt_errno,
                      "UnmapViewOfFile(%p) of file mapping \"%s\" failed",
                      fm->addr, &fm->name);
    }

    if (CloseHandle(fm->handle) == 0) {
        njt_log_error(NJT_LOG_ALERT, fm->log, njt_errno,
                      "CloseHandle() of file mapping \"%s\" failed",
                      &fm->name);
    }

    if (njt_close_file(fm->fd) == NJT_FILE_ERROR) {
        njt_log_error(NJT_LOG_ALERT, fm->log, njt_errno,
                      njt_close_file_n " \"%s\" failed", fm->name);
    }
}


u_char *
njt_realpath(u_char *path, u_char *resolved)
{
    /* STUB */
    return path;
}


njt_int_t
njt_open_dir(njt_str_t *name, njt_dir_t *dir)
{
    u_char     *pattern, *p;
    njt_err_t   err;

    pattern = malloc(name->len + 3);
    if (pattern == NULL) {
        return NJT_ERROR;
    }

    p = njt_cpymem(pattern, name->data, name->len);

    *p++ = '/';
    *p++ = '*';
    *p = '\0';

    dir->dir = FindFirstFile((const char *) pattern, &dir->finddata);

    if (dir->dir == INVALID_HANDLE_VALUE) {
        err = njt_errno;
        njt_free(pattern);
        njt_set_errno(err);
        return NJT_ERROR;
    }

    njt_free(pattern);

    dir->valid_info = 1;
    dir->ready = 1;

    return NJT_OK;
}


njt_int_t
njt_read_dir(njt_dir_t *dir)
{
    if (dir->ready) {
        dir->ready = 0;
        return NJT_OK;
    }

    if (FindNextFile(dir->dir, &dir->finddata) != 0) {
        dir->type = 1;
        return NJT_OK;
    }

    return NJT_ERROR;
}


njt_int_t
njt_close_dir(njt_dir_t *dir)
{
    if (FindClose(dir->dir) == 0) {
        return NJT_ERROR;
    }

    return NJT_OK;
}


njt_int_t
njt_open_glob(njt_glob_t *gl)
{
    u_char     *p;
    size_t      len;
    njt_err_t   err;

    gl->dir = FindFirstFile((const char *) gl->pattern, &gl->finddata);

    if (gl->dir == INVALID_HANDLE_VALUE) {

        err = njt_errno;

        if ((err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)
             && gl->test)
        {
            gl->no_match = 1;
            return NJT_OK;
        }

        return NJT_ERROR;
    }

    for (p = gl->pattern; *p; p++) {
        if (*p == '/') {
            gl->last = p + 1 - gl->pattern;
        }
    }

    len = njt_strlen(gl->finddata.cFileName);
    gl->name.len = gl->last + len;

    gl->name.data = njt_alloc(gl->name.len + 1, gl->log);
    if (gl->name.data == NULL) {
        return NJT_ERROR;
    }

    njt_memcpy(gl->name.data, gl->pattern, gl->last);
    njt_cpystrn(gl->name.data + gl->last, (u_char *) gl->finddata.cFileName,
                len + 1);

    gl->ready = 1;

    return NJT_OK;
}


njt_int_t
njt_read_glob(njt_glob_t *gl, njt_str_t *name)
{
    size_t     len;
    njt_err_t  err;

    if (gl->no_match) {
        return NJT_DONE;
    }

    if (gl->ready) {
        *name = gl->name;

        gl->ready = 0;
        return NJT_OK;
    }

    njt_free(gl->name.data);
    gl->name.data = NULL;

    if (FindNextFile(gl->dir, &gl->finddata) != 0) {

        len = njt_strlen(gl->finddata.cFileName);
        gl->name.len = gl->last + len;

        gl->name.data = njt_alloc(gl->name.len + 1, gl->log);
        if (gl->name.data == NULL) {
            return NJT_ERROR;
        }

        njt_memcpy(gl->name.data, gl->pattern, gl->last);
        njt_cpystrn(gl->name.data + gl->last, (u_char *) gl->finddata.cFileName,
                    len + 1);

        *name = gl->name;

        return NJT_OK;
    }

    err = njt_errno;

    if (err == NJT_ENOMOREFILES) {
        return NJT_DONE;
    }

    njt_log_error(NJT_LOG_ALERT, gl->log, err,
                  "FindNextFile(%s) failed", gl->pattern);

    return NJT_ERROR;
}


void
njt_close_glob(njt_glob_t *gl)
{
    if (gl->name.data) {
        njt_free(gl->name.data);
    }

    if (gl->dir == INVALID_HANDLE_VALUE) {
        return;
    }

    if (FindClose(gl->dir) == 0) {
        njt_log_error(NJT_LOG_ALERT, gl->log, njt_errno,
                      "FindClose(%s) failed", gl->pattern);
    }
}


njt_int_t
njt_de_info(u_char *name, njt_dir_t *dir)
{
    return NJT_OK;
}


njt_int_t
njt_de_link_info(u_char *name, njt_dir_t *dir)
{
    return NJT_OK;
}


njt_int_t
njt_read_ahead(njt_fd_t fd, size_t n)
{
    return ~NJT_FILE_ERROR;
}


njt_int_t
njt_directio_on(njt_fd_t fd)
{
    return ~NJT_FILE_ERROR;
}


njt_int_t
njt_directio_off(njt_fd_t fd)
{
    return ~NJT_FILE_ERROR;
}


size_t
njt_fs_bsize(u_char *name)
{
    u_char  root[4];
    u_long  sc, bs, nfree, ncl;

    if (name[2] == ':') {
        njt_cpystrn(root, name, 4);
        name = root;
    }

    if (GetDiskFreeSpace((const char *) name, &sc, &bs, &nfree, &ncl) == 0) {
        return 512;
    }

    return sc * bs;
}


off_t
njt_fs_available(u_char *name)
{
    ULARGE_INTEGER  navail;

    if (GetDiskFreeSpaceEx((const char *) name, &navail, NULL, NULL) == 0) {
        return NJT_MAX_OFF_T_VALUE;
    }

    return (off_t) navail.QuadPart;
}


static njt_int_t
njt_win32_check_filename(u_char *name, u_short *u, size_t len)
{
    u_char     *p, ch;
    u_long      n;
    u_short    *lu;
    njt_err_t   err;
    enum {
        sw_start = 0,
        sw_normal,
        sw_after_slash,
        sw_after_colon,
        sw_after_dot
    } state;

    /* check for NTFS streams (":"), trailing dots and spaces */

    lu = NULL;
    state = sw_start;

    for (p = name; *p; p++) {
        ch = *p;

        switch (state) {

        case sw_start:

            /*
             * skip till first "/" to allow paths starting with drive and
             * relative path, like "c:html/"
             */

            if (ch == '/' || ch == '\\') {
                state = sw_after_slash;
            }

            break;

        case sw_normal:

            if (ch == ':') {
                state = sw_after_colon;
                break;
            }

            if (ch == '.' || ch == ' ') {
                state = sw_after_dot;
                break;
            }

            if (ch == '/' || ch == '\\') {
                state = sw_after_slash;
                break;
            }

            break;

        case sw_after_slash:

            if (ch == '/' || ch == '\\') {
                break;
            }

            if (ch == '.') {
                break;
            }

            if (ch == ':') {
                state = sw_after_colon;
                break;
            }

            state = sw_normal;
            break;

        case sw_after_colon:

            if (ch == '/' || ch == '\\') {
                state = sw_after_slash;
                break;
            }

            goto invalid;

        case sw_after_dot:

            if (ch == '/' || ch == '\\') {
                goto invalid;
            }

            if (ch == ':') {
                goto invalid;
            }

            if (ch == '.' || ch == ' ') {
                break;
            }

            state = sw_normal;
            break;
        }
    }

    if (state == sw_after_dot) {
        goto invalid;
    }

    /* check if long name match */

    lu = malloc(len * 2);
    if (lu == NULL) {
        return NJT_ERROR;
    }

    n = GetLongPathNameW(u, lu, len);

    if (n == 0) {
        goto failed;
    }

    if (n != len - 1 || _wcsicmp(u, lu) != 0) {
        goto invalid;
    }

    njt_free(lu);

    return NJT_OK;

invalid:

    njt_set_errno(NJT_ENOENT);

failed:

    if (lu) {
        err = njt_errno;
        njt_free(lu);
        njt_set_errno(err);
    }

    return NJT_ERROR;
}


static u_short *
njt_utf8_to_utf16(u_short *utf16, u_char *utf8, size_t *len)
{
    u_char    *p;
    u_short   *u, *last;
    uint32_t   n;

    p = utf8;
    u = utf16;
    last = utf16 + *len;

    while (u < last) {

        if (*p < 0x80) {
            *u++ = (u_short) *p;

            if (*p == 0) {
                *len = u - utf16;
                return utf16;
            }

            p++;

            continue;
        }

        if (u + 1 == last) {
            *len = u - utf16;
            break;
        }

        n = njt_utf8_decode(&p, 4);

        if (n > 0x10ffff) {
            njt_set_errno(NJT_EILSEQ);
            return NULL;
        }

        if (n > 0xffff) {
            n -= 0x10000;
            *u++ = (u_short) (0xd800 + (n >> 10));
            *u++ = (u_short) (0xdc00 + (n & 0x03ff));
            continue;
        }

        *u++ = (u_short) n;
    }

    /* the given buffer is not enough, allocate a new one */

    u = malloc(((p - utf8) + njt_strlen(p) + 1) * sizeof(u_short));
    if (u == NULL) {
        return NULL;
    }

    njt_memcpy(u, utf16, *len * 2);

    utf16 = u;
    u += *len;

    for ( ;; ) {

        if (*p < 0x80) {
            *u++ = (u_short) *p;

            if (*p == 0) {
                *len = u - utf16;
                return utf16;
            }

            p++;

            continue;
        }

        n = njt_utf8_decode(&p, 4);

        if (n > 0x10ffff) {
            njt_free(utf16);
            njt_set_errno(NJT_EILSEQ);
            return NULL;
        }

        if (n > 0xffff) {
            n -= 0x10000;
            *u++ = (u_short) (0xd800 + (n >> 10));
            *u++ = (u_short) (0xdc00 + (n & 0x03ff));
            continue;
        }

        *u++ = (u_short) n;
    }

    /* unreachable */
}
