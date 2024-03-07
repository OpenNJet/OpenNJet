
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_FILES_H_INCLUDED_
#define _NJT_FILES_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


typedef HANDLE                      njt_fd_t;
typedef BY_HANDLE_FILE_INFORMATION  njt_file_info_t;
typedef uint64_t                    njt_file_uniq_t;


typedef struct {
    u_char                         *name;
    size_t                          size;
    void                           *addr;
    njt_fd_t                        fd;
    HANDLE                          handle;
    njt_log_t                      *log;
} njt_file_mapping_t;


typedef struct {
    HANDLE                          dir;
    WIN32_FIND_DATAW                finddata;

    u_char                         *name;
    size_t                          namelen;
    size_t                          allocated;

    unsigned                        valid_info:1;
    unsigned                        type:1;
    unsigned                        ready:1;
} njt_dir_t;


typedef struct {
    HANDLE                          dir;
    WIN32_FIND_DATAW                finddata;

    unsigned                        ready:1;
    unsigned                        test:1;
    unsigned                        no_match:1;

    u_char                         *pattern;
    njt_str_t                       name;
    size_t                          last;
    njt_log_t                      *log;
} njt_glob_t;



/* INVALID_FILE_ATTRIBUTES is specified but not defined at least in MSVC6SP2 */
#ifndef INVALID_FILE_ATTRIBUTES
#define INVALID_FILE_ATTRIBUTES     0xffffffff
#endif

/* INVALID_SET_FILE_POINTER is not defined at least in MSVC6SP2 */
#ifndef INVALID_SET_FILE_POINTER
#define INVALID_SET_FILE_POINTER    0xffffffff
#endif


#define NJT_INVALID_FILE            INVALID_HANDLE_VALUE
#define NJT_FILE_ERROR              0


njt_fd_t njt_open_file(u_char *name, u_long mode, u_long create, u_long access);
#define njt_open_file_n             "CreateFile()"

#define NJT_FILE_RDONLY             GENERIC_READ
#define NJT_FILE_WRONLY             GENERIC_WRITE
#define NJT_FILE_RDWR               GENERIC_READ|GENERIC_WRITE
#define NJT_FILE_APPEND             FILE_APPEND_DATA|SYNCHRONIZE
#define NJT_FILE_NONBLOCK           0

#define NJT_FILE_CREATE_OR_OPEN     OPEN_ALWAYS
#define NJT_FILE_OPEN               OPEN_EXISTING
#define NJT_FILE_TRUNCATE           CREATE_ALWAYS

#define NJT_FILE_DEFAULT_ACCESS     0
#define NJT_FILE_OWNER_ACCESS       0


#define njt_open_tempfile(name, persistent, access)                          \
    CreateFile((const char *) name,                                          \
               GENERIC_READ|GENERIC_WRITE,                                   \
               FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,           \
               NULL,                                                         \
               CREATE_NEW,                                                   \
               persistent ? 0:                                               \
                   FILE_ATTRIBUTE_TEMPORARY|FILE_FLAG_DELETE_ON_CLOSE,       \
               NULL);

#define njt_open_tempfile_n         "CreateFile()"


#define njt_close_file              CloseHandle
#define njt_close_file_n            "CloseHandle()"


ssize_t njt_read_fd(njt_fd_t fd, void *buf, size_t size);
#define njt_read_fd_n               "ReadFile()"


ssize_t njt_write_fd(njt_fd_t fd, void *buf, size_t size);
#define njt_write_fd_n              "WriteFile()"


ssize_t njt_write_console(njt_fd_t fd, void *buf, size_t size);


#define njt_linefeed(p)             *p++ = CR; *p++ = LF;
#define NJT_LINEFEED_SIZE           2
#define NJT_LINEFEED                CRLF


njt_int_t njt_delete_file(u_char *name);
#define njt_delete_file_n           "DeleteFile()"


#define njt_rename_file(o, n)       MoveFile((const char *) o, (const char *) n)
#define njt_rename_file_n           "MoveFile()"
njt_err_t njt_win32_rename_file(njt_str_t *from, njt_str_t *to, njt_log_t *log);



njt_int_t njt_set_file_time(u_char *name, njt_fd_t fd, time_t s);
#define njt_set_file_time_n         "SetFileTime()"


njt_int_t njt_file_info(u_char *filename, njt_file_info_t *fi);
#define njt_file_info_n             "GetFileAttributesEx()"


#define njt_fd_info(fd, fi)         GetFileInformationByHandle(fd, fi)
#define njt_fd_info_n               "GetFileInformationByHandle()"


#define njt_link_info(name, fi)     njt_file_info(name, fi)
#define njt_link_info_n             "GetFileAttributesEx()"


#define njt_is_dir(fi)                                                       \
    (((fi)->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
#define njt_is_file(fi)                                                      \
    (((fi)->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
#define njt_is_link(fi)     0
#define njt_is_exec(fi)     0

#define njt_file_access(fi) 0

#define njt_file_size(fi)                                                    \
    (((off_t) (fi)->nFileSizeHigh << 32) | (fi)->nFileSizeLow)
#define njt_file_fs_size(fi)        njt_file_size(fi)

#define njt_file_uniq(fi)   (*(njt_file_uniq_t *) &(fi)->nFileIndexHigh)


/* 116444736000000000 is commented in src/os/win32/njt_time.c */

#define njt_file_mtime(fi)                                                   \
 (time_t) (((((unsigned __int64) (fi)->ftLastWriteTime.dwHighDateTime << 32) \
                               | (fi)->ftLastWriteTime.dwLowDateTime)        \
                                          - 116444736000000000) / 10000000)

njt_int_t njt_create_file_mapping(njt_file_mapping_t *fm);
void njt_close_file_mapping(njt_file_mapping_t *fm);


u_char *njt_realpath(u_char *path, u_char *resolved);
#define njt_realpath_n              ""


size_t ngx_getcwd(u_char *buf, size_t size);
#define njt_getcwd_n                "GetCurrentDirectory()"


#define njt_path_separator(c)       ((c) == '/' || (c) == '\\')

#define NJT_HAVE_MAX_PATH           1
#define NJT_MAX_PATH                MAX_PATH


njt_int_t njt_open_dir(njt_str_t *name, njt_dir_t *dir);
#define njt_open_dir_n              "FindFirstFile()"


njt_int_t njt_read_dir(njt_dir_t *dir);
#define njt_read_dir_n              "FindNextFile()"


njt_int_t njt_close_dir(njt_dir_t *dir);
#define njt_close_dir_n             "FindClose()"


njt_int_t ngx_create_dir(u_char *name, njt_uint_t access);
#define njt_create_dir_n            "CreateDirectory()"


njt_int_t njt_delete_dir(u_char *name);
#define njt_delete_dir_n            "RemoveDirectory()"


#define njt_dir_access(a)           (a)


#define njt_de_name(dir)            (dir)->name
#define njt_de_namelen(dir)         (dir)->namelen

njt_int_t njt_de_info(u_char *name, njt_dir_t *dir);
#define njt_de_info_n               "dummy()"

njt_int_t njt_de_link_info(u_char *name, njt_dir_t *dir);
#define njt_de_link_info_n          "dummy()"

#define njt_de_is_dir(dir)                                                   \
    (((dir)->finddata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
#define njt_de_is_file(dir)                                                  \
    (((dir)->finddata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
#define njt_de_is_link(dir)         0
#define njt_de_access(dir)          0
#define njt_de_size(dir)                                                     \
  (((off_t) (dir)->finddata.nFileSizeHigh << 32) | (dir)->finddata.nFileSizeLow)
#define njt_de_fs_size(dir)         njt_de_size(dir)

/* 116444736000000000 is commented in src/os/win32/njt_time.c */

#define njt_de_mtime(dir)                                                    \
    (time_t) (((((unsigned __int64)                                          \
                     (dir)->finddata.ftLastWriteTime.dwHighDateTime << 32)   \
                      | (dir)->finddata.ftLastWriteTime.dwLowDateTime)       \
                                          - 116444736000000000) / 10000000)


njt_int_t njt_open_glob(njt_glob_t *gl);
#define njt_open_glob_n             "FindFirstFile()"

njt_int_t njt_read_glob(njt_glob_t *gl, njt_str_t *name);
void njt_close_glob(njt_glob_t *gl);


ssize_t njt_read_file(njt_file_t *file, u_char *buf, size_t size, off_t offset);
#define njt_read_file_n             "ReadFile()"

ssize_t njt_write_file(njt_file_t *file, u_char *buf, size_t size,
    off_t offset);

ssize_t njt_write_chain_to_file(njt_file_t *file, njt_chain_t *ce,
    off_t offset, njt_pool_t *pool);

njt_int_t njt_read_ahead(njt_fd_t fd, size_t n);
#define njt_read_ahead_n            "njt_read_ahead_n"

njt_int_t njt_directio_on(njt_fd_t fd);
#define njt_directio_on_n           "njt_directio_on_n"

njt_int_t njt_directio_off(njt_fd_t fd);
#define njt_directio_off_n          "njt_directio_off_n"

size_t njt_fs_bsize(u_char *name);
off_t njt_fs_available(u_char *name);


#define njt_stdout               GetStdHandle(STD_OUTPUT_HANDLE)
#define njt_stderr               GetStdHandle(STD_ERROR_HANDLE)
#define njt_set_stderr(fd)       SetStdHandle(STD_ERROR_HANDLE, fd)
#define njt_set_stderr_n         "SetStdHandle(STD_ERROR_HANDLE)"


#endif /* _NJT_FILES_H_INCLUDED_ */
