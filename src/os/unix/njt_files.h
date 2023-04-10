
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_FILES_H_INCLUDED_
#define _NJT_FILES_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


typedef int                      njt_fd_t;
typedef struct stat              njt_file_info_t;
typedef ino_t                    njt_file_uniq_t;


typedef struct {
    u_char                      *name;
    size_t                       size;
    void                        *addr;
    njt_fd_t                     fd;
    njt_log_t                   *log;
} njt_file_mapping_t;


typedef struct {
    DIR                         *dir;
    struct dirent               *de;
    struct stat                  info;

    unsigned                     type:8;
    unsigned                     valid_info:1;
} njt_dir_t;


typedef struct {
    size_t                       n;
    glob_t                       pglob;
    u_char                      *pattern;
    njt_log_t                   *log;
    njt_uint_t                   test;
} njt_glob_t;


#define NJT_INVALID_FILE         -1
#define NJT_FILE_ERROR           -1



#ifdef __CYGWIN__

#ifndef NJT_HAVE_CASELESS_FILESYSTEM
#define NJT_HAVE_CASELESS_FILESYSTEM  1
#endif

#define njt_open_file(name, mode, create, access)                            \
    open((const char *) name, mode|create|O_BINARY, access)

#else

#define njt_open_file(name, mode, create, access)                            \
    open((const char *) name, mode|create, access)

#endif

#define njt_open_file_n          "open()"

#define NJT_FILE_RDONLY          O_RDONLY
#define NJT_FILE_WRONLY          O_WRONLY
#define NJT_FILE_RDWR            O_RDWR
#define NJT_FILE_CREATE_OR_OPEN  O_CREAT
#define NJT_FILE_OPEN            0
#define NJT_FILE_TRUNCATE        (O_CREAT|O_TRUNC)
#define NJT_FILE_APPEND          (O_WRONLY|O_APPEND)
#define NJT_FILE_NONBLOCK        O_NONBLOCK

#if (NJT_HAVE_OPENAT)
#define NJT_FILE_NOFOLLOW        O_NOFOLLOW

#if defined(O_DIRECTORY)
#define NJT_FILE_DIRECTORY       O_DIRECTORY
#else
#define NJT_FILE_DIRECTORY       0
#endif

#if defined(O_SEARCH)
#define NJT_FILE_SEARCH          (O_SEARCH|NJT_FILE_DIRECTORY)

#elif defined(O_EXEC)
#define NJT_FILE_SEARCH          (O_EXEC|NJT_FILE_DIRECTORY)

#elif (NJT_HAVE_O_PATH)
#define NJT_FILE_SEARCH          (O_PATH|O_RDONLY|NJT_FILE_DIRECTORY)

#else
#define NJT_FILE_SEARCH          (O_RDONLY|NJT_FILE_DIRECTORY)
#endif

#endif /* NJT_HAVE_OPENAT */

#define NJT_FILE_DEFAULT_ACCESS  0644
#define NJT_FILE_OWNER_ACCESS    0600


#define njt_close_file           close
#define njt_close_file_n         "close()"


#define njt_delete_file(name)    unlink((const char *) name)
#define njt_delete_file_n        "unlink()"


njt_fd_t njt_open_tempfile(u_char *name, njt_uint_t persistent,
    njt_uint_t access);
#define njt_open_tempfile_n      "open()"


ssize_t njt_read_file(njt_file_t *file, u_char *buf, size_t size, off_t offset);
#if (NJT_HAVE_PREAD)
#define njt_read_file_n          "pread()"
#else
#define njt_read_file_n          "read()"
#endif

ssize_t njt_write_file(njt_file_t *file, u_char *buf, size_t size,
    off_t offset);

ssize_t njt_write_chain_to_file(njt_file_t *file, njt_chain_t *ce,
    off_t offset, njt_pool_t *pool);


#define njt_read_fd              read
#define njt_read_fd_n            "read()"

/*
 * we use inlined function instead of simple #define
 * because glibc 2.3 sets warn_unused_result attribute for write()
 * and in this case gcc 4.3 ignores (void) cast
 */
static njt_inline ssize_t
njt_write_fd(njt_fd_t fd, void *buf, size_t n)
{
    return write(fd, buf, n);
}

#define njt_write_fd_n           "write()"


#define njt_write_console        njt_write_fd


#define njt_linefeed(p)          *p++ = LF;
#define NJT_LINEFEED_SIZE        1
#define NJT_LINEFEED             "\x0a"


#define njt_rename_file(o, n)    rename((const char *) o, (const char *) n)
#define njt_rename_file_n        "rename()"


#define njt_change_file_access(n, a) chmod((const char *) n, a)
#define njt_change_file_access_n "chmod()"


njt_int_t njt_set_file_time(u_char *name, njt_fd_t fd, time_t s);
#define njt_set_file_time_n      "utimes()"


#define njt_file_info(file, sb)  stat((const char *) file, sb)
#define njt_file_info_n          "stat()"

#define njt_fd_info(fd, sb)      fstat(fd, sb)
#define njt_fd_info_n            "fstat()"

#define njt_link_info(file, sb)  lstat((const char *) file, sb)
#define njt_link_info_n          "lstat()"

#define njt_is_dir(sb)           (S_ISDIR((sb)->st_mode))
#define njt_is_file(sb)          (S_ISREG((sb)->st_mode))
#define njt_is_link(sb)          (S_ISLNK((sb)->st_mode))
#define njt_is_exec(sb)          (((sb)->st_mode & S_IXUSR) == S_IXUSR)
#define njt_file_access(sb)      ((sb)->st_mode & 0777)
#define njt_file_size(sb)        (sb)->st_size
#define njt_file_fs_size(sb)                                                 \
    (((sb)->st_blocks * 512 > (sb)->st_size                                  \
     && (sb)->st_blocks * 512 < (sb)->st_size + 8 * (sb)->st_blksize)        \
     ? (sb)->st_blocks * 512 : (sb)->st_size)
#define njt_file_mtime(sb)       (sb)->st_mtime
#define njt_file_uniq(sb)        (sb)->st_ino


njt_int_t njt_create_file_mapping(njt_file_mapping_t *fm);
void njt_close_file_mapping(njt_file_mapping_t *fm);


#define njt_realpath(p, r)       (u_char *) realpath((char *) p, (char *) r)
#define njt_realpath_n           "realpath()"
#define njt_getcwd(buf, size)    (getcwd((char *) buf, size) != NULL)
#define njt_getcwd_n             "getcwd()"
#define njt_path_separator(c)    ((c) == '/')


#if defined(PATH_MAX)

#define NJT_HAVE_MAX_PATH        1
#define NJT_MAX_PATH             PATH_MAX

#else

#define NJT_MAX_PATH             4096

#endif


njt_int_t njt_open_dir(njt_str_t *name, njt_dir_t *dir);
#define njt_open_dir_n           "opendir()"


#define njt_close_dir(d)         closedir((d)->dir)
#define njt_close_dir_n          "closedir()"


njt_int_t njt_read_dir(njt_dir_t *dir);
#define njt_read_dir_n           "readdir()"


#define njt_create_dir(name, access) mkdir((const char *) name, access)
#define njt_create_dir_n         "mkdir()"


#define njt_delete_dir(name)     rmdir((const char *) name)
#define njt_delete_dir_n         "rmdir()"


#define njt_dir_access(a)        (a | (a & 0444) >> 2)


#define njt_de_name(dir)         ((u_char *) (dir)->de->d_name)
#if (NJT_HAVE_D_NAMLEN)
#define njt_de_namelen(dir)      (dir)->de->d_namlen
#else
#define njt_de_namelen(dir)      njt_strlen((dir)->de->d_name)
#endif

static njt_inline njt_int_t
njt_de_info(u_char *name, njt_dir_t *dir)
{
    dir->type = 0;
    return stat((const char *) name, &dir->info);
}

#define njt_de_info_n            "stat()"
#define njt_de_link_info(name, dir)  lstat((const char *) name, &(dir)->info)
#define njt_de_link_info_n       "lstat()"

#if (NJT_HAVE_D_TYPE)

/*
 * some file systems (e.g. XFS on Linux and CD9660 on FreeBSD)
 * do not set dirent.d_type
 */

#define njt_de_is_dir(dir)                                                   \
    (((dir)->type) ? ((dir)->type == DT_DIR) : (S_ISDIR((dir)->info.st_mode)))
#define njt_de_is_file(dir)                                                  \
    (((dir)->type) ? ((dir)->type == DT_REG) : (S_ISREG((dir)->info.st_mode)))
#define njt_de_is_link(dir)                                                  \
    (((dir)->type) ? ((dir)->type == DT_LNK) : (S_ISLNK((dir)->info.st_mode)))

#else

#define njt_de_is_dir(dir)       (S_ISDIR((dir)->info.st_mode))
#define njt_de_is_file(dir)      (S_ISREG((dir)->info.st_mode))
#define njt_de_is_link(dir)      (S_ISLNK((dir)->info.st_mode))

#endif

#define njt_de_access(dir)       (((dir)->info.st_mode) & 0777)
#define njt_de_size(dir)         (dir)->info.st_size
#define njt_de_fs_size(dir)                                                  \
    njt_max((dir)->info.st_size, (dir)->info.st_blocks * 512)
#define njt_de_mtime(dir)        (dir)->info.st_mtime


njt_int_t njt_open_glob(njt_glob_t *gl);
#define njt_open_glob_n          "glob()"
njt_int_t njt_read_glob(njt_glob_t *gl, njt_str_t *name);
void njt_close_glob(njt_glob_t *gl);


njt_err_t njt_trylock_fd(njt_fd_t fd);
njt_err_t njt_lock_fd(njt_fd_t fd);
njt_err_t njt_unlock_fd(njt_fd_t fd);

#define njt_trylock_fd_n         "fcntl(F_SETLK, F_WRLCK)"
#define njt_lock_fd_n            "fcntl(F_SETLKW, F_WRLCK)"
#define njt_unlock_fd_n          "fcntl(F_SETLK, F_UNLCK)"


#if (NJT_HAVE_F_READAHEAD)

#define NJT_HAVE_READ_AHEAD      1

#define njt_read_ahead(fd, n)    fcntl(fd, F_READAHEAD, (int) n)
#define njt_read_ahead_n         "fcntl(fd, F_READAHEAD)"

#elif (NJT_HAVE_POSIX_FADVISE)

#define NJT_HAVE_READ_AHEAD      1

njt_int_t njt_read_ahead(njt_fd_t fd, size_t n);
#define njt_read_ahead_n         "posix_fadvise(POSIX_FADV_SEQUENTIAL)"

#else

#define njt_read_ahead(fd, n)    0
#define njt_read_ahead_n         "njt_read_ahead_n"

#endif


#if (NJT_HAVE_O_DIRECT)

njt_int_t njt_directio_on(njt_fd_t fd);
#define njt_directio_on_n        "fcntl(O_DIRECT)"

njt_int_t njt_directio_off(njt_fd_t fd);
#define njt_directio_off_n       "fcntl(!O_DIRECT)"

#elif (NJT_HAVE_F_NOCACHE)

#define njt_directio_on(fd)      fcntl(fd, F_NOCACHE, 1)
#define njt_directio_on_n        "fcntl(F_NOCACHE, 1)"

#elif (NJT_HAVE_DIRECTIO)

#define njt_directio_on(fd)      directio(fd, DIRECTIO_ON)
#define njt_directio_on_n        "directio(DIRECTIO_ON)"

#else

#define njt_directio_on(fd)      0
#define njt_directio_on_n        "njt_directio_on_n"

#endif

size_t njt_fs_bsize(u_char *name);
off_t njt_fs_available(u_char *name);


#if (NJT_HAVE_OPENAT)

#define njt_openat_file(fd, name, mode, create, access)                      \
    openat(fd, (const char *) name, mode|create, access)

#define njt_openat_file_n        "openat()"

#define njt_file_at_info(fd, name, sb, flag)                                 \
    fstatat(fd, (const char *) name, sb, flag)

#define njt_file_at_info_n       "fstatat()"

#define NJT_AT_FDCWD             (njt_fd_t) AT_FDCWD

#endif


#define njt_stdout               STDOUT_FILENO
#define njt_stderr               STDERR_FILENO
#define njt_set_stderr(fd)       dup2(fd, STDERR_FILENO)
#define njt_set_stderr_n         "dup2(STDERR_FILENO)"


#if (NJT_HAVE_FILE_AIO)

njt_int_t njt_file_aio_init(njt_file_t *file, njt_pool_t *pool);
ssize_t njt_file_aio_read(njt_file_t *file, u_char *buf, size_t size,
    off_t offset, njt_pool_t *pool);

extern njt_uint_t  njt_file_aio;

#endif

#if (NJT_THREADS)
ssize_t njt_thread_read(njt_file_t *file, u_char *buf, size_t size,
    off_t offset, njt_pool_t *pool);
ssize_t njt_thread_write_chain_to_file(njt_file_t *file, njt_chain_t *cl,
    off_t offset, njt_pool_t *pool);
#endif


#endif /* _NJT_FILES_H_INCLUDED_ */
