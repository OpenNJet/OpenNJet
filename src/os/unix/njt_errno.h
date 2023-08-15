
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_ERRNO_H_INCLUDED_
#define _NJT_ERRNO_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


typedef int               njt_err_t;

#define NJT_EPERM         EPERM
#define NJT_ENOENT        ENOENT
#define NJT_ENOPATH       ENOENT
#define NJT_ESRCH         ESRCH
#define NJT_EINTR         EINTR
#define NJT_ECHILD        ECHILD
#define NJT_ENOMEM        ENOMEM
#define NJT_EACCES        EACCES
#define NJT_EBUSY         EBUSY
#define NJT_EEXIST        EEXIST
#define NJT_EEXIST_FILE   EEXIST
#define NJT_EXDEV         EXDEV
#define NJT_ENOTDIR       ENOTDIR
#define NJT_EISDIR        EISDIR
#define NJT_EINVAL        EINVAL
#define NJT_ENFILE        ENFILE
#define NJT_EMFILE        EMFILE
#define NJT_ENOSPC        ENOSPC
#define NJT_EPIPE         EPIPE
#define NJT_EINPROGRESS   EINPROGRESS
#define NJT_ENOPROTOOPT   ENOPROTOOPT
#define NJT_EOPNOTSUPP    EOPNOTSUPP
#define NJT_EADDRINUSE    EADDRINUSE
#define NJT_ECONNABORTED  ECONNABORTED
#define NJT_ECONNRESET    ECONNRESET
#define NJT_ENOTCONN      ENOTCONN
#define NJT_ETIMEDOUT     ETIMEDOUT
#define NJT_ECONNREFUSED  ECONNREFUSED
#define NJT_ENAMETOOLONG  ENAMETOOLONG
#define NJT_ENETDOWN      ENETDOWN
#define NJT_ENETUNREACH   ENETUNREACH
#define NJT_EHOSTDOWN     EHOSTDOWN
#define NJT_EHOSTUNREACH  EHOSTUNREACH
#define NJT_ENOSYS        ENOSYS
#define NJT_ECANCELED     ECANCELED
#define NJT_EILSEQ        EILSEQ
#define NJT_ENOMOREFILES  0
#define NJT_ELOOP         ELOOP
#define NJT_EBADF         EBADF
#define NJT_EMSGSIZE      EMSGSIZE

#if (NJT_HAVE_OPENAT)
#define NJT_EMLINK        EMLINK
#endif

#if (__hpux__)
#define NJT_EAGAIN        EWOULDBLOCK
#else
#define NJT_EAGAIN        EAGAIN
#endif


#define njt_errno                  errno
#define njt_socket_errno           errno
#define njt_set_errno(err)         errno = err
#define njt_set_socket_errno(err)  errno = err


u_char *njt_strerror(njt_err_t err, u_char *errstr, size_t size);
njt_int_t njt_strerror_init(void);


#endif /* _NJT_ERRNO_H_INCLUDED_ */
