
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NJET_ERRNO_H_INCLUDED_
#define _NJET_ERRNO_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef int               ngx_err_t;

#define NJET_EPERM         EPERM
#define NJET_ENOENT        ENOENT
#define NJET_ENOPATH       ENOENT
#define NJET_ESRCH         ESRCH
#define NJET_EINTR         EINTR
#define NJET_ECHILD        ECHILD
#define NJET_ENOMEM        ENOMEM
#define NJET_EACCES        EACCES
#define NJET_EBUSY         EBUSY
#define NJET_EEXIST        EEXIST
#define NJET_EEXIST_FILE   EEXIST
#define NJET_EXDEV         EXDEV
#define NJET_ENOTDIR       ENOTDIR
#define NJET_EISDIR        EISDIR
#define NJET_EINVAL        EINVAL
#define NJET_ENFILE        ENFILE
#define NJET_EMFILE        EMFILE
#define NJET_ENOSPC        ENOSPC
#define NJET_EPIPE         EPIPE
#define NJET_EINPROGRESS   EINPROGRESS
#define NJET_ENOPROTOOPT   ENOPROTOOPT
#define NJET_EOPNOTSUPP    EOPNOTSUPP
#define NJET_EADDRINUSE    EADDRINUSE
#define NJET_ECONNABORTED  ECONNABORTED
#define NJET_ECONNRESET    ECONNRESET
#define NJET_ENOTCONN      ENOTCONN
#define NJET_ETIMEDOUT     ETIMEDOUT
#define NJET_ECONNREFUSED  ECONNREFUSED
#define NJET_ENAMETOOLONG  ENAMETOOLONG
#define NJET_ENETDOWN      ENETDOWN
#define NJET_ENETUNREACH   ENETUNREACH
#define NJET_EHOSTDOWN     EHOSTDOWN
#define NJET_EHOSTUNREACH  EHOSTUNREACH
#define NJET_ENOSYS        ENOSYS
#define NJET_ECANCELED     ECANCELED
#define NJET_EILSEQ        EILSEQ
#define NJET_ENOMOREFILES  0
#define NJET_ELOOP         ELOOP
#define NJET_EBADF         EBADF

#if (NJET_HAVE_OPENAT)
#define NJET_EMLINK        EMLINK
#endif

#if (__hpux__)
#define NJET_EAGAIN        EWOULDBLOCK
#else
#define NJET_EAGAIN        EAGAIN
#endif


#define ngx_errno                  errno
#define ngx_socket_errno           errno
#define ngx_set_errno(err)         errno = err
#define ngx_set_socket_errno(err)  errno = err


u_char *ngx_strerror(ngx_err_t err, u_char *errstr, size_t size);
ngx_int_t ngx_strerror_init(void);


#endif /* _NJET_ERRNO_H_INCLUDED_ */
