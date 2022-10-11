
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NJET_ERRNO_H_INCLUDED_
#define _NJET_ERRNO_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef DWORD                      ngx_err_t;

#define ngx_errno                  GetLastError()
#define ngx_set_errno(err)         SetLastError(err)
#define ngx_socket_errno           WSAGetLastError()
#define ngx_set_socket_errno(err)  WSASetLastError(err)

#define NJET_EPERM                  ERROR_ACCESS_DENIED
#define NJET_ENOENT                 ERROR_FILE_NOT_FOUND
#define NJET_ENOPATH                ERROR_PATH_NOT_FOUND
#define NJET_ENOMEM                 ERROR_NOT_ENOUGH_MEMORY
#define NJET_EACCES                 ERROR_ACCESS_DENIED
/*
 * there are two EEXIST error codes:
 * ERROR_FILE_EXISTS used by CreateFile(CREATE_NEW),
 * and ERROR_ALREADY_EXISTS used by CreateDirectory();
 * MoveFile() uses both
 */
#define NJET_EEXIST                 ERROR_ALREADY_EXISTS
#define NJET_EEXIST_FILE            ERROR_FILE_EXISTS
#define NJET_EXDEV                  ERROR_NOT_SAME_DEVICE
#define NJET_ENOTDIR                ERROR_PATH_NOT_FOUND
#define NJET_EISDIR                 ERROR_CANNOT_MAKE
#define NJET_ENOSPC                 ERROR_DISK_FULL
#define NJET_EPIPE                  EPIPE
#define NJET_EAGAIN                 WSAEWOULDBLOCK
#define NJET_EINPROGRESS            WSAEINPROGRESS
#define NJET_ENOPROTOOPT            WSAENOPROTOOPT
#define NJET_EOPNOTSUPP             WSAEOPNOTSUPP
#define NJET_EADDRINUSE             WSAEADDRINUSE
#define NJET_ECONNABORTED           WSAECONNABORTED
#define NJET_ECONNRESET             WSAECONNRESET
#define NJET_ENOTCONN               WSAENOTCONN
#define NJET_ETIMEDOUT              WSAETIMEDOUT
#define NJET_ECONNREFUSED           WSAECONNREFUSED
#define NJET_ENAMETOOLONG           ERROR_BAD_PATHNAME
#define NJET_ENETDOWN               WSAENETDOWN
#define NJET_ENETUNREACH            WSAENETUNREACH
#define NJET_EHOSTDOWN              WSAEHOSTDOWN
#define NJET_EHOSTUNREACH           WSAEHOSTUNREACH
#define NJET_ENOMOREFILES           ERROR_NO_MORE_FILES
#define NJET_EILSEQ                 ERROR_NO_UNICODE_TRANSLATION
#define NJET_ELOOP                  0
#define NJET_EBADF                  WSAEBADF

#define NJET_EALREADY               WSAEALREADY
#define NJET_EINVAL                 WSAEINVAL
#define NJET_EMFILE                 WSAEMFILE
#define NJET_ENFILE                 WSAEMFILE


u_char *ngx_strerror(ngx_err_t err, u_char *errstr, size_t size);
ngx_int_t ngx_strerror_init(void);


#endif /* _NJET_ERRNO_H_INCLUDED_ */
