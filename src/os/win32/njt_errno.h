
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_ERRNO_H_INCLUDED_
#define _NJT_ERRNO_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


typedef DWORD                      njt_err_t;

#define njt_errno                  GetLastError()
#define njt_set_errno(err)         SetLastError(err)
#define njt_socket_errno           WSAGetLastError()
#define njt_set_socket_errno(err)  WSASetLastError(err)

#define NJT_EPERM                  ERROR_ACCESS_DENIED
#define NJT_ENOENT                 ERROR_FILE_NOT_FOUND
#define NJT_ENOPATH                ERROR_PATH_NOT_FOUND
#define NJT_ENOMEM                 ERROR_NOT_ENOUGH_MEMORY
#define NJT_EACCES                 ERROR_ACCESS_DENIED
/*
 * there are two EEXIST error codes:
 * ERROR_FILE_EXISTS used by CreateFile(CREATE_NEW),
 * and ERROR_ALREADY_EXISTS used by CreateDirectory();
 * MoveFile() uses both
 */
#define NJT_EEXIST                 ERROR_ALREADY_EXISTS
#define NJT_EEXIST_FILE            ERROR_FILE_EXISTS
#define NJT_EXDEV                  ERROR_NOT_SAME_DEVICE
#define NJT_ENOTDIR                ERROR_PATH_NOT_FOUND
#define NJT_EISDIR                 ERROR_CANNOT_MAKE
#define NJT_ENOSPC                 ERROR_DISK_FULL
#define NJT_EPIPE                  EPIPE
#define NJT_EAGAIN                 WSAEWOULDBLOCK
#define NJT_EINPROGRESS            WSAEINPROGRESS
#define NJT_ENOPROTOOPT            WSAENOPROTOOPT
#define NJT_EOPNOTSUPP             WSAEOPNOTSUPP
#define NJT_EADDRINUSE             WSAEADDRINUSE
#define NJT_ECONNABORTED           WSAECONNABORTED
#define NJT_ECONNRESET             WSAECONNRESET
#define NJT_ENOTCONN               WSAENOTCONN
#define NJT_ETIMEDOUT              WSAETIMEDOUT
#define NJT_ECONNREFUSED           WSAECONNREFUSED
#define NJT_ENAMETOOLONG           ERROR_BAD_PATHNAME
#define NJT_ENETDOWN               WSAENETDOWN
#define NJT_ENETUNREACH            WSAENETUNREACH
#define NJT_EHOSTDOWN              WSAEHOSTDOWN
#define NJT_EHOSTUNREACH           WSAEHOSTUNREACH
#define NJT_ENOMOREFILES           ERROR_NO_MORE_FILES
#define NJT_EILSEQ                 ERROR_NO_UNICODE_TRANSLATION
#define NJT_ELOOP                  0
#define NJT_EBADF                  WSAEBADF
#define NJT_EMSGSIZE               WSAEMSGSIZE

#define NJT_EALREADY               WSAEALREADY
#define NJT_EINVAL                 WSAEINVAL
#define NJT_EMFILE                 WSAEMFILE
#define NJT_ENFILE                 WSAEMFILE


u_char *njt_strerror(njt_err_t err, u_char *errstr, size_t size);
njt_int_t njt_strerror_init(void);


#endif /* _NJT_ERRNO_H_INCLUDED_ */
