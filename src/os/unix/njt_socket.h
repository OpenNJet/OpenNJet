
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) TMLake, Inc.
 */


#ifndef _NJT_SOCKET_H_INCLUDED_
#define _NJT_SOCKET_H_INCLUDED_


#include <njt_config.h>


#define NJT_WRITE_SHUTDOWN SHUT_WR

typedef int  njt_socket_t;

#define njt_socket          socket
#define njt_socket_n        "socket()"


#if (NJT_HAVE_FIONBIO)

int njt_nonblocking(njt_socket_t s);
int njt_blocking(njt_socket_t s);

#define njt_nonblocking_n   "ioctl(FIONBIO)"
#define njt_blocking_n      "ioctl(!FIONBIO)"

#else

#define njt_nonblocking(s)  fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK)
#define njt_nonblocking_n   "fcntl(O_NONBLOCK)"

#define njt_blocking(s)     fcntl(s, F_SETFL, fcntl(s, F_GETFL) & ~O_NONBLOCK)
#define njt_blocking_n      "fcntl(!O_NONBLOCK)"

#endif

#if (NJT_HAVE_FIONREAD)

#define njt_socket_nread(s, n)  ioctl(s, FIONREAD, n)
#define njt_socket_nread_n      "ioctl(FIONREAD)"

#endif

int njt_tcp_nopush(njt_socket_t s);
int njt_tcp_push(njt_socket_t s);

#if (NJT_LINUX)

#define njt_tcp_nopush_n   "setsockopt(TCP_CORK)"
#define njt_tcp_push_n     "setsockopt(!TCP_CORK)"

#else

#define njt_tcp_nopush_n   "setsockopt(TCP_NOPUSH)"
#define njt_tcp_push_n     "setsockopt(!TCP_NOPUSH)"

#endif


#define njt_shutdown_socket    shutdown
#define njt_shutdown_socket_n  "shutdown()"

#define njt_close_socket    close
#define njt_close_socket_n  "close() socket"


#endif /* _NJT_SOCKET_H_INCLUDED_ */
