
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_OS_H_INCLUDED_
#define _NJT_OS_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


#define NJT_IO_SENDFILE    1


typedef ssize_t (*njt_recv_pt)(njt_connection_t *c, u_char *buf, size_t size);
typedef ssize_t (*njt_recv_chain_pt)(njt_connection_t *c, njt_chain_t *in,
    off_t limit);
typedef ssize_t (*njt_send_pt)(njt_connection_t *c, u_char *buf, size_t size);
typedef njt_chain_t *(*njt_send_chain_pt)(njt_connection_t *c, njt_chain_t *in,
    off_t limit);

typedef struct {
    njt_recv_pt        recv;
    njt_recv_chain_pt  recv_chain;
    njt_recv_pt        udp_recv;
    njt_send_pt        send;
    njt_send_pt        udp_send;
    njt_send_chain_pt  udp_send_chain;
    njt_send_chain_pt  send_chain;
    njt_uint_t         flags;
} njt_os_io_t;


njt_int_t njt_os_init(njt_log_t *log);
void njt_os_status(njt_log_t *log);
njt_int_t njt_os_specific_init(njt_log_t *log);
void njt_os_specific_status(njt_log_t *log);
njt_int_t njt_daemon(njt_log_t *log);
njt_int_t njt_os_signal_process(njt_cycle_t *cycle, char *sig, njt_pid_t pid);


ssize_t njt_unix_recv(njt_connection_t *c, u_char *buf, size_t size);
ssize_t njt_readv_chain(njt_connection_t *c, njt_chain_t *entry, off_t limit);
ssize_t njt_udp_unix_recv(njt_connection_t *c, u_char *buf, size_t size);
ssize_t njt_unix_send(njt_connection_t *c, u_char *buf, size_t size);
njt_chain_t *njt_writev_chain(njt_connection_t *c, njt_chain_t *in,
    off_t limit);
ssize_t njt_udp_unix_send(njt_connection_t *c, u_char *buf, size_t size);
njt_chain_t *njt_udp_unix_sendmsg_chain(njt_connection_t *c, njt_chain_t *in,
    off_t limit);


#if (IOV_MAX > 64)
#define NJT_IOVS_PREALLOCATE  64
#else
#define NJT_IOVS_PREALLOCATE  IOV_MAX
#endif


typedef struct {
    struct iovec  *iovs;
    njt_uint_t     count;
    size_t         size;
    njt_uint_t     nalloc;
} njt_iovec_t;

njt_chain_t *njt_output_chain_to_iovec(njt_iovec_t *vec, njt_chain_t *in,
    size_t limit, njt_log_t *log);


ssize_t njt_writev(njt_connection_t *c, njt_iovec_t *vec);


extern njt_os_io_t  njt_os_io;
extern njt_int_t    njt_ncpu;
extern njt_int_t    njt_max_sockets;
extern njt_uint_t   njt_inherited_nonblocking;
extern njt_uint_t   njt_tcp_nodelay_and_tcp_nopush;


#if (NJT_FREEBSD)
#include <njt_freebsd.h>


#elif (NJT_LINUX)
#include <njt_linux.h>


#elif (NJT_SOLARIS)
#include <njt_solaris.h>


#elif (NJT_DARWIN)
#include <njt_darwin.h>
#endif


#endif /* _NJT_OS_H_INCLUDED_ */
