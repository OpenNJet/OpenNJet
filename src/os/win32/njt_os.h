
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
njt_int_t njt_os_signal_process(njt_cycle_t *cycle, char *sig, njt_pid_t pid);

ssize_t njt_wsarecv(njt_connection_t *c, u_char *buf, size_t size);
ssize_t njt_overlapped_wsarecv(njt_connection_t *c, u_char *buf, size_t size);
ssize_t njt_udp_wsarecv(njt_connection_t *c, u_char *buf, size_t size);
ssize_t njt_udp_overlapped_wsarecv(njt_connection_t *c, u_char *buf,
    size_t size);
ssize_t njt_wsarecv_chain(njt_connection_t *c, njt_chain_t *chain, off_t limit);
ssize_t njt_wsasend(njt_connection_t *c, u_char *buf, size_t size);
ssize_t njt_overlapped_wsasend(njt_connection_t *c, u_char *buf, size_t size);
njt_chain_t *njt_wsasend_chain(njt_connection_t *c, njt_chain_t *in,
    off_t limit);
njt_chain_t *njt_overlapped_wsasend_chain(njt_connection_t *c, njt_chain_t *in,
    off_t limit);

void njt_cdecl njt_event_log(njt_err_t err, const char *fmt, ...);


extern njt_os_io_t  njt_os_io;
extern njt_uint_t   njt_ncpu;
extern njt_uint_t   njt_max_wsabufs;
extern njt_int_t    njt_max_sockets;
extern njt_uint_t   njt_inherited_nonblocking;
extern njt_uint_t   njt_tcp_nodelay_and_tcp_nopush;
extern njt_uint_t   njt_win32_version;
extern char         njt_unique[];


#endif /* _NJT_OS_H_INCLUDED_ */
