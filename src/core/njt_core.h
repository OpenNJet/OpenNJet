
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_CORE_H_INCLUDED_
#define _NJT_CORE_H_INCLUDED_


#include <njt_config.h>


typedef struct njt_module_s          njt_module_t;
typedef struct njt_conf_s            njt_conf_t;
typedef struct njt_cycle_s           njt_cycle_t;
typedef struct njt_pool_s            njt_pool_t;
typedef struct njt_chain_s           njt_chain_t;
typedef struct njt_log_s             njt_log_t;
typedef struct njt_open_file_s       njt_open_file_t;
typedef struct njt_command_s         njt_command_t;
typedef struct njt_file_s            njt_file_t;
typedef struct njt_event_s           njt_event_t;
typedef struct njt_event_aio_s       njt_event_aio_t;
typedef struct njt_connection_s      njt_connection_t;
typedef struct njt_thread_task_s     njt_thread_task_t;
typedef struct njt_ssl_s             njt_ssl_t;
typedef struct njt_proxy_protocol_s  njt_proxy_protocol_t;
typedef struct njt_quic_stream_s     njt_quic_stream_t;
typedef struct njt_ssl_connection_s  njt_ssl_connection_t;
typedef struct njt_udp_connection_s  njt_udp_connection_t;

typedef void (*njt_event_handler_pt)(njt_event_t *ev);
typedef void (*njt_connection_handler_pt)(njt_connection_t *c);


#define  NJT_OK          0
#define  NJT_ERROR      -1
#define  NJT_AGAIN      -2
#define  NJT_BUSY       -3
#define  NJT_DONE       -4
#define  NJT_DECLINED   -5
#define  NJT_ABORT      -6

#define NJT_WEIGHT_POWER      100

#include <njt_errno.h>
#include <njt_atomic.h>
#include <njt_thread.h>
#include <njt_rbtree.h>
#include <njt_time.h>
#include <njt_socket.h>
#include <njt_string.h>
#include <njt_files.h>
#include <njt_shmem.h>
#include <njt_process.h>
#include <njt_user.h>
#include <njt_dlopen.h>
#include <njt_parse.h>
#include <njt_parse_time.h>
#include <njt_log.h>
#include <njt_alloc.h>
#include <njt_palloc.h>
#include <njt_buf.h>
#include <njt_queue.h>
#include <njt_array.h>
#include <njt_list.h>
#include <njt_hash.h>
#include <njt_lvlhsh.h>
#include <njt_file.h>
#include <njt_crc.h>
#include <njt_crc32.h>
#include <njt_murmurhash.h>
#if (NJT_PCRE)
#include <njt_regex.h>
#endif
#include <njt_radix_tree.h>
#include <njt_times.h>
#include <njt_rwlock.h>
#include <njt_shmtx.h>
#include <njt_slab.h>
#include <njt_inet.h>
#include <njt_cycle.h>
#include <njt_resolver.h>
#if (NJT_OPENSSL)
#include <njt_event_openssl.h>
#if (NJT_QUIC)
#include <njt_event_quic.h>
#endif
#endif
#include <njt_process_cycle.h>
#include <njt_dyn_conf.h>
#include <njt_conf_file.h>
#include <njt_module.h>
#include <njt_open_file_cache.h>
#include <njt_os.h>
#include <njt_connection.h>
#include <njt_syslog.h>
#include <njt_proxy_protocol.h>
#if (NJT_HAVE_BPF)
#include <njt_bpf.h>
#endif


#define LF     (u_char) '\n'
#define CR     (u_char) '\r'
#define CRLF   "\r\n"


#define njt_abs(value)       (((value) >= 0) ? (value) : - (value))
#define njt_max(val1, val2)  ((val1 < val2) ? (val2) : (val1))
#define njt_min(val1, val2)  ((val1 > val2) ? (val2) : (val1))

void njt_cpuinfo(void);

#if (NJT_HAVE_OPENAT)
#define NJT_DISABLE_SYMLINKS_OFF        0
#define NJT_DISABLE_SYMLINKS_ON         1
#define NJT_DISABLE_SYMLINKS_NOTOWNER   2
#endif

extern njt_pool_t        *saved_init_cycle_pool; // openresty patch

#define SIGCONF 37

#endif /* _NJT_CORE_H_INCLUDED_ */
