
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_STREAM_H_INCLUDED_
#define _NJT_STREAM_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>

#if (NJT_STREAM_SSL)
#include <njt_stream_ssl_module.h>
#endif

typedef struct njt_stream_session_s  njt_stream_session_t;


#include <njt_stream_variables.h>
#include <njt_stream_script.h>
#include <njt_stream_upstream.h>
#include <njt_stream_upstream_round_robin.h>


#define NJT_STREAM_OK                        200
#define NJT_STREAM_SPECIAL_RESPONSE          300 // openresty patch
#define NJT_STREAM_BAD_REQUEST               400
#define NJT_STREAM_FORBIDDEN                 403
#define NJT_STREAM_INTERNAL_SERVER_ERROR     500
#define NJT_STREAM_BAD_GATEWAY               502
#define NJT_STREAM_SERVICE_UNAVAILABLE       503


typedef struct {
    void                         **main_conf;
    void                         **srv_conf;
} njt_stream_conf_ctx_t;


typedef struct {
    struct sockaddr               *sockaddr;
    socklen_t                      socklen;
    njt_str_t                      addr_text;

    /* server ctx */
    njt_stream_conf_ctx_t         *ctx;

    unsigned                       bind:1;
    unsigned                       wildcard:1;
    unsigned                       ssl:1;
#if (NJT_HAVE_INET6)
    unsigned                       ipv6only:1;
#endif
    unsigned                       reuseport:1;
    unsigned                       so_keepalive:2;
    unsigned                       proxy_protocol:1;
    //add by clb, used for udp and tcp traffic hack
    unsigned                     mesh:1;
    //end add by clb
#if (NJT_HAVE_KEEPALIVE_TUNABLE)
    int                            tcp_keepidle;
    int                            tcp_keepintvl;
    int                            tcp_keepcnt;
#endif
    int                            backlog;
    int                            rcvbuf;
    int                            sndbuf;
#if (NJT_HAVE_TCP_FASTOPEN)
    int                            fastopen;
#endif
    int                            type;
} njt_stream_listen_t;


typedef struct {
    njt_stream_conf_ctx_t         *ctx;
    njt_str_t                      addr_text;
    unsigned                       ssl:1;
    unsigned                       proxy_protocol:1;
} njt_stream_addr_conf_t;

typedef struct {
    in_addr_t                      addr;
    njt_stream_addr_conf_t         conf;
} njt_stream_in_addr_t;


#if (NJT_HAVE_INET6)

typedef struct {
    struct in6_addr                addr6;
    njt_stream_addr_conf_t         conf;
} njt_stream_in6_addr_t;

#endif


typedef struct {
    /* njt_stream_in_addr_t or njt_stream_in6_addr_t */
    void                          *addrs;
    njt_uint_t                     naddrs;
} njt_stream_port_t;


typedef struct {
    int                            family;
    int                            type;
    in_port_t                      port;
    njt_array_t                    addrs; /* array of njt_stream_conf_addr_t */
} njt_stream_conf_port_t;


typedef struct {
    njt_stream_listen_t            opt;
} njt_stream_conf_addr_t;


typedef enum {
    NJT_STREAM_POST_ACCEPT_PHASE = 0,
    NJT_STREAM_PREACCESS_PHASE,
    NJT_STREAM_ACCESS_PHASE,
    NJT_STREAM_SSL_PHASE,
    NJT_STREAM_PREREAD_PHASE,
    NJT_STREAM_CONTENT_PHASE,
    NJT_STREAM_LOG_PHASE
} njt_stream_phases;


typedef struct njt_stream_phase_handler_s  njt_stream_phase_handler_t;

typedef njt_int_t (*njt_stream_phase_handler_pt)(njt_stream_session_t *s,
    njt_stream_phase_handler_t *ph);
typedef njt_int_t (*njt_stream_handler_pt)(njt_stream_session_t *s);
typedef void (*njt_stream_content_handler_pt)(njt_stream_session_t *s);


struct njt_stream_phase_handler_s {
    njt_stream_phase_handler_pt    checker;
    njt_stream_handler_pt          handler;
    njt_uint_t                     next;
};


typedef struct {
    njt_stream_phase_handler_t    *handlers;
} njt_stream_phase_engine_t;


typedef struct {
    njt_array_t                    handlers;
} njt_stream_phase_t;


typedef struct {
    njt_array_t                    servers;     /* njt_stream_core_srv_conf_t */
    njt_array_t                    listen;      /* njt_stream_listen_t */

    njt_stream_phase_engine_t      phase_engine;

    njt_hash_t                     variables_hash;

    njt_array_t                    variables;        /* njt_stream_variable_t */
    njt_array_t                    prefix_variables; /* njt_stream_variable_t */
    njt_uint_t                     ncaptures;

    njt_uint_t                     variables_hash_max_size;
    njt_uint_t                     variables_hash_bucket_size;

    njt_hash_keys_arrays_t        *variables_keys;

    njt_stream_phase_t             phases[NJT_STREAM_LOG_PHASE + 1];
} njt_stream_core_main_conf_t;


typedef struct {
    njt_stream_content_handler_pt  handler;

    njt_stream_conf_ctx_t         *ctx;

    u_char                        *file_name;
    njt_uint_t                     line;

    njt_flag_t                     tcp_nodelay;
    size_t                         preread_buffer_size;
    njt_msec_t                     preread_timeout;

    njt_log_t                     *error_log;

    njt_msec_t                     resolver_timeout;
    njt_resolver_t                *resolver;

    njt_msec_t                     proxy_protocol_timeout;

    njt_uint_t                     listen;  /* unsigned  listen:1; */
} njt_stream_core_srv_conf_t;


struct njt_stream_session_s {
    uint32_t                       signature;         /* "STRM" */

    njt_connection_t              *connection;

    off_t                          received;
    time_t                         start_sec;
    njt_msec_t                     start_msec;

    njt_log_handler_pt             log_handler;

    void                         **ctx;
    void                         **main_conf;
    void                         **srv_conf;

    njt_stream_upstream_t         *upstream;
    njt_array_t                   *upstream_states;
                                           /* of njt_stream_upstream_state_t */
    njt_stream_variable_value_t   *variables;

#if (NJT_PCRE)
    njt_uint_t                     ncaptures;
    int                           *captures;
    u_char                        *captures_data;
#endif

#if (NJT_STREAM_FTP_PROXY)
    njt_queue_t                    ftp_port_list;
#endif    

    njt_int_t                      phase_handler;
    njt_uint_t                     status;

    unsigned                       ssl:1;

    unsigned                       stat_processing:1;

    unsigned                       health_check:1;

    unsigned                       limit_conn_status:2;
};


typedef struct {
    njt_int_t                    (*preconfiguration)(njt_conf_t *cf);
    njt_int_t                    (*postconfiguration)(njt_conf_t *cf);

    void                        *(*create_main_conf)(njt_conf_t *cf);
    char                        *(*init_main_conf)(njt_conf_t *cf, void *conf);

    void                        *(*create_srv_conf)(njt_conf_t *cf);
    char                        *(*merge_srv_conf)(njt_conf_t *cf, void *prev,
                                                   void *conf);
} njt_stream_module_t;

typedef struct {
    size_t          left;
    size_t          size;
    size_t          ext;
    u_char         *pos;
    u_char         *dst;
    u_char          buf[4];
    u_char          version[2];
    njt_str_t       host;
    njt_str_t       alpn;
    njt_log_t      *log;
    njt_pool_t     *pool;
    njt_uint_t      state;

	///nginmesh_dest
	njt_flag_t      ssl;
	njt_str_t       dest;
	njt_str_t       dest_ip;
	njt_str_t       dest_port;
	njt_str_t       proto;
	njt_str_t       port_mode;
    unsigned        complete:1;
    unsigned        complete_get_port:1;
    unsigned        complete_nginmesh:1;

} njt_stream_proto_ctx_t;
typedef struct {
	njt_array_t     *proto_ports;
	njt_flag_t      proto_enabled;
} njt_stream_proto_srv_conf_t;

// openresty patch
typedef struct {
    njt_msec_t                       connect_timeout;
    njt_msec_t                       timeout;
} njt_stream_proxy_ctx_t;


#define NJT_STREAM_HAVE_PROXY_TIMEOUT_FIELDS_PATCH 1
// openresty patch end


#define NJT_STREAM_MODULE       0x4d525453     /* "STRM" */

#define NJT_STREAM_MAIN_CONF    0x02000000
#define NJT_STREAM_SRV_CONF     0x04000000
#define NJT_STREAM_UPS_CONF     0x08000000


#define NJT_STREAM_MAIN_CONF_OFFSET  offsetof(njt_stream_conf_ctx_t, main_conf)
#define NJT_STREAM_SRV_CONF_OFFSET   offsetof(njt_stream_conf_ctx_t, srv_conf)


#define njt_stream_get_module_ctx(s, module)   (s)->ctx[module.ctx_index]
#define njt_stream_set_ctx(s, c, module)       s->ctx[module.ctx_index] = c;
#define njt_stream_delete_ctx(s, module)       s->ctx[module.ctx_index] = NULL;


#define njt_stream_get_module_main_conf(s, module)                             \
    (s)->main_conf[module.ctx_index]
#define njt_stream_get_module_srv_conf(s, module)                              \
    (s)->srv_conf[module.ctx_index]

#define njt_stream_conf_get_module_main_conf(cf, module)                       \
    ((njt_stream_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define njt_stream_conf_get_module_srv_conf(cf, module)                        \
    ((njt_stream_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]

#define njt_stream_cycle_get_module_main_conf(cycle, module)                   \
    (cycle->conf_ctx[njt_stream_module.index] ?                                \
        ((njt_stream_conf_ctx_t *) cycle->conf_ctx[njt_stream_module.index])   \
            ->main_conf[module.ctx_index]:                                     \
        NULL)


#define NJT_STREAM_WRITE_BUFFERED  0x10


void njt_stream_core_run_phases(njt_stream_session_t *s);
njt_int_t njt_stream_core_generic_phase(njt_stream_session_t *s,
    njt_stream_phase_handler_t *ph);
njt_int_t njt_stream_core_preread_phase(njt_stream_session_t *s,
    njt_stream_phase_handler_t *ph);
njt_int_t njt_stream_core_content_phase(njt_stream_session_t *s,
    njt_stream_phase_handler_t *ph);


void njt_stream_init_connection(njt_connection_t *c);
void njt_stream_session_handler(njt_event_t *rev);
void njt_stream_finalize_session(njt_stream_session_t *s, njt_uint_t rc);


extern njt_module_t  njt_stream_module;
extern njt_uint_t    njt_stream_max_module;
extern njt_module_t  njt_stream_core_module;
extern njt_module_t  njt_stream_proxy_module; // openresty patch


typedef njt_int_t (*njt_stream_filter_pt)(njt_stream_session_t *s,
    njt_chain_t *chain, njt_uint_t from_upstream);


extern njt_stream_filter_pt  njt_stream_top_filter;

#define HAS_NJT_STREAM_PROXY_GET_NEXT_UPSTREAM_TRIES_PATCH 1 // openresty patch

#endif /* _NJT_STREAM_H_INCLUDED_ */
