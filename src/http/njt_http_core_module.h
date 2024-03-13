
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_CORE_H_INCLUDED_
#define _NJT_HTTP_CORE_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>

#if (NJT_THREADS)
#include <njt_thread_pool.h>
#elif (NJT_COMPAT)
typedef struct njt_thread_pool_s  njt_thread_pool_t;
#endif


#define NJT_HTTP_GZIP_PROXIED_OFF       0x0002
#define NJT_HTTP_GZIP_PROXIED_EXPIRED   0x0004
#define NJT_HTTP_GZIP_PROXIED_NO_CACHE  0x0008
#define NJT_HTTP_GZIP_PROXIED_NO_STORE  0x0010
#define NJT_HTTP_GZIP_PROXIED_PRIVATE   0x0020
#define NJT_HTTP_GZIP_PROXIED_NO_LM     0x0040
#define NJT_HTTP_GZIP_PROXIED_NO_ETAG   0x0080
#define NJT_HTTP_GZIP_PROXIED_AUTH      0x0100
#define NJT_HTTP_GZIP_PROXIED_ANY       0x0200


#define NJT_HTTP_AIO_OFF                0
#define NJT_HTTP_AIO_ON                 1
#define NJT_HTTP_AIO_THREADS            2


#define NJT_HTTP_SATISFY_ALL            0
#define NJT_HTTP_SATISFY_ANY            1


#define NJT_HTTP_LINGERING_OFF          0
#define NJT_HTTP_LINGERING_ON           1
#define NJT_HTTP_LINGERING_ALWAYS       2


#define NJT_HTTP_IMS_OFF                0
#define NJT_HTTP_IMS_EXACT              1
#define NJT_HTTP_IMS_BEFORE             2


#define NJT_HTTP_KEEPALIVE_DISABLE_NONE    0x0002
#define NJT_HTTP_KEEPALIVE_DISABLE_MSIE6   0x0004
#define NJT_HTTP_KEEPALIVE_DISABLE_SAFARI  0x0008


#define NJT_HTTP_SERVER_TOKENS_OFF      0
#define NJT_HTTP_SERVER_TOKENS_ON       1
#define NJT_HTTP_SERVER_TOKENS_BUILD    2


typedef struct njt_http_location_tree_node_s  njt_http_location_tree_node_t;
typedef struct njt_http_core_loc_conf_s  njt_http_core_loc_conf_t;


typedef struct {
    struct sockaddr           *sockaddr;
    socklen_t                  socklen;
    njt_str_t                  addr_text;

    unsigned                   set:1;
    unsigned                   default_server:1;
    unsigned                   bind:1;
    unsigned                   wildcard:1;
    unsigned                   ssl:1;
    unsigned                   http2:1;
    unsigned                   http3:1;
    unsigned                   quic:1;
#if (NJT_HAVE_INET6)
    unsigned                   ipv6only:1;
#endif
    unsigned                   deferred_accept:1;
    unsigned                   reuseport:1;
    unsigned                   so_keepalive:2;
    unsigned                   proxy_protocol:1;

    int                        backlog;
    int                        rcvbuf;
    int                        sndbuf;
    int                        type;
#if (NJT_HAVE_SETFIB)
    int                        setfib;
#endif
#if (NJT_HAVE_TCP_FASTOPEN)
    int                        fastopen;
#endif
#if (NJT_HAVE_KEEPALIVE_TUNABLE)
    int                        tcp_keepidle;
    int                        tcp_keepintvl;
    int                        tcp_keepcnt;
#endif

#if (NJT_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    char                      *accept_filter;
#endif
} njt_http_listen_opt_t;


typedef enum {
    NJT_HTTP_POST_READ_PHASE = 0,

    NJT_HTTP_SERVER_REWRITE_PHASE,

    NJT_HTTP_FIND_CONFIG_PHASE,
    NJT_HTTP_REWRITE_PHASE,
    NJT_HTTP_POST_REWRITE_PHASE,

    NJT_HTTP_PREACCESS_PHASE,

    NJT_HTTP_ACCESS_PHASE,
    NJT_HTTP_POST_ACCESS_PHASE,

    NJT_HTTP_PRECONTENT_PHASE,

    NJT_HTTP_CONTENT_PHASE,

    NJT_HTTP_LOG_PHASE
} njt_http_phases;

typedef struct njt_http_phase_handler_s  njt_http_phase_handler_t;

typedef njt_int_t (*njt_http_phase_handler_pt)(njt_http_request_t *r,
    njt_http_phase_handler_t *ph);

struct njt_http_phase_handler_s {
    njt_http_phase_handler_pt  checker;
    njt_http_handler_pt        handler;
    njt_uint_t                 next;
};


typedef struct {
    njt_http_phase_handler_t  *handlers;
    njt_uint_t                 server_rewrite_index;
    njt_uint_t                 location_rewrite_index;
} njt_http_phase_engine_t;


typedef struct {
    njt_array_t                handlers;
} njt_http_phase_t;


typedef struct {
    njt_array_t                servers;         /* njt_http_core_srv_conf_t */

    njt_http_phase_engine_t    phase_engine;

    njt_hash_t                 headers_in_hash;

    njt_hash_t                 variables_hash;

    njt_array_t                variables;         /* njt_http_variable_t */
    njt_array_t                prefix_variables;  /* njt_http_variable_t */
    njt_uint_t                 ncaptures;

    njt_uint_t                 server_names_hash_max_size;
    njt_uint_t                 server_names_hash_bucket_size;

    njt_uint_t                 variables_hash_max_size;
    njt_uint_t                 variables_hash_bucket_size;

    njt_hash_keys_arrays_t    *variables_keys;
#if (NJT_HTTP_DYNAMIC_LOC)
    njt_pool_t		           *dyn_var_pool;
#endif
#if (NJT_HTTP_DYNAMIC_SERVER)
        njt_pool_t		           *dyn_vs_pool;
#endif
    njt_array_t               *ports;

    njt_http_phase_t           phases[NJT_HTTP_LOG_PHASE + 1];
} njt_http_core_main_conf_t;


typedef struct {
    /* array of the njt_http_server_name_t, "server_name" directive */
    njt_array_t                 server_names;

    /* server ctx */
    njt_http_conf_ctx_t        *ctx;

    u_char                     *file_name;
    njt_uint_t                  line;

    njt_str_t                   server_name;

    size_t                      connection_pool_size;
    size_t                      request_pool_size;
    size_t                      client_header_buffer_size;

    njt_bufs_t                  large_client_header_buffers;

    njt_msec_t                  client_header_timeout;

    njt_flag_t                  ignore_invalid_headers;
    njt_flag_t                  merge_slashes;
    njt_flag_t                  underscores_in_headers;

    unsigned                    listen:1;
#if (NJT_PCRE)
    unsigned                    captures:1;
#endif

    njt_http_core_loc_conf_t  **named_locations;
    //add by clb
#if (NJT_HTTP_DYNAMIC_LOC)
    njt_pool_t                *named_parent_pool;
#endif
#if (NJT_HTTP_DYNAMIC_SERVER)
    unsigned		          dynamic:1;
    unsigned		          dynamic_status:2;
    unsigned                  disable:1;
    njt_pool_t                *pool;
    njt_uint_t                ref_count;
#endif
} njt_http_core_srv_conf_t;


/* list of structures to find core_srv_conf quickly at run time */


typedef struct {
#if (NJT_PCRE)
    njt_http_regex_t          *regex;
#endif
    njt_http_core_srv_conf_t  *server;   /* virtual name server conf */
    njt_str_t                  name;
#if (NJT_HTTP_DYNAMIC_LOC) 
    njt_str_t                  full_name;
#endif
} njt_http_server_name_t;


typedef struct {
    njt_hash_combined_t        names;

    njt_uint_t                 nregex;
    njt_http_server_name_t    *regex;
} njt_http_virtual_names_t;


struct njt_http_addr_conf_s {
    /* the default server configuration for this address:port */
    njt_http_core_srv_conf_t  *default_server;

    njt_http_virtual_names_t  *virtual_names;

    unsigned                   ssl:1;
    unsigned                   http2:1;
    unsigned                   http3:1;
    unsigned                   quic:1;
    unsigned                   proxy_protocol:1;
};


typedef struct {
    in_addr_t                  addr;
    njt_http_addr_conf_t       conf;
} njt_http_in_addr_t;


#if (NJT_HAVE_INET6)

typedef struct {
    struct in6_addr            addr6;
    njt_http_addr_conf_t       conf;
} njt_http_in6_addr_t;

#endif


typedef struct {
    /* njt_http_in_addr_t or njt_http_in6_addr_t */
    void                      *addrs;
    njt_uint_t                 naddrs;
} njt_http_port_t;


typedef struct {
    njt_int_t                  family;
    njt_int_t                  type;
    in_port_t                  port;
    njt_array_t                addrs;     /* array of njt_http_conf_addr_t */
} njt_http_conf_port_t;


typedef struct {
    njt_http_listen_opt_t      opt;

    unsigned                   protocols:3;
    unsigned                   protocols_set:1;
    unsigned                   protocols_changed:1;

    njt_hash_t                 hash;
    njt_hash_wildcard_t       *wc_head;
    njt_hash_wildcard_t       *wc_tail;

#if (NJT_PCRE)
    njt_uint_t                 nregex;
    njt_http_server_name_t    *regex;
#endif

    /* the default server configuration for this address:port */
    njt_http_core_srv_conf_t  *default_server;
    njt_array_t                servers;  /* array of njt_http_core_srv_conf_t */
} njt_http_conf_addr_t;


typedef struct {
    njt_int_t                  status;
    njt_int_t                  overwrite;
    njt_http_complex_value_t   value;
    njt_str_t                  args;
} njt_http_err_page_t;
// by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
typedef struct njt_http_location_destroy_s {
    void(*destroy_loc)(njt_http_core_loc_conf_t *hclf,void* data);
    void* data;     // 携带必要上下文数据
    struct njt_http_location_destroy_s *next;
} njt_http_location_destroy_t;
#endif
//end

//add by clb, used for ctrl api module
typedef struct {
    njt_str_t       module_key;
    uint32_t        api_limit_except;
    void            **limit_except_loc_conf;
} njt_http_api_limit_except_t;
//end add by clb

struct njt_http_core_loc_conf_s {
    njt_str_t     name;          /* location name */
    njt_str_t     escaped_name;

#if (NJT_PCRE)
    njt_http_regex_t  *regex;
#endif

    unsigned      noname:1;   /* "if () {}" block or limit_except */
    unsigned      lmt_excpt:1;
    unsigned      named:1;
    unsigned      if_loc:1;

    unsigned      exact_match:1;
    unsigned      noregex:1;

    unsigned      auto_redirect:1;
#if (NJT_HTTP_GZIP)
    unsigned      gzip_disable_msie6:2;
    unsigned      gzip_disable_degradation:2;
#endif

    njt_http_location_tree_node_t   *static_locations;


#if (NJT_PCRE)
    njt_http_core_loc_conf_t       **regex_locations;
    //add by clb
#if (NJT_HTTP_DYNAMIC_LOC)
//    njt_pool_t                     *regex_parent_pool;
//    njt_http_core_loc_conf_t       **new_regex_locations;
//    njt_pool_t                     *new_regex_parent_pool;
      void                           *if_location_root;
#endif
    //end
#endif

    /* pointer to the modules' loc_conf */
    void        **loc_conf;

    //add by clb, used for ctrl api module
    njt_array_t  *api_limit_excepts;
    //end add by clb

    uint32_t      limit_except;
    void        **limit_except_loc_conf;

    njt_http_handler_pt  handler;

    /* location name length for inclusive location with inherited alias */
    size_t        alias;
    njt_str_t     root;                    /* root, alias */
    njt_str_t     post_action;

    njt_array_t  *root_lengths;
    njt_array_t  *root_values;

    njt_array_t  *types;
    njt_hash_t    types_hash;
    njt_str_t     default_type;

    off_t         client_max_body_size;    /* client_max_body_size */
    off_t         directio;                /* directio */
    off_t         directio_alignment;      /* directio_alignment */

    size_t        client_body_buffer_size; /* client_body_buffer_size */
    size_t        send_lowat;              /* send_lowat */
    size_t        postpone_output;         /* postpone_output */
    size_t        sendfile_max_chunk;      /* sendfile_max_chunk */
    size_t        read_ahead;              /* read_ahead */
    size_t        subrequest_output_buffer_size;
                                           /* subrequest_output_buffer_size */

    njt_http_complex_value_t  *limit_rate; /* limit_rate */
    njt_http_complex_value_t  *limit_rate_after; /* limit_rate_after */

    njt_msec_t    client_body_timeout;     /* client_body_timeout */
    njt_msec_t    send_timeout;            /* send_timeout */
    njt_msec_t    keepalive_time;          /* keepalive_time */
    njt_msec_t    keepalive_timeout;       /* keepalive_timeout */
    njt_msec_t    lingering_time;          /* lingering_time */
    njt_msec_t    lingering_timeout;       /* lingering_timeout */
    njt_msec_t    resolver_timeout;        /* resolver_timeout */
    njt_msec_t    auth_delay;              /* auth_delay */

    njt_resolver_t  *resolver;             /* resolver */

    time_t        keepalive_header;        /* keepalive_timeout */

    njt_uint_t    keepalive_requests;      /* keepalive_requests */
    njt_uint_t    keepalive_disable;       /* keepalive_disable */
    njt_uint_t    satisfy;                 /* satisfy */
    njt_uint_t    lingering_close;         /* lingering_close */
    njt_uint_t    if_modified_since;       /* if_modified_since */
    njt_uint_t    max_ranges;              /* max_ranges */
    njt_uint_t    client_body_in_file_only; /* client_body_in_file_only */

    njt_flag_t    client_body_in_single_buffer;
                                           /* client_body_in_singe_buffer */
    njt_flag_t    internal;                /* internal */
    njt_flag_t    sendfile;                /* sendfile */
    njt_flag_t    aio;                     /* aio */
    njt_flag_t    aio_write;               /* aio_write */
    njt_flag_t    tcp_nopush;              /* tcp_nopush */
    njt_flag_t    tcp_nodelay;             /* tcp_nodelay */
    njt_flag_t    reset_timedout_connection; /* reset_timedout_connection */
    njt_flag_t    absolute_redirect;       /* absolute_redirect */
    njt_flag_t    server_name_in_redirect; /* server_name_in_redirect */
    njt_flag_t    port_in_redirect;        /* port_in_redirect */
    njt_flag_t    msie_padding;            /* msie_padding */
    njt_flag_t    msie_refresh;            /* msie_refresh */
    njt_flag_t    log_not_found;           /* log_not_found */
    njt_flag_t    log_subrequest;          /* log_subrequest */
    njt_flag_t    recursive_error_pages;   /* recursive_error_pages */
    njt_uint_t    server_tokens;           /* server_tokens */
    njt_flag_t    chunked_transfer_encoding; /* chunked_transfer_encoding */
    njt_flag_t    etag;                    /* etag */

#if (NJT_HTTP_GZIP)
    njt_flag_t    gzip_vary;               /* gzip_vary */

    njt_uint_t    gzip_http_version;       /* gzip_http_version */
    njt_uint_t    gzip_proxied;            /* gzip_proxied */

#if (NJT_PCRE)
    njt_array_t  *gzip_disable;            /* gzip_disable */
#endif
#endif

#if (NJT_THREADS || NJT_COMPAT)
    njt_thread_pool_t         *thread_pool;
    njt_http_complex_value_t  *thread_pool_value;
#endif

#if (NJT_HAVE_OPENAT)
    njt_uint_t    disable_symlinks;        /* disable_symlinks */
    njt_http_complex_value_t  *disable_symlinks_from;
#endif

    njt_array_t  *error_pages;             /* error_page */

    njt_path_t   *client_body_temp_path;   /* client_body_temp_path */

    njt_open_file_cache_t  *open_file_cache;
    time_t        open_file_cache_valid;
    njt_uint_t    open_file_cache_min_uses;
    njt_flag_t    open_file_cache_errors;
    njt_flag_t    open_file_cache_events;

    njt_log_t    *error_log;

    njt_uint_t    types_hash_max_size;
    njt_uint_t    types_hash_bucket_size;

    njt_queue_t  *locations;
    // by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
    njt_queue_t  *old_locations; //zyg
    njt_queue_t  *if_locations; //zyg
    njt_queue_t  *new_locations;    //clb
    njt_pool_t   *new_locations_pool;    //zyg
    njt_pool_t   *pool;          //cx 处理上下文内存释放
    njt_http_location_destroy_t *destroy_locs; //cx 处理上下文内存释放,按照链表顺序释放
    njt_str_t    full_name;       // cx 查找location
    njt_uint_t   ref_count;
    unsigned     disable:1;
    unsigned     clean_set:1;
    unsigned     clean_end:1;
	unsigned     dynamic_status:2; // 1 init, 2 nomal
    njt_http_location_tree_node_t   *new_static_locations;//add by clb
#endif
    //end

#if 0
    njt_http_core_loc_conf_t  *prev_location;
#endif
};


typedef struct {
    njt_queue_t                      queue;
    njt_http_core_loc_conf_t        *exact;
    njt_http_core_loc_conf_t        *inclusive;
    njt_str_t                       *name;
    u_char                          *file_name;
    njt_uint_t                       line;
    njt_queue_t                      list;
	    // by zyg
#if (NJT_HTTP_DYNAMIC_LOC)
	unsigned     dynamic_status:2; // 1 init, 2 nomal
    njt_pool_t   *parent_pool;  //add by clb
#endif
} njt_http_location_queue_t;


struct njt_http_location_tree_node_s {
    njt_http_location_tree_node_t   *left;
    njt_http_location_tree_node_t   *right;
    njt_http_location_tree_node_t   *tree;

    njt_http_core_loc_conf_t        *exact;
    njt_http_core_loc_conf_t        *inclusive;
    //by clb
#if (NJT_HTTP_DYNAMIC_LOC)
    njt_pool_t   *parent_pool;
#endif
//end by clb
    u_short                          len;
    u_char                           auto_redirect;
    u_char                           name[1];
};


void njt_http_core_run_phases(njt_http_request_t *r);
njt_int_t njt_http_core_generic_phase(njt_http_request_t *r,
    njt_http_phase_handler_t *ph);
njt_int_t njt_http_core_rewrite_phase(njt_http_request_t *r,
    njt_http_phase_handler_t *ph);
njt_int_t njt_http_core_find_config_phase(njt_http_request_t *r,
    njt_http_phase_handler_t *ph);
njt_int_t njt_http_core_post_rewrite_phase(njt_http_request_t *r,
    njt_http_phase_handler_t *ph);
njt_int_t njt_http_core_access_phase(njt_http_request_t *r,
    njt_http_phase_handler_t *ph);
njt_int_t njt_http_core_post_access_phase(njt_http_request_t *r,
    njt_http_phase_handler_t *ph);
njt_int_t njt_http_core_content_phase(njt_http_request_t *r,
    njt_http_phase_handler_t *ph);


void *njt_http_test_content_type(njt_http_request_t *r, njt_hash_t *types_hash);
njt_int_t njt_http_set_content_type(njt_http_request_t *r);
void njt_http_set_exten(njt_http_request_t *r);
njt_int_t njt_http_set_etag(njt_http_request_t *r);
void njt_http_weak_etag(njt_http_request_t *r);
njt_int_t njt_http_send_response(njt_http_request_t *r, njt_uint_t status,
    njt_str_t *ct, njt_http_complex_value_t *cv);
u_char *njt_http_map_uri_to_path(njt_http_request_t *r, njt_str_t *name,
    size_t *root_length, size_t reserved);
njt_int_t njt_http_auth_basic_user(njt_http_request_t *r);
#if (NJT_HTTP_GZIP)
njt_int_t njt_http_gzip_ok(njt_http_request_t *r);
#endif


njt_int_t njt_http_subrequest(njt_http_request_t *r,
    njt_str_t *uri, njt_str_t *args, njt_http_request_t **psr,
    njt_http_post_subrequest_t *ps, njt_uint_t flags);
njt_int_t njt_http_internal_redirect(njt_http_request_t *r,
    njt_str_t *uri, njt_str_t *args);
njt_int_t njt_http_named_location(njt_http_request_t *r, njt_str_t *name);


njt_http_cleanup_t *njt_http_cleanup_add(njt_http_request_t *r, size_t size);
//by chengxu
#if (NJT_HTTP_DYNAMIC_LOC)
void njt_http_location_cleanup(njt_http_core_loc_conf_t *clcf);
njt_int_t njt_http_location_cleanup_add(njt_http_core_loc_conf_t *clcf, void(*handler)(njt_http_core_loc_conf_t *hclcf,void* data) ,void* data);
void njt_http_location_delete_dyn_var(njt_http_core_loc_conf_t *clcf);
void njt_http_server_delete_dyn_var(njt_http_core_srv_conf_t *cscf);
njt_int_t njt_http_add_location_pre_process(njt_conf_t *cf,njt_queue_t **locations,njt_pool_t *pool);
njt_int_t njt_http_del_variable(njt_http_variable_t *fv);
void njt_http_refresh_variables_keys();
#endif
//end

typedef njt_int_t (*njt_http_output_header_filter_pt)(njt_http_request_t *r);
typedef njt_int_t (*njt_http_output_body_filter_pt)
    (njt_http_request_t *r, njt_chain_t *chain);
typedef njt_int_t (*njt_http_request_body_filter_pt)
    (njt_http_request_t *r, njt_chain_t *chain);


njt_int_t njt_http_output_filter(njt_http_request_t *r, njt_chain_t *chain);
njt_int_t njt_http_write_filter(njt_http_request_t *r, njt_chain_t *chain);
njt_int_t njt_http_request_body_save_filter(njt_http_request_t *r,
    njt_chain_t *chain);


njt_int_t njt_http_set_disable_symlinks(njt_http_request_t *r,
    njt_http_core_loc_conf_t *clcf, njt_str_t *path, njt_open_file_info_t *of);

njt_int_t njt_http_get_forwarded_addr(njt_http_request_t *r, njt_addr_t *addr,
    njt_table_elt_t *headers, njt_str_t *value, njt_array_t *proxies,
    int recursive);

njt_int_t njt_http_link_multi_headers(njt_http_request_t *r);
njt_http_location_queue_t *njt_http_find_location(njt_str_t name, njt_queue_t *locations);

#if (NJT_HTTP_DYNAMIC_SERVER)
void njt_http_core_free_srv_ctx(void* data);
#endif

extern njt_module_t  njt_http_core_module;

extern njt_uint_t njt_http_max_module;

extern njt_str_t  njt_http_core_get_method;


#define njt_http_clear_content_length(r)                                      \
                                                                              \
    r->headers_out.content_length_n = -1;                                     \
    if (r->headers_out.content_length) {                                      \
        r->headers_out.content_length->hash = 0;                              \
        r->headers_out.content_length = NULL;                                 \
    }

#define njt_http_clear_accept_ranges(r)                                       \
                                                                              \
    r->allow_ranges = 0;                                                      \
    if (r->headers_out.accept_ranges) {                                       \
        r->headers_out.accept_ranges->hash = 0;                               \
        r->headers_out.accept_ranges = NULL;                                  \
    }

#define njt_http_clear_last_modified(r)                                       \
                                                                              \
    r->headers_out.last_modified_time = -1;                                   \
    if (r->headers_out.last_modified) {                                       \
        r->headers_out.last_modified->hash = 0;                               \
        r->headers_out.last_modified = NULL;                                  \
    }

#define njt_http_clear_location(r)                                            \
                                                                              \
    if (r->headers_out.location) {                                            \
        r->headers_out.location->hash = 0;                                    \
        r->headers_out.location = NULL;                                       \
    }

#define njt_http_clear_etag(r)                                                \
                                                                              \
    if (r->headers_out.etag) {                                                \
        r->headers_out.etag->hash = 0;                                        \
        r->headers_out.etag = NULL;                                           \
    }


#endif /* _NJT_HTTP_CORE_H_INCLUDED_ */
