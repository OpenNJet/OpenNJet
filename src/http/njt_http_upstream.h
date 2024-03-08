
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_UPSTREAM_H_INCLUDED_
#define _NJT_HTTP_UPSTREAM_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>
#include <njt_event_connect.h>
#include <njt_event_pipe.h>
#include <njt_http.h>


#define NJT_HTTP_UPSTREAM_FT_ERROR           0x00000002
#define NJT_HTTP_UPSTREAM_FT_TIMEOUT         0x00000004
#define NJT_HTTP_UPSTREAM_FT_INVALID_HEADER  0x00000008
#define NJT_HTTP_UPSTREAM_FT_HTTP_500        0x00000010
#define NJT_HTTP_UPSTREAM_FT_HTTP_502        0x00000020
#define NJT_HTTP_UPSTREAM_FT_HTTP_503        0x00000040
#define NJT_HTTP_UPSTREAM_FT_HTTP_504        0x00000080
#define NJT_HTTP_UPSTREAM_FT_HTTP_403        0x00000100
#define NJT_HTTP_UPSTREAM_FT_HTTP_404        0x00000200
#define NJT_HTTP_UPSTREAM_FT_HTTP_429        0x00000400
#define NJT_HTTP_UPSTREAM_FT_UPDATING        0x00000800
#define NJT_HTTP_UPSTREAM_FT_BUSY_LOCK       0x00001000
#define NJT_HTTP_UPSTREAM_FT_MAX_WAITING     0x00002000
#define NJT_HTTP_UPSTREAM_FT_NON_IDEMPOTENT  0x00004000
#define NJT_HTTP_UPSTREAM_FT_NOLIVE          0x40000000
#define NJT_HTTP_UPSTREAM_FT_OFF             0x80000000

#define NJT_HTTP_UPSTREAM_FT_STATUS          (NJT_HTTP_UPSTREAM_FT_HTTP_500  \
                                             |NJT_HTTP_UPSTREAM_FT_HTTP_502  \
                                             |NJT_HTTP_UPSTREAM_FT_HTTP_503  \
                                             |NJT_HTTP_UPSTREAM_FT_HTTP_504  \
                                             |NJT_HTTP_UPSTREAM_FT_HTTP_403  \
                                             |NJT_HTTP_UPSTREAM_FT_HTTP_404  \
                                             |NJT_HTTP_UPSTREAM_FT_HTTP_429)

#define NJT_HTTP_UPSTREAM_INVALID_HEADER     40


#define NJT_HTTP_UPSTREAM_IGN_XA_REDIRECT    0x00000002
#define NJT_HTTP_UPSTREAM_IGN_XA_EXPIRES     0x00000004
#define NJT_HTTP_UPSTREAM_IGN_EXPIRES        0x00000008
#define NJT_HTTP_UPSTREAM_IGN_CACHE_CONTROL  0x00000010
#define NJT_HTTP_UPSTREAM_IGN_SET_COOKIE     0x00000020
#define NJT_HTTP_UPSTREAM_IGN_XA_LIMIT_RATE  0x00000040
#define NJT_HTTP_UPSTREAM_IGN_XA_BUFFERING   0x00000080
#define NJT_HTTP_UPSTREAM_IGN_XA_CHARSET     0x00000100
#define NJT_HTTP_UPSTREAM_IGN_VARY           0x00000200


typedef struct {
    njt_uint_t                       status;
    njt_msec_t                       response_time;
    njt_msec_t                       connect_time;
    njt_msec_t                       header_time;
    njt_msec_t                       queue_time;
    off_t                            response_length;
    off_t                            bytes_received;
    off_t                            bytes_sent;

    njt_str_t                       *peer;
} njt_http_upstream_state_t;


typedef struct {
    njt_hash_t                       headers_in_hash;
    njt_array_t                      upstreams;
                                             /* njt_http_upstream_srv_conf_t */
} njt_http_upstream_main_conf_t;

typedef struct njt_http_upstream_srv_conf_s  njt_http_upstream_srv_conf_t;

typedef njt_int_t (*njt_http_upstream_init_pt)(njt_conf_t *cf,
    njt_http_upstream_srv_conf_t *us);
typedef njt_int_t (*njt_http_upstream_init_peer_pt)(njt_http_request_t *r,
    njt_http_upstream_srv_conf_t *us);


typedef struct {
    njt_http_upstream_init_pt        init_upstream;
    njt_http_upstream_init_peer_pt   init;
    void                            *data;
} njt_http_upstream_peer_t;


typedef struct {
    njt_str_t                        name;
    njt_addr_t                      *addrs;
    njt_uint_t                       naddrs;
    njt_uint_t                       weight;
    njt_uint_t                       max_conns;
    njt_uint_t                       max_fails;
    time_t                           fail_timeout;
    njt_msec_t                       slow_start;
    njt_uint_t                       down;

    unsigned                         backup:1;
#if (NJT_HTTP_UPSTREAM_DYNAMIC_SERVER)
    unsigned                         dynamic:1;
    njt_int_t                        parent_id;
    njt_str_t                        route;
#endif
    NJT_COMPAT_BEGIN(6)
    NJT_COMPAT_END
} njt_http_upstream_server_t;


#define NJT_HTTP_UPSTREAM_CREATE        0x0001
#define NJT_HTTP_UPSTREAM_WEIGHT        0x0002
#define NJT_HTTP_UPSTREAM_MAX_FAILS     0x0004
#define NJT_HTTP_UPSTREAM_FAIL_TIMEOUT  0x0008
#define NJT_HTTP_UPSTREAM_DOWN          0x0010
#define NJT_HTTP_UPSTREAM_BACKUP        0x0020
#define NJT_HTTP_UPSTREAM_MAX_CONNS     0x0100
#define NJT_HTTP_UPSTREAM_SLOW_START    0x0200

/////动态upstream
#define NJT_HTTP_DYNAMIC_UPSTREAM       1
 ////////
 struct njt_http_upstream_srv_conf_s {
    njt_http_upstream_peer_t         peer;
    void                           **srv_conf;

    njt_array_t                     *servers;  /* njt_http_upstream_server_t */

    njt_uint_t                       flags;
    njt_str_t                        host;
    u_char                          *file_name;
    njt_uint_t                       line;
    in_port_t                        port;
    njt_uint_t                       no_port;  /* unsigned no_port:1 */

#if (NJT_HTTP_UPSTREAM_ZONE)
    njt_shm_zone_t                  *shm_zone;
    njt_uint_t                       update_id;
#endif
#if (NJT_HTTP_UPSTREAM_DYNAMIC_SERVER)
    njt_str_t                       state_file;
    njt_resolver_t                 *resolver;/* resolver */
    njt_msec_t                      resolver_timeout;
    time_t                          valid;
    unsigned                         set_keep_alive:1;
    unsigned                         hc_type:2;
    unsigned                         reload:1;
    unsigned					     persistent:1;
    unsigned						 mandatory:1;
#endif
#if (NJT_HTTP_DYNAMIC_UPSTREAM)
    njt_uint_t   ref_count;
    njt_pool_t   *pool;
#endif
};


typedef struct {
    njt_addr_t                      *addr;
    njt_http_complex_value_t        *value;
#if (NJT_HAVE_TRANSPARENT_PROXY)
    njt_uint_t                       transparent; /* unsigned  transparent:1; */
#endif
} njt_http_upstream_local_t;


typedef struct {
    njt_http_upstream_srv_conf_t    *upstream;

    njt_msec_t                       connect_timeout;
    njt_msec_t                       send_timeout;
    njt_msec_t                       read_timeout;
    njt_msec_t                       next_upstream_timeout;

    size_t                           send_lowat;
    size_t                           buffer_size;
    size_t                           limit_rate;

    size_t                           busy_buffers_size;
    size_t                           max_temp_file_size;
    size_t                           temp_file_write_size;

    size_t                           busy_buffers_size_conf;
    size_t                           max_temp_file_size_conf;
    size_t                           temp_file_write_size_conf;

    njt_bufs_t                       bufs;

    njt_uint_t                       ignore_headers;
    njt_uint_t                       next_upstream;
    njt_uint_t                       store_access;
    njt_uint_t                       next_upstream_tries;
    njt_flag_t                       buffering;
    njt_flag_t                       request_buffering;
    njt_flag_t                       pass_request_headers;
    njt_flag_t                       pass_request_body;

    njt_flag_t                       ignore_client_abort;
    njt_flag_t                       intercept_errors;
    njt_flag_t                       cyclic_temp_file;
    njt_flag_t                       force_ranges;

    njt_path_t                      *temp_path;

    njt_hash_t                       hide_headers_hash;
    njt_array_t                     *hide_headers;
    njt_array_t                     *pass_headers;

    njt_http_upstream_local_t       *local;
    njt_flag_t                       socket_keepalive;

#if (NJT_HTTP_CACHE)
    njt_shm_zone_t                  *cache_zone;
    njt_http_complex_value_t        *cache_value;

    njt_uint_t                       cache_min_uses;
    njt_uint_t                       cache_use_stale;
    njt_uint_t                       cache_methods;

    off_t                            cache_max_range_offset;

    njt_flag_t                       cache_lock;
    njt_msec_t                       cache_lock_timeout;
    njt_msec_t                       cache_lock_age;

    njt_flag_t                       cache_revalidate;
    njt_flag_t                       cache_convert_head;
    njt_flag_t                       cache_background_update;

    njt_array_t                     *cache_valid;
    njt_array_t                     *cache_bypass;
    njt_array_t                     *cache_purge;
    njt_array_t                     *no_cache;
#endif

    njt_array_t                     *store_lengths;
    njt_array_t                     *store_values;

#if (NJT_HTTP_CACHE)
    signed                           cache:2;
#endif
    signed                           store:2;
    unsigned                         intercept_404:1;
    unsigned                         change_buffering:1;
    unsigned                         pass_trailers:1;
    unsigned                         preserve_output:1;

#if (NJT_HTTP_SSL || NJT_COMPAT)
    njt_ssl_t                       *ssl;
    njt_flag_t                       ssl_session_reuse;

    njt_http_complex_value_t        *ssl_name;
    njt_flag_t                       ssl_server_name;
    njt_flag_t                       ssl_verify;

    njt_http_complex_value_t        *ssl_certificate;
    njt_http_complex_value_t        *ssl_certificate_key;
    njt_array_t                     *ssl_passwords;

#if (NJT_HTTP_MULTICERT)
    njt_array_t                     *ssl_certificates;
    njt_array_t                     *ssl_certificate_keys;

    njt_array_t                     *ssl_certificate_values;
    njt_array_t                     *ssl_certificate_key_values;
#endif

#if (NJT_HAVE_NTLS)
    njt_flag_t                      ssl_ntls;
    njt_str_t                       ssl_ciphers;
#endif

#endif

    njt_str_t                        module;

    NJT_COMPAT_BEGIN(2)
    NJT_COMPAT_END
} njt_http_upstream_conf_t;


typedef struct {
    njt_str_t                        name;
    njt_http_header_handler_pt       handler;
    njt_uint_t                       offset;
    njt_http_header_handler_pt       copy_handler;
    njt_uint_t                       conf;
    njt_uint_t                       redirect;  /* unsigned   redirect:1; */
} njt_http_upstream_header_t;


typedef struct {
    njt_list_t                       headers;
    njt_list_t                       trailers;

    njt_uint_t                       status_n;
    njt_str_t                        status_line;

    njt_table_elt_t                 *status;
    njt_table_elt_t                 *date;
    njt_table_elt_t                 *server;
    njt_table_elt_t                 *connection;

    njt_table_elt_t                 *expires;
    njt_table_elt_t                 *etag;
    njt_table_elt_t                 *x_accel_expires;
    njt_table_elt_t                 *x_accel_redirect;
    njt_table_elt_t                 *x_accel_limit_rate;

    njt_table_elt_t                 *content_type;
    njt_table_elt_t                 *content_length;

    njt_table_elt_t                 *last_modified;
    njt_table_elt_t                 *location;
    njt_table_elt_t                 *refresh;
    njt_table_elt_t                 *www_authenticate;
    njt_table_elt_t                 *transfer_encoding;
    njt_table_elt_t                 *vary;

    njt_table_elt_t                 *cache_control;
    njt_table_elt_t                 *set_cookie;

    off_t                            content_length_n;
    time_t                           last_modified_time;

    unsigned                         connection_close:1;
    unsigned                         chunked:1;
    unsigned                         no_cache:1;
    unsigned                         expired:1;
} njt_http_upstream_headers_in_t;


typedef struct {
    njt_str_t                        host;
    in_port_t                        port;
    njt_uint_t                       no_port; /* unsigned no_port:1 */

    njt_uint_t                       naddrs;
    njt_resolver_addr_t             *addrs;

    struct sockaddr                 *sockaddr;
    socklen_t                        socklen;
    njt_str_t                        name;

    njt_resolver_ctx_t              *ctx;
} njt_http_upstream_resolved_t;


typedef void (*njt_http_upstream_handler_pt)(njt_http_request_t *r,
    njt_http_upstream_t *u);


struct njt_http_upstream_s {
    njt_http_upstream_handler_pt     read_event_handler;
    njt_http_upstream_handler_pt     write_event_handler;

    njt_peer_connection_t            peer;

    njt_event_pipe_t                *pipe;

    njt_chain_t                     *request_bufs;

    njt_output_chain_ctx_t           output;
    njt_chain_writer_ctx_t           writer;

    njt_http_upstream_conf_t        *conf;
    njt_http_upstream_srv_conf_t    *upstream;
#if (NJT_HTTP_CACHE)
    njt_array_t                     *caches;
#endif

    // openresty patch
#define HAVE_NJT_UPSTREAM_TIMEOUT_FIELDS  1
    njt_msec_t                       connect_timeout;
    njt_msec_t                       send_timeout;
    njt_msec_t                       read_timeout;
    // openresty patch end

    njt_http_upstream_headers_in_t   headers_in;

    njt_http_upstream_resolved_t    *resolved;

    njt_buf_t                        from_client;

    njt_buf_t                        buffer;
    off_t                            length;

    njt_chain_t                     *out_bufs;
    njt_chain_t                     *busy_bufs;
    njt_chain_t                     *free_bufs;

    njt_int_t                      (*input_filter_init)(void *data);
    njt_int_t                      (*input_filter)(void *data, ssize_t bytes);
    void                            *input_filter_ctx;

#if (NJT_HTTP_CACHE)
    njt_int_t                      (*create_key)(njt_http_request_t *r);
#endif
    njt_int_t                      (*create_request)(njt_http_request_t *r);
    njt_int_t                      (*reinit_request)(njt_http_request_t *r);
    njt_int_t                      (*process_header)(njt_http_request_t *r);
    void                           (*abort_request)(njt_http_request_t *r);
    void                           (*finalize_request)(njt_http_request_t *r,
                                         njt_int_t rc);
    njt_int_t                      (*rewrite_redirect)(njt_http_request_t *r,
                                         njt_table_elt_t *h, size_t prefix);
    njt_int_t                      (*rewrite_cookie)(njt_http_request_t *r,
                                         njt_table_elt_t *h);

    njt_msec_t                       start_time;
    njt_msec_t                       req_delay;

    njt_http_upstream_state_t       *state;

    njt_str_t                        method;
    njt_str_t                        schema;
    njt_str_t                        uri;

#if (NJT_HTTP_SSL || NJT_COMPAT)
    njt_str_t                        ssl_name;
#endif

    njt_http_cleanup_pt             *cleanup;

    unsigned                         store:1;
    unsigned                         cacheable:1;
    unsigned                         accel:1;
    unsigned                         ssl:1;
#if (NJT_HTTP_CACHE)
    unsigned                         cache_status:3;
#endif

    unsigned                         buffering:1;
    unsigned                         keepalive:1;
    unsigned                         upgrade:1;
    unsigned                         error:1;

    unsigned                         request_sent:1;
    unsigned                         request_body_sent:1;
    unsigned                         request_body_blocked:1;
    unsigned                         header_sent:1;
};


typedef struct {
    njt_uint_t                      status;
    njt_uint_t                      mask;
} njt_http_upstream_next_t;


typedef struct {
    njt_str_t   key;
    njt_str_t   value;
    njt_uint_t  skip_empty;
} njt_http_upstream_param_t;


njt_int_t njt_http_upstream_create(njt_http_request_t *r);
void njt_http_upstream_init(njt_http_request_t *r);
njt_int_t njt_http_upstream_non_buffered_filter_init(void *data);
njt_int_t njt_http_upstream_non_buffered_filter(void *data, ssize_t bytes);
njt_http_upstream_srv_conf_t *njt_http_upstream_add(njt_conf_t *cf,
    njt_url_t *u, njt_uint_t flags);
char *njt_http_upstream_bind_set_slot(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *njt_http_upstream_param_set_slot(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
njt_int_t njt_http_upstream_hide_headers_hash(njt_conf_t *cf,
    njt_http_upstream_conf_t *conf, njt_http_upstream_conf_t *prev,
    njt_str_t *default_hide_headers, njt_hash_init_t *hash);


#define njt_http_conf_upstream_srv_conf(uscf, module)                         \
    uscf->srv_conf[module.ctx_index]


extern njt_module_t        njt_http_upstream_module;
extern njt_conf_bitmask_t  njt_http_upstream_cache_method_mask[];
extern njt_conf_bitmask_t  njt_http_upstream_ignore_headers_masks[];


#endif /* _NJT_HTTP_UPSTREAM_H_INCLUDED_ */
