
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_REQUEST_H_INCLUDED_
#define _NJT_HTTP_REQUEST_H_INCLUDED_


#define NJT_HTTP_MAX_URI_CHANGES           10
#define NJT_HTTP_MAX_SUBREQUESTS           50

/* must be 2^n */
#define NJT_HTTP_LC_HEADER_LEN             32


#define NJT_HTTP_DISCARD_BUFFER_SIZE       4096
#define NJT_HTTP_LINGERING_BUFFER_SIZE     4096


#define NJT_HTTP_VERSION_9                 9
#define NJT_HTTP_VERSION_10                1000
#define NJT_HTTP_VERSION_11                1001
#define NJT_HTTP_VERSION_20                2000
#define NJT_HTTP_VERSION_30                3000

#define NJT_HTTP_UNKNOWN                   0x00000001
#define NJT_HTTP_GET                       0x00000002
#define NJT_HTTP_HEAD                      0x00000004
#define NJT_HTTP_POST                      0x00000008
#define NJT_HTTP_PUT                       0x00000010
#define NJT_HTTP_DELETE                    0x00000020
#define NJT_HTTP_MKCOL                     0x00000040
#define NJT_HTTP_COPY                      0x00000080
#define NJT_HTTP_MOVE                      0x00000100
#define NJT_HTTP_OPTIONS                   0x00000200
#define NJT_HTTP_PROPFIND                  0x00000400
#define NJT_HTTP_PROPPATCH                 0x00000800
#define NJT_HTTP_LOCK                      0x00001000
#define NJT_HTTP_UNLOCK                    0x00002000
#define NJT_HTTP_PATCH                     0x00004000
#define NJT_HTTP_TRACE                     0x00008000
#define NJT_HTTP_CONNECT                   0x00010000

#define NJT_HTTP_CONNECTION_CLOSE          1
#define NJT_HTTP_CONNECTION_KEEP_ALIVE     2


#define NJT_NONE                           1


#define NJT_HTTP_PARSE_HEADER_DONE         1

#define NJT_HTTP_CLIENT_ERROR              10
#define NJT_HTTP_PARSE_INVALID_METHOD      10
#define NJT_HTTP_PARSE_INVALID_REQUEST     11
#define NJT_HTTP_PARSE_INVALID_VERSION     12
#define NJT_HTTP_PARSE_INVALID_09_METHOD   13

#define NJT_HTTP_PARSE_INVALID_HEADER      14


/* unused                                  1 */
#define NJT_HTTP_SUBREQUEST_IN_MEMORY      2
#define NJT_HTTP_SUBREQUEST_WAITED         4
#define NJT_HTTP_SUBREQUEST_CLONE          8
#define NJT_HTTP_SUBREQUEST_BACKGROUND     16

#define NJT_HTTP_LOG_UNSAFE                1


#define NJT_HTTP_CONTINUE                  100
#define NJT_HTTP_SWITCHING_PROTOCOLS       101
#define NJT_HTTP_PROCESSING                102

#define NJT_HTTP_OK                        200
#define NJT_HTTP_CREATED                   201
#define NJT_HTTP_ACCEPTED                  202
#define NJT_HTTP_NO_CONTENT                204
#define NJT_HTTP_PARTIAL_CONTENT           206

#define NJT_HTTP_SPECIAL_RESPONSE          300
#define NJT_HTTP_MOVED_PERMANENTLY         301
#define NJT_HTTP_MOVED_TEMPORARILY         302
#define NJT_HTTP_SEE_OTHER                 303
#define NJT_HTTP_NOT_MODIFIED              304
#define NJT_HTTP_TEMPORARY_REDIRECT        307
#define NJT_HTTP_PERMANENT_REDIRECT        308

#define NJT_HTTP_BAD_REQUEST               400
#define NJT_HTTP_UNAUTHORIZED              401
#define NJT_HTTP_FORBIDDEN                 403
#define NJT_HTTP_NOT_FOUND                 404
#define NJT_HTTP_NOT_ALLOWED               405
#define NJT_HTTP_REQUEST_TIME_OUT          408
#define NJT_HTTP_CONFLICT                  409
#define NJT_HTTP_LENGTH_REQUIRED           411
#define NJT_HTTP_PRECONDITION_FAILED       412
#define NJT_HTTP_REQUEST_ENTITY_TOO_LARGE  413
#define NJT_HTTP_REQUEST_URI_TOO_LARGE     414
#define NJT_HTTP_UNSUPPORTED_MEDIA_TYPE    415
#define NJT_HTTP_RANGE_NOT_SATISFIABLE     416
#define NJT_HTTP_MISDIRECTED_REQUEST       421
#define NJT_HTTP_TOO_MANY_REQUESTS         429


/* Our own HTTP codes */

/* The special code to close connection without any response */
#define NJT_HTTP_CLOSE                     444

#define NJT_HTTP_NJT_CODES               494

#define NJT_HTTP_REQUEST_HEADER_TOO_LARGE  494

#define NJT_HTTPS_CERT_ERROR               495
#define NJT_HTTPS_NO_CERT                  496

/*
 * We use the special code for the plain HTTP requests that are sent to
 * HTTPS port to distinguish it from 4XX in an error page redirection
 */
#define NJT_HTTP_TO_HTTPS                  497

/* 498 is the canceled code for the requests with invalid host name */

/*
 * HTTP does not define the code for the case when a client closed
 * the connection while we are processing its request so we introduce
 * own code to log such situation when a client has closed the connection
 * before we even try to send the HTTP header to it
 */
#define NJT_HTTP_CLIENT_CLOSED_REQUEST     499


#define NJT_HTTP_INTERNAL_SERVER_ERROR     500
#define NJT_HTTP_NOT_IMPLEMENTED           501
#define NJT_HTTP_BAD_GATEWAY               502
#define NJT_HTTP_SERVICE_UNAVAILABLE       503
#define NJT_HTTP_GATEWAY_TIME_OUT          504
#define NJT_HTTP_VERSION_NOT_SUPPORTED     505
#define NJT_HTTP_INSUFFICIENT_STORAGE      507


#define NJT_HTTP_LOWLEVEL_BUFFERED         0xf0
#define NJT_HTTP_WRITE_BUFFERED            0x10
#define NJT_HTTP_GZIP_BUFFERED             0x20
#define NJT_HTTP_SSI_BUFFERED              0x01
#define NJT_HTTP_SUB_BUFFERED              0x02
#define NJT_HTTP_COPY_BUFFERED             0x04


typedef enum {
    NJT_HTTP_INITING_REQUEST_STATE = 0,
    NJT_HTTP_READING_REQUEST_STATE,
    NJT_HTTP_PROCESS_REQUEST_STATE,

    NJT_HTTP_CONNECT_UPSTREAM_STATE,
    NJT_HTTP_WRITING_UPSTREAM_STATE,
    NJT_HTTP_READING_UPSTREAM_STATE,

    NJT_HTTP_WRITING_REQUEST_STATE,
    NJT_HTTP_LINGERING_CLOSE_STATE,
    NJT_HTTP_KEEPALIVE_STATE
} njt_http_state_e;


typedef struct {
    njt_str_t                         name;
    njt_uint_t                        offset;
    njt_http_header_handler_pt        handler;
} njt_http_header_t;


typedef struct {
    njt_str_t                         name;
    njt_uint_t                        offset;
} njt_http_header_out_t;


typedef struct {
    njt_list_t                        headers;

    njt_table_elt_t                  *host;
    njt_table_elt_t                  *connection;
    njt_table_elt_t                  *if_modified_since;
    njt_table_elt_t                  *if_unmodified_since;
    njt_table_elt_t                  *if_match;
    njt_table_elt_t                  *if_none_match;
    njt_table_elt_t                  *user_agent;
    njt_table_elt_t                  *referer;
    njt_table_elt_t                  *content_length;
    njt_table_elt_t                  *content_range;
    njt_table_elt_t                  *content_type;

    njt_table_elt_t                  *range;
    njt_table_elt_t                  *if_range;

    njt_table_elt_t                  *transfer_encoding;
    njt_table_elt_t                  *te;
    njt_table_elt_t                  *expect;
    njt_table_elt_t                  *upgrade;

#if (NJT_HTTP_GZIP || NJT_HTTP_HEADERS)
    njt_table_elt_t                  *accept_encoding;
    njt_table_elt_t                  *via;
#endif

    njt_table_elt_t                  *authorization;

    njt_table_elt_t                  *keep_alive;

#if (NJT_HTTP_X_FORWARDED_FOR)
    njt_table_elt_t                  *x_forwarded_for;
#endif

#if (NJT_HTTP_REALIP)
    njt_table_elt_t                  *x_real_ip;
#endif

#if (NJT_HTTP_HEADERS)
    njt_table_elt_t                  *accept;
    njt_table_elt_t                  *accept_language;
#endif

#if (NJT_HTTP_DAV)
    njt_table_elt_t                  *depth;
    njt_table_elt_t                  *destination;
    njt_table_elt_t                  *overwrite;
    njt_table_elt_t                  *date;
#endif

    njt_table_elt_t                  *cookie;

    njt_str_t                         user;
    njt_str_t                         passwd;

    njt_str_t                         server;
    off_t                             content_length_n;
    time_t                            keep_alive_n;

    unsigned                          connection_type:2;
    unsigned                          chunked:1;
    unsigned                          multi:1;
    unsigned                          multi_linked:1;
    unsigned                          msie:1;
    unsigned                          msie6:1;
    unsigned                          opera:1;
    unsigned                          gecko:1;
    unsigned                          chrome:1;
    unsigned                          safari:1;
    unsigned                          konqueror:1;
} njt_http_headers_in_t;


typedef struct {
    njt_list_t                        headers;
    njt_list_t                        trailers;

    njt_uint_t                        status;
    njt_str_t                         status_line;

    njt_table_elt_t                  *server;
    njt_table_elt_t                  *date;
    njt_table_elt_t                  *content_length;
    njt_table_elt_t                  *content_encoding;
    njt_table_elt_t                  *location;
    njt_table_elt_t                  *refresh;
    njt_table_elt_t                  *last_modified;
    njt_table_elt_t                  *content_range;
    njt_table_elt_t                  *accept_ranges;
    njt_table_elt_t                  *www_authenticate;
    njt_table_elt_t                  *expires;
    njt_table_elt_t                  *etag;

    njt_table_elt_t                  *cache_control;
    njt_table_elt_t                  *link;

    njt_str_t                        *override_charset;

    size_t                            content_type_len;
    njt_str_t                         content_type;
    njt_str_t                         charset;
    u_char                           *content_type_lowcase;
    njt_uint_t                        content_type_hash;

    off_t                             content_length_n;
    off_t                             content_offset;
    time_t                            date_time;
    time_t                            last_modified_time;
} njt_http_headers_out_t;


typedef void (*njt_http_client_body_handler_pt)(njt_http_request_t *r);

typedef struct {
    njt_temp_file_t                  *temp_file;
    njt_chain_t                      *bufs;
    njt_buf_t                        *buf;
    off_t                             rest;
    off_t                             received;
    njt_chain_t                      *free;
    njt_chain_t                      *busy;
    njt_http_chunked_t               *chunked;
    njt_http_client_body_handler_pt   post_handler;
    unsigned                          filter_need_buffering:1;
    unsigned                          last_sent:1;
    unsigned                          last_saved:1;
} njt_http_request_body_t;


typedef struct njt_http_addr_conf_s  njt_http_addr_conf_t;

typedef struct {
    njt_http_addr_conf_t             *addr_conf;
    njt_http_conf_ctx_t              *conf_ctx;

#if (NJT_HTTP_SSL || NJT_COMPAT)
    njt_str_t                        *ssl_servername;
#if (NJT_PCRE)
    njt_http_regex_t                 *ssl_servername_regex;
#endif
#endif

    njt_chain_t                      *busy;
    njt_int_t                         nbusy;

    njt_chain_t                      *free;

    unsigned                          ssl:1;
    unsigned                          proxy_protocol:1;
} njt_http_connection_t;


typedef void (*njt_http_cleanup_pt)(void *data);

typedef struct njt_http_cleanup_s  njt_http_cleanup_t;

struct njt_http_cleanup_s {
    njt_http_cleanup_pt               handler;
    void                             *data;
    njt_http_cleanup_t               *next;
};


typedef njt_int_t (*njt_http_post_subrequest_pt)(njt_http_request_t *r,
    void *data, njt_int_t rc);

typedef struct {
    njt_http_post_subrequest_pt       handler;
    void                             *data;
} njt_http_post_subrequest_t;


typedef struct njt_http_postponed_request_s  njt_http_postponed_request_t;

struct njt_http_postponed_request_s {
    njt_http_request_t               *request;
    njt_chain_t                      *out;
    njt_http_postponed_request_t     *next;
};


typedef struct njt_http_posted_request_s  njt_http_posted_request_t;

struct njt_http_posted_request_s {
    njt_http_request_t               *request;
    njt_http_posted_request_t        *next;
};


typedef njt_int_t (*njt_http_handler_pt)(njt_http_request_t *r);
typedef void (*njt_http_event_handler_pt)(njt_http_request_t *r);


struct njt_http_request_s {
    uint32_t                          signature;         /* "HTTP" */

    njt_connection_t                 *connection;

    void                            **ctx;
    void                            **main_conf;
    void                            **srv_conf;
    void                            **loc_conf;

    njt_http_event_handler_pt         read_event_handler;
    njt_http_event_handler_pt         write_event_handler;

#if (NJT_HTTP_CACHE)
    njt_http_cache_t                 *cache;
#endif

    njt_http_upstream_t              *upstream;
    njt_array_t                      *upstream_states;
                                         /* of njt_http_upstream_state_t */

    njt_pool_t                       *pool;
    njt_buf_t                        *header_in;

    njt_http_headers_in_t             headers_in;
    njt_http_headers_out_t            headers_out;

    njt_http_request_body_t          *request_body;

    time_t                            lingering_time;
    time_t                            start_sec;
    njt_msec_t                        start_msec;

    njt_uint_t                        method;
    njt_uint_t                        http_version;

    njt_str_t                         request_line;
    njt_str_t                         uri;
    njt_str_t                         uri_key;
    njt_str_t                         args;
    njt_str_t                         exten;
    njt_str_t                         tmp_location_name;     //add by clb
    njt_str_t                         unparsed_uri;
//add by clb
#if (NJT_HTTP_PROXY_CONNECT)
    njt_str_t                         connect_host;
    njt_str_t                         connect_port;
    in_port_t                         connect_port_n;
    u_char                           *connect_host_start;
    u_char                           *connect_host_end;
    u_char                           *connect_port_end;
#endif

    njt_str_t                         method_name;
    njt_str_t                         http_protocol;
    njt_str_t                         schema;

    njt_chain_t                      *out;
    njt_http_request_t               *main;
    njt_http_request_t               *parent;
    njt_http_postponed_request_t     *postponed;
    njt_http_post_subrequest_t       *post_subrequest;
    njt_http_posted_request_t        *posted_requests;

    njt_int_t                         phase_handler;
    njt_http_handler_pt               content_handler;
    njt_uint_t                        access_code;

    njt_http_variable_value_t        *variables;

#if (NJT_PCRE)
    njt_uint_t                        ncaptures;
    int                              *captures;
    u_char                           *captures_data;
#endif

    size_t                            limit_rate;
    size_t                            limit_rate_after;

    /* used to learn the Apache compatible response length without a header */
    size_t                            header_size;

    off_t                             request_length;

    njt_uint_t                        err_status;

    njt_http_connection_t            *http_connection;
    njt_http_v2_stream_t             *stream;
    njt_http_v3_parse_t              *v3_parse;

    njt_http_log_handler_pt           log_handler;

    njt_http_cleanup_t               *cleanup;

    unsigned                          count:16;
    unsigned                          subrequests:8;
    unsigned                          blocked:8;

    unsigned                          aio:1;

    unsigned                          http_state:4;

    /* URI with "/." and on Win32 with "//" */
    unsigned                          complex_uri:1;

    /* URI with "%" */
    unsigned                          quoted_uri:1;

    /* URI with "+" */
    unsigned                          plus_in_uri:1;

    /* URI with empty path */
    unsigned                          empty_path_in_uri:1;

    unsigned                          invalid_header:1;

    unsigned                          add_uri_to_alias:1;
    unsigned                          valid_location:1;
    unsigned                          valid_unparsed_uri:1;
    unsigned                          uri_changed:1;
    unsigned                          uri_changes:4;

    unsigned                          request_body_in_single_buf:1;
    unsigned                          request_body_in_file_only:1;
    unsigned                          request_body_in_persistent_file:1;
    unsigned                          request_body_in_clean_file:1;
    unsigned                          request_body_file_group_access:1;
    unsigned                          request_body_file_log_level:3;
    unsigned                          request_body_no_buffering:1;

    unsigned                          subrequest_in_memory:1;
    unsigned                          waited:1;

#if (NJT_HTTP_CACHE)
    unsigned                          cached:1;
#endif

#if (NJT_HTTP_GZIP)
    unsigned                          gzip_tested:1;
    unsigned                          gzip_ok:1;
    unsigned                          gzip_vary:1;
#endif

#if (NJT_PCRE)
    unsigned                          realloc_captures:1;
#endif

    unsigned                          proxy:1;
    unsigned                          bypass_cache:1;
    unsigned                          no_cache:1;

    /*
     * instead of using the request context data in
     * njt_http_limit_conn_module and njt_http_limit_req_module
     * we use the bit fields in the request structure
     */
    unsigned                          limit_conn_status:2;
    unsigned                          limit_req_status:3;

    unsigned                          limit_rate_set:1;
    unsigned                          limit_rate_after_set:1;

#if 0
    unsigned                          cacheable:1;
#endif

    unsigned                          pipeline:1;
    unsigned                          chunked:1;
    unsigned                          header_only:1;
    unsigned                          expect_trailers:1;
    unsigned                          keepalive:1;
    unsigned                          lingering_close:1;
    unsigned                          discard_body:1;
    unsigned                          reading_body:1;
    unsigned                          internal:1;
    unsigned                          error_page:1;
    unsigned                          filter_finalize:1;
    unsigned                          post_action:1;
    unsigned                          request_complete:1;
    unsigned                          request_output:1;
    unsigned                          header_sent:1;
    unsigned                          response_sent:1;
    unsigned                          expect_tested:1;
    unsigned                          root_tested:1;
    unsigned                          done:1;
    unsigned                          logged:1;

    unsigned                          buffered:4;

    unsigned                          main_filter_need_in_memory:1;
    unsigned                          filter_need_in_memory:1;
    unsigned                          filter_need_temporary:1;
    unsigned                          preserve_body:1;
    unsigned                          allow_ranges:1;
    unsigned                          subrequest_ranges:1;
    unsigned                          single_range:1;
    unsigned                          disable_not_modified:1;
    unsigned                          stat_reading:1;
    unsigned                          stat_writing:1;
    unsigned                          stat_processing:1;

    unsigned                          background:1;
    unsigned                          health_check:1;

    /* used to parse HTTP headers */

    njt_uint_t                        state;

    njt_uint_t                        header_hash;
    njt_uint_t                        lowcase_index;
    u_char                            lowcase_header[NJT_HTTP_LC_HEADER_LEN];

    u_char                           *header_name_start;
    u_char                           *header_name_end;
    u_char                           *header_start;
    u_char                           *header_end;

    /*
     * a memory that can be reused after parsing a request line
     * via njt_http_ephemeral_t
     */

    u_char                           *uri_start;
    u_char                           *uri_end;
    u_char                           *uri_ext;
    u_char                           *args_start;
    u_char                           *request_start;
    u_char                           *request_end;
    u_char                           *method_end;
    u_char                           *schema_start;
    u_char                           *schema_end;
    u_char                           *host_start;
    u_char                           *host_end;
    u_char                           *port_start;
    u_char                           *port_end;

    unsigned                          http_minor:16;
    unsigned                          http_major:16;
    // by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
    //unsigned                          used_ref;
#endif
    //end

    //add by clb
#if (NJT_HTTP_FAULT_INJECT)
      //used for fault inject of delay
    njt_uint_t                        abort_flag;
    njt_event_t                      *delay_timer;
#endif
};


typedef struct {
    njt_http_posted_request_t         terminal_posted_request;
} njt_http_ephemeral_t;


#define njt_http_ephemeral(r)  (void *) (&r->uri_start)


extern njt_http_header_t       njt_http_headers_in[];
extern njt_http_header_out_t   njt_http_headers_out[];


#define njt_http_set_log_request(log, r)                                      \
    ((njt_http_log_ctx_t *) log->data)->current_request = r


#endif /* _NJT_HTTP_REQUEST_H_INCLUDED_ */
