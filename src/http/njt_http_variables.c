
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njet.h>


static njt_http_variable_t *njt_http_add_prefix_variable(njt_conf_t *cf,
    njt_str_t *name, njt_uint_t flags);

static njt_int_t njt_http_variable_request(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
#if 0
static void njt_http_variable_request_set(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
#endif
static njt_int_t njt_http_variable_request_get_size(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_header(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);

static njt_int_t njt_http_variable_cookies(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_headers_internal(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data, u_char sep);

static njt_int_t njt_http_variable_unknown_header_in(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_unknown_header_out(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_unknown_trailer_out(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_request_line(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_cookie(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_argument(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
#if (NJT_HAVE_TCP_INFO)
static njt_int_t njt_http_variable_tcpinfo(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
#endif

static njt_int_t njt_http_variable_content_length(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_host(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_binary_remote_addr(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_remote_addr(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_remote_port(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_proxy_protocol_addr(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_proxy_protocol_port(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_server_addr(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_server_port(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_scheme(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_https(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static void njt_http_variable_set_args(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_is_args(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_document_root(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_realpath_root(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_request_filename(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_server_name(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_request_method(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_remote_user(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_bytes_sent(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_body_bytes_sent(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_pipe(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_request_completion(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_request_body(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_request_body_file(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_request_length(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_request_time(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_request_id(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_status(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);

static njt_int_t njt_http_variable_sent_content_type(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_sent_content_length(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_sent_location(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_sent_last_modified(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_sent_connection(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_sent_keep_alive(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_sent_transfer_encoding(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static void njt_http_variable_set_limit_rate(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);

static njt_int_t njt_http_variable_connection(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_connection_requests(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_connection_time(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);

static njt_int_t njt_http_variable_njet_version(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_hostname(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_pid(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_msec(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_time_iso8601(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_time_local(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static void njt_http_variable_set_uri_key(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_variable_get_uri_key(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t
njt_http_variable_proxy_protocol_tlv(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
/*
 * TODO:
 *     Apache CGI: AUTH_TYPE, PATH_INFO (null), PATH_TRANSLATED
 *                 REMOTE_HOST (null), REMOTE_IDENT (null),
 *                 SERVER_SOFTWARE
 *
 *     Apache SSI: DOCUMENT_NAME, LAST_MODIFIED, USER_NAME (file owner)
 */

/*
 * the $http_host, $http_user_agent, $http_referer, and $http_via
 * variables may be handled by generic
 * njt_http_variable_unknown_header_in(), but for performance reasons
 * they are handled using dedicated entries
 */

static njt_http_variable_t  njt_http_core_variables[] = {
//add by clb
#if (NJT_HTTP_PROXY_CONNECT)
    { njt_string("connect_host"), NULL, njt_http_variable_request,
      offsetof(njt_http_request_t, connect_host), 0, 0,
      NJT_VAR_INIT_REF_COUNT },

    { njt_string("connect_port"), NULL, njt_http_variable_request,
      offsetof(njt_http_request_t, connect_port), 0, 0,
      NJT_VAR_INIT_REF_COUNT },
#endif

    { njt_string("http_host"), NULL, njt_http_variable_header,
      offsetof(njt_http_request_t, headers_in.host), 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("http_user_agent"), NULL, njt_http_variable_header,
      offsetof(njt_http_request_t, headers_in.user_agent), 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("http_referer"), NULL, njt_http_variable_header,
      offsetof(njt_http_request_t, headers_in.referer), 0, 0, NJT_VAR_INIT_REF_COUNT },

#if (NJT_HTTP_GZIP)
    { njt_string("http_via"), NULL, njt_http_variable_header,
      offsetof(njt_http_request_t, headers_in.via), 0, 0, NJT_VAR_INIT_REF_COUNT },
#endif

#if (NJT_HTTP_X_FORWARDED_FOR)
    { njt_string("http_x_forwarded_for"), NULL, njt_http_variable_header,
      offsetof(njt_http_request_t, headers_in.x_forwarded_for), 0, 0, NJT_VAR_INIT_REF_COUNT },
#endif

    { njt_string("http_cookie"), NULL, njt_http_variable_cookies,
      offsetof(njt_http_request_t, headers_in.cookie), 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("content_length"), NULL, njt_http_variable_content_length,
      0, 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("content_type"), NULL, njt_http_variable_header,
      offsetof(njt_http_request_t, headers_in.content_type), 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("host"), NULL, njt_http_variable_host, 0, 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("binary_remote_addr"), NULL,
      njt_http_variable_binary_remote_addr, 0, 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("remote_addr"), NULL, njt_http_variable_remote_addr, 0, 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("remote_port"), NULL, njt_http_variable_remote_port, 0, 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("proxy_protocol_addr"), NULL,
      njt_http_variable_proxy_protocol_addr,
      offsetof(njt_proxy_protocol_t, src_addr), 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("proxy_protocol_port"), NULL,
      njt_http_variable_proxy_protocol_port,
      offsetof(njt_proxy_protocol_t, src_port), 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("proxy_protocol_server_addr"), NULL,
      njt_http_variable_proxy_protocol_addr,
      offsetof(njt_proxy_protocol_t, dst_addr), 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("proxy_protocol_server_port"), NULL,
      njt_http_variable_proxy_protocol_port,
      offsetof(njt_proxy_protocol_t, dst_port), 0, 0, NJT_VAR_INIT_REF_COUNT },
    { njt_string("proxy_protocol_tlv_"), NULL,
      njt_http_variable_proxy_protocol_tlv,
      0, NJT_HTTP_VAR_PREFIX, 0,NJT_VAR_INIT_REF_COUNT},
    { njt_string("server_addr"), NULL, njt_http_variable_server_addr, 0, 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("server_port"), NULL, njt_http_variable_server_port, 0, 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("server_protocol"), NULL, njt_http_variable_request,
      offsetof(njt_http_request_t, http_protocol), 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("scheme"), NULL, njt_http_variable_scheme, 0, 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("https"), NULL, njt_http_variable_https, 0, 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("request_uri"), NULL, njt_http_variable_request,
      offsetof(njt_http_request_t, unparsed_uri), 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("uri"), NULL, njt_http_variable_request,
      offsetof(njt_http_request_t, uri),
      NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },
    { njt_string("uri_key"),njt_http_variable_set_uri_key,njt_http_variable_get_uri_key,
      offsetof(njt_http_request_t, uri_key),
      NJT_HTTP_VAR_CHANGEABLE|NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },
    { njt_string("document_uri"), NULL, njt_http_variable_request,
      offsetof(njt_http_request_t, uri),
      NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("request"), NULL, njt_http_variable_request_line, 0, 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("document_root"), NULL,
      njt_http_variable_document_root, 0, NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("realpath_root"), NULL,
      njt_http_variable_realpath_root, 0, NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("query_string"), NULL, njt_http_variable_request,
      offsetof(njt_http_request_t, args),
      NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("args"),
      njt_http_variable_set_args,
      njt_http_variable_request,
      offsetof(njt_http_request_t, args),
      NJT_HTTP_VAR_CHANGEABLE|NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("is_args"), NULL, njt_http_variable_is_args,
      0, NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("request_filename"), NULL,
      njt_http_variable_request_filename, 0,
      NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("server_name"), NULL, njt_http_variable_server_name, 0, 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("request_method"), NULL,
      njt_http_variable_request_method, 0,
      NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("remote_user"), NULL, njt_http_variable_remote_user, 0, 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("bytes_sent"), NULL, njt_http_variable_bytes_sent,
      0, 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("body_bytes_sent"), NULL, njt_http_variable_body_bytes_sent,
      0, 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("pipe"), NULL, njt_http_variable_pipe,
      0, 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("request_completion"), NULL,
      njt_http_variable_request_completion,
      0, 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("request_body"), NULL,
      njt_http_variable_request_body,
      0, 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("request_body_file"), NULL,
      njt_http_variable_request_body_file,
      0, 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("request_length"), NULL, njt_http_variable_request_length,
      0, NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("request_time"), NULL, njt_http_variable_request_time,
      0, NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("request_id"), NULL,
      njt_http_variable_request_id,
      0, 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("status"), NULL,
      njt_http_variable_status, 0,
      NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("sent_http_content_type"), NULL,
      njt_http_variable_sent_content_type, 0, 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("sent_http_content_length"), NULL,
      njt_http_variable_sent_content_length, 0, 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("sent_http_location"), NULL,
      njt_http_variable_sent_location, 0, 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("sent_http_last_modified"), NULL,
      njt_http_variable_sent_last_modified, 0, 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("sent_http_connection"), NULL,
      njt_http_variable_sent_connection, 0, 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("sent_http_keep_alive"), NULL,
      njt_http_variable_sent_keep_alive, 0, 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("sent_http_transfer_encoding"), NULL,
      njt_http_variable_sent_transfer_encoding, 0, 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("sent_http_cache_control"), NULL, njt_http_variable_header,
      offsetof(njt_http_request_t, headers_out.cache_control), 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("sent_http_link"), NULL, njt_http_variable_header,
      offsetof(njt_http_request_t, headers_out.link), 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("limit_rate"), njt_http_variable_set_limit_rate,
      njt_http_variable_request_get_size,
      offsetof(njt_http_request_t, limit_rate),
      NJT_HTTP_VAR_CHANGEABLE|NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("connection"), NULL,
      njt_http_variable_connection, 0, 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("connection_requests"), NULL,
      njt_http_variable_connection_requests, 0, 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("connection_time"), NULL, njt_http_variable_connection_time,
      0, NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("njet_version"), NULL, njt_http_variable_njet_version,
      0, 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("hostname"), NULL, njt_http_variable_hostname,
      0, 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("pid"), NULL, njt_http_variable_pid,
      0, 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("msec"), NULL, njt_http_variable_msec,
      0, NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("time_iso8601"), NULL, njt_http_variable_time_iso8601,
      0, NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("time_local"), NULL, njt_http_variable_time_local,
      0, NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

#if (NJT_HAVE_TCP_INFO)
    { njt_string("tcpinfo_rtt"), NULL, njt_http_variable_tcpinfo,
      0, NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("tcpinfo_rttvar"), NULL, njt_http_variable_tcpinfo,
      1, NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("tcpinfo_snd_cwnd"), NULL, njt_http_variable_tcpinfo,
      2, NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("tcpinfo_rcv_space"), NULL, njt_http_variable_tcpinfo,
      3, NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },
#endif

    { njt_string("http_"), NULL, njt_http_variable_unknown_header_in,
      0, NJT_HTTP_VAR_PREFIX, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("sent_http_"), NULL, njt_http_variable_unknown_header_out,
      0, NJT_HTTP_VAR_PREFIX, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("sent_trailer_"), NULL, njt_http_variable_unknown_trailer_out,
      0, NJT_HTTP_VAR_PREFIX, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("cookie_"), NULL, njt_http_variable_cookie,
      0, NJT_HTTP_VAR_PREFIX, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("arg_"), NULL, njt_http_variable_argument,
      0, NJT_HTTP_VAR_NOCACHEABLE|NJT_HTTP_VAR_PREFIX, 0,NJT_VAR_INIT_REF_COUNT},

      njt_http_null_variable
};


njt_http_variable_value_t  njt_http_variable_null_value =
    njt_http_variable("");
njt_http_variable_value_t  njt_http_variable_true_value =
    njt_http_variable("1");


static njt_uint_t  njt_http_variable_depth = 100;


njt_http_variable_t *
njt_http_add_variable(njt_conf_t *cf, njt_str_t *name, njt_uint_t flags)
{
    njt_int_t                   rc;
    njt_uint_t                  i;
    njt_hash_key_t             *key;
    njt_http_variable_t        *v,*free_v;
    njt_http_core_main_conf_t  *cmcf;
	//njt_http_rewrite_loc_conf_t  *rlcf;

    if (name->len == 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid variable name \"$\"");
        return NULL;
    }

    if (flags & NJT_HTTP_VAR_PREFIX) {
        return njt_http_add_prefix_variable(cf, name, flags);
    }

    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);

	//rlcf = njt_http_conf_get_module_main_conf(cf, njt_http_rewrite_module);

	free_v = NULL;
    key = cmcf->variables_keys->keys.elts;
    for (i = 0; i < cmcf->variables_keys->keys.nelts; i++) {
		v = key[i].value;
#if (NJT_HTTP_DYNAMIC_LOC)
		if(v->name.len == 0 && v->name.data == NULL && free_v == NULL){
			free_v = v;
		}
#endif
        if (name->len != key[i].key.len
            || njt_strncasecmp(name->data, key[i].key.data, name->len) != 0)
        {
            continue;
        }

        

        if (!(v->flags & NJT_HTTP_VAR_CHANGEABLE)) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "the duplicate \"%V\" variable", name);
            return NULL;
        }

        if (!(flags & NJT_HTTP_VAR_WEAK)) {
            v->flags &= ~NJT_HTTP_VAR_WEAK;
        }
		v->ref_count++;
        return v;
    }
#if (NJT_HTTP_DYNAMIC_LOC)
			if(free_v == NULL) {
				v = njt_palloc(cmcf->dyn_var_pool, sizeof(njt_http_variable_t));
			} else {
				v = free_v;
			}
#else
    v = njt_palloc(cf->pool, sizeof(njt_http_variable_t));
#endif
    if (v == NULL) {
        return NULL;
    }

    v->name.len = name->len;
#if (NJT_HTTP_DYNAMIC_LOC)
	v->name.data = njt_pnalloc(cmcf->dyn_var_pool, name->len);
	v->ref_count = 1;
#else
    v->name.data = njt_pnalloc(cf->pool, name->len);
#endif
    if (v->name.data == NULL) {
        return NULL;
    }

    njt_strlow(v->name.data, name->data, name->len);

    v->set_handler = NULL;
    v->get_handler = NULL;
    v->data = 0;
    v->flags = flags;
    v->index = 0;

    rc = njt_hash_add_key(cmcf->variables_keys, &v->name, v, 0);

    if (rc == NJT_ERROR) {
        return NULL;
    }
    if (rc == NJT_BUSY) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "conflicting variable name \"%V\"", name);
        return NULL;
    }
#if (NJT_HTTP_DYNAMIC_LOC)
	if(cf->dynamic == 1) {
		v->flags |=  NJT_HTTP_DYN_VAR;
	}
#endif

    return v;
}


static njt_http_variable_t *
njt_http_add_prefix_variable(njt_conf_t *cf, njt_str_t *name, njt_uint_t flags)
{
    njt_uint_t                  i;
    njt_http_variable_t        *v;
    njt_http_core_main_conf_t  *cmcf;

    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);

    v = cmcf->prefix_variables.elts;
    for (i = 0; i < cmcf->prefix_variables.nelts; i++) {
        if (name->len != v[i].name.len
            || njt_strncasecmp(name->data, v[i].name.data, name->len) != 0)
        {
            continue;
        }

        v = &v[i];

        if (!(v->flags & NJT_HTTP_VAR_CHANGEABLE)) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "the duplicate \"%V\" variable", name);
            return NULL;
        }

        if (!(flags & NJT_HTTP_VAR_WEAK)) {
            v->flags &= ~NJT_HTTP_VAR_WEAK;
        }

        return v;
    }

    v = njt_array_push(&cmcf->prefix_variables);
    if (v == NULL) {
        return NULL;
    }

    v->name.len = name->len;
    v->name.data = njt_pnalloc(cf->pool, name->len);
    if (v->name.data == NULL) {
        return NULL;
    }

    njt_strlow(v->name.data, name->data, name->len);

    v->set_handler = NULL;
    v->get_handler = NULL;
    v->data = 0;
    v->flags = flags;
    v->index = 0;

    return v;
}


njt_int_t
njt_http_get_variable_index(njt_conf_t *cf, njt_str_t *name)
{
    njt_uint_t                  i;
    njt_http_variable_t        *v,*free_v;
    njt_http_core_main_conf_t  *cmcf;
	
    if (name->len == 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid variable name \"$\"");
        return NJT_ERROR;
    }

    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);

    v = cmcf->variables.elts;
#if (NJT_HTTP_DYNAMIC_LOC)
	free_v = NULL;
#endif
    if (v == NULL) {
#if (NJT_HTTP_DYNAMIC_LOC)
		 njt_pool_t *new_pool = njt_create_dynamic_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
			if (new_pool == NULL) {
				return NJT_ERROR;
			}
			if(cf->dynamic == 0) {
				njt_sub_pool(cf->pool,new_pool);
			} else {
				 njt_sub_pool(njt_cycle->pool,new_pool);
			}
			//cmcf->variables.free = 1;
			if (njt_array_init(&cmcf->variables, new_pool, 4,
                           sizeof(njt_http_variable_t))
            != NJT_OK)
#else
        if (njt_array_init(&cmcf->variables, cf->pool, 4,
                           sizeof(njt_http_variable_t))
            != NJT_OK)
#endif
        {
            return NJT_ERROR;
        }

    } else {
        for (i = 0; i < cmcf->variables.nelts; i++) {
#if (NJT_HTTP_DYNAMIC_LOC)
			if(v[i].name.data == NULL && v[i].name.len == 0 && free_v == NULL){
				free_v = &v[i];
			}
#endif
            if (name->len != v[i].name.len
                || njt_strncasecmp(name->data, v[i].name.data, name->len) != 0)
            {
                continue;
            }

            return i;
        }
    }
#if (NJT_HTTP_DYNAMIC_LOC)
			if(free_v != NULL){
				v = free_v;
			} else {
				 v = njt_array_push(&cmcf->variables);
			}
#else
    v = njt_array_push(&cmcf->variables);
#endif
    if (v == NULL) {
        return NJT_ERROR;
    }

    v->name.len = name->len;

#if (NJT_HTTP_DYNAMIC_LOC)
		v->name.data = njt_pnalloc(cmcf->variables.pool, name->len);
#else
	v->name.data = njt_pnalloc(cf->pool, name->len);
#endif

   
    if (v->name.data == NULL) {
        return NJT_ERROR;
    }

    njt_strlow(v->name.data, name->data, name->len);

    v->set_handler = NULL;
    v->get_handler = NULL;
    v->data = 0;
    v->flags = 0;
#if (NJT_HTTP_DYNAMIC_LOC)
	if(cf->dynamic == 1) {
		v->flags |=  NJT_HTTP_DYN_VAR;
	} 
#endif
	if(free_v != v) {
		v->index = cmcf->variables.nelts - 1;
	} else {
		v->index = free_v->index; // zyg ʹ�þɵġ�
	}
    

    return v->index;
}


njt_http_variable_value_t *
njt_http_get_indexed_variable(njt_http_request_t *r, njt_uint_t index)
{
    njt_http_variable_t        *v;
    njt_http_core_main_conf_t  *cmcf;

    cmcf = njt_http_get_module_main_conf(r, njt_http_core_module);

    if (cmcf->variables.nelts <= index) {
        njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
                      "unknown variable index: %ui", index);
        return NULL;
    }

    if (r->variables[index].not_found || r->variables[index].valid) {
        return &r->variables[index];
    }

    v = cmcf->variables.elts;

    if (njt_http_variable_depth == 0) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "cycle while evaluating variable \"%V\"",
                      &v[index].name);
        return NULL;
    }

    njt_http_variable_depth--;

    if (v[index].get_handler && v[index].get_handler(r, &r->variables[index], v[index].data)
        == NJT_OK)
    {
        njt_http_variable_depth++;

        if (v[index].flags & NJT_HTTP_VAR_NOCACHEABLE) {
            r->variables[index].no_cacheable = 1;
        }

        return &r->variables[index];
    }

    njt_http_variable_depth++;

    r->variables[index].valid = 0;
    r->variables[index].not_found = 1;

    return NULL;
}


njt_http_variable_value_t *
njt_http_get_flushed_variable(njt_http_request_t *r, njt_uint_t index)
{
    njt_http_variable_value_t  *v;

    v = &r->variables[index];

    if (v->valid || v->not_found) {
        if (!v->no_cacheable) {
            return v;
        }

        v->valid = 0;
        v->not_found = 0;
    }

    return njt_http_get_indexed_variable(r, index);
}


njt_http_variable_value_t *
njt_http_get_variable(njt_http_request_t *r, njt_str_t *name, njt_uint_t key)
{
    size_t                      len;
    njt_uint_t                  i, n;
    njt_http_variable_t        *v;
    njt_http_variable_value_t  *vv;
    njt_http_core_main_conf_t  *cmcf;

    cmcf = njt_http_get_module_main_conf(r, njt_http_core_module);

    v = njt_hash_find(&cmcf->variables_hash, key, name->data, name->len);

    if (v) {
        if (v->flags & NJT_HTTP_VAR_INDEXED) {
            return njt_http_get_flushed_variable(r, v->index);
        }

        if (njt_http_variable_depth == 0) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "cycle while evaluating variable \"%V\"", name);
            return NULL;
        }

        njt_http_variable_depth--;

        vv = njt_palloc(r->pool, sizeof(njt_http_variable_value_t));

        if (vv && v->get_handler(r, vv, v->data) == NJT_OK) {
            njt_http_variable_depth++;
            return vv;
        }

        njt_http_variable_depth++;
        return NULL;
    }

    vv = njt_palloc(r->pool, sizeof(njt_http_variable_value_t));
    if (vv == NULL) {
        return NULL;
    }

    len = 0;

    v = cmcf->prefix_variables.elts;
    n = cmcf->prefix_variables.nelts;

    for (i = 0; i < cmcf->prefix_variables.nelts; i++) {
        if (name->len >= v[i].name.len && name->len > len
            && njt_strncmp(name->data, v[i].name.data, v[i].name.len) == 0)
        {
            len = v[i].name.len;
            n = i;
        }
    }

    if (n != cmcf->prefix_variables.nelts) {
        if (v[n].get_handler(r, vv, (uintptr_t) name) == NJT_OK) {
            return vv;
        }

        return NULL;
    }

    vv->not_found = 1;

    return vv;
}

static njt_int_t
njt_http_variable_get_uri_key(njt_http_request_t *r, njt_http_variable_value_t *v,
    uintptr_t data)
{
    njt_str_t  *s;

    s = (njt_str_t *) ((char *) r + data);

    if (s->len > 1 && s->data) {
        v->len = s->len-1;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = s->data + 1;

    } else {
        v->not_found = 1;
    }

    return NJT_OK;
}
static njt_int_t
njt_http_variable_request(njt_http_request_t *r, njt_http_variable_value_t *v,
    uintptr_t data)
{
    njt_str_t  *s;

    s = (njt_str_t *) ((char *) r + data);

    if (s->data) {
        v->len = s->len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = s->data;

    } else {
        v->not_found = 1;
    }

    return NJT_OK;
}


#if 0

static void
njt_http_variable_request_set(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    njt_str_t  *s;

    s = (njt_str_t *) ((char *) r + data);

    s->len = v->len;
    s->data = v->data;
}

#endif


static njt_int_t
njt_http_variable_request_get_size(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    size_t  *sp;

    sp = (size_t *) ((char *) r + data);

    v->data = njt_pnalloc(r->pool, NJT_SIZE_T_LEN);
    if (v->data == NULL) {
        return NJT_ERROR;
    }

    v->len = njt_sprintf(v->data, "%uz", *sp) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NJT_OK;
}


static njt_int_t
njt_http_variable_header(njt_http_request_t *r, njt_http_variable_value_t *v,
    uintptr_t data)
{
    return njt_http_variable_headers_internal(r, v, data, ',');
}


static njt_int_t
njt_http_variable_cookies(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    return njt_http_variable_headers_internal(r, v, data, ';');
}


static njt_int_t
njt_http_variable_headers_internal(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data, u_char sep)
{
    size_t            len;
    u_char           *p, *end;
    njt_table_elt_t  *h, *th;

    h = *(njt_table_elt_t **) ((char *) r + data);

    len = 0;

    for (th = h; th; th = th->next) {

        if (th->hash == 0) {
            continue;
        }

        len += th->value.len + 2;
    }

    if (len == 0) {
        v->not_found = 1;
        return NJT_OK;
    }

    len -= 2;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (h->next == NULL) {
        v->len = h->value.len;
        v->data = h->value.data;

        return NJT_OK;
    }

    p = njt_pnalloc(r->pool, len);
    if (p == NULL) {
        return NJT_ERROR;
    }

    v->len = len;
    v->data = p;

    end = p + len;

    for (th = h; th; th = th->next) {

        if (th->hash == 0) {
            continue;
        }

        p = njt_copy(p, th->value.data, th->value.len);

        if (p == end) {
            break;
        }

        *p++ = sep; *p++ = ' ';
    }

    return NJT_OK;
}


static njt_int_t
njt_http_variable_unknown_header_in(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    return njt_http_variable_unknown_header(r, v, (njt_str_t *) data,
                                            &r->headers_in.headers.part,
                                            sizeof("http_") - 1);
}


static njt_int_t
njt_http_variable_unknown_header_out(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    return njt_http_variable_unknown_header(r, v, (njt_str_t *) data,
                                            &r->headers_out.headers.part,
                                            sizeof("sent_http_") - 1);
}


static njt_int_t
njt_http_variable_unknown_trailer_out(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    return njt_http_variable_unknown_header(r, v, (njt_str_t *) data,
                                            &r->headers_out.trailers.part,
                                            sizeof("sent_trailer_") - 1);
}


njt_int_t
njt_http_variable_unknown_header(njt_http_request_t *r,
    njt_http_variable_value_t *v, njt_str_t *var,
    njt_list_part_t *part, size_t prefix)
{
    u_char           *p, ch;
    size_t            len;
    njt_uint_t        i, n;
    njt_table_elt_t  *header, *h, **ph;

    ph = &h;
#if (NJT_SUPPRESS_WARN)
    len = 0;
#endif

    header = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        if (header[i].key.len != var->len - prefix) {
            continue;
        }

        for (n = 0; n < var->len - prefix; n++) {
            ch = header[i].key.data[n];

            if (ch >= 'A' && ch <= 'Z') {
                ch |= 0x20;

            } else if (ch == '-') {
                ch = '_';
            }

            if (var->data[n + prefix] != ch) {
                break;
            }
        }

        if (n != var->len - prefix) {
            continue;
        }

        len += header[i].value.len + 2;

        *ph = &header[i];
        ph = &header[i].next;
    }

    *ph = NULL;

    if (h == NULL) {
        v->not_found = 1;
        return NJT_OK;
    }

    len -= 2;

    if (h->next == NULL) {

        v->len = h->value.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = h->value.data;

        return NJT_OK;
    }

    p = njt_pnalloc(r->pool, len);
    if (p == NULL) {
        return NJT_ERROR;
    }

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    for ( ;; ) {

        p = njt_copy(p, h->value.data, h->value.len);

        if (h->next == NULL) {
            break;
        }

        *p++ = ','; *p++ = ' ';

        h = h->next;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_variable_request_line(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p, *s;

    s = r->request_line.data;

    if (s == NULL) {
        s = r->request_start;

        if (s == NULL) {
            v->not_found = 1;
            return NJT_OK;
        }

        for (p = s; p < r->header_in->last; p++) {
            if (*p == CR || *p == LF) {
                break;
            }
        }

        r->request_line.len = p - s;
        r->request_line.data = s;
    }

    v->len = r->request_line.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = s;

    return NJT_OK;
}


static njt_int_t
njt_http_variable_cookie(njt_http_request_t *r, njt_http_variable_value_t *v,
    uintptr_t data)
{
    njt_str_t *name = (njt_str_t *) data;

    njt_str_t  cookie, s;

    s.len = name->len - (sizeof("cookie_") - 1);
    s.data = name->data + sizeof("cookie_") - 1;

    if (njt_http_parse_multi_header_lines(r, r->headers_in.cookie, &s, &cookie)
        == NULL)
    {
        v->not_found = 1;
        return NJT_OK;
    }

    v->len = cookie.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = cookie.data;

    return NJT_OK;
}


static njt_int_t
njt_http_variable_argument(njt_http_request_t *r, njt_http_variable_value_t *v,
    uintptr_t data)
{
    njt_str_t *name = (njt_str_t *) data;

    u_char     *arg;
    size_t      len;
    njt_str_t   value;

    len = name->len - (sizeof("arg_") - 1);
    arg = name->data + sizeof("arg_") - 1;

    if (len == 0 || njt_http_arg(r, arg, len, &value) != NJT_OK) {
        v->not_found = 1;
        return NJT_OK;
    }

    v->data = value.data;
    v->len = value.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NJT_OK;
}


#if (NJT_HAVE_TCP_INFO)

static njt_int_t
njt_http_variable_tcpinfo(njt_http_request_t *r, njt_http_variable_value_t *v,
    uintptr_t data)
{
    struct tcp_info  ti;
    socklen_t        len;
    uint32_t         value;

    len = sizeof(struct tcp_info);
    if (getsockopt(r->connection->fd, IPPROTO_TCP, TCP_INFO, &ti, &len) == -1) {
        v->not_found = 1;
        return NJT_OK;
    }

    v->data = njt_pnalloc(r->pool, NJT_INT32_LEN);
    if (v->data == NULL) {
        return NJT_ERROR;
    }

    switch (data) {
    case 0:
        value = ti.tcpi_rtt;
        break;

    case 1:
        value = ti.tcpi_rttvar;
        break;

    case 2:
        value = ti.tcpi_snd_cwnd;
        break;

    case 3:
        value = ti.tcpi_rcv_space;
        break;

    /* suppress warning */
    default:
        value = 0;
        break;
    }

    v->len = njt_sprintf(v->data, "%uD", value) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NJT_OK;
}

#endif


static njt_int_t
njt_http_variable_content_length(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    if (r->headers_in.content_length) {
        v->len = r->headers_in.content_length->value.len;
        v->data = r->headers_in.content_length->value.data;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;

    } else if (r->reading_body) {
        v->not_found = 1;
        v->no_cacheable = 1;

    } else if (r->headers_in.content_length_n >= 0) {
        p = njt_pnalloc(r->pool, NJT_OFF_T_LEN);
        if (p == NULL) {
            return NJT_ERROR;
        }

        v->len = njt_sprintf(p, "%O", r->headers_in.content_length_n) - p;
        v->data = p;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;

    } else if (r->headers_in.chunked) {
        v->not_found = 1;
        v->no_cacheable = 1;

    } else {
        v->not_found = 1;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_variable_host(njt_http_request_t *r, njt_http_variable_value_t *v,
    uintptr_t data)
{
    njt_http_core_srv_conf_t  *cscf;

    if (r->headers_in.server.len) {
        v->len = r->headers_in.server.len;
        v->data = r->headers_in.server.data;

    } else {
        cscf = njt_http_get_module_srv_conf(r, njt_http_core_module);

        v->len = cscf->server_name.len;
        v->data = cscf->server_name.data;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NJT_OK;
}


static njt_int_t
njt_http_variable_binary_remote_addr(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    struct sockaddr_in   *sin;
#if (NJT_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    switch (r->connection->sockaddr->sa_family) {

#if (NJT_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;

        v->len = sizeof(struct in6_addr);
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = sin6->sin6_addr.s6_addr;

        break;
#endif

#if (NJT_HAVE_UNIX_DOMAIN)
    case AF_UNIX:

        v->len = r->connection->addr_text.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = r->connection->addr_text.data;

        break;
#endif

    default: /* AF_INET */
        sin = (struct sockaddr_in *) r->connection->sockaddr;

        v->len = sizeof(in_addr_t);
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = (u_char *) &sin->sin_addr;

        break;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_variable_remote_addr(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    v->len = r->connection->addr_text.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = r->connection->addr_text.data;

    return NJT_OK;
}


static njt_int_t
njt_http_variable_remote_port(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    njt_uint_t  port;

    v->len = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = njt_pnalloc(r->pool, sizeof("65535") - 1);
    if (v->data == NULL) {
        return NJT_ERROR;
    }

    port = njt_inet_get_port(r->connection->sockaddr);

    if (port > 0 && port < 65536) {
        v->len = njt_sprintf(v->data, "%ui", port) - v->data;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_variable_proxy_protocol_addr(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    njt_str_t             *addr;
    njt_proxy_protocol_t  *pp;

    pp = r->connection->proxy_protocol;
    if (pp == NULL) {
        v->not_found = 1;
        return NJT_OK;
    }

    addr = (njt_str_t *) ((char *) pp + data);

    v->len = addr->len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = addr->data;

    return NJT_OK;
}


static njt_int_t
njt_http_variable_proxy_protocol_port(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    njt_uint_t             port;
    njt_proxy_protocol_t  *pp;

    pp = r->connection->proxy_protocol;
    if (pp == NULL) {
        v->not_found = 1;
        return NJT_OK;
    }

    v->len = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = njt_pnalloc(r->pool, sizeof("65535") - 1);
    if (v->data == NULL) {
        return NJT_ERROR;
    }

    port = *(in_port_t *) ((char *) pp + data);

    if (port > 0 && port < 65536) {
        v->len = njt_sprintf(v->data, "%ui", port) - v->data;
    }

    return NJT_OK;
}

static njt_int_t
njt_http_variable_proxy_protocol_tlv(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    njt_str_t *name = (njt_str_t *) data;

    njt_int_t  rc;
    njt_str_t  tlv, value;

    tlv.len = name->len - (sizeof("proxy_protocol_tlv_") - 1);
    tlv.data = name->data + sizeof("proxy_protocol_tlv_") - 1;

    rc = njt_proxy_protocol_get_tlv(r->connection, &tlv, &value);

    if (rc == NJT_ERROR) {
        return NJT_ERROR;
    }

    if (rc == NJT_DECLINED) {
        v->not_found = 1;
        return NJT_OK;
    }

    v->len = value.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = value.data;

    return NJT_OK;
}



static njt_int_t
njt_http_variable_server_addr(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    njt_str_t  s;
    u_char     addr[NJT_SOCKADDR_STRLEN];

    s.len = NJT_SOCKADDR_STRLEN;
    s.data = addr;

    if (njt_connection_local_sockaddr(r->connection, &s, 0) != NJT_OK) {
        return NJT_ERROR;
    }

    s.data = njt_pnalloc(r->pool, s.len);
    if (s.data == NULL) {
        return NJT_ERROR;
    }

    njt_memcpy(s.data, addr, s.len);

    v->len = s.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = s.data;

    return NJT_OK;
}


static njt_int_t
njt_http_variable_server_port(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    njt_uint_t  port;

    v->len = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (njt_connection_local_sockaddr(r->connection, NULL, 0) != NJT_OK) {
        return NJT_ERROR;
    }

    v->data = njt_pnalloc(r->pool, sizeof("65535") - 1);
    if (v->data == NULL) {
        return NJT_ERROR;
    }

    port = njt_inet_get_port(r->connection->local_sockaddr);

    if (port > 0 && port < 65536) {
        v->len = njt_sprintf(v->data, "%ui", port) - v->data;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_variable_scheme(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
#if (NJT_HTTP_SSL)

    if (r->connection->ssl) {
        v->len = sizeof("https") - 1;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = (u_char *) "https";

        return NJT_OK;
    }

#endif

    v->len = sizeof("http") - 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) "http";

    return NJT_OK;
}


static njt_int_t
njt_http_variable_https(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
#if (NJT_HTTP_SSL)

    if (r->connection->ssl) {
        v->len = sizeof("on") - 1;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = (u_char *) "on";

        return NJT_OK;
    }

#endif

    *v = njt_http_variable_null_value;

    return NJT_OK;
}

static void
njt_http_variable_set_uri_key(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
   if(v->len != 0) {  
    r->uri_key.data = njt_pnalloc(r->pool, v->len + 1);
    if(r->uri_key.data != NULL) {
    	r->uri_key.len = v->len + 1;
	r->uri_key.data[0] = '/';
    	njt_memcpy(r->uri_key.data+1,v->data, v->len);
    }
   }
}

static void
njt_http_variable_set_args(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    r->args.len = v->len;
    r->args.data = v->data;
    r->valid_unparsed_uri = 0;
}


static njt_int_t
njt_http_variable_is_args(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    if (r->args.len == 0) {
        *v = njt_http_variable_null_value;
        return NJT_OK;
    }

    v->len = 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) "?";

    return NJT_OK;
}


static njt_int_t
njt_http_variable_document_root(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    njt_str_t                  path;
    njt_http_core_loc_conf_t  *clcf;

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    if (clcf->root_lengths == NULL) {
        v->len = clcf->root.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = clcf->root.data;

    } else {
        if (njt_http_script_run(r, &path, clcf->root_lengths->elts, 0,
                                clcf->root_values->elts)
            == NULL)
        {
            return NJT_ERROR;
        }

        if (njt_get_full_name(r->pool, (njt_str_t *) &njt_cycle->prefix, &path)
            != NJT_OK)
        {
            return NJT_ERROR;
        }

        v->len = path.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = path.data;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_variable_realpath_root(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    u_char                    *real;
    size_t                     len;
    njt_str_t                  path;
    njt_http_core_loc_conf_t  *clcf;
#if (NJT_HAVE_MAX_PATH)
    u_char                     buffer[NJT_MAX_PATH];
#endif

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    if (clcf->root_lengths == NULL) {
        path = clcf->root;

    } else {
        if (njt_http_script_run(r, &path, clcf->root_lengths->elts, 1,
                                clcf->root_values->elts)
            == NULL)
        {
            return NJT_ERROR;
        }

        path.data[path.len - 1] = '\0';

        if (njt_get_full_name(r->pool, (njt_str_t *) &njt_cycle->prefix, &path)
            != NJT_OK)
        {
            return NJT_ERROR;
        }
    }

#if (NJT_HAVE_MAX_PATH)
    real = buffer;
#else
    real = NULL;
#endif

    real = njt_realpath(path.data, real);

    if (real == NULL) {
        njt_log_error(NJT_LOG_CRIT, r->connection->log, njt_errno,
                      njt_realpath_n " \"%s\" failed", path.data);
        return NJT_ERROR;
    }

    len = njt_strlen(real);

    v->data = njt_pnalloc(r->pool, len);
    if (v->data == NULL) {
#if !(NJT_HAVE_MAX_PATH)
        njt_free(real);
#endif
        return NJT_ERROR;
    }

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    njt_memcpy(v->data, real, len);

#if !(NJT_HAVE_MAX_PATH)
    njt_free(real);
#endif

    return NJT_OK;
}


static njt_int_t
njt_http_variable_request_filename(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    size_t     root;
    njt_str_t  path;

    if (njt_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
        return NJT_ERROR;
    }

    /* njt_http_map_uri_to_path() allocates memory for terminating '\0' */

    v->len = path.len - 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = path.data;

    return NJT_OK;
}


static njt_int_t
njt_http_variable_server_name(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    njt_http_core_srv_conf_t  *cscf;

    cscf = njt_http_get_module_srv_conf(r, njt_http_core_module);

    v->len = cscf->server_name.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = cscf->server_name.data;

    return NJT_OK;
}


static njt_int_t
njt_http_variable_request_method(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    if (r->main->method_name.data) {
        v->len = r->main->method_name.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = r->main->method_name.data;

    } else {
        v->not_found = 1;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_variable_remote_user(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    njt_int_t  rc;

    rc = njt_http_auth_basic_user(r);

    if (rc == NJT_DECLINED) {
        v->not_found = 1;
        return NJT_OK;
    }

    if (rc == NJT_ERROR) {
        return NJT_ERROR;
    }

    v->len = r->headers_in.user.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = r->headers_in.user.data;

    return NJT_OK;
}


static njt_int_t
njt_http_variable_bytes_sent(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = njt_pnalloc(r->pool, NJT_OFF_T_LEN);
    if (p == NULL) {
        return NJT_ERROR;
    }

    v->len = njt_sprintf(p, "%O", r->connection->sent) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NJT_OK;
}


static njt_int_t
njt_http_variable_body_bytes_sent(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    off_t    sent;
    u_char  *p;

    sent = r->connection->sent - r->header_size;

    if (sent < 0) {
        sent = 0;
    }

    p = njt_pnalloc(r->pool, NJT_OFF_T_LEN);
    if (p == NULL) {
        return NJT_ERROR;
    }

    v->len = njt_sprintf(p, "%O", sent) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NJT_OK;
}


static njt_int_t
njt_http_variable_pipe(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    v->data = (u_char *) (r->pipeline ? "p" : ".");
    v->len = 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NJT_OK;
}


static njt_int_t
njt_http_variable_status(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    njt_uint_t  status;

    v->data = njt_pnalloc(r->pool, NJT_INT_T_LEN);
    if (v->data == NULL) {
        return NJT_ERROR;
    }

    if (r->err_status) {
        status = r->err_status;

    } else if (r->headers_out.status) {
        status = r->headers_out.status;

    } else if (r->http_version == NJT_HTTP_VERSION_9) {
        status = 9;

    } else {
        status = 0;
    }

    v->len = njt_sprintf(v->data, "%03ui", status) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NJT_OK;
}


static njt_int_t
njt_http_variable_sent_content_type(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    if (r->headers_out.content_type.len) {
        v->len = r->headers_out.content_type.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = r->headers_out.content_type.data;

    } else {
        v->not_found = 1;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_variable_sent_content_length(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    if (r->headers_out.content_length) {
        v->len = r->headers_out.content_length->value.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = r->headers_out.content_length->value.data;

        return NJT_OK;
    }

    if (r->headers_out.content_length_n >= 0) {
        p = njt_pnalloc(r->pool, NJT_OFF_T_LEN);
        if (p == NULL) {
            return NJT_ERROR;
        }

        v->len = njt_sprintf(p, "%O", r->headers_out.content_length_n) - p;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = p;

        return NJT_OK;
    }

    v->not_found = 1;

    return NJT_OK;
}


static njt_int_t
njt_http_variable_sent_location(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    njt_str_t  name;

    if (r->headers_out.location) {
        v->len = r->headers_out.location->value.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = r->headers_out.location->value.data;

        return NJT_OK;
    }

    njt_str_set(&name, "sent_http_location");

    return njt_http_variable_unknown_header(r, v, &name,
                                            &r->headers_out.headers.part,
                                            sizeof("sent_http_") - 1);
}


static njt_int_t
njt_http_variable_sent_last_modified(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    if (r->headers_out.last_modified) {
        v->len = r->headers_out.last_modified->value.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = r->headers_out.last_modified->value.data;

        return NJT_OK;
    }

    if (r->headers_out.last_modified_time >= 0) {
        p = njt_pnalloc(r->pool, sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1);
        if (p == NULL) {
            return NJT_ERROR;
        }

        v->len = njt_http_time(p, r->headers_out.last_modified_time) - p;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = p;

        return NJT_OK;
    }

    v->not_found = 1;

    return NJT_OK;
}


static njt_int_t
njt_http_variable_sent_connection(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    size_t   len;
    char    *p;

    if (r->headers_out.status == NJT_HTTP_SWITCHING_PROTOCOLS) {
        len = sizeof("upgrade") - 1;
        p = "upgrade";

    } else if (r->keepalive) {
        len = sizeof("keep-alive") - 1;
        p = "keep-alive";

    } else {
        len = sizeof("close") - 1;
        p = "close";
    }

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) p;

    return NJT_OK;
}


static njt_int_t
njt_http_variable_sent_keep_alive(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    u_char                    *p;
    njt_http_core_loc_conf_t  *clcf;

    if (r->keepalive) {
        clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

        if (clcf->keepalive_header) {

            p = njt_pnalloc(r->pool, sizeof("timeout=") - 1 + NJT_TIME_T_LEN);
            if (p == NULL) {
                return NJT_ERROR;
            }

            v->len = njt_sprintf(p, "timeout=%T", clcf->keepalive_header) - p;
            v->valid = 1;
            v->no_cacheable = 0;
            v->not_found = 0;
            v->data = p;

            return NJT_OK;
        }
    }

    v->not_found = 1;

    return NJT_OK;
}


static njt_int_t
njt_http_variable_sent_transfer_encoding(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    if (r->chunked) {
        v->len = sizeof("chunked") - 1;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = (u_char *) "chunked";

    } else {
        v->not_found = 1;
    }

    return NJT_OK;
}


static void
njt_http_variable_set_limit_rate(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    ssize_t    s;
    njt_str_t  val;

    val.len = v->len;
    val.data = v->data;

    s = njt_parse_size(&val);

    if (s == NJT_ERROR) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "invalid $limit_rate \"%V\"", &val);
        return;
    }

    r->limit_rate = s;
    r->limit_rate_set = 1;
}


static njt_int_t
njt_http_variable_request_completion(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    if (r->request_complete) {
        v->len = 2;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = (u_char *) "OK";

        return NJT_OK;
    }

    *v = njt_http_variable_null_value;

    return NJT_OK;
}


static njt_int_t
njt_http_variable_request_body(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    u_char       *p;
    size_t        len;
    njt_buf_t    *buf;
    njt_chain_t  *cl;

    if (r->request_body == NULL
        || r->request_body->bufs == NULL
        || r->request_body->temp_file)
    {
        v->not_found = 1;

        return NJT_OK;
    }

    cl = r->request_body->bufs;
    buf = cl->buf;

    if (cl->next == NULL) {
        v->len = buf->last - buf->pos;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = buf->pos;

        return NJT_OK;
    }

    len = buf->last - buf->pos;
    cl = cl->next;

    for ( /* void */ ; cl; cl = cl->next) {
        buf = cl->buf;
        len += buf->last - buf->pos;
    }

    p = njt_pnalloc(r->pool, len);
    if (p == NULL) {
        return NJT_ERROR;
    }

    v->data = p;
    cl = r->request_body->bufs;

    for ( /* void */ ; cl; cl = cl->next) {
        buf = cl->buf;
        p = njt_cpymem(p, buf->pos, buf->last - buf->pos);
    }

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NJT_OK;
}


static njt_int_t
njt_http_variable_request_body_file(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    if (r->request_body == NULL || r->request_body->temp_file == NULL) {
        v->not_found = 1;

        return NJT_OK;
    }

    v->len = r->request_body->temp_file->file.name.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = r->request_body->temp_file->file.name.data;

    return NJT_OK;
}


static njt_int_t
njt_http_variable_request_length(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = njt_pnalloc(r->pool, NJT_OFF_T_LEN);
    if (p == NULL) {
        return NJT_ERROR;
    }

    v->len = njt_sprintf(p, "%O", r->request_length) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NJT_OK;
}


static njt_int_t
njt_http_variable_request_time(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    u_char          *p;
    njt_time_t      *tp;
    njt_msec_int_t   ms;

    p = njt_pnalloc(r->pool, NJT_TIME_T_LEN + 4);
    if (p == NULL) {
        return NJT_ERROR;
    }

    tp = njt_timeofday();

    ms = (njt_msec_int_t)
             ((tp->sec - r->start_sec) * 1000 + (tp->msec - r->start_msec));
    ms = njt_max(ms, 0);

    v->len = njt_sprintf(p, "%T.%03M", (time_t) ms / 1000, ms % 1000) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NJT_OK;
}


static njt_int_t
njt_http_variable_request_id(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    u_char  *id;

#if (NJT_OPENSSL)
    u_char   random_bytes[16];
#endif

    id = njt_pnalloc(r->pool, 32);
    if (id == NULL) {
        return NJT_ERROR;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->len = 32;
    v->data = id;

#if (NJT_OPENSSL)

    if (RAND_bytes(random_bytes, 16) == 1) {
        njt_hex_dump(id, random_bytes, 16);
        return NJT_OK;
    }

    njt_ssl_error(NJT_LOG_ERR, r->connection->log, 0, "RAND_bytes() failed");

#endif

    njt_sprintf(id, "%08xD%08xD%08xD%08xD",
                (uint32_t) njt_random(), (uint32_t) njt_random(),
                (uint32_t) njt_random(), (uint32_t) njt_random());

    return NJT_OK;
}


static njt_int_t
njt_http_variable_connection(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = njt_pnalloc(r->pool, NJT_ATOMIC_T_LEN);
    if (p == NULL) {
        return NJT_ERROR;
    }

    v->len = njt_sprintf(p, "%uA", r->connection->number) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NJT_OK;
}


static njt_int_t
njt_http_variable_connection_requests(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = njt_pnalloc(r->pool, NJT_INT_T_LEN);
    if (p == NULL) {
        return NJT_ERROR;
    }

    v->len = njt_sprintf(p, "%ui", r->connection->requests) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NJT_OK;
}


static njt_int_t
njt_http_variable_connection_time(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    u_char          *p;
    njt_msec_int_t   ms;

    p = njt_pnalloc(r->pool, NJT_TIME_T_LEN + 4);
    if (p == NULL) {
        return NJT_ERROR;
    }

    ms = njt_current_msec - r->connection->start_time;
    ms = njt_max(ms, 0);

    v->len = njt_sprintf(p, "%T.%03M", (time_t) ms / 1000, ms % 1000) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NJT_OK;
}


static njt_int_t
njt_http_variable_njet_version(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    v->len = sizeof(NJT_VERSION) - 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) NJT_VERSION;

    return NJT_OK;
}


static njt_int_t
njt_http_variable_hostname(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    v->len = njt_cycle->hostname.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = njt_cycle->hostname.data;

    return NJT_OK;
}


static njt_int_t
njt_http_variable_pid(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = njt_pnalloc(r->pool, NJT_INT64_LEN);
    if (p == NULL) {
        return NJT_ERROR;
    }

    v->len = njt_sprintf(p, "%P", njt_pid) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NJT_OK;
}


static njt_int_t
njt_http_variable_msec(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    u_char      *p;
    njt_time_t  *tp;

    p = njt_pnalloc(r->pool, NJT_TIME_T_LEN + 4);
    if (p == NULL) {
        return NJT_ERROR;
    }

    tp = njt_timeofday();

    v->len = njt_sprintf(p, "%T.%03M", tp->sec, tp->msec) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NJT_OK;
}


static njt_int_t
njt_http_variable_time_iso8601(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = njt_pnalloc(r->pool, njt_cached_http_log_iso8601.len);
    if (p == NULL) {
        return NJT_ERROR;
    }

    njt_memcpy(p, njt_cached_http_log_iso8601.data,
               njt_cached_http_log_iso8601.len);

    v->len = njt_cached_http_log_iso8601.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NJT_OK;
}


static njt_int_t
njt_http_variable_time_local(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = njt_pnalloc(r->pool, njt_cached_http_log_time.len);
    if (p == NULL) {
        return NJT_ERROR;
    }

    njt_memcpy(p, njt_cached_http_log_time.data, njt_cached_http_log_time.len);

    v->len = njt_cached_http_log_time.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NJT_OK;
}


void *
njt_http_map_find(njt_http_request_t *r, njt_http_map_t *map, njt_str_t *match)
{
    void        *value;
    u_char      *low;
    size_t       len;
    njt_uint_t   key;

    len = match->len;

    if (len) {
        low = njt_pnalloc(r->pool, len);
        if (low == NULL) {
            return NULL;
        }

    } else {
        low = NULL;
    }

    key = njt_hash_strlow(low, match->data, len);

    value = njt_hash_find_combined(&map->hash, key, low, len);
    if (value) {
        return value;
    }

#if (NJT_PCRE)

    if (len && map->nregex) {
        njt_int_t              n;
        njt_uint_t             i;
        njt_http_map_regex_t  *reg;

        reg = map->regex;

        for (i = 0; i < map->nregex; i++) {

            n = njt_http_regex_exec(r, reg[i].regex, match);

            if (n == NJT_OK) {
                return reg[i].value;
            }

            if (n == NJT_DECLINED) {
                continue;
            }

            /* NJT_ERROR */

            return NULL;
        }
    }

#endif

    return NULL;
}


#if (NJT_PCRE)

static njt_int_t
njt_http_variable_not_found(njt_http_request_t *r, njt_http_variable_value_t *v,
    uintptr_t data)
{
    v->not_found = 1;
    return NJT_OK;
}


njt_http_regex_t *
njt_http_regex_compile(njt_conf_t *cf, njt_regex_compile_t *rc)
{
    u_char                     *p;
    size_t                      size;
    njt_str_t                   name;
    njt_uint_t                  i, n;
    njt_http_variable_t        *v;
    njt_http_regex_t           *re;
    njt_http_regex_variable_t  *rv;
    njt_http_core_main_conf_t  *cmcf;

    rc->pool = cf->pool;

    if (njt_regex_compile(rc) != NJT_OK) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "%V", &rc->err);
        return NULL;
    }

    re = njt_pcalloc(cf->pool, sizeof(njt_http_regex_t));
    if (re == NULL) {
        return NULL;
    }

    re->regex = rc->regex;
    re->ncaptures = rc->captures;
    re->name = rc->pattern;

    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);
    cmcf->ncaptures = njt_max(cmcf->ncaptures, re->ncaptures);

    n = (njt_uint_t) rc->named_captures;

    if (n == 0) {
        return re;
    }

    rv = njt_palloc(rc->pool, n * sizeof(njt_http_regex_variable_t));
    if (rv == NULL) {
        return NULL;
    }

    re->variables = rv;
    re->nvariables = n;

    size = rc->name_size;
    p = rc->names;

    for (i = 0; i < n; i++) {
        rv[i].capture = 2 * ((p[0] << 8) + p[1]);

        name.data = &p[2];
        name.len = njt_strlen(name.data);

        v = njt_http_add_variable(cf, &name, NJT_HTTP_VAR_CHANGEABLE);
        if (v == NULL) {
            return NULL;
        }

        rv[i].index = njt_http_get_variable_index(cf, &name);
        if (rv[i].index == NJT_ERROR) {
            return NULL;
        }

        v->get_handler = njt_http_variable_not_found;

        p += size;
    }

    return re;
}


njt_int_t
njt_http_regex_exec(njt_http_request_t *r, njt_http_regex_t *re, njt_str_t *s)
{
    njt_int_t                   rc, index;
    njt_uint_t                  i, n, len;
    njt_http_variable_value_t  *vv;
    njt_http_core_main_conf_t  *cmcf;

    cmcf = njt_http_get_module_main_conf(r, njt_http_core_module);

    if (re->ncaptures) {
        len = cmcf->ncaptures;

        if (r->captures == NULL || r->realloc_captures) {
            r->realloc_captures = 0;

            r->captures = njt_palloc(r->pool, len * sizeof(int));
            if (r->captures == NULL) {
                return NJT_ERROR;
            }
        }

    } else {
        len = 0;
    }

    rc = njt_regex_exec(re->regex, s, r->captures, len);

    if (rc == NJT_REGEX_NO_MATCHED) {
        return NJT_DECLINED;
    }

    if (rc < 0) {
        njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
                      njt_regex_exec_n " failed: %i on \"%V\" using \"%V\"",
                      rc, s, &re->name);
        return NJT_ERROR;
    }

    for (i = 0; i < re->nvariables; i++) {

        n = re->variables[i].capture;
        index = re->variables[i].index;
        vv = &r->variables[index];

        vv->len = r->captures[n + 1] - r->captures[n];
        vv->valid = 1;
        vv->no_cacheable = 0;
        vv->not_found = 0;
        vv->data = &s->data[r->captures[n]];

#if (NJT_DEBUG)
        {
        njt_http_variable_t  *v;

        v = cmcf->variables.elts;

        njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http regex set $%V to \"%v\"", &v[index].name, vv);
        }
#endif
    }

    r->ncaptures = rc * 2;
    r->captures_data = s->data;

    return NJT_OK;
}

#endif


njt_int_t
njt_http_variables_add_core_vars(njt_conf_t *cf)
{
    njt_http_variable_t        *cv, *v;
    njt_http_core_main_conf_t  *cmcf;

    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);

#if (NJT_HTTP_DYNAMIC_LOC)
       //if(cmcf->variables_keys != NULL && cmcf->variables_keys->pool != NULL) {
       //	 njt_destroy_pool(cmcf->variables_keys->pool);
       //}
       njt_pool_t *new_pool = njt_create_dynamic_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
	   if(new_pool == NULL) {
		   return NJT_ERROR;
	   }
	   if(cf->dynamic == 0) {
		   njt_sub_pool(cf->pool,new_pool);
	   } else {
		   njt_sub_pool(njt_cycle->pool,new_pool);
	   }
	   cmcf->variables_keys = njt_pcalloc(new_pool,
                                       sizeof(njt_hash_keys_arrays_t));
		if (cmcf->variables_keys == NULL) {
			return NJT_ERROR;
		}

		cmcf->variables_keys->pool = new_pool;
		cmcf->variables_keys->temp_pool = new_pool;
    
#else

    cmcf->variables_keys = njt_pcalloc(cf->temp_pool,
                                       sizeof(njt_hash_keys_arrays_t));
    if (cmcf->variables_keys == NULL) {
        return NJT_ERROR;
    }

    cmcf->variables_keys->pool = cf->pool;
    cmcf->variables_keys->temp_pool = cf->pool;
#endif
    if (njt_hash_keys_array_init(cmcf->variables_keys, NJT_HASH_SMALL)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    if (njt_array_init(&cmcf->prefix_variables, cf->pool, 8,
                       sizeof(njt_http_variable_t))
        != NJT_OK)
    {
        return NJT_ERROR;
    }
#if (NJT_HTTP_DYNAMIC_LOC)
	 cmcf->dyn_var_pool = njt_create_dynamic_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
	 if(cmcf->dyn_var_pool == NULL){
	    njt_log_error(NJT_LOG_ERR, njt_cycle->pool->log, 0, "dyn_var_pool  alloc  error!");
	    return NJT_ERROR;
	 }
	 //njt_sub_pool(cf->pool,cmcf->dyn_var_pool);
	 if(cf->dynamic == 0) {
		 njt_sub_pool(cf->pool,cmcf->dyn_var_pool);
	 } else {
		 njt_sub_pool(njt_cycle->pool,cmcf->dyn_var_pool);
	 }

#endif
    for (cv = njt_http_core_variables; cv->name.len; cv++) {
        v = njt_http_add_variable(cf, &cv->name, cv->flags);
        if (v == NULL) {
            return NJT_ERROR;
        }

        *v = *cv;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_variables_init_vars_proc(njt_conf_t *cf, njt_uint_t dyn)
{
    size_t                      len;
    njt_uint_t                  i, n;
    njt_hash_key_t             *key;
    njt_hash_init_t             hash;
    njt_http_variable_t        *v, *av, *pv;
    njt_http_core_main_conf_t  *cmcf;
    njt_int_t rc;

    /* set the handlers for the indexed http variables */

    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);

    v = cmcf->variables.elts;
    pv = cmcf->prefix_variables.elts;
    key = cmcf->variables_keys->keys.elts;

    for (i = 0; i < cmcf->variables.nelts; i++) {
        if (v[i].name.len == 0 || v[i].name.data == NULL) {
            continue;
        }

        for (n = 0; n < cmcf->variables_keys->keys.nelts; n++) {

            av = key[n].value;

            if (v[i].name.len == key[n].key.len
                && njt_strncmp(v[i].name.data, key[n].key.data, v[i].name.len)
                   == 0)
            {
                v[i].get_handler = av->get_handler;
                v[i].data = av->data;

                av->flags |= NJT_HTTP_VAR_INDEXED;
                v[i].flags = av->flags;

                av->index = i;

                if (av->get_handler == NULL
                    || (av->flags & NJT_HTTP_VAR_WEAK))
                {
                    break;
                }

                goto next;
            }
        }

        len = 0;
        av = NULL;

        for (n = 0; n < cmcf->prefix_variables.nelts; n++) {
            if (v[i].name.len >= pv[n].name.len && v[i].name.len > len
                && njt_strncmp(v[i].name.data, pv[n].name.data, pv[n].name.len)
                   == 0)
            {
                av = &pv[n];
                len = pv[n].name.len;
            }
        }

        if (av) {
            v[i].get_handler = av->get_handler;
            v[i].data = (uintptr_t) &v[i].name;
            v[i].flags = av->flags;

            goto next;
        }

        if (v[i].get_handler == NULL) {
            njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                          "unknown \"%V\" variable", &v[i].name);
            if (!dyn) {
                return NJT_ERROR;
            }
        }

    next:
        continue;
    }


    for (n = 0; n < cmcf->variables_keys->keys.nelts; n++) {
        av = key[n].value;

        if (av->flags & NJT_HTTP_VAR_NOHASH) {
            //zyg key[n].key.data = NULL;
        }
    }


    hash.hash = &cmcf->variables_hash;

    //by zyg
    #if (NJT_HTTP_DYNAMIC_LOC)
      njt_pool_t *new_pool;
     if(hash.hash->pool != NULL) {
	  njt_destroy_pool(hash.hash->pool);
	}   
	 new_pool = njt_create_dynamic_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
    if (new_pool == NULL) {
        return NJT_ERROR;
    }
    hash.hash->pool = new_pool;
    if(dyn == 0) {
    	rc = njt_sub_pool(cf->pool,new_pool);
    } else {
	rc = njt_sub_pool(njt_cycle->pool,new_pool);
    }
    if (rc != NJT_OK) {
        return NJT_ERROR;
    }

    #endif
    //end
    hash.key = njt_hash_key;
    hash.max_size = cmcf->variables_hash_max_size;
    hash.bucket_size = cmcf->variables_hash_bucket_size;
    hash.name = "variables_hash";
    hash.pool = cf->pool;
	#if (NJT_HTTP_DYNAMIC_LOC)
		hash.pool = new_pool;
	#endif
    hash.temp_pool = NULL;
    if (njt_hash_init(&hash, cmcf->variables_keys->keys.elts,
                      cmcf->variables_keys->keys.nelts)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

   //zyg  cmcf->variables_keys = NULL;

    return NJT_OK;
}

njt_int_t
njt_http_variables_init_vars(njt_conf_t *cf)
{
    return njt_http_variables_init_vars_proc(cf, 0);
}

/*
 * New init vars API used in dynamic configuration.
 * Here cf->pool do not and will not have sub pools.
 */
njt_int_t
njt_http_variables_init_vars_dyn(njt_conf_t *cf)
{
    return njt_http_variables_init_vars_proc(cf, 1);
}
