
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */

#ifndef _NJT_HTTP_PROXY_H_INCLUDED_
#define _NJT_HTTP_PROXY_H_INCLUDED_

#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>

#define NJT_HAVE_SET_ALPN  1

typedef struct {
    njt_array_t                    caches;  /* njt_http_file_cache_t * */
} njt_http_proxy_main_conf_t;


typedef struct njt_http_proxy_rewrite_s  njt_http_proxy_rewrite_t;

typedef njt_int_t (*njt_http_proxy_rewrite_pt)(njt_http_request_t *r,
    njt_str_t *value, size_t prefix, size_t len,
    njt_http_proxy_rewrite_t *pr);

struct njt_http_proxy_rewrite_s {
    njt_http_proxy_rewrite_pt      handler;

    union {
        njt_http_complex_value_t   complex;
#if (NJT_PCRE)
        njt_http_regex_t          *regex;
#endif
    } pattern;

    njt_http_complex_value_t       replacement;
};


typedef struct {
    union {
        njt_http_complex_value_t   complex;
#if (NJT_PCRE)
        njt_http_regex_t          *regex;
#endif
    } cookie;

    njt_array_t                    flags_values;
    njt_uint_t                     regex;
} njt_http_proxy_cookie_flags_t;


typedef struct {
    njt_str_t                      key_start;
    njt_str_t                      schema;
    njt_str_t                      host_header;
    njt_str_t                      port;
    njt_str_t                      uri;
} njt_http_proxy_vars_t;


typedef struct {
    njt_array_t                   *flushes;
    njt_array_t                   *lengths;
    njt_array_t                   *values;
    njt_hash_t                     hash;
} njt_http_proxy_headers_t;


typedef struct {
    njt_http_upstream_conf_t       upstream;

    njt_array_t                   *body_flushes;
    njt_array_t                   *body_lengths;
    njt_array_t                   *body_values;
    njt_str_t                      body_source;

    njt_http_proxy_headers_t       headers;
#if (NJT_HTTP_CACHE)
    njt_http_proxy_headers_t       headers_cache;
#endif
    njt_array_t                   *headers_source;

    njt_array_t                   *proxy_lengths;
    njt_array_t                   *proxy_values;

    njt_array_t                   *redirects;
    njt_array_t                   *cookie_domains;
    njt_array_t                   *cookie_paths;
    njt_array_t                   *cookie_flags;

    njt_http_complex_value_t      *method;
    njt_str_t                      location;
    njt_str_t                      url;

#if (NJT_HTTP_CACHE)
    njt_http_complex_value_t       cache_key;
    njt_http_complex_value_t       cache_file_key;
#endif

    njt_http_proxy_vars_t          vars;

    njt_flag_t                     redirect;

    njt_uint_t                     http_version;

    njt_uint_t                     headers_hash_max_size;
    njt_uint_t                     headers_hash_bucket_size;

#if (NJT_HTTP_SSL)
    njt_uint_t                     ssl;
    njt_uint_t                     ssl_protocols;
    njt_str_t                      ssl_ciphers;
    njt_uint_t                     ssl_verify_depth;
    njt_str_t                      ssl_trusted_certificate;
    njt_str_t                      ssl_crl;
    njt_array_t                   *ssl_conf_commands;
#endif
#if (NJT_HAVE_SET_ALPN)
    njt_str_t        proxy_ssl_alpn;
#endif
#if(NJT_HTTP_DYNAMIC_UPSTREAM)
    unsigned  preserve:1;
#endif
} njt_http_proxy_loc_conf_t;


typedef struct {
    njt_http_status_t              status;
    njt_http_chunked_t             chunked;
    njt_http_proxy_vars_t          vars;
    off_t                          internal_body_length;

    njt_chain_t                   *free;
    njt_chain_t                   *busy;

    unsigned                       head:1;
    unsigned                       internal_chunked:1;
    unsigned                       header_sent:1;
} njt_http_proxy_ctx_t;

#endif
