#ifndef _NJT_STREAM_PROXY_H_INCLUDED_
#define _NJT_STREAM_PROXY_H_INCLUDED_

#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>

#define NJT_HAVE_SET_ALPN  1

typedef struct {
    njt_addr_t                      *addr;
    njt_stream_complex_value_t      *value;
#if (NJT_HAVE_TRANSPARENT_PROXY)
    njt_uint_t                       transparent; /* unsigned  transparent:1; */
#endif
} njt_stream_upstream_local_t;

typedef struct {
    njt_msec_t                       connect_timeout;
    njt_msec_t                       timeout;
    njt_msec_t                       next_upstream_timeout;
    size_t                           buffer_size;
    njt_stream_complex_value_t      *upload_rate;
    njt_stream_complex_value_t      *download_rate;
    njt_uint_t                       requests;
    njt_uint_t                       responses;
    njt_uint_t                       next_upstream_tries;
    njt_flag_t                       next_upstream;
    njt_flag_t                       proxy_protocol;
    njt_flag_t                       half_close;
    njt_stream_upstream_local_t     *local;
    njt_flag_t                       socket_keepalive;

#if (NJT_STREAM_SSL)
    njt_flag_t                       ssl_enable;
    njt_flag_t                       ssl_session_reuse;
    njt_uint_t                       ssl_protocols;
    njt_str_t                        ssl_ciphers;
    njt_stream_complex_value_t      *ssl_name;
    njt_flag_t                       ssl_server_name;

    njt_flag_t                       ssl_verify;
    njt_uint_t                       ssl_verify_depth;
    njt_str_t                        ssl_trusted_certificate;
    njt_str_t                        ssl_crl;

#if (NJT_STREAM_MULTICERT)
    njt_array_t                     *ssl_certificates;
    njt_array_t                     *ssl_certificate_keys;

    njt_array_t                     *ssl_certificate_values;
    njt_array_t                     *ssl_certificate_key_values;
#else
    njt_stream_complex_value_t      *ssl_certificate;
    njt_stream_complex_value_t      *ssl_certificate_key;
#endif

    njt_array_t                     *ssl_passwords;
    njt_array_t                     *ssl_conf_commands;
    njt_ssl_t                       *ssl;

#if (NJT_HAVE_NTLS)
    njt_flag_t                       ssl_ntls;
#endif

#if (NJT_HAVE_SET_ALPN)
    njt_str_t                        proxy_ssl_alpn;
#endif

#endif

    njt_stream_upstream_srv_conf_t  *upstream;
    njt_stream_complex_value_t      *upstream_value;
} njt_stream_proxy_srv_conf_t;



void njt_stream_proxy_handler(njt_stream_session_t *s);
#endif
