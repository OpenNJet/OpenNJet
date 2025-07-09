
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_STREAM_SSL_H_INCLUDED_
#define _NJT_STREAM_SSL_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>


typedef struct {
    njt_msec_t        handshake_timeout;

    njt_flag_t        prefer_server_ciphers;
    njt_flag_t        reject_handshake;

    njt_ssl_t         ssl;

    njt_uint_t        protocols;

    njt_uint_t        verify;
    njt_uint_t        verify_depth;

    ssize_t           builtin_session_cache;

    time_t            session_timeout;

    njt_array_t      *certificates;
    njt_array_t      *certificate_keys;

    njt_array_t      *certificate_values;
    njt_array_t      *certificate_key_values;

    njt_str_t         dhparam;
    njt_str_t         ecdh_curve;
    njt_str_t         client_certificate;
    njt_str_t         trusted_certificate;
    njt_str_t         crl;
    njt_str_t         alpn;
    njt_ssl_cache_t  *certificate_cache;

    njt_array_t      *dyn_cert_crc32;   //add by clb
    njt_array_t      *cert_types;        //add by clb

    njt_str_t         ciphers;

    njt_array_t      *passwords;
    njt_array_t      *conf_commands;

    njt_shm_zone_t   *shm_zone;

    njt_flag_t        session_tickets;
    njt_array_t      *session_ticket_keys;

    njt_uint_t        ocsp;
    njt_str_t         ocsp_responder;
    njt_shm_zone_t   *ocsp_cache_zone;

    njt_flag_t        stapling;
    njt_flag_t        stapling_verify;
    njt_str_t         stapling_file;
    njt_str_t         stapling_responder;

#if (NJT_HAVE_NTLS)
    njt_flag_t        ntls;
#endif
#if (NJT_STREAM_DYNAMIC_SERVER)
   njt_pool_t        *pool;
#endif
} njt_stream_ssl_srv_conf_t;


extern njt_module_t  njt_stream_ssl_module;

#if (NJT_STREAM_MULTICERT)
char *njt_stream_ssl_certificate_slot(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);
njt_int_t njt_stream_ssl_compile_certificates(njt_conf_t *cf,
    njt_stream_ssl_srv_conf_t *conf);
#endif

#endif /* _NJT_STREAM_SSL_H_INCLUDED_ */
