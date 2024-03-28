
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_MAIL_SSL_H_INCLUDED_
#define _NJT_MAIL_SSL_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>
#include <njt_mail.h>


#define NJT_MAIL_STARTTLS_OFF   0
#define NJT_MAIL_STARTTLS_ON    1
#define NJT_MAIL_STARTTLS_ONLY  2


typedef struct {
    njt_flag_t       prefer_server_ciphers;

    njt_ssl_t        ssl;

    njt_uint_t       starttls;
    njt_uint_t       listen;
    njt_uint_t       protocols;

    njt_uint_t       verify;
    njt_uint_t       verify_depth;

    ssize_t          builtin_session_cache;

    time_t           session_timeout;

    njt_array_t     *certificates;
    njt_array_t     *certificate_keys;

    njt_str_t        dhparam;
    njt_str_t        ecdh_curve;
    njt_str_t        client_certificate;
    njt_str_t        trusted_certificate;
    njt_str_t        crl;

    njt_str_t        ciphers;

    njt_array_t     *passwords;
    njt_array_t     *conf_commands;

    njt_shm_zone_t  *shm_zone;

    njt_flag_t       session_tickets;
    njt_array_t     *session_ticket_keys;

    u_char          *file;
    njt_uint_t       line;
} njt_mail_ssl_conf_t;


extern njt_module_t  njt_mail_ssl_module;


#endif /* _NJT_MAIL_SSL_H_INCLUDED_ */
