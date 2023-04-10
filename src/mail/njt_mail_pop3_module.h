
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_MAIL_POP3_MODULE_H_INCLUDED_
#define _NJT_MAIL_POP3_MODULE_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>
#include <njt_mail.h>


typedef struct {
    njt_str_t    capability;
    njt_str_t    starttls_capability;
    njt_str_t    starttls_only_capability;
    njt_str_t    auth_capability;

    njt_uint_t   auth_methods;

    njt_array_t  capabilities;
} njt_mail_pop3_srv_conf_t;


void njt_mail_pop3_init_session(njt_mail_session_t *s, njt_connection_t *c);
void njt_mail_pop3_init_protocol(njt_event_t *rev);
void njt_mail_pop3_auth_state(njt_event_t *rev);
njt_int_t njt_mail_pop3_parse_command(njt_mail_session_t *s);


extern njt_module_t  njt_mail_pop3_module;


#endif /* _NJT_MAIL_POP3_MODULE_H_INCLUDED_ */
