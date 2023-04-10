
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_MAIL_H_INCLUDED_
#define _NJT_MAIL_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>
#include <njt_event_connect.h>

#if (NJT_MAIL_SSL)
#include <njt_mail_ssl_module.h>
#endif



typedef struct {
    void                  **main_conf;
    void                  **srv_conf;
} njt_mail_conf_ctx_t;


typedef struct {
    struct sockaddr        *sockaddr;
    socklen_t               socklen;
    njt_str_t               addr_text;

    /* server ctx */
    njt_mail_conf_ctx_t    *ctx;

    unsigned                bind:1;
    unsigned                wildcard:1;
    unsigned                ssl:1;
#if (NJT_HAVE_INET6)
    unsigned                ipv6only:1;
#endif
    unsigned                so_keepalive:2;
    unsigned                proxy_protocol:1;
#if (NJT_HAVE_KEEPALIVE_TUNABLE)
    int                     tcp_keepidle;
    int                     tcp_keepintvl;
    int                     tcp_keepcnt;
#endif
    int                     backlog;
    int                     rcvbuf;
    int                     sndbuf;
} njt_mail_listen_t;


typedef struct {
    njt_mail_conf_ctx_t    *ctx;
    njt_str_t               addr_text;
    unsigned                ssl:1;
    unsigned                proxy_protocol:1;
} njt_mail_addr_conf_t;

typedef struct {
    in_addr_t               addr;
    njt_mail_addr_conf_t    conf;
} njt_mail_in_addr_t;


#if (NJT_HAVE_INET6)

typedef struct {
    struct in6_addr         addr6;
    njt_mail_addr_conf_t    conf;
} njt_mail_in6_addr_t;

#endif


typedef struct {
    /* njt_mail_in_addr_t or njt_mail_in6_addr_t */
    void                   *addrs;
    njt_uint_t              naddrs;
} njt_mail_port_t;


typedef struct {
    int                     family;
    in_port_t               port;
    njt_array_t             addrs;       /* array of njt_mail_conf_addr_t */
} njt_mail_conf_port_t;


typedef struct {
    njt_mail_listen_t       opt;
} njt_mail_conf_addr_t;


typedef struct {
    njt_array_t             servers;     /* njt_mail_core_srv_conf_t */
    njt_array_t             listen;      /* njt_mail_listen_t */
} njt_mail_core_main_conf_t;


#define NJT_MAIL_POP3_PROTOCOL  0
#define NJT_MAIL_IMAP_PROTOCOL  1
#define NJT_MAIL_SMTP_PROTOCOL  2


typedef struct njt_mail_protocol_s  njt_mail_protocol_t;


typedef struct {
    njt_mail_protocol_t    *protocol;

    njt_msec_t              timeout;
    njt_msec_t              resolver_timeout;

    njt_uint_t              max_errors;

    njt_str_t               server_name;

    u_char                 *file_name;
    njt_uint_t              line;

    njt_resolver_t         *resolver;
    njt_log_t              *error_log;

    /* server ctx */
    njt_mail_conf_ctx_t    *ctx;

    njt_uint_t              listen;  /* unsigned  listen:1; */
} njt_mail_core_srv_conf_t;


typedef enum {
    njt_pop3_start = 0,
    njt_pop3_user,
    njt_pop3_passwd,
    njt_pop3_auth_login_username,
    njt_pop3_auth_login_password,
    njt_pop3_auth_plain,
    njt_pop3_auth_cram_md5,
    njt_pop3_auth_external
} njt_pop3_state_e;


typedef enum {
    njt_imap_start = 0,
    njt_imap_auth_login_username,
    njt_imap_auth_login_password,
    njt_imap_auth_plain,
    njt_imap_auth_cram_md5,
    njt_imap_auth_external,
    njt_imap_login,
    njt_imap_user,
    njt_imap_passwd
} njt_imap_state_e;


typedef enum {
    njt_smtp_start = 0,
    njt_smtp_auth_login_username,
    njt_smtp_auth_login_password,
    njt_smtp_auth_plain,
    njt_smtp_auth_cram_md5,
    njt_smtp_auth_external,
    njt_smtp_helo,
    njt_smtp_helo_xclient,
    njt_smtp_helo_auth,
    njt_smtp_helo_from,
    njt_smtp_xclient,
    njt_smtp_xclient_from,
    njt_smtp_xclient_helo,
    njt_smtp_xclient_auth,
    njt_smtp_from,
    njt_smtp_to
} njt_smtp_state_e;


typedef struct {
    njt_peer_connection_t   upstream;
    njt_buf_t              *buffer;
    njt_uint_t              proxy_protocol;  /* unsigned  proxy_protocol:1; */
} njt_mail_proxy_ctx_t;


typedef struct {
    uint32_t                signature;         /* "MAIL" */

    njt_connection_t       *connection;

    njt_str_t               out;
    njt_buf_t              *buffer;

    void                  **ctx;
    void                  **main_conf;
    void                  **srv_conf;

    njt_resolver_ctx_t     *resolver_ctx;

    njt_mail_proxy_ctx_t   *proxy;

    njt_uint_t              mail_state;

    unsigned                ssl:1;
    unsigned                protocol:3;
    unsigned                blocked:1;
    unsigned                quit:1;
    unsigned                quoted:1;
    unsigned                backslash:1;
    unsigned                no_sync_literal:1;
    unsigned                starttls:1;
    unsigned                esmtp:1;
    unsigned                auth_method:3;
    unsigned                auth_wait:1;

    njt_str_t               login;
    njt_str_t               passwd;

    njt_str_t               salt;
    njt_str_t               tag;
    njt_str_t               tagged_line;
    njt_str_t               text;

    njt_str_t              *addr_text;
    njt_str_t               host;
    njt_str_t               smtp_helo;
    njt_str_t               smtp_from;
    njt_str_t               smtp_to;

    njt_str_t               cmd;

    njt_uint_t              command;
    njt_array_t             args;

    njt_uint_t              errors;
    njt_uint_t              login_attempt;

    /* used to parse POP3/IMAP/SMTP command */

    njt_uint_t              state;
    u_char                 *tag_start;
    u_char                 *cmd_start;
    u_char                 *arg_start;
    njt_uint_t              literal_len;
} njt_mail_session_t;


typedef struct {
    njt_str_t              *client;
    njt_mail_session_t     *session;
} njt_mail_log_ctx_t;


#define NJT_POP3_USER          1
#define NJT_POP3_PASS          2
#define NJT_POP3_CAPA          3
#define NJT_POP3_QUIT          4
#define NJT_POP3_NOOP          5
#define NJT_POP3_STLS          6
#define NJT_POP3_APOP          7
#define NJT_POP3_AUTH          8
#define NJT_POP3_STAT          9
#define NJT_POP3_LIST          10
#define NJT_POP3_RETR          11
#define NJT_POP3_DELE          12
#define NJT_POP3_RSET          13
#define NJT_POP3_TOP           14
#define NJT_POP3_UIDL          15


#define NJT_IMAP_LOGIN         1
#define NJT_IMAP_LOGOUT        2
#define NJT_IMAP_CAPABILITY    3
#define NJT_IMAP_NOOP          4
#define NJT_IMAP_STARTTLS      5

#define NJT_IMAP_NEXT          6

#define NJT_IMAP_AUTHENTICATE  7


#define NJT_SMTP_HELO          1
#define NJT_SMTP_EHLO          2
#define NJT_SMTP_AUTH          3
#define NJT_SMTP_QUIT          4
#define NJT_SMTP_NOOP          5
#define NJT_SMTP_MAIL          6
#define NJT_SMTP_RSET          7
#define NJT_SMTP_RCPT          8
#define NJT_SMTP_DATA          9
#define NJT_SMTP_VRFY          10
#define NJT_SMTP_EXPN          11
#define NJT_SMTP_HELP          12
#define NJT_SMTP_STARTTLS      13


#define NJT_MAIL_AUTH_PLAIN             0
#define NJT_MAIL_AUTH_LOGIN             1
#define NJT_MAIL_AUTH_LOGIN_USERNAME    2
#define NJT_MAIL_AUTH_APOP              3
#define NJT_MAIL_AUTH_CRAM_MD5          4
#define NJT_MAIL_AUTH_EXTERNAL          5
#define NJT_MAIL_AUTH_NONE              6


#define NJT_MAIL_AUTH_PLAIN_ENABLED     0x0002
#define NJT_MAIL_AUTH_LOGIN_ENABLED     0x0004
#define NJT_MAIL_AUTH_APOP_ENABLED      0x0008
#define NJT_MAIL_AUTH_CRAM_MD5_ENABLED  0x0010
#define NJT_MAIL_AUTH_EXTERNAL_ENABLED  0x0020
#define NJT_MAIL_AUTH_NONE_ENABLED      0x0040


#define NJT_MAIL_PARSE_INVALID_COMMAND  20


typedef void (*njt_mail_init_session_pt)(njt_mail_session_t *s,
    njt_connection_t *c);
typedef void (*njt_mail_init_protocol_pt)(njt_event_t *rev);
typedef void (*njt_mail_auth_state_pt)(njt_event_t *rev);
typedef njt_int_t (*njt_mail_parse_command_pt)(njt_mail_session_t *s);


struct njt_mail_protocol_s {
    njt_str_t                   name;
    njt_str_t                   alpn;
    in_port_t                   port[4];
    njt_uint_t                  type;

    njt_mail_init_session_pt    init_session;
    njt_mail_init_protocol_pt   init_protocol;
    njt_mail_parse_command_pt   parse_command;
    njt_mail_auth_state_pt      auth_state;

    njt_str_t                   internal_server_error;
    njt_str_t                   cert_error;
    njt_str_t                   no_cert;
};


typedef struct {
    njt_mail_protocol_t        *protocol;

    void                       *(*create_main_conf)(njt_conf_t *cf);
    char                       *(*init_main_conf)(njt_conf_t *cf, void *conf);

    void                       *(*create_srv_conf)(njt_conf_t *cf);
    char                       *(*merge_srv_conf)(njt_conf_t *cf, void *prev,
                                                  void *conf);
} njt_mail_module_t;


#define NJT_MAIL_MODULE         0x4C49414D     /* "MAIL" */

#define NJT_MAIL_MAIN_CONF      0x02000000
#define NJT_MAIL_SRV_CONF       0x04000000


#define NJT_MAIL_MAIN_CONF_OFFSET  offsetof(njt_mail_conf_ctx_t, main_conf)
#define NJT_MAIL_SRV_CONF_OFFSET   offsetof(njt_mail_conf_ctx_t, srv_conf)


#define njt_mail_get_module_ctx(s, module)     (s)->ctx[module.ctx_index]
#define njt_mail_set_ctx(s, c, module)         s->ctx[module.ctx_index] = c;
#define njt_mail_delete_ctx(s, module)         s->ctx[module.ctx_index] = NULL;


#define njt_mail_get_module_main_conf(s, module)                             \
    (s)->main_conf[module.ctx_index]
#define njt_mail_get_module_srv_conf(s, module)  (s)->srv_conf[module.ctx_index]

#define njt_mail_conf_get_module_main_conf(cf, module)                       \
    ((njt_mail_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define njt_mail_conf_get_module_srv_conf(cf, module)                        \
    ((njt_mail_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]


#if (NJT_MAIL_SSL)
void njt_mail_starttls_handler(njt_event_t *rev);
njt_int_t njt_mail_starttls_only(njt_mail_session_t *s, njt_connection_t *c);
#endif


void njt_mail_init_connection(njt_connection_t *c);

njt_int_t njt_mail_salt(njt_mail_session_t *s, njt_connection_t *c,
    njt_mail_core_srv_conf_t *cscf);
njt_int_t njt_mail_auth_plain(njt_mail_session_t *s, njt_connection_t *c,
    njt_uint_t n);
njt_int_t njt_mail_auth_login_username(njt_mail_session_t *s,
    njt_connection_t *c, njt_uint_t n);
njt_int_t njt_mail_auth_login_password(njt_mail_session_t *s,
    njt_connection_t *c);
njt_int_t njt_mail_auth_cram_md5_salt(njt_mail_session_t *s,
    njt_connection_t *c, char *prefix, size_t len);
njt_int_t njt_mail_auth_cram_md5(njt_mail_session_t *s, njt_connection_t *c);
njt_int_t njt_mail_auth_external(njt_mail_session_t *s, njt_connection_t *c,
    njt_uint_t n);
njt_int_t njt_mail_auth_parse(njt_mail_session_t *s, njt_connection_t *c);

void njt_mail_send(njt_event_t *wev);
njt_int_t njt_mail_read_command(njt_mail_session_t *s, njt_connection_t *c);
void njt_mail_auth(njt_mail_session_t *s, njt_connection_t *c);
void njt_mail_close_connection(njt_connection_t *c);
void njt_mail_session_internal_server_error(njt_mail_session_t *s);
u_char *njt_mail_log_error(njt_log_t *log, u_char *buf, size_t len);


char *njt_mail_capabilities(njt_conf_t *cf, njt_command_t *cmd, void *conf);


/* STUB */
void njt_mail_proxy_init(njt_mail_session_t *s, njt_addr_t *peer);
void njt_mail_auth_http_init(njt_mail_session_t *s);
njt_int_t njt_mail_realip_handler(njt_mail_session_t *s);
/**/


extern njt_uint_t    njt_mail_max_module;
extern njt_module_t  njt_mail_core_module;


#endif /* _NJT_MAIL_H_INCLUDED_ */
