
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_SYSLOG_H_INCLUDED_
#define _NJT_SYSLOG_H_INCLUDED_


typedef struct {
    njt_uint_t         facility;
    njt_uint_t         severity;
    njt_str_t          tag;

    njt_str_t         *hostname;

    njt_addr_t         server;
    njt_connection_t   conn;

    njt_log_t          log;
    njt_log_t         *logp;

    unsigned           busy:1;
    unsigned           nohostname:1;
} njt_syslog_peer_t;


char *njt_syslog_process_conf(njt_conf_t *cf, njt_syslog_peer_t *peer);
u_char *njt_syslog_add_header(njt_syslog_peer_t *peer, u_char *buf);
void njt_syslog_writer(njt_log_t *log, njt_uint_t level, u_char *buf,
    size_t len);
ssize_t njt_syslog_send(njt_syslog_peer_t *peer, u_char *buf, size_t len);


#endif /* _NJT_SYSLOG_H_INCLUDED_ */
