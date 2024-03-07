
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


#define NJT_SYSLOG_MAX_STR                                                    \
    NJT_MAX_ERROR_STR + sizeof("<255>Jan 01 00:00:00 ") - 1                   \
    + (NJT_MAXHOSTNAMELEN - 1) + 1 /* space */                                \
    + 32 /* tag */ + 2 /* colon, space */


static char *njt_syslog_parse_args(njt_conf_t *cf, njt_syslog_peer_t *peer);
static njt_int_t njt_syslog_init_peer(njt_syslog_peer_t *peer);
static void njt_syslog_cleanup(void *data);
static u_char *njt_syslog_log_error(njt_log_t *log, u_char *buf, size_t len);


static char  *facilities[] = {
    "kern", "user", "mail", "daemon", "auth", "intern", "lpr", "news", "uucp",
    "clock", "authpriv", "ftp", "ntp", "audit", "alert", "cron", "local0",
    "local1", "local2", "local3", "local4", "local5", "local6", "local7",
    NULL
};

/* note 'error/warn' like in njet.conf, not 'err/warning' */
static char  *severities[] = {
    "emerg", "alert", "crit", "error", "warn", "notice", "info", "debug", NULL
};

static njt_log_t    njt_syslog_dummy_log;
static njt_event_t  njt_syslog_dummy_event;


char *
njt_syslog_process_conf(njt_conf_t *cf, njt_syslog_peer_t *peer)
{
    njt_pool_cleanup_t  *cln;

    peer->facility = NJT_CONF_UNSET_UINT;
    peer->severity = NJT_CONF_UNSET_UINT;

    if (njt_syslog_parse_args(cf, peer) != NJT_CONF_OK) {
        return NJT_CONF_ERROR;
    }

    if (peer->server.sockaddr == NULL) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "no syslog server specified");
        return NJT_CONF_ERROR;
    }

    if (peer->facility == NJT_CONF_UNSET_UINT) {
        peer->facility = 23; /* local7 */
    }

    if (peer->severity == NJT_CONF_UNSET_UINT) {
        peer->severity = 6; /* info */
    }

    if (peer->tag.data == NULL) {
        njt_str_set(&peer->tag, "njet");
    }

    peer->hostname = &cf->cycle->hostname;
    peer->logp = &cf->cycle->new_log;

    peer->conn.fd = (njt_socket_t) -1;

    peer->conn.read = &njt_syslog_dummy_event;
    peer->conn.write = &njt_syslog_dummy_event;

    njt_syslog_dummy_event.log = &njt_syslog_dummy_log;

    cln = njt_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NJT_CONF_ERROR;
    }

    cln->data = peer;
    cln->handler = njt_syslog_cleanup;

    return NJT_CONF_OK;
}


static char *
njt_syslog_parse_args(njt_conf_t *cf, njt_syslog_peer_t *peer)
{
    u_char      *p, *comma, c;
    size_t       len;
    njt_str_t   *value;
    njt_url_t    u;
    njt_uint_t   i;

    value = cf->args->elts;

    p = value[1].data + sizeof("syslog:") - 1;

    for ( ;; ) {
        comma = (u_char *) njt_strchr(p, ',');

        if (comma != NULL) {
            len = comma - p;
            *comma = '\0';

        } else {
            len = value[1].data + value[1].len - p;
        }

        if (njt_strncmp(p, "server=", 7) == 0) {

            if (peer->server.sockaddr != NULL) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "duplicate syslog \"server\"");
                return NJT_CONF_ERROR;
            }

            njt_memzero(&u, sizeof(njt_url_t));

            u.url.data = p + 7;
            u.url.len = len - 7;
            u.default_port = 514;

            if (njt_parse_url(cf->pool, &u) != NJT_OK) {
                if (u.err) {
                    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                       "%s in syslog server \"%V\"",
                                       u.err, &u.url);
                }

                return NJT_CONF_ERROR;
            }

            peer->server = u.addrs[0];

        } else if (njt_strncmp(p, "facility=", 9) == 0) {

            if (peer->facility != NJT_CONF_UNSET_UINT) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "duplicate syslog \"facility\"");
                return NJT_CONF_ERROR;
            }

            for (i = 0; facilities[i] != NULL; i++) {

                if (njt_strcmp(p + 9, facilities[i]) == 0) {
                    peer->facility = i;
                    goto next;
                }
            }

            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "unknown syslog facility \"%s\"", p + 9);
            return NJT_CONF_ERROR;

        } else if (njt_strncmp(p, "severity=", 9) == 0) {

            if (peer->severity != NJT_CONF_UNSET_UINT) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "duplicate syslog \"severity\"");
                return NJT_CONF_ERROR;
            }

            for (i = 0; severities[i] != NULL; i++) {

                if (njt_strcmp(p + 9, severities[i]) == 0) {
                    peer->severity = i;
                    goto next;
                }
            }

            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "unknown syslog severity \"%s\"", p + 9);
            return NJT_CONF_ERROR;

        } else if (njt_strncmp(p, "tag=", 4) == 0) {

            if (peer->tag.data != NULL) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "duplicate syslog \"tag\"");
                return NJT_CONF_ERROR;
            }

            /*
             * RFC 3164: the TAG is a string of ABNF alphanumeric characters
             * that MUST NOT exceed 32 characters.
             */
            if (len - 4 > 32) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "syslog tag length exceeds 32");
                return NJT_CONF_ERROR;
            }

            for (i = 4; i < len; i++) {
                c = njt_tolower(p[i]);

                if (c < '0' || (c > '9' && c < 'a' && c != '_') || c > 'z') {
                    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                       "syslog \"tag\" only allows "
                                       "alphanumeric characters "
                                       "and underscore");
                    return NJT_CONF_ERROR;
                }
            }

            peer->tag.data = p + 4;
            peer->tag.len = len - 4;

        } else if (len == 10 && njt_strncmp(p, "nohostname", 10) == 0) {
            peer->nohostname = 1;

        } else {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "unknown syslog parameter \"%s\"", p);
            return NJT_CONF_ERROR;
        }

    next:

        if (comma == NULL) {
            break;
        }

        p = comma + 1;
    }

    return NJT_CONF_OK;
}


u_char *
njt_syslog_add_header(njt_syslog_peer_t *peer, u_char *buf)
{
    njt_uint_t  pri;

    pri = peer->facility * 8 + peer->severity;

    if (peer->nohostname) {
        return njt_sprintf(buf, "<%ui>%V %V: ", pri, &njt_cached_syslog_time,
                           &peer->tag);
    }

    return njt_sprintf(buf, "<%ui>%V %V %V: ", pri, &njt_cached_syslog_time,
                       peer->hostname, &peer->tag);
}


void
njt_syslog_writer(njt_log_t *log, njt_uint_t level, u_char *buf,
    size_t len)
{
    u_char             *p, msg[NJT_SYSLOG_MAX_STR];
    njt_uint_t          head_len;
    njt_syslog_peer_t  *peer;

    peer = log->wdata;

    if (peer->busy) {
        return;
    }

    peer->busy = 1;
    peer->severity = level - 1;

    p = njt_syslog_add_header(peer, msg);
    head_len = p - msg;

    len -= NJT_LINEFEED_SIZE;

    if (len > NJT_SYSLOG_MAX_STR - head_len) {
        len = NJT_SYSLOG_MAX_STR - head_len;
    }

    p = njt_snprintf(p, len, "%s", buf);

    (void) njt_syslog_send(peer, msg, p - msg);

    peer->busy = 0;
}


ssize_t
njt_syslog_send(njt_syslog_peer_t *peer, u_char *buf, size_t len)
{
    ssize_t  n;

    if (peer->log.handler == NULL) {
        peer->log = *peer->logp;
        peer->log.handler = njt_syslog_log_error;
        peer->log.data = peer;
        peer->log.action = "logging to syslog";
    }

    if (peer->conn.fd == (njt_socket_t) -1) {
        if (njt_syslog_init_peer(peer) != NJT_OK) {
            return NJT_ERROR;
        }
    }

    if (njt_send) {
        n = njt_send(&peer->conn, buf, len);

    } else {
        /* event module has not yet set njt_io */
        n = njt_os_io.send(&peer->conn, buf, len);
    }

    if (n == NJT_ERROR) {

        if (njt_close_socket(peer->conn.fd) == -1) {
            njt_log_error(NJT_LOG_ALERT, &peer->log, njt_socket_errno,
                          njt_close_socket_n " failed");
        }

        peer->conn.fd = (njt_socket_t) -1;
    }

    return n;
}


static njt_int_t
njt_syslog_init_peer(njt_syslog_peer_t *peer)
{
    njt_socket_t  fd;

    fd = njt_socket(peer->server.sockaddr->sa_family, SOCK_DGRAM, 0);
    if (fd == (njt_socket_t) -1) {
        njt_log_error(NJT_LOG_ALERT, &peer->log, njt_socket_errno,
                      njt_socket_n " failed");
        return NJT_ERROR;
    }

    if (njt_nonblocking(fd) == -1) {
        njt_log_error(NJT_LOG_ALERT, &peer->log, njt_socket_errno,
                      njt_nonblocking_n " failed");
        goto failed;
    }

    if (connect(fd, peer->server.sockaddr, peer->server.socklen) == -1) {
        njt_log_error(NJT_LOG_ALERT, &peer->log, njt_socket_errno,
                      "connect() failed");
        goto failed;
    }

    peer->conn.fd = fd;
    peer->conn.log = &peer->log;

    /* UDP sockets are always ready to write */
    peer->conn.write->ready = 1;

    return NJT_OK;

failed:

    if (njt_close_socket(fd) == -1) {
        njt_log_error(NJT_LOG_ALERT, &peer->log, njt_socket_errno,
                      njt_close_socket_n " failed");
    }

    return NJT_ERROR;
}


static void
njt_syslog_cleanup(void *data)
{
    njt_syslog_peer_t  *peer = data;

    /* prevents further use of this peer */
    peer->busy = 1;

    if (peer->conn.fd == (njt_socket_t) -1) {
        return;
    }

    if (njt_close_socket(peer->conn.fd) == -1) {
        njt_log_error(NJT_LOG_ALERT, &peer->log, njt_socket_errno,
                      njt_close_socket_n " failed");
    }
}


static u_char *
njt_syslog_log_error(njt_log_t *log, u_char *buf, size_t len)
{
    u_char             *p;
    njt_syslog_peer_t  *peer;

    p = buf;

    if (log->action) {
        p = njt_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
    }

    peer = log->data;

    if (peer) {
        p = njt_snprintf(p, len, ", server: %V", &peer->server.name);
    }

    return p;
}
