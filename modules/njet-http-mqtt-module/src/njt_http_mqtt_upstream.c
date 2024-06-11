/*
 * Copyright (c) 2010, FRiCKLE Piotr Sikora <info@frickle.com>
 * Copyright (c) 2009-2010, Xiaozhe Wang <chaoslawful@gmail.com>
 * Copyright (c) 2009-2010, Yichun Zhang <agentzh@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include <njet.h>
#include "njt_http_mqtt_module.h"
#include "njt_http_mqtt_keepalive.h"
#include "njt_http_mqtt_processor.h"


njt_int_t
njt_http_mqtt_upstream_init(njt_conf_t *cf, njt_http_upstream_srv_conf_t *uscf)
{
    njt_http_mqtt_upstream_srv_conf_t   *mqttscf;
    njt_http_upstream_server_t          *server;
    njt_http_mqtt_upstream_server_t     *self_server;
    njt_http_mqtt_upstream_peers_t      *peers;
    njt_uint_t                          i, j, n;

    uscf->peer.init = njt_http_mqtt_upstream_init_peer;

    mqttscf = njt_http_conf_upstream_srv_conf(uscf, njt_http_mqtt_module);
    if (mqttscf->servers == NULL || mqttscf->servers->nelts == 0) {
        njt_log_error(NJT_LOG_ERR, cf->log, 0,
                      "http_mqtt: no \"http_mqtt_server\" defined"
                      " in upstream \"%V\" in %s:%ui",
                      &uscf->host, uscf->file_name, uscf->line);

        return NJT_ERROR;
    }

    /* mqttscf->servers != NULL */

    server = uscf->servers->elts;

    n = 0;

    for (i = 0; i < uscf->servers->nelts; i++) {
        n += server[i].naddrs;
    }

    peers = njt_pcalloc(cf->pool, sizeof(njt_http_mqtt_upstream_peers_t)
            + sizeof(njt_http_mqtt_upstream_peer_t) * (n - 1));

    if (peers == NULL) {
        return NJT_ERROR;
    }

    peers->single = (n == 1);
    peers->number = n;
    peers->name = &uscf->host;

    n = 0;

    for (i = 0; i < uscf->servers->nelts; i++) {
        for (j = 0; j < server[i].naddrs; j++) {
            peers->peer[n].sockaddr = server[i].addrs[j].sockaddr;
            peers->peer[n].socklen = server[i].addrs[j].socklen;
            peers->peer[n].name = server[i].addrs[j].name;
            if(server[i].data != NULL){
                self_server = (njt_http_mqtt_upstream_server_t *)server[i].data;
                peers->peer[n].port = self_server->port;
                peers->peer[n].user = self_server->user;
                peers->peer[n].password = self_server->password;
            }

            peers->peer[n].host.data = njt_pnalloc(cf->pool,
                                                   NJT_SOCKADDR_STRLEN);
            if (peers->peer[n].host.data == NULL) {
                return NJT_ERROR;
            }

            peers->peer[n].host.len = njt_sock_ntop(peers->peer[n].sockaddr,
                                          peers->peer[n].socklen,
                                          peers->peer[n].host.data,
                                          NJT_SOCKADDR_STRLEN, 0);
            if (peers->peer[n].host.len == 0) {
                return NJT_ERROR;
            }

            n++;
        }
    }

    mqttscf->peers = peers;
    mqttscf->active_conns = 0;

    if (mqttscf->max_cached) {
        return njt_http_mqtt_keepalive_init(cf->pool, mqttscf);
    }

    return NJT_OK;
}

njt_int_t
njt_http_mqtt_upstream_init_peer(njt_http_request_t *r,
    njt_http_upstream_srv_conf_t *uscf)
{
    njt_http_mqtt_upstream_peer_data_t  *mqttdt;
    njt_http_mqtt_upstream_srv_conf_t   *mqttscf;
    njt_http_mqtt_loc_conf_t            *mqttlcf;
    // njt_http_mqtt_ctx_t                 *mqttctx;
    njt_http_upstream_t                *u;


    mqttdt = njt_pcalloc(r->pool, sizeof(njt_http_mqtt_upstream_peer_data_t));
    if (mqttdt == NULL) {
        goto failed;
    }

    u = r->upstream;

    mqttdt->upstream = u;
    mqttdt->request = r;

    mqttdt->get_peer_times = 0;     //get peer times

    mqttscf = njt_http_conf_upstream_srv_conf(uscf, njt_http_mqtt_module);
    mqttlcf = njt_http_get_module_loc_conf(r, njt_http_mqtt_module);
    // mqttctx = njt_http_get_module_ctx(r, njt_http_mqtt_module);

    mqttdt->srv_conf = mqttscf;
    mqttdt->max_retry_times = mqttscf->retry_times;

    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, 
        "malloc mattdata mqttdt->get_peer_times:%d mqttscf->retry_times:%d send_buffer_size:%d",
        mqttdt->get_peer_times,mqttscf->retry_times, mqttscf->send_buffer_size);

    mqttdt->loc_conf = mqttlcf;

    u->peer.data = mqttdt;
    u->peer.get = njt_http_mqtt_upstream_get_peer;
    u->peer.free = njt_http_mqtt_upstream_free_peer;

    return NJT_OK;

failed:

    return NJT_ERROR;
}

njt_int_t
njt_http_mqtt_upstream_get_peer(njt_peer_connection_t *pc, void *data)
{
    njt_http_mqtt_upstream_peer_data_t  *mqttdt = data;
    njt_http_mqtt_upstream_srv_conf_t   *mqttscf;

    njt_http_mqtt_upstream_peers_t      *peers;
    njt_http_mqtt_upstream_peer_t       *peer;
    njt_connection_t                   *mqttxc = NULL;
    int                                 fd;
    njt_event_t                        *rev, *wev;
    njt_int_t                           rc;
    njt_err_t                           err;
    int                                 type, value;
#if (NJT_HAVE_IP_BIND_ADDRESS_NO_PORT || NJT_LINUX)
    in_port_t          port;
#endif

    mqttscf = mqttdt->srv_conf;

    if (mqttscf->max_cached && mqttscf->single) {
        rc = njt_http_mqtt_keepalive_get_peer_single(pc, mqttdt, mqttscf);
        if (rc != NJT_DECLINED) {
            /* re-use keepalive peer */
            njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0,"re-using keepalive peer (single)");

            mqttdt->state = state_mqtt_publish;
            // njt_http_mqtt_process_events(mqttdt->request);
            mqttxc = mqttdt->request->upstream->peer.connection;
            rc = njt_http_mqtt_upstream_internal_publish(mqttdt->request, mqttxc, mqttdt);
            if(rc != NJT_OK){
                return NJT_ERROR;
            }else{
                return NJT_AGAIN;
            }
        }
    }

    peers = mqttscf->peers;

    if (mqttscf->current > peers->number - 1) {
        mqttscf->current = 0;
    }

    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,"mqtt current server:%d", mqttscf->current);
    peer = &peers->peer[mqttscf->current++];

    mqttdt->name.len = peer->name.len;
    mqttdt->name.data = peer->name.data;
    mqttdt->user = peer->user;
    mqttdt->password = peer->password;
    mqttdt->sockaddr = *peer->sockaddr;

    pc->name = &mqttdt->name;
    pc->sockaddr = &mqttdt->sockaddr;
    pc->socklen = peer->socklen;
    pc->cached = 0;

    if ((mqttscf->max_cached) && (!mqttscf->single)) {
        rc = njt_http_mqtt_keepalive_get_peer_multi(pc, mqttdt, mqttscf);
        if (rc != NJT_DECLINED) {
            /* re-use keepalive peer */
            njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0,"re-using keepalive peer (multi)");

            mqttdt->state = state_mqtt_publish;
            // njt_http_mqtt_process_events(mqttdt->request);
            mqttxc = mqttdt->request->upstream->peer.connection;
            rc = njt_http_mqtt_upstream_internal_publish(mqttdt->request, mqttxc, mqttdt);
            if(rc != NJT_OK){
                return NJT_ERROR;
            }else{
                return NJT_AGAIN;
            }
            return NJT_AGAIN;
        }
    }

    if ((mqttscf->reject) && (mqttscf->active_conns >= mqttscf->max_cached)) {
        njt_log_error(NJT_LOG_INFO, pc->log, 0,
                      "http_mqtt: keepalive connection pool is full,"
                      " rejecting request to upstream \"%V\"", &peer->name);

        /* a bit hack-ish way to return error response (setup part) */
        pc->connection = njt_get_connection(0, pc->log);

        return NJT_AGAIN;
    }

    type = (pc->type ? pc->type : SOCK_STREAM);

    /* take spot in keepalive connection pool */
    mqttscf->active_conns++;

    /* add the file descriptor (fd) into an njet connection structure */

#if (NJT_HAVE_SOCKET_CLOEXEC) // openresty patch
    fd = njt_socket(pc->sockaddr->sa_family, type | SOCK_CLOEXEC, 0);

#else
    fd = njt_socket(pc->sockaddr->sa_family, type, 0);

#endif // openresty patch end

    if (fd == -1) {
        njt_log_error(NJT_LOG_ERR, pc->log, 0,
                      "http_mqtt: failed to get connection fd");

        goto invalid;
    }

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, pc->log, 0,
                   "http_mqtt: connection fd:%d", fd);

    mqttxc = pc->connection = njt_get_connection(fd, pc->log);
    if (mqttxc == NULL) {
        njt_log_error(NJT_LOG_ERR, pc->log, 0,
                      "http_mqtt: failed to get a free njet connection");

        goto invalid;
    }

    if (pc->rcvbuf) {
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
                       (const void *) &pc->rcvbuf, sizeof(int)) == -1)
        {
            njt_log_error(NJT_LOG_ALERT, pc->log, njt_socket_errno,
                          "setsockopt(SO_RCVBUF) failed");
            goto invalid;
        }
    }

    if (pc->so_keepalive) {
        value = 1;

        if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,
                       (const void *) &value, sizeof(int))
            == -1)
        {
            njt_log_error(NJT_LOG_ALERT, pc->log, njt_socket_errno,
                          "setsockopt(SO_KEEPALIVE) failed, ignored");
        }
    }

    if (njt_nonblocking(fd) == -1) {
        njt_log_error(NJT_LOG_ALERT, pc->log, njt_socket_errno,
                      njt_nonblocking_n " failed");

        goto invalid;
    }

#if (NJT_HAVE_FD_CLOEXEC) // openresty patch
    if (njt_cloexec(fd) == -1) {
        njt_log_error(NJT_LOG_ALERT, pc->log, njt_socket_errno,
                      njt_cloexec_n " failed");

        goto invalid;
    }
#endif // openresty patch end

    if (pc->local) {

// #if (NJT_HAVE_TRANSPARENT_PROXY)
//         if (pc->transparent) {
//             if (njt_event_connect_set_transparent(pc, fd) != NJT_OK) {
//                 goto invalid;
//             }
//         }
// #endif

#if (NJT_HAVE_IP_BIND_ADDRESS_NO_PORT || NJT_LINUX)
        port = njt_inet_get_port(pc->local->sockaddr);
#endif

#if (NJT_HAVE_IP_BIND_ADDRESS_NO_PORT)

        if (pc->sockaddr->sa_family != AF_UNIX && port == 0) {
            static int  bind_address_no_port = 1;

            if (bind_address_no_port) {
                if (setsockopt(fd, IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT,
                               (const void *) &bind_address_no_port,
                               sizeof(int)) == -1)
                {
                    err = njt_socket_errno;

                    if (err != NJT_EOPNOTSUPP && err != NJT_ENOPROTOOPT) {
                        njt_log_error(NJT_LOG_ALERT, pc->log, err,
                                      "setsockopt(IP_BIND_ADDRESS_NO_PORT) "
                                      "failed, ignored");

                    } else {
                        bind_address_no_port = 0;
                    }
                }
            }
        }

#endif

#if (NJT_LINUX)

        if (pc->type == SOCK_DGRAM && port != 0) {
            int  reuse_addr = 1;

            if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                           (const void *) &reuse_addr, sizeof(int))
                 == -1)
            {
                njt_log_error(NJT_LOG_ALERT, pc->log, njt_socket_errno,
                              "setsockopt(SO_REUSEADDR) failed");
                goto invalid;
            }
        }

#endif

        if (bind(fd, pc->local->sockaddr, pc->local->socklen) == -1) {
            njt_log_error(NJT_LOG_CRIT, pc->log, njt_socket_errno,
                          "bind(%V) failed", &pc->local->name);

            goto invalid;
        }
    }

    if (type == SOCK_STREAM) {
        mqttxc->recv = njt_recv;
        mqttxc->send = njt_send;
        mqttxc->recv_chain = njt_recv_chain;
        mqttxc->send_chain = njt_send_chain;

        mqttxc->sendfile = 1;

        if (pc->sockaddr->sa_family == AF_UNIX) {
            mqttxc->tcp_nopush = NJT_TCP_NOPUSH_DISABLED;
            mqttxc->tcp_nodelay = NJT_TCP_NODELAY_DISABLED;

#if (NJT_SOLARIS)
            /* Solaris's sendfilev() supports AF_NCA, AF_INET, and AF_INET6 */
            c->sendfile = 0;
#endif
        }

    } else { /* type == SOCK_DGRAM */
        mqttxc->recv = njt_udp_recv;
        mqttxc->send = njt_send;
        mqttxc->send_chain = njt_udp_send_chain;

        mqttxc->need_flush_buf = 1;
    }

    mqttxc->log = pc->log;
    mqttxc->log_error = pc->log_error;
    mqttxc->number = njt_atomic_fetch_add(njt_connection_counter, 1);

    rev = mqttxc->read;
    wev = mqttxc->write;

    rev->log = pc->log;
    wev->log = pc->log;

    /* register the connection with http_mqtt connection fd into the
     * njet event model */

    if (njt_event_flags & NJT_USE_RTSIG_EVENT) {
        njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,"NJT_USE_RTSIG_EVENT");
        if (njt_add_conn(mqttxc) != NJT_OK) {
            goto bad_add;
        }

    } else if (njt_event_flags & NJT_USE_CLEAR_EVENT) {
        njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,"NJT_USE_CLEAR_EVENT");
        if (njt_add_event(rev, NJT_READ_EVENT, NJT_CLEAR_EVENT) != NJT_OK) {
            goto bad_add;
        }

        if (njt_add_event(wev, NJT_WRITE_EVENT, NJT_CLEAR_EVENT) != NJT_OK) {
            goto bad_add;
        }

    } else {
        njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,"NJT_USE_LEVEL_EVENT");
        if (njt_add_event(rev, NJT_READ_EVENT, NJT_LEVEL_EVENT) != NJT_OK) {
            goto bad_add;
        }

        if (njt_add_event(wev, NJT_WRITE_EVENT, NJT_LEVEL_EVENT) != NJT_OK) {
            goto bad_add;
        }
    }

    mqttxc->log->action = "connecting to mqtt database";
    mqttdt->state = state_mqtt_connect;

    return NJT_AGAIN;

bad_add:

    njt_log_error(NJT_LOG_ERR, pc->log, 0,
                  "mqtt: failed to get peer");

invalid:

    njt_http_mqtt_upstream_free_connection(pc->log, pc->connection,
                                          mqttdt->mqtt_conn, mqttscf);

    return NJT_ERROR;
}

void
njt_http_mqtt_upstream_free_peer(njt_peer_connection_t *pc,
    void *data, njt_uint_t state)
{
    njt_http_mqtt_upstream_peer_data_t  *mqttdt = data;
    njt_http_mqtt_upstream_srv_conf_t   *mqttscf;

    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,"mqtt entering njt_http_mqtt_upstream_free_peer");

    mqttscf = mqttdt->srv_conf;

    if (mqttscf->max_cached) {
        njt_http_mqtt_keepalive_free_peer(pc, mqttdt, mqttscf, state);
    }

    if (pc->connection) {
        njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,"free connection to mqtt database");

        njt_http_mqtt_upstream_free_connection(pc->log, pc->connection,
                mqttdt->mqtt_conn, mqttscf);

        mqttdt->mqtt_conn = NULL;
        pc->connection = NULL;
    }

    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,"mqtt returning njt_http_mqtt_upstream_free_peer");
}

njt_flag_t
njt_http_mqtt_upstream_is_my_peer(const njt_peer_connection_t *peer)
{
    return (peer->get == njt_http_mqtt_upstream_get_peer);
}

void
njt_http_mqtt_upstream_free_connection(njt_log_t *log, njt_connection_t *c,
    struct mqtt_client *mqtt_conn, njt_http_mqtt_upstream_srv_conf_t *mqttscf)
{
    njt_event_t  *rev, *wev;

    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,"mqtt entering njt_http_mqtt_upstream_free_connection");

    // PQfinish(mqtt_conn);

    if (c) {
        rev = c->read;
        wev = c->write;

        if (rev->timer_set) {
            njt_del_timer(rev);
        }

        if (wev->timer_set) {
            njt_del_timer(wev);
        }

        if (njt_del_conn) {
           njt_del_conn(c, NJT_CLOSE_EVENT);
        } else {
            if (rev->active || rev->disabled) {
                njt_del_event(rev, NJT_READ_EVENT, NJT_CLOSE_EVENT);
            }

            if (wev->active || wev->disabled) {
                njt_del_event(wev, NJT_WRITE_EVENT, NJT_CLOSE_EVENT);
            }
        }


        if (rev->posted) {
            njt_delete_posted_event(rev);
        }

        if (wev->posted) {
            njt_delete_posted_event(wev);
        }

        rev->closed = 1;
        wev->closed = 1;

        if (c->pool) {
            njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,"mqtt close connection pool:%p", c->pool);
            njt_destroy_pool(c->pool);
            c->pool = NULL;
        }

        njt_free_connection(c);

        c->fd = (njt_socket_t) -1;
    
        if(mqtt_conn != NULL){
            mqtt_exit(mqtt_conn);
        }
    }

    /* free spot in keepalive connection pool */
    mqttscf->active_conns--;

    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,"mqtt returning njt_http_mqtt_upstream_free_connection");
}
