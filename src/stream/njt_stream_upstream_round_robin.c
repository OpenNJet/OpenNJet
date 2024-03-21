
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>


#define njt_stream_upstream_tries(p) ((p)->tries                              \
                                      + ((p)->next ? (p)->next->tries : 0))


static njt_stream_upstream_rr_peer_t *njt_stream_upstream_get_peer(
    njt_stream_upstream_rr_peer_data_t *rrp);
static void njt_stream_upstream_notify_round_robin_peer(
    njt_peer_connection_t *pc, void *data, njt_uint_t state);
#if (NJT_STREAM_SSL)

// openresty patch
// static njt_int_t njt_stream_upstream_set_round_robin_peer_session(
//     njt_peer_connection_t *pc, void *data);
// static void njt_stream_upstream_save_round_robin_peer_session(
//     njt_peer_connection_t *pc, void *data);
// openresty patch end

static njt_int_t njt_stream_upstream_empty_set_session(
    njt_peer_connection_t *pc, void *data);
static void njt_stream_upstream_empty_save_session(njt_peer_connection_t *pc,
    void *data);

#endif


#if (NJT_STREAM_FTP_PROXY)
njt_int_t njt_stream_ftp_data_proxy_upstream_init_round_robin(njt_pool_t *pool,
    njt_stream_upstream_srv_conf_t *us)
{
    njt_url_t                        u;
    njt_uint_t                       i, j, n, w, t;
    njt_stream_upstream_server_t    *server;
    njt_stream_upstream_rr_peer_t   *peer, **peerp;
    njt_stream_upstream_rr_peers_t  *peers, *backup;
    njt_msec_t now_time = njt_time();

    us->peer.init = njt_stream_upstream_init_round_robin_peer;

    if (us->servers) {
        server = us->servers->elts;

        n = 0;
        w = 0;
        t = 0;

        peers = njt_pcalloc(pool, sizeof(njt_stream_upstream_rr_peers_t));
        if (peers == NULL) {
            return NJT_ERROR;
        }
        for (i = 0; i < us->servers->nelts; i++) {
            if (server[i].backup) {
                continue;
            }
	    //zyg
	    if(server[i].dynamic != 1){
		server[i].parent_id = -1;
	    }else {
		server[i].parent_id = (njt_int_t)peers->next_order++;
	    }
	    //end
            n += server[i].naddrs;
            w += server[i].naddrs * server[i].weight;

            if (!server[i].down) {
                t += server[i].naddrs;
            }
        }

        peers->single = (n <= 1);
        peers->number = n;
        peers->weighted = (w != n);
        peers->total_weight = w;
        peers->tries = t;
        peers->name = &us->host;
        peerp = &peers->peer;

	if(n > 0) {
	peer = njt_pcalloc(pool, sizeof(njt_stream_upstream_rr_peer_t) * n);
        if (peer == NULL) {
            return NJT_ERROR;
        }
        n = 0;

        for (i = 0; i < us->servers->nelts; i++) {
            if (server[i].backup) {
                continue;
            }

            for (j = 0; j < server[i].naddrs; j++) {
                peer[n].sockaddr = server[i].addrs[j].sockaddr;
                peer[n].socklen = server[i].addrs[j].socklen;
                peer[n].name = server[i].addrs[j].name;
                peer[n].weight = server[i].weight;
                peer[n].effective_weight = server[i].weight;
		peer[n].rr_effective_weight = server[i].weight * NJT_WEIGHT_POWER;
                peer[n].current_weight = 0;
                peer[n].rr_current_weight = 0;
                peer[n].max_conns = server[i].max_conns;
                peer[n].max_fails = server[i].max_fails;
                peer[n].fail_timeout = server[i].fail_timeout;
                peer[n].down = server[i].down;
                peer[n].server = server[i].name;
		peer[n].hc_upstart = now_time;
		//zyg
		peer[n].id = peers->next_order++;
		peer[n].slow_start = server[i].slow_start;
		peer[n].parent_id = server[i].parent_id;
		//end
                *peerp = &peer[n];
                peerp = &peer[n].next;
                n++;
            }
        }
	}
        us->peer.data = peers;

        /* backup servers */

        n = 0;
        w = 0;
        t = 0;

        for (i = 0; i < us->servers->nelts; i++) {
            if (!server[i].backup) {
                continue;
            }
	    if(server[i].dynamic != 1) {
		server[i].parent_id = -1;
	    } else {
		server[i].parent_id = (njt_int_t)peers->next_order++;
	    }
            n += server[i].naddrs;
            w += server[i].naddrs * server[i].weight;

            if (!server[i].down) {
                t += server[i].naddrs;
            }
        }

        if (n == 0) {
            return NJT_OK;
        }

        backup = njt_pcalloc(pool, sizeof(njt_stream_upstream_rr_peers_t));
        if (backup == NULL) {
            return NJT_ERROR;
        }

        peer = njt_pcalloc(pool, sizeof(njt_stream_upstream_rr_peer_t) * n);
        if (peer == NULL) {
            return NJT_ERROR;
        }

        backup->single = 0;
        backup->number = n;
        backup->weighted = (w != n);
        backup->total_weight = w;
        backup->tries = t;
        backup->name = &us->host;

        n = 0;
        peerp = &backup->peer;

        for (i = 0; i < us->servers->nelts; i++) {
            if (!server[i].backup) {
                continue;
            }

            for (j = 0; j < server[i].naddrs; j++) {
                peer[n].sockaddr = server[i].addrs[j].sockaddr;
                peer[n].socklen = server[i].addrs[j].socklen;
                peer[n].name = server[i].addrs[j].name;
                peer[n].weight = server[i].weight;
                peer[n].effective_weight = server[i].weight;
		peer[n].rr_effective_weight = server[i].weight * NJT_WEIGHT_POWER;
                peer[n].current_weight = 0;
                peer[n].rr_current_weight = 0;
                peer[n].max_conns = server[i].max_conns;
                peer[n].max_fails = server[i].max_fails;
                peer[n].fail_timeout = server[i].fail_timeout;
                peer[n].down = server[i].down;
                peer[n].server = server[i].name;
		peer[n].parent_id = server[i].parent_id;
		peer[n].slow_start = server[i].slow_start;
		peer[n].hc_upstart = now_time;
	        peer[n].id = peers->next_order++;
                *peerp = &peer[n];
                peerp = &peer[n].next;
                n++;
            }
        }

        peers->next = backup;
        peers->single = (peers->number + peers->next->number == 1);

        return NJT_OK;
    }


    /* an upstream implicitly defined by proxy_pass, etc. */

    if (us->port == 0) {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0,
                      "no port in upstream \"%V\" in %s:%ui",
                      &us->host, us->file_name, us->line);
        return NJT_ERROR;
    }

    njt_memzero(&u, sizeof(njt_url_t));

    u.host = us->host;
    u.port = us->port;

    if (njt_inet_resolve_host(pool, &u) != NJT_OK) {
        if (u.err) {
            njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0,
                          "%s in upstream \"%V\" in %s:%ui",
                          u.err, &us->host, us->file_name, us->line);
        }

        return NJT_ERROR;
    }

    n = u.naddrs;

    peers = njt_pcalloc(pool, sizeof(njt_stream_upstream_rr_peers_t));
    if (peers == NULL) {
        return NJT_ERROR;
    }

    peer = njt_pcalloc(pool, sizeof(njt_stream_upstream_rr_peer_t) * n);
    if (peer == NULL) {
        return NJT_ERROR;
    }

    peers->single = (n <= 1);
    peers->number = n;
    peers->weighted = 0;
    peers->total_weight = n;
    peers->tries = n;
    peers->name = &us->host;

    peerp = &peers->peer;

    for (i = 0; i < u.naddrs; i++) {
        peer[i].sockaddr = u.addrs[i].sockaddr;
        peer[i].socklen = u.addrs[i].socklen;
        peer[i].name = u.addrs[i].name;
        peer[i].weight = 1;
        peer[i].effective_weight = 1;
	peer[i].rr_effective_weight = 1*NJT_WEIGHT_POWER;
        peer[i].current_weight = 0;
        peer[i].rr_current_weight = 0;
        peer[i].max_conns = 0;
        peer[i].max_fails = 1;
        peer[i].fail_timeout = 10;
        *peerp = &peer[i];
        peerp = &peer[i].next;
    }

    us->peer.data = peers;

    /* implicitly defined upstream has no backup servers */

    return NJT_OK;
}
#endif


njt_int_t
njt_stream_upstream_init_round_robin(njt_conf_t *cf,
    njt_stream_upstream_srv_conf_t *us)
{
    njt_url_t                        u;
    njt_uint_t                       i, j, n, w, t;
    njt_stream_upstream_server_t    *server;
    njt_stream_upstream_rr_peer_t   *peer, **peerp;
    njt_stream_upstream_rr_peers_t  *peers, *backup;
    njt_msec_t now_time = njt_time();

    us->peer.init = njt_stream_upstream_init_round_robin_peer;

    if (us->servers) {
        server = us->servers->elts;

        n = 0;
        w = 0;
        t = 0;

        peers = njt_pcalloc(cf->pool, sizeof(njt_stream_upstream_rr_peers_t));
        if (peers == NULL) {
            return NJT_ERROR;
        }
        for (i = 0; i < us->servers->nelts; i++) {
            if (server[i].backup) {
                continue;
            }
	    //zyg
	    if(server[i].dynamic != 1){
		server[i].parent_id = -1;
	    }else {
		server[i].parent_id = (njt_int_t)peers->next_order++;
	    }
	    //end
            n += server[i].naddrs;
            w += server[i].naddrs * server[i].weight;

            if (!server[i].down) {
                t += server[i].naddrs;
            }
        }
	/* zyg
        if (n == 0) {
            njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                          "no servers in upstream \"%V\" in %s:%ui",
                          &us->host, us->file_name, us->line);
            return NJT_ERROR;
        }


        peer = njt_pcalloc(cf->pool, sizeof(njt_stream_upstream_rr_peer_t) * n);
        if (peer == NULL) {
            return NJT_ERROR;
        }*/

        peers->single = (n <= 1);
        peers->number = n;
        peers->weighted = (w != n);
        peers->total_weight = w;
        peers->tries = t;
        peers->name = &us->host;
        peerp = &peers->peer;

	if(n > 0) {
	peer = njt_pcalloc(cf->pool, sizeof(njt_stream_upstream_rr_peer_t) * n);
        if (peer == NULL) {
            return NJT_ERROR;
        }
        n = 0;

        for (i = 0; i < us->servers->nelts; i++) {
            if (server[i].backup) {
                continue;
            }

            for (j = 0; j < server[i].naddrs; j++) {
                peer[n].sockaddr = server[i].addrs[j].sockaddr;
                peer[n].socklen = server[i].addrs[j].socklen;
                peer[n].name = server[i].addrs[j].name;
                peer[n].weight = server[i].weight;
                peer[n].effective_weight = server[i].weight;
		peer[n].rr_effective_weight = server[i].weight * NJT_WEIGHT_POWER;
                peer[n].current_weight = 0;
                peer[n].rr_current_weight = 0;
                peer[n].max_conns = server[i].max_conns;
                peer[n].max_fails = server[i].max_fails;
                peer[n].fail_timeout = server[i].fail_timeout;
                peer[n].down = server[i].down;
                peer[n].server = server[i].name;
		peer[n].hc_upstart = now_time;
		//zyg
		peer[n].id = peers->next_order++;
		peer[n].slow_start = server[i].slow_start;
		peer[n].parent_id = server[i].parent_id;
		//end
                *peerp = &peer[n];
                peerp = &peer[n].next;
                n++;
            }
        }
	}
        us->peer.data = peers;

        /* backup servers */

        n = 0;
        w = 0;
        t = 0;

        for (i = 0; i < us->servers->nelts; i++) {
            if (!server[i].backup) {
                continue;
            }
	    if(server[i].dynamic != 1) {
		server[i].parent_id = -1;
	    } else {
		server[i].parent_id = (njt_int_t)peers->next_order++;
	    }
            n += server[i].naddrs;
            w += server[i].naddrs * server[i].weight;

            if (!server[i].down) {
                t += server[i].naddrs;
            }
        }

        if (n == 0) {
            return NJT_OK;
        }

        backup = njt_pcalloc(cf->pool, sizeof(njt_stream_upstream_rr_peers_t));
        if (backup == NULL) {
            return NJT_ERROR;
        }

        peer = njt_pcalloc(cf->pool, sizeof(njt_stream_upstream_rr_peer_t) * n);
        if (peer == NULL) {
            return NJT_ERROR;
        }

        backup->single = 0;
        backup->number = n;
        backup->weighted = (w != n);
        backup->total_weight = w;
        backup->tries = t;
        backup->name = &us->host;

        n = 0;
        peerp = &backup->peer;

        for (i = 0; i < us->servers->nelts; i++) {
            if (!server[i].backup) {
                continue;
            }

            for (j = 0; j < server[i].naddrs; j++) {
                peer[n].sockaddr = server[i].addrs[j].sockaddr;
                peer[n].socklen = server[i].addrs[j].socklen;
                peer[n].name = server[i].addrs[j].name;
                peer[n].weight = server[i].weight;
                peer[n].effective_weight = server[i].weight;
		peer[n].rr_effective_weight = server[i].weight * NJT_WEIGHT_POWER;
                peer[n].current_weight = 0;
                peer[n].rr_current_weight = 0;
                peer[n].max_conns = server[i].max_conns;
                peer[n].max_fails = server[i].max_fails;
                peer[n].fail_timeout = server[i].fail_timeout;
                peer[n].down = server[i].down;
                peer[n].server = server[i].name;
		peer[n].parent_id = server[i].parent_id;
		peer[n].slow_start = server[i].slow_start;
		peer[n].hc_upstart = now_time;
	        peer[n].id = peers->next_order++;
                *peerp = &peer[n];
                peerp = &peer[n].next;
                n++;
            }
        }

        peers->next = backup;
        peers->single = (peers->number + peers->next->number == 1);

        return NJT_OK;
    }


    /* an upstream implicitly defined by proxy_pass, etc. */

    if (us->port == 0) {
        njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                      "no port in upstream \"%V\" in %s:%ui",
                      &us->host, us->file_name, us->line);
        return NJT_ERROR;
    }

    njt_memzero(&u, sizeof(njt_url_t));

    u.host = us->host;
    u.port = us->port;

    if (njt_inet_resolve_host(cf->pool, &u) != NJT_OK) {
        if (u.err) {
            njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                          "%s in upstream \"%V\" in %s:%ui",
                          u.err, &us->host, us->file_name, us->line);
        }

        return NJT_ERROR;
    }

    n = u.naddrs;

    peers = njt_pcalloc(cf->pool, sizeof(njt_stream_upstream_rr_peers_t));
    if (peers == NULL) {
        return NJT_ERROR;
    }

    peer = njt_pcalloc(cf->pool, sizeof(njt_stream_upstream_rr_peer_t) * n);
    if (peer == NULL) {
        return NJT_ERROR;
    }

    peers->single = (n <= 1);
    peers->number = n;
    peers->weighted = 0;
    peers->total_weight = n;
    peers->tries = n;
    peers->name = &us->host;

    peerp = &peers->peer;

    for (i = 0; i < u.naddrs; i++) {
        peer[i].sockaddr = u.addrs[i].sockaddr;
        peer[i].socklen = u.addrs[i].socklen;
        peer[i].name = u.addrs[i].name;
        peer[i].weight = 1;
        peer[i].effective_weight = 1;
	peer[i].rr_effective_weight = 1*NJT_WEIGHT_POWER;
        peer[i].current_weight = 0;
        peer[i].rr_current_weight = 0;
        peer[i].max_conns = 0;
        peer[i].max_fails = 1;
        peer[i].fail_timeout = 10;
        *peerp = &peer[i];
        peerp = &peer[i].next;
    }

    us->peer.data = peers;

    /* implicitly defined upstream has no backup servers */

    return NJT_OK;
}


njt_int_t
njt_stream_upstream_init_round_robin_peer(njt_stream_session_t *s,
    njt_stream_upstream_srv_conf_t *us)
{
    njt_uint_t                           n;
    njt_stream_upstream_rr_peer_data_t  *rrp;

    rrp = s->upstream->peer.data;

    if (rrp == NULL) {
        rrp = njt_palloc(s->connection->pool,
                         sizeof(njt_stream_upstream_rr_peer_data_t));
        if (rrp == NULL) {
            return NJT_ERROR;
        }

        s->upstream->peer.data = rrp;
    }

    rrp->peers = us->peer.data;
    rrp->current = NULL;
    rrp->config = 0;

    n = rrp->peers->number;

    if (rrp->peers->next && rrp->peers->next->number > n) {
        n = rrp->peers->next->number;
    }

    if (n <= 8 * sizeof(uintptr_t)) {
        rrp->tried = &rrp->data;
        rrp->data = 0;

    } else {
        n = (n + (8 * sizeof(uintptr_t) - 1)) / (8 * sizeof(uintptr_t));

        rrp->tried = njt_pcalloc(s->connection->pool, n * sizeof(uintptr_t));
        if (rrp->tried == NULL) {
            return NJT_ERROR;
        }
    }

    s->upstream->peer.get = njt_stream_upstream_get_round_robin_peer;
    s->upstream->peer.free = njt_stream_upstream_free_round_robin_peer;
    s->upstream->peer.notify = njt_stream_upstream_notify_round_robin_peer;
    s->upstream->peer.tries = njt_stream_upstream_tries(rrp->peers);
#if (NJT_STREAM_SSL)
    s->upstream->peer.set_session =
                             njt_stream_upstream_set_round_robin_peer_session;
    s->upstream->peer.save_session =
                             njt_stream_upstream_save_round_robin_peer_session;
#endif

    return NJT_OK;
}


njt_int_t
njt_stream_upstream_create_round_robin_peer(njt_stream_session_t *s,
    njt_stream_upstream_resolved_t *ur)
{
    u_char                              *p;
    size_t                               len;
    socklen_t                            socklen;
    njt_uint_t                           i, n;
    struct sockaddr                     *sockaddr;
    njt_stream_upstream_rr_peer_t       *peer, **peerp;
    njt_stream_upstream_rr_peers_t      *peers;
    njt_stream_upstream_rr_peer_data_t  *rrp;

    rrp = s->upstream->peer.data;

    if (rrp == NULL) {
        rrp = njt_palloc(s->connection->pool,
                         sizeof(njt_stream_upstream_rr_peer_data_t));
        if (rrp == NULL) {
            return NJT_ERROR;
        }

        s->upstream->peer.data = rrp;
    }

    peers = njt_pcalloc(s->connection->pool,
                        sizeof(njt_stream_upstream_rr_peers_t));
    if (peers == NULL) {
        return NJT_ERROR;
    }

    peer = njt_pcalloc(s->connection->pool,
                       sizeof(njt_stream_upstream_rr_peer_t) * ur->naddrs);
    if (peer == NULL) {
        return NJT_ERROR;
    }

    peers->single = (ur->naddrs <= 1);
    peers->number = ur->naddrs;
    peers->tries = ur->naddrs;
    peers->name = &ur->host;

    if (ur->sockaddr) {
        peer[0].sockaddr = ur->sockaddr;
        peer[0].socklen = ur->socklen;
        peer[0].name = ur->name;
        peer[0].weight = 1;
        peer[0].effective_weight = 1;
	peer[0].rr_effective_weight = 1*NJT_WEIGHT_POWER;
        peer[0].current_weight = 0;
        peer[0].rr_current_weight = 0;
        peer[0].max_conns = 0;
        peer[0].max_fails = 1;
        peer[0].fail_timeout = 10;
        peers->peer = peer;

    } else {
        peerp = &peers->peer;

        for (i = 0; i < ur->naddrs; i++) {

            socklen = ur->addrs[i].socklen;

            sockaddr = njt_palloc(s->connection->pool, socklen);
            if (sockaddr == NULL) {
                return NJT_ERROR;
            }

            njt_memcpy(sockaddr, ur->addrs[i].sockaddr, socklen);
            njt_inet_set_port(sockaddr, ur->port);

            p = njt_pnalloc(s->connection->pool, NJT_SOCKADDR_STRLEN);
            if (p == NULL) {
                return NJT_ERROR;
            }

            len = njt_sock_ntop(sockaddr, socklen, p, NJT_SOCKADDR_STRLEN, 1);

            peer[i].sockaddr = sockaddr;
            peer[i].socklen = socklen;
            peer[i].name.len = len;
            peer[i].name.data = p;
            peer[i].weight = 1;
            peer[i].effective_weight = 1;
	    peer[i].rr_effective_weight = 1*NJT_WEIGHT_POWER;
            peer[i].current_weight = 0;
            peer[i].rr_current_weight = 0;
            peer[i].max_conns = 0;
            peer[i].max_fails = 1;
            peer[i].fail_timeout = 10;
            *peerp = &peer[i];
            peerp = &peer[i].next;
        }
    }

    rrp->peers = peers;
    rrp->current = NULL;
    rrp->config = 0;

    if (rrp->peers->number <= 8 * sizeof(uintptr_t)) {
        rrp->tried = &rrp->data;
        rrp->data = 0;

    } else {
        n = (rrp->peers->number + (8 * sizeof(uintptr_t) - 1))
                / (8 * sizeof(uintptr_t));

        rrp->tried = njt_pcalloc(s->connection->pool, n * sizeof(uintptr_t));
        if (rrp->tried == NULL) {
            return NJT_ERROR;
        }
    }

    s->upstream->peer.get = njt_stream_upstream_get_round_robin_peer;
    s->upstream->peer.free = njt_stream_upstream_free_round_robin_peer;
    s->upstream->peer.tries = njt_stream_upstream_tries(rrp->peers);
#if (NJT_STREAM_SSL)
    s->upstream->peer.set_session = njt_stream_upstream_empty_set_session;
    s->upstream->peer.save_session = njt_stream_upstream_empty_save_session;
#endif

    return NJT_OK;
}

njt_int_t
njt_stream_upstream_pre_handle_peer(njt_stream_upstream_rr_peer_t   *peer)
{
#if (NJT_HTTP_UPSTREAM_API || NJT_STREAM_UPSTREAM_DYNAMIC_SERVER)
        time_t                        now;
        now = njt_time();
        if (peer->down) {
                return NJT_ERROR;
        }
        if (peer->hc_down > 0) {
            return NJT_ERROR;
    }
        if (peer->max_conns && peer->conns >= peer->max_conns) {
                return NJT_ERROR;
        }
        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout) {
            return NJT_ERROR;
        }
#endif
        return NJT_OK;
}

static njt_int_t
njt_stream_upstream_single_pre_handle_peer(njt_stream_upstream_rr_peer_t   *peer)
{
#if (NJT_HTTP_UPSTREAM_API || NJT_STREAM_UPSTREAM_DYNAMIC_SERVER)
        if (peer->down) {
                return NJT_ERROR;
        }
        if (peer->hc_down > 0) {
            return NJT_ERROR;
    }
        if (peer->max_conns && peer->conns >= peer->max_conns) {
                return NJT_ERROR;
        }
#endif
        return NJT_OK;
}

njt_int_t
njt_stream_upstream_get_round_robin_peer(njt_peer_connection_t *pc, void *data)
{
    njt_stream_upstream_rr_peer_data_t *rrp = data;

    njt_int_t                        rc;
    njt_uint_t                       i, n;
    njt_stream_upstream_rr_peer_t   *peer;
    njt_stream_upstream_rr_peers_t  *peers;

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, pc->log, 0,
                   "get rr peer, try: %ui", pc->tries);

    pc->connection = NULL;

    peers = rrp->peers;
    njt_stream_upstream_rr_peers_wlock(peers);

    if (peers->single && peers->number != 0) {
        peer = peers->peer;
	/*
        if (peer->down) {
            goto failed;
        }

        if (peer->max_conns && peer->conns >= peer->max_conns) {
            goto failed;
        }*/
	if (njt_stream_upstream_single_pre_handle_peer(peer) == NJT_ERROR) {
	  goto failed;
	}
        rrp->current = peer;

    } else {

        /* there are several peers */

        peer = njt_stream_upstream_get_peer(rrp);

        if (peer == NULL) {
            goto failed;
        }

        njt_log_debug2(NJT_LOG_DEBUG_STREAM, pc->log, 0,
                       "get rr peer, current: %p %i",
                       peer, peer->rr_current_weight);
    }

    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;

    peer->conns++;
    peer->requests++;
    njt_stream_upstream_rr_peers_unlock(peers);

    return NJT_OK;

failed:

    if (peers->next && peers->next->number > 0) {

        njt_log_debug0(NJT_LOG_DEBUG_STREAM, pc->log, 0, "backup servers");

        rrp->peers = peers->next;

        n = (rrp->peers->number + (8 * sizeof(uintptr_t) - 1))
                / (8 * sizeof(uintptr_t));

        for (i = 0; i < n; i++) {
            rrp->tried[i] = 0;
        }

        njt_stream_upstream_rr_peers_unlock(peers);

        rc = njt_stream_upstream_get_round_robin_peer(pc, rrp);

        if (rc != NJT_BUSY) {
            return rc;
        }

        njt_stream_upstream_rr_peers_wlock(peers);
    }

    njt_stream_upstream_rr_peers_unlock(peers);

    pc->name = peers->name;

    return NJT_BUSY;
}


static njt_stream_upstream_rr_peer_t *
njt_stream_upstream_get_peer(njt_stream_upstream_rr_peer_data_t *rrp)
{
    time_t                          now;
    uintptr_t                       m;
    njt_int_t                       total;
    njt_uint_t                      i, n, p;
    njt_stream_upstream_rr_peer_t  *peer, *best;
    njt_int_t                     peer_slow_weight;

    now = njt_time();

    best = NULL;
    total = 0;

#if (NJT_SUPPRESS_WARN)
    p = 0;
#endif

    for (peer = rrp->peers->peer, i = 0;
         peer;
         peer = peer->next, i++)
    {
        n = i / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

        if (rrp->tried[n] & m) {
            continue;
        }
	
        if (peer->down) {
            continue;
        }

        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
            continue;
        }

        if (peer->max_conns && peer->conns >= peer->max_conns) {
            continue;
        }
	if (njt_stream_upstream_pre_handle_peer(peer) == NJT_ERROR) {
            continue;
        }

	 /////zyg/////////////
         peer_slow_weight = peer->weight * NJT_WEIGHT_POWER;
         if(peer->slow_start > 0) { //limit slow_start
                 if(peer->hc_upstart + peer->slow_start > (njt_msec_t)now) {
                    peer_slow_weight = ((now - peer->hc_upstart )*peer_slow_weight)/peer->slow_start;
                    if (peer->rr_effective_weight > peer_slow_weight) {
                               peer->rr_effective_weight = peer_slow_weight;
                    }
                   njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "00 ip=%V,max_fail=%d,now=%ui,hc_upstart=%ui,slow_start=%d,time=%d",&peer->server,peer->max_fails,now,peer->hc_upstart,peer->slow_start,(now - peer->hc_upstart ));
                 }
         }
	peer->rr_current_weight += peer->rr_effective_weight;
        total += peer->rr_effective_weight;

        ////////////////////
	 if (peer->effective_weight < peer->weight) {
            peer->effective_weight++;
        }
        if (peer->rr_effective_weight < peer_slow_weight) {
	    peer->rr_effective_weight += (peer_slow_weight/peer->weight);
        }
	 if(peer != NULL) {
           njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "peer ip=%V,rr_current_weight=%d,rr_effective_weight=%d,peer_slow_weight=%d",&peer->server,peer->rr_current_weight,peer->rr_effective_weight,peer_slow_weight);
        }
        if (best == NULL || peer->rr_current_weight > best->rr_current_weight) {
            best = peer;
            p = i;
        }
    }

    if (best == NULL) {
        return NULL;
    }
    best->selected_time = ((njt_timeofday())->sec)*1000 + (njt_uint_t)((njt_timeofday())->msec);
    rrp->current = best;

    n = p / (8 * sizeof(uintptr_t));
    m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

    rrp->tried[n] |= m;

    best->rr_current_weight -= total;

    if (now - best->checked > best->fail_timeout) {
        best->checked = now;
    }

    return best;
}


void
njt_stream_upstream_free_round_robin_peer(njt_peer_connection_t *pc, void *data,
    njt_uint_t state)
{
    njt_stream_upstream_rr_peer_data_t  *rrp = data;

    time_t                          now;
    njt_stream_upstream_rr_peer_t  *peer;

    njt_log_debug2(NJT_LOG_DEBUG_STREAM, pc->log, 0,
                   "free rr peer %ui %ui", pc->tries, state);

    peer = rrp->current;

    njt_stream_upstream_rr_peers_rlock(rrp->peers);
    njt_stream_upstream_rr_peer_lock(rrp->peers, peer);

    if (rrp->peers->single) {
        peer->conns--;

        njt_stream_upstream_rr_peer_unlock(rrp->peers, peer);
        njt_stream_upstream_rr_peers_unlock(rrp->peers);

        pc->tries = 0;
        return;
    }

    if (state & NJT_PEER_FAILED) {
        now = njt_time();

        peer->fails++;
	if(peer->fails == peer->max_fails) {
		peer->unavail++;
	}
        peer->total_fails++;
        peer->accessed = now;
        peer->checked = now;
        if (peer->max_fails) {
	     peer->effective_weight -= peer->weight / peer->max_fails;
	     peer->rr_effective_weight -= ((peer->weight*NJT_WEIGHT_POWER) / peer->max_fails);
            if (peer->fails >= peer->max_fails) {
                njt_log_error(NJT_LOG_WARN, pc->log, 0,
                              "upstream server temporarily disabled");
            }
        }

        njt_log_debug2(NJT_LOG_DEBUG_STREAM, pc->log, 0,
                       "free rr peer failed: %p %i",
                       peer, peer->effective_weight);

        if (peer->effective_weight < 0) {
            peer->effective_weight = 0;
        }
	if (peer->rr_effective_weight < 0) {
            peer->rr_effective_weight = 0;
        }

    } else {

        /* mark peer live if check passed */

        if (peer->accessed < peer->checked) {
            peer->fails = 0;
	    if (peer->max_fails && peer->slow_start > 0 && peer->fails >= peer->max_fails) {
		    peer->hc_upstart =  njt_time();
	    }
        }
    }

    peer->conns--;

    njt_stream_upstream_rr_peer_unlock(rrp->peers, peer);
    njt_stream_upstream_rr_peers_unlock(rrp->peers);

    if (pc->tries) {
        pc->tries--;
    }
}


static void
njt_stream_upstream_notify_round_robin_peer(njt_peer_connection_t *pc,
    void *data, njt_uint_t type)
{
    njt_stream_upstream_rr_peer_data_t  *rrp = data;

    njt_stream_upstream_rr_peer_t  *peer;

    peer = rrp->current;

    if (type == NJT_STREAM_UPSTREAM_NOTIFY_CONNECT
        && pc->connection->type == SOCK_STREAM)
    {
        njt_stream_upstream_rr_peers_rlock(rrp->peers);
        njt_stream_upstream_rr_peer_lock(rrp->peers, peer);

        if (peer->accessed < peer->checked) {
            peer->fails = 0;
        }

        njt_stream_upstream_rr_peer_unlock(rrp->peers, peer);
        njt_stream_upstream_rr_peers_unlock(rrp->peers);
    }
}


#if (NJT_STREAM_SSL)

// static njt_int_t openresty patch
njt_int_t // openresty patch
njt_stream_upstream_set_round_robin_peer_session(njt_peer_connection_t *pc,
    void *data)
{
    njt_stream_upstream_rr_peer_data_t  *rrp = data;

    njt_int_t                        rc;
    njt_ssl_session_t               *ssl_session;
    njt_stream_upstream_rr_peer_t   *peer;
#if (NJT_STREAM_UPSTREAM_ZONE)
    int                              len;
    const u_char                    *p;
    njt_stream_upstream_rr_peers_t  *peers;
    u_char                           buf[NJT_SSL_MAX_SESSION_SIZE];
#endif

    peer = rrp->current;

#if (NJT_STREAM_UPSTREAM_ZONE)
    peers = rrp->peers;

    if (peers->shpool) {
        njt_stream_upstream_rr_peers_rlock(peers);
        njt_stream_upstream_rr_peer_lock(peers, peer);

        if (peer->ssl_session == NULL) {
            njt_stream_upstream_rr_peer_unlock(peers, peer);
            njt_stream_upstream_rr_peers_unlock(peers);
            return NJT_OK;
        }

        len = peer->ssl_session_len;

        njt_memcpy(buf, peer->ssl_session, len);

        njt_stream_upstream_rr_peer_unlock(peers, peer);
        njt_stream_upstream_rr_peers_unlock(peers);

        p = buf;
        ssl_session = d2i_SSL_SESSION(NULL, &p, len);

        rc = njt_ssl_set_session(pc->connection, ssl_session);

        njt_log_debug1(NJT_LOG_DEBUG_STREAM, pc->log, 0,
                       "set session: %p", ssl_session);

        njt_ssl_free_session(ssl_session);

        return rc;
    }
#endif

    ssl_session = peer->ssl_session;

    rc = njt_ssl_set_session(pc->connection, ssl_session);

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, pc->log, 0,
                   "set session: %p", ssl_session);

    return rc;
}


// static void openresty patch
void // openresty patch
njt_stream_upstream_save_round_robin_peer_session(njt_peer_connection_t *pc,
    void *data)
{
    njt_stream_upstream_rr_peer_data_t  *rrp = data;

    njt_ssl_session_t               *old_ssl_session, *ssl_session;
    njt_stream_upstream_rr_peer_t   *peer;
#if (NJT_STREAM_UPSTREAM_ZONE)
    int                              len;
    u_char                          *p;
    njt_stream_upstream_rr_peers_t  *peers;
    u_char                           buf[NJT_SSL_MAX_SESSION_SIZE];
#endif

#if (NJT_STREAM_UPSTREAM_ZONE)
    peers = rrp->peers;

    if (peers->shpool) {

        ssl_session = njt_ssl_get0_session(pc->connection);

        if (ssl_session == NULL) {
            return;
        }

        njt_log_debug1(NJT_LOG_DEBUG_STREAM, pc->log, 0,
                       "save session: %p", ssl_session);

        len = i2d_SSL_SESSION(ssl_session, NULL);

        /* do not cache too big session */

        if (len > NJT_SSL_MAX_SESSION_SIZE) {
            return;
        }

        p = buf;
        (void) i2d_SSL_SESSION(ssl_session, &p);

        peer = rrp->current;

        njt_stream_upstream_rr_peers_rlock(peers);
        njt_stream_upstream_rr_peer_lock(peers, peer);

        if (len > peer->ssl_session_len) {
            njt_shmtx_lock(&peers->shpool->mutex);

            if (peer->ssl_session) {
                njt_slab_free_locked(peers->shpool, peer->ssl_session);
            }

            peer->ssl_session = njt_slab_alloc_locked(peers->shpool, len);

            njt_shmtx_unlock(&peers->shpool->mutex);

            if (peer->ssl_session == NULL) {
                peer->ssl_session_len = 0;

                njt_stream_upstream_rr_peer_unlock(peers, peer);
                njt_stream_upstream_rr_peers_unlock(peers);
                return;
            }

            peer->ssl_session_len = len;
        }

        njt_memcpy(peer->ssl_session, buf, len);

        njt_stream_upstream_rr_peer_unlock(peers, peer);
        njt_stream_upstream_rr_peers_unlock(peers);

        return;
    }
#endif

    ssl_session = njt_ssl_get_session(pc->connection);

    if (ssl_session == NULL) {
        return;
    }

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, pc->log, 0,
                   "save session: %p", ssl_session);

    peer = rrp->current;

    old_ssl_session = peer->ssl_session;
    peer->ssl_session = ssl_session;

    if (old_ssl_session) {

        njt_log_debug1(NJT_LOG_DEBUG_STREAM, pc->log, 0,
                       "old session: %p", old_ssl_session);

        /* TODO: may block */

        njt_ssl_free_session(old_ssl_session);
    }
}


static njt_int_t
njt_stream_upstream_empty_set_session(njt_peer_connection_t *pc, void *data)
{
    return NJT_OK;
}


static void
njt_stream_upstream_empty_save_session(njt_peer_connection_t *pc, void *data)
{
    return;
}
 void
njt_stream_upstream_del_round_robin_peer(njt_slab_pool_t *pool, njt_stream_upstream_rr_peer_t *peer)
{
    if (peer->server.data) {
        njt_slab_free_locked(pool, peer->server.data);
    }

    if (peer->name.data) {
        njt_slab_free_locked(pool, peer->name.data);
    }

    if (peer->sockaddr) {
        njt_slab_free_locked(pool, peer->sockaddr);
    }

    njt_slab_free_locked(pool, peer);

    return;
}
#endif
