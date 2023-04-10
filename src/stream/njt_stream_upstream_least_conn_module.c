
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>


static njt_int_t njt_stream_upstream_init_least_conn_peer(
    njt_stream_session_t *s, njt_stream_upstream_srv_conf_t *us);
static njt_int_t njt_stream_upstream_get_least_conn_peer(
    njt_peer_connection_t *pc, void *data);
static char *njt_stream_upstream_least_conn(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);


static njt_command_t  njt_stream_upstream_least_conn_commands[] = {

    { njt_string("least_conn"),
      NJT_STREAM_UPS_CONF|NJT_CONF_NOARGS,
      njt_stream_upstream_least_conn,
      0,
      0,
      NULL },

      njt_null_command
};


static njt_stream_module_t  njt_stream_upstream_least_conn_module_ctx = {
    NULL,                                    /* preconfiguration */
    NULL,                                    /* postconfiguration */

    NULL,                                    /* create main configuration */
    NULL,                                    /* init main configuration */

    NULL,                                    /* create server configuration */
    NULL                                     /* merge server configuration */
};


njt_module_t  njt_stream_upstream_least_conn_module = {
    NJT_MODULE_V1,
    &njt_stream_upstream_least_conn_module_ctx, /* module context */
    njt_stream_upstream_least_conn_commands, /* module directives */
    NJT_STREAM_MODULE,                       /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    NULL,                                    /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NJT_MODULE_V1_PADDING
};


static njt_int_t
njt_stream_upstream_init_least_conn(njt_conf_t *cf,
    njt_stream_upstream_srv_conf_t *us)
{
    njt_log_debug0(NJT_LOG_DEBUG_STREAM, cf->log, 0,
                   "init least conn");

    if (njt_stream_upstream_init_round_robin(cf, us) != NJT_OK) {
        return NJT_ERROR;
    }

    us->peer.init = njt_stream_upstream_init_least_conn_peer;

    return NJT_OK;
}


static njt_int_t
njt_stream_upstream_init_least_conn_peer(njt_stream_session_t *s,
    njt_stream_upstream_srv_conf_t *us)
{
    njt_log_debug0(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "init least conn peer");

    if (njt_stream_upstream_init_round_robin_peer(s, us) != NJT_OK) {
        return NJT_ERROR;
    }

    s->upstream->peer.get = njt_stream_upstream_get_least_conn_peer;

    return NJT_OK;
}


static njt_int_t
njt_stream_upstream_get_least_conn_peer(njt_peer_connection_t *pc, void *data)
{
    njt_stream_upstream_rr_peer_data_t *rrp = data;

    time_t                           now;
    uintptr_t                        m;
    njt_int_t                        rc, total;
    njt_uint_t                       i, n, p, many;
    njt_stream_upstream_rr_peer_t   *peer, *best;
    njt_stream_upstream_rr_peers_t  *peers;

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, pc->log, 0,
                   "get least conn peer, try: %ui", pc->tries);

    if (rrp->peers->single) {
        return njt_stream_upstream_get_round_robin_peer(pc, rrp);
    }

    pc->connection = NULL;

    now = njt_time();

    peers = rrp->peers;

    njt_stream_upstream_rr_peers_wlock(peers);

    best = NULL;
    total = 0;

#if (NJT_SUPPRESS_WARN)
    many = 0;
    p = 0;
#endif

    for (peer = peers->peer, i = 0;
         peer;
         peer = peer->next, i++)
    {
        n = i / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

        if (rrp->tried[n] & m) {
            continue;
        }
	/*
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
        }*/
	if(njt_stream_upstream_pre_handle_peer(peer) == NJT_ERROR)
                continue;

        /*
         * select peer with least number of connections; if there are
         * multiple peers with the same number of connections, select
         * based on round-robin
         */

        if (best == NULL
            || peer->conns * best->weight < best->conns * peer->weight)
        {
            best = peer;
            many = 0;
            p = i;

        } else if (peer->conns * best->weight == best->conns * peer->weight) {
            many = 1;
        }
    }

    if (best == NULL) {
        njt_log_debug0(NJT_LOG_DEBUG_STREAM, pc->log, 0,
                       "get least conn peer, no peer found");

        goto failed;
    }

    if (many) {
        njt_log_debug0(NJT_LOG_DEBUG_STREAM, pc->log, 0,
                       "get least conn peer, many");

        for (peer = best, i = p;
             peer;
             peer = peer->next, i++)
        {
            n = i / (8 * sizeof(uintptr_t));
            m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

            if (rrp->tried[n] & m) {
                continue;
            }
	    /*
            if (peer->down) {
                continue;
            }

            if (peer->conns * best->weight != best->conns * peer->weight) {
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
            }*/
	     if(njt_stream_upstream_pre_handle_peer(peer) == NJT_ERROR)
                continue;

            peer->current_weight += peer->effective_weight;
            total += peer->effective_weight;

            if (peer->effective_weight < peer->weight) {
                peer->effective_weight++;
            }

            if (peer->current_weight > best->current_weight) {
                best = peer;
                p = i;
            }
        }
    }

    best->current_weight -= total;

    if (now - best->checked > best->fail_timeout) {
        best->checked = now;
    }

    pc->sockaddr = best->sockaddr;
    pc->socklen = best->socklen;
    pc->name = &best->name;

    best->conns++;
    best->requests++;
    rrp->current = best;

    n = p / (8 * sizeof(uintptr_t));
    m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

    rrp->tried[n] |= m;

    njt_stream_upstream_rr_peers_unlock(peers);

    return NJT_OK;

failed:

    if (peers->next) {
        njt_log_debug0(NJT_LOG_DEBUG_STREAM, pc->log, 0,
                       "get least conn peer, backup servers");

        rrp->peers = peers->next;

        n = (rrp->peers->number + (8 * sizeof(uintptr_t) - 1))
                / (8 * sizeof(uintptr_t));

        for (i = 0; i < n; i++) {
            rrp->tried[i] = 0;
        }

        njt_stream_upstream_rr_peers_unlock(peers);

        rc = njt_stream_upstream_get_least_conn_peer(pc, rrp);

        if (rc != NJT_BUSY) {
            return rc;
        }

        njt_stream_upstream_rr_peers_wlock(peers);
    }

    njt_stream_upstream_rr_peers_unlock(peers);

    pc->name = peers->name;

    return NJT_BUSY;
}


static char *
njt_stream_upstream_least_conn(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_stream_upstream_srv_conf_t  *uscf;

    uscf = njt_stream_conf_get_module_srv_conf(cf, njt_stream_upstream_module);

    if (uscf->peer.init_upstream) {
        njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                           "load balancing method redefined");
    }

    uscf->peer.init_upstream = njt_stream_upstream_init_least_conn;

    uscf->flags = NJT_STREAM_UPSTREAM_CREATE
                  |NJT_STREAM_UPSTREAM_WEIGHT
                  |NJT_STREAM_UPSTREAM_MAX_CONNS
                  |NJT_STREAM_UPSTREAM_MAX_FAILS
                  |NJT_STREAM_UPSTREAM_FAIL_TIMEOUT
                  |NJT_STREAM_UPSTREAM_DOWN
                  |NJT_STREAM_UPSTREAM_BACKUP;

    return NJT_CONF_OK;
}
