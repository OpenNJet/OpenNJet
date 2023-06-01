
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>


typedef struct {
    njt_stream_upstream_rr_peer_t          *peer;
    njt_uint_t                              range;
} njt_stream_upstream_random_range_t;


typedef struct {
    njt_uint_t                              two;
    njt_stream_upstream_random_range_t     *ranges;
    njt_uint_t                              update_id;
} njt_stream_upstream_random_srv_conf_t;


typedef struct {
    /* the round robin data must be first */
    njt_stream_upstream_rr_peer_data_t      rrp;

    njt_stream_upstream_random_srv_conf_t  *conf;
    u_char                                  tries;
} njt_stream_upstream_random_peer_data_t;


static njt_int_t njt_stream_upstream_init_random(njt_conf_t *cf,
    njt_stream_upstream_srv_conf_t *us);
static njt_int_t njt_stream_upstream_update_random(njt_pool_t *pool,
    njt_stream_upstream_srv_conf_t *us);

static njt_int_t njt_stream_upstream_init_random_peer(njt_stream_session_t *s,
    njt_stream_upstream_srv_conf_t *us);
static njt_int_t njt_stream_upstream_get_random_peer(njt_peer_connection_t *pc,
    void *data);
static njt_int_t njt_stream_upstream_get_random2_peer(njt_peer_connection_t *pc,
    void *data);
static njt_uint_t njt_stream_upstream_peek_random_peer(
    njt_stream_upstream_rr_peers_t *peers,
    njt_stream_upstream_random_peer_data_t *rp);
static void *njt_stream_upstream_random_create_conf(njt_conf_t *cf);
static char *njt_stream_upstream_random(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);


static njt_command_t  njt_stream_upstream_random_commands[] = {

    { njt_string("random"),
      NJT_STREAM_UPS_CONF|NJT_CONF_NOARGS|NJT_CONF_TAKE12,
      njt_stream_upstream_random,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      njt_null_command
};


static njt_stream_module_t  njt_stream_upstream_random_module_ctx = {
    NULL,                                    /* preconfiguration */
    NULL,                                    /* postconfiguration */

    NULL,                                    /* create main configuration */
    NULL,                                    /* init main configuration */

    njt_stream_upstream_random_create_conf,  /* create server configuration */
    NULL                                     /* merge server configuration */
};


njt_module_t  njt_stream_upstream_random_module = {
    NJT_MODULE_V1,
    &njt_stream_upstream_random_module_ctx,  /* module context */
    njt_stream_upstream_random_commands,     /* module directives */
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
njt_stream_upstream_init_random(njt_conf_t *cf,
    njt_stream_upstream_srv_conf_t *us)
{
    njt_log_debug0(NJT_LOG_DEBUG_STREAM, cf->log, 0, "init random");

    if (njt_stream_upstream_init_round_robin(cf, us) != NJT_OK) {
        return NJT_ERROR;
    }

    us->peer.init = njt_stream_upstream_init_random_peer;

#if (NJT_STREAM_UPSTREAM_ZONE)
    if (us->shm_zone) {
        return NJT_OK;
    }
#endif

    return njt_stream_upstream_update_random(cf->pool, us);
}


static njt_int_t
njt_stream_upstream_update_random(njt_pool_t *pool,
    njt_stream_upstream_srv_conf_t *us)
{
    size_t                                  size;
    njt_uint_t                              i, total_weight;
    njt_stream_upstream_rr_peer_t          *peer;
    njt_stream_upstream_rr_peers_t         *peers;
    njt_stream_upstream_random_range_t     *ranges;
    njt_stream_upstream_random_srv_conf_t  *rcf;

    rcf = njt_stream_conf_upstream_srv_conf(us,
                                            njt_stream_upstream_random_module);
    peers = us->peer.data;

    size = peers->number * sizeof(njt_stream_upstream_random_range_t);

    ranges = pool ? njt_palloc(pool, size) : njt_alloc(size, njt_cycle->log);
    if (ranges == NULL) {
        return NJT_ERROR;
    }

    total_weight = 0;

    for (peer = peers->peer, i = 0; peer; peer = peer->next, i++) {
        ranges[i].peer = peer;
        ranges[i].range = total_weight;
        total_weight += peer->weight;
    }

    rcf->ranges = ranges;

    return NJT_OK;
}


static njt_int_t
njt_stream_upstream_init_random_peer(njt_stream_session_t *s,
    njt_stream_upstream_srv_conf_t *us)
{
    njt_stream_upstream_random_srv_conf_t   *rcf;
    njt_stream_upstream_random_peer_data_t  *rp;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "init random peer");

    rcf = njt_stream_conf_upstream_srv_conf(us,
                                            njt_stream_upstream_random_module);

    rp = njt_palloc(s->connection->pool,
                    sizeof(njt_stream_upstream_random_peer_data_t));
    if (rp == NULL) {
        return NJT_ERROR;
    }

    s->upstream->peer.data = &rp->rrp;

    if (njt_stream_upstream_init_round_robin_peer(s, us) != NJT_OK) {
        return NJT_ERROR;
    }

    if (rcf->two) {
        s->upstream->peer.get = njt_stream_upstream_get_random2_peer;

    } else {
        s->upstream->peer.get = njt_stream_upstream_get_random_peer;
    }

    rp->conf = rcf;
    rp->tries = 0;

    njt_stream_upstream_rr_peers_rlock(rp->rrp.peers);

#if (NJT_STREAM_UPSTREAM_ZONE)
    if(rp->rrp.peers->shpool && (rcf->ranges != NULL && rp->rrp.peers->update_id != rcf->update_id)) {
	njt_free(rcf->ranges);	
	rcf->ranges = NULL;
    }
    rcf->update_id = rp->rrp.peers->update_id;
    if (rp->rrp.peers->shpool && rcf->ranges == NULL) {
        if (njt_stream_upstream_update_random(NULL, us) != NJT_OK) {
            njt_stream_upstream_rr_peers_unlock(rp->rrp.peers);
            return NJT_ERROR;
        }
    }
#endif

    njt_stream_upstream_rr_peers_unlock(rp->rrp.peers);

    return NJT_OK;
}


static njt_int_t
njt_stream_upstream_get_random_peer(njt_peer_connection_t *pc, void *data)
{
    njt_stream_upstream_random_peer_data_t  *rp = data;

    time_t                               now;
    uintptr_t                            m;
    njt_uint_t                           i, n;
    njt_stream_upstream_rr_peer_t       *peer;
    njt_stream_upstream_rr_peers_t      *peers;
    njt_stream_upstream_rr_peer_data_t  *rrp;

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, pc->log, 0,
                   "get random peer, try: %ui", pc->tries);

    rrp = &rp->rrp;
    peers = rrp->peers;

    njt_stream_upstream_rr_peers_rlock(peers);

    if (rp->tries > 20 || peers->single) {
        njt_stream_upstream_rr_peers_unlock(peers);
        return njt_stream_upstream_get_round_robin_peer(pc, rrp);
    }

    pc->cached = 0;
    pc->connection = NULL;

    now = njt_time();

    for ( ;; ) {

        i = njt_stream_upstream_peek_random_peer(peers, rp);

        peer = rp->conf->ranges[i].peer;

        n = i / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

        if (rrp->tried[n] & m) {
            goto next;
        }

        njt_stream_upstream_rr_peer_lock(peers, peer);
	/*
        if (peer->down) {
            njt_stream_upstream_rr_peer_unlock(peers, peer);
            goto next;
        }

        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
            njt_stream_upstream_rr_peer_unlock(peers, peer);
            goto next;
        }

        if (peer->max_conns && peer->conns >= peer->max_conns) {
            njt_stream_upstream_rr_peer_unlock(peers, peer);
            goto next;
        }*/
	if (njt_stream_upstream_pre_handle_peer(peer) == NJT_ERROR) {
            njt_stream_upstream_rr_peer_unlock(peers, peer);
            goto next;
        }

        break;

    next:

        if (++rp->tries > 20) {
            njt_stream_upstream_rr_peers_unlock(peers);
            return njt_stream_upstream_get_round_robin_peer(pc, rrp);
        }
    }

    rrp->current = peer;

    if (now - peer->checked > peer->fail_timeout) {
        peer->checked = now;
    }

    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;

    peer->conns++;
    peer->requests++;
    njt_stream_upstream_rr_peer_unlock(peers, peer);
    njt_stream_upstream_rr_peers_unlock(peers);

    rrp->tried[n] |= m;

    return NJT_OK;
}


static njt_int_t
njt_stream_upstream_get_random2_peer(njt_peer_connection_t *pc, void *data)
{
    njt_stream_upstream_random_peer_data_t  *rp = data;

    time_t                               now;
    uintptr_t                            m;
    njt_uint_t                           i, n, p;
    njt_stream_upstream_rr_peer_t       *peer, *prev;
    njt_stream_upstream_rr_peers_t      *peers;
    njt_stream_upstream_rr_peer_data_t  *rrp;

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, pc->log, 0,
                   "get random2 peer, try: %ui", pc->tries);

    rrp = &rp->rrp;
    peers = rrp->peers;

    njt_stream_upstream_rr_peers_wlock(peers);

    if (rp->tries > 20 || peers->single) {
        njt_stream_upstream_rr_peers_unlock(peers);
        return njt_stream_upstream_get_round_robin_peer(pc, rrp);
    }

    pc->cached = 0;
    pc->connection = NULL;

    now = njt_time();

    prev = NULL;

#if (NJT_SUPPRESS_WARN)
    p = 0;
#endif

    for ( ;; ) {

        i = njt_stream_upstream_peek_random_peer(peers, rp);

        peer = rp->conf->ranges[i].peer;

        if (peer == prev) {
            goto next;
        }

        n = i / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

        if (rrp->tried[n] & m) {
            goto next;
        }
	/*
        if (peer->down) {
            goto next;
        }

        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
            goto next;
        }

        if (peer->max_conns && peer->conns >= peer->max_conns) {
            goto next;
        }*/
	if (njt_stream_upstream_pre_handle_peer(peer) == NJT_ERROR) {
            goto next;
        }

        if (prev) {
            if (peer->conns * prev->weight > prev->conns * peer->weight) {
                peer = prev;
                n = p / (8 * sizeof(uintptr_t));
                m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));
            }

            break;
        }

        prev = peer;
        p = i;

    next:

        if (++rp->tries > 20) {
            njt_stream_upstream_rr_peers_unlock(peers);
            return njt_stream_upstream_get_round_robin_peer(pc, rrp);
        }
    }

    rrp->current = peer;

    if (now - peer->checked > peer->fail_timeout) {
        peer->checked = now;
    }

    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;

    peer->conns++;
    peer->requests++;
    njt_stream_upstream_rr_peers_unlock(peers);

    rrp->tried[n] |= m;

    return NJT_OK;
}


static njt_uint_t
njt_stream_upstream_peek_random_peer(njt_stream_upstream_rr_peers_t *peers,
    njt_stream_upstream_random_peer_data_t *rp)
{
    njt_uint_t  i, j, k, x;

    x = njt_random() % peers->total_weight;

    i = 0;
    j = peers->number;

    while (j - i > 1) {
        k = (i + j) / 2;

        if (x < rp->conf->ranges[k].range) {
            j = k;

        } else {
            i = k;
        }
    }

    return i;
}


static void *
njt_stream_upstream_random_create_conf(njt_conf_t *cf)
{
    njt_stream_upstream_random_srv_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_stream_upstream_random_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     conf->two = 0;
     */
    conf->update_id = NJT_CONF_UNSET_UINT;
    return conf;
}


static char *
njt_stream_upstream_random(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_stream_upstream_random_srv_conf_t  *rcf = conf;

    njt_str_t                       *value;
    njt_stream_upstream_srv_conf_t  *uscf;

    uscf = njt_stream_conf_get_module_srv_conf(cf, njt_stream_upstream_module);

    if (uscf->peer.init_upstream) {
        njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                           "load balancing method redefined");
    }

    uscf->peer.init_upstream = njt_stream_upstream_init_random;

    uscf->flags = NJT_STREAM_UPSTREAM_CREATE
                  |NJT_STREAM_UPSTREAM_WEIGHT
                  |NJT_STREAM_UPSTREAM_MAX_CONNS
                  |NJT_STREAM_UPSTREAM_MAX_FAILS
                  |NJT_STREAM_UPSTREAM_FAIL_TIMEOUT
                  |NJT_STREAM_UPSTREAM_DOWN;

    if (cf->args->nelts == 1) {
        return NJT_CONF_OK;
    }

    value = cf->args->elts;

    if (njt_strcmp(value[1].data, "two") == 0) {
        rcf->two = 1;

    } else {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[1]);
        return NJT_CONF_ERROR;
    }

    if (cf->args->nelts == 2) {
        return NJT_CONF_OK;
    }

    if (njt_strcmp(value[2].data, "least_conn") != 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[2]);
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}
