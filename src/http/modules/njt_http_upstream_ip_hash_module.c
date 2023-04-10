
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


typedef struct {
    /* the round robin data must be first */
    njt_http_upstream_rr_peer_data_t   rrp;

    njt_uint_t                         hash;

    u_char                             addrlen;
    u_char                            *addr;

    u_char                             tries;

    njt_event_get_peer_pt              get_rr_peer;
} njt_http_upstream_ip_hash_peer_data_t;


static njt_int_t njt_http_upstream_init_ip_hash_peer(njt_http_request_t *r,
    njt_http_upstream_srv_conf_t *us);
static njt_int_t njt_http_upstream_get_ip_hash_peer(njt_peer_connection_t *pc,
    void *data);
static char *njt_http_upstream_ip_hash(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);


static njt_command_t  njt_http_upstream_ip_hash_commands[] = {

    { njt_string("ip_hash"),
      NJT_HTTP_UPS_CONF|NJT_CONF_NOARGS,
      njt_http_upstream_ip_hash,
      0,
      0,
      NULL },

      njt_null_command
};


static njt_http_module_t  njt_http_upstream_ip_hash_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


njt_module_t  njt_http_upstream_ip_hash_module = {
    NJT_MODULE_V1,
    &njt_http_upstream_ip_hash_module_ctx, /* module context */
    njt_http_upstream_ip_hash_commands,    /* module directives */
    NJT_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};


static u_char njt_http_upstream_ip_hash_pseudo_addr[3];


static njt_int_t
njt_http_upstream_init_ip_hash(njt_conf_t *cf, njt_http_upstream_srv_conf_t *us)
{
    if (njt_http_upstream_init_round_robin(cf, us) != NJT_OK) {
        return NJT_ERROR;
    }

    us->peer.init = njt_http_upstream_init_ip_hash_peer;

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_init_ip_hash_peer(njt_http_request_t *r,
    njt_http_upstream_srv_conf_t *us)
{
    struct sockaddr_in                     *sin;
#if (NJT_HAVE_INET6)
    struct sockaddr_in6                    *sin6;
#endif
    njt_http_upstream_ip_hash_peer_data_t  *iphp;

    iphp = njt_palloc(r->pool, sizeof(njt_http_upstream_ip_hash_peer_data_t));
    if (iphp == NULL) {
        return NJT_ERROR;
    }

    r->upstream->peer.data = &iphp->rrp;

    if (njt_http_upstream_init_round_robin_peer(r, us) != NJT_OK) {
        return NJT_ERROR;
    }

    r->upstream->peer.get = njt_http_upstream_get_ip_hash_peer;

    switch (r->connection->sockaddr->sa_family) {

    case AF_INET:
        sin = (struct sockaddr_in *) r->connection->sockaddr;
        iphp->addr = (u_char *) &sin->sin_addr.s_addr;
        iphp->addrlen = 3;
        break;

#if (NJT_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;
        iphp->addr = (u_char *) &sin6->sin6_addr.s6_addr;
        iphp->addrlen = 16;
        break;
#endif

    default:
        iphp->addr = njt_http_upstream_ip_hash_pseudo_addr;
        iphp->addrlen = 3;
    }

    iphp->hash = 89;
    iphp->tries = 0;
    iphp->get_rr_peer = njt_http_upstream_get_round_robin_peer;

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_get_ip_hash_peer(njt_peer_connection_t *pc, void *data)
{
    njt_http_upstream_ip_hash_peer_data_t  *iphp = data;

    time_t                        now;
    njt_int_t                     w;
    uintptr_t                     m;
    njt_uint_t                    i, n, p, hash;
    njt_http_upstream_rr_peer_t  *peer;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, pc->log, 0,
                   "get ip hash peer, try: %ui", pc->tries);

    /* TODO: cached */

    njt_http_upstream_rr_peers_rlock(iphp->rrp.peers);

    if(iphp->rrp.peers->number == 0) {
	njt_http_upstream_rr_peers_unlock(iphp->rrp.peers);
	return NJT_BUSY;
    }
    if (iphp->tries > 20 || iphp->rrp.peers->single) {
        njt_http_upstream_rr_peers_unlock(iphp->rrp.peers);
        return iphp->get_rr_peer(pc, &iphp->rrp);
    }

    now = njt_time();

    pc->cached = 0;
    pc->connection = NULL;

    hash = iphp->hash;

    for ( ;; ) {

        for (i = 0; i < (njt_uint_t) iphp->addrlen; i++) {
            hash = (hash * 113 + iphp->addr[i]) % 6271;
        }

        w = hash % iphp->rrp.peers->total_weight;
        peer = iphp->rrp.peers->peer;
        p = 0;

        while (w >= peer->weight) {
            w -= peer->weight;
            peer = peer->next;
            p++;
        }

        n = p / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

        if (iphp->rrp.tried[n] & m) {
            goto next;
        }

        njt_log_debug2(NJT_LOG_DEBUG_HTTP, pc->log, 0,
                       "get ip hash peer, hash: %ui %04XL", p, (uint64_t) m);

        njt_http_upstream_rr_peer_lock(iphp->rrp.peers, peer);
	/* zyg
        if (peer->down) {
            njt_http_upstream_rr_peer_unlock(iphp->rrp.peers, peer);
            goto next;
        }

        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
            njt_http_upstream_rr_peer_unlock(iphp->rrp.peers, peer);
            goto next;
        }

        if (peer->max_conns && peer->conns >= peer->max_conns) {
            njt_http_upstream_rr_peer_unlock(iphp->rrp.peers, peer);
            goto next;
        }*/
	if (njt_http_upstream_pre_handle_peer(peer) == NJT_ERROR) {
            njt_http_upstream_rr_peer_unlock(iphp->rrp.peers, peer);
            goto next;
        }
        break;

    next:

        if (++iphp->tries > 20) {
            njt_http_upstream_rr_peers_unlock(iphp->rrp.peers);
            return iphp->get_rr_peer(pc, &iphp->rrp);
        }
    }

    iphp->rrp.current = peer;

    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;

    peer->conns++;
    peer->requests++;
    if (now - peer->checked > peer->fail_timeout) {
        peer->checked = now;
    }

    njt_http_upstream_rr_peer_unlock(iphp->rrp.peers, peer);
    njt_http_upstream_rr_peers_unlock(iphp->rrp.peers);

    iphp->rrp.tried[n] |= m;
    iphp->hash = hash;

    return NJT_OK;
}


static char *
njt_http_upstream_ip_hash(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_upstream_srv_conf_t  *uscf;

    uscf = njt_http_conf_get_module_srv_conf(cf, njt_http_upstream_module);

    if (uscf->peer.init_upstream) {
        njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                           "load balancing method redefined");
    }

    uscf->peer.init_upstream = njt_http_upstream_init_ip_hash;

    uscf->flags = NJT_HTTP_UPSTREAM_CREATE
                  |NJT_HTTP_UPSTREAM_WEIGHT
                  |NJT_HTTP_UPSTREAM_MAX_CONNS
                  |NJT_HTTP_UPSTREAM_MAX_FAILS
                  |NJT_HTTP_UPSTREAM_FAIL_TIMEOUT
                  |NJT_HTTP_UPSTREAM_DOWN;

    return NJT_CONF_OK;
}
