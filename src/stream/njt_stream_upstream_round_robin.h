
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NJT_STREAM_UPSTREAM_ROUND_ROBIN_H_INCLUDED_
#define _NJT_STREAM_UPSTREAM_ROUND_ROBIN_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>


typedef struct njt_stream_upstream_rr_peer_s   njt_stream_upstream_rr_peer_t;

struct njt_stream_upstream_rr_peer_s {
    struct sockaddr                 *sockaddr;
    socklen_t                        socklen;
    njt_str_t                        name;
    njt_str_t                        server;

    njt_int_t                        current_weight;
    njt_int_t                        effective_weight;
    njt_int_t                        weight;

    njt_uint_t                       conns;
    njt_uint_t                       max_conns;

    njt_uint_t                       fails;
    time_t                           accessed;
    time_t                           checked;

    njt_uint_t                       max_fails;
    time_t                           fail_timeout;
    njt_msec_t                       slow_start;
    njt_msec_t                       start_time;

    njt_uint_t                       down;

    void                            *ssl_session;
    int                              ssl_session_len;

#if (NJT_STREAM_UPSTREAM_ZONE)
    njt_atomic_t                     lock;
#endif

    njt_stream_upstream_rr_peer_t   *next;

    NJT_COMPAT_BEGIN(25)
    NJT_COMPAT_END
};


typedef struct njt_stream_upstream_rr_peers_s  njt_stream_upstream_rr_peers_t;

struct njt_stream_upstream_rr_peers_s {
    njt_uint_t                       number;

#if (NJT_STREAM_UPSTREAM_ZONE)
    njt_slab_pool_t                 *shpool;
    njt_atomic_t                     rwlock;
    njt_stream_upstream_rr_peers_t  *zone_next;
#endif

    njt_uint_t                       total_weight;
    njt_uint_t                       tries;

    unsigned                         single:1;
    unsigned                         weighted:1;

    njt_str_t                       *name;

    njt_stream_upstream_rr_peers_t  *next;

    njt_stream_upstream_rr_peer_t   *peer;
};


#if (NJT_STREAM_UPSTREAM_ZONE)

#define njt_stream_upstream_rr_peers_rlock(peers)                             \
                                                                              \
    if (peers->shpool) {                                                      \
        njt_rwlock_rlock(&peers->rwlock);                                     \
    }

#define njt_stream_upstream_rr_peers_wlock(peers)                             \
                                                                              \
    if (peers->shpool) {                                                      \
        njt_rwlock_wlock(&peers->rwlock);                                     \
    }

#define njt_stream_upstream_rr_peers_unlock(peers)                            \
                                                                              \
    if (peers->shpool) {                                                      \
        njt_rwlock_unlock(&peers->rwlock);                                    \
    }


#define njt_stream_upstream_rr_peer_lock(peers, peer)                         \
                                                                              \
    if (peers->shpool) {                                                      \
        njt_rwlock_wlock(&peer->lock);                                        \
    }

#define njt_stream_upstream_rr_peer_unlock(peers, peer)                       \
                                                                              \
    if (peers->shpool) {                                                      \
        njt_rwlock_unlock(&peer->lock);                                       \
    }

#else

#define njt_stream_upstream_rr_peers_rlock(peers)
#define njt_stream_upstream_rr_peers_wlock(peers)
#define njt_stream_upstream_rr_peers_unlock(peers)
#define njt_stream_upstream_rr_peer_lock(peers, peer)
#define njt_stream_upstream_rr_peer_unlock(peers, peer)

#endif


typedef struct {
    njt_uint_t                       config;
    njt_stream_upstream_rr_peers_t  *peers;
    njt_stream_upstream_rr_peer_t   *current;
    uintptr_t                       *tried;
    uintptr_t                        data;
} njt_stream_upstream_rr_peer_data_t;


njt_int_t njt_stream_upstream_init_round_robin(njt_conf_t *cf,
    njt_stream_upstream_srv_conf_t *us);
njt_int_t njt_stream_upstream_init_round_robin_peer(njt_stream_session_t *s,
    njt_stream_upstream_srv_conf_t *us);
njt_int_t njt_stream_upstream_create_round_robin_peer(njt_stream_session_t *s,
    njt_stream_upstream_resolved_t *ur);
njt_int_t njt_stream_upstream_get_round_robin_peer(njt_peer_connection_t *pc,
    void *data);
void njt_stream_upstream_free_round_robin_peer(njt_peer_connection_t *pc,
    void *data, njt_uint_t state);


#endif /* _NJT_STREAM_UPSTREAM_ROUND_ROBIN_H_INCLUDED_ */
