
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_UPSTREAM_ROUND_ROBIN_H_INCLUDED_
#define _NJT_HTTP_UPSTREAM_ROUND_ROBIN_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


typedef struct njt_http_upstream_rr_peer_s   njt_http_upstream_rr_peer_t;

struct njt_http_upstream_rr_peer_s {
    struct sockaddr                *sockaddr;
    socklen_t                       socklen;
    njt_str_t                       name;
    njt_str_t                       server;

    njt_int_t                       current_weight;
    njt_int_t                       effective_weight;
    njt_int_t                       weight;

    njt_uint_t                      conns;
    njt_uint_t                      max_conns;

    njt_uint_t                      fails;
    time_t                          accessed;
    time_t                          checked;

    njt_uint_t                      max_fails;
    time_t                          fail_timeout;
    njt_msec_t                      slow_start;
    njt_msec_t                      start_time;

    njt_uint_t                      down;

#if (NJT_HTTP_SSL || NJT_COMPAT)
    void                           *ssl_session;
    int                             ssl_session_len;
#endif

#if (NJT_HTTP_UPSTREAM_ZONE)
    njt_atomic_t                    lock;
#endif
#if (NJT_HTTP_UPSTREAM_DYNAMIC_SERVER)
    njt_uint_t                      id;
    unsigned                        del_pending:1;
    unsigned                        hc_last_passed:1;
    unsigned                        hc_check_in_process:1;
    unsigned                        set_backup:1;
    unsigned                        set_first_check:1;

    njt_uint_t                      requests;   
    njt_str_t                       route;
    njt_int_t                       parent_id;
    njt_uint_t                      hc_checks;
    njt_uint_t                      hc_fails;
    njt_uint_t                      hc_unhealthy;
    njt_uint_t                      hc_consecutive_fails;
    njt_uint_t                      hc_consecutive_passes;
    njt_uint_t                      hc_down;
    njt_msec_t                      hc_downtime;
    njt_msec_t                      hc_downstart;
    njt_msec_t                      hc_upstart;
    njt_uint_t                      unavail;
    njt_msec_t                      selected_time;
    njt_atomic_t                    total_header_time;
    njt_atomic_t                    total_response_time;
    njt_uint_t                      total_fails;
    njt_int_t                       rr_effective_weight;
    njt_int_t                       rr_current_weight;
#endif
    njt_http_upstream_rr_peer_t    *next;

    NJT_COMPAT_BEGIN(32)
    NJT_COMPAT_END
};


typedef struct njt_http_upstream_rr_peers_s  njt_http_upstream_rr_peers_t;

struct njt_http_upstream_rr_peers_s {
    njt_uint_t                      number;

#if (NJT_HTTP_UPSTREAM_ZONE)
    njt_slab_pool_t                *shpool;
    njt_atomic_t                    rwlock;
    njt_http_upstream_rr_peers_t   *zone_next;
    njt_uint_t                      update_id;
#endif

    njt_uint_t                      total_weight;
    njt_uint_t                      tries;

    unsigned                        single:1;
    unsigned                        weighted:1;

    njt_str_t                      *name;

    njt_http_upstream_rr_peers_t   *next;

    njt_http_upstream_rr_peer_t    *peer;
#if (NJT_HTTP_UPSTREAM_DYNAMIC_SERVER)
    njt_uint_t                       next_order;
    njt_http_upstream_rr_peer_t   *parent_node;
#endif
};


#if (NJT_HTTP_UPSTREAM_ZONE)

#define njt_http_upstream_rr_peers_rlock(peers)                               \
                                                                              \
    if (peers->shpool) {                                                      \
        njt_rwlock_rlock(&peers->rwlock);                                     \
    }

#define njt_http_upstream_rr_peers_wlock(peers)                               \
                                                                              \
    if (peers->shpool) {                                                      \
        njt_rwlock_wlock(&peers->rwlock);                                     \
    }

#define njt_http_upstream_rr_peers_unlock(peers)                              \
                                                                              \
    if (peers->shpool) {                                                      \
        njt_rwlock_unlock(&peers->rwlock);                                    \
    }


#define njt_http_upstream_rr_peer_lock(peers, peer)                           \
                                                                              \
    if (peers->shpool) {                                                      \
        njt_rwlock_wlock(&peer->lock);                                        \
    }

#define njt_http_upstream_rr_peer_unlock(peers, peer)                         \
                                                                              \
    if (peers->shpool) {                                                      \
        njt_rwlock_unlock(&peer->lock);                                       \
    }

#else

#define njt_http_upstream_rr_peers_rlock(peers)
#define njt_http_upstream_rr_peers_wlock(peers)
#define njt_http_upstream_rr_peers_unlock(peers)
#define njt_http_upstream_rr_peer_lock(peers, peer)
#define njt_http_upstream_rr_peer_unlock(peers, peer)

#endif


typedef struct {
    njt_uint_t                      config;
    njt_http_upstream_rr_peers_t   *peers;
    njt_http_upstream_rr_peer_t    *current;
    uintptr_t                      *tried;
    uintptr_t                       data;
} njt_http_upstream_rr_peer_data_t;


njt_int_t njt_http_upstream_init_round_robin(njt_conf_t *cf,
    njt_http_upstream_srv_conf_t *us);
njt_int_t njt_http_upstream_init_round_robin_peer(njt_http_request_t *r,
    njt_http_upstream_srv_conf_t *us);
njt_int_t njt_http_upstream_create_round_robin_peer(njt_http_request_t *r,
    njt_http_upstream_resolved_t *ur);
njt_int_t njt_http_upstream_get_round_robin_peer(njt_peer_connection_t *pc,
    void *data);
void njt_http_upstream_free_round_robin_peer(njt_peer_connection_t *pc,
    void *data, njt_uint_t state);
void njt_http_upstream_free_peer_memory(njt_slab_pool_t *pool,
        njt_http_upstream_rr_peer_t *peer);
njt_int_t
njt_http_upstream_pre_handle_peer(njt_http_upstream_rr_peer_t   *peer);
#if (NJT_HTTP_SSL)
njt_int_t
    njt_http_upstream_set_round_robin_peer_session(njt_peer_connection_t *pc,
    void *data);
void njt_http_upstream_save_round_robin_peer_session(njt_peer_connection_t *pc,
    void *data);
#endif


#endif /* _NJT_HTTP_UPSTREAM_ROUND_ROBIN_H_INCLUDED_ */
