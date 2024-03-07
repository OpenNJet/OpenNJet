/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_EVENT_QUIC_MIGRATION_H_INCLUDED_
#define _NJT_EVENT_QUIC_MIGRATION_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>

#define NJT_QUIC_PATH_RETRIES   3

#define NJT_QUIC_PATH_PROBE     0
#define NJT_QUIC_PATH_ACTIVE    1
#define NJT_QUIC_PATH_BACKUP    2

#define njt_quic_path_dbg(c, msg, path)                                       \
    njt_log_debug7(NJT_LOG_DEBUG_EVENT, c->log, 0,                            \
                   "quic path seq:%uL %s tx:%O rx:%O valid:%d st:%d mtu:%uz", \
                   path->seqnum, msg, path->sent, path->received,             \
                   path->validated, path->state, path->mtu);

njt_int_t njt_quic_handle_path_challenge_frame(njt_connection_t *c,
    njt_quic_header_t *pkt, njt_quic_path_challenge_frame_t *f);
njt_int_t njt_quic_handle_path_response_frame(njt_connection_t *c,
    njt_quic_path_challenge_frame_t *f);

njt_quic_path_t *njt_quic_new_path(njt_connection_t *c,
    struct sockaddr *sockaddr, socklen_t socklen, njt_quic_client_id_t *cid);
njt_int_t njt_quic_free_path(njt_connection_t *c, njt_quic_path_t *path);

njt_int_t njt_quic_set_path(njt_connection_t *c, njt_quic_header_t *pkt);
njt_int_t njt_quic_handle_migration(njt_connection_t *c,
    njt_quic_header_t *pkt);

void njt_quic_path_handler(njt_event_t *ev);

void njt_quic_discover_path_mtu(njt_connection_t *c, njt_quic_path_t *path);
njt_int_t njt_quic_handle_path_mtu(njt_connection_t *c,
    njt_quic_path_t *path, uint64_t min, uint64_t max);

#endif /* _NJT_EVENT_QUIC_MIGRATION_H_INCLUDED_ */
