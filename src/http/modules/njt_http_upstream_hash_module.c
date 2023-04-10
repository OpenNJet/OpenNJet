
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


typedef struct {
    uint32_t                            hash;
    njt_str_t                          *server;
} njt_http_upstream_chash_point_t;


typedef struct {
    njt_uint_t                          number;
    njt_http_upstream_chash_point_t     point[1];
} njt_http_upstream_chash_points_t;


typedef struct {
    njt_http_complex_value_t            key;
    njt_http_upstream_chash_points_t   *points;
} njt_http_upstream_hash_srv_conf_t;


typedef struct {
    /* the round robin data must be first */
    njt_http_upstream_rr_peer_data_t    rrp;
    njt_http_upstream_hash_srv_conf_t  *conf;
    njt_str_t                           key;
    njt_uint_t                          tries;
    njt_uint_t                          rehash;
    uint32_t                            hash;
    njt_event_get_peer_pt               get_rr_peer;
} njt_http_upstream_hash_peer_data_t;


static njt_int_t njt_http_upstream_init_hash(njt_conf_t *cf,
    njt_http_upstream_srv_conf_t *us);
static njt_int_t njt_http_upstream_init_hash_peer(njt_http_request_t *r,
    njt_http_upstream_srv_conf_t *us);
static njt_int_t njt_http_upstream_get_hash_peer(njt_peer_connection_t *pc,
    void *data);

static njt_int_t njt_http_upstream_init_chash(njt_conf_t *cf,
    njt_http_upstream_srv_conf_t *us);
static int njt_libc_cdecl
    njt_http_upstream_chash_cmp_points(const void *one, const void *two);
static njt_uint_t njt_http_upstream_find_chash_point(
    njt_http_upstream_chash_points_t *points, uint32_t hash);
static njt_int_t njt_http_upstream_init_chash_peer(njt_http_request_t *r,
    njt_http_upstream_srv_conf_t *us);
static njt_int_t njt_http_upstream_get_chash_peer(njt_peer_connection_t *pc,
    void *data);

static void *njt_http_upstream_hash_create_conf(njt_conf_t *cf);
static char *njt_http_upstream_hash(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static njt_int_t
njt_http_upstream_update_chash(njt_http_upstream_srv_conf_t *us);

static njt_command_t  njt_http_upstream_hash_commands[] = {

    { njt_string("hash"),
      NJT_HTTP_UPS_CONF|NJT_CONF_TAKE12,
      njt_http_upstream_hash,
      NJT_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

      njt_null_command
};


static njt_http_module_t  njt_http_upstream_hash_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    njt_http_upstream_hash_create_conf,    /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


njt_module_t  njt_http_upstream_hash_module = {
    NJT_MODULE_V1,
    &njt_http_upstream_hash_module_ctx,    /* module context */
    njt_http_upstream_hash_commands,       /* module directives */
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


static njt_int_t
njt_http_upstream_init_hash(njt_conf_t *cf, njt_http_upstream_srv_conf_t *us)
{
    if (njt_http_upstream_init_round_robin(cf, us) != NJT_OK) {
        return NJT_ERROR;
    }

    us->peer.init = njt_http_upstream_init_hash_peer;

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_init_hash_peer(njt_http_request_t *r,
    njt_http_upstream_srv_conf_t *us)
{
    njt_http_upstream_hash_srv_conf_t   *hcf;
    njt_http_upstream_hash_peer_data_t  *hp;

    hp = njt_palloc(r->pool, sizeof(njt_http_upstream_hash_peer_data_t));
    if (hp == NULL) {
        return NJT_ERROR;
    }

    r->upstream->peer.data = &hp->rrp;

    if (njt_http_upstream_init_round_robin_peer(r, us) != NJT_OK) {
        return NJT_ERROR;
    }

    r->upstream->peer.get = njt_http_upstream_get_hash_peer;

    hcf = njt_http_conf_upstream_srv_conf(us, njt_http_upstream_hash_module);

    if (njt_http_complex_value(r, &hcf->key, &hp->key) != NJT_OK) {
        return NJT_ERROR;
    }

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "upstream hash key:\"%V\"", &hp->key);

    hp->conf = hcf;
    hp->tries = 0;
    hp->rehash = 0;
    hp->hash = 0;
    hp->get_rr_peer = njt_http_upstream_get_round_robin_peer;

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_get_hash_peer(njt_peer_connection_t *pc, void *data)
{
    njt_http_upstream_hash_peer_data_t  *hp = data;

    time_t                        now;
    u_char                        buf[NJT_INT_T_LEN];
    size_t                        size;
    uint32_t                      hash;
    njt_int_t                     w;
    uintptr_t                     m;
    njt_uint_t                    n, p;
    njt_http_upstream_rr_peer_t  *peer;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, pc->log, 0,
                   "get hash peer, try: %ui", pc->tries);

    njt_http_upstream_rr_peers_rlock(hp->rrp.peers);

    if (hp->tries > 20 || hp->rrp.peers->single || hp->key.len == 0) {
        njt_http_upstream_rr_peers_unlock(hp->rrp.peers);
        return hp->get_rr_peer(pc, &hp->rrp);
    }

    now = njt_time();

    pc->cached = 0;
    pc->connection = NULL;

    for ( ;; ) {

        /*
         * Hash expression is compatible with Cache::Memcached:
         * ((crc32([REHASH] KEY) >> 16) & 0x7fff) + PREV_HASH
         * with REHASH omitted at the first iteration.
         */

        njt_crc32_init(hash);

        if (hp->rehash > 0) {
            size = njt_sprintf(buf, "%ui", hp->rehash) - buf;
            njt_crc32_update(&hash, buf, size);
        }

        njt_crc32_update(&hash, hp->key.data, hp->key.len);
        njt_crc32_final(hash);

        hash = (hash >> 16) & 0x7fff;

        hp->hash += hash;
        hp->rehash++;

        w = hp->hash % hp->rrp.peers->total_weight;
        peer = hp->rrp.peers->peer;
        p = 0;

        while (w >= peer->weight) {
            w -= peer->weight;
            peer = peer->next;
            p++;
        }

        n = p / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

        if (hp->rrp.tried[n] & m) {
            goto next;
        }

        njt_http_upstream_rr_peer_lock(hp->rrp.peers, peer);

        njt_log_debug2(NJT_LOG_DEBUG_HTTP, pc->log, 0,
                       "get hash peer, value:%uD, peer:%ui", hp->hash, p);
	/* zyg
        if (peer->down) {
            njt_http_upstream_rr_peer_unlock(hp->rrp.peers, peer);
            goto next;
        }

        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
            njt_http_upstream_rr_peer_unlock(hp->rrp.peers, peer);
            goto next;
        }

        if (peer->max_conns && peer->conns >= peer->max_conns) {
            njt_http_upstream_rr_peer_unlock(hp->rrp.peers, peer);
            goto next;
        }*/
	if(njt_http_upstream_pre_handle_peer(peer) == NJT_ERROR) {
                njt_http_upstream_rr_peer_unlock(hp->rrp.peers, peer);
                goto next;
        }
        break;

    next:

        if (++hp->tries > 20) {
            njt_http_upstream_rr_peers_unlock(hp->rrp.peers);
            return hp->get_rr_peer(pc, &hp->rrp);
        }
    }

    hp->rrp.current = peer;

    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;

    peer->conns++;
    peer->requests++;
    if (now - peer->checked > peer->fail_timeout) {
        peer->checked = now;
    }

    njt_http_upstream_rr_peer_unlock(hp->rrp.peers, peer);
    njt_http_upstream_rr_peers_unlock(hp->rrp.peers);

    hp->rrp.tried[n] |= m;

    return NJT_OK;
}

static njt_int_t
njt_http_upstream_init_chash(njt_conf_t *cf, njt_http_upstream_srv_conf_t *us)
{
    u_char                             *host, *port, c;
    size_t                              host_len, port_len, size;
    uint32_t                            hash, base_hash;
    njt_str_t                          *server;
    njt_uint_t                          npoints, i, j;
    njt_http_upstream_rr_peer_t        *peer;
    njt_http_upstream_rr_peers_t       *peers;
    njt_http_upstream_chash_points_t   *points;
    njt_http_upstream_hash_srv_conf_t  *hcf;
    union {
        uint32_t                        value;
        u_char                          byte[4];
    } prev_hash;

    if (njt_http_upstream_init_round_robin(cf, us) != NJT_OK) {
        return NJT_ERROR;
    }

    us->peer.init = njt_http_upstream_init_chash_peer;
    us->update_id = NJT_CONF_UNSET_UINT;
    peers = us->peer.data;
    npoints = peers->total_weight * 160;

    size = sizeof(njt_http_upstream_chash_points_t)
           + sizeof(njt_http_upstream_chash_point_t) * (npoints - 1);

    // by zyg points = njt_palloc(cf->pool, size);
    points = njt_alloc(size, njt_cycle->log);
    if (points == NULL) {
        return NJT_ERROR;
    }

    points->number = 0;

    for (peer = peers->peer; peer; peer = peer->next) {
        server = &peer->server;

        /*
         * Hash expression is compatible with Cache::Memcached::Fast:
         * crc32(HOST \0 PORT PREV_HASH).
         */

        if (server->len >= 5
            && njt_strncasecmp(server->data, (u_char *) "unix:", 5) == 0)
        {
            host = server->data + 5;
            host_len = server->len - 5;
            port = NULL;
            port_len = 0;
            goto done;
        }

        for (j = 0; j < server->len; j++) {
            c = server->data[server->len - j - 1];

            if (c == ':') {
                host = server->data;
                host_len = server->len - j - 1;
                port = server->data + server->len - j;
                port_len = j;
                goto done;
            }

            if (c < '0' || c > '9') {
                break;
            }
        }

        host = server->data;
        host_len = server->len;
        port = NULL;
        port_len = 0;

    done:

        njt_crc32_init(base_hash);
        njt_crc32_update(&base_hash, host, host_len);
        njt_crc32_update(&base_hash, (u_char *) "", 1);
        njt_crc32_update(&base_hash, port, port_len);

        prev_hash.value = 0;
        npoints = peer->weight * 160;

        for (j = 0; j < npoints; j++) {
            hash = base_hash;

            njt_crc32_update(&hash, prev_hash.byte, 4);
            njt_crc32_final(hash);

            points->point[points->number].hash = hash;
            points->point[points->number].server = server;
            points->number++;

#if (NJT_HAVE_LITTLE_ENDIAN)
            prev_hash.value = hash;
#else
            prev_hash.byte[0] = (u_char) (hash & 0xff);
            prev_hash.byte[1] = (u_char) ((hash >> 8) & 0xff);
            prev_hash.byte[2] = (u_char) ((hash >> 16) & 0xff);
            prev_hash.byte[3] = (u_char) ((hash >> 24) & 0xff);
#endif
        }
    }

    njt_qsort(points->point,
              points->number,
              sizeof(njt_http_upstream_chash_point_t),
              njt_http_upstream_chash_cmp_points);

    for (i = 0, j = 1; j < points->number; j++) {
        if (points->point[i].hash != points->point[j].hash) {
            points->point[++i] = points->point[j];
        }
    }

    points->number = i + 1;

    hcf = njt_http_conf_upstream_srv_conf(us, njt_http_upstream_hash_module);
    hcf->points = points;

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_update_chash(njt_http_upstream_srv_conf_t *us)
{
    u_char                             *host, *port, c;
    size_t                              host_len, port_len, size;
    uint32_t                            hash, base_hash;
    njt_str_t                          *server;
    njt_uint_t                          npoints, i, j;
    njt_http_upstream_rr_peer_t        *peer;
    njt_http_upstream_rr_peers_t       *peers;
    njt_http_upstream_chash_points_t   *points;
    njt_http_upstream_hash_srv_conf_t  *hcf;
    union {
        uint32_t                        value;
        u_char                          byte[4];
    } prev_hash;



    peers = us->peer.data;
    if(us->update_id == peers->update_id && us->update_id != NJT_CONF_UNSET_UINT){
        return NJT_OK;
    }
    if(us->update_id == NJT_CONF_UNSET_UINT){
        us->update_id = 0;
    } else {
       us->update_id = peers->update_id;
    }
    npoints = peers->total_weight * 160;

    size = sizeof(njt_http_upstream_chash_points_t)
           + sizeof(njt_http_upstream_chash_point_t) * (npoints - 1);

    hcf = njt_http_conf_upstream_srv_conf(us, njt_http_upstream_hash_module);
    if(hcf != NULL && hcf->points != NULL){
	njt_free(hcf->points);
	hcf->points = NULL;
    }
    points = njt_alloc(size, njt_cycle->log);
    if (points == NULL) {
        return NJT_ERROR;
    }
    hcf->points = points;

    points->number = 0;
    if(peers->number <= 0){
	return NJT_OK;
    }

    for (peer = peers->peer; peer; peer = peer->next) {
        server = &peer->server;

        /*
         * Hash expression is compatible with Cache::Memcached::Fast:
         * crc32(HOST \0 PORT PREV_HASH).
         */

        if (server->len >= 5
            && njt_strncasecmp(server->data, (u_char *) "unix:", 5) == 0)
        {
            host = server->data + 5;
            host_len = server->len - 5;
            port = NULL;
            port_len = 0;
            goto done;
        }

        for (j = 0; j < server->len; j++) {
            c = server->data[server->len - j - 1];

            if (c == ':') {
                host = server->data;
                host_len = server->len - j - 1;
                port = server->data + server->len - j;
                port_len = j;
                goto done;
            }

            if (c < '0' || c > '9') {
                break;
            }
        }

        host = server->data;
        host_len = server->len;
        port = NULL;
        port_len = 0;

    done:

        njt_crc32_init(base_hash);
        njt_crc32_update(&base_hash, host, host_len);
        njt_crc32_update(&base_hash, (u_char *) "", 1);
        njt_crc32_update(&base_hash, port, port_len);

        prev_hash.value = 0;
        npoints = peer->weight * 160;

        for (j = 0; j < npoints; j++) {
            hash = base_hash;

            njt_crc32_update(&hash, prev_hash.byte, 4);
            njt_crc32_final(hash);

            points->point[points->number].hash = hash;
            points->point[points->number].server = server;
            points->number++;

#if (NJT_HAVE_LITTLE_ENDIAN)
            prev_hash.value = hash;
#else
            prev_hash.byte[0] = (u_char) (hash & 0xff);
            prev_hash.byte[1] = (u_char) ((hash >> 8) & 0xff);
            prev_hash.byte[2] = (u_char) ((hash >> 16) & 0xff);
            prev_hash.byte[3] = (u_char) ((hash >> 24) & 0xff);
#endif
        }
    }

    njt_qsort(points->point,
              points->number,
              sizeof(njt_http_upstream_chash_point_t),
              njt_http_upstream_chash_cmp_points);

    for (i = 0, j = 1; j < points->number; j++) {
        if (points->point[i].hash != points->point[j].hash) {
            points->point[++i] = points->point[j];
        }
    }

    points->number = i + 1;

    hcf->points = points;

    return NJT_OK;
}


static int njt_libc_cdecl
njt_http_upstream_chash_cmp_points(const void *one, const void *two)
{
    njt_http_upstream_chash_point_t *first =
                                       (njt_http_upstream_chash_point_t *) one;
    njt_http_upstream_chash_point_t *second =
                                       (njt_http_upstream_chash_point_t *) two;

    if (first->hash < second->hash) {
        return -1;

    } else if (first->hash > second->hash) {
        return 1;

    } else {
        return 0;
    }
}


static njt_uint_t
njt_http_upstream_find_chash_point(njt_http_upstream_chash_points_t *points,
    uint32_t hash)
{
    njt_uint_t                        i, j, k;
    njt_http_upstream_chash_point_t  *point;
    if(points->number == 0){
	return 0;
    }

    /* find first point >= hash */

    point = &points->point[0];

    i = 0;
    j = points->number;

    while (i < j) {
        k = (i + j) / 2;

        if (hash > point[k].hash) {
            i = k + 1;

        } else if (hash < point[k].hash) {
            j = k;

        } else {
            return k;
        }
    }

    return i;
}


static njt_int_t
njt_http_upstream_init_chash_peer(njt_http_request_t *r,
    njt_http_upstream_srv_conf_t *us)
{
    uint32_t                             hash;
    int32_t                              rc;
    njt_http_upstream_hash_srv_conf_t   *hcf;
    njt_http_upstream_hash_peer_data_t  *hp;

    if (njt_http_upstream_init_hash_peer(r, us) != NJT_OK) {
        return NJT_ERROR;
    }

    r->upstream->peer.get = njt_http_upstream_get_chash_peer;

    hp = r->upstream->peer.data;
    hcf = njt_http_conf_upstream_srv_conf(us, njt_http_upstream_hash_module);

    hash = njt_crc32_long(hp->key.data, hp->key.len);

    njt_http_upstream_rr_peers_rlock(hp->rrp.peers);
    rc = njt_http_upstream_update_chash(us);
    if(rc != NJT_OK){
	njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                   "njt_http_upstream_init_chash_peer error!");
    }

    hp->hash = njt_http_upstream_find_chash_point(hcf->points, hash);

    njt_http_upstream_rr_peers_unlock(hp->rrp.peers);

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_get_chash_peer(njt_peer_connection_t *pc, void *data)
{
    njt_http_upstream_hash_peer_data_t  *hp = data;

    time_t                              now;
    intptr_t                            m;
    njt_str_t                          *server;
    njt_int_t                           total;
    njt_uint_t                          i, n, best_i;
    njt_http_upstream_rr_peer_t        *peer, *best;
    njt_http_upstream_chash_point_t    *point;
    njt_http_upstream_chash_points_t   *points;
    njt_http_upstream_hash_srv_conf_t  *hcf;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, pc->log, 0,
                   "get consistent hash peer, try: %ui", pc->tries);

    njt_http_upstream_rr_peers_wlock(hp->rrp.peers);

    if (hp->tries > 20 || hp->rrp.peers->single || hp->key.len == 0) {
        njt_http_upstream_rr_peers_unlock(hp->rrp.peers);
        return hp->get_rr_peer(pc, &hp->rrp);
    }

    pc->cached = 0;
    pc->connection = NULL;

    now = njt_time();
    hcf = hp->conf;

    points = hcf->points;
    point = &points->point[0];

    for ( ;; ) {
        server = point[hp->hash % points->number].server;

        njt_log_debug2(NJT_LOG_DEBUG_HTTP, pc->log, 0,
                       "consistent hash peer:%uD, server:\"%V\"",
                       hp->hash, server);

        best = NULL;
        best_i = 0;
        total = 0;

        for (peer = hp->rrp.peers->peer, i = 0;
             peer;
             peer = peer->next, i++)
        {
            n = i / (8 * sizeof(uintptr_t));
            m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

            if (hp->rrp.tried[n] & m) {
                continue;
            }
	    /* zyg
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
	    if(njt_http_upstream_pre_handle_peer(peer) == NJT_ERROR)
                continue;
            if (peer->server.len != server->len
                || njt_strncmp(peer->server.data, server->data, server->len)
                   != 0)
            {
                continue;
            }

            peer->current_weight += peer->effective_weight;
            total += peer->effective_weight;

            if (peer->effective_weight < peer->weight) {
                peer->effective_weight++;
            }

            if (best == NULL || peer->current_weight > best->current_weight) {
                best = peer;
                best_i = i;
            }
        }

        if (best) {
            best->current_weight -= total;
            goto found;
        }

        hp->hash++;
        hp->tries++;

        if (hp->tries > 20) {
            njt_http_upstream_rr_peers_unlock(hp->rrp.peers);
            return hp->get_rr_peer(pc, &hp->rrp);
        }
    }

found:

    hp->rrp.current = best;

    pc->sockaddr = best->sockaddr;
    pc->socklen = best->socklen;
    pc->name = &best->name;

    best->conns++;
    best->requests++;
    if (now - best->checked > best->fail_timeout) {
        best->checked = now;
    }

    njt_http_upstream_rr_peers_unlock(hp->rrp.peers);

    n = best_i / (8 * sizeof(uintptr_t));
    m = (uintptr_t) 1 << best_i % (8 * sizeof(uintptr_t));

    hp->rrp.tried[n] |= m;

    return NJT_OK;
}


static void *
njt_http_upstream_hash_create_conf(njt_conf_t *cf)
{
    njt_http_upstream_hash_srv_conf_t  *conf;

    conf = njt_palloc(cf->pool, sizeof(njt_http_upstream_hash_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->points = NULL;

    return conf;
}


static char *
njt_http_upstream_hash(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_upstream_hash_srv_conf_t  *hcf = conf;

    njt_str_t                         *value;
    njt_http_upstream_srv_conf_t      *uscf;
    njt_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &hcf->key;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    uscf = njt_http_conf_get_module_srv_conf(cf, njt_http_upstream_module);

    if (uscf->peer.init_upstream) {
        njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                           "load balancing method redefined");
    }

    uscf->flags = NJT_HTTP_UPSTREAM_CREATE
                  |NJT_HTTP_UPSTREAM_WEIGHT
                  |NJT_HTTP_UPSTREAM_MAX_CONNS
                  |NJT_HTTP_UPSTREAM_MAX_FAILS
                  |NJT_HTTP_UPSTREAM_FAIL_TIMEOUT
                  |NJT_HTTP_UPSTREAM_DOWN;

    if (cf->args->nelts == 2) {
        uscf->peer.init_upstream = njt_http_upstream_init_hash;

    } else if (njt_strcmp(value[2].data, "consistent") == 0) {
        uscf->peer.init_upstream = njt_http_upstream_init_chash;

    } else {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[2]);
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}
