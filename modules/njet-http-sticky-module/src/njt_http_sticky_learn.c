/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include "njt_http_sticky_learn.h"

static void njt_http_sticky_learn_timeout_handler(njt_event_t *event);
static njt_int_t njt_http_sticky_learn_init_zone(njt_shm_zone_t *shm_zone,
        void *data);
static void njt_http_sticky_learn_create_session(
    njt_str_t *cookie, njt_http_sticky_peer_data_t *sp, njt_log_t *log);

njt_int_t njt_http_sticky_learn_get_peer(njt_peer_connection_t *pc,
        njt_http_sticky_peer_data_t *sp)
{

    njt_int_t ret;
    njt_str_t cookie;
    njt_http_sticky_learn_conf_t *conf = sp->conf->learn_cf;
    njt_http_request_t *request = sp->request;
    uint32_t hash;
    njt_rbtree_t *tree;
    njt_slab_pool_t *shpool;
    njt_http_sticky_learn_node_t *node;
    njt_http_sticky_learn_tree_t *sticky_tree;


    njt_log_error(NJT_LOG_DEBUG, pc->log, 0,
                  "[worker %d] Enter njt_http_sticky_learn_get_peer", njt_worker);

    /* Try to get the cookie defined by lookup array */
    njt_str_null(&cookie);
    njt_http_sticky_learn_find_variable_in_array(request, conf->lookup, &cookie);
    if (cookie.len > 0) {
        njt_log_debug1(NJT_LOG_DEBUG_STREAM, pc->log, 0,
                       "lookup: using the variable: %V", &cookie);
    }

    /* try to select a peer */
    njt_http_upstream_rr_peer_data_t *rrp;
    rrp = &sp->rrp;

    njt_http_upstream_rr_peers_rlock(rrp->peers);

    if (cookie.len == 0 || sp->tries > 1 || rrp->peers->single) {
        goto round_robin;
    }

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, pc->log, 0, "lookup: deciding the peer");
    /* find a session in shared memory zone */
    /* get the red black tree */
    sticky_tree = sp->conf->learn_cf->shm_zone->data;
    tree = sticky_tree->tree;
    shpool = (njt_slab_pool_t *)sp->conf->learn_cf->shm_zone->shm.addr;
    hash = njt_crc32_short(cookie.data, cookie.len);

    pc->cached = 0;
    pc->connection = NULL;

    njt_shmtx_lock(&shpool->mutex);
    /* try to find the session */
    node = njt_http_sticky_learn_rbtree_lookup(tree, &cookie, hash);
    if (node == NULL) {
        /* use round robin */
        njt_shmtx_unlock(&shpool->mutex);
        njt_log_debug0(NJT_LOG_DEBUG_STREAM, pc->log, 0,
                       "lookup: cookie does not match a valid session");
        goto round_robin;
    }

    njt_log_error(NJT_LOG_DEBUG, pc->log, 0,
                  "lookup: a valid session has been found: %V => %V",
                  &node->value, &node->server);

    /* goto the current session */
    njt_http_upstream_rr_peer_t *peer = rrp->peers->peer;
    njt_http_upstream_rr_peer_t *selected = NULL;

    /* find the proposed peer */
    while (peer != NULL) {
        njt_http_sticky_md5(request->pool, peer->sockaddr, &sp->md5);

        if ((sp->md5.len == node->server.len && node->server.len == MD5_LENGTH * 2) &&   njt_strncmp(sp->md5.data, node->server.data, MD5_LENGTH * 2) == 0) {
            if (!peer->down && !(peer->max_conns && peer->conns >= peer->max_conns)) {
                selected = peer;
            }
            break;
        }

        peer = peer->next;
    }
    njt_shmtx_unlock(&shpool->mutex);

    /* apply the peer */
    if (selected == NULL) {
        goto round_robin;
    }
    selected->selected_time = ((njt_timeofday())->sec)*1000 + (njt_uint_t)((njt_timeofday())->msec);    
    sp->rrp.current = selected;

    pc->sockaddr = selected->sockaddr;
    pc->socklen = selected->socklen;
    pc->name = &selected->name;

    selected->conns++;
    selected->requests++;

    njt_http_upstream_rr_peers_unlock(rrp->peers);

    njt_log_error(NJT_LOG_DEBUG, pc->log, 0,
                  "Sticky Learn: peer %V got selected.", &sp->md5);

    return NJT_OK;

round_robin:
    njt_http_upstream_rr_peers_unlock(rrp->peers);

    ret = njt_http_upstream_get_round_robin_peer(pc, rrp);

    if (ret == NJT_OK) {
        njt_http_sticky_md5(sp->request->pool, pc->sockaddr, &sp->md5);
        njt_log_error(NJT_LOG_DEBUG, pc->log, 0,
                      "Round Robin: peer %V got selected.", &sp->md5);
    } else {
        njt_log_error(NJT_LOG_DEBUG, pc->log, 0,
                      "Round Robin: no peer is selected.");
    }

    return ret;
}

void njt_http_sticky_learn_free_peer(njt_peer_connection_t *pc,
                                     njt_http_sticky_peer_data_t *sp,
                                     njt_uint_t state)
{

    njt_str_t                       cookie;
    njt_http_sticky_learn_conf_t    *conf;
    njt_http_request_t              *request;
    njt_http_upstream_rr_peer_t     *peer;
    time_t                          now;


    conf = sp->conf->learn_cf;
    request = sp->request;
    peer =  sp->rrp.current;

    njt_http_upstream_rr_peers_rlock(sp->rrp.peers);
    njt_http_upstream_rr_peer_lock(sp->rrp.peers, peer);

    if (sp->rrp.peers->single) {
	peer->conns--;

        njt_http_upstream_rr_peer_unlock(sp->rrp.peers, peer);
        njt_http_upstream_rr_peers_unlock(sp->rrp.peers);

        pc->tries = 0;
        return;
    }


    if (state == NJT_PEER_FAILED) {
        now = njt_time();

        peer->fails++;
        peer->accessed = now;
        peer->checked = now;

        njt_log_error(NJT_LOG_DEBUG, pc->log, 0,
                      "[worker %d] Peer connection failed.", njt_worker);
    }
    peer->conns--;

    njt_http_upstream_rr_peer_unlock(sp->rrp.peers, peer);
    njt_http_upstream_rr_peers_unlock(sp->rrp.peers);

    if (pc->tries) {
        pc->tries--;
    }

    njt_log_error(NJT_LOG_DEBUG, pc->log, 0,
                  "[worker %d] Enter njt_http_sticky_learn_free_peer",
                  njt_worker);

    /* try to find cookie defined by 'create' variable */
    njt_str_null(&cookie);
    njt_http_sticky_learn_find_variable_in_array(request, conf->create, &cookie);
    /* when no non-empty cookie is found */
    if (cookie.len == 0) {
        njt_log_error(NJT_LOG_DEBUG, pc->log, 0,
                      "No available cookie is found as defined in create.");
        return;
    }

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, pc->log, 0,
                   "create: found the variable: %V", &cookie);

    /* create a session in shared memory zone */
    njt_http_sticky_learn_create_session(&cookie, sp, pc->log);
}

static void njt_http_sticky_learn_timeout_handler(njt_event_t *event)
{

    njt_msec_t diff;
    njt_queue_t *cache;
    njt_slab_pool_t *shpool;
    njt_shm_zone_t *shm_zone;
    njt_http_sticky_learn_node_t *curr;
    njt_http_sticky_learn_tree_t *sticky_tree;

    njt_log_error(NJT_LOG_DEBUG, event->log, 0,
                  "[worker %d] Enter http sticky learn timeout handler",
                  njt_worker);

    shm_zone = event->data;
    sticky_tree = shm_zone->data;
    shpool = (njt_slab_pool_t *)shm_zone->shm.addr;

    njt_shmtx_lock(&shpool->mutex);
    /* check exit signals */
    njt_http_sticky_learn_cleanup_on_exit(sticky_tree, event->log);

    /* iterate the doublely linked list */
    for (cache = njt_queue_head(&sticky_tree->queue);
         cache != njt_queue_sentinel(&sticky_tree->queue);
         cache = njt_queue_next(cache)) {
        /* get the node */
        curr = njt_queue_data(cache, njt_http_sticky_learn_node_t, lru_node);

        diff = (njt_msec_t)(njt_current_msec - curr->time);
        if (diff > sticky_tree->timeout) {
            /* timeout, remove the node */
            njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                          "[event] removing node %V", &curr->value);

            /* delete the node from tree */
            njt_queue_remove(&curr->lru_node);
            njt_rbtree_delete(sticky_tree->tree, &curr->rbnode);

            /* free the memory blocks */
//            njt_slab_free_locked(shpool, curr->value.data);
//            njt_slab_free_locked(shpool, curr->server.data);
            njt_slab_free_locked(shpool, curr);

            njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                          "[event] node has been deleted");

        } else {
            njt_shmtx_unlock(&shpool->mutex);
            /* time is not out */
            njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                          "[event] reset timer to %dms for node %V", diff,
                          &curr->value);
            /* get back after 'diff' time */
            njt_add_timer(event, diff);
            return;
        }
    }

    njt_shmtx_unlock(&shpool->mutex);
    /* nothing in the queue */
    /* add a new timer */
    njt_add_timer(event, sticky_tree->timeout);
}

njt_int_t njt_http_sticky_learn_process_header(njt_http_request_t *r)
{
    njt_int_t rc;
    njt_str_t cookie;
    njt_http_upstream_t *upstream;
    njt_http_sticky_learn_conf_t *conf;

    njt_log_error(NJT_LOG_DEBUG, r->connection->log, 0,
                  "[process headers] Enter %s", __FUNCTION__);

    upstream = r->upstream;
    conf = ((njt_http_sticky_peer_data_t *)upstream->peer.data)->conf->learn_cf;
    rc = conf->set_header(r); /* parse the header */
    if (rc != NJT_OK) {
        return rc;
    }

    // _debug_echo_headers(r->connection->log, &upstream->headers_in.headers);
    /* try to find cookie defined by 'create' variable */
    njt_str_null(&cookie);
    njt_http_sticky_learn_find_variable_in_array(r, conf->create, &cookie);
    /* when no non-empty cookie is found */
    if (cookie.len == 0) {
        njt_log_error(NJT_LOG_DEBUG, r->connection->log, 0,
                      "No available cookie is found as defined in create.");
        return rc;
    }

    njt_log_error(NJT_LOG_DEBUG, r->connection->log, 0,
                  "create: found the variable: %V", &cookie);

    /* create a session in shared memory zone */
    njt_http_sticky_learn_create_session(&cookie, upstream->peer.data,
                                         r->connection->log);
    return rc;
}

static void njt_http_sticky_learn_create_session(
    njt_str_t *cookie, njt_http_sticky_peer_data_t *sp, njt_log_t *log)
{
    /* Create a session based on cookie value */
    uint32_t hash;
    njt_rbtree_t *tree;
    njt_slab_pool_t *shpool;
    njt_http_sticky_learn_conf_t *conf;
    njt_http_sticky_learn_node_t *node;
    njt_http_sticky_learn_tree_t *sticky_tree;
    size_t buf_size;

    /* get the red black tree */
    conf = sp->conf->learn_cf;
    sticky_tree = conf->shm_zone->data;
    tree = sticky_tree->tree;
    shpool = (njt_slab_pool_t *)conf->shm_zone->shm.addr;
    hash = njt_crc32_short(cookie->data, cookie->len);

    njt_shmtx_lock(&shpool->mutex);
    /* try to find the session */
    node = njt_http_sticky_learn_rbtree_lookup(tree, cookie, hash);
    if (node == NULL) {
        /* create a session */
        njt_log_error(NJT_LOG_DEBUG, log, 0, "create: creating new session");

        buf_size = sizeof(njt_http_sticky_learn_node_t) + cookie->len + sp->md5.len;
        /* allocate a red black tree node in shm_zone */
        node = njt_slab_alloc_locked(shpool, buf_size);
        if (node == NULL) {
            njt_shmtx_unlock(&shpool->mutex);
            njt_log_error(NJT_LOG_EMERG, log, 0, "create: no enough memory");
            return;
        }

        /* allocate the value of node, this value is the cookie's value */
        node->value.len = cookie->len;
        node->value.data = ((u_char*)node + sizeof(njt_http_sticky_learn_node_t)) ;

        /* allocate server data in the node, this is the md5 of server */
        node->server.len = sp->md5.len;
        node->server.data = ((u_char*)node + sizeof(njt_http_sticky_learn_node_t) + cookie->len );

        /* copy cookie's value into the node */
        njt_memcpy(node->value.data, cookie->data, cookie->len);

        /* set the rbtree node's hash */
        node->rbnode.key = hash;

        /* insert into tree */
        njt_rbtree_insert(tree, &node->rbnode);
    } else {
        /* the node already exists */
        njt_queue_remove(&node->lru_node);
    }

    /* save the server of node, use md5 as identifier here */
    njt_memcpy(node->server.data, sp->md5.data, sp->md5.len);

    njt_log_error(NJT_LOG_DEBUG, log, 0, "create: node value: %V, server: %V",
                  &node->value, &node->server);

    /* move the node to the tail of LRU cache queue */
    njt_queue_insert_tail(&sticky_tree->queue, &node->lru_node);

    /* set the access time */
    node->time = njt_current_msec;

    /* if there is no timer, set one */
    if (sticky_tree->has_timer == 0) {
        sticky_tree->timeout = conf->timeout;
        /* create a event */
        /* let it point to a local address? */
        sticky_tree->event = njt_pcalloc(njt_cycle->pool, sizeof(njt_event_t));
        if (sticky_tree->event == NULL) {
            njt_log_error(NJT_LOG_EMERG, log, 0, "[event]: no enough memory");
            goto end;
        }

        /* append the shm_zone to event */
        sticky_tree->event->data = conf->shm_zone;
        /* event should be ignored while shutting down the worker? */
        sticky_tree->event->cancelable = 0;
        sticky_tree->event->log = njt_cycle->log;
        sticky_tree->event->handler = njt_http_sticky_learn_timeout_handler;
        /* add a timer */
        njt_add_timer(sticky_tree->event, conf->timeout);
        sticky_tree->has_timer = 1;
        sticky_tree->event_worker = njt_worker;
        njt_log_error(NJT_LOG_DEBUG, log, 0,
                      "[event]: a timer (%dms) is added to worker %d",
                      conf->timeout, njt_worker);
    }
    /* check exit signals */
    njt_http_sticky_learn_cleanup_on_exit(sticky_tree, log);

#if(NJT_STREAM_ZONE_SYNC)
    njt_uint_t size;
    njt_chain_t *chain;
    njt_buf_t *buf;
    njt_http_sticky_learn_sync_data_t *header;

    size = node->server.len + node->value.len + sizeof(njt_http_sticky_learn_sync_data_t) + sizeof(njt_chain_t);
    buf = njt_create_temp_buf(njt_cycle->pool,size);
    if(buf == NULL ) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,"http sticky learn snapshot: alloc buf error");
        goto end;
    }
    chain = (njt_chain_t*)buf->pos;
    buf->last += sizeof(njt_chain_t);
    chain->buf = buf;
    header = (njt_http_sticky_learn_sync_data_t*)buf->last;
    buf->last += sizeof(njt_http_sticky_learn_sync_data_t);
    header->key_len = node->value.len;
    header->server_len = node->server.len;
    header->diff = sticky_tree->timeout;
    njt_memcpy(buf->last,node->value.data,node->value.len);
    buf->last +=node->value.len;
    njt_memcpy(buf->last,node->server.data,node->server.len);
    buf->last +=node->value.len;
#if (NJT_HAVE_LITTLE_ENDIAN)
    njt_htonl32(header->key_len );
    njt_htonl32(header->server_len);
    njt_htonl32(header->diff);
#endif
    njt_stream_zone_sync_send_data(NJT_HTTP_STICKY_MODULE_ID,conf->shm_zone->shm.name,chain);
    buf = chain->buf;
    njt_pfree(njt_cycle->pool,chain->buf->start);
    njt_pfree(njt_cycle->pool,buf);

#endif
end:
    njt_shmtx_unlock(&shpool->mutex);
}

void njt_http_sticky_learn_rbtree_insert_value(njt_rbtree_node_t *temp,
        njt_rbtree_node_t *node,
        njt_rbtree_node_t *sentinel)
{
    /* refer to njt_str_rbtree_insert_value */
    njt_rbtree_node_t **p;
    njt_http_sticky_learn_node_t *n, *t;

    for (;;) {
        n = (njt_http_sticky_learn_node_t *)(node -
                                             offsetof(njt_http_sticky_learn_node_t,
                                                     rbnode));
        t = (njt_http_sticky_learn_node_t *)(temp -
                                             offsetof(njt_http_sticky_learn_node_t,
                                                     rbnode));

        if (node->key != temp->key) {
            p = (node->key < temp->key) ? &temp->left : &temp->right;
        } else if (n->value.len != t->value.len) {
            p = (n->value.len < t->value.len) ? &temp->left : &temp->right;
        } else {
            p = (njt_memcmp(n->value.data, t->value.data, n->value.len) < 0)
                ? &temp->left
                : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    njt_rbt_red(node);
}

njt_http_sticky_learn_node_t *njt_http_sticky_learn_rbtree_lookup(
    njt_rbtree_t *rbtree, njt_str_t *val, uint32_t hash)
{
    /* refer to njt_str_rbtree_lookup */
    njt_int_t rc;
    njt_http_sticky_learn_node_t *n;
    njt_rbtree_node_t *node, *sentinel;

    node = rbtree->root;
    sentinel = rbtree->sentinel;

    while (node != sentinel) {
        n = (njt_http_sticky_learn_node_t *)(node -
                                             offsetof(njt_http_sticky_learn_node_t,
                                                     rbnode));

        if (hash != node->key) {
            node = (hash < node->key) ? node->left : node->right;
            continue;
        }

        if (val->len != n->value.len) {
            node = (val->len < n->value.len) ? node->left : node->right;
            continue;
        }

        rc = njt_memcmp(val->data, n->value.data, val->len);

        if (rc < 0) {
            node = node->left;
            continue;
        }

        if (rc > 0) {
            node = node->right;
            continue;
        }

        return n;
    }

    return NULL;
}

static njt_int_t njt_http_sticky_learn_init_zone(njt_shm_zone_t *shm_zone,
        void *data)
{

    njt_slab_pool_t *shpool;
    njt_http_sticky_learn_tree_t *sticky_tree;

    /* reusing a shared zone from old cycle */
    if (data) {
        shm_zone->data = data;
        return NJT_OK;
    }

    /* setup our shm zone */
    shpool = (njt_slab_pool_t *)shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        /* Windows: indicates shared memory was inherited from the master process */
        /* init shared zone context in Windows ngx worker */
        shm_zone->data = shpool->data;
        return NJT_OK;
    }

    /* init shared zone */
    sticky_tree = njt_slab_alloc(shpool, sizeof(njt_http_sticky_learn_tree_t));
    if (sticky_tree == NULL) {
        return NJT_ERROR;
    }

    sticky_tree->tree = njt_slab_alloc(shpool, sizeof(njt_rbtree_t));
    if (sticky_tree->tree == NULL) {
        return NJT_ERROR;
    }

    sticky_tree->sentinel = njt_slab_alloc(shpool, sizeof(njt_rbtree_node_t));
    if (sticky_tree->sentinel == NULL) {
        return NJT_ERROR;
    }

    /* init other parameters */
    sticky_tree->event = NULL;
    sticky_tree->has_timer = 0;
    sticky_tree->event_worker = 0;
    njt_queue_init(&sticky_tree->queue);

    /* init red black tree */
    njt_rbtree_init(sticky_tree->tree, sticky_tree->sentinel,
                    njt_http_sticky_learn_rbtree_insert_value);
    shm_zone->data = sticky_tree;

    return NJT_OK;
}

char *njt_http_sticky_learn_setup(njt_conf_t *cf, njt_http_sticky_conf_t *scf,
                                  njt_str_t *value)
{

    njt_int_t create_len = 0, lookup_len = 0, has_zone = 0;
    ssize_t size;      /* parsed zone size */
    njt_str_t zone, s; /* zone name, zone size str */
    u_char *size_p;    /* the pointer of ':' */
    njt_uint_t i;

#if(NJT_STREAM_ZONE_SYNC)
   njt_int_t sync = 0;
   njt_str_t zone_name;
#endif

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, cf->log, 0,
                   "entering sticky learn setup");

    /* since create and lookup parameter can be specified multiple times,
       we need to count the number of them
       zone is also a mandatory parameter, let's check it here */
    for (i = 2; i < cf->args->nelts; ++i) {
        if ((u_char *)njt_strstr(value[i].data, "create=$") == value[i].data) {
            create_len += 1;
            continue;
        }
        if ((u_char *)njt_strstr(value[i].data, "lookup=$") == value[i].data) {
            lookup_len += 1;
            continue;
        }
        if ((u_char *)njt_strstr(value[i].data, "zone=") == value[i].data) {
            if (has_zone != 0) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "parameter 'zone' cannot be specified"
                                   " multiple times.");
                return NJT_CONF_ERROR;
            }
            has_zone += 1;
            continue;
        }
#if(NJT_STREAM_ZONE_SYNC)
        if (njt_strncmp(value[i].data, "sync",4) == 0) {
            sync = 1;
            continue;
        }
#endif

    }

    /* check mandatory parameters */
    if (create_len == 0 || lookup_len == 0 || has_zone == 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "parameter 'create', 'lookup', and 'zone'"
                           " are mandatory for sticky learn directive.");
        return NJT_CONF_ERROR;
    }

    /* allocate the space for create/lookup array */
    scf->learn_cf->create =
        njt_array_create(cf->pool, create_len, sizeof(njt_int_t));
    scf->learn_cf->lookup =
        njt_array_create(cf->pool, lookup_len, sizeof(njt_int_t));

    /* set timeout to 10 minutes by default */
    scf->learn_cf->timeout = 600000; /* 10 minutes in millisec */

    /* set 'header' to 0 by default */
    scf->learn_cf->header = 0;

    /* check arguments */
    for (i = 2; i < cf->args->nelts; ++i) {
        /* Create: mandatory & could be specified multiple times */
        /* it specifies a variable that indicates how a new session is created */
        if ((u_char *)njt_strstr(value[i].data, "create=$") == value[i].data) {
            /* check whether the name of create variable is defined */
            if (value[i].len <= sizeof("create=$") - 1) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "a variable must be indicated under \"create\""
                                   " parameter.");
                return NJT_CONF_ERROR;
            }

            /* get the name of the variable */
            njt_str_t variable;
            variable.len = value[i].len - sizeof("create=$") + 1;
            variable.data = value[i].data + sizeof("create=$") - 1;

            /* check and save its index in conf */
            njt_int_t *var_index = njt_array_push(scf->learn_cf->create);
            if (var_index == NULL) {
                return NJT_CONF_ERROR;
            }
            *var_index = njt_http_get_variable_index(cf, &variable);
            if (*var_index == NJT_ERROR) {
                return NJT_CONF_ERROR;
            }

            njt_log_debug2(NJT_LOG_DEBUG_STREAM, cf->log, 0,
                           "create: getting %V variable at index %d", &variable,
                           *var_index);
            continue;
        }

        /* Lookup: mandatory & could be specified multiple times */
        /* it specifies how to search for existing sessions */
        if ((u_char *)njt_strstr(value[i].data, "lookup=$") == value[i].data) {
            /* check whether the name of lookup variable is defined */
            if (value[i].len <= sizeof("lookup=$") - 1) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "a variable must be indicated under "
                                   "\"lookup\" parameter.");
                return NJT_CONF_ERROR;
            }

            /* get the name of the variable */
            njt_str_t variable;
            variable.len = value[i].len - sizeof("lookup=$") + 1;
            variable.data = value[i].data + sizeof("lookup=$") - 1;

            /* check and save its index in conf */
            njt_int_t *var_index = njt_array_push(scf->learn_cf->lookup);
            if (var_index == NULL) {
                return NJT_CONF_ERROR;
            }
            *var_index = njt_http_get_variable_index(cf, &variable);
            if (*var_index == NJT_ERROR) {
                return NJT_CONF_ERROR;
            }

            njt_log_debug2(NJT_LOG_DEBUG_STREAM, cf->log, 0,
                           "lookup: getting %V variable at index %d", &variable,
                           *var_index);
            continue;
        }

        /* Zone specifies a shared memory zone where
           all information about sticky sessions is kept. */
        if ((u_char *)njt_strstr(value[i].data, "zone=") == value[i].data) {
            /* check whether the name of zone variable is defined */
            if (value[i].len <= sizeof("zone=") - 1) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "time and size must be indicated under "
                                   "\"zone\" parameter.");
                return NJT_CONF_ERROR;
            }

            /* create shared memory zone */
            zone.data = value[i].data + sizeof("zone=") - 1;
            size_p = (u_char *)njt_strchr(zone.data, ':');
            if (size_p == NULL) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "invalid zone settings %V",
                                   &value[i]);
                return NJT_CONF_ERROR;
            }

            zone.len = size_p - zone.data;
            if (zone.len == 0) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "a name of zone must be given in %V", &value[i]);
                return NJT_CONF_ERROR;
            }

            /* get the size as a string */
            s.data = size_p + 1;
            s.len = value[i].len - zone.len - 6;

            /* parse the size string */
            size = njt_parse_size(&s);

            if (size == NJT_ERROR) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "invalid zone size %V", &s);
                return NJT_CONF_ERROR;
            }

            if (size < (ssize_t)(8 * njt_pagesize)) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "zone \"%V\" is too small",
                                   &value[i]);
                return NJT_CONF_ERROR;
            }

            /* setup shared memory zone */
            njt_shm_zone_t *shm_zone;
            /* add an entry */
            shm_zone =
                njt_shared_memory_add(cf, &zone, size, &njt_http_sticky_module);
            if (shm_zone == NULL) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "error while creating shared memory zone.");
                return NJT_CONF_ERROR;
            }
#if(NJT_STREAM_ZONE_SYNC)
            zone_name = zone;
#endif
            scf->learn_cf->shm_zone = shm_zone;

            /* init is called after the shared zone is mapped to actual memory */
            shm_zone->init = njt_http_sticky_learn_init_zone;

            njt_log_debug2(NJT_LOG_DEBUG_STREAM, cf->log, 0,
                           "zone: [%V] with size [%V]", &zone, &s);

            continue;
        }

        /* Timeout: The sessions that are not accessed during the time
           specified by the timeout parameter get removed from the zone.
           By default, timeout is set to 10 minutes. */
        if ((u_char *)njt_strstr(value[i].data, "timeout=") == value[i].data) {
            /* check whether the timeout is defined */
            if (value[i].len <= sizeof("timeout=") - 1) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "a value must be provided under \"timeout\""
                                   " parameter.");
                return NJT_CONF_ERROR;
            }

            /* get the time string */
            njt_str_t timeout_str;
            timeout_str.data = value[i].data + sizeof("timeout=") - 1;
            timeout_str.len = value[i].len - sizeof("timeout=") + 1;

            /* parse the string to milliseconds */
            scf->learn_cf->timeout = njt_parse_time(&timeout_str, 0);
            if (scf->learn_cf->timeout == (njt_msec_t)NJT_ERROR) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "Invalid \"timeout\" parameter %V.", &value[i]);
                return NJT_CONF_ERROR;
            }

            njt_log_debug1(NJT_LOG_DEBUG_STREAM, cf->log, 0, "set timeout: %d ms",
                           scf->learn_cf->timeout);

            continue;
        }

        /* Header allows creating a session right after receiving response headers
         * from the upstream server. */
        if (njt_strcmp(value[i].data, "header") == 0) {
            scf->learn_cf->header = 1;
            continue;
        }

        /* invalid parameter */
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "invalid parameter \"%V\"",
                           &value[i]);
        return NJT_CONF_ERROR;
    }
#if(NJT_STREAM_ZONE_SYNC)
    uint32_t hash;
    if ( sync == 1) {
        njt_stream_zone_sync_register_zone(cf,NJT_HTTP_STICKY_MODULE_ID,zone_name);
        njt_http_sticky_learn_main_conf_t *slmcf = njt_http_conf_get_module_main_conf(cf,njt_http_sticky_module);
        if(slmcf == NULL){
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,"cann`t get sticky learn main conf");
            return NJT_CONF_ERROR;
        }
        njt_http_sticky_learn_zone_info_t *zone_info = njt_pcalloc(cf->pool, sizeof(njt_http_sticky_learn_zone_info_t));
        if(zone_info == NULL){
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,"alloc zone info error!");
            return NJT_CONF_ERROR;
        }
        zone_info->ctx = cf->ctx;
        zone_info->server_cf = scf->learn_cf;
        zone_info->zone_name = zone_name;
        hash = njt_crc32_long(zone_name.data, zone_name.len);
        zone_info->tree_node.key = hash;
        njt_queue_insert_tail(&slmcf->zones,&zone_info->queue);
        njt_rbtree_insert(&slmcf->lookup_tree,&zone_info->tree_node);
    }
#endif
    return NJT_CONF_OK;
}
