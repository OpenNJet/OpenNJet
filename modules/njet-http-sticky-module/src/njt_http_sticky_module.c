/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */
#include "njt_http_sticky_module.h"
#include "njt_http_sticky_route.h"
#include "njt_http_sticky_cookie.h"
#include "njt_http_sticky_learn.h"

static void *njt_http_sticky_create_conf(njt_conf_t *cf);
static char *njt_http_sticky_setup(njt_conf_t *cf, njt_command_t *cmd,
                                   void *conf);
static njt_int_t njt_http_sticky_init(njt_conf_t *cf,
                                      njt_http_upstream_srv_conf_t *us);
static njt_int_t njt_http_sticky_init_peer(njt_http_request_t *r,
        njt_http_upstream_srv_conf_t *us);
static njt_int_t njt_http_sticky_get_peer(njt_peer_connection_t *pc,
        void *data);
static void njt_http_sticky_free_peer(njt_peer_connection_t *pc, void *data,
                                      njt_uint_t state);
#if(NJT_STREAM_ZONE_SYNC)
static void * njt_http_sticky_create_main_conf(njt_conf_t *cf); //注册模块
#endif
/**
 * This module provided directive: sticky.
 *
 */
static njt_command_t njt_http_sticky_commands[] = {
    {
        njt_string("sticky"),               /* directive */
        NJT_HTTP_UPS_CONF | NJT_CONF_2MORE, /* location context */
        njt_http_sticky_setup,              /* setup function */
        NJT_HTTP_SRV_CONF_OFFSET, 0, NULL
    },

    njt_null_command /* command termination */
};

/* The module context. */
static njt_http_module_t njt_http_sticky_module_ctx = {
    NULL, /* preconfiguration */
    NULL, /* postconfiguration */
#if(NJT_STREAM_ZONE_SYNC)
    njt_http_sticky_create_main_conf,
#else
    NULL, /* create main configuration */
#endif
    NULL, /* init main configuration */

    njt_http_sticky_create_conf, /* create server configuration */
    NULL,                        /* merge server configuration */

    NULL, /* create location configuration */
    NULL  /* merge location configuration */
};

/* Module definition. */
njt_module_t njt_http_sticky_module = {
    NJT_MODULE_V1,
    &njt_http_sticky_module_ctx, /* module context */
    njt_http_sticky_commands,    /* module directives */
    NJT_HTTP_MODULE,             /* module type */
    NULL,                        /* init master */
    NULL,                        /* init module */
    NULL,                        /* init process */
    NULL,                        /* init thread */
    NULL,                        /* exit thread */
    NULL,                        /* exit process */
    NULL,                        /* exit master */
    NJT_MODULE_V1_PADDING
};

/**
 * Configuration setup function that installs the content handler.
 *
 * @param cf
 *   Module configuration structure pointer.
 * @param cmd
 *   Module directives structure pointer.
 * @param conf
 *   Module configuration structure pointer.
 * @return string
 *   Status of the configuration setup.
 */
static char *njt_http_sticky_setup(njt_conf_t *cf, njt_command_t *cmd,
                                   void *conf)
{

    njt_http_sticky_conf_t *scf = conf;
    njt_str_t *value;
    njt_http_upstream_srv_conf_t *uscf;

    uscf = njt_http_conf_get_module_srv_conf(cf, njt_http_upstream_module);

    if (uscf->peer.init_upstream) {
        njt_conf_log_error(NJT_LOG_WARN, cf, 0, "load balancing method redefined");
    }

    uscf->peer.init_upstream = njt_http_sticky_init;
    uscf->flags = NJT_HTTP_UPSTREAM_CREATE | NJT_HTTP_UPSTREAM_WEIGHT |
                  NJT_HTTP_UPSTREAM_MAX_CONNS | NJT_HTTP_UPSTREAM_MAX_FAILS |
                  NJT_HTTP_UPSTREAM_FAIL_TIMEOUT | NJT_HTTP_UPSTREAM_DOWN;

    if (cf->args->nelts < 3) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid number of arguments in \"sticky\" directive");
        return NJT_CONF_ERROR;
    }

    value = cf->args->elts;

    if (njt_strcmp(value[1].data, "cookie") == 0) {
        /* sticky cookie */
        scf->type = HTTP_STICKY_TYPE_COOKIE;
        return njt_http_sticky_cookie_setup(cf, scf, value);
    } else if (njt_strcmp(value[1].data, "learn") == 0) {
        /* sticky learn */
        scf->type = HTTP_STICKY_TYPE_LEARN;
        return njt_http_sticky_learn_setup(cf, scf, value);
    } else if (njt_strcmp(value[1].data, "route") == 0) {
        /* sticky route */
        scf->type = HTTP_STICKY_TYPE_ROUTE;
        return njt_http_sticky_route_setup(cf, scf, value);
    } else {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "unknown parameter \"%V\"",
                           &value[1]);
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
} /* njt_http_sticky */

static void *njt_http_sticky_create_conf(njt_conf_t *cf)
{

    njt_http_sticky_conf_t *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_sticky_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->cookie_cf =
        njt_pcalloc(cf->pool, sizeof(njt_http_sticky_cookie_conf_t));
    if (conf->cookie_cf == NULL) {
        return NULL;
    }

    conf->learn_cf = njt_pcalloc(cf->pool, sizeof(njt_http_sticky_learn_conf_t));
    if (conf->learn_cf == NULL) {
        return NULL;
    }
	conf->route_cf = njt_pcalloc(cf->pool, sizeof(njt_http_sticky_route_conf_t));
    if (conf->route_cf == NULL) {
        return NULL;
    }

    return conf;
}

static njt_int_t njt_http_sticky_init(njt_conf_t *cf,
                                      njt_http_upstream_srv_conf_t *uscf)
{

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, cf->log, 0, "init http sticky");

    if (njt_http_upstream_init_round_robin(cf, uscf) != NJT_OK) {
        return NJT_ERROR;
    }

    uscf->peer.init = njt_http_sticky_init_peer;

    return NJT_OK;
}

static njt_int_t njt_http_sticky_init_peer(njt_http_request_t *r,
        njt_http_upstream_srv_conf_t *uscf)
{

    njt_http_sticky_conf_t *scf;
    njt_http_sticky_peer_data_t *sp;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0, "init sticky peer");

    scf = njt_http_conf_upstream_srv_conf(uscf, njt_http_sticky_module);

    sp = njt_palloc(r->pool, sizeof(njt_http_sticky_peer_data_t));
    if (sp == NULL) {
        return NJT_ERROR;
    }

    r->upstream->peer.data = &sp->rrp;

    if (njt_http_upstream_init_round_robin_peer(r, uscf) != NJT_OK) {
        return NJT_ERROR;
    }

    r->upstream->peer.get = njt_http_sticky_get_peer;

    if (scf->type == HTTP_STICKY_TYPE_LEARN && scf->learn_cf->header) {
        /* store the callback for handling headers */
        scf->learn_cf->set_header = r->upstream->process_header;
        /* register callback right after upstream headers are received */
        r->upstream->process_header = njt_http_sticky_learn_process_header;
    } else {
        r->upstream->peer.free = njt_http_sticky_free_peer;
    }

    sp->conf = scf;
    sp->tries = 0;
    sp->request = r;
    sp->data = r->upstream->peer.data;
    sp->original_free_peer = njt_http_upstream_free_round_robin_peer;
    sp->original_get_peer = njt_http_upstream_get_round_robin_peer;

    return NJT_OK;
}

static void njt_http_sticky_free_peer(njt_peer_connection_t *pc, void *data,
                                      njt_uint_t state)
{

    njt_http_sticky_peer_data_t *sp = data;

    if (sp->conf->type == HTTP_STICKY_TYPE_LEARN) {
        njt_http_sticky_learn_free_peer(pc, sp, state);
    }
    sp->original_free_peer(pc, sp->data, state);
}

static njt_int_t njt_http_sticky_get_peer(njt_peer_connection_t *pc,
        void *data)
{

    njt_http_sticky_peer_data_t *sp = data;

    if (sp->conf->type == HTTP_STICKY_TYPE_COOKIE) {
        return njt_http_sticky_cookie_get_peer(pc, sp);
    } else if (sp->conf->type == HTTP_STICKY_TYPE_LEARN) {
        return njt_http_sticky_learn_get_peer(pc, sp);
    }else if (sp->conf->type == HTTP_STICKY_TYPE_ROUTE) {
        return njt_http_sticky_route_get_peer(pc, sp);
    }

    return NJT_ERROR;
}

njt_int_t njt_http_sticky_md5(njt_pool_t *pool, struct sockaddr *in,
                              njt_str_t *out)
{

    size_t len;
    njt_str_t addr;
    njt_md5_t md5;
    u_char hash[MD5_LENGTH];

    if (!pool || !in || !out) {
        return NJT_ERROR;
    }

    /* Determine the length of addr string */
    switch (in->sa_family) {
    case AF_INET:
        len = NJT_INET_ADDRSTRLEN + sizeof(":65535") - 1;
        break;

#if (NJT_HAVE_INET6)
    case AF_INET6:
        len = NJT_INET6_ADDRSTRLEN + sizeof(":65535") - 1;
        break;
#endif

#if (NJT_HAVE_UNIX_DOMAIN)
    case AF_UNIX:
        len = sizeof("unix:") - 1 + NJT_UNIX_ADDRSTRLEN;
        break;
#endif

    default:
        return NJT_ERROR;
    }

    /* Convert sockaddr to addr string */
    addr.data = njt_pnalloc(pool, len);
    if (addr.data == NULL) {
        return NJT_ERROR;
    }
    addr.len = njt_sock_ntop(in, sizeof(struct sockaddr_in), addr.data, len, 1);

    /* Calculate MD5 of sockaddr */
    out->data = njt_pcalloc(pool, MD5_LENGTH * 2);
    if (out->data == NULL) {
        njt_pfree(pool, &addr);
        return NJT_ERROR;
    }

    out->len = MD5_LENGTH * 2;
    njt_md5_init(&md5);
    njt_md5_update(&md5, addr.data, addr.len);
    njt_md5_final(hash, &md5);

    njt_hex_dump(out->data, hash, MD5_LENGTH);
    return njt_pfree(pool, &addr);
}

#if(NJT_STREAM_ZONE_SYNC)
static njt_http_sticky_learn_zone_info_t* njt_http_sticky_learn_lookup_zone(njt_http_sticky_learn_main_conf_t *slmcf,
                                                                      njt_str_t *zone_name){
    njt_rbtree_node_t *node;
    njt_rbtree_key_t key;
    njt_int_t rc;
    njt_http_sticky_learn_zone_info_t* info;

    key = njt_crc32_long(zone_name->data,zone_name->len);
    node = slmcf->lookup_tree.root;
    while (node != slmcf->lookup_tree.sentinel){
        info = (njt_http_sticky_learn_zone_info_t* )((u_char*)node - offsetof(njt_http_sticky_learn_zone_info_t,tree_node));
        if (key != node->key) {
            node = (key < node->key) ? node->left : node->right;
            continue;
        }else if(info->zone_name.len != zone_name->len){
            node = (zone_name->len < info->zone_name.len) ? node->left : node->right;
            continue;
        }else {
            rc = njt_memcmp(zone_name->data, info->zone_name.data, zone_name->len);
            if(rc == 0){
                return info;
            }
            node =  rc < 0 ? node->left : node->right;
        }
    }
    return NULL;
}

static njt_uint_t njt_http_sticky_learn_zs_unpack(njt_str_t *zone_name,u_char *data,size_t len){
    njt_http_sticky_learn_main_conf_t *slmcf;
    njt_http_sticky_learn_zone_info_t* zone_info;
    njt_http_sticky_learn_tree_t  *sh;
    njt_uint_t index,size,buf_size;
    njt_http_sticky_learn_sync_data_t *header;
    uint32_t hash;
    njt_http_sticky_learn_node_t *node,*old_node;
    njt_str_t key;
    njt_slab_pool_t *pool;

    slmcf = njt_http_cycle_get_module_main_conf(njt_cycle, njt_http_sticky_module);
    if(slmcf == NULL){
        return NJT_ERROR;
    }
    zone_info = njt_http_sticky_learn_lookup_zone(slmcf,zone_name);
    if(zone_info == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,"http limit req can`t find zone: %V",zone_name);
        return NJT_ERROR;
    }
    sh = zone_info->server_cf->shm_zone->data;
    for(index = 0;index < len;){
        pool = (njt_slab_pool_t *)zone_info->server_cf->shm_zone->shm.addr;
        header = (njt_http_sticky_learn_sync_data_t *)data+index;
#if (NJT_HAVE_LITTLE_ENDIAN)
        njt_htonl32(header->key_len );
        njt_htonl32(header->server_len);
        njt_htonl32(header->diff);
#endif
        buf_size = sizeof(njt_http_sticky_learn_node_t) + header->server_len + header->key_len;
        node = njt_slab_alloc(pool,buf_size);
        if(node == NULL){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,"http sticky learn snapshot: alloc buf error");
            size = header->server_len + header->key_len + sizeof(njt_http_sticky_learn_sync_data_t);
            index += size;
            continue;
        }
        node->time = njt_current_msec + header->diff - sh->timeout;
        node->value.len = header->key_len;
        node->value.data = ((u_char*)node+sizeof(njt_http_sticky_learn_node_t));
        index += sizeof(njt_http_sticky_learn_sync_data_t);
        njt_memcpy(node->value.data,data+index,node->value.len);
        node->server.len = header->server_len;
        node->server.data = ((u_char*)node+sizeof(njt_http_sticky_learn_node_t)+header->key_len);
        index += header->key_len;
        njt_memcpy(node->server.data,data+index,node->server.len);
        index += header->server_len;

        hash = njt_crc32_short(data+index,header->key_len);
        key.data = data+index;
        key.len = header->key_len;
        old_node = njt_http_sticky_learn_rbtree_lookup(sh->tree, &key, hash);
        if(old_node != NULL && old_node->time < node->time){
            njt_queue_remove(&old_node->lru_node);
            njt_rbtree_delete(sh->tree, &old_node->rbnode);
            njt_slab_free(pool,old_node);
            njt_queue_insert_tail(&sh->queue,&node->lru_node);
            njt_rbtree_insert(sh->tree,&node->rbnode);
        } else{
            njt_slab_free(pool,node);
        }
        size = header->server_len + header->key_len + sizeof(njt_http_sticky_learn_sync_data_t);
        index += size;
    }
    return NJT_OK;
}


static njt_int_t njt_http_sticky_learn_zs_snapshot(void *ctx){
    njt_http_sticky_learn_main_conf_t *slmcf;
    njt_http_sticky_learn_zone_info_t* zone_info;
    njt_http_sticky_learn_tree_t  *sh;
    njt_queue_t *queue,*z_queue;
    njt_http_sticky_learn_node_t *node;
    njt_msec_t diff;
    njt_chain_t *chain,**next,*first;
    njt_buf_t *buf;
    njt_uint_t size;
    njt_http_sticky_learn_sync_data_t *header;
    njt_slab_pool_t *pool;

    slmcf = njt_http_cycle_get_module_main_conf(njt_cycle, njt_http_sticky_module);
    if(slmcf == NULL){
        return NJT_ERROR;
    }
    z_queue = njt_queue_head(&slmcf->zones);
    for (; z_queue != njt_queue_sentinel(&slmcf->zones) ;z_queue= njt_queue_next(z_queue)) {
        zone_info = njt_queue_data(z_queue,njt_http_sticky_learn_zone_info_t,queue);
        sh = zone_info->server_cf->shm_zone->data;
        queue = njt_queue_head(&sh->queue);
        first = chain = NULL;
        next = &first;
        for(;queue != njt_queue_sentinel(&sh->queue) ; queue = njt_queue_next(queue)){
            node = njt_queue_data(queue, njt_http_sticky_learn_node_t, lru_node);
            diff = (njt_msec_t)(njt_current_msec - node->time);
            if (diff >= sh->timeout){
                break;
            }
            size = node->server.len + node->value.len + sizeof(njt_http_sticky_learn_sync_data_t) + sizeof(njt_chain_t);
            buf = njt_create_temp_buf(njt_cycle->pool,size);
            if(buf == NULL ) {
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,"http sticky learn snapshot: alloc buf error");
                continue;
            }
            chain = (njt_chain_t*)buf->pos;
            buf->last += sizeof(njt_chain_t);
            chain->buf = buf;
            header = (njt_http_sticky_learn_sync_data_t*)buf->last;
            buf->last += sizeof(njt_http_sticky_learn_sync_data_t);
            pool = (njt_slab_pool_t *)zone_info->server_cf->shm_zone->shm.addr;
            njt_shmtx_lock(&pool->mutex) ;
            header->key_len = node->value.len;
            header->server_len = node->server.len;
            header->diff = diff;
            njt_memcpy(buf->last,node->value.data,node->value.len);
            buf->last +=node->value.len;
            njt_memcpy(buf->last,node->server.data,node->server.len);
            buf->last +=node->value.len;
            njt_shmtx_unlock(&pool->mutex) ;
#if (NJT_HAVE_LITTLE_ENDIAN)
            njt_htonl32(header->key_len );
            njt_htonl32(header->server_len);
            njt_htonl32(header->diff);
#endif
            *next = chain;
            chain->next = NULL;
            next = &chain->next;
        }
        njt_stream_zone_sync_send_connection_data(NJT_HTTP_STICKY_MODULE_ID,zone_info->zone_name,first,ctx);
        for(chain = first;chain != NULL; chain = chain->next){
            buf = chain->buf;
            njt_pfree(njt_cycle->pool,chain->buf->start);
            njt_pfree(njt_cycle->pool,buf);
        }
    }
    return NJT_OK;
}

static njt_stream_zone_status_info_t* njt_http_sticky_learn_zs_get_size(njt_str_t *zone_name){
    njt_http_sticky_learn_main_conf_t *slmcf;
    njt_http_sticky_learn_zone_info_t* zone_info;
    njt_http_sticky_learn_tree_t  *sh;
    njt_queue_t *queue;
    njt_uint_t count = 0;
    njt_stream_zone_status_info_t* res;
    njt_http_sticky_learn_node_t *node;
    njt_msec_t diff;

    slmcf = njt_http_cycle_get_module_main_conf(njt_cycle, njt_http_sticky_module);
    if(slmcf == NULL){
        return NULL;
    }
    zone_info = njt_http_sticky_learn_lookup_zone(slmcf,zone_name);
    if(zone_info == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,"http limit req can`t find zone: %V",zone_name);
        return NULL;
    }
    sh = zone_info->server_cf->shm_zone->data;
    queue = njt_queue_head(&sh->queue);
    for(;queue != njt_queue_sentinel(&sh->queue) ; queue = njt_queue_next(queue)){
        node = njt_queue_data(queue, njt_http_sticky_learn_node_t, lru_node);
        diff = (njt_msec_t)(njt_current_msec - node->time);
        if (diff < sh->timeout){
            ++count;
        }
    }
    res = &sh->status_info;
    res->need_sends = 0;
    res->quantity = count;
    return res;
}

static void* njt_http_sticky_create_main_conf(njt_conf_t *cf){
    njt_http_sticky_learn_main_conf_t *slmcf;
    njt_stream_zone_sync_call_func_t* module_info;
    njt_int_t   rc;

    slmcf = njt_pcalloc(cf->pool, sizeof(njt_http_sticky_learn_main_conf_t));
    if(slmcf == NULL ){
        return NULL;
    }
    module_info = njt_pcalloc(cf->pool, sizeof(njt_stream_zone_sync_call_func_t));
    if(module_info == NULL ){
        return NULL;
    }
    module_info->module_id = NJT_HTTP_STICKY_MODULE_ID;
    module_info->version = NJT_HTTP_STICKY_MODULE_VER;
    module_info->getsize = njt_http_sticky_learn_zs_get_size;
    module_info->unpack = njt_http_sticky_learn_zs_unpack;
    module_info->snapshot = njt_http_sticky_learn_zs_snapshot;
    rc = njt_stream_zone_sync_register_module(cf,module_info);
    if(rc != NJT_OK){
        return NULL;
    }
    njt_rbtree_init(&slmcf->lookup_tree,&slmcf->sentinel,njt_str_rbtree_insert_value);
    njt_queue_init(&slmcf->zones);
    return slmcf;
}
#endif
