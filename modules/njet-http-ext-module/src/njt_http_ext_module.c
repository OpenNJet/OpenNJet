
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_http_ext_module.h>
#include <njt_hash_util.h>

extern njt_cycle_t *njet_master_cycle;
static void *njt_http_ext_create_main_conf(njt_conf_t *cf);
static njt_int_t njt_http_ext_init(njt_conf_t *cf);
static void njt_http_ext_exit_worker(njt_cycle_t *cycle);
static char *njt_http_ext_upstream_domain_zone(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static njt_int_t njt_http_ext_upstream_domain_zone_init(njt_shm_zone_t *shm_zone, void *data);
njt_int_t njt_http_upstream_find_cache_domain(njt_conf_t *cf, njt_url_t *u);

typedef struct
{
    njt_lvlhash_map_t *njt_http_notice_hashmap;
    njt_array_t hash_keys;

   //upstream domain cache
   njt_http_dyn_upstream_domain_main_conf_t *domain_main; 
} njt_http_ext_main_conf_t;

static njt_command_t njt_http_ext_commands[] = {
    { njt_string("http_domain_upstream_zone"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_1MORE,
      njt_http_ext_upstream_domain_zone,
      0,
      0,
      NULL },
    njt_null_command};

static njt_http_module_t njt_http_ext_module_ctx = {
    NULL,              /* preconfiguration */
    njt_http_ext_init, /* postconfiguration */

    njt_http_ext_create_main_conf, /* create main configuration */
    NULL,                          /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    NULL, /* create location configuration */
    NULL  /* merge location configuration */
};

njt_module_t njt_http_ext_module = {
    NJT_MODULE_V1,
    &njt_http_ext_module_ctx,  /* module context */
    njt_http_ext_commands,     /* module directives */
    NJT_HTTP_MODULE,           /* module type */
    NULL,                      /* init master */
    NULL,                      /* init module */
    NULL,                      /* init process */
    NULL,                      /* init thread */
    NULL,                      /* exit thread */
    &njt_http_ext_exit_worker, /* exit process */
    NULL,                      /* exit master */
    NJT_MODULE_V1_PADDING};

static void *
njt_http_ext_create_main_conf(njt_conf_t *cf)
{
    njt_http_ext_main_conf_t *conf;
    njt_str_t name = njt_string("http_domain_zone");
    njt_uint_t size = 128*1024;
    conf = njt_pcalloc(cf->pool, sizeof(njt_http_ext_main_conf_t));
    if (conf == NULL)
    {
        return NULL;
    }
    njt_array_init(&conf->hash_keys, cf->pool, 1, sizeof(njt_str_t *));
    conf->njt_http_notice_hashmap = njt_pcalloc(cf->pool, sizeof(njt_lvlhash_map_t));
    if (conf->njt_http_notice_hashmap == NULL)
    {
        return NULL;
    }
    conf->domain_main = njt_pcalloc(cf->pool, sizeof(njt_http_dyn_upstream_domain_main_conf_t));
    if (conf->domain_main == NULL)
    {
        return NULL;
    }
	conf->domain_main->shm_zone.shm.name = name;
	conf->domain_main->shm_zone.shm.size = size;
	conf->domain_main->shm_zone.shm.log = cf->cycle->log;
    return conf;
}

static njt_int_t
njt_http_ext_init(njt_conf_t *cf)
{
    njt_http_ext_main_conf_t *umcf;
    njt_core_conf_t      *ccf;

	ccf = (njt_core_conf_t *) njt_get_conf(cf->cycle->conf_ctx, njt_core_module);
	
    umcf = njt_http_conf_get_module_main_conf(cf, njt_http_ext_module);
	if(ccf->shared_slab_pool_size > 0 && umcf != NULL && umcf->domain_main != NULL && umcf->domain_main->shm_zone.shm.size > 0) {
		umcf->domain_main->shm_zone.data = umcf;
		umcf->domain_main->shm_zone.init = njt_http_ext_upstream_domain_zone_init;
		umcf->domain_main->shm_zone.noreuse = 1;
		njt_share_slab_defer_get_pool((njt_cycle_t *)cf->cycle,&umcf->domain_main->shm_zone,NJT_DYN_SHM_CREATE_OR_OPEN, &umcf->domain_main->shpool); 
	}
    return NJT_OK;
}

njt_int_t njt_http_object_register_notice(njt_str_t *key, njt_http_object_change_reg_info_t *handler)
{
    njt_http_ext_main_conf_t *mcf;
    njt_int_t rc;
    njt_str_t **name;
    object_change_hash_data_t *hash_data = NULL, *old_hash_data;
    njt_http_object_change_handler_t *object_handler;
    mcf = njt_http_cycle_get_module_main_conf(njt_cycle, njt_http_ext_module);
    if (mcf && mcf->njt_http_notice_hashmap)
    {

        rc = njt_lvlhsh_map_get(mcf->njt_http_notice_hashmap, key, (intptr_t *)&hash_data);
        if (rc != NJT_OK)
        {
            hash_data = njt_pcalloc(njt_cycle->pool, sizeof(object_change_hash_data_t));
            if (hash_data == NULL)
            {
                return NJT_ERROR;
            }
            njt_queue_init(&hash_data->handler_queue);
            hash_data->key.len = key->len;
            hash_data->key.data = njt_pcalloc(njt_cycle->pool, key->len);
            if (hash_data->key.data == NULL)
            {
                return NJT_ERROR;
            }
            njt_memcpy(hash_data->key.data, key->data, key->len);
            name = njt_array_push(&mcf->hash_keys);
            *name = &hash_data->key;
            njt_lvlhsh_map_put(mcf->njt_http_notice_hashmap, &hash_data->key, (intptr_t)hash_data, (intptr_t *)&old_hash_data);
            if (old_hash_data && old_hash_data != hash_data)
            {
                return NJT_ERROR;
            }
        }
        if (hash_data != NULL)
        {
            object_handler = njt_pcalloc(njt_cycle->pool, sizeof(njt_http_object_change_handler_t));
            if (object_handler == NULL)
            {
                return NJT_ERROR;
            }
            object_handler->callbacks.add_handler = handler->add_handler;
            object_handler->callbacks.update_handler = handler->update_handler;
            object_handler->callbacks.del_handler = handler->del_handler;
            njt_queue_insert_tail(&hash_data->handler_queue, &object_handler->queue);
        }
    }
    return NJT_OK;
}
void njt_http_object_dispatch_notice(njt_str_t *key, notice_op op, void *object_data)
{
    njt_queue_t *q;
    njt_http_ext_main_conf_t *mcf;
    njt_int_t rc;
    njt_http_object_change_handler_t *handler;
    object_change_hash_data_t *hash_data = NULL;
    mcf = njt_http_cycle_get_module_main_conf(njt_cycle, njt_http_ext_module);
    if (mcf && mcf->njt_http_notice_hashmap)
    {
        rc = njt_lvlhsh_map_get(mcf->njt_http_notice_hashmap, key, (intptr_t *)&hash_data);
        if (rc == NJT_OK && hash_data != NULL)
        {
            q = njt_queue_head(&hash_data->handler_queue);
            while (q != njt_queue_sentinel(&hash_data->handler_queue))
            {
                handler = njt_queue_data(q, njt_http_object_change_handler_t, queue);
                q = njt_queue_next(q);
                if (op == ADD_NOTICE && handler->callbacks.add_handler)
                {
                    handler->callbacks.add_handler(object_data);
                }
                else if (op == UPDATE_NOTICE && handler->callbacks.update_handler)
                {
                    handler->callbacks.update_handler(object_data);
                }
                else if (op == DELETE_NOTICE && handler->callbacks.del_handler)
                {
                    handler->callbacks.del_handler(object_data);
                }
            }
        }
    }
}

static void njt_http_ext_exit_worker(njt_cycle_t *cycle)
{
    njt_http_ext_main_conf_t *mcf;
    njt_uint_t i;
    njt_str_t **arr;
    mcf = njt_http_cycle_get_module_main_conf(cycle, njt_http_ext_module);
    if (mcf && mcf->njt_http_notice_hashmap)
    {
        arr = mcf->hash_keys.elts;
        for (i = 0; i < mcf->hash_keys.nelts; i++)
        {
            njt_lvlhsh_map_remove(mcf->njt_http_notice_hashmap, arr[i]);
        }
    }
}
static char *njt_http_ext_upstream_domain_zone(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
	njt_str_t *value;
	ssize_t size;
	njt_http_ext_main_conf_t *uscf;

	uscf = njt_http_conf_get_module_main_conf(cf, njt_http_ext_module);

	value = cf->args->elts;
    if (cf->args->nelts == 2 && njt_strcmp(value[1].data, "on") == 0)
	{
		return NJT_CONF_OK;
	}
    if (njt_strcmp(value[1].data, "off") == 0)
	{
        if(cf->args->nelts == 2) {
            njt_str_set(&uscf->domain_main->shm_zone.shm.name, "");
		    uscf->domain_main->shm_zone.shm.size = 0;
		    return NJT_CONF_OK;
        } else {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
						   "invalid parameter \"%V\"", &value[0]);
		    return NJT_CONF_ERROR;
        }
	} 
    if (cf->args->nelts != 4)
	{
		njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
						   "too few arguments \"%V\"", &value[0]);
		return NJT_CONF_ERROR;
	}
    if ( !(njt_strcmp(value[1].data, "on") == 0 && cf->args->nelts == 4)) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
						   "invalid parameter \"%V\"", &value[0]);
		return NJT_CONF_ERROR;
    }
	
	if (!value[2].len)
	{
		njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
						   "invalid zone name \"%V\"", &value[2]);
		return NJT_CONF_ERROR;
	}
	uscf->domain_main->shm_zone.shm.name = value[2];

	size = njt_parse_size(&value[3]);

	if (size == NJT_ERROR)
	{
		njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
						   "invalid zone size \"%V\"", &value[3]);
		return NJT_CONF_ERROR;
	}

	if (size < (ssize_t)(8 * njt_pagesize))
	{
		njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
						   "zone \"%V\" is too small", &value[2]);
		return NJT_CONF_ERROR;
	}
	uscf->domain_main->shm_zone.shm.size = size;
	

	return NJT_CONF_OK;
}

static njt_int_t
njt_http_ext_upstream_domain_zone_init(njt_shm_zone_t *shm_zone, void *data)
{
	size_t                   len;
    njt_http_ext_main_conf_t  *ctx;
    

    ctx = shm_zone->data;
    
    ctx->domain_main->shpool = (njt_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->domain_main->sh = ctx->domain_main->shpool->data;

        return NJT_OK;
    }

    ctx->domain_main->sh = njt_slab_calloc(ctx->domain_main->shpool, sizeof(njt_http_dyn_upstream_domain_cache_ctx_t));
    if (ctx->domain_main->sh == NULL) {
        return NJT_ERROR;
    }

    ctx->domain_main->shpool->data = ctx->domain_main->sh;

    njt_rbtree_init(&ctx->domain_main->sh->rbtree, &ctx->domain_main->sh->sentinel,
                    njt_str_rbtree_insert_value);
              

    len = sizeof(" in njt_http_ext_upstream_domain_zone_init \"\"") + shm_zone->shm.name.len;

    ctx->domain_main->shpool->log_ctx = njt_slab_calloc(ctx->domain_main->shpool, len);
    if (ctx->domain_main->shpool->log_ctx == NULL) {
        return NJT_ERROR;
    }

    njt_sprintf(ctx->domain_main->shpool->log_ctx, " in njt_http_ext_upstream_domain_zone_init \"%V\"%Z",
                &shm_zone->shm.name);

    return NJT_OK;
}
njt_int_t njt_http_upstream_find_cache_domain(njt_conf_t *cf, njt_url_t *u)
{
    njt_str_t domain_port;
    u_char *p;
	uint32_t hash;
    njt_uint_t i,len;
    njt_http_ext_main_conf_t  *usmf;
	njt_http_dyn_upstream_domain_node_t *ip_node;
    njt_slab_pool_t *shpool;
    struct sockaddr  *sa;
    njt_cycle_t  *cycle = (njet_master_cycle ?njet_master_cycle:(njt_cycle_t  *)njt_cycle);

    usmf = njt_http_cycle_get_module_main_conf(cycle, njt_http_ext_module);
    if(cf->dynamic == 0 || usmf->domain_main == NULL || usmf->domain_main->shpool == NULL) {
        return NJT_ERROR;
    }
    domain_port.len = u->host.len + sizeof("65535");
    domain_port.data = njt_pcalloc(cf->pool, domain_port.len);
    if (domain_port.data == NULL)
    {
        return NJT_ERROR;
    }
    p = njt_snprintf(domain_port.data,domain_port.len,"%V:%d",&u->host,u->port);
    domain_port.len = p - domain_port.data;
	hash = njt_hash_key(domain_port.data, domain_port.len);
    shpool = usmf->domain_main->shpool;

    njt_shmtx_lock(&shpool->mutex);
	ip_node = (njt_http_dyn_upstream_domain_node_t *)njt_str_rbtree_lookup(&usmf->domain_main->sh->rbtree, &domain_port, hash);
	if(ip_node == NULL) {
        njt_pfree(cf->pool,domain_port.data);
        njt_shmtx_unlock(&shpool->mutex);
		return NJT_ERROR;
	}
   
    
    u->addrs = njt_pcalloc(cf->pool,ip_node->naddrs * sizeof(njt_addr_t));
    if(u->addrs == NULL) {
        goto err;
    }
    u->naddrs = ip_node->naddrs;
   
    for(i=0; i < ip_node->naddrs; i++)
    {
        u->addrs[i].socklen = ip_node->addrs[i].socklen;
        u->addrs[i].sockaddr = njt_pcalloc(cf->pool,u->addrs[i].socklen);
        if(u->addrs[i].sockaddr == NULL) {
            goto err;
        }
        njt_memcpy(u->addrs[i].sockaddr,ip_node->addrs[i].sockaddr,ip_node->addrs[i].socklen);
        sa = njt_pcalloc(cf->pool, u->addrs[i].socklen);
        if (sa == NULL) {
            goto err;
        }

        njt_memcpy(sa, u->addrs[i].sockaddr, u->addrs[i].socklen);

        njt_inet_set_port(sa, u->port);
        switch (sa->sa_family) {

#if (NJT_HAVE_INET6)
        case AF_INET6:
            len = NJT_INET6_ADDRSTRLEN + sizeof("[]:65536") - 1;
            break;
#endif

        default: /* AF_INET */
            len = NJT_INET_ADDRSTRLEN + sizeof(":65535") - 1;
        }

        p = njt_pnalloc(cf->pool, len);
        if (p == NULL) {
            goto err;
        }

        len = njt_sock_ntop(sa, u->addrs[i].socklen, p, len, 1);
        u->addrs[i].name.len = len;
        u->addrs[i].name.data = p;

    }
    njt_shmtx_unlock(&shpool->mutex);
     njt_log_debug(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                                  "using domain [%V] cached!", &u->host);

    return NJT_OK;
err:
    if(domain_port.data != NULL) {
        njt_pfree(cf->pool,domain_port.data);
	}
    for(i=0; i < u->naddrs; i++) {
        if(u->addrs[i].sockaddr != NULL) {
            njt_pfree(cf->pool,u->addrs[i].sockaddr);
        }
        if(u->addrs[i].name.data != NULL) {
            njt_pfree(cf->pool,u->addrs[i].name.data);
        }
    }
    if(u->naddrs != 0) {
        njt_pfree(cf->pool,u->addrs);
    }
    u->naddrs = 0;
    njt_shmtx_unlock(&shpool->mutex);
    return NJT_ERROR;		
}
njt_int_t njt_http_upstream_add_cache_domain(njt_conf_t *cf, njt_url_t *u)
{
    njt_str_t domain_port;
    u_char *p;
	uint32_t hash;
    njt_uint_t i;
    njt_http_ext_main_conf_t  *usmf;
	njt_http_dyn_upstream_domain_node_t *ip_node;
    njt_slab_pool_t *shpool;
    njt_cycle_t  *cycle = (njet_master_cycle ?njet_master_cycle:(njt_cycle_t  *)njt_cycle);
    usmf = njt_http_cycle_get_module_main_conf(cycle, njt_http_ext_module);
    if(cf->dynamic == 0 || usmf->domain_main == NULL || usmf->domain_main->shpool == NULL) {
        return NJT_ERROR;
    }
    domain_port.len = u->host.len + sizeof("65535");
    domain_port.data = njt_pcalloc(cf->pool, domain_port.len);
    if (domain_port.data == NULL)
    {
        return NJT_ERROR;
    }
    p = njt_snprintf(domain_port.data,domain_port.len,"%V:%d",&u->host,u->port);
    domain_port.len = p - domain_port.data;
	hash = njt_hash_key(domain_port.data, domain_port.len);

    shpool = usmf->domain_main->shpool;
    njt_shmtx_lock(&shpool->mutex);
    ip_node = (njt_http_dyn_upstream_domain_node_t *)njt_str_rbtree_lookup(&usmf->domain_main->sh->rbtree, &domain_port, hash);
    if(ip_node != NULL) {
        njt_log_debug(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                                  "add domain [%V] to cache,is exsited!", &u->host);
        if (domain_port.data != NULL)
        {
            njt_pfree(cf->pool, domain_port.data);
        }
        njt_shmtx_unlock(&shpool->mutex);
        return NJT_OK;
    }
    ip_node = njt_slab_calloc_locked(shpool,
                             sizeof(njt_http_dyn_upstream_domain_node_t) + domain_port.len);
    if(ip_node == NULL) {
        if (domain_port.data != NULL)
        {
            njt_pfree(cf->pool, domain_port.data);
        }
        njt_shmtx_unlock(&shpool->mutex);
        return NJT_ERROR;
    }
    ip_node->node.str.len = domain_port.len;
    ip_node->node.str.data = (u_char *) ip_node + sizeof(njt_http_dyn_upstream_domain_node_t);
    njt_memcpy(ip_node->node.str.data, domain_port.data, domain_port.len);
    ip_node->node.node.key = hash;
    ip_node->addrs = njt_slab_calloc_locked(shpool,u->naddrs * sizeof(njt_cache_addr_t));
    if(ip_node->addrs == NULL) {
        goto err;
    }
    ip_node->naddrs = u->naddrs;
    for(i = 0; i < u->naddrs; i++) {
        ip_node->addrs[i].socklen = u->addrs[i].socklen;
        ip_node->addrs[i].sockaddr = njt_slab_calloc_locked(shpool,ip_node->addrs[i].socklen);
        if(ip_node->addrs[i].sockaddr == NULL) {
           goto err; 
        }
        njt_memcpy(ip_node->addrs[i].sockaddr,u->addrs[i].sockaddr,u->addrs[i].socklen);
    }
    
    njt_rbtree_insert(&usmf->domain_main->sh->rbtree, &ip_node->node.node);
    njt_shmtx_unlock(&shpool->mutex);
    if(domain_port.data != NULL) {
        njt_pfree(cf->pool,domain_port.data);
	}
    njt_log_debug(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                                  "add domain [%V] to cache!", &u->host);
    return NJT_OK;
err:
    if(domain_port.data != NULL) {
        njt_pfree(cf->pool,domain_port.data);
	}
    for(i = 0; i < ip_node->naddrs; i++) {
        if(ip_node->addrs[i].sockaddr) {
            njt_slab_free_locked(shpool,ip_node->addrs[i].sockaddr);
        }
    }
    if(ip_node->addrs != NULL) {
        njt_slab_free_locked(shpool,ip_node->addrs);
    }
    njt_shmtx_unlock(&shpool->mutex);
    return NJT_ERROR;
	
}

njt_int_t
njt_http_upstream_init_cache_domain(njt_conf_t *cf,
                                   njt_http_upstream_srv_conf_t *us)
{
    njt_url_t u;
    njt_int_t rc;
    njt_uint_t n,i;
    njt_http_upstream_rr_peer_t *peer, **peerp;
    njt_http_upstream_rr_peers_t *peers;
    us->peer.init = njt_http_upstream_init_round_robin_peer;

    /* an upstream implicitly defined by proxy_pass, etc. */

    if (us->port == 0)
    {
        njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                      "no port in upstream \"%V\" in %s:%ui",
                      &us->host, us->file_name, us->line);
        return NJT_ERROR;
    }

    njt_memzero(&u, sizeof(njt_url_t));

    u.host = us->host;
    u.port = us->port;
    rc = njt_http_upstream_find_cache_domain(cf,&u);
    if (rc == NJT_ERROR)
    {
        if (njt_inet_resolve_host(cf->pool, &u) != NJT_OK)
        {
            if (u.err)
            {
                if (us->file_name != NULL)
                {
                    njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                                  "%s in upstream \"%V\" in %s:%ui",
                                  u.err, &us->host, us->file_name, us->line);
                }
                else
                {
                    njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                                  "%s in upstream \"%V\"",
                                  u.err, &us->host);
                }
            }

            return NJT_ERROR;
        }
        if(u.naddrs != 0) {
            njt_http_upstream_add_cache_domain(cf,&u);
        }
    }

    n = u.naddrs;

    peers = njt_pcalloc(cf->pool, sizeof(njt_http_upstream_rr_peers_t));
    if (peers == NULL)
    {
        return NJT_ERROR;
    }

    peer = njt_pcalloc(cf->pool, sizeof(njt_http_upstream_rr_peer_t) * n);
    if (peer == NULL)
    {
        return NJT_ERROR;
    }

    peers->single = (n <= 1);
    peers->number = n;
    peers->weighted = 0;
    peers->total_weight = n;
    peers->tries = n;
    peers->name = &us->host;

    peerp = &peers->peer;

    for (i = 0; i < u.naddrs; i++)
    {
        peer[i].sockaddr = u.addrs[i].sockaddr;
        peer[i].socklen = u.addrs[i].socklen;
        peer[i].name = u.addrs[i].name;
        peer[i].weight = 1;
        peer[i].effective_weight = 1;
        peer[i].rr_effective_weight = 1 * NJT_WEIGHT_POWER;
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
njt_http_upstream_destroy_cache_domain(njt_http_upstream_srv_conf_t *us)
{
    njt_url_t u;
    njt_uint_t i;
    njt_str_t domain_port;
    u_char *p;
	uint32_t hash;
    njt_http_upstream_rr_peers_t *peers;
    njt_http_upstream_rr_peer_t   *peer;
    njt_http_ext_main_conf_t  *usmf;
	njt_http_dyn_upstream_domain_node_t *ip_node;
    njt_slab_pool_t *shpool;
    njt_cycle_t  *cycle = (njet_master_cycle ?njet_master_cycle:(njt_cycle_t  *)njt_cycle);
    /* an upstream implicitly defined by proxy_pass, etc. */

    if (us->port == 0 || us->dynamic == 0)
    {
        return NJT_OK;
    }

    njt_memzero(&u, sizeof(njt_url_t));
    u.host = us->host;
    u.port = us->port;
    u.no_resolve = 1;
    //struct sockaddr  *sa;
    usmf = njt_http_cycle_get_module_main_conf(cycle, njt_http_ext_module);
    if(usmf->domain_main == NULL || usmf->domain_main->shpool == NULL) {
        return NJT_ERROR;
    }
    domain_port.len = u.host.len + sizeof("65535");
    domain_port.data = njt_pcalloc(us->pool, domain_port.len);
    if (domain_port.data == NULL)
    {
        return NJT_ERROR;
    }
    p = njt_snprintf(domain_port.data,domain_port.len,"%V:%d",&u.host,u.port);
    domain_port.len = p - domain_port.data;
    peers = us->peer.data;
    if (peers != NULL && peers->number != 0) {
        peer = peers->peer;
        if(peer != NULL && peer->name.len == domain_port.len && njt_memcmp(peer->name.data,domain_port.data,domain_port.len) == 0) {
            njt_pfree(us->pool,domain_port.data);
            return NJT_OK;
        }
	}
	hash = njt_hash_key(domain_port.data, domain_port.len);

    shpool = usmf->domain_main->shpool;
    njt_shmtx_lock(&shpool->mutex);
    ip_node = (njt_http_dyn_upstream_domain_node_t *)njt_str_rbtree_lookup(&usmf->domain_main->sh->rbtree, &domain_port, hash);
	if(ip_node != NULL) {
         njt_rbtree_delete(&usmf->domain_main->sh->rbtree, &ip_node->node.node);
         for (i = 0; i < ip_node->naddrs; i++)
         {
             if (ip_node->addrs[i].sockaddr)
             {
                 njt_slab_free_locked(shpool, ip_node->addrs[i].sockaddr);
             }
         }
         if (ip_node->addrs != NULL)
         {
             njt_slab_free_locked(shpool, ip_node->addrs);
         }
         njt_slab_free_locked(shpool, ip_node);
    }
    njt_log_debug(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                                  "del domain [%V] from cache!", &u.host);

    njt_shmtx_unlock(&shpool->mutex);
    njt_pfree(us->pool,domain_port.data);
    return NJT_OK;
}
