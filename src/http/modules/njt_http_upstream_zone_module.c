
/*
 * Copyright (C) Ruslan Ermilov
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


static char *njt_http_upstream_zone(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static njt_int_t njt_http_upstream_init_zone(njt_shm_zone_t *shm_zone,
    void *data);
static njt_http_upstream_rr_peers_t *njt_http_upstream_zone_copy_peers(
    njt_slab_pool_t *shpool, njt_http_upstream_srv_conf_t *uscf);
static njt_http_upstream_rr_peer_t *njt_http_upstream_zone_copy_peer(
    njt_http_upstream_rr_peers_t *peers, njt_http_upstream_rr_peer_t *src);
 static njt_int_t
njt_http_upstream_merge_zone(njt_shm_zone_t *shm_zone, void *data);
static void
njt_http_upstream_zone_inherit_peer_status (njt_http_upstream_rr_peers_t *peers,
                njt_http_upstream_rr_peers_t *src_peers);

static njt_command_t  njt_http_upstream_zone_commands[] = {

    { njt_string("zone"),
      NJT_HTTP_UPS_CONF|NJT_CONF_TAKE12,
      njt_http_upstream_zone,
      0,
      0,
      NULL },

      njt_null_command
};


static njt_http_module_t  njt_http_upstream_zone_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


njt_module_t  njt_http_upstream_zone_module = {
    NJT_MODULE_V1,
    &njt_http_upstream_zone_module_ctx,    /* module context */
    njt_http_upstream_zone_commands,       /* module directives */
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


static char *
njt_http_upstream_zone(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    ssize_t                         size;
    njt_str_t                      *value;
    njt_http_upstream_srv_conf_t   *uscf;
    njt_http_upstream_main_conf_t  *umcf;

    uscf = njt_http_conf_get_module_srv_conf(cf, njt_http_upstream_module);
    umcf = njt_http_conf_get_module_main_conf(cf, njt_http_upstream_module);

    value = cf->args->elts;

    if (!value[1].len) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid zone name \"%V\"", &value[1]);
        return NJT_CONF_ERROR;
    }

    if (cf->args->nelts == 3) {
        size = njt_parse_size(&value[2]);

        if (size == NJT_ERROR) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid zone size \"%V\"", &value[2]);
            return NJT_CONF_ERROR;
        }

        if (size < (ssize_t) (8 * njt_pagesize)) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "zone \"%V\" is too small", &value[1]);
            return NJT_CONF_ERROR;
        }

    } else {
        size = 0;
    }

    uscf->shm_zone = njt_shared_memory_add(cf, &value[1], size,
                                           &njt_http_upstream_module);
    if (uscf->shm_zone == NULL) {
        return NJT_CONF_ERROR;
    }

    uscf->shm_zone->init = njt_http_upstream_init_zone;
    uscf->shm_zone->merge = njt_http_upstream_merge_zone;
    uscf->shm_zone->data = umcf;

    uscf->shm_zone->noreuse = 1;

    return NJT_CONF_OK;
}
static njt_int_t
njt_http_upstream_merge_zone(njt_shm_zone_t *shm_zone, void *data)
{
         njt_http_upstream_srv_conf_t   *uscf, **uscfp,*old_uscf,**old_uscfp;
         njt_http_upstream_main_conf_t  *umcf,*old_umcf;
         njt_uint_t                      i;
         njt_http_upstream_rr_peers_t   *peers;
         umcf = shm_zone->data;
          uscfp = umcf->upstreams.elts;
           if(data && shm_zone->shm.exists == 0) {
                old_umcf = data;
                old_uscfp = old_umcf->upstreams.elts;
                if(umcf->upstreams.nelts == old_umcf->upstreams.nelts) {
                        for (i = 0; i < umcf->upstreams.nelts; i++) {
                                uscf = uscfp[i];
                                if(uscf->hc_type == 2) {
                                        old_uscf = old_uscfp[i];
                                        if (uscf->shm_zone->shm.name.len != old_uscf->shm_zone->shm.name.len 
					|| njt_strncmp(uscf->shm_zone->shm.name.data,old_uscf->shm_zone->shm.name.data,uscf->shm_zone->shm.name.len) != 0 ) 					    {
                                                continue;
                                        }
                                        peers = old_uscf->peer.data;
                                        njt_http_upstream_zone_inherit_peer_status(uscf->peer.data,peers);
                                        uscf->reload = 1;
                                }
                        }
                }
     }
        return NJT_OK;
}

static njt_int_t
njt_http_upstream_init_zone(njt_shm_zone_t *shm_zone, void *data)
{
    size_t                          len;
    njt_uint_t                      i;
    njt_slab_pool_t                *shpool;
    njt_http_upstream_rr_peers_t   *peers, **peersp;
    njt_http_upstream_srv_conf_t   *uscf, **uscfp;
    njt_http_upstream_main_conf_t  *umcf;

    shpool = (njt_slab_pool_t *) shm_zone->shm.addr;
    umcf = shm_zone->data;
    uscfp = umcf->upstreams.elts;

    if (shm_zone->shm.exists) {
        peers = shpool->data;

        for (i = 0; i < umcf->upstreams.nelts; i++) {
            uscf = uscfp[i];

            if (uscf->shm_zone != shm_zone) {
                continue;
            }

            uscf->peer.data = peers;
            peers = peers->zone_next;
        }

        return NJT_OK;
    }

    len = sizeof(" in upstream zone \"\"") + shm_zone->shm.name.len;

    shpool->log_ctx = njt_slab_alloc(shpool, len);
    if (shpool->log_ctx == NULL) {
        return NJT_ERROR;
    }

    njt_sprintf(shpool->log_ctx, " in upstream zone \"%V\"%Z",
                &shm_zone->shm.name);


    /* copy peers to shared memory */

    peersp = (njt_http_upstream_rr_peers_t **) (void *) &shpool->data;

    for (i = 0; i < umcf->upstreams.nelts; i++) {
        uscf = uscfp[i];

        if (uscf->shm_zone != shm_zone) {
            continue;
        }

        peers = njt_http_upstream_zone_copy_peers(shpool, uscf);
        if (peers == NULL) {
            return NJT_ERROR;
        }

        *peersp = peers;
        peersp = &peers->zone_next;
    }

    return NJT_OK;
}


static njt_http_upstream_rr_peers_t *
njt_http_upstream_zone_copy_peers(njt_slab_pool_t *shpool,
    njt_http_upstream_srv_conf_t *uscf)
{
    njt_str_t                     *name;
    njt_http_upstream_rr_peer_t   *peer, **peerp;
    njt_http_upstream_rr_peers_t  *peers, *backup;

    peers = njt_slab_alloc(shpool, sizeof(njt_http_upstream_rr_peers_t));
    if (peers == NULL) {
        return NULL;
    }

    njt_memcpy(peers, uscf->peer.data, sizeof(njt_http_upstream_rr_peers_t));

    name = njt_slab_alloc(shpool, sizeof(njt_str_t));
    if (name == NULL) {
        return NULL;
    }

    name->data = njt_slab_alloc(shpool, peers->name->len);
    if (name->data == NULL) {
        return NULL;
    }

    njt_memcpy(name->data, peers->name->data, peers->name->len);
    name->len = peers->name->len;

    peers->name = name;

    peers->shpool = shpool;

    for (peerp = &peers->peer; *peerp; peerp = &peer->next) {
        /* pool is unlocked */
        peer = njt_http_upstream_zone_copy_peer(peers, *peerp);
        if (peer == NULL) {
            return NULL;
        }
	
	if(uscf->mandatory == 1 && uscf->persistent == 0) {
	  peer->hc_down = 2;
	}
        *peerp = peer;
    }
    //by zyg
    //if (peers->next == NULL) {
      //  goto done;
    //}

    backup = njt_slab_alloc(shpool, sizeof(njt_http_upstream_rr_peers_t));
    if (backup == NULL) {
        return NULL;
    }
    if(peers->next != NULL) {
    	njt_memcpy(backup, peers->next, sizeof(njt_http_upstream_rr_peers_t));
    }

    backup->name = name;

    backup->shpool = shpool;

    for (peerp = &backup->peer; *peerp; peerp = &peer->next) {
        /* pool is unlocked */
        peer = njt_http_upstream_zone_copy_peer(backup, *peerp);
        if (peer == NULL) {
            return NULL;
        }
	 if(uscf->mandatory == 1 && uscf->persistent == 0) {
          peer->hc_down = 2;
        }

        *peerp = peer;
    }

    peers->next = backup;

//done:

    uscf->peer.data = peers;

    return peers;
}


static njt_http_upstream_rr_peer_t *
njt_http_upstream_zone_copy_peer(njt_http_upstream_rr_peers_t *peers,
    njt_http_upstream_rr_peer_t *src)
{
    njt_slab_pool_t              *pool;
    njt_http_upstream_rr_peer_t  *dst;

    pool = peers->shpool;

    dst = njt_slab_calloc_locked(pool, sizeof(njt_http_upstream_rr_peer_t));
    if (dst == NULL) {
        return NULL;
    }

    if (src) {
        njt_memcpy(dst, src, sizeof(njt_http_upstream_rr_peer_t));
        dst->sockaddr = NULL;
        dst->name.data = NULL;
        dst->server.data = NULL;
    }

    dst->sockaddr = njt_slab_calloc_locked(pool, sizeof(njt_sockaddr_t));
    if (dst->sockaddr == NULL) {
        goto failed;
    }

    dst->name.data = njt_slab_calloc_locked(pool, NJT_SOCKADDR_STRLEN);
    if (dst->name.data == NULL) {
        goto failed;
    }

    if (src) {
        njt_memcpy(dst->sockaddr, src->sockaddr, src->socklen);
        njt_memcpy(dst->name.data, src->name.data, src->name.len);

        dst->server.data = njt_slab_alloc_locked(pool, src->server.len);
        if (dst->server.data == NULL) {
            goto failed;
        }

        njt_memcpy(dst->server.data, src->server.data, src->server.len);
    }

    return dst;

failed:

    if (dst->server.data) {
        njt_slab_free_locked(pool, dst->server.data);
    }

    if (dst->name.data) {
        njt_slab_free_locked(pool, dst->name.data);
    }

    if (dst->sockaddr) {
        njt_slab_free_locked(pool, dst->sockaddr);
    }

    njt_slab_free_locked(pool, dst);

    return NULL;
}
static void
njt_http_upstream_zone_inherit_peer_status (njt_http_upstream_rr_peers_t *peers,
		njt_http_upstream_rr_peers_t *src_peers) {

	njt_http_upstream_rr_peer_t    *peer,*old_peer;

	if(src_peers == NULL)
		return;
	for (peer = peers->peer; peer;peer = peer->next) {
		if(peer->parent_id == -1) {
			for (old_peer = src_peers->peer; old_peer;old_peer = old_peer->next) {
				if(peer->server.len == old_peer->server.len && njt_strncmp(peer->server.data,old_peer->server.data,peer->server.len
							) == 0){
					peer->hc_down = old_peer->hc_down;
					break;
				}
			}
		}

	}
	if(peers->next != NULL && src_peers->next != NULL) {
	  njt_http_upstream_zone_inherit_peer_status(peers->next,src_peers->next);
	}
	
}
