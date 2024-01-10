
/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_http_upstream.h>

#include "njt_gossip.h"
#include "msgpuck.h"

#define GOSSIP_APP_APP_STICKY 	0xB118DB6F
#define APP_STICKY_SYNC_INT  	2000
#define APP_STICKY_DATA_CNT  	4
#define APP_STICKY_MAX_ZONE  	30
#define APP_STICKY_EXPIRE_INT 	600


typedef struct
{
    u_char					color;
    u_char 					len;
	//todo: optimize ,only store addr_text ptr here, to save space
	njt_str_t 				up_name;	//i.e. 127.0.0.1:8000
	njt_msec_t 				last_seen;
	njt_queue_t            	queue;
    u_char 					data[1];
} njt_app_sticky_rb_node_t;

typedef struct
{
    njt_rbtree_t 			rbtree;
    njt_rbtree_node_t 		sentinel;
	njt_queue_t          	queue;
} njt_app_sticky_shctx_t;

typedef struct {
	njt_app_sticky_shctx_t  *sh;
    njt_slab_pool_t         *shpool;
	njt_msec_t 				ttl;		//default 10mins ,600
	njt_log_t 				*log;
	void					*data;
} njt_app_sticky_ctx_t;


typedef struct {
    njt_str_t 				var;		//header name , or cookie_name
	njt_msec_t 				ttl;		//default 10mins ,600
	njt_str_t 				zone_name;
	njt_app_sticky_ctx_t 	*ctx;
	unsigned  				is_cookie:1;
} njt_app_sticky_srv_conf_t;

typedef struct {
	njt_str_t  					up_name;
	njt_app_sticky_ctx_t 		*ctx;
	njt_http_request_t 			*request;
	njt_int_t 					(*old_proc)(njt_http_request_t *r);
	njt_app_sticky_srv_conf_t 	*srv_conf;
} njt_app_sticky_req_ctx_t;

typedef struct {
	/* important: the round robin data must be first */
    njt_http_upstream_rr_peer_data_t 	rrp;
	njt_str_t 							key;			//cookie name ,header or query params and so on
	njt_app_sticky_srv_conf_t 			*srv_conf;
	njt_http_request_t 					*request;
	njt_int_t 							(*old_proc)(njt_http_request_t *r);
} njt_app_sticky_peer_data_t;


static njt_array_t *sticky_ctxes = NULL;


static njt_int_t njt_app_sticky_update_node(njt_app_sticky_ctx_t *ctx, njt_str_t key, njt_str_t value, 	njt_msec_t ttl);

static void app_sticky_sync_data( njt_app_sticky_ctx_t* ctx, njt_str_t* zone, njt_str_t* target, njt_str_t* target_pid, njt_msec_t interval);

static njt_int_t      njt_app_sticky_init_worker(njt_cycle_t *cycle);

static  void*  njt_app_sticky_create_srv_conf (njt_conf_t *cf);
//static char *njt_app_sticky_merge_srv_conf(njt_conf_t *cf, void *parent,void *child);

static njt_int_t njt_app_sticky_init_peer(njt_http_request_t *r,
    njt_http_upstream_srv_conf_t *us);

static njt_int_t njt_app_sticky_get_peer(njt_peer_connection_t *pc, void *data);
    
static char *njt_app_sticky_cmd(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);

static njt_table_elt_t* njt_app_sticky_search_header(njt_http_request_t *r, u_char *name, size_t len,int is_proxy) ;

static njt_rbtree_node_t *
njt_app_sticky_lookup(njt_rbtree_t *rbtree, njt_str_t *key, uint32_t hash);

static njt_int_t njt_app_sticky_init_zone(njt_shm_zone_t *shm_zone, void *data);

static njt_int_t
njt_app_sticky_header_filter(njt_http_request_t *r);



static njt_http_module_t njt_app_sticky_module_ctx = {
    NULL, /* preconfiguration */
    NULL, //njt_app_sticky_reg_filter, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    njt_app_sticky_create_srv_conf, /* create server configuration */
    NULL, // njt_app_sticky_merge_srv_conf,  /* merge server configuration */ the directive is in upstream, no need for merge

    NULL, /* create location configuration */
    NULL   /* merge location configuration */
};
static njt_command_t njt_app_sticky_commands[] = {
      { njt_string("app_sticky"),
      NJT_HTTP_UPS_CONF|NJT_CONF_TAKE23,
      njt_app_sticky_cmd,
      0,
      0,
      NULL }
    ,njt_null_command /* command termination */
};

njt_module_t  njt_app_sticky_module = {
    NJT_MODULE_V1,
    &njt_app_sticky_module_ctx, /* module context */
    njt_app_sticky_commands, /* module directives */
    NJT_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    njt_app_sticky_init_worker,                /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};
static njt_int_t njt_app_sticky_init_upstream(njt_conf_t *cf,
    njt_http_upstream_srv_conf_t *us) {
    if (njt_http_upstream_init_round_robin(cf, us) != NJT_OK) {
        return NJT_ERROR;
    }
    
    us->peer.init = njt_app_sticky_init_peer;
    
    return NJT_OK;

};
static njt_int_t njt_app_sticky_init_peer(njt_http_request_t *r,
    njt_http_upstream_srv_conf_t *us) {
	njt_app_sticky_peer_data_t *aspd;

	njt_app_sticky_srv_conf_t *ascf = njt_http_conf_upstream_srv_conf(us, njt_app_sticky_module);

	aspd = njt_palloc(r->pool, sizeof(njt_app_sticky_peer_data_t));

	if (aspd==NULL) {
		njt_log_error(NJT_LOG_ERR,r->connection->log,0,"init app_sticky failed,malloc failure");
		return NJT_ERROR;
	}
	aspd->srv_conf = ascf;
	aspd->request = r;
	
	r->upstream->peer.data = &aspd->rrp;

    if (njt_http_upstream_init_round_robin_peer(r, us) != NJT_OK) {
        return NJT_ERROR;
    }

	if(ascf != NULL){
		if (ascf->is_cookie ==0) {
			njt_table_elt_t* header_val=njt_app_sticky_search_header(r,ascf->var.data,ascf->var.len,0);
			if (header_val !=NULL ) {
				aspd->key.data = njt_pstrdup(r->pool, &header_val->value);
				aspd->key.len =header_val->value.len;
				njt_log_error(NJT_LOG_DEBUG,r->connection->log,0, "found header:\"%V :%V\"  in request",&ascf->var, &aspd->key);
			} else aspd->key.len =0;
		} else {
			njt_str_t cookie_value;
			if (njt_http_parse_multi_header_lines(r, r->headers_in.cookie, &ascf->var, &cookie_value) 
				!= NULL) {
				// warn: aspd->key= &cookie_value; wrong usage
				aspd->key.data = njt_pstrdup(r->pool, &cookie_value);
				aspd->key.len =cookie_value.len;
				njt_log_error(NJT_LOG_DEBUG,r->connection->log,0, "found cookie:\"%V :%V\"  in request",
					&ascf->var, &aspd->key);
			} else aspd->key.len =0;

		}
	}
    r->upstream->peer.get = njt_app_sticky_get_peer;
	aspd->old_proc = r->upstream->process_header;

    return NJT_OK;
}
static njt_table_elt_t* njt_app_sticky_search_header(njt_http_request_t *r, u_char *name, size_t len, int is_proxy) {
    njt_list_part_t            *part;
    njt_table_elt_t            *h;
    njt_uint_t                  i;
	if (is_proxy ==0 )
    	part = &r->headers_in.headers.part;
    else 
		part = &r->upstream->headers_in.headers.part;

    h = part->elts;
    for (i = 0; /* void */ ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                /* The last part, search is done. */
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        /*
        Just compare the lengths and then the names case insensitively.
        */
        if (len != h[i].key.len || njt_strcasecmp(name, h[i].key.data) != 0) {
            /* This header doesn't match. */
            continue;
        }

        return &h[i];
    }
    return NULL;
}
static njt_int_t njt_app_sticky_get_peer(njt_peer_connection_t *pc, void *data){
	njt_http_upstream_rr_peer_t   *peer;
    njt_http_upstream_rr_peers_t  *peers;
	njt_rbtree_node_t *node;
	njt_app_sticky_rb_node_t *lc;
	njt_app_sticky_req_ctx_t *req_ctx;

	njt_uint_t i;
	njt_app_sticky_ctx_t *ctx = NULL;
	njt_app_sticky_peer_data_t * aspd=(njt_app_sticky_peer_data_t*)data;

	if(aspd == NULL){
		njt_log_error(NJT_LOG_DEBUG, aspd->request->connection->log, 0, "no app_sticky key, use rr");
		goto use_rr;
	}

	ctx = aspd->srv_conf->ctx;

	if (aspd->key.len ==0 )  {
		njt_log_error(NJT_LOG_DEBUG, aspd->request->connection->log, 0, "no app_sticky key, use rr");
		goto use_rr;
	}

	uint32_t hash = njt_crc32_short(aspd->key.data, aspd->key.len);
    njt_shmtx_lock(&ctx->shpool->mutex);
    node = njt_app_sticky_lookup(&ctx->sh->rbtree, &aspd->key, hash);
    njt_shmtx_unlock(&ctx->shpool->mutex);
	if (node==NULL) {
		njt_log_error(NJT_LOG_DEBUG, aspd->request->connection->log, 0, "no peer found for %V, use rr",&aspd->key);
		goto use_rr;
	}

	lc = (njt_app_sticky_rb_node_t *)&node->color;
	peers =  aspd->rrp.peers;
    njt_http_upstream_rr_peers_wlock(peers);

	for (peer = peers->peer, i = 0;
         peer;
         peer = peer->next, i++)
    {
		if ( (lc->up_name.len == peer->name.len)  &&  memcmp(lc->up_name.data,peer->name.data,lc->up_name.len)==0 ) {
			if (!peer->down) {
				//todo: other logic like max failure, etc.
				pc->sockaddr = peer->sockaddr;
    			pc->socklen = peer->socklen;
    			pc->name = &peer->name;

				req_ctx=(njt_app_sticky_req_ctx_t *)njt_palloc(aspd->request->pool,sizeof (njt_app_sticky_req_ctx_t));
				req_ctx->up_name.data=njt_pstrdup(aspd->request->pool,&peer->name);
				req_ctx->up_name.len = peer->name.len;

				req_ctx->ctx = ctx;
				req_ctx->request = aspd->request;

				req_ctx->old_proc = aspd->old_proc;
				
				req_ctx->request->upstream->process_header = njt_app_sticky_header_filter;

				req_ctx->srv_conf = aspd->srv_conf;

				njt_http_set_ctx(aspd->request,req_ctx,njt_app_sticky_module);

				njt_log_error(NJT_LOG_DEBUG, aspd->request->connection->log, 0, "app_sticky choose cached upsteam:%V",
					&peer->name);
				
				//important: sync with rrp, so it can be freed properly
				aspd->rrp.current = peer;

				njt_http_upstream_rr_peers_unlock(peers);

				return NJT_OK;
			} else {
    			njt_shmtx_lock(&ctx->shpool->mutex);
				njt_rbtree_delete(&ctx->sh->rbtree, node);
				//todo: do we need remove
				njt_queue_remove(&lc->queue);

				njt_slab_free_locked(ctx->shpool,lc->up_name.data);
				njt_slab_free_locked(ctx->shpool, node);

    			njt_shmtx_unlock(&ctx->shpool->mutex);
				njt_log_error(NJT_LOG_DEBUG, aspd->request->connection->log, 0, "cached upsteam:%V is down, fallback to rr",	&peer->name);
				goto use_rr;
			}
		}
	}
	njt_http_upstream_rr_peers_unlock(peers);

	use_rr:
	i= njt_http_upstream_get_round_robin_peer(pc, data);
	
	req_ctx=(njt_app_sticky_req_ctx_t *)njt_palloc(aspd->request->pool,sizeof (njt_app_sticky_req_ctx_t));

	req_ctx->up_name.data=njt_pstrdup(aspd->request->pool,&aspd->rrp.current->name);
	req_ctx->up_name.len = aspd->rrp.current->name.len;
	req_ctx->ctx = ctx;
	req_ctx->request = aspd->request;

	req_ctx->old_proc = aspd->old_proc;
	req_ctx->request->upstream->process_header = njt_app_sticky_header_filter;
	req_ctx->srv_conf = aspd->srv_conf;

	njt_http_set_ctx(aspd->request,req_ctx,njt_app_sticky_module);

	njt_log_error(NJT_LOG_DEBUG, aspd->request->connection->log, 0, "rr choose upsteam:%V",&aspd->rrp.current->name);
		
	return i;
}
static char *njt_app_sticky_cmd(njt_conf_t *cf, njt_command_t *cmd,
    void *conf) {
	njt_http_upstream_srv_conf_t  	*uscf;
	njt_shm_zone_t          		*shm_zone;
    njt_str_t 						*value = cf->args->elts;
    njt_str_t 						shm_name, shm_size, key_name;
	njt_int_t 						size;
	njt_app_sticky_srv_conf_t 		*ascf;
	njt_str_t						tmp_str;
	njt_msec_t						tmp_ttl;

    uscf = njt_http_conf_get_module_srv_conf(cf, njt_http_upstream_module);
	if(uscf == NULL){
		njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                           " app sticky has not updatem module");
		return NJT_CONF_ERROR;
	}

    if (uscf->peer.init_upstream) {
        njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                           "load balancing method redefined");
		return NJT_CONF_ERROR;
    }

    uscf->peer.init_upstream = njt_app_sticky_init_upstream;

    uscf->flags = NJT_HTTP_UPSTREAM_CREATE
                  |NJT_HTTP_UPSTREAM_WEIGHT
                  |NJT_HTTP_UPSTREAM_MAX_CONNS
                  |NJT_HTTP_UPSTREAM_MAX_FAILS
                  |NJT_HTTP_UPSTREAM_FAIL_TIMEOUT
                  |NJT_HTTP_UPSTREAM_DOWN
                  |NJT_HTTP_UPSTREAM_BACKUP;
	
	if (njt_strncmp(value[1].data, "zone=", 5) == 0) {
            u_char *p;
            shm_name.data = value[1].data + 5;
            p = (u_char *) njt_strchr(shm_name.data, ':');
            if (p == NULL) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[1]);
                return NJT_CONF_ERROR;
            }
            shm_name.len = p - shm_name.data;
            shm_size.data = p + 1;
            shm_size.len = value[1].data + value[1].len - shm_size.data;
            size = njt_parse_size(&shm_size);
            if (size == NJT_ERROR) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[1]);
                return NJT_CONF_ERROR;
            }
    } else {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                   "invalid app_sticky param \"%V\", format is zone={zone_name}:{size}M", &value[1]);
            return NJT_CONF_ERROR;
    }
	
	ascf = njt_http_conf_upstream_srv_conf(uscf, njt_app_sticky_module);
	if(ascf == NULL){
		njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                   "app_sticky has no app_sticky_module");
        return NJT_CONF_ERROR;
	}

	if (njt_strncmp(value[2].data, "cookie:", 7) == 0) {
		ascf->is_cookie =1;
		key_name.data= value[2].data+7;
		key_name.len= value[2].len-7;
	} else if (njt_strncmp(value[2].data, "header:", 7) == 0) {
		ascf->is_cookie =0;
		key_name.data= value[2].data+7;
		key_name.len= value[2].len-7;
	}else {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid key \"%V\", must be prefixed with header: or cookie:", &value[2]);
		return NJT_CONF_ERROR;
	}

	ascf->ttl = APP_STICKY_EXPIRE_INT * 1000;
	if(cf->args->nelts == 4){
		if (njt_strncmp(value[3].data, "ttl:", 4) == 0) {
			tmp_str.data = value[3].data + 4;
			tmp_str.len = value[3].len - 4;
			tmp_ttl = njt_parse_time(&tmp_str, 0);
			if (tmp_ttl == (njt_msec_t) NJT_ERROR || tmp_ttl < 1000) {
				njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
					" app sticky, invalid ttl:\"%V\" or should >= 1s", &tmp_str);
				return NJT_CONF_ERROR;
			}

			ascf->ttl = tmp_ttl;
		}else {
			njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
									" invalid key\"%V\", must be ttl", &value[3]);
			return NJT_CONF_ERROR;
		}
	}

	ascf->zone_name.data = njt_pnalloc(cf->pool, shm_name.len);
	njt_memcpy(ascf->zone_name.data, shm_name.data, shm_name.len);
	ascf->zone_name.len = shm_name.len;

	ascf->var.data = njt_pnalloc(cf->pool, key_name.len+1);
	njt_memzero(ascf->var.data,key_name.len+1);
	ascf->var.len =  key_name.len;
	memcpy(ascf->var.data, key_name.data,key_name.len);

	ascf->ctx = njt_pcalloc(cf->cycle->pool, sizeof(njt_app_sticky_ctx_t));
	ascf->ctx->ttl = ascf->ttl;
	ascf->ctx->log = &cf->cycle->new_log;
	ascf->ctx->data =  ascf;

	shm_zone = njt_shared_memory_add(cf, &shm_name , size,&njt_app_sticky_module);
    if (shm_zone == NULL) {
        return NJT_CONF_ERROR;
    }

    if (shm_zone->data) {
        ascf->ctx = shm_zone->data;

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "%V \"%V\" is already bound to other, please use a new zone",
                           &cmd->name, &shm_name);
        return NJT_CONF_ERROR;
    }


    shm_zone->init = njt_app_sticky_init_zone;
    shm_zone->data = ascf->ctx;

    return NJT_CONF_OK;
}

static void
njt_app_sticky_rbtree_insert_value(njt_rbtree_node_t *temp,njt_rbtree_node_t *node, njt_rbtree_node_t *sentinel)
{
    njt_rbtree_node_t **p;
    njt_app_sticky_rb_node_t *lcn, *lcnt;
    for (;;)
    {
        if (node->key < temp->key)
        {

            p = &temp->left;
        }
        else if (node->key > temp->key)
        {

            p = &temp->right;
        }
    	else 
		{ /* node->key == temp->key */
            lcn = (njt_app_sticky_rb_node_t *)&node->color;
            lcnt = ( njt_app_sticky_rb_node_t*)&temp->color;

            p = (njt_memn2cmp(lcn->data, lcnt->data, lcn->len, lcnt->len) < 0)
                    ? &temp->left
                    : &temp->right;
        }

        if (*p == sentinel)
        {
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

static njt_rbtree_node_t *
njt_app_sticky_lookup(njt_rbtree_t *rbtree, njt_str_t *key, uint32_t hash)
{
    njt_int_t rc;
    njt_rbtree_node_t *node, *sentinel;
    njt_app_sticky_rb_node_t *lcn;

    node = rbtree->root;
    sentinel = rbtree->sentinel;
	
	while (node != sentinel)
    {

        if (hash < node->key)
        {
            node = node->left;
            continue;
        }

        if (hash > node->key)
        {
            node = node->right;
            continue;
        }
		lcn = (njt_app_sticky_rb_node_t *)&node->color;
        rc = njt_memn2cmp(key->data, lcn->data, key->len, (size_t)lcn->len);

        if (rc == 0)
        {
            return node;
        }

        node = (rc < 0) ? node->left : node->right;
    }
    return NULL;
}

static njt_int_t njt_app_sticky_init_zone(njt_shm_zone_t *shm_zone, void *data)
{
	njt_app_sticky_ctx_t  *ctx, *octx = data;
    size_t                      len;

    ctx = shm_zone->data;
    if (octx) {
        //todo: check old shm size
        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;
        return NJT_OK;
    }
	ctx->shpool = (njt_slab_pool_t *) shm_zone->shm.addr;
    if (shm_zone->shm.exists) {
        ctx->sh = ctx->shpool->data;
        return NJT_OK;
    }
	ctx->sh = njt_slab_alloc(ctx->shpool, sizeof(njt_app_sticky_shctx_t));
    if (ctx->sh == NULL) {
        return NJT_ERROR;
    }

    ctx->shpool->data = ctx->sh;

    njt_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    njt_app_sticky_rbtree_insert_value);

	njt_queue_init(&ctx->sh->queue);

    len = sizeof(" in app_sticky zone \"\"") + shm_zone->shm.name.len;
    ctx->shpool->log_ctx = njt_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return NJT_ERROR;
    }
	njt_sprintf(ctx->shpool->log_ctx, " in app_sticky zone \"%V\"%Z",
                &shm_zone->shm.name);
    return NJT_OK;
}

static  void*  njt_app_sticky_create_srv_conf (njt_conf_t *cf)
{
	njt_app_sticky_srv_conf_t *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_app_sticky_srv_conf_t));
    if (conf == NULL)
    {
        return NULL;
    }
    conf->ttl = APP_STICKY_EXPIRE_INT * 1000;
    conf->zone_name.len = 0;
	conf->var.len = 0;

    return conf;
}
/*
static char *njt_app_sticky_merge_srv_conf(njt_conf_t *cf, void *parent,void *child)
{
    njt_app_sticky_srv_conf_t *p= (njt_app_sticky_srv_conf_t *)parent;
    njt_app_sticky_srv_conf_t *c= (njt_app_sticky_srv_conf_t *)child;
	njt_log_error(NJT_LOG_ERR,cf->log,0,"appsticky merge:%p,%p,%p",parent,child,c->ctx);

    if (c->zone_name.len>0) {
            p->zone_name.len=c->zone_name.len;
			p->zone_name.data=njt_pstrdup(cf->pool, &c->zone_name);
			memcpy(p->zone_name.data, c->zone_name.data,c->zone_name.len);
	}
    if (c->var.len>0) {
            p->var.len=c->var.len+1;
			p->var.data=njt_pstrdup(cf->pool, &c->var);
			p->var.data[p->var.len]='\0';
			memcpy(p->var.data, c->var.data,c->var.len);
	}
    p->ttl = c->ttl ;
    if (c->ctx) p->ctx = c->ctx;

    return NJT_OK;
}
*/
static void app_sticky_expire_node(njt_app_sticky_ctx_t* ctx, njt_msec_t before_stamp)
{
	njt_queue_t 					*q;
	njt_rbtree_node_t 				*node;
	njt_app_sticky_rb_node_t 		*lr;
	njt_shmtx_lock(&ctx->shpool->mutex);

	while  (!njt_queue_empty(&ctx->sh->queue) ) {
	 	q = njt_queue_last(&ctx->sh->queue);
        lr = njt_queue_data(q, njt_app_sticky_rb_node_t, queue);
		if (lr->last_seen > before_stamp)  break;
		
		njt_queue_remove(q);

        node = (njt_rbtree_node_t *)
                   ((u_char *) lr - offsetof(njt_rbtree_node_t, color));
		njt_log_error(NJT_LOG_DEBUG, ctx->log,0,
			"app sticky clean expire session, up_name:%V  last_seen:%d",
			&lr->up_name, lr->last_seen);
        njt_rbtree_delete(&ctx->sh->rbtree, node);
        njt_slab_free_locked(ctx->shpool, node);
	}
   	njt_shmtx_unlock(&ctx->shpool->mutex);
}

static void app_sticky_sync_data( njt_app_sticky_ctx_t* ctx, njt_str_t* zone, njt_str_t* target, njt_str_t* target_pid, njt_msec_t interval)
{
	size_t 					buf_size=0;
	char 					*buf=NULL, *head=NULL;
	uint32_t 				msg_cnt =0;	
	njt_queue_t 			*q;
	size_t        			tmp_zone_len;
	njt_msec_t  			checkpoint_stamp = njt_current_msec;

    njt_shmtx_lock(&ctx->shpool->mutex);
	if (njt_queue_empty(&ctx->sh->queue) ) {
    	njt_shmtx_unlock(&ctx->shpool->mutex);
		 return;
	}
	for (q = njt_queue_head(&ctx->sh->queue);
     			q != njt_queue_sentinel(&ctx->sh->queue);
     		q = njt_queue_next(q))
	{
		njt_app_sticky_rb_node_t * lr;
		lr = njt_queue_data(q, njt_app_sticky_rb_node_t, queue);	
		njt_msec_t ttl = checkpoint_stamp - lr->last_seen;

		//todo: 
		if ( ttl > interval) break;
		//todo: check tail for remove
		if (head == NULL ) {
			int pack_cnt=1;
			char *pack_head;
			buf=njt_gossip_app_get_msg_buf(GOSSIP_APP_APP_STICKY, *target, *target_pid, &buf_size);
			if (buf_size<=0 || buf ==NULL) {
				njt_log_error(NJT_LOG_ERR,ctx->log,0,"apply buffer failed");
    			njt_shmtx_unlock(&ctx->shpool->mutex);
				return;
			}

			pack_head=buf;
			head= mp_encode_array(pack_head,pack_cnt);
		} 
		msg_cnt++;
		int arr_cnt = APP_STICKY_DATA_CNT;
		char *tail = head;
		tail= mp_encode_array(tail,arr_cnt);

		tail = mp_encode_str(tail,(char *)lr->data,lr->len);	//header value	//max 255
		
		if(lr->up_name.len > 255){
			tail = mp_encode_str(tail,(char *)lr->up_name.data,255);	//backend name like 127.0.0.1:8080
		}else{
			tail = mp_encode_str(tail,(char *)lr->up_name.data,lr->up_name.len);	//backend name like 127.0.0.1:8080
		}
		
		tmp_zone_len = zone->len;
		if(zone->len > APP_STICKY_MAX_ZONE){
			tmp_zone_len = APP_STICKY_MAX_ZONE;
		}
		tail= mp_encode_str(tail,(char *)zone->data, tmp_zone_len);	//zone name
		tail= mp_encode_uint(tail, njt_current_msec - lr->last_seen);	
 
		// njt_str_t tmpkey;
		// tmpkey.data = lr->data;
		// tmpkey.len = lr->len;
		// njt_log_error(NJT_LOG_DEBUG, ctx->log, 0," send data msg_index:%d key:%V val:%V zone:%V ttl:%M",
		// 	msg_cnt, &tmpkey, &lr->up_name, zone, njt_current_msec - lr->last_seen);


		buf_size  = buf_size - (tail - head);
		head = tail;
		if (msg_cnt == 15 || buf_size < 255 + 20 + APP_STICKY_MAX_ZONE + 10) {
			njt_gossip_app_close_msg_buf(tail);
			//if (msg_cnt>=10) {
				mp_encode_array(buf, msg_cnt);
				njt_log_error(NJT_LOG_DEBUG,ctx->log,0," large sync pack:%d",msg_cnt);
				njt_gossip_send_app_msg_buf();
				msg_cnt= 0;
				head=NULL;
			//}
		}
	}
	njt_shmtx_unlock(&ctx->shpool->mutex);
	if (head !=NULL) {
		njt_gossip_app_close_msg_buf(head);
	}
	if (msg_cnt >0) {
		mp_encode_array(buf,msg_cnt);
		njt_log_error(NJT_LOG_DEBUG,ctx->log,0,"sync pack:%d",msg_cnt);
		njt_gossip_send_app_msg_buf();
	}
	app_sticky_expire_node(ctx, checkpoint_stamp - ctx->ttl);
}
static void app_sticky_sync(njt_event_t *ev)
{
	njt_app_sticky_srv_conf_t		**zone_ctxes = NULL;
	njt_uint_t                      i;

	// njt_app_sticky_ctx_t* ctx=(njt_app_sticky_ctx_t*) ev->data;
	if (!ev->timedout)  return;

	if ( !njt_exiting) {
		njt_add_timer(ev,APP_STICKY_SYNC_INT);	
		njt_str_t target = njt_string("all");
		njt_str_t target_pid = njt_string("0");
		// app_sticky_sync_data(ctx, &target, &target_pid, APP_STICKY_SYNC_INT);

		zone_ctxes = sticky_ctxes->elts;
		// njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0," ========app_sticky_sync sitckey_count:%d", sticky_ctxes->nelts);
		for(i = 0; i < sticky_ctxes->nelts; i++){
			if(zone_ctxes[i] == NULL || zone_ctxes[i]->ctx == NULL){
				njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0," app_sticky_sync sitckey[%d] is null", i);
				continue;
			}
		
			app_sticky_sync_data(zone_ctxes[i]->ctx, &zone_ctxes[i]->zone_name, &target, &target_pid, APP_STICKY_SYNC_INT);
		}
	}
}


njt_app_sticky_ctx_t *njt_app_sticky_get_ctx_by_zone(njt_str_t *zone){
	njt_app_sticky_srv_conf_t		**zone_ctxes = NULL;
	njt_uint_t                      i;


	zone_ctxes = sticky_ctxes->elts;
	for(i = 0; i < sticky_ctxes->nelts; i++){
		if(zone_ctxes[i] == NULL){
			continue;
		}
		if(zone_ctxes[i]->zone_name.len == zone->len && njt_strncmp(zone_ctxes[i]->zone_name.data, zone->data, zone->len) == 0){
			return zone_ctxes[i]->ctx;
		}
	}
	
	return NULL;
}

static int njt_app_sticky_recv_data(const char* msg, void* data)
{
	njt_str_t 					key, val, zone;
	uint32_t 					pack_cnt, arr_cnt, i, len;
	njt_msec_t					ttl;
	const char 					*r = msg;
	njt_app_sticky_ctx_t 		*ctx = NULL;

	pack_cnt = mp_decode_array(&r);
	njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,"%d packages received", pack_cnt);
	for (i=0;i<pack_cnt;i++) {
		arr_cnt = mp_decode_array(&r);
		if (arr_cnt != APP_STICKY_DATA_CNT) {
			njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,"warn: invalid package , a package need include 4 elements:%d", arr_cnt);
			return NJT_ERROR;
		}
		// aa = true;
		key.data = (u_char *)mp_decode_str(&r, &len);
    	key.len=len;

		val.data = (u_char *)mp_decode_str(&r, &len);
    	val.len=len;

		zone.data = (u_char *)mp_decode_str(&r, &len);
    	zone.len=len;

		ttl = mp_decode_uint(&r);

		njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0," recv data index:%d key:%V val:%V zone:%V ttl:%M",
			i, &key, &val, &zone, ttl);

		ctx = njt_app_sticky_get_ctx_by_zone(&zone);
		if(ctx == NULL){
			njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,"warn: has no ctx of zone:%V", &zone);
			continue;
		}

		// aa = false;
		njt_app_sticky_update_node(ctx, key, val, ttl);
	}
	return NJT_OK;
}
static int  njt_app_sticky_on_node_on(njt_str_t* node, njt_str_t* node_pid, void* data)
{
	// njt_app_sticky_ctx_t* ctx= (njt_app_sticky_ctx_t*) data;
	// njt_app_sticky_srv_conf_t* ascf =(njt_app_sticky_srv_conf_t*) ctx->data;
	
	njt_app_sticky_srv_conf_t		**zone_ctxes = NULL;
	njt_uint_t                      i;
	njt_app_sticky_srv_conf_t		*ascf = NULL;

	zone_ctxes = sticky_ctxes->elts;
	for(i = 0; i < sticky_ctxes->nelts; i++){
		if(zone_ctxes[i] == NULL || zone_ctxes[i]->ctx == NULL){
			njt_log_error(NJT_LOG_INFO, zone_ctxes[i]->ctx->log,0,
				"sticky_ctxes[%d] is null", i);
			continue;
		}
		ascf =(njt_app_sticky_srv_conf_t*) zone_ctxes[i]->ctx->data;
		if(ascf == NULL){
			njt_log_error(NJT_LOG_INFO, zone_ctxes[i]->ctx->log,0,
				"sticky_ctxes[%d] ascf is null", i);
			continue;
		}

		njt_log_error(NJT_LOG_INFO, zone_ctxes[i]->ctx->log,0,
			"node:%V online zone:%V, begin sync sticky session,%d",
			node, &zone_ctxes[i]->zone_name, ascf->ttl);
	
		app_sticky_sync_data(zone_ctxes[i]->ctx, &zone_ctxes[i]->zone_name, node, node_pid, ascf->ttl);
	}

	return NJT_OK;
}

static njt_int_t njt_app_sticky_init_worker(njt_cycle_t *cycle)
{
	// njt_http_conf_ctx_t 			*conf_ctx = NULL;
	njt_http_upstream_main_conf_t   *umcf = NULL; 
	njt_http_upstream_srv_conf_t  	*uscf = NULL;
	njt_http_upstream_srv_conf_t    **uscfp = NULL;
	njt_app_sticky_srv_conf_t 		*ascf = NULL;
	njt_uint_t                      i;
	njt_app_sticky_srv_conf_t 		**zone_ctx = NULL;
	njt_flag_t						app_sticky_exist = 0;
	void            				*ev_data = NULL;

	if (njt_process==NJT_PROCESS_HELPER ) {
        return NJT_OK;
    }
	if (njt_app_sticky_module.ctx_index == NJT_CONF_UNSET_UINT)
    {
        return NJT_OK;
    }

	//find all app sticky upstream config
	umcf = njt_http_cycle_get_module_main_conf(cycle, njt_http_upstream_module);
	if(umcf == NULL){
		njt_log_error(NJT_LOG_ERR, cycle->log,0," app sticky, get upstrem module config error");
		return NJT_ERROR;
	}


	if(sticky_ctxes == NULL){
		sticky_ctxes = njt_array_create(cycle->pool, 8, sizeof(njt_app_sticky_srv_conf_t *));
	}

	uscfp = umcf->upstreams.elts;
	for (i = 0; i < umcf->upstreams.nelts; i++)
	{
		uscf = uscfp[i];
		if (uscf == NULL) {
			//means not configure upstream {}
			njt_log_error(NJT_LOG_ERR, cycle->log,0," app sticky get uscf config error");
			return NJT_ERROR;
		}

		if (uscf->srv_conf == NULL) {
			//means not configure upstream {}
			njt_log_error(NJT_LOG_DEBUG, cycle->log,0," upstream server has no srv_conf");
			continue;
		}

		ascf = njt_http_conf_upstream_srv_conf(uscf, njt_app_sticky_module);
		//tips: ascf->ctx is null means not confiugre app_sticky cmd
		if (ascf == NULL || ascf->ctx ==NULL){
			njt_log_error(NJT_LOG_DEBUG, cycle->log,0," app sticky ascf null return");
			continue;
		}
		ev_data = ascf;
		app_sticky_exist = 1;

        zone_ctx = njt_array_push(sticky_ctxes);
		if(zone_ctx == NULL){
			njt_log_error(NJT_LOG_ERR, cycle->log,0," app sticky array push error");
			return NJT_ERROR;
		}

		*zone_ctx = ascf;

		njt_log_error(NJT_LOG_INFO, cycle->log, 0,
			"push sticky ascf:%p  sticky_ctxes count:%d sticky_ctxes[0]:%p  zone_name:%V", 
			ascf, sticky_ctxes->nelts, ((njt_app_sticky_srv_conf_t **)sticky_ctxes->elts)[0], &ascf->zone_name);
	}

	njt_gossip_reg_app_handler(njt_app_sticky_recv_data,njt_app_sticky_on_node_on, GOSSIP_APP_APP_STICKY, sticky_ctxes);
	//only the first worker do broadcast job
	if (njt_worker == 0 && app_sticky_exist)  {
		njt_event_t *ev = njt_palloc(cycle->pool, sizeof(njt_event_t));
		ev->log = &cycle->new_log;
		ev->timer_set = 0;
		ev->cancelable = 1;
		ev->handler = app_sticky_sync;
		ev->data = ev_data;
		njt_add_timer(ev,APP_STICKY_SYNC_INT);	
	}

    return NJT_OK;
}

static njt_int_t njt_app_sticky_update_node(njt_app_sticky_ctx_t *ctx, njt_str_t key, njt_str_t value, njt_msec_t ttl)
{
  	njt_app_sticky_rb_node_t *lr;
	njt_rbtree_node_t *node;

	if (ttl > ctx->ttl) return  NJT_OK;	

	uint32_t hash = njt_crc32_short(key.data, key.len);

    njt_shmtx_lock(&ctx->shpool->mutex);
    node = njt_app_sticky_lookup(&ctx->sh->rbtree, &key, hash);
	if (node != NULL ) {
		njt_log_error(NJT_LOG_DEBUG,ctx->log,0, "found node according to:%V",&key);
		lr= (njt_app_sticky_rb_node_t *) &node->color;
		//tips: if the node exist, but last_seen is old in tree, then update, else omit
		if ( (njt_current_msec- ttl) > lr->last_seen  ) {

			lr->last_seen = njt_current_msec - ttl;

			njt_slab_free_locked(ctx->shpool, lr->up_name.data);

			lr->up_name.data = njt_slab_alloc_locked(ctx->shpool, value.len);
			if (lr->up_name.data == NULL) {
				njt_log_error(NJT_LOG_CRIT,ctx->log,0, "malloc failed in app_sticky init tree, pos1");
				njt_shmtx_unlock(&ctx->shpool->mutex);
				return NJT_ERROR;
			} 			
			lr->up_name.len = value.len;
			memcpy(lr->up_name.data, value.data, value.len);

			njt_queue_remove(&lr->queue);
			//todo:  this queue should sort
            njt_queue_insert_head(&ctx->sh->queue, &lr->queue);
		}
    	njt_shmtx_unlock(&ctx->shpool->mutex);
		return NJT_OK;
	}
	njt_log_error(NJT_LOG_DEBUG,ctx->log,0, "no node according to:%V,create:%V ",&key,&value);

	uint32_t n = offsetof(njt_rbtree_node_t, color)
        + offsetof(njt_app_sticky_rb_node_t, data)
        + value.len;

   	node = njt_slab_alloc_locked(ctx->shpool, n);
	if (node == NULL) {
       	njt_log_error(NJT_LOG_CRIT,ctx->log,0, "malloc failed in app_sticky init tree, pos2");
    	njt_shmtx_unlock(&ctx->shpool->mutex);
		return NJT_ERROR;
   	} 

    node->key = hash;
    lr = (njt_app_sticky_rb_node_t *) &node->color;
    lr->len = (u_short) key.len;
	lr->last_seen = njt_current_msec - ttl;

	lr->up_name.data = njt_slab_alloc_locked(ctx->shpool, value.len);
	if (lr->up_name.data == NULL) {
       	njt_log_error(NJT_LOG_CRIT,ctx->log,0, "malloc failed in app_sticky init tree, pos3");
    	njt_shmtx_unlock(&ctx->shpool->mutex);
		return NJT_ERROR;
   	} 	
	lr->up_name.len= value.len;
	memcpy(lr->up_name.data, value.data, value.len);

	njt_memcpy(lr->data, key.data, key.len);

	njt_rbtree_insert(&ctx->sh->rbtree, node);

    njt_queue_insert_head(&ctx->sh->queue, &lr->queue);

    njt_shmtx_unlock(&ctx->shpool->mutex);

	return NJT_OK;
}
static njt_int_t
njt_app_sticky_header_filter(njt_http_request_t *r)
{
	njt_int_t ret;
	njt_app_sticky_req_ctx_t  *req_ctx = njt_http_get_module_ctx(r,njt_app_sticky_module);

	// njt_log_error(NJT_LOG_DEBUG,r->connection->log,0,"appsticky process header,using ctx:%p",req_ctx);

	if (req_ctx ==NULL ) return NJT_ERROR;
	
	ret = req_ctx->old_proc(r);
	if (ret != NJT_OK) {
		njt_log_error(NJT_LOG_INFO,r->connection->log,0,"process header:%d", ret);
		return ret;
	}

	njt_app_sticky_srv_conf_t *ascf = req_ctx->srv_conf;
	if (ascf->is_cookie == 0) {
		njt_table_elt_t* header_val = njt_app_sticky_search_header(r,ascf->var.data,ascf->var.len,1);
		if (header_val !=NULL ) {
			njt_log_error(NJT_LOG_DEBUG,r->connection->log,0,"found header, will update in rb %V:%V", &header_val->value,&req_ctx->up_name);
			njt_app_sticky_update_node(req_ctx->ctx, header_val->value, req_ctx->up_name,1);
		} else njt_log_error(NJT_LOG_INFO,r->connection->log,0,"no %V in backend header", &ascf->var);
	} else {
		njt_str_t cookie_value;
		if (njt_http_parse_multi_header_lines(r, r->upstream->headers_in.set_cookie, &ascf->var, &cookie_value) 
			!= NULL) {
			njt_log_error(NJT_LOG_DEBUG,r->connection->log,0,"found cookie, will update in rb %V:%V", &cookie_value,&req_ctx->up_name);
			njt_app_sticky_update_node(req_ctx->ctx, cookie_value, req_ctx->up_name,1);
		} else njt_log_error(NJT_LOG_INFO,r->connection->log,0,"no cookie %V in backend header", &ascf->var);
	}

	return NJT_OK;
}
