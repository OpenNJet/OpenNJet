
/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>
#include <njt_http.h>

#include <njt_mqconf_module.h>

#include "njt_gossip_module.h"

// #include "msgpack.h"

#define  GOSSIP_HEARTBEAT_INT 10000



static char *njt_stream_gossip_cmd(njt_conf_t *cf, njt_command_t *cmd, void *conf);

static void *njt_gossip_create_srv_conf(njt_conf_t *cf);
static char *njt_gossip_merge_srv_conf(njt_conf_t *cf, void *parent,void *child);
static njt_int_t njt_gossip_init_zone(njt_shm_zone_t *shm_zone, void *data);


static void njt_gossip_handler(njt_stream_session_t *s);
static void gossip_read_handler(njt_event_t *ev);

static njt_int_t      gossip_start(njt_cycle_t *cycle);
static void           gossip_stop(njt_cycle_t *cycle);
static njt_int_t njt_gossip_connect(njt_gossip_udp_ctx_t *ctx) ;
static void njt_gossip_send_handler(njt_event_t *ev);
static void njt_gossip_node_clean_handler(njt_event_t *ev);

static void njt_gossip_upd_member(njt_stream_session_t *s, njt_uint_t state, njt_msec_t uptime,
		njt_str_t *node_name, njt_str_t *pid);
static njt_int_t njt_gossip_build_member_msg(njt_uint_t msg_type, njt_str_t *target_node, 
		njt_str_t *target_pid, njt_msec_t uptime);
static int	njt_gossip_syn_data_request(njt_str_t *node, njt_str_t *pid);
static njt_int_t add_self_to_memberslist();


extern njt_module_t  njt_mqconf_module;

static njt_command_t njt_gossip_commands[] = {
      {njt_string("gossip"),
      NJT_STREAM_SRV_CONF|NJT_CONF_TAKE123,
      njt_stream_gossip_cmd,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
	  NULL }
    ,njt_null_command /* command termination */
};

/* The module context. */
static njt_stream_module_t njt_gossip_module_ctx = {
	NULL,
	NULL,
    NULL,
    NULL ,
    njt_gossip_create_srv_conf, 
    njt_gossip_merge_srv_conf 
};

static njt_gossip_udp_ctx_t  *gossip_udp_ctx = NULL;	
static njt_array_t *gossip_app_handle_fac = NULL;

/* Module definition. */
njt_module_t  njt_gossip_module = {
    NJT_MODULE_V1,
    &njt_gossip_module_ctx, /* module context */
    njt_gossip_commands,    /* module directives */
    NJT_STREAM_MODULE,        /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    gossip_start,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    gossip_stop,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};

static void *njt_gossip_create_srv_conf(njt_conf_t *cf) 
{
    njt_gossip_srv_conf_t *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_gossip_srv_conf_t));
    if (conf == NULL)
    {
        return NULL;
    }
	conf->cluster_name = NULL;
	conf->node_name = NULL;
	conf->pid = NULL;
	conf->heartbeat_timeout = NJT_CONF_UNSET_MSEC;
	conf->nodeclean_timeout = NJT_CONF_UNSET_MSEC;
	conf->sockaddr = NULL;
	conf->req_ctx = NULL;

    return conf;
}

static char *
njt_stream_gossip_cmd(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
	njt_mqconf_conf_t 			*mqconf;
	njt_stream_core_srv_conf_t 	*cscf;
	njt_stream_core_main_conf_t *cmcf;
	njt_shm_zone_t          	*shm_zone;
	njt_str_t 					*value = cf->args->elts;
	njt_str_t 					shm_name, shm_size;
	
    njt_gossip_srv_conf_t 		*gscf = conf;
	njt_uint_t 					s;
	njt_uint_t                  i;
	njt_int_t 					size;
	njt_stream_core_srv_conf_t 	**servers;
	njt_flag_t				    has_zone;
	njt_str_t					tmp_str;


	mqconf = (njt_mqconf_conf_t*)njt_get_conf(cf->cycle->conf_ctx,njt_mqconf_module);
	if (!mqconf || !mqconf->cluster_name.data || !mqconf->node_name.data)
	{
		njt_log_error(NJT_LOG_EMERG, cf->log, 0, "no mqconf module or not set cluster_name or node_name");
        return NJT_CONF_ERROR;
	} 

	gscf->cluster_name = &mqconf->cluster_name;
	gscf->node_name = &mqconf->node_name;
	gscf->req_ctx=njt_pcalloc(cf->cycle->pool, sizeof(njt_gossip_req_ctx_t));
	gscf->req_ctx->shpool=NULL;
	gscf->req_ctx->sh=NULL;

	gscf->heartbeat_timeout = GOSSIP_HEARTBEAT_INT;
	gscf->nodeclean_timeout = 2 * gscf->heartbeat_timeout;
	
	cscf=njt_stream_conf_get_module_srv_conf(cf,njt_stream_core_module);
	cmcf=njt_stream_conf_get_module_main_conf(cf,njt_stream_core_module);
	if (cmcf->servers.nelts>0) {
		servers = (njt_stream_core_srv_conf_t**) cmcf->servers.elts;
		for (s = 0; s < cmcf->servers.nelts; s++) {
			if (cscf== servers[s]) {
				if (cmcf->listen.nelts<=s) {
			 		njt_log_error(NJT_LOG_ERR, cf->log, 0, "gossip depend on listen directive");
					return NJT_CONF_ERROR;
				}
				njt_stream_listen_t* l= cmcf->listen.elts;
				if (l[s].type!= SOCK_DGRAM) {
			 		njt_log_error(NJT_LOG_ERR, cf->log, 0, "gossip only support udp");
					return NJT_CONF_ERROR;
				}
				if (l[s].sockaddr->sa_family!=AF_INET) {
			 		njt_log_error(NJT_LOG_ERR, cf->log, 0, "only ipv4 support");
					return NJT_CONF_ERROR;
				}
				u_char buf [256];
				size_t addr_l=njt_sock_ntop(l[s].sockaddr,l[s].socklen,buf,255,1);
				buf[addr_l] ='\0';
		 		njt_log_error(NJT_LOG_DEBUG, cf->log, 0, "gossip join mulicast-addr:%p,%s",gscf,buf);
				gscf->sockaddr= l[s].sockaddr;
				gscf->socklen = l[s].socklen;

				break;
			}
		}
		if (!gscf->sockaddr) {
			njt_log_error(NJT_LOG_INFO, cf->log, 0, "gossip depend on listen directive in the same server");
			return NJT_CONF_ERROR;
		}
	} else {
		njt_log_error(NJT_LOG_INFO, cf->log, 0, "no stream.server sec found");
		return NJT_CONF_ERROR;
	}

	has_zone = false;
	for (i = 1; i < cf->args->nelts; i++) {
		if (njt_strncmp(value[i].data, "zone=", 5) == 0) {
			u_char *p;
			shm_name.data = value[i].data + 5;
			p = (u_char *) njt_strchr(shm_name.data, ':');
			if (p == NULL) {
				njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
									"invalid zone size \"%V\"", &value[i]);
				return NJT_CONF_ERROR;
			}
			shm_name.len = p - shm_name.data;
			shm_size.data = p + 1;
			shm_size.len = value[i].data + value[i].len - shm_size.data;
			size = njt_parse_size(&shm_size);
			if (size == NJT_ERROR) {
				njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
									"invalid zone size \"%V\"", &value[i]);
				return NJT_CONF_ERROR;
			}

			has_zone = true;
		} else if (njt_strncmp(value[i].data, "heartbeat_timeout=", 18) == 0){
			tmp_str.data = value[i].data + 18;
			tmp_str.len = value[i].len - 18;
			gscf->heartbeat_timeout = njt_parse_time(&tmp_str, 0);
			if (gscf->heartbeat_timeout == (njt_msec_t) NJT_ERROR) {
				njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
					" gossip, invalid heartbeat_timeout:\"%V\"", &tmp_str);
				return NJT_CONF_ERROR;
			}

			if (gscf->heartbeat_timeout < 1000) {
				njt_conf_log_error(NJT_LOG_INFO, cf, 0,
					" gossip heartbeat_timeout should not less than 1s, default 10s, config:\"%V\", now use default", &tmp_str);
				
				gscf->heartbeat_timeout = GOSSIP_HEARTBEAT_INT;
				// return NJT_CONF_ERROR;
			}
		} else if (njt_strncmp(value[i].data, "nodeclean_timeout=", 18) == 0){
			tmp_str.data = value[i].data + 18;
			tmp_str.len = value[i].len - 18;
			gscf->nodeclean_timeout = njt_parse_time(&tmp_str, 0);
			if (gscf->nodeclean_timeout == (njt_msec_t) NJT_ERROR) {
				njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
					"invalid nodeclean_timeout:\"%V\"", &tmp_str);
				return NJT_CONF_ERROR;
			}

			if (gscf->nodeclean_timeout < 1000) {
				njt_conf_log_error(NJT_LOG_INFO, cf, 0,
					" gossip nodeclean_timeout should not less than 1s, default 20s, config:\"%V\", now use default", &tmp_str);
				
				gscf->nodeclean_timeout = 2 * GOSSIP_HEARTBEAT_INT;
				// return NJT_CONF_ERROR;
			}
		} else {
			njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
				"invalid gossip param \"%V\", format is zone={zone_name}:{size}M [heartbeat_timeout={timeout}] [nodeclean_timeout={timeout}]", &value[i]);
			return NJT_CONF_ERROR;
		}
	}

	if(gscf->nodeclean_timeout < (2 * gscf->heartbeat_timeout)){
		gscf->nodeclean_timeout = 2 * gscf->heartbeat_timeout;
	}

	if(!has_zone){
		njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
			"invalid gossip param, format is zone={zone_name}:{size}M [heartbeat_timeout={timeout}] [nodeclean_timeout={timeout}]");
		return NJT_CONF_ERROR;
	}

	shm_zone = njt_shared_memory_add(cf, &shm_name , size,&njt_gossip_module);
	if (shm_zone == NULL) {
        return NJT_CONF_ERROR;
    }

    shm_zone->init = njt_gossip_init_zone;
    shm_zone->data = gscf->req_ctx;
	
    cscf->handler = njt_gossip_handler;
    return NJT_CONF_OK;

}
static njt_int_t njt_gossip_init_zone(njt_shm_zone_t *shm_zone, void *data)
{
	njt_gossip_req_ctx_t  	*octx = data;
    size_t                  len;
    njt_gossip_req_ctx_t  	*ctx;

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

    ctx->sh = njt_slab_alloc(ctx->shpool, sizeof(njt_gossip_shctx_t));
    if (ctx->sh == NULL) {
        return NJT_ERROR;
    }
	ctx->sh->members=NULL;
    ctx->shpool->data = ctx->sh;
	/*
	njt_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    njt_http_limit_conn_rbtree_insert_value);
	*/
    len = sizeof(" in gossip zone \"\"") + shm_zone->shm.name.len;
    ctx->shpool->log_ctx = njt_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return NJT_ERROR;
    }

    njt_sprintf(ctx->shpool->log_ctx, " in gossip zone \"%V\"%Z",
                &shm_zone->shm.name);
    return NJT_OK;
}

static void njt_gossip_handler(njt_stream_session_t *s)
{
	njt_connection_t              *c;
    c = s->connection;
    c->log->action = "gossip receive";
    c->read->handler=gossip_read_handler;
	// njt_add_timer(c->read, gossip_udp_ctx->nodeclean_timeout);

    gossip_read_handler(c->read);

}
static void njt_gossip_upd_member(njt_stream_session_t *s, njt_uint_t state, njt_msec_t uptime
			, njt_str_t *node_name, njt_str_t *pid)
{
	njt_connection_t              *c;
    njt_str_t                      type;

    c = s->connection;
    c->log->action = "gossip upd member";
	njt_gossip_srv_conf_t *gscf	=njt_stream_get_module_srv_conf(s,njt_gossip_module);
	if(gscf == NULL){
		njt_log_error(NJT_LOG_NOTICE, c->log, 0, 
			" has no gossip module config");
		return;
	}

	njt_gossip_req_ctx_t  *shared_ctx = gscf->req_ctx;
	if(shared_ctx == NULL){
		njt_log_error(NJT_LOG_NOTICE, c->log, 0, 
			" gossip module has no shared zone ctx");
		return;
	}

	njt_gossip_member_list_t *p_member = shared_ctx->sh->members;
	if(p_member == NULL){
		njt_log_error(NJT_LOG_NOTICE, c->log, 0, 
			" gossip module has no member list");
		return;
	}

	njt_gossip_member_list_t *prev=NULL;
	//  njt_gossip_member_list_t *elder=NULL;
	njt_msec_t update_stamp = njt_current_msec;

	switch (state )  {
		case GOSSIP_OFF:
			njt_shmtx_lock(&shared_ctx->shpool->mutex);
			p_member=shared_ctx->sh->members->next;
			while (p_member) {
				if ((p_member->node_name.len==node_name->len && 
					memcmp(p_member->node_name.data,node_name->data,node_name->len)==0)
					&& (p_member->pid.len==pid->len && 
					memcmp(p_member->pid.data,pid->data,pid->len)==0)) {
					if (prev==NULL){
						shared_ctx->sh->members->next = p_member->next;
					} 
					else{
						prev->next = p_member->next;
					} 
						
					njt_slab_free_locked(shared_ctx->shpool, p_member->node_name.data);
					njt_slab_free_locked(shared_ctx->shpool, p_member->pid.data);
					njt_slab_free_locked(shared_ctx->shpool, p_member);
					break;
				} else {
					prev = p_member;
					p_member = p_member->next;
				}
			}
			njt_shmtx_unlock(&shared_ctx->shpool->mutex);
			break;
		case GOSSIP_ON:
		case GOSSIP_HEARTBEAT:
			njt_shmtx_lock(&shared_ctx->shpool->mutex);
			p_member = shared_ctx->sh->members->next;
			prev = NULL;
			if(state == GOSSIP_ON)
			{ 
				njt_str_set(&type, "online");
			}else{
				njt_str_set(&type, "hearbeat");
			}

			while (p_member) {
				if ((p_member->node_name.len==node_name->len && 
					memcmp(p_member->node_name.data,node_name->data,node_name->len)==0)
					&& (p_member->pid.len==pid->len && 
					memcmp(p_member->pid.data,pid->data,pid->len)==0)) {
					break;
				} else {
					prev=p_member;
					p_member=p_member->next;
				}
			}
			if (p_member==NULL) {
				p_member=njt_slab_alloc_locked(shared_ctx->shpool, sizeof(njt_gossip_member_list_t));
				p_member->next =NULL;

				p_member->node_name.data = njt_slab_alloc_locked(shared_ctx->shpool,node_name->len);
				memcpy(p_member->node_name.data,node_name->data,node_name->len);
                                p_member->node_name.len=node_name->len;
				p_member->pid.data = njt_slab_alloc_locked(shared_ctx->shpool,pid->len);
				memcpy(p_member->pid.data,pid->data,pid->len);
                                p_member->pid.len=pid->len;
			}
			p_member->state = 1;		//todo : support for gossip protocol
			p_member->last_seen = update_stamp;
			p_member->uptime = uptime;
			
			if (prev==NULL) {
				shared_ctx->sh->members->next = p_member;
			}else{
				prev->next = p_member;
			}
			
			njt_shmtx_unlock(&shared_ctx->shpool->mutex);
			break;
		default:
			return ;
	}
	
}
static int	njt_gossip_reply_status(void)
{
	njt_str_t target_node = njt_string("all");
	njt_str_t target_pid = njt_string("0");

	if(gossip_udp_ctx == NULL){
		njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0, 
			" has no gossip module config");

		return NJT_OK;	
	}

	njt_gossip_build_member_msg(GOSSIP_HEARTBEAT, &target_node, &target_pid, njt_current_msec- gossip_udp_ctx->boot_timestamp);
	njt_gossip_send_handler(gossip_udp_ctx->udp->write);
	return NJT_OK;
}

/*
 *  set synstat and return last state
*/
static bool njt_gossip_set_syn_state(bool state){
	njt_gossip_req_ctx_t  			*shared_ctx;
	njt_gossip_member_list_t 		*p_member;
	bool 						     need_syn = false;

	if(gossip_udp_ctx == NULL){
		njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0, 
			" in syn state, has no gossip module config");

		return false;	
	}

	shared_ctx = gossip_udp_ctx->req_ctx;

	njt_shmtx_lock(&shared_ctx->shpool->mutex);
	p_member = shared_ctx->sh->members;
	if(p_member == NULL){
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
			" members has no self");
		njt_shmtx_unlock(&shared_ctx->shpool->mutex);
	}else{
		need_syn = p_member->need_syn;
		p_member->need_syn = state;
	}

	njt_shmtx_unlock(&shared_ctx->shpool->mutex);

	return need_syn;
}

static int	njt_gossip_upd_syn_state(njt_str_t *node, njt_str_t *pid)
{
	bool 						     need_syn = false;

	need_syn = njt_gossip_set_syn_state(false);

	if(need_syn){
		njt_gossip_syn_data_request(node, pid);
	}

	return NJT_OK;
}

static int	njt_gossip_syn_data_request(njt_str_t *node, njt_str_t *pid)
{
	if(gossip_udp_ctx == NULL){
		njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0, 
			" in syn data request, has no gossip module config");

		return NJT_OK;	
	}

	njt_gossip_build_member_msg(GOSSIP_MSG_SYN, node, pid, njt_current_msec - gossip_udp_ctx->boot_timestamp);
	njt_gossip_send_handler(gossip_udp_ctx->udp->write);

	return NJT_OK;
}


static int njt_gossip_proc_package(const u_char *begin,const u_char* end, njt_log_t *log, njt_stream_session_t *s)
{
	njt_gossip_srv_conf_t 	*gscf=njt_stream_get_module_srv_conf(s,njt_gossip_module);
	uint32_t 				arr_cnt ,len;
	uint32_t  				magic, msg_type;
	njt_str_t 				c_name, n_name, n_pid, target_name;
	// njt_str_t				target_pid;
	njt_msec_t 				uptime;

	if(gscf == NULL){
		njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0, 
			" in proc packet, has no gossip module config");

		return NJT_OK;
	}


	const char *r = (const char*)begin;
	arr_cnt = mp_decode_array(&r);
	if (arr_cnt<8) {
		njt_log_error(NJT_LOG_WARN, log, 0, "invalid package,array size should large than 8,got :%d", arr_cnt);
		return NJT_OK;
	}
	magic = mp_decode_uint(&r);
	if ( magic != GOSSIP_MAGIC ) {
		njt_log_error(NJT_LOG_WARN, log, 0, " not gossip package,:%d", magic);
		return NJT_OK;
	}
	c_name.data = (u_char *)mp_decode_str(&r, &len);
	c_name.len=len;
	if ( c_name.len!= gscf->cluster_name->len || memcmp(c_name.data, gscf->cluster_name->data, c_name.len)!=0)  {
		njt_log_error(NJT_LOG_INFO, log, 0, " not matched cluster :%V", &c_name);
		return NJT_OK;
	}
	n_name.data = (u_char *)mp_decode_str(&r, &len);
	n_name.len=len;

	if (n_name.len==gscf->node_name->len && memcmp(n_name.data, gscf->node_name->data, n_name.len)==0) {
		//todo: this msg is self sent, will emit this message later ,by send multicast param
		njt_log_error(NJT_LOG_DEBUG, log, 0, " self to self msg, ignore");
		return NJT_OK;
	}

	n_pid.data = (u_char *)mp_decode_str(&r, &len);
	n_pid.len=len;

	target_name.data = (u_char *)mp_decode_str(&r, &len);
	target_name.len=len;

	//target pid now just add ,no use
	// target_pid.data = (u_char *)mp_decode_str(&r, &len);
	// target_pid.len=len;
	mp_decode_str(&r, &len);

	// njt_log_error(NJT_LOG_INFO, log, 0, "target name:%V pid_name:%V",&target_name, &target_pid);
	if ( target_name.len==3 && memcmp(target_name.data, "all", 3)==0){
		njt_log_error(NJT_LOG_DEBUG, log, 0, " recv all type msg, need read");
	}else{
		if(target_name.len==gscf->node_name->len 
			&& memcmp(target_name.data, gscf->node_name->data, target_name.len)==0)
		{
			njt_log_error(NJT_LOG_DEBUG, log, 0, " recv special msg to me, need read");
		}else{
			njt_log_error(NJT_LOG_DEBUG, log, 0, 
				" recv special msg to node[%V], but not me, so ignore", &target_name);
			return NJT_OK;
		}
	}

	msg_type = mp_decode_uint(&r);
	switch ( msg_type) {
		case GOSSIP_ON: 
			uptime=mp_decode_uint(&r);
			njt_log_error(NJT_LOG_INFO, log, 0, "node:%V pid:%V msg_type:online uptime %d", &n_name, &n_pid, uptime);
			njt_gossip_upd_member(s,msg_type,uptime,&n_name, &n_pid);
			njt_gossip_reply_status();
			//todo: call online hook of modules
		break;
		case GOSSIP_OFF: 
			uptime=mp_decode_uint(&r);
			njt_log_error(NJT_LOG_INFO, log, 0, "node:%V pid:%V msg_type:offline uptime:%d", &n_name, &n_pid, uptime);
			njt_gossip_upd_member(s,GOSSIP_OFF,uptime,&n_name, &n_pid);
			//todo: call offline hook of modules
		break;
		case GOSSIP_HEARTBEAT: 
			uptime=mp_decode_uint(&r);
			njt_log_error(NJT_LOG_DEBUG, log, 0, "node:%V pid:%V msg_type:heartbeat uptime:%d", &n_name, &n_pid, uptime);
			njt_gossip_upd_member(s,GOSSIP_HEARTBEAT,uptime,&n_name, &n_pid);
			
			if(gossip_udp_ctx->need_syn){ 
				njt_gossip_upd_syn_state(&n_name, &n_pid);
				gossip_udp_ctx->need_syn = false;
			}

		break;
		case GOSSIP_MSG_SYN:
			uptime=mp_decode_uint(&r);
			njt_log_error(NJT_LOG_DEBUG, log, 0, "node:%V pid:%V msg_type:syn_msg uptime:%d", &n_name, &n_pid, uptime);
			if (target_name.len==gscf->node_name->len && memcmp(target_name.data, gscf->node_name->data, target_name.len)==0)
			{
				njt_log_error(NJT_LOG_INFO, log, 0, 
					" I syn data, I'snode:%V onlinenode:%V onlinenode'spid:%V", 
					gscf->node_name, &n_name, &n_pid);
					
				uint32_t i;
				if (gossip_app_handle_fac) {
					gossip_app_msg_handle_t *app_handle=gossip_app_handle_fac->elts;
					for (i=0;i<gossip_app_handle_fac->nelts;i++) {
						if (  app_handle[i].node_handler)  {
							njt_log_error(NJT_LOG_DEBUG,log,0,"invoke node startup handler:%d",app_handle[i].app_magic);
							app_handle[i].node_handler(&n_name, &n_pid, app_handle[i].data);
						}
					}
				}
			}
		break;
		default:
			njt_log_error(NJT_LOG_DEBUG, log, 0, "node:%V pid:%V msg_type:%d", &n_name, &n_pid, msg_type);
			{
				uint32_t i;
				if(gossip_app_handle_fac){
					gossip_app_msg_handle_t *app_handle = gossip_app_handle_fac->elts;
					for (i=0;i<gossip_app_handle_fac->nelts;i++) {
						if ( app_handle[i].app_magic == msg_type && app_handle[i].handler)  {
							njt_log_error(NJT_LOG_DEBUG, log, 0, "gossip_app procs %d msg", msg_type);
							app_handle[i].handler(r,app_handle[i].data);
							return NJT_OK;
						}
					}
				}
			}
			
		njt_log_error(NJT_LOG_WARN, log, 0, "unknonw msg:%d", msg_type);
	}

	return NJT_OK;
}

static void gossip_read_handler(njt_event_t *ev)
{
    njt_connection_t         	*c;
    ssize_t 					n;
	njt_stream_session_t 		*s;
	u_char 						buf[2048];
    c = ev->data;
    s = c->data;

	// if(ev)
	// njt_stream_close_connection(c)
    if (ev->timedout) {
        njt_log_error(NJT_LOG_DEBUG, c->log, NJT_ETIMEDOUT, "client timed out");
        njt_stream_finalize_session(s, NJT_STREAM_OK);
        return;
    }

	if (c->close) {
        njt_log_error(NJT_LOG_DEBUG, c->log, NJT_ETIMEDOUT, "client close");
        njt_stream_finalize_session(s, NJT_STREAM_OK);
        return;
    }

	if (s->received) {
    	njt_log_error(NJT_LOG_DEBUG, c->log,0, "preread data:%d",s->received);
		njt_memcpy(buf, c->buffer->pos, s->received);
        c->buffer->pos = c->buffer->last;
		s->received = 0;
		njt_gossip_proc_package(buf,buf+s->received,c->log, s);
    }
	while (ev->ready) {
        n = c->recv(c, buf, 2048);
    	njt_log_error(NJT_LOG_DEBUG, c->log,0, "recv data:%d",n);
        if (n>0) {
			njt_gossip_proc_package(buf,buf+n,c->log, s);
        }
        if (n<0) break;
		if (n==0){
			//todo: update nodes pool	,close connection
		}
    }

	ev->timedout = 0;
	ev->cancelable = 1;
	njt_add_timer(ev, gossip_udp_ctx->nodeclean_timeout);
}
//tips: why we need merge from child to parent?
// because nginx creagte conf multi times, when parse config, 
// if you use get configure in init_process, it return the top(parent config), but directive do work in child.
static char *njt_gossip_merge_srv_conf(njt_conf_t *cf, void *parent,void *child)
{
	njt_gossip_srv_conf_t *p = (njt_gossip_srv_conf_t *)parent;
	njt_gossip_srv_conf_t *c = (njt_gossip_srv_conf_t *)child;
    njt_log_error(NJT_LOG_DEBUG, cf->log,0, "merge conf,parent:%p,child:%p",parent,child);
	
	if (c->cluster_name) {
			p->cluster_name = c->cluster_name;
			p->node_name = c->node_name;
	}

    njt_conf_merge_msec_value(p->heartbeat_timeout,
                              c->heartbeat_timeout, GOSSIP_HEARTBEAT_INT);

    njt_conf_merge_msec_value(p->nodeclean_timeout,
                              c->nodeclean_timeout, (GOSSIP_HEARTBEAT_INT * 2));

	if (c->sockaddr) {
		p->sockaddr=c->sockaddr;
		p->socklen=c->socklen;
		p->req_ctx=c->req_ctx;
	}
	return NJT_OK;
}

//the first worker began broad its port ,anounce it's online, 
//then broad health state every 3 secs, 
//and member state it recorded

static njt_int_t gossip_start(njt_cycle_t *cycle)
{
	njt_stream_conf_ctx_t 		*conf_ctx =NULL ;
	njt_gossip_srv_conf_t		*gscf =NULL;
	u_char      				pid[20];
	size_t      				len;
	njt_event_t                 *nc_timer;

    if (njt_process == NJT_PROCESS_HELPER ) {
        return NJT_OK;
    }
	
	conf_ctx =(njt_stream_conf_ctx_t *)cycle->conf_ctx[njt_stream_module.index];
	if (conf_ctx) 
		gscf = conf_ctx->srv_conf[njt_gossip_module.ctx_index];
	else {
		return NJT_OK;
	}
	if (!gscf) return NJT_ERROR;
	if (!gscf->sockaddr || !gscf->cluster_name || !gscf->node_name) {
		njt_log_error(NJT_LOG_INFO,cycle->log, 0,"gossip cant init, no listen address , or cluster_name, node_name configured");
		return NJT_OK;
	}
	njt_log_error(NJT_LOG_INFO,cycle->log, 0,"gossip worker start:%d",njt_worker);

	gossip_udp_ctx = njt_pcalloc(cycle->pool, sizeof(njt_gossip_udp_ctx_t));
    if (gossip_udp_ctx == NULL) {
        return NJT_ERROR;
    }
	gossip_udp_ctx->log=  &cycle->new_log;
	gossip_udp_ctx->pool= cycle->pool;
	gossip_udp_ctx->requests=NULL;
	gossip_udp_ctx->udp=NULL;
	gossip_udp_ctx->need_syn = true;


	gossip_udp_ctx->boot_timestamp = njt_current_msec;
	gossip_udp_ctx->last_seen = gossip_udp_ctx->boot_timestamp;

	//gossip_udp_ctx->sockaddr=gscf->sockaddr;
	//tips: by stdanley, alloc sockaddr for every worker
	gossip_udp_ctx->sockaddr=njt_pcalloc(cycle->pool,gscf->socklen);
	memcpy(gossip_udp_ctx->sockaddr, gscf->sockaddr, gscf->socklen);
	gossip_udp_ctx->socklen=gscf->socklen;

	gossip_udp_ctx->cluster_name=gscf->cluster_name;
	gossip_udp_ctx->node_name=gscf->node_name;

	gossip_udp_ctx->heartbeat_timeout = gscf->heartbeat_timeout;
	gossip_udp_ctx->nodeclean_timeout = gscf->nodeclean_timeout;

	gossip_udp_ctx->pid = NULL;
	gossip_udp_ctx->req_ctx = gscf->req_ctx;

	if (njt_gossip_connect(gossip_udp_ctx) !=NJT_OK) {
		njt_log_error(NJT_LOG_WARN,cycle->log, 0,"connect failed");
		return NJT_ERROR;
	}
	if (njt_worker == 0 ) {
		len = njt_snprintf(pid, 20, "%P", njt_getpid()) - pid;
		gossip_udp_ctx->pid = njt_pcalloc(cycle->pool, sizeof(njt_str_t));
		gossip_udp_ctx->pid->data = njt_pcalloc(cycle->pool, len);
		njt_memcpy(gossip_udp_ctx->pid->data, pid, len);
		gossip_udp_ctx->pid->len = len;
		njt_log_error(NJT_LOG_INFO, cycle->log, 0, 
			" gossip pid:%V getpid:%P   nodeclean_timeout:%M heartbeat_timeout:%M", 
			gossip_udp_ctx->pid, njt_getpid(), gscf->nodeclean_timeout, gscf->heartbeat_timeout);

		//add self to memeberslist
        add_self_to_memberslist();

        njt_str_t target_node = njt_string("all");
		njt_str_t target_pid = njt_string("0");

		njt_gossip_build_member_msg(GOSSIP_ON, &target_node, &target_pid, 1);
    	njt_gossip_send_handler(gossip_udp_ctx->udp->write);
		njt_add_timer(gossip_udp_ctx->udp->write, gossip_udp_ctx->heartbeat_timeout);

		//start nodeclean timeout event
		nc_timer = &gscf->nc_timer;
		nc_timer->handler = njt_gossip_node_clean_handler;
		nc_timer->log = njt_cycle->log;
    	nc_timer->data = gossip_udp_ctx->udp;
		nc_timer->cancelable = 1;

		njt_add_timer(nc_timer, gossip_udp_ctx->nodeclean_timeout);
	}

	return NJT_OK;
}


static njt_int_t njt_get_work0_pid(){
	njt_gossip_req_ctx_t  			*shared_ctx;
	njt_gossip_member_list_t 		*p_member;

	if(gossip_udp_ctx == NULL){
		njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0, 
			" in proc packet, has no gossip module config");

		return NJT_OK;
	}

	shared_ctx = gossip_udp_ctx->req_ctx;

	njt_shmtx_lock(&shared_ctx->shpool->mutex);
	p_member = shared_ctx->sh->members;
	if(p_member == NULL){
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "===============work[%d] get work0 pid fail",
			njt_worker);
		gossip_udp_ctx->pid = njt_pcalloc(njt_cycle->pool, sizeof(njt_str_t));
		gossip_udp_ctx->pid->data = njt_pcalloc(njt_cycle->pool, 1);
		njt_memcpy(gossip_udp_ctx->pid->data, "0", 1);
		gossip_udp_ctx->pid->len = 1;
	}else{
		njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "===============work[%d] get work0pid:[%V]",
			njt_worker, &p_member->pid);
		gossip_udp_ctx->pid = njt_pcalloc(njt_cycle->pool, sizeof(njt_str_t));
		gossip_udp_ctx->pid->data = njt_pcalloc(njt_cycle->pool, p_member->pid.len);
		njt_memcpy(gossip_udp_ctx->pid->data, p_member->pid.data, p_member->pid.len);
		gossip_udp_ctx->pid->len = p_member->pid.len;
		// njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "===============work[%d] get work0pid:[%V]",
		// 	njt_worker, gossip_udp_ctx->pid);
	}

	njt_shmtx_unlock(&shared_ctx->shpool->mutex);
	
	return NJT_OK;	
}

static njt_int_t add_self_to_memberslist()
{
	njt_gossip_req_ctx_t  			*shared_ctx;
	njt_gossip_member_list_t 		*p_member;

	if(gossip_udp_ctx == NULL){
		njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0, 
			" in proc packet, has no gossip module config");

		return NJT_OK;
	}

	shared_ctx = gossip_udp_ctx->req_ctx;

	njt_shmtx_lock(&shared_ctx->shpool->mutex);
	p_member = shared_ctx->sh->members;
	if(p_member == NULL){
		njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, " gossip add_self_to_memberslist work[%d] pid:[%V]",
			njt_worker, gossip_udp_ctx->pid);
		p_member = njt_slab_alloc_locked(shared_ctx->shpool, sizeof(njt_gossip_member_list_t));
		p_member->next = NULL;

		p_member->node_name.data = njt_slab_alloc_locked(shared_ctx->shpool, gossip_udp_ctx->node_name->len);
		memcpy(p_member->node_name.data,gossip_udp_ctx->node_name->data,gossip_udp_ctx->node_name->len);
		p_member->node_name.len = gossip_udp_ctx->node_name->len;
		
		p_member->pid.data = njt_slab_alloc_locked(shared_ctx->shpool,gossip_udp_ctx->pid->len);
		memcpy(p_member->pid.data,gossip_udp_ctx->pid->data,gossip_udp_ctx->pid->len);
		p_member->pid.len = gossip_udp_ctx->pid->len;

		shared_ctx->sh->members = p_member;
	}else{
		njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "gossip add_self_to_memberslist exist update work[%d] pid:[%V]",
			njt_worker, gossip_udp_ctx->pid);
		njt_slab_free_locked(shared_ctx->shpool, p_member->pid.data);
		p_member->pid.data = njt_slab_alloc_locked(shared_ctx->shpool,gossip_udp_ctx->pid->len);
		memcpy(p_member->pid.data,gossip_udp_ctx->pid->data,gossip_udp_ctx->pid->len);
		p_member->pid.len = gossip_udp_ctx->pid->len;
	}

	p_member->state = 1;		//todo : support for gossip protocol
	p_member->need_syn = true;
	njt_shmtx_unlock(&shared_ctx->shpool->mutex);
	
	return NJT_OK;
}


static njt_int_t njt_gossip_build_member_msg(njt_uint_t member_msg_type, 
			njt_str_t *target_node, njt_str_t *target_pid, njt_msec_t uptime)
{
	size_t buf_len;
	char  *buf=njt_gossip_app_get_msg_buf(member_msg_type, *target_node, *target_pid,&buf_len);
	char *head, *w;
    head = buf;
	w=head;
	w = mp_encode_uint(w, uptime);
	njt_gossip_app_close_msg_buf(w);
	return  NJT_OK;
}


njt_int_t  njt_gossip_send_app_msg(void )
{
	if (gossip_udp_ctx)
		njt_gossip_send_handler(gossip_udp_ctx->udp->write);

	return NJT_OK;
}
void njt_gossip_app_close_msg_buf(char *end)
{
	njt_gossip_udp_ctx_t *ctx=gossip_udp_ctx;
	if (ctx && ctx->requests) {
		ctx->requests->buf->last=(u_char*)end;
	}
}
char* njt_gossip_app_get_msg_buf(uint32_t msg_type, njt_str_t target, njt_str_t target_pid, size_t* len)
{
	char *head, *w;
	njt_chain_t *chain_head;
	njt_gossip_udp_ctx_t *ctx = gossip_udp_ctx;

	if(gossip_udp_ctx == NULL){
		njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0, 
			" in proc packet, has no gossip module config");

		return NULL;
	}


	if (ctx->requests==NULL) {
		ctx->requests = njt_alloc_chain_link(ctx->pool);
		ctx->requests->next = NULL;
	} else {
		chain_head= njt_alloc_chain_link(ctx->pool);
		chain_head->next = ctx->requests;
		ctx->requests = chain_head;
	}
	
	//get work0 pid
	if(ctx->pid == NULL){
		njt_get_work0_pid();
	}

	ctx->requests->buf = njt_create_temp_buf(ctx->pool, 1400);
	
    head = (char *)ctx->requests->buf->pos;
	w=head;
	w=mp_encode_array(w, 8);
	w = mp_encode_uint(w, GOSSIP_MAGIC);
	w = mp_encode_str(w,(const char*)ctx->cluster_name->data,ctx->cluster_name->len);
	w = mp_encode_str(w,(const char*)ctx->node_name->data,ctx->node_name->len);
	w = mp_encode_str(w,(const char*)ctx->pid->data,ctx->pid->len);
	w = mp_encode_str(w,(const char*)target.data,target.len);
	w = mp_encode_str(w,(const char*)target_pid.data,target_pid.len);
	w = mp_encode_uint(w, msg_type);
		
	*len=ctx->requests->buf->end - (u_char*)w;

	return w;
}
static njt_int_t njt_gossip_connect(njt_gossip_udp_ctx_t *ctx)
{
    njt_socket_t 		s;
    int 				rc;
    njt_event_t 		*wev ;
    njt_connection_t 	*c;
	char 				*loopch = 0;

    s = njt_socket(ctx->sockaddr->sa_family, SOCK_DGRAM, 0);
    if (s == (njt_socket_t)-1)
    {
        njt_log_error(NJT_LOG_ALERT, ctx->log, njt_socket_errno,
                      njt_socket_n " failed");
        return NJT_ERROR;
    }
	if(setsockopt(s, IPPROTO_IP, IP_MULTICAST_LOOP, (char *)&loopch, sizeof(loopch)) < 0)
	{
        njt_log_error(NJT_LOG_ALERT, ctx->log, njt_socket_errno,
                          "set opt:IP_MULTICAST_LOOP, failed");
        if (njt_close_socket(s) == -1)
        {
            njt_log_error(NJT_LOG_ALERT, ctx->log, njt_socket_errno,
                          njt_close_socket_n " failed");
        }
        return NJT_ERROR;
		
	}
    c = njt_get_connection(s, ctx->log);
	c->pool = ctx->pool;

    if (c == NULL)
    {
        if (njt_close_socket(s) == -1)
        {
            njt_log_error(NJT_LOG_ALERT, ctx->log, njt_socket_errno,
                          njt_close_socket_n " failed");
        }
        return NJT_ERROR;
    }
	/*
	njt_connection_local_sockaddr(c,NULL,0);
	if ( bind(s, c->local_sockaddr, c->local_socklen) <0)  
    {
            njt_log_error(NJT_LOG_ALERT, ctx->log, njt_socket_errno,
                           "bind  failed,%d,%p",c->local_socklen,c->local_sockaddr);
			goto failed;
    } else {
		socklen_t             len;
    	njt_sockaddr_t        sa;
    	struct sockaddr_in   *sin;
		len = sizeof(njt_sockaddr_t);

		getsockname(s, &sa.sockaddr, &len);
		sin=(struct sockaddr_in *) &sa.sockaddr;
            njt_log_error(NJT_LOG_INFO, ctx->log, njt_socket_errno,
                           "bind  ok,port:%d",ntohs(sin->sin_port) );
	}
	*/
    if (njt_nonblocking(s) == -1)
    {
        njt_log_error(NJT_LOG_ALERT, ctx->log, njt_socket_errno,
                      njt_nonblocking_n " failed");

        goto failed;
    }
    wev = c->write;
    wev->data = c;
    wev->log = ctx->log;

    ctx->udp = c;
    rc = connect(s, ctx->sockaddr, ctx->socklen);
    if (rc == -1)
    {
        njt_log_error(NJT_LOG_CRIT, ctx->log, njt_socket_errno,
                      "connect() failed");
        goto failed;
    }
    c->data = ctx;
    wev->ready = 1;
	wev->cancelable = 1;
    wev->handler = njt_gossip_send_handler;

    return NJT_OK;

failed:

    njt_close_connection(c);
    ctx->udp = NULL;

    return NJT_ERROR;
}

static void njt_gossip_send_handler(njt_event_t *ev)
{
    njt_connection_t 			*c;
    njt_gossip_udp_ctx_t 		*ctx;
	njt_chain_t 				*chain, *ln, *cl , *chain_head;

    c = ev->data;
    ctx = (njt_gossip_udp_ctx_t *)c->data;

	if(ctx == NULL || gossip_udp_ctx == NULL){
		njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0, 
			" in proc packet, has no gossip module config");

		return;
	}

	if (ctx->requests ) {
		chain_head = ctx->requests;
		chain = njt_send_chain(ctx->udp,chain_head, 0);
		//tips: assume chain is null when sent completely
		//todo: may send partical if chain is too long
		for (cl = chain_head; cl && cl != chain; /* void */)
        {
            ln = cl;
            cl = cl->next;
            njt_free_chain(ctx->pool, ln);
        }
		ctx->requests=NULL;

		if  (chain == NJT_CHAIN_ERROR)
        {
            njt_log_error(NJT_LOG_ERR, ctx->log, 0, "send chain error:");
            return;
        } else 
            njt_log_error(NJT_LOG_DEBUG, ctx->log, 0, "send chain ok: %p", chain);
	}

	if (ev->timedout && !njt_exiting)
    {
		ev->timedout = 0;
		if(gossip_udp_ctx->need_syn){
			gossip_udp_ctx->need_syn = false;
			// njt_log_error(NJT_LOG_INFO, ctx->log, 0, " has no other node online, so not need syn");
			njt_gossip_set_syn_state(false);
		}

		njt_msec_t uptime = njt_current_msec - ctx->boot_timestamp;
		njt_str_t target_node = njt_string("all");
		njt_str_t target_pid = njt_string("0");
		njt_gossip_build_member_msg(GOSSIP_HEARTBEAT, &target_node, &target_pid, uptime);
		njt_gossip_send_handler(ev);
		njt_add_timer(ev, ctx->heartbeat_timeout);
	}
}

static void njt_gossip_node_clean_handler(njt_event_t *ev)
{
	njt_gossip_req_ctx_t  			*shared_ctx;
	njt_gossip_member_list_t 		*p_member;
	njt_msec_t 						current_stamp, diff_time; 
	njt_gossip_member_list_t 		*prev = NULL;

	if(gossip_udp_ctx == NULL){
		njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0, 
			" in proc packet, has no gossip module config");

		return;
	}

	shared_ctx = gossip_udp_ctx->req_ctx;

	njt_shmtx_lock(&shared_ctx->shpool->mutex);
	p_member = shared_ctx->sh->members->next;
	current_stamp = njt_current_msec;

	while (p_member) {
		diff_time = current_stamp - p_member->last_seen;
		if (diff_time >= gossip_udp_ctx->nodeclean_timeout) {
			njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, 
				" node[%V] pid[%V] not send heart, so clean",
				&p_member->node_name, &p_member->pid);
			if (prev==NULL){
				shared_ctx->sh->members->next = p_member->next;
				njt_slab_free_locked(shared_ctx->shpool, p_member->node_name.data);
				njt_slab_free_locked(shared_ctx->shpool, p_member->pid.data);
				njt_slab_free_locked(shared_ctx->shpool, p_member);

				p_member = shared_ctx->sh->members->next;
			} else {
				prev->next = p_member->next;
				njt_slab_free_locked(shared_ctx->shpool, p_member->node_name.data);
				njt_slab_free_locked(shared_ctx->shpool, p_member->pid.data);
				njt_slab_free_locked(shared_ctx->shpool, p_member);
				p_member = prev->next;
			} 
		} else {
			prev = p_member;
			p_member = p_member->next;
		}
	}
	njt_shmtx_unlock(&shared_ctx->shpool->mutex);

    if (ev->timedout && !njt_exiting)
    {
		njt_add_timer(ev, gossip_udp_ctx->nodeclean_timeout);
	}
}


static void   gossip_stop(njt_cycle_t *cycle)
{
	//njt_log_error(NJT_LOG_ERR,cycle->log,0,"gossip proc stop:%d",njt_worker);
	if (njt_worker==0 && gossip_udp_ctx) {
		njt_str_t target_node = njt_string("all");
		njt_str_t target_pid = njt_string("0");
		njt_gossip_build_member_msg(GOSSIP_OFF, &target_node, &target_pid, 0);
		njt_log_error(NJT_LOG_INFO,cycle->log,0,"node stop, broad offline msg");
		njt_gossip_send_handler(gossip_udp_ctx->udp->write);
	}
}
int  njt_gossip_reg_app_handler( gossip_app_pt app_msg_handler, gossip_app_node_pt app_node_handler, uint32_t app_magic, void* data)
{
	if (gossip_app_handle_fac == NULL)
		gossip_app_handle_fac = njt_array_create(njt_cycle->pool, 4, sizeof(gossip_app_msg_handle_t));

	gossip_app_msg_handle_t *app_handle = njt_array_push(gossip_app_handle_fac);
	app_handle->data=data;
	app_handle->app_magic=app_magic;
	app_handle->handler=app_msg_handler;
	app_handle->node_handler=app_node_handler;

    njt_log_error(NJT_LOG_INFO,njt_cycle->log,0," gossip, reg app_magic:%d", app_magic);

	return NJT_OK;
}
void njt_gossip_send_app_msg_buf(void) 
{
	if (gossip_udp_ctx) {
		njt_gossip_send_handler(gossip_udp_ctx->udp->write);
	}
}
/* tabstop=4 */
