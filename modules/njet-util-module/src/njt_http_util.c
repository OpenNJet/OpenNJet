/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_core.h>
#include <njt_http.h>
#include <njt_http_proxy_module.h>
#include <njt_http_util.h>
#include <njt_http_kv_module.h>
extern njt_module_t  njt_http_proxy_module;
extern njt_module_t  njt_http_upstream_keepalive_module;
extern njt_cycle_t *njet_master_cycle;
extern njt_int_t
njt_http_upstream_destroy_cache_domain(njt_http_upstream_srv_conf_t *us);
static void njt_http_upstream_destroy(njt_http_upstream_srv_conf_t *upstream);
njt_http_core_srv_conf_t* njt_http_get_srv_by_server_name(njt_cycle_t *cycle,njt_str_t *addr_port,njt_str_t *server_name){
	njt_http_core_srv_conf_t* cscf, *ret_cscf;
	njt_listening_t *ls, *target_ls = NULL;
	njt_uint_t i,j,k;
	in_port_t  nport;
	njt_http_server_name_t  *name;
	njt_http_port_t *port;
	njt_http_in_addr_t *addr;
	njt_http_in6_addr_t *addr6;
	njt_http_addr_conf_t *addr_conf;
	njt_http_server_name_t *sn;
	njt_str_t server_low_name,full_name;
	njt_url_t  u;
	njt_uint_t         worker;
	struct sockaddr_in   *ssin;
#if (NJT_HAVE_INET6)
	struct sockaddr_in6  *ssin6;
#endif

	njt_pool_t *pool;

	target_ls = NULL;
	cscf = NULL;
	ret_cscf = NULL;
	pool = njt_create_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
	if(pool == NULL) {
		return NULL;
	}

	njt_memzero(&u,sizeof(njt_url_t));
	u.url = *addr_port;
	u.default_port = 80;
	u.no_resolve = 1;

	if (njt_parse_url(pool, &u) != NJT_OK) {
		goto out;
	}

	if (server_name !=NULL && addr_port != NULL && addr_port->len > 0 ) {
		njt_str_null(&server_low_name);
		if (server_name->len > 0) {
			server_low_name.data = njt_pnalloc(pool,server_name->len);
			if(server_low_name.data == NULL) {
				njt_log_error(NJT_LOG_ERR, cycle->log, 0, "njt_http_get_srv_by_port alloc error!");
				goto out;
			}
		}
		server_low_name.len = server_name->len;
		njt_strlow(server_low_name.data, server_name->data,server_name->len);

		server_name = &server_low_name;
		worker = njt_worker;
		if (njt_process == NJT_PROCESS_HELPER && njt_is_privileged_agent) {
			worker = 0;
		}

		ls = cycle->listening.elts;
		for (i = 0; i < cycle->listening.nelts; i++) {
			if(ls[i].server_type != NJT_HTTP_SERVER_TYPE){
				continue; // 非http listen
			}
			if (ls[i].reuseport && ls[i].worker != worker) {
				continue; 
			}
			nport = 0;
			if (njt_cmp_sockaddr(ls[i].sockaddr, ls[i].socklen,
						&u.sockaddr.sockaddr, u.socklen, 1)
					== NJT_OK) {
				target_ls = &ls[i];
				break;
			} else if(ls[i].sockaddr->sa_family != AF_UNIX && ls[i].sockaddr->sa_family == u.family && njt_inet_wildcard(ls[i].sockaddr) == 1){
				nport = njt_inet_get_port(ls[i].sockaddr);
				if(nport == u.port) {
					target_ls = &ls[i];
					break;
				}
			}
		}
		if (target_ls == NULL) {
			njt_log_error(NJT_LOG_INFO, cycle->log, 0, "can`t find listen server %V",addr_port);
			goto out;
		}
		port = target_ls->servers;
		addr=NULL;
		addr6=NULL;
		switch (target_ls->sockaddr->sa_family) {

#if (NJT_HAVE_INET6)
			case AF_INET6:
				addr6 = port->addrs;
				break;
#endif
			default: /* AF_INET */
				addr = port->addrs;
				break;
		}
		for (i = 0; i < port->naddrs ; ++i) {
			if(target_ls->sockaddr->sa_family != AF_UNIX) {
				if (addr6 != NULL) {
					ssin6 = (struct sockaddr_in6 *) &u.sockaddr.sockaddr; 
					if (njt_memcmp(&addr6[i].addr6, &ssin6->sin6_addr,16) != 0) {
						continue;
					}
					addr_conf = &addr6[i].conf;
				} else {
					ssin = (struct sockaddr_in *) &u.sockaddr.sockaddr;          
					if (addr[i].addr != ssin->sin_addr.s_addr) {
						continue;
					}
					addr_conf = &addr[i].conf;
				}
				if(addr_conf == NULL){
					continue;
				}
			} else {
				addr_conf = &addr[0].conf;
			}
			cscf = addr_conf->default_server;
			name = cscf->server_names.elts;
			for(j = 0 ; j < cscf->server_names.nelts ; ++j ){
				full_name = njt_get_command_unique_name(pool,name[j].full_name);
				if(full_name.len == server_name->len
						&& njt_strncasecmp(full_name.data,server_name->data,server_name->len) == 0){
					ret_cscf = cscf;
					goto out;
				}
			}


			if (addr_conf->virtual_names != NULL) {

				if(server_name->len > 0 && server_name->data[0] == '~') {
					sn = addr_conf->virtual_names->regex;
					for (k = 0; k <  addr_conf->virtual_names->nregex; ++k) {
						full_name = njt_get_command_unique_name(pool,sn[k].full_name);
						if(full_name.len == server_name->len &&
								njt_strncasecmp(full_name.data,server_name->data,server_name->len)==0){
							ret_cscf = sn[k].server;
							goto out;
						}
					}
				} else {
					cscf = njt_hash_find_combined(&addr_conf->virtual_names->names,
							njt_hash_key(server_name->data, server_name->len),
							server_name->data, server_name->len);
					if(cscf != NULL){
						ret_cscf = cscf;
						goto out;
					}
				} 
			}

		}
	}
out:
	if(pool != NULL) {
		njt_destroy_pool(pool);
	}
	return ret_cscf;
}

// 获取server的listen 字符串列表
njt_int_t njt_http_get_listens_by_server(njt_array_t *array,njt_http_core_srv_conf_t  *cscf){
//    njt_hash_elt_t  **elt;
	njt_listening_t *ls;
	njt_uint_t i,j,k,len;
	njt_http_port_t *port;
	njt_http_in_addr_t *addr;
	njt_uint_t         worker;
	njt_http_in6_addr_t *addr6;
	njt_http_addr_conf_t             *addr_conf;   //(njt_process == NJT_PROCESS_HELPER && njt_is_privileged_agent)  if (!ls[i].reuseport || ls[i].worker != 0)
	njt_str_t *listen, data;
	njt_http_server_name_t *sn;
	njt_http_core_srv_conf_t  *tcscf;
	struct sockaddr          *sockaddr;
	struct sockaddr_in6  *sin6, ssin6;
	struct sockaddr_in   *sin,   ssin;
	in_port_t  nport;
	//njt_uint_t  addr_len = NJT_SOCKADDR_STRLEN;
	worker = njt_worker;
	if (njt_process == NJT_PROCESS_HELPER && njt_is_privileged_agent) {
		worker = 0;
	}

	ls = njt_cycle->listening.elts;
	for (i = 0; i < njt_cycle->listening.nelts; ++i) {
		if(ls[i].server_type != NJT_HTTP_SERVER_TYPE){
			continue; // 非http listen
		}
		if (ls[i].reuseport && ls[i].worker != worker) {
			continue; 
		}
		port = ls[i].servers;
		addr=NULL;
		addr6=NULL;
		switch (ls[i].sockaddr->sa_family) {

#if (NJT_HAVE_INET6)
			case AF_INET6:
				addr6 = port->addrs;
				break;
#endif
			default: /* AF_INET */
				addr = port->addrs;
				break;
		}

		for (j = 0; j < port->naddrs ; ++j) {
			if(addr6 != NULL){
				addr_conf = &addr6[j].conf;
			}else{
				addr_conf = &addr[j].conf;
			}
			if(addr_conf == NULL){
				continue;
			}
			listen = NULL;
			if(addr_conf->default_server == cscf ){
				listen  = njt_array_push(array);
				if(listen == NULL){
					return NJT_ERROR_ERR;
				}
			}
			if (listen == NULL && addr_conf->virtual_names != NULL) {
				if(cscf->server_name.len > 0 && cscf->server_name.data[0] == '~' ) {
					sn = addr_conf->virtual_names->regex;
					for (k = 0; k <  addr_conf->virtual_names->nregex; ++k) {
						if(sn[k].server == cscf){
							listen  = njt_array_push(array);
							if(listen == NULL){
								return NJT_ERROR_ERR;
							}
							break;
						}
					}
				} else {
					tcscf = njt_hash_find_combined(&addr_conf->virtual_names->names,
							njt_hash_key(cscf->server_name.data, cscf->server_name.len),
							cscf->server_name.data, cscf->server_name.len);
					if(cscf == tcscf){
						listen  = njt_array_push(array);
						if(listen == NULL){
							return NJT_ERROR_ERR;
						}
					}
				} 

			}
			if(listen != NULL) {
				if (ls[i].sockaddr->sa_family == AF_UNIX) {
					*listen = ls[i].addr_text;
				} else {
					nport = njt_inet_get_port(ls[i].sockaddr);
					data.data = njt_pnalloc(array->pool, NJT_SOCKADDR_STRLEN);
					if (data.data == NULL) {
						return NJT_ERROR_ERR;
					}
					data.len = NJT_SOCKADDR_STRLEN;

					//njt_memzero(&sockaddr,sizeof(struct sockaddr ));
					//sockaddr.sa_family = ls[i].sockaddr->sa_family;
					sockaddr = NULL;
					if(ls[i].sockaddr->sa_family == AF_INET6) {
						sockaddr = (struct sockaddr *)&ssin6;
						njt_memzero(&ssin6,sizeof(struct sockaddr_in6 ));
						sin6 = (struct sockaddr_in6  *)sockaddr;  //if (njt_memcmp(&addr6[i].addr6, &ssin6->sin6_addr,16)
						njt_memcpy(&sin6->sin6_addr, &addr6[j].addr6, 16);
					} else if (ls[i].sockaddr->sa_family == AF_INET)  {
						sockaddr = (struct sockaddr *)&ssin;
						njt_memzero(&ssin,sizeof(struct sockaddr_in ));
						sin = (struct sockaddr_in  *)sockaddr;
						sin->sin_addr.s_addr = addr[j].addr;
					}
					if (sockaddr == NULL) {
						return NJT_ERROR;
					} 
					sockaddr->sa_family = ls[i].sockaddr->sa_family;
					njt_inet_set_port(sockaddr,nport);
					len = njt_sock_ntop(sockaddr, sizeof(njt_sockaddr_t),
							data.data, data.len, 1);
					if (len == 0) {
						return NJT_ERROR;
					}
					data.len = len;
					*listen = data;
				}

			}
		}
	}
	return NJT_OK;
}

njt_int_t njt_http_util_read_request_body(njt_http_request_t *r, njt_str_t *req_body, size_t min_len, size_t max_len)
{
	njt_chain_t *body_chain, *tmp_chain;
	ssize_t n;
	size_t len, size;
	njt_fd_t  fd;
	njt_file_info_t   fi;

	req_body->len = 0;
	req_body->data = NULL;

	if (r == NULL || r->request_body == NULL) {
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
				"request and request_body should not be NULL");
		return NJT_ERROR;
	}
	body_chain = r->request_body->bufs;
	if (body_chain == NULL) {
		njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
				"request body chain is NULL");
		return NJT_ERROR;
	}

	len = 0;
	fd = -1;
	// if requst body is more than client_body_buffer_size, it is in the tmp file  
	if (body_chain->buf->file) {
		fd = body_chain->buf->file->fd;
		if (njt_fd_info(fd, &fi) == NJT_FILE_ERROR) {
			njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
					"get temp file err: %V", &body_chain->buf->file->name);
			return NJT_ERROR;
		}
		len = njt_file_size(&fi);
	} else {
		tmp_chain = body_chain;
		while (tmp_chain != NULL) {
			len += tmp_chain->buf->last - tmp_chain->buf->pos;
			tmp_chain = tmp_chain->next;
		}
	}

	if (len < min_len || len > max_len) {
		njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
				"request body size is: %uz, not within [%uz, %uz]", len, min_len, max_len);
		return NJT_ERROR;
	}

	req_body->len = len;
	req_body->data = njt_pcalloc(r->pool, len);
	if (req_body->data == NULL) {
		njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
				"could not alloc buffer in function %s", __func__);
		req_body->len = 0;
		return NJT_ERROR;
	}
	if (body_chain->buf->file && fd != -1) {
		n = njt_read_fd(fd, req_body->data, len);
		if (n == -1) {
			njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
					" read request body fail from temp file: %V", &body_chain->buf->file->name);
			req_body->len = 0;
			return NJT_ERROR;
		}
		if ((size_t)n != len) {
			njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
					" read request body fail from temp file: %V", &body_chain->buf->file->name);
			req_body->len = 0;
			return NJT_ERROR;
		}
	} else {
		len=0;
		tmp_chain = r->request_body->bufs;
		while (tmp_chain != NULL) {
			size = tmp_chain->buf->last - tmp_chain->buf->pos;
			njt_memcpy(req_body->data + len, tmp_chain->buf->pos, size);
			tmp_chain = tmp_chain->next;
			len+=size;
		}
	}

	return NJT_OK;
}

void njt_http_location_destroy(njt_http_core_loc_conf_t *clcf,njt_int_t del_toic) {
	njt_queue_t *q;
	njt_queue_t *locations;
	njt_http_location_queue_t *lq;
	njt_http_core_loc_conf_t *new_clcf;
	njt_http_proxy_loc_conf_t    *plcf;
	njt_http_upstream_srv_conf_t    *upstream;
	njt_int_t old_disable;
	njt_str_t cotent;
	if(clcf == NULL) {
		return;
	}
	locations = clcf->old_locations;
	if (locations != NULL) {
		for (q = njt_queue_head(locations);
				q != njt_queue_sentinel(locations);
		    ) {
			lq = (njt_http_location_queue_t *) q;
			q = njt_queue_next(q);
			new_clcf = NULL;
			if (lq->exact != NULL) {
				new_clcf = lq->exact;
				//njt_http_location_destroy(new_clcf);
			} else if (lq->inclusive != NULL) {
				new_clcf = lq->inclusive;
				//njt_http_location_destroy(new_clcf); //zyg
			}
		
			if (new_clcf != NULL && (new_clcf->noname == 1 && clcf->ref_count != 0)){
				
			} else {
				njt_queue_remove(&lq->queue);
				njt_http_location_destroy(new_clcf,del_toic);
			}
		}
	}
	njt_http_location_cleanup(clcf);
	old_disable = clcf->disable;
	clcf->disable = 1;
	upstream = NULL;
	if (clcf->pool != NULL && clcf->dynamic_status != 0) {
		plcf = clcf->loc_conf[njt_http_proxy_module.ctx_index];
		if(plcf != NULL && plcf->upstream.upstream != NULL) {
			upstream = plcf->upstream.upstream;
			if(old_disable == 0) {
				upstream->ref_count --;
			}
			
		}
		if(upstream == NULL) {
			njt_log_debug(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "njt_destroy_pool clcf=%p,name=%V,pool=%p,ref_count=%i",clcf,&clcf->name,clcf->pool,clcf->ref_count);
		} else {
			njt_log_debug(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "njt_destroy_pool clcf=%p,name=%V,pool=%p,ref_count=%i,upstream ref_count=%d",clcf,&clcf->name,clcf->pool,clcf->ref_count,upstream->ref_count);
		}
		if(old_disable == 0 && del_toic) {
			if (clcf->topic != NULL && njt_process == NJT_PROCESS_HELPER && njt_is_privileged_agent)
			{
				njt_str_set(&cotent, "");
				njt_kv_sendmsg(clcf->topic, &cotent, 0);
				njt_log_debug(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "del topic clcf=%p,name=%V,topic=%V", clcf, &clcf->name, clcf->topic);
			}
		}
		if(clcf->ref_count == 0) {
			if(upstream != NULL) {
				njt_http_upstream_del((njt_cycle_t  *)njt_cycle,upstream);
			}
			njt_destroy_pool(clcf->pool);
		}
	}
}

#if(NJT_HTTP_ADD_DYNAMIC_UPSTREAM)
njt_int_t njt_http_upstream_del(njt_cycle_t  *cycle,njt_http_upstream_srv_conf_t *upstream) {

	njt_uint_t                      i;
	njt_http_upstream_srv_conf_t   **uscfp;
	njt_http_upstream_main_conf_t  *umcf;
	njt_int_t rc,ret;

	njt_log_debug(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "try njt_http_upstream_del=%V,port=%d,ref_count=%d,client_count=%d",&upstream->host,upstream->port,upstream->ref_count,upstream->client_count);	
	if (upstream->ref_count != 0 || upstream->dynamic != 1) {
		return NJT_ERROR;
	}
	umcf = njt_http_cycle_get_module_main_conf(cycle, njt_http_upstream_module);

	uscfp = umcf->upstreams.elts;

	for (i = 0; i < umcf->upstreams.nelts; i++)
	{
		if (uscfp[i] == upstream)
		{
			upstream->disable = 1;
			
			rc = njt_http_upstream_check_free(upstream);
			if (rc == NJT_OK)
			{
				njt_array_delete_idx(&umcf->upstreams,i);
				njt_log_debug(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "njt_http_upstream_del=%V,port=%d,ref_count=%d,client_count=%d",&upstream->host,upstream->port,upstream->ref_count,upstream->client_count);	
				
				ret = NJT_OK;
				if(njet_master_cycle != NULL) {
					if(upstream->shm_zone != NULL && upstream->shm_zone->shm.addr != NULL) {
						ret = njt_share_slab_free_pool(njet_master_cycle,(njt_slab_pool_t *)upstream->shm_zone->shm.addr);
					}
				} else {
					if(upstream->shm_zone != NULL && upstream->shm_zone->shm.addr != NULL) {
						ret = njt_share_slab_free_pool((njt_cycle_t *)njt_cycle,(njt_slab_pool_t *)upstream->shm_zone->shm.addr);
					}
				}
				if (ret == NJT_ERROR)
				{
					njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "njt_http_upstream_del  njt_share_slab_free_pool failure");
				}
				njt_http_upstream_destroy(upstream);
				njt_destroy_pool(upstream->pool);
				return NJT_OK;
			}

			break;
		}
	}
	return NJT_ERROR;
}
#endif

  njt_str_t njt_get_command_unique_name(njt_pool_t *pool,njt_str_t src) {
  njt_conf_t cf;
  njt_str_t full_name,*value,new_src;
  u_char* index;
  njt_uint_t len,i;
  full_name.len = 0;
  full_name.data = NULL;
  njt_memzero(&cf, sizeof(njt_conf_t));
  cf.pool = pool;
  cf.temp_pool = pool;
  cf.log = njt_cycle->log;


  //njt_str_set(&src,"~\\");
  if(src.len == 0) {
	return full_name;
  }
   new_src.len = src.len + 3;
   new_src.data = njt_pcalloc(pool,new_src.len);  //add " {"
	if (new_src.data == NULL){
		return full_name;
	}
	njt_memcpy(new_src.data,src.data,src.len);
	new_src.data[new_src.len - 3] = ' ';
	new_src.data[new_src.len - 2] = '{';
	new_src.data[new_src.len - 1] = '\0';
	

  cf.args = njt_array_create(cf.pool, 10, sizeof(njt_str_t));
    if (cf.args == NULL) {
        return full_name;
    }
   njt_conf_read_memory_token(&cf,new_src);
   //if(cf.args->nelts > 0) {
//	cf.args->nelts--;
  // }
   len =0;
   value = cf.args->elts;
    for(i = 0; i < cf.args->nelts; i++){
        len += value[i].len;
    }
    index = njt_pcalloc(pool,len);
    if (index == NULL){
        return full_name;
    }
    full_name.data = index;
    for(i = 0; i < cf.args->nelts; i++){
        njt_memcpy(index,value[i].data,value[i].len);
        index += value[i].len;
        //*index = (u_char)' ';
        //++index;
    }
    full_name.len = len;
    return full_name;
 
}


njt_int_t njt_http_location_full_name_cmp(njt_str_t full_name,njt_str_t src) {

	njt_pool_t  *pool;
	njt_str_t   command1,command2;

	pool = njt_create_pool(1024, njt_cycle->log);
	if(pool == NULL) {
		return NJT_ERROR;
	}

	command1 = njt_get_command_unique_name(pool,full_name);
	command2 = njt_get_command_unique_name(pool,src);
	if(command1.len == command2.len && njt_strncmp(command1.data,command2.data,command1.len) == 0) {
			njt_destroy_pool(pool);
			return NJT_OK;
	}
	njt_destroy_pool(pool);
	return NJT_ERROR;
}

njt_int_t njt_http_server_full_name_cmp(njt_str_t full_name,njt_str_t server_name,njt_uint_t need_parse) {
	njt_pool_t  *pool;
	njt_str_t   command1,command2;
	njt_uint_t  is_case;
	pool = njt_create_pool(1024, njt_cycle->log);
	if(pool == NULL) {
		return NJT_ERROR;
	}
	if (need_parse) {
		command1 = njt_get_command_unique_name(pool,server_name);
	} else {
		command1 = server_name;
	}
	command2 = njt_get_command_unique_name(pool,full_name);
	is_case = 1;
	if(command1.len > 0 && command1.data[0] != '~' && command2.len > 0 && command2.data[0] != '~') {
		is_case = 0;
	}
	is_case = 0;  //我们正则也不区分大小写。所以用 0 
	if(is_case == 1) {
		if(command1.len == command2.len && njt_strncmp(command1.data,command2.data,command1.len) == 0) {
			njt_destroy_pool(pool);
			return NJT_OK;
		}
	} else {
		if(command1.len == command2.len && njt_strncasecmp(command1.data,command2.data,command1.len) == 0) {
			njt_destroy_pool(pool);
			return NJT_OK;
		}
	}
	njt_destroy_pool(pool);
	return NJT_ERROR;
}

njt_http_core_srv_conf_t* njt_http_get_srv_by_port(njt_cycle_t *cycle,njt_str_t *addr_port,njt_str_t *server_name){

	njt_pool_t  *pool;
	njt_str_t   name;
	njt_http_core_srv_conf_t* srv;

	njt_log_error(NJT_LOG_DEBUG, cycle->log, 0, "njt_http_get_srv_by_port server_name = %V",server_name);
	pool = njt_create_pool(1024, njt_cycle->log);
	if(pool == NULL) {
		return NULL;
	}
	name = njt_get_command_unique_name(pool,*server_name);
	srv = njt_http_get_srv_by_server_name(cycle,addr_port,&name);

	njt_destroy_pool(pool);
	return srv;
}

njt_int_t njt_http_parse_path(njt_str_t uri, njt_array_t *path){
	u_char                              *p,*end, *sub_p;
    njt_uint_t                          len;
    njt_str_t                           *item;

    /*the uri is parsed and delete all the duplidated '/' characters.
     * for example, "/api//7//http///upstreams///////" will be parse to
     * "/api/7/http/upstreams/" already*/

    p = uri.data;
    end = uri.data + uri.len;
    len = uri.len;

    if (len != 0 && *p != '/') {
        return NJT_HTTP_NOT_FOUND;
    }
    if (*p == '/') {
        len --;
        p ++;
    }

    while (len > 0) {
        item = njt_array_push(path);
        if (item == NULL) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                          "zack: array item of path push error.");
            return NJT_ERROR;
        }

        item->data = p;
        sub_p = (u_char *)njt_strlchr(p, end, '/');

        if (sub_p == NULL || (njt_uint_t)(sub_p - uri.data) > uri.len) {
            item->len = uri.data + uri.len - p;
            break;

        } else {
            item->len = sub_p - p;
        }

        len -= item->len;
        p += item->len;

        if (*p == '/') {
            len --;
            p ++;
        }

    }

    return NJT_OK;
}



njt_int_t
njt_http_util_add_header(njt_http_request_t *r, njt_str_t key,
    njt_str_t value)
{
    njt_table_elt_t  *h;

    if (value.len) {
        h = njt_list_push(&r->headers_out.headers);
        if (h == NULL) {
            return NJT_ERROR;
        }

        h->hash = 1;
        h->key = key;
        h->value = value;
    }

    return NJT_OK;
}

/*
  根据变量名，查找变量是否定义。
  返回值： 定义返回NJT_OK。  否则返回NJT_ERROR  
*/
static njt_int_t njt_http_util_check_variable(njt_str_t *name){

    njt_uint_t                  i;
    njt_http_core_main_conf_t  *cmcf;
    njt_hash_key_t             *key;
    njt_http_variable_t        *pv;

    if (name->len == 0) {
        return NJT_ERROR;
    }

    cmcf = njt_http_cycle_get_module_main_conf(njt_cycle, njt_http_core_module);
    key = cmcf->variables_keys->keys.elts;

    key = cmcf->variables_keys->keys.elts;
    pv = cmcf->prefix_variables.elts;
    for (i = 0; i < cmcf->variables_keys->keys.nelts; i++) {
        if(name->len == key[i].key.len
            && njt_strncasecmp(name->data, key[i].key.data,name->len)
                == 0)
        {
            return NJT_OK;
        }
    }
    for (i = 0; i < cmcf->prefix_variables.nelts; i++) {
        if (name->len >= pv[i].name.len
            && njt_strncasecmp(name->data, pv[i].name.data, pv[i].name.len)
                == 0)
        {
            return NJT_OK;
        }
    }
    
    return NJT_ERROR;
}

/*
  动态功能中，检查字符串中，是否存在未定义的变量。
  返回值：返回第一个遇到的未定义变量名。 没有则返回 “” 字符。
*/

njt_str_t
njt_http_util_check_str_variable(njt_str_t *source)
{
    u_char       ch;
    njt_str_t    name;
    njt_uint_t   i, bracket;
    njt_int_t    rc;

    for (i = 0; i < source->len; /* void */ ) {

        name.len = 0;

        if (source->data[i] == '$') {

            if (++i == source->len) {
                njt_str_set(&name,"$");
                goto invalid_variable;
            }
            if (source->data[i] == '{') {
                bracket = 1;

                if (++i == source->len) {
                    njt_str_set(&name,"{");
                    goto invalid_variable;
                }

                name.data = &source->data[i];

            } else {
                bracket = 0;
                name.data = &source->data[i];
            }

            for ( /* void */ ; i < source->len; i++, name.len++) {
                ch = source->data[i];

                if (ch == '}' && bracket) {
                    i++;
                    bracket = 0;
                    break;
                }

                if ((ch >= 'A' && ch <= 'Z')
                    || (ch >= 'a' && ch <= 'z')
                    || (ch >= '0' && ch <= '9')
                    || ch == '_')
                {
                    continue;
                }

                break;
            }

            if (bracket) {
                njt_str_set(&name,"{");
                goto invalid_variable;
            }

            if (name.len == 0) {
                njt_str_set(&name,"null variable");
                goto invalid_variable;
            }
            rc = njt_http_util_check_variable(&name);
            if(rc == NJT_ERROR) {
                goto invalid_variable;
            } 
            continue;
        }



        name.data = &source->data[i];

        while (i < source->len) {

            if (source->data[i] == '$') {
                break;
            }

            i++;
            name.len++;
        }
        //check variable  name
         
    }
njt_str_set(&name,"");
return name;

invalid_variable:
    return name;
}

njt_http_upstream_srv_conf_t* njt_http_util_find_upstream(njt_cycle_t *cycle,njt_str_t *name){
    njt_http_upstream_main_conf_t  *umcf;
    njt_http_upstream_srv_conf_t   **uscfp;
    njt_uint_t i;

    umcf = njt_http_cycle_get_module_main_conf(cycle, njt_http_upstream_module);
    if(umcf == NULL){
        return NULL;
    }	
    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {
        if (uscfp[i]->host.len != name->len
            || njt_strncasecmp(uscfp[i]->host.data, name->data, name->len) != 0) {
            continue;
        }
		njt_log_debug(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "njt_http_util_find_upstream umcf=%p,upstream=%p",umcf,uscfp[i]);
        return uscfp[i];
    }
	njt_log_debug(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "njt_http_util_find_upstream umcf=%p,upstream=NULL",umcf);
    return NULL;
}

static void njt_http_upstream_destroy(njt_http_upstream_srv_conf_t *upstream){
	if(upstream && upstream->state_file.len != 0 && upstream->state_file.data != NULL) {
		if (njt_process == NJT_PROCESS_HELPER && njt_is_privileged_agent) {
			njt_delete_file(upstream->state_file.data);
		}
	}
	if(upstream && upstream->peer.destroy_upstream) {
		upstream->peer.destroy_upstream(upstream);
	}
	if(upstream != NULL) {
		njt_log_debug(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "njt_http_upstream_destroy=%V,port=%d,ref_count=%d,client_count=%d,pool=%p",&upstream->host,upstream->port,upstream->ref_count,upstream->client_count,upstream->pool);	
	}
	njt_http_upstream_destroy_cache_domain(upstream);
}
njt_int_t njt_http_upstream_check_free(njt_http_upstream_srv_conf_t *upstream)
{
    //njt_http_upstream_t *u = (njt_http_upstream_t *)((u_char *)upstream - offsetof(njt_http_upstream_t, upstream));
    //njt_http_upstream_rr_peer_data_t  *rrp = upstream->peer.data;
	if(upstream->client_count != 0) {
		return NJT_DECLINED;
	}
	return NJT_OK;
}

void njt_http_location_upstream_destroy(njt_http_core_loc_conf_t *clcf,njt_http_request_t *r) {

	njt_http_upstream_srv_conf_t    *upstream;
	njt_http_proxy_loc_conf_t *plcf;
	njt_http_core_loc_conf_t *main_clcf;

	upstream = NULL;
	if(r->upstream != NULL && r->upstream->upstream) {
		upstream = r->upstream->upstream;
	} 
	main_clcf = njt_http_get_module_loc_conf(r,njt_http_core_module);
	if(main_clcf == clcf) {
		if(upstream != NULL && upstream->dynamic == 1) {
			plcf = clcf->loc_conf[njt_http_proxy_module.ctx_index];
			if (plcf != NULL && plcf->upstream.upstream != upstream)
			{
				njt_log_debug(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "njt_http_location_upstream_destroy=%V,ref_count=%d,client_count=%d",&upstream->host,upstream->ref_count,upstream->client_count);	
				njt_http_upstream_del((njt_cycle_t *)njt_cycle, upstream);
			}
		}
	} else {
		plcf = clcf->loc_conf[njt_http_proxy_module.ctx_index];
		if (plcf != NULL && plcf->upstream.upstream != NULL && plcf->upstream.upstream != upstream)
		{
			if(plcf->upstream.upstream != NULL && upstream != NULL) {
				njt_log_debug(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "subrequest njt_http_location_upstream_destroy=%V,ref_count=%d,client_count=%d",&plcf->upstream.upstream->host,upstream->ref_count,upstream->client_count);	
			}
			njt_http_upstream_del((njt_cycle_t *)njt_cycle, plcf->upstream.upstream);
		}
	}
	
	return;
}