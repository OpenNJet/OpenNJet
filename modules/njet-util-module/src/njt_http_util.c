/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_core.h>
#include <njt_http.h>
#include <njt_http_proxy_module.h>
#include <njt_http_util.h>
extern njt_module_t  njt_http_proxy_module;

njt_http_core_srv_conf_t* njt_http_get_srv_by_port(njt_cycle_t *cycle,njt_str_t *addr_port,njt_str_t *server_name){
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
    njt_str_t server_low_name;
	njt_url_t  u;
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
	
	server_low_name.data = njt_pnalloc(pool,server_name->len);
	if(server_low_name.data == NULL) {
		goto out;
	}
	server_low_name.len = server_name->len;
	njt_strlow(server_low_name.data, server_name->data,server_name->len);

	server_name = &server_low_name;

	    ls = cycle->listening.elts;
	    for (i = 0; i < cycle->listening.nelts; i++) {
            if(ls[i].server_type != NJT_HTTP_SERVER_TYPE){
                continue; // 非http listen
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
                if(server_name->data[0] != '~' && name[j].full_name.len == server_name->len
                   && njt_strncmp(name[j].full_name.data,server_name->data,server_name->len) == 0){
					ret_cscf = cscf;
                    goto out;
                } else if(server_name->data[0] == '~' && name[j].full_name.len == server_name->len
                   && njt_strncasecmp(name[j].full_name.data,server_name->data,server_name->len) == 0){
					ret_cscf = cscf;
                    goto out;
                }
            }


            if (addr_conf->virtual_names != NULL) {

                if(server_name->len > 0 && server_name->data[0] == '~') {
                     sn = addr_conf->virtual_names->regex;
                    for (k = 0; k <  addr_conf->virtual_names->nregex; ++k) {
                        if(sn[k].full_name.len == server_name->len &&
                        njt_strncasecmp(sn[k].full_name.data,server_name->data,server_name->len)==0){
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
    njt_http_in6_addr_t *addr6;
    njt_http_addr_conf_t             *addr_conf;
    njt_str_t *listen, data;
    njt_http_server_name_t *sn;
    njt_http_core_srv_conf_t  *tcscf;
	 struct sockaddr          *sockaddr;
	 struct sockaddr_in6  *sin6, ssin6;
	 struct sockaddr_in   *sin,   ssin;
	 in_port_t  nport;
	//njt_uint_t  addr_len = NJT_SOCKADDR_STRLEN;
    ls = njt_cycle->listening.elts;
    for (i = 0; i < njt_cycle->listening.nelts; ++i) {
        if(ls[i].server_type != NJT_HTTP_SERVER_TYPE){
            continue; // 非http listen
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

 void njt_http_location_destroy(njt_http_core_loc_conf_t *clcf) {
    njt_queue_t *q;
	njt_queue_t *locations;
    njt_http_location_queue_t *lq;
    njt_http_core_loc_conf_t *new_clcf;
    njt_http_proxy_loc_conf_t    *plcf;
     njt_http_upstream_srv_conf_t    *upstream;

    locations = clcf->old_locations;
    if (locations != NULL) {
        for (q = njt_queue_head(locations);
             q != njt_queue_sentinel(locations);
             ) {
            lq = (njt_http_location_queue_t *) q;
	    q = njt_queue_next(q);
	    njt_queue_remove(&lq->queue);
            if (lq->exact != NULL) {
                new_clcf = lq->exact;
                njt_http_location_destroy(new_clcf);
            } else if (lq->inclusive != NULL) {
                new_clcf = lq->inclusive;
                njt_http_location_destroy(new_clcf); //zyg
            }
			
        }
    }
    njt_http_location_cleanup(clcf);
    clcf->disable = 1;
    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "njt_destroy_pool clcf=%p,name=%V,pool=%p,ref_count=%i",clcf,&clcf->name,clcf->pool,clcf->ref_count);
    if (clcf->ref_count == 0 && clcf->pool != NULL && clcf->dynamic_status != 0) {
        plcf = clcf->loc_conf[njt_http_proxy_module.ctx_index];
        if(plcf != NULL && plcf->upstream.upstream != NULL) {
            upstream = plcf->upstream.upstream;
            upstream->ref_count --;
            if(upstream->ref_count == 0) {
                njt_http_upstream_del(upstream);
            }
        }
        njt_destroy_pool(clcf->pool);
    }
}

#if(NJT_HTTP_DYNAMIC_UPSTREAM)
void njt_http_upstream_del(njt_http_upstream_srv_conf_t *upstream) {

    njt_uint_t                      i;
    njt_http_upstream_srv_conf_t   **uscfp;
    njt_http_upstream_main_conf_t  *umcf;

    umcf = njt_http_cycle_get_module_main_conf(njt_cycle, njt_http_upstream_module);

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {
        if(uscfp[i] == upstream) {
            if(i != umcf->upstreams.nelts-1) {
                uscfp[i] = uscfp[umcf->upstreams.nelts-1];
            } 
            umcf->upstreams.nelts--;
            njt_destroy_pool(upstream->pool);
            break;
        }
    }
}
#endif
  
