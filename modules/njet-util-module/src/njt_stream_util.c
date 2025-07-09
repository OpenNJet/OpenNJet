/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_core.h>
#include <njt_stream.h>
extern njt_str_t njt_get_command_unique_name(njt_pool_t *pool,njt_str_t src);

// 获取server的listen 字符串列表
njt_int_t njt_stream_get_listens_by_server(njt_array_t *array,njt_stream_core_srv_conf_t  *cscf){
//    njt_hash_elt_t  **elt;
	njt_listening_t *ls;
	njt_uint_t i,j,k,len;
	njt_stream_port_t *port;
	njt_stream_in_addr_t *addr;
	njt_uint_t         worker;
	njt_stream_in6_addr_t *addr6;
	njt_stream_addr_conf_t             *addr_conf;   //(njt_process == NJT_PROCESS_HELPER && njt_is_privileged_agent)  if (!ls[i].reuseport || ls[i].worker != 0)
	njt_str_t *listen, data;
	njt_stream_server_name_t *sn;
	njt_stream_core_srv_conf_t  *tcscf;
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
		if(ls[i].server_type != NJT_STREAM_SERVER_TYPE){
			continue; // 非stream listen
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


njt_stream_core_srv_conf_t* njt_stream_get_srv_by_server_name(njt_cycle_t *cycle,njt_str_t *addr_port,njt_str_t *server_name){
	njt_stream_core_srv_conf_t* cscf, *ret_cscf;
	njt_listening_t *ls, *target_ls = NULL;
	njt_uint_t i,j,k;
	in_port_t  nport;
	njt_stream_server_name_t  *name;
	njt_stream_port_t *port;
	njt_stream_in_addr_t *addr;
	njt_stream_in6_addr_t *addr6;
	njt_stream_addr_conf_t *addr_conf;
	njt_stream_server_name_t *sn;
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
				njt_log_error(NJT_LOG_ERR, cycle->log, 0, "njt_stream_get_srv_by_port alloc error!");
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
			if(ls[i].server_type != NJT_STREAM_SERVER_TYPE){
				continue; // 非stream listen
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

njt_stream_core_srv_conf_t* njt_stream_get_srv_by_port(njt_cycle_t *cycle,njt_str_t *addr_port,njt_str_t *server_name){

	njt_pool_t  *pool;
	njt_str_t   name;
	njt_stream_core_srv_conf_t* srv;

	njt_log_error(NJT_LOG_DEBUG, cycle->log, 0, "njt_stream_get_srv_by_port server_name = %V",server_name);
	pool = njt_create_pool(1024, njt_cycle->log);
	if(pool == NULL) {
		return NULL;
	}
	name = njt_get_command_unique_name(pool,*server_name);
	srv = njt_stream_get_srv_by_server_name(cycle,addr_port,&name); 

	njt_destroy_pool(pool);
	return srv;
}
