/*************************************************************************************
 Copyright (C), 2021-2023, TMLake(Beijing) Technology Ltd.,
 File name    : njt_http_util.c
 Version      : 1.0
 Author       : ChengXu
 Date         : 2023/2/27/027 
 Description  : 
 Other        :
 History      :
 <author>       <time>          <version >      <desc>
 ChengXu        2023/2/27/027       1.1             
***********************************************************************************/
//
// Created by Administrator on 2023/2/27/027.
//

#include <njt_core.h>
#include <njt_http.H>
#include <njt_http_util.h>

njt_http_core_srv_conf_t* njt_http_get_srv_by_port(njt_cycle_t *cycle,njt_pool_t *pool,njt_str_t *addr_port,njt_str_t *server_name){
    njt_http_core_srv_conf_t* cscf;
    njt_listening_t *ls, *target_ls;
    njt_uint_t i, len;
    u_char *last;
    u_char *p;
    njt_str_t  dport;
    njt_str_t wide_addr = njt_string("0.0.0.0");
    njt_http_port_t *port;
    njt_url_t u;
    struct sockaddr local_sockaddr;
    struct sockaddr_in *sin;
    njt_http_in_addr_t *addr;
    njt_http_connection_t hc;
    njt_http_virtual_names_t *virtual_names;
    njt_str_t  sport;


    cscf = NULL;
    if (addr_port->len > 0) {
        ls = cycle->listening.elts;
        for (i = 0; i < cycle->listening.nelts; i++) {
            if (ls[i].addr_text.len == addr_port->len &&
                njt_strncmp(ls[i].addr_text.data, addr_port->data, addr_port->len) == 0) {
                target_ls = &ls[i];
                break;
            } else {
                njt_memzero(&sport , sizeof(njt_str_t));
                last = addr_port->data + addr_port->len;
                p = njt_strlchr(addr_port->data, last, ':');
                if(p != NULL){
                    sport.data = p+1;
                    sport.len = last - sport.data;
                }
                last = ls[i].addr_text.data + ls[i].addr_text.len;
                p = njt_strlchr(ls[i].addr_text.data, last, ':');
                if (p != NULL) {
                    dport.data = p + 1;
                    dport.len = last - dport.data;
                    len = p - ls[i].addr_text.data;
                    if (dport.len == sport.len && njt_strncmp(dport.data, sport.data, dport.len) == 0
                        && wide_addr.len == len
                        && njt_strncmp(wide_addr.data, ls[i].addr_text.data, wide_addr.len) == 0) {
                        target_ls = &ls[i];
                        //todo 处理default
                        break;
                    }
                }
            }
        }
        if (target_ls == NULL) {
            return NULL;
        }
        port = target_ls->servers;
        if (port->naddrs > 1) {
            njt_memzero(&u, sizeof(njt_url_t));
            u.url = *addr_port;
            u.default_port = 80;
            njt_parse_url(pool, &u);
            njt_memcpy(&local_sockaddr, &u.sockaddr, u.socklen);
            sin = (struct sockaddr_in *) &local_sockaddr;

            addr = port->addrs;
            for (i = 0; i < port->naddrs - 1; i++) {
                if (addr[i].addr == sin->sin_addr.s_addr) {
                    break;
                }
            }
            hc.addr_conf = &addr[i].conf;
        } else {
            addr = port->addrs;
            hc.addr_conf = &addr[0].conf;
        }
        hc.conf_ctx = hc.addr_conf->default_server->ctx;
        virtual_names = hc.addr_conf->virtual_names;
        if (virtual_names != NULL) {
            cscf = njt_hash_find_combined(&virtual_names->names,
                                          njt_hash_key(server_name->data, server_name->len),
                                          server_name->data, server_name->len);
        }
        if(cscf == NULL && virtual_names != NULL && server_name->len > 0 && server_name->data != NULL) {
            njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "no find server add_port=%V,server_name=%V",&addr_port,&server_name);
            return NULL;
        }
        if (cscf == NULL) {
            cscf = njt_http_get_module_srv_conf(hc.conf_ctx, njt_http_core_module);
        }
    } else {
        cscf = NULL;
    }
    return cscf;
}

// 获取server的listen 字符串列表
njt_int_t njt_http_get_listens_by_server(njt_array_t *array,njt_http_core_srv_conf_t  *cscf){
    njt_hash_elt_t  **elt;
    njt_listening_t *ls;
    njt_uint_t i,j,k;
    njt_http_port_t *port;
    njt_http_in_addr_t *addr;
    njt_http_addr_conf_t             *addr_conf;
    njt_str_t *listen;

    ls = njt_cycle->listening.elts;
    for (i = 0; i < njt_cycle->listening.nelts; ++i) {
        port = ls[i].servers;
        addr = port->addrs;
        for (j = 0; j < port->naddrs ; ++j) {
            addr_conf = &addr[j].conf;
            if(addr_conf->default_server == cscf){
                listen  = njt_array_push(array);
                if(listen == NULL){
                    return NJT_ERROR_ERR;
                }
                *listen = ls[i].addr_text;
            }
            if(addr_conf->virtual_names == NULL ){
                continue;
            }
            elt = addr_conf->virtual_names->names.hash.buckets;
            for(k = 0 ; k < addr_conf->virtual_names->names.hash.size;++k){
                if(elt[k] != NULL ){
                    if(elt[k]->value == cscf ){
                        listen  = njt_array_push(array);
                        if(listen == NULL){
                            return NJT_ERROR_ERR;
                        }
                        *listen = ls[i].addr_text;
                    }
                }
            }
            if(addr_conf->virtual_names->names.wc_head != NULL){
                elt = addr_conf->virtual_names->names.wc_head->hash.buckets;
                for(k = 0 ; k < addr_conf->virtual_names->names.wc_head->hash.size;++k){
                    if(elt[k] != NULL ){
                        if(elt[k]->value == cscf ){
                            listen  = njt_array_push(array);
                            if(listen == NULL){
                                return NJT_ERROR_ERR;
                            }
                            *listen = ls[i].addr_text;
                        }
                    }
                }
            }
            if(addr_conf->virtual_names->names.wc_tail != NULL){
                elt = addr_conf->virtual_names->names.wc_tail->hash.buckets;
                for(k = 0 ; k < addr_conf->virtual_names->names.wc_tail->hash.size;++k){
                    if(elt[k] != NULL ){
                        if(elt[k]->value == cscf ){
                            listen  = njt_array_push(array);
                            if(listen == NULL){
                                return NJT_ERROR_ERR;
                            }
                            *listen = ls[i].addr_text;
                        }
                    }
                }
            }
        }
    }
    return NJT_OK;
}
