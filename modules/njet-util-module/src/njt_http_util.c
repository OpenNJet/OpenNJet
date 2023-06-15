/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_core.h>
#include <njt_http.h>
#include <njt_http_util.h>

njt_http_core_srv_conf_t* njt_http_get_srv_by_port(njt_cycle_t *cycle,njt_str_t *addr_port,njt_str_t *server_name){
    njt_http_core_srv_conf_t* cscf;
    njt_listening_t *ls, *target_ls = NULL;
    njt_uint_t i,j,k;
    njt_http_server_name_t  *name;
    njt_http_port_t *port;
    njt_http_in_addr_t *addr;
    njt_http_in6_addr_t *addr6;
    njt_http_addr_conf_t *addr_conf;
    njt_http_server_name_t *sn;

    target_ls = NULL;
    cscf = NULL;
    if (server_name !=NULL && addr_port != NULL && addr_port->len > 0 ) {
        ls = cycle->listening.elts;
        for (i = 0; i < cycle->listening.nelts; i++) {
            if(ls[i].server_type != NJT_HTTP_SERVER_TYPE){
                continue; // 非http listen
            }
            if (ls[i].addr_text.len == addr_port->len &&
                njt_strncmp(ls[i].addr_text.data, addr_port->data, addr_port->len) == 0) {
                target_ls = &ls[i];
                break;
            }
        }
        if (target_ls == NULL) {
            njt_log_error(NJT_LOG_INFO, cycle->log, 0, "can`t find listen server %V",addr_port);
            return NULL;
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
            if (addr6 != NULL) {
                addr_conf = &addr6[i].conf;
            } else {
                addr_conf = &addr[i].conf;
            }
            if(addr_conf == NULL){
                continue;
            }
            cscf = addr_conf->default_server;
            name = cscf->server_names.elts;
            for(j = 0 ; j < cscf->server_names.nelts ; ++j ){
                if(name[j].name.len == server_name->len
                   && njt_strncmp(name[j].name.data,server_name->data,server_name->len) == 0){
                    return cscf;
                }
            }


            if (addr_conf->virtual_names == NULL) {
                return NULL;
            }
            cscf = njt_hash_find_combined(&addr_conf->virtual_names->names,
                                           njt_hash_key(server_name->data, server_name->len),
                                           server_name->data, server_name->len);
            if(cscf != NULL){
                return cscf;
            }
            sn = addr_conf->virtual_names->regex;
            for (k = 0; k <  addr_conf->virtual_names->nregex; ++k) {
                if(sn[i].name.len == server_name->len &&
                njt_strncasecmp(sn[i].name.data,server_name->data,server_name->len)==0){
                    return sn[i].server;
                }
            }
        }
    }
    return NULL;
}

// 获取server的listen 字符串列表
njt_int_t njt_http_get_listens_by_server(njt_array_t *array,njt_http_core_srv_conf_t  *cscf){
//    njt_hash_elt_t  **elt;
    njt_listening_t *ls;
    njt_uint_t i,j,k;
    njt_http_port_t *port;
    njt_http_in_addr_t *addr;
    njt_http_in6_addr_t *addr6;
    njt_http_addr_conf_t             *addr_conf;
    njt_str_t *listen;
    njt_http_server_name_t *sn;
    njt_http_core_srv_conf_t  *tcscf;

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
        listen = NULL;
        for (j = 0; j < port->naddrs ; ++j) {
            if(addr6 != NULL){
                addr_conf = &addr6[j].conf;
            }else{
                addr_conf = &addr[j].conf;
            }
            if(addr_conf == NULL){
                continue;
            }
            if(addr_conf->default_server == cscf){
                listen  = njt_array_push(array);
                if(listen == NULL){
                    return NJT_ERROR_ERR;
                }
                *listen = ls[i].addr_text;
                continue;
            }

            if(listen != NULL){
                continue;
            }

            if (addr_conf->virtual_names != NULL) {
                tcscf = njt_hash_find_combined(&addr_conf->virtual_names->names,
                                              njt_hash_key(cscf->server_name.data, cscf->server_name.len),
                                              cscf->server_name.data, cscf->server_name.len);
                if(cscf == tcscf){
                    listen  = njt_array_push(array);
                    if(listen == NULL){
                        return NJT_ERROR_ERR;
                    }
                    *listen = ls[i].addr_text;
                    continue;
                }
                if(listen != NULL){
                    continue;
                }
                sn = addr_conf->virtual_names->regex;
                for (k = 0; k <  addr_conf->virtual_names->nregex; ++k) {
                    if(sn[i].server == cscf){
                        listen  = njt_array_push(array);
                        if(listen == NULL){
                            return NJT_ERROR_ERR;
                        }
                        *listen = ls[i].addr_text;
                        continue;
                    }
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
    if (body_chain->buf->file) {
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
