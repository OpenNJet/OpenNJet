/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_core.h>
#include <njt_stream.h>

njt_stream_core_srv_conf_t *njt_stream_get_srv_by_port(njt_cycle_t *cycle, njt_str_t *addr_port)
{
    njt_stream_core_srv_conf_t *cscf;
    njt_uint_t i, j, worker;
    njt_listening_t *ls;
    njt_stream_port_t *port;
    njt_stream_in_addr_t *addr;
    njt_stream_addr_conf_t *addr_conf;
#if (NJT_HAVE_INET6)
    njt_stream_in6_addr_t *addr6;
#endif
    worker = njt_worker;
    if (njt_process == NJT_PROCESS_HELPER && njt_is_privileged_agent) {
        worker = 0;
    }

    ls = njt_cycle->listening.elts;
    cscf=NULL;
    for (i = 0; i < njt_cycle->listening.nelts; ++i) {
        if (ls[i].server_type != NJT_STREAM_SERVER_TYPE) {
            continue; // not stream server
        }
        if (ls[i].reuseport && ls[i].worker != worker) {
            continue;
        }
        port = ls[i].servers;
        addr = NULL;
        addr6 = NULL;
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

        for (j = 0; j < port->naddrs; ++j) {
            if (addr6 != NULL) {
                addr_conf = &addr6[j].conf;
            } else {
                addr_conf = &addr[j].conf;
            }
            if (addr_conf == NULL) {
                continue;
            }

            if (njt_strncmp(addr_conf->addr_text.data, addr_port->data, addr_port->len) ==0){
               cscf = (njt_stream_core_srv_conf_t *)addr_conf->ctx->srv_conf[0];
               return cscf; 
            }
            
        }
    }

    return NULL;
}

njt_int_t njt_stream_get_listens_by_server(njt_array_t *array,
    njt_stream_core_srv_conf_t *cscf)
{
    njt_uint_t i, j, worker;
    njt_str_t *listen;
    njt_listening_t *ls;
    njt_stream_port_t *port;
    njt_stream_in_addr_t *addr;
    njt_stream_addr_conf_t *addr_conf;
#if (NJT_HAVE_INET6)
    njt_stream_in6_addr_t *addr6;
#endif
    worker = njt_worker;
    if (njt_process == NJT_PROCESS_HELPER && njt_is_privileged_agent) {
        worker = 0;
    }

    ls = njt_cycle->listening.elts;
    for (i = 0; i < njt_cycle->listening.nelts; ++i) {
        if (ls[i].server_type != NJT_STREAM_SERVER_TYPE) {
            continue; // not stream server
        }
        if (ls[i].reuseport && ls[i].worker != worker) {
            continue;
        }
        port = ls[i].servers;
        addr = NULL;
        addr6 = NULL;
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

        for (j = 0; j < port->naddrs; ++j) {
            if (addr6 != NULL) {
                addr_conf = &addr6[j].conf;
            } else {
                addr_conf = &addr[j].conf;
            }
            if (addr_conf == NULL) {
                continue;
            }
            listen = NULL;
            if ((njt_stream_core_srv_conf_t *)addr_conf->ctx->srv_conf[0] == cscf) {
                listen = njt_array_push(array);
                if (listen == NULL) {
                    return NJT_ERROR_ERR;
                }
                *listen = addr_conf->addr_text;
            }
        }
    }
    return NJT_OK;
}