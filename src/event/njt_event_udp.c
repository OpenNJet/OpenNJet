
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>

#if !(NJT_WIN32)

static void njt_close_accepted_udp_connection(njt_connection_t *c);
static ssize_t njt_udp_shared_recv(njt_connection_t *c, u_char *buf,
    size_t size);
static njt_int_t njt_insert_udp_connection(njt_connection_t *c);
static njt_connection_t *njt_lookup_udp_connection(njt_listening_t *ls,
    struct sockaddr *sockaddr, socklen_t socklen,
    struct sockaddr *local_sockaddr, socklen_t local_socklen);


void
njt_event_recvmsg(njt_event_t *ev)
{
    ssize_t            n;
    njt_buf_t          buf;
    njt_log_t         *log;
    njt_err_t          err;
    socklen_t          socklen, local_socklen;
    njt_event_t       *rev, *wev;
    struct iovec       iov[1];
    struct msghdr      msg;
    njt_sockaddr_t     sa, lsa;
    struct sockaddr   *sockaddr, *local_sockaddr;
    njt_listening_t   *ls;
    njt_event_conf_t  *ecf;
    njt_connection_t  *c, *lc;
    static u_char      buffer[65535];

    //add by clb for udp traffic hack
    struct cmsghdr    *cmsg_tmp;
    struct sockaddr_in *tmp_real_dst_addr = NULL; // for gcc-9 build
    struct sockaddr_in *tmp_local_addr;
    struct sockaddr_in6 *tmp_real_dst_addr6;
    struct sockaddr_in6 *tmp_local_addr6;
    njt_uint_t         found = 0;
    //end by clb

#if (NJT_HAVE_ADDRINFO_CMSG)
    //modify by clb, udp traffic hack need more memory(old 32bytes, modify to 256 bytes)
    // u_char             msg_control[CMSG_SPACE(sizeof(njt_addrinfo_t))];
    u_char             msg_control[256];
    //end modify by clb
#endif

    if (ev->timedout) {
        if (njt_enable_accept_events((njt_cycle_t *) njt_cycle) != NJT_OK) {
            return;
        }

        ev->timedout = 0;
    }

    ecf = njt_event_get_conf(njt_cycle->conf_ctx, njt_event_core_module);

    if (!(njt_event_flags & NJT_USE_KQUEUE_EVENT)) {
        ev->available = ecf->multi_accept;
    }

    lc = ev->data;
    ls = lc->listening;
    ev->ready = 0;

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, ev->log, 0,
                   "recvmsg on %V, ready: %d", &ls->addr_text, ev->available);

    do {
        njt_memzero(&msg, sizeof(struct msghdr));

        iov[0].iov_base = (void *) buffer;
        iov[0].iov_len = sizeof(buffer);

        msg.msg_name = &sa;
        msg.msg_namelen = sizeof(njt_sockaddr_t);
        msg.msg_iov = iov;
        msg.msg_iovlen = 1;

#if (NJT_HAVE_ADDRINFO_CMSG)
        if (ls->wildcard || ls->mesh) {
            msg.msg_control = &msg_control;
            msg.msg_controllen = sizeof(msg_control);
            njt_memzero(&msg_control, sizeof(msg_control));
        }
#endif

        n = recvmsg(lc->fd, &msg, 0);

        if (n == -1) {
            err = njt_socket_errno;

            if (err == NJT_EAGAIN) {
                njt_log_debug0(NJT_LOG_DEBUG_EVENT, ev->log, err,
                               "recvmsg() not ready");
                return;
            }

            njt_log_error(NJT_LOG_ALERT, ev->log, err, "recvmsg() failed");

            return;
        }

#if (NJT_HAVE_ADDRINFO_CMSG)
        if (msg.msg_flags & (MSG_TRUNC|MSG_CTRUNC)) {
            njt_log_error(NJT_LOG_ALERT, ev->log, 0,
                          "recvmsg() truncated data");
            continue;
        }
#endif

        sockaddr = msg.msg_name;
        socklen = msg.msg_namelen;

        if (socklen > (socklen_t) sizeof(njt_sockaddr_t)) {
            socklen = sizeof(njt_sockaddr_t);
        }

        if (socklen == 0) {

            /*
             * on Linux recvmsg() returns zero msg_namelen
             * when receiving packets from unbound AF_UNIX sockets
             */

            socklen = sizeof(struct sockaddr);
            njt_memzero(&sa, sizeof(struct sockaddr));
            sa.sockaddr.sa_family = ls->sockaddr->sa_family;
        }

        local_sockaddr = ls->sockaddr;
        local_socklen = ls->socklen;

#if (NJT_HAVE_ADDRINFO_CMSG)
        if (ls->wildcard) {
            struct cmsghdr  *cmsg;

            njt_memcpy(&lsa, local_sockaddr, local_socklen);
            local_sockaddr = &lsa.sockaddr;

            for (cmsg = CMSG_FIRSTHDR(&msg);
                 cmsg != NULL;
                 cmsg = CMSG_NXTHDR(&msg, cmsg))
            {
                if (njt_get_srcaddr_cmsg(cmsg, local_sockaddr) == NJT_OK) {
                    break;
                }
            }
        }

#endif

        c = njt_lookup_udp_connection(ls, sockaddr, socklen, local_sockaddr,
                                      local_socklen);

        if (c) {

#if (NJT_DEBUG)
            if (c->log->log_level & NJT_LOG_DEBUG_EVENT) {
                njt_log_handler_pt  handler;

                handler = c->log->handler;
                c->log->handler = NULL;

                njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                               "recvmsg: fd:%d n:%z", c->fd, n);

                c->log->handler = handler;
            }
#endif

            njt_memzero(&buf, sizeof(njt_buf_t));

            buf.pos = buffer;
            buf.last = buffer + n;

            rev = c->read;

            c->udp->buffer = &buf;

            rev->ready = 1;
            rev->active = 0;

            rev->handler(rev);

            if (c->udp) {
                c->udp->buffer = NULL;
            }

            rev->ready = 0;
            rev->active = 1;

            goto next;
        }

#if (NJT_STAT_STUB)
        (void) njt_atomic_fetch_add(njt_stat_accepted, 1);
#endif



        njt_accept_disabled = njt_cycle->connection_n / 8
                              - njt_cycle->free_connection_n;

        c = njt_get_connection(lc->fd, ev->log);
        if (c == NULL) {
            return;
        }

        c->shared = 1;
        c->type = SOCK_DGRAM;
        c->socklen = socklen;

#if (NJT_STAT_STUB)
        (void) njt_atomic_fetch_add(njt_stat_active, 1);
#endif

        c->pool = njt_create_pool(ls->pool_size, ev->log);
        if (c->pool == NULL) {
            njt_close_accepted_udp_connection(c);
            return;
        }

        c->sockaddr = njt_palloc(c->pool, socklen);
        if (c->sockaddr == NULL) {
            njt_close_accepted_udp_connection(c);
            return;
        }

        njt_memcpy(c->sockaddr, sockaddr, socklen);

        log = njt_palloc(c->pool, sizeof(njt_log_t));
        if (log == NULL) {
            njt_close_accepted_udp_connection(c);
            return;
        }

        *log = ls->log;

        c->recv = njt_udp_shared_recv;
        c->send = njt_udp_send;
        c->send_chain = njt_udp_send_chain;

        c->need_flush_buf = 1;

        c->log = log;
        c->pool->log = log;
        c->listening = ls;

        if (local_sockaddr == &lsa.sockaddr) {
            local_sockaddr = njt_palloc(c->pool, local_socklen);
            if (local_sockaddr == NULL) {
                njt_close_accepted_udp_connection(c);
                return;
            }

            njt_memcpy(local_sockaddr, &lsa, local_socklen);
        }

        c->local_sockaddr = local_sockaddr;
        c->local_socklen = local_socklen;

        c->buffer = njt_create_temp_buf(c->pool, n);
        if (c->buffer == NULL) {
            njt_close_accepted_udp_connection(c);
            return;
        }

        c->buffer->last = njt_cpymem(c->buffer->last, buffer, n);

        rev = c->read;
        wev = c->write;

        rev->active = 1;
        wev->ready = 1;

        rev->log = log;
        wev->log = log;

        /*
         * TODO: MT: - njt_atomic_fetch_add()
         *             or protection by critical section or light mutex
         *
         * TODO: MP: - allocated in a shared memory
         *           - njt_atomic_fetch_add()
         *             or protection by critical section or light mutex
         */

        c->number = njt_atomic_fetch_add(njt_connection_counter, 1);

        c->start_time = njt_current_msec;

#if (NJT_STAT_STUB)
        (void) njt_atomic_fetch_add(njt_stat_handled, 1);
#endif

        if (ls->addr_ntop) {
            c->addr_text.data = njt_pnalloc(c->pool, ls->addr_text_max_len);
            if (c->addr_text.data == NULL) {
                njt_close_accepted_udp_connection(c);
                return;
            }

            c->addr_text.len = njt_sock_ntop(c->sockaddr, c->socklen,
                                             c->addr_text.data,
                                             ls->addr_text_max_len, 0);
            if (c->addr_text.len == 0) {
                njt_close_accepted_udp_connection(c);
                return;
            }
        }

#if (NJT_DEBUG)
        {
        njt_str_t  addr;
        u_char     text[NJT_SOCKADDR_STRLEN];

        njt_debug_accepted_connection(ecf, c);

        if (log->log_level & NJT_LOG_DEBUG_EVENT) {
            addr.data = text;
            addr.len = njt_sock_ntop(c->sockaddr, c->socklen, text,
                                     NJT_SOCKADDR_STRLEN, 1);

            njt_log_debug4(NJT_LOG_DEBUG_EVENT, log, 0,
                           "*%uA recvmsg: %V fd:%d n:%z",
                           c->number, &addr, c->fd, n);
        }

        }
#endif

        if (njt_insert_udp_connection(c) != NJT_OK) {
            njt_close_accepted_udp_connection(c);
            return;
        }

        //add by clb, used for udp traffic hack
        if(ls->mesh){
            found = 0;
            if(AF_INET == ls->sockaddr->sa_family){
                for(cmsg_tmp = CMSG_FIRSTHDR(&msg); cmsg_tmp != NULL; cmsg_tmp = CMSG_NXTHDR(&msg, cmsg_tmp)){
                    if(cmsg_tmp->cmsg_level == SOL_IP && cmsg_tmp->cmsg_type == IP_RECVORIGDSTADDR){
                        tmp_local_addr = (struct sockaddr_in*)local_sockaddr;
                        memcpy(&c->mesh_dst_addr, CMSG_DATA(cmsg_tmp), sizeof(struct sockaddr_in));
                        tmp_real_dst_addr = (struct sockaddr_in *)&c->mesh_dst_addr;
                        // njt_log_error(NJT_LOG_ALERT, ev->log, 0,
                        //     "==================ipv4 port:%d", ntohs(tmp_real_dst_addr->sin_port));
                        if(ntohs(tmp_local_addr->sin_port) == ntohs(tmp_real_dst_addr->sin_port)){
                            break;
                        }

                        found = 1;
                        break;
                    }
                }
            }else if(AF_INET6 == ls->sockaddr->sa_family){
                for(cmsg_tmp = CMSG_FIRSTHDR(&msg); cmsg_tmp != NULL; cmsg_tmp = CMSG_NXTHDR(&msg, cmsg_tmp)){
                    if(cmsg_tmp->cmsg_level == SOL_IPV6 && cmsg_tmp->cmsg_type == IPV6_RECVORIGDSTADDR){
                        tmp_local_addr6 = (struct sockaddr_in6*)local_sockaddr;

                        memcpy(&c->mesh_dst_addr, CMSG_DATA(cmsg_tmp), sizeof(struct sockaddr_in6));
                        tmp_real_dst_addr6 = (struct sockaddr_in6 *)&c->mesh_dst_addr;
                        // njt_log_error(NJT_LOG_ALERT, ev->log, 0,
                        //     "==================ipv6 port:%d", ntohs(tmp_real_dst_addr6->sin6_port));
                        if(ntohs(tmp_local_addr6->sin6_port) == ntohs(tmp_real_dst_addr6->sin6_port)){
                            break;
                        }

                        found = 1;
                        break;
                    }
                }
            }

            if(found){
                //create udp socket
                c->udp->real_sock = njt_socket(c->mesh_dst_addr.ss_family, SOCK_DGRAM, 0);
                if (c->udp->real_sock == (njt_socket_t) -1) {
                    njt_log_error(NJT_LOG_ALERT, ev->log, 0,
                            "udp create real sock error, port:%d", ntohs(tmp_real_dst_addr->sin_port));
                }else{
                    if(njt_nonblocking(c->udp->real_sock) == -1)
                    {
                        njt_log_error(NJT_LOG_ALERT, ev->log, 0,
                            "udp set real sock nonblocking error, port:%d", ntohs(tmp_real_dst_addr->sin_port));
                    }

                    int  reuseport = 1;
    #ifdef SO_REUSEPORT_LB
                    if (setsockopt(c->udp->real_sock, SOL_SOCKET, SO_REUSEPORT_LB,
                                (const void *) &reuseport, sizeof(int))
                        == -1)
                    {
                        njt_log_error(NJT_LOG_ALERT, ev->log, 0,
                            "udp real sock set sock reuseport error, port:%d", ntohs(tmp_real_dst_addr->sin_port));
                    }
    #else
                    if (setsockopt(c->udp->real_sock, SOL_SOCKET, SO_REUSEPORT,
                                (const void *) &reuseport, sizeof(int))
                        == -1)
                    {
                        njt_log_error(NJT_LOG_ALERT, ev->log, 0,
                            "udp real sock set sock reuseport error, port:%d", ntohs(tmp_real_dst_addr->sin_port));
                    }
    #endif
                    //bind real port info
                    if(AF_INET == c->mesh_dst_addr.ss_family){
                        if(bind(c->udp->real_sock, (struct sockaddr*)&c->mesh_dst_addr, sizeof(struct sockaddr_in)) <0)
                        {
                            njt_log_error(NJT_LOG_ALERT, ev->log, 0,
                                "udp real sock bind error(ipv4), port:%d", ntohs(tmp_real_dst_addr->sin_port));
                        }
                    }else if(AF_INET6 == c->mesh_dst_addr.ss_family){
                        if(bind(c->udp->real_sock, (struct sockaddr*)&c->mesh_dst_addr, sizeof(struct sockaddr_in6)) <0)
                        {
                            njt_log_error(NJT_LOG_ALERT, ev->log, 0,
                                "udp real sock bind error(ipv6), port:%d", ntohs(tmp_real_dst_addr->sin_port));
                        }
                    }
                }
            }else{
                //set local addr
                if(AF_INET == ls->sockaddr->sa_family){
                    memcpy(&c->mesh_dst_addr, local_sockaddr, sizeof(struct sockaddr_in));
                }else if(AF_INET6 == ls->sockaddr->sa_family){
                    memcpy(&c->mesh_dst_addr, local_sockaddr, sizeof(struct sockaddr_in6));
                }
            }
        }
        //end by clb

        log->data = NULL;
        log->handler = NULL;

        ls->handler(c);

    next:

        if (njt_event_flags & NJT_USE_KQUEUE_EVENT) {
            ev->available -= n;
        }

    } while (ev->available);
}


static void
njt_close_accepted_udp_connection(njt_connection_t *c)
{
    njt_free_connection(c);

    c->fd = (njt_socket_t) -1;

    if (c->pool) {
        njt_destroy_pool(c->pool);
    }

#if (NJT_STAT_STUB)
    (void) njt_atomic_fetch_add(njt_stat_active, -1);
#endif
}


static ssize_t
njt_udp_shared_recv(njt_connection_t *c, u_char *buf, size_t size)
{
    ssize_t     n;
    njt_buf_t  *b;

    if (c->udp == NULL || c->udp->buffer == NULL) {
        return NJT_AGAIN;
    }

    b = c->udp->buffer;

    n = njt_min(b->last - b->pos, (ssize_t) size);

    njt_memcpy(buf, b->pos, n);

    c->udp->buffer = NULL;

    c->read->ready = 0;
    c->read->active = 1;

    return n;
}


void
njt_udp_rbtree_insert_value(njt_rbtree_node_t *temp,
    njt_rbtree_node_t *node, njt_rbtree_node_t *sentinel)
{
    njt_int_t               rc;
    njt_connection_t       *c, *ct;
    njt_rbtree_node_t     **p;
    njt_udp_connection_t   *udp, *udpt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            udp = (njt_udp_connection_t *) node;
            c = udp->connection;

            udpt = (njt_udp_connection_t *) temp;
            ct = udpt->connection;

            rc = njt_memn2cmp(udp->key.data, udpt->key.data,
                              udp->key.len, udpt->key.len);

            if (rc == 0 && c->listening->wildcard) {
                rc = njt_cmp_sockaddr(c->local_sockaddr, c->local_socklen,
                                      ct->local_sockaddr, ct->local_socklen, 1);
            }

            p = (rc < 0) ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
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


static njt_int_t
njt_insert_udp_connection(njt_connection_t *c)
{
    uint32_t               hash;
    njt_pool_cleanup_t    *cln;
    njt_udp_connection_t  *udp;

    if (c->udp) {
        return NJT_OK;
    }

    udp = njt_pcalloc(c->pool, sizeof(njt_udp_connection_t));
    if (udp == NULL) {
        return NJT_ERROR;
    }

    udp->connection = c;
    udp->real_sock = (njt_socket_t)-1;

    njt_crc32_init(hash);
    njt_crc32_update(&hash, (u_char *) c->sockaddr, c->socklen);

    if (c->listening->wildcard) {
        njt_crc32_update(&hash, (u_char *) c->local_sockaddr, c->local_socklen);
    }

    njt_crc32_final(hash);

    udp->node.key = hash;
    udp->key.data = (u_char *) c->sockaddr;
    udp->key.len = c->socklen;

    cln = njt_pool_cleanup_add(c->pool, 0);
    if (cln == NULL) {
        return NJT_ERROR;
    }

    cln->data = c;
    cln->handler = njt_delete_udp_connection;

    njt_rbtree_insert(&c->listening->rbtree, &udp->node);

    c->udp = udp;

    return NJT_OK;
}


void
njt_delete_udp_connection(void *data)
{
    njt_connection_t  *c = data;

    if (c->udp == NULL) {
        return;
    }

    njt_rbtree_delete(&c->listening->rbtree, &c->udp->node);

    c->udp = NULL;
}


static njt_connection_t *
njt_lookup_udp_connection(njt_listening_t *ls, struct sockaddr *sockaddr,
    socklen_t socklen, struct sockaddr *local_sockaddr, socklen_t local_socklen)
{
    uint32_t               hash;
    njt_int_t              rc;
    njt_connection_t      *c;
    njt_rbtree_node_t     *node, *sentinel;
    njt_udp_connection_t  *udp;

#if (NJT_HAVE_UNIX_DOMAIN)

    if (sockaddr->sa_family == AF_UNIX) {
        struct sockaddr_un *saun = (struct sockaddr_un *) sockaddr;

        if (socklen <= (socklen_t) offsetof(struct sockaddr_un, sun_path)
            || saun->sun_path[0] == '\0')
        {
            njt_log_debug0(NJT_LOG_DEBUG_EVENT, njt_cycle->log, 0,
                           "unbound unix socket");
            return NULL;
        }
    }

#endif

    node = ls->rbtree.root;
    sentinel = ls->rbtree.sentinel;

    njt_crc32_init(hash);
    njt_crc32_update(&hash, (u_char *) sockaddr, socklen);

    if (ls->wildcard) {
        njt_crc32_update(&hash, (u_char *) local_sockaddr, local_socklen);
    }

    njt_crc32_final(hash);

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        udp = (njt_udp_connection_t *) node;

        c = udp->connection;

        rc = njt_cmp_sockaddr(sockaddr, socklen,
                              c->sockaddr, c->socklen, 1);

        if (rc == 0 && ls->wildcard) {
            rc = njt_cmp_sockaddr(local_sockaddr, local_socklen,
                                  c->local_sockaddr, c->local_socklen, 1);
        }

        if (rc == 0) {
            return c;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}

#else

void
njt_delete_udp_connection(void *data)
{
    return;
}

#endif
