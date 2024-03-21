
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>

// openresty patch
#if !(NJT_WIN32)
#include <resolv.h>
#endif
// openresty patch end


#define NJT_RESOLVER_UDP_SIZE   4096

#define NJT_RESOLVER_TCP_RSIZE  (2 + 65535)
#define NJT_RESOLVER_TCP_WSIZE  8192

// openresty patch
#if !(NJT_WIN32)
/*
 * note that 2KB should be more than enough for majority of the
 * resolv.conf files out there. it also acts as a safety guard to prevent
 * abuse.
 */
#define NJT_RESOLVER_FILE_BUF_SIZE  2048
#define NJT_RESOLVER_FILE_NAME      "/etc/resolv.conf"
#endif
// openresty patch end


typedef struct {
    u_char  ident_hi;
    u_char  ident_lo;
    u_char  flags_hi;
    u_char  flags_lo;
    u_char  nqs_hi;
    u_char  nqs_lo;
    u_char  nan_hi;
    u_char  nan_lo;
    u_char  nns_hi;
    u_char  nns_lo;
    u_char  nar_hi;
    u_char  nar_lo;
} njt_resolver_hdr_t;


typedef struct {
    u_char  type_hi;
    u_char  type_lo;
    u_char  class_hi;
    u_char  class_lo;
} njt_resolver_qs_t;


typedef struct {
    u_char  type_hi;
    u_char  type_lo;
    u_char  class_hi;
    u_char  class_lo;
    u_char  ttl[4];
    u_char  len_hi;
    u_char  len_lo;
} njt_resolver_an_t;


#define njt_resolver_node(n)  njt_rbtree_data(n, njt_resolver_node_t, node)


static njt_int_t njt_udp_connect(njt_resolver_connection_t *rec);
static njt_int_t njt_tcp_connect(njt_resolver_connection_t *rec);


static void njt_resolver_cleanup(void *data);
static void njt_resolver_cleanup_tree(njt_resolver_t *r, njt_rbtree_t *tree);
static njt_int_t njt_resolve_name_locked(njt_resolver_t *r,
    njt_resolver_ctx_t *ctx, njt_str_t *name);
static void njt_resolver_expire(njt_resolver_t *r, njt_rbtree_t *tree,
    njt_queue_t *queue);
static njt_int_t njt_resolver_send_query(njt_resolver_t *r,
    njt_resolver_node_t *rn);
static njt_int_t njt_resolver_send_udp_query(njt_resolver_t *r,
    njt_resolver_connection_t *rec, u_char *query, u_short qlen);
static njt_int_t njt_resolver_send_tcp_query(njt_resolver_t *r,
    njt_resolver_connection_t *rec, u_char *query, u_short qlen);
static njt_int_t njt_resolver_create_name_query(njt_resolver_t *r,
    njt_resolver_node_t *rn, njt_str_t *name);
static njt_int_t njt_resolver_create_srv_query(njt_resolver_t *r,
    njt_resolver_node_t *rn, njt_str_t *name);
static njt_int_t njt_resolver_create_addr_query(njt_resolver_t *r,
    njt_resolver_node_t *rn, njt_resolver_addr_t *addr);
static void njt_resolver_resend_handler(njt_event_t *ev);
static time_t njt_resolver_resend(njt_resolver_t *r, njt_rbtree_t *tree,
    njt_queue_t *queue);
static njt_uint_t njt_resolver_resend_empty(njt_resolver_t *r);
static void njt_resolver_udp_read(njt_event_t *rev);
static void njt_resolver_tcp_write(njt_event_t *wev);
static void njt_resolver_tcp_read(njt_event_t *rev);
static void njt_resolver_process_response(njt_resolver_t *r, u_char *buf,
    size_t n, njt_uint_t tcp);
static void njt_resolver_process_a(njt_resolver_t *r, u_char *buf, size_t n,
    njt_uint_t ident, njt_uint_t code, njt_uint_t qtype,
    njt_uint_t nan, njt_uint_t trunc, njt_uint_t ans);
static void njt_resolver_process_srv(njt_resolver_t *r, u_char *buf, size_t n,
    njt_uint_t ident, njt_uint_t code, njt_uint_t nan,
    njt_uint_t trunc, njt_uint_t ans);
static void njt_resolver_process_ptr(njt_resolver_t *r, u_char *buf, size_t n,
    njt_uint_t ident, njt_uint_t code, njt_uint_t nan);
static njt_resolver_node_t *njt_resolver_lookup_name(njt_resolver_t *r,
    njt_str_t *name, uint32_t hash);
static njt_resolver_node_t *njt_resolver_lookup_srv(njt_resolver_t *r,
    njt_str_t *name, uint32_t hash);
static njt_resolver_node_t *njt_resolver_lookup_addr(njt_resolver_t *r,
    in_addr_t addr);
static void njt_resolver_rbtree_insert_value(njt_rbtree_node_t *temp,
    njt_rbtree_node_t *node, njt_rbtree_node_t *sentinel);
static njt_int_t njt_resolver_copy(njt_resolver_t *r, njt_str_t *name,
    u_char *buf, u_char *src, u_char *last);
static njt_int_t njt_resolver_set_timeout(njt_resolver_t *r,
    njt_resolver_ctx_t *ctx);
static void njt_resolver_timeout_handler(njt_event_t *ev);
static void njt_resolver_free_node(njt_resolver_t *r, njt_resolver_node_t *rn);
static void *njt_resolver_alloc(njt_resolver_t *r, size_t size);
static void *njt_resolver_calloc(njt_resolver_t *r, size_t size);
static void njt_resolver_free(njt_resolver_t *r, void *p);
static void njt_resolver_free_locked(njt_resolver_t *r, void *p);
static void *njt_resolver_dup(njt_resolver_t *r, void *src, size_t size);
static njt_resolver_addr_t *njt_resolver_export(njt_resolver_t *r,
    njt_resolver_node_t *rn, njt_uint_t rotate);
static void njt_resolver_report_srv(njt_resolver_t *r, njt_resolver_ctx_t *ctx);
static u_char *njt_resolver_log_error(njt_log_t *log, u_char *buf, size_t len);
static void njt_resolver_resolve_srv_names(njt_resolver_ctx_t *ctx,
    njt_resolver_node_t *rn);
static void njt_resolver_srv_names_handler(njt_resolver_ctx_t *ctx);
static njt_int_t njt_resolver_cmp_srvs(const void *one, const void *two);

#if (NJT_HAVE_INET6)
static void njt_resolver_rbtree_insert_addr6_value(njt_rbtree_node_t *temp,
    njt_rbtree_node_t *node, njt_rbtree_node_t *sentinel);
static njt_resolver_node_t *njt_resolver_lookup_addr6(njt_resolver_t *r,
    struct in6_addr *addr, uint32_t hash);
#endif


// openresty patch
#if !(NJT_WIN32)
static njt_int_t
njt_resolver_read_resolv_conf(njt_conf_t *cf, njt_resolver_t *r, u_char *path,
    size_t path_len)
{
    njt_url_t                        u;
    njt_resolver_connection_t       *rec;
    njt_fd_t                         fd;
    njt_file_t                       file;
    u_char                           buf[NJT_RESOLVER_FILE_BUF_SIZE];
    u_char                           ipv6_buf[NJT_INET6_ADDRSTRLEN];
    njt_uint_t                       address = 0, j, total = 0;
    ssize_t                          n, i;
    enum {
        sw_nameserver,
        sw_spaces,
        sw_address,
        sw_skip
    } state;

    file.name.data = path;
    file.name.len = path_len;

    if (njt_conf_full_name(cf->cycle, &file.name, 1) != NJT_OK) {
        return NJT_ERROR;
    }

    fd = njt_open_file(file.name.data, NJT_FILE_RDONLY,
                       NJT_FILE_OPEN, 0);

    if (fd == NJT_INVALID_FILE) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, njt_errno,
                           njt_open_file_n " \"%s\" failed", file.name.data);

        return NJT_ERROR;
    }

    njt_memzero(&file, sizeof(njt_file_t));

    file.fd = fd;
    file.log = cf->log;

    state = sw_nameserver;

    n = njt_read_file(&file, buf, NJT_RESOLVER_FILE_BUF_SIZE, 0);

    if (n == NJT_ERROR) {
        njt_conf_log_error(NJT_LOG_ALERT, cf, njt_errno,
                           njt_read_file_n " \"%s\" failed", file.name.data);
    }

    if (njt_close_file(file.fd) == NJT_FILE_ERROR) {
        njt_conf_log_error(NJT_LOG_ALERT, cf, njt_errno,
                           njt_close_file_n " \"%s\" failed", file.name.data);
    }

    if (n == NJT_ERROR) {
        return NJT_ERROR;
    }

    if (n == 0) {
        return NJT_OK;
    }

    for (i = 0; i < n && total < MAXNS; /* void */) {
        if (buf[i] == '#' || buf[i] == ';') {
            state = sw_skip;
        }

        switch (state) {

        case sw_nameserver:

            if ((size_t) n - i >= sizeof("nameserver") - 1
                && njt_memcmp(buf + i, "nameserver",
                              sizeof("nameserver") - 1) == 0)
            {
                state = sw_spaces;
                i += sizeof("nameserver") - 1;

                continue;
            }

            break;

        case sw_spaces:
            if (buf[i] != '\t' && buf[i] != ' ') {
                address = i;
                state = sw_address;
            }

            break;
        case sw_address:

            if (buf[i] == CR || buf[i] == LF || i == n - 1) {
                njt_memzero(&u, sizeof(njt_url_t));

                u.url.data = buf + address;

                if (i == n - 1 && buf[i] != CR && buf[i] != LF) {
                    u.url.len = n - address;

                } else {
                    u.url.len = i - address;
                }

                u.default_port = 53;

                /* IPv6? */
                if (njt_strlchr(u.url.data, u.url.data + u.url.len,
                                ':') != NULL)
                {
                    if (u.url.len + 2 > sizeof(ipv6_buf)) {
                        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                           "IPv6 resolver address is too long:"
                                           " \"%V\"", &u.url);

                        return NJT_ERROR;
                    }

                    ipv6_buf[0] = '[';
                    njt_memcpy(ipv6_buf + 1, u.url.data, u.url.len);
                    ipv6_buf[u.url.len + 1] = ']';

                    u.url.data = ipv6_buf;
                    u.url.len = u.url.len + 2;
                }

                if (njt_parse_url(cf->pool, &u) != NJT_OK) {
                    if (u.err) {
                        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                           "%s in resolver \"%V\"",
                                           u.err, &u.url);
                    }

                    return NJT_ERROR;
                }

                rec = njt_array_push_n(&r->connections, u.naddrs);
                if (rec == NULL) {
                    return NJT_ERROR;
                }

                njt_memzero(rec, u.naddrs * sizeof(njt_resolver_connection_t));

                for (j = 0; j < u.naddrs; j++) {
                    rec[j].sockaddr = u.addrs[j].sockaddr;
                    rec[j].socklen = u.addrs[j].socklen;
                    rec[j].server = u.addrs[j].name;
                    rec[j].resolver = r;
                }

                total++;

#if (NJT_DEBUG)
                /*
                 * logs with level below NJT_LOG_NOTICE will not be printed
                 * in this early phase
                 */
                njt_conf_log_error(NJT_LOG_NOTICE, cf, 0,
                                   "parsed a resolver: \"%V\"", &u.url);
#endif

                state = sw_nameserver;
            }

            break;

        case sw_skip:
            if (buf[i] == CR || buf[i] == LF) {
                state = sw_nameserver;
            }

            break;
        }

        i++;
    }

    return NJT_OK;
}
#endif
// openresty patch end


njt_resolver_t *
njt_resolver_create(njt_conf_t *cf, njt_str_t *names, njt_uint_t n)
{
    njt_str_t                   s;
    njt_url_t                   u;
    njt_uint_t                  i, j;
    njt_resolver_t             *r;
    njt_pool_cleanup_t         *cln;
    njt_resolver_connection_t  *rec;

    r = njt_pcalloc(cf->pool, sizeof(njt_resolver_t));
    if (r == NULL) {
        return NULL;
    }

    r->event = njt_pcalloc(cf->pool, sizeof(njt_event_t));
    if (r->event == NULL) {
        return NULL;
    }

    cln = njt_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = njt_resolver_cleanup;
    cln->data = r;

    r->ipv4 = 1;

    njt_rbtree_init(&r->name_rbtree, &r->name_sentinel,
                    njt_resolver_rbtree_insert_value);

    njt_rbtree_init(&r->srv_rbtree, &r->srv_sentinel,
                    njt_resolver_rbtree_insert_value);

    njt_rbtree_init(&r->addr_rbtree, &r->addr_sentinel,
                    njt_rbtree_insert_value);

    njt_queue_init(&r->name_resend_queue);
    njt_queue_init(&r->srv_resend_queue);
    njt_queue_init(&r->addr_resend_queue);

    njt_queue_init(&r->name_expire_queue);
    njt_queue_init(&r->srv_expire_queue);
    njt_queue_init(&r->addr_expire_queue);

#if (NJT_HAVE_INET6)
    r->ipv6 = 1;

    njt_rbtree_init(&r->addr6_rbtree, &r->addr6_sentinel,
                    njt_resolver_rbtree_insert_addr6_value);

    njt_queue_init(&r->addr6_resend_queue);

    njt_queue_init(&r->addr6_expire_queue);
#endif

    r->event->handler = njt_resolver_resend_handler;
    r->event->data = r;
    r->event->log = &cf->cycle->new_log;
    r->event->cancelable = 1;
    r->ident = -1;

    r->resend_timeout = 5;
    r->tcp_timeout = 5;
    r->expire = 30;
    r->valid = 0;

    r->log = &cf->cycle->new_log;
    r->log_level = NJT_LOG_ERR;

    if (n) {
        if (njt_array_init(&r->connections, cf->pool, n,
                           sizeof(njt_resolver_connection_t))
            != NJT_OK)
        {
            return NULL;
        }
    }

    for (i = 0; i < n; i++) {
        if (njt_strncmp(names[i].data, "valid=", 6) == 0) {
            s.len = names[i].len - 6;
            s.data = names[i].data + 6;

            r->valid = njt_parse_time(&s, 1);

            if (r->valid == (time_t) NJT_ERROR) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid parameter: %V", &names[i]);
                return NULL;
            }

            continue;
        }

// #if (NJT_HAVE_INET6) openresy patch
        if (njt_strncmp(names[i].data, "ipv4=", 5) == 0) {

            if (njt_strcmp(&names[i].data[5], "on") == 0) {
#if (NJT_HAVE_INET6) // openresy patch
                r->ipv4 = 1;
                // openresty patch
#else
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "no ipv6 support but \"%V\" in resolver",
                                   &names[i]);
                return NULL;
#endif
                // openresty patch end

            } else if (njt_strcmp(&names[i].data[5], "off") == 0) {
                r->ipv4 = 0;

            } else {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid parameter: %V", &names[i]);
                return NULL;
            }

            continue;
        }

        if (njt_strncmp(names[i].data, "ipv6=", 5) == 0) {

            if (njt_strcmp(&names[i].data[5], "on") == 0) {
                r->ipv6 = 1;

            } else if (njt_strcmp(&names[i].data[5], "off") == 0) {
#if (NJT_HAVE_INET6) // openresy patch
                r->ipv6 = 0;
#endif // openresty patch
            } else {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid parameter: %V", &names[i]);
                return NULL;
            }

            continue;
        }
// #endif openresty

// openresty patch
#if !(NJT_WIN32)
        if (njt_strncmp(names[i].data, "local=", 6) == 0) {

            if (njt_strcmp(&names[i].data[6], "on") == 0) {
                if (njt_resolver_read_resolv_conf(cf, r,
                                                  (u_char *)
                                                  NJT_RESOLVER_FILE_NAME,
                                                  sizeof(NJT_RESOLVER_FILE_NAME)
                                                  - 1)
                    != NJT_OK)
                {
                    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                       "unable to parse local resolver");
                    return NULL;
                }

            } else if (njt_strcmp(&names[i].data[6], "off") != 0) {
                if (njt_resolver_read_resolv_conf(cf, r,
                                                  &names[i].data[6],
                                                  names[i].len - 6)
                    != NJT_OK)
                {
                    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                       "unable to parse local resolver");
                    return NULL;
                }

            }

            continue;
        }
#endif
// openresty patch end



        njt_memzero(&u, sizeof(njt_url_t));

        u.url = names[i];
        u.default_port = 53;

        if (njt_parse_url(cf->pool, &u) != NJT_OK) {
            if (u.err) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "%s in resolver \"%V\"",
                                   u.err, &u.url);
            }

            return NULL;
        }

        rec = njt_array_push_n(&r->connections, u.naddrs);
        if (rec == NULL) {
            return NULL;
        }

        njt_memzero(rec, u.naddrs * sizeof(njt_resolver_connection_t));

        for (j = 0; j < u.naddrs; j++) {
            rec[j].sockaddr = u.addrs[j].sockaddr;
            rec[j].socklen = u.addrs[j].socklen;
            rec[j].server = u.addrs[j].name;
            rec[j].resolver = r;
        }
    }

#if (NJT_HAVE_INET6)
    if (r->ipv4 + r->ipv6 == 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "\"ipv4\" and \"ipv6\" cannot both be \"off\"");
        return NULL;
    }
#endif

    if (n && r->connections.nelts == 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "no name servers defined");
        return NULL;
    }

    return r;
}


static void
njt_resolver_cleanup(void *data)
{
    njt_resolver_t  *r = data;

    njt_uint_t                  i;
    njt_resolver_connection_t  *rec;

    njt_log_debug0(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0, "cleanup resolver");

    njt_resolver_cleanup_tree(r, &r->name_rbtree);

    njt_resolver_cleanup_tree(r, &r->srv_rbtree);

    njt_resolver_cleanup_tree(r, &r->addr_rbtree);

#if (NJT_HAVE_INET6)
    njt_resolver_cleanup_tree(r, &r->addr6_rbtree);
#endif

    if (r->event->timer_set) {
        njt_del_timer(r->event);
    }

    rec = r->connections.elts;

    for (i = 0; i < r->connections.nelts; i++) {
        if (rec[i].udp) {
            njt_close_connection(rec[i].udp);
        }

        if (rec[i].tcp) {
            njt_close_connection(rec[i].tcp);
        }

        if (rec[i].read_buf) {
            njt_resolver_free(r, rec[i].read_buf->start);
            njt_resolver_free(r, rec[i].read_buf);
        }

        if (rec[i].write_buf) {
            njt_resolver_free(r, rec[i].write_buf->start);
            njt_resolver_free(r, rec[i].write_buf);
        }
    }
}


static void
njt_resolver_cleanup_tree(njt_resolver_t *r, njt_rbtree_t *tree)
{
    njt_resolver_ctx_t   *ctx, *next;
    njt_resolver_node_t  *rn;

    while (tree->root != tree->sentinel) {

        rn = njt_resolver_node(njt_rbtree_min(tree->root, tree->sentinel));

        njt_queue_remove(&rn->queue);

        for (ctx = rn->waiting; ctx; ctx = next) {
            next = ctx->next;

            if (ctx->event) {
                if (ctx->event->timer_set) {
                    njt_del_timer(ctx->event);
                }

                njt_resolver_free(r, ctx->event);
            }

            njt_resolver_free(r, ctx);
        }

        njt_rbtree_delete(tree, &rn->node);

        njt_resolver_free_node(r, rn);
    }
}


njt_resolver_ctx_t *
njt_resolve_start(njt_resolver_t *r, njt_resolver_ctx_t *temp)
{
    in_addr_t            addr;
    njt_resolver_ctx_t  *ctx;

    if (temp) {
        addr = njt_inet_addr(temp->name.data, temp->name.len);

        if (addr != INADDR_NONE) {
            temp->resolver = r;
            temp->state = NJT_OK;
            temp->naddrs = 1;
            temp->addrs = &temp->addr;
            temp->addr.sockaddr = (struct sockaddr *) &temp->sin;
            temp->addr.socklen = sizeof(struct sockaddr_in);
            njt_memzero(&temp->sin, sizeof(struct sockaddr_in));
            temp->sin.sin_family = AF_INET;
            temp->sin.sin_addr.s_addr = addr;
            temp->quick = 1;

            return temp;
        }
    }

    if (r->connections.nelts == 0) {
        return NJT_NO_RESOLVER;
    }

    ctx = njt_resolver_calloc(r, sizeof(njt_resolver_ctx_t));

    if (ctx) {
        ctx->resolver = r;
    }

    return ctx;
}


njt_int_t
njt_resolve_name(njt_resolver_ctx_t *ctx)
{
    size_t           slen;
    njt_int_t        rc;
    njt_str_t        name;
    njt_resolver_t  *r;

    r = ctx->resolver;

    if (ctx->name.len > 0 && ctx->name.data[ctx->name.len - 1] == '.') {
        ctx->name.len--;
    }

    njt_log_debug1(NJT_LOG_DEBUG_CORE, r->log, 0,
                   "resolve: \"%V\"", &ctx->name);

    if (ctx->quick) {
        ctx->handler(ctx);
        return NJT_OK;
    }

    if (ctx->service.len) {
        slen = ctx->service.len;

        if (njt_strlchr(ctx->service.data,
                        ctx->service.data + ctx->service.len, '.')
            == NULL)
        {
            slen += sizeof("_._tcp") - 1;
        }

        name.len = slen + 1 + ctx->name.len;

        name.data = njt_resolver_alloc(r, name.len);
        if (name.data == NULL) {
            goto failed;
        }

        if (slen == ctx->service.len) {
            njt_sprintf(name.data, "%V.%V", &ctx->service, &ctx->name);

        } else {
            njt_sprintf(name.data, "_%V._tcp.%V", &ctx->service, &ctx->name);
        }

        /* lock name mutex */

        rc = njt_resolve_name_locked(r, ctx, &name);

        njt_resolver_free(r, name.data);

    } else {
        /* lock name mutex */

        rc = njt_resolve_name_locked(r, ctx, &ctx->name);
    }

    if (rc == NJT_OK) {
        return NJT_OK;
    }

    /* unlock name mutex */

    if (rc == NJT_AGAIN) {
        return NJT_OK;
    }

    /* NJT_ERROR */

    if (ctx->event) {
        njt_resolver_free(r, ctx->event);
    }

failed:

    njt_resolver_free(r, ctx);

    return NJT_ERROR;
}


void
njt_resolve_name_done(njt_resolver_ctx_t *ctx)
{
    njt_uint_t            i;
    njt_resolver_t       *r;
    njt_resolver_ctx_t   *w, **p;
    njt_resolver_node_t  *rn;

    r = ctx->resolver;

    njt_log_debug1(NJT_LOG_DEBUG_CORE, r->log, 0,
                   "resolve name done: %i", ctx->state);

    if (ctx->quick) {
        return;
    }

    if (ctx->event && ctx->event->timer_set) {
        njt_del_timer(ctx->event);
    }

    /* lock name mutex */

    if (ctx->nsrvs) {
        for (i = 0; i < ctx->nsrvs; i++) {
            if (ctx->srvs[i].ctx) {
                njt_resolve_name_done(ctx->srvs[i].ctx);
            }

            if (ctx->srvs[i].addrs) {
                njt_resolver_free(r, ctx->srvs[i].addrs->sockaddr);
                njt_resolver_free(r, ctx->srvs[i].addrs);
            }

            njt_resolver_free(r, ctx->srvs[i].name.data);
        }

        njt_resolver_free(r, ctx->srvs);
    }

    if (ctx->state == NJT_AGAIN || ctx->state == NJT_RESOLVE_TIMEDOUT) {

        rn = ctx->node;

        if (rn) {
            p = &rn->waiting;
            w = rn->waiting;

            while (w) {
                if (w == ctx) {
                    *p = w->next;

                    goto done;
                }

                p = &w->next;
                w = w->next;
            }

            njt_log_error(NJT_LOG_ALERT, r->log, 0,
                          "could not cancel %V resolving", &ctx->name);
        }
    }

done:

    if (ctx->service.len) {
        njt_resolver_expire(r, &r->srv_rbtree, &r->srv_expire_queue);

    } else {
        njt_resolver_expire(r, &r->name_rbtree, &r->name_expire_queue);
    }

    /* unlock name mutex */

    /* lock alloc mutex */

    if (ctx->event) {
        njt_resolver_free_locked(r, ctx->event);
    }

    njt_resolver_free_locked(r, ctx);

    /* unlock alloc mutex */

    if (r->event->timer_set && njt_resolver_resend_empty(r)) {
        njt_del_timer(r->event);
    }
}


static njt_int_t
njt_resolve_name_locked(njt_resolver_t *r, njt_resolver_ctx_t *ctx,
    njt_str_t *name)
{
    uint32_t              hash;
    njt_int_t             rc;
    njt_str_t             cname;
    njt_uint_t            i, naddrs;
    njt_queue_t          *resend_queue, *expire_queue;
    njt_rbtree_t         *tree;
    njt_resolver_ctx_t   *next, *last;
    njt_resolver_addr_t  *addrs;
    njt_resolver_node_t  *rn;

    njt_strlow(name->data, name->data, name->len);

    hash = njt_crc32_short(name->data, name->len);

    if (ctx->service.len) {
        rn = njt_resolver_lookup_srv(r, name, hash);

        tree = &r->srv_rbtree;
        resend_queue = &r->srv_resend_queue;
        expire_queue = &r->srv_expire_queue;

    } else {
        rn = njt_resolver_lookup_name(r, name, hash);

        tree = &r->name_rbtree;
        resend_queue = &r->name_resend_queue;
        expire_queue = &r->name_expire_queue;
    }

    if (rn) {

        /* ctx can be a list after NJT_RESOLVE_CNAME */
        for (last = ctx; last->next; last = last->next);

        if (rn->valid >= njt_time()) {

            njt_log_debug0(NJT_LOG_DEBUG_CORE, r->log, 0, "resolve cached");

            njt_queue_remove(&rn->queue);

            rn->expire = njt_time() + r->expire;

            njt_queue_insert_head(expire_queue, &rn->queue);

            naddrs = (rn->naddrs == (u_short) -1) ? 0 : rn->naddrs;
#if (NJT_HAVE_INET6)
            naddrs += (rn->naddrs6 == (u_short) -1) ? 0 : rn->naddrs6;
#endif

            if (naddrs) {

                if (naddrs == 1 && rn->naddrs == 1) {
                    addrs = NULL;

                } else {
                    addrs = njt_resolver_export(r, rn, 1);
                    if (addrs == NULL) {
                        return NJT_ERROR;
                    }
                }

                last->next = rn->waiting;
                rn->waiting = NULL;

                /* unlock name mutex */

                do {
                    ctx->state = NJT_OK;
                    ctx->valid = rn->valid;
                    ctx->naddrs = naddrs;

                    if (addrs == NULL) {
                        ctx->addrs = &ctx->addr;
                        ctx->addr.sockaddr = (struct sockaddr *) &ctx->sin;
                        ctx->addr.socklen = sizeof(struct sockaddr_in);
                        njt_memzero(&ctx->sin, sizeof(struct sockaddr_in));
                        ctx->sin.sin_family = AF_INET;
                        ctx->sin.sin_addr.s_addr = rn->u.addr;

                    } else {
                        ctx->addrs = addrs;
                    }

                    next = ctx->next;

                    ctx->handler(ctx);

                    ctx = next;
                } while (ctx);

                if (addrs != NULL) {
                    njt_resolver_free(r, addrs->sockaddr);
                    njt_resolver_free(r, addrs);
                }

                return NJT_OK;
            }

            if (rn->nsrvs) {
                last->next = rn->waiting;
                rn->waiting = NULL;

                /* unlock name mutex */

                do {
                    next = ctx->next;

                    njt_resolver_resolve_srv_names(ctx, rn);

                    ctx = next;
                } while (ctx);

                return NJT_OK;
            }

            /* NJT_RESOLVE_CNAME */

            if (ctx->recursion++ < NJT_RESOLVER_MAX_RECURSION) {

                cname.len = rn->cnlen;
                cname.data = rn->u.cname;

                return njt_resolve_name_locked(r, ctx, &cname);
            }

            last->next = rn->waiting;
            rn->waiting = NULL;

            /* unlock name mutex */

            do {
                ctx->state = NJT_RESOLVE_NXDOMAIN;
                ctx->valid = njt_time() + (r->valid ? r->valid : 10);
                next = ctx->next;

                ctx->handler(ctx);

                ctx = next;
            } while (ctx);

            return NJT_OK;
        }

        if (rn->waiting) {
            if (njt_resolver_set_timeout(r, ctx) != NJT_OK) {
                return NJT_ERROR;
            }

            last->next = rn->waiting;
            rn->waiting = ctx;
            ctx->state = NJT_AGAIN;
            ctx->async = 1;

            do {
                ctx->node = rn;
                ctx = ctx->next;
            } while (ctx);

            return NJT_AGAIN;
        }

        njt_queue_remove(&rn->queue);

        /* lock alloc mutex */

        if (rn->query) {
            njt_resolver_free_locked(r, rn->query);
            rn->query = NULL;
#if (NJT_HAVE_INET6)
            rn->query6 = NULL;
#endif
        }

        if (rn->cnlen) {
            njt_resolver_free_locked(r, rn->u.cname);
        }

        if (rn->naddrs > 1 && rn->naddrs != (u_short) -1) {
            njt_resolver_free_locked(r, rn->u.addrs);
        }

#if (NJT_HAVE_INET6)
        if (rn->naddrs6 > 1 && rn->naddrs6 != (u_short) -1) {
            njt_resolver_free_locked(r, rn->u6.addrs6);
        }
#endif

        if (rn->nsrvs) {
            for (i = 0; i < (njt_uint_t) rn->nsrvs; i++) {
                if (rn->u.srvs[i].name.data) {
                    njt_resolver_free_locked(r, rn->u.srvs[i].name.data);
                }
            }

            njt_resolver_free_locked(r, rn->u.srvs);
        }

        /* unlock alloc mutex */

    } else {

        rn = njt_resolver_alloc(r, sizeof(njt_resolver_node_t));
        if (rn == NULL) {
            return NJT_ERROR;
        }

        rn->name = njt_resolver_dup(r, name->data, name->len);
        if (rn->name == NULL) {
            njt_resolver_free(r, rn);
            return NJT_ERROR;
        }

        rn->node.key = hash;
        rn->nlen = (u_short) name->len;
        rn->query = NULL;
#if (NJT_HAVE_INET6)
        rn->query6 = NULL;
#endif

        njt_rbtree_insert(tree, &rn->node);
    }

    if (ctx->service.len) {
        rc = njt_resolver_create_srv_query(r, rn, name);

    } else {
        rc = njt_resolver_create_name_query(r, rn, name);
    }

    if (rc == NJT_ERROR) {
        goto failed;
    }

    if (rc == NJT_DECLINED) {
        njt_rbtree_delete(tree, &rn->node);

        njt_resolver_free(r, rn->query);
        njt_resolver_free(r, rn->name);
        njt_resolver_free(r, rn);

        do {
            ctx->state = NJT_RESOLVE_NXDOMAIN;
            next = ctx->next;

            ctx->handler(ctx);

            ctx = next;
        } while (ctx);

        return NJT_OK;
    }

    rn->last_connection = r->last_connection++;
    if (r->last_connection == r->connections.nelts) {
        r->last_connection = 0;
    }

    rn->naddrs = r->ipv4 ? (u_short) -1 : 0;
    rn->tcp = 0;
#if (NJT_HAVE_INET6)
    rn->naddrs6 = r->ipv6 ? (u_short) -1 : 0;
    rn->tcp6 = 0;
#endif
    rn->nsrvs = 0;

    if (njt_resolver_send_query(r, rn) != NJT_OK) {

        /* immediately retry once on failure */

        rn->last_connection++;
        if (rn->last_connection == r->connections.nelts) {
            rn->last_connection = 0;
        }

        (void) njt_resolver_send_query(r, rn);
    }

    if (njt_resolver_set_timeout(r, ctx) != NJT_OK) {
        goto failed;
    }

    if (njt_resolver_resend_empty(r)) {
        njt_add_timer(r->event, (njt_msec_t) (r->resend_timeout * 1000));
    }

    rn->expire = njt_time() + r->resend_timeout;

    njt_queue_insert_head(resend_queue, &rn->queue);

    rn->code = 0;
    rn->cnlen = 0;
    rn->valid = 0;
    rn->ttl = NJT_MAX_UINT32_VALUE;
    rn->waiting = ctx;

    ctx->state = NJT_AGAIN;
    ctx->async = 1;

    do {
        ctx->node = rn;
        ctx = ctx->next;
    } while (ctx);

    return NJT_AGAIN;

failed:

    njt_rbtree_delete(tree, &rn->node);

    if (rn->query) {
        njt_resolver_free(r, rn->query);
    }

    njt_resolver_free(r, rn->name);

    njt_resolver_free(r, rn);

    return NJT_ERROR;
}


njt_int_t
njt_resolve_addr(njt_resolver_ctx_t *ctx)
{
    u_char               *name;
    in_addr_t             addr;
    njt_queue_t          *resend_queue, *expire_queue;
    njt_rbtree_t         *tree;
    njt_resolver_t       *r;
    struct sockaddr_in   *sin;
    njt_resolver_node_t  *rn;
#if (NJT_HAVE_INET6)
    uint32_t              hash;
    struct sockaddr_in6  *sin6;
#endif

#if (NJT_SUPPRESS_WARN)
    addr = 0;
#if (NJT_HAVE_INET6)
    hash = 0;
    sin6 = NULL;
#endif
#endif

    r = ctx->resolver;

    switch (ctx->addr.sockaddr->sa_family) {

#if (NJT_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) ctx->addr.sockaddr;
        hash = njt_crc32_short(sin6->sin6_addr.s6_addr, 16);

        /* lock addr mutex */

        rn = njt_resolver_lookup_addr6(r, &sin6->sin6_addr, hash);

        tree = &r->addr6_rbtree;
        resend_queue = &r->addr6_resend_queue;
        expire_queue = &r->addr6_expire_queue;

        break;
#endif

    default: /* AF_INET */
        sin = (struct sockaddr_in *) ctx->addr.sockaddr;
        addr = ntohl(sin->sin_addr.s_addr);

        /* lock addr mutex */

        rn = njt_resolver_lookup_addr(r, addr);

        tree = &r->addr_rbtree;
        resend_queue = &r->addr_resend_queue;
        expire_queue = &r->addr_expire_queue;
    }

    if (rn) {

        if (rn->valid >= njt_time()) {

            njt_log_debug0(NJT_LOG_DEBUG_CORE, r->log, 0, "resolve cached");

            njt_queue_remove(&rn->queue);

            rn->expire = njt_time() + r->expire;

            njt_queue_insert_head(expire_queue, &rn->queue);

            name = njt_resolver_dup(r, rn->name, rn->nlen);
            if (name == NULL) {
                njt_resolver_free(r, ctx);
                return NJT_ERROR;
            }

            ctx->name.len = rn->nlen;
            ctx->name.data = name;

            /* unlock addr mutex */

            ctx->state = NJT_OK;
            ctx->valid = rn->valid;

            ctx->handler(ctx);

            njt_resolver_free(r, name);

            return NJT_OK;
        }

        if (rn->waiting) {
            if (njt_resolver_set_timeout(r, ctx) != NJT_OK) {
                return NJT_ERROR;
            }

            ctx->next = rn->waiting;
            rn->waiting = ctx;
            ctx->state = NJT_AGAIN;
            ctx->async = 1;
            ctx->node = rn;

            /* unlock addr mutex */

            return NJT_OK;
        }

        njt_queue_remove(&rn->queue);

        njt_resolver_free(r, rn->query);
        rn->query = NULL;
#if (NJT_HAVE_INET6)
        rn->query6 = NULL;
#endif

    } else {
        rn = njt_resolver_alloc(r, sizeof(njt_resolver_node_t));
        if (rn == NULL) {
            goto failed;
        }

        switch (ctx->addr.sockaddr->sa_family) {

#if (NJT_HAVE_INET6)
        case AF_INET6:
            rn->addr6 = sin6->sin6_addr;
            rn->node.key = hash;
            break;
#endif

        default: /* AF_INET */
            rn->node.key = addr;
        }

        rn->query = NULL;
#if (NJT_HAVE_INET6)
        rn->query6 = NULL;
#endif

        njt_rbtree_insert(tree, &rn->node);
    }

    if (njt_resolver_create_addr_query(r, rn, &ctx->addr) != NJT_OK) {
        goto failed;
    }

    rn->last_connection = r->last_connection++;
    if (r->last_connection == r->connections.nelts) {
        r->last_connection = 0;
    }

    rn->naddrs = (u_short) -1;
    rn->tcp = 0;
#if (NJT_HAVE_INET6)
    rn->naddrs6 = (u_short) -1;
    rn->tcp6 = 0;
#endif
    rn->nsrvs = 0;

    if (njt_resolver_send_query(r, rn) != NJT_OK) {

        /* immediately retry once on failure */

        rn->last_connection++;
        if (rn->last_connection == r->connections.nelts) {
            rn->last_connection = 0;
        }

        (void) njt_resolver_send_query(r, rn);
    }

    if (njt_resolver_set_timeout(r, ctx) != NJT_OK) {
        goto failed;
    }

    if (njt_resolver_resend_empty(r)) {
        njt_add_timer(r->event, (njt_msec_t) (r->resend_timeout * 1000));
    }

    rn->expire = njt_time() + r->resend_timeout;

    njt_queue_insert_head(resend_queue, &rn->queue);

    rn->code = 0;
    rn->cnlen = 0;
    rn->name = NULL;
    rn->nlen = 0;
    rn->valid = 0;
    rn->ttl = NJT_MAX_UINT32_VALUE;
    rn->waiting = ctx;

    /* unlock addr mutex */

    ctx->state = NJT_AGAIN;
    ctx->async = 1;
    ctx->node = rn;

    return NJT_OK;

failed:

    if (rn) {
        njt_rbtree_delete(tree, &rn->node);

        if (rn->query) {
            njt_resolver_free(r, rn->query);
        }

        njt_resolver_free(r, rn);
    }

    /* unlock addr mutex */

    if (ctx->event) {
        njt_resolver_free(r, ctx->event);
    }

    njt_resolver_free(r, ctx);

    return NJT_ERROR;
}


void
njt_resolve_addr_done(njt_resolver_ctx_t *ctx)
{
    njt_queue_t          *expire_queue;
    njt_rbtree_t         *tree;
    njt_resolver_t       *r;
    njt_resolver_ctx_t   *w, **p;
    njt_resolver_node_t  *rn;

    r = ctx->resolver;

    switch (ctx->addr.sockaddr->sa_family) {

#if (NJT_HAVE_INET6)
    case AF_INET6:
        tree = &r->addr6_rbtree;
        expire_queue = &r->addr6_expire_queue;
        break;
#endif

    default: /* AF_INET */
        tree = &r->addr_rbtree;
        expire_queue = &r->addr_expire_queue;
    }

    njt_log_debug1(NJT_LOG_DEBUG_CORE, r->log, 0,
                   "resolve addr done: %i", ctx->state);

    if (ctx->event && ctx->event->timer_set) {
        njt_del_timer(ctx->event);
    }

    /* lock addr mutex */

    if (ctx->state == NJT_AGAIN || ctx->state == NJT_RESOLVE_TIMEDOUT) {

        rn = ctx->node;

        if (rn) {
            p = &rn->waiting;
            w = rn->waiting;

            while (w) {
                if (w == ctx) {
                    *p = w->next;

                    goto done;
                }

                p = &w->next;
                w = w->next;
            }
        }

        {
            u_char     text[NJT_SOCKADDR_STRLEN];
            njt_str_t  addrtext;

            addrtext.data = text;
            addrtext.len = njt_sock_ntop(ctx->addr.sockaddr, ctx->addr.socklen,
                                         text, NJT_SOCKADDR_STRLEN, 0);

            njt_log_error(NJT_LOG_ALERT, r->log, 0,
                          "could not cancel %V resolving", &addrtext);
        }
    }

done:

    njt_resolver_expire(r, tree, expire_queue);

    /* unlock addr mutex */

    /* lock alloc mutex */

    if (ctx->event) {
        njt_resolver_free_locked(r, ctx->event);
    }

    njt_resolver_free_locked(r, ctx);

    /* unlock alloc mutex */

    if (r->event->timer_set && njt_resolver_resend_empty(r)) {
        njt_del_timer(r->event);
    }
}


static void
njt_resolver_expire(njt_resolver_t *r, njt_rbtree_t *tree, njt_queue_t *queue)
{
    time_t                now;
    njt_uint_t            i;
    njt_queue_t          *q;
    njt_resolver_node_t  *rn;

    njt_log_debug0(NJT_LOG_DEBUG_CORE, r->log, 0, "resolver expire");

    now = njt_time();

    for (i = 0; i < 2; i++) {
        if (njt_queue_empty(queue)) {
            return;
        }

        q = njt_queue_last(queue);

        rn = njt_queue_data(q, njt_resolver_node_t, queue);

        if (now <= rn->expire) {
            return;
        }

        njt_log_debug2(NJT_LOG_DEBUG_CORE, r->log, 0,
                       "resolver expire \"%*s\"", (size_t) rn->nlen, rn->name);

        njt_queue_remove(q);

        njt_rbtree_delete(tree, &rn->node);

        njt_resolver_free_node(r, rn);
    }
}


static njt_int_t
njt_resolver_send_query(njt_resolver_t *r, njt_resolver_node_t *rn)
{
    njt_int_t                   rc;
    njt_resolver_connection_t  *rec;

    rec = r->connections.elts;
    rec = &rec[rn->last_connection];

    if (rec->log.handler == NULL) {
        rec->log = *r->log;
        rec->log.handler = njt_resolver_log_error;
        rec->log.data = rec;
        rec->log.action = "resolving";
    }

    if (rn->query && rn->naddrs == (u_short) -1) {
        rc = rn->tcp ? njt_resolver_send_tcp_query(r, rec, rn->query, rn->qlen)
                     : njt_resolver_send_udp_query(r, rec, rn->query, rn->qlen);

        if (rc != NJT_OK) {
            return rc;
        }
    }

#if (NJT_HAVE_INET6)

    if (rn->query6 && rn->naddrs6 == (u_short) -1) {
        rc = rn->tcp6
                    ? njt_resolver_send_tcp_query(r, rec, rn->query6, rn->qlen)
                    : njt_resolver_send_udp_query(r, rec, rn->query6, rn->qlen);

        if (rc != NJT_OK) {
            return rc;
        }
    }

#endif

    return NJT_OK;
}


static njt_int_t
njt_resolver_send_udp_query(njt_resolver_t *r, njt_resolver_connection_t  *rec,
    u_char *query, u_short qlen)
{
    ssize_t  n;

    if (rec->udp == NULL) {
        if (njt_udp_connect(rec) != NJT_OK) {
            return NJT_ERROR;
        }

        rec->udp->data = rec;
        rec->udp->read->handler = njt_resolver_udp_read;
        rec->udp->read->resolver = 1;
    }

    n = njt_send(rec->udp, query, qlen);

    if (n == NJT_ERROR) {
        goto failed;
    }

    if ((size_t) n != (size_t) qlen) {
        njt_log_error(NJT_LOG_CRIT, &rec->log, 0, "send() incomplete");
        goto failed;
    }

    return NJT_OK;

failed:

    njt_close_connection(rec->udp);
    rec->udp = NULL;

    return NJT_ERROR;
}


static njt_int_t
njt_resolver_send_tcp_query(njt_resolver_t *r, njt_resolver_connection_t *rec,
    u_char *query, u_short qlen)
{
    njt_buf_t  *b;
    njt_int_t   rc;

    rc = NJT_OK;

    if (rec->tcp == NULL) {
        b = rec->read_buf;

        if (b == NULL) {
            b = njt_resolver_calloc(r, sizeof(njt_buf_t));
            if (b == NULL) {
                return NJT_ERROR;
            }

            b->start = njt_resolver_alloc(r, NJT_RESOLVER_TCP_RSIZE);
            if (b->start == NULL) {
                njt_resolver_free(r, b);
                return NJT_ERROR;
            }

            b->end = b->start + NJT_RESOLVER_TCP_RSIZE;

            rec->read_buf = b;
        }

        b->pos = b->start;
        b->last = b->start;

        b = rec->write_buf;

        if (b == NULL) {
            b = njt_resolver_calloc(r, sizeof(njt_buf_t));
            if (b == NULL) {
                return NJT_ERROR;
            }

            b->start = njt_resolver_alloc(r, NJT_RESOLVER_TCP_WSIZE);
            if (b->start == NULL) {
                njt_resolver_free(r, b);
                return NJT_ERROR;
            }

            b->end = b->start + NJT_RESOLVER_TCP_WSIZE;

            rec->write_buf = b;
        }

        b->pos = b->start;
        b->last = b->start;

        rc = njt_tcp_connect(rec);
        if (rc == NJT_ERROR) {
            return NJT_ERROR;
        }

        rec->tcp->data = rec;
        rec->tcp->write->handler = njt_resolver_tcp_write;
        rec->tcp->write->cancelable = 1;
        rec->tcp->read->handler = njt_resolver_tcp_read;
        rec->tcp->read->resolver = 1;

        njt_add_timer(rec->tcp->write, (njt_msec_t) (r->tcp_timeout * 1000));
    }

    b = rec->write_buf;

    if (b->end - b->last <  2 + qlen) {
        njt_log_error(NJT_LOG_CRIT, &rec->log, 0, "buffer overflow");
        return NJT_ERROR;
    }

    *b->last++ = (u_char) (qlen >> 8);
    *b->last++ = (u_char) qlen;
    b->last = njt_cpymem(b->last, query, qlen);

    if (rc == NJT_OK) {
        njt_resolver_tcp_write(rec->tcp->write);
    }

    return NJT_OK;
}


static void
njt_resolver_resend_handler(njt_event_t *ev)
{
    time_t           timer, atimer, stimer, ntimer;
#if (NJT_HAVE_INET6)
    time_t           a6timer;
#endif
    njt_resolver_t  *r;

    r = ev->data;

    njt_log_debug0(NJT_LOG_DEBUG_CORE, r->log, 0,
                   "resolver resend handler");

    /* lock name mutex */

    ntimer = njt_resolver_resend(r, &r->name_rbtree, &r->name_resend_queue);

    stimer = njt_resolver_resend(r, &r->srv_rbtree, &r->srv_resend_queue);

    /* unlock name mutex */

    /* lock addr mutex */

    atimer = njt_resolver_resend(r, &r->addr_rbtree, &r->addr_resend_queue);

    /* unlock addr mutex */

#if (NJT_HAVE_INET6)

    /* lock addr6 mutex */

    a6timer = njt_resolver_resend(r, &r->addr6_rbtree, &r->addr6_resend_queue);

    /* unlock addr6 mutex */

#endif

    timer = ntimer;

    if (timer == 0) {
        timer = atimer;

    } else if (atimer) {
        timer = njt_min(timer, atimer);
    }

    if (timer == 0) {
        timer = stimer;

    } else if (stimer) {
        timer = njt_min(timer, stimer);
    }

#if (NJT_HAVE_INET6)

    if (timer == 0) {
        timer = a6timer;

    } else if (a6timer) {
        timer = njt_min(timer, a6timer);
    }

#endif

    if (timer) {
        njt_add_timer(r->event, (njt_msec_t) (timer * 1000));
    }
}


static time_t
njt_resolver_resend(njt_resolver_t *r, njt_rbtree_t *tree, njt_queue_t *queue)
{
    time_t                now;
    njt_queue_t          *q;
    njt_resolver_node_t  *rn;

    now = njt_time();

    for ( ;; ) {
        if (njt_queue_empty(queue)) {
            return 0;
        }

        q = njt_queue_last(queue);

        rn = njt_queue_data(q, njt_resolver_node_t, queue);

        if (now < rn->expire) {
            return rn->expire - now;
        }

        njt_log_debug3(NJT_LOG_DEBUG_CORE, r->log, 0,
                       "resolver resend \"%*s\" %p",
                       (size_t) rn->nlen, rn->name, rn->waiting);

        njt_queue_remove(q);

        if (rn->waiting) {

            if (++rn->last_connection == r->connections.nelts) {
                rn->last_connection = 0;
            }

            (void) njt_resolver_send_query(r, rn);

            rn->expire = now + r->resend_timeout;

            njt_queue_insert_head(queue, q);

            continue;
        }

        njt_rbtree_delete(tree, &rn->node);

        njt_resolver_free_node(r, rn);
    }
}


static njt_uint_t
njt_resolver_resend_empty(njt_resolver_t *r)
{
    return njt_queue_empty(&r->name_resend_queue)
           && njt_queue_empty(&r->srv_resend_queue)
#if (NJT_HAVE_INET6)
           && njt_queue_empty(&r->addr6_resend_queue)
#endif
           && njt_queue_empty(&r->addr_resend_queue);
}


static void
njt_resolver_udp_read(njt_event_t *rev)
{
    ssize_t                     n;
    njt_connection_t           *c;
    njt_resolver_connection_t  *rec;
    u_char                      buf[NJT_RESOLVER_UDP_SIZE];

    c = rev->data;
    rec = c->data;

    do {
        n = njt_udp_recv(c, buf, NJT_RESOLVER_UDP_SIZE);

        if (n == NJT_AGAIN) {
            break;
        }

        if (n == NJT_ERROR) {
            goto failed;
        }

        njt_resolver_process_response(rec->resolver, buf, n, 0);

    } while (rev->ready);

    if (njt_handle_read_event(rev, 0) != NJT_OK) {
        goto failed;
    }

    return;

failed:

    njt_close_connection(rec->udp);
    rec->udp = NULL;
}


static void
njt_resolver_tcp_write(njt_event_t *wev)
{
    off_t                       sent;
    ssize_t                     n;
    njt_buf_t                  *b;
    njt_resolver_t             *r;
    njt_connection_t           *c;
    njt_resolver_connection_t  *rec;

    c = wev->data;
    rec = c->data;
    b = rec->write_buf;
    r = rec->resolver;

    if (wev->timedout) {
        goto failed;
    }

    sent = c->sent;

    while (wev->ready && b->pos < b->last) {
        n = njt_send(c, b->pos, b->last - b->pos);

        if (n == NJT_AGAIN) {
            break;
        }

        if (n == NJT_ERROR) {
            goto failed;
        }

        b->pos += n;
    }

    if (b->pos != b->start) {
        b->last = njt_movemem(b->start, b->pos, b->last - b->pos);
        b->pos = b->start;
    }

    if (c->sent != sent) {
        njt_add_timer(wev, (njt_msec_t) (r->tcp_timeout * 1000));
    }

    if (njt_handle_write_event(wev, 0) != NJT_OK) {
        goto failed;
    }

    return;

failed:

    njt_close_connection(c);
    rec->tcp = NULL;
}


static void
njt_resolver_tcp_read(njt_event_t *rev)
{
    u_char                     *p;
    size_t                      size;
    ssize_t                     n;
    u_short                     qlen;
    njt_buf_t                  *b;
    njt_resolver_t             *r;
    njt_connection_t           *c;
    njt_resolver_connection_t  *rec;

    c = rev->data;
    rec = c->data;
    b = rec->read_buf;
    r = rec->resolver;

    while (rev->ready) {
        n = njt_recv(c, b->last, b->end - b->last);

        if (n == NJT_AGAIN) {
            break;
        }

        if (n == NJT_ERROR || n == 0) {
            goto failed;
        }

        b->last += n;

        for ( ;; ) {
            p = b->pos;
            size = b->last - p;

            if (size < 2) {
                break;
            }

            qlen = (u_short) *p++ << 8;
            qlen += *p++;

            if (size < (size_t) (2 + qlen)) {
                break;
            }

            njt_resolver_process_response(r, p, qlen, 1);

            b->pos += 2 + qlen;
        }

        if (b->pos != b->start) {
            b->last = njt_movemem(b->start, b->pos, b->last - b->pos);
            b->pos = b->start;
        }
    }

    if (njt_handle_read_event(rev, 0) != NJT_OK) {
        goto failed;
    }

    return;

failed:

    njt_close_connection(c);
    rec->tcp = NULL;
}


static void
njt_resolver_process_response(njt_resolver_t *r, u_char *buf, size_t n,
    njt_uint_t tcp)
{
    char                 *err;
    njt_uint_t            i, times, ident, qident, flags, code, nqs, nan, trunc,
                          qtype, qclass;
#if (NJT_HAVE_INET6)
    njt_uint_t            qident6;
#endif
    njt_queue_t          *q;
    njt_resolver_qs_t    *qs;
    njt_resolver_hdr_t   *response;
    njt_resolver_node_t  *rn;

    if (n < sizeof(njt_resolver_hdr_t)) {
        goto short_response;
    }

    response = (njt_resolver_hdr_t *) buf;

    ident = (response->ident_hi << 8) + response->ident_lo;
    flags = (response->flags_hi << 8) + response->flags_lo;
    nqs = (response->nqs_hi << 8) + response->nqs_lo;
    nan = (response->nan_hi << 8) + response->nan_lo;
    trunc = flags & 0x0200;

    njt_log_debug6(NJT_LOG_DEBUG_CORE, r->log, 0,
                   "resolver DNS response %ui fl:%04Xi %ui/%ui/%ud/%ud",
                   ident, flags, nqs, nan,
                   (response->nns_hi << 8) + response->nns_lo,
                   (response->nar_hi << 8) + response->nar_lo);

    /* response to a standard query */
    if ((flags & 0xf870) != 0x8000 || (trunc && tcp)) {
        njt_log_error(r->log_level, r->log, 0,
                      "invalid %s DNS response %ui fl:%04Xi",
                      tcp ? "TCP" : "UDP", ident, flags);
        return;
    }

    code = flags & 0xf;

    if (code == NJT_RESOLVE_FORMERR) {

        times = 0;

        for (q = njt_queue_head(&r->name_resend_queue);
             q != njt_queue_sentinel(&r->name_resend_queue) && times++ < 100;
             q = njt_queue_next(q))
        {
            rn = njt_queue_data(q, njt_resolver_node_t, queue);

            if (rn->query) {
                qident = (rn->query[0] << 8) + rn->query[1];

                if (qident == ident) {
                    goto dns_error_name;
                }
            }

#if (NJT_HAVE_INET6)
            if (rn->query6) {
                qident6 = (rn->query6[0] << 8) + rn->query6[1];

                if (qident6 == ident) {
                    goto dns_error_name;
                }
            }
#endif
        }

        goto dns_error;
    }

    if (code > NJT_RESOLVE_REFUSED) {
        goto dns_error;
    }

    if (nqs != 1) {
        err = "invalid number of questions in DNS response";
        goto done;
    }

    i = sizeof(njt_resolver_hdr_t);

    while (i < (njt_uint_t) n) {

        if (buf[i] & 0xc0) {
            err = "unexpected compression pointer in DNS response";
            goto done;
        }

        if (buf[i] == '\0') {
            goto found;
        }

        i += 1 + buf[i];
    }

    goto short_response;

found:

    if (i++ == sizeof(njt_resolver_hdr_t)) {
        err = "zero-length domain name in DNS response";
        goto done;
    }

    if (i + sizeof(njt_resolver_qs_t) + nan * (2 + sizeof(njt_resolver_an_t))
        > (njt_uint_t) n)
    {
        goto short_response;
    }

    qs = (njt_resolver_qs_t *) &buf[i];

    qtype = (qs->type_hi << 8) + qs->type_lo;
    qclass = (qs->class_hi << 8) + qs->class_lo;

    njt_log_debug2(NJT_LOG_DEBUG_CORE, r->log, 0,
                   "resolver DNS response qt:%ui cl:%ui", qtype, qclass);

    if (qclass != 1) {
        njt_log_error(r->log_level, r->log, 0,
                      "unknown query class %ui in DNS response", qclass);
        return;
    }

    switch (qtype) {

    case NJT_RESOLVE_A:
#if (NJT_HAVE_INET6)
    case NJT_RESOLVE_AAAA:
#endif

        njt_resolver_process_a(r, buf, n, ident, code, qtype, nan, trunc,
                               i + sizeof(njt_resolver_qs_t));

        break;

    case NJT_RESOLVE_SRV:

        njt_resolver_process_srv(r, buf, n, ident, code, nan, trunc,
                                 i + sizeof(njt_resolver_qs_t));

        break;

    case NJT_RESOLVE_PTR:

        njt_resolver_process_ptr(r, buf, n, ident, code, nan);

        break;

    default:
        njt_log_error(r->log_level, r->log, 0,
                      "unknown query type %ui in DNS response", qtype);
        return;
    }

    return;

short_response:

    err = "short DNS response";

done:

    njt_log_error(r->log_level, r->log, 0, err);

    return;

dns_error_name:

    njt_log_error(r->log_level, r->log, 0,
                  "DNS error (%ui: %s), query id:%ui, name:\"%*s\"",
                  code, njt_resolver_strerror(code), ident,
                  (size_t) rn->nlen, rn->name);
    return;

dns_error:

    njt_log_error(r->log_level, r->log, 0,
                  "DNS error (%ui: %s), query id:%ui",
                  code, njt_resolver_strerror(code), ident);
    return;
}


static void
njt_resolver_process_a(njt_resolver_t *r, u_char *buf, size_t n,
    njt_uint_t ident, njt_uint_t code, njt_uint_t qtype,
    njt_uint_t nan, njt_uint_t trunc, njt_uint_t ans)
{
    char                       *err;
    u_char                     *cname;
    size_t                      len;
    int32_t                     ttl;
    uint32_t                    hash;
    in_addr_t                  *addr;
    njt_str_t                   name;
    njt_uint_t                  type, class, qident, naddrs, a, i, j, start;
#if (NJT_HAVE_INET6)
    struct in6_addr            *addr6;
#endif
    njt_resolver_an_t          *an;
    njt_resolver_ctx_t         *ctx, *next;
    njt_resolver_node_t        *rn;
    njt_resolver_addr_t        *addrs;
    njt_resolver_connection_t  *rec;

    if (njt_resolver_copy(r, &name, buf,
                          buf + sizeof(njt_resolver_hdr_t), buf + n)
        != NJT_OK)
    {
        return;
    }

    njt_log_debug1(NJT_LOG_DEBUG_CORE, r->log, 0, "resolver qs:%V", &name);

    hash = njt_crc32_short(name.data, name.len);

    /* lock name mutex */

    rn = njt_resolver_lookup_name(r, &name, hash);

    if (rn == NULL) {
        njt_log_error(r->log_level, r->log, 0,
                      "unexpected DNS response for %V", &name);
        njt_resolver_free(r, name.data);
        goto failed;
    }

    switch (qtype) {

#if (NJT_HAVE_INET6)
    case NJT_RESOLVE_AAAA:

        if (rn->query6 == NULL || rn->naddrs6 != (u_short) -1) {
            njt_log_error(r->log_level, r->log, 0,
                          "unexpected DNS response for %V", &name);
            njt_resolver_free(r, name.data);
            goto failed;
        }

        if (trunc && rn->tcp6) {
            njt_resolver_free(r, name.data);
            goto failed;
        }

        qident = (rn->query6[0] << 8) + rn->query6[1];

        break;
#endif

    default: /* NJT_RESOLVE_A */

        if (rn->query == NULL || rn->naddrs != (u_short) -1) {
            njt_log_error(r->log_level, r->log, 0,
                          "unexpected DNS response for %V", &name);
            njt_resolver_free(r, name.data);
            goto failed;
        }

        if (trunc && rn->tcp) {
            njt_resolver_free(r, name.data);
            goto failed;
        }

        qident = (rn->query[0] << 8) + rn->query[1];
    }

    if (ident != qident) {
        njt_log_error(r->log_level, r->log, 0,
                      "wrong ident %ui in DNS response for %V, expect %ui",
                      ident, &name, qident);
        njt_resolver_free(r, name.data);
        goto failed;
    }

    njt_resolver_free(r, name.data);

    if (trunc) {

        njt_queue_remove(&rn->queue);

        if (rn->waiting == NULL) {
            njt_rbtree_delete(&r->name_rbtree, &rn->node);
            njt_resolver_free_node(r, rn);
            goto next;
        }

        rec = r->connections.elts;
        rec = &rec[rn->last_connection];

        switch (qtype) {

#if (NJT_HAVE_INET6)
        case NJT_RESOLVE_AAAA:

            rn->tcp6 = 1;

            (void) njt_resolver_send_tcp_query(r, rec, rn->query6, rn->qlen);

            break;
#endif

        default: /* NJT_RESOLVE_A */

            rn->tcp = 1;

            (void) njt_resolver_send_tcp_query(r, rec, rn->query, rn->qlen);
        }

        rn->expire = njt_time() + r->resend_timeout;

        njt_queue_insert_head(&r->name_resend_queue, &rn->queue);

        goto next;
    }

    if (code == 0 && rn->code) {
        code = rn->code;
    }

    if (code == 0 && nan == 0) {

#if (NJT_HAVE_INET6)
        switch (qtype) {

        case NJT_RESOLVE_AAAA:

            rn->naddrs6 = 0;

            if (rn->naddrs == (u_short) -1) {
                goto next;
            }

            if (rn->naddrs) {
                goto export;
            }

            break;

        default: /* NJT_RESOLVE_A */

            rn->naddrs = 0;

            if (rn->naddrs6 == (u_short) -1) {
                goto next;
            }

            if (rn->naddrs6) {
                goto export;
            }
        }
#endif

        code = NJT_RESOLVE_NXDOMAIN;
    }

    if (code) {

#if (NJT_HAVE_INET6)
        switch (qtype) {

        case NJT_RESOLVE_AAAA:

            rn->naddrs6 = 0;

            if (rn->naddrs == (u_short) -1) {
                rn->code = (u_char) code;
                goto next;
            }

            break;

        default: /* NJT_RESOLVE_A */

            rn->naddrs = 0;

            if (rn->naddrs6 == (u_short) -1) {
                rn->code = (u_char) code;
                goto next;
            }
        }
#endif

        next = rn->waiting;
        rn->waiting = NULL;

        njt_queue_remove(&rn->queue);

        njt_rbtree_delete(&r->name_rbtree, &rn->node);

        /* unlock name mutex */

        while (next) {
            ctx = next;
            ctx->state = code;
            ctx->valid = njt_time() + (r->valid ? r->valid : 10);
            next = ctx->next;

            ctx->handler(ctx);
        }

        njt_resolver_free_node(r, rn);

        return;
    }

    i = ans;
    naddrs = 0;
    cname = NULL;

    for (a = 0; a < nan; a++) {

        start = i;

        while (i < n) {

            if (buf[i] & 0xc0) {
                i += 2;
                goto found;
            }

            if (buf[i] == 0) {
                i++;
                goto test_length;
            }

            i += 1 + buf[i];
        }

        goto short_response;

    test_length:

        if (i - start < 2) {
            err = "invalid name in DNS response";
            goto invalid;
        }

    found:

        if (i + sizeof(njt_resolver_an_t) >= n) {
            goto short_response;
        }

        an = (njt_resolver_an_t *) &buf[i];

        type = (an->type_hi << 8) + an->type_lo;
        class = (an->class_hi << 8) + an->class_lo;
        len = (an->len_hi << 8) + an->len_lo;
        ttl = (an->ttl[0] << 24) + (an->ttl[1] << 16)
            + (an->ttl[2] << 8) + (an->ttl[3]);

        if (class != 1) {
            njt_log_error(r->log_level, r->log, 0,
                          "unexpected RR class %ui in DNS response", class);
            goto failed;
        }

        if (ttl < 0) {
            ttl = 0;
        }

        rn->ttl = njt_min(rn->ttl, (uint32_t) ttl);

        i += sizeof(njt_resolver_an_t);

        switch (type) {

        case NJT_RESOLVE_A:

            if (qtype != NJT_RESOLVE_A) {
                err = "unexpected A record in DNS response";
                goto invalid;
            }

            if (len != 4) {
                err = "invalid A record in DNS response";
                goto invalid;
            }

            if (i + 4 > n) {
                goto short_response;
            }

            naddrs++;

            break;

#if (NJT_HAVE_INET6)
        case NJT_RESOLVE_AAAA:

            if (qtype != NJT_RESOLVE_AAAA) {
                err = "unexpected AAAA record in DNS response";
                goto invalid;
            }

            if (len != 16) {
                err = "invalid AAAA record in DNS response";
                goto invalid;
            }

            if (i + 16 > n) {
                goto short_response;
            }

            naddrs++;

            break;
#endif

        case NJT_RESOLVE_CNAME:

            cname = &buf[i];

            break;

        case NJT_RESOLVE_DNAME:

            break;

        default:

            njt_log_error(r->log_level, r->log, 0,
                          "unexpected RR type %ui in DNS response", type);
        }

        i += len;
    }

    njt_log_debug3(NJT_LOG_DEBUG_CORE, r->log, 0,
                   "resolver naddrs:%ui cname:%p ttl:%uD",
                   naddrs, cname, rn->ttl);

    if (naddrs) {

        switch (qtype) {

#if (NJT_HAVE_INET6)
        case NJT_RESOLVE_AAAA:

            if (naddrs == 1) {
                addr6 = &rn->u6.addr6;
                rn->naddrs6 = 1;

            } else {
                addr6 = njt_resolver_alloc(r, naddrs * sizeof(struct in6_addr));
                if (addr6 == NULL) {
                    goto failed;
                }

                rn->u6.addrs6 = addr6;
                rn->naddrs6 = (u_short) naddrs;
            }

#if (NJT_SUPPRESS_WARN)
            addr = NULL;
#endif

            break;
#endif

        default: /* NJT_RESOLVE_A */

            if (naddrs == 1) {
                addr = &rn->u.addr;
                rn->naddrs = 1;

            } else {
                addr = njt_resolver_alloc(r, naddrs * sizeof(in_addr_t));
                if (addr == NULL) {
                    goto failed;
                }

                rn->u.addrs = addr;
                rn->naddrs = (u_short) naddrs;
            }

#if (NJT_HAVE_INET6 && NJT_SUPPRESS_WARN)
            addr6 = NULL;
#endif
        }

        j = 0;
        i = ans;

        for (a = 0; a < nan; a++) {

            for ( ;; ) {

                if (buf[i] & 0xc0) {
                    i += 2;
                    break;
                }

                if (buf[i] == 0) {
                    i++;
                    break;
                }

                i += 1 + buf[i];
            }

            an = (njt_resolver_an_t *) &buf[i];

            type = (an->type_hi << 8) + an->type_lo;
            len = (an->len_hi << 8) + an->len_lo;

            i += sizeof(njt_resolver_an_t);

            if (type == NJT_RESOLVE_A) {

                addr[j] = htonl((buf[i] << 24) + (buf[i + 1] << 16)
                                + (buf[i + 2] << 8) + (buf[i + 3]));

                if (++j == naddrs) {

#if (NJT_HAVE_INET6)
                    if (rn->naddrs6 == (u_short) -1) {
                        goto next;
                    }
#endif

                    break;
                }
            }

#if (NJT_HAVE_INET6)
            else if (type == NJT_RESOLVE_AAAA) {

                njt_memcpy(addr6[j].s6_addr, &buf[i], 16);

                if (++j == naddrs) {

                    if (rn->naddrs == (u_short) -1) {
                        goto next;
                    }

                    break;
                }
            }
#endif

            i += len;
        }
    }

    switch (qtype) {

#if (NJT_HAVE_INET6)
    case NJT_RESOLVE_AAAA:

        if (rn->naddrs6 == (u_short) -1) {
            rn->naddrs6 = 0;
        }

        break;
#endif

    default: /* NJT_RESOLVE_A */

        if (rn->naddrs == (u_short) -1) {
            rn->naddrs = 0;
        }
    }

    if (rn->naddrs != (u_short) -1
#if (NJT_HAVE_INET6)
        && rn->naddrs6 != (u_short) -1
#endif
        && rn->naddrs
#if (NJT_HAVE_INET6)
           + rn->naddrs6
#endif
           > 0)
    {

#if (NJT_HAVE_INET6)
    export:
#endif

        naddrs = rn->naddrs;
#if (NJT_HAVE_INET6)
        naddrs += rn->naddrs6;
#endif

        if (naddrs == 1 && rn->naddrs == 1) {
            addrs = NULL;

        } else {
            addrs = njt_resolver_export(r, rn, 0);
            if (addrs == NULL) {
                goto failed;
            }
        }

        njt_queue_remove(&rn->queue);

        rn->valid = njt_time() + (r->valid ? r->valid : (time_t) rn->ttl);
        rn->expire = njt_time() + r->expire;

        njt_queue_insert_head(&r->name_expire_queue, &rn->queue);

        next = rn->waiting;
        rn->waiting = NULL;

        /* unlock name mutex */

        while (next) {
            ctx = next;
            ctx->state = NJT_OK;
            ctx->valid = rn->valid;
            ctx->naddrs = naddrs;

            if (addrs == NULL) {
                ctx->addrs = &ctx->addr;
                ctx->addr.sockaddr = (struct sockaddr *) &ctx->sin;
                ctx->addr.socklen = sizeof(struct sockaddr_in);
                njt_memzero(&ctx->sin, sizeof(struct sockaddr_in));
                ctx->sin.sin_family = AF_INET;
                ctx->sin.sin_addr.s_addr = rn->u.addr;

            } else {
                ctx->addrs = addrs;
            }

            next = ctx->next;

            ctx->handler(ctx);
        }

        if (addrs != NULL) {
            njt_resolver_free(r, addrs->sockaddr);
            njt_resolver_free(r, addrs);
        }

        njt_resolver_free(r, rn->query);
        rn->query = NULL;
#if (NJT_HAVE_INET6)
        rn->query6 = NULL;
#endif

        return;
    }

    if (cname) {

        /* CNAME only */

        if (rn->naddrs == (u_short) -1
#if (NJT_HAVE_INET6)
            || rn->naddrs6 == (u_short) -1
#endif
            )
        {
            goto next;
        }

        if (njt_resolver_copy(r, &name, buf, cname, buf + n) != NJT_OK) {
            goto failed;
        }

        njt_log_debug1(NJT_LOG_DEBUG_CORE, r->log, 0,
                       "resolver cname:\"%V\"", &name);

        njt_queue_remove(&rn->queue);

        rn->cnlen = (u_short) name.len;
        rn->u.cname = name.data;

        rn->valid = njt_time() + (r->valid ? r->valid : (time_t) rn->ttl);
        rn->expire = njt_time() + r->expire;

        njt_queue_insert_head(&r->name_expire_queue, &rn->queue);

        njt_resolver_free(r, rn->query);
        rn->query = NULL;
#if (NJT_HAVE_INET6)
        rn->query6 = NULL;
#endif

        ctx = rn->waiting;
        rn->waiting = NULL;

        if (ctx) {

            if (ctx->recursion++ >= NJT_RESOLVER_MAX_RECURSION) {

                /* unlock name mutex */

                do {
                    ctx->state = NJT_RESOLVE_NXDOMAIN;
                    next = ctx->next;

                    ctx->handler(ctx);

                    ctx = next;
                } while (ctx);

                return;
            }

            for (next = ctx; next; next = next->next) {
                next->node = NULL;
            }

            (void) njt_resolve_name_locked(r, ctx, &name);
        }

        /* unlock name mutex */

        return;
    }

    njt_log_error(r->log_level, r->log, 0,
                  "no A or CNAME types in DNS response");
    return;

short_response:

    err = "short DNS response";

invalid:

    /* unlock name mutex */

    njt_log_error(r->log_level, r->log, 0, err);

    return;

failed:

next:

    /* unlock name mutex */

    return;
}


static void
njt_resolver_process_srv(njt_resolver_t *r, u_char *buf, size_t n,
    njt_uint_t ident, njt_uint_t code, njt_uint_t nan,
    njt_uint_t trunc, njt_uint_t ans)
{
    char                       *err;
    u_char                     *cname;
    size_t                      len;
    int32_t                     ttl;
    uint32_t                    hash;
    njt_str_t                   name;
    njt_uint_t                  type, qident, class, start, nsrvs, a, i, j;
    njt_resolver_an_t          *an;
    njt_resolver_ctx_t         *ctx, *next;
    njt_resolver_srv_t         *srvs;
    njt_resolver_node_t        *rn;
    njt_resolver_connection_t  *rec;

    if (njt_resolver_copy(r, &name, buf,
                          buf + sizeof(njt_resolver_hdr_t), buf + n)
        != NJT_OK)
    {
        return;
    }

    njt_log_debug1(NJT_LOG_DEBUG_CORE, r->log, 0, "resolver qs:%V", &name);

    hash = njt_crc32_short(name.data, name.len);

    rn = njt_resolver_lookup_srv(r, &name, hash);

    if (rn == NULL || rn->query == NULL) {
        njt_log_error(r->log_level, r->log, 0,
                      "unexpected DNS response for %V", &name);
        njt_resolver_free(r, name.data);
        goto failed;
    }

    if (trunc && rn->tcp) {
        njt_resolver_free(r, name.data);
        goto failed;
    }

    qident = (rn->query[0] << 8) + rn->query[1];

    if (ident != qident) {
        njt_log_error(r->log_level, r->log, 0,
                      "wrong ident %ui in DNS response for %V, expect %ui",
                      ident, &name, qident);
        njt_resolver_free(r, name.data);
        goto failed;
    }

    njt_resolver_free(r, name.data);

    if (trunc) {

        njt_queue_remove(&rn->queue);

        if (rn->waiting == NULL) {
            njt_rbtree_delete(&r->srv_rbtree, &rn->node);
            njt_resolver_free_node(r, rn);
            return;
        }

        rec = r->connections.elts;
        rec = &rec[rn->last_connection];

        rn->tcp = 1;

        (void) njt_resolver_send_tcp_query(r, rec, rn->query, rn->qlen);

        rn->expire = njt_time() + r->resend_timeout;

        njt_queue_insert_head(&r->srv_resend_queue, &rn->queue);

        return;
    }

    if (code == 0 && rn->code) {
        code = rn->code;
    }

    if (code == 0 && nan == 0) {
        code = NJT_RESOLVE_NXDOMAIN;
    }

    if (code) {
        next = rn->waiting;
        rn->waiting = NULL;

        njt_queue_remove(&rn->queue);

        njt_rbtree_delete(&r->srv_rbtree, &rn->node);

        while (next) {
            ctx = next;
            ctx->state = code;
            ctx->valid = njt_time() + (r->valid ? r->valid : 10);
            next = ctx->next;

            ctx->handler(ctx);
        }

        njt_resolver_free_node(r, rn);

        return;
    }

    i = ans;
    nsrvs = 0;
    cname = NULL;

    for (a = 0; a < nan; a++) {

        start = i;

        while (i < n) {

            if (buf[i] & 0xc0) {
                i += 2;
                goto found;
            }

            if (buf[i] == 0) {
                i++;
                goto test_length;
            }

            i += 1 + buf[i];
        }

        goto short_response;

    test_length:

        if (i - start < 2) {
            err = "invalid name DNS response";
            goto invalid;
        }

    found:

        if (i + sizeof(njt_resolver_an_t) >= n) {
            goto short_response;
        }

        an = (njt_resolver_an_t *) &buf[i];

        type = (an->type_hi << 8) + an->type_lo;
        class = (an->class_hi << 8) + an->class_lo;
        len = (an->len_hi << 8) + an->len_lo;
        ttl = (an->ttl[0] << 24) + (an->ttl[1] << 16)
            + (an->ttl[2] << 8) + (an->ttl[3]);

        if (class != 1) {
            njt_log_error(r->log_level, r->log, 0,
                          "unexpected RR class %ui in DNS response", class);
            goto failed;
        }

        if (ttl < 0) {
            ttl = 0;
        }

        rn->ttl = njt_min(rn->ttl, (uint32_t) ttl);

        i += sizeof(njt_resolver_an_t);

        switch (type) {

        case NJT_RESOLVE_SRV:

            if (i + 6 > n) {
                goto short_response;
            }

            if (njt_resolver_copy(r, NULL, buf, &buf[i + 6], buf + n)
                != NJT_OK)
            {
                goto failed;
            }

            nsrvs++;

            break;

        case NJT_RESOLVE_CNAME:

            cname = &buf[i];

            break;

        case NJT_RESOLVE_DNAME:

            break;

        default:

            njt_log_error(r->log_level, r->log, 0,
                          "unexpected RR type %ui in DNS response", type);
        }

        i += len;
    }

    njt_log_debug3(NJT_LOG_DEBUG_CORE, r->log, 0,
                   "resolver nsrvs:%ui cname:%p ttl:%uD",
                   nsrvs, cname, rn->ttl);

    if (nsrvs) {

        srvs = njt_resolver_calloc(r, nsrvs * sizeof(njt_resolver_srv_t));
        if (srvs == NULL) {
            goto failed;
        }

        rn->u.srvs = srvs;
        rn->nsrvs = (u_short) nsrvs;

        j = 0;
        i = ans;

        for (a = 0; a < nan; a++) {

            for ( ;; ) {

                if (buf[i] & 0xc0) {
                    i += 2;
                    break;
                }

                if (buf[i] == 0) {
                    i++;
                    break;
                }

                i += 1 + buf[i];
            }

            an = (njt_resolver_an_t *) &buf[i];

            type = (an->type_hi << 8) + an->type_lo;
            len = (an->len_hi << 8) + an->len_lo;

            i += sizeof(njt_resolver_an_t);

            if (type == NJT_RESOLVE_SRV) {

                srvs[j].priority = (buf[i] << 8) + buf[i + 1];
                srvs[j].weight = (buf[i + 2] << 8) + buf[i + 3];

                if (srvs[j].weight == 0) {
                    srvs[j].weight = 1;
                }

                srvs[j].port = (buf[i + 4] << 8) + buf[i + 5];

                if (njt_resolver_copy(r, &srvs[j].name, buf, &buf[i + 6],
                                      buf + n)
                    != NJT_OK)
                {
                    goto failed;
                }

                j++;
            }

            i += len;
        }

        njt_sort(srvs, nsrvs, sizeof(njt_resolver_srv_t),
                 njt_resolver_cmp_srvs);

        njt_resolver_free(r, rn->query);
        rn->query = NULL;

        njt_queue_remove(&rn->queue);

        rn->valid = njt_time() + (r->valid ? r->valid : (time_t) rn->ttl);
        rn->expire = njt_time() + r->expire;

        njt_queue_insert_head(&r->srv_expire_queue, &rn->queue);

        next = rn->waiting;
        rn->waiting = NULL;

        while (next) {
            ctx = next;
            next = ctx->next;

            njt_resolver_resolve_srv_names(ctx, rn);
        }

        return;
    }

    rn->nsrvs = 0;

    if (cname) {

        /* CNAME only */

        if (njt_resolver_copy(r, &name, buf, cname, buf + n) != NJT_OK) {
            goto failed;
        }

        njt_log_debug1(NJT_LOG_DEBUG_CORE, r->log, 0,
                       "resolver cname:\"%V\"", &name);

        njt_queue_remove(&rn->queue);

        rn->cnlen = (u_short) name.len;
        rn->u.cname = name.data;

        rn->valid = njt_time() + (r->valid ? r->valid : (time_t) rn->ttl);
        rn->expire = njt_time() + r->expire;

        njt_queue_insert_head(&r->srv_expire_queue, &rn->queue);

        njt_resolver_free(r, rn->query);
        rn->query = NULL;
#if (NJT_HAVE_INET6)
        rn->query6 = NULL;
#endif

        ctx = rn->waiting;
        rn->waiting = NULL;

        if (ctx) {

            if (ctx->recursion++ >= NJT_RESOLVER_MAX_RECURSION) {

                /* unlock name mutex */

                do {
                    ctx->state = NJT_RESOLVE_NXDOMAIN;
                    next = ctx->next;

                    ctx->handler(ctx);

                    ctx = next;
                } while (ctx);

                return;
            }

            for (next = ctx; next; next = next->next) {
                next->node = NULL;
            }

            (void) njt_resolve_name_locked(r, ctx, &name);
        }

        /* unlock name mutex */

        return;
    }

    njt_log_error(r->log_level, r->log, 0, "no SRV type in DNS response");

    return;

short_response:

    err = "short DNS response";

invalid:

    /* unlock name mutex */

    njt_log_error(r->log_level, r->log, 0, err);

    return;

failed:

    /* unlock name mutex */

    return;
}


static void
njt_resolver_resolve_srv_names(njt_resolver_ctx_t *ctx, njt_resolver_node_t *rn)
{
    njt_uint_t                i;
    njt_resolver_t           *r;
    njt_resolver_ctx_t       *cctx;
    njt_resolver_srv_name_t  *srvs;

    r = ctx->resolver;

    ctx->node = NULL;
    ctx->state = NJT_OK;
    ctx->valid = rn->valid;
    ctx->count = rn->nsrvs;

    srvs = njt_resolver_calloc(r, rn->nsrvs * sizeof(njt_resolver_srv_name_t));
    if (srvs == NULL) {
        goto failed;
    }

    ctx->srvs = srvs;
    ctx->nsrvs = rn->nsrvs;

    if (ctx->event && ctx->event->timer_set) {
        njt_del_timer(ctx->event);
    }

    for (i = 0; i < (njt_uint_t) rn->nsrvs; i++) {
        srvs[i].name.data = njt_resolver_alloc(r, rn->u.srvs[i].name.len);
        if (srvs[i].name.data == NULL) {
            goto failed;
        }

        srvs[i].name.len = rn->u.srvs[i].name.len;
        njt_memcpy(srvs[i].name.data, rn->u.srvs[i].name.data,
                   srvs[i].name.len);

        cctx = njt_resolve_start(r, NULL);
        if (cctx == NULL) {
            goto failed;
        }

        cctx->name = srvs[i].name;
        cctx->handler = njt_resolver_srv_names_handler;
        cctx->data = ctx;
        cctx->srvs = &srvs[i];
        cctx->timeout = ctx->timeout;

        srvs[i].priority = rn->u.srvs[i].priority;
        srvs[i].weight = rn->u.srvs[i].weight;
        srvs[i].port = rn->u.srvs[i].port;
        srvs[i].ctx = cctx;

        if (njt_resolve_name(cctx) == NJT_ERROR) {
            srvs[i].ctx = NULL;
            goto failed;
        }
    }

    return;

failed:

    ctx->state = NJT_ERROR;
    ctx->valid = njt_time() + (r->valid ? r->valid : 10);

    ctx->handler(ctx);
}


static void
njt_resolver_srv_names_handler(njt_resolver_ctx_t *cctx)
{
    njt_uint_t                i;
    njt_addr_t               *addrs;
    njt_resolver_t           *r;
    njt_sockaddr_t           *sockaddr;
    njt_resolver_ctx_t       *ctx;
    njt_resolver_srv_name_t  *srv;

    r = cctx->resolver;
    ctx = cctx->data;
    srv = cctx->srvs;

    ctx->count--;
    ctx->async |= cctx->async;

    srv->ctx = NULL;
    srv->state = cctx->state;

    if (cctx->naddrs) {

        ctx->valid = njt_min(ctx->valid, cctx->valid);

        addrs = njt_resolver_calloc(r, cctx->naddrs * sizeof(njt_addr_t));
        if (addrs == NULL) {
            srv->state = NJT_ERROR;
            goto done;
        }

        sockaddr = njt_resolver_alloc(r, cctx->naddrs * sizeof(njt_sockaddr_t));
        if (sockaddr == NULL) {
            njt_resolver_free(r, addrs);
            srv->state = NJT_ERROR;
            goto done;
        }

        for (i = 0; i < cctx->naddrs; i++) {
            addrs[i].sockaddr = &sockaddr[i].sockaddr;
            addrs[i].socklen = cctx->addrs[i].socklen;

            njt_memcpy(&sockaddr[i], cctx->addrs[i].sockaddr,
                       addrs[i].socklen);

            njt_inet_set_port(addrs[i].sockaddr, srv->port);
        }

        srv->addrs = addrs;
        srv->naddrs = cctx->naddrs;
    }

done:

    njt_resolve_name_done(cctx);

    if (ctx->count == 0) {
        njt_resolver_report_srv(r, ctx);
    }
}


static void
njt_resolver_process_ptr(njt_resolver_t *r, u_char *buf, size_t n,
    njt_uint_t ident, njt_uint_t code, njt_uint_t nan)
{
    char                 *err;
    size_t                len;
    in_addr_t             addr;
    int32_t               ttl;
    njt_int_t             octet;
    njt_str_t             name;
    njt_uint_t            mask, type, class, qident, a, i, start;
    njt_queue_t          *expire_queue;
    njt_rbtree_t         *tree;
    njt_resolver_an_t    *an;
    njt_resolver_ctx_t   *ctx, *next;
    njt_resolver_node_t  *rn;
#if (NJT_HAVE_INET6)
    uint32_t              hash;
    njt_int_t             digit;
    struct in6_addr       addr6;
#endif

    if (njt_resolver_copy(r, &name, buf,
                          buf + sizeof(njt_resolver_hdr_t), buf + n)
        != NJT_OK)
    {
        return;
    }

    njt_log_debug1(NJT_LOG_DEBUG_CORE, r->log, 0, "resolver qs:%V", &name);

    /* AF_INET */

    addr = 0;
    i = sizeof(njt_resolver_hdr_t);

    for (mask = 0; mask < 32; mask += 8) {
        len = buf[i++];

        octet = njt_atoi(&buf[i], len);
        if (octet == NJT_ERROR || octet > 255) {
            goto invalid_in_addr_arpa;
        }

        addr += octet << mask;
        i += len;
    }

    if (njt_strcasecmp(&buf[i], (u_char *) "\7in-addr\4arpa") == 0) {
        i += sizeof("\7in-addr\4arpa");

        /* lock addr mutex */

        rn = njt_resolver_lookup_addr(r, addr);

        tree = &r->addr_rbtree;
        expire_queue = &r->addr_expire_queue;

        goto valid;
    }

invalid_in_addr_arpa:

#if (NJT_HAVE_INET6)

    i = sizeof(njt_resolver_hdr_t);

    for (octet = 15; octet >= 0; octet--) {
        if (buf[i++] != '\1') {
            goto invalid_ip6_arpa;
        }

        digit = njt_hextoi(&buf[i++], 1);
        if (digit == NJT_ERROR) {
            goto invalid_ip6_arpa;
        }

        addr6.s6_addr[octet] = (u_char) digit;

        if (buf[i++] != '\1') {
            goto invalid_ip6_arpa;
        }

        digit = njt_hextoi(&buf[i++], 1);
        if (digit == NJT_ERROR) {
            goto invalid_ip6_arpa;
        }

        addr6.s6_addr[octet] += (u_char) (digit * 16);
    }

    if (njt_strcasecmp(&buf[i], (u_char *) "\3ip6\4arpa") == 0) {
        i += sizeof("\3ip6\4arpa");

        /* lock addr mutex */

        hash = njt_crc32_short(addr6.s6_addr, 16);
        rn = njt_resolver_lookup_addr6(r, &addr6, hash);

        tree = &r->addr6_rbtree;
        expire_queue = &r->addr6_expire_queue;

        goto valid;
    }

invalid_ip6_arpa:
#endif

    njt_log_error(r->log_level, r->log, 0,
                  "invalid in-addr.arpa or ip6.arpa name in DNS response");
    njt_resolver_free(r, name.data);
    return;

valid:

    if (rn == NULL || rn->query == NULL) {
        njt_log_error(r->log_level, r->log, 0,
                      "unexpected DNS response for %V", &name);
        njt_resolver_free(r, name.data);
        goto failed;
    }

    qident = (rn->query[0] << 8) + rn->query[1];

    if (ident != qident) {
        njt_log_error(r->log_level, r->log, 0,
                      "wrong ident %ui in DNS response for %V, expect %ui",
                      ident, &name, qident);
        njt_resolver_free(r, name.data);
        goto failed;
    }

    njt_resolver_free(r, name.data);

    if (code == 0 && nan == 0) {
        code = NJT_RESOLVE_NXDOMAIN;
    }

    if (code) {
        next = rn->waiting;
        rn->waiting = NULL;

        njt_queue_remove(&rn->queue);

        njt_rbtree_delete(tree, &rn->node);

        /* unlock addr mutex */

        while (next) {
            ctx = next;
            ctx->state = code;
            ctx->valid = njt_time() + (r->valid ? r->valid : 10);
            next = ctx->next;

            ctx->handler(ctx);
        }

        njt_resolver_free_node(r, rn);

        return;
    }

    i += sizeof(njt_resolver_qs_t);

    for (a = 0; a < nan; a++) {

        start = i;

        while (i < n) {

            if (buf[i] & 0xc0) {
                i += 2;
                goto found;
            }

            if (buf[i] == 0) {
                i++;
                goto test_length;
            }

            i += 1 + buf[i];
        }

        goto short_response;

    test_length:

        if (i - start < 2) {
            err = "invalid name in DNS response";
            goto invalid;
        }

    found:

        if (i + sizeof(njt_resolver_an_t) >= n) {
            goto short_response;
        }

        an = (njt_resolver_an_t *) &buf[i];

        type = (an->type_hi << 8) + an->type_lo;
        class = (an->class_hi << 8) + an->class_lo;
        len = (an->len_hi << 8) + an->len_lo;
        ttl = (an->ttl[0] << 24) + (an->ttl[1] << 16)
            + (an->ttl[2] << 8) + (an->ttl[3]);

        if (class != 1) {
            njt_log_error(r->log_level, r->log, 0,
                          "unexpected RR class %ui in DNS response", class);
            goto failed;
        }

        if (ttl < 0) {
            ttl = 0;
        }

        njt_log_debug3(NJT_LOG_DEBUG_CORE, r->log, 0,
                      "resolver qt:%ui cl:%ui len:%uz",
                      type, class, len);

        i += sizeof(njt_resolver_an_t);

        switch (type) {

        case NJT_RESOLVE_PTR:

            goto ptr;

        case NJT_RESOLVE_CNAME:

            break;

        default:

            njt_log_error(r->log_level, r->log, 0,
                          "unexpected RR type %ui in DNS response", type);
        }

        i += len;
    }

    /* unlock addr mutex */

    njt_log_error(r->log_level, r->log, 0,
                  "no PTR type in DNS response");
    return;

ptr:

    if (njt_resolver_copy(r, &name, buf, buf + i, buf + n) != NJT_OK) {
        goto failed;
    }

    njt_log_debug1(NJT_LOG_DEBUG_CORE, r->log, 0, "resolver an:%V", &name);

    if (name.len != (size_t) rn->nlen
        || njt_strncmp(name.data, rn->name, name.len) != 0)
    {
        if (rn->nlen) {
            njt_resolver_free(r, rn->name);
        }

        rn->nlen = (u_short) name.len;
        rn->name = name.data;

        name.data = njt_resolver_dup(r, rn->name, name.len);
        if (name.data == NULL) {
            goto failed;
        }
    }

    njt_queue_remove(&rn->queue);

    rn->valid = njt_time() + (r->valid ? r->valid : ttl);
    rn->expire = njt_time() + r->expire;

    njt_queue_insert_head(expire_queue, &rn->queue);

    next = rn->waiting;
    rn->waiting = NULL;

    /* unlock addr mutex */

    while (next) {
        ctx = next;
        ctx->state = NJT_OK;
        ctx->valid = rn->valid;
        ctx->name = name;
        next = ctx->next;

        ctx->handler(ctx);
    }

    njt_resolver_free(r, name.data);

    return;

short_response:

    err = "short DNS response";

invalid:

    /* unlock addr mutex */

    njt_log_error(r->log_level, r->log, 0, err);

    return;

failed:

    /* unlock addr mutex */

    return;
}


static njt_resolver_node_t *
njt_resolver_lookup_name(njt_resolver_t *r, njt_str_t *name, uint32_t hash)
{
    njt_int_t             rc;
    njt_rbtree_node_t    *node, *sentinel;
    njt_resolver_node_t  *rn;

    node = r->name_rbtree.root;
    sentinel = r->name_rbtree.sentinel;

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

        rn = njt_resolver_node(node);

        rc = njt_memn2cmp(name->data, rn->name, name->len, rn->nlen);

        if (rc == 0) {
            return rn;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    /* not found */

    return NULL;
}


static njt_resolver_node_t *
njt_resolver_lookup_srv(njt_resolver_t *r, njt_str_t *name, uint32_t hash)
{
    njt_int_t             rc;
    njt_rbtree_node_t    *node, *sentinel;
    njt_resolver_node_t  *rn;

    node = r->srv_rbtree.root;
    sentinel = r->srv_rbtree.sentinel;

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

        rn = njt_resolver_node(node);

        rc = njt_memn2cmp(name->data, rn->name, name->len, rn->nlen);

        if (rc == 0) {
            return rn;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    /* not found */

    return NULL;
}


static njt_resolver_node_t *
njt_resolver_lookup_addr(njt_resolver_t *r, in_addr_t addr)
{
    njt_rbtree_node_t  *node, *sentinel;

    node = r->addr_rbtree.root;
    sentinel = r->addr_rbtree.sentinel;

    while (node != sentinel) {

        if (addr < node->key) {
            node = node->left;
            continue;
        }

        if (addr > node->key) {
            node = node->right;
            continue;
        }

        /* addr == node->key */

        return njt_resolver_node(node);
    }

    /* not found */

    return NULL;
}


#if (NJT_HAVE_INET6)

static njt_resolver_node_t *
njt_resolver_lookup_addr6(njt_resolver_t *r, struct in6_addr *addr,
    uint32_t hash)
{
    njt_int_t             rc;
    njt_rbtree_node_t    *node, *sentinel;
    njt_resolver_node_t  *rn;

    node = r->addr6_rbtree.root;
    sentinel = r->addr6_rbtree.sentinel;

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

        rn = njt_resolver_node(node);

        rc = njt_memcmp(addr, &rn->addr6, 16);

        if (rc == 0) {
            return rn;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    /* not found */

    return NULL;
}

#endif


static void
njt_resolver_rbtree_insert_value(njt_rbtree_node_t *temp,
    njt_rbtree_node_t *node, njt_rbtree_node_t *sentinel)
{
    njt_rbtree_node_t    **p;
    njt_resolver_node_t   *rn, *rn_temp;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            rn = njt_resolver_node(node);
            rn_temp = njt_resolver_node(temp);

            p = (njt_memn2cmp(rn->name, rn_temp->name, rn->nlen, rn_temp->nlen)
                 < 0) ? &temp->left : &temp->right;
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


#if (NJT_HAVE_INET6)

static void
njt_resolver_rbtree_insert_addr6_value(njt_rbtree_node_t *temp,
    njt_rbtree_node_t *node, njt_rbtree_node_t *sentinel)
{
    njt_rbtree_node_t    **p;
    njt_resolver_node_t   *rn, *rn_temp;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            rn = njt_resolver_node(node);
            rn_temp = njt_resolver_node(temp);

            p = (njt_memcmp(&rn->addr6, &rn_temp->addr6, 16)
                 < 0) ? &temp->left : &temp->right;
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

#endif


static njt_int_t
njt_resolver_create_name_query(njt_resolver_t *r, njt_resolver_node_t *rn,
    njt_str_t *name)
{
    u_char              *p, *s;
    size_t               len, nlen;
    njt_uint_t           ident;
    njt_resolver_qs_t   *qs;
    njt_resolver_hdr_t  *query;

    nlen = name->len ? (1 + name->len + 1) : 1;

    len = sizeof(njt_resolver_hdr_t) + nlen + sizeof(njt_resolver_qs_t);

#if (NJT_HAVE_INET6)
    p = njt_resolver_alloc(r, len * (r->ipv4 + r->ipv6));
#else
    p = njt_resolver_alloc(r, len);
#endif
    if (p == NULL) {
        return NJT_ERROR;
    }

    rn->qlen = (u_short) len;
    rn->query = p;

#if (NJT_HAVE_INET6)
    if (r->ipv6) {
        rn->query6 = r->ipv4 ? (p + len) : p;
    }
#endif

    query = (njt_resolver_hdr_t *) p;

    if (r->ipv4) {
        ident = njt_random();

        njt_log_debug2(NJT_LOG_DEBUG_CORE, r->log, 0,
                       "resolve: \"%V\" A %i", name, ident & 0xffff);

        query->ident_hi = (u_char) ((ident >> 8) & 0xff);
        query->ident_lo = (u_char) (ident & 0xff);
    }

    /* recursion query */
    query->flags_hi = 1; query->flags_lo = 0;

    /* one question */
    query->nqs_hi = 0; query->nqs_lo = 1;
    query->nan_hi = 0; query->nan_lo = 0;
    query->nns_hi = 0; query->nns_lo = 0;
    query->nar_hi = 0; query->nar_lo = 0;

    p += sizeof(njt_resolver_hdr_t) + nlen;

    qs = (njt_resolver_qs_t *) p;

    /* query type */
    qs->type_hi = 0; qs->type_lo = NJT_RESOLVE_A;

    /* IN query class */
    qs->class_hi = 0; qs->class_lo = 1;

    /* convert "www.example.com" to "\3www\7example\3com\0" */

    len = 0;
    p--;
    *p-- = '\0';

    if (name->len == 0)  {
        return NJT_DECLINED;
    }

    for (s = name->data + name->len - 1; s >= name->data; s--) {
        if (*s != '.') {
            *p = *s;
            len++;

        } else {
            if (len == 0 || len > 255) {
                return NJT_DECLINED;
            }

            *p = (u_char) len;
            len = 0;
        }

        p--;
    }

    if (len == 0 || len > 255) {
        return NJT_DECLINED;
    }

    *p = (u_char) len;

#if (NJT_HAVE_INET6)
    if (!r->ipv6) {
        return NJT_OK;
    }

    p = rn->query6;

    if (r->ipv4) {
        njt_memcpy(p, rn->query, rn->qlen);
    }

    query = (njt_resolver_hdr_t *) p;

    ident = njt_random();

    njt_log_debug2(NJT_LOG_DEBUG_CORE, r->log, 0,
                   "resolve: \"%V\" AAAA %i", name, ident & 0xffff);

    query->ident_hi = (u_char) ((ident >> 8) & 0xff);
    query->ident_lo = (u_char) (ident & 0xff);

    p += sizeof(njt_resolver_hdr_t) + nlen;

    qs = (njt_resolver_qs_t *) p;

    qs->type_lo = NJT_RESOLVE_AAAA;
#endif

    return NJT_OK;
}


static njt_int_t
njt_resolver_create_srv_query(njt_resolver_t *r, njt_resolver_node_t *rn,
    njt_str_t *name)
{
    u_char              *p, *s;
    size_t               len, nlen;
    njt_uint_t           ident;
    njt_resolver_qs_t   *qs;
    njt_resolver_hdr_t  *query;

    nlen = name->len ? (1 + name->len + 1) : 1;

    len = sizeof(njt_resolver_hdr_t) + nlen + sizeof(njt_resolver_qs_t);

    p = njt_resolver_alloc(r, len);
    if (p == NULL) {
        return NJT_ERROR;
    }

    rn->qlen = (u_short) len;
    rn->query = p;

    query = (njt_resolver_hdr_t *) p;

    ident = njt_random();

    njt_log_debug2(NJT_LOG_DEBUG_CORE, r->log, 0,
                   "resolve: \"%V\" SRV %i", name, ident & 0xffff);

    query->ident_hi = (u_char) ((ident >> 8) & 0xff);
    query->ident_lo = (u_char) (ident & 0xff);

    /* recursion query */
    query->flags_hi = 1; query->flags_lo = 0;

    /* one question */
    query->nqs_hi = 0; query->nqs_lo = 1;
    query->nan_hi = 0; query->nan_lo = 0;
    query->nns_hi = 0; query->nns_lo = 0;
    query->nar_hi = 0; query->nar_lo = 0;

    p += sizeof(njt_resolver_hdr_t) + nlen;

    qs = (njt_resolver_qs_t *) p;

    /* query type */
    qs->type_hi = 0; qs->type_lo = NJT_RESOLVE_SRV;

    /* IN query class */
    qs->class_hi = 0; qs->class_lo = 1;

    /* converts "www.example.com" to "\3www\7example\3com\0" */

    len = 0;
    p--;
    *p-- = '\0';

    if (name->len == 0)  {
        return NJT_DECLINED;
    }

    for (s = name->data + name->len - 1; s >= name->data; s--) {
        if (*s != '.') {
            *p = *s;
            len++;

        } else {
            if (len == 0 || len > 255) {
                return NJT_DECLINED;
            }

            *p = (u_char) len;
            len = 0;
        }

        p--;
    }

    if (len == 0 || len > 255) {
        return NJT_DECLINED;
    }

    *p = (u_char) len;

    return NJT_OK;
}


static njt_int_t
njt_resolver_create_addr_query(njt_resolver_t *r, njt_resolver_node_t *rn,
    njt_resolver_addr_t *addr)
{
    u_char               *p, *d;
    size_t                len;
    in_addr_t             inaddr;
    njt_int_t             n;
    njt_uint_t            ident;
    njt_resolver_hdr_t   *query;
    struct sockaddr_in   *sin;
#if (NJT_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    switch (addr->sockaddr->sa_family) {

#if (NJT_HAVE_INET6)
    case AF_INET6:
        len = sizeof(njt_resolver_hdr_t)
              + 64 + sizeof(".ip6.arpa.") - 1
              + sizeof(njt_resolver_qs_t);

        break;
#endif

    default: /* AF_INET */
        len = sizeof(njt_resolver_hdr_t)
              + sizeof(".255.255.255.255.in-addr.arpa.") - 1
              + sizeof(njt_resolver_qs_t);
    }

    p = njt_resolver_alloc(r, len);
    if (p == NULL) {
        return NJT_ERROR;
    }

    rn->query = p;
    query = (njt_resolver_hdr_t *) p;

    ident = njt_random();

    query->ident_hi = (u_char) ((ident >> 8) & 0xff);
    query->ident_lo = (u_char) (ident & 0xff);

    /* recursion query */
    query->flags_hi = 1; query->flags_lo = 0;

    /* one question */
    query->nqs_hi = 0; query->nqs_lo = 1;
    query->nan_hi = 0; query->nan_lo = 0;
    query->nns_hi = 0; query->nns_lo = 0;
    query->nar_hi = 0; query->nar_lo = 0;

    p += sizeof(njt_resolver_hdr_t);

    switch (addr->sockaddr->sa_family) {

#if (NJT_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) addr->sockaddr;

        for (n = 15; n >= 0; n--) {
            p = njt_sprintf(p, "\1%xd\1%xd",
                            sin6->sin6_addr.s6_addr[n] & 0xf,
                            (sin6->sin6_addr.s6_addr[n] >> 4) & 0xf);
        }

        p = njt_cpymem(p, "\3ip6\4arpa\0", 10);

        break;
#endif

    default: /* AF_INET */

        sin = (struct sockaddr_in *) addr->sockaddr;
        inaddr = ntohl(sin->sin_addr.s_addr);

        for (n = 0; n < 32; n += 8) {
            d = njt_sprintf(&p[1], "%ud", (inaddr >> n) & 0xff);
            *p = (u_char) (d - &p[1]);
            p = d;
        }

        p = njt_cpymem(p, "\7in-addr\4arpa\0", 14);
    }

    /* query type "PTR", IN query class */
    p = njt_cpymem(p, "\0\14\0\1", 4);

    rn->qlen = (u_short) (p - rn->query);

    return NJT_OK;
}


static njt_int_t
njt_resolver_copy(njt_resolver_t *r, njt_str_t *name, u_char *buf, u_char *src,
    u_char *last)
{
    char        *err;
    u_char      *p, *dst;
    size_t       len;
    njt_uint_t   i, n;

    p = src;
    len = 0;

    /*
     * compression pointers allow to create endless loop, so we set limit;
     * 128 pointers should be enough to store 255-byte name
     */

    for (i = 0; i < 128; i++) {
        n = *p++;

        if (n == 0) {
            goto done;
        }

        if (n & 0xc0) {
            if ((n & 0xc0) != 0xc0) {
                err = "invalid label type in DNS response";
                goto invalid;
            }

            if (p >= last) {
                err = "name is out of DNS response";
                goto invalid;
            }

            n = ((n & 0x3f) << 8) + *p;
            p = &buf[n];

        } else {
            len += 1 + n;
            p = &p[n];
        }

        if (p >= last) {
            err = "name is out of DNS response";
            goto invalid;
        }
    }

    err = "compression pointers loop in DNS response";

invalid:

    njt_log_error(r->log_level, r->log, 0, err);

    return NJT_ERROR;

done:

    if (name == NULL) {
        return NJT_OK;
    }

    if (len == 0) {
        njt_str_null(name);
        return NJT_OK;
    }

    dst = njt_resolver_alloc(r, len);
    if (dst == NULL) {
        return NJT_ERROR;
    }

    name->data = dst;

    for ( ;; ) {
        n = *src++;

        if (n == 0) {
            name->len = dst - name->data - 1;
            return NJT_OK;
        }

        if (n & 0xc0) {
            n = ((n & 0x3f) << 8) + *src;
            src = &buf[n];

        } else {
            njt_strlow(dst, src, n);
            dst += n;
            src += n;
            *dst++ = '.';
        }
    }
}


static njt_int_t
njt_resolver_set_timeout(njt_resolver_t *r, njt_resolver_ctx_t *ctx)
{
    if (ctx->event || ctx->timeout == 0) {
        return NJT_OK;
    }

    ctx->event = njt_resolver_calloc(r, sizeof(njt_event_t));
    if (ctx->event == NULL) {
        return NJT_ERROR;
    }

    ctx->event->handler = njt_resolver_timeout_handler;
    ctx->event->data = ctx;
    ctx->event->log = r->log;
    ctx->event->cancelable = ctx->cancelable;
    ctx->ident = -1;

    njt_add_timer(ctx->event, ctx->timeout);

    return NJT_OK;
}


static void
njt_resolver_timeout_handler(njt_event_t *ev)
{
    njt_resolver_ctx_t  *ctx;

    ctx = ev->data;

    ctx->state = NJT_RESOLVE_TIMEDOUT;

    ctx->handler(ctx);
}


static void
njt_resolver_free_node(njt_resolver_t *r, njt_resolver_node_t *rn)
{
    njt_uint_t  i;

    /* lock alloc mutex */

    if (rn->query) {
        njt_resolver_free_locked(r, rn->query);
    }

    if (rn->name) {
        njt_resolver_free_locked(r, rn->name);
    }

    if (rn->cnlen) {
        njt_resolver_free_locked(r, rn->u.cname);
    }

    if (rn->naddrs > 1 && rn->naddrs != (u_short) -1) {
        njt_resolver_free_locked(r, rn->u.addrs);
    }

#if (NJT_HAVE_INET6)
    if (rn->naddrs6 > 1 && rn->naddrs6 != (u_short) -1) {
        njt_resolver_free_locked(r, rn->u6.addrs6);
    }
#endif

    if (rn->nsrvs) {
        for (i = 0; i < (njt_uint_t) rn->nsrvs; i++) {
            if (rn->u.srvs[i].name.data) {
                njt_resolver_free_locked(r, rn->u.srvs[i].name.data);
            }
        }

        njt_resolver_free_locked(r, rn->u.srvs);
    }

    njt_resolver_free_locked(r, rn);

    /* unlock alloc mutex */
}


static void *
njt_resolver_alloc(njt_resolver_t *r, size_t size)
{
    u_char  *p;

    /* lock alloc mutex */

    p = njt_alloc(size, r->log);

    /* unlock alloc mutex */

    return p;
}


static void *
njt_resolver_calloc(njt_resolver_t *r, size_t size)
{
    u_char  *p;

    p = njt_resolver_alloc(r, size);

    if (p) {
        njt_memzero(p, size);
    }

    return p;
}


static void
njt_resolver_free(njt_resolver_t *r, void *p)
{
    /* lock alloc mutex */

    njt_free(p);

    /* unlock alloc mutex */
}


static void
njt_resolver_free_locked(njt_resolver_t *r, void *p)
{
    njt_free(p);
}


static void *
njt_resolver_dup(njt_resolver_t *r, void *src, size_t size)
{
    void  *dst;

    dst = njt_resolver_alloc(r, size);

    if (dst == NULL) {
        return dst;
    }

    njt_memcpy(dst, src, size);

    return dst;
}


static njt_resolver_addr_t *
njt_resolver_export(njt_resolver_t *r, njt_resolver_node_t *rn,
    njt_uint_t rotate)
{
    njt_uint_t            d, i, j, n;
    in_addr_t            *addr;
    njt_sockaddr_t       *sockaddr;
    struct sockaddr_in   *sin;
    njt_resolver_addr_t  *dst;
#if (NJT_HAVE_INET6)
    struct in6_addr      *addr6;
    struct sockaddr_in6  *sin6;
#endif

    n = rn->naddrs;
#if (NJT_HAVE_INET6)
    n += rn->naddrs6;
#endif

    dst = njt_resolver_calloc(r, n * sizeof(njt_resolver_addr_t));
    if (dst == NULL) {
        return NULL;
    }

    sockaddr = njt_resolver_calloc(r, n * sizeof(njt_sockaddr_t));
    if (sockaddr == NULL) {
        njt_resolver_free(r, dst);
        return NULL;
    }

    i = 0;
    d = rotate ? njt_random() % n : 0;

    if (rn->naddrs) {
        j = rotate ? njt_random() % rn->naddrs : 0;

        addr = (rn->naddrs == 1) ? &rn->u.addr : rn->u.addrs;

        do {
            sin = &sockaddr[d].sockaddr_in;
            sin->sin_family = AF_INET;
            sin->sin_addr.s_addr = addr[j++];
            dst[d].sockaddr = (struct sockaddr *) sin;
            dst[d++].socklen = sizeof(struct sockaddr_in);

            if (d == n) {
                d = 0;
            }

            if (j == (njt_uint_t) rn->naddrs) {
                j = 0;
            }
        } while (++i < (njt_uint_t) rn->naddrs);
    }

#if (NJT_HAVE_INET6)
    if (rn->naddrs6) {
        j = rotate ? njt_random() % rn->naddrs6 : 0;

        addr6 = (rn->naddrs6 == 1) ? &rn->u6.addr6 : rn->u6.addrs6;

        do {
            sin6 = &sockaddr[d].sockaddr_in6;
            sin6->sin6_family = AF_INET6;
            njt_memcpy(sin6->sin6_addr.s6_addr, addr6[j++].s6_addr, 16);
            dst[d].sockaddr = (struct sockaddr *) sin6;
            dst[d++].socklen = sizeof(struct sockaddr_in6);

            if (d == n) {
                d = 0;
            }

            if (j == rn->naddrs6) {
                j = 0;
            }
        } while (++i < n);
    }
#endif

    return dst;
}


static void
njt_resolver_report_srv(njt_resolver_t *r, njt_resolver_ctx_t *ctx)
{
    njt_uint_t                naddrs, nsrvs, nw, i, j, k, l, m, n, w;
    njt_resolver_addr_t      *addrs;
    njt_resolver_srv_name_t  *srvs;

    srvs = ctx->srvs;
    nsrvs = ctx->nsrvs;

    naddrs = 0;

    for (i = 0; i < nsrvs; i++) {
        if (srvs[i].state == NJT_ERROR) {
            ctx->state = NJT_ERROR;
            ctx->valid = njt_time() + (r->valid ? r->valid : 10);

            ctx->handler(ctx);
            return;
        }

        naddrs += srvs[i].naddrs;
    }

    if (naddrs == 0) {
        ctx->state = srvs[0].state;

        for (i = 0; i < nsrvs; i++) {
            if (srvs[i].state == NJT_RESOLVE_NXDOMAIN) {
                ctx->state = NJT_RESOLVE_NXDOMAIN;
                break;
            }
        }

        ctx->valid = njt_time() + (r->valid ? r->valid : 10);

        ctx->handler(ctx);
        return;
    }

    addrs = njt_resolver_calloc(r, naddrs * sizeof(njt_resolver_addr_t));
    if (addrs == NULL) {
        ctx->state = NJT_ERROR;
        ctx->valid = njt_time() + (r->valid ? r->valid : 10);

        ctx->handler(ctx);
        return;
    }

    i = 0;
    n = 0;

    do {
        nw = 0;

        for (j = i; j < nsrvs; j++) {
            if (srvs[j].priority != srvs[i].priority) {
                break;
            }

            nw += srvs[j].naddrs * srvs[j].weight;
        }

        if (nw == 0) {
            goto next_srv;
        }

        w = njt_random() % nw;

        for (k = i; k < j; k++) {
            if (w < srvs[k].naddrs * srvs[k].weight) {
                break;
            }

            w -= srvs[k].naddrs * srvs[k].weight;
        }

        for (l = i; l < j; l++) {

            for (m = 0; m < srvs[k].naddrs; m++) {
                addrs[n].socklen = srvs[k].addrs[m].socklen;
                addrs[n].sockaddr = srvs[k].addrs[m].sockaddr;
                addrs[n].name = srvs[k].name;
                addrs[n].priority = srvs[k].priority;
                addrs[n].weight = srvs[k].weight;
                n++;
            }

            if (++k == j) {
                k = i;
            }
        }

next_srv:

        i = j;

    } while (i < ctx->nsrvs);

    ctx->state = NJT_OK;
    ctx->addrs = addrs;
    ctx->naddrs = naddrs;

    ctx->handler(ctx);

    njt_resolver_free(r, addrs);
}


char *
njt_resolver_strerror(njt_int_t err)
{
    static char *errors[] = {
        "Format error",     /* FORMERR */
        "Server failure",   /* SERVFAIL */
        "Host not found",   /* NXDOMAIN */
        "Unimplemented",    /* NOTIMP */
        "Operation refused" /* REFUSED */
    };

    if (err > 0 && err < 6) {
        return errors[err - 1];
    }

    if (err == NJT_RESOLVE_TIMEDOUT) {
        return "Operation timed out";
    }

    return "Unknown error";
}


static u_char *
njt_resolver_log_error(njt_log_t *log, u_char *buf, size_t len)
{
    u_char                     *p;
    njt_resolver_connection_t  *rec;

    p = buf;

    if (log->action) {
        p = njt_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
    }

    rec = log->data;

    if (rec) {
        p = njt_snprintf(p, len, ", resolver: %V", &rec->server);
    }

    return p;
}


static njt_int_t
njt_udp_connect(njt_resolver_connection_t *rec)
{
    int                rc;
    njt_int_t          event;
    njt_event_t       *rev, *wev;
    njt_socket_t       s;
    njt_connection_t  *c;

    s = njt_socket(rec->sockaddr->sa_family, SOCK_DGRAM, 0);

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, &rec->log, 0, "UDP socket %d", s);

    if (s == (njt_socket_t) -1) {
        njt_log_error(NJT_LOG_ALERT, &rec->log, njt_socket_errno,
                      njt_socket_n " failed");
        return NJT_ERROR;
    }

    c = njt_get_connection(s, &rec->log);

    if (c == NULL) {
        if (njt_close_socket(s) == -1) {
            njt_log_error(NJT_LOG_ALERT, &rec->log, njt_socket_errno,
                          njt_close_socket_n " failed");
        }

        return NJT_ERROR;
    }

    if (njt_nonblocking(s) == -1) {
        njt_log_error(NJT_LOG_ALERT, &rec->log, njt_socket_errno,
                      njt_nonblocking_n " failed");

        goto failed;
    }

    rev = c->read;
    wev = c->write;

    rev->log = &rec->log;
    wev->log = &rec->log;

    rec->udp = c;

    c->number = njt_atomic_fetch_add(njt_connection_counter, 1);

    c->start_time = njt_current_msec;

    njt_log_debug3(NJT_LOG_DEBUG_EVENT, &rec->log, 0,
                   "connect to %V, fd:%d #%uA", &rec->server, s, c->number);

    rc = connect(s, rec->sockaddr, rec->socklen);

    /* TODO: iocp */

    if (rc == -1) {
        njt_log_error(NJT_LOG_CRIT, &rec->log, njt_socket_errno,
                      "connect() failed");

        goto failed;
    }

    /* UDP sockets are always ready to write */
    wev->ready = 1;

    event = (njt_event_flags & NJT_USE_CLEAR_EVENT) ?
                /* kqueue, epoll */                 NJT_CLEAR_EVENT:
                /* select, poll, /dev/poll */       NJT_LEVEL_EVENT;
                /* eventport event type has no meaning: oneshot only */

    if (njt_add_event(rev, NJT_READ_EVENT, event) != NJT_OK) {
        goto failed;
    }

    return NJT_OK;

failed:

    njt_close_connection(c);
    rec->udp = NULL;

    return NJT_ERROR;
}


static njt_int_t
njt_tcp_connect(njt_resolver_connection_t *rec)
{
    int                rc;
    njt_int_t          event;
    njt_err_t          err;
    njt_uint_t         level;
    njt_socket_t       s;
    njt_event_t       *rev, *wev;
    njt_connection_t  *c;

// openresty patch
#if (NJT_HAVE_SOCKET_CLOEXEC)
    s = njt_socket(rec->sockaddr->sa_family, SOCK_STREAM | SOCK_CLOEXEC, 0);

#else
    s = njt_socket(rec->sockaddr->sa_family, SOCK_STREAM, 0);
#endif
// openresty patch end
    s = njt_socket(rec->sockaddr->sa_family, SOCK_STREAM, 0); // openresty patch


    njt_log_debug1(NJT_LOG_DEBUG_EVENT, &rec->log, 0, "TCP socket %d", s);

    if (s == (njt_socket_t) -1) {
        njt_log_error(NJT_LOG_ALERT, &rec->log, njt_socket_errno,
                      njt_socket_n " failed");
        return NJT_ERROR;
    }

    c = njt_get_connection(s, &rec->log);

    if (c == NULL) {
        if (njt_close_socket(s) == -1) {
            njt_log_error(NJT_LOG_ALERT, &rec->log, njt_socket_errno,
                          njt_close_socket_n " failed");
        }

        return NJT_ERROR;
    }

    if (njt_nonblocking(s) == -1) {
        njt_log_error(NJT_LOG_ALERT, &rec->log, njt_socket_errno,
                      njt_nonblocking_n " failed");

        goto failed;
    }

    rev = c->read;
    wev = c->write;

    rev->log = &rec->log;
    wev->log = &rec->log;

    rec->tcp = c;

    c->number = njt_atomic_fetch_add(njt_connection_counter, 1);

    c->start_time = njt_current_msec;

    if (njt_add_conn) {
        if (njt_add_conn(c) == NJT_ERROR) {
            goto failed;
        }
    }

    njt_log_debug3(NJT_LOG_DEBUG_EVENT, &rec->log, 0,
                   "connect to %V, fd:%d #%uA", &rec->server, s, c->number);

    rc = connect(s, rec->sockaddr, rec->socklen);

    if (rc == -1) {
        err = njt_socket_errno;


        if (err != NJT_EINPROGRESS
#if (NJT_WIN32)
            /* Winsock returns WSAEWOULDBLOCK (NJT_EAGAIN) */
            && err != NJT_EAGAIN
#endif
            )
        {
            if (err == NJT_ECONNREFUSED
#if (NJT_LINUX)
                /*
                 * Linux returns EAGAIN instead of ECONNREFUSED
                 * for unix sockets if listen queue is full
                 */
                || err == NJT_EAGAIN
#endif
                || err == NJT_ECONNRESET
                || err == NJT_ENETDOWN
                || err == NJT_ENETUNREACH
                || err == NJT_EHOSTDOWN
                || err == NJT_EHOSTUNREACH)
            {
                level = NJT_LOG_ERR;

            } else {
                level = NJT_LOG_CRIT;
            }

            njt_log_error(level, &rec->log, err, "connect() to %V failed",
                          &rec->server);

            njt_close_connection(c);
            rec->tcp = NULL;

            return NJT_ERROR;
        }
    }

    if (njt_add_conn) {
        if (rc == -1) {

            /* NJT_EINPROGRESS */

            return NJT_AGAIN;
        }

        njt_log_debug0(NJT_LOG_DEBUG_EVENT, &rec->log, 0, "connected");

        wev->ready = 1;

        return NJT_OK;
    }

    if (njt_event_flags & NJT_USE_IOCP_EVENT) {

        njt_log_debug1(NJT_LOG_DEBUG_EVENT, &rec->log, njt_socket_errno,
                       "connect(): %d", rc);

        if (njt_blocking(s) == -1) {
            njt_log_error(NJT_LOG_ALERT, &rec->log, njt_socket_errno,
                          njt_blocking_n " failed");
            goto failed;
        }

        /*
         * FreeBSD's aio allows to post an operation on non-connected socket.
         * NT does not support it.
         *
         * TODO: check in Win32, etc. As workaround we can use NJT_ONESHOT_EVENT
         */

        rev->ready = 1;
        wev->ready = 1;

        return NJT_OK;
    }

    if (njt_event_flags & NJT_USE_CLEAR_EVENT) {

        /* kqueue */

        event = NJT_CLEAR_EVENT;

    } else {

        /* select, poll, /dev/poll */

        event = NJT_LEVEL_EVENT;
    }

    if (njt_add_event(rev, NJT_READ_EVENT, event) != NJT_OK) {
        goto failed;
    }

    if (rc == -1) {

        /* NJT_EINPROGRESS */

        if (njt_add_event(wev, NJT_WRITE_EVENT, event) != NJT_OK) {
            goto failed;
        }

        return NJT_AGAIN;
    }

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, &rec->log, 0, "connected");

    wev->ready = 1;

    return NJT_OK;

failed:

    njt_close_connection(c);
    rec->tcp = NULL;

    return NJT_ERROR;
}


static njt_int_t
njt_resolver_cmp_srvs(const void *one, const void *two)
{
    njt_int_t            p1, p2;
    njt_resolver_srv_t  *first, *second;

    first = (njt_resolver_srv_t *) one;
    second = (njt_resolver_srv_t *) two;

    p1 = first->priority;
    p2 = second->priority;

    return p1 - p2;
}
