
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>


#define NJT_QUIC_BPF_VARNAME  "NJET_BPF_MAPS"
#define NJT_QUIC_BPF_VARSEP    ';'
#define NJT_QUIC_BPF_ADDRSEP   '#'


#define njt_quic_bpf_get_conf(cycle)                                          \
    (njt_quic_bpf_conf_t *) njt_get_conf(cycle->conf_ctx, njt_quic_bpf_module)

#define njt_quic_bpf_get_old_conf(cycle)                                      \
    cycle->old_cycle->conf_ctx ? njt_quic_bpf_get_conf(cycle->old_cycle)      \
                               : NULL

#define njt_core_get_conf(cycle)                                              \
    (njt_core_conf_t *) njt_get_conf(cycle->conf_ctx, njt_core_module)


typedef struct {
    njt_queue_t           queue;
    int                   map_fd;

    struct sockaddr      *sockaddr;
    socklen_t             socklen;
    njt_uint_t            unused;     /* unsigned  unused:1; */
} njt_quic_sock_group_t;


typedef struct {
    njt_flag_t            enabled;
    njt_uint_t            map_size;
    njt_queue_t           groups;     /* of njt_quic_sock_group_t */
} njt_quic_bpf_conf_t;


static void *njt_quic_bpf_create_conf(njt_cycle_t *cycle);
static njt_int_t njt_quic_bpf_module_init(njt_cycle_t *cycle);

static void njt_quic_bpf_cleanup(void *data);
static njt_inline void njt_quic_bpf_close(njt_log_t *log, int fd,
    const char *name);

static njt_quic_sock_group_t *njt_quic_bpf_find_group(njt_quic_bpf_conf_t *bcf,
    njt_listening_t *ls);
static njt_quic_sock_group_t *njt_quic_bpf_alloc_group(njt_cycle_t *cycle,
    struct sockaddr *sa, socklen_t socklen);
static njt_quic_sock_group_t *njt_quic_bpf_create_group(njt_cycle_t *cycle,
    njt_listening_t *ls);
static njt_quic_sock_group_t *njt_quic_bpf_get_group(njt_cycle_t *cycle,
    njt_listening_t *ls);
static njt_int_t njt_quic_bpf_group_add_socket(njt_cycle_t *cycle,
    njt_listening_t *ls);
static uint64_t njt_quic_bpf_socket_key(njt_fd_t fd, njt_log_t *log);

static njt_int_t njt_quic_bpf_export_maps(njt_cycle_t *cycle);
static njt_int_t njt_quic_bpf_import_maps(njt_cycle_t *cycle);

extern njt_bpf_program_t  njt_quic_reuseport_helper;


static njt_command_t  njt_quic_bpf_commands[] = {

    { njt_string("quic_bpf"),
      NJT_MAIN_CONF|NJT_DIRECT_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      0,
      offsetof(njt_quic_bpf_conf_t, enabled),
      NULL },

      njt_null_command
};


static njt_core_module_t  njt_quic_bpf_module_ctx = {
    njt_string("quic_bpf"),
    njt_quic_bpf_create_conf,
    NULL
};


njt_module_t  njt_quic_bpf_module = {
    NJT_MODULE_V1,
    &njt_quic_bpf_module_ctx,              /* module context */
    njt_quic_bpf_commands,                 /* module directives */
    NJT_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    njt_quic_bpf_module_init,              /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};


static void *
njt_quic_bpf_create_conf(njt_cycle_t *cycle)
{
    njt_quic_bpf_conf_t  *bcf;

    bcf = njt_pcalloc(cycle->pool, sizeof(njt_quic_bpf_conf_t));
    if (bcf == NULL) {
        return NULL;
    }

    bcf->enabled = NJT_CONF_UNSET;
    bcf->map_size = NJT_CONF_UNSET_UINT;

    njt_queue_init(&bcf->groups);

    return bcf;
}


static njt_int_t
njt_quic_bpf_module_init(njt_cycle_t *cycle)
{
    njt_uint_t            i;
    njt_listening_t      *ls;
    njt_core_conf_t      *ccf;
    njt_pool_cleanup_t   *cln;
    njt_quic_bpf_conf_t  *bcf;

    if (njt_test_config) {
        /*
         * during config test, SO_REUSEPORT socket option is
         * not set, thus making further processing meaningless
         */
        return NJT_OK;
    }

    ccf = njt_core_get_conf(cycle);
    bcf = njt_quic_bpf_get_conf(cycle);

    njt_conf_init_value(bcf->enabled, 0);

    bcf->map_size = ccf->worker_processes * 4;

    cln = njt_pool_cleanup_add(cycle->pool, 0);
    if (cln == NULL) {
        goto failed;
    }

    cln->data = bcf;
    cln->handler = njt_quic_bpf_cleanup;

    if (njt_inherited && njt_is_init_cycle(cycle->old_cycle)) {
        if (njt_quic_bpf_import_maps(cycle) != NJT_OK) {
            goto failed;
        }
    }

    ls = cycle->listening.elts;

    for (i = 0; i < cycle->listening.nelts; i++) {
        if (ls[i].quic && ls[i].reuseport) {
            if (njt_quic_bpf_group_add_socket(cycle, &ls[i]) != NJT_OK) {
                goto failed;
            }
        }
    }

    if (njt_quic_bpf_export_maps(cycle) != NJT_OK) {
        goto failed;
    }

    return NJT_OK;

failed:

    if (njt_is_init_cycle(cycle->old_cycle)) {
        njt_log_error(NJT_LOG_EMERG, cycle->log, 0,
                      "njt_quic_bpf_module failed to initialize, check limits");

        /* refuse to start */
        return NJT_ERROR;
    }

    /*
     * returning error now will lead to master process exiting immediately
     * leaving worker processes orphaned, what is really unexpected.
     * Instead, just issue a not about failed initialization and try
     * to cleanup a bit. Still program can be already loaded to kernel
     * for some reuseport groups, and there is no way to revert, so
     * behaviour may be inconsistent.
     */

    njt_log_error(NJT_LOG_EMERG, cycle->log, 0,
                  "njt_quic_bpf_module failed to initialize properly, ignored."
                  "please check limits and note that njet state now "
                  "can be inconsistent and restart may be required");

    return NJT_OK;
}


static void
njt_quic_bpf_cleanup(void *data)
{
    njt_quic_bpf_conf_t  *bcf = (njt_quic_bpf_conf_t *) data;

    njt_queue_t            *q;
    njt_quic_sock_group_t  *grp;

    for (q = njt_queue_head(&bcf->groups);
         q != njt_queue_sentinel(&bcf->groups);
         q = njt_queue_next(q))
    {
        grp = njt_queue_data(q, njt_quic_sock_group_t, queue);

        njt_quic_bpf_close(njt_cycle->log, grp->map_fd, "map");
    }
}


static njt_inline void
njt_quic_bpf_close(njt_log_t *log, int fd, const char *name)
{
    if (close(fd) != -1) {
        return;
    }

    njt_log_error(NJT_LOG_EMERG, log, njt_errno,
                  "quic bpf close %s fd:%d failed", name, fd);
}


static njt_quic_sock_group_t *
njt_quic_bpf_find_group(njt_quic_bpf_conf_t *bcf, njt_listening_t *ls)
{
    njt_queue_t            *q;
    njt_quic_sock_group_t  *grp;

    for (q = njt_queue_head(&bcf->groups);
         q != njt_queue_sentinel(&bcf->groups);
         q = njt_queue_next(q))
    {
        grp = njt_queue_data(q, njt_quic_sock_group_t, queue);

        if (njt_cmp_sockaddr(ls->sockaddr, ls->socklen,
                             grp->sockaddr, grp->socklen, 1)
            == NJT_OK)
        {
            return grp;
        }
    }

    return NULL;
}


static njt_quic_sock_group_t *
njt_quic_bpf_alloc_group(njt_cycle_t *cycle, struct sockaddr *sa,
    socklen_t socklen)
{
    njt_quic_bpf_conf_t    *bcf;
    njt_quic_sock_group_t  *grp;

    bcf = njt_quic_bpf_get_conf(cycle);

    grp = njt_pcalloc(cycle->pool, sizeof(njt_quic_sock_group_t));
    if (grp == NULL) {
        return NULL;
    }

    grp->socklen = socklen;
    grp->sockaddr = njt_palloc(cycle->pool, socklen);
    if (grp->sockaddr == NULL) {
        return NULL;
    }
    njt_memcpy(grp->sockaddr, sa, socklen);

    njt_queue_insert_tail(&bcf->groups, &grp->queue);

    return grp;
}


static njt_quic_sock_group_t *
njt_quic_bpf_create_group(njt_cycle_t *cycle, njt_listening_t *ls)
{
    int                     progfd, failed, flags, rc;
    njt_quic_bpf_conf_t    *bcf;
    njt_quic_sock_group_t  *grp;

    bcf = njt_quic_bpf_get_conf(cycle);

    if (!bcf->enabled) {
        return NULL;
    }

    grp = njt_quic_bpf_alloc_group(cycle, ls->sockaddr, ls->socklen);
    if (grp == NULL) {
        return NULL;
    }

    grp->map_fd = njt_bpf_map_create(cycle->log, BPF_MAP_TYPE_SOCKHASH,
                                     sizeof(uint64_t), sizeof(uint64_t),
                                     bcf->map_size, 0);
    if (grp->map_fd == -1) {
        goto failed;
    }

    flags = fcntl(grp->map_fd, F_GETFD);
    if (flags == -1) {
        njt_log_error(NJT_LOG_EMERG, cycle->log, errno,
                      "quic bpf getfd failed");
        goto failed;
    }

    /* need to inherit map during binary upgrade after exec */
    flags &= ~FD_CLOEXEC;

    rc = fcntl(grp->map_fd, F_SETFD, flags);
    if (rc == -1) {
        njt_log_error(NJT_LOG_EMERG, cycle->log, errno,
                      "quic bpf setfd failed");
        goto failed;
    }

    njt_bpf_program_link(&njt_quic_reuseport_helper,
                         "njt_quic_sockmap", grp->map_fd);

    progfd = njt_bpf_load_program(cycle->log, &njt_quic_reuseport_helper);
    if (progfd < 0) {
        goto failed;
    }

    failed = 0;

    if (setsockopt(ls->fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF,
                   &progfd, sizeof(int))
        == -1)
    {
        njt_log_error(NJT_LOG_EMERG, cycle->log, njt_socket_errno,
                      "quic bpf setsockopt(SO_ATTACH_REUSEPORT_EBPF) failed");
        failed = 1;
    }

    njt_quic_bpf_close(cycle->log, progfd, "program");

    if (failed) {
        goto failed;
    }

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                   "quic bpf sockmap created fd:%d", grp->map_fd);
    return grp;

failed:

    if (grp->map_fd != -1) {
        njt_quic_bpf_close(cycle->log, grp->map_fd, "map");
    }

    njt_queue_remove(&grp->queue);

    return NULL;
}


static njt_quic_sock_group_t *
njt_quic_bpf_get_group(njt_cycle_t *cycle, njt_listening_t *ls)
{
    njt_quic_bpf_conf_t    *bcf, *old_bcf;
    njt_quic_sock_group_t  *grp, *ogrp;

    bcf = njt_quic_bpf_get_conf(cycle);

    grp = njt_quic_bpf_find_group(bcf, ls);
    if (grp) {
        return grp;
    }

    old_bcf = njt_quic_bpf_get_old_conf(cycle);

    if (old_bcf == NULL) {
        return njt_quic_bpf_create_group(cycle, ls);
    }

    ogrp = njt_quic_bpf_find_group(old_bcf, ls);
    if (ogrp == NULL) {
        return njt_quic_bpf_create_group(cycle, ls);
    }

    grp = njt_quic_bpf_alloc_group(cycle, ls->sockaddr, ls->socklen);
    if (grp == NULL) {
        return NULL;
    }

    grp->map_fd = dup(ogrp->map_fd);
    if (grp->map_fd == -1) {
        njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                      "quic bpf failed to duplicate bpf map descriptor");

        njt_queue_remove(&grp->queue);

        return NULL;
    }

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                   "quic bpf sockmap fd duplicated old:%d new:%d",
                   ogrp->map_fd, grp->map_fd);

    return grp;
}


static njt_int_t
njt_quic_bpf_group_add_socket(njt_cycle_t *cycle,  njt_listening_t *ls)
{
    uint64_t                cookie;
    njt_quic_bpf_conf_t    *bcf;
    njt_quic_sock_group_t  *grp;

    bcf = njt_quic_bpf_get_conf(cycle);

    grp = njt_quic_bpf_get_group(cycle, ls);

    if (grp == NULL) {
        if (!bcf->enabled) {
            return NJT_OK;
        }

        return NJT_ERROR;
    }

    grp->unused = 0;

    cookie = njt_quic_bpf_socket_key(ls->fd, cycle->log);
    if (cookie == (uint64_t) NJT_ERROR) {
        return NJT_ERROR;
    }

    /* map[cookie] = socket; for use in kernel helper */
    if (njt_bpf_map_update(grp->map_fd, &cookie, &ls->fd, BPF_ANY) == -1) {
        njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                      "quic bpf failed to update socket map key=%xL", cookie);
        return NJT_ERROR;
    }

    njt_log_debug4(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                 "quic bpf sockmap fd:%d add socket:%d cookie:0x%xL worker:%ui",
                 grp->map_fd, ls->fd, cookie, ls->worker);

    /* do not inherit this socket */
    ls->ignore = 1;

    return NJT_OK;
}


static uint64_t
njt_quic_bpf_socket_key(njt_fd_t fd, njt_log_t *log)
{
    uint64_t   cookie;
    socklen_t  optlen;

    optlen = sizeof(cookie);

    if (getsockopt(fd, SOL_SOCKET, SO_COOKIE, &cookie, &optlen) == -1) {
        njt_log_error(NJT_LOG_EMERG, log, njt_socket_errno,
                      "quic bpf getsockopt(SO_COOKIE) failed");

        return (njt_uint_t) NJT_ERROR;
    }

    return cookie;
}


static njt_int_t
njt_quic_bpf_export_maps(njt_cycle_t *cycle)
{
    u_char                 *p, *buf;
    size_t                  len;
    njt_str_t              *var;
    njt_queue_t            *q;
    njt_core_conf_t        *ccf;
    njt_quic_bpf_conf_t    *bcf;
    njt_quic_sock_group_t  *grp;

    ccf = njt_core_get_conf(cycle);
    bcf = njt_quic_bpf_get_conf(cycle);

    len = sizeof(NJT_QUIC_BPF_VARNAME) + 1;

    q = njt_queue_head(&bcf->groups);

    while (q != njt_queue_sentinel(&bcf->groups)) {

        grp = njt_queue_data(q, njt_quic_sock_group_t, queue);

        q = njt_queue_next(q);

        if (grp->unused) {
            /*
             * map was inherited, but it is not used in this configuration;
             * do not pass such map further and drop the group to prevent
             * interference with changes during reload
             */

            njt_quic_bpf_close(cycle->log, grp->map_fd, "map");
            njt_queue_remove(&grp->queue);

            continue;
        }

        len += NJT_INT32_LEN + 1 + NJT_SOCKADDR_STRLEN + 1;
    }

    len++;

    buf = njt_palloc(cycle->pool, len);
    if (buf == NULL) {
        return NJT_ERROR;
    }

    p = njt_cpymem(buf, NJT_QUIC_BPF_VARNAME "=",
                   sizeof(NJT_QUIC_BPF_VARNAME));

    for (q = njt_queue_head(&bcf->groups);
         q != njt_queue_sentinel(&bcf->groups);
         q = njt_queue_next(q))
    {
        grp = njt_queue_data(q, njt_quic_sock_group_t, queue);

        p = njt_sprintf(p, "%ud", grp->map_fd);

        *p++ = NJT_QUIC_BPF_ADDRSEP;

        p += njt_sock_ntop(grp->sockaddr, grp->socklen, p,
                           NJT_SOCKADDR_STRLEN, 1);

        *p++ = NJT_QUIC_BPF_VARSEP;
    }

    *p = '\0';

    var = njt_array_push(&ccf->env);
    if (var == NULL) {
        return NJT_ERROR;
    }

    var->data = buf;
    var->len = sizeof(NJT_QUIC_BPF_VARNAME) - 1;

    return NJT_OK;
}


static njt_int_t
njt_quic_bpf_import_maps(njt_cycle_t *cycle)
{
    int                     s;
    u_char                 *inherited, *p, *v;
    njt_uint_t              in_fd;
    njt_addr_t              tmp;
    njt_quic_bpf_conf_t    *bcf;
    njt_quic_sock_group_t  *grp;

    inherited = (u_char *) getenv(NJT_QUIC_BPF_VARNAME);

    if (inherited == NULL) {
        return NJT_OK;
    }

    bcf = njt_quic_bpf_get_conf(cycle);

#if (NJT_SUPPRESS_WARN)
    s = -1;
#endif

    in_fd = 1;

    for (p = inherited, v = p; *p; p++) {

        switch (*p) {

        case NJT_QUIC_BPF_ADDRSEP:

            if (!in_fd) {
                njt_log_error(NJT_LOG_EMERG, cycle->log, 0,
                              "quic bpf failed to parse inherited env");
                return NJT_ERROR;
            }
            in_fd = 0;

            s = njt_atoi(v, p - v);
            if (s == NJT_ERROR) {
                njt_log_error(NJT_LOG_EMERG, cycle->log, 0,
                              "quic bpf failed to parse inherited map fd");
                return NJT_ERROR;
            }

            v = p + 1;
            break;

        case NJT_QUIC_BPF_VARSEP:

            if (in_fd) {
                njt_log_error(NJT_LOG_EMERG, cycle->log, 0,
                              "quic bpf failed to parse inherited env");
                return NJT_ERROR;
            }
            in_fd = 1;

            grp = njt_pcalloc(cycle->pool,
                              sizeof(njt_quic_sock_group_t));
            if (grp == NULL) {
                return NJT_ERROR;
            }

            grp->map_fd = s;

            if (njt_parse_addr_port(cycle->pool, &tmp, v, p - v)
                != NJT_OK)
            {
                njt_log_error(NJT_LOG_EMERG, cycle->log, 0,
                              "quic bpf failed to parse inherited"
                              " address '%*s'", p - v , v);

                njt_quic_bpf_close(cycle->log, s, "inherited map");

                return NJT_ERROR;
            }

            grp->sockaddr = tmp.sockaddr;
            grp->socklen = tmp.socklen;

            grp->unused = 1;

            njt_queue_insert_tail(&bcf->groups, &grp->queue);

            njt_log_debug3(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                           "quic bpf sockmap inherited with "
                           "fd:%d address:%*s",
                           grp->map_fd, p - v, v);
            v = p + 1;
            break;

        default:
            break;
        }
    }

    return NJT_OK;
}
