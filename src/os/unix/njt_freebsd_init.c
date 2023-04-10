
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>


/* FreeBSD 3.0 at least */
char    njt_freebsd_kern_ostype[16];
char    njt_freebsd_kern_osrelease[128];
int     njt_freebsd_kern_osreldate;
int     njt_freebsd_hw_ncpu;
int     njt_freebsd_kern_ipc_somaxconn;
u_long  njt_freebsd_net_inet_tcp_sendspace;

/* FreeBSD 4.9 */
int     njt_freebsd_machdep_hlt_logical_cpus;


njt_uint_t  njt_freebsd_sendfile_nbytes_bug;
njt_uint_t  njt_freebsd_use_tcp_nopush;

njt_uint_t  njt_debug_malloc;


static njt_os_io_t njt_freebsd_io = {
    njt_unix_recv,
    njt_readv_chain,
    njt_udp_unix_recv,
    njt_unix_send,
    njt_udp_unix_send,
    njt_udp_unix_sendmsg_chain,
#if (NJT_HAVE_SENDFILE)
    njt_freebsd_sendfile_chain,
    NJT_IO_SENDFILE
#else
    njt_writev_chain,
    0
#endif
};


typedef struct {
    char        *name;
    void        *value;
    size_t       size;
    njt_uint_t   exists;
} sysctl_t;


sysctl_t sysctls[] = {
    { "hw.ncpu",
      &njt_freebsd_hw_ncpu,
      sizeof(njt_freebsd_hw_ncpu), 0 },

    { "machdep.hlt_logical_cpus",
      &njt_freebsd_machdep_hlt_logical_cpus,
      sizeof(njt_freebsd_machdep_hlt_logical_cpus), 0 },

    { "net.inet.tcp.sendspace",
      &njt_freebsd_net_inet_tcp_sendspace,
      sizeof(njt_freebsd_net_inet_tcp_sendspace), 0 },

    { "kern.ipc.somaxconn",
      &njt_freebsd_kern_ipc_somaxconn,
      sizeof(njt_freebsd_kern_ipc_somaxconn), 0 },

    { NULL, NULL, 0, 0 }
};


void
njt_debug_init(void)
{
#if (NJT_DEBUG_MALLOC)

#if __FreeBSD_version >= 500014 && __FreeBSD_version < 1000011
    _malloc_options = "J";
#elif __FreeBSD_version < 500014
    malloc_options = "J";
#endif

    njt_debug_malloc = 1;

#else
    char  *mo;

    mo = getenv("MALLOC_OPTIONS");

    if (mo && njt_strchr(mo, 'J')) {
        njt_debug_malloc = 1;
    }
#endif
}


njt_int_t
njt_os_specific_init(njt_log_t *log)
{
    int         version;
    size_t      size;
    njt_err_t   err;
    njt_uint_t  i;

    size = sizeof(njt_freebsd_kern_ostype);
    if (sysctlbyname("kern.ostype",
                     njt_freebsd_kern_ostype, &size, NULL, 0) == -1) {
        njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                      "sysctlbyname(kern.ostype) failed");

        if (njt_errno != NJT_ENOMEM) {
            return NJT_ERROR;
        }

        njt_freebsd_kern_ostype[size - 1] = '\0';
    }

    size = sizeof(njt_freebsd_kern_osrelease);
    if (sysctlbyname("kern.osrelease",
                     njt_freebsd_kern_osrelease, &size, NULL, 0) == -1) {
        njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                      "sysctlbyname(kern.osrelease) failed");

        if (njt_errno != NJT_ENOMEM) {
            return NJT_ERROR;
        }

        njt_freebsd_kern_osrelease[size - 1] = '\0';
    }


    size = sizeof(int);
    if (sysctlbyname("kern.osreldate",
                     &njt_freebsd_kern_osreldate, &size, NULL, 0) == -1) {
        njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                      "sysctlbyname(kern.osreldate) failed");
        return NJT_ERROR;
    }

    version = njt_freebsd_kern_osreldate;


#if (NJT_HAVE_SENDFILE)

    /*
     * The determination of the sendfile() "nbytes bug" is complex enough.
     * There are two sendfile() syscalls: a new #393 has no bug while
     * an old #336 has the bug in some versions and has not in others.
     * Besides libc_r wrapper also emulates the bug in some versions.
     * There is no way to say exactly if syscall #336 in FreeBSD circa 4.6
     * has the bug.  We use the algorithm that is correct at least for
     * RELEASEs and for syscalls only (not libc_r wrapper).
     *
     * 4.6.1-RELEASE and below have the bug
     * 4.6.2-RELEASE and above have the new syscall
     *
     * We detect the new sendfile() syscall available at the compile time
     * to allow an old binary to run correctly on an updated FreeBSD system.
     */

#if (__FreeBSD__ == 4 && __FreeBSD_version >= 460102) \
    || __FreeBSD_version == 460002 || __FreeBSD_version >= 500039

    /* a new syscall without the bug */

    njt_freebsd_sendfile_nbytes_bug = 0;

#else

    /* an old syscall that may have the bug */

    njt_freebsd_sendfile_nbytes_bug = 1;

#endif

#endif /* NJT_HAVE_SENDFILE */


    if ((version < 500000 && version >= 440003) || version >= 500017) {
        njt_freebsd_use_tcp_nopush = 1;
    }


    for (i = 0; sysctls[i].name; i++) {
        size = sysctls[i].size;

        if (sysctlbyname(sysctls[i].name, sysctls[i].value, &size, NULL, 0)
            == 0)
        {
            sysctls[i].exists = 1;
            continue;
        }

        err = njt_errno;

        if (err == NJT_ENOENT) {
            continue;
        }

        njt_log_error(NJT_LOG_ALERT, log, err,
                      "sysctlbyname(%s) failed", sysctls[i].name);
        return NJT_ERROR;
    }

    if (njt_freebsd_machdep_hlt_logical_cpus) {
        njt_ncpu = njt_freebsd_hw_ncpu / 2;

    } else {
        njt_ncpu = njt_freebsd_hw_ncpu;
    }

    if (version < 600008 && njt_freebsd_kern_ipc_somaxconn > 32767) {
        njt_log_error(NJT_LOG_ALERT, log, 0,
                      "sysctl kern.ipc.somaxconn must be less than 32768");
        return NJT_ERROR;
    }

    njt_tcp_nodelay_and_tcp_nopush = 1;

    njt_os_io = njt_freebsd_io;

    return NJT_OK;
}


void
njt_os_specific_status(njt_log_t *log)
{
    u_long      value;
    njt_uint_t  i;

    njt_log_error(NJT_LOG_NOTICE, log, 0, "OS: %s %s",
                  njt_freebsd_kern_ostype, njt_freebsd_kern_osrelease);

#ifdef __DragonFly_version
    njt_log_error(NJT_LOG_NOTICE, log, 0,
                  "kern.osreldate: %d, built on %d",
                  njt_freebsd_kern_osreldate, __DragonFly_version);
#else
    njt_log_error(NJT_LOG_NOTICE, log, 0,
                  "kern.osreldate: %d, built on %d",
                  njt_freebsd_kern_osreldate, __FreeBSD_version);
#endif

    for (i = 0; sysctls[i].name; i++) {
        if (sysctls[i].exists) {
            if (sysctls[i].size == sizeof(long)) {
                value = *(long *) sysctls[i].value;

            } else {
                value = *(int *) sysctls[i].value;
            }

            njt_log_error(NJT_LOG_NOTICE, log, 0, "%s: %l",
                          sysctls[i].name, value);
        }
    }
}
