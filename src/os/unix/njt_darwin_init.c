
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>


char    njt_darwin_kern_ostype[16];
char    njt_darwin_kern_osrelease[128];
int     njt_darwin_hw_ncpu;
int     njt_darwin_kern_ipc_somaxconn;
u_long  njt_darwin_net_inet_tcp_sendspace;

njt_uint_t  njt_debug_malloc;


static njt_os_io_t njt_darwin_io = {
    njt_unix_recv,
    njt_readv_chain,
    njt_udp_unix_recv,
    njt_unix_send,
    njt_udp_unix_send,
    njt_udp_unix_sendmsg_chain,
#if (NJT_HAVE_SENDFILE)
    njt_darwin_sendfile_chain,
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
      &njt_darwin_hw_ncpu,
      sizeof(njt_darwin_hw_ncpu), 0 },

    { "net.inet.tcp.sendspace",
      &njt_darwin_net_inet_tcp_sendspace,
      sizeof(njt_darwin_net_inet_tcp_sendspace), 0 },

    { "kern.ipc.somaxconn",
      &njt_darwin_kern_ipc_somaxconn,
      sizeof(njt_darwin_kern_ipc_somaxconn), 0 },

    { NULL, NULL, 0, 0 }
};


void
njt_debug_init(void)
{
#if (NJT_DEBUG_MALLOC)

    /*
     * MacOSX 10.6, 10.7:  MallocScribble fills freed memory with 0x55
     *                     and fills allocated memory with 0xAA.
     * MacOSX 10.4, 10.5:  MallocScribble fills freed memory with 0x55,
     *                     MallocPreScribble fills allocated memory with 0xAA.
     * MacOSX 10.3:        MallocScribble fills freed memory with 0x55,
     *                     and no way to fill allocated memory.
     */

    setenv("MallocScribble", "1", 0);

    njt_debug_malloc = 1;

#else

    if (getenv("MallocScribble")) {
        njt_debug_malloc = 1;
    }

#endif
}


njt_int_t
njt_os_specific_init(njt_log_t *log)
{
    size_t      size;
    njt_err_t   err;
    njt_uint_t  i;

    size = sizeof(njt_darwin_kern_ostype);
    if (sysctlbyname("kern.ostype", njt_darwin_kern_ostype, &size, NULL, 0)
        == -1)
    {
        err = njt_errno;

        if (err != NJT_ENOENT) {

            njt_log_error(NJT_LOG_ALERT, log, err,
                          "sysctlbyname(kern.ostype) failed");

            if (err != NJT_ENOMEM) {
                return NJT_ERROR;
            }

            njt_darwin_kern_ostype[size - 1] = '\0';
        }
    }

    size = sizeof(njt_darwin_kern_osrelease);
    if (sysctlbyname("kern.osrelease", njt_darwin_kern_osrelease, &size,
                     NULL, 0)
        == -1)
    {
        err = njt_errno;

        if (err != NJT_ENOENT) {

            njt_log_error(NJT_LOG_ALERT, log, err,
                          "sysctlbyname(kern.osrelease) failed");

            if (err != NJT_ENOMEM) {
                return NJT_ERROR;
            }

            njt_darwin_kern_osrelease[size - 1] = '\0';
        }
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

    njt_ncpu = njt_darwin_hw_ncpu;

    if (njt_darwin_kern_ipc_somaxconn > 32767) {
        njt_log_error(NJT_LOG_ALERT, log, 0,
                      "sysctl kern.ipc.somaxconn must be less than 32768");
        return NJT_ERROR;
    }

    njt_tcp_nodelay_and_tcp_nopush = 1;

    njt_os_io = njt_darwin_io;

    return NJT_OK;
}


void
njt_os_specific_status(njt_log_t *log)
{
    u_long      value;
    njt_uint_t  i;

    if (njt_darwin_kern_ostype[0]) {
        njt_log_error(NJT_LOG_NOTICE, log, 0, "OS: %s %s",
                      njt_darwin_kern_ostype, njt_darwin_kern_osrelease);
    }

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
