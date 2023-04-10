
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>


u_char  njt_linux_kern_ostype[50];
u_char  njt_linux_kern_osrelease[50];


static njt_os_io_t njt_linux_io = {
    njt_unix_recv,
    njt_readv_chain,
    njt_udp_unix_recv,
    njt_unix_send,
    njt_udp_unix_send,
    njt_udp_unix_sendmsg_chain,
#if (NJT_HAVE_SENDFILE)
    njt_linux_sendfile_chain,
    NJT_IO_SENDFILE
#else
    njt_writev_chain,
    0
#endif
};


njt_int_t
njt_os_specific_init(njt_log_t *log)
{
    struct utsname  u;

    if (uname(&u) == -1) {
        njt_log_error(NJT_LOG_ALERT, log, njt_errno, "uname() failed");
        return NJT_ERROR;
    }

    (void) njt_cpystrn(njt_linux_kern_ostype, (u_char *) u.sysname,
                       sizeof(njt_linux_kern_ostype));

    (void) njt_cpystrn(njt_linux_kern_osrelease, (u_char *) u.release,
                       sizeof(njt_linux_kern_osrelease));

    njt_os_io = njt_linux_io;

    return NJT_OK;
}


void
njt_os_specific_status(njt_log_t *log)
{
    njt_log_error(NJT_LOG_NOTICE, log, 0, "OS: %s %s",
                  njt_linux_kern_ostype, njt_linux_kern_osrelease);
}
