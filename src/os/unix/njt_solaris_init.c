
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>


char njt_solaris_sysname[20];
char njt_solaris_release[10];
char njt_solaris_version[50];


static njt_os_io_t njt_solaris_io = {
    njt_unix_recv,
    njt_readv_chain,
    njt_udp_unix_recv,
    njt_unix_send,
    njt_udp_unix_send,
    njt_udp_unix_sendmsg_chain,
#if (NJT_HAVE_SENDFILE)
    njt_solaris_sendfilev_chain,
    NJT_IO_SENDFILE
#else
    njt_writev_chain,
    0
#endif
};


njt_int_t
njt_os_specific_init(njt_log_t *log)
{
    if (sysinfo(SI_SYSNAME, njt_solaris_sysname, sizeof(njt_solaris_sysname))
        == -1)
    {
        njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                      "sysinfo(SI_SYSNAME) failed");
        return NJT_ERROR;
    }

    if (sysinfo(SI_RELEASE, njt_solaris_release, sizeof(njt_solaris_release))
        == -1)
    {
        njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                      "sysinfo(SI_RELEASE) failed");
        return NJT_ERROR;
    }

    if (sysinfo(SI_VERSION, njt_solaris_version, sizeof(njt_solaris_version))
        == -1)
    {
        njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                      "sysinfo(SI_SYSNAME) failed");
        return NJT_ERROR;
    }


    njt_os_io = njt_solaris_io;

    return NJT_OK;
}


void
njt_os_specific_status(njt_log_t *log)
{

    njt_log_error(NJT_LOG_NOTICE, log, 0, "OS: %s %s",
                  njt_solaris_sysname, njt_solaris_release);

    njt_log_error(NJT_LOG_NOTICE, log, 0, "version: %s",
                  njt_solaris_version);
}
