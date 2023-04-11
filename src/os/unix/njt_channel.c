
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_channel.h>


njt_int_t
njt_write_channel(njt_socket_t s, njt_channel_t *ch, size_t size,
    njt_log_t *log)
{
    ssize_t             n;
    njt_err_t           err;
    struct iovec        iov[1];
    struct msghdr       msg;

#if (NJT_HAVE_MSGHDR_MSG_CONTROL)

    union {
        struct cmsghdr  cm;
        char            space[CMSG_SPACE(sizeof(int))];
    } cmsg;

    if (ch->fd == -1) {
        msg.msg_control = NULL;
        msg.msg_controllen = 0;

    } else {
        msg.msg_control = (caddr_t) &cmsg;
        msg.msg_controllen = sizeof(cmsg);

        njt_memzero(&cmsg, sizeof(cmsg));

        cmsg.cm.cmsg_len = CMSG_LEN(sizeof(int));
        cmsg.cm.cmsg_level = SOL_SOCKET;
        cmsg.cm.cmsg_type = SCM_RIGHTS;

        /*
         * We have to use njt_memcpy() instead of simple
         *   *(int *) CMSG_DATA(&cmsg.cm) = ch->fd;
         * because some gcc 4.4 with -O2/3/s optimization issues the warning:
         *   dereferencing type-punned pointer will break strict-aliasing rules
         *
         * Fortunately, gcc with -O1 compiles this njt_memcpy()
         * in the same simple assignment as in the code above
         */

        njt_memcpy(CMSG_DATA(&cmsg.cm), &ch->fd, sizeof(int));
    }

    msg.msg_flags = 0;

#else

    if (ch->fd == -1) {
        msg.msg_accrights = NULL;
        msg.msg_accrightslen = 0;

    } else {
        msg.msg_accrights = (caddr_t) &ch->fd;
        msg.msg_accrightslen = sizeof(int);
    }

#endif

    iov[0].iov_base = (char *) ch;
    iov[0].iov_len = size;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    n = sendmsg(s, &msg, 0);

    if (n == -1) {
        err = njt_errno;
        if (err == NJT_EAGAIN) {
            return NJT_AGAIN;
        }

        njt_log_error(NJT_LOG_ALERT, log, err, "sendmsg() failed");
        return NJT_ERROR;
    }

    return NJT_OK;
}


njt_int_t
njt_read_channel(njt_socket_t s, njt_channel_t *ch, size_t size, njt_log_t *log)
{
    ssize_t             n;
    njt_err_t           err;
    struct iovec        iov[1];
    struct msghdr       msg;

#if (NJT_HAVE_MSGHDR_MSG_CONTROL)
    union {
        struct cmsghdr  cm;
        char            space[CMSG_SPACE(sizeof(int))];
    } cmsg;
#else
    int                 fd;
#endif

    iov[0].iov_base = (char *) ch;
    iov[0].iov_len = size;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

#if (NJT_HAVE_MSGHDR_MSG_CONTROL)
    msg.msg_control = (caddr_t) &cmsg;
    msg.msg_controllen = sizeof(cmsg);
#else
    msg.msg_accrights = (caddr_t) &fd;
    msg.msg_accrightslen = sizeof(int);
#endif

    n = recvmsg(s, &msg, 0);

    if (n == -1) {
        err = njt_errno;
        if (err == NJT_EAGAIN) {
            return NJT_AGAIN;
        }

        njt_log_error(NJT_LOG_ALERT, log, err, "recvmsg() failed");
        return NJT_ERROR;
    }

    if (n == 0) {
        njt_log_debug0(NJT_LOG_DEBUG_CORE, log, 0, "recvmsg() returned zero");
        return NJT_ERROR;
    }

    if ((size_t) n < sizeof(njt_channel_t)) {
        njt_log_error(NJT_LOG_ALERT, log, 0,
                      "recvmsg() returned not enough data: %z", n);
        return NJT_ERROR;
    }

#if (NJT_HAVE_MSGHDR_MSG_CONTROL)

    if (ch->command == NJT_CMD_OPEN_CHANNEL) {

        if (cmsg.cm.cmsg_len < (socklen_t) CMSG_LEN(sizeof(int))) {
            njt_log_error(NJT_LOG_ALERT, log, 0,
                          "recvmsg() returned too small ancillary data");
            return NJT_ERROR;
        }

        if (cmsg.cm.cmsg_level != SOL_SOCKET || cmsg.cm.cmsg_type != SCM_RIGHTS)
        {
            njt_log_error(NJT_LOG_ALERT, log, 0,
                          "recvmsg() returned invalid ancillary data "
                          "level %d or type %d",
                          cmsg.cm.cmsg_level, cmsg.cm.cmsg_type);
            return NJT_ERROR;
        }

        /* ch->fd = *(int *) CMSG_DATA(&cmsg.cm); */

        njt_memcpy(&ch->fd, CMSG_DATA(&cmsg.cm), sizeof(int));
    }

    if (msg.msg_flags & (MSG_TRUNC|MSG_CTRUNC)) {
        njt_log_error(NJT_LOG_ALERT, log, 0,
                      "recvmsg() truncated data");
    }

#else

    if (ch->command == NJT_CMD_OPEN_CHANNEL) {
        if (msg.msg_accrightslen != sizeof(int)) {
            njt_log_error(NJT_LOG_ALERT, log, 0,
                          "recvmsg() returned no ancillary data");
            return NJT_ERROR;
        }

        ch->fd = fd;
    }

#endif

    return n;
}


njt_int_t
njt_add_channel_event(njt_cycle_t *cycle, njt_fd_t fd, njt_int_t event,
    njt_event_handler_pt handler)
{
    njt_event_t       *ev, *rev, *wev;
    njt_connection_t  *c;

    c = njt_get_connection(fd, cycle->log);

    if (c == NULL) {
        return NJT_ERROR;
    }

    c->pool = cycle->pool;

    rev = c->read;
    wev = c->write;

    rev->log = cycle->log;
    wev->log = cycle->log;

    rev->channel = 1;
    wev->channel = 1;

    ev = (event == NJT_READ_EVENT) ? rev : wev;

    ev->handler = handler;

    if (njt_add_conn && (njt_event_flags & NJT_USE_EPOLL_EVENT) == 0) {
        if (njt_add_conn(c) == NJT_ERROR) {
            njt_free_connection(c);
            return NJT_ERROR;
        }

    } else {
        if (njt_add_event(ev, event, 0) == NJT_ERROR) {
            njt_free_connection(c);
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}


void
njt_close_channel(njt_fd_t *fd, njt_log_t *log)
{
    if (close(fd[0]) == -1) {
        njt_log_error(NJT_LOG_ALERT, log, njt_errno, "close() channel failed");
    }

    if (close(fd[1]) == -1) {
        njt_log_error(NJT_LOG_ALERT, log, njt_errno, "close() channel failed");
    }
}
