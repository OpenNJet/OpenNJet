
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>


int
njt_nonblocking(njt_socket_t s)
{
    unsigned long  nb = 1;

    return ioctlsocket(s, FIONBIO, &nb);
}


int
njt_blocking(njt_socket_t s)
{
    unsigned long  nb = 0;

    return ioctlsocket(s, FIONBIO, &nb);
}


int
njt_socket_nread(njt_socket_t s, int *n)
{
    unsigned long  nread;

    if (ioctlsocket(s, FIONREAD, &nread) == -1) {
        return -1;
    }

    *n = nread;

    return 0;
}


int
njt_tcp_push(njt_socket_t s)
{
    return 0;
}
