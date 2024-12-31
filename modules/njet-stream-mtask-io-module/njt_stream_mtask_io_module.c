/******************************************************************************
Copyright (c) 2011-2012, Roman Arutyunyan (arut@qip.ru)
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, 
are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice, 
      this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice, 
      this list of conditions and the following disclaimer in the documentation
	  and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR 
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
OF SUCH DAMAGE.
*******************************************************************************/

/*
 NGINX module providing userspace cooperative multitasking 
 for IO-bound content handlers
*/
/*
 * Copyright (C) 2021-2024 TMLake(Beijing) Technology Co., Ltd.
 */


#include "njt_stream_mtask_io_module.h"

#define MTASK_DEFAULT_STACK_SIZE 65536
#define MTASK_DEFAULT_TIMEOUT 10000
#define MTASK_WAKE_TIMEDOUT 0x01
#define MTASK_WAKE_NOFINALIZE 0x02

static njt_stream_session_t *mtask_io_req;

#define mtask_io_current (mtask_io_req)

#define mtask_io_setcurrent(s) (mtask_io_req = (s))

#define mtask_io_resetcurrent() mtask_io_setcurrent(NULL)

#define mtask_have_io_scheduled (mtask_io_current != NULL)

static void mtask_event_handler(njt_event_t *ev);

/* The module context. */
static njt_stream_module_t njt_stream_mtask_io_module_ctx = {
    NULL, /* preconfiguration */
    NULL, /* postconfiguration */
    NULL,
    NULL, /* init main configuration */
    NULL, /* create server configuration */
    NULL /* merge server configuration */

};

/* Module definition. */
njt_module_t njt_stream_mtask_io_module = {
    NJT_MODULE_V1,
    &njt_stream_mtask_io_module_ctx, /* module context */
    NULL, /* module directives */
    NJT_STREAM_MODULE, /* module type */
    NULL, /* init master */
    NULL, /* init module */
    NULL, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    NULL, /* exit master */
    NJT_MODULE_V1_PADDING
};

/* returns 1 on timeout */
static int mtask_yield(int fd, njt_int_t event)
{
    njt_stream_proto_server_client_ctx_t *ctx;
    njt_connection_t *c;
    njt_event_t *e;
    njt_stream_proto_server_srv_conf_t *mlcf;

    mlcf = njt_stream_get_module_srv_conf(mtask_io_current, njt_stream_proto_server_module);
    ctx = njt_stream_get_module_ctx(mtask_io_current, njt_stream_proto_server_module);
    c = njt_get_connection(fd, mtask_io_current->connection->log);
    c->data = mtask_io_current;
    if (event == NJT_READ_EVENT)
        e = c->read;
    else
        e = c->write;

    e->data = c;
    e->handler = &mtask_event_handler;
    e->log = mtask_io_current->connection->log;

    if (mlcf->mtask_timeout != NJT_CONF_UNSET_MSEC)
        njt_add_timer(e, mlcf->mtask_timeout);

    njt_add_event(e, event, 0);
    ctx->mtask_timeout = 0;
    if (njt_tcc_yield(ctx) != NJT_OK)
    {
        njt_del_timer(e);
        return NJT_ERROR;
    }

    if (e->timer_set)
        njt_del_timer(e);

    njt_del_event(e, event, 0);
    njt_free_connection(c);
    return ctx->mtask_timeout;
}
static int mtask_wake(njt_stream_session_t *s, int flags)
{

    njt_stream_proto_server_client_ctx_t *ctx;

    njt_log_debug(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                  "mtask wake");

    ctx = njt_stream_get_module_ctx(s, njt_stream_proto_server_module);

    mtask_io_setcurrent(s);
    if (flags & MTASK_WAKE_TIMEDOUT)
        ctx->mtask_timeout = 1;
    swapcontext(&ctx->main_ctx, &ctx->runctx);
    mtask_io_resetcurrent();

    return 0;
}
static void mtask_event_handler(njt_event_t *ev)
{
    njt_stream_session_t *r;
    njt_connection_t *c;
    int wf = 0;

    c = ev->data;
    r = c->data;
    if (ev->timedout)
    {
        wf |= MTASK_WAKE_TIMEDOUT;
    }
    mtask_wake(r, wf);
}
int tcc_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{

    ssize_t ret;
    int flags;
    socklen_t len;

    if (mtask_have_io_scheduled)
    {
        flags = fcntl(sockfd, F_GETFL, 0);
        if (!(flags & O_NONBLOCK))
            fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
    }
    ret = connect(sockfd, addr, addrlen);
    if (!mtask_have_io_scheduled || ret != -1 || errno != EINPROGRESS)
        return ret;

    for (;;)
    {
        if (mtask_yield(sockfd, NJT_WRITE_EVENT))
        {
            errno = ETIMEDOUT;
            return -1;
        }
        len = sizeof(flags);
        flags = 0;
        ret = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &flags, &len);
        if (ret == -1 || !len)
            return -1;
        if (!flags)
            return 0;
        if (flags != EINPROGRESS)
        {
            errno = flags;
            return -1;
        }
    }
}
ssize_t tcc_recv(int sockfd, void *buf, size_t len, int flags)
{

    ssize_t ret;

    for (;;)
    {
        ret = recv(sockfd, buf, len, flags);
        if (!mtask_have_io_scheduled || ret != -1 || errno != EAGAIN)
            return ret;
        if (mtask_yield(sockfd, NJT_READ_EVENT))
        {
            errno = ECONNRESET;
            return -1;
        }
    }
}
ssize_t tcc_write(int fd, const void *buf, size_t count)
{
    ssize_t ret;

    for (;;)
    {
        ret = write(fd, buf, count);
        if (!mtask_have_io_scheduled || ret != -1 || errno != EAGAIN)
            return ret;
        if (mtask_yield(fd, NJT_WRITE_EVENT))
        {
            errno = ECONNRESET;
            return -1;
        }
    }
}

ssize_t tcc_send(int sockfd, const void *buf, size_t len, int flags)
{
    ssize_t ret;

    for (;;)
    {
        ret = send(sockfd, buf, len, flags);
        if (!mtask_have_io_scheduled || ret != -1 || errno != EAGAIN)
            return ret;
        if (mtask_yield(sockfd, NJT_WRITE_EVENT))
        {
            errno = ECONNREFUSED;
            return -1;
        }
    }
}


