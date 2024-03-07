
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>
#include <njt_iocp_module.h>


static njt_int_t njt_iocp_init(njt_cycle_t *cycle, njt_msec_t timer);
static njt_thread_value_t __stdcall njt_iocp_timer(void *data);
static void njt_iocp_done(njt_cycle_t *cycle);
static njt_int_t njt_iocp_add_event(njt_event_t *ev, njt_int_t event,
    njt_uint_t key);
static njt_int_t njt_iocp_del_connection(njt_connection_t *c, njt_uint_t flags);
static njt_int_t njt_iocp_process_events(njt_cycle_t *cycle, njt_msec_t timer,
    njt_uint_t flags);
static void *njt_iocp_create_conf(njt_cycle_t *cycle);
static char *njt_iocp_init_conf(njt_cycle_t *cycle, void *conf);


static njt_str_t      iocp_name = njt_string("iocp");

static njt_command_t  njt_iocp_commands[] = {

    { njt_string("iocp_threads"),
      NJT_EVENT_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      0,
      offsetof(njt_iocp_conf_t, threads),
      NULL },

    { njt_string("post_acceptex"),
      NJT_EVENT_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      0,
      offsetof(njt_iocp_conf_t, post_acceptex),
      NULL },

    { njt_string("acceptex_read"),
      NJT_EVENT_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      0,
      offsetof(njt_iocp_conf_t, acceptex_read),
      NULL },

      njt_null_command
};


static njt_event_module_t  njt_iocp_module_ctx = {
    &iocp_name,
    njt_iocp_create_conf,                  /* create configuration */
    njt_iocp_init_conf,                    /* init configuration */

    {
        njt_iocp_add_event,                /* add an event */
        NULL,                              /* delete an event */
        NULL,                              /* enable an event */
        NULL,                              /* disable an event */
        NULL,                              /* add an connection */
        njt_iocp_del_connection,           /* delete an connection */
        NULL,                              /* trigger a notify */
        njt_iocp_process_events,           /* process the events */
        njt_iocp_init,                     /* init the events */
        njt_iocp_done                      /* done the events */
    }

};

njt_module_t  njt_iocp_module = {
    NJT_MODULE_V1,
    &njt_iocp_module_ctx,                  /* module context */
    njt_iocp_commands,                     /* module directives */
    NJT_EVENT_MODULE,                      /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};


njt_os_io_t njt_iocp_io = {
    njt_overlapped_wsarecv,
    NULL,
    njt_udp_overlapped_wsarecv,
    NULL,
    NULL,
    NULL,
    njt_overlapped_wsasend_chain,
    0
};


static HANDLE      iocp;
static njt_tid_t   timer_thread;
static njt_msec_t  msec;


static njt_int_t
njt_iocp_init(njt_cycle_t *cycle, njt_msec_t timer)
{
    njt_iocp_conf_t  *cf;

    cf = njt_event_get_conf(cycle->conf_ctx, njt_iocp_module);

    if (iocp == NULL) {
        iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0,
                                      cf->threads);
    }

    if (iocp == NULL) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                      "CreateIoCompletionPort() failed");
        return NJT_ERROR;
    }

    njt_io = njt_iocp_io;

    njt_event_actions = njt_iocp_module_ctx.actions;

    njt_event_flags = NJT_USE_IOCP_EVENT;

    if (timer == 0) {
        return NJT_OK;
    }

    /*
     * The waitable timer could not be used, because
     * GetQueuedCompletionStatus() does not set a thread to alertable state
     */

    if (timer_thread == NULL) {

        msec = timer;

        if (njt_create_thread(&timer_thread, njt_iocp_timer, &msec, cycle->log)
            != 0)
        {
            return NJT_ERROR;
        }
    }

    njt_event_flags |= NJT_USE_TIMER_EVENT;

    return NJT_OK;
}


static njt_thread_value_t __stdcall
njt_iocp_timer(void *data)
{
    njt_msec_t  timer = *(njt_msec_t *) data;

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, njt_cycle->log, 0,
                   "THREAD %p %p", &msec, data);

    for ( ;; ) {
        Sleep(timer);

        njt_time_update();
#if 1
        njt_log_debug0(NJT_LOG_DEBUG_EVENT, njt_cycle->log, 0, "timer");
#endif
    }

#if defined(__WATCOMC__) || defined(__GNUC__)
    return 0;
#endif
}


static void
njt_iocp_done(njt_cycle_t *cycle)
{
    if (CloseHandle(iocp) == -1) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                      "iocp CloseHandle() failed");
    }

    iocp = NULL;
}


static njt_int_t
njt_iocp_add_event(njt_event_t *ev, njt_int_t event, njt_uint_t key)
{
    njt_connection_t  *c;

    c = (njt_connection_t *) ev->data;

    c->read->active = 1;
    c->write->active = 1;

    njt_log_debug3(NJT_LOG_DEBUG_EVENT, ev->log, 0,
                   "iocp add: fd:%d k:%ui ov:%p", c->fd, key, &ev->ovlp);

    if (CreateIoCompletionPort((HANDLE) c->fd, iocp, key, 0) == NULL) {
        njt_log_error(NJT_LOG_ALERT, c->log, njt_errno,
                      "CreateIoCompletionPort() failed");
        return NJT_ERROR;
    }

    return NJT_OK;
}


static njt_int_t
njt_iocp_del_connection(njt_connection_t *c, njt_uint_t flags)
{
#if 0
    if (flags & NJT_CLOSE_EVENT) {
        return NJT_OK;
    }

    if (CancelIo((HANDLE) c->fd) == 0) {
        njt_log_error(NJT_LOG_ALERT, c->log, njt_errno, "CancelIo() failed");
        return NJT_ERROR;
    }
#endif

    return NJT_OK;
}


static njt_int_t
njt_iocp_process_events(njt_cycle_t *cycle, njt_msec_t timer,
    njt_uint_t flags)
{
    int                rc;
    u_int              key;
    u_long             bytes;
    njt_err_t          err;
    njt_msec_t         delta;
    njt_event_t       *ev;
    njt_event_ovlp_t  *ovlp;

    if (timer == NJT_TIMER_INFINITE) {
        timer = INFINITE;
    }

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, cycle->log, 0, "iocp timer: %M", timer);

    rc = GetQueuedCompletionStatus(iocp, &bytes, (PULONG_PTR) &key,
                                   (LPOVERLAPPED *) &ovlp, (u_long) timer);

    if (rc == 0) {
        err = njt_errno;
    } else {
        err = 0;
    }

    delta = njt_current_msec;

    if (flags & NJT_UPDATE_TIME) {
        njt_time_update();
    }

    njt_log_debug4(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                   "iocp: %d b:%d k:%d ov:%p", rc, bytes, key, ovlp);

    if (timer != INFINITE) {
        delta = njt_current_msec - delta;

        njt_log_debug2(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                       "iocp timer: %M, delta: %M", timer, delta);
    }

    if (err) {
        if (ovlp == NULL) {
            if (err != WAIT_TIMEOUT) {
                njt_log_error(NJT_LOG_ALERT, cycle->log, err,
                              "GetQueuedCompletionStatus() failed");

                return NJT_ERROR;
            }

            return NJT_OK;
        }

        ovlp->error = err;
    }

    if (ovlp == NULL) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, 0,
                      "GetQueuedCompletionStatus() returned no operation");
        return NJT_ERROR;
    }


    ev = ovlp->event;

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, cycle->log, err, "iocp event:%p", ev);


    if (err == ERROR_NETNAME_DELETED /* the socket was closed */
        || err == ERROR_OPERATION_ABORTED /* the operation was canceled */)
    {

        /*
         * the WSA_OPERATION_ABORTED completion notification
         * for a file descriptor that was closed
         */

        njt_log_debug1(NJT_LOG_DEBUG_EVENT, cycle->log, err,
                       "iocp: aborted event %p", ev);

        return NJT_OK;
    }

    if (err) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, err,
                      "GetQueuedCompletionStatus() returned operation error");
    }

    switch (key) {

    case NJT_IOCP_ACCEPT:
        if (bytes) {
            ev->ready = 1;
        }
        break;

    case NJT_IOCP_IO:
        ev->complete = 1;
        ev->ready = 1;
        break;

    case NJT_IOCP_CONNECT:
        ev->ready = 1;
    }

    ev->available = bytes;

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                   "iocp event handler: %p", ev->handler);

    ev->handler(ev);

    return NJT_OK;
}


static void *
njt_iocp_create_conf(njt_cycle_t *cycle)
{
    njt_iocp_conf_t  *cf;

    cf = njt_palloc(cycle->pool, sizeof(njt_iocp_conf_t));
    if (cf == NULL) {
        return NULL;
    }

    cf->threads = NJT_CONF_UNSET;
    cf->post_acceptex = NJT_CONF_UNSET;
    cf->acceptex_read = NJT_CONF_UNSET;

    return cf;
}


static char *
njt_iocp_init_conf(njt_cycle_t *cycle, void *conf)
{
    njt_iocp_conf_t *cf = conf;

    njt_conf_init_value(cf->threads, 0);
    njt_conf_init_value(cf->post_acceptex, 10);
    njt_conf_init_value(cf->acceptex_read, 1);

    return NJT_CONF_OK;
}
