
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


static njt_int_t njt_select_init(njt_cycle_t *cycle, njt_msec_t timer);
static void njt_select_done(njt_cycle_t *cycle);
static njt_int_t njt_select_add_event(njt_event_t *ev, njt_int_t event,
    njt_uint_t flags);
static njt_int_t njt_select_del_event(njt_event_t *ev, njt_int_t event,
    njt_uint_t flags);
static njt_int_t njt_select_process_events(njt_cycle_t *cycle, njt_msec_t timer,
    njt_uint_t flags);
static void njt_select_repair_fd_sets(njt_cycle_t *cycle);
static char *njt_select_init_conf(njt_cycle_t *cycle, void *conf);


static fd_set         master_read_fd_set;
static fd_set         master_write_fd_set;
static fd_set         work_read_fd_set;
static fd_set         work_write_fd_set;
static fd_set         work_except_fd_set;

static njt_uint_t     max_read;
static njt_uint_t     max_write;
static njt_uint_t     nevents;

static njt_event_t  **event_index;


static njt_str_t           select_name = njt_string("select");

static njt_event_module_t  njt_select_module_ctx = {
    &select_name,
    NULL,                                  /* create configuration */
    njt_select_init_conf,                  /* init configuration */

    {
        njt_select_add_event,              /* add an event */
        njt_select_del_event,              /* delete an event */
        njt_select_add_event,              /* enable an event */
        njt_select_del_event,              /* disable an event */
        NULL,                              /* add an connection */
        NULL,                              /* delete an connection */
        NULL,                              /* trigger a notify */
        njt_select_process_events,         /* process the events */
        njt_select_init,                   /* init the events */
        njt_select_done                    /* done the events */
    }

};

njt_module_t  njt_select_module = {
    NJT_MODULE_V1,
    &njt_select_module_ctx,                /* module context */
    NULL,                                  /* module directives */
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


static njt_int_t
njt_select_init(njt_cycle_t *cycle, njt_msec_t timer)
{
    njt_event_t  **index;

    if (event_index == NULL) {
        FD_ZERO(&master_read_fd_set);
        FD_ZERO(&master_write_fd_set);
        nevents = 0;
    }

    if (njt_process >= NJT_PROCESS_WORKER
        || cycle->old_cycle == NULL
        || cycle->old_cycle->connection_n < cycle->connection_n)
    {
        index = njt_alloc(sizeof(njt_event_t *) * 2 * cycle->connection_n,
                          cycle->log);
        if (index == NULL) {
            return NJT_ERROR;
        }

        if (event_index) {
            njt_memcpy(index, event_index, sizeof(njt_event_t *) * nevents);
            njt_free(event_index);
        }

        event_index = index;
    }

    njt_io = njt_os_io;

    njt_event_actions = njt_select_module_ctx.actions;

    njt_event_flags = NJT_USE_LEVEL_EVENT;

    max_read = 0;
    max_write = 0;

    return NJT_OK;
}


static void
njt_select_done(njt_cycle_t *cycle)
{
    njt_free(event_index);

    event_index = NULL;
}


static njt_int_t
njt_select_add_event(njt_event_t *ev, njt_int_t event, njt_uint_t flags)
{
    njt_connection_t  *c;

    c = ev->data;

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, ev->log, 0,
                   "select add event fd:%d ev:%i", c->fd, event);

    if (ev->index != NJT_INVALID_INDEX) {
        njt_log_error(NJT_LOG_ALERT, ev->log, 0,
                      "select event fd:%d ev:%i is already set", c->fd, event);
        return NJT_OK;
    }

    if ((event == NJT_READ_EVENT && ev->write)
        || (event == NJT_WRITE_EVENT && !ev->write))
    {
        njt_log_error(NJT_LOG_ALERT, ev->log, 0,
                      "invalid select %s event fd:%d ev:%i",
                      ev->write ? "write" : "read", c->fd, event);
        return NJT_ERROR;
    }

    if ((event == NJT_READ_EVENT && max_read >= FD_SETSIZE)
        || (event == NJT_WRITE_EVENT && max_write >= FD_SETSIZE))
    {
        njt_log_error(NJT_LOG_ERR, ev->log, 0,
                      "maximum number of descriptors "
                      "supported by select() is %d", FD_SETSIZE);
        return NJT_ERROR;
    }

    if (event == NJT_READ_EVENT) {
        FD_SET(c->fd, &master_read_fd_set);
        max_read++;

    } else if (event == NJT_WRITE_EVENT) {
        FD_SET(c->fd, &master_write_fd_set);
        max_write++;
    }

    ev->active = 1;

    event_index[nevents] = ev;
    ev->index = nevents;
    nevents++;

    return NJT_OK;
}


static njt_int_t
njt_select_del_event(njt_event_t *ev, njt_int_t event, njt_uint_t flags)
{
    njt_event_t       *e;
    njt_connection_t  *c;

    c = ev->data;

    ev->active = 0;

    if (ev->index == NJT_INVALID_INDEX) {
        return NJT_OK;
    }

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, ev->log, 0,
                   "select del event fd:%d ev:%i", c->fd, event);

    if (event == NJT_READ_EVENT) {
        FD_CLR(c->fd, &master_read_fd_set);
        max_read--;

    } else if (event == NJT_WRITE_EVENT) {
        FD_CLR(c->fd, &master_write_fd_set);
        max_write--;
    }

    if (ev->index < --nevents) {
        e = event_index[nevents];
        event_index[ev->index] = e;
        e->index = ev->index;
    }

    ev->index = NJT_INVALID_INDEX;

    return NJT_OK;
}


static njt_int_t
njt_select_process_events(njt_cycle_t *cycle, njt_msec_t timer,
    njt_uint_t flags)
{
    int                ready, nready;
    njt_err_t          err;
    njt_uint_t         i, found;
    njt_event_t       *ev;
    njt_queue_t       *queue;
    struct timeval     tv, *tp;
    njt_connection_t  *c;

#if (NJT_DEBUG)
    if (cycle->log->log_level & NJT_LOG_DEBUG_ALL) {
        for (i = 0; i < nevents; i++) {
            ev = event_index[i];
            c = ev->data;
            njt_log_debug2(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                           "select event: fd:%d wr:%d", c->fd, ev->write);
        }
    }
#endif

    if (timer == NJT_TIMER_INFINITE) {
        tp = NULL;

    } else {
        tv.tv_sec = (long) (timer / 1000);
        tv.tv_usec = (long) ((timer % 1000) * 1000);
        tp = &tv;
    }

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                   "select timer: %M", timer);

    work_read_fd_set = master_read_fd_set;
    work_write_fd_set = master_write_fd_set;
    work_except_fd_set = master_write_fd_set;

    if (max_read || max_write) {
        ready = select(0, &work_read_fd_set, &work_write_fd_set,
                       &work_except_fd_set, tp);

    } else {

        /*
         * Winsock select() requires that at least one descriptor set must be
         * be non-null, and any non-null descriptor set must contain at least
         * one handle to a socket.  Otherwise select() returns WSAEINVAL.
         */

        njt_msleep(timer);

        ready = 0;
    }

    err = (ready == -1) ? njt_socket_errno : 0;

    if (flags & NJT_UPDATE_TIME) {
        njt_time_update();
    }

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                   "select ready %d", ready);

    if (err) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, err, "select() failed");

        if (err == WSAENOTSOCK) {
            njt_select_repair_fd_sets(cycle);
        }

        return NJT_ERROR;
    }

    if (ready == 0) {
        if (timer != NJT_TIMER_INFINITE) {
            return NJT_OK;
        }

        njt_log_error(NJT_LOG_ALERT, cycle->log, 0,
                      "select() returned no events without timeout");
        return NJT_ERROR;
    }

    nready = 0;

    for (i = 0; i < nevents; i++) {
        ev = event_index[i];
        c = ev->data;
        found = 0;

        if (ev->write) {
            if (FD_ISSET(c->fd, &work_write_fd_set)) {
                found++;
                njt_log_debug1(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                               "select write %d", c->fd);
            }

            if (FD_ISSET(c->fd, &work_except_fd_set)) {
                found++;
                njt_log_debug1(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                               "select except %d", c->fd);
            }

        } else {
            if (FD_ISSET(c->fd, &work_read_fd_set)) {
                found++;
                njt_log_debug1(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                               "select read %d", c->fd);
            }
        }

        if (found) {
            ev->ready = 1;
            ev->available = -1;

            queue = ev->accept ? &njt_posted_accept_events
                               : &njt_posted_events;

            njt_post_event(ev, queue);

            nready += found;
        }
    }

    if (ready != nready) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, 0,
                      "select ready != events: %d:%d", ready, nready);

        njt_select_repair_fd_sets(cycle);
    }

    return NJT_OK;
}


static void
njt_select_repair_fd_sets(njt_cycle_t *cycle)
{
    int           n;
    u_int         i;
    socklen_t     len;
    njt_err_t     err;
    njt_socket_t  s;

    for (i = 0; i < master_read_fd_set.fd_count; i++) {

        s = master_read_fd_set.fd_array[i];
        len = sizeof(int);

        if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char *) &n, &len) == -1) {
            err = njt_socket_errno;

            njt_log_error(NJT_LOG_ALERT, cycle->log, err,
                          "invalid descriptor #%d in read fd_set", s);

            FD_CLR(s, &master_read_fd_set);
        }
    }

    for (i = 0; i < master_write_fd_set.fd_count; i++) {

        s = master_write_fd_set.fd_array[i];
        len = sizeof(int);

        if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char *) &n, &len) == -1) {
            err = njt_socket_errno;

            njt_log_error(NJT_LOG_ALERT, cycle->log, err,
                          "invalid descriptor #%d in write fd_set", s);

            FD_CLR(s, &master_write_fd_set);
        }
    }
}


static char *
njt_select_init_conf(njt_cycle_t *cycle, void *conf)
{
    njt_event_conf_t  *ecf;

    ecf = njt_event_get_conf(cycle->conf_ctx, njt_event_core_module);

    if (ecf->use != njt_select_module.ctx_index) {
        return NJT_CONF_OK;
    }

    return NJT_CONF_OK;
}
