
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

static njt_int_t      max_fd;
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

    max_fd = -1;

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

    if (event == NJT_READ_EVENT) {
        FD_SET(c->fd, &master_read_fd_set);

    } else if (event == NJT_WRITE_EVENT) {
        FD_SET(c->fd, &master_write_fd_set);
    }

    if (max_fd != -1 && max_fd < c->fd) {
        max_fd = c->fd;
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

    } else if (event == NJT_WRITE_EVENT) {
        FD_CLR(c->fd, &master_write_fd_set);
    }

    if (max_fd == c->fd) {
        max_fd = -1;
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

    if (max_fd == -1) {
        for (i = 0; i < nevents; i++) {
            c = event_index[i]->data;
            if (max_fd < c->fd) {
                max_fd = c->fd;
            }
        }

        njt_log_debug1(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                       "change max_fd: %i", max_fd);
    }

#if (NJT_DEBUG)
    if (cycle->log->log_level & NJT_LOG_DEBUG_ALL) {
        for (i = 0; i < nevents; i++) {
            ev = event_index[i];
            c = ev->data;
            njt_log_debug2(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                           "select event: fd:%d wr:%d", c->fd, ev->write);
        }

        njt_log_debug1(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                       "max_fd: %i", max_fd);
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

    ready = select(max_fd + 1, &work_read_fd_set, &work_write_fd_set, NULL, tp);

    err = (ready == -1) ? njt_errno : 0;

    if (flags & NJT_UPDATE_TIME || njt_event_timer_alarm) {
        njt_time_update();
    }

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                   "select ready %d", ready);

    if (err) {
        njt_uint_t  level;

        if (err == NJT_EINTR) {

            if (njt_event_timer_alarm) {
                njt_event_timer_alarm = 0;
                return NJT_OK;
            }

            level = NJT_LOG_INFO;

        } else {
            level = NJT_LOG_ALERT;
        }

        njt_log_error(level, cycle->log, err, "select() failed");

        if (err == NJT_EBADF) {
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
                found = 1;
                njt_log_debug1(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                               "select write %d", c->fd);
            }

        } else {
            if (FD_ISSET(c->fd, &work_read_fd_set)) {
                found = 1;
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

            nready++;
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
    socklen_t     len;
    njt_err_t     err;
    njt_socket_t  s;

    for (s = 0; s <= max_fd; s++) {

        if (FD_ISSET(s, &master_read_fd_set) == 0) {
            continue;
        }

        len = sizeof(int);

        if (getsockopt(s, SOL_SOCKET, SO_TYPE, &n, &len) == -1) {
            err = njt_socket_errno;

            njt_log_error(NJT_LOG_ALERT, cycle->log, err,
                          "invalid descriptor #%d in read fd_set", s);

            FD_CLR(s, &master_read_fd_set);
        }
    }

    for (s = 0; s <= max_fd; s++) {

        if (FD_ISSET(s, &master_write_fd_set) == 0) {
            continue;
        }

        len = sizeof(int);

        if (getsockopt(s, SOL_SOCKET, SO_TYPE, &n, &len) == -1) {
            err = njt_socket_errno;

            njt_log_error(NJT_LOG_ALERT, cycle->log, err,
                          "invalid descriptor #%d in write fd_set", s);

            FD_CLR(s, &master_write_fd_set);
        }
    }

    max_fd = -1;
}


static char *
njt_select_init_conf(njt_cycle_t *cycle, void *conf)
{
    njt_event_conf_t  *ecf;

    ecf = njt_event_get_conf(cycle->conf_ctx, njt_event_core_module);

    if (ecf->use != njt_select_module.ctx_index) {
        return NJT_CONF_OK;
    }

    /* disable warning: the default FD_SETSIZE is 1024U in FreeBSD 5.x */

    if (cycle->connection_n > FD_SETSIZE) {
        njt_log_error(NJT_LOG_EMERG, cycle->log, 0,
                      "the maximum number of files "
                      "supported by select() is %ud", FD_SETSIZE);
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}
