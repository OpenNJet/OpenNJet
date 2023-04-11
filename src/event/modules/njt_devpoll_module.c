
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


#if (NJT_TEST_BUILD_DEVPOLL)

/* Solaris declarations */

#ifndef POLLREMOVE
#define POLLREMOVE   0x0800
#endif
#define DP_POLL      0xD001
#define DP_ISPOLLED  0xD002

struct dvpoll {
    struct pollfd  *dp_fds;
    int             dp_nfds;
    int             dp_timeout;
};

#endif


typedef struct {
    njt_uint_t      changes;
    njt_uint_t      events;
} njt_devpoll_conf_t;


static njt_int_t njt_devpoll_init(njt_cycle_t *cycle, njt_msec_t timer);
static void njt_devpoll_done(njt_cycle_t *cycle);
static njt_int_t njt_devpoll_add_event(njt_event_t *ev, njt_int_t event,
    njt_uint_t flags);
static njt_int_t njt_devpoll_del_event(njt_event_t *ev, njt_int_t event,
    njt_uint_t flags);
static njt_int_t njt_devpoll_set_event(njt_event_t *ev, njt_int_t event,
    njt_uint_t flags);
static njt_int_t njt_devpoll_process_events(njt_cycle_t *cycle,
    njt_msec_t timer, njt_uint_t flags);

static void *njt_devpoll_create_conf(njt_cycle_t *cycle);
static char *njt_devpoll_init_conf(njt_cycle_t *cycle, void *conf);

static int              dp = -1;
static struct pollfd   *change_list, *event_list;
static njt_uint_t       nchanges, max_changes, nevents;

static njt_event_t    **change_index;


static njt_str_t      devpoll_name = njt_string("/dev/poll");

static njt_command_t  njt_devpoll_commands[] = {

    { njt_string("devpoll_changes"),
      NJT_EVENT_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      0,
      offsetof(njt_devpoll_conf_t, changes),
      NULL },

    { njt_string("devpoll_events"),
      NJT_EVENT_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      0,
      offsetof(njt_devpoll_conf_t, events),
      NULL },

      njt_null_command
};


static njt_event_module_t  njt_devpoll_module_ctx = {
    &devpoll_name,
    njt_devpoll_create_conf,               /* create configuration */
    njt_devpoll_init_conf,                 /* init configuration */

    {
        njt_devpoll_add_event,             /* add an event */
        njt_devpoll_del_event,             /* delete an event */
        njt_devpoll_add_event,             /* enable an event */
        njt_devpoll_del_event,             /* disable an event */
        NULL,                              /* add an connection */
        NULL,                              /* delete an connection */
        NULL,                              /* trigger a notify */
        njt_devpoll_process_events,        /* process the events */
        njt_devpoll_init,                  /* init the events */
        njt_devpoll_done,                  /* done the events */
    }

};

njt_module_t  njt_devpoll_module = {
    NJT_MODULE_V1,
    &njt_devpoll_module_ctx,               /* module context */
    njt_devpoll_commands,                  /* module directives */
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
njt_devpoll_init(njt_cycle_t *cycle, njt_msec_t timer)
{
    size_t               n;
    njt_devpoll_conf_t  *dpcf;

    dpcf = njt_event_get_conf(cycle->conf_ctx, njt_devpoll_module);

    if (dp == -1) {
        dp = open("/dev/poll", O_RDWR);

        if (dp == -1) {
            njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                          "open(/dev/poll) failed");
            return NJT_ERROR;
        }
    }

    if (max_changes < dpcf->changes) {
        if (nchanges) {
            n = nchanges * sizeof(struct pollfd);
            if (write(dp, change_list, n) != (ssize_t) n) {
                njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                              "write(/dev/poll) failed");
                return NJT_ERROR;
            }

            nchanges = 0;
        }

        if (change_list) {
            njt_free(change_list);
        }

        change_list = njt_alloc(sizeof(struct pollfd) * dpcf->changes,
                                cycle->log);
        if (change_list == NULL) {
            return NJT_ERROR;
        }

        if (change_index) {
            njt_free(change_index);
        }

        change_index = njt_alloc(sizeof(njt_event_t *) * dpcf->changes,
                                 cycle->log);
        if (change_index == NULL) {
            return NJT_ERROR;
        }
    }

    max_changes = dpcf->changes;

    if (nevents < dpcf->events) {
        if (event_list) {
            njt_free(event_list);
        }

        event_list = njt_alloc(sizeof(struct pollfd) * dpcf->events,
                               cycle->log);
        if (event_list == NULL) {
            return NJT_ERROR;
        }
    }

    nevents = dpcf->events;

    njt_io = njt_os_io;

    njt_event_actions = njt_devpoll_module_ctx.actions;

    njt_event_flags = NJT_USE_LEVEL_EVENT|NJT_USE_FD_EVENT;

    return NJT_OK;
}


static void
njt_devpoll_done(njt_cycle_t *cycle)
{
    if (close(dp) == -1) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                      "close(/dev/poll) failed");
    }

    dp = -1;

    njt_free(change_list);
    njt_free(event_list);
    njt_free(change_index);

    change_list = NULL;
    event_list = NULL;
    change_index = NULL;
    max_changes = 0;
    nchanges = 0;
    nevents = 0;
}


static njt_int_t
njt_devpoll_add_event(njt_event_t *ev, njt_int_t event, njt_uint_t flags)
{
#if (NJT_DEBUG)
    njt_connection_t *c;
#endif

#if (NJT_READ_EVENT != POLLIN)
    event = (event == NJT_READ_EVENT) ? POLLIN : POLLOUT;
#endif

#if (NJT_DEBUG)
    c = ev->data;
    njt_log_debug2(NJT_LOG_DEBUG_EVENT, ev->log, 0,
                   "devpoll add event: fd:%d ev:%04Xi", c->fd, event);
#endif

    ev->active = 1;

    return njt_devpoll_set_event(ev, event, 0);
}


static njt_int_t
njt_devpoll_del_event(njt_event_t *ev, njt_int_t event, njt_uint_t flags)
{
    njt_event_t       *e;
    njt_connection_t  *c;

    c = ev->data;

#if (NJT_READ_EVENT != POLLIN)
    event = (event == NJT_READ_EVENT) ? POLLIN : POLLOUT;
#endif

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, ev->log, 0,
                   "devpoll del event: fd:%d ev:%04Xi", c->fd, event);

    if (njt_devpoll_set_event(ev, POLLREMOVE, flags) == NJT_ERROR) {
        return NJT_ERROR;
    }

    ev->active = 0;

    if (flags & NJT_CLOSE_EVENT) {
        e = (event == POLLIN) ? c->write : c->read;

        if (e) {
            e->active = 0;
        }

        return NJT_OK;
    }

    /* restore the pair event if it exists */

    if (event == POLLIN) {
        e = c->write;
        event = POLLOUT;

    } else {
        e = c->read;
        event = POLLIN;
    }

    if (e && e->active) {
        return njt_devpoll_set_event(e, event, 0);
    }

    return NJT_OK;
}


static njt_int_t
njt_devpoll_set_event(njt_event_t *ev, njt_int_t event, njt_uint_t flags)
{
    size_t             n;
    njt_connection_t  *c;

    c = ev->data;

    njt_log_debug3(NJT_LOG_DEBUG_EVENT, ev->log, 0,
                   "devpoll fd:%d ev:%04Xi fl:%04Xi", c->fd, event, flags);

    if (nchanges >= max_changes) {
        njt_log_error(NJT_LOG_WARN, ev->log, 0,
                      "/dev/pool change list is filled up");

        n = nchanges * sizeof(struct pollfd);
        if (write(dp, change_list, n) != (ssize_t) n) {
            njt_log_error(NJT_LOG_ALERT, ev->log, njt_errno,
                          "write(/dev/poll) failed");
            return NJT_ERROR;
        }

        nchanges = 0;
    }

    change_list[nchanges].fd = c->fd;
    change_list[nchanges].events = (short) event;
    change_list[nchanges].revents = 0;

    change_index[nchanges] = ev;
    ev->index = nchanges;

    nchanges++;

    if (flags & NJT_CLOSE_EVENT) {
        n = nchanges * sizeof(struct pollfd);
        if (write(dp, change_list, n) != (ssize_t) n) {
            njt_log_error(NJT_LOG_ALERT, ev->log, njt_errno,
                          "write(/dev/poll) failed");
            return NJT_ERROR;
        }

        nchanges = 0;
    }

    return NJT_OK;
}


static njt_int_t
njt_devpoll_process_events(njt_cycle_t *cycle, njt_msec_t timer,
    njt_uint_t flags)
{
    int                 events, revents, rc;
    size_t              n;
    njt_fd_t            fd;
    njt_err_t           err;
    njt_int_t           i;
    njt_uint_t          level, instance;
    njt_event_t        *rev, *wev;
    njt_queue_t        *queue;
    njt_connection_t   *c;
    struct pollfd       pfd;
    struct dvpoll       dvp;

    /* NJT_TIMER_INFINITE == INFTIM */

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                   "devpoll timer: %M", timer);

    if (nchanges) {
        n = nchanges * sizeof(struct pollfd);
        if (write(dp, change_list, n) != (ssize_t) n) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                          "write(/dev/poll) failed");
            return NJT_ERROR;
        }

        nchanges = 0;
    }

    dvp.dp_fds = event_list;
    dvp.dp_nfds = (int) nevents;
    dvp.dp_timeout = timer;
    events = ioctl(dp, DP_POLL, &dvp);

    err = (events == -1) ? njt_errno : 0;

    if (flags & NJT_UPDATE_TIME || njt_event_timer_alarm) {
        njt_time_update();
    }

    if (err) {
        if (err == NJT_EINTR) {

            if (njt_event_timer_alarm) {
                njt_event_timer_alarm = 0;
                return NJT_OK;
            }

            level = NJT_LOG_INFO;

        } else {
            level = NJT_LOG_ALERT;
        }

        njt_log_error(level, cycle->log, err, "ioctl(DP_POLL) failed");
        return NJT_ERROR;
    }

    if (events == 0) {
        if (timer != NJT_TIMER_INFINITE) {
            return NJT_OK;
        }

        njt_log_error(NJT_LOG_ALERT, cycle->log, 0,
                      "ioctl(DP_POLL) returned no events without timeout");
        return NJT_ERROR;
    }

    for (i = 0; i < events; i++) {

        fd = event_list[i].fd;
        revents = event_list[i].revents;

        c = njt_cycle->files[fd];

        if (c == NULL || c->fd == -1) {

            pfd.fd = fd;
            pfd.events = 0;
            pfd.revents = 0;

            rc = ioctl(dp, DP_ISPOLLED, &pfd);

            switch (rc) {

            case -1:
                njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                    "ioctl(DP_ISPOLLED) failed for socket %d, event %04Xd",
                    fd, revents);
                break;

            case 0:
                njt_log_error(NJT_LOG_ALERT, cycle->log, 0,
                    "phantom event %04Xd for closed and removed socket %d",
                    revents, fd);
                break;

            default:
                njt_log_error(NJT_LOG_ALERT, cycle->log, 0,
                    "unexpected event %04Xd for closed and removed socket %d, "
                    "ioctl(DP_ISPOLLED) returned rc:%d, fd:%d, event %04Xd",
                    revents, fd, rc, pfd.fd, pfd.revents);

                pfd.fd = fd;
                pfd.events = POLLREMOVE;
                pfd.revents = 0;

                if (write(dp, &pfd, sizeof(struct pollfd))
                    != (ssize_t) sizeof(struct pollfd))
                {
                    njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                                  "write(/dev/poll) for %d failed", fd);
                }

                if (close(fd) == -1) {
                    njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                                  "close(%d) failed", fd);
                }

                break;
            }

            continue;
        }

        njt_log_debug3(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                       "devpoll: fd:%d, ev:%04Xd, rev:%04Xd",
                       fd, event_list[i].events, revents);

        if (revents & (POLLERR|POLLHUP|POLLNVAL)) {
            njt_log_debug3(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                          "ioctl(DP_POLL) error fd:%d ev:%04Xd rev:%04Xd",
                          fd, event_list[i].events, revents);
        }

        if (revents & ~(POLLIN|POLLOUT|POLLERR|POLLHUP|POLLNVAL)) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, 0,
                          "strange ioctl(DP_POLL) events "
                          "fd:%d ev:%04Xd rev:%04Xd",
                          fd, event_list[i].events, revents);
        }

        if (revents & (POLLERR|POLLHUP|POLLNVAL)) {

            /*
             * if the error events were returned, add POLLIN and POLLOUT
             * to handle the events at least in one active handler
             */

            revents |= POLLIN|POLLOUT;
        }

        rev = c->read;

        if ((revents & POLLIN) && rev->active) {
            rev->ready = 1;
            rev->available = -1;

            if (flags & NJT_POST_EVENTS) {
                queue = rev->accept ? &njt_posted_accept_events
                                    : &njt_posted_events;

                njt_post_event(rev, queue);

            } else {
                instance = rev->instance;

                rev->handler(rev);

                if (c->fd == -1 || rev->instance != instance) {
                    continue;
                }
            }
        }

        wev = c->write;

        if ((revents & POLLOUT) && wev->active) {
            wev->ready = 1;

            if (flags & NJT_POST_EVENTS) {
                njt_post_event(wev, &njt_posted_events);

            } else {
                wev->handler(wev);
            }
        }
    }

    return NJT_OK;
}


static void *
njt_devpoll_create_conf(njt_cycle_t *cycle)
{
    njt_devpoll_conf_t  *dpcf;

    dpcf = njt_palloc(cycle->pool, sizeof(njt_devpoll_conf_t));
    if (dpcf == NULL) {
        return NULL;
    }

    dpcf->changes = NJT_CONF_UNSET;
    dpcf->events = NJT_CONF_UNSET;

    return dpcf;
}


static char *
njt_devpoll_init_conf(njt_cycle_t *cycle, void *conf)
{
    njt_devpoll_conf_t *dpcf = conf;

    njt_conf_init_uint_value(dpcf->changes, 32);
    njt_conf_init_uint_value(dpcf->events, 32);

    return NJT_CONF_OK;
}
