
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


static njt_int_t njt_poll_init(njt_cycle_t *cycle, njt_msec_t timer);
static void njt_poll_done(njt_cycle_t *cycle);
static njt_int_t njt_poll_add_event(njt_event_t *ev, njt_int_t event,
    njt_uint_t flags);
static njt_int_t njt_poll_del_event(njt_event_t *ev, njt_int_t event,
    njt_uint_t flags);
static njt_int_t njt_poll_process_events(njt_cycle_t *cycle, njt_msec_t timer,
    njt_uint_t flags);
static char *njt_poll_init_conf(njt_cycle_t *cycle, void *conf);


static struct pollfd  *event_list;
static njt_uint_t      nevents;


static njt_str_t           poll_name = njt_string("poll");

static njt_event_module_t  njt_poll_module_ctx = {
    &poll_name,
    NULL,                                  /* create configuration */
    njt_poll_init_conf,                    /* init configuration */

    {
        njt_poll_add_event,                /* add an event */
        njt_poll_del_event,                /* delete an event */
        njt_poll_add_event,                /* enable an event */
        njt_poll_del_event,                /* disable an event */
        NULL,                              /* add an connection */
        NULL,                              /* delete an connection */
        NULL,                              /* trigger a notify */
        njt_poll_process_events,           /* process the events */
        njt_poll_init,                     /* init the events */
        njt_poll_done                      /* done the events */
    }

};

njt_module_t  njt_poll_module = {
    NJT_MODULE_V1,
    &njt_poll_module_ctx,                  /* module context */
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
njt_poll_init(njt_cycle_t *cycle, njt_msec_t timer)
{
    struct pollfd   *list;

    if (event_list == NULL) {
        nevents = 0;
    }

    if (njt_process >= NJT_PROCESS_WORKER
        || cycle->old_cycle == NULL
        || cycle->old_cycle->connection_n < cycle->connection_n)
    {
        list = njt_alloc(sizeof(struct pollfd) * cycle->connection_n,
                         cycle->log);
        if (list == NULL) {
            return NJT_ERROR;
        }

        if (event_list) {
            njt_memcpy(list, event_list, sizeof(struct pollfd) * nevents);
            njt_free(event_list);
        }

        event_list = list;
    }

    njt_io = njt_os_io;

    njt_event_actions = njt_poll_module_ctx.actions;

    njt_event_flags = NJT_USE_LEVEL_EVENT|NJT_USE_FD_EVENT;

    return NJT_OK;
}


static void
njt_poll_done(njt_cycle_t *cycle)
{
    njt_free(event_list);

    event_list = NULL;
}


static njt_int_t
njt_poll_add_event(njt_event_t *ev, njt_int_t event, njt_uint_t flags)
{
    njt_event_t       *e;
    njt_connection_t  *c;

    c = ev->data;

    ev->active = 1;

    if (ev->index != NJT_INVALID_INDEX) {
        njt_log_error(NJT_LOG_ALERT, ev->log, 0,
                      "poll event fd:%d ev:%i is already set", c->fd, event);
        return NJT_OK;
    }

    if (event == NJT_READ_EVENT) {
        e = c->write;
#if (NJT_READ_EVENT != POLLIN)
        event = POLLIN;
#endif

    } else {
        e = c->read;
#if (NJT_WRITE_EVENT != POLLOUT)
        event = POLLOUT;
#endif
    }

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, ev->log, 0,
                   "poll add event: fd:%d ev:%i", c->fd, event);

    if (e == NULL || e->index == NJT_INVALID_INDEX) {
        event_list[nevents].fd = c->fd;
        event_list[nevents].events = (short) event;
        event_list[nevents].revents = 0;

        ev->index = nevents;
        nevents++;

    } else {
        njt_log_debug1(NJT_LOG_DEBUG_EVENT, ev->log, 0,
                       "poll add index: %i", e->index);

        event_list[e->index].events |= (short) event;
        ev->index = e->index;
    }

    return NJT_OK;
}


static njt_int_t
njt_poll_del_event(njt_event_t *ev, njt_int_t event, njt_uint_t flags)
{
    njt_event_t       *e;
    njt_connection_t  *c;

    c = ev->data;

    ev->active = 0;

    if (ev->index == NJT_INVALID_INDEX) {
        njt_log_error(NJT_LOG_ALERT, ev->log, 0,
                      "poll event fd:%d ev:%i is already deleted",
                      c->fd, event);
        return NJT_OK;
    }

    if (event == NJT_READ_EVENT) {
        e = c->write;
#if (NJT_READ_EVENT != POLLIN)
        event = POLLIN;
#endif

    } else {
        e = c->read;
#if (NJT_WRITE_EVENT != POLLOUT)
        event = POLLOUT;
#endif
    }

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, ev->log, 0,
                   "poll del event: fd:%d ev:%i", c->fd, event);

    if (e == NULL || e->index == NJT_INVALID_INDEX) {
        nevents--;

        if (ev->index < nevents) {

            njt_log_debug2(NJT_LOG_DEBUG_EVENT, ev->log, 0,
                           "index: copy event %ui to %i", nevents, ev->index);

            event_list[ev->index] = event_list[nevents];

            c = njt_cycle->files[event_list[nevents].fd];

            if (c->fd == -1) {
                njt_log_error(NJT_LOG_ALERT, ev->log, 0,
                              "unexpected last event");

            } else {
                if (c->read->index == nevents) {
                    c->read->index = ev->index;
                }

                if (c->write->index == nevents) {
                    c->write->index = ev->index;
                }
            }
        }

    } else {
        njt_log_debug1(NJT_LOG_DEBUG_EVENT, ev->log, 0,
                       "poll del index: %i", e->index);

        event_list[e->index].events &= (short) ~event;
    }

    ev->index = NJT_INVALID_INDEX;

    return NJT_OK;
}


static njt_int_t
njt_poll_process_events(njt_cycle_t *cycle, njt_msec_t timer, njt_uint_t flags)
{
    int                 ready, revents;
    njt_err_t           err;
    njt_uint_t          i, found, level;
    njt_event_t        *ev;
    njt_queue_t        *queue;
    njt_connection_t   *c;

    /* NJT_TIMER_INFINITE == INFTIM */

#if (NJT_DEBUG0)
    if (cycle->log->log_level & NJT_LOG_DEBUG_ALL) {
        for (i = 0; i < nevents; i++) {
            njt_log_debug3(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                           "poll: %ui: fd:%d ev:%04Xd",
                           i, event_list[i].fd, event_list[i].events);
        }
    }
#endif

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, cycle->log, 0, "poll timer: %M", timer);

    ready = poll(event_list, (u_int) nevents, (int) timer);

    err = (ready == -1) ? njt_errno : 0;

    if (flags & NJT_UPDATE_TIME || njt_event_timer_alarm) {
        njt_time_update();
    }

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                   "poll ready %d of %ui", ready, nevents);

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

        njt_log_error(level, cycle->log, err, "poll() failed");
        return NJT_ERROR;
    }

    if (ready == 0) {
        if (timer != NJT_TIMER_INFINITE) {
            return NJT_OK;
        }

        njt_log_error(NJT_LOG_ALERT, cycle->log, 0,
                      "poll() returned no events without timeout");
        return NJT_ERROR;
    }

    for (i = 0; i < nevents && ready; i++) {

        revents = event_list[i].revents;

#if 1
        njt_log_debug4(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                       "poll: %ui: fd:%d ev:%04Xd rev:%04Xd",
                       i, event_list[i].fd, event_list[i].events, revents);
#else
        if (revents) {
            njt_log_debug4(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                           "poll: %ui: fd:%d ev:%04Xd rev:%04Xd",
                           i, event_list[i].fd, event_list[i].events, revents);
        }
#endif

        if (revents & POLLNVAL) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, 0,
                          "poll() error fd:%d ev:%04Xd rev:%04Xd",
                          event_list[i].fd, event_list[i].events, revents);
        }

        if (revents & ~(POLLIN|POLLOUT|POLLERR|POLLHUP|POLLNVAL)) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, 0,
                          "strange poll() events fd:%d ev:%04Xd rev:%04Xd",
                          event_list[i].fd, event_list[i].events, revents);
        }

        if (event_list[i].fd == -1) {
            /*
             * the disabled event, a workaround for our possible bug,
             * see the comment below
             */
            continue;
        }

        c = njt_cycle->files[event_list[i].fd];

        if (c->fd == -1) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, 0, "unexpected event");

            /*
             * it is certainly our fault and it should be investigated,
             * in the meantime we disable this event to avoid a CPU spinning
             */

            if (i == nevents - 1) {
                nevents--;
            } else {
                event_list[i].fd = -1;
            }

            continue;
        }

        if (revents & (POLLERR|POLLHUP|POLLNVAL)) {

            /*
             * if the error events were returned, add POLLIN and POLLOUT
             * to handle the events at least in one active handler
             */

            revents |= POLLIN|POLLOUT;
        }

        found = 0;

        if ((revents & POLLIN) && c->read->active) {
            found = 1;

            ev = c->read;
            ev->ready = 1;
            ev->available = -1;

            queue = ev->accept ? &njt_posted_accept_events
                               : &njt_posted_events;

            njt_post_event(ev, queue);
        }

        if ((revents & POLLOUT) && c->write->active) {
            found = 1;

            ev = c->write;
            ev->ready = 1;

            njt_post_event(ev, &njt_posted_events);
        }

        if (found) {
            ready--;
            continue;
        }
    }

    if (ready != 0) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, 0, "poll ready != events");
    }

    return NJT_OK;
}


static char *
njt_poll_init_conf(njt_cycle_t *cycle, void *conf)
{
    njt_event_conf_t  *ecf;

    ecf = njt_event_get_conf(cycle->conf_ctx, njt_event_core_module);

    if (ecf->use != njt_poll_module.ctx_index) {
        return NJT_CONF_OK;
    }

    return NJT_CONF_OK;
}
