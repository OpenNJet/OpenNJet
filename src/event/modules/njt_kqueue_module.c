
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


typedef struct {
    njt_uint_t  changes;
    njt_uint_t  events;
} njt_kqueue_conf_t;


static njt_int_t njt_kqueue_init(njt_cycle_t *cycle, njt_msec_t timer);
#ifdef EVFILT_USER
static njt_int_t njt_kqueue_notify_init(njt_log_t *log);
#endif
static void njt_kqueue_done(njt_cycle_t *cycle);
static njt_int_t njt_kqueue_add_event(njt_event_t *ev, njt_int_t event,
    njt_uint_t flags);
static njt_int_t njt_kqueue_del_event(njt_event_t *ev, njt_int_t event,
    njt_uint_t flags);
static njt_int_t njt_kqueue_set_event(njt_event_t *ev, njt_int_t filter,
    njt_uint_t flags);
#ifdef EVFILT_USER
static njt_int_t njt_kqueue_notify(njt_event_handler_pt handler);
#endif
static njt_int_t njt_kqueue_process_events(njt_cycle_t *cycle, njt_msec_t timer,
    njt_uint_t flags);
static njt_inline void njt_kqueue_dump_event(njt_log_t *log,
    struct kevent *kev);

static void *njt_kqueue_create_conf(njt_cycle_t *cycle);
static char *njt_kqueue_init_conf(njt_cycle_t *cycle, void *conf);


int                    njt_kqueue = -1;

static struct kevent  *change_list;
static struct kevent  *event_list;
static njt_uint_t      max_changes, nchanges, nevents;

#ifdef EVFILT_USER
static njt_event_t     notify_event;
static struct kevent   notify_kev;
#endif


static njt_str_t      kqueue_name = njt_string("kqueue");

static njt_command_t  njt_kqueue_commands[] = {

    { njt_string("kqueue_changes"),
      NJT_EVENT_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      0,
      offsetof(njt_kqueue_conf_t, changes),
      NULL },

    { njt_string("kqueue_events"),
      NJT_EVENT_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      0,
      offsetof(njt_kqueue_conf_t, events),
      NULL },

      njt_null_command
};


static njt_event_module_t  njt_kqueue_module_ctx = {
    &kqueue_name,
    njt_kqueue_create_conf,                /* create configuration */
    njt_kqueue_init_conf,                  /* init configuration */

    {
        njt_kqueue_add_event,              /* add an event */
        njt_kqueue_del_event,              /* delete an event */
        njt_kqueue_add_event,              /* enable an event */
        njt_kqueue_del_event,              /* disable an event */
        NULL,                              /* add an connection */
        NULL,                              /* delete an connection */
#ifdef EVFILT_USER
        njt_kqueue_notify,                 /* trigger a notify */
#else
        NULL,                              /* trigger a notify */
#endif
        njt_kqueue_process_events,         /* process the events */
        njt_kqueue_init,                   /* init the events */
        njt_kqueue_done                    /* done the events */
    }

};

njt_module_t  njt_kqueue_module = {
    NJT_MODULE_V1,
    &njt_kqueue_module_ctx,                /* module context */
    njt_kqueue_commands,                   /* module directives */
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
njt_kqueue_init(njt_cycle_t *cycle, njt_msec_t timer)
{
    njt_kqueue_conf_t  *kcf;
    struct timespec     ts;
#if (NJT_HAVE_TIMER_EVENT)
    struct kevent       kev;
#endif

    kcf = njt_event_get_conf(cycle->conf_ctx, njt_kqueue_module);

    if (njt_kqueue == -1) {
        njt_kqueue = kqueue();

        if (njt_kqueue == -1) {
            njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                          "kqueue() failed");
            return NJT_ERROR;
        }

#ifdef EVFILT_USER
        if (njt_kqueue_notify_init(cycle->log) != NJT_OK) {
            return NJT_ERROR;
        }
#endif
    }

    if (max_changes < kcf->changes) {
        if (nchanges) {
            ts.tv_sec = 0;
            ts.tv_nsec = 0;

            if (kevent(njt_kqueue, change_list, (int) nchanges, NULL, 0, &ts)
                == -1)
            {
                njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                              "kevent() failed");
                return NJT_ERROR;
            }
            nchanges = 0;
        }

        if (change_list) {
            njt_free(change_list);
        }

        change_list = njt_alloc(kcf->changes * sizeof(struct kevent),
                                cycle->log);
        if (change_list == NULL) {
            return NJT_ERROR;
        }
    }

    max_changes = kcf->changes;

    if (nevents < kcf->events) {
        if (event_list) {
            njt_free(event_list);
        }

        event_list = njt_alloc(kcf->events * sizeof(struct kevent), cycle->log);
        if (event_list == NULL) {
            return NJT_ERROR;
        }
    }

    njt_event_flags = NJT_USE_ONESHOT_EVENT
                      |NJT_USE_KQUEUE_EVENT
                      |NJT_USE_VNODE_EVENT;

#if (NJT_HAVE_TIMER_EVENT)

    if (timer) {
        kev.ident = 0;
        kev.filter = EVFILT_TIMER;
        kev.flags = EV_ADD|EV_ENABLE;
        kev.fflags = 0;
        kev.data = timer;
        kev.udata = 0;

        ts.tv_sec = 0;
        ts.tv_nsec = 0;

        if (kevent(njt_kqueue, &kev, 1, NULL, 0, &ts) == -1) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                          "kevent(EVFILT_TIMER) failed");
            return NJT_ERROR;
        }

        njt_event_flags |= NJT_USE_TIMER_EVENT;
    }

#endif

#if (NJT_HAVE_CLEAR_EVENT)
    njt_event_flags |= NJT_USE_CLEAR_EVENT;
#else
    njt_event_flags |= NJT_USE_LEVEL_EVENT;
#endif

#if (NJT_HAVE_LOWAT_EVENT)
    njt_event_flags |= NJT_USE_LOWAT_EVENT;
#endif

    nevents = kcf->events;

    njt_io = njt_os_io;

    njt_event_actions = njt_kqueue_module_ctx.actions;

    return NJT_OK;
}


#ifdef EVFILT_USER

static njt_int_t
njt_kqueue_notify_init(njt_log_t *log)
{
    notify_kev.ident = 0;
    notify_kev.filter = EVFILT_USER;
    notify_kev.data = 0;
    notify_kev.flags = EV_ADD|EV_CLEAR;
    notify_kev.fflags = 0;
    notify_kev.udata = 0;

    if (kevent(njt_kqueue, &notify_kev, 1, NULL, 0, NULL) == -1) {
        njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                      "kevent(EVFILT_USER, EV_ADD) failed");
        return NJT_ERROR;
    }

    notify_event.active = 1;
    notify_event.log = log;

    notify_kev.flags = 0;
    notify_kev.fflags = NOTE_TRIGGER;
    notify_kev.udata = NJT_KQUEUE_UDATA_T ((uintptr_t) &notify_event);

    return NJT_OK;
}

#endif


static void
njt_kqueue_done(njt_cycle_t *cycle)
{
    if (close(njt_kqueue) == -1) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                      "kqueue close() failed");
    }

    njt_kqueue = -1;

    njt_free(change_list);
    njt_free(event_list);

    change_list = NULL;
    event_list = NULL;
    max_changes = 0;
    nchanges = 0;
    nevents = 0;
}


static njt_int_t
njt_kqueue_add_event(njt_event_t *ev, njt_int_t event, njt_uint_t flags)
{
    njt_int_t          rc;
#if 0
    njt_event_t       *e;
    njt_connection_t  *c;
#endif

    ev->active = 1;
    ev->disabled = 0;
    ev->oneshot = (flags & NJT_ONESHOT_EVENT) ? 1 : 0;

#if 0

    if (ev->index < nchanges
        && ((uintptr_t) change_list[ev->index].udata & (uintptr_t) ~1)
            == (uintptr_t) ev)
    {
        if (change_list[ev->index].flags == EV_DISABLE) {

            /*
             * if the EV_DISABLE is still not passed to a kernel
             * we will not pass it
             */

            njt_log_debug2(NJT_LOG_DEBUG_EVENT, ev->log, 0,
                           "kevent activated: %d: ft:%i",
                           njt_event_ident(ev->data), event);

            if (ev->index < --nchanges) {
                e = (njt_event_t *)
                    ((uintptr_t) change_list[nchanges].udata & (uintptr_t) ~1);
                change_list[ev->index] = change_list[nchanges];
                e->index = ev->index;
            }

            return NJT_OK;
        }

        c = ev->data;

        njt_log_error(NJT_LOG_ALERT, ev->log, 0,
                      "previous event on #%d were not passed in kernel", c->fd);

        return NJT_ERROR;
    }

#endif

    rc = njt_kqueue_set_event(ev, event, EV_ADD|EV_ENABLE|flags);

    return rc;
}


static njt_int_t
njt_kqueue_del_event(njt_event_t *ev, njt_int_t event, njt_uint_t flags)
{
    njt_int_t     rc;
    njt_event_t  *e;

    ev->active = 0;
    ev->disabled = 0;

    if (ev->index < nchanges
        && ((uintptr_t) change_list[ev->index].udata & (uintptr_t) ~1)
            == (uintptr_t) ev)
    {
        njt_log_debug2(NJT_LOG_DEBUG_EVENT, ev->log, 0,
                       "kevent deleted: %d: ft:%i",
                       njt_event_ident(ev->data), event);

        /* if the event is still not passed to a kernel we will not pass it */

        nchanges--;

        if (ev->index < nchanges) {
            e = (njt_event_t *)
                    ((uintptr_t) change_list[nchanges].udata & (uintptr_t) ~1);
            change_list[ev->index] = change_list[nchanges];
            e->index = ev->index;
        }

        return NJT_OK;
    }

    /*
     * when the file descriptor is closed the kqueue automatically deletes
     * its filters so we do not need to delete explicitly the event
     * before the closing the file descriptor.
     */

    if (flags & NJT_CLOSE_EVENT) {
        return NJT_OK;
    }

    if (flags & NJT_DISABLE_EVENT) {
        ev->disabled = 1;

    } else {
        flags |= EV_DELETE;
    }

    rc = njt_kqueue_set_event(ev, event, flags);

    return rc;
}


static njt_int_t
njt_kqueue_set_event(njt_event_t *ev, njt_int_t filter, njt_uint_t flags)
{
    struct kevent     *kev;
    struct timespec    ts;
    njt_connection_t  *c;

    c = ev->data;

    njt_log_debug3(NJT_LOG_DEBUG_EVENT, ev->log, 0,
                   "kevent set event: %d: ft:%i fl:%04Xi",
                   c->fd, filter, flags);

    if (nchanges >= max_changes) {
        njt_log_error(NJT_LOG_WARN, ev->log, 0,
                      "kqueue change list is filled up");

        ts.tv_sec = 0;
        ts.tv_nsec = 0;

        if (kevent(njt_kqueue, change_list, (int) nchanges, NULL, 0, &ts)
            == -1)
        {
            njt_log_error(NJT_LOG_ALERT, ev->log, njt_errno, "kevent() failed");
            return NJT_ERROR;
        }

        nchanges = 0;
    }

    kev = &change_list[nchanges];

    kev->ident = c->fd;
    kev->filter = (short) filter;
    kev->flags = (u_short) flags;
    kev->udata = NJT_KQUEUE_UDATA_T ((uintptr_t) ev | ev->instance);

    if (filter == EVFILT_VNODE) {
        kev->fflags = NOTE_DELETE|NOTE_WRITE|NOTE_EXTEND
                                 |NOTE_ATTRIB|NOTE_RENAME
#if (__FreeBSD__ == 4 && __FreeBSD_version >= 430000) \
    || __FreeBSD_version >= 500018
                                 |NOTE_REVOKE
#endif
                      ;
        kev->data = 0;

    } else {
#if (NJT_HAVE_LOWAT_EVENT)
        if (flags & NJT_LOWAT_EVENT) {
            kev->fflags = NOTE_LOWAT;
            kev->data = ev->available;

        } else {
            kev->fflags = 0;
            kev->data = 0;
        }
#else
        kev->fflags = 0;
        kev->data = 0;
#endif
    }

    ev->index = nchanges;
    nchanges++;

    if (flags & NJT_FLUSH_EVENT) {
        ts.tv_sec = 0;
        ts.tv_nsec = 0;

        njt_log_debug0(NJT_LOG_DEBUG_EVENT, ev->log, 0, "kevent flush");

        if (kevent(njt_kqueue, change_list, (int) nchanges, NULL, 0, &ts)
            == -1)
        {
            njt_log_error(NJT_LOG_ALERT, ev->log, njt_errno, "kevent() failed");
            return NJT_ERROR;
        }

        nchanges = 0;
    }

    return NJT_OK;
}


#ifdef EVFILT_USER

static njt_int_t
njt_kqueue_notify(njt_event_handler_pt handler)
{
    notify_event.handler = handler;

    if (kevent(njt_kqueue, &notify_kev, 1, NULL, 0, NULL) == -1) {
        njt_log_error(NJT_LOG_ALERT, notify_event.log, njt_errno,
                      "kevent(EVFILT_USER, NOTE_TRIGGER) failed");
        return NJT_ERROR;
    }

    return NJT_OK;
}

#endif


static njt_int_t
njt_kqueue_process_events(njt_cycle_t *cycle, njt_msec_t timer,
    njt_uint_t flags)
{
    int               events, n;
    njt_int_t         i, instance;
    njt_uint_t        level;
    njt_err_t         err;
    njt_event_t      *ev;
    njt_queue_t      *queue;
    struct timespec   ts, *tp;

    n = (int) nchanges;
    nchanges = 0;

    if (timer == NJT_TIMER_INFINITE) {
        tp = NULL;

    } else {

        ts.tv_sec = timer / 1000;
        ts.tv_nsec = (timer % 1000) * 1000000;

        /*
         * 64-bit Darwin kernel has the bug: kernel level ts.tv_nsec is
         * the int32_t while user level ts.tv_nsec is the long (64-bit),
         * so on the big endian PowerPC all nanoseconds are lost.
         */

#if (NJT_DARWIN_KEVENT_BUG)
        ts.tv_nsec <<= 32;
#endif

        tp = &ts;
    }

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                   "kevent timer: %M, changes: %d", timer, n);

    events = kevent(njt_kqueue, change_list, n, event_list, (int) nevents, tp);

    err = (events == -1) ? njt_errno : 0;

    if (flags & NJT_UPDATE_TIME || njt_event_timer_alarm) {
        njt_time_update();
    }

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                   "kevent events: %d", events);

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

        njt_log_error(level, cycle->log, err, "kevent() failed");
        return NJT_ERROR;
    }

    if (events == 0) {
        if (timer != NJT_TIMER_INFINITE) {
            return NJT_OK;
        }

        njt_log_error(NJT_LOG_ALERT, cycle->log, 0,
                      "kevent() returned no events without timeout");
        return NJT_ERROR;
    }

    for (i = 0; i < events; i++) {

        njt_kqueue_dump_event(cycle->log, &event_list[i]);

        if (event_list[i].flags & EV_ERROR) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, event_list[i].data,
                          "kevent() error on %d filter:%d flags:%04Xd",
                          (int) event_list[i].ident, event_list[i].filter,
                          event_list[i].flags);
            continue;
        }

#if (NJT_HAVE_TIMER_EVENT)

        if (event_list[i].filter == EVFILT_TIMER) {
            njt_time_update();
            continue;
        }

#endif

        ev = (njt_event_t *) event_list[i].udata;

        switch (event_list[i].filter) {

        case EVFILT_READ:
        case EVFILT_WRITE:

            instance = (uintptr_t) ev & 1;
            ev = (njt_event_t *) ((uintptr_t) ev & (uintptr_t) ~1);

            if (ev->closed || ev->instance != instance) {

                /*
                 * the stale event from a file descriptor
                 * that was just closed in this iteration
                 */

                njt_log_debug1(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                               "kevent: stale event %p", ev);
                continue;
            }

            if (ev->log && (ev->log->log_level & NJT_LOG_DEBUG_CONNECTION)) {
                njt_kqueue_dump_event(ev->log, &event_list[i]);
            }

            if (ev->oneshot) {
                ev->active = 0;
            }

            ev->available = event_list[i].data;

            if (event_list[i].flags & EV_EOF) {
                ev->pending_eof = 1;
                ev->kq_errno = event_list[i].fflags;
            }

            ev->ready = 1;

            break;

        case EVFILT_VNODE:
            ev->kq_vnode = 1;

            break;

        case EVFILT_AIO:
            ev->complete = 1;
            ev->ready = 1;

            break;

#ifdef EVFILT_USER
        case EVFILT_USER:
            break;
#endif

        default:
            njt_log_error(NJT_LOG_ALERT, cycle->log, 0,
                          "unexpected kevent() filter %d",
                          event_list[i].filter);
            continue;
        }

        if (flags & NJT_POST_EVENTS) {
            queue = ev->accept ? &njt_posted_accept_events
                               : &njt_posted_events;

            njt_post_event(ev, queue);

            continue;
        }

        ev->handler(ev);
    }

    return NJT_OK;
}


static njt_inline void
njt_kqueue_dump_event(njt_log_t *log, struct kevent *kev)
{
    if (kev->ident > 0x8000000 && kev->ident != (unsigned) -1) {
        njt_log_debug6(NJT_LOG_DEBUG_EVENT, log, 0,
                       "kevent: %p: ft:%d fl:%04Xd ff:%08Xd d:%d ud:%p",
                       (void *) kev->ident, kev->filter,
                       kev->flags, kev->fflags,
                       (int) kev->data, kev->udata);

    } else {
        njt_log_debug6(NJT_LOG_DEBUG_EVENT, log, 0,
                       "kevent: %d: ft:%d fl:%04Xd ff:%08Xd d:%d ud:%p",
                       (int) kev->ident, kev->filter,
                       kev->flags, kev->fflags,
                       (int) kev->data, kev->udata);
    }
}


static void *
njt_kqueue_create_conf(njt_cycle_t *cycle)
{
    njt_kqueue_conf_t  *kcf;

    kcf = njt_palloc(cycle->pool, sizeof(njt_kqueue_conf_t));
    if (kcf == NULL) {
        return NULL;
    }

    kcf->changes = NJT_CONF_UNSET;
    kcf->events = NJT_CONF_UNSET;

    return kcf;
}


static char *
njt_kqueue_init_conf(njt_cycle_t *cycle, void *conf)
{
    njt_kqueue_conf_t *kcf = conf;

    njt_conf_init_uint_value(kcf->changes, 512);
    njt_conf_init_uint_value(kcf->events, 512);

    return NJT_CONF_OK;
}
