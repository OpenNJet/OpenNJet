
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


#if (NJT_TEST_BUILD_EVENTPORT)

#define ushort_t  u_short
#define uint_t    u_int

#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME          0
typedef int     clockid_t;
typedef void *  timer_t;
#elif (NJT_DARWIN)
typedef void *  timer_t;
#endif

/* Solaris declarations */

#define PORT_SOURCE_AIO         1
#define PORT_SOURCE_TIMER       2
#define PORT_SOURCE_USER        3
#define PORT_SOURCE_FD          4
#define PORT_SOURCE_ALERT       5
#define PORT_SOURCE_MQ          6

#ifndef ETIME
#define ETIME                   64
#endif

#define SIGEV_PORT              4

typedef struct {
    int         portev_events;  /* event data is source specific */
    ushort_t    portev_source;  /* event source */
    ushort_t    portev_pad;     /* port internal use */
    uintptr_t   portev_object;  /* source specific object */
    void       *portev_user;    /* user cookie */
} port_event_t;

typedef struct  port_notify {
    int         portnfy_port;   /* bind request(s) to port */
    void       *portnfy_user;   /* user defined */
} port_notify_t;

#if (__FreeBSD__ && __FreeBSD_version < 700005) || (NJT_DARWIN)

typedef struct itimerspec {     /* definition per POSIX.4 */
    struct timespec it_interval;/* timer period */
    struct timespec it_value;   /* timer expiration */
} itimerspec_t;

#endif

int port_create(void);

int port_create(void)
{
    return -1;
}


int port_associate(int port, int source, uintptr_t object, int events,
    void *user);

int port_associate(int port, int source, uintptr_t object, int events,
    void *user)
{
    return -1;
}


int port_dissociate(int port, int source, uintptr_t object);

int port_dissociate(int port, int source, uintptr_t object)
{
    return -1;
}


int port_getn(int port, port_event_t list[], uint_t max, uint_t *nget,
    struct timespec *timeout);

int port_getn(int port, port_event_t list[], uint_t max, uint_t *nget,
    struct timespec *timeout)
{
    return -1;
}

int port_send(int port, int events, void *user);

int port_send(int port, int events, void *user)
{
    return -1;
}


int timer_create(clockid_t clock_id, struct sigevent *evp, timer_t *timerid);

int timer_create(clockid_t clock_id, struct sigevent *evp, timer_t *timerid)
{
    return -1;
}


int timer_settime(timer_t timerid, int flags, const struct itimerspec *value,
    struct itimerspec *ovalue);

int timer_settime(timer_t timerid, int flags, const struct itimerspec *value,
    struct itimerspec *ovalue)
{
    return -1;
}


int timer_delete(timer_t timerid);

int timer_delete(timer_t timerid)
{
    return -1;
}

#endif


typedef struct {
    njt_uint_t  events;
} njt_eventport_conf_t;


static njt_int_t njt_eventport_init(njt_cycle_t *cycle, njt_msec_t timer);
static void njt_eventport_done(njt_cycle_t *cycle);
static njt_int_t njt_eventport_add_event(njt_event_t *ev, njt_int_t event,
    njt_uint_t flags);
static njt_int_t njt_eventport_del_event(njt_event_t *ev, njt_int_t event,
    njt_uint_t flags);
static njt_int_t njt_eventport_notify(njt_event_handler_pt handler);
static njt_int_t njt_eventport_process_events(njt_cycle_t *cycle,
    njt_msec_t timer, njt_uint_t flags);

static void *njt_eventport_create_conf(njt_cycle_t *cycle);
static char *njt_eventport_init_conf(njt_cycle_t *cycle, void *conf);

static int            ep = -1;
static port_event_t  *event_list;
static njt_uint_t     nevents;
static timer_t        event_timer = (timer_t) -1;
static njt_event_t    notify_event;

static njt_str_t      eventport_name = njt_string("eventport");


static njt_command_t  njt_eventport_commands[] = {

    { njt_string("eventport_events"),
      NJT_EVENT_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      0,
      offsetof(njt_eventport_conf_t, events),
      NULL },

      njt_null_command
};


static njt_event_module_t  njt_eventport_module_ctx = {
    &eventport_name,
    njt_eventport_create_conf,             /* create configuration */
    njt_eventport_init_conf,               /* init configuration */

    {
        njt_eventport_add_event,           /* add an event */
        njt_eventport_del_event,           /* delete an event */
        njt_eventport_add_event,           /* enable an event */
        njt_eventport_del_event,           /* disable an event */
        NULL,                              /* add an connection */
        NULL,                              /* delete an connection */
        njt_eventport_notify,              /* trigger a notify */
        njt_eventport_process_events,      /* process the events */
        njt_eventport_init,                /* init the events */
        njt_eventport_done,                /* done the events */
    }

};

njt_module_t  njt_eventport_module = {
    NJT_MODULE_V1,
    &njt_eventport_module_ctx,             /* module context */
    njt_eventport_commands,                /* module directives */
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
njt_eventport_init(njt_cycle_t *cycle, njt_msec_t timer)
{
    port_notify_t          pn;
    struct itimerspec      its;
    struct sigevent        sev;
    njt_eventport_conf_t  *epcf;

    epcf = njt_event_get_conf(cycle->conf_ctx, njt_eventport_module);

    if (ep == -1) {
        ep = port_create();

        if (ep == -1) {
            njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                          "port_create() failed");
            return NJT_ERROR;
        }

        notify_event.active = 1;
        notify_event.log = cycle->log;
    }

    if (nevents < epcf->events) {
        if (event_list) {
            njt_free(event_list);
        }

        event_list = njt_alloc(sizeof(port_event_t) * epcf->events,
                               cycle->log);
        if (event_list == NULL) {
            return NJT_ERROR;
        }
    }

    njt_event_flags = NJT_USE_EVENTPORT_EVENT;

    if (timer) {
        njt_memzero(&pn, sizeof(port_notify_t));
        pn.portnfy_port = ep;

        njt_memzero(&sev, sizeof(struct sigevent));
        sev.sigev_notify = SIGEV_PORT;
        sev.sigev_value.sival_ptr = &pn;

        if (timer_create(CLOCK_REALTIME, &sev, &event_timer) == -1) {
            njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                          "timer_create() failed");
            return NJT_ERROR;
        }

        its.it_interval.tv_sec = timer / 1000;
        its.it_interval.tv_nsec = (timer % 1000) * 1000000;
        its.it_value.tv_sec = timer / 1000;
        its.it_value.tv_nsec = (timer % 1000) * 1000000;

        if (timer_settime(event_timer, 0, &its, NULL) == -1) {
            njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                          "timer_settime() failed");
            return NJT_ERROR;
        }

        njt_event_flags |= NJT_USE_TIMER_EVENT;
    }

    nevents = epcf->events;

    njt_io = njt_os_io;

    njt_event_actions = njt_eventport_module_ctx.actions;

    return NJT_OK;
}


static void
njt_eventport_done(njt_cycle_t *cycle)
{
    if (event_timer != (timer_t) -1) {
        if (timer_delete(event_timer) == -1) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                          "timer_delete() failed");
        }

        event_timer = (timer_t) -1;
    }

    if (close(ep) == -1) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                      "close() event port failed");
    }

    ep = -1;

    njt_free(event_list);

    event_list = NULL;
    nevents = 0;
}


static njt_int_t
njt_eventport_add_event(njt_event_t *ev, njt_int_t event, njt_uint_t flags)
{
    njt_int_t          events, prev;
    njt_event_t       *e;
    njt_connection_t  *c;

    c = ev->data;

    events = event;

    if (event == NJT_READ_EVENT) {
        e = c->write;
        prev = POLLOUT;
#if (NJT_READ_EVENT != POLLIN)
        events = POLLIN;
#endif

    } else {
        e = c->read;
        prev = POLLIN;
#if (NJT_WRITE_EVENT != POLLOUT)
        events = POLLOUT;
#endif
    }

    if (e->oneshot) {
        events |= prev;
    }

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, ev->log, 0,
                   "eventport add event: fd:%d ev:%04Xi", c->fd, events);

    if (port_associate(ep, PORT_SOURCE_FD, c->fd, events,
                       (void *) ((uintptr_t) ev | ev->instance))
        == -1)
    {
        njt_log_error(NJT_LOG_ALERT, ev->log, njt_errno,
                      "port_associate() failed");
        return NJT_ERROR;
    }

    ev->active = 1;
    ev->oneshot = 1;

    return NJT_OK;
}


static njt_int_t
njt_eventport_del_event(njt_event_t *ev, njt_int_t event, njt_uint_t flags)
{
    njt_event_t       *e;
    njt_connection_t  *c;

    /*
     * when the file descriptor is closed, the event port automatically
     * dissociates it from the port, so we do not need to dissociate explicitly
     * the event before the closing the file descriptor
     */

    if (flags & NJT_CLOSE_EVENT) {
        ev->active = 0;
        ev->oneshot = 0;
        return NJT_OK;
    }

    c = ev->data;

    if (event == NJT_READ_EVENT) {
        e = c->write;
        event = POLLOUT;

    } else {
        e = c->read;
        event = POLLIN;
    }

    if (e->oneshot) {
        njt_log_debug2(NJT_LOG_DEBUG_EVENT, ev->log, 0,
                       "eventport change event: fd:%d ev:%04Xi", c->fd, event);

        if (port_associate(ep, PORT_SOURCE_FD, c->fd, event,
                           (void *) ((uintptr_t) ev | ev->instance))
            == -1)
        {
            njt_log_error(NJT_LOG_ALERT, ev->log, njt_errno,
                          "port_associate() failed");
            return NJT_ERROR;
        }

    } else if (ev->active) {
        njt_log_debug1(NJT_LOG_DEBUG_EVENT, ev->log, 0,
                       "eventport del event: fd:%d", c->fd);

        if (port_dissociate(ep, PORT_SOURCE_FD, c->fd) == -1) {
            njt_log_error(NJT_LOG_ALERT, ev->log, njt_errno,
                          "port_dissociate() failed");
            return NJT_ERROR;
        }
    }

    ev->active = 0;
    ev->oneshot = 0;

    return NJT_OK;
}


static njt_int_t
njt_eventport_notify(njt_event_handler_pt handler)
{
    notify_event.handler = handler;

    if (port_send(ep, 0, &notify_event) != 0) {
        njt_log_error(NJT_LOG_ALERT, notify_event.log, njt_errno,
                      "port_send() failed");
        return NJT_ERROR;
    }

    return NJT_OK;
}


static njt_int_t
njt_eventport_process_events(njt_cycle_t *cycle, njt_msec_t timer,
    njt_uint_t flags)
{
    int                 n, revents;
    u_int               events;
    njt_err_t           err;
    njt_int_t           instance;
    njt_uint_t          i, level;
    njt_event_t        *ev, *rev, *wev;
    njt_queue_t        *queue;
    njt_connection_t   *c;
    struct timespec     ts, *tp;

    if (timer == NJT_TIMER_INFINITE) {
        tp = NULL;

    } else {
        ts.tv_sec = timer / 1000;
        ts.tv_nsec = (timer % 1000) * 1000000;
        tp = &ts;
    }

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                   "eventport timer: %M", timer);

    events = 1;

    n = port_getn(ep, event_list, (u_int) nevents, &events, tp);

    err = njt_errno;

    if (flags & NJT_UPDATE_TIME) {
        njt_time_update();
    }

    if (n == -1) {
        if (err == ETIME) {
            if (timer != NJT_TIMER_INFINITE) {
                return NJT_OK;
            }

            njt_log_error(NJT_LOG_ALERT, cycle->log, 0,
                          "port_getn() returned no events without timeout");
            return NJT_ERROR;
        }

        level = (err == NJT_EINTR) ? NJT_LOG_INFO : NJT_LOG_ALERT;
        njt_log_error(level, cycle->log, err, "port_getn() failed");
        return NJT_ERROR;
    }

    if (events == 0) {
        if (timer != NJT_TIMER_INFINITE) {
            return NJT_OK;
        }

        njt_log_error(NJT_LOG_ALERT, cycle->log, 0,
                      "port_getn() returned no events without timeout");
        return NJT_ERROR;
    }

    for (i = 0; i < events; i++) {

        if (event_list[i].portev_source == PORT_SOURCE_TIMER) {
            njt_time_update();
            continue;
        }

        ev = event_list[i].portev_user;

        switch (event_list[i].portev_source) {

        case PORT_SOURCE_FD:

            instance = (uintptr_t) ev & 1;
            ev = (njt_event_t *) ((uintptr_t) ev & (uintptr_t) ~1);

            if (ev->closed || ev->instance != instance) {

                /*
                 * the stale event from a file descriptor
                 * that was just closed in this iteration
                 */

                njt_log_debug1(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                               "eventport: stale event %p", ev);
                continue;
            }

            revents = event_list[i].portev_events;

            njt_log_debug2(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                           "eventport: fd:%d, ev:%04Xd",
                           (int) event_list[i].portev_object, revents);

            if (revents & (POLLERR|POLLHUP|POLLNVAL)) {
                njt_log_debug2(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                               "port_getn() error fd:%d ev:%04Xd",
                               (int) event_list[i].portev_object, revents);
            }

            if (revents & ~(POLLIN|POLLOUT|POLLERR|POLLHUP|POLLNVAL)) {
                njt_log_error(NJT_LOG_ALERT, cycle->log, 0,
                              "strange port_getn() events fd:%d ev:%04Xd",
                              (int) event_list[i].portev_object, revents);
            }

            if (revents & (POLLERR|POLLHUP|POLLNVAL)) {

                /*
                 * if the error events were returned, add POLLIN and POLLOUT
                 * to handle the events at least in one active handler
                 */

                revents |= POLLIN|POLLOUT;
            }

            c = ev->data;
            rev = c->read;
            wev = c->write;

            rev->active = 0;
            wev->active = 0;

            if (revents & POLLIN) {
                rev->ready = 1;
                rev->available = -1;

                if (flags & NJT_POST_EVENTS) {
                    queue = rev->accept ? &njt_posted_accept_events
                                        : &njt_posted_events;

                    njt_post_event(rev, queue);

                } else {
                    rev->handler(rev);

                    if (ev->closed || ev->instance != instance) {
                        continue;
                    }
                }

                if (rev->accept) {
                    if (njt_use_accept_mutex) {
                        njt_accept_events = 1;
                        continue;
                    }

                    if (port_associate(ep, PORT_SOURCE_FD, c->fd, POLLIN,
                                       (void *) ((uintptr_t) ev | ev->instance))
                        == -1)
                    {
                        njt_log_error(NJT_LOG_ALERT, ev->log, njt_errno,
                                      "port_associate() failed");
                        return NJT_ERROR;
                    }
                }
            }

            if (revents & POLLOUT) {
                wev->ready = 1;

                if (flags & NJT_POST_EVENTS) {
                    njt_post_event(wev, &njt_posted_events);

                } else {
                    wev->handler(wev);
                }
            }

            continue;

        case PORT_SOURCE_USER:

            ev->handler(ev);

            continue;

        default:
            njt_log_error(NJT_LOG_ALERT, cycle->log, 0,
                          "unexpected eventport object %d",
                          (int) event_list[i].portev_object);
            continue;
        }
    }

    return NJT_OK;
}


static void *
njt_eventport_create_conf(njt_cycle_t *cycle)
{
    njt_eventport_conf_t  *epcf;

    epcf = njt_palloc(cycle->pool, sizeof(njt_eventport_conf_t));
    if (epcf == NULL) {
        return NULL;
    }

    epcf->events = NJT_CONF_UNSET;

    return epcf;
}


static char *
njt_eventport_init_conf(njt_cycle_t *cycle, void *conf)
{
    njt_eventport_conf_t *epcf = conf;

    njt_conf_init_uint_value(epcf->events, 32);

    return NJT_CONF_OK;
}
