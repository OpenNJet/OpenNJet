
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


#if (NJT_TEST_BUILD_EPOLL)

/* epoll declarations */

#define EPOLLIN        0x001
#define EPOLLPRI       0x002
#define EPOLLOUT       0x004
#define EPOLLERR       0x008
#define EPOLLHUP       0x010
#define EPOLLRDNORM    0x040
#define EPOLLRDBAND    0x080
#define EPOLLWRNORM    0x100
#define EPOLLWRBAND    0x200
#define EPOLLMSG       0x400

#define EPOLLRDHUP     0x2000

#define EPOLLEXCLUSIVE 0x10000000
#define EPOLLONESHOT   0x40000000
#define EPOLLET        0x80000000

#define EPOLL_CTL_ADD  1
#define EPOLL_CTL_DEL  2
#define EPOLL_CTL_MOD  3

typedef union epoll_data {
    void         *ptr;
    int           fd;
    uint32_t      u32;
    uint64_t      u64;
} epoll_data_t;

struct epoll_event {
    uint32_t      events;
    epoll_data_t  data;
};


int epoll_create(int size);

int epoll_create(int size)
{
    return -1;
}


int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    return -1;
}


int epoll_wait(int epfd, struct epoll_event *events, int nevents, int timeout);

int epoll_wait(int epfd, struct epoll_event *events, int nevents, int timeout)
{
    return -1;
}

#if (NJT_HAVE_EVENTFD)
#define SYS_eventfd       323
#endif

#if (NJT_HAVE_FILE_AIO)

#define SYS_io_setup      245
#define SYS_io_destroy    246
#define SYS_io_getevents  247

typedef u_int  aio_context_t;

struct io_event {
    uint64_t  data;  /* the data field from the iocb */
    uint64_t  obj;   /* what iocb this event came from */
    int64_t   res;   /* result code for this event */
    int64_t   res2;  /* secondary result */
};


#endif
#endif /* NJT_TEST_BUILD_EPOLL */


typedef struct {
    njt_uint_t  events;
    njt_uint_t  aio_requests;
} njt_epoll_conf_t;


static njt_int_t njt_epoll_init(njt_cycle_t *cycle, njt_msec_t timer);
#if (NJT_HAVE_EVENTFD)
static njt_int_t njt_epoll_notify_init(njt_log_t *log);
static void njt_epoll_notify_handler(njt_event_t *ev);
#endif
#if (NJT_HAVE_EPOLLRDHUP)
static void njt_epoll_test_rdhup(njt_cycle_t *cycle);
#endif
static void njt_epoll_done(njt_cycle_t *cycle);
static njt_int_t njt_epoll_add_event(njt_event_t *ev, njt_int_t event,
    njt_uint_t flags);
static njt_int_t njt_epoll_del_event(njt_event_t *ev, njt_int_t event,
    njt_uint_t flags);
static njt_int_t njt_epoll_add_connection(njt_connection_t *c);
static njt_int_t njt_epoll_del_connection(njt_connection_t *c,
    njt_uint_t flags);
#if (NJT_HAVE_EVENTFD)
static njt_int_t njt_epoll_notify(njt_event_handler_pt handler);
#endif
static njt_int_t njt_epoll_process_events(njt_cycle_t *cycle, njt_msec_t timer,
    njt_uint_t flags);

#if (NJT_HAVE_FILE_AIO)
static void njt_epoll_eventfd_handler(njt_event_t *ev);
#endif

static void *njt_epoll_create_conf(njt_cycle_t *cycle);
static char *njt_epoll_init_conf(njt_cycle_t *cycle, void *conf);

static int                  ep = -1;
static struct epoll_event  *event_list;
static njt_uint_t           nevents;

#if (NJT_HAVE_EVENTFD)
static int                  notify_fd = -1;
static njt_event_t          notify_event;
static njt_connection_t     notify_conn;
#endif

#if (NJT_HAVE_FILE_AIO)

int                         njt_eventfd = -1;
aio_context_t               njt_aio_ctx = 0;

static njt_event_t          njt_eventfd_event;
static njt_connection_t     njt_eventfd_conn;

#endif

#if (NJT_HAVE_EPOLLRDHUP)
njt_uint_t                  njt_use_epoll_rdhup;
#endif

static njt_str_t      epoll_name = njt_string("epoll");

static njt_command_t  njt_epoll_commands[] = {

    { njt_string("epoll_events"),
      NJT_EVENT_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      0,
      offsetof(njt_epoll_conf_t, events),
      NULL },

    { njt_string("worker_aio_requests"),
      NJT_EVENT_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      0,
      offsetof(njt_epoll_conf_t, aio_requests),
      NULL },

      njt_null_command
};


static njt_event_module_t  njt_epoll_module_ctx = {
    &epoll_name,
    njt_epoll_create_conf,               /* create configuration */
    njt_epoll_init_conf,                 /* init configuration */

    {
        njt_epoll_add_event,             /* add an event */
        njt_epoll_del_event,             /* delete an event */
        njt_epoll_add_event,             /* enable an event */
        njt_epoll_del_event,             /* disable an event */
        njt_epoll_add_connection,        /* add an connection */
        njt_epoll_del_connection,        /* delete an connection */
#if (NJT_HAVE_EVENTFD)
        njt_epoll_notify,                /* trigger a notify */
#else
        NULL,                            /* trigger a notify */
#endif
        njt_epoll_process_events,        /* process the events */
        njt_epoll_init,                  /* init the events */
        njt_epoll_done,                  /* done the events */
    }
};

njt_module_t  njt_epoll_module = {
    NJT_MODULE_V1,
    &njt_epoll_module_ctx,               /* module context */
    njt_epoll_commands,                  /* module directives */
    NJT_EVENT_MODULE,                    /* module type */
    NULL,                                /* init master */
    NULL,                                /* init module */
    NULL,                                /* init process */
    NULL,                                /* init thread */
    NULL,                                /* exit thread */
    NULL,                                /* exit process */
    NULL,                                /* exit master */
    NJT_MODULE_V1_PADDING
};


#if (NJT_HAVE_FILE_AIO)

/*
 * We call io_setup(), io_destroy() io_submit(), and io_getevents() directly
 * as syscalls instead of libaio usage, because the library header file
 * supports eventfd() since 0.3.107 version only.
 */

static int
io_setup(u_int nr_reqs, aio_context_t *ctx)
{
    return syscall(SYS_io_setup, nr_reqs, ctx);
}


static int
io_destroy(aio_context_t ctx)
{
    return syscall(SYS_io_destroy, ctx);
}


static int
io_getevents(aio_context_t ctx, long min_nr, long nr, struct io_event *events,
    struct timespec *tmo)
{
    return syscall(SYS_io_getevents, ctx, min_nr, nr, events, tmo);
}


static void
njt_epoll_aio_init(njt_cycle_t *cycle, njt_epoll_conf_t *epcf)
{
    int                 n;
    struct epoll_event  ee;

#if (NJT_HAVE_SYS_EVENTFD_H)
    njt_eventfd = eventfd(0, 0);
#else
    njt_eventfd = syscall(SYS_eventfd, 0);
#endif

    if (njt_eventfd == -1) {
        njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                      "eventfd() failed");
        njt_file_aio = 0;
        return;
    }

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                   "eventfd: %d", njt_eventfd);

    n = 1;

    if (ioctl(njt_eventfd, FIONBIO, &n) == -1) {
        njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                      "ioctl(eventfd, FIONBIO) failed");
        goto failed;
    }

    if (io_setup(epcf->aio_requests, &njt_aio_ctx) == -1) {
        njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                      "io_setup() failed");
        goto failed;
    }

    njt_eventfd_event.data = &njt_eventfd_conn;
    njt_eventfd_event.handler = njt_epoll_eventfd_handler;
    njt_eventfd_event.log = cycle->log;
    njt_eventfd_event.active = 1;
    njt_eventfd_conn.fd = njt_eventfd;
    njt_eventfd_conn.read = &njt_eventfd_event;
    njt_eventfd_conn.log = cycle->log;

    ee.events = EPOLLIN|EPOLLET;
    ee.data.ptr = &njt_eventfd_conn;

    if (epoll_ctl(ep, EPOLL_CTL_ADD, njt_eventfd, &ee) != -1) {
        return;
    }

    njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                  "epoll_ctl(EPOLL_CTL_ADD, eventfd) failed");

    if (io_destroy(njt_aio_ctx) == -1) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                      "io_destroy() failed");
    }

failed:

    if (close(njt_eventfd) == -1) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                      "eventfd close() failed");
    }

    njt_eventfd = -1;
    njt_aio_ctx = 0;
    njt_file_aio = 0;
}

#endif


static njt_int_t
njt_epoll_init(njt_cycle_t *cycle, njt_msec_t timer)
{
    njt_epoll_conf_t  *epcf;

    epcf = njt_event_get_conf(cycle->conf_ctx, njt_epoll_module);

    if (ep == -1) {
        ep = epoll_create(cycle->connection_n / 2);

        if (ep == -1) {
            njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                          "epoll_create() failed");
            return NJT_ERROR;
        }

#if (NJT_HAVE_EVENTFD)
        if (njt_epoll_notify_init(cycle->log) != NJT_OK) {
            njt_epoll_module_ctx.actions.notify = NULL;
        }
#endif

#if (NJT_HAVE_FILE_AIO)
        njt_epoll_aio_init(cycle, epcf);
#endif

#if (NJT_HAVE_EPOLLRDHUP)
        njt_epoll_test_rdhup(cycle);
#endif
    }

    if (nevents < epcf->events) {
        if (event_list) {
            njt_free(event_list);
        }

        event_list = njt_alloc(sizeof(struct epoll_event) * epcf->events,
                               cycle->log);
        if (event_list == NULL) {
            return NJT_ERROR;
        }
    }

    nevents = epcf->events;

    njt_io = njt_os_io;

    njt_event_actions = njt_epoll_module_ctx.actions;

#if (NJT_HAVE_CLEAR_EVENT)
    njt_event_flags = NJT_USE_CLEAR_EVENT
#else
    njt_event_flags = NJT_USE_LEVEL_EVENT
#endif
                      |NJT_USE_GREEDY_EVENT
                      |NJT_USE_EPOLL_EVENT;

    return NJT_OK;
}


#if (NJT_HAVE_EVENTFD)

static njt_int_t
njt_epoll_notify_init(njt_log_t *log)
{
    struct epoll_event  ee;

#if (NJT_HAVE_SYS_EVENTFD_H)
    notify_fd = eventfd(0, 0);
#else
    notify_fd = syscall(SYS_eventfd, 0);
#endif

    if (notify_fd == -1) {
        njt_log_error(NJT_LOG_EMERG, log, njt_errno, "eventfd() failed");
        return NJT_ERROR;
    }

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, log, 0,
                   "notify eventfd: %d", notify_fd);

    notify_event.handler = njt_epoll_notify_handler;
    notify_event.log = log;
    notify_event.active = 1;

    notify_conn.fd = notify_fd;
    notify_conn.read = &notify_event;
    notify_conn.log = log;

    ee.events = EPOLLIN|EPOLLET;
    ee.data.ptr = &notify_conn;

    if (epoll_ctl(ep, EPOLL_CTL_ADD, notify_fd, &ee) == -1) {
        njt_log_error(NJT_LOG_EMERG, log, njt_errno,
                      "epoll_ctl(EPOLL_CTL_ADD, eventfd) failed");

        if (close(notify_fd) == -1) {
            njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                            "eventfd close() failed");
        }

        return NJT_ERROR;
    }

    return NJT_OK;
}


static void
njt_epoll_notify_handler(njt_event_t *ev)
{
    ssize_t               n;
    uint64_t              count;
    njt_err_t             err;
    njt_event_handler_pt  handler;

    if (++ev->index == NJT_MAX_UINT32_VALUE) {
        ev->index = 0;

        n = read(notify_fd, &count, sizeof(uint64_t));

        err = njt_errno;

        njt_log_debug3(NJT_LOG_DEBUG_EVENT, ev->log, 0,
                       "read() eventfd %d: %z count:%uL", notify_fd, n, count);

        if ((size_t) n != sizeof(uint64_t)) {
            njt_log_error(NJT_LOG_ALERT, ev->log, err,
                          "read() eventfd %d failed", notify_fd);
        }
    }

    handler = ev->data;
    handler(ev);
}

#endif


#if (NJT_HAVE_EPOLLRDHUP)

static void
njt_epoll_test_rdhup(njt_cycle_t *cycle)
{
    int                 s[2], events;
    struct epoll_event  ee;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, s) == -1) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                      "socketpair() failed");
        return;
    }

    ee.events = EPOLLET|EPOLLIN|EPOLLRDHUP;

    if (epoll_ctl(ep, EPOLL_CTL_ADD, s[0], &ee) == -1) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                      "epoll_ctl() failed");
        goto failed;
    }

    if (close(s[1]) == -1) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                      "close() failed");
        s[1] = -1;
        goto failed;
    }

    s[1] = -1;

    events = epoll_wait(ep, &ee, 1, 5000);

    if (events == -1) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                      "epoll_wait() failed");
        goto failed;
    }

    if (events) {
        njt_use_epoll_rdhup = ee.events & EPOLLRDHUP;

    } else {
        njt_log_error(NJT_LOG_ALERT, cycle->log, NJT_ETIMEDOUT,
                      "epoll_wait() timed out");
    }

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                   "testing the EPOLLRDHUP flag: %s",
                   njt_use_epoll_rdhup ? "success" : "fail");

failed:

    if (s[1] != -1 && close(s[1]) == -1) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                      "close() failed");
    }

    if (close(s[0]) == -1) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                      "close() failed");
    }
}

#endif


static void
njt_epoll_done(njt_cycle_t *cycle)
{
    if (close(ep) == -1) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                      "epoll close() failed");
    }

    ep = -1;

#if (NJT_HAVE_EVENTFD)

    if (close(notify_fd) == -1) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                      "eventfd close() failed");
    }

    notify_fd = -1;

#endif

#if (NJT_HAVE_FILE_AIO)

    if (njt_eventfd != -1) {

        if (io_destroy(njt_aio_ctx) == -1) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                          "io_destroy() failed");
        }

        if (close(njt_eventfd) == -1) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                          "eventfd close() failed");
        }

        njt_eventfd = -1;
    }

    njt_aio_ctx = 0;

#endif

    njt_free(event_list);

    event_list = NULL;
    nevents = 0;
}


static njt_int_t
njt_epoll_add_event(njt_event_t *ev, njt_int_t event, njt_uint_t flags)
{
    int                  op;
    uint32_t             events, prev;
    njt_event_t         *e;
    njt_connection_t    *c;
    struct epoll_event   ee;

    c = ev->data;

    events = (uint32_t) event;

    if (event == NJT_READ_EVENT) {
        e = c->write;
        prev = EPOLLOUT;
#if (NJT_READ_EVENT != EPOLLIN|EPOLLRDHUP)
        events = EPOLLIN|EPOLLRDHUP;
#endif

    } else {
        e = c->read;
        prev = EPOLLIN|EPOLLRDHUP;
#if (NJT_WRITE_EVENT != EPOLLOUT)
        events = EPOLLOUT;
#endif
    }

    if (e->active) {
        op = EPOLL_CTL_MOD;
        events |= prev;

    } else {
        op = EPOLL_CTL_ADD;
    }

#if (NJT_HAVE_EPOLLEXCLUSIVE && NJT_HAVE_EPOLLRDHUP)
    if (flags & NJT_EXCLUSIVE_EVENT) {
        events &= ~EPOLLRDHUP;
    }
#endif

    ee.events = events | (uint32_t) flags;
    ee.data.ptr = (void *) ((uintptr_t) c | ev->instance);

    njt_log_debug3(NJT_LOG_DEBUG_EVENT, ev->log, 0,
                   "epoll add event: fd:%d op:%d ev:%08XD",
                   c->fd, op, ee.events);

    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        njt_log_error(NJT_LOG_ALERT, ev->log, njt_errno,
                      "epoll_ctl(%d, %d) failed", op, c->fd);
        return NJT_ERROR;
    }

    ev->active = 1;
#if 0
    ev->oneshot = (flags & NJT_ONESHOT_EVENT) ? 1 : 0;
#endif

    return NJT_OK;
}


static njt_int_t
njt_epoll_del_event(njt_event_t *ev, njt_int_t event, njt_uint_t flags)
{
    int                  op;
    uint32_t             prev;
    njt_event_t         *e;
    njt_connection_t    *c;
    struct epoll_event   ee;

    /*
     * when the file descriptor is closed, the epoll automatically deletes
     * it from its queue, so we do not need to delete explicitly the event
     * before the closing the file descriptor
     */

    if (flags & NJT_CLOSE_EVENT) {
        ev->active = 0;
        return NJT_OK;
    }

    c = ev->data;

    if (event == NJT_READ_EVENT) {
        e = c->write;
        prev = EPOLLOUT;

    } else {
        e = c->read;
        prev = EPOLLIN|EPOLLRDHUP;
    }

    if (e->active) {
        op = EPOLL_CTL_MOD;
        ee.events = prev | (uint32_t) flags;
        ee.data.ptr = (void *) ((uintptr_t) c | ev->instance);

    } else {
        op = EPOLL_CTL_DEL;
        ee.events = 0;
        ee.data.ptr = NULL;
    }

    njt_log_debug3(NJT_LOG_DEBUG_EVENT, ev->log, 0,
                   "epoll del event: fd:%d op:%d ev:%08XD",
                   c->fd, op, ee.events);

    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        njt_log_error(NJT_LOG_ALERT, ev->log, njt_errno,
                      "epoll_ctl(%d, %d) failed", op, c->fd);
        return NJT_ERROR;
    }

    ev->active = 0;

    return NJT_OK;
}


static njt_int_t
njt_epoll_add_connection(njt_connection_t *c)
{
    struct epoll_event  ee;

    ee.events = EPOLLIN|EPOLLOUT|EPOLLET|EPOLLRDHUP;
    ee.data.ptr = (void *) ((uintptr_t) c | c->read->instance);

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "epoll add connection: fd:%d ev:%08XD", c->fd, ee.events);

    if (epoll_ctl(ep, EPOLL_CTL_ADD, c->fd, &ee) == -1) {
        njt_log_error(NJT_LOG_ALERT, c->log, njt_errno,
                      "epoll_ctl(EPOLL_CTL_ADD, %d) failed", c->fd);
        return NJT_ERROR;
    }

    c->read->active = 1;
    c->write->active = 1;

    return NJT_OK;
}


static njt_int_t
njt_epoll_del_connection(njt_connection_t *c, njt_uint_t flags)
{
    int                 op;
    struct epoll_event  ee;

    /*
     * when the file descriptor is closed the epoll automatically deletes
     * it from its queue so we do not need to delete explicitly the event
     * before the closing the file descriptor
     */

    if (flags & NJT_CLOSE_EVENT) {
        c->read->active = 0;
        c->write->active = 0;
        return NJT_OK;
    }

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "epoll del connection: fd:%d", c->fd);

    op = EPOLL_CTL_DEL;
    ee.events = 0;
    ee.data.ptr = NULL;

    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        njt_log_error(NJT_LOG_ALERT, c->log, njt_errno,
                      "epoll_ctl(%d, %d) failed", op, c->fd);
        return NJT_ERROR;
    }

    c->read->active = 0;
    c->write->active = 0;

    return NJT_OK;
}


#if (NJT_HAVE_EVENTFD)

static njt_int_t
njt_epoll_notify(njt_event_handler_pt handler)
{
    static uint64_t inc = 1;

    notify_event.data = handler;

    if ((size_t) write(notify_fd, &inc, sizeof(uint64_t)) != sizeof(uint64_t)) {
        njt_log_error(NJT_LOG_ALERT, notify_event.log, njt_errno,
                      "write() to eventfd %d failed", notify_fd);
        return NJT_ERROR;
    }

    return NJT_OK;
}

#endif


static njt_int_t
njt_epoll_process_events(njt_cycle_t *cycle, njt_msec_t timer, njt_uint_t flags)
{
    int                events;
    uint32_t           revents;
    njt_int_t          instance, i;
    njt_uint_t         level;
    njt_err_t          err;
    njt_event_t       *rev, *wev;
    njt_queue_t       *queue;
    njt_connection_t  *c;

    /* NJT_TIMER_INFINITE == INFTIM */

    // njt_log_debug1(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
    //                "epoll timer: %M", timer);

    events = epoll_wait(ep, event_list, (int) nevents, timer);

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

        njt_log_error(level, cycle->log, err, "epoll_wait() failed");
        return NJT_ERROR;
    }

    if (events == 0) {
        if (timer != NJT_TIMER_INFINITE) {
            return NJT_OK;
        }

        njt_log_error(NJT_LOG_ALERT, cycle->log, 0,
                      "epoll_wait() returned no events without timeout");
        return NJT_ERROR;
    }

    for (i = 0; i < events; i++) {
        c = event_list[i].data.ptr;

        instance = (uintptr_t) c & 1;
        c = (njt_connection_t *) ((uintptr_t) c & (uintptr_t) ~1);

        rev = c->read;

        if (c->fd == -1 || rev->instance != instance) {

            /*
             * the stale event from a file descriptor
             * that was just closed in this iteration
             */

            njt_log_debug1(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                           "epoll: stale event %p", c);
            continue;
        }

        revents = event_list[i].events;

        njt_log_debug3(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                       "epoll: fd:%d ev:%04XD d:%p",
                       c->fd, revents, event_list[i].data.ptr);

        if (revents & (EPOLLERR|EPOLLHUP)) {
            njt_log_debug2(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                           "epoll_wait() error on fd:%d ev:%04XD",
                           c->fd, revents);

            /*
             * if the error events were returned, add EPOLLIN and EPOLLOUT
             * to handle the events at least in one active handler
             */

            revents |= EPOLLIN|EPOLLOUT;
        }

#if 0
        if (revents & ~(EPOLLIN|EPOLLOUT|EPOLLERR|EPOLLHUP)) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, 0,
                          "strange epoll_wait() events fd:%d ev:%04XD",
                          c->fd, revents);
        }
#endif

        if ((revents & EPOLLIN) && rev->active) {

#if (NJT_HAVE_EPOLLRDHUP)
            if (revents & EPOLLRDHUP) {
                rev->pending_eof = 1;
            }
#endif

            rev->ready = 1;
            rev->available = -1;

            if (flags & NJT_POST_EVENTS) {
                queue = rev->accept ? &njt_posted_accept_events
                                    : &njt_posted_events;

                njt_post_event(rev, queue);

            } else {
                rev->handler(rev);
            }
        }

        wev = c->write;

        if ((revents & EPOLLOUT) && wev->active) {

            if (c->fd == -1 || wev->instance != instance) {

                /*
                 * the stale event from a file descriptor
                 * that was just closed in this iteration
                 */

                njt_log_debug1(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                               "epoll: stale event %p", c);
                continue;
            }

            wev->ready = 1;
#if (NJT_THREADS)
            wev->complete = 1;
#endif

            if (flags & NJT_POST_EVENTS) {
                njt_post_event(wev, &njt_posted_events);

            } else {
                wev->handler(wev);
            }
        }
    }

    return NJT_OK;
}


#if (NJT_HAVE_FILE_AIO)

static void
njt_epoll_eventfd_handler(njt_event_t *ev)
{
    int               n, events;
    long              i;
    uint64_t          ready;
    njt_err_t         err;
    njt_event_t      *e;
    njt_event_aio_t  *aio;
    struct io_event   event[64];
    struct timespec   ts;

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, ev->log, 0, "eventfd handler");

    n = read(njt_eventfd, &ready, 8);

    err = njt_errno;

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, ev->log, 0, "eventfd: %d", n);

    if (n != 8) {
        if (n == -1) {
            if (err == NJT_EAGAIN) {
                return;
            }

            njt_log_error(NJT_LOG_ALERT, ev->log, err, "read(eventfd) failed");
            return;
        }

        njt_log_error(NJT_LOG_ALERT, ev->log, 0,
                      "read(eventfd) returned only %d bytes", n);
        return;
    }

    ts.tv_sec = 0;
    ts.tv_nsec = 0;

    while (ready) {

        events = io_getevents(njt_aio_ctx, 1, 64, event, &ts);

        njt_log_debug1(NJT_LOG_DEBUG_EVENT, ev->log, 0,
                       "io_getevents: %d", events);

        if (events > 0) {
            ready -= events;

            for (i = 0; i < events; i++) {

                njt_log_debug4(NJT_LOG_DEBUG_EVENT, ev->log, 0,
                               "io_event: %XL %XL %L %L",
                                event[i].data, event[i].obj,
                                event[i].res, event[i].res2);

                e = (njt_event_t *) (uintptr_t) event[i].data;

                e->complete = 1;
                e->active = 0;
                e->ready = 1;

                aio = e->data;
                aio->res = event[i].res;

                njt_post_event(e, &njt_posted_events);
            }

            continue;
        }

        if (events == 0) {
            return;
        }

        /* events == -1 */
        njt_log_error(NJT_LOG_ALERT, ev->log, njt_errno,
                      "io_getevents() failed");
        return;
    }
}

#endif


static void *
njt_epoll_create_conf(njt_cycle_t *cycle)
{
    njt_epoll_conf_t  *epcf;

    epcf = njt_palloc(cycle->pool, sizeof(njt_epoll_conf_t));
    if (epcf == NULL) {
        return NULL;
    }

    epcf->events = NJT_CONF_UNSET;
    epcf->aio_requests = NJT_CONF_UNSET;

    return epcf;
}


static char *
njt_epoll_init_conf(njt_cycle_t *cycle, void *conf)
{
    njt_epoll_conf_t *epcf = conf;

    njt_conf_init_uint_value(epcf->events, 512);
    njt_conf_init_uint_value(epcf->aio_requests, 32);

    return NJT_CONF_OK;
}
