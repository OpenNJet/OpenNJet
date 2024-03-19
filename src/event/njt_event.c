
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


#define DEFAULT_CONNECTIONS  512


extern njt_module_t njt_kqueue_module;
extern njt_module_t njt_eventport_module;
extern njt_module_t njt_devpoll_module;
extern njt_module_t njt_epoll_module;
extern njt_module_t njt_select_module;


static char *njt_event_init_conf(njt_cycle_t *cycle, void *conf);
static njt_int_t njt_event_module_init(njt_cycle_t *cycle);
static njt_int_t njt_event_process_init(njt_cycle_t *cycle);
static char *njt_events_block(njt_conf_t *cf, njt_command_t *cmd, void *conf);

static char *njt_event_connections(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_event_use(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static char *njt_event_debug_connection(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);

static void *njt_event_core_create_conf(njt_cycle_t *cycle);
static char *njt_event_core_init_conf(njt_cycle_t *cycle, void *conf);


static njt_uint_t     njt_timer_resolution;
sig_atomic_t          njt_event_timer_alarm;

static njt_uint_t     njt_event_max_module;

njt_uint_t            njt_event_flags;
njt_event_actions_t   njt_event_actions;


static njt_atomic_t   connection_counter = 1;
njt_atomic_t         *njt_connection_counter = &connection_counter;


njt_atomic_t         *njt_accept_mutex_ptr;
njt_shmtx_t           njt_accept_mutex;
njt_uint_t            njt_use_accept_mutex;
njt_uint_t            njt_accept_events;
njt_uint_t            njt_accept_mutex_held;
njt_msec_t            njt_accept_mutex_delay;
njt_int_t             njt_accept_disabled;
njt_uint_t            njt_use_exclusive_accept;


#if (NJT_STAT_STUB)

static njt_atomic_t   njt_stat_accepted0;
njt_atomic_t         *njt_stat_accepted = &njt_stat_accepted0;
static njt_atomic_t   njt_stat_handled0;
njt_atomic_t         *njt_stat_handled = &njt_stat_handled0;
static njt_atomic_t   njt_stat_requests0;
njt_atomic_t         *njt_stat_requests = &njt_stat_requests0;
static njt_atomic_t   njt_stat_active0;
njt_atomic_t         *njt_stat_active = &njt_stat_active0;
static njt_atomic_t   njt_stat_reading0;
njt_atomic_t         *njt_stat_reading = &njt_stat_reading0;
static njt_atomic_t   njt_stat_writing0;
njt_atomic_t         *njt_stat_writing = &njt_stat_writing0;
static njt_atomic_t   njt_stat_waiting0;
njt_atomic_t         *njt_stat_waiting = &njt_stat_waiting0;

#endif



static njt_command_t  njt_events_commands[] = {

    { njt_string("events"),
      NJT_MAIN_CONF|NJT_CONF_BLOCK|NJT_CONF_NOARGS,
      njt_events_block,
      0,
      0,
      NULL },

      njt_null_command
};


static njt_core_module_t  njt_events_module_ctx = {
    njt_string("events"),
    NULL,
    njt_event_init_conf
};


njt_module_t  njt_events_module = {
    NJT_MODULE_V1,
    &njt_events_module_ctx,                /* module context */
    njt_events_commands,                   /* module directives */
    NJT_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};


static njt_str_t  event_core_name = njt_string("event_core");


static njt_command_t  njt_event_core_commands[] = {

    { njt_string("worker_connections"),
      NJT_EVENT_CONF|NJT_CONF_TAKE1,
      njt_event_connections,
      0,
      0,
      NULL },

    { njt_string("use"),
      NJT_EVENT_CONF|NJT_CONF_TAKE1,
      njt_event_use,
      0,
      0,
      NULL },

    { njt_string("multi_accept"),
      NJT_EVENT_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      0,
      offsetof(njt_event_conf_t, multi_accept),
      NULL },

    { njt_string("accept_mutex"),
      NJT_EVENT_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      0,
      offsetof(njt_event_conf_t, accept_mutex),
      NULL },

    { njt_string("accept_mutex_delay"),
      NJT_EVENT_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      0,
      offsetof(njt_event_conf_t, accept_mutex_delay),
      NULL },

    { njt_string("debug_connection"),
      NJT_EVENT_CONF|NJT_CONF_TAKE1,
      njt_event_debug_connection,
      0,
      0,
      NULL },

      njt_null_command
};


static njt_event_module_t  njt_event_core_module_ctx = {
    &event_core_name,
    njt_event_core_create_conf,            /* create configuration */
    njt_event_core_init_conf,              /* init configuration */

    { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL }
};


njt_module_t  njt_event_core_module = {
    NJT_MODULE_V1,
    &njt_event_core_module_ctx,            /* module context */
    njt_event_core_commands,               /* module directives */
    NJT_EVENT_MODULE,                      /* module type */
    NULL,                                  /* init master */
    njt_event_module_init,                 /* init module */
    njt_event_process_init,                /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};


void
njt_process_events_and_timers(njt_cycle_t *cycle)
{
    njt_uint_t  flags;
    njt_msec_t  timer, delta;

    njt_queue_t     *q; // openresty patch
    njt_event_t     *ev; // openresty patch

    if (njt_timer_resolution) {
        timer = NJT_TIMER_INFINITE;
        flags = 0;

    } else {
        timer = njt_event_find_timer();
        flags = NJT_UPDATE_TIME;

#if (NJT_WIN32)

        /* handle signals from master in case of network inactivity */

        if (timer == NJT_TIMER_INFINITE || timer > 500) {
            timer = 500;
        }

#endif
    }

    // openrestry patch
    if (!njt_queue_empty(&njt_posted_delayed_events)) {
        njt_log_debug0(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                       "posted delayed event queue not empty"
                       " making poll timeout 0");
        timer = 0;
    }
    // openresty patch end

    if (njt_use_accept_mutex) {
        if (njt_accept_disabled > 0) {
            njt_accept_disabled--;

        } else {
            if (njt_trylock_accept_mutex(cycle) == NJT_ERROR) {
                return;
            }

            if (njt_accept_mutex_held) {
                flags |= NJT_POST_EVENTS;

            } else {
                if (timer == NJT_TIMER_INFINITE
                    || timer > njt_accept_mutex_delay)
                {
                    timer = njt_accept_mutex_delay;
                }
            }
        }
    }

    if (!njt_queue_empty(&njt_posted_next_events)) {
        njt_event_move_posted_next(cycle);
        timer = 0;
    }

    delta = njt_current_msec;

    (void) njt_process_events(cycle, timer, flags);

    delta = njt_current_msec - delta;

    // njt_log_debug1(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
    //                "timer delta: %M", delta);

    njt_event_process_posted(cycle, &njt_posted_accept_events);

    if (njt_accept_mutex_held) {
        njt_shmtx_unlock(&njt_accept_mutex);
    }

    njt_event_expire_timers();

    njt_event_process_posted(cycle, &njt_posted_events);

    // openresty patch
    while (!njt_queue_empty(&njt_posted_delayed_events)) {
        q = njt_queue_head(&njt_posted_delayed_events);

        ev = njt_queue_data(q, njt_event_t, queue);
        if (ev->delayed) {
            /* start of newly inserted nodes */
            for (/* void */;
                 q != njt_queue_sentinel(&njt_posted_delayed_events);
                 q = njt_queue_next(q))
            {
                ev = njt_queue_data(q, njt_event_t, queue);
                ev->delayed = 0;

                njt_log_debug1(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                               "skipping delayed posted event %p,"
                               " till next iteration", ev);
            }

            break;
        }

        njt_log_debug1(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                       "delayed posted event %p", ev);

        njt_delete_posted_event(ev);

        ev->handler(ev);
    }
    // openresty patch end

}


njt_int_t
njt_handle_read_event(njt_event_t *rev, njt_uint_t flags)
{
#if (NJT_QUIC)

    njt_connection_t  *c;

    c = rev->data;

    if (c->quic) {
        return NJT_OK;
    }

#endif

    if (njt_event_flags & NJT_USE_CLEAR_EVENT) {

        /* kqueue, epoll */

        if (!rev->active && !rev->ready) {
            if (njt_add_event(rev, NJT_READ_EVENT, NJT_CLEAR_EVENT)
                == NJT_ERROR)
            {
                return NJT_ERROR;
            }
        }

        return NJT_OK;

    } else if (njt_event_flags & NJT_USE_LEVEL_EVENT) {

        /* select, poll, /dev/poll */

        if (!rev->active && !rev->ready) {
            if (njt_add_event(rev, NJT_READ_EVENT, NJT_LEVEL_EVENT)
                == NJT_ERROR)
            {
                return NJT_ERROR;
            }

            return NJT_OK;
        }

        if (rev->active && (rev->ready || (flags & NJT_CLOSE_EVENT))) {
            if (njt_del_event(rev, NJT_READ_EVENT, NJT_LEVEL_EVENT | flags)
                == NJT_ERROR)
            {
                return NJT_ERROR;
            }

            return NJT_OK;
        }

    } else if (njt_event_flags & NJT_USE_EVENTPORT_EVENT) {

        /* event ports */

        if (!rev->active && !rev->ready) {
            if (njt_add_event(rev, NJT_READ_EVENT, 0) == NJT_ERROR) {
                return NJT_ERROR;
            }

            return NJT_OK;
        }

        if (rev->oneshot && rev->ready) {
            if (njt_del_event(rev, NJT_READ_EVENT, 0) == NJT_ERROR) {
                return NJT_ERROR;
            }

            return NJT_OK;
        }
    }

    /* iocp */

    return NJT_OK;
}


njt_int_t
njt_handle_write_event(njt_event_t *wev, size_t lowat)
{
    njt_connection_t  *c;

    c = wev->data;

#if (NJT_QUIC)
    if (c->quic) {
        return NJT_OK;
    }
#endif

    if (lowat) {
        if (njt_send_lowat(c, lowat) == NJT_ERROR) {
            return NJT_ERROR;
        }
    }

    if (njt_event_flags & NJT_USE_CLEAR_EVENT) {

        /* kqueue, epoll */

        if (!wev->active && !wev->ready) {
            if (njt_add_event(wev, NJT_WRITE_EVENT,
                              NJT_CLEAR_EVENT | (lowat ? NJT_LOWAT_EVENT : 0))
                == NJT_ERROR)
            {
                return NJT_ERROR;
            }
        }

        return NJT_OK;

    } else if (njt_event_flags & NJT_USE_LEVEL_EVENT) {

        /* select, poll, /dev/poll */

        if (!wev->active && !wev->ready) {
            if (njt_add_event(wev, NJT_WRITE_EVENT, NJT_LEVEL_EVENT)
                == NJT_ERROR)
            {
                return NJT_ERROR;
            }

            return NJT_OK;
        }

        if (wev->active && wev->ready) {
            if (njt_del_event(wev, NJT_WRITE_EVENT, NJT_LEVEL_EVENT)
                == NJT_ERROR)
            {
                return NJT_ERROR;
            }

            return NJT_OK;
        }

    } else if (njt_event_flags & NJT_USE_EVENTPORT_EVENT) {

        /* event ports */

        if (!wev->active && !wev->ready) {
            if (njt_add_event(wev, NJT_WRITE_EVENT, 0) == NJT_ERROR) {
                return NJT_ERROR;
            }

            return NJT_OK;
        }

        if (wev->oneshot && wev->ready) {
            if (njt_del_event(wev, NJT_WRITE_EVENT, 0) == NJT_ERROR) {
                return NJT_ERROR;
            }

            return NJT_OK;
        }
    }

    /* iocp */

    return NJT_OK;
}


static char *
njt_event_init_conf(njt_cycle_t *cycle, void *conf)
{
#if (NJT_HAVE_REUSEPORT)
    njt_uint_t        i;
    njt_core_conf_t  *ccf;
    njt_listening_t  *ls;
#endif

    if (njt_get_conf(cycle->conf_ctx, njt_events_module) == NULL) {
        njt_log_error(NJT_LOG_EMERG, cycle->log, 0,
                      "no \"events\" section in configuration");
        return NJT_CONF_ERROR;
    }

    if (cycle->connection_n < cycle->listening.nelts + 1) {

        /*
         * there should be at least one connection for each listening
         * socket, plus an additional connection for channel
         */

        njt_log_error(NJT_LOG_EMERG, cycle->log, 0,
                      "%ui worker_connections are not enough "
                      "for %ui listening sockets",
                      cycle->connection_n, cycle->listening.nelts);

        return NJT_CONF_ERROR;
    }

#if (NJT_HAVE_REUSEPORT)

    ccf = (njt_core_conf_t *) njt_get_conf(cycle->conf_ctx, njt_core_module);

    if (!njt_test_config && ccf->master) {

        ls = cycle->listening.elts;
        for (i = 0; i < cycle->listening.nelts; i++) {

            if (!ls[i].reuseport || ls[i].worker != 0) {
                continue;
            }

            if (njt_clone_listening(cycle, &ls[i]) != NJT_OK) {
                return NJT_CONF_ERROR;
            }

            /* cloning may change cycle->listening.elts */

            ls = cycle->listening.elts;
        }
    }

#endif

    return NJT_CONF_OK;
}


static njt_int_t
njt_event_module_init(njt_cycle_t *cycle)
{
    void              ***cf;
    u_char              *shared;
    size_t               size, cl;
    njt_shm_t            shm;
    njt_time_t          *tp;
    njt_core_conf_t     *ccf;
    njt_event_conf_t    *ecf;

    cf = njt_get_conf(cycle->conf_ctx, njt_events_module);
    ecf = (*cf)[njt_event_core_module.ctx_index];

    if (!njt_test_config && njt_process <= NJT_PROCESS_MASTER) {
        njt_log_error(NJT_LOG_NOTICE, cycle->log, 0,
                      "using the \"%s\" event method", ecf->name);
    }

    ccf = (njt_core_conf_t *) njt_get_conf(cycle->conf_ctx, njt_core_module);

    njt_timer_resolution = ccf->timer_resolution;

#if !(NJT_WIN32)
    {
    njt_int_t      limit;
    struct rlimit  rlmt;

    if (getrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                      "getrlimit(RLIMIT_NOFILE) failed, ignored");

    } else {
        if (ecf->connections > (njt_uint_t) rlmt.rlim_cur
            && (ccf->rlimit_nofile == NJT_CONF_UNSET
                || ecf->connections > (njt_uint_t) ccf->rlimit_nofile))
        {
            limit = (ccf->rlimit_nofile == NJT_CONF_UNSET) ?
                         (njt_int_t) rlmt.rlim_cur : ccf->rlimit_nofile;

            njt_log_error(NJT_LOG_WARN, cycle->log, 0,
                          "%ui worker_connections exceed "
                          "open file resource limit: %i",
                          ecf->connections, limit);
        }
    }
    }
#endif /* !(NJT_WIN32) */


    if (ccf->master == 0) {
        return NJT_OK;
    }

    if (njt_accept_mutex_ptr) {
        return NJT_OK;
    }


    /* cl should be equal to or greater than cache line size */

    cl = 128;

    size = cl            /* njt_accept_mutex */
           + cl          /* njt_connection_counter */
           + cl;         /* njt_temp_number */

#if (NJT_STAT_STUB)

    size += cl           /* njt_stat_accepted */
           + cl          /* njt_stat_handled */
           + cl          /* njt_stat_requests */
           + cl          /* njt_stat_active */
           + cl          /* njt_stat_reading */
           + cl          /* njt_stat_writing */
           + cl;         /* njt_stat_waiting */

#endif

    shm.size = size;
    njt_str_set(&shm.name, "njet_shared_zone");
    shm.log = cycle->log;

    if (njt_shm_alloc(&shm) != NJT_OK) {
        return NJT_ERROR;
    }

    shared = shm.addr;

    njt_accept_mutex_ptr = (njt_atomic_t *) shared;
    njt_accept_mutex.spin = (njt_uint_t) -1;

    if (njt_shmtx_create(&njt_accept_mutex, (njt_shmtx_sh_t *) shared,
                         cycle->lock_file.data)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    njt_connection_counter = (njt_atomic_t *) (shared + 1 * cl);

    (void) njt_atomic_cmp_set(njt_connection_counter, 0, 1);

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                   "counter: %p, %uA",
                   njt_connection_counter, *njt_connection_counter);

    njt_temp_number = (njt_atomic_t *) (shared + 2 * cl);

    tp = njt_timeofday();

    njt_random_number = (tp->msec << 16) + njt_pid;

#if (NJT_STAT_STUB)

    njt_stat_accepted = (njt_atomic_t *) (shared + 3 * cl);
    njt_stat_handled = (njt_atomic_t *) (shared + 4 * cl);
    njt_stat_requests = (njt_atomic_t *) (shared + 5 * cl);
    njt_stat_active = (njt_atomic_t *) (shared + 6 * cl);
    njt_stat_reading = (njt_atomic_t *) (shared + 7 * cl);
    njt_stat_writing = (njt_atomic_t *) (shared + 8 * cl);
    njt_stat_waiting = (njt_atomic_t *) (shared + 9 * cl);

#endif

    return NJT_OK;
}


#if !(NJT_WIN32)

static void
njt_timer_signal_handler(int signo)
{
    njt_event_timer_alarm = 1;

#if 1
    njt_log_debug0(NJT_LOG_DEBUG_EVENT, njt_cycle->log, 0, "timer signal");
#endif
}

#endif


static njt_int_t
njt_event_process_init(njt_cycle_t *cycle)
{
    njt_uint_t           m, i;
    njt_event_t         *rev, *wev;
    njt_listening_t     *ls;
    njt_connection_t    *c, *next, *old;
    njt_core_conf_t     *ccf;
    njt_event_conf_t    *ecf;
    njt_event_module_t  *module;

    ccf = (njt_core_conf_t *) njt_get_conf(cycle->conf_ctx, njt_core_module);
    ecf = njt_event_get_conf(cycle->conf_ctx, njt_event_core_module);

    if (ccf->master && ccf->worker_processes > 1 && ecf->accept_mutex) {
        njt_use_accept_mutex = 1;
        njt_accept_mutex_held = 0;
        njt_accept_mutex_delay = ecf->accept_mutex_delay;

    } else {
        njt_use_accept_mutex = 0;
    }

#if (NJT_WIN32)

    /*
     * disable accept mutex on win32 as it may cause deadlock if
     * grabbed by a process which can't accept connections
     */

    njt_use_accept_mutex = 0;

#endif

    njt_use_exclusive_accept = 0;

    njt_queue_init(&njt_posted_accept_events);
    njt_queue_init(&njt_posted_next_events);
    njt_queue_init(&njt_posted_events);
    njt_queue_init(&njt_posted_delayed_events); // openresty patch

    if (njt_event_timer_init(cycle->log) == NJT_ERROR) {
        return NJT_ERROR;
    }

    for (m = 0; cycle->modules[m]; m++) {
        if (cycle->modules[m]->type != NJT_EVENT_MODULE) {
            continue;
        }

        if (cycle->modules[m]->ctx_index != ecf->use) {
            continue;
        }

        module = cycle->modules[m]->ctx;

        if (module->actions.init(cycle, njt_timer_resolution) != NJT_OK) {
            /* fatal */
            exit(2);
        }

        break;
    }

#if !(NJT_WIN32)

    if (njt_timer_resolution && !(njt_event_flags & NJT_USE_TIMER_EVENT)) {
        struct sigaction  sa;
        struct itimerval  itv;

        njt_memzero(&sa, sizeof(struct sigaction));
        sa.sa_handler = njt_timer_signal_handler;
        sigemptyset(&sa.sa_mask);

        if (sigaction(SIGALRM, &sa, NULL) == -1) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                          "sigaction(SIGALRM) failed");
            return NJT_ERROR;
        }

        itv.it_interval.tv_sec = njt_timer_resolution / 1000;
        itv.it_interval.tv_usec = (njt_timer_resolution % 1000) * 1000;
        itv.it_value.tv_sec = njt_timer_resolution / 1000;
        itv.it_value.tv_usec = (njt_timer_resolution % 1000 ) * 1000;

        if (setitimer(ITIMER_REAL, &itv, NULL) == -1) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                          "setitimer() failed");
        }
    }

    if (njt_event_flags & NJT_USE_FD_EVENT) {
        struct rlimit  rlmt;

        if (getrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                          "getrlimit(RLIMIT_NOFILE) failed");
            return NJT_ERROR;
        }

        cycle->files_n = (njt_uint_t) rlmt.rlim_cur;

        cycle->files = njt_calloc(sizeof(njt_connection_t *) * cycle->files_n,
                                  cycle->log);
        if (cycle->files == NULL) {
            return NJT_ERROR;
        }
    }

#else

    if (njt_timer_resolution && !(njt_event_flags & NJT_USE_TIMER_EVENT)) {
        njt_log_error(NJT_LOG_WARN, cycle->log, 0,
                      "the \"timer_resolution\" directive is not supported "
                      "with the configured event method, ignored");
        njt_timer_resolution = 0;
    }

#endif

    cycle->connections =
        njt_alloc(sizeof(njt_connection_t) * cycle->connection_n, cycle->log);
    if (cycle->connections == NULL) {
        return NJT_ERROR;
    }

    c = cycle->connections;

    cycle->read_events = njt_alloc(sizeof(njt_event_t) * cycle->connection_n,
                                   cycle->log);
    if (cycle->read_events == NULL) {
        return NJT_ERROR;
    }

    rev = cycle->read_events;
    for (i = 0; i < cycle->connection_n; i++) {
        rev[i].closed = 1;
        rev[i].instance = 1;
    }

    cycle->write_events = njt_alloc(sizeof(njt_event_t) * cycle->connection_n,
                                    cycle->log);
    if (cycle->write_events == NULL) {
        return NJT_ERROR;
    }

    wev = cycle->write_events;
    for (i = 0; i < cycle->connection_n; i++) {
        wev[i].closed = 1;
    }

    i = cycle->connection_n;
    next = NULL;

    do {
        i--;

        c[i].data = next;
        c[i].read = &cycle->read_events[i];
        c[i].write = &cycle->write_events[i];
        c[i].fd = (njt_socket_t) -1;

        next = &c[i];
    } while (i);

    cycle->free_connections = next;
    cycle->free_connection_n = cycle->connection_n;

    /* for each listening socket */

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {

#if (NJT_HAVE_REUSEPORT)
        if (ls[i].reuseport && ls[i].worker != njt_worker) {
            // openresty patch
            njt_log_debug2(NJT_LOG_DEBUG_CORE, cycle->log, 0,
                           "closing unused fd:%d listening on %V",
                           ls[i].fd, &ls[i].addr_text);

            if (njt_close_socket(ls[i].fd) == -1) {
                njt_log_error(NJT_LOG_EMERG, cycle->log, njt_socket_errno,
                              njt_close_socket_n " %V failed",
                              &ls[i].addr_text);
            }

            ls[i].fd = (njt_socket_t) -1;
            // openresty patch end

            continue;
        }
#endif

        c = njt_get_connection(ls[i].fd, cycle->log);

        if (c == NULL) {
            return NJT_ERROR;
        }

        c->type = ls[i].type;
        c->log = &ls[i].log;
        c->listening = &ls[i];
        ls[i].connection = c;

        rev = c->read;

        rev->log = c->log;
        rev->accept = 1;

#if (NJT_HAVE_DEFERRED_ACCEPT)
        rev->deferred_accept = ls[i].deferred_accept;
#endif

        if (!(njt_event_flags & NJT_USE_IOCP_EVENT)
            && cycle->old_cycle)
        {
            if (ls[i].previous) {

                /*
                 * delete the old accept events that were bound to
                 * the old cycle read events array
                 */

                old = ls[i].previous->connection;

                if (njt_del_event(old->read, NJT_READ_EVENT, NJT_CLOSE_EVENT)
                    == NJT_ERROR)
                {
                    return NJT_ERROR;
                }

                old->fd = (njt_socket_t) -1;
            }
        }

#if (NJT_WIN32)

        if (njt_event_flags & NJT_USE_IOCP_EVENT) {
            njt_iocp_conf_t  *iocpcf;

            rev->handler = njt_event_acceptex;

            if (njt_use_accept_mutex) {
                continue;
            }

            if (njt_add_event(rev, 0, NJT_IOCP_ACCEPT) == NJT_ERROR) {
                return NJT_ERROR;
            }

            ls[i].log.handler = njt_acceptex_log_error;

            iocpcf = njt_event_get_conf(cycle->conf_ctx, njt_iocp_module);
            if (njt_event_post_acceptex(&ls[i], iocpcf->post_acceptex)
                == NJT_ERROR)
            {
                return NJT_ERROR;
            }

        } else {
            rev->handler = njt_event_accept;

            if (njt_use_accept_mutex) {
                continue;
            }

            if (njt_add_event(rev, NJT_READ_EVENT, 0) == NJT_ERROR) {
                return NJT_ERROR;
            }
        }

#else

        if (c->type == SOCK_STREAM) {
            rev->handler = njt_event_accept;

#if (NJT_QUIC)
        } else if (ls[i].quic) {
            rev->handler = njt_quic_recvmsg;
#endif
        } else {
            rev->handler = njt_event_recvmsg;
        }

#if (NJT_HAVE_REUSEPORT)

        if (ls[i].reuseport) {
            if (njt_add_event(rev, NJT_READ_EVENT, 0) == NJT_ERROR) {
                return NJT_ERROR;
            }

            continue;
        }

#endif

        if (njt_use_accept_mutex) {
            continue;
        }

#if (NJT_HAVE_EPOLLEXCLUSIVE)

        if ((njt_event_flags & NJT_USE_EPOLL_EVENT)
            && ccf->worker_processes > 1)
        {
            njt_use_exclusive_accept = 1;

            if (njt_add_event(rev, NJT_READ_EVENT, NJT_EXCLUSIVE_EVENT)
                == NJT_ERROR)
            {
                return NJT_ERROR;
            }

            continue;
        }

#endif

        if (njt_add_event(rev, NJT_READ_EVENT, 0) == NJT_ERROR) {
            return NJT_ERROR;
        }

#endif

    }

    return NJT_OK;
}


njt_int_t
njt_send_lowat(njt_connection_t *c, size_t lowat)
{
    int  sndlowat;

#if (NJT_HAVE_LOWAT_EVENT)

    if (njt_event_flags & NJT_USE_KQUEUE_EVENT) {
        c->write->available = lowat;
        return NJT_OK;
    }

#endif

    if (lowat == 0 || c->sndlowat) {
        return NJT_OK;
    }

    sndlowat = (int) lowat;

    if (setsockopt(c->fd, SOL_SOCKET, SO_SNDLOWAT,
                   (const void *) &sndlowat, sizeof(int))
        == -1)
    {
        njt_connection_error(c, njt_socket_errno,
                             "setsockopt(SO_SNDLOWAT) failed");
        return NJT_ERROR;
    }

    c->sndlowat = 1;

    return NJT_OK;
}


static char *
njt_events_block(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char                 *rv;
    void               ***ctx;
    njt_uint_t            i;
    njt_conf_t            pcf;
    njt_event_module_t   *m;

    if (*(void **) conf) {
        return "is duplicate";
    }

    /* count the number of the event modules and set up their indices */

    njt_event_max_module = njt_count_modules(cf->cycle, NJT_EVENT_MODULE);

    ctx = njt_pcalloc(cf->pool, sizeof(void *));
    if (ctx == NULL) {
        return NJT_CONF_ERROR;
    }

    *ctx = njt_pcalloc(cf->pool, njt_event_max_module * sizeof(void *));
    if (*ctx == NULL) {
        return NJT_CONF_ERROR;
    }

    *(void **) conf = ctx;

    for (i = 0; cf->cycle->modules[i]; i++) {
        if (cf->cycle->modules[i]->type != NJT_EVENT_MODULE) {
            continue;
        }

        m = cf->cycle->modules[i]->ctx;

        if (m->create_conf) {
            (*ctx)[cf->cycle->modules[i]->ctx_index] =
                                                     m->create_conf(cf->cycle);
            if ((*ctx)[cf->cycle->modules[i]->ctx_index] == NULL) {
                return NJT_CONF_ERROR;
            }
        }
    }

    pcf = *cf;
    cf->ctx = ctx;
    cf->module_type = NJT_EVENT_MODULE;
    cf->cmd_type = NJT_EVENT_CONF;

    rv = njt_conf_parse(cf, NULL);

    *cf = pcf;

    if (rv != NJT_CONF_OK) {
        return rv;
    }

    for (i = 0; cf->cycle->modules[i]; i++) {
        if (cf->cycle->modules[i]->type != NJT_EVENT_MODULE) {
            continue;
        }

        m = cf->cycle->modules[i]->ctx;

        if (m->init_conf) {
            rv = m->init_conf(cf->cycle,
                              (*ctx)[cf->cycle->modules[i]->ctx_index]);
            if (rv != NJT_CONF_OK) {
                return rv;
            }
        }
    }

    return NJT_CONF_OK;
}


static char *
njt_event_connections(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_event_conf_t  *ecf = conf;

    njt_str_t  *value;

    if (ecf->connections != NJT_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;
    ecf->connections = njt_atoi(value[1].data, value[1].len);
    if (ecf->connections == (njt_uint_t) NJT_ERROR) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid number \"%V\"", &value[1]);

        return NJT_CONF_ERROR;
    }

    cf->cycle->connection_n = ecf->connections;

    return NJT_CONF_OK;
}


static char *
njt_event_use(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_event_conf_t  *ecf = conf;

    njt_int_t             m;
    njt_str_t            *value;
    njt_event_conf_t     *old_ecf;
    njt_event_module_t   *module;

    if (ecf->use != NJT_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cf->cycle->old_cycle->conf_ctx) {
        old_ecf = njt_event_get_conf(cf->cycle->old_cycle->conf_ctx,
                                     njt_event_core_module);
    } else {
        old_ecf = NULL;
    }


    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NJT_EVENT_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;
        if (module->name->len == value[1].len) {
            if (njt_strcmp(module->name->data, value[1].data) == 0) {
                ecf->use = cf->cycle->modules[m]->ctx_index;
                ecf->name = module->name->data;

                if (njt_process == NJT_PROCESS_SINGLE
                    && old_ecf
                    && old_ecf->use != ecf->use)
                {
                    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "when the server runs without a master process "
                               "the \"%V\" event type must be the same as "
                               "in previous configuration - \"%s\" "
                               "and it cannot be changed on the fly, "
                               "to change it you need to stop server "
                               "and start it again",
                               &value[1], old_ecf->name);

                    return NJT_CONF_ERROR;
                }

                return NJT_CONF_OK;
            }
        }
    }

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "invalid event type \"%V\"", &value[1]);

    return NJT_CONF_ERROR;
}


static char *
njt_event_debug_connection(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
#if (NJT_DEBUG)
    njt_event_conf_t  *ecf = conf;

    njt_int_t             rc;
    njt_str_t            *value;
    njt_url_t             u;
    njt_cidr_t            c, *cidr;
    njt_uint_t            i;
    struct sockaddr_in   *sin;
#if (NJT_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    value = cf->args->elts;

#if (NJT_HAVE_UNIX_DOMAIN)

    if (njt_strcmp(value[1].data, "unix:") == 0) {
        cidr = njt_array_push(&ecf->debug_connection);
        if (cidr == NULL) {
            return NJT_CONF_ERROR;
        }

        cidr->family = AF_UNIX;
        return NJT_CONF_OK;
    }

#endif

    rc = njt_ptocidr(&value[1], &c);

    if (rc != NJT_ERROR) {
        if (rc == NJT_DONE) {
            njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                               "low address bits of %V are meaningless",
                               &value[1]);
        }

        cidr = njt_array_push(&ecf->debug_connection);
        if (cidr == NULL) {
            return NJT_CONF_ERROR;
        }

        *cidr = c;

        return NJT_CONF_OK;
    }

    njt_memzero(&u, sizeof(njt_url_t));
    u.host = value[1];

    if (njt_inet_resolve_host(cf->pool, &u) != NJT_OK) {
        if (u.err) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "%s in debug_connection \"%V\"",
                               u.err, &u.host);
        }

        return NJT_CONF_ERROR;
    }

    cidr = njt_array_push_n(&ecf->debug_connection, u.naddrs);
    if (cidr == NULL) {
        return NJT_CONF_ERROR;
    }

    njt_memzero(cidr, u.naddrs * sizeof(njt_cidr_t));

    for (i = 0; i < u.naddrs; i++) {
        cidr[i].family = u.addrs[i].sockaddr->sa_family;

        switch (cidr[i].family) {

#if (NJT_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) u.addrs[i].sockaddr;
            cidr[i].u.in6.addr = sin6->sin6_addr;
            njt_memset(cidr[i].u.in6.mask.s6_addr, 0xff, 16);
            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) u.addrs[i].sockaddr;
            cidr[i].u.in.addr = sin->sin_addr.s_addr;
            cidr[i].u.in.mask = 0xffffffff;
            break;
        }
    }

#else

    njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                       "\"debug_connection\" is ignored, you need to rebuild "
                       "njet using --with-debug option to enable it");

#endif

    return NJT_CONF_OK;
}


static void *
njt_event_core_create_conf(njt_cycle_t *cycle)
{
    njt_event_conf_t  *ecf;

    ecf = njt_palloc(cycle->pool, sizeof(njt_event_conf_t));
    if (ecf == NULL) {
        return NULL;
    }

    ecf->connections = NJT_CONF_UNSET_UINT;
    ecf->use = NJT_CONF_UNSET_UINT;
    ecf->multi_accept = NJT_CONF_UNSET;
    ecf->accept_mutex = NJT_CONF_UNSET;
    ecf->accept_mutex_delay = NJT_CONF_UNSET_MSEC;
    ecf->name = (void *) NJT_CONF_UNSET;

#if (NJT_DEBUG)

    if (njt_array_init(&ecf->debug_connection, cycle->pool, 4,
                       sizeof(njt_cidr_t)) == NJT_ERROR)
    {
        return NULL;
    }

#endif

    return ecf;
}


static char *
njt_event_core_init_conf(njt_cycle_t *cycle, void *conf)
{
    njt_event_conf_t  *ecf = conf;

#if (NJT_HAVE_EPOLL) && !(NJT_TEST_BUILD_EPOLL)
    int                  fd;
#endif
    njt_int_t            i;
    njt_module_t        *module;
    njt_event_module_t  *event_module;

    module = NULL;

#if (NJT_HAVE_EPOLL) && !(NJT_TEST_BUILD_EPOLL)

    fd = epoll_create(100);

    if (fd != -1) {
        (void) close(fd);
        module = &njt_epoll_module;

    } else if (njt_errno != NJT_ENOSYS) {
        module = &njt_epoll_module;
    }

#endif

#if (NJT_HAVE_DEVPOLL) && !(NJT_TEST_BUILD_DEVPOLL)

    module = &njt_devpoll_module;

#endif

#if (NJT_HAVE_KQUEUE)

    module = &njt_kqueue_module;

#endif

#if (NJT_HAVE_SELECT)

    if (module == NULL) {
        module = &njt_select_module;
    }

#endif

    if (module == NULL) {
        for (i = 0; cycle->modules[i]; i++) {

            if (cycle->modules[i]->type != NJT_EVENT_MODULE) {
                continue;
            }

            event_module = cycle->modules[i]->ctx;

            if (njt_strcmp(event_module->name->data, event_core_name.data) == 0)
            {
                continue;
            }

            module = cycle->modules[i];
            break;
        }
    }

    if (module == NULL) {
        njt_log_error(NJT_LOG_EMERG, cycle->log, 0, "no events module found");
        return NJT_CONF_ERROR;
    }

    njt_conf_init_uint_value(ecf->connections, DEFAULT_CONNECTIONS);
    cycle->connection_n = ecf->connections;

    njt_conf_init_uint_value(ecf->use, module->ctx_index);

    event_module = module->ctx;
    njt_conf_init_ptr_value(ecf->name, event_module->name->data);

    njt_conf_init_value(ecf->multi_accept, 0);
    njt_conf_init_value(ecf->accept_mutex, 0);
    njt_conf_init_msec_value(ecf->accept_mutex_delay, 500);

    return NJT_CONF_OK;
}
void
njt_show_listening_sockets(njt_cycle_t *cycle)
{
    njt_uint_t         i;
    njt_listening_t   *ls;



    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {

 	njt_log_error(NJT_LOG_EMERG, cycle->log, 0, "njt_show_listening_sockets listening=%p,ls=%p,servers=%p",ls,&ls[i],ls[i].servers);       
    }

}
