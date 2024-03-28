
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_EVENT_H_INCLUDED_
#define _NJT_EVENT_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


#define NJT_INVALID_INDEX  0xd0d0d0d0

//add by clb, support ipv6 udp traffic hack
#ifndef IPV6_ORIGDSTADDR
#define IPV6_ORIGDSTADDR        74
#endif

#ifndef IPV6_RECVORIGDSTADDR
#define IPV6_RECVORIGDSTADDR    IPV6_ORIGDSTADDR
#endif

#ifndef IPV6_TRANSPARENT
#define IPV6_TRANSPARENT        75
#endif
//end add by clb

#if (NJT_HAVE_IOCP)

typedef struct {
    WSAOVERLAPPED    ovlp;
    njt_event_t     *event;
    int              error;
} njt_event_ovlp_t;

#endif


struct njt_event_s {
    void            *data;

    unsigned         write:1;

    unsigned         accept:1;

    /* used to detect the stale events in kqueue and epoll */
    unsigned         instance:1;

    /*
     * the event was passed or would be passed to a kernel;
     * in aio mode - operation was posted.
     */
    unsigned         active:1;

    unsigned         disabled:1;

    /* the ready event; in aio mode 0 means that no operation can be posted */
    unsigned         ready:1;

    unsigned         oneshot:1;

    /* aio operation is complete */
    unsigned         complete:1;

    unsigned         eof:1;
    unsigned         error:1;

    unsigned         timedout:1;
    unsigned         timer_set:1;

    unsigned         delayed:1;

    unsigned         deferred_accept:1;

    /* the pending eof reported by kqueue, epoll or in aio chain operation */
    unsigned         pending_eof:1;

    unsigned         posted:1;

    unsigned         closed:1;

    /* to test on worker exit */
    unsigned         channel:1;
    unsigned         resolver:1;

#if (HAVE_SOCKET_CLOEXEC_PATCH) // openresty patch
    unsigned         skip_socket_leak_check:1;
#endif // openresty patch end

    unsigned         cancelable:1;

#if (NJT_HAVE_KQUEUE)
    unsigned         kq_vnode:1;

    /* the pending errno reported by kqueue */
    int              kq_errno;
#endif

    /*
     * kqueue only:
     *   accept:     number of sockets that wait to be accepted
     *   read:       bytes to read when event is ready
     *               or lowat when event is set with NJT_LOWAT_EVENT flag
     *   write:      available space in buffer when event is ready
     *               or lowat when event is set with NJT_LOWAT_EVENT flag
     *
     * iocp: TODO
     *
     * otherwise:
     *   accept:     1 if accept many, 0 otherwise
     *   read:       bytes to read when event is ready, -1 if not known
     */

    int              available;

    njt_event_handler_pt  handler;


#if (NJT_HAVE_IOCP)
    njt_event_ovlp_t ovlp;
#endif

    njt_uint_t       index;

    njt_log_t       *log;

    njt_rbtree_node_t   timer;

    /* the posted queue */
    njt_queue_t      queue;

#if 0

    /* the threads support */

    /*
     * the event thread context, we store it here
     * if $(CC) does not understand __thread declaration
     * and pthread_getspecific() is too costly
     */

    void            *thr_ctx;

#if (NJT_EVENT_T_PADDING)

    /* event should not cross cache line in SMP */

    uint32_t         padding[NJT_EVENT_T_PADDING];
#endif
#endif
};


#if (NJT_HAVE_FILE_AIO)

struct njt_event_aio_s {
    void                      *data;
    njt_event_handler_pt       handler;
    njt_file_t                *file;

    njt_fd_t                   fd;

#if (NJT_HAVE_EVENTFD)
    int64_t                    res;
#endif

#if !(NJT_HAVE_EVENTFD) || (NJT_TEST_BUILD_EPOLL)
    njt_err_t                  err;
    size_t                     nbytes;
#endif

    njt_aiocb_t                aiocb;
    njt_event_t                event;
};

#endif


typedef struct {
    njt_int_t  (*add)(njt_event_t *ev, njt_int_t event, njt_uint_t flags);
    njt_int_t  (*del)(njt_event_t *ev, njt_int_t event, njt_uint_t flags);

    njt_int_t  (*enable)(njt_event_t *ev, njt_int_t event, njt_uint_t flags);
    njt_int_t  (*disable)(njt_event_t *ev, njt_int_t event, njt_uint_t flags);

    njt_int_t  (*add_conn)(njt_connection_t *c);
    njt_int_t  (*del_conn)(njt_connection_t *c, njt_uint_t flags);

    njt_int_t  (*notify)(njt_event_handler_pt handler);

    njt_int_t  (*process_events)(njt_cycle_t *cycle, njt_msec_t timer,
                                 njt_uint_t flags);

    njt_int_t  (*init)(njt_cycle_t *cycle, njt_msec_t timer);
    void       (*done)(njt_cycle_t *cycle);
} njt_event_actions_t;


extern njt_event_actions_t   njt_event_actions;
#if (NJT_HAVE_EPOLLRDHUP)
extern njt_uint_t            njt_use_epoll_rdhup;
#endif


/*
 * The event filter requires to read/write the whole data:
 * select, poll, /dev/poll, kqueue, epoll.
 */
#define NJT_USE_LEVEL_EVENT      0x00000001

/*
 * The event filter is deleted after a notification without an additional
 * syscall: kqueue, epoll.
 */
#define NJT_USE_ONESHOT_EVENT    0x00000002

/*
 * The event filter notifies only the changes and an initial level:
 * kqueue, epoll.
 */
#define NJT_USE_CLEAR_EVENT      0x00000004

/*
 * The event filter has kqueue features: the eof flag, errno,
 * available data, etc.
 */
#define NJT_USE_KQUEUE_EVENT     0x00000008

/*
 * The event filter supports low water mark: kqueue's NOTE_LOWAT.
 * kqueue in FreeBSD 4.1-4.2 has no NOTE_LOWAT so we need a separate flag.
 */
#define NJT_USE_LOWAT_EVENT      0x00000010

/*
 * The event filter requires to do i/o operation until EAGAIN: epoll.
 */
#define NJT_USE_GREEDY_EVENT     0x00000020

/*
 * The event filter is epoll.
 */
#define NJT_USE_EPOLL_EVENT      0x00000040

/*
 * Obsolete.
 */
#define NJT_USE_RTSIG_EVENT      0x00000080

/*
 * Obsolete.
 */
#define NJT_USE_AIO_EVENT        0x00000100

/*
 * Need to add socket or handle only once: i/o completion port.
 */
#define NJT_USE_IOCP_EVENT       0x00000200

/*
 * The event filter has no opaque data and requires file descriptors table:
 * poll, /dev/poll.
 */
#define NJT_USE_FD_EVENT         0x00000400

/*
 * The event module handles periodic or absolute timer event by itself:
 * kqueue in FreeBSD 4.4, NetBSD 2.0, and MacOSX 10.4, Solaris 10's event ports.
 */
#define NJT_USE_TIMER_EVENT      0x00000800

/*
 * All event filters on file descriptor are deleted after a notification:
 * Solaris 10's event ports.
 */
#define NJT_USE_EVENTPORT_EVENT  0x00001000

/*
 * The event filter support vnode notifications: kqueue.
 */
#define NJT_USE_VNODE_EVENT      0x00002000


/*
 * The event filter is deleted just before the closing file.
 * Has no meaning for select and poll.
 * kqueue, epoll, eventport:         allows to avoid explicit delete,
 *                                   because filter automatically is deleted
 *                                   on file close,
 *
 * /dev/poll:                        we need to flush POLLREMOVE event
 *                                   before closing file.
 */
#define NJT_CLOSE_EVENT    1

/*
 * disable temporarily event filter, this may avoid locks
 * in kernel malloc()/free(): kqueue.
 */
#define NJT_DISABLE_EVENT  2

/*
 * event must be passed to kernel right now, do not wait until batch processing.
 */
#define NJT_FLUSH_EVENT    4


/* these flags have a meaning only for kqueue */
#define NJT_LOWAT_EVENT    0
#define NJT_VNODE_EVENT    0


#if (NJT_HAVE_EPOLL) && !(NJT_HAVE_EPOLLRDHUP)
#define EPOLLRDHUP         0
#endif


#if (NJT_HAVE_KQUEUE)

#define NJT_READ_EVENT     EVFILT_READ
#define NJT_WRITE_EVENT    EVFILT_WRITE

#undef  NJT_VNODE_EVENT
#define NJT_VNODE_EVENT    EVFILT_VNODE

/*
 * NJT_CLOSE_EVENT, NJT_LOWAT_EVENT, and NJT_FLUSH_EVENT are the module flags
 * and they must not go into a kernel so we need to choose the value
 * that must not interfere with any existent and future kqueue flags.
 * kqueue has such values - EV_FLAG1, EV_EOF, and EV_ERROR:
 * they are reserved and cleared on a kernel entrance.
 */
#undef  NJT_CLOSE_EVENT
#define NJT_CLOSE_EVENT    EV_EOF

#undef  NJT_LOWAT_EVENT
#define NJT_LOWAT_EVENT    EV_FLAG1

#undef  NJT_FLUSH_EVENT
#define NJT_FLUSH_EVENT    EV_ERROR

#define NJT_LEVEL_EVENT    0
#define NJT_ONESHOT_EVENT  EV_ONESHOT
#define NJT_CLEAR_EVENT    EV_CLEAR

#undef  NJT_DISABLE_EVENT
#define NJT_DISABLE_EVENT  EV_DISABLE


#elif (NJT_HAVE_DEVPOLL && !(NJT_TEST_BUILD_DEVPOLL)) \
      || (NJT_HAVE_EVENTPORT && !(NJT_TEST_BUILD_EVENTPORT))

#define NJT_READ_EVENT     POLLIN
#define NJT_WRITE_EVENT    POLLOUT

#define NJT_LEVEL_EVENT    0
#define NJT_ONESHOT_EVENT  1


#elif (NJT_HAVE_EPOLL) && !(NJT_TEST_BUILD_EPOLL)

#define NJT_READ_EVENT     (EPOLLIN|EPOLLRDHUP)
#define NJT_WRITE_EVENT    EPOLLOUT

#define NJT_LEVEL_EVENT    0
#define NJT_CLEAR_EVENT    EPOLLET
#define NJT_ONESHOT_EVENT  0x70000000
#if 0
#define NJT_ONESHOT_EVENT  EPOLLONESHOT
#endif

#if (NJT_HAVE_EPOLLEXCLUSIVE)
#define NJT_EXCLUSIVE_EVENT  EPOLLEXCLUSIVE
#endif

#elif (NJT_HAVE_POLL)

#define NJT_READ_EVENT     POLLIN
#define NJT_WRITE_EVENT    POLLOUT

#define NJT_LEVEL_EVENT    0
#define NJT_ONESHOT_EVENT  1


#else /* select */

#define NJT_READ_EVENT     0
#define NJT_WRITE_EVENT    1

#define NJT_LEVEL_EVENT    0
#define NJT_ONESHOT_EVENT  1

#endif /* NJT_HAVE_KQUEUE */


#if (NJT_HAVE_IOCP)
#define NJT_IOCP_ACCEPT      0
#define NJT_IOCP_IO          1
#define NJT_IOCP_CONNECT     2
#endif


#if (NJT_TEST_BUILD_EPOLL)
#define NJT_EXCLUSIVE_EVENT  0
#endif


#ifndef NJT_CLEAR_EVENT
#define NJT_CLEAR_EVENT    0    /* dummy declaration */
#endif


#define njt_process_events   njt_event_actions.process_events
#define njt_done_events      njt_event_actions.done

#define njt_add_event        njt_event_actions.add
#define njt_del_event        njt_event_actions.del
#define njt_add_conn         njt_event_actions.add_conn
#define njt_del_conn         njt_event_actions.del_conn

#define njt_notify           njt_event_actions.notify

#define njt_add_timer        njt_event_add_timer
#define njt_del_timer        njt_event_del_timer


extern njt_os_io_t  njt_io;

#define njt_recv             njt_io.recv
#define njt_recv_chain       njt_io.recv_chain
#define njt_udp_recv         njt_io.udp_recv
#define njt_send             njt_io.send
#define njt_send_chain       njt_io.send_chain
#define njt_udp_send         njt_io.udp_send
#define njt_udp_send_chain   njt_io.udp_send_chain


#define NJT_EVENT_MODULE      0x544E5645  /* "EVNT" */
#define NJT_EVENT_CONF        0x02000000


typedef struct {
    njt_uint_t    connections;
    njt_uint_t    use;

    njt_flag_t    multi_accept;
    njt_flag_t    accept_mutex;

    njt_msec_t    accept_mutex_delay;

    u_char       *name;

#if (NJT_DEBUG)
    njt_array_t   debug_connection;
#endif
} njt_event_conf_t;


typedef struct {
    njt_str_t              *name;

    void                 *(*create_conf)(njt_cycle_t *cycle);
    char                 *(*init_conf)(njt_cycle_t *cycle, void *conf);

    njt_event_actions_t     actions;
} njt_event_module_t;


extern njt_atomic_t          *njt_connection_counter;

extern njt_atomic_t          *njt_accept_mutex_ptr;
extern njt_shmtx_t            njt_accept_mutex;
extern njt_uint_t             njt_use_accept_mutex;
extern njt_uint_t             njt_accept_events;
extern njt_uint_t             njt_accept_mutex_held;
extern njt_msec_t             njt_accept_mutex_delay;
extern njt_int_t              njt_accept_disabled;
extern njt_uint_t             njt_use_exclusive_accept;


#if (NJT_STAT_STUB)

extern njt_atomic_t  *njt_stat_accepted;
extern njt_atomic_t  *njt_stat_handled;
extern njt_atomic_t  *njt_stat_requests;
extern njt_atomic_t  *njt_stat_active;
extern njt_atomic_t  *njt_stat_reading;
extern njt_atomic_t  *njt_stat_writing;
extern njt_atomic_t  *njt_stat_waiting;

#endif


#define NJT_UPDATE_TIME         1
#define NJT_POST_EVENTS         2


extern sig_atomic_t           njt_event_timer_alarm;
extern njt_uint_t             njt_event_flags;
extern njt_module_t           njt_events_module;
extern njt_module_t           njt_event_core_module;


#define njt_event_get_conf(conf_ctx, module)                                  \
             (*(njt_get_conf(conf_ctx, njt_events_module))) [module.ctx_index]



void njt_event_accept(njt_event_t *ev);
njt_int_t njt_trylock_accept_mutex(njt_cycle_t *cycle);
njt_int_t njt_enable_accept_events(njt_cycle_t *cycle);
u_char *njt_accept_log_error(njt_log_t *log, u_char *buf, size_t len);
#if (NJT_DEBUG)
void njt_debug_accepted_connection(njt_event_conf_t *ecf, njt_connection_t *c);
#endif


void njt_process_events_and_timers(njt_cycle_t *cycle);
njt_int_t njt_handle_read_event(njt_event_t *rev, njt_uint_t flags);
njt_int_t njt_handle_write_event(njt_event_t *wev, size_t lowat);


#if (NJT_WIN32)
void njt_event_acceptex(njt_event_t *ev);
njt_int_t njt_event_post_acceptex(njt_listening_t *ls, njt_uint_t n);
u_char *njt_acceptex_log_error(njt_log_t *log, u_char *buf, size_t len);
#endif


njt_int_t njt_send_lowat(njt_connection_t *c, size_t lowat);


/* used in njt_log_debugX() */
#define njt_event_ident(p)  ((njt_connection_t *) (p))->fd


#include <njt_event_timer.h>
#include <njt_event_posted.h>
#include <njt_event_udp.h>

#if (NJT_WIN32)
#include <njt_iocp_module.h>
#endif


#endif /* _NJT_EVENT_H_INCLUDED_ */
