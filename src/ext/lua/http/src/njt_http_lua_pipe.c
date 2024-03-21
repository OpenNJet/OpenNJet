
/*
 * Copyright (C) by OpenResty Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_http_lua_common.h"
#include "njt_http_lua_input_filters.h"
#include "njt_http_lua_util.h"
#include "njt_http_lua_pipe.h"
#if (NJT_HTTP_LUA_HAVE_SIGNALFD)
#include <sys/signalfd.h>
#endif


#ifdef HAVE_NJT_LUA_PIPE
static njt_rbtree_node_t *njt_http_lua_pipe_lookup_pid(njt_rbtree_key_t key);
#if !(NJT_HTTP_LUA_HAVE_SIGNALFD)
static void njt_http_lua_pipe_sigchld_handler(int signo, siginfo_t *siginfo,
    void *ucontext);
#endif
static void njt_http_lua_pipe_sigchld_event_handler(njt_event_t *ev);
static ssize_t njt_http_lua_pipe_fd_read(njt_connection_t *c, u_char *buf,
    size_t size);
static ssize_t njt_http_lua_pipe_fd_write(njt_connection_t *c, u_char *buf,
    size_t size);
static void njt_http_lua_pipe_close_helper(njt_http_lua_pipe_t *pipe,
    njt_http_lua_pipe_ctx_t *pipe_ctx, njt_event_t *ev);
static void njt_http_lua_pipe_close_stdin(njt_http_lua_pipe_t *pipe);
static void njt_http_lua_pipe_close_stdout(njt_http_lua_pipe_t *pipe);
static void njt_http_lua_pipe_close_stderr(njt_http_lua_pipe_t *pipe);
static void njt_http_lua_pipe_proc_finalize(njt_http_lua_ffi_pipe_proc_t *proc);
static njt_int_t njt_http_lua_pipe_get_lua_ctx(njt_http_request_t *r,
    njt_http_lua_ctx_t **ctx, u_char *errbuf, size_t *errbuf_size);
static void njt_http_lua_pipe_put_error(njt_http_lua_pipe_ctx_t *pipe_ctx,
    u_char *errbuf, size_t *errbuf_size);
static void njt_http_lua_pipe_put_data(njt_http_lua_pipe_t *pipe,
    njt_http_lua_pipe_ctx_t *pipe_ctx, u_char **buf, size_t *buf_size);
static njt_int_t njt_http_lua_pipe_add_input_buffer(njt_http_lua_pipe_t *pipe,
    njt_http_lua_pipe_ctx_t *pipe_ctx);
static njt_int_t njt_http_lua_pipe_read_all(void *data, ssize_t bytes);
static njt_int_t njt_http_lua_pipe_read_bytes(void *data, ssize_t bytes);
static njt_int_t njt_http_lua_pipe_read_line(void *data, ssize_t bytes);
static njt_int_t njt_http_lua_pipe_read_any(void *data, ssize_t bytes);
static njt_int_t njt_http_lua_pipe_read(njt_http_lua_pipe_t *pipe,
    njt_http_lua_pipe_ctx_t *pipe_ctx);
static njt_int_t njt_http_lua_pipe_init_ctx(
    njt_http_lua_pipe_ctx_t **pipe_ctx_pt, int fd, njt_pool_t *pool,
    u_char *errbuf, size_t *errbuf_size);
static njt_int_t njt_http_lua_pipe_write(njt_http_lua_pipe_t *pipe,
    njt_http_lua_pipe_ctx_t *pipe_ctx);
static int njt_http_lua_pipe_read_stdout_retval(
    njt_http_lua_ffi_pipe_proc_t *proc, lua_State *L);
static int njt_http_lua_pipe_read_stderr_retval(
    njt_http_lua_ffi_pipe_proc_t *proc, lua_State *L);
static int njt_http_lua_pipe_read_retval_helper(
    njt_http_lua_ffi_pipe_proc_t *proc, lua_State *L, int from_stderr);
static int njt_http_lua_pipe_write_retval(njt_http_lua_ffi_pipe_proc_t *proc,
    lua_State *L);
static int njt_http_lua_pipe_wait_retval(njt_http_lua_ffi_pipe_proc_t *proc,
    lua_State *L);
static void njt_http_lua_pipe_resume_helper(njt_event_t *ev,
    njt_http_lua_co_ctx_t *wait_co_ctx);
static void njt_http_lua_pipe_resume_read_stdout_handler(njt_event_t *ev);
static void njt_http_lua_pipe_resume_read_stderr_handler(njt_event_t *ev);
static void njt_http_lua_pipe_resume_write_handler(njt_event_t *ev);
static void njt_http_lua_pipe_resume_wait_handler(njt_event_t *ev);
static njt_int_t njt_http_lua_pipe_resume(njt_http_request_t *r);
static void njt_http_lua_pipe_dummy_event_handler(njt_event_t *ev);
static void njt_http_lua_pipe_clear_event(njt_event_t *ev);
static void njt_http_lua_pipe_proc_read_stdout_cleanup(void *data);
static void njt_http_lua_pipe_proc_read_stderr_cleanup(void *data);
static void njt_http_lua_pipe_proc_write_cleanup(void *data);
static void njt_http_lua_pipe_proc_wait_cleanup(void *data);
static void njt_http_lua_pipe_reap_pids(njt_event_t *ev);
static void njt_http_lua_pipe_reap_timer_handler(njt_event_t *ev);
void njt_http_lua_ffi_pipe_proc_destroy(
    njt_http_lua_ffi_pipe_proc_t *proc);


static njt_rbtree_t       njt_http_lua_pipe_rbtree;
static njt_rbtree_node_t  njt_http_lua_pipe_proc_sentinel;
static njt_event_t        njt_reap_pid_event;


#if (NJT_HTTP_LUA_HAVE_SIGNALFD)
static int                                njt_http_lua_signalfd;
static struct signalfd_siginfo            njt_http_lua_pipe_notification;

#define njt_http_lua_read_sigfd           njt_http_lua_signalfd

#else
static int                                njt_http_lua_sigchldfd[2];
static u_char                             njt_http_lua_pipe_notification[1];

#define njt_http_lua_read_sigfd           njt_http_lua_sigchldfd[0]
#define njt_http_lua_write_sigfd          njt_http_lua_sigchldfd[1]
#endif


static njt_connection_t                  *njt_http_lua_sigfd_conn = NULL;


/* The below signals are ignored by Nginx.
 * We need to reset them for the spawned child processes. */
njt_http_lua_pipe_signal_t njt_signals[] = {
    { SIGSYS, "SIGSYS" },
    { SIGPIPE, "SIGPIPE" },
    { 0, NULL }
};


enum {
    PIPE_ERR_CLOSED = 1,
    PIPE_ERR_SYSCALL,
    PIPE_ERR_NOMEM,
    PIPE_ERR_TIMEOUT,
    PIPE_ERR_ADD_READ_EV,
    PIPE_ERR_ADD_WRITE_EV,
    PIPE_ERR_ABORTED,
};


enum {
    PIPE_READ_ALL = 0,
    PIPE_READ_BYTES,
    PIPE_READ_LINE,
    PIPE_READ_ANY,
};


#define REASON_EXIT         "exit"
#define REASON_SIGNAL       "signal"
#define REASON_UNKNOWN      "unknown"

#define REASON_RUNNING_CODE  0
#define REASON_EXIT_CODE     1
#define REASON_SIGNAL_CODE   2
#define REASON_UNKNOWN_CODE  3


void
njt_http_lua_pipe_init(void)
{
    njt_rbtree_init(&njt_http_lua_pipe_rbtree,
                    &njt_http_lua_pipe_proc_sentinel, njt_rbtree_insert_value);
}


njt_int_t
njt_http_lua_pipe_add_signal_handler(njt_cycle_t *cycle)
{
    njt_event_t         *rev;
#if (NJT_HTTP_LUA_HAVE_SIGNALFD)
    sigset_t             set;

#else
    int                  rc;
    struct sigaction     sa;
#endif

    njt_reap_pid_event.handler = njt_http_lua_pipe_reap_timer_handler;
    njt_reap_pid_event.log = cycle->log;
    njt_reap_pid_event.data = cycle;
    njt_reap_pid_event.cancelable = 1;

    if (!njt_reap_pid_event.timer_set) {
        njt_add_timer(&njt_reap_pid_event, 1000);
    }

#if (NJT_HTTP_LUA_HAVE_SIGNALFD)
    if (sigemptyset(&set) != 0) {
        njt_log_error(NJT_LOG_ERR, cycle->log, njt_errno,
                      "lua pipe init signal set failed");
        return NJT_ERROR;
    }

    if (sigaddset(&set, SIGCHLD) != 0) {
        njt_log_error(NJT_LOG_ERR, cycle->log, njt_errno,
                      "lua pipe add SIGCHLD to signal set failed");
        return NJT_ERROR;
    }

    if (sigprocmask(SIG_BLOCK, &set, NULL) != 0) {
        njt_log_error(NJT_LOG_ERR, cycle->log, njt_errno,
                      "lua pipe block SIGCHLD failed");
        return NJT_ERROR;
    }

    njt_http_lua_signalfd = signalfd(-1, &set, SFD_NONBLOCK|SFD_CLOEXEC);
    if (njt_http_lua_signalfd < 0) {
        njt_log_error(NJT_LOG_ERR, cycle->log, njt_errno,
                      "lua pipe create signalfd instance failed");
        return NJT_ERROR;
    }

#else /* !(NJT_HTTP_LUA_HAVE_SIGNALFD) */
#   if (NJT_HTTP_LUA_HAVE_PIPE2)
    rc = pipe2(njt_http_lua_sigchldfd, O_NONBLOCK|O_CLOEXEC);
#   else
    rc = pipe(njt_http_lua_sigchldfd);
#   endif

    if (rc == -1) {
        njt_log_error(NJT_LOG_ERR, cycle->log, njt_errno,
                      "lua pipe init SIGCHLD fd failed");
        return NJT_ERROR;
    }

#   if !(NJT_HTTP_LUA_HAVE_PIPE2)
    if (njt_nonblocking(njt_http_lua_read_sigfd) == -1) {
        njt_log_error(NJT_LOG_ERR, cycle->log, njt_errno, "lua pipe "
                      njt_nonblocking_n " SIGCHLD read fd failed");
        goto failed;
    }

    if (njt_nonblocking(njt_http_lua_write_sigfd) == -1) {
        njt_log_error(NJT_LOG_ERR, cycle->log, njt_errno, "lua pipe "
                      njt_nonblocking_n " SIGCHLD write fd failed");
        goto failed;
    }

    /* it's ok not to set the pipe fd with O_CLOEXEC. This requires
     * extra syscall */
#   endif /* !(NJT_HTTP_LUA_HAVE_PIPE2) */
#endif /* NJT_HTTP_LUA_HAVE_SIGNALFD */

    njt_http_lua_sigfd_conn = njt_get_connection(njt_http_lua_read_sigfd,
                                                 cycle->log);
    if (njt_http_lua_sigfd_conn == NULL) {
        goto failed;
    }

    njt_http_lua_sigfd_conn->log = cycle->log;
    njt_http_lua_sigfd_conn->recv = njt_http_lua_pipe_fd_read;
    rev = njt_http_lua_sigfd_conn->read;
    rev->log = njt_http_lua_sigfd_conn->log;
    rev->handler = njt_http_lua_pipe_sigchld_event_handler;

#ifdef HAVE_SOCKET_CLOEXEC_PATCH
    rev->skip_socket_leak_check = 1;
#endif

    if (njt_handle_read_event(rev, 0) == NJT_ERROR) {
        goto failed;
    }

#if !(NJT_HTTP_LUA_HAVE_SIGNALFD)
    njt_memzero(&sa, sizeof(struct sigaction));
    sa.sa_sigaction = njt_http_lua_pipe_sigchld_handler;
    sa.sa_flags = SA_SIGINFO;

    if (sigemptyset(&sa.sa_mask) != 0) {
        njt_log_error(NJT_LOG_ERR, cycle->log, njt_errno,
                      "lua pipe init signal mask failed");
        goto failed;
    }

    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        njt_log_error(NJT_LOG_ERR, cycle->log, njt_errno,
                      "lua pipe sigaction(SIGCHLD) failed");
        goto failed;
    }
#endif

    return NJT_OK;

failed:

    if (njt_http_lua_sigfd_conn != NULL) {
        njt_close_connection(njt_http_lua_sigfd_conn);
        njt_http_lua_sigfd_conn = NULL;
    }

    if (close(njt_http_lua_read_sigfd) == -1) {
        njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                      "lua pipe close the read sigfd failed");
    }

#if !(NJT_HTTP_LUA_HAVE_SIGNALFD)
    if (close(njt_http_lua_write_sigfd) == -1) {
        njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                      "lua pipe close the write sigfd failed");
    }
#endif

    return NJT_ERROR;
}


static njt_rbtree_node_t *
njt_http_lua_pipe_lookup_pid(njt_rbtree_key_t key)
{
    njt_rbtree_node_t    *node, *sentinel;

    node = njt_http_lua_pipe_rbtree.root;
    sentinel = njt_http_lua_pipe_rbtree.sentinel;

    while (node != sentinel) {
        if (key < node->key) {
            node = node->left;
            continue;
        }

        if (key > node->key) {
            node = node->right;
            continue;
        }

        return node;
    }

    return NULL;
}


#if !(NJT_HTTP_LUA_HAVE_SIGNALFD)
static void
njt_http_lua_pipe_sigchld_handler(int signo, siginfo_t *siginfo,
    void *ucontext)
{
    njt_err_t                        err, saved_err;
    njt_int_t                        n;

    saved_err = njt_errno;

    for ( ;; ) {
        n = write(njt_http_lua_write_sigfd, njt_http_lua_pipe_notification,
                  sizeof(njt_http_lua_pipe_notification));

        njt_log_debug1(NJT_LOG_DEBUG_EVENT, njt_cycle->log, 0,
                       "lua pipe SIGCHLD fd write siginfo:%p", siginfo);

        if (n >= 0) {
            break;
        }

        err = njt_errno;

        if (err != NJT_EINTR) {
            if (err != NJT_EAGAIN) {
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, err,
                              "lua pipe SIGCHLD fd write failed");
            }

            break;
        }

        njt_log_debug0(NJT_LOG_DEBUG_EVENT, njt_cycle->log, err,
                       "lua pipe SIGCHLD fd write was interrupted");
    }

    njt_set_errno(saved_err);
}
#endif


static void
njt_http_lua_pipe_sigchld_event_handler(njt_event_t *ev)
{
    int                              n;
    njt_connection_t                *c = ev->data;

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, njt_cycle->log, 0,
                   "lua pipe reaping children");

    for ( ;; ) {
#if (NJT_HTTP_LUA_HAVE_SIGNALFD)
        n = c->recv(c, (u_char *) &njt_http_lua_pipe_notification,
#else
        n = c->recv(c, njt_http_lua_pipe_notification,
#endif
                    sizeof(njt_http_lua_pipe_notification));

        if (n <= 0) {
            if (n == NJT_ERROR) {
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, njt_errno,
                              "lua pipe SIGCHLD fd read failed");
            }

            break;
        }

        njt_http_lua_pipe_reap_pids(ev);
    }
}


static void
njt_http_lua_pipe_reap_pids(njt_event_t *ev)
{
    int                              status;
    njt_pid_t                        pid;
    njt_rbtree_node_t               *node;
    njt_http_lua_pipe_node_t        *pipe_node;

    for ( ;; ) {
        pid = waitpid(-1, &status, WNOHANG);

        if (pid == 0) {
            break;
        }

        if (pid < 0) {
            if (njt_errno != NJT_ECHILD) {
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, njt_errno,
                              "lua pipe waitpid failed");
            }

            break;
        }

        /* This log is ported from Nginx's signal handler since we override
         * or block it in this implementation. */
        njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0,
                      "signal %d (SIGCHLD) received from %P",
                      SIGCHLD, pid);

        njt_log_debug2(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "lua pipe SIGCHLD fd read pid:%P status:%d", pid,
                       status);

        node = njt_http_lua_pipe_lookup_pid(pid);
        if (node != NULL) {
            pipe_node = (njt_http_lua_pipe_node_t *) &node->color;
            if (pipe_node->wait_co_ctx != NULL) {
                njt_log_debug2(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                               "lua pipe resume process:%p waiting for %P",
                               pipe_node->proc, pid);

                /*
                 * We need the extra parentheses around the first argument
                 * of njt_post_event() just to work around macro issues in
                 * njet cores older than 1.7.12 (exclusive).
                 */
                njt_post_event((&pipe_node->wait_co_ctx->sleep),
                               &njt_posted_events);
            }

            /* TODO: we should proactively close and free up the pipe after
             * the user consume all the data in the pipe.
             */
            pipe_node->proc->pipe->dead = 1;

            if (WIFSIGNALED(status)) {
                pipe_node->status = WTERMSIG(status);
                pipe_node->reason_code = REASON_SIGNAL_CODE;

            } else if (WIFEXITED(status)) {
                pipe_node->status = WEXITSTATUS(status);
                pipe_node->reason_code = REASON_EXIT_CODE;

            } else {
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                              "lua pipe unknown exit status %d from "
                              "process %P", status, pid);
                pipe_node->status = status;
                pipe_node->reason_code = REASON_UNKNOWN_CODE;
            }
        }
    }
}


static void
njt_http_lua_pipe_reap_timer_handler(njt_event_t *ev)
{
    njt_http_lua_pipe_reap_pids(ev);

    if (!njt_exiting) {
        njt_add_timer(&njt_reap_pid_event, 1000);
        njt_reap_pid_event.timedout = 0;
    }
}


static ssize_t
njt_http_lua_pipe_fd_read(njt_connection_t *c, u_char *buf, size_t size)
{
    ssize_t       n;
    njt_err_t     err;
    njt_event_t  *rev;

    rev = c->read;

    do {
        n = read(c->fd, buf, size);

        err = njt_errno;

        njt_log_debug3(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "read: fd:%d %z of %uz", c->fd, n, size);

        if (n == 0) {
            rev->ready = 0;
            rev->eof = 1;
            return 0;
        }

        if (n > 0) {
            if ((size_t) n < size
                && !(njt_event_flags & NJT_USE_GREEDY_EVENT))
            {
                rev->ready = 0;
            }

            return n;
        }

        if (err == NJT_EAGAIN || err == NJT_EINTR) {
            njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, err,
                           "read() not ready");
            n = NJT_AGAIN;

        } else {
            n = njt_connection_error(c, err, "read() failed");
            break;
        }

    } while (err == NJT_EINTR);

    rev->ready = 0;

    if (n == NJT_ERROR) {
        rev->error = 1;
    }

    return n;
}


static ssize_t
njt_http_lua_pipe_fd_write(njt_connection_t *c, u_char *buf, size_t size)
{
    ssize_t       n;
    njt_err_t     err;
    njt_event_t  *wev;

    wev = c->write;

    do {
        n = write(c->fd, buf, size);

        njt_log_debug3(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "write: fd:%d %z of %uz", c->fd, n, size);

        if (n >= 0) {
            if ((size_t) n != size) {
                wev->ready = 0;
            }

            return n;
        }

        err = njt_errno;

        if (err == NJT_EAGAIN || err == NJT_EINTR) {
            njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, err,
                           "write() not ready");
            n = NJT_AGAIN;

        } else if (err != NJT_EPIPE) {
            n = njt_connection_error(c, err, "write() failed");
            break;
        }

    } while (err == NJT_EINTR);

    wev->ready = 0;

    if (n == NJT_ERROR) {
        wev->error = 1;
    }

    return n;
}


#if !(NJT_HTTP_LUA_HAVE_EXECVPE)
static int
njt_http_lua_execvpe(const char *program, char * const argv[],
    char * const envp[])
{
    int    rc;
    char **saved = environ;

    environ = (char **) envp;
    rc = execvp(program, argv);
    environ = saved;
    return rc;
}
#endif


int
njt_http_lua_ffi_pipe_spawn(njt_http_request_t *r,
    njt_http_lua_ffi_pipe_proc_t *proc,
    const char *file, const char **argv, int merge_stderr, size_t buffer_size,
    const char **environ, u_char *errbuf, size_t *errbuf_size)
{
    int                             rc;
    int                             in[2];
    int                             out[2];
    int                             err[2];
    int                             stdin_fd, stdout_fd, stderr_fd;
    int                             errlog_fd, temp_errlog_fd;
    njt_pid_t                       pid;
    ssize_t                         pool_size;
    njt_pool_t                     *pool;
    njt_uint_t                      i;
    njt_listening_t                *ls;
    njt_http_lua_pipe_t            *pp;
    njt_rbtree_node_t              *node;
    njt_http_lua_pipe_node_t       *pipe_node;
    struct sigaction                sa;
    njt_http_lua_pipe_signal_t     *sig;
    njt_pool_cleanup_t             *cln;
    sigset_t                        set;

    pool_size = njt_align(NJT_MIN_POOL_SIZE + buffer_size * 2,
                          NJT_POOL_ALIGNMENT);

    pool = njt_create_pool(pool_size, njt_cycle->log);
    if (pool == NULL) {
        *errbuf_size = njt_snprintf(errbuf, *errbuf_size, "no memory")
                       - errbuf;
        return NJT_ERROR;
    }

    pp = njt_pcalloc(pool, sizeof(njt_http_lua_pipe_t)
                     + offsetof(njt_rbtree_node_t, color)
                     + sizeof(njt_http_lua_pipe_node_t));
    if (pp == NULL) {
        *errbuf_size = njt_snprintf(errbuf, *errbuf_size, "no memory")
                       - errbuf;
        goto free_pool;
    }

    rc = pipe(in);
    if (rc == -1) {
        *errbuf_size = njt_snprintf(errbuf, *errbuf_size, "pipe failed: %s",
                                    strerror(errno))
                       - errbuf;
        goto free_pool;
    }

    rc = pipe(out);
    if (rc == -1) {
        *errbuf_size = njt_snprintf(errbuf, *errbuf_size, "pipe failed: %s",
                                    strerror(errno))
                       - errbuf;
        goto close_in_fd;
    }

    if (!merge_stderr) {
        rc = pipe(err);
        if (rc == -1) {
            *errbuf_size = njt_snprintf(errbuf, *errbuf_size,
                                        "pipe failed: %s", strerror(errno))
                           - errbuf;
            goto close_in_out_fd;
        }
    }

    pid = fork();
    if (pid == -1) {
        *errbuf_size = njt_snprintf(errbuf, *errbuf_size, "fork failed: %s",
                                    strerror(errno))
                       - errbuf;
        goto close_in_out_err_fd;
    }

    if (pid == 0) {

#if (NJT_HAVE_CPU_AFFINITY)
        /* reset the CPU affinity mask */
        njt_uint_t     log_level;
        njt_cpuset_t   child_cpu_affinity;

        if (njt_process == NJT_PROCESS_WORKER
            && njt_get_cpu_affinity(njt_worker) != NULL)
        {
            CPU_ZERO(&child_cpu_affinity);

            for (i = 0; i < (njt_uint_t) njt_min(njt_ncpu, CPU_SETSIZE); i++) {
                CPU_SET(i, &child_cpu_affinity);
            }

            log_level = njt_cycle->log->log_level;
            njt_cycle->log->log_level = NJT_LOG_WARN;
            njt_setaffinity(&child_cpu_affinity, njt_cycle->log);
            njt_cycle->log->log_level = log_level;
        }
#endif

        /* reset the handler of ignored signals to the default */
        for (sig = njt_signals; sig->signo != 0; sig++) {
            njt_memzero(&sa, sizeof(struct sigaction));
            sa.sa_handler = SIG_DFL;

            if (sigemptyset(&sa.sa_mask) != 0) {
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, njt_errno,
                              "lua pipe child init signal mask failed");
                exit(EXIT_FAILURE);
            }

            if (sigaction(sig->signo, &sa, NULL) == -1) {
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, njt_errno,
                              "lua pipe child reset signal handler for %s "
                              "failed", sig->signame);
                exit(EXIT_FAILURE);
            }
        }

        /* reset signal mask */
        if (sigemptyset(&set) != 0) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, njt_errno,
                          "lua pipe child init signal set failed");
            exit(EXIT_FAILURE);
        }

        if (sigprocmask(SIG_SETMASK, &set, NULL) != 0) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, njt_errno,
                          "lua pipe child reset signal mask failed");
            exit(EXIT_FAILURE);
        }

        /* close listening socket fd */
        ls = njt_cycle->listening.elts;
        for (i = 0; i < njt_cycle->listening.nelts; i++) {
            if (ls[i].fd != (njt_socket_t) -1 &&
                njt_close_socket(ls[i].fd) == -1)
            {
                njt_log_error(NJT_LOG_WARN, njt_cycle->log, njt_socket_errno,
                              "lua pipe child " njt_close_socket_n
                              " %V failed", &ls[i].addr_text);
            }
        }

        /* close and dup pipefd */
        if (close(in[1]) == -1) {
            njt_log_error(NJT_LOG_EMERG, njt_cycle->log, njt_errno,
                          "lua pipe child failed to close the in[1] "
                          "pipe fd");
        }

        if (close(out[0]) == -1) {
            njt_log_error(NJT_LOG_EMERG, njt_cycle->log, njt_errno,
                          "lua pipe child failed to close the out[0] "
                          "pipe fd");
        }

        if (njt_cycle->log->file && njt_cycle->log->file->fd == STDERR_FILENO) {
            errlog_fd = njt_cycle->log->file->fd;
            temp_errlog_fd = dup(errlog_fd);

            if (temp_errlog_fd == -1) {
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, njt_errno,
                              "lua pipe child dup errlog fd failed");
                exit(EXIT_FAILURE);
            }

            if (njt_cloexec(temp_errlog_fd) == -1) {
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, njt_errno,
                              "lua pipe child new errlog fd " njt_cloexec_n
                              " failed");
            }

            njt_log_debug2(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                           "lua pipe child dup old errlog fd %d to new fd %d",
                           njt_cycle->log->file->fd, temp_errlog_fd);

            njt_cycle->log->file->fd = temp_errlog_fd;
        }

        if (dup2(in[0], STDIN_FILENO) == -1) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, njt_errno,
                          "lua pipe child dup2 stdin failed");
            exit(EXIT_FAILURE);
        }

        if (dup2(out[1], STDOUT_FILENO) == -1) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, njt_errno,
                          "lua pipe child dup2 stdout failed");
            exit(EXIT_FAILURE);
        }

        if (merge_stderr) {
            if (dup2(STDOUT_FILENO, STDERR_FILENO) == -1) {
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, njt_errno,
                              "lua pipe child dup2 stderr failed");
                exit(EXIT_FAILURE);
            }

        } else {
            if (close(err[0]) == -1) {
                njt_log_error(NJT_LOG_EMERG, njt_cycle->log, njt_errno,
                              "lua pipe child failed to close the err[0] "
                              "pipe fd");
            }

            if (dup2(err[1], STDERR_FILENO) == -1) {
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, njt_errno,
                              "lua pipe child dup2 stderr failed");
                exit(EXIT_FAILURE);
            }
        }

        if (close(in[0]) == -1) {
            njt_log_error(NJT_LOG_EMERG, njt_cycle->log, njt_errno,
                          "lua pipe failed to close the in[0]");
        }

        if (close(out[1]) == -1) {
            njt_log_error(NJT_LOG_EMERG, njt_cycle->log, njt_errno,
                          "lua pipe failed to close the out[1]");
        }

        if (!merge_stderr) {
            if (close(err[1]) == -1) {
                njt_log_error(NJT_LOG_EMERG, njt_cycle->log, njt_errno,
                              "lua pipe failed to close the err[1]");
            }
        }

        if (environ != NULL) {
#if (NJT_HTTP_LUA_HAVE_EXECVPE)
            if (execvpe(file, (char * const *) argv, (char * const *) environ)
#else
            if (njt_http_lua_execvpe(file, (char * const *) argv,
                                     (char * const *) environ)
#endif
                == -1)
            {
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, njt_errno,
                              "lua pipe child execvpe() failed while "
                              "executing %s", file);
            }

        } else {
            if (execvp(file, (char * const *) argv) == -1) {
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, njt_errno,
                              "lua pipe child execvp() failed while "
                              "executing %s", file);
            }
        }

        exit(EXIT_FAILURE);
    }

    /* parent process */
    if (close(in[0]) == -1) {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, njt_errno,
                      "lua pipe: failed to close the in[0] pipe fd");
    }

    stdin_fd = in[1];

    if (njt_nonblocking(stdin_fd) == -1) {
        *errbuf_size = njt_snprintf(errbuf, *errbuf_size,
                                    njt_nonblocking_n " failed: %s",
                                    strerror(errno))
                       - errbuf;
        goto close_in_out_err_fd;
    }

    pp->stdin_fd = stdin_fd;

    if (close(out[1]) == -1) {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, njt_errno,
                      "lua pipe: failed to close the out[1] pipe fd");
    }

    stdout_fd = out[0];

    if (njt_nonblocking(stdout_fd) == -1) {
        *errbuf_size = njt_snprintf(errbuf, *errbuf_size,
                                    njt_nonblocking_n " failed: %s",
                                    strerror(errno))
                       - errbuf;
        goto close_in_out_err_fd;
    }

    pp->stdout_fd = stdout_fd;

    if (!merge_stderr) {
        if (close(err[1]) == -1) {
            njt_log_error(NJT_LOG_EMERG, njt_cycle->log, njt_errno,
                          "lua pipe: failed to close the err[1] pipe fd");
        }

        stderr_fd = err[0];

        if (njt_nonblocking(stderr_fd) == -1) {
            *errbuf_size = njt_snprintf(errbuf, *errbuf_size,
                                        njt_nonblocking_n " failed: %s",
                                        strerror(errno))
                           - errbuf;
            goto close_in_out_err_fd;
        }

        pp->stderr_fd = stderr_fd;
    }

    if (pp->cleanup == NULL) {
        cln = njt_pool_cleanup_add(r->pool, 0);

        if (cln == NULL) {
            *errbuf_size = njt_snprintf(errbuf, *errbuf_size, "no memory")
                           - errbuf;
            goto close_in_out_err_fd;
        }

        cln->handler = (njt_pool_cleanup_pt) njt_http_lua_ffi_pipe_proc_destroy;
        cln->data = proc;
        pp->cleanup = &cln->handler;
        pp->r = r;
    }

    node = (njt_rbtree_node_t *) (pp + 1);
    node->key = pid;
    pipe_node = (njt_http_lua_pipe_node_t *) &node->color;
    pipe_node->proc = proc;
    njt_rbtree_insert(&njt_http_lua_pipe_rbtree, node);

    pp->node = node;
    pp->pool = pool;
    pp->merge_stderr = merge_stderr;
    pp->buffer_size = buffer_size;

    proc->_pid = pid;
    proc->pipe = pp;

    njt_log_debug4(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                   "lua pipe spawn process:%p pid:%P merge_stderr:%d "
                   "buffer_size:%uz", proc, pid, merge_stderr, buffer_size);
    return NJT_OK;

close_in_out_err_fd:

    if (!merge_stderr) {
        if (close(err[0]) == -1) {
            njt_log_error(NJT_LOG_EMERG, njt_cycle->log, njt_errno,
                          "failed to close the err[0] pipe fd");
        }

        if (close(err[1]) == -1) {
            njt_log_error(NJT_LOG_EMERG, njt_cycle->log, njt_errno,
                          "failed to close the err[1] pipe fd");
        }
    }

close_in_out_fd:

    if (close(out[0]) == -1) {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, njt_errno,
                      "failed to close the out[0] pipe fd");
    }

    if (close(out[1]) == -1) {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, njt_errno,
                      "failed to close the out[1] pipe fd");
    }

close_in_fd:

    if (close(in[0]) == -1) {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, njt_errno,
                      "failed to close the in[0] pipe fd");
    }

    if (close(in[1]) == -1) {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, njt_errno,
                      "failed to close the in[1] pipe fd");
    }

free_pool:

    njt_destroy_pool(pool);
    return NJT_ERROR;
}


static void
njt_http_lua_pipe_close_helper(njt_http_lua_pipe_t *pipe,
    njt_http_lua_pipe_ctx_t *pipe_ctx, njt_event_t *ev)
{
    if (ev->handler != njt_http_lua_pipe_dummy_event_handler) {
        njt_log_debug2(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "lua pipe abort blocking operation pipe_ctx:%p ev:%p",
                       pipe_ctx, ev);

        if (pipe->dead) {
            pipe_ctx->err_type = PIPE_ERR_CLOSED;

        } else {
            pipe_ctx->err_type = PIPE_ERR_ABORTED;
        }

        njt_post_event(ev, &njt_posted_events);
        return;
    }

    njt_close_connection(pipe_ctx->c);
    pipe_ctx->c = NULL;
}


static void
njt_http_lua_pipe_close_stdin(njt_http_lua_pipe_t *pipe)
{
    njt_event_t                     *wev;

    if (pipe->stdin_ctx == NULL) {
        if (pipe->stdin_fd != -1) {
            if (close(pipe->stdin_fd) == -1) {
                njt_log_error(NJT_LOG_EMERG, njt_cycle->log, njt_errno,
                              "failed to close the stdin pipe fd");
            }

            pipe->stdin_fd = -1;
        }

    } else if (pipe->stdin_ctx->c != NULL) {
        wev = pipe->stdin_ctx->c->write;
        njt_http_lua_pipe_close_helper(pipe, pipe->stdin_ctx, wev);
    }
}


static void
njt_http_lua_pipe_close_stdout(njt_http_lua_pipe_t *pipe)
{
    njt_event_t                     *rev;

    if (pipe->stdout_ctx == NULL) {
        if (pipe->stdout_fd != -1) {
            if (close(pipe->stdout_fd) == -1) {
                njt_log_error(NJT_LOG_EMERG, njt_cycle->log, njt_errno,
                              "failed to close the stdout pipe fd");
            }

            pipe->stdout_fd = -1;
        }

    } else if (pipe->stdout_ctx->c != NULL) {
        rev = pipe->stdout_ctx->c->read;
        njt_http_lua_pipe_close_helper(pipe, pipe->stdout_ctx, rev);
    }
}


static void
njt_http_lua_pipe_close_stderr(njt_http_lua_pipe_t *pipe)
{
    njt_event_t                     *rev;

    if (pipe->stderr_ctx == NULL) {
        if (pipe->stderr_fd != -1) {
            if (close(pipe->stderr_fd) == -1) {
                njt_log_error(NJT_LOG_EMERG, njt_cycle->log, njt_errno,
                              "failed to close the stderr pipe fd");
            }

            pipe->stderr_fd = -1;
        }

    } else if (pipe->stderr_ctx->c != NULL) {
        rev = pipe->stderr_ctx->c->read;
        njt_http_lua_pipe_close_helper(pipe, pipe->stderr_ctx, rev);
    }
}


int
njt_http_lua_ffi_pipe_proc_shutdown_stdin(njt_http_lua_ffi_pipe_proc_t *proc,
    u_char *errbuf, size_t *errbuf_size)
{
    njt_http_lua_pipe_t             *pipe;

    pipe = proc->pipe;
    if (pipe == NULL || pipe->closed) {
        *errbuf_size = njt_snprintf(errbuf, *errbuf_size, "closed") - errbuf;
        return NJT_ERROR;
    }

    njt_http_lua_pipe_close_stdin(pipe);

    return NJT_OK;
}


int
njt_http_lua_ffi_pipe_proc_shutdown_stdout(njt_http_lua_ffi_pipe_proc_t *proc,
    u_char *errbuf, size_t *errbuf_size)
{
    njt_http_lua_pipe_t             *pipe;

    pipe = proc->pipe;
    if (pipe == NULL || pipe->closed) {
        *errbuf_size = njt_snprintf(errbuf, *errbuf_size, "closed") - errbuf;
        return NJT_ERROR;
    }

    njt_http_lua_pipe_close_stdout(pipe);

    return NJT_OK;
}


int
njt_http_lua_ffi_pipe_proc_shutdown_stderr(njt_http_lua_ffi_pipe_proc_t *proc,
    u_char *errbuf, size_t *errbuf_size)
{
    njt_http_lua_pipe_t             *pipe;

    pipe = proc->pipe;
    if (pipe == NULL || pipe->closed) {
        *errbuf_size = njt_snprintf(errbuf, *errbuf_size, "closed") - errbuf;
        return NJT_ERROR;
    }

    if (pipe->merge_stderr) {
        /* stdout is used internally as stderr when merge_stderr is true */
        *errbuf_size = njt_snprintf(errbuf, *errbuf_size, "merged to stdout")
                       - errbuf;
        return NJT_ERROR;
    }

    njt_http_lua_pipe_close_stderr(pipe);

    return NJT_OK;
}


static void
njt_http_lua_pipe_proc_finalize(njt_http_lua_ffi_pipe_proc_t *proc)
{
    njt_http_lua_pipe_t          *pipe;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                   "lua pipe finalize process:%p pid:%P",
                   proc, proc->_pid);
    pipe = proc->pipe;

    if (pipe->node) {
        njt_rbtree_delete(&njt_http_lua_pipe_rbtree, pipe->node);
        pipe->node = NULL;
    }

    pipe->dead = 1;

    njt_http_lua_pipe_close_stdin(pipe);
    njt_http_lua_pipe_close_stdout(pipe);

    if (!pipe->merge_stderr) {
        njt_http_lua_pipe_close_stderr(pipe);
    }

    pipe->closed = 1;
}


void
njt_http_lua_ffi_pipe_proc_destroy(njt_http_lua_ffi_pipe_proc_t *proc)
{
    njt_http_lua_pipe_t          *pipe;

    pipe = proc->pipe;
    if (pipe == NULL) {
        return;
    }

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                   "lua pipe destroy process:%p pid:%P", proc, proc->_pid);

    if (!pipe->dead) {
        njt_log_debug2(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "lua pipe kill process:%p pid:%P", proc, proc->_pid);

        if (kill(proc->_pid, SIGKILL) == -1) {
            if (njt_errno != ESRCH) {
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, njt_errno,
                              "lua pipe failed to kill process:%p pid:%P",
                              proc, proc->_pid);
            }
        }
    }

    if (pipe->cleanup != NULL) {
        *pipe->cleanup = NULL;
        njt_http_lua_cleanup_free(pipe->r, pipe->cleanup);
        pipe->cleanup = NULL;
    }

    njt_http_lua_pipe_proc_finalize(proc);
    njt_destroy_pool(pipe->pool);
    proc->pipe = NULL;
}


static njt_int_t
njt_http_lua_pipe_get_lua_ctx(njt_http_request_t *r,
    njt_http_lua_ctx_t **ctx, u_char *errbuf, size_t *errbuf_size)
{
    int                                 rc;

    *ctx = njt_http_get_module_ctx(r, njt_http_lua_module);
    if (*ctx == NULL) {
        return NJT_HTTP_LUA_FFI_NO_REQ_CTX;
    }

    rc = njt_http_lua_ffi_check_context(*ctx, NJT_HTTP_LUA_CONTEXT_YIELDABLE,
                                        errbuf, errbuf_size);
    if (rc != NJT_OK) {
        return NJT_HTTP_LUA_FFI_BAD_CONTEXT;
    }

    return NJT_OK;
}


static void
njt_http_lua_pipe_put_error(njt_http_lua_pipe_ctx_t *pipe_ctx, u_char *errbuf,
    size_t *errbuf_size)
{
    switch (pipe_ctx->err_type) {

    case PIPE_ERR_CLOSED:
        *errbuf_size = njt_snprintf(errbuf, *errbuf_size, "closed") - errbuf;
        break;

    case PIPE_ERR_SYSCALL:
        *errbuf_size = njt_snprintf(errbuf, *errbuf_size, "%s",
                                    strerror(pipe_ctx->pipe_errno))
                       - errbuf;
        break;

    case PIPE_ERR_NOMEM:
        *errbuf_size = njt_snprintf(errbuf, *errbuf_size, "no memory")
                       - errbuf;
        break;

    case PIPE_ERR_TIMEOUT:
        *errbuf_size = njt_snprintf(errbuf, *errbuf_size, "timeout")
                       - errbuf;
        break;

    case PIPE_ERR_ADD_READ_EV:
        *errbuf_size = njt_snprintf(errbuf, *errbuf_size,
                                    "failed to add read event")
                       - errbuf;
        break;

    case PIPE_ERR_ADD_WRITE_EV:
        *errbuf_size = njt_snprintf(errbuf, *errbuf_size,
                                    "failed to add write event")
                       - errbuf;
        break;

    case PIPE_ERR_ABORTED:
        *errbuf_size = njt_snprintf(errbuf, *errbuf_size, "aborted") - errbuf;
        break;

    default:
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                      "unexpected err type: %d", pipe_ctx->err_type);
        njt_http_lua_assert(NULL);
    }
}


static void
njt_http_lua_pipe_put_data(njt_http_lua_pipe_t *pipe,
    njt_http_lua_pipe_ctx_t *pipe_ctx, u_char **buf, size_t *buf_size)
{
    size_t                   size = 0;
    size_t                   chunk_size;
    size_t                   nbufs;
    u_char                  *p;
    njt_buf_t               *b;
    njt_chain_t             *cl;
    njt_chain_t            **ll;

    nbufs = 0;
    ll = NULL;

    for (cl = pipe_ctx->bufs_in; cl; cl = cl->next) {
        b = cl->buf;
        chunk_size = b->last - b->pos;

        if (cl->next) {
            ll = &cl->next;
        }

        size += chunk_size;

        nbufs++;
    }

    if (*buf_size < size) {
        *buf = NULL;
        *buf_size = size;

        return;
    }

    *buf_size = size;

    p = *buf;
    for (cl = pipe_ctx->bufs_in; cl; cl = cl->next) {
        b = cl->buf;
        chunk_size = b->last - b->pos;
        p = njt_cpymem(p, b->pos, chunk_size);
    }

    if (nbufs > 1 && ll) {
        *ll = pipe->free_bufs;
        pipe->free_bufs = pipe_ctx->bufs_in;
        pipe_ctx->bufs_in = pipe_ctx->buf_in;
    }

    if (pipe_ctx->buffer.pos == pipe_ctx->buffer.last) {
        pipe_ctx->buffer.pos = pipe_ctx->buffer.start;
        pipe_ctx->buffer.last = pipe_ctx->buffer.start;
    }

    if (pipe_ctx->bufs_in) {
        pipe_ctx->buf_in->buf->last = pipe_ctx->buffer.pos;
        pipe_ctx->buf_in->buf->pos = pipe_ctx->buffer.pos;
    }
}


static njt_int_t
njt_http_lua_pipe_add_input_buffer(njt_http_lua_pipe_t *pipe,
    njt_http_lua_pipe_ctx_t *pipe_ctx)
{
    njt_chain_t             *cl;

    cl = njt_http_lua_chain_get_free_buf(njt_cycle->log, pipe->pool,
                                         &pipe->free_bufs,
                                         pipe->buffer_size);

    if (cl == NULL) {
        pipe_ctx->err_type = PIPE_ERR_NOMEM;
        return NJT_ERROR;
    }

    pipe_ctx->buf_in->next = cl;
    pipe_ctx->buf_in = cl;
    pipe_ctx->buffer = *cl->buf;

    return NJT_OK;
}


static njt_int_t
njt_http_lua_pipe_read_all(void *data, ssize_t bytes)
{
    njt_http_lua_pipe_ctx_t      *pipe_ctx = data;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "lua pipe read all");
    return njt_http_lua_read_all(&pipe_ctx->buffer, pipe_ctx->buf_in, bytes,
                                 njt_cycle->log);
}


static njt_int_t
njt_http_lua_pipe_read_bytes(void *data, ssize_t bytes)
{
    njt_int_t                          rc;
    njt_http_lua_pipe_ctx_t           *pipe_ctx = data;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                   "lua pipe read bytes %z", bytes);

    rc = njt_http_lua_read_bytes(&pipe_ctx->buffer, pipe_ctx->buf_in,
                                 &pipe_ctx->rest, bytes, njt_cycle->log);
    if (rc == NJT_ERROR) {
        pipe_ctx->err_type = PIPE_ERR_CLOSED;
        return NJT_ERROR;
    }

    return rc;
}


static njt_int_t
njt_http_lua_pipe_read_line(void *data, ssize_t bytes)
{
    njt_int_t                          rc;
    njt_http_lua_pipe_ctx_t           *pipe_ctx = data;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                   "lua pipe read line");
    rc = njt_http_lua_read_line(&pipe_ctx->buffer, pipe_ctx->buf_in, bytes,
                                njt_cycle->log);
    if (rc == NJT_ERROR) {
        pipe_ctx->err_type = PIPE_ERR_CLOSED;
        return NJT_ERROR;
    }

    return rc;
}


static njt_int_t
njt_http_lua_pipe_read_any(void *data, ssize_t bytes)
{
    njt_int_t                          rc;
    njt_http_lua_pipe_ctx_t           *pipe_ctx = data;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "lua pipe read any");
    rc = njt_http_lua_read_any(&pipe_ctx->buffer, pipe_ctx->buf_in,
                               &pipe_ctx->rest, bytes, njt_cycle->log);
    if (rc == NJT_ERROR) {
        pipe_ctx->err_type = PIPE_ERR_CLOSED;
        return NJT_ERROR;
    }

    return rc;
}


static njt_int_t
njt_http_lua_pipe_read(njt_http_lua_pipe_t *pipe,
    njt_http_lua_pipe_ctx_t *pipe_ctx)
{
    int                                 rc;
    int                                 read;
    size_t                              size;
    ssize_t                             n;
    njt_buf_t                          *b;
    njt_event_t                        *rev;
    njt_connection_t                   *c;

    c = pipe_ctx->c;
    rev = c->read;
    b = &pipe_ctx->buffer;
    read = 0;

    for ( ;; ) {
        size = b->last - b->pos;

        if (size || pipe_ctx->eof) {
            rc = pipe_ctx->input_filter(pipe_ctx->input_filter_ctx, size);
            if (rc == NJT_ERROR) {
                return NJT_ERROR;
            }

            if (rc == NJT_OK) {
                njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                               "lua pipe read done pipe:%p", pipe_ctx);
                return NJT_OK;
            }

            /* rc == NJT_AGAIN */
            continue;
        }

        if (read && !rev->ready) {
            break;
        }

        size = b->end - b->last;

        if (size == 0) {
            rc = njt_http_lua_pipe_add_input_buffer(pipe, pipe_ctx);
            if (rc == NJT_ERROR) {
                return NJT_ERROR;
            }

            b = &pipe_ctx->buffer;
            size = (size_t) (b->end - b->last);
        }

        njt_log_debug2(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "lua pipe try to read data %uz pipe:%p",
                       size, pipe_ctx);

        n = c->recv(c, b->last, size);
        read = 1;

        njt_log_debug2(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "lua pipe read data returned %z pipe:%p", n, pipe_ctx);

        if (n == NJT_AGAIN) {
            break;
        }

        if (n == 0) {
            pipe_ctx->eof = 1;
            njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                           "lua pipe closed pipe:%p", pipe_ctx);
            continue;
        }

        if (n == NJT_ERROR) {
            njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, njt_errno,
                           "lua pipe read data error pipe:%p", pipe_ctx);

            pipe_ctx->err_type = PIPE_ERR_SYSCALL;
            pipe_ctx->pipe_errno = njt_errno;
            return NJT_ERROR;
        }

        b->last += n;
    }

    return NJT_AGAIN;
}


static njt_int_t
njt_http_lua_pipe_init_ctx(njt_http_lua_pipe_ctx_t **pipe_ctx_pt, int fd,
    njt_pool_t *pool, u_char *errbuf, size_t *errbuf_size)
{
    njt_connection_t                   *c;

    if (fd == -1) {
        *errbuf_size = njt_snprintf(errbuf, *errbuf_size, "closed") - errbuf;
        return NJT_ERROR;
    }

    *pipe_ctx_pt = njt_pcalloc(pool, sizeof(njt_http_lua_pipe_ctx_t));
    if (*pipe_ctx_pt == NULL) {
        *errbuf_size = njt_snprintf(errbuf, *errbuf_size, "no memory")
                       - errbuf;
        return NJT_ERROR;
    }

    c = njt_get_connection(fd, njt_cycle->log);
    if (c == NULL) {
        *errbuf_size = njt_snprintf(errbuf, *errbuf_size, "no connection")
                       - errbuf;
        return NJT_ERROR;
    }

    c->log = njt_cycle->log;
    c->recv = njt_http_lua_pipe_fd_read;
    c->read->handler = njt_http_lua_pipe_dummy_event_handler;
    c->read->log = c->log;

#ifdef HAVE_SOCKET_CLOEXEC_PATCH
    c->read->skip_socket_leak_check = 1;
#endif

    c->send = njt_http_lua_pipe_fd_write;
    c->write->handler = njt_http_lua_pipe_dummy_event_handler;
    c->write->log = c->log;
    (*pipe_ctx_pt)->c = c;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                   "lua pipe init pipe ctx:%p fd:*%d", *pipe_ctx_pt, fd);

    return NJT_OK;
}


int
njt_http_lua_ffi_pipe_proc_read(njt_http_request_t *r,
    njt_http_lua_ffi_pipe_proc_t *proc, int from_stderr, int reader_type,
    size_t length, u_char **buf, size_t *buf_size, u_char *errbuf,
    size_t *errbuf_size)
{
    int                                 rc;
    njt_msec_t                          timeout;
    njt_event_t                        *rev;
    njt_connection_t                   *c;
    njt_http_lua_ctx_t                 *ctx;
    njt_http_lua_pipe_t                *pipe;
    njt_http_lua_co_ctx_t              *wait_co_ctx;
    njt_http_lua_pipe_ctx_t            *pipe_ctx;

    rc = njt_http_lua_pipe_get_lua_ctx(r, &ctx, errbuf, errbuf_size);
    if (rc != NJT_OK) {
        return rc;
    }

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua pipe read process:%p pid:%P", proc, proc->_pid);

    pipe = proc->pipe;
    if (pipe == NULL || pipe->closed) {
        *errbuf_size = njt_snprintf(errbuf, *errbuf_size, "closed") - errbuf;
        return NJT_ERROR;
    }

    if (pipe->merge_stderr && from_stderr) {
        *errbuf_size = njt_snprintf(errbuf, *errbuf_size, "merged to stdout")
                       - errbuf;
        return NJT_ERROR;
    }

    if (from_stderr) {
        if (pipe->stderr_ctx == NULL) {
            if (njt_http_lua_pipe_init_ctx(&pipe->stderr_ctx, pipe->stderr_fd,
                                           pipe->pool, errbuf,
                                           errbuf_size)
                != NJT_OK)
            {
                return NJT_ERROR;
            }

        } else {
            pipe->stderr_ctx->err_type = 0;
        }

        pipe_ctx = pipe->stderr_ctx;

    } else {
        if (pipe->stdout_ctx == NULL) {
            if (njt_http_lua_pipe_init_ctx(&pipe->stdout_ctx, pipe->stdout_fd,
                                           pipe->pool, errbuf,
                                           errbuf_size)
                != NJT_OK)
            {
                return NJT_ERROR;
            }

        } else {
            pipe->stdout_ctx->err_type = 0;
        }

        pipe_ctx = pipe->stdout_ctx;
    }

    c = pipe_ctx->c;
    if (c == NULL) {
        *errbuf_size = njt_snprintf(errbuf, *errbuf_size, "closed") - errbuf;
        return NJT_ERROR;
    }

    rev = c->read;
    if (rev->handler != njt_http_lua_pipe_dummy_event_handler) {
        *errbuf_size = njt_snprintf(errbuf, *errbuf_size, "pipe busy reading")
                       - errbuf;
        return NJT_ERROR;
    }

    pipe_ctx->input_filter_ctx = pipe_ctx;

    switch (reader_type) {

    case PIPE_READ_ALL:
        pipe_ctx->input_filter = njt_http_lua_pipe_read_all;
        break;

    case PIPE_READ_BYTES:
        pipe_ctx->input_filter = njt_http_lua_pipe_read_bytes;
        break;

    case PIPE_READ_LINE:
        pipe_ctx->input_filter = njt_http_lua_pipe_read_line;
        break;

    case PIPE_READ_ANY:
        pipe_ctx->input_filter = njt_http_lua_pipe_read_any;
        break;

    default:
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                      "unexpected reader_type: %d", reader_type);
        njt_http_lua_assert(NULL);
    }

    pipe_ctx->rest = length;

    if (pipe_ctx->bufs_in == NULL) {
        pipe_ctx->bufs_in =
            njt_http_lua_chain_get_free_buf(njt_cycle->log, pipe->pool,
                                            &pipe->free_bufs,
                                            pipe->buffer_size);

        if (pipe_ctx->bufs_in == NULL) {
            pipe_ctx->err_type = PIPE_ERR_NOMEM;
            goto error;
        }

        pipe_ctx->buf_in = pipe_ctx->bufs_in;
        pipe_ctx->buffer = *pipe_ctx->buf_in->buf;
    }

    rc = njt_http_lua_pipe_read(pipe, pipe_ctx);
    if (rc == NJT_ERROR) {
        goto error;
    }

    if (rc == NJT_OK) {
        njt_http_lua_pipe_put_data(pipe, pipe_ctx, buf, buf_size);
        return NJT_OK;
    }

    /* rc == NJT_AGAIN */
    wait_co_ctx = ctx->cur_co_ctx;

    c->data = wait_co_ctx;
    if (njt_handle_read_event(rev, 0) != NJT_OK) {
        pipe_ctx->err_type = PIPE_ERR_ADD_READ_EV;
        goto error;
    }

    wait_co_ctx->data = proc;

    if (from_stderr) {
        rev->handler = njt_http_lua_pipe_resume_read_stderr_handler;
        wait_co_ctx->cleanup = njt_http_lua_pipe_proc_read_stderr_cleanup;
        timeout = proc->stderr_read_timeout;

    } else {
        rev->handler = njt_http_lua_pipe_resume_read_stdout_handler;
        wait_co_ctx->cleanup = njt_http_lua_pipe_proc_read_stdout_cleanup;
        timeout = proc->stdout_read_timeout;
    }

    if (timeout > 0) {
        njt_add_timer(rev, timeout);
        njt_log_debug5(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "lua pipe add timer for reading: %d(ms) process:%p "
                       "pid:%P pipe:%p ev:%p", timeout, proc, proc->_pid, pipe,
                       rev);
    }

    njt_log_debug3(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua pipe read yielding process:%p pid:%P pipe:%p", proc,
                   proc->_pid, pipe);

    return NJT_AGAIN;

error:

    if (pipe_ctx->bufs_in) {
        njt_http_lua_pipe_put_data(pipe, pipe_ctx, buf, buf_size);
        njt_http_lua_pipe_put_error(pipe_ctx, errbuf, errbuf_size);
        return NJT_DECLINED;
    }

    njt_http_lua_pipe_put_error(pipe_ctx, errbuf, errbuf_size);

    return NJT_ERROR;
}


/*
 * njt_http_lua_ffi_pipe_get_read_result should only be called just after
 * njt_http_lua_ffi_pipe_proc_read, so we omit most of the sanity check already
 * done in njt_http_lua_ffi_pipe_proc_read.
 */
int
njt_http_lua_ffi_pipe_get_read_result(njt_http_request_t *r,
    njt_http_lua_ffi_pipe_proc_t *proc, int from_stderr, u_char **buf,
    size_t *buf_size, u_char *errbuf, size_t *errbuf_size)
{
    njt_http_lua_pipe_t                *pipe;
    njt_http_lua_pipe_ctx_t            *pipe_ctx;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua pipe get read result process:%p pid:%P", proc,
                   proc->_pid);

    pipe = proc->pipe;
    pipe_ctx = from_stderr ? pipe->stderr_ctx : pipe->stdout_ctx;

    if (!pipe_ctx->err_type) {
        njt_http_lua_pipe_put_data(pipe, pipe_ctx, buf, buf_size);
        return NJT_OK;
    }

    if (pipe_ctx->bufs_in) {
        njt_http_lua_pipe_put_data(pipe, pipe_ctx, buf, buf_size);
        njt_http_lua_pipe_put_error(pipe_ctx, errbuf, errbuf_size);
        return NJT_DECLINED;
    }

    njt_http_lua_pipe_put_error(pipe_ctx, errbuf, errbuf_size);

    return NJT_ERROR;
}


static njt_int_t
njt_http_lua_pipe_write(njt_http_lua_pipe_t *pipe,
    njt_http_lua_pipe_ctx_t *pipe_ctx)
{
    size_t                       size;
    njt_int_t                    n;
    njt_buf_t                   *b;
    njt_connection_t            *c;

    c = pipe_ctx->c;
    b = pipe_ctx->buf_in->buf;

    for ( ;; ) {
        size = b->last - b->pos;
        njt_log_debug2(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "lua pipe try to write data %uz pipe:%p", size,
                       pipe_ctx);

        n = c->send(c, b->pos, size);
        njt_log_debug2(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "lua pipe write returned %i pipe:%p", n, pipe_ctx);

        if (n >= 0) {
            b->pos += n;

            if (b->pos == b->last) {
                b->pos = b->start;
                b->last = b->start;

                if (!pipe->free_bufs) {
                    pipe->free_bufs = pipe_ctx->buf_in;

                } else {
                    pipe->free_bufs->next = pipe_ctx->buf_in;
                }

                njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                               "lua pipe write done pipe:%p", pipe_ctx);
                return NJT_OK;
            }

            continue;
        }

        /* NJT_ERROR || NJT_AGAIN */
        break;
    }

    if (n == NJT_ERROR) {
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, njt_errno,
                       "lua pipe write data error pipe:%p", pipe_ctx);

        if (njt_errno == NJT_EPIPE) {
            pipe_ctx->err_type = PIPE_ERR_CLOSED;

        } else {
            pipe_ctx->err_type = PIPE_ERR_SYSCALL;
            pipe_ctx->pipe_errno = njt_errno;
        }

        return NJT_ERROR;
    }

    return NJT_AGAIN;
}


ssize_t
njt_http_lua_ffi_pipe_proc_write(njt_http_request_t *r,
    njt_http_lua_ffi_pipe_proc_t *proc, const u_char *data, size_t len,
    u_char *errbuf, size_t *errbuf_size)
{
    int                                 rc;
    njt_buf_t                          *b;
    njt_msec_t                          timeout;
    njt_chain_t                        *cl;
    njt_event_t                        *wev;
    njt_http_lua_ctx_t                 *ctx;
    njt_http_lua_pipe_t                *pipe;
    njt_http_lua_co_ctx_t              *wait_co_ctx;
    njt_http_lua_pipe_ctx_t            *pipe_ctx;

    rc = njt_http_lua_pipe_get_lua_ctx(r, &ctx, errbuf, errbuf_size);
    if (rc != NJT_OK) {
        return rc;
    }

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua pipe write process:%p pid:%P", proc, proc->_pid);

    pipe = proc->pipe;
    if (pipe == NULL || pipe->closed) {
        *errbuf_size = njt_snprintf(errbuf, *errbuf_size, "closed") - errbuf;
        return NJT_ERROR;
    }

    if (pipe->stdin_ctx == NULL) {
        if (njt_http_lua_pipe_init_ctx(&pipe->stdin_ctx, pipe->stdin_fd,
                                       pipe->pool, errbuf,
                                       errbuf_size)
            != NJT_OK)
        {
            return NJT_ERROR;
        }

    } else {
        pipe->stdin_ctx->err_type = 0;
    }

    pipe_ctx = pipe->stdin_ctx;
    if (pipe_ctx->c == NULL) {
        *errbuf_size = njt_snprintf(errbuf, *errbuf_size, "closed") - errbuf;
        return NJT_ERROR;
    }

    wev = pipe_ctx->c->write;
    if (wev->handler != njt_http_lua_pipe_dummy_event_handler) {
        *errbuf_size = njt_snprintf(errbuf, *errbuf_size, "pipe busy writing")
                       - errbuf;
        return NJT_ERROR;
    }

    pipe_ctx->rest = len;

    cl = njt_http_lua_chain_get_free_buf(njt_cycle->log, pipe->pool,
                                         &pipe->free_bufs, len);
    if (cl == NULL) {
        pipe_ctx->err_type = PIPE_ERR_NOMEM;
        goto error;
    }

    pipe_ctx->buf_in = cl;
    b = pipe_ctx->buf_in->buf;
    b->last = njt_copy(b->last, data, len);

    rc = njt_http_lua_pipe_write(pipe, pipe_ctx);
    if (rc == NJT_ERROR) {
        goto error;
    }

    if (rc == NJT_OK) {
        return len;
    }

    /* rc == NJT_AGAIN */
    wait_co_ctx = ctx->cur_co_ctx;
    pipe_ctx->c->data = wait_co_ctx;

    wev->handler = njt_http_lua_pipe_resume_write_handler;
    if (njt_handle_write_event(wev, 0) != NJT_OK) {
        pipe_ctx->err_type = PIPE_ERR_ADD_WRITE_EV;
        goto error;
    }

    wait_co_ctx->data = proc;
    wait_co_ctx->cleanup = njt_http_lua_pipe_proc_write_cleanup;
    timeout = proc->write_timeout;

    if (timeout > 0) {
        njt_add_timer(wev, timeout);
        njt_log_debug5(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "lua pipe add timer for writing: %d(ms) process:%p "
                       "pid:%P pipe:%p ev:%p", timeout, proc, proc->_pid, pipe,
                       wev);
    }

    njt_log_debug3(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua pipe write yielding process:%p pid:%P pipe:%p", proc,
                   proc->_pid, pipe);

    return NJT_AGAIN;

error:

    njt_http_lua_pipe_put_error(pipe_ctx, errbuf, errbuf_size);
    return NJT_ERROR;
}


/*
 * njt_http_lua_ffi_pipe_get_write_result should only be called just after
 * njt_http_lua_ffi_pipe_proc_write, so we omit most of the sanity check
 * already done in njt_http_lua_ffi_pipe_proc_write.
 */
ssize_t
njt_http_lua_ffi_pipe_get_write_result(njt_http_request_t *r,
    njt_http_lua_ffi_pipe_proc_t *proc, u_char *errbuf, size_t *errbuf_size)
{
    njt_http_lua_pipe_t                *pipe;
    njt_http_lua_pipe_ctx_t            *pipe_ctx;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua pipe get write result process:%p pid:%P", proc,
                   proc->_pid);

    pipe = proc->pipe;
    pipe_ctx = pipe->stdin_ctx;

    if (pipe_ctx->err_type) {
        njt_http_lua_pipe_put_error(pipe_ctx, errbuf, errbuf_size);
        return NJT_ERROR;
    }

    return pipe_ctx->rest;
}


int
njt_http_lua_ffi_pipe_proc_wait(njt_http_request_t *r,
    njt_http_lua_ffi_pipe_proc_t *proc, char **reason, int *status,
    u_char *errbuf, size_t *errbuf_size)
{
    int                                 rc;
    njt_rbtree_node_t                  *node;
    njt_http_lua_ctx_t                 *ctx;
    njt_http_lua_pipe_t                *pipe;
    njt_http_lua_co_ctx_t              *wait_co_ctx;
    njt_http_lua_pipe_node_t           *pipe_node;

    rc = njt_http_lua_pipe_get_lua_ctx(r, &ctx, errbuf, errbuf_size);
    if (rc != NJT_OK) {
        return rc;
    }

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua pipe wait process:%p pid:%P", proc, proc->_pid);

    pipe = proc->pipe;
    if (pipe == NULL || pipe->closed) {
        *errbuf_size = njt_snprintf(errbuf, *errbuf_size, "exited") - errbuf;
        return NJT_ERROR;
    }

    node = pipe->node;
    pipe_node = (njt_http_lua_pipe_node_t *) &node->color;
    if (pipe_node->wait_co_ctx) {
        *errbuf_size = njt_snprintf(errbuf, *errbuf_size, "pipe busy waiting")
                       - errbuf;
        return NJT_ERROR;
    }

    if (pipe_node->reason_code == REASON_RUNNING_CODE) {
        wait_co_ctx = ctx->cur_co_ctx;
        wait_co_ctx->data = proc;
        njt_memzero(&wait_co_ctx->sleep, sizeof(njt_event_t));
        wait_co_ctx->sleep.handler = njt_http_lua_pipe_resume_wait_handler;
        wait_co_ctx->sleep.data = wait_co_ctx;
        wait_co_ctx->sleep.log = r->connection->log;
        wait_co_ctx->cleanup = njt_http_lua_pipe_proc_wait_cleanup;

        pipe_node->wait_co_ctx = wait_co_ctx;

        if (proc->wait_timeout > 0) {
            njt_add_timer(&wait_co_ctx->sleep, proc->wait_timeout);
            njt_log_debug4(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "lua pipe add timer for waiting: %d(ms) process:%p "
                           "pid:%P ev:%p", proc->wait_timeout, proc,
                           proc->_pid, &wait_co_ctx->sleep);
        }

        njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "lua pipe wait yielding process:%p pid:%P", proc,
                       proc->_pid);

        return NJT_AGAIN;
    }

    *status = pipe_node->status;

    switch (pipe_node->reason_code) {

    case REASON_EXIT_CODE:
        *reason = REASON_EXIT;
        break;

    case REASON_SIGNAL_CODE:
        *reason = REASON_SIGNAL;
        break;

    default:
        *reason = REASON_UNKNOWN;
    }

    njt_http_lua_pipe_proc_finalize(proc);

    if (*status == 0) {
        return NJT_OK;
    }

    return NJT_DECLINED;
}


int
njt_http_lua_ffi_pipe_proc_kill(njt_http_lua_ffi_pipe_proc_t *proc, int signal,
    u_char *errbuf, size_t *errbuf_size)
{
    njt_pid_t                           pid;
    njt_http_lua_pipe_t                *pipe;

    pipe = proc->pipe;

    if (pipe == NULL || pipe->dead) {
        *errbuf_size = njt_snprintf(errbuf, *errbuf_size, "exited") - errbuf;
        return NJT_ERROR;
    }

    pid = proc->_pid;

    if (kill(pid, signal) == -1) {
        switch (njt_errno) {
        case EINVAL:
            *errbuf_size = njt_snprintf(errbuf, *errbuf_size, "invalid signal")
                           - errbuf;
            break;

        case ESRCH:
            *errbuf_size = njt_snprintf(errbuf, *errbuf_size, "exited")
                           - errbuf;
            break;

        default:
            *errbuf_size = njt_snprintf(errbuf, *errbuf_size, "%s",
                                        strerror(njt_errno))
                           - errbuf;
        }

        return NJT_ERROR;
    }

    return NJT_OK;
}


static int
njt_http_lua_pipe_read_stdout_retval(njt_http_lua_ffi_pipe_proc_t *proc,
    lua_State *L)
{
    return njt_http_lua_pipe_read_retval_helper(proc, L, 0);
}


static int
njt_http_lua_pipe_read_stderr_retval(njt_http_lua_ffi_pipe_proc_t *proc,
    lua_State *L)
{
    return njt_http_lua_pipe_read_retval_helper(proc, L, 1);
}


static int
njt_http_lua_pipe_read_retval_helper(njt_http_lua_ffi_pipe_proc_t *proc,
    lua_State *L, int from_stderr)
{
    int                              rc;
    njt_msec_t                       timeout;
    njt_event_t                     *rev;
    njt_http_lua_pipe_t             *pipe;
    njt_http_lua_pipe_ctx_t         *pipe_ctx;

    pipe = proc->pipe;
    if (from_stderr) {
        pipe_ctx = pipe->stderr_ctx;

    } else {
        pipe_ctx = pipe->stdout_ctx;
    }

    if (pipe->timeout) {
        pipe->timeout = 0;
        pipe_ctx->err_type = PIPE_ERR_TIMEOUT;
        return 0;
    }

    if (pipe_ctx->err_type == PIPE_ERR_ABORTED) {
        njt_close_connection(pipe_ctx->c);
        pipe_ctx->c = NULL;
        return 0;
    }

    rc = njt_http_lua_pipe_read(pipe, pipe_ctx);
    if (rc != NJT_AGAIN) {
        return 0;
    }

    rev = pipe_ctx->c->read;

    if (from_stderr) {
        rev->handler = njt_http_lua_pipe_resume_read_stderr_handler;
        timeout = proc->stderr_read_timeout;

    } else {
        rev->handler = njt_http_lua_pipe_resume_read_stdout_handler;
        timeout = proc->stdout_read_timeout;
    }

    if (timeout > 0) {
        njt_add_timer(rev, timeout);
        njt_log_debug5(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "lua pipe add timer for reading: %d(ms) proc:%p "
                       "pid:%P pipe:%p ev:%p", timeout, proc, proc->_pid, pipe,
                       rev);
    }

    njt_log_debug3(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                   "lua pipe read yielding process:%p pid:%P pipe:%p", proc,
                   proc->_pid, pipe);

    return NJT_AGAIN;
}


static int
njt_http_lua_pipe_write_retval(njt_http_lua_ffi_pipe_proc_t *proc,
    lua_State *L)
{
    int                              rc;
    njt_msec_t                       timeout;
    njt_event_t                     *wev;
    njt_http_lua_pipe_t             *pipe;
    njt_http_lua_pipe_ctx_t         *pipe_ctx;

    pipe = proc->pipe;
    pipe_ctx = pipe->stdin_ctx;

    if (pipe->timeout) {
        pipe->timeout = 0;
        pipe_ctx->err_type = PIPE_ERR_TIMEOUT;
        return 0;
    }

    if (pipe_ctx->err_type == PIPE_ERR_ABORTED) {
        njt_close_connection(pipe_ctx->c);
        pipe_ctx->c = NULL;
        return 0;
    }

    rc = njt_http_lua_pipe_write(pipe, pipe_ctx);
    if (rc != NJT_AGAIN) {
        return 0;
    }

    wev = pipe_ctx->c->write;
    wev->handler = njt_http_lua_pipe_resume_write_handler;
    timeout = proc->write_timeout;

    if (timeout > 0) {
        njt_add_timer(wev, timeout);
        njt_log_debug5(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "lua pipe add timer for writing: %d(ms) proc:%p "
                       "pid:%P pipe:%p ev:%p", timeout, proc, proc->_pid, pipe,
                       wev);
    }

    njt_log_debug3(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                   "lua pipe write yielding process:%p pid:%P pipe:%p", proc,
                   proc->_pid, pipe);

    return NJT_AGAIN;
}


static int
njt_http_lua_pipe_wait_retval(njt_http_lua_ffi_pipe_proc_t *proc, lua_State *L)
{
    int                              nret;
    njt_rbtree_node_t               *node;
    njt_http_lua_pipe_t             *pipe;
    njt_http_lua_pipe_node_t        *pipe_node;

    pipe = proc->pipe;
    node = pipe->node;
    pipe_node = (njt_http_lua_pipe_node_t *) &node->color;
    pipe_node->wait_co_ctx = NULL;

    if (pipe->timeout) {
        pipe->timeout = 0;
        lua_pushnil(L);
        lua_pushliteral(L, "timeout");
        return 2;
    }

    njt_http_lua_pipe_proc_finalize(pipe_node->proc);

    if (pipe_node->status == 0) {
        lua_pushboolean(L, 1);
        lua_pushliteral(L, REASON_EXIT);
        lua_pushinteger(L, pipe_node->status);
        nret = 3;

    } else {
        lua_pushboolean(L, 0);

        switch (pipe_node->reason_code) {

        case REASON_EXIT_CODE:
            lua_pushliteral(L, REASON_EXIT);
            break;

        case REASON_SIGNAL_CODE:
            lua_pushliteral(L, REASON_SIGNAL);
            break;

        default:
            lua_pushliteral(L, REASON_UNKNOWN);
        }

        lua_pushinteger(L, pipe_node->status);
        nret = 3;
    }

    return nret;
}


static void
njt_http_lua_pipe_resume_helper(njt_event_t *ev,
    njt_http_lua_co_ctx_t *wait_co_ctx)
{
    njt_connection_t                *c;
    njt_http_request_t              *r;
    njt_http_lua_ctx_t              *ctx;
    njt_http_lua_pipe_t             *pipe;
    njt_http_lua_ffi_pipe_proc_t    *proc;

    if (ev->timedout) {
        proc = wait_co_ctx->data;
        pipe = proc->pipe;
        pipe->timeout = 1;
        ev->timedout = 0;
    }

    njt_http_lua_pipe_clear_event(ev);

    r = njt_http_lua_get_req(wait_co_ctx->co);
    c = r->connection;

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);
    njt_http_lua_assert(ctx != NULL);

    ctx->cur_co_ctx = wait_co_ctx;

    if (ctx->entered_content_phase) {
        (void) njt_http_lua_pipe_resume(r);

    } else {
        ctx->resume_handler = njt_http_lua_pipe_resume;
        njt_http_core_run_phases(r);
    }

    njt_http_run_posted_requests(c);
}


static void
njt_http_lua_pipe_resume_read_stdout_handler(njt_event_t *ev)
{
    njt_connection_t                *c = ev->data;
    njt_http_lua_co_ctx_t           *wait_co_ctx;
    njt_http_lua_pipe_t             *pipe;
    njt_http_lua_ffi_pipe_proc_t    *proc;

    wait_co_ctx = c->data;
    proc = wait_co_ctx->data;
    pipe = proc->pipe;
    pipe->retval_handler = njt_http_lua_pipe_read_stdout_retval;
    njt_http_lua_pipe_resume_helper(ev, wait_co_ctx);
}


static void
njt_http_lua_pipe_resume_read_stderr_handler(njt_event_t *ev)
{
    njt_connection_t                *c = ev->data;
    njt_http_lua_co_ctx_t           *wait_co_ctx;
    njt_http_lua_pipe_t             *pipe;
    njt_http_lua_ffi_pipe_proc_t    *proc;

    wait_co_ctx = c->data;
    proc = wait_co_ctx->data;
    pipe = proc->pipe;
    pipe->retval_handler = njt_http_lua_pipe_read_stderr_retval;
    njt_http_lua_pipe_resume_helper(ev, wait_co_ctx);
}


static void
njt_http_lua_pipe_resume_write_handler(njt_event_t *ev)
{
    njt_connection_t                *c = ev->data;
    njt_http_lua_co_ctx_t           *wait_co_ctx;
    njt_http_lua_pipe_t             *pipe;
    njt_http_lua_ffi_pipe_proc_t    *proc;

    wait_co_ctx = c->data;
    proc = wait_co_ctx->data;
    pipe = proc->pipe;
    pipe->retval_handler = njt_http_lua_pipe_write_retval;
    njt_http_lua_pipe_resume_helper(ev, wait_co_ctx);
}


static void
njt_http_lua_pipe_resume_wait_handler(njt_event_t *ev)
{
    njt_http_lua_co_ctx_t           *wait_co_ctx = ev->data;
    njt_http_lua_pipe_t             *pipe;
    njt_http_lua_ffi_pipe_proc_t    *proc;

    proc = wait_co_ctx->data;
    pipe = proc->pipe;
    pipe->retval_handler = njt_http_lua_pipe_wait_retval;
    njt_http_lua_pipe_resume_helper(ev, wait_co_ctx);
}


static njt_int_t
njt_http_lua_pipe_resume(njt_http_request_t *r)
{
    int                              nret;
    lua_State                       *vm;
    njt_int_t                        rc;
    njt_uint_t                       nreqs;
    njt_connection_t                *c;
    njt_http_lua_ctx_t              *ctx;
    njt_http_lua_pipe_t             *pipe;
    njt_http_lua_ffi_pipe_proc_t    *proc;

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);
    if (ctx == NULL) {
        return NJT_ERROR;
    }

    ctx->resume_handler = njt_http_lua_wev_handler;
    ctx->cur_co_ctx->cleanup = NULL;

    proc = ctx->cur_co_ctx->data;
    pipe = proc->pipe;
    nret = pipe->retval_handler(proc, ctx->cur_co_ctx->co);
    if (nret == NJT_AGAIN) {
        return NJT_DONE;
    }

    c = r->connection;
    vm = njt_http_lua_get_lua_vm(r, ctx);
    nreqs = c->requests;

    rc = njt_http_lua_run_thread(vm, r, ctx, nret);

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua run thread returned %d", rc);

    if (rc == NJT_AGAIN) {
        return njt_http_lua_run_posted_threads(c, vm, r, ctx, nreqs);
    }

    if (rc == NJT_DONE) {
        njt_http_lua_finalize_request(r, NJT_DONE);
        return njt_http_lua_run_posted_threads(c, vm, r, ctx, nreqs);
    }

    /* rc == NJT_ERROR || rc >= NJT_OK */

    if (ctx->entered_content_phase) {
        njt_http_lua_finalize_request(r, rc);
        return NJT_DONE;
    }

    return rc;
}


static void
njt_http_lua_pipe_dummy_event_handler(njt_event_t *ev)
{
    /* do nothing */
}


static void
njt_http_lua_pipe_clear_event(njt_event_t *ev)
{
    ev->handler = njt_http_lua_pipe_dummy_event_handler;

    if (ev->timer_set) {
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, ev->log, 0,
                       "lua pipe del timer for ev:%p", ev);
        njt_del_timer(ev);
    }

    if (ev->posted) {
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, ev->log, 0,
                       "lua pipe del posted event for ev:%p", ev);
        njt_delete_posted_event(ev);
    }
}


static void
njt_http_lua_pipe_proc_read_stdout_cleanup(void *data)
{
    njt_event_t                    *rev;
    njt_connection_t               *c;
    njt_http_lua_co_ctx_t          *wait_co_ctx = data;
    njt_http_lua_ffi_pipe_proc_t   *proc;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                   "lua pipe proc read stdout cleanup");

    proc = wait_co_ctx->data;
    c = proc->pipe->stdout_ctx->c;
    if (c) {
        rev = c->read;
        njt_http_lua_pipe_clear_event(rev);
    }

    wait_co_ctx->cleanup = NULL;
}


static void
njt_http_lua_pipe_proc_read_stderr_cleanup(void *data)
{
    njt_event_t                    *rev;
    njt_connection_t               *c;
    njt_http_lua_co_ctx_t          *wait_co_ctx = data;
    njt_http_lua_ffi_pipe_proc_t   *proc;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                   "lua pipe proc read stderr cleanup");

    proc = wait_co_ctx->data;
    c = proc->pipe->stderr_ctx->c;
    if (c) {
        rev = c->read;
        njt_http_lua_pipe_clear_event(rev);
    }

    wait_co_ctx->cleanup = NULL;
}


static void
njt_http_lua_pipe_proc_write_cleanup(void *data)
{
    njt_event_t                    *wev;
    njt_connection_t               *c;
    njt_http_lua_co_ctx_t          *wait_co_ctx = data;
    njt_http_lua_ffi_pipe_proc_t   *proc;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                   "lua pipe proc write cleanup");

    proc = wait_co_ctx->data;
    c = proc->pipe->stdin_ctx->c;
    if (c) {
        wev = c->write;
        njt_http_lua_pipe_clear_event(wev);
    }

    wait_co_ctx->cleanup = NULL;
}


static void
njt_http_lua_pipe_proc_wait_cleanup(void *data)
{
    njt_rbtree_node_t              *node;
    njt_http_lua_co_ctx_t          *wait_co_ctx = data;
    njt_http_lua_pipe_node_t       *pipe_node;
    njt_http_lua_ffi_pipe_proc_t   *proc;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                   "lua pipe proc wait cleanup");

    proc = wait_co_ctx->data;
    node = proc->pipe->node;
    pipe_node = (njt_http_lua_pipe_node_t *) &node->color;
    pipe_node->wait_co_ctx = NULL;

    njt_http_lua_pipe_clear_event(&wait_co_ctx->sleep);

    wait_co_ctx->cleanup = NULL;
}


#endif /* HAVE_NJT_LUA_PIPE */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
