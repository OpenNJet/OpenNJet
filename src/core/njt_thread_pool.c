
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) Ruslan Ermilov
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_thread_pool.h>


typedef struct {
    njt_array_t               pools;
} njt_thread_pool_conf_t;


typedef struct {
    njt_thread_task_t        *first;
    njt_thread_task_t       **last;
} njt_thread_pool_queue_t;

#define njt_thread_pool_queue_init(q)                                         \
    (q)->first = NULL;                                                        \
    (q)->last = &(q)->first


struct njt_thread_pool_s {
    njt_thread_mutex_t        mtx;
    njt_thread_pool_queue_t   queue;
    njt_int_t                 waiting;
    njt_thread_cond_t         cond;

    njt_log_t                *log;

    njt_str_t                 name;
    njt_uint_t                threads;
    njt_int_t                 max_queue;

    u_char                   *file;
    njt_uint_t                line;
};


static njt_int_t njt_thread_pool_init(njt_thread_pool_t *tp, njt_log_t *log,
    njt_pool_t *pool);
static void njt_thread_pool_destroy(njt_thread_pool_t *tp);
static void njt_thread_pool_exit_handler(void *data, njt_log_t *log);

static void *njt_thread_pool_cycle(void *data);
static void njt_thread_pool_handler(njt_event_t *ev);

static char *njt_thread_pool(njt_conf_t *cf, njt_command_t *cmd, void *conf);

static void *njt_thread_pool_create_conf(njt_cycle_t *cycle);
static char *njt_thread_pool_init_conf(njt_cycle_t *cycle, void *conf);

static njt_int_t njt_thread_pool_init_worker(njt_cycle_t *cycle);
static void njt_thread_pool_exit_worker(njt_cycle_t *cycle);


static njt_command_t  njt_thread_pool_commands[] = {

    { njt_string("thread_pool"),
      NJT_MAIN_CONF|NJT_DIRECT_CONF|NJT_CONF_TAKE23,
      njt_thread_pool,
      0,
      0,
      NULL },

      njt_null_command
};


static njt_core_module_t  njt_thread_pool_module_ctx = {
    njt_string("thread_pool"),
    njt_thread_pool_create_conf,
    njt_thread_pool_init_conf
};


njt_module_t  njt_thread_pool_module = {
    NJT_MODULE_V1,
    &njt_thread_pool_module_ctx,           /* module context */
    njt_thread_pool_commands,              /* module directives */
    NJT_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    njt_thread_pool_init_worker,           /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    njt_thread_pool_exit_worker,           /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};


static njt_str_t  njt_thread_pool_default = njt_string("default");

static njt_uint_t               njt_thread_pool_task_id;
static njt_atomic_t             njt_thread_pool_done_lock;
static njt_thread_pool_queue_t  njt_thread_pool_done;


static njt_int_t
njt_thread_pool_init(njt_thread_pool_t *tp, njt_log_t *log, njt_pool_t *pool)
{
    int             err;
    pthread_t       tid;
    njt_uint_t      n;
    pthread_attr_t  attr;

    if (njt_notify == NULL) {
        njt_log_error(NJT_LOG_ALERT, log, 0,
               "the configured event method cannot be used with thread pools");
        return NJT_ERROR;
    }

    njt_thread_pool_queue_init(&tp->queue);

    if (njt_thread_mutex_create(&tp->mtx, log) != NJT_OK) {
        return NJT_ERROR;
    }

    if (njt_thread_cond_create(&tp->cond, log) != NJT_OK) {
        (void) njt_thread_mutex_destroy(&tp->mtx, log);
        return NJT_ERROR;
    }

    tp->log = log;

    err = pthread_attr_init(&attr);
    if (err) {
        njt_log_error(NJT_LOG_ALERT, log, err,
                      "pthread_attr_init() failed");
        return NJT_ERROR;
    }

    err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (err) {
        njt_log_error(NJT_LOG_ALERT, log, err,
                      "pthread_attr_setdetachstate() failed");
        return NJT_ERROR;
    }

#if 0
    err = pthread_attr_setstacksize(&attr, PTHREAD_STACK_MIN);
    if (err) {
        njt_log_error(NJT_LOG_ALERT, log, err,
                      "pthread_attr_setstacksize() failed");
        return NJT_ERROR;
    }
#endif

    for (n = 0; n < tp->threads; n++) {
        err = pthread_create(&tid, &attr, njt_thread_pool_cycle, tp);
        if (err) {
            njt_log_error(NJT_LOG_ALERT, log, err,
                          "pthread_create() failed");
            return NJT_ERROR;
        }
    }

    (void) pthread_attr_destroy(&attr);

    return NJT_OK;
}


static void
njt_thread_pool_destroy(njt_thread_pool_t *tp)
{
    njt_uint_t           n;
    njt_thread_task_t    task;
    volatile njt_uint_t  lock;

    njt_memzero(&task, sizeof(njt_thread_task_t));

    task.handler = njt_thread_pool_exit_handler;
    task.ctx = (void *) &lock;

    for (n = 0; n < tp->threads; n++) {
        lock = 1;

        if (njt_thread_task_post(tp, &task) != NJT_OK) {
            return;
        }

        while (lock) {
            njt_sched_yield();
        }

        task.event.active = 0;
    }

    (void) njt_thread_cond_destroy(&tp->cond, tp->log);

    (void) njt_thread_mutex_destroy(&tp->mtx, tp->log);
}


static void
njt_thread_pool_exit_handler(void *data, njt_log_t *log)
{
    njt_uint_t *lock = data;

    *lock = 0;

    pthread_exit(0);
}


njt_thread_task_t *
njt_thread_task_alloc(njt_pool_t *pool, size_t size)
{
    njt_thread_task_t  *task;

    task = njt_pcalloc(pool, sizeof(njt_thread_task_t) + size);
    if (task == NULL) {
        return NULL;
    }

    task->ctx = task + 1;

    return task;
}


njt_int_t
njt_thread_task_post(njt_thread_pool_t *tp, njt_thread_task_t *task)
{
    if (task->event.active) {
        njt_log_error(NJT_LOG_ALERT, tp->log, 0,
                      "task #%ui already active", task->id);
        return NJT_ERROR;
    }

    if (njt_thread_mutex_lock(&tp->mtx, tp->log) != NJT_OK) {
        return NJT_ERROR;
    }

    if (tp->waiting >= tp->max_queue) {
        (void) njt_thread_mutex_unlock(&tp->mtx, tp->log);

        njt_log_error(NJT_LOG_ERR, tp->log, 0,
                      "thread pool \"%V\" queue overflow: %i tasks waiting",
                      &tp->name, tp->waiting);
        return NJT_ERROR;
    }

    task->event.active = 1;

    task->id = njt_thread_pool_task_id++;
    task->next = NULL;

    if (njt_thread_cond_signal(&tp->cond, tp->log) != NJT_OK) {
        (void) njt_thread_mutex_unlock(&tp->mtx, tp->log);
        return NJT_ERROR;
    }

    *tp->queue.last = task;
    tp->queue.last = &task->next;

    tp->waiting++;

    (void) njt_thread_mutex_unlock(&tp->mtx, tp->log);

    njt_log_debug2(NJT_LOG_DEBUG_CORE, tp->log, 0,
                   "task #%ui added to thread pool \"%V\"",
                   task->id, &tp->name);

    return NJT_OK;
}


static void *
njt_thread_pool_cycle(void *data)
{
    njt_thread_pool_t *tp = data;

    int                 err;
    sigset_t            set;
    njt_thread_task_t  *task;

#if 0
    njt_time_update();
#endif

    njt_log_debug1(NJT_LOG_DEBUG_CORE, tp->log, 0,
                   "thread in pool \"%V\" started", &tp->name);

    sigfillset(&set);

    sigdelset(&set, SIGILL);
    sigdelset(&set, SIGFPE);
    sigdelset(&set, SIGSEGV);
    sigdelset(&set, SIGBUS);

    err = pthread_sigmask(SIG_BLOCK, &set, NULL);
    if (err) {
        njt_log_error(NJT_LOG_ALERT, tp->log, err, "pthread_sigmask() failed");
        return NULL;
    }

    for ( ;; ) {
        if (njt_thread_mutex_lock(&tp->mtx, tp->log) != NJT_OK) {
            return NULL;
        }

        /* the number may become negative */
        tp->waiting--;

        while (tp->queue.first == NULL) {
            if (njt_thread_cond_wait(&tp->cond, &tp->mtx, tp->log)
                != NJT_OK)
            {
                (void) njt_thread_mutex_unlock(&tp->mtx, tp->log);
                return NULL;
            }
        }

        task = tp->queue.first;
        tp->queue.first = task->next;

        if (tp->queue.first == NULL) {
            tp->queue.last = &tp->queue.first;
        }

        if (njt_thread_mutex_unlock(&tp->mtx, tp->log) != NJT_OK) {
            return NULL;
        }

#if 0
        njt_time_update();
#endif

        njt_log_debug2(NJT_LOG_DEBUG_CORE, tp->log, 0,
                       "run task #%ui in thread pool \"%V\"",
                       task->id, &tp->name);

        task->handler(task->ctx, tp->log);

        njt_log_debug2(NJT_LOG_DEBUG_CORE, tp->log, 0,
                       "complete task #%ui in thread pool \"%V\"",
                       task->id, &tp->name);

        task->next = NULL;

        njt_spinlock(&njt_thread_pool_done_lock, 1, 2048);

        *njt_thread_pool_done.last = task;
        njt_thread_pool_done.last = &task->next;

        njt_memory_barrier();

        njt_unlock(&njt_thread_pool_done_lock);

        (void) njt_notify(njt_thread_pool_handler);
    }
}


static void
njt_thread_pool_handler(njt_event_t *ev)
{
    njt_event_t        *event;
    njt_thread_task_t  *task;

    njt_log_debug0(NJT_LOG_DEBUG_CORE, ev->log, 0, "thread pool handler");

    njt_spinlock(&njt_thread_pool_done_lock, 1, 2048);

    task = njt_thread_pool_done.first;
    njt_thread_pool_done.first = NULL;
    njt_thread_pool_done.last = &njt_thread_pool_done.first;

    njt_memory_barrier();

    njt_unlock(&njt_thread_pool_done_lock);

    while (task) {
        njt_log_debug1(NJT_LOG_DEBUG_CORE, ev->log, 0,
                       "run completion handler for task #%ui", task->id);

        event = &task->event;
        task = task->next;

        event->complete = 1;
        event->active = 0;

        event->handler(event);
    }
}


static void *
njt_thread_pool_create_conf(njt_cycle_t *cycle)
{
    njt_thread_pool_conf_t  *tcf;

    tcf = njt_pcalloc(cycle->pool, sizeof(njt_thread_pool_conf_t));
    if (tcf == NULL) {
        return NULL;
    }

    if (njt_array_init(&tcf->pools, cycle->pool, 4,
                       sizeof(njt_thread_pool_t *))
        != NJT_OK)
    {
        return NULL;
    }

    return tcf;
}


static char *
njt_thread_pool_init_conf(njt_cycle_t *cycle, void *conf)
{
    njt_thread_pool_conf_t *tcf = conf;

    njt_uint_t           i;
    njt_thread_pool_t  **tpp;

    tpp = tcf->pools.elts;

    for (i = 0; i < tcf->pools.nelts; i++) {

        if (tpp[i]->threads) {
            continue;
        }

        if (tpp[i]->name.len == njt_thread_pool_default.len
            && njt_strncmp(tpp[i]->name.data, njt_thread_pool_default.data,
                           njt_thread_pool_default.len)
               == 0)
        {
            tpp[i]->threads = 32;
            tpp[i]->max_queue = 65536;
            continue;
        }

        njt_log_error(NJT_LOG_EMERG, cycle->log, 0,
                      "unknown thread pool \"%V\" in %s:%ui",
                      &tpp[i]->name, tpp[i]->file, tpp[i]->line);

        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


static char *
njt_thread_pool(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_str_t          *value;
    njt_uint_t          i;
    njt_thread_pool_t  *tp;

    value = cf->args->elts;

    tp = njt_thread_pool_add(cf, &value[1]);

    if (tp == NULL) {
        return NJT_CONF_ERROR;
    }

    if (tp->threads) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "duplicate thread pool \"%V\"", &tp->name);
        return NJT_CONF_ERROR;
    }

    tp->max_queue = 65536;

    for (i = 2; i < cf->args->nelts; i++) {

        if (njt_strncmp(value[i].data, "threads=", 8) == 0) {

            tp->threads = njt_atoi(value[i].data + 8, value[i].len - 8);

            if (tp->threads == (njt_uint_t) NJT_ERROR || tp->threads == 0) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid threads value \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "max_queue=", 10) == 0) {

            tp->max_queue = njt_atoi(value[i].data + 10, value[i].len - 10);

            if (tp->max_queue == NJT_ERROR) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid max_queue value \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            continue;
        }
    }

    if (tp->threads == 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"threads\" parameter",
                           &cmd->name);
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


njt_thread_pool_t *
njt_thread_pool_add(njt_conf_t *cf, njt_str_t *name)
{
    njt_thread_pool_t       *tp, **tpp;
    njt_thread_pool_conf_t  *tcf;

    if (name == NULL) {
        name = &njt_thread_pool_default;
    }

    tp = njt_thread_pool_get(cf->cycle, name);

    if (tp) {
        return tp;
    }

    tp = njt_pcalloc(cf->pool, sizeof(njt_thread_pool_t));
    if (tp == NULL) {
        return NULL;
    }

    tp->name = *name;
    tp->file = cf->conf_file->file.name.data;
    tp->line = cf->conf_file->line;

    tcf = (njt_thread_pool_conf_t *) njt_get_conf(cf->cycle->conf_ctx,
                                                  njt_thread_pool_module);

    tpp = njt_array_push(&tcf->pools);
    if (tpp == NULL) {
        return NULL;
    }

    *tpp = tp;

    return tp;
}


njt_thread_pool_t *
njt_thread_pool_get(njt_cycle_t *cycle, njt_str_t *name)
{
    njt_uint_t                i;
    njt_thread_pool_t       **tpp;
    njt_thread_pool_conf_t   *tcf;

    tcf = (njt_thread_pool_conf_t *) njt_get_conf(cycle->conf_ctx,
                                                  njt_thread_pool_module);

    tpp = tcf->pools.elts;

    for (i = 0; i < tcf->pools.nelts; i++) {

        if (tpp[i]->name.len == name->len
            && njt_strncmp(tpp[i]->name.data, name->data, name->len) == 0)
        {
            return tpp[i];
        }
    }

    return NULL;
}


static njt_int_t
njt_thread_pool_init_worker(njt_cycle_t *cycle)
{
    njt_uint_t                i;
    njt_thread_pool_t       **tpp;
    njt_thread_pool_conf_t   *tcf;

    if (njt_process != NJT_PROCESS_WORKER
        && njt_process != NJT_PROCESS_SINGLE)
    {
        return NJT_OK;
    }

    tcf = (njt_thread_pool_conf_t *) njt_get_conf(cycle->conf_ctx,
                                                  njt_thread_pool_module);

    if (tcf == NULL) {
        return NJT_OK;
    }

    njt_thread_pool_queue_init(&njt_thread_pool_done);

    tpp = tcf->pools.elts;

    for (i = 0; i < tcf->pools.nelts; i++) {
        if (njt_thread_pool_init(tpp[i], cycle->log, cycle->pool) != NJT_OK) {
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}


static void
njt_thread_pool_exit_worker(njt_cycle_t *cycle)
{
    njt_uint_t                i;
    njt_thread_pool_t       **tpp;
    njt_thread_pool_conf_t   *tcf;

    if (njt_process != NJT_PROCESS_WORKER
        && njt_process != NJT_PROCESS_SINGLE)
    {
        return;
    }

    tcf = (njt_thread_pool_conf_t *) njt_get_conf(cycle->conf_ctx,
                                                  njt_thread_pool_module);

    if (tcf == NULL) {
        return;
    }

    tpp = tcf->pools.elts;

    for (i = 0; i < tcf->pools.nelts; i++) {
        njt_thread_pool_destroy(tpp[i]);
    }
}
