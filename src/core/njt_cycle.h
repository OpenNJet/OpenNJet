
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_CYCLE_H_INCLUDED_
#define _NJT_CYCLE_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


#ifndef NJT_CYCLE_POOL_SIZE
#define NJT_CYCLE_POOL_SIZE     NJT_DEFAULT_POOL_SIZE
#endif


#define NJT_DEBUG_POINTS_STOP   1
#define NJT_DEBUG_POINTS_ABORT  2
#define HAVE_PRIVILEGED_PROCESS_PATCH   1

#define HAVE_INTERCEPT_ERROR_LOG_PATCH // openresty patch

typedef struct njt_shm_zone_s  njt_shm_zone_t;

typedef njt_int_t (*njt_shm_zone_init_pt) (njt_shm_zone_t *zone, void *data);
typedef njt_int_t (*njt_log_intercept_pt) (njt_log_t *log, njt_uint_t level, 
    u_char *buf, size_t len); // openresty patch

struct njt_shm_zone_s {
    void                     *data;
    njt_shm_t                 shm;
    njt_shm_zone_init_pt      init;
    njt_shm_zone_init_pt      merge;
    void                     *tag;
    void                     *sync;
    njt_uint_t                noreuse;  /* unsigned  noreuse:1; */
};


struct njt_cycle_s {
    void                  ****conf_ctx;
    njt_pool_t               *pool;

    njt_log_t                *log;
    njt_log_t                 new_log;

    njt_uint_t                log_use_stderr;  /* unsigned  log_use_stderr:1; */

    njt_connection_t        **files;
    njt_connection_t         *free_connections;
    njt_uint_t                free_connection_n;

    njt_module_t            **modules;
    njt_uint_t                modules_n;
    njt_uint_t                modules_used;    /* unsigned  modules_used:1; */

    njt_queue_t               reusable_connections_queue;
    njt_uint_t                reusable_connections_n;
    time_t                    connections_reuse_time;

    njt_array_t               listening;
    njt_array_t               paths;

    njt_array_t               config_dump;
    njt_rbtree_t              config_dump_rbtree;
    njt_rbtree_node_t         config_dump_sentinel;
    njt_rbtree_t              old_config_dump_rbtree;

    njt_list_t                open_files;
    njt_list_t                shared_memory;

    njt_uint_t                connection_n;
    njt_uint_t                files_n;

    njt_connection_t         *connections;
    njt_event_t              *read_events;
    njt_event_t              *write_events;

    njt_cycle_t              *old_cycle;

    njt_str_t                 conf_file;
    njt_str_t                 conf_param;
    njt_str_t                 conf_prefix;
    njt_str_t                 prefix;
    njt_str_t                 error_log;
    njt_str_t                 lock_file;
    njt_str_t                 hostname;
    void                     *conf_root; // by lcm for dyn conf
    
    njt_log_intercept_pt      intercept_error_log_handler;  // openresy patch
    void                     *intercept_error_log_data; // openresty patch
    unsigned                  entered_logger;    /* :1 */ // openresty patch

};


typedef struct {
    njt_flag_t                daemon;
    njt_flag_t                master;

    njt_flag_t                privileged_agent;
    njt_uint_t                privileged_agent_connections;

    njt_msec_t                timer_resolution;
    njt_msec_t                shutdown_timeout;

    njt_int_t                 worker_processes;
    njt_int_t                 debug_points;

    njt_int_t                 rlimit_nofile;
    off_t                     rlimit_core;

    int                       priority;

    njt_uint_t                cpu_affinity_auto;
    njt_uint_t                cpu_affinity_n;
    njt_cpuset_t             *cpu_affinity;

    char                     *username;
    njt_uid_t                 user;
    njt_gid_t                 group;

    njt_str_t                 working_directory;
    njt_str_t                 lock_file;

    njt_str_t                 pid;
    njt_str_t                 oldpid;

    njt_array_t               env;
    char                    **environment;

    njt_uint_t                transparent;  /* unsigned  transparent:1; */
} njt_core_conf_t;


#define njt_is_init_cycle(cycle)  (cycle->conf_ctx == NULL)


njt_cycle_t *njt_init_cycle(njt_cycle_t *old_cycle);
njt_int_t njt_create_pidfile(njt_str_t *name, njt_log_t *log);
void njt_delete_pidfile(njt_cycle_t *cycle);
njt_int_t njt_signal_process(njt_cycle_t *cycle, char *sig);
void njt_reopen_files(njt_cycle_t *cycle, njt_uid_t user);
char **njt_set_environment(njt_cycle_t *cycle, njt_uint_t *last);
njt_pid_t njt_exec_new_binary(njt_cycle_t *cycle, char *const *argv);
njt_cpuset_t *njt_get_cpu_affinity(njt_uint_t n);
njt_shm_zone_t *njt_shared_memory_add(njt_conf_t *cf, njt_str_t *name,
    size_t size, void *tag);
void njt_set_shutdown_timer(njt_cycle_t *cycle);


extern volatile njt_cycle_t  *njt_cycle;
extern njt_array_t            njt_old_cycles;
extern njt_module_t           njt_core_module;
extern njt_uint_t             njt_test_config;
extern njt_uint_t             njt_dump_config;
extern njt_uint_t             njt_quiet_mode;


#endif /* _NJT_CYCLE_H_INCLUDED_ */
