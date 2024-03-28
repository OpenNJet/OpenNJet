
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njet.h>


static void njt_show_version_info(void);
static njt_int_t njt_add_inherited_sockets(njt_cycle_t *cycle);
static void njt_cleanup_environment(void *data);
static void njt_cleanup_environment_variable(void *data);
static njt_int_t njt_get_options(int argc, char *const *argv);
static njt_int_t njt_process_options(njt_cycle_t *cycle);
static njt_int_t njt_save_argv(njt_cycle_t *cycle, int argc, char *const *argv);
static void *njt_core_module_create_conf(njt_cycle_t *cycle);
static char *njt_core_module_init_conf(njt_cycle_t *cycle, void *conf);
static char *njt_set_user(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static char *njt_set_env(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static char *njt_set_priority(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static char *njt_set_cpu_affinity(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_set_worker_processes(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_load_module(njt_conf_t *cf, njt_command_t *cmd, void *conf);
#if (NJT_HAVE_DLOPEN)
static void njt_unload_module(void *data);
#endif


static njt_conf_enum_t  njt_debug_points[] = {
    { njt_string("stop"), NJT_DEBUG_POINTS_STOP },
    { njt_string("abort"), NJT_DEBUG_POINTS_ABORT },
    { njt_null_string, 0 }
};


static njt_command_t  njt_core_commands[] = {

    { njt_string("daemon"),
      NJT_MAIN_CONF|NJT_DIRECT_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      0,
      offsetof(njt_core_conf_t, daemon),
      NULL },

    { njt_string("master_process"),
      NJT_MAIN_CONF|NJT_DIRECT_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      0,
      offsetof(njt_core_conf_t, master),
      NULL },

    { njt_string("timer_resolution"),
      NJT_MAIN_CONF|NJT_DIRECT_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      0,
      offsetof(njt_core_conf_t, timer_resolution),
      NULL },

    { njt_string("pid"),
      NJT_MAIN_CONF|NJT_DIRECT_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      0,
      offsetof(njt_core_conf_t, pid),
      NULL },

    { njt_string("lock_file"),
      NJT_MAIN_CONF|NJT_DIRECT_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      0,
      offsetof(njt_core_conf_t, lock_file),
      NULL },

    { njt_string("worker_processes"),
      NJT_MAIN_CONF|NJT_DIRECT_CONF|NJT_CONF_TAKE1,
      njt_set_worker_processes,
      0,
      0,
      NULL },

    { njt_string("debug_points"),
      NJT_MAIN_CONF|NJT_DIRECT_CONF|NJT_CONF_TAKE1,
      njt_conf_set_enum_slot,
      0,
      offsetof(njt_core_conf_t, debug_points),
      &njt_debug_points },

    { njt_string("user"),
      NJT_MAIN_CONF|NJT_DIRECT_CONF|NJT_CONF_TAKE12,
      njt_set_user,
      0,
      0,
      NULL },

    { njt_string("worker_priority"),
      NJT_MAIN_CONF|NJT_DIRECT_CONF|NJT_CONF_TAKE1,
      njt_set_priority,
      0,
      0,
      NULL },

    { njt_string("worker_cpu_affinity"),
      NJT_MAIN_CONF|NJT_DIRECT_CONF|NJT_CONF_1MORE,
      njt_set_cpu_affinity,
      0,
      0,
      NULL },

    { njt_string("worker_rlimit_nofile"),
      NJT_MAIN_CONF|NJT_DIRECT_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      0,
      offsetof(njt_core_conf_t, rlimit_nofile),
      NULL },

    { njt_string("worker_rlimit_core"),
      NJT_MAIN_CONF|NJT_DIRECT_CONF|NJT_CONF_TAKE1,
      njt_conf_set_off_slot,
      0,
      offsetof(njt_core_conf_t, rlimit_core),
      NULL },

    { njt_string("worker_shutdown_timeout"),
      NJT_MAIN_CONF|NJT_DIRECT_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      0,
      offsetof(njt_core_conf_t, shutdown_timeout),
      NULL },

    { njt_string("working_directory"),
      NJT_MAIN_CONF|NJT_DIRECT_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      0,
      offsetof(njt_core_conf_t, working_directory),
      NULL },

    { njt_string("env"),
      NJT_MAIN_CONF|NJT_DIRECT_CONF|NJT_CONF_TAKE1,
      njt_set_env,
      0,
      0,
      NULL },

    { njt_string("load_module"),
      NJT_MAIN_CONF|NJT_DIRECT_CONF|NJT_CONF_TAKE1,
      njt_load_module,
      0,
      0,
      NULL },
    
    { njt_string("privileged_agent"),
      NJT_MAIN_CONF|NJT_DIRECT_CONF|NJT_CONF_TAKE1,
      njt_conf_set_flag_slot,
      0,
      offsetof(njt_core_conf_t, privileged_agent),
      NULL },
    
    { njt_string("privileged_agent_connections"),
      NJT_MAIN_CONF|NJT_DIRECT_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      0,
      offsetof(njt_core_conf_t, privileged_agent_connections),
      NULL },
    

      njt_null_command
};


static njt_core_module_t  njt_core_module_ctx = {
    njt_string("core"),
    njt_core_module_create_conf,
    njt_core_module_init_conf
};


njt_module_t  njt_core_module = {
    NJT_MODULE_V1,
    &njt_core_module_ctx,                  /* module context */
    njt_core_commands,                     /* module directives */
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


static njt_uint_t   njt_show_help;
static njt_uint_t   njt_show_version;
static njt_uint_t   njt_show_configure;
static u_char      *njt_prefix;
static u_char      *njt_error_log;
static u_char      *njt_conf_file;
static u_char      *njt_conf_params;
static char        *njt_signal;
njt_pool_t         *saved_init_cycle_pool = NULL; // openresty patch


static char **njt_os_environ;


int njt_cdecl
main(int argc, char *const *argv)
{
    njt_buf_t        *b;
    njt_log_t        *log;
    njt_uint_t        i;
    njt_cycle_t      *cycle, init_cycle;
    njt_conf_dump_t  *cd;
    njt_core_conf_t  *ccf;
#if (NJT_DEBUG)
    njt_int_t  rc;
#endif
    njt_debug_init();

    if (njt_strerror_init() != NJT_OK) {
        return 1;
    }

    if (njt_get_options(argc, argv) != NJT_OK) {
        return 1;
    }

    if (njt_show_version) {
        njt_show_version_info();

        if (!njt_test_config) {
            return 0;
        }
    }

    /* TODO */ njt_max_sockets = -1;

    njt_time_init();

#if (NJT_PCRE)
    njt_regex_init();
#endif

    njt_pid = njt_getpid();
    njt_parent = njt_getppid();

    log = njt_log_init(njt_prefix, njt_error_log);
    if (log == NULL) {
        return 1;
    }

    /* STUB */
#if (NJT_OPENSSL)
    njt_ssl_init(log);
#endif

    /*
     * init_cycle->log is required for signal handlers and
     * njt_process_options()
     */

    njt_memzero(&init_cycle, sizeof(njt_cycle_t));
    init_cycle.log = log;
    njt_cycle = &init_cycle;

    init_cycle.pool = njt_create_pool(1024, log);
    if (init_cycle.pool == NULL) {
        return 1;
    }

    if (njt_save_argv(&init_cycle, argc, argv) != NJT_OK) {
        return 1;
    }

    saved_init_cycle_pool = init_cycle.pool; // openresty patch

    if (njt_process_options(&init_cycle) != NJT_OK) {
        return 1;
    }

    if (njt_os_init(log) != NJT_OK) {
        return 1;
    }

    /*
     * njt_crc32_table_init() requires njt_cacheline_size set in njt_os_init()
     */

    if (njt_crc32_table_init() != NJT_OK) {
        return 1;
    }

    /*
     * njt_slab_sizes_init() requires njt_pagesize set in njt_os_init()
     */

    njt_slab_sizes_init();

    if (njt_add_inherited_sockets(&init_cycle) != NJT_OK) {
        return 1;
    }

    if (njt_preinit_modules() != NJT_OK) {
        return 1;
    }

    cycle = njt_init_cycle(&init_cycle);
    if (cycle == NULL) {
        if (njt_test_config) {
            njt_log_stderr(0, "configuration file %s test failed",
                           init_cycle.conf_file.data);
        }
#if (NJT_DEBUG)
	njt_destroy_pool(init_cycle.pool);
#endif
        return 1;
    }

    if (njt_test_config) {
        if (!njt_quiet_mode) {
            njt_log_stderr(0, "configuration file %s test is successful",
                           cycle->conf_file.data);
        }

        if (njt_dump_config) {
            cd = cycle->config_dump.elts;

            for (i = 0; i < cycle->config_dump.nelts; i++) {

                njt_write_stdout("# configuration file ");
                (void) njt_write_fd(njt_stdout, cd[i].name.data,
                                    cd[i].name.len);
                njt_write_stdout(":" NJT_LINEFEED);

                b = cd[i].buffer;

                (void) njt_write_fd(njt_stdout, b->pos, b->last - b->pos);
                njt_write_stdout(NJT_LINEFEED);
            }
        }

        return 0;
    }

    if (njt_signal) {
#if (NJT_DEBUG)
        rc = njt_signal_process(cycle, njt_signal);
    	njt_destroy_pool(init_cycle.pool);
	return rc;
#else
	return njt_signal_process(cycle, njt_signal);
#endif
    }

    njt_os_status(cycle->log);

    njt_cycle = cycle;

    ccf = (njt_core_conf_t *) njt_get_conf(cycle->conf_ctx, njt_core_module);

    if (ccf->master && njt_process == NJT_PROCESS_SINGLE) {
        njt_process = NJT_PROCESS_MASTER;
    }

#if !(NJT_WIN32)

    if (njt_init_signals(cycle->log) != NJT_OK) {
        return 1;
    }

    if (!njt_inherited && ccf->daemon) {
        if (njt_daemon(cycle->log) != NJT_OK) {
            return 1;
        }

        njt_daemonized = 1;
    }

    if (njt_inherited) {
        njt_daemonized = 1;
    }

#endif

    if (njt_create_pidfile(&ccf->pid, cycle->log) != NJT_OK) {
        return 1;
    }

    if (njt_log_redirect_stderr(cycle) != NJT_OK) {
        return 1;
    }

    if (log->file->fd != njt_stderr) {
        if (njt_close_file(log->file->fd) == NJT_FILE_ERROR) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                          njt_close_file_n " built-in log failed");
        }
    }

    njt_use_stderr = 0;

    if (njt_process == NJT_PROCESS_SINGLE) {
        njt_single_process_cycle(cycle);

    } else {
        njt_master_process_cycle(cycle);
    }

    return 0;
}


static void
njt_show_version_info(void)
{
    if (!njt_show_configure) {
        njt_write_stderr("njet version: " NJT_VER_BUILD NJT_LINEFEED);
    }

    if (njt_show_help) {
        njt_write_stderr(
            "Usage: njet [-?hvVtTq] [-s signal] [-p prefix]" NJT_LINEFEED
            "             [-e filename] [-c filename] [-g directives]"
                          NJT_LINEFEED NJT_LINEFEED
            "Options:" NJT_LINEFEED
            "  -?,-h         : this help" NJT_LINEFEED
            "  -v            : show version and exit" NJT_LINEFEED
            "  -V            : show version and configure options then exit"
                               NJT_LINEFEED
            "  -t            : test configuration and exit" NJT_LINEFEED
            "  -T            : test configuration, dump it and exit"
                               NJT_LINEFEED
            "  -q            : suppress non-error messages "
                               "during configuration testing" NJT_LINEFEED
            "  -s signal     : send signal to a master process: "
                               "stop, quit, reopen, reload" NJT_LINEFEED
#ifdef NJT_PREFIX
            "  -p prefix     : set prefix path (default: " NJT_PREFIX ")"
                               NJT_LINEFEED
#else
            "  -p prefix     : set prefix path (default: NONE)" NJT_LINEFEED
#endif
            "  -e filename   : set error log file (default: "
#ifdef NJT_ERROR_LOG_STDERR
                               "stderr)" NJT_LINEFEED
#else
                               NJT_ERROR_LOG_PATH ")" NJT_LINEFEED
#endif
            "  -c filename   : set configuration file (default: " NJT_CONF_PATH
                               ")" NJT_LINEFEED
            "  -g directives : set global directives out of configuration "
                               "file" NJT_LINEFEED NJT_LINEFEED
        );
    }

    if (njt_show_configure) {
        njt_write_stderr("njet version: " NJT_VER_BUILD);
        njt_write_stderr(" (developed based on " NGNX_VER " and "RESTY_VER ")" NJT_LINEFEED);

#ifdef NJT_COMPILER
        njt_write_stderr("built by " NJT_COMPILER NJT_LINEFEED);
#endif

#if (NJT_SSL)
        if (njt_strcmp(njt_ssl_version(), OPENSSL_VERSION_TEXT) == 0) {
            njt_write_stderr("built with " OPENSSL_VERSION_TEXT NJT_LINEFEED);
        } else {
            njt_write_stderr("built with " OPENSSL_VERSION_TEXT
                             " (running with ");
            njt_write_stderr((char *) (uintptr_t) njt_ssl_version());
            njt_write_stderr(")" NJT_LINEFEED);
        }
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
        njt_write_stderr("TLS SNI support enabled" NJT_LINEFEED);
#else
        njt_write_stderr("TLS SNI support disabled" NJT_LINEFEED);
#endif
#endif

        njt_write_stderr("configure arguments:" NJT_CONFIGURE NJT_LINEFEED);
    }
}


static njt_int_t
njt_add_inherited_sockets(njt_cycle_t *cycle)
{
    u_char           *p, *v, *inherited;
    njt_int_t         s;
    njt_listening_t  *ls;

    inherited = (u_char *) getenv(NJT_VAR);

    if (inherited == NULL) {
        return NJT_OK;
    }

    njt_log_error(NJT_LOG_NOTICE, cycle->log, 0,
                  "using inherited sockets from \"%s\"", inherited);

    if (njt_array_init(&cycle->listening, cycle->pool, 10,
                       sizeof(njt_listening_t))
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    for (p = inherited, v = p; *p; p++) {
        if (*p == ':' || *p == ';') {
            s = njt_atoi(v, p - v);
            if (s == NJT_ERROR) {
                njt_log_error(NJT_LOG_EMERG, cycle->log, 0,
                              "invalid socket number \"%s\" in " NJT_VAR
                              " environment variable, ignoring the rest"
                              " of the variable", v);
                break;
            }

            v = p + 1;

            ls = njt_array_push(&cycle->listening);
            if (ls == NULL) {
                return NJT_ERROR;
            }

            njt_memzero(ls, sizeof(njt_listening_t));

            ls->fd = (njt_socket_t) s;
            ls->inherited = 1;
        }
    }

    if (v != p) {
        njt_log_error(NJT_LOG_EMERG, cycle->log, 0,
                      "invalid socket number \"%s\" in " NJT_VAR
                      " environment variable, ignoring", v);
    }

    njt_inherited = 1;

    return njt_set_inherited_sockets(cycle);
}


char **
njt_set_environment(njt_cycle_t *cycle, njt_uint_t *last)
{
    char                **p, **env, *str;
    size_t                len;
    njt_str_t            *var;
    njt_uint_t            i, n;
    njt_core_conf_t      *ccf;
    njt_pool_cleanup_t   *cln;

    ccf = (njt_core_conf_t *) njt_get_conf(cycle->conf_ctx, njt_core_module);

    if (last == NULL && ccf->environment) {
        return ccf->environment;
    }

    var = ccf->env.elts;

    for (i = 0; i < ccf->env.nelts; i++) {
        if (njt_strcmp(var[i].data, "TZ") == 0
            || njt_strncmp(var[i].data, "TZ=", 3) == 0)
        {
            goto tz_found;
        }
    }

    var = njt_array_push(&ccf->env);
    if (var == NULL) {
        return NULL;
    }

    var->len = 2;
    var->data = (u_char *) "TZ";

    var = ccf->env.elts;

tz_found:

    n = 0;

    for (i = 0; i < ccf->env.nelts; i++) {

        if (var[i].data[var[i].len] == '=') {
            n++;
            continue;
        }

        for (p = njt_os_environ; *p; p++) {

            if (njt_strncmp(*p, var[i].data, var[i].len) == 0
                && (*p)[var[i].len] == '=')
            {
                n++;
                break;
            }
        }
    }

    if (last) {
        env = njt_alloc((*last + n + 1) * sizeof(char *), cycle->log);
        if (env == NULL) {
            return NULL;
        }

        *last = n;

    } else {
        cln = njt_pool_cleanup_add(cycle->pool, 0);
        if (cln == NULL) {
            return NULL;
        }

        env = njt_alloc((n + 1) * sizeof(char *), cycle->log);
        if (env == NULL) {
            return NULL;
        }

        cln->handler = njt_cleanup_environment;
        cln->data = env;
    }

    n = 0;

    for (i = 0; i < ccf->env.nelts; i++) {

        if (var[i].data[var[i].len] == '=') {

            if (last) {
                env[n++] = (char *) var[i].data;
                continue;
            }

            cln = njt_pool_cleanup_add(cycle->pool, 0);
            if (cln == NULL) {
                return NULL;
            }

            len = njt_strlen(var[i].data) + 1;

            str = njt_alloc(len, cycle->log);
            if (str == NULL) {
                return NULL;
            }

            njt_memcpy(str, var[i].data, len);

            cln->handler = njt_cleanup_environment_variable;
            cln->data = str;

            env[n++] = str;

            continue;
        }

        for (p = njt_os_environ; *p; p++) {

            if (njt_strncmp(*p, var[i].data, var[i].len) == 0
                && (*p)[var[i].len] == '=')
            {
                env[n++] = *p;
                break;
            }
        }
    }

    env[n] = NULL;

    if (last == NULL) {
        ccf->environment = env;
        environ = env;
    }

    return env;
}


static void
njt_cleanup_environment(void *data)
{
    char  **env = data;

    if (environ == env) {

        /*
         * if the environment is still used, as it happens on exit,
         * the only option is to leak it
         */

        return;
    }

    njt_free(env);
}


static void
njt_cleanup_environment_variable(void *data)
{
    char  *var = data;

    char  **p;

    for (p = environ; *p; p++) {

        /*
         * if an environment variable is still used, as it happens on exit,
         * the only option is to leak it
         */

        if (*p == var) {
            return;
        }
    }

    njt_free(var);
}


njt_pid_t
njt_exec_new_binary(njt_cycle_t *cycle, char *const *argv)
{
    char             **env, *var;
    u_char            *p;
    njt_uint_t         i, n;
    njt_pid_t          pid;
    njt_exec_ctx_t     ctx;
    njt_core_conf_t   *ccf;
    njt_listening_t   *ls;

    njt_memzero(&ctx, sizeof(njt_exec_ctx_t));

    ctx.path = argv[0];
    ctx.name = "new binary process";
    ctx.argv = argv;

    n = 2;
    env = njt_set_environment(cycle, &n);
    if (env == NULL) {
        return NJT_INVALID_PID;
    }

    var = njt_alloc(sizeof(NJT_VAR)
                    + cycle->listening.nelts * (NJT_INT32_LEN + 1) + 2,
                    cycle->log);
    if (var == NULL) {
        njt_free(env);
        return NJT_INVALID_PID;
    }

    p = njt_cpymem(var, NJT_VAR "=", sizeof(NJT_VAR));

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {
        if (ls[i].ignore) {
            continue;
        }
        p = njt_sprintf(p, "%ud;", ls[i].fd);
    }

    *p = '\0';

    env[n++] = var;

#if (NJT_SETPROCTITLE_USES_ENV)

    /* allocate the spare 300 bytes for the new binary process title */

    env[n++] = "SPARE=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
               "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
               "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
               "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
               "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

#endif

    env[n] = NULL;

#if (NJT_DEBUG)
    {
    char  **e;
    for (e = env; *e; e++) {
        njt_log_debug1(NJT_LOG_DEBUG_CORE, cycle->log, 0, "env: %s", *e);
    }
    }
#endif

    ctx.envp = (char *const *) env;

    ccf = (njt_core_conf_t *) njt_get_conf(cycle->conf_ctx, njt_core_module);

    if (njt_rename_file(ccf->pid.data, ccf->oldpid.data) == NJT_FILE_ERROR) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                      njt_rename_file_n " %s to %s failed "
                      "before executing new binary process \"%s\"",
                      ccf->pid.data, ccf->oldpid.data, argv[0]);

        njt_free(env);
        njt_free(var);

        return NJT_INVALID_PID;
    }

    pid = njt_execute(cycle, &ctx);

    if (pid == NJT_INVALID_PID) {
        if (njt_rename_file(ccf->oldpid.data, ccf->pid.data)
            == NJT_FILE_ERROR)
        {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                          njt_rename_file_n " %s back to %s failed after "
                          "an attempt to execute new binary process \"%s\"",
                          ccf->oldpid.data, ccf->pid.data, argv[0]);
        }
    }

    njt_free(env);
    njt_free(var);

    return pid;
}


static njt_int_t
njt_get_options(int argc, char *const *argv)
{
    u_char     *p;
    njt_int_t   i;

    for (i = 1; i < argc; i++) {

        p = (u_char *) argv[i];

        if (*p++ != '-') {
            njt_log_stderr(0, "invalid option: \"%s\"", argv[i]);
            return NJT_ERROR;
        }

        while (*p) {

            switch (*p++) {

            case '?':
            case 'h':
                njt_show_version = 1;
                njt_show_help = 1;
                break;

            case 'v':
                njt_show_version = 1;
                break;

            case 'V':
                njt_show_version = 1;
                njt_show_configure = 1;
                break;

            case 't':
                njt_test_config = 1;
                break;

            case 'T':
                njt_test_config = 1;
                njt_dump_config = 1;
                break;

            case 'q':
                njt_quiet_mode = 1;
                break;

            case 'p':
                if (*p) {
                    njt_prefix = p;
                    goto next;
                }

                if (argv[++i]) {
                    njt_prefix = (u_char *) argv[i];
                    goto next;
                }

                njt_log_stderr(0, "option \"-p\" requires directory name");
                return NJT_ERROR;

            case 'e':
                if (*p) {
                    njt_error_log = p;

                } else if (argv[++i]) {
                    njt_error_log = (u_char *) argv[i];

                } else {
                    njt_log_stderr(0, "option \"-e\" requires file name");
                    return NJT_ERROR;
                }

                if (njt_strcmp(njt_error_log, "stderr") == 0) {
                    njt_error_log = (u_char *) "";
                }

                goto next;

            case 'c':
                if (*p) {
                    njt_conf_file = p;
                    goto next;
                }

                if (argv[++i]) {
                    njt_conf_file = (u_char *) argv[i];
                    goto next;
                }

                njt_log_stderr(0, "option \"-c\" requires file name");
                return NJT_ERROR;

            case 'g':
                if (*p) {
                    njt_conf_params = p;
                    goto next;
                }

                if (argv[++i]) {
                    njt_conf_params = (u_char *) argv[i];
                    goto next;
                }

                njt_log_stderr(0, "option \"-g\" requires parameter");
                return NJT_ERROR;

            case 's':
                if (*p) {
                    njt_signal = (char *) p;

                } else if (argv[++i]) {
                    njt_signal = argv[i];

                } else {
                    njt_log_stderr(0, "option \"-s\" requires parameter");
                    return NJT_ERROR;
                }

                if (njt_strcmp(njt_signal, "stop") == 0
                    || njt_strcmp(njt_signal, "quit") == 0
                    || njt_strcmp(njt_signal, "reopen") == 0
                    || njt_strcmp(njt_signal, "reload") == 0)
                {
                    njt_process = NJT_PROCESS_SIGNALLER;
                    goto next;
                }

                njt_log_stderr(0, "invalid option: \"-s %s\"", njt_signal);
                return NJT_ERROR;

            default:
                njt_log_stderr(0, "invalid option: \"%c\"", *(p - 1));
                return NJT_ERROR;
            }
        }

    next:

        continue;
    }

    return NJT_OK;
}


static njt_int_t
njt_save_argv(njt_cycle_t *cycle, int argc, char *const *argv)
{
#if (NJT_FREEBSD)

    njt_os_argv = (char **) argv;
    njt_argc = argc;
    njt_argv = (char **) argv;

#else
    size_t     len;
    njt_int_t  i;

    njt_os_argv = (char **) argv;
    njt_argc = argc;

    njt_argv = njt_alloc((argc + 1) * sizeof(char *), cycle->log);
    if (njt_argv == NULL) {
        return NJT_ERROR;
    }

    for (i = 0; i < argc; i++) {
        len = njt_strlen(argv[i]) + 1;

        njt_argv[i] = njt_alloc(len, cycle->log);
        if (njt_argv[i] == NULL) {
            return NJT_ERROR;
        }

        (void) njt_cpystrn((u_char *) njt_argv[i], (u_char *) argv[i], len);
    }

    njt_argv[i] = NULL;

#endif

    njt_os_environ = environ;

    return NJT_OK;
}


static njt_int_t
njt_process_options(njt_cycle_t *cycle)
{
    u_char  *p;
    size_t   len;

    if (njt_prefix) {
        len = njt_strlen(njt_prefix);
        p = njt_prefix;

        if (len && !njt_path_separator(p[len - 1])) {
            p = njt_pnalloc(cycle->pool, len + 1);
            if (p == NULL) {
                return NJT_ERROR;
            }

            njt_memcpy(p, njt_prefix, len);
            p[len++] = '/';
        }

        cycle->conf_prefix.len = len;
        cycle->conf_prefix.data = p;
        cycle->prefix.len = len;
        cycle->prefix.data = p;

    } else {

#ifndef NJT_PREFIX

        p = njt_pnalloc(cycle->pool, NJT_MAX_PATH);
        if (p == NULL) {
            return NJT_ERROR;
        }

        if (njt_getcwd(p, NJT_MAX_PATH) == 0) {
            njt_log_stderr(njt_errno, "[emerg]: " njt_getcwd_n " failed");
            return NJT_ERROR;
        }

        len = njt_strlen(p);

        p[len++] = '/';

        cycle->conf_prefix.len = len;
        cycle->conf_prefix.data = p;
        cycle->prefix.len = len;
        cycle->prefix.data = p;

#else

#ifdef NJT_CONF_PREFIX
        njt_str_set(&cycle->conf_prefix, NJT_CONF_PREFIX);
#else
        njt_str_set(&cycle->conf_prefix, NJT_PREFIX);
#endif
        njt_str_set(&cycle->prefix, NJT_PREFIX);

#endif
    }

    if (njt_conf_file) {
        cycle->conf_file.len = njt_strlen(njt_conf_file);
        cycle->conf_file.data = njt_conf_file;

    } else {
        njt_str_set(&cycle->conf_file, NJT_CONF_PATH);
    }

    if (njt_conf_full_name(cycle, &cycle->conf_file, 0) != NJT_OK) {
        return NJT_ERROR;
    }

    for (p = cycle->conf_file.data + cycle->conf_file.len - 1;
         p > cycle->conf_file.data;
         p--)
    {
        if (njt_path_separator(*p)) {
            cycle->conf_prefix.len = p - cycle->conf_file.data + 1;
            cycle->conf_prefix.data = cycle->conf_file.data;
            break;
        }
    }

    if (njt_error_log) {
        cycle->error_log.len = njt_strlen(njt_error_log);
        cycle->error_log.data = njt_error_log;

    } else {
        njt_str_set(&cycle->error_log, NJT_ERROR_LOG_PATH);
    }

    if (njt_conf_params) {
        cycle->conf_param.len = njt_strlen(njt_conf_params);
        cycle->conf_param.data = njt_conf_params;
    }

    if (njt_test_config) {
        cycle->log->log_level = NJT_LOG_INFO;
    }

    return NJT_OK;
}


static void *
njt_core_module_create_conf(njt_cycle_t *cycle)
{
    njt_core_conf_t  *ccf;

    ccf = njt_pcalloc(cycle->pool, sizeof(njt_core_conf_t));
    if (ccf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc()
     *
     *     ccf->pid = NULL;
     *     ccf->oldpid = NULL;
     *     ccf->priority = 0;
     *     ccf->cpu_affinity_auto = 0;
     *     ccf->cpu_affinity_n = 0;
     *     ccf->cpu_affinity = NULL;
     */

    ccf->daemon = NJT_CONF_UNSET;
    ccf->master = NJT_CONF_UNSET;
    ccf->timer_resolution = NJT_CONF_UNSET_MSEC;
    ccf->shutdown_timeout = NJT_CONF_UNSET_MSEC;

    ccf->worker_processes = NJT_CONF_UNSET;
    ccf->debug_points = NJT_CONF_UNSET;

    ccf->rlimit_nofile = NJT_CONF_UNSET;
    ccf->rlimit_core = NJT_CONF_UNSET;

    ccf->user = (njt_uid_t) NJT_CONF_UNSET_UINT;
    ccf->group = (njt_gid_t) NJT_CONF_UNSET_UINT;

    ccf->privileged_agent = NJT_CONF_UNSET;
    ccf->privileged_agent_connections = NJT_CONF_UNSET_UINT;

    if (njt_array_init(&ccf->env, cycle->pool, 1, sizeof(njt_str_t))
        != NJT_OK)
    {
        return NULL;
    }

    return ccf;
}


static char *
njt_core_module_init_conf(njt_cycle_t *cycle, void *conf)
{
    njt_core_conf_t  *ccf = conf;

    njt_conf_init_value(ccf->daemon, 1);
    njt_conf_init_value(ccf->master, 1);
    njt_conf_init_msec_value(ccf->timer_resolution, 0);
    njt_conf_init_msec_value(ccf->shutdown_timeout, 0);

    njt_conf_init_value(ccf->worker_processes, 1);
    njt_conf_init_value(ccf->debug_points, 0);

    njt_conf_init_value(ccf->privileged_agent, 1);
    njt_conf_init_uint_value(ccf->privileged_agent_connections, 128);

#if (NJT_HAVE_CPU_AFFINITY)

    if (!ccf->cpu_affinity_auto
        && ccf->cpu_affinity_n
        && ccf->cpu_affinity_n != 1
        && ccf->cpu_affinity_n != (njt_uint_t) ccf->worker_processes)
    {
        njt_log_error(NJT_LOG_WARN, cycle->log, 0,
                      "the number of \"worker_processes\" is not equal to "
                      "the number of \"worker_cpu_affinity\" masks, "
                      "using last mask for remaining worker processes");
    }

#endif


    if (ccf->pid.len == 0) {
        njt_str_set(&ccf->pid, NJT_PID_PATH);
    }

    if (njt_conf_full_name(cycle, &ccf->pid, 0) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    ccf->oldpid.len = ccf->pid.len + sizeof(NJT_OLDPID_EXT);

    ccf->oldpid.data = njt_pnalloc(cycle->pool, ccf->oldpid.len);
    if (ccf->oldpid.data == NULL) {
        return NJT_CONF_ERROR;
    }

    njt_memcpy(njt_cpymem(ccf->oldpid.data, ccf->pid.data, ccf->pid.len),
               NJT_OLDPID_EXT, sizeof(NJT_OLDPID_EXT));


#if !(NJT_WIN32)

    if (ccf->user == (uid_t) NJT_CONF_UNSET_UINT && geteuid() == 0) {
        struct group   *grp;
        struct passwd  *pwd;

        njt_set_errno(0);
        pwd = getpwnam(NJT_USER);
        if (pwd == NULL) {
            njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                          "getpwnam(\"" NJT_USER "\") failed");
            return NJT_CONF_ERROR;
        }

        ccf->username = NJT_USER;
        ccf->user = pwd->pw_uid;

        njt_set_errno(0);
        grp = getgrnam(NJT_GROUP);
        if (grp == NULL) {
            njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                          "getgrnam(\"" NJT_GROUP "\") failed");
            return NJT_CONF_ERROR;
        }

        ccf->group = grp->gr_gid;
    }


    if (ccf->lock_file.len == 0) {
        njt_str_set(&ccf->lock_file, NJT_LOCK_PATH);
    }

    if (njt_conf_full_name(cycle, &ccf->lock_file, 0) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    {
    njt_str_t  lock_file;

    lock_file = cycle->old_cycle->lock_file;

    if (lock_file.len) {
        lock_file.len--;

        if (ccf->lock_file.len != lock_file.len
            || njt_strncmp(ccf->lock_file.data, lock_file.data, lock_file.len)
               != 0)
        {
            njt_log_error(NJT_LOG_EMERG, cycle->log, 0,
                          "\"lock_file\" could not be changed, ignored");
        }

        cycle->lock_file.len = lock_file.len + 1;
        lock_file.len += sizeof(".accept");

        cycle->lock_file.data = njt_pstrdup(cycle->pool, &lock_file);
        if (cycle->lock_file.data == NULL) {
            return NJT_CONF_ERROR;
        }

    } else {
        cycle->lock_file.len = ccf->lock_file.len + 1;
        cycle->lock_file.data = njt_pnalloc(cycle->pool,
                                      ccf->lock_file.len + sizeof(".accept"));
        if (cycle->lock_file.data == NULL) {
            return NJT_CONF_ERROR;
        }

        njt_memcpy(njt_cpymem(cycle->lock_file.data, ccf->lock_file.data,
                              ccf->lock_file.len),
                   ".accept", sizeof(".accept"));
    }
    }

#endif

    return NJT_CONF_OK;
}


static char *
njt_set_user(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
#if (NJT_WIN32)

    njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                       "\"user\" is not supported, ignored");

    return NJT_CONF_OK;

#else

    njt_core_conf_t  *ccf = conf;

    char             *group;
    struct passwd    *pwd;
    struct group     *grp;
    njt_str_t        *value;

    if (ccf->user != (uid_t) NJT_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    if (geteuid() != 0) {
        njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                           "the \"user\" directive makes sense only "
                           "if the master process runs "
                           "with super-user privileges, ignored");
        return NJT_CONF_OK;
    }

    value = cf->args->elts;

    ccf->username = (char *) value[1].data;

    njt_set_errno(0);
    pwd = getpwnam((const char *) value[1].data);
    if (pwd == NULL) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, njt_errno,
                           "getpwnam(\"%s\") failed", value[1].data);
        return NJT_CONF_ERROR;
    }

    ccf->user = pwd->pw_uid;

    group = (char *) ((cf->args->nelts == 2) ? value[1].data : value[2].data);

    njt_set_errno(0);
    grp = getgrnam(group);
    if (grp == NULL) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, njt_errno,
                           "getgrnam(\"%s\") failed", group);
        return NJT_CONF_ERROR;
    }

    ccf->group = grp->gr_gid;

    return NJT_CONF_OK;

#endif
}


static char *
njt_set_env(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_core_conf_t  *ccf = conf;

    njt_str_t   *value, *var;
    njt_uint_t   i;

    var = njt_array_push(&ccf->env);
    if (var == NULL) {
        return NJT_CONF_ERROR;
    }

    value = cf->args->elts;
    *var = value[1];

    for (i = 0; i < value[1].len; i++) {

        if (value[1].data[i] == '=') {

            var->len = i;

            return NJT_CONF_OK;
        }
    }

    return NJT_CONF_OK;
}


static char *
njt_set_priority(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_core_conf_t  *ccf = conf;

    njt_str_t        *value;
    njt_uint_t        n, minus;

    if (ccf->priority != 0) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (value[1].data[0] == '-') {
        n = 1;
        minus = 1;

    } else if (value[1].data[0] == '+') {
        n = 1;
        minus = 0;

    } else {
        n = 0;
        minus = 0;
    }

    ccf->priority = njt_atoi(&value[1].data[n], value[1].len - n);
    if (ccf->priority == NJT_ERROR) {
        return "invalid number";
    }

    if (minus) {
        ccf->priority = -ccf->priority;
    }

    return NJT_CONF_OK;
}


static char *
njt_set_cpu_affinity(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
#if (NJT_HAVE_CPU_AFFINITY)
    njt_core_conf_t  *ccf = conf;

    u_char            ch, *p;
    njt_str_t        *value;
    njt_uint_t        i, n;
    njt_cpuset_t     *mask;

    if (ccf->cpu_affinity) {
        return "is duplicate";
    }

    mask = njt_palloc(cf->pool, (cf->args->nelts - 1) * sizeof(njt_cpuset_t));
    if (mask == NULL) {
        return NJT_CONF_ERROR;
    }

    ccf->cpu_affinity_n = cf->args->nelts - 1;
    ccf->cpu_affinity = mask;

    value = cf->args->elts;

    if (njt_strcmp(value[1].data, "auto") == 0) {

        if (cf->args->nelts > 3) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid number of arguments in "
                               "\"worker_cpu_affinity\" directive");
            return NJT_CONF_ERROR;
        }

        ccf->cpu_affinity_auto = 1;

        CPU_ZERO(&mask[0]);
        for (i = 0; i < (njt_uint_t) njt_min(njt_ncpu, CPU_SETSIZE); i++) {
            CPU_SET(i, &mask[0]);
        }

        n = 2;

    } else {
        n = 1;
    }

    for ( /* void */ ; n < cf->args->nelts; n++) {

        if (value[n].len > CPU_SETSIZE) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                         "\"worker_cpu_affinity\" supports up to %d CPUs only",
                         CPU_SETSIZE);
            return NJT_CONF_ERROR;
        }

        i = 0;
        CPU_ZERO(&mask[n - 1]);

        for (p = value[n].data + value[n].len - 1;
             p >= value[n].data;
             p--)
        {
            ch = *p;

            if (ch == ' ') {
                continue;
            }

            i++;

            if (ch == '0') {
                continue;
            }

            if (ch == '1') {
                CPU_SET(i - 1, &mask[n - 1]);
                continue;
            }

            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                          "invalid character \"%c\" in \"worker_cpu_affinity\"",
                          ch);
            return NJT_CONF_ERROR;
        }
    }

#else

    njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                       "\"worker_cpu_affinity\" is not supported "
                       "on this platform, ignored");
#endif

    return NJT_CONF_OK;
}


njt_cpuset_t *
njt_get_cpu_affinity(njt_uint_t n)
{
#if (NJT_HAVE_CPU_AFFINITY)
    njt_uint_t        i, j;
    njt_cpuset_t     *mask;
    njt_core_conf_t  *ccf;

    static njt_cpuset_t  result;

    ccf = (njt_core_conf_t *) njt_get_conf(njt_cycle->conf_ctx,
                                           njt_core_module);

    if (ccf->cpu_affinity == NULL) {
        return NULL;
    }

    if (ccf->cpu_affinity_auto) {
        mask = &ccf->cpu_affinity[ccf->cpu_affinity_n - 1];

        for (i = 0, j = n; /* void */ ; i++) {

            if (CPU_ISSET(i % CPU_SETSIZE, mask) && j-- == 0) {
                break;
            }

            if (i == CPU_SETSIZE && j == n) {
                /* empty mask */
                return NULL;
            }

            /* void */
        }

        CPU_ZERO(&result);
        CPU_SET(i % CPU_SETSIZE, &result);

        return &result;
    }

    if (ccf->cpu_affinity_n > n) {
        return &ccf->cpu_affinity[n];
    }

    return &ccf->cpu_affinity[ccf->cpu_affinity_n - 1];

#else

    return NULL;

#endif
}


static char *
njt_set_worker_processes(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_str_t        *value;
    njt_core_conf_t  *ccf;

    ccf = (njt_core_conf_t *) conf;

    if (ccf->worker_processes != NJT_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (njt_strcmp(value[1].data, "auto") == 0) {
        ccf->worker_processes = njt_ncpu;
        return NJT_CONF_OK;
    }

    ccf->worker_processes = njt_atoi(value[1].data, value[1].len);

    if (ccf->worker_processes == NJT_ERROR) {
        return "invalid value";
    }

    return NJT_CONF_OK;
}


static char *
njt_load_module(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
#if (NJT_HAVE_DLOPEN)
    void                *handle;
    char               **names, **order;
    njt_str_t           *value, file;
    njt_uint_t           i;
    njt_module_t        *module, **modules;
    njt_pool_cleanup_t  *cln;

    if (cf->cycle->modules_used) {
        return "is specified too late";
    }

    value = cf->args->elts;

    file = value[1];

    if (njt_conf_full_name(cf->cycle, &file, 0) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    cln = njt_pool_cleanup_add(cf->cycle->pool, 0);
    if (cln == NULL) {
        return NJT_CONF_ERROR;
    }

    handle = njt_dlopen(file.data);
    if (handle == NULL) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           njt_dlopen_n " \"%s\" failed (%s)",
                           file.data, njt_dlerror());
        return NJT_CONF_ERROR;
    }

    cln->handler = njt_unload_module;
    cln->data = handle;

    modules = njt_dlsym(handle, "njt_modules");
    if (modules == NULL) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           njt_dlsym_n " \"%V\", \"%s\" failed (%s)",
                           &value[1], "njt_modules", njt_dlerror());
        return NJT_CONF_ERROR;
    }

    names = njt_dlsym(handle, "njt_module_names");
    if (names == NULL) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           njt_dlsym_n " \"%V\", \"%s\" failed (%s)",
                           &value[1], "njt_module_names", njt_dlerror());
        return NJT_CONF_ERROR;
    }

    order = njt_dlsym(handle, "njt_module_order");

    for (i = 0; modules[i]; i++) {
        module = modules[i];
        module->name = names[i];

        if (njt_add_module(cf, &file, module, order) != NJT_OK) {
            return NJT_CONF_ERROR;
        }

        njt_log_debug2(NJT_LOG_DEBUG_CORE, cf->log, 0, "module: %s i:%ui",
                       module->name, module->index);
    }

    return NJT_CONF_OK;

#else

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "\"load_module\" is not supported "
                       "on this platform");
    return NJT_CONF_ERROR;

#endif
}


#if (NJT_HAVE_DLOPEN)

static void
njt_unload_module(void *data)
{
    void  *handle = data;

    if (njt_dlclose(handle) != 0) {
        njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,
                      njt_dlclose_n " failed (%s)", njt_dlerror());
    }
}

#endif
