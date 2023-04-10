
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>

/*
 * declare Profiler interface here because
 * <google/profiler.h> is C++ header file
 */

int ProfilerStart(u_char* fname);
void ProfilerStop(void);
void ProfilerRegisterThread(void);


static void *njt_google_perftools_create_conf(njt_cycle_t *cycle);
static njt_int_t njt_google_perftools_worker(njt_cycle_t *cycle);


typedef struct {
    njt_str_t  profiles;
} njt_google_perftools_conf_t;


static njt_command_t  njt_google_perftools_commands[] = {

    { njt_string("google_perftools_profiles"),
      NJT_MAIN_CONF|NJT_DIRECT_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      0,
      offsetof(njt_google_perftools_conf_t, profiles),
      NULL },

      njt_null_command
};


static njt_core_module_t  njt_google_perftools_module_ctx = {
    njt_string("google_perftools"),
    njt_google_perftools_create_conf,
    NULL
};


njt_module_t  njt_google_perftools_module = {
    NJT_MODULE_V1,
    &njt_google_perftools_module_ctx,      /* module context */
    njt_google_perftools_commands,         /* module directives */
    NJT_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    njt_google_perftools_worker,           /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};


static void *
njt_google_perftools_create_conf(njt_cycle_t *cycle)
{
    njt_google_perftools_conf_t  *gptcf;

    gptcf = njt_pcalloc(cycle->pool, sizeof(njt_google_perftools_conf_t));
    if (gptcf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc()
     *
     *     gptcf->profiles = { 0, NULL };
     */

    return gptcf;
}


static njt_int_t
njt_google_perftools_worker(njt_cycle_t *cycle)
{
    u_char                       *profile;
    njt_google_perftools_conf_t  *gptcf;

    gptcf = (njt_google_perftools_conf_t *)
                njt_get_conf(cycle->conf_ctx, njt_google_perftools_module);

    if (gptcf->profiles.len == 0) {
        return NJT_OK;
    }

    profile = njt_alloc(gptcf->profiles.len + NJT_INT_T_LEN + 2, cycle->log);
    if (profile == NULL) {
        return NJT_OK;
    }

    if (getenv("CPUPROFILE")) {
        /* disable inherited Profiler enabled in master process */
        ProfilerStop();
    }

    njt_sprintf(profile, "%V.%d%Z", &gptcf->profiles, njt_pid);

    if (ProfilerStart(profile)) {
        /* start ITIMER_PROF timer */
        ProfilerRegisterThread();

    } else {
        njt_log_error(NJT_LOG_CRIT, cycle->log, njt_errno,
                      "ProfilerStart(%s) failed", profile);
    }

    njt_free(profile);

    return NJT_OK;
}


/* ProfilerStop() is called on Profiler destruction */
