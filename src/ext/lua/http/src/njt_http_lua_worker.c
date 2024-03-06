
/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"

#if !(NJT_WIN32)
#include <njt_channel.h>
#endif


#define NJT_PROCESS_PRIVILEGED_AGENT    99


int
njt_http_lua_ffi_worker_pid(void)
{
    return (int) njt_pid;
}


#if !(NJT_WIN32)
int
njt_http_lua_ffi_worker_pids(int *pids, size_t *pids_len)
{
    size_t    n;
    njt_int_t i;

    n = 0;
    for (i = 0; n < *pids_len && i < NJT_MAX_PROCESSES; i++) {
        if (i != njt_process_slot && njt_processes[i].pid == 0) {
            break;
        }

        /* The current process */
        if (i == njt_process_slot) {
            pids[n++] = njt_pid;
        }

        if (njt_processes[i].channel[0] > 0 && njt_processes[i].pid > 0) {
            pids[n++] = njt_processes[i].pid;
        }
    }

    if (n == 0) {
        return NJT_ERROR;
    }

    *pids_len = n;

    return NJT_OK;
}
#endif


int
njt_http_lua_ffi_worker_id(void)
{
#if (njet_version >= 1009001)
    if (njt_process != NJT_PROCESS_WORKER
        && njt_process != NJT_PROCESS_SINGLE)
    {
        return -1;
    }

    return (int) njt_worker;
#else
    return -1;
#endif
}


int
njt_http_lua_ffi_worker_exiting(void)
{
    return (int) njt_exiting;
}


int
njt_http_lua_ffi_worker_count(void)
{
    njt_core_conf_t   *ccf;

    ccf = (njt_core_conf_t *) njt_get_conf(njt_cycle->conf_ctx,
                                           njt_core_module);

    return (int) ccf->worker_processes;
}


int
njt_http_lua_ffi_master_pid(void)
{
#if (njet_version >= 1013008)
    if (njt_process == NJT_PROCESS_SINGLE) {
        return (int) njt_pid;
    }

    return (int) njt_parent;
#else
    return NJT_ERROR;
#endif
}


int
njt_http_lua_ffi_get_process_type(void)
{
    njt_core_conf_t  *ccf;

#if defined(HAVE_PRIVILEGED_PROCESS_PATCH) && !NJT_WIN32
    if (njt_process == NJT_PROCESS_HELPER) {
        if (njt_is_privileged_agent) {
            return NJT_PROCESS_PRIVILEGED_AGENT;
        }
    }
#endif

    if (njt_process == NJT_PROCESS_SINGLE) {
        ccf = (njt_core_conf_t *) njt_get_conf(njt_cycle->conf_ctx,
                                               njt_core_module);

        if (ccf->master) {
            return NJT_PROCESS_MASTER;
        }
    }

    return njt_process;
}

#if defined(njet_version) && njet_version >= 1019003
int
njt_http_lua_ffi_enable_privileged_agent(char **err, unsigned int connections)
#else
int
njt_http_lua_ffi_enable_privileged_agent(char **err)
#endif
{
#ifdef HAVE_PRIVILEGED_PROCESS_PATCH
    njt_core_conf_t   *ccf;

    ccf = (njt_core_conf_t *) njt_get_conf(njt_cycle->conf_ctx,
                                           njt_core_module);

    ccf->privileged_agent = 1;
#if defined(njet_version) && njet_version >= 1019003
    ccf->privileged_agent_connections = connections;
#endif

    return NJT_OK;

#else
    *err = "missing privileged agent process patch in the njet core";
    return NJT_ERROR;
#endif
}


void
njt_http_lua_ffi_process_signal_graceful_exit(void)
{
    njt_quit = 1;
}


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
