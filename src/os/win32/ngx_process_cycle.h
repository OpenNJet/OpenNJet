
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NJT_PROCESS_CYCLE_H_INCLUDED_
#define _NJT_PROCESS_CYCLE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NJT_PROCESS_SINGLE     0
#define NJT_PROCESS_MASTER     1
#define NJT_PROCESS_SIGNALLER  2
#define NJT_PROCESS_WORKER     3


void ngx_master_process_cycle(ngx_cycle_t *cycle);
void ngx_single_process_cycle(ngx_cycle_t *cycle);
void ngx_close_handle(HANDLE h);


extern ngx_uint_t      ngx_process;
extern ngx_uint_t      ngx_worker;
extern ngx_pid_t       ngx_pid;
extern ngx_uint_t      ngx_exiting;

extern sig_atomic_t    ngx_quit;
extern sig_atomic_t    ngx_terminate;
extern sig_atomic_t    ngx_reopen;

extern ngx_uint_t      ngx_inherited;
extern ngx_pid_t       ngx_new_binary;


extern HANDLE          ngx_master_process_event;
extern char            ngx_master_process_event_name[];


#endif /* _NJT_PROCESS_CYCLE_H_INCLUDED_ */
