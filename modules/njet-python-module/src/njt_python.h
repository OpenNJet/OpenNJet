
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) 2021-2024  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_PYTHON_H_INCLUDED_
#define _NJT_PYTHON_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>
#include <Python.h>
#include <frameobject.h>


#define NJT_PYTHON_AGAIN  (void *) -1

typedef struct njt_python_ctx_s  njt_python_ctx_t;


#if !(NJT_PYTHON_SYNC)

njt_python_ctx_t *njt_python_get_ctx();
njt_int_t njt_python_yield();
void njt_python_wakeup(njt_python_ctx_t *ctx);

// njt_int_t njt_python_sleep_install(njt_cycle_t *cycle);
// njt_int_t njt_python_socket_install(njt_cycle_t *cycle);
// njt_int_t njt_python_resolve_install(njt_cycle_t *cycle);
PyObject *njt_python_socket_create_wrapper(njt_connection_t *c);

#endif

njt_python_ctx_t *njt_python_create_ctx(njt_pool_t *pool, njt_log_t *log);
PyObject *njt_python_eval(njt_python_ctx_t *ctx, PyObject *code,
    njt_event_t *wake, PyObject* arg, char *key);
void njt_python_set_resolver(njt_python_ctx_t *ctx, njt_resolver_t *resolver,
    njt_msec_t timeout);
njt_resolver_t *njt_python_get_resolver(njt_python_ctx_t *ctx,
    njt_msec_t *timeout);
PyObject *njt_python_set_value(njt_python_ctx_t *ctx, const char *name,
    PyObject *value);
void njt_python_reset_value(njt_python_ctx_t *ctx, const char *name,
    PyObject *old);
u_char *njt_python_get_error(njt_pool_t *pool);

char *njt_python_set_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf);
char *njt_python_include_set_slot(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
PyObject *njt_python_compile(njt_conf_t *cf, u_char *script);
njt_int_t njt_python_active(njt_conf_t *cf);

PyObject * njt_python_init_namespace(njt_conf_t *cf);
PyObject * njt_python_get_namespace(njt_cycle_t* cycle);
void* njt_python_add_init_code(njt_conf_t *cf,PyObject* init_code);
// void njt_python_cleanup_thread_ctx(njt_python_ctx_t *ctx);

#endif /* _NJT_PYTHON_H_INCLUDED_ */
