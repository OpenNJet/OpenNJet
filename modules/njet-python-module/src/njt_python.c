
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) 2021-2024  TMLake(Beijing) Technology Co., Ltd.
 */


#include <Python.h>

/*
 * The Python.h file is included first in contrast with normal njet
 * practice.  Python headers deliberately define the following macros:
 * _GNU_SOURCE, _POSIX_C_SOURCE, _XOPEN_SOURCE.
 * When compiling on Linux, they are defined by njet or system headers
 * with Python possibly redefining them.  Since njet is built with -Werror
 * compilation option, macros redefinition causes compilation errors.
 */

#include <njt_config.h>
#include <njt_core.h>
#include <njt_event_posted.h>
#include <ucontext.h>
#include "njt_python.h"


typedef struct {
    PyObject               *ns;
    PyThreadState          *main_ps;
    njt_array_t            *init_codes; //init_worker func
    size_t                  stack_size;
    njt_resolver_t         *resolver;
} njt_python_conf_t;


struct njt_python_ctx_s {
    PyObject              *code;
    PyObject              *ns;
    PyObject              *local;
    PyObject              *result;

    njt_event_t           *wake;
    njt_pool_t            *pool;
    njt_log_t             *log;

    njt_resolver_t        *resolver;
    njt_msec_t             resolver_timeout;

    size_t                 stack_size;

#if !(NJT_PYTHON_SYNC)

    void                  *stack;

    ucontext_t             uc;
    ucontext_t             ruc;

    int                    recursion_depth;
    struct _frame         *frame;

    struct _frame         *func_frame; // should be dec ref
    PyThreadState         *ps;  // should be return or deleted
    PyThreadState         *main_ps;
    //PyObject              *exc_type;  by stdanley
    //PyObject              *exc_value;
    //PyObject              *exc_traceback;

    njt_uint_t             terminate;  /* unsigned  terminate:1; */

#endif
};


typedef struct {
    PyObject              *ns;
    u_char                *name;
    PyThreadState         *ps;
} njt_python_ns_cleanup_t;


#if !(NJT_PYTHON_SYNC)
static njt_python_ctx_t *njt_python_set_ctx(njt_python_ctx_t *ctx);
static void njt_python_task_handler();
static void njt_python_cleanup_ctx(void *data);
#endif
static char *njt_python_include_file(njt_conf_t *cf, PyObject *ns, char *file);
static char *njt_python_load_app(njt_conf_t *cf, PyObject *ns, char *file);
static void njt_python_decref(void *data);
//static PyObject *njt_python_init_namespace(njt_conf_t *cf);
static void njt_python_cleanup_namespace(void *data);

static void *njt_python_create_conf(njt_cycle_t *cycle);
static char *njt_python_init_conf(njt_cycle_t *cycle, void *conf);
static njt_int_t njt_python_init_worker(njt_cycle_t *cycle);
//static char * njt_python_resolver(njt_conf_t *cf, njt_command_t *cmd, void *conf);

static njt_command_t  njt_python_commands[] = {
/*
    { njt_string("python_resolver"),
      NJT_MAIN_CONF|NJT_DIRECT_CONF|NJT_CONF_TAKE1,
      njt_python_resolver,
      0,
      0,
      NULL },
*/
    { njt_string("python_include"),
      NJT_MAIN_CONF|NJT_CONF_TAKE1,
      njt_python_include_set_slot,
      0,
      0,
      NULL },

    { njt_string("python_stack_size"),
      NJT_MAIN_CONF|NJT_DIRECT_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      0,
      offsetof(njt_python_conf_t, stack_size),
      NULL },

      njt_null_command
};
/*
static char *
njt_python_resolver(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_python_conf_t  *pcf = (njt_python_conf_t  *)conf;

    njt_str_t  *value;

    if (pcf->resolver) {
        return "is duplicate";
    }

    value = cf->args->elts;

    pcf->resolver = njt_resolver_create(cf, &value[1], cf->args->nelts - 1);
    if (pcf->resolver == NULL) {
        return NJT_CONF_ERROR;
    }
    njt_log_error(NJT_LOG_ERR,cf->log,0,"set resolver:%p,%p",pcf,pcf->resolver);
    return NJT_CONF_OK;
}
*/
static njt_core_module_t  njt_python_module_ctx = {
    njt_string("python"),
    njt_python_create_conf,
    njt_python_init_conf
};


njt_module_t  njt_python_module = {
    NJT_MODULE_V1,
    &njt_python_module_ctx,                /* module context */
    njt_python_commands,                   /* module directives */
    NJT_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    njt_python_init_worker,                /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};

/*
static int py_trace(PyObject *obj, PyFrameObject *frame, int what, PyObject *arg) {
    njt_log_error(NJT_LOG_DEBUG,ngx_cycle->log,0,"f:%p,w:%d",frame,what);
    return 0;
}
*/

#if !(NJT_PYTHON_SYNC)

njt_python_ctx_t  * volatile njt_python_ctx;


njt_python_ctx_t *
njt_python_get_ctx()
{
    return njt_python_ctx;
}


static njt_python_ctx_t *
njt_python_set_ctx(njt_python_ctx_t *ctx)
{
    njt_python_ctx_t  *pctx;

    pctx = njt_python_ctx;
    njt_python_ctx = ctx;

    return pctx;
}


void *
njt_python_add_init_code(njt_conf_t *cf,PyObject* init_code){
    njt_python_conf_t *pcf= (njt_python_conf_t*)njt_get_conf(cf->cycle->conf_ctx,njt_python_module);
    PyObject **pcode = njt_array_push(pcf->init_codes);

    if (pcode == NULL) {
        return NJT_CONF_ERROR;
    }
    *pcode= init_code;
    return NJT_CONF_OK;
}


njt_int_t
njt_python_yield()
{
    njt_python_ctx_t  *ctx;

    ctx = njt_python_get_ctx();
    if (ctx == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "blocking calls are not allowed");
        return NJT_ERROR;
    }

    njt_log_debug1(NJT_LOG_DEBUG_CORE, ctx->log, 0, "python yield,with ctx:%p",ctx);

    if (swapcontext(&ctx->uc, &ctx->ruc)) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NJT_ERROR;
    }

    njt_log_debug0(NJT_LOG_DEBUG_CORE, ctx->log, 0, "python regain");

    if (ctx->terminate) {
        PyErr_SetString(PyExc_RuntimeError, "terminated");
        njt_log_debug0(NJT_LOG_DEBUG_CORE, ctx->log, 0, "python terminate");
        return NJT_ERROR;
    }

    return NJT_OK;
}


void
njt_python_wakeup(njt_python_ctx_t *ctx)
{
    if (!ctx->terminate) {
        // njt_log_debug2(NJT_LOG_DEBUG_CORE, ctx->log, 0, "python wakeup,with ctx:%p,wake event:%p",ctx,ctx->wake);
        njt_post_event(ctx->wake, &njt_posted_events);
    }
}

#endif


njt_python_ctx_t *
njt_python_create_ctx(njt_pool_t *pool, njt_log_t *log)
{
    njt_python_ctx_t    *ctx;
    njt_python_conf_t   *pcf;
#if !(NJT_PYTHON_SYNC)
    njt_pool_cleanup_t  *cln;
#endif

    pcf = (njt_python_conf_t *) njt_get_conf(njt_cycle->conf_ctx,
                                             njt_python_module);
    if (pcf->ns == NULL) {
        return NULL;
    }

    ctx = njt_pcalloc(pool, sizeof(njt_python_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

#if !(NJT_PYTHON_SYNC)

    cln = njt_pool_cleanup_add(pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = njt_python_cleanup_ctx;
    cln->data = ctx;

#endif

    ctx->pool = pool;
    ctx->log = log;
    ctx->ns = pcf->ns;
    ctx->stack_size = pcf->stack_size;
    ctx->main_ps = pcf->main_ps;
    ctx->local = ctx->ns;

    return ctx;
}


#if !(NJT_PYTHON_SYNC)
// static void njt_python_reset_thread_ctx(void *data){
    
//     njt_python_ctx_t  *ctx = data;
//     njt_python_conf_t   *pcf;

//     if (ctx->terminate) {
//         return;
//     }

//     pcf = (njt_python_conf_t *) njt_get_conf(njt_cycle->conf_ctx,
//                                              njt_python_module);
//     if (pcf->ns == NULL) {
//         return;
//     }

//     void *stack = ctx->stack;
//     njt_pool_t *pool = ctx->pool;
//     njt_log_t *log = ctx->log;
//     njt_memzero(ctx, sizeof(njt_python_ctx_t));
//     ctx->stack = stack;
//     ctx->pool = pool;
//     ctx->log = log;
//     ctx->ns = pcf->ns;
//     ctx->stack_size = pcf->stack_size;
//     // njt_memzero(ctx->stack, ctx->stack_size);
//     ctx->main_ps = pcf->main_ps;
//     ctx->local = ctx->ns;

// }


// void
// njt_python_cleanup_thread_ctx(njt_python_ctx_t *ctx)
// {
//     PyObject  *result;

//     if (ctx->terminate) {
//         return;
//     }

//     result = ctx->result;

//     Py_XDECREF(result);
//     njt_log_debug2(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0, "python_cleanup_ctx,f:%d,l:%d",Py_REFCNT(ctx->func_frame),Py_REFCNT(ctx->local));
//     // f should be 1 , l:2

//     PyThreadState_Swap(ctx->main_ps);
//     Py_XDECREF(ctx->func_frame);
//     //f use l ,so after dealloc f, l should be 1

//     printf("ctx->local ref count: %ld\n", Py_REFCNT(ctx->local));
//     if (ctx->local != ctx->ns) {
//         Py_XDECREF(ctx->local);
//     }

//     if (ctx->ps) {
//         printf("ctx-state-clear\n");
//         PyThreadState_Clear(ctx->ps);
//         PyThreadState_Delete(ctx->ps);
//     }

//     ctx->ps = NULL;

//     njt_python_reset_thread_ctx(ctx);
// }


static void
njt_python_cleanup_ctx(void *data)
{
    njt_python_ctx_t  *ctx = data;

    PyObject  *result;

    ctx->terminate = 1;

    result = ctx->result;

    while (result == NJT_PYTHON_AGAIN) {
        result = njt_python_eval(ctx, NULL, ctx->wake, NULL, NULL);
    }

    Py_XDECREF(result);
    // njt_log_debug2(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0, "python_cleanup_ctx,f:%d,l:%d",Py_REFCNT(ctx->func_frame),Py_REFCNT(ctx->local));
    // f should be 1 , l:2

    PyThreadState_Swap(ctx->main_ps);
    Py_XDECREF(ctx->func_frame);
    //f use l ,so after dealloc f, l should be 1

    if (ctx->local != ctx->ns) {
        Py_XDECREF(ctx->local);
    }
    if (ctx->ps) {
        PyThreadState_Clear(ctx->ps);
        PyThreadState_Delete(ctx->ps);
    }
    /*
    PyObject *forum= PyModule_GetDict(PyDict_GetItemString(ctx->ns,"forum"));
    PyObject * keys= PyDict_Keys(forum);
    int  idx,cnt=PyList_GET_SIZE(keys);
    for (idx=0;idx<cnt;idx++)
        njt_log_debug1(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0, "python_cleanup_ctx,ns key:%s", _PyUnicode_AsString(PyList_GetItem(keys,idx)));
    */

}

#endif


PyObject *
njt_python_eval(njt_python_ctx_t *ctx, PyObject *code, njt_event_t *wake, PyObject* arg, char *key)
{
    PyObject          *result;

#if !(NJT_PYTHON_SYNC)

    int                recursion_depth;
    //PyObject           *exc_value, *exc_traceback;
    struct _frame     *frame;
    PyThreadState     *ps;
    njt_python_ctx_t  *pctx;

    if (wake) {

        if (ctx->result == NULL) {
            if (ctx->stack == NULL) {
                ctx->stack = njt_palloc(ctx->pool, ctx->stack_size);
                if (ctx->stack == NULL) {
                    return NULL;
                }
            }

            if (getcontext(&ctx->uc) == -1) {
                njt_log_debug0(NJT_LOG_DEBUG_CORE, ctx->log, njt_errno,
                               "getcontext() failed");
                return NULL;
            }

            ctx->uc.uc_stack.ss_size = ctx->stack_size;
            ctx->uc.uc_stack.ss_sp = ctx->stack;
            ctx->uc.uc_link = &ctx->ruc;

            makecontext(&ctx->uc, &njt_python_task_handler, 0);

            ctx->code = code;
            ctx->wake = wake;
            ctx->result = NJT_PYTHON_AGAIN;
            ctx->ps = PyThreadState_New(PyInterpreterState_Main());
            ctx->local = PyDict_New();
            if (arg && key) {
                PyDict_SetItemString(ctx->local, key, arg); // free in clean ctx
                //tips: we leave local's clear to free arg later
                Py_DECREF(arg);
            }
            ctx->func_frame = PyFrame_New(ctx->ps, (PyCodeObject*)code, ctx->ns, ctx->local);
            ctx->frame = ctx->func_frame;
        }
        PyThreadState_Swap(ctx->ps);
        ps = PyThreadState_GET();       //hack
        pctx = njt_python_set_ctx(ctx);

        recursion_depth = ps->recursion_depth;
        frame = ps->frame;

        ps->recursion_depth = ctx->recursion_depth;
        ps->frame = ctx->frame;

        njt_log_debug3(NJT_LOG_DEBUG_CORE, ctx->log, 0, "run vm use frame:%p,stack:%d,overflow:%d",ps->frame,ps->recursion_depth,ps->overflowed);
        if (swapcontext(&ctx->ruc, &ctx->uc) == -1) {
            njt_log_error(NJT_LOG_ERR, ctx->log, njt_errno,
                          "swapcontext() failed");
        }

        ctx->recursion_depth = ps->recursion_depth;
        ctx->frame = ps->frame;

        ps->recursion_depth = recursion_depth;
        ps->frame = frame;

        njt_log_debug1(NJT_LOG_DEBUG_CORE, ctx->log, 0, "after eval,restore frame:%p",ps->frame);
        (void) njt_python_set_ctx(pctx);

        result = ctx->result;
        if (result != NJT_PYTHON_AGAIN) {
            ctx->code = NULL;
            ctx->wake = NULL;
            ctx->result = NULL;
        }

        njt_log_debug2(NJT_LOG_DEBUG_CORE, ctx->log, 0, "python http eval return :ctx:%p,ret:%p",ctx,result);
        return result;
    }

    pctx = njt_python_set_ctx(NULL);

#endif

    result = PyEval_EvalCode(code, ctx->ns, ctx->ns);
    if (result == NULL) {
        njt_log_error(NJT_LOG_ERR, ctx->log, 0, "python error pos 1: %s",
                      njt_python_get_error(ctx->pool));
    }

#if !(NJT_PYTHON_SYNC)
    (void) njt_python_set_ctx(pctx);
#endif

    return result;
}


#if !(NJT_PYTHON_SYNC)

static void
njt_python_task_handler()
{
    njt_python_ctx_t  *ctx;

    ctx = njt_python_get_ctx();
    PyThreadState_Swap(ctx->ps);
    njt_log_debug0(NJT_LOG_DEBUG_CORE, ctx->log, 0, "python task handler");
    //ctx->result = PyObject_CallFunctionObjArgs(ctx->code, ctx->arg,NULL);
    ctx->result = PyEval_EvalFrame(ctx->frame);
    //ctx->result = PyEval_EvalCode(ctx->code, ctx->ns, ctx->ns);
    if (ctx->result == NULL) {
        njt_log_debug1(NJT_LOG_DEBUG_CORE, ctx->log, 0, "python result null pos 2: %s",
                      njt_python_get_error(ctx->pool));
    }
    njt_log_debug2(NJT_LOG_DEBUG_CORE, ctx->log, 0, "python task handler,ctx:%p,ret:%p",ctx,ctx->result);
}

#endif


void
njt_python_set_resolver(njt_python_ctx_t *ctx, njt_resolver_t *resolver,
    njt_msec_t timeout)
{
    ctx->resolver = resolver;
    ctx->resolver_timeout = timeout;
}


njt_resolver_t *
njt_python_get_resolver(njt_python_ctx_t *ctx, njt_msec_t *timeout)
{
    *timeout = ctx->resolver_timeout;
    return ctx->resolver;
}


PyObject *
njt_python_set_value(njt_python_ctx_t *ctx, const char *name, PyObject *value)
{
    PyObject  *old;
    old = PyDict_GetItemString(ctx->local, name);

    if (old == NULL) {
        if (PyDict_SetItemString(ctx->local, name, value) < 0) {
            njt_log_error(NJT_LOG_ERR, ctx->log, 0,
                          "python error pos 3: %s", njt_python_get_error(ctx->pool));
        }
    }

    return old;
}


void
njt_python_reset_value(njt_python_ctx_t *ctx, const char *name, PyObject *old)
{
    if (old == NULL) {
        if (PyDict_DelItemString(ctx->local, name) < 0) {
            njt_log_error(NJT_LOG_ERR, ctx->log, 0,
                          "python error pos 4: %s", njt_python_get_error(ctx->pool));
        }
    }
}


njt_int_t
njt_python_active(njt_conf_t *cf)
{
    njt_python_conf_t  *pcf;

    pcf = (njt_python_conf_t *) njt_get_conf(cf->cycle->conf_ctx,
                                             njt_python_module);

    return pcf->ns ? NJT_OK : NJT_DECLINED;
}


char *
njt_python_set_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    PyObject   *ret, *ns;
    njt_str_t  *value;

    ns = njt_python_init_namespace(cf);
    if (ns == NULL) {
        return NJT_CONF_ERROR;
    }

    value = cf->args->elts;

    ret = PyRun_StringFlags((char *) value[1].data, Py_file_input, ns, ns,
                            NULL);
    if (ret == NULL) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "python error pos 5: %s",
                           njt_python_get_error(cf->pool));
        return NJT_CONF_ERROR;
    }

    Py_DECREF(ret);

    return NJT_CONF_OK;
}


char *
njt_python_include_set_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char         *rv;
    PyObject     *ns;
    njt_int_t     n;
    njt_str_t    *value, file, name;
    njt_glob_t    gl;

    ns = njt_python_init_namespace(cf);
    if (ns == NULL) {
        return NJT_CONF_ERROR;
    }

    value = cf->args->elts;
    file = value[1];

    njt_log_debug2(NJT_LOG_DEBUG_CORE, cf->log, 0, "python_include %s,%p",
                   file.data,conf);

    if (njt_conf_full_name(cf->cycle, &file, 1) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    if (strpbrk((char *) file.data, "*?[") == NULL) {

        njt_log_debug1(NJT_LOG_DEBUG_CORE, cf->log, 0, "python_include %s",
                       file.data);
        if (memcmp(file.data+file.len-3,".py",3)==0)
            return njt_python_include_file(cf, ns, (char *) file.data);
        else
            return njt_python_load_app(cf, ns, (char *) file.data);
    }

    njt_memzero(&gl, sizeof(njt_glob_t));

    gl.pattern = file.data;
    gl.log = cf->log;
    gl.test = 1;

    if (njt_open_glob(&gl) != NJT_OK) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, njt_errno,
                           njt_open_glob_n " \"%s\" failed", file.data);
        return NJT_CONF_ERROR;
    }

    rv = NJT_CONF_OK;

    for ( ;; ) {
        n = njt_read_glob(&gl, &name);

        if (n != NJT_OK) {
            break;
        }

        file.len = name.len++;
        file.data = njt_pstrdup(cf->pool, &name);
        if (file.data == NULL) {
            return NJT_CONF_ERROR;
        }

        njt_log_debug1(NJT_LOG_DEBUG_CORE, cf->log, 0, "python_include %s",
                       file.data);
                       //hack, 
                       //todo: howto check it's a library, instead of py file?
        if (memcmp(file.data+file.len-3,".py",3)==0)
            rv = njt_python_include_file(cf, ns, (char *) file.data);
        else 
            rv = njt_python_load_app(cf, ns, (char *) file.data);
        if (rv != NJT_CONF_OK) {
            break;
        }
    }

    njt_close_glob(&gl);

    return rv;
}

static char *njt_python_load_app(njt_conf_t *cf, PyObject *ns, char *file){
    void* hd= dlopen(file,RTLD_LAZY);
    if (!hd) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, njt_errno,
                           "fopen() \"%s\" failed", file);
        return NJT_CONF_ERROR;
    }
    else  njt_conf_log_error(NJT_LOG_INFO, cf, njt_errno,
                           "fopen() \"%s\" ok", file);

    PyObject* ( * md)() =dlsym(hd,"PyInit_run_doc");
    if (!md){
        njt_conf_log_error(NJT_LOG_EMERG, cf, njt_errno,
                           "no sym() \"%s\" failed", "PyInit_run_doc");
        return NJT_CONF_ERROR;
    }
    if (NULL==(md)()){
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "python error pos 6: %s",
                           njt_python_get_error(cf->pool));
        return NJT_CONF_ERROR;
    }
     PyObject *pmodule = PyImport_ImportModuleEx("run_doc",ns,ns,0);
     if (NULL==pmodule){
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "python error pos 7: %s",
                           njt_python_get_error(cf->pool));
        return NJT_CONF_ERROR;
    }

    PyDict_SetItemString(ns,"run_doc",pmodule);

    return NJT_CONF_OK;
};
static char *
njt_python_include_file(njt_conf_t *cf, PyObject *ns, char *file)
{
    FILE      *fp;
    PyObject  *ret;

    fp = fopen(file, "r");
    if (fp == NULL) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, njt_errno,
                           "fopen() \"%s\" failed", file);
        return NJT_CONF_ERROR;
    }

    ret = PyRun_FileExFlags(fp, file, Py_file_input, ns, ns, 0, NULL);

    fclose(fp);

    if (ret == NULL) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "python error pos 8: %s",
                           njt_python_get_error(cf->pool));
        return NJT_CONF_ERROR;
    }

    Py_DECREF(ret);

    return NJT_CONF_OK;
}


PyObject *
njt_python_compile(njt_conf_t *cf, u_char *script)
{
    u_char              *p;
    size_t               len;
    PyObject            *code;
    njt_pool_cleanup_t  *cln;

    if (njt_python_init_namespace(cf) == NULL) {
        return NULL;
    }

    len = cf->conf_file->file.name.len + 1 + NJT_INT_T_LEN + 1;

    p = njt_pnalloc(cf->pool, len);
    if (p == NULL) {
        return NULL;
    }

    njt_sprintf(p, "%V:%ui%Z", &cf->conf_file->file.name, cf->conf_file->line);

    code = Py_CompileString((char *) script, (char *) p, Py_eval_input);

    if (code == NULL) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "python error pos 9: %s",
                           njt_python_get_error(cf->pool));
        return NULL;
    }

    cln = njt_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        Py_DECREF(code);
        return NULL;
    }

    cln->handler = njt_python_decref;
    cln->data = code;

    return  code;
}


static void
njt_python_decref(void *data)
{
    PyObject *obj = data;

    Py_DECREF(obj);
}

/*
static PyMethodDef njtPyMethods[]= {
	{NULL, NULL, 0, NULL}
};
*/

static struct PyModuleDef njtPyDem =
{
    PyModuleDef_HEAD_INIT,
    "njt", /* name of module */
    "",          /* module documentation, may be NULL */
    -1,          /* size of per-interpreter state of the module, or -1 if the module keeps state in global variables. */
    NULL,
	NULL,
	NULL,
	NULL,
	NULL
};

PyMODINIT_FUNC
PyInit_njt(void)
{
    PyObject* m= PyModule_Create(&njtPyDem);
        PyModule_AddIntConstant(m, "OK", NJT_OK);
        PyModule_AddIntConstant(m, "ERROR", NJT_ERROR);
        PyModule_AddIntConstant(m, "AGAIN", NJT_AGAIN);
        PyModule_AddIntConstant(m, "BUSY", NJT_BUSY);
        PyModule_AddIntConstant(m, "DONE", NJT_DONE);
        PyModule_AddIntConstant(m, "DECLINED", NJT_DECLINED);
        PyModule_AddIntConstant(m, "ABORT", NJT_ABORT);

        PyModule_AddIntConstant(m, "LOG_EMERG", NJT_LOG_EMERG);
        PyModule_AddIntConstant(m, "LOG_ALERT", NJT_LOG_ALERT);
        PyModule_AddIntConstant(m, "LOG_CRIT", NJT_LOG_CRIT);
        PyModule_AddIntConstant(m, "LOG_ERR", NJT_LOG_ERR);
        PyModule_AddIntConstant(m, "LOG_WARN", NJT_LOG_WARN);
        PyModule_AddIntConstant(m, "LOG_NOTICE", NJT_LOG_NOTICE);
        PyModule_AddIntConstant(m, "LOG_INFO", NJT_LOG_INFO);
        PyModule_AddIntConstant(m, "LOG_DEBUG", NJT_LOG_DEBUG);

        PyModule_AddIntConstant(m, "SEND_LAST", 1);
        PyModule_AddIntConstant(m, "SEND_FLUSH", 2);
	return m;
}
PyObject * njt_python_get_namespace(njt_cycle_t* cycle){
    njt_python_conf_t        *pcf;
    pcf = (njt_python_conf_t *) njt_get_conf(cycle->conf_ctx,
                                             njt_python_module);
    if (pcf->ns) {
        return pcf->ns;
    }
    return NULL;
};
PyObject *
njt_python_init_namespace(njt_conf_t *cf)
{
    u_char                   *name;
    PyObject                 *ns, *m;
    njt_python_conf_t        *pcf;
    njt_pool_cleanup_t       *cln;
    njt_python_ns_cleanup_t  *nc;
    static njt_int_t          initialized;
    static njt_uint_t         counter;

    pcf = (njt_python_conf_t *) njt_get_conf(cf->cycle->conf_ctx,
                                             njt_python_module);
    if (pcf->ns) {
        return pcf->ns;
    }

    if (!initialized) {
        initialized = 1;

		PyImport_AppendInittab("njt",PyInit_njt) ;
        Py_Initialize();
        printf("py init succeed.\n");
    }

    nc = njt_palloc(cf->pool, sizeof(njt_python_ns_cleanup_t));
    if (nc == NULL) {
        return NULL;
    }

    cln = njt_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    name = njt_pnalloc(cf->pool, 4 + NJT_INT_T_LEN);
    if (name == NULL) {
        return NULL;
    }

    /* generate a unique namespace name */

    njt_sprintf(name, "njt%ui%Z", counter++);

    m = PyImport_AddModule((char *) name);
    if (m == NULL) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "could not add \"%s\" Python module", name);
        return NULL;
    }

    ns = PyModule_GetDict(m);
    if (ns == NULL) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "could not get \"%s\" Python module dictionary",
                           name);
        return NULL;
    }

    Py_INCREF(ns);

    nc->ns = ns;
    nc->name = name;
    nc->ps = PyThreadState_GET();

    cln->handler = njt_python_cleanup_namespace;
    cln->data = nc;

    if (PyDict_SetItemString(ns, "__builtins__", PyEval_GetBuiltins()) < 0) {
        return NULL;
    }

    pcf->ns = ns;
    pcf->main_ps = nc->ps;

    return ns;
}


static void
njt_python_cleanup_namespace(void *data)
{
    njt_python_ns_cleanup_t  *nc = data;

    PyObject  *modules;

    PyThreadState_Swap(nc->ps);
    Py_DECREF(nc->ns);

    modules = PyImport_GetModuleDict();

    if (PyDict_GetItemString(modules, (char *) nc->name) == NULL) {
        return;
    }

    if (PyDict_DelItemString(modules, (char *) nc->name) < 0) {
        /* XXX error removing module from sys.modules */
    }
}


u_char *
njt_python_get_error(njt_pool_t *pool)
{
    long         line;
    const char        *text, *file;
    size_t       len;
    u_char      *p;
    PyObject    *type, *value, *traceback, *str, *module, *func, *ret, *frame,
                *obj;
    Py_ssize_t   size;

    /* PyErr_Print(); */

    str = NULL;
    module = NULL;
    func = NULL;
    ret = NULL;

    text = "";
    file = "";
    line = 0;

    PyErr_Fetch(&type, &value, &traceback);
    if (type == NULL) {
        goto done;
    }

    PyErr_NormalizeException(&type, &value, &traceback);
    if (type == NULL) {
        goto done;
    }

    str = PyObject_Str(value);
    if (str && PyUnicode_Check(str)) {
        text = PyUnicode_AsUTF8(str);
    }

    module = PyImport_ImportModule("traceback");
    if (module == NULL) {
        goto done;
    }

    func = PyObject_GetAttrString(module, "extract_tb");
    if (func == NULL || !PyCallable_Check(func)) {
        goto done;
    }

    ret = PyObject_CallFunctionObjArgs(func, traceback, NULL);


    if (ret == NULL || !PyList_Check(ret)) {
        goto done;
    }

    size = PyList_Size(ret);
    if (size <= 0) {
        goto done;
    }
    ssize_t cnt=size-1;
    frame = PyList_GetItem(ret, cnt);
    if (frame == NULL || !PyTuple_Check(frame)) {
        goto done;
    }

    obj = PyTuple_GetItem(frame, 0);
    if (obj &&  PyUnicode_Check(obj)) {
        file = PyUnicode_AsUTF8(obj);
    }

    obj = PyTuple_GetItem(frame, 1);
    if (obj && PyLong_Check(obj)) {
        line = PyLong_AsLong(obj);
    }


done:

    PyErr_Clear();

    len = njt_strlen(text) + 2 + njt_strlen(file) + 1 + NJT_INT_T_LEN + 2;

    p = njt_pnalloc(pool, len);
    if (p == NULL) {
        return (u_char *) "";
    }

    njt_sprintf(p, "%s [%s:%l]%Z", text, file, line);

    Py_XDECREF(str);
    Py_XDECREF(type);
    Py_XDECREF(value);
    Py_XDECREF(traceback);
    Py_XDECREF(module);
    Py_XDECREF(func);
    Py_XDECREF(ret);

    return p;
}


static void *
njt_python_create_conf(njt_cycle_t *cycle)
{
    njt_python_conf_t  *pcf;

    pcf = njt_pcalloc(cycle->pool, sizeof(njt_python_conf_t));
    if (pcf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     pcf->ns = NULL;
     *
     */

    pcf->stack_size = NJT_CONF_UNSET_SIZE;
    pcf->init_codes = njt_array_create(cycle->pool, 1, sizeof(PyObject *));
    pcf->init_codes->nelts =0;
    // njt_log_error(NJT_LOG_ERR,cycle->log,0,"create cf:%p,%p",pcf,pcf->resolver);
    return pcf;
}


static char *
njt_python_init_conf(njt_cycle_t *cycle, void *conf)
{
    njt_python_conf_t *pcf = conf;

    njt_conf_init_size_value(pcf->stack_size, 32768);

    return NJT_CONF_OK;
}
/*
static void timer_handler(njt_event_t *ev) {
    return;
}
static njt_event_t *add_timer(njt_cycle_t *cycle,void (* handler)(njt_event_t *)   ){
    njt_event_t *ev;
    njt_connection_t *c = njt_palloc(cycle->pool, sizeof(njt_connection_t));
    njt_memzero(c, sizeof(njt_connection_t));

    ev = njt_palloc(cycle->pool, sizeof(njt_event_t));
    njt_memzero(ev, sizeof(njt_event_t));
    ev->log = cycle->log;
    ev->handler = handler;
    ev->cancelable = 1;
    ev->data = c;
    c->fd = (njt_socket_t)-1;
    c->data = NULL;
    //njt_add_timer(ev, interval);
    return ev;
}
*/
static njt_int_t
njt_python_init_worker(njt_cycle_t *cycle)
{
#if !(NJT_PYTHON_SYNC)

    njt_python_conf_t  *pcf;

    pcf = (njt_python_conf_t *) njt_get_conf(cycle->conf_ctx,
                                             njt_python_module);

    if (pcf->ns) {

        // if (njt_python_sleep_install(cycle) != NJT_OK) {
        //     njt_log_error(NJT_LOG_ERR, cycle->log, 0, "failed to load python sleep module");
        //     return NJT_ERROR;
        // }

        // if (njt_python_socket_install(cycle) != NJT_OK) {
        //     njt_log_error(NJT_LOG_ERR, cycle->log, 0, "failed to load python socket module");
        //     return NJT_ERROR;
        // }

        // if (njt_python_resolve_install(cycle) != NJT_OK) {
        //     njt_log_error(NJT_LOG_ERR, cycle->log, 0, "failed to load python resolve module");
        //     return NJT_ERROR;
        // }

    }

#endif

    return NJT_OK;
}
