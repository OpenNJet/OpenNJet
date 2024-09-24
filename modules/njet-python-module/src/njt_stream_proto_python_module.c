
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) 2021-2024  TMLake(Beijing) Technology Co., Ltd.
 */


#include <Python.h>
#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>
#include "njt_python.h"
#include <njt_tcc.h>
#include <tcc_ws.h>
#include <njt_stream_proto_server_module.h>
#include "njt_stream_proto_python_session.h"

#include <stdlib.h>

#define NJT_STREEAM_PROTO_SVR_PY_WS_APP 0x00000001;
typedef struct {
    PyObject                *on_msg;
    njt_uint_t               app_type; // only ws type now
} njt_stream_proto_svr_py_conf_t;


typedef struct {
    njt_pool_t                 *pool;
    njt_uint_t                  in_sleep;
    PyObject                   *session;
    njt_python_ctx_t           *python;
} njt_stream_proto_python_ctx_t;


static void *njt_stream_proto_python_create_srv_conf(njt_conf_t *cf);
static char *njt_stream_proto_python_merge_srv_conf(njt_conf_t *cf, void *parent,
    void *child);
static char *njt_proto_server_python_include_set(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static njt_int_t njt_stream_proto_python_init(njt_conf_t *cf);
static PyObject * njt_stream_proto_python_eval_code(tcc_stream_request_t *r, PyObject *code,
    njt_event_t *wake, char *msg, size_t msg_len);


static njt_command_t  njt_stream_proto_python_commands[] = {

    { njt_string("proto_server_py_module"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE12,
      njt_proto_server_python_include_set,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      njt_null_command
};


static njt_stream_module_t  njt_stream_proto_python_module_ctx = {
    NULL,                                  /* preconfiguration */
    njt_stream_proto_python_init,                /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    njt_stream_proto_python_create_srv_conf,     /* create server configuration */
    njt_stream_proto_python_merge_srv_conf       /* merge server configuration */
};


njt_module_t  njt_stream_proto_python_module = {
    NJT_MODULE_V1,
    &njt_stream_proto_python_module_ctx,         /* module context */
    njt_stream_proto_python_commands,            /* module directives */
    NJT_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};


static void
njt_stream_proto_python_ctx_cleanup(void *data)
{
    njt_stream_session_t *s = data;
    njt_stream_proto_python_ctx_t    *ctx;

    ctx = njt_stream_get_module_ctx(s, njt_stream_proto_python_module);

    ctx->python = NULL;
    ctx->session = NULL;
}


int
njt_stream_proto_python_on_msg(tcc_stream_request_t *r, char *msg, size_t msg_len)
{
    PyObject                         *ret;
    njt_int_t                         rc;
    njt_stream_session_t             *s;
    njt_stream_proto_svr_py_conf_t   *pscf;
    njt_stream_proto_python_ctx_t    *ctx;

    s = (njt_stream_session_t*) r->s;
    pscf = njt_stream_get_module_srv_conf(s, njt_stream_proto_python_module);

    ret = njt_stream_proto_python_eval_code(r, pscf->on_msg, s->connection->read, msg, msg_len);

    if (ret == NULL) {
        return NJT_ERROR;
    }

    ctx = njt_stream_get_module_ctx(s, njt_stream_proto_python_module); // ctx is created in eval code

    if (ret == NJT_PYTHON_AGAIN) {
        njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                "stream python doesn't support async op now");

        return NJT_AGAIN;
    }

    rc = PyLong_Check(ret) ? PyLong_AsLong(ret) : NJT_ERROR;
    Py_DECREF(ret);

    njt_destroy_pool(ctx->pool);
    ctx->session = NULL;
    ctx->python = NULL;
    ctx->in_sleep = 0;
    ctx->pool = NULL;

    return rc;
}


static PyObject *
njt_stream_proto_python_eval_code(tcc_stream_request_t *r, PyObject *code,
    njt_event_t *wake, char *msg, size_t msg_len)
{
    PyObject                       *result, *proto_session, *old;
    njt_stream_session_t           *s;
    njt_pool_cleanup_t             *cln;
    njt_pool_t                     *pool;
    njt_stream_proto_python_ctx_t  *ctx;

    s = (njt_stream_session_t*) r->s;

    njt_log_debug2(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream python eval start code:%p, wake:%p", code, wake);

    ctx = njt_stream_get_module_ctx(s, njt_stream_proto_python_module);
    if (ctx == NULL) {
        ctx = njt_pcalloc(s->connection->pool, sizeof(njt_stream_proto_python_ctx_t));
        if (ctx == NULL) {
            njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                   "stream python failed to allocate ctx");

            return NULL;
        }

        cln = njt_pool_cleanup_add(s->connection->pool, 0);
        if (cln == NULL) {
            njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                   "stream python failed to add cln");

            return NULL;
        }
        cln->data = s;
        cln->handler = njt_stream_proto_python_ctx_cleanup;

        njt_stream_set_ctx(s, ctx, njt_stream_proto_python_module);
    } 

    if (ctx->in_sleep == 0) {
        pool = njt_create_pool(NJT_CYCLE_POOL_SIZE, s->connection->log);
        if (pool == NULL) {
            return NULL;
        }
        ctx->pool = pool;
        njt_sub_pool(s->connection->pool, ctx->pool);
        
        if (ctx->python == NULL) {
            ctx->python = njt_python_create_ctx(ctx->pool,
                                                s->connection->log);
            if (ctx->python == NULL) {
                return NULL;
            }
        }

        njt_log_debug1(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                    "stream python create ctx->python: %p", ctx->python);
    }

    if(ctx->session == NULL) {
        proto_session = njt_stream_proto_python_create(r, msg, msg_len);
        if (proto_session == NULL) {
            return NULL;
        }
        ctx->session = proto_session;

        njt_log_debug1(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                    "stream python create ctx->session: %p", ctx->session);
    }

    old = njt_python_set_value(ctx->python, "r", ctx->session);
    result = njt_python_eval(ctx->python, code, NULL, NULL, NULL);
    njt_python_reset_value(ctx->python, "r", old);


    njt_log_debug3(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream python eval end code:%p, wake:%p, result:%p",
                   code, wake, result);

    return result;
}


static void *
njt_stream_proto_python_create_srv_conf(njt_conf_t *cf)
{
    njt_stream_proto_svr_py_conf_t *pscf;

    pscf = njt_pcalloc(cf->pool, sizeof(njt_stream_proto_svr_py_conf_t));
    if (pscf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     pscf->content = NULL;
     */

    // pscf->on_conn = NJT_CONF_UNSET_PTR;
    // pscf->on_msg = NJT_CONF_UNSET_PTR;
    pscf->app_type = NJT_CONF_UNSET_UINT;

    return pscf;
}


static char *
njt_stream_proto_python_merge_srv_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_stream_proto_svr_py_conf_t *prev = parent;
    njt_stream_proto_svr_py_conf_t *conf = child;

    // njt_conf_merge_ptr_value(conf->on_conn, prev->on_conn, NULL);
    njt_conf_merge_ptr_value(conf->on_msg, prev->on_msg, NULL);
    njt_conf_merge_uint_value(conf->app_type, prev->app_type, 0);

    return NJT_CONF_OK;
}


static njt_int_t
njt_stream_proto_python_init(njt_conf_t *cf)
{
    if (njt_python_active(cf) != NJT_OK) {
        return NJT_OK;
    }

    if (njt_stream_proto_python_session_init(cf) != NJT_OK) {
        return NJT_ERROR;
    }

    return NJT_OK;
}


static char *njt_proto_server_python_app_ws_set(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{

    njt_str_t                       *value, full_name;
    PyObject                        *ns, *func_def;
    PyObject                        *app;
    const char*                      file;
    njt_stream_proto_svr_py_conf_t  *pscf = conf;

    if (pscf->on_msg) {
        return "is duplicate (proto_server_py_module)";
    }

    ns = njt_python_init_namespace(cf);
    if (ns == NULL) {
        return NJT_CONF_ERROR;
    }

    value = cf->args->elts;
    full_name = value[1];

    file = (char *)full_name.data;
    app = PyImport_ImportModuleEx(file, ns, ns, 0);

    if (app == NULL) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "python error: %s",
                           njt_python_get_error(cf->pool));
        return NJT_CONF_ERROR;
    }

    PyDict_SetItemString(ns, file, app);

    func_def = NULL;
    func_def = PyObject_GetAttrString(app,"on_msg");
    if (!func_def) {
        njt_conf_log_error(NJT_LOG_INFO, cf, 0, "no python on_msg found in: %s",file);
        PyErr_Clear();
    } else {
        if (!PyCallable_Check(func_def)) {
            //todo: verify signature
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "python on_msg signature error: %s",file);
            return NJT_CONF_ERROR;
        }
    }

    if (func_def) {
        char buf[128];
        snprintf(buf,128,"%s.on_msg(r)",file);
        PyObject * msg_code = Py_CompileString(buf, "" ,Py_eval_input);
        njt_conf_log_error(NJT_LOG_INFO, cf, 0, "python on_msg  found: ");
        pscf->on_msg = msg_code;
    }

    return NJT_CONF_OK;
}

// extern char* njt_prefix;
static char *njt_proto_server_python_include_set(njt_conf_t *cf, njt_command_t *cmd, void *conf) {
    char       *py_path;
    njt_str_t  *value;
    char       *ori_env;
    njt_uint_t  env_len;

    ori_env = getenv("PYTHONPATH");
    env_len = ori_env ? strlen(ori_env) : 0;


    if (cf->args->nelts == 2) {
        py_path = njt_pcalloc(cf->pool, cf->cycle->conf_prefix.len + 2 + env_len);
        if (env_len) {
            memcpy(py_path, ori_env, env_len);
            py_path[env_len] = ':';
            memcpy(py_path + env_len + 1, cf->cycle->conf_prefix.data, cf->cycle->conf_prefix.len);
        } else {
            memcpy(py_path, cf->cycle->conf_prefix.data, cf->cycle->conf_prefix.len);
        }
    } else {
        value = cf->args->elts;
        py_path = njt_pcalloc(cf->pool, value[2].len + 2 + env_len);
        if (env_len) {
            memcpy(py_path, ori_env, env_len);
            py_path[env_len] = ':';
            memcpy(py_path + env_len + 1, value[2].data, value[2].len);
        } else {
            memcpy(py_path, value[2].data, value[2].len);
        }
    }

    setenv("PYTHONPATH", py_path, 1);

    // if (value[2].len == 2 && njt_strcmp(value[2].data, "ws") == 0) {
        return njt_proto_server_python_app_ws_set(cf, cmd, conf);
    // }
}
