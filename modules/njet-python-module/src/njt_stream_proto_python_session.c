
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) 2021-2024  TMLake(Beijing) Technology Co., Ltd.
 */


#include <Python.h>
#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>
#include "njt_stream_proto_python_session.h"
#include "njt_stream_proto_server_module.h"
#include "tcc_ws.h"


typedef struct{
    WSOpcode  code;
    char     *msg;
    size_t    msg_len;
} njt_ws_in_data_t;

typedef struct app_client_s {
    tcc_str_t *init_data;
    int  id;
} app_client_t; // same as tcc_ws.c

typedef struct {
    PyObject_HEAD
    njt_stream_session_t          *session;
    PyObject                      *msg;
    tcc_stream_request_t          *ws_req;
} njt_stream_proto_python_session_t;


// typedef struct {
//     PyObject_HEAD
//     njt_stream_proto_python_session_t   *ps;
// } njt_stream_proto_python_session_var_t;


static PyObject *njt_stream_proto_python_session_log(
    njt_stream_proto_python_session_t* self, PyObject* args);
static PyObject *njt_stream_proto_python_send(
    njt_stream_proto_python_session_t* self, PyObject* args);
static PyObject *njt_stream_proto_python_send_others(
    njt_stream_proto_python_session_t* self, PyObject* args);
static PyObject *njt_stream_proto_python_broadcast(
    njt_stream_proto_python_session_t* self, PyObject* args);
static PyObject *njt_stream_proto_python_session_msg(
    njt_stream_proto_python_session_t *self, void *closure);
static PyObject *njt_stream_proto_python_session_client_id(
    njt_stream_proto_python_session_t *self, void *closure);
static void njt_stream_proto_python_session_dealloc(
    njt_stream_proto_python_session_t *self);

// static PyObject *njt_stream_proto_python_session_var_subscript(
//     njt_stream_proto_python_session_var_t *self, PyObject *key);
// static void njt_stream_proto_python_session_var_dealloc(
//     njt_stream_proto_python_session_var_t *self);

// static void njt_stream_proto_python_session_cleanup(void *data);


static PyMethodDef njt_stream_proto_python_session_methods[] = {

    { "log",
      (PyCFunction) njt_stream_proto_python_session_log,
      METH_VARARGS,
      "output a message to the error log" },

    { "send",
      (PyCFunction) njt_stream_proto_python_send,
      METH_VARARGS,
      "output a message to the error log" },

    { "send_others",
      (PyCFunction) njt_stream_proto_python_send_others,
      METH_VARARGS,
      "output a message to the error log" },

    { "broadcast",
      (PyCFunction) njt_stream_proto_python_broadcast,
      METH_VARARGS,
      "output a message to the error log" },

    { NULL, NULL, 0, NULL }
};


static PyGetSetDef njt_stream_proto_python_session_getset[] = {

    { "msg",
      (getter) njt_stream_proto_python_session_msg,
      NULL,
      "njet per-session variables",
      NULL },

    { "client_id",
      (getter) njt_stream_proto_python_session_client_id,
      NULL,
      "njet per-session variables",
      NULL },

    { NULL, NULL, NULL, NULL, NULL }
};


static PyTypeObject  njt_stream_proto_python_session_type = {
    .tp_name = "njt.StreamSession",
    .tp_basicsize = sizeof(njt_stream_proto_python_session_t),
    .tp_dealloc = (destructor) njt_stream_proto_python_session_dealloc,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = "Stream session",
    .tp_methods = njt_stream_proto_python_session_methods,
    .tp_getset = njt_stream_proto_python_session_getset
};


// static PyMappingMethods njt_stream_proto_python_session_var_mapping = {
//     NULL,                                          /*mp_length*/
//     (binaryfunc) njt_stream_proto_python_session_var_subscript,
//                                                    /*mp_subscript*/
//     NULL,                                          /*mp_ass_subscript*/
// };


// static PyTypeObject  njt_stream_proto_python_session_var_type = {
//     //.ob_refcnt = 1,
//     .tp_name = "njt.StreamVariables",
//     .tp_basicsize = sizeof(njt_stream_proto_python_session_var_t),
//     .tp_dealloc = (destructor) njt_stream_proto_python_session_var_dealloc,
//     .tp_as_mapping = &njt_stream_proto_python_session_var_mapping,
//     .tp_flags = Py_TPFLAGS_DEFAULT,
//     .tp_doc = "Stream variables"
// };


static PyObject  *njt_stream_proto_python_session_error;


PyObject *
njt_stream_proto_python_session_log(njt_stream_proto_python_session_t *self, PyObject *args)
{
    int                    level;
    const char            *msg;
    njt_stream_session_t  *s;

    s = self->session;
    if (s == NULL) {
        PyErr_SetString(njt_stream_proto_python_session_error, "session finalized");
        return NULL;
    }

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream python log()");

    level = NJT_LOG_INFO;

    if (!PyArg_ParseTuple(args, "s|i:log", &msg, &level)) {
        return NULL;
    }

    njt_log_error((njt_uint_t) level, s->connection->log, 0, msg);

    Py_RETURN_NONE;
}


PyObject *
njt_stream_proto_python_send(njt_stream_proto_python_session_t* self, PyObject *args)
{
    int                    level;
    char                  *msg;
    tcc_stream_request_t  *r;
    njt_stream_session_t  *s;
    tcc_str_t              out_data;
    njt_ws_in_data_t       in_data;

    s = self->session;
    r = self->ws_req;

    if (s == NULL) {
        PyErr_SetString(njt_stream_proto_python_session_error, "session finalized");
        return NULL;
    }

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream python send()");

    level = NJT_LOG_INFO;

    if (!PyArg_ParseTuple(args, "s|i:log", &msg, &level)) {
        return NULL;
    }

    in_data.code = WS_OPCODE_TEXT;
    in_data.msg = msg;
    in_data.msg_len = strlen(msg);

    proto_server_build_message(r, (void *)&in_data, &out_data);
    proto_server_send(r, (char *)out_data.data, out_data.len,1);
    // proto_free(r, out_data.data);
    free(out_data.data);

    Py_RETURN_NONE;
}

PyObject *
njt_stream_proto_python_send_others(njt_stream_proto_python_session_t *self, PyObject *args)
{
    int                    level;
    char                  *msg;
    tcc_stream_request_t  *r;
    njt_stream_session_t  *s;
    tcc_str_t              out_data;
    njt_ws_in_data_t       in_data;

    s = self->session;
    r = self->ws_req;

    if (s == NULL) {
        PyErr_SetString(njt_stream_proto_python_session_error, "session finalized");
        return NULL;
    }

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream python send()");

    level = NJT_LOG_INFO;

    if (!PyArg_ParseTuple(args, "s|i:log", &msg, &level)) {
        return NULL;
    }

    in_data.code = WS_OPCODE_TEXT;
    in_data.msg = msg;
    in_data.msg_len = strlen(msg);

    proto_server_build_message(r, (void *)&in_data, &out_data);
    proto_server_send_others(&r->session,r->tcc_server, (char *)out_data.data, out_data.len);
    // proto_free(r, out_data.data);
    free(out_data.data);

    Py_RETURN_NONE;
}


PyObject *
njt_stream_proto_python_broadcast(njt_stream_proto_python_session_t* self, PyObject* args)
{
    int                    level;
    char                  *msg;
    tcc_stream_request_t  *r;
    njt_stream_session_t  *s;
    tcc_str_t              out_data;
    njt_ws_in_data_t       in_data;

    s = self->session;
    r = self->ws_req;

    if (s == NULL) {
        PyErr_SetString(njt_stream_proto_python_session_error, "session finalized");
        return NULL;
    }

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream python send()");

    level = NJT_LOG_INFO;

    if (!PyArg_ParseTuple(args, "s|i:log", &msg, &level)) {
        return NULL;
    }

    in_data.code = WS_OPCODE_TEXT;
    in_data.msg = msg;
    in_data.msg_len = strlen(msg);

    proto_server_build_message(r, (void *)&in_data, &out_data);
    proto_server_send_broadcast(&r->session,r->tcc_server, (char *)out_data.data, out_data.len);
    // proto_free(r, out_data.data);
    free(out_data.data);

    Py_RETURN_NONE;
}

static PyObject *
njt_stream_proto_python_session_msg(njt_stream_proto_python_session_t *self, void *closure)
{
    Py_INCREF(self->msg);
    return self->msg;
}


static PyObject *
njt_stream_proto_python_session_client_id(njt_stream_proto_python_session_t *self, void *closure)
{

    app_client_t *app_client = tcc_get_client_app_ctx(self->ws_req);
    PyObject *client_id = PyLong_FromLong(app_client->id);
    return client_id;
}


static void
njt_stream_proto_python_session_dealloc(njt_stream_proto_python_session_t *self)
{
    Py_XDECREF(self->msg);

    self->session = NULL;
    self->ws_req = NULL;

    Py_TYPE(self)->tp_free((PyObject*) self);
}


// static PyObject *
// njt_stream_python_session_var_subscript(njt_stream_python_session_var_t *self,
//     PyObject *key)
// {
//     char                         *data;
//     njt_str_t                     name;
//     njt_uint_t                    hash;
//     Py_ssize_t                    len;
//     njt_stream_session_t         *s;
//     njt_stream_variable_value_t  *vv;

//     s = self->ps->session;
//     if (s == NULL) {
//         PyErr_SetString(njt_stream_python_session_error, "session finalized");
//         return NULL;
//     }

//     njt_log_debug0(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
//                    "stream python var subscript()");

//     if (PyBytes_AsStringAndSize(key, &data, &len) < 0 ) {
//         return NULL;
//     }

//     name.data = (u_char *) data;
//     name.len = len;

//     hash = njt_hash_strlow(name.data, name.data, name.len);

//     vv = njt_stream_get_variable(s, &name, hash);
//     if (vv == NULL) {
//         PyErr_SetNone(njt_stream_python_session_error);
//         return NULL;
//     }

//     if (vv->not_found) {
//         return PyBytes_FromStringAndSize(NULL, 0);
//     }

//     return PyBytes_FromStringAndSize((char *) vv->data, vv->len);
// }


// static void
// njt_stream_python_session_var_dealloc(njt_stream_python_session_var_t *self)
// {
//     Py_DECREF(self->ps);

//     Py_TYPE(self)->tp_free((PyObject*) self);
// }


njt_int_t
njt_stream_proto_python_session_init(njt_conf_t *cf)
{
    static njt_int_t  initialized;

    if (initialized) {
        return NJT_OK;
    }

    initialized = 1;

    if (PyType_Ready(&njt_stream_proto_python_session_type) < 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "could not add %s type",
                           njt_stream_proto_python_session_type.tp_name);
        return NJT_ERROR;
    }

    // if (PyType_Ready(&njt_stream_python_session_var_type) < 0) {
    //     njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "could not add %s type",
    //                        njt_stream_python_session_var_type.tp_name);
    //     return NJT_ERROR;
    // }

    njt_stream_proto_python_session_error = PyErr_NewException(
                                                       "njt.StreamSessionError",
                                                       PyExc_RuntimeError,
                                                       NULL);
    if (njt_stream_proto_python_session_error == NULL) {
        return NJT_ERROR;
    }

    return NJT_OK;
}


PyObject *
njt_stream_proto_python_create(tcc_stream_request_t *r, char *msg, size_t msg_len)
{
    njt_stream_session_t               *s;
    njt_stream_proto_python_session_t  *ps;

    s = (njt_stream_session_t*) r->s;
    njt_log_debug0(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream python create session");

    ps = PyObject_New(njt_stream_proto_python_session_t,
                      &njt_stream_proto_python_session_type);
    if (ps == NULL) {
        goto failed;
    }

    ps->session = s;
    ps->ws_req = r;

    ps->msg = PyBytes_FromStringAndSize(msg, msg_len);
    if (ps->msg == NULL) {
        Py_DECREF(ps);
        goto failed;
    }

    return (PyObject *) ps;

failed:

    njt_log_error(NJT_LOG_ERR, s->connection->log, 0, "python error: %s",
                  njt_python_get_error(s->connection->pool));

    return NULL;
}


// static void
// njt_stream_python_session_cleanup(void *data)
// {
//     njt_stream_python_session_t *ps = data;

//     ps->session = NULL;

//     Py_DECREF(ps);
// }
