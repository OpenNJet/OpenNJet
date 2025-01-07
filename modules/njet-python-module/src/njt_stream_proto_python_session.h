
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) 2021-2024  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_STREAM_PYTHON_SESSION_H_INCLUDED_
#define _NJT_STREAM_PYTHON_SESSION_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>
#include "njt_python.h"
#include "njt_tcc.h"


njt_int_t njt_stream_proto_python_session_init(njt_conf_t *cf);
PyObject *njt_stream_proto_python_create(tcc_stream_request_t *s, char *msg, size_t len);
int njt_stream_proto_python_on_msg(tcc_stream_request_t *s, char *msg, size_t len);

#endif /* _NJT_STREAM_PYTHON_SESSION_H_INCLUDED_ */
