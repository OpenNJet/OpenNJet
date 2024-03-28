
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#ifndef _NJT_STREAM_STS_VARIABLES_H_INCLUDED_
#define _NJT_STREAM_STS_VARIABLES_H_INCLUDED_


njt_int_t njt_stream_server_traffic_status_node_variable(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data);
njt_int_t njt_stream_server_traffic_status_add_variables(njt_conf_t *cf);


#endif /* _NJT_STREAM_STS_VARIABLES_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
