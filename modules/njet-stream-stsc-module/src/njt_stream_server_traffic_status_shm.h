
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#ifndef _NJT_STREAM_STS_SHM_H_INCLUDED_
#define _NJT_STREAM_STS_SHM_H_INCLUDED_


njt_int_t njt_stream_server_traffic_status_shm_add_server(njt_stream_session_t *s);
njt_int_t njt_stream_server_traffic_status_shm_add_filter(njt_stream_session_t *s);
njt_int_t njt_stream_server_traffic_status_shm_add_upstream(njt_stream_session_t *s);


#endif /* _NJT_STREAM_STS_SHM_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
