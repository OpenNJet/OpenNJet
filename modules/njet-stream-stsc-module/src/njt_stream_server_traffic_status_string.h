
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#ifndef _NJT_STREAM_STS_STRING_H_INCLUDED_
#define _NJT_STREAM_STS_STRING_H_INCLUDED_

uintptr_t njt_stream_server_traffic_status_escape_json(u_char *dst, u_char *src, size_t size);
njt_int_t njt_stream_server_traffic_status_escape_json_pool(njt_pool_t *pool,
    njt_str_t *buf, njt_str_t *dst);
njt_int_t njt_stream_server_traffic_status_copy_str(njt_pool_t *pool,
    njt_str_t *buf, njt_str_t *dst);
njt_int_t njt_stream_server_traffic_status_replace_chrc(njt_str_t *buf,
    u_char in, u_char to);
njt_int_t njt_stream_server_traffic_status_replace_strc(njt_str_t *buf,
    njt_str_t *dst, u_char c);


#endif /* _NJT_STREAM_STS_STRING_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
