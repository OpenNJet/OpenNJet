
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 * Copyright (C), 2021-2023, TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_VTS_STRING_H_INCLUDED_
#define _NJT_HTTP_VTS_STRING_H_INCLUDED_


#if !defined(njet_version) || njet_version < 1007009
uintptr_t njt_http_vhost_traffic_status_escape_json(u_char *dst, u_char *src, size_t size);
#endif
njt_int_t njt_http_vhost_traffic_status_escape_json_pool(njt_pool_t *pool,
    njt_str_t *buf, njt_str_t *dst);
njt_int_t njt_http_vhost_traffic_status_copy_str(njt_pool_t *pool,
    njt_str_t *buf, njt_str_t *dst);
njt_int_t njt_http_vhost_traffic_status_replace_chrc(njt_str_t *buf,
    u_char in, u_char to);
njt_int_t njt_http_vhost_traffic_status_replace_strc(njt_str_t *buf,
    njt_str_t *dst, u_char c);
njt_int_t njt_http_vhost_traffic_status_escape_prometheus(njt_pool_t *pool, njt_str_t *buf,
	u_char *p, size_t n);

#endif /* _NJT_HTTP_VTS_STRING_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
