
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_log_ringbuf.h.tt2
 */


#ifndef _NJT_STREAM_LUA_RINGBUF_H_INCLUDED_
#define _NJT_STREAM_LUA_RINGBUF_H_INCLUDED_


#include "njt_stream_lua_common.h"


typedef struct {
    njt_uint_t   filter_level;
    char        *tail;              /* writed point */
    char        *head;              /* readed point */
    char        *data;              /* buffer */
    char        *sentinel;
    size_t       size;              /* buffer total size */
    size_t       count;             /* count of logs */
} njt_stream_lua_log_ringbuf_t;


void njt_stream_lua_log_ringbuf_init(njt_stream_lua_log_ringbuf_t *rb,
    void *buf, size_t len);
void njt_stream_lua_log_ringbuf_reset(njt_stream_lua_log_ringbuf_t *rb);
njt_int_t njt_stream_lua_log_ringbuf_read(njt_stream_lua_log_ringbuf_t *rb,
    int *log_level, void **buf, size_t *n, double *log_time);
njt_int_t njt_stream_lua_log_ringbuf_write(njt_stream_lua_log_ringbuf_t *rb,
    int log_level, void *buf, size_t n);


#endif /* _NJT_STREAM_LUA_RINGBUF_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
