
/*
 * Copyright (C) OpenResty Inc.
 */


#ifndef _NJT_STREAM_LUA_REQUEST_H_INCLUDED_
#define _NJT_STREAM_LUA_REQUEST_H_INCLUDED_


typedef void (*njt_stream_lua_cleanup_pt)(void *data);

typedef struct njt_stream_lua_cleanup_s  njt_stream_lua_cleanup_t;

struct njt_stream_lua_cleanup_s {
    njt_stream_lua_cleanup_pt               handler;
    void                                   *data;
    njt_stream_lua_cleanup_t               *next;
};


typedef struct njt_stream_lua_request_s  njt_stream_lua_request_t;

typedef void (*njt_stream_lua_event_handler_pt)(njt_stream_lua_request_t *r);


struct njt_stream_lua_request_s {
    njt_connection_t                     *connection;
    njt_stream_session_t                 *session;
    njt_pool_t                           *pool;
    njt_stream_lua_cleanup_t             *cleanup;

    njt_stream_lua_event_handler_pt       read_event_handler;
    njt_stream_lua_event_handler_pt       write_event_handler;
};


void njt_stream_lua_empty_handler(njt_event_t *wev);
void njt_stream_lua_request_handler(njt_event_t *ev);
void njt_stream_lua_block_reading(njt_stream_lua_request_t *r);

njt_stream_lua_cleanup_t *
njt_stream_lua_cleanup_add(njt_stream_lua_request_t *r, size_t size);

njt_stream_lua_request_t *
njt_stream_lua_create_request(njt_stream_session_t *s);
void njt_stream_lua_finalize_real_request(njt_stream_lua_request_t *r,
    njt_int_t rc);
void njt_stream_lua_core_run_phases(njt_stream_lua_request_t *r);


typedef njt_int_t (*njt_stream_lua_handler_pt)(njt_stream_lua_request_t *r);


#define njt_stream_lua_get_module_ctx(r, module)                             \
    njt_stream_get_module_ctx((r)->session, module)
#define njt_stream_lua_set_ctx(r, c, module)                                 \
    njt_stream_set_ctx((r)->session, c, module)
#define njt_stream_lua_get_module_main_conf(r, module)                       \
    njt_stream_get_module_main_conf((r)->session, module)
#define njt_stream_lua_get_module_srv_conf(r, module)                        \
    njt_stream_get_module_srv_conf((r)->session, module)
#define njt_stream_lua_get_module_loc_conf                                   \
    njt_stream_lua_get_module_srv_conf


#endif /* _NJT_STREAM_LUA_REQUEST_H_INCLUDED_ */
