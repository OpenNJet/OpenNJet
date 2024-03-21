#ifndef _NJT_HTTP_LUA_SET_BY_H_INCLUDED_
#define _NJT_HTTP_LUA_SET_BY_H_INCLUDED_

#include "njt_http_lua_common.h"


njt_int_t njt_http_lua_set_by_chunk(lua_State *L, njt_http_request_t *r,
    njt_str_t *val, njt_http_variable_value_t *args, size_t nargs,
    njt_str_t *script);


#endif /* _NJT_HTTP_LUA_SET_BY_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
