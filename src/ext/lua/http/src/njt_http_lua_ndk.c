
/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_http_lua_ndk.h"
#include "njt_http_lua_util.h"


#if defined(NDK) && NDK


static ndk_set_var_value_pt njt_http_lookup_ndk_set_var_directive(u_char *name,
    size_t name_len);


void
njt_http_lua_inject_ndk_api(lua_State *L)
{
    lua_createtable(L, 0, 1 /* nrec */);    /* ndk.* */

    lua_getglobal(L, "package"); /* ndk package */
    lua_getfield(L, -1, "loaded"); /* ndk package loaded */
    lua_pushvalue(L, -3); /* ndk package loaded ndk */
    lua_setfield(L, -2, "ndk"); /* ndk package loaded */
    lua_pop(L, 2);

    lua_setglobal(L, "ndk");
}


static ndk_set_var_value_pt
njt_http_lookup_ndk_set_var_directive(u_char *name,
    size_t name_len)
{
    ndk_set_var_t           *filter;
    njt_uint_t               i;
    njt_module_t            *module;
    njt_module_t           **modules;
    njt_command_t           *cmd;

#if (njet_version >= 1009011)
    modules = njt_cycle->modules;
#else
    modules = njt_modules;
#endif

    for (i = 0; modules[i]; i++) {
        module = modules[i];
        if (module->type != NJT_HTTP_MODULE) {
            continue;
        }

        cmd = modules[i]->commands;
        if (cmd == NULL) {
            continue;
        }

        for ( /* void */ ; cmd->name.len; cmd++) {
            if (cmd->set != ndk_set_var_value) {
                continue;
            }

            filter = cmd->post;
            if (filter == NULL) {
                continue;
            }

            if (cmd->name.len != name_len
                || njt_strncmp(cmd->name.data, name, name_len) != 0)
            {
                continue;
            }

            return (ndk_set_var_value_pt)(filter->func);
        }
    }

    return NULL;
}


int
njt_http_lua_ffi_ndk_lookup_directive(const u_char *var_data,
    size_t var_len, ndk_set_var_value_pt *func)
{
    *func = njt_http_lookup_ndk_set_var_directive((u_char *) var_data, var_len);

    if (*func == NULL) {
        return NJT_ERROR;
    }

    return NJT_OK;
}


int
njt_http_lua_ffi_ndk_set_var_get(njt_http_request_t *r,
    ndk_set_var_value_pt func, const u_char *arg_data, size_t arg_len,
    njt_http_lua_ffi_str_t *value)
{
    njt_int_t                            rc;
    njt_str_t                            res;
    njt_http_variable_value_t            arg;

    njt_memzero(&arg, sizeof(njt_http_variable_value_t));
    arg.valid = 1;

    arg.data = (u_char *) arg_data;
    arg.len = arg_len;

    rc = func(r, &res, &arg);

    if (rc != NJT_OK) {
        return rc;
    }

    value->data = res.data;
    value->len = res.len;
    return NJT_OK;
}


#endif /* defined(NDK) && NDK */


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
