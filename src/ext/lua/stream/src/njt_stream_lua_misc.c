
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_misc.c.tt2
 */


/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_stream_lua_misc.h"
#include "njt_stream_lua_util.h"




int
njt_stream_lua_ffi_get_resp_status(njt_stream_lua_request_t *r)
{
    return r->session->status;
}




int
njt_stream_lua_ffi_get_conf_env(u_char *name, u_char **env_buf,
    size_t *name_len)
{
    njt_uint_t            i;
    njt_str_t            *var;
    njt_core_conf_t      *ccf;

    ccf = (njt_core_conf_t *) njt_get_conf(njt_cycle->conf_ctx,
                                           njt_core_module);

    var = ccf->env.elts;

    for (i = 0; i < ccf->env.nelts; i++) {
        if (var[i].data[var[i].len] == '='
            && njt_strncmp(name, var[i].data, var[i].len) == 0)
        {
            *env_buf = var[i].data;
            *name_len = var[i].len;

            return NJT_OK;
        }
    }

    return NJT_DECLINED;
}


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
