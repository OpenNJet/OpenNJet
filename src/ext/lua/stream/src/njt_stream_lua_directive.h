
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_directive.h.tt2
 */


/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_STREAM_LUA_DIRECTIVE_H_INCLUDED_
#define _NJT_STREAM_LUA_DIRECTIVE_H_INCLUDED_


#include "njt_stream_lua_common.h"


char *njt_stream_lua_shared_dict(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *njt_stream_lua_package_cpath(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *njt_stream_lua_package_path(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *njt_stream_lua_content_by_lua_block(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *njt_stream_lua_content_by_lua(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *njt_stream_lua_log_by_lua_block(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *njt_stream_lua_log_by_lua(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);


char *njt_stream_lua_init_by_lua_block(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *njt_stream_lua_init_by_lua(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *njt_stream_lua_init_worker_by_lua_block(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);
char *njt_stream_lua_init_worker_by_lua(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *njt_stream_lua_code_cache(njt_conf_t *cf, njt_command_t *cmd, void *conf);
char *njt_stream_lua_load_resty_core(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);


char *
njt_stream_lua_preread_by_lua_block(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *
njt_stream_lua_preread_by_lua(njt_conf_t *cf, njt_command_t *cmd, void *conf);
char *
njt_stream_lua_add_variable(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);

char *njt_stream_lua_conf_lua_block_parse(njt_conf_t *cf,
    njt_command_t *cmd);


char *njt_stream_lua_capture_error_log(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);

#endif /* _NJT_STREAM_LUA_DIRECTIVE_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
