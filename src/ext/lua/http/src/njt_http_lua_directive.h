
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_LUA_DIRECTIVE_H_INCLUDED_
#define _NJT_HTTP_LUA_DIRECTIVE_H_INCLUDED_


#include "njt_http_lua_common.h"


char *njt_http_lua_shared_dict(njt_conf_t *cf, njt_command_t *cmd, void *conf);
char *njt_http_lua_package_cpath(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *njt_http_lua_package_path(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *njt_http_lua_regex_cache_max_entries(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *njt_http_lua_regex_match_limit(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *njt_http_lua_content_by_lua_block(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *njt_http_lua_content_by_lua(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *njt_http_lua_server_rewrite_by_lua(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *njt_http_lua_server_rewrite_by_lua_block(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);
char *njt_http_lua_rewrite_by_lua_block(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *njt_http_lua_rewrite_by_lua(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *njt_http_lua_access_by_lua_block(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *njt_http_lua_access_by_lua(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *njt_http_lua_log_by_lua_block(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *njt_http_lua_log_by_lua(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *njt_http_lua_header_filter_by_lua_block(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);
char *njt_http_lua_header_filter_by_lua(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *njt_http_lua_body_filter_by_lua_block(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);
char *njt_http_lua_body_filter_by_lua(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *njt_http_lua_init_by_lua_block(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *njt_http_lua_init_by_lua(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *njt_http_lua_init_worker_by_lua_block(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);
char *njt_http_lua_init_worker_by_lua(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *njt_http_lua_exit_worker_by_lua_block(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);
char *njt_http_lua_exit_worker_by_lua(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *njt_http_lua_code_cache(njt_conf_t *cf, njt_command_t *cmd, void *conf);
char *njt_http_lua_load_resty_core(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);

#if defined(NDK) && NDK

char *njt_http_lua_set_by_lua_block(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *njt_http_lua_set_by_lua(njt_conf_t *cf, njt_command_t *cmd, void *conf);
char *njt_http_lua_set_by_lua_file(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
njt_int_t njt_http_lua_filter_set_by_lua_inline(njt_http_request_t *r,
    njt_str_t *val, njt_http_variable_value_t *v, void *data);
njt_int_t njt_http_lua_filter_set_by_lua_file(njt_http_request_t *r,
    njt_str_t *val, njt_http_variable_value_t *v, void *data);

#endif

char *njt_http_lua_rewrite_no_postpone(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *njt_http_lua_conf_lua_block_parse(njt_conf_t *cf,
    njt_command_t *cmd);
char *njt_http_lua_capture_error_log(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
u_char *njt_http_lua_gen_chunk_name(njt_conf_t *cf, const char *tag,
    size_t tag_len, size_t *chunkname_len);

#endif /* _NJT_HTTP_LUA_DIRECTIVE_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
