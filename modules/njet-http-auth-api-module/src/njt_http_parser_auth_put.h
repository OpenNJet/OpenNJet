

/* This file was generated by JSON Schema to C.
 * Any changes made to it will be lost on regeneration. 

 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */

#ifndef PARSER_AUTH_PUT_H
#define PARSER_AUTH_PUT_H
#include <stdint.h>
#include <stdbool.h>
#include "njt_core.h"
#include "js2c_njet_builtins.h"
/* ===================== Generated type declarations ===================== */
typedef njt_str_t auth_passwd_put_api_prefix_t;

typedef njt_str_t auth_passwd_put_api_user_name_t;

typedef njt_str_t auth_passwd_put_api_password_t;

typedef struct auth_passwd_put_api_t_s {
    auth_passwd_put_api_prefix_t prefix;
    auth_passwd_put_api_user_name_t user_name;
    auth_passwd_put_api_password_t password;
    unsigned int is_prefix_set:1;
    unsigned int is_user_name_set:1;
    unsigned int is_password_set:1;
} auth_passwd_put_api_t;

auth_passwd_put_api_prefix_t* get_auth_passwd_put_api_prefix(auth_passwd_put_api_t *out);
auth_passwd_put_api_user_name_t* get_auth_passwd_put_api_user_name(auth_passwd_put_api_t *out);
auth_passwd_put_api_password_t* get_auth_passwd_put_api_password(auth_passwd_put_api_t *out);
void set_auth_passwd_put_api_prefix(auth_passwd_put_api_t* obj, auth_passwd_put_api_prefix_t* field);
void set_auth_passwd_put_api_user_name(auth_passwd_put_api_t* obj, auth_passwd_put_api_user_name_t* field);
void set_auth_passwd_put_api_password(auth_passwd_put_api_t* obj, auth_passwd_put_api_password_t* field);
auth_passwd_put_api_t* create_auth_passwd_put_api(njt_pool_t *pool);
auth_passwd_put_api_t* json_parse_auth_passwd_put_api(njt_pool_t *pool, const njt_str_t *json_string, js2c_parse_error_t *err_ret);
njt_str_t* to_json_auth_passwd_put_api(njt_pool_t *pool, auth_passwd_put_api_t *out, njt_int_t flags);
#endif /* PARSER_AUTH_PUT_H */
