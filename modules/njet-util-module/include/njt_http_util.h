
/*
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef NJET_MAIN_NJT_HTTP_JSON_H
#define NJET_MAIN_NJT_HTTP_JSON_H

#include <njt_core.h>
#include <njt_http.h>

#define  NEED_PARSE_SERVER_NAME 1

njt_http_core_srv_conf_t* njt_http_get_srv_by_port(njt_cycle_t *cycle,njt_str_t *addr_port,njt_str_t *server_name);

njt_int_t njt_http_get_listens_by_server(njt_array_t *array,njt_http_core_srv_conf_t  *cscf);
njt_http_core_srv_conf_t* njt_http_get_srv_by_server_name(njt_cycle_t *cycle,njt_str_t *addr_port,njt_str_t *server_name);
njt_int_t njt_http_util_read_request_body(njt_http_request_t *r, njt_str_t *req_body, size_t min_len, size_t max_len);
void njt_http_location_destroy(njt_http_core_loc_conf_t *clcf);
void njt_http_upstream_del(njt_cycle_t  *cycle,njt_http_upstream_srv_conf_t *upstream);
njt_int_t njt_http_location_full_name_cmp(njt_str_t full_name,njt_str_t src);
njt_str_t njt_get_command_unique_name(njt_pool_t *pool,njt_str_t src);
njt_http_core_srv_conf_t* njt_http_get_srv_by_ori_name(njt_cycle_t *cycle,njt_str_t *addr_port,njt_str_t *server_name);
njt_int_t njt_http_server_full_name_cmp(njt_str_t full_name,njt_str_t server_name,njt_uint_t need_parse);

njt_int_t njt_http_parse_path(njt_str_t uri, njt_array_t *path);
njt_int_t
njt_http_util_add_header(njt_http_request_t *r, njt_str_t key,
    njt_str_t value);
njt_str_t
njt_http_util_check_str_variable(njt_str_t *source);
njt_http_upstream_srv_conf_t* njt_http_util_find_upstream(njt_cycle_t *cycle,njt_str_t *name);
njt_int_t njt_http_upstream_check_free(njt_http_upstream_srv_conf_t *upstream);

#endif //NJET_MAIN_NJT_HTTP_JSON_H
