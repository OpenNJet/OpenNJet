
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
void njt_http_upstream_del(njt_http_upstream_srv_conf_t *upstream);
njt_int_t njt_http_location_full_name_cmp(njt_str_t full_name,njt_str_t src);
njt_str_t njt_get_command_unique_name(njt_pool_t *pool,njt_str_t src);
njt_http_core_srv_conf_t* njt_http_get_srv_by_ori_name(njt_cycle_t *cycle,njt_str_t *addr_port,njt_str_t *server_name);
njt_int_t njt_http_server_full_name_cmp(njt_str_t full_name,njt_str_t server_name,njt_uint_t need_parse);

njt_int_t njt_http_parse_path(njt_str_t uri, njt_array_t *path);

#endif //NJET_MAIN_NJT_HTTP_JSON_H
