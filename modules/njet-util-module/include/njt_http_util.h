/*************************************************************************************
 Copyright (C), 2021-2023, TMLake(Beijing) Technology Ltd.,
 File name    : njt_http_json.h
 Version      : 1.0
 Author       : ChengXu
 Date         : 2023/2/27/027 
 Description  : 
 Other        :
 History      :
 <author>       <time>          <version >      <desc>
 ChengXu        2023/2/27/027       1.1             
***********************************************************************************/
//
// Created by Administrator on 2023/2/27/027.
//

#ifndef NJET_MAIN_NJT_HTTP_JSON_H
#define NJET_MAIN_NJT_HTTP_JSON_H

#include <njt_core.h>
#include <njt_http.h>

njt_http_core_srv_conf_t* njt_http_get_srv_by_port(njt_cycle_t *cycle,njt_pool_t *pool,njt_str_t *addr_port,njt_str_t *server_name);

njt_int_t njt_http_get_listens_by_server(njt_array_t *array,njt_http_core_srv_conf_t  *cscf);

#endif //NJET_MAIN_NJT_HTTP_JSON_H
