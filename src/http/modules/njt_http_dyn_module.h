/*************************************************************************************
 Copyright (C), 2021-2023, TMLake(Beijing) Technology Ltd.,
 File name    : njt_http_dyn_module.h
 Version      : 1.0
 Author       : ChengXu
 Date         : 2023/2/21/021 
 Description  : 
 Other        :
 History      :
 <author>       <time>          <version >      <desc>
 ChengXu        2023/2/21/021       1.1             
***********************************************************************************/
//
// Created by Administrator on 2023/2/21/021.
//

#ifndef NJET_MAIN_NJT_HTTP_DYN_MODULE_H
#define NJET_MAIN_NJT_HTTP_DYN_MODULE_H


typedef struct {
    njt_array_t                *logs;       /* array of njt_http_log_t */

    njt_open_file_cache_t      *open_file_cache;
    time_t                      open_file_cache_valid;
    njt_uint_t                  open_file_cache_min_uses;

    njt_uint_t                  off;        /* unsigned  off:1 */
} njt_http_log_loc_conf_t;

extern njt_module_t  njt_http_log_module;

#endif //NJET_MAIN_NJT_HTTP_DYN_MODULE_H
