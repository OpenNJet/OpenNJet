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

typedef struct {
    in_addr_t         mask;
    in_addr_t         addr;
    njt_uint_t        deny;      /* unsigned  deny:1; */
} njt_http_access_rule_t;

#if (NJT_HAVE_INET6)

typedef struct {
    struct in6_addr   addr;
    struct in6_addr   mask;
    njt_uint_t        deny;      /* unsigned  deny:1; */
} njt_http_access_rule6_t;

#endif

#if (NJT_HAVE_UNIX_DOMAIN)

typedef struct {
    njt_uint_t        deny;      /* unsigned  deny:1; */
} njt_http_access_rule_un_t;

#endif

typedef struct {
    njt_array_t      *rules;     /* array of njt_http_access_rule_t */
#if (NJT_HAVE_INET6)
    njt_array_t      *rules6;    /* array of njt_http_access_rule6_t */
#endif
#if (NJT_HAVE_UNIX_DOMAIN)
    njt_array_t      *rules_un;  /* array of njt_http_access_rule_un_t */
#endif
} njt_http_access_loc_conf_t;

#endif //NJET_MAIN_NJT_HTTP_DYN_MODULE_H
