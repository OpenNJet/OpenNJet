
/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */

#ifndef NJT_HTTP_API_REGISTER_H_
#define NJT_HTTP_API_REGISTER_H_

#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>

typedef njt_int_t (*api_module_handler)(njt_http_request_t *r);


struct njt_http_api_module_reg_info_s {
   njt_str_t *key;
   api_module_handler handler;
};

typedef struct njt_http_api_module_reg_info_s njt_http_api_reg_info_t;


njt_int_t njt_http_api_module_reg_handler(njt_http_api_reg_info_t *reg_info);

#endif //NJT_HTTP_API_REGISTER_H_