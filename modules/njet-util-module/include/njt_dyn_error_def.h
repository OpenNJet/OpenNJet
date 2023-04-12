/*
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */

#ifndef NJET_MAIN_NJT_DYN_ERROR_DEF_H
#define NJET_MAIN_NJT_DYN_ERROR_DEF_H
// 定义错误码以及相应的响应msg
// 通用错误码定义
enum
{
    DYN_RSP_SUCCESS = 0,
    DYN_RSP_ERR_GENERAL,
    DYN_RSP_ERR_POOL_CREATION,
    DYN_RSP_ERR_JSON,
    DYN_RSP_ERR_TOTAL_PERCENTAGE
} NJT_HTTP_RSP_ERROR;




const char * njt_dyn_strerror(int error_code);


#endif //NJET_MAIN_NJT_DYN_ERROR_DEF_H
