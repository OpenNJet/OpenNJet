/*
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */

#include "njt_dyn_error_def.h"

static njt_str_t njt_http_split_clients_2_error_msg[] = {
        njt_string("success"),
        njt_string("error occuried"),
        njt_string("can't create memory pool"),
        njt_string("json is not valid"),
        njt_string("total percenage is more than 100%"),
};
const char * njt_dyn_strerror(int error_code){
    // todo
    switch (error_code) {
        case DYN_RSP_SUCCESS:
            return "success";
            break;
        case DYN_RSP_ERR_GENERAL:
            return "can't create memory pool";
            break;
        case DYN_RSP_ERR_POOL_CREATION:
            return "json is not valid";
            break;
        case DYN_RSP_ERR_JSON:
            break;
        case DYN_RSP_ERR_TOTAL_PERCENTAG:
            return "total percenage is more than 100%";
            break;
        default:
            return NULL;
    }
}
