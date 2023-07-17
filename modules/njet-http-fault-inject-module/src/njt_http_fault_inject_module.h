
/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */

#ifndef NJT_HTTP_FAULT_INJECT_H_
#define NJT_HTTP_FAULT_INJECT_H_

#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


#define NJT_HTTP_FAULT_INJECT_NONE              0
#define NJT_HTTP_FAULT_INJECT_DELAY             1
#define NJT_HTTP_FAULT_INJECT_ABORT             2
#define NJT_HTTP_FAULT_INJECT_DELAY_ABORT       3

typedef struct {
    njt_uint_t                    fault_inject_type;     // type
    njt_msec_t                    duration;              // delay time
    njt_uint_t                    status_code;           // abort status code
    uint32_t                      delay_percent;         // delay percent, default 100
    uint32_t                      abort_percent;         // abort percent, default 100   
    
    njt_uint_t                    dynamic;               // 
    njt_pool_t                    *pool;
} njt_http_fault_inject_conf_t;

void njt_http_fault_inject_handler(njt_http_request_t *r);


#endif //NJT_HTTP_FAULT_INJECT_H_