
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

void njt_http_fault_inject_handler(njt_http_request_t *r);


#endif //NJT_HTTP_FAULT_INJECT_H_