/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */
#ifndef YUNKE_SLB_V2_1_NG1_20_1_NGX_CACHE_PURGE_H
#define YUNKE_SLB_V2_1_NG1_20_1_NGX_CACHE_PURGE_H


#include <njt_config.h>
#include <njet.h>
#include <njt_core.h>
#include <njt_http.h>

njt_int_t njt_http_cache_purge_filter(njt_http_request_t *r);

#endif //YUNKE_SLB_V2_1_NG1_20_1_NGX_CACHE_PURGE_H
