//
// Created by Administrator on 2022/11/2/002.
//

#ifndef YUNKE_SLB_V2_1_NG1_20_1_NGX_CACHE_PURGE_H
#define YUNKE_SLB_V2_1_NG1_20_1_NGX_CACHE_PURGE_H


#include <njt_config.h>
#include <njet.h>
#include <njt_core.h>
#include <njt_http.h>

njt_int_t njt_http_cache_purge_filter(njt_http_request_t *r);

#endif //YUNKE_SLB_V2_1_NG1_20_1_NGX_CACHE_PURGE_H
