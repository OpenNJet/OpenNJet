
/*
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef NJET_MAIN_NJT_STR_UTIL_H
#define NJET_MAIN_NJT_STR_UTIL_H

#include <njt_core.h>

#define njt_str_copy_pool(pool, desc, src, err)    \
    desc.data = njt_pcalloc(pool,src.len+1); \
    if(desc.data == NULL){                              \
        err;                                            \
    }                                                   \
    njt_memcpy(desc.data,src.data,src.len);         \
    desc.len = src.len

#define njt_str_concat(pool, desc, front, after, err) \
    desc.data = njt_pcalloc(pool,front.len+after.len); \
    if(desc.data == NULL){                              \
        err;                                            \
    }                                                   \
    njt_memcpy(desc.data,front.data,front.len);         \
    njt_memcpy(desc.data+front.len,after.data,after.len);         \
    desc.len = front.len+after.len;

njt_int_t njt_str_split(njt_str_t *src, njt_array_t *array, char sign);
njt_str_t njt_del_headtail_space(njt_str_t src);
njt_str_t  add_escape(njt_pool_t *pool, njt_str_t src);
njt_str_t delete_escape(njt_pool_t *pool, njt_str_t src);
#endif //NJET_MAIN_NJT_STR_UTIL_H
