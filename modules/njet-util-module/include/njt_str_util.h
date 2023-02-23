/*************************************************************************************
 Copyright (C), 2021-2023, TMLake(Beijing) Technology Ltd.,
 File name    : njt_str_util.h
 Version      : 1.0
 Author       : ChengXu
 Date         : 2023/2/16/016 
 Description  : 
 Other        :
 History      :
 <author>       <time>          <version >      <desc>
 ChengXu        2023/2/16/016       1.1             
***********************************************************************************/
//
// Created by Administrator on 2023/2/16/016.
//

#ifndef NJET_MAIN_NJT_STR_UTIL_H
#define NJET_MAIN_NJT_STR_UTIL_H

#include <njt_core.h>

#define njt_str_copy_pool(pool, desc, src, err)    \
    desc.data = njt_pstrdup(cf->pool, &src);      \
        if(desc.data == NULL){                  \
            err ;                               \
        }                                       \
    desc.len = src.len

#define njt_str_concat(pool, desc, front, after, err) \
    desc.data = njt_pcalloc(pool,front.len+after.len); \
    if(desc.data == NULL){                              \
        err;                                            \
    }                                                   \
    njt_memcpy(desc.data,front.data,front.len);         \
    njt_memcpy(desc.data+front.len,after.data,after.len);         \
    desc.len = front.len+after.len;


#endif //NJET_MAIN_NJT_STR_UTIL_H
