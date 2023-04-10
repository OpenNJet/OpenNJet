/*************************************************************************************
 Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 File name    : njt_str_util.c
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

#include <njt_str_util.h>

njt_int_t njt_str_split(njt_str_t *src,njt_array_t *array,char sign){
    u_char              *p, *last, *end;
    size_t               len;
    njt_str_t           *pwd;

    p = last=src->data;
    end = src->data + src->len;
    for ( ;last < end ; ) {
        last = njt_strlchr(last, end, sign);
        if (last == NULL) {
            last = end;
        }
        len = last - p;
        if (len) {
            pwd = njt_array_push(array);
            if (pwd == NULL) {
                return NJT_ERROR;
            }
            pwd->len = len;
            pwd->data = p ;
        }
        p = ++last;
    }
    return NJT_OK;
}