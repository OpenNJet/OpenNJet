/*************************************************************************************
 Copyright (C), 2021-2023, TMLake(Beijing) Technology Ltd.,
 File name    : njt_json_util.h
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

#ifndef NJET_MAIN_NJT_JSON_UTIL_H
#define NJET_MAIN_NJT_JSON_UTIL_H

#include <njt_core.h>
#include <njt_json_api.h>

typedef struct njt_json_define_s njt_json_define_t;

typedef njt_int_t (*njt_parse_item_handler)(njt_json_element *el, njt_json_define_t *def, void *data);

struct njt_json_define_s {
    njt_str_t name;
    njt_int_t offset;
    njt_int_t size;
    int8_t type;
    int8_t eletype;             //just used for array type
    njt_json_define_t *sub;
    njt_parse_item_handler parse;
};

#define njt_json_define_null {njt_null_string,0,0,NJT_JSON_ERROR,0,NULL,NULL}

njt_int_t njt_json_parse_msec(njt_json_element *el, njt_json_define_t *def, void *data);

njt_int_t njt_json_parse_data(njt_pool_t *pool, njt_str_t *str, njt_json_define_t *def, void *data);

#endif //NJET_MAIN_NJT_JSON_UTIL_H
