/*************************************************************************************
 Copyright (C), 2021-2023, TMLake(Beijing) Technology Ltd.,
 File name    : njt_common_health_check.c
 Version      : 1.0
 Author       : ChengXu
 Date         : 2023/2/1/001 
 Description  : 
 Other        :
 History      :
 <author>       <time>          <version >      <desc>
 ChengXu        2023/2/1/001       1.1             
***********************************************************************************/
//
// Created by Administrator on 2023/2/1/001.
//
#include "njt_common_health_check.h"


/**
 * 它接受一个字符串，将其解析为时间，并将结果存储在 njt_msec_t 变量中
 *
 * @param el 要解析的 json 元素
 * @param def 字段的定义。
 * @param data 指向数据结构的指针
 *
 * @return 返回值是解析的状态。
 */
njt_int_t njt_json_parse_msec(njt_json_element *el,njt_json_define_t *def,void *data){
    njt_int_t tmp;
    njt_msec_t *target = data ;
    tmp = njt_parse_time(&el->strval, 0);
    if(tmp == NJT_ERROR){
        return NJT_ERROR;
    }
    target= data;
    *target = tmp;
    return NJT_OK;
}

#if (NJT_OPENSSL)
static njt_conf_bitmask_t  njt_http_ssl_protocols[] = {
        { njt_string("SSLv2"), NJT_SSL_SSLv2 },
        { njt_string("SSLv3"), NJT_SSL_SSLv3 },
        { njt_string("TLSv1"), NJT_SSL_TLSv1 },
        { njt_string("TLSv1.1"), NJT_SSL_TLSv1_1 },
        { njt_string("TLSv1.2"), NJT_SSL_TLSv1_2 },
        { njt_string("TLSv1.3"), NJT_SSL_TLSv1_3 },
        { njt_null_string, 0 }
};
njt_int_t njt_json_parse_ssl_protocols(njt_json_element *el,njt_json_define_t *def,void *data)
{
    njt_uint_t          *np, i, m;
    njt_str_t           value;
    njt_conf_bitmask_t  *mask;

    if(el->type != NJT_JSON_STR){
        return NJT_ERROR;
    }
    np = (njt_uint_t *)data;
    value = el->strval;
    mask = njt_http_ssl_protocols;

    for (i = 0; i < value.len; i++) {
        for (m = 0; mask[m].name.len != 0; m++) {

            if (mask[m].name.len <= value.len-i
                || njt_strncmp(mask[m].name.data, value.data+i,mask[m].name.len) != 0)
            {
                continue;
            }

//            if (*np & mask[m].mask) {
//                return NJT_ERROR;
//            } else {
                *np |= mask[m].mask;
//            }
            break;
        }

        if (mask[m].name.len == 0) {
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}

njt_int_t njt_json_parse_ssl(njt_json_element *el,njt_json_define_t *def,void *data){
    njt_int_t tmp;
    njt_msec_t *target = data ;
    tmp = njt_parse_time(&el->strval, 0);
    if(tmp == NJT_ERROR){
        return NJT_ERROR;
    }
    target= data;
    *target = tmp;
    return NJT_OK;
}
#endif

/**
 * > 函数用于将json字符串解析成用户定义的数据结构
 *
 * @param pool 内存池
 * @param json_keyval json_keyval参数是json解析器解析出来的json元素数组。
 * @param def 要解析的结构的定义。
 * @param data 要解析的数据结构
 *
 * @return 一个字符串。
 */
njt_int_t njt_json_parse_json_element(njt_pool_t *pool,njt_array_t *json_keyval,njt_json_define_t *def,void *data){
    njt_int_t rc;
    njt_json_element  *items;
    njt_uint_t i, j;
    char  *p = data;
    void *item_data;

    items = json_keyval->elts;
    for (i = 0; i < json_keyval->nelts; ++i ) {
        for( j = 0 ; def[j].name.len != 0 ; ++j ){
            if(njt_strncmp(items[i].key.data, def[j].name.data, def[j].name.len) == 0){
                if (items[i].type != def[j].type){
                    njt_log_error(NJT_LOG_EMERG, pool->log, 0, "%V type not matching",&items[i].key);
                    return NJT_ERROR;
                }
                item_data = (void*)(p + def[j].offset);
                if(def[j].parse){
                    rc = def[j].parse(&items[i],&def[j],item_data);
                    if(rc != NJT_OK){
                        njt_log_error(NJT_LOG_EMERG, pool->log, 0, "%V custom parse error",&items[i].key);
                        return rc;
                    }
                    continue;
                }
                if(def[j].type == NJT_JSON_OBJ && def[j].sub != NULL){
                    rc = njt_json_parse_json_element(pool,items[i].sudata,def[j].sub,item_data);
                    if(rc != NJT_OK){
                        return rc;
                    }
                    continue;
                }
                switch (def[j].type) {
                    case NJT_JSON_STR:
                        *((njt_str_t*)item_data)=items[i].strval;
                        break;
                    case NJT_JSON_INT:
                        *((njt_int_t*)item_data)=items[i].intval;
                        break;
                    case NJT_JSON_DOUBLE:
                        *((double*)item_data)=items[i].doubleval;
                        break;
                    case NJT_JSON_BOOL:
                        *((bool*)item_data)=items[i].bval;
                        break;
                    case NJT_JSON_NULL:
                    case NJT_JSON_OBJ:
                    case NJT_JSON_ARRAY:
                    default:
                        njt_log_error(NJT_LOG_EMERG, pool->log, 0, "%V not allow is NULL, ARRAY ",&items[i].key);
                        return NJT_ERROR;
                }
            }
        }
    }
    return NJT_OK;
}


/**
 * > 函数用来将json字符串解析成结构体的，不支持array类型。
 *
 * @param pool 内存池
 * @param str 要解析的json字符串
 * @param def json结构的定义，定义方式如下：
 * @param data 要解析的数据
 *
 * @return njt_str_t 状态码
 */
njt_int_t njt_json_parse_data(njt_pool_t *pool,njt_str_t *str,njt_json_define_t *def,void *data){
    njt_json_manager json_body;
    njt_int_t rc;

    rc = njt_json_2_structure(str, &json_body,pool);
    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_EMERG, pool->log, 0, "structure json body mem malloc error !!");
        return rc;
    }
    return njt_json_parse_json_element(pool,json_body.json_keyval,def,data);
}
