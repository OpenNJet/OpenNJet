
/*
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include "njt_json_api.h"

njt_int_t njt_json_hsh_callback(njt_json_element *json_val,
                               njt_json_val *next,
                               njt_pool_t *pool);


njt_int_t njt_json_array_callback(njt_json_element *json_val,
                               njt_json_val *next,
                               njt_pool_t *pool);


static njt_int_t njt_http_lvlhsh_test(njt_lvlhsh_query_t *lhq, void *data);

const njt_lvlhsh_proto_t  njt_http_lvlhsh_proto = {
    NJT_LVLHSH_LARGE_MEMALIGN,
    njt_http_lvlhsh_test,
    njt_lvlhsh_pool_alloc,
    njt_lvlhsh_pool_free,
};


static njt_int_t
njt_http_lvlhsh_test(njt_lvlhsh_query_t *lhq, void *data)
{
    njt_json_element *kv = data;

    if (lhq->key.len == kv->key.len
        && njt_memcmp(lhq->key.data, kv->key.data, lhq->key.len) == 0)
    {
        return NJT_OK;
    }

    return NJT_DECLINED;
}



/**
 * @brief  get array or object element's size
 *  
 * @param datas           intput array datas
 * @param contain_key     true if element has key, else false
 * @return int64_t        return all sub element's size
 */
int64_t njt_calc_array_size(njt_queue_t *datas, bool contain_key)
{
    int64_t size = 0;
    njt_queue_t *q;
    njt_json_element *item;

    if(datas == NULL){
        return 0;
    }


    for (q = njt_queue_head(datas);
         q != njt_queue_sentinel(datas);
         q = njt_queue_next(q))
    {
        item = njt_queue_data(q, njt_json_element, ele_queue);
        if(item == NULL){
            continue;
        }

        size += njt_calc_element_size(item, contain_key);
    }

    return size;
}



/**
 * @brief  get element's size
 *  
 * @param element         intput element
 * @param contain_key     true if element has key, else false
 * @return int64_t        return element's size
 */
int64_t njt_calc_element_size(njt_json_element *element, bool contain_key)
{
    int64_t size = 0;

    if(element == NULL){
        return 0;
    }

    switch (element->type)
    {
        case NJT_JSON_STR:
            size += NJT_JSON_ELEM_SIZE_STR;
            size += element->strval.len * 6;
            break;
        case NJT_JSON_BOOL:
            size += NJT_JSON_ELEM_SIZE_BOOL;
            break;
        case NJT_JSON_DOUBLE:
            size += NJT_JSON_ELEM_SIZE_DOUBLE;
            break;
        case NJT_JSON_INT:
            size += NJT_JSON_ELEM_SIZE_INT;
            break;
        case NJT_JSON_ARRAY:
            size += NJT_JSON_ELEM_SIZE_ARRAY;
            size += njt_calc_array_size(&element->arrdata, false);
            break;
        case NJT_JSON_OBJ:
            size += NJT_JSON_ELEM_SIZE_OBJ;
            size += njt_calc_array_size(&element->objdata.datas, true);
            break;
        case NJT_JSON_NULL:
            size += NJT_JSON_ELEM_SIZE_NULL;
            break;
        default:
            return 0;
    }

    size += NJT_JSON_ELEM_SIZE_PUNCTUATION;

    if(contain_key){
        size += element->key.len * 6;
        size += NJT_JSON_ELEM_SIZE_STR;
        size += NJT_JSON_ELEM_SIZE_PUNCTUATION;
    }

    return size;
}



njt_int_t parseObjJson(njt_json_lvlhsh_t *json_hash, njt_json_val *key,
                    njt_json_val *val, njt_pool_t *pool)
{
    njt_json_element        *json_element;
    njt_lvlhsh_query_t            lhq;
    char buffer[4096] = {};
    const char *pData;
    njt_uint_t len;
    njt_uint_t rc;

    if(json_hash == NULL || key == NULL || val == NULL || pool == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                          "parseObjJson input not valid");
        return NJT_ERROR;
    }

    if(json_hash->lvlhsh == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                          "parseObjJson lvlhash is null");
        return NJT_ERROR;
    }

    json_element = njt_pnalloc(pool, sizeof(njt_json_element));
    if (json_element == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                          "parseObjJson alloc element fail");
        return NJT_ERROR;
    }

    json_element->type = NJT_JSON_ERROR;

    //parse key
    pData = njt_json_get_str(key);
    if (pData == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                          "parseObjJson parse key fail");
        return NJT_ERROR;
    }

    len = strlen(pData);
    json_element->key.data =  njt_pnalloc(pool, len);
    if (json_element->key.data == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                          "parseObjJson key alloc fail");
        return NJT_ERROR;
    }

    json_element->key.len  = len;
    njt_memcpy(json_element->key.data, pData, len);
    njt_memzero(buffer, sizeof(buffer));
    njt_memcpy(buffer, pData, njt_min(len,sizeof(buffer)-1));
    njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                    "key: %s", buffer);

    if (njt_json_is_obj(val)) {

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                        "key: %s", "========================obj===================");
        json_element->type = NJT_JSON_OBJ;
        json_element->objdata.lvlhsh = njt_pnalloc(pool, sizeof(njt_lvlhsh_t));
        if(json_element->objdata.lvlhsh == NULL){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                          "parseObjJson lvlhsh alloc fail");
            return NJT_ERROR;
        }

        json_element->objdata.lvlhsh->slot = NULL;
        njt_queue_init(&json_element->objdata.datas);

        rc = njt_json_hsh_callback(json_element, val, pool);
        if(rc != NJT_OK){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                          "parseObjJson parse hsh fail");
            return NJT_ERROR;
        }
    } else if (njt_json_is_arr(val)) {
        //todo 
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                        "key: %s", "========================list===================");
        json_element->type = NJT_JSON_ARRAY;
        njt_queue_init(&json_element->arrdata);
        rc = njt_json_array_callback(json_element, val, pool);
        if(rc != NJT_OK){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                          "parseObjJson parse array fail");
            return NJT_ERROR;
        }
    } else if (njt_json_is_null(val)) {

        json_element->type = NJT_JSON_NULL;
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                        "NULL val is: %s", "");

    } else if (njt_json_is_bool(val)) {

        json_element->type = NJT_JSON_BOOL;
        json_element->bval = njt_json_get_bool(val);
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                        "BOOL val is: %d", json_element->bval);

    } else if (njt_json_is_int(val)) {

        json_element->type = NJT_JSON_INT;
        json_element->intval = njt_json_get_int(val);
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                        "number val is: %d", json_element->intval);

    } else if (njt_json_is_real(val)) {

        json_element->type = NJT_JSON_DOUBLE;
        json_element->doubleval = njt_json_get_real(val);
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                        "double val is: %f", json_element->doubleval);

    } else if (njt_json_is_str(val)) {

        json_element->type = NJT_JSON_STR;
        pData = njt_json_get_str(val);
        if (pData == NULL) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                          "parseObjJson parse str fail");
            return NJT_ERROR;
        }

        len = strlen(pData);
        json_element->strval.data =  njt_pnalloc(pool, len);
        if (json_element->strval.data == NULL) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                          "parseObjJson str alloc fail");
            return NJT_ERROR;
        }

        json_element->strval.len  = len;
        njt_memcpy(json_element->strval.data, pData, len);
        njt_memzero(buffer, sizeof(buffer));
        njt_memcpy(buffer, pData, njt_min(len,sizeof(buffer)-1));
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                        "string val is: %s", buffer);
    }
    
    //create lhq
    lhq.key = json_element->key;
    lhq.key_hash = njt_murmur_hash2(lhq.key.data, lhq.key.len);
    lhq.proto = &njt_http_lvlhsh_proto;
    lhq.pool = pool;
    lhq.value = json_element;

    //insert to hash
    rc = njt_lvlhsh_insert(json_hash->lvlhsh, &lhq);
    if(rc != NJT_OK){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                      "parseObjJson lvlhash insert fail");
        return NJT_ERROR;
    }

    njt_queue_insert_tail(&json_hash->datas, &json_element->ele_queue);

    return NJT_OK;
}


njt_int_t parseArrayJson(njt_queue_t *json_queue,
                    njt_json_val *val, njt_pool_t *pool)
{
    njt_json_element        *json_element;
    char buffer[4096] = {};
    const char *pData;
    njt_uint_t len;
    njt_uint_t rc;

    if(json_queue == NULL || val == NULL || pool == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                      "parseArrayJson input param invalid, should not null");
        return NJT_ERROR;
    }

    json_element = njt_pnalloc(pool, sizeof(njt_json_element));
    if (json_element == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                      "parseArrayJson element clloc fail");
        return NJT_ERROR;
    }

    json_element->type = NJT_JSON_ERROR;

    if (njt_json_is_obj(val)) {

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                        "key: %s", "========================obj===================");
        json_element->type = NJT_JSON_OBJ;
        json_element->objdata.lvlhsh = njt_pnalloc(pool, sizeof(njt_lvlhsh_t));
        if(json_element->objdata.lvlhsh == NULL){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                      "parseArrayJson lvlhsh clloc fail");
            return NJT_ERROR;
        }
        json_element->objdata.lvlhsh->slot = NULL;
        njt_queue_init(&json_element->objdata.datas);

        rc = njt_json_hsh_callback(json_element, val, pool);
        if(rc != NJT_OK){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                      "parseArrayJson parse hsh fail");
            return NJT_ERROR;
        }
    } else if (njt_json_is_arr(val)) {
        //todo 
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                        "key: %s", "========================list===================");
        json_element->type = NJT_JSON_ARRAY;
        njt_queue_init(&json_element->arrdata);
        rc = njt_json_array_callback(json_element, val, pool);
        if(rc != NJT_OK){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                      "parseArrayJson parse array fail");
            return NJT_ERROR;
        }
    } else if (njt_json_is_null(val)) {

        json_element->type = NJT_JSON_NULL;
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                        "NULL val is: %s", "");

    } else if (njt_json_is_bool(val)) {

        json_element->type = NJT_JSON_BOOL;
        json_element->bval = njt_json_get_bool(val);
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                        "BOOL val is: %d", json_element->bval);

    } else if (njt_json_is_int(val)) {

        json_element->type = NJT_JSON_INT;
        json_element->intval = njt_json_get_int(val);
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                        "number val is: %d", json_element->intval);

    } else if (njt_json_is_real(val)) {

        json_element->type = NJT_JSON_DOUBLE;
        json_element->doubleval = njt_json_get_real(val);
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                        "double val is: %f", json_element->doubleval);

    } else if (njt_json_is_str(val)) {

        json_element->type = NJT_JSON_STR;
        pData = njt_json_get_str(val);
        if (pData == NULL) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                      "parseArrayJson parse str fail");
            return NJT_ERROR;
        }

        len = strlen(pData);
        json_element->strval.data =  njt_pnalloc(pool, len);
        if (json_element->strval.data == NULL) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                      "parseArrayJson str alloc fail");
            return NJT_ERROR;
        }

        json_element->strval.len  = len;
        njt_memcpy(json_element->strval.data, pData, len);
        njt_memzero(buffer, sizeof(buffer));
        njt_memcpy(buffer, pData, njt_min(len,sizeof(buffer)-1));
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                        "string val is: %s", buffer);
    }

    njt_queue_insert_tail(json_queue, &json_element->ele_queue);

    return NJT_OK;
}



/**
 * @brief transfer json to hash element
 * 
 * @param json_val      output hash element
 * @param next          input json object
 * @param pool          input pool
 * @return njt_int_t    result status NJT_ERROR or NJT_OK
 */
njt_int_t njt_json_hsh_callback(njt_json_element *json_val,
                               njt_json_val *next,
                               njt_pool_t *pool)
{

    njt_int_t ret = NJT_OK;
    njt_json_val *key, *val;
    njt_json_obj_iter objiter;
    njt_json_val *root;

    root = next;

    if (root == NULL || json_val == NULL || pool == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                 "njt_json_hsh_callback input shoude not null");
        return NJT_ERROR;
    }

    if (njt_json_is_obj(root)) {
        njt_json_obj_iter_init(root, &objiter);
        while ((key = njt_json_obj_iter_next(&objiter))) {

            val = njt_json_obj_iter_get_val(key);

            ret = parseObjJson(&json_val->objdata, key, val, pool);
            if (ret != NJT_OK) {
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                      "njt_json_hsh_callback parse object fail");
                return NJT_ERROR;
            }
        }

    } else {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                 "njt_json_hsh_callback type should is object");
        return NJT_ERROR;
    }

    return ret;
}


/**
 * @brief transfer json to array element
 * 
 * @param json_val      output array element
 * @param next          input json object
 * @param pool          input pool
 * @return njt_int_t    result status NJT_ERROR or NJT_OK
 */
njt_int_t njt_json_array_callback(njt_json_element *json_val,
                               njt_json_val *next,
                               njt_pool_t *pool)
{
    njt_int_t ret = NJT_OK;
    njt_json_val *val;
    njt_json_arr_iter arriter;
    njt_json_val *root;

    root = next;

    if(root == NULL || json_val == NULL || pool == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                 "njt_json_array_callback input shoude not null");
        return NJT_ERROR;
    }

    if(njt_json_is_arr(root)) {
        njt_json_arr_iter_init(root, &arriter);
        while ((val = njt_json_arr_iter_next(&arriter))) {
            ret = parseArrayJson(&json_val->arrdata, val, pool);
            if (ret != NJT_OK){
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                      "njt_json_array_callback parse array fail");
                return NJT_ERROR;
            }
        }
    } else {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                 "njt_json_array_callback type should is array");
        return NJT_ERROR;
    }

    return NJT_OK;
}


void njt_json_manager_free(njt_json_manager *pt)
{
    if (pt->pool) {
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "njt_json_manager_free: %s", "ok");
        njt_destroy_pool(pt->pool);
        pt->pool = NULL;
    }

    return;
}


/**
 * @brief transfer json str to json manager
 * 
 * @param json           input json str
 * @param pjson_manager  ouput json manager
 * @param init_pool      input required  pool
 * @return njt_int_t     result status NJT_ERROR or NJT_OK
 */
njt_int_t njt_json_2_structure(njt_str_t *json,
                njt_json_manager *pjson_manager, njt_pool_t *init_pool)
{
    njt_int_t   rc;
    njt_pool_t *pool = NULL;
    njt_json_doc *doc;
    njt_json_val *root;
    // u_char     *json_buf;
    // njt_json_alc alc;
    njt_json_element *json_val;

    if (json == NULL || pjson_manager == NULL || init_pool == NULL)
    {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                 "njt_json_2_structure input param invalid, should not null");
        return NJT_ERROR;
    }

    pool = init_pool;
    pjson_manager->pool = pool;
    pjson_manager->free = njt_json_manager_free;
    // pjson_manager->total_size = json->len * 6 + njt_pagesize;
    // pjson_manager->total_size *= 2;

    // json_buf = njt_pnalloc(pool, pjson_manager->total_size);
    // if (json_buf == NULL) {
    //     njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
    //              "njt_json_2_structure json buf alloc fail");
    //     goto cleanup;
    // }
    
    // njt_json_alc_pool_init(&alc, json_buf, pjson_manager->total_size);

    // doc = njt_json_read_opts((char *)json->data, json->len, 0, &alc, NULL);
    njt_json_read_err err;
    doc = njt_json_read_opts((char *)json->data, json->len, 0, NULL, &err);
    if (doc == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                 "njt_json_2_structure get doc fail, code:%d  msg:%s pos:%d",
                 err.code, err.msg, err.pos);
        return NJT_ERROR;
    }

    root = njt_json_doc_get_root(doc);
    if (root == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                 "njt_json_2_structure get root fail");
        goto cleanup;
    }

    json_val = njt_pnalloc(pool, sizeof(njt_json_element));
    if (json_val == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                 "njt_json_2_structure json val alloc fail");
        goto cleanup;
    }

    pjson_manager->json_val = json_val;

    if (njt_json_is_obj(root)) {
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                        "root key: %s", "========================obj===================");
        json_val->type = NJT_JSON_OBJ;
        json_val->objdata.lvlhsh = njt_pnalloc(pool, sizeof(njt_lvlhsh_t));
        if(json_val->objdata.lvlhsh == NULL){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                 "njt_json_2_structure lvlhsh alloc fail");
            goto cleanup;
        }
        json_val->objdata.lvlhsh->slot = NULL;
        njt_queue_init(&json_val->objdata.datas);

        rc = njt_json_hsh_callback(json_val, root, pool);
    }else if (njt_json_is_arr(root)) {
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                        "root key: %s", "========================list===================");
        json_val->type = NJT_JSON_ARRAY;
        njt_queue_init(&json_val->arrdata);
        rc = njt_json_array_callback(json_val, root, pool);
    }else{
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                 "njt_json_2_structure type shoudle be object or array fail");
        goto cleanup;
    }

    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                 "njt_json_2_structure parse object or array fail");
        goto cleanup;
    }

    njt_json_doc_free(doc);
    return NJT_OK;

cleanup:
    njt_json_doc_free(doc);
    return NJT_ERROR;
}



njt_int_t njt_struct_2_json_callback(njt_json_alc *alc,
            njt_json_element *json_val, njt_json_mut_doc *doc,
            njt_json_mut_val *parent_val)
{
    njt_int_t rc = NJT_OK;
    njt_json_element *item;
    njt_json_mut_val *msg_key, *msg = NULL;
    njt_queue_t *datas;
    njt_queue_t *q;

    if(json_val->type == NJT_JSON_ARRAY){
        datas = &json_val->arrdata;
    }else if(json_val->type == NJT_JSON_OBJ){
        datas = &json_val->objdata.datas;
    }else{
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                 "njt_struct_2_json_callback type should be object or array, now:%d", json_val->type);
        return NJT_ERROR;
    }

    for (q = njt_queue_head(datas);
         q != njt_queue_sentinel(datas);
         q = njt_queue_next(q))
    {
        item = njt_queue_data(q, njt_json_element, ele_queue);
        if(item == NULL){
            continue;
        }

        switch (item->type)
        {
            case NJT_JSON_STR:
                msg = njt_json_mut_strncpy(doc, (const char*)item->strval.data, item->strval.len);
                break;
            case NJT_JSON_BOOL:
                msg = njt_json_mut_bool(doc, item->bval);
                break;
            case NJT_JSON_DOUBLE:
                msg = njt_json_mut_real(doc, item->doubleval);
                break;
            case NJT_JSON_INT:
                msg = njt_json_mut_int(doc, item->intval);
                break;
            case NJT_JSON_ARRAY:
                msg = njt_json_mut_arr(doc);

                if(json_val->type == NJT_JSON_OBJ){
                    msg_key = njt_json_mut_strncpy(doc, (const char*)item->key.data, item->key.len);
                    njt_json_mut_obj_add(parent_val, msg_key, msg);
                }else if(json_val->type == NJT_JSON_ARRAY){
                    njt_json_mut_arr_append(parent_val, msg);
                }

                rc = njt_struct_2_json_callback(alc, item, doc, msg);
                if(rc != NJT_OK){
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "njt_struct_2_json_callback parse array fail");
                    return rc;
                }
                break;
            case NJT_JSON_OBJ:
                msg = njt_json_mut_obj(doc);

                if(json_val->type == NJT_JSON_OBJ){
                    msg_key = njt_json_mut_strncpy(doc, (const char*)item->key.data, item->key.len);
                    njt_json_mut_obj_add(parent_val, msg_key, msg);
                }else if(json_val->type == NJT_JSON_ARRAY){
                    njt_json_mut_arr_append(parent_val, msg);
                }

                rc = njt_struct_2_json_callback(alc, item, doc, msg);
                if(rc != NJT_OK){
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "njt_struct_2_json_callback parse object fail");
                    return rc;
                }
                break;
            case NJT_JSON_NULL:
                msg = njt_json_mut_null(doc);
                break;
            default:
                break;
        }

        if(msg == NULL)
        {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                    "njt_struct_2_json_callback mut msg fail");
            return NJT_ERROR;
        }

        if(item->type != NJT_JSON_OBJ && item->type != NJT_JSON_ARRAY){
            if(json_val->type == NJT_JSON_OBJ){
                msg_key = njt_json_mut_strncpy(doc, (const char*)item->key.data, item->key.len);
                if(msg_key == NULL)
                {
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "njt_struct_2_json_callback mut msg_key fail");
                    return NJT_ERROR;
                }
                njt_json_mut_obj_add(parent_val, msg_key, msg);
            }else if(json_val->type == NJT_JSON_ARRAY){
                njt_json_mut_arr_append(parent_val, msg);
            }
        }
    }

    return rc;
}


/**
 * @brief transfer json manager to json str
 * 
 * @param pjson_manager     input json manager
 * @param json              output json str
 * @param init_pool         input pool
 * @return njt_int_t        result status NJT_ERROR or NJT_OK
 */
njt_int_t njt_structure_2_json(njt_json_manager *pjson_manager,
                                njt_str_t *json, njt_pool_t *init_pool)
{
    njt_pool_t *pool = NULL;
    njt_json_mut_val *root;
    njt_json_mut_doc *doc;
    size_t len;
    njt_int_t rc = NJT_OK;
    char *ret_json = NULL;
    u_char     *json_buf;
    njt_json_alc alc;
    int8_t  root_type;

    if (pjson_manager == NULL || json == NULL
        || init_pool == NULL)
    {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
             "njt_struct_2_json input param invalid, should not null");
        return NJT_ERROR;
    }

    pool = init_pool;
    pjson_manager->free = njt_json_manager_free;
    //if json manager has no element, return {} as default
    if(pjson_manager->json_val == NULL){
        njt_str_set(json,"{}");
        pjson_manager->total_size = 10;
        return NJT_OK;
    }

    doc = njt_json_mut_doc_new(NULL);
    if(doc == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
             "njt_struct_2_json doc mut fail");
        return NJT_ERROR;
    }

    //calc struct size
    pjson_manager->total_size = njt_calc_element_size(pjson_manager->json_val, false);
    pjson_manager->total_size += njt_pagesize;
    pjson_manager->total_size *= 2;
   
    njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "============struct2json size: %d", pjson_manager->total_size);

    //json buf size
    json_buf = njt_pnalloc(pool, pjson_manager->total_size);
    if (json_buf == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
             "njt_struct_2_json json buf alloc fail");
        goto cleanup;
    }

    //root is object or array
    root_type = pjson_manager->json_val->type;
    if (root_type == NJT_JSON_OBJ)
    {
        root = njt_json_mut_obj(doc);
    }else if(root_type == NJT_JSON_ARRAY){
        root = njt_json_mut_arr(doc);
    }else{
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
             "njt_struct_2_json type should be object or array, now:%d", root_type);
        goto cleanup;
    }

    if(root == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
             "njt_struct_2_json mut root fail");
        goto cleanup;
    }

    njt_json_mut_doc_set_root(doc, root);
    njt_json_alc_pool_init(&alc, json_buf, pjson_manager->total_size);

    rc = njt_struct_2_json_callback(&alc, pjson_manager->json_val, doc, root);
    if(rc != NJT_OK){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
             "njt_struct_2_json parse struct fail");
        goto cleanup;
    }

    ret_json = njt_json_mut_write_opts(doc, 0, &alc, &len, NULL);
    if (ret_json == NULL)
    {
        json->data = NULL;
        json->len = 0;

        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
             "njt_struct_2_json get json str fail");
        goto cleanup;
    }else{
        //ret_json[len-1] = '\0';
        json->data = (u_char *)ret_json;
        json->len = len;
    }

    njt_json_mut_doc_free(doc);

    return rc;
cleanup:
    njt_json_mut_doc_free(doc);

    return NJT_ERROR;
}

/**
 * @brief find element from parent element by key
 *        not support array element find, because array element has no key
 * 
 * @param parent_element    input element
 * @param key               search key string
 * @param out_element       output element
 * @return njt_int_t        result status NJT_ERROR or NJT_OK
 */
njt_int_t njt_struct_find(njt_json_element *parent_element,
            njt_str_t *key, njt_json_element **out_element)
{
    njt_int_t rc = NJT_ERROR;
    njt_lvlhsh_query_t     lhq;

    if (parent_element == NULL || key == NULL || parent_element->type == NJT_JSON_ARRAY)
    {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
             "njt_struct_find input param invalid, shoude not null or type shoude not array");
        return NJT_ERROR;
    }

    if(parent_element->type == NJT_JSON_OBJ){
        if(parent_element->objdata.lvlhsh == NULL){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "njt_struct_find object lvlhsh houle not null");
            return NJT_ERROR;
        }

        //create lhq
        lhq.key = *key;
        lhq.key_hash = njt_murmur_hash2(lhq.key.data, lhq.key.len);
        lhq.proto = &njt_http_lvlhsh_proto;

        //find
        rc = njt_lvlhsh_find(parent_element->objdata.lvlhsh, &lhq);
        if(rc != NJT_OK){
            njt_log_debug(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                "njt_struct_find not find element");
            return NJT_ERROR;
        }

        *out_element = lhq.value;
        return NJT_OK;
    }else{
        if(parent_element->key.len != key->len){
            njt_log_debug(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                "njt_struct_find key is not equal");
            return NJT_ERROR;
        }
        if(njt_strncmp(parent_element->key.data, key->data, key->len) == 0){
            *out_element = parent_element;
            return NJT_OK;
        }
    }

    return rc;
}


/**
 * @brief find element from json manager by key
 *        not support array element find, because array element has no key
 *
 * @param pjson_manager     input json manger object
 * @param key               search key string
 * @param out_element       output element
 * @return njt_int_t        result status NJT_ERROR or NJT_OK
 */
njt_int_t njt_struct_top_find(njt_json_manager *pjson_manager,
                        njt_str_t *key, njt_json_element **out_element)
{
    if (pjson_manager == NULL || pjson_manager->json_val == NULL
        || key == NULL)
    {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
             "njt_struct_top_find input param invalid, shoude not null");
        return NJT_ERROR;
    }

    return njt_struct_find(pjson_manager->json_val, key, out_element);
}


/**
 * @brief add element to parent element, support all type's add
 * 
 * @param parent_element    input parent element, type must object or array
 * @param element           input element
 * @param pool              input pool
 * @return njt_int_t        result status NJT_ERROR or NJT_OK
 */
njt_int_t njt_struct_add(njt_json_element *parent_element,
                        njt_json_element *element, njt_pool_t *pool)
{
    njt_int_t rc = NJT_OK;
    njt_lvlhsh_query_t lhq;

    if(parent_element == NULL
         || element == NULL || pool == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
             "njt_struct_add input param invalid, shoude not null");
        return NJT_ERROR;
    }

    if(parent_element->type == NJT_JSON_ARRAY){
        njt_queue_insert_tail(&parent_element->arrdata, &element->ele_queue);
    }else if(parent_element->type == NJT_JSON_OBJ){
        if(parent_element->objdata.lvlhsh == NULL){
            parent_element->objdata.lvlhsh = njt_pnalloc(pool, sizeof(njt_lvlhsh_t));
            if(parent_element->objdata.lvlhsh == NULL){
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                    "njt_struct_add lvlhsh alloc fail");
                return NJT_ERROR;
            }
            parent_element->objdata.lvlhsh->slot = NULL;
            njt_queue_init(&parent_element->objdata.datas);
        }

        if(element->key.len < 1){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                    "njt_struct_add must has key");
            return NJT_ERROR; 
        }

        //create lhq
        lhq.key = element->key;
        lhq.key_hash = njt_murmur_hash2(lhq.key.data, lhq.key.len);
        lhq.proto = &njt_http_lvlhsh_proto;
        lhq.pool = pool;
        lhq.value = element;

        //insert to hash
        rc = njt_lvlhsh_insert(parent_element->objdata.lvlhsh, &lhq);
        if(rc != NJT_OK){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                    "njt_struct_add hash insert fail, error code:%s", rc);
            return NJT_ERROR;
        }

        njt_queue_insert_tail(&parent_element->objdata.datas, &element->ele_queue);
    }else{
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "parent_element only NJT_JSON_ARRAY or NJT_JSON_OBJ,  type: %d", parent_element->type);
        return NJT_ERROR;
    }

    return rc;
}


/**
 * @brief add element to json manager (top level), support all type's add
 * 
 * @param pjson_manager     input json manager
 * @param element           input element
 * @param root_type         input root_type, must NJT_JSON_ARRAY or NJT_JSON_OBJ
 * @param pool              input pool
 * @return njt_int_t        result status NJT_ERROR or NJT_OK
 */
njt_int_t njt_struct_top_add(njt_json_manager *pjson_manager,
        njt_json_element *element, int8_t  root_type, njt_pool_t *pool)
{
    njt_int_t rc = NJT_OK;

    if(pjson_manager == NULL || element == NULL || pool == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
             "njt_struct_top_add input param invalid, shoude not null");
        return NJT_ERROR;
    }

    if(pjson_manager->json_val == NULL){
        if(root_type != NJT_JSON_ARRAY && root_type != NJT_JSON_OBJ){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "njt_struct_top_add root_type should be object or array, now:%d", root_type);
            return NJT_ERROR;
        }

        pjson_manager->json_val = njt_pnalloc(pool, sizeof(njt_json_element));
        if (pjson_manager->json_val == NULL) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "njt_struct_top_add json alloc fail");
            return NJT_ERROR;
        }

        pjson_manager->json_val->type = root_type;

        if(root_type == NJT_JSON_ARRAY){
            njt_queue_init(&pjson_manager->json_val->arrdata);
        }else if(root_type == NJT_JSON_OBJ){
            pjson_manager->json_val->objdata.lvlhsh = NULL;
            njt_queue_init(&pjson_manager->json_val->objdata.datas);
        }
    }

    if(pjson_manager->json_val->type != NJT_JSON_ARRAY && 
        pjson_manager->json_val->type != NJT_JSON_OBJ){

        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
            "njt_struct_top_add json type should be object or array, now:%d", pjson_manager->json_val->type);
        return NJT_ERROR;
    }

    rc = njt_struct_add(pjson_manager->json_val, element, pool);

    return rc;
}



/**
 * @brief   delete element from parent element
 *          just support delete NJT_JSON_OBJ's element which must has key
 *     
 * @param parent_element    input parent_element
 * @param key               input key
 * @return njt_int_t        result status NJT_ERROR or NJT_OK
 */
njt_int_t njt_struct_object_delete(njt_json_element *parent_element,
        njt_str_t *key)
{
    njt_int_t rc = NJT_OK;
    njt_lvlhsh_query_t lhq;
    njt_json_element *out_element; 

    if(parent_element == NULL || key == NULL || key->len < 1){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
             "njt_struct_object_delete input param invalid, shoude not null");
        return NJT_ERROR;
    }

    if(parent_element->type != NJT_JSON_OBJ){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
             "njt_struct_object_delete type shoude object, now:%d", parent_element->type);
        return NJT_ERROR; 
    }

    if(parent_element->objdata.lvlhsh == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
             "njt_struct_object_delete lvlhsh shoude not null");
        return NJT_ERROR;
    }

    rc = njt_struct_find(parent_element, key, &out_element);
    if(rc == NJT_OK){
        lhq.key = *key;
        lhq.key_hash = njt_murmur_hash2(lhq.key.data, lhq.key.len);
        lhq.proto = &njt_http_lvlhsh_proto;

        rc = njt_lvlhsh_delete(parent_element->objdata.lvlhsh, &lhq);
        if(rc == NJT_OK){
            //remove from queue
            njt_queue_remove(&out_element->ele_queue);
        }
    }

    return NJT_OK;
}


/**
 * @brief   delete element from array element
 *     
 * @param element           input element
 * @return njt_int_t        result status NJT_ERROR or NJT_OK
 */
njt_int_t njt_struct_array_delete(njt_json_element *element)
{
    if(element == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
             "njt_struct_array_delete input element shoude not null");
        return NJT_ERROR;
    }

    njt_queue_remove(&element->ele_queue);

    return NJT_OK;
}


njt_json_element* njt_json_str_element(njt_pool_t *pool,u_char *key,njt_uint_t len,njt_str_t *value)
{
    njt_json_element *element;

    element = NULL;
    element = njt_pcalloc(pool,sizeof (njt_json_element));
    if(element == NULL ){
        goto end;
    }
    element->type = NJT_JSON_STR;
    element->key.len = 0;
    if(key != NULL){
        element->key.data = key;
        element->key.len = len;
    }
    if(value != NULL && value->len > 0){
        element->strval = *value;
    }else{
        njt_str_set(&element->strval, "");
    }

    end:
    return element;
}


njt_json_element* njt_json_bool_element(njt_pool_t *pool, u_char *key,njt_uint_t len,bool value)
{
    njt_json_element *element;

    element = NULL;
    element = njt_pcalloc(pool,sizeof (njt_json_element));
    if(element == NULL ){
        goto end;
    }
    element->type = NJT_JSON_BOOL;
    element->key.len = 0;
    if(key != NULL){
        element->key.data = key;
        element->key.len = len;
    }
    element->bval = value;

    end:
    return element;
}


njt_json_element* njt_json_arr_element(njt_pool_t *pool,u_char *key,njt_uint_t len)
{
    njt_json_element *element;

    element = NULL;
    element = njt_pcalloc(pool,sizeof (njt_json_element));
    if(element == NULL ){
        goto end;
    }
    element->type = NJT_JSON_ARRAY;
    element->key.len = 0;
    if(key != NULL){
        element->key.data = key;
        element->key.len = len;
    }

    njt_queue_init(&element->arrdata);

    end:
    return element;
}


njt_json_element* njt_json_obj_element(njt_pool_t *pool,u_char *key, njt_uint_t len)
{
    njt_json_element *element;

    element = NULL;
    element = njt_pcalloc(pool,sizeof (njt_json_element));
    if(element == NULL ){
        goto end;
    }
    element->type = NJT_JSON_OBJ;
    element->key.len = 0;
    if(key != NULL){
        element->key.data = key;
        element->key.len = len;
    }

    element->objdata.lvlhsh = NULL;
    njt_queue_init(&element->objdata.datas);

    end:
    return element;

}


njt_json_element* njt_json_int_element(njt_pool_t *pool,u_char *key, njt_uint_t len, int64_t intval)
{
    njt_json_element *element;
    
    element = NULL;
    element = njt_pcalloc(pool,sizeof (njt_json_element));
    if(element == NULL ){
        goto end;
    }
    element->type = NJT_JSON_INT;
    element->key.len = 0;
    if(key != NULL){
        element->key.data = key;
        element->key.len = len;
    }
    
    element->intval = intval;
    
    end:
    return element;
}


njt_json_element* njt_json_double_element(njt_pool_t *pool,u_char *key, njt_uint_t len, double doubleval)
{
    njt_json_element *element;

    element = NULL;
    element = njt_pcalloc(pool,sizeof (njt_json_element));
    if(element == NULL ){
        goto end;
    }
    element->type = NJT_JSON_DOUBLE;
    element->key.len = 0;
    if(key != NULL){
        element->key.data = key;
        element->key.len = len;
    }
    element->doubleval = doubleval;

    end:
    return element;
}


njt_json_element* njt_json_null_element(njt_pool_t *pool,u_char *key, njt_uint_t len)
{
    njt_json_element *element;

    element = NULL;
    element = njt_pcalloc(pool,sizeof (njt_json_element));
    if(element == NULL ){
        goto end;
    }
    element->type = NJT_JSON_NULL;
    element->key.len = 0;
    if(key != NULL){
        element->key.data = key;
        element->key.len = len;
    }

    end:
    return element;
}
