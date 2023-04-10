
/*
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_JSON_API_H_INCLUDED_
#define _NJT_JSON_API_H_INCLUDED_

#include <njt_config.h>
#include <njt_core.h>
#include "njt_json.h"
#define NJT_JSON_ERROR  -1
#define NJT_JSON_NULL  0
#define NJT_JSON_OBJ  1
#define NJT_JSON_ARRAY  2
#define NJT_JSON_STR  3
#define NJT_JSON_INT  4
#define NJT_JSON_DOUBLE  5
#define NJT_JSON_BOOL  6



#define NJT_JSON_ELEM_SIZE_PUNCTUATION  10
#define NJT_JSON_ELEM_SIZE_BOOL         16
#define NJT_JSON_ELEM_SIZE_INT          32
#define NJT_JSON_ELEM_SIZE_STR          16
#define NJT_JSON_ELEM_SIZE_DOUBLE       100
#define NJT_JSON_ELEM_SIZE_ARRAY        16
#define NJT_JSON_ELEM_SIZE_OBJ          16
#define NJT_JSON_ELEM_SIZE_NULL         16


#define njt_json_fast_key(key) (u_char*)key,sizeof(key)-1
#define njt_json_null_key NULL,0


//use for obj hash data
typedef struct {
    njt_lvlhsh_t *lvlhsh;   //hash struct, main for insert/find/update
    njt_queue_t  datas;     //main for loop use
} njt_json_lvlhsh_t;

typedef struct {
    njt_str_t key;
    int8_t  type;
    union {
        bool bval;
        //uint64_t uintval;
        int64_t  intval;
        double   doubleval;
        njt_str_t strval;
        njt_json_lvlhsh_t objdata; //just for object
        njt_queue_t  arrdata;      //just for array
    };
    njt_queue_t      ele_queue;
} njt_json_element;


struct njt_json_manager_s {
    //top element, type only NJT_JSON_OBJ or NJT_JSON_ARRAY
    njt_json_element   *json_val;
    int64_t            total_size;
    njt_pool_t         *pool;
    void (*free)(struct njt_json_manager_s *pt);
};

typedef struct  njt_json_manager_s njt_json_manager;

typedef void (*njt_json_manager_free_pt)(njt_json_manager *pt);

int64_t njt_calc_element_size(njt_json_element *element, bool contain_key);


/**
 * @brief transfer json str to json manager
 * 
 * @param json           input json str
 * @param pjson_manager  ouput json manager
 * @param init_pool      input required  pool
 * @return njt_int_t     result status NJT_ERROR or NJT_OK
 */
njt_int_t njt_json_2_structure(njt_str_t *json,
                njt_json_manager *pjson_manager, njt_pool_t *init_pool);


/**
 * @brief transfer json manager to json str
 * 
 * @param pjson_manager   input json manager
 * @param json            output json str
 * @param init_pool       input required  pool
 * @return njt_int_t      result status NJT_ERROR or NJT_OK
 */
njt_int_t njt_structure_2_json(njt_json_manager *pjson_manager,
                njt_str_t *json, njt_pool_t *init_pool);


/**
 * @brief find element from json manager by key
 *        not support array element find, because array element has no key
 * @param pjson_manager     input json manager
 * @param key               input key
 * @param out_element       output element
 * @return njt_int_t        result status NJT_ERROR or NJT_OK
 */
njt_int_t njt_struct_top_find(njt_json_manager *pjson_manager,
                        njt_str_t *key, njt_json_element **out_element);


/**
 * @brief find element from parent element by key
 *        not support array element find, because array element has no key
 * @param parent_element    input parent_element
 * @param key               input key
 * @param out_element       output element
 * @return njt_int_t        result status NJT_ERROR or NJT_OK
 */
njt_int_t njt_struct_find(njt_json_element *parent_element,
                        njt_str_t *key, njt_json_element **out_element);


/**
 * @brief add element to json manager (top level)
 * 
 * @param pjson_manager     input json manager
 * @param element           input element
 * @param root_type         input root_type, must NJT_JSON_ARRAY or NJT_JSON_OBJ
 * @param pool              input pool
 * @return njt_int_t        result status NJT_ERROR or NJT_OK
 */
njt_int_t njt_struct_top_add(njt_json_manager *pjson_manager,
        njt_json_element *element, int8_t  root_type, njt_pool_t *pool);


/**
 * @brief add element to parent element
 * 
 * @param parent_element    input parent element
 * @param element           input element
 * @param pool              input pool
 * @return njt_int_t        result status NJT_ERROR or NJT_OK
 */
njt_int_t njt_struct_add(njt_json_element *parent_element,
                        njt_json_element *element, njt_pool_t *pool);


/**
 * @brief   delete element from parent element
 *          just support delete NJT_JSON_OBJ's element which must has key
 *     
 * @param parent_element    input parent_element
 * @param key               input key
 * @return njt_int_t        because array element has no key
 */
njt_int_t njt_struct_object_delete(njt_json_element *parent_element,
                        njt_str_t *key);


/**
 * @brief   delete element from array element
 *     
 * @param element           input element
 * @return njt_int_t        result status NJT_ERROR or NJT_OK
 */
njt_int_t njt_struct_array_delete(njt_json_element *element);



njt_json_element* njt_json_str_element(njt_pool_t *pool,u_char *key,njt_uint_t len,njt_str_t *value);
njt_json_element* njt_json_bool_element(njt_pool_t *pool, u_char *key,njt_uint_t len,bool value);
njt_json_element* njt_json_arr_element(njt_pool_t *pool,u_char *key,njt_uint_t len);
njt_json_element* njt_json_obj_element(njt_pool_t *pool,u_char *key, njt_uint_t len);
njt_json_element* njt_json_int_element(njt_pool_t *pool,u_char *key, njt_uint_t len, int64_t intval);
njt_json_element* njt_json_double_element(njt_pool_t *pool,u_char *key, njt_uint_t len, double doubleval);
njt_json_element* njt_json_null_element(njt_pool_t *pool,u_char *key, njt_uint_t len);


#endif
