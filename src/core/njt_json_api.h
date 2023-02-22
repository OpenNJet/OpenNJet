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

typedef struct {
    njt_str_t key;
    int8_t  type;
    union {
        bool bval;
        //uint64_t uintval;
        int64_t  intval;
        double   doubleval;
        njt_str_t strval;
        njt_array_t *sudata;
    };
} njt_json_element;

struct njt_json_manager_s {
    njt_array_t        *json_keyval;
    njt_pool_t         *pool;
    void (*free)(struct njt_json_manager_s *pt);
};

typedef struct  njt_json_manager_s njt_json_manager;

typedef void (*njt_json_manager_free_pt)(njt_json_manager *pt);

njt_int_t njt_json_2_structure(njt_str_t *json,
                               njt_json_manager *pjson_manager, njt_pool_t *init_pool);


njt_int_t njt_structure_2_json(njt_json_manager *pjson_manager,
                               njt_str_t *json, njt_pool_t *init_pool);
njt_int_t njt_struct_top_find(njt_json_manager *pjson_manager,
                        njt_str_t *key, njt_json_element **out_element);
njt_int_t njt_struct_find(njt_json_element *in_element,
                        njt_str_t *key, njt_json_element **out_element);

njt_int_t njt_struct_add(njt_json_element *parent_element,
                        njt_json_element *element, njt_pool_t *pool);

njt_int_t njt_struct_element_destroy(njt_json_element *element,
                njt_pool_t *pool);

njt_int_t njt_struct_destroy(njt_json_manager *pjson_manager);

#endif
