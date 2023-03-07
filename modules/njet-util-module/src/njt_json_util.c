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

#include <njt_json_util.h>
njt_int_t njt_json_parse_json_element(njt_pool_t *pool,njt_json_element  *element,njt_json_define_t *def,void *data){
    njt_int_t rc;
    njt_json_element  *sub,*target;
    njt_uint_t  j;
    njt_array_t *array;
    njt_queue_t *q;
    char  *p ;

    rc = NJT_OK;
    if (element->type == NJT_JSON_ARRAY){
        q = njt_queue_head(&element->arrdata) ;
        array = data;
        njt_array_init(array,pool,4,def->size);
        for (; q != njt_queue_sentinel(&element->arrdata); q = njt_queue_next(q) ) {
            p = njt_array_push(array);
            njt_memzero(p,def->size);
            sub = njt_queue_data(q,njt_json_element ,ele_queue);
            rc = njt_json_parse_json_element(pool,sub,def,p);
            if(rc != NJT_OK){
                return rc;
            }
        }
        return rc;
    }
    if (element->type != def->type){
        njt_log_error(NJT_LOG_EMERG, pool->log, 0, "%V type not matching",&element->key);
        return NJT_ERROR;
    }
    if(def->parse){
        rc = def->parse(element,def,data);
        if(rc != NJT_OK){
            njt_log_error(NJT_LOG_EMERG, pool->log, 0, "%V custom parse error",&element->key);
        }
        return rc;
    }
    if(def->type == NJT_JSON_OBJ && def->sub != NULL ){
        for( j = 0 ; def->sub[j].name.len != 0 ; ++j ) {
            if(njt_struct_find(element,&def->sub[j].name,&target) == NJT_OK){
                p = data;
                p += def->sub[j].offset;
                rc = njt_json_parse_json_element(pool,target, &def->sub[j], p);
                if (rc != NJT_OK) {
                    return rc;
                }
            }
        }
        return NJT_OK;
    }
    switch (def->type) {
        case NJT_JSON_STR:
            *((njt_str_t*)data)=element->strval;
            break;
        case NJT_JSON_INT:
            *((njt_int_t*)data)=element->intval;
            break;
        case NJT_JSON_DOUBLE:
            *((double*)data)=element->doubleval;
            break;
        case NJT_JSON_BOOL:
            *((bool*)data)=element->bval;
            break;
        case NJT_JSON_NULL:
        case NJT_JSON_OBJ:
        default:
            njt_log_error(NJT_LOG_EMERG, pool->log, 0, "%V sub not allow is NULL, ARRAY ",&element->key);
            return NJT_ERROR;
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
    njt_json_element  *items,*sub;
    njt_array_t *array;
    void *p;
    njt_queue_t *q;

    njt_json_define_t obj_def={
            njt_null_string,
            0,
            0,
            NJT_JSON_OBJ,
            def,
            NULL,
    };

    rc = njt_json_2_structure(str, &json_body,pool);
    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_EMERG, pool->log, 0, "structure json body mem malloc error !!");
        return rc;
    }

    items = json_body.json_val;
    if(items->type== NJT_JSON_OBJ){
        rc = njt_json_parse_json_element(pool,items,&obj_def,data);
        if(rc != NJT_OK){
            return rc;
        }
    }
    array = data;
    if(items->type== NJT_JSON_ARRAY){
        p = njt_array_push(array);
        q = njt_queue_head(&items->arrdata);
        for(; q == njt_queue_sentinel(&items->arrdata); q = njt_queue_next(q)){
            sub = njt_queue_data(q,njt_json_element,ele_queue);
            rc = njt_json_parse_json_element(pool,sub,&obj_def,p);
            if(rc != NJT_OK){
                return rc;
            }
        }
    }

    return NJT_OK;
}