/*
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */
#include <njt_rpc_result_util.h>

njt_rpc_result_t * njt_rpc_result_create(){
    njt_rpc_result_t * rpc_result;
    njt_pool_t * pool;
    rpc_result = (njt_rpc_result_t *)njt_calloc(sizeof(njt_rpc_result_t),njt_cycle->log);
    pool = njt_create_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
    rpc_result->pool = pool;
    rpc_result->data = njt_array_create(pool,4,sizeof(njt_str_t));
    return rpc_result;
}

void  njt_rpc_result_set_code(njt_rpc_result_t * rpc_result,njt_int_t code){
    if(rpc_result){
        rpc_result->code = code;
    }
}
void njt_rpc_result_set_msg(njt_rpc_result_t * rpc_result,u_char * msg){
    size_t len = 0;
    njt_str_t tmp_msg;
    if(!rpc_result) {
        return;
    }

    // 先free
    if(rpc_result->msg){
        njt_pfree(rpc_result->pool,rpc_result->msg);
        rpc_result->msg = NULL;
    }
    if(msg){
        len = njt_strlen(msg);
        tmp_msg.len = len;
        tmp_msg.data = msg;
        rpc_result->msg = njt_pstrdup(rpc_result->pool,&tmp_msg);
    }
}
//void njt_rpc_result_add_err_data(njt_rpc_result_t * rpc_result,njt_str_t * msg) {
//    njt_str_t * str_msg;
//    if(!rpc_result || !msg || msg->len == 0){
//        return;
//    }
//
//    str_msg = (njt_str_t * )njt_array_push(rpc_result->data);
//    str_msg->data = njt_pstrdup(rpc_result->pool,msg);
//    str_msg->len = msg->len;
//}
int njt_rpc_result_to_json_str(njt_rpc_result_t * rpc_result,njt_str_t *json_str) {
    njt_json_manager json_manager;
    njt_int_t rc;
    size_t i;
    njt_pool_t *init_pool;
    njt_str_t str_val, *p;
    njt_json_element *element,*data_element;
    if(!rpc_result){
        rc = NJT_ERROR;
        goto out;
    }

    njt_memzero(&json_manager, sizeof(njt_json_manager));
    //创建 pool
    //    init_pool= njt_create_pool(NJT_DEFAULT_POOL_SIZE, njt_cycle->log);
    init_pool= rpc_result->pool;
    if (init_pool== NULL)
    {
        rc = NJT_ERROR;
        goto out;
    }
    // 添加code
    element = njt_json_int_element(init_pool, njt_json_fast_key("code"), rpc_result->code);

    rc = njt_struct_top_add(&json_manager, element, NJT_JSON_OBJ, init_pool);
    if(rc != NJT_OK){
        njt_log_error(NJT_LOG_ALERT, njt_cycle->log, rc,
                      "====njt_struct_top_add code error");
        goto out;
    }
    // 添加msg
    str_val.data = rpc_result->msg;
    str_val.len = njt_strlen(rpc_result->msg);
    element = njt_json_str_element(init_pool, njt_json_fast_key("msg"), &str_val);

    rc = njt_struct_top_add(&json_manager, element, NJT_JSON_OBJ, init_pool);
    if(rc != NJT_OK){
        njt_log_error(NJT_LOG_ALERT, njt_cycle->log, rc,
                      "====njt_struct_top_add msg error");
        goto out;
    }

    // 添加data
    data_element = njt_json_arr_element(init_pool, njt_json_fast_key("data"));
    p = rpc_result->data->elts;
    for(i=0; i < rpc_result->data->nelts; ++i) {
        str_val.len = (p + i)->len;
        str_val.data = (p + i)->data;
        element = njt_json_str_element(init_pool, njt_json_null_key, &str_val);

        rc = njt_struct_add(data_element, element, init_pool);
        if(rc != NJT_OK){
            njt_log_error(NJT_LOG_ALERT, njt_cycle->log, rc,
                          "====njt_struct_add data error");
            goto out;

        }
    }

    rc = njt_struct_top_add(&json_manager, data_element, NJT_JSON_OBJ, init_pool);
    if(rc != NJT_OK){
        njt_log_error(NJT_LOG_ALERT, njt_cycle->log, rc,
                      "====njt_struct_top_add msg error");
        goto out;
    }

    // 转string
    //struct转json
    rc = njt_structure_2_json(&json_manager, json_str, init_pool);
    if(rc != NJT_OK){
        njt_log_error(NJT_LOG_ALERT, njt_cycle->log, rc,
                      "====njt_structure_2_json error");
        goto out;
    }

    out:
    //最后一定记得释放掉pool
    if(init_pool){
        njt_destroy_pool(init_pool);
    }

    return rc;
}
void njt_rpc_result_destroy(njt_rpc_result_t * rpc_result){

    size_t i;
    njt_str_t *p;
    if(rpc_result){
        // 释放msg
        if(rpc_result->msg){
            njt_pfree(rpc_result->pool,rpc_result->msg);
            rpc_result->msg = NULL;
        }

        // 释放array
        p = rpc_result->data->elts;
        for(i=0; i < rpc_result->data->nelts; ++i) {
            if((p + i)->len>0){
                njt_pfree(rpc_result->pool,(p + i)->data);
                (p + i)->len = 0;
                (p + i)->data = NULL;
            }
        }
        njt_array_destroy(rpc_result->data);

        // 销毁pool
        if(rpc_result->pool){
            njt_destroy_pool(rpc_result->pool);
        }
        njt_free(rpc_result);
    }
}
