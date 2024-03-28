/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */
#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njet.h>
#include "njt_http_kv_module.h"

#include "njt_http_util.h"
#include "njt_str_util.h"
#include <njt_rpc_result_util.h>
#include "njt_http_dyn_range_api_parser.h"
#include "njt_http_dyn_range_parser.h"
#include "njt_range_module.h"

extern  njt_module_t njt_range_module;



static njt_int_t njt_dyn_range_check_param(dyn_range_api_t *api_data,
            njt_rpc_result_t *rpc_result){
    u_char                      data_buf[1024];
    u_char                      *end;
    njt_str_t                   rpc_data_str;
    u_char                      *p = NULL;
    njt_int_t                   tmp_value;
    njt_int_t                   left_value, right_value, left_len, right_len;
    njt_uint_t                  j, has_m = 0, m_count = 0;

    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;

    //check type
    if(api_data->type != DYN_RANGE_API_TYPE_TCP && api_data->type != DYN_RANGE_API_TYPE_UDP){
        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
            " type should be tcp or udp");

        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

        return NJT_ERROR;
    }

    if(api_data->dst_port < 1){
        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
            " range dst_port should be int and more than 0");

        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

        return NJT_ERROR;
    }

    //check valid
    if(!api_data->is_src_ports_set || api_data->src_ports.len < 1){
        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
            " range src_port must be set and not empty");

        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

        return NJT_ERROR;
    }

    for(j = 0; j < api_data->src_ports.len; j++){
        if(api_data->src_ports.data[j] == ':'){
            has_m = 1;
            m_count++;
            p = &api_data->src_ports.data[j];
        }
    }

    if(m_count > 1){
        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
            " range src_port not valid");

        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
        return NJT_ERROR;   
    }

    if(has_m == 0){
        tmp_value = njt_atoi(api_data->src_ports.data, api_data->src_ports.len);
        if (tmp_value < 1) {
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
                " range src_port not valid");

            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            return NJT_ERROR;
        }
    }else{
        left_len = p - api_data->src_ports.data;
        right_len = api_data->src_ports.len - left_len - 1;
        if(left_len < 1 || right_len < 1){
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
                " range src_port not valid");

            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            return NJT_ERROR;
        }

        //check left value
        left_value = njt_atoi(api_data->src_ports.data, left_len);
        if (left_value < 1) {
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
                " range src_port not valid");

            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            return NJT_ERROR;
        }

        //check right value
        right_value = njt_atoi(p+1, right_len);
        if (right_value < 1) {
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
                " range src_port not valid");

            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}

static njt_int_t njt_update_range(njt_pool_t *pool, dyn_range_api_t *api_data,
                njt_rpc_result_t *rpc_result){
    njt_range_conf_t                *rcf;
    njt_cycle_t                     *cycle;
    u_char                           data_buf[1024];
    u_char                          *end;
    njt_str_t                        rpc_data_str;
    njt_queue_t                     *q;
    njt_range_rule_t                *rule_item;
    njt_int_t                       found = 0;
    dyn_range_api_type_t            tmp_type;
    dyn_range_api_family_t          tmp_family;
    njt_str_t                       tmp_str;
    njt_str_t                       tmp_ip_str;

    
    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;

    cycle = (njt_cycle_t*)njt_cycle;
    njt_str_null(&rpc_result->conf_path);

    if (!api_data->is_action_set || !api_data->is_type_set 
        || !api_data->is_src_ports_set || !api_data->is_dst_port_set) {
        njt_log_error(NJT_LOG_ERR, cycle->log, 0,
            "parameters error, action:%d or type:%d or src_ports:%d or dst_port:%d is empty",
            api_data->is_action_set, api_data->is_type_set,
            api_data->is_src_ports_set, api_data->is_dst_port_set);

        // params is empty
        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
            " parameters error, action or type or src_ports or dst_port is empty");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
        return NJT_ERROR;
    }

    rcf = (njt_range_conf_t *)njt_get_conf(cycle->conf_ctx, njt_range_module);    
    if(rcf == NULL){
        njt_log_error(NJT_LOG_ERR, cycle->log, 0,
                "dyn range create dynamic pool error");
        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
            " no range module load");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
        return NJT_ERROR;
    }

    if(rcf->pool == NJT_CONF_UNSET_PTR){
        rcf->pool = njt_create_dynamic_pool(njt_pagesize, cycle->log);
        if (rcf->pool == NULL || NJT_OK != njt_sub_pool(cycle->pool, rcf->pool)) {
            njt_log_error(NJT_LOG_ERR, cycle->log, 0,
                    "dyn range create dynamic pool error");

            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
                " dyn range create dynamic pool error");
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            return NJT_ERROR;
        }
    }

    //check same range, if has exist, should update other info
    found = 0;
    q = njt_queue_head(&rcf->ranges);
    for (; q != njt_queue_sentinel(&rcf->ranges); q = njt_queue_next(q)) {
        rule_item = njt_queue_data(q, njt_range_rule_t, range_queue);
        if(rule_item->type.len == 3 && njt_strncmp(rule_item->type.data, "tcp", 3) == 0){
            tmp_type = DYN_RANGE_API_TYPE_TCP;
        }else if(rule_item->type.len == 3 && njt_strncmp(rule_item->type.data, "udp", 3) == 0){
            tmp_type = DYN_RANGE_API_TYPE_UDP;
        }else{
            continue;
        }

        if(rule_item->family.len == 4 && njt_strncmp(rule_item->family.data, "ipv4", 4) == 0){
            tmp_family = DYN_RANGE_API_FAMILY_IPV_4;
        }else if(rule_item->family.len == 4 && njt_strncmp(rule_item->family.data, "ipv6", 4) == 0){
            tmp_family = DYN_RANGE_API_FAMILY_IPV_6;
        }else{
            continue;
        }

        if(api_data->is_family_set){
            if(tmp_type == api_data->type && tmp_family == api_data->family
                && rule_item->src_ports.len == api_data->src_ports.len
                && njt_strncmp(rule_item->src_ports.data, api_data->src_ports.data, api_data->src_ports.len) == 0
                && rule_item->dst_port == api_data->dst_port){
                
                found = 1;
                break;
            }
        }else{
            if(DYN_RANGE_API_FAMILY_IPV_6 == tmp_family){
                continue;
            }

            if(tmp_type == api_data->type
                && rule_item->src_ports.len == api_data->src_ports.len
                && njt_strncmp(rule_item->src_ports.data, api_data->src_ports.data, api_data->src_ports.len) == 0
                && rule_item->dst_port == api_data->dst_port){
                
                found = 1;
                break;
            }
        }
    }

    if(found){
        if(api_data->action == DYN_RANGE_API_ACTION_ADD){
            return NJT_DECLINED;
        }else if(api_data->action == DYN_RANGE_API_ACTION_DEL){
            if(api_data->is_family_set && DYN_RANGE_API_FAMILY_IPV_6 == api_data->family){
                tmp_str.data = rcf->ip6tables_path.path;
                tmp_str.len = rcf->ip6tables_path.len;
            }else{
                tmp_str.data = rcf->iptables_path.path;
                tmp_str.len = rcf->iptables_path.len;
            }

            tmp_ip_str.data = rcf->ip_path.path;
            tmp_ip_str.len = rcf->ip_path.len;

            if(NJT_OK != njt_range_operator_rule(&tmp_str, &tmp_ip_str, NJT_RANGE_ACTION_DEL,
                    &rule_item->type, &rule_item->src_ports, rule_item->dst_port)){
                njt_log_error(NJT_LOG_ERR, cycle->log, 0,
                        "range add rule error, type:%V  src_ports:%V  dst_port:%d",
                        &rule_item->type, &rule_item->src_ports, rule_item->dst_port);
                return NJT_ERROR;
            }

            njt_queue_remove(&rule_item->range_queue);
            njt_pfree(rcf->pool, rule_item->src_ports.data);
            njt_pfree(rcf->pool, rule_item);
        }
    }else{
        if(api_data->action == DYN_RANGE_API_ACTION_ADD){
            //check param
            if(NJT_OK != njt_dyn_range_check_param(api_data, rpc_result)){
                njt_log_error(NJT_LOG_EMERG, cycle->log, 0,
                        "dyn range check param error");
                return NJT_ERROR;  
            }

            //create range rule in pool
            rule_item = njt_pcalloc(rcf->pool, sizeof(njt_range_rule_t));
            if(rule_item == NULL){
                njt_log_error(NJT_LOG_EMERG, cycle->log, 0,
                        "dyn range malloc rule error");
                return NJT_ERROR;  
            }
            rule_item->dst_port = api_data->dst_port;
            if(api_data->type == DYN_RANGE_API_TYPE_TCP){
                njt_str_set(&rule_item->type, "tcp");
            }else{
                njt_str_set(&rule_item->type, "udp");
            }

            if(api_data->is_family_set && DYN_RANGE_API_FAMILY_IPV_6 == api_data->family){
                njt_str_set(&rule_item->family, "ipv6");
                tmp_str.data = rcf->ip6tables_path.path;
                tmp_str.len = rcf->ip6tables_path.len;
            }else{
                njt_str_set(&rule_item->family, "ipv4");
                tmp_str.data = rcf->iptables_path.path;
                tmp_str.len = rcf->iptables_path.len;
            }
            
            rule_item->src_ports.len = api_data->src_ports.len;
            rule_item->src_ports.data = njt_pcalloc(rcf->pool, api_data->src_ports.len);
            if(rule_item->src_ports.data == NULL){
                njt_log_error(NJT_LOG_EMERG, cycle->log, 0,
                        "dyn range malloc rule src_ports error");
                return NJT_ERROR;  
            }
            njt_memcpy(rule_item->src_ports.data, api_data->src_ports.data, api_data->src_ports.len);


            tmp_ip_str.data = rcf->ip_path.path;
            tmp_ip_str.len = rcf->ip_path.len;
            if(NJT_OK != njt_range_operator_rule(&tmp_str, &tmp_ip_str, NJT_RANGE_ACTION_ADD,
                    &rule_item->type, &rule_item->src_ports, rule_item->dst_port)){
                njt_log_error(NJT_LOG_ERR, cycle->log, 0,
                        "range add rule error, type:%V  src_ports:%V  dst_port:%d",
                        &rule_item->type, &rule_item->src_ports, rule_item->dst_port);

                end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
                    " range add rule error, type:%V  src_ports:%V  dst_port:%d",
                    &rule_item->type, &rule_item->src_ports, rule_item->dst_port);
                rpc_data_str.len = end - data_buf;
                njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

                njt_pfree(rcf->pool, rule_item->src_ports.data);
                njt_pfree(rcf->pool, rule_item);

                return NJT_ERROR;
            }

            njt_queue_insert_tail(&rcf->ranges, &rule_item->range_queue);

        }else if(api_data->action == DYN_RANGE_API_ACTION_DEL){
            //not found, should not be delete
            return NJT_DECLINED;
        }
    }

    return NJT_OK;
}

// static int  njt_http_dyn_range_full_update_handler(njt_str_t *key, njt_str_t *value, void *data){
//     njt_int_t                            rc = NJT_OK;
//     dyn_range_t                         *api_full_datas = NULL;
//     dyn_range_api_t                     api_data;
//     njt_pool_t                          *pool = NULL;
//     njt_rpc_result_t                    *rpc_result = NULL;
//     js2c_parse_error_t                  err_info;
//     dyn_range_ranges_t                  *dyn_ranges = NULL;
//     dyn_range_ranges_item_t             *range_item = NULL;
//     njt_uint_t                          j;


//     rpc_result = njt_rpc_result_create();
//     if(!rpc_result){
//         njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0,
//                 "dyn_range_full_update, njt_rpc_result_create error");
//         rc = NJT_ERROR;

//         goto end;
//     }

//     if(value->len < 2 ){
//         njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "input param not valid, less then 2 byte");
        
//         return NJT_ERROR;
//     }

//     pool = njt_create_pool(njt_pagesize, njt_cycle->log);
//     if(pool == NULL){
//         njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_http_dyn_range_full_change_handler create pool error");
        
//         return NJT_ERROR;
//     }

//     api_full_datas = json_parse_dyn_range(pool, value, &err_info);
//     if (api_full_datas == NULL)
//     {
//         njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
//                 "json_parse_dyn_range err: %V",  &err_info.err_str);

//         rc = NJT_ERROR;
//         goto end;
//     }

//     if(!api_full_datas->is_ranges_set){
//         rc = NJT_OK;
//         goto end;
//     }

//     njt_rpc_result_set_code(rpc_result,NJT_RPC_RSP_SUCCESS);

//     //loop range
//     dyn_ranges = get_dyn_range_ranges(api_full_datas);
//     range_item = dyn_ranges->elts;
//     for (j = 0; j < dyn_ranges->nelts; ++j) {
//         range_item = get_dyn_range_ranges_item(dyn_ranges, j);
//         if(range_item == NULL){
//             continue;
//         }
//         njt_memzero(&api_data, sizeof(dyn_range_api_t));
//         set_dyn_range_api_action(&api_data, DYN_RANGE_API_ACTION_ADD);

//         if(range_item->is_type_set){
//             set_dyn_range_api_type(&api_data, get_dyn_range_ranges_item_type(range_item));
//         }

//         if(range_item->is_src_ports_set){
//             set_dyn_range_api_src_ports(&api_data, get_dyn_range_ranges_item_src_ports(range_item));
//         }

//         if(range_item->is_dst_port_set){
//             set_dyn_range_api_dst_port(&api_data, get_dyn_range_ranges_item_dst_port(range_item));
//         }

//         rc = njt_update_range(pool, &api_data, rpc_result);
//         if(rc != NJT_OK){
//             if(rc == NJT_DECLINED){
//                 njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0, 
//                     "full range change rule has exist");
//             }else{
//                 njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0, 
//                     "full range change update fail");
//             }
//         }
//     }

// end:
//     if(pool != NULL){
//         njt_destroy_pool(pool);
//     }

//     return rc;
// }


static int  njt_http_dyn_range_update_handler(njt_str_t *key, njt_str_t *value, void *data, njt_str_t *out_msg){
    njt_int_t                            rc = NJT_OK;
    dyn_range_api_t                     *api_data = NULL;
    njt_pool_t                          *pool = NULL;
    njt_rpc_result_t                    *rpc_result = NULL;
    js2c_parse_error_t                  err_info;


    rpc_result = njt_rpc_result_create();
    if(!rpc_result){
        if(out_msg != NULL){
            njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
            njt_rpc_result_set_msg(rpc_result, (u_char *)" create rpc_result error");
        }
        rc = NJT_ERROR;

        goto end;
    }

    if(value->len < 2 ){
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_INPUT_PARAM);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" input param not valid, less then 2 byte");
        rc = NJT_ERROR;

        goto end;
    }

    pool = njt_create_pool(njt_pagesize,njt_cycle->log);
    if(pool == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_http_dyn_range_change_handler create pool error");
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_MEM_ALLOC);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" update handler create pool error");
        rc = NJT_ERROR;

        goto end;
    }

    api_data = json_parse_dyn_range_api(pool, value, &err_info);
    if (api_data == NULL)
    {
        njt_log_error(NJT_LOG_ERR, pool->log, 0, 
                "json_parse_dyn_range_api err: %V",  &err_info.err_str);
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_JSON);
        njt_rpc_result_set_msg2(rpc_result, &err_info.err_str);

        rc = NJT_ERROR;
        njt_str_t msg = njt_string("");
        njt_kv_sendmsg(key,&msg,0);
        goto end;
    }

    njt_rpc_result_set_code(rpc_result,NJT_RPC_RSP_SUCCESS);
    rc = njt_update_range(pool,api_data, rpc_result);
    if(rc != NJT_OK){
        njt_str_t msg = njt_string("");
        njt_kv_sendmsg(key,&msg,0);

        if(rc == NJT_DECLINED){
            njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
            if(api_data->action == DYN_RANGE_API_ACTION_DEL){
                njt_rpc_result_set_msg(rpc_result, (u_char *)" rule is not found");
            }else if(api_data->action == DYN_RANGE_API_ACTION_ADD){
                njt_rpc_result_set_msg(rpc_result, (u_char *)" rule has exist");
            }
        }else{
            njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
        }
    }else if(api_data->action == DYN_RANGE_API_ACTION_DEL){
        //need delete msg
        njt_str_t msg = njt_string("");
        njt_kv_sendmsg(key, &msg, 0);
    }

    end:
    if(out_msg){
        njt_rpc_result_to_json_str(rpc_result,out_msg);
    }

    if(pool != NULL){
        njt_destroy_pool(pool);
    }

    if(rpc_result){
        njt_rpc_result_destroy(rpc_result);
    }

    return rc;
}


njt_str_t njt_http_dyn_range_srv_err_msg=njt_string("{\"code\":500,\"msg\":\"server error\"}");
njt_str_t njt_http_dyn_range_range_not_config_msg=njt_string("{\"code\":500,\"msg\":\"no range module config\"}");

static njt_str_t *njt_http_dyn_range_dump_conf(njt_cycle_t *cycle,njt_pool_t *pool){
    dyn_range_t                         dynjson_obj;
    dyn_range_ranges_item_t             *range_item;
    njt_queue_t                         *q;
    njt_range_rule_t                    *rule_item;
    njt_range_conf_t                    *rcf;


    njt_memzero(&dynjson_obj, sizeof(dyn_range_t));

    set_dyn_range_ranges(&dynjson_obj, create_dyn_range_ranges(pool, 4));
    if(dynjson_obj.ranges == NULL){
        goto err;
    }

    rcf = (njt_range_conf_t *)njt_get_conf(cycle->conf_ctx, njt_range_module);    
    if(rcf == NULL){
        return &njt_http_dyn_range_range_not_config_msg;
    }

    q = njt_queue_head(&rcf->ranges);
    for (; q != njt_queue_sentinel(&rcf->ranges); q = njt_queue_next(q)) {
        rule_item = njt_queue_data(q, njt_range_rule_t, range_queue);
        range_item = njt_pcalloc(pool, sizeof(dyn_range_ranges_item_t));
        if(range_item == NULL){
            goto err;
        }

        //set type
        if(njt_strncmp(rule_item->type.data, "tcp", 3) == 0){
            set_dyn_range_ranges_item_type(range_item, DYN_RANGE_RANGES_ITEM_TYPE_TCP);
        }else{
            set_dyn_range_ranges_item_type(range_item, DYN_RANGE_RANGES_ITEM_TYPE_UDP);
        }

        if(njt_strncmp(rule_item->family.data, "ipv4", 4) == 0){
            set_dyn_range_ranges_item_family(range_item, DYN_RANGE_RANGES_ITEM_FAMILY_IPV_4);
        }else{
            set_dyn_range_ranges_item_family(range_item, DYN_RANGE_RANGES_ITEM_FAMILY_IPV_6);
        }        
        
        //set src_ports
        set_dyn_range_ranges_item_src_ports(range_item, &rule_item->src_ports);

        //set dst_port
        set_dyn_range_ranges_item_dst_port(range_item, rule_item->dst_port);

        add_item_dyn_range_ranges(dynjson_obj.ranges, range_item);
    }


    return to_json_dyn_range(pool, &dynjson_obj, OMIT_NULL_ARRAY | OMIT_NULL_OBJ | OMIT_NULL_STR);

err:
    return &njt_http_dyn_range_srv_err_msg;
}

static u_char* njt_http_dyn_range_rpc_handler(njt_str_t *topic, njt_str_t *request, int* len, void *data){
    njt_cycle_t     *cycle;
    njt_str_t       *msg;
    u_char          *buf;

    buf = NULL;
    cycle = (njt_cycle_t*) njt_cycle;
    *len = 0 ;
    njt_pool_t *pool = NULL;
    pool = njt_create_pool(njt_pagesize,njt_cycle->log);
    if(pool == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_http_dyn_range_rpc_handler create pool error");
        goto end;
    }
    msg = njt_http_dyn_range_dump_conf(cycle, pool);
    buf = njt_calloc(msg->len,cycle->log);
    if(buf == NULL){
        goto end;
    }
    // njt_log_error(NJT_LOG_INFO, pool->log, 0, "send json : %V",msg);
    njt_memcpy(buf, msg->data, msg->len);
    *len = msg->len;

    end:
    if(pool != NULL){
        njt_destroy_pool(pool);
    }

    return buf;
}


// static int  njt_http_dyn_range_change_handler(njt_str_t *key, njt_str_t *value, void *data){
//     return njt_http_dyn_range_update_handler(key, value, data, NULL);
// }

static u_char* njt_http_dyn_range_put_handler(njt_str_t *topic, njt_str_t *request, int* len, void *data){
    njt_str_t err_json_msg;
    njt_str_null(&err_json_msg);
    njt_http_dyn_range_update_handler(topic, request, data, &err_json_msg);
    *len = err_json_msg.len;
    return err_json_msg.data;
}

static njt_int_t njt_http_dyn_range_init_process(njt_cycle_t* cycle){
    njt_str_t  rpc_key = njt_string("range");
    njt_kv_reg_handler_t h;

    if(njt_process != NJT_PROCESS_HELPER || 1 != njt_is_privileged_agent){
        return NJT_OK;
    }

    njt_memzero(&h, sizeof(njt_kv_reg_handler_t));
    h.key = &rpc_key;
    h.rpc_get_handler = njt_http_dyn_range_rpc_handler;
    h.rpc_put_handler = njt_http_dyn_range_put_handler;
    // h.handler = njt_http_dyn_range_full_update_handler;
    h.handler = NULL;
    h.api_type = NJT_KV_API_TYPE_INSTRUCTIONAL;
    njt_kv_reg_handler(&h);

    return NJT_OK;
}


static njt_http_module_t njt_http_dyn_range_module_ctx = {
        NULL,                                   /* preconfiguration */
        NULL,                                   /* postconfiguration */

        NULL,                                   /* create main configuration */
        NULL,                                  /* init main configuration */

        NULL,                                  /* create server configuration */
        NULL,                                  /* merge server configuration */

        NULL,                                   /* create location configuration */
        NULL                                    /* merge location configuration */
};

njt_module_t njt_http_dyn_range_module = {
        NJT_MODULE_V1,
        &njt_http_dyn_range_module_ctx,                /* module context */
        NULL,                                   /* module directives */
        NJT_HTTP_MODULE,                        /* module type */
        NULL,                                   /* init master */
        NULL,                                   /* init module */
        njt_http_dyn_range_init_process,          /* init process */
        NULL,                                   /* init thread */
        NULL,                                   /* exit thread */
        NULL,                                   /* exit process */
        NULL,                                   /* exit master */
        NJT_MODULE_V1_PADDING
};

