/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */
#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_stream.h>
#include <njt_json_api.h>
#include <njt_str_util.h>
#include <math.h>
#include <njt_http_kv_module.h>
#include <njt_http_sendmsg_module.h>
#include <njt_rpc_result_util.h>
#include <njt_rpc_result_parser.h>
#include <njt_http_util.h>
#include <njt_http_client_util.h>

#include "njt_http_api_register_module.h"
#include "njt_http_parser_cache.h"
#include "njt_http_parser_cache_api.h"
#include "njt_http_parser_cache_add_loc.h"
#include "njt_http_parser_cache_del_loc.h"


#define MIN_CONFIG_BODY_LEN 2
#define MAX_CONFIG_BODY_LEN 5242880
#define HTTP_CACHE_QUICK_CONFS "cache_quick_confs"
#define DOWNLOAD_STATUS_INFO "download_ratio: %d"

#define NJT_HTTP_CACHE_QUICK_HTTP_SERVER "0.0.0.0:80"
#define NJT_HTTP_CACHE_QUICK_HTTPS_SERVER "0.0.0.0:443"
#define NJT_HTTP_CACHE_QUICK_BODY "proxy_cache cache_quick; add_header cache $upstream_cache_status; proxy_cache_purge $purge_method"


extern njt_uint_t njt_worker;
extern njt_module_t  njt_http_rewrite_module;
extern njt_cycle_t *njet_master_cycle;


typedef enum cache_quick_status_t_e{
    CACHE_QUICK_STATUS_INIT,
    CACHE_QUICK_STATUS_ADD_LOC_OK,
    CACHE_QUICK_STATUS_DEL_LOC_OK,
    CACHE_QUICK_STATUS_DOWNLOAD_ING,
    CACHE_QUICK_STATUS_DOWNLOAD_ERROR,
    CACHE_QUICK_STATUS_OK,
    CACHE_QUICK_STATUS_ERROR
} cache_quick_status_t;

typedef enum cache_quick_op_status_t_e{
    CACHE_QUICK_OP_STATUS_ADDING,
    CACHE_QUICK_OP_STATUS_DELING,
    CACHE_QUICK_OP_STATUS_DONE
} cache_quick_op_status_t;

typedef enum cache_quick_server_ssl_type_t_e{
    CACHE_QUICK_SERVER_SSL_TYPE_NONE,
    CACHE_QUICK_SERVER_SSL_TYPE_SSL,
    CACHE_QUICK_SERVER_SSL_TYPE_NTLS
} cache_quick_server_ssl_type_t;

static njt_int_t
njt_http_cache_quick_handler(njt_http_request_t *r);

static njt_int_t
njt_http_cache_quick_init_worker(njt_cycle_t *cycle);

static njt_int_t njt_http_cache_quick_init_module(njt_cycle_t *cycle);

static njt_int_t
njt_http_cache_quick_init(njt_conf_t *cf);


njt_int_t
njt_http_cache_quick_lvlhsh_test(njt_lvlhsh_query_t *lhq, void *data);



typedef struct njt_http_cache_quick_main_conf_s{
    njt_lvlhsh_t    resource_to_metainfo; //key: addr(server_name, location)   value:metainfo
    njt_queue_t     caches;
    njt_pool_t      *cache_pool;            //used for map
} njt_http_cache_quick_main_conf_t;



typedef struct njt_http_cache_resouce_metainfo_s{
    njt_str_t       addr_port;
    njt_str_t       server_name;
    njt_str_t       location_rule;
    njt_str_t       location_name;
    njt_str_t       location_body;
    njt_str_t       proxy_pass;
    
    cache_quick_server_ssl_type_t       ssl_type;

    uint32_t        crc32;
    njt_str_t       crc32_str;

    ssize_t         resource_size;
    ssize_t         current_size;
    njt_int_t       download_ratio;

    cache_quick_status_t  status;
    cache_quick_op_status_t  op_status;
    njt_str_t       status_str;
    njt_event_t     download_timer;
    njt_pool_t      *item_pool;

    njt_http_client_util_t *client_util;

    njt_queue_t     cache_item;
} njt_http_cache_resouce_metainfo_t;


static void njt_http_cache_quick_save(njt_http_cache_quick_main_conf_t *cqmf);
static njt_int_t
njt_http_cache_quick_download(njt_http_cache_resouce_metainfo_t *cache_info);

static void
njt_http_cache_quick_update_download_status_str(njt_http_cache_resouce_metainfo_t  *cache_info,
        cache_quick_status_t status);

void njt_http_cache_quick_update_download_status(njt_http_cache_resouce_metainfo_t  *cache_info,
        cache_quick_status_t status);

static njt_int_t njt_http_del_cache_item_from_queue(
    njt_http_cache_quick_main_conf_t *cqmf, njt_http_cache_resouce_metainfo_t   *cache_info);

void njt_http_cache_quick_start_success_handler(void *data);

//read timeout handler
void njt_http_cache_quick_read_timeout_handler(void *data);

//write timeout handler
void njt_http_cache_quick_write_timeout_handler(void *data);


//ssl handshake 成功handler
void njt_http_cache_quick_ssl_handshake_success_handler(void *data);

//ssl handshake 失败handler
void njt_http_cache_quick_ssl_handshake_fail_handler(void *data);

//每一次read事件调用处理，rc为每次调用read事件的返回值，可供使用者状态更新
//NJT_ERROR： read调用出错，错误结束
//NJT_DONE： http请求处理完成，正常结束
//NJT_ABORT： http请求异常结束，异常终止
//其他，继续read事件循环
void njt_http_cache_quick_read_event_result(void *data, njt_int_t rc);

//每一次write事件调用处理，rc为每次调用write事件的返回值，可供使用者状态更新
//NJT_ERROR： read调用出错，错误结束
//NJT_DONE： http请求处理完成，正常结束
//NJT_OK: http请求处理完成，正常结束
//其他，继续write事件循环
void njt_http_cache_quick_write_event_result(void *data, njt_int_t rc);

//parse line，可根据rc值来判断parse结果
//rc: NJT_OK or NJT_ERROR
void njt_http_cache_quick_parse_line(void *data, njt_int_t rc);

//parse header，可根据rc值来判断parse结果（最终结果）
void njt_http_cache_quick_parse_header(void *data, njt_int_t rc);

//parse header， 每一个header都会调用，可以通过h->key, h->value 获取数据
void njt_http_cache_quick_parse_header_data(void *data, njt_table_elt_t *h);
   
//parse body，可根据rc值来判断parse结果（最终结果）
void njt_http_cache_quick_parse_body(void *data, njt_int_t rc);

//parse body content， 每次受到的中间数据， 数据放在[start, end)指针范围内，start为数据开始，end为数据最后一个字符的下一位
void njt_http_cache_quick_parse_body_data(void *data, u_char *start, u_char *end);



static void
njt_http_cache_quick_update_status_str(njt_http_cache_resouce_metainfo_t  *cache_info,
        cache_quick_status_t status, njt_str_t *tmp_str);

const njt_lvlhsh_proto_t  njt_http_cache_quick_lvlhsh_proto = {
    NJT_LVLHSH_LARGE_MEMALIGN,
    njt_http_cache_quick_lvlhsh_test,
    njt_lvlhsh_pool_alloc,
    njt_lvlhsh_pool_free,
};


njt_int_t
njt_http_cache_quick_lvlhsh_test(njt_lvlhsh_query_t *lhq, void *data)
{
    //ignore value compare, just return ok
    return NJT_OK;
}


static njt_http_module_t njt_http_cache_quick_module_ctx = {
        NULL,                              /* preconfiguration */
        njt_http_cache_quick_init,         /* postconfiguration */

        NULL,                              /* create main configuration */
        NULL,                              /* init main configuration */

        NULL,                              /* create server configuration */
        NULL,                              /* merge server configuration */

        NULL,                              /* create location configuration */
        NULL                               /* merge location configuration */
};

njt_module_t njt_http_cache_quick_module = {
        NJT_MODULE_V1,
        &njt_http_cache_quick_module_ctx, /* module context */
        NULL,                               /* module directives */
        NJT_HTTP_MODULE,                    /* module type */
        NULL,                               /* init master */
        njt_http_cache_quick_init_module,   /* init module */
        njt_http_cache_quick_init_worker, /* init process */
        NULL,                               /* init thread */
        NULL,                               /* exit thread */
        NULL,                               /* exit process */
        NULL,                               /* exit master */
        NJT_MODULE_V1_PADDING
};


static njt_int_t njt_http_cache_quick_init_module(njt_cycle_t *cycle) {
    njt_http_cache_quick_main_conf_t *cqmf;

    cqmf = njt_pcalloc(cycle->pool, sizeof(njt_http_cache_quick_main_conf_t));
    if (cqmf == NULL) {
        njt_log_error(NJT_LOG_ERR, cycle->log, 0, "malloc njt_http_cache_quick_main_conf_t eror");
        return NJT_ERROR;
    }

    njt_queue_init(&cqmf->caches);
    njt_lvlhsh_init(&cqmf->resource_to_metainfo);

    if(cqmf->cache_pool == NULL){
        cqmf->cache_pool = njt_create_dynamic_pool(NJT_MIN_POOL_SIZE, cycle->log);
        if (cqmf->cache_pool == NULL) {
            njt_log_error(NJT_LOG_EMERG, cycle->log, 0,
                    " cache quick create dynamic pool error");

            return NJT_ERROR;
        }

        njt_sub_pool(cycle->pool, cqmf->cache_pool);
    }

    cycle->conf_ctx[njt_http_cache_quick_module.index] = (void *) cqmf;

    return NJT_OK;
}


static njt_int_t
njt_http_cache_quick_init(njt_conf_t *cf) {
    njt_http_api_reg_info_t             h;
    njt_str_t  module_key = njt_string("/v1/cache");

    njt_memzero(&h, sizeof(njt_http_api_reg_info_t));
    h.key = &module_key;
    h.handler = njt_http_cache_quick_handler;
    njt_http_api_module_reg_handler(&h);

    return NJT_OK;
}


static njt_str_t *njt_http_caches_to_json(njt_pool_t *pool, njt_http_cache_quick_main_conf_t *cqmf) {
    njt_http_cache_resouce_metainfo_t       *cache_info;
    njt_queue_t                             *q;
    cache_t                                 dynjson_obj;
    cache_caches_item_t                     *cache_item;          

    njt_memzero(&dynjson_obj, sizeof(cache_t));

    set_cache_caches(&dynjson_obj, create_cache_caches(pool, 4));
    if(dynjson_obj.caches == NULL){
        goto err;
    }

    q = njt_queue_head(&cqmf->caches);
    for (; q != njt_queue_sentinel(&cqmf->caches); q = njt_queue_next(q)) {
        cache_info = njt_queue_data(q, njt_http_cache_resouce_metainfo_t, cache_item);
        cache_item = create_cache_caches_item(pool);
        if(cache_item == NULL ){
            goto err;
        }

        set_cache_caches_item_location_name(cache_item, &cache_info->location_name);
        set_cache_caches_item_backend_server(cache_item, &cache_info->proxy_pass);
        set_cache_caches_item_status(cache_item, &cache_info->status_str);
        set_cache_caches_item_download_ratio(cache_item, cache_info->download_ratio);

        add_item_cache_caches(dynjson_obj.caches, cache_item);
    }

    return to_json_cache(pool, &dynjson_obj, OMIT_NULL_ARRAY | OMIT_NULL_OBJ | OMIT_NULL_STR);

    err:
    return NULL;
}


static njt_int_t njt_http_get_caches(njt_http_request_t *r, njt_http_cache_quick_main_conf_t *cqmf,
            njt_rpc_result_t *rpc_result) {
    njt_int_t                           rc;
    njt_buf_t                           *buf;
    njt_chain_t                         out;
    njt_str_t                           *json;

    rc = njt_http_discard_request_body(r);
    if (rc == NJT_ERROR || rc >= NJT_HTTP_SPECIAL_RESPONSE) {
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" cache quick discard request body error");
        
        return NJT_ERROR;
    }

    json = njt_http_caches_to_json(r->pool, cqmf);
    if (json == NULL || json->len == 0) {
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" cache quick caches to json error");
        
        return NJT_ERROR;
    }

    buf = njt_create_temp_buf(r->pool, json->len);
    if(buf == NULL){
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "njt_create_temp_buf error , size :%ui" ,json->len);
        
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" cache quick create tmp buffer error");
        
        return NJT_ERROR;
    }

    buf->last = buf->pos + json->len;
    njt_memcpy(buf->pos, json->data, json->len);
    r->headers_out.status = NJT_HTTP_OK;
    njt_str_t type = njt_string("application/json");
    r->headers_out.content_type = type;
    r->headers_out.content_length_n = buf->last - buf->pos;
    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    rc = njt_http_send_header(r);
    if (rc == NJT_ERROR || rc > NJT_OK || r->header_only) {
        return rc;
    }

    buf->last_buf = 1;
    out.buf = buf;
    out.next = NULL;

    return njt_http_output_filter(r, &out);
}


static uint32_t njt_cache_quick_item_crc32(cache_api_t *api_data){
    uint32_t                                 crc32;

    njt_crc32_init(crc32);
    if(api_data->is_location_name_set){
        njt_crc32_update(&crc32, api_data->location_name.data, api_data->location_name.len);
    }

    if(api_data->is_backend_server_set){
        njt_crc32_update(&crc32, api_data->backend_server.data, api_data->backend_server.len);
    }

    njt_crc32_final(crc32);

    return crc32;
}


static njt_int_t njt_cache_quick_item_exist(uint32_t crc32,
            njt_http_cache_quick_main_conf_t *cqmf,
            njt_http_cache_resouce_metainfo_t **cache_info){
    njt_lvlhsh_query_t                      lhq;
    u_char                                  buff[50];
    u_char                                  *end;
    
    end = njt_snprintf(buff, 50, "%d", crc32);
    lhq.key.data = buff;
    lhq.key.len = end - buff;
    lhq.key_hash = njt_murmur_hash2(lhq.key.data, lhq.key.len);
    lhq.proto = &njt_http_cache_quick_lvlhsh_proto;
    lhq.pool = cqmf->cache_pool;

    if(NJT_OK == njt_lvlhsh_find(&cqmf->resource_to_metainfo, &lhq)){
        *cache_info = lhq.value;
        return NJT_OK;
    }

    return NJT_ERROR;
}


static njt_int_t njt_http_del_cache_item_from_lvlhash(uint32_t crc32,
        njt_http_cache_quick_main_conf_t *cqmf){
    njt_lvlhsh_query_t                      lhq;
    u_char                                  buff[50];
    u_char                                  *end;
    
    end = njt_snprintf(buff, 50, "%d", crc32);
    lhq.key.data = buff;
    lhq.key.len = end - buff;
    lhq.key_hash = njt_murmur_hash2(lhq.key.data, lhq.key.len);
    lhq.proto = &njt_http_cache_quick_lvlhsh_proto;
    lhq.pool = cqmf->cache_pool;

    return njt_lvlhsh_delete(&cqmf->resource_to_metainfo, &lhq);
}


static int njt_http_cache_quicky_add_dynloc_rpc_msg_handler(njt_dyn_rpc_res_t* res, njt_str_t *msg){
    njt_http_cache_resouce_metainfo_t   *cache_info;
    njt_int_t                           rc = NJT_OK;
    js2c_parse_error_t                  err_info;
    njt_pool_t                          *tmp_pool;
    njt_str_t                           tmp_str;
    rpc_result_t                        *rpc_res;

    cache_info = res->data;
    if(res->rc == RPC_RC_OK){
        tmp_pool = njt_create_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
        if(tmp_pool == NULL){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
                    " cache quick dyn loc result msg create pool error");

            njt_str_set(&tmp_str, "cache quick dyn loc result msg create pool error");
            njt_http_cache_quick_update_status_str(cache_info, CACHE_QUICK_STATUS_ERROR, &tmp_str);

            return NJT_ERROR;
        }

        rpc_res = json_parse_rpc_result(tmp_pool, msg, &err_info);
        if(rpc_res == NULL){
            njt_destroy_pool(tmp_pool);

            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
                    " cache quick dyn loc result msg parse error");

            njt_str_set(&tmp_str, "cache quick dyn loc result msg parse error");
            njt_http_cache_quick_update_status_str(cache_info, CACHE_QUICK_STATUS_ERROR, &tmp_str);

            return NJT_ERROR;
        }

        if(rpc_res->code != 0){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
                    " cache quick add dyn loc error:%V", &rpc_res->msg);

            njt_http_cache_quick_update_status_str(cache_info, CACHE_QUICK_STATUS_ERROR, &rpc_res->msg);

            njt_destroy_pool(tmp_pool);

            return NJT_ERROR;
        }else{
            njt_destroy_pool(tmp_pool);
            cache_info->status = CACHE_QUICK_STATUS_ADD_LOC_OK;

            njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, 
                    " cache quick add dyn loc ok, location:%V", &cache_info->location_name);

            njt_http_cache_quick_update_download_status_str(cache_info, CACHE_QUICK_STATUS_ADD_LOC_OK);

            //start download
            njt_http_cache_quick_download(cache_info);

            return NJT_OK;
        }
    }

    if(res->rc == RPC_RC_TIMEOUT){
        cache_info->status = CACHE_QUICK_STATUS_ERROR;

        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
                    " cache quick add dyn loc rpc timeout, location:%V", &cache_info->location_name);

        njt_str_set(&tmp_str, "cache quick add dyn loc rpc timeout");
        njt_http_cache_quick_update_status_str(cache_info, CACHE_QUICK_STATUS_ERROR, &tmp_str);

        return NJT_ERROR;
    }else{
        cache_info->status = CACHE_QUICK_STATUS_ERROR;

        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
                    " cache quick add dyn loc error, location:%V", &cache_info->location_name);

        njt_str_set(&tmp_str, "cache quick add dyn loc error");
        njt_http_cache_quick_update_status_str(cache_info, CACHE_QUICK_STATUS_ERROR, &tmp_str);

        return NJT_ERROR;
    }

    return rc;
}


static int njt_http_cache_quicky_del_dynloc_rpc_msg_handler(njt_dyn_rpc_res_t* res, njt_str_t *msg){
    njt_int_t                           rc = NJT_OK;
    js2c_parse_error_t                  err_info;
    njt_pool_t                          *tmp_pool;
    rpc_result_t                        *rpc_res;
    njt_http_cache_resouce_metainfo_t   *cache_info;
    njt_http_cache_quick_main_conf_t    *cqmf;


    //real delete
    cache_info = res->data;

    cqmf = (njt_http_cache_quick_main_conf_t *)njt_get_conf(njt_cycle->conf_ctx, njt_http_cache_quick_module);   
    if(cqmf != NULL){
        //first delete from lvlhash
        if(NJT_OK != njt_http_del_cache_item_from_lvlhash(cache_info->crc32, cqmf)){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
                " del cache info from lvlhash error");
        }else if(NJT_OK != njt_http_del_cache_item_from_queue(cqmf, cache_info)){
            //delete from queue
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
                " del cache info from queue error");
        }else{
            //kv_set refresh
            njt_http_cache_quick_save(cqmf);
        }
    }

    if(res->rc == RPC_RC_OK){
        tmp_pool = njt_create_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
        if(tmp_pool == NULL){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
                " cache quick del dyn loc create pool error");

            return NJT_ERROR;
        }

        rpc_res = json_parse_rpc_result(tmp_pool, msg, &err_info);
        if(rpc_res == NULL){
            njt_destroy_pool(tmp_pool);
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
                " cache quick dyn loc result msg parse error");

            return NJT_ERROR;
        }

        if(rpc_res->code != 0){
            njt_destroy_pool(tmp_pool);
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
                " cache quick del dyn loc error");

            return NJT_ERROR;
        }else{
            njt_destroy_pool(tmp_pool);
            njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, 
                    " cache quick del dyn loc success");

            return NJT_OK;
        }
    }

    if(res->rc == RPC_RC_TIMEOUT){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
                " cache quick del dyn loc rpc timeout");

        return NJT_ERROR;
    }

    return rc;
}



static njt_int_t njt_http_cache_item_add_dyn_location(
        njt_http_cache_resouce_metainfo_t *cache_info, njt_http_cache_quick_main_conf_t *cqmf){
    njt_int_t                       rc = NJT_OK;
    cache_add_dyn_location_t        dyn_location;
    njt_pool_t                      *pool = NULL;
    njt_str_t                       tmp_str;
    njt_str_t                       *msg;
    uint32_t                        crc32;
    u_char                          buf[100];
    u_char                          *p;
    njt_str_t                       topic_name;
    cache_add_dyn_location_locations_item_t *dyn_loc_item;


    pool = njt_create_pool(njt_pagesize, njt_cycle->log);
    if (pool == NULL)
    {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, " cache quick create dyn loc pool error");
        
        njt_str_set(&tmp_str, "cache quick create dyn loc pool error");
        njt_http_cache_quick_update_status_str(cache_info, CACHE_QUICK_STATUS_ERROR, &tmp_str);
        
        return NJT_ERROR;
    }

    //create dyn location structure and get json str
    set_cache_add_dyn_location_type(&dyn_location, CACHE_ADD_DYN_LOCATION_TYPE_ADD);
    set_cache_add_dyn_location_addr_port(&dyn_location, &cache_info->addr_port);
    set_cache_add_dyn_location_server_name(&dyn_location, &cache_info->server_name);
    set_cache_add_dyn_location_locations(&dyn_location, create_cache_add_dyn_location_locations(pool, 1));
    if(dyn_location.locations == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, " cache quick create dyn loc locations error");

        njt_str_set(&tmp_str, "cache quick create dyn loc locations error");
        njt_http_cache_quick_update_status_str(cache_info, CACHE_QUICK_STATUS_ERROR, &tmp_str);

        rc = NJT_ERROR;
        goto add_dyn_loc_out;
    }

    dyn_loc_item = create_cache_add_dyn_location_locations_item(pool);
    if(dyn_loc_item == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, " cache quick create dyn loc item error");
        
        njt_str_set(&tmp_str, "cache quick create dyn loc item error");
        njt_http_cache_quick_update_status_str(cache_info, CACHE_QUICK_STATUS_ERROR, &tmp_str);

        rc = NJT_ERROR;
        goto add_dyn_loc_out;
    }

    set_cache_add_dyn_location_locations_item_location_rule(dyn_loc_item, &cache_info->location_rule);
    set_cache_add_dyn_location_locations_item_location_name(dyn_loc_item, &cache_info->location_name);
    set_cache_add_dyn_location_locations_item_location_body(dyn_loc_item, &cache_info->location_body);
    set_cache_add_dyn_location_locations_item_proxy_pass(dyn_loc_item, &cache_info->proxy_pass);

    add_item_cache_add_dyn_location_locations(dyn_location.locations, dyn_loc_item);

    msg = to_json_cache_add_dyn_location(pool, &dyn_location, OMIT_NULL_ARRAY | OMIT_NULL_OBJ | OMIT_NULL_STR);
    if(msg == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, " cache quick location json parse error");
        
        njt_str_set(&tmp_str, "cache quick location json parse error");
        njt_http_cache_quick_update_status_str(cache_info, CACHE_QUICK_STATUS_ERROR, &tmp_str);

        rc = NJT_ERROR;
        goto add_dyn_loc_out;
    }

	njt_crc32_init(crc32);
	njt_crc32_update(&crc32, cache_info->addr_port.data, cache_info->addr_port.len);
	if (cache_info->server_name.len > 0) {
		njt_crc32_update(&crc32, cache_info->server_name.data, cache_info->server_name.len);
	}
	if (cache_info->location_rule.len > 0) {
		njt_crc32_update(&crc32, cache_info->location_rule.data, cache_info->location_rule.len);
	}

	njt_crc32_update(&crc32, cache_info->location_name.data, cache_info->location_name.len);
	njt_crc32_final(crc32);

    topic_name.data = buf;
    p = njt_snprintf(buf, 100, "/worker_a/ins/loc/l_%ui", crc32);
    topic_name.len = p - buf;

    njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, 
        " cache quick add dyn location, topic:%V  msg:%V", &topic_name, msg);
    
    //call njt_rpc_send to add dyn location
    njt_dyn_rpc(&topic_name, msg, 0, 0, njt_http_cache_quicky_add_dynloc_rpc_msg_handler, cache_info);

add_dyn_loc_out:
    if (pool != NULL)
    {
        njt_destroy_pool(pool);
    }

    return rc;
}


static njt_int_t njt_http_cache_item_del_dyn_location(njt_http_cache_resouce_metainfo_t *cache_info,
            njt_http_cache_quick_main_conf_t *cqmf){
    uint32_t                        crc32;
    u_char                          buf[100];
    u_char                          *p;
    njt_str_t                       topic_name;
    njt_int_t                       rc = NJT_OK;
    njt_pool_t                      *pool;
    cache_del_dyn_location_t        dyn_location;
    njt_str_t                       tmp_str;
    njt_str_t                       *msg;


    pool = njt_create_pool(njt_pagesize, njt_cycle->log);
    if (pool == NULL)
    {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, " cache quick create del dyn loc pool error");
        
        njt_str_set(&tmp_str, "cache quick create del dyn loc pool error");
        njt_http_cache_quick_update_status_str(cache_info, CACHE_QUICK_STATUS_ERROR, &tmp_str);

        return NJT_ERROR;
    }

    //create dyn location structure and get json str
    set_cache_del_dyn_location_type(&dyn_location, CACHE_DEL_DYN_LOCATION_TYPE_DEL);
    set_cache_del_dyn_location_addr_port(&dyn_location, &cache_info->addr_port);
    set_cache_del_dyn_location_server_name(&dyn_location, &cache_info->server_name);
    set_cache_del_dyn_location_location_rule(&dyn_location, &cache_info->location_rule);
    set_cache_del_dyn_location_location_name(&dyn_location, &cache_info->location_name);

    msg = to_json_cache_del_dyn_location(pool, &dyn_location, OMIT_NULL_ARRAY | OMIT_NULL_OBJ | OMIT_NULL_STR);
    if(msg == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, " cache quick del location json parse error");
        
        njt_str_set(&tmp_str, "cache quick del location json parse error");
        njt_http_cache_quick_update_status_str(cache_info, CACHE_QUICK_STATUS_ERROR, &tmp_str);

        rc = NJT_ERROR;
        goto del_dyn_loc_out;
    }

	njt_crc32_init(crc32);
	njt_crc32_update(&crc32, cache_info->addr_port.data, cache_info->addr_port.len);
	if (cache_info->server_name.len > 0) {
	}
		njt_crc32_update(&crc32, cache_info->server_name.data, cache_info->server_name.len);
	if (cache_info->location_rule.len > 0) {
		njt_crc32_update(&crc32, cache_info->location_rule.data, cache_info->location_rule.len);
	}

	njt_crc32_update(&crc32, cache_info->location_name.data, cache_info->location_name.len);
	njt_crc32_final(crc32);

    topic_name.data = buf;
    p = njt_snprintf(buf, 100, "/worker_a/ins/loc/l_%ui", crc32);
    topic_name.len = p - buf;

    njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, 
        " cache quick del dyn location, topic:%V  json:%V", &topic_name, msg);

    //call njt_rpc_send to add dyn location
    njt_dyn_rpc(&topic_name, msg, 0, 0, njt_http_cache_quicky_del_dynloc_rpc_msg_handler, cache_info);

del_dyn_loc_out:
    if (pool != NULL)
    {
        njt_destroy_pool(pool);
    }


    return rc;
}



static njt_int_t njt_http_add_cache_item_to_lvlhash(uint32_t crc32,
        njt_http_cache_resouce_metainfo_t *cache_info, njt_http_cache_quick_main_conf_t *cqmf){
    njt_lvlhsh_query_t                      lhq;
    u_char                                  buff[50];
    u_char                                  *end;
    
    end = njt_snprintf(buff, 50, "%d", crc32);
    lhq.key.data = buff;
    lhq.key.len = end - buff;

    //update cache item crc32 info
    cache_info->crc32 = crc32;
    cache_info->crc32_str.data = njt_pstrdup(cache_info->item_pool, &lhq.key);
    cache_info->crc32_str.len = lhq.key.len;

    lhq.key_hash = njt_murmur_hash2(lhq.key.data, lhq.key.len);
    lhq.proto = &njt_http_cache_quick_lvlhsh_proto;
    lhq.pool = cqmf->cache_pool;
    lhq.value = cache_info;

    return njt_lvlhsh_insert(&cqmf->resource_to_metainfo, &lhq);
}


static njt_int_t njt_http_del_cache_item_from_queue(
            njt_http_cache_quick_main_conf_t *cqmf, njt_http_cache_resouce_metainfo_t   *cache_info){

    njt_queue_remove(&cache_info->cache_item);

    //free memory
    if(cache_info->item_pool != NULL){
        if(cache_info->download_timer.timer_set){
            njt_del_timer(&cache_info->download_timer);
        }

        njt_destroy_pool(cache_info->item_pool);
    }

    return NJT_OK;
}


static njt_http_cache_resouce_metainfo_t *njt_http_add_cache_item_to_queue(
            njt_http_cache_quick_main_conf_t *cqmf, cache_api_t *api_data){
    njt_http_cache_resouce_metainfo_t       *cache_info;
    njt_pool_t                              *item_pool;


    item_pool = njt_create_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
    if (item_pool == NULL || NJT_OK != njt_sub_pool(njt_cycle->pool, item_pool)) {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "create pool error in function %s", __func__);
        return NULL;
    }

    cache_info = njt_pcalloc(item_pool, sizeof(njt_http_cache_resouce_metainfo_t));
    if(cache_info == NULL){
        return NULL;
    }

    if(api_data->backend_server.len >= 5 && 0 == njt_strncmp(api_data->backend_server.data, "https", 5)){
        cache_info->ssl_type = CACHE_QUICK_SERVER_SSL_TYPE_SSL;
    }else{
        cache_info->ssl_type = CACHE_QUICK_SERVER_SSL_TYPE_NONE;
    }

    cache_info->item_pool = item_pool;
    if(CACHE_QUICK_SERVER_SSL_TYPE_NONE == cache_info->ssl_type){
        njt_str_set(&cache_info->addr_port, NJT_HTTP_CACHE_QUICK_HTTP_SERVER);
    }else{
        njt_str_set(&cache_info->addr_port, NJT_HTTP_CACHE_QUICK_HTTPS_SERVER);
    }

    if(api_data->is_location_name_set){
        cache_info->location_name.data = njt_pstrdup(item_pool, &api_data->location_name);
        cache_info->location_name.len = api_data->location_name.len;
    }

    njt_str_set(&cache_info->location_body, NJT_HTTP_CACHE_QUICK_BODY);

    if(api_data->is_backend_server_set){
        cache_info->proxy_pass.data = njt_pstrdup(item_pool, &api_data->backend_server);
        cache_info->proxy_pass.len = api_data->backend_server.len;
    }

    njt_queue_insert_tail(&cqmf->caches, &cache_info->cache_item);

    njt_http_cache_quick_update_download_status_str(cache_info, CACHE_QUICK_STATUS_INIT);

    return cache_info;
}


static void njt_http_cache_quick_flush_confs(njt_http_cache_quick_main_conf_t *cqmf) {
    njt_pool_t  *pool;
    njt_str_t   *msg;
    njt_str_t   key = njt_string(HTTP_CACHE_QUICK_CONFS);

    pool = njt_create_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
    if (pool == NULL) {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, 
            " cache quick create pool error in function %s", __func__);
        return;
    }

    msg = njt_http_caches_to_json(pool, cqmf);
    if (msg == NULL || msg->len == 0) {
        goto end;
    }

    njt_dyn_kv_set(&key, msg);

    end:
    njt_destroy_pool(pool);
}

static void
njt_http_cache_quick_update_download_status_str(njt_http_cache_resouce_metainfo_t  *cache_info,
        cache_quick_status_t status){
    njt_str_t           tmp_str;
    njt_http_cache_quick_main_conf_t   *cqmf;

    cache_info->status = status;
    switch(cache_info->status)
    {
    case CACHE_QUICK_STATUS_INIT:
        njt_str_set(&tmp_str, "init status");
        cache_info->op_status = CACHE_QUICK_OP_STATUS_DONE;
        break;
    case CACHE_QUICK_STATUS_ADD_LOC_OK:
        njt_str_set(&tmp_str, "add dyn location ok");
        break;
    case CACHE_QUICK_STATUS_OK:
        if(cache_info->resource_size == cache_info->current_size){
            njt_str_set(&tmp_str, "download ok");
            cache_info->op_status = CACHE_QUICK_OP_STATUS_DONE;
        }else{
            njt_str_set(&tmp_str, "has error, please check error log file");
            cache_info->op_status = CACHE_QUICK_OP_STATUS_DONE;
        }
        break;
    case CACHE_QUICK_STATUS_DOWNLOAD_ING:
        njt_str_set(&tmp_str, "downloading");
        break;
    case CACHE_QUICK_STATUS_DOWNLOAD_ERROR:
        njt_str_set(&tmp_str, "download error, return not 200");
        cache_info->op_status = CACHE_QUICK_OP_STATUS_DONE;
        break;
    case CACHE_QUICK_STATUS_ERROR:
        njt_str_set(&tmp_str, "has error");
        cache_info->op_status = CACHE_QUICK_OP_STATUS_DONE;
        break;
    default:
        njt_str_set(&tmp_str, "init status");
        break;
    }

    cache_info->status_str.data = njt_pstrdup(cache_info->item_pool, &tmp_str);
    cache_info->status_str.len = tmp_str.len;

    //need flush kv set
    //kv_set refresh
    cqmf = (njt_http_cache_quick_main_conf_t *)njt_get_conf(njt_cycle->conf_ctx, njt_http_cache_quick_module);   
    if(cqmf != NULL){
        njt_http_cache_quick_save(cqmf);
    }
}


static void
njt_http_cache_quick_update_status_str(njt_http_cache_resouce_metainfo_t  *cache_info,
        cache_quick_status_t status, njt_str_t *tmp_str){
    njt_http_cache_quick_main_conf_t   *cqmf;

    cache_info->status = status;
    cache_info->status_str.data = njt_pstrdup(cache_info->item_pool, tmp_str);
    cache_info->status_str.len = tmp_str->len;

    cache_info->op_status = CACHE_QUICK_OP_STATUS_DONE;

    //need flush kv set
    //kv_set refresh
    cqmf = (njt_http_cache_quick_main_conf_t *)njt_get_conf(njt_cycle->conf_ctx, njt_http_cache_quick_module);   
    if(cqmf != NULL){
        njt_http_cache_quick_save(cqmf);
    }
}


void njt_http_cache_quick_start_success_handler(void *data){
    njt_http_cache_resouce_metainfo_t *cache_info = (njt_http_cache_resouce_metainfo_t *)data;

    njt_http_cache_quick_update_download_status_str(cache_info, CACHE_QUICK_STATUS_DOWNLOAD_ING);
}

void njt_http_cache_quick_parse_line(void *data, njt_int_t rc){
    njt_http_cache_resouce_metainfo_t *cache_info = (njt_http_cache_resouce_metainfo_t *)data;

    switch (rc)
    {
        case NJT_ERROR:
            /*log the case and update the peer status.*/
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "read line action error for cache_quick");
            njt_http_cache_quick_update_download_status(cache_info, CACHE_QUICK_STATUS_ERROR);
            return;
        case NJT_DONE:
            njt_http_cache_quick_update_download_status(cache_info, CACHE_QUICK_STATUS_ERROR);
            return;
        case NJT_ABORT:
            njt_http_cache_quick_update_download_status(cache_info, CACHE_QUICK_STATUS_DOWNLOAD_ERROR);
            return;
        default:
            break;
    }
}


void njt_http_cache_quick_parse_header(void *data, njt_int_t rc){
    njt_http_cache_resouce_metainfo_t *cache_info = (njt_http_cache_resouce_metainfo_t *)data;

    switch (rc)
    {
        case NJT_ERROR:
            /*log the case and update the peer status.*/
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "read header action error for cache_quick");
            njt_http_cache_quick_update_download_status(cache_info, CACHE_QUICK_STATUS_ERROR);
            return;
        case NJT_DONE:
            njt_http_cache_quick_update_download_status(cache_info, CACHE_QUICK_STATUS_OK);
            return;
        case NJT_ABORT:
            njt_http_cache_quick_update_download_status(cache_info, CACHE_QUICK_STATUS_DOWNLOAD_ERROR);
            return;
        default:
            break;
    }
}


void njt_http_cache_quick_parse_body(void *data, njt_int_t rc){
    njt_http_cache_resouce_metainfo_t *cache_info = (njt_http_cache_resouce_metainfo_t *)data;

    switch (rc)
    {
        case NJT_ERROR:
            /*log the case and update the peer status.*/
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "read body action error for cache_quick");
            njt_http_cache_quick_update_download_status(cache_info, CACHE_QUICK_STATUS_ERROR);
            return;
        case NJT_DONE:
            njt_http_cache_quick_update_download_status(cache_info, CACHE_QUICK_STATUS_OK);
            return;
        case NJT_ABORT:
            njt_http_cache_quick_update_download_status(cache_info, CACHE_QUICK_STATUS_DOWNLOAD_ERROR);
            return;
        default:
            break;
    }
}


void njt_http_cache_quick_write_timeout_handler(void *data){
    njt_http_cache_resouce_metainfo_t *cache_info = (njt_http_cache_resouce_metainfo_t *)data;
    njt_http_cache_quick_update_download_status(cache_info, CACHE_QUICK_STATUS_ERROR);
}


void njt_http_cache_quick_read_timeout_handler(void *data){
    njt_http_cache_resouce_metainfo_t *cache_info = (njt_http_cache_resouce_metainfo_t *)data;
    njt_http_cache_quick_update_download_status(cache_info, CACHE_QUICK_STATUS_ERROR);
}


void njt_http_cache_quick_read_event_result(void *data, njt_int_t rc){
    njt_http_cache_resouce_metainfo_t *cache_info = (njt_http_cache_resouce_metainfo_t *)data;

    switch (rc)
    {
        case NJT_ERROR:
            /*log the case and update the peer status.*/
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "read action error for cache_quick");
            njt_http_cache_quick_update_download_status(cache_info, CACHE_QUICK_STATUS_ERROR);
            return;
        case NJT_ABORT:
            njt_http_cache_quick_update_download_status(cache_info, CACHE_QUICK_STATUS_DOWNLOAD_ERROR);
            return;
        default:
            break;
    }
}

void njt_http_cache_quick_update_download_status(njt_http_cache_resouce_metainfo_t  *cache_info, cache_quick_status_t status){
    njt_http_cache_quick_update_download_status_str(cache_info, status);
    cache_info->client_util = NULL;
}

//每一次write事件调用处理，rc为每次调用write事件的返回值，可供使用者状态更新
//NJT_ERROR： read调用出错，错误结束
//NJT_DONE： http请求处理完成，正常结束
//NJT_OK: http请求处理完成，正常结束
//其他，继续write事件循环
void njt_http_cache_quick_write_event_result(void *data, njt_int_t rc){
    njt_http_cache_resouce_metainfo_t *cache_info = (njt_http_cache_resouce_metainfo_t *)data;

    if(rc == NJT_ERROR){
        njt_http_cache_quick_update_download_status(cache_info, CACHE_QUICK_STATUS_ERROR);
    }
}


void njt_http_cache_quick_parse_header_data(void *data, njt_table_elt_t *h){
    njt_http_cache_resouce_metainfo_t *cache_info = (njt_http_cache_resouce_metainfo_t *)data;

    //get content length header
    if (h->key.len == njt_strlen("Content-Length")
        && njt_strncasecmp(h->key.data, (u_char *) "Content-Length",
                            h->key.len) == 0) {
        cache_info->resource_size = njt_atoof(h->value.data, h->value.len);
    }
}


void njt_http_cache_quick_parse_body_data(void *data, u_char *start, u_char *end){
    // njt_lvlhsh_query_t                  lhq;
    size_t                              n;

    njt_http_cache_resouce_metainfo_t *cache_info = (njt_http_cache_resouce_metainfo_t *)data;

    n = end - start;
    cache_info->current_size += n;
    cache_info->download_ratio = (cache_info->current_size * 1.0) / (cache_info->resource_size * 1.0) * 100;

    return;    
}

void njt_http_cache_quick_ssl_handshake_success_handler(void *data){
    njt_http_cache_resouce_metainfo_t *cache_info = (njt_http_cache_resouce_metainfo_t *)data;
    njt_http_cache_quick_update_download_status_str(cache_info, CACHE_QUICK_STATUS_DOWNLOAD_ING);
}


void njt_http_cache_quick_ssl_handshake_fail_handler(void *data){
    njt_http_cache_resouce_metainfo_t *cache_info = (njt_http_cache_resouce_metainfo_t *)data;
    njt_http_cache_quick_update_download_status(cache_info, CACHE_QUICK_STATUS_ERROR);
}



static void njt_http_cache_quick_download_timer_handler(njt_event_t *ev)
{
    njt_http_cache_resouce_metainfo_t   *cache_info;
    njt_str_t                           tmp_str;
    njt_http_client_util_t              *client_util;
    njt_str_t                           post_data;
    u_char                              url_buffer[1024];
    njt_str_t                           url;
    u_char                              *last;


    cache_info = ev->data;
    
    if(ev->timer_set){
        njt_del_timer(ev);
        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0,
                      " cache quick del timer ");
    }

    if (njt_quit || njt_terminate || njt_exiting) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
            " cache quick download for quiting, url:%V", &cache_info->addr_port);

        return;
    }

    //create client util
    njt_str_null(&post_data);
    if(CACHE_QUICK_SERVER_SSL_TYPE_SSL == cache_info->ssl_type){
        last = njt_snprintf(url_buffer, 1024, "https://%V%V", &cache_info->addr_port, &cache_info->location_name);
    }else{
        last = njt_snprintf(url_buffer, 1024, "http://%V%V", &cache_info->addr_port, &cache_info->location_name);
    }
    
    url.data = url_buffer;
    url.len = last - url_buffer;

    client_util = njt_http_client_util_create(NJT_HTTP_CLIENT_UTIL_METHOD_GET, url, post_data, cache_info);
    if (client_util == NULL) {
        njt_str_set(&tmp_str, "cache quick download create client util error");
        njt_http_cache_quick_update_status_str(cache_info, CACHE_QUICK_STATUS_ERROR, &tmp_str);

        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        " cache quick download create client util error, url:%V", &cache_info->addr_port);
        return;
    }
    
    cache_info->client_util = client_util;
    
    client_util->start_success_handler = njt_http_cache_quick_start_success_handler;
    client_util->read_timeout_handler = njt_http_cache_quick_read_timeout_handler;
    client_util->write_timeout_handler = njt_http_cache_quick_write_timeout_handler;
    client_util->ssl_handshake_success_handler = njt_http_cache_quick_ssl_handshake_success_handler;
    client_util->ssl_handshake_fail_handler = njt_http_cache_quick_ssl_handshake_fail_handler;
    client_util->read_event_result_handler = njt_http_cache_quick_read_event_result;
    client_util->write_event_result_handler = njt_http_cache_quick_write_event_result;
    client_util->parse_line_handler = njt_http_cache_quick_parse_line;
    client_util->parse_header_handler = njt_http_cache_quick_parse_header;
    client_util->parse_header_data_handler = njt_http_cache_quick_parse_header_data;
    client_util->parse_body_handler = njt_http_cache_quick_parse_body;
    client_util->parse_body_data_handler = njt_http_cache_quick_parse_body_data;

    if(NJT_OK != njt_http_client_util_start(client_util)){
        njt_str_set(&tmp_str, "cache quick download client util start error");
        njt_http_cache_quick_update_status_str(cache_info, CACHE_QUICK_STATUS_ERROR, &tmp_str);

        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        " cache quick download client util start error, url:%V", &cache_info->addr_port);
        return;
    }
}


static njt_int_t njt_http_cache_quick_download(njt_http_cache_resouce_metainfo_t *cache_info) {
    njt_event_t                     *download_timer;

    download_timer = &cache_info->download_timer;
    download_timer->handler = njt_http_cache_quick_download_timer_handler;
    download_timer->log = njt_cycle->log;
    download_timer->data = cache_info;
    download_timer->cancelable = 1;

    njt_add_timer(download_timer, 1000);

    return NJT_OK;
}


static void njt_http_cache_quick_save(njt_http_cache_quick_main_conf_t *cqmf) {
    njt_http_cache_quick_flush_confs(cqmf);

    return;
}


static njt_int_t njt_cache_quick_download_status(njt_http_cache_quick_main_conf_t *cqmf,
        cache_api_t *api_data, njt_rpc_result_t*rpc_result) {
    njt_http_cache_resouce_metainfo_t       *cache_info;
    uint32_t                                 crc32;
    njt_lvlhsh_query_t                      lhq;
    u_char                                  buff[50];
    u_char                                  *end;
    njt_str_t                               tmp_str;


    //del item from local, queue and lvlhash
    crc32 = njt_cache_quick_item_crc32(api_data);
    
    end = njt_snprintf(buff, 50, "%d", crc32);
    lhq.key.data = buff;
    lhq.key.len = end - buff;
    lhq.key_hash = njt_murmur_hash2(lhq.key.data, lhq.key.len);
    lhq.proto = &njt_http_cache_quick_lvlhsh_proto;
    lhq.pool = cqmf->cache_pool;

    if(NJT_OK != njt_lvlhsh_find(&cqmf->resource_to_metainfo, &lhq)){
        if(api_data->is_location_name_set){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
                " cache quick item:%V is not exist", &api_data->location_name);
        }

        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
        njt_rpc_result_set_msg(rpc_result, (u_char *)"cache quick item is not exist");

        return NJT_ERROR;  
    }

    cache_info = lhq.value;
    if(cache_info->status != CACHE_QUICK_STATUS_ERROR){
        end = njt_snprintf(buff, 50, DOWNLOAD_STATUS_INFO, cache_info->download_ratio);
        tmp_str.data = buff;
        tmp_str.len = end - buff;
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_SUCCESS);
        njt_rpc_result_set_msg2(rpc_result, &tmp_str);
    }else{
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" downlodd error");

        return NJT_ERROR; 
    }
    
    return NJT_OK;
}



static njt_int_t njt_cache_quick_del_item(njt_http_cache_quick_main_conf_t *cqmf,
        cache_api_t *api_data, njt_rpc_result_t *rpc_result) {
    uint32_t                                 crc32;
    njt_http_cache_resouce_metainfo_t       *cache_info;

    //del item from local, queue and lvlhash
    crc32 = njt_cache_quick_item_crc32(api_data);

    //find from lvlhash
    if(NJT_OK != njt_cache_quick_item_exist(crc32, cqmf, &cache_info)){
        if(api_data->is_location_name_set){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
                " cache quick item:%V is not exist", &api_data->location_name);
        }

        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_INPUT_PARAM);
        njt_rpc_result_set_msg(rpc_result, (u_char *)"cache quick item is not exist");

        return NJT_ERROR;
    }

    //check wether is download
    if(cache_info->client_util != NULL){
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_INPUT_PARAM);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" downloading, please delete a moment later");

        return NJT_ERROR;
    }


    if(CACHE_QUICK_OP_STATUS_ADDING == cache_info->op_status){
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_INPUT_PARAM);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" last add operator is adding, please delete a moment later");

        return NJT_ERROR;
    }


    if(CACHE_QUICK_OP_STATUS_DELING == cache_info->op_status){
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_INPUT_PARAM);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" last del operator is deleting, please delete a moment later");

        return NJT_ERROR;
    }

    cache_info->op_status = CACHE_QUICK_OP_STATUS_DELING;

    //del dyn locaton
    if(NJT_OK != njt_http_cache_item_del_dyn_location(cache_info, cqmf)){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
            " cache quick del dyn location error");

        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
        njt_rpc_result_set_msg(rpc_result, (u_char *)"cache quick del dyn location error");

        // return NJT_ERROR;
    }

    //todo purge cache info
    
    return NJT_OK;
}


static njt_int_t njt_cache_quick_add_item(njt_http_cache_quick_main_conf_t *cqmf,
            cache_api_t *api_data, njt_rpc_result_t*rpc_result) {
    njt_http_cache_resouce_metainfo_t       *cache_info;
    uint32_t                                 crc32;
    njt_str_t                                tmp_str;


    //add item to local, queue and lvlhash
    crc32 = njt_cache_quick_item_crc32(api_data);

    //find from lvlhash
    if(NJT_OK == njt_cache_quick_item_exist(crc32, cqmf, &cache_info)){
        if(api_data->is_location_name_set){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
                " cache quick item:%V is already exist(please delete first) or maybe last delete action is deleteing",
                &api_data->location_name);
        }

        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_INPUT_PARAM);
        njt_rpc_result_set_msg(rpc_result, (u_char *)"cache quick item is already exist");

        return NJT_ERROR;
    }
    
    //insert queue
    cache_info = njt_http_add_cache_item_to_queue(cqmf, api_data);
    if(cache_info == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
            " malloc cache info error");

        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_MEM_ALLOC);
        njt_rpc_result_set_msg(rpc_result, (u_char *)"malloc cache info error");

        return NJT_ERROR;
    }

    //insert lvlhash
    if(NJT_OK != njt_http_add_cache_item_to_lvlhash(crc32, cache_info, cqmf)){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
            " add cache info to lvlhash error");

        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
        njt_rpc_result_set_msg(rpc_result, (u_char *)"add cache info to lvlhash error");

        return NJT_ERROR;  
    }

    cache_info->op_status = CACHE_QUICK_OP_STATUS_ADDING;

    //kv_set save
    njt_http_cache_quick_save(cqmf);

    //add dyn locaton
    if(NJT_OK != njt_http_cache_item_add_dyn_location(cache_info, cqmf)){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
            " cache quick add dyn location error");

        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
        njt_rpc_result_set_msg(rpc_result, (u_char *)"cache quick add dyn location error");
        
        njt_str_set(&tmp_str, "cache quick add dyn location error");
        njt_http_cache_quick_update_status_str(cache_info, CACHE_QUICK_STATUS_ERROR, &tmp_str);

        return NJT_ERROR;
    }

    
    return NJT_OK;
}


static njt_int_t njt_http_cache_quick_conf_out_handler(
            njt_http_request_t *r, njt_rpc_result_t *rpc_result) {
    njt_buf_t       *buf;
    njt_chain_t     out;
    njt_int_t       rc;
    njt_str_t       tmp_str;

    switch (rpc_result->code) {
        case NJT_RPC_RSP_SUCCESS:
            r->headers_out.status = NJT_HTTP_OK;
            break;
        case NJT_RPC_RSP_ERR_MEM_ALLOC:
        case NJT_RPC_RSP_ERR:
            r->headers_out.status = NJT_HTTP_INTERNAL_SERVER_ERROR;
            break;
        case NJT_RPC_RSP_ERR_JSON:
            r->headers_out.status = NJT_HTTP_BAD_REQUEST;
            break;
        default:
            r->headers_out.status = NJT_HTTP_INTERNAL_SERVER_ERROR;
            break;
    }

    njt_rpc_result_to_json_str(rpc_result, &tmp_str);
    buf = njt_create_temp_buf(r->pool, tmp_str.len);
    if (buf == NULL) {
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "could not alloc buffer in function %s", __func__);
        return NJT_ERROR;
    }

    njt_memcpy(buf->last, tmp_str.data, tmp_str.len);
    buf->last += tmp_str.len;

    njt_str_t type = njt_string("application/json");
    r->headers_out.content_type = type;
    r->headers_out.content_length_n = buf->last - buf->pos;
    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }
    rc = njt_http_send_header(r);

    // r->header_only  when method is HEAD ,header_only is set.
    if (rc == NJT_ERROR || rc > NJT_OK) {
        return rc;
    }

    buf->last_buf = 1;
    out.buf = buf;
    out.next = NULL;
    return njt_http_output_filter(r, &out);
}


static void njt_http_cache_quick_api_read_data(njt_http_request_t *r){
    njt_str_t                   json_str;
    njt_chain_t                 *body_chain, *tmp_chain;
    njt_int_t                   rc = NJT_OK;
    cache_api_t                 *api_data = NULL;
    njt_uint_t                  len, size;
    js2c_parse_error_t          err_info;
    njt_rpc_result_t            *rpc_result = NULL;
    njt_http_cache_quick_main_conf_t *cqmf;


    rpc_result = njt_rpc_result_create();
    if(!rpc_result){
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, 
                " cache quick create rpc_result error");
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" cache quick create rpc_result error");

        rc = NJT_ERROR;
        goto end;
    }

    njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_SUCCESS);

    body_chain = r->request_body->bufs;
    /*check the sanity of the json body*/
    if(NULL == body_chain){
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, 
                " cache quick input body error");
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" input body error");

        rc = NJT_ERROR;
        goto out;
    }

    len = 0;
    tmp_chain = body_chain;
    while (tmp_chain != NULL) {
        len += tmp_chain->buf->last - tmp_chain->buf->pos;
        tmp_chain = tmp_chain->next;
    }

    json_str.len = len;
    json_str.data = njt_pcalloc(r->pool, len);
    if (json_str.data == NULL) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, 
                " cache quick malloc error");
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_MEM_ALLOC);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" malloc error");

        rc = NJT_ERROR;
        goto out;
    }

    len = 0;
    tmp_chain = r->request_body->bufs;
    while (tmp_chain != NULL) {
        size = tmp_chain->buf->last - tmp_chain->buf->pos;
        njt_memcpy(json_str.data + len, tmp_chain->buf->pos, size);
        tmp_chain = tmp_chain->next;
        len += size;
    }

    api_data = json_parse_cache_api(r->pool, &json_str, &err_info);
    if(api_data == NULL){
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, 
            " cache quick json parse error:%V json:%V", &err_info.err_str, &json_str);

        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_JSON);
        njt_rpc_result_set_msg2(rpc_result, &err_info.err_str);

        rc = NJT_ERROR;
        goto out;
    }

    njt_http_set_ctx(r, api_data, njt_http_cache_quick_module);
    cqmf = (njt_http_cache_quick_main_conf_t *)njt_get_conf(njt_cycle->conf_ctx, njt_http_cache_quick_module);   
    if(cqmf == NULL){
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" module main config is null");

        rc = NJT_ERROR;
        goto out;
    }

    if(!api_data->is_location_name_set || api_data->location_name.len < 1){
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" location_name should set and not empty");

        rc = NJT_ERROR;
        goto out;
    }

    if(!api_data->is_backend_server_set || api_data->backend_server.len < 1){
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" backend_server should set and not empty");

        rc = NJT_ERROR;
        goto out;
    }    

    switch (api_data->type)
    {
    case CACHE_API_TYPE_ADD:
        rc = njt_cache_quick_add_item(cqmf, api_data, rpc_result);
        if (rc == NJT_OK) {
            goto out;
        }
        break;
    
    case CACHE_API_TYPE_DEL:
        rc = njt_cache_quick_del_item(cqmf, api_data, rpc_result);
        if (rc == NJT_OK) {
            goto out;
        }
        break;
    
    case CACHE_API_TYPE_DOWNLOAD_STATUS:
        rc = njt_cache_quick_download_status(cqmf, api_data, rpc_result);
        if (rc == NJT_OK) {
            goto out;
        }
        break;

    default:
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
            " cache put type error:%d", api_data->type);

        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_JSON);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" cache put type error");

        rc = NJT_ERROR;
        goto out;
    }

out:
    rc = njt_http_cache_quick_conf_out_handler(r, rpc_result);

end:
    if(rpc_result){
        njt_rpc_result_destroy(rpc_result);
        rpc_result = NULL;
    }
    njt_http_finalize_request(r, rc);
}


static njt_int_t
njt_http_cache_quick_handler(njt_http_request_t *r) {
    njt_int_t                       rc = NJT_OK;
    njt_http_cache_quick_main_conf_t *cqmf;
    njt_rpc_result_t                *rpc_result = NULL;

    cqmf = (njt_http_cache_quick_main_conf_t *)njt_get_conf(njt_cycle->conf_ctx, njt_http_cache_quick_module);   
    if(cqmf == NULL){
        return NJT_DECLINED;
    }

    rpc_result = njt_rpc_result_create();
    if(!rpc_result){
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, 
                " cache quick create rpc_result error");
        return NJT_ERROR;
    }
    njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_SUCCESS);

    if (r->method == NJT_HTTP_GET) {
        njt_http_get_caches(r, cqmf, rpc_result);
    } else if (r->method == NJT_HTTP_PUT) {
        rc = njt_http_read_client_request_body(r, njt_http_cache_quick_api_read_data);

        if (rc == NJT_ERROR || rc >= NJT_HTTP_SPECIAL_RESPONSE) {
            if(rpc_result != NULL){
                njt_rpc_result_destroy(rpc_result);
                rpc_result = NULL;
            }
            return rc;
        }

        if(rpc_result != NULL){
            njt_rpc_result_destroy(rpc_result);
            rpc_result = NULL;
        }
        return NJT_DONE;
    } else {
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" method not allowed");
    }

    rc = njt_http_cache_quick_conf_out_handler(r, rpc_result);

    if(rpc_result != NULL){
        njt_rpc_result_destroy(rpc_result);
    }

    return rc;
}


static void njt_http_cache_quick_recovery_confs(njt_http_cache_quick_main_conf_t *cqmf, njt_str_t *msg){
    njt_pool_t                     *pool;
    njt_uint_t                      i;
    cache_t                        *caches;    
    cache_caches_item_t            *item;
    uint32_t                        crc32;
    cache_api_t                     api_data, *p_api_data;
    js2c_parse_error_t              err_info;
    njt_http_cache_resouce_metainfo_t       *cache_info;
    njt_str_t                       tmp_str;


    pool = njt_create_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
    if (pool == NULL) {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "create pool error in function %s", __func__);
        goto end;
    }

    njt_log_error(NJT_LOG_INFO, pool->log, 0, 
                " cache quick recover confs msg: %V",  msg);

    caches = json_parse_cache(pool, msg, &err_info);
    if (caches == NULL || !caches->is_caches_set)
    {
        njt_log_error(NJT_LOG_ERR, pool->log, 0, 
                " cache quick recover confs json parse err: %V",  &err_info.err_str);

        goto end;
    }

    if (!caches->is_caches_set)
    {
        njt_log_error(NJT_LOG_INFO, pool->log, 0, 
                " cache quick recover confs json size 0");

        goto end;
    }

    for (i = 0; i < caches->caches->nelts; ++i) {
        item = get_cache_caches_item(caches->caches, i);
        if(item == NULL){
            continue;
        }

        njt_memzero(&api_data, sizeof(cache_api_t));
        p_api_data = &api_data;
        if(item->is_location_name_set){
            set_cache_api_location_name(p_api_data, get_cache_caches_item_location_name(item));
        }

        if(item->is_backend_server_set){
            set_cache_api_backend_server(p_api_data, get_cache_caches_item_backend_server(item));
        }
       
        //add item to local, queue and lvlhash
        crc32 = njt_cache_quick_item_crc32(p_api_data);

        //find from lvlhash
        if(NJT_OK == njt_cache_quick_item_exist(crc32, cqmf, &cache_info)){
            if(p_api_data->is_location_name_set){
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
                    " cache quick item:%V is already exist", &p_api_data->location_name);
            }

            continue;
        }

        //insert queue
        cache_info = njt_http_add_cache_item_to_queue(cqmf, p_api_data);
        if(cache_info == NULL){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
                " malloc cache info error");

            continue;
        }

        //update origin status
        njt_str_set(&tmp_str, "downloading");
        if(item->status.len == tmp_str.len && 0 == njt_strncmp(item->status.data, tmp_str.data, tmp_str.len)){
            njt_str_set(&tmp_str, "has error, reload when downloading");
            njt_http_cache_quick_update_status_str(cache_info, CACHE_QUICK_STATUS_ERROR, &tmp_str);
        }else{
            cache_info->status_str.data = njt_pstrdup(cache_info->item_pool, &item->status);
            cache_info->status_str.len = item->status.len;
            cache_info->download_ratio = item->download_ratio;
        }

        cache_info->op_status = CACHE_QUICK_OP_STATUS_DONE;

        //insert lvlhash
        if(NJT_OK != njt_http_add_cache_item_to_lvlhash(crc32, cache_info, cqmf)){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
                " add cache info to lvlhash error");

            continue;  
        }
    }

end:
    if(pool != NULL){
        njt_destroy_pool(pool);
    }
}


static njt_int_t
njt_http_cache_quick_init_worker(njt_cycle_t *cycle) {
    njt_http_cache_quick_main_conf_t   *cqmf;
    njt_str_t                          key = njt_string(HTTP_CACHE_QUICK_CONFS);
    njt_str_t                          msg;

    cqmf = (njt_http_cache_quick_main_conf_t *)njt_get_conf(cycle->conf_ctx, njt_http_cache_quick_module);   
    if(cqmf == NULL){
        return NJT_OK;
    }

    //recover all config
    njt_memzero(&msg, sizeof(njt_str_t));
    njt_dyn_kv_get(&key, &msg);

    if (msg.len > 2) {
        njt_http_cache_quick_recovery_confs(cqmf, &msg);
    }

    return NJT_OK;
}

