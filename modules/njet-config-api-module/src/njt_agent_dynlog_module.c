/*************************************************************************************
 Copyright (C), 2021-2023, TMLake(Beijing) Technology Ltd.,
 File name    : njt_agent_dynlog_module.c
 Version      : 1.0
 Author       : ChengXu
 Date         : 2023/2/20/020 
 Description  : 
 Other        :
 History      :
 <author>       <time>          <version >      <desc>
 ChengXu        2023/2/20/020       1.1             
***********************************************************************************/
//
// Created by Administrator on 2023/2/20/020.
//
#include <njt_core.h>
#include <njt_http_kv_module.h>
#include <njt_http.h>
#include <njt_json_util.h>
#include "njt_dynlog_module.h"



static njt_json_define_t njt_http_dyn_access_api_loc_json_dt[] ={
        {
                njt_string("location"),
                offsetof(njt_http_dyn_access_api_loc_t, full_name),
                0,
                NJT_JSON_STR,
                NULL,
                NULL,
        },
        {
                njt_string("accessLogOn"),
                offsetof(njt_http_dyn_access_api_loc_t, log_on),
                0,
                NJT_JSON_BOOL,
                NULL,
                NULL,
        },
        {
                njt_string("locations"),
                offsetof(njt_http_dyn_access_api_loc_t, locs),
                sizeof(njt_http_dyn_access_api_loc_t),
                NJT_JSON_OBJ,
                njt_http_dyn_access_api_loc_json_dt,
                NULL,
        },
        njt_json_define_null,
};

static njt_json_define_t njt_http_dyn_access_api_srv_json_dt[] ={
        {
                njt_string("listens"),
                offsetof(njt_http_dyn_access_api_srv_t, listens),
                sizeof(njt_str_t),
                NJT_JSON_STR,
                NULL,
                NULL,
        },
        {
                njt_string("serverNames"),
                offsetof(njt_http_dyn_access_api_srv_t, server_names),
                sizeof(njt_str_t),
                NJT_JSON_STR,
                NULL,
                NULL,
        },
        {
                njt_string("locations"),
                offsetof(njt_http_dyn_access_api_srv_t, locs),
                sizeof(njt_http_dyn_access_api_loc_t),
                NJT_JSON_OBJ,
                njt_http_dyn_access_api_loc_json_dt,
                NULL,
        },
        njt_json_define_null,
};

static njt_json_define_t njt_http_dyn_access_api_main_json_dt[] ={
        {
                njt_string("servers"),
                offsetof(njt_http_dyn_access_api_main_t, servers),
                sizeof(njt_http_dyn_access_api_srv_t),
                NJT_JSON_OBJ,
                njt_http_dyn_access_api_srv_json_dt,
                NULL,
        },
        njt_json_define_null,
};

static njt_http_core_srv_conf_t* njt_dynlog_get_srv_by_port(njt_cycle_t *cycle,njt_pool_t *pool,njt_str_t *addr_port,njt_str_t *server_name){
    njt_http_core_srv_conf_t* cscf;
    njt_listening_t *ls, *target_ls;
    njt_uint_t i, len;
    u_char *last;
    u_char *p;
    njt_str_t  dport;
    njt_str_t wide_addr = njt_string("0.0.0.0");
    njt_http_port_t *port;
    njt_url_t u;
    struct sockaddr local_sockaddr;
    struct sockaddr_in *sin;
    njt_http_in_addr_t *addr;
    njt_http_connection_t hc;
    njt_http_virtual_names_t *virtual_names;
    njt_str_t  sport;


    cscf = NULL;
    if (addr_port->len > 0) {
        ls = cycle->listening.elts;
        for (i = 0; i < cycle->listening.nelts; i++) {
            if (ls[i].addr_text.len == addr_port->len &&
                njt_strncmp(ls[i].addr_text.data, addr_port->data, addr_port->len) == 0) {
                target_ls = &ls[i];
                break;
            } else {
                njt_memzero(&sport , sizeof(njt_str_t));
                last = addr_port->data + addr_port->len;
                p = njt_strlchr(addr_port->data, last, ':');
                if(p != NULL){
                    sport.data = p+1;
                    sport.len = last - sport.data;
                }
                last = ls[i].addr_text.data + ls[i].addr_text.len;
                p = njt_strlchr(ls[i].addr_text.data, last, ':');
                if (p != NULL) {
                    dport.data = p + 1;
                    dport.len = last - dport.data;
                    len = p - ls[i].addr_text.data;
                    if (dport.len == sport.len && njt_strncmp(dport.data, sport.data, dport.len) == 0
                        && wide_addr.len == len
                        && njt_strncmp(wide_addr.data, ls[i].addr_text.data, wide_addr.len) == 0) {
                        target_ls = &ls[i];
                        //todo 处理default
                        break;
                    }
                }
            }
        }
        if (target_ls == NULL) {
            return NULL;
        }
        port = target_ls->servers;
        if (port->naddrs > 1) {
            njt_memzero(&u, sizeof(njt_url_t));
            u.url = *addr_port;
            u.default_port = 80;
            njt_parse_url(pool, &u);
            njt_memcpy(&local_sockaddr, &u.sockaddr, u.socklen);
            sin = (struct sockaddr_in *) &local_sockaddr;

            addr = port->addrs;
            for (i = 0; i < port->naddrs - 1; i++) {
                if (addr[i].addr == sin->sin_addr.s_addr) {
                    break;
                }
            }
            hc.addr_conf = &addr[i].conf;
        } else {
            addr = port->addrs;
            hc.addr_conf = &addr[0].conf;
        }
        hc.conf_ctx = hc.addr_conf->default_server->ctx;
        virtual_names = hc.addr_conf->virtual_names;
        if (virtual_names != NULL) {
            cscf = njt_hash_find_combined(&virtual_names->names,
                                          njt_hash_key(server_name->data, server_name->len),
                                          server_name->data, server_name->len);
        }
        if(cscf == NULL && virtual_names != NULL && server_name->len > 0 && server_name->data != NULL) {
            njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "no find server add_port=%V,server_name=%V",&addr_port,&server_name);
            return NULL;
        }
        if (cscf == NULL) {
            cscf = njt_http_get_module_srv_conf(hc.conf_ctx, njt_http_core_module);
        }
    } else {
        cscf = NULL;
    }
    return cscf;
}

static njt_int_t njt_dynlog_update_locs_log(njt_array_t *locs,njt_queue_t *q){
    njt_http_core_loc_conf_t  *clcf;
    njt_http_location_queue_t *hlq;
    njt_http_dyn_access_api_loc_t *daal;
    njt_uint_t j;
    njt_queue_t *tq;
    njt_http_log_loc_conf_t *llcf;

    if(q == NULL){
        return NJT_OK;
    }
    daal = locs->elts;
    for( j = 0; j < locs->nelts ; ++j ){
        tq = njt_queue_head(q);
        for (;tq!= njt_queue_sentinel(q);tq = njt_queue_next(tq)) {
            hlq = njt_queue_data(tq, njt_http_location_queue_t, queue);
            clcf = hlq->exact == NULL ? hlq->inclusive : hlq->exact;
            njt_str_t name = daal[j].full_name;
            if (name.len == clcf->full_name.len && njt_strncmp(name.data, clcf->full_name.data, name.len) == 0) {
                llcf = njt_http_get_module_loc_conf(clcf, njt_http_log_module);
                llcf->off = daal[j].log_on?0:1;
                njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "change location %V log to %i",&daal[j].full_name,daal[j].log_on);
            }
            if(daal[j].locs.nelts > 0){
                njt_dynlog_update_locs_log(&daal[j].locs,clcf->old_locations);
            }
        }
    }
    return NJT_OK;
}

static njt_int_t njt_dynlog_update_access_log(njt_pool_t *pool,njt_http_dyn_access_api_main_t *api_data){

    njt_cycle_t *cycle,*new_cycle;
    njt_http_core_srv_conf_t  *cscf;
    njt_http_core_loc_conf_t  *clcf;
    njt_http_dyn_access_api_srv_t *daas;
    njt_uint_t i;

    if (njt_process == NJT_PROCESS_HELPER){
        new_cycle = (njt_cycle_t*)njt_cycle;
        cycle = new_cycle->old_cycle;
    } else{
        cycle = (njt_cycle_t*)njt_cycle;
    }

    daas = api_data->servers.elts;
    for(i = 0; i < api_data->servers.nelts; ++i){
        cscf = njt_dynlog_get_srv_by_port(cycle,pool,(njt_str_t*)daas[i].listens.elts,(njt_str_t*)daas[i].server_names.elts);
        if(cscf == NULL){
            njt_log_error(NJT_LOG_INFO, pool->log, 0, "can`t find server by listen:%V server_name:%V ",
                          (njt_str_t*)daas[i].listens.nelts,(njt_str_t*)daas[i].server_names.nelts);
            continue;
        }
        clcf = njt_http_get_module_loc_conf(cscf->ctx,njt_http_core_module);
        njt_dynlog_update_locs_log(&daas[i].locs,clcf->old_locations);

    }
    return NJT_OK;
}

// 获取server的listen 字符串列表
static njt_int_t njt_dynlog_get_listens_by_server(njt_array_t *array,njt_http_core_srv_conf_t  *cscf){
    njt_hash_elt_t  **elt;
    njt_listening_t *ls;
    njt_uint_t i,j,k;
    njt_http_port_t *port;
    njt_http_in_addr_t *addr;
    njt_http_addr_conf_t             *addr_conf;
    njt_str_t *listen;

    ls = njt_cycle->listening.elts;
    for (i = 0; i < njt_cycle->listening.nelts; ++i) {
        port = ls[i].servers;
        addr = port->addrs;
        for (j = 0; j < port->naddrs ; ++j) {
            addr_conf = &addr[j].conf;
            if(addr_conf->default_server == cscf){
                listen  = njt_array_push(array);
                if(listen == NULL){
                    return NJT_ERROR_ERR;
                }
                *listen = ls[i].addr_text;
            }
            if(addr_conf->virtual_names == NULL ){
                continue;
            }
            elt = addr_conf->virtual_names->names.hash.buckets;
            for(k = 0 ; k < addr_conf->virtual_names->names.hash.size;++k){
                if(elt[k] != NULL ){
                    if(elt[k]->value == cscf ){
                        listen  = njt_array_push(array);
                        if(listen == NULL){
                            return NJT_ERROR_ERR;
                        }
                        *listen = ls[i].addr_text;
                    }
                }
            }
            if(addr_conf->virtual_names->names.wc_head != NULL){
                elt = addr_conf->virtual_names->names.wc_head->hash.buckets;
                for(k = 0 ; k < addr_conf->virtual_names->names.wc_head->hash.size;++k){
                    if(elt[k] != NULL ){
                        if(elt[k]->value == cscf ){
                            listen  = njt_array_push(array);
                            if(listen == NULL){
                                return NJT_ERROR_ERR;
                            }
                            *listen = ls[i].addr_text;
                        }
                    }
                }
            }
            if(addr_conf->virtual_names->names.wc_tail != NULL){
                elt = addr_conf->virtual_names->names.wc_tail->hash.buckets;
                for(k = 0 ; k < addr_conf->virtual_names->names.wc_tail->hash.size;++k){
                    if(elt[k] != NULL ){
                        if(elt[k]->value == cscf ){
                            listen  = njt_array_push(array);
                            if(listen == NULL){
                                return NJT_ERROR_ERR;
                            }
                            *listen = ls[i].addr_text;
                        }
                    }
                }
            }
        }
    }
    return NJT_OK;
}

#define njt_json_fast_key(key) (u_char*)key,sizeof(key)-1
#define njt_json_null_key NULL,0

static njt_json_element* njt_json_str_element(njt_pool_t *pool,u_char *key,njt_uint_t len,njt_str_t *value){
    njt_json_element *element;

    element = NULL;
    element = njt_pcalloc(pool,sizeof (njt_json_element));
    if(element == NULL ){
        goto end;
    }
    element->type = NJT_JSON_STR;
    if(key != NULL){
        element->key.data = key;
        element->key.len = len;
    }
    if(value != NULL){
        element->strval = *value;
    }
    end:
    return element;
}
static njt_json_element* njt_json_bool_element(njt_pool_t *pool, u_char *key,njt_uint_t len,bool value){
    njt_json_element *element;

    element = NULL;
    element = njt_pcalloc(pool,sizeof (njt_json_element));
    if(element == NULL ){
        goto end;
    }
    element->type = NJT_JSON_BOOL;
    if(key != NULL){
        element->key.data = key;
        element->key.len = len;
    }
    element->bval = value;

    end:
    return element;
}

static njt_json_element* njt_json_obj_element(njt_pool_t *pool,u_char *key,njt_uint_t len){
    njt_json_element *element;

    element = NULL;
    element = njt_pcalloc(pool,sizeof (njt_json_element));
    if(element == NULL ){
        goto end;
    }
    element->type = NJT_JSON_OBJ;
    if(key != NULL){
        element->key.data = key;
        element->key.len = len;
    }
    end:
    return element;
}

static njt_json_element* njt_json_arr_element(njt_pool_t *pool,u_char *key,njt_uint_t len){
    njt_json_element *element;

    element = NULL;
    element = njt_pcalloc(pool,sizeof (njt_json_element));
    if(element == NULL ){
        goto end;
    }
    element->type = NJT_JSON_ARRAY;
    if(key != NULL){
        element->key.data = key;
        element->key.len = len;
    }
    end:
    return element;
}

static njt_json_element* njt_dynlog_dump_locs_json(njt_pool_t *pool,njt_queue_t *locations){
    njt_http_core_loc_conf_t  *clcf;
    njt_http_location_queue_t *hlq;
    njt_queue_t *q,*tq;
    njt_http_log_loc_conf_t *llcf;

    njt_json_element *locs,*item,*sub;

    if(locations == NULL){
        return NULL;
    }
    locs = NULL;
    q = locations;
    if(njt_queue_empty(q)){
        return NULL;
    }

    tq = njt_queue_head(q);
    locs = njt_json_arr_element(pool,njt_json_fast_key("locations"));
    if(locs == NULL){
        return NULL;
    }
    for (;tq!= njt_queue_sentinel(q);tq = njt_queue_next(tq)){
        hlq = njt_queue_data(tq,njt_http_location_queue_t,queue);
        clcf = hlq->exact == NULL ? hlq->inclusive : hlq->exact;
        llcf = njt_http_get_module_loc_conf(clcf,njt_http_log_module);

        item = njt_json_obj_element(pool,njt_json_null_key);
        if(item == NULL){
            return NULL;
        }
        sub = njt_json_str_element(pool,njt_json_fast_key("location"),&clcf->full_name);
        if(sub == NULL){
            return NULL;
        }
        njt_struct_add(item,sub,pool);

        sub = njt_json_bool_element(pool,njt_json_fast_key("accessLogOn"),llcf->off?0:1);
        if(sub == NULL){
            return NULL;
        }
        njt_struct_add(item,sub,pool);

        sub = njt_dynlog_dump_locs_json(pool,clcf->old_locations);
        if(sub != NULL){
            njt_struct_add(item,sub,pool);
        }
        njt_struct_add(locs,item,pool);
    }
    return locs;
}

njt_str_t dynlog_update_srv_err_msg=njt_string("{\"code\":500,\"msg\":\"server error\"}");


static njt_str_t njt_dynlog_dump_log_conf(njt_cycle_t *cycle,njt_pool_t *pool){
    njt_http_core_loc_conf_t  *clcf;
    njt_http_core_main_conf_t *hcmcf;
    njt_http_core_srv_conf_t  **cscfp;
    njt_uint_t i,j;
    njt_array_t *array;
    njt_str_t json,*tmp_str;
    njt_json_manager json_manager;
    njt_json_element *root,*srvs,*srv,*subs,*sub;

    hcmcf = njt_http_cycle_get_module_main_conf(cycle,njt_http_core_module);

    json_manager.json_keyval = njt_array_create(pool,1,sizeof (njt_json_element));
    if(json_manager.json_keyval == NULL ){
        goto err;
    }
    root = njt_array_push(json_manager.json_keyval);
    if(root == NULL ){
        goto err;
    }
    njt_memzero(root, sizeof(njt_json_element));
    root->type = NJT_JSON_OBJ;

    srvs =  njt_json_arr_element(pool,njt_json_fast_key("servers"));
    if(srvs == NULL ){
        goto err;
    }

    cscfp = hcmcf->servers.elts;
    for( i = 0; i < hcmcf->servers.nelts; i++){
        array = njt_array_create(pool,4, sizeof(njt_str_t));
        njt_dynlog_get_listens_by_server(array,cscfp[i]);

        srv =  njt_json_obj_element(pool,njt_json_null_key);
        if(srv == NULL ){
            goto err;
        }

        subs =  njt_json_arr_element(pool,njt_json_fast_key("listens"));
        if(subs == NULL ){
            goto err;
        }

        tmp_str = array->elts;
        for(j = 0 ; j < array->nelts ; ++j ){
            sub =  njt_json_str_element(pool,njt_json_null_key,&tmp_str[j]);
            if(sub == NULL ){
                goto err;
            }
            njt_struct_add(subs,sub,pool);
        }
        njt_struct_add(srv,subs,pool);
        subs =  njt_json_arr_element(pool,njt_json_fast_key("serverNames"));
        if(subs == NULL ){
            goto err;
        }
        tmp_str = cscfp[i]->server_names.elts;
        for(j = 0 ; j < cscfp[i]->server_names.nelts ; ++j ){
            sub =  njt_json_str_element(pool,njt_json_null_key,&tmp_str[j]);
            if(sub == NULL ){
                goto err;
            }
            njt_struct_add(subs,sub,pool);
        }
        njt_struct_add(srv,subs,pool);
        clcf = njt_http_get_module_loc_conf(cscfp[i]->ctx,njt_http_core_module);
        subs = njt_dynlog_dump_locs_json(pool,clcf->old_locations);
        if(subs != NULL){
            njt_struct_add(srv,subs,pool);
        }
        njt_struct_add(srvs,srv,pool);
    }

    njt_struct_add(root,srvs,pool);// 顶层
    njt_memzero(&json, sizeof(njt_str_t));
    njt_structure_2_json(&json_manager, &json, pool);

    return json;

    err:
    return dynlog_update_srv_err_msg;
}

static u_char* njt_agent_dynlog_rpc_handler(njt_str_t *topic, njt_str_t *request, int* len, void *data){
    njt_cycle_t *cycle;
    njt_str_t msg;
    u_char *buf;

    buf = NULL;
    cycle = (njt_cycle_t*) njt_cycle;
    *len = 0 ;
    njt_pool_t *pool = NULL;
    pool = njt_create_pool(njt_pagesize,njt_cycle->log);
    if(pool == NULL){
        njt_log_error(NJT_LOG_EMERG, pool->log, 0, "njt_agent_dynlog_change_handler create pool error");
        goto end;
    }
    msg = njt_dynlog_dump_log_conf(cycle,pool);
    buf = njt_calloc(msg.len,cycle->log);
    if(buf == NULL){
        goto end;
    }
    njt_log_error(NJT_LOG_INFO, pool->log, 0, "send json : %V",&msg);
    njt_memcpy(buf,msg.data,msg.len);
    *len = msg.len;

    end:
    if(pool != NULL){
        njt_destroy_pool(pool);
    }

    return buf;
}

static int  njt_agent_dynlog_change_handler(njt_str_t *key, njt_str_t *value, void *data){
    njt_int_t rc;
    njt_http_dyn_access_api_main_t *api_data = NULL;
    njt_pool_t *pool = NULL;
    if(value->len < 2 ){
        return NJT_OK;
    }
    pool = njt_create_pool(njt_pagesize,njt_cycle->log);
    if(pool == NULL){
        njt_log_error(NJT_LOG_EMERG, pool->log, 0, "njt_agent_dynlog_change_handler create pool error");
        return NJT_OK;
    }
    api_data = njt_pcalloc(pool,sizeof (njt_http_dyn_access_api_main_t));
    if(api_data == NULL){
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, pool->log, 0,
                       "could not alloc buffer in function %s", __func__);
        goto end;
    }

    rc =njt_json_parse_data(pool,value,njt_http_dyn_access_api_main_json_dt,api_data);
    if(rc == NJT_OK ){
        njt_dynlog_update_access_log(pool,api_data);
    }

    end:
    if(pool != NULL){
        njt_destroy_pool(pool);
    }
    return NJT_OK;
}

static njt_int_t njt_agent_dynlog_init_process(njt_cycle_t* cycle){
    njt_str_t  rpc_key = njt_string("http_log");
    njt_reg_kv_change_handler(&rpc_key, njt_agent_dynlog_change_handler,njt_agent_dynlog_rpc_handler, NULL);
    return NJT_OK;
}


static njt_http_module_t njt_agent_dynlog_module_ctx = {
        NULL,                                   /* preconfiguration */
        NULL,                                   /* postconfiguration */

        NULL,                                   /* create main configuration */
        NULL,                                  /* init main configuration */

        NULL,                                  /* create server configuration */
        NULL,                                  /* merge server configuration */

        NULL,                                   /* create location configuration */
        NULL                                    /* merge location configuration */
};

njt_module_t njt_agent_dynlog_module = {
        NJT_MODULE_V1,
        &njt_agent_dynlog_module_ctx,                 /* module context */
        NULL,                                   /* module directives */
        NJT_HTTP_MODULE,                        /* module type */
        NULL,                                   /* init master */
        NULL,                                   /* init module */
        njt_agent_dynlog_init_process,          /* init process */
        NULL,                                   /* init thread */
        NULL,                                   /* exit thread */
        NULL,                                   /* exit process */
        NULL,                                   /* exit master */
        NJT_MODULE_V1_PADDING
};