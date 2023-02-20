/*************************************************************************************
 Copyright (C), 2021-2023, TMLake(Beijing) Technology Ltd.,
 File name    : njt_dynlog_module.c
 Version      : 1.0
 Author       : ChengXu
 Date         : 2023/2/13/013 
 Description  : 
 Other        :
 History      :
 <author>       <time>          <version >      <desc>
 ChengXu        2023/2/13/013       1.1             
***********************************************************************************/
//
// Created by Administrator on 2023/2/13/013.
//

#include <njt_core.h>
#include <njt_http.h>
#include <njt_json_api.h>
#include "njt_json_util.h"

extern njt_cycle_t *njet_master_cycle;
extern njt_module_t njt_dynlog_module;

typedef struct {
    njt_array_t                *logs;       /* array of njt_http_log_t */

    njt_open_file_cache_t      *open_file_cache;
    time_t                      open_file_cache_valid;
    njt_uint_t                  open_file_cache_min_uses;

    njt_uint_t                  off;        /* unsigned  off:1 */
} njt_http_log_loc_conf_t;

extern njt_module_t  njt_http_log_module;


typedef struct {
    njt_str_t full_name;
    bool log_off;
}njt_http_dyn_access_api_loc_t;
typedef struct {
    njt_array_t listens;
    njt_array_t server_names;
    njt_array_t locs;
}njt_http_dyn_access_api_srv_t;
typedef struct {
    njt_array_t servers;
    njt_int_t rc;
    unsigned success:1;
}njt_http_dyn_access_api_main_t;

static njt_json_define_t njt_http_dyn_access_api_loc_json_dt[] ={
        {
                njt_string("fullName"),
                offsetof(njt_http_dyn_access_api_loc_t, full_name),
                0,
                NJT_JSON_STR,
                NULL,
                NULL,
        },
        {
                njt_string("logOff"),
                offsetof(njt_http_dyn_access_api_loc_t, log_off),
                0,
                NJT_JSON_BOOL,
                NULL,
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

static void njt_http_dyn_access_log_read_api(njt_http_request_t *r){
    njt_str_t json_str;
    njt_chain_t *body_chain,*tmp_chain;
    njt_int_t rc;
    njt_http_dyn_access_api_main_t *api_data = NULL;
    njt_uint_t len,size;
    njt_json_manager json_body;


    body_chain = r->request_body->bufs;
    if(body_chain == NULL){
        return;
    }
    /*check the sanity of the json body*/
    json_str.data = body_chain->buf->pos;
    json_str.len = body_chain->buf->last - body_chain->buf->pos;

    if(json_str.len < 2 ){
        return;
    }

    api_data = njt_pcalloc(r->pool,sizeof (njt_http_dyn_access_api_main_t));
    if(api_data == NULL){
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "could not alloc buffer in function %s", __func__);
        return;
    }
    len = 0 ;
    tmp_chain = body_chain;
    while (tmp_chain!= NULL){
        len += tmp_chain->buf->last - tmp_chain->buf->pos;
        tmp_chain = tmp_chain->next;
    }
    json_str.len = len;
    json_str.data = njt_pcalloc(r->pool,len);
    if(json_str.data == NULL){
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "could not alloc buffer in function %s", __func__);
        return;
    }
    len = 0;
    tmp_chain = r->request_body->bufs;
    while (tmp_chain!= NULL){
        size = tmp_chain->buf->last-tmp_chain->buf->pos;
        njt_memcpy(json_str.data + len,tmp_chain->buf->pos,size);
        tmp_chain = tmp_chain->next;
        len += size;
    }
    njt_memzero(&json_body, sizeof(njt_json_manager));
    rc = njt_json_2_structure(&json_str, &json_body,r->pool);
    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_EMERG, r->pool->log, 0, "structure json body mem malloc error !!");
        goto end;
    }
    rc =njt_json_parse_data(r->pool,&json_str,njt_http_dyn_access_api_main_json_dt,api_data);


    end:
    api_data->rc = rc;
    if(rc != NJT_OK ){
        api_data->success = 0;
    }else {
        api_data->success = 1;
    }
    njt_http_set_ctx(r, api_data, njt_dynlog_module);
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
            addr_conf = &addr[i].conf;
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

static njt_str_t njt_dynlog_dump_log_conf(njt_cycle_t *cycle,njt_pool_t *pool){
    njt_http_core_loc_conf_t  *clcf;
    njt_http_location_queue_t *hlq;
    njt_http_core_main_conf_t *hcmcf;
    njt_http_core_srv_conf_t  **cscfp;
    njt_uint_t i,j;
    njt_queue_t *q,*tq;
    njt_http_log_loc_conf_t *llcf;
    u_char* index,*end;
    njt_array_t *array;
    njt_str_t json,*tmp_str;

    index = njt_pcalloc(pool,njt_pagesize);
    if(index == NULL){
        njt_str_null(&json);
        return json;
    }
    end = index + njt_pagesize;
    json.data = index;
    hcmcf = njt_http_cycle_get_module_main_conf(cycle,njt_http_core_module);
    index = njt_snprintf(index, end - index  , "{\"servers\":[" );
    cscfp = hcmcf->servers.elts;
    for( i = 0; i < hcmcf->servers.nelts; i++){
        array = njt_array_create(pool,4, sizeof(njt_str_t));
        njt_dynlog_get_listens_by_server(array,cscfp[i]);
        tmp_str = array->elts;
        index = njt_snprintf(index, end - index  , "{\"listens\":[" );
        for(j = 0 ; j < array->nelts ; ++j ){
            index = njt_snprintf(index, end - index  , "\"%V\",",&tmp_str[j]);
        }
        if(*index == ','){
            --index;
        }
        index = njt_snprintf(index, end - index  , "],serverNames:[" );
        tmp_str = cscfp[i]->server_names.elts;
        for(j = 0 ; j < cscfp[i]->server_names.nelts ; ++j ){
            index = njt_snprintf(index, end - index  , "\"%V\",",&tmp_str[j]);
        }
        if(*index == ','){
            --index;
        }
        index = njt_snprintf(index, end - index  , "]" );
        clcf = njt_http_get_module_loc_conf(cscfp[i]->ctx,njt_http_core_module);
        q = clcf->old_locations;
        tq = njt_queue_head(q);
        if(tq!= njt_queue_sentinel(q)){
            index = njt_snprintf(index, end - index  , ",locations:[" );
        }
        for (;tq!= njt_queue_sentinel(q);tq = njt_queue_next(tq)){
            hlq = njt_queue_data(tq,njt_http_location_queue_t,queue);
            clcf = hlq->exact == NULL ? hlq->inclusive : hlq->exact;
            llcf = njt_http_get_module_loc_conf(clcf,njt_http_log_module);
            llcf->off= llcf->off==1?0:1;
            index = njt_snprintf(index, end - index  , "{\"fullName\": \"%V\",",&clcf->full_name);
            if(llcf->off){
                index = njt_snprintf(index, end - index  , "\"logOff\": true},",&clcf->full_name);
            } else{
                index = njt_snprintf(index, end - index  , "\"logOff\": false},",&clcf->full_name);
            }
        }
        if(*index == ','){
            --index;
        }
        index = njt_snprintf(index, end - index  , "]}," );
    }
    if(*index == ','){
        --index;
    }
    index = njt_snprintf(index, end - index  , "]}" );
    json.len = index - json.data;
    return json;
}

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

static njt_int_t njt_dynlog_get_access_log_conf(njt_http_request_t *r){
    njt_cycle_t *cycle,*new_cycle;
    njt_str_t body;
    njt_buf_t *buf;
    njt_chain_t out;
    njt_int_t rc;

    if (njt_process == NJT_PROCESS_HELPER){
        new_cycle = (njt_cycle_t*)njt_cycle;
        cycle = new_cycle->old_cycle;
    } else{
        cycle = (njt_cycle_t*)njt_cycle;
    }
    body = njt_dynlog_dump_log_conf(cycle,r->pool);
    buf = njt_create_temp_buf(r->pool, body.len);
    if(buf == NULL){
        return NJT_ERROR;
    }
    njt_memcpy(buf->pos,body.data,body.len);
    buf->last = buf->pos + body.len;
    r->headers_out.status = NJT_HTTP_OK;
    njt_str_t type=njt_string("application/json");
    r->headers_out.content_type = type;
    r->headers_out.content_length_n = buf->last - buf->pos;
    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }
    rc = njt_http_send_header(r);
    if(rc == NJT_ERROR || rc > NJT_OK || r->header_only){
        return rc;
    }
    buf->last_buf = 1;
    out.buf = buf;
    out.next = NULL;
    return njt_http_output_filter(r, &out);
}

static njt_int_t njt_dynlog_update_access_log(njt_pool_t *pool,njt_http_dyn_access_api_main_t *api_data){

    njt_cycle_t *cycle,*new_cycle;
    njt_http_core_srv_conf_t  *cscf;
    njt_http_core_loc_conf_t  *clcf;
    njt_http_location_queue_t *hlq;
    njt_http_dyn_access_api_loc_t *daal;
    njt_http_dyn_access_api_srv_t *daas;

    njt_uint_t i,j;
    njt_queue_t *q,*tq;

    njt_http_log_loc_conf_t *llcf;

    if (njt_process == NJT_PROCESS_HELPER){
        new_cycle = (njt_cycle_t*)njt_cycle;
        cycle = new_cycle->old_cycle;
    } else{
        cycle = (njt_cycle_t*)njt_cycle;
    }

    daas = api_data->servers.elts;
    for(i = 0; i < api_data->servers.nelts; ++i){
        daal = daas[i].locs.elts;
        cscf = njt_dynlog_get_srv_by_port(cycle,pool,(njt_str_t*)daas[i].listens.elts,(njt_str_t*)daas[i].server_names.elts);
        if(cscf == NULL){
            njt_log_error(NJT_LOG_INFO, pool->log, 0, "can`t find server by listen:%V server_name:%V ",
                          (njt_str_t*)daas[i].listens.nelts,(njt_str_t*)daas[i].server_names.nelts);
            continue;
        }
        for( j = 0; j <  daas[i].locs.nelts ; ++j ){
            clcf = njt_http_get_module_loc_conf(cscf->ctx,njt_http_core_module);
            q = clcf->old_locations;
            tq = njt_queue_head(q);
            for (;tq!= njt_queue_sentinel(q);tq = njt_queue_next(tq)) {
                hlq = njt_queue_data(tq, njt_http_location_queue_t, queue);
                clcf = hlq->exact == NULL ? hlq->inclusive : hlq->exact;
                njt_str_t name = daal[j].full_name;
                if (name.len == clcf->full_name.len && njt_strncmp(name.data, clcf->full_name.data, name.len) == 0) {
                    llcf = njt_http_get_module_loc_conf(clcf, njt_http_log_module);
                    llcf->off = daal[j].log_off;
                    njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "change location %V log to %i",&daal[j].full_name,daal[j].log_off);
                }
            }
        }
    }
    return NJT_OK;
}

static njt_int_t njt_dynlog_http_handler(njt_http_request_t *r){
    njt_int_t rc;
    njt_http_dyn_access_api_main_t *api_data;


    rc = njt_http_read_client_request_body(r, njt_http_dyn_access_log_read_api);
    if (rc == NJT_OK) {
        njt_http_finalize_request(r, NJT_DONE);
    }
    api_data = njt_http_get_module_ctx(r, njt_dynlog_module);

    if(r->method == NJT_HTTP_PUT){
        if (api_data == NULL || !api_data->success) {
            njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "get api %ui ",api_data->servers.nelts);
            goto out;
        }
        njt_dynlog_update_access_log(r->pool,api_data);
    }
    if(r->method == NJT_HTTP_GET){
        return njt_dynlog_get_access_log_conf(r);
    }

    out:
    r->headers_out.status = NJT_HTTP_NO_CONTENT;
    return njt_http_send_header(r);
}
static char *njt_dynlog_http_handler_conf(njt_conf_t *cf, njt_command_t *cmd, void *conf) {
    njt_http_core_loc_conf_t *clcf;
    clcf = njt_http_conf_get_module_loc_conf(cf, njt_http_core_module);
    clcf->handler = njt_dynlog_http_handler;
    return NJT_CONF_OK;
}



static njt_command_t njt_dynlog_module_commands[] = {
        {
                njt_string("dynlog"),
                NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF | NJT_CONF_NOARGS,
                njt_dynlog_http_handler_conf,
                NJT_HTTP_LOC_CONF_OFFSET,
                0,
                NULL
        },
        njt_null_command
};

static njt_http_module_t njt_dynlog_module_ctx = {
        NULL,                                   /* preconfiguration */
        NULL,                                   /* postconfiguration */

        NULL,                                   /* create main configuration */
        NULL,                                  /* init main configuration */

        NULL,                                  /* create server configuration */
        NULL,                                  /* merge server configuration */

        NULL,                                   /* create location configuration */
        NULL                                    /* merge location configuration */
};

njt_module_t njt_dynlog_module = {
        NJT_MODULE_V1,
        &njt_dynlog_module_ctx,        /* module context */
        njt_dynlog_module_commands,          /* module directives */
        NJT_HTTP_MODULE,                        /* module type */
        NULL,                                   /* init master */
        NULL,                                   /* init module */
        NULL,                                   /* init process */
        NULL,                                   /* init thread */
        NULL,                                   /* exit thread */
        NULL,                                   /* exit process */
        NULL,                                   /* exit master */
        NJT_MODULE_V1_PADDING
};