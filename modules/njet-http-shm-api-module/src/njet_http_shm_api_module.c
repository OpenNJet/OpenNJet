/*
 * Copyright (C) 2021-2025  TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_http_util.h>
#include "njt_http_api_register_module.h"
#include <njt_slab.h>

extern njt_uint_t njt_worker;
extern njt_module_t  njt_http_rewrite_module;
extern njt_cycle_t *njet_master_cycle;

static njt_int_t njt_http_shm_api_handler(njt_http_request_t *r);
static njt_int_t njt_http_shm_api_process_put(njt_http_request_t *r, njt_array_t *path);
static njt_int_t njt_http_shm_api_process_get(njt_http_request_t *r, njt_array_t *path);
static njt_int_t njt_http_shm_api_init_worker(njt_cycle_t *cycle);
static void* njt_http_shm_api_create_main_conf(njt_conf_t *cf);
static njt_int_t njt_http_shm_api_init(njt_conf_t *cf);
static int njt_http_shm_api_request_output(njt_http_request_t *r,njt_int_t code, njt_str_t *msg);
static njt_int_t njt_http_shm_api_set_zone_autoscale(njt_cycle_t *cycle, njt_str_t *zone_name, njt_int_t dyn, njt_int_t value);


typedef struct njt_http_shm_api_ctx_s {
} njt_http_shm_api_ctx_t;

typedef struct njt_http_shm_api_main_conf_s {
} njt_http_shm_api_main_conf_t;


typedef struct {
    njt_int_t code;
    njt_str_t msg;
    void* data;
    unsigned success:1;
}njt_http_shm_api_request_err_ctx_t;

static njt_http_module_t njt_http_shm_api_module_ctx = {
        NULL,                              /* preconfiguration */
        njt_http_shm_api_init,             /* postconfiguration */

        njt_http_shm_api_create_main_conf, /* create main configuration */
        NULL,                              /* init main configuration */

        NULL,                              /* create server configuration */
        NULL,                              /* merge server configuration */

        NULL,                               /* create location configuration */
        NULL                                /* merge location configuration */
};

njt_module_t njt_http_shm_api_module = {
        NJT_MODULE_V1,
        &njt_http_shm_api_module_ctx,       /* module context */
        NULL,                               /* module directives */
        NJT_HTTP_MODULE,                    /* module type */
        NULL,                               /* init master */
        NULL,                               /* init module */
        njt_http_shm_api_init_worker,       /* init process */
        NULL,                               /* init thread */
        NULL,                               /* exit thread */
        NULL,                               /* exit process */
        NULL,                               /* exit master */
        NJT_MODULE_V1_PADDING
};


static njt_int_t
njt_http_shm_api_init(njt_conf_t *cf) {
    njt_http_api_reg_info_t             h;
	njt_http_shm_api_main_conf_t       *smcf;


    if (njet_master_cycle == NULL) {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njet_master cycle is NULL. not in ctrl helper?");
        return NJT_ERROR;
    }

    smcf = njt_http_conf_get_module_main_conf(cf, njt_http_shm_api_module);
    if(smcf == NULL){
        return NJT_ERROR;
    }

    njt_str_t  module_key = njt_string("/v1/shm");
    njt_memzero(&h, sizeof(njt_http_api_reg_info_t));
    h.key = &module_key;
    h.handler = njt_http_shm_api_handler;
    njt_http_api_module_reg_handler(&h);

    return NJT_OK;
}


static void *
njt_http_shm_api_create_main_conf(njt_conf_t *cf) {
    njt_http_shm_api_main_conf_t *smcf;

    smcf = njt_pcalloc(cf->pool, sizeof(njt_http_shm_api_main_conf_t));
    if (smcf == NULL) {
        njt_log_error(NJT_LOG_ERR, cf->log, 0, "malloc njt_http_dyn_ssl_main_conf_t eror");
        return NULL;
    }

    return smcf;
}


/*!
    路由解析
*/
static njt_int_t
njt_http_api_parse_path(njt_http_request_t *r, njt_array_t *path)
{
    u_char                              *p,*end, *sub_p;
    njt_uint_t                          len;
    njt_str_t                           *item;
    njt_http_core_loc_conf_t            *clcf;
    njt_str_t                           uri;

    /*the uri is parsed and delete all the duplidated '/' characters.
     * for example, "/api//7//http///upstreams///////" will be parse to
     * "/api/7/http/upstreams/" already*/

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    uri = r->uri;
    p = uri.data + clcf->name.len;
    end = uri.data + uri.len;
    len = uri.len - clcf->name.len;

    if (len != 0 && *p != '/') {
        return NJT_HTTP_NOT_FOUND;
    }
    if (*p == '/') {
        len --;
        p ++;
    }

    while (len > 0) {
        item = njt_array_push(path);
        if (item == NULL) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "zack: array item of path push error.");
            return NJT_ERROR;
        }

        item->data = p;
        sub_p = (u_char *)njt_strlchr(p, end, '/');

        if (sub_p == NULL || (njt_uint_t)(sub_p - uri.data) > uri.len) {
            item->len = uri.data + uri.len - p;
            break;

        } else {
            item->len = sub_p - p;
        }

        len -= item->len;
        p += item->len;

        if (*p == '/') {
            len --;
            p ++;
        }

    }
    return NJT_OK;
}


static njt_int_t
njt_http_shm_api_handler(njt_http_request_t *r) {
    njt_int_t                       rc = NJT_OK;
    njt_array_t                    *path;

    njt_str_t not_found_err = njt_string("{\"code\":404,\"msg\":\"api or zone_name not found error\"}");

    path = njt_array_create(r->pool, 5, sizeof(njt_str_t));
    rc = njt_http_api_parse_path(r, path);
    if (rc != NJT_OK) {
        rc =  NJT_HTTP_NOT_FOUND;
        goto out;
    }

    // path 数组第一项是 v1 第二项是 shm
    rc = NJT_HTTP_NOT_FOUND;
    if(r->method == NJT_HTTP_PUT){
        if (path->nelts != 5) {
            rc =  NJT_HTTP_NOT_FOUND;
            goto out;

        }
        rc = njt_http_shm_api_process_put(r, path);
    } else if(r->method == NJT_HTTP_GET){
        rc = njt_http_shm_api_process_get(r, path);
    }

    if (rc != NJT_HTTP_NOT_FOUND) {
        return  rc;
    }

out:
    return njt_http_shm_api_request_output(r, NJT_HTTP_NOT_FOUND, &not_found_err);
}


static njt_int_t
njt_http_shm_api_init_worker(njt_cycle_t *cycle) {

    return NJT_OK;
}

static njt_int_t
njt_http_shm_api_process_put(njt_http_request_t *r, njt_array_t *path)
{
    njt_str_t       *item;
    njt_int_t        dyn, value, rc;
    njt_str_t       *zone_name = NULL;
    njt_str_t        srv_ok = njt_string("{\"code\":200,\"msg\":\"successfully update zone status\"}");

    if (path->nelts != 5) {
        return NJT_HTTP_NOT_FOUND;
    }

    item = path->elts; 
    dyn = NJT_CONF_UNSET;
    value = NJT_CONF_UNSET;

    if (njt_strncmp(item[2].data, "set", 3) == 0) {
        value = 1;
    } else if (njt_strncmp(item[2].data, "unset", 5) == 0) {
        value = 0;
    }

    if (value == NJT_CONF_UNSET) {
        return NJT_HTTP_NOT_FOUND;
    }
    
    if (njt_strncmp(item[3].data, "static", 6) == 0) {
        dyn = 0;
    } else if (njt_strncmp(item[3].data, "dynamic", 7) == 0) {
        dyn = 1;
    }

    if (dyn == NJT_CONF_UNSET) {
        return NJT_HTTP_NOT_FOUND;
    }

    if (item[4].len) {
        zone_name = &item[4];
    }

    rc = njt_http_shm_api_set_zone_autoscale(njet_master_cycle, zone_name, dyn, value);

    if (rc != NJT_OK) {
        return rc;
    }

    return njt_http_shm_api_request_output(r, NJT_HTTP_OK, &srv_ok);
}


static njt_int_t
njt_http_shm_api_process_get(njt_http_request_t *r, njt_array_t *path)
{
    njt_int_t         dyn;
    njt_str_t        *item, *zone_name;
    njt_slab_pool_t  *pool;
    njt_str_t         zone_autosale_yes = njt_string("{\"code\":200,\"msg\":\"zone autoscale is set\"}");
    njt_str_t         zone_autosale_no = njt_string("{\"code\":200,\"msg\":\"zone autoscale is unset\"}");
    njt_str_t         zone_autosale_all = njt_string("{\"code\":200,\"msg\":\"query all zones attributes can be get from where 'shm_status_display' cmd is set\"}");

    item = path->elts;
    pool = NULL;

    if (njt_strncmp(item[2].data, "get", 3) == 0) {
        if (path->nelts == 3) {
            return njt_http_shm_api_request_output(r, NJT_HTTP_OK, &zone_autosale_all);
        } 

        if (path->nelts != 5) {
            return NJT_HTTP_NOT_FOUND;
        } 

        dyn = NJT_CONF_UNSET;
        if (njt_strncmp(item[3].data, "static", 6) == 0) {
            dyn = 0;
        } else if (njt_strncmp(item[3].data, "dynamic", 7) == 0) {
            dyn = 1;
        }

        if (dyn == NJT_CONF_UNSET) {
            return NJT_HTTP_NOT_FOUND;
        }

        zone_name = &item[4];
        pool = njt_share_slab_get_pool_by_name(njet_master_cycle, zone_name, dyn);
        if (pool == NULL) {
            return NJT_HTTP_NOT_FOUND;
        }
        if (pool->auto_scale) {
            return njt_http_shm_api_request_output(r, NJT_HTTP_OK, &zone_autosale_yes);
        } else {
            return njt_http_shm_api_request_output(r, NJT_HTTP_OK, &zone_autosale_no);
        }
    }
    
    return NJT_HTTP_NOT_FOUND;
}


static int
njt_http_shm_api_request_output(njt_http_request_t *r,njt_int_t code, njt_str_t *msg)
{
    njt_int_t rc;
    njt_buf_t *buf;
    njt_chain_t out;


    if(code == NJT_OK){
        if(msg == NULL || msg->len == 0){
            r->headers_out.status = NJT_HTTP_NO_CONTENT;
        } else{
            r->headers_out.status = NJT_HTTP_OK;
        }
    }else{
        r->headers_out.status = code;
    }
    r->headers_out.content_length_n = 0;
    if(msg != NULL && msg->len > 0){
        njt_str_t type=njt_string("application/json");
        r->headers_out.content_type = type;
        r->headers_out.content_length_n = msg->len;
    }
    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }
    rc = njt_http_send_header(r);
    if(rc == NJT_ERROR || rc > NJT_OK || r->header_only || msg == NULL ||msg->len < 1 ){
        return rc;
    }
    buf = njt_create_temp_buf(r->pool,msg->len);
    if(buf == NULL){
        return NJT_ERROR;
    }
    njt_memcpy(buf->pos,msg->data, msg->len);
    buf->last = buf->pos + msg->len;
    buf->last_buf = 1;
    out.buf = buf;
    out.next = NULL;
    return njt_http_output_filter(r, &out);
}





static njt_int_t
njt_http_shm_api_set_zone_autoscale(njt_cycle_t *cycle,
    njt_str_t *zone_name, njt_int_t dyn, njt_int_t value)
{
    njt_slab_pool_t   *pool;

    pool = (njt_slab_pool_t *)njt_share_slab_get_pool_by_name(cycle, zone_name, dyn);
    if (pool == NULL) {
        return NJT_HTTP_NOT_FOUND;
    }

    njt_share_slab_set_auotscale(pool, value);

    return NJT_OK;
}


