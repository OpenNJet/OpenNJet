/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */
#include <njt_core.h>
#include <njt_http_kv_module.h>
#include <njt_http.h>
// #include <njt_json_util.h>
#include <njt_rpc_result_util.h>
#include <njt_http_util.h>
#include "njt_dynlog_module.h"
#include "njt_str_util.h"

njt_str_t *njt_dynlog_dump_log_conf(njt_cycle_t *cycle,njt_pool_t *pool) 
{
    njt_http_core_loc_conf_t    *clcf;
    njt_http_core_main_conf_t   *hcmcf;
    njt_http_core_srv_conf_t    **cscfp;
    njt_http_log_main_conf_t    *lmcf;
    njt_http_log_fmt_t          *fmt;
    njt_uint_t                  i,j;
    njt_array_t                 *array;
    njt_str_t                   *tmp_str;
    njt_http_server_name_t      *server_name;
    dynlog_t                    dynjson_obj;
    dynlog_servers_item_t       *server_item;
    dynlog_accessLogFormats_item_t *accessLog_formats_item;

    njt_memzero(&dynjson_obj, sizeof(dynlog_t));
    hcmcf = njt_http_cycle_get_module_main_conf(cycle, njt_http_core_module);
    if(hcmcf == NULL){
        goto err;
    }

    set_dynlog_servers(&dynjson_obj, create_dynlog_servers(pool, 4));
    if(dynjson_obj.servers == NULL){
        goto err;
    }

    cscfp = hcmcf->servers.elts;
    for (i = 0; i < hcmcf->servers.nelts; i++)
    {
        server_item = create_dynlog_servers_item(pool);
        if(server_item == NULL){
            goto err;
        }

        set_dynlog_servers_item_listens(server_item, create_dynlog_servers_item_listens(pool, 4));
        set_dynlog_servers_item_serverNames(server_item, create_dynlog_servers_item_serverNames(pool, 4));
        set_dynlog_servers_item_locations(server_item, create_dynlog_servers_item_locations(pool, 4));

        array = njt_array_create(pool, 4, sizeof(njt_str_t));
        if(array == NULL){
            goto err;
        }
        njt_http_get_listens_by_server(array, cscfp[i]);

        for (j = 0; j < array->nelts; ++j) {
            tmp_str = (njt_str_t *)(array->elts)+ j;
            add_item_dynlog_servers_item_listens(server_item->listens, tmp_str);
        }

        server_name = cscfp[i]->server_names.elts;
        for (j = 0; j < cscfp[i]->server_names.nelts; ++j) {
            tmp_str = &server_name[j].full_name;
            add_item_dynlog_servers_item_serverNames(server_item->serverNames,tmp_str);
        }

        clcf = njt_http_get_module_loc_conf(cscfp[i]->ctx, njt_http_core_module);
        if(clcf != NULL){
            njt_dynlog_dump_locs_json(pool, clcf->old_locations, server_item->locations);
        }

        add_item_dynlog_servers(dynjson_obj.servers, server_item);
    }


    lmcf = njt_http_cycle_get_module_main_conf(cycle,njt_http_log_module);
    if(lmcf == NULL ){
        goto err;
    }

    set_dynlog_accessLogFormats(&dynjson_obj, create_dynlog_accessLogFormats(pool, 4));
    if(dynjson_obj.accessLogFormats == NULL){
        goto err;
    }

    fmt = lmcf->formats.elts;
    for( i = 0; i < lmcf->formats.nelts; i++){
        accessLog_formats_item = njt_pcalloc(pool, sizeof(dynlog_accessLogFormats_item_t));
        if(accessLog_formats_item == NULL){
            goto err;
        }

        if( fmt[i].name.len > 0 ) {
            set_dynlog_accessLogFormat_name(accessLog_formats_item, &fmt[i].name);
        }
        if( fmt[i].escape.len > 0 ){
            if(fmt[i].escape.len == 7 && njt_strncmp(fmt[i].escape.data, "default", 7) ==0){
                set_dynlog_accessLogFormat_escape(accessLog_formats_item, DYNLOG_ACCESSLOGFORMAT_ESCAPE_DEFAULT);
            }else if (fmt[i].escape.len == 4 && njt_strncmp(fmt[i].escape.data, "json", 4) ==0)
            {
                set_dynlog_accessLogFormat_escape(accessLog_formats_item, DYNLOG_ACCESSLOGFORMAT_ESCAPE_JSON);
            }
            else if (fmt[i].escape.len == 4 && njt_strncmp(fmt[i].escape.data, "none", 4) ==0)
            {
                set_dynlog_accessLogFormat_escape(accessLog_formats_item, DYNLOG_ACCESSLOGFORMAT_ESCAPE_NONE);
            }
        }
        if(fmt[i].format.len){
            set_dynlog_accessLogFormat_format(accessLog_formats_item, &fmt[i].format);
        }

        add_item_dynlog_accessLogFormats(dynjson_obj.accessLogFormats, accessLog_formats_item);
    }
    
    return to_json_dynlog(pool, &dynjson_obj, OMIT_NULL_ARRAY | OMIT_NULL_OBJ | OMIT_NULL_STR);

    err:
    return &dynlog_update_srv_err_msg;
}

