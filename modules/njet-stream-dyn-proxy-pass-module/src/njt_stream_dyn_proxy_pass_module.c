/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */
#include <njt_core.h>
#include <njt_http_kv_module.h>
#include <njt_http.h>
#include <njt_json_util.h>
#include <njt_stream_util.h>
#include <njt_stream_dyn_module.h>
#include <njt_rpc_result_util.h>
#include "njt_stream_dyn_proxy_pass_parser.h"
#include <njt_stream_proxy_module.h>
#include <njt_http_ext_module.h>
// njt_stream_proxy_srv_conf_t
extern njt_module_t njt_stream_proxy_module;

njt_str_t dyn_proxy_pass_update_srv_err_msg = njt_string("{\"code\":500,\"msg\":\"server error\"}");

/*
static njt_uint_t  njt_stream_dyn_proxy_pass_get_args(njt_conf_t *cf,njt_pool_t *pool,njt_str_t src) {
  //njt_conf_t cf;
  njt_str_t  new_src;
  njt_memzero(cf, sizeof(njt_conf_t));
  cf->pool = pool;
  cf->temp_pool = pool;
  cf->log = njt_cycle->log;


  if(src.len == 0) {
    return NJT_ERROR;
  }
    new_src.len = src.len + 3;
    new_src.data = njt_pcalloc(pool,new_src.len);  //add " {"
    if (new_src.data == NULL){
        return NJT_ERROR;
    }
    njt_memcpy(new_src.data,src.data,src.len);
    new_src.data[new_src.len - 3] = ' ';
    new_src.data[new_src.len - 2] = '{';
    new_src.data[new_src.len - 1] = '\0';

  cf->args = njt_array_create(cf->pool, 10, sizeof(njt_str_t));
    if (cf->args == NULL) {
        return NJT_ERROR;
    }
   njt_conf_read_memory_token(cf,new_src);
   return NJT_OK;
}

static njt_int_t njt_stream_dyn_proxy_pass_check_var(njt_str_t *name){

    njt_uint_t                  i;
    njt_stream_core_main_conf_t  *cmcf;
    njt_hash_key_t             *key;
    njt_stream_variable_t        *pv;

    if (name->len == 0) {
        return NJT_ERROR;
    }

    cmcf = njt_stream_cycle_get_module_main_conf(njt_cycle, njt_stream_core_module);
    key = cmcf->variables_keys->keys.elts;

    key = cmcf->variables_keys->keys.elts;
    pv = cmcf->prefix_variables.elts;
    for (i = 0; i < cmcf->variables_keys->keys.nelts; i++) {
        if(name->len == key[i].key.len
            && njt_strncmp(name->data, key[i].key.data,name->len)
                == 0)
        {
            return NJT_OK;
        }
    }
    for (i = 0; i < cmcf->prefix_variables.nelts; i++) {
        if (name->len >= pv[i].name.len
            && njt_strncmp(name->data, pv[i].name.data, pv[i].name.len)
                == 0)
        {
            return NJT_OK;
        }
    }

    return NJT_ERROR;
}
*/
/*
static njt_str_t
njt_stream_dyn_proxy_pass_check_url_variable(njt_str_t *source)
{
    u_char       ch;
    njt_str_t    name;
    njt_uint_t   i, bracket;
    njt_int_t    rc;

    for (i = 0; i < source->len; ) {

        name.len = 0;

        if (source->data[i] == '$') {

            if (++i == source->len) {
                njt_str_set(&name,"$");
                goto invalid_variable;
            }
            if (source->data[i] == '{') {
                bracket = 1;

                if (++i == source->len) {
                    njt_str_set(&name,"{");
                    goto invalid_variable;
                }

                name.data = &source->data[i];

            } else {
                bracket = 0;
                name.data = &source->data[i];
            }

            for (; i < source->len; i++, name.len++) {
                ch = source->data[i];

                if (ch == '}' && bracket) {
                    i++;
                    bracket = 0;
                    break;
                }

                if ((ch >= 'A' && ch <= 'Z')
                    || (ch >= 'a' && ch <= 'z')
                    || (ch >= '0' && ch <= '9')
                    || ch == '_')
                {
                    continue;
                }

                break;
            }

            if (bracket) {
                njt_str_set(&name,"{");
                goto invalid_variable;
            }

            if (name.len == 0) {
                njt_str_set(&name,"null variable");
                goto invalid_variable;
            }
            rc = njt_stream_dyn_proxy_pass_check_var(&name);
            if(rc == NJT_ERROR) {
                goto invalid_variable;
            }
            continue;
        }



        name.data = &source->data[i];

        while (i < source->len) {

            if (source->data[i] == '$') {
                break;
            }

            i++;
            name.len++;
        }
        //check variable  name

    }
njt_str_set(&name,"");
return name;

invalid_variable:
    return name;
}
*/

/*
接口url_data  如果包含变量。http://backend1$uri 会被 http://backend1 处理。 提取 backend1
*/

static njt_stream_upstream_srv_conf_t *njt_stream_dyn_proxy_pass_find_upstream_by_url(njt_str_t *url_data)
{
    njt_stream_upstream_main_conf_t *umcf;
    njt_uint_t i;
    njt_stream_upstream_srv_conf_t *uscf, **uscfp;
    njt_pool_t *pool;
    njt_url_t u_data, *u;
    njt_str_t *url, new_url;

    if (url_data == NULL || url_data->len == 0)
    {
        return NULL;
    }
    new_url = *url_data;

    for (i = 0; i < new_url.len; i++)
    {
        if (new_url.data[i] == '$')
        {
            new_url.len = i;
            break;
        }
    }

    url = &new_url;
    umcf = njt_stream_cycle_get_module_main_conf(njt_cycle, njt_stream_upstream_module);
    if (umcf == NULL)
    {
        return NULL;
    }

    pool = njt_create_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
    if (NULL == pool)
    {
        return NULL;
    }
    u = &u_data;
    njt_memzero(&u_data, sizeof(njt_url_t));
    u_data.url.len = url->len;
    u_data.url.data = url->data;
    u_data.uri_part = 1;
    u_data.no_resolve = 1;
    u_data.default_port = 0;

    uscf = NULL;
    if (njt_parse_url(pool, u) != NJT_OK)
    {
        goto end;
    }

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++)
    {

        if (uscfp[i]->host.len != u->host.len || njt_strncasecmp(uscfp[i]->host.data, u->host.data, u->host.len) != 0)
        {
            continue;
        }
        if (uscfp[i]->port != u->port) {
            continue;
        }
        uscf = uscfp[i];
        goto end;
    }
end:
    if (pool != NULL)
    {
        njt_destroy_pool(pool);
    }
    return uscf;
}

char *
njt_stream_dyn_set_proxy_pass(njt_stream_core_srv_conf_t *cscf, njt_str_t pass_url, njt_rpc_result_t *rpc_result)
{

    u_char data_buf[NJT_MAX_CONF_ERRSTR];
    njt_str_t *url;
    njt_url_t u;
    njt_conf_t *cf, conf;
    njt_int_t rc;
    njt_stream_upstream_srv_conf_t *upstream, *old_upstream;
    njt_str_t rpc_data_str;
    njt_stream_proxy_srv_conf_t *pscf;
    u_char *end;
    njt_stream_complex_value_t cv;
    njt_stream_compile_complex_value_t ccv;
    njt_conf_file_t      conf_file;
    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;

    pscf = cscf->ctx->srv_conf[njt_stream_proxy_module.ctx_index];
    if (pscf == NULL)
    {
        return NJT_CONF_ERROR;
    }
    // 没有变化的。
    if (pscf->ori_url.len == pass_url.len && njt_memcmp(pscf->ori_url.data, pass_url.data, pass_url.len) == 0)
    {
        return NJT_CONF_OK;
    }
    //直接取正在用的。
    old_upstream = pscf->upstream;
    if (pscf->ori_url.len == 0 || pscf->ori_url.data == NULL)
    {
        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "server[%V] can`t change proxy_pass!", &cscf->server_name);
        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, "server[%V] can`t change proxy_pass!", &cscf->server_name);
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

        return NJT_CONF_ERROR;
    }
    // 判断新的proxy_pass 是否是 upstream 名。
    upstream = njt_stream_dyn_proxy_pass_find_upstream_by_url(&pass_url);
    if (upstream == NULL)
    {
    }
    else if (upstream != NULL && upstream->type != NULL)
    {
        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "proxy_pass[%V] type[%V] error!", &pass_url, upstream->type);
        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, "proxy_pass[%V] type[%V] error!", &pass_url, upstream->type);
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
        return NJT_CONF_ERROR;
    }

    cf = &conf;
    njt_memzero(&ccv, sizeof(njt_stream_compile_complex_value_t));
    njt_memzero(cf, sizeof(njt_conf_t)); // njt_stream_proxy_vars_t   proxy_vars;

    njt_pool_t *new_pool = njt_create_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
    if (NULL == new_pool)
    {
        return NJT_CONF_ERROR;
    }
    rc = njt_sub_pool(cscf->pool, new_pool);
    if (rc != NJT_OK)
    {
        njt_destroy_pool(new_pool);
        return NJT_CONF_ERROR;
    }
    url = &pass_url;
    url->data = njt_pstrdup(new_pool, &pass_url);
    if (url->data == NULL)
    {
        njt_destroy_pool(new_pool);
        return NJT_CONF_ERROR;
    }
    url->len = pass_url.len;

    njt_memzero(&conf_file,sizeof(conf_file));
    njt_str_set(&conf_file.file.name,"api");
    conf_file.file.fd = 0;
    conf_file.line = 0;
    cf->conf_file = &conf_file;
    cf->args = NULL;
    cf->pool = new_pool;
    cf->temp_pool = new_pool;
    cf->ctx = (njt_stream_conf_ctx_t *)njt_get_conf(njt_cycle->conf_ctx, njt_stream_module);
    cf->cycle = (njt_cycle_t *)njt_cycle;
    cf->log = njt_cycle->log;
    cf->module_type = NJT_STREAM_MODULE;
    cf->cmd_type = NJT_STREAM_SRV_CONF;
    cf->dynamic = 1;
    rpc_data_str.len = NJT_MAX_CONF_ERRSTR;
    cf->errstr = &rpc_data_str;
    ccv.cf = cf;
    ccv.value = url;
    ccv.complex_value = &cv;

    if (njt_stream_compile_complex_value(&ccv) != NJT_OK)
    {
         if(cf->errstr->len == NJT_MAX_CONF_ERRSTR) {
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, "proxy_pass[%V] complex error", &pass_url);
            rpc_data_str.len = end - data_buf;
        }
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
        njt_destroy_pool(new_pool);
        return NJT_CONF_ERROR;
    }

    if (cv.lengths)
    {
        pscf->upstream_value = njt_palloc(cf->pool,
                                          sizeof(njt_stream_complex_value_t));
        if (pscf->upstream_value == NULL)
        {
            njt_destroy_pool(new_pool);
            return NJT_CONF_ERROR;
        }
        if (old_upstream != NULL && old_upstream->ref_count > 0)
        {
            njt_log_debug(NJT_LOG_DEBUG_STREAM, njt_cycle->log, 0, "var njt_stream_dyn_set_proxy_pass del old_upstream=%V,port=%d,ref_count=%d,client_count=%d",&old_upstream->host,old_upstream->port,old_upstream->ref_count,old_upstream->client_count);	
            old_upstream->ref_count--;
            njt_stream_upstream_del((njt_cycle_t *)njt_cycle, old_upstream);
        }
        pscf->upstream = NULL;
        if (pscf->pool != NULL)
        {
            njt_destroy_pool(pscf->pool);
        }
        pscf->pool = new_pool;
        *pscf->upstream_value = cv;
        pscf->ori_url = *url;
        return NJT_CONF_OK;
    }

    njt_memzero(&u, sizeof(njt_url_t));

    u.url = *url;
    u.no_resolve = 1;

    
    pscf->upstream = njt_stream_upstream_add(cf, &u, 0);
    if (pscf->upstream == NULL)
    {
        if(cf->errstr->len == NJT_MAX_CONF_ERRSTR) {
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, "proxy_pass[%V] resolve_host error", &pass_url);
            rpc_data_str.len = end - data_buf;
        }
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);

        njt_destroy_pool(new_pool);
        return NJT_CONF_ERROR;
    }
    pscf->upstream_value = NULL;
    pscf->ori_url = *url;
    if (pscf->pool != NULL)
    {
        njt_destroy_pool(pscf->pool);
    }
    pscf->pool = new_pool;
    if (old_upstream != NULL && old_upstream->ref_count > 0)
    {
        njt_log_debug(NJT_LOG_DEBUG_STREAM, njt_cycle->log, 0, "njt_stream_dyn_set_proxy_pass del old_upstream=%V,port=%d,ref_count=%d,client_count=%d",&old_upstream->host,old_upstream->port,old_upstream->ref_count,old_upstream->client_count);	
        old_upstream->ref_count--;
        njt_stream_upstream_del((njt_cycle_t *)njt_cycle, old_upstream);
    }
    return NJT_CONF_OK;
}

static njt_int_t njt_dyn_proxy_pass_update_srv(njt_stream_core_srv_conf_t *cscf, njt_str_t *proxy_pass, njt_rpc_result_t *rpc_result)
{
    char * rv;
    rv = njt_stream_dyn_set_proxy_pass(cscf, *proxy_pass, rpc_result);
    if(rv != NULL) 
    {
        return NJT_ERROR;
    }
    return NJT_OK;
}

static void njt_dyn_proxy_pass_dump_srv(njt_pool_t *pool, njt_stream_core_srv_conf_t *cscf, stream_proxypass_servers_item_t *server_item)
{
    njt_stream_proxy_srv_conf_t *plcf;
    njt_str_t defalut = njt_string("");

    plcf = cscf->ctx->srv_conf[njt_stream_proxy_module.ctx_index];
    if (plcf != NULL && plcf->ori_url.len != 0)
    {
        set_stream_proxypass_servers_item_proxy_pass(server_item, &plcf->ori_url);
    }
    else
    {
        // set_proxypass_servers_item_proxy_pass
        set_stream_proxypass_servers_item_proxy_pass(server_item, &defalut);
    }
}

static njt_str_t *njt_dyn_proxy_pass_dump_conf(njt_cycle_t *cycle, njt_pool_t *pool)
{

    njt_stream_core_main_conf_t *hcmcf;
    njt_stream_core_srv_conf_t **cscfp;
    njt_uint_t i, j;
    njt_array_t *array;
    njt_str_t *tmp_str;
    njt_stream_server_name_t *server_name;

    stream_proxypass_t dynjson_obj;
    stream_proxypass_servers_item_t *server_item;

    njt_memzero(&dynjson_obj, sizeof(stream_proxypass_t));
    hcmcf = njt_stream_cycle_get_module_main_conf(cycle, njt_stream_core_module);
    if (hcmcf == NULL)
    {
        goto err;
    }

    set_stream_proxypass_servers(&dynjson_obj, create_stream_proxypass_servers(pool, 4));
    if (dynjson_obj.servers == NULL)
    {
        goto err;
    }

    cscfp = hcmcf->servers.elts;
    for (i = 0; i < hcmcf->servers.nelts; i++)
    {
        server_item = create_stream_proxypass_servers_item(pool);
        if (server_item == NULL)
        {
            goto err;
        }

        set_stream_proxypass_servers_item_listens(server_item, create_stream_proxypass_servers_item_listens(pool, 4));
        set_stream_proxypass_servers_item_serverNames(server_item, create_stream_proxypass_servers_item_serverNames(pool, 4));
        // set_proxypass_servers_item_locations(server_item, create_proxypass_servers_item_locations(pool, 4));

        array = njt_array_create(pool, 4, sizeof(njt_str_t));
        if (array == NULL)
        {
            goto err;
        }
        njt_stream_get_listens_by_server(array, cscfp[i]);

        for (j = 0; j < array->nelts; ++j)
        {
            tmp_str = (njt_str_t *)(array->elts) + j;
            add_item_stream_proxypass_servers_item_listens(server_item->listens, tmp_str);
        }

        server_name = cscfp[i]->server_names.elts;
        for (j = 0; j < cscfp[i]->server_names.nelts; ++j)
        {
            tmp_str = &server_name[j].full_name;
            add_item_stream_proxypass_servers_item_serverNames(server_item->serverNames, tmp_str);
        }
        njt_dyn_proxy_pass_dump_srv(pool, cscfp[i], server_item);
        add_item_stream_proxypass_servers(dynjson_obj.servers, server_item);
    }

    return to_json_stream_proxypass(pool, &dynjson_obj, OMIT_NULL_ARRAY | OMIT_NULL_OBJ | OMIT_NULL_STR);

err:
    return &dyn_proxy_pass_update_srv_err_msg;
}

static njt_int_t njt_dyn_proxy_pass_update_conf(njt_pool_t *pool, stream_proxypass_t *api_data, njt_rpc_result_t *rpc_result)
{

    njt_cycle_t *cycle;
    njt_stream_core_srv_conf_t *cscf;
    stream_proxypass_servers_item_t *dsi;
    njt_str_t *port;
    njt_str_t *serverName;
    njt_str_t *proxy_pass;
    njt_uint_t i;
    njt_int_t rc;
    u_char data_buf[1024];
    u_char *end;
    njt_str_t rpc_data_str;
    rpc_data_str.data = data_buf;

    cycle = (njt_cycle_t *)njt_cycle;

    // empty path
    rpc_data_str.len = 0;
    njt_rpc_result_set_conf_path(rpc_result, &rpc_data_str);

    for (i = 0; i < api_data->servers->nelts; i++)
    {
        dsi = get_stream_proxypass_servers_item(api_data->servers, i);
        port = get_stream_proxypass_servers_item_listens_item(dsi->listens, 0);
        serverName = get_stream_proxypass_servers_item_serverNames_item(dsi->serverNames, 0);
        proxy_pass = get_stream_proxypass_servers_item_proxy_pass(dsi);
        if (dsi->listens->nelts < 1)
        {
            // listens or server_names is empty
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " server parameters error, listens or serverNames is empty,at position %d", i);
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            continue;
        }

        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, "servers[%V,%V]", port, serverName);
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_set_conf_path(rpc_result, &rpc_data_str);

        cscf = njt_stream_get_srv_by_port(cycle, port, serverName);
        if (cscf == NULL)
        {
            if (port != NULL && serverName != NULL)
            {
                njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "can`t find server by listen:%V server_name:%V;",
                              port, serverName);

                end = njt_snprintf(data_buf, sizeof(data_buf) - 1, "can not find server.");
                rpc_data_str.len = end - data_buf;
                njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            }
            continue;
        }

        rc = njt_dyn_proxy_pass_update_srv(cscf, proxy_pass, rpc_result);
        if (rc == NJT_OK)
        {
            njt_rpc_result_add_success_count(rpc_result);
        }
    }
    njt_rpc_result_update_code(rpc_result);

    return NJT_OK;
}

static u_char *njt_dyn_proxy_pass_rpc_get_handler(njt_str_t *topic, njt_str_t *request, int *len, void *data)
{
    njt_cycle_t *cycle;
    njt_str_t *msg;
    u_char *buf;
    njt_pool_t *pool = NULL;

    buf = NULL;
    cycle = (njt_cycle_t *)njt_cycle;
    *len = 0;

    pool = njt_create_pool(njt_pagesize, njt_cycle->log);
    if (pool == NULL)
    {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_proxy_pass_rpc_handler create pool error");
        goto out;
    }

    msg = njt_dyn_proxy_pass_dump_conf(cycle, pool);
    buf = njt_calloc(msg->len, cycle->log);
    if (buf == NULL)
    {
        goto out;
    }

    njt_memcpy(buf, msg->data, msg->len);
    *len = msg->len;

out:
    if (pool != NULL)
    {
        njt_destroy_pool(pool);
    }

    return buf;
}

static int njt_dyn_proxy_pass_change_handler_internal(njt_str_t *key, njt_str_t *value, void *data, njt_str_t *out_msg)
{
    njt_int_t rc;
    stream_proxypass_t *api_data = NULL;
    njt_pool_t *pool = NULL;
    njt_json_manager json_manager;
    njt_rpc_result_t *rpc_result;
    js2c_parse_error_t err_info;

    if (value->len < 2)
    {
        return NJT_OK;
    }

    njt_memzero(&json_manager, sizeof(njt_json_manager));
    pool = NULL;
    rpc_result = njt_rpc_result_create();
    if (!rpc_result)
    {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "can't create rpc result");
        rc = NJT_ERROR;
        goto end;
    }
    njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_SUCCESS);
    pool = njt_create_pool(njt_pagesize, njt_cycle->log);
    if (pool == NULL)
    {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_proxy_pass_change_handler create pool error");
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_MEM_ALLOC);
        rc = NJT_ERROR;
        goto rpc_msg;
    }

    api_data = json_parse_stream_proxypass(pool, value, &err_info);
    if (api_data == NULL)
    {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "json_parse_proxypass err: %V", &err_info.err_str);
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_JSON);
        njt_rpc_result_set_msg2(rpc_result, &err_info.err_str);
        rc = NJT_ERROR;
        goto rpc_msg;
    }

    rc = njt_dyn_proxy_pass_update_conf(pool, api_data, rpc_result);

rpc_msg:
    if (out_msg)
    {
        njt_rpc_result_to_json_str(rpc_result, out_msg);
    }
end:
    if (pool != NULL)
    {
        njt_destroy_pool(pool);
    }
    if (rpc_result)
    {
        njt_rpc_result_destroy(rpc_result);
    }

    return rc;
}

static int njt_dyn_proxy_pass_change_handler(njt_str_t *key, njt_str_t *value, void *data)
{
    return njt_dyn_proxy_pass_change_handler_internal(key, value, data, NULL);
}

static u_char *njt_dyn_proxy_pass_rpc_put_handler(njt_str_t *topic, njt_str_t *request, int *len, void *data)
{
    njt_str_t err_json_msg;
    njt_str_null(&err_json_msg);
    njt_dyn_proxy_pass_change_handler_internal(topic, request, data, &err_json_msg);
    *len = err_json_msg.len;
    return err_json_msg.data;
}

static njt_int_t njt_stream_dyn_proxy_pass_module_init_process(njt_cycle_t *cycle)
{
    njt_str_t proxy_pass_rpc_key = njt_string("stream_proxy_pass");
    njt_str_t obj_vs_key = njt_string(VS_DEL_STREAM_EVENT); // 删除VS 的事件名

    njt_kv_reg_handler_t h;
    njt_memzero(&h, sizeof(njt_kv_reg_handler_t));
    h.key = &proxy_pass_rpc_key;
    h.rpc_get_handler = njt_dyn_proxy_pass_rpc_get_handler;
    h.rpc_put_handler = njt_dyn_proxy_pass_rpc_put_handler;
    h.handler = njt_dyn_proxy_pass_change_handler;
    h.api_type = NJT_KV_API_TYPE_DECLATIVE;
    njt_kv_reg_handler(&h);

    njt_regist_update_fullconfig(&obj_vs_key, &proxy_pass_rpc_key); // 注册删除VS 时更新全量配置

    return NJT_OK;
}

static njt_stream_module_t njt_stream_dyn_proxy_pass_module_ctx = {
    NULL, /* preconfiguration */
    NULL, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL  /* merge server configuration */
};

njt_module_t njt_stream_dyn_proxy_pass_module = {
    NJT_MODULE_V1,
    &njt_stream_dyn_proxy_pass_module_ctx,         /* module context */
    NULL,                                          /* module directives */
    NJT_STREAM_MODULE,                             /* module type */
    NULL,                                          /* init master */
    NULL,                                          /* init module */
    njt_stream_dyn_proxy_pass_module_init_process, /* init process */
    NULL,                                          /* init thread */
    NULL,                                          /* exit thread */
    NULL,                                          /* exit process */
    NULL,                                          /* exit master */
    NJT_MODULE_V1_PADDING};
