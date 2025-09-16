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
#include <math.h>
#include <njt_http_kv_module.h>
#include <njt_http_util.h>
#include <njt_http_sendmsg_module.h>
#include <njt_stream_dyn_server_module.h>
#include <njt_rpc_result_util.h>
#include "js2c_njet_builtins.h"
#include <njt_str_util.h>
#include <njt_http_ext_module.h>
#include <njt_stream_util.h>
#include <njt_stream_proxy_module.h>
extern njt_uint_t njt_worker;

extern njt_conf_check_cmd_handler_pt njt_conf_check_cmd_handler;
extern njt_int_t njt_stream_optimize_servers(njt_conf_t *cf,
											 njt_stream_core_main_conf_t *cmcf, njt_array_t *ports);

// dyn_listen
extern njt_int_t
njt_stream_start_dyn_listen(njt_conf_t *cf, njt_uint_t pos);
extern void
njt_stream_delete_dyn_ports(njt_cycle_t *cycle);
// dyn_listen end

extern njt_int_t
njt_stream_variables_init_vars_dyn(njt_conf_t *cf);

extern njt_int_t
njt_stream_ssl_dynamic_init(njt_conf_t *cf, njt_stream_addr_conf_t *addr_conf);

njt_str_t njt_del_headtail_space(njt_str_t src);

static njt_int_t
njt_stream_dyn_server_init_worker(njt_cycle_t *cycle);

static njt_int_t
njt_stream_dyn_server_delete_configure_server();

static njt_int_t njt_stream_dyn_server_write_data(njt_stream_dyn_server_info_t *server_info);

static njt_int_t njt_stream_dyn_server_post_merge_servers();
static njt_int_t njt_stream_dyn_server_delete_dirtyservers(njt_stream_dyn_server_info_t *server_info);
static njt_stream_addr_conf_t *njt_stream_get_ssl_by_port(njt_cycle_t *cycle, njt_str_t *addr_port);
static njt_int_t njt_stream_check_server_body(njt_str_t cmd,void *data);
static void njt_stream_server_delete_dyn_var(njt_stream_core_srv_conf_t *cscf);
static njt_int_t njt_stream_dyn_server_init(njt_conf_t *cf);
static char *
njt_stream_merge_servers(njt_conf_t *cf, njt_stream_core_main_conf_t *cmcf,
						 njt_stream_module_t *module, njt_uint_t ctx_index);
typedef struct njt_stream_dyn_server_ctx_s
{
} njt_stream_dyn_server_ctx_t, njt_stream_stream_dyn_server_ctx_t;

static njt_stream_module_t njt_stream_dyn_server_module_ctx = {
	NULL,						/* preconfiguration */
	njt_stream_dyn_server_init, /* postconfiguration */

	NULL, /* create main configuration */
	NULL, /* init main configuration */

	NULL, /* create server configuration */
	NULL, /* merge server configuration */
};

njt_module_t njt_stream_dyn_server_module = {
	NJT_MODULE_V1,
	&njt_stream_dyn_server_module_ctx, /* module context */
	NULL,							   /* module directives */
	NJT_STREAM_MODULE,				   /* module type */
	NULL,							   /* init master */
	NULL,							   /* init module */
	njt_stream_dyn_server_init_worker, /* init process */
	NULL,							   /* init thread */
	NULL,							   /* exit thread */
	NULL,							   /* exit process */
	NULL,							   /* exit master */
	NJT_MODULE_V1_PADDING};

static njt_str_t njt_invalid_dyn_server_body[] = {
	njt_string("zone"),
	njt_string("location"),
	// njt_string("if"),
	njt_string("ssl_ocsp"),
	njt_string("ssl_stapling"),
	njt_string("quic"),
	njt_null_string};

static njt_int_t njt_stream_dyn_server_access_handler(njt_stream_session_t *s)
{
	// njt_connection_t *c;
	njt_str_t host;
	// njt_str_t addr = njt_string("127.0.0.1");
	njt_stream_core_srv_conf_t *cscf = NULL;
	njt_str_t mesh_server_name = njt_string("mesh_server_name");
	njt_str_t name_low;
	njt_uint_t proto_hash;
	njt_stream_variable_value_t *vv;

	njt_str_set(&host, "");
	// mesh_server_name
	name_low.len = mesh_server_name.len;
	name_low.data = njt_pcalloc(s->connection->pool, name_low.len);
	proto_hash = njt_hash_strlow(name_low.data, mesh_server_name.data, mesh_server_name.len);
	vv = njt_stream_get_variable(s, &name_low, proto_hash);
	if (vv != NULL && 0 == vv->not_found)
	{
		host.data = vv->data;
		host.len = vv->len;
		njt_stream_find_virtual_server(s, &host, &cscf);
		if (cscf != NULL)
		{
			njt_stream_set_virtual_server(s, cscf);
		}
	} /*else {
	   //njtmesh_port
	   name_low.len = name.len;
	   name_low.data = njt_pcalloc(s->connection->pool,name_low.len);
	   proto_hash = njt_hash_strlow(name_low.data,name.data,name.len);
	   vv =  njt_stream_get_variable(s, &name_low, proto_hash);
	   if(vv != NULL && 0 == vv->not_found){
		   proxy_port = njt_atoi(vv->data, vv->len);
		   if(proxy_port != NJT_ERROR)
		   {
			   p = njt_snprintf(buffer,sizeof(buffer),"server-%d",proxy_port);
			   host.data = buffer;
			   host.len = p - buffer;
			   njt_stream_find_virtual_server(s,&host,&cscf);
			   if(cscf != NULL) {
				   njt_stream_set_virtual_server(s,cscf);
			   }
		   }
	   }
	}*/
	return NJT_DECLINED;
}

static njt_int_t njt_stream_dyn_server_init(njt_conf_t *cf)
{
	njt_stream_handler_pt *h;
	njt_stream_core_main_conf_t *cmcf;

	cmcf = njt_stream_conf_get_module_main_conf(cf, njt_stream_core_module);

	h = njt_array_push(&cmcf->phases[NJT_STREAM_ACCESS_PHASE].handlers);
	if (h == NULL)
	{
		return NJT_ERROR;
	}

	*h = njt_stream_dyn_server_access_handler;

	return NJT_OK;
}

static njt_int_t
njt_stream_dyn_server_delete_handler(njt_stream_dyn_server_info_t *server_info)
{
	njt_stream_core_srv_conf_t *cscf;
	u_char *p;
	njt_stream_core_main_conf_t *cmcf;
	njt_pool_t *old_pool;
	njt_conf_t conf;
	njt_int_t rc = NJT_OK;

	if (server_info->buffer.len == 0 || server_info->buffer.data == NULL)
	{
		njt_log_error(NJT_LOG_DEBUG, njt_cycle->pool->log, 0, "buffer null");
		njt_str_set(&server_info->msg, "error:buffer null!");
		return NJT_ERROR;
	}

	cscf = server_info->cscf;
	if (cscf == NULL)
	{
		if (cscf == NULL)
		{
			p = njt_snprintf(server_info->buffer.data, server_info->buffer.len, "error:host[%V],no find server [%V]!", &server_info->addr_port, &server_info->server_name);
			server_info->msg = server_info->buffer;
			server_info->msg.len = p - server_info->buffer.data;
			njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0, "host[%V],no find server [%V]!", &server_info->addr_port, &server_info->server_name);
		}
		else if (cscf != NULL)
		{
			njt_str_set(&server_info->msg, "error:server is null!");
			njt_log_error(NJT_LOG_DEBUG, njt_cycle->pool->log, 0, "error:server is null!");
		}
		else
		{
			njt_str_set(&server_info->msg, "no find server!");
			njt_log_error(NJT_LOG_DEBUG, njt_cycle->pool->log, 0, "host[%V],no find server [%V]!", &server_info->addr_port, &server_info->server_name);
		}
		return NJT_ERROR;
	}

	rc = njt_stream_dyn_server_delete_configure_server(cscf, server_info);
	if (rc != NJT_OK)
	{
		// rc = NJT_ERROR;
		goto out;
	}
	cmcf = njt_stream_cycle_get_module_main_conf(njt_cycle, njt_stream_core_module);

	old_pool = cmcf->dyn_vs_pool;
	cmcf->dyn_vs_pool = NULL;
	cmcf->dyn_vs_pool = njt_create_dynamic_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
	if (cmcf->dyn_vs_pool == NULL)
	{
		rc = NJT_ERROR;
		goto out;
	}
	rc = njt_sub_pool(njt_cycle->pool, cmcf->dyn_vs_pool);
	if (rc != NJT_OK)
	{
		njt_destroy_pool(cmcf->dyn_vs_pool);
		cmcf->dyn_vs_pool = old_pool;
		rc = NJT_ERROR;
		goto out;
	}
	njt_memzero(&conf, sizeof(njt_conf_t));
	conf.dynamic = 1;
	conf.pool = cmcf->dyn_vs_pool;
	conf.temp_pool = cmcf->dyn_vs_pool;
	conf.module_type = NJT_CORE_MODULE;
	conf.cmd_type = NJT_MAIN_CONF;
	conf.cycle = (njt_cycle_t *)njt_cycle;
	conf.ctx = njt_cycle->conf_ctx;
	conf.log = njt_cycle->log;

	njt_stream_delete_dyn_ports(conf.cycle); // dyn_listen
	if (njt_stream_optimize_servers(&conf, cmcf, cmcf->ports) != NJT_OK)
	{
		njt_destroy_pool(cmcf->dyn_vs_pool);
		cmcf->dyn_vs_pool = old_pool;
		rc = NJT_ERROR;
		goto out;
	}

	if (old_pool != NULL)
	{
		njt_destroy_pool(old_pool);
	}
	// note: delete queue memory, which delete when remove queue
	njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0, "delete  server [%V] succ!", &server_info->server_name);
	return NJT_OK;
out:
	return rc;
}

static njt_int_t njt_stream_add_server_handler(njt_stream_dyn_server_info_t *server_info, njt_uint_t from_api_add)
{
	njt_conf_t conf;
	njt_int_t rc = NJT_OK;
	njt_int_t ret = NJT_OK;
	u_char *p;
	char *rv = NULL;
	njt_flag_t del = 0;
	njt_pool_t *old_pool = NULL;
	njt_stream_conf_ctx_t *stream_ctx;
	njt_str_t server_name;
	njt_str_t server_path; // = njt_string("./conf/add_server.txt");
	njt_stream_core_main_conf_t *cmcf;
	njt_stream_core_srv_conf_t *cscf;
	njt_uint_t s;
	njt_stream_core_srv_conf_t **cscfp;
	njt_conf_check_cmd_handler_t check_cmd;
	njt_uint_t  old_ls_nelts; // dyn_listen

	// njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "add server start +++++++++++++++");
	if (server_info->buffer.len == 0 || server_info->buffer.data == NULL)
	{
		njt_log_error(NJT_LOG_DEBUG, njt_cycle->pool->log, 0, "buffer null");
		njt_str_set(&server_info->msg, "error:buffer null!");
		return NJT_ERROR;
	}

	server_path.len = 0;
	server_path.data = NULL;
	if (server_info->file.len != 0)
	{
		server_path = server_info->file;
	}
	server_name = server_info->server_name;
	cscf = server_info->cscf;
	if (cscf != NULL)
	{
		p = njt_snprintf(server_info->buffer.data, server_info->buffer.len, "error:[%V] server[%V] exist!", &server_info->addr_port, &server_info->server_name);
		server_info->msg = server_info->buffer;
		server_info->msg.len = p - server_info->buffer.data;
		njt_log_error(NJT_LOG_DEBUG, njt_cycle->pool->log, 0, "%V", &server_info->msg);
		return NJT_RPC_NOT_ALLOW;
	}

	if (server_path.len == 0)
	{
		// njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "add server error:server_path=0");
		njt_str_set(&server_info->msg, "add server error:server_path=0");
		rc = NJT_ERROR;
		goto out;
	}

	if (rc == NJT_ERROR || rc > NJT_OK)
	{
		// njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "add server error!");
		njt_str_set(&server_info->msg, "add server error!");
		rc = NJT_ERROR;
		goto out;
	}

	njt_memzero(&conf, sizeof(njt_conf_t));
	conf.args = njt_array_create(server_info->pool, 10, sizeof(njt_str_t));
	if (conf.args == NULL)
	{
		njt_str_set(&server_info->msg, "add server njt_array_create error!");
		// njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "add  server[%V] error:args allocate fail!",&server_name);
		rc = NJT_ERROR;
		goto out;
	}

	server_info->msg.len = NJT_MAX_CONF_ERRSTR;
	server_info->msg.data = server_info->buffer.data;
	if (server_info->msg.data != NULL)
	{
		njt_memzero(server_info->msg.data, server_info->msg.len);
		conf.errstr = &server_info->msg;
	}

	cmcf = njt_stream_cycle_get_module_main_conf(njt_cycle, njt_stream_core_module);
	stream_ctx = (njt_stream_conf_ctx_t *)njt_get_conf(njt_cycle->conf_ctx, njt_stream_module);
	conf.pool = server_info->pool;
	conf.temp_pool = server_info->pool;
	conf.ctx = stream_ctx;
	conf.cycle = (njt_cycle_t *)njt_cycle;
	conf.log = njt_cycle->log;
	conf.module_type = NJT_STREAM_MODULE;
	conf.cmd_type = NJT_STREAM_MAIN_CONF;
	conf.dynamic = 1;
	conf.attr |= from_api_add ? NJT_CONF_ATTR_ADD_FROM_API : 0; // dyn_listen

	// clcf->locations = NULL; // clcf->old_locations;
	// njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "njt_conf_parse start +++++++++++++++");

	del = 1;
	njt_memzero(&check_cmd,sizeof(check_cmd));
	check_cmd.handler = njt_stream_check_server_body;
	check_cmd.data = server_info;
	njt_conf_check_cmd_handler = &check_cmd;

	old_ls_nelts = conf.cycle->listening.nelts; // dyn_listen

	rv = njt_conf_parse(&conf, &server_path);
	if (rv != NULL)
	{
		if (server_info->msg.len == NJT_MAX_CONF_ERRSTR && server_info->msg.data[0] == '\0')
		{
			njt_str_set(&server_info->msg, "njt_conf_parse error!");
		}
		else if (server_info->msg.len != NJT_MAX_CONF_ERRSTR)
		{
			njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "njt_conf_parse  location[%V] error:%V", &server_name, &server_info->msg);
		}

		rc = NJT_ERROR;
		njt_conf_check_cmd_handler = NULL;
		goto out;
	}
	njt_conf_check_cmd_handler = NULL;
	if(server_info->addr_conf && server_info->addr_conf->ssl && (server_info->ssl_certificate != 1 || server_info->ssl_certificate_key != 1)){ // dyn_listen
	// if(server_info->addr_conf->ssl && (server_info->ssl_certificate != 1 || server_info->ssl_certificate_key != 1)){
		if(server_info->ssl_certificate_key == 0) {
			njt_str_set(&server_info->msg,"no ssl_certificate_key!");
		} else if(server_info->ssl_certificate == 0) {
			njt_str_set(&server_info->msg,"no ssl_certificate!");
		} 
		rc = NJT_ERROR;
		goto out;
	}
	// njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "njt_conf_parse end +++++++++++++++");

	cscf = stream_ctx->srv_conf[njt_stream_core_module.ctx_index];
	cscfp = cmcf->servers.elts;
	for (s = 0; s < cmcf->servers.nelts; s++)
	{
		if (cscfp[s]->dynamic_status == 1)
		{
			cscf = cscfp[s];
			break;
		}
	}
	conf.pool = cscf->pool;
	conf.temp_pool = cscf->pool;
	// merge servers
	njt_stream_module_t *module;
	njt_uint_t mi, m;
	// njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "merge start +++++++++++++++");
	for (m = 0; conf.cycle->modules[m]; m++)
	{
		if (conf.cycle->modules[m]->type != NJT_STREAM_MODULE)
		{
			continue;
		}

		module = conf.cycle->modules[m]->ctx;
		mi = conf.cycle->modules[m]->ctx_index;

		rv = njt_stream_merge_servers(&conf, cmcf, module, mi);
		if (rv != NJT_CONF_OK)
		{
			rc = NJT_ERROR;
			njt_str_set(&server_info->msg, "add server error:merge_servers");
			goto out;
		}
	}
	njt_stream_variables_init_vars_dyn(&conf);
	if (njt_stream_ssl_dynamic_init(&conf, server_info->addr_conf) != NJT_OK)
	{
		rc = NJT_ERROR;
		njt_str_set(&server_info->msg, "add server error:no ssl_certificate!");

		goto out;
	}

	old_pool = cmcf->dyn_vs_pool;
	cmcf->dyn_vs_pool = NULL;
	cmcf->dyn_vs_pool = njt_create_dynamic_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
	if (cmcf->dyn_vs_pool == NULL)
	{
		njt_str_set(&server_info->msg, "create pool error!");
		cmcf->dyn_vs_pool = old_pool;
		rc = NJT_ERROR;
		goto out;
	}
	else
	{
		njt_sub_pool(conf.cycle->pool, cmcf->dyn_vs_pool);
	}
	conf.pool = cmcf->dyn_vs_pool;
	conf.temp_pool = cmcf->dyn_vs_pool;
	conf.module_type = NJT_CORE_MODULE;
	conf.cmd_type = NJT_MAIN_CONF;
	conf.ctx = njt_cycle->conf_ctx;
	if (njt_stream_optimize_servers(&conf, cmcf, cmcf->ports) != NJT_OK)
	{
		njt_str_set(&server_info->msg, "njt_stream_optimize_servers error!");
		njt_stream_dyn_server_delete_dirtyservers(server_info);
		njt_destroy_pool(cmcf->dyn_vs_pool);
		cmcf->dyn_vs_pool = old_pool;
		rc = NJT_ERROR;
		del = 0;
		goto out;
	}


    // dyn_listen
    if (conf.cycle->listening.nelts > old_ls_nelts) {
		server_info->addr_conf = njt_stream_get_ssl_by_port(conf.cycle, &server_info->addr_port);
        if(server_info->addr_conf->ssl && (server_info->ssl_certificate != 1 || server_info->ssl_certificate_key != 1)){
			if(server_info->ssl_certificate_key == 0) {
				njt_str_set(&server_info->msg,"no ssl_certificate_key!");
			} else if(server_info->ssl_certificate == 0) {
				njt_str_set(&server_info->msg,"no ssl_certificate!");
			}
			njt_stream_dyn_server_delete_dirtyservers(server_info);
			njt_destroy_pool(cmcf->dyn_vs_pool);
			njt_stream_delete_dyn_ports(conf.cycle); // dyn_listen
			cmcf->dyn_vs_pool = old_pool;
			rc = NJT_ERROR;
			goto out;
		}
		if (njt_stream_ssl_dynamic_init(&conf,server_info->addr_conf) != NJT_OK) {
			rc = NJT_ERROR;
			njt_str_set(&server_info->msg,"add server error:no ssl_certificate!");
			//njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "add server error:no ssl_certificate!");
			goto out;
        }
        njt_stream_start_dyn_listen(&conf, old_ls_nelts);
    }
    // dyn_listen end

	ret = njt_stream_dyn_server_post_merge_servers();
	if (old_pool != NULL)
	{
		njt_destroy_pool(old_pool);
	}
	if (ret == NJT_ERROR)
	{
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "add server,but no find in servers.");
	}

out:

	if (rc != NJT_OK)
	{
		if (del == 1)
		{
			njt_stream_dyn_server_delete_dirtyservers(server_info);
			njt_stream_delete_dyn_ports(conf.cycle);
		}
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "add  server [%V] error!", &server_name);
	}
	else
	{
		njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0, "add  server [%V] succ!", &server_name);
	}
	return rc;
}
static int njt_agent_server_change_handler_internal(njt_str_t *key, njt_str_t *value, void *data, njt_str_t *out_msg)
{
	njt_str_t add = njt_string("add");
	njt_str_t del = njt_string("del");
	njt_str_t del_topic = njt_string("");
	njt_str_t worker_str = njt_string("/worker_a");
	njt_str_t obj_key = njt_string(VS_DEL_STREAM_EVENT);
	njt_str_t new_key;
	njt_rpc_result_t *rpc_result;
	njt_uint_t from_api_add = 0;

	njt_int_t rc = NJT_OK;
	njt_stream_dyn_server_info_t *server_info;
	njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "get topic  key=%V,value=%V", key, value);

	server_info = njt_stream_parser_server_data(*value, 0);
	if (server_info == NULL)
	{
		njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "topic msg error key=%V,value=%V", key, value);
		return NJT_ERROR;
	}
	rpc_result = njt_rpc_result_create();
	if (rpc_result == NULL)
	{
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "rpc_result allocate null");
		return NJT_ERROR;
	}

	if (server_info->type.len == add.len && njt_strncmp(server_info->type.data, add.data, server_info->type.len) == 0)
	{
		rc = njt_stream_dyn_server_write_data(server_info);
		if (rc == NJT_OK)
		{
			if (key->len > worker_str.len && njt_strncmp(key->data, worker_str.data, worker_str.len) == 0)
			{
				from_api_add = 1;
			}
			rc = njt_stream_add_server_handler(server_info, from_api_add); // njt_stream_dyn_server_delete_handler
			if (rc != NJT_OK)
			{
				if (from_api_add == 0)
				{
					// njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "add topic_kv_change_handler error key=%V,value=%V",key,value);
					njt_kv_sendmsg(key, &del_topic, 0);
				}
				njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "add topic_kv_change_handler error key=%V,value=%V", key, value);
			}
			else
			{
				if (key->len > worker_str.len && njt_strncmp(key->data, worker_str.data, worker_str.len) == 0)
				{
					new_key.data = key->data + worker_str.len;
					new_key.len = key->len - worker_str.len;
					njt_kv_sendmsg(&new_key, value, 1);
					njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "add topic_kv_change_handler succ key=%V,value=%V", &new_key, value);
				}
				// njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "add topic_kv_change_handler succ key=%V,value=%V",key,value);
			}
		}
	}
	else if (server_info->type.len == del.len && njt_strncmp(server_info->type.data, del.data, server_info->type.len) == 0)
	{
		rc = njt_stream_dyn_server_write_data(server_info);
		if (rc == NJT_OK)
		{
			rc = njt_stream_dyn_server_delete_handler(server_info);
			if (rc == NJT_OK)
			{
				if (key->len > worker_str.len && njt_strncmp(key->data, worker_str.data, worker_str.len) == 0)
				{
					new_key.data = key->data + worker_str.len;
					new_key.len = key->len - worker_str.len;
					njt_kv_sendmsg(&new_key, value, 0);
				}
				njt_http_object_dispatch_notice(&obj_key, TOPIC_UPDATE, NULL);
			}
			njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "delete topic_kv_change_handler key=%V,value=%V", key, value);
		}
	}
	if (rc == NJT_OK)
	{
		njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_SUCCESS);
	}
	else
	{
		if (rc == NJT_RPC_NOT_ALLOW)
		{
			njt_rpc_result_set_code(rpc_result, NJT_RPC_NOT_ALLOW);
		}
		else
		{
			njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
		}
		njt_rpc_result_set_msg2(rpc_result, &server_info->msg);
	}
	if (out_msg)
	{
		njt_rpc_result_to_json_str(rpc_result, out_msg);
	}
	if (rpc_result)
	{
		njt_rpc_result_destroy(rpc_result);
	}

	njt_destroy_pool(server_info->pool);

	return NJT_OK;
}

static u_char *njt_agent_server_put_handler(njt_str_t *topic, njt_str_t *request, int *len, void *data)
{
	njt_str_t err_json_msg;
	njt_str_null(&err_json_msg);
	// 新增字符串参数err_json_msg用于返回到客户端。
	njt_agent_server_change_handler_internal(topic, request, data, &err_json_msg);
	*len = err_json_msg.len;
	return err_json_msg.data;
}

static int topic_kv_change_handler(njt_str_t *key, njt_str_t *value, void *data)
{
	return njt_agent_server_change_handler_internal(key, value, data, NULL);
}

static njt_int_t
njt_stream_dyn_server_init_worker(njt_cycle_t *cycle)
{

	njt_str_t key = njt_string("stream_srv");
	njt_kv_reg_handler_t h;
	njt_memzero(&h, sizeof(njt_kv_reg_handler_t));
	h.key = &key;
	h.rpc_put_handler = njt_agent_server_put_handler;
	h.handler = topic_kv_change_handler;
	h.api_type = NJT_KV_API_TYPE_INSTRUCTIONAL;
	njt_kv_reg_handler(&h);
	return NJT_OK;
}

static njt_int_t njt_stream_check_server_body(njt_str_t cmd,void *data)
{
	njt_str_t *name,ssl_key;
	njt_stream_dyn_server_info_t *server_info = data;

	if (cmd.len == 0)
	{
		return NJT_OK;
	}
	for (name = njt_invalid_dyn_server_body; name->len; name++)
	{
		if (cmd.len == name->len && njt_strncmp(cmd.data, name->data, name->len) == 0)
		{
			// njt_invalid_dyn_server_body_field = *name;
			return NJT_ERROR;
		}
	}
	njt_str_set(&ssl_key,"ssl_certificate_key");
	if(cmd.len == ssl_key.len && njt_strncmp(cmd.data,ssl_key.data,ssl_key.len) == 0) {
		if(server_info != NULL) {
			server_info->ssl_certificate_key = 1; 
		}
	}
	njt_str_set(&ssl_key,"ssl_certificate");
	if(cmd.len == ssl_key.len && njt_strncmp(cmd.data,ssl_key.data,ssl_key.len) == 0) {
		if(server_info != NULL) {
			server_info->ssl_certificate = 1; 
		}
	}
	njt_str_set(&ssl_key, "listen");
	if(cmd.len == ssl_key.len && njt_strncmp(cmd.data,ssl_key.data,ssl_key.len) == 0) {
		if(server_info != NULL) {
			if (server_info->listen_count) {
				server_info->listen_count = 2;
				njt_str_set(&server_info->msg, "listen cmd in the server body of dynamic stream vs");
				return NJT_ERROR;
			} else {
				server_info->listen_count = 1;
			}
		}
	}
	return NJT_OK;
}

njt_int_t njt_http_check_top_server(njt_json_manager *json_body, njt_stream_dyn_server_info_t *server_info)
{

	njt_json_element *items;
	njt_str_t str;
	u_char *p;
	njt_queue_t *q;
	njt_str_t error = njt_string("invalid parameter:");
	if (json_body->json_val == NULL || json_body->json_val->type != NJT_JSON_OBJ)
	{
		njt_str_set(&server_info->msg, "json error!!!");
		return NJT_ERROR;
	}

	for (q = njt_queue_head(&json_body->json_val->objdata.datas);
		 q != njt_queue_sentinel(&json_body->json_val->objdata.datas);
		 q = njt_queue_next(q))
	{

		items = njt_queue_data(q, njt_json_element, ele_queue);
		if (items == NULL)
		{
			break;
		}
		njt_str_set(&str, "type");
		if (items->key.len == str.len && njt_strncmp(str.data, items->key.data, str.len) == 0)
		{
			continue;
		}
		njt_str_set(&str, "addr_port");
		if (items->key.len == str.len && njt_strncmp(str.data, items->key.data, str.len) == 0)
		{
			continue;
		}
		njt_str_set(&str,"listen_option");
		if(items->key.len == str.len && njt_strncmp(str.data,items->key.data,str.len) == 0){
			continue;
		}
		njt_str_set(&str, "server_name");
		if (items->key.len == str.len && njt_strncmp(str.data, items->key.data, str.len) == 0)
		{
			continue;
		}
		njt_str_set(&str, "server_body");
		if (items->key.len == str.len && njt_strncmp(str.data, items->key.data, str.len) == 0)
		{
			continue;
		}

		p = njt_snprintf(server_info->buffer.data, server_info->buffer.len, "%V%V!", &error, &items->key);
		server_info->msg = server_info->buffer;
		server_info->msg.len = p - server_info->buffer.data;
	}
	if (server_info->msg.len > 0)
	{
		return NJT_ERROR;
	}
	return NJT_OK;
}
njt_stream_dyn_server_info_t *njt_stream_parser_server_data(njt_str_t json_str, njt_uint_t method)
{
	njt_json_manager json_body;
	njt_pool_t *server_pool;
	njt_stream_dyn_server_info_t *server_info;
	njt_int_t rc;
	njt_uint_t i;
	njt_str_t add = njt_string("add");
	njt_str_t del = njt_string("del");
	njt_str_t key;
	int32_t buffer_len;
	njt_str_t new_addr_port;
	njt_json_element *items;
	njt_url_t u;

	server_pool = njt_create_pool(NJT_DEFAULT_POOL_SIZE, njt_cycle->log);
	if (server_pool == NULL)
	{
		return NULL;
	}

	rc = njt_json_2_structure(&json_str, &json_body, server_pool);
	if (rc != NJT_OK)
	{
		rc = NJT_ERROR;
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "json error!,json=%V", &json_str);
		njt_destroy_pool(server_pool);
		return NULL;
	}
	server_info = njt_pcalloc(server_pool, sizeof(njt_stream_dyn_server_info_t));
	if (server_info == NULL)
	{
		njt_destroy_pool(server_pool);
		return NULL;
	}

	// server_info->type = -1;
	server_info->pool = server_pool;
	buffer_len = json_str.len + 1024;
	buffer_len = (buffer_len > NJT_MAX_CONF_ERRSTR ? buffer_len : NJT_MAX_CONF_ERRSTR);
	server_info->buffer.len = 0;
	server_info->buffer.data = njt_pcalloc(server_info->pool, buffer_len);
	if (server_info->buffer.data != NULL)
	{
		server_info->buffer.len = buffer_len;
	}

	rc = njt_http_check_top_server(&json_body, server_info);
	if (rc == NJT_ERROR)
	{
		goto end;
	}

	njt_str_set(&key, "addr_port");
	rc = njt_struct_top_find(&json_body, &key, &items);
	if (rc != NJT_OK || items->type != NJT_JSON_STR)
	{
		// server_info->code = 1;
		njt_str_set(&server_info->msg, "addr_port error!!!");
		goto end;
	}
	else
	{
		server_info->addr_port = njt_del_headtail_space(items->strval);
		if (server_info->addr_port.len == 0)
		{
			njt_str_set(&server_info->msg, "addr_port null!!!");
			goto end;
		}
		else
		{
			new_addr_port = server_info->addr_port;
			for(i = 0; i < server_info->addr_port.len; i++){
				if(server_info->addr_port.data[i] == '\0' || server_info->addr_port.data[i] == '\n' || server_info->addr_port.data[i] == '\t' || server_info->addr_port.data[i] == ' ' || server_info->addr_port.data[i] == '\r'){
					new_addr_port.len = i;
					break;
				}
			}
			njt_memzero(&u, sizeof(njt_url_t));
			u.url = new_addr_port;
			u.default_port = 80;
			u.no_resolve = 1;

			if (njt_parse_url(server_info->pool, &u) != NJT_OK)
			{
				njt_str_set(&server_info->msg, "addr_port error!!!");
				goto end;
			}
		}
	}
	njt_str_set(&key, "type");
	rc = njt_struct_top_find(&json_body, &key, &items);
	if (rc != NJT_OK || items->type != NJT_JSON_STR)
	{
		njt_str_set(&server_info->msg, "type error!!!");
		goto end;
	}
	else
	{
		server_info->type = njt_del_headtail_space(items->strval);
		if (method != 0 && server_info->type.len == add.len && njt_strncmp(server_info->type.data, add.data, server_info->type.len) == 0 && method != NJT_HTTP_POST)
		{
			njt_str_set(&server_info->msg, "no support method when add server!");
			goto end;
		}
		if (method != 0 && server_info->type.len == del.len && njt_strncmp(server_info->type.data, del.data, server_info->type.len) == 0 && method != NJT_HTTP_PUT)
		{
			njt_str_set(&server_info->msg, "no support method when del server!");
			goto end;
		}
		if ((server_info->type.len == add.len && njt_strncmp(server_info->type.data, add.data, server_info->type.len) == 0) || (server_info->type.len == del.len && njt_strncmp(server_info->type.data, del.data, server_info->type.len) == 0))
		{
		}
		else
		{
			njt_str_set(&server_info->msg, "type error!!!");
			goto end;
		}
	}

	njt_str_set(&key, "server_name");
	rc = njt_struct_top_find(&json_body, &key, &items);
	if (rc == NJT_OK)
	{
		if (items->type != NJT_JSON_STR)
		{
			njt_str_set(&server_info->msg, "server_name error!");
			goto end;
		}
		server_info->old_server_name = njt_del_headtail_space(items->strval);
		server_info->server_name = server_info->old_server_name;
		njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "server_name[%V,%V]", &items->strval, &server_info->old_server_name);
		if (server_info->old_server_name.len == 0)
		{
			njt_str_set(&server_info->msg, "server_name is null!");
			goto end;
		}
	}
	else
	{
		if (server_info->type.len == del.len && njt_strncmp(server_info->type.data, del.data, server_info->type.len) == 0)
		{
			njt_str_set(&server_info->msg, "server_name is null!");
			goto end;
		}
	}

	njt_str_set(&key,"listen_option");
	rc = njt_struct_top_find(&json_body, &key, &items);
	if(rc == NJT_OK ){
		if (items->type != NJT_JSON_STR) {
			njt_str_set(&server_info->msg, "listen_option error!");
			goto end;
		}
		server_info->listen_option = njt_del_headtail_space(items->strval);
		if(server_info->listen_option.len == 0) {
		}
	} 

	njt_str_set(&key, "server_body");
	rc = njt_struct_top_find(&json_body, &key, &items);
	if (rc == NJT_OK)
	{
		if (items->type != NJT_JSON_STR)
		{
			njt_str_set(&server_info->msg, "server_body error!");
			goto end;
		}
		server_info->server_body = njt_del_headtail_space(items->strval);
		if (server_info->server_body.len == 0)
		{
		}
	}

end:
	return server_info;
}

static njt_int_t njt_stream_server_write_file(njt_fd_t fd, njt_stream_dyn_server_info_t *server_info)
{

	u_char *p, *data;
	int32_t rlen, buffer_len, remain;
	njt_str_t escape_server_name, escape_server_body;
	njt_uint_t ssl;
	njt_stream_addr_conf_t *addr_conf;
	njt_str_t opt_ssl;
	buffer_len = server_info->buffer.len;
	remain = buffer_len;
	data = server_info->buffer.data;

	if (server_info)
	{
		njt_memzero(data, buffer_len);
		njt_str_set(&opt_ssl, "");
		ssl = 0;
		addr_conf = njt_stream_get_ssl_by_port((njt_cycle_t *)njt_cycle, &server_info->addr_port);
		if (addr_conf != NULL)
		{
			ssl = addr_conf->ssl;
		}
		// dyn_listen
		else {
			if (server_info->listen_option.len == 3 && njt_strncmp(server_info->listen_option.data, "ssl", 3) == 0) {
				ssl = 1;
			}
		}
		// dyn_listen end
		server_info->addr_conf = addr_conf;

		if (ssl == 1)
		{
			njt_str_set(&opt_ssl, "ssl");
		}
		p = data;
		p = njt_snprintf(p, remain, "server {\n");
		remain = data + buffer_len - p;
		escape_server_name = server_info->old_server_name;
		if (escape_server_name.len != 0 && server_info->server_body.len != 0)
		{
			escape_server_body = server_info->server_body;
			if (escape_server_body.len > 0 && escape_server_body.data[escape_server_body.len - 1] != ';' && escape_server_body.data[escape_server_body.len - 1] != '}')
			{
				p = njt_snprintf(p, remain, "listen %V %V %V;\nserver_name %V;\n%V; \n}\n", &server_info->addr_port, &opt_ssl, &server_info->listen_option, &escape_server_name, &escape_server_body);
			}
			else
			{
				p = njt_snprintf(p, remain, "listen %V %V %V;\nserver_name %V;\n%V \n}\n", &server_info->addr_port, &opt_ssl, &server_info->listen_option, &escape_server_name, &escape_server_body);
			}
		}
		else
		{
			if (escape_server_name.len > 0 && escape_server_name.data[escape_server_name.len - 1] != ';')
			{
				p = njt_snprintf(p, remain, "listen %V %V %V;\nserver_name %V; \n}\n", &server_info->addr_port, &opt_ssl, &server_info->listen_option, &escape_server_name);
			}
			else
			{
				p = njt_snprintf(p, remain, "listen %V %V %V;\nserver_name %V \n}\n", &server_info->addr_port, &opt_ssl, &server_info->listen_option, &escape_server_name);
			}
		}
		remain = data + buffer_len - p;

		rlen = njt_write_fd(fd, data, p - data);
		if (rlen < 0)
		{
			return NJT_ERROR;
		}
	}
	return NJT_OK;
}
static njt_int_t njt_stream_dyn_server_write_data(njt_stream_dyn_server_info_t *server_info)
{

	njt_fd_t fd;
	njt_int_t rc = NJT_OK;

	u_char *p; // *data;
	njt_stream_core_srv_conf_t *cscf;

	njt_str_t server_file = njt_string("add_server.txt");
	njt_str_t server_path;
	njt_str_t server_full_file;

	server_info->server_name = njt_get_command_unique_name(server_info->pool, server_info->old_server_name);
	cscf = njt_stream_get_srv_by_port((njt_cycle_t *)njt_cycle, &server_info->addr_port, &server_info->old_server_name);
	(*server_info).cscf = cscf;

	server_path = njt_cycle->log_prefix;

	server_full_file.len = server_path.len + server_file.len + 50; //  workid_add_server.txt
	server_full_file.data = njt_pcalloc(server_info->pool, server_full_file.len);
	p = njt_snprintf(server_full_file.data, server_full_file.len, "%Vlogs/%d_%d_%V", &server_path, njt_process, njt_worker,
					 &server_file);

	server_full_file.len = p - server_full_file.data;
	fd = njt_open_file(server_full_file.data, NJT_FILE_CREATE_OR_OPEN | NJT_FILE_RDWR, NJT_FILE_TRUNCATE,
					   NJT_FILE_DEFAULT_ACCESS);
	if (fd == NJT_INVALID_FILE)
	{
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "njt_stream_dyn_server_write_data njt_open_file[%V] error!", &server_full_file);
		rc = NJT_ERROR;
		goto out;
	}
	rc = njt_stream_server_write_file(fd, server_info);

	if (njt_close_file(fd) == NJT_FILE_ERROR)
	{
	}

	if (rc == NJT_ERROR)
	{
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "njt_stream_server_write_data error!");
		goto out;
	}
	(*server_info).file = server_full_file;

out:
	return rc;
}

static void
njt_stream_dyn_server_delete_regex_server_name(njt_pool_t *pool, njt_stream_conf_addr_t *addr, njt_str_t *server_name)
{

	njt_uint_t i;
	njt_uint_t len;

	if (server_name == NULL || server_name->len == 0 || server_name->data[0] != '~')
	{
		return;
	}
	for (i = 0; i < addr->nregex; i++)
	{
		if (njt_http_server_full_name_cmp(addr->regex[i].full_name, *server_name, 0) == NJT_OK)
		{
			if (i < addr->nregex - 1)
			{
				len = (addr->nregex - 1 - i) * sizeof(njt_stream_server_name_t);
				njt_memmove(&addr->regex[i], &addr->regex[i + 1], len); // 不做交互，防止有序。
			}
			addr->nregex--;
			break;
		}
	}
}

static void
njt_stream_dyn_server_delete_main_server(njt_stream_core_srv_conf_t *cscf)
{
	njt_stream_core_srv_conf_t **cscfp;
	njt_stream_core_main_conf_t *cmcf;
	njt_uint_t i;
	njt_str_t key;
	njt_stream_proxy_srv_conf_t *pscf;
	cmcf = njt_stream_cycle_get_module_main_conf(njt_cycle, njt_stream_core_module);
	cscfp = cmcf->servers.elts;
	for (i = 0; i < cmcf->servers.nelts; i++)
	{

		if (cscfp[i] == cscf && cscf->listen == 1 && cscf->dynamic == 1)
		{ // 动态，并且有listen，没listen 的没有做引用计数。 cscf->dynamic == 1
			cscf->disable = 1;
			njt_str_set(&key, STREAM_VS_OBJ);
			njt_http_object_dispatch_notice(&key, DELETE_NOTICE, cscf);

			njt_array_delete_idx(&cmcf->servers, i);
			if (cscf->ref_count == 0)
			{
				pscf = cscf->ctx->srv_conf[njt_stream_proxy_module.ctx_index];
				if (pscf != NULL && pscf->upstream != NULL)
				{
					pscf->upstream->ref_count --;
					njt_stream_upstream_del((njt_cycle_t *)njt_cycle, pscf->upstream);
				}
				njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "1 zyg delete ntj_destroy_pool server %V,ref_count=%d,pool=%p!", &cscf->server_name, cscf->ref_count, cscf->pool);
				njt_stream_server_delete_dyn_var(cscf);
				njt_destroy_pool(cscf->pool);
			}
			break;
		}
	}
}

static njt_int_t
njt_stream_dyn_server_delete_configure_server(njt_stream_core_srv_conf_t *cscf, njt_stream_dyn_server_info_t *server_info) // njt_stream_dyn_server_info_t *server_info
{
	njt_uint_t p, a, i, j, del_flag, find;
	njt_stream_conf_port_t *port;
	njt_stream_conf_addr_t *addr;
	njt_stream_core_main_conf_t *cmcf;
	njt_array_t *ports;
	njt_stream_core_srv_conf_t **cscfp;
	njt_stream_server_name_t *name;
	njt_str_t *server_name = &server_info->server_name;
	u_char *pdata;

	cmcf = njt_stream_cycle_get_module_main_conf(njt_cycle, njt_stream_core_module);
	ports = cmcf->ports;
	if (ports == NULL)
	{
		return NJT_OK;
	}
	del_flag = 0;
	find = 0;
	port = ports->elts;
	for (p = 0; p < ports->nelts; p++)
	{

		/*
		 * check whether all name-based servers have the same
		 * configuration as a default server for given address:port
		 */

		addr = port[p].addrs.elts;
		for (a = 0; a < port[p].addrs.nelts; a++)
		{

			cscfp = addr[a].servers.elts;
			for (i = 0; i < addr[a].servers.nelts; i++)
			{
				if (cscfp[i] == cscf)
				{
					find = 1;
					if (cscf->server_names.nelts == 1)
					{
						if (cscf->dynamic == 1)
						{
							njt_array_delete_idx(&addr[a].servers, i);
							if (addr[a].servers.nelts == 0)
							{
								njt_array_delete_idx(&port[p].addrs, a);
							}
							if (addr[a].default_server == cscf && addr[a].servers.nelts > 0)
							{ // 切换默认default_server
								// addr[a].opt.default_server = 0; todo
								addr[a].default_server = cscfp[0];
							}
							if (addr[a].servers.nelts <= 1)
							{
								addr[a].wc_head = NULL;
								addr[a].wc_tail = NULL;
								njt_memset(&addr[a].hash, 0, sizeof(njt_hash_t));
							}
							njt_stream_dyn_server_delete_regex_server_name(server_info->pool, &addr[a], server_name);
							del_flag = 1;
							// njt_stream_dyn_server_delete_main_server(cscf);
							continue;
						}
						else
						{

							pdata = njt_snprintf(server_info->buffer.data, server_info->buffer.len, "only dynamic server,can to be delete!", &server_info->addr_port);
							server_info->msg = server_info->buffer;
							server_info->msg.len = pdata - server_info->buffer.data;
							return NJT_RPC_NOT_ALLOW;
						}
					}
					else
					{
						if (cscf->dynamic == 0)
						{

							pdata = njt_snprintf(server_info->buffer.data, server_info->buffer.len, "only dynamic server,can to be delete!", &server_info->addr_port);
							server_info->msg = server_info->buffer;
							server_info->msg.len = pdata - server_info->buffer.data;
							return NJT_RPC_NOT_ALLOW;
						}
						name = cscf->server_names.elts;
						for (j = 0; j < cscf->server_names.nelts; ++j)
						{
							if (name[j].name.len == server_name->len && njt_strncasecmp(name[j].name.data, server_name->data, server_name->len) == 0)
							{
								njt_array_delete_idx(&cscf->server_names, j);
								njt_stream_dyn_server_delete_regex_server_name(server_info->pool, &addr[a], server_name);
								del_flag = 1;
								// njt_stream_dyn_server_delete_main_server(cscf);
								continue;
							}
						}
					}
				}
			}
		}
	}
	if (del_flag == 1 || find == 0)
	{
		njt_stream_dyn_server_delete_main_server(cscf);
	}

	return NJT_OK;
}

static njt_int_t njt_stream_dyn_server_delete_dirtyservers(njt_stream_dyn_server_info_t *server_info)
{
	njt_stream_core_srv_conf_t **cscfp;
	njt_stream_core_main_conf_t *cmcf;

	cmcf = njt_stream_cycle_get_module_main_conf(njt_cycle, njt_stream_core_module);
	cscfp = cmcf->servers.elts;
	if (cmcf->servers.nelts > 0)
	{
		if (cscfp[cmcf->servers.nelts - 1]->dynamic_status) // dyn_listen
		// if (cscfp[cmcf->servers.nelts - 1]->dynamic_status == 1)
		{

			njt_stream_dyn_server_delete_configure_server(cscfp[cmcf->servers.nelts - 1], server_info);
		}
	}
	return NJT_OK;
}

static njt_int_t njt_stream_dyn_server_post_merge_servers()
{
	njt_stream_core_srv_conf_t **cscfp;
	njt_stream_core_main_conf_t *cmcf;
	njt_str_t key;
	cmcf = njt_stream_cycle_get_module_main_conf(njt_cycle, njt_stream_core_module);
	cscfp = cmcf->servers.elts;
	if (cmcf->servers.nelts > 0)
	{
		if (cscfp[cmcf->servers.nelts - 1]->dynamic_status == 1)
		{
			cscfp[cmcf->servers.nelts - 1]->dynamic_status = 2;
			njt_str_set(&key, STREAM_VS_OBJ);
			njt_http_object_dispatch_notice(&key, ADD_NOTICE, cscfp[cmcf->servers.nelts - 1]);
			return NJT_OK;
		}
	}
	else
	{
		return NJT_OK;
	}
	return NJT_ERROR;
}
static njt_stream_addr_conf_t *njt_stream_get_ssl_by_port(njt_cycle_t *cycle, njt_str_t *addr_port)
{
	njt_listening_t *ls, *target_ls = NULL;
	njt_uint_t i;
	in_port_t nport;
	njt_uint_t worker;
	njt_stream_port_t *port;
	njt_stream_in_addr_t *addr;
	njt_stream_in6_addr_t *addr6;
	njt_stream_addr_conf_t *addr_conf;
	njt_url_t u;
	njt_str_t udp = njt_string(" udp");
	njt_str_t new_addr_port;
	int type;
	u_char *p;
	struct sockaddr_in *ssin;
#if (NJT_HAVE_INET6)
	struct sockaddr_in6 *ssin6;
#endif

	njt_pool_t *pool;
	addr_conf = NULL;
	target_ls = NULL;

	pool = njt_create_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
	if (pool == NULL)
	{
		return NULL;
	}
	new_addr_port = *addr_port;
	for(i = 0; i < addr_port->len; i++){
		if(addr_port->data[i] == '\0' || addr_port->data[i] == '\n' || addr_port->data[i] == '\t' || addr_port->data[i] == ' ' || addr_port->data[i] == '\r'){
			new_addr_port.len = i;
			break;
		}
	}
	type = SOCK_STREAM;
	p = njt_strlcasestrn(addr_port->data + i,addr_port->data + addr_port->len,udp.data,udp.len - 1);
	if(p != NULL) {
		if (p + udp.len == addr_port->data + addr_port->len) {  //结尾
			type = SOCK_DGRAM;
		} else if(p[udp.len] == '\0' || p[udp.len] == '\n' || p[udp.len] == '\t' || p[udp.len] == ' ' || p[udp.len] == '\r'){
			type = SOCK_DGRAM;
		}
	}
	njt_memzero(&u, sizeof(njt_url_t));
	u.url = new_addr_port;
	u.default_port = 80;
	u.no_resolve = 1;

	if (njt_parse_url(pool, &u) != NJT_OK)
	{
		goto out;
	}

	if (addr_port != NULL && addr_port->len > 0)
	{

		worker = njt_worker;
		if (njt_process == NJT_PROCESS_HELPER && njt_is_privileged_agent)
		{
			worker = 0;
		}
		ls = cycle->listening.elts;
		for (i = 0; i < cycle->listening.nelts; i++)
		{
			if (ls[i].server_type != NJT_STREAM_SERVER_TYPE)
			{
				continue; // 非stream listen
			}
			if(ls[i].type != type){
				continue; //
			}
			if (ls[i].reuseport && ls[i].worker != worker)
			{
				continue;
			}

			nport = 0;
			if (njt_cmp_sockaddr(ls[i].sockaddr, ls[i].socklen,
								 &u.sockaddr.sockaddr, u.socklen, 1) == NJT_OK)
			{
				target_ls = &ls[i];
				break;
			}
			else if (ls[i].sockaddr->sa_family != AF_UNIX && ls[i].sockaddr->sa_family == u.family && njt_inet_wildcard(ls[i].sockaddr) == 1)
			{
				nport = njt_inet_get_port(ls[i].sockaddr);
				if (nport == u.port)
				{
					target_ls = &ls[i];
					break;
				}
			}
		}
		if (target_ls == NULL)
		{
			njt_log_error(NJT_LOG_INFO, cycle->log, 0, "can`t find listen server %V", addr_port);
			goto out;
		}
		port = target_ls->servers;
		addr = NULL;
		addr6 = NULL;
		switch (target_ls->sockaddr->sa_family)
		{

#if (NJT_HAVE_INET6)
		case AF_INET6:
			addr6 = port->addrs;
			break;
#endif
		default: /* AF_INET */
			addr = port->addrs;
			break;
		}
		for (i = 0; i < port->naddrs; ++i)
		{
			if (target_ls->sockaddr->sa_family != AF_UNIX)
			{
				if (addr6 != NULL)
				{
					ssin6 = (struct sockaddr_in6 *)&u.sockaddr.sockaddr;
					if (njt_memcmp(&addr6[i].addr6, &ssin6->sin6_addr, 16) != 0)
					{
						continue;
					}
					addr_conf = &addr6[i].conf;
				}
				else if (addr != NULL)
				{
					ssin = (struct sockaddr_in *)&u.sockaddr.sockaddr;
					if (addr[i].addr != ssin->sin_addr.s_addr)
					{
						continue;
					}
					addr_conf = &addr[i].conf;
				}
				if (addr_conf == NULL)
				{
					continue;
				}
			}
			else
			{
				if (addr != NULL)
				{
					addr_conf = &addr[0].conf;
				}
			}
			break;
		}
	}
out:
	if (pool != NULL)
	{
		njt_destroy_pool(pool);
	}
	return addr_conf;
}

static void njt_stream_server_delete_dyn_var(njt_stream_core_srv_conf_t *cscf)
{
	return;
}

// static char *
static char *
njt_stream_merge_servers(njt_conf_t *cf, njt_stream_core_main_conf_t *cmcf,
						 njt_stream_module_t *module, njt_uint_t ctx_index)
{
	char *rv;
	njt_uint_t s;
	njt_stream_conf_ctx_t *ctx, saved;
	njt_stream_core_srv_conf_t **cscfp;

	cscfp = cmcf->servers.elts;
	ctx = (njt_stream_conf_ctx_t *)cf->ctx;
	saved = *ctx;
	rv = NJT_CONF_OK;

	for (s = 0; s < cmcf->servers.nelts; s++)
	{

		if (cf->dynamic == 1 && cscfp[s]->dynamic_status != 1)
		{
			continue;
		}
		/* merge the server{}s' srv_conf's */

		ctx->srv_conf = cscfp[s]->ctx->srv_conf;

		if (module->merge_srv_conf)
		{
			rv = module->merge_srv_conf(cf, saved.srv_conf[ctx_index],
										cscfp[s]->ctx->srv_conf[ctx_index]);
			if (rv != NJT_CONF_OK)
			{
				goto failed;
			}
		}
		/*
		if (module->postconfiguration) {
			if (module->postconfiguration(cf) != NJT_OK) {
				 goto failed;
			}
		}*/
	}

failed:

	*ctx = saved;

	return rv;
}
