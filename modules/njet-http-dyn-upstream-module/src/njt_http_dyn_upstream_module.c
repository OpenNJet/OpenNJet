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
#include <njt_http_dyn_upstream_module.h>
#include <njt_http_dyn_upstream_parser.h>
#include <njt_rpc_result_util.h>
#include "js2c_njet_builtins.h"
#include <njt_str_util.h>

static njt_str_t dyn_upstream_update_srv_err_msg = njt_string("{\"code\":500,\"msg\":\"server error\"}");

extern njt_uint_t njt_worker;
extern njt_cycle_t *njet_master_cycle;
extern njt_module_t njt_http_rewrite_module;
extern njt_conf_check_cmd_handler_pt njt_conf_check_cmd_handler;
static njt_uint_t    njt_check_server_directive = 1;
extern njt_int_t njt_http_upstream_init_zone(njt_shm_zone_t *shm_zone,
											 void *data);
extern njt_int_t
njt_http_optimize_servers(njt_conf_t *cf, njt_http_core_main_conf_t *cmcf,
						  njt_array_t *ports);

extern njt_int_t njt_http_upstream_keepalive_get_keepalive_time(njt_http_upstream_srv_conf_t *upstream);
extern njt_int_t njt_http_upstream_keepalive_get_keepalive_timeout(njt_http_upstream_srv_conf_t *upstream);
extern njt_int_t njt_http_upstream_keepalive_get_keepalive_requests(njt_http_upstream_srv_conf_t *upstream);
extern njt_int_t njt_http_upstream_keepalive_get_keepalive(njt_http_upstream_srv_conf_t *upstream);

njt_str_t njt_del_headtail_space(njt_str_t src);

static njt_int_t
njt_http_dyn_upstream_init_worker(njt_cycle_t *cycle);

static njt_int_t njt_http_dyn_upstream_write_data(njt_http_dyn_upstream_info_t *upstream_info);

static njt_int_t njt_http_check_upstream_body(njt_str_t cmd);
static njt_int_t   njt_http_dyn_upstream_postconfiguration(njt_conf_t *cf);

typedef struct njt_http_dyn_upstream_ctx_s
{
} njt_http_dyn_upstream_ctx_t, njt_stream_http_dyn_upstream_ctx_t;

static njt_http_module_t njt_http_dyn_upstream_module_ctx = {
	NULL, /* preconfiguration */
	&njt_http_dyn_upstream_postconfiguration, /* postconfiguration */

	NULL, /* create main configuration */
	NULL, /* init main configuration */

	NULL, /* create server configuration */
	NULL, /* merge server configuration */

	NULL, /* create server configuration */
	NULL  /* merge server configuration */
};

njt_module_t njt_http_dyn_upstream_module = {
	NJT_MODULE_V1,
	&njt_http_dyn_upstream_module_ctx, /* module context */
	NULL,							   /* module directives */
	NJT_HTTP_MODULE,				   /* module type */
	NULL,							   /* init master */
	NULL,							   /* init module */
	njt_http_dyn_upstream_init_worker, /* init process */
	NULL,							   /* init thread */
	NULL,							   /* exit thread */
	NULL,							   /* exit process */
	NULL,							   /* exit master */
	NJT_MODULE_V1_PADDING};

static njt_str_t njt_invalid_dyn_upstream_body[] = {
	njt_string("server"),
	njt_null_string};

static njt_int_t   njt_http_dyn_upstream_postconfiguration(njt_conf_t *cf) {

	njt_core_conf_t      *ccf;
	if (njet_master_cycle != NULL)
	{
		ccf = (njt_core_conf_t *)njt_get_conf(njet_master_cycle->conf_ctx, njt_core_module);
	}
	else
	{
		ccf = (njt_core_conf_t *) njt_get_conf(cf->cycle->conf_ctx, njt_core_module);
	}

	if(ccf == NULL || ccf->shared_slab_pool_size <= 0) {
		 njt_log_error(NJT_LOG_EMERG, cf->log, 0,"need shared_slab_pool_size directive!");
		return NJT_ERROR;
	}
	return NJT_OK;
}
static njt_int_t
njt_http_dyn_upstream_delete_handler(njt_http_dyn_upstream_info_t *upstream_info)
{
	njt_http_upstream_srv_conf_t *upstream;
	u_char *p;
	njt_int_t rc;

	rc = NJT_ERROR;
	if (upstream_info->buffer.len == 0 || upstream_info->buffer.data == NULL)
	{
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "buffer null");
		njt_str_set(&upstream_info->msg, "error:buffer null!");
		return NJT_ERROR;
	}

	upstream = upstream_info->upstream;
	if (upstream == NULL)
	{
		if (upstream == NULL)
		{
			p = njt_snprintf(upstream_info->buffer.data, upstream_info->buffer.len, "error:no find upstream [%V]!", &upstream_info->upstream_name);
			upstream_info->msg = upstream_info->buffer;
			upstream_info->msg.len = p - upstream_info->buffer.data;
			njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0, "no find upstream [%V]!", &upstream_info->upstream_name);
		}
		else if (upstream != NULL)
		{
			njt_str_set(&upstream_info->msg, "error:upstream is null!");
			njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "error:upstream is null!");
		}
		else
		{
			njt_str_set(&upstream_info->msg, "no find upstream!");
			njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0, "no find upstream [%V]!", &upstream_info->upstream_name);
		}
		return NJT_ERROR;
	}
	njt_log_debug(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "del upstream =%V,ref_count=%d,client_count=%d",&upstream->host,upstream->ref_count,upstream->client_count);	
	if (upstream && upstream->disable == 0 && upstream->ref_count == 1 && upstream->dynamic == 1 && upstream->no_port == 1)
	{ // 只删标准upstream，ref_count 默认是 1.
		njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0, "del upstream [%V] succ!", &upstream_info->upstream_name);

		upstream->ref_count--;
		upstream->disable = 1;
		if(njet_master_cycle != NULL) {
			njt_http_upstream_del(njet_master_cycle,upstream);
		} else {
			njt_http_upstream_del((njt_cycle_t *)njt_cycle,upstream);
		}
		rc = NJT_OK;
	} else if (upstream && upstream->ref_count > 1 && upstream->dynamic == 1 && upstream->no_port == 1) { //if (cf->dynamic == 1 && u->naddrs == 1 && (u->port || u->family == AF_UNIX))
		p = njt_snprintf(upstream_info->buffer.data, upstream_info->buffer.len, "fail:upstream [%V] is using!", &upstream_info->upstream_name);
		upstream_info->msg = upstream_info->buffer;
		upstream_info->msg.len = p - upstream_info->buffer.data;

		njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0, "del upstream fail,[%V] is using!", &upstream_info->upstream_name);

	} else if (upstream && upstream->dynamic == 0) {
		p = njt_snprintf(upstream_info->buffer.data, upstream_info->buffer.len, "fail:upstream [%V] is static!", &upstream_info->upstream_name);
		upstream_info->msg = upstream_info->buffer;
		upstream_info->msg.len = p - upstream_info->buffer.data;
		njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0, "del upstream fail,[%V] is static!", &upstream_info->upstream_name);
	}
	// note: delete queue memory, which delete when remove queue
	return rc;
}

static njt_int_t njt_http_add_upstream_handler(njt_http_dyn_upstream_info_t *upstream_info, njt_uint_t from_api_add)
{
	njt_conf_t conf;
	njt_int_t rc = NJT_OK;
	u_char *p;
	njt_int_t ret;
	char *rv = NULL;
	njt_uint_t old_ups_num = 0, ups_num = 0;
	njt_slab_pool_t *shpool;
	njt_http_conf_ctx_t *http_ctx;
	njt_http_upstream_init_pt init;
	njt_str_t upstream_name;
	njt_str_t server_path; // = njt_string("./conf/add_server.txt");
	njt_http_upstream_srv_conf_t *upstream;
	njt_http_upstream_srv_conf_t **uscfp;
	njt_http_upstream_main_conf_t *umcf = NULL;
	njt_http_upstream_rr_peers_t   *peers, **peersp;
	if (upstream_info->upstream != NULL)
	{
		p = njt_snprintf(upstream_info->buffer.data, upstream_info->buffer.len, "error:upstream[%V] exist!", &upstream_info->upstream_name);
		upstream_info->msg = upstream_info->buffer;
		upstream_info->msg.len = p - upstream_info->buffer.data;
		njt_log_debug(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "%V", &upstream_info->msg);
		return NJT_RPC_NOT_ALLOW;
	}

	if (upstream_info->buffer.len == 0 || upstream_info->buffer.data == NULL)
	{
		njt_log_debug(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "buffer null");
		njt_str_set(&upstream_info->msg, "error:buffer null!");
		return NJT_ERROR;
	}

	server_path.len = 0;
	server_path.data = NULL;
	if (upstream_info->file.len != 0)
	{
		server_path = upstream_info->file;
	}
	upstream_name = upstream_info->upstream_name;
	upstream = upstream_info->upstream;
	if (upstream != NULL)
	{
		p = njt_snprintf(upstream_info->buffer.data, upstream_info->buffer.len, "error: upstream [%V] exist!", &upstream_info->upstream_name);
		upstream_info->msg = upstream_info->buffer;
		upstream_info->msg.len = p - upstream_info->buffer.data;
		njt_log_debug(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "%V", &upstream_info->msg);
		return NJT_RPC_NOT_ALLOW;
	}

	if (server_path.len == 0)
	{
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "add upstream error:upstream_path=0");
		njt_str_set(&upstream_info->msg, "add upstream error:upstream_path=0");
		rc = NJT_ERROR;
		goto out;
	}

	if (rc == NJT_ERROR || rc > NJT_OK)
	{
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "add upstream error!");
		njt_str_set(&upstream_info->msg, "add upstream error!");
		rc = NJT_ERROR;
		goto out;
	}

	njt_memzero(&conf, sizeof(njt_conf_t));
	conf.args = njt_array_create(upstream_info->pool, 10, sizeof(njt_str_t));
	if (conf.args == NULL)
	{
		njt_str_set(&upstream_info->msg, "add upstream njt_array_create error!");
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "add  upstream[%V] error:args allocate fail!", &upstream_name);
		rc = NJT_ERROR;
		goto out;
	}

	upstream_info->msg.len = NJT_MAX_CONF_ERRSTR;
	upstream_info->msg.data = upstream_info->buffer.data;
	if (upstream_info->msg.data != NULL)
	{
		njt_memzero(upstream_info->msg.data, upstream_info->msg.len);
		conf.errstr = &upstream_info->msg;
	}
	http_ctx = (njt_http_conf_ctx_t *)njt_get_conf(njt_cycle->conf_ctx, njt_http_module);
	umcf = njt_http_cycle_get_module_main_conf(njt_cycle, njt_http_upstream_module);
	conf.cycle = (njt_cycle_t *)njt_cycle;
	if(njet_master_cycle != NULL) {
		http_ctx = (njt_http_conf_ctx_t *)njt_get_conf(njet_master_cycle->conf_ctx, njt_http_module);
		umcf = njt_http_cycle_get_module_main_conf(njet_master_cycle, njt_http_upstream_module);
		conf.cycle = (njt_cycle_t *)njet_master_cycle;
	} 
		
	
	conf.pool = upstream_info->pool;
	conf.temp_pool = upstream_info->pool;
	conf.ctx = http_ctx;
	conf.log = njt_cycle->log;
	conf.module_type = NJT_HTTP_MODULE;
	conf.cmd_type = NJT_HTTP_MAIN_CONF;
	conf.dynamic = 1;

	
	old_ups_num = umcf->upstreams.nelts;
	
	njt_conf_check_cmd_handler = NULL;
	njt_check_server_directive = 0;
	if(from_api_add == 1) {
		njt_check_server_directive = 1;
		njt_conf_check_cmd_handler = njt_http_check_upstream_body;
	}
	rv = njt_conf_parse(&conf, &server_path);
	if (rv != NULL)
	{
		if (upstream_info->msg.len == NJT_MAX_CONF_ERRSTR && upstream_info->msg.data[0] == '\0')
		{
			njt_str_set(&upstream_info->msg, "njt_conf_parse error!");
		}
		else if (upstream_info->msg.len != NJT_MAX_CONF_ERRSTR)
		{
			njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "njt_conf_parse  upstream[%V] error:%V", &upstream_name, &upstream_info->msg);
		}

		rc = NJT_ERROR;
		njt_conf_check_cmd_handler = NULL;
		goto out;
	}
	njt_conf_check_cmd_handler = NULL;

	ups_num = umcf->upstreams.nelts;
	if (ups_num == old_ups_num + 1)
	{
		uscfp = umcf->upstreams.elts;
		if(uscfp[old_ups_num]->shm_zone == NULL) {
			rc = NJT_ERROR;
			goto out;
		}

		init = uscfp[old_ups_num]->peer.init_upstream ? uscfp[old_ups_num]->peer.init_upstream : njt_http_upstream_init_round_robin;
		conf.pool = uscfp[old_ups_num]->pool;
		conf.temp_pool = uscfp[old_ups_num]->pool;
		if (init(&conf, uscfp[old_ups_num]) != NJT_OK)
		{
			rc = NJT_ERROR;
			goto out;
		}
		shpool = NULL;
		uscfp[old_ups_num]->shm_zone->data = umcf;
		uscfp[old_ups_num]->shm_zone->init = njt_http_upstream_init_zone;
		if(njet_master_cycle != NULL) {
			ret = njt_share_slab_get_pool((njt_cycle_t *)njet_master_cycle,uscfp[old_ups_num]->shm_zone,NJT_DYN_SHM_CREATE_OR_OPEN, &shpool); 
		} else {
			ret = njt_share_slab_get_pool((njt_cycle_t *)njt_cycle,uscfp[old_ups_num]->shm_zone,NJT_DYN_SHM_CREATE_OR_OPEN, &shpool); 
		}
		if (ret == NJT_ERROR || shpool == NULL)
		{
			njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "add  upstream [%V] njt_share_slab_get_pool error!", &upstream_name);
			rc = NJT_ERROR;
			goto out;
		} else {
			njt_log_debug(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "add  upstream [%V] njt_share_slab_get_pool=%p!", &upstream_name,shpool);
		}
		if(ret == NJT_DONE)
		{
			peersp = (njt_http_upstream_rr_peers_t **) (void *) &shpool->data;  //worker 直接用共享内存。获取peers。
			peers = *peersp;
			peers->zone_next = NULL;
			uscfp[old_ups_num]->peer.data = peers;
		}
	}
out:

	if (rc != NJT_OK)
	{	
		if(ups_num == old_ups_num + 1) { 
			njt_destroy_pool(uscfp[old_ups_num]->pool);
			umcf->upstreams.nelts--;
			njt_log_debug(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "delete dirty  upstream [%V]!",&upstream_name);
		}
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "add  upstream [%V] error!", &upstream_name);
	}
	else
	{
		njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0, "add  upstream [%V],ups_num=%d,umcf=%p succ!", &upstream_name,ups_num,umcf);
	}
	return rc;
}

static int njt_agent_upstream_change_handler_internal(njt_str_t *key, njt_str_t *value, void *data, njt_str_t *out_msg)
{
	njt_str_t add = njt_string("add");
	njt_str_t del = njt_string("del");
	njt_str_t del_topic = njt_string("");
	njt_str_t worker_str = njt_string("/worker_a");
	njt_str_t new_key;
	njt_rpc_result_t *rpc_result;
	njt_uint_t from_api_add = 0;

	njt_int_t rc = NJT_OK;
	njt_http_dyn_upstream_info_t *upstream_info;

	upstream_info = njt_http_parser_upstream_data(*value, 0);
	if (upstream_info == NULL)
	{
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "topic msg error key=%V,value=%V", key, value);
		return NJT_ERROR;
	}
	rpc_result = njt_rpc_result_create();
	if (rpc_result == NULL)
	{
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "rpc_result allocate null");
		return NJT_ERROR;
	}

	if (upstream_info->type.len == add.len && njt_strncmp(upstream_info->type.data, add.data, upstream_info->type.len) == 0)
	{
		rc = njt_http_dyn_upstream_write_data(upstream_info);
		if (rc == NJT_OK)
		{
			if (key->len > worker_str.len && njt_strncmp(key->data, worker_str.data, worker_str.len) == 0)
			{
				from_api_add = 1;
			}
			rc = njt_http_add_upstream_handler(upstream_info, from_api_add); // njt_http_dyn_upstream_delete_handler
			if (rc != NJT_OK)
			{
				if (from_api_add == 0)
				{
					njt_kv_sendmsg(key, &del_topic, 0);
				}
				njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "add topic_kv_change_handler error key=%V,value=%V", key, value);
			}
			else
			{
				if (key->len > worker_str.len && njt_strncmp(key->data, worker_str.data, worker_str.len) == 0)
				{
					new_key.data = key->data + worker_str.len;
					new_key.len = key->len - worker_str.len;
					njt_kv_sendmsg(&new_key, value, 1);
				}
			}
		}
	}
	else if (upstream_info->type.len == del.len && njt_strncmp(upstream_info->type.data, del.data, upstream_info->type.len) == 0)
	{
		rc = njt_http_dyn_upstream_write_data(upstream_info);
		if (rc == NJT_OK)
		{
			rc = njt_http_dyn_upstream_delete_handler(upstream_info);
			if (rc == NJT_OK)
			{
				if (key->len > worker_str.len && njt_strncmp(key->data, worker_str.data, worker_str.len) == 0)
				{
					new_key.data = key->data + worker_str.len;
					new_key.len = key->len - worker_str.len;
					njt_kv_sendmsg(&new_key, value, 0);
				}
			}
			njt_log_debug(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "delete topic_kv_change_handler key=%V,value=%V", key, value);
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
		njt_rpc_result_set_msg2(rpc_result, &upstream_info->msg);
	}
	if (out_msg)
	{
		njt_rpc_result_to_json_str(rpc_result, out_msg);
	}
	if (rpc_result)
	{
		njt_rpc_result_destroy(rpc_result);
	}

	njt_destroy_pool(upstream_info->pool);

	return NJT_OK;
}

static u_char *njt_agent_upstream_put_handler(njt_str_t *topic, njt_str_t *request, int *len, void *data)
{
	njt_str_t err_json_msg;
	njt_str_null(&err_json_msg);
	// 新增字符串参数err_json_msg用于返回到客户端。
	njt_agent_upstream_change_handler_internal(topic, request, data, &err_json_msg);
	*len = err_json_msg.len;
	return err_json_msg.data;
}

static int topic_kv_change_handler(njt_str_t *key, njt_str_t *value, void *data)
{
	return njt_agent_upstream_change_handler_internal(key, value, data, NULL);
}

static njt_str_t *njt_dyn_upstream_dump_conf(njt_cycle_t *cycle, njt_pool_t *pool)
{
	njt_uint_t                      i,j,num,len;
	njt_http_upstream_srv_conf_t   **uscfp,*upstream;
	njt_http_upstream_main_conf_t  *umcf;
	dyn_upstream_list_t *dyn_upstream_list;
	dyn_upstream_list_item_t *item;
	njt_resolver_connection_t  *rec;
	njt_str_t ips;
	u_char *p;
	njt_str_t balancing = njt_string("round_robin");
	njt_int_t keepalive,keepalive_requests,keepalive_timeout,keepalive_time;
	//njt_str_t resolver = njt_string("127.0.0.1:8000");

	umcf = njt_http_cycle_get_module_main_conf(cycle, njt_http_upstream_module);

	uscfp = umcf->upstreams.elts;

	dyn_upstream_list = create_dyn_upstream_list(pool,4);
	if(dyn_upstream_list == NULL) {
		return NULL;
	}
	for (i = 0; i < umcf->upstreams.nelts; i++)
	{
		upstream = uscfp[i];
		if(upstream->no_port == 0) {
			continue;
		}
		item = create_dyn_upstream_list_upstream(pool);
		if(item == NULL) {
			goto err;
		}
		set_dyn_upstream_list_upstream_name(item,&upstream->host);
		set_dyn_upstream_list_upstream_is_static(item,!upstream->dynamic);
		if(upstream->resolver != NULL && upstream->resolver_timeout > 0) { //state_file
			set_dyn_upstream_list_upstream_resolver_timeout(item,upstream->resolver_timeout);
			num = upstream->resolver->connections.nelts;
			len = 0;
			rec = upstream->resolver->connections.elts;
			for(j=0; j < num; j++) {
				len = len + rec[j].server.len + 1;
			}
			ips.len = len + 1;
			ips.data = njt_pcalloc(pool,ips.len);
			if(ips.data == NULL) {
				goto err;
			}
			p = ips.data;
			for(j=0; j < num; j++) {
				njt_memcpy(p,rec[j].server.data,rec[j].server.len);
				p = p + rec[j].server.len;
				*p = ';';
				p++;
			}
			*p = '\0';
			ips.len = p - ips.data;
			set_dyn_upstream_list_upstream_resolver(item,&ips);	
		}
		if(upstream->shm_zone != NULL) {
			set_dyn_upstream_list_upstream_zone(item,&upstream->shm_zone->shm.name);
		}
		if(upstream->state_file.len != 0 && upstream->state_file.data != NULL) {
			set_dyn_upstream_list_upstream_state(item,&upstream->state_file);
		}
		if(upstream->peer.balancing.data != NULL) {
			set_dyn_upstream_list_upstream_balance(item,&upstream->peer.balancing);
		} else {
			set_dyn_upstream_list_upstream_balance(item,&balancing);
		}
		//set_dyn_upstream_list_upstream_resolver(item,);
		keepalive = njt_http_upstream_keepalive_get_keepalive(upstream);
		if(keepalive > 0) {
			set_dyn_upstream_list_upstream_keepalive(item, keepalive);

			keepalive_requests = njt_http_upstream_keepalive_get_keepalive_requests(upstream);
			set_dyn_upstream_list_upstream_keepalive_requests(item, keepalive_requests);

			keepalive_timeout = njt_http_upstream_keepalive_get_keepalive_timeout(upstream);
			set_dyn_upstream_list_upstream_keepalive_timeout(item, keepalive_timeout);

			keepalive_time = njt_http_upstream_keepalive_get_keepalive_time(upstream);
			set_dyn_upstream_list_upstream_keepalive_time(item, keepalive_time);
		}
		add_item_dyn_upstream_list(dyn_upstream_list,item);

	}
	 return to_json_dyn_upstream_list(pool,dyn_upstream_list, OMIT_NULL_ARRAY | OMIT_NULL_OBJ | OMIT_NULL_STR);
err:
    return &dyn_upstream_update_srv_err_msg;

}

static u_char *njt_dyn_upstream_rpc_get_handler(njt_str_t *topic, njt_str_t *request, int *len, void *data)
{
    njt_cycle_t *cycle;
    njt_str_t *msg;
    u_char *buf;
    njt_pool_t *pool = NULL;

    buf = NULL;
    cycle = (njt_cycle_t *)njt_cycle;
    *len = 0;

    pool = njt_create_pool(njt_pagesize, njt_cycle->log);
    if (pool == NULL) {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_proxy_pass_rpc_handler create pool error");
        goto out;
    }

    msg = njt_dyn_upstream_dump_conf(cycle, pool);
    buf = njt_calloc(msg->len, cycle->log);
    if (buf == NULL) {
        goto out;
    }

    njt_memcpy(buf, msg->data, msg->len);
    *len = msg->len;

out:
    if (pool != NULL) {
        njt_destroy_pool(pool);
    }

    return buf;
}

static u_char *njt_dyn_upstream_rpc_put_handler(njt_str_t *topic, njt_str_t *request, int *len, void *data)
{
    njt_str_t err_json_msg;
    njt_str_null(&err_json_msg);
    //njt_dyn_proxy_pass_change_handler_internal(topic, request, data, &err_json_msg);
    *len = err_json_msg.len;
    return err_json_msg.data;
}

static int njt_dyn_upstream_change_handler(njt_str_t *key, njt_str_t *value, void *data)
{
    return NJT_ERROR; //njt_dyn_proxy_pass_change_handler_internal(key, value, data, NULL);
}


static njt_int_t
njt_http_dyn_upstream_init_worker(njt_cycle_t *cycle)
{
	//int loop = 1;
	njt_core_conf_t      *ccf;
	if(njet_master_cycle != NULL) {
		ccf = (njt_core_conf_t *) njt_get_conf(njet_master_cycle->conf_ctx, njt_core_module);
	} else {
		ccf = (njt_core_conf_t *) njt_get_conf(cycle->conf_ctx, njt_core_module);
	}
	if(ccf == NULL || ccf->shared_slab_pool_size <= 0) {
		 njt_log_error(NJT_LOG_EMERG, cycle->log, 0,"need shared_slab_pool_size directive!");
		return NJT_ERROR;
	}

	njt_str_t key = njt_string("ups");
	njt_kv_reg_handler_t h;
	njt_memzero(&h, sizeof(njt_kv_reg_handler_t));
	h.key = &key;
	h.rpc_put_handler = njt_agent_upstream_put_handler;
	h.handler = topic_kv_change_handler;
	h.api_type = NJT_KV_API_TYPE_INSTRUCTIONAL;
	njt_kv_reg_handler(&h);


	njt_str_t dyn_upstream_key = njt_string("dyn_upstream");
    njt_kv_reg_handler_t dyn_upstream;
    njt_memzero(&dyn_upstream, sizeof(njt_kv_reg_handler_t));
    dyn_upstream.key = &dyn_upstream_key;
    dyn_upstream.rpc_get_handler = njt_dyn_upstream_rpc_get_handler;
    dyn_upstream.rpc_put_handler = njt_dyn_upstream_rpc_put_handler;
    dyn_upstream.handler = njt_dyn_upstream_change_handler;
    dyn_upstream.api_type = NJT_KV_API_TYPE_DECLATIVE;
    njt_kv_reg_handler(&dyn_upstream);
	return NJT_OK;
}

static njt_int_t njt_http_check_upstream_body(njt_str_t cmd)
{
	njt_str_t *name;
	njt_str_t state = njt_string("state");
	njt_str_t server = njt_string("server");
	if (cmd.len == 0)
	{
		return NJT_OK;
	}
	for (name = njt_invalid_dyn_upstream_body; name->len; name++)
	{
		if (cmd.len == state.len && njt_strncmp(cmd.data, state.data, name->len) == 0) { //如果有sate字段，则不屏蔽server
			njt_check_server_directive = 0;
		}
		if (cmd.len == name->len && njt_strncmp(cmd.data, name->data, name->len) == 0)
		{
			if (cmd.len == server.len && njt_strncmp(cmd.data, server.data, name->len) == 0 && njt_check_server_directive == 0)
			{ // 如果有sate字段，则不屏蔽server
				continue;
			}
			return NJT_ERROR;
		}
	}
	return NJT_OK;
}

njt_int_t njt_http_check_top_server(njt_json_manager *json_body, njt_http_dyn_upstream_info_t *upstream_info)
{

	njt_json_element *items;
	njt_str_t str;
	u_char *p;
	njt_queue_t *q;
	njt_str_t error = njt_string("invalid parameter:");
	if (json_body->json_val == NULL || json_body->json_val->type != NJT_JSON_OBJ)
	{
		njt_str_set(&upstream_info->msg, "json error!!!");
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

		njt_str_set(&str, "upstream_name");
		if (items->key.len == str.len && njt_strncmp(str.data, items->key.data, str.len) == 0)
		{
			continue;
		}
		njt_str_set(&str, "upstream_body");
		if (items->key.len == str.len && njt_strncmp(str.data, items->key.data, str.len) == 0)
		{
			continue;
		}

		p = njt_snprintf(upstream_info->buffer.data, upstream_info->buffer.len, "%V%V!", &error, &items->key);
		upstream_info->msg = upstream_info->buffer;
		upstream_info->msg.len = p - upstream_info->buffer.data;
	}
	if (upstream_info->msg.len > 0)
	{
		return NJT_ERROR;
	}
	return NJT_OK;
}
njt_http_dyn_upstream_info_t *njt_http_parser_upstream_data(njt_str_t json_str, njt_uint_t method)
{
	njt_json_manager json_body;
	njt_pool_t *server_pool;
	njt_http_dyn_upstream_info_t *upstream_info;
	njt_int_t rc;
	njt_str_t add = njt_string("add");
	njt_str_t del = njt_string("del");
	njt_str_t key;
	int32_t buffer_len;
	njt_json_element *items;

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
	upstream_info = njt_pcalloc(server_pool, sizeof(njt_http_dyn_upstream_info_t));
	if (upstream_info == NULL)
	{
		njt_destroy_pool(server_pool);
		return NULL;
	}

	// upstream_info->type = -1;
	upstream_info->pool = server_pool;
	buffer_len = json_str.len + 1024;
	buffer_len = (buffer_len > NJT_MAX_CONF_ERRSTR ? buffer_len : NJT_MAX_CONF_ERRSTR);
	upstream_info->buffer.len = 0;
	upstream_info->buffer.data = njt_pcalloc(upstream_info->pool, buffer_len);
	if (upstream_info->buffer.data != NULL)
	{
		upstream_info->buffer.len = buffer_len;
	}

	rc = njt_http_check_top_server(&json_body, upstream_info);
	if (rc == NJT_ERROR)
	{
		goto end;
	}

	njt_str_set(&key, "type");
	rc = njt_struct_top_find(&json_body, &key, &items);
	if (rc != NJT_OK || items->type != NJT_JSON_STR)
	{
		njt_str_set(&upstream_info->msg, "type error!!!");
		goto end;
	}
	else
	{
		upstream_info->type = njt_del_headtail_space(items->strval);
		if (method != 0 && upstream_info->type.len == add.len && njt_strncmp(upstream_info->type.data, add.data, upstream_info->type.len) == 0 && method != NJT_HTTP_POST)
		{
			njt_str_set(&upstream_info->msg, "no support method when add server!");
			goto end;
		}
		if (method != 0 && upstream_info->type.len == del.len && njt_strncmp(upstream_info->type.data, del.data, upstream_info->type.len) == 0 && method != NJT_HTTP_PUT)
		{
			njt_str_set(&upstream_info->msg, "no support method when del server!");
			goto end;
		}
		if ((upstream_info->type.len == add.len && njt_strncmp(upstream_info->type.data, add.data, upstream_info->type.len) == 0) || (upstream_info->type.len == del.len && njt_strncmp(upstream_info->type.data, del.data, upstream_info->type.len) == 0))
		{
		}
		else
		{
			njt_str_set(&upstream_info->msg, "type error!!!");
			goto end;
		}
	}

	njt_str_set(&key, "upstream_name");
	rc = njt_struct_top_find(&json_body, &key, &items);
	if (rc == NJT_OK)
	{
		if (items->type != NJT_JSON_STR)
		{
			njt_str_set(&upstream_info->msg, "upstream_name error!");
			goto end;
		}
		upstream_info->old_upstream_name = njt_del_headtail_space(items->strval);
		upstream_info->upstream_name = upstream_info->old_upstream_name;
		if (upstream_info->old_upstream_name.len == 0)
		{
			njt_str_set(&upstream_info->msg, "upstream_name is null!");
			goto end;
		}
	}
	else
	{
		if (upstream_info->type.len == del.len && njt_strncmp(upstream_info->type.data, del.data, upstream_info->type.len) == 0)
		{
			njt_str_set(&upstream_info->msg, "upstream_name is null!");
			goto end;
		}
	}

	njt_str_set(&key, "upstream_body");
	rc = njt_struct_top_find(&json_body, &key, &items);
	if (rc == NJT_OK)
	{
		if (items->type != NJT_JSON_STR)
		{
			njt_str_set(&upstream_info->msg, "upstream_name error!");
			goto end;
		}
		upstream_info->upstream_body = njt_del_headtail_space(items->strval);
	}

end:
	return upstream_info;
}

static njt_int_t njt_http_upstream_write_file(njt_fd_t fd, njt_http_dyn_upstream_info_t *upstream_info)
{

	u_char *p, *data;
	int32_t rlen, buffer_len, remain;
	njt_str_t add_escape_val;
	buffer_len = upstream_info->buffer.len;
	remain = buffer_len;
	data = upstream_info->buffer.data;

	if (upstream_info)
	{
		njt_memzero(data, buffer_len);

		p = data;
		p = njt_snprintf(p, remain, "upstream ");
		remain = data + buffer_len - p;

		if (upstream_info->old_upstream_name.len != 0 && upstream_info->old_upstream_name.data != NULL)
		{

			p = njt_snprintf(p, remain, "%V {\n", &upstream_info->old_upstream_name);
			remain = data + buffer_len - p;
		}
		if (upstream_info->upstream_body.len != 0 && upstream_info->upstream_body.data != NULL)
		{
			add_escape_val = upstream_info->upstream_body;
			if (add_escape_val.len > 0 && add_escape_val.data[add_escape_val.len - 1] != ';' && add_escape_val.data[add_escape_val.len - 1] != '}')
			{
				p = njt_snprintf(p, remain, " %V; \n}", &add_escape_val);
			}
			else
			{
				p = njt_snprintf(p, remain, " %V \n}", &add_escape_val);
			}
			remain = data + buffer_len - p;
		}

		rlen = njt_write_fd(fd, data, p - data);
		if (rlen < 0)
		{
			return NJT_ERROR;
		}
	}
	return NJT_OK;
}
static njt_int_t njt_http_dyn_upstream_write_data(njt_http_dyn_upstream_info_t *upstream_info)
{

	njt_fd_t fd;
	njt_int_t rc = NJT_OK;
	njt_http_upstream_srv_conf_t *upstream;
	u_char *p; // *data;

	njt_str_t server_file = njt_string("add_ups.txt");
	njt_str_t server_path;
	njt_str_t server_full_file;

	upstream_info->upstream_name = upstream_info->old_upstream_name;
	if(njet_master_cycle != NULL) {
		upstream = njt_http_util_find_upstream((njt_cycle_t *)njet_master_cycle, &upstream_info->upstream_name);
	} else {
		upstream = njt_http_util_find_upstream((njt_cycle_t *)njt_cycle, &upstream_info->upstream_name);
	}
	upstream_info->upstream = upstream;

	server_path = njt_cycle->prefix;

	server_full_file.len = server_path.len + server_file.len + 50; //  workid_add_server.txt
	server_full_file.data = njt_pcalloc(upstream_info->pool, server_full_file.len);
	p = njt_snprintf(server_full_file.data, server_full_file.len, "%Vlogs/%d_%d_%V", &server_path, njt_process, njt_worker,
					 &server_file);

	server_full_file.len = p - server_full_file.data;
	fd = njt_open_file(server_full_file.data, NJT_FILE_CREATE_OR_OPEN | NJT_FILE_RDWR, NJT_FILE_TRUNCATE,
					   NJT_FILE_DEFAULT_ACCESS);
	if (fd == NJT_INVALID_FILE)
	{
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "njt_http_dyn_upstream_write_data njt_open_file[%V] error!", &server_full_file);
		rc = NJT_ERROR;
		goto out;
	}
	rc = njt_http_upstream_write_file(fd, upstream_info);

	if (njt_close_file(fd) == NJT_FILE_ERROR)
	{
	}

	if (rc == NJT_ERROR)
	{
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "njt_http_upstream_write_data error!");
		goto out;
	}
	(*upstream_info).file = server_full_file;

out:
	return rc;
}
