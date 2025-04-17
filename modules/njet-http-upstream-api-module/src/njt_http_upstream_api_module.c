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


#include "njt_http_upstream_api_module.h"
#include "njt_str_util.h"
#include <njt_http_util.h>
#include "njt_http_api_register_module.h"
#include <njt_conf_ext_module.h>
#include <njt_http_kv_module.h>
#include <njt_rpc_result_util.h>
#include "njt_http_sendmsg_module.h"
#include <njt_http_ext_module.h>

#define MIN_UPSTREAM_API_BODY_LEN 2
#define MAX_UPSTREAM_API_BODY_LEN 5242880
#define MIN_UPSTREAM_API_VERSION 1
#define MAX_UPSTREAM_API_VERSION 1

extern njt_cycle_t *njet_master_cycle;
typedef struct
{
	njt_pool_t *pool;
	njt_str_t *topic;
	njt_str_t *value;
	njt_uint_t method;
	void *ctx;
	njt_uint_t status;
	njt_int_t rc;
	njt_str_t out;

} njt_http_upstream_api_request_topic;

static njt_int_t
njt_http_upstream_api_handler(njt_http_request_t *r);

static njt_int_t
njt_http_upstream_api_init_worker(njt_cycle_t *cycle);

static void *
njt_http_upstream_api_create_main_conf(njt_conf_t *cf);

static njt_int_t
njt_http_upstream_api_init(njt_conf_t *cf);

static void
njt_http_upstream_api_read_data(njt_http_request_t *r);

static njt_int_t njt_http_upstream_api_rpc_send(njt_http_request_t *r, njt_str_t *module_name, njt_str_t *msg, int retain);
static void njt_get_upstream_api_topic(njt_http_request_t *r, njt_str_t *out_topic);
static int njt_http_upstream_api_request_output(njt_http_request_t *r, njt_int_t code, njt_str_t *msg);

typedef struct njt_http_upstream_api_loc_conf_s
{
} njt_http_upstream_api_loc_conf_t;
typedef struct njt_http_upstream_api_main_conf_s
{
	njt_http_request_t **reqs;
	njt_int_t size;
} njt_http_upstream_api_main_conf_t;

typedef struct
{
	njt_http_request_t *req;
	njt_int_t index;
	njt_http_upstream_api_main_conf_t *dlmcf;
} njt_http_upstream_api_rpc_ctx_t;


static njt_command_t njt_http_upstream_api_commands[] = {
	njt_null_command};

static njt_http_module_t njt_http_upstream_api_module_ctx = {
	NULL,						/* preconfiguration */
	njt_http_upstream_api_init, /* postconfiguration */

	njt_http_upstream_api_create_main_conf, /* create main configuration */
	NULL,									/* init main configuration */

	NULL, /* create server configuration */
	NULL, /* merge server configuration */

	NULL, /* create location configuration */
	NULL   /* merge location configuration */
};

njt_module_t njt_http_upstream_api_module = {
	NJT_MODULE_V1,
	&njt_http_upstream_api_module_ctx, /* module context */
	njt_http_upstream_api_commands,	   /* module directives */
	NJT_HTTP_MODULE,				   /* module type */
	NULL,							   /* init master */
	NULL,							   /* init module */
	njt_http_upstream_api_init_worker, /* init process */
	NULL,							   /* init thread */
	NULL,							   /* exit thread */
	NULL,							   /* exit process */
	NULL,							   /* exit master */
	NJT_MODULE_V1_PADDING};

static njt_int_t
njt_http_upstream_api_init(njt_conf_t *cf)
{
	
	njt_http_api_reg_info_t h;
	njt_http_upstream_api_main_conf_t *mcf;
	njt_str_t module_key = njt_string("/v1/upstream_api");
	njt_memzero(&h, sizeof(njt_http_api_reg_info_t));
	h.key = &module_key;
	h.handler = njt_http_upstream_api_handler;
	njt_http_api_module_reg_handler(&h);

	mcf = njt_http_conf_get_module_main_conf(cf, njt_http_upstream_api_module);
	if (mcf->size == NJT_CONF_UNSET)
	{
		mcf->size = 500;
	}

	mcf->reqs = njt_pcalloc(cf->pool, sizeof(njt_http_request_t *) * (mcf->size));
	if (mcf->reqs == NULL)
	{
		njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_http_upstream_api_init alloc mem error");
		return NJT_ERROR;
	}
	return NJT_OK;
}

static void *
njt_http_upstream_api_create_main_conf(njt_conf_t *cf)
{
	// ssize_t size;
	// njt_str_t zone = njt_string("api_dy_server");

	njt_http_upstream_api_main_conf_t *uclcf;

	// size = (ssize_t)(10 * njt_pagesize);
	uclcf = njt_pcalloc(cf->pool, sizeof(njt_http_upstream_api_main_conf_t));
	if (uclcf == NULL)
	{
		njt_log_error(NJT_LOG_ERR, cf->log, 0, "malloc njt_http_upstream_api_main_conf_t eror");
		return NULL;
	}
	uclcf->size = NJT_CONF_UNSET;
	return uclcf;
}
static njt_int_t
njt_http_upstream_api_handler(njt_http_request_t *r)
{
	njt_int_t rc = NJT_OK;
	njt_str_t msg, topic;
	if (njet_master_cycle == NULL)
	{
		return NJT_DONE;
	}
	njt_str_null(&msg);
	njt_str_t srv_err = njt_string("{\"code\":500,\"msg\":\"server error\"}");

	if (r->method == NJT_HTTP_PATCH || r->method == NJT_HTTP_POST)
	{
		rc = njt_http_read_client_request_body(r, njt_http_upstream_api_read_data);
		if (rc == NJT_ERROR || rc >= NJT_HTTP_SPECIAL_RESPONSE)
		{
			return rc;
		}
		return NJT_DONE;
	}
	else if (r->method == NJT_HTTP_GET || r->method == NJT_HTTP_DELETE)
	{

		njt_str_t smsg = njt_string("{\"method\":\"GET\"}");
		njt_get_upstream_api_topic(r, &topic);
		if (topic.data == NULL)
		{
			rc = NJT_HTTP_INTERNAL_SERVER_ERROR;
			goto err;
		}
		rc = njt_http_upstream_api_rpc_send(r, &topic, &smsg, 0);
		if (rc != NJT_OK)
		{
			goto err;
		}
		++r->main->count;
		return NJT_DONE;
	}
	else
	{
		rc = NJT_HTTP_UPS_API_METHOD_NOT_SUPPORTED;
		njt_str_set(&srv_err, "{\"error\":{\"status\":405,\"text\":\"method not supported\",\"code\":\"MethodNotSupported\"},\"request_id\":\"N/A\",\"href\":\"https://njet.org/en/docs/http/njt_http_api_module.html\"}");
	}

err:
	return njt_http_upstream_api_request_output(r, rc, &srv_err);
}

static njt_int_t
njt_http_upstream_api_init_worker(njt_cycle_t *cycle)
{
	return NJT_OK;
}

static void
njt_http_upstream_api_read_data(njt_http_request_t *r)
{
	njt_str_t json_str;
	njt_int_t rc;
	njt_str_t topic_name;

	rc = njt_http_util_read_request_body(r, &json_str, MIN_UPSTREAM_API_BODY_LEN, MAX_UPSTREAM_API_BODY_LEN);
	if (rc != NJT_OK)
	{
		njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
					   "request_body error in function %s", __func__);
		rc = NJT_HTTP_INTERNAL_SERVER_ERROR;
		goto err;
	}
	njt_get_upstream_api_topic(r, &topic_name);
	if (topic_name.data == NULL)
	{
		rc = NJT_HTTP_INTERNAL_SERVER_ERROR;
		goto err;
	}
	rc = njt_http_upstream_api_rpc_send(r, &topic_name, &json_str, 0);
	if (rc == NJT_OK)
	{
		++r->main->count;
	}
	else
	{
		rc = NJT_HTTP_INTERNAL_SERVER_ERROR;
	}

	goto out;

err:
	njt_http_upstream_api_request_output(r, rc, NULL);

out:
	njt_http_finalize_request(r, rc);

	return;
}

static int njt_http_upstream_api_request_output(njt_http_request_t *r, njt_int_t code, njt_str_t *msg)
{
	njt_int_t rc;
	njt_buf_t *buf;
	njt_chain_t out;
	njt_http_upstream_api_request_topic request_topic;
	njt_uint_t status;
	u_char *p;

	request_topic.pool = r->pool;
	request_topic.status = 0;

	if (code == NJT_OK)
	{
		if (msg == NULL || msg->len < sizeof(request_topic.status))
		{
			r->headers_out.status = NJT_HTTP_NO_CONTENT;
			msg->len = 0;
		}
		else
		{
			p = msg->data + msg->len - sizeof(request_topic.status);
			status = *(njt_uint_t *)p;
			r->headers_out.status = status;
			msg->len = msg->len - sizeof(request_topic.status);
		}
	}
	else
	{
		r->headers_out.status = NJT_HTTP_NOT_FOUND;
	}
	r->headers_out.content_length_n = 0;
	if (msg != NULL && msg->len > 0)
	{
		njt_str_t type = njt_string("application/json");
		r->headers_out.content_type = type;
		r->headers_out.content_length_n = msg->len;
	}
	if (r->headers_out.content_length)
	{
		r->headers_out.content_length->hash = 0;
		r->headers_out.content_length = NULL;
	}
	rc = njt_http_send_header(r);
	if (rc == NJT_ERROR || rc > NJT_OK || r->header_only || msg == NULL || msg->len < 1)
	{
		return rc;
	}
	buf = njt_create_temp_buf(r->pool, msg->len);
	if (buf == NULL)
	{
		return NJT_ERROR;
	}
	njt_memcpy(buf->pos, msg->data, msg->len);
	buf->last = buf->pos + msg->len;
	buf->last_buf = 1;
	out.buf = buf;
	out.next = NULL;
	return njt_http_output_filter(r, &out);
}
static void njt_get_upstream_api_topic(njt_http_request_t *r, njt_str_t *out_topic)
{
	u_char *p;
	njt_str_t prefix = njt_string("/worker_a/dyn/upstream_api/");
	out_topic->len = prefix.len + r->uri.len + 10; // 10 method
	out_topic->data = njt_pcalloc(r->pool, out_topic->len);
	if (out_topic->data != NULL)
	{
		p = njt_snprintf(out_topic->data, out_topic->len, "%V%d%V", &prefix, r->method, &r->uri);
		out_topic->len = p - out_topic->data;
	}
}
static njt_int_t njt_http_upstream_api_get_free_index(njt_http_upstream_api_main_conf_t *dlmcf)
{
	njt_int_t i;

	for (i = 0; i < dlmcf->size; ++i)
	{
		if (dlmcf->reqs[i] == NULL)
		{
			return i;
		}
	}
	return -1;
}
static void njt_http_upstream_api_cleanup_handler(void *data)
{
	njt_http_upstream_api_rpc_ctx_t *ctx;

	ctx = data;
	if (ctx->dlmcf->size > ctx->index && ctx->dlmcf->reqs[ctx->index] == ctx->req)
	{
		ctx->dlmcf->reqs[ctx->index] = NULL;
	}
}

static int njt_http_upstream_api_rpc_msg_handler(njt_dyn_rpc_res_t *res, njt_str_t *msg)
{
	njt_http_upstream_api_rpc_ctx_t *ctx;
	njt_http_request_t *req;
	njt_int_t rc;

	rc = NJT_ERROR;
	njt_str_t err_msg = njt_string("{\"error\":{\"status\":404,\"text\":\"unknown error\",\"code\":\"UnknownError\"},\"request_id\":\"N/A\",\"href\":\"https://njet.org/en/docs/http/njt_http_api_module.html\"}");
	ctx = res->data;
	njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "hand rpc time : %M", njt_current_msec);
	if (ctx->dlmcf->size > ctx->index && ctx->dlmcf->reqs[ctx->index] == ctx->req)
	{
		req = ctx->req;
		if (res->rc == RPC_RC_OK)
		{
			rc = njt_http_upstream_api_request_output(req, NJT_OK, msg);
		}
		if (res->rc == RPC_RC_TIMEOUT)
		{
			rc = njt_http_upstream_api_request_output(req, NJT_HTTP_INTERNAL_SERVER_ERROR, &err_msg);
		}
		njt_http_finalize_request(req, rc);
	}

	return NJT_OK;
}

static njt_int_t njt_http_upstream_api_rpc_send(njt_http_request_t *r, njt_str_t *module_name, njt_str_t *msg, int retain)
{
	njt_http_upstream_api_main_conf_t *dlmcf;
	njt_int_t index;
	njt_int_t rc;
	njt_http_upstream_api_rpc_ctx_t *ctx;
	njt_pool_cleanup_t *cleanup;

	r->write_event_handler = njt_http_request_empty_handler;
	dlmcf = njt_http_get_module_main_conf(r, njt_http_upstream_api_module);
	if (dlmcf == NULL)
	{
		goto err;
	}
	index = njt_http_upstream_api_get_free_index(dlmcf);
	if (index == -1)
	{
		njt_log_error(NJT_LOG_ERR, r->pool->log, 0, "not find request free index ");
		goto err;
	}
	else
	{
		njt_log_error(NJT_LOG_INFO, r->pool->log, 0, "use index :%i ", index);
	}
	ctx = njt_pcalloc(r->pool, sizeof(njt_http_upstream_api_rpc_ctx_t));
	if (ctx == NULL)
	{
		njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
					   "could not alloc mem in function %s", __func__);
		goto err;
	}
	ctx->index = index;
	ctx->req = r;
	ctx->dlmcf = dlmcf;
	cleanup = njt_pool_cleanup_add(r->pool, 0);
	if (cleanup == NULL)
	{
		njt_log_error(NJT_LOG_ERR, r->pool->log, 0, "request cleanup error ");
		goto err;
	}
	cleanup->handler = njt_http_upstream_api_cleanup_handler;
	cleanup->data = ctx;
	njt_log_error(NJT_LOG_INFO, r->pool->log, 0, "send rpc time : %M", njt_current_msec);


	rc = njt_dyn_rpc(module_name, msg, retain, index, njt_http_upstream_api_rpc_msg_handler, ctx);
	if (rc == NJT_OK)
	{
		dlmcf->reqs[index] = r;
	}

	return rc;
		
	

err:
	return NJT_ERROR;
}