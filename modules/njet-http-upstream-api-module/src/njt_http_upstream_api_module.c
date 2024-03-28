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

#include "njt_http_upstream_api_parser.h"
#include "njt_http_upstream_api_server_list_parser.h"
#include "njt_http_upstream_list_api_parser.h"
#include "njt_http_upstream_api_module.h"  
#include "njt_http_upstream_api_error_msg.h" 
#include "njt_str_util.h"
#include <njt_http_util.h>
#include "njt_http_api_register_module.h"

static njt_str_t upstream_api_module_name = njt_string("upstream_api");
static njt_str_t status_down = njt_string("down");  
static njt_str_t status_unhealthy = njt_string("unhealthy");  
static njt_str_t status_draining = njt_string("draining");  
static njt_str_t status_checking = njt_string("checking");  
static njt_str_t status_unavail = njt_string("unavail");  
static njt_str_t status_up = njt_string("up");  

#define MIN_UPSTREAM_API_BODY_LEN 2
#define MAX_UPSTREAM_API_BODY_LEN 5242880
#define MIN_UPSTREAM_API_VERSION  1
#define MAX_UPSTREAM_API_VERSION  1

#define NJT_GET_CHAR_NUM_INT(x)   \
	({              \
	 njt_int_t num = 1,num2 = 1;  \
	 int64_t  n=x; \
	 uint64_t un=x; \
	 if (n < 0) { \
	 while (n != 0) { \
	 num++;      \
	 n /= 10;     \
	 }                \
	 } else if (n > 0) {  \
	 num = 0; \
	 while (n != 0) { \
	 num++;      \
	 n /= 10;     \
	 }                \
	 }  \
	 if(un > 0) { \
	 num2 = 0; \
	 while (un != 0) { \
	 num2++;      \
	 un /= 10;     \
	 } \
	 } \
		(num > num2?num:num2);      \
	})



#define njt_get_peer_status_name(peer) \
	({ \
	 njt_str_t *msg;  \
	 if(peer->down == 1) {  \
	 msg = &status_down; \
	 } \
	 else if(peer->hc_down%100 == 1 ) {  \
	 msg = &status_unhealthy;  \
	 } \
	 else if(peer->hc_down/100 == 1 ) {  \
	 msg = &status_draining; \
	 } \
	 else if(peer->hc_down%100 == 2 ) {  \
	 msg = &status_checking; \
	 } else if (peer->max_fails   && peer->fails >= peer->max_fails) { \
	 msg = &status_unavail;  \
	 } else { \
		 msg = &status_up; \
	 }\
		(msg);\
	})




#define NJT_GET_CHAR_NUM_C(n)  (n.len)   //char
#define NJT_GET_CHAR_NUM_B(n)  (n>0?4:5)   //bool
//#define NJT_GET_CHAR_NUM_S(n)  (n>0?16:16)   //up,down
#define NJT_GET_CHAR_NUM_S(n)  (16)   //up,down



extern njt_cycle_t *njet_master_cycle;



static njt_int_t
njt_http_upstream_api_handler(njt_http_request_t *r);
static char *
njt_http_upstream_api(njt_conf_t *cf, njt_command_t *cmd, void *conf);

static njt_int_t
njt_http_upstream_api_init_worker(njt_cycle_t *cycle);
static void *
njt_http_upstream_api_create_loc_conf(njt_conf_t *cf);
static char *njt_http_upstream_api_merge_loc_conf(njt_conf_t *cf,
		void *parent, void *child);
static njt_int_t
njt_http_upstream_api_err_out(njt_http_request_t *r, njt_int_t code,njt_str_t *msg,
		njt_chain_t *out);
static ssize_t
njt_http_upstream_api_out_len(njt_chain_t *out);

static void *
njt_http_upstream_api_create_main_conf(njt_conf_t *cf);

static njt_int_t
njt_http_upstream_api_init(njt_conf_t *cf);

static njt_shm_zone_t *
njt_shared_memory_get(njt_cycle_t *cycle, njt_str_t *name, size_t size, void *tag);

static njt_int_t  njt_http_upstream_api_packet_out(njt_http_request_t *r,njt_str_t *to_json,njt_chain_t *out);


typedef njt_int_t (*njt_upstream_api_process_get_pt)(njt_http_request_t *r,
		void *target_uscf,
		ssize_t server_id, njt_flag_t detailed, njt_chain_t *out);
typedef njt_int_t (*njt_upstream_api_process_reset_pt)(njt_http_request_t *r,
		void *target_uscf, njt_chain_t *out);
typedef njt_int_t (*njt_upstream_api_process_delete_pt)(njt_http_request_t *r,
		void *uscf,
		njt_uint_t id, njt_chain_t *out);
typedef njt_int_t (*njt_upstream_api_process_patch_pt)(njt_http_request_t *r,
		void *uscf,
		njt_uint_t id);
typedef njt_int_t (*njt_upstream_api_process_post_pt)(njt_http_request_t *r,
		void *uscf);
typedef njt_int_t (*njt_upstream_state_save_pt)(njt_http_request_t *r,
		void *uscf);
extern void to_oneline_json_upstream_list_upstreamDef(njt_pool_t *pool, upstream_list_upstreamDef_t *out, njt_str_t *buf, njt_int_t flags); 
extern void get_json_length_upstream_list_upstreamDef(njt_pool_t *pool, upstream_list_upstreamDef_t *out, size_t *length, njt_int_t flags);
extern void get_json_length_server_list_serverDef(njt_pool_t *pool, server_list_serverDef_t *out, size_t *length, njt_int_t flags); 
extern void to_oneline_json_server_list_serverDef(njt_pool_t *pool, server_list_serverDef_t *out, njt_str_t *buf, njt_int_t flags);

extern void get_json_length_server_list(njt_pool_t *pool, server_list_t *out, size_t *length, njt_int_t flags);
extern  void to_oneline_json_server_list(njt_pool_t *pool, server_list_t *out, njt_str_t* buf, njt_int_t flags);
njt_str_t* to_json_upstream_list_upstreamDef(njt_pool_t *pool, upstream_list_upstreamDef_t* out, njt_int_t flags);
njt_str_t* to_json_one_serverDef(njt_pool_t *pool, server_list_serverDef_t* out, njt_int_t flags);
njt_str_t* to_json_one_server_list(njt_pool_t *pool, server_list_t* out, njt_int_t flags);

static njt_int_t
njt_stream_upstream_api_process_get(njt_http_request_t *r,
		void *cf,
		ssize_t server_id, njt_flag_t detailed, njt_chain_t *out);
static njt_int_t
njt_stream_upstream_api_process_reset(njt_http_request_t *r,
		void *cf,
		njt_chain_t *out);
static njt_int_t
njt_stream_upstream_api_process_delete(njt_http_request_t *r,
		void *cf,
		njt_uint_t id, njt_chain_t *out);
static njt_int_t
njt_stream_upstream_api_process_patch(njt_http_request_t *r,
		void *cf,
		njt_uint_t id);
static njt_int_t
njt_stream_upstream_api_process_post(njt_http_request_t *r,
		void *cf);	  
static njt_int_t
njt_stream_upstream_state_save(njt_http_request_t *r,
		void *cf);
static upstream_list_peerDef_t *
njt_stream_upstream_api_compose_one_detail_server(njt_http_request_t *r,
		njt_stream_upstream_rr_peer_t *peer,
		njt_flag_t backup, njt_flag_t is_parent,njt_str_t upstream_name);	

static server_list_serverDef_t *
njt_stream_upstream_api_compose_one_server_schemo(njt_http_request_t *r,
		njt_stream_upstream_rr_peer_t *peer,
		njt_flag_t backup, njt_flag_t is_parent,njt_str_t upstream_name);	

static void
njt_stream_upstream_api_post(njt_http_request_t *r);

static njt_int_t
njt_stream_upstream_api_compose_one_server(njt_http_request_t *r,
		void *p, njt_stream_upstream_rr_peer_t      *peer,njt_flag_t is_backup,ssize_t id,server_list_serverDef_t                    **server_one);


typedef struct njt_http_upstream_api_ctx_s {
	void   *peers;
	njt_uint_t                     id;
	njt_resolver_t                 *resolver;
	njt_flag_t                     keep_alive;
	njt_int_t                      hc_type;
	void                           *uscf;
} njt_http_upstream_api_ctx_t,njt_stream_upstream_api_ctx_t;

typedef struct njt_http_upstream_api_loc_conf_s {
	njt_uint_t  enable;
	njt_uint_t write;
} njt_http_upstream_api_loc_conf_t;
typedef struct njt_http_upstream_api_main_conf_s {
	njt_shm_zone_t *shm_zone_http;
	njt_http_upstream_rr_peers_t *peers_http;
	njt_shm_zone_t *shm_zone_stream;
	njt_stream_upstream_rr_peers_t *peers_stream;
	njt_uint_t  enable;
	njt_uint_t write;
} njt_http_upstream_api_main_conf_t;

typedef struct njt_http_upstream_api_peer_s {
	njt_str_t    server;
	njt_int_t   weight;
	njt_int_t   max_conns;
	njt_int_t   max_fails;
	njt_int_t   fail_timeout;
	njt_int_t   slow_start;
	union {
		njt_str_t    route;
		njt_str_t    msg;
	};
	njt_int_t   backup;
	njt_int_t   drain;
	njt_int_t   down;
	njt_flag_t  domain;
} njt_http_upstream_api_peer_t;

//{\"processing\":3,\"requests\":8,\"responses\":{\"1xx\":0,\"2xx\":4,\"3xx\":4,\"4xx\":0,\"5xx\":0,\"codes\":{\"200\":4,\"301\":0,\"404\":0,\"503\":0},\"total\":8},\"discarded\":0,\"received\":3828,\"sent\":88036}
typedef struct njt_http_upstream_peer_code_s {
	uint64_t    one;
	uint64_t    two;
	uint64_t    three;
	uint64_t    four;
	uint64_t    five;
	uint64_t    processing;
	uint64_t    requests;
	uint64_t    discarded;
	uint64_t    received;
	uint64_t    sent;
	njt_array_t *codes;
	uint64_t    total;
} njt_http_upstream_peer_code_t;


static njt_http_upstream_api_peer_t       json_peer;

static njt_command_t njt_http_upstream_api_commands[] = {
	{
		njt_string("api"),
		NJT_HTTP_LOC_CONF | NJT_CONF_ANY,
		njt_http_upstream_api,
		0,
		0,
		NULL
	},
	njt_null_command
};


static njt_http_module_t njt_http_upstream_api_module_ctx = {
	NULL,                              /* preconfiguration */
	njt_http_upstream_api_init,                              /* postconfiguration */

	njt_http_upstream_api_create_main_conf,                              /* create main configuration */
	NULL,                              /* init main configuration */

	NULL,                              /* create server configuration */
	NULL,                              /* merge server configuration */

	njt_http_upstream_api_create_loc_conf, /* create location configuration */
	njt_http_upstream_api_merge_loc_conf   /* merge location configuration */
};

njt_module_t njt_http_upstream_api_module = {
	NJT_MODULE_V1,
	&njt_http_upstream_api_module_ctx, /* module context */
	njt_http_upstream_api_commands,    /* module directives */
	NJT_HTTP_MODULE,                    /* module type */
	NULL,                               /* init master */
	NULL,                               /* init module */
	njt_http_upstream_api_init_worker, /* init process */
	NULL,                               /* init thread */
	NULL,                               /* exit thread */
	NULL,                               /* exit process */
	NULL,                               /* exit master */
	NJT_MODULE_V1_PADDING
};


	static njt_int_t
njt_http_upstream_api_init(njt_conf_t *cf)
{
	njt_http_api_reg_info_t h;
	njt_str_t  module_key = njt_string("/v1/upstream_api");
	njt_memzero(&h, sizeof(njt_http_api_reg_info_t));
	h.key = &module_key;
	h.handler = njt_http_upstream_api_handler;
	njt_http_api_module_reg_handler(&h);
	return NJT_OK;
}




static njt_int_t njt_http_upstream_api_create_dynamic_server(njt_http_request_t *r,njt_http_upstream_rr_peer_t        *peer,njt_flag_t backup) {

	njt_http_upstream_api_main_conf_t *uclcf;
	njt_http_upstream_rr_peer_t        *new_peer,*tail_peer;
	njt_slab_pool_t                    *shpool;
	njt_http_upstream_api_ctx_t       *ctx;
	njt_http_upstream_rr_peers_t *peers;


	ctx = njt_http_get_module_ctx(r, njt_http_upstream_api_module);
	peers = ctx->peers;

	uclcf = njt_http_get_module_main_conf(r, njt_http_upstream_api_module);
	if(uclcf->peers_http == NULL || ctx == NULL || ctx->resolver == NULL) { // not support dynamic  domain server
		njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0,
				"add domain name:%V!",&peer->server);
		return NJT_HTTP_UPS_API_NO_RESOLVER;
	}
	shpool = uclcf->peers_http->shpool;
	njt_http_upstream_rr_peers_wlock(uclcf->peers_http);
	new_peer = njt_slab_calloc_locked(shpool, sizeof(njt_http_upstream_rr_peer_t));
	if(new_peer) {
		new_peer->server.data = njt_slab_calloc_locked(shpool, peer->server.len+1);
		if (new_peer->server.data) {
			new_peer->id = peer->id; //add dynamic  domain server
			new_peer->parent_id = peer->parent_id; 
			new_peer->server.len = peer->server.len;
			njt_cpystrn(new_peer->server.data, peer->server.data, peer->server.len+1);
			peer->hc_upstart =  njt_time();
			new_peer->weight    = peer->weight;
			new_peer->max_conns = peer->max_conns;
			new_peer->max_fails = peer->max_fails;
			new_peer->fail_timeout = peer->fail_timeout;
			new_peer->slow_start = peer->slow_start;
			new_peer->down = peer->down;
			new_peer->hc_down = peer->hc_down;
			new_peer->set_backup = backup;
			if(peers->name->len > 0) {  //zone name
				new_peer->name.len = peers->name->len;
				new_peer->name.data = njt_slab_calloc_locked(shpool, peers->name->len+1);
				if (new_peer->name.data) { 
					njt_cpystrn(new_peer->name.data, peers->name->data, peers->name->len+1);
				}
			}
			if(peer->route.len > 0) {
				new_peer->route.len = peer->route.len;
				new_peer->route.data = njt_slab_calloc_locked(shpool, peer->route.len+1);
				if (new_peer->route.data) { 
					njt_cpystrn(new_peer->route.data, peer->route.data, peer->route.len+1);
				}
			}
			new_peer->next = NULL;
			if(uclcf->peers_http->peer == NULL) {
				uclcf->peers_http->peer = new_peer;
			} else {
				for(tail_peer = uclcf->peers_http->peer;tail_peer->next != NULL; tail_peer = tail_peer->next);
				tail_peer->next = new_peer;
			}


			//uclcf->peers->peer = new_peer;
			//uclcf->peers_http->number++;
		} else {
			njt_slab_free_locked(shpool,new_peer);
		}
	}
	njt_http_upstream_rr_peers_unlock(uclcf->peers_http);
	return NJT_OK;


}

	static void *
njt_http_upstream_api_create_loc_conf(njt_conf_t *cf)
{
	//ssize_t size; 
	//njt_str_t zone = njt_string("api_dy_server");
	njt_http_upstream_api_loc_conf_t *uclcf;

	//size = (ssize_t)(10 * njt_pagesize);
	uclcf = njt_pcalloc(cf->pool, sizeof(njt_http_upstream_api_loc_conf_t));
	if (uclcf == NULL) {
		njt_log_error(NJT_LOG_ERR, cf->log, 0, "malloc uclcf eror");
		return NULL;
	}
	uclcf->write = NJT_CONF_UNSET_UINT;
	uclcf->enable =NJT_CONF_UNSET_UINT;
	return uclcf;
}

	static void *
njt_http_upstream_api_create_main_conf(njt_conf_t *cf)
{
	//ssize_t size; 
	//njt_str_t zone = njt_string("api_dy_server");

	njt_http_upstream_api_main_conf_t *uclcf;

	//size = (ssize_t)(10 * njt_pagesize);
	uclcf = njt_pcalloc(cf->pool, sizeof(njt_http_upstream_api_main_conf_t));
	if (uclcf == NULL) {
		njt_log_error(NJT_LOG_ERR, cf->log, 0, "malloc njt_http_upstream_api_main_conf_t eror");
		return NULL;
	}
	return uclcf;
}


static char *njt_http_upstream_api_merge_loc_conf(njt_conf_t *cf,
		void *parent, void *child)
{
	njt_http_upstream_api_loc_conf_t *prev = parent;
	njt_http_upstream_api_loc_conf_t *conf = child;

	njt_conf_merge_uint_value(conf->write, prev->write, 0);
	njt_conf_merge_uint_value(conf->enable, prev->enable, 0);

	return NJT_CONF_OK;
}


	static njt_int_t
njt_upstream_api_get_params(njt_array_t *path, njt_str_t *upstream,
		njt_str_t *id,njt_flag_t *upstream_type)
{
	njt_int_t           length;
	njt_str_t           *item;
	njt_int_t           version;

	item  = path->elts;
	length = path->nelts;

	if (length < 3 || length > 7) {
		return NJT_HTTP_UPS_API_PATH_NOT_FOUND;
	}
	if(item[0].len < 2) {
		return NJT_HTTP_UPS_API_UNKNOWN_VERSION;
	}
	version = njt_atoi(item[0].data+1, item[0].len-1);

	if (version < MIN_UPSTREAM_API_VERSION || version > MAX_UPSTREAM_API_VERSION) {
		return NJT_HTTP_UPS_API_UNKNOWN_VERSION;
	}
	*upstream_type = 0;
	if (njt_strncmp(item[1].data, "http", 4) == 0) {
		*upstream_type = 1;
		if(item[1].len != 4) {
			return NJT_HTTP_UPS_API_PATH_NOT_FOUND;
		}
	} 
	if (njt_strncmp(item[1].data, "stream", 6) == 0) {
		*upstream_type = 2;
		if(item[1].len != 6) {
			return NJT_HTTP_UPS_API_PATH_NOT_FOUND;
		}
	} 

	if(*upstream_type == 0) {
		return NJT_HTTP_UPS_API_PATH_NOT_FOUND;
	}
	if (item[2].len != 9 ||  njt_strncmp(item[2].data, "upstreams", 9) != 0) {
		return NJT_HTTP_UPS_API_PATH_NOT_FOUND;
	}


	if (length >= 4) {
		*upstream = item[3];
	}

	if (length >= 5) {
		if (item[4].len != 7 ||  njt_strncmp(item[4].data, "servers", 7) != 0) {
			return NJT_HTTP_UPS_API_PATH_NOT_FOUND;
		}
	}

	if (length >= 6) {
		*id = item[5];
	}

	return NJT_OK;
}

	static u_char *
njt_format_time(u_char *buf,njt_uint_t nt)
{
	time_t t;
	njt_uint_t mt;
	njt_tm_t  tm;  //njt_gmtime(entry[i].mtime, &tm);

	mt = nt%1000;
	t = (nt/1000);
	njt_gmtime(t, &tm);

	return njt_sprintf(buf, "%4d-%02d-%02dT%02d:%02d:%02d.%03dZ",  //",\"downstart\":\"2022-06-28T11:09:21.602Z\""
			tm.njt_tm_year, tm.njt_tm_mon,
			tm.njt_tm_mday, tm.njt_tm_hour,
			tm.njt_tm_min, tm.njt_tm_sec,mt);

}





	static njt_buf_t *
njt_http_upstream_api_get_out_buf(njt_http_request_t *r, ssize_t len,
		njt_chain_t *out)
{
	njt_buf_t                      *b;


	//if ((njt_uint_t)len > njt_pagesize) {
		/*The string len is larger than one buf*/

		njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
				"buffer size is beyond one pagesize. len=%d,njt_pagesize=%d",len,njt_pagesize);
	//}
	
		b = njt_create_temp_buf(r->pool,len);
		if(b == NULL){
			return NULL;
		}

		b->last_buf = 1;
		out->buf = b;
		out->next = NULL;
		return b;
}


	static njt_int_t
njt_http_upstream_api_insert_out_str(njt_http_request_t *r,
		njt_chain_t *out, njt_str_t *str)
{
	njt_buf_t                      *b;

	if(str->len == 0) {
		return NJT_OK;
	}
	if (str == NULL || str->data == NULL)  {
		njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
				"parameter error in function %s", __func__);
		return NJT_ERROR;
	}

	b = njt_http_upstream_api_get_out_buf(r, str->len, out);
	if (b == NULL) {
		njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
				"could not alloc buffer in function %s", __func__);
		return NJT_ERROR;
	}

	b->last = njt_snprintf(b->last, str->len, "%V", str);

	return NJT_OK;
}

	static upstream_list_peerDef_t *
njt_http_upstream_api_compose_one_detail_server(njt_http_request_t *r,
		njt_http_upstream_rr_peer_t *peer,
		njt_flag_t backup, njt_flag_t is_parent,njt_str_t upstream_name)
{

	njt_str_t                      *pname,data;
	njt_uint_t                      id,down_time;

	njt_str_t                     buf;
	njt_str_t                     timebuf;
	njt_str_t                     codes = njt_string("{}");


	buf.len = 256;
	buf.data = njt_pcalloc(r->pool,buf.len);

	timebuf.len = 128;
	timebuf.data = njt_pcalloc(r->pool,timebuf.len);

	upstream_list_peerDef_health_checks_t* health_checks = create_upstream_list_peerDef_health_checks(r->pool); //upstream_list_peerDef_health_checks_t* create_upstream_list_peerDef_health_checks(njt_pool_t *pool);
	upstream_list_peerDef_responses_t* responses = create_upstream_list_peerDef_responses(r->pool);  //upstream_list_peerDef_responses_t* create_upstream_list_peerDef_responses(njt_pool_t *pool);
	upstream_list_peerDef_t* peerDef = create_upstream_list_peerDef(r->pool);   //upstream_list_peerDef_t* create_upstream_list_peerDef(njt_pool_t *pool)
	if(peerDef == NULL || responses == NULL || health_checks == NULL){
		return NULL;
	}
	pname = (is_parent == 1?(&peer->server):(&peer->name));
	id =  (is_parent == 1?((njt_uint_t)peer->parent_id):(peer->id));
	if(peer->hc_downstart != 0) {

		down_time =  ((njt_uint_t)((njt_timeofday())->sec )*1000 + (njt_uint_t)((njt_timeofday())->msec) ) -  peer->hc_downstart + peer->hc_downtime;
		buf.len = njt_format_time(buf.data,peer->hc_downstart) - buf.data;
		
		set_upstream_list_peerDef_downstart(peerDef, &buf);
	} else {
		down_time = peer->hc_downtime;
		id = peer->id;
		pname = &peer->name;

	}
	if(peer->selected_time != 0) {
		timebuf.len = njt_format_time(timebuf.data,peer->selected_time) - timebuf.data;
		set_upstream_list_peerDef_selected(peerDef, &timebuf);

	}
	set_upstream_list_peerDef_id(peerDef, id);
	njt_str_copy_pool(r->pool,data,(*pname), return NULL;);
	set_upstream_list_peerDef_server(peerDef, &data);

	njt_str_copy_pool(r->pool,data,peer->server, return NULL;);
	set_upstream_list_peerDef_name(peerDef, &data);

	set_upstream_list_peerDef_backup(peerDef, backup);
	set_upstream_list_peerDef_weight(peerDef, peer->weight);
	set_upstream_list_peerDef_state(peerDef, njt_get_peer_status_name(peer));
	set_upstream_list_peerDef_active(peerDef, peer->conns);
	if( peer->max_conns != 0) {
		set_upstream_list_peerDef_max_conns(peerDef,peer->max_conns);
	}
	set_upstream_list_peerDef_requests(peerDef, peer->requests);
	if(peer->total_header_time != 0 && peer->requests != 0) {
		set_upstream_list_peerDef_header_time(peerDef,peer->total_header_time/peer->requests);

	} 
	if(peer->total_response_time != 0 && peer->requests != 0) {
		set_upstream_list_peerDef_response_time(peerDef,peer->total_response_time/peer->requests);

	} 
	set_upstream_list_peerDef_responses_one(responses,0);
	set_upstream_list_peerDef_responses_two(responses,0);
	set_upstream_list_peerDef_responses_three(responses,0);
	set_upstream_list_peerDef_responses_four(responses,0);
	set_upstream_list_peerDef_responses_five(responses,0);
	set_upstream_list_peerDef_responses_total(responses,0);
	set_upstream_list_peerDef_responses_codes(responses,&codes);

	set_upstream_list_peerDef_responses(peerDef,responses);


	set_upstream_list_peerDef_sent(peerDef, 0);
	set_upstream_list_peerDef_received(peerDef, 0);

	set_upstream_list_peerDef_fails(peerDef, peer->total_fails);
	set_upstream_list_peerDef_unavail(peerDef, peer->unavail);


	set_upstream_list_peerDef_health_checks_checks(health_checks,peer->hc_checks);
	set_upstream_list_peerDef_health_checks_fails(health_checks,peer->hc_fails);
	set_upstream_list_peerDef_health_checks_unhealthy(health_checks,peer->hc_unhealthy);
	if(peer->hc_checks != 0) {
		set_upstream_list_peerDef_health_checks_last_passed(health_checks,peer->hc_last_passed);
	}
	set_upstream_list_peerDef_health_checks(peerDef,health_checks);
	set_upstream_list_peerDef_downtime(peerDef, down_time);





	return peerDef;
}








	static server_list_serverDef_t *
njt_http_upstream_api_compose_one_server_schemo(njt_http_request_t *r,
		njt_http_upstream_rr_peer_t *peer,
		njt_flag_t backup, njt_flag_t is_parent,njt_str_t upstream_name)
{
	njt_str_t                      *pname,data;
	njt_uint_t                      id;
	u_char                    *p;

	njt_str_t                     slow_str,fail_timeout;

	slow_str.len = NJT_INT64_LEN + 1;
	slow_str.data = njt_pcalloc(r->pool,slow_str.len);

	fail_timeout.len = NJT_INT64_LEN + 1;
	fail_timeout.data = njt_pcalloc(r->pool,fail_timeout.len);

	server_list_serverDef_t* server_one = create_server_list_serverDef(r->pool);
	if(server_one == NULL || slow_str.data == NULL || fail_timeout.data == NULL) {
		return NULL;
	}





	p = njt_snprintf(slow_str.data, slow_str.len,"%ds",peer->slow_start);	
	slow_str.len = p - slow_str.data;

	p = njt_snprintf(fail_timeout.data, fail_timeout.len,"%ds",peer->fail_timeout);	
	fail_timeout.len = p - fail_timeout.data;


	if(peer->parent_id >= 0 && is_parent == 0) {
		id =  peer->id;
		pname = &peer->name;
		set_server_list_serverDef_parent(server_one,peer->parent_id);
		set_server_list_serverDef_host(server_one,&peer->server);

	} else {
		pname = (is_parent == 1?(&peer->server):(&peer->name));
		id =  peer->id;
	}

	set_server_list_serverDef_id(server_one, id);

	njt_str_copy_pool(r->pool,data,(*pname), return NULL;);


	set_server_list_serverDef_server(server_one, &data);
	set_server_list_serverDef_weight(server_one, peer->weight);
	set_server_list_serverDef_max_conns(server_one,peer->max_conns);
	set_server_list_serverDef_max_fails(server_one,peer->max_fails);
	set_server_list_serverDef_fail_timeout(server_one,&fail_timeout);
	set_server_list_serverDef_slow_start(server_one,&slow_str);

	njt_str_copy_pool(r->pool,data,peer->route, return NULL;);

	set_server_list_serverDef_route(server_one,&data);
	set_server_list_serverDef_backup(server_one,(backup ? true : false));
	set_server_list_serverDef_down(server_one,(peer->down == 1 ? true : false));
	if(peer->hc_down/100 == 1) {
		set_server_list_serverDef_drain(server_one,true);
	}

	return server_one;
}











	static njt_int_t
njt_http_upstream_api_compose_one_upstream(upstream_list_upstreamDef_t *upstream_one,njt_http_request_t *r,
		void *p)
{

	njt_http_upstream_rr_peer_t    *peer;
	njt_int_t                      rc = NJT_OK;
	njt_http_upstream_rr_peers_t   *backup;
	upstream_list_peerDef_t *peerDef;

	njt_http_upstream_rr_peers_t *peers = p;
	njt_uint_t   zombies = 0; //njt_pcalloc

	upstream_list_upstreamDef_peers_t  *upstreamDef_peers = create_upstream_list_upstreamDef_peers(r->pool,1);
	if(upstreamDef_peers == NULL) {
		return NJT_ERROR;
	}

	set_upstream_list_upstreamDef_peers(upstream_one,upstreamDef_peers);
	njt_http_upstream_rr_peers_rlock(peers);

	for (peer = peers->peer; peer != NULL; peer = peer->next) {


		if(peer->del_pending) {
			zombies++;
		}
		//add_item_upstream_list_upstreamDef_peers
		peerDef = njt_http_upstream_api_compose_one_detail_server(r, peer,0,0,*peers->name);  //add_item_upstream_list_upstreamDef_peers

		if (peerDef == NULL) {
			njt_http_upstream_rr_peers_unlock(peers);
			return rc;
		}
		add_item_upstream_list_upstreamDef_peers(upstreamDef_peers,peerDef);

	}

	backup = peers->next;
	if (backup != NULL) {
		for (peer = backup->peer; peer != NULL; peer = peer->next) {


			if(peer->del_pending) {
				zombies++;
			}
			peerDef = njt_http_upstream_api_compose_one_detail_server(r, peer,1,0,*peers->name);


			if (peerDef == NULL) {
				njt_http_upstream_rr_peers_unlock(peers);
				return rc;
			}
			add_item_upstream_list_upstreamDef_peers(upstreamDef_peers,peerDef);

		}
	}



	njt_http_upstream_rr_peers_unlock(peers);


	set_upstream_list_upstreamDef_zombies(upstream_one,zombies);



	return NJT_OK;
}






	static njt_int_t
njt_http_upstream_api_compose_one_server(njt_http_request_t *r,
		void *p, njt_http_upstream_rr_peer_t      *peer,njt_flag_t is_backup,ssize_t id,server_list_serverDef_t                    **server_one)
{

	
	njt_http_upstream_rr_peers_t   *backup;

	njt_http_upstream_rr_peers_t *peers = p;


	if (id < 0) {
		return NJT_HTTP_UPS_API_INTERNAL_ERROR;  
	}
	if(peer != NULL) {  //����
		*server_one = njt_http_upstream_api_compose_one_server_schemo(r, peer,is_backup,(peer->id == (njt_uint_t)peer->parent_id ?1:0),*peers->name);
		if(*server_one == NULL) {
			return NJT_HTTP_UPS_API_INTERNAL_ERROR;
		}
		return NJT_OK;
	}
	

	njt_http_upstream_rr_peers_rlock(peers);

	for (peer = peers->peer; peer != NULL; peer = peer->next) {

		/*only compose one server*/
		if (id >= 0) {
			if (peer->id == (njt_uint_t)id) {

				njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "find the server %ui",
						id);
		
				*server_one = njt_http_upstream_api_compose_one_server_schemo(r, peer, 0,(peer->id == (njt_uint_t)peer->parent_id ?1:0),*peers->name);
				njt_http_upstream_rr_peers_unlock(peers);
				if(*server_one == NULL) {
					return NJT_HTTP_UPS_API_INTERNAL_ERROR;
				}
				return NJT_OK;
			}

			continue;
		}
	}

	backup = peers->next;
	if (backup != NULL) {
		for (peer = backup->peer; peer != NULL; peer = peer->next) {

			/*only compose one server*/
			if (id >= 0) {
				if (peer->id == (njt_uint_t)id ) {
					njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
							"find the backup server %ui", id);

					
					*server_one = njt_http_upstream_api_compose_one_server_schemo(r, peer, 1,(peer->id == (njt_uint_t)peer->parent_id ?1:0),*peers->name);
					njt_http_upstream_rr_peers_unlock(peers);
					if(*server_one == NULL) {
						return NJT_HTTP_UPS_API_INTERNAL_ERROR;
					}
					return NJT_OK;
				}
				continue;
			}
		}
	}
	//������ڵ㡣
	for (peer = peers->parent_node; peer != NULL; peer = peer->next) {

		if(peer->parent_id == -1)
			continue;

		/*only compose one server*/
		if (id >= 0) {
			if (peer->id == (njt_uint_t)id || peer->parent_id == (njt_int_t)id) {
				njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
						"find the backup server %ui", id);


				*server_one = njt_http_upstream_api_compose_one_server_schemo(r, peer,peer->set_backup,(peer->id == (njt_uint_t)peer->parent_id ?1:0),*peers->name);
				njt_http_upstream_rr_peers_unlock(peers);
				if(*server_one == NULL) {
					return NJT_HTTP_UPS_API_INTERNAL_ERROR;
				}
				return NJT_OK;
			}
			continue;
		}
	}



	njt_http_upstream_rr_peers_unlock(peers);


	return NJT_HTTP_UPS_API_SRV_NOT_FOUND;
}

	static njt_int_t
njt_http_upstream_api_compose_all_server(njt_http_request_t *r,
		void *p,server_list_t                   *server_list)
{
	njt_http_upstream_rr_peer_t    *peer;

	njt_http_upstream_rr_peers_t   *backup;

	njt_http_upstream_rr_peers_t *peers = p;

	server_list_serverDef_t       *peerDef; 


	njt_http_upstream_rr_peers_rlock(peers);

	for (peer = peers->peer; peer != NULL; peer = peer->next) {


		peerDef = njt_http_upstream_api_compose_one_server_schemo(r, peer,0,(peer->id == (njt_uint_t)peer->parent_id ?1:0),*peers->name);

		if (peerDef == NULL) {
			njt_http_upstream_rr_peers_unlock(peers);
			return NJT_ERROR;
		}
		add_item_server_list(server_list,peerDef);

	}

	backup = peers->next;
	if (backup != NULL) {
		for (peer = backup->peer; peer != NULL; peer = peer->next) {

			peerDef = njt_http_upstream_api_compose_one_server_schemo(r, peer,1,(peer->id == (njt_uint_t)peer->parent_id ?1:0),*peers->name);

			if (peerDef == NULL) {
				njt_http_upstream_rr_peers_unlock(peers);
				return NJT_ERROR;
			}
			add_item_server_list(server_list,peerDef);

		}
	}
	//������ڵ㡣
	for (peer = peers->parent_node; peer != NULL; peer = peer->next) {

		if(peer->parent_id == -1)
			continue;

		peerDef = njt_http_upstream_api_compose_one_server_schemo(r, peer,peer->set_backup,(peer->id == (njt_uint_t)peer->parent_id ?1:0),*peers->name);


		if (peerDef == NULL) {
			njt_http_upstream_rr_peers_unlock(peers);
			return NJT_ERROR;
		}
		add_item_server_list(server_list,peerDef);

	}



	njt_http_upstream_rr_peers_unlock(peers);

	return NJT_OK;
}








njt_str_t* to_json_upstream_list_upstreamDef(njt_pool_t *pool, upstream_list_upstreamDef_t* out, njt_int_t flags) {
	njt_str_t *json_str;
	json_str = njt_palloc(pool, sizeof(njt_str_t));
	if(json_str == NULL){
		return NULL;
	}
	size_t str_len = 0;
	get_json_length_upstream_list_upstreamDef(pool, out, &str_len, flags);
	json_str->data = (u_char*)njt_palloc(pool, str_len + 1);
	if(json_str->data == NULL){
		return NULL;
	}
	json_str->len = 0;
	to_oneline_json_upstream_list_upstreamDef(pool, out, json_str, flags);
	return json_str;
}


njt_str_t* to_json_one_serverDef(njt_pool_t *pool, server_list_serverDef_t* out, njt_int_t flags) {
	njt_str_t *json_str;
	json_str = njt_palloc(pool, sizeof(njt_str_t));
	if(json_str == NULL){
		return NULL;
	}
	size_t str_len = 0;
	get_json_length_server_list_serverDef(pool, out, &str_len, flags);
	json_str->data = (u_char*)njt_palloc(pool, str_len + 1);
	if(json_str->data == NULL){
		return NULL;
	}
	json_str->len = 0;
	to_oneline_json_server_list_serverDef(pool, out, json_str, flags);
	return json_str;
}


njt_str_t* to_json_one_server_list(njt_pool_t *pool, server_list_t* out, njt_int_t flags) {
	njt_str_t *json_str;
	json_str = njt_palloc(pool, sizeof(njt_str_t));
	if(json_str == NULL){
		return NULL;
	}
	size_t str_len = 0;
	get_json_length_server_list(pool, out, &str_len, flags);
	json_str->data = (u_char*)njt_palloc(pool, str_len + 1);
	if(json_str->data == NULL){
		return NULL;
	}
	json_str->len = 0;
	to_oneline_json_server_list(pool, out, json_str, flags);
	return json_str;
}


	static njt_int_t
njt_http_upstream_api_process_get(njt_http_request_t *r,
		void *cf,
		ssize_t server_id, njt_flag_t detailed, njt_chain_t *out)
{
	njt_int_t                       rc = NJT_OK;
	njt_uint_t                      i;
	njt_http_upstream_srv_conf_t   *uscf, **uscfp;
	njt_http_upstream_main_conf_t  *umcf;
	njt_http_upstream_rr_peers_t   *peers;
	njt_str_t                       zone_name = njt_string("");
	njt_flag_t                      keep_alive;
	upstream_list_t                 *upstream_list;  
	upstream_list_upstreamDef_t     *upstream_one;
	server_list_serverDef_t         *server_one = NULL;  
	server_list_t                   *server_list = NULL; 
	njt_str_t                       *to_json = NULL;


	njt_http_upstream_srv_conf_t *target_uscf = cf;
#if (NJT_HTTP_UPSTREAM_ZONE)
	if (target_uscf != NULL && target_uscf->shm_zone != NULL) {
		zone_name = target_uscf->shm_zone->shm.name;
	}
#endif
	/*get a specific upstream's server inforamtion*/
	if (target_uscf != NULL) {
		keep_alive = target_uscf->set_keep_alive;

		peers = (njt_http_upstream_rr_peers_t *)target_uscf->peer.data;

		if(detailed == 1) {
			upstream_one = create_upstream_list_upstreamDef(r->pool);
			if (upstream_one == NULL) {
				return NJT_HTTP_UPS_API_INTERNAL_ERROR;
			}
			set_upstream_list_upstreamDef_name(upstream_one,&target_uscf->host);
			set_upstream_list_upstreamDef_keepalive(upstream_one,keep_alive);
			set_upstream_list_upstreamDef_zone(upstream_one,&zone_name);	

			rc = njt_http_upstream_api_compose_one_upstream(upstream_one,r, peers);
			if (rc != NJT_OK) {
				return rc;
			}
			to_json = to_json_upstream_list_upstreamDef(r->pool,upstream_one,OMIT_NULL_ARRAY | OMIT_NULL_OBJ | OMIT_NULL_STR);



		} else {
			if(server_id >= 0) {
				rc = njt_http_upstream_api_compose_one_server(r, peers,NULL,0,server_id,&server_one);
				if (rc != NJT_OK) {
					return rc;
				}
				to_json = to_json_one_serverDef(r->pool,server_one,OMIT_NULL_ARRAY | OMIT_NULL_OBJ | OMIT_NULL_STR);

			} else {
				server_list = create_server_list(r->pool,1);
				njt_http_upstream_api_compose_all_server( r, peers,server_list);
				to_json = to_json_one_server_list(r->pool,server_list,OMIT_NULL_ARRAY | OMIT_NULL_OBJ | OMIT_NULL_STR);

			}
		}
		if(to_json != NULL) {
	 	   rc = njt_http_upstream_api_packet_out(r,to_json,out);
		}


		return rc;
	}

	/*get all the upstreams' server information*/
	umcf = njt_http_cycle_get_module_main_conf(njet_master_cycle, njt_http_upstream_module);
	if(umcf == NULL) {
		rc = NJT_HTTP_UPS_API_PATH_NOT_FOUND;
		return rc;
	}

	uscfp = umcf->upstreams.elts;

	/*Go throught the upstreams and compose the output content*/

	upstream_list =  create_upstream_list(r->pool,umcf->upstreams.nelts);
	if(upstream_list == NULL) {
		return  NJT_HTTP_UPS_API_INTERNAL_ERROR;
	}

	for (i = 0; i < umcf->upstreams.nelts; i++) {

		uscf = uscfp[i];
#if (NJT_HTTP_UPSTREAM_ZONE)
		if (uscf == NULL || uscf->shm_zone == NULL)
			continue;
		zone_name = uscf->shm_zone->shm.name;
#endif
		keep_alive = uscf->set_keep_alive;
		peers = (njt_http_upstream_rr_peers_t *)uscf->peer.data;

		upstream_one = create_upstream_list_upstreamDef(r->pool);
		if (upstream_one == NULL) {
			return NJT_HTTP_UPS_API_INTERNAL_ERROR;
		}
		add_item_upstream_list(upstream_list,upstream_one);
		set_upstream_list_upstreamDef_name(upstream_one,&uscf->host);
		set_upstream_list_upstreamDef_keepalive(upstream_one,keep_alive);
		set_upstream_list_upstreamDef_zone(upstream_one,&zone_name);	

		rc = njt_http_upstream_api_compose_one_upstream(upstream_one,r, peers);
		if (rc != NJT_OK) {
			return rc;
		}
	}
	to_json = to_json_upstream_list(r->pool,upstream_list,OMIT_NULL_ARRAY | OMIT_NULL_OBJ | OMIT_NULL_STR);
	if(to_json){
		rc = njt_http_upstream_api_packet_out(r,to_json,out);
	}
	return rc;
}




	static njt_int_t
njt_http_upstream_api_json_2_peer(upstream_api_t *json_manager,
		njt_http_upstream_api_peer_t *api_peer,
		njt_flag_t  server_flag,njt_http_request_t *r,njt_flag_t proto) //proto  0 http,1 stream
{
	njt_int_t          rc;
	njt_str_t           *pdata;

	rc = NJT_OK;


	if(json_manager->is_server_set == 1){
		pdata = get_upstream_api_server(json_manager);
		if(pdata != NULL) {
			api_peer->server = *pdata;
		}
	}

	if(json_manager->is_weight_set == 1){

		api_peer->weight = get_upstream_api_weight(json_manager);
	}

	if(json_manager->is_max_conns_set == 1){
		api_peer->max_conns = get_upstream_api_max_conns(json_manager);
	}

	if(json_manager->is_max_fails_set == 1){
		api_peer->max_fails = get_upstream_api_max_fails(json_manager);
	}

	if(json_manager->is_down_set == 1){
		if (get_upstream_api_down(json_manager) == false) {
			api_peer->down = 0;
		} else {

			api_peer->down = 1;
		}
	}
	if(json_manager->is_backup_set == 1){
		if (get_upstream_api_backup(json_manager) == false) {
			api_peer->backup = 0;
		} else {

			api_peer->backup = 1;
		}
	}

	if(json_manager->is_drain_set == 1){
		if (get_upstream_api_drain(json_manager) == false) {
			api_peer->drain = 0;
		} else {

			api_peer->drain = 1;
		}
	}

	if(json_manager->is_fail_timeout_set == 1){
		pdata = get_upstream_api_fail_timeout(json_manager);
		if(pdata != NULL) {
			api_peer->fail_timeout = njt_parse_time(pdata, 1);
		}

	}


	if(json_manager->is_slow_start_set == 1){
		pdata = get_upstream_api_slow_start(json_manager);
		if(pdata != NULL) {
			api_peer->slow_start = njt_parse_time(pdata, 1);
		}

	}
	if (json_manager->is_route_set == 1) {  //rc = NJT_HTTP_UPS_API_INVALID_JSON_BODY;
		pdata = get_upstream_api_route(json_manager);
		if(pdata != NULL) {
			api_peer->route = *pdata;
		}
	}

	rc = NJT_OK;


	/*For post*/
	if (server_flag) {

		if (api_peer->server.data == NULL || api_peer->server.len == 0) {
			rc = NJT_HTTP_UPS_API_MISS_SRV;
		}

	} 
	return rc;
}



	static void
njt_http_upstream_api_patch(njt_http_request_t *r)
{

	njt_http_upstream_rr_peers_t       *peers, *backup, *target_peers;
	njt_http_upstream_api_ctx_t       *ctx;

	njt_str_t                          json_str;
	njt_chain_t                        *body_chain;
	njt_chain_t                        out;
	njt_int_t                          rc,pre_rc;
	ssize_t                            len;
	njt_url_t                          u;
	njt_http_upstream_rr_peer_t        *peer;// *prev;
	njt_uint_t                         server_id;
	njt_str_t                          server;
	u_char                             *port,*last;
	upstream_api_t                     *json_body;
	js2c_parse_error_t                 err_code;
	njt_flag_t                         is_backup;
	server_list_serverDef_t         *server_one = NULL;  
	njt_str_t                          *to_json = NULL;



	ctx = njt_http_get_module_ctx(r, njt_http_upstream_api_module);

	peers = ctx->peers;

	rc = NJT_OK;
	pre_rc = NJT_OK;
	body_chain = r->request_body->bufs;
	if (body_chain && body_chain->next) {
		/*The post body is too large*/
		rc = NJT_HTTP_UPS_API_TOO_LARGE_BODY;
		goto out;
	}

	out.next = NULL;
	out.buf = NULL;

	rc = njt_http_util_read_request_body(r, &json_str, MIN_UPSTREAM_API_BODY_LEN, MAX_UPSTREAM_API_BODY_LEN);
	if(rc == NJT_ERROR) {
		rc = NJT_HTTP_UPS_API_INVALID_JSON_PARSE;
		goto out;
	}

	json_body = json_parse_upstream_api(r->pool,  &json_str, &err_code);
	if (json_body == NULL) {
		rc = NJT_HTTP_UPS_API_INVALID_JSON_PARSE;
		json_peer.msg = err_code.err_str;
		goto out;
	}

	/*conduct the perform*/
	njt_memzero(&json_peer, sizeof(njt_http_upstream_api_peer_t));
	json_peer.weight = -1;
	json_peer.max_fails = -1;
	json_peer.fail_timeout = -1;
	json_peer.max_conns = -1;
	json_peer.backup = -1;
	json_peer.down = -1;
	json_peer.slow_start = -1;
	json_peer.drain = -1;
	njt_str_null(&json_peer.route);
	njt_str_null(&json_peer.server);

	rc = njt_http_upstream_api_json_2_peer(json_body, &json_peer, 0,r,0);

	if (rc != NJT_OK) {
		//rc = NJT_HTTP_UPS_API_INVALID_JSON_PARSE;
		goto out;
	}


	/*perform the insert*/
	server_id = ctx->id;
	if (json_peer.server.len  > 0) {
		njt_memzero(&u, sizeof(njt_url_t));
		u.url.data = njt_pcalloc(r->pool, json_peer.server.len + 1);

		if (u.url.data == NULL) {

			rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;

			njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "url data allocate error.");
			goto out;
		}

		njt_cpystrn(u.url.data, json_peer.server.data, json_peer.server.len + 1);
		u.url.len = json_peer.server.len;
		u.default_port = 80;

		if (njt_parse_url(r->pool, &u) != NJT_OK) {
			//rc = NJT_HTTP_UPS_API_INVALID_SRV_ARG;
			//if (u.err) {
			//	njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
			//			  "%s in upstream \"%V\"", u.err, &u.url);
			//}
			//goto out;
		}
		if(u.naddrs == 1 && json_peer.server.len <= u.addrs[0].name.len && njt_strncmp(json_peer.server.data,u.addrs[0].name.data,json_peer.server.len) == 0){
			json_peer.domain = 0;  //ip
		} else {
			json_peer.domain = 1;  //domain name
		}

		if(json_peer.domain == 1) {
			pre_rc = NJT_HTTP_UPS_API_INVALID_SRV_ARG;
			//goto out;
		} else {
			last = json_peer.server.data + json_peer.server.len;
			port = njt_strlchr(json_peer.server.data, last, ':');
			if(port == NULL) {
				server = json_peer.server;
				json_peer.server.len = server.len + 3;
				json_peer.server.data = njt_pcalloc(r->pool,json_peer.server.len);  //add port 
				if(json_peer.server.data == NULL) {
					goto out;
				}
				njt_memcpy(json_peer.server.data,server.data,server.len);
				json_peer.server.data[server.len] = ':';
				json_peer.server.data[server.len+1] = '8';
				json_peer.server.data[server.len+2] = '0';
			}
		}
	}
	is_backup = 0;
	njt_http_upstream_rr_peers_wlock(peers);
	target_peers = peers;
	for (peer = peers->peer; peer != NULL;  peer = peer->next) {
		if (peer->id == (njt_uint_t)server_id ) {
			njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "find the server %ui",
					server_id);

			break;
		} 
	}
	backup = peers->next;  
	if (peer == NULL && backup) {
		is_backup = 1;
		target_peers = backup;
		for (peer = backup->peer; peer;  peer = peer->next) {
			if (peer->id == (njt_uint_t)server_id) {
				njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
						"find the backup server %ui", server_id);
				break;
			}
		}
	} 
	if(peer == NULL) {
		for (peer = peers->parent_node; peer;  peer = peer->next) {

			if (peer->id == server_id && peer->parent_id == (njt_int_t)server_id) {
				is_backup = peer->set_backup;
				break;
			}
		}
	}
	if (peer == NULL) {

		rc = NJT_HTTP_UPS_API_SRV_NOT_FOUND;
		njt_http_upstream_rr_peers_unlock(peers);
		goto out;
	}

	if(peer->parent_id != -1 && json_peer.server.len > 0) {
		njt_http_upstream_rr_peers_unlock(peers);
		rc = NJT_HTTP_UPS_API_NOT_MODIFY_SRV_NAME;
		goto out;
	}
	if(pre_rc != NJT_OK) {
		njt_http_upstream_rr_peers_unlock(peers);
		rc = pre_rc;
		goto out;
	}

	if (json_peer.max_fails != -1) {
		peer->max_fails = json_peer.max_fails;
	}

	if (json_peer.max_conns != -1) {
		peer->max_conns = json_peer.max_conns;
	}

	if (json_peer.fail_timeout != -1) {
		peer->fail_timeout = json_peer.fail_timeout;
	}
	if (json_peer.slow_start != -1) {  //zyg
		peer->slow_start = json_peer.slow_start;
		peer->hc_upstart =  njt_time(); //patch
	}
	//patch
	if(json_peer.drain == 1) {
		peer->hc_down  = 100 + peer->hc_down;
	}

	if (json_peer.route.len  > 0) {
		if(peer->route.len < json_peer.route.len) {
			if(peer->route.len != 0) {
				njt_slab_free_locked(peers->shpool,peer->route.data);
			}

			peer->route.data = njt_slab_calloc_locked(peers->shpool, json_peer.route.len);
			if (peer->route.data == NULL) {
				njt_http_upstream_rr_peers_unlock(peers);
				goto error;
			}
		}
		njt_memcpy(peer->route.data, json_peer.route.data,json_peer.route.len);
		peer->route.len = json_peer.route.len;



	}
	if (json_peer.server.len  > 0 && u.naddrs > 0 ) {
		if(peer->server.len < json_peer.server.len) {
			njt_slab_free_locked(peers->shpool,peer->server.data);
			peer->server.data = njt_slab_calloc_locked(peers->shpool, json_peer.server.len);
			if (peer->server.data == NULL) {
				njt_http_upstream_rr_peers_unlock(peers);
				goto error;
			}
		}

		if(peer->socklen < u.addrs[0].socklen) {
			njt_slab_free_locked(peers->shpool, peer->sockaddr);
		}
		peer->socklen = u.addrs[0].socklen;
		peer->sockaddr = njt_slab_calloc_locked(peers->shpool, peer->socklen + 1);
		if (peer->sockaddr == NULL) {

			rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
			njt_http_upstream_rr_peers_unlock(peers);
			njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
					"peer sockaddr allocate error.");
			goto out;
		}
		peer->name.data = njt_slab_calloc_locked(peers->shpool, u.addrs->name.len + 1);
		if (peer->name.data == NULL) {

			rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
			njt_http_upstream_rr_peers_unlock(peers);
			njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
					"name data allocate error.");

			goto out;
		}

		njt_cpystrn(peer->name.data, u.addrs->name.data, u.addrs->name.len + 1);
		peer->name.len = u.addrs->name.len;



		njt_memcpy(peer->sockaddr, u.addrs[0].sockaddr, peer->socklen);
		njt_memcpy(peer->server.data, json_peer.server.data,json_peer.server.len);
		peer->server.len = json_peer.server.len;
		peer->hc_checks = 0;
		peer->hc_fails = 0;
		peer->hc_last_passed = 0;
		peer->hc_downstart = 0;
		peer->hc_downtime = 0;
		peer->hc_down = 0;
		if(json_peer.drain == 1) {
			peer->hc_down  = 100 + peer->hc_down;
		}
		peer->hc_consecutive_fails = 0;
		peer->hc_consecutive_passes = 0;
		peer->hc_unhealthy = 0;
	}
	if (json_peer.down != -1) {

		peer->down = json_peer.down;
		if (peer->down != (njt_uint_t)json_peer.down) {

			if (peer->down) {
				/*originally the peer is down, then it is up now*/
				target_peers->tries++;
			} else {
				/*originally the peer is up, then it is down now */
				target_peers->tries--;
			}
		}

		peer->down = json_peer.down;
	}

	/*update the modified items*/
	if (json_peer.weight != -1) {

		target_peers->total_weight -= peer->weight;
		target_peers->total_weight += json_peer.weight;
		target_peers->weighted = (peers->total_weight != peers->number);

		peer->weight = json_peer.weight;
		peer->effective_weight = json_peer.weight;
	}
	peers->update_id++;
	rc = njt_http_upstream_api_compose_one_server(r, peers,peer,is_backup, peer->id,&server_one);
	njt_http_upstream_rr_peers_unlock(peers);

out:

	if (rc != NJT_OK) {

		rc = njt_http_upstream_api_err_out(r, rc,&json_peer.msg, &out);
		if (rc != NJT_OK) {
			goto error;
		}

		goto send;
	}
	r->headers_out.status = NJT_HTTP_OK;


	/*return the current servers*/
	
	if (rc != NJT_OK) {
		goto error;
	}
	to_json = to_json_one_serverDef(r->pool,server_one,OMIT_NULL_ARRAY | OMIT_NULL_OBJ | OMIT_NULL_STR);
	rc = njt_http_upstream_api_packet_out(r,to_json,&out);
	if (rc != NJT_OK) {
		goto error;
	}




send:
	r->headers_out.content_type_len = sizeof("text/plain") - 1;
	njt_str_set(&r->headers_out.content_type, "text/plain");
	r->headers_out.content_type_lowcase = NULL;

	len = njt_http_upstream_api_out_len(&out);
	r->headers_out.content_length_n = len;

	if (r->headers_out.content_length) {
		r->headers_out.content_length->hash = 0;
		r->headers_out.content_length = NULL;
	}

	rc = njt_http_send_header(r);

	if (rc == NJT_ERROR || rc > NJT_OK || r->header_only) {
		njt_http_finalize_request(r, rc);
		return;
	}

	rc = njt_http_output_filter(r, &out);
	njt_http_finalize_request(r, rc);
	return;


error:
	njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
	return;
}









	static void
njt_http_upstream_api_post(njt_http_request_t *r)
{
	u_char						       *last,*port;
	njt_http_upstream_rr_peers_t       *peers, *backup, *target_peers;
	njt_slab_pool_t                    *shpool;
	njt_http_upstream_api_ctx_t       *ctx;
	upstream_api_t                     *json_body;
	njt_str_t                          json_str;
	njt_http_upstream_api_main_conf_t *uclcf;
	njt_chain_t                        *body_chain;
	njt_chain_t                        out;
	njt_int_t                          rc;
	njt_int_t                          parent_id;
	//njt_uint_t                          i;
	ssize_t                            len;
	njt_http_upstream_rr_peer_t        *peer,*tail_peer;
	njt_http_upstream_rr_peer_t         new_peer;
	//njt_http_upstream_api_peer_t      json_peer;
	njt_url_t                          u;
	njt_str_t                          name, server;
	njt_str_t                          *peers_name;
	njt_http_upstream_srv_conf_t       *uscf;
	js2c_parse_error_t                 err_code;
	njt_str_t                          *to_json = NULL;
	server_list_serverDef_t         *server_one = NULL;  
	//njt_str_t                           zone_name = njt_string("");
	peer = NULL;

	ctx = njt_http_get_module_ctx(r, njt_http_upstream_api_module);
	peers = ctx->peers;


	rc = NJT_OK;
	body_chain = r->request_body->bufs;
	if (body_chain && body_chain->next) {
		/*The post body is too large*/
		rc = NJT_HTTP_UPS_API_TOO_LARGE_BODY;
		goto out;
	}

	out.next = NULL;
	out.buf = NULL;

	rc = njt_http_util_read_request_body(r, &json_str, MIN_UPSTREAM_API_BODY_LEN, MAX_UPSTREAM_API_BODY_LEN);
	if(rc == NJT_ERROR) {
		rc = NJT_HTTP_UPS_API_INVALID_JSON_PARSE;
		goto out;
	}

	json_body = json_parse_upstream_api(r->pool,  &json_str, &err_code);
	if (json_body == NULL) {
		rc = NJT_HTTP_UPS_API_INVALID_JSON_PARSE;
		json_peer.msg = err_code.err_str;
		goto out;
	}

	/*conduct the perform*/
	njt_memzero(&json_peer, sizeof(njt_http_upstream_api_peer_t));


	/*initialize the jason peer. Other items other than the following are all zero*/
	json_peer.weight = 1*NJT_WEIGHT_POWER;
	json_peer.max_fails = 1;
	json_peer.fail_timeout = 10;
	json_peer.drain = -1;

	rc = njt_http_upstream_api_json_2_peer(json_body, &json_peer, 1,r,0);

	if (rc != NJT_OK) {
		//rc = NJT_HTTP_UPS_API_INVALID_JSON_PARSE;
		goto out;
	}
	uscf = ctx->uscf;
	if(json_peer.backup == 1 && uscf != NULL && (!(uscf->flags & NJT_HTTP_UPSTREAM_BACKUP))) {
		rc = NJT_HTTP_UPS_API_HAS_NO_BACKUP;
		goto out;
	}

	/*perform the insert*/
	shpool = peers->shpool;

	njt_memzero(&u, sizeof(njt_url_t));





	u.url.data = njt_pcalloc(r->pool, json_peer.server.len + 1);

	if (u.url.data == NULL) {
		rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "url data allocate error.");
		goto out;
	}
	njt_cpystrn(u.url.data, json_peer.server.data, json_peer.server.len + 1);
	u.url.len = json_peer.server.len;
	u.default_port = 80;

	if (njt_parse_url(r->pool, &u) != NJT_OK) {

		rc = NJT_HTTP_UPS_API_NOT_SUPPORTED_SRV;
		if (u.err) {
			njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
					"api post http domain: \"%V\"",&u.url);
		}
		//goto out;
	}



	njt_http_upstream_rr_peers_wlock(peers);
	njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0,
			"njt_http_upstream_api_post!");
	json_peer.domain = 0;  //ip
	parent_id = -1;
	if(u.naddrs == 1 && json_peer.server.len <= u.addrs[0].name.len && njt_strncmp(json_peer.server.data,u.addrs[0].name.data,json_peer.server.len) == 0){
		parent_id = -1;
		json_peer.domain = 0;  //ip
	} else {
		uclcf = njt_http_cycle_get_module_main_conf(njt_cycle, njt_http_upstream_api_module);
		if(uclcf && (uclcf->shm_zone_http == NULL || ctx->resolver == NULL)) {
			rc = NJT_HTTP_UPS_API_NO_RESOLVER;
			njt_http_upstream_rr_peers_unlock(peers);
			goto out;
		}
		if(ctx->resolver != NULL) {
			parent_id = (njt_int_t)peers->next_order++;
			json_peer.domain = 1;  //domain name
		}

	}
	if(json_peer.domain == 0) {
		last = json_peer.server.data + json_peer.server.len;
		port = njt_strlchr(json_peer.server.data, last, ':');
		if(port == NULL) {
			server = json_peer.server;
			json_peer.server.len = server.len + 3;
			json_peer.server.data = njt_pcalloc(r->pool,json_peer.server.len);  //add port 
			if(json_peer.server.data == NULL) {
				njt_http_upstream_rr_peers_unlock(peers);
				goto out;
			}
			njt_memcpy(json_peer.server.data,server.data,server.len);
			json_peer.server.data[server.len] = ':';
			json_peer.server.data[server.len+1] = '8';
			json_peer.server.data[server.len+2] = '0';
		}
	}

	/////////////////////////////////////////////////////////////
	if(parent_id != -1)  {
		server.data = njt_pcalloc(r->pool, json_peer.server.len + 1);
		njt_cpystrn(server.data, json_peer.server.data, json_peer.server.len + 1);
		server.len = json_peer.server.len;
		new_peer.server = server;
		new_peer.id = parent_id;
		new_peer.parent_id = parent_id;
		new_peer.weight = json_peer.weight;
		new_peer.effective_weight = json_peer.weight;
		new_peer.current_weight = 0;
		new_peer.max_fails = json_peer.max_fails;
		new_peer.max_conns = json_peer.max_conns;
		new_peer.fail_timeout = json_peer.fail_timeout;
		new_peer.down = json_peer.down;
		new_peer.slow_start = json_peer.slow_start;
		new_peer.name = server;
		new_peer.route.len = json_peer.route.len;
		new_peer.hc_down  = ctx->hc_type;
		if(json_peer.drain == 1) {  //post not drain
			//new_peer.hc_down  = 100 + new_peer.hc_down;
		}
		if(new_peer.route.len > 0) {
			new_peer.route.data = njt_pcalloc(r->pool, new_peer.route.len + 1);
			if (new_peer.route.data == NULL) {

				rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
				njt_http_upstream_rr_peers_unlock(peers);
				njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
						"peer route allocate error.");
				goto out;
			}
			njt_cpystrn(new_peer.route.data, json_peer.route.data, json_peer.route.len + 1);
		}
		njt_http_upstream_rr_peers_unlock(peers);

		njt_http_upstream_api_create_dynamic_server(r,&new_peer,json_peer.backup);
		rc = njt_http_upstream_api_compose_one_server(r, peers,&new_peer,json_peer.backup,new_peer.id,&server_one);
		rc = NJT_OK;

	} else if (parent_id == -1) {

		peer = njt_slab_calloc_locked(shpool, sizeof(njt_http_upstream_rr_peer_t));

		if (peer == NULL) {

			rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
			njt_http_upstream_rr_peers_unlock(peers);
			njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "peer allocate error.");

			goto out;
		}

		server.data = njt_slab_calloc_locked(shpool, json_peer.server.len + 1);
		if (server.data == NULL) {

			rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
			njt_http_upstream_rr_peers_unlock(peers);
			njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "server data allocate error.");

			goto out;
		}

		njt_cpystrn(server.data, json_peer.server.data, json_peer.server.len + 1);
		server.len = json_peer.server.len;
		peer->server = server;

		name.data = njt_slab_calloc_locked(shpool, u.addrs[0].name.len + 1);
		if (name.data == NULL) {

			rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
			njt_http_upstream_rr_peers_unlock(peers);
			njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
					"name data allocate error.");

			goto out;
		}

		njt_cpystrn(name.data, u.addrs[0].name.data, u.addrs[0].name.len + 1);
		name.len = u.addrs[0].name.len;
		peer->name = name;

		peer->socklen = u.addrs[0].socklen;
		peer->sockaddr = njt_slab_calloc_locked(shpool, peer->socklen + 1);
		if (peer->sockaddr == NULL) {

			rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
			njt_http_upstream_rr_peers_unlock(peers);
			njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
					"peer sockaddr allocate error.");
			goto out;
		}

		njt_memcpy(peer->sockaddr, u.addrs[0].sockaddr, peer->socklen);

		peer->id = peers->next_order++;
		peer->parent_id = parent_id;

		peer->hc_upstart =  njt_time(); //post
		peer->weight = json_peer.weight;
		peer->effective_weight = json_peer.weight;
		peer->current_weight = 0;
		peer->max_fails = json_peer.max_fails;
		peer->max_conns = json_peer.max_conns;
		peer->fail_timeout = json_peer.fail_timeout;
		peer->down = json_peer.down;
		peer->slow_start = json_peer.slow_start;
		peer->hc_down  = ctx->hc_type;
		if(json_peer.drain == 1) {  //post //post not drain
			// peer->hc_down  = 100 + peer->hc_down;
		}
		peer->route.len = json_peer.route.len;
		peer->route.data = njt_slab_calloc_locked(shpool, peer->route.len + 1);
		if (peer->route.data == NULL) {

			rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
			njt_http_upstream_rr_peers_unlock(peers);
			njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
					"peer route allocate error.");
			goto out;
		}
		njt_cpystrn(peer->route.data, json_peer.route.data, json_peer.route.len + 1);

		target_peers = peers;

		/*insert into the right peer list according to the backup value*/
		if (json_peer.backup) {

			backup = peers->next;
			if (backup == NULL) {

				backup = njt_slab_calloc(peers->shpool, sizeof(njt_http_upstream_rr_peers_t));
				if (backup == NULL) {
					rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
					njt_http_upstream_rr_peers_unlock(peers);
					njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
							"backup peers allocate error.");

					goto out;
				}

				peers_name = njt_slab_calloc(peers->shpool, sizeof(njt_str_t));
				if (peers_name == NULL) {
					rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
					njt_http_upstream_rr_peers_unlock(peers);
					njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
							"peers_name allocate error.");

					goto out;
				}

				peers_name->data = njt_slab_calloc(peers->shpool, peers->name->len);
				if (peers_name->data == NULL) {
					rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
					njt_http_upstream_rr_peers_unlock(peers);
					njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
							"peers_name data allocate error.");

					goto out;
				}

				njt_memcpy(peers_name->data, peers->name->data, peers->name->len);
				peers_name->len = peers->name->len;

				backup->name = peers_name;
				peers->next = backup;
			}

			target_peers = backup;
		}

		if (target_peers->peer) {
			//peer->next = target_peers->peer;
			//target_peers->peer = peer;

			for(tail_peer = target_peers->peer;tail_peer->next != NULL; tail_peer = tail_peer->next);
			tail_peer->next = peer;

		} else {
			target_peers->peer = peer;
		}
		target_peers->number++;
		target_peers->total_weight += peer->weight;
		target_peers->weighted = (target_peers->total_weight != target_peers->number);

		if (peer->down == 0) {
			peers->tries ++;
		}

		target_peers->single = (target_peers->number <= 1);
		peers->single = (peers->number + peers->next->number <= 1);
		peers->update_id++;	
		rc = njt_http_upstream_api_compose_one_server(r, peers,peer,json_peer.backup,peer->id,&server_one);
		njt_http_upstream_rr_peers_unlock(peers);
	}


out:
	if (rc != NJT_OK) {

		/* free the allocated memory*/
		if (peer) {
			njt_shmtx_lock(&peers->shpool->mutex);
			njt_http_upstream_free_peer_memory(peers->shpool, peer);  //njt_http_upstream_free_peer_memory  todo  zyg
			njt_shmtx_unlock(&peers->shpool->mutex);
		}

		rc = njt_http_upstream_api_err_out(r, rc,&json_peer.msg, &out);
		if (rc != NJT_OK) {
			goto error;
		}

		goto send;
	}


	r->headers_out.status = NJT_HTTP_CREATED;
	
	
	if (rc != NJT_OK) {
			goto error;
	}
	to_json = to_json_one_serverDef(r->pool,server_one,OMIT_NULL_ARRAY | OMIT_NULL_OBJ | OMIT_NULL_STR);
	rc = njt_http_upstream_api_packet_out(r,to_json,&out);
	if (rc != NJT_OK) {
		goto error;
	}



send:
	r->headers_out.content_type_len = sizeof("text/plain") - 1;
	njt_str_set(&r->headers_out.content_type, "text/plain");
	r->headers_out.content_type_lowcase = NULL;

	len = njt_http_upstream_api_out_len(&out);
	r->headers_out.content_length_n = len;

	if (r->headers_out.content_length) {
		r->headers_out.content_length->hash = 0;
		r->headers_out.content_length = NULL;
	}

	rc = njt_http_send_header(r);
	if (rc == NJT_ERROR || rc > NJT_OK || r->header_only) {
		njt_http_finalize_request(r, rc);
		return;
	}

	rc = njt_http_output_filter(r, &out);
	njt_http_finalize_request(r, rc);
	return;

error:
	njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
	return;
}




	static njt_int_t
njt_http_upstream_api_process_patch(njt_http_request_t *r,
		void *cf,
		njt_uint_t id)
{
	njt_int_t                          rc;
	njt_http_upstream_rr_peers_t       *peers;
	njt_http_upstream_api_ctx_t       *ctx;
	njt_http_upstream_srv_conf_t *uscf = cf;

	/*try to search the server*/
	peers = (njt_http_upstream_rr_peers_t *)uscf->peer.data;

	ctx = njt_pcalloc(r->pool, sizeof(njt_http_upstream_api_ctx_t));
	if (ctx == NULL) {
		njt_http_discard_request_body(r);
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
				"upstream api ctx allocate error.");
		return NJT_HTTP_INTERNAL_SERVER_ERROR;
	}
	ctx->resolver = uscf->resolver;
	ctx->uscf  = uscf;
	ctx->peers = peers;
	ctx->id = id;
	ctx->keep_alive = uscf->set_keep_alive;
	njt_http_set_ctx(r, ctx, njt_http_upstream_api_module);

	rc = njt_http_read_client_request_body(r, njt_http_upstream_api_patch);
	if (rc >= NJT_HTTP_SPECIAL_RESPONSE) {
		/* error */
		return rc;
	}
	return NJT_DONE;
}



	static njt_int_t
njt_http_upstream_api_process_post(njt_http_request_t *r,
		void *cf)
{
	njt_int_t                          rc;
	njt_http_upstream_rr_peers_t       *peers;
	njt_http_upstream_api_ctx_t       *ctx;
	njt_http_upstream_srv_conf_t *uscf = cf;


	peers = (njt_http_upstream_rr_peers_t *)uscf->peer.data;

	ctx = njt_pcalloc(r->pool, sizeof(njt_http_upstream_api_ctx_t));
	if (ctx == NULL) {
		njt_http_discard_request_body(r);
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
				"upstream api ctx allocate error.");
		return NJT_HTTP_INTERNAL_SERVER_ERROR;
	}

	ctx->peers = peers;
	ctx->uscf  = uscf;
	ctx->resolver = uscf->resolver;
	ctx->keep_alive = uscf->set_keep_alive;
	ctx->hc_type  = (uscf->hc_type == 0 ?0:2);
	njt_http_set_ctx(r, ctx, njt_http_upstream_api_module);

	rc = njt_http_read_client_request_body(r, njt_http_upstream_api_post);
	if (rc >= NJT_HTTP_SPECIAL_RESPONSE) {
		/* error */
		return rc;
	}
	return NJT_DONE;
}



	static njt_int_t
njt_http_upstream_api_process_reset(njt_http_request_t *r,
		void *cf,
		njt_chain_t *out)
{
	njt_int_t                      rc;
	njt_str_t                       peer_name;
	njt_http_upstream_rr_peers_t   *peers, *backup;
	njt_http_upstream_rr_peer_t    *peer;
	njt_http_upstream_srv_conf_t *uscf = cf;
	peer_name.len = 256;
	peer_name.data = njt_pcalloc(r->pool,peer_name.len);
	rc = NJT_OK;

	peers = (njt_http_upstream_rr_peers_t *)uscf->peer.data;


	njt_http_upstream_rr_peers_wlock(peers);
	for (peer = peers->peer; peer;peer = peer->next) {	
		peer->requests = 0;
		peer->total_fails = 0;
		peer->hc_checks = 0;
		peer->hc_fails = 0;
		peer->hc_last_passed = 0;
		peer->hc_downtime = 0;
		peer->hc_downstart = 0;
		peer->total_header_time = 0;
		peer->total_response_time = 0;
		peer->selected_time = 0;
		peer->unavail = 0;
		peer->fails = 0;

		njt_memzero(peer_name.data, peer_name.len);
		peer_name.len = njt_snprintf(peer_name.data,peer_name.len,"upstream_status_%V_%d_%V",peers->name,peer->id,&peer->name) - peer_name.data;
		njt_http_get_variable(r,&peer_name,0);
	}
	backup = peers->next;

	if (backup) {

		for (peer = backup->peer; peer; peer = peer->next) {

			peer->requests = 0;
			peer->hc_checks = 0;
			peer->hc_fails = 0;
			peer->hc_last_passed = 0;
			peer->hc_downtime = 0;
			peer->hc_downstart = 0;
			peer->total_header_time = 0;
			peer->total_response_time = 0;
			peer->selected_time = 0;
			peer->total_fails = 0;
			peer->unavail = 0;
			peer->fails = 0;


			njt_memzero(peer_name.data, peer_name.len);
			peer_name.len = njt_snprintf(peer_name.data,peer_name.len,"upstream_status_%V_%d_%V",peers->name,peer->id,&peer->name) - peer_name.data;
			njt_http_get_variable(r,&peer_name,0);
		}
	}

	if (rc != NJT_OK) {
		njt_http_upstream_rr_peers_unlock(peers);
		return rc;
	}

	njt_http_upstream_rr_peers_unlock(peers);

	/*Output the servers*/
	rc = NJT_HTTP_UPS_API_RESET; 
	return rc;

}




	static njt_int_t
njt_http_upstream_api_process_delete(njt_http_request_t *r,
		void *cf,
		njt_uint_t id, njt_chain_t *out)
{
	njt_int_t                      rc;
	upstream_list_upstreamDef_t *upstream_one;
	njt_http_upstream_rr_peers_t   *peers, *backup, *target_peers;
	njt_http_upstream_rr_peer_t    *peer,  *prev, *del_peer,**p;
	njt_flag_t                      del_parent = 0; 
	njt_http_upstream_api_ctx_t       *ctx = NULL;
	njt_http_upstream_srv_conf_t *uscf = cf;
	njt_flag_t keep_alive = 0;
	njt_str_t  *to_json = NULL;
	njt_str_t zone_name = njt_string("");

#if (NJT_HTTP_UPSTREAM_ZONE)
	if (uscf != NULL && uscf->shm_zone != NULL){
		zone_name = uscf->shm_zone->shm.name;
	}
#endif

	rc = NJT_HTTP_UPS_API_SRV_NOT_FOUND; //NJT_OK;

	del_peer = NULL;
	peers = (njt_http_upstream_rr_peers_t *)uscf->peer.data; //
	prev = peers->peer;
	p = &peers->peer;
	target_peers = peers;


	njt_http_upstream_rr_peers_wlock(peers);
	for (peer = peers->peer; peer; ) {
		if(peer->id == id && peer->parent_id != -1)
		{
			rc = NJT_HTTP_UPS_API_SRV_NOT_REMOVALBE;
			goto out;
		}
		if ((peer->id == id && peer->parent_id == -1) || (peer->parent_id == (njt_int_t)id)) {
			del_parent = (peer->parent_id == (njt_int_t)id) ? 1:0;
			if (peer->down == 0) {
				target_peers->tries--;
			}
			if (peer->conns) {
				peer->down = 1;
				peer->del_pending = 1;
				continue;
			}

			target_peers->number--;

			target_peers->total_weight -= peer->weight;
			target_peers->single = (target_peers->number <= 1);
			//target_peers->empty = (target_peers->number == 0);
			target_peers->weighted = (target_peers->total_weight != target_peers->number);
			if (peer->down == 0) {
				target_peers->tries--;
			}
			del_peer = peer;
			*p = peer->next;
			peer = peer->next;
			/*TODO is the lock nessary?*/
			njt_shmtx_lock(&peers->shpool->mutex);
			njt_http_upstream_free_peer_memory(peers->shpool, del_peer);
			njt_shmtx_unlock(&peers->shpool->mutex);

			rc = NJT_OK;
		} else {
			prev = peer;
			p = &prev->next;
			peer = peer->next;
		}
	}

	if (del_peer == NULL) {
		backup = peers->next;
		target_peers = backup;

		if (backup == NULL) {
			rc = NJT_HTTP_UPS_API_SRV_NOT_FOUND;
		} else {

			prev = backup->peer;
			p = &backup->peer;
			for (peer = backup->peer; peer; ) {

				if ((peer->id == id && peer->parent_id == -1) || (peer->parent_id == (njt_int_t)id)) {
					del_parent = (peer->parent_id == (njt_int_t)id) ? 1:0;
					if (peer->down == 0) {
						target_peers->tries--;
					}
					if (peer->conns) {
						peer->down = 1;
						peer->del_pending = 1;
						continue;
					}
					target_peers->number--;
					target_peers->total_weight -= peer->weight;
					target_peers->single = (target_peers->number <= 1);
					//target_peers->empty = (target_peers->number == 0);
					target_peers->weighted = (target_peers->total_weight != target_peers->number);

					del_peer = peer;
					*p = peer->next;
					peer = peer->next;
					/*TODO is the lock nessary?*/
					njt_shmtx_lock(&peers->shpool->mutex);
					njt_http_upstream_free_peer_memory(peers->shpool, del_peer);
					njt_shmtx_unlock(&peers->shpool->mutex);

					rc = NJT_OK;
				} else {
					prev = peer;
					p = &prev->next;
					peer = peer->next;
				}


			}
		}
	}
	if (del_parent == 1 || del_peer == NULL) {

		for (peer = peers->parent_node; peer; peer = peer->next) {
			if(peer->parent_id == -1)
				continue;

			if (peer->id == id) {


				ctx = njt_pcalloc(r->pool, sizeof(njt_http_upstream_api_ctx_t));
				if (ctx == NULL) {
					njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
							"upstream api ctx allocate error.");
					return NJT_HTTP_UPS_API_INTERNAL_ERROR;
				}
				ctx->resolver = uscf->resolver;
				ctx->uscf  = uscf;
				ctx->peers = peers;
				ctx->id = id;
				ctx->keep_alive = uscf->set_keep_alive;
				njt_http_set_ctx(r, ctx, njt_http_upstream_api_module);
				peer->parent_id = -1;
				njt_http_upstream_api_create_dynamic_server(r,peer,0);

				rc = NJT_OK;
				break;

			}
		}

	}

out:
	if (rc != NJT_OK) {
		njt_http_upstream_rr_peers_unlock(peers);
		return rc;
	}
	peers->single = (peers->number + peers->next->number <= 1);
	peers->update_id++;	
	njt_http_upstream_rr_peers_unlock(peers);

	/*Output the servers*/
	if(ctx) {
		keep_alive = ctx->keep_alive;
	}
	upstream_one = create_upstream_list_upstreamDef(r->pool);
	if (upstream_one == NULL) {
		return NJT_HTTP_UPS_API_INTERNAL_ERROR;
	}

	set_upstream_list_upstreamDef_name(upstream_one,&uscf->host);
	set_upstream_list_upstreamDef_keepalive(upstream_one,keep_alive);
	set_upstream_list_upstreamDef_zone(upstream_one,&zone_name);	


	rc = njt_http_upstream_api_compose_one_upstream(upstream_one,r, peers);
	if (rc != NJT_OK) {
		return rc;
	}
	to_json = to_json_upstream_list_upstreamDef(r->pool,upstream_one,OMIT_NULL_ARRAY | OMIT_NULL_OBJ | OMIT_NULL_STR);
	if(to_json != NULL){
		rc = njt_http_upstream_api_packet_out(r,to_json,out);
	}

	return rc;

}



	static njt_int_t
njt_http_upstream_state_save(njt_http_request_t *r,
		void *cf)
{
	njt_int_t                      rc;
	njt_fd_t                       fd;
	njt_http_upstream_rr_peer_t   *peer,*peer_data;
	njt_http_upstream_rr_peers_t  *peers, *backup;
	njt_str_t                      state_file;
	u_char                        *server_info;
	ssize_t                        len;
	njt_http_upstream_srv_conf_t *uscf = cf;
	if(uscf == NULL) {
		return NJT_OK;
	}

	rc = NJT_ERROR;
	state_file = uscf->state_file;

	if(state_file.data == NULL || state_file.len == 0) {
		rc = NJT_OK;
		return rc;
	}
	peers = uscf->peer.data;
	njt_http_upstream_rr_peers_wlock(peers);

	fd = njt_open_file(state_file.data, NJT_FILE_CREATE_OR_OPEN | NJT_FILE_RDWR,
			NJT_FILE_TRUNCATE, 0);
	if (fd == NJT_INVALID_FILE ) {
		njt_log_error(NJT_LOG_CRIT, njt_cycle->log, njt_errno,
				njt_open_file_n " \"%V\" failed", &state_file);
		njt_http_upstream_rr_peers_unlock(peers);
		goto failed;
	}

	/*TODO refine the length 512 for malloc*/
	server_info = njt_pcalloc(r->pool, 512);
	if (server_info == NULL) {
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
				"failed to allocate memory from r->pool %s:%d",
				__FUNCTION__,
				__LINE__);
		njt_http_upstream_rr_peers_unlock(peers);
		goto failed;
	}



	for (peer = peers->peer; peer ; peer = peer->next) {

		if(peer->parent_id != -1)
			continue;

		peer_data = peer;
		njt_memzero(server_info, 512);
		if(peer_data && peer_data->route.len > 0) {
			njt_snprintf(server_info, 511,
					"server %V %s weight=%d max_conns=%d %s max_fails=%d fail_timeout=%d slow_start=%d route=%V;\r\n",
					&peer_data->server, (peer_data->parent_id != -1?"resolve" : ""),peer_data->weight, peer_data->max_conns,
					peer_data->down ? "down" : "",
					peer_data->max_fails, peer_data->fail_timeout,peer_data->slow_start,&peer_data->route);
		} else {
			njt_snprintf(server_info, 511,
					"server %V %s weight=%d max_conns=%d %s max_fails=%d fail_timeout=%d slow_start=%d;\r\n",
					&peer_data->server, (peer_data->parent_id != -1?"resolve" : ""),peer_data->weight, peer_data->max_conns,
					peer_data->down ? "down" : "",
					peer_data->max_fails, peer_data->fail_timeout,peer_data->slow_start);
		}

		len = njt_write_fd(fd, server_info, njt_strlen(server_info));
		if (len == -1) {
			njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,
					njt_write_fd_n " write file error %V",
					&state_file);
			njt_http_upstream_rr_peers_unlock(peers);
			goto failed;

		}

	}

	backup = peers->next;
	if (backup) {

		njt_memzero(server_info, 512);

		for (peer = backup->peer; peer ; peer = peer->next) {

			if(peer->parent_id != -1)
				continue;

			peer_data = peer;
			njt_memzero(server_info, 512);
			if(peer_data && peer_data->route.len > 0) {
				njt_snprintf(server_info, 511,
						"server %V %s weight=%d max_conns=%d %s max_fails=%d fail_timeout=%d slow_start=%d route=%V backup;\r\n",
						&peer_data->server, (peer_data->parent_id != -1?"resolve" : ""),peer_data->weight, peer_data->max_conns,
						peer_data->down ? "down" : "",
						peer_data->max_fails, peer_data->fail_timeout,peer_data->slow_start,&peer_data->route);
			} else {
				njt_snprintf(server_info, 511,
						"server %V %s weight=%d max_conns=%d %s max_fails=%d fail_timeout=%d slow_start=%d backup;\r\n",
						&peer_data->server, (peer_data->parent_id != -1?"resolve" : ""),peer_data->weight, peer_data->max_conns,
						peer_data->down ? "down" : "",
						peer_data->max_fails, peer_data->fail_timeout,peer_data->slow_start);
			}

			len = njt_write_fd(fd, server_info, njt_strlen(server_info));
			if (len == -1) {
				njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,
						njt_write_fd_n " write file error %V",
						&state_file);
				njt_http_upstream_rr_peers_unlock(peers);
				goto failed;

			}
		}
	}



	for (peer = peers->parent_node; peer ; peer = peer->next) {

		if(peer->parent_id == -1)
			continue;

		peer_data = peer;
		njt_memzero(server_info, 512);
		if(peer_data && peer_data->route.len > 0) {
			njt_snprintf(server_info, 511,
					"server %V %s weight=%d max_conns=%d %s max_fails=%d fail_timeout=%d slow_start=%d route=%V %s;\r\n",
					&peer_data->server, (peer_data->parent_id != -1?"resolve" : ""),peer_data->weight, peer_data->max_conns,
					peer_data->down ? "down" : "",
					peer_data->max_fails, peer_data->fail_timeout,peer_data->slow_start,&peer_data->route,peer_data->set_backup > 0? "backup" : "");
		} else {
			njt_snprintf(server_info, 511,
					"server %V %s weight=%d max_conns=%d %s max_fails=%d fail_timeout=%d slow_start=%d %s;\r\n",
					&peer_data->server, (peer_data->parent_id != -1?"resolve" : ""),peer_data->weight, peer_data->max_conns,
					peer_data->down ? "down" : "",
					peer_data->max_fails, peer_data->fail_timeout,peer_data->slow_start,peer_data->set_backup > 0? "backup" : "");
		}

		len = njt_write_fd(fd, server_info, njt_strlen(server_info));
		if (len == -1) {
			njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,
					njt_write_fd_n " write file error %V",
					&state_file);
			njt_http_upstream_rr_peers_unlock(peers);
			goto failed;

		}
	}
	if(r->method == NJT_HTTP_POST && json_peer.domain == 1) {
		njt_memzero(server_info, 512);
		if(json_peer.route.len > 0) {
			njt_snprintf(server_info, 511,
					"server %V resolve weight=%d max_conns=%d %s max_fails=%d fail_timeout=%d slow_start=%d route=%V %s;\r\n",
					&json_peer.server, json_peer.weight, json_peer.max_conns,
					json_peer.down ? "down" : "",
					json_peer.max_fails, json_peer.fail_timeout,json_peer.slow_start,&json_peer.route,json_peer.backup > 0? "backup" : "");
		} else {
			njt_snprintf(server_info, 511,
					"server %V resolve weight=%d max_conns=%d %s max_fails=%d fail_timeout=%d slow_start=%d %s;\r\n",
					&json_peer.server, json_peer.weight, json_peer.max_conns,
					json_peer.down ? "down" : "",
					json_peer.max_fails, json_peer.fail_timeout,json_peer.slow_start,json_peer.backup > 0? "backup" : "");
		}
		len = njt_write_fd(fd, server_info, njt_strlen(server_info));
		if (len == -1) {
			njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,
					njt_write_fd_n " write file error %V",
					&state_file);
			goto failed;

		}
	}


	rc = NJT_OK;
	njt_http_upstream_rr_peers_unlock(peers);

failed:

	if (fd != NJT_INVALID_FILE) {

		if (njt_close_file(fd) == NJT_FILE_ERROR) {
			njt_log_error(NJT_LOG_ALERT, njt_cycle->log, njt_errno,
					njt_close_file_n " \"%V\" failed", &state_file);
		}
	}

	return rc;
}


	static njt_int_t
njt_upstream_api_params_check(njt_array_t *path, njt_http_request_t *r, njt_str_t *upstream,
		njt_str_t *id, void **target_uscf, ssize_t *server_id,
		njt_flag_t   upstream_type)
{
	njt_int_t                       rc;
	njt_http_upstream_main_conf_t  *umcf;
	njt_stream_upstream_main_conf_t  *umcf_stream;
	njt_http_upstream_srv_conf_t   *uscf, **uscfp;
	njt_stream_upstream_srv_conf_t   *uscf_strem, **uscfp_stream;
	njt_uint_t                      i;
	void       *peers = NULL;


	rc = NJT_OK;
	*target_uscf = NULL;
	*server_id = -1;

	/*upstream must have value for post patch and delete*/
	if (r->method & (NJT_HTTP_POST | NJT_HTTP_PATCH | NJT_HTTP_DELETE)) {
		if (upstream->data == NULL || upstream->len == 0) {
			rc = NJT_HTTP_UPS_API_METHOD_NOT_SUPPORTED;
			return rc;
		}
	}

	/*id must not have value for post*/
	if (r->method == NJT_HTTP_POST) {
		if (id->data || id->len) {
			rc = NJT_HTTP_UPS_API_METHOD_NOT_SUPPORTED;
			return rc;
		}
	}

	/*id must have value for patch and delete*/
	if ((r->method & (NJT_HTTP_PATCH | NJT_HTTP_DELETE)) && path->nelts >= 5) {
		if (id->data == NULL || id->len == 0) {
			rc = NJT_HTTP_UPS_API_METHOD_NOT_SUPPORTED;
			return rc;
		}
	}


	if (upstream->data && upstream->len) {
		if(upstream_type == 1) {
			umcf = njt_http_cycle_get_module_main_conf(njet_master_cycle ,
					njt_http_upstream_module);
			if(umcf == NULL) {
				rc = NJT_HTTP_UPS_API_PATH_NOT_FOUND;
				return rc;
			}
			uscfp = umcf->upstreams.elts;
			for (i = 0; i < umcf->upstreams.nelts; i++) {

				uscf = uscfp[i];
				/*specify zone name*/
				if (uscf->host.len == upstream->len
						&& njt_strncmp(uscf->host.data, upstream->data, upstream->len) == 0) {
					*target_uscf = uscf;
					break;
				}
			}
		} else {
			umcf_stream = njt_stream_cycle_get_module_main_conf(njet_master_cycle,
					njt_stream_upstream_module);
			if(umcf_stream == NULL) {
				rc = NJT_HTTP_UPS_API_PATH_NOT_FOUND;
				return rc;
			}
			uscfp_stream = umcf_stream->upstreams.elts;
			for (i = 0; i < umcf_stream->upstreams.nelts; i++) {
				uscf_strem = uscfp_stream[i];
				/*specify zone name*/
				if (uscf_strem->host.len == upstream->len
						&& njt_strncmp(uscf_strem->host.data, upstream->data, upstream->len) == 0) {
					*target_uscf = uscf_strem;
					break;
				}
			}
		}
	}

	if (r->method & NJT_HTTP_GET) {

		if (*target_uscf == NULL && (upstream->len || upstream->data)) {
			rc = NJT_HTTP_UPS_API_UPS_NOT_FOUND;
			return rc;
		}
		if(*target_uscf != NULL) {
			peers = (upstream_type == 1? (void *)((njt_http_upstream_srv_conf_t *)(*target_uscf))->peer.data : (void *)((njt_stream_upstream_srv_conf_t *)(*target_uscf))->peer.data);
		}
	} else {

		if (*target_uscf == NULL) {
			rc = NJT_HTTP_UPS_API_UPS_NOT_FOUND;
			return rc;
		}
		peers = (upstream_type == 1? (void *)((njt_http_upstream_srv_conf_t *)(*target_uscf))->peer.data : (void *)((njt_stream_upstream_srv_conf_t *)(*target_uscf))->peer.data);
	}
	if(peers) {
		if (upstream_type == 1 && !(((njt_http_upstream_rr_peers_t   *)peers)->shpool)) {
			return  NJT_HTTP_UPS_API_STATIC_UPS;
		}
		if (upstream_type == 2 && !(((njt_stream_upstream_rr_peers_t   *)peers)->shpool)) {
			return  NJT_HTTP_UPS_API_STATIC_UPS;
		}

		if (id->data && id->len) {
			*server_id = njt_atoof(id->data, id->len);
			if (*server_id == NJT_ERROR) {
				rc =  NJT_HTTP_UPS_API_INVALID_SRVID;
				return rc;
			}
		}
	}

	return rc;
}

	static njt_int_t
njt_http_upstream_api_versions(njt_http_request_t *r, njt_chain_t *out)
{
	njt_str_t versions;
	njt_int_t rc;

	njt_str_set(&versions, "[1,2,3,4,5,6,7]");
	rc = njt_http_upstream_api_insert_out_str(r, out, &versions);

	return rc;
}

/*out holds the content needs to be sent out if any.*/
	static njt_int_t
njt_upstream_api_process_request(njt_http_request_t *r, njt_array_t *path,
		njt_chain_t *out,njt_int_t *if_send)
{

	njt_int_t                     rc;
	njt_str_t                     upstream, id;
	njt_flag_t                    detailed;
	void *uscf;
	ssize_t                       server_id;
	njt_flag_t                    upstream_type;
	njt_upstream_api_process_get_pt     njt_upstream_api_process_get;
	njt_upstream_api_process_reset_pt   njt_upstream_api_process_reset;
	njt_upstream_api_process_delete_pt  njt_upstream_api_process_delete;
	njt_upstream_api_process_patch_pt   njt_upstream_api_process_patch;
	njt_upstream_api_process_post_pt    njt_upstream_api_process_post;
	njt_upstream_state_save_pt          njt_upstream_state_save;
	//njt_int_t index;


	njt_str_null(&upstream);
	njt_str_null(&id);

	/*pure api request . return [1,2,3,4,5,6,7]*/
	if (path->nelts == 0) {
		rc = njt_http_upstream_api_versions(r, out);
		njt_http_discard_request_body(r);
		return rc;
	}
	if (r->method == NJT_HTTP_POST && path->nelts < 5){
		rc = NJT_HTTP_UPS_API_PERM_NOT_ALLOWED;
		return rc;

	}
	rc = njt_upstream_api_get_params(path, &upstream, &id,&upstream_type);
	if (rc != NJT_OK) {
		/*PATH not found*/
		njt_http_discard_request_body(r);
		return rc;
	}

	rc = njt_upstream_api_params_check(path,r, &upstream, &id, (void **)&uscf, &server_id,upstream_type);
	if (rc != NJT_OK) {
		/*PATH not found*/
		njt_http_discard_request_body(r);
		return rc;
	}
	njt_upstream_api_process_get   = njt_http_upstream_api_process_get;
	njt_upstream_api_process_reset = njt_http_upstream_api_process_reset;
	njt_upstream_api_process_delete = njt_http_upstream_api_process_delete;
	njt_upstream_api_process_patch = njt_http_upstream_api_process_patch;
	njt_upstream_api_process_post  = njt_http_upstream_api_process_post;
	njt_upstream_state_save        = njt_http_upstream_state_save;

	if(upstream_type != 1) {
		njt_upstream_api_process_get   = njt_stream_upstream_api_process_get;
		njt_upstream_api_process_reset = njt_stream_upstream_api_process_reset;
		njt_upstream_api_process_delete = njt_stream_upstream_api_process_delete;
		njt_upstream_api_process_patch = njt_stream_upstream_api_process_patch;
		njt_upstream_api_process_post  = njt_stream_upstream_api_process_post;
		njt_upstream_state_save        = njt_stream_upstream_state_save;
	}


	/*deal with all kinds of reqeust*/

	switch (r->method) {

		case NJT_HTTP_GET:

			rc = njt_http_discard_request_body(r);
			if (rc != NJT_OK) {
				goto out;
			}

			detailed = (path->nelts >= 5) ? 0 : 1;
			rc = njt_upstream_api_process_get(r, uscf, server_id, detailed, out);
			break;

		case NJT_HTTP_DELETE:

			rc = njt_http_discard_request_body(r);
			if (rc != NJT_OK) {
				goto out;
			}
			if(path->nelts == 4) { //reset statistics
				rc = njt_upstream_api_process_reset(r, uscf, out);

			} else {
				rc = njt_upstream_api_process_delete(r, uscf, server_id, out);
			}

			break;

		case NJT_HTTP_PATCH:
			rc = njt_upstream_api_process_patch(r, uscf, server_id);
			*if_send = 0;
			break;

		case NJT_HTTP_POST:
			if(path->nelts >=5) {
				rc = njt_upstream_api_process_post(r, uscf);
				*if_send = 0;
			} 
			break;


		default:
			rc = NJT_HTTP_UPS_API_METHOD_NOT_SUPPORTED;
			break;

	}

out:
	/*try to save the upstream servers into the stat file*/
	if ((rc == NJT_OK || rc == NJT_DONE) &&  r->method != NJT_HTTP_GET) {
		njt_upstream_state_save(r, uscf);

	}

	return rc;

}

	static njt_int_t
njt_upstream_api_parse_path(njt_http_request_t *r, njt_array_t *path)
{

	u_char                              *p, *sub_p,*last;
	njt_uint_t                          len;
	njt_str_t                           *item;
	njt_http_core_loc_conf_t            *clcf;
	njt_str_t                           uri,data;

	/*the uri is parsed and delete all the duplidated '/' characters.
	 * for example, "/api//7//http///upstreams///////" will be parse to
	 * "/api/7/http/upstreams/" already*/

	clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

	uri = r->uri;
	p = uri.data + clcf->name.len;
	len = uri.len - clcf->name.len;
	last = uri.data + uri.len;

	if (*p == '/') {
		len --;
		p ++;
	}

	while (len > 0) {

		data.data = p;
		sub_p = (u_char *)njt_strlchr(p,last,'/');

		if (sub_p == NULL || (njt_uint_t)(sub_p - uri.data) > uri.len) {
			data.len = uri.data + uri.len - p;

			if(path->nelts == 1 &&  data.len == upstream_api_module_name.len && njt_memcmp(data.data,upstream_api_module_name.data,data.len) == 0) {

			} else {
				item = njt_array_push(path);
				if (item == NULL) {
					njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
							"array item of path push error.");
					return NJT_ERROR;
				}
				*item = data;
			}
			break;

		} else {
			data.len = sub_p - p;
		}
		if(path->nelts == 1 &&  data.len == upstream_api_module_name.len && njt_memcmp(data.data,upstream_api_module_name.data,data.len) == 0) {

		} else {
			item = njt_array_push(path);
			if (item == NULL) {
				njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
						"array item of path push error.");
				return NJT_ERROR;
			}
			*item = data;
		}


		len -= data.len;
		p += data.len;

		if (*p == '/') {
			len --;
			p ++;
		}

	}

	return NJT_OK;
}


/*TODO use an error to define the map of the error code and its error message.*/
	static njt_int_t
njt_http_upstream_api_err_out(njt_http_request_t *r, njt_int_t code,njt_str_t *msg,
		njt_chain_t *out)
{
	njt_str_t error_text,error_code,request_id,href;
	njt_int_t rc;
	njt_http_variable_value_t  *value;
	njt_uint_t                  key;
	u_char                     *low;
	njt_str_t                  *to_json;


	upstream_error_msg_error_t   *error_obj          =  create_upstream_error_msg_error(r->pool);
	upstream_error_msg_t         *upstream_error_msg =  create_upstream_error_msg(r->pool);

	if(upstream_error_msg == NULL || error_obj == NULL) {
		return NJT_ERROR;
	}


	rc = NJT_OK;

	/*We need to clean up the out buf at first.*/
	out->buf = NULL;
	out->next = NULL;

	set_upstream_error_msg_error(upstream_error_msg,error_obj);

	r->headers_out.status = NJT_HTTP_NOT_FOUND;
	switch (code) {

		case NJT_HTTP_UPS_API_PATH_NOT_FOUND:
			r->headers_out.status = 404;
			njt_str_set(&error_text,"path not found");
			njt_str_set(&error_code,"PathNotFound");


			break;

		case NJT_HTTP_UPS_API_UPS_NOT_FOUND:
			r->headers_out.status = 404;

			njt_str_set(&error_text,"upstream not found");
			njt_str_set(&error_code,"UpstreamNotFound");


			break;

		case NJT_HTTP_UPS_API_UNKNOWN_VERSION:
			r->headers_out.status = 404;

			njt_str_set(&error_text,"unknown version");
			njt_str_set(&error_code,"Unknownversion");

			break;

		case NJT_HTTP_UPS_API_INVALID_SRVID:
			r->headers_out.status = NJT_HTTP_BAD_REQUEST;

			njt_str_set(&error_text,"invalid server id");
			njt_str_set(&error_code,"UpStreamBadServerId");

			break;

		case NJT_HTTP_UPS_API_SRV_NOT_FOUND:
			r->headers_out.status = 404;

			njt_str_set(&error_text,"server not found");
			njt_str_set(&error_code,"UpStreamServerNotFound");

			break;

		case NJT_HTTP_UPS_API_PERM_NOT_ALLOWED:
			r->headers_out.status = 405;

			njt_str_set(&error_text,"method not supported");
			njt_str_set(&error_code,"MethodNotSupported");

			break;

		case NJT_HTTP_UPS_API_STATIC_UPS:
			r->headers_out.status = 400;

			njt_str_set(&error_text,"upstream is static");
			njt_str_set(&error_code,"UpstreamStatic");

			break;

		case NJT_HTTP_UPS_API_SRV_NOT_REMOVALBE:
			r->headers_out.status = 400;

			njt_str_set(&error_text,"server not removeable");
			njt_str_set(&error_code,"UpstreamServerImmutable");

			break;

		case NJT_HTTP_UPS_API_METHOD_NOT_SUPPORTED:
			r->headers_out.status = 405;

			njt_str_set(&error_text,"method not supported");
			njt_str_set(&error_code,"MethodNotSupported");

			break;

		case NJT_HTTP_UPS_API_TOO_LARGE_BODY:
			r->headers_out.status = 405;

			njt_str_set(&error_text,"too large post body");
			njt_str_set(&error_code,"TooLargePostBody");

			break;
		case NJT_HTTP_UPS_API_ROUTE_INVALID_LEN:
			r->headers_out.status = 400;

			njt_str_set(&error_text,"route is longer than 32");
			njt_str_set(&error_code,"UpstreamBadRoute");

			break;
		case NJT_HTTP_UPS_API_INVALID_JSON_BODY:
			r->headers_out.status = 400;
			if(msg != NULL && msg->data != NULL && msg->len > 0) {

				njt_str_set(&error_text,"unknown parameter \"route\"");
				njt_str_set(&error_code,"UpstreamConfFormatError");

			} else {
				r->headers_out.status = 405;

				njt_str_set(&error_text,"invalid json body");
				njt_str_set(&error_code,"InvalidJsonBody");
			}

			break;

		case NJT_HTTP_UPS_API_MISS_SRV:
			r->headers_out.status = 400;
			njt_str_set(&error_text,"missing \"server\" argument");
			njt_str_set(&error_code,"UpstreamConfFormatError");

			break;

		case NJT_HTTP_UPS_API_MODIFY_SRV:
			r->headers_out.status = 405;

			njt_str_set(&error_text,"try to modify server");
			njt_str_set(&error_code,"TryToModifyServer");

			break;

		case NJT_HTTP_UPS_API_NOT_SUPPORTED_SRV:
			r->headers_out.status = 405;

			njt_str_set(&error_text,"domain name isn't supported");
			njt_str_set(&error_code,"DomainName");
			break;
		case NJT_HTTP_UPS_API_INVALID_JSON_PARSE:
			r->headers_out.status = 415;

			njt_str_set(&error_text,"json error");
			njt_str_set(&error_code,"JsonError");
			break;
		case NJT_HTTP_UPS_API_NO_RESOLVER:
			r->headers_out.status = 400;

			njt_str_set(&error_text,"no resolver defined to resolve");
			njt_str_set(&error_code,"UpstreamConfNoResolver");
			break;
		case NJT_HTTP_UPS_API_WEIGHT_ERROR:
			r->headers_out.status = 400;

			njt_str_set(&error_text,"invalid weight");
			njt_str_set(&error_code,"UpstreamBadWeight");

			break;
		case NJT_HTTP_UPS_API_NO_SRV_PORT:
			r->headers_out.status = 400;
			njt_str_set(&error_text,"no port in server");
			njt_str_set(&error_code,"UpstreamBadAddress");
			break;
		case NJT_HTTP_UPS_API_NOT_MODIFY_SRV_NAME:
			r->headers_out.status = 400;

			njt_str_set(&error_text,"server address is immutable");
			njt_str_set(&error_code,"UpstreamServer Immutable");
			break;
		case NJT_HTTP_UPS_API_INVALID_SRV_ARG:
			r->headers_out.status = 400;

			njt_str_set(&error_text,"invalid \"server\" argument");
			njt_str_set(&error_code,"UpstreamBadAddress");
			break;  //
		case NJT_HTTP_UPS_API_HAS_NO_BACKUP:
			r->headers_out.status = 400;

			njt_str_set(&error_text,"upstream has no backup");
			njt_str_set(&error_code,"UpstreamNoBackup");
			break;  
		case NJT_HTTP_UPS_API_RESET:
			r->headers_out.status = 204;
			r->header_only = 1;
			return NJT_OK;
		default:
			r->headers_out.status = 404;

			njt_str_set(&error_text,"unknown error");
			njt_str_set(&error_code,"UnknownError");
			break;
	}
	set_upstream_error_msg_error_status(error_obj,r->headers_out.status);
	set_upstream_error_msg_error_text(error_obj,&error_text);
	set_upstream_error_msg_error_code(error_obj,&error_code);

	njt_str_set(&href,"https://njet.org/en/docs/http/njt_http_api_module.html");
	set_upstream_error_msg_href(upstream_error_msg,&href);

	njt_str_set(&request_id,"request_id");
	low = njt_pnalloc(r->pool, request_id.len);
	if (low == NULL) {
		return NJT_ERROR;
	}
	key = njt_hash_strlow(low,request_id.data, request_id.len);
	value = njt_http_get_variable(r, &request_id, key);
	if (value == NULL || value->not_found || value->len == 0) {
		njt_str_set(&request_id,"N/A");
	} else {
		request_id.data = value->data;
		request_id.len = value->len;

	}
	set_upstream_error_msg_request_id(upstream_error_msg,&request_id);

	to_json = to_json_upstream_error_msg(r->pool,upstream_error_msg,OMIT_NULL_ARRAY | OMIT_NULL_OBJ | OMIT_NULL_STR);
	rc = njt_http_upstream_api_packet_out(r,to_json,out);

	return rc;
}

	static ssize_t
njt_http_upstream_api_out_len(njt_chain_t *out)
{
	ssize_t len;

	len = 0;
	while (out) {

		if (out->buf) {
			len += out->buf->last - out->buf->pos;
		}

		out = out->next;
	}

	return len;
}

	static njt_int_t
njt_http_upstream_api_handler(njt_http_request_t *r)
{
	njt_int_t                          rc;
	njt_array_t                        path;
	njt_chain_t                        out;
	njt_http_upstream_api_loc_conf_t *uclcf;
	ssize_t                            len;
	njt_int_t                          if_send;
	// njt_http_upstream_api_main_conf_t *mcf;
	//njt_http_core_loc_conf_t          *clcf;

	/*
	 * check of the permission according to the configure.
	 */
	//mcf = njt_http_get_module_main_conf(r, njt_http_upstream_api_module);

	if_send = 1;
	uclcf = njt_http_get_module_loc_conf(r, njt_http_upstream_api_module);
	if(uclcf == NULL){
		return NJT_DECLINED;
	}
	uclcf->write = 1;
	if (uclcf->write == NJT_CONF_UNSET_UINT || uclcf->write == 0) {
		if (r->method == NJT_HTTP_POST || r->method == NJT_HTTP_DELETE
				|| r->method == NJT_HTTP_PATCH) {
			rc = NJT_HTTP_UPS_API_PERM_NOT_ALLOWED;
			goto out;
		}
	}

	if (njt_array_init(&path, r->pool, 8, sizeof(njt_str_t)) != NJT_OK) {
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
				"array init of upstream api error.");
		rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
		goto out;
	}

	rc = njt_upstream_api_parse_path(r, &path);

	/*internal error*/
	if (rc != NJT_OK) {
		goto out;
	}

	out.next = NULL;
	out.buf = NULL;
	rc = njt_upstream_api_process_request(r, &path, &out,&if_send);
	if (if_send == 0){
		return rc;
	}

out:
	/*find in the error message*/
	if (rc != NJT_OK) {

		rc = njt_http_upstream_api_err_out(r, rc,NULL, &out);
		if (rc != NJT_OK) {
			return NJT_HTTP_INTERNAL_SERVER_ERROR;
		}

	} else {
		r->headers_out.status = NJT_HTTP_OK;
	}

	r->headers_out.content_type_len = sizeof("text/plain") - 1;
	njt_str_set(&r->headers_out.content_type, "text/plain");
	r->headers_out.content_type_lowcase = NULL;

	len = njt_http_upstream_api_out_len(&out);

	r->headers_out.content_length_n = len;
	if (r->headers_out.content_length) {
		r->headers_out.content_length->hash = 0;
		r->headers_out.content_length = NULL;
	}
	rc = njt_http_send_header(r);

	if (rc == NJT_ERROR || rc > NJT_OK || r->header_only) {
		return rc;
	}


	return njt_http_output_filter(r, &out);
}


static njt_int_t  njt_http_upstream_api_packet_out(njt_http_request_t *r,njt_str_t *to_json,njt_chain_t *out) {
	njt_buf_t                      *b;
	if(to_json){
		b = njt_http_upstream_api_get_out_buf(r, to_json->len, out);
		if (b == NULL) {
			njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
					"could not alloc buffer in function %s", __func__);
			return NJT_ERROR;
		}
		njt_memcpy(b->last, to_json->data, to_json->len);
		b->last = b->last + to_json->len;
	}
	return NJT_OK;
}




////////////////////////stream upstream///////////////////////////

static njt_int_t njt_stream_upstream_api_create_dynamic_server(njt_http_request_t *r,njt_stream_upstream_rr_peer_t        *peer,njt_flag_t backup) {

	njt_http_upstream_api_main_conf_t *uclcf;
	njt_stream_upstream_rr_peer_t        *new_peer,*tail_peer;
	njt_slab_pool_t                    *shpool;
	njt_stream_upstream_api_ctx_t       *ctx;
	njt_stream_upstream_rr_peers_t *peers;


	ctx = njt_http_get_module_ctx(r, njt_http_upstream_api_module);
	peers = ctx->peers;

	uclcf = njt_http_get_module_main_conf(r, njt_http_upstream_api_module);
	if(uclcf->peers_stream == NULL || ctx == NULL || ctx->resolver == NULL) { // not support dynamic  domain server
		njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0,
				"add domain name:%V!",&peer->server);
		return NJT_HTTP_UPS_API_NO_RESOLVER;
	}
	shpool = uclcf->peers_stream->shpool;
	njt_stream_upstream_rr_peers_wlock(uclcf->peers_stream);
	new_peer = njt_slab_calloc_locked(shpool, sizeof(njt_stream_upstream_rr_peer_t));
	if(new_peer) {
		new_peer->server.data = njt_slab_calloc_locked(shpool, peer->server.len+1);
		if (new_peer->server.data) {
			new_peer->id = peer->id; //add dynamic  domain server
			new_peer->parent_id = peer->parent_id; 
			new_peer->server.len = peer->server.len;
			njt_cpystrn(new_peer->server.data, peer->server.data, peer->server.len+1);
			new_peer->hc_upstart =  njt_time();
			new_peer->weight    = peer->weight;
			new_peer->max_conns = peer->max_conns;
			new_peer->max_fails = peer->max_fails;
			new_peer->fail_timeout = peer->fail_timeout;
			new_peer->slow_start = peer->slow_start;
			new_peer->down = peer->down;
			new_peer->hc_down = peer->hc_down;
			new_peer->set_backup = backup;
			if(peers->name->len > 0) {  //zone name
				new_peer->name.len = peers->name->len;
				new_peer->name.data = njt_slab_calloc_locked(shpool, peers->name->len+1);
				if (new_peer->name.data) { 
					njt_cpystrn(new_peer->name.data, peers->name->data, peers->name->len+1);
				}
			}

			new_peer->next = NULL;
			if(uclcf->peers_stream->peer == NULL) {
				uclcf->peers_stream->peer = new_peer;
			} else {
				for(tail_peer = uclcf->peers_stream->peer;tail_peer->next != NULL; tail_peer = tail_peer->next);
				tail_peer->next = new_peer;
			}


			//uclcf->peers->peer = new_peer;
			//uclcf->peers_stream->number++;
		} else {
			njt_slab_free_locked(shpool,new_peer);
		}
	}
	njt_stream_upstream_rr_peers_unlock(uclcf->peers_stream);
	return NJT_OK;


}

	static njt_int_t
njt_stream_upstream_api_compose_one_upstream(upstream_list_upstreamDef_t *upstream_one,njt_http_request_t *r,
		void *p)
{

	njt_stream_upstream_rr_peer_t    *peer;
	njt_int_t                      rc = NJT_OK;
	njt_stream_upstream_rr_peers_t   *backup;
	upstream_list_peerDef_t *peerDef;

	njt_stream_upstream_rr_peers_t *peers = p;
	njt_uint_t   zombies = 0; //njt_pcalloc

	upstream_list_upstreamDef_peers_t  *upstreamDef_peers = create_upstream_list_upstreamDef_peers(r->pool,1);
	if(upstreamDef_peers == NULL) {
		return NJT_ERROR;
	}

	set_upstream_list_upstreamDef_peers(upstream_one,upstreamDef_peers);
	njt_http_upstream_rr_peers_rlock(peers);

	for (peer = peers->peer; peer != NULL; peer = peer->next) {


		if(peer->del_pending) {
			zombies++;
		}
		//add_item_upstream_list_upstreamDef_peers
		peerDef = njt_stream_upstream_api_compose_one_detail_server(r, peer,0,0,*peers->name);  //add_item_upstream_list_upstreamDef_peers

		if (peerDef == NULL) {
			njt_http_upstream_rr_peers_unlock(peers);
			return rc;
		}
		add_item_upstream_list_upstreamDef_peers(upstreamDef_peers,peerDef);

	}

	backup = peers->next;
	if (backup != NULL) {
		for (peer = backup->peer; peer != NULL; peer = peer->next) {


			if(peer->del_pending) {
				zombies++;
			}
			peerDef = njt_stream_upstream_api_compose_one_detail_server(r, peer,1,0,*peers->name);


			if (peerDef == NULL) {
				njt_http_upstream_rr_peers_unlock(peers);
				return rc;
			}
			add_item_upstream_list_upstreamDef_peers(upstreamDef_peers,peerDef);

		}
	}



	njt_http_upstream_rr_peers_unlock(peers);


	set_upstream_list_upstreamDef_zombies(upstream_one,zombies);



	return NJT_OK;
}

	static njt_int_t
njt_stream_upstream_state_save(njt_http_request_t *r,
		void *cf)
{
	njt_int_t                      rc;
	njt_fd_t                       fd;
	njt_stream_upstream_rr_peer_t   *peer,*peer_data;
	njt_stream_upstream_rr_peers_t  *peers, *backup;
	njt_str_t                      state_file;
	u_char                        *server_info;
	ssize_t                        len;
	njt_stream_upstream_srv_conf_t *uscf = cf;

	if(uscf == NULL){
		return NJT_OK;
	}
	rc = NJT_ERROR;
	state_file = uscf->state_file;

	if(state_file.data == NULL || state_file.len == 0) {
		rc = NJT_OK;
		return rc;
	}
	peers = uscf->peer.data;
	njt_stream_upstream_rr_peers_wlock(peers);

	fd = njt_open_file(state_file.data, NJT_FILE_CREATE_OR_OPEN | NJT_FILE_RDWR,
			NJT_FILE_TRUNCATE, 0);
	if (fd == NJT_INVALID_FILE ) {
		njt_log_error(NJT_LOG_CRIT, njt_cycle->log, njt_errno,
				njt_open_file_n " \"%V\" failed", &state_file);

		njt_stream_upstream_rr_peers_unlock(peers);
		goto failed;
	}

	/*TODO refine the length 512 for malloc*/
	server_info = njt_pcalloc(r->pool, 512);
	if (server_info == NULL) {
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
				"failed to allocate memory from r->pool %s:%d",
				__FUNCTION__,
				__LINE__);

		njt_stream_upstream_rr_peers_unlock(peers);
		goto failed;
	}



	for (peer = peers->peer; peer ; peer = peer->next) {

		if(peer->parent_id != -1)
			continue;

		peer_data = peer;
		njt_memzero(server_info, 512);

		njt_snprintf(server_info, 511,
				"server %V %s weight=%d max_conns=%d %s max_fails=%d fail_timeout=%d slow_start=%d;\r\n",
				&peer_data->server, (peer_data->parent_id != -1?"resolve" : ""),peer_data->weight, peer_data->max_conns,
				peer_data->down ? "down" : "",
				peer_data->max_fails, peer_data->fail_timeout,peer_data->slow_start);


		len = njt_write_fd(fd, server_info, njt_strlen(server_info));
		if (len == -1) {
			njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,
					njt_write_fd_n " write file error %V",
					&state_file);
			njt_stream_upstream_rr_peers_unlock(peers);
			goto failed;

		}

	}

	backup = peers->next;
	if (backup) {

		njt_memzero(server_info, 512);

		for (peer = backup->peer; peer ; peer = peer->next) {

			if(peer->parent_id != -1)
				continue;

			peer_data = peer;
			njt_memzero(server_info, 512);

			njt_snprintf(server_info, 511,
					"server %V %s weight=%d max_conns=%d %s max_fails=%d fail_timeout=%d slow_start=%d backup;\r\n",
					&peer_data->server, (peer_data->parent_id != -1?"resolve" : ""),peer_data->weight, peer_data->max_conns,
					peer_data->down ? "down" : "",
					peer_data->max_fails, peer_data->fail_timeout,peer_data->slow_start);


			len = njt_write_fd(fd, server_info, njt_strlen(server_info));
			if (len == -1) {
				njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,
						njt_write_fd_n " write file error %V",
						&state_file);
				njt_stream_upstream_rr_peers_unlock(peers);
				goto failed;

			}
		}
	}



	for (peer = peers->parent_node; peer ; peer = peer->next) {

		if(peer->parent_id == -1)
			continue;

		peer_data = peer;
		njt_memzero(server_info, 512);

		njt_snprintf(server_info, 511,
				"server %V %s weight=%d max_conns=%d %s max_fails=%d fail_timeout=%d slow_start=%d %s;\r\n",
				&peer_data->server, (peer_data->parent_id != -1?"resolve" : ""),peer_data->weight, peer_data->max_conns,
				peer_data->down ? "down" : "",
				peer_data->max_fails, peer_data->fail_timeout,peer_data->slow_start,peer_data->set_backup > 0? "backup" : "");


		len = njt_write_fd(fd, server_info, njt_strlen(server_info));
		if (len == -1) {
			njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,
					njt_write_fd_n " write file error %V",
					&state_file);
			njt_stream_upstream_rr_peers_unlock(peers);
			goto failed;

		}
	}
	if(r->method == NJT_HTTP_POST && json_peer.domain == 1) {
		njt_memzero(server_info, 512);
		njt_snprintf(server_info, 511,
				"server %V resolve weight=%d max_conns=%d %s max_fails=%d fail_timeout=%d slow_start=%d %s;\r\n",
				&json_peer.server, json_peer.weight, json_peer.max_conns,
				json_peer.down ? "down" : "",
				json_peer.max_fails, json_peer.fail_timeout,json_peer.slow_start,json_peer.backup > 0? "backup" : "");

		len = njt_write_fd(fd, server_info, njt_strlen(server_info));
		if (len == -1) {
			njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,
					njt_write_fd_n " write file error %V",
					&state_file);
			goto failed;

		}
	}


	rc = NJT_OK;
	njt_stream_upstream_rr_peers_unlock(peers);

failed:

	if (fd != NJT_INVALID_FILE) {

		if (njt_close_file(fd) == NJT_FILE_ERROR) {
			njt_log_error(NJT_LOG_ALERT, njt_cycle->log, njt_errno,
					njt_close_file_n " \"%V\" failed", &state_file);
		}
	}

	return rc;
}

	static njt_int_t
njt_stream_upstream_api_process_delete(njt_http_request_t *r,
		void *cf,
		njt_uint_t id, njt_chain_t *out)
{
	njt_int_t                      rc;
	njt_stream_upstream_rr_peers_t   *peers, *backup, *target_peers;
	njt_stream_upstream_rr_peer_t    *peer,  *prev, *del_peer,**p;
	njt_flag_t                      del_parent = 0;
	njt_stream_upstream_api_ctx_t       *ctx;
	njt_str_t  *to_json = NULL;
	upstream_list_upstreamDef_t *upstream_one;
	njt_stream_upstream_srv_conf_t *uscf = cf;

	njt_str_t zone_name = njt_string("");

#if (NJT_STREAM_UPSTREAM_ZONE)
	if (uscf != NULL && uscf->shm_zone != NULL){
		zone_name = uscf->shm_zone->shm.name;
	}
#endif

	rc = NJT_HTTP_UPS_API_SRV_NOT_FOUND; //NJT_OK;

	del_peer = NULL;
	peers = (njt_stream_upstream_rr_peers_t *)uscf->peer.data;
	prev = peers->peer;
	p = &peers->peer;
	target_peers = peers;


	njt_stream_upstream_rr_peers_wlock(peers);
	for (peer = peers->peer; peer; ) {
		if(peer->id == id && peer->parent_id != -1)
		{
			rc = NJT_HTTP_UPS_API_SRV_NOT_REMOVALBE;
			goto out;
		}
		if ((peer->id == id && peer->parent_id == -1) || (peer->parent_id == (njt_int_t)id)) {
			del_parent = (peer->parent_id == (njt_int_t)id) ? 1:0;
			if (peer->down == 0) {
				target_peers->tries--;
			}
			if (peer->conns) {
				peer->down = 1;
				peer->del_pending = 1;
				continue;
			}

			target_peers->number--;

			target_peers->total_weight -= peer->weight;
			target_peers->single = (target_peers->number <= 1);
			//target_peers->empty = (target_peers->number == 0);
			target_peers->weighted = (target_peers->total_weight != target_peers->number);
			if (peer->down == 0) {
				target_peers->tries--;
			}
			del_peer = peer;
			*p = peer->next;
			peer = peer->next;
			/*TODO is the lock nessary?*/
			njt_shmtx_lock(&peers->shpool->mutex);
			njt_stream_upstream_del_round_robin_peer(peers->shpool, del_peer);
			njt_shmtx_unlock(&peers->shpool->mutex);

			rc = NJT_OK;
		} else {
			prev = peer;
			p = &prev->next;
			peer = peer->next;
		}
	}

	if (del_peer == NULL) {
		backup = peers->next;
		target_peers = backup;

		if (backup == NULL) {
			rc = NJT_HTTP_UPS_API_SRV_NOT_FOUND;
		} else {

			prev = backup->peer;
			p = &backup->peer;
			for (peer = backup->peer; peer; ) {

				if ((peer->id == id && peer->parent_id == -1) || (peer->parent_id == (njt_int_t)id)) {
					del_parent = (peer->parent_id == (njt_int_t)id) ? 1:0;
					if (peer->down == 0) {
						target_peers->tries--;
					}
					if (peer->conns) {
						peer->down = 1;
						peer->del_pending = 1;
						continue;
					}
					target_peers->number--;
					target_peers->total_weight -= peer->weight;
					target_peers->single = (target_peers->number <= 1);
					target_peers->weighted = (target_peers->total_weight != target_peers->number);

					del_peer = peer;
					*p = peer->next;
					peer = peer->next;
					/*TODO is the lock nessary?*/
					njt_shmtx_lock(&peers->shpool->mutex);
					njt_stream_upstream_del_round_robin_peer(peers->shpool, del_peer);
					njt_shmtx_unlock(&peers->shpool->mutex);

					rc = NJT_OK;
				} else {
					prev = peer;
					p = &prev->next;
					peer = peer->next;
				}


			}
		}
	}
	if (del_parent == 1 || del_peer == NULL) {

		for (peer = peers->parent_node; peer; peer = peer->next) {
			if(peer->parent_id == -1)
				continue;

			if (peer->id == id) {


				ctx = njt_pcalloc(r->pool, sizeof(njt_stream_upstream_api_ctx_t));
				if (ctx == NULL) {
					njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
							"upstream api ctx allocate error.");
					return NJT_HTTP_UPS_API_INTERNAL_ERROR;
				}
				ctx->resolver = uscf->resolver;
				ctx->peers = peers;
				ctx->uscf  = uscf;
				ctx->id = id;
				njt_stream_set_ctx(r, ctx, njt_http_upstream_api_module);
				peer->parent_id = -1;
				njt_stream_upstream_api_create_dynamic_server(r,peer,0);

				rc = NJT_OK;
				break;

			}
		}

	}

out:
	if (rc != NJT_OK) {
		njt_stream_upstream_rr_peers_unlock(peers);
		return rc;
	}
	peers->single = (peers->number + peers->next->number <= 1);
	peers->update_id++;	
	njt_stream_upstream_rr_peers_unlock(peers);

	/*Output the servers*/

	upstream_one = create_upstream_list_upstreamDef(r->pool);
	if (upstream_one == NULL) {
		return NJT_HTTP_UPS_API_INTERNAL_ERROR;
	}
	set_upstream_list_upstreamDef_name(upstream_one,&uscf->host);
	set_upstream_list_upstreamDef_zone(upstream_one,&zone_name);

	rc = njt_stream_upstream_api_compose_one_upstream(upstream_one,r, peers);
	if (rc != NJT_OK) {
		return rc;
	}
	to_json = to_json_upstream_list_upstreamDef(r->pool,upstream_one,OMIT_NULL_ARRAY | OMIT_NULL_OBJ | OMIT_NULL_STR);
	if(to_json){
		 rc = njt_http_upstream_api_packet_out(r,to_json,out);
	}

	return rc;

}
	static njt_int_t
njt_stream_upstream_api_process_reset(njt_http_request_t *r,
		void *cf,
		njt_chain_t *out)
{
	njt_int_t                      rc;
	njt_stream_upstream_rr_peers_t   *peers, *backup;
	njt_stream_upstream_rr_peer_t    *peer;
	njt_stream_upstream_srv_conf_t *uscf = cf;

	rc = NJT_OK;

	peers = (njt_stream_upstream_rr_peers_t *)uscf->peer.data;


	njt_stream_upstream_rr_peers_wlock(peers);
	for (peer = peers->peer; peer;peer = peer->next) {	
		peer->requests = 0;
		peer->total_fails = 0;
		peer->hc_checks = 0;
		peer->hc_fails = 0;
		peer->hc_downtime = 0;
		peer->hc_downstart = 0;
		peer->hc_last_passed = 0;
		peer->sent = 0;
		peer->received = 0;
		peer->selected_time = 0;
		peer->unavail = 0;
		peer->fails = 0;
	}
	backup = peers->next;

	if (backup) {

		for (peer = backup->peer; peer; peer = peer->next) {
			peer->hc_downtime = 0;
			peer->hc_downstart = 0;
			peer->requests = 0;
			peer->hc_checks = 0;
			peer->hc_fails = 0;
			peer->hc_last_passed = 0;
			peer->sent = 0;
			peer->received = 0;
			peer->selected_time = 0;
			peer->total_fails = 0;
			peer->unavail = 0;
			peer->fails = 0;
		}
	}

	if (rc != NJT_OK) {
		njt_stream_upstream_rr_peers_unlock(peers);
		return rc;
	}

	njt_stream_upstream_rr_peers_unlock(peers);

	/*Output the servers*/
	rc = NJT_HTTP_UPS_API_RESET; 
	return rc;

}

	static njt_int_t
njt_stream_upstream_api_process_post(njt_http_request_t *r,
		void *cf)
{
	njt_int_t                          rc;
	njt_stream_upstream_rr_peers_t       *peers;
	njt_stream_upstream_api_ctx_t       *ctx;
	njt_stream_upstream_srv_conf_t *uscf = cf;


	peers = (njt_stream_upstream_rr_peers_t *)uscf->peer.data;

	ctx = njt_pcalloc(r->pool, sizeof(njt_stream_upstream_api_ctx_t));
	if (ctx == NULL) {
		njt_http_discard_request_body(r);
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
				"upstream api ctx allocate error.");
		return NJT_HTTP_INTERNAL_SERVER_ERROR;
	}

	ctx->peers = peers;
	ctx->uscf  = uscf;
	ctx->resolver = uscf->resolver;
	ctx->hc_type  = (uscf->hc_type == 0 ?0:2);
	njt_http_set_ctx(r, ctx, njt_http_upstream_api_module);

	rc = njt_http_read_client_request_body(r, njt_stream_upstream_api_post);

	if (rc >= NJT_HTTP_SPECIAL_RESPONSE) {
		/* error */
		return rc;
	}
	return NJT_DONE;
}

	static void
njt_stream_upstream_api_post(njt_http_request_t *r)
{
	u_char						       *last,*port;
	njt_stream_upstream_rr_peers_t       *peers, *backup, *target_peers;
	njt_slab_pool_t                    *shpool;
	njt_stream_upstream_api_ctx_t       *ctx;
	upstream_api_t                     *json_body;
	njt_str_t                          json_str;
	njt_http_upstream_api_main_conf_t *uclcf;
	njt_chain_t                        *body_chain;
	njt_chain_t                        out;
	njt_int_t                          rc;
	njt_int_t                          parent_id;
	
	ssize_t                            len;
	njt_stream_upstream_rr_peer_t        *peer,*tail_peer;
	njt_stream_upstream_rr_peer_t         new_peer;
	//njt_http_upstream_api_peer_t      json_peer;
	njt_url_t                          u;
	njt_str_t                          name, server;
	njt_str_t                          *peers_name;
	server_list_serverDef_t         *server_one = NULL; 
	njt_str_t                          *to_json = NULL;
	njt_stream_upstream_srv_conf_t  *uscf;
	
	js2c_parse_error_t                 err_code;
	
	
	ctx = njt_http_get_module_ctx(r, njt_http_upstream_api_module);
	
	rc = NJT_OK;
	peer = NULL;
	body_chain = r->request_body->bufs;
	if (body_chain && body_chain->next) {
		/*The post body is too large*/
		rc = NJT_HTTP_UPS_API_TOO_LARGE_BODY;
		goto out;
	}

	peers = ctx->peers;
	out.next = NULL;
	out.buf = NULL;

	rc = njt_http_util_read_request_body(r, &json_str, MIN_UPSTREAM_API_BODY_LEN, MAX_UPSTREAM_API_BODY_LEN);
	if(rc == NJT_ERROR) {
		rc = NJT_HTTP_UPS_API_INVALID_JSON_PARSE;
		goto out;
	}

	json_body = json_parse_upstream_api(r->pool,  &json_str, &err_code);
	if (json_body == NULL) {
		rc = NJT_HTTP_UPS_API_INVALID_JSON_PARSE;
		json_peer.msg = err_code.err_str;
		goto out;
	}

	/*conduct the perform*/
	njt_memzero(&json_peer, sizeof(njt_http_upstream_api_peer_t));

	/*initialize the jason peer. Other items other than the following are all zero*/
	json_peer.weight = 1*NJT_WEIGHT_POWER;
	json_peer.max_fails = 1;
	json_peer.fail_timeout = 10;
	json_peer.drain = -1;
	rc = njt_http_upstream_api_json_2_peer(json_body, &json_peer, 1,r,1);

	if (rc != NJT_OK) {
		//rc = NJT_HTTP_UPS_API_INVALID_JSON_PARSE;
		goto out;
	}

	uscf = ctx->uscf;
	if(json_peer.backup == 1 && uscf != NULL && (!(uscf->flags & NJT_STREAM_UPSTREAM_BACKUP))) {
		rc = NJT_HTTP_UPS_API_HAS_NO_BACKUP;
		goto out;
	}


	if(json_peer.route.data != NULL) {
		njt_str_set(&json_peer.msg,
				"route");
		rc = NJT_HTTP_UPS_API_INVALID_JSON_BODY	;
		goto out;
	}
	/*perform the insert*/
	shpool = peers->shpool;

	njt_memzero(&u, sizeof(njt_url_t));





	u.url.data = njt_pcalloc(r->pool, json_peer.server.len + 1);

	if (u.url.data == NULL) {
		rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "url data allocate error.");
		goto out;
	}
	njt_cpystrn(u.url.data, json_peer.server.data, json_peer.server.len + 1);
	u.url.len = json_peer.server.len;
	u.default_port = 80;

	if (njt_parse_url(r->pool, &u) != NJT_OK) {

		rc = NJT_HTTP_UPS_API_NOT_SUPPORTED_SRV;
		if (u.err) {
			njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
					"api post stream domain: \"%V\"",&u.url);
		}
		//goto out;
	}



	njt_stream_upstream_rr_peers_wlock(peers);
	njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0,
			"njt_http_upstream_api_post!");



	json_peer.domain = 0;  //ip
	parent_id = -1;
	if(u.naddrs == 1 && json_peer.server.len <= u.addrs[0].name.len && njt_strncmp(json_peer.server.data,u.addrs[0].name.data,json_peer.server.len) == 0){
		parent_id = -1;
		json_peer.domain = 0;  //ip
	} else {
		uclcf = njt_http_cycle_get_module_main_conf(njt_cycle, njt_http_upstream_api_module);
		if(uclcf && (uclcf->shm_zone_stream == NULL || ctx->resolver == NULL)) {
			rc = NJT_HTTP_UPS_API_NO_RESOLVER;
			njt_stream_upstream_rr_peers_unlock(peers);
			goto out;
		}
		if(ctx->resolver != NULL) {
			parent_id = (njt_int_t)peers->next_order++;
			json_peer.domain = 1;  //domain name
		}

	}
	last = json_peer.server.data + json_peer.server.len;
	port = njt_strlchr(json_peer.server.data, last, ':');
	if(port == NULL) {
		njt_stream_upstream_rr_peers_unlock(peers);
		json_peer.msg = json_peer.server;
		rc = NJT_HTTP_UPS_API_NO_SRV_PORT;
		goto out;
	}


	/////////////////////////////////////////////////////////////
	if(parent_id != -1)  {
		njt_stream_upstream_rr_peers_unlock(peers);

		server.data = njt_pcalloc(r->pool, json_peer.server.len + 1);
		njt_cpystrn(server.data, json_peer.server.data, json_peer.server.len + 1);
		server.len = json_peer.server.len;
		new_peer.server = server;
		new_peer.id = parent_id;
		new_peer.parent_id = parent_id;
		new_peer.weight = json_peer.weight;
		new_peer.effective_weight = json_peer.weight;
		new_peer.current_weight = 0;
		new_peer.max_fails = json_peer.max_fails;
		new_peer.max_conns = json_peer.max_conns;
		new_peer.fail_timeout = json_peer.fail_timeout;
		new_peer.down = json_peer.down;
		new_peer.slow_start = json_peer.slow_start;
		new_peer.name = server;
		new_peer.hc_down  = ctx->hc_type;
		if(json_peer.drain == 1) {  //post not drain
			//new_peer.hc_down  = 100 + new_peer.hc_down;
		}

		njt_stream_upstream_api_create_dynamic_server(r,&new_peer,json_peer.backup);
		njt_stream_upstream_api_compose_one_server(r, peers,&new_peer,json_peer.backup,new_peer.id,&server_one);  //����
		
		rc = NJT_OK;

	} else if (parent_id == -1) {

		peer = njt_slab_calloc_locked(shpool, sizeof(njt_stream_upstream_rr_peer_t));

		if (peer == NULL) {

			rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
			njt_stream_upstream_rr_peers_unlock(peers);
			njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "peer allocate error.");

			goto out;
		}

		server.data = njt_slab_calloc_locked(shpool, json_peer.server.len + 1);
		if (server.data == NULL) {

			rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
			njt_stream_upstream_rr_peers_unlock(peers);
			njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "server data allocate error.");

			goto out;
		}

		njt_cpystrn(server.data, json_peer.server.data, json_peer.server.len + 1);
		server.len = json_peer.server.len;
		peer->server = server;

		name.data = njt_slab_calloc_locked(shpool, u.addrs[0].name.len + 1);
		if (name.data == NULL) {

			rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
			njt_stream_upstream_rr_peers_unlock(peers);
			njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
					"name data allocate error.");

			goto out;
		}

		njt_cpystrn(name.data, u.addrs[0].name.data, u.addrs[0].name.len + 1);
		name.len = u.addrs[0].name.len;
		peer->name = name;

		peer->socklen = u.addrs[0].socklen;
		peer->sockaddr = njt_slab_calloc_locked(shpool, peer->socklen + 1);
		if (peer->sockaddr == NULL) {

			rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
			njt_stream_upstream_rr_peers_unlock(peers);
			njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
					"peer sockaddr allocate error.");
			goto out;
		}

		njt_memcpy(peer->sockaddr, u.addrs[0].sockaddr, peer->socklen);

		peer->id = peers->next_order++;
		
		peer->parent_id = parent_id;
		peer->hc_upstart =  njt_time(); //post
		peer->weight = json_peer.weight;
		peer->effective_weight = json_peer.weight;
		peer->current_weight = 0;
		peer->max_fails = json_peer.max_fails;
		peer->max_conns = json_peer.max_conns;
		peer->fail_timeout = json_peer.fail_timeout;
		peer->down = json_peer.down;
		peer->down = json_peer.down;
		peer->slow_start = json_peer.slow_start;
		peer->hc_down  = ctx->hc_type;
		if(json_peer.drain == 1) {  //post //post not drain
			//peer->hc_down  = 100 + peer->hc_down;
		}
		target_peers = peers;

		/*insert into the right peer list according to the backup value*/
		if (json_peer.backup) {

			backup = peers->next;
			if (backup == NULL) {

				backup = njt_slab_calloc(peers->shpool, sizeof(njt_stream_upstream_rr_peers_t));
				if (backup == NULL) {
					rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
					njt_stream_upstream_rr_peers_unlock(peers);
					njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
							"backup peers allocate error.");

					goto out;
				}

				peers_name = njt_slab_calloc(peers->shpool, sizeof(njt_str_t));
				if (peers_name == NULL) {
					rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
					njt_stream_upstream_rr_peers_unlock(peers);
					njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
							"peers_name allocate error.");

					goto out;
				}

				peers_name->data = njt_slab_calloc(peers->shpool, peers->name->len);
				if (peers_name->data == NULL) {
					rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
					njt_stream_upstream_rr_peers_unlock(peers);
					njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
							"peers_name data allocate error.");

					goto out;
				}

				njt_memcpy(peers_name->data, peers->name->data, peers->name->len);
				peers_name->len = peers->name->len;

				backup->name = peers_name;
				peers->next = backup;
			}

			target_peers = backup;
		}

		if (target_peers->peer) {
			//peer->next = target_peers->peer;
			//target_peers->peer = peer;

			for(tail_peer = target_peers->peer;tail_peer->next != NULL; tail_peer = tail_peer->next);
			tail_peer->next = peer;

		} else {
			target_peers->peer = peer;
		}
		target_peers->number++;
		target_peers->total_weight += peer->weight;
		target_peers->weighted = (target_peers->total_weight != target_peers->number);

		if (peer->down == 0) {
			peers->tries ++;
		}

		target_peers->single = (target_peers->number <= 1);
		peers->single = (peers->number + peers->next->number <= 1);
		peers->update_id++;	
		
		njt_stream_upstream_api_compose_one_server(r, peers,peer,json_peer.backup,peer->id,&server_one);  //����
		njt_stream_upstream_rr_peers_unlock(peers);
	}


out:
	if (rc != NJT_OK) {

		/* free the allocated memory*/
		if (peer) {
			njt_shmtx_lock(&peers->shpool->mutex);
			njt_stream_upstream_del_round_robin_peer(peers->shpool, peer);  //njt_http_upstream_free_peer_memory  todo  zyg
			njt_shmtx_unlock(&peers->shpool->mutex);
		}

		rc = njt_http_upstream_api_err_out(r, rc,&json_peer.msg, &out);
		if (rc != NJT_OK) {
			goto error;
		}

		goto send;
	}
	r->headers_out.status = NJT_HTTP_CREATED;
	
	if(server_one) {
		to_json = to_json_one_serverDef(r->pool,server_one,OMIT_NULL_ARRAY | OMIT_NULL_OBJ | OMIT_NULL_STR);
		rc = njt_http_upstream_api_packet_out(r,to_json,&out);
		if(rc != NJT_OK) {
			goto error;
		}
	}

send:
	r->headers_out.content_type_len = sizeof("text/plain") - 1;
	njt_str_set(&r->headers_out.content_type, "text/plain");
	r->headers_out.content_type_lowcase = NULL;
	len = njt_http_upstream_api_out_len(&out);
	r->headers_out.content_length_n = len;

	if (r->headers_out.content_length) {
		r->headers_out.content_length->hash = 0;
		r->headers_out.content_length = NULL;
	}

	rc = njt_http_send_header(r);
	if (rc == NJT_ERROR || rc > NJT_OK || r->header_only) {
		njt_http_finalize_request(r, rc);
		return;
	}

	rc = njt_http_output_filter(r, &out);
	njt_http_finalize_request(r, rc);
	return;

error:
	njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
	return;
}

	static upstream_list_peerDef_t *
njt_stream_upstream_api_compose_one_detail_server(njt_http_request_t *r,
		njt_stream_upstream_rr_peer_t *peer,
		njt_flag_t backup, njt_flag_t is_parent,njt_str_t upstream_name)
{

	njt_str_t                      *pname,data;
	njt_uint_t                      id,down_time;

	njt_str_t                     buf;
	njt_str_t                     timebuf;



	buf.len = 256;
	buf.data = njt_pcalloc(r->pool,buf.len);

	timebuf.len = 128;
	timebuf.data = njt_pcalloc(r->pool,timebuf.len);

	upstream_list_peerDef_health_checks_t* health_checks = create_upstream_list_peerDef_health_checks(r->pool); //upstream_list_peerDef_health_checks_t* create_upstream_list_peerDef_health_checks(njt_pool_t *pool);
	upstream_list_peerDef_responses_t* responses = create_upstream_list_peerDef_responses(r->pool);  //upstream_list_peerDef_responses_t* create_upstream_list_peerDef_responses(njt_pool_t *pool);
	upstream_list_peerDef_t* peerDef = create_upstream_list_peerDef(r->pool);   //upstream_list_peerDef_t* create_upstream_list_peerDef(njt_pool_t *pool)
	if(peerDef == NULL || responses == NULL || health_checks == NULL){
		return NULL;
	}
	pname = (is_parent == 1?(&peer->server):(&peer->name));
	id =  (is_parent == 1?((njt_uint_t)peer->parent_id):(peer->id));
	if(peer->hc_downstart != 0) {

		down_time =  ((njt_uint_t)((njt_timeofday())->sec )*1000 + (njt_uint_t)((njt_timeofday())->msec) ) -  peer->hc_downstart + peer->hc_downtime;
		buf.len = njt_format_time(buf.data,peer->hc_downstart) - buf.data;
		set_upstream_list_peerDef_downstart(peerDef, &buf);
	} else {
		down_time = peer->hc_downtime;
		id = peer->id;
		pname = &peer->name;

	}
	if(peer->selected_time != 0) {
		timebuf.len = njt_format_time(timebuf.data,peer->selected_time) - timebuf.data;
		set_upstream_list_peerDef_selected(peerDef, &timebuf);

	}
	set_upstream_list_peerDef_id(peerDef, id);


	njt_str_copy_pool(r->pool,data,(*pname), return NULL;);
	set_upstream_list_peerDef_server(peerDef, &data);

	njt_str_copy_pool(r->pool,data,peer->server, return NULL;);
	set_upstream_list_peerDef_name(peerDef, &data);

	set_upstream_list_peerDef_backup(peerDef, backup);
	set_upstream_list_peerDef_weight(peerDef, peer->weight);
	set_upstream_list_peerDef_state(peerDef, njt_get_peer_status_name(peer));
	set_upstream_list_peerDef_active(peerDef, peer->conns);
	if( peer->max_conns != 0) {
		set_upstream_list_peerDef_max_conns(peerDef,peer->max_conns);
	}
	set_upstream_list_peerDef_connections(peerDef, peer->requests);

	if( peer->requests != 0) {
		set_upstream_list_peerDef_connect_time(peerDef, peer->total_connect_time/peer->requests);
		set_upstream_list_peerDef_first_byte_time(peerDef, peer->total_first_byte_time/peer->requests);
		set_upstream_list_peerDef_response_time(peerDef, peer->total_response_time/peer->requests);
	}





	set_upstream_list_peerDef_sent(peerDef, 0);
	set_upstream_list_peerDef_received(peerDef, 0);

	set_upstream_list_peerDef_fails(peerDef, peer->total_fails);
	set_upstream_list_peerDef_unavail(peerDef, peer->unavail);


	set_upstream_list_peerDef_health_checks_checks(health_checks,peer->hc_checks);
	set_upstream_list_peerDef_health_checks_fails(health_checks,peer->hc_fails);
	set_upstream_list_peerDef_health_checks_unhealthy(health_checks,peer->hc_unhealthy);
	if(peer->hc_checks != 0) {
		set_upstream_list_peerDef_health_checks_last_passed(health_checks,peer->hc_last_passed);
	}

	set_upstream_list_peerDef_downtime(peerDef, down_time);
	set_upstream_list_peerDef_health_checks(peerDef,health_checks);





	return peerDef;
}
	static server_list_serverDef_t *
njt_stream_upstream_api_compose_one_server_schemo(njt_http_request_t *r,
		njt_stream_upstream_rr_peer_t *peer,
		njt_flag_t backup, njt_flag_t is_parent,njt_str_t upstream_name)
{
	njt_str_t                      *pname,data;
	njt_uint_t                      id;
	u_char                    *p;

	njt_str_t                     slow_str,fail_timeout;

	slow_str.len = NJT_INT64_LEN + 1;
	slow_str.data = njt_pcalloc(r->pool,slow_str.len);

	fail_timeout.len = NJT_INT64_LEN + 1;
	fail_timeout.data = njt_pcalloc(r->pool,fail_timeout.len);

	server_list_serverDef_t* server_one = create_server_list_serverDef(r->pool);
	if(server_one == NULL || slow_str.data == NULL || fail_timeout.data == NULL) {
		return NULL;
	}





	p = njt_snprintf(slow_str.data, slow_str.len,"%ds",peer->slow_start);	
	slow_str.len = p - slow_str.data;

	p = njt_snprintf(fail_timeout.data, fail_timeout.len,"%ds",peer->fail_timeout);	
	fail_timeout.len = p - fail_timeout.data;


	if(peer->parent_id >= 0 && is_parent == 0) {
		id =  peer->id;
		pname = &peer->name;
		set_server_list_serverDef_parent(server_one,peer->parent_id);
		set_server_list_serverDef_host(server_one,&peer->server);

	} else {
		pname = (is_parent == 1?(&peer->server):(&peer->name));
		id =  peer->id;
	}
	njt_str_copy_pool(r->pool,data,(*pname), return NULL;);	

	set_server_list_serverDef_id(server_one, id);
	set_server_list_serverDef_server(server_one, &data);
	set_server_list_serverDef_weight(server_one, peer->weight);
	set_server_list_serverDef_max_conns(server_one,peer->max_conns);
	set_server_list_serverDef_max_fails(server_one,peer->max_fails);
	set_server_list_serverDef_fail_timeout(server_one,&fail_timeout);
	set_server_list_serverDef_slow_start(server_one,&slow_str);
	set_server_list_serverDef_backup(server_one,(backup ? true : false));
	set_server_list_serverDef_down(server_one,(peer->down == 1 ? true : false));
	if(peer->hc_down/100 == 1) {
		set_server_list_serverDef_drain(server_one,true);
	}

	return server_one;
}

	static njt_int_t
njt_stream_upstream_api_compose_all_server(njt_http_request_t *r,
		void *p,server_list_t                   *server_list)
{
	njt_stream_upstream_rr_peer_t    *peer,*peer_node;

	njt_stream_upstream_rr_peers_t   *backup;

	njt_stream_upstream_rr_peers_t *peers = p;

	server_list_serverDef_t       *peerDef; 


	njt_stream_upstream_rr_peers_rlock(peers);

	for (peer = peers->peer; peer != NULL; peer = peer->next) {


		peerDef = njt_stream_upstream_api_compose_one_server_schemo(r, peer,0,(peer->id == (njt_uint_t)peer->parent_id ?1:0),*peers->name);

		if (peerDef == NULL) {
			njt_stream_upstream_rr_peers_unlock(peers);
			return NJT_ERROR;
		}
		add_item_server_list(server_list,peerDef);

	}

	backup = peers->next;
	if (backup != NULL) {
		for (peer = backup->peer; peer != NULL; peer = peer->next) {

			peerDef = njt_stream_upstream_api_compose_one_server_schemo(r, peer,1,(peer->id == (njt_uint_t)peer->parent_id ?1:0),*peers->name);

			if (peerDef == NULL) {
				njt_stream_upstream_rr_peers_unlock(peers);
				return NJT_ERROR;
			}
			add_item_server_list(server_list,peerDef);

		}
	}
	//������ڵ㡣
	for (peer = peers->parent_node; peer != NULL; peer = peer->next) {

		if(peer->parent_id == -1)
			continue;
		peer_node = peer;
		peerDef = njt_stream_upstream_api_compose_one_server_schemo(r, peer_node,peer_node->set_backup,(peer_node->id == (njt_uint_t)peer_node->parent_id ?1:0),*peers->name);


		if (peerDef == NULL) {
			njt_stream_upstream_rr_peers_unlock(peers);
			return NJT_ERROR;
		}
		add_item_server_list(server_list,peerDef);

	}



	njt_stream_upstream_rr_peers_unlock(peers);

	return NJT_OK;
}
	static njt_int_t
njt_stream_upstream_api_compose_one_server(njt_http_request_t *r,
		void *p,njt_stream_upstream_rr_peer_t      *peer, njt_flag_t is_backup,ssize_t id,server_list_serverDef_t                    **server_one)
{

	
	njt_stream_upstream_rr_peers_t   *backup;

	njt_stream_upstream_rr_peers_t *peers = p;
	
	if (id < 0) {
		return NJT_HTTP_UPS_API_INTERNAL_ERROR;  
	}

	if(peer != NULL) {  //����
		*server_one = njt_stream_upstream_api_compose_one_server_schemo(r, peer,is_backup,(peer->id == (njt_uint_t)peer->parent_id ?1:0),*peers->name);
		if(*server_one == NULL) {
			return NJT_HTTP_UPS_API_INTERNAL_ERROR;
		}
		return NJT_OK;
	}
	njt_stream_upstream_rr_peers_rlock(peers);

	for (peer = peers->peer; peer != NULL; peer = peer->next) {

		/*only compose one server*/
		if (id >= 0) {
			if (peer->id == (njt_uint_t)id) {

				njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "find the server %ui",
						id);
				
				*server_one = njt_stream_upstream_api_compose_one_server_schemo(r, peer, 0,(peer->id == (njt_uint_t)peer->parent_id ?1:0),*peers->name);
				njt_stream_upstream_rr_peers_unlock(peers);
				if(*server_one == NULL) {
					return NJT_HTTP_UPS_API_INTERNAL_ERROR;
				}
				return NJT_OK;
			}

			continue;
		}
	}

	backup = peers->next;
	if (backup != NULL) {
		for (peer = backup->peer; peer != NULL; peer = peer->next) {

			/*only compose one server*/
			if (id >= 0) {
				if (peer->id == (njt_uint_t)id ) {
					njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
							"find the backup server %ui", id);

					
					*server_one = njt_stream_upstream_api_compose_one_server_schemo(r, peer, 1,(peer->id == (njt_uint_t)peer->parent_id ?1:0),*peers->name);
					njt_stream_upstream_rr_peers_unlock(peers);
					if(*server_one == NULL) {
						return NJT_HTTP_UPS_API_INTERNAL_ERROR;
					}
					return NJT_OK;
				}
				continue;
			}
		}
	}
	//������ڵ㡣
	for (peer = peers->parent_node; peer != NULL; peer = peer->next) {

		if(peer->parent_id == -1)
			continue;
		
		/*only compose one server*/
		if (id >= 0) {
			if (peer->id == (njt_uint_t)id || peer->parent_id == (njt_int_t)id) {
				njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
						"find the backup server %ui", id);


				*server_one = njt_stream_upstream_api_compose_one_server_schemo(r, peer,peer->set_backup,(peer->id == (njt_uint_t)peer->parent_id ?1:0),*peers->name);
				njt_stream_upstream_rr_peers_unlock(peers);
				if(*server_one == NULL) {
					return NJT_HTTP_UPS_API_INTERNAL_ERROR;
				}
				return NJT_OK;
			}
			continue;
		}
	}



	njt_stream_upstream_rr_peers_unlock(peers);


	return NJT_HTTP_UPS_API_SRV_NOT_FOUND;
}




	static njt_int_t
njt_stream_upstream_api_process_get(njt_http_request_t *r,
		void *cf,
		ssize_t server_id, njt_flag_t detailed, njt_chain_t *out)
{
	njt_int_t                       rc;
	njt_uint_t                      i;
	njt_stream_upstream_srv_conf_t   *uscf, **uscfp;
	njt_stream_upstream_main_conf_t  *umcf;


	njt_stream_upstream_rr_peers_t   *peers;
	njt_stream_upstream_srv_conf_t *target_uscf = cf;
	njt_str_t                       zone_name = njt_string("");
	upstream_list_t                 *upstream_list = NULL;  
	upstream_list_upstreamDef_t     *upstream_one;
	server_list_serverDef_t         *server_one = NULL;  
	server_list_t                   *server_list = NULL; 
	njt_str_t                       *to_json = NULL;

	rc = NJT_OK;
	umcf = njt_stream_cycle_get_module_main_conf(njet_master_cycle, njt_stream_upstream_module);
	if(umcf == NULL) {
		rc = NJT_HTTP_UPS_API_PATH_NOT_FOUND;
		return rc;
	}
#if (NJT_HTTP_UPSTREAM_ZONE)
	if (target_uscf != NULL) {
		zone_name = target_uscf->host;
	}
#endif
	/*get a specific upstream's server inforamtion*/
	if (target_uscf != NULL) {
		peers = (njt_stream_upstream_rr_peers_t *)target_uscf->peer.data;
		if(detailed == 1) {
			upstream_one = create_upstream_list_upstreamDef(r->pool);
			if (upstream_one == NULL) {
				return NJT_HTTP_UPS_API_INTERNAL_ERROR;
			}
			set_upstream_list_upstreamDef_name(upstream_one,&target_uscf->host);
			set_upstream_list_upstreamDef_zone(upstream_one,&zone_name);	

			rc = njt_stream_upstream_api_compose_one_upstream(upstream_one,r, peers); //njt_stream_upstream_api_compose_one_upstream
			if (rc != NJT_OK) {
				return rc;
			}
			to_json = to_json_upstream_list_upstreamDef(r->pool,upstream_one,OMIT_NULL_ARRAY | OMIT_NULL_OBJ | OMIT_NULL_STR);



		} else {
			if(server_id >= 0) {
				rc = njt_stream_upstream_api_compose_one_server(r, peers, NULL,0,server_id,&server_one);  //������ʾ��
				if (server_one == NULL) {
					return rc;
				}
				
				
				to_json = to_json_one_serverDef(r->pool,server_one,OMIT_NULL_ARRAY | OMIT_NULL_OBJ | OMIT_NULL_STR);

			} else {
				server_list = create_server_list(r->pool,1);
				rc = njt_stream_upstream_api_compose_all_server( r, peers,server_list);
				if (rc != NJT_OK) {
					return rc;
				}
				to_json = to_json_one_server_list(r->pool,server_list,OMIT_NULL_ARRAY | OMIT_NULL_OBJ | OMIT_NULL_STR);

			}
		}
		rc = njt_http_upstream_api_packet_out(r,to_json,out);

		return rc;
	}

	/*get all the upstreams' server information*/

	uscfp = umcf->upstreams.elts;

	upstream_list =  create_upstream_list(r->pool,umcf->upstreams.nelts);
	if(upstream_list == NULL) {
		return  NJT_HTTP_UPS_API_INTERNAL_ERROR;
	}

	for (i = 0; i < umcf->upstreams.nelts; i++) {

		uscf = uscfp[i];
#if (NJT_HTTP_UPSTREAM_ZONE)
		if (uscf == NULL || uscf->shm_zone == NULL)
			continue;
		zone_name = uscf->shm_zone->shm.name;
#endif
		peers = (njt_stream_upstream_rr_peers_t *)uscf->peer.data;

		upstream_one = create_upstream_list_upstreamDef(r->pool);
		if (upstream_one == NULL) {
			return NJT_HTTP_UPS_API_INTERNAL_ERROR;
		}
		add_item_upstream_list(upstream_list,upstream_one);
		set_upstream_list_upstreamDef_name(upstream_one,&uscf->host);
		set_upstream_list_upstreamDef_zone(upstream_one,&zone_name);	


		rc = njt_stream_upstream_api_compose_one_upstream(upstream_one,r, peers);
		if (rc != NJT_OK) {
			return rc;
		}
	}
	to_json = to_json_upstream_list(r->pool,upstream_list,OMIT_NULL_ARRAY | OMIT_NULL_OBJ | OMIT_NULL_STR);
	if(to_json){
		 rc = njt_http_upstream_api_packet_out(r,to_json,out);
	}
	return rc;
}
	static void
njt_stream_upstream_api_patch(njt_http_request_t *r)
{

	njt_stream_upstream_rr_peers_t     *peers, *backup, *target_peers;
	njt_stream_upstream_api_ctx_t      *ctx;
	upstream_api_t                     *json_body;
	njt_str_t                          json_str;
	//njt_chain_t                      *body_chain;
	njt_chain_t                        out;
	njt_int_t                          rc,pre_rc;
	ssize_t                            len;
	njt_url_t                          u;
	njt_stream_upstream_rr_peer_t      *peer;// *prev;
	njt_uint_t                         server_id;
	//njt_str_t                        server;
	u_char                             *port,*last;
	js2c_parse_error_t                 err_code;
	njt_flag_t                         is_backup;
	server_list_serverDef_t            *server_one = NULL;  
	njt_str_t                          *to_json = NULL;





	ctx = njt_stream_get_module_ctx(r, njt_http_upstream_api_module);
	peers = ctx->peers;

	rc = NJT_OK;
	pre_rc = NJT_OK;

	out.next = NULL;
	out.buf = NULL;

	rc = njt_http_util_read_request_body(r, &json_str, MIN_UPSTREAM_API_BODY_LEN, MAX_UPSTREAM_API_BODY_LEN);
	if(rc == NJT_ERROR) {
		rc = NJT_HTTP_UPS_API_INVALID_JSON_PARSE;
		goto out;
	}


	json_body = json_parse_upstream_api(r->pool,  &json_str, &err_code);
	if (json_body == NULL) {
		rc = NJT_HTTP_UPS_API_INVALID_JSON_PARSE;
		json_peer.msg = err_code.err_str;
		goto out;
	}

	/*conduct the perform*/
	njt_memzero(&json_peer, sizeof(njt_http_upstream_api_peer_t));

	json_peer.weight = -1;
	json_peer.max_fails = -1;
	json_peer.fail_timeout = -1;
	json_peer.max_conns = -1;
	json_peer.backup = -1;
	json_peer.down = -1;
	json_peer.slow_start = -1;
	json_peer.drain = -1;
	njt_str_null(&json_peer.route);
	njt_str_null(&json_peer.server);

	/*initialize the jason peer. Other items other than the following are all zero*/
	rc = njt_http_upstream_api_json_2_peer(json_body, &json_peer, 0,r,1);
	if (rc != NJT_OK) {
		//rc = NJT_HTTP_UPS_API_INVALID_JSON_PARSE;
		goto out;
	}

	if(json_peer.route.data != NULL) {
		njt_str_set(&json_peer.msg,
				"route");
		rc = NJT_HTTP_UPS_API_INVALID_JSON_BODY	;
		goto out;
	}

	/*perform the insert*/
	server_id = ctx->id;
	if (json_peer.server.len  > 0) {
		njt_memzero(&u, sizeof(njt_url_t));
		u.url.data = njt_pcalloc(r->pool, json_peer.server.len + 1);

		if (u.url.data == NULL) {

			rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;

			njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "url data allocate error.");
			goto out;
		}

		njt_cpystrn(u.url.data, json_peer.server.data, json_peer.server.len + 1);
		u.url.len = json_peer.server.len;
		u.default_port = 80;

		if (njt_parse_url(r->pool, &u) != NJT_OK) {
			//rc = NJT_HTTP_UPS_API_INVALID_SRV_ARG;
			//if (u.err) {
			//	njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
			//				  "%s in upstream \"%V\"", u.err, &u.url);
			//}
			//goto out;
		}
		if(u.naddrs == 1 && json_peer.server.len <= u.addrs[0].name.len && njt_strncmp(json_peer.server.data,u.addrs[0].name.data,json_peer.server.len) == 0){
			json_peer.domain = 0;  //ip
		} else {
			json_peer.domain = 1;  //domain name
		}

		if(json_peer.domain == 1) {
			pre_rc = NJT_HTTP_UPS_API_INVALID_SRV_ARG;
			//goto out;
		} else {
			last = json_peer.server.data + json_peer.server.len;
			port = njt_strlchr(json_peer.server.data, last, ':');
			if(port == NULL) {
				json_peer.msg = json_peer.server;
				rc = NJT_HTTP_UPS_API_NO_SRV_PORT;
				goto out;
			}
		}
	}

	njt_stream_upstream_rr_peers_wlock(peers);
	target_peers = peers;
	is_backup = 0;
	for (peer = peers->peer; peer != NULL;  peer = peer->next) {
		if (peer->id == (njt_uint_t)server_id ) {
			njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "find the server %ui",
					server_id);

			break;
		} 
	}
	backup = peers->next;  
	if (peer == NULL && backup) {
		target_peers = backup;
		is_backup = 1;
		for (peer = backup->peer; peer;  peer = peer->next) {
			if (peer->id == (njt_uint_t)server_id) {
				njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
						"find the backup server %ui", server_id);
				break;
			}
		}
	} 
	if(peer == NULL) {
		for (peer = peers->parent_node; peer;  peer = peer->next) {

			if (peer->id == server_id && peer->parent_id == (njt_int_t)server_id) {
				is_backup = peer->set_backup;
				break;
			}
		}
	}
	if (peer == NULL) {

		rc = NJT_HTTP_UPS_API_SRV_NOT_FOUND;
		njt_stream_upstream_rr_peers_unlock(peers);
		goto out;
	}

	if(peer->parent_id != -1 && json_peer.server.len > 0) {
		njt_stream_upstream_rr_peers_unlock(peers);
		rc = NJT_HTTP_UPS_API_NOT_MODIFY_SRV_NAME;
		goto out;
	}
	if(pre_rc != NJT_OK) {
		njt_stream_upstream_rr_peers_unlock(peers);
		rc = pre_rc;
		goto out;
	}

	if (json_peer.max_fails != -1) {
		peer->max_fails = json_peer.max_fails;
	}

	if (json_peer.max_conns != -1) {
		peer->max_conns = json_peer.max_conns;
	}

	if (json_peer.fail_timeout != -1) {
		peer->fail_timeout = json_peer.fail_timeout;
	}
	if (json_peer.slow_start != -1) {  //zyg
		peer->slow_start = json_peer.slow_start;
		peer->hc_upstart =  njt_time(); //patch
	}

	if(json_peer.drain == 1) { //patch
		peer->hc_down  = 100 + peer->hc_down;
	} 

	if (json_peer.server.len  > 0 && u.naddrs > 0) {
		if(peer->server.len < json_peer.server.len) {
			njt_slab_free_locked(peers->shpool,peer->server.data);
			peer->server.data = njt_slab_calloc_locked(peers->shpool, json_peer.server.len);
			if (peer->server.data == NULL) {
				njt_stream_upstream_rr_peers_unlock(peers);
				goto error;
			}
		}

		if(peer->socklen < u.addrs[0].socklen) {
			njt_slab_free_locked(peers->shpool, peer->sockaddr);
		}
		peer->socklen = u.addrs[0].socklen;
		peer->sockaddr = njt_slab_calloc_locked(peers->shpool, peer->socklen + 1);
		if (peer->sockaddr == NULL) {

			rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
			njt_stream_upstream_rr_peers_unlock(peers);
			njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
					"peer sockaddr allocate error.");
			goto out;
		}
		peer->name.data = njt_slab_calloc_locked(peers->shpool, u.addrs->name.len + 1);
		if (peer->name.data == NULL) {

			rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
			njt_stream_upstream_rr_peers_unlock(peers);
			njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
					"name data allocate error.");

			goto out;
		}

		njt_cpystrn(peer->name.data, u.addrs->name.data, u.addrs->name.len + 1);
		peer->name.len = u.addrs->name.len;



		njt_memcpy(peer->sockaddr, u.addrs[0].sockaddr, peer->socklen);
		njt_memcpy(peer->server.data, json_peer.server.data,json_peer.server.len);
		peer->server.len = json_peer.server.len;
		peer->hc_checks = 0;
		peer->hc_fails = 0;
		peer->hc_last_passed = 0;
		peer->hc_downstart = 0;
		peer->hc_down = 0;
		if(json_peer.drain == 1) {
			peer->hc_down  = 100 + peer->hc_down;
		}
		peer->hc_consecutive_fails = 0;
		peer->hc_consecutive_passes = 0;
		peer->hc_unhealthy = 0;
	}
	if (json_peer.down != -1) {

		peer->down = json_peer.down;
		if (peer->down != (njt_uint_t)json_peer.down) {

			if (peer->down) {
				/*originally the peer is down, then it is up now*/
				target_peers->tries++;
			} else {
				/*originally the peer is up, then it is down now */
				target_peers->tries--;
			}
		}

		peer->down = json_peer.down;
	}

	/*update the modified items*/
	if (json_peer.weight != -1) {

		target_peers->total_weight -= peer->weight;
		target_peers->total_weight += json_peer.weight;
		target_peers->weighted = (peers->total_weight != peers->number);

		peer->weight = json_peer.weight;
		peer->effective_weight = json_peer.weight;
	}
	peers->update_id++;
	rc = njt_stream_upstream_api_compose_one_server(r, peers, peer,is_backup,peer->id,&server_one); //���ԡ�
	njt_stream_upstream_rr_peers_unlock(peers);

out:

	if (rc != NJT_OK) {

		rc = njt_http_upstream_api_err_out(r, rc,&json_peer.msg, &out);
		if (rc != NJT_OK) {
			goto error;
		}

		goto send;
	}


	r->headers_out.status = NJT_HTTP_OK;
	/*return the current servers*/


	
	if (server_one == NULL) {
		goto error;
	}
	to_json = to_json_one_serverDef(r->pool,server_one,OMIT_NULL_ARRAY | OMIT_NULL_OBJ | OMIT_NULL_STR);
	rc = njt_http_upstream_api_packet_out(r,to_json,&out);
	if (rc != NJT_OK) {
		goto error;
	}

send:
	r->headers_out.content_type_len = sizeof("text/plain") - 1;
	njt_str_set(&r->headers_out.content_type, "text/plain");
	r->headers_out.content_type_lowcase = NULL;

	len = njt_http_upstream_api_out_len(&out);
	r->headers_out.content_length_n = len;

	if (r->headers_out.content_length) {
		r->headers_out.content_length->hash = 0;
		r->headers_out.content_length = NULL;
	}
	rc = njt_http_send_header(r);

	if (rc == NJT_ERROR || rc > NJT_OK || r->header_only) {
		njt_http_finalize_request(r, rc);
		return;
	}

	rc = njt_http_output_filter(r, &out);
	njt_http_finalize_request(r, rc);
	return;

error:
	njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
	return;
}

	static njt_int_t
njt_stream_upstream_api_process_patch(njt_http_request_t *r,
		void *cf,
		njt_uint_t id)
{
	njt_int_t                          rc;
	njt_stream_upstream_rr_peers_t       *peers;
	njt_stream_upstream_api_ctx_t       *ctx;
	njt_stream_upstream_srv_conf_t *uscf = cf;

	/*try to search the server*/
	peers = (njt_stream_upstream_rr_peers_t *)uscf->peer.data;

	ctx = njt_pcalloc(r->pool, sizeof(njt_stream_upstream_api_ctx_t));
	if (ctx == NULL) {
		njt_http_discard_request_body(r);
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
				"upstream api ctx allocate error.");
		return NJT_HTTP_INTERNAL_SERVER_ERROR;
	}

	ctx->peers = peers;
	ctx->id = id;
	ctx->uscf  = uscf;
	ctx->resolver = uscf->resolver;
	njt_stream_set_ctx(r, ctx, njt_http_upstream_api_module);

	rc = njt_http_read_client_request_body(r, njt_stream_upstream_api_patch);
	if (rc >= NJT_HTTP_SPECIAL_RESPONSE) {
		/* error */
		return rc;
	}
	return NJT_DONE;
}

/////////////////////////stream upstream end ///////////////////////////

	static char *
njt_http_upstream_api(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
	njt_http_upstream_api_loc_conf_t *uclcf;
	njt_str_t                         *value;
	njt_http_upstream_api_main_conf_t *mcf;
	mcf = njt_http_conf_get_module_main_conf(cf, njt_http_upstream_api_module);
	uclcf = njt_http_conf_get_module_loc_conf(cf, njt_http_upstream_api_module);

	value = cf->args->elts;
	if (cf->args->nelts > 2) {
		njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
				"invalid parameter number");
		return NJT_CONF_ERROR;
	}

	if (cf->args->nelts == 2) {

		if (njt_strncmp(value[1].data, "write=", 6) == 0) {

			if (njt_strcmp(&value[1].data[6], "on") == 0) {
				mcf->write = 1;

			} else if (njt_strcmp(&value[1].data[6], "off") == 0) {
				//mcf->write = 0;

			} else {
				njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
						"value of \"%V\" must be \"on\" or \"off\"", &value[1]);
				return NJT_CONF_ERROR;
			}

		} else {
			njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
					"invalid parameter \"%V\"", &value[1]);
			return NJT_CONF_ERROR;
		}
	}

	mcf->enable = 1;
	uclcf->enable = 1;
	uclcf->write = mcf->write;

	//clcf = njt_http_conf_get_module_loc_conf(cf, njt_http_core_module);
	//clcf->handler = njt_http_upstream_api_handler;

	return NJT_CONF_OK;
}


	static njt_shm_zone_t *
njt_shared_memory_get(njt_cycle_t *cycle, njt_str_t *name, size_t size, void *tag)
{
	njt_uint_t        i;
	njt_shm_zone_t   *shm_zone;
	njt_list_part_t  *part;

	part = &cycle->shared_memory.part;
	shm_zone = part->elts;

	for (i = 0; /* void */ ; i++) {

		if (i >= part->nelts) {
			if (part->next == NULL) {
				break;
			}
			part = part->next;
			shm_zone = part->elts;
			i = 0;
		}

		if (name->len != shm_zone[i].shm.name.len) {
			continue;
		}

		if (njt_strncmp(name->data, shm_zone[i].shm.name.data, name->len)
				!= 0)
		{
			continue;
		}

		if (tag != shm_zone[i].tag) {
			return NULL;
		}

		if (shm_zone[i].shm.size == 0) {
			shm_zone[i].shm.size = size;
		}

		if (size && size != shm_zone[i].shm.size) {
			return NULL;
		}

		return &shm_zone[i];
	}
	return NULL;
}


	static njt_int_t
njt_http_upstream_api_init_worker(njt_cycle_t *cycle)
{

	njt_http_upstream_api_main_conf_t *uclcf;
	njt_slab_pool_t *shpool;
	njt_str_t zone_http = njt_string("api_dy_server");
	njt_str_t zone_stream = njt_string("api_stream_server");

	njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0, "njt_http_upstream_api_init_worker");

	uclcf = njt_http_cycle_get_module_main_conf(cycle, njt_http_upstream_api_module);
	if(uclcf == NULL){
		return NJT_OK;
	}

	uclcf->shm_zone_http = njt_shared_memory_get(njet_master_cycle, &zone_http, 0, &njt_http_upstream_module);
	uclcf->peers_http = NULL;
	if(uclcf->shm_zone_http) {
		shpool = (njt_slab_pool_t *)uclcf->shm_zone_http->shm.addr;
		uclcf->peers_http = shpool->data;
		njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0, "njt_http_upstream_api_init_worker http api_dy_server ok");
	}

	uclcf->shm_zone_stream = njt_shared_memory_get(njet_master_cycle, &zone_stream, 0, &njt_stream_upstream_module);
	uclcf->peers_stream = NULL;
	if(uclcf->shm_zone_stream) {
		shpool = (njt_slab_pool_t *)uclcf->shm_zone_stream->shm.addr;
		uclcf->peers_stream = shpool->data;
		njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0, "njt_http_upstream_api_init_worker stream api_dy_server ok");
	}

	return NJT_OK;
}


