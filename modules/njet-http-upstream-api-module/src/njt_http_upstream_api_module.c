#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_stream.h>
#include <njt_json_api.h>
#include <math.h>
#include "njt_http_upstream_api_module.h"


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


#define NJT_GET_CHAR_NUM_C(n)  (n.len)   //char
#define NJT_GET_CHAR_NUM_B(n)  (n>0?4:5)   //bool
#define NJT_GET_CHAR_NUM_S(n)  (n>0?16:16)   //up,down

extern njt_cycle_t *njet_master_cycle;
static njt_int_t
njt_http_upstream_api_add_server_retrun(njt_http_request_t *r,
        njt_http_upstream_rr_peer_t *peer, njt_flag_t comma,
        njt_flag_t backup, njt_chain_t *out);
static njt_int_t
njt_stream_upstream_api_add_server_retrun(njt_http_request_t *r,
        njt_stream_upstream_rr_peer_t *peer, njt_flag_t comma,
        njt_flag_t backup, njt_chain_t *out);

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


typedef struct njt_http_upstream_api_ctx_s {
    void   *peers;
    njt_uint_t                     id;
	njt_resolver_t                 *resolver;
	njt_flag_t                     keep_alive;
	njt_int_t                      hc_type;
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
	njt_http_core_main_conf_t  *cmcf;
	njt_http_handler_pt        *h;
	cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);
	//njt_http_upstream_api_handler
	 h = njt_array_push(&cmcf->phases[NJT_HTTP_CONTENT_PHASE].handlers);
	 if (h == NULL) {
		 return NJT_ERROR;
	 }

    *h = njt_http_upstream_api_handler;
    return NJT_OK;
}

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
		uclcf->peers_stream->number++;
		} else {
			njt_slab_free_locked(shpool,new_peer);
		}
	}
	njt_stream_upstream_rr_peers_unlock(uclcf->peers_stream);
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
		uclcf->peers_http->number++;
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

    version = njt_atoi(item[0].data, item[0].len);

    if (version < 1 || version > 7) {
        return NJT_HTTP_UPS_API_UNKNOWN_VERSION;
    }
	*upstream_type = 0;
    if (njt_strncmp(item[1].data, "http", 4) == 0) {
       *upstream_type = 1;
    } 
	if (njt_strncmp(item[1].data, "stream", 6) == 0) {
        *upstream_type = 2;
    } 

	if(*upstream_type == 0) {
		return NJT_HTTP_UPS_API_PATH_NOT_FOUND;
	}
    if (njt_strncmp(item[2].data, "upstreams", 9) != 0) {
        return NJT_HTTP_UPS_API_PATH_NOT_FOUND;
    }


    if (length >= 4) {
        *upstream = item[3];
    }

    if (length >= 5) {
        if (njt_strncmp(item[4].data, "servers", 7) != 0) {
            return NJT_HTTP_UPS_API_PATH_NOT_FOUND;
        }
    }

    if (length >= 6) {
        *id = item[5];
    }

    return NJT_OK;
}

static u_char *
njt_format_time(u_char *buf, const char *field,njt_uint_t nt)
{
	time_t t;
	njt_uint_t mt;
    njt_tm_t  tm;  //njt_gmtime(entry[i].mtime, &tm);
	
	mt = nt%1000;
	t = (nt/1000);
    njt_gmtime(t, &tm);

    return njt_sprintf(buf, ",\"%s\":\"%4d-%02d-%02dT%02d:%02d:%02d.%03dZ\"",  //",\"downstart\":\"2022-06-28T11:09:21.602Z\""
                       field,tm.njt_tm_year, tm.njt_tm_mon,
                       tm.njt_tm_mday, tm.njt_tm_hour,
                       tm.njt_tm_min, tm.njt_tm_sec,mt);

}

static ssize_t
njt_stream_upstream_api_one_server_strlen(ssize_t reserve_size, njt_flag_t detailed, njt_stream_upstream_rr_peer_t *peer,njt_flag_t is_parent,njt_http_upstream_peer_code_t *responses)
{
    ssize_t len = 0;
	njt_str_t *pname;
	njt_uint_t id;
    if (detailed) {

			  len = sizeof("%s{\"id\":%d,\"server\":\"%V\",\"name\":\"%V\",\"backup\":%s,\"weight\":%d," \
								   "\"state\":\"%s\",\"active\":%d,\"max_conns\":%d,\"connecions\":%d,\"sent\": %d,\"received\": %d,\"fails\": %d,\"unavail\": %d,\"health_checks\":{\"checks\":%d,\"fails\":%d,\"unhealthy\":%d\",\"last_passed\": %s},\"downtime\": %d}") -1;

			  if(peer->hc_downstart != 0) {
				  len += sizeof(",\"downstart\": \"2022-06-28T11:09:21.602Z\"") -1;
			  } else {
				  len += 1;
			  }
			  if(peer->requests != 0) {
				 len += sizeof(",\"connect_time\":%d");
				 len += NJT_ATOMIC_T_LEN;
			  } else {
				  len += 1;
			  }
			  if(peer->requests != 0) {
				 len += sizeof(",\"first_byte_time\":%d");
				 len += NJT_ATOMIC_T_LEN;
			  } else {
				  len += 1;
			  }
			  if(peer->requests != 0) {
				 len += sizeof(",\"response_time\":%d");
				 len += NJT_ATOMIC_T_LEN;
			  } else {
				  len += 1;
			  }
			  len += 1;
			  len += NJT_GET_CHAR_NUM_INT(peer->id);
			  len += NJT_GET_CHAR_NUM_C(peer->name);
			  len += NJT_GET_CHAR_NUM_C(peer->server);
			  len += 5;
			  len += NJT_GET_CHAR_NUM_INT(peer->weight);
			  len += NJT_GET_CHAR_NUM_S(peer->down);
			  len += NJT_GET_CHAR_NUM_INT(peer->conns);
			  len += NJT_GET_CHAR_NUM_INT(peer->max_conns);
			  len += NJT_GET_CHAR_NUM_INT(peer->requests);
			  len += NJT_GET_CHAR_NUM_INT(peer->sent);
			  len += NJT_GET_CHAR_NUM_INT(peer->received);
			  len += NJT_GET_CHAR_NUM_INT(peer->fails);
			  len += NJT_GET_CHAR_NUM_INT(peer->unavail);
			  len += NJT_GET_CHAR_NUM_INT(peer->hc_checks);//checks peer->hc_checks
			  len += NJT_GET_CHAR_NUM_INT(peer->hc_fails);//checks peer->hc_fails
			  len += NJT_GET_CHAR_NUM_INT(peer->hc_unhealthy);//checks peer->hc_fails
			  len += NJT_GET_CHAR_NUM_B(peer->hc_last_passed);
			  len += NJT_INT64_LEN; // NJT_GET_CHAR_NUM_INT(peer->downtime);
			   if(peer->selected_time != 0) {
				 len += sizeof(",\"selected\": \"2022-06-28T11:09:21.602Z\"");
			  } else {
				  len += 1;
			  }


			  
			

    } else {
		  if(peer->parent_id >= 0 && is_parent == 0) {
			  len += sizeof(",\"parent\": %d,\"host\":\"%V\"}") - 1;
			  id =  peer->id;
			  pname = &peer->name;
			
			  len += NJT_GET_CHAR_NUM_INT(peer->parent_id);
			  len += NJT_GET_CHAR_NUM_C(peer->server);
		  } else {
			   len += 1;
			   pname = (is_parent == 1?(&peer->server):(&peer->name));
			   id =  (is_parent == 1?((njt_uint_t)peer->parent_id):(peer->id)); 
		  }
		  len += sizeof("%s{\"id\":%d,\"server\":\"%V\",\"weight\":%d,\"max_conns\": %d,"  \
                               "\"max_fails\":%d,\"fail_timeout\":\"%ds\",\"slow_start\":\"%ds\"," \
                               "\"backup\":%s,\"down\":%s}") - 1;

			  len += 1;
			  len += NJT_GET_CHAR_NUM_INT(id);
			  len += NJT_GET_CHAR_NUM_C((*pname));;
			  len += NJT_GET_CHAR_NUM_INT(peer->weight);
			  len += NJT_GET_CHAR_NUM_INT(peer->max_conns);
			  len += NJT_GET_CHAR_NUM_INT(peer->max_fails);
			  len += NJT_GET_CHAR_NUM_INT(peer->fail_timeout) + 1;
			  len += NJT_GET_CHAR_NUM_INT(peer->slow_start) + 1;
			  len += 5;
			  len += 5;
		  
		
	}

    return len;
}

static ssize_t
njt_http_upstream_api_one_server_strlen(ssize_t reserve_size, njt_flag_t detailed, njt_http_upstream_rr_peer_t *peer,njt_flag_t is_parent,njt_http_upstream_peer_code_t *responses)
{
    ssize_t len = 0;
	njt_str_t *pname;
	njt_uint_t id;
    if (detailed) {
			   len = sizeof("%s{\"id\":%d,\"server\":\"%V\",\"name\":\"%V\",\"backup\":%s,\"weight\":%d," \
								   "\"state\":\"%s\",\"active\":%d,\"max_conns\":%d,\"requests\":%d,\"responses\": {\"1xx\": %d,\"2xx\": %d,\"3xx\": %d,\"4xx\": %d,\"5xx\": %d,\"codes\": %s,\"total\": %d" \
				  "},\"sent\": %d,\"received\": %d,\"fails\": %d,\"unavail\": %d,\"health_checks\":{\"checks\":%d,\"fails\":%d,\"unhealthy\":%d\",\"last_passed\": %s},\"downtime\": %d}") -1;

			  if(peer->hc_downstart != 0) {
				  len += sizeof(",\"downstart\":\"2022-06-28T11:09:21.602Z\"") -1;
			  } else {
				  len += 1;
			  }
			  if(peer->total_header_time != 0) {
				  len += sizeof(",\"header_time\":%d") -1;
			  } else {
				  len += 1;
			  }
			  if(peer->total_response_time != 0) {
				  len += sizeof(",\"response_time\":%d") -1;
			  } else {
				  len += 1;
			  }
			  len += 1;
			  len += NJT_GET_CHAR_NUM_INT(peer->id);
			  len += NJT_GET_CHAR_NUM_C(peer->name);
			  len += NJT_GET_CHAR_NUM_C(peer->server);
			  len += 5;
			  len += NJT_GET_CHAR_NUM_INT(peer->weight);
			  len += NJT_GET_CHAR_NUM_S(peer->down);
			  len += NJT_GET_CHAR_NUM_INT(peer->conns);
			  len += NJT_GET_CHAR_NUM_INT(peer->max_conns);
			  len += NJT_GET_CHAR_NUM_INT(peer->requests);
			  len += NJT_GET_CHAR_NUM_INT(peer->total_header_time);
			  len += NJT_GET_CHAR_NUM_INT(peer->total_response_time);
			  len += NJT_GET_CHAR_NUM_INT(responses->one);
			  len += NJT_GET_CHAR_NUM_INT(responses->two);
			  len += NJT_GET_CHAR_NUM_INT(responses->three);
			  len += NJT_GET_CHAR_NUM_INT(responses->four);
			  len += NJT_GET_CHAR_NUM_INT(responses->five);
			  len += reserve_size;  //code
			  len += NJT_GET_CHAR_NUM_INT(responses->total);
			  len += NJT_GET_CHAR_NUM_INT(responses->sent);
			  len += NJT_GET_CHAR_NUM_INT(responses->received);
			  len += NJT_GET_CHAR_NUM_INT(peer->fails);
			  len += NJT_GET_CHAR_NUM_INT(peer->unavail);
			  len += NJT_GET_CHAR_NUM_INT(peer->hc_checks);//checks peer->hc_checks
			  len += NJT_GET_CHAR_NUM_INT(peer->hc_fails);//checks peer->hc_fails
			  len += NJT_GET_CHAR_NUM_INT(peer->hc_unhealthy);//checks peer->hc_fails
			  len += NJT_GET_CHAR_NUM_B(peer->hc_last_passed);
			  len += NJT_INT64_LEN; //  peer->downtime
			  if(peer->selected_time != 0) {
				 len += sizeof(",\"selected\": \"2022-06-28T11:09:21.602Z\"");
			  } else {
				  len += 1;
			  }
			  
			

    } else {
		  if(peer->hc_down/100 == 1){
				len = sizeof(",\"drain\": true") - 1;
		  }else{
			   len += 1;
		  }
		  if(peer->parent_id >= 0 && is_parent == 0) {
			  len = sizeof(",\"parent\": %d,\"host\":\"%V\"") - 1;
			  pname = &peer->name;
			  id = peer->id;
			  len += NJT_GET_CHAR_NUM_INT(peer->parent_id);
			  len += NJT_GET_CHAR_NUM_C(peer->server);
		  } else {
			   len += 1;
			   pname = (is_parent == 1?(&peer->server):(&peer->name));
			   id =  (is_parent == 1?((njt_uint_t)peer->parent_id):(peer->id));
		  }
		  	   len += sizeof("%s{\"id\":%d,\"server\":\"%V\",\"weight\":%d,\"max_conns\": %d,"  \
                               "\"max_fails\":%d,\"fail_timeout\":\"%ds\",\"slow_start\":\"%ds\",\"route\":\"%V\"," \
                               "\"backup\":%s,\"down\":%s%s}") - 1;

		  	  len += 1;
			  len += NJT_GET_CHAR_NUM_INT(id);
			  len += NJT_GET_CHAR_NUM_C((*pname));
			  len += NJT_GET_CHAR_NUM_INT(peer->weight);
			  len += NJT_GET_CHAR_NUM_INT(peer->max_conns);
			  len += NJT_GET_CHAR_NUM_INT(peer->max_fails);
			  len += NJT_GET_CHAR_NUM_INT(peer->fail_timeout) + 1;
			  len += NJT_GET_CHAR_NUM_INT(peer->slow_start) + 1;
			  len += NJT_GET_CHAR_NUM_C(peer->route);
			  len += 5;
			  len += 5;
		  
		
	}

    return len;
}


static njt_buf_t *
njt_http_upstream_api_get_out_buf(njt_http_request_t *r, ssize_t len,
                                  njt_chain_t *out)
{
    njt_buf_t                      *b;
    njt_chain_t                    *last_chain, *new_chain;


    if ((njt_uint_t)len > njt_pagesize) {
        /*The string len is larger than one buf*/

        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "buffer size is beyond one pagesize.");
        return NULL;
    }

    last_chain = out;
    while (out->next) {
        out->buf->last_buf = 0;
        out->buf->last_in_chain = 0;

        last_chain = out->next;
        out = out->next;
    }

    b = last_chain->buf;
    if (b == NULL) {

        b = njt_create_temp_buf(r->pool, njt_pagesize);
        if (b == NULL) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "couldn't allocate the temp buffer.");
            return NULL;
        }

        last_chain->buf = b;
        last_chain->next = NULL;

        b->last_buf = 1;
        b->last_in_chain = 1;
        b->memory = 1;

        return b;
    }

    /*if the buf's left size is big enough to hold one server*/

    if ((b->end - b->last) < len) {

        new_chain = njt_pcalloc(r->pool, sizeof(njt_chain_t));
        if (new_chain == NULL) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "couldn't allocate the chain.");
            return NULL;
        }

        b = njt_create_temp_buf(r->pool, njt_pagesize);
        if (b == NULL) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "couldn't allocate temp buffer.");
            return NULL;
        }

        new_chain->buf = b;
        new_chain->next = NULL;

        last_chain->buf->last_buf = 0;
        last_chain->buf->last_in_chain = 0;

        new_chain->buf->last_buf = 1;
        new_chain->buf->last_in_chain = 1;

        last_chain->next = new_chain;
    }

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
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "parameter error in function %s", __func__);
        return NJT_ERROR;
    }

    b = njt_http_upstream_api_get_out_buf(r, str->len, out);
    if (b == NULL) {
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "could not alloc buffer in function %s", __func__);
        return NJT_ERROR;
    }

    b->last = njt_snprintf(b->last, str->len, "%V", str);

    return NJT_OK;
}

static char * njt_get_stream_down_status_name(njt_stream_upstream_rr_peer_t *peer)
{

  time_t                        now;
  now = njt_time();
 if(peer->down == 1) {
	  return "down";
  }
  else if(peer->hc_down%100 == 1 ) {
	  return "unhealthy";
  }
  else if(peer->hc_down/100 == 1 ) {
	  return "draining";
  }
  else if(peer->hc_down%100 == 2 ) {
	  return "checking";
  } else if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout){
	  return "unavail";
  }
  
  
  return "up";
}
static char * njt_get_http_down_status_name(njt_http_upstream_rr_peer_t *peer)
{
  time_t                        now;
  now = njt_time();
 if(peer->down == 1) {
	  return "down";
  }
  else if(peer->hc_down%100 == 1 ) {
	  return "unhealthy";
  }
  else if(peer->hc_down/100 == 1 ) {
	  return "draining";
  }
  else if(peer->hc_down%100 == 2 ) {
	  return "checking";
  } else if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout){
	  return "unavail";
  }
  
  
  return "up";
  
}
//{\"processing\":3,\"requests\":8,\"responses\":{\"1xx\":0,\"2xx\":4,\"3xx\":4,\"4xx\":0,\"5xx\":0,\"codes\":{\"200\":4,\"301\":0,\"404\":0,\"503\":0},\"total\":8},\"discarded\":0,\"received\":3828,\"sent\":88036}
static njt_int_t
njt_http_upstream_api_get_peer_from_json(njt_json_manager *json_manager,
                                  njt_http_upstream_peer_code_t *json_peer
                                  )
{
    njt_int_t          rc;
    njt_uint_t         i,j;
    njt_json_element  *items;
	njt_json_element  *items_rsp;
    

    rc = NJT_OK;

	 items = json_manager->json_keyval->elts;
    for (i = 0; i < json_manager->json_keyval->nelts; i ++) {

        if (njt_strncmp(items[i].key.data, "processing", 10) == 0) {

            if (items[i].type != NJT_JSON_INT) {
                rc = NJT_HTTP_UPS_API_INVALID_JSON_BODY;
                return rc;
            }

            json_peer->processing = items[i].intval;
            continue;
        } else if (njt_strncmp(items[i].key.data, "requests", 8) == 0) {

            if (items[i].type != NJT_JSON_INT) {
                rc = NJT_HTTP_UPS_API_INVALID_JSON_BODY;
                return rc;
            }

            json_peer->requests = items[i].intval;
            continue;
        } else if (njt_strncmp(items[i].key.data, "discarded", 9) == 0) {

            if (items[i].type != NJT_JSON_INT) {
                rc = NJT_HTTP_UPS_API_INVALID_JSON_BODY;
                return rc;
            }

            json_peer->discarded = items[i].intval;
            continue;
        } else if (njt_strncmp(items[i].key.data, "received", 8) == 0) {

            if (items[i].type != NJT_JSON_INT) {
                rc = NJT_HTTP_UPS_API_INVALID_JSON_BODY;
                return rc;
            }

            json_peer->received = items[i].intval;
            continue;
        } else if (njt_strncmp(items[i].key.data, "sent", 4) == 0) {

            if (items[i].type != NJT_JSON_INT) {
                rc = NJT_HTTP_UPS_API_INVALID_JSON_BODY;
                return rc;
            }

            json_peer->sent = items[i].intval;
            continue;
        } else if (njt_strncmp(items[i].key.data, "total", 5) == 0) {

            if (items[i].type != NJT_JSON_INT) {
                rc = NJT_HTTP_UPS_API_INVALID_JSON_BODY;
                return rc;
            }

            json_peer->total = items[i].intval;
            continue;
        } else if (njt_strncmp(items[i].key.data, "responses", 9) == 0) {

            if (items[i].type != NJT_JSON_OBJ) {
                rc = NJT_HTTP_UPS_API_INVALID_JSON_BODY;
                return rc;
            }

            items_rsp = items[i].sudata->elts;  //sudata
			for (j = 0; j < items[i].sudata->nelts; j ++) {
				if (njt_strncmp(items_rsp[j].key.data, "1xx", 3) == 0) {

					if (items_rsp[j].type != NJT_JSON_INT) {
						rc = NJT_HTTP_UPS_API_INVALID_JSON_BODY;
						return rc;
					}

					json_peer->one = items_rsp[j].intval;
					continue;
				} else if (njt_strncmp(items_rsp[j].key.data, "2xx", 3) == 0) {

					if (items_rsp[j].type != NJT_JSON_INT) {
						rc = NJT_HTTP_UPS_API_INVALID_JSON_BODY;
						return rc;
					}

					json_peer->two = items_rsp[j].intval;
					continue;
				} else if (njt_strncmp(items_rsp[j].key.data, "3xx", 3) == 0) {

					if (items_rsp[j].type != NJT_JSON_INT) {
						rc = NJT_HTTP_UPS_API_INVALID_JSON_BODY;
						return rc;
					}

					json_peer->three = items_rsp[j].intval;
					continue;
				} else if (njt_strncmp(items_rsp[j].key.data, "4xx", 3) == 0) {

					if (items_rsp[j].type != NJT_JSON_INT) {
						rc = NJT_HTTP_UPS_API_INVALID_JSON_BODY;
						return rc;
					}

					json_peer->four = items_rsp[j].intval;
					continue;
				} else if (njt_strncmp(items_rsp[j].key.data, "5xx", 3) == 0) {

					if (items_rsp[j].type != NJT_JSON_INT) {
						rc = NJT_HTTP_UPS_API_INVALID_JSON_BODY;
						return rc;
					}

					json_peer->five = items_rsp[j].intval;
					continue;
				} else if (njt_strncmp(items_rsp[j].key.data, "total", 5) == 0) {

					if (items_rsp[j].type != NJT_JSON_INT) {
						rc = NJT_HTTP_UPS_API_INVALID_JSON_BODY;
						return rc;
					}

					json_peer->total = items_rsp[j].intval;
					continue;
				} else if (njt_strncmp(items_rsp[j].key.data, "codes", 5) == 0) {

					if (items_rsp[j].type != NJT_JSON_OBJ) {
						rc = NJT_HTTP_UPS_API_INVALID_JSON_BODY;
						return rc;
					}

					json_peer->codes = items_rsp[j].sudata;
					continue;
				}
			}
            continue;
        } 

        /*unknown parameters*/
	
        rc = NJT_HTTP_UPS_API_INVALID_JSON_BODY;
        return rc;

    }

    return rc;
}


static njt_int_t
njt_stream_upstream_api_compose_one_server(njt_http_request_t *r,
        njt_stream_upstream_rr_peer_t *peer, njt_flag_t detailed, njt_flag_t comma,
        njt_flag_t backup, njt_chain_t *out,njt_flag_t is_parent,njt_str_t upstream_name)
{
    njt_buf_t                      *b;
    ssize_t                        len;
	njt_str_t                      *pname;
	njt_uint_t                      id,down_time;
	njt_http_upstream_peer_code_t   peer_code;
	u_char                     buf[256] = {0};
	u_char                     timebuf[256] = {0};
	u_char                     conn_time[128] = {0};
	u_char                     first_time[128] = {0};
	u_char                     response_time[128] = {0};
	u_char                     max_conns[128] = {0};
	u_char                     last_passed[128] = {0};
	
	len = 0;
    /*if the buf's left size is big enough to hold one server*/
    len = njt_stream_upstream_api_one_server_strlen(len,detailed, peer,is_parent,&peer_code);

    b =  njt_http_upstream_api_get_out_buf(r, len, out);
    if (b == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* copy the server's information into the buffer*/
    if (detailed) {
        /*detailed version*/
		 pname = (is_parent == 1?(&peer->server):(&peer->name));
		 id =  (is_parent == 1?((njt_uint_t)peer->parent_id):(peer->id));
		 if(peer->hc_downstart != 0) {
			down_time =  ((njt_uint_t)((njt_timeofday())->sec)*1000 + (njt_uint_t)((njt_timeofday())->msec) ) -  peer->hc_downstart + peer->hc_downtime;
			njt_format_time(buf,"downstart",peer->hc_downstart);

		} else {
			 id = peer->id;
			 pname = &peer->name;
			 down_time = peer->hc_downtime;
		}
		 if(peer->selected_time != 0) {
			njt_format_time(timebuf,"selected",peer->selected_time);

		} 
		if( peer->requests != 0) {
			njt_snprintf(conn_time,sizeof(conn_time),",\"connect_time\":%d",peer->total_connect_time/peer->requests);
			njt_snprintf(first_time,sizeof(first_time),",\"first_byte_time\":%d",peer->total_first_byte_time/peer->requests);
			njt_snprintf(response_time,sizeof(response_time),",\"response_time\":%d",peer->total_response_time/peer->requests);

		} 
		if( peer->max_conns != 0) {
			njt_snprintf(max_conns,sizeof(max_conns),",\"max_conns\":%d",peer->max_conns);
		}
		if(peer->hc_checks != 0) {
			njt_snprintf(last_passed,sizeof(last_passed),",\"last_passed\":%s",peer->hc_last_passed ? "true" : "false");
		}
		 b->last = njt_snprintf(b->last, len,
                               "%s{\"id\":%d,\"server\":\"%V\",\"name\":\"%V\",\"backup\":%s,\"weight\":%d," \
                               "\"state\":\"%s\",\"active\":%d%s,\"connecions\":%d%s%s%s,\"sent\": %d,\"received\": %d,\"fails\": %d,\"unavail\": %d,\"health_checks\":{\"checks\":%d,\"fails\":%d,\"unhealthy\":%d%s},\"downtime\": %d%s%s}",  //\"parent\": %d
                               comma ? "," : "", id,pname, &peer->server,backup ? "true" : "false", peer->weight,
                               njt_get_stream_down_status_name(peer),peer->conns,max_conns,peer->requests,conn_time,first_time,response_time,
			 peer->sent,peer->received,peer->fails,peer->unavail,peer->hc_checks, peer->hc_fails,peer->hc_unhealthy,last_passed,down_time,buf,timebuf);
       
    } else {
			 njt_memzero(buf,sizeof(buf));
			 id =  peer->id;
			 if(peer->parent_id >= 0 && is_parent == 0) {
				njt_snprintf(buf,sizeof(buf),",\"parent\": %d,\"host\":\"%V\"",peer->parent_id,&peer->server);
				pname = &peer->name;
				
			} else {
				pname = (is_parent == 1?(&peer->server):(&peer->name));
			}
			b->last = njt_snprintf(b->last, len,
								   "%s{\"id\":%d,\"server\":\"%V\",\"weight\":%d,\"max_conns\": %d,"
								   "\"max_fails\":%d,\"fail_timeout\":\"%ds\",\"slow_start\":\"%ds\","
								   "\"backup\":%s,\"down\":%s%s}", comma ? "," : "",
								   id,pname, peer->weight, peer->max_conns,
								   peer->max_fails, peer->fail_timeout,peer->slow_start,backup ? "true" : "false",
								   (peer->down == 1) ? "true":"false",buf);
		
    }

    return NJT_OK;
}



static njt_int_t
njt_http_upstream_api_compose_one_server(njt_http_request_t *r,
        njt_http_upstream_rr_peer_t *peer, njt_flag_t detailed, njt_flag_t comma,
        njt_flag_t backup, njt_chain_t *out,njt_flag_t is_parent,njt_str_t upstream_name)
{
    njt_buf_t                      *b;
    ssize_t                        len;
	njt_str_t                      *pname;
	njt_uint_t                      id,down_time;
	njt_str_t                       peer_name;
	njt_str_t                       json_str;
	njt_json_manager                json_body;
	njt_http_upstream_peer_code_t   peer_code;
	njt_json_element                *pele;
	njt_uint_t                       i;
	njt_int_t                        rc;
	njt_http_variable_value_t        *v;
	njt_str_t                         strcodes;
	u_char                    *p,*pdata;
	u_char                     buf[256] = {0};
	u_char                     timebuf[128] = {0};
	u_char                     header[128] = {0};
	u_char                     response[128] = {0};
	u_char                     max_conns[128] = {0};
	u_char                     last_passed[128] = {0};
	
	len = 0;
	njt_str_set(&strcodes,"");
	if(detailed == 1) {
		peer_name.len = 256;
		strcodes.len = 1024;
		strcodes.data = njt_pcalloc(r->pool,strcodes.len);
		peer_name.data = njt_pcalloc(r->pool,peer_name.len);
		if(strcodes.data == NULL || peer_name.data == NULL) {
			return NJT_HTTP_INTERNAL_SERVER_ERROR; 
		}
		
		njt_memzero(&peer_code, sizeof(njt_http_upstream_peer_code_t));
		len = strcodes.len;
		pdata = strcodes.data;
		p = njt_snprintf(pdata, len,"{");
		len -= p - pdata;
		pdata =p;
		//if(peer_name.data && is_parent == 0) { //zyg todo
		if(false) { //zyg todo
			njt_memzero(peer_name.data, peer_name.len);
			peer_name.len = njt_snprintf(peer_name.data,peer_name.len,"upstream_status_%V_%d_%V",&upstream_name,peer->id,&peer->name) - peer_name.data;
			v = njt_http_get_variable(r,&peer_name,0);
			if(v->len > 10) {
				json_str.len = v->len;
				json_str.data = v->data;
				rc = njt_json_2_structure(&json_str, &json_body, r->pool);
				if(rc == NJT_OK) {
				  njt_http_upstream_api_get_peer_from_json(&json_body,&peer_code);
				  if(peer_code.codes && peer_code.codes->nelts > 0) {
						pele = peer_code.codes->elts;
						for(i=0; i < peer_code.codes->nelts; i++) {
							p = njt_snprintf(pdata, len,"\"%V\":%d,",&pele[i].key,pele[i].intval);
							len -= p - pdata;
							pdata = p;
							
						}
						p--;
						
				}
				}
			}
		}
		*p = '}';
		len = p - strcodes.data + 1;
	}
    /*if the buf's left size is big enough to hold one server*/
    len = njt_http_upstream_api_one_server_strlen(len,detailed, peer,is_parent,&peer_code);

    b =  njt_http_upstream_api_get_out_buf(r, len, out);
    if (b == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* copy the server's information into the buffer*/
    if (detailed) {
        /*detailed version*/

		 pname = (is_parent == 1?(&peer->server):(&peer->name));
		 id =  (is_parent == 1?((njt_uint_t)peer->parent_id):(peer->id));
		 if(peer->hc_downstart != 0) {

			down_time =  ((njt_uint_t)((njt_timeofday())->sec )*1000 + (njt_uint_t)((njt_timeofday())->msec) ) -  peer->hc_downstart + peer->hc_downtime;
			njt_format_time(buf,"downstart",peer->hc_downstart);
		} else {
			 down_time = peer->hc_downtime;
			 id = peer->id;
			 pname = &peer->name;
			
		}
		 if(peer->selected_time != 0) {
			njt_format_time(timebuf,"selected",peer->selected_time);

		}
		 if(peer->total_header_time != 0 && peer->requests != 0) {
			njt_snprintf(header,sizeof(header),",\"header_time\":%d",peer->total_header_time/peer->requests);

		} 
		 if(peer->total_response_time != 0 && peer->requests != 0) {
			njt_snprintf(response,sizeof(response),",\"response_time\":%d",peer->total_response_time/peer->requests);

		} 
		if( peer->max_conns != 0) {
			njt_snprintf(max_conns,sizeof(max_conns),",\"max_conns\":%d",peer->max_conns);
		}
		if(peer->hc_checks != 0) {
			njt_snprintf(last_passed,sizeof(last_passed),",\"last_passed\":%s",peer->hc_last_passed ? "true" : "false");
		}
		 b->last = njt_snprintf(b->last, len,
                               "%s{\"id\":%d,\"server\":\"%V\",\"name\":\"%V\",\"backup\":%s,\"weight\":%d," \
                               "\"state\":\"%s\",\"active\":%d%s,\"requests\":%d%s%s,\"responses\": {\"1xx\": %d,\"2xx\": %d,\"3xx\": %d,\"4xx\": %d,\"5xx\": %d,\"codes\": %s,\"total\": %d" \
              "},\"sent\": %d,\"received\": %d,\"fails\": %d,\"unavail\": %d,\"health_checks\":{\"checks\":%d,\"fails\":%d,\"unhealthy\":%d%s},\"downtime\": %d%s%s}",  //\"parent\": %d
                               comma ? "," : "", id,pname, &peer->server,backup ? "true" : "false", peer->weight,
                               njt_get_http_down_status_name(peer),peer->conns,max_conns,peer->requests,header,response, peer_code.one,peer_code.two,peer_code.three,peer_code.four,peer_code.five,strcodes.data,peer_code.total,
			 peer_code.sent,peer_code.received,peer->fails,peer->unavail,peer->hc_checks, peer->hc_fails,peer->hc_unhealthy,last_passed,down_time,buf,timebuf);
       
    } else {
			 njt_memzero(buf,sizeof(buf));
			 if(peer->parent_id >= 0 && is_parent == 0) {
				id =  peer->id;
				pname = &peer->name;
				njt_snprintf(buf,sizeof(buf),",\"parent\": %d,\"host\":\"%V\"",peer->parent_id,&peer->server);

				
			} else {
				pname = (is_parent == 1?(&peer->server):(&peer->name));
				id =  peer->id;
			}
			b->last = njt_snprintf(b->last, len,
								   "%s{\"id\":%d,\"server\":\"%V\",\"weight\":%d,\"max_conns\": %d,"
								   "\"max_fails\":%d,\"fail_timeout\":\"%ds\",\"slow_start\":\"%ds\",\"route\":\"%V\","
								   "\"backup\":%s,\"down\":%s%s%s}", comma ? "," : "",
								   id, pname, peer->weight, peer->max_conns,
								   peer->max_fails, peer->fail_timeout,peer->slow_start,&peer->route,backup ? "true" : "false",
								   (peer->down == 1) ? "true":"false",buf,peer->hc_down/100 == 1?",\"drain\":true":"");
		
    }

    return NJT_OK;
}


static njt_int_t
njt_stream_upstream_api_compose_one_upstream(njt_str_t zone_name,njt_http_request_t *r,
        void *p, ssize_t id,
        njt_flag_t detailed, njt_flag_t comma, njt_chain_t *out)
{
    njt_str_t                      insert;
    njt_stream_upstream_rr_peer_t    *peer,*peer_node;
    njt_int_t                      rc;
    njt_stream_upstream_rr_peers_t   *backup;
    njt_flag_t                     server_comma = 0;
	njt_stream_upstream_rr_peers_t *peers = p;
	njt_uint_t   zombies = 0; //njt_pcalloc
	njt_str_t				        buf;
    if (detailed) {
        njt_str_set(&insert, "{\"peers\":");
        rc = njt_http_upstream_api_insert_out_str(r, out, &insert);

        if (rc != NJT_OK) {
            return NJT_HTTP_UPS_API_INTERNAL_ERROR;
        }
    }

    if (id < 0) {
        njt_str_set(&insert, "[");
        rc = njt_http_upstream_api_insert_out_str(r, out, &insert);

        if (rc != NJT_OK) {
            return NJT_HTTP_UPS_API_INTERNAL_ERROR;
        }
    }

    njt_stream_upstream_rr_peers_rlock(peers);

    for (peer = peers->peer; peer != NULL; peer = peer->next) {
		 
        /*only compose one server*/
        if (id >= 0) {
            if (peer->id == (njt_uint_t)id) {
				
                njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0, "find the server %u",
                               id);
				peer_node = peer;
				rc = njt_stream_upstream_api_compose_one_server(r, peer_node, detailed, 0, 0, out,0,*peers->name);
                njt_stream_upstream_rr_peers_unlock(peers);
                return rc;
            }

            continue;
        }
		if(peer->del_pending) {
			 zombies++;
		}
        rc = njt_stream_upstream_api_compose_one_server(r, peer, detailed, server_comma,
                0,
                out,0,*peers->name);
		
        if (rc != NJT_OK) {
            njt_stream_upstream_rr_peers_unlock(peers);
            return rc;
        }
        server_comma = 1;
    }

    backup = peers->next;
    if (backup != NULL) {
        for (peer = backup->peer; peer != NULL; peer = peer->next) {

            /*only compose one server*/
            if (id >= 0) {
                if (peer->id == (njt_uint_t)id ) {
                    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "find the backup server %u", id);
				
					peer_node = peer;
                    rc = njt_stream_upstream_api_compose_one_server(r, peer_node, detailed, 0, 1, out,0,*peers->name);
                    njt_stream_upstream_rr_peers_unlock(peers);
                    return rc;
                }
                continue;
            }
			if(peer->del_pending) {
			 zombies++;
			}
            rc = njt_stream_upstream_api_compose_one_server(r, peer, detailed, server_comma,
                    1,
                    out,0,*peers->name);
		

            if (rc != NJT_OK) {
                njt_stream_upstream_rr_peers_unlock(peers);
                return rc;
            }
            server_comma = 1;
        }
    }

	if(detailed == 0) {
		for (peer = peers->parent_node; peer != NULL; peer = peer->next) {
				
				if(peer->parent_id == -1)
					continue;
				peer_node = peer;
				/*only compose one server*/
				if (id >= 0) {
					if (peer->id == (njt_uint_t)id || peer->parent_id == (njt_int_t)id) {
						njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
									   "find the backup server %u", id);
						
						
						rc = njt_stream_upstream_api_compose_one_server(r, peer_node, detailed, 0, peer_node->set_backup, out,1,*peers->name);
						njt_stream_upstream_rr_peers_unlock(peers);
						return rc;
					}
					continue;
				}
				rc = njt_stream_upstream_api_compose_one_server(r, peer_node, detailed, server_comma,
						peer_node->set_backup,
						out,1,*peers->name);
			

				if (rc != NJT_OK) {
					njt_stream_upstream_rr_peers_unlock(peers);
					return rc;
				}
				server_comma = 1;
			}
	}
	
    njt_stream_upstream_rr_peers_unlock(peers);

    /*The server isn't found*/
    if (id >= 0) {
        return NJT_HTTP_UPS_API_SRV_NOT_FOUND;
    }

    njt_str_set(&insert, "]");
    rc = njt_http_upstream_api_insert_out_str(r, out, &insert);

    if (rc != NJT_OK) {
        return NJT_HTTP_UPS_API_INTERNAL_ERROR;
    }
    if (detailed) {
		
		if(zombies == 0) {
			njt_str_set(&insert, ",\"zombies\":0");
			rc = njt_http_upstream_api_insert_out_str(r, out, &insert);
		} else {
			buf.len = 64;
			buf.data = njt_pcalloc(r->pool,buf.len);
			if(buf.data) {
				buf.len = njt_sprintf(buf.data, "%d",zombies) - buf.data;
			}
			njt_str_set(&insert, ",\"zombies\":");
			rc = njt_http_upstream_api_insert_out_str(r, out, &insert);
			rc = njt_http_upstream_api_insert_out_str(r, out, &buf);
			
		}
		
		if (rc != NJT_OK) {
			return NJT_HTTP_UPS_API_INTERNAL_ERROR;
		}
		
		njt_str_set(&insert, ",\"zone\":\"");
		rc = njt_http_upstream_api_insert_out_str(r, out, &insert);

		if (rc != NJT_OK) {
			return NJT_HTTP_UPS_API_INTERNAL_ERROR;
		}
		//njt_str_set(&insert, zone_name);
		rc = njt_http_upstream_api_insert_out_str(r, out, &zone_name);

		if (rc != NJT_OK) {
			return NJT_HTTP_UPS_API_INTERNAL_ERROR;
		}

		/////
		njt_str_set(&insert, "\"");
		rc = njt_http_upstream_api_insert_out_str(r, out, &insert);

		if (rc != NJT_OK) {
			return NJT_HTTP_UPS_API_INTERNAL_ERROR;
		}
		
        njt_str_set(&insert, "}");
        rc = njt_http_upstream_api_insert_out_str(r, out, &insert);

        if (rc != NJT_OK) {
            return NJT_HTTP_UPS_API_INTERNAL_ERROR;
        }
    }

    if (comma) {
        njt_str_set(&insert, ",");
        rc = njt_http_upstream_api_insert_out_str(r, out, &insert);

        if (rc != NJT_OK) {
            return NJT_HTTP_UPS_API_INTERNAL_ERROR;
        }
    }

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_api_compose_one_upstream(njt_flag_t keep_alive,njt_str_t zone_name,njt_http_request_t *r,
        void *p, ssize_t id,
        njt_flag_t detailed, njt_flag_t comma, njt_chain_t *out)
{
    njt_str_t                      insert;
    njt_http_upstream_rr_peer_t    *peer,*peer_node;
    njt_int_t                      rc;
    njt_http_upstream_rr_peers_t   *backup;
    njt_flag_t                     server_comma = 0;
	njt_http_upstream_rr_peers_t *peers = p;
	njt_uint_t   zombies = 0; //njt_pcalloc
	njt_str_t				        buf;
	

    if (detailed) {
        njt_str_set(&insert, "{\"peers\":");
        rc = njt_http_upstream_api_insert_out_str(r, out, &insert);

        if (rc != NJT_OK) {
            return NJT_HTTP_UPS_API_INTERNAL_ERROR;
        }
    }

    if (id < 0) {
        njt_str_set(&insert, "[");
        rc = njt_http_upstream_api_insert_out_str(r, out, &insert);

        if (rc != NJT_OK) {
            return NJT_HTTP_UPS_API_INTERNAL_ERROR;
        }
    }

    njt_http_upstream_rr_peers_rlock(peers);

    for (peer = peers->peer; peer != NULL; peer = peer->next) {
		 
        /*only compose one server*/
        if (id >= 0) {
            if (peer->id == (njt_uint_t)id) {
				
                njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0, "find the server %u",
                               id);
				peer_node = peer;
				rc = njt_http_upstream_api_compose_one_server(r, peer_node, detailed, 0, 0, out,0,*peers->name);
                njt_http_upstream_rr_peers_unlock(peers);
                return rc;
            }

            continue;
        }
		if(peer->del_pending) {
			 zombies++;
		}
        rc = njt_http_upstream_api_compose_one_server(r, peer, detailed, server_comma,
                0,
                out,0,*peers->name);
		
        if (rc != NJT_OK) {
            njt_http_upstream_rr_peers_unlock(peers);
            return rc;
        }
        server_comma = 1;
    }

    backup = peers->next;
    if (backup != NULL) {
        for (peer = backup->peer; peer != NULL; peer = peer->next) {
			
            /*only compose one server*/
            if (id >= 0) {
                if (peer->id == (njt_uint_t)id ) {
                    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "find the backup server %u", id);
				
					peer_node = peer;
                    rc = njt_http_upstream_api_compose_one_server(r, peer_node, detailed, 0, 1, out,0,*peers->name);
                    njt_http_upstream_rr_peers_unlock(peers);
                    return rc;
                }
                continue;
            }
			if(peer->del_pending) {
			 zombies++;
			}
            rc = njt_http_upstream_api_compose_one_server(r, peer, detailed, server_comma,
                    1,
                    out,0,*peers->name);
		

            if (rc != NJT_OK) {
                njt_http_upstream_rr_peers_unlock(peers);
                return rc;
            }
            server_comma = 1;
        }
    }
	if(detailed == 0) {
		for (peer = peers->parent_node; peer != NULL; peer = peer->next) {
				
				if(peer->parent_id == -1)
					continue;
				peer_node = peer;
				/*only compose one server*/
				if (id >= 0) {
					if (peer->id == (njt_uint_t)id || peer->parent_id == (njt_int_t)id) {
						njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
									   "find the backup server %u", id);
						
						
						rc = njt_http_upstream_api_compose_one_server(r, peer_node, detailed, 0, peer_node->set_backup, out,1,*peers->name);
						njt_http_upstream_rr_peers_unlock(peers);
						return rc;
					}
					continue;
				}
				rc = njt_http_upstream_api_compose_one_server(r, peer_node, detailed, server_comma,
						peer_node->set_backup,
						out,1,*peers->name);
			

				if (rc != NJT_OK) {
					njt_http_upstream_rr_peers_unlock(peers);
					return rc;
				}
				server_comma = 1;
			}
	}

	
    njt_http_upstream_rr_peers_unlock(peers);

    /*The server isn't found*/
    if (id >= 0) {
        return NJT_HTTP_UPS_API_SRV_NOT_FOUND;
    }

    njt_str_set(&insert, "]");
    rc = njt_http_upstream_api_insert_out_str(r, out, &insert);

    if (rc != NJT_OK) {
        return NJT_HTTP_UPS_API_INTERNAL_ERROR;
    }
    if (detailed) {
		if(keep_alive == 0) {
			njt_str_set(&insert, ",\"keepalive\":0");
		} else {
			njt_str_set(&insert, ",\"keepalive\":1");
		}
		rc = njt_http_upstream_api_insert_out_str(r, out, &insert);
		
		if (rc != NJT_OK) {
			return NJT_HTTP_UPS_API_INTERNAL_ERROR;
		}

		if(zombies == 0) {
			njt_str_set(&insert, ",\"zombies\":0");
			rc = njt_http_upstream_api_insert_out_str(r, out, &insert);
		} else {
			buf.len = 64;
			buf.data = njt_pcalloc(r->pool,buf.len);
			if(buf.data) {
				buf.len = njt_sprintf(buf.data, "%d",zombies) - buf.data;
			}
			njt_str_set(&insert, ",\"zombies\":");
			rc = njt_http_upstream_api_insert_out_str(r, out, &insert);
			rc = njt_http_upstream_api_insert_out_str(r, out, &buf);
		}
		//rc = njt_http_upstream_api_insert_out_str(r, out, &insert);

		if (rc != NJT_OK) {
			return NJT_HTTP_UPS_API_INTERNAL_ERROR;
		}
		
		njt_str_set(&insert, ",\"zone\":\"");
		rc = njt_http_upstream_api_insert_out_str(r, out, &insert);

		if (rc != NJT_OK) {
			return NJT_HTTP_UPS_API_INTERNAL_ERROR;
		}
		//njt_str_set(&insert, zone_name);
		rc = njt_http_upstream_api_insert_out_str(r, out, &zone_name);

		if (rc != NJT_OK) {
			return NJT_HTTP_UPS_API_INTERNAL_ERROR;
		}

		/////
		njt_str_set(&insert, "\"");
		rc = njt_http_upstream_api_insert_out_str(r, out, &insert);

		if (rc != NJT_OK) {
			return NJT_HTTP_UPS_API_INTERNAL_ERROR;
		}
		
        njt_str_set(&insert, "}");
        rc = njt_http_upstream_api_insert_out_str(r, out, &insert);

        if (rc != NJT_OK) {
            return NJT_HTTP_UPS_API_INTERNAL_ERROR;
        }
    }

    if (comma) {
        njt_str_set(&insert, ",");
        rc = njt_http_upstream_api_insert_out_str(r, out, &insert);

        if (rc != NJT_OK) {
            return NJT_HTTP_UPS_API_INTERNAL_ERROR;
        }
    }

    return NJT_OK;
}

static njt_int_t
njt_stream_upstream_api_process_get(njt_http_request_t *r,
                                  void *cf,
                                  ssize_t server_id, njt_flag_t detailed, njt_chain_t *out)
{
    njt_int_t                       rc;
    njt_uint_t                      i,number;
    njt_stream_upstream_srv_conf_t   *uscf, **uscfp;
    njt_stream_upstream_main_conf_t  *umcf;
    njt_flag_t                     comma;
    njt_str_t                      insert;
    njt_stream_upstream_rr_peers_t   *peers;
	njt_stream_upstream_srv_conf_t *target_uscf = cf;
	njt_str_t                       zone_name = njt_string("");

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
        rc = njt_stream_upstream_api_compose_one_upstream(zone_name, r, peers, server_id, detailed,
                0, out);

        return rc;
    }

    /*get all the upstreams' server information*/
   
    uscfp = umcf->upstreams.elts;


    njt_str_set(&insert, "{");
    rc = njt_http_upstream_api_insert_out_str(r, out, &insert);

    if (rc != NJT_OK) {
        return  NJT_HTTP_UPS_API_INTERNAL_ERROR;
    }

    /*Go throught the upstreams and compose the output content*/
    number = 0;
   for (i = 0; i < umcf->upstreams.nelts; i++) {
	uscf = uscfp[i];
	if (uscf != NULL  && uscf->shm_zone != NULL)
	  number ++;
   }
    for (i = 0; i < umcf->upstreams.nelts; i++) {

        uscf = uscfp[i];
#if (NJT_HTTP_UPSTREAM_ZONE)
	if (uscf == NULL || uscf->shm_zone == NULL)
	   continue;
	zone_name = uscf->shm_zone->shm.name;
#endif
        peers = (njt_stream_upstream_rr_peers_t *)uscf->peer.data;

        /*insert name*/
        njt_str_set(&insert, "\"");
        rc = njt_http_upstream_api_insert_out_str(r, out, &insert);

        if (rc != NJT_OK) {
            return NJT_HTTP_UPS_API_INTERNAL_ERROR;
        }

        rc = njt_http_upstream_api_insert_out_str(r, out, &uscf->host);
        if (rc != NJT_OK) {
            return NJT_HTTP_UPS_API_INTERNAL_ERROR;
        }

        njt_str_set(&insert, "\":");
        rc = njt_http_upstream_api_insert_out_str(r, out, &insert);

        if (rc != NJT_OK) {
            return NJT_HTTP_UPS_API_INTERNAL_ERROR;
        }

        /*go through all the upstreams and compose all the servers' info*/
	number--;
        //comma = (i < umcf->upstreams.nelts - 1);
        comma = (number > 0);

        rc = njt_stream_upstream_api_compose_one_upstream(zone_name,r, peers, -1, detailed, comma,
                out);
        if (rc != NJT_OK) {
            return rc;
        }
    }

    njt_str_set(&insert, "}");
    rc = njt_http_upstream_api_insert_out_str(r, out, &insert);

    if (rc != NJT_OK) {
        return NJT_HTTP_UPS_API_INTERNAL_ERROR;
    }

    return NJT_OK;
}

static njt_int_t
njt_http_upstream_api_process_get(njt_http_request_t *r,
                                  void *cf,
                                  ssize_t server_id, njt_flag_t detailed, njt_chain_t *out)
{
    njt_int_t                       rc;
    njt_uint_t                      i,number;
    njt_http_upstream_srv_conf_t   *uscf, **uscfp;
    njt_http_upstream_main_conf_t  *umcf;
    njt_flag_t                     comma;
    njt_str_t                      insert;
    njt_http_upstream_rr_peers_t   *peers;
	njt_str_t                       zone_name = njt_string("");
	njt_flag_t                      keep_alive;
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
        rc = njt_http_upstream_api_compose_one_upstream(keep_alive,zone_name, r, peers, server_id, detailed,
                0, out);

        return rc;
    }

    /*get all the upstreams' server information*/
    umcf = njt_http_cycle_get_module_main_conf(njet_master_cycle, njt_http_upstream_module);
	 if(umcf == NULL) {
		 rc = NJT_HTTP_UPS_API_PATH_NOT_FOUND;
		 return rc;
	 }

    uscfp = umcf->upstreams.elts;


    njt_str_set(&insert, "{");
    rc = njt_http_upstream_api_insert_out_str(r, out, &insert);

    if (rc != NJT_OK) {
        return  NJT_HTTP_UPS_API_INTERNAL_ERROR;
    }

    /*Go throught the upstreams and compose the output content*/
    number = 0;
   for (i = 0; i < umcf->upstreams.nelts; i++) {
	uscf = uscfp[i];
	if (uscf != NULL  && uscf->shm_zone != NULL)
	  number ++;
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

        /*insert name*/
        njt_str_set(&insert, "\"");
        rc = njt_http_upstream_api_insert_out_str(r, out, &insert);

        if (rc != NJT_OK) {
            return NJT_HTTP_UPS_API_INTERNAL_ERROR;
        }

        rc = njt_http_upstream_api_insert_out_str(r, out, &uscf->host);
        if (rc != NJT_OK) {
            return NJT_HTTP_UPS_API_INTERNAL_ERROR;
        }

        njt_str_set(&insert, "\":");
        rc = njt_http_upstream_api_insert_out_str(r, out, &insert);

        if (rc != NJT_OK) {
            return NJT_HTTP_UPS_API_INTERNAL_ERROR;
        }

        /*go through all the upstreams and compose all the servers' info*/
	number--;
        //comma = (i < umcf->upstreams.nelts - 1);
        comma = (number > 0);
		
        rc = njt_http_upstream_api_compose_one_upstream(keep_alive,zone_name,r, peers, -1, detailed, comma,
                out);
        if (rc != NJT_OK) {
            return rc;
        }
    }

    njt_str_set(&insert, "}");
    rc = njt_http_upstream_api_insert_out_str(r, out, &insert);

    if (rc != NJT_OK) {
        return NJT_HTTP_UPS_API_INTERNAL_ERROR;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_api_json_2_peer(njt_json_manager *json_manager,
                                  njt_http_upstream_api_peer_t *json_peer,
                                  njt_flag_t  server_flag,njt_http_request_t *r,njt_flag_t proto) //proto  0 http,1 stream
{
    njt_int_t          rc;
    njt_json_element  *items;
    njt_int_t          value;
	njt_str_t          data;
    rc = NJT_OK;
	njt_str_t  key;

    //items = json_manager->json_keyval->elts;

	njt_str_set(&key,"server");
	rc = njt_struct_top_find(json_manager, &key, &items);
	if(rc == NJT_OK){
		if(items->type != NJT_JSON_STR) {
			 rc = NJT_HTTP_UPS_API_INVALID_JSON_BODY;
			 return rc;
		}
		json_peer->server = items->strval;
	}
	njt_str_set(&key,"weight");
	rc = njt_struct_top_find(json_manager, &key, &items);
	if(rc == NJT_OK){
		if (items->type == NJT_JSON_INT) {
				json_peer->weight = items->intval;
            }  else if (items->type == NJT_JSON_STR) {
                value = njt_atoi(items->strval.data, items->strval.len);
                if (value < 0) {
					 json_peer->msg = items->strval;
                     rc = NJT_HTTP_UPS_API_WEIGHT_ERROR;
                     return rc;
                }

                json_peer->weight = value;

            } else {
				json_peer->msg = items->strval;
                rc = NJT_HTTP_UPS_API_WEIGHT_ERROR;
                return rc;
            } 
	}
	njt_str_set(&key,"max_conns");
	rc = njt_struct_top_find(json_manager, &key, &items);
	if(rc == NJT_OK){
		if (items->type == NJT_JSON_INT) {
				json_peer->max_conns = items->intval;
            }  else if (items->type == NJT_JSON_STR) {
                value = njt_atoi(items->strval.data, items->strval.len);
                if (value < 0) {
                     rc = NJT_HTTP_UPS_API_INVALID_JSON_BODY;
                     return rc;
                }

                json_peer->max_conns = value;

            } else {
                rc = NJT_HTTP_UPS_API_INVALID_JSON_BODY;
                return rc;
            } 
	}
	njt_str_set(&key,"max_fails");
	rc = njt_struct_top_find(json_manager, &key, &items);
	if(rc == NJT_OK){
		if (items->type == NJT_JSON_INT) {
				json_peer->max_fails = items->intval;
            }  else if (items->type == NJT_JSON_STR) {
                value = njt_atoi(items->strval.data, items->strval.len);
                if (value < 0) {
                     rc = NJT_HTTP_UPS_API_INVALID_JSON_BODY;
                     return rc;
                }

                json_peer->max_fails = value;

            } else {
                rc = NJT_HTTP_UPS_API_INVALID_JSON_BODY;
                return rc;
            } 
	}
	njt_str_set(&key,"down");
	rc = njt_struct_top_find(json_manager, &key, &items);
	if(rc == NJT_OK){
		if (items->type == NJT_JSON_BOOL) {
				 json_peer->down = items->bval;
            }  else if (items->type == NJT_JSON_STR) {
                if (njt_strncmp(items->strval.data, "false", 5) == 0) {

                    json_peer->down = 0;
                } else if (njt_strncmp(items->strval.data, "true", 4) == 0) {

                    json_peer->down = 1;
                } else {

                    rc = NJT_HTTP_UPS_API_INVALID_JSON_BODY;
                    return rc;
                }

            } else {
                rc = NJT_HTTP_UPS_API_INVALID_JSON_BODY;
                return rc;
            } 
	}
	njt_str_set(&key,"backup");
	rc = njt_struct_top_find(json_manager, &key, &items);
	if(rc == NJT_OK){
		if (items->type == NJT_JSON_BOOL) {
				 json_peer->backup = items->bval;
            }  else if (items->type == NJT_JSON_STR) {
                if (njt_strncmp(items->strval.data, "false", 5) == 0) {

                    json_peer->backup = 0;
                } else if (njt_strncmp(items->strval.data, "true", 4) == 0) {

                    json_peer->backup = 1;
                } else {

                    rc = NJT_HTTP_UPS_API_INVALID_JSON_BODY;
                    return rc;
                }

            } else {
                rc = NJT_HTTP_UPS_API_INVALID_JSON_BODY;
                return rc;
            } 
	}
	njt_str_set(&key,"drain");
	rc = njt_struct_top_find(json_manager, &key, &items);
	if(rc == NJT_OK){
		if (items->type == NJT_JSON_BOOL) {
				 json_peer->drain = items->bval;
            }  else if (items->type == NJT_JSON_STR) {
                if (njt_strncmp(items->strval.data, "false", 5) == 0) {

                    json_peer->drain = 0;
                } else if (njt_strncmp(items->strval.data, "true", 4) == 0) {

                    json_peer->drain = 1;
                } else {

                    rc = NJT_HTTP_UPS_API_INVALID_JSON_BODY;
                    return rc;
                }

            } else {
                rc = NJT_HTTP_UPS_API_INVALID_JSON_BODY;
                return rc;
            } 
	}
	njt_str_set(&key,"fail_timeout");
	rc = njt_struct_top_find(json_manager, &key, &items);
	 if (rc == NJT_OK) {

            if (items->type == NJT_JSON_INT) {
                json_peer->fail_timeout = items->intval;

            } else if (items->type == NJT_JSON_STR) {

				json_peer->fail_timeout = njt_parse_time(&items->strval, 1);

            } else {
                rc = NJT_HTTP_UPS_API_INVALID_JSON_BODY;
                return rc;
            }
        }
	njt_str_set(&key,"slow_start");
	rc = njt_struct_top_find(json_manager, &key, &items);
        if (rc == NJT_OK) {
			   if (items->type == NJT_JSON_INT) {
                json_peer->slow_start = items->intval;

            } else if (items->type == NJT_JSON_STR) {

				json_peer->slow_start = njt_parse_time(&items->strval, 1);

            } else {
                rc = NJT_HTTP_UPS_API_INVALID_JSON_BODY;
                return rc;
            }

        }
		njt_str_set(&key,"route");
		rc = njt_struct_top_find(json_manager, &key, &items);

         if (rc == NJT_OK) {  //rc = NJT_HTTP_UPS_API_INVALID_JSON_BODY;
			 if (items->type == NJT_JSON_STR) {
                json_peer->route = items->strval;
				if(json_peer->route.len > 32) {
					 rc = NJT_HTTP_UPS_API_ROUTE_INVALID_LEN;
					 return rc;
				}
            } else if(items->type == NJT_JSON_INT){
				data.len = 64;
				data.data = njt_pcalloc(r->pool,data.len);
				if(data.data == NULL) {
					rc = NJT_HTTP_UPS_API_INVALID_JSON_BODY;
					 return rc;
				}
				data.len = njt_snprintf(data.data,data.len,"%d",items->intval) - data.data;
				json_peer->route = data;
            } else {
				rc = NJT_HTTP_UPS_API_INVALID_JSON_BODY;
                return rc;
			}

            
        }

	rc = NJT_OK;


    /*For post*/
    if (server_flag) {

        if (json_peer->server.data == NULL || json_peer->server.len == 0) {
            rc = NJT_HTTP_UPS_API_MISS_SRV;
        }

    } else {

        if (json_peer->server.data || json_peer->server.len) {
          //  rc = NJT_HTTP_UPS_API_MODIFY_SRV;
        }
    }

    return rc;
}

static void
njt_stream_upstream_api_patch(njt_http_request_t *r)
{

    njt_stream_upstream_rr_peers_t       *peers, *backup, *target_peers;
    njt_stream_upstream_api_ctx_t       *ctx;
    njt_json_manager                   json_body;
    njt_str_t                          json_str;
    njt_chain_t                        *body_chain;
    njt_chain_t                        out;
    njt_int_t                          rc;
    ssize_t                            len;
	njt_url_t                          u;
    njt_stream_upstream_rr_peer_t        *peer;// *prev;
    njt_uint_t                         server_id;
    //njt_str_t                          server;
	u_char                             *port,*last;
	njt_str_t  zone_name = njt_string("");


    ctx = njt_stream_get_module_ctx(r, njt_http_upstream_api_module);
    if (ctx == NULL) {

        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "ctx is missing %s",
                      __func__);
        goto error;
    }

    peers = ctx->peers;
    if (peers == NULL) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "peers is missing %s",
                      __func__);
        goto error;
    }

    rc = NJT_OK;

    body_chain = r->request_body->bufs;
    if (body_chain && body_chain->next) {
        /*The post body is too large*/
        rc = NJT_HTTP_UPS_API_TOO_LARGE_BODY;
        goto out;
    }

    out.next = NULL;
    out.buf = NULL;

    /*check the sanity of the json body*/
    json_str.data = body_chain->buf->pos;
    json_str.len = body_chain->buf->last - body_chain->buf->pos;

    rc = njt_json_2_structure(&json_str, &json_body, r->pool);
    if (rc != NJT_OK) {
        rc = NJT_HTTP_UPS_API_INVALID_JSON_PARSE;
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

    /*initialize the jason peer. Other items other than the following are all zero*/
    rc = njt_http_upstream_api_json_2_peer(&json_body, &json_peer, 0,r,1);
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
			
			njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "url data allocate error.");
			goto out;
		}

		njt_cpystrn(u.url.data, json_peer.server.data, json_peer.server.len + 1);
		u.url.len = json_peer.server.len;
		u.default_port = 80;

		if (njt_parse_url(r->pool, &u) != NJT_OK) {
			rc = NJT_HTTP_UPS_API_INVALID_SRV_ARG;
			if (u.err) {
				njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
							  "%s in upstream \"%V\"", u.err, &u.url);
			}
			goto out;
		}
		if(u.naddrs == 1 && json_peer.server.len <= u.addrs[0].name.len && njt_strncmp(json_peer.server.data,u.addrs[0].name.data,json_peer.server.len) == 0){
		  json_peer.domain = 0;  //ip
		} else {
			json_peer.domain = 1;  //domain name
		}

		if(json_peer.domain == 1) {
			rc = NJT_HTTP_UPS_API_INVALID_SRV_ARG;
			goto out;
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
	 for (peer = peers->peer; peer != NULL;  peer = peer->next) {
        if (peer->id == (njt_uint_t)server_id ) {
            njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0, "find the server %u",
                           server_id);

            break;
        } 
    }
    backup = peers->next;  
    if (peer == NULL && backup) {
        target_peers = backup;
        for (peer = backup->peer; peer;  peer = peer->next) {
            if (peer->id == (njt_uint_t)server_id) {
                njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "find the backup server %u", server_id);
                break;
            }
        }
    } 
	if(peer == NULL) {
		for (peer = peers->parent_node; peer;  peer = peer->next) {

            if (peer->id == server_id && peer->parent_id == (njt_int_t)server_id) {
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
     }
	 
	if(json_peer.drain == 1) { //patch
		peer->hc_down  = 100 + peer->hc_down;
	} 
		
	 if (json_peer.server.len  > 0) {
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
			njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
						  "peer sockaddr allocate error.");
			goto out;
		}
		 peer->name.data = njt_slab_calloc_locked(peers->shpool, u.addrs->name.len + 1);
		if (peer->name.data == NULL) {

			rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
			njt_stream_upstream_rr_peers_unlock(peers);
			njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
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

    njt_stream_upstream_rr_peers_unlock(peers);

out:

    if (rc != NJT_OK) {

        rc = njt_http_upstream_api_err_out(r, rc,&json_peer.msg, &out);
        if (rc != NJT_OK) {
            goto error;
        }

        goto send;
    }
	
    r->headers_out.content_type_len = sizeof("text/plain") - 1;
    njt_str_set(&r->headers_out.content_type, "text/plain");
    r->headers_out.content_type_lowcase = NULL;
	r->headers_out.status = NJT_HTTP_OK;
    /*return the current servers*/
	

	//rc = njt_http_upstream_api_add_server_retrun(r,peer,0,back,&out);

    rc = njt_stream_upstream_api_compose_one_upstream(zone_name,r, ctx->peers, server_id, 0,
           0, &out);
    if (rc != NJT_OK) {
        goto error;
    }

send:
    len = njt_http_upstream_api_out_len(&out);
	r->headers_out.content_length_n = len;
    
    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    rc = njt_http_send_header(r);

    if (rc == NJT_ERROR || rc > NJT_OK || r->header_only) {
        goto error;
    }

    rc = njt_http_output_filter(r, &out);
    if (rc == NJT_OK) {
        return;
    }

error:
    njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
    return;
}

static void
njt_http_upstream_api_patch(njt_http_request_t *r)
{

    njt_http_upstream_rr_peers_t       *peers, *backup, *target_peers;
    njt_http_upstream_api_ctx_t       *ctx;
    njt_json_manager                   json_body;
    njt_str_t                          json_str;
    njt_chain_t                        *body_chain;
    njt_chain_t                        out;
    njt_int_t                          rc;
    ssize_t                            len;
	njt_url_t                          u;
    njt_http_upstream_rr_peer_t        *peer;// *prev;
    njt_uint_t                         server_id;
    njt_str_t                          server;
	u_char                             *port,*last;
	njt_str_t  zone_name = njt_string("");


    ctx = njt_http_get_module_ctx(r, njt_http_upstream_api_module);
    if (ctx == NULL) {

        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "ctx is missing %s",
                      __func__);
        goto error;
    }

    peers = ctx->peers;
    if (peers == NULL) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "peers is missing %s",
                      __func__);
        goto error;
    }

    rc = NJT_OK;

    body_chain = r->request_body->bufs;
    if (body_chain && body_chain->next) {
        /*The post body is too large*/
        rc = NJT_HTTP_UPS_API_TOO_LARGE_BODY;
        goto out;
    }

    out.next = NULL;
    out.buf = NULL;

    /*check the sanity of the json body*/
    json_str.data = body_chain->buf->pos;
    json_str.len = body_chain->buf->last - body_chain->buf->pos;

    rc = njt_json_2_structure(&json_str, &json_body, r->pool);
    if (rc != NJT_OK) {
        rc = NJT_HTTP_UPS_API_INVALID_JSON_PARSE;
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

    /*initialize the jason peer. Other items other than the following are all zero*/
    rc = njt_http_upstream_api_json_2_peer(&json_body, &json_peer, 0,r,0);
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
			
			njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "url data allocate error.");
			goto out;
		}

		njt_cpystrn(u.url.data, json_peer.server.data, json_peer.server.len + 1);
		u.url.len = json_peer.server.len;
		u.default_port = 80;

		if (njt_parse_url(r->pool, &u) != NJT_OK) {
			rc = NJT_HTTP_UPS_API_INVALID_SRV_ARG;
			if (u.err) {
				njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
							  "%s in upstream \"%V\"", u.err, &u.url);
			}
			goto out;
		}
		if(u.naddrs == 1 && json_peer.server.len <= u.addrs[0].name.len && njt_strncmp(json_peer.server.data,u.addrs[0].name.data,json_peer.server.len) == 0){
		  json_peer.domain = 0;  //ip
		} else {
			json_peer.domain = 1;  //domain name
		}

		if(json_peer.domain == 1) {
			rc = NJT_HTTP_UPS_API_INVALID_SRV_ARG;
			goto out;
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

	njt_http_upstream_rr_peers_wlock(peers);
    target_peers = peers;
	 for (peer = peers->peer; peer != NULL;  peer = peer->next) {
        if (peer->id == (njt_uint_t)server_id ) {
            njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0, "find the server %u",
                           server_id);

            break;
        } 
    }
    backup = peers->next;  
    if (peer == NULL && backup) {
        target_peers = backup;
        for (peer = backup->peer; peer;  peer = peer->next) {
            if (peer->id == (njt_uint_t)server_id) {
                njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "find the backup server %u", server_id);
                break;
            }
        }
    } 
	if(peer == NULL) {
		for (peer = peers->parent_node; peer;  peer = peer->next) {

            if (peer->id == server_id && peer->parent_id == (njt_int_t)server_id) {
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
     }
	  //patch
		if(json_peer.drain == 1) {
			peer->hc_down  = 100 + peer->hc_down;
		}
	 
	 if (json_peer.route.len  > 0) {
		 if(peer->route.len < json_peer.route.len) {
			 njt_slab_free_locked(peers->shpool,peer->route.data);

			  peer->route.data = njt_slab_calloc_locked(peers->shpool, json_peer.route.len);
			   if (peer->route.data == NULL) {
                    njt_http_upstream_rr_peers_unlock(peers);
                    goto error;
                }
				}
				njt_memcpy(peer->route.data, json_peer.route.data,json_peer.route.len);
                peer->route.len = json_peer.route.len;


		 
     }
	 if (json_peer.server.len  > 0) {
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
			njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
						  "peer sockaddr allocate error.");
			goto out;
		}
		 peer->name.data = njt_slab_calloc_locked(peers->shpool, u.addrs->name.len + 1);
		if (peer->name.data == NULL) {

			rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
			njt_http_upstream_rr_peers_unlock(peers);
			njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
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

    njt_http_upstream_rr_peers_unlock(peers);

out:

    if (rc != NJT_OK) {

        rc = njt_http_upstream_api_err_out(r, rc,&json_peer.msg, &out);
        if (rc != NJT_OK) {
            goto error;
        }

        goto send;
    }
	
    r->headers_out.content_type_len = sizeof("text/plain") - 1;
    njt_str_set(&r->headers_out.content_type, "text/plain");
    r->headers_out.content_type_lowcase = NULL;
	r->headers_out.status = NJT_HTTP_OK;
    /*return the current servers*/
	

	//rc = njt_http_upstream_api_add_server_retrun(r,peer,0,back,&out);

    rc = njt_http_upstream_api_compose_one_upstream(ctx->keep_alive,zone_name,r, ctx->peers, server_id, 0,
           0, &out);
    if (rc != NJT_OK) {
        goto error;
    }

send:
    len = njt_http_upstream_api_out_len(&out);
	r->headers_out.content_length_n = len;
    
    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    rc = njt_http_send_header(r);

    if (rc == NJT_ERROR || rc > NJT_OK || r->header_only) {
        goto error;
    }

    rc = njt_http_output_filter(r, &out);
    if (rc == NJT_OK) {
        return;
    }

error:
    njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
    return;
}


static njt_int_t
njt_stream_upstream_api_add_server_retrun(njt_http_request_t *r,
        njt_stream_upstream_rr_peer_t *peer, njt_flag_t comma,
        njt_flag_t backup, njt_chain_t *out)
{
    njt_buf_t                      *b;
    ssize_t                        len = 0;
	njt_str_t                      *pname;
	njt_uint_t                      id;
	njt_http_upstream_peer_code_t  peer_code;
	njt_flag_t is_parent = 0;

	njt_memzero(&peer_code,sizeof(njt_http_upstream_peer_code_t));
    /*if the buf's left size is big enough to hold one server*/
    len = njt_stream_upstream_api_one_server_strlen(len,0, peer,is_parent,&peer_code);

    b =  njt_http_upstream_api_get_out_buf(r, len, out);
    if (b == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }


		
	 if(peer->parent_id >= 0 && is_parent == 0) {
		b->last = njt_snprintf(b->last, len,
						   "%s{\"id\":%d,\"server\":\"%V\",\"weight\":%d,\"max_conns\": %d,"
						   "\"max_fails\":%d,\"fail_timeout\":\"%ds\",\"slow_start\":\"%ds\","
						   "\"backup\":%s,\"down\":%s}", comma ? "," : "",
						   peer->id, &peer->name, peer->weight, peer->max_conns,
						   peer->max_fails, peer->fail_timeout,peer->slow_start,backup ? "true" : "false",
						   peer->down ? "true" : "false");
	} else {
		pname = (is_parent == 1?(&peer->server):(&peer->name));
		 id =  (is_parent == 1?((njt_uint_t)peer->parent_id):(peer->id));
		b->last = njt_snprintf(b->last, len,
						   "%s{\"id\":%d,\"server\":\"%V\",\"weight\":%d,\"max_conns\": %d,"
						   "\"max_fails\":%d,\"fail_timeout\":\"%ds\",\"slow_start\":\"%ds\","
						   "\"backup\":%s,\"down\":%s}", comma ? "," : "",
						   id, pname, peer->weight, peer->max_conns,
						   peer->max_fails, peer->fail_timeout,peer->slow_start,backup ? "true" : "false",
						   peer->down ? "true" : "false");
	}
		
    

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_api_add_server_retrun(njt_http_request_t *r,
        njt_http_upstream_rr_peer_t *peer, njt_flag_t comma,
        njt_flag_t backup, njt_chain_t *out)
{
    njt_buf_t                      *b;
    ssize_t                        len = 0;
	njt_str_t                      *pname;
	njt_uint_t                      id;
	njt_http_upstream_peer_code_t  peer_code;
	njt_flag_t is_parent = 0;

	njt_memzero(&peer_code,sizeof(njt_http_upstream_peer_code_t));
    /*if the buf's left size is big enough to hold one server*/
    len = njt_http_upstream_api_one_server_strlen(len,0, peer,is_parent,&peer_code);

    b =  njt_http_upstream_api_get_out_buf(r, len, out);
    if (b == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }


		
	 if(peer->parent_id >= 0 && is_parent == 0) {
		b->last = njt_snprintf(b->last, len,
						   "%s{\"id\":%d,\"server\":\"%V\",\"weight\":%d,\"max_conns\": %d,"
						   "\"max_fails\":%d,\"fail_timeout\":\"%ds\",\"slow_start\":\"%ds\",\"route\":\"%V\","
						   "\"backup\":%s,\"down\":%s}", comma ? "," : "",
						   peer->id, &peer->name, peer->weight, peer->max_conns,
						   peer->max_fails, peer->fail_timeout,peer->slow_start,&peer->route,backup ? "true" : "false",
						   peer->down ? "true" : "false");
	} else {
		pname = (is_parent == 1?(&peer->server):(&peer->name));
		 id =  (is_parent == 1?((njt_uint_t)peer->parent_id):(peer->id));
		b->last = njt_snprintf(b->last, len,
						   "%s{\"id\":%d,\"server\":\"%V\",\"weight\":%d,\"max_conns\": %d,"
						   "\"max_fails\":%d,\"fail_timeout\":\"%ds\",\"slow_start\":\"%ds\",\"route\":\"%V\","
						   "\"backup\":%s,\"down\":%s}", comma ? "," : "",
						   id, pname, peer->weight, peer->max_conns,
						   peer->max_fails, peer->fail_timeout,peer->slow_start,&peer->route,backup ? "true" : "false",
						   peer->down ? "true" : "false");
	}
		
    

    return NJT_OK;
}

static void
njt_stream_upstream_api_post(njt_http_request_t *r)
{
	u_char						       *last,*port;
    njt_stream_upstream_rr_peers_t       *peers, *backup, *target_peers;
    njt_slab_pool_t                    *shpool;
    njt_stream_upstream_api_ctx_t       *ctx;
    njt_json_manager                   json_body;
    njt_str_t                          json_str;
	 njt_http_upstream_api_main_conf_t *uclcf;
    njt_chain_t                        *body_chain;
    njt_chain_t                        out;
    njt_int_t                          rc;
	njt_int_t                          parent_id;
	//njt_uint_t                          i;
    ssize_t                            len;
    njt_stream_upstream_rr_peer_t        *peer,*tail_peer;
	njt_stream_upstream_rr_peer_t         new_peer;
    //njt_http_upstream_api_peer_t      json_peer;
    njt_url_t                          u;
    njt_str_t                          name, server;
    njt_str_t                          *peers_name;
	//njt_str_t                           zone_name = njt_string("");
    peer = NULL;

    ctx = njt_http_get_module_ctx(r, njt_http_upstream_api_module);
    if (ctx == NULL) {
        rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
        goto out;
    }

    peers = ctx->peers;
    if (peers == NULL) {
        rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
        goto out;
    }

    rc = NJT_OK;
    body_chain = r->request_body->bufs;
    if (body_chain && body_chain->next) {
        /*The post body is too large*/
        rc = NJT_HTTP_UPS_API_TOO_LARGE_BODY;
        goto out;
    }

    out.next = NULL;
    out.buf = NULL;

    /*check the sanity of the json body*/
    json_str.data = body_chain->buf->pos;
    json_str.len = body_chain->buf->last - body_chain->buf->pos;

    rc = njt_json_2_structure(&json_str, &json_body, r->pool);
    if (rc != NJT_OK) {
        rc = NJT_HTTP_UPS_API_INVALID_JSON_PARSE;
        goto out;
    }

    /*conduct the perform*/
    njt_memzero(&json_peer, sizeof(njt_http_upstream_api_peer_t));

    /*initialize the jason peer. Other items other than the following are all zero*/
    json_peer.weight = 1;
    json_peer.max_fails = 1;
    json_peer.fail_timeout = 10;
	json_peer.drain = -1;
    rc = njt_http_upstream_api_json_2_peer(&json_body, &json_peer, 1,r,1);

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
    shpool = peers->shpool;

    njt_memzero(&u, sizeof(njt_url_t));

    



    u.url.data = njt_pcalloc(r->pool, json_peer.server.len + 1);

    if (u.url.data == NULL) {
        rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "url data allocate error.");
        goto out;
    }
    njt_cpystrn(u.url.data, json_peer.server.data, json_peer.server.len + 1);
    u.url.len = json_peer.server.len;
    u.default_port = 80;

    if (njt_parse_url(r->pool, &u) != NJT_OK) {

        rc = NJT_HTTP_UPS_API_NOT_SUPPORTED_SRV;
        if (u.err) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "%s in upstream \"%V\"", u.err, &u.url);
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
		njt_http_upstream_rr_peers_unlock(peers);

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
		rc = NJT_OK;

	} else if (parent_id == -1) {
	
    peer = njt_slab_calloc_locked(shpool, sizeof(njt_stream_upstream_rr_peer_t));

    if (peer == NULL) {

        rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
        njt_stream_upstream_rr_peers_unlock(peers);
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "peer allocate error.");

        goto out;
    }

    server.data = njt_slab_calloc_locked(shpool, json_peer.server.len + 1);
    if (server.data == NULL) {

        rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
        njt_stream_upstream_rr_peers_unlock(peers);
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "server data allocate error.");

        goto out;
    }

    njt_cpystrn(server.data, json_peer.server.data, json_peer.server.len + 1);
    server.len = json_peer.server.len;
    peer->server = server;

    name.data = njt_slab_calloc_locked(shpool, u.addrs[0].name.len + 1);
    if (name.data == NULL) {

        rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
        njt_stream_upstream_rr_peers_unlock(peers);
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
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
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "peer sockaddr allocate error.");
        goto out;
    }

    njt_memcpy(peer->sockaddr, u.addrs[0].sockaddr, peer->socklen);
	
	peer->id = peers->next_order++;
	peer->parent_id = parent_id;

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
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "backup peers allocate error.");

                goto out;
            }

            peers_name = njt_slab_calloc(peers->shpool, sizeof(njt_str_t));
            if (peers_name == NULL) {
                rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
                njt_stream_upstream_rr_peers_unlock(peers);
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "peers_name allocate error.");

                goto out;
            }

            peers_name->data = njt_slab_calloc(peers->shpool, peers->name->len);
            if (peers_name->data == NULL) {
                rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
                njt_stream_upstream_rr_peers_unlock(peers);
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
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


    target_peers->single = (target_peers->number == 1);
    //target_peers->empty = (target_peers->number == 0);
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

    r->headers_out.content_type_len = sizeof("text/plain") - 1;
    njt_str_set(&r->headers_out.content_type, "text/plain");
    r->headers_out.content_type_lowcase = NULL;
	r->headers_out.status = NJT_HTTP_CREATED;
	if(parent_id != -1) {
		peer = &new_peer;
	}
	rc = njt_stream_upstream_api_add_server_retrun(r,peer,0,json_peer.backup,&out);
    if (rc != NJT_OK) {
        goto error;
    }

send:

    len = njt_http_upstream_api_out_len(&out);
    r->headers_out.content_length_n = len;
	
    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    rc = njt_http_send_header(r);
    if (rc == NJT_ERROR || rc > NJT_OK || r->header_only) {
        goto error;
    }

    rc = njt_http_output_filter(r, &out);

error:

    /*free the malloced memory for u*/
    if (rc == NJT_OK) {
        return;
    }

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
    njt_json_manager                   json_body;
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
	//njt_str_t                           zone_name = njt_string("");
    peer = NULL;

    ctx = njt_http_get_module_ctx(r, njt_http_upstream_api_module);
    if (ctx == NULL) {
        rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
        goto out;
    }

    peers = ctx->peers;
    if (peers == NULL) {
        rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
        goto out;
    }

    rc = NJT_OK;
    body_chain = r->request_body->bufs;
    if (body_chain && body_chain->next) {
        /*The post body is too large*/
        rc = NJT_HTTP_UPS_API_TOO_LARGE_BODY;
        goto out;
    }

    out.next = NULL;
    out.buf = NULL;

    /*check the sanity of the json body*/
    json_str.data = body_chain->buf->pos;
    json_str.len = body_chain->buf->last - body_chain->buf->pos;

    rc = njt_json_2_structure(&json_str, &json_body, r->pool);
    if (rc != NJT_OK) {
        rc = NJT_HTTP_UPS_API_INVALID_JSON_PARSE;
        goto out;
    }

    /*conduct the perform*/
    njt_memzero(&json_peer, sizeof(njt_http_upstream_api_peer_t));

    /*initialize the jason peer. Other items other than the following are all zero*/
    json_peer.weight = 1;
    json_peer.max_fails = 1;
    json_peer.fail_timeout = 10;
	json_peer.drain = -1;

    rc = njt_http_upstream_api_json_2_peer(&json_body, &json_peer, 1,r,0);

    if (rc != NJT_OK) {
		//rc = NJT_HTTP_UPS_API_INVALID_JSON_PARSE;
        goto out;
    }

    /*perform the insert*/
    shpool = peers->shpool;

    njt_memzero(&u, sizeof(njt_url_t));

    



    u.url.data = njt_pcalloc(r->pool, json_peer.server.len + 1);

    if (u.url.data == NULL) {
        rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "url data allocate error.");
        goto out;
    }
    njt_cpystrn(u.url.data, json_peer.server.data, json_peer.server.len + 1);
    u.url.len = json_peer.server.len;
    u.default_port = 80;

    if (njt_parse_url(r->pool, &u) != NJT_OK) {

        rc = NJT_HTTP_UPS_API_NOT_SUPPORTED_SRV;
        if (u.err) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "%s in upstream \"%V\"", u.err, &u.url);
        }
        //goto out;
    }

	

	njt_http_upstream_rr_peers_wlock(peers);
	njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0,
                      "njt_http_upstream_api_post!");

	
	//peers_data = (json_peer.backup > 0?peers->next : peers);
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
				njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
							  "peer route allocate error.");
				goto out;
			}
			njt_cpystrn(new_peer.route.data, json_peer.route.data, json_peer.route.len + 1);
		}
		njt_http_upstream_rr_peers_unlock(peers);
	
		njt_http_upstream_api_create_dynamic_server(r,&new_peer,json_peer.backup);
		rc = NJT_OK;

	} else if (parent_id == -1) {
	
    peer = njt_slab_calloc_locked(shpool, sizeof(njt_http_upstream_rr_peer_t));

    if (peer == NULL) {

        rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
        njt_http_upstream_rr_peers_unlock(peers);
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "peer allocate error.");

        goto out;
    }

    server.data = njt_slab_calloc_locked(shpool, json_peer.server.len + 1);
    if (server.data == NULL) {

        rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
        njt_http_upstream_rr_peers_unlock(peers);
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "server data allocate error.");

        goto out;
    }

    njt_cpystrn(server.data, json_peer.server.data, json_peer.server.len + 1);
    server.len = json_peer.server.len;
    peer->server = server;

    name.data = njt_slab_calloc_locked(shpool, u.addrs[0].name.len + 1);
    if (name.data == NULL) {

        rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
        njt_http_upstream_rr_peers_unlock(peers);
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
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
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "peer sockaddr allocate error.");
        goto out;
    }

    njt_memcpy(peer->sockaddr, u.addrs[0].sockaddr, peer->socklen);
	
	peer->id = peers->next_order++;
	peer->parent_id = parent_id;

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
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
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
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "backup peers allocate error.");

                goto out;
            }

            peers_name = njt_slab_calloc(peers->shpool, sizeof(njt_str_t));
            if (peers_name == NULL) {
                rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
                njt_http_upstream_rr_peers_unlock(peers);
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "peers_name allocate error.");

                goto out;
            }

            peers_name->data = njt_slab_calloc(peers->shpool, peers->name->len);
            if (peers_name->data == NULL) {
                rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
                njt_http_upstream_rr_peers_unlock(peers);
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
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


    target_peers->single = (target_peers->number == 1);
    //target_peers->empty = (target_peers->number == 0);
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

    r->headers_out.content_type_len = sizeof("text/plain") - 1;
    njt_str_set(&r->headers_out.content_type, "text/plain");
    r->headers_out.content_type_lowcase = NULL;
	r->headers_out.status = NJT_HTTP_CREATED;
	if(parent_id != -1) {
		peer = &new_peer;
	}
	rc = njt_http_upstream_api_add_server_retrun(r,peer,0,json_peer.backup,&out);
    if (rc != NJT_OK) {
        goto error;
    }

send:

    len = njt_http_upstream_api_out_len(&out);
    r->headers_out.content_length_n = len;
	
    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    rc = njt_http_send_header(r);
    if (rc == NJT_ERROR || rc > NJT_OK || r->header_only) {
        goto error;
    }

    rc = njt_http_output_filter(r, &out);

error:

    /*free the malloced memory for u*/
    if (rc == NJT_OK) {
        return;
    }

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
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "upstream api ctx allocate error.");
        return NJT_HTTP_UPS_API_INTERNAL_ERROR;
    }

    ctx->peers = peers;
    ctx->id = id;

    njt_stream_set_ctx(r, ctx, njt_http_upstream_api_module);

    rc = njt_http_read_client_request_body(r, njt_stream_upstream_api_patch);

    return rc;
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
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "upstream api ctx allocate error.");
        return NJT_HTTP_UPS_API_INTERNAL_ERROR;
    }

    ctx->peers = peers;
    ctx->id = id;
	ctx->keep_alive = uscf->set_keep_alive;
    njt_http_set_ctx(r, ctx, njt_http_upstream_api_module);

    rc = njt_http_read_client_request_body(r, njt_http_upstream_api_patch);

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
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "upstream api ctx allocate error.");
        return NJT_HTTP_UPS_API_INTERNAL_ERROR;
    }

    ctx->peers = peers;
	ctx->resolver = uscf->resolver;
	ctx->hc_type  = (uscf->hc_type == 0 ?0:2);
    njt_http_set_ctx(r, ctx, njt_http_upstream_api_module);

    rc = njt_http_read_client_request_body(r, njt_stream_upstream_api_post);

    return rc;
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
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "upstream api ctx allocate error.");
        return NJT_HTTP_UPS_API_INTERNAL_ERROR;
    }

    ctx->peers = peers;
	ctx->resolver = uscf->resolver;
	ctx->keep_alive = uscf->set_keep_alive;
	ctx->hc_type  = (uscf->hc_type == 0 ?0:2);
    njt_http_set_ctx(r, ctx, njt_http_upstream_api_module);

    rc = njt_http_read_client_request_body(r, njt_http_upstream_api_post);

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
		peer->hc_checks = 0;
		peer->hc_fails = 0;
		peer->hc_downtime = 0;
		peer->hc_downstart = 0;
		peer->hc_last_passed = 0;
		peer->sent = 0;
		peer->received = 0;
		peer->selected_time = 0;
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
		}
	}
    
    if (rc != NJT_OK) {
        njt_stream_upstream_rr_peers_unlock(peers);
        return rc;
    }

    njt_stream_upstream_rr_peers_unlock(peers);

    /*Output the servers*/
    rc = NJT_HTTP_UPS_API_RESET; //njt_http_upstream_api_compose_one_upstream(zone_name,r, peers, -1, 1, 0, out);
    return rc;

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
		peer->hc_checks = 0;
		peer->hc_fails = 0;
		peer->hc_last_passed = 0;
		peer->hc_downtime = 0;
		peer->hc_downstart = 0;
		peer->total_header_time = 0;
		peer->total_response_time = 0;
		peer->selected_time = 0;

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
    rc = NJT_HTTP_UPS_API_RESET; //njt_http_upstream_api_compose_one_upstream(zone_name,r, peers, -1, 1, 0, out);
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
	njt_stream_upstream_srv_conf_t *uscf = cf;

	njt_str_t zone_name = njt_string("");

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
			target_peers->single = (target_peers->number == 1);
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
					target_peers->single = (target_peers->number == 1);
					//target_peers->empty = (target_peers->number == 0);
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
					njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
								  "upstream api ctx allocate error.");
					return NJT_HTTP_UPS_API_INTERNAL_ERROR;
				}
				ctx->peers = peers;
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

    njt_stream_upstream_rr_peers_unlock(peers);

    /*Output the servers*/
    rc = njt_stream_upstream_api_compose_one_upstream(zone_name,r, peers, -1, 0, 0, out);

    return rc;

}

static njt_int_t
njt_http_upstream_api_process_delete(njt_http_request_t *r,
                                     void *cf,
                                     njt_uint_t id, njt_chain_t *out)
{
    njt_int_t                      rc;
    njt_http_upstream_rr_peers_t   *peers, *backup, *target_peers;
    njt_http_upstream_rr_peer_t    *peer,  *prev, *del_peer,**p;
	njt_flag_t                      del_parent = 0;
	njt_http_upstream_api_ctx_t       *ctx = NULL;
	njt_http_upstream_srv_conf_t *uscf = cf;
	njt_flag_t keep_alive = 0;
	njt_str_t zone_name = njt_string("");

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
			target_peers->single = (target_peers->number == 1);
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
					target_peers->single = (target_peers->number == 1);
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
					njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
								  "upstream api ctx allocate error.");
					return NJT_HTTP_UPS_API_INTERNAL_ERROR;
				}
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

    njt_http_upstream_rr_peers_unlock(peers);

    /*Output the servers*/
    if(ctx) {
	  keep_alive = ctx->keep_alive;
	}
    rc = njt_http_upstream_api_compose_one_upstream(keep_alive,zone_name,r, peers, -1, 0, 0, out);

    return rc;

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

	//parent_list = njt_array_create(r->pool, 4, sizeof(njt_http_upstream_rr_peer_t *));

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
		njt_log_error(NJT_LOG_CRIT, r->connection->log, njt_errno,
                      njt_open_file_n " \"%V\" failed", &state_file);

		njt_stream_upstream_rr_peers_unlock(peers);
		goto failed;
    }

    /*TODO refine the length 512 for malloc*/
    server_info = njt_pcalloc(r->pool, 512);
    if (server_info == NULL) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
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
				njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
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
				njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
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
			njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
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
            njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
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
            njt_log_error(NJT_LOG_ALERT, r->connection->log, njt_errno,
                          njt_close_file_n " \"%V\" failed", &state_file);
        }
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

	//parent_list = njt_array_create(r->pool, 4, sizeof(njt_http_upstream_rr_peer_t *));

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
		njt_log_error(NJT_LOG_CRIT, r->connection->log, njt_errno,
                      njt_open_file_n " \"%V\" failed", &state_file);
		njt_http_upstream_rr_peers_unlock(peers);
		goto failed;
    }

    /*TODO refine the length 512 for malloc*/
    server_info = njt_pcalloc(r->pool, 512);
    if (server_info == NULL) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
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
				njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
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
				njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
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
			njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
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
            njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
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
            njt_log_error(NJT_LOG_ALERT, r->connection->log, njt_errno,
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
                                 njt_chain_t *out)
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
        return rc;
    }

    rc = njt_upstream_api_get_params(path, &upstream, &id,&upstream_type);
    if (rc != NJT_OK) {
        /*PATH not found*/
        return rc;
    }

    rc = njt_upstream_api_params_check(path,r, &upstream, &id, (void **)&uscf, &server_id,upstream_type);
    if (rc != NJT_OK) {
        /*PATH not found*/
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
		/*
		if(upstream_type == 1) {
			rc = njt_http_upstream_api_process_get(r, uscf, server_id, detailed, out);
		} else {
			rc = njt_stream_upstream_api_process_get(r, uscf, server_id, detailed, out);
		}*/
		rc = njt_upstream_api_process_get(r, uscf, server_id, detailed, out);
        break;

    case NJT_HTTP_DELETE:

        rc = njt_http_discard_request_body(r);
        if (rc != NJT_OK) {
            goto out;
        }
		if(path->nelts == 4) { //reset statistics
			/*
			if(upstream_type == 1) {
				rc = njt_http_upstream_api_process_reset(r, uscf, out);
			} else {
				rc = njt_stream_upstream_api_process_reset(r, uscf, out);
			}*/
			rc = njt_upstream_api_process_reset(r, uscf, out);

		} else {
			/*
			if(upstream_type == 1) {
				rc = njt_http_upstream_api_process_delete(r, uscf, server_id, out);
			}else {
				rc = njt_stream_upstream_api_process_delete(r, uscf, server_id, out);
			}*/
			rc = njt_upstream_api_process_delete(r, uscf, server_id, out);
		}

        break;

    case NJT_HTTP_PATCH:
		/*
		if(upstream_type == 1) {
				 rc = njt_http_upstream_api_process_patch(r, uscf, server_id);
			}else {
				 rc = njt_stream_upstream_api_process_patch(r, uscf, server_id);
			}*/
        rc = njt_upstream_api_process_patch(r, uscf, server_id);
        break;

    case NJT_HTTP_POST:
		if(path->nelts >=5) {
			/*
			if(upstream_type == 1) {
				rc = njt_http_upstream_api_process_post(r, uscf);
			}else {
				rc = njt_stream_upstream_api_process_post(r, uscf);
			}*/
			rc = njt_upstream_api_process_post(r, uscf);
		} else {
			rc = NJT_HTTP_UPS_API_PERM_NOT_ALLOWED;
		}
        break;


    default:
        rc = NJT_HTTP_UPS_API_METHOD_NOT_SUPPORTED;
        break;

    }

out:
    /*try to save the upstream servers into the stat file*/
    if (rc == NJT_OK && r->method != NJT_HTTP_GET) {
		/*
		if(upstream_type == 1) {
				 njt_http_upstream_state_save(r, uscf);
			} else {
				 njt_stream_upstream_state_save(r, uscf);
			}*/
			njt_upstream_state_save(r, uscf);
       
    }

    return rc;

}

static njt_int_t
njt_upstream_api_parse_path(njt_http_request_t *r, njt_array_t *path)
{

    u_char                              *p, *sub_p;
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
    len = uri.len - clcf->name.len;

    if (*p == '/') {
        len --;
        p ++;
    }

    while (len > 0) {

        item = njt_array_push(path);
        if (item == NULL) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "array item of path push error.");
            return NJT_ERROR;
        }

        item->data = p;
        sub_p = (u_char *)njt_strchr(p, '/');

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


/*TODO use an error to define the map of the error code and its error message.*/
static njt_int_t
njt_http_upstream_api_err_out(njt_http_request_t *r, njt_int_t code,njt_str_t *msg,
                              njt_chain_t *out)
{
    njt_str_t insert;
    njt_int_t rc;
	njt_http_variable_value_t  *value;
	njt_uint_t                  key;
	u_char                     *low;
    rc = NJT_OK;

    /*We need to clean up the out buf at first.*/
    out->buf = NULL;
    out->next = NULL;

    njt_str_set(&insert, "{\"error\":{\"status\":");
    rc = njt_http_upstream_api_insert_out_str(r, out, &insert);
    if (rc != NJT_OK) {
        return rc;
    }

    r->headers_out.status = NJT_HTTP_NOT_FOUND;
    switch (code) {

    case NJT_HTTP_UPS_API_PATH_NOT_FOUND:
		r->headers_out.status = 404;
        njt_str_set(&insert,
                    "404,\"text\":\"path not found\",\"code\":\"PathNotFound\"}");
        rc = njt_http_upstream_api_insert_out_str(r, out, &insert);
        if (rc != NJT_OK) {
            return rc;
        }
        break;

    case NJT_HTTP_UPS_API_UPS_NOT_FOUND:
		r->headers_out.status = 404;
        njt_str_set(&insert,
                    "404,\"text\":\"upstream not found\",\"code\":\"UpstreamNotFound\"}");
        rc = njt_http_upstream_api_insert_out_str(r, out, &insert);
        if (rc != NJT_OK) {
            return rc;
        }
        break;

    case NJT_HTTP_UPS_API_UNKNOWN_VERSION:
		r->headers_out.status = 404;
        njt_str_set(&insert,
                    "404,\"text\":\"unknown version\",\"code\":\"Unknownversion\"}");
        rc = njt_http_upstream_api_insert_out_str(r, out, &insert);
        if (rc != NJT_OK) {
            return rc;
        }
        break;

    case NJT_HTTP_UPS_API_INVALID_SRVID:
		r->headers_out.status = 400;
        r->headers_out.status = NJT_HTTP_BAD_REQUEST;
        njt_str_set(&insert,
                    "400,\"text\":\"invalid server id\",\"code\":\"UpStreamBadServerId\"}");
        rc = njt_http_upstream_api_insert_out_str(r, out, &insert);
        if (rc != NJT_OK) {
            return rc;
        }
        break;

    case NJT_HTTP_UPS_API_SRV_NOT_FOUND:
		r->headers_out.status = 404;
        njt_str_set(&insert,
                    "404,\"text\":\"server not found\",\"code\":\"UpStreamServerNotFound\"}");
        rc = njt_http_upstream_api_insert_out_str(r, out, &insert);
        if (rc != NJT_OK) {
            return rc;
        }
        break;

    case NJT_HTTP_UPS_API_PERM_NOT_ALLOWED:
		r->headers_out.status = 405;
        njt_str_set(&insert,
                    "405,\"text\":\"method not supported\",\"code\":\"MethodNotSupported\"}");
        rc = njt_http_upstream_api_insert_out_str(r, out, &insert);
        if (rc != NJT_OK) {
            return rc;
        }
        break;

    case NJT_HTTP_UPS_API_STATIC_UPS:
		r->headers_out.status = 400;
        njt_str_set(&insert,
                    "400,\"text\":\"upstream is static\",\"code\":\"UpstreamStatic\"}");
        rc = njt_http_upstream_api_insert_out_str(r, out, &insert);
        if (rc != NJT_OK) {
            return rc;
        }
        break;

    case NJT_HTTP_UPS_API_SRV_NOT_REMOVALBE:
		r->headers_out.status = 400;
        njt_str_set(&insert,
                    "400,\"text\":\"server not removeable\",\"code\":\"UpstreamServerImmutable\"}");
        rc = njt_http_upstream_api_insert_out_str(r, out, &insert);
        if (rc != NJT_OK) {
            return rc;
        }
        break;

    case NJT_HTTP_UPS_API_METHOD_NOT_SUPPORTED:
		r->headers_out.status = 405;
        njt_str_set(&insert,
                    "405,\"text\":\"method not supported\",\"code\":\"MethodNotSupported\"}");
        rc = njt_http_upstream_api_insert_out_str(r, out, &insert);
        if (rc != NJT_OK) {
            return rc;
        }
        break;

    case NJT_HTTP_UPS_API_TOO_LARGE_BODY:
		r->headers_out.status = 405;
        njt_str_set(&insert,
                    "405,\"text\":\"too large post body\",\"code\":\"TooLargePostBody\"}");
        rc = njt_http_upstream_api_insert_out_str(r, out, &insert);
        if (rc != NJT_OK) {
            return rc;
        }
        break;
	case NJT_HTTP_UPS_API_ROUTE_INVALID_LEN:
		r->headers_out.status = 400;
		njt_str_set(&insert,
                    "400,\"text\":\"route is longer than 32\",\"code\":\"UpstreamBadRoute\"}");
        rc = njt_http_upstream_api_insert_out_str(r, out, &insert);
        if (rc != NJT_OK) {
            return rc;
        }
        break;
    case NJT_HTTP_UPS_API_INVALID_JSON_BODY:
		r->headers_out.status = 400;
		if(msg != NULL && msg->data != NULL && msg->len > 0) {
			njt_str_set(&insert,
                    "400,\"text\":\"unknown parameter \\\"");
			rc = njt_http_upstream_api_insert_out_str(r, out, &insert);

			//njt_str_set(&insert,msg);
			rc = njt_http_upstream_api_insert_out_str(r, out, msg);

			njt_str_set(&insert,
                    "\\\"\",\"code\":\"UpstreamConfFormatError\"}");
			rc = njt_http_upstream_api_insert_out_str(r, out, &insert);

		} else {
			r->headers_out.status = 405;
			njt_str_set(&insert,
						"405,\"text\":\"invalid json body\",\"code\":\"InvalidJsonBody\"}");
			rc = njt_http_upstream_api_insert_out_str(r, out, &insert);
		}
        if (rc != NJT_OK) {
            return rc;
        }
        break;

    case NJT_HTTP_UPS_API_MISS_SRV:
		r->headers_out.status = 400;
        njt_str_set(&insert,
                    "400,\"text\":\"missing \\\"server\\\" argument \",\"code\":\"UpstreamConfFormatError\"}");
        rc = njt_http_upstream_api_insert_out_str(r, out, &insert);
        if (rc != NJT_OK) {
            return rc;
        }
        break;

    case NJT_HTTP_UPS_API_MODIFY_SRV:
		r->headers_out.status = 405;
        njt_str_set(&insert,
                    "405,\"text\":\"try to modify server\",\"code\":\"TryToModifyServer\"}");
        rc = njt_http_upstream_api_insert_out_str(r, out, &insert);
        if (rc != NJT_OK) {
            return rc;
        }
        break;

    case NJT_HTTP_UPS_API_NOT_SUPPORTED_SRV:
		r->headers_out.status = 405;
        njt_str_set(&insert,
                    "405,\"text\":\"domain name isn't supported\",\"code\":\"DomainName\"}");
        rc = njt_http_upstream_api_insert_out_str(r, out, &insert);
        if (rc != NJT_OK) {
            return rc;
        }
        break;
	case NJT_HTTP_UPS_API_INVALID_JSON_PARSE:
		r->headers_out.status = 415;
		njt_str_set(&insert,
                    "415,\"text\":\"json error\",\"code\":\"JsonError\"}");
        rc = njt_http_upstream_api_insert_out_str(r, out, &insert);
        if (rc != NJT_OK) {
            return rc;
        }
        break;
	case NJT_HTTP_UPS_API_NO_RESOLVER:
		r->headers_out.status = 400;
		njt_str_set(&insert,
                    "400,\"text\":\"no resolver defined to resolve "); //,\"code\":\"JsonError\"}");
        rc = njt_http_upstream_api_insert_out_str(r, out, &insert);
		rc = njt_http_upstream_api_insert_out_str(r, out, &json_peer.server);
		njt_str_set(&insert,
                    "\",\"code\":\"UpstreamConfNoResolver\"}");
		rc = njt_http_upstream_api_insert_out_str(r, out, &insert);

        if (rc != NJT_OK) {
            return rc;
        }
        break;
	case NJT_HTTP_UPS_API_WEIGHT_ERROR:
		r->headers_out.status = 400;
		njt_str_set(&insert,
                    "400,\"text\":\"invalid weight \\\""); //,\"code\":\"JsonError\"}");
        rc = njt_http_upstream_api_insert_out_str(r, out, &insert);
		rc = njt_http_upstream_api_insert_out_str(r, out, msg);
		njt_str_set(&insert,
                    "\\\"\",\"code\":\"UpstreamBadWeight\"}");
		rc = njt_http_upstream_api_insert_out_str(r, out, &insert);

        if (rc != NJT_OK) {
            return rc;
        }
		break;
	case NJT_HTTP_UPS_API_NO_SRV_PORT:
		r->headers_out.status = 400;
		njt_str_set(&insert,
                    "400,\"text\":\"no port in server\\\""); //,\"code\":\"JsonError\"}");
        rc = njt_http_upstream_api_insert_out_str(r, out, &insert);
		rc = njt_http_upstream_api_insert_out_str(r, out, msg);
		njt_str_set(&insert,
                    "\\\"\",\"code\":\"UpstreamBadAddress\"}");
		rc = njt_http_upstream_api_insert_out_str(r, out, &insert);

        if (rc != NJT_OK) {
            return rc;
        }
		break;
	case NJT_HTTP_UPS_API_NOT_MODIFY_SRV_NAME:
		r->headers_out.status = 400;
		njt_str_set(&insert,
                    "400,\"text\":\"server address is immutable\",\"code\":\"UpstramServerImmutable\"}");
        rc = njt_http_upstream_api_insert_out_str(r, out, &insert);
        if (rc != NJT_OK) {
            return rc;
        }
		break;
	case NJT_HTTP_UPS_API_INVALID_SRV_ARG:
		r->headers_out.status = 400;
		njt_str_set(&insert,
                    "400,\"text\":\"invalid \\\"server\\\" argument\",\"code\":\"UpstramBadAddress\"}");
        rc = njt_http_upstream_api_insert_out_str(r, out, &insert);
        if (rc != NJT_OK) {
            return rc;
        }
		break;
	case NJT_HTTP_UPS_API_RESET:
		r->headers_out.status = 204;
		r->header_only = 1;
		return NJT_OK;
		break;
	case NJT_HTTP_UPS_API_INVALID_ERROR:
		 r->headers_out.status = 400;
		 rc = njt_http_upstream_api_insert_out_str(r, out, msg);
		  if (rc != NJT_OK) {
            return rc;
		  }
		  break;
    default:
		r->headers_out.status = 404;
        njt_str_set(&insert,
                    "404,\"text\":\"unknown error\",\"code\":\"UnknownError\"}");
        rc = njt_http_upstream_api_insert_out_str(r, out, &insert);
        if (rc != NJT_OK) {
            return rc;
        }
        break;
    }
	njt_str_set(&insert,"request_id");
    low = njt_pnalloc(r->pool, insert.len);
	if (low == NULL) {
            return NJT_ERROR;
        }
	key = njt_hash_strlow(low,insert.data, insert.len);
	value = njt_http_get_variable(r, &insert, key);
	 if (value == NULL || value->not_found || value->len == 0) {
        njt_str_set(&insert,
                ",\"request_id\":\"N/A\",\"href\":\"https://nginx.org/en/docs/http/njt_http_api_module.html\"}");
		rc = njt_http_upstream_api_insert_out_str(r, out, &insert);
    } else {
		njt_str_set(&insert,
                ",\"request_id\":\"");
		rc = njt_http_upstream_api_insert_out_str(r, out, &insert);
		insert.data = value->data;
		insert.len = value->len;
		rc = njt_http_upstream_api_insert_out_str(r, out, &insert);
		njt_str_set(&insert,
                "\",\"href\":\"https://nginx.org/en/docs/http/njt_http_api_module.html\"}");
		rc = njt_http_upstream_api_insert_out_str(r, out, &insert);
	}
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
   // njt_http_upstream_api_main_conf_t *mcf;
    //njt_http_core_loc_conf_t          *clcf;

    /*
     * check of the permission according to the configure.
     */
    //mcf = njt_http_get_module_main_conf(r, njt_http_upstream_api_module);
    uclcf = njt_http_get_module_loc_conf(r, njt_http_upstream_api_module);
    if(uclcf == NULL  || uclcf->enable == NJT_CONF_UNSET_UINT || uclcf->enable == 0){
	return NJT_DECLINED;
    }
    if (uclcf->write == NJT_CONF_UNSET_UINT || uclcf->write == 0) {
        if (r->method == NJT_HTTP_POST || r->method == NJT_HTTP_DELETE
            || r->method == NJT_HTTP_PATCH) {
            rc = NJT_HTTP_UPS_API_PERM_NOT_ALLOWED;
            goto out;
        }
    }

    if (njt_array_init(&path, r->pool, 8, sizeof(njt_str_t)) != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "array init of upstream api error.");
        rc = NJT_HTTP_UPS_API_INTERNAL_ERROR;
        goto out;
    }

    rc = njt_upstream_api_parse_path(r, &path);

    /*internal error*/
    if (rc != NJT_OK) {
        goto out;
    }

    r->headers_out.content_type_len = sizeof("text/plain") - 1;
    njt_str_set(&r->headers_out.content_type, "text/plain");
    r->headers_out.content_type_lowcase = NULL;

    out.next = NULL;
    out.buf = NULL;
    rc = njt_upstream_api_process_request(r, &path, &out);

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

