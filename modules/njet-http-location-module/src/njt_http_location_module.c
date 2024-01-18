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
#include <njt_str_util.h>
#include <njt_http_sendmsg_module.h>
#include <njt_http_location_module.h>
#include <njt_rpc_result_util.h>
extern njt_uint_t njt_worker;
extern njt_module_t  njt_http_rewrite_module;
extern njt_conf_check_cmd_handler_pt  njt_conf_check_cmd_handler;

njt_str_t njt_del_headtail_space(njt_str_t src);

static njt_int_t
njt_http_location_init_worker(njt_cycle_t *cycle);

static void *
njt_http_location_create_loc_conf(njt_conf_t *cf);

static char *njt_http_location_merge_loc_conf(njt_conf_t *cf,
                                              void *parent, void *child);

static void *
njt_http_location_create_main_conf(njt_conf_t *cf);



extern njt_int_t njt_http_init_locations(njt_conf_t *cf,
                                         njt_http_core_srv_conf_t *cscf, njt_http_core_loc_conf_t *pclcf);

static void njt_http_location_clear_dirty_data(njt_http_core_loc_conf_t *clcf);
static njt_http_core_loc_conf_t * njt_http_location_find_new_location(njt_http_core_loc_conf_t *clcf);

static njt_int_t  njt_http_location_check_location_body(njt_str_t src);

static char *
njt_http_location_api(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static njt_str_t njt_http_location_get_full_name(njt_pool_t *pool,njt_str_t src);

static void njt_http_location_write_data(njt_http_location_info_t *location_info);
typedef struct njt_http_location_ctx_s {
} njt_http_location_ctx_t, njt_stream_http_location_ctx_t;


typedef struct njt_http_location_main_conf_s {
} njt_http_location_main_conf_t;


static  njt_str_t njt_invalid_dyn_location_body[] = {
	njt_string("zone"),
	njt_string("if"),
	njt_string("alias"),
	njt_null_string
};
static  njt_str_t njt_invalid_dyn_proxy_pass[] = {
	njt_null_string
};



static njt_command_t njt_http_location_commands[] = {
        {
                njt_string("dyn_location_api"),
                NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_ANY,
                njt_http_location_api,
                NJT_HTTP_LOC_CONF_OFFSET,
                offsetof(njt_http_location_loc_conf_t, dyn_location_enable),
                NULL
        },
        njt_null_command
};


static njt_http_module_t njt_http_location_module_ctx = {
        NULL,                              /* preconfiguration */
        NULL,                              /* postconfiguration */

        njt_http_location_create_main_conf,                              /* create main configuration */
        NULL,                              /* init main configuration */

        NULL,                              /* create server configuration */
        NULL,                              /* merge server configuration */

        njt_http_location_create_loc_conf, /* create location configuration */
        njt_http_location_merge_loc_conf   /* merge location configuration */
};

njt_module_t njt_http_location_module = {
        NJT_MODULE_V1,
        &njt_http_location_module_ctx, /* module context */
        njt_http_location_commands,    /* module directives */
        NJT_HTTP_MODULE,                    /* module type */
        NULL,                               /* init master */
        NULL,                               /* init module */
        njt_http_location_init_worker, /* init process */
        NULL,                               /* init thread */
        NULL,                               /* exit thread */
        NULL,                               /* exit process */
        NULL,                               /* exit master */
        NJT_MODULE_V1_PADDING
};

static char *
njt_http_location_api(njt_conf_t *cf, njt_command_t *cmd, void *conf) {
    
	njt_http_location_loc_conf_t   *clcf = conf;


    clcf->dyn_location_enable = 1;
    return NJT_CONF_OK;
}


static void *
njt_http_location_create_loc_conf(njt_conf_t *cf) {
    njt_http_location_loc_conf_t *uclcf;

    uclcf = njt_pcalloc(cf->pool, sizeof(njt_http_location_loc_conf_t));
    if (uclcf == NULL) {
        njt_log_error(NJT_LOG_ERR, cf->log, 0, "malloc uclcf eror");
        return NULL;
    }
	uclcf->dyn_location_enable = NJT_CONF_UNSET;
    return uclcf;
}

static void *
njt_http_location_create_main_conf(njt_conf_t *cf) {
    njt_http_location_main_conf_t *uclcf;
    uclcf = njt_pcalloc(cf->pool, sizeof(njt_http_location_main_conf_t));
    if (uclcf == NULL) {
        njt_log_error(NJT_LOG_ERR, cf->log, 0, "malloc njt_http_location_main_conf_t eror");
        return NULL;
    }
    return uclcf;
}


static char *njt_http_location_merge_loc_conf(njt_conf_t *cf,
                                              void *parent, void *child) {
	  njt_http_location_loc_conf_t *prev = parent;
    njt_http_location_loc_conf_t *conf = child;

    njt_conf_merge_value(conf->dyn_location_enable, prev->dyn_location_enable, 0);

    return NJT_CONF_OK;
}



    




static njt_http_core_loc_conf_t*  njt_http_location_copy_location (njt_http_core_loc_conf_t *pclcf,njt_http_core_loc_conf_t *clcf,njt_pool_t *pool){
 
 njt_queue_t *x;
 njt_http_location_queue_t *lq, *lx;
 njt_http_core_loc_conf_t  *loc_q;

  loc_q = clcf;
  if(clcf->old_locations == NULL) {
	return loc_q;
 }

   njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "njt_http_location_copy_location clcf=%p",loc_q);
  if(clcf->old_locations != NULL) {
	   loc_q->locations = njt_palloc(pool, sizeof(njt_http_location_queue_t));
        if (loc_q->locations == NULL) {
            return loc_q;
        }
      
  njt_queue_init(loc_q->locations);
  for (x = njt_queue_head(clcf->old_locations);
         x != njt_queue_sentinel(clcf->old_locations);
         x = njt_queue_next(x)) {
        lx = (njt_http_location_queue_t *) x;
        lq = njt_palloc(pool, sizeof(njt_http_location_queue_t));
        if (lq == NULL) {
            return loc_q;
        }
        if (lx->dynamic_status == 1) {
            lx->dynamic_status = 2;
        }
        *lq = *lx;
        lq->parent_pool = pool;

        if(lx->exact != NULL) {
           lq->exact = njt_http_location_copy_location(pclcf,lx->exact,pool);
        } else if (lx->inclusive != NULL){
           lq->inclusive = njt_http_location_copy_location(pclcf,lx->inclusive,pool);
        }
        njt_queue_init(&lq->list);
	njt_queue_insert_tail(loc_q->locations, &lq->queue);
    }
  }

  return loc_q;
}


static njt_int_t
njt_http_refresh_location(njt_conf_t *cf, njt_http_core_srv_conf_t *cscf, njt_http_core_loc_conf_t *clcf) {
    njt_queue_t *x;
    njt_http_location_queue_t *lq,*lx;
    njt_int_t rc = NJT_OK;
    njt_http_location_queue_t *tmp_queue;
    njt_pool_t    *old_new_locations_pool, *old_cf_pool;

	old_new_locations_pool = NULL;

    //njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "new_locations njt_palloc start +++++++++++++++");
    //dump old_location to a new_location

	if(clcf->new_locations_pool == NULL) {
		 clcf->new_locations_pool = njt_create_pool(1024, njt_cycle->log);
		 if (clcf->new_locations_pool == NULL) {
            rc = NJT_ERROR;
            return rc;
        }
		njt_sub_pool(cf->cycle->pool ,clcf->new_locations_pool);

	} else {
		old_new_locations_pool = clcf->new_locations_pool;
	}
	if(old_new_locations_pool != NULL) {
		 //njt_destroy_pool(old_new_locations_pool);
		 njt_reset_pool(old_new_locations_pool);
	}

	clcf->locations = njt_palloc(clcf->new_locations_pool,
									 sizeof(njt_http_location_queue_t));
	if (clcf->locations == NULL) {
		rc = NJT_ERROR;
		return rc;
	}

	tmp_queue = (njt_http_location_queue_t *) clcf->locations;
	//used for delete memory
	tmp_queue->parent_pool = clcf->new_locations_pool;
	njt_queue_init(clcf->locations);
     
    //njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "new_locations njt_palloc end +++++++++++++++");

    //njt_log_error(NJT_LOG_DEBUG,njt_cycle->log, 0, "copy old_locations start +++++++++++++++");
    
    for (x = njt_queue_head(clcf->old_locations);
         x != njt_queue_sentinel(clcf->old_locations);
         x = njt_queue_next(x)) {
        lx = (njt_http_location_queue_t *) x;
        lq = njt_palloc(clcf->new_locations_pool, sizeof(njt_http_location_queue_t));
        if (lq == NULL) {
            return NJT_ERROR;
        }
        if (lx->dynamic_status == 1) {
            lx->dynamic_status = 2;
        }
        *lq = *lx;
        lq->parent_pool = clcf->new_locations_pool;

	if(lx->exact != NULL) {
	   lq->exact = njt_http_location_copy_location(clcf,lx->exact,clcf->new_locations_pool);
	} else if (lx->inclusive != NULL){
	   lq->inclusive = njt_http_location_copy_location(clcf,lx->inclusive,clcf->new_locations_pool);
	}
        njt_queue_init(&lq->list);
        njt_queue_insert_tail(clcf->locations, &lq->queue);
    }
    if(rc == NJT_ERROR) {
	njt_log_error(NJT_LOG_ERR,njt_cycle->log, 0, "copy old_locations  error!");
	return rc;
    }
    //njt_log_error(NJT_LOG_DEBUG,njt_cycle->log, 0, "copy old_locations end +++++++++++++++");

    if (njt_http_init_new_locations(cf, cscf, clcf) != NJT_OK) {
        return NJT_ERROR;
    }

	
    //njt_log_error(NJT_LOG_DEBUG,njt_cycle->log, 0, "init_new_static_location_trees start +++++++++++++++");
    clcf->new_static_locations = NULL;
    
	old_cf_pool = cf->pool;
	cf->pool = clcf->new_locations_pool;
    if (njt_http_init_new_static_location_trees(cf, clcf) != NJT_OK) {
		cf->pool = old_cf_pool;
        return NJT_ERROR;
    }
	cf->pool = old_cf_pool;

    //njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "init_new_static_location_trees end +++++++++++++++");

//save last locations
    clcf->static_locations = clcf->new_static_locations;


    return rc;
}

static njt_int_t
njt_http_location_delete_handler(njt_http_location_info_t *location_info) {
    njt_http_core_srv_conf_t *cscf;
    njt_http_core_loc_conf_t *clcf, *dclcf;
    njt_http_location_queue_t *lq,*if_lq;
    u_char *p;
    njt_str_t location_name,msg,location_name_key,add_escape_val;

    
    msg.len = 1024;
    msg.data = njt_pcalloc(location_info->pool,msg.len);
    if(msg.data == NULL) {
	return NJT_ERROR;
    }
    cscf = location_info->cscf;
    if (cscf == NULL || location_info->location.len == 0) {
	if(msg.data != NULL && cscf == NULL){
                    p = njt_snprintf(msg.data, 1024, "error:host[%V],no find server [%V]!", &location_info->addr_port,&location_info->server_name);
                    msg.len = p - msg.data;
                    location_info->msg = msg;
                    njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0, "host[%V],no find server [%V]!",&location_info->addr_port,&location_info->server_name);
            } else if(cscf != NULL){
                    njt_str_set(&location_info->msg,"error:location is null!");
                    njt_log_error(NJT_LOG_DEBUG,njt_cycle->pool->log, 0, "error:location is null!");
            } else {
                njt_str_set(&location_info->msg,"no find server!");
                njt_log_error(NJT_LOG_DEBUG,njt_cycle->pool->log, 0, "host[%V],no find server [%V]!",&location_info->addr_port,&location_info->server_name);
            }
        return NJT_ERROR;
    }
    clcf = cscf->ctx->loc_conf[njt_http_core_module.ctx_index];

 
    njt_conf_t cf = {
            NULL,
            NULL,
            (njt_cycle_t *) njt_cycle,
            clcf->pool,
            location_info->pool,
            NULL,
            njt_cycle->log,
            1,
			0,
            cscf->ctx,
            NJT_HTTP_MODULE,
            NJT_HTTP_SRV_CONF,
            NULL,
            NULL,
	    NULL,
    };

    //njt_log_error(NJT_LOG_DEBUG,njt_cycle->pool->log, 0, "find && free old location start +++++++++++++++");

	location_name.data = njt_pcalloc(location_info->pool, 1024);
	if(location_name.data == NULL) {
		return NJT_ERROR;
	}
	if(location_info->location_rule.len > 0) {
		p = njt_snprintf(location_name.data, 1024, "%V%V", &location_info->location_rule,
								 &location_info->location);
	} else {
		p = njt_snprintf(location_name.data, 1024, "%V", &location_info->location);
	}
	location_name.len = p - location_name.data;
	add_escape_val = add_escape(location_info->pool,location_name);
	location_name_key = njt_http_location_get_full_name(location_info->pool,add_escape_val);

    if(clcf->old_locations == NULL) {
	   lq = NULL;
    } else {
		lq = njt_http_find_location(location_name_key, clcf->old_locations);
	}
    if (lq == NULL) {
	njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0, "not find  location [%V]!",&location_name);
	if(msg.data != NULL){
		p = njt_snprintf(msg.data, 1024, "not find  location [%V]!", &location_name);
		msg.len = p - msg.data;
		location_info->msg = msg;
	} else {
		njt_str_set(&location_info->msg,"not find  location!");
	}
	
        return NJT_ERROR;
    }


    dclcf = lq->exact ? lq->exact : lq->inclusive;
    //if(dclcf->dynamic_status == 0) {
    //    njt_log_error(NJT_LOG_DEBUG, njt_cycle->pool->log, 0, "static  location=%V not allow delete!",&location_name);
    //	return NJT_OK;
    //}
    if(dclcf->if_loc == 1) {
	if_lq = njt_http_find_location(location_name_key, clcf->if_locations);
	if(if_lq != NULL) {
	  njt_queue_remove(&if_lq->queue);
	}
    }
  
    njt_queue_remove(&lq->queue);
    njt_pfree(lq->parent_pool, lq);
	njt_http_location_delete_dyn_var(dclcf);
    njt_http_location_destroy(dclcf);
	njt_http_refresh_location(&cf, cscf, clcf);

	
    //note: delete queue memory, which delete when remove queue 
    //njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0, "delete  location [%V] succ!",&location_name);
    return NJT_OK;
	
}


njt_int_t njt_http_check_upstream_exist(njt_cycle_t *cycle,njt_pool_t *pool, njt_str_t *name) {
    return NJT_OK;
    
    /*
    njt_uint_t i;
    njt_http_upstream_srv_conf_t **uscfp;
    njt_http_upstream_main_conf_t *umcf;
    njt_url_t u;
    size_t add,len;
    u_short port;
    u_char *p;
    if (name->len < 8) {
        return NJT_ERROR;
    }
    if (njt_strncasecmp(name->data, (u_char *) "http://", 7) == 0) {
        add = 7;
        port = 80;
    } else if (njt_strncasecmp(name->data, (u_char *) "https://", 8) == 0) {
        add = 8;
        port = 443;
    } else {
        return NJT_ERROR;
    }
    len = name->len;
    p = (u_char *) njt_strlchr(name->data,name->data+name->len,'$');
    if(p != NULL){
	len = p - name->data;
    } 
    njt_memzero(&u, sizeof(njt_url_t));
    
    u.url.len =  len - add;
    u.url.data = name->data + add;
    u.default_port = port;
    u.uri_part = 1;
    u.no_resolve = 1;

    if (njt_parse_url(pool, &u) != NJT_OK) {
        if (u.err) {
            return NJT_ERROR;
        }
    }
    umcf = njt_http_cycle_get_module_main_conf(cycle, njt_http_upstream_module);

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {
        if (uscfp[i]->host.len == u.host.len
            && njt_strncasecmp(uscfp[i]->host.data, u.host.data, u.host.len)
               == 0) {
            return NJT_OK;
        }
    }
    return NJT_ERROR;
	*/
}



static njt_int_t njt_http_add_location_handler(njt_http_location_info_t *location_info,njt_uint_t from_api_add) {
    njt_conf_t conf;
    njt_int_t rc = NJT_OK;
	njt_uint_t  msg_len;
    njt_http_core_srv_conf_t *cscf;
    char *rv = NULL;
    njt_http_core_loc_conf_t *clcf,*new_clcf;
    njt_str_t location_name,msg,location_name_key,add_escape_val;
    u_char *p;
	njt_http_sub_location_info_t  *sub_location, *loc;
    njt_http_location_queue_t *lq;

    njt_str_t location_path; // = njt_string("./conf/add_location.txt");

    //njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "add location start +++++++++++++++");

    msg_len = 1024;
    msg.len = msg_len;
    msg.data = njt_pcalloc(location_info->pool,msg.len);
    if(msg.data == NULL) {
	rc = NJT_ERROR;
	njt_str_set(&location_info->msg,"memory allocat error!");
	return rc;
    }
	if (location_info->location_array == NULL || location_info->location_array->nelts == 0) {
    		//njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "add location error:locations null");
		njt_str_set(&location_info->msg,"add location error:locations null");
        rc = NJT_ERROR;
        return rc;
    }
    location_path.len = 0;
    location_path.data = NULL;
    if (location_info->file.len != 0) {
        location_path = location_info->file;
    }
	

    if (location_path.len == 0) {
	    //njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "add location error:location_path=0");
	    njt_str_set(&location_info->msg,"add location error:location_path=0");
	    rc = NJT_ERROR;
	    return rc;
    }


    sub_location = location_info->location_array->elts;
    loc = &sub_location[0];

        location_name.data = njt_pcalloc(location_info->pool, msg_len);
	if(location_name.data == NULL) {
		rc = NJT_ERROR;
		return rc;
	}
        if(loc->location_rule.len > 0) {
                p = njt_snprintf(location_name.data, msg_len, "%V%V", &loc->location_rule,
                                                                 &loc->location);
        } else {
                p = njt_snprintf(location_name.data, msg_len, "%V", &loc->location);
        }
        location_name.len = p - location_name.data;
	

    cscf = location_info->cscf;  
    if (cscf == NULL) {
		 //njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "error:host[%V],no find server[%V]!",&location_info->addr_port,&location_info->server_name);
		 rv = "no find server!";
		 njt_str_set(&location_info->msg,"no find server!");
		 if(msg.data != NULL){
			p = njt_snprintf(msg.data,msg_len, "error:host[%V],no find server[%V]!",&location_info->addr_port,&location_info->server_name);
			msg.len = p - msg.data;
			location_info->msg = msg;
		 }
		 rc = NJT_ERROR;
		 goto out;
    }
    clcf = cscf->ctx->loc_conf[njt_http_core_module.ctx_index];
	if(clcf->old_locations) {
	    add_escape_val = add_escape(location_info->pool,location_name);
	    location_name_key = njt_http_location_get_full_name(location_info->pool,add_escape_val);
	    lq = njt_http_find_location(location_name_key, clcf->old_locations);
	    if (lq != NULL) {  
		 njt_str_set(&location_info->msg,"location exist!");
		 if(msg.data != NULL){
			 p = njt_snprintf(msg.data,msg_len, "error:location[%V] exist!", &location_name);
			 msg.len = p - msg.data;
			 location_info->msg = msg;
		 }
		 if(from_api_add == 0) {
		 	njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "location[%V] exist!",&location_name);
			rc = NJT_OK;
			return rc;
		 }
		 njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "error:location[%V] exist!",&location_name);
		 rc = NJT_ERROR;
		goto out;
	    }
	}

    

    njt_memzero(&conf, sizeof(njt_conf_t));
    conf.args = njt_array_create(location_info->pool, 10, sizeof(njt_str_t));
    if (conf.args == NULL) {
	njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "add  location[%V] error:args allocate fail!",&location_name);
	rc = NJT_ERROR;
	goto out;
    }

    location_info->msg.len = 0;
    location_info->msg.data = njt_pcalloc(location_info->pool,NJT_MAX_CONF_ERRSTR);
    if(location_info->msg.data != NULL){ 
		location_info->msg.len = NJT_MAX_CONF_ERRSTR;
		conf.errstr = &location_info->msg;
    }
	
    conf.pool = location_info->pool; 
    conf.temp_pool = location_info->pool;
    conf.ctx = cscf->ctx;
    conf.cycle = (njt_cycle_t *) njt_cycle;
    conf.log = njt_cycle->log;
    conf.module_type = NJT_HTTP_MODULE;
    conf.cmd_type = NJT_HTTP_SRV_CONF;
    conf.dynamic = 1;

    //clcf->locations = NULL; // clcf->old_locations;
    //njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "njt_conf_parse start +++++++++++++++");

	njt_conf_check_cmd_handler = njt_http_location_check_location_body;

    rv = njt_conf_parse(&conf, &location_path);
    if (rv != NULL) {
	
		//njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "njt_conf_parse  location[%V] error:%s",&location_name,rv);
	    if(location_info->msg.len == NJT_MAX_CONF_ERRSTR && location_info->msg.data[0] == '\0') {
	    	njt_str_set(&location_info->msg,"njt_conf_parse error!");
	    }
	    njt_http_location_delete_dyn_var(clcf);
	    njt_http_location_clear_dirty_data(clcf);
	    rc = NJT_ERROR;
		njt_conf_check_cmd_handler = NULL;
	    goto out;
    }
    //njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "njt_conf_parse end +++++++++++++++");

    conf.pool = clcf->pool; 
    new_clcf = njt_http_location_find_new_location(clcf);
    if(new_clcf != NULL && new_clcf->pool != NULL){
	//conf.pool = new_clcf->pool;  //zyg new add location  pool.  used by merge
	    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "new add location[%V],new_clcf=%p!",&location_name,new_clcf);
    }
   
    njt_http_variables_init_vars_dyn(&conf);


    //merge servers
    njt_http_module_t *module;
    njt_uint_t mi, m;
    //njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "merge start +++++++++++++++");
    for (m = 0; conf.cycle->modules[m]; m++) {
        if (conf.cycle->modules[m]->type != NJT_HTTP_MODULE) {
            continue;
        }

        module = conf.cycle->modules[m]->ctx;
        
        if (module->merge_loc_conf) {

			mi = conf.cycle->modules[m]->ctx_index;
            /* merge the locations{}' loc_conf's */
            rv = njt_http_merge_locations(&conf, clcf->old_locations,
                                          cscf->ctx->loc_conf,
                                          module, mi);
            if (rv != NJT_CONF_OK) {
                rc = NJT_ERROR;
		njt_str_set(&location_info->msg,"add location error:merge_locations");
    		//njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "add location error:merge_locations!");
                goto out;
            }
        }
    }
    //njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "merge end +++++++++++++++");

    rc = njt_http_refresh_location(&conf, cscf, clcf);
    if (rc != NJT_OK) {
	     njt_str_set(&location_info->msg,"add location error:njt_http_refresh_location!");
	     //njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "add location error:njt_http_refresh_location!");
        goto out;
    }
    //njt_log_error(NJT_LOG_DEBUG,njt_cycle->log, 0, "add location end +++++++++++++++");
out:
    if(rc != NJT_OK) {
    	   //njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "add  location [%V] error!",&location_name);
    } else {
	   //njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0, "add  location [%V] succ!",&location_name);
    }
    return rc;
}





static int njt_agent_location_change_handler_internal(njt_str_t *key, njt_str_t *value, void *data,njt_str_t *out_msg) {
	njt_str_t  add = njt_string("add");
	njt_str_t  del = njt_string("del");
	njt_str_t  del_topic = njt_string("");
	njt_str_t  worker_str = njt_string("/worker_a");
	njt_str_t  new_key;
	njt_rpc_result_t * rpc_result;
	njt_uint_t from_api_add = 0;

	njt_int_t rc = NJT_OK;
	njt_http_location_info_t *location_info;
	//njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "get topic  key=%V,value=%V",key,value);

	location_info = njt_http_parser_location_data(*value,0);
	if(location_info == NULL) {
		njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "topic msg error key=%V,value=%V",key,value);
		return NJT_ERROR;
	}
	rpc_result = njt_rpc_result_create();
    if(rpc_result == NULL){
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "rpc_result allocate null");
       return NJT_ERROR;
    }

	if(location_info->type.len == add.len && njt_strncmp(location_info->type.data,add.data,location_info->type.len) == 0 ) {
		njt_http_location_write_data(location_info);
		if(key->len > worker_str.len && njt_strncmp(key->data,worker_str.data,worker_str.len) == 0) {
			from_api_add = 1;
		} 
		rc = njt_http_add_location_handler(location_info,from_api_add);  //njt_http_location_delete_handler
		if(rc != NJT_OK) {
			if(from_api_add == 0){
				//njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "add topic_kv_change_handler error key=%V,value=%V",key,value);
				njt_kv_sendmsg(key,&del_topic,0);
			}
			njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "add topic_kv_change_handler error key=%V,value=%V",key,value);
		} else {
			if(key->len > worker_str.len && njt_strncmp(key->data,worker_str.data,worker_str.len) == 0) {
				new_key.data = key->data + worker_str.len;
				new_key.len  = key->len - worker_str.len;
				njt_kv_sendmsg(&new_key,value,1);
			}
			njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "add topic_kv_change_handler succ key=%V,value=%V",key,value);
		}
	} else if(location_info->type.len == del.len && njt_strncmp(location_info->type.data,del.data,location_info->type.len) == 0 ){
		njt_http_location_write_data(location_info);
		rc = njt_http_location_delete_handler(location_info);
		if (rc == NJT_OK) {
			if(key->len > worker_str.len && njt_strncmp(key->data,worker_str.data,worker_str.len) == 0) {
				new_key.data = key->data + worker_str.len;
				new_key.len  = key->len - worker_str.len;
				//njt_kv_sendmsg(&new_key,value,1);
				njt_kv_sendmsg(&new_key,value,0);
			}
		}
		//njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "delete topic_kv_change_handler key=%V,value=%V",key,value);
	}
	if(rc == NJT_OK) {
		njt_rpc_result_set_code(rpc_result,NJT_RPC_RSP_SUCCESS);
	} else {
		njt_rpc_result_set_code(rpc_result,NJT_RPC_RSP_ERR);
		njt_rpc_result_set_msg2(rpc_result,&location_info->msg);
	}
	if(out_msg){
        njt_rpc_result_to_json_str(rpc_result,out_msg);
    }
	if(rpc_result){
        njt_rpc_result_destroy(rpc_result);
    }

	njt_destroy_pool(location_info->pool);
	
	return NJT_OK;
}


static u_char* njt_agent_location_put_handler(njt_str_t *topic, njt_str_t *request, int* len, void *data) {
    njt_str_t err_json_msg;
    njt_str_null(&err_json_msg);
    // 新增字符串参数err_json_msg用于返回到客户端。
    njt_agent_location_change_handler_internal(topic,request,data,&err_json_msg);
    *len = err_json_msg.len;
    return err_json_msg.data;

}

static int  topic_kv_change_handler(njt_str_t *key, njt_str_t *value, void *data){
    return  njt_agent_location_change_handler_internal(key,value,data,NULL);
}

static njt_int_t
njt_http_location_init_worker(njt_cycle_t *cycle) {

	njt_str_t  key = njt_string("loc");

    njt_kv_reg_handler_t h;
    njt_memzero(&h, sizeof(njt_kv_reg_handler_t));
    h.key = &key;
    h.rpc_put_handler = njt_agent_location_put_handler;
    h.handler = topic_kv_change_handler;
    h.api_type = NJT_KV_API_TYPE_INSTRUCTIONAL;
    njt_kv_reg_handler(&h);

    return NJT_OK;
}



njt_int_t njt_http_check_sub_location(njt_json_element *in_items,njt_http_location_info_t *location_info) {
 
	njt_json_element  *items;
	njt_str_t   str;
	njt_str_t   error = njt_string("invalid parameter:");
	njt_queue_t   *q;
	if(in_items->type != NJT_JSON_OBJ) {
		njt_str_set(&location_info->msg, "json error!!!");
		return NJT_ERROR;
	}

        for (q = njt_queue_head(&in_items->objdata.datas);
         q != njt_queue_sentinel(&in_items->objdata.datas);
         q = njt_queue_next(q)) {

		items = njt_queue_data(q, njt_json_element, ele_queue);
		if(items == NULL){
			break;
		}
	  njt_str_set(&str,"location_rule");
	  if(items->key.len == str.len && njt_strncmp(str.data,items->key.data,str.len) == 0){
		continue;
	  }
	  njt_str_set(&str,"location_name");
	  if(items->key.len == str.len && njt_strncmp(str.data,items->key.data,str.len) == 0){
		continue;
	  }
	  njt_str_set(&str,"location_body");
	  if(items->key.len == str.len && njt_strncmp(str.data,items->key.data,str.len) == 0){
		continue;
	  }
	  njt_str_set(&str,"proxy_pass");
	  if(items->key.len == str.len && njt_strncmp(str.data,items->key.data,str.len) == 0){
		continue;
	  }
	  njt_str_set(&str,"locations");
	  if(items->key.len == str.len && njt_strncmp(str.data,items->key.data,str.len) == 0){
		continue;
	  }
	  str.len = error.len + items->key.len + 1;
	  str.data = njt_pcalloc(location_info->pool,str.len);
	  if(str.data != NULL) {
	     njt_snprintf(str.data,str.len,"%V%V!",&error,&items->key);	
	     location_info->msg = str;
	  } else {
		njt_str_set(&location_info->msg, "json error!!!");
	  }
	}
	if(location_info->msg.len > 0){
	  return NJT_ERROR;
	}
	return NJT_OK;
}


static njt_int_t  njt_http_location_check_location_body(njt_str_t cmd) {
	njt_str_t *name;

	if(cmd.len == 0 ){
		return NJT_OK;
	}
	for (name = njt_invalid_dyn_location_body; name->len; name++) {
       if(cmd.len == name->len && njt_strncmp(cmd.data,name->data,name->len) == 0) {
		  //njt_invalid_dyn_location_body_field = *name;
		  return NJT_ERROR;
	   }
    }
	return NJT_OK;
}
static njt_str_t  njt_http_location_check_proxy_pass(njt_str_t src) {
	njt_str_t *name;
	njt_str_t ret_null = njt_null_string;

	if(src.len == 0 ){
		return ret_null;
	}
	for (name = njt_invalid_dyn_proxy_pass; name->len; name++) {
       if(njt_strlcasestrn(src.data,src.data + src.len,name->data,name->len - 1) != NULL) {
		  return *name;
	   }
    }
	return ret_null;

}
static njt_int_t
njt_http_parser_sub_location_data(njt_http_location_info_t *location_info,njt_array_t *location_array,njt_json_element *in_items) {

	njt_json_element *out_items, *items;
	njt_int_t rc;
	njt_str_t  key;
	u_char *p;
	njt_str_t  check_val;
	njt_uint_t  msg_len = 128;
	njt_queue_t   *q;
	njt_str_t  add = njt_string("add");
	//njt_str_t  del = njt_string("del");
	njt_http_sub_location_info_t  * sub_location;

	//njt_memzero(&sub_location_info,sizeof(njt_http_sub_location_info_t));

	if(in_items->type != NJT_JSON_ARRAY) {
		return NJT_ERROR;
	}

	for (q = njt_queue_head(&in_items->arrdata);
         q != njt_queue_sentinel(&in_items->arrdata);
         q = njt_queue_next(q)) {
		 
		  items = njt_queue_data(q, njt_json_element, ele_queue);
		   if(items == NULL){
            break;
        }

		rc = njt_http_check_sub_location(items,location_info);
	        if(rc == NJT_ERROR) {
		   return NJT_ERROR;
		}
		sub_location = njt_array_push(location_array);
		if(sub_location == NULL) {
			return NJT_ERROR;
		}
		njt_memzero(sub_location,sizeof(njt_http_sub_location_info_t));
		njt_str_set(&key,"location_rule");
			rc = njt_struct_find(items, &key, &out_items);
			if(rc == NJT_OK ){
				 if (out_items->type != NJT_JSON_STR) {
				njt_str_set(&location_info->msg, "location_rule error!");
					   return NJT_ERROR;
					}
				sub_location->location_rule = njt_del_headtail_space(out_items->strval);
				njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "location_rule[%V,%V]",&out_items->strval,&sub_location->location_rule);
				
			} 

			njt_str_set(&key,"location_name");
			rc = njt_struct_find(items, &key, &out_items);
			if(rc != NJT_OK || out_items->type != NJT_JSON_STR){
				njt_str_set(&location_info->msg, "location_name error!!!");
				return NJT_ERROR;
			} else {
				sub_location->location = njt_del_headtail_space(out_items->strval);
				njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "location_name[%V,%V]",&out_items->strval,&sub_location->location);
				if(sub_location->location.len == 0) {
				   njt_str_set(&location_info->msg, "location_name is null!");
				   return NJT_ERROR;
				}
			}
			
			njt_str_set(&key,"proxy_pass");
			rc = njt_struct_find(items, &key, &out_items);
			if(rc == NJT_OK ){
				 if (out_items->type != NJT_JSON_STR) {
				 	njt_str_set(&location_info->msg, "proxy_pass error!!!");
					  return NJT_ERROR;
					}
				sub_location->proxy_pass = njt_del_headtail_space(out_items->strval);

				check_val = njt_http_location_check_proxy_pass(sub_location->proxy_pass);
				if(check_val.len != 0) {
					location_info->msg.len = 0;
					location_info->msg.data = njt_palloc(location_info->pool,msg_len);
					if(location_info->msg.data != NULL) {
						location_info->msg.len = msg_len;
						p = njt_snprintf(location_info->msg.data,location_info->msg.len,"proxy_pass no support %V!",&check_val);	
						location_info->msg.len = p - location_info->msg.data;

					} else {
						njt_str_set(&location_info->msg, "proxy_pass error!");
					}
					
					return NJT_ERROR;
				}

			} 

			njt_str_set(&key,"location_body");

			njt_str_set(&sub_location->location_body,"");
			rc = njt_struct_find(items, &key, &out_items);
			if( (location_info->type.len == add.len && njt_strncmp(location_info->type.data,add.data,location_info->type.len) == 0)) {
				if(rc != NJT_OK || out_items->type != NJT_JSON_STR){
					njt_str_set(&sub_location->location_body,"");
				} else {
					sub_location->location_body = njt_del_headtail_space(out_items->strval);
				}
			} else if(rc == NJT_OK && out_items->type == NJT_JSON_STR) {
				 sub_location->location_body = njt_del_headtail_space(out_items->strval);
			}
			
			if(sub_location->location_body.len > 0 && sub_location->location_body.data != NULL) {
				if(njt_strstr(sub_location->location_body.data,"proxy_pass ") != NULL) {
					njt_str_set(&location_info->msg, "directive is not allowed here in location_body");
					return NJT_ERROR;
				}
			}

			njt_str_set(&key,"locations");
			rc = njt_struct_find(items, &key, &out_items);
			if(rc == NJT_OK ) {
				if(sub_location->sub_location_array == NULL) {
					sub_location->sub_location_array = njt_array_create(location_info->pool, 1, sizeof(njt_http_sub_location_info_t));
					if(sub_location->sub_location_array == NULL){
						 return NJT_ERROR;
					}
				}
				rc = njt_http_parser_sub_location_data(location_info,sub_location->sub_location_array,out_items);
				if(rc != NJT_OK ) {
					njt_str_set(&location_info->msg, "locations field error!");
					return NJT_ERROR;
				} 
			}
	}

	

   return NJT_OK;
}

njt_int_t njt_http_check_top_location( njt_json_manager *json_body,njt_http_location_info_t *location_info) {
 
	njt_json_element  *items;
	njt_str_t   str;
	njt_queue_t   *q;
	njt_str_t   error = njt_string("invalid parameter:");
	if(json_body->json_val == NULL || json_body->json_val->type != NJT_JSON_OBJ) {
		njt_str_set(&location_info->msg, "json error!!!");
		return NJT_ERROR;
	}

        for (q = njt_queue_head(&json_body->json_val->objdata.datas);
         q != njt_queue_sentinel(&json_body->json_val->objdata.datas);
         q = njt_queue_next(q)) {

		items = njt_queue_data(q, njt_json_element, ele_queue);
		if(items == NULL){
			break;
		}
	  njt_str_set(&str,"type");
	  if(items->key.len == str.len && njt_strncmp(str.data,items->key.data,str.len) == 0){
		continue;
	  }
	  njt_str_set(&str,"addr_port");
	  if(items->key.len == str.len && njt_strncmp(str.data,items->key.data,str.len) == 0){
		continue;
	  }
	  njt_str_set(&str,"server_name");
	  if(items->key.len == str.len && njt_strncmp(str.data,items->key.data,str.len) == 0){
		continue;
	  }
	  njt_str_set(&str,"locations");
	  if(items->key.len == str.len && njt_strncmp(str.data,items->key.data,str.len) == 0){
		continue;
	  }
	  njt_str_set(&str,"location_rule");
	  if(items->key.len == str.len && njt_strncmp(str.data,items->key.data,str.len) == 0){
		continue;
	  }
	  njt_str_set(&str,"location_name");
	  if(items->key.len == str.len && njt_strncmp(str.data,items->key.data,str.len) == 0){
		continue;
	  }
	  str.len = error.len + items->key.len + 1;
	  str.data = njt_pcalloc(location_info->pool,str.len);
	  if(str.data != NULL) {
	     njt_snprintf(str.data,str.len,"%V%V!",&error,&items->key);	
	     location_info->msg = str;
	  } else {
		njt_str_set(&location_info->msg, "json error!!!");
	  }
	}
	if(location_info->msg.len > 0){
	  return NJT_ERROR;
	}
	return NJT_OK;
}
njt_http_location_info_t * njt_http_parser_location_data(njt_str_t json_str,njt_uint_t method) {
	 njt_json_manager json_body;
	 njt_pool_t  *location_pool;
	  njt_http_location_info_t *location_info;
	 njt_int_t rc;
	 //njt_http_sub_location_info_t   sub_location;
	 //u_char *last;
	 //u_char *p;
	 njt_str_t  add = njt_string("add");
	njt_str_t  del = njt_string("del");
	njt_str_t  key;
	 njt_json_element *items;
	 

	location_pool = njt_create_pool(NJT_DEFAULT_POOL_SIZE, njt_cycle->log);
	if(location_pool == NULL) {
		return NULL;
	}

	rc = njt_json_2_structure(&json_str, &json_body, location_pool);
    if (rc != NJT_OK) {
        rc = NJT_ERROR;
		njt_destroy_pool(location_pool);
        return NULL;
    }
	location_info = njt_pcalloc(location_pool, sizeof(njt_http_location_info_t));
    if (location_info == NULL) {
		njt_destroy_pool(location_pool);
        return NULL;
    }

	//location_info->type = -1;
	location_info->pool = location_pool;

	rc = njt_http_check_top_location(&json_body,location_info);
	if(rc == NJT_ERROR) {
	   goto end;
	}
	if(location_info->location_array == NULL) {
		location_info->location_array = njt_array_create(location_info->pool, 1, sizeof(njt_http_sub_location_info_t));
		if(location_info->location_array == NULL){
			 goto end;
		}
	}
	
	njt_str_set(&key,"addr_port");
	rc = njt_struct_top_find(&json_body, &key, &items);
	if(rc != NJT_OK || items->type != NJT_JSON_STR){
		//location_info->code = 1; 
		njt_str_set(&location_info->msg, "addr_port error!!!");
		goto end;
	} else {
		location_info->addr_port = njt_del_headtail_space(items->strval);
		if(location_info->addr_port.len == 0){
		  njt_str_set(&location_info->msg, "addr_port null!!!");
		  goto end;
		}
		/*
		 last = location_info->addr_port.data + location_info->addr_port.len;
            p = njt_strlchr(location_info->addr_port.data, last, ':');
            if (p != NULL) {
                p = p + 1;
                location_info->sport.data = p;
                location_info->sport.len = location_info->addr_port.data + location_info->addr_port.len - p;
            } else {
                location_info->sport = location_info->addr_port;
            }*/
	}
	njt_str_set(&key,"type");
	rc = njt_struct_top_find(&json_body, &key, &items);
	if(rc != NJT_OK || items->type != NJT_JSON_STR){
		njt_str_set(&location_info->msg, "type error!!!");
		goto end;
	} else {
		location_info->type = njt_del_headtail_space(items->strval);
		if(method != 0 && location_info->type.len == add.len && njt_strncmp(location_info->type.data,add.data,location_info->type.len) == 0 && method != NJT_HTTP_POST) {
		     njt_str_set(&location_info->msg, "no support method when add location!");
		     goto end;
		}
		if(method != 0 && location_info->type.len == del.len && njt_strncmp(location_info->type.data,del.data,location_info->type.len) == 0 && method != NJT_HTTP_PUT) {
		     njt_str_set(&location_info->msg, "no support method when del location!");
		     goto end;
		}
		if((location_info->type.len == add.len && njt_strncmp(location_info->type.data,add.data,location_info->type.len) == 0) || (location_info->type.len == del.len && njt_strncmp(location_info->type.data,del.data,location_info->type.len) == 0)) {
		} else {
			njt_str_set(&location_info->msg, "type error!!!");
			goto end;
		}
	}
	njt_str_set(&key,"locations");
	rc = njt_struct_top_find(&json_body, &key, &items);
	if(rc != NJT_OK ) {
		if(location_info->type.len == add.len && njt_strncmp(location_info->type.data,add.data,location_info->type.len) == 0) {
			njt_str_set(&location_info->msg, "locations error!!!");
			goto end;
		}
	} else {
		rc = njt_http_parser_sub_location_data(location_info,location_info->location_array,items);
		if(rc != NJT_OK ) {
			goto end;
		}
		if(location_info->location_array->nelts == 0) {
			njt_str_set(&location_info->msg, "locations []  error!!!");
			goto end;
		}
	}

	njt_str_set(&key,"location_rule");
	rc = njt_struct_top_find(&json_body, &key, &items);
	if(rc == NJT_OK ){
		 if (items->type != NJT_JSON_STR) {
	   	njt_str_set(&location_info->msg, "location_rule error!");
			   goto end;
          	}
		location_info->location_rule = njt_del_headtail_space(items->strval);
		njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "location_rule[%V,%V]",&items->strval,&location_info->location_rule);
	} 
	njt_str_set(&key,"location_name");
	rc = njt_struct_top_find(&json_body, &key, &items);
	if(rc == NJT_OK ){
		 if (items->type != NJT_JSON_STR) {
	   	njt_str_set(&location_info->msg, "location_name error!");
			   goto end;
          	}
		location_info->location = njt_del_headtail_space(items->strval);
		njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "location_rule[%V,%V]",&items->strval,&location_info->location);
		if(location_info->location.len == 0) {
                                   njt_str_set(&location_info->msg, "location_name is null!");
                                   goto end;
                                }
	}else {
		if( location_info->type.len == del.len && njt_strncmp(location_info->type.data,del.data,location_info->type.len) == 0) {
		    njt_str_set(&location_info->msg, "location_name is null!");
			goto end;
		}
	}

	

	njt_str_set(&key,"server_name");
	rc = njt_struct_top_find(&json_body, &key, &items);
	if(rc == NJT_OK ){
		 if (items->type != NJT_JSON_STR) {
	   	njt_str_set(&location_info->msg, "server_name error!");
			   goto end;
          	}
		location_info->server_name = njt_del_headtail_space(items->strval);
		if(location_info->server_name.len == 0) {
		  //njt_str_set(&location_info->msg, "server_name is null!");
		  goto end;
		}
	} else {
	   	njt_str_set(&location_info->msg, "server_name is null!");
		goto end;
	} 
	
end:
	return location_info;


}



static njt_int_t njt_http_sub_location_write_data(njt_fd_t fd,njt_http_location_info_t *location_info,njt_array_t *location_array,njt_flag_t write_endtag) {

	u_char *p,*data;
	int32_t  rlen,buffer_len,remain;
	njt_uint_t i;
	njt_http_sub_location_info_t *loc,*loc_array;
	njt_str_t  add_escape_val;
	njt_str_t  tag = njt_string("\n}\n");

	if(location_array->nelts == 0 ) {
		return NJT_OK;
	}
	buffer_len = location_info->buffer_len;
	remain = buffer_len;
	data = location_info->buffer;

	
	loc_array  = location_array->elts;
	for(i=0; i < location_array->nelts; i++) {
		
		loc = &loc_array[i];
		if(loc) {
			njt_memzero(data,buffer_len);
			p = data;
			p = njt_snprintf(p, remain, "location ");
			remain = data + buffer_len - p;

			if(loc->location_rule.len != 0 && loc->location_rule.data != NULL){
				add_escape_val = add_escape(location_info->pool,loc->location_rule);
				p = njt_snprintf(p, remain, "%V ",&add_escape_val);
				remain = data + buffer_len - p;
			}
			if(loc->location.len != 0 && loc->location.data != NULL){
				add_escape_val = add_escape(location_info->pool,loc->location);
				p = njt_snprintf(p, remain, "%V {\n",&add_escape_val);
				remain = data + buffer_len - p;
			}
			if(loc->location_body.len != 0 && loc->location_body.data != NULL){
				add_escape_val = loc->location_body;//add_escape(location_info->pool,loc->location_body);
				if(add_escape_val.len > 0 && add_escape_val.data[add_escape_val.len-1] != ';' && add_escape_val.data[add_escape_val.len-1] != '}'){
					p = njt_snprintf(p, remain, " %V; \n",&add_escape_val);
				} else {
					p = njt_snprintf(p, remain, " %V \n",&add_escape_val);
				}
				remain = data + buffer_len - p;
			}
			if(loc->proxy_pass.len != 0 && loc->proxy_pass.data != NULL){
				add_escape_val = loc->proxy_pass; //add_escape(location_info->pool,loc->proxy_pass);
				p = njt_snprintf(p, remain, " proxy_pass %V;\n",&add_escape_val);
				remain = data + buffer_len - p;
			}

			rlen = njt_write_fd(fd, data, p - data);
			if(rlen < 0) {
					return NJT_ERROR;
			}

			if(loc->sub_location_array != NULL && loc->sub_location_array->nelts > 0 ){
				njt_http_sub_location_write_data(fd,location_info,loc->sub_location_array,1);

			}
			if(i != 0){
				rlen = njt_write_fd(fd, tag.data, tag.len);
				if(rlen < 0) {
					return NJT_ERROR;
				}
			}
				
			

			
		}
	}
	if (location_array->nelts > 0) {
		rlen = njt_write_fd(fd, tag.data, tag.len);
                                if(rlen < 0) {
                                        return NJT_ERROR;
                                }
	}
	return NJT_OK;

}
static void njt_http_location_write_data(njt_http_location_info_t *location_info) {

    
    //njt_str_t  dport;
    njt_fd_t fd;
    njt_int_t  rc; 
    //njt_uint_t i;
    
    u_char *p; // *data;
    njt_http_core_srv_conf_t *cscf;
  
    njt_str_t location_file = njt_string("add_location.txt");
    njt_str_t location_path;
    njt_str_t location_full_file;
	//njt_str_t  tag = njt_string("\n}\n");
	int32_t  rlen;
	//njt_http_sub_location_info_t **loc_array;
    

    cscf = njt_http_get_srv_by_port((njt_cycle_t  *)njt_cycle,&location_info->addr_port,&location_info->server_name);	
    (*location_info).cscf = cscf;

        location_path = njt_cycle->prefix;

        //todo
        //njt_str_set(&location_path, "/tmp/");
        location_full_file.len = location_path.len + location_file.len + 50;//  workid_add_location.txt
        location_full_file.data = njt_pcalloc(location_info->pool, location_full_file.len);
        p = njt_snprintf(location_full_file.data, location_full_file.len, "%Vlogs/%d_%d_%V", &location_path, njt_process, njt_worker,
                         &location_file);
        location_full_file.len = p - location_full_file.data;
    fd = njt_open_file(location_full_file.data, NJT_FILE_CREATE_OR_OPEN | NJT_FILE_RDWR, NJT_FILE_TRUNCATE,
                       NJT_FILE_DEFAULT_ACCESS);
    if (fd == NJT_INVALID_FILE) {
        return;
    }

    
		//loc_array  = location_info->location_array->elts;
		if(location_info->buffer == NULL) {
			location_info->buffer_len = 10240;
			location_info->buffer     = njt_pcalloc(location_info->pool, location_info->buffer_len);
			if(location_info->buffer == NULL) {
				return;
			}
		}
	rc = njt_http_sub_location_write_data(fd,location_info,location_info->location_array,0);
	if (location_info->location_array->nelts > 1) {
		rlen = 1; //njt_write_fd(fd, tag.data, tag.len);
					if(rlen < 0) {
						return;
					}
	}
	
	if (njt_close_file(fd) == NJT_FILE_ERROR) {

	}
    

    if (rc  == NJT_ERROR) {
        return;
    }
    (*location_info).file = location_full_file;
}

static void njt_http_location_clear_dirty_data(njt_http_core_loc_conf_t *clcf) {

    njt_queue_t *x, *q;
    njt_http_location_queue_t *lx;
    njt_http_core_loc_conf_t *dclcf;

        if(clcf->if_locations != NULL) {
    q = njt_queue_head(clcf->if_locations);

    while (q != njt_queue_sentinel(clcf->if_locations)) {
        x = njt_queue_next(q);
        lx = (njt_http_location_queue_t *) q;
        if (lx->dynamic_status == 1) {
            njt_queue_remove(q);
        }
        q = x;
    }
    }

    if(clcf->old_locations != NULL) {
    q = njt_queue_head(clcf->old_locations);

    while (q != njt_queue_sentinel(clcf->old_locations)) {
        x = njt_queue_next(q);
        lx = (njt_http_location_queue_t *) q;
        if (lx->dynamic_status == 1) {
            njt_queue_remove(q);
	    dclcf = lx->exact ? lx->exact : lx->inclusive;
	    njt_http_location_destroy(dclcf);
        }
        q = x;
    }
    }

}
static njt_http_core_loc_conf_t * njt_http_location_find_new_location(njt_http_core_loc_conf_t *clcf) {

    njt_queue_t *x, *q;
    njt_http_location_queue_t *lx;
    njt_http_core_loc_conf_t *dclcf;
    q = njt_queue_head(clcf->old_locations);

    while (q != njt_queue_sentinel(clcf->old_locations)) {
        x = njt_queue_next(q);
        lx = (njt_http_location_queue_t *) q;
        if (lx->dynamic_status == 1) {
	    dclcf = lx->exact ? lx->exact : lx->inclusive;
	    return dclcf;
        }
        q = x;
    }
    return NULL;

}
static njt_str_t njt_http_location_get_full_name(njt_pool_t *pool,njt_str_t src) {
  njt_conf_t cf;
  njt_str_t full_name,*value;
  u_char* index;
  njt_uint_t len,i;
  full_name.len = 0;
  full_name.data = NULL;
  njt_memzero(&cf, sizeof(njt_conf_t));
  cf.pool = pool;
  cf.temp_pool = pool;
  cf.log = njt_cycle->log;
  cf.args = njt_array_create(cf.pool, 10, sizeof(njt_str_t));
    if (cf.args == NULL) {
        return full_name;
    }
   njt_conf_read_memory_token(&cf,src);
   len =0;
   value = cf.args->elts;
    for(i = 0; i < cf.args->nelts; i++){
        //len += value[i].len+1;
        len += value[i].len;
    }
    index = njt_pcalloc(pool,len);
    if (index == NULL){
        return full_name;
    }
    full_name.data = index;
    for(i = 0; i < cf.args->nelts; i++){
        njt_memcpy(index,value[i].data,value[i].len);
        index += value[i].len;
        //*index = (u_char)' ';
        //++index;
    }
    full_name.len = len;
    return full_name;
 
}
