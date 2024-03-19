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


static void njt_http_location_write_data(njt_http_location_info_t *location_info);
typedef struct njt_http_location_ctx_s {
} njt_http_location_ctx_t, njt_stream_http_location_ctx_t;


typedef struct njt_http_location_main_conf_s {
} njt_http_location_main_conf_t;


static  njt_str_t njt_invalid_dyn_location_body[] = {
	njt_string("zone"),
	//njt_string("alias"),
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
    njt_str_t location_name;

    if(location_info->buffer.len == 0 || location_info->buffer.data == NULL) {
           njt_log_error(NJT_LOG_DEBUG,njt_cycle->pool->log, 0, "buffer null");
		   njt_str_set(&location_info->msg,"error:buffer null!");
           return NJT_ERROR;
    }
    
    cscf = location_info->cscf;
    if (cscf == NULL || location_info->location.len == 0) {
			if(cscf == NULL){
                    p = njt_snprintf(location_info->buffer.data,location_info->buffer.len, "error:host[%V],no find server [%V]!", &location_info->addr_port,&location_info->server_name);
                    location_info->msg = location_info->buffer;
                    location_info->msg.len = p - location_info->buffer.data;
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
	    NULL,
    };

    //njt_log_error(NJT_LOG_DEBUG,njt_cycle->pool->log, 0, "find && free old location start +++++++++++++++");
	location_name.len = (location_info->location_rule.len + location_info->location.len) + 1;
	location_name.data = njt_pcalloc(location_info->pool,location_name.len);
	if(location_name.data == NULL) {
		return NJT_ERROR;
	}
	if(location_info->location_rule.len > 0) {
		p = njt_snprintf(location_name.data,location_name.len, "%V%V", &location_info->location_rule,
								 &location_info->location);
	} else {
		p = njt_snprintf(location_name.data,location_name.len, "%V", &location_info->location);
	}
	location_name.len = p - location_name.data;



    if(clcf->old_locations == NULL) {
	   lq = NULL;
    } else {
		lq = njt_http_find_location(location_name, clcf->old_locations);
	}
    if (lq == NULL) {
		njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0, "not find  location [%V]!",&location_name);
		
		p = njt_snprintf(location_info->buffer.data,location_info->buffer.len, "not find  location [%V]!", &location_name);
		location_info->msg = location_info->buffer;
		location_info->msg.len = p - location_info->buffer.data;
		
	
        return NJT_ERROR;
    }


    dclcf = lq->exact ? lq->exact : lq->inclusive;
    //if(dclcf->dynamic_status == 0) {
    //    njt_log_error(NJT_LOG_DEBUG, njt_cycle->pool->log, 0, "static  location=%V not allow delete!",&location_name);
    //	return NJT_OK;
    //}
    if(dclcf->if_loc == 1) {
	if_lq = njt_http_find_location(location_name, clcf->if_locations);
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

#if (NJT_HELPER_GO_DYNCONF) // add for dyn_conf update
	if (njt_process == NJT_PROCESS_HELPER) {
		njt_pool_t *dyn_pool = njt_create_pool(NJT_CYCLE_POOL_SIZE, njt_cycle->log);
		njt_conf_dyn_loc_del_loc(njt_conf_dyn_loc_pool, njt_conf_dyn_loc_ptr, (void *)location_info);
		njt_conf_dyn_loc_save_pub_to_file(dyn_pool, njt_cycle->log, njt_conf_dyn_loc_ptr);
		njt_destroy_pool(dyn_pool);
	}
#endif	// end for dyn_loc conf update

    return NJT_OK;
	
}
static njt_int_t njt_http_add_location_handler(njt_http_location_info_t *location_info,njt_uint_t from_api_add) {
    njt_conf_t conf;
    njt_int_t rc = NJT_OK;

    njt_http_core_srv_conf_t *cscf;
    char *rv = NULL;
    njt_http_core_loc_conf_t *clcf,*new_clcf;
    njt_str_t location_name;
    u_char *p;
	njt_http_sub_location_info_t  *sub_location, *loc;
    njt_http_location_queue_t *lq;

    njt_str_t location_path; // = njt_string("./conf/add_location.txt");
	
#if (NJT_HELPER_GO_DYNCONF) // add for dyn_conf update
	njt_conf_element_t *dyn_loc = NULL;
	njt_pool_t         *dyn_pool = NULL;
#endif	// end for dyn_conf update

    //njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "add location start +++++++++++++++");
	if(location_info->buffer.len == 0 || location_info->buffer.data == NULL) {
		njt_log_error(NJT_LOG_DEBUG,njt_cycle->pool->log, 0, "buffer null");
		njt_str_set(&location_info->msg,"error:buffer null!");
        return NJT_ERROR;
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
		location_name.len = (loc->location_rule.len + loc->location.len + 128);
        location_name.data = njt_pcalloc(location_info->pool,location_name.len);
		if(location_name.data == NULL) {
			rc = NJT_ERROR;
			return rc;
		}
        if(loc->location_rule.len > 0) {
                p = njt_snprintf(location_name.data, location_name.len, "%V%V", &loc->location_rule,
                                                                 &loc->location);
        } else {
                p = njt_snprintf(location_name.data, location_name.len, "%V", &loc->location);
        }
        location_name.len = p - location_name.data;
	

    cscf = location_info->cscf;  
    if (cscf == NULL) {
		 //njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "error:host[%V],no find server[%V]!",&location_info->addr_port,&location_info->server_name);
		 rv = "no find server!";
		 njt_str_set(&location_info->msg,"no find server!");
		 if(location_info->buffer.data != NULL){
			p = njt_snprintf(location_info->buffer.data,location_info->buffer.len, "error:host[%V],no find server[%V]!",&location_info->addr_port,&location_info->server_name);
			location_info->msg = location_info->buffer;
			location_info->msg.len = p - location_info->buffer.data;
		 }
		 rc = NJT_ERROR;
		 goto out;
    }
    clcf = cscf->ctx->loc_conf[njt_http_core_module.ctx_index];
	if(clcf->old_locations) {
	    lq = njt_http_find_location(location_name, clcf->old_locations);
	    if (lq != NULL) {  
		 njt_str_set(&location_info->msg,"location exist!");
		 if(location_info->buffer.data != NULL){
			 p = njt_snprintf(location_info->buffer.data,location_info->buffer.len, "error:location[%V] exist!", &location_name);
			 location_info->msg = location_info->buffer;
			 location_info->msg.len = p - location_info->buffer.data;

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

    location_info->msg.len = NJT_MAX_CONF_ERRSTR;
    location_info->msg.data = location_info->buffer.data;
    if(location_info->msg.data != NULL){ 
		njt_memzero(location_info->msg.data,location_info->msg.len);
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

#if (NJT_HELPER_GO_DYNCONF) // add for dyn_conf update
	if (njt_process == NJT_PROCESS_HELPER) {
		dyn_loc = njt_pcalloc(njt_cycle->pool, sizeof(njt_conf_element_t));
		if (dyn_loc == NULL) {
			rc = NJT_ERROR;
			goto out;
		}
		njt_conf_cur_ptr = dyn_loc;
		njt_conf_init_conf_parse(dyn_loc, njt_conf_dyn_loc_pool);
	}
#endif

    rv = njt_conf_parse(&conf, &location_path);
		
#if (NJT_HELPER_GO_DYNCONF) // add for dyn_conf update
	if (njt_process == NJT_PROCESS_HELPER) {
		njt_conf_finish_conf_parse(); 
	}
#endif

    if (rv != NULL) {
	
	    if(location_info->msg.len == NJT_MAX_CONF_ERRSTR && location_info->msg.data[0] == '\0') {
	    	njt_str_set(&location_info->msg,"njt_conf_parse error!");
	    } else if(location_info->msg.len != NJT_MAX_CONF_ERRSTR) {
	    	njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "njt_conf_parse  location[%V] error:%V",&location_name,&location_info->msg);
	    }
	    //njt_http_location_delete_dyn_var(clcf);
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

#if (NJT_HELPER_GO_DYNCONF) // add for dyn_conf update
	if (njt_process == NJT_PROCESS_HELPER) {
		dyn_pool = njt_create_pool(NJT_CYCLE_POOL_SIZE, njt_cycle->log);
		if (dyn_pool == NULL) {
			rc = NJT_ERROR;
			goto out;
		}
		njt_int_t ret;
		// printf("end of add dyn location . --------------------------\n");
		ret = njt_conf_dyn_loc_merge_location(njt_conf_dyn_loc_pool, &location_info->addr_port, &location_info->server_name, dyn_loc);
		njt_log_error(NJT_LOG_DEBUG,njt_cycle->log, 0, "dyn loc merge result %ld", ret);
		ret = njt_conf_dyn_loc_add_loc(njt_conf_dyn_loc_pool, njt_conf_dyn_loc_ptr, (void *)location_info);
		njt_log_error(NJT_LOG_DEBUG,njt_cycle->log, 0, "dyn loc add result %ld", ret);
		njt_conf_dyn_loc_save_pub_to_file(dyn_pool, njt_cycle->log, njt_conf_dyn_loc_ptr);
	}
    // njt_destroy_pool(dyn_pool);
#endif

out:
#if (NJT_HELPER_GO_DYNCONF) // add for dyn_conf update
    if (dyn_pool != NULL) {
		njt_destroy_pool(dyn_pool);
	}
#endif
    if(rc != NJT_OK) {
    	   njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "add  location [%V] error!",&location_name);
    } else {
	   njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0, "add  location [%V] succ!",&location_name);
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

#if (NJT_HELPER_GO_DYNCONF && 0) // add for dyn_conf update
static njt_str_t *njt_dyn_location_dump_conf(njt_cycle_t *cycle, njt_pool_t *pool) {
	
	// njt_str_t *ret = njt_pcalloc(cycle->pool, sizeof(njt_str_t));
	njt_str_t *ret = njt_conf_dyn_loc_get_ins_str(pool, njt_conf_dyn_loc_ptr);
	return ret;
}

static u_char *njt_agent_location_get_handler(njt_str_t *topic, njt_str_t *request, int *len, void *data) {
#if (NJT_HELPER_GO_DYNCONF) // add for dyn_conf update
    njt_cycle_t *cycle;
    njt_str_t *msg;
    u_char *buf;
    njt_pool_t *pool = NULL;

    buf = NULL;
    cycle = (njt_cycle_t *)njt_cycle;
    *len = 0;

    pool = njt_create_pool(njt_pagesize, njt_cycle->log);
    if (pool == NULL) {
        njt_log_error(NJT_LOG_EMERG, pool->log, 0, "njt_dyn_bwlist_rpc_handler create pool error");
        goto out;
    }

    msg = njt_dyn_location_dump_conf(cycle, pool);
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
#else
    return NULL;
#endif

}
#endif

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

#if (NJT_HELPER_GO_DYNCONF) // add for dyn_conf update
	if (njt_process == NJT_PROCESS_HELPER) { // check for worker_p
		njt_conf_dyn_loc_pool = njt_create_dynamic_pool(NJT_CYCLE_POOL_SIZE, njt_cycle->log);
		if (njt_conf_dyn_loc_pool == NULL) {
			njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "dyn loc: create dynamic pool error ");
			return NJT_ERROR;
		}
		njt_conf_dyn_loc_ptr = njt_conf_dyn_loc_init_server(njt_conf_dyn_loc_pool, njt_cycle->conf_root);
		if (njt_conf_dyn_loc_ptr == NULL) {
			njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "dyn loc: init dyn servers error ");
			return NJT_ERROR;
		}
		njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "dyn loc: init dyn loc conf finished ");
	}
#endif	// end for dyn_conf update

	njt_str_t  key = njt_string("loc");
	// if (njt_process != NJT_PROCESS_WORKER && njt_process != NJT_PROCESS_SINGLE) {
	// 	/*only works in the worker 0 prcess.*/
	// 	return NJT_OK;
	// }
    njt_kv_reg_handler_t h;
    njt_memzero(&h, sizeof(njt_kv_reg_handler_t));
    h.key = &key;
#if (NJT_HELPER_GO_DYNCONF && 0) // by lcm, rmmove && 0 when this handler is needed
	h.rpc_get_handler = njt_agent_location_get_handler;
#endif
    h.rpc_put_handler = njt_agent_location_put_handler;
    h.handler = topic_kv_change_handler;
    h.api_type = NJT_KV_API_TYPE_INSTRUCTIONAL;
    njt_kv_reg_handler(&h);
    return NJT_OK;
}



njt_int_t njt_http_check_sub_location(njt_json_element *in_items,njt_http_location_info_t *location_info) {
 
	njt_json_element  *items;
	njt_str_t   str;
	u_char *p;
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
	
	
	p = njt_snprintf(location_info->buffer.data,location_info->buffer.len,"%V%V!",&error,&items->key);	
	location_info->msg = location_info->buffer;
	location_info->msg.len = p - location_info->buffer.data;
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
static njt_int_t
njt_http_parser_sub_location_data(njt_http_location_info_t *location_info,njt_array_t *location_array,njt_json_element *in_items) {

	njt_json_element *out_items, *items;
	njt_int_t rc;
	njt_str_t  key;
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
			/*
			if(sub_location->location_body.len > 0 && sub_location->location_body.data != NULL) {
				if(njt_strstr(sub_location->location_body.data,"proxy_pass ") != NULL) {
					njt_str_set(&location_info->msg, "directive is not allowed here in location_body");
					return NJT_ERROR;
				}
			}*/

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
	u_char        *p;
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
	
	
	     p = njt_snprintf(location_info->buffer.data,location_info->buffer.len,"%V%V!",&error,&items->key);	
	     location_info->msg = location_info->buffer;
		 location_info->msg.len = p - location_info->buffer.data;
	   
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
	 int32_t  buffer_len;
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
	njt_log_error(NJT_LOG_ERR,njt_cycle->log, 0, "json error!,json=%V",&json_str);
	njt_destroy_pool(location_pool);
        return NULL;
    }
	location_info = njt_pcalloc(location_pool, sizeof(njt_http_location_info_t));
    if (location_info == NULL) {
		njt_destroy_pool(location_pool);
        return NULL;
    }

	
	location_info->pool = location_pool;
	buffer_len = json_str.len  + 1024;
	buffer_len = (buffer_len > NJT_MAX_CONF_ERRSTR ?buffer_len:NJT_MAX_CONF_ERRSTR);
	location_info->buffer.len = 0;
	location_info->buffer.data = njt_pcalloc(location_info->pool,buffer_len);
	if(location_info->buffer.data != NULL) {
		location_info->buffer.len = buffer_len;
	}
		
	
	
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
	buffer_len = location_info->buffer.len;
	remain = buffer_len;
	data = location_info->buffer.data;

	
	loc_array  = location_array->elts;
	for(i=0; i < location_array->nelts; i++) {
		
		loc = &loc_array[i];
		if(loc) {
			njt_memzero(data,buffer_len);
			p = data;
			p = njt_snprintf(p, remain, "location ");
			remain = data + buffer_len - p;

			if(loc->location_rule.len != 0 && loc->location_rule.data != NULL){
				add_escape_val = loc->location_rule;
				p = njt_snprintf(p, remain, "%V ",&add_escape_val);
				remain = data + buffer_len - p;
			}
			if(loc->location.len != 0 && loc->location.data != NULL){
				add_escape_val = loc->location;
				p = njt_snprintf(p, remain, "%V {\n",&add_escape_val);
				remain = data + buffer_len - p;
			}
			if(loc->location_body.len != 0 && loc->location_body.data != NULL){
				add_escape_val = loc->location_body;
				if(add_escape_val.len > 0 && add_escape_val.data[add_escape_val.len-1] != ';' && add_escape_val.data[add_escape_val.len-1] != '}'){
					p = njt_snprintf(p, remain, " %V; \n",&add_escape_val);
				} else {
					p = njt_snprintf(p, remain, " %V \n",&add_escape_val);
				}
				remain = data + buffer_len - p;
			}
			if(loc->proxy_pass.len != 0 && loc->proxy_pass.data != NULL){
				add_escape_val = loc->proxy_pass; 
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

    
    njt_fd_t fd;
    njt_int_t  rc; 
    
    u_char *p; // *data;
    njt_http_core_srv_conf_t *cscf;
  
    njt_str_t location_file = njt_string("add_location.txt");
    njt_str_t location_path;
    njt_str_t location_full_file;
	int32_t  rlen;
    

    cscf = njt_http_get_srv_by_port((njt_cycle_t  *)njt_cycle,&location_info->addr_port,&location_info->server_name);	

        location_path = njt_cycle->prefix;

        //todo
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
    (*location_info).cscf = cscf;
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
	    njt_http_location_delete_dyn_var(dclcf);
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
