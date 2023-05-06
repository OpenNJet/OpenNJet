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
#include <njt_http_location_module.h>
extern njt_uint_t njt_worker;
extern njt_module_t  njt_http_rewrite_module;



static void
free_static_tree_momery(njt_http_location_tree_node_t *static_tree);

njt_str_t njt_del_headtail_space(njt_str_t src);

static njt_int_t
njt_http_location_init_worker(njt_cycle_t *cycle);

static void *
njt_http_location_create_loc_conf(njt_conf_t *cf);

static char *njt_http_location_merge_loc_conf(njt_conf_t *cf,
                                              void *parent, void *child);

static void *
njt_http_location_create_main_conf(njt_conf_t *cf);


extern njt_int_t
njt_http_init_static_location_trees(njt_conf_t *cf,
                                    njt_http_core_loc_conf_t *pclcf);

extern njt_int_t njt_http_init_locations(njt_conf_t *cf,
                                         njt_http_core_srv_conf_t *cscf, njt_http_core_loc_conf_t *pclcf);

static void njt_http_location_clear_dirty_data(njt_http_core_loc_conf_t *clcf);
static njt_http_core_loc_conf_t * njt_http_location_find_new_location(njt_http_core_loc_conf_t *clcf);
static void njt_http_location_delete_dyn_var(njt_http_core_loc_conf_t *clcf);
static void
njt_http_set_del_variable_flag( njt_str_t *name);

static void
njt_http_set_del_variables_keys_flag( njt_str_t *name);

static void
njt_http_refresh_variables_keys();


static char *
njt_http_location_api(njt_conf_t *cf, njt_command_t *cmd, void *conf);


static void njt_http_location_write_data(njt_http_location_info_t *location_info);
typedef struct njt_http_location_ctx_s {
} njt_http_location_ctx_t, njt_stream_http_location_ctx_t;


typedef struct njt_http_location_main_conf_s {
} njt_http_location_main_conf_t;





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




static void njt_http_location_destroy(njt_http_core_loc_conf_t *clcf) {
    njt_queue_t *locations;
    njt_queue_t *q;
    njt_http_location_queue_t *lq;

    locations = clcf->old_locations;
    if (locations != NULL) {
        for (q = njt_queue_head(locations);
             q != njt_queue_sentinel(locations);
             q = njt_queue_next(q)) {
            lq = (njt_http_location_queue_t *) q;
            if (lq->exact != NULL) {
                clcf = lq->exact;
                njt_http_location_destroy(clcf);
            }
            if (lq->inclusive != NULL) {
                clcf = lq->inclusive;
                //njt_http_location_destroy(clcf); zyg 嵌套。
            }
        }
    }
    njt_http_location_cleanup(clcf);
    clcf->disable = 1;
    if (clcf->ref_count == 0 && clcf->pool != NULL) {
    	njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "njt_destroy_pool clcf=%p",clcf);
        njt_destroy_pool(clcf->pool);
    }
}

static njt_http_location_queue_t *njt_http_find_location(njt_str_t name, njt_queue_t *locations) {
    njt_queue_t *x;
    njt_http_location_queue_t *lq;
    njt_http_core_loc_conf_t *clcf;

    for (x = njt_queue_head(locations);
         x != njt_queue_sentinel(locations);
         x = njt_queue_next(x)) {
        lq = (njt_http_location_queue_t *) x;
        clcf = lq->exact ? lq->exact : lq->inclusive;
        if (name.len == clcf->full_name.len) {
            if (njt_strncmp(name.data, clcf->full_name.data, name.len) == 0) {
                return lq;
            }
        }
    }
    return NULL;
}

static njt_int_t
njt_http_refresh_location(njt_conf_t *cf, njt_http_core_srv_conf_t *cscf, njt_http_core_loc_conf_t *clcf) {
    njt_http_location_tree_node_t *saved_static_locations;
    njt_queue_t *x;
    njt_http_location_queue_t *lq, *lx;
    njt_int_t rc = NJT_OK;
    njt_http_location_queue_t *tmp_queue;

    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "new_locations njt_palloc start +++++++++++++++");
    //dump old_location to a new_location
    if (clcf->new_locations == NULL) {
        clcf->new_locations = njt_palloc(clcf->pool,
                                         sizeof(njt_http_location_queue_t));
        if (clcf->new_locations == NULL) {
            rc = NJT_ERROR;
            return rc;
        }

        tmp_queue = (njt_http_location_queue_t *) clcf->new_locations;
        //used for delete memory
        tmp_queue->parent_pool = clcf->pool;
        njt_queue_init(clcf->new_locations);
    }
    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "new_locations njt_palloc end +++++++++++++++");

    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "free new_locations start +++++++++++++++");

    for (x = njt_queue_head(clcf->new_locations);
         x != njt_queue_sentinel(clcf->new_locations);) {
        lq = njt_queue_data(x, njt_http_location_queue_t, queue);
        x = njt_queue_next(x);
        njt_queue_remove(&lq->queue);
        njt_pfree(lq->parent_pool, lq);
    }
    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "free new_locations end +++++++++++++++");

    njt_log_error(NJT_LOG_DEBUG,njt_cycle->log, 0, "copy old_locations start +++++++++++++++");

    for (x = njt_queue_head(clcf->old_locations);
         x != njt_queue_sentinel(clcf->old_locations);
         x = njt_queue_next(x)) {
        lx = (njt_http_location_queue_t *) x;
        lq = njt_palloc(clcf->pool, sizeof(njt_http_location_queue_t));
        if (lq == NULL) {
            return NJT_ERROR;
        }
        if (lx->dynamic_status == 1) {
            lx->dynamic_status = 2;
        }
        *lq = *lx;
        lq->parent_pool = clcf->pool;

        njt_queue_init(&lq->list);
        njt_queue_insert_tail(clcf->new_locations, &lq->queue);
    }
    njt_log_error(NJT_LOG_DEBUG,njt_cycle->log, 0, "copy old_locations end +++++++++++++++");

    if (njt_http_init_new_locations(cf, cscf, clcf) != NJT_OK) {
        return NJT_ERROR;
    }
    njt_log_error(NJT_LOG_DEBUG,njt_cycle->log, 0, "init_new_static_location_trees start +++++++++++++++");
    clcf->new_static_locations = NULL;
    if (njt_http_init_new_static_location_trees(cf, clcf) != NJT_OK) {
        return NJT_ERROR;
    }
    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "init_new_static_location_trees end +++++++++++++++");
    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "free old location start +++++++++++++++");

//save last locations
    saved_static_locations = clcf->static_locations;

    clcf->static_locations = clcf->new_static_locations;

    //free old static_locations tree node
    //now just delete dynamic tree(clcf->pool), initial static tree not delete(cf->pool)
    free_static_tree_momery(saved_static_locations);
    njt_log_error(NJT_LOG_DEBUG,njt_cycle->log, 0, "free old location end +++++++++++++++");
    return rc;
}

static njt_int_t
njt_http_location_delete_handler(njt_http_location_info_t *location_info) {
    njt_http_core_srv_conf_t *cscf;
    njt_http_core_loc_conf_t *clcf, *dclcf;
    njt_http_location_queue_t *lq;
	u_char *p;
	njt_str_t location_name;
    cscf = location_info->cscf;
    if (cscf == NULL || location_info->location.len == 0) {
        return NJT_ERROR;
    }
    clcf = cscf->ctx->loc_conf[njt_http_core_module.ctx_index];

    njt_http_conf_ctx_t cf_ctx = { //zyg todo
            cscf->ctx->main_conf,  ///r->main_conf
            cscf->ctx->srv_conf,   //r->srv_conf
            cscf->ctx->loc_conf,   //r->loc_conf
    };
    njt_conf_t cf = {
            NULL,
            NULL,
            (njt_cycle_t *) njt_cycle,
            clcf->pool,
            clcf->pool,
            NULL,
            njt_cycle->log,
            1,
            &cf_ctx,
            NJT_HTTP_MODULE,
            NJT_CONF_BLOCK,
            NULL,
            NULL,
    };
    njt_log_error(NJT_LOG_DEBUG,njt_cycle->pool->log, 0, "delete start +++++++++++++++");

    njt_log_error(NJT_LOG_DEBUG,njt_cycle->pool->log, 0, "find && free old location start +++++++++++++++");

	location_name.data = njt_pcalloc(location_info->pool, 1024);
	if(location_info->location_rule.len > 0) {
		p = njt_snprintf(location_name.data, 1024, "%V%V", &location_info->location_rule,
								 &location_info->location);
	} else {
		p = njt_snprintf(location_name.data, 1024, "%V", &location_info->location);
	}
	location_name.len = p - location_name.data;

    if(clcf->old_locations == NULL) {
	 return NJT_OK;
    }
    lq = njt_http_find_location(location_name, clcf->old_locations);
    if (lq == NULL) {
        return NJT_ERROR;
    }


    dclcf = lq->exact ? lq->exact : lq->inclusive;

    njt_http_location_delete_dyn_var(dclcf);
    njt_queue_remove(&lq->queue);
    njt_pfree(lq->parent_pool, lq);
    njt_log_error(NJT_LOG_DEBUG, njt_cycle->pool->log, 0, "find && free old location end +++++++++++++++");

    njt_http_refresh_location(&cf, cscf, clcf);

    njt_http_location_destroy(dclcf);
    //note: delete queue memory, which delete when remove queue 
    njt_log_error(NJT_LOG_DEBUG, njt_cycle->pool->log, 0, "delete end  %V+++++++++++++++",&location_name);
    return NJT_OK;
}

static void free_static_tree_momery(njt_http_location_tree_node_t *static_tree) {
    if (static_tree == NULL) {
        return;
    }

    free_static_tree_momery(static_tree->left);
    static_tree->left = NULL;
    free_static_tree_momery(static_tree->right);
    static_tree->right = NULL;
    free_static_tree_momery(static_tree->tree);
    static_tree->tree = NULL;

    njt_pfree(static_tree->parent_pool, static_tree);
}

njt_int_t njt_http_check_upstream_exist(njt_cycle_t *cycle,njt_pool_t *pool, njt_str_t *name) {
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
    p = (u_char *) njt_strchr(name->data, '$');
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
}



static njt_int_t njt_http_add_location_handler(njt_http_location_info_t *location_info) {
    njt_conf_t conf;
    njt_int_t rc = NJT_OK;
	njt_uint_t  i;
    njt_http_core_srv_conf_t *cscf;
    char *rv = NULL;
    njt_http_core_loc_conf_t *clcf,*new_clcf;
    njt_str_t location_name;
    u_char *p;
	njt_http_sub_location_info_t  *sub_location, *loc;
    njt_http_location_queue_t *lq;

    njt_str_t location_path; // = njt_string("./conf/add_location.txt");

    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "add location start +++++++++++++++");


	if (location_info->location_array == NULL || location_info->location_array->nelts == 0) {
    	njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "add location error:location_path=0");
        rc = NJT_ERROR;
        goto out;
    }
    location_path.len = 0;
    location_path.data = NULL;
    if (location_info->file.len != 0) {
        location_path = location_info->file;
    }
	

    if (location_path.len == 0) {
    	njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "add location error:location_path=0");
        rc = NJT_ERROR;
        goto out;
    }


    if (rc == NJT_ERROR || rc > NJT_OK) {
    	njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "add location error!");
        rc = NJT_ERROR;
        goto out;
    }
		sub_location = location_info->location_array->elts;
		loc = &sub_location[0];

        location_name.data = njt_pcalloc(location_info->pool, 1024);
        if(location_info->location_rule.len > 0) {
                p = njt_snprintf(location_name.data, 1024, "%V%V", &loc->location_rule,
                                                                 &loc->location);
        } else {
                p = njt_snprintf(location_name.data, 1024, "%V", &loc->location);
        }
        location_name.len = p - location_name.data;
	
	sub_location = location_info->location_array->elts;
	for(i = 0; i < location_info->location_array->nelts; i++) {
		loc = &sub_location[i];
		rc = njt_http_check_upstream_exist((njt_cycle_t  *)njt_cycle,location_info->pool, &loc->proxy_pass);
		if (rc != NJT_OK) {
			goto out;
		    rc = NJT_OK;
		}
	}

    cscf = location_info->cscf;  
    if (cscf == NULL) {
	//njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "add location[%v] error:no find server!",&location_name);
	rv = "no find server!";
        rc = NJT_ERROR;
        goto out;
    }
    clcf = cscf->ctx->loc_conf[njt_http_core_module.ctx_index];
	if(clcf->old_locations) {
	    lq = njt_http_find_location(location_name, clcf->old_locations);
	    if (lq != NULL) {  
    		 njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "add location error:location exist!");
		 rc = NJT_OK;
		goto out;
	    }
	}

    

    njt_memzero(&conf, sizeof(njt_conf_t));
    conf.args = njt_array_create(location_info->pool, 10, sizeof(njt_str_t));
    if (conf.args == NULL) {
	rc = NJT_ERROR;
	goto out;
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
    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "njt_conf_parse start +++++++++++++++");
    rv = njt_conf_parse(&conf, &location_path);
    if (rv != NULL) {
	
		//njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "njt_conf_parse  location[%V] error:%s",&location_name,rv);
        njt_http_location_clear_dirty_data(clcf);
        rc = NJT_ERROR;
        goto out;
    }
    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "njt_conf_parse end +++++++++++++++");

    conf.pool = clcf->pool; 
    new_clcf = njt_http_location_find_new_location(clcf);
    if(new_clcf != NULL && new_clcf->pool != NULL){
	//conf.pool = new_clcf->pool;  //zyg new add location  pool.  used by merge
    }
   
    njt_http_variables_init_vars(&conf);


    //merge servers
    njt_http_module_t *module;
    njt_uint_t mi, m;
    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "merge start +++++++++++++++");
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
    		njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "add location error:merge_locations!");
                goto out;
            }
        }
    }
    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "merge end +++++++++++++++");

    rc = njt_http_refresh_location(&conf, cscf, clcf);
    if (rc != NJT_OK) {
	njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "add location error:njt_http_refresh_location!");
        goto out;
    }
    njt_log_error(NJT_LOG_DEBUG,njt_cycle->log, 0, "add location end +++++++++++++++");
out:
    if(rc != NJT_OK) {
    	njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "add  location[%V] error",&location_name);
    } else {
		njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "add  location[%V] succ!",&location_name);
    }
    return rc;
}





static int topic_kv_change_handler(njt_str_t *key, njt_str_t *value, void *data) {
	njt_str_t  add = njt_string("add");
	njt_str_t  del = njt_string("del");
	njt_str_t  del_topic = njt_string("");
	njt_int_t rc = NJT_OK;
	njt_http_location_info_t *location_info;
	njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "get topic  key=%V,value=%V",key,value);

	location_info = njt_http_parser_location_data(*value);
	if(location_info == NULL) {
		njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "topic msg error key=%V,value=%V",key,value);
		return NJT_ERROR;
	}
	if(location_info->type.len == add.len && njt_strncmp(location_info->type.data,add.data,location_info->type.len) == 0 ) {
		njt_http_location_write_data(location_info);
		rc = njt_http_add_location_handler(location_info);  //njt_http_location_delete_handler
		if(rc != NJT_OK) {
			njt_kv_sendmsg(key,&del_topic,1);
			njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "add topic_kv_change_handler error key=%V,value=%V",key,value);
		} else {
			njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "add topic_kv_change_handler succ key=%V,value=%V",key,value);
		}
	} else if(location_info->type.len == del.len && njt_strncmp(location_info->type.data,del.data,location_info->type.len) == 0 ){
		njt_http_location_write_data(location_info);
		njt_http_location_delete_handler(location_info);
		njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "delete topic_kv_change_handler key=%V,value=%V",key,value);
	}
	njt_destroy_pool(location_info->pool);
	
	return NJT_OK;
}

static njt_int_t
njt_http_location_init_worker(njt_cycle_t *cycle) {

	njt_str_t  key = njt_string("loc");
	njt_reg_kv_change_handler(&key, topic_kv_change_handler,NULL, NULL);
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
			}
			
			njt_str_set(&key,"proxy_pass");
			rc = njt_struct_find(items, &key, &out_items);
			if(rc == NJT_OK ){
				 if (out_items->type != NJT_JSON_STR) {
				 njt_str_set(&location_info->msg, "proxy_pass error!!!");
					  return NJT_ERROR;
					}
				sub_location->proxy_pass = out_items->strval;
			} 

			njt_str_set(&key,"location_body");
			rc = njt_struct_find(items, &key, &out_items);
			if( (location_info->type.len == add.len && njt_strncmp(location_info->type.data,add.data,location_info->type.len) == 0)) {
				if(rc != NJT_OK || out_items->type != NJT_JSON_STR){
				 if(sub_location->proxy_pass.len == 0) {
					njt_str_set(&location_info->msg, "location_body null");
					return NJT_ERROR;
				  } else {
					njt_str_set(&sub_location->location_body," ");
				  }
				} else {
					sub_location->location_body = out_items->strval;
				}
			} else if(rc == NJT_OK && out_items->type == NJT_JSON_STR) {
				 sub_location->location_body = out_items->strval;
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
njt_http_location_info_t * njt_http_parser_location_data(njt_str_t json_str) {
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
        return NULL;;
    }
	//location_info->type = -1;
	location_info->pool = location_pool;

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
		location_info->addr_port = items->strval;
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
		location_info->type = items->strval;
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
		location_info->server_name = items->strval;
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
				p = njt_snprintf(p, remain, "%V",&loc->location_rule);
				remain = data + buffer_len - p;
			}
			if(loc->location.len != 0 && loc->location.data != NULL){
				
				p = njt_snprintf(p, remain, "%V {\n",&loc->location);
				remain = data + buffer_len - p;
			}
			if(loc->location_body.len != 0 && loc->location_body.data != NULL){
				p = njt_snprintf(p, remain, " %V \n",&loc->location_body);
				remain = data + buffer_len - p;
			}
			if(loc->proxy_pass.len != 0 && loc->proxy_pass.data != NULL){
				p = njt_snprintf(p, remain, " proxy_pass %V;\n",&loc->proxy_pass);
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
        location_full_file.len = location_path.len + location_file.len + 10;//  workid_add_location.txt
        location_full_file.data = njt_pcalloc(location_info->pool, location_full_file.len);
        p = njt_snprintf(location_full_file.data, location_full_file.len, "%Vlogs/%d_%V", &location_path, njt_worker,
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

static void njt_http_location_delete_dyn_var(njt_http_core_loc_conf_t *clcf) {

	
	//njt_http_core_main_conf_t  *cmcf;
	
	//njt_hash_keys_arrays_t    *new_variables_keys;
	njt_http_variable_t                     **ip;
	njt_uint_t	               i;
	njt_uint_t                 rf = 0;
	njt_http_rewrite_loc_conf_t  *rlcf = clcf->loc_conf[njt_http_rewrite_module.ctx_index];  //njt_http_conf_get_module_loc_conf(clcf,njt_http_rewrite_module); //clcf->loc_conf[njt_http_core_module.ctx_index])
	//cmcf = njt_http_cycle_get_module_main_conf(njt_cycle, njt_http_core_module);
	
	ip = rlcf->var_names.elts;

	for(i=0; i < rlcf->var_names.nelts; i++) {   //var_names，location 上内存不需要释放。
		ip[i]->ref_count--;
		//printf("%s",ip[i]->name.data);
		if( (ip[i]->ref_count == 0 && ip[i]->flags &  NJT_HTTP_DYN_VAR) ){

			
			
			//printf("%s",ip[i]->name.data);
			njt_http_set_del_variable_flag(&ip[i]->name);
			njt_http_set_del_variables_keys_flag(&ip[i]->name);
			rf = 1;
		}
	}
	if(rf == 1) {
		njt_http_refresh_variables_keys();
	}

	
}

static void
njt_http_set_del_variable_flag( njt_str_t *name)
{
    njt_uint_t                  i;
    njt_http_variable_t        *v;
    njt_http_core_main_conf_t  *cmcf;

  

    cmcf = njt_http_cycle_get_module_main_conf(njt_cycle, njt_http_core_module); //variables  动态pool 上申请，格位重复使用。 内存释放
	if(cmcf == NULL) {
		return;
	}

    v = cmcf->variables.elts;

    if (v == NULL) {
        return;
    } else {
        for (i = 0; i < cmcf->variables.nelts; i++) {
            if (name->len != v[i].name.len
                || njt_strncasecmp(name->data, v[i].name.data, name->len) != 0)
            {
                continue;
            }
           njt_pfree(cmcf->variables.pool,v[i].name.data);
		   v[i].name.data = NULL;
		   v[i].name.len =  0;
		   break;
        }
    }
 
}

static void
njt_http_set_del_variables_keys_flag( njt_str_t *name)
{
    njt_uint_t                  i;
    njt_http_variable_t        *v;
    njt_http_core_main_conf_t  *cmcf;
	njt_hash_key_t             *key;

  

   cmcf = njt_http_cycle_get_module_main_conf(njt_cycle, njt_http_core_module);
   if(cmcf == NULL) {
		return;
	}

   key = cmcf->variables_keys->keys.elts;

    if ( key == NULL) {
        return;
    } else {
       for (i = 0; i < cmcf->variables_keys->keys.nelts; i++) {
        if (name->len != key[i].key.len
            || njt_strncasecmp(name->data, key[i].key.data, name->len) != 0)
        {
            continue;
        }

        v = key[i].value;
	if(v != NULL && v->name.data != NULL) {
	   njt_pfree(cmcf->dyn_var_pool,v->name.data);
	   v->name.data = NULL;
	   v->name.len = 0;
	}
	break;

       }
    }
}


static void
njt_http_refresh_variables_keys(){
	
    njt_uint_t                  i,count;
    njt_http_variable_t        *v,*newv;
    njt_http_core_main_conf_t  *cmcf;
	njt_hash_key_t             *key;
	njt_pool_t *old_pool;
	u_char *pdata;
	njt_hash_keys_arrays_t    *old_variables_keys;

njt_log_error(NJT_LOG_DEBUG, njt_cycle->pool->log, 0, "zyg begin");

   cmcf = njt_http_cycle_get_module_main_conf(njt_cycle, njt_http_core_module);
   if(cmcf == NULL) {
		return;
	}

   key = cmcf->variables_keys->keys.elts;
   count = cmcf->variables_keys->keys.nelts;
	  old_pool = cmcf->variables_keys->pool;
	  old_variables_keys = cmcf->variables_keys;

	  njt_pool_t *new_pool = njt_create_dynamic_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
	   if(new_pool == NULL) {
		   njt_log_error(NJT_LOG_ERR, njt_cycle->pool->log, 0, "njt_http_refresh_variables_keys create pool error!");
		   return ;
	   }


	   cmcf->variables_keys = njt_pcalloc(new_pool,
                                       sizeof(njt_hash_keys_arrays_t));
		if (cmcf->variables_keys == NULL) {
			cmcf->variables_keys = old_variables_keys; //失败时，继续使用旧的。
			njt_destroy_pool(new_pool);
			njt_log_error(NJT_LOG_ERR, njt_cycle->pool->log, 0, "njt_http_refresh_variables_keys create variables_keys error!");
			return ;
		}

		cmcf->variables_keys->pool = new_pool;
		cmcf->variables_keys->temp_pool = new_pool;

		


		if (njt_hash_keys_array_init(cmcf->variables_keys, NJT_HASH_SMALL) != NJT_OK)
		{
			cmcf->variables_keys = old_variables_keys; //失败时，继续使用旧的。
			njt_destroy_pool(new_pool);
			njt_log_error(NJT_LOG_ERR, njt_cycle->pool->log, 0, "njt_http_refresh_variables_keys njt_hash_keys_array_init  error!");
			return;
		}
 
       for (i = 0; i < count; i++) {
		    v = key[i].value;
			if (v->name.data == NULL || v->name.len == 0)
			{
				njt_pfree(cmcf->dyn_var_pool,v);
				continue;
			}
			
			/*
			newv = njt_palloc(new_pool, sizeof(njt_http_variable_t));
			if (newv == NULL) {
				exit(0); //todo
				return;
			}
			*newv = *v;*/
			pdata = v->name.data;
			newv = v;
			newv->name.data = njt_pnalloc(cmcf->dyn_var_pool, v->name.len);
			

			//num++;
			if (newv->name.data == NULL) {
				cmcf->variables_keys = old_variables_keys; //失败时，继续使用旧的。
				 njt_destroy_pool(new_pool);
				 njt_log_error(NJT_LOG_ERR, njt_cycle->pool->log, 0, "njt_http_refresh_variables_keys name alloc  error!");
				return;
			}

			njt_strlow(newv->name.data, pdata, v->name.len);


			njt_hash_add_key(cmcf->variables_keys, &newv->name, newv, 0);
			
			njt_pfree(cmcf->dyn_var_pool,pdata);
			

		}

		if(old_pool){
		   njt_destroy_pool(old_pool);
		   njt_log_error(NJT_LOG_DEBUG, njt_cycle->pool->log, 0, "zyg njt_destroy_pool pool:%p, remain:%p",old_pool,new_pool);
		}
		njt_log_error(NJT_LOG_DEBUG, njt_cycle->pool->log, 0, "zyg end");
		 //njt_log_error(NJT_LOG_DEBUG, njt_cycle->pool->log, 0, "zyg all:%d, remain:%d",count,num);
		
}
