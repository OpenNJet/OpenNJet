#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_stream.h>
#include <njt_json_api.h>
#include <math.h>
#include <njt_http_kv_module.h>
#include <njt_http_sendmsg_module.h>
#include <njet_http_location_module.h>
extern njt_uint_t njt_worker;
extern njt_module_t  njt_http_rewrite_module;



static void
njt_http_location_read_data(njt_http_request_t *r);


static njt_int_t
njt_http_location_handler(njt_http_request_t *r);



static njt_int_t
njt_http_location_init_worker(njt_cycle_t *cycle);

static void *
njt_http_location_create_loc_conf(njt_conf_t *cf);

static char *njt_http_location_merge_loc_conf(njt_conf_t *cf,
                                              void *parent, void *child);

static void *
njt_http_location_create_main_conf(njt_conf_t *cf);

static njt_int_t
njt_http_location_init(njt_conf_t *cf);

extern njt_int_t
njt_http_init_static_location_trees(njt_conf_t *cf,
                                    njt_http_core_loc_conf_t *pclcf);

extern njt_int_t njt_http_init_locations(njt_conf_t *cf,
                                         njt_http_core_srv_conf_t *cscf, njt_http_core_loc_conf_t *pclcf);


static char *
njt_http_location_api(njt_conf_t *cf, njt_command_t *cmd, void *conf);



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


static njt_http_module_t njt_http_location_api_module_ctx = {
        NULL,                              /* preconfiguration */
        njt_http_location_init,                              /* postconfiguration */

        njt_http_location_create_main_conf,                              /* create main configuration */
        NULL,                              /* init main configuration */

        NULL,                              /* create server configuration */
        NULL,                              /* merge server configuration */

        njt_http_location_create_loc_conf, /* create location configuration */
        njt_http_location_merge_loc_conf   /* merge location configuration */
};

njt_module_t njt_http_location_api_module = {
        NJT_MODULE_V1,
        &njt_http_location_api_module_ctx, /* module context */
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



static njt_int_t
njt_http_location_init(njt_conf_t *cf) {
    njt_http_core_main_conf_t *cmcf;
    njt_http_handler_pt *h;
    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);
    //njt_http_location_handler
    h = njt_array_push(&cmcf->phases[NJT_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_http_location_handler;
    return NJT_OK;
}


static void *
njt_http_location_create_loc_conf(njt_conf_t *cf) {
    //ssize_t size;
    //njt_str_t zone = njt_string("api_dy_server");
    njt_http_location_loc_conf_t *uclcf;
    //size = (ssize_t)(10 * njt_pagesize);
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
    //ssize_t size;
    //njt_str_t zone = njt_string("api_dy_server");

    njt_http_location_main_conf_t *uclcf;

    //size = (ssize_t)(10 * njt_pagesize);
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

static njt_buf_t *
njt_http_upstream_api_get_out_buf(njt_http_request_t *r, ssize_t len,
                                  njt_chain_t *out) {
    njt_buf_t *b;
    njt_chain_t *last_chain, *new_chain;


    if ((njt_uint_t) len > njt_pagesize) {
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
                                     njt_chain_t *out, njt_str_t *str) {
    njt_buf_t *b;

    if (str->len == 0) {
        return NJT_OK;
    }
    if (str == NULL || str->data == NULL) {
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

static ssize_t
njt_http_upstream_api_out_len(njt_chain_t *out) {
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
njt_http_location_handler(njt_http_request_t *r) {
    njt_int_t rc = NJT_OK;
    njt_chain_t out;
    njt_str_t insert;
    njt_conf_t conf;
    njt_http_location_loc_conf_t *loc;
    njt_http_location_info_t *location_info;

	 //njt_log_debug0(NJT_LOG_DEBUG_ALLOC, r->pool->log, 0, "zyg 0 read_client_request_body start +++++++++++++++");
    //njt_str_t location_req = njt_string("/add_location");



    out.next = NULL;
    out.buf = NULL;
    njt_memzero(&conf, sizeof(njt_conf_t));
    loc = njt_http_get_module_loc_conf(r, njt_http_location_api_module);
    if (loc && loc->dyn_location_enable) {
        //printf("11");
    } else {
        //printf("NJT_DECLINED");
        return NJT_DECLINED;
    }


    njt_log_debug0(NJT_LOG_DEBUG_ALLOC, r->pool->log, 0, "1 read_client_request_body start +++++++++++++++");
    rc = njt_http_read_client_request_body(r, njt_http_location_read_data);
	location_info = njt_http_get_module_ctx(r, njt_http_location_api_module);
	njt_log_debug0(NJT_LOG_DEBUG_ALLOC, r->pool->log, 0, "2 read_client_request_body end +++++++++++++++");


    if (rc == NJT_OK) {
        njt_http_finalize_request(r, NJT_DONE);
    }
	/*
	if(rc == NJT_ERROR) {
		location_info->code = 1; //json error
	} else if(location_info->sport.len == 0) {
		location_info->code = 2; //sport error
	}else if(location_info->location.len == 0) {
		location_info->code = 3; //location error
	}else if(location_info->type == -1) {
		location_info->code = 4; //type error
	}else if(location_info->location_body.len == 0) {
		location_info->code = 5; //location_body error
	}*/
	
    if (location_info != NULL && location_info->code == 0) {
        njt_str_set(&insert, "Success");
    } else {
		if(location_info == NULL) {
			njt_str_set(&insert, "json parser error!");
		} else if(location_info->code == 1){
			njt_str_set(&insert, "sport error!!!");
		}else if(location_info->code == 2){
			njt_str_set(&insert, "location error!!!");
		}else if(location_info->code == 3){
			njt_str_set(&insert, "proxy_pass error!!!");
		}else if(location_info->code == 4){
			njt_str_set(&insert, "server_name error!!!");
		}else if(location_info->code == 5){
			njt_str_set(&insert, "location_body error!!!");
		}else if(location_info->code == 6){
			njt_str_set(&insert, "type error!!!");
		}
        
    }

	if(location_info != NULL) {
		njt_destroy_pool(location_info->pool);
	}

    r->headers_out.content_type_len = sizeof("text/plain") - 1;
    njt_str_set(&r->headers_out.content_type, "text/plain");
    r->headers_out.content_type_lowcase = NULL;
    r->headers_out.status = NJT_HTTP_OK;
    rc = njt_http_upstream_api_insert_out_str(r, &out, &insert);
    int len = njt_http_upstream_api_out_len(&out);
    r->headers_out.content_length_n = len;
    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }
    rc = njt_http_send_header(r);
    return njt_http_output_filter(r, &out);
}


static njt_int_t
njt_http_location_init_worker(njt_cycle_t *cycle) {

    return NJT_OK;
}


static void
njt_http_location_read_data(njt_http_request_t *r){
	njt_str_t json_str;
    njt_chain_t *body_chain;
    //njt_int_t rc;
    u_char *p;
    njt_http_location_info_t *location_info;
	 uint32_t                                      crc32;
	 uint32_t									   topic_len = NJT_INT64_LEN  + 2;
	 njt_str_t									   topic_name;
	njt_str_t  add = njt_string("add");
	njt_str_t  del = njt_string("del");
   



    body_chain = r->request_body->bufs;
    if (body_chain && body_chain->next) {
        /*The post body is too large*/
        //rc = NJT_ERROR;
		 njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "njt_http_location_read_data njt_pcalloc error.");
        return;
    }

	
    /*check the sanity of the json body*/
    json_str.data = body_chain->buf->pos;
    json_str.len = body_chain->buf->last - body_chain->buf->pos;
	location_info = njt_http_parser_location_data(json_str);
	if(location_info == NULL) {
		return;
	}
	njt_http_set_ctx(r, location_info, njt_http_location_api_module);
	if(location_info->code != 0) {
		return;
	}

	njt_crc32_init(crc32);
	njt_crc32_update(&crc32,location_info->addr_port.data,location_info->addr_port.len);
	if (location_info->server_name.len > 0) {
		njt_crc32_update(&crc32,location_info->server_name.data,location_info->server_name.len);
	}
	if (location_info->location_rule.len > 0) {
		njt_crc32_update(&crc32,location_info->location_rule.data,location_info->location_rule.len);
	}
	njt_crc32_update(&crc32,location_info->location.data,location_info->location.len);
	njt_crc32_final(crc32);

   
	topic_name.data = njt_pcalloc(r->pool,topic_len);
	 if (topic_name.data == NULL) {
		 njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "topic_name njt_pcalloc error.");
        return;
    }
	
	p = njt_snprintf(topic_name.data,topic_len,"/dyn/loc/l_%d",crc32);
	topic_name.len = p - topic_name.data;
	if(location_info->type.len == del.len && njt_strncmp(location_info->type.data,del.data,location_info->type.len) == 0 ){
		njt_dyn_sendmsg(&topic_name,&json_str,0);
	} else  if(location_info->type.len == add.len && njt_strncmp(location_info->type.data,add.data,location_info->type.len) == 0 ){
		njt_dyn_sendmsg(&topic_name,&json_str,1);
	}
	

	njt_log_error(NJT_LOG_DEBUG, r->connection->log, 0, "1 send topic retain_flag=%V, key=%V,value=%V",&location_info->type,&topic_name,&json_str);

	//njt_http_location_write_data(location_info);

}










