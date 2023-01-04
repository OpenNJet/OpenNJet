#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_stream.h>
#include <njt_json_api.h>
#include <math.h>

void
njt_http_location_read_data(njt_http_request_t *r);

static njt_int_t
njt_http_location_handler(njt_http_request_t *r);

static char *
njt_http_location(njt_conf_t *cf, njt_command_t *cmd, void *conf);

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


typedef struct njt_http_location_ctx_s {
} njt_http_location_ctx_t, njt_stream_http_location_ctx_t;

typedef struct njt_http_location_loc_conf_s {
    //njt_uint_t write;
} njt_http_location_loc_conf_t;
typedef struct njt_http_location_main_conf_s {
} njt_http_location_main_conf_t;


static njt_command_t njt_http_location_commands[] = {
        {
                njt_string("add_location"),
                NJT_HTTP_LOC_CONF | NJT_CONF_ANY,
                njt_http_location,
                0,
                0,
                NULL
        },
        njt_null_command
};


static njt_http_module_t njt_http_location_module_ctx = {
        NULL,                              /* preconfiguration */
        njt_http_location_init,                              /* postconfiguration */

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
    //uclcf->write = 0;
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
    //njt_http_location_loc_conf_t *prev = parent;
    //njt_http_location_loc_conf_t *conf = child;

    //njt_conf_merge_uint_value(conf->write, prev->write, 0);

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

static void njt_http_location_destroy(njt_http_core_loc_conf_t *clcf) {
    njt_queue_t *locations;
    njt_queue_t *q;
    njt_http_location_queue_t *lq;
    njt_http_location_destroy_t *ld;

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
                njt_http_location_destroy(clcf);
            }
        }
    }

    while (clcf->destroy_locs != NULL) {
        clcf->destroy_locs->destroy_loc(clcf, clcf->destroy_locs->data);
        ld = clcf->destroy_locs;
        clcf->destroy_locs = clcf->destroy_locs->next;
        ld->destroy_loc = NULL;
    }
    clcf->disable = 1;
    if(clcf->disable && clcf->ref_count == 0 && clcf->pool != NULL){
        njt_destroy_pool(clcf->pool);
    }
}

static njt_http_location_queue_t *njt_http_find_location(njt_str_t name, njt_queue_t *locations) {
    njt_queue_t *x;
    njt_http_location_queue_t *lq;
    njt_http_core_loc_conf_t *clcf;

    for (x = njt_queue_next(locations);
         x != njt_queue_sentinel(locations);
         x = njt_queue_next(x)) {
        lq = (njt_http_location_queue_t *) x;
        clcf = lq->exact ? lq->exact : lq->inclusive;
        if(name.len == clcf->full_name.len){
           if (njt_strncmp(name.data, clcf->full_name.data, name.len) == 0) {
            return lq;
           } 
        }
    }
    return NULL;
}

static njt_int_t
njt_http_location_delete_handler(njt_http_request_t *r, njt_str_t name) {
    njt_http_core_srv_conf_t *cscf;
    njt_http_core_loc_conf_t *clcf, *dclcf;
    njt_queue_t *x;
    njt_http_location_queue_t *lq, *lx;

    // njt_str_t name = njt_string("/websocket");
    cscf = njt_http_get_module_srv_conf(r, njt_http_core_module);
    clcf = cscf->ctx->loc_conf[njt_http_core_module.ctx_index];

    njt_http_conf_ctx_t cf_ctx = {
            r->main_conf,
            r->srv_conf,
            r->loc_conf,
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
    if (clcf->new_locations == NULL) {
        clcf->new_locations = njt_palloc(cf.pool, sizeof(njt_http_location_queue_t));
        if (clcf->new_locations == NULL) {
            return NJT_ERROR;
        }

        njt_queue_init(clcf->new_locations);
    }
    lq = njt_http_find_location(name, clcf->old_locations);
    if (lq == NULL) {
        return NJT_ERROR;
    }
    dclcf = lq->exact ? lq->exact : lq->inclusive;
    njt_http_location_destroy(dclcf);
    njt_queue_remove(&lq->queue);
    for (x = njt_queue_next(clcf->old_locations);
         x != njt_queue_sentinel(clcf->old_locations);
         x = njt_queue_next(x)) {
        lx = (njt_http_location_queue_t *) x;
        lq = njt_palloc(cf.pool, sizeof(njt_http_location_queue_t));
        if (lq == NULL) {
            return NJT_ERROR;
        }
        *lq = *lx;
        njt_queue_init(&lq->list);
        njt_queue_insert_tail(clcf->new_locations, &lq->queue);
    }

// todo 换pool 清理内存
    if (njt_http_init_new_locations(&cf, cscf, clcf) != NJT_OK) {
        return NJT_ERROR;
    }

    if (njt_http_init_new_static_location_trees(&cf, clcf) != NJT_OK) {
        return NJT_ERROR;
    }


    cscf->named_locations = cscf->new_named_locations;
    clcf->regex_locations = clcf->new_regex_locations;
    clcf->static_locations = clcf->new_static_locations;

    njt_http_discard_request_body(r);
    r->headers_out.status = NJT_HTTP_NO_CONTENT;
    njt_int_t rc = njt_http_send_header(r);
    if (rc == NJT_ERROR || rc > NJT_OK || r->header_only) {
        return rc;
    }
    return NJT_OK;
}

static njt_int_t
njt_http_location_handler(njt_http_request_t *r) {
    njt_int_t rc = NJT_OK;
    njt_chain_t out;
    njt_str_t insert;
    njt_conf_t conf;
    njt_http_core_srv_conf_t *cscf;
    char *rv;
    njt_http_module_t *module;
    njt_uint_t mi, m;
    njt_queue_t *x;
    njt_http_location_queue_t *lq, *lx;
    njt_http_core_loc_conf_t *clcf, *loc;
    njt_http_conf_ctx_t         *saved_ctx;
//    njt_queue_t  *save_queue;
    njt_pool_t *location_pool;

    njt_str_t location_path = njt_string("/dev/shm/add_location.txt");
    njt_str_t location_req = njt_string("/add_location");

    njt_memzero(&conf, sizeof(njt_conf_t));
    loc = njt_http_get_module_loc_conf(r, njt_http_core_module);
    if(loc && r->uri.len == location_req.len && njt_strncmp(r->uri.data,location_req.data,r->uri.len) ==0) {
        printf("11");
    } else {
        return NJT_DECLINED;
    }
    if (r->method == NJT_HTTP_DELETE) {
        njt_str_t name = njt_string("/websocket");
        return njt_http_location_delete_handler(r, name);
    }

    //put (delete location)
    if (r->method == NJT_HTTP_PUT) {
        rc = njt_http_read_client_request_body(r,njt_http_location_read_data);
        return njt_http_location_delete_handler(r, r->exten);
    }

    //read json data
    if(r->method == NJT_HTTP_POST) {
    	rc = njt_http_read_client_request_body(r,njt_http_location_read_data);
    }

    out.next = NULL;
    out.buf = NULL;


    if (rc == NJT_ERROR || rc > NJT_OK || r->header_only) {
	    goto out;
    }
    cscf = njt_http_get_module_srv_conf(r, njt_http_core_module);
    // njt_cycle->conf_ctx

    // njt_memzero(&conf, sizeof(njt_conf_t));
    conf.args = njt_array_create(njt_cycle->pool, 10, sizeof(njt_str_t));
    if (conf.args == NULL) {
    }
    location_pool = njt_create_pool(NJT_CYCLE_POOL_SIZE, njt_cycle->log);
    if (location_pool == NULL) {
		rc = NJT_ERROR;
            	goto out;
    }
    conf.temp_pool = location_pool;
//    conf.temp_pool = njt_create_pool(NJT_CYCLE_POOL_SIZE, njt_cycle->log);
//    if (conf.temp_pool == NULL) {
//        return rc;
//    }
    conf.ctx = cscf->ctx;
    //conf.ctx = njt_cycle->conf_ctx;
    //conf.conf_file = *njt_cycle->conf_file;
    //cycle->config_dump_rbtree;
    conf.cycle = (njt_cycle_t *) njt_cycle;
    conf.cycle->config_dump_rbtree = conf.cycle->old_config_dump_rbtree;
    conf.pool = location_pool;
    conf.log = njt_cycle->log;
    conf.module_type = NJT_HTTP_MODULE;
    conf.cmd_type = NJT_HTTP_SRV_CONF;
    conf.dynamic = 1;
    clcf = cscf->ctx->loc_conf[njt_http_core_module.ctx_index];
    //clcf->locations = NULL; // clcf->old_locations;
    njt_conf_parse(&conf, &location_path);
    njt_http_variables_init_vars(&conf);
    clcf->pool = location_pool;

    //merge servers
    // cmcf = ctx->main_conf[njt_http_core_module.ctx_index];
    // cscfp = cmcf->servers.elts;
//    cmcf = njt_http_get_module_main_conf(r, njt_http_core_module);

    for (m = 0; conf.cycle->modules[m]; m++) {
        if (conf.cycle->modules[m]->type != NJT_HTTP_MODULE) {
            continue;
        }

        module = conf.cycle->modules[m]->ctx;
        mi = conf.cycle->modules[m]->ctx_index;

        /* merge the server{}s' srv_conf's */
        saved_ctx = (njt_http_conf_ctx_t *) conf.ctx;
        if (module->merge_srv_conf) {
            rv = module->merge_srv_conf(&conf, saved_ctx->srv_conf[mi],
                                        cscf->ctx->srv_conf[mi]);
            if (rv != NJT_CONF_OK) {
		rc = NJT_ERROR;
            	goto out;
            }
        }

        if (module->merge_loc_conf) {

            /* merge the server{}'s loc_conf */
            rv = module->merge_loc_conf(&conf, saved_ctx->loc_conf[mi],
                                        cscf->ctx->loc_conf[mi]);
            if (rv != NJT_CONF_OK) {
		rc = NJT_ERROR;
            	goto out;
            }

            /* merge the locations{}' loc_conf's */
            rv = njt_http_merge_locations(&conf, clcf->old_locations,
                                          cscf->ctx->loc_conf,
                                          module, mi);
            if (rv != NJT_CONF_OK) {
		rc = NJT_ERROR;
            	goto out;
            }
        }
    }

    //dump old_location to a new_location
    if (clcf->new_locations == NULL) {
        clcf->new_locations = njt_palloc(conf.temp_pool,
                                         sizeof(njt_http_location_queue_t));
        if (clcf->new_locations == NULL) {
		rc = NJT_ERROR;
            goto out;
        }

        njt_queue_init(clcf->new_locations);
    }

    for (x = njt_queue_next(clcf->old_locations);
         x != njt_queue_sentinel(clcf->old_locations);
         x = njt_queue_next(x)) {
        lx = (njt_http_location_queue_t *) x;

        lq = njt_palloc(conf.temp_pool, sizeof(njt_http_location_queue_t));
        if (lq == NULL) {
		rc = NJT_ERROR;
            goto out;
        }

        *lq = *lx;
        njt_queue_init(&lq->list);

        njt_queue_insert_tail(clcf->new_locations, &lq->queue);
    }

    if (njt_http_init_new_locations(&conf, cscf, clcf) != NJT_OK) {
		rc = NJT_ERROR;
        goto out;
    }

    if (njt_http_init_new_static_location_trees(&conf, clcf) != NJT_OK) {
		rc = NJT_ERROR;
        goto out;
    }

    //todo 处理变量

    //update tmp value
    cscf->named_locations = cscf->new_named_locations;
    clcf->regex_locations = clcf->new_regex_locations;
    clcf->static_locations = clcf->new_static_locations;

    // clcf->internal = 0;
out:
    if(rc == NJT_OK) {
    	njt_str_set(&insert, "ok");
    } else {
	njt_str_set(&insert, "error:add location!!!");
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

static char *
njt_http_location(njt_conf_t *cf, njt_command_t *cmd, void *conf){
    return NJT_CONF_OK;
}


static njt_int_t
njt_http_location_init_worker(njt_cycle_t *cycle) {
    return NJT_OK;
}

void
njt_http_location_read_data(njt_http_request_t *r)
{

    njt_json_manager                   json_body;
    njt_str_t                          json_str;
     njt_fd_t                       fd;
     njt_uint_t         i;
    njt_int_t          len;
    njt_json_element  *items;
    njt_str_t          location,proxy_pass;
    njt_chain_t                        *body_chain;
    njt_int_t                          rc;
    u_char                         *p;
    u_char                        *location_info;
    njt_str_t                      location_file = njt_string("/dev/shm/add_location.txt");
    //njt_chain_t                        out;

    rc = NJT_OK;
    body_chain = r->request_body->bufs;
    if (body_chain && body_chain->next) {
        /*The post body is too large*/
        rc = NJT_ERROR;
        return ;
    }


    /*check the sanity of the json body*/
    json_str.data = body_chain->buf->pos;
    json_str.len = body_chain->buf->last - body_chain->buf->pos;

    rc = njt_json_2_structure(&json_str, &json_body, r->pool);
    if (rc != NJT_OK) {
	rc = NJT_ERROR;
        return ;
    }
    items = json_body.json_keyval->elts;
    for (i = 0; i < json_body.json_keyval->nelts; i ++) {

        if (njt_strncmp(items[i].key.data, "location", 8) == 0) {

            if (items[i].type != NJT_JSON_STR) {
                return ;
            }

            location = items[i].strval;
            //temp use for delete location
            r->exten = location;
            continue;
        }
        if (njt_strncmp(items[i].key.data, "proxy_pass", 10) == 0) {

            if (items[i].type != NJT_JSON_STR) {
                return ;
            }

            proxy_pass = items[i].strval;
            continue;
        }
   }
   fd = njt_open_file(location_file.data, NJT_FILE_CREATE_OR_OPEN | NJT_FILE_RDWR,NJT_FILE_TRUNCATE, 0);  
   if (fd == NJT_INVALID_FILE ){
	return ;
   }
   location_info = njt_pcalloc(r->pool, 512);
   if(location_info == NULL) {
	 return ;
   }
   p = njt_snprintf(location_info,512,"location %V {\nproxy_pass %V;\n}\n",&location,&proxy_pass);
   len = njt_write_fd(fd, location_info,p-location_info);
   if (fd != NJT_INVALID_FILE) {

        if (njt_close_file(fd) == NJT_FILE_ERROR) {
           
        }
   }
   if(len < 0) {
         return ;
   }
}
