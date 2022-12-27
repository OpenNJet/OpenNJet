#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_stream.h>
#include <math.h>




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

extern  njt_int_t
njt_http_init_static_location_trees(njt_conf_t *cf,
    njt_http_core_loc_conf_t *pclcf);
extern  njt_int_t njt_http_init_locations(njt_conf_t *cf,
    njt_http_core_srv_conf_t *cscf, njt_http_core_loc_conf_t *pclcf);



typedef struct njt_http_location_ctx_s {
} njt_http_location_ctx_t,njt_stream_http_location_ctx_t;

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
njt_http_location_init(njt_conf_t *cf)
{
	njt_http_core_main_conf_t  *cmcf;
	njt_http_handler_pt        *h;
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
njt_http_location_create_loc_conf(njt_conf_t *cf)
{
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
njt_http_location_create_main_conf(njt_conf_t *cf)
{
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
        void *parent, void *child)
{
    //njt_http_location_loc_conf_t *prev = parent;
    //njt_http_location_loc_conf_t *conf = child;

    //njt_conf_merge_uint_value(conf->write, prev->write, 0);

    return NJT_CONF_OK;
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
njt_http_location_handler(njt_http_request_t *r)
{
   njt_int_t                          rc;
   njt_chain_t                        out;
   njt_str_t insert;
   njt_conf_t           conf;
    njt_http_core_srv_conf_t  *cscf;
    char                        *rv;
    njt_http_module_t           *module;
    njt_uint_t                   mi, m;
    njt_queue_t                *x;
    njt_http_location_queue_t  *lq, *lx;
   njt_http_core_loc_conf_t    *clcf, *loc;
   njt_http_core_main_conf_t   *cmcf;
   njt_str_t  location_path = njt_string("/etc/njet/add_location.txt");
   njt_str_t  location_req = njt_string("/add_location");
 
    njt_memzero(&conf,sizeof(njt_conf_t));
    loc = njt_http_get_module_loc_conf(r,njt_http_core_module);
    if(loc && loc->name.len == location_req.len && njt_strncmp(loc->name.data,location_req.data,loc->name.len) == 0) {
	printf("11");
    } else {
	return NJT_DECLINED;
    }
    out.next = NULL;
    out.buf = NULL;
   njt_str_set(&insert, "ok");
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

    if (rc == NJT_ERROR || rc > NJT_OK || r->header_only) {
        return rc;
    }
    cscf = njt_http_get_module_srv_conf(r, njt_http_core_module);
    // njt_cycle->conf_ctx

    // njt_memzero(&conf, sizeof(njt_conf_t));
    conf.args = njt_array_create(njt_cycle->pool, 10, sizeof(njt_str_t));
    if (conf.args == NULL) {
    }

    conf.temp_pool = njt_create_pool(NJT_CYCLE_POOL_SIZE, njt_cycle->log);
    if (conf.temp_pool == NULL) {
        return rc;
    }
    conf.ctx = cscf->ctx;
    //conf.ctx = njt_cycle->conf_ctx;
    //conf.conf_file = *njt_cycle->conf_file;
    //cycle->config_dump_rbtree;
    conf.cycle = (njt_cycle_t  *)njt_cycle;
    conf.cycle->config_dump_rbtree = conf.cycle->old_config_dump_rbtree;
    conf.pool = njt_cycle->pool;
    conf.log = njt_cycle->log;
    conf.module_type = NJT_HTTP_MODULE;
    conf.cmd_type = NJT_HTTP_SRV_CONF;
    clcf = cscf->ctx->loc_conf[njt_http_core_module.ctx_index];
    //clcf->locations = NULL; // clcf->old_locations;
    njt_conf_parse(&conf, &location_path);

    //merge servers
    // cmcf = ctx->main_conf[njt_http_core_module.ctx_index];
    // cscfp = cmcf->servers.elts;
    cmcf = njt_http_get_module_main_conf(r, njt_http_core_module);

    for (m = 0; conf.cycle->modules[m]; m++) {
        if (conf.cycle->modules[m]->type != NJT_HTTP_MODULE) {
            continue;
        }

        module = conf.cycle->modules[m]->ctx;
        mi = conf.cycle->modules[m]->ctx_index;

        /* init http{} main_conf's */

        // if (module->init_main_conf) {
        //     rv = module->init_main_conf(cf, ctx->main_conf[mi]);
        //     if (rv != NJT_CONF_OK) {
        //         goto failed;
        //     }
        // }

        rv = njt_http_merge_servers(&conf, cmcf, module, mi);
        if (rv != NJT_CONF_OK) {
            return NJT_ERROR;
        }
    }

    //dump old_location to a tmp_location
    if (clcf->new_locations == NULL) {
        clcf->new_locations = njt_palloc(conf.temp_pool,
                                sizeof(njt_http_location_queue_t));
        if (clcf->new_locations == NULL) {
            return NJT_ERROR;
        }

        njt_queue_init(clcf->new_locations);
    }

    for (x = njt_queue_next(clcf->old_locations);
         x != njt_queue_sentinel(clcf->old_locations);
         x = njt_queue_next(x))
    {
        lx = (njt_http_location_queue_t *) x;

        lq = njt_palloc(conf.temp_pool, sizeof(njt_http_location_queue_t));
        if (lq == NULL) {
            return NJT_ERROR;
        }
        
        *lq = *lx;
        njt_queue_init(&lq->list);

        njt_queue_insert_tail(clcf->new_locations, &lq->queue);
    }

    //init location, may update named_location and regex_location
    // if (njt_http_init_locations(&conf, cscf, clcf) != NJT_OK) {
    //     return rc;
    // }
    if (njt_http_init_new_locations(&conf, cscf, clcf) != NJT_OK) {
        return rc;
    }

    //create static location tree
    // if (njt_http_init_static_location_trees(&conf, clcf) != NJT_OK) {
    //     return rc;
    // }
    if (njt_http_init_new_static_location_trees(&conf, clcf) != NJT_OK) {
        return rc;
    }

    //update tmp value
    cscf->named_locations = cscf->new_named_locations;
    clcf->regex_locations = clcf->new_regex_locations;
    clcf->static_locations = clcf->new_static_locations;

    // clcf->internal = 0;
    return njt_http_output_filter(r, &out);
}



static char *
njt_http_location(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
  

    return NJT_CONF_OK;
}




static njt_int_t
njt_http_location_init_worker(njt_cycle_t *cycle)
{
    return NJT_OK;
}

