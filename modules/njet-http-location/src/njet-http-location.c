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
    njt_destroy_pool(clcf->pool);
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
        if (njt_strcmp(&name, &clcf->full_name) == 0) {
            return lq;
        }
    }
    return NULL;
}

static njt_int_t
njt_http_location_delete_handler(njt_http_request_t *r) {
    njt_http_core_srv_conf_t *cscf;
    njt_http_core_loc_conf_t *clcf, *dclcf;
    njt_queue_t *x;
    njt_http_location_queue_t *lq, *lx;

    njt_str_t name = njt_string("= /test/demo");
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


    if (njt_http_init_new_locations(&cf, cscf, clcf) != NJT_OK) {
        return NJT_ERROR;
    }

    if (njt_http_init_new_static_location_trees(&cf, clcf) != NJT_OK) {
        return NJT_ERROR;
    }

    //todo 处理变量
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
    njt_int_t rc;
    njt_chain_t out;
    njt_str_t insert;
    njt_conf_t conf;
    njt_http_core_srv_conf_t *cscf;
    char *rv;
    njt_http_module_t *module;
    njt_uint_t mi, m;
    // njt_http_core_main_conf_t   *cmcf;njt_queue_t *x;
    njt_http_location_queue_t *lq, *lx;
    njt_http_core_loc_conf_t *clcf, *loc;
    njt_http_conf_ctx_t         *saved_ctx;
//    njt_queue_t  *save_queue;
    njt_pool_t *location_pool;

    njt_str_t location_path = njt_string("./conf/add_location.txt");
    njt_str_t location_req = njt_string("/add_location");

    njt_memzero(&conf, sizeof(njt_conf_t));
    loc = njt_http_get_module_loc_conf(r, njt_http_core_module);
    //if (loc && loc->name.len == location_req.len &&
        njt_strncmp(loc->name.data, location_req.data, loc->name.len) == 0) {
    if(loc && r->uri.len == location_req.len && njt_strncmp(r->uri.data,location_req.data,r->uri.len) ==0) {
        printf("11");
    } else {
        return NJT_DECLINED;
    }
    if (r->method == NJT_HTTP_DELETE) {
        return njt_http_location_delete_handler(r);
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
    location_pool = njt_create_pool(NJT_CYCLE_POOL_SIZE, njt_cycle->log);
    if (location_pool == NULL) {
        return NJT_ERROR;
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

        /* merge the server{}s' srv_conf's */
        saved_ctx = (njt_http_conf_ctx_t *) conf.ctx;
        if (module->merge_srv_conf) {
            rv = module->merge_srv_conf(&conf, saved_ctx->srv_conf[mi],
                                        cscf->ctx->srv_conf[mi]);
            if (rv != NJT_CONF_OK) {
                return NJT_ERROR;
            }
        }

        if (module->merge_loc_conf) {

            /* merge the server{}'s loc_conf */
            rv = module->merge_loc_conf(&conf, saved_ctx->loc_conf[mi],
                                        cscf->ctx->loc_conf[mi]);
            if (rv != NJT_CONF_OK) {
                return NJT_ERROR;
            }

            /* merge the locations{}' loc_conf's */
            rv = njt_http_merge_locations(&conf, clcf->old_locations,
                                          cscf->ctx->loc_conf,
                                          module, mi);
            if (rv != NJT_CONF_OK) {
                return NJT_ERROR;
            }
        }
    }

    //dump old_location to a new_location
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
         x = njt_queue_next(x)) {
        lx = (njt_http_location_queue_t *) x;

        lq = njt_palloc(conf.temp_pool, sizeof(njt_http_location_queue_t));
        if (lq == NULL) {
            return NJT_ERROR;
        }

        *lq = *lx;
        njt_queue_init(&lq->list);

        njt_queue_insert_tail(clcf->new_locations, &lq->queue);
    }

    if (njt_http_init_new_locations(&conf, cscf, clcf) != NJT_OK) {
        return rc;
    }

    if (njt_http_init_new_static_location_trees(&conf, clcf) != NJT_OK) {
        return rc;
    }

    //todo 处理变量

    //update tmp value
    cscf->named_locations = cscf->new_named_locations;
    clcf->regex_locations = clcf->new_regex_locations;
    clcf->static_locations = clcf->new_static_locations;

    // clcf->internal = 0;
    return njt_http_output_filter(r, &out);
}


static char *
njt_http_location(njt_conf_t *cf, njt_command_t *cmd, void *conf) {


    return NJT_CONF_OK;
}


static njt_int_t
njt_http_location_init_worker(njt_cycle_t *cycle) {
    return NJT_OK;
}

