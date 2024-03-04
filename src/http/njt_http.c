
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_http_ssl_module.h>

static char *njt_http_block(njt_conf_t *cf, njt_command_t *cmd, void *conf);

static njt_int_t njt_http_init_phases(njt_conf_t *cf,
                                      njt_http_core_main_conf_t *cmcf);

static njt_int_t njt_http_init_headers_in_hash(njt_conf_t *cf,
                                               njt_http_core_main_conf_t *cmcf);

static njt_int_t njt_http_init_phase_handlers(njt_conf_t *cf,
                                              njt_http_core_main_conf_t *cmcf);

static njt_int_t njt_http_add_addresses(njt_conf_t *cf,
                                        njt_http_core_srv_conf_t *cscf, njt_http_conf_port_t *port,
                                        njt_http_listen_opt_t *lsopt);

static njt_int_t njt_http_add_address(njt_conf_t *cf,
                                      njt_http_core_srv_conf_t *cscf, njt_http_conf_port_t *port,
                                      njt_http_listen_opt_t *lsopt);

static njt_int_t njt_http_add_server(njt_conf_t *cf,
                                     njt_http_core_srv_conf_t *cscf, njt_http_conf_addr_t *addr);

// static char *njt_http_merge_servers(njt_conf_t *cf,
//     njt_http_core_main_conf_t *cmcf, njt_http_module_t *module,
//     njt_uint_t ctx_index);
// static char *njt_http_merge_locations(njt_conf_t *cf,
//     njt_queue_t *locations, void **loc_conf, njt_http_module_t *module,
//     njt_uint_t ctx_index);
njt_int_t njt_http_init_locations(njt_conf_t *cf,
                                  njt_http_core_srv_conf_t *cscf, njt_http_core_loc_conf_t *pclcf);

njt_int_t njt_http_init_static_location_trees(njt_conf_t *cf,
                                              njt_http_core_loc_conf_t *pclcf);

static njt_int_t njt_http_escape_location_name(njt_conf_t *cf,
                                               njt_http_core_loc_conf_t *clcf);

static njt_int_t njt_http_cmp_locations(const njt_queue_t *one,
                                        const njt_queue_t *two);

static njt_int_t njt_http_join_exact_locations(njt_conf_t *cf,
                                               njt_queue_t *locations);

static void njt_http_create_locations_list(njt_queue_t *locations,
                                           njt_queue_t *q);

static njt_http_location_tree_node_t *
njt_http_create_locations_tree(njt_conf_t *cf, njt_queue_t *locations,
                               size_t prefix);
 njt_int_t njt_http_optimize_servers(njt_conf_t *cf,
                                           njt_http_core_main_conf_t *cmcf, njt_array_t *ports);

static njt_int_t njt_http_server_names(njt_conf_t *cf,
                                       njt_http_core_main_conf_t *cmcf, njt_http_conf_addr_t *addr);

static njt_int_t njt_http_cmp_conf_addrs(const void *one, const void *two);

static int njt_libc_cdecl njt_http_cmp_dns_wildcards(const void *one,
                                                     const void *two);

static njt_int_t njt_http_init_listening(njt_conf_t *cf,
                                         njt_http_conf_port_t *port);

static njt_listening_t *njt_http_add_listening(njt_conf_t *cf,
                                               njt_http_conf_addr_t *addr);

static njt_int_t njt_http_add_addrs(njt_conf_t *cf, njt_http_port_t *hport,
                                    njt_http_conf_addr_t *addr);

#if (NJT_HAVE_INET6)

static njt_int_t njt_http_add_addrs6(njt_conf_t *cf, njt_http_port_t *hport,
                                     njt_http_conf_addr_t *addr);

#endif

njt_uint_t njt_http_max_module;


njt_http_output_header_filter_pt njt_http_top_header_filter;
njt_http_output_body_filter_pt njt_http_top_body_filter;
njt_http_request_body_filter_pt njt_http_top_request_body_filter;


njt_str_t njt_http_html_default_types[] = {
        njt_string("text/html"),
        njt_null_string
};


static njt_command_t njt_http_commands[] = {

        {njt_string("http"),
         NJT_MAIN_CONF | NJT_CONF_BLOCK | NJT_CONF_NOARGS,
         njt_http_block,
         0,
         0,
         NULL},

        njt_null_command
};


static njt_core_module_t njt_http_module_ctx = {
        njt_string("http"),
        NULL,
        NULL
};


njt_module_t njt_http_module = {
        NJT_MODULE_V1,
        &njt_http_module_ctx,                  /* module context */
        njt_http_commands,                     /* module directives */
        NJT_CORE_MODULE,                       /* module type */
        NULL,                                  /* init master */
        NULL,                                  /* init module */
        NULL,                                  /* init process */
        NULL,                                  /* init thread */
        NULL,                                  /* exit thread */
        NULL,                                  /* exit process */
        NULL,                                  /* exit master */
        NJT_MODULE_V1_PADDING
};


static char *
njt_http_block(njt_conf_t *cf, njt_command_t *cmd, void *conf) {
    char *rv;
    njt_uint_t mi, m, s;
    njt_conf_t pcf;
    njt_http_module_t *module;
    njt_http_conf_ctx_t *ctx;
    njt_http_core_loc_conf_t *clcf;
    njt_http_core_srv_conf_t **cscfp;
    njt_http_core_main_conf_t *cmcf;


    if (*(njt_http_conf_ctx_t **) conf) {
        return "is duplicate";
    }

    /* the main http context */

    ctx = njt_pcalloc(cf->pool, sizeof(njt_http_conf_ctx_t));
    if (ctx == NULL) {
        return NJT_CONF_ERROR;
    }

    *(njt_http_conf_ctx_t **) conf = ctx;


    /* count the number of the http modules and set up their indices */

    njt_http_max_module = njt_count_modules(cf->cycle, NJT_HTTP_MODULE);


    /* the http main_conf context, it is the same in the all http contexts */

    ctx->main_conf = njt_pcalloc(cf->pool,
                                 sizeof(void *) * njt_http_max_module);
    if (ctx->main_conf == NULL) {
        return NJT_CONF_ERROR;
    }


    /*
     * the http null srv_conf context, it is used to merge
     * the server{}s' srv_conf's
     */

    ctx->srv_conf = njt_pcalloc(cf->pool, sizeof(void *) * njt_http_max_module);
    if (ctx->srv_conf == NULL) {
        return NJT_CONF_ERROR;
    }


    /*
     * the http null loc_conf context, it is used to merge
     * the server{}s' loc_conf's
     */

    ctx->loc_conf = njt_pcalloc(cf->pool, sizeof(void *) * njt_http_max_module);
    if (ctx->loc_conf == NULL) {
        return NJT_CONF_ERROR;
    }


    /*
     * create the main_conf's, the null srv_conf's, and the null loc_conf's
     * of the all http modules
     */
    // by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
    njt_pool_t *old_pool, *new_pool,*old_temp_pool;
    njt_int_t rc;

    old_pool = cf->pool;
    old_temp_pool = cf->temp_pool;
    new_pool = njt_create_dynamic_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
    if (new_pool == NULL) {
        return NJT_CONF_ERROR;
    }
    rc = njt_sub_pool(cf->cycle->pool,new_pool);
    if (rc != NJT_OK) {
        return NJT_CONF_ERROR;
    }
#endif
    //end
    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NJT_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;
        mi = cf->cycle->modules[m]->ctx_index;

        if (module->create_main_conf) {
            ctx->main_conf[mi] = module->create_main_conf(cf);
            if (ctx->main_conf[mi] == NULL) {
                return NJT_CONF_ERROR;
            }
        }

        if (module->create_srv_conf) {
            ctx->srv_conf[mi] = module->create_srv_conf(cf);
            if (ctx->srv_conf[mi] == NULL) {
                return NJT_CONF_ERROR;
            }
        }
        // by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
        cf->pool = new_pool;
#endif
        //end
        if (module->create_loc_conf) {
            ctx->loc_conf[mi] = module->create_loc_conf(cf);
            if (ctx->loc_conf[mi] == NULL) {
                return NJT_CONF_ERROR;
            }
        }
        // by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
        cf->pool = old_pool;
        cf->temp_pool = old_temp_pool;
#endif
    }
        //end
    pcf = *cf;
    cf->ctx = ctx;

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NJT_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        if (module->preconfiguration) {
            if (module->preconfiguration(cf) != NJT_OK) {
                return NJT_CONF_ERROR;
            }
        }
    }

    /* parse inside the http{} block */

    cf->module_type = NJT_HTTP_MODULE;
    cf->cmd_type = NJT_HTTP_MAIN_CONF;
    rv = njt_conf_parse(cf, NULL);

    if (rv != NJT_CONF_OK) {
        goto failed;
    }

    /*
     * init http{} main_conf's, merge the server{}s' srv_conf's
     * and its location{}s' loc_conf's
     */

    cmcf = ctx->main_conf[njt_http_core_module.ctx_index];
    cscfp = cmcf->servers.elts;

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NJT_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;
        mi = cf->cycle->modules[m]->ctx_index;

        /* init http{} main_conf's */

        if (module->init_main_conf) {
            rv = module->init_main_conf(cf, ctx->main_conf[mi]);
            if (rv != NJT_CONF_OK) {
                goto failed;
            }
        }

        rv = njt_http_merge_servers(cf, cmcf, module, mi);
        if (rv != NJT_CONF_OK) {
            goto failed;
        }
    }


    /* create location trees */

    for (s = 0; s < cmcf->servers.nelts; s++) {

        clcf = cscfp[s]->ctx->loc_conf[njt_http_core_module.ctx_index];

        if (njt_http_init_locations(cf, cscfp[s], clcf) != NJT_OK) {
            return NJT_CONF_ERROR;
        }
        if (njt_http_init_static_location_trees(cf, clcf) != NJT_OK) {
            return NJT_CONF_ERROR;
        }
    }


    if (njt_http_init_phases(cf, cmcf) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    if (njt_http_init_headers_in_hash(cf, cmcf) != NJT_OK) {
        return NJT_CONF_ERROR;
    }


    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NJT_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        if (module->postconfiguration) {
            if (module->postconfiguration(cf) != NJT_OK) {
                return NJT_CONF_ERROR;
            }
        }
    }

    if (njt_http_variables_init_vars(cf) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    /*
     * http{}'s cf->ctx was needed while the configuration merging
     * and in postconfiguration process
     */

    *cf = pcf;


    if (njt_http_init_phase_handlers(cf, cmcf) != NJT_OK) {
        return NJT_CONF_ERROR;
    }


    /* optimize the lists of ports, addresses and server names */

    if (njt_http_optimize_servers(cf, cmcf, cmcf->ports) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;

    failed:

    *cf = pcf;

    return rv;
}


static njt_int_t
njt_http_init_phases(njt_conf_t *cf, njt_http_core_main_conf_t *cmcf) {
    if (njt_array_init(&cmcf->phases[NJT_HTTP_POST_READ_PHASE].handlers,
                       cf->pool, 1, sizeof(njt_http_handler_pt))
        != NJT_OK) {
        return NJT_ERROR;
    }

    if (njt_array_init(&cmcf->phases[NJT_HTTP_SERVER_REWRITE_PHASE].handlers,
                       cf->pool, 1, sizeof(njt_http_handler_pt))
        != NJT_OK) {
        return NJT_ERROR;
    }

    if (njt_array_init(&cmcf->phases[NJT_HTTP_REWRITE_PHASE].handlers,
                       cf->pool, 1, sizeof(njt_http_handler_pt))
        != NJT_OK) {
        return NJT_ERROR;
    }

    if (njt_array_init(&cmcf->phases[NJT_HTTP_PREACCESS_PHASE].handlers,
                       cf->pool, 1, sizeof(njt_http_handler_pt))
        != NJT_OK) {
        return NJT_ERROR;
    }

    if (njt_array_init(&cmcf->phases[NJT_HTTP_ACCESS_PHASE].handlers,
                       cf->pool, 2, sizeof(njt_http_handler_pt))
        != NJT_OK) {
        return NJT_ERROR;
    }

    if (njt_array_init(&cmcf->phases[NJT_HTTP_PRECONTENT_PHASE].handlers,
                       cf->pool, 2, sizeof(njt_http_handler_pt))
        != NJT_OK) {
        return NJT_ERROR;
    }

    if (njt_array_init(&cmcf->phases[NJT_HTTP_CONTENT_PHASE].handlers,
                       cf->pool, 4, sizeof(njt_http_handler_pt))
        != NJT_OK) {
        return NJT_ERROR;
    }

    if (njt_array_init(&cmcf->phases[NJT_HTTP_LOG_PHASE].handlers,
                       cf->pool, 1, sizeof(njt_http_handler_pt))
        != NJT_OK) {
        return NJT_ERROR;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_init_headers_in_hash(njt_conf_t *cf, njt_http_core_main_conf_t *cmcf) {
    njt_array_t headers_in;
    njt_hash_key_t *hk;
    njt_hash_init_t hash;
    njt_http_header_t *header;

    if (njt_array_init(&headers_in, cf->temp_pool, 32, sizeof(njt_hash_key_t))
        != NJT_OK) {
        return NJT_ERROR;
    }

    for (header = njt_http_headers_in; header->name.len; header++) {
        hk = njt_array_push(&headers_in);
        if (hk == NULL) {
            return NJT_ERROR;
        }

        hk->key = header->name;
        hk->key_hash = njt_hash_key_lc(header->name.data, header->name.len);
        hk->value = header;
    }

    hash.hash = &cmcf->headers_in_hash;
    hash.key = njt_hash_key_lc;
    hash.max_size = 512;
    hash.bucket_size = njt_align(64, njt_cacheline_size);
    hash.name = "headers_in_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    if (njt_hash_init(&hash, headers_in.elts, headers_in.nelts) != NJT_OK) {
        return NJT_ERROR;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_init_phase_handlers(njt_conf_t *cf, njt_http_core_main_conf_t *cmcf) {
    njt_int_t j;
    njt_uint_t i, n;
    njt_uint_t find_config_index, use_rewrite, use_access;
    njt_http_handler_pt *h;
    njt_http_phase_handler_t *ph;
    njt_http_phase_handler_pt checker;

    cmcf->phase_engine.server_rewrite_index = (njt_uint_t) -1;
    cmcf->phase_engine.location_rewrite_index = (njt_uint_t) -1;
    find_config_index = 0;
    use_rewrite = cmcf->phases[NJT_HTTP_REWRITE_PHASE].handlers.nelts ? 1 : 0;
    use_access = cmcf->phases[NJT_HTTP_ACCESS_PHASE].handlers.nelts ? 1 : 0;

    n = 1                  /* find config phase */
        + use_rewrite      /* post rewrite phase */
        + use_access;      /* post access phase */

    for (i = 0; i < NJT_HTTP_LOG_PHASE; i++) {
        n += cmcf->phases[i].handlers.nelts;
    }

    ph = njt_pcalloc(cf->pool,
                     n * sizeof(njt_http_phase_handler_t) + sizeof(void *));
    if (ph == NULL) {
        return NJT_ERROR;
    }

    cmcf->phase_engine.handlers = ph;
    n = 0;

    for (i = 0; i < NJT_HTTP_LOG_PHASE; i++) {
        h = cmcf->phases[i].handlers.elts;

        switch (i) {

            case NJT_HTTP_SERVER_REWRITE_PHASE:
                if (cmcf->phase_engine.server_rewrite_index == (njt_uint_t) -1) {
                    cmcf->phase_engine.server_rewrite_index = n;
                }
                checker = njt_http_core_rewrite_phase;

                break;

            case NJT_HTTP_FIND_CONFIG_PHASE:
                find_config_index = n;

                ph->checker = njt_http_core_find_config_phase;
                n++;
                ph++;

                continue;

            case NJT_HTTP_REWRITE_PHASE:
                if (cmcf->phase_engine.location_rewrite_index == (njt_uint_t) -1) {
                    cmcf->phase_engine.location_rewrite_index = n;
                }
                checker = njt_http_core_rewrite_phase;

                break;

            case NJT_HTTP_POST_REWRITE_PHASE:
                if (use_rewrite) {
                    ph->checker = njt_http_core_post_rewrite_phase;
                    ph->next = find_config_index;
                    n++;
                    ph++;
                }

                continue;

            case NJT_HTTP_ACCESS_PHASE:
                checker = njt_http_core_access_phase;
                n++;
                break;

            case NJT_HTTP_POST_ACCESS_PHASE:
                if (use_access) {
                    ph->checker = njt_http_core_post_access_phase;
                    ph->next = n;
                    ph++;
                }

                continue;

            case NJT_HTTP_CONTENT_PHASE:
                checker = njt_http_core_content_phase;
                break;

            default:
                checker = njt_http_core_generic_phase;
        }

        n += cmcf->phases[i].handlers.nelts;

        for (j = cmcf->phases[i].handlers.nelts - 1; j >= 0; j--) {
            ph->checker = checker;
            ph->handler = h[j];
            ph->next = n;
            ph++;
        }
    }

    return NJT_OK;
}


// static char *
char *
njt_http_merge_servers(njt_conf_t *cf, njt_http_core_main_conf_t *cmcf,
                       njt_http_module_t *module, njt_uint_t ctx_index) {
    char *rv;
    njt_uint_t s;
    njt_http_conf_ctx_t *ctx, saved;
    njt_http_core_loc_conf_t *clcf;
    njt_http_core_srv_conf_t **cscfp;

    cscfp = cmcf->servers.elts;
    ctx = (njt_http_conf_ctx_t *) cf->ctx;
    saved = *ctx;
    rv = NJT_CONF_OK;

    for (s = 0; s < cmcf->servers.nelts; s++) {

#if (NJT_HTTP_DYNAMIC_SERVER)
	if (cf->dynamic == 1 &&  cscfp[s]->dynamic_status != 1 ) {
		continue;
	}
#endif
        /* merge the server{}s' srv_conf's */

        ctx->srv_conf = cscfp[s]->ctx->srv_conf;

        if (module->merge_srv_conf) {
            rv = module->merge_srv_conf(cf, saved.srv_conf[ctx_index],
                                        cscfp[s]->ctx->srv_conf[ctx_index]);
            if (rv != NJT_CONF_OK) {
                goto failed;
            }
        }

        if (module->merge_loc_conf) {

            /* merge the server{}'s loc_conf */

            ctx->loc_conf = cscfp[s]->ctx->loc_conf;

            rv = module->merge_loc_conf(cf, saved.loc_conf[ctx_index],
                                        cscfp[s]->ctx->loc_conf[ctx_index]);
            if (rv != NJT_CONF_OK) {
                goto failed;
            }

            /* merge the locations{}' loc_conf's */

            clcf = cscfp[s]->ctx->loc_conf[njt_http_core_module.ctx_index];

            rv = njt_http_merge_locations(cf, clcf->locations,
                                          cscfp[s]->ctx->loc_conf,
                                          module, ctx_index);
            if (rv != NJT_CONF_OK) {
                goto failed;
            }
        }
    }

    failed:

    *ctx = saved;

    return rv;
}


char *
njt_http_merge_locations(njt_conf_t *cf, njt_queue_t *locations,
                         void **loc_conf, njt_http_module_t *module, njt_uint_t ctx_index) {
    char *rv;
    njt_queue_t *q;
    njt_http_conf_ctx_t *ctx, saved;
    njt_http_core_loc_conf_t *clcf;
    njt_http_location_queue_t *lq;

    if (locations == NULL) {
        return NJT_CONF_OK;
    }

    ctx = (njt_http_conf_ctx_t *) cf->ctx;
    saved = *ctx;

    for (q = njt_queue_head(locations);
         q != njt_queue_sentinel(locations);
         q = njt_queue_next(q)) {
        lq = (njt_http_location_queue_t *) q;

        clcf = lq->exact ? lq->exact : lq->inclusive;
        ctx->loc_conf = clcf->loc_conf;
        // by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
	if(cf->dynamic == 1) {
	   if(lq->dynamic_status != 1){
		continue;
	   }
	}
        njt_pool_t *old_pool,*old_temp_pool;
        old_pool = cf->pool;
        old_temp_pool = cf->temp_pool;
        cf->pool = ((njt_http_core_loc_conf_t *)clcf->loc_conf[njt_http_core_module.ctx_index])->pool;
        cf->temp_pool = ((njt_http_core_loc_conf_t *)clcf->loc_conf[njt_http_core_module.ctx_index])->pool;
#endif
        // end
        rv = module->merge_loc_conf(cf, loc_conf[ctx_index],
                                    clcf->loc_conf[ctx_index]);
        // by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
        cf->pool = old_pool;
        cf->temp_pool = old_temp_pool;
#endif
        // end
        if (rv != NJT_CONF_OK) {
            return rv;
        }
	if(cf->dynamic == 0) {
        rv = njt_http_merge_locations(cf, clcf->locations, clcf->loc_conf,
                                      module, ctx_index);
	} else {
		rv = njt_http_merge_locations(cf, clcf->old_locations, clcf->loc_conf,
                                      module, ctx_index);
	}
        if (rv != NJT_CONF_OK) {
            return rv;
        }
    }

    *ctx = saved;

    return NJT_CONF_OK;
}


static njt_inline njt_int_t
njt_http_init_locations_common(njt_conf_t *cf, njt_http_core_srv_conf_t *cscf,
                        njt_http_core_loc_conf_t *pclcf,njt_queue_t *locations) {
    njt_uint_t n;
    njt_queue_t *q, *named, tail;
    njt_http_core_loc_conf_t *clcf;
    njt_http_location_queue_t *lq;
    njt_http_core_loc_conf_t **clcfp;
    njt_int_t   rc;
#if (NJT_PCRE)
    njt_uint_t r;
    njt_queue_t *regex;
#endif

    if (locations == NULL) {
        return NJT_OK;
    }
    if (pclcf == NULL){
	njt_log_error(NJT_LOG_WARN, njt_cycle->log, 0,"njt_http_init_locations_common pclcf null!");
	return NJT_ERROR;
    }

    njt_queue_sort(locations, njt_http_cmp_locations);

    named = NULL;
    n = 0;
#if (NJT_PCRE)
    regex = NULL;
    r = 0;
#endif
    
    if(pclcf->if_locations != NULL &&  !njt_queue_empty(pclcf->if_locations)) {
    for (q = njt_queue_head(locations);
         q != njt_queue_sentinel(locations);
         ) {
        lq = (njt_http_location_queue_t *) q;

        clcf = lq->exact ? lq->exact : lq->inclusive;
	if(clcf->if_loc == 1) {
	  q = njt_queue_next(q);
	  njt_queue_remove(&lq->queue);
	  continue;
	}
	q = njt_queue_next(q);
    }
   }

    for (q = njt_queue_head(locations);
         q != njt_queue_sentinel(locations);
         q = njt_queue_next(q)) {
        lq = (njt_http_location_queue_t *) q;

        clcf = lq->exact ? lq->exact : lq->inclusive;
        if (njt_http_init_locations(cf, NULL, clcf) != NJT_OK) {
            return NJT_ERROR;
        }

#if (NJT_PCRE)

        if (clcf->regex) {
            r++;

            if (regex == NULL) {
                regex = q;
            }

            continue;
        }

#endif

        if (clcf->named) {
            n++;

            if (named == NULL) {
                named = q;
            }

            continue;
        }

        if (clcf->noname) {
            break;
        }
    }

    if (q != njt_queue_sentinel(locations)) {
        njt_queue_split(locations, q, &tail);
    }

        // by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
        if (cscf != NULL && cscf->named_locations != NULL) {
            njt_pfree(cscf->named_parent_pool, cscf->named_locations);
        }
#endif
        //end
    if (named && cscf != NULL) {
        // by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
        if (cscf->named_parent_pool == NULL) {
            cscf->named_parent_pool = njt_create_dynamic_pool(NJT_MIN_POOL_SIZE,cf->pool->log);
	    if(cscf->named_parent_pool == NULL) {
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,"njt_http_init_locations_common create  named_parent_pool null!");	
		return NJT_ERROR;
	    }
	    rc = njt_sub_pool(cscf->pool,cscf->named_parent_pool);
    	    if (rc != NJT_OK) {
        	return NJT_ERROR;
   	    }
        }
        clcfp = njt_palloc(cscf->named_parent_pool,
                           (n + 1) * sizeof(njt_http_core_loc_conf_t *));
#else
        clcfp = njt_palloc(cf->pool,
                           (n + 1) * sizeof(njt_http_core_loc_conf_t *));
#endif
        //end
        if (clcfp == NULL) {
            return NJT_ERROR;
        }
        cscf->named_locations = clcfp;

        for (q = named;
             q != njt_queue_sentinel(locations);) {
            lq = (njt_http_location_queue_t *) q;
            q = njt_queue_next(q);
            *(clcfp++) = lq->exact;
	   if(lq->exact != NULL) {
	   	lq->exact->loc_conf[njt_http_core_module.ctx_index] = lq->exact;
	   }
            // by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
            njt_queue_remove(&lq->queue);
            njt_pfree(lq->parent_pool,lq);
#endif
            //end
        }

        *clcfp = NULL;
        // by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
#else
        njt_queue_split(locations, named, &tail);
#endif
        // end
    }

#if (NJT_PCRE)

        // by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
        if (pclcf->regex_locations!= NULL){
            njt_pfree(pclcf->pool,pclcf->regex_locations);
            pclcf->regex_locations= NULL;
        }
#endif
        // end
    if (regex) {
        // by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
        clcfp = njt_palloc(pclcf->pool,
                           (r + 1) * sizeof(njt_http_core_loc_conf_t *));
#else
        clcfp = njt_palloc(cf->pool,
                           (r + 1) * sizeof(njt_http_core_loc_conf_t *));
#endif
        //end

        if (clcfp == NULL) {
            return NJT_ERROR;
        }
        pclcf->regex_locations = clcfp;

        for (q = regex;
             q != njt_queue_sentinel(locations);) {
            lq = (njt_http_location_queue_t *) q;
            q = njt_queue_next(q);
            *(clcfp++) = lq->exact;
	   if(lq->exact != NULL) {
	   	lq->exact->loc_conf[njt_http_core_module.ctx_index] = lq->exact;
	   }
            // by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
            njt_queue_remove(&lq->queue);
            njt_pfree(lq->parent_pool,lq);
#endif
            //end
        }

        *clcfp = NULL;
        // by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
#else
        njt_queue_split(locations, regex, &tail);
#endif
        // end
    }

#endif

    return NJT_OK;
}
njt_int_t
njt_http_init_locations(njt_conf_t *cf, njt_http_core_srv_conf_t *cscf,
                        njt_http_core_loc_conf_t *pclcf) {
	 return njt_http_init_locations_common(cf, cscf,pclcf,pclcf->locations);
}

//add by clb
njt_int_t
njt_http_init_new_locations(njt_conf_t *cf, njt_http_core_srv_conf_t *cscf,
                            njt_http_core_loc_conf_t *pclcf) {

    return njt_http_init_locations_common(cf, cscf,pclcf,pclcf->locations);
}

static njt_inline njt_int_t
njt_http_init_static_location_trees_common(njt_conf_t *cf,njt_http_core_loc_conf_t *pclcf,
                                           njt_queue_t *locations,njt_http_location_tree_node_t   **static_locations) {
    njt_queue_t *q;
    njt_http_core_loc_conf_t *clcf;
    njt_http_location_queue_t *lq;


    if (locations == NULL) {
        return NJT_OK;
    }

    if (njt_queue_empty(locations)) {
        return NJT_OK;
    }

    for (q = njt_queue_head(locations);
         q != njt_queue_sentinel(locations);
         q = njt_queue_next(q)) {
        lq = (njt_http_location_queue_t *) q;

        clcf = lq->exact ? lq->exact : lq->inclusive;

        if (njt_http_init_static_location_trees(cf, clcf) != NJT_OK) {
            return NJT_ERROR;
        }
    }

    if (njt_http_join_exact_locations(cf, locations) != NJT_OK) {
        return NJT_ERROR;
    }

    njt_http_create_locations_list(locations, njt_queue_head(locations));

    *static_locations = njt_http_create_locations_tree(cf, locations, 0);
    if (*static_locations == NULL) {
        return NJT_ERROR;
    }

    return NJT_OK;
}
njt_int_t
njt_http_init_static_location_trees(njt_conf_t *cf,
                                    njt_http_core_loc_conf_t *pclcf) {
    	return njt_http_init_static_location_trees_common(cf,pclcf,pclcf->locations,&pclcf->static_locations);
}
//add by clb
njt_int_t
njt_http_init_new_static_location_trees(njt_conf_t *cf,
                                        njt_http_core_loc_conf_t *pclcf) {
    return njt_http_init_static_location_trees_common(cf,pclcf,pclcf->locations,&pclcf->new_static_locations);
}


njt_int_t
njt_http_add_location(njt_conf_t *cf, njt_queue_t **locations,
                      njt_http_core_loc_conf_t *clcf) {
    njt_http_location_queue_t *lq;
    njt_http_location_queue_t *tmp_queue;
    njt_pool_t *parent_pool;	
    if (*locations == NULL) {
	parent_pool = cf->cycle->pool;
        *locations = njt_palloc(parent_pool,sizeof(njt_http_location_queue_t));
        if (*locations == NULL) {
            return NJT_ERROR;
        }

        //add by clb
#if (NJT_HTTP_DYNAMIC_LOC)
        tmp_queue = (njt_http_location_queue_t *)*locations;
        tmp_queue->parent_pool = parent_pool;
#endif
        //end
        njt_queue_init(*locations);
    }

    lq = njt_palloc(cf->temp_pool, sizeof(njt_http_location_queue_t));
    if (lq == NULL) {
        return NJT_ERROR;
    }
        //add by clb
#if (NJT_HTTP_DYNAMIC_LOC)
        lq->parent_pool = cf->temp_pool;
#endif
        //end
    if (clcf->exact_match
        #if (NJT_PCRE)
        || clcf->regex
        #endif
        || clcf->named || clcf->noname) {
        lq->exact = clcf;
        lq->inclusive = NULL;

    } else {
        lq->exact = NULL;
        lq->inclusive = clcf;
    }

    lq->name = &clcf->name;
    lq->file_name = cf->conf_file->file.name.data;
    lq->line = cf->conf_file->line;
    //by zyg
    #if (NJT_HTTP_DYNAMIC_LOC)
	lq->dynamic_status = clcf->dynamic_status; // 1 init, 2 nomal
    #endif
    //end
    njt_queue_init(&lq->list);

    njt_queue_insert_tail(*locations, &lq->queue);

    if (njt_http_escape_location_name(cf, clcf) != NJT_OK) {
        return NJT_ERROR;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_escape_location_name(njt_conf_t *cf, njt_http_core_loc_conf_t *clcf) {
    u_char *p;
    size_t len;
    uintptr_t escape;

    escape = 2 * njt_escape_uri(NULL, clcf->name.data, clcf->name.len,
                                NJT_ESCAPE_URI);

    if (escape) {
        len = clcf->name.len + escape;

        p = njt_pnalloc(cf->pool, len);
        if (p == NULL) {
            return NJT_ERROR;
        }

        clcf->escaped_name.len = len;
        clcf->escaped_name.data = p;

        njt_escape_uri(p, clcf->name.data, clcf->name.len, NJT_ESCAPE_URI);

    } else {
        clcf->escaped_name = clcf->name;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_cmp_locations(const njt_queue_t *one, const njt_queue_t *two) {
    njt_int_t rc;
    njt_http_core_loc_conf_t *first, *second;
    njt_http_location_queue_t *lq1, *lq2;

    lq1 = (njt_http_location_queue_t *) one;
    lq2 = (njt_http_location_queue_t *) two;

    first = lq1->exact ? lq1->exact : lq1->inclusive;
    second = lq2->exact ? lq2->exact : lq2->inclusive;

    if (first->noname && !second->noname) {
        /* shift no named locations to the end */
        return 1;
    }

    if (!first->noname && second->noname) {
        /* shift no named locations to the end */
        return -1;
    }

    if (first->noname || second->noname) {
        /* do not sort no named locations */
        return 0;
    }

    if (first->named && !second->named) {
        /* shift named locations to the end */
        return 1;
    }

    if (!first->named && second->named) {
        /* shift named locations to the end */
        return -1;
    }

    if (first->named && second->named) {
        return njt_strcmp(first->name.data, second->name.data);
    }

#if (NJT_PCRE)

    if (first->regex && !second->regex) {
        /* shift the regex matches to the end */
        return 1;
    }

    if (!first->regex && second->regex) {
        /* shift the regex matches to the end */
        return -1;
    }

    if (first->regex || second->regex) {
        /* do not sort the regex matches */
        return 0;
    }

#endif

    rc = njt_filename_cmp(first->name.data, second->name.data,
                          njt_min(first->name.len, second->name.len) + 1);

    if (rc == 0 && !first->exact_match && second->exact_match) {
        /* an exact match must be before the same inclusive one */
        return 1;
    }

    return rc;
}


static njt_int_t
njt_http_join_exact_locations(njt_conf_t *cf, njt_queue_t *locations) {
    njt_queue_t *q, *x;
    njt_http_location_queue_t *lq, *lx;

    q = njt_queue_head(locations);

    while (q != njt_queue_last(locations)) {

        x = njt_queue_next(q);

        lq = (njt_http_location_queue_t *) q;
        lx = (njt_http_location_queue_t *) x;

        if (lq->name->len == lx->name->len
            && njt_filename_cmp(lq->name->data, lx->name->data, lx->name->len)
               == 0) {
            if ((lq->exact && lx->exact) || (lq->inclusive && lx->inclusive)) {
                njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                              "duplicate location \"%V\" in %s:%ui",
                              lx->name, lx->file_name, lx->line);

                return NJT_ERROR;
            }

            lq->inclusive = lx->inclusive;

            njt_queue_remove(x);

            continue;
        }

        q = njt_queue_next(q);
    }

    return NJT_OK;
}


static void
njt_http_create_locations_list(njt_queue_t *locations, njt_queue_t *q) {
    u_char *name;
    size_t len;
    njt_queue_t *x, tail;
    njt_http_location_queue_t *lq, *lx;

    if (q == njt_queue_last(locations)) {
        return;
    }

    lq = (njt_http_location_queue_t *) q;

    if (lq->inclusive == NULL) {
        njt_http_create_locations_list(locations, njt_queue_next(q));
        return;
    }

    len = lq->name->len;
    name = lq->name->data;

    for (x = njt_queue_next(q);
         x != njt_queue_sentinel(locations);
         x = njt_queue_next(x)) {
        lx = (njt_http_location_queue_t *) x;

        if (len > lx->name->len
            || njt_filename_cmp(name, lx->name->data, len) != 0) {
            break;
        }
    }

    q = njt_queue_next(q);

    if (q == x) {
        njt_http_create_locations_list(locations, x);
        return;
    }

    njt_queue_split(locations, q, &tail);
    njt_queue_add(&lq->list, &tail);

    if (x == njt_queue_sentinel(locations)) {
        njt_http_create_locations_list(&lq->list, njt_queue_head(&lq->list));
        return;
    }

    njt_queue_split(&lq->list, x, &tail);
    njt_queue_add(locations, &tail);

    njt_http_create_locations_list(&lq->list, njt_queue_head(&lq->list));

    njt_http_create_locations_list(locations, x);
}


/*
 * to keep cache locality for left leaf nodes, allocate nodes in following
 * order: node, left subtree, right subtree, inclusive subtree
 */

static njt_http_location_tree_node_t *
njt_http_create_locations_tree(njt_conf_t *cf, njt_queue_t *locations,
                               size_t prefix) {
    size_t len;
    njt_queue_t *q, tail;
    njt_http_location_queue_t *lq;
    njt_http_location_tree_node_t *node;

    q = njt_queue_middle(locations);

    lq = (njt_http_location_queue_t *) q;
    len = lq->name->len - prefix;

    node = njt_palloc(cf->pool,
                      offsetof(njt_http_location_tree_node_t, name) + len);
    if (node == NULL) {
        return NULL;
    }

    //by clb
#if (NJT_HTTP_DYNAMIC_LOC)
    node->parent_pool = cf->pool;
#endif
    //end
    node->left = NULL;
    node->right = NULL;
    node->tree = NULL;
    node->exact = lq->exact;
    node->inclusive = lq->inclusive;

    node->auto_redirect = (u_char) ((lq->exact && lq->exact->auto_redirect)
                                    || (lq->inclusive && lq->inclusive->auto_redirect));

    node->len = (u_short) len;
    njt_memcpy(node->name, &lq->name->data[prefix], len);

    njt_queue_split(locations, q, &tail);

    if (njt_queue_empty(locations)) {
        /*
         * njt_queue_split() insures that if left part is empty,
         * then right one is empty too
         */
        goto inclusive;
    }

    node->left = njt_http_create_locations_tree(cf, locations, prefix);
    if (node->left == NULL) {
        return NULL;
    }

    njt_queue_remove(q);


    if (njt_queue_empty(&tail)) {
        goto inclusive;
    }

    node->right = njt_http_create_locations_tree(cf, &tail, prefix);
    if (node->right == NULL) {
        return NULL;
    }

    inclusive:

    if (njt_queue_empty(&lq->list)) {
        //by clb
#if (NJT_HTTP_DYNAMIC_LOC)
        //need remove q memory
        if (lq != NULL && lq->parent_pool != NULL){
            njt_pfree(lq->parent_pool, lq);
        }
#endif
        //end
        return node;
    }

    node->tree = njt_http_create_locations_tree(cf, &lq->list, prefix + len);
    if (node->tree == NULL) {
        //by clb
#if (NJT_HTTP_DYNAMIC_LOC)
        //need remove q memory
        if (lq != NULL && lq->parent_pool != NULL){
            njt_pfree(lq->parent_pool, lq);
        }
#endif
        //end
        return NULL;
    }
    //by clb
#if (NJT_HTTP_DYNAMIC_LOC)
    //need remove q memory
    if (lq != NULL && lq->parent_pool != NULL){
        njt_pfree(lq->parent_pool, lq);
    }
#endif
    //end
    return node;
}


njt_int_t
njt_http_add_listen(njt_conf_t *cf, njt_http_core_srv_conf_t *cscf,
                    njt_http_listen_opt_t *lsopt) {
    in_port_t p;
    njt_uint_t i;
    struct sockaddr *sa;
    njt_http_conf_port_t *port;
    njt_http_core_main_conf_t *cmcf;

    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);

    if (cmcf->ports == NULL) {
        cmcf->ports = njt_array_create(cf->temp_pool, 2,
                                       sizeof(njt_http_conf_port_t));
        if (cmcf->ports == NULL) {
            return NJT_ERROR;
        }
    }

    sa = lsopt->sockaddr;
    p = njt_inet_get_port(sa);

    port = cmcf->ports->elts;
    for (i = 0; i < cmcf->ports->nelts; i++) {

        if (p != port[i].port
            || lsopt->type != port[i].type
            || sa->sa_family != port[i].family)
        {
            continue;
        }

        /* a port is already in the port list */

        return njt_http_add_addresses(cf, cscf, &port[i], lsopt);
    }

    /* add a port to the port list */
    if(cf->dynamic == 1) {  //zyg 动态的必须有监听。
          njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "no find listen port for %d",p);
         return NJT_ERROR;
    }
    port = njt_array_push(cmcf->ports);
    if (port == NULL) {
        return NJT_ERROR;
    }

    port->family = sa->sa_family;
    port->type = lsopt->type;
    port->port = p;
    port->addrs.elts = NULL;

    return njt_http_add_address(cf, cscf, port, lsopt);
}


static njt_int_t
njt_http_add_addresses(njt_conf_t *cf, njt_http_core_srv_conf_t *cscf,
                       njt_http_conf_port_t *port, njt_http_listen_opt_t *lsopt) {
    njt_uint_t             i, default_server, proxy_protocol,
                           protocols, protocols_prev;
    njt_http_conf_addr_t  *addr;
#if (NJT_HTTP_SSL)
    njt_uint_t ssl;
#endif
#if (NJT_HTTP_V2)
    njt_uint_t http2;
#endif
#if (NJT_HTTP_V3)
    njt_uint_t quic;
#endif

    /*
     * we cannot compare whole sockaddr struct's as kernel
     * may fill some fields in inherited sockaddr struct's
     */

    addr = port->addrs.elts;

    for (i = 0; i < port->addrs.nelts; i++) {

        if (njt_cmp_sockaddr(lsopt->sockaddr, lsopt->socklen,
                             addr[i].opt.sockaddr,
                             addr[i].opt.socklen, 0)
            != NJT_OK) {
            continue;
        }

#if (NJT_HTTP_DYNAMIC_SERVER)
	if(cf->dynamic == 1) {
		if(lsopt->ssl != addr[i].opt.ssl) {
			njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
					   "error listen options for ssl %V",
					   &addr[i].opt.addr_text);
			return NJT_ERROR;
		}
		/*
		njt_http_ssl_srv_conf_t     *sscf;
		sscf = cscf->ctx->srv_conf[njt_http_ssl_module.ctx_index];
		if ((sscf->certificates == NJT_CONF_UNSET_PTR || sscf->certificates == NULL) && (sscf->reject_handshake == 0 || sscf->reject_handshake == NJT_CONF_UNSET)) {
			 njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                              "no \"ssl_certificate\" is defined for "
                              "the \"listen ... ssl\" directive in %s:%ui",
                              cscf->file_name, cscf->line);
			return NJT_ERROR;
			 
		}*/
	}
#endif
        /* the address is already in the address list */

        if (njt_http_add_server(cf, cscf, &addr[i]) != NJT_OK) {
            return NJT_ERROR;
        }

        /* preserve default_server bit during listen options overwriting */
        default_server = addr[i].opt.default_server;

        proxy_protocol = lsopt->proxy_protocol || addr[i].opt.proxy_protocol;
        protocols = lsopt->proxy_protocol;
        protocols_prev = addr[i].opt.proxy_protocol;

#if (NJT_HTTP_SSL)
        ssl = lsopt->ssl || addr[i].opt.ssl;
        protocols |= lsopt->ssl << 1;
        protocols_prev |= addr[i].opt.ssl << 1;
#endif
#if (NJT_HTTP_V2)
        http2 = lsopt->http2 || addr[i].opt.http2;
        protocols |= lsopt->http2 << 2;
        protocols_prev |= addr[i].opt.http2 << 2;
#endif
#if (NJT_HTTP_V3)
        quic = lsopt->quic || addr[i].opt.quic;
#endif

        if (lsopt->set) {

            if (addr[i].opt.set) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "duplicate listen options for %V",
                                   &addr[i].opt.addr_text);
                return NJT_ERROR;
            }
            addr[i].opt = *lsopt;
        }

        /* check the duplicate "default" server for this address:port */

        if (lsopt->default_server) {

            if (default_server) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "a duplicate default server for %V",
                                   &addr[i].opt.addr_text);
                return NJT_ERROR;
            }

            default_server = 1;
            addr[i].default_server = cscf;
        }

        /* check for conflicting protocol options */

        if ((protocols | protocols_prev) != protocols_prev) {

            /* options added */

            if ((addr[i].opt.set && !lsopt->set)
                || addr[i].protocols_changed
                || (protocols | protocols_prev) != protocols)
            {
                njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                                   "protocol options redefined for %V",
                                   &addr[i].opt.addr_text);
            }

            addr[i].protocols = protocols_prev;
            addr[i].protocols_set = 1;
            addr[i].protocols_changed = 1;

        } else if ((protocols_prev | protocols) != protocols) {

            /* options removed */

            if (lsopt->set
                || (addr[i].protocols_set && protocols != addr[i].protocols))
            {
                njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                                   "protocol options redefined for %V",
                                   &addr[i].opt.addr_text);
            }

            addr[i].protocols = protocols;
            addr[i].protocols_set = 1;
            addr[i].protocols_changed = 1;

        } else {

            /* the same options */

            if ((lsopt->set && addr[i].protocols_changed)
                || (addr[i].protocols_set && protocols != addr[i].protocols))
            {
                njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                                   "protocol options redefined for %V",
                                   &addr[i].opt.addr_text);
            }

            addr[i].protocols = protocols;
            addr[i].protocols_set = 1;
        }


        addr[i].opt.default_server = default_server;
        addr[i].opt.proxy_protocol = proxy_protocol;
#if (NJT_HTTP_SSL)
        addr[i].opt.ssl = ssl;
#endif
#if (NJT_HTTP_V2)
        addr[i].opt.http2 = http2;
#endif
#if (NJT_HTTP_V3)
        addr[i].opt.quic = quic;
#endif


        return NJT_OK;
    }
    if(cf->dynamic == 1) {
         njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "no find listen for %V",
                                   &lsopt->addr_text);
        return NJT_ERROR;
    }

    /* add the address to the addresses list that bound to this port */

    return njt_http_add_address(cf, cscf, port, lsopt);
}


/*
 * add the server address, the server names and the server core module
 * configurations to the port list
 */

static njt_int_t
njt_http_add_address(njt_conf_t *cf, njt_http_core_srv_conf_t *cscf,
                     njt_http_conf_port_t *port, njt_http_listen_opt_t *lsopt) {
    njt_http_conf_addr_t *addr;

    if (port->addrs.elts == NULL) {
        if (njt_array_init(&port->addrs, cf->temp_pool, 4,
                           sizeof(njt_http_conf_addr_t))
            != NJT_OK) {
            return NJT_ERROR;
        }
    }

#if (NJT_HTTP_V2 && NJT_HTTP_SSL                                              \
 && !defined TLSEXT_TYPE_application_layer_protocol_negotiation)

    if (lsopt->http2 && lsopt->ssl) {
        njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                           "njet was built with OpenSSL that lacks ALPN "
                           "support, HTTP/2 is not enabled for %V",
                           &lsopt->addr_text);
    }

#endif

    addr = njt_array_push(&port->addrs);
    if (addr == NULL) {
        return NJT_ERROR;
    }

    addr->opt = *lsopt;
    addr->protocols = 0;
    addr->protocols_set = 0;
    addr->protocols_changed = 0;
    addr->hash.buckets = NULL;
    addr->hash.size = 0;
    addr->wc_head = NULL;
    addr->wc_tail = NULL;
#if (NJT_PCRE)
    addr->nregex = 0;
    addr->regex = NULL;
#endif
    addr->default_server = cscf;
    addr->servers.elts = NULL;

    return njt_http_add_server(cf, cscf, addr);
}


/* add the server core module configuration to the address:port */

static njt_int_t
njt_http_add_server(njt_conf_t *cf, njt_http_core_srv_conf_t *cscf,
                    njt_http_conf_addr_t *addr) {
    njt_uint_t i;
    njt_http_core_srv_conf_t **server;

    if (addr->servers.elts == NULL) {
        if (njt_array_init(&addr->servers, cf->temp_pool, 4,
                           sizeof(njt_http_core_srv_conf_t *))
            != NJT_OK) {
            return NJT_ERROR;
        }

    } else {
        server = addr->servers.elts;
        for (i = 0; i < addr->servers.nelts; i++) {
            if (server[i] == cscf) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "a duplicate listen %V",
                                   &addr->opt.addr_text);
                return NJT_ERROR;
            }
        }
    }

    server = njt_array_push(&addr->servers);
    if (server == NULL) {
        return NJT_ERROR;
    }

    *server = cscf;

    return NJT_OK;
}
   extern  void
njt_show_listening_sockets(njt_cycle_t *cycle);   //zyg todo

njt_int_t
njt_http_optimize_servers(njt_conf_t *cf, njt_http_core_main_conf_t *cmcf,
                          njt_array_t *ports) {
    njt_uint_t p, a;
    njt_http_conf_port_t *port;
    njt_http_conf_addr_t *addr;

    if (ports == NULL) {
        return NJT_OK;
    }
    port = ports->elts;
    for (p = 0; p < ports->nelts; p++) {

        njt_sort(port[p].addrs.elts, (size_t) port[p].addrs.nelts,
                 sizeof(njt_http_conf_addr_t), njt_http_cmp_conf_addrs);

        /*
         * check whether all name-based servers have the same
         * configuration as a default server for given address:port
         */
	
        addr = port[p].addrs.elts;
        for (a = 0; a < port[p].addrs.nelts; a++) {
	   //njt_log_error(NJT_LOG_WARN, njt_cycle->log, 0,"index=%d,ports=%p,port=%p,addr=%p,servers.nelts=%d",p,ports,&port[p],addr,addr[a].servers.nelts);
            if (addr[a].servers.nelts > 1
                #if (NJT_PCRE)
                || addr[a].default_server->captures
#endif
                    ) {
                if (njt_http_server_names(cf, cmcf, &addr[a]) != NJT_OK) {
                    return NJT_ERROR;
                }
            }
        }
        if (njt_http_init_listening(cf, &port[p]) != NJT_OK) {
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}


static njt_int_t
njt_http_server_names(njt_conf_t *cf, njt_http_core_main_conf_t *cmcf,
                      njt_http_conf_addr_t *addr) {
    njt_int_t rc;
    njt_uint_t n, s;
    njt_hash_init_t hash;
    njt_hash_keys_arrays_t ha;
    njt_http_server_name_t *name;
    njt_http_core_srv_conf_t **cscfp;
#if (NJT_PCRE)
    njt_uint_t regex, i;

    regex = 0;
#endif

    njt_memzero(&ha, sizeof(njt_hash_keys_arrays_t));

    ha.temp_pool = njt_create_pool(NJT_DEFAULT_POOL_SIZE, cf->log);
    if (ha.temp_pool == NULL) {
        return NJT_ERROR;
    }

    ha.pool = cf->pool;

    if (njt_hash_keys_array_init(&ha, NJT_HASH_LARGE) != NJT_OK) {
        goto failed;
    }

    cscfp = addr->servers.elts;

    for (s = 0; s < addr->servers.nelts; s++) {

        name = cscfp[s]->server_names.elts;

        for (n = 0; n < cscfp[s]->server_names.nelts; n++) {

#if (NJT_PCRE)
            if (name[n].regex) {
                regex++;
                continue;
            }
#endif
	
            rc = njt_hash_add_key(&ha, &name[n].name, name[n].server,
                                  NJT_HASH_WILDCARD_KEY);

            if (rc == NJT_ERROR) {
                goto failed;
            }

            if (rc == NJT_DECLINED) {
                njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                              "invalid server name or wildcard \"%V\" on %V",
                              &name[n].name, &addr->opt.addr_text);
                goto failed;
            }

            if (rc == NJT_BUSY) {
                njt_log_error(NJT_LOG_WARN, cf->log, 0,
                              "conflicting server name \"%V\" on %V, ignored",
                              &name[n].name, &addr->opt.addr_text);
            }
        }
    }

    hash.key = njt_hash_key_lc;
    hash.max_size = cmcf->server_names_hash_max_size;
    hash.bucket_size = cmcf->server_names_hash_bucket_size;
    hash.name = "server_names_hash";
    hash.pool = cf->pool;

    if (ha.keys.nelts) {
        hash.hash = &addr->hash;
        hash.temp_pool = NULL;
        if (njt_hash_init(&hash, ha.keys.elts, ha.keys.nelts) != NJT_OK) {
            goto failed;
        }
    }

    if (ha.dns_wc_head.nelts) {

        njt_qsort(ha.dns_wc_head.elts, (size_t) ha.dns_wc_head.nelts,
                  sizeof(njt_hash_key_t), njt_http_cmp_dns_wildcards);

        hash.hash = NULL;
        hash.temp_pool = ha.temp_pool;

        if (njt_hash_wildcard_init(&hash, ha.dns_wc_head.elts,
                                   ha.dns_wc_head.nelts)
            != NJT_OK) {
            goto failed;
        }

        addr->wc_head = (njt_hash_wildcard_t *) hash.hash;
    }

    if (ha.dns_wc_tail.nelts) {

        njt_qsort(ha.dns_wc_tail.elts, (size_t) ha.dns_wc_tail.nelts,
                  sizeof(njt_hash_key_t), njt_http_cmp_dns_wildcards);

        hash.hash = NULL;
        hash.temp_pool = ha.temp_pool;

        if (njt_hash_wildcard_init(&hash, ha.dns_wc_tail.elts,
                                   ha.dns_wc_tail.nelts)
            != NJT_OK) {
            goto failed;
        }

        addr->wc_tail = (njt_hash_wildcard_t *) hash.hash;
    }

    njt_destroy_pool(ha.temp_pool);

#if (NJT_PCRE)

    if (regex == 0) {
        return NJT_OK;
    }

    addr->nregex = regex;
    addr->regex = njt_palloc(cf->pool, regex * sizeof(njt_http_server_name_t));
    if (addr->regex == NULL) {
        return NJT_ERROR;
    }

    i = 0;

    for (s = 0; s < addr->servers.nelts; s++) {

        name = cscfp[s]->server_names.elts;

        for (n = 0; n < cscfp[s]->server_names.nelts; n++) {
            if (name[n].regex) {
                addr->regex[i++] = name[n];
            }
        }
    }

#endif

    return NJT_OK;

    failed:

    njt_destroy_pool(ha.temp_pool);

    return NJT_ERROR;
}


static njt_int_t
njt_http_cmp_conf_addrs(const void *one, const void *two) {
    njt_http_conf_addr_t *first, *second;

    first = (njt_http_conf_addr_t *) one;
    second = (njt_http_conf_addr_t *) two;

    if (first->opt.wildcard) {
        /* a wildcard address must be the last resort, shift it to the end */
        return 1;
    }

    if (second->opt.wildcard) {
        /* a wildcard address must be the last resort, shift it to the end */
        return -1;
    }

    if (first->opt.bind && !second->opt.bind) {
        /* shift explicit bind()ed addresses to the start */
        return -1;
    }

    if (!first->opt.bind && second->opt.bind) {
        /* shift explicit bind()ed addresses to the start */
        return 1;
    }

    /* do not sort by default */

    return 0;
}


static int njt_libc_cdecl
njt_http_cmp_dns_wildcards(const void *one, const void *two) {
    njt_hash_key_t *first, *second;

    first = (njt_hash_key_t *) one;
    second = (njt_hash_key_t *) two;

    return njt_dns_strcmp(first->key.data, second->key.data);
}


static njt_int_t
njt_http_init_listening(njt_conf_t *cf, njt_http_conf_port_t *port) {
    njt_uint_t i, last, bind_wildcard;
    njt_listening_t *ls;
    njt_http_port_t *hport;
    njt_http_conf_addr_t *addr;

    addr = port->addrs.elts;
    last = port->addrs.nelts;

    /*
     * If there is a binding to an "*:port" then we need to bind() to
     * the "*:port" only and ignore other implicit bindings.  The bindings
     * have been already sorted: explicit bindings are on the start, then
     * implicit bindings go, and wildcard binding is in the end.
     */

    if (addr[last - 1].opt.wildcard) {
        addr[last - 1].opt.bind = 1;
        bind_wildcard = 1;

    } else {
        bind_wildcard = 0;
    }

    i = 0;

    while (i < last) {

        if (bind_wildcard && !addr[i].opt.bind) {
            i++;
            continue;
        }
#if (NJT_HTTP_DYNAMIC_SERVER)
	if (cf->dynamic == 1) {// 0.0.0.0   //127.0.0.1
	   ls = njt_get_listening(cf,addr[i].opt.sockaddr,addr[i].opt.socklen);
       if(ls == NULL) {
            return NJT_ERROR;
       }
	   hport = ls->servers;
	} else {
#endif
		ls = njt_http_add_listening(cf, &addr[i]);
		if (ls == NULL) {
		    return NJT_ERROR;
		}
		//addr[i].if_bind = 1;

		hport = njt_pcalloc(cf->pool, sizeof(njt_http_port_t));
		if (hport == NULL) {
		    return NJT_ERROR;
		}
		ls->servers = hport;
#if (NJT_HTTP_DYNAMIC_SERVER)
	}
#endif
        ls->server_type = NJT_HTTP_SERVER_TYPE;

        hport->naddrs = i + 1;

        switch (ls->sockaddr->sa_family) {

#if (NJT_HAVE_INET6)
            case AF_INET6:
                if (njt_http_add_addrs6(cf, hport, addr) != NJT_OK) {
                    return NJT_ERROR;
                }
                break;
#endif
            default: /* AF_INET */
                if (njt_http_add_addrs(cf, hport, addr) != NJT_OK) {
                    return NJT_ERROR;
                }
                break;
        }
        addr++;
        last--;
    }

    return NJT_OK;
}


static njt_listening_t *
njt_http_add_listening(njt_conf_t *cf, njt_http_conf_addr_t *addr) {
    njt_listening_t *ls;
    njt_http_core_loc_conf_t *clcf;
    njt_http_core_srv_conf_t *cscf;

    ls = njt_create_listening(cf, addr->opt.sockaddr, addr->opt.socklen);
    if (ls == NULL) {
        return NULL;
    }
    ls->addr_ntop = 1;

    ls->handler = njt_http_init_connection;

    cscf = addr->default_server;
    ls->pool_size = cscf->connection_pool_size;

    clcf = cscf->ctx->loc_conf[njt_http_core_module.ctx_index];

    ls->logp = clcf->error_log;
    ls->log.data = &ls->addr_text;
    ls->log.handler = njt_accept_log_error;

#if (NJT_WIN32)
    {
    njt_iocp_conf_t  *iocpcf = NULL;

    if (njt_get_conf(cf->cycle->conf_ctx, njt_events_module)) {
        iocpcf = njt_event_get_conf(cf->cycle->conf_ctx, njt_iocp_module);
    }
    if (iocpcf && iocpcf->acceptex_read) {
        ls->post_accept_buffer_size = cscf->client_header_buffer_size;
    }
    }
#endif

    ls->type = addr->opt.type;
    ls->backlog = addr->opt.backlog;
    ls->rcvbuf = addr->opt.rcvbuf;
    ls->sndbuf = addr->opt.sndbuf;

    ls->keepalive = addr->opt.so_keepalive;
#if (NJT_HAVE_KEEPALIVE_TUNABLE)
    ls->keepidle = addr->opt.tcp_keepidle;
    ls->keepintvl = addr->opt.tcp_keepintvl;
    ls->keepcnt = addr->opt.tcp_keepcnt;
#endif

#if (NJT_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    ls->accept_filter = addr->opt.accept_filter;
#endif

#if (NJT_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
    ls->deferred_accept = addr->opt.deferred_accept;
#endif

#if (NJT_HAVE_INET6)
    ls->ipv6only = addr->opt.ipv6only;
#endif

#if (NJT_HAVE_SETFIB)
    ls->setfib = addr->opt.setfib;
#endif

#if (NJT_HAVE_TCP_FASTOPEN)
    ls->fastopen = addr->opt.fastopen;
#endif

#if (NJT_HAVE_REUSEPORT)
    ls->reuseport = addr->opt.reuseport;
#endif

    ls->wildcard = addr->opt.wildcard;

#if (NJT_HTTP_V3)
    ls->quic = addr->opt.quic;
#endif

    return ls;
}


static njt_int_t
njt_http_add_addrs(njt_conf_t *cf, njt_http_port_t *hport,
                   njt_http_conf_addr_t *addr) {
    njt_uint_t i;
    njt_http_in_addr_t *addrs;
    struct sockaddr_in *sin;
    njt_http_virtual_names_t *vn;

    if ( cf->dynamic == 0 || hport->addrs == NULL) {
	    hport->addrs = njt_pcalloc(cf->pool,
				       hport->naddrs * sizeof(njt_http_in_addr_t));
	    if (hport->addrs == NULL) {
		return NJT_ERROR;
	    }
   } 
    addrs = hport->addrs;

    for (i = 0; i < hport->naddrs; i++) {

        addrs[i].conf.virtual_names = NULL;   //zyg.dynamic  动态需要

        sin = (struct sockaddr_in *) addr[i].opt.sockaddr;
        addrs[i].addr = sin->sin_addr.s_addr;
        addrs[i].conf.default_server = addr[i].default_server;
#if (NJT_HTTP_SSL)
        addrs[i].conf.ssl = addr[i].opt.ssl;
#endif
#if (NJT_HTTP_V2)
        addrs[i].conf.http2 = addr[i].opt.http2;
#endif
#if (NJT_HTTP_V3)
        addrs[i].conf.quic = addr[i].opt.quic;
#endif
        addrs[i].conf.proxy_protocol = addr[i].opt.proxy_protocol;

        if (addr[i].hash.buckets == NULL
            && (addr[i].wc_head == NULL
                || addr[i].wc_head->hash.buckets == NULL)
            && (addr[i].wc_tail == NULL
                || addr[i].wc_tail->hash.buckets == NULL)
            #if (NJT_PCRE)
            && addr[i].nregex == 0
#endif
                ) {
            continue;
        }

        vn = njt_palloc(cf->pool, sizeof(njt_http_virtual_names_t));
        if (vn == NULL) {
            return NJT_ERROR;
        }
	
        addrs[i].conf.virtual_names = vn;

        vn->names.hash = addr[i].hash;
        vn->names.wc_head = addr[i].wc_head;
        vn->names.wc_tail = addr[i].wc_tail;
#if (NJT_PCRE)
        vn->nregex = addr[i].nregex;
        vn->regex = addr[i].regex;
#endif
    }

    return NJT_OK;
}


#if (NJT_HAVE_INET6)

static njt_int_t
njt_http_add_addrs6(njt_conf_t *cf, njt_http_port_t *hport,
                    njt_http_conf_addr_t *addr) {
    njt_uint_t i;
    njt_http_in6_addr_t *addrs6;
    struct sockaddr_in6 *sin6;
    njt_http_virtual_names_t *vn;

    if ( cf->dynamic == 0 || hport->addrs == NULL) {
	    hport->addrs = njt_pcalloc(cf->pool,
				       hport->naddrs * sizeof(njt_http_in6_addr_t));
	    if (hport->addrs == NULL) {
		return NJT_ERROR;
	    }
    }

    addrs6 = hport->addrs;

    for (i = 0; i < hport->naddrs; i++) {
        addrs6[i].conf.virtual_names = NULL;  //zyg.dynamic  动态需要
        sin6 = (struct sockaddr_in6 *) addr[i].opt.sockaddr;
        addrs6[i].addr6 = sin6->sin6_addr;
        addrs6[i].conf.default_server = addr[i].default_server;
#if (NJT_HTTP_SSL)
        addrs6[i].conf.ssl = addr[i].opt.ssl;
#endif
#if (NJT_HTTP_V2)
        addrs6[i].conf.http2 = addr[i].opt.http2;
#endif
#if (NJT_HTTP_V3)
        addrs6[i].conf.quic = addr[i].opt.quic;
#endif
        addrs6[i].conf.proxy_protocol = addr[i].opt.proxy_protocol;

        if (addr[i].hash.buckets == NULL
            && (addr[i].wc_head == NULL
                || addr[i].wc_head->hash.buckets == NULL)
            && (addr[i].wc_tail == NULL
                || addr[i].wc_tail->hash.buckets == NULL)
            #if (NJT_PCRE)
            && addr[i].nregex == 0
#endif
                ) {
            continue;
        }

        vn = njt_palloc(cf->pool, sizeof(njt_http_virtual_names_t));
        if (vn == NULL) {
            return NJT_ERROR;
        }

        addrs6[i].conf.virtual_names = vn;

        vn->names.hash = addr[i].hash;
        vn->names.wc_head = addr[i].wc_head;
        vn->names.wc_tail = addr[i].wc_tail;
#if (NJT_PCRE)
        vn->nregex = addr[i].nregex;
        vn->regex = addr[i].regex;
#endif
    }

    return NJT_OK;
}

#endif


char *
njt_http_types_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf) {
    char *p = conf;

    njt_array_t **types;
    njt_str_t *value, *default_type;
    njt_uint_t i, n, hash;
    njt_hash_key_t *type;

    types = (njt_array_t **) (p + cmd->offset);

    if (*types == (void *) -1) {
        return NJT_CONF_OK;
    }

    default_type = cmd->post;

    if (*types == NULL) {
        *types = njt_array_create(cf->temp_pool, 1, sizeof(njt_hash_key_t));
        if (*types == NULL) {
            return NJT_CONF_ERROR;
        }

        if (default_type) {
            type = njt_array_push(*types);
            if (type == NULL) {
                return NJT_CONF_ERROR;
            }

            type->key = *default_type;
            type->key_hash = njt_hash_key(default_type->data,
                                          default_type->len);
            type->value = (void *) 4;
        }
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (value[i].len == 1 && value[i].data[0] == '*') {
            *types = (void *) -1;
            return NJT_CONF_OK;
        }

        hash = njt_hash_strlow(value[i].data, value[i].data, value[i].len);
        value[i].data[value[i].len] = '\0';

        type = (*types)->elts;
        for (n = 0; n < (*types)->nelts; n++) {

            if (njt_strcmp(value[i].data, type[n].key.data) == 0) {
                njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                                   "duplicate MIME type \"%V\"", &value[i]);
                goto next;
            }
        }

        type = njt_array_push(*types);
        if (type == NULL) {
            return NJT_CONF_ERROR;
        }

        type->key = value[i];
        type->key_hash = hash;
        type->value = (void *) 4;

        next:

        continue;
    }

    return NJT_CONF_OK;
}


char *
njt_http_merge_types(njt_conf_t *cf, njt_array_t **keys, njt_hash_t *types_hash,
                     njt_array_t **prev_keys, njt_hash_t *prev_types_hash,
                     njt_str_t *default_types) {
    njt_hash_init_t hash;

    if (*keys) {

        if (*keys == (void *) -1) {
            return NJT_CONF_OK;
        }

        hash.hash = types_hash;
        hash.key = NULL;
        hash.max_size = 2048;
        hash.bucket_size = 64;
        hash.name = "test_types_hash";
        hash.pool = cf->pool;
        hash.temp_pool = NULL;

        if (njt_hash_init(&hash, (*keys)->elts, (*keys)->nelts) != NJT_OK) {
            return NJT_CONF_ERROR;
        }

        return NJT_CONF_OK;
    }

    if (prev_types_hash->buckets == NULL) {

        if (*prev_keys == NULL) {

            if (njt_http_set_default_types(cf, prev_keys, default_types)
                != NJT_OK) {
                return NJT_CONF_ERROR;
            }

        } else if (*prev_keys == (void *) -1) {
            *keys = *prev_keys;
            return NJT_CONF_OK;
        }

        hash.hash = prev_types_hash;
        hash.key = NULL;
        hash.max_size = 2048;
        hash.bucket_size = 64;
        hash.name = "test_types_hash";
        hash.pool = cf->pool;
        hash.temp_pool = NULL;

        if (njt_hash_init(&hash, (*prev_keys)->elts, (*prev_keys)->nelts)
            != NJT_OK) {
            return NJT_CONF_ERROR;
        }
    }

    *types_hash = *prev_types_hash;

    return NJT_CONF_OK;

}


njt_int_t
njt_http_set_default_types(njt_conf_t *cf, njt_array_t **types,
                           njt_str_t *default_type) {
    njt_hash_key_t *type;

    *types = njt_array_create(cf->temp_pool, 1, sizeof(njt_hash_key_t));
    if (*types == NULL) {
        return NJT_ERROR;
    }

    while (default_type->len) {

        type = njt_array_push(*types);
        if (type == NULL) {
            return NJT_ERROR;
        }

        type->key = *default_type;
        type->key_hash = njt_hash_key(default_type->data,
                                      default_type->len);
        type->value = (void *) 4;

        default_type++;
    }

    return NJT_OK;
}

njt_int_t
njt_http_add_if_location(njt_conf_t *cf, njt_queue_t **locations,
                      njt_http_core_loc_conf_t *clcf) {
  return NJT_OK;
}
