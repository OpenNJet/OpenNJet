
/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_rand_util.h>
#include <njt_http_dyn_module.h>

#include "njt_http_fault_inject_module.h"



// static njt_conf_enum_t  njt_http_fault_inject_types[] = {
//     { njt_string("none"), NJT_HTTP_FAULT_INJECT_NONE },
//     { njt_string("delay"), NJT_HTTP_FAULT_INJECT_DELAY },
//     { njt_string("abort"), NJT_HTTP_FAULT_INJECT_ABORT },
//     { njt_string("delay_abort"), NJT_HTTP_FAULT_INJECT_DELAY_ABORT }
// };


static void *njt_http_fault_inject_create_conf(njt_conf_t *cf);
static char *njt_http_fault_inject(njt_conf_t *cf, njt_command_t *cmd,
                                        void *conf);
static void njt_http_fault_inject_timer_cleanup(void *data);
static void njt_http_fault_inject_abort_request(njt_http_request_t *r);

// static njt_conf_num_bounds_t njt_http_fault_inject_abort_status_bounds = {
//     njt_conf_check_num_bounds, 200, 600};

static njt_command_t njt_http_fault_inject_commands[] = {

    {njt_string("fault_inject"),
     NJT_HTTP_LOC_CONF | NJT_CONF_2MORE,
     njt_http_fault_inject,
     NJT_HTTP_LOC_CONF_OFFSET,
     0,
     NULL},

    njt_null_command};

static njt_http_module_t njt_http_fault_inject_module_ctx = {
    NULL, /* preconfiguration */
    NULL,          /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    njt_http_fault_inject_create_conf, /* create location configuration */
    NULL   /* merge location configuration */
};


njt_module_t njt_http_fault_inject_module = {
    NJT_MODULE_V1,
    &njt_http_fault_inject_module_ctx, /* module context */
    njt_http_fault_inject_commands,    /* module directives */
    NJT_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NJT_MODULE_V1_PADDING
};



static void *
njt_http_fault_inject_create_conf(njt_conf_t *cf)
{
    njt_http_fault_inject_conf_t *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_fault_inject_conf_t));

    if (conf == NULL)
    {
        return NULL;
    }

    conf->fault_inject_type = NJT_HTTP_FAULT_INJECT_NONE;
    conf->duration = NJT_CONF_UNSET_MSEC;
    conf->str_duration.data = NULL;
    conf->str_duration.len = 0;
    conf->dynamic = 0;
    conf->delay_percent = 100;
    conf->abort_percent = 100;
    conf->status_code = 200;
    conf->pool = NULL;

    return conf;
}



static char *
njt_http_fault_inject(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_str_t                           *value;
    njt_uint_t                          i;
    njt_http_fault_inject_conf_t        *ficf;
    size_t                              param_len;
    njt_str_t					        tmp_str;
    bool                                status_code_set = false;

    value = cf->args->elts;
    ficf = (njt_http_fault_inject_conf_t *)conf;
    if(NJT_HTTP_FAULT_INJECT_NONE != ficf->fault_inject_type){
        return "is duplicate";
    }

    for (i = 1; i < cf->args->nelts; i++)
    {
        if (njt_strncmp(value[i].data, "type=", 5) == 0)
        {
            param_len = value[i].len - 5;
            if(param_len < 1){
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                " fault inject type should not null");
                return NJT_CONF_ERROR;
            }

            if(param_len == 5 && njt_strncmp(value[i].data+5, "delay", 5) == 0){
                ficf->fault_inject_type = NJT_HTTP_FAULT_INJECT_DELAY;
            }else if(param_len == 5 && njt_strncmp(value[i].data+5, "abort", 5) == 0){
                ficf->fault_inject_type = NJT_HTTP_FAULT_INJECT_ABORT;
            }else if(param_len == 11 && njt_strncmp(value[i].data+5, "delay_abort", 11) == 0){
                ficf->fault_inject_type = NJT_HTTP_FAULT_INJECT_DELAY_ABORT;
            }else{
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                            " fault inject type should be delay or abort or delay_abort");
                return NJT_CONF_ERROR;
            }

            continue;
        }else if (njt_strncmp(value[i].data, "delay_duration=", 15) == 0)
        {
            tmp_str.data = value[i].data + 15;
			tmp_str.len = value[i].len - 15;
			ficf->duration = njt_parse_time(&tmp_str, 0);
			if (ficf->duration == (njt_msec_t) NJT_ERROR) {
				njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
					" fault inject, invalid delay_duration, should 1h/1m/1s/1ms format");
				return NJT_CONF_ERROR;
			}

			if (ficf->duration < 1) {
				njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
					" fault inject, delay_duration should not less than 1ms");

				return NJT_CONF_ERROR;
			}

            ficf->str_duration.len = tmp_str.len;
            ficf->str_duration.data = njt_pcalloc(cf->pool, tmp_str.len);
            if(ficf->str_duration.data == NULL){
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
					" fault inject, delay_duration malloc error");

				return NJT_CONF_ERROR;
            }
            njt_memcpy(ficf->str_duration.data, tmp_str.data, tmp_str.len);

            continue;
        }else if (njt_strncmp(value[i].data, "status_code=", 12) == 0)
        {
            status_code_set = true;
            tmp_str.data = value[i].data + 12;
			tmp_str.len = value[i].len - 12;

            ficf->status_code = njt_atoi(tmp_str.data, tmp_str.len);
			if (ficf->status_code < 200 || ficf->status_code > 600) {
				njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
					" fault inject, status_code should [200, 600]");

				return NJT_CONF_ERROR;
			}

            continue;
        }else if (njt_strncmp(value[i].data, "delay_percentage=", 17) == 0)
        {
            tmp_str.data = value[i].data + 17;
			tmp_str.len = value[i].len - 17;

            ficf->delay_percent = njt_atoi(tmp_str.data, tmp_str.len);
			if (ficf->delay_percent < 1 || ficf->delay_percent > 100) {
				njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
					" fault inject, invalid delay_percent, shoud [1,100]");

				return NJT_CONF_ERROR;
			}

            continue;
        }else if (njt_strncmp(value[i].data, "abort_percentage=", 17) == 0)
        {
            tmp_str.data = value[i].data + 17;
			tmp_str.len = value[i].len - 17;

            ficf->abort_percent = njt_atoi(tmp_str.data, tmp_str.len);
			if (ficf->abort_percent < 1 || ficf->abort_percent > 100) {
				njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
					" fault inject, invalid abort_percent, shoud [1,100]");
				return NJT_CONF_ERROR;
			}

            continue;
        }else{
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
					" fault inject, not support param:%V", &value[i]);
			return NJT_CONF_ERROR;
        }
    }

    if(NJT_HTTP_FAULT_INJECT_NONE == ficf->fault_inject_type){
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                "fault injet directive must has type, should delay, abort, delay_abort");
        return NJT_CONF_ERROR;
    }

    //if delay must has delay_duration
    if(NJT_HTTP_FAULT_INJECT_DELAY == ficf->fault_inject_type
        || NJT_HTTP_FAULT_INJECT_DELAY_ABORT == ficf->fault_inject_type){
        if(NJT_CONF_UNSET_MSEC == ficf->duration){
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                "fault injet, delay or delay_abort must has delay_duration param");
            return NJT_CONF_ERROR;
        } 
    }

    //if abort must has status_code
    if(NJT_HTTP_FAULT_INJECT_ABORT == ficf->fault_inject_type
        || NJT_HTTP_FAULT_INJECT_DELAY_ABORT == ficf->fault_inject_type){
        if(!status_code_set){
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                "fault injet, abort or delay_abort must has status_code param");
            return NJT_CONF_ERROR;
        } 
    }

    return NJT_CONF_OK;
}

static void njt_http_fault_inject_delay_handler(njt_event_t *ev){
    njt_http_request_t                  *r;
    njt_http_fault_inject_conf_t        *ficf;

    r = ev->data;

    njt_log_error(NJT_LOG_EMERG, r->pool->log, 0, " fault njet delay success");

    ficf = njt_http_get_module_loc_conf(r, njt_http_fault_inject_module);
    if(ficf == NULL || ficf->fault_inject_type == NJT_HTTP_FAULT_INJECT_NONE
        || ficf->fault_inject_type == NJT_HTTP_FAULT_INJECT_ABORT){
        njt_log_error(NJT_LOG_EMERG, r->pool->log, 0, " delay fault inject internal error");
        njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if(NJT_HTTP_FAULT_INJECT_DELAY == ficf->fault_inject_type){
        return njt_http_upstream_init(r);
    }

    if(NJT_HTTP_FAULT_INJECT_DELAY_ABORT == ficf->fault_inject_type){
        if(njt_rand_percentage_sample(ficf->abort_percent)){
            //abort percentage hit
            return njt_http_fault_inject_abort_request(r);
        }

        // if not hit percent, need connect upstream;
        return njt_http_upstream_init(r);
    }

    return;
}


static void
njt_http_fault_inject_timer_cleanup(void *data)
{
    njt_http_request_t *r = data;
    njt_log_error(NJT_LOG_EMERG, r->pool->log, 0, " fault inject delay timer clean");
    if (r->delay_timer && r->delay_timer->timer_set) {
        njt_del_timer(r->delay_timer);
    }

    return;
}


void njt_http_fault_inject_delay_request(njt_http_request_t *r){
    njt_http_fault_inject_conf_t        *ficf;
    njt_event_t                         *delay_timer;
    njt_connection_t                    *c;
    njt_http_cleanup_t                  *cln;

    ficf = njt_http_get_module_loc_conf(r, njt_http_fault_inject_module);
    if(ficf == NULL || ficf->fault_inject_type == NJT_HTTP_FAULT_INJECT_NONE
        || ficf->fault_inject_type == NJT_HTTP_FAULT_INJECT_ABORT){
        njt_log_error(NJT_LOG_EMERG, r->pool->log, 0, " fault inject config is null in delay inject");
        njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if(r->delay_timer == NULL){
        r->delay_timer = njt_pcalloc(r->pool, sizeof(njt_event_t));
        if(r->delay_timer == NULL){
            njt_log_error(NJT_LOG_EMERG, r->pool->log, 0, " delay timer malloc error in fault inject");
            njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    delay_timer = r->delay_timer;
    delay_timer->handler = njt_http_fault_inject_delay_handler;
    delay_timer->log = njt_cycle->log;
    delay_timer->data = r;
    delay_timer->cancelable = 1;

    njt_add_timer(delay_timer, ficf->duration);

    // add clean handler
    cln = njt_http_cleanup_add(r, 0);
    if (cln == NULL) {
        njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    cln->handler = njt_http_fault_inject_timer_cleanup;
    cln->data = r;
    njt_log_error(NJT_LOG_EMERG, r->pool->log, 0, " fault inject start deleay");
    //need close read timeout event to downstream
#if (NJT_HTTP_V2)
    if (r->stream) {
        return;
    }
#endif

    c = r->connection;
    if (c->read->timer_set) {
        njt_del_timer(c->read);
    }
}


static void njt_http_fault_inject_abort_request(njt_http_request_t *r){
    njt_http_fault_inject_conf_t        *ficf;

    ficf = njt_http_get_module_loc_conf(r, njt_http_fault_inject_module);
    if(ficf == NULL || ficf->fault_inject_type == NJT_HTTP_FAULT_INJECT_NONE
        || ficf->fault_inject_type == NJT_HTTP_FAULT_INJECT_DELAY){
        njt_log_error(NJT_LOG_EMERG, r->pool->log, 0, " fault inject config is null in abort inject");
        
        njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    njt_log_error(NJT_LOG_EMERG, r->pool->log, 0, " fault injet abort %d", ficf->status_code);
    
    r->headers_out.status = ficf->status_code;
    r->abort_flag = 1;
    // njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
    njt_http_finalize_request(r, ficf->status_code);
}


void njt_http_fault_inject_handler(njt_http_request_t *r){
    njt_http_fault_inject_conf_t        *ficf;

    ficf = njt_http_get_module_loc_conf(r, njt_http_fault_inject_module);
    if(ficf == NULL || ficf->fault_inject_type == NJT_HTTP_FAULT_INJECT_NONE){
        return njt_http_upstream_init(r);
    }
    
    switch (ficf->fault_inject_type)
    {
        case NJT_HTTP_FAULT_INJECT_NONE:
            goto norm_handler;
            break;
        case NJT_HTTP_FAULT_INJECT_DELAY:
            if(njt_rand_percentage_sample(ficf->delay_percent)){
                //delay percentage hit
                return njt_http_fault_inject_delay_request(r);
            }else{
                goto norm_handler;
            }
            break;
        case NJT_HTTP_FAULT_INJECT_ABORT:
            if(njt_rand_percentage_sample(ficf->abort_percent)){
                //abort percentage hit
                return njt_http_fault_inject_abort_request(r);
            }else{
                goto norm_handler;
            }
        case NJT_HTTP_FAULT_INJECT_DELAY_ABORT:
            if(njt_rand_percentage_sample(ficf->delay_percent)){
                //delay percentage hit
                return njt_http_fault_inject_delay_request(r);
            }else if(njt_rand_percentage_sample(ficf->abort_percent)){
                //abort percentage hit
                return njt_http_fault_inject_abort_request(r);
            }else{
                goto norm_handler;
            }
        default:
            goto norm_handler;
            break;
    }

norm_handler:
    njt_http_upstream_init(r);
}