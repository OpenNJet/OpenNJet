/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */
#include <njt_core.h>
#include <njt_http_kv_module.h>
#include <njt_http.h>
#include <njt_json_util.h>
#include <njt_http_util.h>
#include <njt_http_dyn_module.h>

#include "njt_http_dyn_limit_module.h"

extern njt_module_t njt_http_limit_conn_module;
extern njt_module_t njt_http_limit_req_module;


static njt_conf_enum_t  njt_http_dyn_limit_conn_log_levels[] = {
    { njt_string("info"), NJT_LOG_INFO },
    { njt_string("notice"), NJT_LOG_NOTICE },
    { njt_string("warn"), NJT_LOG_WARN },
    { njt_string("error"), NJT_LOG_ERR },
    { njt_null_string, 0 }
};

static njt_conf_enum_t  njt_http_dyn_limit_req_log_levels[] = {
    { njt_string("info"), NJT_LOG_INFO },
    { njt_string("notice"), NJT_LOG_NOTICE },
    { njt_string("warn"), NJT_LOG_WARN },
    { njt_string("error"), NJT_LOG_ERR },
    { njt_null_string, 0 }
};

static njt_command_t limit_rate_cmd = {
      njt_string("limit_rate"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_CONF_TAKE1,
      njt_http_set_complex_value_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, limit_rate),
      NULL
};

static njt_command_t limit_rate_after_cmd = {
      njt_string("limit_rate_after"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_CONF_TAKE1,
      njt_http_set_complex_value_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, limit_rate_after),
      NULL
};


static njt_json_define_t njt_http_dyn_limit_conn_json_dt[] = {
    {
        njt_string("zone"),
        offsetof(njt_http_dyn_limit_conn_t, zone),
        0,
        NJT_JSON_STR,
        0,
        NULL,
        NULL,
    },
    {
        njt_string("conn"),
        offsetof(njt_http_dyn_limit_conn_t, conn),
        0,
        NJT_JSON_INT,
        0,
        NULL,
        NULL,
    },

    njt_json_define_null,
};


static njt_json_define_t njt_http_dyn_limit_req_json_dt[] = {
    {
        njt_string("zone"),
        offsetof(njt_http_dyn_limit_req_t, zone),
        0,
        NJT_JSON_STR,
        0,
        NULL,
        NULL,
    },
    {
        njt_string("burst"),
        offsetof(njt_http_dyn_limit_req_t, burst),
        0,
        NJT_JSON_INT,
        0,
        NULL,
        NULL,
    },
    {
        njt_string("delay"),
        offsetof(njt_http_dyn_limit_req_t, delay),
        0,
        NJT_JSON_STR,
        0,
        NULL,
        NULL,
    },

    njt_json_define_null,
};



static njt_json_define_t njt_http_dyn_limit_loc_json_dt[] = {
    {
        njt_string("location"),
        offsetof(njt_http_dyn_limit_loc_t, full_name),
        0,
        NJT_JSON_STR,
        0,
        NULL,
        NULL,
    },
    {
        njt_string("limit_rate"),
        offsetof(njt_http_dyn_limit_loc_t, limit_rate),
        0,
        NJT_JSON_STR,
        0,
        NULL,
        NULL,
    },
    {
        njt_string("limit_rate_after"),
        offsetof(njt_http_dyn_limit_loc_t, limit_rate_after),
        0,
        NJT_JSON_STR,
        0,
        NULL,
        NULL,
    },
    {
        njt_string("limit_reqs_scope"),
        offsetof(njt_http_dyn_limit_loc_t, limit_reqs_scope),
        sizeof(njt_http_dyn_limit_conn_t),
        NJT_JSON_STR,
        0,
        njt_http_dyn_limit_conn_json_dt,
        NULL,
    },
    {
        njt_string("limit_reqs"),
        offsetof(njt_http_dyn_limit_loc_t, limit_reqs),
        sizeof(njt_http_dyn_limit_req_t),
        NJT_JSON_ARRAY,
        NJT_JSON_OBJ,
        njt_http_dyn_limit_req_json_dt,
        NULL,
    },
    {
        njt_string("limit_req_dry_run"),
        offsetof(njt_http_dyn_limit_loc_t, limit_req_dry_run),
        0,
        NJT_JSON_STR,
        0,
        NULL,
        NULL,
    },
    {
        njt_string("limit_req_log_level"),
        offsetof(njt_http_dyn_limit_loc_t, limit_req_log_level),
        0,
        NJT_JSON_STR,
        0,
        NULL,
        NULL,
    },
    {
        njt_string("limit_req_status"),
        offsetof(njt_http_dyn_limit_loc_t, limit_req_status),
        0,
        NJT_JSON_INT,
        0,
        NULL,
        NULL,
    },
    {
        njt_string("limit_conns_scope"),
        offsetof(njt_http_dyn_limit_loc_t, limit_conns_scope),
        sizeof(njt_http_dyn_limit_conn_t),
        NJT_JSON_STR,
        0,
        njt_http_dyn_limit_conn_json_dt,
        NULL,
    },
    {
        njt_string("limit_conns"),
        offsetof(njt_http_dyn_limit_loc_t, limit_conns),
        sizeof(njt_http_dyn_limit_conn_t),
        NJT_JSON_ARRAY,
        NJT_JSON_OBJ,
        njt_http_dyn_limit_conn_json_dt,
        NULL,
    },
    {
        njt_string("limit_conn_dry_run"),
        offsetof(njt_http_dyn_limit_loc_t, limit_conn_dry_run),
        0,
        NJT_JSON_STR,
        0,
        NULL,
        NULL,
    },
    {
        njt_string("limit_conn_log_level"),
        offsetof(njt_http_dyn_limit_loc_t, limit_conn_log_level),
        0,
        NJT_JSON_STR,
        0,
        NULL,
        NULL,
    },
    {
        njt_string("limit_conn_status"),
        offsetof(njt_http_dyn_limit_loc_t, limit_conn_status),
        0,
        NJT_JSON_INT,
        0,
        NULL,
        NULL,
    },
    {
        njt_string("locations"),
        offsetof(njt_http_dyn_limit_loc_t, locs),
        sizeof(njt_http_dyn_limit_loc_t),
        NJT_JSON_ARRAY,
        NJT_JSON_OBJ,
        njt_http_dyn_limit_loc_json_dt,
        NULL,
    },

    njt_json_define_null,
};


static njt_json_define_t njt_http_dyn_limit_rps_json_dt[] = {
    {
        njt_string("zone"),
        offsetof(njt_http_dyn_limit_rps_t, zone),
        0,
        NJT_JSON_STR,
        0,
        NULL,
        NULL,
    },
    {
        njt_string("rate"),
        offsetof(njt_http_dyn_limit_rps_t, rate),
        0,
        NJT_JSON_STR,
        0,
        NULL,
        NULL,
    },

    njt_json_define_null,
};


static njt_json_define_t njt_http_dyn_limit_srv_json_dt[] = {
    {
        njt_string("listens"),
        offsetof(njt_http_dyn_limit_srv_t, listens),
        sizeof(njt_str_t),
        NJT_JSON_ARRAY,
        NJT_JSON_STR,
        NULL,
        NULL,
    },

    {
        njt_string("serverNames"),
        offsetof(njt_http_dyn_limit_srv_t, server_names),
        sizeof(njt_str_t),
        NJT_JSON_ARRAY,
        NJT_JSON_STR,
        NULL,
        NULL,
    },

    {
        njt_string("locations"),
        offsetof(njt_http_dyn_limit_srv_t, locs),
        sizeof(njt_http_dyn_limit_loc_t),
        NJT_JSON_ARRAY,
        NJT_JSON_OBJ,
        njt_http_dyn_limit_loc_json_dt,
        NULL,
    },

    njt_json_define_null,
};

static njt_json_define_t njt_http_dyn_limit_main_json_dt[] = {
    {
        njt_string("servers"),
        offsetof(njt_http_dyn_limit_main_t, servers),
        sizeof(njt_http_dyn_limit_srv_t),
        NJT_JSON_ARRAY,
        NJT_JSON_OBJ,
        njt_http_dyn_limit_srv_json_dt,
        NULL,
    },
    {
        njt_string("limit_rps"),
        offsetof(njt_http_dyn_limit_main_t, limit_rps),
        sizeof(njt_http_dyn_limit_rps_t),
        NJT_JSON_ARRAY,
        NJT_JSON_OBJ,
        njt_http_dyn_limit_rps_json_dt,
        NULL,
    },

    njt_json_define_null,
};

njt_str_t dyn_limit_update_srv_err_msg = njt_string("{\"code\":500,\"msg\":\"server error\"}");


njt_int_t njt_dyn_limit_check_var(njt_conf_t *cf, njt_str_t *var){
    njt_http_core_main_conf_t  *cmcf;
    njt_http_variable_t        *v;
    njt_uint_t                  i;
    size_t                      var_len;
    bool                        found = false;

    if(var == NULL || var->len < 1){
        return NJT_ERROR;
    }

    if(var->data[0] == ' '){
        return NJT_ERROR;
    } 

    if(var->data[0] != '$'){
        return NJT_OK;
    }

    if(var->len < 2){
        return NJT_ERROR;
    }

    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);
    v = cmcf->variables.elts;
    var_len = var->len - 1;
    for (i = 0; i < cmcf->variables.nelts; i++) {
        if(v[i].name.len == var_len
            && njt_strncmp(v[i].name.data, var->data + 1, v[i].name.len)
              == 0)
        {
            if (v[i].get_handler == NULL) {
                njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                    "njt_dyn_limit_rate unknown \"%V\" variable", &v[i].name);
                
                return NJT_ERROR;
            }

            found = true;
        }
    }

    if(found){
        return NJT_OK;
    }

    return NJT_ERROR;
}


njt_int_t njt_dyn_limit_check_zone(njt_conf_t *cf, njt_str_t *name, void *tag){
    njt_uint_t        i;
    njt_shm_zone_t   *shm_zone;
    njt_list_part_t  *part;
    bool              found = false;

    part = &cf->cycle->shared_memory.part;
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
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                "type error, the shared memory zone \"%V\" is "
                "already declared for a different use",
                &shm_zone[i].shm.name);
            return NJT_ERROR;
        }

        found = true;
        break;
    }

    if(found){
        return NJT_OK;
    }

    return NJT_ERROR;
}


static njt_int_t njt_dyn_limit_set_limit_conns(njt_http_dyn_limit_loc_t *data, njt_http_conf_ctx_t *ctx)
{
    njt_conf_t                   *cf;
    njt_http_limit_conn_conf_t   *lccf;
    njt_http_limit_conn_limit_t  *limit, *limits;
    njt_http_dyn_limit_conn_t     *data_limits;
    njt_uint_t                   i, j;
    bool                         found = false;
    njt_shm_zone_t               *shm_zone;
    njt_int_t                    rc;

    if(data->limit_conns.nelts < 1){
        return NJT_OK;
    }

    if(data->limit_conns_scope.len != 8 ||
        njt_strncasecmp(data->limit_conns_scope.data, (u_char *) "location", 8) !=0){
        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, 
                 "dyn limit conn not location level, so not update");
        return NJT_OK;
    }

    njt_conf_t cf_data = {
        .cycle = (njt_cycle_t *)njt_cycle,
        .log = njt_cycle->log,
        .ctx = ctx,
    };
    cf = &cf_data;

    lccf = njt_http_conf_get_module_loc_conf(cf, njt_http_limit_conn_module);
    if(lccf == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, 
            "njt_dyn_limit_set_limit_conns get module config error");
		return NJT_ERROR;
	}

    if(lccf->from_up == 1){
        lccf->limits.elts = NULL;
        lccf->from_up = 0;
    }

    limits = lccf->limits.elts;
    if (limits == NULL) {
        if (njt_array_init(&lccf->limits, njt_cycle->pool, 1,
                           sizeof(njt_http_limit_conn_limit_t))
            != NJT_OK)
        {
            return NJT_ERROR;
        }
    }

    data_limits = data->limit_conns.elts;
    for (i = 0; i < data->limit_conns.nelts; i++) {
        if(data_limits[i].zone.len < 1){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
                 "njt_dyn_limit_set_limit_conns zone name is empty");
            continue;
        }

        if(data_limits[i].conn <= 0 || data_limits[i].conn > 65535){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
                 "njt_dyn_limit_set_limit_conns zone:%V conn number is invalid, should >0 and <= 65535",
                 &data_limits[i].zone);
            continue;
        }

        found = false;
        limits = lccf->limits.elts;
        for (j = 0; j < lccf->limits.nelts; j++){
            if(limits[j].shm_zone == NULL)
            {
                njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, 
                    "njt_dyn_limit_set_limit_conns limit conn zone is null");
                continue;
            }
            
            if(data_limits[i].zone.len == limits[j].shm_zone->shm.name.len
               && njt_strncmp(data_limits[i].zone.data, limits[j].shm_zone->shm.name.data, data_limits[i].zone.len) == 0){
                //found
                found = true;
                //update
                limits[j].conn = data_limits[i].conn;
                break;
            }
        }

        if(!found){
            //check zone whether exist
            rc = njt_dyn_limit_check_zone(cf, &data_limits[i].zone, &njt_http_limit_conn_module);
            if(rc != NJT_OK){
                njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0,
                    "njt_dyn_limit_set_limit_conns zone:%V not valid", &data_limits[i].zone);
                continue;
            }
            //add
            shm_zone = njt_shared_memory_add(cf, &data_limits[i].zone, 0,
                                     &njt_http_limit_conn_module);
            if (shm_zone == NULL) {
                njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0,
                  "njt_dyn_limit_set_limit_conns shared_memory_add error, zone:%V", &data_limits[i].zone);
                continue;
            }

            limit = njt_array_push(&lccf->limits);
            if (limit == NULL) {
                njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, 
                    "njt_dyn_limit_set_limit_conns limit conn push error");
                return NJT_ERROR;
            }

            limit->conn = data_limits[i].conn;
            limit->shm_zone = shm_zone;
        }
    }

 
    return NJT_OK;
}

static njt_int_t njt_dyn_limit_set_limit_reqs(njt_http_dyn_limit_loc_t *data, njt_http_conf_ctx_t *ctx)
{
    njt_conf_t                  *cf;
    njt_http_limit_req_conf_t   *lrcf;
    njt_http_limit_req_limit_t  *limit, *limits;
    njt_http_dyn_limit_req_t    *data_limits;
    njt_uint_t                   i, j;
    bool                         found = false;
    njt_shm_zone_t              *shm_zone;
    njt_int_t                    rc;
    njt_uint_t                   delay;
    njt_int_t                    tmp_delay;

    if(data->limit_reqs.nelts < 1){
        return NJT_OK;
    }

    if(data->limit_reqs_scope.len != 8 ||
        njt_strncasecmp(data->limit_reqs_scope.data, (u_char *) "location", 8) !=0){
        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, 
                 "dyn limit req not location level, so not update");
        return NJT_OK;
    } 

    njt_conf_t cf_data = {
        .cycle = (njt_cycle_t *)njt_cycle,
        .log = njt_cycle->log,
        .ctx = ctx,
    };
    cf = &cf_data;

    lrcf = njt_http_conf_get_module_loc_conf(cf, njt_http_limit_req_module);
    if(lrcf == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, 
            "njt_dyn_limit_set_limit_reqs get module config error");
		return NJT_ERROR;
	}

    if(lrcf->from_up == 1){
        lrcf->limits.elts = NULL;
        lrcf->from_up = 0;
    }

    limits = lrcf->limits.elts;
    if (limits == NULL) {
        if (njt_array_init(&lrcf->limits, njt_cycle->pool, 1,
                           sizeof(njt_http_limit_req_limit_t))
            != NJT_OK)
        {
            return NJT_ERROR;
        }
    }

    data_limits = data->limit_reqs.elts;
    for (i = 0; i < data->limit_reqs.nelts; i++) {
        if(data_limits[i].zone.len < 1){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
                 "njt_dyn_limit_set_limit_reqs zone name is empty");
            continue;
        }

        if(data_limits[i].burst < 0 || data_limits[i].delay.len < 1){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
                 "njt_dyn_limit_set_limit_reqs zone:%V burst or delay shoud > 0 or nodelay",
                 &data_limits[i].zone);
            continue;
        }

        //check delay
        //nodelay len=7
        if(data_limits[i].delay.len == 7
            && njt_strncmp(data_limits[i].delay.data, "nodelay", 7) == 0){
            delay = NJT_MAX_INT_T_VALUE / 1000;
        }else{
            tmp_delay = njt_atoi(data_limits[i].delay.data, data_limits[i].delay.len);
            if (tmp_delay < 0) {
                njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0,
                    "njt_dyn_limit_set_limit_reqs zone:%V delay format invalid", &data_limits[i].zone);
                continue;
            }
            delay = tmp_delay;
        }

        found = false;
        limits = lrcf->limits.elts;
        for (j = 0; j < lrcf->limits.nelts; j++){
            if(limits[j].shm_zone == NULL)
            {
                njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, 
                    "njt_dyn_limit_set_limit_reqs limit req zone is null");
                continue;
            }
            
            if(data_limits[i].zone.len == limits[j].shm_zone->shm.name.len
               && njt_strncmp(data_limits[i].zone.data, limits[j].shm_zone->shm.name.data, data_limits[i].zone.len) == 0){
                //found
                found = true;
                //update
                limits[j].burst = data_limits[i].burst * 1000;
                limits[j].delay = delay * 1000;
                
                break;
            }
        }

        if(!found){
            //check zone whether exist
            rc = njt_dyn_limit_check_zone(cf, &data_limits[i].zone, &njt_http_limit_req_module);
            if(rc != NJT_OK){
                njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0,
                    "njt_dyn_limit_set_limit_reqs zone:%V not valid", &data_limits[i].zone);
                continue;
            }
            //add
            shm_zone = njt_shared_memory_add(cf, &data_limits[i].zone, 0,
                                     &njt_http_limit_req_module);
            if (shm_zone == NULL) {
                njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0,
                  "njt_dyn_limit_set_limit_reqs shared_memory_add error, zone:%V", &data_limits[i].zone);
                continue;
            }

            limit = njt_array_push(&lrcf->limits);
            if (limit == NULL) {
                njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, 
                    "njt_dyn_limit_set_limit_reqs limit req push error");
                return NJT_ERROR;
            }

            limit->burst = data_limits[i].burst * 1000;

            limit->delay = delay * 1000;
            limit->shm_zone = shm_zone;
        }
    }

 
    return NJT_OK;
}



static njt_int_t njt_dyn_limit_set_limit_rate(njt_http_dyn_limit_loc_t *data, njt_http_conf_ctx_t *ctx)
{
    njt_http_core_loc_conf_t *clcf;
    // njt_http_access_rule_t *rule;
    njt_http_complex_value_t  *old_limit_rate;
    njt_int_t rc;
    char *rv;
    njt_conf_t *cf;
    // bool limit_rate_set = false;
    njt_pool_t *pool = NULL;
    njt_str_t *rate;
    njt_str_t *rate_name;

    if(data->limit_rate.len < 1){
        return NJT_OK;
    }

    njt_conf_t cf_data = {
        .cycle = (njt_cycle_t *)njt_cycle,
        .log = njt_cycle->log,
        .ctx = ctx,
    };
    cf = &cf_data;

    //if variable, need check variable table
    rc = njt_dyn_limit_check_var(cf, &data->limit_rate);
    if(rc != NJT_OK){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0,
            "njt_dyn_limit_set_limit_rate var not exist or format error");
        return NJT_ERROR;
    }

    clcf = njt_http_conf_get_module_loc_conf(cf, njt_http_core_module);
    if(clcf == NULL){
		return NJT_ERROR;
	}

    //create dyn pool             
    pool = njt_create_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
    if (pool == NULL)
    {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_limit_set_limit_rate create pool error");
        return NJT_ERROR;
    }
    rc = njt_sub_pool(njt_cycle->pool, pool);
    if (rc != NJT_OK)
    {
        njt_destroy_pool(pool);
        return NJT_ERROR;
    }   

    cf->pool = pool;
    cf->temp_pool = pool;

    old_limit_rate = clcf->limit_rate;
    clcf->limit_rate = NULL;

    //set limit_rate
    //create cf
    cf->args = njt_array_create(pool, 10, sizeof(njt_str_t));
    if (cf->args == NULL) {
        goto err;
    }
 
    rate_name = njt_array_push(cf->args);
    njt_str_set(rate_name, "limit_rate");

    rate = njt_array_push(cf->args);
    rate->len = data->limit_rate.len;
    rate->data = njt_palloc(pool, data->limit_rate.len);
    if(rate->data == NULL){
        goto err;
    }

    njt_memcpy(rate->data, data->limit_rate.data, data->limit_rate.len);

    cf->dynamic = 1;

    //set limit_rate
    rv = njt_http_set_complex_value_size_slot(cf, &limit_rate_cmd, clcf);
    if (rv != NJT_CONF_OK) {
        goto err;
    }

    //destroy old dyn pool
    if(old_limit_rate != NULL && old_limit_rate->dynamic == 1){
        njt_destroy_pool(old_limit_rate->pool);
    }

    return NJT_OK;

err:
    if(pool != NULL){
        njt_destroy_pool(pool);
        pool = NULL;
    }

    clcf->limit_rate = old_limit_rate;

    return NJT_ERROR;
}


static njt_int_t njt_dyn_limit_set_limit_rate_after(njt_http_dyn_limit_loc_t *data, njt_http_conf_ctx_t *ctx)
{
    njt_http_core_loc_conf_t *clcf;
    // njt_http_access_rule_t *rule;
    njt_http_complex_value_t  *old_limit_rate_after;
    njt_int_t rc;
    char *rv;
    njt_conf_t *cf;
    // bool limit_rate_set = false;
    njt_pool_t *pool = NULL;
    njt_str_t *rate_after;
    njt_str_t *rate_after_name;

    if(data->limit_rate_after.len < 1){
        return NJT_OK;
    }

    njt_conf_t cf_data = {
        .cycle = (njt_cycle_t *)njt_cycle,
        .log = njt_cycle->log,
        .ctx = ctx,
    };
    cf = &cf_data;

    //if variable, need check variable table
    rc = njt_dyn_limit_check_var(cf, &data->limit_rate_after);
    if(rc != NJT_OK){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0,
            "njt_dyn_limit_set_limit_rate_after var not exist or format error");
        return NJT_ERROR;
    }

    clcf = njt_http_conf_get_module_loc_conf(cf, njt_http_core_module);
    if(clcf == NULL){
		return NJT_ERROR;
	}

    //create dyn pool             
    pool = njt_create_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
    if (pool == NULL)
    {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_limit_set_limit_rate_after create pool error");
        return NJT_ERROR;
    }
    rc = njt_sub_pool(njt_cycle->pool, pool);
    if (rc != NJT_OK)
    {
        njt_destroy_pool(pool);
        return NJT_ERROR;
    }   

    cf->pool = pool;
    cf->temp_pool = pool;

    old_limit_rate_after = clcf->limit_rate_after;
    clcf->limit_rate_after = NULL;

    //set limit_rate_after
    //create cf
    cf->args = njt_array_create(pool, 10, sizeof(njt_str_t));
    if (cf->args == NULL) {
        goto err;
    }
 
    rate_after_name = njt_array_push(cf->args);
    njt_str_set(rate_after_name, "limit_rate_after");

    rate_after = njt_array_push(cf->args);
    rate_after->len = data->limit_rate_after.len;
    rate_after->data = njt_palloc(pool, data->limit_rate_after.len);
    if(rate_after->data == NULL){
        goto err;
    }

    njt_memcpy(rate_after->data, data->limit_rate_after.data, data->limit_rate_after.len);

    cf->dynamic = 1;

    //set limit_rate_after
    rv = njt_http_set_complex_value_size_slot(cf, &limit_rate_after_cmd, clcf);
    if (rv != NJT_CONF_OK) {
        goto err;
    }

    //destroy old dyn pool
    if(old_limit_rate_after != NULL && old_limit_rate_after->dynamic == 1){
        njt_destroy_pool(old_limit_rate_after->pool);
    }

    return NJT_OK;

err:
    if(pool != NULL){
        njt_destroy_pool(pool);
        pool = NULL;
    }

    clcf->limit_rate_after = old_limit_rate_after;

    return NJT_ERROR;
}


static njt_int_t njt_dyn_limit_set_limit_conn_status(njt_http_dyn_limit_loc_t *data, njt_http_conf_ctx_t *ctx)
{
    njt_conf_t *cf;
    njt_http_limit_conn_conf_t *lccf;

    if(data->limit_conn_status < 1){
        return NJT_OK;
    }

    if(data->limit_conn_status >= 400 &&
       data->limit_conn_status <= 599){

    }else{
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, 
           "njt_dyn_limit_set_limit_conn_status status invalid, shoudld [400, 599]");
        return NJT_ERROR;
    }

    njt_conf_t cf_data = {
        .cycle = (njt_cycle_t *)njt_cycle,
        .log = njt_cycle->log,
        .ctx = ctx,
    };
    cf = &cf_data;

    lccf = njt_http_conf_get_module_loc_conf(cf, njt_http_limit_conn_module);
    if(lccf == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, 
            "njt_dyn_limit_set_limit_conn_status get module config error");
		return NJT_ERROR;
	}

    lccf->status_code = data->limit_conn_status;

 
    return NJT_OK;
}


static njt_int_t njt_dyn_limit_set_limit_req_status(njt_http_dyn_limit_loc_t *data, njt_http_conf_ctx_t *ctx)
{
    njt_conf_t *cf;
    njt_http_limit_req_conf_t *lrcf;

    if(data->limit_req_status < 1){
        return NJT_OK;
    }

    if(data->limit_req_status >= 400 &&
       data->limit_req_status <= 599){

    }else{
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, 
           "njt_dyn_limit_set_limit_req_status status invalid, shoudld [400, 599]");
        return NJT_ERROR;
    }

    njt_conf_t cf_data = {
        .cycle = (njt_cycle_t *)njt_cycle,
        .log = njt_cycle->log,
        .ctx = ctx,
    };
    cf = &cf_data;

    lrcf = njt_http_conf_get_module_loc_conf(cf, njt_http_limit_req_module);
    if(lrcf == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, 
            "njt_dyn_limit_set_limit_req_status get module config error");
		return NJT_ERROR;
	}

    lrcf->status_code = data->limit_req_status;

 
    return NJT_OK;
}


static njt_int_t njt_dyn_limit_set_limit_conn_log_level(njt_http_dyn_limit_loc_t *data, njt_http_conf_ctx_t *ctx)
{
    njt_conf_t *cf;
    njt_http_limit_conn_conf_t *lccf;
    bool found = false;
    njt_conf_enum_t  *e;
    njt_uint_t       i, index;

    if(data->limit_conn_log_level.len < 1){
        return NJT_OK;
    }

    e = njt_http_dyn_limit_conn_log_levels;
    for (i = 0; e[i].name.len != 0; i++) {
        if (e[i].name.len == data->limit_conn_log_level.len
            && njt_strncasecmp(e[i].name.data, data->limit_conn_log_level.data, e[i].name.len) == 0)
        {
            found = true;
            index = i;
            break;
        }
    }

    if(!found){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_limit_set_limit_conn_log_level level error");
        return NJT_ERROR;
    }

    njt_conf_t cf_data = {
        .cycle = (njt_cycle_t *)njt_cycle,
        .log = njt_cycle->log,
        .ctx = ctx,
    };
    cf = &cf_data;

    lccf = njt_http_conf_get_module_loc_conf(cf, njt_http_limit_conn_module);
    if(lccf == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_limit_set_limit_conn_log_level get module config error");
		return NJT_ERROR;
	}

    lccf->log_level = e[index].value;

 
    return NJT_OK;
}


static njt_int_t njt_dyn_limit_set_limit_req_log_level(njt_http_dyn_limit_loc_t *data, njt_http_conf_ctx_t *ctx)
{
    njt_conf_t *cf;
    njt_http_limit_req_conf_t *lrcf;
    bool found = false;
    njt_conf_enum_t  *e;
    njt_uint_t       i, index;

    if(data->limit_req_log_level.len < 1){
        return NJT_OK;
    }

    e = njt_http_dyn_limit_req_log_levels;
    for (i = 0; e[i].name.len != 0; i++) {
        if (e[i].name.len == data->limit_req_log_level.len
            && njt_strncasecmp(e[i].name.data, data->limit_req_log_level.data, e[i].name.len) == 0)
        {
            found = true;
            index = i;
            break;
        }
    }

    if(!found){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_limit_set_limit_req_log_level level error");
        return NJT_ERROR;
    }

    njt_conf_t cf_data = {
        .cycle = (njt_cycle_t *)njt_cycle,
        .log = njt_cycle->log,
        .ctx = ctx,
    };
    cf = &cf_data;

    lrcf = njt_http_conf_get_module_loc_conf(cf, njt_http_limit_req_module);
    if(lrcf == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_limit_set_limit_req_log_level get module config error");
		return NJT_ERROR;
	}

    lrcf->limit_log_level = e[index].value;

    lrcf->delay_log_level = (lrcf->limit_log_level == NJT_LOG_INFO) ?
                                NJT_LOG_INFO : lrcf->limit_log_level + 1;
 
    return NJT_OK;
}


static njt_int_t njt_dyn_limit_set_limit_conn_dry_run(njt_http_dyn_limit_loc_t *data, njt_http_conf_ctx_t *ctx)
{
    njt_conf_t *cf;
    njt_flag_t dry_run;
    njt_http_limit_conn_conf_t *lccf;

    if(data->limit_conn_dry_run.len < 1){
        return NJT_OK;
    }

    if(data->limit_conn_dry_run.len < 2 || data->limit_conn_dry_run.len > 3){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_limit_set_limit_conn_dry_run format error");
        return NJT_ERROR;
    }

    if(data->limit_conn_dry_run.len == 2 &&
            njt_strncasecmp(data->limit_conn_dry_run.data, (u_char *) "on", 2) ==0){
        dry_run = 1;
    }else if (data->limit_conn_dry_run.len == 3 &&
            njt_strncasecmp(data->limit_conn_dry_run.data, (u_char *) "off", 3) == 0) {
        dry_run = 0;
    } else {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_limit_set_limit_conn_dry_run format error");
        return NJT_ERROR;
    }

    njt_conf_t cf_data = {
        .cycle = (njt_cycle_t *)njt_cycle,
        .log = njt_cycle->log,
        .ctx = ctx,
    };
    cf = &cf_data;

    lccf = njt_http_conf_get_module_loc_conf(cf, njt_http_limit_conn_module);
    if(lccf == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_limit_set_limit_conn_dry_run get module config error");
		return NJT_ERROR;
	}

    lccf->dry_run = dry_run;
 
    return NJT_OK;
}


static njt_int_t njt_dyn_limit_set_limit_req_dry_run(njt_http_dyn_limit_loc_t *data, njt_http_conf_ctx_t *ctx)
{
    njt_conf_t *cf;
    njt_flag_t dry_run;
    njt_http_limit_req_conf_t *lrcf;

    if(data->limit_req_dry_run.len < 1){
        return NJT_OK;
    }

    if(data->limit_req_dry_run.len < 2 || data->limit_req_dry_run.len > 3){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_limit_set_limit_req_dry_run format error");
        return NJT_ERROR;
    }

    if(data->limit_req_dry_run.len == 2 &&
            njt_strncasecmp(data->limit_req_dry_run.data, (u_char *) "on", 2) ==0){
        dry_run = 1;
    }else if (data->limit_req_dry_run.len == 3 &&
            njt_strncasecmp(data->limit_req_dry_run.data, (u_char *) "off", 3) == 0) {
        dry_run = 0;
    } else {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_limit_set_limit_req_dry_run format error");
        return NJT_ERROR;
    }

    njt_conf_t cf_data = {
        .cycle = (njt_cycle_t *)njt_cycle,
        .log = njt_cycle->log,
        .ctx = ctx,
    };
    cf = &cf_data;

    lrcf = njt_http_conf_get_module_loc_conf(cf, njt_http_limit_req_module);
    if(lrcf == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_dyn_limit_set_limit_req_dry_run get module config error");
		return NJT_ERROR;
	}

    lrcf->dry_run = dry_run;
 
    return NJT_OK;
}

static njt_int_t njt_dyn_limit_update_rps(njt_cycle_t *cycle, njt_http_dyn_limit_rps_t *rps_date){
    njt_uint_t        i;
    njt_uint_t        index;
    njt_shm_zone_t   *shm_zone;
    njt_list_part_t  *part;
    size_t            len;
    u_char           *p;
    njt_int_t         rate, scale;
    bool             found = false;
    bool             tag_match = true;
    void             *rps_tag = &njt_http_limit_req_module;
    njt_http_limit_req_ctx_t          *req_ctx;

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

        if (rps_date->zone.len != shm_zone[i].shm.name.len) {
            continue;
        }

        if (njt_strncmp(rps_date->zone.data, shm_zone[i].shm.name.data, rps_date->zone.len)
            != 0)
        {
            continue;
        }

        found = true;
        if (rps_tag != shm_zone[i].tag) {
            tag_match = false;
            continue;
        }

        index = i;
        break;
    }

    if(!found){
        njt_log_error(NJT_LOG_ERR, cycle->log, 0, " update rps zone:%V  is not exist", &rps_date->zone);
        return NJT_ERROR;
    }

    if(!tag_match){
        njt_log_error(NJT_LOG_ERR, cycle->log, 0, " update rps zone:%V  tag error", &rps_date->zone);
        return NJT_ERROR;
    }

    rate = 1;
    scale = 1;
    len = rps_date->rate.len;
    p = rps_date->rate.data + len - 3;
    if (njt_strncmp(p, "r/s", 3) == 0) {
        scale = 1;
        len -= 3;

    } else if (njt_strncmp(p, "r/m", 3) == 0) {
        scale = 60;
        len -= 3;
    }

    rate = njt_atoi(rps_date->rate.data, len);
    if (rate <= 0) {
        njt_log_error(NJT_LOG_ERR, cycle->log, 0, " update rps zone:%V  rate error", &rps_date->zone);
        return NJT_ERROR;
    }

    req_ctx = shm_zone[index].data;
    if(req_ctx == NULL){
        njt_log_error(NJT_LOG_EMERG, cycle->log, 0, " update rps zone:%V  zone data is null", &rps_date->zone);
        return NJT_ERROR;
    }

    req_ctx->rate = rate * 1000 / scale;
    req_ctx->ori_rate = rate;
    req_ctx->scale = scale;

    return NJT_OK;
}

static njt_int_t njt_dyn_limit_update_locs(njt_array_t *locs, njt_queue_t *q, njt_http_conf_ctx_t *ctx)
{
    njt_http_core_loc_conf_t *clcf;
    njt_http_location_queue_t *hlq;
    njt_http_dyn_limit_loc_t *dbwl;
    njt_uint_t j;
    njt_queue_t *tq;
    njt_int_t rc;

    if (q == NULL)
    {
        return NJT_OK;
    }

    dbwl = locs->elts;

    for (j = 0; j < locs->nelts; ++j)
    {
        tq = njt_queue_head(q);
        for (; tq != njt_queue_sentinel(q); tq = njt_queue_next(tq))
        {
            hlq = njt_queue_data(tq, njt_http_location_queue_t, queue);
            clcf = hlq->exact == NULL ? hlq->inclusive : hlq->exact;

            njt_str_t name = dbwl[j].full_name;
            if (name.len == clcf->full_name.len && njt_strncmp(name.data, clcf->full_name.data, name.len) == 0)
            {
                ctx->loc_conf = clcf->loc_conf;
                njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "dynlimit start set location:%V", &clcf->full_name);
                
                //set limit_conns
                rc = njt_dyn_limit_set_limit_conns(&dbwl[j], ctx);
                if (rc != NJT_OK)
                {
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "error in njt_dyn_limit_set_limit_conns");
                }

                //set limit_reqs
                rc = njt_dyn_limit_set_limit_reqs(&dbwl[j], ctx);
                if (rc != NJT_OK)
                {
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "error in njt_dyn_limit_set_limit_reqs");
                }
                
                //set limit_rate
                rc = njt_dyn_limit_set_limit_rate(&dbwl[j], ctx);
                if (rc != NJT_OK)
                {
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " error in njt_dyn_limit_set_limit_rate");
                }

                //set limit_rate_after
                rc = njt_dyn_limit_set_limit_rate_after(&dbwl[j], ctx);
                if (rc != NJT_OK)
                {
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " error in njt_dyn_limit_set_limit_rate_after");
                }

                //set limit_conn_dry_run
                rc = njt_dyn_limit_set_limit_conn_dry_run(&dbwl[j], ctx);
                if (rc != NJT_OK)
                {
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " error in njt_dyn_limit_set_limit_conn_dry_run");
                }

                //set limit_req_dry_run
                rc = njt_dyn_limit_set_limit_req_dry_run(&dbwl[j], ctx);
                if (rc != NJT_OK)
                {
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " error in njt_dyn_limit_set_limit_req_dry_run");
                }  

                //set limit_conn_log_level
                rc = njt_dyn_limit_set_limit_conn_log_level(&dbwl[j], ctx);
                if (rc != NJT_OK)
                {
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " error in njt_dyn_limit_set_limit_conn_log_level");
                }

                //set limit_req_log_level
                rc = njt_dyn_limit_set_limit_req_log_level(&dbwl[j], ctx);
                if (rc != NJT_OK)
                {
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " error in njt_dyn_limit_set_limit_req_log_level");
                }

                //set limit_conn_status
                rc = njt_dyn_limit_set_limit_conn_status(&dbwl[j], ctx);
                if (rc != NJT_OK)
                {
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " error in njt_dyn_limit_set_limit_conn_status");
                }

                //set limit_req_status
                rc = njt_dyn_limit_set_limit_req_status(&dbwl[j], ctx);
                if (rc != NJT_OK)
                {
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " error in njt_dyn_limit_set_limit_req_status");
                }
            }

            if (dbwl[j].locs.nelts > 0)
            {
                njt_dyn_limit_update_locs(&dbwl[j].locs, clcf->old_locations, ctx);
            }
        }
    }

    return NJT_OK;
}

static njt_json_element *njt_dyn_limit_dump_locs_json(njt_pool_t *pool, njt_queue_t *locations)
{
    njt_http_core_loc_conf_t      *clcf;
    njt_http_location_queue_t     *hlq;
    njt_queue_t                   *q, *tq;
    njt_http_limit_conn_conf_t    *lccf;
    njt_http_limit_req_conf_t     *lrcf;
    njt_json_element              *locs, *item, *sub;
    njt_json_element              *limit_conn, *zone, *conn;
    njt_str_t                      tmpstr;
    njt_conf_enum_t               *e;
    njt_uint_t                     i;
    njt_http_limit_conn_limit_t   *conn_limits;
    njt_http_limit_req_limit_t    *req_limits;
    njt_json_element *             burst_ele;
    njt_json_element *             delay_ele;
    njt_uint_t                     delay;
    njt_uint_t                     delay_max_comp;
    njt_str_t                      delay_str;
    u_char                        *p; 
    njt_int_t                      delay_max_len = 100;

    // njt_http_access_rule_t *rule;

    if (locations == NULL)
    {
        return NULL;
    }

    locs = NULL;
    q = locations;
    if (njt_queue_empty(q))
    {
        return NULL;
    }

    tq = njt_queue_head(q);
    locs = njt_json_arr_element(pool, njt_json_fast_key("locations"));
    if (locs == NULL)
    {
        return NULL;
    }

    for (; tq != njt_queue_sentinel(q); tq = njt_queue_next(tq))
    {
        hlq = njt_queue_data(tq, njt_http_location_queue_t, queue);
        clcf = hlq->exact == NULL ? hlq->inclusive : hlq->exact;
        if(clcf == NULL){
            continue;
        }

        lccf = njt_http_get_module_loc_conf(clcf, njt_http_limit_conn_module);
        lrcf = njt_http_get_module_loc_conf(clcf, njt_http_limit_req_module);

        item = njt_json_obj_element(pool, njt_json_null_key);
        if (item == NULL)
        {
            return NULL;
        }

        sub = njt_json_str_element(pool, njt_json_fast_key("location"), &clcf->full_name);
        if (sub == NULL)
        {
            return NULL;
        }
        njt_struct_add(item, sub, pool);

        if(clcf->limit_rate){
            sub = njt_json_str_element(pool, njt_json_fast_key("limit_rate"), &clcf->limit_rate->value);
        }else{
            sub = njt_json_str_element(pool, njt_json_fast_key("limit_rate"), NULL);
        }
        if (sub == NULL)
        {
            return NULL;
        }
        njt_struct_add(item, sub, pool);

        if(clcf->limit_rate_after){
            sub = njt_json_str_element(pool, njt_json_fast_key("limit_rate_after"), &clcf->limit_rate_after->value);
        }else{
            sub = njt_json_str_element(pool, njt_json_fast_key("limit_rate_after"), NULL);
        }
        if (sub == NULL)
        {
            return NULL;
        }
        njt_struct_add(item, sub, pool);

        if(lccf != NULL)
        {
            if(lccf->from_up == 1){
                njt_str_set(&tmpstr, "up_share");
            }else{
                njt_str_set(&tmpstr, "location");
            }
            
            sub = njt_json_str_element(pool, njt_json_fast_key("limit_conns_scope"), &tmpstr);
            if(sub == NULL){
                return NULL;
            }
            njt_struct_add(item,sub,pool);

            sub = njt_json_arr_element(pool, njt_json_fast_key("limit_conns"));
            if(sub == NULL){
                return NULL;
            }
            njt_struct_add(item,sub,pool);

            if(lccf->limits.nelts > 0){
                conn_limits = lccf->limits.elts;
                for (i = 0; i < lccf->limits.nelts; i++) {
                    limit_conn = njt_json_obj_element(pool, njt_json_null_key);
                    if(limit_conn == NULL){
                        return NULL;
                    }
                    njt_struct_add(sub,limit_conn,pool);

                    zone = njt_json_str_element(pool, njt_json_fast_key("zone"), &conn_limits[i].shm_zone->shm.name);
                    if(sub == NULL){
                        return NULL;
                    }
                    njt_struct_add(limit_conn,zone,pool);

                    conn = njt_json_int_element(pool, njt_json_fast_key("conn"), conn_limits[i].conn);
                    if(sub == NULL){
                        return NULL;
                    }
                    njt_struct_add(limit_conn,conn,pool);
                }
            }


            if(lccf->dry_run == 1){
                njt_str_set(&tmpstr, "on");
            }else{
                njt_str_set(&tmpstr, "off");      
            }
            sub = njt_json_str_element(pool, njt_json_fast_key("limit_conn_dry_run"), &tmpstr);

            if(sub == NULL){
                return NULL;
            }
            njt_struct_add(item,sub,pool);

            e = njt_http_dyn_limit_conn_log_levels;
            for (i = 0; e[i].name.len != 0; i++) {
                if(lccf->log_level == e[i].value){
                    tmpstr = e[i].name;
                    sub = njt_json_str_element(pool, njt_json_fast_key("limit_conn_log_level"), &tmpstr);
                    if(sub == NULL){
                        return NULL;
                    }
                    njt_struct_add(item,sub,pool);
                    break;
                }
            }

            sub = njt_json_int_element(pool, njt_json_fast_key("limit_conn_status"), lccf->status_code);
            if(sub == NULL){
                return NULL;
            }
            njt_struct_add(item,sub,pool);
        }

        if(lrcf != NULL)
        {
            if(lrcf->from_up == 1){
                njt_str_set(&tmpstr, "up_share");
            }else{
                njt_str_set(&tmpstr, "location");
            }
            
            sub = njt_json_str_element(pool, njt_json_fast_key("limit_reqs_scope"), &tmpstr);
            if(sub == NULL){
                return NULL;
            }
            njt_struct_add(item,sub,pool);

            sub = njt_json_arr_element(pool, njt_json_fast_key("limit_reqs"));
            if(sub == NULL){
                return NULL;
            }
            njt_struct_add(item,sub,pool);

            if(lrcf->limits.nelts > 0){
                req_limits = lrcf->limits.elts;
                for (i = 0; i < lrcf->limits.nelts; i++) {
                    limit_conn = njt_json_obj_element(pool, njt_json_null_key);
                    if(limit_conn == NULL){
                        return NULL;
                    }
                    njt_struct_add(sub,limit_conn,pool);

                    zone = njt_json_str_element(pool, njt_json_fast_key("zone"), &req_limits[i].shm_zone->shm.name);
                    if(sub == NULL){
                        return NULL;
                    }
                    njt_struct_add(limit_conn,zone,pool);

                    burst_ele = njt_json_int_element(pool, njt_json_fast_key("burst"), req_limits[i].burst / 1000);
                    if(sub == NULL){
                        return NULL;
                    }
                    njt_struct_add(limit_conn, burst_ele, pool);
                   
                    delay_max_comp = NJT_MAX_INT_T_VALUE / 1000;
                    delay_max_comp *= 1000;
                    if(req_limits[i].delay == delay_max_comp){
                        njt_str_set(&delay_str, "nodelay");
                    }else{
                        delay = req_limits[i].delay / 1000;

                        delay_str.data = njt_palloc(pool, delay_max_len);
                        njt_memzero(delay_str.data, delay_max_len);
                        p = njt_snprintf(delay_str.data, delay_max_len, "%d", delay);
                        delay_str.len = p - delay_str.data;       
                    }

                    delay_ele = njt_json_str_element(pool, njt_json_fast_key("delay"), &delay_str);
                    if(sub == NULL){
                        return NULL;
                    }
                    njt_struct_add(limit_conn, delay_ele, pool);
                }
            }

            if(lrcf->dry_run == 1){
                njt_str_set(&tmpstr, "on");
                
            }else{
                njt_str_set(&tmpstr, "off");          
            }
            sub = njt_json_str_element(pool, njt_json_fast_key("limit_req_dry_run"), &tmpstr);
            if(sub == NULL){
                return NULL;
            }
            njt_struct_add(item,sub,pool);

            e = njt_http_dyn_limit_req_log_levels;
            for (i = 0; e[i].name.len != 0; i++) {
                if(lrcf->limit_log_level == e[i].value){
                    tmpstr = e[i].name;
                    sub = njt_json_str_element(pool, njt_json_fast_key("limit_req_log_level"), &tmpstr);
                    if(sub == NULL){
                        return NULL;
                    }
                    njt_struct_add(item,sub,pool);
                    break;
                }
            }

            sub = njt_json_int_element(pool, njt_json_fast_key("limit_req_status"), lrcf->status_code);
            if(sub == NULL){
                return NULL;
            }
            njt_struct_add(item,sub,pool);
        }

        sub = njt_dyn_limit_dump_locs_json(pool, clcf->old_locations);
        if (sub != NULL)
        {
            njt_struct_add(item, sub, pool);
        }

        njt_struct_add(locs, item, pool);
    }

    return locs;
}

static njt_str_t njt_dyn_limit_dump_limit_conf(njt_cycle_t *cycle, njt_pool_t *pool)
{
    njt_http_core_loc_conf_t *clcf;
    njt_http_core_main_conf_t *hcmcf;
    njt_http_core_srv_conf_t **cscfp;
    njt_uint_t i, j;
    njt_int_t rc;
    njt_array_t *array;
    njt_str_t json, *tmp_str, rate_str;
    njt_http_server_name_t *server_name;
    njt_json_manager json_manager;
    njt_json_element *srvs, *srv, *subs, *sub;
    njt_json_element *rpses, *rps;
    njt_list_part_t  *part;
    njt_int_t        tmp_rate;
    njt_shm_zone_t   *shm_zone;
    u_char           *p; 
    njt_http_limit_req_ctx_t          *req_ctx;
    void             *rps_tag = &njt_http_limit_req_module;
    njt_int_t        rate_max_len = 100;


    njt_memzero(&json_manager, sizeof(njt_json_manager));
    hcmcf = njt_http_cycle_get_module_main_conf(cycle, njt_http_core_module);

    srvs = njt_json_arr_element(pool, njt_json_fast_key("servers"));
    if (srvs == NULL)
    {
        goto err;
    }

    cscfp = hcmcf->servers.elts;
    for (i = 0; i < hcmcf->servers.nelts; i++)
    {
        array = njt_array_create(pool, 4, sizeof(njt_str_t));
        njt_http_get_listens_by_server(array, cscfp[i]);

        srv = njt_json_obj_element(pool, njt_json_null_key);
        if (srv == NULL)
        {
            goto err;
        }

        subs = njt_json_arr_element(pool, njt_json_fast_key("listens"));
        if (subs == NULL)
        {
            goto err;
        }

        tmp_str = array->elts;
        for (j = 0; j < array->nelts; ++j)
        {
            sub = njt_json_str_element(pool, njt_json_null_key, &tmp_str[j]);
            if (sub == NULL)
            {
                goto err;
            }
            njt_struct_add(subs, sub, pool);
        }
        njt_struct_add(srv, subs, pool);
        subs = njt_json_arr_element(pool, njt_json_fast_key("serverNames"));
        if (subs == NULL)
        {
            goto err;
        }

        server_name = cscfp[i]->server_names.elts;
        for (j = 0; j < cscfp[i]->server_names.nelts; ++j)
        {
            sub = njt_json_str_element(pool, njt_json_null_key, &server_name[j].name);
            if (sub == NULL)
            {
                goto err;
            }
            njt_struct_add(subs, sub, pool);
        }

        njt_struct_add(srv, subs, pool);
        clcf = njt_http_get_module_loc_conf(cscfp[i]->ctx, njt_http_core_module);
        subs = njt_dyn_limit_dump_locs_json(pool, clcf->old_locations);

        if (subs != NULL)
        {
            njt_struct_add(srv, subs, pool);
        }

        njt_struct_add(srvs, srv, pool);
    }

    rc = njt_struct_top_add(&json_manager, srvs, NJT_JSON_OBJ, pool);
    if (rc != NJT_OK)
    {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                      "njt_struct_top_add error");
    }

    rpses = njt_json_arr_element(pool, njt_json_fast_key("limit_rps"));
    if (rpses == NULL)
    {
        goto err;
    }

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

        if (rps_tag != shm_zone[i].tag) {
            continue;
        }

        rps = njt_json_obj_element(pool, njt_json_null_key);
        if (rps == NULL)
        {
            goto err;
        }
        njt_struct_add(rpses, rps, pool);

        sub = njt_json_str_element(pool, njt_json_fast_key("zone"), &shm_zone[i].shm.name);
        if (sub == NULL)
        {
            goto err;
        }
        njt_struct_add(rps, sub, pool);

        req_ctx = shm_zone[i].data;
        if(req_ctx == NULL){
            njt_str_set(&rate_str, "0r/s");
        }else{
            tmp_rate = req_ctx->ori_rate;
            rate_str.data = njt_palloc(pool, rate_max_len);
            njt_memzero(rate_str.data, rate_max_len);
            if(60 == req_ctx->scale){
                p = njt_snprintf(rate_str.data, rate_max_len, "%dr/m", tmp_rate);
            }else{
                p = njt_snprintf(rate_str.data, rate_max_len, "%dr/s", tmp_rate);
            }

            rate_str.len = p - rate_str.data;
        }

        sub = njt_json_str_element(pool, njt_json_fast_key("rate"), &rate_str);
        if (sub == NULL)
        {
            goto err;
        }
        njt_struct_add(rps, sub, pool);
    }

    rc = njt_struct_top_add(&json_manager, rpses, NJT_JSON_OBJ, pool);
    if (rc != NJT_OK)
    {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                    "njt_struct_top_add rpses error");
    }

    njt_memzero(&json, sizeof(njt_str_t));
    njt_structure_2_json(&json_manager, &json, pool);

    return json;

err:
    return dyn_limit_update_srv_err_msg;
}

static njt_int_t njt_dyn_limit_update_limit_conf(njt_pool_t *pool, njt_http_dyn_limit_main_t *api_data)
{
    njt_cycle_t              *cycle, *new_cycle;
    njt_http_core_srv_conf_t *cscf;
    njt_http_core_loc_conf_t *clcf;
    njt_http_dyn_limit_srv_t *daas;
    njt_http_dyn_limit_rps_t *rps_datas;
    njt_str_t                *p_port, *p_sname;
    njt_uint_t                i;
    njt_int_t                 rc;
    if (njt_process == NJT_PROCESS_HELPER)
    {
        new_cycle = (njt_cycle_t *)njt_cycle;
        cycle = new_cycle->old_cycle;
    }
    else
    {
        cycle = (njt_cycle_t *)njt_cycle;
    }

    //update rps
    rps_datas = api_data->limit_rps.elts;
    for(i = 0; i < api_data->limit_rps.nelts; ++i){
        if(rps_datas[i].zone.len < 1 || rps_datas[i].rate.len < 3){
        njt_log_error(NJT_LOG_INFO, pool->log, 0, "update limit rps error, format invalid, zone:%V  rate:%V",
                &rps_datas[i].zone, &rps_datas[i].rate);
            continue;
        }
        rc = njt_dyn_limit_update_rps(cycle, &rps_datas[i]);
        if(rc != NJT_OK){
            njt_log_error(NJT_LOG_INFO, pool->log, 0, "update limit rps error, zone:%V",
                &rps_datas[i].zone);
        }
    }

    daas = api_data->servers.elts;
    for (i = 0; i < api_data->servers.nelts; ++i)
    {
        p_port = (njt_str_t *)daas[i].listens.elts;
        p_sname = (njt_str_t *)daas[i].server_names.elts;
        if (p_port == NULL || p_sname == NULL)
        {
            njt_log_error(NJT_LOG_INFO, pool->log, 0, "listen or server_name is NULL, just continue");
            continue;
        }
        cscf = njt_http_get_srv_by_port(cycle, p_port, p_sname);
        if (cscf == NULL)
        {
            njt_log_error(NJT_LOG_INFO, pool->log, 0, "can`t find server by listen:%V server_name:%V ",
                          p_port, p_sname);
            continue;
        }

        njt_log_error(NJT_LOG_INFO, pool->log, 0, "dynlimit start update listen:%V server_name:%V",
                p_port, p_sname);
        njt_http_conf_ctx_t ctx = *cscf->ctx;
        clcf = njt_http_get_module_loc_conf(cscf->ctx, njt_http_core_module);
        rc = njt_dyn_limit_update_locs(&daas[i].locs, clcf->old_locations, &ctx);
        if(rc != NJT_OK){
            njt_log_error(NJT_LOG_INFO, pool->log, 0, "update limit error, listen:%V server_name:%V",
                p_port, p_sname);
        }
    }

    return NJT_OK;
}

static u_char *njt_dyn_limit_rpc_handler(njt_str_t *topic, njt_str_t *request, int *len, void *data)
{
    njt_cycle_t *cycle;
    njt_str_t msg;
    u_char *buf;
    njt_pool_t *pool = NULL;

    buf = NULL;
    cycle = (njt_cycle_t *)njt_cycle;
    *len = 0;

    pool = njt_create_pool(njt_pagesize, njt_cycle->log);
    if (pool == NULL)
    {
        njt_log_error(NJT_LOG_EMERG, pool->log, 0, "njt_dyn_limit_rpc_handler create pool error");
        goto out;
    }

    msg = njt_dyn_limit_dump_limit_conf(cycle, pool);
    buf = njt_calloc(msg.len, cycle->log);
    if (buf == NULL)
    {
        goto out;
    }

    njt_log_error(NJT_LOG_INFO, pool->log, 0, "send json : %V", &msg);
    njt_memcpy(buf, msg.data, msg.len);
    *len = msg.len;

out:
    if (pool != NULL)
    {
        njt_destroy_pool(pool);
    }

    return buf;
}

static int njt_dyn_limit_change_handler(njt_str_t *key, njt_str_t *value, void *data)
{
    njt_int_t rc;
    njt_http_dyn_limit_main_t *api_data = NULL;
    njt_pool_t *pool = NULL;

    if (value->len < 2)
    {
        return NJT_OK;
    }

    pool = njt_create_pool(njt_pagesize, njt_cycle->log);
    if (pool == NULL)
    {
        njt_log_error(NJT_LOG_EMERG, pool->log, 0, "njt_dyn_limit_change_handler create pool error");
        return NJT_OK;
    }

    api_data = njt_pcalloc(pool, sizeof(njt_http_dyn_limit_main_t));
    if (api_data == NULL)
    {
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, pool->log, 0,
                       "could not alloc buffer in function %s", __func__);
        goto out;
    }

    rc = njt_json_parse_data(pool, value, njt_http_dyn_limit_main_json_dt, api_data);
    if (rc == NJT_OK)
    {
        rc = njt_dyn_limit_update_limit_conf(pool, api_data);
    }

    if (rc != NJT_OK) {
        njt_str_t topic=njt_string("/dyn/http_dyn_limit");
        njt_str_t msg=njt_string("");
        njt_kv_sendmsg(&topic,&msg, 1);
    }

out:
    if (pool != NULL)
    {
        njt_destroy_pool(pool);
    }

    return NJT_OK;
}

static njt_int_t njt_http_dyn_limit_module_init_process(njt_cycle_t *cycle)
{
    njt_str_t limit_rpc_key = njt_string("http_dyn_limit");

    njt_reg_kv_change_handler(&limit_rpc_key, njt_dyn_limit_change_handler, njt_dyn_limit_rpc_handler, NULL);

    return NJT_OK;
}

static njt_http_module_t njt_http_dyn_limit_module_ctx = {
    NULL, /* preconfiguration */
    NULL, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    NULL, /* create location configuration */
    NULL  /* merge location configuration */
};

njt_module_t njt_http_dyn_limit_module = {
    NJT_MODULE_V1,
    &njt_http_dyn_limit_module_ctx,         /* module context */
    NULL,                                    /* module directives */
    NJT_HTTP_MODULE,                         /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    njt_http_dyn_limit_module_init_process, /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NJT_MODULE_V1_PADDING};
