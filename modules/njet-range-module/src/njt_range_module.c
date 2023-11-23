/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */
#include <njt_core.h>
#include "njt_range_module.h"


static void *njt_range_module_create_conf(njt_cycle_t *cycle);
static char *njt_range(njt_conf_t *cf, njt_command_t *cmd, void *conf);

static njt_int_t njt_range_init_process(njt_cycle_t *cycle);
static void njt_range_exit_process(njt_cycle_t *cycle);



static njt_command_t  njt_range_commands[] = {

    { njt_string("range"),
      NJT_MAIN_CONF|NJT_DIRECT_CONF|NJT_CONF_ANY,
      njt_range,
      0,
      0,
      NULL },

      njt_null_command
};


static njt_core_module_t  njt_range_module_ctx = {
    njt_string("range"),
    njt_range_module_create_conf,
    NULL
};

njt_module_t  njt_range_module = {
    NJT_MODULE_V1,
    &njt_range_module_ctx,               /* module context */
    njt_range_commands,                  /* module directives */
    NJT_CORE_MODULE,                            /* module type */
    NULL,                                       /* init master */
    NULL,                                       /* init module */
    njt_range_init_process,                 /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    njt_range_exit_process,                /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};


static void *
njt_range_module_create_conf(njt_cycle_t *cycle)
{
    njt_range_conf_t    *rcf;
    njt_str_t           tmp_str;

    rcf = njt_pcalloc(cycle->pool, sizeof(njt_range_conf_t));
    if (rcf == NULL) {
        return NULL;
    }

    rcf->pool = NJT_CONF_UNSET_PTR;
    njt_queue_init(&rcf->ranges);
    njt_str_set(&tmp_str, NJT_IPTABLES_PATH);

    rcf->iptables_path.len = tmp_str.len;
    njt_memcpy(rcf->iptables_path.path, tmp_str.data, tmp_str.len);

    rcf->try_del_times = 3;
    // rcf->try_del_times = 0;

    return rcf;
}


static char *
njt_range(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_str_t                   *value;
    njt_range_conf_t            *rcf;
    njt_uint_t                  i;
    njt_range_rule_t            rule;
    njt_range_rule_t            *rule_item;
    u_char                      *p;
    njt_int_t                   tmp_value;
    njt_int_t                   left_value, right_value, left_len, right_len;


    rcf = (njt_range_conf_t *) conf;

    value = cf->args->elts;

    njt_str_set(&rule.type, "tcp");
    njt_str_null(&rule.src_ports);
    rule.dst_port = 0;
    

    for (i = 1; i < cf->args->nelts; i++) {
        if (njt_strncmp(value[i].data, "type=", 5) == 0) {
            if (value[i].len == 5) {
                goto invalid;
            }

            value[i].data += 5;
            value[i].len -= 5;

            if(njt_strncmp(value[i].data, "tcp", 3) == 0) {
                njt_str_set(&rule.type, "tcp");
            }else if(njt_strncmp(value[i].data, "udp", 3) == 0) {
                njt_str_set(&rule.type, "udp");
            }else{
                return "range type should be tcp or udp";
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "dst_port=", 9) == 0) {
            if (value[i].len == 9) {
                goto invalid;
            }

            value[i].data += 9;
            value[i].len -= 9;

            rule.dst_port = njt_atoi(value[i].data, value[i].len);
            if (rule.dst_port < 1) {
                return "range dst_port should be int and more than 0";
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "try_del_times=", 14) == 0) {
            if (value[i].len == 14) {
                continue;
            }

            value[i].data += 14;
            value[i].len -= 14;

            rcf->try_del_times = njt_atoi(value[i].data, value[i].len);
            if (rcf->try_del_times < 1) {
                rcf->try_del_times = 0;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "iptables_path=", 14) == 0) {
            if (value[i].len == 14) {
                continue;
            }

            value[i].data += 14;
            value[i].len -= 14;

            if(value[i].len > IPTABLES_PATH_LEN){
                value[i].len = IPTABLES_PATH_LEN;
            }

            if (value[i].len  == rcf->iptables_path.len && njt_strncmp(value[i].data, NJT_IPTABLES_PATH, value[i].len) == 0){
            }else{
                rcf->iptables_path.len = value[i].len;
                njt_memcpy(rcf->iptables_path.path, value[i].data, value[i].len);
            }

            continue;
        }


        if (njt_strncmp(value[i].data, "src_ports=", 10) == 0) {
            if (value[i].len == 10) {
                goto invalid;
            }

            value[i].data += 10;
            value[i].len -= 10;

            //check valid
            p = (u_char *) njt_strchr(value[i].data, ':');
            if (p == NULL) {
                tmp_value = njt_atoi(value[i].data, value[i].len);
                if (tmp_value < 1) {
                    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                            "range src_ports not valid:\"%V\"", &value[i]);
                    return NJT_CONF_ERROR;
                }
            }else{
                left_len = p - value[i].data;
                right_len = value[i].len - left_len - 1;
                if(left_len < 1 || right_len < 1){
                    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                            "range src_ports not valid:\"%V\"", &value[i]);
                    return NJT_CONF_ERROR;
                }

                //check left value
                left_value = njt_atoi(value[i].data, left_len);
                if (left_value < 1) {
                    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                            "range src_ports not valid:\"%V\"", &value[i]);
                    return NJT_CONF_ERROR;
                }

                //check right value
                right_value = njt_atoi(p+1, right_len);
                if (right_value < 1) {
                    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                            "range src_ports not valid:\"%V\"", &value[i]);
                    return NJT_CONF_ERROR;
                }
            }

            rule.src_ports = value[i];

            continue;
        }           
    }

    if(rule.src_ports.len == 0 || rule.dst_port == 0){
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                "range src_ports and dst_port must set");
        return NJT_CONF_ERROR;
    }

    if(rcf->pool == NJT_CONF_UNSET_PTR){
        rcf->pool = njt_create_dynamic_pool(njt_pagesize, cf->log);
        if (rcf->pool == NULL || NJT_OK != njt_sub_pool(cf->pool, rcf->pool)) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                    "range create dynamic pool error");
            return NJT_CONF_ERROR;
        }
    }

    //create range rule in pool
    rule_item = njt_pcalloc(rcf->pool, sizeof(njt_range_rule_t));
    if(rule_item == NULL){
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                "range malloc rule error");
        return NJT_CONF_ERROR;  
    }
    rule_item->dst_port = rule.dst_port;
    rule_item->type = rule.type;
    rule_item->src_ports.len = rule.src_ports.len;
    rule_item->src_ports.data = njt_pcalloc(rcf->pool, rule.src_ports.len);
    if(rule_item->src_ports.data == NULL){
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                "range malloc rule src_ports error");
        return NJT_CONF_ERROR;  
    }
    njt_memcpy(rule_item->src_ports.data, rule.src_ports.data, rule.src_ports.len);

    njt_queue_insert_tail(&rcf->ranges, &rule_item->range_queue);

    return NJT_CONF_OK;

invalid:

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\"", &value[i]);

    return NJT_CONF_ERROR;
}



njt_int_t njt_range_init_process(njt_cycle_t *cycle){
    njt_range_conf_t                *rcf;
    njt_queue_t                     *q;
    njt_range_rule_t                *rule_item;
    njt_uint_t                       i = 0;
    njt_str_t                       tmp_path;
    uid_t                           uid = 0;


    if(njt_process != NJT_PROCESS_HELPER){
        return NJT_OK;
    }

    rcf = (njt_range_conf_t *)njt_get_conf(cycle->conf_ctx, njt_range_module);    
    if(rcf == NULL){
        return NJT_OK;
    }

    //setuid
    setuid(uid);

    //update rcf->pool->log = cycle_log
    if(rcf->pool != NJT_CONF_UNSET_PTR){
        rcf->pool->log = cycle->log;
    }

    tmp_path.data = rcf->iptables_path.path;
    tmp_path.len = rcf->iptables_path.len;

    q = njt_queue_head(&rcf->ranges);
    for (; q != njt_queue_sentinel(&rcf->ranges); q = njt_queue_next(q)) {
        rule_item = njt_queue_data(q, njt_range_rule_t, range_queue);
        //try delete some times 
        for(i = 0; i < rcf->try_del_times; i++){
            njt_range_del_rule(&tmp_path, &rule_item->type, &rule_item->src_ports, rule_item->dst_port);
        }

        if(NJT_OK != njt_range_add_rule(&tmp_path, &rule_item->type, &rule_item->src_ports, rule_item->dst_port)){
            njt_log_error(NJT_LOG_DEBUG, cycle->log, 0,
                    "range add rule error, type:%V  src_ports:%V  dst_port:%d",
                    &rule_item->type, &rule_item->src_ports, rule_item->dst_port);
            continue;
        }
    }

    return NJT_OK;
}


static void njt_range_exit_process(njt_cycle_t *cycle){
    njt_range_conf_t                *rcf;
    njt_queue_t                     *q;
    njt_range_rule_t                *rule_item;
    njt_str_t                       tmp_path;


    if(njt_process != NJT_PROCESS_HELPER){
        return;
    }

    rcf = (njt_range_conf_t *)njt_get_conf(cycle->conf_ctx, njt_range_module);    
    if(rcf == NULL){
        return;
    }

    tmp_path.data = rcf->iptables_path.path;
    tmp_path.len = rcf->iptables_path.len;

    q = njt_queue_head(&rcf->ranges);
    for (; q != njt_queue_sentinel(&rcf->ranges); q = njt_queue_next(q)) {
        rule_item = njt_queue_data(q, njt_range_rule_t, range_queue);

        if(NJT_OK != njt_range_del_rule(&tmp_path, &rule_item->type, &rule_item->src_ports, rule_item->dst_port)){
            njt_log_error(NJT_LOG_DEBUG, cycle->log, 0,
                    "range add rule error, type:%V  src_ports:%V  dst_port:%d",
                    &rule_item->type, &rule_item->src_ports, rule_item->dst_port);
            continue;
        }
    }

    return;
}



njt_int_t njt_range_add_rule(njt_str_t *iptables_path, njt_str_t *type, njt_str_t *src_ports, njt_uint_t dst_port){
    u_char          buf[1024];
    int             ret;
    u_char          *end;
    njt_str_t       tmp_str;


    njt_memzero(buf, 1024);
    end = njt_snprintf(buf, 1024, NJT_RANG_ADD_RULE, iptables_path, src_ports, dst_port);
    tmp_str.data = buf;
    tmp_str.len = end - buf;


    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
            "range add rule:%V", &tmp_str);


    ret = system((char *)buf);
    if(0 != ret){
        return NJT_ERROR;
    }

    return NJT_OK;
}


njt_int_t njt_range_del_rule(njt_str_t *iptables_path, njt_str_t *type, njt_str_t *src_ports, njt_uint_t dst_port){
    u_char          buf[1024];
    int             ret;
    u_char          *end;
    njt_str_t       tmp_str;


    njt_memzero(buf, 1024);
    end = njt_snprintf(buf, 1024, NJT_RANG_DEL_RULE, iptables_path, src_ports, dst_port);
    tmp_str.data = buf;
    tmp_str.len = end - buf;

    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
            "range del rule:%V", &tmp_str);

    ret = system((char *)buf);
    if(0 != ret){
        return NJT_ERROR;
    }

    return NJT_OK;
}
