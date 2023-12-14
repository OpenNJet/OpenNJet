/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */
#include <njt_core.h>
#include "njt_range_module.h"


#define NJT_IPTABLES_PATH   "/usr/sbin/iptables"

//chain
#define NJT_RANG_CREATE_CHAIN   "%V -t nat -N OPENNJET"
#define NJT_RANG_REMOVE_CHAIN   "%V -t nat -X OPENNJET"
#define NJT_RANG_CLEAR_CHAIN   "%V -t nat -F OPENNJET"

//rule
#define NJT_RANG_ADD_RULE   "%V -t nat -I OPENNJET -p tcp --dport %V -j REDIRECT --to-port %d"
#define NJT_RANG_DEL_RULE   "%V -t nat -D OPENNJET -p tcp --dport %V -j REDIRECT --to-port %d"

//map nat chain
#define NJT_RANG_MAP_NAT_CHAIN   "%V -t nat -I PREROUTING -j OPENNJET"
#define NJT_RANG_GET_NAT_CHAIN "%V --line -t nat -nvL|grep OPENNJET| grep -v Chain | awk '{print $1}'"
#define NJT_RANG_DEL_MAP_NAT_CHAIN   "%V -t nat -D PREROUTING %V"


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
        if (njt_strncmp(value[i].data, "iptables_path=", 14) == 0) {
            if (value[i].len == 14) {
                goto invalid;
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

            return NJT_CONF_OK;
        }

        if (njt_strncmp(value[i].data, "type=", 5) == 0) {
            if (value[i].len == 5) {
                goto invalid;
            }

            value[i].data += 5;
            value[i].len -= 5;

            if(value[i].len == 3 && njt_strncmp(value[i].data, "tcp", 3) == 0) {
                njt_str_set(&rule.type, "tcp");
            // }else if(value[i].len == 3 && njt_strncmp(value[i].data, "udp", 3) == 0) {
            //     njt_str_set(&rule.type, "udp");
            }else{
                return "range type should be tcp";
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



static njt_int_t njt_range_create_chain(njt_str_t *iptables){
    u_char          buf[1024];
    FILE            *fp= NULL;
    // u_char          *end;
    // njt_str_t       tmp_str;

    njt_memzero(buf, 1024);
    njt_snprintf(buf, 1024, NJT_RANG_CREATE_CHAIN, iptables);
    // tmp_str.data = buf;
    // tmp_str.len = end - buf;

    fp = popen((char *)buf, "w");
    if(fp == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
            "range create chain OPENNJET error");
        
        return NJT_ERROR;
    }

    if(fp != NULL){
        pclose(fp);
    }

    return NJT_OK;
}

static njt_int_t njt_range_remove_chain(njt_str_t *iptables){
    u_char          buf[1024];
    FILE            *fp= NULL;
    // u_char          *end;
    // njt_str_t       tmp_str;

    njt_memzero(buf, 1024);
    njt_snprintf(buf, 1024, NJT_RANG_REMOVE_CHAIN, iptables);
    // tmp_str.data = buf;
    // tmp_str.len = end - buf;

    fp = popen((char *)buf, "w");
    if(fp == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
            "range remove chain OPENNJET error");
        
        return NJT_ERROR;
    }

    if(fp != NULL){
        pclose(fp);
    }

    return NJT_OK;
}

static njt_int_t njt_range_clear_chain(njt_str_t *iptables){
    u_char          buf[1024];
    FILE            *fp= NULL;
    // u_char          *end;
    // njt_str_t       tmp_str;

    njt_memzero(buf, 1024);
    njt_snprintf(buf, 1024, NJT_RANG_CLEAR_CHAIN, iptables);
    // tmp_str.data = buf;
    // tmp_str.len = end - buf;

    fp = popen((char *)buf, "w");
    if(fp == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
            "range clear chain OPENNJET error");
        
        return NJT_ERROR;
    }

    if(fp != NULL){
        pclose(fp);
    }

    return NJT_OK;
}

static njt_int_t njt_range_del_one_nat_chain(njt_str_t *iptables, njt_str_t *str_num){
    u_char          buf[1024];
    FILE            *fp= NULL;
    // u_char          *end;
    // njt_str_t       tmp_str;

    njt_memzero(buf, 1024);
    njt_snprintf(buf, 1024, NJT_RANG_DEL_MAP_NAT_CHAIN, iptables, str_num);
    // tmp_str.data = buf;
    // tmp_str.len = end - buf;

    fp = popen((char *)buf, "w");
    if(fp == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
            "range clear chain OPENNJET error");
        
        return NJT_ERROR;
    }

    if(fp != NULL){
        pclose(fp);
    }

    return NJT_OK;
}


static njt_int_t njt_range_del_map_nat_chain(njt_str_t *iptables){
    njt_int_t       rc = NJT_OK;
    u_char          buf[1024];
    u_char          get_buf[10240];
    FILE            *fp= NULL;
    // u_char          *end;
    njt_str_t       tmp_str;
    int             nread;
    u_char          *tmp_point, *data_point, *last_point, *first_point;


    njt_memzero(buf, 1024);
    njt_snprintf(buf, 1024, NJT_RANG_GET_NAT_CHAIN, iptables);
    // tmp_str.data = buf;
    // tmp_str.len = end - buf;

    fp = popen((char *)buf, "r");
    if(fp == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
            "range map nat chain OPENNJET error");
        
        return NJT_ERROR;
    }

    nread = fread(get_buf,1,10240,fp);

    // tmp_str.data = get_buf;
    // tmp_str.len = nread;

    if(nread > 1){
        data_point = &get_buf[0];
        tmp_point = data_point + nread - 1;
        while(tmp_point > data_point){
            if(*tmp_point != '\n'){
                rc = NJT_ERROR;
                break;
            }

            last_point = tmp_point;
            tmp_point--;
            if(tmp_point == data_point){
                first_point = tmp_point;
                tmp_str.data = first_point;
                tmp_str.len = last_point - first_point;
                njt_range_del_one_nat_chain(iptables, &tmp_str);
                break;
            }
            
            //find send n
            while(tmp_point > data_point){
                if(*tmp_point == '\n'){
                    break;
                }

                tmp_point--;
            }
            if(tmp_point == data_point){
                first_point = data_point;
                tmp_str.data = first_point;
                tmp_str.len = last_point - first_point;
                njt_range_del_one_nat_chain(iptables, &tmp_str);
                break;
            }else{
                first_point = tmp_point + 1;
                tmp_str.data = first_point;
                tmp_str.len = last_point - first_point;
                njt_range_del_one_nat_chain(iptables, &tmp_str);
            }
        }
    }

    if(fp != NULL){
        pclose(fp);
    }
    return rc;
}


static njt_int_t njt_range_map_nat_chain(njt_str_t *iptables){
    u_char          buf[1024];
    FILE            *fp= NULL;
    // u_char          *end;
    // njt_str_t       tmp_str;

    njt_memzero(buf, 1024);
    njt_snprintf(buf, 1024, NJT_RANG_MAP_NAT_CHAIN, iptables);
    // tmp_str.data = buf;
    // tmp_str.len = end - buf;

    // njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
    //         "range map nat chain:%V", &tmp_str);

    fp = popen((char *)buf, "w");
    if(fp == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
            "range map nat chain OPENNJET error");
        
        return NJT_ERROR;
    }

    if(fp != NULL){
        pclose(fp);
    }

    return NJT_OK;
}


njt_int_t njt_range_init_process(njt_cycle_t *cycle){
    njt_range_conf_t                *rcf;
    njt_queue_t                     *q;
    njt_range_rule_t                *rule_item;
    uid_t                           uid = 0;
    njt_str_t                       tmp_path;


    if(njt_process != NJT_PROCESS_HELPER || 1 != njt_is_privileged_agent){
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
    
    njt_range_del_map_nat_chain(&tmp_path);
    njt_range_clear_chain(&tmp_path);
    njt_range_remove_chain(&tmp_path);

    njt_range_create_chain(&tmp_path);
    njt_range_map_nat_chain(&tmp_path);

    q = njt_queue_head(&rcf->ranges);
    for (; q != njt_queue_sentinel(&rcf->ranges); q = njt_queue_next(q)) {
        rule_item = njt_queue_data(q, njt_range_rule_t, range_queue);
        if(NJT_OK != njt_range_add_rule(&tmp_path, &rule_item->type,
                &rule_item->src_ports, rule_item->dst_port)){
            njt_log_error(NJT_LOG_ERR, cycle->log, 0,
                    "range add rule error, type:%V  src_ports:%V  dst_port:%d",
                    &rule_item->type, &rule_item->src_ports, rule_item->dst_port);
            continue;
        }
    }

    return NJT_OK;
}


static void njt_range_exit_process(njt_cycle_t *cycle){
    njt_range_conf_t                *rcf;
    njt_str_t                       tmp_path;

    if(njt_process != NJT_PROCESS_HELPER || 1 != njt_is_privileged_agent){
        return;
    }

    rcf = (njt_range_conf_t *)njt_get_conf(cycle->conf_ctx, njt_range_module);    
    if(rcf == NULL){
        return;
    }

    //update rcf->pool->log = cycle_log
    if(rcf->pool != NJT_CONF_UNSET_PTR){
        rcf->pool->log = cycle->log;
    }

    tmp_path.data = rcf->iptables_path.path;
    tmp_path.len = rcf->iptables_path.len;
    
    njt_range_del_map_nat_chain(&tmp_path);
    njt_range_clear_chain(&tmp_path);
    njt_range_remove_chain(&tmp_path);

    return;
}



njt_int_t njt_range_add_rule(njt_str_t *iptables_path, njt_str_t *type, njt_str_t *src_ports, njt_uint_t dst_port){
    u_char          buf[1024];
    FILE            *fp= NULL;
    // u_char          *end;
    // njt_str_t       tmp_str;

    njt_memzero(buf, 1024);
    njt_snprintf(buf, 1024, NJT_RANG_ADD_RULE, iptables_path, src_ports, dst_port);
    // tmp_str.data = buf;
    // tmp_str.len = end - buf;

    fp = popen((char *)buf, "w");
    if(fp == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
            "range add rule error");
        
        return NJT_ERROR;
    }

    if(fp != NULL){
        pclose(fp);
    }

    return NJT_OK;
}


njt_int_t njt_range_del_rule(njt_str_t *iptables_path, njt_str_t *type, njt_str_t *src_ports, njt_uint_t dst_port){
    u_char          buf[1024];
    FILE            *fp= NULL;
    // u_char          *end;
    // njt_str_t       tmp_str;

    njt_memzero(buf, 1024);
    njt_snprintf(buf, 1024, NJT_RANG_DEL_RULE, iptables_path, src_ports, dst_port);
    // tmp_str.data = buf;
    // tmp_str.len = end - buf;

    fp = popen((char *)buf, "w");
    if(fp == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
            "range del rule error");
        
        return NJT_ERROR;
    }

    if(fp != NULL){
        pclose(fp);
    }

    return NJT_OK;
}
