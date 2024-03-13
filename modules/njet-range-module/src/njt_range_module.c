/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */
#include <njt_core.h>
#include "njt_range_module.h"


#define NJT_IPTABLES_PATH   "/usr/sbin/iptables"
#define NJT_IP6TABLES_PATH   "/usr/sbin/ip6tables"
#define NJT_IP_PATH   "/usr/sbin/ip"

//used for tcp
//chain
#define NJT_RANG_CREATE_CHAIN   "%V -t nat -N OPENNJET"
#define NJT_RANG_REMOVE_CHAIN   "%V -t nat -X OPENNJET"
#define NJT_RANG_CLEAR_CHAIN   "%V -t nat -F OPENNJET"

//rule
#define NJT_RANG_ADD_TCP_RULE   "%V -t nat -I OPENNJET -p tcp --dport %V -j REDIRECT --to-port %d"
#define NJT_RANG_DEL_TCP_RULE   "%V -t nat -D OPENNJET -p tcp --dport %V -j REDIRECT --to-port %d"

//map nat chain
#define NJT_RANG_MAP_NAT_CHAIN   "%V -t nat -I PREROUTING -j OPENNJET"
#define NJT_RANG_GET_NAT_CHAIN "%V --line -t nat -nvL|grep OPENNJET| grep -v Chain | awk '{print $1}'"
#define NJT_RANG_DEL_MAP_NAT_CHAIN   "%V -t nat -D PREROUTING %V"


//used for udp
//ip rule and route
#define NJT_RANG_UDP_ADD_IP_RULE "%V rule add fwmark 1 lookup 100 pri 32000"
#define NJT_RANG_UDP_DEL_IP_RULE "%V rule del pri 32000"
#define NJT_RANG_UDP_ADD_IP_ROUTE "%V route add local default dev lo table 100"
#define NJT_RANG_UDP_DEL_IP_ROUTE "%V route flush table 100"

//chain
#define NJT_RANG_UDP_CREATE_CHAIN   "%V -t mangle -N OPENNJETUDP"
#define NJT_RANG_UDP_REMOVE_CHAIN   "%V -t mangle -X OPENNJETUDP"
#define NJT_RANG_UDP_CLEAR_CHAIN   "%V -t mangle -F OPENNJETUDP"

//rule
#define NJT_RANG_ADD_UDP_RULE   "%V -t mangle -A OPENNJETUDP -p udp --dport %V -j TPROXY --tproxy-mark 0x1/0x1 --on-port %d"
#define NJT_RANG_DEL_UDP_RULE   "%V -t mangle -D OPENNJETUDP -p udp --dport %V -j TPROXY --tproxy-mark 0x1/0x1 --on-port %d"

//map nat chain
#define NJT_RANG_MAP_MANGLE_CHAIN   "%V -t mangle -A PREROUTING -j OPENNJETUDP"
#define NJT_RANG_GET_MANGLE_CHAIN "%V --line -t mangle -nvL|grep OPENNJETUDP| grep -v Chain | awk '{print $1}'"
#define NJT_RANG_DEL_MAP_MANGLE_CHAIN   "%V -t mangle -D PREROUTING %V"


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

    njt_str_set(&tmp_str, NJT_IP6TABLES_PATH);
    rcf->ip6tables_path.len = tmp_str.len;
    njt_memcpy(rcf->ip6tables_path.path, tmp_str.data, tmp_str.len);

    njt_str_set(&tmp_str, NJT_IP_PATH);
    rcf->ip_path.len = tmp_str.len;
    njt_memcpy(rcf->ip_path.path, tmp_str.data, tmp_str.len);

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

    njt_str_null(&rule.type);
    njt_str_set(&rule.family, "ipv4");
    njt_str_null(&rule.src_ports);
    rule.dst_port = 0;
    

    for (i = 1; i < cf->args->nelts; i++) {
        if (njt_strncmp(value[i].data, "iptables_path=", 14) == 0) {
            if (value[i].len == 14) {
                goto invalid;
            }

            value[i].data += 14;
            value[i].len -= 14;

            if(value[i].len > NJT_RANGE_PATH_LEN){
                value[i].len = NJT_RANGE_PATH_LEN;
            }

            if (value[i].len  == rcf->iptables_path.len && njt_strncmp(value[i].data, NJT_IPTABLES_PATH, value[i].len) == 0){
            }else{
                rcf->iptables_path.len = value[i].len;
                njt_memcpy(rcf->iptables_path.path, value[i].data, value[i].len);
            }

            return NJT_CONF_OK;
        }

        if (njt_strncmp(value[i].data, "ip6tables_path=", 15) == 0) {
            if (value[i].len == 15) {
                goto invalid;
            }

            value[i].data += 15;
            value[i].len -= 15;

            if(value[i].len > NJT_RANGE_PATH_LEN){
                value[i].len = NJT_RANGE_PATH_LEN;
            }

            if (value[i].len  == rcf->ip6tables_path.len && njt_strncmp(value[i].data, NJT_IP6TABLES_PATH, value[i].len) == 0){
            }else{
                rcf->ip6tables_path.len = value[i].len;
                njt_memcpy(rcf->ip6tables_path.path, value[i].data, value[i].len);
            }

            return NJT_CONF_OK;
        }

        if (njt_strncmp(value[i].data, "ip_path=", 8) == 0) {
            if (value[i].len == 8) {
                goto invalid;
            }

            value[i].data += 8;
            value[i].len -= 8;

            if(value[i].len > NJT_RANGE_PATH_LEN){
                value[i].len = NJT_RANGE_PATH_LEN;
            }

            if (value[i].len  == rcf->ip_path.len && njt_strncmp(value[i].data, NJT_IP_PATH, value[i].len) == 0){
            }else{
                rcf->ip_path.len = value[i].len;
                njt_memcpy(rcf->ip_path.path, value[i].data, value[i].len);
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
            }else if(value[i].len == 3 && njt_strncmp(value[i].data, "udp", 3) == 0) {
                njt_str_set(&rule.type, "udp");
            }else{
                return "range type should be tcp or udp";
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "family=", 7) == 0) {
            if (value[i].len == 7) {
                goto invalid;
            }

            value[i].data += 7;
            value[i].len -= 7;

            if(value[i].len == 4 && njt_strncmp(value[i].data, "ipv4", 4) == 0) {
                njt_str_set(&rule.family, "ipv4");
            }else if(value[i].len == 4 && njt_strncmp(value[i].data, "ipv6", 4) == 0) {
                njt_str_set(&rule.family, "ipv6");
            }else{
                return "range family should be ipv4 or ipv6";
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

    if(rule.type.len == 0){
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                "range type must set, should be tcp or udp");
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
    rule_item->family = rule.family;
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


static njt_int_t njt_range_operator_ip_rule(njt_str_t *ip, int action, int type){
    u_char          buf[1024];
    FILE            *fp= NULL;

    njt_memzero(buf, 1024);
    if (NJT_RANGE_ACTION_ADD == action)
    {
        if(NJT_RANGE_UDP_IP_RULE == type){
            njt_snprintf(buf, 1024, NJT_RANG_UDP_ADD_IP_RULE, ip);
        }else{
            njt_snprintf(buf, 1024, NJT_RANG_UDP_ADD_IP_ROUTE, ip);
        }
    }else{
        if(NJT_RANGE_UDP_IP_RULE == type){
            njt_snprintf(buf, 1024, NJT_RANG_UDP_DEL_IP_RULE, ip);
        }else{
            njt_snprintf(buf, 1024, NJT_RANG_UDP_DEL_IP_ROUTE, ip);
        }
    }

    fp = popen((char *)buf, "w");
    if(fp == NULL){
        if (NJT_RANGE_ACTION_ADD == action)
        {
            if(NJT_RANGE_UDP_IP_RULE == type){
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                    "range add ip rule error");
            }else{
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                    "range add ip route error");
            }
        }else{
            if(NJT_RANGE_UDP_IP_RULE == type){
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                    "range del ip rule error");
            }else{
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                    "range del ip route error");
            }
        }

        return NJT_ERROR;
    }

    if(fp != NULL){
        pclose(fp);
    }

    return NJT_OK;
}



static njt_int_t njt_range_create_chain(njt_str_t *iptables, int type){
    u_char          buf[1024];
    FILE            *fp= NULL;

    njt_memzero(buf, 1024);
    if(NJT_RANGE_TCP == type){
        njt_snprintf(buf, 1024, NJT_RANG_CREATE_CHAIN, iptables);
    }else{
        njt_snprintf(buf, 1024, NJT_RANG_UDP_CREATE_CHAIN, iptables);
    }

    fp = popen((char *)buf, "w");
    if(fp == NULL){
        if(NJT_RANGE_TCP == type){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "range create chain OPENNJET error");
        }else{
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "range create chain OPENNJETUDP error");
        }
        
        return NJT_ERROR;
    }

    if(fp != NULL){
        pclose(fp);
    }

    return NJT_OK;
}



static njt_int_t njt_range_remove_chain(njt_str_t *iptables, int type){
    u_char          buf[1024];
    FILE            *fp= NULL;

    njt_memzero(buf, 1024);
    if(NJT_RANGE_TCP == type){
        njt_snprintf(buf, 1024, NJT_RANG_REMOVE_CHAIN, iptables);
    }else{
        njt_snprintf(buf, 1024, NJT_RANG_UDP_REMOVE_CHAIN, iptables);
    }

    fp = popen((char *)buf, "w");
    if(fp == NULL){
        if(NJT_RANGE_TCP == type){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "range remove chain OPENNJET error");
        }else{
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "range remove chain OPENNJETUDP error");
        }
        
        return NJT_ERROR;
    }

    if(fp != NULL){
        pclose(fp);
    }

    return NJT_OK;
}

static njt_int_t njt_range_clear_chain(njt_str_t *iptables, int type){
    u_char          buf[1024];
    FILE            *fp= NULL;

    njt_memzero(buf, 1024);
    if(NJT_RANGE_TCP == type){
        njt_snprintf(buf, 1024, NJT_RANG_CLEAR_CHAIN, iptables);
    }else{
        njt_snprintf(buf, 1024, NJT_RANG_UDP_CLEAR_CHAIN, iptables);
    }

    fp = popen((char *)buf, "w");
    if(fp == NULL){
        if(NJT_RANGE_TCP == type){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "range clear chain OPENNJET error");
        }else{
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "range clear chain OPENNJETUDP error");
        }
        
        return NJT_ERROR;
    }

    if(fp != NULL){
        pclose(fp);
    }

    return NJT_OK;
}

static njt_int_t njt_range_del_one_chain(njt_str_t *iptables, int type, njt_str_t *str_num){
    u_char          buf[1024];
    FILE            *fp= NULL;

    njt_memzero(buf, 1024);
    if(NJT_RANGE_TCP == type){
        njt_snprintf(buf, 1024, NJT_RANG_DEL_MAP_NAT_CHAIN, iptables, str_num);
    }else{
        njt_snprintf(buf, 1024, NJT_RANG_DEL_MAP_MANGLE_CHAIN, iptables, str_num);
    }

    fp = popen((char *)buf, "w");
    if(fp == NULL){
        if(NJT_RANGE_TCP == type){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "range del one chain OPENNJET error");
        }else{
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "range del one chain OPENNJETUDP error");
        }
        
        return NJT_ERROR;
    }

    if(fp != NULL){
        pclose(fp);
    }

    return NJT_OK;
}


static njt_int_t njt_range_del_map_chain(njt_str_t *iptables, int type){
    njt_int_t       rc = NJT_OK;
    u_char          buf[1024];
    u_char          get_buf[10240];
    FILE            *fp= NULL;
    njt_str_t       tmp_str;
    int             nread;
    u_char          *tmp_point, *data_point, *last_point, *first_point;


    njt_memzero(buf, 1024);
    if(NJT_RANGE_TCP == type){
        njt_snprintf(buf, 1024, NJT_RANG_GET_NAT_CHAIN, iptables);
    }else{
        njt_snprintf(buf, 1024, NJT_RANG_GET_MANGLE_CHAIN, iptables);
    }

    fp = popen((char *)buf, "r");
    if(fp == NULL){
        if(NJT_RANGE_TCP == type){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "range get nat chain OPENNJET error");
        }else{
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "range get mangle chain OPENNJETUDP error"); 
        }
        
        return NJT_ERROR;
    }

    nread = fread(get_buf,1,10240,fp);
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
                njt_range_del_one_chain(iptables, type, &tmp_str);
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
                njt_range_del_one_chain(iptables, type, &tmp_str);
                break;
            }else{
                first_point = tmp_point + 1;
                tmp_str.data = first_point;
                tmp_str.len = last_point - first_point;
                njt_range_del_one_chain(iptables, type, &tmp_str);
            }
        }
    }

    if(fp != NULL){
        pclose(fp);
    }
    return rc;
}


static njt_int_t njt_range_map_chain(njt_str_t *iptables, int type){
    u_char          buf[1024];
    FILE            *fp= NULL;

    njt_memzero(buf, 1024);
    if(NJT_RANGE_TCP == type){
        njt_snprintf(buf, 1024, NJT_RANG_MAP_NAT_CHAIN, iptables);
    }else{
        njt_snprintf(buf, 1024, NJT_RANG_MAP_MANGLE_CHAIN, iptables);
    }

    fp = popen((char *)buf, "w");
    if(fp == NULL){
        if(NJT_RANGE_TCP == type){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "range map nat chain OPENNJET error");
        }else{
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "range map mangle chain OPENNJETUDP error");
        }
        
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
    njt_str_t                       tmp_iptables_path;
    njt_str_t                       tmp_ip6tables_path;
    njt_str_t                       tmp_ip_path;


    if(njt_process != NJT_PROCESS_HELPER || 1 != njt_is_privileged_agent){
        return NJT_OK;
    }

    rcf = (njt_range_conf_t *)njt_get_conf(cycle->conf_ctx, njt_range_module);    
    if(rcf == NULL){
        return NJT_OK;
    }

    //setuid
    //setuid(uid);
    if (setuid(uid) == -1) {
            njt_log_error(NJT_LOG_ERR, cycle->log, 0, "njt_range_init_process setuid error!");
    }

    //update rcf->pool->log = cycle_log
    if(rcf->pool != NJT_CONF_UNSET_PTR){
        rcf->pool->log = cycle->log;
    }

    tmp_iptables_path.data = rcf->iptables_path.path;
    tmp_iptables_path.len = rcf->iptables_path.len;
    
    //iptables delele nat and mangle chain
    njt_range_del_map_chain(&tmp_iptables_path, NJT_RANGE_TCP);
    njt_range_del_map_chain(&tmp_iptables_path, NJT_RANGE_UDP);
    njt_range_clear_chain(&tmp_iptables_path, NJT_RANGE_TCP);
    njt_range_clear_chain(&tmp_iptables_path, NJT_RANGE_UDP);
    njt_range_remove_chain(&tmp_iptables_path, NJT_RANGE_TCP);
    njt_range_remove_chain(&tmp_iptables_path, NJT_RANGE_UDP);

    //iptables create nat and mangle chain
    njt_range_create_chain(&tmp_iptables_path, NJT_RANGE_TCP);
    njt_range_create_chain(&tmp_iptables_path, NJT_RANGE_UDP);
    njt_range_map_chain(&tmp_iptables_path, NJT_RANGE_TCP);
    njt_range_map_chain(&tmp_iptables_path, NJT_RANGE_UDP);

    tmp_ip6tables_path.data = rcf->ip6tables_path.path;
    tmp_ip6tables_path.len = rcf->ip6tables_path.len;
    
    //ip6tables delele nat and mangle chain
    njt_range_del_map_chain(&tmp_ip6tables_path, NJT_RANGE_TCP);
    njt_range_del_map_chain(&tmp_ip6tables_path, NJT_RANGE_UDP);
    njt_range_clear_chain(&tmp_ip6tables_path, NJT_RANGE_TCP);
    njt_range_clear_chain(&tmp_ip6tables_path, NJT_RANGE_UDP);
    njt_range_remove_chain(&tmp_ip6tables_path, NJT_RANGE_TCP);
    njt_range_remove_chain(&tmp_ip6tables_path, NJT_RANGE_UDP);

    //ip6tables create nat and mangle chain
    njt_range_create_chain(&tmp_ip6tables_path, NJT_RANGE_TCP);
    njt_range_create_chain(&tmp_ip6tables_path, NJT_RANGE_UDP);
    njt_range_map_chain(&tmp_ip6tables_path, NJT_RANGE_TCP);
    njt_range_map_chain(&tmp_ip6tables_path, NJT_RANGE_UDP);


    tmp_ip_path.data = rcf->ip_path.path;
    tmp_ip_path.len = rcf->ip_path.len;
    //ip add rule and route
    njt_range_operator_ip_rule(&tmp_ip_path, NJT_RANGE_ACTION_ADD, NJT_RANGE_UDP_IP_RULE);
    njt_range_operator_ip_rule(&tmp_ip_path, NJT_RANGE_ACTION_ADD, NJT_RANGE_UDP_IP_ROUTE);

    q = njt_queue_head(&rcf->ranges);
    for (; q != njt_queue_sentinel(&rcf->ranges); q = njt_queue_next(q)) {
        rule_item = njt_queue_data(q, njt_range_rule_t, range_queue);
        if(rule_item->family.len == 4 && 0 == njt_strncmp(rule_item->family.data, "ipv4", 4)){
            if(NJT_OK != njt_range_operator_rule(&tmp_iptables_path, &tmp_ip_path, NJT_RANGE_ACTION_ADD,
                    &rule_item->type, &rule_item->src_ports, rule_item->dst_port)){
                njt_log_error(NJT_LOG_ERR, cycle->log, 0,
                        "range add rule error, type:%V family:%V src_ports:%V  dst_port:%d",
                        &rule_item->type, &rule_item->family, &rule_item->src_ports, rule_item->dst_port);
                continue;
            }
        }else if(rule_item->family.len == 4 && 0 == njt_strncmp(rule_item->family.data, "ipv6", 4)){
            if(NJT_OK != njt_range_operator_rule(&tmp_ip6tables_path, &tmp_ip_path, NJT_RANGE_ACTION_ADD,
                    &rule_item->type, &rule_item->src_ports, rule_item->dst_port)){
                njt_log_error(NJT_LOG_ERR, cycle->log, 0,
                        "range add rule error, type:%V family:%V src_ports:%V  dst_port:%d",
                        &rule_item->type, &rule_item->family, &rule_item->src_ports, rule_item->dst_port);
                continue;
            }
        }else{
            njt_log_error(NJT_LOG_ERR, cycle->log, 0,
                        "range add rule error, type:%V family:%V src_ports:%V  dst_port:%d",
                        &rule_item->type, &rule_item->family, &rule_item->src_ports, rule_item->dst_port);
        }
    }

    return NJT_OK;
}


static void njt_range_exit_process(njt_cycle_t *cycle){
    njt_range_conf_t                *rcf;
    njt_str_t                       tmp_iptables_path;
    njt_str_t                       tmp_ip6tables_path;
    njt_str_t                       tmp_ip_path;

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

    //iptables clear
    tmp_iptables_path.data = rcf->iptables_path.path;
    tmp_iptables_path.len = rcf->iptables_path.len;
    
    njt_range_del_map_chain(&tmp_iptables_path, NJT_RANGE_TCP);
    njt_range_clear_chain(&tmp_iptables_path, NJT_RANGE_TCP);
    njt_range_remove_chain(&tmp_iptables_path, NJT_RANGE_TCP);

    njt_range_del_map_chain(&tmp_iptables_path, NJT_RANGE_UDP);
    njt_range_clear_chain(&tmp_iptables_path, NJT_RANGE_UDP);
    njt_range_remove_chain(&tmp_iptables_path, NJT_RANGE_UDP);

    //ip6tables clear
    tmp_ip6tables_path.data = rcf->ip6tables_path.path;
    tmp_ip6tables_path.len = rcf->ip6tables_path.len;
    njt_range_del_map_chain(&tmp_ip6tables_path, NJT_RANGE_TCP);
    njt_range_clear_chain(&tmp_ip6tables_path, NJT_RANGE_TCP);
    njt_range_remove_chain(&tmp_ip6tables_path, NJT_RANGE_TCP);

    njt_range_del_map_chain(&tmp_ip6tables_path, NJT_RANGE_UDP);
    njt_range_clear_chain(&tmp_ip6tables_path, NJT_RANGE_UDP);
    njt_range_remove_chain(&tmp_ip6tables_path, NJT_RANGE_UDP);

    tmp_ip_path.data = rcf->ip_path.path;
    tmp_ip_path.len = rcf->ip_path.len;
    njt_range_operator_ip_rule(&tmp_ip_path, NJT_RANGE_ACTION_DEL, NJT_RANGE_UDP_IP_RULE);
    njt_range_operator_ip_rule(&tmp_ip_path, NJT_RANGE_ACTION_DEL, NJT_RANGE_UDP_IP_ROUTE);

    return;
}



njt_int_t njt_range_operator_rule(njt_str_t *iptables_path, njt_str_t *ip_path,
        int action, njt_str_t *type, njt_str_t *src_ports, njt_uint_t dst_port){
    u_char          buf[1024];
    // u_char          read_buf[10240];
    FILE            *fp= NULL;
    njt_str_t       tmp_str;
    // njt_int_t       nread;
    u_char          *end;
    njt_int_t       status;

    njt_memzero(buf, 1024);
    if(NJT_RANGE_ACTION_ADD == action){
        if(type->len == 3 && njt_strncmp(type->data, "tcp", 3) == 0) {
            end = njt_snprintf(buf, 1024, NJT_RANG_ADD_TCP_RULE, iptables_path, src_ports, dst_port);
        }else{
            end = njt_snprintf(buf, 1024, NJT_RANG_ADD_UDP_RULE, iptables_path, src_ports, dst_port);
        }
    }else{
        if(type->len == 3 && njt_strncmp(type->data, "tcp", 3) == 0) {
            end = njt_snprintf(buf, 1024, NJT_RANG_DEL_TCP_RULE, iptables_path, src_ports, dst_port);
        }else{
            end = njt_snprintf(buf, 1024, NJT_RANG_DEL_UDP_RULE, iptables_path, src_ports, dst_port);
        }
    }

    fp = popen((char *)buf, "w");
    if(fp == NULL){
        tmp_str.data = buf;
        tmp_str.len = end - buf;
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
            "range popen error about rule:%V", &tmp_str);
        
        return NJT_ERROR;
    }

    if(fp != NULL){
        status = pclose(fp);

        if(0 != WEXITSTATUS(status)){
            tmp_str.data = buf;
            tmp_str.len = end - buf;
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "range error about rule:%V exitstatus:%d", &tmp_str, WEXITSTATUS(status));

            return NJT_ERROR;
        }
    }

    return NJT_OK;
}
