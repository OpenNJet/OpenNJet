
/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */

#ifndef NJT_RANGE_H_
#define NJT_RANGE_H_

#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


#define NJT_RANGE_TCP              0
#define NJT_RANGE_UDP              1

#define IPTABLES_PATH_LEN   300

#define NJT_IPTABLES_PATH   "/usr/sbin/iptables"

#define NJT_RANG_ADD_RULE   "%V -t nat -I PREROUTING -p tcp --dport %V -j REDIRECT --to-port %d"
#define NJT_RANG_DEL_RULE   "%V -t nat -D PREROUTING -p tcp --dport %V -j REDIRECT --to-port %d"

typedef struct {
    njt_str_t               type;
    njt_str_t               src_ports;
    njt_int_t               dst_port;

    njt_queue_t             range_queue;
} njt_range_rule_t;

typedef struct {
    u_char                  path[IPTABLES_PATH_LEN];
    njt_uint_t              len;
} njt_range_iptables_path_t;

typedef struct {
    njt_queue_t                     ranges;
    njt_uint_t                      try_del_times;
    njt_range_iptables_path_t       iptables_path;
    njt_pool_t                      *pool;
} njt_range_conf_t;

njt_int_t njt_range_add_rule(njt_str_t *iptables_path, njt_str_t *type, njt_str_t *src_ports, njt_uint_t dst_port);
njt_int_t njt_range_del_rule(njt_str_t *iptables_path, njt_str_t *type, njt_str_t *src_ports, njt_uint_t dst_port);

#endif //NJT_RANGE_H_