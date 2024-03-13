
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

#define NJT_RANGE_ACTION_ADD       0
#define NJT_RANGE_ACTION_DEL       1

#define NJT_RANGE_UDP_IP_RULE      0
#define NJT_RANGE_UDP_IP_ROUTE     1

#define NJT_RANGE_PATH_LEN   300


typedef struct {
    njt_str_t               type;
    njt_str_t               family;
    njt_str_t               src_ports;
    njt_int_t               dst_port;

    njt_queue_t             range_queue;
} njt_range_rule_t;

typedef struct {
    u_char                  path[NJT_RANGE_PATH_LEN];
    njt_uint_t              len;
} njt_range_path_t;

typedef struct {
    njt_queue_t                     ranges;
    njt_range_path_t                iptables_path;
    njt_range_path_t                ip6tables_path;
    njt_range_path_t                ip_path;
    njt_pool_t                      *pool;
} njt_range_conf_t;

njt_int_t njt_range_operator_rule(njt_str_t *iptables_path, njt_str_t *ip_path,
        int action, njt_str_t *type, njt_str_t *src_ports, njt_uint_t dst_port);


#endif //NJT_RANGE_H_