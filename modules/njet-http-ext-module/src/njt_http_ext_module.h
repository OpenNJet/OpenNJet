/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */

#ifndef NJT_HTTP_EXT_MODULE_H_
#define NJT_HTTP_EXT_MODULE_H_

typedef enum
{
    ADD_NOTICE = 0,
    UPDATE_NOTICE,
    DELETE_NOTICE,
    TOPIC_UPDATE
} notice_op;
#define VS_OBJ              "vs"
#define LOCATION_OBJ        "location"
#define UPSTREAM_OBJ        "upstream"
#define VS_DEL_EVENT        "del_vs"
#define VS_DEL_STREAM_EVENT "del_stream_vs"
#define UPS_DEL_STREAM_EVENT "del_stream_ups"
#define UPS_DEL_HTTP_EVENT   "del_ups"
#define LOCATION_DEL_EVENT  "del_location"
#define STREAM_VS_OBJ       "stream_vs"
#define STREAM_UPSTREAM_OBJ "stream_upstream"

#define UPSTREAM_PEER_OBJ   "upstream_peer"
#define STREAM_UPSTREAM_PEER_OBJ "stream_upstream_peer"


#define NJT_CONFIG_UPDATE_EVENT_VS_OBJ              0x00000001
#define NJT_CONFIG_UPDATE_EVENT_LOCATION_OBJ        0x00000002
#define NJT_CONFIG_UPDATE_EVENT_UPSTREAM_OBJ        0x00000004
#define NJT_CONFIG_UPDATE_EVENT_VS_DEL              0x00000008
#define NJT_CONFIG_UPDATE_EVENT_LOCATION_DEL        0x00000010

#define NJT_CONF_ATTR_FIRST_CREATE 0x00000002

typedef void (*object_change_handler)(void *data);

struct njt_http_object_change_reg_info_s
{
    object_change_handler add_handler;
    object_change_handler update_handler;
    object_change_handler del_handler;
    njt_str_t   *topic_key;
};

typedef struct njt_http_object_change_reg_info_s njt_http_object_change_reg_info_t;

typedef struct
{
    njt_http_object_change_reg_info_t callbacks;
    njt_queue_t queue;
} njt_http_object_change_handler_t;

typedef struct
{
    njt_str_t key;
    njt_queue_t handler_queue;
} object_change_hash_data_t;

//upstream domain cache
typedef struct {
    struct sockaddr          *sockaddr;
    socklen_t                 socklen;
} njt_cache_addr_t;

typedef struct
{
    njt_str_node_t            node;
    njt_cache_addr_t          *addrs;
    njt_uint_t                naddrs;
} njt_http_dyn_upstream_domain_node_t;

typedef struct
{
    njt_rbtree_t rbtree;
    njt_rbtree_node_t sentinel;
} njt_http_dyn_upstream_domain_cache_ctx_t;
typedef struct njt_http_dyn_upstream_domain_main_conf_s
{
   njt_slab_pool_t *shpool;
   njt_shm_zone_t shm_zone;
   njt_http_dyn_upstream_domain_cache_ctx_t *sh;
} njt_http_dyn_upstream_domain_main_conf_t;

typedef struct njt_http_upstream_peer_change_s
{
   njt_str_t  upstream_name;
   njt_uint_t peer_id;
   njt_str_t  ip_port;
} njt_http_upstream_peer_change_t;

njt_int_t njt_http_object_register_notice(njt_str_t *key, njt_http_object_change_reg_info_t *handler);
void njt_http_object_dispatch_notice(njt_str_t *key, notice_op op, void *object_data);
njt_int_t njt_http_upstream_peer_change_register(njt_http_upstream_srv_conf_t *upstream,njt_http_upstream_server_change_handler_t ups_srv_handlers);
njt_int_t njt_http_upstream_peer_set_notice(njt_http_upstream_srv_conf_t *upstream);
//only work at pa
njt_int_t njt_regist_update_fullconfig(njt_str_t *object_key,njt_str_t *topic_key);
njt_int_t njt_http_regist_update_fullconfig_event(njt_uint_t update_event, njt_str_t *topic_key);
njt_int_t njt_http_upstream_peer_send_broadcast(njt_http_upstream_srv_conf_t *upstream,njt_str_t type,njt_http_upstream_rr_peer_t *peer);
#endif // NJT_HTTP_EXT_MODULE_H_