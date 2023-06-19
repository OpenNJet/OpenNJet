
/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */

#ifndef NGX_GOSSIP_MODULE_H_
#define NGX_GOSSIP_MODULE_H_
#include <njt_core.h>

#include "njt_gossip.h"
#include "msgpuck.h"

#define GOSSIP_MAGIC 0xE2F79D34

//crc of on
#define GOSSIP_ON	0xDED57BA4
//crc of off
#define GOSSIP_OFF 0x9B7E7B3C
//crc of heartbeat
#define GOSSIP_HEARTBEAT 0xE4880F7B
//crc of msgsync
#define GOSSIP_MSG_SYN 0xEF7CCE4F

//todo:

enum node_state {
	/* set node status to node_online when initprocess,
	 * and send online msg to widecast indirect,
	 * then set node status to node_wait_first_heartbeat_node
	 *      and start a heartbeat event;
	*/
	node_online = 0,
	node_wait_first_heartbeat_node,

    /* when fisrt heartbeat event come, if node_status is still
	 * node_wait_first_heartbeat_node, then set node status to
	 * node_active status, because has no other node online
	*/
    node_active,


	/* when recv heartbeat msg, then check node status, if is
	 * is node_wait_first_heartbeat_node, now send syn data request msg
	 * and set node status to node_wait_syn_data status
	 * and start a wait syndata event
	 * when the event timeout ,the status node is still node_wait_syndata
	 * need select the next online node to request syndata
	*/
	node_wait_syndata,

    /*when recv syndata msg, then set node status to node_active*/

    /*when node offlinem set node status to node_offline*/
	node_offline
};



typedef struct njt_gossip_member_list_s
{
    struct njt_gossip_member_list_s *next;
    //njt_str_t node_addr;
    njt_str_t 						node_name;
	njt_str_t						pid;
    njt_msec_t  					last_seen;
    njt_msec_t  					uptime;
	uint32_t  						state;
	bool 							need_syn;
} njt_gossip_member_list_t;

struct gossip_app_msg_handle_s {
	uint32_t 			app_magic;
	void 				*data;
	gossip_app_pt 		handler;
	gossip_app_node_pt 	node_handler;	//when a node is on/off
} ;
typedef struct gossip_app_msg_handle_s  gossip_app_msg_handle_t;


typedef struct
{
    njt_gossip_member_list_t *members;
} njt_gossip_shctx_t;


typedef struct  njt_gossip_req_ctx_s njt_gossip_req_ctx_t;
struct njt_gossip_req_ctx_s
{
	njt_gossip_shctx_t  		*sh;
    njt_slab_pool_t             *shpool;
} ;



typedef struct  njt_gossip_udp_ctx_s njt_gossip_udp_ctx_t;
struct njt_gossip_udp_ctx_s
{
	// njt_gossip_shctx_t  		*sh;
    // njt_slab_pool_t             *shpool;
	njt_gossip_req_ctx_t  		*req_ctx;

	njt_str_t					*cluster_name;
	njt_str_t					*node_name;
	njt_str_t					*pid;

	njt_msec_t                   heartbeat_timeout;
	njt_msec_t                   nodeclean_timeout;
	njt_uint_t                   node_status;

	njt_connection_t 			*udp;
    struct sockaddr 			*sockaddr;
	socklen_t 					 socklen;

	njt_chain_t                 *requests;

	njt_pool_t                  *pool;
    njt_log_t                   *log;

	njt_msec_t 					 boot_timestamp;
	njt_msec_t 					 last_seen;
	bool						 need_syn;

	//njt_array_t  *app_handle;
};	


typedef struct 
{
	njt_str_t					*cluster_name;
	njt_str_t					*node_name;
	njt_str_t					*pid;
	njt_gossip_req_ctx_t  		*req_ctx;
    struct sockaddr 			*sockaddr;
	socklen_t 					 socklen;

    //heartbeat timeout, default 10000 ms
	njt_msec_t                   heartbeat_timeout;

	//nodeclean timeout, should > heartbeat timeout, default 2*heartbeat
	njt_msec_t                   nodeclean_timeout;
	njt_event_t                  nc_timer;
} njt_gossip_srv_conf_t;

//this should be done in init process



#endif
