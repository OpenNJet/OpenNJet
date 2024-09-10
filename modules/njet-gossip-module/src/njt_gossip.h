
/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */

#ifndef NGX_GOSSIP_H_
#define NGX_GOSSIP_H_

//msg handler
typedef int (* gossip_app_pt) (const char *msg, void    *data);

//node on handler, only need one node syn data 
typedef int (* gossip_app_node_on_single_pt) (njt_str_t *node, njt_str_t *pid, void* data);

//node on handler, need all node syn data to new node
typedef int (* gossip_app_node_on_all_pt) (njt_str_t *node, njt_str_t *pid, void* data);

//node on handler, need all node syn data to new node
typedef int (* gossip_app_node_off_pt) (njt_str_t *node, njt_str_t *pid, void* data);

//register all handler
int  njt_gossip_reg_app_handler(gossip_app_pt app_msg_handler, gossip_app_node_on_single_pt node_on_single_handler,
        gossip_app_node_on_all_pt node_on_all_handler, gossip_app_node_off_pt node_off_handler,
        uint32_t app_magic, void* data);
char* njt_gossip_app_get_msg_buf(  uint32_t app_magic,njt_str_t target_node, njt_str_t target_pid, size_t *buf_size);
void  njt_gossip_app_close_msg_buf(char* end);
void  njt_gossip_send_app_msg_buf(void);

#endif 
