/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */
#ifndef NJT_STREAM_FTP_PROXY_MODULE_H_   
#define NJT_STREAM_PROXY_MODULE_H_
#include <njt_core.h>


typedef struct {
    njt_rbtree_t                    rbtree;
    njt_rbtree_node_t               sentinel;

    njt_int_t                       min_port;
    njt_int_t                       max_port;

    //used for quic check, list next_port = cur_empty_port + 1
    njt_int_t                       cur_empty_port;
    njt_uint_t                      used_port_num;
    njt_uint_t                      freed_port_num;    
} njt_stream_ftp_proxy_shctx_t;

typedef enum {
    NJT_STREAM_FTP_NONE = 0,
    NJT_STREAM_FTP_CTRL,
    NJT_STREAM_FTP_DATA
} njt_stream_ftp_type_t;


typedef enum {
    NJT_STREAM_FTP_PROXY_MODE_PLAIN = 0,
    NJT_STREAM_FTP_PROXY_MODE_ENCRY,
    NJT_STREAM_FTP_PROXY_MODE_AUTH
} njt_stream_ftp_proxy_mode_t;

typedef struct {
    njt_int_t                  data_port;
    njt_queue_t                queue;
} njt_stream_ftp_data_port_t;

typedef struct {
    njt_stream_ftp_proxy_shctx_t  *sh;
    njt_slab_pool_t               *shpool;
    // njt_http_complex_value_t      key;

    njt_int_t                  min_port;
    njt_int_t                  max_port;
} njt_stream_ftp_proxy_ctx_t;

typedef struct {
    njt_flag_t                  enable;
    njt_stream_ftp_type_t       type;       //ctrl or data
    njt_stream_ftp_proxy_mode_t mode;       //transfer content type, [plain|encry|auth]

    njt_str_t                   zone;
    njt_int_t                   min_port;
    njt_int_t                   max_port;
    njt_str_t                   proxy_ip;

    //save port map info
    //key: proxy_calloc_port     value:njt_http_ftp_proxy_node_t
    njt_shm_zone_t              *shm_zone;
    
    //save every connection's used port, 
    //should free all port when close control connection
    //key:cip:cport         value:proxy_calloc_port list
    njt_lvlhsh_t                connection_port_map;
    njt_pool_t                  *pool;
} njt_stream_ftp_proxy_srv_conf_t;


typedef struct {
    u_char                      color;
    njt_uint_t                  port;     //proxy port

    u_char                      sip[50];      //server data ip
    u_short                     sip_len;
    njt_uint_t                  sport;    //server data port

    //current client addr info
    u_char                      cip[50];      //client data ip
    u_short                     cip_len;
    njt_uint_t                  cport;    //client data port

    u_char 					    len;
    u_char 					    data[1];
} njt_stream_ftp_proxy_node_t;


// typedef struct {
//     njt_shm_zone_t                 *shm_zone;
//     njt_rbtree_node_t              *node;
// } njt_stream_ftp_proxy_cleanup_t;


void njt_stream_ftp_proxy_filter_pasv(njt_stream_session_t *s, u_char *data, ssize_t *n);
void njt_stream_ftp_proxy_cleanup(njt_stream_session_t *s);
njt_int_t njt_stream_ftp_proxy_replace_upstream(njt_stream_session_t *s,
        njt_stream_upstream_srv_conf_t **uscf);

extern njt_module_t  njt_stream_ftp_proxy_module;
#endif
