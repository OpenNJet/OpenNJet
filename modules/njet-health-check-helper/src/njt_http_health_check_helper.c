/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njet.h>
#include <njt_stream.h>
#include <njt_str_util.h>
#include <njt_json_util.h>
#include "njt_http_match_module.h"
#include "njt_common_health_check.h"
#include <njt_http_sendmsg_module.h>
#include "njt_hc_parser.h"
#include "njt_hc_ctrl_parser.h"
#include "njt_http_api_register_module.h"


#define NJT_HTTP_SERVER_PORT        5688
#define NJT_HTTP_HC_INTERVAL        5000
#define NJT_HTTP_HC_CONNECT_TIMEOUT 5000


#define NJT_HTTP_HC_TCP                   0x0001
#define NJT_HTTP_HC_HTTP                  0x0002
#define NJT_HTTP_HC_GRPC                  0x0003

#define NJT_HTTP_PARSE_INIT           0
#define NJT_HTTP_PARSE_STATUS_LINE    1
#define NJT_HTTP_PARSE_HEADER         2
#define NJT_HTTP_PARSE_BODY           4

#define GRPC_STATUS_CODE_OK                  0
#define GRPC_STATUS_CODE_UNIMPLEMENTED       12
#define GRPC_STATUS_CODE_INVALID             ((njt_uint_t)-1)

enum {
    HC_SUCCESS = 0,
    HC_TYPE_NOT_FOUND,
    HC_UPSTREAM_NOT_FOUND,
    HC_VERSION_NOT_SUPPORT,
    HC_CA_NOT_CONF,
    HC_CERTIFICATE_NOT_CONF,
    HC_CERTIFICATE_KEY_NOT_CONF,
    HC_SERVER_ERROR,
    HC_DOUBLE_SET,
    HC_BODY_ERROR,
    HC_PATH_NOT_FOUND,
    HC_METHOD_NOT_ALLOW,
    HC_NOT_FOUND,
    PORT_NOT_ALLOW,
    UDP_NOT_SUPPORT_TLS,
    HC_RESP_DONE
} NJT_HTTP_API_HC_ERROR;

typedef enum {
    njt_http_grpc_hc_st_start = 0,
    njt_http_grpc_hc_st_sent,
    njt_http_grpc_hc_st_end,
} njt_http_grpc_hc_state_e;

static njt_str_t njt_hc_error_msg[] = {
        njt_string("success"),
        njt_string("Type not allow"),
        njt_string("not find upstream"),
        njt_string("version not match , please update njet"),
        njt_string("Trusted CA certificate must be configured"),
        njt_string("Certificate must be configured"),
        njt_string("Certificate key must be configured"),
        njt_string("Unknown server error, please check the error log"),
        njt_string("The health check already configured "),
        njt_string("The request body parse error "),
        njt_string("The request uri not found "),
        njt_string("The request method not allow "),
        njt_string("Not found health check "),
        njt_string("port only allowed in 1-65535"),
        njt_string("UDP does not support tls"),
        njt_string("")
};


static njt_int_t
njt_hc_lvlhsh_test(njt_lvlhsh_query_t *lhq, void *data)
{
    //ignore value compare, just return ok
    return NJT_OK;
}

const njt_lvlhsh_proto_t  njt_hc_lvlhsh_proto = {
    NJT_LVLHSH_LARGE_MEMALIGN,
    njt_hc_lvlhsh_test,
    njt_lvlhsh_pool_alloc,
    njt_lvlhsh_pool_free,
};

typedef struct {
    njt_http_upstream_rr_peer_t *peer;
    njt_queue_t      ele_queue;
} njt_hc_http_peer_element;

typedef struct {
    njt_stream_upstream_rr_peer_t *peer;
    njt_queue_t      ele_queue;
} njt_hc_stream_peer_element;


typedef struct {
    njt_str_t upstream_name;
    njt_str_t hc_type;
    health_check_t *hc_data;
    bool persistent;
    bool mandatory;
    unsigned success: 1;
    njt_int_t rc;
} njt_helper_hc_api_data_t;

static njt_http_v2_header_t njt_http_grpc_hc_headers[] = {
        {njt_string("content-length"), njt_string("5")},
        {njt_string("te"),             njt_string("trailers")},
        {njt_string("content-type"),   njt_string("application/grpc")},
        {njt_string("user-agent"),     njt_string("njet (health check grpc)")},
};
static njt_str_t njt_stcp_ck_type = njt_string("stcp");
static njt_str_t njt_sudp_ck_type = njt_string("sudp");
//static njt_str_t njt_http_ck_type = njt_string("http");
/**
 *This module provided directive: health_check url interval=100 timeout=300 port=8080 type=TCP.
 **/

extern njt_module_t njt_http_proxy_module;

typedef struct njt_http_health_check_peer_s njt_http_health_check_peer_t;
typedef struct njt_health_check_http_parse_s njt_health_check_http_parse_t;

/*Type of callbacks of the checker*/
typedef njt_int_t (*njt_health_check_init_pt)(njt_http_upstream_rr_peer_t *peer);

typedef njt_int_t (*njt_health_check_process_pt)(njt_http_health_check_peer_t *peer);

typedef njt_int_t (*njt_health_check_event_handler)(njt_event_t *ev);

typedef njt_int_t (*njt_health_check_update_pt)(njt_http_health_check_peer_t *hc_peer, njt_int_t status);

typedef struct {
    njt_uint_t type;
    njt_uint_t protocol;
    njt_str_t name;
    njt_flag_t one_side;
    /* HTTP */
    njt_health_check_event_handler write_handler;
    njt_health_check_event_handler read_handler;

    njt_health_check_init_pt init;
    njt_health_check_process_pt process;
    njt_health_check_update_pt update;

} njt_health_checker_t;


/*Structure used for holding http parser internal info*/
struct njt_health_check_http_parse_s {
    njt_uint_t state;
    njt_uint_t code;
    njt_flag_t done;
    njt_flag_t body_used;
    njt_uint_t stage;
    u_char *status_text;
    u_char *status_text_end;
    njt_uint_t count;
    njt_flag_t chunked;
    off_t content_length_n;
    njt_array_t headers;
    u_char *header_name_start;
    u_char *header_name_end;
    u_char *header_start;
    u_char *header_end;
    u_char *body_start;

    njt_int_t (*process)(njt_http_health_check_peer_t *hc_peer);

    njt_msec_t start;
};

/*Main structure of the hc information of a peer*/
struct njt_http_health_check_peer_s {
    njt_uint_t                      peer_id;
    njt_uint_t                      update_id;
    njt_str_t                       server;
    njt_http_upstream_rr_peer_t     *hu_peer;
    njt_http_upstream_rr_peers_t    *hu_peers;
    njt_helper_health_check_conf_t  *hhccf;
    njt_pool_t                      *pool;
    njt_peer_connection_t           peer;
    njt_buf_t                       *send_buf;
    njt_buf_t                       *recv_buf;
    njt_chain_t                     *recv_chain;
    njt_chain_t                     *last_chain_node;
    void                            *parser;
#if (NJT_HTTP_SSL)
    njt_str_t                       ssl_name;
#endif
};


/* TODO */
// typedef njt_stream_health_check_peer_s njt_stream_health_check_peer_t;


typedef struct njt_stream_health_check_peer_s {
    njt_uint_t                      peer_id;
    njt_uint_t                      update_id;
    njt_str_t                       server;
    njt_stream_upstream_rr_peer_t   *hu_peer;
    njt_stream_upstream_rr_peers_t  *hu_peers;
    njt_helper_health_check_conf_t  *hhccf;
    njt_pool_t                      *pool;
    njt_peer_connection_t           peer;
    njt_buf_t                       *send_buf;
    njt_buf_t                       *recv_buf;
    njt_chain_t                     *recv_chain;
    njt_chain_t                     *last_chain_node;
    void                            *parser;
#if (NJT_STREAM_SSL)
    njt_str_t                       ssl_name;
    njt_stream_upstream_rr_peer_t   *rr_peer;
#endif
} njt_stream_health_check_peer_t;

typedef struct njt_http_health_check_conf_ctx_s {
    njt_health_checker_t *checker;
    njt_http_match_t *match;
    njt_str_t uri;
    njt_str_t body;
    njt_str_t status;
    njt_array_t headers;
    njt_str_t gsvc;
    njt_uint_t gstatus;
    njt_http_upstream_srv_conf_t *upstream;
} njt_http_health_check_conf_ctx_t;

/* 
    by zhaokang
    stream health check context 
*/
typedef struct njt_stream_health_check_conf_ctx_s {
    njt_health_checker_t             *checker;     /* type operations */
    njt_stream_match_t               *match;       /* stream match rule */

    njt_str_t                         send;
    njt_str_t                         expect;

    njt_stream_upstream_srv_conf_t   *upstream;    /* stream upstream server conf */

} njt_stream_health_check_conf_ctx_t;


// static char *njt_http_health_check_conf(njt_conf_t *cf, njt_command_t *cmd, void *conf);

static njt_int_t njt_http_health_check_conf_handler(njt_http_request_t *r);

static njt_int_t njt_http_health_check_add(njt_helper_health_check_conf_t *hhccf, njt_int_t sync);

static void njt_http_health_check_timer_handler(njt_event_t *ev);

static njt_int_t njt_http_health_check_common_update(njt_http_health_check_peer_t *hc_peer, njt_int_t status);


/*Common framework functions of all types of checkers*/
static njt_int_t njt_http_health_check_update_status(njt_http_health_check_peer_t *hc_peer, njt_int_t status);

static void njt_http_health_check_write_handler(njt_event_t *event);

static void njt_http_health_check_read_handler(njt_event_t *event);

static njt_health_checker_t *njt_http_get_health_check_type(njt_str_t *str);


/*TCP type of checker related functions.*/
static njt_int_t njt_http_health_check_peek_one_byte(njt_connection_t *c);

//static njt_int_t njt_http_health_check_tcp_handler(njt_event_t *wev);


/*HTTP type of checker related functions*/
static njt_int_t njt_http_health_check_http_write_handler(njt_event_t *event);

static njt_int_t njt_http_health_check_http_read_handler(njt_event_t *event);

static njt_int_t
njt_http_health_check_http_update_status(njt_http_health_check_peer_t *hc_peer,
                                         njt_int_t status);

static njt_int_t njt_http_health_check_http_process(njt_http_health_check_peer_t *hc_peer);

static njt_int_t njt_health_check_http_parse_status_line(njt_http_health_check_peer_t *hc_peer);

static njt_int_t njt_health_check_http_parse_header_line(njt_http_health_check_peer_t *hc_peer);

static njt_int_t njt_health_check_http_process_headers(njt_http_health_check_peer_t *hc_peer);

static njt_int_t njt_health_check_http_process_body(njt_http_health_check_peer_t *hc_peer);

static void njt_http_hc_grpc_loop_peer(njt_helper_health_check_conf_t *hhccf, njt_http_upstream_rr_peer_t *peer);

void *njt_http_grpc_hc_get_up_uptream(void *pglcf);

njt_array_t *njt_http_grpc_hc_get_lengths(void *pglcf);

njt_shm_zone_t *njt_http_grpc_hc_get_shm_zone(void *pglcf);

void njt_http_upstream_handler(njt_event_t *ev);

void njt_http_upstream_send_request_handler(njt_http_request_t *r, njt_http_upstream_t *u);

void njt_http_upstream_process_header(njt_http_request_t *r, njt_http_upstream_t *u);

void njt_http_grpc_hc_set_upstream(njt_http_upstream_t *u);

njt_int_t njt_http_grpc_body_output_filter(void *data, njt_chain_t *in);

njt_int_t njt_http_grpc_create_request(njt_http_request_t *r);

static void njt_http_grpc_hc_handler(njt_event_t *wev);

void *njt_http_grpc_hc_create_in_filter_ctx(njt_pool_t *pool, void *r, void *grpc_con);

void *njt_http_grpc_hc_create_grpc_on(njt_pool_t *pool);

void *njt_http_grpc_hc_get_uptream(void *pglcf);

static njt_int_t njt_hc_helper_module_init(njt_cycle_t *cycle);

static njt_http_match_t *njt_helper_http_match_create(njt_helper_health_check_conf_t *hhccf);

extern njt_module_t njt_http_grpc_module;

static njt_int_t njt_http_match_block(njt_helper_hc_api_data_t *api_data, njt_helper_health_check_conf_t *hhccf);

static njt_int_t njt_http_match(njt_helper_hc_api_data_t *api_data, njt_helper_health_check_conf_t *hhccf);

static njt_int_t njt_health_check_helper_init_process(njt_cycle_t *cycle);

static void njt_hc_kv_flush_confs(njt_helper_main_conf_t *hmcf);

static void njt_hc_kv_flush_conf_info(njt_helper_health_check_conf_t *hhccf);

static njt_int_t njt_hc_api_add_conf(njt_log_t *pool, njt_helper_hc_api_data_t *api_data, njt_int_t sync);

static njt_helper_health_check_conf_t *njt_http_find_helper_hc(njt_cycle_t *cycle, njt_helper_hc_api_data_t *api_data);

static njt_helper_health_check_conf_t *njt_http_find_helper_hc_by_name_and_type(njt_cycle_t *cycle, njt_str_t * hc_type,njt_str_t *upstream_name);

//static njt_str_t njt_http_grpc_hc_svc = njt_string("/grpc.health.v1.Health/Check");


static njt_int_t njt_hc_http_peer_add_map(njt_helper_health_check_conf_t *hhccf, 
                njt_http_upstream_rr_peer_t *peer);

static njt_int_t njt_hc_stream_peer_add_map(njt_helper_health_check_conf_t *hhccf, 
            njt_stream_upstream_rr_peer_t *stream_peer);

static bool njt_hc_http_check_peer(njt_helper_health_check_conf_t *hhccf, 
                njt_http_upstream_rr_peer_t *peer);

static bool njt_hc_stream_check_peer(njt_helper_health_check_conf_t *hhccf, 
                njt_stream_upstream_rr_peer_t *peer);
/* 
 * by zhaokang 
 * stream function
 */
static njt_int_t njt_stream_health_check_send_handler(njt_event_t *wev);
 
static njt_int_t njt_stream_health_check_recv_handler(njt_event_t *rev);

static njt_int_t njt_stream_health_check_common_update(njt_stream_health_check_peer_t *hc_peer, njt_int_t status);

static njt_int_t njt_stream_health_check_match_all(njt_connection_t *c);

static njt_int_t njt_stream_match_block(njt_helper_hc_api_data_t *api_data, njt_helper_health_check_conf_t *hhccf);

static void njt_stream_health_check_timer_handler(njt_event_t *ev);

static void njt_stream_hc_kv_flush_conf_info(njt_helper_health_check_conf_t *hhccf);

static void njt_stream_hc_kv_flush_confs(njt_helper_main_conf_t *hmcf);

static void njt_stream_health_check_recovery_confs();

njt_stream_upstream_srv_conf_t *njt_stream_find_upstream_by_name(njt_cycle_t *cycle, njt_str_t *name);

void njt_http_upstream_traver(void *ctx,njt_int_t (*item_handle)(void *ctx,njt_http_upstream_srv_conf_t *));

void njt_stream_upstream_traver(void *ctx,njt_int_t (*item_handle)(void *ctx,njt_stream_upstream_srv_conf_t *));

static void
njt_http_health_check_close_connection(njt_connection_t *c);


static njt_health_checker_t njt_health_checks[] = {
        {    
                NJT_STREAM_MODULE,
                0,   
                njt_string("stcp"),
                0,   
                njt_stream_health_check_send_handler,
                njt_stream_health_check_recv_handler,
                NULL,
                NULL,
                NULL
        },   

        {    
                NJT_STREAM_MODULE,
                1,
                njt_string("sudp"),
                0,   
                njt_stream_health_check_send_handler,
                njt_stream_health_check_recv_handler,
                NULL,
                NULL,
                NULL
        },  

//        {
//                NJT_STREAM_MODULE,
//                0,
//                njt_string("tcp"),
//                1,
//                njt_http_health_check_tcp_handler,
//                njt_http_health_check_tcp_handler,
//                NULL,
//                NULL,
//                NULL
//        },
//
//        {
//                NJT_STREAM_MODULE,
//                SOCK_DGRAM,
//                njt_string("udp"),
//                1,
//                njt_http_health_check_tcp_handler,
//                njt_http_health_check_tcp_handler,
//                NULL,
//                NULL,
//                NULL
//        },
        {
                NJT_HTTP_MODULE,
                0,
                njt_string("http"),
                0,
                njt_http_health_check_http_write_handler,
                njt_http_health_check_http_read_handler,
                NULL,
                njt_http_health_check_http_process,
                njt_http_health_check_http_update_status
        },

        {
                NJT_HTTP_MODULE,
                0,
                njt_string("grpc"),
                0,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL
        },
 
    {
                0,
                0,
                njt_null_string,
                0,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL
        }
};


extern njt_module_t njt_helper_health_check_module;


static njt_int_t
njt_http_health_check_peek_one_byte(njt_connection_t *c) {
    u_char buf[1];
    njt_int_t n;
    njt_err_t err;

    n = c->recv(c,buf,1);

    err = njt_socket_errno;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, err,
                   "http check upstream recv(): %i, fd: %d",
                   n, c->fd);

    if (n == 1 || (n == -1 && err == NJT_EAGAIN)) {
        return NJT_OK;
    }

    return NJT_ERROR;
}

//static njt_int_t njt_http_health_check_tcp_handler(njt_event_t *ev) {
//    njt_connection_t *c;
//    njt_int_t rc;
//
//    c = ev->data;
//
//    rc = njt_http_health_check_peek_one_byte(c);
//
//    return rc;
//}

static void
njt_http_health_check_dummy_handler(njt_event_t *ev) {
    njt_log_debug0(NJT_LOG_DEBUG_EVENT, ev->log, 0,
                   "http health check dummy handler");
}

static njt_int_t
njt_http_health_check_http_write_handler(njt_event_t *wev) {
    njt_connection_t *c;
    njt_http_health_check_peer_t *hc_peer;
    ssize_t n, size;
    njt_http_health_check_conf_ctx_t *cf_ctx;
    njt_helper_health_check_conf_t *hhccf;

    c = wev->data;
    hc_peer = c->data;
    hhccf = hc_peer->hhccf;
    cf_ctx = hhccf->ctx;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0, "http check send.");


    if (hc_peer->send_buf == NULL) {
        hc_peer->send_buf = njt_create_temp_buf(hc_peer->pool, njt_pagesize);
        if (hc_peer->send_buf == NULL) {
            /*log the send buf allocation failure*/
            njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                           "malloc failure of the send buffer for health check.");
            return NJT_ERROR;
        }
        /*Fill in the buff*/
        hc_peer->send_buf->last = njt_snprintf(hc_peer->send_buf->last,
                                               hc_peer->send_buf->end - hc_peer->send_buf->last, "GET %V HTTP/1.1" CRLF,
                                               &cf_ctx->uri);
        hc_peer->send_buf->last = njt_snprintf(hc_peer->send_buf->last,
                                               hc_peer->send_buf->end - hc_peer->send_buf->last,
                                               "Connection: close" CRLF);
        hc_peer->send_buf->last = njt_snprintf(hc_peer->send_buf->last,
                                               hc_peer->send_buf->end - hc_peer->send_buf->last, "Host: %V" CRLF,
                                               &cf_ctx->upstream->host);
        hc_peer->send_buf->last = njt_snprintf(hc_peer->send_buf->last,
                                               hc_peer->send_buf->end - hc_peer->send_buf->last,
                                               "User-Agent: njet (health-check)" CRLF);
        hc_peer->send_buf->last = njt_snprintf(hc_peer->send_buf->last,
                                               hc_peer->send_buf->end - hc_peer->send_buf->last, CRLF);
    }

    size = hc_peer->send_buf->last - hc_peer->send_buf->pos;

    n = c->send(c, hc_peer->send_buf->pos,
                hc_peer->send_buf->last - hc_peer->send_buf->pos);

    if (n == NJT_ERROR) {
        return NJT_ERROR;
    }

    if (n > 0) {
        hc_peer->send_buf->pos += n;
        if (n == size) {
            wev->handler = njt_http_health_check_dummy_handler;

            if (njt_handle_write_event(wev, 0) != NJT_OK) {
                /*LOG the failure*/
                njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                               "write event handle error for health check");
                return NJT_ERROR;
            }
            return NJT_DONE;
        }
    }

    return NJT_AGAIN;
}

static void 
njt_stream_health_check_dummy_handler(njt_event_t *ev) {
    njt_log_debug0(NJT_LOG_DEBUG_EVENT, ev->log, 0,
                        "stream health check dummy handler");
}
static u_char* test_str=(u_char*)"njet health check";
static njt_int_t
njt_stream_health_check_send_handler(njt_event_t *wev) {
    njt_connection_t                    *c;
    njt_int_t                            rc;
    njt_stream_health_check_peer_t      *hc_peer;
    njt_uint_t                           size;
    njt_int_t                            n;

    njt_stream_health_check_conf_ctx_t  *shccc;
    njt_helper_health_check_conf_t      *hhccf;
    njt_stream_match_t                  *match;

    c = wev->data;
    hc_peer = c->data;
    rc = NJT_OK;

    hhccf = hc_peer->hhccf;
    shccc = hhccf->ctx;
    match = shccc->match;

    if(  match == NULL || match->send.len == 0){
        if(hhccf->protocol == 1){
            n = c->send(c,test_str,18);
            if(n<=0){
                rc = NJT_ERROR;
            }
        }
        return rc;
    }


//    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
//                   "$$$ njt_stream_health_check_send_handler ... ");
    if (hc_peer->send_buf == NULL) {
        hc_peer->send_buf = njt_pcalloc(hc_peer->pool, sizeof(njt_buf_t));
        if (hc_peer->send_buf == NULL) {
            /*log the send buf allocation failure*/
            njt_log_debug0(NJT_LOG_ERR, njt_cycle->log, 0,
                           "malloc failure of the send buffer for health check.");
            return NJT_ERROR;
        }

        hc_peer->send_buf->pos = match->send.data;
        hc_peer->send_buf->last = hc_peer->send_buf->pos + match->send.len;
    }
    size = hc_peer->send_buf->last - hc_peer->send_buf->pos;
    n = c->send(c, hc_peer->send_buf->pos,size);
    if (n == NJT_ERROR) {
        return NJT_ERROR;
    }
    if (n > 0) {
        hc_peer->send_buf->pos += n;
        if (n == (njt_int_t)size) {
            wev->handler = njt_stream_health_check_dummy_handler;
            if (njt_handle_write_event(wev, 0) != NJT_OK) {
                /*LOG the failure*/
                njt_log_debug0(NJT_LOG_ERR, njt_cycle->log, 0,
                               "write event handle error for health check");
                return NJT_ERROR;
            }
            return NJT_DONE;
        }
    }
    return rc;
}

inline static njt_int_t 
njt_stream_hc_init_buf(njt_connection_t *c){
    njt_stream_health_check_peer_t      *hc_peer;
    njt_stream_health_check_conf_ctx_t  *shccc;
    njt_helper_health_check_conf_t      *hhccf;
    njt_stream_match_t                  *match;
    njt_uint_t                           size;

    hc_peer = c->data;
    hhccf = hc_peer->hhccf;
    shccc = hhccf->ctx;
    match = shccc->match;

    //plus max is 0x40000LL
    size = njt_pagesize;
    if(hc_peer->recv_buf == NULL){
        // if(hc_peer->hcscf->match->regex == NGX_CONF_UNSET_PTR || hc_peer->hcscf->match->regex == NULL){
          size = match->expect.len;
        // }
        hc_peer->recv_buf = njt_create_temp_buf(hc_peer->pool, size);
        if(hc_peer->recv_buf == NULL){
            njt_log_error(NJT_LOG_EMERG, c->log, 0,"cannot alloc ngx_buf_t in check match all");
            return NJT_ERROR;
        }
        hc_peer->recv_buf->last = hc_peer->recv_buf->pos = hc_peer->recv_buf->start;
    }
    return NJT_OK;
}


static njt_int_t 
njt_stream_health_check_match_all(njt_connection_t *c){
    njt_stream_health_check_peer_t        *hc_peer;
    njt_buf_t                             *b;
    ssize_t                                n, size;
    njt_int_t                              rc;

    njt_stream_health_check_conf_ctx_t    *shccc;
    njt_helper_health_check_conf_t        *hhccf;
    njt_stream_match_t                    *match;

    hc_peer = c->data;
    hhccf = hc_peer->hhccf;
    shccc = hhccf->ctx;
    match = shccc->match;

    rc = njt_stream_hc_init_buf(c);
    if(rc != NJT_OK){
        return rc;
    }

//    {
        b = hc_peer->recv_buf;
        size = b->end - b->last;
        n = c->recv(c, b->last, size);
        if (n > 0) {
            b->last += n;
            /*link chain buffer*/
            if (b->last == b->end) {

                if(njt_strncmp(match->expect.data, hc_peer->recv_buf->start,
                               match->expect.len) == 0){
                    return NJT_OK;
                }
            }
        }
        if (n == NJT_AGAIN) {
            if (njt_handle_read_event(c->read, 0) != NJT_OK) {
                njt_log_debug0(NJT_LOG_ERR, njt_cycle->log, 0,"read event handle error for health check");
                return NJT_ERROR;
            }
            return NJT_AGAIN;
        }
        if (n == NJT_ERROR) {
            njt_log_debug0(NJT_LOG_ERR, njt_cycle->log, 0,"read error for health check");
        }
//        break;
//    }
    return NJT_ERROR;
}

static njt_int_t
njt_stream_health_check_recv_handler(njt_event_t *rev) {
       njt_connection_t                    *c;

//    njt_int_t                           rc;
    njt_stream_health_check_peer_t        *hc_peer;
//    u_char buf[4];
//    njt_int_t size;
    njt_stream_health_check_conf_ctx_t    *shccc;
    njt_helper_health_check_conf_t        *hhccf;
    njt_stream_match_t                    *match;

    c = rev->data;
    hc_peer = c->data;
    hhccf = hc_peer->hhccf;
    shccc = hhccf->ctx;
    match = shccc->match;
    if( match == NULL || match->expect.len == 0 ) {
        return njt_http_health_check_peek_one_byte(c);
    }

//    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
//                   "### njt_stream_health_check_recv_handler ...");


    return njt_stream_health_check_match_all(c);
}

static njt_int_t
njt_http_health_check_http_read_handler(njt_event_t *rev) {
    njt_connection_t *c;
    njt_http_health_check_peer_t *hc_peer;
    ssize_t n, size;
    njt_buf_t *b;
    njt_int_t rc;
    njt_chain_t *chain, *node;
    njt_health_check_http_parse_t *hp;
    njt_http_health_check_conf_ctx_t *cf_ctx;
    njt_helper_health_check_conf_t *hhccf;

    c = rev->data;
    hc_peer = c->data;
    hhccf = hc_peer->hhccf;
    cf_ctx = hhccf->ctx;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0, "http check recv.");


    /*Init the internal parser*/
    if (hc_peer->parser == NULL) {
        hp = njt_pcalloc(hc_peer->pool, sizeof(njt_http_health_check_peer_t));
        if (hp == NULL) {
            /*log*/
            njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                           "memory allocation error for health check.");
            return NJT_ERROR;
        }

        hp->stage = NJT_HTTP_PARSE_STATUS_LINE;
        hp->process = njt_health_check_http_parse_status_line;

        hc_peer->parser = hp;
    }

    for (;;) {

        if (hc_peer->recv_buf == NULL) {
            b = njt_create_temp_buf(hc_peer->pool, njt_pagesize);
            if (b == NULL) {
                /*log*/
                njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                               "recv buffer memory allocation error for health check.");
                return NJT_ERROR;
            }
            hc_peer->recv_buf = b;
        }

        b = hc_peer->recv_buf;
        size = b->end - b->last;

        n = c->recv(c, b->last, size);

        if (n > 0) {
            b->last += n;

            rc = cf_ctx->checker->process(hc_peer);
            if (rc == NJT_ERROR) {
                return NJT_ERROR;
            }

            /*link chain buffer*/
            if (b->last == b->end) {

                hp = hc_peer->parser;

                if (hp->stage != NJT_HTTP_PARSE_BODY) {
                    /*log. The status and headers are too large to be hold in one buffer*/
                    njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                                   "status and headers exceed one page size");
                    return NJT_ERROR;
                }

                chain = njt_alloc_chain_link(hc_peer->pool);
                if (chain == NULL) {
                    /*log and process the error*/
                    njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                                   "memory allocation of the chain buf failed.");
                    return NJT_ERROR;
                }

                chain->buf = b;
                chain->next = NULL;

                node = hc_peer->recv_chain;
                if (node == NULL) {
                    hc_peer->recv_chain = chain;
                } else {
                    hc_peer->last_chain_node->next = chain;
                }
                hc_peer->last_chain_node = chain;

                /*Reset the recv buffer*/
                hc_peer->recv_buf = NULL;
            }

            continue;
        }

        if (n == NJT_AGAIN) {
            if (njt_handle_read_event(rev, 0) != NJT_OK) {
                /*log*/
                njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                               "read event handle error for health check");
                return NJT_ERROR;
            }
            return NJT_AGAIN;
        }

        if (n == NJT_ERROR) {
            /*log*/
            njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                           "read error for health check");
            return NJT_ERROR;
        }

        break;
    }


    hp = hc_peer->parser;
    hp->done = 1;
    rc = cf_ctx->checker->process(hc_peer);

    if (rc == NJT_DONE) {
        return NJT_DONE;
    }

    if (rc == NJT_AGAIN) {
        /* the connection is shutdown*/
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "connection is shutdown");
        return NJT_ERROR;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_health_check_http_match_header(njt_http_match_header_t *input,
                                        njt_http_health_check_peer_t *hc_peer) {
    njt_health_check_http_parse_t *hp;
    njt_int_t rc;
    njt_uint_t i;
    njt_int_t n;
    njt_table_elt_t *headers, *header;

    hp = hc_peer->parser;
    headers = hp->headers.elts;

    rc = NJT_OK;

    switch (input->operation) {

        case NJT_HTTP_MATCH_CONTAIN:

            rc = NJT_ERROR;
            for (i = 0; i < hp->headers.nelts; i++) {
                header = headers + i;
                if (header->key.len != input->key.len) {
                    continue;
                }

                if (njt_strncmp(header->key.data, input->key.data, input->key.len) == 0) {
                    return NJT_OK;
                }
            }
            break;

        case NJT_HTTP_MATCH_NOT_CONTAIN:
            rc = NJT_OK;
            for (i = 0; i < hp->headers.nelts; i++) {
                header = headers + i;
                if (header->key.len != input->key.len) {
                    continue;
                }

                if (njt_strncmp(header->key.data, input->key.data, input->key.len) == 0) {
                    return NJT_ERROR;
                }
            }

            break;

            /*If the header doesn't occur means failure*/
        case NJT_HTTP_MATCH_EQUAL:

            rc = NJT_ERROR;

            for (i = 0; i < hp->headers.nelts; i++) {

                header = headers + i;
                if (header->key.len != input->key.len) {
                    continue;
                }

                if (njt_strncmp(header->key.data, input->key.data, input->key.len) == 0) {
                    if (header->value.len != input->value.len) {
                        return NJT_ERROR;
                    }

                    if (njt_strncmp(header->value.data, input->value.data,
                                    input->value.len) == 0) {
                        return NJT_OK;
                    }

                    return NJT_ERROR;
                }
            }

            break;

        case NJT_HTTP_MATCH_NOT_EQUAL:

            rc = NJT_ERROR;

            for (i = 0; i < hp->headers.nelts; i++) {

                header = headers + i;
                if (header->key.len != input->key.len) {
                    continue;
                }

                if (njt_strncmp(header->key.data, input->key.data, input->key.len) == 0) {

                    if (header->value.len != input->value.len) {
                        return NJT_OK;
                    }

                    if (njt_strncmp(header->value.data, input->value.data,
                                    input->value.len) == 0) {
                        return NJT_ERROR;
                    }

                    return NJT_OK;
                }
            }

            break;

#if (NJT_PCRE)
        case NJT_HTTP_MATCH_REG_MATCH:

            if (input->regex == NULL) {
                return NJT_ERROR;
            }

            rc = NJT_ERROR;

            for (i = 0; i < hp->headers.nelts; i++) {

                header = headers + i;
                if (header->key.len != input->key.len) {
                    continue;
                }

                if (njt_strncmp(header->key.data, input->key.data, input->key.len) == 0) {

                    n = njt_regex_exec(input->regex, &header->value, NULL, 0);

                    if (n == NJT_REGEX_NO_MATCHED) {
                        return NJT_ERROR;
                    }

                    return NJT_OK;
                }
            }

            break;

        case NJT_HTTP_MATCH_NOT_REG_MATCH:

            if (input->regex == NULL) {
                return NJT_ERROR;
            }

            rc = NJT_ERROR;

            for (i = 0; i < hp->headers.nelts; i++) {

                header = headers + i;
                if (header->key.len != input->key.len) {
                    continue;
                }

                if (njt_strncmp(header->key.data, input->key.data, input->key.len) == 0) {

                    n = njt_regex_exec(input->regex, &header->value, NULL, 0);

                    if (n == NJT_REGEX_NO_MATCHED) {
                        return NJT_OK;
                    }

                    return NJT_ERROR;
                }
            }

            break;
#endif
        default:
            njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                           "unsupported operation %u.\n", input->operation);
            return NJT_ERROR;
    }

    return rc;
}


static njt_int_t
njt_http_health_check_http_match_body(njt_http_match_body_t *body,
                                      njt_http_health_check_peer_t *hc_peer) {
    njt_int_t n;
    njt_str_t result;
    njt_health_check_http_parse_t *hp;
    njt_buf_t *content;
    njt_uint_t size;
    njt_chain_t *node;


    /* recreate the body buffer*/
    content = njt_create_temp_buf(hc_peer->pool, njt_pagesize);
    if (content == NULL) {
        /*log*/
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "content buffer allocation error for health check");
        return NJT_ERROR;
    }

    hp = hc_peer->parser;
    if (hc_peer->recv_chain == NULL) {

        size = hc_peer->recv_buf->last - hp->body_start;
        content->last = njt_snprintf(content->last, size, "%s", hp->body_start);

    } else {

        node = hc_peer->recv_chain;
        size = node->buf->last - hp->body_start;
        content->last = njt_snprintf(content->last, size, "%s", hp->body_start);

        if (node->buf->end == node->buf->last) {
            node = node->next;
            size = njt_pagesize - size;
            content->last = njt_snprintf(content->last, size, "%s", node->buf->pos);
        }

    }

    result.data = content->start;
    result.len = content->last - content->start;

    n = njt_regex_exec(body->regex, &result, NULL, 0);

    if (body->operation == NJT_HTTP_MATCH_REG_MATCH) {

        if (n == NJT_REGEX_NO_MATCHED) {
            return NJT_ERROR;
        } else {
            return NJT_OK;
        }

    } else if (body->operation == NJT_HTTP_MATCH_NOT_REG_MATCH) {

        if (n == NJT_REGEX_NO_MATCHED) {
            return NJT_OK;
        } else {
            return NJT_ERROR;
        }
    } else {
        return NJT_ERROR;
    }

    return NJT_OK;
}

static njt_int_t
njt_http_health_check_http_update_status(njt_http_health_check_peer_t *hc_peer,
                                         njt_int_t status) {
    njt_int_t rc;
    njt_health_check_http_parse_t *hp;
    njt_http_match_t *match;
    njt_uint_t i, result;
    njt_http_match_code_t *code, *codes;
    njt_http_match_header_t *header, *headers;
    njt_http_health_check_conf_ctx_t *cf_ctx;
    njt_helper_health_check_conf_t *hhccf;

    hp = hc_peer->parser;
    hhccf = hc_peer->hhccf;
    cf_ctx = hhccf->ctx;
    match = cf_ctx->match;

    /*By default, we change the code is in range 200 or 300*/
    rc = NJT_ERROR;
    if (hp == NULL) {
        rc = njt_http_health_check_common_update(hc_peer, rc);
        return rc;
    }

    if (match == NULL) {
        if (hp->code >= 200 && hp->code <= 399) {
            rc = NJT_OK;
        }
        goto set_status;
    }

    /*an empty match*/
    if (!match->conditions) {
        goto set_status;
    }

    /*check the status*/

    /*step1 check code*/
    if (match->status.codes.nelts == 0) {
        goto headers;
    }

    result = 0;
    codes = match->status.codes.elts;
    for (i = 0; i < match->status.codes.nelts; i++) {
        code = codes + i;
        if (code->single) {
            if (hp->code == code->code) {
                result = 1;
                break;
            }
        } else {
            if (hp->code >= code->code && hp->code <= code->last_code) {
                result = 1;
                break;
            }
        }
    }

    if (match->status.not_operation) {
        result = !result;
    }

    rc = result ? NJT_OK : NJT_ERROR;

    if (rc == NJT_ERROR) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "match status error.");
        goto set_status;
    }

    headers:
    /*step2 check header*/
    headers = match->headers.elts;
    for (i = 0; i < match->headers.nelts; i++) {
        header = headers + i;

        rc = njt_http_health_check_http_match_header(header, hc_peer);
        if (rc == NJT_ERROR) {
            njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "match header %V error.",
                           &header->value);
            goto set_status;
        }

    }

    /*step3 check body*/
    if (match->body.regex) {
        rc = njt_http_health_check_http_match_body(&match->body, hc_peer);
        /*regular expression match of the body*/
        if (rc == NJT_ERROR) {
            njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "match body %V error.",
                           &match->body.value);
            goto set_status;
        }
    }

    set_status:
    rc = njt_http_health_check_common_update(hc_peer, rc);
    return rc;
}

static njt_int_t
njt_http_health_check_http_process(njt_http_health_check_peer_t *hc_peer) {
    njt_health_check_http_parse_t *parse;
    njt_int_t rc;

    parse = hc_peer->parser;
    rc = parse->process(hc_peer);

    return rc;
}

/*We assume the status line and headers are located in one buffer*/
static njt_int_t
njt_health_check_http_parse_status_line(njt_http_health_check_peer_t *hc_peer) {
    u_char ch;
    u_char *p;
    njt_health_check_http_parse_t *hp;
    njt_buf_t *b;

    enum {
        sw_start = 0,
        sw_H,
        sw_HT,
        sw_HTT,
        sw_HTTP,
        sw_first_major_digit,
        sw_major_digit,
        sw_first_minor_digit,
        sw_minor_digit,
        sw_status,
        sw_space_after_status,
        sw_status_text,
        sw_almost_done
    } state;

    hp = hc_peer->parser;
    b = hc_peer->recv_buf;
    state = hp->state;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

        switch (state) {

            /* "HTTP/" */
            case sw_start:
                switch (ch) {
                    case 'H':
                        state = sw_H;
                        break;
                    default:
                        return NJT_ERROR;
                }
                break;

            case sw_H:
                switch (ch) {
                    case 'T':
                        state = sw_HT;
                        break;
                    default:
                        return NJT_ERROR;
                }
                break;

            case sw_HT:
                switch (ch) {
                    case 'T':
                        state = sw_HTT;
                        break;
                    default:
                        return NJT_ERROR;
                }
                break;

            case sw_HTT:
                switch (ch) {
                    case 'P':
                        state = sw_HTTP;
                        break;
                    default:
                        return NJT_ERROR;
                }
                break;

            case sw_HTTP:
                switch (ch) {
                    case '/':
                        state = sw_first_major_digit;
                        break;
                    default:
                        return NJT_ERROR;
                }
                break;

                /* the first digit of major HTTP version */
            case sw_first_major_digit:
                if (ch < '1' || ch > '9') {
                    return NJT_ERROR;
                }

                state = sw_major_digit;
                break;

                /* the major HTTP version or dot */
            case sw_major_digit:
                if (ch == '.') {
                    state = sw_first_minor_digit;
                    break;
                }

                if (ch < '0' || ch > '9') {
                    return NJT_ERROR;
                }

                break;

                /* the first digit of minor HTTP version */
            case sw_first_minor_digit:
                if (ch < '0' || ch > '9') {
                    return NJT_ERROR;
                }

                state = sw_minor_digit;
                break;

                /* the minor HTTP version or the end of the request line */
            case sw_minor_digit:
                if (ch == ' ') {
                    state = sw_status;
                    break;
                }

                if (ch < '0' || ch > '9') {
                    return NJT_ERROR;
                }

                break;

                /* HTTP status code */
            case sw_status:
                if (ch == ' ') {
                    break;
                }

                if (ch < '0' || ch > '9') {
                    return NJT_ERROR;
                }

                hp->code = hp->code * 10 + (ch - '0');

                if (++hp->count == 3) {
                    state = sw_space_after_status;
                }

                break;

                /* space or end of line */
            case sw_space_after_status:
                switch (ch) {
                    case ' ':
                        state = sw_status_text;
                        break;
                    case '.':                    /* IIS may send 403.1, 403.2, etc */
                        state = sw_status_text;
                        break;
                    case CR:
                        break;
                    case LF:
                        goto done;
                    default:
                        return NJT_ERROR;
                }
                break;

                /* any text until end of line */
            case sw_status_text:
                switch (ch) {
                    case CR:
                        hp->status_text_end = p;
                        state = sw_almost_done;
                        break;
                    case LF:
                        hp->status_text_end = p;
                        goto done;
                }

                if (hp->status_text == NULL) {
                    hp->status_text = p;
                }

                break;

                /* end of status line */
            case sw_almost_done:
                switch (ch) {
                    case LF:
                        goto done;
                    default:
                        return NJT_ERROR;
                }
        }
    }

    b->pos = p;
    hp->state = state;

    return NJT_AGAIN;

    done:

    b->pos = p + 1;
    hp->state = sw_start;

    /*begin to process headers*/

    hp->stage = NJT_HTTP_PARSE_HEADER;
    hp->process = njt_health_check_http_process_headers;

    hp->process(hc_peer);

    return NJT_OK;
}

static njt_int_t
njt_health_check_http_parse_header_line(njt_http_health_check_peer_t *hc_peer) {
    u_char c, ch, *p;
    njt_health_check_http_parse_t *hp;
    njt_buf_t *b;

    enum {
        sw_start = 0,
        sw_name,
        sw_space_before_value,
        sw_value,
        sw_space_after_value,
        sw_almost_done,
        sw_header_almost_done
    } state;

    b = hc_peer->recv_buf;
    hp = hc_peer->parser;
    state = hp->state;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

        switch (state) {

            /* first char */
            case sw_start:

                switch (ch) {
                    case CR:
                        hp->header_end = p;
                        state = sw_header_almost_done;
                        break;
                    case LF:
                        hp->header_end = p;
                        goto header_done;
                    default:
                        state = sw_name;
                        hp->header_name_start = p;

                        c = (u_char) (ch | 0x20);
                        if (c >= 'a' && c <= 'z') {
                            break;
                        }

                        if (ch >= '0' && ch <= '9') {
                            break;
                        }

                        return NJT_ERROR;
                }
                break;

                /* header name */
            case sw_name:
                c = (u_char) (ch | 0x20);
                if (c >= 'a' && c <= 'z') {
                    break;
                }

                if (ch == ':') {
                    hp->header_name_end = p;
                    state = sw_space_before_value;
                    break;
                }

                if (ch == '-') {
                    break;
                }

                if (ch >= '0' && ch <= '9') {
                    break;
                }

                if (ch == CR) {
                    hp->header_name_end = p;
                    hp->header_start = p;
                    hp->header_end = p;
                    state = sw_almost_done;
                    break;
                }

                if (ch == LF) {
                    hp->header_name_end = p;
                    hp->header_start = p;
                    hp->header_end = p;
                    goto done;
                }

                return NJT_ERROR;

                /* space* before header value */
            case sw_space_before_value:
                switch (ch) {
                    case ' ':
                        break;
                    case CR:
                        hp->header_start = p;
                        hp->header_end = p;
                        state = sw_almost_done;
                        break;
                    case LF:
                        hp->header_start = p;
                        hp->header_end = p;
                        goto done;
                    default:
                        hp->header_start = p;
                        state = sw_value;
                        break;
                }
                break;

                /* header value */
            case sw_value:
                switch (ch) {
                    case ' ':
                        hp->header_end = p;
                        state = sw_space_after_value;
                        break;
                    case CR:
                        hp->header_end = p;
                        state = sw_almost_done;
                        break;
                    case LF:
                        hp->header_end = p;
                        goto done;
                }
                break;

                /* space* before end of header line */
            case sw_space_after_value:
                switch (ch) {
                    case ' ':
                        break;
                    case CR:
                        state = sw_almost_done;
                        break;
                    case LF:
                        goto done;
                    default:
                        state = sw_value;
                        break;
                }
                break;

                /* end of header line */
            case sw_almost_done:
                switch (ch) {
                    case LF:
                        goto done;
                    default:
                        return NJT_ERROR;
                }

                /* end of header */
            case sw_header_almost_done:
                switch (ch) {
                    case LF:
                        goto header_done;
                    default:
                        return NJT_ERROR;
                }
        }
    }

    b->pos = p;
    hp->state = state;

    return NJT_AGAIN;

    done:

    b->pos = p + 1;
    hp->state = sw_start;

    return NJT_OK;

    header_done:

    b->pos = p + 1;
    hp->state = sw_start;
    hp->body_start = b->pos;

    return NJT_DONE;
}

static njt_int_t
njt_health_check_http_process_headers(njt_http_health_check_peer_t *hc_peer) {
    njt_int_t rc;
    njt_table_elt_t *h;
    njt_health_check_http_parse_t *hp;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "http process header.");

    hp = hc_peer->parser;

    if (hp->headers.size == 0) {
        rc = njt_array_init(&hp->headers, hc_peer->pool, 4,
                            sizeof(njt_table_elt_t));
        if (rc != NJT_OK) {
            return NJT_ERROR;
        }
    }

    for (;;) {

        rc = njt_health_check_http_parse_header_line(hc_peer);

        if (rc == NJT_OK) {
            h = njt_array_push(&hp->headers);
            if (h == NULL) {
                return NJT_ERROR;
            }

            njt_memzero(h, sizeof(njt_table_elt_t));
            h->hash = 1;
            h->key.data = hp->header_name_start;
            h->key.len = hp->header_name_end - hp->header_name_start;

            h->value.data = hp->header_start;
            h->value.len = hp->header_end - hp->header_start;

            njt_log_debug4(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                           "http header \"%*s: %*s\"",
                           h->key.len, h->key.data, h->value.len,
                           h->value.data);

            if (h->key.len == njt_strlen("Transfer-Encoding")
                && h->value.len == njt_strlen("chunked")
                && njt_strncasecmp(h->key.data, (u_char *) "Transfer-Encoding",
                                   h->key.len) == 0
                && njt_strncasecmp(h->value.data, (u_char *) "chunked",
                                   h->value.len) == 0) {
                hp->chunked = 1;
            }

            if (h->key.len == njt_strlen("Content-Length")
                && njt_strncasecmp(h->key.data, (u_char *) "Content-Length",
                                   h->key.len) == 0) {
                hp->content_length_n = njt_atoof(h->value.data, h->value.len);

                if (hp->content_length_n == NJT_ERROR) {

                    njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                                   "invalid fetch content length");
                    return NJT_ERROR;
                }
            }

            continue;
        }

        if (rc == NJT_DONE) {
            break;
        }

        if (rc == NJT_AGAIN) {
            return NJT_AGAIN;
        }

        /*http header parse error*/
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "http process header error.");
        return NJT_ERROR;
    }

    /*TODO check if the first buffer is used out*/
    hp->stage = NJT_HTTP_PARSE_BODY;
    hp->process = njt_health_check_http_process_body;

    return hp->process(hc_peer);
}

static njt_int_t
njt_health_check_http_process_body(njt_http_health_check_peer_t *hc_peer) {
    njt_health_check_http_parse_t *hp;

    hp = hc_peer->parser;

    if (hp->done) {
        return NJT_DONE;
    }
    return NJT_OK;
}

struct njt_http_grpc_hc_peer_s {
    njt_uint_t peer_id;
    njt_helper_health_check_conf_t *hhccf;
    njt_pool_t *pool;
    njt_peer_connection_t pc;
    njt_buf_t *send_buf;
    njt_buf_t *recv_buf;
    njt_chain_t *recv_chain;
    njt_chain_t *last_chain_node;
    void *parser;
};
typedef struct njt_http_grpc_hc_peer_s njt_http_grpc_hc_peer_t;

static void
njt_http_hc_grpc_loop_peer(njt_helper_health_check_conf_t *hhccf, njt_http_upstream_rr_peer_t *peer) {
    njt_int_t rc;
    njt_http_grpc_hc_peer_t *hc_peer = NULL;
    njt_http_request_t *r;
    njt_http_upstream_t *u;
    njt_http_upstream_state_t *state;
    njt_chain_t **last;
    njt_health_check_http_parse_t *hp;
    njt_list_part_t *part;
    njt_table_elt_t *header;
    njt_uint_t i;
    njt_peer_connection_t *pc;
    void *grpc_con;
    void *input_filter_ctx;
    njt_http_health_check_conf_ctx_t *cf_ctx;
    njt_pool_t *pool;

    pool = njt_create_pool(njt_pagesize, njt_cycle->log);
    if (pool == NULL) {
        /*log the malloc failure*/
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                      "create pool failure for health check.");
        goto OUT;
    }
    hc_peer = njt_pcalloc(pool, sizeof(njt_http_grpc_hc_peer_t));
    if (hc_peer == NULL) {
        /*log the malloc failure*/
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                      "memory allocate failure for health check.");
        goto OUT;
    }
    hc_peer->pool = pool;


    hc_peer->pc.sockaddr = njt_pcalloc(pool, sizeof(struct sockaddr));
    if (hc_peer->pc.sockaddr == NULL) {
        /*log the malloc failure*/
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                      "memory allocate failure for health check.");
        goto OUT;
    }
    njt_memcpy(hc_peer->pc.sockaddr, peer->sockaddr, sizeof(struct sockaddr));

    hc_peer = njt_calloc(sizeof(njt_http_grpc_hc_peer_t), njt_cycle->log);
    if (hc_peer == NULL) {
        /*log the malloc failure*/
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "memory allocate failure for health check.");
        goto OUT;
    }

    hc_peer->peer_id = peer->id;
    hc_peer->hhccf = hhccf;

    /*customized the peer's port*/
    if (hhccf->port) {
        njt_inet_set_port(hc_peer->pc.sockaddr, hhccf->port);
    }

    hc_peer->pc.socklen = peer->socklen;
    hc_peer->pc.name = &peer->name;
    hc_peer->pc.get = njt_event_get_peer;
    hc_peer->pc.log = njt_cycle->log;
    hc_peer->pc.log_error = NJT_ERROR_ERR;


    /* allocate memory, create context for grpc health check */

    r = njt_pcalloc(pool, sizeof(njt_http_request_t));
    if (r == NULL) {
        goto OUT;
    }

    grpc_con = njt_http_grpc_hc_create_grpc_on(pool);
    if (grpc_con == NULL) {
        goto OUT;
    }

    input_filter_ctx = njt_http_grpc_hc_create_in_filter_ctx(pool, r, grpc_con);
    if (input_filter_ctx == NULL) {
        goto OUT;
    }

    /*Init the internal parser*/
    if (hc_peer->parser == NULL) {
        hp = njt_pcalloc(pool, sizeof(njt_http_grpc_hc_peer_t));
        if (hp == NULL) {
            njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                           "memory allocation error for health check.");
            goto OUT;
        }

        hc_peer->parser = hp;
    } else {
        hp = hc_peer->parser;
    }

    hp->state = njt_http_grpc_hc_st_start;
    hp->start = njt_current_msec;
    hp->code = GRPC_STATUS_CODE_INVALID;

    part = &r->headers_in.headers.part;
    part->nelts = sizeof(njt_http_grpc_hc_headers) / sizeof(njt_http_v2_header_t);
    part->next = NULL;
    part->elts = njt_pcalloc(pool, sizeof(njt_table_elt_t) * part->nelts);
    if (part->elts == NULL) {
        goto OUT;
    };

    header = part->elts;
    for (i = 0; i < part->nelts; i++) {
        header[i].key = njt_http_grpc_hc_headers[i].name;
        header[i].value = njt_http_grpc_hc_headers[i].value;
        header[i].lowcase_key = header[i].key.data;
        header[i].hash = njt_hash_key(header[i].key.data, header[i].key.len);
    }

    pc = &hc_peer->pc;
    pc->type = SOCK_STREAM;

    //r->hc = hc_peer; //zyg delete
    njt_http_set_ctx(r, hc_peer, njt_helper_health_check_module);
    cf_ctx = hhccf->ctx;
    r->unparsed_uri = cf_ctx->gsvc;
    r->uri.len = r->unparsed_uri.len;
    r->uri.data = r->unparsed_uri.data;
    r->pool = pool;
    r->method = NJT_HTTP_POST;
    r->main = r;

    u = njt_pcalloc(pool, sizeof(njt_http_upstream_t));
    if (u == NULL) {
        goto OUT;
    }
    r->upstream = u;

    rc = njt_event_connect_peer(pc);

    if (rc == NJT_ERROR || rc == NJT_DECLINED) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                      "health check connect to peer %V failed.", &peer->name);
        goto OUT;
    }

    r->connection = pc->connection;
    u->peer.connection = pc->connection;
    u->input_filter_ctx = input_filter_ctx;
    u->writer.pool = pool;
    u->writer.connection = pc->connection;

    last = njt_pcalloc(pool, sizeof(njt_chain_t *));
    if (last == NULL) {
        goto OUT;
    };
    u->writer.last = last;
    u->start_time = njt_current_msec;

    state = njt_pcalloc(pool, sizeof(njt_http_upstream_state_t));
    if (state == NULL) {
        goto OUT;
    }

    cf_ctx = hhccf->ctx;
    u->state = state;
    u->output.filter_ctx = r;
    u->output.output_filter = njt_http_grpc_body_output_filter;
    u->write_event_handler = njt_http_upstream_send_request_handler;
    u->read_event_handler = njt_http_upstream_process_header;

    njt_http_grpc_hc_set_upstream(u);

    rc = njt_http_grpc_create_request(r);

    pc->connection->data = r;
    pc->connection->log = njt_cycle->log;
    pc->connection->pool = pool;
    pc->connection->write->data = pc->connection;
    pc->connection->read->data = pc->connection;
    pc->connection->write->handler = njt_http_grpc_hc_handler;
    pc->connection->read->handler = njt_http_upstream_handler;

    return;

    OUT:
    /*release the memory and update the statistics*/
    njt_http_health_check_common_update((njt_http_health_check_peer_t *) hc_peer, NJT_ERROR);
    return;
}

static void
njt_http_grpc_hc_handler(njt_event_t *wev) {
    njt_connection_t *c;
    njt_http_request_t *r;
    njt_http_grpc_hc_peer_t *hc_peer;
    njt_http_upstream_t *u;
    njt_health_check_http_parse_t *hp;
    ssize_t n, size;
    njt_peer_connection_t *pc;
    njt_http_health_check_conf_ctx_t *cf_ctx;
    njt_helper_health_check_conf_t *hhccf;

    njt_uint_t result = NJT_ERROR;

    c = wev->data;
    r = c->data;
    u = r->upstream;
    //hc_peer = r->hc;  zyg
    hc_peer = njt_http_get_module_ctx(r, njt_helper_health_check_module);
    hp = hc_peer->parser;
    pc = &hc_peer->pc;
    hhccf = hc_peer->hhccf;
    cf_ctx = hhccf->ctx;

    if ((hp->state >= njt_http_grpc_hc_st_sent) || (njt_current_msec - hp->start + 1000 >= hhccf->timeout)) {

        if ((hp->code != GRPC_STATUS_CODE_INVALID) || (njt_current_msec - hp->start + 1000 >= hhccf->timeout)) {
            if ((hp->code == GRPC_STATUS_CODE_OK) || (hp->code == cf_ctx->gstatus)) {
                result = NJT_OK;
            }

            njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0,
                          "grpc hc %s for peer %V", (result == NJT_OK) ? "OK" : "ERROR", hc_peer->pc.name);

            /* update peer status and free the resource */
            njt_http_health_check_common_update((njt_http_health_check_peer_t *) hc_peer, result);
            return;
        }

        njt_add_timer(wev, 1000);
        return;
    }

    size = u->request_bufs->buf->last - u->request_bufs->buf->pos;
    n = pc->connection->send(pc->connection, u->request_bufs->buf->pos, size);

    if (n == NJT_ERROR) {
        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0,
                      "grpc hc ERROR for peer %V", hc_peer->pc.name);

        /* update peer status and free the resource */
        njt_http_health_check_common_update((njt_http_health_check_peer_t *) hc_peer, NJT_ERROR);
        return;
    }

    njt_add_timer(wev, 1000);

    if (n > 0) {
        u->request_bufs->buf->pos += n;
        if (n == size) {
            hp->state = njt_http_grpc_hc_st_sent;
            if (njt_handle_write_event(wev, 0) != NJT_OK) {
                /*LOG the failure*/
                njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                               "write event handle error for health check");
            }
        }
    }
}


static njt_health_checker_t *
njt_http_get_health_check_type(njt_str_t *str) {
    njt_uint_t i;

    for (i = 0; /* void */ ; i++) {

        if (njt_health_checks[i].type == 0) {
            break;
        }

        if (str->len != njt_health_checks[i].name.len) {
            continue;
        }

        if (njt_strncasecmp(str->data, njt_health_checks[i].name.data,
                            str->len) == 0) {
            return &njt_health_checks[i];
        }
    }

    return NULL;
}


static void
njt_http_health_check_close_connection(njt_connection_t *c)
{
    njt_pool_t  *pool;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "close http connection: %d", c->fd);

#if (NJT_HTTP_SSL)

    if (c->ssl) {
        if (njt_ssl_shutdown(c) == NJT_AGAIN) {
            c->ssl->handler = njt_http_health_check_close_connection;
            return;
        }
    }

#endif

#if (NJT_HTTP_V3)
    if (c->quic) {
        njt_http_v3_reset_stream(c);
    }
#endif

    c->destroyed = 1;

    pool = c->pool;

    njt_close_connection(c);

    njt_destroy_pool(pool);
}

static void njt_free_peer_resource(njt_http_health_check_peer_t *hc_peer) {
//    njt_pool_t *pool;
    njt_helper_health_check_conf_t *hhccf = hc_peer->hhccf;
//    pool = hc_peer->pool;
    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                  "free peer pool : upstream = %V   ref_count = %d",hc_peer->peer.name,hc_peer->hhccf->ref_count);

    njt_uint_t local_peer_id = hc_peer->peer_id;
    
    if (hc_peer->peer.connection) {
        njt_http_health_check_close_connection(hc_peer->peer.connection);
//        njt_close_connection(hc_peer->peer.connection);
    }

    if(hhccf->ref_count>0){
        hhccf->ref_count--;
    }

    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                "====http free peer check, peerid:%d ref_count=%d", local_peer_id, hhccf->ref_count); 
//    if (hc_peer->hhccf->disable) {
////        njt_destroy_pool(hc_peer->hhccf->pool);
//        --(hc_peer->hhccf->ref_count);
//    }

//    if (pool) {
//        njt_destroy_pool(pool);
//    }
//    return;
}


static void njt_stream_free_peer_resource(njt_stream_health_check_peer_t *hc_peer) {
    njt_pool_t *pool;


    pool = hc_peer->pool;
    njt_connection_t                *pc = hc_peer->peer.connection;
    njt_helper_health_check_conf_t *hhccf = hc_peer->hhccf;

    njt_uint_t local_peer_id = hc_peer->peer_id;
    if (pc) {
#if (NJT_STREAM_SSL)
        if (pc->ssl) {
            pc->ssl->no_wait_shutdown = 1;
            pc->ssl->no_send_shutdown = 1;

            (void) njt_ssl_shutdown(pc);
        }
#endif
        njt_close_connection(pc);
    }
    if(hhccf->ref_count>0){
        hhccf->ref_count--;
    }

        njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
            "====stream free peer check, peerid:%d ref_count=%d", local_peer_id, hhccf->ref_count);

//    if (hc_peer->hhccf->disable) {
//        njt_destroy_pool(hc_peer->hhccf->pool);
//    }

    if (pool) {
        njt_destroy_pool(pool);
    }
    return;
}

static njt_int_t
njt_http_health_check_update_status(njt_http_health_check_peer_t *hc_peer,
                                    njt_int_t status) {
    njt_int_t rc;
    njt_http_health_check_conf_ctx_t *cf_ctx;
    njt_helper_health_check_conf_t *hhccf;

    hhccf = hc_peer->hhccf;
    cf_ctx = hhccf->ctx;

    if (cf_ctx->checker->update == NULL) {
        rc = njt_http_health_check_common_update(hc_peer, status);
    } else {
        rc = cf_ctx->checker->update(hc_peer, status);
    }

    return rc;

}


static void njt_http_health_check_write_handler(njt_event_t *wev) {
    njt_connection_t *c;
    njt_http_health_check_peer_t *hc_peer;
    njt_int_t rc;
    njt_http_health_check_conf_ctx_t *cf_ctx;
    njt_helper_health_check_conf_t *hhccf;

    c = wev->data;
    hc_peer = c->data;
    hhccf = hc_peer->hhccf;
    cf_ctx = hhccf->ctx;
    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                  "write handler : upstream = %V   ref_count = %d",hc_peer->peer.name,hc_peer->hhccf->ref_count);
    if (wev->timedout) {
        /*log the case and update the peer status.*/
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "write action for health check timeout");
        njt_http_health_check_update_status(hc_peer, NJT_ERROR);
        return;
    }

    if (wev->timer_set) {
        njt_del_timer(wev);
    }
    if (hc_peer->hhccf->disable) {
        njt_free_peer_resource(hc_peer);
        return;
    }

    rc = cf_ctx->checker->write_handler(wev);
    if (rc == NJT_ERROR) {

        /*log the case and update the peer status.*/
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "write action error for health check");
        njt_http_health_check_update_status(hc_peer, NJT_ERROR);
        return;
    } else if (rc == NJT_DONE || rc == NJT_OK) {
        if (cf_ctx->checker->one_side) {
            njt_http_health_check_update_status(hc_peer, rc);
            return;
        }
    } else {
        /*AGAIN*/
    }

    if (!wev->timer_set) {
        njt_add_timer(wev, hhccf->timeout);
    }

    return;
}


static void njt_stream_health_check_write_handler(njt_event_t *wev) {
    njt_connection_t                   *c;
    njt_stream_health_check_peer_t     *hc_peer;
    njt_int_t                           rc;
    njt_stream_health_check_conf_ctx_t *cf_ctx;
    njt_helper_health_check_conf_t     *hhccf;

    c = wev->data;
    hc_peer = c->data;
    hhccf = hc_peer->hhccf;
    cf_ctx = hhccf->ctx;

    if (wev->timedout) {
        /*log the case and update the peer status.*/
        njt_log_debug0(NJT_LOG_DEBUG_STREAM, njt_cycle->log, 0,
                       "write action for health check timeout");
        njt_stream_health_check_common_update(hc_peer, NJT_ERROR);
        return;
    }

    if (wev->timer_set) {
        njt_del_timer(wev);
    }
    if (hc_peer->hhccf->disable) {
        njt_stream_free_peer_resource(hc_peer);
        return;
    }

    rc = cf_ctx->checker->write_handler(wev);
    wev->handler = njt_stream_health_check_dummy_handler;
    if (rc == NJT_ERROR) {

        /*log the case and update the peer status.*/
        njt_log_debug0(NJT_LOG_DEBUG_STREAM, njt_cycle->log, 0,
                       "write action error for health check");
        njt_stream_health_check_common_update(hc_peer, NJT_ERROR);
        return;
    } else if (rc == NJT_DONE || rc == NJT_OK) {
        if ((cf_ctx->match == NULL || cf_ctx->match->expect.len == 0)
            && hhccf->protocol == 0   //udp 等待接收 icmp
                ) {
            njt_stream_health_check_common_update(hc_peer, rc);
            return;
        }else{
            if(!c->read->timer_set){
                njt_event_add_timer(c->read,hhccf->timeout);
            }

        }

//        if (cf_ctx->checker->one_side) {
//            njt_stream_health_check_common_update(hc_peer, rc);
//            return;
//        }
    } else {
        /*AGAIN*/
    }

    if (!wev->timer_set) {
        njt_add_timer(wev, hhccf->timeout);
    }

    return;
}


static void njt_http_health_check_read_handler(njt_event_t *rev) {
    njt_connection_t *c;
    njt_http_health_check_peer_t *hc_peer;
    njt_int_t rc;
    njt_http_health_check_conf_ctx_t *cf_ctx;
    njt_helper_health_check_conf_t *hhccf;

    c = rev->data;
    hc_peer = c->data;
    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                  "read handler : upstream = %V   ref_count = %d",hc_peer->peer.name,hc_peer->hhccf->ref_count);

    hhccf = hc_peer->hhccf;
    cf_ctx = hhccf->ctx;

    if (rev->timedout) {

        /*log the case and update the peer status.*/
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "read action for health check timeout");
    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                  "====timeout, hc_peerid:%d  ref_count:%d",hc_peer->peer_id, hhccf->ref_count);
        njt_http_health_check_update_status(hc_peer, NJT_ERROR);
    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                  "====timeout, ref_count:%d",hhccf->ref_count);
        return;
    }

    if (rev->timer_set) {
        njt_del_timer(rev);
    }

    if (hc_peer->hhccf->disable) {
        njt_free_peer_resource(hc_peer);
        return;
    }

    rc = cf_ctx->checker->read_handler(rev);
    if (rc == NJT_ERROR) {
        /*log the case and update the peer status.*/
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "read action error for health check");
        njt_http_health_check_update_status(hc_peer, NJT_ERROR);
        return;
    } else if (rc == NJT_DONE) {
        njt_http_health_check_update_status(hc_peer, rc);
        return;
    } else {
        /*AGAIN*/
    }

    if (!rev->timer_set) {
        njt_add_timer(rev, hhccf->timeout);
    }

    return;
}


static void njt_stream_health_check_read_handler(njt_event_t *rev) {
    njt_connection_t                   *c;
    njt_stream_health_check_peer_t     *hc_peer;
    njt_int_t                           rc;
    njt_stream_health_check_conf_ctx_t *cf_ctx;
    njt_helper_health_check_conf_t     *hhccf;

    c = rev->data;
    hc_peer = c->data;
    hhccf = hc_peer->hhccf;
    cf_ctx = hhccf->ctx;

    if (rev->timedout) {
        if(hhccf->protocol == 1 && (cf_ctx->match == NULL || cf_ctx->match->expect.len == 0)){
            rc = NJT_OK;
        } else {
            rc = NJT_ERROR;
        }

        /*log the case and update the peer status.*/
        njt_log_debug0(NJT_LOG_DEBUG_STREAM, njt_cycle->log, 0,
                       "read action for health check timeout");
        njt_stream_health_check_common_update(hc_peer, rc);
        return;
    }
    if (hc_peer->hhccf->disable) {
        njt_stream_free_peer_resource(hc_peer);
        return;
    }

    if (rev->timer_set) {
        njt_del_timer(rev);
    }

    rc = cf_ctx->checker->read_handler(rev);
    if (rc == NJT_ERROR) {
        /*log the case and update the peer status.*/
        njt_log_debug0(NJT_LOG_DEBUG_STREAM, njt_cycle->log, 0,
                       "read action error for health check");
        njt_stream_health_check_common_update(hc_peer, NJT_ERROR);
        return;
    } else if (rc == NJT_DONE || rc == NJT_OK) { //TODO
        njt_stream_health_check_common_update(hc_peer, rc);
        return;
    } else {
        /*AGAIN*/
    }

    if (!rev->timer_set) {
        njt_add_timer(rev, hhccf->timeout);
    }

    return;
}


static void njt_update_peer(njt_http_upstream_srv_conf_t *uscf,
                            njt_http_upstream_rr_peer_t *peer,
                            njt_int_t status, njt_uint_t passes, njt_uint_t fails) {
    peer->hc_check_in_process = 0;
    // 如果是持久化，并且是reload后第一次进入不做。  如果peer已经down状态也不做
    if((uscf->mandatory == 1 && uscf->reload == 1 &&  uscf->persistent == 1 &&  peer->set_first_check == 0) || peer->down == 1 ) {
        peer->set_first_check = 1;
        return;
    }

    peer->hc_checks++;
    if (status == NJT_OK || status == NJT_DONE) {

        peer->hc_consecutive_fails = 0;
        peer->hc_last_passed = 1; //zyg

        if (peer->hc_last_passed) {
            peer->hc_consecutive_passes++;
        }

        if (peer->hc_consecutive_passes >= passes) {
            peer->hc_down = (peer->hc_down / 100 * 100);

            if (peer->hc_downstart != 0) {
                peer->hc_upstart = njt_time();
                peer->hc_downtime = peer->hc_downtime + (((njt_uint_t) ((njt_timeofday())->sec) * 1000 +
                                                          (njt_uint_t) ((njt_timeofday())->msec)) - peer->hc_downstart);
            }
            peer->hc_downstart = 0;//(njt_timeofday())->sec;

        }
//        if (uscf->mandatory == 1 && uscf->reload != 1 &&
//            peer->hc_checks == 1) {  //hclcf->plcf->upstream.upstream->reload
//            if (peer->down == 0) {
//                peer->hc_down = (peer->hc_down / 100 * 100);
//            }
//        }


    } else {

        peer->hc_fails++;
        peer->hc_consecutive_passes = 0;
        peer->hc_consecutive_fails++;


        /*Only change the status at the first time when fails number mets*/
        if (peer->hc_consecutive_fails == fails) {
            peer->hc_unhealthy++;

            peer->hc_down = (peer->hc_down / 100 * 100) + 1;

            peer->hc_downstart = (njt_uint_t) ((njt_timeofday())->sec) * 1000 +
                                 (njt_uint_t) ((njt_timeofday())->msec); //(peer->hc_downstart == 0 ?(njt_current_msec):(peer->hc_downstart));
        }
        peer->hc_last_passed = 0;

    }

    return;
}


static void njt_stream_update_peer(njt_stream_upstream_srv_conf_t *uscf,
                            njt_stream_upstream_rr_peer_t *peer,
                            njt_int_t status, njt_uint_t passes, njt_uint_t fails) {
    peer->hc_check_in_process = 0;

    // 如果是持久化，并且是reload后第一次进入不做。  如果peer已经down状态也不做
    if((uscf->mandatory == 1 && uscf->reload == 1 &&  uscf->persistent == 1 &&  peer->set_first_check == 0 ) || peer->down == 1 ) {
        peer->set_first_check = 1;
        return;
    }
    peer->hc_checks++;

    if (status == NJT_OK || status == NJT_DONE) {
//        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
//            "enable check peer: %V ",
//            &peer->name);

        peer->hc_consecutive_fails = 0;
        peer->hc_last_passed = 1; //zyg

        if (peer->hc_last_passed) {
            peer->hc_consecutive_passes++;
        }

        if (peer->hc_consecutive_passes >= passes) {
            peer->hc_down = (peer->hc_down / 100 * 100);

            if (peer->hc_downstart != 0) {
                peer->hc_upstart = njt_time();
                peer->hc_downtime = peer->hc_downtime + (((njt_uint_t) ((njt_timeofday())->sec) * 1000 +
                                                          (njt_uint_t) ((njt_timeofday())->msec)) - peer->hc_downstart);
            }
            peer->hc_downstart = 0;//(njt_timeofday())->sec;

        }
//        if (uscf->mandatory == 1 && uscf->reload != 1 &&
//            peer->hc_checks == 1) {  //hclcf->plcf->upstream.upstream->reload
//            if (peer->down == 0) {
//                peer->hc_down = (peer->hc_down / 100 * 100);
//            }
//        }


    } else {
        njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, 
            "disable check peer: %V ",
            &peer->name);

        peer->hc_fails++;
        peer->hc_consecutive_passes = 0;
        peer->hc_consecutive_fails++;

    /*TODO*/
        /*Only change the status at the first time when fails number mets*/
        if (peer->hc_consecutive_fails == fails) {
            peer->hc_unhealthy++;

            peer->hc_down = (peer->hc_down / 100 * 100) + 1;

            peer->hc_downstart = (njt_uint_t) ((njt_timeofday())->sec) * 1000 +
                                 (njt_uint_t) ((njt_timeofday())->msec); //(peer->hc_downstart == 0 ?(njt_current_msec):(peer->hc_downstart));
        }
        peer->hc_last_passed = 0;

    }

    return;
}

static njt_int_t
njt_http_health_check_common_update(njt_http_health_check_peer_t *hc_peer,
                                    njt_int_t status) {

    // njt_uint_t                      peer_id;
    njt_http_upstream_srv_conf_t    *uscf;
    njt_http_upstream_rr_peers_t    *peers;
    njt_http_upstream_rr_peer_t     *peer;
    njt_lvlhsh_query_t              lhq;
    njt_uint_t                      rc;
    njt_hc_http_same_peer_t         *http_lvlhsh_value;
    njt_queue_t                     *q;
    njt_hc_http_peer_element        *http_ele;


    /*Find the right peer and update it's status*/
    // peer_id = hc_peer->peer_id;
    uscf = njt_http_find_upstream_by_name(njet_master_cycle, &hc_peer->hhccf->upstream_name);
    if (uscf == NULL) {
        njt_log_error(NJT_LOG_ERR, hc_peer->pool->log, 0, "upstream %V isn't found", &hc_peer->hhccf->upstream_name);
        goto end;
    }
    peers = (njt_http_upstream_rr_peers_t *) uscf->peer.data;

    njt_http_upstream_rr_peers_wlock(peers);

    //compare update_id
    if(hc_peer->update_id == peers->update_id){
        //just use saved map for update
        //get all peers of has same servername
        lhq.key = hc_peer->server;
        lhq.key_hash = njt_murmur_hash2(lhq.key.data, lhq.key.len);
        lhq.proto = &njt_hc_lvlhsh_proto;

        //find
        rc = njt_lvlhsh_find(&hc_peer->hhccf->servername_to_peers, &lhq);
        if(rc != NJT_OK){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "njt_http_health_check_common_update not found  from map");
        
            njt_http_upstream_rr_peers_unlock(peers);
            njt_free_peer_resource(hc_peer);
            return NJT_ERROR;
        }else{
            http_lvlhsh_value = lhq.value;
            //update self
            njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                    "hc check peer update status peer:%V peerid:%d status:%d",
                    &http_lvlhsh_value->peer->server, http_lvlhsh_value->peer->id, status);
            njt_update_peer(uscf, http_lvlhsh_value->peer, status, hc_peer->hhccf->passes, hc_peer->hhccf->fails);

            //update others
            q = njt_queue_head(&http_lvlhsh_value->datas);
            for (; q != njt_queue_sentinel(&http_lvlhsh_value->datas); q = njt_queue_next(q)) {
                http_ele = njt_queue_data(q, njt_hc_http_peer_element, ele_queue);
                njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                    "hc same peer update status peer:%V peerid:%d status:%d",
                    &http_ele->peer->server, http_ele->peer->id, status);
                njt_update_peer(uscf, http_ele->peer, status, hc_peer->hhccf->passes, hc_peer->hhccf->fails);
            }
        }
    }else{
        //list all peers of has same servername
        for (peer = peers->peer; peer != NULL; peer = peer->next) {
            if(peer->server.len == hc_peer->server.len
                && njt_memcmp(peer->server.data, hc_peer->server.data, peer->server.len) == 0){
                njt_update_peer(uscf, peer, status, hc_peer->hhccf->passes, hc_peer->hhccf->fails);
                njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                    "hc update peer update status peer:%V peerid:%d status:%d",
                    &peer->server, peer->id, status);
            }
        }
        if (peer == NULL && peers->next) {
            for (peer = peers->next->peer; peer != NULL; peer = peer->next) {
                if(peer->server.len == hc_peer->server.len
                    && njt_memcmp(peer->server.data, hc_peer->server.data, peer->server.len) == 0){
                    njt_update_peer(uscf, peer, status, hc_peer->hhccf->passes, hc_peer->hhccf->fails);
                    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                        "hc update peer update status peer:%V peerid:%d status:%d",
                        &peer->server, peer->id, status);
                }
            }
        }
    }

    njt_http_upstream_rr_peers_unlock(peers);

    end:
    njt_free_peer_resource(hc_peer);
    return NJT_OK;
}


static njt_int_t
njt_stream_health_check_common_update(njt_stream_health_check_peer_t *hc_peer,
                                    njt_int_t status) {

    // njt_uint_t                      peer_id;
    njt_stream_upstream_srv_conf_t *uscf;
    njt_stream_upstream_rr_peers_t *peers;
    njt_stream_upstream_rr_peer_t  *peer;
    njt_lvlhsh_query_t              lhq;
    njt_uint_t                      rc;
    njt_hc_stream_same_peer_t       *stream_lvlhsh_value;
    njt_queue_t                     *q;
    njt_hc_stream_peer_element      *stream_ele;


    /*Find the right peer and update it's status*/
    // peer_id = hc_peer->peer_id;
    uscf = njt_stream_find_upstream_by_name(njet_master_cycle, &hc_peer->hhccf->upstream_name);
    if (uscf == NULL) {
        njt_log_error(NJT_LOG_ERR, hc_peer->pool->log, 0, "upstream %V isn't found", &hc_peer->hhccf->upstream_name);
        goto end;
    }

    peers = (njt_stream_upstream_rr_peers_t *) uscf->peer.data;

    njt_stream_upstream_rr_peers_wlock(peers);
    //compare update_id
    if(hc_peer->hhccf->update_id == peers->update_id){
        //just use saved map for update
        //get all peers of has same servername
        lhq.key = hc_peer->server;
        lhq.key_hash = njt_murmur_hash2(lhq.key.data, lhq.key.len);
        lhq.proto = &njt_hc_lvlhsh_proto;

        //find
        rc = njt_lvlhsh_find(&hc_peer->hhccf->servername_to_peers, &lhq);
        if(rc != NJT_OK){
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                    "njt_stream_health_check_common_update not found  from map");
                njt_stream_upstream_rr_peers_unlock(peers);
                return NJT_ERROR;
        }else{
            stream_lvlhsh_value = lhq.value;
            //update self
            njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                "hc stream check peer update status peer:%V peerid:%d status:%d",
                &stream_lvlhsh_value->peer->server, stream_lvlhsh_value->peer->id, status);
            njt_stream_update_peer(uscf, stream_lvlhsh_value->peer, status, hc_peer->hhccf->passes, hc_peer->hhccf->fails);

            //update others
            q = njt_queue_head(&stream_lvlhsh_value->datas);
            for (; q != njt_queue_sentinel(&stream_lvlhsh_value->datas); q = njt_queue_next(q)) {
                stream_ele = njt_queue_data(q, njt_hc_stream_peer_element, ele_queue);
                njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                    "hc stream same peer update status peer:%V peerid:%d status:%d",
                    &stream_ele->peer->server, stream_ele->peer->id, status);
                njt_stream_update_peer(uscf, stream_ele->peer, status, hc_peer->hhccf->passes, hc_peer->hhccf->fails);
            }
        }
    }else{
        //list all peers of has same servername
        for (peer = peers->peer; peer != NULL; peer = peer->next) {
            if(peer->server.len == hc_peer->server.len
                && njt_memcmp(peer->server.data, hc_peer->server.data, peer->server.len) == 0){
                njt_stream_update_peer(uscf, peer, status, hc_peer->hhccf->passes, hc_peer->hhccf->fails);
                njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                    "hc stream update peer update status peer:%V peerid:%d status:%d", &peer->server, peer->id, status);
            }
        }
        if (peer == NULL && peers->next) {
            for (peer = peers->next->peer; peer != NULL; peer = peer->next) {
                if(peer->server.len == hc_peer->server.len
                    && njt_memcmp(peer->server.data, hc_peer->server.data, peer->server.len) == 0){
                    njt_stream_update_peer(uscf, peer, status, hc_peer->hhccf->passes, hc_peer->hhccf->fails);
                    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                        "hc stream update peer update status peer:%V peerid:%d status:%d", &peer->server, peer->id, status);
                }
            }
        }
    }

    njt_stream_upstream_rr_peers_unlock(peers);

end:
    njt_stream_free_peer_resource(hc_peer);
    return NJT_OK;
}

static njt_int_t njy_hc_api_data2_ssl_cf(njt_helper_hc_api_data_t *api_data, njt_helper_health_check_conf_t *hhccf) {
    njt_str_t      tmp_str;

    if(api_data->hc_type.len == njt_sudp_ck_type.len
       && njt_strncmp(api_data->hc_type.data, njt_sudp_ck_type.data, njt_sudp_ck_type.len) == 0 
       && api_data->hc_data->ssl != NULL && 1 == api_data->hc_data->ssl->enable) {
        return UDP_NOT_SUPPORT_TLS;
    }

    if(!api_data->hc_data->is_ssl_set){
        return HC_SUCCESS;
    }
    if(api_data->hc_data->ssl->enable){
        hhccf->ssl.ssl_enable = 1;
    }

    if(api_data->hc_data->ssl->ntls){
        hhccf->ssl.ssl_enable = 1;
        hhccf->ssl.ntls_enable = 1;
    }

    hhccf->ssl.ssl_session_reuse = api_data->hc_data->ssl->session_reuse ? 1 : 0;

    if (api_data->hc_data->ssl->ciphers.len <= 0) {
        njt_str_set(&hhccf->ssl.ssl_ciphers, "DEFAULT");
    } else {
        njt_str_copy_pool(hhccf->pool, hhccf->ssl.ssl_ciphers, api_data->hc_data->ssl->ciphers, return HC_SERVER_ERROR);
    }

    if(api_data->hc_data->ssl->protocols.len > 0){
        njt_str_copy_pool(hhccf->pool, hhccf->ssl.ssl_protocol_str, api_data->hc_data->ssl->protocols,
                    return HC_SERVER_ERROR);
        
        if(NJT_OK != njt_json_parse_ssl_protocols(api_data->hc_data->ssl->protocols, &hhccf->ssl.ssl_protocols)){
            return HC_BODY_ERROR;
            // hhccf->ssl.ssl_protocols = (NJT_CONF_BITMASK_SET | NJT_SSL_TLSv1 | NJT_SSL_TLSv1_1 | NJT_SSL_TLSv1_2);
        }
    }else{
        hhccf->ssl.ssl_protocols = (NJT_CONF_BITMASK_SET | NJT_SSL_TLSv1 | NJT_SSL_TLSv1_1 | NJT_SSL_TLSv1_2);
    }

    if(api_data->hc_data->ssl->name.len > 0){
        njt_str_copy_pool(hhccf->pool, hhccf->ssl.ssl_name, api_data->hc_data->ssl->name, return HC_SERVER_ERROR);
    }

    hhccf->ssl.ssl_server_name = api_data->hc_data->ssl->serverName ? 1 : 0;
    hhccf->ssl.ssl_verify = api_data->hc_data->ssl->verify ? 1 : 0;
    hhccf->ssl.ssl_verify_depth = api_data->hc_data->ssl->verifyDepth <= 0 ? 1 : api_data->hc_data->ssl->verifyDepth;
    if(api_data->hc_data->ssl->trustedCertificate.len > 0){
        tmp_str = api_data->hc_data->ssl->trustedCertificate;
        njt_str_copy_pool(hhccf->pool, hhccf->ssl.ssl_trusted_certificate, tmp_str, return HC_SERVER_ERROR);
    }

    if(api_data->hc_data->ssl->crl.len > 0){
        tmp_str = api_data->hc_data->ssl->crl;
        njt_str_copy_pool(hhccf->pool, hhccf->ssl.ssl_crl, tmp_str, return HC_SERVER_ERROR);
    }

    if(api_data->hc_data->ssl->certificate.len > 0){
        tmp_str = api_data->hc_data->ssl->certificate;
        njt_str_copy_pool(hhccf->pool, hhccf->ssl.ssl_certificate, tmp_str, return HC_SERVER_ERROR);
    }

    if(api_data->hc_data->ssl->certificateKey.len > 0){
        tmp_str = api_data->hc_data->ssl->certificateKey;
        njt_str_copy_pool(hhccf->pool, hhccf->ssl.ssl_certificate_key, tmp_str, return HC_SERVER_ERROR);
    }

    if(api_data->hc_data->ssl->encCertificate.len > 0){
        tmp_str = api_data->hc_data->ssl->encCertificate;
        njt_str_copy_pool(hhccf->pool, hhccf->ssl.ssl_enc_certificate, tmp_str, return HC_SERVER_ERROR);
    }

    if(api_data->hc_data->ssl->encCertificate.len > 0){
        tmp_str = api_data->hc_data->ssl->encCertificate;
        njt_str_copy_pool(hhccf->pool, hhccf->ssl.ssl_enc_certificate, tmp_str, return HC_SERVER_ERROR);
    }

    if(api_data->hc_data->ssl->encCertificateKey.len > 0){
        tmp_str = api_data->hc_data->ssl->encCertificateKey;
        njt_str_copy_pool(hhccf->pool, hhccf->ssl.ssl_enc_certificate_key, tmp_str, return HC_SERVER_ERROR);
    }
//    njt_array_t *ssl_passwords;
//    njt_array_t *ssl_conf_commands;

    hhccf->ssl.ssl = njt_pcalloc(hhccf->pool, sizeof(njt_ssl_t));
    if (hhccf->ssl.ssl == NULL) {
        return HC_SERVER_ERROR;
    }
    hhccf->ssl.ssl->log = hhccf->log;
    if (njt_helper_hc_set_ssl(hhccf, &hhccf->ssl) != NJT_OK) {
        return HC_BODY_ERROR;
    } else {
        return HC_SUCCESS;
    }
}


static njt_int_t njt_hc_api_data2_common_cf(njt_helper_hc_api_data_t *api_data, njt_helper_health_check_conf_t *hhccf) {
    njt_http_health_check_conf_ctx_t *hhccc;
    njt_int_t rc;

    njt_str_copy_pool(hhccf->pool, hhccf->upstream_name, api_data->upstream_name,
                      njt_log_error(NJT_LOG_EMERG, hhccf->log, 0,
                                    "health check helper create dynamic pool error "); return HC_SERVER_ERROR);

    if(api_data->hc_data == NULL){
        return HC_SUCCESS;
    }

    if(api_data->hc_data->is_interval_set && api_data->hc_data->interval.len > 0){
        njt_int_t i_interval;
        i_interval = njt_parse_time(&api_data->hc_data->interval, 0);
        if(NJT_ERROR == i_interval  || i_interval <= 0){
            return HC_BODY_ERROR;
        }else{
            hhccf->interval = i_interval;
        }
    }else{
        hhccf->interval = NJT_HTTP_HC_INTERVAL;
    }

    if(api_data->hc_data->is_jitter_set && api_data->hc_data->jitter.len > 0){
        njt_int_t i_jitter;
        i_jitter = njt_parse_time(&api_data->hc_data->jitter, 0);
        if(NJT_ERROR == i_jitter  || i_jitter < 0){
            return HC_BODY_ERROR;
        }else{
            hhccf->jitter = i_jitter;
        }
    }else{
        hhccf->jitter = 0;
    }

    if(api_data->hc_data->is_timeout_set && api_data->hc_data->timeout.len > 0){
        njt_int_t i_timeout;
        i_timeout = njt_parse_time(&api_data->hc_data->timeout, 0);
        if(NJT_ERROR == i_timeout || i_timeout <= 0){
            return HC_BODY_ERROR;
        }else{
            hhccf->timeout = i_timeout;
        }
    }else{
        hhccf->timeout = NJT_HTTP_HC_CONNECT_TIMEOUT;
    }    

    // hhccf->interval = api_data->hc_data->interval <= 0 ? NJT_HTTP_HC_INTERVAL : api_data->hc_data->interval;
    // hhccf->jitter = api_data->hc_data->jitter <= 0 ? 0 : api_data->hc_data->jitter;
    // hhccf->timeout = api_data->hc_data->timeout <= 0 ? NJT_HTTP_HC_CONNECT_TIMEOUT : api_data->hc_data->timeout;
    hhccf->port = api_data->hc_data->port;
    hhccf->passes = api_data->hc_data->passes == 0 ? 1 : api_data->hc_data->passes;
    hhccf->fails = api_data->hc_data->fails == 0 ? 1 : api_data->hc_data->fails;
    if (hhccf->type == NJT_HTTP_MODULE) {
        hhccc = hhccf->ctx;
        if(api_data->hc_data->http != NULL && api_data->hc_data->http->uri.len > 0){
            njt_str_copy_pool(hhccf->pool, hhccc->uri, api_data->hc_data->http->uri, return HC_SERVER_ERROR);
            rc = njt_http_match_block(api_data, hhccf);
            if (rc != HC_SUCCESS) {
                return rc;
            }
            //todo grpc  void *pglcf;//njt_http_grpc_loc_conf_t gsvc gstatus
        }
    }

    /*
        by zhaokang
    */
    if (hhccf->type == NJT_STREAM_MODULE) {

        rc = njt_stream_match_block(api_data, hhccf);
        if (rc != HC_SUCCESS) {
            return rc;
        }    
    }

    rc = njy_hc_api_data2_ssl_cf(api_data, hhccf);
    return rc;
}


static njt_int_t njt_hc_api_add_conf(njt_log_t *log, njt_helper_hc_api_data_t *api_data, njt_int_t sync) {
    njt_health_checker_t                    *checker;
    njt_http_upstream_srv_conf_t            *uscf;
    njt_helper_health_check_conf_t          *hhccf;
    njt_cycle_t                             *cycle = (njt_cycle_t *) njt_cycle;
    njt_pool_t                              *hc_pool;
    njt_http_health_check_conf_ctx_t        *hhccc;
    njt_http_upstream_rr_peers_t            *peers;
    njt_stream_upstream_rr_peers_t          *stream_peers;
    njt_int_t                               rc = HC_SUCCESS;

    if (api_data->hc_type.len == 0 || api_data->upstream_name.len == 0) {
        njt_log_error(NJT_LOG_ERR, log, 0, " type and upstream must be set !!");
        return HC_BODY_ERROR;
    }

    if(api_data->hc_data == NULL){
        njt_log_error(NJT_LOG_ERR, log, 0, " hc data must be set !!");
        return HC_BODY_ERROR;
    }

    if (api_data->hc_data->is_port_set && (api_data->hc_data->port < 0 || api_data->hc_data->port > 65535)) {
        njt_log_error(NJT_LOG_ERR, log, 0, " port is %i , port only allowed in 1-65535", api_data->hc_data->port);
        return PORT_NOT_ALLOW;
    }

    hhccf = njt_http_find_helper_hc(cycle, api_data);
    if (hhccf != NULL) {
        njt_log_error(NJT_LOG_ERR, log, 0, "find upstream %V hc, double set", &api_data->upstream_name);
        return HC_DOUBLE_SET;
    }
    if(api_data->hc_type.len == njt_stcp_ck_type.len
       && njt_strncmp(api_data->hc_type.data, njt_stcp_ck_type.data, njt_stcp_ck_type.len) == 0) {
        hhccf = njt_http_find_helper_hc_by_name_and_type(cycle,&njt_sudp_ck_type,&api_data->upstream_name);
    } else if(api_data->hc_type.len == njt_sudp_ck_type.len
              && njt_strncmp(api_data->hc_type.data, njt_sudp_ck_type.data, njt_sudp_ck_type.len) == 0) {
        hhccf = njt_http_find_helper_hc_by_name_and_type(cycle,&njt_stcp_ck_type,&api_data->upstream_name);
    }
    if (hhccf != NULL) {
        njt_log_error(NJT_LOG_ERR, log, 0, "find upstream %V hc, double set", &api_data->upstream_name);
        return HC_DOUBLE_SET;
    }
    hc_pool = njt_create_dynamic_pool(NJT_MIN_POOL_SIZE, cycle->log);
    if (hc_pool == NULL) {
        njt_log_error(NJT_LOG_ERR, log, 0, "health check helper create dynamic pool error ");
        rc = HC_SERVER_ERROR;
        goto err;
    }
    njt_sub_pool(cycle->pool, hc_pool);
    hhccf = njt_pcalloc(hc_pool, sizeof(njt_helper_health_check_conf_t));
    if (hhccf == NULL) {
        njt_log_error(NJT_LOG_ERR, log, 0, "health check helper alloc hhccf mem error");
        rc = HC_SERVER_ERROR;
        goto err;
    }
    njt_queue_init(&hhccf->queue);
    hhccf->pool = hc_pool;
    hhccf->log = cycle->log;
    checker = njt_http_get_health_check_type(&api_data->hc_type);
    if (checker == NULL) {
        rc = HC_TYPE_NOT_FOUND;
        goto err;
    }
    hhccf->type = checker->type;
    hhccf->type_str = checker->name;
    hhccf->protocol = checker->protocol;
    hhccf->first = 1;
    if (checker->type == NJT_HTTP_MODULE) {
        uscf = njt_http_find_upstream_by_name(njet_master_cycle, &api_data->upstream_name);
        if (uscf == NULL) {
            njt_log_error(NJT_LOG_ERR, log, 0, "not find http upstream: %V", &api_data->upstream_name);
            rc = HC_UPSTREAM_NOT_FOUND;
            goto err;
        }
        hhccc = njt_pcalloc(hc_pool, sizeof(njt_http_health_check_conf_ctx_t));
        if (hhccf == NULL) {
            njt_log_error(NJT_LOG_EMERG, log, 0, "health check helper alloc hhccc error ");
            rc = HC_SERVER_ERROR;
            goto err;
        }
        hhccc->upstream = uscf;
        hhccc->checker = checker;
        hhccf->ctx = hhccc;
        hhccf->mandatory = uscf->mandatory;
        hhccf->persistent = uscf->persistent;
        peers = uscf->peer.data;
        hhccf->update_id = peers->update_id;
    }

    /*
        by zhaokang 
        stream module should't in http module 
    */
    if (checker->type == NJT_STREAM_MODULE) {
        njt_stream_health_check_conf_ctx_t     *shccc;
        njt_stream_upstream_srv_conf_t         *suscf;

        suscf = njt_stream_find_upstream_by_name(njet_master_cycle, &api_data->upstream_name);    
        if (suscf == NULL) {
            njt_log_error(NJT_LOG_ERR, log, 0, "not find stream upstream: %V", &api_data->upstream_name);
            rc = HC_UPSTREAM_NOT_FOUND;
            goto err;
        }

        shccc = njt_pcalloc(hc_pool, sizeof(njt_stream_health_check_conf_ctx_t));
        if (shccc == NULL) {
            njt_log_error(NJT_LOG_EMERG, log, 0, "health check helper alloc stream health check ctx error");
            rc = HC_SERVER_ERROR;
            goto err;
        }    
        
        shccc->upstream = suscf;
        shccc->checker = checker;

        hhccf->ctx = shccc;
        hhccf->mandatory = suscf->mandatory;
        hhccf->persistent = suscf->persistent;
        stream_peers = suscf->peer.data;
        hhccf->update_id = stream_peers->update_id;
    }

    rc = njt_hc_api_data2_common_cf(api_data, hhccf);
    if (rc != HC_SUCCESS) {
        if(rc != UDP_NOT_SUPPORT_TLS )
            rc = HC_BODY_ERROR;
        goto err;
    }
    njt_http_health_check_add(hhccf, sync);
    return rc;

    err:
    if (hc_pool) {
        njt_destroy_pool(hc_pool);
    }
    return rc;
}


static njt_int_t njt_http_match_block(njt_helper_hc_api_data_t *api_data, njt_helper_health_check_conf_t *hhccf) {
    njt_http_match_t        *match;
    njt_int_t               rc;
    njt_uint_t              i;
    njt_str_t               *header;
    health_check_http_header_item_t *header_item;
    njt_str_t               tmp_str;

    njt_http_health_check_conf_ctx_t *hhccc = hhccf->ctx;
    if(api_data->hc_data == NULL || !api_data->hc_data->is_http_set){
        return HC_SUCCESS;
    }

    if(api_data->hc_data->http->is_body_set && api_data->hc_data->http->body.len > 0){
        tmp_str = api_data->hc_data->http->body;
        njt_str_copy_pool(hhccf->pool, hhccc->body, tmp_str, return HC_SERVER_ERROR);
    }
    
    if(api_data->hc_data->http->is_status_set && api_data->hc_data->http->status.len > 0){
        tmp_str = api_data->hc_data->http->status;
        njt_str_copy_pool(hhccf->pool, hhccc->status, tmp_str, return HC_SERVER_ERROR);
    }

    if(api_data->hc_data->http->is_header_set && api_data->hc_data->http->header->nelts > 0){
        njt_array_init(&hhccc->headers, hhccf->pool, api_data->hc_data->http->header->nelts, sizeof(njt_str_t));
        for (i = 0; i < api_data->hc_data->http->header->nelts; ++i) {
            header_item = get_health_check_http_header_item(api_data->hc_data->http->header, i);
            header = njt_array_push(&hhccc->headers);
            tmp_str = *(header_item);
            njt_str_copy_pool(hhccf->pool, header[i], tmp_str, return HC_SERVER_ERROR);
        }
    }

    match = njt_helper_http_match_create(hhccf);
    if (match == NULL) {
        njt_log_error(NJT_LOG_EMERG, hhccf->log, 0, "match create error");
        return HC_SERVER_ERROR;
    }
    hhccc->match = match;
    match->defined = 1;
    if (njt_array_init(&match->status.codes, hhccf->pool, 4,
                       sizeof(njt_http_match_code_t)) != NJT_OK) {
        njt_log_error(NJT_LOG_EMERG, hhccf->log, 0, "status code array init error");
        return HC_SERVER_ERROR;
    }
    if (njt_array_init(&match->headers, hhccf->pool, 4,
                       sizeof(njt_http_match_header_t)) != NJT_OK) {
        njt_log_error(NJT_LOG_EMERG, hhccf->log, 0, "match header array init error");
        return HC_SERVER_ERROR;
    }
    rc = njt_http_match(api_data, hhccf);
    if (rc == NJT_OK) {
        return HC_SUCCESS;
    } else {
        return HC_BODY_ERROR;
    }

}

/*
    by zhaokang
    stream : {
        "send"      : "xxx",
        "expect" : "yyy"
    }
*/
char* njt_hex2bin(njt_str_t *d, njt_str_t *s, int count);
static njt_int_t 
njt_stream_match_block(njt_helper_hc_api_data_t *api_data, njt_helper_health_check_conf_t *hhccf) {
    njt_stream_health_check_conf_ctx_t *shccc; 
    njt_stream_match_t                 *match;
    njt_str_t                          val;
    char *p = NULL;
    /* stream health check context */
    shccc = hhccf->ctx;

    shccc->match = njt_pcalloc(hhccf->pool, sizeof(njt_stream_match_t)); 
    if (shccc->match == NULL) {
        njt_log_error(NJT_LOG_EMERG, hhccf->log, 0, "stream match create error");
        return HC_SERVER_ERROR;
    }

    match = shccc->match;
    if (api_data == NULL || api_data->hc_data == NULL || !api_data->hc_data->is_stream_set
        || api_data->hc_data->stream->send.len < 1) {
//        njt_log_error(NJT_LOG_EMERG, hhccf->log, 0, "stream->send value is null");
//        return HC_BODY_ERROR;
        njt_str_null(&match->send);
        njt_str_null(&shccc->send);
    } else {
        val = api_data->hc_data->stream->send;
        shccc->send.data = njt_pcalloc(hhccf->pool, val.len);
        shccc->send.len  = val.len;
        njt_memcpy(shccc->send.data, val.data, val.len);

        match->send.data = njt_pcalloc(hhccf->pool, val.len);
        match->send.len  = val.len;
        p = njt_hex2bin(&match->send, &shccc->send, val.len);
        if(NULL ==p) {
            njt_log_error(NJT_LOG_EMERG, hhccf->log, 0, "stream->send value is invalid");
            return HC_BODY_ERROR;
        }
        match->send.len = p - (char *)match->send.data;
    }

    if (api_data == NULL || api_data->hc_data == NULL || !api_data->hc_data->is_stream_set 
        || api_data->hc_data->stream->expect.len < 1) {
//        njt_log_error(NJT_LOG_EMERG, hhccf->log, 0, "stream->send value is null");
//        return HC_BODY_ERROR;
        njt_str_null(&match->expect);
        njt_str_null(&shccc->expect);
    } else {
        val = api_data->hc_data->stream->expect;
        shccc->expect.data = njt_pcalloc(hhccf->pool, val.len);
        shccc->expect.len  = val.len;
        njt_memcpy(shccc->expect.data, val.data, val.len);

        match->expect.data = njt_pcalloc(hhccf->pool, val.len);
        match->expect.len  = val.len;
        p = njt_hex2bin(&match->expect, &shccc->expect, val.len);
        if(NULL ==p) {
            njt_log_error(NJT_LOG_EMERG, hhccf->log, 0, "stream->send value is invalid");
            return HC_BODY_ERROR;
        }
        match->expect.len = p - (char *)match->expect.data;
    }

    return HC_SUCCESS;
}


static njt_int_t njt_http_health_check_add(njt_helper_health_check_conf_t *hhccf, njt_int_t sync) {
    njt_event_t *hc_timer;
    njt_uint_t refresh_in;
    njt_helper_main_conf_t *hmcf;


    njt_cycle_t *cycle = (njt_cycle_t *) njt_cycle;

    hmcf = (njt_helper_main_conf_t *) njt_get_conf(cycle->conf_ctx, njt_helper_health_check_module);

    hc_timer = &hhccf->hc_timer;
   
    /* by zhaokang */
    if (hhccf->type == NJT_HTTP_MODULE) {
         hc_timer->handler = njt_http_health_check_timer_handler;
    } 

    /* by zhaokang */
    if (hhccf->type == NJT_STREAM_MODULE) {
        hc_timer->handler = njt_stream_health_check_timer_handler;
    }

    hc_timer->log = hhccf->log;
    hc_timer->data = hhccf;
    hc_timer->cancelable = 1;
    refresh_in = njt_random() % 1000;
    njt_queue_insert_tail(&hmcf->hc_queue, &hhccf->queue);
    if (sync) {
        if (hhccf->type == NJT_HTTP_MODULE) {
            njt_hc_kv_flush_conf_info(hhccf);
            njt_hc_kv_flush_confs(hmcf);
        }
        /* by zhaokang */
        if ((hhccf->type == NJT_STREAM_MODULE)) {
            njt_stream_hc_kv_flush_conf_info(hhccf);
            njt_stream_hc_kv_flush_confs(hmcf);
        }
    }
    njt_add_timer(hc_timer, refresh_in);
    return NJT_OK;
}

static njt_int_t njt_http_match_parse_code(njt_str_t *code, njt_http_match_code_t *match_code) {
    u_char *dash, *last;
    njt_uint_t status;

    last = code->data + code->len;
    dash = njt_strlchr(code->data, last, '-');

    if (dash) {

        status = njt_atoi(code->data, dash - code->data);
        if (status < 100 || status >= 600) {
            return NJT_ERROR;
        }
        match_code->code = status;

        status = njt_atoi(dash + 1, last - dash - 1);
        if (status < 100 || status >= 600) {
            return NJT_ERROR;
        }
        match_code->last_code = status;

        if (match_code->last_code < match_code->code) {
            return NJT_ERROR;
        }

        match_code->single = 0;

    } else {

        status = njt_atoi(code->data, code->len);
        if (status < 100 || status >= 600) {
            return NJT_ERROR;
        }
        match_code->code = status;
        match_code->single = 1;
    }
    return NJT_OK;

}

static njt_regex_t *
njt_http_match_regex_value(njt_conf_t *cf, njt_str_t *regex) {
#if (NJT_PCRE)
    njt_regex_compile_t rc;
    u_char errstr[NJT_MAX_CONF_ERRSTR];

    njt_memzero(&rc, sizeof(njt_regex_compile_t));


    rc.pattern = *regex;
    rc.err.len = NJT_MAX_CONF_ERRSTR;
    rc.err.data = errstr;
    rc.pool = cf->pool;
    rc.options = NJT_REGEX_CASELESS;


        if (njt_regex_compile(&rc) != NJT_OK) {
        return NULL;
    }

    return rc.regex;

#else

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "using regex \"%V\" requires PCRE library",
                       regex);
    return NULL;

#endif
}


static njt_int_t
njt_http_match_parse_dheaders(njt_array_t *arr, njt_http_match_t *match, njt_helper_health_check_conf_t *hhccf) {
    njt_uint_t nelts;
    njt_http_match_header_t *header;
    njt_uint_t i;
    njt_conf_t cf;
    njt_str_t *args;

    cf.pool = hhccf->pool;
    i = 0;
    args = arr->elts;
    nelts = arr->nelts;
    header = njt_array_push(&match->headers);
    if (header == NULL) {
        njt_log_error(NJT_LOG_EMERG, hhccf->log, 0, "header array push error.");
        return NJT_ERROR;
    }
    njt_memzero(header, sizeof(njt_http_match_header_t));

    /*header ! abc;*/
    if (args[i].data != NULL && njt_strncmp(args[i].data, "!", 1) == 0) {
        header->operation = NJT_HTTP_MATCH_NOT_CONTAIN;
        i++;
        if (nelts != 2) {
            njt_log_error(NJT_LOG_EMERG, hhccf->log, 0, "parameter number %u of header ! error.", nelts);
            return NJT_ERROR;
        }
        njt_str_copy_pool(hhccf->pool, header->key, args[1], return NJT_ERROR);
//        header->key = args[2];
        return NJT_OK;
    }
    njt_str_copy_pool(hhccf->pool, header->key, args[i], return NJT_ERROR);
//    header->key = args[i];
    i++;

    /*header abc;*/
    if (nelts == 1) {
        header->operation = NJT_HTTP_MATCH_CONTAIN;
        return NJT_OK;
    }

    if (nelts != 3) {
        njt_log_error(NJT_LOG_EMERG, hhccf->log, 0, "header parse error.");
        return NJT_ERROR;
    }

    if (args[i].len == 1) {
        njt_str_copy_pool(hhccf->pool, header->key, args[2], return NJT_ERROR);
        if (njt_strncmp(args[i].data, "=", 1) == 0) {
            header->operation = NJT_HTTP_MATCH_EQUAL;
        } else if (njt_strncmp(args[i].data, "~", 1) == 0) {

            header->operation = NJT_HTTP_MATCH_REG_MATCH;
            header->regex = njt_http_match_regex_value(&cf, &header->key);

            if (header->regex == NULL) {
                njt_log_error(NJT_LOG_EMERG, hhccf->log, 0, "header regex %V parse error.",
                              &args[2]);
                return NJT_ERROR;
            }

        } else {
            njt_log_error(NJT_LOG_EMERG, hhccf->log, 0, "header operation parse error.");
            return NJT_ERROR;
        }

//        header->value = args[3];

        return NJT_OK;

    } else if (args[i].len == 2) {
        njt_str_copy_pool(hhccf->pool, header->value, args[2], return NJT_ERROR);
        if (njt_strncmp(args[i].data, "!=", 2) == 0) {
            header->operation = NJT_HTTP_MATCH_NOT_EQUAL;

        } else if (njt_strncmp(args[i].data, "!~", 2) == 0) {

            header->operation = NJT_HTTP_MATCH_NOT_REG_MATCH;
            header->regex = njt_http_match_regex_value(&cf, &header->value);

            if (header->regex == NULL) {
                njt_log_error(NJT_LOG_EMERG, hhccf->log, 0, "header regex %V parse error.",
                              &args[2]);
                return NJT_ERROR;
            }

        } else {
            return NJT_ERROR;
        }

//        header->value = args[3];
        return NJT_OK;
    } else {
        njt_log_error(NJT_LOG_EMERG, hhccf->log, 0,
                      "header operation %V isn't supported.", &args[i]);
        return NJT_ERROR;
    }
}


static njt_int_t njt_http_match(njt_helper_hc_api_data_t *api_data, njt_helper_health_check_conf_t *hhccf) {
    njt_str_t                       *args;
    njt_http_match_code_t           *code, tmp_code;
    njt_uint_t                      i;
    njt_int_t                       rc;
    njt_http_match_t                *match;
    njt_conf_t                      cf;
    njt_array_t                     *array;
    health_check_http_header_item_t *header_item;

    njt_http_health_check_conf_ctx_t *hhccc = hhccf->ctx;
    match = hhccc->match;

    match->conditions = 1;
    if(api_data->hc_data == NULL || !api_data->hc_data->is_http_set || api_data->hc_data->http == NULL){
        return NJT_OK;
    }

    if (api_data->hc_data->http->is_status_set && api_data->hc_data->http->status.len > 0) {
        i = 0;
        array = njt_array_create(hhccf->pool,4, sizeof(njt_str_t));
        njt_str_split(&api_data->hc_data->http->status,array,' ');
        if(array->nelts < 1 ){
            njt_log_error(NJT_LOG_ERR, hhccf->log, 0, "code array create error.");
            return NJT_ERROR;
        }
        args = array->elts;
        if (njt_strncmp(args[0].data, "!", 1) == 0) {
            match->status.not_operation = 1;
            i++;
        }
        for (; i < array->nelts;++i) {
            njt_memzero(&tmp_code, sizeof(njt_http_match_code_t));
            rc = njt_http_match_parse_code(&args[i], &tmp_code);
            if (rc == NJT_ERROR) {
                continue;
            }
            code = njt_array_push(&match->status.codes);
            if (code == NULL) {
                njt_log_error(NJT_LOG_EMERG, hhccf->log, 0, "code array push error.");
                return NJT_ERROR;
            }
            *code = tmp_code;
        }

    }
    if (api_data->hc_data->http->is_header_set && api_data->hc_data->http->header->nelts > 0) {
        njt_array_t *arr;
        for (i = 0; i < api_data->hc_data->http->header->nelts; i++) {
            header_item = get_health_check_http_header_item(api_data->hc_data->http->header, i);
            arr = njt_array_create(hhccf->pool, 4, sizeof(njt_str_t));
            if(arr == NULL ){
                njt_log_error(NJT_LOG_ERR, hhccf->log, 0, "header array create error.");
                return NJT_ERROR;
            }
            njt_str_split(header_item, arr, ' ');
            if(arr->nelts > 0 ){
                njt_http_match_parse_dheaders(arr, match, hhccf);
            }
        }
    }
    if (api_data->hc_data->http->is_body_set && api_data->hc_data->http->body.len > 0) {
        array = njt_array_create(hhccf->pool,4, sizeof(njt_str_t));
        njt_str_split(&hhccc->body, array,' ');
        if(array->nelts < 1 ){
            njt_log_error(NJT_LOG_ERR, hhccf->log, 0, "code array create error.");
            return NJT_ERROR;
        }
        args = array->elts;
        if (array->nelts < 2) {
            njt_log_error(NJT_LOG_EMERG, hhccf->log, 0, "body parameter number error.");
            return NJT_ERROR;
        }

        if (njt_strncmp(args[0].data, "!~", 2) == 0) {
            match->body.operation = NJT_HTTP_MATCH_NOT_REG_MATCH;
        } else if (njt_strncmp(args[0].data, "~", 1) == 0) {
            match->body.operation = NJT_HTTP_MATCH_REG_MATCH;
        } else {
            /*log the case*/
            njt_log_error(NJT_LOG_EMERG, hhccf->log, 0, "body operation %V isn't supported error.", &args[0]);
            return NJT_ERROR;
        }
        cf.pool = hhccf->pool;
//        njt_log_error(NJT_LOG_EMERG, hhccf->log, 0, "body regex %V parse error.",args+1);
        match->body.regex = njt_http_match_regex_value(&cf, &args[1]);
        if (match->body.regex == NULL) {
            njt_log_error(NJT_LOG_EMERG, hhccf->log, 0, "body regex %V parse error.",&args[1]);
            return NJT_ERROR;
        }
        match->body.value = args[1];
    }

    return NJT_OK;
}

static njt_int_t njt_http_hc_test_connect(njt_connection_t *c) {
    int err;
    socklen_t len;

#if (NJT_HAVE_KQUEUE)
    if (njt_event_flags & NJT_USE_KQUEUE_EVENT)  {
        if (c->write->pending_eof || c->read->pending_eof) {
            if (c->write->pending_eof) {
                err = c->write->kq_errno;

            } else {
                err = c->read->kq_errno;
            }

            c->log->action = "connecting to upstream";
            (void) njt_connection_error(c, err,
                                    "kevent() reported that connect() failed");
            return NJT_ERROR;
        }

    } else
#endif
    {
        err = 0;
        len = sizeof(int);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1) {
            err = njt_socket_errno;
        }

        if (err) {
            c->log->action = "connecting to hc";
            (void) njt_connection_error(c, err, "connect() failed");
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}


#if (NJT_STREAM_SSL)

static njt_int_t
njt_stream_hc_ssl_name(njt_connection_t *c, njt_stream_health_check_peer_t *hc_peer) {
    u_char *p, *last;
    njt_str_t name;
    njt_stream_health_check_conf_ctx_t *cf_ctx;
    njt_helper_health_check_conf_t *hhccf;

    hhccf = hc_peer->hhccf;
    cf_ctx = hhccf->ctx;

    if (hhccf->ssl.ssl_name.len) {
        name = hhccf->ssl.ssl_name;
    } else {
        name = cf_ctx->upstream->host;
    }
    if (name.len == 0) {
        goto done;
    }

    /*
     * ssl name here may contain port, notably if derived from $proxy_host
     * or $http_host; we have to strip it
     */

    p = name.data;
    last = name.data + name.len;

    if (*p == '[') {
        p = njt_strlchr(p, last, ']');

        if (p == NULL) {
            p = name.data;
        }
    }

    p = njt_strlchr(p, last, ':');

    if (p != NULL) {
        name.len = p - name.data;
    }

    if (!hhccf->ssl.ssl_server_name) {
        goto done;
    }

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME

    /* as per RFC 6066, literal IPv4 and IPv6 addresses are not permitted */

    if (name.len == 0 || *name.data == '[') {
        goto done;
    }

    if (njt_inet_addr(name.data, name.len) != INADDR_NONE) {
        goto done;
    }

    /*
     * SSL_set_tlsext_host_name() needs a null-terminated string,
     * hence we explicitly null-terminate name here
     */

    p = njt_pnalloc(c->pool, name.len + 1);
    if (p == NULL) {
        return NJT_ERROR;
    }

    (void) njt_cpystrn(p, name.data, name.len + 1);

    name.data = p;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0, "upstream SSL server name: \"%s\"", name.data);

    if (SSL_set_tlsext_host_name(c->ssl->connection,
                                 (char *) name.data)
        == 0) {
        njt_ssl_error(NJT_LOG_ERR, c->log, 0,
                      "SSL_set_tlsext_host_name(\"%s\") failed", name.data);
        return NJT_ERROR;
    }

#endif

    done:

    hc_peer->ssl_name = name;

    return NJT_OK;
}
static njt_int_t
njt_stream_hc_ssl_handshake(njt_connection_t *c, njt_stream_health_check_peer_t *hc_peer) {
    long rc;
    njt_helper_health_check_conf_t *hhccf;

    hhccf = hc_peer->hhccf;

    if (c->ssl->handshaked) {

        if (hhccf->ssl.ssl_verify) {
            rc = SSL_get_verify_result(c->ssl->connection);
            if (rc != X509_V_OK) {
                njt_log_error(NJT_LOG_ERR, c->log, 0,
                              "upstream SSL certificate verify error: (%l:%s)",
                              rc, X509_verify_cert_error_string(rc));
                goto failed;
            }

            if (njt_ssl_check_host(c, &hc_peer->ssl_name) != NJT_OK) {
                njt_log_error(NJT_LOG_ERR, c->log, 0,
                              "hc SSL certificate does not match \"%V\"",
                              &hc_peer->ssl_name);
                goto failed;
            }
        }
        hhccf->ref_count++;
        njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
            "====stream peer check ssl, peerid:%d ref_count=%d", hc_peer->peer_id, hhccf->ref_count);
        hc_peer->peer.connection->write->handler = njt_stream_health_check_write_handler;
        hc_peer->peer.connection->read->handler = njt_stream_health_check_read_handler;

        /*NJT_AGAIN or NJT_OK*/
        if (hhccf->timeout) {
            njt_add_timer(hc_peer->peer.connection->write, hhccf->timeout);
            njt_add_timer(hc_peer->peer.connection->read, hhccf->timeout);
        }
        return NJT_OK;
    }

    if (c->write->timedout) {
//        njt_stream_health_check_common_update(hc_peer, NJT_ERROR);
        return NJT_ERROR;
    }

    failed:

//    njt_stream_health_check_common_update(hc_peer, NJT_ERROR);
    return NJT_ERROR;
}
static void
njt_stream_hc_ssl_handshake_handler(njt_connection_t *c) {
    njt_stream_health_check_peer_t *hc_peer;
    njt_int_t rc;

    hc_peer = c->data;

    rc = njt_stream_hc_ssl_handshake(c, hc_peer);
    if (rc != NJT_OK) {
        njt_stream_health_check_common_update(hc_peer, NJT_ERROR);
    }
}

static njt_int_t
njt_stream_hc_ssl_init_connection(njt_connection_t *c, njt_stream_health_check_peer_t *hc_peer) {
    njt_int_t rc;
    njt_helper_health_check_conf_t *hhccf;

    hhccf = hc_peer->hhccf;

    if (njt_http_hc_test_connect(c) != NJT_OK) {
        return NJT_ERROR;
    }

    if (njt_ssl_create_connection(hhccf->ssl.ssl, c,
                                  NJT_SSL_BUFFER | NJT_SSL_CLIENT) != NJT_OK) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "ssl init create connection for health check error ");
        return NJT_ERROR;
    }

    c->sendfile = 0;

    if (hhccf->ssl.ssl_server_name || hhccf->ssl.ssl_verify) {
        if (njt_stream_hc_ssl_name(c, hc_peer) != NJT_OK) {
            njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "ssl init check ssl name for health check error ");
            return NJT_ERROR;
        }
    }

    c->log->action = "SSL handshaking to hc";

    rc = njt_ssl_handshake(c);

    if (rc == NJT_AGAIN) {

        if (!c->write->timer_set) {
            njt_add_timer(c->write, hhccf->timeout);
        }

        c->ssl->handler = njt_stream_hc_ssl_handshake_handler;
        return NJT_OK;
    }

    return njt_stream_hc_ssl_handshake(c, hc_peer);
//    return NJT_OK;
}
#endif

#if (NJT_HTTP_SSL)


static njt_int_t
njt_http_hc_ssl_name(njt_connection_t *c, njt_http_health_check_peer_t *hc_peer) {
    u_char *p, *last;
    njt_str_t name;
    njt_http_health_check_conf_ctx_t *cf_ctx;
    njt_helper_health_check_conf_t *hhccf;

    hhccf = hc_peer->hhccf;
    cf_ctx = hhccf->ctx;

    if (hhccf->ssl.ssl_name.len) {
        name = hhccf->ssl.ssl_name;
    } else {
        name = cf_ctx->upstream->host;
    }
    if (name.len == 0) {
        goto done;
    }

    /*
     * ssl name here may contain port, notably if derived from $proxy_host
     * or $http_host; we have to strip it
     */

    p = name.data;
    last = name.data + name.len;

    if (*p == '[') {
        p = njt_strlchr(p, last, ']');

        if (p == NULL) {
            p = name.data;
        }
    }

    p = njt_strlchr(p, last, ':');

    if (p != NULL) {
        name.len = p - name.data;
    }

    if (!hhccf->ssl.ssl_server_name) {
        goto done;
    }

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME

    /* as per RFC 6066, literal IPv4 and IPv6 addresses are not permitted */

    if (name.len == 0 || *name.data == '[') {
        goto done;
    }

    if (njt_inet_addr(name.data, name.len) != INADDR_NONE) {
        goto done;
    }

    /*
     * SSL_set_tlsext_host_name() needs a null-terminated string,
     * hence we explicitly null-terminate name here
     */

    p = njt_pnalloc(c->pool, name.len + 1);
    if (p == NULL) {
        return NJT_ERROR;
    }

    (void) njt_cpystrn(p, name.data, name.len + 1);

    name.data = p;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0, "upstream SSL server name: \"%s\"", name.data);

    if (SSL_set_tlsext_host_name(c->ssl->connection,
                                 (char *) name.data)
        == 0) {
        njt_ssl_error(NJT_LOG_ERR, c->log, 0,
                      "SSL_set_tlsext_host_name(\"%s\") failed", name.data);
        return NJT_ERROR;
    }

#endif

    done:

    hc_peer->ssl_name = name;

    return NJT_OK;
}

static njt_int_t
njt_http_hc_ssl_handshake(njt_connection_t *c, njt_http_health_check_peer_t *hc_peer) {
    long rc;
    njt_helper_health_check_conf_t *hhccf;

    hhccf = hc_peer->hhccf;

    if (c->ssl->handshaked) {

        if (hhccf->ssl.ssl_verify) {
            rc = SSL_get_verify_result(c->ssl->connection);
            if (rc != X509_V_OK) {
                njt_log_error(NJT_LOG_ERR, c->log, 0,
                              "upstream SSL certificate verify error: (%l:%s)",
                              rc, X509_verify_cert_error_string(rc));
                goto failed;
            }

            if (njt_ssl_check_host(c, &hc_peer->ssl_name) != NJT_OK) {
                njt_log_error(NJT_LOG_ERR, c->log, 0,
                              "hc SSL certificate does not match \"%V\"",
                              &hc_peer->ssl_name);
                goto failed;
            }
        }
        hhccf->ref_count++;
        njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
            "====http peer check ssl, peerid:%d ref_count=%d", hc_peer->peer_id, hhccf->ref_count);
        hc_peer->peer.connection->write->handler = njt_http_health_check_write_handler;
        hc_peer->peer.connection->read->handler = njt_http_health_check_read_handler;

        /*NJT_AGAIN or NJT_OK*/
        if (hhccf->timeout) {
            njt_add_timer(hc_peer->peer.connection->write, hhccf->timeout);
            njt_add_timer(hc_peer->peer.connection->read, hhccf->timeout);
        }
        return NJT_OK;
    }

    if (c->write->timedout) {
//        njt_http_health_check_update_status(hc_peer, NJT_ERROR);
        return NJT_ERROR;
    }

    failed:

//    njt_http_health_check_update_status(hc_peer, NJT_ERROR);
    return NJT_ERROR;
}

static void
njt_http_hc_ssl_handshake_handler(njt_connection_t *c) {
    njt_http_health_check_peer_t *hc_peer;
    njt_int_t rc;

    hc_peer = c->data;

    rc = njt_http_hc_ssl_handshake(c, hc_peer);
    if (rc != NJT_OK) {
        njt_http_health_check_update_status(hc_peer, NJT_ERROR);
    }
}

static njt_int_t
njt_http_hc_ssl_init_connection(njt_connection_t *c, njt_http_health_check_peer_t *hc_peer) {
    njt_int_t rc;
    njt_helper_health_check_conf_t *hhccf;

    hhccf = hc_peer->hhccf;

    if (njt_http_hc_test_connect(c) != NJT_OK) {
        return NJT_ERROR;
    }

    if (njt_ssl_create_connection(hhccf->ssl.ssl, c,
                                  NJT_SSL_BUFFER | NJT_SSL_CLIENT) != NJT_OK) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "ssl init create connection for health check error ");
        return NJT_ERROR;
    }

    c->sendfile = 0;

    if (hhccf->ssl.ssl_server_name || hhccf->ssl.ssl_verify) {
        if (njt_http_hc_ssl_name(c, hc_peer) != NJT_OK) {
            njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "ssl init check ssl name for health check error ");
            return NJT_ERROR;
        }
    }

    c->log->action = "SSL handshaking to hc";

    rc = njt_ssl_handshake(c);

    if (rc == NJT_AGAIN) {

        if (!c->write->timer_set) {
            njt_add_timer(c->write, hhccf->timeout);
        }

        c->ssl->handler = njt_http_hc_ssl_handshake_handler;
        return NJT_OK;
    }

    return njt_http_hc_ssl_handshake(c, hc_peer);
//    return NJT_OK;
}

#endif

static void
njt_http_health_loop_peer(njt_helper_health_check_conf_t *hhccf, njt_http_upstream_rr_peers_t *peers,
                          njt_flag_t backup, njt_flag_t op, bool map_recreate) {
    njt_int_t                       rc;
    njt_http_health_check_peer_t    *hc_peer;
    njt_http_upstream_rr_peer_t     *peer;
    njt_http_upstream_rr_peers_t    *hu_peers;
    njt_pool_t                      *pool;

    hu_peers = peers;
    if (backup == 1) {
        hu_peers = peers->next;
    }
    if (hu_peers == NULL) {
        return;
    }
    peer = hu_peers->peer;
    for (; peer != NULL; peer = peer->next) {

        if (peer->down == 1) //zyg
        {
            continue;
        }
        if ((peer->hc_down == 2) || (op == 1)) {  //checking
            if (peer->hc_check_in_process) {
                njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                               "peer's health check is in process.");
                continue;
            }

            if(map_recreate){
                rc = njt_hc_http_peer_add_map(hhccf, peer);
                switch (rc)
                {
                case NJT_ERROR:
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                            " add http peer:%V peerid:%d to map error", &peer->server, peer->id);
                    continue;
                case NJT_DECLINED:
                    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                            " same http peer:%V peerid:%d exist", &peer->server, peer->id);
                    continue;
                case NJT_OK:
                    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                            " add http peer:%V peerid:%d to map", &peer->server, peer->id);
                    break;
                }
            }else{
                //if not check peer, just continue
                if(!njt_hc_http_check_peer(hhccf, peer)){
                    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                            " http, not check peer:%V peerid:%d just continue", &peer->server, peer->id);
                    continue;
                }
            }

            njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                    " http check peer:%V peerid:%d", &peer->server, peer->id);

            peer->hc_check_in_process = 1;
            if (hhccf->type == NJT_HTTP_HC_GRPC) {
                njt_http_upstream_rr_peers_unlock(peers);
                njt_http_hc_grpc_loop_peer(hhccf, peer);
                njt_http_upstream_rr_peers_wlock(peers);
            } else {
                pool = njt_create_pool(njt_pagesize, njt_cycle->log);
                if (pool == NULL) {
                    /*log the malloc failure*/
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                                  "create pool failure for health check.");
                    continue;
                }
                hc_peer = njt_pcalloc(pool, sizeof(njt_http_health_check_peer_t));
                if (hc_peer == NULL) {
                    /*log the malloc failure*/
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                                  "memory allocate failure for health check.");
                    njt_destroy_pool(pool);
                    continue;
                }
                hc_peer->pool = pool;

                hc_peer->peer_id = peer->id;
                hc_peer->hu_peer = peer;
                hc_peer->hu_peers = hu_peers;
                hc_peer->hhccf = hhccf;
                hc_peer->update_id = hhccf->update_id;

                hc_peer->peer.sockaddr = njt_pcalloc(pool, sizeof(struct sockaddr));
                if (hc_peer->peer.sockaddr == NULL) {
                    /*log the malloc failure*/
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                                  "memory allocate failure for health check.");
                    njt_destroy_pool(pool);
                    continue;
                }
                njt_memcpy(hc_peer->peer.sockaddr, peer->sockaddr, sizeof(struct sockaddr));

                /*customized the peer's port*/
                if (hhccf->port) {
                    njt_inet_set_port(hc_peer->peer.sockaddr, hhccf->port);
                }

                hc_peer->peer.socklen = peer->socklen;
                hc_peer->peer.name = &peer->name;
                hc_peer->server.len = peer->server.len;
                hc_peer->server.data = njt_pcalloc(pool, peer->server.len);
                njt_memcpy(hc_peer->server.data, peer->server.data, peer->server.len);
                hc_peer->peer.get = njt_event_get_peer;
                hc_peer->peer.log = njt_cycle->log;
                hc_peer->peer.log_error = NJT_ERROR_ERR;

                njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                               "health check connect to peer of %V.", &peer->name);
                rc = njt_event_connect_peer(&hc_peer->peer);

                if (rc == NJT_ERROR || rc == NJT_DECLINED || rc == NJT_BUSY) {
                    njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                                   "health check connect to peer of %V errror.", &peer->name);
                    /*release the memory and update the statistics*/
                    njt_http_upstream_rr_peers_unlock(peers);
                    njt_http_health_check_common_update(hc_peer, NJT_ERROR);
                    njt_http_upstream_rr_peers_wlock(peers);
                    continue;
                }

                hc_peer->peer.connection->data = hc_peer;
                hc_peer->peer.connection->pool = hc_peer->pool;
#if (NJT_HTTP_SSL)

                if (hhccf->ssl.ssl_enable && hhccf->ssl.ssl->ctx &&
                    hc_peer->peer.connection->ssl == NULL) { //zyg
                    rc = njt_http_hc_ssl_init_connection(hc_peer->peer.connection, hc_peer);
                    if (rc == NJT_ERROR) {
                        njt_http_upstream_rr_peers_unlock(peers);
                        njt_http_health_check_common_update(hc_peer, NJT_ERROR);
                        njt_http_upstream_rr_peers_wlock(peers);
                    }
                    continue;
                }

#endif

                hhccf->ref_count++;
        njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
            "====http peer check, peerid:%d ref_count=%d", hc_peer->peer_id, hhccf->ref_count);
                hc_peer->peer.connection->write->handler = njt_http_health_check_write_handler;
                hc_peer->peer.connection->read->handler = njt_http_health_check_read_handler;

                /*NJT_AGAIN or NJT_OK*/
                if (hhccf->timeout) {
                    njt_add_timer(hc_peer->peer.connection->write, hhccf->timeout);
                    njt_add_timer(hc_peer->peer.connection->read, hhccf->timeout);
                }
            }
        }
    }
}

void njt_stream_health_loop_peer(njt_helper_health_check_conf_t *hhccf, njt_stream_upstream_rr_peers_t *peers,
                                njt_flag_t backup, njt_flag_t op, bool map_recreate) {
    njt_int_t                       rc;
    njt_stream_health_check_peer_t *hc_peer;
    njt_stream_upstream_rr_peer_t  *peer;
    njt_stream_upstream_rr_peers_t *hu_peers;
    njt_pool_t                     *pool;

    hu_peers = peers;
    if (backup == 1) {
        hu_peers = peers->next;
    }

    if (hu_peers == NULL) {
        return;
    }

    peer = hu_peers->peer;
    for (; peer != NULL; peer = peer->next) {
        if (peer->down == 1) 
        {
            continue;
        }
        if ((peer->hc_down == 2) || (op == 1)) {  
            if (peer->hc_check_in_process) {
                njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                               "peer's health check is in process.");
                continue;
            }

            if(map_recreate){
                rc = njt_hc_stream_peer_add_map(hhccf, peer);
                switch (rc)
                {
                case NJT_ERROR:
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                            " add stream peer:%V peerid:%d to map error", &peer->server, peer->id);
                    continue;
                case NJT_DECLINED:
                    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                            " same stream peer:%V peerid:%d exist", &peer->server, peer->id);
                    continue;
                case NJT_OK:
                    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                            " add stream peer:%V peerid:%d to map", &peer->server, peer->id);
                    break;
                }
            }else{
                //if not check peer, just continue
                if(!njt_hc_stream_check_peer(hhccf, peer)){
                    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                            " not stream check peer:%V peerid:%d just continue", &peer->server, peer->id);
                    continue;
                }
            }

            njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                    " stream check peer:%V peerid:%d", &peer->server, peer->id);

            peer->hc_check_in_process = 1;
            pool = njt_create_pool(njt_pagesize, njt_cycle->log);
            if (pool == NULL) {
                /*log the malloc failure*/
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                              "create pool failure for health check.");
                continue;
            }
                
            hc_peer = njt_pcalloc(pool, sizeof(njt_stream_health_check_peer_t));
            if (hc_peer == NULL) {
                /*log the malloc failure*/
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                              "memory allocate failure for health check.");
                njt_destroy_pool(pool);
                continue;
            }

            hc_peer->pool = pool;
            hc_peer->peer_id = peer->id;
            hc_peer->hu_peer = peer;
            hc_peer->hu_peers = hu_peers;
            hc_peer->hhccf = hhccf;
            hc_peer->update_id = hhccf->update_id;

            hc_peer->peer.sockaddr = njt_pcalloc(pool, sizeof(struct sockaddr));
            if (hc_peer->peer.sockaddr == NULL) {
                 /*log the malloc failure*/
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                                  "memory allocate failure for health check.");
                continue;
            }
                
            njt_memcpy(hc_peer->peer.sockaddr, peer->sockaddr, sizeof(struct sockaddr));

             /*customized the peer's port*/
            if (hhccf->port) {
                  njt_inet_set_port(hc_peer->peer.sockaddr, hhccf->port);
              }

            hc_peer->peer.socklen = peer->socklen;
            hc_peer->peer.name = &peer->name;       //domain name
            hc_peer->server.len = peer->server.len;
            hc_peer->server.data = njt_pcalloc(pool, peer->server.len);
            njt_memcpy(hc_peer->server.data, peer->server.data, peer->server.len);
            hc_peer->peer.get = njt_event_get_peer;
            hc_peer->peer.log = njt_cycle->log;
            hc_peer->peer.log_error = NJT_ERROR_ERR;

            njt_log_debug1(NJT_LOG_DEBUG_STREAM, njt_cycle->log, 0,
                               "health check connect to peer of %V.", &peer->name);
            if(1==hhccf->protocol) hc_peer->peer.type = SOCK_DGRAM;
            rc = njt_event_connect_peer(&hc_peer->peer);

            if (rc == NJT_ERROR || rc == NJT_DECLINED || rc == NJT_BUSY) {
                njt_log_debug1(NJT_LOG_DEBUG_STREAM, njt_cycle->log, 0,
                                   "health check connect to peer of %V error.", &peer->name);
                /*release the memory and update the statistics*/
                njt_stream_upstream_rr_peers_unlock(peers);
                njt_stream_health_check_common_update(hc_peer, NJT_ERROR);
                njt_stream_upstream_rr_peers_wlock(peers);
                continue;
             }
             hc_peer->peer.connection->data = hc_peer;
             hc_peer->peer.connection->pool = hc_peer->pool;

#if (NJT_STREAM_SSL)

            if (hhccf->ssl.ssl_enable && hhccf->ssl.ssl->ctx &&
                hc_peer->peer.connection->ssl == NULL) { //zyg
                rc = njt_stream_hc_ssl_init_connection(hc_peer->peer.connection, hc_peer);
                if (rc == NJT_ERROR) {
                    njt_stream_upstream_rr_peers_unlock(peers);
                    njt_stream_health_check_common_update(hc_peer, NJT_ERROR);
                    njt_stream_upstream_rr_peers_wlock(peers);
                }
                continue;
            }

#endif

             hhccf->ref_count++;
                     njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
            "====stream peer check, peerid:%d ref_count=%d", hc_peer->peer_id, hhccf->ref_count);
             hc_peer->peer.connection->write->handler = njt_stream_health_check_write_handler;
             hc_peer->peer.connection->read->handler = njt_stream_health_check_read_handler;
             /*NJT_AGAIN or NJT_OK*/
             if (hhccf->timeout) {
                 njt_add_timer(hc_peer->peer.connection->write, hhccf->timeout);
                 njt_add_timer(hc_peer->peer.connection->read, hhccf->timeout);
             }
        }
    }
}

static njt_http_match_t *njt_helper_http_match_create(njt_helper_health_check_conf_t *hhccf) {
    njt_http_match_t *match;

    match = njt_pcalloc(hhccf->pool, sizeof(njt_http_match_t));
    if (match == NULL) {
        return NULL;
    }
    njt_memzero(match, sizeof(njt_http_match_t));

    return match;
}

static njt_int_t njt_hc_helper_module_init(njt_cycle_t *cycle) {
    njt_helper_main_conf_t *hmcf;
    hmcf = njt_pcalloc(cycle->pool, sizeof(njt_helper_main_conf_t));
    if (hmcf == NULL) {
        njt_log_error(NJT_LOG_EMERG, cycle->log, 0, "health check helper alloc main conf error ");
        return NJT_ERROR;
    }
    njt_queue_init(&hmcf->hc_queue);
    hmcf->first = 1;
    cycle->conf_ctx[njt_helper_health_check_module.index] = (void *) hmcf;
    return NJT_OK;
}

static void njt_health_check_recovery_conf_info(njt_pool_t *pool, njt_str_t *msg, njt_str_t *name, njt_str_t *type) {
    njt_int_t                   rc;
    njt_helper_hc_api_data_t    *api_data = NULL;
    js2c_parse_error_t          err_info;

    api_data = njt_pcalloc(pool, sizeof(njt_helper_hc_api_data_t));
    if (api_data == NULL) {
        njt_log_error(NJT_LOG_EMERG, pool->log, 0, "could not alloc buffer in function %s", __func__);
        return;
    }

    api_data->hc_data = json_parse_health_check(pool, msg, &err_info);
    if (api_data->hc_data == NULL)
    {
        njt_log_error(NJT_LOG_ERR, pool->log, 0, 
                "json_parse_health_check err: %V",  &err_info.err_str);

        rc = NJT_ERROR;
        return;
    }

    njt_str_copy_pool(pool, api_data->upstream_name, (*name), return);
    njt_str_copy_pool(pool, api_data->hc_type, (*type), return);
    rc = njt_hc_api_add_conf(pool->log, api_data, 0);
    if (rc != HC_SUCCESS) {
        njt_log_error(NJT_LOG_EMERG, pool->log, 0, "recovery conf info info error");
    }

}


static void njt_health_check_recovery_confs(){
    njt_helper_main_conf_t  *hmcf;
    njt_str_t               msg;
    njt_str_t               tkey1, tkey2;
    njt_pool_t              *pool;
    njt_uint_t              i;
    health_checks_t         *hc_datas;    
    health_checks_item_t    *item;
    js2c_parse_error_t      err_info;
    njt_str_t               hc_type, hc_upstream;

    njt_str_t key_pre = njt_string(HTTP_HEALTH_CHECK_CONF_INFO);
    njt_str_t key_separator = njt_string(HTTP_HEALTH_CHECK_SEPARATOR);
    njt_str_t key = njt_string(HTTP_HEALTH_CHECK_CONFS);

    hmcf = (void *) njt_get_conf(njt_cycle->conf_ctx, njt_helper_health_check_module);
    if (hmcf == NULL) {
        return;
    }

    njt_memzero(&msg, sizeof(njt_str_t));
    njt_dyn_kv_get(&key, &msg);
    if (msg.len <= 2) {
        return;
    }
    pool = njt_create_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
    if (pool == NULL) {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "create pool error in function %s", __func__);
        goto end;
    }

    njt_log_error(NJT_LOG_INFO, pool->log, 0, 
                "http json_parse_health_checks msg: %V",  &msg);
    hc_datas = json_parse_health_checks(pool, &msg, &err_info);
    if (hc_datas == NULL)
    {
        njt_log_error(NJT_LOG_ERR, pool->log, 0, 
                "json_parse_health_checks err: %V",  &err_info.err_str);

        goto end;
    }

    for (i = 0; i < hc_datas->nelts; ++i) {
        item = get_health_checks_item(hc_datas, i);
        hc_type = item->hc_type;
        hc_upstream = item->upstream_name;
        njt_str_concat(pool, tkey1, key_pre, hc_type, goto end);
        njt_str_concat(pool, tkey2, tkey1, key_separator, goto end);
        njt_str_concat(pool, tkey1, tkey2, hc_upstream, goto end);
        njt_memzero(&msg, sizeof(njt_str_t));
        njt_dyn_kv_get(&tkey1, &msg);
        if (msg.len <= 0) {
            continue;
        }
        njt_health_check_recovery_conf_info(pool, &msg, &item->upstream_name, &item->hc_type);
    }

    end:
    if(pool != NULL){
        njt_destroy_pool(pool);
    }
}


/* by zhaokang */
static void njt_stream_health_check_recovery_confs(){
    njt_helper_main_conf_t         *hmcf;
    njt_str_t                       msg;
    njt_str_t                       tkey1, tkey2;
    njt_pool_t                     *pool;
    njt_uint_t                      i;
    health_checks_t                 *hc_datas;    
    health_checks_item_t            *item;
    js2c_parse_error_t              err_info;
    njt_str_t                       hc_type, hc_upstream;


    njt_str_t key_pre         = njt_string(STREAM_HEALTH_CHECK_CONF_INFO);
    njt_str_t key_separator = njt_string(STREAM_HEALTH_CHECK_SEPARATOR);
    njt_str_t key             = njt_string(STREAM_HEALTH_CHECK_CONFS);

    hmcf = (void *) njt_get_conf(njt_cycle->conf_ctx, njt_helper_health_check_module);
    if (hmcf == NULL) {
        return;
    }

    njt_memzero(&msg, sizeof(njt_str_t));

    njt_dyn_kv_get(&key, &msg);
    if (msg.len <= 2) {
        return;
    }

    pool = njt_create_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
    if (pool == NULL) {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "create pool error in function %s", __func__);
        goto end;
    }
    njt_log_error(NJT_LOG_INFO, pool->log, 0, 
                "stream json_parse_health_checks msg: %V",  &msg);
    hc_datas = json_parse_health_checks(pool, &msg, &err_info);
    if (hc_datas == NULL)
    {
        njt_log_error(NJT_LOG_ERR, pool->log, 0, 
                "json_parse_health_checks err: %V",  &err_info.err_str);

        goto end;
    }

    for (i = 0; i < hc_datas->nelts; ++i) {
        item = get_health_checks_item(hc_datas, i);
        hc_type = item->hc_type;
        hc_upstream = item->upstream_name;
        njt_str_concat(pool, tkey1, key_pre, hc_type,         goto end);
        njt_str_concat(pool, tkey2, tkey1,      key_separator,         goto end);
        njt_str_concat(pool, tkey1, tkey2,   hc_upstream, goto end);

        njt_memzero(&msg, sizeof(njt_str_t));

        njt_dyn_kv_get(&tkey1, &msg);
        if (msg.len <= 0) {
            continue;
        }

        njt_health_check_recovery_conf_info(pool, &msg, &item->upstream_name, &item->hc_type);
    }

end:
    if(pool != NULL){
        njt_destroy_pool(pool);
    }
}


static char njt_hc_resp_body[] = "{\n  \"code\": %d,\n   \"msg\": \"%V\"\n }";

static njt_int_t njt_http_health_check_conf_out_handler(njt_http_request_t *r, njt_int_t hrc) {
    njt_uint_t buf_len;
    njt_buf_t *buf;
    njt_chain_t out;
    njt_int_t rc;

    switch (hrc) {
        case HC_SUCCESS:
            r->headers_out.status = NJT_HTTP_OK;
            break;
        case HC_TYPE_NOT_FOUND:
        case HC_UPSTREAM_NOT_FOUND:
        case HC_VERSION_NOT_SUPPORT:
        case HC_PATH_NOT_FOUND:
        case HC_NOT_FOUND:
            r->headers_out.status = NJT_HTTP_NOT_FOUND;
            break;
        case HC_METHOD_NOT_ALLOW:
            r->headers_out.status = NJT_HTTP_NOT_ALLOWED;
            break;
        case HC_CA_NOT_CONF:
        case HC_CERTIFICATE_NOT_CONF:
        case HC_CERTIFICATE_KEY_NOT_CONF:
        case HC_BODY_ERROR:
            r->headers_out.status = NJT_HTTP_BAD_REQUEST;
            break;
        case HC_DOUBLE_SET:
            r->headers_out.status = NJT_HTTP_CONFLICT;
            break;
        case HC_SERVER_ERROR:
        default:
            r->headers_out.status = NJT_HTTP_INTERNAL_SERVER_ERROR;
            break;
    }
    buf_len = sizeof(njt_hc_resp_body) - 1 + 9 + njt_hc_error_msg[hrc].len;
    buf = njt_create_temp_buf(r->pool, buf_len);
    if (buf == NULL) {
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "could not alloc buffer in function %s", __func__);
        return NJT_ERROR;
    }
    buf->last = njt_snprintf(buf->last, buf_len, njt_hc_resp_body, hrc, njt_hc_error_msg + hrc);
    njt_str_t type = njt_string("application/json");
    r->headers_out.content_type = type;
    r->headers_out.content_length_n = buf->last - buf->pos;
    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }
    rc = njt_http_send_header(r);

    // r->header_only  when method is HEAD ,header_only is set.
    if (rc == NJT_ERROR || rc > NJT_OK) {
        return rc;
    }
    buf->last_buf = 1;
    out.buf = buf;
    out.next = NULL;
    return njt_http_output_filter(r, &out);
}



/*!
    路由解析
*/
static njt_int_t
njt_http_api_parse_path(njt_http_request_t *r, njt_array_t *path) {
    u_char *p, *sub_p,*end;
    njt_uint_t len;
    njt_str_t *item;
    njt_http_core_loc_conf_t *clcf;
    njt_str_t uri;

    /*the uri is parsed and delete all the duplidated '/' characters.
     * for example, "/api//7//http///upstreams///////" will be parse to
     * "/api/7/http/upstreams/" already*/

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    uri = r->uri;
    p = uri.data + clcf->name.len;
    end = uri.data + uri.len;
    len = uri.len - clcf->name.len;

    if (len != 0 && *p != '/') {
        return HC_PATH_NOT_FOUND;
    }
    if (*p == '/') {
        len--;
        p++;
    }

    while (len > 0) {
        item = njt_array_push(path);
        if (item == NULL) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "zack: array item of path push error.");
            return NJT_ERROR;
        }

        item->data = p;
        sub_p = (u_char *) njt_strlchr(p,end, '/');

        if (sub_p == NULL || (njt_uint_t) (sub_p - uri.data) > uri.len) {
            item->len = uri.data + uri.len - p;
            break;

        } else {
            item->len = sub_p - p;
        }

        len -= item->len;
        p += item->len;

        if (*p == '/') {
            len--;
            p++;
        }

    }
    return NJT_OK;
}



static njt_str_t *njt_hc_confs_to_json(njt_pool_t *pool, njt_helper_main_conf_t *hmcf) {
    njt_helper_health_check_conf_t      *hhccf;
    njt_queue_t                         *q;
    njt_http_health_check_conf_ctx_t    *cf_ctx;
    health_checks_t                     *dynjson_obj;
    health_checks_item_t*               hc_item;               

    dynjson_obj = create_health_checks(pool, 4);
    if(dynjson_obj == NULL){
        goto err;
    }

    q = njt_queue_head(&hmcf->hc_queue);
    for (; q != njt_queue_sentinel(&hmcf->hc_queue); q = njt_queue_next(q)) {
        hhccf = njt_queue_data(q, njt_helper_health_check_conf_t, queue);

        hc_item = create_health_checks_item(pool);
        if(hc_item == NULL ){
            goto err;
        }

        set_health_checks_item_upstream_name(hc_item, &hhccf->upstream_name);
        if (hhccf->type == NJT_HTTP_MODULE) {
            cf_ctx = hhccf->ctx;
            set_health_checks_item_hc_type(hc_item, &cf_ctx->checker->name);
        }
    
        /* by zhaokang */
        if (hhccf->type == NJT_STREAM_MODULE) {
            njt_stream_health_check_conf_ctx_t    *shccc;
            shccc = hhccf->ctx;
            set_health_checks_item_hc_type(hc_item, &shccc->checker->name);
        }

        add_item_health_checks(dynjson_obj, hc_item);
    }

    return to_json_health_checks(pool, dynjson_obj, OMIT_NULL_ARRAY | OMIT_NULL_OBJ | OMIT_NULL_STR);

    err:
    return NULL;
}

static njt_int_t njt_hc_api_get_hcs(njt_http_request_t *r) {
    njt_cycle_t             *cycle;
    njt_int_t               rc;
    njt_helper_main_conf_t  *hmcf;
    njt_buf_t               *buf;
    njt_chain_t             out;
    njt_str_t               *json;

    rc = njt_http_discard_request_body(r);
    if (rc == NJT_ERROR || rc >= NJT_HTTP_SPECIAL_RESPONSE) {
        return HC_SERVER_ERROR;
    }
    cycle = (njt_cycle_t *) njt_cycle;
    hmcf = (njt_helper_main_conf_t *) njt_get_conf(cycle->conf_ctx, njt_helper_health_check_module);
    json = njt_hc_confs_to_json(r->pool, hmcf);
    if (json == NULL || json->len == 0) {
        return HC_SERVER_ERROR;
    }
    buf = njt_create_temp_buf(r->pool, json->len);
    if(buf == NULL){
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "njt_create_temp_buf error , size :%ui" ,json->len);
        return HC_SERVER_ERROR;
    }
    buf->last = buf->pos + json->len;
    njt_memcpy(buf->pos, json->data, json->len);
    r->headers_out.status = NJT_HTTP_OK;
    njt_str_t type = njt_string("application/json");
    r->headers_out.content_type = type;
    r->headers_out.content_length_n = buf->last - buf->pos;
    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }
    rc = njt_http_send_header(r);
    if (rc == NJT_ERROR || rc > NJT_OK || r->header_only) {
        return rc;
    }
    buf->last_buf = 1;
    out.buf = buf;
    out.next = NULL;
    rc = njt_http_output_filter(r, &out);
    if (rc == NJT_OK) {
        return HC_RESP_DONE;
    }
    return HC_SERVER_ERROR;
}


/**
 * 它读取请求体并将其解析为 njt_helper_hc_api_data_t 结构
 *
 * @param r http 请求对象
 */
static void njt_http_hc_api_read_data(njt_http_request_t *r){
    njt_str_t                   json_str;
    njt_int_t                   hrc;
    njt_chain_t                 *body_chain, *tmp_chain;
    njt_int_t                   rc;
    njt_helper_hc_api_data_t    *api_data = NULL;
    njt_uint_t                  len, size;
    njt_str_t                   *uri;
    njt_array_t                 *path;
    js2c_parse_error_t          err_info;

    body_chain = r->request_body->bufs;
    /*check the sanity of the json body*/
    if(NULL == body_chain){
        hrc = HC_SERVER_ERROR;
        goto out;
    }
    json_str.data = body_chain->buf->pos;
    json_str.len = body_chain->buf->last - body_chain->buf->pos;

    api_data = njt_pcalloc(r->pool, sizeof(njt_helper_hc_api_data_t));
    if (api_data == NULL) {
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "could not alloc buffer in function %s", __func__);
        hrc = HC_SERVER_ERROR;
        goto out;
    }
    len = 0;
    tmp_chain = body_chain;
    while (tmp_chain != NULL) {
        len += tmp_chain->buf->last - tmp_chain->buf->pos;
        tmp_chain = tmp_chain->next;
    }
    json_str.len = len;
    json_str.data = njt_pcalloc(r->pool, len);
    if (json_str.data == NULL) {
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "could not alloc buffer in function %s", __func__);
        hrc = HC_SERVER_ERROR;
        goto out;
    }
    len = 0;
    tmp_chain = r->request_body->bufs;
    while (tmp_chain != NULL) {
        size = tmp_chain->buf->last - tmp_chain->buf->pos;
        njt_memcpy(json_str.data + len, tmp_chain->buf->pos, size);
        tmp_chain = tmp_chain->next;
        len += size;
    }

    api_data->hc_data = json_parse_health_check(r->pool, &json_str, &err_info);
    if(api_data->hc_data == NULL){
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "health check json parse error:%V", &err_info.err_str);
        api_data->rc = NJT_ERROR;
        api_data->success = 0;
        hrc = HC_BODY_ERROR;
        goto out;
    } else {
        api_data->success = 1;
    }
    njt_http_set_ctx(r, api_data, njt_helper_health_check_module);

    path = njt_array_create(r->pool, 4, sizeof(njt_str_t));
    if (path == NULL) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "array init of path error.");
        hrc = HC_SERVER_ERROR;
        goto out;
    }
    rc = njt_http_api_parse_path(r, path);
    if (rc != HC_SUCCESS || path->nelts <= 0) {
        hrc = HC_PATH_NOT_FOUND;
        goto out;
    }
    uri = path->elts;
    if (path->nelts < 2
        || (uri[1].len != 2 || njt_strncmp(uri[1].data, "hc", 2) != 0)) {
        hrc = HC_PATH_NOT_FOUND;
        goto out;
    }
    hrc = HC_PATH_NOT_FOUND;
    if (path->nelts == 4) {
        api_data->hc_type = uri[2];
        api_data->upstream_name = uri[3];
    }

    if (r->method == NJT_HTTP_POST) {
        hrc = njt_hc_api_add_conf(r->pool->log, api_data, 1);
    }
    if (hrc == HC_RESP_DONE) {
        rc = NJT_OK;
        goto end;
    }

    out:
    rc = njt_http_health_check_conf_out_handler(r, hrc);

    end:
    njt_http_finalize_request(r, rc);
}

static njt_helper_health_check_conf_t *njt_http_find_helper_hc_by_name_and_type(njt_cycle_t *cycle, njt_str_t * hc_type,njt_str_t *upstream_name){
    njt_helper_main_conf_t *hmcf;
    njt_health_checker_t *checker;
    njt_helper_health_check_conf_t *hhccf;
    njt_queue_t *q;

    hmcf = (njt_helper_main_conf_t *) njt_get_conf(cycle->conf_ctx, njt_helper_health_check_module);
    checker = njt_http_get_health_check_type(hc_type);
    if (checker == NULL) {
        return NULL;
    }
    q = njt_queue_head(&hmcf->hc_queue);
    for (; q != njt_queue_sentinel(&hmcf->hc_queue); q = njt_queue_next(q)) {
        hhccf = njt_queue_data(q, njt_helper_health_check_conf_t, queue);
        if (hhccf->type_str.len == checker->name.len
            && njt_strncmp(hhccf->type_str.data, checker->name.data, checker->name.len) == 0
            && hhccf->upstream_name.len == upstream_name->len
            && njt_strncmp(hhccf->upstream_name.data, upstream_name->data, hhccf->upstream_name.len) == 0) {
            return hhccf;
        }
    }
    return NULL;
}

static njt_helper_health_check_conf_t *njt_http_find_helper_hc(njt_cycle_t *cycle, njt_helper_hc_api_data_t *api_data){
    return njt_http_find_helper_hc_by_name_and_type(cycle,&api_data->hc_type,&api_data->upstream_name);
}


static njt_int_t njt_hc_api_delete_conf(njt_http_request_t *r, njt_helper_hc_api_data_t *api_data) {
    njt_cycle_t *cycle;
    njt_helper_health_check_conf_t *hhccf;
    njt_helper_main_conf_t *hmcf;

    cycle = (njt_cycle_t *) njt_cycle;
    hmcf = (njt_helper_main_conf_t *) njt_get_conf(cycle->conf_ctx, njt_helper_health_check_module);

    if (api_data->hc_type.len == 0 || api_data->upstream_name.len == 0) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, " type and upstream must be set !!");
        return HC_BODY_ERROR;
    }
    hhccf = njt_http_find_helper_hc(cycle, api_data);
    if (hhccf == NULL) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "not find upstream %V hc", &api_data->upstream_name);
        return HC_NOT_FOUND;
    }
    njt_queue_remove(&hhccf->queue);
    hhccf->disable = 1;
    njt_hc_kv_flush_confs(hmcf);
    /* by zhaokang */
    njt_stream_hc_kv_flush_confs(hmcf);
    return HC_SUCCESS;
}

static char njt_hc_time_second_format[] ="%uis";

static njt_str_t *njt_hc_conf_info_to_json(njt_pool_t *pool, njt_helper_health_check_conf_t *hhccf) {
    njt_http_health_check_conf_ctx_t    *cf_ctx;
    njt_str_t                           *header;
    njt_uint_t                          i;
    u_char                              *str_buf,*last;
    health_check_t                      dynjson_obj;
    njt_str_t                           tmp_str;

    njt_memzero(&dynjson_obj, sizeof(health_check_t));
    str_buf = njt_pcalloc(pool,njt_pagesize);
    if(str_buf == NULL ){
        goto err;
    }

    last = str_buf + njt_pagesize;
    tmp_str.data = str_buf;
    str_buf = njt_snprintf(tmp_str.data, 
            last - tmp_str.data, njt_hc_time_second_format, hhccf->interval/ 1000);
    tmp_str.len = str_buf - tmp_str.data;
    set_health_check_interval(&dynjson_obj, &tmp_str);

    tmp_str.data = str_buf;
    str_buf = njt_snprintf(tmp_str.data, 
                last - tmp_str.data, njt_hc_time_second_format,hhccf->jitter / 1000);
    tmp_str.len = str_buf - tmp_str.data;
    set_health_check_jitter(&dynjson_obj, &tmp_str);

    tmp_str.data = str_buf;
    str_buf = njt_snprintf(tmp_str.data,
            last - tmp_str.data, njt_hc_time_second_format,hhccf->timeout/ 1000);
    tmp_str.len = str_buf - tmp_str.data;
    set_health_check_timeout(&dynjson_obj, &tmp_str);

    set_health_check_passes(&dynjson_obj, hhccf->passes);
    set_health_check_fails(&dynjson_obj, hhccf->fails);

    if (hhccf->port > 0) {
        set_health_check_port(&dynjson_obj, hhccf->port);
    }

    /* by zhaokang */
    if (hhccf->type == NJT_STREAM_MODULE) {
        njt_stream_health_check_conf_ctx_t  *shccc;

        shccc = hhccf->ctx;
        set_health_check_stream(&dynjson_obj, create_health_check_stream(pool));
        if (dynjson_obj.stream == NULL) {
            goto err;
        }

        if (shccc->send.len > 0 ) {
            set_health_check_stream_send(dynjson_obj.stream, &shccc->send);
        }

        if (shccc->expect.len > 0) {
            set_health_check_stream_expect(dynjson_obj.stream, &shccc->expect);
        }              
    }

    if (hhccf->type == NJT_HTTP_MODULE) {
        cf_ctx = hhccf->ctx;
        set_health_check_http(&dynjson_obj, create_health_check_http(pool));
        if(dynjson_obj.http == NULL ){
            goto err;
        }
        if (cf_ctx->uri.len > 0) {
            set_health_check_http_uri(dynjson_obj.http, &cf_ctx->uri);
        }
        if (cf_ctx->gsvc.len > 0) {
            set_health_check_http_grpcService(dynjson_obj.http, &cf_ctx->gsvc);
            set_health_check_http_grpcStatus(dynjson_obj.http, cf_ctx->gstatus);
        }
        if (cf_ctx->status.len > 0) {
            set_health_check_http_status(dynjson_obj.http, &cf_ctx->status);
        }
        if (cf_ctx->body.len > 0) {
            set_health_check_http_body(dynjson_obj.http, &cf_ctx->body);
        }
        if (cf_ctx->headers.nelts > 0) {
            set_health_check_http_header(dynjson_obj.http, create_health_check_http_header(pool, 4));
            if(dynjson_obj.http->header == NULL ){
                goto err;
            }
            header = cf_ctx->headers.elts;
            for (i = 0; i < cf_ctx->headers.nelts; ++i) {
                add_item_health_check_http_header(dynjson_obj.http->header, &header[i]);
            }
        }
    }
#if (NJT_OPENSSL)
    if (hhccf->ssl.ssl_enable) {
        set_health_check_ssl(&dynjson_obj, create_health_check_ssl(pool));
        if(dynjson_obj.ssl == NULL ){
            goto err;
        }

        set_health_check_ssl_enable(dynjson_obj.ssl, 1);
        set_health_check_ssl_ntls(dynjson_obj.ssl, hhccf->ssl.ntls_enable);
#if 0
        // item =njt_json_bool_element(pool,njt_json_fast_key("sessionReuse"),hhccf->ssl.ssl_session_reuse);
        // if(item == NULL ){
        //     goto err;
        // }
        // njt_struct_add(ssl,item,pool);
        // item =njt_json_str_element(pool,njt_json_fast_key("name"), &hhccf->ssl.ssl_name);
        // if(item == NULL ){
        //     goto err;
        // }
        // njt_struct_add(ssl,item,pool);

        // item =njt_json_bool_element(pool,njt_json_fast_key("serverName"),hhccf->ssl.ssl_server_name);
        // if(item == NULL ){
        //     goto err;
        // }
        // njt_struct_add(ssl,item,pool);

        // item =njt_json_bool_element(pool,njt_json_fast_key("verify"),hhccf->ssl.ssl_verify);
        // if(item == NULL ){
        //     goto err;
        // }
        // njt_struct_add(ssl,item,pool);
        // if (hhccf->ssl.ssl_verify_depth > 0) {
        //     item =njt_json_int_element(pool,njt_json_fast_key("verifyDepth"),hhccf->ssl.ssl_verify_depth);
        //     if(item == NULL ){
        //         goto err;
        //     }
        //     njt_struct_add(ssl,item,pool);
        // }
        // if (hhccf->ssl.ssl_trusted_certificate.len > 0) {
        //     item =njt_json_str_element(pool,njt_json_fast_key("trustedCertificate"), &hhccf->ssl.ssl_trusted_certificate);
        //     if(item == NULL ){
        //         goto err;
        //     }
        //     njt_struct_add(ssl,item,pool);
        // }
        // if (hhccf->ssl.ssl_crl.len > 0) {
        //     item =njt_json_str_element(pool,njt_json_fast_key("crl"),  &hhccf->ssl.ssl_crl);
        //     if(item == NULL ){
        //         goto err;
        //     }
        //     njt_struct_add(ssl,item,pool);
        // }
        // if (hhccf->ssl.ssl_certificate.len > 0) {
        //     item =njt_json_str_element(pool,njt_json_fast_key("certificate"), &hhccf->ssl.ssl_certificate);
        //     if(item == NULL ){
        //         goto err;
        //     }
        //     njt_struct_add(ssl,item,pool);
        // }
        // if (hhccf->ssl.ssl_certificate_key.len > 0) {
        //     item =njt_json_str_element(pool,njt_json_fast_key("certificateKey"), &hhccf->ssl.ssl_certificate_key);
        //     if(item == NULL ){
        //         goto err;
        //     }
        //     njt_struct_add(ssl,item,pool);
        // }
#endif
        if (hhccf->ssl.ssl_ciphers.len > 0) {
            set_health_check_ssl_ciphers(dynjson_obj.ssl, &hhccf->ssl.ssl_ciphers);
        }
#if 0
        // if (hhccf->ssl.ssl_protocol_str.len > 0) {
        //     item =njt_json_str_element(pool,njt_json_fast_key("protocols"), &hhccf->ssl.ssl_protocol_str);
        //     if(item == NULL ){
        //         goto err;
        //     }
        //     njt_struct_add(ssl,item,pool);
        // }
#endif
    }
#endif

    return to_json_health_check(pool, &dynjson_obj, OMIT_NULL_ARRAY | OMIT_NULL_OBJ | OMIT_NULL_STR);

    err:
    return NULL;
}

static njt_int_t njt_hc_api_get_conf_info(njt_http_request_t *r, njt_helper_hc_api_data_t *api_data) {
    njt_cycle_t                     *cycle;
    njt_helper_health_check_conf_t  *hhccf;
    njt_buf_t                       *buf;
    njt_chain_t                     out;
    njt_int_t                       rc;
    njt_str_t                       *json;


    cycle = (njt_cycle_t *) njt_cycle;
    if (api_data->hc_type.len == 0 || api_data->upstream_name.len == 0) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, " type and upstream must be set !!");
        return HC_BODY_ERROR;
    }
    hhccf = njt_http_find_helper_hc(cycle, api_data);
    if (hhccf == NULL) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "not find upstream %V hc", &api_data->upstream_name);
        return HC_NOT_FOUND;
    }
    json = njt_hc_conf_info_to_json(r->pool, hhccf);
    if (json == NULL || json->len == 0 ) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "njt_hc_conf_info_to_json error");
        return HC_SERVER_ERROR;
    }
    buf = njt_create_temp_buf(r->pool, json->len);
    if(buf == NULL){
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "njt_create_temp_buf error , size :%ui" ,json->len);
        return HC_SERVER_ERROR;
    }
    buf->last = buf->pos + json->len;
    njt_memcpy(buf->pos, json->data, json->len);
    r->headers_out.status = NJT_HTTP_OK;
    njt_str_t type = njt_string("application/json");
    r->headers_out.content_type = type;
    r->headers_out.content_length_n = buf->last - buf->pos;
    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }
    rc = njt_http_send_header(r);
    if (rc == NJT_ERROR || rc > NJT_OK || r->header_only) {
        return rc;
    }
    buf->last_buf = 1;
    out.buf = buf;
    out.next = NULL;
    rc = njt_http_output_filter(r, &out);
    if (rc == NJT_OK) {
        return HC_RESP_DONE;
    }
    return HC_SERVER_ERROR;
}


static njt_int_t njt_http_health_check_conf_handler(njt_http_request_t *r) {
    njt_int_t rc;
    njt_int_t hrc;
    njt_str_t *uri;
    njt_helper_hc_api_data_t *api_data = NULL;
    njt_array_t *path;

    // njt_health_checker_conf_t * hc_flag = njt_http_get_module_loc_conf(r, njt_helper_health_check_module);
    // if(hc_flag == NULL  || hc_flag->hc_enabled == NJT_CONF_UNSET_UINT || hc_flag->hc_enabled == 0){
    //     return NJT_DECLINED;
    // }

    hrc = HC_SUCCESS;
    if (r->method == NJT_HTTP_GET || r->method == NJT_HTTP_DELETE) {
        api_data = njt_pcalloc(r->pool, sizeof(njt_helper_hc_api_data_t));
        if (api_data == NULL) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "alloc api_data error.");
            hrc = HC_SERVER_ERROR;
            goto out;
        }
    } else if (r->method == NJT_HTTP_POST) {
        rc = njt_http_read_client_request_body(r, njt_http_hc_api_read_data);

        if (rc == NJT_ERROR || rc >= NJT_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }
        return NJT_DONE;
    } else {
        hrc = HC_METHOD_NOT_ALLOW;
        goto out;
    }

    //put (delete location)
    path = njt_array_create(r->pool, 4, sizeof(njt_str_t));
    if (path == NULL) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "array init of path error.");
        hrc = HC_SERVER_ERROR;
        goto out;
    }
    rc = njt_http_api_parse_path(r, path);
    if (rc != HC_SUCCESS || path->nelts <= 0) {
        hrc = HC_PATH_NOT_FOUND;
        goto out;
    }
    uri = path->elts;
    if (path->nelts < 2 
        || (uri[1].len != 2 || njt_strncmp(uri[1].data, "hc", 2) != 0)) {
        hrc = HC_PATH_NOT_FOUND;
        goto out;
    }

    hrc = HC_PATH_NOT_FOUND;
    if (path->nelts == 2 && r->method == NJT_HTTP_GET) {
        hrc = njt_hc_api_get_hcs(r);
    }
    if (path->nelts == 4) {
        api_data->hc_type = uri[2];
        api_data->upstream_name = uri[3];
        if (r->method == NJT_HTTP_DELETE) {
            hrc = njt_hc_api_delete_conf(r, api_data);
        }
        if (r->method == NJT_HTTP_GET) {
            hrc = njt_hc_api_get_conf_info(r, api_data);
        }
//        if (r->method == NJT_HTTP_POST) {
//            hrc = njt_hc_api_add_conf(r->pool, api_data, 1);
//        }
    }


    out:
    if (hrc == HC_RESP_DONE) {
        return NJT_OK;
    }
    return njt_http_health_check_conf_out_handler(r, hrc);
}


static bool njt_hc_stream_check_peer(njt_helper_health_check_conf_t *hhccf, 
                njt_stream_upstream_rr_peer_t *peer){
    njt_lvlhsh_query_t                  lhq;
    njt_int_t                           rc;
    njt_hc_stream_same_peer_t             *stream_lvlhsh_value;
    
    //servername to peers
    lhq.key = peer->server;
    lhq.key_hash = njt_murmur_hash2(lhq.key.data, lhq.key.len);
    lhq.proto = &njt_hc_lvlhsh_proto;

    //find
    rc = njt_lvlhsh_find(&hhccf->servername_to_peers, &lhq);
    if(rc != NJT_OK){
        return false;
    }

    stream_lvlhsh_value = lhq.value;
    if(stream_lvlhsh_value->peer->id == peer->id){
        return true;
    }

    return false;
}

static bool njt_hc_http_check_peer(njt_helper_health_check_conf_t *hhccf, 
                njt_http_upstream_rr_peer_t *peer){
    njt_lvlhsh_query_t                  lhq;
    njt_int_t                           rc;
    njt_hc_http_same_peer_t             *http_lvlhsh_value;
    
    //servername to peers
    lhq.key = peer->server;
    lhq.key_hash = njt_murmur_hash2(lhq.key.data, lhq.key.len);
    lhq.proto = &njt_hc_lvlhsh_proto;

    //find
    rc = njt_lvlhsh_find(&hhccf->servername_to_peers, &lhq);
    if(rc != NJT_OK){
        return false;
    }

    http_lvlhsh_value = lhq.value;
    if(http_lvlhsh_value->peer->id == peer->id){
        return true;
    }

    return false;
}

static njt_int_t njt_hc_http_peer_add_map(njt_helper_health_check_conf_t *hhccf, 
                njt_http_upstream_rr_peer_t *peer){
    njt_lvlhsh_query_t                  lhq;
    njt_int_t                           rc, rc2;
    njt_hc_http_same_peer_t             *http_lvlhsh_value;
    njt_hc_http_peer_element            *http_ele;
    
    //servername to peers
    lhq.key = peer->server;
    lhq.key_hash = njt_murmur_hash2(lhq.key.data, lhq.key.len);
    lhq.proto = &njt_hc_lvlhsh_proto;

    //find
    rc = njt_lvlhsh_find(&hhccf->servername_to_peers, &lhq);
    if(rc != NJT_OK){
        //if not exist, insert and update current peer
        lhq.key = peer->server;
        lhq.key_hash = njt_murmur_hash2(lhq.key.data, lhq.key.len);
        lhq.proto = &njt_hc_lvlhsh_proto;
        lhq.pool = hhccf->map_pool;

        http_lvlhsh_value = njt_pcalloc(hhccf->map_pool, sizeof(njt_hc_http_same_peer_t));
        if(http_lvlhsh_value == NULL){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "njt_create_peers_map_by_peer malloc error");
            return NJT_ERROR;
        }

        http_lvlhsh_value->peer = peer;
        njt_queue_init(&http_lvlhsh_value->datas);

        lhq.value = http_lvlhsh_value;
        rc2 = njt_lvlhsh_insert(&hhccf->servername_to_peers, &lhq);
        if(rc2 != NJT_OK){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "njt_create_peers_map_by_peer servername2peers lvlhash insert fail");
            return NJT_ERROR;
        }

        return NJT_OK;
    }else{
        //if exist, update peers list
        http_lvlhsh_value = lhq.value;
        http_ele = njt_pcalloc(hhccf->map_pool, sizeof(njt_hc_http_peer_element));
        if(http_ele == NULL){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "njt_create_peers_map_by_peer http_ele malloc error");
            return NJT_ERROR;
        }

        http_ele->peer = peer;
        njt_queue_insert_tail(&http_lvlhsh_value->datas, &http_ele->ele_queue);

        return NJT_DECLINED;
    }

    return NJT_OK;
}

static njt_int_t njt_hc_stream_peer_add_map(njt_helper_health_check_conf_t *hhccf, 
            njt_stream_upstream_rr_peer_t *stream_peer){
    njt_lvlhsh_query_t                  lhq;
    njt_int_t                           rc, rc2;
    njt_hc_stream_same_peer_t           *stream_lvlhsh_value;
    njt_hc_stream_peer_element          *stream_ele;

    //servername to peers
    lhq.key = stream_peer->server;
    lhq.key_hash = njt_murmur_hash2(lhq.key.data, lhq.key.len);
    lhq.proto = &njt_hc_lvlhsh_proto;

    //find
    rc = njt_lvlhsh_find(&hhccf->servername_to_peers, &lhq);
    if(rc != NJT_OK){
        //if not exist, insert and update current peer
        lhq.key = stream_peer->server;
        lhq.key_hash = njt_murmur_hash2(lhq.key.data, lhq.key.len);
        lhq.proto = &njt_hc_lvlhsh_proto;
        lhq.pool = hhccf->map_pool;
        
        //if(hhccf->type == NJT_STREAM_MODULE){
        stream_lvlhsh_value = njt_pcalloc(hhccf->map_pool, sizeof(njt_hc_stream_same_peer_t));
        if(stream_lvlhsh_value == NULL){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "njt_create_peers_map_by_peer malloc error");
            return NJT_ERROR;
        }

        stream_lvlhsh_value->peer = stream_peer;
        njt_queue_init(&stream_lvlhsh_value->datas);

        lhq.value = stream_lvlhsh_value;

        rc2 = njt_lvlhsh_insert(&hhccf->servername_to_peers, &lhq);
        if(rc2 != NJT_OK){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "njt_create_peers_map_by_peer servername2peers lvlhash insert fail");
            return NJT_ERROR;
        }

        return NJT_OK;
    }else{
        //if exist, update peers list
        stream_lvlhsh_value = lhq.value;
        stream_ele = njt_pcalloc(hhccf->map_pool, sizeof(njt_hc_stream_peer_element));
        if(stream_ele == NULL){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "njt_create_peers_map_by_peer stream_ele malloc error");
            return NJT_ERROR;
        }

        stream_ele->peer = stream_peer;
        njt_queue_insert_tail(&stream_lvlhsh_value->datas, &stream_ele->ele_queue);

        return NJT_DECLINED;
    }

    return NJT_OK;
}


static void njt_hc_clean_peers_map(njt_helper_health_check_conf_t *hhccf){
    if(hhccf->map_pool){
        njt_destroy_pool(hhccf->map_pool);
        hhccf->map_pool = NULL;
    }

    hhccf->map_pool = njt_create_pool(njt_pagesize, njt_cycle->log);
    if (hhccf->map_pool == NULL || NJT_OK != njt_sub_pool(njt_cycle->pool, hhccf->map_pool)) {
        njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "njt_create_peer_map error");
        return;
    }

    njt_lvlhsh_init(&hhccf->servername_to_peers);
}

/*define the status machine stage*/
static void njt_http_health_check_timer_handler(njt_event_t *ev) {
    njt_helper_health_check_conf_t  *hhccf;
    njt_http_upstream_srv_conf_t    *uscf;
    njt_http_upstream_rr_peers_t    *peers;
    njt_uint_t                      jitter;
    njt_flag_t                      op = 0;
    njt_http_health_check_conf_ctx_t *cf_ctx;
    bool                            map_recreate = false;
    
    hhccf = ev->data;
    cf_ctx = hhccf->ctx;
    if (hhccf == NULL) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "no valid data");
        return;
    }
    if(ev->timer_set){
        njt_del_timer(ev);
        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0,
                      "del timer ");
    }
    if (hhccf->disable) {
        if(hhccf->ref_count == 0 ){
            njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0,
                          "active probe cleanup for disable:/%V/%V" ,&hhccf->type_str,&hhccf->upstream_name);
            njt_destroy_pool(hhccf->pool);
        } else {
            njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0,
                          "active probe cleanup for disable,cleanup is delayed:/%V/%V ref_count = %d ",&hhccf->type_str,&hhccf->upstream_name,hhccf->ref_count);
            njt_add_timer(&hhccf->hc_timer, 1000);
        }
        return;
    }
    uscf = cf_ctx->upstream;
    if (uscf == NULL) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "no upstream data");
        return;
    }

    if (njt_quit || njt_terminate || njt_exiting) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "active probe cleanup for quiting");
        return;
    }

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "Health check timer is triggered.");

    if (hhccf->mandatory == 1 && hhccf->persistent == 0 && hhccf->curr_delay != 0) {
        hhccf->curr_frame += 1000;
    }

    if (hhccf->curr_delay != 0 && hhccf->curr_delay <= hhccf->curr_frame) {
        hhccf->curr_frame = 0;
        op = 1;
    } else if (hhccf->curr_delay == 0) {
        op = 1;
    }

    peers = uscf->peer.data;

    njt_http_upstream_rr_peers_wlock(peers);
    if(hhccf->first || hhccf->update_id != peers->update_id){
        hhccf->first = 0;
        hhccf->update_id = peers->update_id;
        //clear map
        njt_hc_clean_peers_map(hhccf);
        map_recreate = true;
    }

    if (peers->peer) {
        njt_http_health_loop_peer(hhccf, peers, 0, op, map_recreate);
    }
    if (peers->next) {
        njt_http_health_loop_peer(hhccf, peers, 1, op, map_recreate);
    }
    njt_http_upstream_rr_peers_unlock(peers);

    jitter = 0;
    if (hhccf->jitter) {
        jitter = njt_random() % hhccf->jitter;
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "delay %u for the health check timer.", jitter);
    }
    if(hhccf->mandatory == 1 && hhccf->persistent == 0) {
        hhccf->curr_delay = hhccf->interval + jitter;
        njt_add_timer(&hhccf->hc_timer, 1000);
    } else {
        njt_add_timer(&hhccf->hc_timer, hhccf->interval + jitter);
    }

    return;
}

/*
    by zhaokang
*/
static void
njt_stream_health_check_timer_handler(njt_event_t *ev) {
    njt_helper_health_check_conf_t         *hhccf;    
    njt_stream_upstream_srv_conf_t         *uscf;
    njt_stream_upstream_rr_peers_t         *peers;
    njt_stream_health_check_conf_ctx_t     *shccc;
    njt_uint_t                              jitter;
    njt_flag_t                              op;
    bool                                    map_recreate = false;

    hhccf = ev->data;
    if (hhccf == NULL) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "no valid data");
        return;
    }
    if(ev->timer_set){
        njt_del_timer(ev);
        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0,
                      "del timer ");
    }
    if (hhccf->disable) {
        if(hhccf->ref_count == 0 ){
            njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0,
                          "active probe cleanup for disable:/%V/%V ",&hhccf->type_str,&hhccf->upstream_name);
            njt_destroy_pool(hhccf->pool);
        } else {
            njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0,
                          "active probe cleanup for disable,cleanup is delayed:/%V/%V ref_count = %d ",&hhccf->type_str,&hhccf->upstream_name,hhccf->ref_count);
            njt_add_timer(&hhccf->hc_timer, 1000);
        }
        return;
    }

    shccc = hhccf->ctx;
    uscf = shccc->upstream;
    if (uscf == NULL) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "no stream upstream data");
        return;
    }

    if (njt_quit || njt_terminate || njt_exiting) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "stream active probe cleanup for quiting");
        return;
    }

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "Stream health check timer is triggered.");
    
    op = 0;
    if (hhccf->curr_delay != 0 
            && hhccf->curr_delay <= hhccf->curr_frame) {
        
        hhccf->curr_frame = 0;
        op = 1;

    } else if (hhccf->curr_delay == 0) {
        op = 1;
    }

    peers = uscf->peer.data;
    njt_stream_upstream_rr_peers_wlock(peers);
    if(hhccf->first || hhccf->update_id != peers->update_id){
        hhccf->first = 0;
        hhccf->update_id = peers->update_id;
        //clear map
        njt_hc_clean_peers_map(hhccf);
        map_recreate = true;
    }

    if (peers->peer) {
        njt_stream_health_loop_peer(hhccf, peers, 0, op, map_recreate);
    }
    if (peers->next) {
        njt_stream_health_loop_peer(hhccf, peers, 1, op, map_recreate);
    }
    njt_stream_upstream_rr_peers_unlock(peers);

    jitter = 0;
    if (hhccf->jitter) {
        jitter = njt_random() % hhccf->jitter;
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "delay %u for the health check timer.", jitter);
    }
    njt_add_timer(&hhccf->hc_timer, hhccf->interval + jitter);

    return;    
}
static njt_int_t njt_traver_http_upstream_item_handle(void *ctx,njt_http_upstream_srv_conf_t * uscfp){
    njt_cycle_t                     *cycle;
    njt_str_t                       hc_type, upstream_name;
    njt_helper_health_check_conf_t  *hhccf;
    njt_pool_t                      *pool;
    njt_str_t                       msg;

    cycle = (njt_cycle_t *)njt_cycle;

    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "http_upstream_item: %V,mandatory:%ud,persistent:%ud",&uscfp->host,uscfp->mandatory,uscfp->persistent);
    if(uscfp->mandatory == 1) {
        njt_str_set(&hc_type,"http");
        njt_str_set(&msg,"{\"interval\": \"10s\",\n"
                         "\"jitter\": \"1s\",\n"
                         "\"timeout\": \"10s\",\n"
                         "\"passes\": 2,\n"
                         "\"fails\": 1,\n"
                         "\"http\": {\n"
                         "\t\"uri\": \"/robots.txt\",\n"
                         "\t\"status\": \"200-299\"\n"
                         "}}");
        upstream_name.data = uscfp->host.data;
        upstream_name.len = uscfp->host.len;
        hhccf = njt_http_find_helper_hc_by_name_and_type(cycle, &hc_type, &upstream_name);
        if(NULL != hhccf) {
            njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "http upstream %V has added by kv",&uscfp->host);
            return 0;
        }
        pool = (njt_pool_t*)ctx;
        njt_health_check_recovery_conf_info(pool, &msg, &upstream_name, &hc_type);
    }
    return 0;
}

static njt_int_t njt_traver_stream_upstream_item_handle(void *ctx,njt_stream_upstream_srv_conf_t * uscfp){
    njt_cycle_t                     *cycle;
    njt_str_t                       hc_type, upstream_name;
    njt_helper_health_check_conf_t  *hhccf;
    njt_pool_t                      *pool;
    njt_str_t                       msg;

    cycle = (njt_cycle_t *)njt_cycle;

    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "http_upstream_item: %V,mandatory:%ud,persistent:%ud",&uscfp->host,uscfp->mandatory,uscfp->persistent);
    if(uscfp->mandatory == 1) {
        njt_str_set(&hc_type,"stcp");
        njt_str_set(&msg,"{\n"
                         "\"interval\": \"10s\",\n"
                         "\"jitter\": \"1s\",\n"
                         "\"timeout\": \"10s\",\n"
                         "\"passes\": 2,\n"
                         "\"fails\": 1,\n"
                         "\"mandatory\": true,\n"
                         "\"stream\": {\n"
                         "\t\"send\":\"\",\n"
                         "\t\"expect\": \"\"\n"
                         "}\n"
                         "}");
        upstream_name.data = uscfp->host.data;
        upstream_name.len = uscfp->host.len;
        hhccf = njt_http_find_helper_hc_by_name_and_type(cycle, &hc_type, &upstream_name);
        if(NULL != hhccf) {
            njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "http upstream %V has added by kv.",&uscfp->host);
            return 0;
        }
        pool = (njt_pool_t*)ctx;
        njt_health_check_recovery_conf_info(pool, &msg, &upstream_name, &hc_type);
    }
    return 0;
}
static njt_int_t njt_health_check_helper_init_process(njt_cycle_t *cycle) {
    njt_helper_main_conf_t *hmcf;
    njt_pool_t * pool = NULL;

    hmcf = (njt_helper_main_conf_t *) njt_get_conf(cycle->conf_ctx, njt_helper_health_check_module);
    if (hmcf == NULL) {
        njt_log_error(NJT_LOG_EMERG, cycle->log, 0, "health check helper alloc main conf error ");
        return NJT_ERROR;
    }

    if (hmcf->first) {
        njt_health_check_recovery_confs();
    
        /* by zhaokang */
        njt_stream_health_check_recovery_confs();

        // 遍历upstream us->mandatory为1时添加健康检查项   interval   jitter  timeout passes  fails
        pool = njt_create_pool(njt_pagesize,cycle->log);
        if(NULL == pool){
            njt_log_error(NJT_LOG_EMERG, cycle->log, 0, "health check helper alloc force hc memory error ");
            return NJT_ERROR;
        }
        njt_http_upstream_traver(pool,njt_traver_http_upstream_item_handle);
        njt_stream_upstream_traver(pool,njt_traver_stream_upstream_item_handle);

        hmcf->first = 0;
    }
    if(NULL != pool){
        njt_destroy_pool(pool);
    }
    return NJT_OK;
}

static void njt_hc_kv_flush_confs(njt_helper_main_conf_t *hmcf) {
    njt_pool_t  *pool;
    njt_str_t   *msg;
    njt_str_t   key = njt_string(HTTP_HEALTH_CHECK_CONFS);

    pool = njt_create_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
    if (pool == NULL) {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "create pool error in function %s", __func__);
        return;
    }
    msg = njt_hc_confs_to_json(pool, hmcf);
    if (msg == NULL || msg->len == 0) {
        goto end;
    }

    njt_dyn_kv_set(&key, msg);

    end:
    njt_destroy_pool(pool);
}

static void njt_stream_hc_kv_flush_confs(njt_helper_main_conf_t *hmcf) {
    njt_pool_t     *pool;
    njt_str_t      *msg;

    njt_str_t key = njt_string(STREAM_HEALTH_CHECK_CONFS);

    pool = njt_create_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
    if (pool == NULL) {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "create pool error in function %s", __func__);
        return;
    }

    msg = njt_hc_confs_to_json(pool, hmcf);
    if (msg == NULL || msg->len == 0) {
        goto end;
    }
    
    njt_dyn_kv_set(&key, msg);

end:
    njt_destroy_pool(pool);
}

static void njt_hc_kv_flush_conf_info(njt_helper_health_check_conf_t *hhccf) {
    njt_pool_t *pool;
    njt_str_t *msg, tkey1, tkey2;
    njt_str_t key_pre = njt_string(HTTP_HEALTH_CHECK_CONF_INFO);
    njt_str_t key_separator = njt_string(HTTP_HEALTH_CHECK_SEPARATOR);

    pool = njt_create_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
    if (pool == NULL) {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "create pool error in function %s", __func__);
        return;
    }
    njt_str_concat(pool, tkey1, key_pre, hhccf->type_str, goto end);
    njt_str_concat(pool, tkey2, tkey1, key_separator, goto end);
    njt_str_concat(pool, tkey1, tkey2, hhccf->upstream_name, goto end);
    msg = njt_hc_conf_info_to_json(pool, hhccf);
    if (msg == NULL || msg->len == 0 ) {
        njt_log_error(NJT_LOG_ERR, pool->log, 0, "njt_hc_conf_info_to_json error");
        goto end;
    }
    njt_dyn_kv_set(&tkey1, msg);
    end:
    njt_destroy_pool(pool);
}

static void njt_stream_hc_kv_flush_conf_info(njt_helper_health_check_conf_t *hhccf) {
    njt_pool_t         *pool;
    njt_str_t          *msg, tkey1, tkey2;

    njt_str_t key_pre         = njt_string(STREAM_HEALTH_CHECK_CONF_INFO);
    njt_str_t key_separator   = njt_string(STREAM_HEALTH_CHECK_SEPARATOR);

    pool = njt_create_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
    if (pool == NULL) {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "create pool error in function %s", __func__);
        return;
    }

    njt_str_concat(pool, tkey1, key_pre, hhccf->type_str,      goto end);
    njt_str_concat(pool, tkey2, tkey1,   key_separator,        goto end);
    njt_str_concat(pool, tkey1, tkey2,   hhccf->upstream_name, goto end);

    msg = njt_hc_conf_info_to_json(pool, hhccf);
    if (msg == NULL || msg->len == 0 ) {
        njt_log_error(NJT_LOG_ERR, pool->log, 0, "njt_hc_conf_info_to_json error");
        goto end;
    }

    njt_dyn_kv_set(&tkey1, msg);

end:
    if(pool != NULL){
        njt_destroy_pool(pool);
    }
}

static njt_int_t   njt_ctrl_hc_postconfiguration(njt_conf_t *cf){
    njt_http_api_reg_info_t             h;

    njt_str_t  module_key = njt_string("/v1/hc");
    njt_memzero(&h, sizeof(njt_http_api_reg_info_t));
    h.key = &module_key;
    h.handler = njt_http_health_check_conf_handler;
    njt_http_api_module_reg_handler(&h);

    return NJT_OK;
}


static njt_http_module_t njt_helper_health_check_module_ctx = {
        NULL,                                   /* preconfiguration */
        njt_ctrl_hc_postconfiguration,          /* postconfiguration */

        NULL,                                   /* create main configuration */
        NULL,                                  /* init main configuration */

        NULL,                                  /* create server configuration */
        NULL,                                  /* merge server configuration */

        NULL,                                   /* create location configuration */
        NULL                                    /* merge location configuration */
};

njt_module_t njt_helper_health_check_module = {
        NJT_MODULE_V1,
        &njt_helper_health_check_module_ctx,      /* module context */
        NULL,                                   /* module directives */
        NJT_HTTP_MODULE,                        /* module type */
        NULL,                                   /* init master */
        njt_hc_helper_module_init,              /* init module */
        njt_health_check_helper_init_process,/* init process */
        NULL,                                   /* init thread */
        NULL,                                   /* exit thread */
        NULL,                                   /* exit process */
        NULL,                                   /* exit master */
        NJT_MODULE_V1_PADDING
};
