/**
 * @file   njt_http_health_check_module.c
 * @brief  active health check modular for Nginx.
 * Jikui Pei
 */

#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_http_upstream.h>
#include <njt_http_proxy_module.h>
#include "njt_http_match_module.h"

#define NJT_HTTP_SERVER_PORT        5688
#define NJT_HTTP_HC_INTERVAL        5000
#define NJT_HTTP_HC_CONNECT_TIMEOUT 5000


#define NJT_HTTP_HC_TCP                   0x0001
#define NJT_HTTP_HC_HTTP                  0x0002
#define NJT_HTTP_HC_GRPC                  0x0003

#if 0
#define NJT_HTTP_HC_SSL_HELLO             0x0004
#define NJT_HTTP_HC_MYSQL                 0x0008
#define NJT_HTTP_HC_AJP                   0x0010
#endif


/**
 *This module provided directive: health_check url interval=100 timeout=300 port=8080 type=TCP.
 **/

extern njt_module_t  njt_http_proxy_module;

typedef struct njt_http_health_check_peer_s njt_http_health_check_peer_t;
typedef struct njt_health_check_http_parse_s njt_health_check_http_parse_t;


/*Type of callbacks of the checker*/
typedef njt_int_t (*njt_http_health_check_init_pt)
(njt_http_upstream_rr_peer_t *peer);
typedef njt_int_t (*njt_http_health_check_process_pt)
(njt_http_health_check_peer_t *peer);
typedef njt_int_t (*njt_http_health_check_event_handler)
(njt_event_t *ev);
typedef njt_int_t (*njt_http_health_check_update_pt)
(njt_http_health_check_peer_t *hc_peer, njt_int_t status);

typedef struct {
    njt_uint_t                               type;
    njt_str_t                                name;
    njt_flag_t                               one_side;
    /* HTTP */
    njt_http_health_check_event_handler       write_handler;
    njt_http_health_check_event_handler       read_handler;

    njt_http_health_check_init_pt             init;
    njt_http_health_check_process_pt          process;
    njt_http_health_check_update_pt           update;

} njt_health_checker_t;


typedef struct njt_http_health_check_main_conf_s {
//    njt_array_t      health_checks;
    njt_queue_t  health_checks;
} njt_http_health_check_main_conf_t;


typedef struct njt_http_health_check_loc_conf_s {
    njt_queue_t                            queue;
    njt_str_t                              *upstream;
    njt_msec_t                             interval;
    njt_msec_t                             jitter;
    njt_msec_t                             timeout;
    njt_uint_t                             protocol;
    njt_health_checker_t                  *checker;
    njt_uint_t                             port;
    njt_str_t                              uri;
    njt_http_match_t                      *match;
    njt_uint_t                             passes;
    njt_uint_t                             fails;
    njt_event_t                            hc_timer;
    //njt_conf_t                            *cf;
    njt_http_proxy_loc_conf_t             *plcf;
    void                                  *pglcf;//njt_http_grpc_loc_conf_t
    njt_str_t                              gsvc;
    njt_uint_t                             gstatus;
	unsigned							  persistent:1;
	unsigned							  mandatory:1;
    njt_uint_t                             type;
	njt_uint_t                             curr_delay;
	njt_uint_t                             curr_frame;
	njt_uint_t                             test_val;
#if (NJT_HTTP_DYNAMIC_LOC)
    unsigned                               disable;
    njt_pool_t                             *pool;
#endif
} njt_http_health_check_loc_conf_t;


#define NJT_HTTP_PARSE_INIT           0
#define NJT_HTTP_PARSE_STATUS_LINE    1
#define NJT_HTTP_PARSE_HEADER         2
#define NJT_HTTP_PARSE_BODY           4

#define GRPC_STATUS_CODE_OK                  0
#define GRPC_STATUS_CODE_UNIMPLEMENTED       12
#define GRPC_STATUS_CODE_INVALID             ((njt_uint_t)-1)

/*Structure used for holding http parser internal info*/
struct njt_health_check_http_parse_s {
    njt_uint_t                     state;
    njt_uint_t                     code;
    njt_flag_t                     done;
    njt_flag_t                     body_used;
    njt_uint_t                     stage;
    u_char                        *status_text;
    u_char                        *status_text_end;
    njt_uint_t                     count;
    njt_flag_t                     chunked;
    off_t                          content_length_n;
    njt_array_t                    headers;
    u_char                        *header_name_start;
    u_char                        *header_name_end;
    u_char                        *header_start;
    u_char                        *header_end;
    u_char                        *body_start;
    njt_int_t (*process)(njt_http_health_check_peer_t *hc_peer);
    njt_msec_t                     start;
};

/*Main structure of the hc information of a peer*/
struct njt_http_health_check_peer_s {
    njt_uint_t                             peer_id;
    njt_http_health_check_loc_conf_t       *hclcf;
    njt_pool_t                             *pool;
    njt_peer_connection_t                  peer;
    njt_buf_t                              *send_buf;
    njt_buf_t                              *recv_buf;
    njt_chain_t                            *recv_chain;
    njt_chain_t                             *last_chain_node;
    void                                   *parser;
#if (NJT_HTTP_SSL)
    njt_str_t                              ssl_name;
#endif
};


typedef enum {
    njt_http_grpc_hc_st_start = 0,
    njt_http_grpc_hc_st_sent,
    njt_http_grpc_hc_st_end,
} njt_http_grpc_hc_state_e;


/*Module related interface functions*/
static char *njt_http_health_check(njt_conf_t *cf, njt_command_t *cmd,
                                   void *conf);
static char *njt_http_health_check_init_main_conf(njt_conf_t *cf, void *conf);
static void *njt_http_health_check_create_main_conf(njt_conf_t *cf);
//static void *njt_http_health_check_create_loc_conf(njt_conf_t *cf);
//static char *njt_http_health_check_merge_loc_conf(njt_conf_t *cf, void *parent,
  //      void *child);
static njt_int_t njt_http_health_check_init_process(njt_cycle_t *cycle);
static void njt_http_health_check_timer_handler(njt_event_t *ev);

static njt_int_t
njt_http_health_check_common_update(njt_http_health_check_peer_t *hc_peer,
                                    njt_int_t status);


/*Common framework functions of all types of checkers*/
static njt_int_t njt_http_health_check_update_status(
    njt_http_health_check_peer_t *hc_peer, njt_int_t status);

/*update the peer's status without lock*/
static njt_int_t
njt_http_health_check_update_wo_lock(njt_http_health_check_loc_conf_t    *hclcf,njt_http_health_check_peer_t *hc_peer,
                                     njt_http_upstream_rr_peer_t *peer,
                                     njt_int_t status);
static void njt_http_health_check_write_handler(njt_event_t *event);
static void njt_http_health_check_read_handler(njt_event_t *event);
static njt_health_checker_t *njt_http_get_health_check_type(njt_str_t *str);


/*TCP type of checker related functions.*/
static njt_int_t njt_http_health_check_peek_one_byte(njt_connection_t *c);
static njt_int_t njt_http_health_check_tcp_handler(njt_event_t *wev);


/*HTTP type of checker related functions*/
static njt_int_t njt_http_health_check_http_write_handler(njt_event_t *event);
static njt_int_t njt_http_health_check_http_read_handler(njt_event_t *event);

static njt_int_t
njt_http_health_check_http_update_status(njt_http_health_check_peer_t *hc_peer,
        njt_int_t status);
static njt_int_t njt_http_health_check_http_process(
    njt_http_health_check_peer_t *hc_peer);
static njt_int_t njt_health_check_http_parse_status_line(
    njt_http_health_check_peer_t *hc_peer);
static njt_int_t njt_health_check_http_parse_header_line(
    njt_http_health_check_peer_t *hc_peer);
static njt_int_t njt_health_check_http_process_headers(
    njt_http_health_check_peer_t *hc_peer);
static njt_int_t njt_health_check_http_process_body(
    njt_http_health_check_peer_t *hc_peer);

static void njt_http_hc_grpc_loop_peer(njt_http_health_check_loc_conf_t *hclcf, njt_http_upstream_rr_peer_t *peer);
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
static njt_int_t
njt_http_health_check_init(njt_conf_t *cf);

static void njt_http_health_check_destroy(njt_http_core_loc_conf_t *hclf,void* data);

extern njt_module_t  njt_http_grpc_module;

static njt_str_t  njt_http_grpc_hc_svc = njt_string("/grpc.health.v1.Health/Check");

static njt_http_v2_header_t  njt_http_grpc_hc_headers[] = {
    { njt_string("content-length"), njt_string("5") },
    { njt_string("te"), njt_string("trailers") },
    { njt_string("content-type"), njt_string("application/grpc") },
    { njt_string("user-agent"), njt_string("YunKe SLB v2.1 (health check grpc)") },
};


static njt_health_checker_t  njt_health_checks[] = {

    {
        NJT_HTTP_HC_TCP,
        njt_string("tcp"),
        1,
        njt_http_health_check_tcp_handler,
        njt_http_health_check_tcp_handler,
        NULL,
        NULL,
        NULL
    },

    {
        NJT_HTTP_HC_HTTP,
        njt_string("http"),
        0,
        njt_http_health_check_http_write_handler,
        njt_http_health_check_http_read_handler,
        NULL,
        njt_http_health_check_http_process,
        njt_http_health_check_http_update_status
    },

    {
        NJT_HTTP_HC_GRPC,
        njt_string("grpc"),
        0,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
    },

    {
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

static njt_command_t njt_http_health_check_commands[] = {

    {
        njt_string("health_check"), /* directive */
        NJT_HTTP_LOC_CONF | NJT_CONF_ANY, /* location context and takes
                                            1,2,3,4 arguments*/
        njt_http_health_check,            /* configuration setup function */
        0,                                /* No offset. Only one context is supported. */
        0,                                /* No offset when storing the module configuration on struct. */
        NULL
    },

    njt_null_command /* command termination */
};

/* The module context. */
static njt_http_module_t njt_http_health_check_module_ctx = {
    NULL,                                   /* preconfiguration */
    njt_http_health_check_init,             /* postconfiguration */

    njt_http_health_check_create_main_conf, /* create main configuration */
    njt_http_health_check_init_main_conf,   /* init main configuration */

    NULL,                                   /*create server configuration*/
    NULL,                                   /*merge server configuration*/

    NULL,  /* create location configuration */
    NULL    /* merge location configuration */
};

/* Module definition. */
njt_module_t njt_http_health_check_module = {
    NJT_MODULE_V1,
    &njt_http_health_check_module_ctx,  /* module context */
    njt_http_health_check_commands,     /* module directives */
    NJT_HTTP_MODULE,                   /* module type */
    NULL,                              /* init master */
    NULL,                              /* init module */
    njt_http_health_check_init_process, /* init process */
    NULL,                              /* init thread */
    NULL,                              /* exit thread */
    NULL,                              /* exit process */
    NULL,                              /* exit master */
    NJT_MODULE_V1_PADDING
};
static void njt_http_health_check_destroy(njt_http_core_loc_conf_t *clcf,void* data){
    njt_http_health_check_loc_conf_t  *hclcf = data;

    njt_queue_remove(&hclcf->queue);
    hclcf->disable = 1;
}

static njt_int_t
njt_http_health_check_init(njt_conf_t *cf)
{
	njt_http_health_check_main_conf_t *hcmcf;
    njt_http_health_check_loc_conf_t  *hclcf;
//    njt_uint_t                        i;
	njt_http_upstream_rr_peers_t   *peers;
	njt_http_upstream_rr_peer_t    *peer;
    njt_queue_t                     *hcq;

    hcmcf = njt_http_conf_get_module_main_conf(cf,
            njt_http_health_check_module);
    if (hcmcf == NULL) {
        return NJT_OK;
    }

//    hclcf = hcmcf->health_checks.elts;
    for (hcq = njt_queue_head(&hcmcf->health_checks);
         hcq != njt_queue_sentinel(&hcmcf->health_checks)
        ; hcq = njt_queue_next(hcq)) {
//    for (i = 0; i < hcmcf->health_checks.nelts; i++) {

        hclcf = njt_queue_data(hcq,njt_http_health_check_loc_conf_t,queue);
        if(hclcf->persistent == 1 && hclcf->plcf && hclcf->plcf->upstream.upstream) {
			hclcf->plcf->upstream.upstream->hc_type = 2;  //peers = olduscf->peer.data;
		} else if(hclcf->mandatory == 1 && hclcf->plcf && hclcf->plcf->upstream.upstream) {
			hclcf->plcf->upstream.upstream->hc_type = 1;
			peers = hclcf->plcf->upstream.upstream->peer.data;
			if(peers) {
				for (peer = peers->peer; peer;peer = peer->next){
					peer->hc_down = 2; //checking
				}
			}
		}
       
        /*log*/
        //njt_add_timer(hc_timer, refresh_in);
    }

    return NJT_OK;
}

/**
 * Configuration setup function that installs the content handler.
 */
static char *njt_http_health_check(njt_conf_t *cf, njt_command_t *cmd,
                                   void *conf)
{
    njt_http_health_check_main_conf_t   *hcmcf;
    njt_http_health_check_loc_conf_t    *hclcf;
    njt_msec_t                             interval, timeout, jitter;
    njt_uint_t                         i, port, passes, fails;
    njt_str_t                         *value, s;
    njt_str_t                          protocol, uri, match;
    njt_http_proxy_loc_conf_t         *plcf;
    void                              *pglcf = NULL;
    njt_uint_t                         gstatus = 0;
    njt_uint_t                         gpos = 0;
    njt_uint_t                         gconflict = 0;
    njt_uint_t                         type = NJT_HTTP_HC_HTTP;
    njt_str_t                          gsvc = njt_http_grpc_hc_svc;


    hcmcf = njt_http_conf_get_module_main_conf(cf, njt_http_health_check_module);
    if (hcmcf == NULL) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "health check isn't defined.");
        return NJT_CONF_ERROR;
    }

//	hclcf = njt_http_conf_get_module_loc_conf(cf, njt_http_health_check_module);

//    hclcf = njt_array_push(&hcmcf->health_checks);
#if (NJT_HTTP_DYNAMIC_LOC)
    njt_pool_t                             *pool;
    pool = njt_create_pool(NJT_CYCLE_POOL_SIZE, cf->log);
    if (pool == NULL){
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,"http hc create pool error");
        return NJT_CONF_ERROR;
    }
    hclcf = njt_pcalloc(pool,sizeof (njt_http_health_check_loc_conf_t));
#else
    hclcf = njt_pcalloc(cf->pool,sizeof (njt_http_health_check_loc_conf_t));
#endif
    if (hclcf == NULL) {
        return NJT_CONF_ERROR;
    }
//    njt_memzero(hclcf, sizeof(njt_http_health_check_loc_conf_t));
#if (NJT_HTTP_DYNAMIC_LOC)
    hclcf->pool = pool;
#endif
    njt_queue_insert_tail(&hcmcf->health_checks,&hclcf->queue);
    interval = NJT_HTTP_HC_INTERVAL;
    timeout = NJT_HTTP_HC_CONNECT_TIMEOUT;
    jitter = 0;
    passes = 1;
    fails = 1;
    port = 0;
	hclcf->persistent = 0;
	hclcf->mandatory = 0;
    value = cf->args->elts;

    njt_str_set(&protocol, "HTTP");
    njt_str_set(&uri, "/");
    njt_str_null(&match);

    for (i = 1; i < cf->args->nelts; i++) {
        if (gpos > 0) {
            gpos++;
        }

        if (njt_strncmp(value[i].data, "grpc_service=", 13) == 0) {
            if (gpos != 2) {
                goto invalid_parameter_pos;
            }
            s.len = value[i].len - 13;
            s.data = value[i].data + 13;
            gsvc = s;
            gpos = 1;
            continue;
        }

        if (njt_strncmp(value[i].data, "grpc_status=", 12) == 0) {
            if  (gpos != 2) {
                goto invalid_parameter_pos;
            }        
            s.len = value[i].len - 12;
            s.data = value[i].data + 12;
            gstatus = njt_atoi(s.data, s.len);
            gpos = 1;
            continue;
        }

        if (gpos > 1) {
            goto invalid_parameter_pos;
        }

        if (njt_strncmp(value[i].data, "interval=", 9) == 0) {
            s.len = value[i].len - 9;
            s.data = value[i].data + 9;

			interval = njt_parse_time(&s, 0);
            if (interval == (njt_msec_t) NJT_ERROR) {
                goto invalid_parameter;
            }
            continue;
        }

        if (njt_strncmp(value[i].data, "jitter=", 7) == 0) {
            s.len = value[i].len - 7;
            s.data = value[i].data + 7;

            jitter = njt_parse_time(&s, 0);
            if (jitter == (njt_msec_t) NJT_ERROR ) {
                goto invalid_parameter;
            }
            continue;
        }

        if (njt_strncmp(value[i].data, "port=", 5) == 0) {
            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            port = njt_atoi(s.data, s.len);
            if (port == (njt_uint_t) NJT_ERROR || port == 0) {
                goto invalid_parameter;
            }
            continue;
        }

        if (njt_strncmp(value[i].data, "timeout=", 8) == 0) {
            s.len = value[i].len - 8;
            s.data = value[i].data + 8;

            timeout = njt_parse_time(&s, 0);
            if (timeout == (njt_msec_t) NJT_ERROR || timeout == 0) {
                goto invalid_parameter;
            }
            continue;
        }

        if (njt_strncmp(value[i].data, "passes=", 7) == 0) {
            s.len = value[i].len - 7;
            s.data = value[i].data + 7;

            passes = njt_atoi(s.data, s.len);
            if (passes == (njt_uint_t) NJT_ERROR || passes == 0) {
                goto invalid_parameter;
            }
            continue;
        }

        if (njt_strncmp(value[i].data, "fails=", 6) == 0) {
            s.len = value[i].len - 6;
            s.data = value[i].data + 6;

            fails = njt_atoi(s.data, s.len);
            if (fails == (njt_uint_t) NJT_ERROR || fails == 0) {
                goto invalid_parameter;
            }
            continue;
        }

        if (njt_strncmp(value[i].data, "type=", 5) == 0) {
            s.len = value[i].len - 5;
            s.data = value[i].data + 5;
            if (njt_strncasecmp(s.data, (u_char *)"TCP", 3) == 0) {
                protocol = s;
                type = NJT_HTTP_HC_TCP;
            } else if (njt_strncasecmp(s.data, (u_char *)"HTTP", 4) == 0) {
                protocol = s;
                type = NJT_HTTP_HC_HTTP;
            } else if (njt_strncasecmp(s.data, (u_char *)"grpc", 4) == 0) {
                protocol = s;
                type = NJT_HTTP_HC_GRPC;
                gpos = 1;
                if (gconflict > 0) {
                    goto invalid_parameter_grpc;
                }
            } else {
                goto invalid_parameter;
            }
            continue;
        }

        if (njt_strncmp(value[i].data, "uri=", 4) == 0) {
            s.len = value[i].len - 4;
            s.data = value[i].data + 4;
            uri = s;
            gconflict = 1;
            continue;
        }

        if (njt_strncmp(value[i].data, "match=", 6) == 0) {
            s.len = value[i].len - 6;
            s.data = value[i].data + 6;
            match = s;
            gconflict = 1;
            continue;
        }
		if (njt_strncmp(value[i].data, "mandatory", 9) == 0) {
            hclcf->mandatory = 1;
            continue;
        }
		if (njt_strncmp(value[i].data, "persistent", 10) == 0) {
            hclcf->persistent = 1;
            continue;
        }
		if (njt_strncmp(value[i].data, "test_val=", 9) == 0) {
			s.len = value[i].len -  9;
            s.data = value[i].data +  9;

            hclcf->test_val = njt_atoi(s.data, s.len);
            continue;
        }

        goto invalid_parameter;
    }
	if(hclcf->persistent == 1 && hclcf->mandatory == 0) {
		 njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "\"persistent\" requires \"mandatory\"");
		return NJT_CONF_ERROR;
	}
    hclcf->match = NULL;
    /*Find the right match*/
    if (match.len != 0 && match.data) {
        hclcf->match = njt_http_match_create(cf, &match, 0);
    }
#if (NJT_HTTP_DYNAMIC_LOC)
    njt_http_core_loc_conf_t          *clcf;
    njt_http_location_destroy_t       *ld;
    clcf = njt_http_conf_get_module_loc_conf(cf, njt_http_core_module);
    ld = njt_pcalloc(cf->pool,sizeof (njt_http_location_destroy_t));
    if ( ld == NULL ){
        return NJT_CONF_ERROR;
    }
    ld->data = hclcf;
    ld->destroy_loc = njt_http_health_check_destroy;
    ld->next = clcf->destroy_locs;
    clcf->destroy_locs = ld;
#endif
    plcf = njt_http_conf_get_module_loc_conf(cf, njt_http_proxy_module);

    hclcf->uri = uri;
    hclcf->interval = interval;
    hclcf->timeout = timeout;
    hclcf->jitter = jitter;
    hclcf->passes = passes;
    hclcf->fails = fails;
    hclcf->port = port;
    hclcf->checker = njt_http_get_health_check_type(&protocol);
    hclcf->plcf = plcf;

    if (type == NJT_HTTP_HC_GRPC) {
        pglcf = njt_http_conf_get_module_loc_conf(cf, njt_http_grpc_module);
        hclcf->type = type;
        hclcf->pglcf = pglcf;
        hclcf->gsvc = gsvc;
        hclcf->gstatus = gstatus;
    }

    return NJT_CONF_OK;

invalid_parameter:
    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "invalid parameter: \"%V\"", &value[i]);
    return NJT_CONF_ERROR;

invalid_parameter_pos:
    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "invalid parameter postion \"%V\"", &value[i]);
    return NJT_CONF_ERROR;

invalid_parameter_grpc:
    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "uri= or match= parameters are not allowed in grpc health check", &value[i]);
    return NJT_CONF_ERROR;
}
/*
static void *
njt_http_health_check_create_loc_conf(njt_conf_t *cf)
{
    njt_http_health_check_loc_conf_t *hclcf;

    hclcf = njt_pcalloc(cf->pool, sizeof(njt_http_health_check_loc_conf_t));
    if (hclcf == NULL) {
        return NULL;
    }

    hclcf->checker = NJT_CONF_UNSET_PTR;
    hclcf->interval = NJT_CONF_UNSET_UINT;
    hclcf->timeout = NJT_CONF_UNSET_UINT;
    hclcf->port = NJT_CONF_UNSET;
    hclcf->passes = NJT_CONF_UNSET_UINT;
    hclcf->fails = NJT_CONF_UNSET_UINT;
    hclcf->protocol = NJT_CONF_UNSET_UINT;
    hclcf->no_port = NJT_CONF_UNSET_UINT;

    return hclcf;
}

static char *
njt_http_health_check_merge_loc_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_health_check_loc_conf_t *prev = parent;
    njt_http_health_check_loc_conf_t *conf = child;
    njt_conf_merge_ptr_value(conf->checker, prev->checker,
                             &njt_health_checks[0]);
    njt_conf_merge_uint_value(conf->interval, prev->interval,
                              NJT_HTTP_HC_INTERVAL);
    njt_conf_merge_uint_value(conf->timeout, prev->timeout,
                              NJT_HTTP_HC_CONNECT_TIMEOUT);
    njt_conf_merge_uint_value(conf->jitter, prev->jitter,
                              0);
    njt_conf_merge_uint_value(conf->port, prev->port, 80);
    njt_conf_merge_uint_value(conf->passes, prev->passes, 0);
    njt_conf_merge_uint_value(conf->fails, prev->fails, 0);
    njt_conf_merge_uint_value(conf->no_port, prev->no_port, 1);

    return NJT_CONF_OK;
}*/

static void *
njt_http_health_check_create_main_conf(njt_conf_t *cf)
{
    njt_http_health_check_main_conf_t *hcmcf;

    hcmcf = njt_pcalloc(cf->pool, sizeof(njt_http_health_check_main_conf_t));
    if (hcmcf == NULL) {
        return NULL;
    }

    njt_queue_init(&hcmcf->health_checks);
//    if (njt_array_init(&hcmcf->health_checks, cf->pool, 4,
//                       sizeof(njt_http_health_check_loc_conf_t))
//        != NJT_OK) {
//        return NULL;
//    }

    return hcmcf;
}

static void njt_free_peer_resource(njt_http_health_check_peer_t *hc_peer)
{
    njt_pool_t                      *pool;

    pool = hc_peer->pool;
    if (pool) {
        njt_destroy_pool(pool);
    }
    if (hc_peer->hclcf->disable){
        njt_destroy_pool(hc_peer->hclcf->pool);
    }
    if (hc_peer->peer.connection) {
        njt_close_connection(hc_peer->peer.connection);
    }

    njt_free(hc_peer);
    return;
}

static void njt_update_peer(njt_http_health_check_loc_conf_t    *hclcf,
							njt_http_upstream_rr_peer_t *peer,
                            njt_int_t status, njt_uint_t passes, njt_uint_t fails)
{
    peer->hc_check_in_process = 0;
    peer->hc_checks ++;
    if (status == NJT_OK || status == NJT_DONE) {

        peer->hc_consecutive_fails = 0;
        peer->hc_last_passed = 1; //zyg

        if (peer->hc_last_passed) {
            peer->hc_consecutive_passes ++;
        }

        if (peer->hc_consecutive_passes >= passes) {
             peer->hc_down = (peer->hc_down/100 * 100);

			 if(peer->hc_downstart != 0) {
				peer->hc_upstart  = njt_time();
				peer->hc_downtime =  peer->hc_downtime + (((njt_uint_t)((njt_timeofday())->sec )*1000 + (njt_uint_t)((njt_timeofday())->msec) ) - peer->hc_downstart);
			 }
			 peer->hc_downstart =  0;//(njt_timeofday())->sec;

        }
		if(hclcf->mandatory == 1 && hclcf->plcf->upstream.upstream->reload != 1 &&  peer->hc_checks == 1) {  //hclcf->plcf->upstream.upstream->reload
			if(peer->down == 0) {
				  peer->hc_down = (peer->hc_down/100 * 100);  
			 }
		}


    } else {

        peer->hc_fails++;
        peer->hc_consecutive_passes = 0;
        peer->hc_consecutive_fails ++;
        

        /*Only change the status at the first time when fails number mets*/
        if (peer->hc_consecutive_fails == fails) {
            peer->hc_unhealthy ++;

			 peer->hc_down = (peer->hc_down/100 * 100) + 1;

	         peer->hc_downstart =  (njt_uint_t)((njt_timeofday())->sec )*1000 + (njt_uint_t)((njt_timeofday())->msec) ; //(peer->hc_downstart == 0 ?(njt_current_msec):(peer->hc_downstart));
        }
        peer->hc_last_passed = 0;
		if(hclcf->mandatory == 1 && hclcf->plcf->upstream.upstream->reload != 1 &&  peer->hc_checks == 1) {
			if(peer->down == 0) {
				 peer->hc_down = (peer->hc_down/100 * 100) + 1; 
                 peer->hc_downstart =  (njt_uint_t)((njt_timeofday())->sec )*1000 + (njt_uint_t)((njt_timeofday())->msec) ; //(peer->hc_downstart == 0 ?(njt_current_msec):(peer->hc_downstart));
			 }
		}

    }

    return;
}

static njt_int_t
njt_http_health_check_update_wo_lock(njt_http_health_check_loc_conf_t    *hclcf,
									 njt_http_health_check_peer_t *hc_peer,
                                     njt_http_upstream_rr_peer_t *peer,
                                     njt_int_t status)
{
    njt_update_peer(hclcf,peer, status, hc_peer->hclcf->passes, hc_peer->hclcf->fails);
    njt_free_peer_resource(hc_peer);
    return NJT_OK;
}


static njt_int_t
njt_http_health_check_common_update(njt_http_health_check_peer_t *hc_peer,
                                    njt_int_t status)
{
    njt_uint_t                      peer_id;
    njt_http_upstream_srv_conf_t    *uscf;
    njt_http_upstream_rr_peers_t    *peers;
    njt_http_upstream_rr_peer_t     *peer;
    njt_http_health_check_loc_conf_t *hclcf;

    /*Find the right peer and update it's status*/
    peer_id = hc_peer->peer_id;
    hclcf = hc_peer->hclcf;
    if (hclcf->type == NJT_HTTP_HC_GRPC) {
        uscf = njt_http_grpc_hc_get_up_uptream(hc_peer->hclcf->pglcf);
    } else {
        uscf = hc_peer->hclcf->plcf->upstream.upstream;
    }
    peers = (njt_http_upstream_rr_peers_t *)uscf->peer.data;

    njt_http_upstream_rr_peers_wlock(peers);

    for (peer = peers->peer; peer != NULL; peer = peer->next) {
        if (peer->id == peer_id) {
            break;
        }
    }
    if(peer == NULL && peers->next)
    {
      for (peer = peers->next->peer; peer != NULL; peer = peer->next) {
        if (peer->id == peer_id) {
            break;
        }
    	}
    }
    if (peer) {
        njt_update_peer(hc_peer->hclcf,peer, status, hc_peer->hclcf->passes, hc_peer->hclcf->fails);
    } else {
        /*LOG peer not found*/
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "peer %u isn't found",
                       peer_id);
    }

    njt_http_upstream_rr_peers_unlock(peers);
    /*Free the resource*/
    njt_free_peer_resource(hc_peer);

    return NJT_OK;
}

static njt_int_t  njt_http_health_check_tcp_handler(njt_event_t *ev)
{
    njt_connection_t                    *c;
    njt_int_t                           rc;

    c = ev->data;

    rc = njt_http_health_check_peek_one_byte(c);

    return rc;
}

static void njt_http_health_check_write_handler(njt_event_t *wev)
{
    njt_connection_t                    *c;
    njt_http_health_check_peer_t        *hc_peer;
    njt_int_t                            rc;

    c = wev->data;
    hc_peer = c->data;

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
    if (hc_peer->hclcf->disable){
        njt_free_peer_resource(hc_peer);
        return;
    }

    rc = hc_peer->hclcf->checker->write_handler(wev);
    if (rc == NJT_ERROR) {

        /*log the case and update the peer status.*/
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "write action error for health check");
        njt_http_health_check_update_status(hc_peer, NJT_ERROR);
        return;
    } else if (rc == NJT_DONE || rc == NJT_OK) {
        if (hc_peer->hclcf->checker->one_side) {
            njt_http_health_check_update_status(hc_peer, rc);
            return;
        }
    } else {
        /*AGAIN*/
    }

    if (!wev->timer_set) {
        njt_add_timer(wev, hc_peer->hclcf->timeout);
    }

    return;
}


static void njt_http_health_check_read_handler(njt_event_t *rev)
{
    njt_connection_t                    *c;
    njt_http_health_check_peer_t        *hc_peer;
    njt_int_t                            rc;

    c = rev->data;
    hc_peer = c->data;

    if (rev->timedout) {

        /*log the case and update the peer status.*/
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "read action for health check timeout");
        njt_http_health_check_update_status(hc_peer, NJT_ERROR);
        return;
    }

    if (rev->timer_set) {
        njt_del_timer(rev);
    }
    if (hc_peer->hclcf->disable){
        njt_free_peer_resource(hc_peer);
        return;
    }
    rc = hc_peer->hclcf->checker->read_handler(rev);
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
        njt_add_timer(rev, hc_peer->hclcf->timeout);
    }

    return;
}
static njt_int_t njt_http_hc_test_connect(njt_connection_t *c)
{
    int        err;
    socklen_t  len;

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
            == -1)
        {
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

#if (NJT_HTTP_SSL)



static njt_int_t
njt_http_hc_ssl_name( njt_connection_t *c, njt_http_health_check_peer_t *hc_peer)
{
    u_char     *p, *last;
    njt_str_t   name;

    if (hc_peer->hclcf->plcf->upstream.ssl_name) {
        if (hc_peer->hclcf->plcf->upstream.ssl_name->lengths == NULL) {
            name = hc_peer->hclcf->plcf->upstream.ssl_name->value;
        }else{
            return NJT_ERROR;
        }

    } else {
        // 名称待测�?//        name = hc_peer->hclcf->plcf->upstream.upstream->host;
//        if(node->g_server->main_server->no_resolve){
//            name =node->g_server->main_server->name;
//        } else{
//        name.data = njt_pcalloc(c->pool,INET6_ADDRSTRLEN);
//        if(name.data == NULL){
//            njt_ssl_error(NJT_LOG_ERR, c->log, 0,"pcalloc name data error");
//            return NJT_ERROR;
//        }
//        struct sockaddr rem_addr;
//        socklen_t nlen = sizeof(struct sockaddr);
//        int nret = getsockname(c->fd, &rem_addr, &nlen);
//        if(nret == 0 ){
//            name.len = njt_sock_ntop(&rem_addr, nlen,name.data,INET6_ADDRSTRLEN,0) ;
//        }
        name=hc_peer->hclcf->plcf->upstream.upstream->host;

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

    if (!hc_peer->hclcf->plcf->upstream.ssl_server_name) {
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

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,"upstream SSL server name: \"%s\"", name.data);

    if (SSL_set_tlsext_host_name(c->ssl->connection,
                                 (char *) name.data)
        == 0)
    {
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
njt_http_hc_ssl_handshake( njt_connection_t *c,njt_http_health_check_peer_t *hc_peer)
{
    long  rc;

    if (c->ssl->handshaked) {

        if (hc_peer->hclcf->plcf->upstream.ssl_verify) {
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

        hc_peer->peer.connection->write->handler = njt_http_health_check_write_handler;
        hc_peer->peer.connection->read->handler = njt_http_health_check_read_handler;

        /*NJT_AGAIN or NJT_OK*/
        if (hc_peer->hclcf->timeout) {
            njt_add_timer(hc_peer->peer.connection->write, hc_peer->hclcf->timeout);
            njt_add_timer(hc_peer->peer.connection->read, hc_peer->hclcf->timeout);
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
njt_http_hc_ssl_handshake_handler(njt_connection_t *c)
{
    njt_http_health_check_peer_t *hc_peer;
    njt_int_t rc;

    hc_peer = c->data;

    rc = njt_http_hc_ssl_handshake(c,hc_peer);
    if(rc != NJT_OK){
        njt_http_health_check_update_status(hc_peer, NJT_ERROR);
    }
//    njt_http_run_posted_requests(c);
}

static njt_int_t
njt_http_hc_ssl_init_connection( njt_connection_t *c, njt_http_health_check_peer_t *hc_peer)
{
    njt_int_t                  rc;

    if (njt_http_hc_test_connect(c) != NJT_OK) {
        return NJT_ERROR;
    }

    if (njt_ssl_create_connection(hc_peer->hclcf->plcf->upstream.ssl, c,
                                  NJT_SSL_BUFFER|NJT_SSL_CLIENT)!= NJT_OK)
    {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,"ssl init create connection for health check error ");
        return NJT_ERROR;
    }

    c->sendfile = 0;

    if (hc_peer->hclcf->plcf->upstream.ssl_server_name || hc_peer->hclcf->plcf->upstream.ssl_verify) {
        if (njt_http_hc_ssl_name(  c,hc_peer) != NJT_OK) {
            njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,"ssl init check ssl name for health check error ");
            return NJT_ERROR;
        }
    }

//    if (u->conf->ssl_session_reuse) {
//        c->ssl->save_session = njt_http_upstream_ssl_save_session;
//
//        if (u->peer.set_session(&u->peer, u->peer.data) != NJT_OK) {
//            njt_http_upstream_finalize_request(r, u,
//                                               NJT_HTTP_INTERNAL_SERVER_ERROR);
//            return;
//        }
//
//        /* abbreviated SSL handshake may interact badly with Nagle */
//
//        clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);
//
//        if (clcf->tcp_nodelay && njt_tcp_nodelay(c) != NJT_OK) {
//            njt_http_upstream_finalize_request(r, u,
//                                               NJT_HTTP_INTERNAL_SERVER_ERROR);
//            return;
//        }
//    }

    c->log->action = "SSL handshaking to hc";

    rc = njt_ssl_handshake(c);

    if (rc == NJT_AGAIN) {

        if (!c->write->timer_set) {
            njt_add_timer(c->write, hc_peer->hclcf->plcf->upstream.connect_timeout);
        }

        c->ssl->handler = njt_http_hc_ssl_handshake_handler;
        return NJT_OK;
    }

    return njt_http_hc_ssl_handshake(  c,hc_peer);
//    return NJT_OK;
}
#endif


static void njt_http_health_loop_peer(njt_http_health_check_loc_conf_t    *hclcf,njt_http_upstream_rr_peers_t        *peers,njt_flag_t backup,njt_flag_t op)
{
   njt_int_t                            rc;
   njt_http_health_check_peer_t        *hc_peer;
   njt_http_upstream_rr_peer_t *peer;
   njt_http_upstream_rr_peers_wlock(peers);

    peer = peers->peer;
	if(backup == 1) {
		peer = peers->next->peer;
	}
    for (; peer != NULL; peer = peer->next) {

	if(peer->down == 1) //zyg
        {
          continue;
        }
		if((peer->hc_down == 2) || (op == 1) ) {  //checking

			if (peer->hc_check_in_process && peer->hc_checks) {
				njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
							   "peer's health check is in process.");
				continue;
			}

			peer->hc_check_in_process = 1;

			if (hclcf->type == NJT_HTTP_HC_GRPC) {
				njt_http_hc_grpc_loop_peer(hclcf, peer);
			} else {
					hc_peer = njt_calloc(sizeof(njt_http_health_check_peer_t), njt_cycle->log);
					if (hc_peer == NULL) {
						/*log the malloc failure*/
						njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
									"memory allocate failure for health check.");
						continue;
					}

					hc_peer->peer_id = peer->id;
					hc_peer->hclcf = hclcf;
					hc_peer->peer.sockaddr = peer->sockaddr;

					/*customized the peer's port*/
					if (hclcf->port) {
						njt_inet_set_port(hc_peer->peer.sockaddr, hclcf->port);
					}

					hc_peer->peer.socklen = peer->socklen;
					hc_peer->peer.name = &peer->name;
					hc_peer->peer.get = njt_event_get_peer;
					hc_peer->peer.log = njt_cycle->log;
					hc_peer->peer.log_error = NJT_ERROR_ERR;
					hc_peer->pool = njt_create_pool(njt_pagesize, njt_cycle->log);


					njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
								"health check connect to peer of %V.", &peer->name);

					rc = njt_event_connect_peer(&hc_peer->peer);

					if (rc == NJT_ERROR || rc == NJT_DECLINED || rc == NJT_BUSY) {
						njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
									"health check connect to peer of %V errror.", &peer->name);
						/*release the memory and update the statistics*/
						njt_http_health_check_update_wo_lock(hclcf,hc_peer, peer, NJT_ERROR);
						continue;
					}

            hc_peer->peer.connection->data = hc_peer;
            hc_peer->peer.connection->pool = hc_peer->pool;
#if (NJT_HTTP_SSL)

            if (hclcf->plcf->upstream.ssl && hclcf->plcf->upstream.ssl->ctx &&  hc_peer->peer.connection->ssl == NULL) { //zyg
                rc = njt_http_hc_ssl_init_connection( hc_peer->peer.connection,hc_peer);
                if (rc == NJT_ERROR){
                    njt_http_health_check_update_wo_lock(hclcf,hc_peer, peer, NJT_ERROR);
                }
                continue;
            }

#endif

            hc_peer->peer.connection->write->handler = njt_http_health_check_write_handler;
            hc_peer->peer.connection->read->handler = njt_http_health_check_read_handler;

					/*NJT_AGAIN or NJT_OK*/
					if (hclcf->timeout) {
						njt_add_timer(hc_peer->peer.connection->write, hclcf->timeout);
						njt_add_timer(hc_peer->peer.connection->read, hclcf->timeout);
					}
				}
			}
    }

    njt_http_upstream_rr_peers_unlock(peers);
}


/*define the status machine stage*/
static void njt_http_health_check_timer_handler(njt_event_t *ev)
{
    njt_http_health_check_loc_conf_t    *hclcf;
    njt_http_upstream_srv_conf_t        *uscf;
    njt_http_upstream_rr_peers_t        *peers;
    njt_uint_t                           jitter;
	njt_flag_t                           op = 0;
    hclcf = ev->data;
    if (hclcf == NULL) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "no valid data");
        return;
    }
    if(hclcf->disable){
        njt_destroy_pool(hclcf->pool);
        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0,
                      "active probe clearup for disable ");
        return;
    }

    if (hclcf->type == NJT_HTTP_HC_GRPC) {
        uscf = njt_http_grpc_hc_get_up_uptream(hclcf->pglcf);
    } else {
        uscf = hclcf->plcf->upstream.upstream;       
    }

    if (uscf == NULL) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "no upstream data");
        return;
    }


    if (njt_quit || njt_terminate || njt_exiting ) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                      "active probe clearup for quiting");
        return;
    }

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                   "Health check timer is triggered.");

	if(hclcf->mandatory == 1 && hclcf->persistent == 0 && hclcf->curr_delay != 0) {
		hclcf->curr_frame += 1000;
	}

	if(hclcf->curr_delay != 0 && hclcf->curr_delay <= hclcf->curr_frame){
		hclcf->curr_frame = 0;
		op = 1;
	} else if (hclcf->curr_delay == 0){
		op = 1;
	}

    peers = (njt_http_upstream_rr_peers_t *)uscf->peer.data;
    if(peers)
 	{
	 njt_http_health_loop_peer(hclcf,peers,0,op); 
	}
    if(peers->next)
 	{
	 njt_http_health_loop_peer(hclcf,peers,1,op); 
	}
    jitter = 0;
    if (hclcf->jitter) {
        jitter = njt_random() % hclcf->jitter;

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "delay %u for the health check timer.", jitter);
    }
	if(hclcf->mandatory == 1 && hclcf->persistent == 0) {
		hclcf->curr_delay = hclcf->interval + jitter;
		njt_add_timer(&hclcf->hc_timer, 1000);
	} else {
		njt_add_timer(&hclcf->hc_timer, hclcf->interval + jitter);
	}

    return;
}

static njt_int_t
njt_http_health_check_init_process(njt_cycle_t *cycle)
{
    njt_http_health_check_main_conf_t *hcmcf;
    njt_http_health_check_loc_conf_t  *hclcf;
    njt_event_t                       *hc_timer;
//    njt_uint_t                        i;
    njt_uint_t                        refresh_in;
    njt_queue_t                     *hcq;

    if ((njt_process != NJT_PROCESS_WORKER && njt_process != NJT_PROCESS_SINGLE) || njt_worker != 0) {
        /*only works in the worker 0 prcess.*/
        return NJT_OK;
    }
    hcmcf = njt_http_cycle_get_module_main_conf(cycle,
            njt_http_health_check_module);
    if (hcmcf == NULL) {
        return NJT_OK;
    }

//    hclcf = hcmcf->health_checks.elts;

//    for (i = 0; i < hcmcf->health_checks.nelts; i++) {
    for (hcq = njt_queue_head(&hcmcf->health_checks);
         hcq != njt_queue_sentinel(&hcmcf->health_checks)
            ; hcq = njt_queue_next(hcq)) {
        hclcf = njt_queue_data(hcq,njt_http_health_check_loc_conf_t,queue);
        hc_timer = &hclcf->hc_timer;
        hc_timer->handler = njt_http_health_check_timer_handler;
        hc_timer->log = cycle->log;
        hc_timer->data = hclcf;
        hc_timer->cancelable = 1;
        refresh_in = njt_random() % 1000 + hclcf->test_val;
        /*log*/
        njt_add_timer(hc_timer, refresh_in);
    }

    return NJT_OK;
}


static njt_int_t
njt_http_health_check_peek_one_byte(njt_connection_t *c)
{
    char                            buf[1];
    njt_int_t                       n;
    njt_err_t                       err;

    n = recv(c->fd, buf, 1, MSG_PEEK);
    err = njt_socket_errno;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, err,
                   "http check upstream recv(): %i, fd: %d",
                   n, c->fd);

    if (n == 1 || (n == -1 && err == NJT_EAGAIN)) {
        return NJT_OK;
    }

    return NJT_ERROR;
}

static njt_health_checker_t *
njt_http_get_health_check_type(njt_str_t *str)
{
    njt_uint_t  i;

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
njt_http_health_check_dummy_handler(njt_event_t *ev)
{
    njt_log_debug0(NJT_LOG_DEBUG_EVENT, ev->log, 0,
                   "http health check dummy handler");
}

static njt_int_t
njt_http_health_check_http_write_handler(njt_event_t *wev)
{
    njt_connection_t                    *c;
    njt_http_health_check_peer_t        *hc_peer;
    ssize_t                             n, size;

    c = wev->data;
    hc_peer = c->data;

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
                                               &hc_peer->hclcf->uri);
        hc_peer->send_buf->last = njt_snprintf(hc_peer->send_buf->last,
                                               hc_peer->send_buf->end - hc_peer->send_buf->last, "Connection: close" CRLF);
        hc_peer->send_buf->last = njt_snprintf(hc_peer->send_buf->last,
                                               hc_peer->send_buf->end - hc_peer->send_buf->last, "Host: %V" CRLF,
                                               &hc_peer->hclcf->plcf->upstream.upstream->host);
        hc_peer->send_buf->last = njt_snprintf(hc_peer->send_buf->last,
                                               hc_peer->send_buf->end - hc_peer->send_buf->last,
                                               "User-Agent: nginx (health-check)" CRLF);
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

static njt_int_t
njt_http_health_check_http_read_handler(njt_event_t *rev)
{
    njt_connection_t                    *c;
    njt_http_health_check_peer_t        *hc_peer;
    ssize_t                             n, size;
    njt_buf_t                           *b;
    njt_int_t                           rc;
    njt_chain_t                        *chain, *node;
    njt_health_check_http_parse_t      *hp;

    c = rev->data;
    hc_peer = c->data;

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

            rc = hc_peer->hclcf->checker->process(hc_peer);
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
    rc = hc_peer->hclcf->checker->process(hc_peer);

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
njt_http_health_check_http_process(njt_http_health_check_peer_t *hc_peer)
{
    njt_health_check_http_parse_t  *parse;
    njt_int_t                      rc;

    parse = hc_peer->parser;
    rc = parse->process(hc_peer);

    return rc;
}

/*We assume the status line and headers are located in one buffer*/
static njt_int_t
njt_health_check_http_parse_status_line(njt_http_health_check_peer_t *hc_peer)
{
    u_char                        ch;
    u_char                        *p;
    njt_health_check_http_parse_t *hp;
    njt_buf_t                     *b;

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
njt_health_check_http_process_headers(njt_http_health_check_peer_t *hc_peer)
{
    njt_int_t                     rc;
    njt_table_elt_t               *h;
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
njt_health_check_http_parse_header_line(njt_http_health_check_peer_t *hc_peer)
{
    u_char                        c, ch, *p;
    njt_health_check_http_parse_t *hp;
    njt_buf_t                     *b;

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

                c = (u_char)(ch | 0x20);
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
            c = (u_char)(ch | 0x20);
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
njt_health_check_http_process_body(njt_http_health_check_peer_t *hc_peer)
{
    njt_health_check_http_parse_t *hp;

    hp = hc_peer->parser;

    if (hp->done) {
        return NJT_DONE;
    }
    return NJT_OK;
}

static njt_int_t
njt_http_health_check_update_status(njt_http_health_check_peer_t *hc_peer,
                                    njt_int_t status)
{
    njt_int_t rc;

    if (hc_peer->hclcf->checker->update == NULL) {
        rc = njt_http_health_check_common_update(hc_peer, status);
    } else {
        rc = hc_peer->hclcf->checker->update(hc_peer, status);
    }

    return rc;

}


static njt_int_t
njt_http_health_check_http_match_body(njt_http_match_body_t *body,
                                      njt_http_health_check_peer_t *hc_peer)
{
    njt_int_t                          n;
    njt_str_t                          result;
    njt_health_check_http_parse_t      *hp;
    njt_buf_t                          *content;
    njt_uint_t                         size;
    njt_chain_t                        *node;


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
njt_http_health_check_http_match_header(njt_http_match_header_t *input,
                                        njt_http_health_check_peer_t *hc_peer)
{
    njt_health_check_http_parse_t *hp;
    njt_int_t                     rc;
    njt_uint_t                    i;
    njt_int_t                     n;
    njt_table_elt_t               *headers, *header;

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
njt_http_health_check_http_update_status(njt_http_health_check_peer_t *hc_peer,
        njt_int_t status)
{
    njt_int_t                          rc;
    njt_health_check_http_parse_t      *hp;
    njt_http_match_t                   *match;
    njt_uint_t                          i, result;
    njt_http_match_code_t              *code, *codes;
    njt_http_match_header_t            *header, *headers;

    hp = hc_peer->parser;
    match = hc_peer->hclcf->match;

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


static char *
njt_http_health_check_init_main_conf(njt_conf_t *cf, void *conf)
{

    njt_http_health_check_main_conf_t *hcmcf;
    njt_http_health_check_loc_conf_t  *hclcf;
//    njt_uint_t                        i;
    njt_http_proxy_loc_conf_t         *plcf = NULL;
    void                              *pglcf = NULL;
    njt_queue_t                     *hcq;

    hcmcf = conf;
    if (hcmcf == NULL) {
        return NJT_OK;
    }

//    hclcf = hcmcf->health_checks.elts;
//
//    for (i = 0; i < hcmcf->health_checks.nelts; i++) {

    for (hcq = njt_queue_head(&hcmcf->health_checks);
         hcq != njt_queue_sentinel(&hcmcf->health_checks)
            ; hcq = njt_queue_next(hcq)) {

        hclcf = njt_queue_data(hcq,njt_http_health_check_loc_conf_t,queue);
        //hclcf = hclcf + i;  //bug zyg

        if (hclcf->type == NJT_HTTP_HC_GRPC) {
            pglcf = hclcf->pglcf;

            if (njt_http_grpc_hc_get_up_uptream(pglcf) == NULL && !njt_http_grpc_hc_get_lengths(pglcf)) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "upstream must be defined");
                return NJT_CONF_ERROR;
            } else {
#if (NJT_HTTP_UPSTREAM_ZONE)
                if (njt_http_grpc_hc_get_up_uptream(pglcf) == NULL) {
                    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                    "health check requires an upstream ");
                    return NJT_CONF_ERROR;
                }
                if (njt_http_grpc_hc_get_shm_zone(pglcf) == NULL) {
                    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                    "health check requires upstream \"%V\" to be in shared memory",
                                    &plcf->upstream.upstream->host);
                    return NJT_CONF_ERROR;
                }
#else
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "upstream zone must be supported");
                return NJT_CONF_ERROR;
#endif
            }
        } else {
            plcf = hclcf->plcf;

            if (plcf->upstream.upstream == NULL && !plcf->proxy_lengths) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "upstream must be defined.");
                return NJT_CONF_ERROR;
            } else {
#if (NJT_HTTP_UPSTREAM_ZONE)
                if (plcf->upstream.upstream == NULL) {
                    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                    "health check requires an upstream ");
                    return NJT_CONF_ERROR;
                }
                if (plcf->upstream.upstream->shm_zone == NULL) {
                    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                    "health check requires upstream \"%V\" to be in shared memory.",
                                    &plcf->upstream.upstream->host);
                    return NJT_CONF_ERROR;
                }
#else
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "upstream zone must be supported.");
                return NJT_CONF_ERROR;
#endif
            }           
        }
    }

    return NJT_CONF_OK;
}


/* added for grpc health check */


struct njt_http_grpc_hc_peer_s {
    njt_uint_t                              peer_id;
    njt_http_health_check_loc_conf_t       *hclcf;
    njt_pool_t                             *pool;
    njt_peer_connection_t                   pc;
    njt_buf_t                              *send_buf;
    njt_buf_t                              *recv_buf;
    njt_chain_t                            *recv_chain;
    njt_chain_t                            *last_chain_node;
    void                                   *parser;
};

typedef struct njt_http_grpc_hc_peer_s njt_http_grpc_hc_peer_t;

static void
njt_http_hc_grpc_loop_peer(njt_http_health_check_loc_conf_t *hclcf, njt_http_upstream_rr_peer_t *peer) 
{
    njt_int_t                            rc;
    njt_http_grpc_hc_peer_t             *hc_peer;
    njt_http_request_t                  *r;
    njt_http_upstream_t                 *u;
    njt_http_upstream_state_t           *state;
    njt_chain_t                        **last;
    njt_health_check_http_parse_t        *hp;
    njt_list_part_t                      *part;
    njt_table_elt_t                      *header;
    njt_uint_t                            i;
    njt_peer_connection_t                *pc;
    void                                 *grpc_con;
    void                                 *input_filter_ctx;

    hc_peer = njt_calloc(sizeof(njt_http_grpc_hc_peer_t), njt_cycle->log);
    if (hc_peer == NULL) {
        /*log the malloc failure*/
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "memory allocate failure for health check.");
        goto OUT;
    }

    hc_peer->peer_id = peer->id;
    hc_peer->hclcf = hclcf;
    hc_peer->pc.sockaddr = peer->sockaddr;

    /*customized the peer's port*/
    if (hclcf->port) {
        njt_inet_set_port(hc_peer->pc.sockaddr, hclcf->port);
    }

    hc_peer->pc.socklen = peer->socklen;
    hc_peer->pc.name = &peer->name;
    hc_peer->pc.get = njt_event_get_peer;
    hc_peer->pc.log = njt_cycle->log;
    hc_peer->pc.log_error = NJT_ERROR_ERR;
    hc_peer->pool = njt_create_pool(njt_pagesize, njt_cycle->log);

    njt_pool_t *pool;
    pool = hc_peer->pool;

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
    part->nelts = sizeof(njt_http_grpc_hc_headers)/sizeof(njt_http_v2_header_t);
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
    njt_http_set_ctx(r,hc_peer,njt_http_health_check_module);
    r->unparsed_uri = hclcf->gsvc;
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
    u->state = state;
    u->conf = (njt_http_upstream_conf_t *)njt_http_grpc_hc_get_uptream(hclcf->pglcf);
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
    njt_http_health_check_update_wo_lock(hclcf,(njt_http_health_check_peer_t *)hc_peer, peer, NJT_ERROR);
    return;
}


static void
njt_http_grpc_hc_handler(njt_event_t *wev)
{
    njt_connection_t                     *c;
    njt_http_request_t                   *r;
    njt_http_grpc_hc_peer_t              *hc_peer;
    njt_http_upstream_t                  *u;
    njt_health_check_http_parse_t        *hp;
    ssize_t                               n, size;
    njt_peer_connection_t                *pc;
    njt_http_health_check_loc_conf_t     *hclcf;
    njt_uint_t                            result = NJT_ERROR;

    c = wev->data;
    r = c->data;
    u= r->upstream;
    //hc_peer = r->hc;  zyg
    hc_peer = njt_http_get_module_ctx(r,njt_http_health_check_module);
    hp = hc_peer->parser;
    pc = &hc_peer->pc;
    hclcf = hc_peer->hclcf;

    if ((hp->state >= njt_http_grpc_hc_st_sent) || (njt_current_msec - hp->start + 1000 >= hclcf->timeout)) {

        if ((hp->code != GRPC_STATUS_CODE_INVALID) || (njt_current_msec - hp->start + 1000 >= hclcf->timeout)) {
            if ((hp->code == GRPC_STATUS_CODE_OK) || (hp->code == hclcf->gstatus)) {
                result = NJT_OK;
            }

            njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0,
                          "grpc hc %s for peer %V", (result == NJT_OK)?"OK":"ERROR", hc_peer->pc.name);

            /* update peer status and free the resource */
            njt_http_health_check_common_update((njt_http_health_check_peer_t *)hc_peer, result);  
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
        njt_http_health_check_common_update((njt_http_health_check_peer_t *)hc_peer, NJT_ERROR);
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


void
njt_http_grpc_hc_set_status(void *hc, njt_str_t value)
{
    njt_http_health_check_peer_t   *hc_peer;
    njt_health_check_http_parse_t  *hp;
    njt_uint_t                     *pcode;
    
    hc_peer = (njt_http_health_check_peer_t *)hc;
    hp = hc_peer->parser;
    pcode = &hp->code;
    *pcode = (njt_uint_t)njt_atoi(value.data, value.len);
}


void *
njt_http_grpc_hc_get_lcf(void *hc)
{
    void *glcf;
    glcf = ((njt_http_health_check_loc_conf_t *)(((njt_http_health_check_peer_t *)hc)->hclcf))->pglcf;
    return glcf;
}
