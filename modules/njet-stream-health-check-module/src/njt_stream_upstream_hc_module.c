

#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>
#include <njt_stream_proxy_module.h>
#include <njt_stream_upstream_hc_module.h>

#define NJT_STREAM_HC_INTERVAL        5000
#define NJT_STREAM_HC_CONNECT_TIMEOUT 5000


#define NJT_STREAM_HC_TCP                   0x0001
#define NJT_STREAM_HC_UDP                  0x0002

#if 0
#define NJT_STREAM_HC_SSL_HELLO             0x0004
#define NJT_STREAM_HC_MYSQL                 0x0008
#define NJT_STREAM_HC_AJP                   0x0010
#endif


/**
 *This module provided directive: health_check url interval=100 timeout=300 port=8080 type=TCP.
 **/

extern njt_module_t  njt_stream_proxy_module;

typedef struct njt_stream_health_check_peer_s njt_stream_health_check_peer_t;
typedef struct njt_health_check_stream_parse_s njt_health_check_stream_parse_t;


/*Type of callbacks of the checker*/
typedef njt_int_t (*njt_stream_health_check_init_pt)
        (njt_stream_upstream_rr_peer_t *peer);
typedef njt_int_t (*njt_stream_health_check_process_pt)
        (njt_stream_health_check_peer_t *peer);
typedef njt_int_t (*njt_stream_health_check_event_handler)
        (njt_event_t *ev);
typedef njt_int_t (*njt_stream_health_check_update_pt)
        (njt_stream_health_check_peer_t *hc_peer, njt_int_t status);

typedef struct {
    njt_uint_t                               type;
    njt_str_t                                name;
    njt_flag_t                               one_side;
    /* HTTP */
    njt_stream_health_check_event_handler       write_handler;
    njt_stream_health_check_event_handler       read_handler;

    njt_stream_health_check_init_pt             init;
    njt_stream_health_check_process_pt          process;
    njt_stream_health_check_update_pt           update;

} njt_health_checker_t;


typedef struct njt_stream_health_check_main_conf_s {
    njt_array_t      health_checks;
} njt_stream_health_check_main_conf_t;

typedef struct njt_stream_health_check_srv_conf_s {
    njt_str_t                              *upstream;
    njt_msec_t                             interval;
    njt_msec_t                             jitter;
    njt_msec_t                             timeout;
    njt_uint_t                             protocol;
    njt_health_checker_t                  *checker;
    njt_uint_t                             port;
    njt_uint_t                             no_port;
    njt_stream_match_t                      *match;
    njt_uint_t                             passes;
    njt_uint_t                             fails;
    njt_event_t                            hc_timer;
    njt_conf_t                            *cf;
    njt_stream_proxy_srv_conf_t             *plcf;
    unsigned							  persistent:1;
    unsigned							  mandatory:1;
	njt_uint_t                             curr_delay;
	njt_uint_t                             curr_frame;
    njt_uint_t                             test_val;
    struct njt_stream_health_check_srv_conf_s     *array_data;
} njt_stream_health_check_srv_conf_t;


#define NJT_STREAM_PARSE_INIT           0
#define NJT_STREAM_PARSE_STATUS_LINE    1
#define NJT_STREAM_PARSE_HEADER         2
#define NJT_STREAM_PARSE_BODY           4
/*Structure used for holding http parser internal info*/
struct njt_health_check_stream_parse_s {
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
    njt_int_t (*process)(njt_stream_health_check_peer_t *hc_peer);
};

/*Main structure of the hc information of a peer*/
struct njt_stream_health_check_peer_s {
    njt_uint_t                             peer_id;
    njt_stream_health_check_srv_conf_t     *hcscf;
    njt_pool_t                             *pool;
    njt_peer_connection_t                  peer;
    njt_buf_t                             *send_buf;
    njt_buf_t                              *recv_buf;
    njt_chain_t                            *recv_chain;
    njt_chain_t                            *last_chain_node;
    void                                   *parser;
#if (NJT_STREAM_SSL)
    njt_str_t                              ssl_name;
    njt_stream_upstream_rr_peer_t           *rr_peer;
#endif
};

/*Module related interface functions*/
static char *njt_stream_health_check(njt_conf_t *cf, njt_command_t *cmd,
                                   void *conf);
static char *njt_stream_health_check_init_main_conf(njt_conf_t *cf, void *conf);
static void *njt_stream_health_check_create_main_conf(njt_conf_t *cf);
static void *njt_stream_health_check_create_srv_conf(njt_conf_t *cf);
static char *njt_stream_health_check_merge_srv_conf(njt_conf_t *cf, void *parent,void *child);
static njt_int_t njt_stream_health_check_post_conf(njt_conf_t *cf);
static njt_int_t njt_stream_health_check_init_process(njt_cycle_t *cycle);
static void njt_stream_health_check_timer_handler(njt_event_t *ev);

static njt_int_t
njt_stream_health_check_common_update(njt_stream_health_check_peer_t *hc_peer,
                                    njt_int_t status);


/*Common framework functions of all types of checkers*/
static njt_int_t njt_stream_health_check_update_status(
        njt_stream_health_check_peer_t *hc_peer, njt_int_t status);

/*update the peer's status without lock*/
static njt_int_t
njt_stream_health_check_update_wo_lock(njt_stream_health_check_srv_conf_t    *hcscf,
                                     njt_stream_health_check_peer_t *hc_peer,
                                     njt_stream_upstream_rr_peer_t *peer,
                                     njt_int_t status);
static void njt_stream_health_check_write_handler(njt_event_t *event);
static void njt_stream_health_check_read_handler(njt_event_t *event);

static void
njt_stream_hc_init_upstream(njt_stream_health_check_peer_t *hc_peer,njt_stream_upstream_rr_peer_t *peer);


/*TCP type of checker related functions.*/
//static njt_int_t njt_stream_health_check_peek_one_byte(njt_connection_t *c);
static njt_int_t  njt_stream_health_check_recv_handler(njt_event_t *rev);
static njt_int_t  njt_stream_health_check_send_handler(njt_event_t *wev);
static void njt_stream_health_check_dummy_handler(njt_event_t *ev);
static njt_int_t
njt_stream_health_check_init(njt_conf_t *cf);


static njt_health_checker_t  njt_health_checks[] = {

        {
                NJT_STREAM_HC_TCP,
                njt_string("tcp"),
                1,
                njt_stream_health_check_send_handler,
                njt_stream_health_check_recv_handler,
                NULL,
                NULL,
                NULL
        },

        {
                NJT_STREAM_HC_UDP,
                njt_string("udp"),
                1,
                njt_stream_health_check_send_handler,
                njt_stream_health_check_recv_handler,
                NULL,
                NULL,
                NULL
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

static njt_command_t njt_stream_health_check_commands[] = {

        {
                njt_string("health_check"), /* directive */
                NJT_STREAM_SRV_CONF | NJT_CONF_ANY, /* location context and takes1,2,3,4 arguments*/
                njt_stream_health_check,            /* configuration setup function */
                NJT_STREAM_SRV_CONF_OFFSET,                                /* No offset. Only one context is supported. */
                0,                                /* No offset when storing the module configuration on struct. */
                NULL
        },

        {
                njt_string("health_check_timeout"), /* directive */
                NJT_STREAM_SRV_CONF | NJT_CONF_ANY, /* location context and takes1,2,3,4 arguments*/
                njt_conf_set_msec_slot,            /* configuration setup function */
                NJT_STREAM_SRV_CONF_OFFSET,                                /* No offset. Only one context is supported. */
                offsetof(njt_stream_health_check_srv_conf_t,timeout),                                /* No offset when storing the module configuration on struct. */
                NULL
        },

        njt_null_command /* command termination */
};

/* The module context. */
static njt_stream_module_t njt_stream_health_check_module_ctx = {
        NULL,                                   /* preconfiguration */
        njt_stream_health_check_init,                                   /* postconfiguration */

        njt_stream_health_check_create_main_conf, /* create main configuration */
        njt_stream_health_check_init_main_conf,   /* init main configuration */

        njt_stream_health_check_create_srv_conf,  /*create server configuration*/
        njt_stream_health_check_merge_srv_conf     /*merge server configuration*/
};

/* Module definition. */
njt_module_t njt_stream_health_check_module = {
        NJT_MODULE_V1,
        &njt_stream_health_check_module_ctx,  /* module context */
        njt_stream_health_check_commands,     /* module directives */
        NJT_STREAM_MODULE,                   /* module type */
        NULL,                              /* init master */
        NULL,                              /* init module */
        njt_stream_health_check_init_process, /* init process */
        NULL,                              /* init thread */
        NULL,                              /* exit thread */
        NULL,                              /* exit process */
        NULL,                              /* exit master */
        NJT_MODULE_V1_PADDING
};



static njt_int_t
njt_stream_health_check_init(njt_conf_t *cf)
{
	njt_stream_health_check_main_conf_t *hcmcf;
    njt_stream_health_check_srv_conf_t  *hclcf;
    njt_uint_t                        i;
	njt_stream_upstream_rr_peers_t   *peers;
	njt_stream_upstream_rr_peer_t    *peer;

    hcmcf = njt_stream_conf_get_module_main_conf(cf,njt_stream_health_check_module);
    if (hcmcf == NULL) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,"get njt_stream_health_check_module main conf error");
        return NJT_ERROR;
    }

    hclcf = hcmcf->health_checks.elts;

    for (i = 0; i < hcmcf->health_checks.nelts; i++) {

        if(hclcf[i].persistent == 1 && hclcf[i].plcf && hclcf[i].plcf->upstream) {
			hclcf[i].plcf->upstream->hc_type = 2;  //peers = olduscf->peer.data;
		} else if(hclcf[i].mandatory == 1 && hclcf[i].plcf && hclcf[i].plcf->upstream) {
			hclcf[i].plcf->upstream->hc_type = 1;
			peers = hclcf[i].plcf->upstream->peer.data;
			if(peers) {
				for (peer = peers->peer; peer;peer = peer->next){
					peer->hc_down = 2; //checking
				}
			}
		}
    }


    return njt_stream_health_check_post_conf(cf);
}

/**
 * Configuration setup function that installs the content handler.
 */
static char *njt_stream_health_check(njt_conf_t *cf, njt_command_t *cmd,void *conf)
{
    njt_stream_health_check_main_conf_t   *hcmcf;
    njt_stream_health_check_srv_conf_t    *hcscf,*def_hcscf;
    njt_msec_t                             interval,  jitter;
    njt_uint_t                         i, port, passes, fails;
    njt_str_t                           *value, s;
    njt_str_t                           match;
    njt_stream_proxy_srv_conf_t         *plcf;

//#if !(NJT_STREAM_PROXY)
//    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
//                       "http proxy modular must be enabled.");
//    return NJT_CONF_ERROR;
//#endif

    hcmcf = njt_stream_conf_get_module_main_conf(cf, njt_stream_health_check_module);
    if (hcmcf == NULL) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "health check isn't defined.");
        return NJT_CONF_ERROR;
    }
//    hcmcf = conf;
    def_hcscf = conf;

    hcscf = njt_array_push(&hcmcf->health_checks);
    if (hcscf == NULL) {
        return NJT_CONF_ERROR;
    }
    njt_memzero(hcscf, sizeof(njt_stream_health_check_srv_conf_t));
    def_hcscf->array_data = hcscf;

    interval = NJT_STREAM_HC_INTERVAL;
    jitter = 0;
    passes = 1;
    fails = 1;
    port = 0;
    value = cf->args->elts;

    hcscf->protocol = 0;
    njt_str_null(&match);

    for (i = 1; i < cf->args->nelts; i++) {

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

        if (njt_strncmp(value[i].data, "udp", 3) == 0) {
            hcscf->protocol = 1;
            continue;
        }
        
        if (njt_strncmp(value[i].data, "match=", 6) == 0) {
            s.len = value[i].len - 6;
            s.data = value[i].data + 6;
            match = s;
            continue;
        }
        if (njt_strncmp(value[i].data, "mandatory", 9) == 0) {
            hcscf->mandatory = 1;
            continue;
        }
        if (njt_strncmp(value[i].data, "persistent", 10) == 0) {
            hcscf->persistent = 1;
            continue;
        }
		if (njt_strncmp(value[i].data, "test_val=", 9) == 0) {
			s.len = value[i].len -  9;
            s.data = value[i].data +  9;

            hcscf->test_val = njt_atoi(s.data, s.len);
            continue;
        }


        goto invalid_parameter;
    }
	if(hcscf->persistent == 1 && hcscf->mandatory == 0) {
		 njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "\"persistent\" requires \"mandatory\"");
		return NJT_CONF_ERROR;
	}
    hcscf->match = NULL;
    /*Find the right match*/
    if (match.len != 0 && match.data) {
        njt_stream_match_main_conf_t *mmcf = njt_stream_conf_get_module_main_conf(cf,njt_stream_match_module);
        hcscf->match = njt_stream_match_lookup_name(mmcf,match);
        if(hcscf->match == NULL){
            hcscf->match = njt_stream_match_create(cf, &match);
//            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
//                               "can`t find match name is \"%V\"", &match);
//            return NJT_CONF_ERROR;
        }
    }


    plcf = njt_stream_conf_get_module_srv_conf(cf, njt_stream_proxy_module);

    hcscf->checker = &njt_health_checks[hcscf->protocol];
    hcscf->interval = interval ;
    hcscf->jitter = jitter ;
    hcscf->passes = passes;
    hcscf->fails = fails;
    hcscf->port = port;
    hcscf->plcf = plcf;


    return NJT_CONF_OK;

    invalid_parameter:
    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\"", &value[i]);
    return NJT_CONF_ERROR;
}

static void *
njt_stream_health_check_create_srv_conf(njt_conf_t *cf)
{
    njt_stream_health_check_srv_conf_t *hcscf;

    hcscf = njt_pcalloc(cf->pool, sizeof(njt_stream_health_check_srv_conf_t));
    if (hcscf == NULL) {
        return NULL;
    }

    hcscf->checker = NJT_CONF_UNSET_PTR;
    hcscf->interval = NJT_CONF_UNSET_MSEC;
    hcscf->jitter   = NJT_CONF_UNSET_MSEC;
    hcscf->timeout = NJT_CONF_UNSET_MSEC;
    hcscf->port = NJT_CONF_UNSET;
    hcscf->passes = NJT_CONF_UNSET_UINT;
    hcscf->fails = NJT_CONF_UNSET_UINT;
    hcscf->protocol = NJT_CONF_UNSET_UINT;
    hcscf->no_port = NJT_CONF_UNSET_UINT;

    return hcscf;
}

static char *
njt_stream_health_check_merge_srv_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_stream_health_check_srv_conf_t *prev = parent;
    njt_stream_health_check_srv_conf_t *conf = child;
    njt_conf_merge_ptr_value(conf->checker, prev->checker,&njt_health_checks[0]);
    njt_conf_merge_msec_value(conf->interval, prev->interval,NJT_STREAM_HC_INTERVAL);
    njt_conf_merge_msec_value(conf->timeout, prev->timeout,NJT_STREAM_HC_CONNECT_TIMEOUT);
    njt_conf_merge_msec_value(conf->jitter, prev->jitter,0);
    njt_conf_merge_uint_value(conf->port, prev->port, 80);
    njt_conf_merge_uint_value(conf->passes, prev->passes, 0);
    njt_conf_merge_uint_value(conf->fails, prev->fails, 0);
    njt_conf_merge_uint_value(conf->no_port, prev->no_port, 1);

    if(conf->array_data != NULL) {
        conf->array_data->timeout = conf->timeout;
    }
    return NJT_CONF_OK;
}

static void *
njt_stream_health_check_create_main_conf(njt_conf_t *cf)
{
    njt_stream_health_check_main_conf_t *hcmcf;

    hcmcf = njt_pcalloc(cf->pool, sizeof(njt_stream_health_check_main_conf_t));
    if (hcmcf == NULL) {
        return NULL;
    }

    if (njt_array_init(&hcmcf->health_checks, cf->pool, 4,
                       sizeof(njt_stream_health_check_srv_conf_t))
        != NJT_OK) {
        return NULL;
    }

    return hcmcf;
}

static njt_int_t njt_stream_health_check_post_conf(njt_conf_t *cf){
    njt_stream_health_check_srv_conf_t         *hcscf;
    njt_stream_health_check_main_conf_t        *hcmcf;
    njt_uint_t  index;

    hcmcf = njt_stream_conf_get_module_main_conf(cf,njt_stream_health_check_module);
    if(hcmcf == NULL){
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,"get njt_stream_health_check_module main conf error");
        return NJT_ERROR;
    }
    hcscf = hcmcf->health_checks.elts;
    for(index = 0 ; index < hcmcf->health_checks.nelts;index++){
        if(hcscf[index].match != NULL && hcscf[index].match->ctx == NJT_CONF_UNSET_PTR){
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,"can`t find match name is \"%v\"",&hcscf[index].match->match_name);
            return NJT_ERROR;
        }
    }
    return NJT_OK;
}
#if (NJT_STREAM_ZONE_SYNC)
#else
static void
njt_stream_close_connection(njt_connection_t *c)
{
    njt_pool_t  *pool;

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0,
                   "close stream connection: %d", c->fd);

#if (NJT_STREAM_SSL)

    if (c->ssl) {
        if (njt_ssl_shutdown(c) == NJT_AGAIN) {
            c->ssl->handler = njt_stream_close_connection;
            return;
        }
    }

#endif

#if (NJT_STAT_STUB)
    (void) njt_atomic_fetch_add(njt_stat_active, -1);
#endif

    pool = c->pool;

    njt_close_connection(c);

    njt_destroy_pool(pool);
}
#endif
static void njt_free_peer_resource(njt_stream_health_check_peer_t *hc_peer)
{
//    njt_pool_t                      *pool;

//    pool = hc_peer->pool;
//    if (pool) {
//        njt_destroy_pool(pool);
//    }

    if (hc_peer->peer.connection) {
        njt_stream_close_connection(hc_peer->peer.connection);
    }

    njt_free(hc_peer);
    return;
}



static void njt_update_peer(njt_stream_health_check_srv_conf_t    *hclcf,
							njt_stream_upstream_rr_peer_t *peer,
                            njt_int_t status, njt_uint_t passes, njt_uint_t fails)
{
    peer->hc_check_in_process = 0;
    peer->hc_checks ++;

    if (status == NJT_OK || status == NJT_DONE) {

        peer->hc_consecutive_fails = 0;
        peer->hc_last_passed = 1; //zyg

        if (peer->hc_last_passed || peer->hc_checks == 1) {
            peer->hc_consecutive_passes ++;
        }

        if (peer->hc_consecutive_passes >= passes) {
             peer->hc_down = (peer->hc_down/100 * 100);
            if(peer->hc_downstart != 0) {
				peer->hc_upstart  = njt_time();
                peer->hc_downtime =  peer->hc_downtime + (((njt_uint_t)((njt_timeofday())->sec  )*1000 + (njt_uint_t)((njt_timeofday())->msec) ) - peer->hc_downstart);
            }
            peer->hc_downstart =  0;//(njt_timeofday())->sec;
        }
		if(hclcf->mandatory == 1 && hclcf->plcf->upstream->reload != 1 &&  peer->hc_checks == 1) {
			if(peer->down == 0) {
				 peer->hc_down = (peer->hc_down/100 * 100);
                peer->hc_downtime =  peer->hc_downtime + (((njt_uint_t)((njt_timeofday())->sec  )*1000 + (njt_uint_t)((njt_timeofday())->msec) ) - peer->hc_downstart);
			 }
		}

        //peer->hc_last_passed = 1;

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
		if(hclcf->mandatory == 1 &&  hclcf->plcf->upstream->reload != 1 &&  peer->hc_checks == 1) {
			if(peer->down == 0) {
				  peer->hc_down = (peer->hc_down/100 * 100) + 1;
			 }
		}
    }

    return;
}

static njt_int_t
njt_stream_health_check_update_wo_lock(njt_stream_health_check_srv_conf_t    *hclcf,
									 njt_stream_health_check_peer_t *hc_peer,
                                     njt_stream_upstream_rr_peer_t *peer,
                                     njt_int_t status)
{
    njt_update_peer(hclcf,peer, status, hc_peer->hcscf->passes, hc_peer->hcscf->fails);
    njt_free_peer_resource(hc_peer);
    return NJT_OK;
}

static njt_int_t
njt_stream_health_check_common_update(njt_stream_health_check_peer_t *hc_peer,
                                    njt_int_t status)
{
    njt_uint_t                      peer_id;
    njt_stream_upstream_srv_conf_t    *uscf;
    njt_stream_upstream_rr_peers_t    *peers;
    njt_stream_upstream_rr_peer_t     *peer;


    /*Find the right peer and update it's status*/
    peer_id = hc_peer->peer_id;
    uscf = hc_peer->hcscf->plcf->upstream;
    peers = (njt_stream_upstream_rr_peers_t *)uscf->peer.data;

    njt_stream_upstream_rr_peers_wlock(peers);

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
        njt_update_peer(hc_peer->hcscf,peer, status, hc_peer->hcscf->passes, hc_peer->hcscf->fails);
    } else {
        /*LOG peer not found*/
        njt_log_debug1(NJT_LOG_ERR, njt_cycle->log, 0, "peer %u isn't found",
                       peer_id);
    }

    njt_stream_upstream_rr_peers_unlock(peers);
    /*Free the resource*/
    njt_free_peer_resource(hc_peer);

    return NJT_OK;
}

inline static njt_int_t njt_stream_hc_init_buf(njt_connection_t *c){
    njt_stream_health_check_peer_t        *hc_peer;
    njt_uint_t size;

    //plus max is 0x40000LL
    size = njt_pagesize;
    hc_peer = c->data;
    if(hc_peer->recv_buf == NULL){
        if(hc_peer->hcscf->match->regex == NJT_CONF_UNSET_PTR || hc_peer->hcscf->match->regex == NULL){
            size = hc_peer->hcscf->match->expect.len;
        }
        hc_peer->recv_buf = njt_create_temp_buf(hc_peer->pool, size);
        if(hc_peer->recv_buf == NULL){
            njt_log_error(NJT_LOG_EMERG, c->log, 0,"cannot alloc njt_buf_t in check match all");
            return NJT_ERROR;
        }
        hc_peer->recv_buf->last = hc_peer->recv_buf->pos = hc_peer->recv_buf->start;
    }
    return NJT_OK;
}

static njt_int_t njt_stream_health_check_match_all(njt_connection_t *c){
    njt_stream_health_check_peer_t        *hc_peer;
    njt_buf_t                           *b;
    ssize_t                             n, size;
    njt_int_t                           rc;

    hc_peer = c->data;
    rc = njt_stream_hc_init_buf(c);
    if(rc != NJT_OK){
        return rc;
    }
    for (;;) {
        b = hc_peer->recv_buf;
        size = b->end - b->last;
        n = c->recv(c, b->last, size);
        if (n > 0) {
            b->last += n;
            /*link chain buffer*/
            if (b->last == b->end) {
                if(njt_strncmp(hc_peer->hcscf->match->expect.data,hc_peer->recv_buf->start,
                               hc_peer->hcscf->match->expect.len)==0){
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
            return NJT_ERROR;
        }
        break;
    }
    return NJT_ERROR;
}

static njt_int_t njt_stream_health_check_match_regex(njt_connection_t *c){
    njt_stream_health_check_peer_t        *hc_peer;
    njt_buf_t                           *b;
    ssize_t                             n, size;
    njt_int_t                           rc;
    njt_str_t                           tmp_str;

    hc_peer = c->data;
    rc = njt_stream_hc_init_buf(c);
    if(rc != NJT_OK){
        return rc;
    }
    for (;;) {
        b = hc_peer->recv_buf;
        size = b->end - b->last;
        n = c->recv(c, b->last, size);
        if (n > 0) {
            b->last += n;
            tmp_str.data = hc_peer->recv_buf->pos;
            tmp_str.len = hc_peer->recv_buf->last - hc_peer->recv_buf->pos;
            if(njt_regex_exec(hc_peer->hcscf->match->regex,&tmp_str,NULL,0)!=NJT_REGEX_NO_MATCHED){
                return NJT_OK;
            }
            /*link chain buffer*/
            if (b->last == b->end) {
                njt_log_debug0(NJT_LOG_ERR, c->log, 0,"health check match buffer is full");
                return NJT_ERROR;
            }
        }
        if (n == NJT_AGAIN) {
            if (njt_handle_read_event(c->read, 0) != NJT_OK) {
                njt_log_debug0(NJT_LOG_ERR, c->log, 0,"read event handle error for health check");
                return NJT_ERROR;
            }
            return NJT_AGAIN;
        }
        if (n == NJT_ERROR) {
            njt_log_debug0(NJT_LOG_ERR, c->log, 0,"read error for health check");
            return NJT_ERROR;
        }
        break;
    }
    return NJT_ERROR;
}

static njt_int_t  njt_stream_health_check_recv_handler(njt_event_t *rev)
{
    njt_connection_t                    *c;
    njt_int_t                           rc;
    njt_stream_health_check_peer_t        *hc_peer;
    u_char buf[4];
    njt_int_t size;

    c = rev->data;
    hc_peer = c->data;

    rc = NJT_ERROR;
    if( hc_peer->hcscf->match == NULL || hc_peer->hcscf->match->expect.data == NULL ){
        if(rev->ready){
//            if(hc_peer->hcscf->protocol == 1){
                size = c->recv(c, buf, 4);
                if (size > 0) {
                    rc = NJT_OK;
                }
//            }
        }

//        rc = njt_stream_health_check_peek_one_byte(c);
    }else{
        if(hc_peer->hcscf->match->regex == NJT_CONF_UNSET_PTR || hc_peer->hcscf->match->regex == NULL){
            rc = njt_stream_health_check_match_all(c);
        }else{
            rc = njt_stream_health_check_match_regex(c);
        }
    }
    return rc;
}
static u_char* test_str=(u_char*)"nginx health check";
static njt_int_t  njt_stream_health_check_send_handler(njt_event_t *wev)
{
    njt_connection_t                    *c;
    njt_int_t                           rc;
    njt_stream_health_check_peer_t      *hc_peer;
    njt_uint_t                          size;
    njt_int_t                           n;

    c = wev->data;
    hc_peer = c->data;
    rc = NJT_OK;

    if(  hc_peer->hcscf->match == NULL || hc_peer->hcscf->match->send.len == 0){
        if(hc_peer->hcscf->protocol == 1){
            n = c->send(c,test_str,18);
            if(n<=0){
                rc = NJT_ERROR;
            }
        }
        return rc;
    }

    if (hc_peer->send_buf == NULL) {
        hc_peer->send_buf = njt_pcalloc(hc_peer->pool, sizeof(njt_buf_t));
        if (hc_peer->send_buf == NULL) {
            /*log the send buf allocation failure*/
            njt_log_debug0(NJT_LOG_ERR, njt_cycle->log, 0,
                           "malloc failure of the send buffer for health check.");
            return NJT_ERROR;
        }
        hc_peer->send_buf->pos = hc_peer->hcscf->match->send.data;
        hc_peer->send_buf->last = hc_peer->send_buf->pos + hc_peer->hcscf->match->send.len;
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



static void njt_stream_health_check_write_handler(njt_event_t *wev)
{
    njt_connection_t                    *c;
    njt_stream_health_check_peer_t        *hc_peer;
    njt_int_t                            rc;

    c = wev->data;
    hc_peer = c->data;

    if (wev->timedout) {
        /*log the case and update the peer status.*/
        njt_log_debug0(NJT_LOG_ERR, njt_cycle->log, 0,
                       "write action for health check timeout");
        wev->handler = njt_stream_health_check_dummy_handler;
        njt_handle_write_event(wev, 0);
        njt_stream_health_check_update_status(hc_peer, NJT_ERROR);
        return;
    }

    if (wev->timer_set) {
        njt_del_timer(wev);
    }

    rc = hc_peer->hcscf->checker->write_handler(wev);
    wev->handler = njt_stream_health_check_dummy_handler;
    njt_handle_write_event(wev, 0);
    if (rc == NJT_ERROR) {

        /*log the case and update the peer status.*/
        njt_log_debug0(NJT_LOG_ERR, njt_cycle->log, 0,
                       "write action error for health check");
        njt_stream_health_check_update_status(hc_peer, NJT_ERROR);
        return;
    } else if (rc == NJT_DONE || rc == NJT_OK) {
        if ((hc_peer->hcscf->match == NULL || hc_peer->hcscf->match->expect.len == 0)
        && hc_peer->hcscf->protocol == 0   //udp 等待接收 icmp
        ) {
            njt_stream_health_check_update_status(hc_peer, rc);
            return;
        }else{
            if(!c->read->timer_set){
                njt_event_add_timer(c->read,hc_peer->hcscf->timeout);
            }
        }

    } else {
        /*AGAIN*/
        njt_stream_health_check_update_status(hc_peer, rc);
    }

//    if (!wev->timer_set) {
//        njt_add_timer(wev, hc_peer->hcscf->timeout);
//    }

    return;
}


static void njt_stream_health_check_read_handler(njt_event_t *rev)
{
    njt_connection_t                    *c;
    njt_stream_health_check_peer_t        *hc_peer;
    njt_int_t                            rc;

    c = rev->data;
    hc_peer = c->data;
    rc = NJT_OK;

    if (rev->timedout) {
        if(hc_peer->hcscf->protocol == 1 && (hc_peer->hcscf->match == NULL || hc_peer->hcscf->match->expect.len == 0)){
            rc = NJT_OK;
            goto end;
        }
        /*log the case and update the peer status.*/
        njt_log_debug0(NJT_LOG_ERR, njt_cycle->log, 0,
                       "read action for health check timeout");
        rc = NJT_ERROR;
        goto end;
    }

    if (rev->timer_set) {
        njt_del_timer(rev);
    }
    rc = hc_peer->hcscf->checker->read_handler(rev);
    if(rc== NJT_OK){
        goto end;
    }
    if (rc == NJT_ERROR) {
        /*log the case and update the peer status.*/
        njt_log_debug0(NJT_LOG_ERR, njt_cycle->log, 0,"read action error for health check");
        goto end;
    } else if (rc == NJT_DONE) {
        njt_stream_health_check_update_status(hc_peer, rc);
        return;
    } else {
        /*AGAIN*/
    }
    return;

    end:
    rev->handler = njt_stream_health_check_dummy_handler;
    if (njt_handle_write_event(rev, 0) != NJT_OK) {
        /*LOG the failure*/
        njt_log_debug0(NJT_LOG_ERR, njt_cycle->log, 0,"write event handle error for health check");
    }
    njt_stream_health_check_update_status(hc_peer, rc);
    return;

}

static njt_int_t
njt_stream_hc_test_connect(njt_connection_t *c)
{
    int        err;
    socklen_t  len;

#if (NJT_HAVE_KQUEUE)

    if (njt_event_flags & NJT_USE_KQUEUE_EVENT)  {
        err = c->write->kq_errno ? c->write->kq_errno : c->read->kq_errno;

        if (err) {
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
            (void) njt_connection_error(c, err, "connect() failed");
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}

#if (NJT_STREAM_SSL)

static void
njt_stream_hc_ssl_handshake(njt_connection_t *pc)
{
    long                          rc;
    njt_stream_proxy_srv_conf_t  *pscf;
    njt_stream_health_check_peer_t *hc_peer;

    hc_peer = pc->data;

    pscf = hc_peer->hcscf->plcf;

    if (pc->ssl->handshaked) {

        if (pscf->ssl_verify) {
            rc = SSL_get_verify_result(pc->ssl->connection);

            if (rc != X509_V_OK) {
                njt_log_error(NJT_LOG_ERR, pc->log, 0,
                              "hc SSL certificate verify error: (%l:%s)",
                              rc, X509_verify_cert_error_string(rc));
                goto failed;
            }

            if (njt_ssl_check_host(pc, &hc_peer->ssl_name) != NJT_OK) {
                njt_log_error(NJT_LOG_ERR, pc->log, 0,
                              "hc SSL certificate does not match \"%V\"",
                              &hc_peer->ssl_name);
                goto failed;
            }
        }

        if (pc->write->timer_set) {
            njt_del_timer(pc->write);
        }

        njt_stream_hc_init_upstream(hc_peer,hc_peer->rr_peer);

        return;
    }

    failed:

    njt_stream_health_check_update_wo_lock(hc_peer->hcscf, hc_peer, hc_peer->rr_peer, NJT_ERROR);
//    njt_stream_health_check_update_status(hc_peer, NJT_ERROR);
}

static void
njt_stream_hc_connect_handler(njt_event_t *ev)
{
    njt_connection_t      *c;
    njt_stream_health_check_peer_t *hc_peer;

    c = ev->data;
    hc_peer = c->data;

    if (ev->timedout) {
        njt_log_error(NJT_LOG_ERR, c->log, NJT_ETIMEDOUT, "hc timed out");
        njt_stream_health_check_update_wo_lock(hc_peer->hcscf, hc_peer, hc_peer->rr_peer, NJT_ERROR);
//        njt_stream_health_check_update_status(hc_peer, NJT_ERROR);
        return;
    }

    njt_del_timer(c->write);

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, c->log, 0,
                   "stream proxy connect upstream");

    if (njt_stream_hc_test_connect(c) != NJT_OK) {
        njt_stream_health_check_update_wo_lock(hc_peer->hcscf, hc_peer, hc_peer->rr_peer, NJT_ERROR);
//        njt_stream_health_check_update_status(hc_peer, NJT_ERROR);
        return;
    }

    njt_stream_hc_init_upstream(hc_peer,hc_peer->rr_peer);
}
static njt_int_t
njt_stream_hc_ssl_name(njt_stream_health_check_peer_t *hc_peer)
{
    u_char                       *p, *last;
    njt_str_t                     name;
    njt_stream_proxy_srv_conf_t  *pscf;
//    njt_connection_t             *c;

    pscf = hc_peer->hcscf->plcf;
//    c= hc_peer->peer.connection;

    if (hc_peer->hcscf->plcf->ssl_name) {
        if (hc_peer->hcscf->plcf->ssl_name->lengths == NULL) {
            name = hc_peer->hcscf->plcf->ssl_name->value;
        }else{
            return NJT_ERROR;
        }

    } else {
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
        name=hc_peer->hcscf->plcf->upstream->host;

    }

    if (name.len == 0) {
        goto done;
    }

    /*
     * ssl name here may contain port, strip it for compatibility
     * with the http module
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

    if (!pscf->ssl_server_name) {
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

    p = njt_pnalloc(hc_peer->peer.connection->pool, name.len + 1);
    if (p == NULL) {
        return NJT_ERROR;
    }

    (void) njt_cpystrn(p, name.data, name.len + 1);

    name.data = p;

    njt_log_debug1(NJT_LOG_DEBUG_STREAM,hc_peer->peer.connection->log, 0,
                   "hc SSL server name: \"%s\"", name.data);

    if (SSL_set_tlsext_host_name(hc_peer->peer.connection->ssl->connection,
                                 (char *) name.data)
        == 0)
    {
        njt_ssl_error(NJT_LOG_ERR, hc_peer->peer.connection->log, 0,
                      "SSL_set_tlsext_host_name(\"%s\") failed", name.data);
        return NJT_ERROR;
    }

#endif

    done:

    hc_peer->ssl_name = name;

    return NJT_OK;
}
static void
njt_stream_hc_ssl_init_connection(njt_stream_health_check_peer_t *hc_peer,njt_stream_upstream_rr_peer_t *peer)
{
    njt_int_t                     rc;
    njt_connection_t             *pc;
    njt_stream_proxy_srv_conf_t  *pscf;


    pc = hc_peer->peer.connection;
    pscf = hc_peer->hcscf->plcf;
    hc_peer->rr_peer = peer;

    if (njt_ssl_create_connection(pscf->ssl, pc, NJT_SSL_BUFFER|NJT_SSL_CLIENT)
        != NJT_OK)
    {
//        njt_stream_health_check_update_status(hc_peer, NJT_ERROR);
        njt_stream_health_check_update_wo_lock(hc_peer->hcscf, hc_peer, peer, NJT_ERROR);
        return;
    }

    if (pscf->ssl_server_name || pscf->ssl_verify) {
        if (njt_stream_hc_ssl_name(hc_peer) != NJT_OK) {
//            njt_stream_health_check_update_status(hc_peer, NJT_ERROR);
            njt_stream_health_check_update_wo_lock(hc_peer->hcscf, hc_peer, peer, NJT_ERROR);
            return;
        }
    }

//    if (pscf->ssl_session_reuse) {
//        pc->ssl->save_session = njt_stream_proxy_ssl_save_session;
//
//        if (u->peer.set_session(&u->peer, u->peer.data) != NJT_OK) {
//            njt_stream_health_check_update_status(hc_peer, NJT_ERROR);
//            return;
//        }
//    }

    pc->log->action = "SSL handshaking to upstream";

    rc = njt_ssl_handshake(pc);

    if (rc == NJT_AGAIN) {

        if (!pc->write->timer_set) {
            njt_add_timer(pc->write, pscf->connect_timeout);
        }

        pc->ssl->handler = njt_stream_hc_ssl_handshake;
        return;
    }

    njt_stream_hc_ssl_handshake(pc);
}
static njt_int_t
njt_stream_hc_send_proxy_protocol(njt_stream_health_check_peer_t *hc_peer)
{
    u_char                       *p;
    ssize_t                       n, size;
    njt_connection_t             *pc;
    njt_stream_proxy_srv_conf_t  *pscf;
    u_char                        buf[NJT_PROXY_PROTOCOL_MAX_HEADER];

    pc = hc_peer->peer.connection;

    p = njt_proxy_protocol_write(pc, buf, buf + NJT_PROXY_PROTOCOL_MAX_HEADER);
    if (p == NULL) {
//        njt_stream_health_check_update_status(hc_peer, NJT_ERROR);
        return NJT_ERROR;
    }

    size = p - buf;

    n = pc->send(pc, buf, size);

    if (n == NJT_AGAIN) {
        if (njt_handle_write_event(pc->write, 0) != NJT_OK) {
//            njt_stream_health_check_update_status(hc_peer, NJT_ERROR);
            return NJT_ERROR;
        }

        pscf = hc_peer->hcscf->plcf;

        njt_add_timer(pc->write, pscf->timeout);

        pc->write->handler = njt_stream_hc_connect_handler;

        return NJT_AGAIN;
    }

    if (n == NJT_ERROR) {
//        njt_stream_health_check_update_status(hc_peer, NJT_ERROR);
        return NJT_ERROR;
    }

    if (n != size) {

        /*
         * PROXY protocol specification:
         * The sender must always ensure that the header
         * is sent at once, so that the transport layer
         * maintains atomicity along the path to the receiver.
         */

        njt_log_error(NJT_LOG_ERR, pc->log, 0,"could not send PROXY protocol header at once");

//        njt_stream_health_check_update_status(hc_peer, NJT_ERROR);

        return NJT_ERROR;
    }

    return NJT_OK;
}
#endif

static void
njt_stream_hc_init_upstream(njt_stream_health_check_peer_t *hc_peer,njt_stream_upstream_rr_peer_t *peer) {
    njt_connection_t            *pc;

    pc = hc_peer->peer.connection;

#if (NJT_STREAM_SSL)

    hc_peer->rr_peer = peer;
    if (pc->type == SOCK_STREAM && hc_peer->hcscf->plcf->ssl) {

        if (hc_peer->hcscf->plcf->proxy_protocol) {
            if (njt_stream_hc_send_proxy_protocol(hc_peer) != NJT_OK) {
                njt_stream_health_check_update_wo_lock(hc_peer->hcscf, hc_peer, peer, NJT_ERROR);
                return;
            }

//            u->proxy_protocol = 0;
        }

        if (pc->ssl == NULL) {
            njt_stream_hc_ssl_init_connection(hc_peer,peer);
            return;
        }
    }

#endif

    hc_peer->peer.connection->write->handler = njt_stream_health_check_write_handler;
    hc_peer->peer.connection->read->handler = njt_stream_health_check_read_handler;

    /*NJT_AGAIN or NJT_OK*/
    if (hc_peer->hcscf->timeout) {
        njt_add_timer(hc_peer->peer.connection->write, hc_peer->hcscf->timeout);
        njt_add_timer(hc_peer->peer.connection->read, hc_peer->hcscf->timeout);
    }
}

static void njt_stream_health_loop_peer(njt_stream_health_check_srv_conf_t    *hcscf,njt_stream_upstream_rr_peers_t        *peers,njt_flag_t backup,njt_flag_t op)
{
    njt_int_t                            rc;
    njt_stream_health_check_peer_t        *hc_peer;
    njt_stream_upstream_rr_peer_t *peer;
    njt_stream_upstream_rr_peers_wlock(peers);

    peer = peers->peer;
    if(backup == 1) {
        peer = peers->next->peer;
    }
    for (; peer != NULL; peer = peer->next) {

        if(peer->down == 1) //zyg
        {
            continue;
        }
		if( (peer->hc_down == 2) || (op == 1) ) {  //checking

            if (peer->hc_check_in_process && peer->hc_checks) {
                njt_log_debug0(NJT_LOG_ERR, njt_cycle->log, 0, "peer's health check is in process.");
                continue;
            }

            peer->hc_check_in_process = 1;

            hc_peer = njt_calloc(sizeof(njt_stream_health_check_peer_t), njt_cycle->log);
            if (hc_peer == NULL) {
                /*log the malloc failure*/
                njt_log_debug0(NJT_LOG_ERR, njt_cycle->log, 0,
                               "memory allocate failure for health check.");
                continue;
            }

            hc_peer->peer_id = peer->id;
            hc_peer->hcscf = hcscf;
            hc_peer->peer.sockaddr = peer->sockaddr;


            /*customized the peer's port*/
            if (hcscf->port) {
                njt_inet_set_port(hc_peer->peer.sockaddr, hcscf->port);
            }
            if (hcscf->protocol == 1) {
                hc_peer->peer.type = SOCK_DGRAM;
            } else {
                hc_peer->peer.type = SOCK_STREAM;
            }

            hc_peer->peer.socklen = peer->socklen;
            hc_peer->peer.name = &peer->name;
            hc_peer->peer.get = njt_event_get_peer;
            hc_peer->peer.log = njt_cycle->log;
            hc_peer->peer.log_error = NJT_ERROR_ERR;
            hc_peer->pool = njt_create_pool(njt_pagesize, njt_cycle->log);

            njt_log_debug1(NJT_LOG_ERR, njt_cycle->log, 0,
                           "health check connect to peer of %V.", &peer->name);
            rc = njt_event_connect_peer(&hc_peer->peer);

            if (rc == NJT_ERROR || rc == NJT_DECLINED || rc == NJT_BUSY) {
                njt_log_debug1(NJT_LOG_ERR, njt_cycle->log, 0,
                               "health check connect to peer of %V errror.", &peer->name);
                /*release the memory and update the statistics*/
                njt_stream_health_check_update_wo_lock(hcscf, hc_peer, peer, NJT_ERROR);
                continue;
            }

            hc_peer->peer.connection->data = hc_peer;
            hc_peer->peer.connection->pool = hc_peer->pool;

            njt_stream_hc_init_upstream(hc_peer,peer);

//        hc_peer->peer.connection->write->handler = njt_stream_health_check_write_handler;
//        hc_peer->peer.connection->read->handler = njt_stream_health_check_read_handler;
//
//        /*NJT_AGAIN or NJT_OK*/
//        if (hcscf->timeout) {
//            njt_add_timer(hc_peer->peer.connection->write, hcscf->timeout);
//            njt_add_timer(hc_peer->peer.connection->read, hcscf->timeout);
//        }}
        }
    }

    njt_stream_upstream_rr_peers_unlock(peers);
}
/*define the status machine stage*/
static void njt_stream_health_check_timer_handler(njt_event_t *ev)
{
    njt_stream_health_check_srv_conf_t    *hcscf;
    njt_stream_upstream_srv_conf_t        *uscf;
    njt_stream_upstream_rr_peers_t        *peers;
    njt_uint_t                           jitter;
	njt_flag_t                           op = 0;

    hcscf = ev->data;
    if (hcscf == NULL) {
        njt_log_debug0(NJT_LOG_ERR, njt_cycle->log, 0, "no valid data");
        return;
    }

    uscf = hcscf->plcf->upstream;
    if (uscf == NULL) {
        njt_log_debug0(NJT_LOG_ERR, njt_cycle->log, 0, "no upstream data");
        return;
    }

    if (njt_quit || njt_terminate || njt_exiting) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                      "active probe clearup for quiting");
        return;
    }

    njt_log_debug0(NJT_LOG_ERR, njt_cycle->log, 0,
                   "Health check timer is triggered.");

	if(hcscf->mandatory == 1 && hcscf->persistent == 0 && hcscf->curr_delay != 0) {
		hcscf->curr_frame += 1000;
	}
	
	if(hcscf->curr_delay != 0 && hcscf->curr_delay <= hcscf->curr_frame){
		hcscf->curr_frame = 0;
		op = 1;
	} else if (hcscf->curr_delay == 0){
		op = 1;
	}

    peers = (njt_stream_upstream_rr_peers_t *)uscf->peer.data;
    if(peers)
    {
        njt_stream_health_loop_peer(hcscf,peers,0,op);
    }
    if(peers->next)
    {
        njt_stream_health_loop_peer(hcscf,peers,1,op);
    }
    jitter = 0;
    if (hcscf->jitter) {
        jitter = njt_random() % hcscf->jitter;

        njt_log_debug1(NJT_LOG_ERR, njt_cycle->log, 0,
                       "delay %u for the health check timer.", jitter);
    }
	if(hcscf->mandatory == 1 && hcscf->persistent == 0) {
		hcscf->curr_delay = hcscf->interval + jitter;
		njt_add_timer(&hcscf->hc_timer, 1000);
	} else {
		njt_add_timer(&hcscf->hc_timer, hcscf->interval + jitter);
	}


    return;
}

static njt_int_t
njt_stream_health_check_init_process(njt_cycle_t *cycle)
{
    njt_stream_health_check_main_conf_t *hcmcf;
    njt_stream_health_check_srv_conf_t  *hcscf;
    njt_event_t                       *hc_timer;
    njt_uint_t                        i;
    njt_uint_t                        refresh_in;

    if ((njt_process != NJT_PROCESS_WORKER && njt_process != NJT_PROCESS_SINGLE) || njt_worker != 0) {
        /*only works in the worker 0 prcess.*/
        return NJT_OK;
    }
    hcmcf = njt_stream_cycle_get_module_main_conf(cycle,njt_stream_health_check_module);
    if (hcmcf == NULL) {
        return NJT_OK;
    }

    hcscf = hcmcf->health_checks.elts;

    for (i = 0; i < hcmcf->health_checks.nelts; i++) {
        if(hcscf[i].timeout == NJT_CONF_UNSET_MSEC || hcscf[i].timeout == 0 ){
            hcscf[i].timeout = NJT_STREAM_HC_CONNECT_TIMEOUT;
        }

        hc_timer = &hcscf[i].hc_timer;
        hc_timer->handler = njt_stream_health_check_timer_handler;
        hc_timer->log = cycle->log;
        hc_timer->data = &hcscf[i];
        hc_timer->cancelable = 1;
        refresh_in = njt_random() % 1000 + hcscf[i].test_val;
        /*log*/
        //njt_stream_health_check_timer_handler(hc_timer);
        njt_add_timer(hc_timer, refresh_in);
    }

    return NJT_OK;
}


//static njt_int_t
//njt_stream_health_check_peek_one_byte(njt_connection_t *c)
//{
//    char                            buf[1];
//    njt_int_t                       n;
//    njt_err_t                       err;
//
//    n = recv(c->fd, buf, 1, MSG_PEEK);
//    err = njt_socket_errno;
//
//    njt_log_debug2(NJT_LOG_ERR, c->log, err,
//                   "http check upstream recv(): %i, fd: %d",
//                   n, c->fd);
//
//    if (n == 1 || (n == -1 && err == NJT_EAGAIN)) {
//        return NJT_OK;
//    }
//
//    return NJT_ERROR;
//}

static void njt_stream_health_check_dummy_handler(njt_event_t *ev)
{
    njt_log_debug0(NJT_LOG_DEBUG_EVENT, ev->log, 0,
                   "http health check dummy handler");
}

static njt_int_t
njt_stream_health_check_update_status(njt_stream_health_check_peer_t *hc_peer,
                                    njt_int_t status)
{
    njt_int_t rc;

    if (hc_peer->hcscf->checker->update == NULL) {
        rc = njt_stream_health_check_common_update(hc_peer, status);
    } else {
        rc = hc_peer->hcscf->checker->update(hc_peer, status);
    }

    return rc;

}


static char *
njt_stream_health_check_init_main_conf(njt_conf_t *cf, void *conf)
{

    njt_stream_health_check_main_conf_t *hcmcf;
    njt_stream_health_check_srv_conf_t  *hcscf;
    njt_uint_t                        i;
    njt_stream_proxy_srv_conf_t         *plcf;

    hcmcf = conf;
    if (hcmcf == NULL) {
        return NJT_OK;
    }

    hcscf = hcmcf->health_checks.elts;

    for (i = 0; i < hcmcf->health_checks.nelts; i++) {

        //hcscf = hcscf + i;  //bug zyg

        plcf = hcscf[i].plcf;

        if (plcf->upstream == NULL ) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "upstream must be defined.");
            return NJT_CONF_ERROR;
        } else {
#if (NJT_STREAM_UPSTREAM_ZONE)
            if (plcf->upstream == NULL) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "health check requires an upstream ");
                return NJT_CONF_ERROR;
            }
            if (plcf->upstream->shm_zone == NULL) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "health check requires upstream \"%V\" to be in shared memory.",
                                   &plcf->upstream->host);
                return NJT_CONF_ERROR;
            }
#else
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "upstream zone must be supported.");
            return NJT_CONF_ERROR;
#endif
        }

    }

    return NJT_CONF_OK;
}
