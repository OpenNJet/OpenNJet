#ifndef NJT_HTTP_LOCATION_MODULE_H_
#define NJT_HTTP_LOCATION_MODULE_H_
#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>

typedef struct njt_http_location_info_s {
    njt_str_t file;
	njt_str_t type;
    njt_str_t addr_port;
    njt_str_t server_name;
	njt_str_t location_rule;
    njt_str_t location;
    njt_str_t proxy_pass;
    njt_str_t location_body;
	njt_pool_t *pool;
	//njt_str_t  sport;
    njt_http_core_srv_conf_t *cscf;
	//njt_int_t code;
    njt_str_t     msg;
} njt_http_location_info_t;

typedef struct njt_http_location_loc_conf_s {
    njt_flag_t dyn_location_enable;
} njt_http_location_loc_conf_t;

njt_http_location_info_t * njt_http_parser_location_data(njt_str_t json_str);
njt_int_t njt_http_check_upstream_exist(njt_cycle_t *cycle,njt_pool_t *pool, njt_str_t *name);
#endif
