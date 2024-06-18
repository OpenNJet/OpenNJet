/*
 * Copyright (C) 2021-2024 TMLake(Beijing) Technology Co., Ltd.
 */

#ifndef NJT_HELPER_ACCESS_DATA_MODULE_H_
#define NJT_HELPER_ACCESS_DATA_MODULE_H_

#include <stdbool.h>

//#define NJT_ACCESS_DATA_DYNLOG_API_IP_ADDR  "http://127.0.0.1:8081"
//#define NJT_ACCESS_DATA_DYNLOG_API_URI_PATH "/api/v1/config/http_log"

#define NJT_HELPER_ACCESS_DATA_ACCESS_PATH_PREFIX "/usr/local/njet/"

#define NJT_HELPER_ACCESS_DATA_STR_DYN_HTTP_LOG        "/dyn/http_log" 
#define NJT_HELPER_ACCESS_DATA_STR_DYN_HTTP_LOG_LEN    13

#define NJT_HELPER_ACCESS_DATA_ACCESS_LOG    "logs/access.log"
#define NJT_HELPER_ACCESS_DATA_GOACCESS_CONF "conf/goaccess.conf"

#define NJT_HELPER_ACCESS_DATA_GOACCESS_DEBUG_LOG   "logs/goaccess_debug.log"

//#define NJT_HELPER_ACCESS_DATA_CONF_LEN_MAX 256
//#define NJT_HELPER_ACCESS_DATA_LOG_FORMAT_MAX 64

#define NJT_HELPER_ACCESS_DATA_ARRAY_MAX 1024

#define NJT_HELPER_ACCESS_DATA_STR_LEN_MAX 1024

#define NJT_HELPER_ACCESS_DATA_DYN_ACCESS_UNITIT_FLAG   0
#define NJT_HELPER_ACCESS_DATA_DYN_ACCESS_INIT_FLAG     1
#define NJT_HELPER_ACCESS_DATA_DYN_ACCESS_SET_FLAG      2

#define NJT_HELPER_ACCESS_DATA_DYN_ACCESS_CONF_INIT_FLAG    0
#define NJT_HELPER_ACCESS_DATA_DYN_ACCESS_CONF_CHANGE_FLAG  1

typedef struct {
    njt_str_t name;

    njt_str_t format;
    njt_str_t escape;
}njt_helper_access_data_dyn_access_log_format_t;

typedef struct njt_helper_access_data_dyn_access_api_loc_s {
    njt_str_t full_name;
    bool log_on;

    njt_array_t logs;
    njt_array_t locs;
} njt_helper_access_data_dyn_access_api_loc_t;

typedef struct njt_helper_access_data_dyn_access_log_conf_s {
    njt_str_t format;
    njt_str_t path;
} njt_helper_access_data_dyn_access_log_conf_t;

typedef struct {
    njt_str_t   path;
    njt_str_t   format;
    
    u_char  convert_path[NJT_HELPER_ACCESS_DATA_STR_LEN_MAX];
    char    convert_format[NJT_HELPER_ACCESS_DATA_STR_LEN_MAX];
} njt_helper_access_data_log_format_t;


//static void njt_helper_access_data_iot_register_outside_reader(njt_event_handler_pt h, struct evt_ctx_t *ctx);

//static void njt_helper_access_data_iot_conn_timeout(njt_event_t *ev);
//static void njt_helper_access_data_iot_register_outside_reader(njt_event_handler_pt h, struct evt_ctx_t *ctx);
//static njt_int_t njt_helper_access_data_dynlog_update_locs_log(dynlog_servers_item_locations_t *locs);

//static njt_int_t njt_helper_access_data_dynlog_update_access_log(njt_pool_t *pool, dynlog_t *api_data);

//static void njt_helper_access_data_loop_mqtt(njt_event_t *ev);
//static void njt_helper_access_data_iot_conn_timeout(njt_event_t *ev);

//static char *access_data_rr_callback(const char *topic, int is_reply, const char *msg, int msg_len, int session_id, int *out_len);

#endif //NJT_HELPER_ACCESS_DATA_MODULE_H_
