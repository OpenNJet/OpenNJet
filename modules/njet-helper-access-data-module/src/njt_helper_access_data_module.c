/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */
#include <njt_http.h>
#include <stdio.h>

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>

#include <unistd.h>
#include "njet_iot_emb.h"

#include <njt_mqconf_module.h>
#include <njt_http_client_util.h>   //包含util 头文件

#include "njt_helper_access_data_module.h"
#include "njt_rpc_result_util.h"

#include "njt_dynlog_parser.h"
#include "njt_http_kv_module.h"
#include "njt_hash_util.h"

#include "goaccess.h"

volatile njt_cycle_t  *njt_cycle;

njt_helper_access_data_log_format_t g_njt_helper_access_data_log_format[NJT_HELPER_ACCESS_DATA_ARRAY_MAX];
njt_helper_access_data_log_format_t g_njt_helper_access_data_log_format_new[NJT_HELPER_ACCESS_DATA_ARRAY_MAX];

static struct evt_ctx_t *access_data_mqtt_ctx;

njt_access_data_conf_file_logformat_t g_njt_access_data_conf_file_logformat[NJT_HELPER_ACCESS_DATA_ARRAY_MAX];

njt_helper_access_data_dyn_access_log_format_t g_njt_helper_access_data_dyn_access_log_format[NJT_HELPER_ACCESS_DATA_ARRAY_MAX];

njt_helper_access_data_log_format_t g_njt_helper_access_data_dyn_access_new_conf[NJT_HELPER_ACCESS_DATA_ARRAY_MAX];

njt_helper_access_data_dyn_access_api_loc_t *g_helper_access_data_dyn_access_api_loc;

volatile njt_int_t g_njt_helper_access_data_dyn_access_init_flag    = NJT_HELPER_ACCESS_DATA_DYN_ACCESS_UNITIT_FLAG; /*默认未初始化*/
volatile njt_int_t g_njt_helper_access_data_dynlog_conf_change_flag = NJT_HELPER_ACCESS_DATA_DYN_ACCESS_CONF_INIT_FLAG; /*默认未改变*/

static char g_njt_helper_access_data_prefix_path[NJT_HELPER_ACCESS_DATA_STR_LEN_MAX] = "";

static njt_access_data_logformat_convert_t g_njt_access_data_logformat_convert[] = {
    {"$remote_addr",    "%h"},
    {"$time_local",     "%d:%t %^"},
    {"$request",        "%r"},
    {"$status",         "%s"},
    {"$body_bytes_sent",    "%b"},
    {"$http_referer",       "%R"},
    {"$http_user_agent",    "%u"}
};

static dynlog_t *njt_helper_access_data_json_parse(njt_pool_t *pool, njt_str_t *value, js2c_parse_error_t *err_info)
{
    dynlog_t *api_data = NULL;
    api_data = json_parse_dynlog(pool, value, err_info);

    if (api_data == NULL) {
        return api_data;
    }

    return api_data;
}

static void convert_log_format(char *src, char *dst)
{
    //char dst[NJT_ACCESS_DATA_FILE_LOGFORMAT_ARRAY_MAX] = "";  /* 增加足够的空间来存储转换后的字符串 */
    char var[32];
    njt_int_t i, j, found = 0;
    
    size_t k;

    /* 遍历源字符串 */
    njt_int_t dst_index = 0;
    njt_int_t src_len   = strlen(src);
    
    for (i = 0; i < src_len; i++) {
        // 检查当前字符是否为变量起始符号 '$'
        if (src[i] == '$') {
            
            // 寻找变量名的结束位置
            j = i + 1;
            while (j < src_len && src[j] != ' ' && src[j] != '\"' && src[j] != ']') {
                j++;
            }
            
            // 提取变量名
            strncpy(var, src + i, j - i);
            var[j - i] = '\0';

            // 在配置数组中查找匹配的变量，并替换为对应的日志格式
            found = 0;
            for (k = 0; k < sizeof(g_njt_access_data_logformat_convert) / sizeof(g_njt_access_data_logformat_convert[0]); k++) {
                if (strcmp(var, g_njt_access_data_logformat_convert[k].var) == 0) {
                    strcat(dst, g_njt_access_data_logformat_convert[k].logformat);
                    dst_index += strlen(g_njt_access_data_logformat_convert[k].logformat);

                    found = 1;
                    break;
                }
            }

            // 如果未找到匹配的变量，则直接转为"%^"
            if (!found) {
                strcat(dst, "%^");
                dst_index += 2; // "%^" 的长度为2
            }

            // 更新索引位置
            i = j - 1;
        } else {
            // 普通字符直接复制到目标字符串
            dst[dst_index++] = src[i];
        }
    }   
    
    return;                                                                                                                                                                                                   
}

// Not using deep copy
static njt_helper_access_data_dyn_access_log_format_t *
njt_log_format_with_accessLogFormat_t(njt_pool_t *pool, dynlog_accessLogFormat_t *fmt)
{
    njt_helper_access_data_dyn_access_log_format_t *alf;

    alf = njt_pcalloc(pool,sizeof(njt_helper_access_data_dyn_access_log_format_t));
    if(!alf) return NULL;

    dynlog_accessLogFormat_format_t *format = get_dynlog_accessLogFormat_format(fmt);
    if(format != NULL){
        alf->format = *format;
    }
    
    dynlog_accessLogFormat_name_t *name = get_dynlog_accessLogFormat_name(fmt);

    if(fmt->is_escape_set){
        dynlog_accessLogFormat_escape_t escape = get_dynlog_accessLogFormat_escape(fmt);
        switch (escape) {
            case DYNLOG_ACCESSLOGFORMAT_ESCAPE_DEFAULT:
                njt_str_set(&alf->escape,"default");
                break;
            case DYNLOG_ACCESSLOGFORMAT_ESCAPE_JSON:
                njt_str_set(&alf->escape,"json");
                break;
            case DYNLOG_ACCESSLOGFORMAT_ESCAPE_NONE:
                njt_str_set(&alf->escape,"none");
                break;
        }
    }

    alf->name = *name;

    return alf;
}
                                                                                                          
static njt_int_t get_access_data_log_format_array_size(njt_helper_access_data_log_format_t *conf) 
{
    njt_int_t length = 0;

    if (!conf) {
        return length;
    }

    while (strlen(conf[length].convert_format) > 0) {
        length++;
    }

    return length;
}

size_t get_array_size(u_char *arr) 
{
    size_t length = 0;

    while (arr[length] != '\0') {
        length++;
    }

    return length;
}
                    
size_t get_dyn_access_log_format_size (njt_helper_access_data_dyn_access_log_format_t *conf) 
{
    size_t len = 0;

    if (!conf) {
        return len;
    }

    while (conf[len].name.len > 0) {
        len++;
    }

    return len;
}

size_t get_conf_array_size(njt_helper_access_data_log_format_t *conf) 
{
    size_t length = 0;

    if (!conf) {
        return length;
    }

    while (conf[length].path.len > 0) {
        length++;
    }

    return length;
}

static njt_int_t dyn_access_log_conf_change_1 (njt_helper_access_data_dyn_access_log_conf_t *new_conf, njt_int_t old_conf_size)
{
    njt_int_t i;

    if (!new_conf) {
        return 0;
    }

    for (i = 0; i < old_conf_size; i++) {
        // 检查当前字符是否存在于 old_conf中

            if (strcmp((char *)new_conf->path.data, (char *)g_njt_helper_access_data_log_format[i].path.data) != 0 ||
                strcmp((char *)new_conf->format.data, (char *)g_njt_helper_access_data_log_format[i].format.data) != 0) {
                return 1;
            } 
    }
    
    return 0;
}

static njt_helper_access_data_dyn_access_api_loc_t *njt_helper_access_data_api_loc_with_loc_item (njt_pool_t *pool, dynlog_locationDef_t *loc_item,
    njt_int_t *conf_init_flag, njt_int_t *conf_change_flag)
{
    njt_helper_access_data_dyn_access_api_loc_t     *aal  = NULL;
    njt_helper_access_data_dyn_access_log_conf_t    *lc   = NULL;
 
    dynlog_accessLog_t              *log;

    njt_int_t   rc, old_conf_size, new_conf_size;
    njt_uint_t  i, j;

    njt_int_t change_flag;

    char format[NJT_HELPER_ACCESS_DATA_STR_LEN_MAX] = "";
    char *prefix_path = g_njt_helper_access_data_prefix_path;

    u_char format_data[NJT_HELPER_ACCESS_DATA_STR_LEN_MAX] = "";

    size_t size;

    if(!loc_item) return NULL;

    aal = njt_pcalloc(pool,sizeof(njt_helper_access_data_dyn_access_api_loc_t));
    if(!aal) return NULL;

    if (loc_item->is_location_set) {
        aal->full_name = *get_dynlog_locationDef_location(loc_item);
    }

    if(loc_item->is_accessLogOn_set){
        aal->log_on = get_dynlog_locationDef_accessLogOn(loc_item);
    }

    if ((loc_item->is_accessLogs_set) && (loc_item->accessLogs != NULL) && (loc_item->accessLogs->nelts > 0)) {
        
        rc = njt_array_init(&aal->logs, pool, sizeof(njt_helper_access_data_dyn_access_api_loc_t), loc_item->accessLogs->nelts);
        if(rc != NJT_OK) return NULL;

        lc = njt_array_push_n(&aal->logs, loc_item->accessLogs->nelts);

        old_conf_size   = get_access_data_log_format_array_size(g_njt_helper_access_data_log_format);
        new_conf_size   = get_access_data_log_format_array_size(g_njt_helper_access_data_log_format_new);

        for (i = 0; i < loc_item->accessLogs->nelts; i++) {
            log = get_dynlog_locationDef_accessLogs_item(loc_item->accessLogs, i);

            lc[i].format    = log->formatName;
            lc[i].path      = log->path;
            
            if (g_njt_helper_access_data_dyn_access_init_flag == NJT_HELPER_ACCESS_DATA_DYN_ACCESS_UNITIT_FLAG) {

                njt_memcpy(&g_njt_helper_access_data_log_format[old_conf_size].format,  &log->formatName, sizeof(log->formatName));
                njt_memcpy(&g_njt_helper_access_data_log_format[old_conf_size].path,    &log->path, sizeof(log->path));

                g_njt_helper_access_data_log_format[old_conf_size].convert_path[0] = '\0';

                njt_snprintf(g_njt_helper_access_data_log_format[old_conf_size].convert_path, sizeof(g_njt_helper_access_data_log_format[old_conf_size].convert_path), "%s%s", 
                    prefix_path, (char *)log->path.data);
                
                format[0]       = '\0';
                format_data[0]  = '\0';

                for (j = 0; j < NJT_HELPER_ACCESS_DATA_ARRAY_MAX; j++) {
                    
                    if (g_njt_helper_access_data_dyn_access_log_format[j].name.data == NULL) continue;
                    
                    if (strcmp((char *)lc[i].format.data, (char *)g_njt_helper_access_data_dyn_access_log_format[j].name.data) == 0) {
                        njt_memcpy(format_data, g_njt_helper_access_data_dyn_access_log_format[j].format.data,  NJT_HELPER_ACCESS_DATA_STR_LEN_MAX * sizeof(u_char));
                       
                        break;
                    }
                }

                convert_log_format((char *)format_data, format);
                
                g_njt_helper_access_data_log_format[old_conf_size].convert_format[0] = '\0';
                njt_memcpy(&g_njt_helper_access_data_log_format[old_conf_size].convert_format, format, sizeof(format));
                
                old_conf_size ++;

                *conf_init_flag = NJT_HELPER_ACCESS_DATA_DYN_ACCESS_INIT_FLAG; /* 表示已初始化, dynlog*/
            } else {
                //存入的时候，先检查是不是新的，不用再比较；节省流程
                change_flag = dyn_access_log_conf_change_1 (&lc[i], old_conf_size);
                if (change_flag == 1) { //有新的access.log logformat

                    njt_memcpy(&g_njt_helper_access_data_log_format_new[new_conf_size].path,    &log->path,         sizeof(log->path));
                    njt_memcpy(&g_njt_helper_access_data_log_format_new[new_conf_size].format,  &log->formatName,   sizeof(log->formatName));

                    g_njt_helper_access_data_log_format_new[new_conf_size].convert_path[0] = '\0';
                    njt_snprintf(g_njt_helper_access_data_log_format_new[new_conf_size].convert_path, sizeof(g_njt_helper_access_data_log_format_new[i].convert_path), "%s%s", 
                        prefix_path, (char *)log->path.data);

                    format[0]   = '\0';
                    format_data[0]  = '\0';

                    size = get_dyn_access_log_format_size(g_njt_helper_access_data_dyn_access_log_format);   

                    for (j = 0; j < size; j++) {
                        
                        if (g_njt_helper_access_data_dyn_access_log_format[j].name.data == NULL) {
                            
                            continue;
                        }
                        
                        if (strcmp((char *)lc[i].format.data, (char *)g_njt_helper_access_data_dyn_access_log_format[j].name.data) == 0) {
                            njt_memcpy(format_data, g_njt_helper_access_data_dyn_access_log_format[j].format.data,  NJT_ACCESS_DATA_FILE_LOGFORMAT_ARRAY_MAX * sizeof(u_char));
                            break;
                        }
                    }

                    convert_log_format((char *)format_data, format);
                    
                    g_njt_helper_access_data_log_format_new[new_conf_size].convert_format[0] = '\0';
                    njt_memcpy(&g_njt_helper_access_data_log_format_new[new_conf_size].convert_format, format, sizeof(format));

                    new_conf_size ++;

                    *conf_change_flag = NJT_HELPER_ACCESS_DATA_DYN_ACCESS_CONF_CHANGE_FLAG; /*access log 配置改变*/
                }

            }
        }
    } else {
        njt_array_init(&aal->logs, pool, sizeof(njt_helper_access_data_dyn_access_api_loc_t), 0);
    }

    return aal;
}

static njt_int_t njt_helper_access_data_dynlog_update_locs_log(dynlog_servers_item_locations_t *locs, njt_int_t *conf_init_flag, njt_int_t *conf_change_flag)
{
    njt_uint_t  i;

    dynlog_locationDef_t    *daal;
    njt_helper_access_data_dyn_access_api_loc_t       *aal;

    for (i = 0; i < locs->nelts ; i++) {
        daal = get_dynlog_servers_item_locations_item(locs, i);
        if (daal == NULL || !daal->is_location_set) {
            continue;
        }

        aal = njt_helper_access_data_api_loc_with_loc_item(locs->pool, daal, conf_init_flag, conf_change_flag);
        if (!aal) {
            continue;
        } 

        g_helper_access_data_dyn_access_api_loc = aal;
        g_helper_access_data_dyn_access_api_loc++;
   }

    return NJT_OK;
}

static njt_int_t
njt_helper_access_data_dynlog_update_access_log(njt_pool_t *pool, dynlog_t *api_data)
{
    dynlog_accessLogFormat_t    *fmt;
    
    njt_helper_access_data_dyn_access_log_format_t *alf = NULL;
    dynlog_servers_item_t       *server_item;

    njt_int_t                   rc = NJT_ERROR, init_flag = 0, change_flag = 0;
    njt_uint_t i;

    dynlog_accessLogFormats_t       *formats;

    njt_memzero(g_njt_helper_access_data_log_format_new, NJT_HELPER_ACCESS_DATA_ARRAY_MAX * sizeof(njt_helper_access_data_log_format_t));

    //1.检查是否设置了访问日志格式。如果设置了，就执行接下来的代码。
    if (api_data->is_accessLogFormats_set) {

        //2.获取动态日志格式。
        formats = get_dynlog_accessLogFormats(api_data);
        
        //3.遍历获取的动态日志格式列表。
        if (formats) {
            for (i = 0; i < formats->nelts; ++i) {

                //4.获取当前索引 `i` 处的动态日志格式项。
                fmt = get_dynlog_accessLogFormats_item(formats, i);
                if(fmt == NULL){
                    continue;
                }

                alf = njt_log_format_with_accessLogFormat_t(pool, fmt);
                if (alf) {
                    
                    alf->name.len = strlen((char *)alf->name.data);
                    
                    /*拷贝到log format全局数组*/
                    njt_memcpy(&g_njt_helper_access_data_dyn_access_log_format[i], alf, sizeof(njt_helper_access_data_dyn_access_log_format_t));                 
                }

            }
        }
    }
 
    // 1. 开始了一个条件语句，检查 `api_data->is_servers_set` 和 `api_data->servers` 是否为真。如果条件成立，则进入条件语句块。
    if (api_data->is_servers_set && api_data->servers != NULL) {

        //2. 在条件成立的情况下，调用 `get_dynlog_servers(api_data)` 函数来获取动态日志服务器的列表，并将其赋值给 `servers` 变量。
        dynlog_servers_t *servers = get_dynlog_servers(api_data);

        //3. 如果 `servers` 不为空，则进入 `for` 循环，遍历 `servers` 中的每个元素。
        if (servers) {

            //4. 在循环中，首先获取当前服务器的信息，并检查其参数是否设置正确。如果参数设置不正确，会记录错误并跳过当前服务器的处理。
            for (i = 0; i < servers->nelts; ++i) {
                
                //5. 如果服务器参数设置正确，则获取其监听地址和服务器名称。
                server_item = get_dynlog_servers_item(servers, i);
                if (server_item == NULL) {
                    continue;
                }

                //6. 使用获取的监听地址和服务器名称，尝试在 nginx 中查找相应的服务器配置。
                if(!server_item->is_listens_set || !server_item->is_serverNames_set || server_item->listens == NULL
                     || server_item->serverNames == NULL || server_item->listens->nelts < 1 || server_item->serverNames->nelts < 1 ) {
  
                    // listens 与server_names都为空
                    njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "====1====server parameters error, listens or serverNames is empty,at position %ui", i);

                    //7. 如果找到了对应的服务器配置，则继续执行后续操作，包括更新服务器的位置信息，并根据操作结果记录成功或失败的计数。
                    //njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                    //8. 如果未找到对应的服务器配置，则记录错误并继续处理下一个服务器。
                    continue;
                }
                
                if (server_item->is_locations_set && server_item->locations != NULL && server_item->locations->nelts > 0) {
                    rc = njt_helper_access_data_dynlog_update_locs_log(server_item->locations, &init_flag, &change_flag);
                    njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "====1====rc:%d", rc);
                } else {
                    rc = NJT_OK;
                }

            }
        }

        if (init_flag) {
            g_njt_helper_access_data_dyn_access_init_flag = init_flag;
        }

        if (change_flag) { 
            g_njt_helper_access_data_dynlog_conf_change_flag = change_flag;
        }

    }

    return 0; 
}

static void njt_helper_access_data_iot_set_timer(njt_event_handler_pt h, int interval, struct evt_ctx_t *ctx)
{
    njt_event_t *ev;
    njt_connection_t *c = njt_palloc(njt_cycle->pool, sizeof(njt_connection_t));

    njt_memzero(c, sizeof(njt_connection_t));

    ev = njt_palloc(njt_cycle->pool, sizeof(njt_event_t));
    njt_memzero(ev, sizeof(njt_event_t));

    ev->log = njt_cycle->log;
    ev->handler = h;

    ev->cancelable = 1;
    ev->data = c;

    c->fd = (njt_socket_t)-1;
    c->data = ctx;

    njt_add_timer(ev, interval);
}

static void njt_helper_access_data_iot_conn_timeout(njt_event_t *ev)
{
    njt_connection_t *c = (njt_connection_t *)ev->data;
    struct evt_ctx_t *ctx = (struct evt_ctx_t *)c->data;
    int ret;
    if (ev->timedout)
    {
        ret = njet_iot_client_connect(3, 5, ctx);
        if (ret != 0)
        {
            if (ret == -5)
            {
                //client is connecting or has connected
                return;
            }
            njt_add_timer(ev, 1000);
        } else {
            //connect ok, register io
            njt_helper_access_data_iot_register_outside_reader(njt_helper_access_data_loop_mqtt, ctx);
        }
    }
}

static void njt_helper_access_data_loop_mqtt(njt_event_t *ev)
{
    int ret;
    struct evt_ctx_t *ctx;
    
    njt_connection_t *c = (njt_connection_t *)ev->data;
    ctx = (struct evt_ctx_t *)c->data;
    
    if (ev->timer_set) {
        njt_del_timer(ev);
    }

    ret = njet_iot_client_run(ctx);    
 
    switch (ret)
    {
    case 0:
        njt_add_timer(ev, 100000);
        return;
    case 4:  // no connection
    case 19: // lost keepalive
    case 7:  // lost connection
        njt_helper_access_data_iot_set_timer(njt_helper_access_data_iot_conn_timeout, 10, ctx);
        njt_del_event(ev, NJT_READ_EVENT, NJT_CLOSE_EVENT);
        break;
    default:
        njt_helper_access_data_iot_set_timer(njt_helper_access_data_iot_conn_timeout, 10, ctx);
        njt_del_event(ev, NJT_READ_EVENT, NJT_CLOSE_EVENT);
    }

    return;
}


static void njt_helper_access_data_iot_register_outside_reader(njt_event_handler_pt h, struct evt_ctx_t *ctx)
{
    int fd;
    njt_event_t *rev, *wev;
    fd = njet_iot_client_socket(ctx);
    njt_connection_t *c = njt_palloc(njt_cycle->pool, sizeof(njt_connection_t));
    njt_memzero(c, sizeof(njt_connection_t));

    rev = njt_palloc(njt_cycle->pool, sizeof(njt_event_t));
    njt_memzero(rev, sizeof(njt_event_t));
    wev = njt_palloc(njt_cycle->pool, sizeof(njt_event_t));
    njt_memzero(wev, sizeof(njt_event_t));

    rev->log = njt_cycle->log;
    rev->handler = h;
    rev->cancelable = 1;
    rev->data = c;

    wev->data = c;
    wev->log = njt_cycle->log;
    wev->ready = 1;

    c->fd = (njt_socket_t)fd;
    // c->data=cycle;
    c->data = ctx;

    c->read = rev;
    c->write = wev;

    if (njt_add_event(rev, NJT_READ_EVENT, 0) != NJT_OK)
    {
        return;
    }
    njt_add_timer(rev, 1000); // tips: trigger every 1s at least, to process misc things like ping/pong
    
}

static char *access_data_rr_callback(const char *topic, int is_reply, const char *msg, int msg_len, int session_id, int *out_len)
{
     //to avoid unused-but-set-variable warning
    return NULL;
}

static int njt_helper_access_data_msg_callback(const char *topic, const char *msg, int msg_len, void *out_data)
{
    njt_pool_t  *pool;
    dynlog_t    *api_data;

    js2c_parse_error_t err_info;

    njt_str_t msg_str;
    
    msg_str.data    = (u_char *)msg;
    msg_str.len     = msg_len;

    if (!topic || (strncmp(topic, NJT_HELPER_ACCESS_DATA_STR_DYN_HTTP_LOG, NJT_HELPER_ACCESS_DATA_STR_DYN_HTTP_LOG_LEN) != 0)) {
        return -1;   
    }

    pool = njt_create_pool(njt_pagesize, njt_cycle->log);
    if (pool == NULL) {
        return -1;
    }

    njt_memzero(&err_info, sizeof(js2c_parse_error_t));
    api_data = njt_helper_access_data_json_parse(pool, &msg_str, &err_info);

    njt_helper_access_data_dynlog_update_access_log(pool, api_data);

    return 1;
}

static njt_int_t njt_access_data_dynlog_init_process (njt_cycle_t *cycle)
{
    char *prefix;
    int ret;

    const char localcfg[1024] = "/usr/local/njet/goaccess/mqtt.conf";
    const char client_id[128] = "/usr/local/njet/goaccess/_msg_access_data-1";
    char log[1024] = "/usr/local/njet/goaccess/sendmsg_access_data-1";

    njt_cycle = cycle;

    prefix = njt_calloc(cycle->prefix.len + 1, cycle->log);
    njt_memcpy(prefix, cycle->prefix.data, cycle->prefix.len);
    
    prefix[cycle->prefix.len] = '\0';

    access_data_mqtt_ctx = njet_iot_client_init(prefix, localcfg, access_data_rr_callback, njt_helper_access_data_msg_callback, client_id, log, cycle);
    njt_free(prefix);
    
    if (access_data_mqtt_ctx == NULL) {
        njet_iot_client_exit(access_data_mqtt_ctx);
        return NJT_ERROR;
    };

    ret = njet_iot_client_connect(3, 5, access_data_mqtt_ctx);
    if (ret != 0) {
        njt_helper_access_data_iot_set_timer(njt_helper_access_data_iot_conn_timeout, 2000, access_data_mqtt_ctx);
    } else {
        njt_helper_access_data_iot_register_outside_reader(njt_helper_access_data_loop_mqtt, access_data_mqtt_ctx);
    };

    return NJT_OK;
}

size_t get_logformat_array_size(njt_access_data_conf_file_logformat_t *conf) 
{
    size_t len = 0;

    if (!conf) {
        return len;
    }

    while (strlen(conf[len].file_name) > 0) {
        len++;
    }

    return len;
}

static njt_int_t njt_helper_access_data_dyn_access_init_handle (Logs *logs)
{
    int ret;
    njt_int_t i, size;
    
    size_t format_array_size;

    if (!logs) {
        return -1;
    }

    size = get_access_data_log_format_array_size (g_njt_helper_access_data_log_format);
    format_array_size = get_logformat_array_size (g_njt_access_data_conf_file_logformat);

    for (i = 0; i < size; i++) {

        if (logs->size + 1 <= NJT_HELPER_ACCESS_DATA_ARRAY_MAX) {


            if (format_array_size + 1 <= NJT_HELPER_ACCESS_DATA_ARRAY_MAX) {
                
                set_logformat_and_file_name((char *)g_njt_helper_access_data_log_format[format_array_size].convert_path, strlen((char *)g_njt_helper_access_data_log_format[format_array_size].convert_path), 
                (char *)g_njt_helper_access_data_log_format[format_array_size].convert_format, strlen((char *)g_njt_helper_access_data_log_format[format_array_size].convert_format));
                format_array_size++;
            } else {
                return -1;
            }

            //越界问题
            ret = set_glog (logs, (char *)g_njt_helper_access_data_log_format[i].convert_path);
            if (ret) {
                return -1;
            }

        } else {
            return -1;
        }
    }

    return 0;
}

static njt_int_t njt_helper_access_data_dynlog_change_handle (Logs *logs)
{
    int ret;
    njt_int_t i, old_conf_size, size;

    size_t format_array_size;

    if (!logs) {
        return -1;
    }

    old_conf_size   = get_access_data_log_format_array_size (g_njt_helper_access_data_log_format);
    size            = get_access_data_log_format_array_size (g_njt_helper_access_data_log_format_new);

    format_array_size = get_logformat_array_size (g_njt_access_data_conf_file_logformat);

    for (i = 0; i < size; i++) {
        if (logs->size + 1 <= NJT_HELPER_ACCESS_DATA_ARRAY_MAX) {

            if (format_array_size + 1 <= NJT_HELPER_ACCESS_DATA_ARRAY_MAX) {
                
                set_logformat_and_file_name((char *)g_njt_helper_access_data_log_format[format_array_size].convert_path, strlen((char *)g_njt_helper_access_data_log_format[format_array_size].convert_path), 
                (char *)g_njt_helper_access_data_log_format[format_array_size].convert_format, strlen((char *)g_njt_helper_access_data_log_format[format_array_size].convert_format));

                format_array_size++;

            } else {
                return -1;
            }

            //越界问题
            ret = set_glog (logs, (char *)g_njt_helper_access_data_log_format_new[i].convert_path);
            if (ret) {
                return -1;
            }

        } else {
            return -1;
        }

        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "====5====old_conf_size:%u", old_conf_size);
        
        if (old_conf_size + 1 <= NJT_HELPER_ACCESS_DATA_ARRAY_MAX) {
            //越界问题
            njt_memcpy(&g_njt_helper_access_data_log_format_new[old_conf_size], &g_njt_helper_access_data_log_format_new[i], sizeof(njt_helper_access_data_log_format_t));
            old_conf_size++;
        } else {
            return -1;
        }

    }
  
    return 0;
}

void njt_helper_run (helper_param param)
{
    int argc = 5;
    char **argv;

    unsigned int cmd;
    Logs *logs      = NULL;

    int             i, ret;
    njt_cycle_t     *cycle;
    
    njt_int_t handle_ret;

    char *prefix_path;
    char debug_path[NJT_HELPER_ACCESS_DATA_STR_LEN_MAX] = "";

    pthread_t goaccess_thread;
    
    char *src_format = "$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\"";
    
    char dst_format[NJT_ACCESS_DATA_FILE_LOGFORMAT_ARRAY_MAX] = "";
    njt_access_data_conf_file_logformat_t file_logformat;

    cycle = param.cycle;

    njt_cycle = cycle;
    argv = njt_alloc(argc * sizeof(char *), cycle->log);
    
    // 为每个argv元素分配内存并复制参数字符串
    for (i = 0; i < argc; i++) {
        argv[i] = (char *)malloc((NJT_HELPER_ACCESS_DATA_STR_LEN_MAX) * sizeof(char));
        if (argv[i] == NULL) {
            njt_log_error(NJT_LOG_ERR, cycle->log, 0, "argv[i] == NULL\n");
        }
    }

    njt_access_data_dynlog_init_process(cycle);

    prefix_path = njt_calloc(cycle->prefix.len + 1, cycle->log);

    strcpy(prefix_path, (char *)cycle->prefix.data);
    strcpy(g_njt_helper_access_data_prefix_path, (char *)cycle->prefix.data);

    strcpy(argv[0], "./goaccess");

    strcpy(argv[1], "-f");
    snprintf(argv[2], NJT_HELPER_ACCESS_DATA_STR_LEN_MAX * sizeof(char), "%s%s", prefix_path, NJT_HELPER_ACCESS_DATA_ACCESS_LOG);

    strcpy(argv[3], "-p");
    
    snprintf(argv[4], NJT_HELPER_ACCESS_DATA_STR_LEN_MAX * sizeof(char), "%s%s", prefix_path, NJT_HELPER_ACCESS_DATA_GOACCESS_CONF);
    strcpy(file_logformat.file_name, argv[2]);
    
    convert_log_format(src_format, dst_format);
    strcpy(file_logformat.logformat, dst_format);

    njt_memzero (g_njt_access_data_conf_file_logformat, NJT_HELPER_ACCESS_DATA_STR_LEN_MAX * sizeof(njt_access_data_conf_file_logformat_t));

    memcpy(&g_njt_access_data_conf_file_logformat[0], &file_logformat, sizeof(njt_access_data_conf_file_logformat_t));

    snprintf(debug_path, NJT_HELPER_ACCESS_DATA_STR_LEN_MAX * sizeof(char), "%s%s", prefix_path, NJT_HELPER_ACCESS_DATA_GOACCESS_DEBUG_LOG);
    dbg_log_open (debug_path);

    logs = njet_helper_access_data_init(argc, argv);
    if (logs == NULL) {
        exit(2);
    }

    ret = pthread_create(&goaccess_thread, NULL, njet_helper_access_data_run, (void *)logs);
    if (ret) {
         exit(2);
    }

    pthread_setname_np(goaccess_thread, "goaccess");

    for (;;) {
        
        /* 在njt_helper_run的事件循环中，需调用param.check_cmd_fp()接收命令; 
            命令宏定义如下：
                #define NJT_HELPER_CMD_NO          0
                #define NJT_HELPER_CMD_STOP       1
                #define NJT_HELPER_CMD_RESTART  2
        */
        cmd = param.check_cmd_fp(cycle);

        /*接收到命令后，需进行命令处理。
        NJT_HELPER_CMD_STOP命令，要进行停止操作；
        */
        if (cmd == NJT_HELPER_CMD_STOP) {
            njt_log_error(NJT_LOG_INFO, cycle->log, 0,
                          "helper access_data stop.\n");

            goto exit;
        }

        /*
          NJT_HELPER_CMD_RESTART 为预留命令，暂不会发送该命令，在事件处理中可以按停止操作处理该命令，
          或者执行自身业务逻辑的重新开始。
        */
        if (cmd == NJT_HELPER_CMD_RESTART) {
            njt_log_error(NJT_LOG_INFO, cycle->log, 0,
                          "helper access_data restart\n");
            //1.持久化，不清理logs内存，只做持久化到db文件，
            persist_data();
        }

        if (g_njt_helper_access_data_dyn_access_init_flag == NJT_HELPER_ACCESS_DATA_DYN_ACCESS_INIT_FLAG) {
            handle_ret = njt_helper_access_data_dyn_access_init_handle(logs);
            if (handle_ret) {
                njt_log_error(NJT_LOG_INFO, cycle->log, 0, "njt_helper_access_data_dyn_access_init_handle error.");
            }
            g_njt_helper_access_data_dyn_access_init_flag = NJT_HELPER_ACCESS_DATA_DYN_ACCESS_SET_FLAG;
        }

        if (g_njt_helper_access_data_dynlog_conf_change_flag == NJT_HELPER_ACCESS_DATA_DYN_ACCESS_CONF_CHANGE_FLAG) {
            handle_ret = njt_helper_access_data_dynlog_change_handle(logs);
            if (handle_ret) {
                njt_log_error(NJT_LOG_INFO, cycle->log, 0, "njt_helper_access_data_dynlog_change_handle error.");
            }
            g_njt_helper_access_data_dynlog_conf_change_flag = NJT_HELPER_ACCESS_DATA_DYN_ACCESS_CONF_INIT_FLAG;
        }
    }
   
exit:
    cleanup(0);

    pthread_join(goaccess_thread, NULL);
   
    return;
}

/*
注：当前版本号是 1
#define NJT_HELPER_VER          1
*/
unsigned int njt_helper_check_version (void)
{
    return NJT_HELPER_VER;
}

/*
返回1，表示该so的copilot进程，不会在reload的时候重启。
放回0，表示该so的copilot进程，会在reload的时候重启。
注1：so可以不实现该接口。若不实现，则等同于返回0。
注2：如果so实现该接口并且返回1，那么在reload的时候该so的copilot进程不会重启，
但是有一点需要注意：reload的时候配置文件中需保留原helper指令，这是配置上的强制要求，
不满足此要求会导致reload失败。
*/
/*
unsigned int njt_helper_ignore_reload(void)
{
    return 1;
}
*/

njt_module_t njt_helper_access_data_module = {
    NJT_MODULE_V1,      
    NULL,               /* module context */
    NULL,               /* module directives */
    NJT_HTTP_MODULE,    /* module type */
    NULL,               /* init master */
    NULL,               /* init module */
    NULL,               /* init process */
    NULL,               /* init thread */
    NULL,               /* exit thread */
    NULL,               /* exit process */
    NULL,               /* exit master */
    NJT_MODULE_V1_PADDING
};
