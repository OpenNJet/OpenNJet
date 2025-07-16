
/*
 * Copyright (C) 2021-2025  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_CONF_JSON_INCLUDED_
#define _NJT_CONF_JSON_INCLUDED_

#include <njt_config.h>
#include <njt_core.h>
#include <jansson.h>

// 直接查找
#define NJT_CONF_JSON_QUERY_KEY         0
// 查找server 需要对比listen和server_name
#define NJT_CONF_JSON_QUERY_SERVER      1
// 查找location 对比location rule 和 location name
#define NJT_CONF_JSON_QUERY_LOCATION    2
#define NJT_CONF_JSON_QUERY_BLOCK       3

#define NJT_CONF_JSON_UPDATE_APPEND     0
#define NJT_CONF_JSON_UPDATE_REPLACE    1

#define NJT_CONF_BLOCK_LUA              4
#define NJT_CONF_CMD_INCLUDE            5


// 只有在init_cycle中可以直接构建json
// 后续的动态更新全部在pa进程中进行

/*
 * 主要json结构
 * 最外层对应的解析结构
 * { 
 *   "file": "conf_file_name",
 *   “parsed”: [{}, {}] 每一个object对应一个命令或一个块
 * }
 * 每一个命令或块
 * {
 *   “cmd": "cmd_name",
 *   "args": ["aaa", "bbb", "ccc"]
 *   "block": [{}, {}]
 * }
 * 为include的具体指令增加两个特殊的标志
 * {
 *   "cmd": "include_start"|"include_end", 用来标志include文件的开始和结束，可能有嵌套
 *   "file": "include file name"
 * }
 */

#define NJT_CONF_JSON_KEY_CMD    "cmd"
#define NJT_CONF_JSON_KEY_FILE   "file"
#define NJT_CONF_JSON_KEY_ARGS   "args"
#define NJT_CONF_JSON_KEY_CODE   "code"
#define NJT_CONF_JSON_KEY_BLOCK  "block"
#define NJT_CONF_JSON_KEY_PARSED  "parsed"

#define NJT_CONF_JSON_PARSE_CONF       1
#define NJT_CONF_JSON_PARSE_JSON_CONF  2

typedef struct {
    njt_uint_t   type;
    char        *key;
    union {
        struct { // type: NJT_CONF_JSON_QUERY_SERVER
            char    *listen;
            char    *server_name;
        };
        struct { // type: NJT_CONF_JSON_QUERY_LOCATION
            char    *location_rule;
            char    *location_name;
        };
        struct { // type: NJT_CONF_JSOGN_QUERY_BLOCK
            char    *block_name;
        };
    };
} njt_conf_json_query_t;


typedef struct {
    njt_uint_t   type; // append, replace
    char        *key;
    njt_array_t *args;
} njt_conf_json_update_cmd_t;


typedef struct {
    njt_uint_t   type; // single obj,  obj array
    char        *key;
    njt_array_t *args; // args != NULL set "_key" value
} njt_conf_json_update_block_t;


extern json_t *njt_conf_json_root;
extern json_t *njt_conf_json_root_old;
extern njt_uint_t njt_conf_json_in_process;

njt_int_t njt_conf_json_op_start(njt_log_t *log);
njt_int_t njt_conf_json_op_end(njt_log_t  *log);


// todo for dyn json conf
// njt_int_t njt_conf_json_update(json_t *root, njt_conf_t *cf);
// njt_int_t njt_conf_json_set(json_t *root, njt_conf_t *cf);
// json_t*  njt_conf_json_get_querys(json_t *root, njt_array_t *querys);
// json_t*  njt_conf_json_get_query(json_t *root, njt_conf_json_query_t *query);

// njt_array_t* njt_conf_json_create_querys();
// njt_int_t njt_conf_json_add_query_key(njt_array_t *queries, njt_str_t *key);
// njt_int_t njt_conf_json_add_query_server(njt_array_t *queries,
//     njt_str_t *listen, njt_str_t *server_name);
// njt_int_t njt_conf_json_add_query_location(njt_array_t *queries,
//     njt_str_t *location_rule, njt_str_t *location_name);
// njt_int_t njt_conf_json_add_query_block(njt_array_t *queries,
//     njt_str_t *key, njt_str_t *block_name);


njt_int_t njt_conf_json_add_cmd_cf(json_t *root, njt_conf_t *cf);
njt_int_t njt_conf_json_add_block_cf(json_t *root, njt_conf_t *cf);
void njt_conf_json_add_block_end_cf(json_t *root, njt_conf_t *cf); //此时需要上移动一层
json_t*   njt_conf_json_get_cur_block();

njt_int_t njt_conf_json_parse_file_start(njt_str_t *file_name, njt_log_t *log);
njt_int_t njt_conf_json_parse_file_end(njt_str_t *file_name, njt_conf_t *cf);
njt_int_t njt_conf_json_handler(njt_conf_t *cf, njt_int_t rc);
njt_int_t njt_conf_json_lua_block_handler(njt_conf_t *cf);

njt_int_t njt_conf_json_validate_json_file(njt_conf_t *cf, const char *filename);
njt_int_t njt_conf_json_get_token(njt_conf_t *cf, json_t *item, size_t index);
njt_int_t njt_conf_json_json_parse_log_error(size_t index, njt_conf_t *cf);

#endif /* _NJT_CONF_JSON_INCLUDED_ */