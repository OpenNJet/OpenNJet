/*
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include "njt_conf_json.h"


static njt_queue_t    njt_conf_json_queue_head;
static njt_pool_t    *njt_conf_json_dyn_pool;
njt_uint_t     njt_conf_json_in_process;
json_t        *njt_conf_json_root;


typedef struct {
    njt_queue_t     queue;
    json_t         *json;
    json_t         *cmd;
    size_t          index;
} njt_conf_json_queue_t;


static njt_str_t  njt_conf_json_need_oriarg_cmds[] = {
    njt_string("server_name"),
    njt_string("location"),
    njt_string("")
};

static njt_str_t  njt_conf_json_include_cmds[] = {
    njt_string("include"),
    njt_string("include_start"),
    njt_string("include_end"),
    njt_string("")
};

static njt_str_t  njt_conf_json_lua_blocks[] = {
    njt_string("init_by_lua_block"),
    njt_string("init_worker_by_lua_block"),
    njt_string("exit_worker_by_lua_block"),
    njt_string("set_by_lua_block"),
    njt_string("server_rewrite_by_lua_block"),
    njt_string("rewrite_by_lua_block"),
    njt_string("access_by_lua_block"),
    njt_string("content_by_lua_block"),
    njt_string("preread_by_lua_block"),
    njt_string("log_by_lua_block"),
    njt_string("header_filter_by_lua_block"),
    njt_string("body_filter_by_lua_block"),
    njt_string("balancer_by_lua_block"),
    njt_string("ssl_client_hello_by_lua_block"),
    njt_string("ssl_certificate_by_lua_block"),
    njt_string("ssl_session_fetch_by_lua_block"),
    njt_string("")
};


// static njt_str_t  njt_conf_json_simple_blocks[] = {
//     njt_string("http"),
//     njt_string("mail"),
//     njt_string("event"),
//     njt_string("")
// };


njt_uint_t njt_conf_json_is_server_block(njt_str_t *arg);
njt_uint_t njt_conf_json_is_simple_block(njt_str_t *arg);
njt_uint_t njt_conf_json_is_lua_block(njt_str_t *arg);
njt_uint_t njt_conf_json_is_include_cmd(char *arg);
njt_uint_t njt_conf_json_is_need_oriarg_cmd(char *arg);

njt_uint_t njt_conf_json_obj_is_block(json_t obj);


// njt_int_t njt_conf_json_add_block_cf_simple(json_t *root, njt_conf_t *cf);
njt_int_t njt_conf_json_add_block_cf_lua(json_t *root, njt_conf_t *cf);
njt_int_t njt_conf_json_add_block_cf_common(json_t *root, njt_conf_t *cf);
njt_int_t njt_conf_json_save_to_file(njt_log_t *log, json_t *root);

// for json parser

static njt_int_t  njt_conf_json_file_depth;
#define NJT_CONF_JSON_INCLUDE_START "include_start"
#define NJT_CONF_JSON_INCLUDE_END "include_end"

njt_int_t
njt_conf_json_push_node(size_t index, json_t *cmd, json_t *block, njt_log_t *log)
{
    njt_conf_json_queue_t   *node;

    if (njt_conf_json_dyn_pool == NULL) {
        njt_log_error(NJT_LOG_ERR, log, 0, "no njt_conf_json_dyn_pool available");
        return NJT_ERROR;
    }

    node = njt_palloc(njt_conf_json_dyn_pool, sizeof(njt_conf_json_queue_t));
    if (!node) {
        njt_log_error(NJT_LOG_ERR, log, 0, "failed to alloc njt_conf_json_queue");
        return NJT_ERROR;
    }

    node->json = block;
    node->cmd = cmd;
    node->index = index;

    njt_queue_insert_tail(&njt_conf_json_queue_head, &node->queue);

    return NJT_OK;
}



void
njt_conf_json_pop_node()
{
    njt_conf_json_queue_t   *node;

    if (njt_queue_empty(&njt_conf_json_queue_head)) {
        return;
    }

    node = (njt_conf_json_queue_t *)njt_queue_last(&njt_conf_json_queue_head);
    njt_queue_remove(&node->queue);

    // 是现在删除还是最后 destroy_pool ??
    njt_pfree(njt_conf_json_dyn_pool, node);
}

njt_uint_t
njt_conf_json_is_server_cmd(njt_str_t *arg) {
    return (arg->len == 6 && njt_strncmp(arg->data, "server", 6) == 0);
}


json_t*
njt_conf_json_get_cur_block()
{
    njt_conf_json_queue_t   *node;

    if (njt_queue_empty(&njt_conf_json_queue_head)) {
        return NULL;
    }

    node = (njt_conf_json_queue_t *)njt_queue_last(&njt_conf_json_queue_head);
    return node->json;
}


njt_uint_t
njt_conf_json_is_lua_block(njt_str_t *arg)
{
    njt_int_t        i;
    njt_str_t       *key;
    
    for (i = 0; ; i++ ) {

        key = &njt_conf_json_lua_blocks[i];
        if (key->len == 0) {
            break;
        }

        if (key->len == arg->len && njt_strncasecmp(arg->data, key->data, key->len) == 0) {
            return 1;
        }
    }

    return 0;
}


njt_uint_t
njt_conf_json_is_include_cmd(char *arg)
{
    njt_uint_t        i, size;
    njt_str_t       *key;
    
    size = strlen(arg);
    for (i = 0; ; i++ ) {

        key = &njt_conf_json_include_cmds[i];
        if (key->len == 0) {
            break;
        }

        if (key->len == size && njt_strncasecmp((u_char *)arg, key->data, size) == 0) {
            return 1;
        }
    }

    return 0;
}


njt_uint_t
njt_conf_json_is_need_oriarg_cmd(char *arg)
{
    njt_uint_t        i, size;
    njt_str_t       *key;
    
    size = strlen(arg);
    for (i = 0; ; i++ ) {

        key = &njt_conf_json_need_oriarg_cmds[i];
        if (key->len == 0) {
            break;
        }

        if (key->len == size && njt_strncasecmp((u_char *)arg, key->data, size) == 0) {
            return 1;
        }
    }

    return 0;
}


njt_int_t
njt_conf_json_op_start(njt_log_t *log) {
    json_t * array;

    // 只在初始化， master reload 与 pa进程中完成, 后续有变更再修改
    if (njt_process != NJT_PROCESS_HELPER && njt_worker == 0) {
        if (njt_conf_json_in_process) {
            njt_log_error(NJT_LOG_ERR, log, 0, "call njt_conf_json_parse_start twice.");
            return NJT_ERROR;
        }
        njt_conf_json_dyn_pool = njt_create_pool(NJT_CYCLE_POOL_SIZE, log);
        if (njt_conf_json_dyn_pool == NULL) {
            njt_log_error(NJT_LOG_ERR, log, 0, "failed to create njt_conf_json_dyn_pool.");
            return NJT_ERROR;
        }
        njt_conf_json_in_process = 1;
        njt_queue_init(&njt_conf_json_queue_head);
        if (njt_conf_json_root == NULL) {
            njt_conf_json_root = json_object();
            if (njt_conf_json_root == NULL) {
                njt_log_error(NJT_LOG_ERR, log, 0, "failed to create njt_conf_json_root.");
                return NJT_ERROR;
            }
            array = json_array();
            if (array == NULL) {
                njt_log_error(NJT_LOG_ERR, log, 0, "failed to create array in json root.");
                return NJT_ERROR;
            }
            json_object_set_new(njt_conf_json_root, NJT_CONF_JSON_KEY_PARSED, array);
        }

        njt_conf_json_queue_t *node = njt_palloc(njt_conf_json_dyn_pool, sizeof(njt_conf_json_query_t));
        if (node == NULL) {
            njt_log_error(NJT_LOG_ERR, log, 0, "failed to create njt_conf_json_queue.");
            return NJT_ERROR;
        }
        node->json = json_object_get(njt_conf_json_root, NJT_CONF_JSON_KEY_PARSED);
        njt_queue_insert_tail(&njt_conf_json_queue_head, &node->queue);
    }
    return NJT_OK;
}


njt_int_t
njt_conf_json_op_end(njt_log_t *log) {
    // 只在初始化， master reload 与 pa进程中完成, 后续有变量再修改
    if (njt_process != NJT_PROCESS_HELPER && njt_worker == 0) {
        if (!njt_conf_json_in_process) {
            // njt_log_error(NJT_LOG_INFO, log, 0, "call njt_conf_json_parse_stop twice.");
            return NJT_OK;
        }
        if (njt_conf_json_dyn_pool == NULL) {
            njt_log_error(NJT_LOG_ERR, log, 0, "create njt_conf_json_dyn_pool is null.");
            return NJT_ERROR;
        }
        njt_destroy_pool(njt_conf_json_dyn_pool);
        njt_conf_json_dyn_pool = NULL;
        njt_queue_init(&njt_conf_json_queue_head);
        if (njt_conf_json_root && njt_conf_json_in_process == NJT_CONF_JSON_PARSE_CONF) {
            // njt_conf_json_save_to_file(log, njt_conf_json_root);
        }
        njt_conf_json_in_process = 0;
    }
    return NJT_OK;
}


njt_int_t
njt_conf_json_add_cmd_cf(json_t *root, njt_conf_t *cf)
{
    njt_str_t  *args;
    json_t     *obj, *array;
    njt_uint_t  i;

    if (!njt_conf_json_in_process || !root) {
        return NJT_ERROR;
    }

    if (!json_is_array(root)) {
        njt_log_error(NJT_LOG_ERR, cf->log, 0, "root must be array type");
    }

    obj = json_object();
    if (obj == NULL) {
        njt_log_error(NJT_LOG_ERR, cf->log, 0, "failed to alloc obj for command");
    }

    array = json_array();
    if (array == NULL) {
        njt_log_error(NJT_LOG_ERR, cf->log, 0, "failed to alloc array for command");
    }
    
    args = cf->args->elts;
    json_object_set_new(obj, NJT_CONF_JSON_KEY_CMD, json_stringn((const char *)args->data, args->len));

    for (i=1; i < cf->args->nelts; i++) {
        // cf中解析过程中，每一个arg都是以\0结束的，可以直接使用
        json_array_append_new(array, json_stringn((const char *)args[i].data, args[i].len));
    }

    json_object_set_new(obj, NJT_CONF_JSON_KEY_ARGS, array);
    json_array_append_new(root, obj);

    return NJT_OK;
}


// njt_int_t
// njt_conf_json_add_query_block(njt_array_t *queries,
//     njt_str_t *key, njt_str_t *block_name)
// {
//     json_t  *value;

//     if (block_name == NULL) {

//     }
// }


njt_int_t
njt_conf_json_add_block_cf(json_t *root, njt_conf_t *cf) {
    njt_str_t *args;

    if (!njt_conf_json_in_process || !root) {
        return NJT_ERROR;
    }

    if (!njt_conf_json_in_process || !root) {
        return NJT_ERROR;
    }

    args = cf->args->elts;

    if (njt_conf_json_is_lua_block(args)) {
        // 加lua block; "xxx_by_lua_block": "{\"code_string\"}"
        return NJT_CONF_BLOCK_LUA;
    } else {
        // 普通block  "block_name": [{"_key": ["", ""], "_value"},...,{}]
        return njt_conf_json_add_block_cf_common(root, cf);
    }

    return NJT_OK;
}


njt_int_t
njt_conf_json_add_block_cf_lua(json_t *root, njt_conf_t *cf)
{
    njt_str_t   *cmd;
    json_t      *array, *obj, *args, *lua_obj;

    if (!json_is_array(root)) {
        njt_log_error(NJT_LOG_ERR, cf->log, 0, "root must be array type");
        return NJT_ERROR;
    }

    if (cf->args->nelts != 2) {
        njt_log_error(NJT_LOG_ERR, cf->log, 0, "cf of lua block must has exactly 2 args");
        return NJT_ERROR;
    }

    obj = json_object();
    lua_obj = json_object();
    if (obj == NULL || lua_obj == NULL) {
        njt_log_error(NJT_LOG_ERR, cf->log, 0, "failed to alloc obj or lua_obj for block");
    }

    array = json_array();
    if (array == NULL) {
        njt_log_error(NJT_LOG_ERR, cf->log, 0, "failed to alloc array for block");
    }
    
    cmd = cf->args->elts;
    json_object_set_new(obj, NJT_CONF_JSON_KEY_CMD, json_stringn((const char *)cmd->data, cmd->len));
    json_object_set_new(lua_obj, NJT_CONF_JSON_KEY_CODE, 
                        json_stringn((const char *)cmd[1].data, cmd[1].len));

    args = json_array();
    if (args == NULL) {
        njt_log_error(NJT_LOG_ERR, cf->log, 0, "failed to alloc args for block");
    }
    
    json_array_append_new(array, lua_obj);
    json_object_set_new(obj, NJT_CONF_JSON_KEY_ARGS, args);
    json_object_set_new(obj, NJT_CONF_JSON_KEY_BLOCK, array);
    json_array_append_new(root, obj);

    return NJT_OK;
}


njt_int_t
njt_conf_json_add_block_cf_common(json_t *root, njt_conf_t *cf)
{
    // root must be array
    njt_str_t   *cmd;
    json_t      *array, *obj, *args;
    njt_uint_t   i;

    if (!json_is_array(root)) {
        njt_log_error(NJT_LOG_ERR, cf->log, 0, "root must be array type");
    }

    obj = json_object();
    if (obj == NULL) {
        njt_log_error(NJT_LOG_ERR, cf->log, 0, "failed to alloc obj for block");
    }

    array = json_array();
    if (array == NULL) {
        njt_log_error(NJT_LOG_ERR, cf->log, 0, "failed to alloc array for block");
    }
    
    cmd = cf->args->elts;
    json_object_set_new(obj, NJT_CONF_JSON_KEY_CMD, json_stringn((const char *)cmd->data, cmd->len));

    args = json_array();
    if (args == NULL) {
        njt_log_error(NJT_LOG_ERR, cf->log, 0, "failed to alloc args for block");
    }
    
    for (i = 1; i < cf->args->nelts; i++) {
        json_array_append_new(args, json_stringn((const char *)cmd[i].data, cmd[i].len)); // 要测试 是否需要 len - 1 
    }

    json_object_set_new(obj, NJT_CONF_JSON_KEY_ARGS, args);
    json_object_set_new(obj, NJT_CONF_JSON_KEY_BLOCK, array);
    json_array_append_new(root, obj);


    njt_conf_json_push_node(0, obj, array, cf->log); // todo

    return NJT_OK;
}


void
njt_conf_json_add_block_end_cf(json_t *root, njt_conf_t *cf)
{
    if (njt_conf_json_file_depth <= 1) {
        njt_conf_json_pop_node();
    }
}


njt_int_t
njt_conf_json_parse_file_start(njt_str_t *file, njt_log_t *log)
{
    json_t    *root;
    // json_t    *obj, *root;

    if (njt_process == NJT_PROCESS_HELPER || !njt_conf_json_in_process) {
        return NJT_OK;
    }

    root = njt_conf_json_get_cur_block();
    if (!njt_conf_json_in_process || !root) {
        njt_log_error(NJT_LOG_ERR, log, 0, "not in json parse op process");
        return NJT_ERROR;
    }

    if (njt_conf_json_file_depth) {
        // obj = json_object();
        // json_object_set(obj, NJT_CONF_JSON_KEY_CMD, json_string(NJT_CONF_JSON_INCLUDE_START));
        // json_object_set_new(obj, NJT_CONF_JSON_KEY_FILE,
        //                     json_stringn((const char *)file->data, file->len));
        // json_array_append_new(root, obj);
    } else {
        json_object_set_new(njt_conf_json_root, NJT_CONF_JSON_KEY_FILE,
            json_stringn((const char *)file->data, file->len));
    }

    njt_conf_json_file_depth++;
    return NJT_OK;
}

njt_int_t
njt_conf_json_parse_file_end(njt_str_t *file, njt_conf_t *cf)
{
    json_t   *root;
    // json_t    *obj, *root;

    if (njt_process == NJT_PROCESS_HELPER || !njt_conf_json_in_process) {
        return NJT_OK;
    }

    root = njt_conf_json_get_cur_block();
    if (!root && njt_conf_json_file_depth == 1) {
        return NJT_OK;
    }

    if (!njt_conf_json_in_process) {
        njt_log_error(NJT_LOG_ERR, cf->log, 0, "not in json parse op process");
        return NJT_ERROR;
    }

    njt_conf_json_file_depth--;
    // if (njt_conf_json_file_depth) {
    //     obj = json_object();
    //     json_object_set(obj, NJT_CONF_JSON_KEY_CMD, json_string(NJT_CONF_JSON_INCLUDE_END));
    //     json_object_set_new(obj, NJT_CONF_JSON_KEY_FILE,
    //                         json_stringn((const char *)file->data, file->len));
    //     json_array_append_new(root, obj);
    // }
    cf->args->nelts = 0;
    return NJT_OK;
}


njt_int_t
njt_conf_json_handler(njt_conf_t *cf, njt_int_t rc)
{
    json_t              *root;

    if (njt_process == NJT_PROCESS_HELPER || !njt_conf_json_in_process) {
        return NJT_OK;
    }

    if (njt_conf_json_file_depth > 1 || cf->args->nelts == 0) {
        return  NJT_OK;
    }

    root = njt_conf_json_get_cur_block();
    if (root == NULL) {
        njt_log_error(NJT_LOG_ERR, cf->log, 0, "can not get json root");
        return NJT_ERROR;
    }

    if (rc == NJT_CONF_BLOCK_START) {
        return njt_conf_json_add_block_cf(root, cf);
    } else if (rc == NJT_CONF_BLOCK_DONE) {
        njt_conf_json_pop_node();
        return NJT_OK;
    } else if (rc == NJT_OK) {
        return njt_conf_json_add_cmd_cf(root, cf);
    } 

    njt_log_error(NJT_LOG_ERR, cf->log, 0, "unexpected rc %ld", rc);
    return NJT_ERROR;
}


njt_int_t
njt_conf_json_lua_block_handler(njt_conf_t *cf)
{
    json_t              *root;

    root = njt_conf_json_get_cur_block();
    if (root == NULL) {
        njt_log_error(NJT_LOG_ERR, cf->log, 0, "can not get json root");
        return NJT_ERROR;
    }

    return njt_conf_json_add_block_cf_lua(root, cf);
}


/**
 * 校验文件是否为有效JSON格式
 * @param filename 要校验的文件路径
 * @return 1表示有效JSON，0表示无效或文件错误
 */
njt_int_t
njt_conf_json_validate_json_file(njt_conf_t *cf, const char *filename) {
    json_t              *root;
    json_error_t         error;
    const char* suffix = ".json";
    size_t               len, suffix_len, i;
    
    if (!filename || !*filename) {
        return NJT_ERROR;
    }

    root = json_load_file(filename, 0, &error);

    if (!root) {
        // check file name is *.json
        len = strlen(filename);
        suffix_len = strlen(suffix);
        
        if (len < suffix_len) {
            return NJT_ERROR;
        }
        
        const char* end = filename + len - suffix_len;
        for (i = 0; i < suffix_len; i++) {
            if (tolower((unsigned char)end[i]) != tolower((unsigned char)suffix[i])) {
                return NJT_ERROR;
            }
        }
        njt_log_error(NJT_LOG_EMERG, cf->log, 0, "JSON file parse error (line %d, colume %d): %s\n",
                error.line, error.column, error.text);
        return NJT_ERROR;
    }

    cf->json = root;
    return NJT_OK;
}


njt_int_t
njt_conf_json_get_token(njt_conf_t *cf, json_t *obj, size_t index)
{
    json_t      *args, *block, *item, *cmd;
    njt_str_t   *arg, *ori_arg;
    size_t       idx, len;
    njt_int_t    rc;

    if (!json_is_object(obj)) {
        njt_log_error(NJT_LOG_ERR, cf->log, 0, "item should be a json object");
        return NJT_ERROR;
    }

    if(cf->ori_args == NULL) {
        cf->ori_args = njt_array_create(cf->pool, 10, sizeof(njt_str_t));
        if (cf->ori_args == NULL) {
            return NJT_ERROR;
        }
    }

    cf->args->nelts = 0;
    cf->ori_args->nelts = 0;

    cmd = json_object_get(obj, NJT_CONF_JSON_KEY_CMD);
    block = json_object_get(obj, NJT_CONF_JSON_KEY_BLOCK);

    if (json_is_string(cmd)) {
        arg = njt_array_push(cf->args);
        len = json_string_length(cmd);
        arg->data = njt_palloc(cf->pool, len + 1);
        arg->len = len;
        memcpy(arg->data, json_string_value(cmd), len);
        arg->data[len] = '\0';
        ori_arg = njt_array_push(cf->ori_args);
        *ori_arg = *arg;
    } else {
        njt_log_error(NJT_LOG_ERR, cf->log, 0, "cmd should be a json string");
        return NJT_ERROR;
    }
    
    rc = NJT_OK;

    if (njt_conf_json_is_include_cmd((char *)arg->data) && arg->len > njt_conf_json_include_cmds[0].len) {
        arg = njt_array_push(cf->args);
        item = json_object_get(obj, NJT_CONF_JSON_KEY_FILE);
        if (item == NULL) {
            njt_log_error(NJT_LOG_ERR, cf->log, 0, "include cmd should have file attribute");
            return NJT_ERROR;
        }
        len = json_string_length(item);
        arg->data = njt_palloc(cf->pool, len + 1);
        arg->len = len;
        memcpy(arg->data, json_string_value(item), len);
        arg->data[len] = '\0';
        return NJT_CONF_CMD_INCLUDE;
    }

    if (block) {
        if (njt_conf_json_is_lua_block(arg)) {
            arg = njt_array_push(cf->args);
            item = json_array_get(block, 0);
            item = json_object_get(item, NJT_CONF_JSON_KEY_CODE);
            len = json_string_length(item);
            arg->data = njt_palloc(cf->pool, len + 1 );
            arg->len = len;
            memcpy(arg->data, json_string_value(item), len);
            arg->data[len] = '\0';
            return NJT_CONF_BLOCK_LUA;
        } else {
            // 设置 cf->args
            // push stack
        }
        rc = NJT_CONF_BLOCK_START;
        njt_conf_json_push_node(index, cmd, block, cf->log);
    }

    args = json_object_get(obj, NJT_CONF_JSON_KEY_ARGS);

    json_array_foreach(args, idx, item) {
        arg = njt_array_push(cf->args);
        len = json_string_length(item);
        arg->data = njt_palloc(cf->pool, len + 1 );
        arg->len = len;
        memcpy(arg->data, json_string_value(item), len);
        arg->data[len] = '\0';

        ori_arg = njt_array_push(cf->ori_args);
        *ori_arg = *arg;
    }

    return rc;
}


njt_int_t
njt_conf_json_json_parse_log_error(size_t index, njt_conf_t *cf)
{
    njt_conf_json_queue_t  *node;
    njt_queue_t            *cur;
    njt_int_t               level, written;
    njt_uint_t              i;
    njt_str_t              *args;
    char                    path[NJT_CYCLE_POOL_SIZE];


    if (!njt_conf_json_in_process) {
        return NJT_OK; // output only once
    }
    
    written = 0;
    args = cf->args->elts;
    for (i = 0; i < cf->args->nelts; i++) {
        if (written + args[i].len < NJT_CYCLE_POOL_SIZE) {
            written += snprintf(&path[written], NJT_CYCLE_POOL_SIZE - written - 1,
                               "%s ", args[i].data);
        } else {
            break;
        }
    }
    njt_log_error(NJT_LOG_EMERG, cf->log, 0, "error cmd: %s", path);

    cur = njt_queue_next(&njt_conf_json_queue_head);
    level = 0;
    written = 0;
    
    while (cur != &njt_conf_json_queue_head) {
        node = (njt_conf_json_queue_t *) cur;
        if (level == 0) {
           written += snprintf(&path[written], NJT_CYCLE_POOL_SIZE - written - 1,
                               "root");
        } else {
           written += snprintf(&path[written], NJT_CYCLE_POOL_SIZE - written - 1,
                               "[%ld]->%s", node->index, json_string_value(node->cmd));
        }

        cur = njt_queue_next(cur);
        level++;
    }
    
    njt_log_error(NJT_LOG_EMERG, cf->log, 0, "error position %s", path);
    
    return NJT_OK;
}


njt_int_t
njt_conf_json_save_to_file(njt_log_t *log, json_t *root)
{
    char        fname[1024];
    json_t     *conf;

    conf = json_object_get(root, NJT_CONF_JSON_KEY_FILE);
    if (!conf) {
        return NJT_OK;
    }

    njt_log_error(NJT_LOG_INFO, log, 0, "dump conf file to %s", fname);
    snprintf(fname, 1024, "./njet_conf.json");
    // snprintf(fname, 1024, "./njet_conf.json", json_string_value(conf));

    return json_dump_file(root, fname, JSON_INDENT(2));
}