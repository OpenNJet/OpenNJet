
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_DYN_CONF_H_INCLUDED_
#define _NJT_DYN_CONF_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>

// #if NJT_HTTP_DYNAMIC_LOC
// #include <njt_http_location_module.h>
// #endif

typedef struct njt_conf_cmd_s njt_conf_cmd_t;
typedef struct njt_conf_block_s njt_conf_block_t;
typedef struct njt_conf_element_s njt_conf_element_t;


struct njt_conf_cmd_s {
    njt_str_t     key;
    njt_array_t  *value;
    // njt_uint_t    is_flag:1;
    // njt_uint_t    is_num:1;
};

struct njt_conf_block_s {
    njt_str_t     key;
    njt_array_t  *value;
};

struct njt_conf_element_s {
    njt_conf_cmd_t     *block_name;
    njt_array_t        *cmds;
    njt_array_t        *blocks; // not null, has sub block
    njt_conf_element_t *parent;
};

#if NJT_HTTP_DYNAMIC_LOC
typedef struct njt_conf_sub_location_info_s {
	njt_str_t location_rule;
    njt_str_t location;
    njt_str_t proxy_pass;
    njt_str_t location_body;
	njt_array_t   *sub_location_array;
} njt_conf_sub_location_info_t;

typedef struct njt_conf_location_info_s {
    njt_str_t file;
	njt_str_t type;
    njt_str_t addr_port;
    njt_str_t server_name;
	njt_str_t location_rule;
    njt_str_t location;
    //njt_str_t proxy_pass;
    //njt_str_t location_body;
	njt_pool_t *pool;
    // njt_http_core_srv_conf_t *cscf;
    void *cscf;
    njt_str_t     msg;
	njt_array_t   *location_array;
	u_char *buffer;
	int32_t buffer_len;
} njt_conf_location_info_t;

typedef struct njt_conf_dyn_loc_loc_s njt_conf_dyn_loc_loc_t;
typedef struct njt_conf_dyn_loc_svr_s njt_conf_dyn_loc_svr_t;

struct njt_conf_dyn_loc_loc_s {
    njt_str_t *rule;
    njt_str_t *loc_name;
    njt_str_t *body;
    njt_str_t *proxy_pass;
};

struct njt_conf_dyn_loc_svr_s {
    njt_str_t *listen;
    njt_str_t *svr_name;
};
#endif

extern void *njt_conf_pool_ptr; 
extern void *njt_conf_dyn_loc_pool; 
extern void *njt_conf_cur_ptr; 
extern void *njt_conf_dyn_loc_ptr;
extern njt_str_t njt_conf_json; 

njt_int_t njt_conf_element_handler(njt_pool_t *pool, 
    njt_conf_t *cf, njt_int_t rc);
void njt_conf_get_json_length(njt_conf_element_t *root,
    size_t *length, njt_uint_t is_root);
void njt_conf_get_json_str(njt_conf_element_t *root,
    njt_str_t *out, njt_uint_t is_root);
njt_conf_element_t* njt_conf_get_server_block(
    njt_conf_element_t *cur, njt_str_t *listen, njt_str_t *server_name);
njt_conf_element_t * njt_conf_get_http_block(njt_pool_t *pool);
njt_conf_element_t * njt_conf_get_simple_location_block(njt_pool_t *pool,
    njt_conf_element_t *cur, njt_str_t *name);
njt_conf_element_t* njt_conf_get_loc_block( njt_conf_element_t *cur,
    njt_str_t *key, njt_array_t *sub_names);
njt_conf_element_t* njt_conf_get_block( njt_conf_element_t *cur, 
    njt_str_t *key, njt_array_t *sub_names);
njt_conf_cmd_t* njt_conf_get_cmd_conf(njt_conf_element_t *block, njt_str_t *key);
njt_int_t njt_conf_add_cmd(njt_pool_t *pool,
    njt_conf_element_t *block, njt_array_t *cf);
njt_int_t njt_conf_set_cmd(njt_pool_t *pool,
    njt_conf_element_t *block, njt_array_t *cf);
njt_int_t njt_conf_cmd_hit_item(njt_pool_t *pool,
    njt_conf_element_t *block, njt_array_t *cf);
njt_int_t njt_conf_cmd_del_item(njt_pool_t *pool,
    njt_conf_element_t *block, njt_array_t *cf);
njt_conf_element_t* njt_conf_create_block(njt_pool_t *pool, njt_array_t *names);
njt_int_t njt_conf_add_block( njt_pool_t *pool, njt_conf_element_t *parent, 
    njt_conf_element_t *child, njt_str_t *key);
njt_int_t njt_conf_delete_block(njt_pool_t *pool, njt_conf_element_t *block);
njt_int_t njt_conf_save_to_file(njt_pool_t *pool, njt_log_t *log,
    njt_conf_element_t *root, njt_str_t *fname);
njt_int_t njt_conf_check_svrname_listen(njt_pool_t *pool, njt_conf_element_t *root);

void njt_conf_init_conf_parse(njt_conf_element_t *root, njt_pool_t* pool);
void njt_conf_finish_conf_parse(); 

#if NJT_HTTP_DYNAMIC_LOC
njt_conf_element_t * njt_conf_dyn_loc_init_server(njt_pool_t *pool, njt_conf_element_t* root);
// njt_conf_location_info_t* get_test_location_info(njt_pool_t *pool, njt_uint_t add); // for test only
// njt_conf_element_t* get_test_element_ptr(njt_pool_t *pool, njt_uint_t add); // for test only
njt_int_t 
njt_conf_dyn_loc_merge_location(njt_pool_t *pool, njt_str_t* addr_port, njt_str_t *svr_name, njt_conf_element_t* dyn_locs);
njt_int_t njt_conf_dyn_loc_add_loc(njt_pool_t *pool, njt_conf_element_t *root, njt_conf_location_info_t *loc_info);
njt_int_t njt_conf_dyn_loc_del_loc(njt_pool_t * pool, njt_conf_element_t *root, njt_conf_location_info_t *loc_info);
njt_str_t* njt_conf_dyn_loc_get_pub_str(njt_pool_t *pool, njt_conf_element_t *root);
njt_str_t* njt_conf_dyn_loc_get_ins_str(njt_pool_t *pool, njt_conf_element_t *root);
njt_int_t njt_conf_dyn_loc_save_pub_to_file(njt_pool_t *pool, njt_log_t *log,
    njt_conf_element_t *root);
#endif
#endif // _NJT_DYN_CONF_H_INCLUDED_