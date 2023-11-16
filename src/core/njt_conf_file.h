
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_CONF_FILE_H_INCLUDED_
#define _NJT_CONF_FILE_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


/*
 *        AAAA  number of arguments
 *      FF      command flags
 *    TT        command type, i.e. HTTP "location" or "server" command
 */

#define NJT_CONF_NOARGS      0x00000001
#define NJT_CONF_TAKE1       0x00000002
#define NJT_CONF_TAKE2       0x00000004
#define NJT_CONF_TAKE3       0x00000008
#define NJT_CONF_TAKE4       0x00000010
#define NJT_CONF_TAKE5       0x00000020
#define NJT_CONF_TAKE6       0x00000040
#define NJT_CONF_TAKE7       0x00000080

#define NJT_CONF_MAX_ARGS    8

#define NJT_CONF_TAKE12      (NJT_CONF_TAKE1|NJT_CONF_TAKE2)
#define NJT_CONF_TAKE13      (NJT_CONF_TAKE1|NJT_CONF_TAKE3)

#define NJT_CONF_TAKE23      (NJT_CONF_TAKE2|NJT_CONF_TAKE3)

#define NJT_CONF_TAKE123     (NJT_CONF_TAKE1|NJT_CONF_TAKE2|NJT_CONF_TAKE3)
#define NJT_CONF_TAKE1234    (NJT_CONF_TAKE1|NJT_CONF_TAKE2|NJT_CONF_TAKE3   \
                              |NJT_CONF_TAKE4)

#define NJT_CONF_ARGS_NUMBER 0x000000ff
#define NJT_CONF_BLOCK       0x00000100
#define NJT_CONF_FLAG        0x00000200
#define NJT_CONF_ANY         0x00000400
#define NJT_CONF_1MORE       0x00000800
#define NJT_CONF_2MORE       0x00001000

#define NJT_DIRECT_CONF      0x00010000

#define NJT_MAIN_CONF        0x01000000
#define NJT_ANY_CONF         0xFF000000



#define NJT_CONF_UNSET       -1
#define NJT_CONF_UNSET_UINT  (njt_uint_t) -1
#define NJT_CONF_UNSET_PTR   (void *) -1
#define NJT_CONF_UNSET_SIZE  (size_t) -1
#define NJT_CONF_UNSET_MSEC  (njt_msec_t) -1


#define NJT_CONF_OK          NULL
#define NJT_CONF_ERROR       (void *) -1

#define NJT_CONF_BLOCK_START 1
#define NJT_CONF_BLOCK_DONE  2
#define NJT_CONF_FILE_DONE   3

#define NJT_CORE_MODULE      0x45524F43  /* "CORE" */
#define NJT_CONF_MODULE      0x464E4F43  /* "CONF" */


#define NJT_MAX_CONF_ERRSTR  1024


struct njt_command_s {
    njt_str_t             name;
    njt_uint_t            type;
    char               *(*set)(njt_conf_t *cf, njt_command_t *cmd, void *conf);
    njt_uint_t            conf;
    njt_uint_t            offset;
    void                 *post;
};

#define njt_null_command  { njt_null_string, 0, NULL, 0, 0, NULL }


struct njt_open_file_s {
    njt_fd_t              fd;
    njt_str_t             name;

    void                (*flush)(njt_open_file_t *file, njt_log_t *log);
    void                 *data;
};


typedef struct {
    njt_file_t            file;
    njt_buf_t            *buffer;
    njt_buf_t            *dump;
    njt_uint_t            line;
} njt_conf_file_t;


typedef struct {
    njt_str_t             name;
    njt_buf_t            *buffer;
} njt_conf_dump_t;


typedef char *(*njt_conf_handler_pt)(njt_conf_t *cf,
    njt_command_t *dummy, void *conf);


// add by lcm
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

extern void *njt_conf_cur_ptr; 
extern void *njt_conf_root_ptr;
extern njt_str_t njt_conf_json; 
// end of add

struct njt_conf_s {
    char                 *name;
    njt_array_t          *args;

    njt_cycle_t          *cycle;
    njt_pool_t           *pool;
    njt_pool_t           *temp_pool;
    njt_conf_file_t      *conf_file;
    njt_log_t            *log;

    njt_uint_t           dynamic;   //add by clb
    njt_uint_t           limit_dynamic;   //add by clb
    void                 *ctx;
    njt_uint_t            module_type;
    njt_uint_t            cmd_type;

    njt_conf_handler_pt   handler;
    void                 *handler_conf;
    njt_str_t *errstr;  //by zyg
};

typedef char *(*njt_conf_post_handler_pt) (njt_conf_t *cf,
    void *data, void *conf);

typedef struct {
    njt_conf_post_handler_pt  post_handler;
} njt_conf_post_t;


typedef struct {
    njt_conf_post_handler_pt  post_handler;
    char                     *old_name;
    char                     *new_name;
} njt_conf_deprecated_t;


typedef struct {
    njt_conf_post_handler_pt  post_handler;
    njt_int_t                 low;
    njt_int_t                 high;
} njt_conf_num_bounds_t;


typedef struct {
    njt_str_t                 name;
    njt_uint_t                value;
} njt_conf_enum_t;


#define NJT_CONF_BITMASK_SET  1

typedef struct {
    njt_str_t                 name;
    njt_uint_t                mask;
} njt_conf_bitmask_t;



char * njt_conf_deprecated(njt_conf_t *cf, void *post, void *data);
char *njt_conf_check_num_bounds(njt_conf_t *cf, void *post, void *data);


#define njt_get_conf(conf_ctx, module)  conf_ctx[module.index]



#define njt_conf_init_value(conf, default)                                   \
    if (conf == NJT_CONF_UNSET) {                                            \
        conf = default;                                                      \
    }

#define njt_conf_init_ptr_value(conf, default)                               \
    if (conf == NJT_CONF_UNSET_PTR) {                                        \
        conf = default;                                                      \
    }

#define njt_conf_init_uint_value(conf, default)                              \
    if (conf == NJT_CONF_UNSET_UINT) {                                       \
        conf = default;                                                      \
    }

#define njt_conf_init_size_value(conf, default)                              \
    if (conf == NJT_CONF_UNSET_SIZE) {                                       \
        conf = default;                                                      \
    }

#define njt_conf_init_msec_value(conf, default)                              \
    if (conf == NJT_CONF_UNSET_MSEC) {                                       \
        conf = default;                                                      \
    }

#define njt_conf_merge_value(conf, prev, default)                            \
    if (conf == NJT_CONF_UNSET) {                                            \
        conf = (prev == NJT_CONF_UNSET) ? default : prev;                    \
    }

#define njt_conf_merge_ptr_value(conf, prev, default)                        \
    if (conf == NJT_CONF_UNSET_PTR) {                                        \
        conf = (prev == NJT_CONF_UNSET_PTR) ? default : prev;                \
    }

#define njt_conf_merge_uint_value(conf, prev, default)                       \
    if (conf == NJT_CONF_UNSET_UINT) {                                       \
        conf = (prev == NJT_CONF_UNSET_UINT) ? default : prev;               \
    }

#define njt_conf_merge_msec_value(conf, prev, default)                       \
    if (conf == NJT_CONF_UNSET_MSEC) {                                       \
        conf = (prev == NJT_CONF_UNSET_MSEC) ? default : prev;               \
    }

#define njt_conf_merge_sec_value(conf, prev, default)                        \
    if (conf == NJT_CONF_UNSET) {                                            \
        conf = (prev == NJT_CONF_UNSET) ? default : prev;                    \
    }

#define njt_conf_merge_size_value(conf, prev, default)                       \
    if (conf == NJT_CONF_UNSET_SIZE) {                                       \
        conf = (prev == NJT_CONF_UNSET_SIZE) ? default : prev;               \
    }

#define njt_conf_merge_off_value(conf, prev, default)                        \
    if (conf == NJT_CONF_UNSET) {                                            \
        conf = (prev == NJT_CONF_UNSET) ? default : prev;                    \
    }

#define njt_conf_merge_str_value(conf, prev, default)                        \
    if (conf.data == NULL) {                                                 \
        if (prev.data) {                                                     \
            conf.len = prev.len;                                             \
            conf.data = prev.data;                                           \
        } else {                                                             \
            conf.len = sizeof(default) - 1;                                  \
            conf.data = (u_char *) default;                                  \
        }                                                                    \
    }

#define njt_conf_merge_bufs_value(conf, prev, default_num, default_size)     \
    if (conf.num == 0) {                                                     \
        if (prev.num) {                                                      \
            conf.num = prev.num;                                             \
            conf.size = prev.size;                                           \
        } else {                                                             \
            conf.num = default_num;                                          \
            conf.size = default_size;                                        \
        }                                                                    \
    }

#define njt_conf_merge_bitmask_value(conf, prev, default)                    \
    if (conf == 0) {                                                         \
        conf = (prev == 0) ? default : prev;                                 \
    }


char *njt_conf_param(njt_conf_t *cf);
char *njt_conf_parse(njt_conf_t *cf, njt_str_t *filename);
char *njt_conf_include(njt_conf_t *cf, njt_command_t *cmd, void *conf);


// ------------------------------------------
void njt_conf_get_json_length(njt_conf_element_t *root,
    size_t *length, njt_uint_t is_root);
void njt_conf_get_json_str(njt_conf_element_t *root,
    njt_str_t *out, njt_uint_t is_root);
njt_conf_element_t* njt_conf_get_server_block(
    njt_conf_element_t *cur, njt_str_t *listen, njt_str_t *server_name);
njt_conf_element_t * njt_conf_get_http_block(njt_pool_t *pool);
njt_conf_element_t * njt_conf_get_simple_location_block(njt_pool_t *pool,
    njt_conf_element_t *cur, njt_str_t *name);
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
// ---------------------------------------------

njt_int_t njt_conf_full_name(njt_cycle_t *cycle, njt_str_t *name,
    njt_uint_t conf_prefix);
njt_open_file_t *njt_conf_open_file(njt_cycle_t *cycle, njt_str_t *name);
void njt_cdecl njt_conf_log_error(njt_uint_t level, njt_conf_t *cf,
    njt_err_t err, const char *fmt, ...);


char *njt_conf_set_flag_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf);
char *njt_conf_set_str_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf);
char *njt_conf_set_str_array_slot(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *njt_conf_set_keyval_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf);
char *njt_conf_set_num_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf);
char *njt_conf_set_size_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf);
char *njt_conf_set_off_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf);
char *njt_conf_set_msec_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf);
char *njt_conf_set_sec_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf);
char *njt_conf_set_bufs_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf);
char *njt_conf_set_enum_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf);
char *njt_conf_set_bitmask_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf);
njt_int_t njt_conf_read_memory_token(njt_conf_t *cf,njt_str_t data);

#endif /* _NJT_CONF_FILE_H_INCLUDED_ */
