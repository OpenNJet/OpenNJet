/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */

#ifndef NJT_HTTP_EXT_MODULE_H_
#define NJT_HTTP_EXT_MODULE_H_

typedef enum
{
    ADD_NOTICE = 0,
    UPDATE_NOTICE,
    DELETE_NOTICE
} notice_op;
typedef void (*object_change_handler)(void *data);

struct njt_http_object_change_reg_info_s
{
    object_change_handler add_handler;
    object_change_handler update_handler;
    object_change_handler del_handler;
};

typedef struct njt_http_object_change_reg_info_s njt_http_object_change_reg_info_t;

typedef struct
{
    njt_http_object_change_reg_info_t callbacks;
    njt_queue_t queue;
} njt_http_object_change_handler_t;

typedef struct
{
    njt_str_t key;
    njt_queue_t handler_queue;
} object_change_hash_data_t;

njt_int_t njt_http_object_register_notice(njt_str_t *key, njt_http_object_change_reg_info_t *handler);
void njt_http_object_dispatch_notice(njt_str_t *key, notice_op op, void *object_data);
#endif // NJT_HTTP_EXT_MODULE_H_