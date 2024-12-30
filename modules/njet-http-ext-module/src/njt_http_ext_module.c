
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_http_ext_module.h>
#include <njt_hash_util.h>

static void *njt_http_ext_create_main_conf(njt_conf_t *cf);
//static njt_int_t njt_http_ext_init(njt_conf_t *cf);
static void njt_http_ext_exit_worker(njt_cycle_t *cycle);

typedef struct
{
    njt_lvlhash_map_t *njt_http_notice_hashmap;
    njt_array_t hash_keys;
} njt_http_ext_main_conf_t;

static njt_command_t njt_http_ext_commands[] = {
    njt_null_command};

static njt_http_module_t njt_http_ext_module_ctx = {
    NULL,              /* preconfiguration */
    NULL,//njt_http_ext_init, /* postconfiguration */

    njt_http_ext_create_main_conf, /* create main configuration */
    NULL,                          /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    NULL, /* create location configuration */
    NULL  /* merge location configuration */
};

njt_module_t njt_http_ext_module = {
    NJT_MODULE_V1,
    &njt_http_ext_module_ctx,  /* module context */
    njt_http_ext_commands,     /* module directives */
    NJT_HTTP_MODULE,           /* module type */
    NULL,                      /* init master */
    NULL,                      /* init module */
    NULL,                      /* init process */
    NULL,                      /* init thread */
    NULL,                      /* exit thread */
    &njt_http_ext_exit_worker, /* exit process */
    NULL,                      /* exit master */
    NJT_MODULE_V1_PADDING};

static void *
njt_http_ext_create_main_conf(njt_conf_t *cf)
{
    njt_http_ext_main_conf_t *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_ext_main_conf_t));
    if (conf == NULL)
    {
        return NULL;
    }
    njt_array_init(&conf->hash_keys, cf->pool, 1, sizeof(njt_str_t *));
    conf->njt_http_notice_hashmap = njt_pcalloc(cf->pool, sizeof(njt_lvlhash_map_t));
    if (conf->njt_http_notice_hashmap == NULL)
    {
        return NULL;
    }
    return conf;
}

/*static njt_int_t
njt_http_ext_init(njt_conf_t *cf)
{
    return NJT_OK;
}*/

njt_int_t njt_http_object_register_notice(njt_str_t *key, njt_http_object_change_reg_info_t *handler)
{
    njt_http_ext_main_conf_t *mcf;
    njt_int_t rc;
    njt_str_t **name;
    object_change_hash_data_t *hash_data = NULL, *old_hash_data;
    njt_http_object_change_handler_t *object_handler;
    mcf = njt_http_cycle_get_module_main_conf(njt_cycle, njt_http_ext_module);
    if (mcf && mcf->njt_http_notice_hashmap)
    {

        rc = njt_lvlhsh_map_get(mcf->njt_http_notice_hashmap, key, (intptr_t *)&hash_data);
        if (rc != NJT_OK)
        {
            hash_data = njt_pcalloc(njt_cycle->pool, sizeof(object_change_hash_data_t));
            if (hash_data == NULL)
            {
                return NJT_ERROR;
            }
            njt_queue_init(&hash_data->handler_queue);
            hash_data->key.len = key->len;
            hash_data->key.data = njt_pcalloc(njt_cycle->pool, key->len);
            if (hash_data->key.data == NULL)
            {
                return NJT_ERROR;
            }
            njt_memcpy(hash_data->key.data, key->data, key->len);
            name = njt_array_push(&mcf->hash_keys);
            *name = &hash_data->key;
            njt_lvlhsh_map_put(mcf->njt_http_notice_hashmap, &hash_data->key, (intptr_t)hash_data, (intptr_t *)&old_hash_data);
            if (old_hash_data && old_hash_data != hash_data)
            {
                return NJT_ERROR;
            }
        }
        if (hash_data != NULL)
        {
            object_handler = njt_pcalloc(njt_cycle->pool, sizeof(njt_http_object_change_handler_t));
            if (object_handler == NULL)
            {
                return NJT_ERROR;
            }
            object_handler->callbacks.add_handler = handler->add_handler;
            object_handler->callbacks.update_handler = handler->update_handler;
            object_handler->callbacks.del_handler = handler->del_handler;
            njt_queue_insert_tail(&hash_data->handler_queue, &object_handler->queue);
        }
    }
    return NJT_OK;
}
void njt_http_object_dispatch_notice(njt_str_t *key, notice_op op, void *object_data)
{
    njt_queue_t *q;
    njt_http_ext_main_conf_t *mcf;
    njt_int_t rc;
    njt_http_object_change_handler_t *handler;
    object_change_hash_data_t *hash_data = NULL;
    mcf = njt_http_cycle_get_module_main_conf(njt_cycle, njt_http_ext_module);
    if (mcf && mcf->njt_http_notice_hashmap)
    {
        rc = njt_lvlhsh_map_get(mcf->njt_http_notice_hashmap, key, (intptr_t *)&hash_data);
        if (rc == NJT_OK && hash_data != NULL)
        {
            q = njt_queue_head(&hash_data->handler_queue);
            while (q != njt_queue_sentinel(&hash_data->handler_queue))
            {
                handler = njt_queue_data(q, njt_http_object_change_handler_t, queue);
                q = njt_queue_next(q);
                if (op == ADD_NOTICE && handler->callbacks.add_handler)
                {
                    handler->callbacks.add_handler(object_data);
                }
                else if (op == UPDATE_NOTICE && handler->callbacks.update_handler)
                {
                    handler->callbacks.update_handler(object_data);
                }
                else if (op == DELETE_NOTICE && handler->callbacks.del_handler)
                {
                    handler->callbacks.del_handler(object_data);
                }
            }
        }
    }
}

static void njt_http_ext_exit_worker(njt_cycle_t *cycle)
{
    njt_http_ext_main_conf_t *mcf;
    njt_uint_t i;
    njt_str_t **arr;
    mcf = njt_http_cycle_get_module_main_conf(cycle, njt_http_ext_module);
    if (mcf && mcf->njt_http_notice_hashmap)
    {
        arr = mcf->hash_keys.elts;
        for (i = 0; i < mcf->hash_keys.nelts; i++)
        {
            njt_lvlhsh_map_remove(mcf->njt_http_notice_hashmap, arr[i]);
        }
    }
}
