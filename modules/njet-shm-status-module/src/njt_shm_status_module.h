/*
 * Copyright (C) 2021-2025 TMLake(Beijing) Technology Co., Ltd.
 */

#ifndef NJT_SHM_STATUS_H_
#define NJT_SHM_STATUS_H_

#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


#define NJT_SHM_STATUS_STATIC   0
#define NJT_SHM_STATUS_DYNAMIC  1

#define NJT_SHM_STATUS_TIMER_INTERVAL 500


typedef struct {
    njt_str_t    name;
    ssize_t      size; // 
    njt_uint_t   pool_count;
    njt_uint_t   total_pages;
    njt_uint_t   used_pages;
    njt_queue_t  queue;
    njt_queue_t  pools; // queue for slab pool
    njt_uint_t   dyn:1;
    njt_uint_t   del:1;
    njt_uint_t   autoscale:1;
} njt_shm_status_zone_record_t;

typedef struct {
    njt_uint_t used;
    njt_uint_t free;
    njt_uint_t reqs;
    njt_uint_t fails;
} njt_shm_status_slot_rec_t;

typedef struct {
    njt_uint_t                      total_pages;
    njt_uint_t                      used_pages;
    njt_shm_status_slot_rec_t       slots[9];

    njt_shm_status_zone_record_t   *parent;
    njt_queue_t                     queue;
} njt_shm_status_slab_record_t;

typedef struct {
    njt_shm_status_slab_record_t  *rec;
    njt_uint_t                     slot;
    njt_uint_t                     pages;
    njt_uint_t                     failed:1;
    njt_uint_t                     alloc:1;
    njt_uint_t                     top:1;
    
} njt_shm_status_slab_update_item_t;

typedef struct {
    njt_flag_t                         on;
    njt_shm_zone_t                     zone;
    njt_shm_status_slab_update_item_t  upds[100];
    njt_int_t                          count;
    njt_event_t                        update_timer;
} njt_shm_status_conf_t;

typedef struct {
    njt_uint_t                    total_zone_counts;
    njt_uint_t                    total_static_zone_counts;
    njt_uint_t                    total_static_zone_pool_counts;
    njt_uint_t                    total_static_zone_pages;
    njt_uint_t                    total_static_zone_used_pages;
    njt_uint_t                    total_dyn_pages;
    njt_uint_t                    total_used_dyn_pages;
    njt_uint_t                    total_dyn_zone_counts;
    njt_uint_t                    total_dyn_zone_pool_counts;
    njt_uint_t                    total_dyn_zone_pages;
    njt_uint_t                    total_dyn_zone_used_pages;
    njt_queue_t  zones;
    njt_queue_t  dyn_zones;
} njt_shm_status_summary_t;

typedef njt_int_t (*shm_status_update_fp)(void *ctx);

#define NJT_SHM_STATIC_ZONE  0
#define NJT_SHM_DYNAMIC_ZONE 1

typedef struct {
    njt_slab_pool_t               *shpool;
    njt_shm_status_summary_t      *summary;
} njt_shm_status_ctx_t;

njt_int_t njt_shm_status_add_zone_record(njt_str_t *name, ssize_t size, njt_uint_t dyn, void **ptr);
njt_int_t njt_shm_status_add_pool_record(void *first_rec, ssize_t size, njt_uint_t dyn, void **ptr);
njt_int_t njt_shm_status_add_main_pool(njt_slab_pool_t *pool);
njt_int_t njt_shm_status_rm_main_pool(njt_slab_pool_t *pool);
void njt_shm_status_update_alloc_item(njt_shm_status_slab_update_item_t *item);
njt_int_t njt_shm_status_rm_zone_record(njt_slab_pool_t *pool);
njt_int_t njt_shm_status_mark_zone_delete(njt_slab_pool_t *pool);
njt_int_t njt_shm_status_mark_zone_autoscale(njt_slab_pool_t *pool);
njt_int_t njt_shm_status_init_all_zones(njt_cycle_t *cycle);
void njt_shm_status_update_pool_record(njt_shm_status_slab_update_item_t *upd); // todo set to batch later
void njt_shm_status_update_records(njt_shm_status_conf_t *conf);
void njt_shm_status_print_all(); // for test only
void njt_shm_status_add_batch_update_timer(njt_cycle_t *cycle);
void njt_shm_status_exit_process(njt_cycle_t *cycle);
extern njt_shm_status_summary_t *njt_shm_status_summary;
extern njt_module_t  njt_shm_status_module;
#endif // NJT_SHM_STATUS_H_


