/*
 * Copyright (C) 2021-2025 TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>

#include "njt_shm_status_module.h"


static njt_int_t njt_shm_status_batch_update_on;
/*
 * slot 8    newpage  free 504;
 * slot 16   newpage  free 254;
 * slot 32   newpage  free 127;
 * slot 64   newpage  free 64;
 * slot 128  newpage  free 32;
 * slot 256  newpage  free 16;
 * slot 512  newpage  free 8;
 * slot 1024 newpage  free 4;
 * slot 2048 newpage  free 2;
 */
njt_uint_t njt_shm_status_slot_free[9] = {
    504,
    254,
    127,
    64,
    32,
    16,
    8,
    4,
    2 };

static void *njt_shm_status_create_conf(njt_cycle_t *cycle);
static char *njt_shm_status_init_conf(njt_cycle_t *cycle, void *conf);

static njt_int_t njt_shm_status_init_zone(njt_shm_zone_t *shm_zone, void *data);
static njt_int_t njt_shm_status_init_zone_record(njt_shm_status_zone_record_t *rec, njt_str_t *name, ssize_t size, njt_uint_t dyn);
static void njt_shm_status_init_pool_record(njt_shm_status_slab_record_t *rec, ssize_t size, njt_uint_t dyn);
// static njt_int_t njt_shm_status_add_pool_record(void *first_rec, ssize_t size, njt_uint_t dyn, void **ptr);
static void njt_shm_status_update_pool_record_locked(njt_shm_status_slab_update_item_t *upd);
void njt_shm_status_rm_zone_record_locked(njt_shm_status_slab_record_t *rec);
static void njt_shm_status_update_pool_stats(njt_shm_status_slab_record_t *rec, njt_slab_pool_t *pool);

njt_shm_status_summary_t *njt_shm_status_summary = NULL;
njt_slab_pool_t *njt_shm_status_pool = NULL;
njt_shm_status_conf_t *shm_status_conf = NULL;

static njt_command_t njt_shm_status_commands[] = {
    {njt_string("shm_status"),
     NJT_MAIN_CONF |NJT_DIRECT_CONF| NJT_CONF_TAKE1234,
     njt_conf_set_flag_slot,
     0,
     offsetof(njt_shm_status_conf_t, on),
     NULL},

    njt_null_command /* command termination */
};


static njt_core_module_t njt_shm_status_module_ctx = {
    njt_string("shm_status"),
    njt_shm_status_create_conf,
    njt_shm_status_init_conf
};

njt_module_t njt_shm_status_module = {
    NJT_MODULE_V1,
    &njt_shm_status_module_ctx,  /* module context */
    njt_shm_status_commands,     /* module directives */
    NJT_CORE_MODULE,             /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    njt_shm_status_exit_process,           /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};



static void*
njt_shm_status_create_conf(njt_cycle_t *cycle)
{
    njt_shm_status_conf_t  *conf;

    conf = njt_pcalloc(cycle->pool, sizeof(njt_shm_status_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->on = NJT_CONF_UNSET;
    // TODO

    return conf;
}


void
njt_shm_status_update_handler(njt_event_t *ev)
{
    njt_shm_status_conf_t   *sscf;

    sscf = (njt_shm_status_conf_t *)ev->data;
    njt_shm_status_update_records(sscf);
    if (!njt_exiting && !njt_quit && !njt_terminate) {
        njt_add_timer(&sscf->update_timer, NJT_SHM_STATUS_TIMER_INTERVAL);
    }
}


void
njt_shm_status_add_batch_update_timer(njt_cycle_t *cycle)
{
    njt_shm_status_conf_t     *conf;

    if (njt_shm_status_summary == NULL) {
        return;
    }

    conf = (void *)njt_get_conf(cycle->conf_ctx, njt_shm_status_module);
    njt_add_timer(&conf->update_timer, NJT_SHM_STATUS_TIMER_INTERVAL);
    njt_shm_status_batch_update_on = 1;
}


void
njt_shm_status_exit_process(njt_cycle_t *cycle)
{
    njt_shm_status_conf_t     *conf;

    conf = (void *)njt_get_conf(cycle->conf_ctx, njt_shm_status_module);
    njt_shm_status_update_records(conf);
    if (conf->update_timer.timer_set) {
        njt_del_timer(&conf->update_timer);
    }

}


static char*
njt_shm_status_init_conf(njt_cycle_t *cycle, void *cf)
{
    njt_str_t               name;
    ssize_t                 size;
    njt_conf_t             *conf;
    njt_shm_status_conf_t  *sscf;
    njt_shm_zone_t         *zone;


    conf = (njt_conf_t *)cf;
    if (conf->cycle == NULL) {
        conf->cycle = cycle;
    }

    sscf = (njt_shm_status_conf_t *)njt_get_conf(conf->cycle->conf_ctx, njt_shm_status_module);

    if (njt_shm_status_pool != NULL && sscf->on == 0) {
        return "shm_status cannot be set on->off during reload";
    }

    njt_conf_init_value(sscf->on, 1);

    if(sscf->on == 0) {
        return NJT_OK;
    }
    
    njt_str_set(&name, "njt_shm_status");
    size = 10 * 1024 * 1024; // 10M is enough for <= 4k dyn zones in most time
    zone = njt_shared_memory_add(cf, &name, size, &njt_shm_status_module);
    if (zone == NULL) {
        return NJT_CONF_ERROR;
    }

    zone->init = njt_shm_status_init_zone;

    sscf->update_timer.data = sscf;
    sscf->update_timer.handler = njt_shm_status_update_handler;
    shm_status_conf = sscf;

    return NJT_CONF_OK;
}


static njt_int_t
njt_shm_status_init_zone(njt_shm_zone_t *shm_zone, void *data)
{
    njt_shm_status_summary_t *summary;

    if (njt_shm_status_summary || njt_process == NJT_PROCESS_HELPER) {
        return NJT_OK; // only work in master cycle
    }

    njt_shm_status_pool = (njt_slab_pool_t *)shm_zone->shm.addr;
    summary = njt_slab_calloc(njt_shm_status_pool, sizeof(njt_shm_status_summary_t));
    if (!summary) {
        return NJT_ERROR;
    }

    njt_shm_status_summary = summary;
    njt_queue_init(&summary->zones); // init zones queue
    njt_queue_init(&summary->dyn_zones); // init dyn zone queue

    return NJT_OK;
}


static njt_int_t
njt_shm_status_reload_all_zones(njt_cycle_t *cycle)
{
    njt_uint_t                    i, find;
    njt_list_part_t              *part;
    njt_shm_zone_t               *shm_zone;
    njt_str_t                    *name;
    size_t                        size;
    njt_slab_pool_t              *shpool;
    njt_share_slab_pool_node_t   *node;
    njt_queue_t                  *head, *q;
    njt_queue_t                  *zhead, *zq;
    njt_shm_status_zone_record_t *zone_rec;

    part = &cycle->shared_memory.part;
    shm_zone = part->elts;

    head = &njt_shm_status_summary->zones;
    // list all static zones
    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            shm_zone = part->elts;
            i = 0;
        }

        name = &shm_zone[i].shm.name;
        if (name->len == 14
            && njt_strncmp("njt_shm_status", name->data, 14) == 0)
        {
            continue; // donot add status for shm_status zone
        }

        q = head->next;
        find = 0;
        while (q != head) {
            zone_rec = (njt_shm_status_zone_record_t *)njt_queue_data(q, njt_shm_status_zone_record_t, queue);
            if (name->len == zone_rec->name.len
                && njt_strncmp(name->data, zone_rec->name.data, name->len) == 0)
            {
                find = 1;
                break;
            }
            q = q->next;
        }

        if (find) {
            continue;
        }

        size = shm_zone[i].shm.size;
        shpool = (njt_slab_pool_t *)shm_zone[i].shm.addr;
        if ( njt_shm_status_add_zone_record(name, size, NJT_SHM_STATUS_STATIC, &shpool->status_rec) != NJT_OK) {
            return NJT_ERROR;
        }
        njt_shm_status_update_pool_stats(shpool->status_rec, shpool);
    }

    // list all dynamic zones
    if (njt_shared_slab_header == NULL) {
        return NJT_OK;
    }

    njt_shmtx_lock(&njt_shared_slab_header->mutex);
    if (cycle->shared_slab.header == NULL) {
        njt_shmtx_unlock(&njt_shared_slab_header->mutex);
        return NJT_OK;
    }

    head = &njt_shm_status_summary->dyn_zones;
    zhead = &cycle->shared_slab.queues_header->zones;
    zq = njt_queue_next(zhead);
    while (zq != zhead) {
        node = (njt_share_slab_pool_node_t *)njt_queue_data(zq, njt_share_slab_pool_node_t, queue);
        name = &node->name;
        size = node->size;
        shpool = node->pool;

        if (node->del) {
            goto found;
        }
        find = 0;
        q = head->next;
        while (q != head) {
            zone_rec = (njt_shm_status_zone_record_t *)njt_queue_data(q, njt_shm_status_zone_record_t, queue);
            if (name->len == zone_rec->name.len && !zone_rec->del
                && njt_strncmp(name->data, zone_rec->name.data, name->len) == 0) {
                find = 1;
                break;;

            }
            q = q->next;
        }

        if (!find && njt_shm_status_add_zone_record(name, size, NJT_SHM_STATUS_DYNAMIC, &shpool->status_rec) != NJT_OK) {
            njt_shmtx_unlock(&njt_shared_slab_header->mutex);
            return NJT_OK; // no memory in shm_status zone
        }
        njt_shm_status_update_pool_stats(shpool->status_rec, shpool);

found:
        zq = njt_queue_next(zq);
    }
    njt_shmtx_unlock(&njt_shared_slab_header->mutex);
    return NJT_OK;
}


njt_int_t
njt_shm_status_init_all_zones(njt_cycle_t *cycle)
{
    njt_uint_t                   i, reload;
    njt_list_part_t              *part;
    njt_shm_zone_t               *shm_zone;
    njt_str_t                    *name;
    size_t                        size;
    njt_slab_pool_t              *shpool;
    njt_share_slab_pool_node_t   *node;
    njt_queue_t                  *head, *q;

    if (njt_shm_status_pool == 0 || cycle->shared_memory.part.nelts == 0) {
        return NJT_OK;
    }

    reload = njt_shm_status_summary->total_zone_counts != 0;
    if (reload) {
        return njt_shm_status_reload_all_zones(cycle);
    }


    part = &cycle->shared_memory.part;
    shm_zone = part->elts;

    // list all static zones
    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            shm_zone = part->elts;
            i = 0;
        }

        if (shm_zone[i].shm.name.len == 14
            && njt_strncmp("njt_shm_status", shm_zone[i].shm.name.data, 14) == 0)
        {
            continue; // donot add status for shm_status zone
        }

        name = &shm_zone[i].shm.name;
        size = shm_zone[i].shm.size;
        shpool = (njt_slab_pool_t *)shm_zone[i].shm.addr;

        if (njt_shm_status_add_zone_record(name, size, NJT_SHM_STATUS_STATIC, &shpool->status_rec) != NJT_OK) {
            return NJT_ERROR;
        }
        njt_shm_status_update_pool_stats(shpool->status_rec, shpool);
        // njt_shm_status_print_all();
    }

    // list all dynamic zones
    shpool = cycle->shared_slab.header;
    if (shpool == NULL) {
        return NJT_OK;
    }

    while (shpool) {
        njt_shm_status_add_main_pool(shpool);
        shpool = shpool->next;
    }

    head = &cycle->shared_slab.queues_header->zones;
    q = njt_queue_next(head);
    while (q != head) {
        node = (njt_share_slab_pool_node_t *)njt_queue_data(q, njt_share_slab_pool_node_t, queue);
        name = &node->name;
        size = node->size;
        shpool = node->pool;

        if (!node->del && njt_shm_status_add_zone_record(name, size, NJT_SHM_STATUS_DYNAMIC, &shpool->status_rec) != NJT_OK) {
            return NJT_ERROR;
        }
        njt_shm_status_update_pool_stats(shpool->status_rec, shpool);
        q = njt_queue_next(q);
    }

    return NJT_OK;
}


static void
njt_shm_status_init_pool_record(njt_shm_status_slab_record_t *rec, ssize_t size, njt_uint_t dyn)
{
    size_t real_size;

    real_size = size - sizeof(njt_slab_pool_t);
    real_size -= (njt_pagesize_shift - 3) * (sizeof(njt_slab_page_t) + sizeof(njt_slab_stat_t)); // 3 is pool->min_shift
    rec->total_pages = (njt_uint_t) ( real_size / (njt_pagesize + sizeof(njt_slab_page_t)));
    rec->used_pages = 0;

    rec->parent->total_pages += rec->total_pages;
    rec->parent->pool_count ++;

    if (dyn) {
        njt_shm_status_summary->total_used_dyn_pages += (njt_uint_t) ( (size + njt_pagesize - 1) / njt_pagesize);
    }
    if (rec->parent->dyn) {
        njt_shm_status_summary->total_dyn_zone_pages += rec->total_pages;
        njt_shm_status_summary->total_dyn_zone_pool_counts ++;
    } else {
        njt_shm_status_summary->total_static_zone_pages += rec->total_pages;
        njt_shm_status_summary->total_static_zone_pool_counts ++;
    }
}


static void
njt_shm_status_update_pool_stats(njt_shm_status_slab_record_t *rec, njt_slab_pool_t *pool)
{
    njt_slab_pool_t               *cur;
    njt_shm_status_slab_record_t  *slab_rec, *cur_rec;
    njt_uint_t                     i;

    if (pool->first != pool) {
        return; // only update for the first pool of a shm_zone
    }

    rec->parent->autoscale = pool->auto_scale;
    rec->parent->used_pages = 0;
    cur = pool;
    cur_rec = rec;
    while (cur) {
        if (cur != pool) {
            slab_rec = njt_slab_calloc_locked(njt_shm_status_pool, sizeof(njt_shm_status_slab_record_t));
            if (slab_rec == NULL) {
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "no memory in njt_shm_status zone");
                return;
            }
            cur->status_rec = slab_rec;
            njt_queue_insert_tail(&rec->parent->pools, &slab_rec->queue);
            slab_rec->parent = rec->parent;
            njt_shm_status_init_pool_record(slab_rec, slab_rec->parent->size, NJT_SHM_STATUS_DYNAMIC);
            cur_rec = slab_rec;
        }
        for (i = 0; i < 9; i++) {
            cur_rec->slots[i].free = cur->stats[i].total - cur->stats[i].used;
            cur_rec->slots[i].used = cur->stats[i].used;
            cur_rec->slots[i].reqs = cur->stats[i].reqs;
            cur_rec->slots[i].fails = cur->stats[i].fails;
        }

        cur_rec->used_pages = cur_rec->total_pages - cur->pfree;
        cur_rec->parent->used_pages += cur_rec->used_pages;
        if (rec->parent->dyn) {
            njt_shm_status_summary->total_dyn_zone_used_pages += cur_rec->used_pages;
        } else {
            njt_shm_status_summary->total_static_zone_used_pages += cur_rec->used_pages;
        }
        cur = cur->next;
    }
}


static njt_int_t
njt_shm_status_init_zone_record(njt_shm_status_zone_record_t *rec, njt_str_t *name, ssize_t size, njt_uint_t dyn)
{

    rec->name.data = njt_slab_alloc_locked(njt_shm_status_pool, name->len);
    if (rec->name.data == NULL) {
        return NJT_ERROR;
    }
    rec->name.len = name->len;
    rec->size = size;
    rec->dyn = dyn;

    njt_memcpy(rec->name.data, name->data, name->len);
    njt_shm_status_summary->total_zone_counts ++;
    if (dyn) {
        njt_shm_status_summary->total_dyn_zone_counts ++;
    } else {
        njt_shm_status_summary->total_static_zone_counts ++;
    }

    return NJT_OK;
}

njt_int_t
njt_shm_status_add_zone_record(njt_str_t *name, ssize_t size, njt_uint_t dyn, void **ptr)
{

    njt_shm_status_zone_record_t *zone_rec;
    njt_shm_status_slab_record_t *slab_rec;
    njt_shm_status_summary_t     *summary;

    summary = njt_shm_status_summary;

    njt_shmtx_lock(&njt_shm_status_pool->mutex);
    zone_rec = njt_slab_calloc_locked(njt_shm_status_pool, sizeof(njt_shm_status_zone_record_t));
    if (zone_rec == NULL) {
        goto failed;
    }
    if (dyn) {
        njt_queue_insert_tail(&summary->dyn_zones, &zone_rec->queue);
    } else {
        njt_queue_insert_tail(&summary->zones, &zone_rec->queue);
    }
    if (njt_shm_status_init_zone_record(zone_rec, name, size, dyn) != NJT_OK) {
        goto failed;
    }

    njt_queue_init(&zone_rec->pools);
    // add first slab_pool record
    slab_rec = njt_slab_calloc_locked(njt_shm_status_pool, sizeof(njt_shm_status_slab_record_t));
    if (slab_rec == NULL) {
        njt_queue_remove(&zone_rec->queue);
        goto failed;
    }
    *ptr = slab_rec;
    njt_queue_insert_tail(&zone_rec->pools, &slab_rec->queue);
    slab_rec->parent = zone_rec;
    njt_shm_status_init_pool_record(slab_rec, size, dyn);

    njt_shmtx_unlock(&njt_shm_status_pool->mutex);
    return NJT_OK;

failed:
    njt_shmtx_unlock(&njt_shm_status_pool->mutex);
    *ptr = NULL;
    return NJT_ERROR;
}


njt_int_t
njt_shm_status_add_pool_record(void *first_rec, ssize_t size, njt_uint_t dyn, void **ptr)
{
    njt_shm_status_slab_record_t *first;
    njt_shm_status_slab_record_t *rec;

    first = (njt_shm_status_slab_record_t *)first_rec;
    njt_shmtx_lock(&njt_shm_status_pool->mutex);
    rec = njt_slab_calloc_locked(njt_shm_status_pool, sizeof(njt_shm_status_slab_record_t));
    if (rec == NULL) {
        goto failed;
    }
    *ptr = rec;
    rec->parent = first->parent;
    njt_shm_status_init_pool_record(rec, size, dyn);
    njt_queue_insert_tail(&first->parent->pools, &rec->queue);

    njt_shmtx_unlock(&njt_shm_status_pool->mutex);
    return NJT_OK;


failed:
    njt_shmtx_unlock(&njt_shm_status_pool->mutex);
    *ptr = NULL;
    return NJT_ERROR;
}


void
njt_shm_status_update_pool_record(njt_shm_status_slab_update_item_t *upd)
{
    if (njt_shm_status_batch_update_on) {
        njt_memcpy(&shm_status_conf->upds[shm_status_conf->count],
                    upd, sizeof(njt_shm_status_slab_update_item_t));
        shm_status_conf->count++;
        if (shm_status_conf->count >= 99) {
            njt_shm_status_update_records(shm_status_conf);
        }

        return;
    } 

    // for helper process not set timer, update each time
    njt_shmtx_lock(&njt_shm_status_pool->mutex);
    njt_shm_status_update_pool_record_locked(upd);
    njt_shmtx_unlock(&njt_shm_status_pool->mutex);
}


void
njt_shm_status_update_records(njt_shm_status_conf_t *conf)
{
    njt_int_t                          i;
    njt_shm_status_slab_update_item_t  upd;

    if (conf->count) {
        njt_shmtx_lock(&njt_shm_status_pool->mutex);
        for (i = 0; i < conf->count; i++) {
            upd = conf->upds[i];
            njt_shm_status_update_pool_record_locked(&upd);
        }
        njt_shmtx_unlock(&njt_shm_status_pool->mutex);
    }
    conf->count = 0;
}

static void
njt_shm_status_update_pool_record_locked(njt_shm_status_slab_update_item_t *upd)
{
    njt_shm_status_slab_record_t  *rec;
    njt_shm_status_slot_rec_t     *slot;
    njt_shm_status_zone_record_t  *zone;

    rec = upd->rec;
    zone = rec->parent;

    if (upd->slot) {
        slot = &rec->slots[upd->slot - 3];
        if (upd->alloc) {
            slot->reqs ++;
            if (upd->failed) {
                slot->fails ++;
            } else {
                slot->used ++;
                if (upd->pages) {
                    slot->free += njt_shm_status_slot_free[upd->slot-3];
                    rec->used_pages ++; 
                    zone->used_pages ++;
                    if(zone->dyn) {
                        njt_shm_status_summary->total_dyn_zone_used_pages ++; 
                    } else {
                        njt_shm_status_summary->total_static_zone_used_pages ++;
                    } 
                }
                slot->free --;
            } 
        } else { // never failed
            slot->used --;
            slot->free ++;
            if (upd->pages) {
                slot->free -= njt_shm_status_slot_free[upd->slot-3];
                rec->used_pages --; 
                zone->used_pages --;
                if(zone->dyn) {
                    njt_shm_status_summary->total_dyn_zone_used_pages --;
                } else {
                    njt_shm_status_summary->total_static_zone_used_pages --;
                }
            }
        }
    } else {
        if (upd->alloc) {
            if (!upd->failed) {
                rec->used_pages += upd->pages;
                zone->used_pages += upd->pages;
                if(!zone->dyn) {
                    njt_shm_status_summary->total_static_zone_used_pages += upd->pages;
                } else {
                    njt_shm_status_summary->total_dyn_zone_used_pages += upd->pages;
                }
            }
        } else {
            rec->used_pages -= upd->pages; 
            zone->used_pages -= upd->pages;
            if (zone->dyn) {
                njt_shm_status_summary->total_dyn_zone_used_pages -= upd->pages;
            } else {
                njt_shm_status_summary->total_static_zone_used_pages -= upd->pages;
            }
        }
    }

}


void
njt_shm_status_rm_zone_record_locked(njt_shm_status_slab_record_t *rec)
{
    njt_shm_status_zone_record_t *zone_rec;
    njt_shm_status_slab_record_t *slab_rec;
    njt_queue_t                  *head, *cur;

    zone_rec = rec->parent;
    head = &rec->parent->pools;
    cur = &rec->queue; // head->next
    while (cur != head) {
        slab_rec = njt_queue_data(cur, njt_shm_status_slab_record_t, queue);
        cur = njt_queue_next(cur);
        njt_slab_free_locked(njt_shm_status_pool, slab_rec);
    }
    // njt_slab_free_locked(njt_shm_status_pool, rec); double free

    njt_shm_status_summary->total_zone_counts --;
    if (zone_rec->dyn) {
        njt_shm_status_summary->total_dyn_zone_counts --;
        njt_shm_status_summary->total_dyn_zone_pool_counts -= zone_rec->pool_count;
        njt_shm_status_summary->total_dyn_zone_pages -= zone_rec->total_pages;
        njt_shm_status_summary->total_dyn_zone_used_pages -= zone_rec->used_pages;
        njt_shm_status_summary->total_used_dyn_pages -= (zone_rec->size * zone_rec->pool_count)/njt_pagesize;
    } else {
        njt_shm_status_summary->total_static_zone_counts --;
        njt_shm_status_summary->total_static_zone_pool_counts -= zone_rec->pool_count;
        njt_shm_status_summary->total_static_zone_pages -= zone_rec->total_pages;
        njt_shm_status_summary->total_static_zone_used_pages -= zone_rec->used_pages;
    }
    njt_queue_remove(&zone_rec->queue);
    njt_slab_free_locked(njt_shm_status_pool, zone_rec);
}


njt_int_t
njt_shm_status_rm_zone_record(njt_slab_pool_t *pool)
{
    njt_shm_status_slab_record_t *rec;

    rec = pool->status_rec;
    if (rec == NULL) {
        return NJT_OK;
    }

    njt_shmtx_lock(&njt_shm_status_pool->mutex);
    njt_shm_status_rm_zone_record_locked(rec);
    njt_shmtx_unlock(&njt_shm_status_pool->mutex);

    return NJT_OK;
}


njt_int_t
njt_shm_status_makr_zone_delete(njt_slab_pool_t *pool)
{
    njt_shm_status_slab_record_t *rec;
    njt_shm_status_zone_record_t *zone_rec;

    rec = pool->status_rec;
    if (rec == NULL) {
        return NJT_OK;
    }
    njt_shmtx_lock(&njt_shm_status_pool->mutex);
    zone_rec = rec->parent;
    zone_rec->del = 1;
    njt_shmtx_unlock(&njt_shm_status_pool->mutex);
    return NJT_OK;
}

njt_int_t
njt_shm_status_add_main_pool(njt_slab_pool_t *pool)
{
    size_t      real_size, size;
    njt_uint_t  pages;
    size = pool->end - (u_char *)pool;

    real_size = size - sizeof(njt_slab_pool_t);
    real_size -= (njt_pagesize_shift - 3) * (sizeof(njt_slab_page_t) + sizeof(njt_slab_stat_t)); // 3 is pool->min_shift
    pages = (njt_uint_t) ( real_size / (njt_pagesize + sizeof(njt_slab_page_t)));

    njt_shmtx_lock(&njt_shm_status_pool->mutex);
    njt_shm_status_summary->total_dyn_pages += pages; 
    njt_shmtx_unlock(&njt_shm_status_pool->mutex);
    return NJT_OK;
}


njt_int_t
njt_shm_status_rm_main_pool(njt_slab_pool_t *pool)
{
    size_t      real_size, size;
    njt_uint_t  pages;
    size = pool->end - (u_char *)pool;

    real_size = size - sizeof(njt_slab_pool_t);
    real_size -= (njt_pagesize_shift - 3) * (sizeof(njt_slab_page_t) + sizeof(njt_slab_stat_t)); // 3 is pool->min_shift
    pages = (njt_uint_t) ( real_size / (njt_pagesize + sizeof(njt_slab_page_t)));

    njt_shmtx_lock(&njt_shm_status_pool->mutex);
    njt_shm_status_summary->total_dyn_pages -= pages;
    njt_shmtx_unlock(&njt_shm_status_pool->mutex);
    return NJT_OK;
}


njt_int_t
njt_shm_status_mark_zone_delete(njt_slab_pool_t *pool)
{
    njt_shm_status_slab_record_t *pool_rec;

    pool_rec = (njt_shm_status_slab_record_t *)pool->status_rec;
    if (pool_rec == NULL) {
        return NJT_OK;
    }

    njt_shmtx_lock(&njt_shm_status_pool->mutex);
    pool_rec->parent->del = 1;
    njt_shmtx_unlock(&njt_shm_status_pool->mutex);

    return NJT_OK;
}


njt_int_t
njt_shm_status_mark_zone_autoscale(njt_slab_pool_t *pool)
{
    njt_shm_status_slab_record_t *pool_rec;

    pool_rec = (njt_shm_status_slab_record_t *)pool->status_rec;
    if (pool_rec == NULL) {
        return NJT_OK;
    }

    njt_shmtx_lock(&njt_shm_status_pool->mutex);
    pool_rec->parent->autoscale = pool->auto_scale;
    njt_shmtx_unlock(&njt_shm_status_pool->mutex);

    return NJT_OK;
}


void
njt_shm_status_update_alloc_item(njt_shm_status_slab_update_item_t *item)
{
    njt_shm_status_update_pool_record(item);
}


void
njt_shm_status_print_summary_locked()
{
    njt_shm_status_summary_t *summary = njt_shm_status_summary;
    fprintf(stderr,"\n summary :\n");
    fprintf(stderr,"total_zone_count: %ld, ", summary->total_zone_counts);
    fprintf(stderr,"total_static_zone_count: %ld, ", summary->total_static_zone_counts);
    fprintf(stderr,"total_static_zone_pool_counts: %ld, ", summary->total_static_zone_pool_counts);
    fprintf(stderr,"total_static_zone_pages: %ld, ", summary->total_static_zone_pages);
    fprintf(stderr,"total_static_zone_used_pages: %ld\n", summary->total_static_zone_used_pages);
    // todo dyn_zones
    fprintf(stderr,"total_dyn_pages: %ld, ", summary->total_dyn_pages);
    fprintf(stderr,"total_dyn_used_pages: %ld, ", summary->total_used_dyn_pages);
    fprintf(stderr,"total_dyn_zone_count: %ld, ", summary->total_dyn_zone_counts);
    fprintf(stderr,"total_dyn_zone_pool_count: %ld, ", summary->total_dyn_zone_pool_counts);
    fprintf(stderr,"total_dyn_zone_pages: %ld, ", summary->total_dyn_zone_pages);
    fprintf(stderr,"total_dyn_zone_used_pages: %ld\n", summary->total_dyn_zone_used_pages);
}


void
njt_shm_status_print_pool_slots_locked(njt_shm_status_slab_record_t *pool_rec)
{
    njt_int_t  i;
    njt_shm_status_slot_rec_t *slots;

    slots = pool_rec->slots;
    for (i = 0; i < 9; i++){
        fprintf(stderr,"\t\t slots_%d:, use %ld, free %ld, reqs %ld, fails %ld\n", 8 << i, slots[i].used, slots[i].free, slots[i].reqs, slots[i].fails);
    }

}

void
njt_shm_status_print_zone_locked(njt_shm_status_zone_record_t *zone_rec)
{
    njt_queue_t                   *head, *cur;
    njt_shm_status_slab_record_t  *pool;
    njt_int_t                      count;

    head = &zone_rec->pools;
    cur = njt_queue_next(head);

    fprintf(stderr,"  zone  name %s, size %ld, pool counts %ld, used_pages %ld, auto_scale %d ", 
            zone_rec->name.data, zone_rec->size, zone_rec->pool_count, zone_rec->used_pages, zone_rec->autoscale);
    if (zone_rec->dyn) {
        fprintf(stderr, " mark_delete %d\n", zone_rec->del);
    } else {
        fprintf(stderr, "\n");
    }

    count = 0;
    while (cur != head) {
        pool = njt_queue_data(cur, njt_shm_status_slab_record_t, queue);
        fprintf(stderr,"\t pool[%ld], total pages %ld, used pages %ld, slots later\n", count, pool->total_pages, pool->used_pages);
        njt_shm_status_print_pool_slots_locked(pool);
        cur = njt_queue_next(cur);
        count ++;
    }

}


void
njt_shm_status_print_static_zones_locked()
{
    fprintf(stderr,"zones: \n");
    njt_shm_status_summary_t      *summary = njt_shm_status_summary;
    njt_queue_t                   *head, *cur;
    njt_shm_status_zone_record_t  *zone_rec;

    head = &summary->zones;
    cur = njt_queue_next(head);

    while (cur != head) {
        zone_rec = njt_queue_data(cur, njt_shm_status_zone_record_t, queue);
        njt_shm_status_print_zone_locked(zone_rec);
        cur = njt_queue_next(cur);
    }

}


void
njt_shm_status_print_dyn_zones_locked()
{
    fprintf(stderr,"dyn zones: \n");
    njt_shm_status_summary_t      *summary = njt_shm_status_summary;
    njt_queue_t                   *head, *cur;
    njt_shm_status_zone_record_t  *zone_rec;

    head = &summary->dyn_zones;
    cur = njt_queue_next(head);

    while (cur != head) {
        zone_rec = njt_queue_data(cur, njt_shm_status_zone_record_t, queue);
        njt_shm_status_print_zone_locked(zone_rec);
        cur = njt_queue_next(cur);
    }

}


void
njt_shm_status_print_all()
{
    if (njt_shm_status_summary == NULL) {
        fprintf(stderr, "null summary\n");
        return;
    }
    njt_shmtx_lock(&njt_shm_status_pool->mutex);
    njt_shm_status_print_summary_locked();
    njt_shm_status_print_static_zones_locked();
    njt_shm_status_print_dyn_zones_locked();
    njt_shmtx_unlock(&njt_shm_status_pool->mutex);
}