
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_md5.h>


static njt_int_t njt_http_file_cache_lock(njt_http_request_t *r,
    njt_http_cache_t *c);
static void njt_http_file_cache_lock_wait_handler(njt_event_t *ev);
static void njt_http_file_cache_lock_wait(njt_http_request_t *r,
    njt_http_cache_t *c);
static njt_int_t njt_http_file_cache_read(njt_http_request_t *r,
    njt_http_cache_t *c);
static ssize_t njt_http_file_cache_aio_read(njt_http_request_t *r,
    njt_http_cache_t *c);
#if (NJT_HAVE_FILE_AIO)
static void njt_http_cache_aio_event_handler(njt_event_t *ev);
#endif
#if (NJT_THREADS)
static njt_int_t njt_http_cache_thread_handler(njt_thread_task_t *task,
    njt_file_t *file);
static void njt_http_cache_thread_event_handler(njt_event_t *ev);
#endif
static njt_int_t njt_http_file_cache_exists(njt_http_file_cache_t *cache,
    njt_http_cache_t *c);
static njt_int_t njt_http_file_cache_name(njt_http_request_t *r,
    njt_path_t *path);
static njt_http_file_cache_node_t *
    njt_http_file_cache_lookup(njt_http_file_cache_t *cache, u_char *key);
static void njt_http_file_cache_rbtree_insert_value(njt_rbtree_node_t *temp,
    njt_rbtree_node_t *node, njt_rbtree_node_t *sentinel);
static void njt_http_file_cache_vary(njt_http_request_t *r, u_char *vary,
    size_t len, u_char *hash);
static void njt_http_file_cache_vary_header(njt_http_request_t *r,
    njt_md5_t *md5, njt_str_t *name);
static njt_int_t njt_http_file_cache_reopen(njt_http_request_t *r,
    njt_http_cache_t *c);
static njt_int_t njt_http_file_cache_update_variant(njt_http_request_t *r,
    njt_http_cache_t *c);
static void njt_http_file_cache_cleanup(void *data);
static time_t njt_http_file_cache_forced_expire(njt_http_file_cache_t *cache);
static time_t njt_http_file_cache_expire(njt_http_file_cache_t *cache);
static void njt_http_file_cache_delete(njt_http_file_cache_t *cache,
    njt_queue_t *q, u_char *name);
static void njt_http_file_cache_loader_sleep(njt_http_file_cache_t *cache);
static njt_int_t njt_http_file_cache_noop(njt_tree_ctx_t *ctx,
    njt_str_t *path);
static njt_int_t njt_http_file_cache_manage_file(njt_tree_ctx_t *ctx,
    njt_str_t *path);
static njt_int_t njt_http_file_cache_manage_directory(njt_tree_ctx_t *ctx,
    njt_str_t *path);
static njt_int_t njt_http_file_cache_add_file(njt_tree_ctx_t *ctx,
    njt_str_t *path);
#if (NJT_HTTP_CACHE_PURGE)
static njt_int_t njt_http_file_cache_add(njt_http_file_cache_t *cache, njt_http_cache_t *c,njt_str_t* name);
#else
static njt_int_t njt_http_file_cache_add(njt_http_file_cache_t *cache,
    njt_http_cache_t *c);
#endif
static njt_int_t njt_http_file_cache_delete_file(njt_tree_ctx_t *ctx,
    njt_str_t *path);
static void njt_http_file_cache_set_watermark(njt_http_file_cache_t *cache);


njt_str_t  njt_http_cache_status[] = {
    njt_string("MISS"),
    njt_string("BYPASS"),
    njt_string("EXPIRED"),
    njt_string("STALE"),
    njt_string("UPDATING"),
    njt_string("REVALIDATED"),
    njt_string("HIT")
};


static u_char  njt_http_file_cache_key[] = { LF, 'K', 'E', 'Y', ':', ' ' };
// by chengxu
#if (NJT_HTTP_CACHE_PURGE)
static u_char  njt_http_file_key[] = { LF ,'F', 'I', 'L','E', ':', ' ' };
#endif
//end

static njt_int_t
njt_http_file_cache_init(njt_shm_zone_t *shm_zone, void *data)
{
    njt_http_file_cache_t  *ocache = data;

    size_t                  len;
    njt_uint_t              n;
    njt_http_file_cache_t  *cache;

    cache = shm_zone->data;

    if (ocache) {
        if (njt_strcmp(cache->path->name.data, ocache->path->name.data) != 0) {
            njt_log_error(NJT_LOG_EMERG, shm_zone->shm.log, 0,
                          "cache \"%V\" uses the \"%V\" cache path "
                          "while previously it used the \"%V\" cache path",
                          &shm_zone->shm.name, &cache->path->name,
                          &ocache->path->name);

            return NJT_ERROR;
        }

        for (n = 0; n < NJT_MAX_PATH_LEVEL; n++) {
            if (cache->path->level[n] != ocache->path->level[n]) {
                njt_log_error(NJT_LOG_EMERG, shm_zone->shm.log, 0,
                              "cache \"%V\" had previously different levels",
                              &shm_zone->shm.name);
                return NJT_ERROR;
            }
        }

        cache->sh = ocache->sh;

        cache->shpool = ocache->shpool;
        cache->bsize = ocache->bsize;

        cache->max_size /= cache->bsize;

        if (!cache->sh->cold || cache->sh->loading) {
            cache->path->loader = NULL;
        }

        return NJT_OK;
    }

    cache->shpool = (njt_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        cache->sh = cache->shpool->data;
        cache->bsize = njt_fs_bsize(cache->path->name.data);
        cache->max_size /= cache->bsize;

        return NJT_OK;
    }

    cache->sh = njt_slab_alloc(cache->shpool, sizeof(njt_http_file_cache_sh_t));
    if (cache->sh == NULL) {
        return NJT_ERROR;
    }

    cache->shpool->data = cache->sh;

    njt_rbtree_init(&cache->sh->rbtree, &cache->sh->sentinel,
                    njt_http_file_cache_rbtree_insert_value);

    njt_queue_init(&cache->sh->queue);

    cache->sh->cold = 1;
    cache->sh->loading = 0;
    cache->sh->size = 0;
    cache->sh->count = 0;
    cache->sh->watermark = (njt_uint_t) -1;

    cache->bsize = njt_fs_bsize(cache->path->name.data);

    cache->max_size /= cache->bsize;

    len = sizeof(" in cache keys zone \"\"") + shm_zone->shm.name.len;

    cache->shpool->log_ctx = njt_slab_alloc(cache->shpool, len);
    if (cache->shpool->log_ctx == NULL) {
        return NJT_ERROR;
    }

    njt_sprintf(cache->shpool->log_ctx, " in cache keys zone \"%V\"%Z",
                &shm_zone->shm.name);

    cache->shpool->log_nomem = 0;

    return NJT_OK;
}


njt_int_t
njt_http_file_cache_new(njt_http_request_t *r)
{
    njt_http_cache_t  *c;

    c = njt_pcalloc(r->pool, sizeof(njt_http_cache_t));
    if (c == NULL) {
        return NJT_ERROR;
    }

    if (njt_array_init(&c->keys, r->pool, 4, sizeof(njt_str_t)) != NJT_OK) {
        return NJT_ERROR;
    }
    // by chengxu
#if (NJT_HTTP_CACHE_PURGE)
    if (njt_array_init(&c->file_keys, r->pool, 4, sizeof(njt_str_t)) != NJT_OK) {
        return NJT_ERROR;
    }
#endif
    //end
    r->cache = c;
    c->file.log = r->connection->log;
    c->file.fd = NJT_INVALID_FILE;

    return NJT_OK;
}


njt_int_t
njt_http_file_cache_create(njt_http_request_t *r)
{
    njt_http_cache_t       *c;
    njt_pool_cleanup_t     *cln;
    njt_http_file_cache_t  *cache;

    c = r->cache;
    cache = c->file_cache;

    cln = njt_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        return NJT_ERROR;
    }

    cln->handler = njt_http_file_cache_cleanup;
    cln->data = c;

    if (njt_http_file_cache_exists(cache, c) == NJT_ERROR) {
        return NJT_ERROR;
    }

    if (njt_http_file_cache_name(r, cache->path) != NJT_OK) {
        return NJT_ERROR;
    }

    return NJT_OK;
}
// by chengxu
#if (NJT_HTTP_CACHE_PURGE)
//获取自定义key长度
static njt_int_t njt_http_file_cache_request_key_len(njt_http_request_t *r){
    njt_int_t len = 0;
    njt_str_t         *key;
    key = r->cache->keys.elts;
    njt_uint_t i;
    for (i = 0; i < r->cache->keys.nelts; i++) {
        len += key[i].len;
    }
    return len;
}
//设置请求生成的key
njt_int_t njt_http_file_cache_set_request_key(njt_http_request_t *r){
    njt_str_t         *key;
    u_int i=0;
    u_char* data = njt_pnalloc(r->pool, r->cache->request_key.len );
    if (data == NULL) {
        return NJT_ERROR;
    }
    r->cache->request_key.data = data;
    int len = 0;
    key = r->cache->keys.elts;
    for (i = 0; i < r->cache->keys.nelts; i++) {
        njt_memcpy(data+len,key[i].data, key[i].len);
        len += key[i].len;
    }
    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "save http file cache request key:  \"%V\" , p:%Xp", &r->cache->request_key,&r->cache->request_key);
    return NJT_OK;
}
#endif
// end

void
njt_http_file_cache_create_key(njt_http_request_t *r)
{
    size_t             len;
    njt_str_t         *key;
    njt_uint_t         i;
    njt_md5_t          md5;
    njt_http_cache_t  *c;

    c = r->cache;
// by chengxu
#if (NJT_HTTP_CACHE_PURGE)
    len = njt_http_file_cache_request_key_len(r);
    r->cache->request_key.len = len;
#endif
    // end
    len = 0;

    njt_crc32_init(c->crc32);
    njt_md5_init(&md5);

    key = c->keys.elts;
    for (i = 0; i < c->keys.nelts; i++) {
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http cache key: \"%V\"", &key[i]);

        len += key[i].len;

        njt_crc32_update(&c->crc32, key[i].data, key[i].len);
        njt_md5_update(&md5, key[i].data, key[i].len);
    }
    // by chengxu
#if (NJT_HTTP_CACHE_PURGE)
    key = c->file_keys.elts;
    for (i = 0; i < c->file_keys.nelts; i++) {
        len += key[i].len;
    }
#endif
    // end
    // by chengxu
#if (NJT_HTTP_CACHE_PURGE)
    c->header_start = sizeof(njt_http_file_cache_header_t)
                      + sizeof(njt_http_file_cache_key) +sizeof (njt_http_file_key) + len + 1;
#else
    c->header_start = sizeof(njt_http_file_cache_header_t)
                      + sizeof(njt_http_file_cache_key) + len + 1;
#endif
    // end

    njt_crc32_final(c->crc32);
    njt_md5_final(c->key, &md5);

    njt_memcpy(c->main, c->key, NJT_HTTP_CACHE_KEY_LEN);
}
// by chengxu
#if (NJT_HTTP_CACHE_PURGE)
njt_int_t njt_http_file_cache_delete_file_slice(njt_http_request_t *r)
{
    njt_http_cache_t            *c;
    njt_http_file_cache_t       *cache;
    njt_int_t                   rc;
    njt_http_file_cache_node_t  *fcn;
    njt_queue_t                 *item;

    c = r->cache;
    cache = c->file_cache;
    rc = NJT_OK;

    if(r->cache->node== NULL || r->cache->node->file_key.data == NULL ){
        return NJT_OK;
    }

    njt_shmtx_lock(&cache->shpool->mutex);
    item = njt_queue_head(&cache->sh->queue);
    while(item != njt_queue_sentinel(&cache->sh->queue)) {
        fcn = njt_queue_data(item, njt_http_file_cache_node_t, queue);
        if ( njt_strcmp(&fcn->file_key,&r->cache->node->file_key) == 0 ) {
            fcn->purged = 1;
        }
        item = njt_queue_next(item);
    }
    njt_shmtx_unlock(&cache->shpool->mutex);
    return rc;
}
njt_int_t
njt_http_file_cache_purge_one_cache_files(njt_http_file_cache_t *cache)
{
    njt_queue_t                 *item;
    njt_http_file_cache_node_t  *fcn;

    /*
     * TODO if the list of this queue is long enough,
     * will it time consuming for this loop?
     */

    njt_shmtx_lock(&cache->shpool->mutex);
    //遍历队列
    item = njt_queue_head(&cache->sh->queue);
    while(item != njt_queue_sentinel(&cache->sh->queue)) {
        fcn = njt_queue_data(item, njt_http_file_cache_node_t, queue);
        if (fcn) {
            //设置删除状态
            fcn->purged = 1;
        }
        item = njt_queue_next(item);
    }
    njt_shmtx_unlock(&cache->shpool->mutex);

    return NJT_OK;
}

njt_int_t
njt_http_file_cache_purge_one_file(njt_http_request_t *r)
{
    //    判断是否开启统配符匹配
    njt_http_slice_loc_conf_t* slice_conf = njt_http_get_module_loc_conf(r,njt_http_slice_filter_module);
    if(slice_conf->size != NJT_CONF_UNSET_SIZE && slice_conf->size != 0 ){
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http file cache purge is wildcard used : ");
        return njt_http_file_cache_purge_one_path(r);
    }

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "http file cache purge is one file used : ");
    njt_http_cache_t            *c;
    njt_http_file_cache_t       *cache;
    njt_int_t                   rc;
    njt_http_file_cache_node_t  *fcn;

    c = r->cache;
    cache = c->file_cache;
    rc = NJT_OK;

    njt_shmtx_lock(&cache->shpool->mutex);
    fcn = c->node;
    if (fcn == NULL) {
        fcn = njt_http_file_cache_lookup(cache, c->key);
    }

    if (fcn) {
        fcn->purged = 1;
    }
//    else {
//        rc = NJT_DECLINED;
//    }
    njt_shmtx_unlock(&cache->shpool->mutex);
    return rc;
}

//清理指定路径缓存文件
njt_int_t njt_http_file_cache_purge_one_path(njt_http_request_t *r){

    //遍历红黑树前缀
    njt_http_cache_t            *c;
    njt_http_file_cache_t       *cache;
    njt_int_t                   rc;
    njt_http_file_cache_node_t  *fcn;
    njt_queue_t                 *item;
    njt_str_t prefix;


    c = r->cache;
    cache = c->file_cache;
    rc = NJT_OK;

    prefix.data = r->cache->request_key.data;
    prefix.len = r->cache->request_key.len;
    u_char * index = njt_strlchr(prefix.data,prefix.data+prefix.len,'*');
    if(index != NULL){
        prefix.len = index - prefix.data;
    }
    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,"http file cache purge key prefix : \"%V\"",&prefix);

    njt_shmtx_lock(&cache->shpool->mutex);
    item = njt_queue_head(&cache->sh->queue);
    njt_uint_t count = 0;
    while(item != njt_queue_sentinel(&cache->sh->queue)) {
        fcn = njt_queue_data(item, njt_http_file_cache_node_t, queue);
        if(fcn){
            njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http file cache purge fcn->request_key : \"%V\"",&fcn->request_key);
        }
        if (fcn
	&& fcn->request_key.len >= prefix.len
        && njt_strncmp(prefix.data,fcn->request_key.data,prefix.len) == 0
        ) {
            //设置删除状态
            fcn->purged = 1;
            ++count;
        }
        item = njt_queue_next(item);
    }
    njt_shmtx_unlock(&cache->shpool->mutex);
//    if(count == 0 && !njt_queue_empty(&cache->sh->queue)){
//        rc=NJT_DECLINED;
//    }
    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache purge files quantity : \"%ui\"",count);
    return rc;
}

#endif
// end

njt_int_t
njt_http_file_cache_open(njt_http_request_t *r)
{
    njt_int_t                  rc, rv;
    njt_uint_t                 test;
    njt_http_cache_t          *c;
    njt_pool_cleanup_t        *cln;
    njt_open_file_info_t       of;
    njt_http_file_cache_t     *cache;
    njt_http_core_loc_conf_t  *clcf;

    c = r->cache;

    if (c->waiting) {
        return NJT_AGAIN;
    }

    if (c->reading) {
        return njt_http_file_cache_read(r, c);
    }

    cache = c->file_cache;

    if (c->node == NULL) {
        cln = njt_pool_cleanup_add(r->pool, 0);
        if (cln == NULL) {
            return NJT_ERROR;
        }

        cln->handler = njt_http_file_cache_cleanup;
        cln->data = c;
    }

    c->buffer_size = c->body_start;

    rc = njt_http_file_cache_exists(cache, c);

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache exists: %i e:%d", rc, c->exists);

    if (rc == NJT_ERROR) {
        return rc;
    }

    if (rc == NJT_AGAIN) {
        return NJT_HTTP_CACHE_SCARCE;
    }

    if (rc == NJT_OK) {

        if (c->error) {
            return c->error;
        }

        c->temp_file = 1;
        test = c->exists ? 1 : 0;
        rv = NJT_DECLINED;

    } else { /* rc == NJT_DECLINED */

        test = cache->sh->cold ? 1 : 0;

        if (c->min_uses > 1) {

            if (!test) {
                return NJT_HTTP_CACHE_SCARCE;
            }

            rv = NJT_HTTP_CACHE_SCARCE;

        } else {
            c->temp_file = 1;
            rv = NJT_DECLINED;
        }
    }

    if (njt_http_file_cache_name(r, cache->path) != NJT_OK) {
        return NJT_ERROR;
    }

    if (!test) {
        goto done;
    }

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    njt_memzero(&of, sizeof(njt_open_file_info_t));

    of.uniq = c->uniq;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.events = clcf->open_file_cache_events;
    of.directio = NJT_OPEN_FILE_DIRECTIO_OFF;
    of.read_ahead = clcf->read_ahead;

    if (njt_open_cached_file(clcf->open_file_cache, &c->file.name, &of, r->pool)
        != NJT_OK)
    {
        switch (of.err) {

        case 0:
            return NJT_ERROR;

        case NJT_ENOENT:
        case NJT_ENOTDIR:
            goto done;

        default:
            njt_log_error(NJT_LOG_CRIT, r->connection->log, of.err,
                          njt_open_file_n " \"%s\" failed", c->file.name.data);
            return NJT_ERROR;
        }
    }

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache fd: %d", of.fd);

    c->file.fd = of.fd;
    c->file.log = r->connection->log;
    c->uniq = of.uniq;
    c->length = of.size;
    c->fs_size = (of.fs_size + cache->bsize - 1) / cache->bsize;

    c->buf = njt_create_temp_buf(r->pool, c->body_start);
    if (c->buf == NULL) {
        return NJT_ERROR;
    }

    return njt_http_file_cache_read(r, c);

done:

    if (rv == NJT_DECLINED) {
        return njt_http_file_cache_lock(r, c);
    }

    return rv;
}


static njt_int_t
njt_http_file_cache_lock(njt_http_request_t *r, njt_http_cache_t *c)
{
    njt_msec_t                 now, timer;
    njt_http_file_cache_t     *cache;

    if (!c->lock) {
        return NJT_DECLINED;
    }

    now = njt_current_msec;

    cache = c->file_cache;

    njt_shmtx_lock(&cache->shpool->mutex);

    timer = c->node->lock_time - now;

    if (!c->node->updating || (njt_msec_int_t) timer <= 0) {
        c->node->updating = 1;
        c->node->lock_time = now + c->lock_age;
        c->updating = 1;
        c->lock_time = c->node->lock_time;
    }

    njt_shmtx_unlock(&cache->shpool->mutex);

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache lock u:%d wt:%M",
                   c->updating, c->wait_time);

    if (c->updating) {
        return NJT_DECLINED;
    }

    if (c->lock_timeout == 0) {
        return NJT_HTTP_CACHE_SCARCE;
    }

    c->waiting = 1;

    if (c->wait_time == 0) {
        c->wait_time = now + c->lock_timeout;

        c->wait_event.handler = njt_http_file_cache_lock_wait_handler;
        c->wait_event.data = r;
        c->wait_event.log = r->connection->log;
    }

    timer = c->wait_time - now;

    njt_add_timer(&c->wait_event, (timer > 500) ? 500 : timer);

    r->main->blocked++;

    return NJT_AGAIN;
}


static void
njt_http_file_cache_lock_wait_handler(njt_event_t *ev)
{
    njt_connection_t    *c;
    njt_http_request_t  *r;

    r = ev->data;
    c = r->connection;

    njt_http_set_log_request(c->log, r);

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http file cache wait: \"%V?%V\"", &r->uri, &r->args);

    njt_http_file_cache_lock_wait(r, r->cache);

    njt_http_run_posted_requests(c);
}


static void
njt_http_file_cache_lock_wait(njt_http_request_t *r, njt_http_cache_t *c)
{
    njt_uint_t              wait;
    njt_msec_t              now, timer;
    njt_http_file_cache_t  *cache;

    now = njt_current_msec;

    timer = c->wait_time - now;

    if ((njt_msec_int_t) timer <= 0) {
        njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                      "cache lock timeout");
        c->lock_timeout = 0;
        goto wakeup;
    }

    cache = c->file_cache;
    wait = 0;

    njt_shmtx_lock(&cache->shpool->mutex);

    timer = c->node->lock_time - now;

    if (c->node->updating && (njt_msec_int_t) timer > 0) {
        wait = 1;
    }

    njt_shmtx_unlock(&cache->shpool->mutex);

    if (wait) {
        njt_add_timer(&c->wait_event, (timer > 500) ? 500 : timer);
        return;
    }

wakeup:

    c->waiting = 0;
    r->main->blocked--;
    r->write_event_handler(r);
}


static njt_int_t
njt_http_file_cache_read(njt_http_request_t *r, njt_http_cache_t *c)
{
    u_char                        *p;
    time_t                         now;
    ssize_t                        n;
    njt_str_t                     *key;
    njt_int_t                      rc;
    njt_uint_t                     i;
    njt_http_file_cache_t         *cache;
    njt_http_file_cache_header_t  *h;

    n = njt_http_file_cache_aio_read(r, c);

    if (n < 0) {
        return n;
    }

    if ((size_t) n < c->header_start) {
        njt_log_error(NJT_LOG_CRIT, r->connection->log, 0,
                      "cache file \"%s\" is too small", c->file.name.data);
        return NJT_DECLINED;
    }

    h = (njt_http_file_cache_header_t *) c->buf->pos;

    if (h->version != NJT_HTTP_CACHE_VERSION) {
        njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                      "cache file \"%s\" version mismatch", c->file.name.data);
        return NJT_DECLINED;
    }

    if (h->crc32 != c->crc32 || (size_t) h->header_start != c->header_start) {
        njt_log_error(NJT_LOG_CRIT, r->connection->log, 0,
                      "cache file \"%s\" has md5 collision", c->file.name.data);
        return NJT_DECLINED;
    }

    p = c->buf->pos + sizeof(njt_http_file_cache_header_t)
        + sizeof(njt_http_file_cache_key);

    key = c->keys.elts;
    for (i = 0; i < c->keys.nelts; i++) {
        if (njt_memcmp(p, key[i].data, key[i].len) != 0) {
            njt_log_error(NJT_LOG_CRIT, r->connection->log, 0,
                          "cache file \"%s\" has md5 collision",
                          c->file.name.data);
            return NJT_DECLINED;
        }

        p += key[i].len;
    }

    if ((size_t) h->body_start > c->body_start) {
        njt_log_error(NJT_LOG_CRIT, r->connection->log, 0,
                      "cache file \"%s\" has too long header",
                      c->file.name.data);
        return NJT_DECLINED;
    }

    if (h->vary_len > NJT_HTTP_CACHE_VARY_LEN) {
        njt_log_error(NJT_LOG_CRIT, r->connection->log, 0,
                      "cache file \"%s\" has incorrect vary length",
                      c->file.name.data);
        return NJT_DECLINED;
    }

    if (h->vary_len) {
        njt_http_file_cache_vary(r, h->vary, h->vary_len, c->variant);

        if (njt_memcmp(c->variant, h->variant, NJT_HTTP_CACHE_KEY_LEN) != 0) {
            njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http file cache vary mismatch");
            return njt_http_file_cache_reopen(r, c);
        }
    }

    c->buf->last += n;

    c->valid_sec = h->valid_sec;
    c->updating_sec = h->updating_sec;
    c->error_sec = h->error_sec;
    c->last_modified = h->last_modified;
    c->date = h->date;
    c->valid_msec = h->valid_msec;
    c->body_start = h->body_start;
    c->etag.len = h->etag_len;
    c->etag.data = h->etag;

    r->cached = 1;

    cache = c->file_cache;

    if (cache->sh->cold) {

        njt_shmtx_lock(&cache->shpool->mutex);

        if (!c->node->exists) {
            c->node->uses = 1;
            c->node->body_start = c->body_start;
            c->node->exists = 1;
            c->node->uniq = c->uniq;
            c->node->fs_size = c->fs_size;

            cache->sh->size += c->fs_size;
        }

        njt_shmtx_unlock(&cache->shpool->mutex);
    }

    now = njt_time();
    // by chengxu
#if (NJT_HTTP_CACHE_PURGE)
    if(c->node && c->node->valid_sec != 0 && c->node->valid_sec < now) {
        c->valid_sec = c->node->valid_sec;
    }
#endif
    // end


    if (c->valid_sec < now) {
        c->stale_updating = c->valid_sec + c->updating_sec >= now;
        c->stale_error = c->valid_sec + c->error_sec >= now;

        njt_shmtx_lock(&cache->shpool->mutex);

        if (c->node && c->node->updating) {
            rc = NJT_HTTP_CACHE_UPDATING;

        } else {
            c->node->updating = 1;
            c->updating = 1;
            c->lock_time = c->node->lock_time;
            rc = NJT_HTTP_CACHE_STALE;
        }

        njt_shmtx_unlock(&cache->shpool->mutex);

        // njt_log_debug3(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
        //                "http file cache expired: %i %T %T",
        //                rc, c->valid_sec, now);

        return rc;
    }

    return NJT_OK;
}


static ssize_t
njt_http_file_cache_aio_read(njt_http_request_t *r, njt_http_cache_t *c)
{
#if (NJT_HAVE_FILE_AIO || NJT_THREADS)
    ssize_t                    n;
    njt_http_core_loc_conf_t  *clcf;

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);
#endif

#if (NJT_HAVE_FILE_AIO)

    if (clcf->aio == NJT_HTTP_AIO_ON && njt_file_aio) {
        n = njt_file_aio_read(&c->file, c->buf->pos, c->body_start, 0, r->pool);

        if (n != NJT_AGAIN) {
            c->reading = 0;
            return n;
        }

        c->reading = 1;

        c->file.aio->data = r;
        c->file.aio->handler = njt_http_cache_aio_event_handler;

        r->main->blocked++;
        r->aio = 1;

        return NJT_AGAIN;
    }

#endif

#if (NJT_THREADS)

    if (clcf->aio == NJT_HTTP_AIO_THREADS) {
        c->file.thread_task = c->thread_task;
        c->file.thread_handler = njt_http_cache_thread_handler;
        c->file.thread_ctx = r;

        n = njt_thread_read(&c->file, c->buf->pos, c->body_start, 0, r->pool);

        c->thread_task = c->file.thread_task;
        c->reading = (n == NJT_AGAIN);

        return n;
    }

#endif

    return njt_read_file(&c->file, c->buf->pos, c->body_start, 0);
}


#if (NJT_HAVE_FILE_AIO)

static void
njt_http_cache_aio_event_handler(njt_event_t *ev)
{
    njt_event_aio_t     *aio;
    njt_connection_t    *c;
    njt_http_request_t  *r;

    aio = ev->data;
    r = aio->data;
    c = r->connection;

    njt_http_set_log_request(c->log, r);

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http file cache aio: \"%V?%V\"", &r->uri, &r->args);

    r->main->blocked--;
    r->aio = 0;

    r->write_event_handler(r);

    njt_http_run_posted_requests(c);
}

#endif


#if (NJT_THREADS)

static njt_int_t
njt_http_cache_thread_handler(njt_thread_task_t *task, njt_file_t *file)
{
    njt_str_t                  name;
    njt_thread_pool_t         *tp;
    njt_http_request_t        *r;
    njt_http_core_loc_conf_t  *clcf;

    r = file->thread_ctx;

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);
    tp = clcf->thread_pool;

    if (tp == NULL) {
        if (njt_http_complex_value(r, clcf->thread_pool_value, &name)
            != NJT_OK)
        {
            return NJT_ERROR;
        }

        tp = njt_thread_pool_get((njt_cycle_t *) njt_cycle, &name);

        if (tp == NULL) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "thread pool \"%V\" not found", &name);
            return NJT_ERROR;
        }
    }

    task->event.data = r;
    task->event.handler = njt_http_cache_thread_event_handler;

    if (njt_thread_task_post(tp, task) != NJT_OK) {
        return NJT_ERROR;
    }

    r->main->blocked++;
    r->aio = 1;

    return NJT_OK;
}


static void
njt_http_cache_thread_event_handler(njt_event_t *ev)
{
    njt_connection_t    *c;
    njt_http_request_t  *r;

    r = ev->data;
    c = r->connection;

    njt_http_set_log_request(c->log, r);

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http file cache thread: \"%V?%V\"", &r->uri, &r->args);

    r->main->blocked--;
    r->aio = 0;

    r->write_event_handler(r);

    njt_http_run_posted_requests(c);
}

#endif


static njt_int_t
njt_http_file_cache_exists(njt_http_file_cache_t *cache, njt_http_cache_t *c)
{
    njt_int_t                    rc;
    njt_http_file_cache_node_t  *fcn;

    // by chengxu
#if (NJT_HTTP_CACHE_PURGE)
    njt_uint_t  index,len=0;
#endif
    // end
    njt_shmtx_lock(&cache->shpool->mutex);

    fcn = c->node;

    if (fcn == NULL) {
        fcn = njt_http_file_cache_lookup(cache, c->key);
    }

    if (fcn) {
        njt_queue_remove(&fcn->queue);

        if (c->node == NULL) {
            fcn->uses++;
            fcn->count++;
        }
        // by chengxu
#if (NJT_HTTP_CACHE_PURGE)
        if (fcn->purged) {
            goto purged;
        }
#endif
        // end
        if (fcn->error) {

            if (fcn->valid_sec < njt_time()) {
                goto renew;
            }

            rc = NJT_OK;

            goto done;
        }

        if (fcn->exists || fcn->uses >= c->min_uses) {

            c->exists = fcn->exists;
            if (fcn->body_start && !c->update_variant) {
                c->body_start = fcn->body_start;
            }

            rc = NJT_OK;

            goto done;
        }

        rc = NJT_AGAIN;

        goto done;
    }
    // by chengxu
#if (NJT_HTTP_CACHE_PURGE)
    njt_str_t *data = c->file_keys.elts;
    for(index = 0 ; index < c->file_keys.nelts ;index++){
        len += data[index].len;
    }
    fcn = njt_slab_calloc_locked(cache->shpool,
                                 sizeof(njt_http_file_cache_node_t)+ len + c->request_key.len);
#else
    fcn = njt_slab_calloc_locked(cache->shpool,
                                 sizeof(njt_http_file_cache_node_t));
#endif
    // end



    if (fcn == NULL) {
        njt_http_file_cache_set_watermark(cache);

        njt_shmtx_unlock(&cache->shpool->mutex);

        (void) njt_http_file_cache_forced_expire(cache);

        njt_shmtx_lock(&cache->shpool->mutex);
        // by chengxu
#if (NJT_HTTP_CACHE_PURGE)
        fcn = njt_slab_calloc_locked(cache->shpool,
                                     sizeof(njt_http_file_cache_node_t) + len);
#else
        fcn = njt_slab_calloc_locked(cache->shpool,
                                     sizeof(njt_http_file_cache_node_t));
#endif
        // end

        if (fcn == NULL) {
            njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,
                          "could not allocate node%s", cache->shpool->log_ctx);
            rc = NJT_ERROR;
            goto failed;
        }
    }
    // by chengxu
#if (NJT_HTTP_CACHE_PURGE)
    fcn->file_key.data = ((u_char*)fcn) + sizeof(njt_http_file_cache_node_t) ;
    fcn->file_key.len = len;
    len=0;
    for(index = 0 ; index < c->file_keys.nelts ;index++){
        njt_memcpy(fcn->file_key.data+len,data[index].data,data[index].len);
        len += data[index].len;
    }
#endif
    // end

    cache->sh->count++;

    njt_memcpy((u_char *) &fcn->node.key, c->key, sizeof(njt_rbtree_key_t));
    // by chengxu
#if (NJT_HTTP_CACHE_PURGE)
    fcn->request_key.data = ((u_char*)fcn) + sizeof(njt_http_file_cache_node_t) + fcn->file_key.len;
    //copy key内存数据
    njt_str_t         *key;
    u_int i=0;
    u_char* u_data = fcn->request_key.data;
    njt_uint_t u_len = 0;
    key = c->keys.elts;
    for (i = 0; i < c->keys.nelts; i++) {
        njt_memcpy(u_data+u_len,key[i].data, key[i].len);
        u_len += key[i].len;
    }
    fcn->request_key.len = c->request_key.len;
    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                  "save key fcn->request_key \"%V\"", &fcn->request_key);
#endif
    // end
    njt_memcpy(fcn->key, &c->key[sizeof(njt_rbtree_key_t)],
               NJT_HTTP_CACHE_KEY_LEN - sizeof(njt_rbtree_key_t));

    njt_rbtree_insert(&cache->sh->rbtree, &fcn->node);

    fcn->uses = 1;
    fcn->count = 1;

renew:
    // by chengxu
#if (NJT_HTTP_CACHE_PURGE)
    fcn->purged = 0;
purged:
#endif
    // end
    rc = NJT_DECLINED;

    fcn->valid_msec = 0;
    fcn->error = 0;
    fcn->exists = 0;
    fcn->valid_sec = 0;
    fcn->uniq = 0;
    fcn->body_start = 0;
    fcn->fs_size = 0;

done:

    fcn->expire = njt_time() + cache->inactive;

    njt_queue_insert_head(&cache->sh->queue, &fcn->queue);

    c->uniq = fcn->uniq;
    c->error = fcn->error;
    c->node = fcn;

failed:

    njt_shmtx_unlock(&cache->shpool->mutex);

    return rc;
}


static njt_int_t
njt_http_file_cache_name(njt_http_request_t *r, njt_path_t *path)
{
    u_char            *p;
    njt_http_cache_t  *c;

    c = r->cache;

    if (c->file.name.len) {
        return NJT_OK;
    }

    c->file.name.len = path->name.len + 1 + path->len
                       + 2 * NJT_HTTP_CACHE_KEY_LEN;

    c->file.name.data = njt_pnalloc(r->pool, c->file.name.len + 1);
    if (c->file.name.data == NULL) {
        return NJT_ERROR;
    }

    njt_memcpy(c->file.name.data, path->name.data, path->name.len);

    p = c->file.name.data + path->name.len + 1 + path->len;
    p = njt_hex_dump(p, c->key, NJT_HTTP_CACHE_KEY_LEN);
    *p = '\0';

    njt_create_hashed_filename(path, c->file.name.data, c->file.name.len);

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "cache file: \"%s\"", c->file.name.data);

    return NJT_OK;
}


static njt_http_file_cache_node_t *
njt_http_file_cache_lookup(njt_http_file_cache_t *cache, u_char *key)
{
    njt_int_t                    rc;
    njt_rbtree_key_t             node_key;
    njt_rbtree_node_t           *node, *sentinel;
    njt_http_file_cache_node_t  *fcn;

    njt_memcpy((u_char *) &node_key, key, sizeof(njt_rbtree_key_t));

    node = cache->sh->rbtree.root;
    sentinel = cache->sh->rbtree.sentinel;

    while (node != sentinel) {

        if (node_key < node->key) {
            node = node->left;
            continue;
        }

        if (node_key > node->key) {
            node = node->right;
            continue;
        }

        /* node_key == node->key */

        fcn = (njt_http_file_cache_node_t *) node;

        rc = njt_memcmp(&key[sizeof(njt_rbtree_key_t)], fcn->key,
                        NJT_HTTP_CACHE_KEY_LEN - sizeof(njt_rbtree_key_t));

        if (rc == 0) {
            return fcn;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    /* not found */

    return NULL;
}


static void
njt_http_file_cache_rbtree_insert_value(njt_rbtree_node_t *temp,
    njt_rbtree_node_t *node, njt_rbtree_node_t *sentinel)
{
    njt_rbtree_node_t           **p;
    njt_http_file_cache_node_t   *cn, *cnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            cn = (njt_http_file_cache_node_t *) node;
            cnt = (njt_http_file_cache_node_t *) temp;

            p = (njt_memcmp(cn->key, cnt->key,
                            NJT_HTTP_CACHE_KEY_LEN - sizeof(njt_rbtree_key_t))
                 < 0)
                    ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    njt_rbt_red(node);
}


static void
njt_http_file_cache_vary(njt_http_request_t *r, u_char *vary, size_t len,
    u_char *hash)
{
    u_char     *p, *last;
    njt_str_t   name;
    njt_md5_t   md5;
    u_char      buf[NJT_HTTP_CACHE_VARY_LEN];

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache vary: \"%*s\"", len, vary);

    njt_md5_init(&md5);
    njt_md5_update(&md5, r->cache->main, NJT_HTTP_CACHE_KEY_LEN);

    njt_strlow(buf, vary, len);

    p = buf;
    last = buf + len;

    while (p < last) {

        while (p < last && (*p == ' ' || *p == ',')) { p++; }

        name.data = p;

        while (p < last && *p != ',' && *p != ' ') { p++; }

        name.len = p - name.data;

        if (name.len == 0) {
            break;
        }

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http file cache vary: %V", &name);

        njt_md5_update(&md5, name.data, name.len);
        njt_md5_update(&md5, (u_char *) ":", sizeof(":") - 1);

        njt_http_file_cache_vary_header(r, &md5, &name);

        njt_md5_update(&md5, (u_char *) CRLF, sizeof(CRLF) - 1);
    }

    njt_md5_final(hash, &md5);
}


static void
njt_http_file_cache_vary_header(njt_http_request_t *r, njt_md5_t *md5,
    njt_str_t *name)
{
    size_t            len;
    u_char           *p, *start, *last;
    njt_uint_t        i, multiple, normalize;
    njt_list_part_t  *part;
    njt_table_elt_t  *header;

    multiple = 0;
    normalize = 0;

    if (name->len == sizeof("Accept-Charset") - 1
        && njt_strncasecmp(name->data, (u_char *) "Accept-Charset",
                           sizeof("Accept-Charset") - 1) == 0)
    {
        normalize = 1;

    } else if (name->len == sizeof("Accept-Encoding") - 1
        && njt_strncasecmp(name->data, (u_char *) "Accept-Encoding",
                           sizeof("Accept-Encoding") - 1) == 0)
    {
        normalize = 1;

    } else if (name->len == sizeof("Accept-Language") - 1
        && njt_strncasecmp(name->data, (u_char *) "Accept-Language",
                           sizeof("Accept-Language") - 1) == 0)
    {
        normalize = 1;
    }

    part = &r->headers_in.headers.part;
    header = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        if (header[i].key.len != name->len) {
            continue;
        }

        if (njt_strncasecmp(header[i].key.data, name->data, name->len) != 0) {
            continue;
        }

        if (!normalize) {

            if (multiple) {
                njt_md5_update(md5, (u_char *) ",", sizeof(",") - 1);
            }

            njt_md5_update(md5, header[i].value.data, header[i].value.len);

            multiple = 1;

            continue;
        }

        /* normalize spaces */

        p = header[i].value.data;
        last = p + header[i].value.len;

        while (p < last) {

            while (p < last && (*p == ' ' || *p == ',')) { p++; }

            start = p;

            while (p < last && *p != ',' && *p != ' ') { p++; }

            len = p - start;

            if (len == 0) {
                break;
            }

            if (multiple) {
                njt_md5_update(md5, (u_char *) ",", sizeof(",") - 1);
            }

            njt_md5_update(md5, start, len);

            multiple = 1;
        }
    }
}


static njt_int_t
njt_http_file_cache_reopen(njt_http_request_t *r, njt_http_cache_t *c)
{
    njt_http_file_cache_t  *cache;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->file.log, 0,
                   "http file cache reopen");

    if (c->secondary) {
        njt_log_error(NJT_LOG_CRIT, r->connection->log, 0,
                      "cache file \"%s\" has incorrect vary hash",
                      c->file.name.data);
        return NJT_DECLINED;
    }

    cache = c->file_cache;

    njt_shmtx_lock(&cache->shpool->mutex);

    c->node->count--;
    c->node = NULL;

    njt_shmtx_unlock(&cache->shpool->mutex);

    c->secondary = 1;
    c->file.name.len = 0;
    c->body_start = c->buffer_size;

    njt_memcpy(c->key, c->variant, NJT_HTTP_CACHE_KEY_LEN);

    return njt_http_file_cache_open(r);
}


njt_int_t
njt_http_file_cache_set_header(njt_http_request_t *r, u_char *buf)
{
    njt_http_file_cache_header_t  *h = (njt_http_file_cache_header_t *) buf;

    u_char            *p;
    njt_str_t         *key;
    njt_uint_t         i;
    njt_http_cache_t  *c;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache set header");

    c = r->cache;

    njt_memzero(h, sizeof(njt_http_file_cache_header_t));

    h->version = NJT_HTTP_CACHE_VERSION;
    h->valid_sec = c->valid_sec;
    h->updating_sec = c->updating_sec;
    h->error_sec = c->error_sec;
    h->last_modified = c->last_modified;
    h->date = c->date;
    h->crc32 = c->crc32;
    h->valid_msec = (u_short) c->valid_msec;
    h->header_start = (u_short) c->header_start;
    h->body_start = (u_short) c->body_start;

    if (c->etag.len <= NJT_HTTP_CACHE_ETAG_LEN) {
        h->etag_len = (u_char) c->etag.len;
        njt_memcpy(h->etag, c->etag.data, c->etag.len);
    }

    if (c->vary.len) {
        if (c->vary.len > NJT_HTTP_CACHE_VARY_LEN) {
            /* should not happen */
            c->vary.len = NJT_HTTP_CACHE_VARY_LEN;
        }

        h->vary_len = (u_char) c->vary.len;
        njt_memcpy(h->vary, c->vary.data, c->vary.len);

        njt_http_file_cache_vary(r, c->vary.data, c->vary.len, c->variant);
        njt_memcpy(h->variant, c->variant, NJT_HTTP_CACHE_KEY_LEN);
    }

    if (njt_http_file_cache_update_variant(r, c) != NJT_OK) {
        return NJT_ERROR;
    }

    p = buf + sizeof(njt_http_file_cache_header_t);

    p = njt_cpymem(p, njt_http_file_cache_key, sizeof(njt_http_file_cache_key));

    key = c->keys.elts;
    for (i = 0; i < c->keys.nelts; i++) {
        p = njt_copy(p, key[i].data, key[i].len);
    }
    // by chengxu
#if (NJT_HTTP_CACHE_PURGE)
    p = njt_cpymem(p, njt_http_file_key, sizeof(njt_http_file_key));
    key = c->file_keys.elts;
    for (i = 0; i < c->file_keys.nelts; i++) {
        p = njt_copy(p, key[i].data, key[i].len);
    }
#endif
    //end

    *p = LF;

    return NJT_OK;
}


static njt_int_t
njt_http_file_cache_update_variant(njt_http_request_t *r, njt_http_cache_t *c)
{
    njt_http_file_cache_t  *cache;

    if (!c->secondary) {
        return NJT_OK;
    }

    if (c->vary.len
        && njt_memcmp(c->variant, c->key, NJT_HTTP_CACHE_KEY_LEN) == 0)
    {
        return NJT_OK;
    }

    /*
     * if the variant hash doesn't match one we used as a secondary
     * cache key, switch back to the original key
     */

    cache = c->file_cache;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache main key");

    njt_shmtx_lock(&cache->shpool->mutex);

    c->node->count--;
    c->node->updating = 0;
    c->node = NULL;

    njt_shmtx_unlock(&cache->shpool->mutex);

    c->file.name.len = 0;
    c->update_variant = 1;

    njt_memcpy(c->key, c->main, NJT_HTTP_CACHE_KEY_LEN);

    if (njt_http_file_cache_exists(cache, c) == NJT_ERROR) {
        return NJT_ERROR;
    }

    if (njt_http_file_cache_name(r, cache->path) != NJT_OK) {
        return NJT_ERROR;
    }

    return NJT_OK;
}


void
njt_http_file_cache_update(njt_http_request_t *r, njt_temp_file_t *tf)
{
    off_t                   fs_size;
    njt_int_t               rc;
    njt_file_uniq_t         uniq;
    njt_file_info_t         fi;
    njt_http_cache_t        *c;
    njt_ext_rename_file_t   ext;
    njt_http_file_cache_t  *cache;

    c = r->cache;

    if (c->updated) {
        return;
    }

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache update");

    cache = c->file_cache;

    c->updated = 1;
    c->updating = 0;

    uniq = 0;
    fs_size = 0;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache rename: \"%s\" to \"%s\"",
                   tf->file.name.data, c->file.name.data);

    ext.access = NJT_FILE_OWNER_ACCESS;
    ext.path_access = NJT_FILE_OWNER_ACCESS;
    ext.time = -1;
    ext.create_path = 1;
    ext.delete_file = 1;
    ext.log = r->connection->log;

    rc = njt_ext_rename_file(&tf->file.name, &c->file.name, &ext);

    if (rc == NJT_OK) {

        if (njt_fd_info(tf->file.fd, &fi) == NJT_FILE_ERROR) {
            njt_log_error(NJT_LOG_CRIT, r->connection->log, njt_errno,
                          njt_fd_info_n " \"%s\" failed", tf->file.name.data);

            rc = NJT_ERROR;

        } else {
            uniq = njt_file_uniq(&fi);
            fs_size = (njt_file_fs_size(&fi) + cache->bsize - 1) / cache->bsize;
        }
    }

    njt_shmtx_lock(&cache->shpool->mutex);

    c->node->count--;
    c->node->error = 0;
    c->node->uniq = uniq;
    c->node->body_start = c->body_start;

    cache->sh->size += fs_size - c->node->fs_size;
    c->node->fs_size = fs_size;

    if (rc == NJT_OK) {
        c->node->exists = 1;
    }

    c->node->updating = 0;

    njt_shmtx_unlock(&cache->shpool->mutex);
}


void
njt_http_file_cache_update_header(njt_http_request_t *r)
{
    ssize_t                        n;
    njt_err_t                      err;
    njt_file_t                     file;
    njt_file_info_t                fi;
    njt_http_cache_t              *c;
    njt_http_file_cache_header_t   h;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache update header");

    c = r->cache;

    njt_memzero(&file, sizeof(njt_file_t));

    file.name = c->file.name;
    file.log = r->connection->log;
    file.fd = njt_open_file(file.name.data, NJT_FILE_RDWR, NJT_FILE_OPEN, 0);

    if (file.fd == NJT_INVALID_FILE) {
        err = njt_errno;

        /* cache file may have been deleted */

        if (err == NJT_ENOENT) {
            njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http file cache \"%s\" not found",
                           file.name.data);
            return;
        }

        njt_log_error(NJT_LOG_CRIT, r->connection->log, err,
                      njt_open_file_n " \"%s\" failed", file.name.data);
        return;
    }

    /*
     * make sure cache file wasn't replaced;
     * if it was, do nothing
     */

    if (njt_fd_info(file.fd, &fi) == NJT_FILE_ERROR) {
        njt_log_error(NJT_LOG_CRIT, r->connection->log, njt_errno,
                      njt_fd_info_n " \"%s\" failed", file.name.data);
        goto done;
    }

    if (c->uniq != njt_file_uniq(&fi)
        || c->length != njt_file_size(&fi))
    {
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http file cache \"%s\" changed",
                       file.name.data);
        goto done;
    }

    n = njt_read_file(&file, (u_char *) &h,
                      sizeof(njt_http_file_cache_header_t), 0);

    if (n == NJT_ERROR) {
        goto done;
    }

    if ((size_t) n != sizeof(njt_http_file_cache_header_t)) {
        njt_log_error(NJT_LOG_CRIT, r->connection->log, 0,
                      njt_read_file_n " read only %z of %z from \"%s\"",
                      n, sizeof(njt_http_file_cache_header_t), file.name.data);
        goto done;
    }

    if (h.version != NJT_HTTP_CACHE_VERSION
        || h.last_modified != c->last_modified
        || h.crc32 != c->crc32
        || (size_t) h.header_start != c->header_start
        || (size_t) h.body_start != c->body_start)
    {
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http file cache \"%s\" content changed",
                       file.name.data);
        goto done;
    }

    /*
     * update cache file header with new data,
     * notably h.valid_sec and h.date
     */

    njt_memzero(&h, sizeof(njt_http_file_cache_header_t));

    h.version = NJT_HTTP_CACHE_VERSION;
    h.valid_sec = c->valid_sec;
    h.updating_sec = c->updating_sec;
    h.error_sec = c->error_sec;
    h.last_modified = c->last_modified;
    h.date = c->date;
    h.crc32 = c->crc32;
    h.valid_msec = (u_short) c->valid_msec;
    h.header_start = (u_short) c->header_start;
    h.body_start = (u_short) c->body_start;

    if (c->etag.len <= NJT_HTTP_CACHE_ETAG_LEN) {
        h.etag_len = (u_char) c->etag.len;
        njt_memcpy(h.etag, c->etag.data, c->etag.len);
    }

    if (c->vary.len) {
        if (c->vary.len > NJT_HTTP_CACHE_VARY_LEN) {
            /* should not happen */
            c->vary.len = NJT_HTTP_CACHE_VARY_LEN;
        }

        h.vary_len = (u_char) c->vary.len;
        njt_memcpy(h.vary, c->vary.data, c->vary.len);

        njt_http_file_cache_vary(r, c->vary.data, c->vary.len, c->variant);
        njt_memcpy(h.variant, c->variant, NJT_HTTP_CACHE_KEY_LEN);
    }

    (void) njt_write_file(&file, (u_char *) &h,
                          sizeof(njt_http_file_cache_header_t), 0);

done:

    if (njt_close_file(file.fd) == NJT_FILE_ERROR) {
        njt_log_error(NJT_LOG_ALERT, r->connection->log, njt_errno,
                      njt_close_file_n " \"%s\" failed", file.name.data);
    }
}


njt_int_t
njt_http_cache_send(njt_http_request_t *r)
{
    njt_int_t          rc;
    njt_buf_t         *b;
    njt_chain_t        out;
    njt_http_cache_t  *c;

    c = r->cache;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache send: %s", c->file.name.data);

    /* we need to allocate all before the header would be sent */

    b = njt_calloc_buf(r->pool);
    if (b == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->file = njt_pcalloc(r->pool, sizeof(njt_file_t));
    if (b->file == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = njt_http_send_header(r);

    if (rc == NJT_ERROR || rc > NJT_OK || r->header_only) {
        return rc;
    }

    b->file_pos = c->body_start;
    b->file_last = c->length;

    b->in_file = (c->length - c->body_start) ? 1 : 0;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;
    b->sync = (b->last_buf || b->in_file) ? 0 : 1;

    b->file->fd = c->file.fd;
    b->file->name = c->file.name;
    b->file->log = r->connection->log;

    out.buf = b;
    out.next = NULL;

    return njt_http_output_filter(r, &out);
}


void
njt_http_file_cache_free(njt_http_cache_t *c, njt_temp_file_t *tf)
{
    njt_http_file_cache_t       *cache;
    njt_http_file_cache_node_t  *fcn;

    if (c->updated || c->node == NULL) {
        return;
    }

    cache = c->file_cache;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->file.log, 0,
                   "http file cache free, fd: %d", c->file.fd);

    njt_shmtx_lock(&cache->shpool->mutex);

    fcn = c->node;
    fcn->count--;

    if (c->updating && fcn->lock_time == c->lock_time) {
        fcn->updating = 0;
    }

    if (c->error) {
        fcn->error = c->error;

        if (c->valid_sec) {
            fcn->valid_sec = c->valid_sec;
            fcn->valid_msec = c->valid_msec;
        }

    } else if (!fcn->exists && fcn->count == 0 && c->min_uses == 1) {
        njt_queue_remove(&fcn->queue);
        njt_rbtree_delete(&cache->sh->rbtree, &fcn->node);
        njt_slab_free_locked(cache->shpool, fcn);
        cache->sh->count--;
        c->node = NULL;
    }

    njt_shmtx_unlock(&cache->shpool->mutex);

    c->updated = 1;
    c->updating = 0;

    if (c->temp_file) {
        if (tf && tf->file.fd != NJT_INVALID_FILE) {
            njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->file.log, 0,
                           "http file cache incomplete: \"%s\"",
                           tf->file.name.data);

            if (njt_delete_file(tf->file.name.data) == NJT_FILE_ERROR) {
                njt_log_error(NJT_LOG_CRIT, c->file.log, njt_errno,
                              njt_delete_file_n " \"%s\" failed",
                              tf->file.name.data);
            }
        }
    }

    if (c->wait_event.timer_set) {
        njt_del_timer(&c->wait_event);
    }
}


static void
njt_http_file_cache_cleanup(void *data)
{
    njt_http_cache_t  *c = data;

    if (c->updated) {
        return;
    }

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->file.log, 0,
                   "http file cache cleanup");

    if (c->updating && !c->background) {
        njt_log_error(NJT_LOG_ALERT, c->file.log, 0,
                      "stalled cache updating, error:%ui", c->error);
    }

    njt_http_file_cache_free(c, NULL);
}


static time_t
njt_http_file_cache_forced_expire(njt_http_file_cache_t *cache)
{
    u_char                      *name, *p;
    size_t                       len;
    time_t                       wait;
    njt_uint_t                   tries;
    njt_path_t                  *path;
    njt_queue_t                 *q, *sentinel;
    njt_http_file_cache_node_t  *fcn;
    u_char                       key[2 * NJT_HTTP_CACHE_KEY_LEN];

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                   "http file cache forced expire");

    path = cache->path;
    len = path->name.len + 1 + path->len + 2 * NJT_HTTP_CACHE_KEY_LEN;

    name = njt_alloc(len + 1, njt_cycle->log);
    if (name == NULL) {
        return 10;
    }

    njt_memcpy(name, path->name.data, path->name.len);

    wait = 10;
    tries = 20;
    sentinel = NULL;

    njt_shmtx_lock(&cache->shpool->mutex);

    for ( ;; ) {
        if (njt_queue_empty(&cache->sh->queue)) {
            break;
        }

        q = njt_queue_last(&cache->sh->queue);

        if (q == sentinel) {
            break;
        }

        fcn = njt_queue_data(q, njt_http_file_cache_node_t, queue);

        njt_log_debug6(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                  "http file cache forced expire: #%d %d %02xd%02xd%02xd%02xd",
                  fcn->count, fcn->exists,
                  fcn->key[0], fcn->key[1], fcn->key[2], fcn->key[3]);

        if (fcn->count == 0) {
            njt_http_file_cache_delete(cache, q, name);
            wait = 0;
            break;
        }

        if (fcn->deleting) {
            wait = 1;
            break;
        }

        p = njt_hex_dump(key, (u_char *) &fcn->node.key,
                         sizeof(njt_rbtree_key_t));
        len = NJT_HTTP_CACHE_KEY_LEN - sizeof(njt_rbtree_key_t);
        (void) njt_hex_dump(p, fcn->key, len);

        /*
         * abnormally exited workers may leave locked cache entries,
         * and although it may be safe to remove them completely,
         * we prefer to just move them to the top of the inactive queue
         */

        njt_queue_remove(q);
        fcn->expire = njt_time() + cache->inactive;
        njt_queue_insert_head(&cache->sh->queue, &fcn->queue);

        njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,
                      "ignore long locked inactive cache entry %*s, count:%d",
                      (size_t) 2 * NJT_HTTP_CACHE_KEY_LEN, key, fcn->count);

        if (sentinel == NULL) {
            sentinel = q;
        }

        if (--tries) {
            continue;
        }

        wait = 1;
        break;
    }

    njt_shmtx_unlock(&cache->shpool->mutex);

    njt_free(name);

    return wait;
}


static time_t
njt_http_file_cache_expire(njt_http_file_cache_t *cache)
{
    u_char                      *name, *p;
    size_t                       len;
    time_t                       now, wait;
    njt_path_t                  *path;
    njt_msec_t                   elapsed;
    njt_queue_t                 *q;
    njt_http_file_cache_node_t  *fcn;
    u_char                       key[2 * NJT_HTTP_CACHE_KEY_LEN];

    // njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
    //                "http file cache expire");

    path = cache->path;
    len = path->name.len + 1 + path->len + 2 * NJT_HTTP_CACHE_KEY_LEN;

    name = njt_alloc(len + 1, njt_cycle->log);
    if (name == NULL) {
        return 10;
    }

    njt_memcpy(name, path->name.data, path->name.len);

    now = njt_time();

    njt_shmtx_lock(&cache->shpool->mutex);

    for ( ;; ) {

        if (njt_quit || njt_terminate) {
            wait = 1;
            break;
        }

        if (njt_queue_empty(&cache->sh->queue)) {
            wait = 10;
            break;
        }

        q = njt_queue_last(&cache->sh->queue);

        fcn = njt_queue_data(q, njt_http_file_cache_node_t, queue);

        wait = fcn->expire - now;

        if (wait > 0) {
            wait = wait > 10 ? 10 : wait;
            break;
        }

        njt_log_debug6(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "http file cache expire: #%d %d %02xd%02xd%02xd%02xd",
                       fcn->count, fcn->exists,
                       fcn->key[0], fcn->key[1], fcn->key[2], fcn->key[3]);

        if (fcn->count == 0) {
            njt_http_file_cache_delete(cache, q, name);
            goto next;
        }

        if (fcn->deleting) {
            wait = 1;
            break;
        }

        p = njt_hex_dump(key, (u_char *) &fcn->node.key,
                         sizeof(njt_rbtree_key_t));
        len = NJT_HTTP_CACHE_KEY_LEN - sizeof(njt_rbtree_key_t);
        (void) njt_hex_dump(p, fcn->key, len);

        /*
         * abnormally exited workers may leave locked cache entries,
         * and although it may be safe to remove them completely,
         * we prefer to just move them to the top of the inactive queue
         */

        njt_queue_remove(q);
        fcn->expire = njt_time() + cache->inactive;
        njt_queue_insert_head(&cache->sh->queue, &fcn->queue);

        njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,
                      "ignore long locked inactive cache entry %*s, count:%d",
                      (size_t) 2 * NJT_HTTP_CACHE_KEY_LEN, key, fcn->count);

next:

        if (++cache->files >= cache->manager_files) {
            wait = 0;
            break;
        }

        njt_time_update();

        elapsed = njt_abs((njt_msec_int_t) (njt_current_msec - cache->last));

        if (elapsed >= cache->manager_threshold) {
            wait = 0;
            break;
        }
    }

    njt_shmtx_unlock(&cache->shpool->mutex);

    njt_free(name);

    return wait;
}


static void
njt_http_file_cache_delete(njt_http_file_cache_t *cache, njt_queue_t *q,
    u_char *name)
{
    u_char                      *p;
    size_t                       len;
    njt_path_t                  *path;
    njt_http_file_cache_node_t  *fcn;

    fcn = njt_queue_data(q, njt_http_file_cache_node_t, queue);

    if (fcn->exists) {
        cache->sh->size -= fcn->fs_size;

        path = cache->path;
        p = name + path->name.len + 1 + path->len;
        p = njt_hex_dump(p, (u_char *) &fcn->node.key,
                         sizeof(njt_rbtree_key_t));
        len = NJT_HTTP_CACHE_KEY_LEN - sizeof(njt_rbtree_key_t);
        p = njt_hex_dump(p, fcn->key, len);
        *p = '\0';

        fcn->count++;
        fcn->deleting = 1;
        njt_shmtx_unlock(&cache->shpool->mutex);

        len = path->name.len + 1 + path->len + 2 * NJT_HTTP_CACHE_KEY_LEN;
        njt_create_hashed_filename(path, name, len);

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "http file cache expire: \"%s\"", name);

        if (njt_delete_file(name) == NJT_FILE_ERROR) {
            njt_log_error(NJT_LOG_CRIT, njt_cycle->log, njt_errno,
                          njt_delete_file_n " \"%s\" failed", name);
        }

        njt_shmtx_lock(&cache->shpool->mutex);
        fcn->count--;
        fcn->deleting = 0;
    }

    if (fcn->count == 0) {
        njt_queue_remove(q);
        njt_rbtree_delete(&cache->sh->rbtree, &fcn->node);
        njt_slab_free_locked(cache->shpool, fcn);
        cache->sh->count--;
    }
}
// by chengxu
#if (NJT_HTTP_CACHE_PURGE)

static time_t
njt_http_file_cache_purge(njt_http_file_cache_t *cache)
{
    u_char                      *name;
    size_t                       len;
    time_t                       wait;
    njt_path_t                  *path;
    njt_msec_t                   elapsed;
    njt_queue_t                 *item;
    njt_http_file_cache_node_t  *fcn;

    // njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
    //                "http file purge");

    path = cache->path;
    len = path->name.len + 1 + path->len + 2 * NJT_HTTP_CACHE_KEY_LEN;

    name = njt_alloc(len + 1, njt_cycle->log);
    if (name == NULL) {
        return 10;
    }

    njt_memcpy(name, path->name.data, path->name.len);

    njt_shmtx_lock(&cache->shpool->mutex);
    item = njt_queue_head(&cache->sh->queue);
    wait = 1;
    if(njt_queue_empty(&cache->sh->queue)){
        // njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,"http cache files size is 0 ");
    }
    while(item != njt_queue_sentinel(&cache->sh->queue)) {

        if (njt_quit || njt_terminate) {
            wait = 1;
            break;
        }

        if (njt_queue_empty(&cache->sh->queue)) {
            wait = 10;
            break;
        }

        fcn = njt_queue_data(item, njt_http_file_cache_node_t, queue);

        njt_log_debug4(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "http cache file : #%d %d %d \"%v\" ",
                       fcn->count, fcn->exists, fcn->purged,&fcn->request_key );
        if (!fcn->purged) {
            item = njt_queue_next(item);
            continue;
        }
        njt_log_debug4(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "http file purge: #%d %d %d \"%v\" ",
                       fcn->count, fcn->exists, fcn->purged,
                       &fcn->request_key );

        if (fcn->deleting) {
            wait = 1;
            break;
        }

        njt_http_file_cache_delete(cache, item, name);

        if (++cache->files >= cache->purger_files) {
            wait = 0;
            break;
        }

        njt_time_update();

        elapsed = njt_abs((njt_msec_int_t) (njt_current_msec - cache->last));

        if (elapsed >= cache->purger_threshold) {
            wait = 0;
            break;
        }
        item = njt_queue_next(item);
    }

    njt_shmtx_unlock(&cache->shpool->mutex);

    njt_free(name);

    return wait;
}

static njt_msec_t
njt_http_file_cache_purger(void *data)
{
    njt_http_file_cache_t  *cache = data;
    njt_msec_t             next;

    cache->last = njt_current_msec;
    cache->files = 0;
    next = (njt_msec_t) njt_http_file_cache_purge(cache) * 1000;
    return next;
}
#endif
// end

static njt_msec_t
njt_http_file_cache_manager(void *data)
{
    njt_http_file_cache_t  *cache = data;

    off_t       size, free;
    time_t      wait;
    njt_msec_t  elapsed, next;
    njt_uint_t  count, watermark;

    cache->last = njt_current_msec;
    cache->files = 0;

    next = (njt_msec_t) njt_http_file_cache_expire(cache) * 1000;

    if (next == 0) {
        next = cache->manager_sleep;
        goto done;
    }

    for ( ;; ) {
        njt_shmtx_lock(&cache->shpool->mutex);

        size = cache->sh->size;
        count = cache->sh->count;
        watermark = cache->sh->watermark;

        njt_shmtx_unlock(&cache->shpool->mutex);

        // njt_log_debug3(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
        //                "http file cache size: %O c:%ui w:%i",
        //                size, count, (njt_int_t) watermark);

        if (size < cache->max_size && count < watermark) {

            if (!cache->min_free) {
                break;
            }

            free = njt_fs_available(cache->path->name.data);

            njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                           "http file cache free: %O", free);

            if (free > cache->min_free) {
                break;
            }
        }

        wait = njt_http_file_cache_forced_expire(cache);

        if (wait > 0) {
            next = (njt_msec_t) wait * 1000;
            break;
        }

        if (njt_quit || njt_terminate) {
            break;
        }

        if (++cache->files >= cache->manager_files) {
            next = cache->manager_sleep;
            break;
        }

        njt_time_update();

        elapsed = njt_abs((njt_msec_int_t) (njt_current_msec - cache->last));

        if (elapsed >= cache->manager_threshold) {
            next = cache->manager_sleep;
            break;
        }
    }

done:

    // elapsed = njt_abs((njt_msec_int_t) (njt_current_msec - cache->last));

    // njt_log_debug3(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
    //                "http file cache manager: %ui e:%M n:%M",
    //                cache->files, elapsed, next);

    return next;
}


static void
njt_http_file_cache_loader(void *data)
{
    njt_http_file_cache_t  *cache = data;

    njt_tree_ctx_t  tree;

    if (!cache->sh->cold || cache->sh->loading) {
        return;
    }

    if (!njt_atomic_cmp_set(&cache->sh->loading, 0, njt_pid)) {
        return;
    }

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                   "http file cache loader");

    tree.init_handler = NULL;
    tree.file_handler = njt_http_file_cache_manage_file;
    tree.pre_tree_handler = njt_http_file_cache_manage_directory;
    tree.post_tree_handler = njt_http_file_cache_noop;
    tree.spec_handler = njt_http_file_cache_delete_file;
    tree.data = cache;
    tree.alloc = 0;
    tree.log = njt_cycle->log;

    cache->last = njt_current_msec;
    cache->files = 0;

    if (njt_walk_tree(&tree, &cache->path->name) == NJT_ABORT) {
        cache->sh->loading = 0;
        return;
    }

    cache->sh->cold = 0;
    cache->sh->loading = 0;

    njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0,
                  "http file cache: %V %.3fM, bsize: %uz",
                  &cache->path->name,
                  ((double) cache->sh->size * cache->bsize) / (1024 * 1024),
                  cache->bsize);
}


static njt_int_t
njt_http_file_cache_noop(njt_tree_ctx_t *ctx, njt_str_t *path)
{
    return NJT_OK;
}


static njt_int_t
njt_http_file_cache_manage_file(njt_tree_ctx_t *ctx, njt_str_t *path)
{
    njt_msec_t              elapsed;
    njt_http_file_cache_t  *cache;

    cache = ctx->data;

    if (njt_http_file_cache_add_file(ctx, path) != NJT_OK) {
        (void) njt_http_file_cache_delete_file(ctx, path);
    }

    if (++cache->files >= cache->loader_files) {
        njt_http_file_cache_loader_sleep(cache);

    } else {
        njt_time_update();

        elapsed = njt_abs((njt_msec_int_t) (njt_current_msec - cache->last));

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "http file cache loader time elapsed: %M", elapsed);

        if (elapsed >= cache->loader_threshold) {
            njt_http_file_cache_loader_sleep(cache);
        }
    }

    return (njt_quit || njt_terminate) ? NJT_ABORT : NJT_OK;
}


static njt_int_t
njt_http_file_cache_manage_directory(njt_tree_ctx_t *ctx, njt_str_t *path)
{
    if (path->len >= 5
        && njt_strncmp(path->data + path->len - 5, "/temp", 5) == 0)
    {
        return NJT_DECLINED;
    }

    return NJT_OK;
}


static void
njt_http_file_cache_loader_sleep(njt_http_file_cache_t *cache)
{
    njt_msleep(cache->loader_sleep);

    njt_time_update();

    cache->last = njt_current_msec;
    cache->files = 0;
}


static njt_int_t
njt_http_file_cache_add_file(njt_tree_ctx_t *ctx, njt_str_t *name)
{
    u_char                 *p;
    njt_int_t               n;
    njt_uint_t              i;
    njt_http_cache_t        c;
    njt_http_file_cache_t  *cache;

    if (name->len < 2 * NJT_HTTP_CACHE_KEY_LEN) {
        return NJT_ERROR;
    }

    /*
     * Temporary files in cache have a suffix consisting of a dot
     * followed by 10 digits.
     */

    if (name->len >= 2 * NJT_HTTP_CACHE_KEY_LEN + 1 + 10
        && name->data[name->len - 10 - 1] == '.')
    {
        return NJT_OK;
    }

    if (ctx->size < (off_t) sizeof(njt_http_file_cache_header_t)) {
        njt_log_error(NJT_LOG_CRIT, ctx->log, 0,
                      "cache file \"%s\" is too small", name->data);
        return NJT_ERROR;
    }

    njt_memzero(&c, sizeof(njt_http_cache_t));
    cache = ctx->data;

    c.length = ctx->size;
    c.fs_size = (ctx->fs_size + cache->bsize - 1) / cache->bsize;

    p = &name->data[name->len - 2 * NJT_HTTP_CACHE_KEY_LEN];

    for (i = 0; i < NJT_HTTP_CACHE_KEY_LEN; i++) {
        n = njt_hextoi(p, 2);

        if (n == NJT_ERROR) {
            return NJT_ERROR;
        }

        p += 2;

        c.key[i] = (u_char) n;
    }
    // by chengxu
#if (NJT_HTTP_CACHE_PURGE)
    return njt_http_file_cache_add(cache, &c , name);
#else
    return njt_http_file_cache_add(cache, &c);
#endif
    //end
}

// by chengxu
#if (NJT_HTTP_CACHE_PURGE)
//把缓存文件元数据加载到共享内存
static njt_int_t
njt_http_file_cache_add(njt_http_file_cache_t *cache, njt_http_cache_t *c,njt_str_t* name)
{
    njt_http_file_cache_node_t  *fcn;
    njt_http_file_cache_header_t header;
    u_char *key_data,*file_index;
    njt_uint_t key_size,key_offset,file_key_size,cache_key_size,size;

    //读取request_key
    njt_file_t cache_file;
    cache_file.name = *name;
    cache_file.log = njt_cycle->log;
    cache_file.fd = njt_open_file(cache_file.name.data, NJT_FILE_RDONLY, NJT_FILE_OPEN, 0  );
    size = njt_read_file(&cache_file, (u_char*)&header, sizeof (njt_http_file_cache_header_t),0);
    if(size < sizeof (njt_http_file_cache_header_t) ){
        njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,"could not load file header");
        return NJT_ERROR;
    }
    key_offset = sizeof (njt_http_file_cache_header_t) + sizeof (njt_http_file_cache_key) ;
    key_size = header.header_start - key_offset;
    key_data = njt_pcalloc(njt_cycle->pool,key_size);
    if( key_data == NULL){
        njt_close_file(cache_file.fd);
        return NJT_ERROR;
    }
    size = njt_read_file(&cache_file, key_data, key_size,key_offset);
    if( size < key_size){
        njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,"read file too small , name: %V ,size: %i ",&cache_file.name,size);
        njt_close_file(cache_file.fd);
        return NJT_ERROR;
    }
    //关闭文件
    njt_close_file(cache_file.fd);
    file_index = njt_strlchr(key_data,key_data+key_size,LF); //判断去掉换行符
    if( file_index == NULL){
        return NJT_ERROR;
    }
    cache_key_size =  file_index - key_data;
    file_index += sizeof(njt_http_file_key);
    file_key_size = (key_data+key_size) - file_index;

    njt_shmtx_lock(&cache->shpool->mutex);

    fcn = njt_http_file_cache_lookup(cache, c->key);

    if (fcn == NULL) {

        fcn = njt_slab_calloc_locked(cache->shpool,
                                     sizeof(njt_http_file_cache_node_t) + file_key_size + cache_key_size);
        if (fcn == NULL) {
            njt_http_file_cache_set_watermark(cache);

            if (cache->fail_time != njt_time()) {
                cache->fail_time = njt_time();
                njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,
                              "could not allocate node%s", cache->shpool->log_ctx);
            }

            njt_shmtx_unlock(&cache->shpool->mutex);
            return NJT_ERROR;
        }
        fcn->file_key.data = ((u_char*)fcn) + sizeof(njt_http_file_cache_node_t);

        cache->sh->count++;
        fcn->request_key.data = ((u_char*)fcn) + sizeof(njt_http_file_cache_node_t) + file_key_size;
        fcn->request_key.len = cache_key_size;
        njt_memcpy(fcn->request_key.data, key_data, fcn->request_key.len);

        njt_memcpy((u_char *) &fcn->node.key, c->key, sizeof(njt_rbtree_key_t));

        njt_memcpy(fcn->key, &c->key[sizeof(njt_rbtree_key_t)],
                   NJT_HTTP_CACHE_KEY_LEN - sizeof(njt_rbtree_key_t));

        njt_memcpy(fcn->file_key.data, file_index,file_key_size);
        fcn->file_key.len = file_key_size;

        njt_rbtree_insert(&cache->sh->rbtree, &fcn->node);

        fcn->uses = 1;
        fcn->exists = 1;
        fcn->fs_size = c->fs_size;

        cache->sh->size += c->fs_size;

    } else {
        njt_queue_remove(&fcn->queue);
    }

    fcn->expire = njt_time() + cache->inactive;

    njt_queue_insert_head(&cache->sh->queue, &fcn->queue);

    njt_shmtx_unlock(&cache->shpool->mutex);

    return NJT_OK;
}
#else
static njt_int_t
njt_http_file_cache_add(njt_http_file_cache_t *cache, njt_http_cache_t *c)
{
    njt_http_file_cache_node_t  *fcn;

    njt_shmtx_lock(&cache->shpool->mutex);

    fcn = njt_http_file_cache_lookup(cache, c->key);

    if (fcn == NULL) {

        fcn = njt_slab_calloc_locked(cache->shpool,
                                     sizeof(njt_http_file_cache_node_t));
        if (fcn == NULL) {
            njt_http_file_cache_set_watermark(cache);

            if (cache->fail_time != njt_time()) {
                cache->fail_time = njt_time();
                njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,
                           "could not allocate node%s", cache->shpool->log_ctx);
            }

            njt_shmtx_unlock(&cache->shpool->mutex);
            return NJT_ERROR;
        }

        cache->sh->count++;

        njt_memcpy((u_char *) &fcn->node.key, c->key, sizeof(njt_rbtree_key_t));

        njt_memcpy(fcn->key, &c->key[sizeof(njt_rbtree_key_t)],
                   NJT_HTTP_CACHE_KEY_LEN - sizeof(njt_rbtree_key_t));

        njt_rbtree_insert(&cache->sh->rbtree, &fcn->node);

        fcn->uses = 1;
        fcn->exists = 1;
        fcn->fs_size = c->fs_size;

        cache->sh->size += c->fs_size;

    } else {
        njt_queue_remove(&fcn->queue);
    }

    fcn->expire = njt_time() + cache->inactive;

    njt_queue_insert_head(&cache->sh->queue, &fcn->queue);

    njt_shmtx_unlock(&cache->shpool->mutex);

    return NJT_OK;
}
#endif
//end



static njt_int_t
njt_http_file_cache_delete_file(njt_tree_ctx_t *ctx, njt_str_t *path)
{
    njt_log_debug1(NJT_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http file cache delete: \"%s\"", path->data);

    if (njt_delete_file(path->data) == NJT_FILE_ERROR) {
        njt_log_error(NJT_LOG_CRIT, ctx->log, njt_errno,
                      njt_delete_file_n " \"%s\" failed", path->data);
    }

    return NJT_OK;
}


static void
njt_http_file_cache_set_watermark(njt_http_file_cache_t *cache)
{
    cache->sh->watermark = cache->sh->count - cache->sh->count / 8;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                   "http file cache watermark: %ui", cache->sh->watermark);
}


time_t
njt_http_file_cache_valid(njt_array_t *cache_valid, njt_uint_t status)
{
    njt_uint_t               i;
    njt_http_cache_valid_t  *valid;

    if (cache_valid == NULL) {
        return 0;
    }

    valid = cache_valid->elts;
    for (i = 0; i < cache_valid->nelts; i++) {

        if (valid[i].status == 0) {
            return valid[i].valid;
        }

        if (valid[i].status == status) {
            return valid[i].valid;
        }
    }

    return 0;
}


char *
njt_http_file_cache_set_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char  *confp = conf;

    off_t                   max_size, min_free;
    u_char                 *last, *p;
    time_t                  inactive;
    ssize_t                 size;
    njt_str_t               s, name, *value;
    njt_int_t               loader_files, manager_files;
    njt_msec_t              loader_sleep, manager_sleep, loader_threshold,
                            manager_threshold;
    njt_uint_t              i, n, use_temp_path;
    njt_array_t            *caches;
    njt_http_file_cache_t  *cache, **ce;

    // by chengxu
#if (NJT_HTTP_CACHE_PURGE)
    njt_int_t   purger_files;
    njt_msec_t  purger_sleep, purger_threshold;
    njt_uint_t  purger_on;
#endif
    // end

    cache = njt_pcalloc(cf->pool, sizeof(njt_http_file_cache_t));
    if (cache == NULL) {
        return NJT_CONF_ERROR;
    }

    cache->path = njt_pcalloc(cf->pool, sizeof(njt_path_t));
    if (cache->path == NULL) {
        return NJT_CONF_ERROR;
    }

    use_temp_path = 1;

    inactive = 600;

    loader_files = 100;
    loader_sleep = 50;
    loader_threshold = 200;

    manager_files = 100;
    manager_sleep = 50;
    manager_threshold = 200;
    // by chengxu
#if (NJT_HTTP_CACHE_PURGE)
    purger_files = 10;
    purger_sleep = 50;
    purger_threshold = 0;
    purger_on = 0;
#endif
    //end

    name.len = 0;
    size = 0;
    max_size = NJT_MAX_OFF_T_VALUE;
    min_free = 0;

    value = cf->args->elts;

    cache->path->name = value[1];

    if (cache->path->name.data[cache->path->name.len - 1] == '/') {
        cache->path->name.len--;
    }

    if (njt_conf_full_name(cf->cycle, &cache->path->name, 0) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    for (i = 2; i < cf->args->nelts; i++) {

        if (njt_strncmp(value[i].data, "levels=", 7) == 0) {

            p = value[i].data + 7;
            last = value[i].data + value[i].len;

            for (n = 0; n < NJT_MAX_PATH_LEVEL && p < last; n++) {

                if (*p > '0' && *p < '3') {

                    cache->path->level[n] = *p++ - '0';
                    cache->path->len += cache->path->level[n] + 1;

                    if (p == last) {
                        break;
                    }

                    if (*p++ == ':' && n < NJT_MAX_PATH_LEVEL - 1 && p < last) {
                        continue;
                    }

                    goto invalid_levels;
                }

                goto invalid_levels;
            }

            if (cache->path->len < 10 + NJT_MAX_PATH_LEVEL) {
                continue;
            }

        invalid_levels:

            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid \"levels\" \"%V\"", &value[i]);
            return NJT_CONF_ERROR;
        }

        if (njt_strncmp(value[i].data, "use_temp_path=", 14) == 0) {

            if (njt_strcmp(&value[i].data[14], "on") == 0) {
                use_temp_path = 1;

            } else if (njt_strcmp(&value[i].data[14], "off") == 0) {
                use_temp_path = 0;

            } else {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid use_temp_path value \"%V\", "
                                   "it must be \"on\" or \"off\"",
                                   &value[i]);
                return NJT_CONF_ERROR;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "keys_zone=", 10) == 0) {

            name.data = value[i].data + 10;

            p = (u_char *) njt_strchr(name.data, ':');

            if (p == NULL) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid keys zone size \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            name.len = p - name.data;

            s.data = p + 1;
            s.len = value[i].data + value[i].len - s.data;

            size = njt_parse_size(&s);

            if (size == NJT_ERROR) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid keys zone size \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            if (size < (ssize_t) (2 * njt_pagesize)) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "keys zone \"%V\" is too small", &value[i]);
                return NJT_CONF_ERROR;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "inactive=", 9) == 0) {

            s.len = value[i].len - 9;
            s.data = value[i].data + 9;

            inactive = njt_parse_time(&s, 1);
            if (inactive == (time_t) NJT_ERROR) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid inactive value \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "max_size=", 9) == 0) {

            s.len = value[i].len - 9;
            s.data = value[i].data + 9;

            max_size = njt_parse_offset(&s);
            if (max_size < 0) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid max_size value \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "min_free=", 9) == 0) {

#if (NJT_WIN32 || NJT_HAVE_STATFS || NJT_HAVE_STATVFS)

            s.len = value[i].len - 9;
            s.data = value[i].data + 9;

            min_free = njt_parse_offset(&s);
            if (min_free < 0) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid min_free value \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

#else
            njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                               "min_free is not supported "
                               "on this platform, ignored");
#endif

            continue;
        }

        if (njt_strncmp(value[i].data, "loader_files=", 13) == 0) {

            loader_files = njt_atoi(value[i].data + 13, value[i].len - 13);
            if (loader_files == NJT_ERROR) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid loader_files value \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "loader_sleep=", 13) == 0) {

            s.len = value[i].len - 13;
            s.data = value[i].data + 13;

            loader_sleep = njt_parse_time(&s, 0);
            if (loader_sleep == (njt_msec_t) NJT_ERROR) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid loader_sleep value \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "loader_threshold=", 17) == 0) {

            s.len = value[i].len - 17;
            s.data = value[i].data + 17;

            loader_threshold = njt_parse_time(&s, 0);
            if (loader_threshold == (njt_msec_t) NJT_ERROR) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid loader_threshold value \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "manager_files=", 14) == 0) {

            manager_files = njt_atoi(value[i].data + 14, value[i].len - 14);
            if (manager_files == NJT_ERROR) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid manager_files value \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "manager_sleep=", 14) == 0) {

            s.len = value[i].len - 14;
            s.data = value[i].data + 14;

            manager_sleep = njt_parse_time(&s, 0);
            if (manager_sleep == (njt_msec_t) NJT_ERROR) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid manager_sleep value \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "manager_threshold=", 18) == 0) {

            s.len = value[i].len - 18;
            s.data = value[i].data + 18;

            manager_threshold = njt_parse_time(&s, 0);
            if (manager_threshold == (njt_msec_t) NJT_ERROR) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid manager_threshold value \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            continue;
        }
        // by chengxu
#if (NJT_HTTP_CACHE_PURGE)
        if (njt_strncmp(value[i].data, "purger=", 7) == 0) {

            if (njt_strcmp(&value[i].data[7], "on") == 0) {
                purger_on = 1;
            } else if (njt_strcmp(&value[i].data[7], "off") == 0) {
                purger_on = 0;

            } else {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid purger value \"%V\", "
                                   "it must be \"on\" or \"off\"",
                                   &value[i]);
                return NJT_CONF_ERROR;
            }

            continue;
        }
        if (njt_strncmp(value[i].data, "purger_files=", 13) == 0) {

            purger_files = njt_atoi(value[i].data + 13, value[i].len - 13);
            if (purger_files == NJT_ERROR) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid purger_files value \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "purger_sleep=", 13) == 0) {

            s.len = value[i].len - 13;
            s.data = value[i].data + 13;

            purger_sleep = njt_parse_time(&s, 0);
            if (purger_sleep == (njt_msec_t) NJT_ERROR) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid purger_sleep value \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "purger_threshold=", 17) == 0) {

            s.len = value[i].len - 17;
            s.data = value[i].data + 17;

            purger_threshold = njt_parse_time(&s, 0);
            if (purger_threshold == (njt_msec_t) NJT_ERROR) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid purger_threshold value \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            continue;
        }
#endif
        //end

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NJT_CONF_ERROR;
    }

    if (name.len == 0 || size == 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"keys_zone\" parameter",
                           &cmd->name);
        return NJT_CONF_ERROR;
    }

    cache->path->manager = njt_http_file_cache_manager;
    cache->path->loader = njt_http_file_cache_loader;
    // by chengxu
#if (NJT_HTTP_CACHE_PURGE)
    if (purger_on) {
        cache->path->purger = njt_http_file_cache_purger;
    }
    cache->purger_files = purger_files;
    cache->purger_sleep = purger_sleep;
    cache->purger_threshold = purger_threshold;
#endif
    //end

    cache->path->data = cache;
    cache->path->conf_file = cf->conf_file->file.name.data;
    cache->path->line = cf->conf_file->line;
    cache->loader_files = loader_files;
    cache->loader_sleep = loader_sleep;
    cache->loader_threshold = loader_threshold;
    cache->manager_files = manager_files;
    cache->manager_sleep = manager_sleep;
    cache->manager_threshold = manager_threshold;

    if (njt_add_path(cf, &cache->path) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    cache->shm_zone = njt_shared_memory_add(cf, &name, size, cmd->post);
    if (cache->shm_zone == NULL) {
        return NJT_CONF_ERROR;
    }

    if (cache->shm_zone->data) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "duplicate zone \"%V\"", &name);
        return NJT_CONF_ERROR;
    }


    cache->shm_zone->init = njt_http_file_cache_init;
    cache->shm_zone->data = cache;

    cache->use_temp_path = use_temp_path;

    cache->inactive = inactive;
    cache->max_size = max_size;
    cache->min_free = min_free;

    caches = (njt_array_t *) (confp + cmd->offset);

    ce = njt_array_push(caches);
    if (ce == NULL) {
        return NJT_CONF_ERROR;
    }

    *ce = cache;

    return NJT_CONF_OK;
}


char *
njt_http_file_cache_valid_set_slot(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    char  *p = conf;

    time_t                    valid;
    njt_str_t                *value;
    njt_int_t                 status;
    njt_uint_t                i, n;
    njt_array_t             **a;
    njt_http_cache_valid_t   *v;
    static njt_uint_t         statuses[] = { 200, 301, 302 };

    a = (njt_array_t **) (p + cmd->offset);

    if (*a == NJT_CONF_UNSET_PTR) {
        *a = njt_array_create(cf->pool, 1, sizeof(njt_http_cache_valid_t));
        if (*a == NULL) {
            return NJT_CONF_ERROR;
        }
    }

    value = cf->args->elts;
    n = cf->args->nelts - 1;

    valid = njt_parse_time(&value[n], 1);
    if (valid == (time_t) NJT_ERROR) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid time value \"%V\"", &value[n]);
        return NJT_CONF_ERROR;
    }

    if (n == 1) {

        for (i = 0; i < 3; i++) {
            v = njt_array_push(*a);
            if (v == NULL) {
                return NJT_CONF_ERROR;
            }

            v->status = statuses[i];
            v->valid = valid;
        }

        return NJT_CONF_OK;
    }

    for (i = 1; i < n; i++) {

        if (njt_strcmp(value[i].data, "any") == 0) {

            status = 0;

        } else {

            status = njt_atoi(value[i].data, value[i].len);
            if (status < 100 || status > 599) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid status \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }
        }

        v = njt_array_push(*a);
        if (v == NULL) {
            return NJT_CONF_ERROR;
        }

        v->status = status;
        v->valid = valid;
    }

    return NJT_CONF_OK;
}
