
/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.yy
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_http_lua_shdict.h"
#include "njt_http_lua_util.h"
#include "njt_http_lua_api.h"


static int njt_http_lua_shdict_expire(njt_http_lua_shdict_ctx_t *ctx,
    njt_uint_t n);
static njt_int_t njt_http_lua_shdict_lookup(njt_shm_zone_t *shm_zone,
    njt_uint_t hash, u_char *kdata, size_t klen,
    njt_http_lua_shdict_node_t **sdp);
static int njt_http_lua_shdict_flush_expired(lua_State *L);
static int njt_http_lua_shdict_get_keys(lua_State *L);
static int njt_http_lua_shdict_lpush(lua_State *L);
static int njt_http_lua_shdict_rpush(lua_State *L);
static int njt_http_lua_shdict_push_helper(lua_State *L, int flags);
static int njt_http_lua_shdict_lpop(lua_State *L);
static int njt_http_lua_shdict_rpop(lua_State *L);
static int njt_http_lua_shdict_pop_helper(lua_State *L, int flags);
static int njt_http_lua_shdict_llen(lua_State *L);


static njt_inline njt_shm_zone_t *njt_http_lua_shdict_get_zone(lua_State *L,
    int index);


#define NJT_HTTP_LUA_SHDICT_ADD         0x0001
#define NJT_HTTP_LUA_SHDICT_REPLACE     0x0002
#define NJT_HTTP_LUA_SHDICT_SAFE_STORE  0x0004


#define NJT_HTTP_LUA_SHDICT_LEFT        0x0001
#define NJT_HTTP_LUA_SHDICT_RIGHT       0x0002


enum {
    SHDICT_USERDATA_INDEX = 1,
};


enum {
    SHDICT_TNIL = 0,        /* same as LUA_TNIL */
    SHDICT_TBOOLEAN = 1,    /* same as LUA_TBOOLEAN */
    SHDICT_TNUMBER = 3,     /* same as LUA_TNUMBER */
    SHDICT_TSTRING = 4,     /* same as LUA_TSTRING */
    SHDICT_TLIST = 5,
};


static njt_inline njt_queue_t *
njt_http_lua_shdict_get_list_head(njt_http_lua_shdict_node_t *sd, size_t len)
{
    return (njt_queue_t *) njt_align_ptr(((u_char *) &sd->data + len),
                                         NJT_ALIGNMENT);
}


njt_int_t
njt_http_lua_shdict_init_zone(njt_shm_zone_t *shm_zone, void *data)
{
    njt_http_lua_shdict_ctx_t  *octx = data;

    size_t                      len;
    njt_http_lua_shdict_ctx_t  *ctx;

    dd("init zone");

    ctx = shm_zone->data;

    if (octx) {
        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;

        return NJT_OK;
    }

    ctx->shpool = (njt_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->sh = ctx->shpool->data;

        return NJT_OK;
    }

    ctx->sh = njt_slab_alloc(ctx->shpool, sizeof(njt_http_lua_shdict_shctx_t));
    if (ctx->sh == NULL) {
        return NJT_ERROR;
    }

    ctx->shpool->data = ctx->sh;

    njt_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    njt_http_lua_shdict_rbtree_insert_value);

    njt_queue_init(&ctx->sh->lru_queue);

    len = sizeof(" in lua_shared_dict zone \"\"") + shm_zone->shm.name.len;

    ctx->shpool->log_ctx = njt_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return NJT_ERROR;
    }

    njt_sprintf(ctx->shpool->log_ctx, " in lua_shared_dict zone \"%V\"%Z",
                &shm_zone->shm.name);

    ctx->shpool->log_nomem = 0;

    return NJT_OK;
}


void
njt_http_lua_shdict_rbtree_insert_value(njt_rbtree_node_t *temp,
    njt_rbtree_node_t *node, njt_rbtree_node_t *sentinel)
{
    njt_rbtree_node_t           **p;
    njt_http_lua_shdict_node_t   *sdn, *sdnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            sdn = (njt_http_lua_shdict_node_t *) &node->color;
            sdnt = (njt_http_lua_shdict_node_t *) &temp->color;

            p = njt_memn2cmp(sdn->data, sdnt->data, sdn->key_len,
                             sdnt->key_len) < 0 ? &temp->left : &temp->right;
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


static njt_int_t
njt_http_lua_shdict_lookup(njt_shm_zone_t *shm_zone, njt_uint_t hash,
    u_char *kdata, size_t klen, njt_http_lua_shdict_node_t **sdp)
{
    njt_int_t                    rc;
    njt_time_t                  *tp;
    uint64_t                     now;
    int64_t                      ms;
    njt_rbtree_node_t           *node, *sentinel;
    njt_http_lua_shdict_ctx_t   *ctx;
    njt_http_lua_shdict_node_t  *sd;

    ctx = shm_zone->data;

    node = ctx->sh->rbtree.root;
    sentinel = ctx->sh->rbtree.sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        sd = (njt_http_lua_shdict_node_t *) &node->color;

        rc = njt_memn2cmp(kdata, sd->data, klen, (size_t) sd->key_len);

        if (rc == 0) {
            *sdp = sd;

            dd("node expires: %lld", (long long) sd->expires);

            if (sd->expires != 0) {
                tp = njt_timeofday();

                now = (uint64_t) tp->sec * 1000 + tp->msec;
                ms = sd->expires - now;

                dd("time to live: %lld", (long long) ms);

                if (ms < 0) {
                    dd("node already expired");
                    return NJT_DONE;
                }
            }

            njt_queue_remove(&sd->queue);
            njt_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

            return NJT_OK;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    *sdp = NULL;

    return NJT_DECLINED;
}


static int
njt_http_lua_shdict_expire(njt_http_lua_shdict_ctx_t *ctx, njt_uint_t n)
{
    njt_time_t                      *tp;
    uint64_t                         now;
    njt_queue_t                     *q, *list_queue, *lq;
    int64_t                          ms;
    njt_rbtree_node_t               *node;
    njt_http_lua_shdict_node_t      *sd;
    int                              freed = 0;
    njt_http_lua_shdict_list_node_t *lnode;

    tp = njt_timeofday();

    now = (uint64_t) tp->sec * 1000 + tp->msec;

    /*
     * n == 1 deletes one or two expired entries
     * n == 0 deletes oldest entry by force
     *        and one or two zero rate entries
     */

    while (n < 3) {

        if (njt_queue_empty(&ctx->sh->lru_queue)) {
            return freed;
        }

        q = njt_queue_last(&ctx->sh->lru_queue);

        sd = njt_queue_data(q, njt_http_lua_shdict_node_t, queue);

        if (n++ != 0) {

            if (sd->expires == 0) {
                return freed;
            }

            ms = sd->expires - now;
            if (ms > 0) {
                return freed;
            }
        }

        if (sd->value_type == SHDICT_TLIST) {
            list_queue = njt_http_lua_shdict_get_list_head(sd, sd->key_len);

            for (lq = njt_queue_head(list_queue);
                 lq != njt_queue_sentinel(list_queue);
                 lq = njt_queue_next(lq))
            {
                lnode = njt_queue_data(lq, njt_http_lua_shdict_list_node_t,
                                       queue);

                njt_slab_free_locked(ctx->shpool, lnode);
            }
        }

        njt_queue_remove(q);

        node = (njt_rbtree_node_t *)
                   ((u_char *) sd - offsetof(njt_rbtree_node_t, color));

        njt_rbtree_delete(&ctx->sh->rbtree, node);

        njt_slab_free_locked(ctx->shpool, node);

        freed++;
    }

    return freed;
}


void
njt_http_lua_inject_shdict_api(njt_http_lua_main_conf_t *lmcf, lua_State *L)
{
    njt_http_lua_shdict_ctx_t   *ctx;
    njt_uint_t                   i;
    njt_shm_zone_t             **zone;
    njt_shm_zone_t             **zone_udata;

    if (lmcf->shdict_zones != NULL) {
        lua_createtable(L, 0, lmcf->shdict_zones->nelts /* nrec */);
                /* njt.shared */

        lua_createtable(L, 0 /* narr */, 22 /* nrec */); /* shared mt */

        lua_pushcfunction(L, njt_http_lua_shdict_lpush);
        lua_setfield(L, -2, "lpush");

        lua_pushcfunction(L, njt_http_lua_shdict_rpush);
        lua_setfield(L, -2, "rpush");

        lua_pushcfunction(L, njt_http_lua_shdict_lpop);
        lua_setfield(L, -2, "lpop");

        lua_pushcfunction(L, njt_http_lua_shdict_rpop);
        lua_setfield(L, -2, "rpop");

        lua_pushcfunction(L, njt_http_lua_shdict_llen);
        lua_setfield(L, -2, "llen");

        lua_pushcfunction(L, njt_http_lua_shdict_flush_expired);
        lua_setfield(L, -2, "flush_expired");

        lua_pushcfunction(L, njt_http_lua_shdict_get_keys);
        lua_setfield(L, -2, "get_keys");

        lua_pushvalue(L, -1); /* shared mt mt */
        lua_setfield(L, -2, "__index"); /* shared mt */

        zone = lmcf->shdict_zones->elts;

        for (i = 0; i < lmcf->shdict_zones->nelts; i++) {
            ctx = zone[i]->data;

            lua_pushlstring(L, (char *) ctx->name.data, ctx->name.len);
                /* shared mt key */

            lua_createtable(L, 1 /* narr */, 0 /* nrec */);
                /* table of zone[i] */
            zone_udata = lua_newuserdata(L, sizeof(njt_shm_zone_t *));
                /* shared mt key ud */
            *zone_udata = zone[i];
            lua_rawseti(L, -2, SHDICT_USERDATA_INDEX); /* {zone[i]} */
            lua_pushvalue(L, -3); /* shared mt key ud mt */
            lua_setmetatable(L, -2); /* shared mt key ud */
            lua_rawset(L, -4); /* shared mt */
        }

        lua_pop(L, 1); /* shared */

    } else {
        lua_newtable(L);    /* njt.shared */
    }

    lua_setfield(L, -2, "shared");
}


static njt_inline njt_shm_zone_t *
njt_http_lua_shdict_get_zone(lua_State *L, int index)
{
    njt_shm_zone_t      *zone;
    njt_shm_zone_t     **zone_udata;

    lua_rawgeti(L, index, SHDICT_USERDATA_INDEX);
    zone_udata = lua_touserdata(L, -1);
    lua_pop(L, 1);

    if (zone_udata == NULL) {
        return NULL;
    }

    zone = *zone_udata;
    return zone;
}


static int
njt_http_lua_shdict_flush_expired(lua_State *L)
{
    njt_queue_t                     *q, *prev, *list_queue, *lq;
    njt_http_lua_shdict_node_t      *sd;
    njt_http_lua_shdict_ctx_t       *ctx;
    njt_shm_zone_t                  *zone;
    njt_time_t                      *tp;
    int                              freed = 0;
    int                              attempts = 0;
    njt_rbtree_node_t               *node;
    uint64_t                         now;
    int                              n;
    njt_http_lua_shdict_list_node_t *lnode;

    n = lua_gettop(L);

    if (n != 1 && n != 2) {
        return luaL_error(L, "expecting 1 or 2 argument(s), but saw %d", n);
    }

    luaL_checktype(L, 1, LUA_TTABLE);

    zone = njt_http_lua_shdict_get_zone(L, 1);
    if (zone == NULL) {
        return luaL_error(L, "bad user data for the njt_shm_zone_t pointer");
    }

    if (n == 2) {
        attempts = luaL_checkint(L, 2);
    }

    ctx = zone->data;

    njt_shmtx_lock(&ctx->shpool->mutex);

    if (njt_queue_empty(&ctx->sh->lru_queue)) {
        njt_shmtx_unlock(&ctx->shpool->mutex);
        lua_pushnumber(L, 0);
        return 1;
    }

    tp = njt_timeofday();

    now = (uint64_t) tp->sec * 1000 + tp->msec;

    q = njt_queue_last(&ctx->sh->lru_queue);

    while (q != njt_queue_sentinel(&ctx->sh->lru_queue)) {
        prev = njt_queue_prev(q);

        sd = njt_queue_data(q, njt_http_lua_shdict_node_t, queue);

        if (sd->expires != 0 && sd->expires <= now) {

            if (sd->value_type == SHDICT_TLIST) {
                list_queue = njt_http_lua_shdict_get_list_head(sd, sd->key_len);

                for (lq = njt_queue_head(list_queue);
                     lq != njt_queue_sentinel(list_queue);
                     lq = njt_queue_next(lq))
                {
                    lnode = njt_queue_data(lq, njt_http_lua_shdict_list_node_t,
                                           queue);

                    njt_slab_free_locked(ctx->shpool, lnode);
                }
            }

            njt_queue_remove(q);

            node = (njt_rbtree_node_t *)
                ((u_char *) sd - offsetof(njt_rbtree_node_t, color));

            njt_rbtree_delete(&ctx->sh->rbtree, node);
            njt_slab_free_locked(ctx->shpool, node);
            freed++;

            if (attempts && freed == attempts) {
                break;
            }
        }

        q = prev;
    }

    njt_shmtx_unlock(&ctx->shpool->mutex);

    lua_pushnumber(L, freed);
    return 1;
}


/*
 * This trades CPU for memory. This is potentially slow. O(2n)
 */

static int
njt_http_lua_shdict_get_keys(lua_State *L)
{
    njt_queue_t                 *q, *prev;
    njt_http_lua_shdict_node_t  *sd;
    njt_http_lua_shdict_ctx_t   *ctx;
    njt_shm_zone_t              *zone;
    njt_time_t                  *tp;
    int                          total = 0;
    int                          attempts = 1024;
    uint64_t                     now;
    int                          n;

    n = lua_gettop(L);

    if (n != 1 && n != 2) {
        return luaL_error(L, "expecting 1 or 2 argument(s), "
                          "but saw %d", n);
    }

    luaL_checktype(L, 1, LUA_TTABLE);

    zone = njt_http_lua_shdict_get_zone(L, 1);
    if (zone == NULL) {
        return luaL_error(L, "bad user data for the njt_shm_zone_t pointer");
    }

    if (n == 2) {
        attempts = luaL_checkint(L, 2);
    }

    ctx = zone->data;

    njt_shmtx_lock(&ctx->shpool->mutex);

    if (njt_queue_empty(&ctx->sh->lru_queue)) {
        njt_shmtx_unlock(&ctx->shpool->mutex);
        lua_createtable(L, 0, 0);
        return 1;
    }

    tp = njt_timeofday();

    now = (uint64_t) tp->sec * 1000 + tp->msec;

    /* first run through: get total number of elements we need to allocate */

    q = njt_queue_last(&ctx->sh->lru_queue);

    while (q != njt_queue_sentinel(&ctx->sh->lru_queue)) {
        prev = njt_queue_prev(q);

        sd = njt_queue_data(q, njt_http_lua_shdict_node_t, queue);

        if (sd->expires == 0 || sd->expires > now) {
            total++;
            if (attempts && total == attempts) {
                break;
            }
        }

        q = prev;
    }

    lua_createtable(L, total, 0);

    /* second run through: add keys to table */

    total = 0;
    q = njt_queue_last(&ctx->sh->lru_queue);

    while (q != njt_queue_sentinel(&ctx->sh->lru_queue)) {
        prev = njt_queue_prev(q);

        sd = njt_queue_data(q, njt_http_lua_shdict_node_t, queue);

        if (sd->expires == 0 || sd->expires > now) {
            lua_pushlstring(L, (char *) sd->data, sd->key_len);
            lua_rawseti(L, -2, ++total);
            if (attempts && total == attempts) {
                break;
            }
        }

        q = prev;
    }

    njt_shmtx_unlock(&ctx->shpool->mutex);

    /* table is at top of stack */
    return 1;
}


njt_int_t
njt_http_lua_shared_dict_get(njt_shm_zone_t *zone, u_char *key_data,
    size_t key_len, njt_http_lua_value_t *value)
{
    u_char                      *data;
    size_t                       len;
    uint32_t                     hash;
    njt_int_t                    rc;
    njt_http_lua_shdict_ctx_t   *ctx;
    njt_http_lua_shdict_node_t  *sd;

    if (zone == NULL) {
        return NJT_ERROR;
    }

    hash = njt_crc32_short(key_data, key_len);

    ctx = zone->data;

    njt_shmtx_lock(&ctx->shpool->mutex);

    rc = njt_http_lua_shdict_lookup(zone, hash, key_data, key_len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    if (rc == NJT_DECLINED || rc == NJT_DONE) {
        njt_shmtx_unlock(&ctx->shpool->mutex);

        return rc;
    }

    /* rc == NJT_OK */

    value->type = sd->value_type;

    dd("type: %d", (int) value->type);

    data = sd->data + sd->key_len;
    len = (size_t) sd->value_len;

    switch (value->type) {

    case SHDICT_TSTRING:

        if (value->value.s.data == NULL || value->value.s.len == 0) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "no string buffer "
                          "initialized");
            njt_shmtx_unlock(&ctx->shpool->mutex);
            return NJT_ERROR;
        }

        if (len > value->value.s.len) {
            len = value->value.s.len;

        } else {
            value->value.s.len = len;
        }

        njt_memcpy(value->value.s.data, data, len);
        break;

    case SHDICT_TNUMBER:

        if (len != sizeof(double)) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "bad lua number "
                          "value size found for key %*s: %lu", key_len,
                          key_data, (unsigned long) len);

            njt_shmtx_unlock(&ctx->shpool->mutex);
            return NJT_ERROR;
        }

        njt_memcpy(&value->value.n, data, len);
        break;

    case SHDICT_TBOOLEAN:

        if (len != sizeof(u_char)) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "bad lua boolean "
                          "value size found for key %*s: %lu", key_len,
                          key_data, (unsigned long) len);

            njt_shmtx_unlock(&ctx->shpool->mutex);
            return NJT_ERROR;
        }

        value->value.b = *data;
        break;

    default:
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "bad lua value type "
                      "found for key %*s: %d", key_len, key_data,
                      (int) value->type);

        njt_shmtx_unlock(&ctx->shpool->mutex);
        return NJT_ERROR;
    }

    njt_shmtx_unlock(&ctx->shpool->mutex);
    return NJT_OK;
}


static int
njt_http_lua_shdict_lpush(lua_State *L)
{
    return njt_http_lua_shdict_push_helper(L, NJT_HTTP_LUA_SHDICT_LEFT);
}


static int
njt_http_lua_shdict_rpush(lua_State *L)
{
    return njt_http_lua_shdict_push_helper(L, NJT_HTTP_LUA_SHDICT_RIGHT);
}


static int
njt_http_lua_shdict_push_helper(lua_State *L, int flags)
{
    int                              n;
    njt_str_t                        key;
    uint32_t                         hash;
    njt_int_t                        rc;
    njt_http_lua_shdict_ctx_t       *ctx;
    njt_http_lua_shdict_node_t      *sd;
    njt_str_t                        value;
    int                              value_type;
    double                           num;
    njt_rbtree_node_t               *node;
    njt_shm_zone_t                  *zone;
    njt_queue_t                     *queue, *q;
    njt_http_lua_shdict_list_node_t *lnode;

    n = lua_gettop(L);

    if (n != 3) {
        return luaL_error(L, "expecting 3 arguments, "
                          "but only seen %d", n);
    }

    if (lua_type(L, 1) != LUA_TTABLE) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    zone = njt_http_lua_shdict_get_zone(L, 1);
    if (zone == NULL) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    ctx = zone->data;

    if (lua_isnil(L, 2)) {
        lua_pushnil(L);
        lua_pushliteral(L, "nil key");
        return 2;
    }

    key.data = (u_char *) luaL_checklstring(L, 2, &key.len);

    if (key.len == 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "empty key");
        return 2;
    }

    if (key.len > 65535) {
        lua_pushnil(L);
        lua_pushliteral(L, "key too long");
        return 2;
    }

    hash = njt_crc32_short(key.data, key.len);

    value_type = lua_type(L, 3);

    switch (value_type) {

    case SHDICT_TSTRING:
        value.data = (u_char *) lua_tolstring(L, 3, &value.len);
        break;

    case SHDICT_TNUMBER:
        value.len = sizeof(double);
        num = lua_tonumber(L, 3);
        value.data = (u_char *) &num;
        break;

    default:
        lua_pushnil(L);
        lua_pushliteral(L, "bad value type");
        return 2;
    }

    njt_shmtx_lock(&ctx->shpool->mutex);

#if 1
    njt_http_lua_shdict_expire(ctx, 1);
#endif

    rc = njt_http_lua_shdict_lookup(zone, hash, key.data, key.len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    /* exists but expired */

    if (rc == NJT_DONE) {

        if (sd->value_type != SHDICT_TLIST) {
            /* TODO: reuse when length matched */

            njt_log_debug0(NJT_LOG_DEBUG_HTTP, ctx->log, 0,
                           "lua shared dict push: found old entry and value "
                           "type not matched, remove it first");

            njt_queue_remove(&sd->queue);

            node = (njt_rbtree_node_t *)
                        ((u_char *) sd - offsetof(njt_rbtree_node_t, color));

            njt_rbtree_delete(&ctx->sh->rbtree, node);

            njt_slab_free_locked(ctx->shpool, node);

            dd("go to init_list");
            goto init_list;
        }

        njt_log_debug0(NJT_LOG_DEBUG_HTTP, ctx->log, 0,
                       "lua shared dict push: found old entry and value "
                       "type matched, reusing it");

        sd->expires = 0;
        sd->value_len = 0;
        /* free list nodes */

        queue = njt_http_lua_shdict_get_list_head(sd, key.len);

        for (q = njt_queue_head(queue);
             q != njt_queue_sentinel(queue);
             q = njt_queue_next(q))
        {
            /* TODO: reuse matched size list node */
            lnode = njt_queue_data(q, njt_http_lua_shdict_list_node_t, queue);
            njt_slab_free_locked(ctx->shpool, lnode);
        }

        njt_queue_init(queue);

        njt_queue_remove(&sd->queue);
        njt_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

        dd("go to push_node");
        goto push_node;
    }

    /* exists and not expired */

    if (rc == NJT_OK) {

        if (sd->value_type != SHDICT_TLIST) {
            njt_shmtx_unlock(&ctx->shpool->mutex);

            lua_pushnil(L);
            lua_pushliteral(L, "value not a list");
            return 2;
        }

        queue = njt_http_lua_shdict_get_list_head(sd, key.len);

        njt_queue_remove(&sd->queue);
        njt_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

        dd("go to push_node");
        goto push_node;
    }

    /* rc == NJT_DECLINED, not found */

init_list:

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, ctx->log, 0,
                   "lua shared dict list: creating a new entry");

    /* NOTICE: we assume the begin point aligned in slab, be careful */
    n = offsetof(njt_rbtree_node_t, color)
        + offsetof(njt_http_lua_shdict_node_t, data)
        + key.len
        + sizeof(njt_queue_t);

    dd("length before aligned: %d", n);

    n = (int) (uintptr_t) njt_align_ptr(n, NJT_ALIGNMENT);

    dd("length after aligned: %d", n);

    node = njt_slab_alloc_locked(ctx->shpool, n);

    if (node == NULL) {
        njt_shmtx_unlock(&ctx->shpool->mutex);

        lua_pushboolean(L, 0);
        lua_pushliteral(L, "no memory");
        return 2;
    }

    sd = (njt_http_lua_shdict_node_t *) &node->color;

    queue = njt_http_lua_shdict_get_list_head(sd, key.len);

    node->key = hash;
    sd->key_len = (u_short) key.len;

    sd->expires = 0;

    sd->value_len = 0;

    dd("setting value type to %d", (int) SHDICT_TLIST);

    sd->value_type = (uint8_t) SHDICT_TLIST;

    njt_memcpy(sd->data, key.data, key.len);

    njt_queue_init(queue);

    njt_rbtree_insert(&ctx->sh->rbtree, node);

    njt_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

push_node:

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, ctx->log, 0,
                   "lua shared dict list: creating a new list node");

    n = offsetof(njt_http_lua_shdict_list_node_t, data)
        + value.len;

    dd("list node length: %d", n);

    lnode = njt_slab_alloc_locked(ctx->shpool, n);

    if (lnode == NULL) {

        if (sd->value_len == 0) {

            njt_log_debug0(NJT_LOG_DEBUG_HTTP, ctx->log, 0,
                           "lua shared dict list: no memory for create"
                           " list node and list empty, remove it");

            njt_queue_remove(&sd->queue);

            node = (njt_rbtree_node_t *)
                        ((u_char *) sd - offsetof(njt_rbtree_node_t, color));

            njt_rbtree_delete(&ctx->sh->rbtree, node);

            njt_slab_free_locked(ctx->shpool, node);
        }

        njt_shmtx_unlock(&ctx->shpool->mutex);

        lua_pushnil(L);
        lua_pushliteral(L, "no memory");
        return 2;
    }

    dd("setting list length to %d", sd->value_len + 1);

    sd->value_len = sd->value_len + 1;

    dd("setting list node value length to %d", (int) value.len);

    lnode->value_len = (uint32_t) value.len;

    dd("setting list node value type to %d", value_type);

    lnode->value_type = (uint8_t) value_type;

    njt_memcpy(lnode->data, value.data, value.len);

    if (flags == NJT_HTTP_LUA_SHDICT_LEFT) {
        njt_queue_insert_head(queue, &lnode->queue);

    } else {
        njt_queue_insert_tail(queue, &lnode->queue);
    }

    njt_shmtx_unlock(&ctx->shpool->mutex);

    lua_pushnumber(L, sd->value_len);
    return 1;
}


static int
njt_http_lua_shdict_lpop(lua_State *L)
{
    return njt_http_lua_shdict_pop_helper(L, NJT_HTTP_LUA_SHDICT_LEFT);
}


static int
njt_http_lua_shdict_rpop(lua_State *L)
{
    return njt_http_lua_shdict_pop_helper(L, NJT_HTTP_LUA_SHDICT_RIGHT);
}


static int
njt_http_lua_shdict_pop_helper(lua_State *L, int flags)
{
    int                              n;
    njt_str_t                        name;
    njt_str_t                        key;
    uint32_t                         hash;
    njt_int_t                        rc;
    njt_http_lua_shdict_ctx_t       *ctx;
    njt_http_lua_shdict_node_t      *sd;
    njt_str_t                        value;
    int                              value_type;
    double                           num;
    njt_rbtree_node_t               *node;
    njt_shm_zone_t                  *zone;
    njt_queue_t                     *queue;
    njt_http_lua_shdict_list_node_t *lnode;

    n = lua_gettop(L);

    if (n != 2) {
        return luaL_error(L, "expecting 2 arguments, "
                          "but only seen %d", n);
    }

    if (lua_type(L, 1) != LUA_TTABLE) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    zone = njt_http_lua_shdict_get_zone(L, 1);
    if (zone == NULL) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    ctx = zone->data;
    name = ctx->name;

    if (lua_isnil(L, 2)) {
        lua_pushnil(L);
        lua_pushliteral(L, "nil key");
        return 2;
    }

    key.data = (u_char *) luaL_checklstring(L, 2, &key.len);

    if (key.len == 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "empty key");
        return 2;
    }

    if (key.len > 65535) {
        lua_pushnil(L);
        lua_pushliteral(L, "key too long");
        return 2;
    }

    hash = njt_crc32_short(key.data, key.len);

    njt_shmtx_lock(&ctx->shpool->mutex);

#if 1
    njt_http_lua_shdict_expire(ctx, 1);
#endif

    rc = njt_http_lua_shdict_lookup(zone, hash, key.data, key.len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    if (rc == NJT_DECLINED || rc == NJT_DONE) {
        njt_shmtx_unlock(&ctx->shpool->mutex);
        lua_pushnil(L);
        return 1;
    }

    /* rc == NJT_OK */

    if (sd->value_type != SHDICT_TLIST) {
        njt_shmtx_unlock(&ctx->shpool->mutex);

        lua_pushnil(L);
        lua_pushliteral(L, "value not a list");
        return 2;
    }

    if (sd->value_len <= 0) {
        njt_shmtx_unlock(&ctx->shpool->mutex);

        return luaL_error(L, "bad lua list length found for key %s "
                          "in shared_dict %s: %lu", key.data, name.data,
                          (unsigned long) sd->value_len);
    }

    queue = njt_http_lua_shdict_get_list_head(sd, key.len);

    if (flags == NJT_HTTP_LUA_SHDICT_LEFT) {
        queue = njt_queue_head(queue);

    } else {
        queue = njt_queue_last(queue);
    }

    lnode = njt_queue_data(queue, njt_http_lua_shdict_list_node_t, queue);

    value_type = lnode->value_type;

    dd("data: %p", lnode->data);
    dd("value len: %d", (int) sd->value_len);

    value.data = lnode->data;
    value.len = (size_t) lnode->value_len;

    switch (value_type) {

    case SHDICT_TSTRING:

        lua_pushlstring(L, (char *) value.data, value.len);
        break;

    case SHDICT_TNUMBER:

        if (value.len != sizeof(double)) {

            njt_shmtx_unlock(&ctx->shpool->mutex);

            return luaL_error(L, "bad lua list node number value size found "
                              "for key %s in shared_dict %s: %lu", key.data,
                              name.data, (unsigned long) value.len);
        }

        njt_memcpy(&num, value.data, sizeof(double));

        lua_pushnumber(L, num);
        break;

    default:

        njt_shmtx_unlock(&ctx->shpool->mutex);

        return luaL_error(L, "bad list node value type found for key %s in "
                          "shared_dict %s: %d", key.data, name.data,
                          value_type);
    }

    njt_queue_remove(queue);

    njt_slab_free_locked(ctx->shpool, lnode);

    if (sd->value_len == 1) {

        njt_log_debug0(NJT_LOG_DEBUG_HTTP, ctx->log, 0,
                       "lua shared dict list: empty node after pop, "
                       "remove it");

        njt_queue_remove(&sd->queue);

        node = (njt_rbtree_node_t *)
                    ((u_char *) sd - offsetof(njt_rbtree_node_t, color));

        njt_rbtree_delete(&ctx->sh->rbtree, node);

        njt_slab_free_locked(ctx->shpool, node);

    } else {
        sd->value_len = sd->value_len - 1;

        njt_queue_remove(&sd->queue);
        njt_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);
    }

    njt_shmtx_unlock(&ctx->shpool->mutex);

    return 1;
}


static int
njt_http_lua_shdict_llen(lua_State *L)
{
    int                          n;
    njt_str_t                    key;
    uint32_t                     hash;
    njt_int_t                    rc;
    njt_http_lua_shdict_ctx_t   *ctx;
    njt_http_lua_shdict_node_t  *sd;
    njt_shm_zone_t              *zone;

    n = lua_gettop(L);

    if (n != 2) {
        return luaL_error(L, "expecting 2 arguments, "
                          "but only seen %d", n);
    }

    if (lua_type(L, 1) != LUA_TTABLE) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    zone = njt_http_lua_shdict_get_zone(L, 1);
    if (zone == NULL) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    ctx = zone->data;

    if (lua_isnil(L, 2)) {
        lua_pushnil(L);
        lua_pushliteral(L, "nil key");
        return 2;
    }

    key.data = (u_char *) luaL_checklstring(L, 2, &key.len);

    if (key.len == 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "empty key");
        return 2;
    }

    if (key.len > 65535) {
        lua_pushnil(L);
        lua_pushliteral(L, "key too long");
        return 2;
    }

    hash = njt_crc32_short(key.data, key.len);

    njt_shmtx_lock(&ctx->shpool->mutex);

#if 1
    njt_http_lua_shdict_expire(ctx, 1);
#endif

    rc = njt_http_lua_shdict_lookup(zone, hash, key.data, key.len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    if (rc == NJT_OK) {

        if (sd->value_type != SHDICT_TLIST) {
            njt_shmtx_unlock(&ctx->shpool->mutex);

            lua_pushnil(L);
            lua_pushliteral(L, "value not a list");
            return 2;
        }

        njt_queue_remove(&sd->queue);
        njt_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

        njt_shmtx_unlock(&ctx->shpool->mutex);

        lua_pushnumber(L, (lua_Number) sd->value_len);
        return 1;
    }

    njt_shmtx_unlock(&ctx->shpool->mutex);

    lua_pushnumber(L, 0);
    return 1;
}


njt_shm_zone_t *
njt_http_lua_find_zone(u_char *name_data, size_t name_len)
{
    njt_str_t                       *name;
    njt_uint_t                       i;
    njt_shm_zone_t                  *zone;
    njt_http_lua_shm_zone_ctx_t     *ctx;
    volatile njt_list_part_t        *part;

    part = &njt_cycle->shared_memory.part;
    zone = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            zone = part->elts;
            i = 0;
        }

        name = &zone[i].shm.name;

        dd("name: [%.*s] %d", (int) name->len, name->data, (int) name->len);
        dd("name2: [%.*s] %d", (int) name_len, name_data, (int) name_len);

        if (name->len == name_len
            && njt_strncmp(name->data, name_data, name_len) == 0)
        {
            ctx = (njt_http_lua_shm_zone_ctx_t *) zone[i].data;
            return &ctx->zone;
        }
    }

    return NULL;
}


njt_shm_zone_t *
njt_http_lua_ffi_shdict_udata_to_zone(void *zone_udata)
{
    if (zone_udata == NULL) {
        return NULL;
    }

    return *(njt_shm_zone_t **) zone_udata;
}


int
njt_http_lua_ffi_shdict_store(njt_shm_zone_t *zone, int op, u_char *key,
    size_t key_len, int value_type, u_char *str_value_buf,
    size_t str_value_len, double num_value, long exptime, int user_flags,
    char **errmsg, int *forcible)
{
    int                          i, n;
    u_char                       c, *p;
    uint32_t                     hash;
    njt_int_t                    rc;
    njt_time_t                  *tp;
    njt_queue_t                 *queue, *q;
    njt_rbtree_node_t           *node;
    njt_http_lua_shdict_ctx_t   *ctx;
    njt_http_lua_shdict_node_t  *sd;

    dd("exptime: %ld", exptime);

    ctx = zone->data;

    *forcible = 0;

    hash = njt_crc32_short(key, key_len);

    switch (value_type) {

    case SHDICT_TSTRING:
        /* do nothing */
        break;

    case SHDICT_TNUMBER:
        dd("num value: %lf", num_value);
        str_value_buf = (u_char *) &num_value;
        str_value_len = sizeof(double);
        break;

    case SHDICT_TBOOLEAN:
        c = num_value ? 1 : 0;
        str_value_buf = &c;
        str_value_len = sizeof(u_char);
        break;

    case LUA_TNIL:
        if (op & (NJT_HTTP_LUA_SHDICT_ADD|NJT_HTTP_LUA_SHDICT_REPLACE)) {
            *errmsg = "attempt to add or replace nil values";
            return NJT_ERROR;
        }

        str_value_buf = NULL;
        str_value_len = 0;
        break;

    default:
        *errmsg = "unsupported value type";
        return NJT_ERROR;
    }

    njt_shmtx_lock(&ctx->shpool->mutex);

#if 1
    njt_http_lua_shdict_expire(ctx, 1);
#endif

    rc = njt_http_lua_shdict_lookup(zone, hash, key, key_len, &sd);

    dd("lookup returns %d", (int) rc);

    if (op & NJT_HTTP_LUA_SHDICT_REPLACE) {

        if (rc == NJT_DECLINED || rc == NJT_DONE) {
            njt_shmtx_unlock(&ctx->shpool->mutex);
            *errmsg = "not found";
            return NJT_DECLINED;
        }

        /* rc == NJT_OK */

        goto replace;
    }

    if (op & NJT_HTTP_LUA_SHDICT_ADD) {

        if (rc == NJT_OK) {
            njt_shmtx_unlock(&ctx->shpool->mutex);
            *errmsg = "exists";
            return NJT_DECLINED;
        }

        if (rc == NJT_DONE) {
            /* exists but expired */

            dd("go to replace");
            goto replace;
        }

        /* rc == NJT_DECLINED */

        dd("go to insert");
        goto insert;
    }

    if (rc == NJT_OK || rc == NJT_DONE) {

        if (value_type == LUA_TNIL) {
            goto remove;
        }

replace:

        if (str_value_buf
            && str_value_len == (size_t) sd->value_len
            && sd->value_type != SHDICT_TLIST)
        {

            njt_log_debug0(NJT_LOG_DEBUG_HTTP, ctx->log, 0,
                           "lua shared dict set: found old entry and value "
                           "size matched, reusing it");

            njt_queue_remove(&sd->queue);
            njt_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

            if (exptime > 0) {
                tp = njt_timeofday();
                sd->expires = (uint64_t) tp->sec * 1000 + tp->msec
                              + (uint64_t) exptime;

            } else {
                sd->expires = 0;
            }

            sd->user_flags = user_flags;

            dd("setting value type to %d", value_type);

            sd->value_type = (uint8_t) value_type;

            njt_memcpy(sd->data + key_len, str_value_buf, str_value_len);

            njt_shmtx_unlock(&ctx->shpool->mutex);

            return NJT_OK;
        }

        njt_log_debug0(NJT_LOG_DEBUG_HTTP, ctx->log, 0,
                       "lua shared dict set: found old entry but value size "
                       "NOT matched, removing it first");

remove:

        if (sd->value_type == SHDICT_TLIST) {
            queue = njt_http_lua_shdict_get_list_head(sd, key_len);

            for (q = njt_queue_head(queue);
                 q != njt_queue_sentinel(queue);
                 q = njt_queue_next(q))
            {
                p = (u_char *) njt_queue_data(q,
                                              njt_http_lua_shdict_list_node_t,
                                              queue);

                njt_slab_free_locked(ctx->shpool, p);
            }
        }

        njt_queue_remove(&sd->queue);

        node = (njt_rbtree_node_t *)
                   ((u_char *) sd - offsetof(njt_rbtree_node_t, color));

        njt_rbtree_delete(&ctx->sh->rbtree, node);

        njt_slab_free_locked(ctx->shpool, node);

    }

insert:

    /* rc == NJT_DECLINED or value size unmatch */

    if (str_value_buf == NULL) {
        njt_shmtx_unlock(&ctx->shpool->mutex);
        return NJT_OK;
    }

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, ctx->log, 0,
                   "lua shared dict set: creating a new entry");

    n = offsetof(njt_rbtree_node_t, color)
        + offsetof(njt_http_lua_shdict_node_t, data)
        + key_len
        + str_value_len;

    node = njt_slab_alloc_locked(ctx->shpool, n);

    if (node == NULL) {

        if (op & NJT_HTTP_LUA_SHDICT_SAFE_STORE) {
            njt_shmtx_unlock(&ctx->shpool->mutex);

            *errmsg = "no memory";
            return NJT_ERROR;
        }

        njt_log_debug2(NJT_LOG_DEBUG_HTTP, ctx->log, 0,
                       "lua shared dict set: overriding non-expired items "
                       "due to memory shortage for entry \"%*s\"", key_len,
                       key);

        for (i = 0; i < 30; i++) {
            if (njt_http_lua_shdict_expire(ctx, 0) == 0) {
                break;
            }

            *forcible = 1;

            node = njt_slab_alloc_locked(ctx->shpool, n);
            if (node != NULL) {
                goto allocated;
            }
        }

        njt_shmtx_unlock(&ctx->shpool->mutex);

        *errmsg = "no memory";
        return NJT_ERROR;
    }

allocated:

    sd = (njt_http_lua_shdict_node_t *) &node->color;

    node->key = hash;
    sd->key_len = (u_short) key_len;

    if (exptime > 0) {
        tp = njt_timeofday();
        sd->expires = (uint64_t) tp->sec * 1000 + tp->msec
                      + (uint64_t) exptime;

    } else {
        sd->expires = 0;
    }

    sd->user_flags = user_flags;
    sd->value_len = (uint32_t) str_value_len;
    dd("setting value type to %d", value_type);
    sd->value_type = (uint8_t) value_type;

    p = njt_copy(sd->data, key, key_len);
    njt_memcpy(p, str_value_buf, str_value_len);

    njt_rbtree_insert(&ctx->sh->rbtree, node);
    njt_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);
    njt_shmtx_unlock(&ctx->shpool->mutex);

    return NJT_OK;
}


int
njt_http_lua_ffi_shdict_get(njt_shm_zone_t *zone, u_char *key,
    size_t key_len, int *value_type, u_char **str_value_buf,
    size_t *str_value_len, double *num_value, int *user_flags,
    int get_stale, int *is_stale, char **err)
{
    njt_str_t                    name;
    uint32_t                     hash;
    njt_int_t                    rc;
    njt_http_lua_shdict_ctx_t   *ctx;
    njt_http_lua_shdict_node_t  *sd;
    njt_str_t                    value;

    *err = NULL;

    ctx = zone->data;
    name = ctx->name;

    hash = njt_crc32_short(key, key_len);

#if (NJT_DEBUG)
    njt_log_debug3(NJT_LOG_DEBUG_HTTP, ctx->log, 0,
                   "fetching key \"%*s\" in shared dict \"%V\"", key_len,
                   key, &name);
#endif /* NJT_DEBUG */

    njt_shmtx_lock(&ctx->shpool->mutex);

#if 1
    if (!get_stale) {
        njt_http_lua_shdict_expire(ctx, 1);
    }
#endif

    rc = njt_http_lua_shdict_lookup(zone, hash, key, key_len, &sd);

    dd("shdict lookup returns %d", (int) rc);

    if (rc == NJT_DECLINED || (rc == NJT_DONE && !get_stale)) {
        njt_shmtx_unlock(&ctx->shpool->mutex);
        *value_type = LUA_TNIL;
        return NJT_OK;
    }

    /* rc == NJT_OK || (rc == NJT_DONE && get_stale) */

    *value_type = sd->value_type;

    dd("data: %p", sd->data);
    dd("key len: %d", (int) sd->key_len);

    value.data = sd->data + sd->key_len;
    value.len = (size_t) sd->value_len;

    if (*str_value_len < (size_t) value.len) {
        if (*value_type == SHDICT_TBOOLEAN) {
            njt_shmtx_unlock(&ctx->shpool->mutex);
            return NJT_ERROR;
        }

        if (*value_type == SHDICT_TSTRING) {
            *str_value_buf = malloc(value.len);
            if (*str_value_buf == NULL) {
                njt_shmtx_unlock(&ctx->shpool->mutex);
                return NJT_ERROR;
            }
        }
    }

    switch (*value_type) {

    case SHDICT_TSTRING:
        *str_value_len = value.len;
        njt_memcpy(*str_value_buf, value.data, value.len);
        break;

    case SHDICT_TNUMBER:

        if (value.len != sizeof(double)) {
            njt_shmtx_unlock(&ctx->shpool->mutex);
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                          "bad lua number value size found for key %*s "
                          "in shared_dict %V: %z", key_len, key,
                          &name, value.len);
            return NJT_ERROR;
        }

        *str_value_len = value.len;
        njt_memcpy(num_value, value.data, sizeof(double));
        break;

    case SHDICT_TBOOLEAN:

        if (value.len != sizeof(u_char)) {
            njt_shmtx_unlock(&ctx->shpool->mutex);
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                          "bad lua boolean value size found for key %*s "
                          "in shared_dict %V: %z", key_len, key, &name,
                          value.len);
            return NJT_ERROR;
        }

        njt_memcpy(*str_value_buf, value.data, value.len);
        break;

    case SHDICT_TLIST:

        njt_shmtx_unlock(&ctx->shpool->mutex);

        *err = "value is a list";
        return NJT_ERROR;

    default:

        njt_shmtx_unlock(&ctx->shpool->mutex);
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                      "bad value type found for key %*s in "
                      "shared_dict %V: %d", key_len, key, &name,
                      *value_type);
        return NJT_ERROR;
    }

    *user_flags = sd->user_flags;
    dd("user flags: %d", *user_flags);

    njt_shmtx_unlock(&ctx->shpool->mutex);

    if (get_stale) {

        /* always return value, flags, stale */

        *is_stale = (rc == NJT_DONE);
        return NJT_OK;
    }

    return NJT_OK;
}


int
njt_http_lua_ffi_shdict_incr(njt_shm_zone_t *zone, u_char *key,
    size_t key_len, double *value, char **err, int has_init, double init,
    long init_ttl, int *forcible)
{
    int                          i, n;
    uint32_t                     hash;
    njt_int_t                    rc;
    njt_time_t                  *tp = NULL;
    njt_http_lua_shdict_ctx_t   *ctx;
    njt_http_lua_shdict_node_t  *sd;
    double                       num;
    njt_rbtree_node_t           *node;
    u_char                      *p;
    njt_queue_t                 *queue, *q;

    if (init_ttl > 0) {
        tp = njt_timeofday();
    }

    ctx = zone->data;

    *forcible = 0;

    hash = njt_crc32_short(key, key_len);

    dd("looking up key %.*s in shared dict %.*s", (int) key_len, key,
       (int) ctx->name.len, ctx->name.data);

    njt_shmtx_lock(&ctx->shpool->mutex);
#if 1
    njt_http_lua_shdict_expire(ctx, 1);
#endif
    rc = njt_http_lua_shdict_lookup(zone, hash, key, key_len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    if (rc == NJT_DECLINED || rc == NJT_DONE) {
        if (!has_init) {
            njt_shmtx_unlock(&ctx->shpool->mutex);
            *err = "not found";
            return NJT_ERROR;
        }

        /* add value */
        num = *value + init;

        if (rc == NJT_DONE) {

            /* found an expired item */

            if ((size_t) sd->value_len == sizeof(double)
                && sd->value_type != SHDICT_TLIST)
            {
                njt_log_debug0(NJT_LOG_DEBUG_HTTP, ctx->log, 0,
                               "lua shared dict incr: found old entry and "
                               "value size matched, reusing it");

                njt_queue_remove(&sd->queue);
                njt_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

                dd("go to setvalue");
                goto setvalue;
            }

            dd("go to remove");
            goto remove;
        }

        dd("go to insert");
        goto insert;
    }

    /* rc == NJT_OK */

    if (sd->value_type != SHDICT_TNUMBER || sd->value_len != sizeof(double)) {
        njt_shmtx_unlock(&ctx->shpool->mutex);
        *err = "not a number";
        return NJT_ERROR;
    }

    njt_queue_remove(&sd->queue);
    njt_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

    dd("setting value type to %d", (int) sd->value_type);

    p = sd->data + key_len;

    njt_memcpy(&num, p, sizeof(double));
    num += *value;

    njt_memcpy(p, (double *) &num, sizeof(double));

    njt_shmtx_unlock(&ctx->shpool->mutex);

    *value = num;
    return NJT_OK;

remove:

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, ctx->log, 0,
                   "lua shared dict incr: found old entry but value size "
                   "NOT matched, removing it first");

    if (sd->value_type == SHDICT_TLIST) {
        queue = njt_http_lua_shdict_get_list_head(sd, key_len);

        for (q = njt_queue_head(queue);
             q != njt_queue_sentinel(queue);
             q = njt_queue_next(q))
        {
            p = (u_char *) njt_queue_data(q, njt_http_lua_shdict_list_node_t,
                                          queue);

            njt_slab_free_locked(ctx->shpool, p);
        }
    }

    njt_queue_remove(&sd->queue);

    node = (njt_rbtree_node_t *)
               ((u_char *) sd - offsetof(njt_rbtree_node_t, color));

    njt_rbtree_delete(&ctx->sh->rbtree, node);

    njt_slab_free_locked(ctx->shpool, node);

insert:

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, ctx->log, 0,
                   "lua shared dict incr: creating a new entry");

    n = offsetof(njt_rbtree_node_t, color)
        + offsetof(njt_http_lua_shdict_node_t, data)
        + key_len
        + sizeof(double);

    node = njt_slab_alloc_locked(ctx->shpool, n);

    if (node == NULL) {

        njt_log_debug2(NJT_LOG_DEBUG_HTTP, ctx->log, 0,
                       "lua shared dict incr: overriding non-expired items "
                       "due to memory shortage for entry \"%*s\"", key_len,
                       key);

        for (i = 0; i < 30; i++) {
            if (njt_http_lua_shdict_expire(ctx, 0) == 0) {
                break;
            }

            *forcible = 1;

            node = njt_slab_alloc_locked(ctx->shpool, n);
            if (node != NULL) {
                goto allocated;
            }
        }

        njt_shmtx_unlock(&ctx->shpool->mutex);

        *err = "no memory";
        return NJT_ERROR;
    }

allocated:

    sd = (njt_http_lua_shdict_node_t *) &node->color;

    node->key = hash;

    sd->key_len = (u_short) key_len;

    sd->value_len = (uint32_t) sizeof(double);

    njt_rbtree_insert(&ctx->sh->rbtree, node);

    njt_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

setvalue:

    sd->user_flags = 0;

    if (init_ttl > 0) {
        sd->expires = (uint64_t) tp->sec * 1000 + tp->msec
                      + (uint64_t) init_ttl;

    } else {
        sd->expires = 0;
    }

    dd("setting value type to %d", LUA_TNUMBER);

    sd->value_type = (uint8_t) LUA_TNUMBER;

    p = njt_copy(sd->data, key, key_len);
    njt_memcpy(p, (double *) &num, sizeof(double));

    njt_shmtx_unlock(&ctx->shpool->mutex);

    *value = num;
    return NJT_OK;
}


int
njt_http_lua_ffi_shdict_flush_all(njt_shm_zone_t *zone)
{
    njt_queue_t                 *q;
    njt_http_lua_shdict_node_t  *sd;
    njt_http_lua_shdict_ctx_t   *ctx;

    ctx = zone->data;

    njt_shmtx_lock(&ctx->shpool->mutex);

    for (q = njt_queue_head(&ctx->sh->lru_queue);
         q != njt_queue_sentinel(&ctx->sh->lru_queue);
         q = njt_queue_next(q))
    {
        sd = njt_queue_data(q, njt_http_lua_shdict_node_t, queue);
        sd->expires = 1;
    }

    njt_http_lua_shdict_expire(ctx, 0);

    njt_shmtx_unlock(&ctx->shpool->mutex);

    return NJT_OK;
}


static njt_int_t
njt_http_lua_shdict_peek(njt_shm_zone_t *shm_zone, njt_uint_t hash,
    u_char *kdata, size_t klen, njt_http_lua_shdict_node_t **sdp)
{
    njt_int_t                    rc;
    njt_rbtree_node_t           *node, *sentinel;
    njt_http_lua_shdict_ctx_t   *ctx;
    njt_http_lua_shdict_node_t  *sd;

    ctx = shm_zone->data;

    node = ctx->sh->rbtree.root;
    sentinel = ctx->sh->rbtree.sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        sd = (njt_http_lua_shdict_node_t *) &node->color;

        rc = njt_memn2cmp(kdata, sd->data, klen, (size_t) sd->key_len);

        if (rc == 0) {
            *sdp = sd;

            return NJT_OK;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    *sdp = NULL;

    return NJT_DECLINED;
}


long
njt_http_lua_ffi_shdict_get_ttl(njt_shm_zone_t *zone, u_char *key,
    size_t key_len)
{
    uint32_t                     hash;
    uint64_t                     now;
    uint64_t                     expires;
    njt_int_t                    rc;
    njt_time_t                  *tp;
    njt_http_lua_shdict_ctx_t   *ctx;
    njt_http_lua_shdict_node_t  *sd;

    ctx = zone->data;
    hash = njt_crc32_short(key, key_len);

    njt_shmtx_lock(&ctx->shpool->mutex);

    rc = njt_http_lua_shdict_peek(zone, hash, key, key_len, &sd);

    if (rc == NJT_DECLINED) {
        njt_shmtx_unlock(&ctx->shpool->mutex);

        return NJT_DECLINED;
    }

    /* rc == NJT_OK */

    expires = sd->expires;

    njt_shmtx_unlock(&ctx->shpool->mutex);

    if (expires == 0) {
        return 0;
    }

    tp = njt_timeofday();
    now = (uint64_t) tp->sec * 1000 + tp->msec;

    return expires - now;
}


int
njt_http_lua_ffi_shdict_set_expire(njt_shm_zone_t *zone, u_char *key,
    size_t key_len, long exptime)
{
    uint32_t                     hash;
    njt_int_t                    rc;
    njt_time_t                  *tp = NULL;
    njt_http_lua_shdict_ctx_t   *ctx;
    njt_http_lua_shdict_node_t  *sd;

    if (exptime > 0) {
        tp = njt_timeofday();
    }

    ctx = zone->data;
    hash = njt_crc32_short(key, key_len);

    njt_shmtx_lock(&ctx->shpool->mutex);

    rc = njt_http_lua_shdict_peek(zone, hash, key, key_len, &sd);

    if (rc == NJT_DECLINED) {
        njt_shmtx_unlock(&ctx->shpool->mutex);

        return NJT_DECLINED;
    }

    /* rc == NJT_OK */

    if (exptime > 0) {
        sd->expires = (uint64_t) tp->sec * 1000 + tp->msec
                      + (uint64_t) exptime;

    } else {
        sd->expires = 0;
    }

    njt_shmtx_unlock(&ctx->shpool->mutex);

    return NJT_OK;
}


size_t
njt_http_lua_ffi_shdict_capacity(njt_shm_zone_t *zone)
{
    return zone->shm.size;
}


#if (njet_version >= 1011007)
size_t
njt_http_lua_ffi_shdict_free_space(njt_shm_zone_t *zone)
{
    size_t                       bytes;
    njt_http_lua_shdict_ctx_t   *ctx;

    ctx = zone->data;

    njt_shmtx_lock(&ctx->shpool->mutex);
    bytes = ctx->shpool->pfree * njt_pagesize;
    njt_shmtx_unlock(&ctx->shpool->mutex);

    return bytes;
}
#endif


#if (NJT_DARWIN)
int
njt_http_lua_ffi_shdict_get_macos(njt_http_lua_shdict_get_params_t *p)
{
    return njt_http_lua_ffi_shdict_get(p->zone,
                                       (u_char *) p->key, p->key_len,
                                       p->value_type, p->str_value_buf,
                                       p->str_value_len, p->num_value,
                                       p->user_flags, p->get_stale,
                                       p->is_stale, p->errmsg);
}


int
njt_http_lua_ffi_shdict_store_macos(njt_http_lua_shdict_store_params_t *p)
{
    return njt_http_lua_ffi_shdict_store(p->zone, p->op,
                                         (u_char *) p->key, p->key_len,
                                         p->value_type,
                                         (u_char *) p->str_value_buf,
                                         p->str_value_len, p->num_value,
                                         p->exptime, p->user_flags,
                                         p->errmsg, p->forcible);
}


int
njt_http_lua_ffi_shdict_incr_macos(njt_http_lua_shdict_incr_params_t *p)
{
    return njt_http_lua_ffi_shdict_incr(p->zone, (u_char *) p->key, p->key_len,
                                        p->num_value, p->errmsg,
                                        p->has_init, p->init, p->init_ttl,
                                        p->forcible);
}
#endif


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
