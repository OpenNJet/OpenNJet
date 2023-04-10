
/*
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_hash_util.h>

static njt_int_t
njt_lvlhsh_map_test(njt_lvlhsh_query_t *lhq, void *data);
const njt_lvlhsh_proto_t njt_lvlhsh_map_proto = {
    NJT_LVLHSH_DEFAULT,
    njt_lvlhsh_map_test,
    njt_lvlhsh_alloc,
    njt_lvlhsh_free,
};

typedef struct
{
    njt_str_t key;
    intptr_t value;
} njt_lvlhsh_map_keyval_t;

static njt_int_t
njt_lvlhsh_map_test(njt_lvlhsh_query_t *lhq, void *data)
{
    njt_lvlhsh_map_keyval_t *kv = data;
    if (lhq->key.len == kv->key.len && njt_memcmp(lhq->key.data, kv->key.data, lhq->key.len) == 0)
    {
        return NJT_OK;
    }

    return NJT_DECLINED;
}

njt_int_t njt_lvlhsh_map_put(njt_lvlhash_map_t *map, njt_str_t *key, intptr_t value, intptr_t *old_value)
{
    njt_int_t rc;
    njt_lvlhsh_query_t lhq;
    njt_lvlhsh_map_keyval_t *kv;
    njt_log_t *log;
    log = map->log;
    if (log == NULL)
    {
        log = njt_cycle->log;
    }

    kv = njt_calloc(sizeof(njt_lvlhsh_map_keyval_t), log);
    if (kv == NULL)
    {
        return NJT_DECLINED;
    }
    kv->key.data = njt_calloc(key->len, log);
    if (kv->key.data == NULL)
    {
        return NJT_DECLINED;
    }
    kv->key.len = key->len;
    njt_memcpy(kv->key.data, key->data, key->len);
    kv->value = value;
    *old_value= value;

    lhq.proto = &njt_lvlhsh_map_proto;
    lhq.pool = log;
    lhq.key_hash = njt_murmur_hash2(key->data, key->len);
    lhq.key.data = key->data;
    lhq.key.len = key->len;

    /* if key exists, then its value will be replaced */
    lhq.replace = 1;
    lhq.value = kv;

    rc = njt_lvlhsh_insert(&map->lh, &lhq);
    if (kv != lhq.value)
    {
        *old_value=((njt_lvlhsh_map_keyval_t *)lhq.value)->value;
        /* value has been replaced, freeing an old one */
        njt_free(((njt_lvlhsh_map_keyval_t *)lhq.value)->key.data);
        njt_free(lhq.value);
    }

    return rc;
}

njt_int_t njt_lvlhsh_map_get(njt_lvlhash_map_t *map, njt_str_t *key, intptr_t *vp)
{
    njt_int_t rc;
    njt_lvlhsh_query_t lhq;
    njt_log_t *log;
    log = map->log;
    if (log == NULL)
    {
        log = njt_cycle->log;
    }

    lhq.proto = &njt_lvlhsh_map_proto;
    lhq.pool = log;
    lhq.key_hash = njt_murmur_hash2(key->data, key->len);
    lhq.key.data = key->data;
    lhq.key.len = key->len;
    rc = njt_lvlhsh_find(&map->lh, &lhq);

    if (rc == NJT_OK)
    {
        *vp = ((njt_lvlhsh_map_keyval_t *)lhq.value)->value;
    }
    return rc;
}

njt_int_t njt_lvlhsh_map_remove(njt_lvlhash_map_t *map, njt_str_t *key)
{
    njt_int_t rc;
    njt_lvlhsh_query_t lhq;
    njt_log_t *log;
    log = map->log;
    if (log == NULL)
    {
        log = njt_cycle->log;
    }
    lhq.proto = &njt_lvlhsh_map_proto;
    lhq.pool = log;
    lhq.key_hash = njt_murmur_hash2(key->data, key->len);
    lhq.key.data = key->data;
    lhq.key.len = key->len;
    rc = njt_lvlhsh_delete(&map->lh, &lhq);
    if (rc == NJT_OK)
    {
        njt_free(((njt_lvlhsh_map_keyval_t *)lhq.value)->key.data);
        njt_free(lhq.value);
    }
    return rc;
}