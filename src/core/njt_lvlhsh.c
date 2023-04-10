/*
 * Copyright (C) 2023 Web Server LLC
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>


/*
 * The level hash consists of hierarchical levels of arrays of pointers.
 * The pointers may point to another level, a bucket, or NULL.
 * The levels and buckets must be allocated in manner alike posix_memalign()
 * to bookkeep additional information in pointer low bits.
 *
 * A level is an array of pointers.  Its size is a power of 2.  Levels
 * may be different sizes, but on the same level the sizes are the same.
 * Level sizes are specified by number of bits per level in lvlhsh->shift
 * array.  A hash may have up to 7 levels.  There are two predefined
 * shift arrays given by the first two shift array values:
 *
 * 1) [0, 0]:  [4, 4, 4, 4, 4, 4, 4] on a 64-bit platform or
 *             [5, 5, 5, 5, 5, 5, 0] on a 32-bit platform,
 *    so default size of levels is 128 bytes.
 *
 * 2) [0, 10]: [10, 4, 4, 4, 4, 4, 0] on a 64-bit platform or
 *             [10, 5, 5, 5, 5, 0, 0] on a 32-bit platform,
 *    so default size of levels is 128 bytes on all levels except
 *    the first level.  The first level is 8K or 4K on 64-bit or 32-bit
 *    platforms respectively.
 *
 * All buckets in a hash are the same size which is a power of 2.
 * A bucket contains several entries stored and tested sequentially.
 * The bucket size should be one or two CPU cache line size, a minimum
 * allowed size is 32 bytes.  A default 128-byte bucket contains 10 64-bit
 * entries or 15 32-bit entries.  Each entry consists of pointer to value
 * data and 32-bit key.  If an entry value pointer is NULL, the entry is free.
 * On a 64-bit platform entry value pointers are no aligned, therefore they
 * are accessed as two 32-bit integers.  The rest trailing space in a bucket
 * is used as pointer to next bucket and this pointer is always aligned.
 * Although the level hash allows to store a lot of values in a bucket chain,
 * this is non optimal way.  The large data set should be stored using
 * several levels.
 */

#define njt_lvlhsh_is_bucket(p)                                               \
    ((uintptr_t) (p) & 1)


#define njt_lvlhsh_count_inc(n)                                               \
    n = (void *) ((uintptr_t) (n) + 2)


#define njt_lvlhsh_count_dec(n)                                               \
    n = (void *) ((uintptr_t) (n) - 2)


#define njt_lvlhsh_level_size(proto, nlvl)                                    \
    ((uintptr_t) 1 << proto->shift[nlvl])


#define njt_lvlhsh_level(lvl, mask)                                           \
    (void **) ((uintptr_t) lvl & (~mask << 2))


#define njt_lvlhsh_level_entries(lvl, mask)                                   \
    ((uintptr_t) lvl & (mask << 1))


#define njt_lvlhsh_store_bucket(slot, bkt)                                    \
    slot = (void **) ((uintptr_t) bkt | 2 | 1)


#define njt_lvlhsh_bucket_size(proto)                                         \
    proto->bucket_size


#define njt_lvlhsh_bucket(proto, bkt)                                         \
    (uint32_t *) ((uintptr_t) bkt & ~(uintptr_t) proto->bucket_mask)


#define njt_lvlhsh_bucket_entries(proto, bkt)                                 \
    (((uintptr_t) bkt & (uintptr_t) proto->bucket_mask) >> 1)


#define njt_lvlhsh_bucket_end(proto, bkt)                                     \
    &bkt[proto->bucket_end]


#define njt_lvlhsh_free_entry(e)                                              \
    (!(njt_lvlhsh_valid_entry(e)))


#define njt_lvlhsh_next_bucket(proto, bkt)                                    \
    ((void **) &bkt[proto->bucket_end])

#if (NJT_PTR_SIZE == 4)

#define njt_lvlhsh_valid_entry(e)                                             \
    ((e)[0] != 0)


#define njt_lvlhsh_entry_value(e)                                             \
    (void *) (e)[0]


#define njt_lvlhsh_set_entry_value(e, n)                                      \
    (e)[0] = (uint32_t) n


#define njt_lvlhsh_entry_key(e)                                               \
    (e)[1]


#define njt_lvlhsh_set_entry_key(e, n)                                        \
    (e)[1] = n

#else

#define njt_lvlhsh_valid_entry(e)                                             \
    (((e)[0] | (e)[1]) != 0)


#define njt_lvlhsh_entry_value(e)                                             \
    (void *) (((uintptr_t) (e)[1] << 32) + (e)[0])


#define njt_lvlhsh_set_entry_value(e, n)                                      \
    (e)[0] = (uint32_t)  (uintptr_t) n;                                       \
    (e)[1] = (uint32_t) ((uintptr_t) n >> 32)


#define njt_lvlhsh_entry_key(e)                                               \
    (e)[2]


#define njt_lvlhsh_set_entry_key(e, n)                                        \
    (e)[2] = n

#endif


#define NJT_LVLHSH_BUCKET_DONE  ((void *) -1)


static njt_int_t njt_lvlhsh_level_find(njt_lvlhsh_query_t *lhq, void **lvl,
    uint32_t key, njt_uint_t nlvl);
static njt_int_t njt_lvlhsh_bucket_find(njt_lvlhsh_query_t *lhq, void **bkt);
static njt_int_t njt_lvlhsh_new_bucket(njt_lvlhsh_query_t *lhq, void **slot);
static njt_int_t njt_lvlhsh_level_insert(njt_lvlhsh_query_t *lhq,
    void **slot, uint32_t key, njt_uint_t nlvl);
static njt_int_t njt_lvlhsh_bucket_insert(njt_lvlhsh_query_t *lhq,
    void **slot, uint32_t key, njt_int_t nlvl);
static njt_int_t njt_lvlhsh_convert_bucket_to_level(njt_lvlhsh_query_t *lhq,
    void **slot, njt_uint_t nlvl, uint32_t *bucket);
static njt_int_t njt_lvlhsh_level_convertion_insert(njt_lvlhsh_query_t *lhq,
    void **parent, uint32_t key, njt_uint_t nlvl);
static njt_int_t njt_lvlhsh_bucket_convertion_insert(njt_lvlhsh_query_t *lhq,
    void **slot, uint32_t key, njt_int_t nlvl);
static njt_int_t njt_lvlhsh_free_level(njt_lvlhsh_query_t *lhq, void **level,
    njt_uint_t size);
static njt_int_t njt_lvlhsh_level_delete(njt_lvlhsh_query_t *lhq, void **slot,
    uint32_t key, njt_uint_t nlvl);
static njt_int_t njt_lvlhsh_bucket_delete(njt_lvlhsh_query_t *lhq, void **bkt);
static void *njt_lvlhsh_level_each(njt_lvlhsh_each_t *lhe, void **level,
    njt_uint_t nlvl, njt_uint_t shift);
static void *njt_lvlhsh_bucket_each(njt_lvlhsh_each_t *lhe);


njt_int_t
njt_lvlhsh_find(const njt_lvlhsh_t *lh, njt_lvlhsh_query_t *lhq)
{
    void  *slot;

    slot = lh->slot;

    if (slot != NULL) {

        if (njt_lvlhsh_is_bucket(slot)) {
            return njt_lvlhsh_bucket_find(lhq, slot);
        }

        return njt_lvlhsh_level_find(lhq, slot, lhq->key_hash, 0);
    }

    return NJT_DECLINED;
}


static njt_int_t
njt_lvlhsh_level_find(njt_lvlhsh_query_t *lhq, void **lvl, uint32_t key,
    njt_uint_t nlvl)
{
    void        **slot;
    uintptr_t     mask;
    njt_uint_t    shift;

    shift = lhq->proto->shift[nlvl];
    mask = ((uintptr_t) 1 << shift) - 1;

    lvl = njt_lvlhsh_level(lvl, mask);
    slot = lvl[key & mask];

    if (slot != NULL) {

        if (njt_lvlhsh_is_bucket(slot)) {
            return njt_lvlhsh_bucket_find(lhq, slot);
        }

        return njt_lvlhsh_level_find(lhq, slot, key >> shift, nlvl + 1);
    }

    return NJT_DECLINED;
}


static njt_int_t
njt_lvlhsh_bucket_find(njt_lvlhsh_query_t *lhq, void **bkt)
{
    void        *value;
    uint32_t    *bucket, *e;
    njt_uint_t   n;

    do {
        bucket = njt_lvlhsh_bucket(lhq->proto, bkt);
        n = njt_lvlhsh_bucket_entries(lhq->proto, bkt);
        e = bucket;

        do {
            if (njt_lvlhsh_valid_entry(e)) {
                n--;

                if (njt_lvlhsh_entry_key(e) == lhq->key_hash) {

                    value = njt_lvlhsh_entry_value(e);

                    if (lhq->proto->test(lhq, value) == NJT_OK) {
                        lhq->value = value;

                        return NJT_OK;
                    }
                }
            }

            e += NJT_LVLHSH_ENTRY_SIZE;

        } while (n != 0);

        bkt = *njt_lvlhsh_next_bucket(lhq->proto, bucket);

    } while (bkt != NULL);

    return NJT_DECLINED;
}


njt_int_t
njt_lvlhsh_insert(njt_lvlhsh_t *lh, njt_lvlhsh_query_t *lhq)
{
    uint32_t  key;

    if (lh->slot != NULL) {

        key = lhq->key_hash;

        if (njt_lvlhsh_is_bucket(lh->slot)) {
            return njt_lvlhsh_bucket_insert(lhq, &lh->slot, key, -1);
        }

        return njt_lvlhsh_level_insert(lhq, &lh->slot, key, 0);
    }

    return njt_lvlhsh_new_bucket(lhq, &lh->slot);
}


static njt_int_t
njt_lvlhsh_new_bucket(njt_lvlhsh_query_t *lhq, void **slot)
{
    uint32_t  *bucket;

    bucket = lhq->proto->alloc(lhq->pool, njt_lvlhsh_bucket_size(lhq->proto));

    if (bucket != NULL) {

        njt_lvlhsh_set_entry_value(bucket, lhq->value);
        njt_lvlhsh_set_entry_key(bucket, lhq->key_hash);

        *njt_lvlhsh_next_bucket(lhq->proto, bucket) = NULL;

        njt_lvlhsh_store_bucket(*slot, bucket);

        return NJT_OK;
    }

    return NJT_ERROR;
}


static njt_int_t
njt_lvlhsh_level_insert(njt_lvlhsh_query_t *lhq, void **parent, uint32_t key,
    njt_uint_t nlvl)
{
    void        **slot, **lvl;
    njt_int_t     rc;
    uintptr_t     mask;
    njt_uint_t    shift;

    shift = lhq->proto->shift[nlvl];
    mask = ((uintptr_t) 1 << shift) - 1;

    lvl = njt_lvlhsh_level(*parent, mask);
    slot = &lvl[key & mask];

    if (*slot != NULL) {
        key >>= shift;

        if (njt_lvlhsh_is_bucket(*slot)) {
            return njt_lvlhsh_bucket_insert(lhq, slot, key, nlvl);
        }

        return njt_lvlhsh_level_insert(lhq, slot, key, nlvl + 1);
    }

    rc = njt_lvlhsh_new_bucket(lhq, slot);

    if (rc == NJT_OK) {
        njt_lvlhsh_count_inc(*parent);
    }

    return rc;
}


static njt_int_t
njt_lvlhsh_bucket_insert(njt_lvlhsh_query_t *lhq, void **slot, uint32_t key,
    njt_int_t nlvl)
{
    void                      **bkt, **vacant_bucket, *value;
    uint32_t                   *bucket, *e, *vacant_entry;
    njt_int_t                   rc;
    uintptr_t                   n;
    const void                 *new_value;
    const njt_lvlhsh_proto_t   *proto;

    bkt = slot;
    vacant_entry = NULL;
    vacant_bucket = NULL;
    proto = lhq->proto;

    /* Search for duplicate entry in bucket chain. */

    do {
        bucket = njt_lvlhsh_bucket(proto, *bkt);
        n = njt_lvlhsh_bucket_entries(proto, *bkt);
        e = bucket;

        do {
            if (njt_lvlhsh_valid_entry(e)) {

                if (njt_lvlhsh_entry_key(e) == lhq->key_hash) {

                    value = njt_lvlhsh_entry_value(e);

                    if (proto->test(lhq, value) == NJT_OK) {

                        new_value = lhq->value;
                        lhq->value = value;

                        if (lhq->replace) {
                            njt_lvlhsh_set_entry_value(e, new_value);

                            return NJT_OK;
                        }

                        return NJT_DECLINED;
                    }
                }

                n--;

            } else {
                /*
                 * Save a hole vacant position in bucket
                 * and continue to search for duplicate entry.
                 */
                if (vacant_entry == NULL) {
                    vacant_entry = e;
                    vacant_bucket = bkt;
                }
            }

            e += NJT_LVLHSH_ENTRY_SIZE;

        } while (n != 0);

        if (e < njt_lvlhsh_bucket_end(proto, bucket)) {
            /*
             * Save a vacant position on incomplete bucket's end
             * and continue to search for duplicate entry.
             */
            if (vacant_entry == NULL) {
                vacant_entry = e;
                vacant_bucket = bkt;
            }
        }

        bkt = njt_lvlhsh_next_bucket(proto, bucket);

    } while (*bkt != NULL);

    if (vacant_entry != NULL) {
        njt_lvlhsh_set_entry_value(vacant_entry, lhq->value);
        njt_lvlhsh_set_entry_key(vacant_entry, lhq->key_hash);
        njt_lvlhsh_count_inc(*vacant_bucket);

        return NJT_OK;
    }

    /* All buckets are full. */

    nlvl++;

    if (proto->shift[nlvl] != 0) {

        rc = njt_lvlhsh_convert_bucket_to_level(lhq, slot, nlvl, bucket);

        if (rc == NJT_OK) {
            return njt_lvlhsh_level_insert(lhq, slot, key, nlvl);
        }

        return rc;
    }

    /* The last allowed level, only buckets may be allocated here. */

    return njt_lvlhsh_new_bucket(lhq, bkt);
}


static njt_int_t
njt_lvlhsh_convert_bucket_to_level(njt_lvlhsh_query_t *lhq, void **slot,
    njt_uint_t nlvl, uint32_t *bucket)
{
    void                      *lvl, **level;
    uint32_t                  *e, *end, key;
    njt_int_t                  rc;
    njt_uint_t                 i, shift, size;
    njt_lvlhsh_query_t         q;
    const njt_lvlhsh_proto_t  *proto;

    proto = lhq->proto;
    size = njt_lvlhsh_level_size(proto, nlvl);

    lvl = proto->alloc(lhq->pool, size * (sizeof(void *)));
    if (lvl == NULL) {
        return NJT_ERROR;
    }

    njt_memzero(lvl, size * (sizeof(void *)));

    level = lvl;
    shift = 0;

    for (i = 0; i < nlvl; i++) {
        shift += proto->shift[i];
    }

    end = njt_lvlhsh_bucket_end(proto, bucket);

    for (e = bucket; e < end; e += NJT_LVLHSH_ENTRY_SIZE) {

        q.proto = proto;
        q.pool = lhq->pool;
        q.value = njt_lvlhsh_entry_value(e);
        key = njt_lvlhsh_entry_key(e);
        q.key_hash = key;

        rc = njt_lvlhsh_level_convertion_insert(&q, &lvl, key >> shift, nlvl);

        if (rc != NJT_OK) {
            return njt_lvlhsh_free_level(lhq, level, size);
        }
    }

    *slot = lvl;

    proto->free(lhq->pool, bucket);

    return NJT_OK;
}


static njt_int_t
njt_lvlhsh_level_convertion_insert(njt_lvlhsh_query_t *lhq, void **parent,
    uint32_t key, njt_uint_t nlvl)
{
    void        **slot, **lvl;
    njt_int_t     rc;
    uintptr_t     mask;
    njt_uint_t    shift;

    shift = lhq->proto->shift[nlvl];
    mask = ((uintptr_t) 1 << shift) - 1;

    lvl = njt_lvlhsh_level(*parent, mask);
    slot = &lvl[key & mask];

    if (*slot == NULL) {
        rc = njt_lvlhsh_new_bucket(lhq, slot);

        if (rc == NJT_OK) {
            njt_lvlhsh_count_inc(*parent);
        }

        return rc;
    }

    /* Only backets can be here. */

    return njt_lvlhsh_bucket_convertion_insert(lhq, slot, key >> shift, nlvl);
}


/*
 * The special bucket insertion procedure is required because during
 * convertion lhq->key contains garbage values and the test function
 * cannot be called.  Besides, the procedure can be simpler because
 * a new entry is inserted just after occupied entries.
 */

static njt_int_t
njt_lvlhsh_bucket_convertion_insert(njt_lvlhsh_query_t *lhq, void **slot,
    uint32_t key, njt_int_t nlvl)
{
    void                      **bkt;
    uint32_t                   *bucket, *e;
    njt_int_t                   rc;
    uintptr_t                   n;
    const njt_lvlhsh_proto_t   *proto;

    bkt = slot;
    proto = lhq->proto;

    do {
        bucket = njt_lvlhsh_bucket(proto, *bkt);
        n = njt_lvlhsh_bucket_entries(proto, *bkt);
        e = bucket + n * NJT_LVLHSH_ENTRY_SIZE;

        if (e < njt_lvlhsh_bucket_end(proto, bucket)) {

            njt_lvlhsh_set_entry_value(e, lhq->value);
            njt_lvlhsh_set_entry_key(e, lhq->key_hash);
            njt_lvlhsh_count_inc(*bkt);

            return NJT_OK;
        }

        bkt = njt_lvlhsh_next_bucket(proto, bucket);

    } while (*bkt != NULL);

    /* All buckets are full. */

    nlvl++;

    if (proto->shift[nlvl] != 0) {

        rc = njt_lvlhsh_convert_bucket_to_level(lhq, slot, nlvl, bucket);

        if (rc == NJT_OK) {
            return njt_lvlhsh_level_insert(lhq, slot, key, nlvl);
        }

        return rc;
    }

    /* The last allowed level, only buckets may be allocated here. */

    return njt_lvlhsh_new_bucket(lhq, bkt);
}


static njt_int_t
njt_lvlhsh_free_level(njt_lvlhsh_query_t *lhq, void **level, njt_uint_t size)
{
    njt_uint_t                 i;
    const njt_lvlhsh_proto_t  *proto;

    proto = lhq->proto;

    for (i = 0; i < size; i++) {

        if (level[i] != NULL) {
            /*
             * Chained buckets are not possible here, since even
             * in the worst case one bucket cannot be converted
             * in two chained buckets but remains the same bucket.
             */
            proto->free(lhq->pool, njt_lvlhsh_bucket(proto, level[i]));
        }
    }

    proto->free(lhq->pool, level);

    return NJT_ERROR;
}


njt_int_t
njt_lvlhsh_delete(njt_lvlhsh_t *lh, njt_lvlhsh_query_t *lhq)
{
    if (lh->slot != NULL) {

        if (njt_lvlhsh_is_bucket(lh->slot)) {
            return njt_lvlhsh_bucket_delete(lhq, &lh->slot);
        }

        return njt_lvlhsh_level_delete(lhq, &lh->slot, lhq->key_hash, 0);
    }

    return NJT_DECLINED;
}


static njt_int_t
njt_lvlhsh_level_delete(njt_lvlhsh_query_t *lhq, void **parent, uint32_t key,
    njt_uint_t nlvl)
{
    void        **slot, **lvl;
    uintptr_t     mask;
    njt_int_t     rc;
    njt_uint_t    shift;

    shift = lhq->proto->shift[nlvl];
    mask = ((uintptr_t) 1 << shift) - 1;

    lvl = njt_lvlhsh_level(*parent, mask);
    slot = &lvl[key & mask];

    if (*slot != NULL) {

        if (njt_lvlhsh_is_bucket(*slot)) {
            rc = njt_lvlhsh_bucket_delete(lhq, slot);

        } else {
            key >>= shift;
            rc = njt_lvlhsh_level_delete(lhq, slot, key, nlvl + 1);
        }

        if (*slot == NULL) {
            njt_lvlhsh_count_dec(*parent);

            if (njt_lvlhsh_level_entries(*parent, mask) == 0) {
                *parent = NULL;
                lhq->proto->free(lhq->pool, lvl);
            }
        }

        return rc;
    }

    return NJT_DECLINED;
}


static njt_int_t
njt_lvlhsh_bucket_delete(njt_lvlhsh_query_t *lhq, void **bkt)
{
    void                      *value;
    uint32_t                  *bucket, *e;
    uintptr_t                  n;
    const njt_lvlhsh_proto_t  *proto;

    proto = lhq->proto;

    do {
        bucket = njt_lvlhsh_bucket(proto, *bkt);
        n = njt_lvlhsh_bucket_entries(proto, *bkt);
        e = bucket;

        do {
            if (njt_lvlhsh_valid_entry(e)) {

                if (njt_lvlhsh_entry_key(e) == lhq->key_hash) {

                    value = njt_lvlhsh_entry_value(e);

                    if (proto->test(lhq, value) == NJT_OK) {

                        if (njt_lvlhsh_bucket_entries(proto, *bkt) == 1) {
                            *bkt = *njt_lvlhsh_next_bucket(proto, bucket);
                            proto->free(lhq->pool, bucket);

                        } else {
                            njt_lvlhsh_count_dec(*bkt);
                            njt_lvlhsh_set_entry_value(e, NULL);
                        }

                        lhq->value = value;

                        return NJT_OK;
                    }
                }

                n--;
            }

            e += NJT_LVLHSH_ENTRY_SIZE;

        } while (n != 0);

        bkt = njt_lvlhsh_next_bucket(proto, bucket);

    } while (*bkt != NULL);

    return NJT_DECLINED;
}


void *
njt_lvlhsh_each(const njt_lvlhsh_t *lh, njt_lvlhsh_each_t *lhe)
{
    void  **slot;

    if (lhe->bucket == NJT_LVLHSH_BUCKET_DONE) {
        slot = lh->slot;

        if (njt_lvlhsh_is_bucket(slot)) {
            return NULL;
        }

    } else {
        if (lhe->bucket == NULL) {

            /* The first iteration only. */

            slot = lh->slot;

            if (slot == NULL) {
                return NULL;
            }

            if (!njt_lvlhsh_is_bucket(slot)) {
                goto level;
            }

            lhe->bucket = njt_lvlhsh_bucket(lhe->proto, slot);
            lhe->entries = njt_lvlhsh_bucket_entries(lhe->proto, slot);
        }

        return njt_lvlhsh_bucket_each(lhe);
    }

level:

    return njt_lvlhsh_level_each(lhe, slot, 0, 0);
}


static void *
njt_lvlhsh_level_each(njt_lvlhsh_each_t *lhe, void **level, njt_uint_t nlvl,
    njt_uint_t shift)
{
    void        **slot, *value;
    uintptr_t     mask;
    njt_uint_t    n, level_shift;

    level_shift = lhe->proto->shift[nlvl];
    mask = ((uintptr_t) 1 << level_shift) - 1;

    level = njt_lvlhsh_level(level, mask);

    do {
        n = (lhe->current >> shift) & mask;
        slot = level[n];

        if (slot != NULL) {
            if (njt_lvlhsh_is_bucket(slot)) {

                if (lhe->bucket != NJT_LVLHSH_BUCKET_DONE) {

                    lhe->bucket = njt_lvlhsh_bucket(lhe->proto, slot);
                    lhe->entries = njt_lvlhsh_bucket_entries(lhe->proto, slot);
                    lhe->entry = 0;

                    return njt_lvlhsh_bucket_each(lhe);
                }

                lhe->bucket = NULL;

            } else {
                value = njt_lvlhsh_level_each(lhe, slot, nlvl + 1,
                                              shift + level_shift);
                if (value != NULL) {
                    return value;
                }
            }
        }

        lhe->current &= ~(mask << shift);
        n = ((n + 1) & mask) << shift;
        lhe->current |= n;

    } while (n != 0);

    return NULL;
}


static void *
njt_lvlhsh_bucket_each(njt_lvlhsh_each_t *lhe)
{
    void      *value, **next;
    uint32_t  *bucket;

    /* At least one valid entry must present here. */
    do {
        bucket = &lhe->bucket[lhe->entry];
        lhe->entry += NJT_LVLHSH_ENTRY_SIZE;

    } while (njt_lvlhsh_free_entry(bucket));

    value = njt_lvlhsh_entry_value(bucket);

    lhe->entries--;

    if (lhe->entries == 0) {
        next = *njt_lvlhsh_next_bucket(lhe->proto, lhe->bucket);

        lhe->bucket = (next == NULL) ? NJT_LVLHSH_BUCKET_DONE
                                     : njt_lvlhsh_bucket(lhe->proto, next);

        lhe->entries = njt_lvlhsh_bucket_entries(lhe->proto, next);
        lhe->entry = 0;
    }

    return value;
}

#if (NJT_HAVE_POSIX_MEMALIGN || NJT_HAVE_MEMALIGN)

void *
njt_lvlhsh_alloc(void *data, size_t size)
{
    return njt_memalign(size, size, data);
}


void
njt_lvlhsh_free(void *data, void *p)
{
    njt_free(p);
}


void *
njt_lvlhsh_pool_alloc(void *data, size_t size)
{
    return njt_pmemalign(data, size, size);
}


void
njt_lvlhsh_pool_free(void *data, void *p)
{
    njt_pfree(data, p);
}

#endif

void *
njt_lvlhsh_slab_alloc(void *data, size_t size)
{
    return njt_slab_alloc_locked(data, size);
}


void
njt_lvlhsh_slab_free(void *data, void *p)
{
    njt_slab_free_locked(data, p);
}
