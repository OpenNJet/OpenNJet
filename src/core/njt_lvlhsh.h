/*
 * Copyright (C) 2023 Web Server LLC
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */

#ifndef _NJT_LVLHSH_H_INCLUDED_
#define _NJT_LVLHSH_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


typedef struct njt_lvlhsh_query_s  njt_lvlhsh_query_t;

typedef njt_int_t (*njt_lvlhsh_test_t)(njt_lvlhsh_query_t *lhq, void *data);
typedef void *(*njt_lvlhsh_alloc_t)(void *ctx, size_t size);
typedef void (*njt_lvlhsh_free_t)(void *ctx, void *p);


#if (NJT_PTR_SIZE == 4)

#define NJT_LVLHSH_DEFAULT_BUCKET_SIZE  64
#define NJT_LVLHSH_ENTRY_SIZE           2

#else

#define NJT_LVLHSH_DEFAULT_BUCKET_SIZE  128
#define NJT_LVLHSH_ENTRY_SIZE           3

#endif


#define NJT_LVLHSH_BUCKET_END(bucket_size)                                    \
    (((bucket_size) - sizeof(void *))                                         \
        / (NJT_LVLHSH_ENTRY_SIZE * sizeof(uint32_t))                          \
     * NJT_LVLHSH_ENTRY_SIZE)


#define NJT_LVLHSH_BUCKET_SIZE(bucket_size)                                   \
    NJT_LVLHSH_BUCKET_END(bucket_size), bucket_size, (bucket_size - 1)


#define NJT_LVLHSH_DEFAULT                                                    \
    NJT_LVLHSH_BUCKET_SIZE(NJT_LVLHSH_DEFAULT_BUCKET_SIZE),                   \
    { 4, 4, 4, 4, 4, 4, 4, 0 }


#define NJT_LVLHSH_LARGE_SLAB                                                 \
    NJT_LVLHSH_BUCKET_SIZE(NJT_LVLHSH_DEFAULT_BUCKET_SIZE),                   \
    { 10, 4, 4, 4, 4, 4, 4, 0 }


#define NJT_LVLHSH_LARGE_MEMALIGN                                             \
    NJT_LVLHSH_BUCKET_SIZE(NJT_LVLHSH_DEFAULT_BUCKET_SIZE),                   \
    { 10, 4, 4, 4, 4, 0, 0, 0 }


typedef struct {
    uint32_t                   bucket_end;
    uint32_t                   bucket_size;
    uint32_t                   bucket_mask;
    uint8_t                    shift[8];

    njt_lvlhsh_test_t          test;
    njt_lvlhsh_alloc_t         alloc;
    njt_lvlhsh_free_t          free;
} njt_lvlhsh_proto_t;


typedef struct {
    void                      *slot;
} njt_lvlhsh_t;


struct njt_lvlhsh_query_s {
    uint32_t                   key_hash;
    njt_str_t                  key;

    njt_uint_t                 replace;   /* unsigned  replace:1 */
    void                      *value;

    const njt_lvlhsh_proto_t  *proto;
    void                      *pool;

    /* Opaque data passed for the test function. */
    void                      *data;
};


#define njt_lvlhsh_is_empty(lh)                                               \
    ((lh)->slot == NULL)


#define njt_lvlhsh_init(lh)                                                   \
    (lh)->slot = NULL


#define njt_lvlhsh_eq(lhl, lhr)                                               \
    ((lhl)->slot == (lhr)->slot)

/*
 * njt_lvlhsh_find() finds a hash element.  If the element has been
 * found then it is stored in the lhq->value and njt_lvlhsh_find()
 * returns NJT_OK.  Otherwise NJT_DECLINED is returned.
 *
 * The required njt_lvlhsh_query_t fields: key_hash, key, proto.
 */
njt_int_t njt_lvlhsh_find(const njt_lvlhsh_t *lh, njt_lvlhsh_query_t *lhq);

/*
 * njt_lvlhsh_insert() adds a hash element.  If the element already
 * presents in lvlhsh and the lhq->replace flag is zero, then lhq->value
 * is updated with the old element and NJT_DECLINED is returned.
 * If the element already presents in lvlhsh and the lhq->replace flag
 * is non-zero, then the old element is replaced with the new element.
 * lhq->value is updated with the old element, and NJT_OK is returned.
 * If the element is not present in lvlhsh, then it is inserted and
 * NJS_OK is returned.  The lhq->value is not changed.
 * On memory allocation failure NJT_ERROR is returned.
 *
 * The required njt_lvlhsh_query_t fields: key_hash, key, proto, replace, value.
 * The optional njt_lvlhsh_query_t fields: pool.
 */
njt_int_t njt_lvlhsh_insert(njt_lvlhsh_t *lh, njt_lvlhsh_query_t *lhq);

/*
 * njt_lvlhsh_delete() deletes a hash element.  If the element has been
 * found then it is removed from lvlhsh and is stored in the lhq->value,
 * and NJT_OK is returned.  Otherwise NJT_DECLINED is returned.
 *
 * The required njt_lvlhsh_query_t fields: key_hash, key, proto.
 * The optional njt_lvlhsh_query_t fields: pool.
 */
njt_int_t njt_lvlhsh_delete(njt_lvlhsh_t *lh, njt_lvlhsh_query_t *lhq);


typedef struct {
    const njt_lvlhsh_proto_t  *proto;

    /*
     * Fields to store current bucket entry position.  They cannot be
     * combined in a single bucket pointer with number of entries in low
     * bits, because entry positions are not aligned.  A current level is
     * stored as key bit path from the root.
     */
    uint32_t                  *bucket;
    uint32_t                   current;
    uint32_t                   entry;
    uint32_t                   entries;
} njt_lvlhsh_each_t;


#define njt_lvlhsh_each_init(lhe, _proto)                                     \
    do {                                                                      \
        njt_memzero(lhe, sizeof(njt_lvlhsh_each_t));                          \
        (lhe)->proto = _proto;                                                \
    } while (0)

void *njt_lvlhsh_each(const njt_lvlhsh_t *lh, njt_lvlhsh_each_t *lhe);


#if (NJT_HAVE_POSIX_MEMALIGN || NJT_HAVE_MEMALIGN)
void *njt_lvlhsh_alloc(void *data, size_t size);
void njt_lvlhsh_free(void *data, void *p);

void *njt_lvlhsh_pool_alloc(void *data, size_t size);
void njt_lvlhsh_pool_free(void *data, void *p);
#endif

void *njt_lvlhsh_slab_alloc(void *data, size_t size);
void njt_lvlhsh_slab_free(void *data, void *p);


#endif /* _NJT_LVLHSH_H_INCLUDED_ */
