
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HASH_H_INCLUDED_
#define _NJT_HASH_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


typedef struct {
    void             *value;
    u_short           len;
    u_char            name[1];
} njt_hash_elt_t;


typedef struct {
    njt_hash_elt_t  **buckets;
    njt_uint_t        size;
//by zyg
#if (NJT_HTTP_DYNAMIC_LOC)
    njt_pool_t       *pool;
#endif
//end
} njt_hash_t;


typedef struct {
    njt_hash_t        hash;
    void             *value;
} njt_hash_wildcard_t;


typedef struct {
    njt_str_t         key;
    njt_uint_t        key_hash;
    void             *value;
} njt_hash_key_t;


typedef njt_uint_t (*njt_hash_key_pt) (u_char *data, size_t len);


typedef struct {
    njt_hash_t            hash;
    njt_hash_wildcard_t  *wc_head;
    njt_hash_wildcard_t  *wc_tail;
} njt_hash_combined_t;


typedef struct {
    njt_hash_t       *hash;
    njt_hash_key_pt   key;

    njt_uint_t        max_size;
    njt_uint_t        bucket_size;

    char             *name;
    njt_pool_t       *pool;
    njt_pool_t       *temp_pool;
} njt_hash_init_t;


#define NJT_HASH_SMALL            1
#define NJT_HASH_LARGE            2

#define NJT_HASH_LARGE_ASIZE      16384
#define NJT_HASH_LARGE_HSIZE      10007

#define NJT_HASH_WILDCARD_KEY     1
#define NJT_HASH_READONLY_KEY     2


typedef struct {
    njt_uint_t        hsize;

    njt_pool_t       *pool;
    njt_pool_t       *temp_pool;

    njt_array_t       keys;
    njt_array_t      *keys_hash;

    njt_array_t       dns_wc_head;
    njt_array_t      *dns_wc_head_hash;

    njt_array_t       dns_wc_tail;
    njt_array_t      *dns_wc_tail_hash;
} njt_hash_keys_arrays_t;


typedef struct njt_table_elt_s  njt_table_elt_t;

struct njt_table_elt_s {
    njt_uint_t        hash;
    njt_str_t         key;
    njt_str_t         value;
    u_char           *lowcase_key;
    njt_table_elt_t  *next;
};


void *njt_hash_find(njt_hash_t *hash, njt_uint_t key, u_char *name, size_t len);
void *njt_hash_find_wc_head(njt_hash_wildcard_t *hwc, u_char *name, size_t len);
void *njt_hash_find_wc_tail(njt_hash_wildcard_t *hwc, u_char *name, size_t len);
void *njt_hash_find_combined(njt_hash_combined_t *hash, njt_uint_t key,
    u_char *name, size_t len);

njt_int_t njt_hash_init(njt_hash_init_t *hinit, njt_hash_key_t *names,
    njt_uint_t nelts);
njt_int_t njt_hash_wildcard_init(njt_hash_init_t *hinit, njt_hash_key_t *names,
    njt_uint_t nelts);

#define njt_hash(key, c)   ((njt_uint_t) key * 31 + c)
njt_uint_t njt_hash_key(u_char *data, size_t len);
njt_uint_t njt_hash_key_lc(u_char *data, size_t len);
njt_uint_t njt_hash_strlow(u_char *dst, u_char *src, size_t n);


njt_int_t njt_hash_keys_array_init(njt_hash_keys_arrays_t *ha, njt_uint_t type);
njt_int_t njt_hash_add_key(njt_hash_keys_arrays_t *ha, njt_str_t *key,
    void *value, njt_uint_t flags);

//by zyg
#if (NJT_HTTP_DYNAMIC_LOC)
    void njt_hash_free(njt_hash_t *hash);
//    njt_pool_t       *pool;
//    u_char           *elts;
#endif
//end
#endif /* _NJT_HASH_H_INCLUDED_ */
