
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_RADIX_TREE_H_INCLUDED_
#define _NJT_RADIX_TREE_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


#define NJT_RADIX_NO_VALUE   (uintptr_t) -1

typedef struct njt_radix_node_s  njt_radix_node_t;

struct njt_radix_node_s {
    njt_radix_node_t  *right;
    njt_radix_node_t  *left;
    njt_radix_node_t  *parent;
    uintptr_t          value;
};


typedef struct {
    njt_radix_node_t  *root;
    njt_pool_t        *pool;
    njt_radix_node_t  *free;
    char              *start;
    size_t             size;
} njt_radix_tree_t;


njt_radix_tree_t *njt_radix_tree_create(njt_pool_t *pool,
    njt_int_t preallocate);

njt_int_t njt_radix32tree_insert(njt_radix_tree_t *tree,
    uint32_t key, uint32_t mask, uintptr_t value);
njt_int_t njt_radix32tree_delete(njt_radix_tree_t *tree,
    uint32_t key, uint32_t mask);
uintptr_t njt_radix32tree_find(njt_radix_tree_t *tree, uint32_t key);

#if (NJT_HAVE_INET6)
njt_int_t njt_radix128tree_insert(njt_radix_tree_t *tree,
    u_char *key, u_char *mask, uintptr_t value);
njt_int_t njt_radix128tree_delete(njt_radix_tree_t *tree,
    u_char *key, u_char *mask);
uintptr_t njt_radix128tree_find(njt_radix_tree_t *tree, u_char *key);
#endif


#endif /* _NJT_RADIX_TREE_H_INCLUDED_ */
