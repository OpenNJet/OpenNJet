
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_RBTREE_H_INCLUDED_
#define _NJT_RBTREE_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


typedef njt_uint_t  njt_rbtree_key_t;
typedef njt_int_t   njt_rbtree_key_int_t;


typedef struct njt_rbtree_node_s  njt_rbtree_node_t;

struct njt_rbtree_node_s {
    njt_rbtree_key_t       key;
    njt_rbtree_node_t     *left;
    njt_rbtree_node_t     *right;
    njt_rbtree_node_t     *parent;
    u_char                 color;
    u_char                 data;
};


typedef struct njt_rbtree_s  njt_rbtree_t;

typedef void (*njt_rbtree_insert_pt) (njt_rbtree_node_t *root,
    njt_rbtree_node_t *node, njt_rbtree_node_t *sentinel);

struct njt_rbtree_s {
    njt_rbtree_node_t     *root;
    njt_rbtree_node_t     *sentinel;
    njt_rbtree_insert_pt   insert;
};


#define njt_rbtree_init(tree, s, i)                                           \
    njt_rbtree_sentinel_init(s);                                              \
    (tree)->root = s;                                                         \
    (tree)->sentinel = s;                                                     \
    (tree)->insert = i

#define njt_rbtree_data(node, type, link)                                     \
    (type *) ((u_char *) (node) - offsetof(type, link))


void njt_rbtree_insert(njt_rbtree_t *tree, njt_rbtree_node_t *node);
void njt_rbtree_delete(njt_rbtree_t *tree, njt_rbtree_node_t *node);
void njt_rbtree_insert_value(njt_rbtree_node_t *root, njt_rbtree_node_t *node,
    njt_rbtree_node_t *sentinel);
void njt_rbtree_insert_timer_value(njt_rbtree_node_t *root,
    njt_rbtree_node_t *node, njt_rbtree_node_t *sentinel);
njt_rbtree_node_t *njt_rbtree_next(njt_rbtree_t *tree,
    njt_rbtree_node_t *node);


#define njt_rbt_red(node)               ((node)->color = 1)
#define njt_rbt_black(node)             ((node)->color = 0)
#define njt_rbt_is_red(node)            ((node)->color)
#define njt_rbt_is_black(node)          (!njt_rbt_is_red(node))
#define njt_rbt_copy_color(n1, n2)      (n1->color = n2->color)


/* a sentinel must be black */

#define njt_rbtree_sentinel_init(node)  njt_rbt_black(node)


static njt_inline njt_rbtree_node_t *
njt_rbtree_min(njt_rbtree_node_t *node, njt_rbtree_node_t *sentinel)
{
    while (node->left != sentinel) {
        node = node->left;
    }

    return node;
}


#endif /* _NJT_RBTREE_H_INCLUDED_ */
