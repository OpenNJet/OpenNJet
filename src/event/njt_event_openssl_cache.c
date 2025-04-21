
/*
 * Copyright (C) NJet, Inc.
 * Copyright (C) 2021-2025  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


#define NJT_SSL_CACHE_PATH    0


typedef struct {
    unsigned                    type:2;
    unsigned                    len:30;
    u_char                     *data;
} njt_ssl_cache_key_t;


typedef void *(*njt_ssl_cache_create_pt)(njt_ssl_cache_key_t *id, char **err,
    void *data);
typedef void (*njt_ssl_cache_free_pt)(void *data);
typedef void *(*njt_ssl_cache_ref_pt)(char **err, void *data);


typedef struct {
    njt_ssl_cache_create_pt     create;
    njt_ssl_cache_free_pt       free;
    njt_ssl_cache_ref_pt        ref;
} njt_ssl_cache_type_t;


typedef struct {
    njt_rbtree_node_t           node;
    njt_ssl_cache_key_t         id;
    njt_ssl_cache_type_t       *type;
    void                       *value;
} njt_ssl_cache_node_t;


typedef struct {
    njt_rbtree_t                rbtree;
    njt_rbtree_node_t           sentinel;
} njt_ssl_cache_t;


static njt_int_t njt_ssl_cache_init_key(njt_pool_t *pool, njt_uint_t index,
    njt_str_t *path, njt_ssl_cache_key_t *id);
static njt_ssl_cache_node_t *njt_ssl_cache_lookup(njt_ssl_cache_t *cache,
    njt_ssl_cache_type_t *type, njt_ssl_cache_key_t *id, uint32_t hash);

static void *njt_openssl_cache_create_conf(njt_cycle_t *cycle);
static void njt_ssl_cache_cleanup(void *data);
static void njt_ssl_cache_node_insert(njt_rbtree_node_t *temp,
    njt_rbtree_node_t *node, njt_rbtree_node_t *sentinel);


static njt_core_module_t  njt_openssl_cache_module_ctx = {
    njt_string("openssl_cache"),
    njt_openssl_cache_create_conf,
    NULL
};


njt_module_t  njt_openssl_cache_module = {
    NJT_MODULE_V1,
    &njt_openssl_cache_module_ctx,         /* module context */
    NULL,                                  /* module directives */
    NJT_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};


static njt_ssl_cache_type_t  njt_ssl_cache_types[] = {

};


void *
njt_ssl_cache_fetch(njt_conf_t *cf, njt_uint_t index, char **err,
    njt_str_t *path, void *data)
{
    uint32_t               hash;
    njt_ssl_cache_t       *cache;
    njt_ssl_cache_key_t    id;
    njt_ssl_cache_type_t  *type;
    njt_ssl_cache_node_t  *cn;

    if (njt_ssl_cache_init_key(cf->pool, index, path, &id) != NJT_OK) {
        return NULL;
    }

    cache = (njt_ssl_cache_t *) njt_get_conf(cf->cycle->conf_ctx,
                                             njt_openssl_cache_module);

    type = &njt_ssl_cache_types[index];
    hash = njt_murmur_hash2(id.data, id.len);

    cn = njt_ssl_cache_lookup(cache, type, &id, hash);
    if (cn != NULL) {
        return type->ref(err, cn->value);
    }

    cn = njt_palloc(cf->pool, sizeof(njt_ssl_cache_node_t) + id.len + 1);
    if (cn == NULL) {
        return NULL;
    }

    cn->node.key = hash;
    cn->id.data = (u_char *)(cn + 1);
    cn->id.len = id.len;
    cn->id.type = id.type;
    cn->type = type;

    njt_cpystrn(cn->id.data, id.data, id.len + 1);

    cn->value = type->create(&id, err, data);
    if (cn->value == NULL) {
        return NULL;
    }

    njt_rbtree_insert(&cache->rbtree, &cn->node);

    return type->ref(err, cn->value);
}


void *
njt_ssl_cache_connection_fetch(njt_pool_t *pool, njt_uint_t index, char **err,
    njt_str_t *path, void *data)
{
    njt_ssl_cache_key_t  id;

    if (njt_ssl_cache_init_key(pool, index, path, &id) != NJT_OK) {
        return NULL;
    }

    return njt_ssl_cache_types[index].create(&id, err, data);
}


static njt_int_t
njt_ssl_cache_init_key(njt_pool_t *pool, njt_uint_t index, njt_str_t *path,
    njt_ssl_cache_key_t *id)
{
    if (njt_get_full_name(pool, (njt_str_t *) &njt_cycle->conf_prefix, path)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    id->type = NJT_SSL_CACHE_PATH;

    id->len = path->len;
    id->data = path->data;

    return NJT_OK;
}


static njt_ssl_cache_node_t *
njt_ssl_cache_lookup(njt_ssl_cache_t *cache, njt_ssl_cache_type_t *type,
    njt_ssl_cache_key_t *id, uint32_t hash)
{
    njt_int_t              rc;
    njt_rbtree_node_t     *node, *sentinel;
    njt_ssl_cache_node_t  *cn;

    node = cache->rbtree.root;
    sentinel = cache->rbtree.sentinel;

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

        cn = (njt_ssl_cache_node_t *) node;

        if (type < cn->type) {
            node = node->left;
            continue;
        }

        if (type > cn->type) {
            node = node->right;
            continue;
        }

        /* type == cn->type */

        rc = njt_memn2cmp(id->data, cn->id.data, id->len, cn->id.len);

        if (rc == 0) {
            return cn;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


static void *
njt_openssl_cache_create_conf(njt_cycle_t *cycle)
{
    njt_ssl_cache_t     *cache;
    njt_pool_cleanup_t  *cln;

    cache = njt_pcalloc(cycle->pool, sizeof(njt_ssl_cache_t));
    if (cache == NULL) {
        return NULL;
    }

    cln = njt_pool_cleanup_add(cycle->pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = njt_ssl_cache_cleanup;
    cln->data = cache;

    njt_rbtree_init(&cache->rbtree, &cache->sentinel,
                    njt_ssl_cache_node_insert);

    return cache;
}


static void
njt_ssl_cache_cleanup(void *data)
{
    njt_ssl_cache_t  *cache = data;

    njt_rbtree_t          *tree;
    njt_rbtree_node_t     *node;
    njt_ssl_cache_node_t  *cn;

    tree = &cache->rbtree;

    if (tree->root == tree->sentinel) {
        return;
    }

    for (node = njt_rbtree_min(tree->root, tree->sentinel);
         node;
         node = njt_rbtree_next(tree, node))
    {
        cn = njt_rbtree_data(node, njt_ssl_cache_node_t, node);
        cn->type->free(cn->value);
    }
}


static void
njt_ssl_cache_node_insert(njt_rbtree_node_t *temp,
    njt_rbtree_node_t *node, njt_rbtree_node_t *sentinel)
{
    njt_rbtree_node_t     **p;
    njt_ssl_cache_node_t   *n, *t;

    for ( ;; ) {

        n = njt_rbtree_data(node, njt_ssl_cache_node_t, node);
        t = njt_rbtree_data(temp, njt_ssl_cache_node_t, node);

        if (node->key != temp->key) {

            p = (node->key < temp->key) ? &temp->left : &temp->right;

        } else if (n->type != t->type) {

            p = (n->type < t->type) ? &temp->left : &temp->right;

        } else {

            p = (njt_memn2cmp(n->id.data, t->id.data, n->id.len, t->id.len)
                 < 0) ? &temp->left : &temp->right;
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
