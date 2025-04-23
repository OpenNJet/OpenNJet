
/*
 * Copyright (C) NJet, Inc.
 * Copyright (C) 2021-2025  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


#define NJT_SSL_CACHE_PATH    0
#define NJT_SSL_CACHE_DATA    1
#define NJT_SSL_CACHE_ENGINE  2


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

static void *njt_ssl_cache_cert_create(njt_ssl_cache_key_t *id, char **err,
    void *data);
static void njt_ssl_cache_cert_free(void *data);
static void *njt_ssl_cache_cert_ref(char **err, void *data);

static void *njt_ssl_cache_pkey_create(njt_ssl_cache_key_t *id, char **err,
    void *data);
static int njt_ssl_cache_pkey_password_callback(char *buf, int size, int rwflag,
    void *userdata);
static void njt_ssl_cache_pkey_free(void *data);
static void *njt_ssl_cache_pkey_ref(char **err, void *data);

static void *njt_ssl_cache_crl_create(njt_ssl_cache_key_t *id, char **err,
    void *data);
static void njt_ssl_cache_crl_free(void *data);
static void *njt_ssl_cache_crl_ref(char **err, void *data);

static void *njt_ssl_cache_ca_create(njt_ssl_cache_key_t *id, char **err,
    void *data);

static BIO *njt_ssl_cache_create_bio(njt_ssl_cache_key_t *id, char **err);

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

    /* NJT_SSL_CACHE_CERT */
    { njt_ssl_cache_cert_create,
      njt_ssl_cache_cert_free,
      njt_ssl_cache_cert_ref },

    /* NJT_SSL_CACHE_PKEY */
    { njt_ssl_cache_pkey_create,
      njt_ssl_cache_pkey_free,
      njt_ssl_cache_pkey_ref },

    /* NJT_SSL_CACHE_CRL */
    { njt_ssl_cache_crl_create,
      njt_ssl_cache_crl_free,
      njt_ssl_cache_crl_ref },

    /* NJT_SSL_CACHE_CA */
    { njt_ssl_cache_ca_create,
      njt_ssl_cache_cert_free,
      njt_ssl_cache_cert_ref }
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

#if (NJT_HAVE_NTLS)
    njt_str_t  tcert;

    tcert = *path;
    njt_ssl_ntls_prefix_strip(&tcert);
    path = &tcert;
#endif

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

#if (NJT_HAVE_NTLS)
    njt_str_t  tcert;

    tcert = *path;
    njt_ssl_ntls_prefix_strip(&tcert);
    path = &tcert;
#endif

    if (njt_ssl_cache_init_key(pool, index, path, &id) != NJT_OK) {
        return NULL;
    }

    return njt_ssl_cache_types[index].create(&id, err, data);
}


static njt_int_t
njt_ssl_cache_init_key(njt_pool_t *pool, njt_uint_t index, njt_str_t *path,
    njt_ssl_cache_key_t *id)
{
    if (index <= NJT_SSL_CACHE_PKEY
        && njt_strncmp(path->data, "data:", sizeof("data:") - 1) == 0)
    {
        id->type = NJT_SSL_CACHE_DATA;

    } else if (index == NJT_SSL_CACHE_PKEY
        && njt_strncmp(path->data, "engine:", sizeof("engine:") - 1) == 0)
    {
        id->type = NJT_SSL_CACHE_ENGINE;

    } else {
        if (njt_get_full_name(pool, (njt_str_t *) &njt_cycle->conf_prefix, path)
            != NJT_OK)
        {
            return NJT_ERROR;
        }

        id->type = NJT_SSL_CACHE_PATH;
    }

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
njt_ssl_cache_cert_create(njt_ssl_cache_key_t *id, char **err, void *data)
{
    BIO             *bio;
    X509            *x509;
    u_long           n;
    STACK_OF(X509)  *chain;

    chain = sk_X509_new_null();
    if (chain == NULL) {
        *err = "sk_X509_new_null() failed";
        return NULL;
    }

    bio = njt_ssl_cache_create_bio(id, err);
    if (bio == NULL) {
        sk_X509_pop_free(chain, X509_free);
        return NULL;
    }

    /* certificate itself */

    x509 = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
    if (x509 == NULL) {
        *err = "PEM_read_bio_X509_AUX() failed";
        BIO_free(bio);
        sk_X509_pop_free(chain, X509_free);
        return NULL;
    }

    if (sk_X509_push(chain, x509) == 0) {
        *err = "sk_X509_push() failed";
        BIO_free(bio);
        X509_free(x509);
        sk_X509_pop_free(chain, X509_free);
        return NULL;
    }

    /* rest of the chain */

    for ( ;; ) {

        x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (x509 == NULL) {
            n = ERR_peek_last_error();

            if (ERR_GET_LIB(n) == ERR_LIB_PEM
                && ERR_GET_REASON(n) == PEM_R_NO_START_LINE)
            {
                /* end of file */
                ERR_clear_error();
                break;
            }

            /* some real error */

            *err = "PEM_read_bio_X509() failed";
            BIO_free(bio);
            sk_X509_pop_free(chain, X509_free);
            return NULL;
        }

        if (sk_X509_push(chain, x509) == 0) {
            *err = "sk_X509_push() failed";
            BIO_free(bio);
            X509_free(x509);
            sk_X509_pop_free(chain, X509_free);
            return NULL;
        }
    }

    BIO_free(bio);

    return chain;
}


static void
njt_ssl_cache_cert_free(void *data)
{
    sk_X509_pop_free(data, X509_free);
}


static void *
njt_ssl_cache_cert_ref(char **err, void *data)
{
    int              n, i;
    X509            *x509;
    STACK_OF(X509)  *chain;

    chain = sk_X509_dup(data);
    if (chain == NULL) {
        *err = "sk_X509_dup() failed";
        return NULL;
    }

    n = sk_X509_num(chain);

    for (i = 0; i < n; i++) {
        x509 = sk_X509_value(chain, i);

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
        X509_up_ref(x509);
#else
        CRYPTO_add(&x509->references, 1, CRYPTO_LOCK_X509);
#endif
    }

    return chain;
}


static void *
njt_ssl_cache_pkey_create(njt_ssl_cache_key_t *id, char **err, void *data)
{
    njt_array_t  *passwords = data;

    BIO              *bio;
    EVP_PKEY         *pkey;
    njt_str_t        *pwd;
    njt_uint_t        tries;
    pem_password_cb  *cb;

    if (id->type == NJT_SSL_CACHE_ENGINE) {

#ifndef OPENSSL_NO_ENGINE

        u_char  *p, *last;
        ENGINE  *engine;

        p = id->data + sizeof("engine:") - 1;
        last = (u_char *) njt_strchr(p, ':');

        if (last == NULL) {
            *err = "invalid syntax";
            return NULL;
        }

        *last = '\0';

        engine = ENGINE_by_id((char *) p);

        *last++ = ':';

        if (engine == NULL) {
            *err = "ENGINE_by_id() failed";
            return NULL;
        }

        pkey = ENGINE_load_private_key(engine, (char *) last, 0, 0);

        if (pkey == NULL) {
            *err = "ENGINE_load_private_key() failed";
            ENGINE_free(engine);
            return NULL;
        }

        ENGINE_free(engine);

        return pkey;

#else

        *err = "loading \"engine:...\" certificate keys is not supported";
        return NULL;

#endif
    }

    bio = njt_ssl_cache_create_bio(id, err);
    if (bio == NULL) {
        return NULL;
    }

    if (passwords) {
        tries = passwords->nelts;
        pwd = passwords->elts;
        cb = njt_ssl_cache_pkey_password_callback;

    } else {
        tries = 1;
        pwd = NULL;
        cb = NULL;
    }

    for ( ;; ) {

        pkey = PEM_read_bio_PrivateKey(bio, NULL, cb, pwd);
        if (pkey != NULL) {
            break;
        }

        if (tries-- > 1) {
            ERR_clear_error();
            (void) BIO_reset(bio);
            pwd++;
            continue;
        }

        *err = "PEM_read_bio_PrivateKey() failed";
        BIO_free(bio);
        return NULL;
    }

    BIO_free(bio);

    return pkey;
}


static int
njt_ssl_cache_pkey_password_callback(char *buf, int size, int rwflag,
    void *userdata)
{
    njt_str_t  *pwd = userdata;

    if (rwflag) {
        njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,
                      "njt_ssl_cache_pkey_password_callback() is called "
                      "for encryption");
        return 0;
    }

    if (pwd == NULL) {
        return 0;
    }

    if (pwd->len > (size_t) size) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                      "password is truncated to %d bytes", size);
    } else {
        size = pwd->len;
    }

    njt_memcpy(buf, pwd->data, size);

    return size;
}


static void
njt_ssl_cache_pkey_free(void *data)
{
    EVP_PKEY_free(data);
}


static void *
njt_ssl_cache_pkey_ref(char **err, void *data)
{
    EVP_PKEY  *pkey = data;

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    EVP_PKEY_up_ref(pkey);
#else
    CRYPTO_add(&pkey->references, 1, CRYPTO_LOCK_EVP_PKEY);
#endif

    return data;
}


static void *
njt_ssl_cache_crl_create(njt_ssl_cache_key_t *id, char **err, void *data)
{
    BIO                 *bio;
    u_long               n;
    X509_CRL            *x509;
    STACK_OF(X509_CRL)  *chain;

    chain = sk_X509_CRL_new_null();
    if (chain == NULL) {
        *err = "sk_X509_CRL_new_null() failed";
        return NULL;
    }

    bio = njt_ssl_cache_create_bio(id, err);
    if (bio == NULL) {
        sk_X509_CRL_pop_free(chain, X509_CRL_free);
        return NULL;
    }

    for ( ;; ) {

        x509 = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL);
        if (x509 == NULL) {
            n = ERR_peek_last_error();

            if (ERR_GET_LIB(n) == ERR_LIB_PEM
                && ERR_GET_REASON(n) == PEM_R_NO_START_LINE
                && sk_X509_CRL_num(chain) > 0)
            {
                /* end of file */
                ERR_clear_error();
                break;
            }

            /* some real error */

            *err = "PEM_read_bio_X509_CRL() failed";
            BIO_free(bio);
            sk_X509_CRL_pop_free(chain, X509_CRL_free);
            return NULL;
        }

        if (sk_X509_CRL_push(chain, x509) == 0) {
            *err = "sk_X509_CRL_push() failed";
            BIO_free(bio);
            X509_CRL_free(x509);
            sk_X509_CRL_pop_free(chain, X509_CRL_free);
            return NULL;
        }
    }

    BIO_free(bio);

    return chain;
}


static void
njt_ssl_cache_crl_free(void *data)
{
    sk_X509_CRL_pop_free(data, X509_CRL_free);
}


static void *
njt_ssl_cache_crl_ref(char **err, void *data)
{
    int                  n, i;
    X509_CRL            *x509;
    STACK_OF(X509_CRL)  *chain;

    chain = sk_X509_CRL_dup(data);
    if (chain == NULL) {
        *err = "sk_X509_CRL_dup() failed";
        return NULL;
    }

    n = sk_X509_CRL_num(chain);

    for (i = 0; i < n; i++) {
        x509 = sk_X509_CRL_value(chain, i);

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
        X509_CRL_up_ref(x509);
#else
        CRYPTO_add(&x509->references, 1, CRYPTO_LOCK_X509_CRL);
#endif
    }

    return chain;
}


static void *
njt_ssl_cache_ca_create(njt_ssl_cache_key_t *id, char **err, void *data)
{
    BIO             *bio;
    X509            *x509;
    u_long           n;
    STACK_OF(X509)  *chain;

    chain = sk_X509_new_null();
    if (chain == NULL) {
        *err = "sk_X509_new_null() failed";
        return NULL;
    }

    bio = njt_ssl_cache_create_bio(id, err);
    if (bio == NULL) {
        sk_X509_pop_free(chain, X509_free);
        return NULL;
    }

    for ( ;; ) {

        x509 = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
        if (x509 == NULL) {
            n = ERR_peek_last_error();

            if (ERR_GET_LIB(n) == ERR_LIB_PEM
                && ERR_GET_REASON(n) == PEM_R_NO_START_LINE
                && sk_X509_num(chain) > 0)
            {
                /* end of file */
                ERR_clear_error();
                break;
            }

            /* some real error */

            *err = "PEM_read_bio_X509_AUX() failed";
            BIO_free(bio);
            sk_X509_pop_free(chain, X509_free);
            return NULL;
        }

        if (sk_X509_push(chain, x509) == 0) {
            *err = "sk_X509_push() failed";
            BIO_free(bio);
            X509_free(x509);
            sk_X509_pop_free(chain, X509_free);
            return NULL;
        }
    }

    BIO_free(bio);

    return chain;
}


static BIO *
njt_ssl_cache_create_bio(njt_ssl_cache_key_t *id, char **err)
{
    BIO  *bio;

    if (id->type == NJT_SSL_CACHE_DATA) {

        bio = BIO_new_mem_buf(id->data + sizeof("data:") - 1,
                              id->len - (sizeof("data:") - 1));
        if (bio == NULL) {
            *err = "BIO_new_mem_buf() failed";
        }

        return bio;
    }

    bio = BIO_new_file((char *) id->data, "r");
    if (bio == NULL) {
        *err = "BIO_new_file() failed";
    }

    return bio;
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
