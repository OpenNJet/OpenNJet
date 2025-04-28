
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

#define NJT_SSL_CACHE_DISABLED  (njt_array_t *) (uintptr_t) -1


#define njt_ssl_cache_get_conf(cycle)                                         \
    (njt_ssl_cache_t *) njt_get_conf(cycle->conf_ctx, njt_openssl_cache_module)

#define njt_ssl_cache_get_old_conf(cycle)                                     \
    cycle->old_cycle->conf_ctx ? njt_ssl_cache_get_conf(cycle->old_cycle)     \
                               : NULL


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
    njt_queue_t                 queue;
    njt_ssl_cache_key_t         id;
    njt_ssl_cache_type_t       *type;
    void                       *value;

    time_t                      created;
    time_t                      accessed;

    time_t                      mtime;
    njt_file_uniq_t             uniq;
} njt_ssl_cache_node_t;


struct njt_ssl_cache_s {
    njt_rbtree_t                rbtree;
    njt_rbtree_node_t           sentinel;
    njt_queue_t                 expire_queue;

    njt_flag_t                  inheritable;

    njt_uint_t                  current;
    njt_uint_t                  max;
    time_t                      valid;
    time_t                      inactive;
};


typedef struct {
    njt_str_t                  *pwd;
    unsigned                    encrypted:1;
} njt_ssl_cache_pwd_t;


static njt_int_t njt_ssl_cache_init_key(njt_pool_t *pool, njt_uint_t index,
    njt_str_t *path, njt_ssl_cache_key_t *id);
static njt_ssl_cache_node_t *njt_ssl_cache_lookup(njt_ssl_cache_t *cache,
    njt_ssl_cache_type_t *type, njt_ssl_cache_key_t *id, uint32_t hash);
static void njt_ssl_cache_expire(njt_ssl_cache_t *cache, njt_uint_t n,
    njt_log_t *log);

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
static char *njt_openssl_cache_init_conf(njt_cycle_t *cycle, void *conf);
static void njt_ssl_cache_cleanup(void *data);
static void njt_ssl_cache_node_insert(njt_rbtree_node_t *temp,
    njt_rbtree_node_t *node, njt_rbtree_node_t *sentinel);
static void njt_ssl_cache_node_free(njt_rbtree_t *rbtree,
    njt_ssl_cache_node_t *cn);


static njt_command_t  njt_openssl_cache_commands[] = {

    { njt_string("ssl_object_cache_inheritable"),
      NJT_MAIN_CONF|NJT_DIRECT_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      0,
      offsetof(njt_ssl_cache_t, inheritable),
      NULL },

      njt_null_command
};


static njt_core_module_t  njt_openssl_cache_module_ctx = {
    njt_string("openssl_cache"),
    njt_openssl_cache_create_conf,
    njt_openssl_cache_init_conf
};


njt_module_t  njt_openssl_cache_module = {
    NJT_MODULE_V1,
    &njt_openssl_cache_module_ctx,         /* module context */
    njt_openssl_cache_commands,            /* module directives */
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
    void                  *value;
    time_t                 mtime;
    uint32_t               hash;
    njt_int_t              rc;
    njt_file_uniq_t        uniq;
    njt_file_info_t        fi;
    njt_ssl_cache_t       *cache, *old_cache;
    njt_ssl_cache_key_t    id;
    njt_ssl_cache_type_t  *type;
    njt_ssl_cache_node_t  *cn;

    *err = NULL;

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

    value = NULL;

    if (id.type == NJT_SSL_CACHE_PATH
        && (rc = njt_file_info(id.data, &fi)) != NJT_FILE_ERROR)
    {
        mtime = njt_file_mtime(&fi);
        uniq = njt_file_uniq(&fi);

    } else {
        rc = NJT_FILE_ERROR;
        mtime = 0;
        uniq = 0;
    }

   /* try to use a reference from the old cycle */

    old_cache = njt_ssl_cache_get_old_conf(cf->cycle);

    if (old_cache && old_cache->inheritable) {
        cn = njt_ssl_cache_lookup(old_cache, type, &id, hash);

        if (cn != NULL) {
            switch (id.type) {

            case NJT_SSL_CACHE_DATA:
                value = type->ref(err, cn->value);
                break;

            default:
                if (rc != NJT_FILE_ERROR
                    && uniq == cn->uniq && mtime == cn->mtime)
                {
                    value = type->ref(err, cn->value);
                }
                break;
           }
        }
    }

    if (value == NULL) {
        value = type->create(&id, err, &data);

        if (value == NULL || data == NJT_SSL_CACHE_DISABLED) {
            return value;
        }
    }

    cn = njt_palloc(cf->cycle->pool, sizeof(njt_ssl_cache_node_t) + id.len + 1);
    if (cn == NULL) {
        type->free(value);
        return NULL;
    }

    cn->node.key = hash;
    cn->id.data = (u_char *)(cn + 1);
    cn->id.len = id.len;
    cn->id.type = id.type;
    cn->type = type;
    cn->value = value;
    cn->mtime = mtime;
    cn->uniq = uniq;

    njt_cpystrn(cn->id.data, id.data, id.len + 1);

    njt_queue_init(&cn->queue);

    njt_rbtree_insert(&cache->rbtree, &cn->node);

    return type->ref(err, cn->value);
}


void *
njt_ssl_cache_connection_fetch(njt_ssl_cache_t *cache, njt_pool_t *pool,
    njt_uint_t index, char **err, njt_str_t *path, void *data)
 {
    void                  *value;
    time_t                 now;
    uint32_t               hash;
    njt_ssl_cache_key_t    id;
    njt_ssl_cache_type_t  *type;
    njt_ssl_cache_node_t  *cn;

    *err = NULL;

#if (NJT_HAVE_NTLS)
    njt_str_t  tcert;

    tcert = *path;
    njt_ssl_ntls_prefix_strip(&tcert);
    path = &tcert;
#endif

    if (njt_ssl_cache_init_key(pool, index, path, &id) != NJT_OK) {
        return NULL;
    }

    type = &njt_ssl_cache_types[index];

    if (cache == NULL) {
        return type->create(&id, err, &data);
    }

    now = njt_time();

    hash = njt_murmur_hash2(id.data, id.len);

    cn = njt_ssl_cache_lookup(cache, type, &id, hash);

    if (cn != NULL) {
        njt_queue_remove(&cn->queue);

        if (id.type == NJT_SSL_CACHE_DATA) {
            goto found;
        }

        if (now - cn->created > cache->valid) {
            njt_log_debug1(NJT_LOG_DEBUG_CORE, pool->log, 0,
                           "update cached ssl object: %s", cn->id.data);

            type->free(cn->value);

            value = type->create(&id, err, &data);

            if (value == NULL || data == NJT_SSL_CACHE_DISABLED) {
                njt_rbtree_delete(&cache->rbtree, &cn->node);

                cache->current--;

                njt_free(cn);

                return value;
            }

            cn->value = value;
            cn->created = now;
        }

        goto found;
    }

    value = type->create(&id, err, &data);

    if (value == NULL || data == NJT_SSL_CACHE_DISABLED) {
        return value;
    }

    cn = njt_alloc(sizeof(njt_ssl_cache_node_t) + id.len + 1, pool->log);
    if (cn == NULL) {
        type->free(value);
        return NULL;
    }

    cn->node.key = hash;
    cn->id.data = (u_char *)(cn + 1);
    cn->id.len = id.len;
    cn->id.type = id.type;
    cn->type = type;
    cn->value = value;
    cn->created = now;

    njt_cpystrn(cn->id.data, id.data, id.len + 1);

    njt_ssl_cache_expire(cache, 1, pool->log);

    if (cache->current >= cache->max) {
        njt_ssl_cache_expire(cache, 0, pool->log);
    }

    njt_rbtree_insert(&cache->rbtree, &cn->node);

    cache->current++;

found:

    cn->accessed = now;

    njt_queue_insert_head(&cache->expire_queue, &cn->queue);

    return type->ref(err, cn->value);
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


static void
njt_ssl_cache_expire(njt_ssl_cache_t *cache, njt_uint_t n,
    njt_log_t *log)
{
    time_t                 now;
    njt_queue_t           *q;
    njt_ssl_cache_node_t  *cn;

    now = njt_time();

    while (n < 3) {

        if (njt_queue_empty(&cache->expire_queue)) {
            return;
        }

        q = njt_queue_last(&cache->expire_queue);

        cn = njt_queue_data(q, njt_ssl_cache_node_t, queue);

        if (n++ != 0 && now - cn->accessed <= cache->inactive) {
            return;
        }

        njt_ssl_cache_node_free(&cache->rbtree, cn);

        cache->current--;
    }
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
    njt_array_t  **passwords = data;

    BIO                  *bio;
    EVP_PKEY             *pkey;
    njt_uint_t            tries;
    pem_password_cb      *cb;
    njt_ssl_cache_pwd_t   cb_data, *pwd;

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

    cb_data.encrypted = 0;

    if (*passwords) {
        cb_data.pwd = (*passwords)->elts;
        tries = (*passwords)->nelts;
        pwd = &cb_data;
        cb = njt_ssl_cache_pkey_password_callback;

    } else {
        cb_data.pwd = NULL;
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
            cb_data.pwd++;
            continue;
        }

        *err = "PEM_read_bio_PrivateKey() failed";
        BIO_free(bio);
        return NULL;
    }

    if (cb_data.encrypted) {
        *passwords = NJT_SSL_CACHE_DISABLED;
    }

    BIO_free(bio);

    return pkey;
}


static int
njt_ssl_cache_pkey_password_callback(char *buf, int size, int rwflag,
    void *userdata)
{
    njt_ssl_cache_pwd_t  *data = userdata;

    njt_str_t  *pwd;

    if (rwflag) {
        njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,
                      "njt_ssl_cache_pkey_password_callback() is called "
                      "for encryption");
        return 0;
    }

    data->encrypted = 1;

    pwd = data->pwd;

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
    njt_ssl_cache_t  *cache;

    cache = njt_ssl_cache_init(cycle->pool, 0, 0, 0);
    if (cache == NULL) {
        return NULL;
    }

    cache->inheritable = NJT_CONF_UNSET;

    return cache;
}


static char *
njt_openssl_cache_init_conf(njt_cycle_t *cycle, void *conf)
{
    njt_ssl_cache_t *cache = conf;

    // njt_conf_init_value(cache->inheritable, 1); // nginx
    njt_conf_init_value(cache->inheritable, 0); // njet

    return NJT_CONF_OK;
}


njt_ssl_cache_t *
njt_ssl_cache_init(njt_pool_t *pool, njt_uint_t max, time_t valid,
    time_t inactive)
{
    njt_ssl_cache_t     *cache;
    njt_pool_cleanup_t  *cln;

    cache = njt_pcalloc(pool, sizeof(njt_ssl_cache_t));
    if (cache == NULL) {
        return NULL;
    }

    njt_rbtree_init(&cache->rbtree, &cache->sentinel,
                    njt_ssl_cache_node_insert);

    njt_queue_init(&cache->expire_queue);

    cache->max = max;
    cache->valid = valid;
    cache->inactive = inactive;

    cln = njt_pool_cleanup_add(pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = njt_ssl_cache_cleanup;
    cln->data = cache;

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

    node = njt_rbtree_min(tree->root, tree->sentinel);

    while (node != NULL) {
        cn = njt_rbtree_data(node, njt_ssl_cache_node_t, node);
        node = njt_rbtree_next(tree, node);

        njt_ssl_cache_node_free(tree, cn);

        if (cache->max) {
            cache->current--;
        }
    }

    if (cache->current) {
        njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,
                      "%ui items still left in ssl cache",
                      cache->current);
    }

    if (!njt_queue_empty(&cache->expire_queue)) {
        njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,
                      "queue still is not empty in ssl cache");

    }
}


static void
njt_ssl_cache_node_free(njt_rbtree_t *rbtree, njt_ssl_cache_node_t *cn)
{
    cn->type->free(cn->value);

    njt_rbtree_delete(rbtree, &cn->node);

    if (!njt_queue_empty(&cn->queue)) {
        njt_queue_remove(&cn->queue);

        njt_log_debug1(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0,
                       "delete cached ssl object: %s", cn->id.data);

        njt_free(cn);
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
