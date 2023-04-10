
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


#define NJT_HTTP_REFERER_NO_URI_PART  ((void *) 4)


typedef struct {
    njt_hash_combined_t      hash;

#if (NJT_PCRE)
    njt_array_t             *regex;
    njt_array_t             *server_name_regex;
#endif

    njt_flag_t               no_referer;
    njt_flag_t               blocked_referer;
    njt_flag_t               server_names;

    njt_hash_keys_arrays_t  *keys;

    njt_uint_t               referer_hash_max_size;
    njt_uint_t               referer_hash_bucket_size;
} njt_http_referer_conf_t;


static njt_int_t njt_http_referer_add_variables(njt_conf_t *cf);
static void * njt_http_referer_create_conf(njt_conf_t *cf);
static char * njt_http_referer_merge_conf(njt_conf_t *cf, void *parent,
    void *child);
static char *njt_http_valid_referers(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static njt_int_t njt_http_add_referer(njt_conf_t *cf,
    njt_hash_keys_arrays_t *keys, njt_str_t *value, njt_str_t *uri);
static njt_int_t njt_http_add_regex_referer(njt_conf_t *cf,
    njt_http_referer_conf_t *rlcf, njt_str_t *name);
#if (NJT_PCRE)
static njt_int_t njt_http_add_regex_server_name(njt_conf_t *cf,
    njt_http_referer_conf_t *rlcf, njt_http_regex_t *regex);
#endif
static int njt_libc_cdecl njt_http_cmp_referer_wildcards(const void *one,
    const void *two);


static njt_command_t  njt_http_referer_commands[] = {

    { njt_string("valid_referers"),
      NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_http_valid_referers,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("referer_hash_max_size"),
      NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_referer_conf_t, referer_hash_max_size),
      NULL },

    { njt_string("referer_hash_bucket_size"),
      NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_referer_conf_t, referer_hash_bucket_size),
      NULL },

      njt_null_command
};


static njt_http_module_t  njt_http_referer_module_ctx = {
    njt_http_referer_add_variables,        /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_referer_create_conf,          /* create location configuration */
    njt_http_referer_merge_conf            /* merge location configuration */
};


njt_module_t  njt_http_referer_module = {
    NJT_MODULE_V1,
    &njt_http_referer_module_ctx,          /* module context */
    njt_http_referer_commands,             /* module directives */
    NJT_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};


static njt_str_t  njt_http_invalid_referer_name = njt_string("invalid_referer");


static njt_int_t
njt_http_referer_variable(njt_http_request_t *r, njt_http_variable_value_t *v,
    uintptr_t data)
{
    u_char                    *p, *ref, *last;
    size_t                     len;
    njt_str_t                 *uri;
    njt_uint_t                 i, key;
    njt_http_referer_conf_t   *rlcf;
    u_char                     buf[256];
#if (NJT_PCRE)
    njt_int_t                  rc;
    njt_str_t                  referer;
#endif

    rlcf = njt_http_get_module_loc_conf(r, njt_http_referer_module);

    if (rlcf->hash.hash.buckets == NULL
        && rlcf->hash.wc_head == NULL
        && rlcf->hash.wc_tail == NULL
#if (NJT_PCRE)
        && rlcf->regex == NULL
        && rlcf->server_name_regex == NULL
#endif
       )
    {
        goto valid;
    }

    if (r->headers_in.referer == NULL) {
        if (rlcf->no_referer) {
            goto valid;
        }

        goto invalid;
    }

    len = r->headers_in.referer->value.len;
    ref = r->headers_in.referer->value.data;

    if (len >= sizeof("http://i.ru") - 1) {
        last = ref + len;

        if (njt_strncasecmp(ref, (u_char *) "http://", 7) == 0) {
            ref += 7;
            len -= 7;
            goto valid_scheme;

        } else if (njt_strncasecmp(ref, (u_char *) "https://", 8) == 0) {
            ref += 8;
            len -= 8;
            goto valid_scheme;
        }
    }

    if (rlcf->blocked_referer) {
        goto valid;
    }

    goto invalid;

valid_scheme:

    i = 0;
    key = 0;

    for (p = ref; p < last; p++) {
        if (*p == '/' || *p == ':') {
            break;
        }

        if (i == 256) {
            goto invalid;
        }

        buf[i] = njt_tolower(*p);
        key = njt_hash(key, buf[i++]);
    }

    uri = njt_hash_find_combined(&rlcf->hash, key, buf, p - ref);

    if (uri) {
        goto uri;
    }

#if (NJT_PCRE)

    if (rlcf->server_name_regex) {
        referer.len = p - ref;
        referer.data = buf;

        rc = njt_regex_exec_array(rlcf->server_name_regex, &referer,
                                  r->connection->log);

        if (rc == NJT_OK) {
            goto valid;
        }

        if (rc == NJT_ERROR) {
            return rc;
        }

        /* NJT_DECLINED */
    }

    if (rlcf->regex) {
        referer.len = len;
        referer.data = ref;

        rc = njt_regex_exec_array(rlcf->regex, &referer, r->connection->log);

        if (rc == NJT_OK) {
            goto valid;
        }

        if (rc == NJT_ERROR) {
            return rc;
        }

        /* NJT_DECLINED */
    }

#endif

invalid:

    *v = njt_http_variable_true_value;

    return NJT_OK;

uri:

    for ( /* void */ ; p < last; p++) {
        if (*p == '/') {
            break;
        }
    }

    len = last - p;

    if (uri == NJT_HTTP_REFERER_NO_URI_PART) {
        goto valid;
    }

    if (len < uri->len || njt_strncmp(uri->data, p, uri->len) != 0) {
        goto invalid;
    }

valid:

    *v = njt_http_variable_null_value;

    return NJT_OK;
}


static njt_int_t
njt_http_referer_add_variables(njt_conf_t *cf)
{
    njt_http_variable_t  *var;

    var = njt_http_add_variable(cf, &njt_http_invalid_referer_name,
                                NJT_HTTP_VAR_CHANGEABLE);
    if (var == NULL) {
        return NJT_ERROR;
    }

    var->get_handler = njt_http_referer_variable;

    return NJT_OK;
}


static void *
njt_http_referer_create_conf(njt_conf_t *cf)
{
    njt_http_referer_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_referer_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     conf->hash = { NULL };
     *     conf->server_names = 0;
     *     conf->keys = NULL;
     */

#if (NJT_PCRE)
    conf->regex = NJT_CONF_UNSET_PTR;
    conf->server_name_regex = NJT_CONF_UNSET_PTR;
#endif

    conf->no_referer = NJT_CONF_UNSET;
    conf->blocked_referer = NJT_CONF_UNSET;
    conf->referer_hash_max_size = NJT_CONF_UNSET_UINT;
    conf->referer_hash_bucket_size = NJT_CONF_UNSET_UINT;

    return conf;
}


static char *
njt_http_referer_merge_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_referer_conf_t *prev = parent;
    njt_http_referer_conf_t *conf = child;

    njt_uint_t                 n;
    njt_hash_init_t            hash;
    njt_http_server_name_t    *sn;
    njt_http_core_srv_conf_t  *cscf;

    if (conf->keys == NULL) {
        conf->hash = prev->hash;

#if (NJT_PCRE)
        njt_conf_merge_ptr_value(conf->regex, prev->regex, NULL);
        njt_conf_merge_ptr_value(conf->server_name_regex,
                                 prev->server_name_regex, NULL);
#endif
        njt_conf_merge_value(conf->no_referer, prev->no_referer, 0);
        njt_conf_merge_value(conf->blocked_referer, prev->blocked_referer, 0);
        njt_conf_merge_uint_value(conf->referer_hash_max_size,
                                  prev->referer_hash_max_size, 2048);
        njt_conf_merge_uint_value(conf->referer_hash_bucket_size,
                                  prev->referer_hash_bucket_size, 64);

        return NJT_CONF_OK;
    }

    if (conf->server_names == 1) {
        cscf = njt_http_conf_get_module_srv_conf(cf, njt_http_core_module);

        sn = cscf->server_names.elts;
        for (n = 0; n < cscf->server_names.nelts; n++) {

#if (NJT_PCRE)
            if (sn[n].regex) {

                if (njt_http_add_regex_server_name(cf, conf, sn[n].regex)
                    != NJT_OK)
                {
                    return NJT_CONF_ERROR;
                }

                continue;
            }
#endif

            if (njt_http_add_referer(cf, conf->keys, &sn[n].name, NULL)
                != NJT_OK)
            {
                return NJT_CONF_ERROR;
            }
        }
    }

    if ((conf->no_referer == 1 || conf->blocked_referer == 1)
        && conf->keys->keys.nelts == 0
        && conf->keys->dns_wc_head.nelts == 0
        && conf->keys->dns_wc_tail.nelts == 0)
    {
        njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                      "the \"none\" or \"blocked\" referers are specified "
                      "in the \"valid_referers\" directive "
                      "without any valid referer");
        return NJT_CONF_ERROR;
    }

    njt_conf_merge_uint_value(conf->referer_hash_max_size,
                              prev->referer_hash_max_size, 2048);
    njt_conf_merge_uint_value(conf->referer_hash_bucket_size,
                              prev->referer_hash_bucket_size, 64);
    conf->referer_hash_bucket_size = njt_align(conf->referer_hash_bucket_size,
                                               njt_cacheline_size);

    hash.key = njt_hash_key_lc;
    hash.max_size = conf->referer_hash_max_size;
    hash.bucket_size = conf->referer_hash_bucket_size;
    hash.name = "referer_hash";
    hash.pool = cf->pool;

    if (conf->keys->keys.nelts) {
        hash.hash = &conf->hash.hash;
        hash.temp_pool = NULL;

        if (njt_hash_init(&hash, conf->keys->keys.elts, conf->keys->keys.nelts)
            != NJT_OK)
        {
            return NJT_CONF_ERROR;
        }
    }

    if (conf->keys->dns_wc_head.nelts) {

        njt_qsort(conf->keys->dns_wc_head.elts,
                  (size_t) conf->keys->dns_wc_head.nelts,
                  sizeof(njt_hash_key_t),
                  njt_http_cmp_referer_wildcards);

        hash.hash = NULL;
        hash.temp_pool = cf->temp_pool;

        if (njt_hash_wildcard_init(&hash, conf->keys->dns_wc_head.elts,
                                   conf->keys->dns_wc_head.nelts)
            != NJT_OK)
        {
            return NJT_CONF_ERROR;
        }

        conf->hash.wc_head = (njt_hash_wildcard_t *) hash.hash;
    }

    if (conf->keys->dns_wc_tail.nelts) {

        njt_qsort(conf->keys->dns_wc_tail.elts,
                  (size_t) conf->keys->dns_wc_tail.nelts,
                  sizeof(njt_hash_key_t),
                  njt_http_cmp_referer_wildcards);

        hash.hash = NULL;
        hash.temp_pool = cf->temp_pool;

        if (njt_hash_wildcard_init(&hash, conf->keys->dns_wc_tail.elts,
                                   conf->keys->dns_wc_tail.nelts)
            != NJT_OK)
        {
            return NJT_CONF_ERROR;
        }

        conf->hash.wc_tail = (njt_hash_wildcard_t *) hash.hash;
    }

#if (NJT_PCRE)
    njt_conf_merge_ptr_value(conf->regex, prev->regex, NULL);
    njt_conf_merge_ptr_value(conf->server_name_regex, prev->server_name_regex,
                             NULL);
#endif

    if (conf->no_referer == NJT_CONF_UNSET) {
        conf->no_referer = 0;
    }

    if (conf->blocked_referer == NJT_CONF_UNSET) {
        conf->blocked_referer = 0;
    }

    conf->keys = NULL;

    return NJT_CONF_OK;
}


static char *
njt_http_valid_referers(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_referer_conf_t  *rlcf = conf;

    u_char      *p;
    njt_str_t   *value, uri;
    njt_uint_t   i;

    if (rlcf->keys == NULL) {
        rlcf->keys = njt_pcalloc(cf->temp_pool, sizeof(njt_hash_keys_arrays_t));
        if (rlcf->keys == NULL) {
            return NJT_CONF_ERROR;
        }

        rlcf->keys->pool = cf->pool;
        rlcf->keys->temp_pool = cf->pool;

        if (njt_hash_keys_array_init(rlcf->keys, NJT_HASH_SMALL) != NJT_OK) {
            return NJT_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        if (value[i].len == 0) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid referer \"%V\"", &value[i]);
            return NJT_CONF_ERROR;
        }

        if (njt_strcmp(value[i].data, "none") == 0) {
            rlcf->no_referer = 1;
            continue;
        }

        if (njt_strcmp(value[i].data, "blocked") == 0) {
            rlcf->blocked_referer = 1;
            continue;
        }

        if (njt_strcmp(value[i].data, "server_names") == 0) {
            rlcf->server_names = 1;
            continue;
        }

        if (value[i].data[0] == '~') {
            if (njt_http_add_regex_referer(cf, rlcf, &value[i]) != NJT_OK) {
                return NJT_CONF_ERROR;
            }

            continue;
        }

        njt_str_null(&uri);

        p = (u_char *) njt_strchr(value[i].data, '/');

        if (p) {
            uri.len = (value[i].data + value[i].len) - p;
            uri.data = p;
            value[i].len = p - value[i].data;
        }

        if (njt_http_add_referer(cf, rlcf->keys, &value[i], &uri) != NJT_OK) {
            return NJT_CONF_ERROR;
        }
    }

    return NJT_CONF_OK;
}


static njt_int_t
njt_http_add_referer(njt_conf_t *cf, njt_hash_keys_arrays_t *keys,
    njt_str_t *value, njt_str_t *uri)
{
    njt_int_t   rc;
    njt_str_t  *u;

    if (uri == NULL || uri->len == 0) {
        u = NJT_HTTP_REFERER_NO_URI_PART;

    } else {
        u = njt_palloc(cf->pool, sizeof(njt_str_t));
        if (u == NULL) {
            return NJT_ERROR;
        }

        *u = *uri;
    }

    rc = njt_hash_add_key(keys, value, u, NJT_HASH_WILDCARD_KEY);

    if (rc == NJT_OK) {
        return NJT_OK;
    }

    if (rc == NJT_DECLINED) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid hostname or wildcard \"%V\"", value);
    }

    if (rc == NJT_BUSY) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "conflicting parameter \"%V\"", value);
    }

    return NJT_ERROR;
}


static njt_int_t
njt_http_add_regex_referer(njt_conf_t *cf, njt_http_referer_conf_t *rlcf,
    njt_str_t *name)
{
#if (NJT_PCRE)
    njt_regex_elt_t      *re;
    njt_regex_compile_t   rc;
    u_char                errstr[NJT_MAX_CONF_ERRSTR];

    if (name->len == 1) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "empty regex in \"%V\"", name);
        return NJT_ERROR;
    }

    if (rlcf->regex == NJT_CONF_UNSET_PTR) {
        rlcf->regex = njt_array_create(cf->pool, 2, sizeof(njt_regex_elt_t));
        if (rlcf->regex == NULL) {
            return NJT_ERROR;
        }
    }

    re = njt_array_push(rlcf->regex);
    if (re == NULL) {
        return NJT_ERROR;
    }

    name->len--;
    name->data++;

    njt_memzero(&rc, sizeof(njt_regex_compile_t));

    rc.pattern = *name;
    rc.pool = cf->pool;
    rc.options = NJT_REGEX_CASELESS;
    rc.err.len = NJT_MAX_CONF_ERRSTR;
    rc.err.data = errstr;

    if (njt_regex_compile(&rc) != NJT_OK) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "%V", &rc.err);
        return NJT_ERROR;
    }

    re->regex = rc.regex;
    re->name = name->data;

    return NJT_OK;

#else

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "the using of the regex \"%V\" requires PCRE library",
                       name);

    return NJT_ERROR;

#endif
}


#if (NJT_PCRE)

static njt_int_t
njt_http_add_regex_server_name(njt_conf_t *cf, njt_http_referer_conf_t *rlcf,
    njt_http_regex_t *regex)
{
    njt_regex_elt_t  *re;

    if (rlcf->server_name_regex == NJT_CONF_UNSET_PTR) {
        rlcf->server_name_regex = njt_array_create(cf->pool, 2,
                                                   sizeof(njt_regex_elt_t));
        if (rlcf->server_name_regex == NULL) {
            return NJT_ERROR;
        }
    }

    re = njt_array_push(rlcf->server_name_regex);
    if (re == NULL) {
        return NJT_ERROR;
    }

    re->regex = regex->regex;
    re->name = regex->name.data;

    return NJT_OK;
}

#endif


static int njt_libc_cdecl
njt_http_cmp_referer_wildcards(const void *one, const void *two)
{
    njt_hash_key_t  *first, *second;

    first = (njt_hash_key_t *) one;
    second = (njt_hash_key_t *) two;

    return njt_dns_strcmp(first->key.data, second->key.data);
}
