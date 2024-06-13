#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"

#include "njt_http_set_hashed_upstream.h"


njt_uint_t
njt_http_set_misc_apply_distribution(njt_log_t *log, njt_uint_t hash,
    ndk_upstream_list_t *ul, njt_http_set_misc_distribution_t type)
{
    switch (type) {
    case njt_http_set_misc_distribution_modula:
        return (uint32_t) hash % (uint32_t) ul->nelts;

    default:
        njt_log_error(NJT_LOG_ERR, log, 0, "apply_distribution: "
                      "unknown distribution: %d", type);

        return 0;
    }

    /* impossible to reach here */
}


njt_int_t
njt_http_set_misc_set_hashed_upstream(njt_http_request_t *r, njt_str_t *res,
    njt_http_variable_value_t *v, void *data)
{
    njt_str_t                  **u;
    ndk_upstream_list_t         *ul = data;
    njt_str_t                    ulname;
    njt_uint_t                   hash, index;
    njt_http_variable_value_t   *key;

    if (ul == NULL) {
        ulname.data = v->data;
        ulname.len = v->len;

        dd("ulname: %.*s", (int) ulname.len, ulname.data);

        ul = ndk_get_upstream_list(ndk_http_get_main_conf(r),
                                   ulname.data, ulname.len);

        if (ul == NULL) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "set_hashed_upstream: upstream list \"%V\" "
                    "not defined yet", &ulname);
            return NJT_ERROR;
        }

        key = v + 1;

    } else {
        key = v;
    }

    if (ul->nelts == 0) {
        res->data = NULL;
        res->len = 0;

        return NJT_OK;
    }

    u = ul->elts;

    dd("upstream list: %d upstreams found", (int) ul->nelts);

    if (ul->nelts == 1) {
        dd("only one upstream found in the list");

        res->data = u[0]->data;
        res->len = u[0]->len;

        return NJT_OK;
    }

    dd("key: \"%.*s\"", key->len, key->data);

    hash = njt_hash_key_lc(key->data, key->len);

    index = njt_http_set_misc_apply_distribution(r->connection->log, hash, ul,
            njt_http_set_misc_distribution_modula);

    res->data = u[index]->data;
    res->len = u[index]->len;

    return NJT_OK;
}


char *
njt_http_set_hashed_upstream(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_str_t               *value;
    ndk_set_var_t            filter;
    njt_uint_t               n;
    njt_str_t               *var;
    njt_str_t               *ulname;
    ndk_upstream_list_t     *ul;
    njt_str_t               *v;

    value = cf->args->elts;

    var = &value[1];
    ulname = &value[2];

    n = njt_http_script_variables_count(ulname);

    filter.func = (void *) njt_http_set_misc_set_hashed_upstream;

    if (n) {
        /* upstream list name contains variables */
        v = &value[2];
        filter.size = 2;
        filter.data = NULL;
        filter.type = NDK_SET_VAR_MULTI_VALUE_DATA;

        return  ndk_set_var_multi_value_core(cf, var, v, &filter);
    }

    ul = ndk_get_upstream_list(ndk_http_conf_get_main_conf(cf),
                               ulname->data, ulname->len);
    if (ul == NULL) {
        njt_log_error(NJT_LOG_ERR, cf->log, 0,
                      "set_hashed_upstream: upstream list \"%V\" "
                      "not defined yet", ulname);
        return NJT_CONF_ERROR;
    }

    v = &value[3];

    filter.size = 1;
    filter.data = ul;
    filter.type = NDK_SET_VAR_VALUE_DATA;

    return ndk_set_var_value_core(cf, var, v, &filter);
}

