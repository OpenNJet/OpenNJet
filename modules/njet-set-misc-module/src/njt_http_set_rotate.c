#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"

#include <ndk.h>
#include "njt_http_set_rotate.h"
#include "njt_http_set_misc_module.h"
#include <stdlib.h>


njt_int_t
njt_http_set_misc_set_rotate(njt_http_request_t *r, njt_str_t *res,
    njt_http_variable_value_t *v)
{
    njt_http_variable_value_t   *rotate_from, *rotate_to, *rotate_num;
    njt_int_t                    int_from, int_to, tmp, int_current;

    njt_http_set_misc_loc_conf_t        *conf;

    rotate_num = &v[0];
    rotate_from = &v[1];
    rotate_to = &v[2];

    int_from = njt_atoi(rotate_from->data, rotate_from->len);
    if (int_from == NJT_ERROR) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "set_rotate: bad \"from\" argument value: \"%v\"",
                      rotate_from);
        return NJT_ERROR;
    }

    int_to = njt_atoi(rotate_to->data, rotate_to->len);
    if (int_to == NJT_ERROR) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "set_rotate: bad \"to\" argument value: \"%v\"",
                      rotate_to);
        return NJT_ERROR;
    }

    if (int_from > int_to) {
        tmp = int_from;
        int_from = int_to;
        int_to = tmp;
    }

    conf = njt_http_get_module_loc_conf(r, njt_http_set_misc_module);

    dd("current value not found: %d", (int) rotate_num->not_found);

    if (rotate_num->len == 0) {
        if (conf->current != NJT_CONF_UNSET) {
            int_current = conf->current;

        } else {
            int_current = int_from - 1;
        }

    } else {

        int_current = njt_atoi(rotate_num->data, rotate_num->len);
        if (int_current == NJT_ERROR) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "set_rotate: bad current value: \"%v\"", rotate_num);

            if (conf->current != NJT_CONF_UNSET) {
                int_current = conf->current;

            } else {
                int_current = int_from - 1;
            }
        }
    }

    int_current++;

    if (int_current > int_to || int_current < int_from) {
        int_current = int_from;
    }

    conf->current = int_current;

    res->data = njt_palloc(r->pool, NJT_INT_T_LEN);
    if (res->data == NULL) {
        return NJT_ERROR;
    }

    res->len = njt_sprintf(res->data, "%i", int_current) - res->data;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NJT_OK;
}


char *
njt_http_set_rotate(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_str_t               *value;
    ndk_set_var_t            filter;

    value = cf->args->elts;

    filter.type = NDK_SET_VAR_MULTI_VALUE;
    filter.func = (void *) njt_http_set_misc_set_rotate;
    filter.size = 3;
    filter.data = NULL;

    return ndk_set_var_multi_value_core(cf, &value[1], &value[1], &filter);
}

