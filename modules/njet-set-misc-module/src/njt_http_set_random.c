#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include <ndk.h>
#include "njt_http_set_random.h"
#include <stdlib.h>


njt_int_t
njt_http_set_misc_set_random(njt_http_request_t *r, njt_str_t *res,
    njt_http_variable_value_t *v)
{
    njt_http_variable_value_t   *rand_from, *rand_to;
    njt_int_t                    int_from, int_to, tmp, random;

    rand_from = v;
    rand_to = v + 1;

    int_from = njt_atoi(rand_from->data, rand_from->len);
    if (int_from == NJT_ERROR) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "set_random: bad \"from\" argument: %v", rand_from);
        return NJT_ERROR;
    }

    int_to = njt_atoi(rand_to->data, rand_to->len);
    if (int_to == NJT_ERROR) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "set_random: bad \"to\" argument: %v", rand_to);
        return NJT_ERROR;
    }

    if (int_from > int_to) {
        tmp = int_from;
        int_from = int_to;
        int_to = tmp;
    }

    random = rand() % (int_to - int_from + 1) + int_from;

    res->data = njt_palloc(r->pool, NJT_INT_T_LEN);
    if (res->data == NULL) {
        return NJT_ERROR;
    }

    res->len = njt_sprintf(res->data, "%i", random) - res->data;

    /* Set all required params */
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NJT_OK;
}
