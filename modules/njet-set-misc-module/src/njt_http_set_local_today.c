#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"

#include <ndk.h>


#ifndef NJT_HTTP_SET_MISC_FMT_DATE_LEN
#define NJT_HTTP_SET_MISC_FMT_DATE_LEN       256
#endif


njt_int_t
njt_http_set_local_today(njt_http_request_t *r, njt_str_t *res,
    njt_http_variable_value_t *v)
{
    time_t           now;
    njt_tm_t         tm;
    u_char          *p;

    /*t = njt_timeofday();*/

    now = njt_time();

    njt_gmtime(now + njt_cached_time->gmtoff * 60, &tm);

    dd("tm.njt_tm_hour:%d", tm.njt_tm_hour);

    p = njt_palloc(r->pool, sizeof("yyyy-mm-dd") - 1);
    if (p == NULL) {
        return NJT_ERROR;
    }

    njt_sprintf(p, "%04d-%02d-%02d", tm.njt_tm_year, tm.njt_tm_mon,
                tm.njt_tm_mday);

    res->data = p;
    res->len = sizeof("yyyy-mm-dd") - 1;

    return NJT_OK;
}


njt_int_t
njt_http_set_formatted_gmt_time(njt_http_request_t *r, njt_str_t *res,
    njt_http_variable_value_t *v)
{
    time_t           now;
    u_char          *p;
    struct tm        tm;

    if (v->not_found || v->len == 0) {
        res->data = NULL;
        res->len = 0;
        return NJT_OK;
    }

    now = njt_time();
    njt_libc_gmtime(now, &tm);

    p = njt_palloc(r->pool, NJT_HTTP_SET_MISC_FMT_DATE_LEN);
    if (p == NULL) {
        return NJT_ERROR;
    }

    res->len = strftime((char *) p, NJT_HTTP_SET_MISC_FMT_DATE_LEN,
                        (char *) v->data, &tm);
    if (res->len == 0) {
        return NJT_ERROR;
    }

    res->data = p;

    return NJT_OK;
}


njt_int_t
njt_http_set_formatted_local_time(njt_http_request_t *r, njt_str_t *res,
    njt_http_variable_value_t *v)
{
    time_t           now;
    u_char          *p;
    struct tm        tm;

    if (v->not_found || v->len == 0) {
        res->data = NULL;
        res->len = 0;
        return NJT_OK;
    }

    now = njt_time();
    njt_libc_localtime(now, &tm);

    p = njt_palloc(r->pool, NJT_HTTP_SET_MISC_FMT_DATE_LEN);
    if (p == NULL) {
        return NJT_ERROR;
    }

    res->len = strftime((char *) p, NJT_HTTP_SET_MISC_FMT_DATE_LEN,
                        (char *) v->data, &tm);
    if (res->len == 0) {
        return NJT_ERROR;
    }

    res->data = p;

    return NJT_OK;
}
