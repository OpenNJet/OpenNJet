
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.yy
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_http_lua_common.h"


double
njt_http_lua_ffi_now(void)
{
    njt_time_t              *tp;

    tp = njt_timeofday();

    return tp->sec + tp->msec / 1000.0;
}


double
njt_http_lua_ffi_req_start_time(njt_http_request_t *r)
{
    return r->start_sec + r->start_msec / 1000.0;
}


long
njt_http_lua_ffi_time(void)
{
    return (long) njt_time();
}


long
njt_http_lua_ffi_monotonic_msec(void)
{
    return (long) njt_current_msec;
}


void
njt_http_lua_ffi_update_time(void)
{
    njt_time_update();
}


void
njt_http_lua_ffi_today(u_char *buf)
{
    njt_tm_t                 tm;

    njt_gmtime(njt_time() + njt_cached_time->gmtoff * 60, &tm);

    njt_sprintf(buf, "%04d-%02d-%02d", tm.njt_tm_year, tm.njt_tm_mon,
                tm.njt_tm_mday);
}


void
njt_http_lua_ffi_localtime(u_char *buf)
{
    njt_tm_t                 tm;

    njt_gmtime(njt_time() + njt_cached_time->gmtoff * 60, &tm);

    njt_sprintf(buf, "%04d-%02d-%02d %02d:%02d:%02d", tm.njt_tm_year,
                tm.njt_tm_mon, tm.njt_tm_mday, tm.njt_tm_hour, tm.njt_tm_min,
                tm.njt_tm_sec);
}


void
njt_http_lua_ffi_utctime(u_char *buf)
{
    njt_tm_t       tm;

    njt_gmtime(njt_time(), &tm);

    njt_sprintf(buf, "%04d-%02d-%02d %02d:%02d:%02d", tm.njt_tm_year,
                tm.njt_tm_mon, tm.njt_tm_mday, tm.njt_tm_hour, tm.njt_tm_min,
                tm.njt_tm_sec);
}


int
njt_http_lua_ffi_cookie_time(u_char *buf, long t)
{
    u_char                              *p;

    p = njt_http_cookie_time(buf, t);
    return p - buf;
}


void
njt_http_lua_ffi_http_time(u_char *buf, long t)
{
    njt_http_time(buf, t);
}


void
njt_http_lua_ffi_parse_http_time(const u_char *str, size_t len,
    long *time)
{
    /* njt_http_parse_time doesn't modify 'str' actually */
    *time = njt_http_parse_time((u_char *) str, len);
}


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
