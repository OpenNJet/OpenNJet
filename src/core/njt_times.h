
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_TIMES_H_INCLUDED_
#define _NJT_TIMES_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


typedef struct {
    time_t      sec;
    njt_uint_t  msec;
    njt_int_t   gmtoff;
} njt_time_t;


void njt_time_init(void);
void njt_time_update(void);
void njt_time_sigsafe_update(void);
u_char *njt_http_time(u_char *buf, time_t t);
u_char *njt_http_cookie_time(u_char *buf, time_t t);
void njt_gmtime(time_t t, njt_tm_t *tp);

time_t njt_next_time(time_t when);
#define njt_next_time_n      "mktime()"


extern volatile njt_time_t  *njt_cached_time;

#define njt_time()           njt_cached_time->sec
#define njt_timeofday()      (njt_time_t *) njt_cached_time

extern volatile njt_str_t    njt_cached_err_log_time;
extern volatile njt_str_t    njt_cached_http_time;
extern volatile njt_str_t    njt_cached_http_log_time;
extern volatile njt_str_t    njt_cached_http_log_iso8601;
extern volatile njt_str_t    njt_cached_syslog_time;

/*
 * milliseconds elapsed since some unspecified point in the past
 * and truncated to njt_msec_t, used in event timers
 */
extern volatile njt_msec_t  njt_current_msec;


#endif /* _NJT_TIMES_H_INCLUDED_ */
