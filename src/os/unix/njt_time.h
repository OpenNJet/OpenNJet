
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_TIME_H_INCLUDED_
#define _NJT_TIME_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


typedef njt_rbtree_key_t      njt_msec_t;
typedef njt_rbtree_key_int_t  njt_msec_int_t;

typedef struct tm             njt_tm_t;

#define njt_tm_sec            tm_sec
#define njt_tm_min            tm_min
#define njt_tm_hour           tm_hour
#define njt_tm_mday           tm_mday
#define njt_tm_mon            tm_mon
#define njt_tm_year           tm_year
#define njt_tm_wday           tm_wday
#define njt_tm_isdst          tm_isdst

#define njt_tm_sec_t          int
#define njt_tm_min_t          int
#define njt_tm_hour_t         int
#define njt_tm_mday_t         int
#define njt_tm_mon_t          int
#define njt_tm_year_t         int
#define njt_tm_wday_t         int


#if (NJT_HAVE_GMTOFF)
#define njt_tm_gmtoff         tm_gmtoff
#define njt_tm_zone           tm_zone
#endif


#if (NJT_SOLARIS)

#define njt_timezone(isdst) (- (isdst ? altzone : timezone) / 60)

#else

#define njt_timezone(isdst) (- (isdst ? timezone + 3600 : timezone) / 60)

#endif


void njt_timezone_update(void);
void njt_localtime(time_t s, njt_tm_t *tm);
void njt_libc_localtime(time_t s, struct tm *tm);
void njt_libc_gmtime(time_t s, struct tm *tm);

#define njt_gettimeofday(tp)  (void) gettimeofday(tp, NULL);
#define njt_msleep(ms)        (void) usleep(ms * 1000)
#define njt_sleep(s)          (void) sleep(s)


#endif /* _NJT_TIME_H_INCLUDED_ */
