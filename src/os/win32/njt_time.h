
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

typedef SYSTEMTIME            njt_tm_t;
typedef FILETIME              njt_mtime_t;

#define njt_tm_sec            wSecond
#define njt_tm_min            wMinute
#define njt_tm_hour           wHour
#define njt_tm_mday           wDay
#define njt_tm_mon            wMonth
#define njt_tm_year           wYear
#define njt_tm_wday           wDayOfWeek

#define njt_tm_sec_t          u_short
#define njt_tm_min_t          u_short
#define njt_tm_hour_t         u_short
#define njt_tm_mday_t         u_short
#define njt_tm_mon_t          u_short
#define njt_tm_year_t         u_short
#define njt_tm_wday_t         u_short


#define njt_msleep            Sleep

#define NJT_HAVE_GETTIMEZONE  1

#define  njt_timezone_update()

njt_int_t njt_gettimezone(void);
void njt_libc_localtime(time_t s, struct tm *tm);
void njt_libc_gmtime(time_t s, struct tm *tm);
void njt_gettimeofday(struct timeval *tp);


#endif /* _NJT_TIME_H_INCLUDED_ */
