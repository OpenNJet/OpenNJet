
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_PARSE_TIME_H_INCLUDED_
#define _NJT_PARSE_TIME_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


time_t njt_parse_http_time(u_char *value, size_t len);

/* compatibility */
#define njt_http_parse_time(value, len)  njt_parse_http_time(value, len)


#endif /* _NJT_PARSE_TIME_H_INCLUDED_ */
