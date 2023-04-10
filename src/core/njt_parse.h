
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_PARSE_H_INCLUDED_
#define _NJT_PARSE_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


ssize_t njt_parse_size(njt_str_t *line);
off_t njt_parse_offset(njt_str_t *line);
njt_int_t njt_parse_time(njt_str_t *line, njt_uint_t is_sec);


#endif /* _NJT_PARSE_H_INCLUDED_ */
