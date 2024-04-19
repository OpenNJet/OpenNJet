
/*
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */

#ifndef NJET_OPENAPI_UTIL_H
#define NJET_OPENAPI_UTIL_H

#include <njt_config.h>
#include <njt_core.h>

njt_int_t
njt_openapi_parse_json(njt_str_t *json_str, njt_str_t *db_name, njt_int_t group_id);

#endif /*NJET_OPENAPI_UTIL_H*/