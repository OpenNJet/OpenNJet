/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */
#ifndef NJT_HTTP_TOKEN_SYNC_MODULE_H_
#define NJT_HTTP_TOKEN_SYNC_MODULE_H_
#include <njt_core.h>


int njt_token_get(njt_str_t *token, njt_str_t *value);
int njt_token_set(njt_str_t *token, njt_str_t *value, int ttl);  //ttl s
int njt_token_del(njt_str_t *token);

#endif
