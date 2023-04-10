
/*
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef NJET_MAIN_NJT_HASH_UTIL_H
#define NJET_MAIN_NJT_HASH_UTIL_H

#include <njt_core.h>
#include <njt_lvlhsh.h>

typedef struct njt_lvlhash_map_s njt_lvlhash_map_t;

struct njt_lvlhash_map_s
{
    njt_lvlhsh_t lh;
    njt_log_t *log;
};

//if there is an old value existed in hash, it will be set into *p_old_value
njt_int_t njt_lvlhsh_map_put(njt_lvlhash_map_t *map, njt_str_t *key, intptr_t value, intptr_t *p_old_value);
njt_int_t njt_lvlhsh_map_get(njt_lvlhash_map_t *map, njt_str_t *key, intptr_t *p_value);
njt_int_t njt_lvlhsh_map_remove(njt_lvlhash_map_t *map, njt_str_t *key);

#endif // NJET_MAIN_NJT_HASH_UTIL_H
