/* **************************************************************************
 *
 * borrow from: github.com/cloudflare/lua-resty-json
 *
 **/
#ifndef LUA_RESTY_CJSON_H
#define LUA_RESTY_CJSON_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdio.h>
#include <ctype.h>


typedef struct {
    uint32_t hash;
    uint32_t id;
} chash_point_t;

#ifdef BUILDING_SO
    #ifndef __APPLE__
        #define LCH_EXPORT __attribute__ ((visibility ("protected")))
    #else
        /* OSX does not support protect-visibility */
        #define LCH_EXPORT __attribute__ ((visibility ("default")))
    #endif
#else
    #define LCH_EXPORT
#endif

/* **************************************************************************
 *
 *              Export Functions
 *
 * **************************************************************************
 */
void chash_point_init(chash_point_t *points, uint32_t base_hash,
    uint32_t start, uint32_t num, uint32_t id) LCH_EXPORT;
void chash_point_sort(chash_point_t *points, uint32_t npoints) LCH_EXPORT;

void chash_point_add(chash_point_t *old_points, uint32_t old_length,
    uint32_t base_hash, uint32_t from, uint32_t num, uint32_t id,
    chash_point_t *new_points) LCH_EXPORT;
void chash_point_reduce(chash_point_t *old_points, uint32_t old_length,
    uint32_t base_hash, uint32_t from, uint32_t num, uint32_t id) LCH_EXPORT;
void chash_point_delete(chash_point_t *old_points, uint32_t old_length,
    uint32_t id) LCH_EXPORT;

#ifdef __cplusplus
}
#endif

#endif
