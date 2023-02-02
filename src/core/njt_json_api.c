#include "njt_json_api.h"

njt_array_t *njt_json_callback(njt_pool_t *pool, njt_array_t *json_array,
                               njt_json_val *next);

njt_int_t parseJson(njt_array_t *json_array, njt_json_val *key,
                    njt_json_val *val, njt_pool_t *pool)
{
    njt_json_element        *json_element;
    char buffer[256] = {};
    const char *pData;
    njt_uint_t len;

    json_element = njt_array_push(json_array);
    if (json_element == NULL) {
        return NJT_ERROR;
    }

    json_element->type = NJT_JSON_ERROR;
    json_element->sudata = NULL;

    if (key != NULL) {

        pData = njt_json_get_str(key);
        if (pData == NULL) {
            return NJT_ERROR;
        }

        len = strlen(pData);
        json_element->key.data =  njt_pnalloc(pool, len);
        if (json_element->key.data == NULL) {
            return NJT_ERROR;
        }

        json_element->key.len  = len;
        njt_memcpy(json_element->key.data, pData, len);
        njt_memzero(buffer, sizeof(buffer));
        njt_memcpy(buffer, pData, len);
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "key: %s", buffer);

    }

    if (val != NULL) {
        if (njt_json_is_obj(val)) {

            njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                           "key: %s", "========================obj===================");
            json_element->type = NJT_JSON_OBJ;
            json_element->sudata = njt_json_callback(pool, NULL, val);

        } else if (njt_json_is_arr(val)) {

            njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                           "key: %s", "========================list===================");
            json_element->type = NJT_JSON_ARRAY;
            json_element->sudata = njt_json_callback(pool, NULL, val);

        } else if (njt_json_is_null(val)) {

            json_element->type = NJT_JSON_NULL;
            njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                           "NULL val is: %s", "");

        } else if (njt_json_is_bool(val)) {

            json_element->type = NJT_JSON_BOOL;
            json_element->bval = njt_json_get_bool(val);
            njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                           "BOOL val is: %d", json_element->bval);

        } else if (njt_json_is_int(val)) {

            json_element->type = NJT_JSON_INT;
            json_element->intval = njt_json_get_int(val);
            njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                           "number val is: %d", json_element->intval);

        } else if (njt_json_is_real(val)) {

            json_element->type = NJT_JSON_DOUBLE;
            json_element->doubleval = njt_json_get_real(val);
            njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                           "double val is: %f", json_element->doubleval);

        } else if (njt_json_is_str(val)) {

            json_element->type = NJT_JSON_STR;
            pData = njt_json_get_str(val);
            if (pData == NULL) {
                return NJT_ERROR;
            }

            len = strlen(pData);
            json_element->strval.data =  njt_pnalloc(pool, len);
            if (json_element->strval.data == NULL) {
                return NJT_ERROR;
            }

            json_element->strval.len  = len;
            njt_memcpy(json_element->strval.data, pData, len);
            njt_memzero(buffer, sizeof(buffer));
            njt_memcpy(buffer, pData, len);
            njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                           "string val is: %s", buffer);
        }
    }

    return NJT_OK;
}


njt_array_t *njt_json_callback(njt_pool_t *pool, njt_array_t *json_array,
                               njt_json_val *next)
{

    njt_int_t ret = NJT_OK;
    njt_json_val *key, *val;
    njt_json_obj_iter objiter;
    njt_json_arr_iter arriter;
    njt_json_val *root;
    //njt_json_element        *json_element;
    //char buffer[256] = {};

    root = next;

    if (root == NULL) {
        return NULL;
    }

    if (json_array == NULL) {
        json_array = njt_array_create(pool, 4, sizeof(njt_json_element));
    }

    if (json_array == NULL) {
        return NULL;
    }

    if (njt_json_is_obj(root)) {
        njt_json_obj_iter_init(root, &objiter);
        while ((key = njt_json_obj_iter_next(&objiter))) {

            val = njt_json_obj_iter_get_val(key);

            ret = parseJson(json_array, key, val, pool);
            if (ret == NJT_ERROR) {
                goto cleanup;
            }
        }

    } else if (njt_json_is_arr(root)) {
        njt_json_arr_iter_init(root, &arriter);
        while ((val = njt_json_arr_iter_next(&arriter))) {
            ret = parseJson(json_array, NULL, val, pool);
            if (ret == NJT_ERROR)
                goto cleanup;
        }
    }

    return json_array;

cleanup:
    njt_array_destroy(json_array);
    return NULL;
}

void njt_json_manager_free(njt_json_manager *pt)
{
    if (pt->pool) {
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "njt_json_manager_free: %s", "ok");
        njt_destroy_pool(pt->pool);
        pt->pool = NULL;
    }

    return;
}

njt_int_t njt_json_2_structure(njt_str_t *json,
                               njt_json_manager *pjson_manager, njt_pool_t *init_pool)
{
    njt_pool_t *pool = NULL;
    njt_json_doc *doc;
    njt_json_val *root;
    u_char     *json_buf;
    njt_json_alc alc;
    //njt_json_element        *json_element;
    njt_array_t *json_array;
    //char buffer[256] = {};

    if (json == NULL)
        return NJT_ERROR;

    if (init_pool) {
        pool = init_pool;
        pjson_manager->pool = NULL;

    } else {
        pool = njt_create_pool(NJT_DEFAULT_POOL_SIZE, njt_cycle->log);
        pjson_manager->pool =  pool;
    }

    if (pool == NULL) {
        return NJT_ERROR;
    }

    pjson_manager->free = njt_json_manager_free;

    json_buf = njt_pnalloc(pool, njt_pagesize);
    if (json_buf == NULL) {
        goto cleanup;
    }


    njt_json_alc_pool_init(&alc, json_buf, njt_pagesize);

    //doc = njt_json_read((const char*)json->data,json->len, 0);
    doc = njt_json_read_opts((char *)json->data, json->len, 0, &alc, NULL);
    root = njt_json_doc_get_root(doc);

    if (root == NULL) {
        goto cleanup;
    }

    json_array = njt_array_create(pool, 4, sizeof(njt_json_element));
    if (json_array == NULL) {
        goto cleanup;
    }

    pjson_manager->json_keyval = json_array;
    json_array = njt_json_callback(pool, pjson_manager->json_keyval, root);

    if (json_array == NULL) {
        goto cleanup;
    }

    return NJT_OK;

cleanup:
    pjson_manager->free(pjson_manager);
    return NJT_ERROR;
}

