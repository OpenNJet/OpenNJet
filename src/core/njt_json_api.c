#include "njt_json_api.h"

njt_array_t *njt_json_callback(njt_pool_t *pool, njt_array_t *json_array,
                               njt_json_val *next);

njt_int_t parseJson(njt_array_t *json_array, njt_json_val *key,
                    njt_json_val *val, njt_pool_t *pool)
{
    njt_json_element        *json_element;
    char buffer[4096] = {};
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
        njt_memcpy(buffer, pData, njt_min(len,sizeof(buffer)-1));
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
            njt_memcpy(buffer, pData, njt_min(len,sizeof(buffer)-1));
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
    njt_json_element        *json_element;
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

    json_buf = njt_pnalloc(pool, 2 * json->len+njt_pagesize);
    if (json_buf == NULL) {
        goto cleanup;
    }


    njt_json_alc_pool_init(&alc, json_buf, 2 * json->len +njt_pagesize);

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

    json_element = njt_array_push(json_array);
    if (json_element == NULL) {
        goto cleanup;
    }
    if (njt_json_is_obj(root)) {

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                        "root key: %s", "========================obj===================");
        json_element->type = NJT_JSON_OBJ;
    }else if (njt_json_is_arr(root)) {
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                        "root key: %s", "========================list===================");
        json_element->type = NJT_JSON_ARRAY;
    }else{
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                        "root key: %s", "=============not obj or list, error============");
        goto cleanup;
    }

    json_element->sudata = njt_json_callback(pool, NULL, root);

    if (json_element->sudata == NULL) {
        goto cleanup;
    }

    return NJT_OK;

cleanup:
    pjson_manager->free(pjson_manager);
    return NJT_ERROR;
}

njt_int_t njt_struct_2_json_callback(njt_json_alc *alc, njt_array_t *json_array, njt_json_mut_doc *doc,
                                    njt_json_mut_val *val, int8_t val_type)
{
    njt_int_t rc = NJT_OK;
    njt_json_element *items;
    njt_json_mut_val *msg_key, *msg;
    njt_uint_t i;


    items = json_array->elts;
    for (i = 0; i < json_array->nelts; i++)
    {
        switch (items[i].type)
        {

            case NJT_JSON_STR:
                msg = njt_json_mut_strncpy(doc, (const char*)items[i].strval.data, items[i].strval.len);
                break;
            case NJT_JSON_BOOL:
                msg = njt_json_mut_bool(doc, items[i].bval);
                break;
            case NJT_JSON_DOUBLE:
                msg = njt_json_mut_real(doc, items[i].doubleval);
                break;
            case NJT_JSON_INT:
                msg = njt_json_mut_int(doc, items[i].intval);
                break;
            case NJT_JSON_ARRAY:
                msg = njt_json_mut_arr(doc);

                if(val_type == NJT_JSON_OBJ){
                    msg_key = njt_json_mut_strncpy(doc, (const char*)items[i].key.data, items[i].key.len);
                    njt_json_mut_obj_add(val, msg_key, msg);
                }else if(val_type == NJT_JSON_ARRAY){
                    njt_json_mut_arr_append(val, msg);
                }

                rc = njt_struct_2_json_callback(alc, items[i].sudata, doc, msg, NJT_JSON_ARRAY);
                if(rc != NJT_OK){
                    return rc;
                }
                break;
            case NJT_JSON_OBJ:
                msg = njt_json_mut_obj(doc);

                if(val_type == NJT_JSON_OBJ){
                    msg_key = njt_json_mut_strncpy(doc, (const char*)items[i].key.data, items[i].key.len);
                    njt_json_mut_obj_add(val, msg_key, msg);
                }else if(val_type == NJT_JSON_ARRAY){
                    njt_json_mut_arr_append(val, msg);
                }

                rc = njt_struct_2_json_callback(alc, items[i].sudata, doc, msg, NJT_JSON_OBJ);
                if(rc != NJT_OK){
                    return rc;
                }
                break;
            case NJT_JSON_NULL:
                msg = njt_json_mut_null(doc);
                break;
            default:
                break;
        }

        if(msg == NULL)
        {
            return NJT_ERROR;
        }

        if(items[i].type != NJT_JSON_OBJ && items[i].type != NJT_JSON_ARRAY){
            if(val_type == NJT_JSON_OBJ){
                msg_key = njt_json_mut_strncpy(doc, (const char*)items[i].key.data, items[i].key.len);
                if(msg_key == NULL)
                {
                    return NJT_ERROR;
                }
                njt_json_mut_obj_add(val, msg_key, msg);
            }else if(val_type == NJT_JSON_ARRAY){
                njt_json_mut_arr_append(val, msg);
            }
        }
    }

    return rc;
}


njt_int_t njt_structure_2_json(njt_json_manager *pjson_manager,
                                njt_str_t *json, njt_pool_t *init_pool)
{
    njt_pool_t *pool = NULL;
    njt_json_mut_val *root;
    njt_json_mut_doc *doc;
    size_t len;
    njt_int_t rc = NJT_OK;
    char *ret_json = NULL;
    u_char     *json_buf;
    njt_json_alc alc;
    int8_t  root_type;
    njt_json_element *items;

    if (pjson_manager == NULL || pjson_manager->json_keyval == NULL
        || pjson_manager->json_keyval->nelts < 1)
    {
        return NJT_ERROR;
    }

    if (init_pool) {
        pool = init_pool;
        pjson_manager->pool = NULL;

    } else {
        pool = njt_create_pool(NJT_DEFAULT_POOL_SIZE, njt_cycle->log);
        pjson_manager->pool =  pool;
    }

    doc = njt_json_mut_doc_new(NULL);
    if(doc == NULL){
        return NJT_ERROR;
    }

    json_buf = njt_pnalloc(pool, json->len+njt_pagesize);
    if (json_buf == NULL) {
        goto cleanup;
    }

    //root is object or array
    items = pjson_manager->json_keyval->elts;
    root_type = items[0].type;
    if (root_type == NJT_JSON_OBJ)
    {
        root = njt_json_mut_obj(doc);
    }else if(root_type == NJT_JSON_ARRAY){
        root = njt_json_mut_arr(doc);
    }else{
        goto cleanup;
    }

    if(root == NULL){
        goto cleanup;
    }

    njt_json_mut_doc_set_root(doc, root);
    njt_json_alc_pool_init(&alc, json_buf, njt_pagesize);

    rc = njt_struct_2_json_callback(&alc, items[0].sudata, doc, root, root_type);
    if(rc != NJT_OK){
        goto cleanup;
    }

    ret_json = njt_json_mut_write_opts(doc, 0, &alc, &len, NULL);
    if (ret_json == NULL)
    {
        json->data = NULL;
        json->len = 0;

        goto cleanup;
    }else{
        //ret_json[len-1] = '\0';
        json->data = (u_char *)ret_json;
        json->len = len;
    }

    njt_json_mut_doc_free(doc);

    return rc;
cleanup:
    njt_json_mut_doc_free(doc);

    return NJT_ERROR;
}

/**
 * @brief find out_elemetn in in_element by key
 *
 * @param in_element    input element
 * @param key           search key string
 * @param out_element   output element
 * @return njt_int_t    result status NJT_ERROR or NJT_OK
 */
njt_int_t njt_struct_find(njt_json_element *in_element,
                        njt_str_t *key, njt_json_element **out_element)
{
    njt_int_t rc = NJT_ERROR;
    njt_json_element *items;
    njt_uint_t i;

    if (in_element == NULL)
    {
        return NJT_ERROR;
    }

    if(in_element->type == NJT_JSON_ARRAY || in_element->type == NJT_JSON_OBJ){
        items = in_element->sudata->elts;
        for (i = 0; i < in_element->sudata->nelts; i++)
        {
            if(items[i].key.len != key->len){
                continue;
            }

            if(njt_strncmp(items[i].key.data, key->data, key->len) != 0){
                continue;
            }

            *out_element = &items[i];
            return NJT_OK;
        }
    }else{
        if(in_element->key.len != key->len){
            return NJT_ERROR;
        }
        if(njt_strncmp(in_element->key.data, key->data, key->len) == 0){
            *out_element = in_element;
            return NJT_OK;
        }
    }

    return rc;
}


/**
 * @brief find element from json manger which is top level
 *          top level only NJT_JSON_ARRAY or NJT_JSON_OBJ type
 *
 * @param pjson_manager     input json manger object
 * @param key               search key string
 * @param out_element       output element
 * @return njt_int_t        result status NJT_ERROR or NJT_OK
 */
njt_int_t njt_struct_top_find(njt_json_manager *pjson_manager,
                        njt_str_t *key, njt_json_element **out_element)
{
    njt_int_t rc = NJT_ERROR;
    njt_json_element *items;
    njt_json_element *sub_items;
    njt_uint_t i;

    if (pjson_manager == NULL || pjson_manager->json_keyval == NULL
        || pjson_manager->json_keyval->nelts != 1)
    {
        return NJT_ERROR;
    }

    items = pjson_manager->json_keyval->elts;

    if(items[0].type != NJT_JSON_ARRAY &&  items[0].type != NJT_JSON_OBJ){
        return NJT_ERROR;
    }

    if(items[0].sudata == NULL){
        return NJT_ERROR;
    }

    sub_items = items[0].sudata->elts;
    for (i = 0; i < items[0].sudata->nelts; i++){
        if(sub_items[i].key.len != key->len){
            continue;
        }

        if(njt_strncmp(sub_items[i].key.data, key->data, key->len) != 0){
            continue;
        }

        *out_element = &sub_items[i];

        return NJT_OK;
    }

    return rc;
}


/**
 * @brief insert element to parent_element, root_element only is NJT_JSON_OBJ or NJT_JSON_ARRAY
 *
 * @param parent_element   parent element
 * @param element        add element
 * @return njt_int_t     result status NJT_ERROR or NJT_OK
 */
njt_int_t njt_struct_add(njt_json_element *parent_element,
                        njt_json_element *element, njt_pool_t *pool)
{
    njt_int_t rc = NJT_OK;
    njt_json_element *json_element;
    njt_json_element *items;

    if(parent_element == NULL || element == NULL){
        return NJT_ERROR;
    }

    if(parent_element->type != NJT_JSON_ARRAY && parent_element->type != NJT_JSON_OBJ){
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                "parent_element only NJT_JSON_ARRAY or NJT_JSON_OBJ,  type: %d", parent_element->type);
        return NJT_ERROR;
    }

    if(parent_element->sudata == NULL){
        parent_element->sudata = njt_array_create(pool, 4, sizeof(njt_json_element));
        if(parent_element->sudata == NULL){
            return NJT_ERROR;
        }
    }

    if(parent_element->type == NJT_JSON_OBJ){
        json_element = njt_array_push(parent_element->sudata);
        if (json_element == NULL) {
            return NJT_ERROR;
        }
        *json_element = *element;
    }else{
        if(parent_element->sudata->nelts < 1){
            json_element = njt_array_push(parent_element->sudata);
            if (json_element == NULL) {
                return NJT_ERROR;
            }
            *json_element = *element;
        }else{
            items = parent_element->sudata->elts;
            //arrary should same type, so compare type first
            if(items[0].type != element->type){
                njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                    "type is not ok, should type: %d", items[0].type);
                return NJT_ERROR;
            }

            json_element = njt_array_push(parent_element->sudata);
            if (json_element == NULL) {
                return NJT_ERROR;
            }
            *json_element = *element;
        }
    }

    return rc;
}


/**
 * @brief free element
 *
 * @param pjson_manager
 * @return njt_int_t  result status NJT_ERROR or NJT_OK
 */
njt_int_t njt_struct_element_destroy(njt_json_element *element,
                njt_pool_t *pool){
    njt_int_t rc = NJT_OK;

    if(pool == NULL || element == NULL){
        return NJT_ERROR;
    }



    return rc;
}


/**
 * @brief free json manager object memory
 *           now just return because array has no free interface
 *        todo when use dynamic array
 * @param pjson_manager
 * @return njt_int_t  result status NJT_ERROR or NJT_OK
 */
njt_int_t njt_struct_destroy(njt_json_manager *pjson_manager){
    njt_int_t rc = NJT_OK;

    return rc;
}
