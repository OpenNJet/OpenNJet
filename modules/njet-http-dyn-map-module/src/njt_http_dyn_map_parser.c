

/* This file was generated by JSON Schema to C.
 * Any changes made to it will be lost on regeneration. 

 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */

#include "njt_http_dyn_map_parser.h"
#include "njt_core.h"
#include "js2c_njet_builtins.h"
/* ========================== Generated parsers ========================== */


static bool parse_httpmap_maps_item_values_item(njt_pool_t *pool, parse_state_t *parse_state, httpmap_maps_item_values_item_t *out, js2c_parse_error_t *err_ret) {
    njt_uint_t i;

    js2c_check_type(JSMN_OBJECT);
    const int object_start_token = parse_state->current_token;
    const uint64_t n = parse_state->tokens[parse_state->current_token].size;
    parse_state->current_token += 1;
    for (i = 0; i < n; ++i) {
        js2c_key_children_check_for_obj();
        if (current_string_is(parse_state, "valueFrom")) {
            js2c_check_field_set(out->is_valueFrom_set);
            parse_state->current_token += 1;
            const char* saved_key = parse_state->current_key;
            parse_state->current_key = "valueFrom";
            int token_size =  CURRENT_STRING_LENGTH(parse_state) ;
            ((&out->valueFrom))->data = (u_char*)njt_pcalloc(pool, (size_t)(token_size + 1));
            js2c_malloc_check(((&out->valueFrom))->data);
            ((&out->valueFrom))->len = token_size;
            if (builtin_parse_string(pool, parse_state, (&out->valueFrom), 0, ((&out->valueFrom))->len, err_ret)) {
                return true;
            }
            out->is_valueFrom_set = 1;
            parse_state->current_key = saved_key;
        } else if (current_string_is(parse_state, "valueTo")) {
            js2c_check_field_set(out->is_valueTo_set);
            parse_state->current_token += 1;
            const char* saved_key = parse_state->current_key;
            parse_state->current_key = "valueTo";
            int token_size =  CURRENT_STRING_LENGTH(parse_state) ;
            ((&out->valueTo))->data = (u_char*)njt_pcalloc(pool, (size_t)(token_size + 1));
            js2c_malloc_check(((&out->valueTo))->data);
            ((&out->valueTo))->len = token_size;
            if (builtin_parse_string(pool, parse_state, (&out->valueTo), 0, ((&out->valueTo))->len, err_ret)) {
                return true;
            }
            out->is_valueTo_set = 1;
            parse_state->current_key = saved_key;
        } else {
            LOG_ERROR_JSON_PARSE(UNKNOWN_FIELD_ERR, parse_state->current_key, CURRENT_TOKEN(parse_state).start, "Unknown field in '%s': %.*s", parse_state->current_key, CURRENT_STRING_FOR_ERROR(parse_state));
            return true;
        }
    }
    const int saved_current_token = parse_state->current_token;
    parse_state->current_token = object_start_token;
    if (!out->is_valueFrom_set) {
        LOG_ERROR_JSON_PARSE(MISSING_REQUIRED_FIELD_ERR, parse_state->current_key, CURRENT_TOKEN(parse_state).start, "Missing required field in '%s': valueFrom", parse_state->current_key);
        return true;
    }
    if (!out->is_valueTo_set) {
        LOG_ERROR_JSON_PARSE(MISSING_REQUIRED_FIELD_ERR, parse_state->current_key, CURRENT_TOKEN(parse_state).start, "Missing required field in '%s': valueTo", parse_state->current_key);
        return true;
    }
    parse_state->current_token = saved_current_token;
    return false;
}


static bool parse_httpmap_maps_item_values(njt_pool_t *pool, parse_state_t *parse_state, httpmap_maps_item_values_t *out, js2c_parse_error_t *err_ret) {
    int i;
    js2c_check_type(JSMN_ARRAY);
    const int n = parse_state->tokens[parse_state->current_token].size;
    parse_state->current_token += 1;
    for (i = 0; i < n; ++i) {
        ((httpmap_maps_item_values_item_t**)out->elts)[i] = njt_pcalloc(pool, sizeof(httpmap_maps_item_values_item_t));
        memset(((httpmap_maps_item_values_item_t**)out->elts)[i], 0, sizeof(httpmap_maps_item_values_item_t));
        if (parse_httpmap_maps_item_values_item(pool, parse_state, ((httpmap_maps_item_values_item_t**)out->elts)[i], err_ret)) {
            return true;
        }
        out->nelts ++;
    }
    return false;
}


static bool parse_httpmap_maps_item(njt_pool_t *pool, parse_state_t *parse_state, httpmap_maps_item_t *out, js2c_parse_error_t *err_ret) {
    njt_uint_t i;

    js2c_check_type(JSMN_OBJECT);
    const int object_start_token = parse_state->current_token;
    const uint64_t n = parse_state->tokens[parse_state->current_token].size;
    parse_state->current_token += 1;
    for (i = 0; i < n; ++i) {
        js2c_key_children_check_for_obj();
        if (current_string_is(parse_state, "keyFrom")) {
            js2c_check_field_set(out->is_keyFrom_set);
            parse_state->current_token += 1;
            const char* saved_key = parse_state->current_key;
            parse_state->current_key = "keyFrom";
            int token_size =  CURRENT_STRING_LENGTH(parse_state) ;
            ((&out->keyFrom))->data = (u_char*)njt_pcalloc(pool, (size_t)(token_size + 1));
            js2c_malloc_check(((&out->keyFrom))->data);
            ((&out->keyFrom))->len = token_size;
            if (builtin_parse_string(pool, parse_state, (&out->keyFrom), 2, ((&out->keyFrom))->len, err_ret)) {
                return true;
            }
            out->is_keyFrom_set = 1;
            parse_state->current_key = saved_key;
        } else if (current_string_is(parse_state, "keyTo")) {
            js2c_check_field_set(out->is_keyTo_set);
            parse_state->current_token += 1;
            const char* saved_key = parse_state->current_key;
            parse_state->current_key = "keyTo";
            int token_size =  CURRENT_STRING_LENGTH(parse_state) ;
            ((&out->keyTo))->data = (u_char*)njt_pcalloc(pool, (size_t)(token_size + 1));
            js2c_malloc_check(((&out->keyTo))->data);
            ((&out->keyTo))->len = token_size;
            if (builtin_parse_string(pool, parse_state, (&out->keyTo), 2, ((&out->keyTo))->len, err_ret)) {
                return true;
            }
            out->is_keyTo_set = 1;
            parse_state->current_key = saved_key;
        } else if (current_string_is(parse_state, "type")) {
            js2c_check_field_set(out->is_type_set);
            parse_state->current_token += 1;
            const char* saved_key = parse_state->current_key;
            parse_state->current_key = "type";
            js2c_null_check();
            int token_size =  CURRENT_STRING_LENGTH(parse_state) ;
            ((&out->type))->data = (u_char*)njt_pcalloc(pool, (size_t)(token_size + 1));
            js2c_malloc_check(((&out->type))->data);
            ((&out->type))->len = token_size;
            if (builtin_parse_string(pool, parse_state, (&out->type), 0, ((&out->type))->len, err_ret)) {
                return true;
            }
            out->is_type_set = 1;
            parse_state->current_key = saved_key;
        } else if (current_string_is(parse_state, "values")) {
            js2c_check_field_set(out->is_values_set);
            parse_state->current_token += 1;
            const char* saved_key = parse_state->current_key;
            parse_state->current_key = "values";
            out->values = njt_array_create(pool, parse_state->tokens[parse_state->current_token].size ,sizeof(httpmap_maps_item_values_item_t*));
            js2c_malloc_check(out->values);

            if (parse_httpmap_maps_item_values(pool, parse_state, (out->values), err_ret)) {
                return true;
            }
            out->is_values_set = 1;
            parse_state->current_key = saved_key;
        } else if (current_string_is(parse_state, "isVolatile")) {
            js2c_check_field_set(out->is_isVolatile_set);
            parse_state->current_token += 1;
            const char* saved_key = parse_state->current_key;
            parse_state->current_key = "isVolatile";
            js2c_null_check();
            if (builtin_parse_bool(pool, parse_state, (&out->isVolatile), err_ret)) {
                return true;
            }
            out->is_isVolatile_set = 1;
            parse_state->current_key = saved_key;
        } else if (current_string_is(parse_state, "hostnames")) {
            js2c_check_field_set(out->is_hostnames_set);
            parse_state->current_token += 1;
            const char* saved_key = parse_state->current_key;
            parse_state->current_key = "hostnames";
            js2c_null_check();
            if (builtin_parse_bool(pool, parse_state, (&out->hostnames), err_ret)) {
                return true;
            }
            out->is_hostnames_set = 1;
            parse_state->current_key = saved_key;
        } else {
            LOG_ERROR_JSON_PARSE(UNKNOWN_FIELD_ERR, parse_state->current_key, CURRENT_TOKEN(parse_state).start, "Unknown field in '%s': %.*s", parse_state->current_key, CURRENT_STRING_FOR_ERROR(parse_state));
            return true;
        }
    }
    const int saved_current_token = parse_state->current_token;
    parse_state->current_token = object_start_token;
    if (!out->is_keyFrom_set) {
        LOG_ERROR_JSON_PARSE(MISSING_REQUIRED_FIELD_ERR, parse_state->current_key, CURRENT_TOKEN(parse_state).start, "Missing required field in '%s': keyFrom", parse_state->current_key);
        return true;
    }
    if (!out->is_keyTo_set) {
        LOG_ERROR_JSON_PARSE(MISSING_REQUIRED_FIELD_ERR, parse_state->current_key, CURRENT_TOKEN(parse_state).start, "Missing required field in '%s': keyTo", parse_state->current_key);
        return true;
    }
    if (!out->is_values_set) {
        LOG_ERROR_JSON_PARSE(MISSING_REQUIRED_FIELD_ERR, parse_state->current_key, CURRENT_TOKEN(parse_state).start, "Missing required field in '%s': values", parse_state->current_key);
        return true;
    }
    // set default
    if (!out->is_type_set) {
        size_t token_size = strlen("");
        (out->type).data = (u_char*)njt_pcalloc(pool, token_size + 1);
        js2c_malloc_check((out->type).data);
        (out->type).len = token_size;
        if (out->type.len == 0) {
            (out->type).data[0] = 0;
        }
        if (token_size > 0) {
            njt_memcpy(out->type.data, "", token_size);
        }
    }
    // set default
    if (!out->is_isVolatile_set) {
        out->isVolatile = false;
    }
    // set default
    if (!out->is_hostnames_set) {
        out->hostnames = false;
    }
    parse_state->current_token = saved_current_token;
    return false;
}


static bool parse_httpmap_maps(njt_pool_t *pool, parse_state_t *parse_state, httpmap_maps_t *out, js2c_parse_error_t *err_ret) {
    int i;
    js2c_check_type(JSMN_ARRAY);
    const int n = parse_state->tokens[parse_state->current_token].size;
    parse_state->current_token += 1;
    for (i = 0; i < n; ++i) {
        ((httpmap_maps_item_t**)out->elts)[i] = njt_pcalloc(pool, sizeof(httpmap_maps_item_t));
        memset(((httpmap_maps_item_t**)out->elts)[i], 0, sizeof(httpmap_maps_item_t));
        if (parse_httpmap_maps_item(pool, parse_state, ((httpmap_maps_item_t**)out->elts)[i], err_ret)) {
            return true;
        }
        out->nelts ++;
    }
    return false;
}


static bool parse_httpmap(njt_pool_t *pool, parse_state_t *parse_state, httpmap_t *out, js2c_parse_error_t *err_ret) {
    njt_uint_t i;

    js2c_check_type(JSMN_OBJECT);
    const int object_start_token = parse_state->current_token;
    const uint64_t n = parse_state->tokens[parse_state->current_token].size;
    parse_state->current_token += 1;
    for (i = 0; i < n; ++i) {
        js2c_key_children_check_for_obj();
        if (current_string_is(parse_state, "maps")) {
            js2c_check_field_set(out->is_maps_set);
            parse_state->current_token += 1;
            const char* saved_key = parse_state->current_key;
            parse_state->current_key = "maps";
            out->maps = njt_array_create(pool, parse_state->tokens[parse_state->current_token].size ,sizeof(httpmap_maps_item_t*));
            js2c_malloc_check(out->maps);

            if (parse_httpmap_maps(pool, parse_state, (out->maps), err_ret)) {
                return true;
            }
            out->is_maps_set = 1;
            parse_state->current_key = saved_key;
        } else {
            LOG_ERROR_JSON_PARSE(UNKNOWN_FIELD_ERR, parse_state->current_key, CURRENT_TOKEN(parse_state).start, "Unknown field in '%s': %.*s", parse_state->current_key, CURRENT_STRING_FOR_ERROR(parse_state));
            return true;
        }
    }
    const int saved_current_token = parse_state->current_token;
    parse_state->current_token = object_start_token;
    if (!out->is_maps_set) {
        LOG_ERROR_JSON_PARSE(MISSING_REQUIRED_FIELD_ERR, parse_state->current_key, CURRENT_TOKEN(parse_state).start, "Missing required field in '%s': maps", parse_state->current_key);
        return true;
    }
    parse_state->current_token = saved_current_token;
    return false;
}


static void get_json_length_httpmap_maps_item_keyFrom(njt_pool_t *pool, httpmap_maps_item_keyFrom_t *out, size_t *length, njt_int_t flags) {
    njt_str_t *dst = handle_escape_on_write(pool, out);
    *length += dst->len + 2; //  "str" 
}

static void get_json_length_httpmap_maps_item_keyTo(njt_pool_t *pool, httpmap_maps_item_keyTo_t *out, size_t *length, njt_int_t flags) {
    njt_str_t *dst = handle_escape_on_write(pool, out);
    *length += dst->len + 2; //  "str" 
}

static void get_json_length_httpmap_maps_item_type(njt_pool_t *pool, httpmap_maps_item_type_t *out, size_t *length, njt_int_t flags) {
    njt_str_t *dst = handle_escape_on_write(pool, out);
    *length += dst->len + 2; //  "str" 
}

static void get_json_length_httpmap_maps_item_values_item_valueFrom(njt_pool_t *pool, httpmap_maps_item_values_item_valueFrom_t *out, size_t *length, njt_int_t flags) {
    njt_str_t *dst = handle_escape_on_write(pool, out);
    *length += dst->len + 2; //  "str" 
}

static void get_json_length_httpmap_maps_item_values_item_valueTo(njt_pool_t *pool, httpmap_maps_item_values_item_valueTo_t *out, size_t *length, njt_int_t flags) {
    njt_str_t *dst = handle_escape_on_write(pool, out);
    *length += dst->len + 2; //  "str" 
}

static void get_json_length_httpmap_maps_item_values_item(njt_pool_t *pool, httpmap_maps_item_values_item_t *out, size_t *length, njt_int_t flags) {
    if (out == NULL) {
        *length += 4; // null
        return;
    }
    *length += 1;
    njt_int_t omit;
    njt_int_t count = 0;
    omit = 0;
    omit = out->is_valueFrom_set ? 0 : 1;
    omit = (flags & OMIT_NULL_STR) && (out->valueFrom.data) == NULL ? 1 : omit;
    if (omit == 0) {
        *length += (9 + 3); // "valueFrom": 
        get_json_length_httpmap_maps_item_values_item_valueFrom(pool, (&out->valueFrom), length, flags);
        *length += 1; // ","
        count++;
    }
    omit = 0;
    omit = out->is_valueTo_set ? 0 : 1;
    omit = (flags & OMIT_NULL_STR) && (out->valueTo.data) == NULL ? 1 : omit;
    if (omit == 0) {
        *length += (7 + 3); // "valueTo": 
        get_json_length_httpmap_maps_item_values_item_valueTo(pool, (&out->valueTo), length, flags);
        *length += 1; // ","
        count++;
    }
    if (count != 0) {
        *length -= 1; // "\b"
    }
    *length += 1;
}

static void get_json_length_httpmap_maps_item_values(njt_pool_t *pool, httpmap_maps_item_values_t *out, size_t *length, njt_int_t flags) {
    njt_uint_t i;
    njt_uint_t omit;
    njt_int_t count = 0;
    if (out == NULL) {
        *length += 2; // "[]"
        return;
    }
    *length += 2; // "[]"
    for (i = 0; i < out->nelts; ++i) {
        omit = 0;
        omit = ((flags & OMIT_NULL_OBJ) && ((httpmap_maps_item_values_item_t**)out->elts)[i] == NULL) ? 1 : 0;
        if (omit == 0) {
            get_json_length_httpmap_maps_item_values_item(pool, ((httpmap_maps_item_values_item_t**)out->elts)[i], length, flags);
            *length += 1; // ","
            count++; // ","
        }
    }
    if (count != 0) {
        *length -= 1; // "\b"
    }
}

static void get_json_length_httpmap_maps_item_isVolatile(njt_pool_t *pool, httpmap_maps_item_isVolatile_t *out, size_t *length, njt_int_t flags) {
    if (*out) {
        *length += 4; // "true"
    } else {
        *length += 5; // "false"
    }
}

static void get_json_length_httpmap_maps_item_hostnames(njt_pool_t *pool, httpmap_maps_item_hostnames_t *out, size_t *length, njt_int_t flags) {
    if (*out) {
        *length += 4; // "true"
    } else {
        *length += 5; // "false"
    }
}

static void get_json_length_httpmap_maps_item(njt_pool_t *pool, httpmap_maps_item_t *out, size_t *length, njt_int_t flags) {
    if (out == NULL) {
        *length += 4; // null
        return;
    }
    *length += 1;
    njt_int_t omit;
    njt_int_t count = 0;
    omit = 0;
    omit = out->is_keyFrom_set ? 0 : 1;
    omit = (flags & OMIT_NULL_STR) && (out->keyFrom.data) == NULL ? 1 : omit;
    if (omit == 0) {
        *length += (7 + 3); // "keyFrom": 
        get_json_length_httpmap_maps_item_keyFrom(pool, (&out->keyFrom), length, flags);
        *length += 1; // ","
        count++;
    }
    omit = 0;
    omit = out->is_keyTo_set ? 0 : 1;
    omit = (flags & OMIT_NULL_STR) && (out->keyTo.data) == NULL ? 1 : omit;
    if (omit == 0) {
        *length += (5 + 3); // "keyTo": 
        get_json_length_httpmap_maps_item_keyTo(pool, (&out->keyTo), length, flags);
        *length += 1; // ","
        count++;
    }
    omit = 0;
    omit = out->is_type_set ? 0 : 1;
    omit = (flags & OMIT_NULL_STR) && (out->type.data) == NULL ? 1 : omit;
    if (omit == 0) {
        *length += (4 + 3); // "type": 
        get_json_length_httpmap_maps_item_type(pool, (&out->type), length, flags);
        *length += 1; // ","
        count++;
    }
    omit = 0;
    omit = out->is_values_set ? 0 : 1;
    omit = (flags & OMIT_NULL_ARRAY) && (out->values) == NULL ? 1 : omit;
    if (omit == 0) {
        *length += (6 + 3); // "values": 
        get_json_length_httpmap_maps_item_values(pool, (out->values), length, flags);
        *length += 1; // ","
        count++;
    }
    omit = 0;
    omit = out->is_isVolatile_set ? 0 : 1;
    if (omit == 0) {
        *length += (10 + 3); // "isVolatile": 
        get_json_length_httpmap_maps_item_isVolatile(pool, (&out->isVolatile), length, flags);
        *length += 1; // ","
        count++;
    }
    omit = 0;
    omit = out->is_hostnames_set ? 0 : 1;
    if (omit == 0) {
        *length += (9 + 3); // "hostnames": 
        get_json_length_httpmap_maps_item_hostnames(pool, (&out->hostnames), length, flags);
        *length += 1; // ","
        count++;
    }
    if (count != 0) {
        *length -= 1; // "\b"
    }
    *length += 1;
}

static void get_json_length_httpmap_maps(njt_pool_t *pool, httpmap_maps_t *out, size_t *length, njt_int_t flags) {
    njt_uint_t i;
    njt_uint_t omit;
    njt_int_t count = 0;
    if (out == NULL) {
        *length += 2; // "[]"
        return;
    }
    *length += 2; // "[]"
    for (i = 0; i < out->nelts; ++i) {
        omit = 0;
        omit = ((flags & OMIT_NULL_OBJ) && ((httpmap_maps_item_t**)out->elts)[i] == NULL) ? 1 : 0;
        if (omit == 0) {
            get_json_length_httpmap_maps_item(pool, ((httpmap_maps_item_t**)out->elts)[i], length, flags);
            *length += 1; // ","
            count++; // ","
        }
    }
    if (count != 0) {
        *length -= 1; // "\b"
    }
}

static void get_json_length_httpmap(njt_pool_t *pool, httpmap_t *out, size_t *length, njt_int_t flags) {
    if (out == NULL) {
        *length += 4; // null
        return;
    }
    *length += 1;
    njt_int_t omit;
    njt_int_t count = 0;
    omit = 0;
    omit = out->is_maps_set ? 0 : 1;
    omit = (flags & OMIT_NULL_ARRAY) && (out->maps) == NULL ? 1 : omit;
    if (omit == 0) {
        *length += (4 + 3); // "maps": 
        get_json_length_httpmap_maps(pool, (out->maps), length, flags);
        *length += 1; // ","
        count++;
    }
    if (count != 0) {
        *length -= 1; // "\b"
    }
    *length += 1;
}

httpmap_maps_item_values_item_valueFrom_t* get_httpmap_maps_item_values_item_valueFrom(httpmap_maps_item_values_item_t *out) {
    return &out->valueFrom;
}

httpmap_maps_item_values_item_valueTo_t* get_httpmap_maps_item_values_item_valueTo(httpmap_maps_item_values_item_t *out) {
    return &out->valueTo;
}
httpmap_maps_item_values_item_t* get_httpmap_maps_item_values_item(httpmap_maps_item_values_t *out, size_t idx) {
    return ((httpmap_maps_item_values_item_t**)out->elts)[idx];

}

httpmap_maps_item_keyFrom_t* get_httpmap_maps_item_keyFrom(httpmap_maps_item_t *out) {
    return &out->keyFrom;
}

httpmap_maps_item_keyTo_t* get_httpmap_maps_item_keyTo(httpmap_maps_item_t *out) {
    return &out->keyTo;
}

httpmap_maps_item_type_t* get_httpmap_maps_item_type(httpmap_maps_item_t *out) {
    return &out->type;
}

httpmap_maps_item_values_t* get_httpmap_maps_item_values(httpmap_maps_item_t *out) {
    return out->values;
}

httpmap_maps_item_isVolatile_t get_httpmap_maps_item_isVolatile(httpmap_maps_item_t *out) {
    return out->isVolatile;
}

httpmap_maps_item_hostnames_t get_httpmap_maps_item_hostnames(httpmap_maps_item_t *out) {
    return out->hostnames;
}
httpmap_maps_item_t* get_httpmap_maps_item(httpmap_maps_t *out, size_t idx) {
    return ((httpmap_maps_item_t**)out->elts)[idx];

}

httpmap_maps_t* get_httpmap_maps(httpmap_t *out) {
    return out->maps;
}
void set_httpmap_maps_item_keyFrom(httpmap_maps_item_t* obj, httpmap_maps_item_keyFrom_t* field) {
    njt_memcpy(&obj->keyFrom, field, sizeof(njt_str_t));
    obj->is_keyFrom_set = 1;
}
void set_httpmap_maps_item_keyTo(httpmap_maps_item_t* obj, httpmap_maps_item_keyTo_t* field) {
    njt_memcpy(&obj->keyTo, field, sizeof(njt_str_t));
    obj->is_keyTo_set = 1;
}
void set_httpmap_maps_item_type(httpmap_maps_item_t* obj, httpmap_maps_item_type_t* field) {
    njt_memcpy(&obj->type, field, sizeof(njt_str_t));
    obj->is_type_set = 1;
}
void set_httpmap_maps_item_values_item_valueFrom(httpmap_maps_item_values_item_t* obj, httpmap_maps_item_values_item_valueFrom_t* field) {
    njt_memcpy(&obj->valueFrom, field, sizeof(njt_str_t));
    obj->is_valueFrom_set = 1;
}
void set_httpmap_maps_item_values_item_valueTo(httpmap_maps_item_values_item_t* obj, httpmap_maps_item_values_item_valueTo_t* field) {
    njt_memcpy(&obj->valueTo, field, sizeof(njt_str_t));
    obj->is_valueTo_set = 1;
}
httpmap_maps_item_values_item_t* create_httpmap_maps_item_values_item(njt_pool_t *pool) {
    httpmap_maps_item_values_item_t* out = njt_pcalloc(pool, sizeof(httpmap_maps_item_values_item_t));
    return out;
}
int add_item_httpmap_maps_item_values(httpmap_maps_item_values_t *src, httpmap_maps_item_values_item_t* item) {
    void *new = njt_array_push(src);
    if (new == NULL) {
        return NJT_ERROR;
    }
    njt_memcpy(new, &item, src->size);
    return NJT_OK;
}

httpmap_maps_item_values_t* create_httpmap_maps_item_values(njt_pool_t *pool, size_t nelts) {
    return njt_array_create(pool, nelts, sizeof(httpmap_maps_item_values_item_t*));
}
void set_httpmap_maps_item_values(httpmap_maps_item_t* obj, httpmap_maps_item_values_t* field) {
    obj->values = field;
    obj->is_values_set = 1;
}
void set_httpmap_maps_item_isVolatile(httpmap_maps_item_t* obj, httpmap_maps_item_isVolatile_t field) {
    obj->isVolatile = field;
    obj->is_isVolatile_set = 1;
}
void set_httpmap_maps_item_hostnames(httpmap_maps_item_t* obj, httpmap_maps_item_hostnames_t field) {
    obj->hostnames = field;
    obj->is_hostnames_set = 1;
}
httpmap_maps_item_t* create_httpmap_maps_item(njt_pool_t *pool) {
    httpmap_maps_item_t* out = njt_pcalloc(pool, sizeof(httpmap_maps_item_t));
    return out;
}
int add_item_httpmap_maps(httpmap_maps_t *src, httpmap_maps_item_t* item) {
    void *new = njt_array_push(src);
    if (new == NULL) {
        return NJT_ERROR;
    }
    njt_memcpy(new, &item, src->size);
    return NJT_OK;
}

httpmap_maps_t* create_httpmap_maps(njt_pool_t *pool, size_t nelts) {
    return njt_array_create(pool, nelts, sizeof(httpmap_maps_item_t*));
}
void set_httpmap_maps(httpmap_t* obj, httpmap_maps_t* field) {
    obj->maps = field;
    obj->is_maps_set = 1;
}
httpmap_t* create_httpmap(njt_pool_t *pool) {
    httpmap_t* out = njt_pcalloc(pool, sizeof(httpmap_t));
    return out;
}

static void to_oneline_json_httpmap_maps_item_keyFrom(njt_pool_t *pool, httpmap_maps_item_keyFrom_t *out, njt_str_t *buf, njt_int_t flags) {
    u_char* cur = buf->data + buf->len;
    njt_str_t *dst = handle_escape_on_write(pool, out);
    cur = njt_sprintf(cur, "\"%V\"", dst);
    buf->len = cur - buf->data;
}

static void to_oneline_json_httpmap_maps_item_keyTo(njt_pool_t *pool, httpmap_maps_item_keyTo_t *out, njt_str_t *buf, njt_int_t flags) {
    u_char* cur = buf->data + buf->len;
    njt_str_t *dst = handle_escape_on_write(pool, out);
    cur = njt_sprintf(cur, "\"%V\"", dst);
    buf->len = cur - buf->data;
}

static void to_oneline_json_httpmap_maps_item_type(njt_pool_t *pool, httpmap_maps_item_type_t *out, njt_str_t *buf, njt_int_t flags) {
    u_char* cur = buf->data + buf->len;
    njt_str_t *dst = handle_escape_on_write(pool, out);
    cur = njt_sprintf(cur, "\"%V\"", dst);
    buf->len = cur - buf->data;
}

static void to_oneline_json_httpmap_maps_item_values_item_valueFrom(njt_pool_t *pool, httpmap_maps_item_values_item_valueFrom_t *out, njt_str_t *buf, njt_int_t flags) {
    u_char* cur = buf->data + buf->len;
    njt_str_t *dst = handle_escape_on_write(pool, out);
    cur = njt_sprintf(cur, "\"%V\"", dst);
    buf->len = cur - buf->data;
}

static void to_oneline_json_httpmap_maps_item_values_item_valueTo(njt_pool_t *pool, httpmap_maps_item_values_item_valueTo_t *out, njt_str_t *buf, njt_int_t flags) {
    u_char* cur = buf->data + buf->len;
    njt_str_t *dst = handle_escape_on_write(pool, out);
    cur = njt_sprintf(cur, "\"%V\"", dst);
    buf->len = cur - buf->data;
}

static void to_oneline_json_httpmap_maps_item_values_item(njt_pool_t *pool, httpmap_maps_item_values_item_t *out, njt_str_t* buf, njt_int_t flags) {
    njt_int_t omit;
    u_char* cur = buf->data + buf->len;
    if (out == NULL) {
        cur = njt_sprintf(cur, "null");
        buf->len += 4;
        return;
    }
    cur = njt_sprintf(cur, "{");
    buf->len ++;
    omit = 0;
    omit = out->is_valueFrom_set ? 0 : 1;
    omit = (flags & OMIT_NULL_STR) && (out->valueFrom.data) == NULL ? 1 : omit;
    if (omit == 0) {
        cur = njt_sprintf(cur, "\"valueFrom\":");
        buf->len = cur - buf->data;
        to_oneline_json_httpmap_maps_item_values_item_valueFrom(pool, (&out->valueFrom), buf, flags);
        cur = buf->data + buf->len;
        cur = njt_sprintf(cur, ",");
        buf->len ++;
    }
    omit = 0;
    omit = out->is_valueTo_set ? 0 : 1;
    omit = (flags & OMIT_NULL_STR) && (out->valueTo.data) == NULL ? 1 : omit;
    if (omit == 0) {
        cur = njt_sprintf(cur, "\"valueTo\":");
        buf->len = cur - buf->data;
        to_oneline_json_httpmap_maps_item_values_item_valueTo(pool, (&out->valueTo), buf, flags);
        cur = buf->data + buf->len;
        cur = njt_sprintf(cur, ",");
        buf->len ++;
    }
    cur--;
    if (cur[0] == ',') {
        buf->len --;
    } else {
        cur ++;
    }
    cur = njt_sprintf(cur, "}");
    buf->len ++;
}

static void to_oneline_json_httpmap_maps_item_values(njt_pool_t *pool, httpmap_maps_item_values_t *out, njt_str_t* buf, njt_int_t flags) {
    njt_int_t omit;
    u_char *cur = buf->data + buf->len;
    njt_uint_t i;
    if (out == NULL || out->nelts == 0) {
        cur = njt_sprintf(cur, "[]");
        buf->len += 2;
        return;
    }
    cur = njt_sprintf(cur,  "[");
    buf->len ++;
    for (i = 0; i < out->nelts; ++i) {
        omit = 0;
        omit = ((flags & OMIT_NULL_OBJ) && ((httpmap_maps_item_values_item_t**)out->elts)[i] == NULL) ? 1 : 0;
        if (omit == 0) {
            to_oneline_json_httpmap_maps_item_values_item(pool, ((httpmap_maps_item_values_item_t**)out->elts)[i], buf, flags);
            cur = buf->data + buf->len;
            cur = njt_sprintf(cur, ",");
            buf->len ++;
        }
    }
    cur--;
    if (cur[0] == ',') {
        buf->len --;
    } else {
        cur ++;
    }
    cur = njt_sprintf(cur,  "]");
    buf->len ++;
}

static void to_oneline_json_httpmap_maps_item_isVolatile(njt_pool_t *pool, httpmap_maps_item_isVolatile_t *out, njt_str_t *buf, njt_int_t flags) {
    u_char* cur = buf->data + buf->len;
    if (*out) {
        njt_sprintf(cur, "true");
        buf->len += 4;
    } else {
        njt_sprintf(cur, "false");
        buf->len += 5;
    }
}

static void to_oneline_json_httpmap_maps_item_hostnames(njt_pool_t *pool, httpmap_maps_item_hostnames_t *out, njt_str_t *buf, njt_int_t flags) {
    u_char* cur = buf->data + buf->len;
    if (*out) {
        njt_sprintf(cur, "true");
        buf->len += 4;
    } else {
        njt_sprintf(cur, "false");
        buf->len += 5;
    }
}

static void to_oneline_json_httpmap_maps_item(njt_pool_t *pool, httpmap_maps_item_t *out, njt_str_t* buf, njt_int_t flags) {
    njt_int_t omit;
    u_char* cur = buf->data + buf->len;
    if (out == NULL) {
        cur = njt_sprintf(cur, "null");
        buf->len += 4;
        return;
    }
    cur = njt_sprintf(cur, "{");
    buf->len ++;
    omit = 0;
    omit = out->is_keyFrom_set ? 0 : 1;
    omit = (flags & OMIT_NULL_STR) && (out->keyFrom.data) == NULL ? 1 : omit;
    if (omit == 0) {
        cur = njt_sprintf(cur, "\"keyFrom\":");
        buf->len = cur - buf->data;
        to_oneline_json_httpmap_maps_item_keyFrom(pool, (&out->keyFrom), buf, flags);
        cur = buf->data + buf->len;
        cur = njt_sprintf(cur, ",");
        buf->len ++;
    }
    omit = 0;
    omit = out->is_keyTo_set ? 0 : 1;
    omit = (flags & OMIT_NULL_STR) && (out->keyTo.data) == NULL ? 1 : omit;
    if (omit == 0) {
        cur = njt_sprintf(cur, "\"keyTo\":");
        buf->len = cur - buf->data;
        to_oneline_json_httpmap_maps_item_keyTo(pool, (&out->keyTo), buf, flags);
        cur = buf->data + buf->len;
        cur = njt_sprintf(cur, ",");
        buf->len ++;
    }
    omit = 0;
    omit = out->is_type_set ? 0 : 1;
    omit = (flags & OMIT_NULL_STR) && (out->type.data) == NULL ? 1 : omit;
    if (omit == 0) {
        cur = njt_sprintf(cur, "\"type\":");
        buf->len = cur - buf->data;
        to_oneline_json_httpmap_maps_item_type(pool, (&out->type), buf, flags);
        cur = buf->data + buf->len;
        cur = njt_sprintf(cur, ",");
        buf->len ++;
    }
    omit = 0;
    omit = out->is_values_set ? 0 : 1;
    omit = (flags & OMIT_NULL_ARRAY) && (out->values) == NULL ? 1 : omit;
    if (omit == 0) {
        cur = njt_sprintf(cur, "\"values\":");
        buf->len = cur - buf->data;
        to_oneline_json_httpmap_maps_item_values(pool, (out->values), buf, flags);
        cur = buf->data + buf->len;
        cur = njt_sprintf(cur, ",");
        buf->len ++;
    }
    omit = 0;
    omit = out->is_isVolatile_set ? 0 : 1;
    if (omit == 0) {
        cur = njt_sprintf(cur, "\"isVolatile\":");
        buf->len = cur - buf->data;
        to_oneline_json_httpmap_maps_item_isVolatile(pool, (&out->isVolatile), buf, flags);
        cur = buf->data + buf->len;
        cur = njt_sprintf(cur, ",");
        buf->len ++;
    }
    omit = 0;
    omit = out->is_hostnames_set ? 0 : 1;
    if (omit == 0) {
        cur = njt_sprintf(cur, "\"hostnames\":");
        buf->len = cur - buf->data;
        to_oneline_json_httpmap_maps_item_hostnames(pool, (&out->hostnames), buf, flags);
        cur = buf->data + buf->len;
        cur = njt_sprintf(cur, ",");
        buf->len ++;
    }
    cur--;
    if (cur[0] == ',') {
        buf->len --;
    } else {
        cur ++;
    }
    cur = njt_sprintf(cur, "}");
    buf->len ++;
}

static void to_oneline_json_httpmap_maps(njt_pool_t *pool, httpmap_maps_t *out, njt_str_t* buf, njt_int_t flags) {
    njt_int_t omit;
    u_char *cur = buf->data + buf->len;
    njt_uint_t i;
    if (out == NULL || out->nelts == 0) {
        cur = njt_sprintf(cur, "[]");
        buf->len += 2;
        return;
    }
    cur = njt_sprintf(cur,  "[");
    buf->len ++;
    for (i = 0; i < out->nelts; ++i) {
        omit = 0;
        omit = ((flags & OMIT_NULL_OBJ) && ((httpmap_maps_item_t**)out->elts)[i] == NULL) ? 1 : 0;
        if (omit == 0) {
            to_oneline_json_httpmap_maps_item(pool, ((httpmap_maps_item_t**)out->elts)[i], buf, flags);
            cur = buf->data + buf->len;
            cur = njt_sprintf(cur, ",");
            buf->len ++;
        }
    }
    cur--;
    if (cur[0] == ',') {
        buf->len --;
    } else {
        cur ++;
    }
    cur = njt_sprintf(cur,  "]");
    buf->len ++;
}

static void to_oneline_json_httpmap(njt_pool_t *pool, httpmap_t *out, njt_str_t* buf, njt_int_t flags) {
    njt_int_t omit;
    u_char* cur = buf->data + buf->len;
    if (out == NULL) {
        cur = njt_sprintf(cur, "null");
        buf->len += 4;
        return;
    }
    cur = njt_sprintf(cur, "{");
    buf->len ++;
    omit = 0;
    omit = out->is_maps_set ? 0 : 1;
    omit = (flags & OMIT_NULL_ARRAY) && (out->maps) == NULL ? 1 : omit;
    if (omit == 0) {
        cur = njt_sprintf(cur, "\"maps\":");
        buf->len = cur - buf->data;
        to_oneline_json_httpmap_maps(pool, (out->maps), buf, flags);
        cur = buf->data + buf->len;
        cur = njt_sprintf(cur, ",");
        buf->len ++;
    }
    cur--;
    if (cur[0] == ',') {
        buf->len --;
    } else {
        cur ++;
    }
    cur = njt_sprintf(cur, "}");
    buf->len ++;
}
httpmap_t* json_parse_httpmap(njt_pool_t *pool, const njt_str_t *json_string, js2c_parse_error_t *err_ret) {
    httpmap_t* out;
    parse_state_t parse_state_var;
    parse_state_t *parse_state = &parse_state_var;
    uint64_t max_token_number = 1024;
    jsmntok_t *token_buffer;
    int parse_result;
    for ( ; /* parse unsuccessful */; ) {
        token_buffer = njt_pcalloc(pool, sizeof(jsmntok_t)*max_token_number);
        parse_result = builtin_parse_json_string(pool, parse_state, token_buffer, max_token_number, (char *)json_string->data, json_string->len, err_ret);
        if (parse_result == JSMN_ERROR_INVAL) {
            LOG_ERROR_JSON_PARSE(INVALID_JSON_CHAR_ERR, "", -1, "%s", "Invalid character inside JSON string");
            return NULL;
        }
        if (parse_result == JSMN_ERROR_PART) {
            LOG_ERROR_JSON_PARSE(PARTIAL_JSON_ERR, "", -1, "%s", "The string is not a full JSON packet, more bytes expected");
            return NULL;
        }
        if (parse_result == JSMN_ERROR_NOMEM) {
            max_token_number += max_token_number;
            continue;
        }
        if (parse_result == 0) {
            LOG_ERROR_JSON_PARSE(NULL_JSON_ERR, "", 0, "String did not contain %s JSON tokens", "any");
            return NULL;
        }
        break; // parse success
    }
    out = njt_pcalloc(pool, sizeof(httpmap_t));;
    memset(out, 0, sizeof(httpmap_t));
    if (parse_httpmap(pool, parse_state, out, err_ret)) {
        return NULL;
    }
    return out;
}

njt_str_t* to_json_httpmap(njt_pool_t *pool, httpmap_t* out, njt_int_t flags) {
    njt_str_t *json_str;
    json_str = njt_pcalloc(pool, sizeof(njt_str_t));
    size_t str_len = 0;
    get_json_length_httpmap(pool, out, &str_len, flags);
    json_str->data = (u_char*)njt_pcalloc(pool, str_len + 1);
    json_str->len = 0;
    to_oneline_json_httpmap(pool, out, json_str, flags);
    return json_str;
}
