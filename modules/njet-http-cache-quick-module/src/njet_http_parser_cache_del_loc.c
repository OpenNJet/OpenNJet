

/* This file was generated by JSON Schema to C.
 * Any changes made to it will be lost on regeneration. 

 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */

#include "njet_http_parser_cache_del_loc.h"
#include "njt_core.h"
#include "js2c_njet_builtins.h"
/* ========================== Generated parsers ========================== */


static bool parse_cache_del_dyn_location_type(njt_pool_t *pool, parse_state_t *parse_state, cache_del_dyn_location_type_t *out, js2c_parse_error_t *err_ret) {
    js2c_check_type(JSMN_STRING);
    if (current_string_is(parse_state, "del")) {
        *out = CACHE_DEL_DYN_LOCATION_TYPE_DEL;
    } else {
        LOG_ERROR_JSON_PARSE(UNKNOWN_ENUM_VALUE_ERR, parse_state->current_key, CURRENT_TOKEN(parse_state).start, "Unknown enum value in '%s': %.*s", parse_state->current_key, CURRENT_STRING_FOR_ERROR(parse_state));
        return true;
    }
    parse_state->current_token += 1;
    return false;
}


static bool parse_cache_del_dyn_location(njt_pool_t *pool, parse_state_t *parse_state, cache_del_dyn_location_t *out, js2c_parse_error_t *err_ret) {
    njt_uint_t i;

    js2c_check_type(JSMN_OBJECT);
    const int object_start_token = parse_state->current_token;
    const uint64_t n = parse_state->tokens[parse_state->current_token].size;
    parse_state->current_token += 1;
    for (i = 0; i < n; ++i) {
        js2c_key_children_check_for_obj();
        if (current_string_is(parse_state, "type")) {
            js2c_check_field_set(out->is_type_set);
            parse_state->current_token += 1;
            const char* saved_key = parse_state->current_key;
            parse_state->current_key = "type";
            if (parse_cache_del_dyn_location_type(pool, parse_state, (&out->type), err_ret)) {
                return true;
            }
            out->is_type_set = 1;
            parse_state->current_key = saved_key;
        } else if (current_string_is(parse_state, "addr_port")) {
            js2c_check_field_set(out->is_addr_port_set);
            parse_state->current_token += 1;
            const char* saved_key = parse_state->current_key;
            parse_state->current_key = "addr_port";
            int token_size =  CURRENT_STRING_LENGTH(parse_state) ;
            ((&out->addr_port))->data = (u_char*)njt_pcalloc(pool, (size_t)(token_size + 1));
            js2c_malloc_check(((&out->addr_port))->data);
            ((&out->addr_port))->len = token_size;
            if (builtin_parse_string(pool, parse_state, (&out->addr_port), 0, ((&out->addr_port))->len, err_ret)) {
                return true;
            }
            out->is_addr_port_set = 1;
            parse_state->current_key = saved_key;
        } else if (current_string_is(parse_state, "server_name")) {
            js2c_check_field_set(out->is_server_name_set);
            parse_state->current_token += 1;
            const char* saved_key = parse_state->current_key;
            parse_state->current_key = "server_name";
            int token_size =  CURRENT_STRING_LENGTH(parse_state) ;
            ((&out->server_name))->data = (u_char*)njt_pcalloc(pool, (size_t)(token_size + 1));
            js2c_malloc_check(((&out->server_name))->data);
            ((&out->server_name))->len = token_size;
            if (builtin_parse_string(pool, parse_state, (&out->server_name), 0, ((&out->server_name))->len, err_ret)) {
                return true;
            }
            out->is_server_name_set = 1;
            parse_state->current_key = saved_key;
        } else if (current_string_is(parse_state, "location_rule")) {
            js2c_check_field_set(out->is_location_rule_set);
            parse_state->current_token += 1;
            const char* saved_key = parse_state->current_key;
            parse_state->current_key = "location_rule";
            int token_size =  CURRENT_STRING_LENGTH(parse_state) ;
            ((&out->location_rule))->data = (u_char*)njt_pcalloc(pool, (size_t)(token_size + 1));
            js2c_malloc_check(((&out->location_rule))->data);
            ((&out->location_rule))->len = token_size;
            if (builtin_parse_string(pool, parse_state, (&out->location_rule), 0, ((&out->location_rule))->len, err_ret)) {
                return true;
            }
            out->is_location_rule_set = 1;
            parse_state->current_key = saved_key;
        } else if (current_string_is(parse_state, "location_name")) {
            js2c_check_field_set(out->is_location_name_set);
            parse_state->current_token += 1;
            const char* saved_key = parse_state->current_key;
            parse_state->current_key = "location_name";
            int token_size =  CURRENT_STRING_LENGTH(parse_state) ;
            ((&out->location_name))->data = (u_char*)njt_pcalloc(pool, (size_t)(token_size + 1));
            js2c_malloc_check(((&out->location_name))->data);
            ((&out->location_name))->len = token_size;
            if (builtin_parse_string(pool, parse_state, (&out->location_name), 0, ((&out->location_name))->len, err_ret)) {
                return true;
            }
            out->is_location_name_set = 1;
            parse_state->current_key = saved_key;
        } else {
            LOG_ERROR_JSON_PARSE(UNKNOWN_FIELD_ERR, parse_state->current_key, CURRENT_TOKEN(parse_state).start, "Unknown field in '%s': %.*s", parse_state->current_key, CURRENT_STRING_FOR_ERROR(parse_state));
            return true;
        }
    }
    const int saved_current_token = parse_state->current_token;
    parse_state->current_token = object_start_token;
    if (!out->is_type_set) {
        LOG_ERROR_JSON_PARSE(MISSING_REQUIRED_FIELD_ERR, parse_state->current_key, CURRENT_TOKEN(parse_state).start, "Missing required field in '%s': type", parse_state->current_key);
        return true;
    }
    if (!out->is_addr_port_set) {
        LOG_ERROR_JSON_PARSE(MISSING_REQUIRED_FIELD_ERR, parse_state->current_key, CURRENT_TOKEN(parse_state).start, "Missing required field in '%s': addr_port", parse_state->current_key);
        return true;
    }
    if (!out->is_server_name_set) {
        LOG_ERROR_JSON_PARSE(MISSING_REQUIRED_FIELD_ERR, parse_state->current_key, CURRENT_TOKEN(parse_state).start, "Missing required field in '%s': server_name", parse_state->current_key);
        return true;
    }
    if (!out->is_location_rule_set) {
        LOG_ERROR_JSON_PARSE(MISSING_REQUIRED_FIELD_ERR, parse_state->current_key, CURRENT_TOKEN(parse_state).start, "Missing required field in '%s': location_rule", parse_state->current_key);
        return true;
    }
    if (!out->is_location_name_set) {
        LOG_ERROR_JSON_PARSE(MISSING_REQUIRED_FIELD_ERR, parse_state->current_key, CURRENT_TOKEN(parse_state).start, "Missing required field in '%s': location_name", parse_state->current_key);
        return true;
    }
    parse_state->current_token = saved_current_token;
    return false;
}

// BEGIN GET_JSON_LENGTH ENUM

static void get_json_length_cache_del_dyn_location_type(njt_pool_t *pool, cache_del_dyn_location_type_t *out, size_t *length, njt_int_t flags) {
    if (*out == CACHE_DEL_DYN_LOCATION_TYPE_DEL) {
        // "del"
        *length += 3 + 2;
        return;
    }
}

static void get_json_length_cache_del_dyn_location_addr_port(njt_pool_t *pool, cache_del_dyn_location_addr_port_t *out, size_t *length, njt_int_t flags) {
    njt_str_t *dst = handle_escape_on_write(pool, out);
    *length += dst->len + 2; //  "str" 
}

static void get_json_length_cache_del_dyn_location_server_name(njt_pool_t *pool, cache_del_dyn_location_server_name_t *out, size_t *length, njt_int_t flags) {
    njt_str_t *dst = handle_escape_on_write(pool, out);
    *length += dst->len + 2; //  "str" 
}

static void get_json_length_cache_del_dyn_location_location_rule(njt_pool_t *pool, cache_del_dyn_location_location_rule_t *out, size_t *length, njt_int_t flags) {
    njt_str_t *dst = handle_escape_on_write(pool, out);
    *length += dst->len + 2; //  "str" 
}

static void get_json_length_cache_del_dyn_location_location_name(njt_pool_t *pool, cache_del_dyn_location_location_name_t *out, size_t *length, njt_int_t flags) {
    njt_str_t *dst = handle_escape_on_write(pool, out);
    *length += dst->len + 2; //  "str" 
}

static void get_json_length_cache_del_dyn_location(njt_pool_t *pool, cache_del_dyn_location_t *out, size_t *length, njt_int_t flags) {
    if (out == NULL) {
        *length += 4; // null
        return;
    }
    *length += 1;
    njt_int_t omit;
    njt_int_t count = 0;
    omit = 0;
    omit = out->is_type_set ? 0 : 1;
    if (omit == 0) {
        *length += (4 + 3); // "type": 
        get_json_length_cache_del_dyn_location_type(pool, (&out->type), length, flags);
        *length += 1; // ","
        count++;
    }
    omit = 0;
    omit = out->is_addr_port_set ? 0 : 1;
    omit = (flags & OMIT_NULL_STR) && (out->addr_port.data) == NULL ? 1 : omit;
    if (omit == 0) {
        *length += (9 + 3); // "addr_port": 
        get_json_length_cache_del_dyn_location_addr_port(pool, (&out->addr_port), length, flags);
        *length += 1; // ","
        count++;
    }
    omit = 0;
    omit = out->is_server_name_set ? 0 : 1;
    omit = (flags & OMIT_NULL_STR) && (out->server_name.data) == NULL ? 1 : omit;
    if (omit == 0) {
        *length += (11 + 3); // "server_name": 
        get_json_length_cache_del_dyn_location_server_name(pool, (&out->server_name), length, flags);
        *length += 1; // ","
        count++;
    }
    omit = 0;
    omit = out->is_location_rule_set ? 0 : 1;
    omit = (flags & OMIT_NULL_STR) && (out->location_rule.data) == NULL ? 1 : omit;
    if (omit == 0) {
        *length += (13 + 3); // "location_rule": 
        get_json_length_cache_del_dyn_location_location_rule(pool, (&out->location_rule), length, flags);
        *length += 1; // ","
        count++;
    }
    omit = 0;
    omit = out->is_location_name_set ? 0 : 1;
    omit = (flags & OMIT_NULL_STR) && (out->location_name.data) == NULL ? 1 : omit;
    if (omit == 0) {
        *length += (13 + 3); // "location_name": 
        get_json_length_cache_del_dyn_location_location_name(pool, (&out->location_name), length, flags);
        *length += 1; // ","
        count++;
    }
    if (count != 0) {
        *length -= 1; // "\b"
    }
    *length += 1;
}

cache_del_dyn_location_type_t get_cache_del_dyn_location_type(cache_del_dyn_location_t *out) {
    return out->type;
}

cache_del_dyn_location_addr_port_t* get_cache_del_dyn_location_addr_port(cache_del_dyn_location_t *out) {
    return &out->addr_port;
}

cache_del_dyn_location_server_name_t* get_cache_del_dyn_location_server_name(cache_del_dyn_location_t *out) {
    return &out->server_name;
}

cache_del_dyn_location_location_rule_t* get_cache_del_dyn_location_location_rule(cache_del_dyn_location_t *out) {
    return &out->location_rule;
}

cache_del_dyn_location_location_name_t* get_cache_del_dyn_location_location_name(cache_del_dyn_location_t *out) {
    return &out->location_name;
}
void set_cache_del_dyn_location_type(cache_del_dyn_location_t* obj, cache_del_dyn_location_type_t field) {
    obj->type = field;
    obj->is_type_set = 1;
}
void set_cache_del_dyn_location_addr_port(cache_del_dyn_location_t* obj, cache_del_dyn_location_addr_port_t* field) {
    njt_memcpy(&obj->addr_port, field, sizeof(njt_str_t));
    obj->is_addr_port_set = 1;
}
void set_cache_del_dyn_location_server_name(cache_del_dyn_location_t* obj, cache_del_dyn_location_server_name_t* field) {
    njt_memcpy(&obj->server_name, field, sizeof(njt_str_t));
    obj->is_server_name_set = 1;
}
void set_cache_del_dyn_location_location_rule(cache_del_dyn_location_t* obj, cache_del_dyn_location_location_rule_t* field) {
    njt_memcpy(&obj->location_rule, field, sizeof(njt_str_t));
    obj->is_location_rule_set = 1;
}
void set_cache_del_dyn_location_location_name(cache_del_dyn_location_t* obj, cache_del_dyn_location_location_name_t* field) {
    njt_memcpy(&obj->location_name, field, sizeof(njt_str_t));
    obj->is_location_name_set = 1;
}
cache_del_dyn_location_t* create_cache_del_dyn_location(njt_pool_t *pool) {
    cache_del_dyn_location_t* out = njt_pcalloc(pool, sizeof(cache_del_dyn_location_t));
    return out;
}

static void to_oneline_json_cache_del_dyn_location_type(njt_pool_t *pool, cache_del_dyn_location_type_t *out, njt_str_t* buf, njt_int_t flags) {
    u_char* cur = buf->data + buf->len;
    if (*out == CACHE_DEL_DYN_LOCATION_TYPE_DEL) {
        cur = njt_sprintf(cur, "\"del\"");
        buf->len += 3 + 2;
        return;
    }
}

static void to_oneline_json_cache_del_dyn_location_addr_port(njt_pool_t *pool, cache_del_dyn_location_addr_port_t *out, njt_str_t *buf, njt_int_t flags) {
    u_char* cur = buf->data + buf->len;
    njt_str_t *dst = handle_escape_on_write(pool, out);
    cur = njt_sprintf(cur, "\"%V\"", dst);
    buf->len = cur - buf->data;
}

static void to_oneline_json_cache_del_dyn_location_server_name(njt_pool_t *pool, cache_del_dyn_location_server_name_t *out, njt_str_t *buf, njt_int_t flags) {
    u_char* cur = buf->data + buf->len;
    njt_str_t *dst = handle_escape_on_write(pool, out);
    cur = njt_sprintf(cur, "\"%V\"", dst);
    buf->len = cur - buf->data;
}

static void to_oneline_json_cache_del_dyn_location_location_rule(njt_pool_t *pool, cache_del_dyn_location_location_rule_t *out, njt_str_t *buf, njt_int_t flags) {
    u_char* cur = buf->data + buf->len;
    njt_str_t *dst = handle_escape_on_write(pool, out);
    cur = njt_sprintf(cur, "\"%V\"", dst);
    buf->len = cur - buf->data;
}

static void to_oneline_json_cache_del_dyn_location_location_name(njt_pool_t *pool, cache_del_dyn_location_location_name_t *out, njt_str_t *buf, njt_int_t flags) {
    u_char* cur = buf->data + buf->len;
    njt_str_t *dst = handle_escape_on_write(pool, out);
    cur = njt_sprintf(cur, "\"%V\"", dst);
    buf->len = cur - buf->data;
}

static void to_oneline_json_cache_del_dyn_location(njt_pool_t *pool, cache_del_dyn_location_t *out, njt_str_t* buf, njt_int_t flags) {
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
    omit = out->is_type_set ? 0 : 1;
    if (omit == 0) {
        cur = njt_sprintf(cur, "\"type\":");
        buf->len = cur - buf->data;
        to_oneline_json_cache_del_dyn_location_type(pool, (&out->type), buf, flags);
        cur = buf->data + buf->len;
        cur = njt_sprintf(cur, ",");
        buf->len ++;
    }
    omit = 0;
    omit = out->is_addr_port_set ? 0 : 1;
    omit = (flags & OMIT_NULL_STR) && (out->addr_port.data) == NULL ? 1 : omit;
    if (omit == 0) {
        cur = njt_sprintf(cur, "\"addr_port\":");
        buf->len = cur - buf->data;
        to_oneline_json_cache_del_dyn_location_addr_port(pool, (&out->addr_port), buf, flags);
        cur = buf->data + buf->len;
        cur = njt_sprintf(cur, ",");
        buf->len ++;
    }
    omit = 0;
    omit = out->is_server_name_set ? 0 : 1;
    omit = (flags & OMIT_NULL_STR) && (out->server_name.data) == NULL ? 1 : omit;
    if (omit == 0) {
        cur = njt_sprintf(cur, "\"server_name\":");
        buf->len = cur - buf->data;
        to_oneline_json_cache_del_dyn_location_server_name(pool, (&out->server_name), buf, flags);
        cur = buf->data + buf->len;
        cur = njt_sprintf(cur, ",");
        buf->len ++;
    }
    omit = 0;
    omit = out->is_location_rule_set ? 0 : 1;
    omit = (flags & OMIT_NULL_STR) && (out->location_rule.data) == NULL ? 1 : omit;
    if (omit == 0) {
        cur = njt_sprintf(cur, "\"location_rule\":");
        buf->len = cur - buf->data;
        to_oneline_json_cache_del_dyn_location_location_rule(pool, (&out->location_rule), buf, flags);
        cur = buf->data + buf->len;
        cur = njt_sprintf(cur, ",");
        buf->len ++;
    }
    omit = 0;
    omit = out->is_location_name_set ? 0 : 1;
    omit = (flags & OMIT_NULL_STR) && (out->location_name.data) == NULL ? 1 : omit;
    if (omit == 0) {
        cur = njt_sprintf(cur, "\"location_name\":");
        buf->len = cur - buf->data;
        to_oneline_json_cache_del_dyn_location_location_name(pool, (&out->location_name), buf, flags);
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
cache_del_dyn_location_t* json_parse_cache_del_dyn_location(njt_pool_t *pool, const njt_str_t *json_string, js2c_parse_error_t *err_ret) {
    cache_del_dyn_location_t* out;
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
    out = njt_pcalloc(pool, sizeof(cache_del_dyn_location_t));;
    if (parse_cache_del_dyn_location(pool, parse_state, out, err_ret)) {
        return NULL;
    }
    return out;
}

njt_str_t* to_json_cache_del_dyn_location(njt_pool_t *pool, cache_del_dyn_location_t* out, njt_int_t flags) {
    njt_str_t *json_str;
    json_str = njt_pcalloc(pool, sizeof(njt_str_t));
    size_t str_len = 0;
    get_json_length_cache_del_dyn_location(pool, out, &str_len, flags);
    json_str->data = (u_char*)njt_pcalloc(pool, str_len + 1);
    json_str->len = 0;
    to_oneline_json_cache_del_dyn_location(pool, out, json_str, flags);
    return json_str;
}
