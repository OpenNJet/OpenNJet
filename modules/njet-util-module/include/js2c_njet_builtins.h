/*
 * MIT License
 *
 * Copyright (c) 2020 Alex Badics
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef JS2C_BUILTINS_H
#define JS2C_BUILTINS_H

#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef JSMN_STATIC
#define JSMN_STATIC
#endif

#ifndef JSMN_STRICT
#define JSMN_STRICT
#endif

#include "jsmn.h"
#include "njt_core.h"

// #ifndef LOG_ERROR
// #define LOG_ERROR(position, ...) 
// #endif

enum {
    OMIT_NULL_ARRAY = 1 << 0,
    OMIT_NULL_OBJ   = 1 << 1,
    OMIT_NULL_STR   = 1 << 2
};

enum {
    MISSING_SEPARATOR_BETWEEN_VALUES_ERR = 0,
    MISSING_REQUIRED_FIELD_ERR,
    UNKNOWN_FIELD_ERR,
    DUPLICATE_FIELD_ERR,
    MISSIGN_FIELD_VALUE_ERR,
    ARRAY_SIZE_CHECK_ERR,
    UNKNOWN_ENUM_VALUE_ERR,
    NUMBER_RANGE_CHECK_ERR,
    BOOL_VALUE_ERR,
    PARSING_NUMBER_ERR,
    PARSING_STR_ERR,
    STRLENG_CHECK_ERR,
    JSON_TYPE_ERR,
    POOL_MALLOC_ERR,
    INVALID_JSON_CHAR_ERR,
    PARTIAL_JSON_ERR,
    NULL_JSON_ERR
};

typedef struct j2sc_parse_error_s {
    int         err_code;
    njt_str_t   field_name;
    int         pos;
    njt_str_t   err_str;
} js2c_parse_error_t;

#ifndef LOG_ERROR_JSON_PARSE
#define LOG_ERROR_JSON_PARSE(code, field, position, format, ...)  do { \
    err_ret->err_code = code; \
    err_ret->field_name.data = (u_char *)njt_pcalloc(pool, strlen(field) + 1); \
    err_ret->field_name.len = sprintf((char *)err_ret->field_name.data, "%s", field); \
    err_ret->pos = position; \
    int len; \
    err_ret->err_str.data = (u_char *)njt_pcalloc(pool, 1024); \
    len = sprintf((char *)err_ret->err_str.data, "pos: %d, ", position); \
    len += sprintf((char *)err_ret->err_str.data + len, format, __VA_ARGS__); \
    err_ret->err_str.len = len; \
} while(0)
#endif

// #define LOG_POOL_MALLOC_ERR() LOG_ERROR_JSON_PARSE(-1, "%s", "njt_pool malloc error")

typedef struct parse_state_s {
    const char *json_string;
    const char *current_key;
    jsmntok_t *tokens;
    uint64_t current_token;
    uint64_t max_token_num;
} parse_state_t;

#define CURRENT_TOKEN(parse_state) ((parse_state)->tokens[(parse_state)->current_token])
#define CURRENT_STRING(parse_state) ((parse_state)->json_string + CURRENT_TOKEN(parse_state).start)
#define CURRENT_STRING_LENGTH(parse_state) (CURRENT_TOKEN(parse_state).end - CURRENT_TOKEN(parse_state).start)
#define CURRENT_STRING_FOR_ERROR(parse_state) CURRENT_STRING_LENGTH(parse_state), CURRENT_STRING(parse_state)

#define js2c_key_children_check_for_obj() do { \
        if (CURRENT_TOKEN(parse_state).size > 1) { \
            LOG_ERROR_JSON_PARSE(MISSING_SEPARATOR_BETWEEN_VALUES_ERR, parse_state->current_key,  CURRENT_TOKEN(parse_state).start, "Missing separator between values in '%s', after key: %.*s", parse_state->current_key, CURRENT_STRING_FOR_ERROR(parse_state)); \
            return true; \
        } \
        if (CURRENT_TOKEN(parse_state).size < 1) { \
            LOG_ERROR_JSON_PARSE(MISSIGN_FIELD_VALUE_ERR,  parse_state->current_key, CURRENT_TOKEN(parse_state).start, "Missing value in '%s', after key: %.*s", parse_state->current_key, CURRENT_STRING_FOR_ERROR(parse_state)); \
            return true; \
        } \
} while(0)

#define js2c_int_range_check_min(min) do { \
        if (!(int_parse_tmp >= min)) { \
            parse_state->current_token -= 1; \
            LOG_ERROR_JSON_PARSE(NUMBER_RANGE_CHECK_ERR, parse_state->current_key,  CURRENT_TOKEN(parse_state).start, "Integer %" PRIi64 " in '%s' out of range. It must be >= %lld.", int_parse_tmp, parse_state->current_key, min); \
            return true; \
        } \
} while(0)

#define js2c_int_range_check_max(max) do { \
        if (!(int_parse_tmp <= max)) { \
            parse_state->current_token -= 1; \
            LOG_ERROR_JSON_PARSE(NUMBER_RANGE_CHECK_ERR, parse_state->current_key, CURRENT_TOKEN(parse_state).start, "Integer %" PRIi64 " in '%s' out of range. It must be <= %lld.", int_parse_tmp, parse_state->current_key, max); \
            return true; \
        } \
} while(0)

#define js2c_malloc_check(var_ptr) do { \
        if ((var_ptr) == NULL) { \
            LOG_ERROR_JSON_PARSE(POOL_MALLOC_ERR, "", 0, "Failed to allocate memory from %s.", "pool"); \
            return true; \
        } \
} while(0)

#define js2c_null_check() do { \
       if (current_string_is(parse_state, "null")) { \
                parse_state->current_key = saved_key; \
                continue; \
       } \
} while(0)

static inline const char *token_type_as_string(jsmntype_t type) {
    switch (type) {
    case JSMN_UNDEFINED:
        return "UNDEFINED";
    case JSMN_OBJECT:
        return "OBJECT";
    case JSMN_ARRAY:
        return "ARRAY";
    case JSMN_STRING:
        return "STRING";
    case JSMN_PRIMITIVE:
        return "PRIMITIVE";
    default:
        return "UNKNOWN";
    }
}


static inline const char *jsmn_error_as_string(int err) {
    switch (err) {
    case JSMN_ERROR_INVAL:
        return "Invalid character";
    case JSMN_ERROR_NOMEM:
        return "JSON file too complex";
    case JSMN_ERROR_PART:
        return "End-of-file reached (JSON file incomplete)";
    default:
        return "Internal error";
    }
}

#define js2c_check_type(jsmn_type) do { \
    if (check_type(pool, parse_state, jsmn_type, err_ret)) return true; \
} while(0)

#define js2c_check_field_set(obj_field_set) do { \
    if (obj_field_set) { \
        LOG_ERROR_JSON_PARSE(DUPLICATE_FIELD_ERR, CURRENT_STRING(parse_state), CURRENT_TOKEN(parse_state).start, "Duplicate field definition in '%s'", parse_state->current_key); \
        return true; \
    } \
} while(0)

static inline bool check_type(njt_pool_t *pool, const parse_state_t *parse_state, jsmntype_t type, js2c_parse_error_t *err_ret) {
    const jsmntok_t *token = &parse_state->tokens[parse_state->current_token];
    if (token->type != type) {
        LOG_ERROR_JSON_PARSE(
            JSON_TYPE_ERR,
            parse_state->current_key,
            token->start,
            "Unexpected token in '%s': %s instead of %s",
            parse_state->current_key,
            token_type_as_string(token->type),
            token_type_as_string(type));
        return true;
    }
    return false;
}

static inline bool current_string_is(const parse_state_t *parse_state, const char *s) {
    const jsmntok_t *token = &parse_state->tokens[parse_state->current_token];
    if (token->type != JSMN_STRING) {
        return false;
    }
    if (strlen(s) != (size_t)(token->end - token->start)) {
        return false;
    }
    return memcmp(parse_state->json_string + token->start, s, token->end - token->start) == 0;
}

// static inline bool next_string_is_null(const parse_state_t *parse_state) {
//     static const char* null_str = "null";
//     const jsmntok_t *token = &parse_state->tokens[parse_state->current_token + 1];
//     if (token->type != JSMN_PRIMITIVE) {
//         return false;
//     }
//     if (4 != (size_t)(token->end - token->start)) {
//         return false;
//     }
//     return memcmp(parse_state->json_string + token->start, null_str, token->end - token->start) == 0;
// }

static inline bool builtin_check_current_string(njt_pool_t *pool, parse_state_t *parse_state, int min_len, int max_len, js2c_parse_error_t *err_ret) {
    if (check_type(pool, parse_state, JSMN_STRING, err_ret)) {
        return true;
    }
    const jsmntok_t *token = &CURRENT_TOKEN(parse_state);
    if (token->end - token->start > max_len) {
        LOG_ERROR_JSON_PARSE(STRLENG_CHECK_ERR, parse_state->current_key, token->start, "String too large in '%s'. Length: %i. Maximum length: %i.", parse_state->current_key, token->end - token->start, max_len);
        return true;
    }
    if (token->end - token->start < min_len) {
        LOG_ERROR_JSON_PARSE(STRLENG_CHECK_ERR, parse_state->current_key, token->start, "String too short in '%s'. Length: %i. Minimum length: %i.", parse_state->current_key, token->end - token->start, min_len);
        return true;
    }
    return false;
}

static inline void handle_escape_on_read(parse_state_t *state, njt_str_t *out) {
    const char *src;
    char* dst;
    const jsmntok_t *token = &CURRENT_TOKEN(state);
    src = state->json_string + token->start;
    dst = (char *)out->data;
    for(;src < state->json_string + token->end;) {
        if (*src == '\\') {
            out->len --;
            switch (*++src) {
                case '"':  *dst++ = '"';  src++; break;
                case '\\': *dst++ = '\\'; src++; break;
                case '/':  *dst++ = '/';  src++; break;
                case 'b':  *dst++ = '\b'; src++; break;
                case 'f':  *dst++ = '\f'; src++; break;
                case 'n':  *dst++ = '\n'; src++; break;
                case 'r':  *dst++ = '\r'; src++; break;
                case 't':  *dst++ = '\t'; src++; break;
                default:
                break;
                // unreachable, should get err in jsmn parse string
                    // return_err(src, "invalid escaped character in string");
            }
        } else {
            *dst++ = *src++;
        }
    }
    
    if (token->end > token->start) {
        out->data[out->len] = 0;
    }
    // if (token->end > token->start) {
    //     out->data[token->end - token->start] = 0;
    // }
}

static inline njt_str_t* handle_escape_on_write(njt_pool_t *pool, njt_str_t *src) {
    size_t i;
    bool need_convert = false; 
    char *cur = (char *)src->data;
    for (i = 0; i < src->len && need_convert == false; i++, cur++) {
        switch (*cur) {
            case '"':  
            case '\\': 
            // case '/':  need_convert = true; break;
            case '\b':  
            case '\f':  
            case '\n':  
            case '\r':  
            case '\t':  need_convert = true; break;
        default:
            break;
        }
    }
    if (need_convert == false) {
        return src;
    }
    njt_str_t *out = (njt_str_t *)njt_pcalloc(pool, sizeof(njt_str_t));
    out->data = (u_char *)njt_pcalloc(pool, 2*src->len);
    char *dst = (char *)out->data;
    out->len = src->len;
    cur = (char *)src->data;
    for (i = 0; i < src->len; i++, cur++) {
        switch (*cur) {
            case '"':  *dst++ = '\\'; *dst++ = '"'; out->len++; break;
            case '\\': *dst++ = '\\'; *dst++ = '\\'; out->len++; break;
            // case '/':  *dst++ = '\\'; *dst++ = '/'; out->len++; break;
            case '\b': *dst++ = '\\'; *dst++ = 'b'; out->len++; break;
            case '\f': *dst++ = '\\'; *dst++ = 'f'; out->len++; break;
            case '\n': *dst++ = '\\'; *dst++ = 'n'; out->len++; break;
            case '\r': *dst++ = '\\'; *dst++ = 'r'; out->len++; break;
            case '\t': *dst++ = '\\'; *dst++ = 't'; out->len++; break;
        default:
            *dst++ = *cur;
        }
    }

    return out;
}

static inline bool builtin_parse_string(njt_pool_t *pool, parse_state_t *parse_state, njt_str_t *out, int min_len, int max_len, js2c_parse_error_t *err_ret) {
    if (builtin_check_current_string(pool, parse_state, min_len, max_len, err_ret)){
        return true;
    }
    // const jsmntok_t *token = &CURRENT_TOKEN(parse_state);
    // memcpy(out, parse_state->json_string + token->start, token->end - token->start);
    handle_escape_on_read(parse_state, out);
    parse_state->current_token += 1;
    return false;
}

static inline bool builtin_parse_bool(njt_pool_t *pool, parse_state_t *parse_state, bool *out, js2c_parse_error_t* err_ret) {
    if (check_type(pool, parse_state, JSMN_PRIMITIVE, err_ret)) {
        return true;
    }
    const jsmntok_t *token = &parse_state->tokens[parse_state->current_token];
    const char first_char = parse_state->json_string[token->start];
    if (first_char != 't' && first_char != 'f') {
        LOG_ERROR_JSON_PARSE(BOOL_VALUE_ERR, parse_state->current_key , token->start, "Invalid boolean literal in '%s': %.*s", parse_state->current_key, CURRENT_STRING_FOR_ERROR(parse_state));
        return true;
    }
    size_t str_len = (size_t)(token->end - token->start);
    if (4 == str_len && memcmp(parse_state->json_string + token->start, "true", token->end - token->start) == 0){
        *out = true;
        parse_state->current_token += 1;
        return false;
    } else if (5 == str_len && memcmp(parse_state->json_string + token->start, "false", token->end - token->start) == 0){
        *out = false;
        parse_state->current_token += 1;
        return false;
    } else {
        LOG_ERROR_JSON_PARSE(BOOL_VALUE_ERR, parse_state->current_key , token->start, "Invalid boolean literal in '%s': %.*s", parse_state->current_key, CURRENT_STRING_FOR_ERROR(parse_state));
        return true;
    }
}

static inline bool builtin_parse_signed(
    njt_pool_t *pool,
    parse_state_t *parse_state,
    bool number_allowed,
    bool string_allowed,
    int radix,
    int64_t *out,
    js2c_parse_error_t *err_ret) {
    const jsmntok_t *token = &parse_state->tokens[parse_state->current_token];
    if (!((number_allowed && token->type == JSMN_PRIMITIVE) || (string_allowed && token->type == JSMN_STRING))) {
        LOG_ERROR_JSON_PARSE(PARSING_NUMBER_ERR, parse_state->current_key , token->start, "Unexpected token in '%s': %s", parse_state->current_key, token_type_as_string(token->type));
    }
    if (token->type == JSMN_PRIMITIVE) {
        radix = 10;
    }
    char *end_char = NULL;
    *out = strtoll(parse_state->json_string + token->start, &end_char, radix);
    if (end_char != parse_state->json_string + token->end) {
        LOG_ERROR_JSON_PARSE(PARSING_NUMBER_ERR, parse_state->current_key, token->start, "Invalid signed integer literal in '%s': %.*s", parse_state->current_key, CURRENT_STRING_FOR_ERROR(parse_state));
        return true;
    }
    parse_state->current_token += 1;
    return false;
}

static inline bool builtin_parse_unsigned(
    njt_pool_t *pool,
    parse_state_t *parse_state,
    bool number_allowed,
    bool string_allowed,
    int radix,
    uint64_t *out,
    js2c_parse_error_t *err_ret
) {
    const jsmntok_t *token = &parse_state->tokens[parse_state->current_token];
    if (!((number_allowed && token->type == JSMN_PRIMITIVE) || (string_allowed && token->type == JSMN_STRING))) {
        LOG_ERROR_JSON_PARSE(PARSING_NUMBER_ERR, parse_state->current_key, token->start, "Unexpected token in '%s': %s", parse_state->current_key, token_type_as_string(token->type));
        return true;
    }
    if (token->type == JSMN_PRIMITIVE) {
        radix = 10;
    }
    const char *start_char = parse_state->json_string + token->start;
    char *end_char = NULL;
    if (*start_char == '-') {
        LOG_ERROR_JSON_PARSE(PARSING_NUMBER_ERR, parse_state->current_key, token->start, "Invalid unsigned integer literal in '%s': %.*s", parse_state->current_key, CURRENT_STRING_FOR_ERROR(parse_state));
        return true;
    }
    *out = strtoull(start_char, &end_char, radix);
    if (end_char != parse_state->json_string + token->end) {
        LOG_ERROR_JSON_PARSE(PARSING_NUMBER_ERR, parse_state->current_key, token->start, "Invalid unsigned integer literal in '%s': %.*s", parse_state->current_key, CURRENT_STRING_FOR_ERROR(parse_state));
        return true;
    }
    parse_state->current_token += 1;
    return false;
}

static inline bool builtin_parse_double(njt_pool_t *pool, parse_state_t *parse_state, double *out, js2c_parse_error_t *err_ret) {
    const jsmntok_t *token = &parse_state->tokens[parse_state->current_token];
    if (check_type(pool, parse_state, JSMN_PRIMITIVE, err_ret)) {
        return true;
    }
    const char *start_char = parse_state->json_string + token->start;
    if (token->end - token->start >= 2) {
        if (start_char[1] != '.' && start_char[1] != 'e' && start_char[1] != 'E' &&
            !(start_char[1] >= '0' && start_char[1] <= '9')) {
            LOG_ERROR_JSON_PARSE(PARSING_NUMBER_ERR, parse_state->current_key, token->start, "Invalid floating point literal in '%s': %.*s", parse_state->current_key, CURRENT_STRING_FOR_ERROR(parse_state));
            return true;
        }
    }
    char *end_char = NULL;
    *out = strtod(start_char, &end_char);
    if (end_char != parse_state->json_string + token->end) {
        LOG_ERROR_JSON_PARSE(PARSING_NUMBER_ERR, parse_state->current_key, token->start, "Invalid floating point literal in '%s': %.*s", parse_state->current_key, CURRENT_STRING_FOR_ERROR(parse_state));
        return true;
    }
    parse_state->current_token += 1;
    return false;
}

static inline bool builtin_skip(parse_state_t *parse_state) {
    /* The algorithm works, because of how .size behaves on JSMN tokens:
     *   - Arrays have size = number of elements
     *   - Objects have size = number of fields
     *   - Object keys have a size of 1. This is important, because {"a": "b"} is 3 tokens this way:
     *       - An object of size 1,
     *       - A key of size 1
     *       - A string of size 0.
     *   - All other tokens are size 0.
     */
    uint32_t skip_tokens = 1;
    while (skip_tokens > 0) {
        skip_tokens += CURRENT_TOKEN(parse_state).size;
        if (parse_state->current_token >= parse_state->max_token_num) {
            /* Should never happen */
            return true;
        }
        parse_state->current_token += 1;
        skip_tokens -= 1;
    }
    return false;
}

static inline int builtin_parse_json_string(
    njt_pool_t *pool,
    parse_state_t *parse_state,
    jsmntok_t *token_buffer,
    uint64_t token_buffer_size,
    const char *json_string,
    const size_t json_string_len,
    js2c_parse_error_t *err_ret
) {
    jsmn_parser parser = {0};

    parse_state->json_string = json_string;
    parse_state->tokens = token_buffer;
    parse_state->current_token = 0;
    parse_state->max_token_num = token_buffer_size;
    parse_state->current_key = "document root";

    jsmn_init(&parser);
    int token_num = jsmn_parse(&parser, json_string, json_string_len, parse_state->tokens, token_buffer_size);
    return token_num;
}

#endif /* JS2C_BUILTINS_H */
