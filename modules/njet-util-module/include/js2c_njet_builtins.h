/*
 * MIT License
 *
 * Copyright (c) 2020 Alex Badics
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


#ifndef LOG_ERROR_JSON_PARSE
#define LOG_ERROR_JSON_PARSE(position, format, ...)  { \
    int len; \
    err_str->data = njt_palloc(pool, 1024); \
    len = sprintf((char *)err_str->data, "pos: %d, ", position); \
    len += sprintf((char *)err_str->data + len, format, __VA_ARGS__); \
    err_str->len = len; \
}
#endif

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

// static inline njt_str_t* set_parse_error(njt_pool_t* pool, int pos, const char* fmt, ...) {
//     njt_str_t* err;
//     err = njt_palloc(pool, sizeof(njt_str_t));
//     if (err == NULL) return NULL;
//     char buf[2048]; //如果不够，会报错
//     char *cur = buf;
//     int len;
//     len = sprintf(buf, "pos: %d", pos);
//     cur += len;
//     sprint(cur, fmt, __VA_ARGS__); 
// }

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

static inline bool check_type(njt_pool_t *pool, const parse_state_t *parse_state, jsmntype_t type, njt_str_t *err_str) {
    const jsmntok_t *token = &parse_state->tokens[parse_state->current_token];
    if (token->type != type) {
        LOG_ERROR_JSON_PARSE(
            token->start,
            "Unexpected token in '%s': %s instead of %s",
            parse_state->current_key,
            token_type_as_string(token->type),
            token_type_as_string(type))
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

static inline bool builtin_check_current_string(njt_pool_t *pool, parse_state_t *parse_state, int min_len, int max_len, njt_str_t *err_str) {
    if (check_type(pool, parse_state, JSMN_STRING, err_str)) {
        return true;
    }
    const jsmntok_t *token = &CURRENT_TOKEN(parse_state);
    if (token->end - token->start > max_len) {
        LOG_ERROR_JSON_PARSE(token->start, "String too large in '%s'. Length: %i. Maximum length: %i.", parse_state->current_key, token->end - token->start, max_len);
        return true;
    }
    if (token->end - token->start < min_len) {
        LOG_ERROR_JSON_PARSE(token->start, "String too short in '%s'. Length: %i. Minimum length: %i.", parse_state->current_key, token->end - token->start, min_len);
        return true;
    }
    return false;
}

static inline bool builtin_parse_string(njt_pool_t *pool, parse_state_t *parse_state, char *out, int min_len, int max_len, njt_str_t *err_str) {
    if (builtin_check_current_string(pool, parse_state, min_len, max_len, err_str)){
        return true;
    }
    const jsmntok_t *token = &CURRENT_TOKEN(parse_state);
    memcpy(out, parse_state->json_string + token->start, token->end - token->start);
    out[token->end - token->start] = 0;
    parse_state->current_token += 1;
    return false;
}

static inline bool builtin_parse_bool(njt_pool_t *pool, parse_state_t *parse_state, bool *out, njt_str_t* err_str) {
    if (check_type(pool, parse_state, JSMN_PRIMITIVE, err_str)) {
        return true;
    }
    const jsmntok_t *token = &parse_state->tokens[parse_state->current_token];
    const char first_char = parse_state->json_string[token->start];
    if (first_char != 't' && first_char != 'f') {
        LOG_ERROR_JSON_PARSE(token->start, "Invalid boolean literal in '%s': %.*s", parse_state->current_key, CURRENT_STRING_FOR_ERROR(parse_state));
        return true;
    }
    *out = first_char == 't';
    parse_state->current_token += 1;
    return false;
}

static inline bool builtin_parse_signed(
    njt_pool_t *pool,
    parse_state_t *parse_state,
    bool number_allowed,
    bool string_allowed,
    int radix,
    int64_t *out,
    njt_str_t *err_str) {
    const jsmntok_t *token = &parse_state->tokens[parse_state->current_token];
    if (!((number_allowed && token->type == JSMN_PRIMITIVE) || (string_allowed && token->type == JSMN_STRING))) {
        LOG_ERROR_JSON_PARSE(token->start, "Unexpected token in '%s': %s", parse_state->current_key, token_type_as_string(token->type))
        return true;
    }
    if (token->type == JSMN_PRIMITIVE) {
        radix = 10;
    }
    char *end_char = NULL;
    *out = strtoll(parse_state->json_string + token->start, &end_char, radix);
    if (end_char != parse_state->json_string + token->end) {
        LOG_ERROR_JSON_PARSE(token->start, "Invalid signed integer literal in '%s': %.*s", parse_state->current_key, CURRENT_STRING_FOR_ERROR(parse_state));
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
    njt_str_t *err_str
) {
    const jsmntok_t *token = &parse_state->tokens[parse_state->current_token];
    if (!((number_allowed && token->type == JSMN_PRIMITIVE) || (string_allowed && token->type == JSMN_STRING))) {
        LOG_ERROR_JSON_PARSE(token->start, "Unexpected token in '%s': %s", parse_state->current_key, token_type_as_string(token->type))
        return true;
    }
    if (token->type == JSMN_PRIMITIVE) {
        radix = 10;
    }
    const char *start_char = parse_state->json_string + token->start;
    char *end_char = NULL;
    if (*start_char == '-') {
        LOG_ERROR_JSON_PARSE(token->start, "Invalid unsigned integer literal in '%s': %.*s", parse_state->current_key, CURRENT_STRING_FOR_ERROR(parse_state));
        return true;
    }
    *out = strtoull(start_char, &end_char, radix);
    if (end_char != parse_state->json_string + token->end) {
        LOG_ERROR_JSON_PARSE(token->start, "Invalid unsigned integer literal in '%s': %.*s", parse_state->current_key, CURRENT_STRING_FOR_ERROR(parse_state));
        return true;
    }
    parse_state->current_token += 1;
    return false;
}

static inline bool builtin_parse_double(njt_pool_t *pool, parse_state_t *parse_state, double *out, njt_str_t *err_str) {
    const jsmntok_t *token = &parse_state->tokens[parse_state->current_token];
    if (check_type(pool, parse_state, JSMN_PRIMITIVE, err_str)) {
        return true;
    }
    const char *start_char = parse_state->json_string + token->start;
    if (token->end - token->start >= 2) {
        if (start_char[1] != '.' && start_char[1] != 'e' && start_char[1] != 'E' &&
            !(start_char[1] >= '0' && start_char[1] <= '9')) {
            LOG_ERROR_JSON_PARSE(token->start, "Invalid floating point literal in '%s': %.*s", parse_state->current_key, CURRENT_STRING_FOR_ERROR(parse_state));
            return true;
        }
    }
    char *end_char = NULL;
    *out = strtod(start_char, &end_char);
    if (end_char != parse_state->json_string + token->end) {
        LOG_ERROR_JSON_PARSE(token->start, "Invalid floating point literal in '%s': %.*s", parse_state->current_key, CURRENT_STRING_FOR_ERROR(parse_state));
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
    njt_str_t *err_str
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
