
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_STRING_H_INCLUDED_
#define _NJT_STRING_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


typedef struct {
    size_t      len;
    u_char     *data;
} njt_str_t;


typedef struct {
    njt_str_t   key;
    njt_str_t   value;
} njt_keyval_t;


typedef struct {
    unsigned    len:28;

    unsigned    valid:1;
    unsigned    no_cacheable:1;
    unsigned    not_found:1;
    unsigned    escape:1;

    u_char     *data;
} njt_variable_value_t;


#define njt_string(str)     { sizeof(str) - 1, (u_char *) str }
#define njt_null_string     { 0, NULL }
#define njt_str_set(str, text)                                               \
    (str)->len = sizeof(text) - 1; (str)->data = (u_char *) text
#define njt_str_null(str)   (str)->len = 0; (str)->data = NULL


#define njt_tolower(c)      (u_char) ((c >= 'A' && c <= 'Z') ? (c | 0x20) : c)
#define njt_toupper(c)      (u_char) ((c >= 'a' && c <= 'z') ? (c & ~0x20) : c)

void njt_strlow(u_char *dst, u_char *src, size_t n);


#define njt_strncmp(s1, s2, n)  strncmp((const char *) s1, (const char *) s2, n)


/* msvc and icc7 compile strcmp() to inline loop */
#define njt_strcmp(s1, s2)  strcmp((const char *) s1, (const char *) s2)


#define njt_strstr(s1, s2)  strstr((const char *) s1, (const char *) s2)
#define njt_strlen(s)       strlen((const char *) s)

size_t njt_strnlen(u_char *p, size_t n);

#define njt_strchr(s1, c)   strchr((const char *) s1, (int) c)

static njt_inline u_char *
njt_strlchr(u_char *p, u_char *last, u_char c)
{
    while (p < last) {

        if (*p == c) {
            return p;
        }

        p++;
    }

    return NULL;
}


/*
 * msvc and icc7 compile memset() to the inline "rep stos"
 * while ZeroMemory() and bzero() are the calls.
 * icc7 may also inline several mov's of a zeroed register for small blocks.
 */
#define njt_memzero(buf, n)       (void) memset(buf, 0, n)
#define njt_memset(buf, c, n)     (void) memset(buf, c, n)

void njt_explicit_memzero(void *buf, size_t n);


#if (NJT_MEMCPY_LIMIT)

void *njt_memcpy(void *dst, const void *src, size_t n);
#define njt_cpymem(dst, src, n)   (((u_char *) njt_memcpy(dst, src, n)) + (n))

#else

/*
 * gcc3, msvc, and icc7 compile memcpy() to the inline "rep movs".
 * gcc3 compiles memcpy(d, s, 4) to the inline "mov"es.
 * icc8 compile memcpy(d, s, 4) to the inline "mov"es or XMM moves.
 */
#define njt_memcpy(dst, src, n)   (void) memcpy(dst, src, n)
#define njt_cpymem(dst, src, n)   (((u_char *) memcpy(dst, src, n)) + (n))

#endif


#if ( __INTEL_COMPILER >= 800 )

/*
 * the simple inline cycle copies the variable length strings up to 16
 * bytes faster than icc8 autodetecting _intel_fast_memcpy()
 */

static njt_inline u_char *
njt_copy(u_char *dst, u_char *src, size_t len)
{
    if (len < 17) {

        while (len) {
            *dst++ = *src++;
            len--;
        }

        return dst;

    } else {
        return njt_cpymem(dst, src, len);
    }
}

#else

#define njt_copy                  njt_cpymem

#endif


#define njt_memmove(dst, src, n)  (void) memmove(dst, src, n)
#define njt_movemem(dst, src, n)  (((u_char *) memmove(dst, src, n)) + (n))


/* msvc and icc7 compile memcmp() to the inline loop */
#define njt_memcmp(s1, s2, n)     memcmp(s1, s2, n)


u_char *njt_cpystrn(u_char *dst, u_char *src, size_t n);
u_char *njt_pstrdup(njt_pool_t *pool, njt_str_t *src);
u_char * njt_cdecl njt_sprintf(u_char *buf, const char *fmt, ...);
u_char * njt_cdecl njt_snprintf(u_char *buf, size_t max, const char *fmt, ...);
u_char * njt_cdecl njt_slprintf(u_char *buf, u_char *last, const char *fmt,
    ...);
u_char *njt_vslprintf(u_char *buf, u_char *last, const char *fmt, va_list args);
#define njt_vsnprintf(buf, max, fmt, args)                                   \
    njt_vslprintf(buf, buf + (max), fmt, args)

njt_int_t njt_strcasecmp(u_char *s1, u_char *s2);
njt_int_t njt_strncasecmp(u_char *s1, u_char *s2, size_t n);

u_char *njt_strnstr(u_char *s1, char *s2, size_t n);

u_char *njt_strstrn(u_char *s1, char *s2, size_t n);
u_char *njt_strcasestrn(u_char *s1, char *s2, size_t n);
u_char *njt_strlcasestrn(u_char *s1, u_char *last, u_char *s2, size_t n);

njt_int_t njt_rstrncmp(u_char *s1, u_char *s2, size_t n);
njt_int_t njt_rstrncasecmp(u_char *s1, u_char *s2, size_t n);
njt_int_t njt_memn2cmp(u_char *s1, u_char *s2, size_t n1, size_t n2);
njt_int_t njt_dns_strcmp(u_char *s1, u_char *s2);
njt_int_t njt_filename_cmp(u_char *s1, u_char *s2, size_t n);

njt_int_t njt_atoi(u_char *line, size_t n);
njt_int_t njt_atofp(u_char *line, size_t n, size_t point);
ssize_t njt_atosz(u_char *line, size_t n);
off_t njt_atoof(u_char *line, size_t n);
time_t njt_atotm(u_char *line, size_t n);
njt_int_t njt_hextoi(u_char *line, size_t n);

u_char *njt_hex_dump(u_char *dst, u_char *src, size_t len);


#define njt_base64_encoded_length(len)  (((len + 2) / 3) * 4)
#define njt_base64_decoded_length(len)  (((len + 3) / 4) * 3)

void njt_encode_base64(njt_str_t *dst, njt_str_t *src);
void njt_encode_base64url(njt_str_t *dst, njt_str_t *src);
njt_int_t njt_decode_base64(njt_str_t *dst, njt_str_t *src);
njt_int_t njt_decode_base64url(njt_str_t *dst, njt_str_t *src);

uint32_t njt_utf8_decode(u_char **p, size_t n);
size_t njt_utf8_length(u_char *p, size_t n);
u_char *njt_utf8_cpystrn(u_char *dst, u_char *src, size_t n, size_t len);


#define NJT_ESCAPE_URI            0
#define NJT_ESCAPE_ARGS           1
#define NJT_ESCAPE_URI_COMPONENT  2
#define NJT_ESCAPE_HTML           3
#define NJT_ESCAPE_REFRESH        4
#define NJT_ESCAPE_MEMCACHED      5
#define NJT_ESCAPE_MAIL_AUTH      6

#define NJT_UNESCAPE_URI       1
#define NJT_UNESCAPE_REDIRECT  2

uintptr_t njt_escape_uri(u_char *dst, u_char *src, size_t size,
    njt_uint_t type);
void njt_unescape_uri(u_char **dst, u_char **src, size_t size, njt_uint_t type);
uintptr_t njt_escape_html(u_char *dst, u_char *src, size_t size);
uintptr_t njt_escape_json(u_char *dst, u_char *src, size_t size);


typedef struct {
    njt_rbtree_node_t         node;
    njt_str_t                 str;
} njt_str_node_t;


void njt_str_rbtree_insert_value(njt_rbtree_node_t *temp,
    njt_rbtree_node_t *node, njt_rbtree_node_t *sentinel);
njt_str_node_t *njt_str_rbtree_lookup(njt_rbtree_t *rbtree, njt_str_t *name,
    uint32_t hash);


void njt_sort(void *base, size_t n, size_t size,
    njt_int_t (*cmp)(const void *, const void *));
#define njt_qsort             qsort


#define njt_value_helper(n)   #n
#define njt_value(n)          njt_value_helper(n)


#endif /* _NJT_STRING_H_INCLUDED_ */
