/*==============================================================================
 * Created by Yaoyuan on 2019/3/9.
 * Copyright (C) 2019 Yaoyuan <ibireme@gmail.com>.
 *
 * Released under the MIT License:
 * https://github.com/ibireme/yyjson/blob/master/LICENSE
 *============================================================================*/

#ifndef NJT_JSON_H
#define NJT_JSON_H



/*==============================================================================
 * Header Files
 *============================================================================*/

#include <stdlib.h>
#include <stddef.h>
#include <limits.h>
#include <string.h>
#include <float.h>



/*==============================================================================
 * Version
 *============================================================================*/

#define NJT_JSON_VERSION_MAJOR  0
#define NJT_JSON_VERSION_MINOR  4
#define NJT_JSON_VERSION_PATCH  0
#define NJT_JSON_VERSION_HEX    0x000400
#define NJT_JSON_VERSION_STRING "0.4.0"



/*==============================================================================
 * Compile Flags
 *============================================================================*/

/* Define as 1 to disable JSON reader.
   This may reduce binary size if you don't need JSON reader */
#ifndef NJT_JSON_DISABLE_READER
#endif

/* Define as 1 to disable JSON writer.
   This may reduce binary size if you don't need JSON writer */
#ifndef NJT_JSON_DISABLE_WRITER
#endif

/* Define as 1 to disable the fast floating-point number conversion in yyjson,
   and use libc's `strtod/snprintf` instead. This may reduce binary size,
   but slow down floating-point reading and writing speed. */
#ifndef NJT_JSON_DISABLE_FAST_FP_CONV
#endif

/* Define as 1 to disable non-standard JSON support at compile time:
       Reading and writing inf/nan literal, such as 'NaN', '-Infinity'.
       Single line and multiple line comments.
       Single trailing comma at the end of an object or array.
   This may also invalidate these options:
       NJT_JSON_READ_ALLOW_INF_AND_NAN
       NJT_JSON_READ_ALLOW_COMMENTS
       NJT_JSON_READ_ALLOW_TRAILING_COMMAS
       NJT_JSON_WRITE_ALLOW_INF_AND_NAN
   This may reduce binary size, and increase performance slightly. */
#ifndef NJT_JSON_DISABLE_NON_STANDARD
#endif

/* Define as 1 to disable unaligned memory access if target architecture does
   not support unaligned memory access (such as some embedded processors).
   If this value is not defined, yyjson will perform some automatic detection.
   Wrong definition of this flag may cause performance degradation, but will not
   cause runtime errors. */
#ifndef NJT_JSON_DISABLE_UNALIGNED_MEMORY_ACCESS
#endif

/* Define as 1 to export symbols when build library as Windows DLL. */
#ifndef NJT_JSON_EXPORTS
#endif

/* Define as 1 to import symbols when use library as Windows DLL. */
#ifndef NJT_JSON_IMPORTS
#endif

/* Define as 1 to include <stdint.h> for compiler which doesn't support C99. */
#ifndef NJT_JSON_HAS_STDINT_H
#endif

/* Define as 1 to include <stdbool.h> for compiler which doesn't support C99. */
#ifndef NJT_JSON_HAS_STDBOOL_H
#endif



/*==============================================================================
 * Compiler Macros
 *============================================================================*/

/* compiler version check (MSVC) */
#ifdef _MSC_VER
#   define NJT_JSON_MSC_VER _MSC_VER
#else
#   define NJT_JSON_MSC_VER 0
#endif

/* compiler version check (GCC) */
#ifdef __GNUC__
#   define NJT_JSON_GCC_VER __GNUC__
#else
#   define NJT_JSON_GCC_VER 0
#endif

/* C version check */
#if defined(__STDC__) && (__STDC__ >= 1) && defined(__STDC_VERSION__)
#   define NJT_JSON_STDC_VER __STDC_VERSION__
#else
#   define NJT_JSON_STDC_VER 0
#endif

/* C++ version check */
#if defined(__cplusplus)
#   define NJT_JSON_CPP_VER __cplusplus
#else
#   define NJT_JSON_CPP_VER 0
#endif

/* compiler builtin check (since gcc 10.0, clang 2.6, icc 2021) */
#ifndef njt_json_has_builtin
#   ifdef __has_builtin
#       define njt_json_has_builtin(x) __has_builtin(x)
#   else
#       define njt_json_has_builtin(x) 0
#   endif
#endif

/* compiler attribute check (since gcc 5.0, clang 2.9, icc 17) */
#ifndef njt_json_has_attribute
#   ifdef __has_attribute
#       define njt_json_has_attribute(x) __has_attribute(x)
#   else
#       define njt_json_has_attribute(x) 0
#   endif
#endif

/* include check (since gcc 5.0, clang 2.7, icc 16) */
#ifndef njt_json_has_include
#   ifdef __has_include
#       define njt_json_has_include(x) __has_include(x)
#   else
#       define njt_json_has_include(x) 0
#   endif
#endif

/* inline */
#ifndef njt_json_inline
#   if NJT_JSON_MSC_VER >= 1200
#       define njt_json_inline __forceinline
#   elif defined(_MSC_VER)
#       define njt_json_inline __inline
#   elif njt_json_has_attribute(always_inline) || NJT_JSON_GCC_VER >= 4
#       define njt_json_inline __inline__ __attribute__((always_inline))
#   elif defined(__clang__) || defined(__GNUC__)
#       define njt_json_inline __inline__
#   elif defined(__cplusplus) || NJT_JSON_STDC_VER >= 199901L
#       define njt_json_inline inline
#   else
#       define njt_json_inline
#   endif
#endif

/* noinline */
#ifndef njt_json_noinline
#   if NJT_JSON_MSC_VER >= 1400
#       define njt_json_noinline __declspec(noinline)
#   elif njt_json_has_attribute(noinline) || NJT_JSON_GCC_VER >= 4
#       define njt_json_noinline __attribute__((noinline))
#   else
#       define njt_json_noinline
#   endif
#endif

/* align */
#ifndef njt_json_align
#   if NJT_JSON_MSC_VER >= 1300
#       define njt_json_align(x) __declspec(align(x))
#   elif njt_json_has_attribute(aligned) || defined(__GNUC__)
#       define njt_json_align(x) __attribute__((aligned(x)))
#   elif NJT_JSON_CPP_VER >= 201103L
#       define njt_json_align(x) alignas(x)
#   else
#       define njt_json_align(x)
#   endif
#endif

/* likely */
#ifndef njt_json_likely
#   if njt_json_has_builtin(__builtin_expect) || NJT_JSON_GCC_VER >= 4
#       define njt_json_likely(expr) __builtin_expect(!!(expr), 1)
#   else
#       define njt_json_likely(expr) (expr)
#   endif
#endif

/* unlikely */
#ifndef njt_json_unlikely
#   if njt_json_has_builtin(__builtin_expect) || NJT_JSON_GCC_VER >= 4
#       define njt_json_unlikely(expr) __builtin_expect(!!(expr), 0)
#   else
#       define njt_json_unlikely(expr) (expr)
#   endif
#endif

/* function export */
#ifndef njt_json_api
#   if defined(_WIN32)
#       if defined(NJT_JSON_EXPORTS) && NJT_JSON_EXPORTS
#           define njt_json_api __declspec(dllexport)
#       elif defined(NJT_JSON_IMPORTS) && NJT_JSON_IMPORTS
#           define njt_json_api __declspec(dllimport)
#       else
#           define njt_json_api
#       endif
#   elif njt_json_has_attribute(visibility) || NJT_JSON_GCC_VER >= 4
#       define njt_json_api __attribute__((visibility("default")))
#   else
#       define njt_json_api
#   endif
#endif

/* inline function export */
#ifndef njt_json_api_inline
#   define njt_json_api_inline static njt_json_inline
#endif

/* stdint (C89 compatible) */
#if (defined(NJT_JSON_HAS_STDINT_H) && NJT_JSON_HAS_STDINT_H) || \
    NJT_JSON_MSC_VER >= 1600 || NJT_JSON_STDC_VER >= 199901L || \
    defined(_STDINT_H) || defined(_STDINT_H_) || \
    defined(__CLANG_STDINT_H) || defined(_STDINT_H_INCLUDED) || \
    njt_json_has_include(<stdint.h>)
#   include <stdint.h>
#elif defined(_MSC_VER)
#   if _MSC_VER < 1300
typedef signed char         int8_t;
typedef signed short        int16_t;
typedef signed int          int32_t;
typedef unsigned char       uint8_t;
typedef unsigned short      uint16_t;
typedef unsigned int        uint32_t;
typedef signed __int64      int64_t;
typedef unsigned __int64    uint64_t;
#   else
typedef signed __int8       int8_t;
typedef signed __int16      int16_t;
typedef signed __int32      int32_t;
typedef unsigned __int8     uint8_t;
typedef unsigned __int16    uint16_t;
typedef unsigned __int32    uint32_t;
typedef signed __int64      int64_t;
typedef unsigned __int64    uint64_t;
#   endif
#else
#   if UCHAR_MAX == 0xFFU
typedef signed char     int8_t;
typedef unsigned char   uint8_t;
#   else
#       error cannot find 8-bit integer type
#   endif
#   if USHRT_MAX == 0xFFFFU
typedef unsigned short  uint16_t;
typedef signed short    int16_t;
#   elif UINT_MAX == 0xFFFFU
typedef unsigned int    uint16_t;
typedef signed int      int16_t;
#   else
#       error cannot find 16-bit integer type
#   endif
#   if UINT_MAX == 0xFFFFFFFFUL
typedef unsigned int    uint32_t;
typedef signed int      int32_t;
#   elif ULONG_MAX == 0xFFFFFFFFUL
typedef unsigned long   uint32_t;
typedef signed long     int32_t;
#   elif USHRT_MAX == 0xFFFFFFFFUL
typedef unsigned short  uint32_t;
typedef signed short    int32_t;
#   else
#       error cannot find 32-bit integer type
#   endif
#   if defined(__INT64_TYPE__) && defined(__UINT64_TYPE__)
typedef __INT64_TYPE__  int64_t;
typedef __UINT64_TYPE__ uint64_t;
#   elif defined(__GNUC__) || defined(__clang__)
#       if !defined(_SYS_TYPES_H) && !defined(__int8_t_defined)
__extension__ typedef long long             int64_t;
#       endif
__extension__ typedef unsigned long long    uint64_t;
#   elif defined(_LONG_LONG) || defined(__MWERKS__) || defined(_CRAYC) || \
        defined(__SUNPRO_C) || defined(__SUNPRO_CC)
typedef long long           int64_t;
typedef unsigned long long  uint64_t;
#   elif (defined(__BORLANDC__) && __BORLANDC__ > 0x460) || \
        defined(__WATCOM_INT64__) || defined (__alpha) || defined (__DECC)
typedef __int64             int64_t;
typedef unsigned __int64    uint64_t;
#   else
#       error cannot find 64-bit integer type
#   endif
#endif

/* stdbool (C89 compatible) */
#if (defined(NJT_JSON_HAS_STDBOOL_H) && NJT_JSON_HAS_STDBOOL_H) || \
    (njt_json_has_include(<stdbool.h>) && !defined(__STRICT_ANSI__)) || \
    NJT_JSON_MSC_VER >= 1800 || NJT_JSON_STDC_VER >= 199901L
#   include <stdbool.h>
#elif !defined(__bool_true_false_are_defined)
#   define __bool_true_false_are_defined 1
#   if defined(__cplusplus)
#       if defined(__GNUC__) && !defined(__STRICT_ANSI__)
#           define _Bool bool
#           if __cplusplus < 201103L
#               define bool bool
#               define false false
#               define true true
#           endif
#       endif
#   else
#       define bool unsigned char
#       define true 1
#       define false 0
#   endif
#endif

/* char bit check */
#if defined(CHAR_BIT)
#   if CHAR_BIT != 8
#       error non 8-bit char is not supported
#   endif
#endif



/*==============================================================================
 * Compile Hint Begin
 *============================================================================*/

/* extern "C" begin */
#ifdef __cplusplus
extern "C" {
#endif

/* warning suppress begin */
#if defined(__clang__)
#   pragma clang diagnostic push
#   pragma clang diagnostic ignored "-Wunused-function"
#   pragma clang diagnostic ignored "-Wunused-parameter"
#elif defined(__GNUC__)
#   if (__GNUC__ > 4) || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6)
#   pragma GCC diagnostic push
#   endif
#   pragma GCC diagnostic ignored "-Wunused-function"
#   pragma GCC diagnostic ignored "-Wunused-parameter"
#elif defined(_MSC_VER)
#   pragma warning(push)
#   pragma warning(disable:4800) /* 'int': forcing value to 'true' or 'false' */
#endif

/* version, same as NJT_JSON_VERSION_HEX */
njt_json_api uint32_t njt_json_version(void);



/*==============================================================================
 * JSON Types
 *============================================================================*/

/** Type of JSON value (3 bit). */
typedef uint8_t njt_json_type;
#define NJT_JSON_TYPE_NONE        ((uint8_t)0)        /* _____000 */
#define NJT_JSON_TYPE_RAW         ((uint8_t)1)        /* _____001 */
#define NJT_JSON_TYPE_NULL        ((uint8_t)2)        /* _____010 */
#define NJT_JSON_TYPE_BOOL        ((uint8_t)3)        /* _____011 */
#define NJT_JSON_TYPE_NUM         ((uint8_t)4)        /* _____100 */
#define NJT_JSON_TYPE_STR         ((uint8_t)5)        /* _____101 */
#define NJT_JSON_TYPE_ARR         ((uint8_t)6)        /* _____110 */
#define NJT_JSON_TYPE_OBJ         ((uint8_t)7)        /* _____111 */

/** Subtype of JSON value (2 bit). */
typedef uint8_t njt_json_subtype;
#define NJT_JSON_SUBTYPE_NONE     ((uint8_t)(0 << 3)) /* ___00___ */
#define NJT_JSON_SUBTYPE_FALSE    ((uint8_t)(0 << 3)) /* ___00___ */
#define NJT_JSON_SUBTYPE_TRUE     ((uint8_t)(1 << 3)) /* ___01___ */
#define NJT_JSON_SUBTYPE_UINT     ((uint8_t)(0 << 3)) /* ___00___ */
#define NJT_JSON_SUBTYPE_SINT     ((uint8_t)(1 << 3)) /* ___01___ */
#define NJT_JSON_SUBTYPE_REAL     ((uint8_t)(2 << 3)) /* ___10___ */

/** Mask and bits of JSON value. */
#define NJT_JSON_TYPE_MASK        ((uint8_t)0x07)     /* _____111 */
#define NJT_JSON_TYPE_BIT         ((uint8_t)3)
#define NJT_JSON_SUBTYPE_MASK     ((uint8_t)0x18)     /* ___11___ */
#define NJT_JSON_SUBTYPE_BIT      ((uint8_t)2)
#define NJT_JSON_RESERVED_MASK    ((uint8_t)0xE0)     /* 111_____ */
#define NJT_JSON_RESERVED_BIT     ((uint8_t)3)
#define NJT_JSON_TAG_MASK         ((uint8_t)0xFF)     /* 11111111 */
#define NJT_JSON_TAG_BIT          ((uint8_t)8)

/** Padding size for JSON reader. */
#define NJT_JSON_PADDING_SIZE     4



/*==============================================================================
 * Allocator
 *============================================================================*/

/**
 A memory allocator.

 Typically you don't need to use it, unless you want to customize your own
 memory allocator.
 */
typedef struct njt_json_alc {
    /* Same as libc's malloc(), should not be NULL. */
    void *(*malloc)(void *ctx, size_t size);
    /* Same as libc's realloc(), should not be NULL. */
    void *(*realloc)(void *ctx, void *ptr, size_t size);
    /* Same as libc's free(), should not be NULL. */
    void (*free)(void *ctx, void *ptr);
    /* A context for malloc/realloc/free, can be NULL. */
    void *ctx;
} njt_json_alc;

/**
 A pool allocator uses fixed length pre-allocated memory.

 This allocator may used to avoid malloc()/memmove() calls.
 The pre-allocated memory should be held by the caller. This is not
 a general-purpose allocator, and should only be used to read or write
 single JSON document.

 Sample code (parse JSON with stack memory only):

     char buf[65536];
     njt_json_alc alc;
     njt_json_alc_pool_init(&alc, buf, 65536);

     const char *json = "{\"name\":\"Helvetica\",\"size\":14}"
     njt_json_doc *doc = njt_json_read_opts(json, strlen(json), 0, &alc, NULL);

 */
njt_json_api bool njt_json_alc_pool_init(njt_json_alc *alc, void *buf,
        size_t size);



/*==============================================================================
 * JSON Structure
 *============================================================================*/

/** An immutable JSON document. */
typedef struct njt_json_doc njt_json_doc;

/** An immutable JSON value. */
typedef struct njt_json_val njt_json_val;

/** A mutable JSON document. */
typedef struct njt_json_mut_doc njt_json_mut_doc;

/** A mutable JSON value. */
typedef struct njt_json_mut_val njt_json_mut_val;



/*==============================================================================
 * JSON Reader API
 *============================================================================*/

/** Options for JSON reader. */
typedef uint32_t njt_json_read_flag;

/** Default option (RFC 8259 compliant):
    - Read positive integer as uint64_t.
    - Read negative integer as int64_t.
    - Read floating-point number as double with correct rounding.
    - Read integer which cannot fit in uint64_t or int64_t as double.
    - Report error if real number is infinity.
    - Report error if string contains invalid UTF-8 character or BOM.
    - Report error on trailing commas, comments, inf and nan literals. */
static const njt_json_read_flag NJT_JSON_READ_NOFLAG                = 0 << 0;

/** Read the input data in-situ.
    This option allows the reader to modify and use input data to store string
    values, which can increase reading speed slightly.
    The caller should hold the input data before free the document.
    The input data must be padded by at least `NJT_JSON_PADDING_SIZE` byte.
    For example: "[1,2]" should be "[1,2]\0\0\0\0", length should be 5. */
static const njt_json_read_flag NJT_JSON_READ_INSITU                = 1 << 0;

/** Stop when done instead of issues an error if there's additional content
    after a JSON document. This option may used to parse small pieces of JSON
    in larger data, such as NDJSON. */
static const njt_json_read_flag NJT_JSON_READ_STOP_WHEN_DONE        = 1 << 1;

/** Allow single trailing comma at the end of an object or array,
    such as [1,2,3,] {"a":1,"b":2,}. */
static const njt_json_read_flag NJT_JSON_READ_ALLOW_TRAILING_COMMAS = 1 << 2;

/** Allow C-style single line and multiple line comments. */
static const njt_json_read_flag NJT_JSON_READ_ALLOW_COMMENTS        = 1 << 3;

/** Allow inf/nan number and literal, case-insensitive,
    such as 1e999, NaN, inf, -Infinity. */
static const njt_json_read_flag NJT_JSON_READ_ALLOW_INF_AND_NAN     = 1 << 4;

/** Read number as raw string (value with NJT_JSON_TYPE_RAW type),
    inf/nan literal is also read as raw with `ALLOW_INF_AND_NAN` flag. */
static const njt_json_read_flag NJT_JSON_READ_NUMBER_AS_RAW         = 1 << 5;



/** Result code for JSON reader. */
typedef uint32_t njt_json_read_code;

/** Success, no error. */
static const njt_json_read_code NJT_JSON_READ_SUCCESS                       =
    0;

/** Invalid parameter, such as NULL string or invalid file path. */
static const njt_json_read_code NJT_JSON_READ_ERROR_INVALID_PARAMETER       =
    1;

/** Memory allocation failure occurs. */
static const njt_json_read_code NJT_JSON_READ_ERROR_MEMORY_ALLOCATION       =
    2;

/** Input JSON string is empty. */
static const njt_json_read_code NJT_JSON_READ_ERROR_EMPTY_CONTENT           =
    3;

/** Unexpected content after document, such as "[1]#". */
static const njt_json_read_code NJT_JSON_READ_ERROR_UNEXPECTED_CONTENT      =
    4;

/** Unexpected ending, such as "[123". */
static const njt_json_read_code NJT_JSON_READ_ERROR_UNEXPECTED_END          =
    5;

/** Unexpected character inside the document, such as "[#]". */
static const njt_json_read_code NJT_JSON_READ_ERROR_UNEXPECTED_CHARACTER    =
    6;

/** Invalid JSON structure, such as "[1,]". */
static const njt_json_read_code NJT_JSON_READ_ERROR_JSON_STRUCTURE          =
    7;

/** Invalid comment, such as unclosed multi-line comment. */
static const njt_json_read_code NJT_JSON_READ_ERROR_INVALID_COMMENT         =
    8;

/** Invalid number, such as "123.e12", "000". */
static const njt_json_read_code NJT_JSON_READ_ERROR_INVALID_NUMBER          =
    9;

/** Invalid string, such as invalid escaped character inside a string. */
static const njt_json_read_code NJT_JSON_READ_ERROR_INVALID_STRING          =
    10;

/** Invalid JSON literal, such as "truu". */
static const njt_json_read_code NJT_JSON_READ_ERROR_LITERAL                 =
    11;

/** Failed to open a file. */
static const njt_json_read_code NJT_JSON_READ_ERROR_FILE_OPEN               =
    12;

/** Failed to read a file. */
static const njt_json_read_code NJT_JSON_READ_ERROR_FILE_READ               =
    13;

/** Error information for JSON reader. */
typedef struct njt_json_read_err {
    /** Error code, see `njt_json_read_code` for all available values. */
    njt_json_read_code code;
    /** Short error message, constant, no need to free (NULL for success). */
    const char *msg;
    /** Error byte position for input data (0 for success). */
    size_t pos;
} njt_json_read_err;



/**
 Read JSON with options.

 This function is thread-safe if you make sure that:
 1. The `dat` is not modified by other threads.
 2. The `alc` is thread-safe or NULL.

 @param dat The JSON data (UTF-8 without BOM).
            If you pass NULL, you will get NULL result.
            The data will not be modified without the flag `NJT_JSON_READ_INSITU`,
            so you can pass a (const char *) string and case it to (char *) iff
            you don't use the `NJT_JSON_READ_INSITU` flag.

 @param len The JSON data's length.
            If you pass 0, you will get NULL result.

 @param flg The JSON read options.
            You can combine multiple options using bitwise `|` operator.

 @param alc The memory allocator used by JSON reader.
            Pass NULL to use the libc's default allocator (thread-safe).

 @param err A pointer to receive error information.
            Pass NULL if you don't need error information.

 @return    A new JSON document, or NULL if error occurs.
            You should use njt_json_doc_free() to release it
            when it's no longer needed.
 */
njt_json_api njt_json_doc *njt_json_read_opts(char *dat,
        size_t len,
        njt_json_read_flag flg,
        const njt_json_alc *alc,
        njt_json_read_err *err);

/**
 Read a JSON file.

 This function is thread-safe if you make sure that:
 1. The file is not modified by other threads.
 2. The `alc` is thread-safe or NULL.

 @param path The JSON file's path.
             If you pass an invalid path, you will get NULL result.

 @param flg The JSON read options.
            You can combine multiple options using bitwise `|` operator.

 @param alc The memory allocator used by JSON reader.
            Pass NULL to use the libc's default allocator (thread-safe).

 @param err A pointer to receive error information.
            Pass NULL if you don't need error information.

 @return    A new JSON document, or NULL if error occurs.
            You should use njt_json_doc_free() to release it
            when it's no longer needed.
 */
njt_json_api njt_json_doc *njt_json_read_file(const char *path,
        njt_json_read_flag flg,
        const njt_json_alc *alc,
        njt_json_read_err *err);

/**
 Read a JSON string.

 This function is thread-safe.

 @param dat The JSON string (UTF-8 without BOM).
            If you pass NULL, you will get NULL result.

 @param len The JSON data's length.
            If you pass 0, you will get NULL result.

 @param flg The JSON read options.
            You can combine multiple options using bitwise `|` operator.

 @return    A new JSON document, or NULL if error occurs.
            You should use njt_json_doc_free() to release it
            when it's no longer needed.
 */
njt_json_api_inline njt_json_doc *njt_json_read(const char *dat,
        size_t len,
        njt_json_read_flag flg)
{
    flg &= ~NJT_JSON_READ_INSITU; /* const string cannot be modified */
    return njt_json_read_opts((char *)dat, len, flg, NULL, NULL);
}

/**
 Returns the size of maximum memory usage to read a JSON data.
 You may use this value to avoid malloc() or calloc() call inside the reader
 to get better performance, or read multiple JSON.

 Sample code:

     char *dat1, *dat2, *dat3; // JSON data
     size_t len1, len2, len3; // JSON length
     size_t max_len = max(len1, len2, len3);
     njt_json_doc *doc;

     // use one allocator for multiple JSON
     size_t size = njt_json_read_max_memory_usage(max_len, 0);
     void *buf = malloc(size);
     njt_json_alc alc;
     njt_json_alc_pool_init(&alc, buf, size);

     // no more alloc() or realloc() call during reading
     doc = njt_json_read_opts(dat1, len1, 0, &alc, NULL);
     njt_json_doc_free(doc);
     doc = njt_json_read_opts(dat2, len2, 0, &alc, NULL);
     njt_json_doc_free(doc);
     doc = njt_json_read_opts(dat3, len3, 0, &alc, NULL);
     njt_json_doc_free(doc);

     free(buf);

 @param len The JSON data's length.
 @param flg The JSON read options.
 @return The maximum memory size, or 0 if overflow.
 */
njt_json_api_inline size_t njt_json_read_max_memory_usage(size_t len,
        njt_json_read_flag flg)
{
    /*
     1. The max value count is (json_size / 2 + 1),
        for example: "[1,2,3,4]" size is 9, value count is 5.
     2. Some broken JSON may cost more memory during reading, but fail at end,
        for example: "[[[[[[[[".
     3. yyjson use 16 bytes per value, see struct njt_json_val.
     4. yyjson use dynamic memory with a growth factor of 1.5.

     The max memory size is (json_size / 2 * 16 * 1.5 + padding).
     */
    size_t mul = (size_t)12 + !(flg & NJT_JSON_READ_INSITU);
    size_t pad = 256;
    size_t max = (size_t)(~(size_t)0);
    if (flg & NJT_JSON_READ_STOP_WHEN_DONE) len = len < 256 ? 256 : len;
    if (len >= (max - pad - mul) / mul) return 0;
    return len * mul + pad;
}



/*==============================================================================
 * JSON Writer API
 *============================================================================*/

/** Options for JSON writer. */
typedef uint32_t njt_json_write_flag;

/** Default option:
    - Write JSON minify.
    - Report error on inf or nan number.
    - Do not validate string encoding.
    - Do not escape unicode or slash. */
static const njt_json_write_flag NJT_JSON_WRITE_NOFLAG              = 0 << 0;

/** Write JSON pretty with 4 space indent. */
static const njt_json_write_flag NJT_JSON_WRITE_PRETTY              = 1 << 0;

/** Escape unicode as `uXXXX`, make the output ASCII only. */
static const njt_json_write_flag NJT_JSON_WRITE_ESCAPE_UNICODE      = 1 << 1;

/** Escape '/' as '\/'. */
static const njt_json_write_flag NJT_JSON_WRITE_ESCAPE_SLASHES      = 1 << 2;

/** Write inf and nan number as 'Infinity' and 'NaN' literal (non-standard). */
static const njt_json_write_flag NJT_JSON_WRITE_ALLOW_INF_AND_NAN   = 1 << 3;

/** Write inf and nan number as null literal.
    This flag will override `NJT_JSON_WRITE_ALLOW_INF_AND_NAN` flag. */
static const njt_json_write_flag NJT_JSON_WRITE_INF_AND_NAN_AS_NULL = 1 << 4;



/** Result code for JSON writer */
typedef uint32_t njt_json_write_code;

/** Success, no error. */
static const njt_json_write_code NJT_JSON_WRITE_SUCCESS                     =
    0;

/** Invalid parameter, such as NULL document. */
static const njt_json_write_code NJT_JSON_WRITE_ERROR_INVALID_PARAMETER     =
    1;

/** Memory allocation failure occurs. */
static const njt_json_write_code NJT_JSON_WRITE_ERROR_MEMORY_ALLOCATION     =
    2;

/** Invalid value type in JSON document. */
static const njt_json_write_code NJT_JSON_WRITE_ERROR_INVALID_VALUE_TYPE    =
    3;

/** NaN or Infinity number occurs. */
static const njt_json_write_code NJT_JSON_WRITE_ERROR_NAN_OR_INF            =
    4;

/** Failed to open a file. */
static const njt_json_write_code NJT_JSON_WRITE_ERROR_FILE_OPEN             =
    5;

/** Failed to write a file. */
static const njt_json_write_code NJT_JSON_WRITE_ERROR_FILE_WRITE            =
    6;

/** Error information for JSON writer. */
typedef struct njt_json_write_err {
    /** Error code, see njt_json_write_code for all available values. */
    njt_json_write_code code;
    /** Short error message (NULL for success). */
    const char *msg;
} njt_json_write_err;



/**
 Write JSON with options.

 This function is thread-safe if you make sure that:
 1. The `alc` is thread-safe or NULL.

 @param doc The JSON document.
            If you pass NULL, you will get NULL result.

 @param flg The JSON write options.
            You can combine multiple options using bitwise `|` operator.

 @param alc The memory allocator used by JSON writer.
            Pass NULL to use the libc's default allocator (thread-safe).

 @param len A pointer to receive output length in bytes.
            Pass NULL if you don't need length information.

 @param err A pointer to receive error information.
            Pass NULL if you don't need error information.

 @return    A new JSON string, or NULL if error occurs.
            This string is encoded as UTF-8 with a null-terminator.
            You should use free() or alc->free() to release it
            when it's no longer needed.
 */
njt_json_api char *njt_json_write_opts(const njt_json_doc *doc,
                                       njt_json_write_flag flg,
                                       const njt_json_alc *alc,
                                       size_t *len,
                                       njt_json_write_err *err);

/**
 Write JSON file with options.

 This function is thread-safe if you make sure that:
 1. The file is not accessed by other threads.
 2. The `alc` is thread-safe or NULL.

 @param path The JSON file's path.
             If you pass an invalid path, you will get an error.
             If the file is not empty, the content will be discarded.

 @param doc The JSON document.
            If you pass NULL or empty document, you will get an error.

 @param flg The JSON write options.
            You can combine multiple options using bitwise `|` operator.

 @param alc The memory allocator used by JSON writer.
            Pass NULL to use the libc's default allocator (thread-safe).

 @param err A pointer to receive error information.
            Pass NULL if you don't need error information.

 @return    true for success, false for error.
 */
njt_json_api bool njt_json_write_file(const char *path,
                                      const njt_json_doc *doc,
                                      njt_json_write_flag flg,
                                      const njt_json_alc *alc,
                                      njt_json_write_err *err);

/**
 Write JSON.

 This function is thread-safe.

 @param doc The JSON document.
            If you pass NULL, you will get NULL result.

 @param flg The JSON write options.
            You can combine multiple options using bitwise `|` operator.

 @param len A pointer to receive output length in bytes.
            Pass NULL if you don't need length information.

 @return    A new JSON string, or NULL if error occurs.
            This string is encoded as UTF-8 with a null-terminator.
            You should use free() to release it when it's no longer needed.
 */
njt_json_api_inline char *njt_json_write(const njt_json_doc *doc,
        njt_json_write_flag flg,
        size_t *len)
{
    return njt_json_write_opts(doc, flg, NULL, len, NULL);
}



/**
 Write JSON with options.

 This function is thread-safe if you make sure that:
 1. The `doc` is not modified by other threads.
 2. The `alc` is thread-safe or NULL.

 @param doc The mutable JSON document.
            If you pass NULL or empty document, you will get NULL result.

 @param flg The JSON write options.
            You can combine multiple options using bitwise `|` operator.

 @param alc The memory allocator used by JSON writer.
            Pass NULL to use the libc's default allocator (thread-safe).

 @param len A pointer to receive output length in bytes.
            Pass NULL if you don't need length information.

 @param err A pointer to receive error information.
            Pass NULL if you don't need error information.

 @return    A new JSON string, or NULL if error occurs.
            This string is encoded as UTF-8 with a null-terminator.
            You should use free() or alc->free() to release it
            when it's no longer needed.
 */
njt_json_api char *njt_json_mut_write_opts(const njt_json_mut_doc *doc,
        njt_json_write_flag flg,
        const njt_json_alc *alc,
        size_t *len,
        njt_json_write_err *err);

/**
 Write JSON file with options.

 This function is thread-safe if you make sure that:
 1. The file is not accessed by other threads.
 2. The `doc` is not modified by other threads.
 3. The `alc` is thread-safe or NULL.

 @param path The JSON file's path.
             If you pass an invalid path, you will get an error.
             If the file is not empty, the content will be discarded.

 @param doc The mutable JSON document.
            If you pass NULL or empty document, you will get an error.

 @param flg The JSON write options.
            You can combine multiple options using bitwise `|` operator.

 @param alc The memory allocator used by JSON writer.
            Pass NULL to use the libc's default allocator (thread-safe).

 @param err A pointer to receive error information.
            Pass NULL if you don't need error information.

 @return    true for success, false for error.
 */
njt_json_api bool njt_json_mut_write_file(const char *path,
        const njt_json_mut_doc *doc,
        njt_json_write_flag flg,
        const njt_json_alc *alc,
        njt_json_write_err *err);

/**
 Write JSON.

 This function is thread-safe if you make sure that:
 1. The `doc` is not is not modified by other threads.

 @param doc The JSON document.
            If you pass NULL, you will get NULL result.

 @param flg The JSON write options.
            You can combine multiple options using bitwise `|` operator.

 @param len A pointer to receive output length in bytes.
            Pass NULL if you don't need length information.

 @return    A new JSON string, or NULL if error occurs.
            This string is encoded as UTF-8 with a null-terminator.
            You should use free() or alc->free() to release it
            when it's no longer needed.
 */
njt_json_api_inline char *njt_json_mut_write(const njt_json_mut_doc *doc,
        njt_json_write_flag flg,
        size_t *len)
{
    return njt_json_mut_write_opts(doc, flg, NULL, len, NULL);
}



/*==============================================================================
 * JSON Document API
 *============================================================================*/

/** Returns the root value of this JSON document. */
njt_json_api_inline njt_json_val *njt_json_doc_get_root(njt_json_doc *doc);

/** Returns read size of input JSON data. */
njt_json_api_inline size_t njt_json_doc_get_read_size(njt_json_doc *doc);

/** Returns total value count in this JSON document. */
njt_json_api_inline size_t njt_json_doc_get_val_count(njt_json_doc *doc);

/** Release the JSON document and free the memory. */
njt_json_api_inline void njt_json_doc_free(njt_json_doc *doc);



/*==============================================================================
 * JSON Value Type API
 *============================================================================*/

/** Returns whether the JSON value is raw value. */
njt_json_api_inline bool njt_json_is_raw(njt_json_val *val);

/** Returns whether the JSON value is null. */
njt_json_api_inline bool njt_json_is_null(njt_json_val *val);

/** Returns whether the JSON value is true. */
njt_json_api_inline bool njt_json_is_true(njt_json_val *val);

/** Returns whether the JSON value is false. */
njt_json_api_inline bool njt_json_is_false(njt_json_val *val);

/** Returns whether the JSON value is bool (true/false). */
njt_json_api_inline bool njt_json_is_bool(njt_json_val *val);

/** Returns whether the JSON value is unsigned integer (uint64_t). */
njt_json_api_inline bool njt_json_is_uint(njt_json_val *val);

/** Returns whether the JSON value is signed integer (int64_t). */
njt_json_api_inline bool njt_json_is_sint(njt_json_val *val);

/** Returns whether the JSON value is integer (uint64_t/int64_t). */
njt_json_api_inline bool njt_json_is_int(njt_json_val *val);

/** Returns whether the JSON value is real number (double). */
njt_json_api_inline bool njt_json_is_real(njt_json_val *val);

/** Returns whether the JSON value is number (uint64_t/int64_t/double). */
njt_json_api_inline bool njt_json_is_num(njt_json_val *val);

/** Returns whether the JSON value is string. */
njt_json_api_inline bool njt_json_is_str(njt_json_val *val);

/** Returns whether the JSON value is array. */
njt_json_api_inline bool njt_json_is_arr(njt_json_val *val);

/** Returns whether the JSON value is object. */
njt_json_api_inline bool njt_json_is_obj(njt_json_val *val);

/** Returns whether the JSON value is container (array/object). */
njt_json_api_inline bool njt_json_is_ctn(njt_json_val *val);



/*==============================================================================
 * JSON Value Content API
 *============================================================================*/

/** Returns the JSON value's type. */
njt_json_api_inline njt_json_type njt_json_get_type(njt_json_val *val);

/** Returns the JSON value's subtype. */
njt_json_api_inline njt_json_subtype njt_json_get_subtype(njt_json_val *val);

/** Returns the JSON value's tag. */
njt_json_api_inline uint8_t njt_json_get_tag(njt_json_val *val);

/** Returns the JSON value's type description.
    The return description should be one of these strings: "null", "string",
    "array", "object", "true", "false", "uint", "sint", "real", "unknown". */
njt_json_api_inline const char *njt_json_get_type_desc(njt_json_val *val);

/** Returns the content if the value is raw, or NULL on error. */
njt_json_api_inline const char *njt_json_get_raw(njt_json_val *val);

/** Returns the content if the value is bool, or false on error. */
njt_json_api_inline bool njt_json_get_bool(njt_json_val *val);

/** Returns the content if the value is integer, or 0 on error. */
njt_json_api_inline uint64_t njt_json_get_uint(njt_json_val *val);

/** Returns the content if the value is integer, or 0 on error. */
njt_json_api_inline int64_t njt_json_get_sint(njt_json_val *val);

/** Returns the content if the value is integer, or 0 on error. */
njt_json_api_inline int njt_json_get_int(njt_json_val *val);

/** Returns the content if the value is real number, or 0.0 on error. */
njt_json_api_inline double njt_json_get_real(njt_json_val *val);

/** Returns the content if the value is string, or NULL on error. */
njt_json_api_inline const char *njt_json_get_str(njt_json_val *val);

/** Returns the content length (raw length, string length, array size,
    number of object key-value pairs), or 0 on error. */
njt_json_api_inline size_t njt_json_get_len(njt_json_val *val);

/** Returns whether the JSON value is equals to a string. */
njt_json_api_inline bool njt_json_equals_str(njt_json_val *val,
        const char *str);

/** Returns whether the JSON value is equals to a string. */
njt_json_api_inline bool njt_json_equals_strn(njt_json_val *val,
        const char *str,
        size_t len);



/*==============================================================================
 * JSON Array API
 *============================================================================*/

/** Returns the number of elements in this array, or 0 on error. */
njt_json_api_inline size_t njt_json_arr_size(njt_json_val *arr);

/** Returns the element at the specified position in this array,
    or NULL if array is empty or the index is out of bounds.
    @warning This function takes a linear search time if array is not flat. */
njt_json_api_inline njt_json_val *njt_json_arr_get(njt_json_val *arr,
        size_t idx);

/** Returns the first element of this array, or NULL if array is empty. */
njt_json_api_inline njt_json_val *njt_json_arr_get_first(njt_json_val *arr);

/** Returns the last element of this array, or NULL if array is empty.
    @warning This function takes a linear search time if array is not flat. */
njt_json_api_inline njt_json_val *njt_json_arr_get_last(njt_json_val *arr);



/*==============================================================================
 * JSON Array Iterator API
 *============================================================================*/

/**
 A JSON array iterator.

 Sample code:

     njt_json_val *val;
     njt_json_arr_iter iter;
     njt_json_arr_iter_init(arr, &iter);
     while ((val = njt_json_arr_iter_next(&iter))) {
         print(val);
     }
 */
typedef struct njt_json_arr_iter njt_json_arr_iter;

/** Initialize an iterator for this array. */
njt_json_api_inline bool njt_json_arr_iter_init(njt_json_val *arr,
        njt_json_arr_iter *iter);

/** Returns whether the iteration has more elements. */
njt_json_api_inline bool njt_json_arr_iter_has_next(njt_json_arr_iter *iter);

/** Returns the next element in the iteration, or NULL on end. */
njt_json_api_inline njt_json_val *njt_json_arr_iter_next(
    njt_json_arr_iter *iter);

/**
 Macro for iterating over an array.

 Sample code:

     size_t idx, max;
     njt_json_val *val;
     njt_json_arr_foreach(arr, idx, max, val) {
         print(idx, val);
     }
 */
#define njt_json_arr_foreach(arr, idx, max, val) \
    for ((idx) = 0, \
         (max) = njt_json_arr_size(arr), \
         (val) = njt_json_arr_get_first(arr); \
         (idx) < (max); \
         (idx)++, \
         (val) = unsafe_njt_json_get_next(val))



/*==============================================================================
 * JSON Object API
 *============================================================================*/

/** Returns the number of key-value pairs in this object, or 0 on error. */
njt_json_api_inline size_t njt_json_obj_size(njt_json_val *obj);

/** Returns the value to which the specified key is mapped,
    or NULL if this object contains no mapping for the key.
    @warning This function takes a linear search time. */
njt_json_api_inline njt_json_val *njt_json_obj_get(njt_json_val *obj,
        const char *key);

/** Returns the value to which the specified key is mapped,
    or NULL if this object contains no mapping for the key.
    @warning This function takes a linear search time. */
njt_json_api_inline njt_json_val *njt_json_obj_getn(njt_json_val *obj,
        const char *key,
        size_t key_len);



/*==============================================================================
 * JSON Object Iterator API
 *============================================================================*/

/**
 A JSON object iterator.

 Sample code:

     njt_json_val *key, *val;
     njt_json_obj_iter iter;
     njt_json_obj_iter_init(obj, &iter);
     while ((key = njt_json_obj_iter_next(&iter))) {
         val = njt_json_obj_iter_get_val(key);
         print(key, val);
     }
 */
typedef struct njt_json_obj_iter njt_json_obj_iter;

/** Initialize an object iterator. */
njt_json_api_inline bool njt_json_obj_iter_init(njt_json_val *obj,
        njt_json_obj_iter *iter);

/** Returns whether the iteration has more elements. */
njt_json_api_inline bool njt_json_obj_iter_has_next(njt_json_obj_iter *iter);

/** Returns the next key in the iteration, or NULL on end. */
njt_json_api_inline njt_json_val *njt_json_obj_iter_next(
    njt_json_obj_iter *iter);

/** Returns the value for key inside the iteration. */
njt_json_api_inline njt_json_val *njt_json_obj_iter_get_val(njt_json_val *key);

/**
 Iterates to a specified key and returns the value.
 If the key exists in the object, then the iterator will stop at the next key,
 otherwise the iterator will not change and NULL is returned.
 @warning This function takes a linear search time if the key is not nearby.
 */
njt_json_api_inline njt_json_val *njt_json_obj_iter_get(
    njt_json_obj_iter *iter,
    const char *key);

/**
 Iterates to a specified key and returns the value.
 If the key exists in the object, then the iterator will stop at the next key,
 otherwise the iterator will not change and NULL is returned.
 @warning This function takes a linear search time if the key is not nearby.
 */
njt_json_api_inline njt_json_val *njt_json_obj_iter_getn(
    njt_json_obj_iter *iter,
    const char *key,
    size_t key_len);

/**
 Macro for iterating over an object.

 Sample code:

     size_t idx, max;
     njt_json_val *key, *val;
     njt_json_obj_foreach(obj, idx, max, key, val) {
         print(key, val);
     }
 */
#define njt_json_obj_foreach(obj, idx, max, key, val) \
    for ((idx) = 0, \
         (max) = njt_json_obj_size(obj), \
         (key) = (obj) ? unsafe_njt_json_get_first(obj) : NULL, \
         (val) = (key) + 1; \
         (idx) < (max); \
         (idx)++, \
         (key) = unsafe_njt_json_get_next(val), \
         (val) = (key) + 1)



/*==============================================================================
 * Mutable JSON Document API
 *============================================================================*/

/** Returns the root value of this JSON document. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_doc_get_root(
    njt_json_mut_doc *doc);

/** Sets the root value of this JSON document. */
njt_json_api_inline void njt_json_mut_doc_set_root(njt_json_mut_doc *doc,
        njt_json_mut_val *root);

/** Delete the JSON document and free the memory. */
njt_json_api void njt_json_mut_doc_free(njt_json_mut_doc *doc);

/** Creates and returns a new mutable JSON document, returns NULL on error.
    If allocator is NULL, the default allocator will be used. */
njt_json_api njt_json_mut_doc *njt_json_mut_doc_new(const njt_json_alc *alc);

/** Copies and returns a new mutable document from input, returns NULL on error.
    This makes a `deep-copy` on the immutable document.
    If allocator is NULL, the default allocator will be used. */
njt_json_api njt_json_mut_doc *njt_json_doc_mut_copy(njt_json_doc *doc,
        const njt_json_alc *alc);

/** Copies and returns a new mutable document from input, returns NULL on error.
    This makes a `deep-copy` on the mutable document.
    If allocator is NULL, the default allocator will be used. */
njt_json_api njt_json_mut_doc *njt_json_mut_doc_mut_copy(njt_json_mut_doc *doc,
        const njt_json_alc *alc);

/** Copies and returns a new mutable value from input, returns NULL on error.
    This makes a `deep-copy` on the immutable value.
    The memory was managed by mutable document. */
njt_json_api njt_json_mut_val *njt_json_val_mut_copy(njt_json_mut_doc *doc,
        njt_json_val *val);

/** Copies and return a new mutable value from input, returns NULL on error,
    This makes a `deep-copy` on the mutable value.
    The memory was managed by mutable document.
    @warning This function is recursive and may cause a stack overflow
    if the object level is too deep. */
njt_json_api njt_json_mut_val *njt_json_mut_val_mut_copy(njt_json_mut_doc *doc,
        njt_json_mut_val *val);



/*==============================================================================
 * Mutable JSON Value Type API
 *============================================================================*/

/** Returns whether the JSON value is raw. */
njt_json_api_inline bool njt_json_mut_is_raw(njt_json_mut_val *val);

/** Returns whether the JSON value is null. */
njt_json_api_inline bool njt_json_mut_is_null(njt_json_mut_val *val);

/** Returns whether the JSON value is true. */
njt_json_api_inline bool njt_json_mut_is_true(njt_json_mut_val *val);

/** Returns whether the JSON value is false. */
njt_json_api_inline bool njt_json_mut_is_false(njt_json_mut_val *val);

/** Returns whether the JSON value is bool (true/false). */
njt_json_api_inline bool njt_json_mut_is_bool(njt_json_mut_val *val);

/** Returns whether the JSON value is unsigned integer (uint64_t). */
njt_json_api_inline bool njt_json_mut_is_uint(njt_json_mut_val *val);

/** Returns whether the JSON value is signed integer (int64_t). */
njt_json_api_inline bool njt_json_mut_is_sint(njt_json_mut_val *val);

/** Returns whether the JSON value is integer (uint64_t/int64_t). */
njt_json_api_inline bool njt_json_mut_is_int(njt_json_mut_val *val);

/** Returns whether the JSON value is real number (double). */
njt_json_api_inline bool njt_json_mut_is_real(njt_json_mut_val *val);

/** Returns whether the JSON value is number (uint/sint/real). */
njt_json_api_inline bool njt_json_mut_is_num(njt_json_mut_val *val);

/** Returns whether the JSON value is string. */
njt_json_api_inline bool njt_json_mut_is_str(njt_json_mut_val *val);

/** Returns whether the JSON value is array. */
njt_json_api_inline bool njt_json_mut_is_arr(njt_json_mut_val *val);

/** Returns whether the JSON value is object. */
njt_json_api_inline bool njt_json_mut_is_obj(njt_json_mut_val *val);

/** Returns whether the JSON value is container (array/object). */
njt_json_api_inline bool njt_json_mut_is_ctn(njt_json_mut_val *val);



/*==============================================================================
 * Mutable JSON Value Content API
 *============================================================================*/

/** Returns the JSON value's type. */
njt_json_api_inline njt_json_type njt_json_mut_get_type(njt_json_mut_val *val);

/** Returns the JSON value's subtype. */
njt_json_api_inline njt_json_subtype njt_json_mut_get_subtype(
    njt_json_mut_val *val);

/** Returns the JSON value's tag. */
njt_json_api_inline uint8_t njt_json_mut_get_tag(njt_json_mut_val *val);

/** Returns the JSON value's type description.
    The return description should be one of these strings: "null", "string",
    "array", "object", "true", "false", "uint", "sint", "real", "unknown". */
njt_json_api_inline const char *njt_json_mut_get_type_desc(
    njt_json_mut_val *val);

/** Returns whether two JSON values are equal (deep compare).
    @warning This function takes a quadratic time. */
njt_json_api bool njt_json_mut_equals(njt_json_mut_val *lhs,
                                      njt_json_mut_val *rhs);

/** Returns the content if the value is raw, or NULL on error. */
njt_json_api_inline const char *njt_json_mut_get_raw(njt_json_mut_val *val);

/** Returns the content if the value is bool, or false on error. */
njt_json_api_inline bool njt_json_mut_get_bool(njt_json_mut_val *val);

/** Returns the content if the value is integer, or 0 on error. */
njt_json_api_inline uint64_t njt_json_mut_get_uint(njt_json_mut_val *val);

/** Returns the content if the value is integer, or 0 on error. */
njt_json_api_inline int64_t njt_json_mut_get_sint(njt_json_mut_val *val);

/** Returns the content if the value is integer, or 0 on error. */
njt_json_api_inline int njt_json_mut_get_int(njt_json_mut_val *val);

/** Returns the content if the value is real number, or 0.0 on error. */
njt_json_api_inline double njt_json_mut_get_real(njt_json_mut_val *val);

/** Returns the content if the value is string, or NULL on error. */
njt_json_api_inline const char *njt_json_mut_get_str(njt_json_mut_val *val);

/** Returns the content length (raw length, string length, array size,
    number of object key-value pairs), or 0 on error. */
njt_json_api_inline size_t njt_json_mut_get_len(njt_json_mut_val *val);

/** Returns whether the JSON value is equals to a string. */
njt_json_api_inline bool njt_json_mut_equals_str(njt_json_mut_val *val,
        const char *str);

/** Returns whether the JSON value is equals to a string. */
njt_json_api_inline bool njt_json_mut_equals_strn(njt_json_mut_val *val,
        const char *str, size_t len);



/*==============================================================================
 * Mutable JSON Value Creation API
 *============================================================================*/

/** Creates and returns a raw value, returns NULL on error.
    The input value should be a valid UTF-8 encoded string.
    The input string is copied and held by the document. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_raw(njt_json_mut_doc *doc,
        const char *str,
        size_t len);

/** Creates and returns a null value, returns NULL on error. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_null(njt_json_mut_doc *doc);

/** Creates and returns a true value, returns NULL on error. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_true(njt_json_mut_doc *doc);

/** Creates and returns a false value, returns NULL on error. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_false(
    njt_json_mut_doc *doc);

/** Creates and returns a bool value, returns NULL on error. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_bool(njt_json_mut_doc *doc,
        bool val);

/** Creates and returns an unsigned integer value, returns NULL on error. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_uint(njt_json_mut_doc *doc,
        uint64_t num);

/** Creates and returns a signed integer value, returns NULL on error. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_sint(njt_json_mut_doc *doc,
        int64_t num);

/** Creates and returns a signed integer value, returns NULL on error. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_int(njt_json_mut_doc *doc,
        int64_t num);

/** Creates and returns an real number value, returns NULL on error. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_real(njt_json_mut_doc *doc,
        double num);

/** Creates and returns a string value, returns NULL on error.
    The input value should be a valid UTF-8 encoded string with null-terminator.
    @warning The input string is not copied, you should keep this string
    unmodified for the lifetime of this document. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_str(njt_json_mut_doc *doc,
        const char *str);

/** Creates and returns a string value, returns NULL on error.
    The input value should be a valid UTF-8 encoded string.
    @warning The input string is not copied, you should keep this string
    unmodified for the lifetime of this document. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_strn(njt_json_mut_doc *doc,
        const char *str,
        size_t len);

/** Creates and returns a string value, returns NULL on error.
    The input value should be a valid UTF-8 encoded string with null-terminator.
    The input string is copied and held by the document. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_strcpy(
    njt_json_mut_doc *doc,
    const char *str);

/** Creates and returns a string value, returns NULL on error.
    The input value should be a valid UTF-8 encoded string.
    The input string is copied and held by the document. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_strncpy(
    njt_json_mut_doc *doc,
    const char *str,
    size_t len);



/*==============================================================================
 * Mutable JSON Array API
 *============================================================================*/

/** Returns the number of elements in this array. */
njt_json_api_inline size_t njt_json_mut_arr_size(njt_json_mut_val *arr);

/** Returns the element at the specified position in this array,
    or NULL if array is empty or the index is out of bounds.
    @warning This function takes a linear search time. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_get(
    njt_json_mut_val *arr,
    size_t idx);

/** Returns the first element of this array, or NULL if array is empty. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_get_first(
    njt_json_mut_val *arr);

/** Returns the last element of this array, or NULL if array is empty. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_get_last(
    njt_json_mut_val *arr);



/*==============================================================================
 * Mutable JSON Array Iterator API
 *============================================================================*/

/**
 A mutable JSON array iterator.

 Sample code:

     njt_json_mut_val *val;
     njt_json_mut_arr_iter iter;
     njt_json_mut_arr_iter_init(arr, &iter);
     while ((val = njt_json_mut_arr_iter_next(&iter))) {
         print(val);
         if (val_is_unused(val)) {
             njt_json_mut_arr_iter_remove(&iter);
         }
     }

 @warning You should not modify the array while enumerating through it,
          but you can use njt_json_mut_arr_iter_remove() to remove current value.
 */
typedef struct njt_json_mut_arr_iter njt_json_mut_arr_iter;

/** Initialize an iterator for this array. */
njt_json_api_inline bool njt_json_mut_arr_iter_init(njt_json_mut_val *arr,
        njt_json_mut_arr_iter *iter);

/** Returns whether the iteration has more elements. */
njt_json_api_inline bool njt_json_mut_arr_iter_has_next(
    njt_json_mut_arr_iter *iter);

/** Returns the next element in the iteration, or NULL on end. */
njt_json_api_inline
njt_json_mut_val *njt_json_mut_arr_iter_next(njt_json_mut_arr_iter *iter);

/** Removes and returns current element in the iteration. */
njt_json_api_inline
njt_json_mut_val *njt_json_mut_arr_iter_remove(njt_json_mut_arr_iter *iter);

/**
 Macro for iterating over an array.

 Sample code:

     size_t idx, max;
     njt_json_mut_val *val;
     njt_json_mut_arr_foreach(arr, idx, max, val) {
         print(idx, val);
     }

 @warning You should not modify the array while enumerating through it.
 */
#define njt_json_mut_arr_foreach(arr, idx, max, val) \
    for ((idx) = 0, \
         (max) = njt_json_mut_arr_size(arr), \
         (val) = njt_json_mut_arr_get_first(arr); \
         (idx) < (max); \
         (idx)++, \
         (val) = (val)->next)



/*==============================================================================
 * Mutable JSON Array Creation API
 *============================================================================*/

/** Creates and returns a mutable array, returns NULL on error. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_arr(njt_json_mut_doc *doc);

/** Creates and returns a mutable array with bool. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_with_bool(
    njt_json_mut_doc *doc, const bool *vals, size_t count);

/** Creates and returns a mutable array with sint numbers. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_with_sint(
    njt_json_mut_doc *doc, const int64_t *vals, size_t count);

/** Creates and returns a mutable array with uint numbers. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_with_uint(
    njt_json_mut_doc *doc, const uint64_t *vals, size_t count);

/** Creates and returns a mutable array with real numbers. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_with_real(
    njt_json_mut_doc *doc, const double *vals, size_t count);

/** Creates and returns a mutable array with int8 numbers. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_with_sint8(
    njt_json_mut_doc *doc, const int8_t *vals, size_t count);

/** Creates and returns a mutable array with int16 numbers. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_with_sint16(
    njt_json_mut_doc *doc, const int16_t *vals, size_t count);

/** Creates and returns a mutable array with int32 numbers. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_with_sint32(
    njt_json_mut_doc *doc, const int32_t *vals, size_t count);

/** Creates and returns a mutable array with int64 numbers. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_with_sint64(
    njt_json_mut_doc *doc, const int64_t *vals, size_t count);

/** Creates and returns a mutable array with uint8 numbers. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_with_uint8(
    njt_json_mut_doc *doc, const uint8_t *vals, size_t count);

/** Creates and returns a mutable array with uint16 numbers. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_with_uint16(
    njt_json_mut_doc *doc, const uint16_t *vals, size_t count);

/** Creates and returns a mutable array with uint32 numbers. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_with_uint32(
    njt_json_mut_doc *doc, const uint32_t *vals, size_t count);

/** Creates and returns a mutable array with uint64 numbers. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_with_uint64(
    njt_json_mut_doc *doc, const uint64_t *vals, size_t count);

/** Creates and returns a mutable array with float numbers. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_with_float(
    njt_json_mut_doc *doc, const float *vals, size_t count);

/** Creates and returns a mutable array with double numbers. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_with_double(
    njt_json_mut_doc *doc, const double *vals, size_t count);

/** Creates and returns a mutable array with strings (no copy).
    The strings should be encoded as UTF-8 with null-terminator. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_with_str(
    njt_json_mut_doc *doc, const char **vals, size_t count);

/** Creates and returns a mutable array with strings (no copy).
    The strings should be encoded as UTF-8. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_with_strn(
    njt_json_mut_doc *doc, const char **vals, const size_t *lens, size_t count);

/** Creates and returns a mutable array with strings (copied).
    The strings should be encoded as UTF-8 with null-terminator. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_with_strcpy(
    njt_json_mut_doc *doc, const char **vals, size_t count);

/** Creates and returns a mutable array with strings (copied).
    The strings should be encoded as UTF-8. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_with_strncpy(
    njt_json_mut_doc *doc, const char **vals, const size_t *lens, size_t count);



/*==============================================================================
 * Mutable JSON Array Modification API
 *============================================================================*/

/** Inserts a value into an array at a given index, returns false on error.
    @warning This function takes a linear search time. */
njt_json_api_inline bool njt_json_mut_arr_insert(njt_json_mut_val *arr,
        njt_json_mut_val *val, size_t idx);

/** Inserts a val at the end of the array, returns false on error. */
njt_json_api_inline bool njt_json_mut_arr_append(njt_json_mut_val *arr,
        njt_json_mut_val *val);

/** Inserts a val at the head of the array, returns false on error. */
njt_json_api_inline bool njt_json_mut_arr_prepend(njt_json_mut_val *arr,
        njt_json_mut_val *val);

/** Replaces a value at index and returns old value, returns NULL on error.
    @warning This function takes a linear search time. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_replace(
    njt_json_mut_val *arr,
    size_t idx,
    njt_json_mut_val *val);

/** Removes and returns a value at index, returns NULL on error.
    @warning This function takes a linear search time. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_remove(
    njt_json_mut_val *arr,
    size_t idx);

/** Removes and returns the first value in this array, returns NULL on error. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_remove_first(
    njt_json_mut_val *arr);

/** Removes and returns the last value in this array, returns NULL on error. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_remove_last(
    njt_json_mut_val *arr);

/** Removes all values within a specified range in the array.
    @warning This function takes a linear search time. */
njt_json_api_inline bool njt_json_mut_arr_remove_range(njt_json_mut_val *arr,
        size_t idx, size_t len);

/** Removes all values in this array. */
njt_json_api_inline bool njt_json_mut_arr_clear(njt_json_mut_val *arr);

/** Rotates values in this array for the given number of times.
    @warning This function takes a linear search time. */
njt_json_api_inline bool njt_json_mut_arr_rotate(njt_json_mut_val *arr,
        size_t idx);



/*==============================================================================
 * Mutable JSON Array Modification Convenience API
 *============================================================================*/

/** Adds a value at the end of the array. */
njt_json_api_inline bool njt_json_mut_arr_add_val(njt_json_mut_val *arr,
        njt_json_mut_val *val);

/** Adds a null val at the end of the array. */
njt_json_api_inline bool njt_json_mut_arr_add_null(njt_json_mut_doc *doc,
        njt_json_mut_val *arr);

/** Adds a true val at the end of the array. */
njt_json_api_inline bool njt_json_mut_arr_add_true(njt_json_mut_doc *doc,
        njt_json_mut_val *arr);

/** Adds a false val at the end of the array. */
njt_json_api_inline bool njt_json_mut_arr_add_false(njt_json_mut_doc *doc,
        njt_json_mut_val *arr);

/** Adds a bool val at the end of the array. */
njt_json_api_inline bool njt_json_mut_arr_add_bool(njt_json_mut_doc *doc,
        njt_json_mut_val *arr,
        bool val);

/** Adds a uint val at the end of the array. */
njt_json_api_inline bool njt_json_mut_arr_add_uint(njt_json_mut_doc *doc,
        njt_json_mut_val *arr,
        uint64_t num);

/** Adds a sint val at the end of the array. */
njt_json_api_inline bool njt_json_mut_arr_add_sint(njt_json_mut_doc *doc,
        njt_json_mut_val *arr,
        int64_t num);

/** Adds an int val at the end of the array. */
njt_json_api_inline bool njt_json_mut_arr_add_int(njt_json_mut_doc *doc,
        njt_json_mut_val *arr,
        int64_t num);

/** Adds a double val at the end of the array. */
njt_json_api_inline bool njt_json_mut_arr_add_real(njt_json_mut_doc *doc,
        njt_json_mut_val *arr,
        double num);

/** Adds a string val at the end of the array (no copy).
    The string should be encoded as UTF-8 with null-terminator. */
njt_json_api_inline bool njt_json_mut_arr_add_str(njt_json_mut_doc *doc,
        njt_json_mut_val *arr,
        const char *str);

/** Adds a string val at the end of the array (no copy).
    The strings should be encoded as UTF-8. */
njt_json_api_inline bool njt_json_mut_arr_add_strn(njt_json_mut_doc *doc,
        njt_json_mut_val *arr,
        const char *str,
        size_t len);

/** Adds a string val at the end of the array (copied).
    The strings should be encoded as UTF-8 with null-terminator. */
njt_json_api_inline bool njt_json_mut_arr_add_strcpy(njt_json_mut_doc *doc,
        njt_json_mut_val *arr,
        const char *str);

/** Adds a string val at the end of the array (copied).
    The strings should be encoded as UTF-8. */
njt_json_api_inline bool njt_json_mut_arr_add_strncpy(njt_json_mut_doc *doc,
        njt_json_mut_val *arr,
        const char *str,
        size_t len);

/** Creates and adds a new array at the end of the array.
    Returns the new array, or NULL on error. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_add_arr(
    njt_json_mut_doc *doc,
    njt_json_mut_val *arr);

/** Creates and adds a new object at the end of the array.
    Returns the new object, or NULL on error. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_add_obj(
    njt_json_mut_doc *doc,
    njt_json_mut_val *arr);



/*==============================================================================
 * Mutable JSON Object API
 *============================================================================*/

/** Returns the number of key-value pair in this object. */
njt_json_api_inline size_t njt_json_mut_obj_size(njt_json_mut_val *obj);

/** Returns the value to which the specified key is mapped,
    or NULL if this object contains no mapping for the key.
    @warning This function takes a linear search time. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_obj_get(
    njt_json_mut_val *obj,
    const char *key_str);

/** Returns the value to which the specified key is mapped,
    or NULL if this object contains no mapping for the key.
    @warning This function takes a linear search time. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_obj_getn(
    njt_json_mut_val *obj,
    const char *key_str,
    size_t key_len);



/*==============================================================================
 * Mutable JSON Object Iterator API
 *============================================================================*/

/**
 A mutable JSON object iterator.

 Sample code:

     njt_json_mut_val *key, *val;
     njt_json_mut_obj_iter iter;
     njt_json_mut_obj_iter_init(obj, &iter);
     while ((key = njt_json_mut_obj_iter_next(&iter))) {
         val = njt_json_mut_obj_iter_get_val(key);
         print(key, val);
         if (key_is_unused(key)) {
             njt_json_mut_obj_iter_remove(&iter);
         }
     }

 @warning You should not modify the object while enumerating through it,
          but you can use njt_json_mut_obj_iter_remove() to remove current value.
 */
typedef struct njt_json_mut_obj_iter njt_json_mut_obj_iter;

/** Initialize an object iterator. */
njt_json_api_inline bool njt_json_mut_obj_iter_init(njt_json_mut_val *obj,
        njt_json_mut_obj_iter *iter);

/** Returns whether the iteration has more elements. */
njt_json_api_inline bool njt_json_mut_obj_iter_has_next(
    njt_json_mut_obj_iter *iter);

/** Returns the next key in the iteration, or NULL on end. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_obj_iter_next(
    njt_json_mut_obj_iter *iter);

/** Returns the value for key inside the iteration. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_obj_iter_get_val(
    njt_json_mut_val *key);

/** Removes and returns current key in the iteration, the value can be
    accessed by key->next. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_obj_iter_remove(
    njt_json_mut_obj_iter *iter);

/**
 Iterates to a specified key and returns the value.
 If the key exists in the object, then the iterator will stop at the next key,
 otherwise the iterator will not change and NULL is returned.
 @warning This function takes a linear search time if the key is not nearby.
 */
njt_json_api_inline njt_json_mut_val *njt_json_mut_obj_iter_get(
    njt_json_mut_obj_iter *iter,
    const char *key);

/**
 Iterates to a specified key and returns the value.
 If the key exists in the object, then the iterator will stop at the next key,
 otherwise the iterator will not change and NULL is returned.
 @warning This function takes a linear search time if the key is not nearby.
 */
njt_json_api_inline njt_json_mut_val *njt_json_mut_obj_iter_getn(
    njt_json_mut_obj_iter *iter,
    const char *key,
    size_t key_len);

/**
 Macro for iterating over an object.

 Sample code:

     size_t idx, max;
     njt_json_val *key, *val;
     njt_json_obj_foreach(obj, idx, max, key, val) {
         print(key, val);
     }

 @warning You should not modify the object while enumerating through it.
 */
#define njt_json_mut_obj_foreach(obj, idx, max, key, val) \
    for ((idx) = 0, \
         (max) = njt_json_mut_obj_size(obj), \
         (key) = (max) ? ((njt_json_mut_val *)(obj)->uni.ptr)->next->next : NULL, \
         (val) = (key) ? (key)->next : NULL; \
         (idx) < (max); \
         (idx)++, \
         (key) = (val)->next, \
         (val) = (key)->next)



/*==============================================================================
 * Mutable JSON Object Creation API
 *============================================================================*/

/** Creates and returns a mutable object, returns NULL on error. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_obj(njt_json_mut_doc *doc);

/** Creates and returns a mutable object with keys and values,
    returns NULL on error. The keys and values are not copied.
    The strings should be encoded as UTF-8 with null-terminator. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_obj_with_str(
    njt_json_mut_doc *doc,
    const char **keys,
    const char **vals,
    size_t count);

/** Creates and returns a mutable object with key-value pairs and pair count,
    returns NULL on error. The keys and values are not copied.
    The strings should be encoded as UTF-8 with null-terminator. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_obj_with_kv(
    njt_json_mut_doc *doc,
    const char **kv_pairs,
    size_t pair_count);



/*==============================================================================
 * Mutable JSON Object Modification API
 *============================================================================*/

/** Adds a key-value pair at the end of the object. The key must be a string.
    This function allows duplicated key in one object. */
njt_json_api_inline bool njt_json_mut_obj_add(njt_json_mut_val *obj,
        njt_json_mut_val *key,
        njt_json_mut_val *val);

/** Adds a key-value pair to the object. The key must be a string.
    This function may remove all key-value pairs for the given key before add.
    @warning This function takes a linear search time. */
njt_json_api_inline bool njt_json_mut_obj_put(njt_json_mut_val *obj,
        njt_json_mut_val *key,
        njt_json_mut_val *val);

/** Inserts a key-value pair to the object at the given position.
    The key must be a string. This function allows duplicated key in one object.
    @warning This function takes a linear search time. */
njt_json_api_inline bool njt_json_mut_obj_insert(njt_json_mut_val *obj,
        njt_json_mut_val *key,
        njt_json_mut_val *val,
        size_t idx);

/** Removes all key-value pair from the object with given key,
    and return the first match one.
    @warning This function takes a linear search time. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_obj_remove(
    njt_json_mut_val *obj,
    njt_json_mut_val *key);

/** Removes all key-value pairs in this object. */
njt_json_api_inline bool njt_json_mut_obj_clear(njt_json_mut_val *obj);

/** Replaces value from the object with given key.
    @warning This function takes a linear search time. */
njt_json_api_inline bool njt_json_mut_obj_replace(njt_json_mut_val *obj,
        njt_json_mut_val *key,
        njt_json_mut_val *val);

/** Rotates key-value pairs in the object for the given number of times.
    @warning This function takes a linear search time. */
njt_json_api_inline bool njt_json_mut_obj_rotate(njt_json_mut_val *obj,
        size_t idx);



/*==============================================================================
 * Mutable JSON Object Modification Convenience API
 *============================================================================*/

/** Adds a null value at the end of the object. The key is not copied.
    This function allows duplicated key in one object. */
njt_json_api_inline bool njt_json_mut_obj_add_null(njt_json_mut_doc *doc,
        njt_json_mut_val *obj,
        const char *key);

/** Adds a true value at the end of the object. The key is not copied.
    This function allows duplicated key in one object. */
njt_json_api_inline bool njt_json_mut_obj_add_true(njt_json_mut_doc *doc,
        njt_json_mut_val *obj,
        const char *key);

/** Adds a false value at the end of the object. The key is not copied.
    This function allows duplicated key in one object. */
njt_json_api_inline bool njt_json_mut_obj_add_false(njt_json_mut_doc *doc,
        njt_json_mut_val *obj,
        const char *key);

/** Adds a bool value at the end of the object. The key is not copied.
    This function allows duplicated key in one object. */
njt_json_api_inline bool njt_json_mut_obj_add_bool(njt_json_mut_doc *doc,
        njt_json_mut_val *obj,
        const char *key, bool val);

/** Adds a uint value at the end of the object. The key is not copied.
    This function allows duplicated key in one object. */
njt_json_api_inline bool njt_json_mut_obj_add_uint(njt_json_mut_doc *doc,
        njt_json_mut_val *obj,
        const char *key, uint64_t val);

/** Adds a sint value at the end of the object. The key is not copied.
    This function allows duplicated key in one object. */
njt_json_api_inline bool njt_json_mut_obj_add_sint(njt_json_mut_doc *doc,
        njt_json_mut_val *obj,
        const char *key, int64_t val);

/** Adds an int value at the end of the object. The key is not copied.
    This function allows duplicated key in one object. */
njt_json_api_inline bool njt_json_mut_obj_add_int(njt_json_mut_doc *doc,
        njt_json_mut_val *obj,
        const char *key, int64_t val);

/** Adds a double value at the end of the object. The key is not copied.
    This function allows duplicated key in one object. */
njt_json_api_inline bool njt_json_mut_obj_add_real(njt_json_mut_doc *doc,
        njt_json_mut_val *obj,
        const char *key, double val);

/** Adds a string value at the end of the object. The key/value is not copied.
    This function allows duplicated key in one object. */
njt_json_api_inline bool njt_json_mut_obj_add_str(njt_json_mut_doc *doc,
        njt_json_mut_val *obj,
        const char *key, const char *val);

/** Adds a string value at the end of the object.
    The key and value are not copied.
    This function allows duplicated key in one object. */
njt_json_api_inline bool njt_json_mut_obj_add_strn(njt_json_mut_doc *doc,
        njt_json_mut_val *obj,
        const char *key,
        const char *val, size_t len);

/** Adds a string value at the end of the object.
    The key is not copied, but the value is copied.
    This function allows duplicated key in one object. */
njt_json_api_inline bool njt_json_mut_obj_add_strcpy(njt_json_mut_doc *doc,
        njt_json_mut_val *obj,
        const char *key,
        const char *val);

/** Adds a string value at the end of the object.
    The key is not copied, but the value is copied.
    This function allows duplicated key in one object. */
njt_json_api_inline bool njt_json_mut_obj_add_strncpy(njt_json_mut_doc *doc,
        njt_json_mut_val *obj,
        const char *key,
        const char *val, size_t len);

/** Removes all key-value pairs for the given key,
    and return the first match one.
    @warning This function takes a linear search time. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_obj_remove_str(
    njt_json_mut_val *obj,
    const char *key);

/** Removes all key-value pairs for the given key,
    and return the first match one.
    @warning This function takes a linear search time. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_obj_remove_strn(
    njt_json_mut_val *obj,
    const char *key, size_t len);



/*==============================================================================
 * JSON Pointer API
 *============================================================================*/

/** Get a JSON value with JSON Pointer: https://tools.ietf.org/html/rfc6901
    For example: "/users/0/uid".
    Returns NULL if there's no matched value. */
njt_json_api_inline njt_json_val *njt_json_get_pointer(njt_json_val *val,
        const char *pointer);

/** Get a JSON value with JSON Pointer: https://tools.ietf.org/html/rfc6901
    For example: "/users/0/uid".
    Returns NULL if there's no matched value. */
njt_json_api_inline njt_json_val *njt_json_doc_get_pointer(njt_json_doc *doc,
        const char *pointer);

/** Get a JSON value with JSON Pointer: https://tools.ietf.org/html/rfc6901
    For example: "/users/0/uid".
    Returns NULL if there's no matched value. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_get_pointer(
    njt_json_mut_val *val,
    const char *pointer);

/** Get a JSON value with JSON Pointer: https://tools.ietf.org/html/rfc6901
    For example: "/users/0/uid".
    Returns NULL if there's no matched value. */
njt_json_api_inline njt_json_mut_val *njt_json_mut_doc_get_pointer(
    njt_json_mut_doc *doc, const char *pointer);



/*==============================================================================
 * JSON Merge-Patch API
 *============================================================================*/

/** Creates and returns a merge-patched JSON value:
    https://tools.ietf.org/html/rfc7386
    Returns NULL if the patch could not be applied. */
njt_json_api njt_json_mut_val *njt_json_merge_patch(njt_json_mut_doc *doc,
        njt_json_val *orig,
        njt_json_val *patch);



/*==============================================================================
 * JSON Structure (Implementation)
 *============================================================================*/

/* Payload of a JSON value (8 bytes). */
typedef union njt_json_val_uni {
    uint64_t    u64;
    int64_t     i64;
    double      f64;
    const char *str;
    void       *ptr;
    size_t      ofs;
} njt_json_val_uni;

/* An immutable JSON value (16 bytes). */
struct njt_json_val {
    uint64_t tag;
    njt_json_val_uni uni;
};

/* An immutable JSON Document. */
struct njt_json_doc {
    /* Root value of the document (nonnull). */
    njt_json_val *root;
    /* Allocator used by document (nonnull). */
    njt_json_alc alc;
    /* The total number of bytes read when parsing JSON (nonzero). */
    size_t dat_read;
    /* The total number of value read when parsing JSON (nonzero). */
    size_t val_read;
    /* The string pool used by JSON values (nullable). */
    char *str_pool;
};



/*==============================================================================
 * Unsafe JSON Value API (Implementation)
 *============================================================================*/

njt_json_api_inline njt_json_type unsafe_njt_json_get_type(void *val)
{
    uint8_t tag = (uint8_t)((njt_json_val *)val)->tag;
    return (njt_json_type)(tag & NJT_JSON_TYPE_MASK);
}

njt_json_api_inline njt_json_subtype unsafe_njt_json_get_subtype(void *val)
{
    uint8_t tag = (uint8_t)((njt_json_val *)val)->tag;
    return (njt_json_subtype)(tag & NJT_JSON_SUBTYPE_MASK);
}

njt_json_api_inline uint8_t unsafe_njt_json_get_tag(void *val)
{
    uint8_t tag = (uint8_t)((njt_json_val *)val)->tag;
    return (uint8_t)(tag & NJT_JSON_TAG_MASK);
}

njt_json_api_inline bool unsafe_njt_json_is_raw(void *val)
{
    return unsafe_njt_json_get_type(val) == NJT_JSON_TYPE_RAW;
}

njt_json_api_inline bool unsafe_njt_json_is_null(void *val)
{
    return unsafe_njt_json_get_type(val) == NJT_JSON_TYPE_NULL;
}

njt_json_api_inline bool unsafe_njt_json_is_bool(void *val)
{
    return unsafe_njt_json_get_type(val) == NJT_JSON_TYPE_BOOL;
}

njt_json_api_inline bool unsafe_njt_json_is_num(void *val)
{
    return unsafe_njt_json_get_type(val) == NJT_JSON_TYPE_NUM;
}

njt_json_api_inline bool unsafe_njt_json_is_str(void *val)
{
    return unsafe_njt_json_get_type(val) == NJT_JSON_TYPE_STR;
}

njt_json_api_inline bool unsafe_njt_json_is_arr(void *val)
{
    return unsafe_njt_json_get_type(val) == NJT_JSON_TYPE_ARR;
}

njt_json_api_inline bool unsafe_njt_json_is_obj(void *val)
{
    return unsafe_njt_json_get_type(val) == NJT_JSON_TYPE_OBJ;
}

njt_json_api_inline bool unsafe_njt_json_is_ctn(void *val)
{
    uint8_t mask = NJT_JSON_TYPE_ARR & NJT_JSON_TYPE_OBJ;
    return (unsafe_njt_json_get_tag(val) & mask) == mask;
}

njt_json_api_inline bool unsafe_njt_json_is_uint(void *val)
{
    const uint8_t patt = NJT_JSON_TYPE_NUM | NJT_JSON_SUBTYPE_UINT;
    return unsafe_njt_json_get_tag(val) == patt;
}

njt_json_api_inline bool unsafe_njt_json_is_sint(void *val)
{
    const uint8_t patt = NJT_JSON_TYPE_NUM | NJT_JSON_SUBTYPE_SINT;
    return unsafe_njt_json_get_tag(val) == patt;
}

njt_json_api_inline bool unsafe_njt_json_is_int(void *val)
{
    const uint8_t mask = NJT_JSON_TAG_MASK & (~NJT_JSON_SUBTYPE_SINT);
    const uint8_t patt = NJT_JSON_TYPE_NUM | NJT_JSON_SUBTYPE_UINT;
    return (unsafe_njt_json_get_tag(val) & mask) == patt;
}

njt_json_api_inline bool unsafe_njt_json_is_real(void *val)
{
    const uint8_t patt = NJT_JSON_TYPE_NUM | NJT_JSON_SUBTYPE_REAL;
    return unsafe_njt_json_get_tag(val) == patt;
}

njt_json_api_inline bool unsafe_njt_json_is_true(void *val)
{
    const uint8_t patt = NJT_JSON_TYPE_BOOL | NJT_JSON_SUBTYPE_TRUE;
    return unsafe_njt_json_get_tag(val) == patt;
}

njt_json_api_inline bool unsafe_njt_json_is_false(void *val)
{
    const uint8_t patt = NJT_JSON_TYPE_BOOL | NJT_JSON_SUBTYPE_FALSE;
    return unsafe_njt_json_get_tag(val) == patt;
}

njt_json_api_inline bool unsafe_njt_json_arr_is_flat(njt_json_val *val)
{
    size_t ofs = val->uni.ofs;
    size_t len = (size_t)(val->tag >> NJT_JSON_TAG_BIT);
    return len * sizeof(njt_json_val) + sizeof(njt_json_val) == ofs;
}

njt_json_api_inline const char *unsafe_njt_json_get_raw(void *val)
{
    return ((njt_json_val *)val)->uni.str;
}

njt_json_api_inline bool unsafe_njt_json_get_bool(void *val)
{
    uint8_t tag = unsafe_njt_json_get_tag(val);
    return (bool)((tag & NJT_JSON_SUBTYPE_MASK) >> NJT_JSON_TYPE_BIT);
}

njt_json_api_inline uint64_t unsafe_njt_json_get_uint(void *val)
{
    return ((njt_json_val *)val)->uni.u64;
}

njt_json_api_inline int64_t unsafe_njt_json_get_sint(void *val)
{
    return ((njt_json_val *)val)->uni.i64;
}

njt_json_api_inline int unsafe_njt_json_get_int(void *val)
{
    return (int)((njt_json_val *)val)->uni.i64;
}

njt_json_api_inline double unsafe_njt_json_get_real(void *val)
{
    return ((njt_json_val *)val)->uni.f64;
}

njt_json_api_inline const char *unsafe_njt_json_get_str(void *val)
{
    return ((njt_json_val *)val)->uni.str;
}

njt_json_api_inline size_t unsafe_njt_json_get_len(void *val)
{
    return (size_t)(((njt_json_val *)val)->tag >> NJT_JSON_TAG_BIT);
}

njt_json_api_inline void unsafe_njt_json_set_len(void *val, size_t len)
{
    uint64_t tag = ((njt_json_val *)val)->tag & NJT_JSON_TAG_MASK;
    tag |= (uint64_t)len << NJT_JSON_TAG_BIT;
    ((njt_json_val *)val)->tag = tag;
}

njt_json_api_inline njt_json_val *unsafe_njt_json_get_first(njt_json_val *ctn)
{
    return ctn + 1;
}

njt_json_api_inline njt_json_val *unsafe_njt_json_get_next(njt_json_val *val)
{
    bool is_ctn = unsafe_njt_json_is_ctn(val);
    size_t ctn_ofs = val->uni.ofs;
    size_t ofs = (is_ctn ? ctn_ofs : sizeof(njt_json_val));
    return (njt_json_val *)(void *)((uint8_t *)val + ofs);
}

njt_json_api_inline bool unsafe_njt_json_equals_strn(void *val,
        const char *str,
        size_t len)
{
    uint64_t tag = ((uint64_t)len << NJT_JSON_TAG_BIT) | NJT_JSON_TYPE_STR;
    return ((njt_json_val *)val)->tag == tag &&
           memcmp(((njt_json_val *)val)->uni.str, str, len) == 0;
}

njt_json_api_inline bool unsafe_njt_json_equals_str(void *val,
        const char *str)
{
    return unsafe_njt_json_equals_strn(val, str, strlen(str));
}



/*==============================================================================
 * JSON Document API (Implementation)
 *============================================================================*/

njt_json_api_inline njt_json_val *njt_json_doc_get_root(njt_json_doc *doc)
{
    return doc ? doc->root : NULL;
}

njt_json_api_inline size_t njt_json_doc_get_read_size(njt_json_doc *doc)
{
    return doc ? doc->dat_read : 0;
}

njt_json_api_inline size_t njt_json_doc_get_val_count(njt_json_doc *doc)
{
    return doc ? doc->val_read : 0;
}

njt_json_api_inline void njt_json_doc_free(njt_json_doc *doc)
{
    if (doc) {
        njt_json_alc alc = doc->alc;
        if (doc->str_pool) alc.free(alc.ctx, doc->str_pool);
        alc.free(alc.ctx, doc);
    }
}



/*==============================================================================
 * JSON Value Type API (Implementation)
 *============================================================================*/

njt_json_api_inline bool njt_json_is_raw(njt_json_val *val)
{
    return val ? unsafe_njt_json_is_raw(val) : false;
}

njt_json_api_inline bool njt_json_is_null(njt_json_val *val)
{
    return val ? unsafe_njt_json_is_null(val) : false;
}

njt_json_api_inline bool njt_json_is_true(njt_json_val *val)
{
    return val ? unsafe_njt_json_is_true(val) : false;
}

njt_json_api_inline bool njt_json_is_false(njt_json_val *val)
{
    return val ? unsafe_njt_json_is_false(val) : false;
}

njt_json_api_inline bool njt_json_is_bool(njt_json_val *val)
{
    return val ? unsafe_njt_json_is_bool(val) : false;
}

njt_json_api_inline bool njt_json_is_uint(njt_json_val *val)
{
    return val ? unsafe_njt_json_is_uint(val) : false;
}

njt_json_api_inline bool njt_json_is_sint(njt_json_val *val)
{
    return val ? unsafe_njt_json_is_sint(val) : false;
}

njt_json_api_inline bool njt_json_is_int(njt_json_val *val)
{
    return val ? unsafe_njt_json_is_int(val) : false;
}

njt_json_api_inline bool njt_json_is_real(njt_json_val *val)
{
    return val ? unsafe_njt_json_is_real(val) : false;
}

njt_json_api_inline bool njt_json_is_num(njt_json_val *val)
{
    return val ? unsafe_njt_json_is_num(val) : false;
}

njt_json_api_inline bool njt_json_is_str(njt_json_val *val)
{
    return val ? unsafe_njt_json_is_str(val) : false;
}

njt_json_api_inline bool njt_json_is_arr(njt_json_val *val)
{
    return val ? unsafe_njt_json_is_arr(val) : false;
}

njt_json_api_inline bool njt_json_is_obj(njt_json_val *val)
{
    return val ? unsafe_njt_json_is_obj(val) : false;
}

njt_json_api_inline bool njt_json_is_ctn(njt_json_val *val)
{
    return val ? unsafe_njt_json_is_ctn(val) : false;
}



/*==============================================================================
 * JSON Value Content API (Implementation)
 *============================================================================*/

njt_json_api_inline njt_json_type njt_json_get_type(njt_json_val *val)
{
    return val ? unsafe_njt_json_get_type(val) : NJT_JSON_TYPE_NONE;
}

njt_json_api_inline njt_json_subtype njt_json_get_subtype(njt_json_val *val)
{
    return val ? unsafe_njt_json_get_subtype(val) : NJT_JSON_SUBTYPE_NONE;
}

njt_json_api_inline uint8_t njt_json_get_tag(njt_json_val *val)
{
    return val ? unsafe_njt_json_get_tag(val) : 0;
}

njt_json_api_inline const char *njt_json_get_type_desc(njt_json_val *val)
{
    switch (njt_json_get_tag(val)) {
    case NJT_JSON_TYPE_NULL | NJT_JSON_SUBTYPE_NONE:  return "null";
    case NJT_JSON_TYPE_RAW  | NJT_JSON_SUBTYPE_NONE:  return "raw";
    case NJT_JSON_TYPE_STR  | NJT_JSON_SUBTYPE_NONE:  return "string";
    case NJT_JSON_TYPE_ARR  | NJT_JSON_SUBTYPE_NONE:  return "array";
    case NJT_JSON_TYPE_OBJ  | NJT_JSON_SUBTYPE_NONE:  return "object";
    case NJT_JSON_TYPE_BOOL | NJT_JSON_SUBTYPE_TRUE:  return "true";
    case NJT_JSON_TYPE_BOOL | NJT_JSON_SUBTYPE_FALSE: return "false";
    case NJT_JSON_TYPE_NUM  | NJT_JSON_SUBTYPE_UINT:  return "uint";
    case NJT_JSON_TYPE_NUM  | NJT_JSON_SUBTYPE_SINT:  return "sint";
    case NJT_JSON_TYPE_NUM  | NJT_JSON_SUBTYPE_REAL:  return "real";
    default:                                      return "unknown";
    }
}

njt_json_api_inline const char *njt_json_get_raw(njt_json_val *val)
{
    return njt_json_is_raw(val) ? unsafe_njt_json_get_raw(val) : NULL;
}

njt_json_api_inline bool njt_json_get_bool(njt_json_val *val)
{
    return njt_json_is_bool(val) ? unsafe_njt_json_get_bool(val) : false;
}

njt_json_api_inline uint64_t njt_json_get_uint(njt_json_val *val)
{
    return njt_json_is_int(val) ? unsafe_njt_json_get_uint(val) : 0;
}

njt_json_api_inline int64_t njt_json_get_sint(njt_json_val *val)
{
    return njt_json_is_int(val) ? unsafe_njt_json_get_sint(val) : 0;
}

njt_json_api_inline int njt_json_get_int(njt_json_val *val)
{
    return njt_json_is_int(val) ? unsafe_njt_json_get_int(val) : 0;
}

njt_json_api_inline double njt_json_get_real(njt_json_val *val)
{
    return njt_json_is_real(val) ? unsafe_njt_json_get_real(val) : 0.0;
}

njt_json_api_inline const char *njt_json_get_str(njt_json_val *val)
{
    return njt_json_is_str(val) ? unsafe_njt_json_get_str(val) : NULL;
}

njt_json_api_inline size_t njt_json_get_len(njt_json_val *val)
{
    return val ? unsafe_njt_json_get_len(val) : 0;
}

njt_json_api_inline bool njt_json_equals_str(njt_json_val *val,
        const char *str)
{
    if (njt_json_likely(val && str)) {
        return unsafe_njt_json_equals_str(val, str);
    }
    return false;
}

njt_json_api_inline bool njt_json_equals_strn(njt_json_val *val,
        const char *str,
        size_t len)
{
    if (njt_json_likely(val && str)) {
        return unsafe_njt_json_equals_strn(val, str, len);
    }
    return false;
}



/*==============================================================================
 * JSON Array API (Implementation)
 *============================================================================*/

njt_json_api_inline size_t njt_json_arr_size(njt_json_val *arr)
{
    return njt_json_is_arr(arr) ? unsafe_njt_json_get_len(arr) : 0;
}

njt_json_api_inline njt_json_val *njt_json_arr_get(njt_json_val *arr,
        size_t idx)
{
    if (njt_json_likely(njt_json_is_arr(arr))) {
        if (njt_json_likely(unsafe_njt_json_get_len(arr) > idx)) {
            njt_json_val *val = unsafe_njt_json_get_first(arr);
            if (unsafe_njt_json_arr_is_flat(arr)) {
                return val + idx;
            } else {
                while (idx-- > 0) val = unsafe_njt_json_get_next(val);
                return val;
            }
        }
    }
    return NULL;
}

njt_json_api_inline njt_json_val *njt_json_arr_get_first(njt_json_val *arr)
{
    if (njt_json_likely(njt_json_is_arr(arr))) {
        if (njt_json_likely(unsafe_njt_json_get_len(arr) > 0)) {
            return unsafe_njt_json_get_first(arr);
        }
    }
    return NULL;
}

njt_json_api_inline njt_json_val *njt_json_arr_get_last(njt_json_val *arr)
{
    if (njt_json_likely(njt_json_is_arr(arr))) {
        size_t len = unsafe_njt_json_get_len(arr);
        if (njt_json_likely(len > 0)) {
            njt_json_val *val = unsafe_njt_json_get_first(arr);
            if (unsafe_njt_json_arr_is_flat(arr)) {
                return val + (len - 1);
            } else {
                while (len-- > 1) val = unsafe_njt_json_get_next(val);
                return val;
            }
        }
    }
    return NULL;
}



/*==============================================================================
 * JSON Array Iterator API (Implementation)
 *============================================================================*/

struct njt_json_arr_iter {
    size_t idx;
    size_t max;
    njt_json_val *cur;
};

njt_json_api_inline bool njt_json_arr_iter_init(njt_json_val *arr,
        njt_json_arr_iter *iter)
{
    if (njt_json_likely(njt_json_is_arr(arr) && iter)) {
        iter->idx = 0;
        iter->max = unsafe_njt_json_get_len(arr);
        iter->cur = unsafe_njt_json_get_first(arr);
        return true;
    }
    if (iter) memset(iter, 0, sizeof(njt_json_arr_iter));
    return false;
}

njt_json_api_inline bool njt_json_arr_iter_has_next(njt_json_arr_iter *iter)
{
    return iter ? iter->idx < iter->max : false;
}

njt_json_api_inline njt_json_val *njt_json_arr_iter_next(
    njt_json_arr_iter *iter)
{
    njt_json_val *val;
    if (iter && iter->idx < iter->max) {
        val = iter->cur;
        iter->cur = unsafe_njt_json_get_next(val);
        iter->idx++;
        return val;
    }
    return NULL;
}



/*==============================================================================
 * JSON Object API (Implementation)
 *============================================================================*/

njt_json_api_inline size_t njt_json_obj_size(njt_json_val *obj)
{
    return njt_json_is_obj(obj) ? unsafe_njt_json_get_len(obj) : 0;
}

njt_json_api_inline njt_json_val *njt_json_obj_get(njt_json_val *obj,
        const char *key_str)
{
    return njt_json_obj_getn(obj, key_str, key_str ? strlen(key_str) : 0);
}

njt_json_api_inline njt_json_val *njt_json_obj_getn(njt_json_val *obj,
        const char *key_str,
        size_t key_len)
{
    uint64_t tag = (((uint64_t)key_len) << NJT_JSON_TAG_BIT) | NJT_JSON_TYPE_STR;
    if (njt_json_likely(njt_json_is_obj(obj) && key_str)) {
        size_t len = unsafe_njt_json_get_len(obj);
        njt_json_val *key = unsafe_njt_json_get_first(obj);
        while (len-- > 0) {
            if (key->tag == tag &&
                memcmp(key->uni.ptr, key_str, key_len) == 0) {
                return key + 1;
            }
            key = unsafe_njt_json_get_next(key + 1);
        }
    }
    return NULL;
}



/*==============================================================================
 * JSON Object Iterator API (Implementation)
 *============================================================================*/

struct njt_json_obj_iter {
    size_t idx;
    size_t max;
    njt_json_val *cur;
    njt_json_val *obj;
};

njt_json_api_inline bool njt_json_obj_iter_init(njt_json_val *obj,
        njt_json_obj_iter *iter)
{
    if (njt_json_likely(njt_json_is_obj(obj) && iter)) {
        iter->idx = 0;
        iter->max = unsafe_njt_json_get_len(obj);
        iter->cur = unsafe_njt_json_get_first(obj);
        iter->obj = obj;
        return true;
    }
    if (iter) {
        iter->idx = 0;
        iter->max = 0;
    }
    return false;
}

njt_json_api_inline bool njt_json_obj_iter_has_next(njt_json_obj_iter *iter)
{
    return iter ? iter->idx < iter->max : false;
}

njt_json_api_inline njt_json_val *njt_json_obj_iter_next(
    njt_json_obj_iter *iter)
{
    if (iter && iter->idx < iter->max) {
        njt_json_val *key = iter->cur;
        iter->idx++;
        iter->cur = unsafe_njt_json_get_next(key + 1);
        return key;
    }
    return NULL;
}

njt_json_api_inline njt_json_val *njt_json_obj_iter_get_val(njt_json_val *key)
{
    return key + 1;
}

njt_json_api_inline njt_json_val *njt_json_obj_iter_get(
    njt_json_obj_iter *iter,
    const char *key)
{
    return njt_json_obj_iter_getn(iter, key, key ? strlen(key) : 0);
}

njt_json_api_inline njt_json_val *njt_json_obj_iter_getn(
    njt_json_obj_iter *iter,
    const char *key,
    size_t key_len)
{
    if (iter && key) {
        size_t idx = iter->idx;
        size_t max = iter->max;
        njt_json_val *cur = iter->cur;
        if (njt_json_unlikely(idx == max)) {
            idx = 0;
            cur = unsafe_njt_json_get_first(iter->obj);
        }
        while (idx++ < max) {
            njt_json_val *next = unsafe_njt_json_get_next(cur + 1);
            if (unsafe_njt_json_get_len(cur) == key_len &&
                memcmp(cur->uni.str, key, key_len) == 0) {
                iter->idx = idx;
                iter->cur = next;
                return cur + 1;
            }
            cur = next;
            if (idx == iter->max && iter->idx < iter->max) {
                idx = 0;
                max = iter->idx;
                cur = unsafe_njt_json_get_first(iter->obj);
            }
        }
    }
    return NULL;
}



/*==============================================================================
 * Mutable JSON Structure (Implementation)
 *============================================================================*/

/*
 Mutable JSON value, 24 bytes.
 The 'tag' and 'uni' field is same as immutable value.
 The 'next' field links all elements inside the container to be a cycle.
 */
struct njt_json_mut_val {
    uint64_t tag;
    njt_json_val_uni uni;
    njt_json_mut_val *next;
};

typedef struct njt_json_str_chunk {
    struct njt_json_str_chunk *next;
    /* flexible array member here */
} njt_json_str_chunk;

typedef struct njt_json_str_pool {
    char *cur; /* cursor inside current chunk */
    char *end; /* the end of current chunk */
    size_t chunk_size; /* chunk size in bytes while creating new chunk */
    size_t chunk_size_max; /* maximum chunk size in bytes */
    njt_json_str_chunk *chunks; /* a linked list of chunks, nullable */
} njt_json_str_pool;

typedef struct njt_json_val_chunk {
    struct njt_json_val_chunk *next;
    /* flexible array member here */
} njt_json_val_chunk;

typedef struct njt_json_val_pool {
    njt_json_mut_val *cur; /* cursor inside current chunk */
    njt_json_mut_val *end; /* the end of current chunk */
    size_t chunk_size; /* chunk size in bytes while creating new chunk */
    size_t chunk_size_max; /* maximum chunk size in bytes */
    njt_json_val_chunk *chunks; /* a linked list of chunks, nullable */
} njt_json_val_pool;

struct njt_json_mut_doc {
    njt_json_mut_val *root; /* root value of the JSON document, nullable */
    njt_json_alc alc; /* a valid allocator, nonnull */
    njt_json_str_pool str_pool; /* string memory holder */
    njt_json_val_pool val_pool; /* value memory holder */
};

/* Ensures the capacity to at least equal to the specified byte length. */
njt_json_api bool unsafe_njt_json_str_pool_grow(njt_json_str_pool *pool,
        njt_json_alc *alc, size_t len);

/* Ensures the capacity to at least equal to the specified value count. */
njt_json_api bool unsafe_njt_json_val_pool_grow(njt_json_val_pool *pool,
        njt_json_alc *alc, size_t count);

njt_json_api_inline char *unsafe_njt_json_mut_strncpy(njt_json_mut_doc *doc,
        const char *str, size_t len)
{
    char *mem;
    njt_json_alc *alc = &doc->alc;
    njt_json_str_pool *pool = &doc->str_pool;

    if (!str) return NULL;
    if (njt_json_unlikely((size_t)(pool->end - pool->cur) <= len)) {
        if (njt_json_unlikely(!unsafe_njt_json_str_pool_grow(pool, alc, len + 1))) {
            return NULL;
        }
    }

    mem = pool->cur;
    pool->cur = mem + len + 1;
    memcpy((void *)mem, (const void *)str, len);
    mem[len] = '\0';
    return mem;
}

njt_json_api_inline njt_json_mut_val *unsafe_njt_json_mut_val(
    njt_json_mut_doc *doc,
    size_t count)
{
    njt_json_mut_val *val;
    njt_json_alc *alc = &doc->alc;
    njt_json_val_pool *pool = &doc->val_pool;
    if (njt_json_unlikely((size_t)(pool->end - pool->cur) < count)) {
        if (njt_json_unlikely(!unsafe_njt_json_val_pool_grow(pool, alc, count))) {
            return NULL;
        }
    }

    val = pool->cur;
    pool->cur += count;
    return val;
}



/*==============================================================================
 * Mutable JSON Document API (Implementation)
 *============================================================================*/

njt_json_api_inline njt_json_mut_val *njt_json_mut_doc_get_root(
    njt_json_mut_doc *doc)
{
    return doc ? doc->root : NULL;
}

njt_json_api_inline void njt_json_mut_doc_set_root(njt_json_mut_doc *doc,
        njt_json_mut_val *root)
{
    if (doc) doc->root = root;
}



/*==============================================================================
 * Mutable JSON Value Type API (Implementation)
 *============================================================================*/

njt_json_api_inline bool njt_json_mut_is_raw(njt_json_mut_val *val)
{
    return val ? unsafe_njt_json_is_raw(val) : false;
}

njt_json_api_inline bool njt_json_mut_is_null(njt_json_mut_val *val)
{
    return val ? unsafe_njt_json_is_null(val) : false;
}

njt_json_api_inline bool njt_json_mut_is_true(njt_json_mut_val *val)
{
    return val ? unsafe_njt_json_is_true(val) : false;
}

njt_json_api_inline bool njt_json_mut_is_false(njt_json_mut_val *val)
{
    return val ? unsafe_njt_json_is_false(val) : false;
}

njt_json_api_inline bool njt_json_mut_is_bool(njt_json_mut_val *val)
{
    return val ? unsafe_njt_json_is_bool(val) : false;
}

njt_json_api_inline bool njt_json_mut_is_uint(njt_json_mut_val *val)
{
    return val ? unsafe_njt_json_is_uint(val) : false;
}

njt_json_api_inline bool njt_json_mut_is_sint(njt_json_mut_val *val)
{
    return val ? unsafe_njt_json_is_sint(val) : false;
}

njt_json_api_inline bool njt_json_mut_is_int(njt_json_mut_val *val)
{
    return val ? unsafe_njt_json_is_int(val) : false;
}

njt_json_api_inline bool njt_json_mut_is_real(njt_json_mut_val *val)
{
    return val ? unsafe_njt_json_is_real(val) : false;
}

njt_json_api_inline bool njt_json_mut_is_num(njt_json_mut_val *val)
{
    return val ? unsafe_njt_json_is_num(val) : false;
}

njt_json_api_inline bool njt_json_mut_is_str(njt_json_mut_val *val)
{
    return val ? unsafe_njt_json_is_str(val) : false;
}

njt_json_api_inline bool njt_json_mut_is_arr(njt_json_mut_val *val)
{
    return val ? unsafe_njt_json_is_arr(val) : false;
}

njt_json_api_inline bool njt_json_mut_is_obj(njt_json_mut_val *val)
{
    return val ? unsafe_njt_json_is_obj(val) : false;
}

njt_json_api_inline bool njt_json_mut_is_ctn(njt_json_mut_val *val)
{
    return val ? unsafe_njt_json_is_ctn(val) : false;
}



/*==============================================================================
 * Mutable JSON Value Content API (Implementation)
 *============================================================================*/

njt_json_api_inline njt_json_type njt_json_mut_get_type(njt_json_mut_val *val)
{
    return njt_json_get_type((njt_json_val *)val);
}

njt_json_api_inline njt_json_subtype njt_json_mut_get_subtype(
    njt_json_mut_val *val)
{
    return njt_json_get_subtype((njt_json_val *)val);
}

njt_json_api_inline uint8_t njt_json_mut_get_tag(njt_json_mut_val *val)
{
    return njt_json_get_tag((njt_json_val *)val);
}

njt_json_api_inline const char *njt_json_mut_get_type_desc(
    njt_json_mut_val *val)
{
    return njt_json_get_type_desc((njt_json_val *)val);
}

njt_json_api_inline const char *njt_json_mut_get_raw(njt_json_mut_val *val)
{
    return njt_json_get_raw((njt_json_val *)val);
}

njt_json_api_inline bool njt_json_mut_get_bool(njt_json_mut_val *val)
{
    return njt_json_get_bool((njt_json_val *)val);
}

njt_json_api_inline uint64_t njt_json_mut_get_uint(njt_json_mut_val *val)
{
    return njt_json_get_uint((njt_json_val *)val);
}

njt_json_api_inline int64_t njt_json_mut_get_sint(njt_json_mut_val *val)
{
    return njt_json_get_sint((njt_json_val *)val);
}

njt_json_api_inline int njt_json_mut_get_int(njt_json_mut_val *val)
{
    return njt_json_get_int((njt_json_val *)val);
}

njt_json_api_inline double njt_json_mut_get_real(njt_json_mut_val *val)
{
    return njt_json_get_real((njt_json_val *)val);
}

njt_json_api_inline const char *njt_json_mut_get_str(njt_json_mut_val *val)
{
    return njt_json_get_str((njt_json_val *)val);
}

njt_json_api_inline size_t njt_json_mut_get_len(njt_json_mut_val *val)
{
    return njt_json_get_len((njt_json_val *)val);
}

njt_json_api_inline bool njt_json_mut_equals_str(njt_json_mut_val *val,
        const char *str)
{
    return njt_json_equals_str((njt_json_val *)val, str);
}

njt_json_api_inline bool njt_json_mut_equals_strn(njt_json_mut_val *val,
        const char *str, size_t len)
{
    return njt_json_equals_strn((njt_json_val *)val, str, len);
}



/*==============================================================================
 * Mutable JSON Value Creation API (Implementation)
 *============================================================================*/

njt_json_api_inline njt_json_mut_val *njt_json_mut_raw(njt_json_mut_doc *doc,
        const char *str,
        size_t len)
{
    if (njt_json_likely(doc && str)) {
        njt_json_mut_val *val = unsafe_njt_json_mut_val(doc, 1);
        char *new_str = unsafe_njt_json_mut_strncpy(doc, str, len);
        if (njt_json_likely(val && new_str)) {
            val->tag = ((uint64_t)len << NJT_JSON_TAG_BIT) | NJT_JSON_TYPE_RAW;
            val->uni.str = new_str;
            return val;
        }
    }
    return NULL;
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_null(njt_json_mut_doc *doc)
{
    if (njt_json_likely(doc)) {
        njt_json_mut_val *val = unsafe_njt_json_mut_val(doc, 1);
        if (njt_json_likely(val)) {
            val->tag = NJT_JSON_TYPE_NULL | NJT_JSON_SUBTYPE_NONE;
            return val;
        }
    }
    return NULL;
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_true(njt_json_mut_doc *doc)
{
    if (njt_json_likely(doc)) {
        njt_json_mut_val *val = unsafe_njt_json_mut_val(doc, 1);
        if (njt_json_likely(val)) {
            val->tag = NJT_JSON_TYPE_BOOL | NJT_JSON_SUBTYPE_TRUE;
            return val;
        }
    }
    return NULL;
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_false(
    njt_json_mut_doc *doc)
{
    if (njt_json_likely(doc)) {
        njt_json_mut_val *val = unsafe_njt_json_mut_val(doc, 1);
        if (njt_json_likely(val)) {
            val->tag = NJT_JSON_TYPE_BOOL | NJT_JSON_SUBTYPE_FALSE;
            return val;
        }
    }
    return NULL;
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_bool(njt_json_mut_doc *doc,
        bool _val)
{
    if (njt_json_likely(doc)) {
        njt_json_mut_val *val = unsafe_njt_json_mut_val(doc, 1);
        if (njt_json_likely(val)) {
            val->tag = NJT_JSON_TYPE_BOOL | (uint8_t)((uint8_t)_val << 3);
            return val;
        }
    }
    return NULL;
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_uint(njt_json_mut_doc *doc,
        uint64_t num)
{
    if (njt_json_likely(doc)) {
        njt_json_mut_val *val = unsafe_njt_json_mut_val(doc, 1);
        if (njt_json_likely(val)) {
            val->tag = NJT_JSON_TYPE_NUM | NJT_JSON_SUBTYPE_UINT;
            val->uni.u64 = num;
            return val;
        }
    }
    return NULL;
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_sint(njt_json_mut_doc *doc,
        int64_t num)
{
    if (njt_json_likely(doc)) {
        njt_json_mut_val *val = unsafe_njt_json_mut_val(doc, 1);
        if (njt_json_likely(val)) {
            val->tag = NJT_JSON_TYPE_NUM | NJT_JSON_SUBTYPE_SINT;
            val->uni.i64 = num;
            return val;
        }
    }
    return NULL;
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_int(njt_json_mut_doc *doc,
        int64_t num)
{
    return njt_json_mut_sint(doc, num);
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_real(njt_json_mut_doc *doc,
        double num)
{
    if (njt_json_likely(doc)) {
        njt_json_mut_val *val = unsafe_njt_json_mut_val(doc, 1);
        if (njt_json_likely(val)) {
            val->tag = NJT_JSON_TYPE_NUM | NJT_JSON_SUBTYPE_REAL;
            val->uni.f64 = num;
            return val;
        }
    }
    return NULL;
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_str(njt_json_mut_doc *doc,
        const char *str)
{
    if (njt_json_likely(str)) return njt_json_mut_strn(doc, str, strlen(str));
    return NULL;
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_strn(njt_json_mut_doc *doc,
        const char *str,
        size_t len)
{
    if (njt_json_likely(doc && str)) {
        njt_json_mut_val *val = unsafe_njt_json_mut_val(doc, 1);
        if (njt_json_likely(val)) {
            val->tag = ((uint64_t)len << NJT_JSON_TAG_BIT) | NJT_JSON_TYPE_STR;
            val->uni.str = str;
            return val;
        }
    }
    return NULL;
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_strcpy(
    njt_json_mut_doc *doc,
    const char *str)
{
    if (njt_json_likely(str)) return njt_json_mut_strncpy(doc, str, strlen(str));
    return NULL;
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_strncpy(
    njt_json_mut_doc *doc,
    const char *str,
    size_t len)
{
    if (njt_json_likely(doc && str)) {
        njt_json_mut_val *val = unsafe_njt_json_mut_val(doc, 1);
        char *new_str = unsafe_njt_json_mut_strncpy(doc, str, len);
        if (njt_json_likely(val && new_str)) {
            val->tag = ((uint64_t)len << NJT_JSON_TAG_BIT) | NJT_JSON_TYPE_STR;
            val->uni.str = new_str;
            return val;
        }
    }
    return NULL;
}



/*==============================================================================
 * Mutable JSON Array API (Implementation)
 *============================================================================*/

njt_json_api_inline size_t njt_json_mut_arr_size(njt_json_mut_val *arr)
{
    return njt_json_mut_is_arr(arr) ? unsafe_njt_json_get_len(arr) : 0;
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_get(
    njt_json_mut_val *arr,
    size_t idx)
{
    if (njt_json_likely(idx < njt_json_mut_arr_size(arr))) {
        njt_json_mut_val *val = (njt_json_mut_val *)arr->uni.ptr;
        while (idx-- > 0) val = val->next;
        return val->next;
    }
    return NULL;
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_get_first(
    njt_json_mut_val *arr)
{
    if (njt_json_likely(njt_json_mut_arr_size(arr) > 0)) {
        return ((njt_json_mut_val *)arr->uni.ptr)->next;
    }
    return NULL;
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_get_last(
    njt_json_mut_val *arr)
{
    if (njt_json_likely(njt_json_mut_arr_size(arr) > 0)) {
        return ((njt_json_mut_val *)arr->uni.ptr);
    }
    return NULL;
}



/*==============================================================================
 * Mutable JSON Array Iterator API (Implementation)
 *============================================================================*/

struct njt_json_mut_arr_iter {
    size_t idx;
    size_t max;
    njt_json_mut_val *cur;
    njt_json_mut_val *pre;
    njt_json_mut_val *arr;
};

njt_json_api_inline bool njt_json_mut_arr_iter_init(njt_json_mut_val *arr,
        njt_json_mut_arr_iter *iter)
{
    if (njt_json_likely(njt_json_mut_is_arr(arr) && iter)) {
        iter->idx = 0;
        iter->max = unsafe_njt_json_get_len(arr);
        iter->cur = iter->max ? (njt_json_mut_val *)arr->uni.ptr : NULL;
        iter->pre = NULL;
        iter->arr = arr;
        return true;
    }
    if (iter) memset(iter, 0, sizeof(njt_json_mut_arr_iter));
    return false;
}

njt_json_api_inline bool njt_json_mut_arr_iter_has_next(
    njt_json_mut_arr_iter *iter)
{
    return iter ? iter->idx < iter->max : false;
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_iter_next(
    njt_json_mut_arr_iter *iter)
{
    if (iter && iter->idx < iter->max) {
        njt_json_mut_val *val = iter->cur;
        iter->pre = val;
        iter->cur = val->next;
        iter->idx++;
        return iter->cur;
    }
    return NULL;
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_iter_remove(
    njt_json_mut_arr_iter *iter)
{
    if (njt_json_likely(iter && 0 < iter->idx && iter->idx <= iter->max)) {
        njt_json_mut_val *prev = iter->pre;
        njt_json_mut_val *cur = iter->cur;
        njt_json_mut_val *next = cur->next;
        if (njt_json_unlikely(iter->idx == iter->max)) iter->arr->uni.ptr = prev;
        iter->idx--;
        iter->max--;
        unsafe_njt_json_set_len(iter->arr, iter->max);
        prev->next = next;
        iter->cur = next;
        return cur;
    }
    return NULL;
}



/*==============================================================================
 * Mutable JSON Array Creation API (Implementation)
 *============================================================================*/

njt_json_api_inline njt_json_mut_val *njt_json_mut_arr(njt_json_mut_doc *doc)
{
    if (njt_json_likely(doc)) {
        njt_json_mut_val *val = unsafe_njt_json_mut_val(doc, 1);
        if (njt_json_likely(val)) {
            val->tag = NJT_JSON_TYPE_ARR | NJT_JSON_SUBTYPE_NONE;
            return val;
        }
    }
    return NULL;
}

#define njt_json_mut_arr_with_func(func) \
    if (njt_json_likely(doc && ((0 < count && count < \
                                 (~(size_t)0) / sizeof(njt_json_mut_val) && vals) || count == 0))) { \
        njt_json_mut_val *arr = unsafe_njt_json_mut_val(doc, 1 + count); \
        if (njt_json_likely(arr)) { \
            arr->tag = ((uint64_t)count << NJT_JSON_TAG_BIT) | NJT_JSON_TYPE_ARR; \
            if (count > 0) { \
                size_t i; \
                for (i = 0; i < count; i++) { \
                    njt_json_mut_val *val = arr + i + 1; \
                    func \
                    val->next = val + 1; \
                } \
                arr[count].next = arr + 1; \
                arr->uni.ptr = arr + count; \
            } \
            return arr; \
        } \
    } \
    return NULL

njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_with_bool(
    njt_json_mut_doc *doc, const bool *vals, size_t count)
{
    njt_json_mut_arr_with_func({
        val->tag = NJT_JSON_TYPE_BOOL | (uint8_t)((uint8_t)vals[i] << 3);
    });
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_with_sint(
    njt_json_mut_doc *doc, const int64_t *vals, size_t count)
{
    return njt_json_mut_arr_with_sint64(doc, vals, count);
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_with_uint(
    njt_json_mut_doc *doc, const uint64_t *vals, size_t count)
{
    return njt_json_mut_arr_with_uint64(doc, vals, count);
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_with_real(
    njt_json_mut_doc *doc, const double *vals, size_t count)
{
    return njt_json_mut_arr_with_double(doc, vals, count);
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_with_sint8(
    njt_json_mut_doc *doc, const int8_t *vals, size_t count)
{
    njt_json_mut_arr_with_func({
        val->tag = NJT_JSON_TYPE_NUM | NJT_JSON_SUBTYPE_SINT;
        val->uni.i64 = (int64_t)vals[i];
    });
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_with_sint16(
    njt_json_mut_doc *doc, const int16_t *vals, size_t count)
{
    njt_json_mut_arr_with_func({
        val->tag = NJT_JSON_TYPE_NUM | NJT_JSON_SUBTYPE_SINT;
        val->uni.i64 = vals[i];
    });
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_with_sint32(
    njt_json_mut_doc *doc, const int32_t *vals, size_t count)
{
    njt_json_mut_arr_with_func({
        val->tag = NJT_JSON_TYPE_NUM | NJT_JSON_SUBTYPE_SINT;
        val->uni.i64 = vals[i];
    });
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_with_sint64(
    njt_json_mut_doc *doc, const int64_t *vals, size_t count)
{
    njt_json_mut_arr_with_func({
        val->tag = NJT_JSON_TYPE_NUM | NJT_JSON_SUBTYPE_SINT;
        val->uni.i64 = vals[i];
    });
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_with_uint8(
    njt_json_mut_doc *doc, const uint8_t *vals, size_t count)
{
    njt_json_mut_arr_with_func({
        val->tag = NJT_JSON_TYPE_NUM | NJT_JSON_SUBTYPE_UINT;
        val->uni.u64 = vals[i];
    });
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_with_uint16(
    njt_json_mut_doc *doc, const uint16_t *vals, size_t count)
{
    njt_json_mut_arr_with_func({
        val->tag = NJT_JSON_TYPE_NUM | NJT_JSON_SUBTYPE_UINT;
        val->uni.u64 = vals[i];
    });
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_with_uint32(
    njt_json_mut_doc *doc, const uint32_t *vals, size_t count)
{
    njt_json_mut_arr_with_func({
        val->tag = NJT_JSON_TYPE_NUM | NJT_JSON_SUBTYPE_UINT;
        val->uni.u64 = vals[i];
    });
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_with_uint64(
    njt_json_mut_doc *doc, const uint64_t *vals, size_t count)
{
    njt_json_mut_arr_with_func({
        val->tag = NJT_JSON_TYPE_NUM | NJT_JSON_SUBTYPE_UINT;
        val->uni.u64 = vals[i];
    });
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_with_float(
    njt_json_mut_doc *doc, const float *vals, size_t count)
{
    njt_json_mut_arr_with_func({
        val->tag = NJT_JSON_TYPE_NUM | NJT_JSON_SUBTYPE_REAL;
        val->uni.f64 = (double)vals[i];
    });
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_with_double(
    njt_json_mut_doc *doc, const double *vals, size_t count)
{
    njt_json_mut_arr_with_func({
        val->tag = NJT_JSON_TYPE_NUM | NJT_JSON_SUBTYPE_REAL;
        val->uni.f64 = vals[i];
    });
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_with_str(
    njt_json_mut_doc *doc, const char **vals, size_t count)
{
    njt_json_mut_arr_with_func({
        uint64_t len = (uint64_t)strlen(vals[i]);
        val->tag = (len << NJT_JSON_TAG_BIT) | NJT_JSON_TYPE_STR;
        val->uni.str = vals[i];
    });
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_with_strn(
    njt_json_mut_doc *doc, const char **vals, const size_t *lens, size_t count)
{
    if (njt_json_unlikely(count > 0 && !lens)) return NULL;
    njt_json_mut_arr_with_func({
        val->tag = ((uint64_t)lens[i] << NJT_JSON_TAG_BIT) | NJT_JSON_TYPE_STR;
        val->uni.str = vals[i];
    });
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_with_strcpy(
    njt_json_mut_doc *doc, const char **vals, size_t count)
{
    size_t len;
    const char *str;
    njt_json_mut_arr_with_func({
        str = vals[i];
        if (!str) return NULL;
        len = strlen(str);
        val->tag = ((uint64_t)len << NJT_JSON_TAG_BIT) | NJT_JSON_TYPE_STR;
        val->uni.str = unsafe_njt_json_mut_strncpy(doc, str, len);
        if (!val->uni.str) return NULL;
    });
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_with_strncpy(
    njt_json_mut_doc *doc, const char **vals, const size_t *lens, size_t count)
{
    size_t len;
    const char *str;
    if (njt_json_unlikely(count > 0 && !lens)) return NULL;
    njt_json_mut_arr_with_func({
        str = vals[i];
        len = lens[i];
        val->tag = ((uint64_t)len << NJT_JSON_TAG_BIT) | NJT_JSON_TYPE_STR;
        val->uni.str = unsafe_njt_json_mut_strncpy(doc, str, len);
        if (!val->uni.str) return NULL;
    });
}

#undef njt_json_mut_arr_with_func



/*==============================================================================
 * Mutable JSON Array Modification API (Implementation)
 *============================================================================*/

njt_json_api_inline bool njt_json_mut_arr_insert(njt_json_mut_val *arr,
        njt_json_mut_val *val, size_t idx)
{
    if (njt_json_likely(njt_json_mut_is_arr(arr) && val)) {
        size_t len = unsafe_njt_json_get_len(arr);
        if (njt_json_likely(idx <= len)) {
            unsafe_njt_json_set_len(arr, len + 1);
            if (len == 0) {
                val->next = val;
                arr->uni.ptr = val;
            } else {
                njt_json_mut_val *prev = ((njt_json_mut_val *)arr->uni.ptr);
                njt_json_mut_val *next = prev->next;
                if (idx == len) {
                    prev->next = val;
                    val->next = next;
                    arr->uni.ptr = val;
                } else {
                    while (idx-- > 0) {
                        prev = next;
                        next = next->next;
                    }
                    prev->next = val;
                    val->next = next;
                }
            }
            return true;
        }
    }
    return false;
}

njt_json_api_inline bool njt_json_mut_arr_append(njt_json_mut_val *arr,
        njt_json_mut_val *val)
{
    if (njt_json_likely(njt_json_mut_is_arr(arr) && val)) {
        size_t len = unsafe_njt_json_get_len(arr);
        unsafe_njt_json_set_len(arr, len + 1);
        if (len == 0) {
            val->next = val;
        } else {
            njt_json_mut_val *prev = ((njt_json_mut_val *)arr->uni.ptr);
            njt_json_mut_val *next = prev->next;
            prev->next = val;
            val->next = next;
        }
        arr->uni.ptr = val;
        return true;
    }
    return false;
}

njt_json_api_inline bool njt_json_mut_arr_prepend(njt_json_mut_val *arr,
        njt_json_mut_val *val)
{
    if (njt_json_likely(njt_json_mut_is_arr(arr) && val)) {
        size_t len = unsafe_njt_json_get_len(arr);
        unsafe_njt_json_set_len(arr, len + 1);
        if (len == 0) {
            val->next = val;
            arr->uni.ptr = val;
        } else {
            njt_json_mut_val *prev = ((njt_json_mut_val *)arr->uni.ptr);
            njt_json_mut_val *next = prev->next;
            prev->next = val;
            val->next = next;
        }
        return true;
    }
    return false;
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_replace(
    njt_json_mut_val *arr,
    size_t idx,
    njt_json_mut_val *val)
{
    if (njt_json_likely(njt_json_mut_is_arr(arr) && val)) {
        size_t len = unsafe_njt_json_get_len(arr);
        if (njt_json_likely(idx < len)) {
            if (njt_json_likely(len > 1)) {
                njt_json_mut_val *prev = ((njt_json_mut_val *)arr->uni.ptr);
                njt_json_mut_val *next = prev->next;
                while (idx-- > 0) {
                    prev = next;
                    next = next->next;
                }
                prev->next = val;
                val->next = next->next;
                if ((void *)next == arr->uni.ptr) arr->uni.ptr = val;
                return next;
            } else {
                njt_json_mut_val *prev = ((njt_json_mut_val *)arr->uni.ptr);
                val->next = val;
                arr->uni.ptr = val;
                return prev;
            };
        }
    }
    return NULL;
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_remove(
    njt_json_mut_val *arr,
    size_t idx)
{
    if (njt_json_likely(njt_json_mut_is_arr(arr))) {
        size_t len = unsafe_njt_json_get_len(arr);
        if (njt_json_likely(idx < len)) {
            unsafe_njt_json_set_len(arr, len - 1);
            if (njt_json_likely(len > 1)) {
                njt_json_mut_val *prev = ((njt_json_mut_val *)arr->uni.ptr);
                njt_json_mut_val *next = prev->next;
                while (idx-- > 0) {
                    prev = next;
                    next = next->next;
                }
                prev->next = next->next;
                if ((void *)next == arr->uni.ptr) arr->uni.ptr = prev;
                return next;
            } else {
                return ((njt_json_mut_val *)arr->uni.ptr);
            }
        }
    }
    return NULL;
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_remove_first(
    njt_json_mut_val *arr)
{
    if (njt_json_likely(njt_json_mut_is_arr(arr))) {
        size_t len = unsafe_njt_json_get_len(arr);
        if (len > 1) {
            njt_json_mut_val *prev = ((njt_json_mut_val *)arr->uni.ptr);
            njt_json_mut_val *next = prev->next;
            prev->next = next->next;
            unsafe_njt_json_set_len(arr, len - 1);
            return next;
        } else if (len == 1) {
            njt_json_mut_val *prev = ((njt_json_mut_val *)arr->uni.ptr);
            unsafe_njt_json_set_len(arr, 0);
            return prev;
        }
    }
    return NULL;
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_remove_last(
    njt_json_mut_val *arr)
{
    if (njt_json_likely(njt_json_mut_is_arr(arr))) {
        size_t len = unsafe_njt_json_get_len(arr);
        if (njt_json_likely(len > 1)) {
            njt_json_mut_val *prev = ((njt_json_mut_val *)arr->uni.ptr);
            njt_json_mut_val *next = prev->next;
            unsafe_njt_json_set_len(arr, len - 1);
            while (--len > 0) prev = prev->next;
            prev->next = next;
            next = (njt_json_mut_val *)arr->uni.ptr;
            arr->uni.ptr = prev;
            return next;
        } else if (len == 1) {
            njt_json_mut_val *prev = ((njt_json_mut_val *)arr->uni.ptr);
            unsafe_njt_json_set_len(arr, 0);
            return prev;
        }
    }
    return NULL;
}

njt_json_api_inline bool njt_json_mut_arr_remove_range(njt_json_mut_val *arr,
        size_t _idx, size_t _len)
{
    if (njt_json_likely(njt_json_mut_is_arr(arr))) {
        njt_json_mut_val *prev, *next;
        bool tail_removed;
        size_t len = unsafe_njt_json_get_len(arr);
        if (njt_json_unlikely(_idx + _len > len)) return false;
        if (njt_json_unlikely(_len == 0)) return true;
        unsafe_njt_json_set_len(arr, len - _len);
        if (njt_json_unlikely(len == _len)) return true;
        tail_removed = (_idx + _len == len);
        prev = ((njt_json_mut_val *)arr->uni.ptr);
        while (_idx-- > 0) prev = prev->next;
        next = prev->next;
        while (_len-- > 0) next = next->next;
        prev->next = next;
        if (njt_json_unlikely(tail_removed)) arr->uni.ptr = prev;
        return true;
    }
    return false;
}

njt_json_api_inline bool njt_json_mut_arr_clear(njt_json_mut_val *arr)
{
    if (njt_json_likely(njt_json_mut_is_arr(arr))) {
        unsafe_njt_json_set_len(arr, 0);
        return true;
    }
    return false;
}

njt_json_api_inline bool njt_json_mut_arr_rotate(njt_json_mut_val *arr,
        size_t idx)
{
    if (njt_json_likely(njt_json_mut_is_arr(arr) &&
                        unsafe_njt_json_get_len(arr) > idx)) {
        njt_json_mut_val *val = (njt_json_mut_val *)arr->uni.ptr;
        while (idx-- > 0) val = val->next;
        arr->uni.ptr = (void *)val;
        return true;
    }
    return false;
}



/*==============================================================================
 * Mutable JSON Array Modification Convenience API (Implementation)
 *============================================================================*/

njt_json_api_inline bool njt_json_mut_arr_add_val(njt_json_mut_val *arr,
        njt_json_mut_val *val)
{
    return njt_json_mut_arr_append(arr, val);
}

njt_json_api_inline bool njt_json_mut_arr_add_null(njt_json_mut_doc *doc,
        njt_json_mut_val *arr)
{
    if (njt_json_likely(doc && njt_json_mut_is_arr(arr))) {
        njt_json_mut_val *val = njt_json_mut_null(doc);
        return njt_json_mut_arr_append(arr, val);
    }
    return false;
}

njt_json_api_inline bool njt_json_mut_arr_add_true(njt_json_mut_doc *doc,
        njt_json_mut_val *arr)
{
    if (njt_json_likely(doc && njt_json_mut_is_arr(arr))) {
        njt_json_mut_val *val = njt_json_mut_true(doc);
        return njt_json_mut_arr_append(arr, val);
    }
    return false;
}

njt_json_api_inline bool njt_json_mut_arr_add_false(njt_json_mut_doc *doc,
        njt_json_mut_val *arr)
{
    if (njt_json_likely(doc && njt_json_mut_is_arr(arr))) {
        njt_json_mut_val *val = njt_json_mut_false(doc);
        return njt_json_mut_arr_append(arr, val);
    }
    return false;
}

njt_json_api_inline bool njt_json_mut_arr_add_bool(njt_json_mut_doc *doc,
        njt_json_mut_val *arr,
        bool _val)
{
    if (njt_json_likely(doc && njt_json_mut_is_arr(arr))) {
        njt_json_mut_val *val = njt_json_mut_bool(doc, _val);
        return njt_json_mut_arr_append(arr, val);
    }
    return false;
}

njt_json_api_inline bool njt_json_mut_arr_add_uint(njt_json_mut_doc *doc,
        njt_json_mut_val *arr,
        uint64_t num)
{
    if (njt_json_likely(doc && njt_json_mut_is_arr(arr))) {
        njt_json_mut_val *val = njt_json_mut_uint(doc, num);
        return njt_json_mut_arr_append(arr, val);
    }
    return false;
}

njt_json_api_inline bool njt_json_mut_arr_add_sint(njt_json_mut_doc *doc,
        njt_json_mut_val *arr,
        int64_t num)
{
    if (njt_json_likely(doc && njt_json_mut_is_arr(arr))) {
        njt_json_mut_val *val = njt_json_mut_sint(doc, num);
        return njt_json_mut_arr_append(arr, val);
    }
    return false;
}

njt_json_api_inline bool njt_json_mut_arr_add_int(njt_json_mut_doc *doc,
        njt_json_mut_val *arr,
        int64_t num)
{
    if (njt_json_likely(doc && njt_json_mut_is_arr(arr))) {
        njt_json_mut_val *val = njt_json_mut_sint(doc, num);
        return njt_json_mut_arr_append(arr, val);
    }
    return false;
}

njt_json_api_inline bool njt_json_mut_arr_add_real(njt_json_mut_doc *doc,
        njt_json_mut_val *arr,
        double num)
{
    if (njt_json_likely(doc && njt_json_mut_is_arr(arr))) {
        njt_json_mut_val *val = njt_json_mut_real(doc, num);
        return njt_json_mut_arr_append(arr, val);
    }
    return false;
}

njt_json_api_inline bool njt_json_mut_arr_add_str(njt_json_mut_doc *doc,
        njt_json_mut_val *arr,
        const char *str)
{
    if (njt_json_likely(doc && njt_json_mut_is_arr(arr))) {
        njt_json_mut_val *val = njt_json_mut_str(doc, str);
        return njt_json_mut_arr_append(arr, val);
    }
    return false;
}

njt_json_api_inline bool njt_json_mut_arr_add_strn(njt_json_mut_doc *doc,
        njt_json_mut_val *arr,
        const char *str, size_t len)
{
    if (njt_json_likely(doc && njt_json_mut_is_arr(arr))) {
        njt_json_mut_val *val = njt_json_mut_strn(doc, str, len);
        return njt_json_mut_arr_append(arr, val);
    }
    return false;
}

njt_json_api_inline bool njt_json_mut_arr_add_strcpy(njt_json_mut_doc *doc,
        njt_json_mut_val *arr,
        const char *str)
{
    if (njt_json_likely(doc && njt_json_mut_is_arr(arr))) {
        njt_json_mut_val *val = njt_json_mut_strcpy(doc, str);
        return njt_json_mut_arr_append(arr, val);
    }
    return false;
}

njt_json_api_inline bool njt_json_mut_arr_add_strncpy(njt_json_mut_doc *doc,
        njt_json_mut_val *arr,
        const char *str, size_t len)
{
    if (njt_json_likely(doc && njt_json_mut_is_arr(arr))) {
        njt_json_mut_val *val = njt_json_mut_strncpy(doc, str, len);
        return njt_json_mut_arr_append(arr, val);
    }
    return false;
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_add_arr(
    njt_json_mut_doc *doc,
    njt_json_mut_val *arr)
{
    if (njt_json_likely(doc && njt_json_mut_is_arr(arr))) {
        njt_json_mut_val *val = njt_json_mut_arr(doc);
        return njt_json_mut_arr_append(arr, val) ? val : NULL;
    }
    return NULL;
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_arr_add_obj(
    njt_json_mut_doc *doc,
    njt_json_mut_val *arr)
{
    if (njt_json_likely(doc && njt_json_mut_is_arr(arr))) {
        njt_json_mut_val *val = njt_json_mut_obj(doc);
        return njt_json_mut_arr_append(arr, val) ? val : NULL;
    }
    return NULL;
}



/*==============================================================================
 * Mutable JSON Object API (Implementation)
 *============================================================================*/

njt_json_api_inline size_t njt_json_mut_obj_size(njt_json_mut_val *obj)
{
    return njt_json_mut_is_obj(obj) ? unsafe_njt_json_get_len(obj) : 0;
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_obj_get(
    njt_json_mut_val *obj,
    const char *key_str)
{
    return njt_json_mut_obj_getn(obj, key_str, key_str ? strlen(key_str) : 0);
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_obj_getn(
    njt_json_mut_val *obj,
    const char *key_str,
    size_t key_len)
{
    uint64_t tag = (((uint64_t)key_len) << NJT_JSON_TAG_BIT) | NJT_JSON_TYPE_STR;
    size_t len = njt_json_mut_obj_size(obj);
    if (njt_json_likely(len && key_str)) {
        njt_json_mut_val *key = ((njt_json_mut_val *)obj->uni.ptr)->next->next;
        while (len-- > 0) {
            if (key->tag == tag &&
                memcmp(key->uni.ptr, key_str, key_len) == 0) {
                return key->next;
            }
            key = key->next->next;
        }
    }
    return NULL;
}



/*==============================================================================
 * Mutable JSON Object Iterator API (Implementation)
 *============================================================================*/

struct njt_json_mut_obj_iter {
    size_t idx;
    size_t max;
    njt_json_mut_val *cur;
    njt_json_mut_val *pre;
    njt_json_mut_val *obj;
};

njt_json_api_inline bool njt_json_mut_obj_iter_init(njt_json_mut_val *obj,
        njt_json_mut_obj_iter *iter)
{
    if (njt_json_likely(njt_json_mut_is_obj(obj) && iter)) {
        iter->idx = 0;
        iter->max = unsafe_njt_json_get_len(obj);
        iter->cur = iter->max ? (njt_json_mut_val *)obj->uni.ptr : NULL;
        iter->pre = NULL;
        iter->obj = obj;
        return true;
    }
    if (iter) memset(iter, 0, sizeof(njt_json_mut_obj_iter));
    return false;
}

njt_json_api_inline bool njt_json_mut_obj_iter_has_next(
    njt_json_mut_obj_iter *iter)
{
    return iter ? iter->idx < iter->max : false;
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_obj_iter_next(
    njt_json_mut_obj_iter *iter)
{
    if (iter && iter->idx < iter->max) {
        njt_json_mut_val *key = iter->cur;
        iter->pre = key;
        iter->cur = key->next->next;
        iter->idx++;
        return iter->cur;
    }
    return NULL;
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_obj_iter_get_val(
    njt_json_mut_val *key)
{
    return key->next;
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_obj_iter_remove(
    njt_json_mut_obj_iter *iter)
{
    if (njt_json_likely(iter && 0 < iter->idx && iter->idx <= iter->max)) {
        njt_json_mut_val *prev = iter->pre;
        njt_json_mut_val *cur = iter->cur;
        njt_json_mut_val *next = cur->next->next;
        if (njt_json_unlikely(iter->idx == iter->max)) iter->obj->uni.ptr = prev;
        iter->idx--;
        iter->max--;
        unsafe_njt_json_set_len(iter->obj, iter->max);
        prev->next->next = next;
        iter->cur = next;
        return cur;
    }
    return NULL;
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_obj_iter_get(
    njt_json_mut_obj_iter *iter, const char *key)
{
    return njt_json_mut_obj_iter_getn(iter, key, key ? strlen(key) : 0);
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_obj_iter_getn(
    njt_json_mut_obj_iter *iter, const char *key, size_t key_len)
{
    if (iter && key) {
        size_t idx = 0;
        size_t max = iter->max;
        njt_json_mut_val *pre, *cur = iter->cur;
        while (idx++ < max) {
            pre = cur;
            cur = cur->next->next;
            if (unsafe_njt_json_get_len(cur) == key_len &&
                memcmp(cur->uni.str, key, key_len) == 0) {
                iter->idx += idx;
                if (iter->idx > max) iter->idx -= max + 1;
                iter->pre = pre;
                iter->cur = cur;
                return cur->next;
            }
        }
    }
    return NULL;
}



/*==============================================================================
 * Mutable JSON Object Creation API (Implementation)
 *============================================================================*/

njt_json_api_inline njt_json_mut_val *njt_json_mut_obj(njt_json_mut_doc *doc)
{
    if (njt_json_likely(doc)) {
        njt_json_mut_val *val = unsafe_njt_json_mut_val(doc, 1);
        if (njt_json_likely(val)) {
            val->tag = NJT_JSON_TYPE_OBJ | NJT_JSON_SUBTYPE_NONE;
            return val;
        }
    }
    return NULL;
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_obj_with_str(
    njt_json_mut_doc *doc,
    const char **keys,
    const char **vals,
    size_t count)
{
    if (njt_json_likely(doc && ((count > 0 && keys && vals) || (count == 0)))) {
        njt_json_mut_val *obj = unsafe_njt_json_mut_val(doc, 1 + count * 2);
        if (njt_json_likely(obj)) {
            obj->tag = ((uint64_t)count << NJT_JSON_TAG_BIT) | NJT_JSON_TYPE_OBJ;
            if (count > 0) {
                size_t i;
                for (i = 0; i < count; i++) {
                    njt_json_mut_val *key = obj + (i * 2 + 1);
                    njt_json_mut_val *val = obj + (i * 2 + 2);
                    uint64_t key_len = (uint64_t)strlen(keys[i]);
                    uint64_t val_len = (uint64_t)strlen(vals[i]);
                    key->tag = (key_len << NJT_JSON_TAG_BIT) | NJT_JSON_TYPE_STR;
                    val->tag = (val_len << NJT_JSON_TAG_BIT) | NJT_JSON_TYPE_STR;
                    key->uni.str = keys[i];
                    val->uni.str = vals[i];
                    key->next = val;
                    val->next = val + 1;
                }
                obj[count * 2].next = obj + 1;
                obj->uni.ptr = obj + (count * 2 - 1);
            }
            return obj;
        }
    }
    return NULL;
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_obj_with_kv(
    njt_json_mut_doc *doc,
    const char **pairs,
    size_t count)
{
    if (njt_json_likely(doc && ((count > 0 && pairs) || (count == 0)))) {
        njt_json_mut_val *obj = unsafe_njt_json_mut_val(doc, 1 + count * 2);
        if (njt_json_likely(obj)) {
            obj->tag = ((uint64_t)count << NJT_JSON_TAG_BIT) | NJT_JSON_TYPE_OBJ;
            if (count > 0) {
                size_t i;
                for (i = 0; i < count; i++) {
                    njt_json_mut_val *key = obj + (i * 2 + 1);
                    njt_json_mut_val *val = obj + (i * 2 + 2);
                    const char *key_str = pairs[i * 2 + 0];
                    const char *val_str = pairs[i * 2 + 1];
                    uint64_t key_len = (uint64_t)strlen(key_str);
                    uint64_t val_len = (uint64_t)strlen(val_str);
                    key->tag = (key_len << NJT_JSON_TAG_BIT) | NJT_JSON_TYPE_STR;
                    val->tag = (val_len << NJT_JSON_TAG_BIT) | NJT_JSON_TYPE_STR;
                    key->uni.str = key_str;
                    val->uni.str = val_str;
                    key->next = val;
                    val->next = val + 1;
                }
                obj[count * 2].next = obj + 1;
                obj->uni.ptr = obj + (count * 2 - 1);
            }
            return obj;
        }
    }
    return NULL;
}



/*==============================================================================
 * Mutable JSON Object Modification API (Implementation)
 *============================================================================*/

njt_json_api_inline void unsafe_njt_json_mut_obj_add(njt_json_mut_val *obj,
        njt_json_mut_val *key,
        njt_json_mut_val *val,
        size_t len)
{
    if (njt_json_likely(len)) {
        njt_json_mut_val *prev_val = ((njt_json_mut_val *)obj->uni.ptr)->next;
        njt_json_mut_val *next_key = prev_val->next;
        prev_val->next = key;
        val->next = next_key;
    } else {
        val->next = key;
    }
    key->next = val;
    obj->uni.ptr = (void *)key;
    unsafe_njt_json_set_len(obj, len + 1);
}

njt_json_api_inline njt_json_mut_val *unsafe_njt_json_mut_obj_remove(
    njt_json_mut_val *obj,
    const char *key,
    size_t key_len,
    uint64_t key_tag)
{
    size_t obj_len = unsafe_njt_json_get_len(obj);
    if (obj_len) {
        njt_json_mut_val *pre_key = (njt_json_mut_val *)obj->uni.ptr;
        njt_json_mut_val *cur_key = pre_key->next->next;
        njt_json_mut_val *removed_item = NULL;
        size_t i;
        for (i = 0; i < obj_len; i++) {
            if (key_tag == cur_key->tag &&
                memcmp(key, cur_key->uni.ptr, key_len) == 0) {
                if (!removed_item) removed_item = cur_key->next;
                cur_key = cur_key->next->next;
                pre_key->next->next = cur_key;
                if (i + 1 == obj_len) obj->uni.ptr = pre_key;
                i--;
                obj_len--;
            } else {
                pre_key = cur_key;
                cur_key = cur_key->next->next;
            }
        }
        unsafe_njt_json_set_len(obj, obj_len);
        return removed_item;
    } else {
        return NULL;
    }
}

njt_json_api_inline bool unsafe_njt_json_mut_obj_replace(njt_json_mut_val *obj,
        njt_json_mut_val *key,
        njt_json_mut_val *val)
{
    size_t key_len = unsafe_njt_json_get_len(key);
    size_t obj_len = unsafe_njt_json_get_len(obj);
    if (obj_len) {
        njt_json_mut_val *pre_key = (njt_json_mut_val *)obj->uni.ptr;
        njt_json_mut_val *cur_key = pre_key->next->next;
        size_t i;
        for (i = 0; i < obj_len; i++) {
            if (key->tag == cur_key->tag &&
                memcmp(key->uni.str, cur_key->uni.ptr, key_len) == 0) {
                size_t cpy_len = sizeof(*key) - sizeof(key->next);
                njt_json_mut_val tmp;
                memcpy(&tmp, cur_key, cpy_len);
                memcpy(cur_key, key, cpy_len);
                memcpy(key, &tmp, cpy_len);

                memcpy(&tmp, cur_key->next, cpy_len);
                memcpy(cur_key->next, val, cpy_len);
                memcpy(val, &tmp, cpy_len);
                return true;
            } else {
                pre_key = cur_key;
                cur_key = cur_key->next->next;
            }
        }
    }
    return false;
}

njt_json_api_inline void unsafe_njt_json_mut_obj_rotate(njt_json_mut_val *obj,
        size_t idx)
{
    njt_json_mut_val *key = (njt_json_mut_val *)obj->uni.ptr;
    while (idx-- > 0) key = key->next->next;
    obj->uni.ptr = (void *)key;
}

njt_json_api_inline bool njt_json_mut_obj_add(njt_json_mut_val *obj,
        njt_json_mut_val *key,
        njt_json_mut_val *val)
{
    if (njt_json_likely(njt_json_mut_is_obj(obj) &&
                        njt_json_mut_is_str(key) && val)) {
        unsafe_njt_json_mut_obj_add(obj, key, val, unsafe_njt_json_get_len(obj));
        return true;
    }
    return false;
}

njt_json_api_inline bool njt_json_mut_obj_put(njt_json_mut_val *obj,
        njt_json_mut_val *key,
        njt_json_mut_val *val)
{
    if (njt_json_likely(njt_json_mut_is_obj(obj) &&
                        njt_json_mut_is_str(key))) {
        unsafe_njt_json_mut_obj_remove(obj, key->uni.str,
                                       unsafe_njt_json_get_len(key), key->tag);
        if (njt_json_likely(val)) {
            unsafe_njt_json_mut_obj_add(obj, key, val,
                                        unsafe_njt_json_get_len(obj));
        }
        return true;
    }
    return false;
}

njt_json_api_inline bool njt_json_mut_obj_insert(njt_json_mut_val *obj,
        njt_json_mut_val *key,
        njt_json_mut_val *val,
        size_t idx)
{
    if (njt_json_likely(njt_json_mut_is_obj(obj) &&
                        njt_json_mut_is_str(key) && val)) {
        size_t len = unsafe_njt_json_get_len(obj);
        if (njt_json_likely(len >= idx)) {
            if (len > idx) {
                void *ptr = obj->uni.ptr;
                unsafe_njt_json_mut_obj_rotate(obj, idx);
                unsafe_njt_json_mut_obj_add(obj, key, val, len);
                obj->uni.ptr = ptr;
            } else {
                unsafe_njt_json_mut_obj_add(obj, key, val, len);
            }
            return true;
        }
    }
    return false;
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_obj_remove(
    njt_json_mut_val *obj,
    njt_json_mut_val *key)
{
    if (njt_json_likely(njt_json_mut_is_obj(obj) && njt_json_mut_is_str(key))) {
        return unsafe_njt_json_mut_obj_remove(obj, key->uni.str,
                                              unsafe_njt_json_get_len(key), key->tag);
    }
    return NULL;
}

njt_json_api_inline bool njt_json_mut_obj_clear(njt_json_mut_val *obj)
{
    if (njt_json_likely(njt_json_mut_is_obj(obj))) {
        unsafe_njt_json_set_len(obj, 0);
        return true;
    }
    return false;
}

njt_json_api_inline bool njt_json_mut_obj_replace(njt_json_mut_val *obj,
        njt_json_mut_val *key,
        njt_json_mut_val *val)
{
    if (njt_json_likely(njt_json_mut_is_obj(obj) &&
                        njt_json_mut_is_str(key) && val)) {
        return unsafe_njt_json_mut_obj_replace(obj, key, val);
    }
    return false;
}

njt_json_api_inline bool njt_json_mut_obj_rotate(njt_json_mut_val *obj,
        size_t idx)
{
    if (njt_json_likely(njt_json_mut_is_obj(obj) &&
                        unsafe_njt_json_get_len(obj) > idx)) {
        unsafe_njt_json_mut_obj_rotate(obj, idx);
        return true;
    }
    return false;
}



/*==============================================================================
 * Mutable JSON Object Modification Convenience API (Implementation)
 *============================================================================*/

#define njt_json_mut_obj_add_func(func) \
    if (njt_json_likely(doc && njt_json_mut_is_obj(obj) && _key)) { \
        njt_json_mut_val *key = unsafe_njt_json_mut_val(doc, 2); \
        if (njt_json_likely(key)) { \
            size_t len = unsafe_njt_json_get_len(obj); \
            njt_json_mut_val *val = key + 1; \
            key->tag = NJT_JSON_TYPE_STR | NJT_JSON_SUBTYPE_NONE; \
            key->tag |= (uint64_t)strlen(_key) << NJT_JSON_TAG_BIT; \
            key->uni.str = _key; \
            func \
            unsafe_njt_json_mut_obj_add(obj, key, val, len); \
            return true; \
        } \
    } \
    return false

njt_json_api_inline bool njt_json_mut_obj_add_null(njt_json_mut_doc *doc,
        njt_json_mut_val *obj,
        const char *_key)
{
    njt_json_mut_obj_add_func({
        val->tag = NJT_JSON_TYPE_NULL | NJT_JSON_SUBTYPE_NONE;
    });
}

njt_json_api_inline bool njt_json_mut_obj_add_true(njt_json_mut_doc *doc,
        njt_json_mut_val *obj,
        const char *_key)
{
    njt_json_mut_obj_add_func({
        val->tag = NJT_JSON_TYPE_BOOL | NJT_JSON_SUBTYPE_TRUE;
    });
}

njt_json_api_inline bool njt_json_mut_obj_add_false(njt_json_mut_doc *doc,
        njt_json_mut_val *obj,
        const char *_key)
{
    njt_json_mut_obj_add_func({
        val->tag = NJT_JSON_TYPE_BOOL | NJT_JSON_SUBTYPE_FALSE;
    });
}

njt_json_api_inline bool njt_json_mut_obj_add_bool(njt_json_mut_doc *doc,
        njt_json_mut_val *obj,
        const char *_key,
        bool _val)
{
    njt_json_mut_obj_add_func({
        val->tag = NJT_JSON_TYPE_BOOL | (uint8_t)((uint8_t)(_val) << 3);
    });
}

njt_json_api_inline bool njt_json_mut_obj_add_uint(njt_json_mut_doc *doc,
        njt_json_mut_val *obj,
        const char *_key,
        uint64_t _val)
{
    njt_json_mut_obj_add_func({
        val->tag = NJT_JSON_TYPE_NUM | NJT_JSON_SUBTYPE_UINT;
        val->uni.u64 = _val;
    });
}

njt_json_api_inline bool njt_json_mut_obj_add_sint(njt_json_mut_doc *doc,
        njt_json_mut_val *obj,
        const char *_key,
        int64_t _val)
{
    njt_json_mut_obj_add_func({
        val->tag = NJT_JSON_TYPE_NUM | NJT_JSON_SUBTYPE_SINT;
        val->uni.i64 = _val;
    });
}

njt_json_api_inline bool njt_json_mut_obj_add_int(njt_json_mut_doc *doc,
        njt_json_mut_val *obj,
        const char *_key,
        int64_t _val)
{
    njt_json_mut_obj_add_func({
        val->tag = NJT_JSON_TYPE_NUM | NJT_JSON_SUBTYPE_SINT;
        val->uni.i64 = _val;
    });
}

njt_json_api_inline bool njt_json_mut_obj_add_real(njt_json_mut_doc *doc,
        njt_json_mut_val *obj,
        const char *_key,
        double _val)
{
    njt_json_mut_obj_add_func({
        val->tag = NJT_JSON_TYPE_NUM | NJT_JSON_SUBTYPE_REAL;
        val->uni.f64 = _val;
    });
}

njt_json_api_inline bool njt_json_mut_obj_add_str(njt_json_mut_doc *doc,
        njt_json_mut_val *obj,
        const char *_key,
        const char *_val)
{
    if (njt_json_unlikely(!_val)) return false;
    njt_json_mut_obj_add_func({
        val->tag = ((uint64_t)strlen(_val) << NJT_JSON_TAG_BIT) | NJT_JSON_TYPE_STR;
        val->uni.str = _val;
    });
}

njt_json_api_inline bool njt_json_mut_obj_add_strn(njt_json_mut_doc *doc,
        njt_json_mut_val *obj,
        const char *_key,
        const char *_val,
        size_t _len)
{
    if (njt_json_unlikely(!_val)) return false;
    njt_json_mut_obj_add_func({
        val->tag = ((uint64_t)_len << NJT_JSON_TAG_BIT) | NJT_JSON_TYPE_STR;
        val->uni.str = _val;
    });
}

njt_json_api_inline bool njt_json_mut_obj_add_strcpy(njt_json_mut_doc *doc,
        njt_json_mut_val *obj,
        const char *_key,
        const char *_val)
{
    if (njt_json_unlikely(!_val)) return false;
    njt_json_mut_obj_add_func({
        size_t _len = strlen(_val);
        val->uni.str = unsafe_njt_json_mut_strncpy(doc, _val, _len);
        if (njt_json_unlikely(!val->uni.str)) return false;
        val->tag = ((uint64_t)_len << NJT_JSON_TAG_BIT) | NJT_JSON_TYPE_STR;
    });
}

njt_json_api_inline bool njt_json_mut_obj_add_strncpy(njt_json_mut_doc *doc,
        njt_json_mut_val *obj,
        const char *_key,
        const char *_val,
        size_t _len)
{
    if (njt_json_unlikely(!_val)) return false;
    njt_json_mut_obj_add_func({
        val->uni.str = unsafe_njt_json_mut_strncpy(doc, _val, _len);
        if (njt_json_unlikely(!val->uni.str)) return false;
        val->tag = ((uint64_t)_len << NJT_JSON_TAG_BIT) | NJT_JSON_TYPE_STR;
    });
}

njt_json_api_inline bool njt_json_mut_obj_add_val(njt_json_mut_doc *doc,
        njt_json_mut_val *obj,
        const char *_key,
        njt_json_mut_val *_val)
{
    if (njt_json_unlikely(!_val)) return false;
    njt_json_mut_obj_add_func({
        val = _val;
    });
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_obj_remove_str(
    njt_json_mut_val *obj,
    const char *key)
{
    return njt_json_mut_obj_remove_strn(obj, key, key ? strlen(key) : 0);
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_obj_remove_strn(
    njt_json_mut_val *obj,
    const char *_key,
    size_t _len)
{
    if (njt_json_likely(njt_json_mut_is_obj(obj) && _key)) {
        njt_json_mut_val *key;
        njt_json_mut_obj_iter iter;
        njt_json_mut_val *val_removed = NULL;
        njt_json_mut_obj_iter_init(obj, &iter);
        while ((key = njt_json_mut_obj_iter_next(&iter)) != NULL) {
            if (unsafe_njt_json_get_len(key) == _len &&
                memcmp(key->uni.str, _key, _len) == 0) {
                if (!val_removed) val_removed = key->next;
                njt_json_mut_obj_iter_remove(&iter);
            }
        }
        return val_removed;
    }
    return NULL;
}



/*==============================================================================
 * JSON Pointer API (Implementation)
 *============================================================================*/

njt_json_api njt_json_val *unsafe_njt_json_get_pointer(njt_json_val *val,
        const char *ptr,
        size_t len);

njt_json_api njt_json_mut_val *unsafe_njt_json_mut_get_pointer(
    njt_json_mut_val *val,
    const char *ptr,
    size_t len);

njt_json_api_inline njt_json_val *njt_json_get_pointer(njt_json_val *val,
        const char *ptr)
{
    if (val && ptr) {
        if (*ptr == '\0') return val;
        if (*ptr != '/') return NULL;
        return unsafe_njt_json_get_pointer(val, ptr, strlen(ptr));
    }
    return NULL;
}

njt_json_api_inline njt_json_val *njt_json_doc_get_pointer(njt_json_doc *doc,
        const char *ptr)
{
    if (doc) return njt_json_get_pointer(doc->root, ptr);
    return NULL;
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_get_pointer(
    njt_json_mut_val *val,
    const char *ptr)
{
    if (val && ptr) {
        if (*ptr == '\0') return val;
        if (*ptr != '/') return NULL;
        return unsafe_njt_json_mut_get_pointer(val, ptr, strlen(ptr));
    }
    return NULL;
}

njt_json_api_inline njt_json_mut_val *njt_json_mut_doc_get_pointer(
    njt_json_mut_doc *doc, const char *ptr)
{
    if (doc) return njt_json_mut_get_pointer(doc->root, ptr);
    return NULL;
}



/*==============================================================================
 * Compiler Hint End
 *============================================================================*/

#if defined(__clang__)
#   pragma clang diagnostic pop
#elif defined(__GNUC__)
#   if (__GNUC__ > 4) || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6)
#   pragma GCC diagnostic pop
#   endif
#elif defined(_MSC_VER)
#   pragma warning(pop)
#endif /* warning suppress end */

#ifdef __cplusplus
}
#endif /* extern "C" end */

#endif /* NJT_JSON_H */

