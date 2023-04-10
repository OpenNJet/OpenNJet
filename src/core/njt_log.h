
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_LOG_H_INCLUDED_
#define _NJT_LOG_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


#define NJT_LOG_STDERR            0
#define NJT_LOG_EMERG             1
#define NJT_LOG_ALERT             2
#define NJT_LOG_CRIT              3
#define NJT_LOG_ERR               4
#define NJT_LOG_WARN              5
#define NJT_LOG_NOTICE            6
#define NJT_LOG_INFO              7
#define NJT_LOG_DEBUG             8

#define NJT_LOG_DEBUG_CORE        0x010
#define NJT_LOG_DEBUG_ALLOC       0x020
#define NJT_LOG_DEBUG_MUTEX       0x040
#define NJT_LOG_DEBUG_EVENT       0x080
#define NJT_LOG_DEBUG_HTTP        0x100
#define NJT_LOG_DEBUG_MAIL        0x200
#define NJT_LOG_DEBUG_STREAM      0x400

/*
 * do not forget to update debug_levels[] in src/core/njt_log.c
 * after the adding a new debug level
 */

#define NJT_LOG_DEBUG_FIRST       NJT_LOG_DEBUG_CORE
#define NJT_LOG_DEBUG_LAST        NJT_LOG_DEBUG_STREAM
#define NJT_LOG_DEBUG_CONNECTION  0x80000000
#define NJT_LOG_DEBUG_ALL         0x7ffffff0


typedef u_char *(*njt_log_handler_pt) (njt_log_t *log, u_char *buf, size_t len);
typedef void (*njt_log_writer_pt) (njt_log_t *log, njt_uint_t level,
    u_char *buf, size_t len);


struct njt_log_s {
    njt_uint_t           log_level;
    njt_open_file_t     *file;

    njt_atomic_uint_t    connection;

    time_t               disk_full_time;

    njt_log_handler_pt   handler;
    void                *data;

    njt_log_writer_pt    writer;
    void                *wdata;

    /*
     * we declare "action" as "char *" because the actions are usually
     * the static strings and in the "u_char *" case we have to override
     * their types all the time
     */

    char                *action;

    njt_log_t           *next;
};


#define NJT_MAX_ERROR_STR   2048


/*********************************/

#if (NJT_HAVE_C99_VARIADIC_MACROS)

#define NJT_HAVE_VARIADIC_MACROS  1

#define njt_log_error(level, log, ...)                                        \
    if ((log)->log_level >= level) njt_log_error_core(level, log, __VA_ARGS__)

void njt_log_error_core(njt_uint_t level, njt_log_t *log, njt_err_t err,
    const char *fmt, ...);

#define njt_log_debug(level, log, ...)                                        \
    if ((log)->log_level & level)                                             \
        njt_log_error_core(NJT_LOG_DEBUG, log, __VA_ARGS__)

/*********************************/

#elif (NJT_HAVE_GCC_VARIADIC_MACROS)

#define NJT_HAVE_VARIADIC_MACROS  1

#define njt_log_error(level, log, args...)                                    \
    if ((log)->log_level >= level) njt_log_error_core(level, log, args)

void njt_log_error_core(njt_uint_t level, njt_log_t *log, njt_err_t err,
    const char *fmt, ...);

#define njt_log_debug(level, log, args...)                                    \
    if ((log)->log_level & level)                                             \
        njt_log_error_core(NJT_LOG_DEBUG, log, args)

/*********************************/

#else /* no variadic macros */

#define NJT_HAVE_VARIADIC_MACROS  0

void njt_cdecl njt_log_error(njt_uint_t level, njt_log_t *log, njt_err_t err,
    const char *fmt, ...);
void njt_log_error_core(njt_uint_t level, njt_log_t *log, njt_err_t err,
    const char *fmt, va_list args);
void njt_cdecl njt_log_debug_core(njt_log_t *log, njt_err_t err,
    const char *fmt, ...);


#endif /* variadic macros */


/*********************************/

#if (NJT_DEBUG)

#if (NJT_HAVE_VARIADIC_MACROS)

#define njt_log_debug0(level, log, err, fmt)                                  \
        njt_log_debug(level, log, err, fmt)

#define njt_log_debug1(level, log, err, fmt, arg1)                            \
        njt_log_debug(level, log, err, fmt, arg1)

#define njt_log_debug2(level, log, err, fmt, arg1, arg2)                      \
        njt_log_debug(level, log, err, fmt, arg1, arg2)

#define njt_log_debug3(level, log, err, fmt, arg1, arg2, arg3)                \
        njt_log_debug(level, log, err, fmt, arg1, arg2, arg3)

#define njt_log_debug4(level, log, err, fmt, arg1, arg2, arg3, arg4)          \
        njt_log_debug(level, log, err, fmt, arg1, arg2, arg3, arg4)

#define njt_log_debug5(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5)    \
        njt_log_debug(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5)

#define njt_log_debug6(level, log, err, fmt,                                  \
                       arg1, arg2, arg3, arg4, arg5, arg6)                    \
        njt_log_debug(level, log, err, fmt,                                   \
                       arg1, arg2, arg3, arg4, arg5, arg6)

#define njt_log_debug7(level, log, err, fmt,                                  \
                       arg1, arg2, arg3, arg4, arg5, arg6, arg7)              \
        njt_log_debug(level, log, err, fmt,                                   \
                       arg1, arg2, arg3, arg4, arg5, arg6, arg7)

#define njt_log_debug8(level, log, err, fmt,                                  \
                       arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)        \
        njt_log_debug(level, log, err, fmt,                                   \
                       arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)


#else /* no variadic macros */

#define njt_log_debug0(level, log, err, fmt)                                  \
    if ((log)->log_level & level)                                             \
        njt_log_debug_core(log, err, fmt)

#define njt_log_debug1(level, log, err, fmt, arg1)                            \
    if ((log)->log_level & level)                                             \
        njt_log_debug_core(log, err, fmt, arg1)

#define njt_log_debug2(level, log, err, fmt, arg1, arg2)                      \
    if ((log)->log_level & level)                                             \
        njt_log_debug_core(log, err, fmt, arg1, arg2)

#define njt_log_debug3(level, log, err, fmt, arg1, arg2, arg3)                \
    if ((log)->log_level & level)                                             \
        njt_log_debug_core(log, err, fmt, arg1, arg2, arg3)

#define njt_log_debug4(level, log, err, fmt, arg1, arg2, arg3, arg4)          \
    if ((log)->log_level & level)                                             \
        njt_log_debug_core(log, err, fmt, arg1, arg2, arg3, arg4)

#define njt_log_debug5(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5)    \
    if ((log)->log_level & level)                                             \
        njt_log_debug_core(log, err, fmt, arg1, arg2, arg3, arg4, arg5)

#define njt_log_debug6(level, log, err, fmt,                                  \
                       arg1, arg2, arg3, arg4, arg5, arg6)                    \
    if ((log)->log_level & level)                                             \
        njt_log_debug_core(log, err, fmt, arg1, arg2, arg3, arg4, arg5, arg6)

#define njt_log_debug7(level, log, err, fmt,                                  \
                       arg1, arg2, arg3, arg4, arg5, arg6, arg7)              \
    if ((log)->log_level & level)                                             \
        njt_log_debug_core(log, err, fmt,                                     \
                       arg1, arg2, arg3, arg4, arg5, arg6, arg7)

#define njt_log_debug8(level, log, err, fmt,                                  \
                       arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)        \
    if ((log)->log_level & level)                                             \
        njt_log_debug_core(log, err, fmt,                                     \
                       arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)

#endif

#else /* !NJT_DEBUG */

#define njt_log_debug0(level, log, err, fmt)
#define njt_log_debug1(level, log, err, fmt, arg1)
#define njt_log_debug2(level, log, err, fmt, arg1, arg2)
#define njt_log_debug3(level, log, err, fmt, arg1, arg2, arg3)
#define njt_log_debug4(level, log, err, fmt, arg1, arg2, arg3, arg4)
#define njt_log_debug5(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5)
#define njt_log_debug6(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5, arg6)
#define njt_log_debug7(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5,    \
                       arg6, arg7)
#define njt_log_debug8(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5,    \
                       arg6, arg7, arg8)

#endif

/*********************************/

njt_log_t *njt_log_init(u_char *prefix, u_char *error_log);
void njt_cdecl njt_log_abort(njt_err_t err, const char *fmt, ...);
void njt_cdecl njt_log_stderr(njt_err_t err, const char *fmt, ...);
u_char *njt_log_errno(u_char *buf, u_char *last, njt_err_t err);
njt_int_t njt_log_open_default(njt_cycle_t *cycle);
njt_int_t njt_log_redirect_stderr(njt_cycle_t *cycle);
njt_log_t *njt_log_get_file_log(njt_log_t *head);
char *njt_log_set_log(njt_conf_t *cf, njt_log_t **head);


/*
 * njt_write_stderr() cannot be implemented as macro, since
 * MSVC does not allow to use #ifdef inside macro parameters.
 *
 * njt_write_fd() is used instead of njt_write_console(), since
 * CharToOemBuff() inside njt_write_console() cannot be used with
 * read only buffer as destination and CharToOemBuff() is not needed
 * for njt_write_stderr() anyway.
 */
static njt_inline void
njt_write_stderr(char *text)
{
    (void) njt_write_fd(njt_stderr, text, njt_strlen(text));
}


static njt_inline void
njt_write_stdout(char *text)
{
    (void) njt_write_fd(njt_stdout, text, njt_strlen(text));
}


extern njt_module_t  njt_errlog_module;
extern njt_uint_t    njt_use_stderr;


#endif /* _NJT_LOG_H_INCLUDED_ */
