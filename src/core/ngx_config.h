
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NJET_CONFIG_H_INCLUDED_
#define _NJET_CONFIG_H_INCLUDED_


#include <ngx_auto_headers.h>


#if defined __DragonFly__ && !defined __FreeBSD__
#define __FreeBSD__        4
#define __FreeBSD_version  480101
#endif


#if (NJET_FREEBSD)
#include <ngx_freebsd_config.h>


#elif (NJET_LINUX)
#include <ngx_linux_config.h>


#elif (NJET_SOLARIS)
#include <ngx_solaris_config.h>


#elif (NJET_DARWIN)
#include <ngx_darwin_config.h>


#elif (NJET_WIN32)
#include <ngx_win32_config.h>


#else /* POSIX */
#include <ngx_posix_config.h>

#endif


#ifndef NJET_HAVE_SO_SNDLOWAT
#define NJET_HAVE_SO_SNDLOWAT     1
#endif


#if !(NJET_WIN32)

#define ngx_signal_helper(n)     SIG##n
#define ngx_signal_value(n)      ngx_signal_helper(n)

#define ngx_random               random

/* TODO: #ifndef */
#define NJET_SHUTDOWN_SIGNAL      QUIT
#define NJET_TERMINATE_SIGNAL     TERM
#define NJET_NOACCEPT_SIGNAL      WINCH
#define NJET_RECONFIGURE_SIGNAL   HUP

#if (NJET_LINUXTHREADS)
#define NJET_REOPEN_SIGNAL        INFO
#define NJET_CHANGEBIN_SIGNAL     XCPU
#else
#define NJET_REOPEN_SIGNAL        USR1
#define NJET_CHANGEBIN_SIGNAL     USR2
#endif

#define ngx_cdecl
#define ngx_libc_cdecl

#endif

typedef intptr_t        ngx_int_t;
typedef uintptr_t       ngx_uint_t;
typedef intptr_t        ngx_flag_t;


#define NJET_INT32_LEN   (sizeof("-2147483648") - 1)
#define NJET_INT64_LEN   (sizeof("-9223372036854775808") - 1)

#if (NJET_PTR_SIZE == 4)
#define NJET_INT_T_LEN   NJET_INT32_LEN
#define NJET_MAX_INT_T_VALUE  2147483647

#else
#define NJET_INT_T_LEN   NJET_INT64_LEN
#define NJET_MAX_INT_T_VALUE  9223372036854775807
#endif


#ifndef NJET_ALIGNMENT
#define NJET_ALIGNMENT   sizeof(unsigned long)    /* platform word */
#endif

#define ngx_align(d, a)     (((d) + (a - 1)) & ~(a - 1))
#define ngx_align_ptr(p, a)                                                   \
    (u_char *) (((uintptr_t) (p) + ((uintptr_t) a - 1)) & ~((uintptr_t) a - 1))


#define ngx_abort       abort


/* TODO: platform specific: array[NJET_INVALID_ARRAY_INDEX] must cause SIGSEGV */
#define NJET_INVALID_ARRAY_INDEX 0x80000000


/* TODO: auto_conf: ngx_inline   inline __inline __inline__ */
#ifndef ngx_inline
#define ngx_inline      inline
#endif

#ifndef INADDR_NONE  /* Solaris */
#define INADDR_NONE  ((unsigned int) -1)
#endif

#ifdef MAXHOSTNAMELEN
#define NJET_MAXHOSTNAMELEN  MAXHOSTNAMELEN
#else
#define NJET_MAXHOSTNAMELEN  256
#endif


#define NJET_MAX_UINT32_VALUE  (uint32_t) 0xffffffff
#define NJET_MAX_INT32_VALUE   (uint32_t) 0x7fffffff


#if (NJET_COMPAT)

#define NJET_COMPAT_BEGIN(slots)  uint64_t spare[slots];
#define NJET_COMPAT_END

#else

#define NJET_COMPAT_BEGIN(slots)
#define NJET_COMPAT_END

#endif


#endif /* _NJET_CONFIG_H_INCLUDED_ */
