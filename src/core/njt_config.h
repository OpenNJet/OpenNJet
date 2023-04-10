
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_CONFIG_H_INCLUDED_
#define _NJT_CONFIG_H_INCLUDED_


#include <njt_auto_headers.h>


#if defined __DragonFly__ && !defined __FreeBSD__
#define __FreeBSD__        4
#define __FreeBSD_version  480101
#endif


#if (NJT_FREEBSD)
#include <njt_freebsd_config.h>


#elif (NJT_LINUX)
#include <njt_linux_config.h>


#elif (NJT_SOLARIS)
#include <njt_solaris_config.h>


#elif (NJT_DARWIN)
#include <njt_darwin_config.h>


#elif (NJT_WIN32)
#include <njt_win32_config.h>


#else /* POSIX */
#include <njt_posix_config.h>

#endif


#ifndef NJT_HAVE_SO_SNDLOWAT
#define NJT_HAVE_SO_SNDLOWAT     1
#endif


#if !(NJT_WIN32)

#define njt_signal_helper(n)     SIG##n
#define njt_signal_value(n)      njt_signal_helper(n)

#define njt_random               random

/* TODO: #ifndef */
#define NJT_SHUTDOWN_SIGNAL      QUIT
#define NJT_TERMINATE_SIGNAL     TERM
#define NJT_NOACCEPT_SIGNAL      WINCH
#define NJT_RECONFIGURE_SIGNAL   HUP

#if (NJT_LINUXTHREADS)
#define NJT_REOPEN_SIGNAL        INFO
#define NJT_CHANGEBIN_SIGNAL     XCPU
#else
#define NJT_REOPEN_SIGNAL        USR1
#define NJT_CHANGEBIN_SIGNAL     USR2
#endif

#define njt_cdecl
#define njt_libc_cdecl

#endif

typedef intptr_t        njt_int_t;
typedef uintptr_t       njt_uint_t;
typedef intptr_t        njt_flag_t;


#define NJT_INT32_LEN   (sizeof("-2147483648") - 1)
#define NJT_INT64_LEN   (sizeof("-9223372036854775808") - 1)

#if (NJT_PTR_SIZE == 4)
#define NJT_INT_T_LEN   NJT_INT32_LEN
#define NJT_MAX_INT_T_VALUE  2147483647

#else
#define NJT_INT_T_LEN   NJT_INT64_LEN
#define NJT_MAX_INT_T_VALUE  9223372036854775807
#endif


#ifndef NJT_ALIGNMENT
#define NJT_ALIGNMENT   sizeof(unsigned long)    /* platform word */
#endif

#define njt_align(d, a)     (((d) + (a - 1)) & ~(a - 1))
#define njt_align_ptr(p, a)                                                   \
    (u_char *) (((uintptr_t) (p) + ((uintptr_t) a - 1)) & ~((uintptr_t) a - 1))


#define njt_abort       abort


/* TODO: platform specific: array[NJT_INVALID_ARRAY_INDEX] must cause SIGSEGV */
#define NJT_INVALID_ARRAY_INDEX 0x80000000


/* TODO: auto_conf: njt_inline   inline __inline __inline__ */
#ifndef njt_inline
#define njt_inline      inline
#endif

#ifndef INADDR_NONE  /* Solaris */
#define INADDR_NONE  ((unsigned int) -1)
#endif

#ifdef MAXHOSTNAMELEN
#define NJT_MAXHOSTNAMELEN  MAXHOSTNAMELEN
#else
#define NJT_MAXHOSTNAMELEN  256
#endif


#define NJT_MAX_UINT32_VALUE  (uint32_t) 0xffffffff
#define NJT_MAX_INT32_VALUE   (uint32_t) 0x7fffffff


#if (NJT_COMPAT)

#define NJT_COMPAT_BEGIN(slots)  uint64_t spare[slots];
#define NJT_COMPAT_END

#else

#define NJT_COMPAT_BEGIN(slots)
#define NJT_COMPAT_END

#endif


#endif /* _NJT_CONFIG_H_INCLUDED_ */
