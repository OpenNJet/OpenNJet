
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_WIN32_CONFIG_H_INCLUDED_
#define _NJT_WIN32_CONFIG_H_INCLUDED_


#undef  WIN32
#define WIN32         0x0400
#define _WIN32_WINNT  0x0501


#define STRICT
#define WIN32_LEAN_AND_MEAN

/* enable getenv() and gmtime() in msvc8 */
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_DEPRECATE

/* enable gethostbyname() in msvc2015 */
#if !(NJT_HAVE_INET6)
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif

/*
 * we need to include <windows.h> explicitly before <winsock2.h> because
 * the warning 4201 is enabled in <windows.h>
 */
#include <windows.h>

#ifdef _MSC_VER
#pragma warning(disable:4201)
#endif

#include <winsock2.h>
#include <ws2tcpip.h>  /* ipv6 */
#include <mswsock.h>
#include <shellapi.h>
#include <stddef.h>    /* offsetof() */

#ifdef __MINGW64_VERSION_MAJOR

/* GCC MinGW-w64 supports _FILE_OFFSET_BITS */
#define _FILE_OFFSET_BITS 64

#elif defined __GNUC__

/* GCC MinGW's stdio.h includes sys/types.h */
#define _OFF_T_
#define __have_typedef_off_t

#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#ifdef __GNUC__
#include <stdint.h>
#endif
#include <ctype.h>
#include <locale.h>

#ifdef __WATCOMC__
#define _TIME_T_DEFINED
typedef long  time_t;
/* OpenWatcom defines time_t as "unsigned long" */
#endif

#include <time.h>      /* localtime(), strftime() */


#ifdef _MSC_VER

/* the end of the precompiled headers */
#pragma hdrstop

#pragma warning(default:4201)

/* 'type cast': from function pointer to data pointer */
#pragma warning(disable:4054)

/* 'type cast': from data pointer to function pointer */
#pragma warning(disable:4055)

/* 'function' : different 'const' qualifiers */
#pragma warning(disable:4090)

/* unreferenced formal parameter */
#pragma warning(disable:4100)

/* FD_SET() and FD_CLR(): conditional expression is constant */
#pragma warning(disable:4127)

/* conversion from 'type1' to 'type2', possible loss of data */
#pragma warning(disable:4244)

/* conversion from 'size_t' to 'type', possible loss of data */
#pragma warning(disable:4267)

/* array is too small to include a terminating null character */
#pragma warning(disable:4295)

/* conversion from 'type1' to 'type2' of greater size */
#pragma warning(disable:4306)

#endif


#ifdef __WATCOMC__

/* symbol 'njt_rbtree_min' has been defined, but not referenced */
#pragma disable_message(202)

#endif


#ifdef __BORLANDC__

/* the end of the precompiled headers */
#pragma hdrstop

/* functions containing (for|while|some if) are not expanded inline */
#pragma warn -8027

/* unreferenced formal parameter */
#pragma warn -8057

/* suspicious pointer arithmetic */
#pragma warn -8072

#endif


#include <njt_auto_config.h>


#define njt_inline          __inline
#define njt_cdecl           __cdecl


#ifdef _MSC_VER
typedef unsigned __int32    uint32_t;
typedef __int32             int32_t;
typedef unsigned __int16    uint16_t;
#define njt_libc_cdecl      __cdecl

#elif defined __BORLANDC__
typedef unsigned __int32    uint32_t;
typedef __int32             int32_t;
typedef unsigned __int16    uint16_t;
#define njt_libc_cdecl      __cdecl

#else /* __WATCOMC__ */
typedef unsigned int        uint32_t;
typedef int                 int32_t;
typedef unsigned short int  uint16_t;
#define njt_libc_cdecl

#endif

typedef __int64             int64_t;
typedef unsigned __int64    uint64_t;

#if __BORLANDC__
typedef int                 intptr_t;
typedef u_int               uintptr_t;
#endif


#ifndef __MINGW64_VERSION_MAJOR

/* Windows defines off_t as long, which is 32-bit */
typedef __int64             off_t;
#define _OFF_T_DEFINED

#endif


#ifdef __WATCOMC__

/* off_t is redefined by sys/types.h used by zlib.h */
#define __TYPES_H_INCLUDED
typedef int                 dev_t;
typedef unsigned int        ino_t;

#elif __BORLANDC__

/* off_t is redefined by sys/types.h used by zlib.h */
#define __TYPES_H

typedef int                 dev_t;
typedef unsigned int        ino_t;

#endif


#ifndef __GNUC__
#ifdef _WIN64
typedef __int64             ssize_t;
#else
typedef int                 ssize_t;
#endif
#endif


typedef uint32_t            in_addr_t;
typedef u_short             in_port_t;
typedef int                 sig_atomic_t;


#ifdef _WIN64

#define NJT_PTR_SIZE            8
#define NJT_SIZE_T_LEN          (sizeof("-9223372036854775808") - 1)
#define NJT_MAX_SIZE_T_VALUE    9223372036854775807
#define NJT_TIME_T_LEN          (sizeof("-9223372036854775808") - 1)
#define NJT_TIME_T_SIZE         8
#define NJT_MAX_TIME_T_VALUE    9223372036854775807

#else

#define NJT_PTR_SIZE            4
#define NJT_SIZE_T_LEN          (sizeof("-2147483648") - 1)
#define NJT_MAX_SIZE_T_VALUE    2147483647
#define NJT_TIME_T_LEN          (sizeof("-2147483648") - 1)
#define NJT_TIME_T_SIZE         4
#define NJT_MAX_TIME_T_VALUE    2147483647

#endif


#define NJT_OFF_T_LEN           (sizeof("-9223372036854775807") - 1)
#define NJT_MAX_OFF_T_VALUE     9223372036854775807
#define NJT_SIG_ATOMIC_T_SIZE   4


#define NJT_HAVE_LITTLE_ENDIAN  1
#define NJT_HAVE_NONALIGNED     1


#define NJT_WIN_NT        200000


#define NJT_LISTEN_BACKLOG           511


#ifndef NJT_HAVE_INHERITED_NONBLOCK
#define NJT_HAVE_INHERITED_NONBLOCK  1
#endif

#ifndef NJT_HAVE_CASELESS_FILESYSTEM
#define NJT_HAVE_CASELESS_FILESYSTEM  1
#endif

#ifndef NJT_HAVE_WIN32_TRANSMITPACKETS
#define NJT_HAVE_WIN32_TRANSMITPACKETS  1
#define NJT_HAVE_WIN32_TRANSMITFILE     0
#endif

#ifndef NJT_HAVE_WIN32_TRANSMITFILE
#define NJT_HAVE_WIN32_TRANSMITFILE  1
#endif

#if (NJT_HAVE_WIN32_TRANSMITPACKETS) || (NJT_HAVE_WIN32_TRANSMITFILE)
#define NJT_HAVE_SENDFILE  1
#endif

#ifndef NJT_HAVE_SO_SNDLOWAT
/* setsockopt(SO_SNDLOWAT) returns error WSAENOPROTOOPT */
#define NJT_HAVE_SO_SNDLOWAT         0
#endif

#ifndef NJT_HAVE_FIONREAD
#define NJT_HAVE_FIONREAD            1
#endif

#define NJT_HAVE_GETADDRINFO         1

#define njt_random               rand
#define njt_debug_init()


#endif /* _NJT_WIN32_CONFIG_H_INCLUDED_ */
