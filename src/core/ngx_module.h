
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NJET_MODULE_H_INCLUDED_
#define _NJET_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <njet.h>


#define NJET_MODULE_UNSET_INDEX  (ngx_uint_t) -1


#define NJET_MODULE_SIGNATURE_0                                                \
    ngx_value(NJET_PTR_SIZE) ","                                               \
    ngx_value(NJET_SIG_ATOMIC_T_SIZE) ","                                      \
    ngx_value(NJET_TIME_T_SIZE) ","

#if (NJET_HAVE_KQUEUE)
#define NJET_MODULE_SIGNATURE_1   "1"
#else
#define NJET_MODULE_SIGNATURE_1   "0"
#endif

#if (NJET_HAVE_IOCP)
#define NJET_MODULE_SIGNATURE_2   "1"
#else
#define NJET_MODULE_SIGNATURE_2   "0"
#endif

#if (NJET_HAVE_FILE_AIO || NJET_COMPAT)
#define NJET_MODULE_SIGNATURE_3   "1"
#else
#define NJET_MODULE_SIGNATURE_3   "0"
#endif

#if (NJET_HAVE_SENDFILE_NODISKIO || NJET_COMPAT)
#define NJET_MODULE_SIGNATURE_4   "1"
#else
#define NJET_MODULE_SIGNATURE_4   "0"
#endif

#if (NJET_HAVE_EVENTFD)
#define NJET_MODULE_SIGNATURE_5   "1"
#else
#define NJET_MODULE_SIGNATURE_5   "0"
#endif

#if (NJET_HAVE_EPOLL)
#define NJET_MODULE_SIGNATURE_6   "1"
#else
#define NJET_MODULE_SIGNATURE_6   "0"
#endif

#if (NJET_HAVE_KEEPALIVE_TUNABLE)
#define NJET_MODULE_SIGNATURE_7   "1"
#else
#define NJET_MODULE_SIGNATURE_7   "0"
#endif

#if (NJET_HAVE_INET6)
#define NJET_MODULE_SIGNATURE_8   "1"
#else
#define NJET_MODULE_SIGNATURE_8   "0"
#endif

#define NJET_MODULE_SIGNATURE_9   "1"
#define NJET_MODULE_SIGNATURE_10  "1"

#if (NJET_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
#define NJET_MODULE_SIGNATURE_11  "1"
#else
#define NJET_MODULE_SIGNATURE_11  "0"
#endif

#define NJET_MODULE_SIGNATURE_12  "1"

#if (NJET_HAVE_SETFIB)
#define NJET_MODULE_SIGNATURE_13  "1"
#else
#define NJET_MODULE_SIGNATURE_13  "0"
#endif

#if (NJET_HAVE_TCP_FASTOPEN)
#define NJET_MODULE_SIGNATURE_14  "1"
#else
#define NJET_MODULE_SIGNATURE_14  "0"
#endif

#if (NJET_HAVE_UNIX_DOMAIN)
#define NJET_MODULE_SIGNATURE_15  "1"
#else
#define NJET_MODULE_SIGNATURE_15  "0"
#endif

#if (NJET_HAVE_VARIADIC_MACROS)
#define NJET_MODULE_SIGNATURE_16  "1"
#else
#define NJET_MODULE_SIGNATURE_16  "0"
#endif

#define NJET_MODULE_SIGNATURE_17  "0"
#define NJET_MODULE_SIGNATURE_18  "0"

#if (NJET_HAVE_OPENAT)
#define NJET_MODULE_SIGNATURE_19  "1"
#else
#define NJET_MODULE_SIGNATURE_19  "0"
#endif

#if (NJET_HAVE_ATOMIC_OPS)
#define NJET_MODULE_SIGNATURE_20  "1"
#else
#define NJET_MODULE_SIGNATURE_20  "0"
#endif

#if (NJET_HAVE_POSIX_SEM)
#define NJET_MODULE_SIGNATURE_21  "1"
#else
#define NJET_MODULE_SIGNATURE_21  "0"
#endif

#if (NJET_THREADS || NJET_COMPAT)
#define NJET_MODULE_SIGNATURE_22  "1"
#else
#define NJET_MODULE_SIGNATURE_22  "0"
#endif

#if (NJET_PCRE)
#define NJET_MODULE_SIGNATURE_23  "1"
#else
#define NJET_MODULE_SIGNATURE_23  "0"
#endif

#if (NJET_HTTP_SSL || NJET_COMPAT)
#define NJET_MODULE_SIGNATURE_24  "1"
#else
#define NJET_MODULE_SIGNATURE_24  "0"
#endif

#define NJET_MODULE_SIGNATURE_25  "1"

#if (NJET_HTTP_GZIP)
#define NJET_MODULE_SIGNATURE_26  "1"
#else
#define NJET_MODULE_SIGNATURE_26  "0"
#endif

#define NJET_MODULE_SIGNATURE_27  "1"

#if (NJET_HTTP_X_FORWARDED_FOR)
#define NJET_MODULE_SIGNATURE_28  "1"
#else
#define NJET_MODULE_SIGNATURE_28  "0"
#endif

#if (NJET_HTTP_REALIP)
#define NJET_MODULE_SIGNATURE_29  "1"
#else
#define NJET_MODULE_SIGNATURE_29  "0"
#endif

#if (NJET_HTTP_HEADERS)
#define NJET_MODULE_SIGNATURE_30  "1"
#else
#define NJET_MODULE_SIGNATURE_30  "0"
#endif

#if (NJET_HTTP_DAV)
#define NJET_MODULE_SIGNATURE_31  "1"
#else
#define NJET_MODULE_SIGNATURE_31  "0"
#endif

#if (NJET_HTTP_CACHE)
#define NJET_MODULE_SIGNATURE_32  "1"
#else
#define NJET_MODULE_SIGNATURE_32  "0"
#endif

#if (NJET_HTTP_UPSTREAM_ZONE)
#define NJET_MODULE_SIGNATURE_33  "1"
#else
#define NJET_MODULE_SIGNATURE_33  "0"
#endif

#if (NJET_COMPAT)
#define NJET_MODULE_SIGNATURE_34  "1"
#else
#define NJET_MODULE_SIGNATURE_34  "0"
#endif

#define NJET_MODULE_SIGNATURE                                                  \
    NJET_MODULE_SIGNATURE_0 NJET_MODULE_SIGNATURE_1 NJET_MODULE_SIGNATURE_2      \
    NJET_MODULE_SIGNATURE_3 NJET_MODULE_SIGNATURE_4 NJET_MODULE_SIGNATURE_5      \
    NJET_MODULE_SIGNATURE_6 NJET_MODULE_SIGNATURE_7 NJET_MODULE_SIGNATURE_8      \
    NJET_MODULE_SIGNATURE_9 NJET_MODULE_SIGNATURE_10 NJET_MODULE_SIGNATURE_11    \
    NJET_MODULE_SIGNATURE_12 NJET_MODULE_SIGNATURE_13 NJET_MODULE_SIGNATURE_14   \
    NJET_MODULE_SIGNATURE_15 NJET_MODULE_SIGNATURE_16 NJET_MODULE_SIGNATURE_17   \
    NJET_MODULE_SIGNATURE_18 NJET_MODULE_SIGNATURE_19 NJET_MODULE_SIGNATURE_20   \
    NJET_MODULE_SIGNATURE_21 NJET_MODULE_SIGNATURE_22 NJET_MODULE_SIGNATURE_23   \
    NJET_MODULE_SIGNATURE_24 NJET_MODULE_SIGNATURE_25 NJET_MODULE_SIGNATURE_26   \
    NJET_MODULE_SIGNATURE_27 NJET_MODULE_SIGNATURE_28 NJET_MODULE_SIGNATURE_29   \
    NJET_MODULE_SIGNATURE_30 NJET_MODULE_SIGNATURE_31 NJET_MODULE_SIGNATURE_32   \
    NJET_MODULE_SIGNATURE_33 NJET_MODULE_SIGNATURE_34


#define NJET_MODULE_V1                                                         \
    NJET_MODULE_UNSET_INDEX, NJET_MODULE_UNSET_INDEX,                           \
    NULL, 0, 0, njet_version, NJET_MODULE_SIGNATURE

#define NJET_MODULE_V1_PADDING  0, 0, 0, 0, 0, 0, 0, 0


struct ngx_module_s {
    ngx_uint_t            ctx_index;
    ngx_uint_t            index;

    char                 *name;

    ngx_uint_t            spare0;
    ngx_uint_t            spare1;

    ngx_uint_t            version;
    const char           *signature;

    void                 *ctx;
    ngx_command_t        *commands;
    ngx_uint_t            type;

    ngx_int_t           (*init_master)(ngx_log_t *log);

    ngx_int_t           (*init_module)(ngx_cycle_t *cycle);

    ngx_int_t           (*init_process)(ngx_cycle_t *cycle);
    ngx_int_t           (*init_thread)(ngx_cycle_t *cycle);
    void                (*exit_thread)(ngx_cycle_t *cycle);
    void                (*exit_process)(ngx_cycle_t *cycle);

    void                (*exit_master)(ngx_cycle_t *cycle);

    uintptr_t             spare_hook0;
    uintptr_t             spare_hook1;
    uintptr_t             spare_hook2;
    uintptr_t             spare_hook3;
    uintptr_t             spare_hook4;
    uintptr_t             spare_hook5;
    uintptr_t             spare_hook6;
    uintptr_t             spare_hook7;
};


typedef struct {
    ngx_str_t             name;
    void               *(*create_conf)(ngx_cycle_t *cycle);
    char               *(*init_conf)(ngx_cycle_t *cycle, void *conf);
} ngx_core_module_t;


ngx_int_t ngx_preinit_modules(void);
ngx_int_t ngx_cycle_modules(ngx_cycle_t *cycle);
ngx_int_t ngx_init_modules(ngx_cycle_t *cycle);
ngx_int_t ngx_count_modules(ngx_cycle_t *cycle, ngx_uint_t type);


ngx_int_t ngx_add_module(ngx_conf_t *cf, ngx_str_t *file,
    ngx_module_t *module, char **order);


extern ngx_module_t  *ngx_modules[];
extern ngx_uint_t     ngx_max_module;

extern char          *ngx_module_names[];


#endif /* _NJET_MODULE_H_INCLUDED_ */
