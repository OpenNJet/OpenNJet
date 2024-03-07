
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_MODULE_H_INCLUDED_
#define _NJT_MODULE_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>
#include <njet.h>


#define NJT_MODULE_UNSET_INDEX  (njt_uint_t) -1


#define NJT_MODULE_SIGNATURE_0                                                \
    njt_value(NJT_PTR_SIZE) ","                                               \
    njt_value(NJT_SIG_ATOMIC_T_SIZE) ","                                      \
    njt_value(NJT_TIME_T_SIZE) ","

#if (NJT_HAVE_KQUEUE)
#define NJT_MODULE_SIGNATURE_1   "1"
#else
#define NJT_MODULE_SIGNATURE_1   "0"
#endif

#if (NJT_HAVE_IOCP)
#define NJT_MODULE_SIGNATURE_2   "1"
#else
#define NJT_MODULE_SIGNATURE_2   "0"
#endif

#if (NJT_HAVE_FILE_AIO || NJT_COMPAT)
#define NJT_MODULE_SIGNATURE_3   "1"
#else
#define NJT_MODULE_SIGNATURE_3   "0"
#endif

#if (NJT_HAVE_SENDFILE_NODISKIO || NJT_COMPAT)
#define NJT_MODULE_SIGNATURE_4   "1"
#else
#define NJT_MODULE_SIGNATURE_4   "0"
#endif

#if (NJT_HAVE_EVENTFD)
#define NJT_MODULE_SIGNATURE_5   "1"
#else
#define NJT_MODULE_SIGNATURE_5   "0"
#endif

#if (NJT_HAVE_EPOLL)
#define NJT_MODULE_SIGNATURE_6   "1"
#else
#define NJT_MODULE_SIGNATURE_6   "0"
#endif

#if (NJT_HAVE_KEEPALIVE_TUNABLE)
#define NJT_MODULE_SIGNATURE_7   "1"
#else
#define NJT_MODULE_SIGNATURE_7   "0"
#endif

#if (NJT_HAVE_INET6)
#define NJT_MODULE_SIGNATURE_8   "1"
#else
#define NJT_MODULE_SIGNATURE_8   "0"
#endif

#define NJT_MODULE_SIGNATURE_9   "1"
#define NJT_MODULE_SIGNATURE_10  "1"

#if (NJT_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
#define NJT_MODULE_SIGNATURE_11  "1"
#else
#define NJT_MODULE_SIGNATURE_11  "0"
#endif

#define NJT_MODULE_SIGNATURE_12  "1"

#if (NJT_HAVE_SETFIB)
#define NJT_MODULE_SIGNATURE_13  "1"
#else
#define NJT_MODULE_SIGNATURE_13  "0"
#endif

#if (NJT_HAVE_TCP_FASTOPEN)
#define NJT_MODULE_SIGNATURE_14  "1"
#else
#define NJT_MODULE_SIGNATURE_14  "0"
#endif

#if (NJT_HAVE_UNIX_DOMAIN)
#define NJT_MODULE_SIGNATURE_15  "1"
#else
#define NJT_MODULE_SIGNATURE_15  "0"
#endif

#if (NJT_HAVE_VARIADIC_MACROS)
#define NJT_MODULE_SIGNATURE_16  "1"
#else
#define NJT_MODULE_SIGNATURE_16  "0"
#endif

#define NJT_MODULE_SIGNATURE_17  "0"
#if (NJT_QUIC || NJT_COMPAT)
#define NJT_MODULE_SIGNATURE_18  "1"
#else
#define NJT_MODULE_SIGNATURE_18  "0"
#endif

#if (NJT_HAVE_OPENAT)
#define NJT_MODULE_SIGNATURE_19  "1"
#else
#define NJT_MODULE_SIGNATURE_19  "0"
#endif

#if (NJT_HAVE_ATOMIC_OPS)
#define NJT_MODULE_SIGNATURE_20  "1"
#else
#define NJT_MODULE_SIGNATURE_20  "0"
#endif

#if (NJT_HAVE_POSIX_SEM)
#define NJT_MODULE_SIGNATURE_21  "1"
#else
#define NJT_MODULE_SIGNATURE_21  "0"
#endif

#if (NJT_THREADS || NJT_COMPAT)
#define NJT_MODULE_SIGNATURE_22  "1"
#else
#define NJT_MODULE_SIGNATURE_22  "0"
#endif

#if (NJT_PCRE)
#define NJT_MODULE_SIGNATURE_23  "1"
#else
#define NJT_MODULE_SIGNATURE_23  "0"
#endif

#if (NJT_HTTP_SSL || NJT_COMPAT)
#define NJT_MODULE_SIGNATURE_24  "1"
#else
#define NJT_MODULE_SIGNATURE_24  "0"
#endif

#define NJT_MODULE_SIGNATURE_25  "1"

#if (NJT_HTTP_GZIP)
#define NJT_MODULE_SIGNATURE_26  "1"
#else
#define NJT_MODULE_SIGNATURE_26  "0"
#endif

#define NJT_MODULE_SIGNATURE_27  "1"

#if (NJT_HTTP_X_FORWARDED_FOR)
#define NJT_MODULE_SIGNATURE_28  "1"
#else
#define NJT_MODULE_SIGNATURE_28  "0"
#endif

#if (NJT_HTTP_REALIP)
#define NJT_MODULE_SIGNATURE_29  "1"
#else
#define NJT_MODULE_SIGNATURE_29  "0"
#endif

#if (NJT_HTTP_HEADERS)
#define NJT_MODULE_SIGNATURE_30  "1"
#else
#define NJT_MODULE_SIGNATURE_30  "0"
#endif

#if (NJT_HTTP_DAV)
#define NJT_MODULE_SIGNATURE_31  "1"
#else
#define NJT_MODULE_SIGNATURE_31  "0"
#endif

#if (NJT_HTTP_CACHE)
#define NJT_MODULE_SIGNATURE_32  "1"
#else
#define NJT_MODULE_SIGNATURE_32  "0"
#endif

#if (NJT_HTTP_UPSTREAM_ZONE)
#define NJT_MODULE_SIGNATURE_33  "1"
#else
#define NJT_MODULE_SIGNATURE_33  "0"
#endif

#if (NJT_COMPAT)
#define NJT_MODULE_SIGNATURE_34  "1"
#else
#define NJT_MODULE_SIGNATURE_34  "0"
#endif

#define NJT_MODULE_SIGNATURE                                                  \
    NJT_MODULE_SIGNATURE_0 NJT_MODULE_SIGNATURE_1 NJT_MODULE_SIGNATURE_2      \
    NJT_MODULE_SIGNATURE_3 NJT_MODULE_SIGNATURE_4 NJT_MODULE_SIGNATURE_5      \
    NJT_MODULE_SIGNATURE_6 NJT_MODULE_SIGNATURE_7 NJT_MODULE_SIGNATURE_8      \
    NJT_MODULE_SIGNATURE_9 NJT_MODULE_SIGNATURE_10 NJT_MODULE_SIGNATURE_11    \
    NJT_MODULE_SIGNATURE_12 NJT_MODULE_SIGNATURE_13 NJT_MODULE_SIGNATURE_14   \
    NJT_MODULE_SIGNATURE_15 NJT_MODULE_SIGNATURE_16 NJT_MODULE_SIGNATURE_17   \
    NJT_MODULE_SIGNATURE_18 NJT_MODULE_SIGNATURE_19 NJT_MODULE_SIGNATURE_20   \
    NJT_MODULE_SIGNATURE_21 NJT_MODULE_SIGNATURE_22 NJT_MODULE_SIGNATURE_23   \
    NJT_MODULE_SIGNATURE_24 NJT_MODULE_SIGNATURE_25 NJT_MODULE_SIGNATURE_26   \
    NJT_MODULE_SIGNATURE_27 NJT_MODULE_SIGNATURE_28 NJT_MODULE_SIGNATURE_29   \
    NJT_MODULE_SIGNATURE_30 NJT_MODULE_SIGNATURE_31 NJT_MODULE_SIGNATURE_32   \
    NJT_MODULE_SIGNATURE_33 NJT_MODULE_SIGNATURE_34


#define NJT_MODULE_V1                                                         \
    NJT_MODULE_UNSET_INDEX, NJT_MODULE_UNSET_INDEX,                           \
    NULL, 0, 0, njet_version, NJT_MODULE_SIGNATURE

#define NJT_MODULE_V1_PADDING  0, 0, 0, 0, 0, 0, 0, 0


struct njt_module_s {
    njt_uint_t            ctx_index;
    njt_uint_t            index;

    char                 *name;

    njt_uint_t            spare0;
    njt_uint_t            spare1;

    njt_uint_t            version;
    const char           *signature;

    void                 *ctx;
    njt_command_t        *commands;
    njt_uint_t            type;

    njt_int_t           (*init_master)(njt_log_t *log);

    njt_int_t           (*init_module)(njt_cycle_t *cycle);

    njt_int_t           (*init_process)(njt_cycle_t *cycle);
    njt_int_t           (*init_thread)(njt_cycle_t *cycle);
    void                (*exit_thread)(njt_cycle_t *cycle);
    void                (*exit_process)(njt_cycle_t *cycle);

    void                (*exit_master)(njt_cycle_t *cycle);

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
    njt_str_t             name;
    void               *(*create_conf)(njt_cycle_t *cycle);
    char               *(*init_conf)(njt_cycle_t *cycle, void *conf);
} njt_core_module_t;


njt_int_t njt_preinit_modules(void);
njt_int_t njt_cycle_modules(njt_cycle_t *cycle);
njt_int_t njt_init_modules(njt_cycle_t *cycle);
njt_int_t njt_count_modules(njt_cycle_t *cycle, njt_uint_t type);


njt_int_t njt_add_module(njt_conf_t *cf, njt_str_t *file,
    njt_module_t *module, char **order);


extern njt_module_t  *njt_modules[];
extern njt_uint_t     njt_max_module;

extern char          *njt_module_names[];


#endif /* _NJT_MODULE_H_INCLUDED_ */
