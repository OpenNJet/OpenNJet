/*
 * ModSecurity connector for njet, http://www.modsecurity.org/
 * Copyright (c) 2015 Trustwave Holdings, Inc. (http://www.trustwave.com/)
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * If any of the files related to licensing are missing or if you have any
 * other questions related to licensing please contact Trustwave Holdings, Inc.
 * directly using the email address security@modsecurity.org.
 *
 */


#ifndef _NJT_HTTP_MODSECURITY_COMMON_H_INCLUDED_
#define _NJT_HTTP_MODSECURITY_COMMON_H_INCLUDED_

#include <njet.h>
#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>

#include <modsecurity/modsecurity.h>
#include <modsecurity/transaction.h>


/* #define MSC_USE_RULES_SET 1 */

#if defined(MODSECURITY_CHECK_VERSION)
#if MODSECURITY_VERSION_NUM >= 304010
#define MSC_USE_RULES_SET 1
#endif
#endif

#if defined(MSC_USE_RULES_SET)
#include <modsecurity/rules_set.h>
#else
#include <modsecurity/rules.h>
#endif


/**
 * TAG_NUM:
 *
 * Alpha  - 001
 * Beta   - 002
 * Dev    - 010
 * Rc1    - 051
 * Rc2    - 052
 * ...    - ...
 * Release- 100
 *
 */

#define MODSECURITY_NJET_MAJOR "1"
#define MODSECURITY_NJET_MINOR "0"
#define MODSECURITY_NJET_PATCHLEVEL "3"
#define MODSECURITY_NJET_TAG ""
#define MODSECURITY_NJET_TAG_NUM "100"

#define MODSECURITY_NJET_VERSION MODSECURITY_NJET_MAJOR "." \
    MODSECURITY_NJET_MINOR "." MODSECURITY_NJET_PATCHLEVEL \
    MODSECURITY_NJET_TAG

#define MODSECURITY_NJET_VERSION_NUM MODSECURITY_NJET_MAJOR \
    MODSECURITY_NJET_MINOR MODSECURITY_NJET_PATCHLEVEL \
    MODSECURITY_NJET_TAG_NUM

#define MODSECURITY_NJET_WHOAMI "ModSecurity-njet v" \
    MODSECURITY_NJET_VERSION

typedef struct {
    njt_str_t name;
    njt_str_t value;
} njt_http_modsecurity_header_t;


typedef struct {
    njt_http_request_t *r;
    Transaction *modsec_transaction;
    ModSecurityIntervention *delayed_intervention;

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
    /*
     * Should be filled with the headers that were sent to ModSecurity.
     *
     * The idea is to compare this set of headers with the headers that were
     * sent to the client. This check was placed because we don't have control
     * over other modules, thus, we may partially inspect the headers.
     *
     */
    njt_array_t *sanity_headers_out;
#endif

    unsigned waiting_more_body:1;
    unsigned body_requested:1;
    unsigned processed:1;
    unsigned logged:1;
    unsigned intervention_triggered:1;
} njt_http_modsecurity_ctx_t;


typedef struct {
    void                      *pool;
    ModSecurity               *modsec;
    njt_uint_t                 rules_inline;
    njt_uint_t                 rules_file;
    njt_uint_t                 rules_remote;
} njt_http_modsecurity_main_conf_t;


typedef struct {
    void                      *pool;
    /* RulesSet or Rules */
    void                      *rules_set;

    njt_flag_t                 enable;
#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
    njt_flag_t                 sanity_checks_enabled;
#endif

    njt_http_complex_value_t  *transaction_id;
} njt_http_modsecurity_conf_t;


typedef njt_int_t (*njt_http_modsecurity_resolv_header_pt)(njt_http_request_t *r, njt_str_t name, off_t offset);

typedef struct {
    njt_str_t name;
    njt_uint_t offset;
    njt_http_modsecurity_resolv_header_pt resolver;
} njt_http_modsecurity_header_out_t;


extern njt_module_t njt_http_modsecurity_module;

/* njt_http_modsecurity_module.c */
int njt_http_modsecurity_process_intervention (Transaction *transaction, njt_http_request_t *r, njt_int_t early_log);
njt_http_modsecurity_ctx_t *njt_http_modsecurity_create_ctx(njt_http_request_t *r);
char *njt_str_to_char(njt_str_t a, njt_pool_t *p);
#if (NJT_PCRE2)
#define njt_http_modsecurity_pcre_malloc_init(x) NULL
#define njt_http_modsecurity_pcre_malloc_done(x) (void)x
#else
njt_pool_t *njt_http_modsecurity_pcre_malloc_init(njt_pool_t *pool);
void njt_http_modsecurity_pcre_malloc_done(njt_pool_t *old_pool);
#endif

/* njt_http_modsecurity_body_filter.c */
njt_int_t njt_http_modsecurity_body_filter_init(void);
njt_int_t njt_http_modsecurity_body_filter(njt_http_request_t *r, njt_chain_t *in);

/* njt_http_modsecurity_header_filter.c */
njt_int_t njt_http_modsecurity_header_filter_init(void);
njt_int_t njt_http_modsecurity_header_filter(njt_http_request_t *r);
#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
int njt_http_modsecurity_store_ctx_header(njt_http_request_t *r, njt_str_t *name, njt_str_t *value);
#endif

/* njt_http_modsecurity_log.c */
void njt_http_modsecurity_log(void *log, const void* data);
njt_int_t njt_http_modsecurity_log_handler(njt_http_request_t *r);

/* njt_http_modsecurity_pre_access.c */
njt_int_t njt_http_modsecurity_pre_access_handler(njt_http_request_t *r);

/* njt_http_modsecurity_rewrite.c */
njt_int_t njt_http_modsecurity_rewrite_handler(njt_http_request_t *r);


#endif /* _NJT_HTTP_MODSECURITY_COMMON_H_INCLUDED_ */
