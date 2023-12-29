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

#ifndef MODSECURITY_DDEBUG
#define MODSECURITY_DDEBUG 0
#endif
#include "ddebug.h"

#include "njt_http_modsecurity_common.h"
#include "stdio.h"
#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>

static njt_int_t njt_http_modsecurity_init(njt_conf_t *cf);
static void *njt_http_modsecurity_create_main_conf(njt_conf_t *cf);
static char *njt_http_modsecurity_init_main_conf(njt_conf_t *cf, void *conf);
static void *njt_http_modsecurity_create_conf(njt_conf_t *cf);
static char *njt_http_modsecurity_merge_conf(njt_conf_t *cf, void *parent, void *child);
static void njt_http_modsecurity_cleanup_instance(void *data);
static void njt_http_modsecurity_cleanup_rules(void *data);


/*
 * PCRE malloc/free workaround, based on
 * https://github.com/openresty/lua-nginx-module/blob/master/src/njt_http_lua_pcrefix.c
 */

#if !(NJT_PCRE2)
static void *(*old_pcre_malloc)(size_t);
static void (*old_pcre_free)(void *ptr);
static njt_pool_t *njt_http_modsec_pcre_pool = NULL;

static void *
njt_http_modsec_pcre_malloc(size_t size)
{
    if (njt_http_modsec_pcre_pool) {
        return njt_palloc(njt_http_modsec_pcre_pool, size);
    }

    fprintf(stderr, "error: modsec pcre malloc failed due to empty pcre pool");

    return NULL;
}

static void
njt_http_modsec_pcre_free(void *ptr)
{
    if (njt_http_modsec_pcre_pool) {
        njt_pfree(njt_http_modsec_pcre_pool, ptr);
        return;
    }

#if 0
    /* this may happen when called from cleanup handlers */
    fprintf(stderr, "error: modsec pcre free failed due to empty pcre pool");
#endif

    return;
}

njt_pool_t *
njt_http_modsecurity_pcre_malloc_init(njt_pool_t *pool)
{
    njt_pool_t  *old_pool;

    if (pcre_malloc != njt_http_modsec_pcre_malloc) {
        njt_http_modsec_pcre_pool = pool;

        old_pcre_malloc = pcre_malloc;
        old_pcre_free = pcre_free;

        pcre_malloc = njt_http_modsec_pcre_malloc;
        pcre_free = njt_http_modsec_pcre_free;

        return NULL;
    }

    old_pool = njt_http_modsec_pcre_pool;
    njt_http_modsec_pcre_pool = pool;

    return old_pool;
}

void
njt_http_modsecurity_pcre_malloc_done(njt_pool_t *old_pool)
{
    njt_http_modsec_pcre_pool = old_pool;

    if (old_pool == NULL) {
        pcre_malloc = old_pcre_malloc;
        pcre_free = old_pcre_free;
    }
}
#endif

/*
 * njt_string's are not null-terminated in common case, so we need to convert
 * them into null-terminated ones before passing to ModSecurity
 */
njt_inline char *njt_str_to_char(njt_str_t a, njt_pool_t *p)
{
    char *str = NULL;

    if (a.len == 0) {
        return NULL;
    }

    str = njt_pnalloc(p, a.len+1);
    if (str == NULL) {
        dd("failed to allocate memory to convert space njt_string to C string");
        /* We already returned NULL for an empty string, so return -1 here to indicate allocation error */
        return (char *)-1;
    }
    njt_memcpy(str, a.data, a.len);
    str[a.len] = '\0';

    return str;
}


njt_inline int
njt_http_modsecurity_process_intervention (Transaction *transaction, njt_http_request_t *r, njt_int_t early_log)
{
    char *log = NULL;
    ModSecurityIntervention intervention;
    intervention.status = 200;
    intervention.url = NULL;
    intervention.log = NULL;
    intervention.disruptive = 0;
    njt_http_modsecurity_ctx_t *ctx = NULL;

    dd("processing intervention");

    ctx = njt_http_get_module_ctx(r, njt_http_modsecurity_module);
    if (ctx == NULL)
    {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (msc_intervention(transaction, &intervention) == 0) {
        dd("nothing to do");
        return 0;
    }

    log = intervention.log;
    if (intervention.log == NULL) {
        log = "(no log message was specified)";
    }

    njt_log_error(NJT_LOG_ERR, (njt_log_t *)r->connection->log, 0, "%s", log);

    if (intervention.log != NULL) {
        free(intervention.log);
    }

    if (intervention.url != NULL)
    {
        dd("intervention -- redirecting to: %s with status code: %d", intervention.url, intervention.status);

        if (r->header_sent)
        {
            dd("Headers are already sent. Cannot perform the redirection at this point.");
            return -1;
        }

        /**
         * Not sure if it sane to do this indepent of the phase
         * but, here we go...
         *
         * This code cames from: http/njt_http_special_response.c
         * function: njt_http_send_error_page
         * src/http/njt_http_core_module.c
         * From src/http/njt_http_core_module.c (line 1910) i learnt
         * that location->hash should be set to 1.
         *
         */
        njt_http_clear_location(r);
        njt_str_t a = njt_string("");

        a.data = (unsigned char *)intervention.url;
        a.len = strlen(intervention.url);

        njt_table_elt_t *location = NULL;
        location = njt_list_push(&r->headers_out.headers);
        njt_str_set(&location->key, "Location");
        location->value = a;
        r->headers_out.location = location;
        r->headers_out.location->hash = 1;

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
        njt_http_modsecurity_store_ctx_header(r, &location->key, &location->value);
#endif

        return intervention.status;
    }

    if (intervention.status != 200)
    {
        /**
         * FIXME: this will bring proper response code to audit log in case
         * when e.g. error_page redirect was triggered, but there still won't be another
         * required pieces like response headers etc.
         *
         */
        msc_update_status_code(ctx->modsec_transaction, intervention.status);

        if (early_log) {
            dd("intervention -- calling log handler manually with code: %d", intervention.status);
            njt_http_modsecurity_log_handler(r);
            ctx->logged = 1;
	}

        if (r->header_sent)
        {
            dd("Headers are already sent. Cannot perform the redirection at this point.");
            return -1;
        }
        dd("intervention -- returning code: %d", intervention.status);
        return intervention.status;
    }
    return 0;
}


void
njt_http_modsecurity_cleanup(void *data)
{
    njt_http_modsecurity_ctx_t *ctx;

    ctx = (njt_http_modsecurity_ctx_t *) data;

    msc_transaction_cleanup(ctx->modsec_transaction);

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
    /*
     * Purge stored context headers.  Memory allocated for individual stored header
     * name/value pair will be freed automatically when r->pool is destroyed.
     */
    njt_array_destroy(ctx->sanity_headers_out);
#endif
}


njt_inline njt_http_modsecurity_ctx_t *
njt_http_modsecurity_create_ctx(njt_http_request_t *r)
{
    njt_str_t                          s;
    njt_pool_cleanup_t                *cln;
    njt_http_modsecurity_ctx_t        *ctx;
    njt_http_modsecurity_conf_t       *mcf;
    njt_http_modsecurity_main_conf_t  *mmcf;

    ctx = njt_pcalloc(r->pool, sizeof(njt_http_modsecurity_ctx_t));
    if (ctx == NULL)
    {
        dd("failed to allocate memory for the context.");
        return NULL;
    }

    mmcf = njt_http_get_module_main_conf(r, njt_http_modsecurity_module);
    mcf = njt_http_get_module_loc_conf(r, njt_http_modsecurity_module);

    dd("creating transaction with the following rules: '%p' -- ms: '%p'", mcf->rules_set, mmcf->modsec);

    if (mcf->transaction_id) {
        if (njt_http_complex_value(r, mcf->transaction_id, &s) != NJT_OK) {
            return NJT_CONF_ERROR;
        }
        ctx->modsec_transaction = msc_new_transaction_with_id(mmcf->modsec, mcf->rules_set, (char *) s.data, r->connection->log);

    } else {
        ctx->modsec_transaction = msc_new_transaction(mmcf->modsec, mcf->rules_set, r->connection->log);
    }

    dd("transaction created");

    njt_http_set_ctx(r, ctx, njt_http_modsecurity_module);

    cln = njt_pool_cleanup_add(r->pool, sizeof(njt_http_modsecurity_ctx_t));
    if (cln == NULL)
    {
        dd("failed to create the ModSecurity context cleanup");
        return NJT_CONF_ERROR;
    }
    cln->handler = njt_http_modsecurity_cleanup;
    cln->data = ctx;

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
    ctx->sanity_headers_out = njt_array_create(r->pool, 12, sizeof(njt_http_modsecurity_header_t));
    if (ctx->sanity_headers_out == NULL) {
        return NJT_CONF_ERROR;
    }
#endif

    return ctx;
}


char *
njt_conf_set_rules(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    int                                res;
    char                              *rules;
    njt_str_t                         *value;
    const char                        *error;
    njt_pool_t                        *old_pool;
    njt_http_modsecurity_conf_t       *mcf = conf;
    njt_http_modsecurity_main_conf_t  *mmcf;

    value = cf->args->elts;
    rules = njt_str_to_char(value[1], cf->pool);

    if (rules == (char *)-1) {
        return NJT_CONF_ERROR;
    }

    old_pool = njt_http_modsecurity_pcre_malloc_init(cf->pool);
    res = msc_rules_add(mcf->rules_set, rules, &error);
    njt_http_modsecurity_pcre_malloc_done(old_pool);

    if (res < 0) {
        dd("Failed to load the rules: '%s' - reason: '%s'", rules, error);
        return strdup(error);
    }

    mmcf = njt_http_conf_get_module_main_conf(cf, njt_http_modsecurity_module);
    mmcf->rules_inline += res;

    return NJT_CONF_OK;
}


char *
njt_conf_set_rules_file(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    int                                res;
    char                              *rules_set;
    njt_str_t                         *value;
    const char                        *error;
    njt_pool_t                        *old_pool;
    njt_http_modsecurity_conf_t       *mcf = conf;
    njt_http_modsecurity_main_conf_t  *mmcf;

    value = cf->args->elts;
    rules_set = njt_str_to_char(value[1], cf->pool);

    if (rules_set == (char *)-1) {
        return NJT_CONF_ERROR;
    }

    old_pool = njt_http_modsecurity_pcre_malloc_init(cf->pool);
    res = msc_rules_add_file(mcf->rules_set, rules_set, &error);
    njt_http_modsecurity_pcre_malloc_done(old_pool);

    if (res < 0) {
        dd("Failed to load the rules from: '%s' - reason: '%s'", rules_set, error);
        return strdup(error);
    }

    mmcf = njt_http_conf_get_module_main_conf(cf, njt_http_modsecurity_module);
    mmcf->rules_file += res;

    return NJT_CONF_OK;
}


char *
njt_conf_set_rules_remote(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    int                                res;
    njt_str_t                         *value;
    const char                        *error;
    const char                        *rules_remote_key, *rules_remote_server;
    njt_pool_t                        *old_pool;
    njt_http_modsecurity_conf_t       *mcf = conf;
    njt_http_modsecurity_main_conf_t  *mmcf;

    value = cf->args->elts;
    rules_remote_key = njt_str_to_char(value[1], cf->pool);
    rules_remote_server = njt_str_to_char(value[2], cf->pool);

    if (rules_remote_server == (char *)-1) {
        return NJT_CONF_ERROR;
    }

    if (rules_remote_key == (char *)-1) {
        return NJT_CONF_ERROR;
    }

    old_pool = njt_http_modsecurity_pcre_malloc_init(cf->pool);
    res = msc_rules_add_remote(mcf->rules_set, rules_remote_key, rules_remote_server, &error);
    njt_http_modsecurity_pcre_malloc_done(old_pool);

    if (res < 0) {
        dd("Failed to load the rules from: '%s'  - reason: '%s'", rules_remote_server, error);
        return strdup(error);
    }

    mmcf = njt_http_conf_get_module_main_conf(cf, njt_http_modsecurity_module);
    mmcf->rules_remote += res;

    return NJT_CONF_OK;
}


char *njt_conf_set_transaction_id(njt_conf_t *cf, njt_command_t *cmd, void *conf) {
    njt_str_t                         *value;
    njt_http_complex_value_t           cv;
    njt_http_compile_complex_value_t   ccv;
    njt_http_modsecurity_conf_t *mcf = conf;

    value = cf->args->elts;

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;
    ccv.zero = 1;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    mcf->transaction_id = njt_palloc(cf->pool, sizeof(njt_http_complex_value_t));
    if (mcf->transaction_id == NULL) {
        return NJT_CONF_ERROR;
    }

    *mcf->transaction_id = cv;

    return NJT_CONF_OK;
}


static njt_command_t njt_http_modsecurity_commands[] =  {
  {
    njt_string("modsecurity"),
    NJT_HTTP_LOC_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_MAIN_CONF|NJT_CONF_FLAG,
    njt_conf_set_flag_slot,
    NJT_HTTP_LOC_CONF_OFFSET,
    offsetof(njt_http_modsecurity_conf_t, enable),
    NULL
  },
  {
    njt_string("modsecurity_rules"),
    NJT_HTTP_LOC_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_MAIN_CONF|NJT_CONF_TAKE1,
    njt_conf_set_rules,
    NJT_HTTP_LOC_CONF_OFFSET,
    offsetof(njt_http_modsecurity_conf_t, enable),
    NULL
  },
  {
    njt_string("modsecurity_rules_file"),
    NJT_HTTP_LOC_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_MAIN_CONF|NJT_CONF_TAKE1,
    njt_conf_set_rules_file,
    NJT_HTTP_LOC_CONF_OFFSET,
    offsetof(njt_http_modsecurity_conf_t, enable),
    NULL
  },
  {
    njt_string("modsecurity_rules_remote"),
    NJT_HTTP_LOC_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_MAIN_CONF|NJT_CONF_TAKE2,
    njt_conf_set_rules_remote,
    NJT_HTTP_LOC_CONF_OFFSET,
    offsetof(njt_http_modsecurity_conf_t, enable),
    NULL
  },
  {
    njt_string("modsecurity_transaction_id"),
    NJT_HTTP_LOC_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_MAIN_CONF|NJT_CONF_1MORE,
    njt_conf_set_transaction_id,
    NJT_HTTP_LOC_CONF_OFFSET,
    0,
    NULL
  },
  njt_null_command
};


static njt_http_module_t njt_http_modsecurity_ctx = {
    NULL,                                  /* preconfiguration */
    njt_http_modsecurity_init,             /* postconfiguration */

    njt_http_modsecurity_create_main_conf, /* create main configuration */
    njt_http_modsecurity_init_main_conf,   /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_modsecurity_create_conf,      /* create location configuration */
    njt_http_modsecurity_merge_conf        /* merge location configuration */
};


njt_module_t njt_http_modsecurity_module = {
    NJT_MODULE_V1,
    &njt_http_modsecurity_ctx,             /* module context */
    njt_http_modsecurity_commands,         /* module directives */
    NJT_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};


static njt_int_t
njt_http_modsecurity_init(njt_conf_t *cf)
{
    njt_http_handler_pt *h_rewrite;
    njt_http_handler_pt *h_preaccess;
    njt_http_handler_pt *h_log;
    njt_http_core_main_conf_t *cmcf;
    int rc = 0;

    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);
    if (cmcf == NULL)
    {
        dd("We are not sure how this returns, NJet doesn't seem to think it will ever be null");
        return NJT_ERROR;
    }
    /**
     *
     * Seems like we cannot do this very same thing with
     * NJT_HTTP_FIND_CONFIG_PHASE. it does not seems to
     * be an array. Our next option is the REWRITE.
     *
     * TODO: check if we can hook prior to NJT_HTTP_REWRITE_PHASE phase.
     *
     */
    h_rewrite = njt_array_push(&cmcf->phases[NJT_HTTP_REWRITE_PHASE].handlers);
    if (h_rewrite == NULL)
    {
        dd("Not able to create a new NJT_HTTP_REWRITE_PHASE handle");
        return NJT_ERROR;
    }
    *h_rewrite = njt_http_modsecurity_rewrite_handler;

    /**
     *
     * Processing the request body on the preaccess phase.
     *
     * TODO: check if hook into separated phases is the best thing to do.
     *
     */
    h_preaccess = njt_array_push(&cmcf->phases[NJT_HTTP_PREACCESS_PHASE].handlers);
    if (h_preaccess == NULL)
    {
        dd("Not able to create a new NJT_HTTP_PREACCESS_PHASE handle");
        return NJT_ERROR;
    }
    *h_preaccess = njt_http_modsecurity_pre_access_handler;

    /**
     * Process the log phase.
     *
     * TODO: check if the log phase happens like it happens on Apache.
     *       check if last phase will not hold the request.
     *
     */
    h_log = njt_array_push(&cmcf->phases[NJT_HTTP_LOG_PHASE].handlers);
    if (h_log == NULL)
    {
        dd("Not able to create a new NJT_HTTP_LOG_PHASE handle");
        return NJT_ERROR;
    }
    *h_log = njt_http_modsecurity_log_handler;


    rc = njt_http_modsecurity_header_filter_init();
    if (rc != NJT_OK) {
        return rc;
    }

    rc = njt_http_modsecurity_body_filter_init();
    if (rc != NJT_OK) {
        return rc;
    }

    return NJT_OK;
}


static void *
njt_http_modsecurity_create_main_conf(njt_conf_t *cf)
{
    njt_pool_cleanup_t                *cln;
    njt_http_modsecurity_main_conf_t  *conf;

    conf = (njt_http_modsecurity_main_conf_t *) njt_pcalloc(cf->pool,
                                    sizeof(njt_http_modsecurity_main_conf_t));

    if (conf == NULL)
    {
        return NJT_CONF_ERROR;
    }

    /*
     * set by njt_pcalloc():
     *
     *     conf->modsec = NULL;
     *     conf->pool = NULL;
     *     conf->rules_inline = 0;
     *     conf->rules_file = 0;
     *     conf->rules_remote = 0;
     */

    cln = njt_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NJT_CONF_ERROR;
    }

    cln->handler = njt_http_modsecurity_cleanup_instance;
    cln->data = conf;

    conf->pool = cf->pool;

    /* Create our ModSecurity instance */
    conf->modsec = msc_init();
    if (conf->modsec == NULL)
    {
        dd("failed to create the ModSecurity instance");
        return NJT_CONF_ERROR;
    }

    /* Provide our connector information to LibModSecurity */
    msc_set_connector_info(conf->modsec, MODSECURITY_NJET_WHOAMI);
    msc_set_log_cb(conf->modsec, njt_http_modsecurity_log);

    dd ("main conf created at: '%p', instance is: '%p'", conf, conf->modsec);

    return conf;
}


static char *
njt_http_modsecurity_init_main_conf(njt_conf_t *cf, void *conf)
{
    njt_http_modsecurity_main_conf_t  *mmcf;
    mmcf = (njt_http_modsecurity_main_conf_t *) conf;

    njt_log_error(NJT_LOG_NOTICE, cf->log, 0,
                  "%s (rules loaded inline/local/remote: %ui/%ui/%ui)",
                  MODSECURITY_NJET_WHOAMI, mmcf->rules_inline,
                  mmcf->rules_file, mmcf->rules_remote);

    return NJT_CONF_OK;
}


static void *
njt_http_modsecurity_create_conf(njt_conf_t *cf)
{
    njt_pool_cleanup_t           *cln;
    njt_http_modsecurity_conf_t  *conf;

    conf = (njt_http_modsecurity_conf_t *) njt_pcalloc(cf->pool,
                                         sizeof(njt_http_modsecurity_conf_t));

    if (conf == NULL)
    {
        dd("Failed to allocate space for ModSecurity configuration");
        return NJT_CONF_ERROR;
    }

    /*
     * set by njt_pcalloc():
     *
     *     conf->enable = 0;
     *     conf->sanity_checks_enabled = 0;
     *     conf->rules_set = NULL;
     *     conf->pool = NULL;
     *     conf->transaction_id = NULL;
     */

    conf->enable = NJT_CONF_UNSET;
    conf->rules_set = msc_create_rules_set();
    conf->pool = cf->pool;
    conf->transaction_id = NJT_CONF_UNSET_PTR;
#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
    conf->sanity_checks_enabled = NJT_CONF_UNSET;
#endif

    cln = njt_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        dd("failed to create the ModSecurity configuration cleanup");
        return NJT_CONF_ERROR;
    }

    cln->handler = njt_http_modsecurity_cleanup_rules;
    cln->data = conf;

    dd ("conf created at: '%p'", conf);

    return conf;
}


static char *
njt_http_modsecurity_merge_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_modsecurity_conf_t *p = parent;
    njt_http_modsecurity_conf_t *c = child;
#if defined(MODSECURITY_DDEBUG) && (MODSECURITY_DDEBUG)
    njt_http_core_loc_conf_t *clcf = njt_http_conf_get_module_loc_conf(cf, njt_http_core_module);
#endif
    int rules;
    const char *error = NULL;

    dd("merging loc config [%s] - parent: '%p' child: '%p'",
        njt_str_to_char(clcf->name, cf->pool), parent,
        child);

    dd("                  state - parent: '%d' child: '%d'",
        (int) c->enable, (int) p->enable);

    njt_conf_merge_value(c->enable, p->enable, 0);
    njt_conf_merge_ptr_value(c->transaction_id, p->transaction_id, NULL);
#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
    njt_conf_merge_value(c->sanity_checks_enabled, p->sanity_checks_enabled, 0);
#endif

#if defined(MODSECURITY_DDEBUG) && (MODSECURITY_DDEBUG)
    dd("PARENT RULES");
    msc_rules_dump(p->rules_set);
    dd("CHILD RULES");
    msc_rules_dump(c->rules_set);
#endif
    rules = msc_rules_merge(c->rules_set, p->rules_set, &error);

    if (rules < 0) {
        return strdup(error);
    }

#if defined(MODSECURITY_DDEBUG) && (MODSECURITY_DDEBUG)
    dd("NEW CHILD RULES");
    msc_rules_dump(c->rules_set);
#endif
    return NJT_CONF_OK;
}


static void
njt_http_modsecurity_cleanup_instance(void *data)
{
    njt_pool_t                        *old_pool;
    njt_http_modsecurity_main_conf_t  *mmcf;

    mmcf = (njt_http_modsecurity_main_conf_t *) data;

    dd("deleting a main conf -- instance is: \"%p\"", mmcf->modsec);

    old_pool = njt_http_modsecurity_pcre_malloc_init(mmcf->pool);
    msc_cleanup(mmcf->modsec);
    njt_http_modsecurity_pcre_malloc_done(old_pool);
}


static void
njt_http_modsecurity_cleanup_rules(void *data)
{
    njt_pool_t                   *old_pool;
    njt_http_modsecurity_conf_t  *mcf;

    mcf = (njt_http_modsecurity_conf_t *) data;

    dd("deleting a loc conf -- RuleSet is: \"%p\"", mcf->rules_set);

    old_pool = njt_http_modsecurity_pcre_malloc_init(mcf->pool);
    msc_rules_cleanup(mcf->rules_set);
    njt_http_modsecurity_pcre_malloc_done(old_pool);
}


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
