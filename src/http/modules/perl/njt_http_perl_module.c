
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_http_perl_module.h>


typedef struct {
    PerlInterpreter   *perl;
    HV                *njet;
    njt_array_t       *modules;
    njt_array_t       *requires;
} njt_http_perl_main_conf_t;


typedef struct {
    SV                *sub;
    njt_str_t          handler;
} njt_http_perl_loc_conf_t;


typedef struct {
    SV                *sub;
    njt_str_t          handler;
} njt_http_perl_variable_t;


#if (NJT_HTTP_SSI)
static njt_int_t njt_http_perl_ssi(njt_http_request_t *r,
    njt_http_ssi_ctx_t *ssi_ctx, njt_str_t **params);
#endif

static char *njt_http_perl_init_interpreter(njt_conf_t *cf,
    njt_http_perl_main_conf_t *pmcf);
static PerlInterpreter *njt_http_perl_create_interpreter(njt_conf_t *cf,
    njt_http_perl_main_conf_t *pmcf);
static njt_int_t njt_http_perl_run_requires(pTHX_ njt_array_t *requires,
    njt_log_t *log);
static njt_int_t njt_http_perl_call_handler(pTHX_ njt_http_request_t *r,
    njt_http_perl_ctx_t *ctx, HV *njet, SV *sub, SV **args,
    njt_str_t *handler, njt_str_t *rv);
static void njt_http_perl_eval_anon_sub(pTHX_ njt_str_t *handler, SV **sv);

static njt_int_t njt_http_perl_preconfiguration(njt_conf_t *cf);
static void *njt_http_perl_create_main_conf(njt_conf_t *cf);
static char *njt_http_perl_init_main_conf(njt_conf_t *cf, void *conf);
static void *njt_http_perl_create_loc_conf(njt_conf_t *cf);
static char *njt_http_perl_merge_loc_conf(njt_conf_t *cf, void *parent,
    void *child);
static char *njt_http_perl(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static char *njt_http_perl_set(njt_conf_t *cf, njt_command_t *cmd, void *conf);

#if (NJT_HAVE_PERL_MULTIPLICITY)
static void njt_http_perl_cleanup_perl(void *data);
#endif

static njt_int_t njt_http_perl_init_worker(njt_cycle_t *cycle);
static void njt_http_perl_exit(njt_cycle_t *cycle);


static njt_command_t  njt_http_perl_commands[] = {

    { njt_string("perl_modules"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_array_slot,
      NJT_HTTP_MAIN_CONF_OFFSET,
      offsetof(njt_http_perl_main_conf_t, modules),
      NULL },

    { njt_string("perl_require"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_array_slot,
      NJT_HTTP_MAIN_CONF_OFFSET,
      offsetof(njt_http_perl_main_conf_t, requires),
      NULL },

    { njt_string("perl"),
      NJT_HTTP_LOC_CONF|NJT_HTTP_LMT_CONF|NJT_CONF_TAKE1,
      njt_http_perl,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("perl_set"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_TAKE2,
      njt_http_perl_set,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      njt_null_command
};


static njt_http_module_t  njt_http_perl_module_ctx = {
    njt_http_perl_preconfiguration,        /* preconfiguration */
    NULL,                                  /* postconfiguration */

    njt_http_perl_create_main_conf,        /* create main configuration */
    njt_http_perl_init_main_conf,          /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_perl_create_loc_conf,         /* create location configuration */
    njt_http_perl_merge_loc_conf           /* merge location configuration */
};


njt_module_t  njt_http_perl_module = {
    NJT_MODULE_V1,
    &njt_http_perl_module_ctx,             /* module context */
    njt_http_perl_commands,                /* module directives */
    NJT_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    njt_http_perl_init_worker,             /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    njt_http_perl_exit,                    /* exit master */
    NJT_MODULE_V1_PADDING
};


#if (NJT_HTTP_SSI)

#define NJT_HTTP_PERL_SSI_SUB  0
#define NJT_HTTP_PERL_SSI_ARG  1


static njt_http_ssi_param_t  njt_http_perl_ssi_params[] = {
    { njt_string("sub"), NJT_HTTP_PERL_SSI_SUB, 1, 0 },
    { njt_string("arg"), NJT_HTTP_PERL_SSI_ARG, 0, 1 },
    { njt_null_string, 0, 0, 0 }
};

static njt_http_ssi_command_t  njt_http_perl_ssi_command = {
    njt_string("perl"), njt_http_perl_ssi, njt_http_perl_ssi_params, 0, 0, 1
};

#endif


static njt_str_t         njt_null_name = njt_null_string;
static HV               *njet_stash;

#if (NJT_HAVE_PERL_MULTIPLICITY)
static njt_uint_t        njt_perl_term;
#else
static PerlInterpreter  *perl;
#endif


static void
njt_http_perl_xs_init(pTHX)
{
    newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, __FILE__);

    njet_stash = gv_stashpv("njet", TRUE);
}


static njt_int_t
njt_http_perl_handler(njt_http_request_t *r)
{
    r->main->count++;

    njt_http_perl_handle_request(r);

    return NJT_DONE;
}


void
njt_http_perl_handle_request(njt_http_request_t *r)
{
    SV                         *sub;
    njt_int_t                   rc;
    njt_str_t                   uri, args, *handler;
    njt_uint_t                  flags;
    njt_http_perl_ctx_t        *ctx;
    njt_http_perl_loc_conf_t   *plcf;
    njt_http_perl_main_conf_t  *pmcf;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0, "perl handler");

    ctx = njt_http_get_module_ctx(r, njt_http_perl_module);

    if (ctx == NULL) {
        ctx = njt_pcalloc(r->pool, sizeof(njt_http_perl_ctx_t));
        if (ctx == NULL) {
            njt_http_finalize_request(r, NJT_ERROR);
            return;
        }

        njt_http_set_ctx(r, ctx, njt_http_perl_module);

        ctx->request = r;
    }

    pmcf = njt_http_get_module_main_conf(r, njt_http_perl_module);

    {

    dTHXa(pmcf->perl);
    PERL_SET_CONTEXT(pmcf->perl);
    PERL_SET_INTERP(pmcf->perl);

    if (ctx->next == NULL) {
        plcf = njt_http_get_module_loc_conf(r, njt_http_perl_module);
        sub = plcf->sub;
        handler = &plcf->handler;

    } else {
        sub = ctx->next;
        handler = &njt_null_name;
        ctx->next = NULL;
    }

    rc = njt_http_perl_call_handler(aTHX_ r, ctx, pmcf->njet, sub, NULL,
                                    handler, NULL);

    }

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "perl handler done: %i", rc);

    if (rc > 600) {
        rc = NJT_OK;
    }

    if (ctx->redirect_uri.len) {
        uri = ctx->redirect_uri;

    } else {
        uri.len = 0;
    }

    ctx->filename.data = NULL;
    ctx->redirect_uri.len = 0;

    if (rc == NJT_ERROR) {
        njt_http_finalize_request(r, rc);
        return;
    }

    if (ctx->done || ctx->next) {
        njt_http_finalize_request(r, NJT_DONE);
        return;
    }

    if (uri.len) {
        if (uri.data[0] == '@') {
            njt_http_named_location(r, &uri);

        } else {
            njt_str_null(&args);
            flags = NJT_HTTP_LOG_UNSAFE;

            if (njt_http_parse_unsafe_uri(r, &uri, &args, &flags) != NJT_OK) {
                njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            njt_http_internal_redirect(r, &uri, &args);
        }

        njt_http_finalize_request(r, NJT_DONE);
        return;
    }

    if (rc == NJT_OK || rc == NJT_HTTP_OK) {
        njt_http_send_special(r, NJT_HTTP_LAST);
        ctx->done = 1;
    }

    njt_http_finalize_request(r, rc);
}


void
njt_http_perl_sleep_handler(njt_http_request_t *r)
{
    njt_event_t  *wev;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "perl sleep handler");

    wev = r->connection->write;

    if (wev->delayed) {

        if (njt_handle_write_event(wev, 0) != NJT_OK) {
            njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        }

        return;
    }

    njt_http_perl_handle_request(r);
}


static njt_int_t
njt_http_perl_variable(njt_http_request_t *r, njt_http_variable_value_t *v,
    uintptr_t data)
{
    njt_http_perl_variable_t *pv = (njt_http_perl_variable_t *) data;

    njt_int_t                   rc;
    njt_str_t                   value;
    njt_uint_t                  saved;
    njt_http_perl_ctx_t        *ctx;
    njt_http_perl_main_conf_t  *pmcf;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "perl variable handler");

    ctx = njt_http_get_module_ctx(r, njt_http_perl_module);

    if (ctx == NULL) {
        ctx = njt_pcalloc(r->pool, sizeof(njt_http_perl_ctx_t));
        if (ctx == NULL) {
            return NJT_ERROR;
        }

        njt_http_set_ctx(r, ctx, njt_http_perl_module);

        ctx->request = r;
    }

    saved = ctx->variable;
    ctx->variable = 1;

    pmcf = njt_http_get_module_main_conf(r, njt_http_perl_module);

    value.data = NULL;

    {

    dTHXa(pmcf->perl);
    PERL_SET_CONTEXT(pmcf->perl);
    PERL_SET_INTERP(pmcf->perl);

    rc = njt_http_perl_call_handler(aTHX_ r, ctx, pmcf->njet, pv->sub, NULL,
                                    &pv->handler, &value);

    }

    if (value.data) {
        v->len = value.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = value.data;

    } else {
        v->not_found = 1;
    }

    ctx->variable = saved;
    ctx->filename.data = NULL;
    ctx->redirect_uri.len = 0;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "perl variable done");

    return rc;
}


#if (NJT_HTTP_SSI)

static njt_int_t
njt_http_perl_ssi(njt_http_request_t *r, njt_http_ssi_ctx_t *ssi_ctx,
    njt_str_t **params)
{
    SV                         *sv, **asv;
    njt_int_t                   rc;
    njt_str_t                  *handler, **args;
    njt_uint_t                  i;
    njt_http_perl_ctx_t        *ctx;
    njt_http_perl_main_conf_t  *pmcf;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "perl ssi handler");

    ctx = njt_http_get_module_ctx(r, njt_http_perl_module);

    if (ctx == NULL) {
        ctx = njt_pcalloc(r->pool, sizeof(njt_http_perl_ctx_t));
        if (ctx == NULL) {
            return NJT_ERROR;
        }

        njt_http_set_ctx(r, ctx, njt_http_perl_module);

        ctx->request = r;
    }

    pmcf = njt_http_get_module_main_conf(r, njt_http_perl_module);

    ctx->ssi = ssi_ctx;
    ctx->header_sent = 1;

    handler = params[NJT_HTTP_PERL_SSI_SUB];
    handler->data[handler->len] = '\0';

    {

    dTHXa(pmcf->perl);
    PERL_SET_CONTEXT(pmcf->perl);
    PERL_SET_INTERP(pmcf->perl);

#if 0

    /* the code is disabled to force the precompiled perl code using only */

    njt_http_perl_eval_anon_sub(aTHX_ handler, &sv);

    if (sv == &PL_sv_undef) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "eval_pv(\"%V\") failed", handler);
        return NJT_ERROR;
    }

    if (sv == NULL) {
        sv = newSVpvn((char *) handler->data, handler->len);
    }

#endif

    sv = newSVpvn((char *) handler->data, handler->len);

    args = &params[NJT_HTTP_PERL_SSI_ARG];

    if (args[0]) {

        for (i = 0; args[i]; i++) { /* void */ }

        asv = njt_pcalloc(r->pool, (i + 1) * sizeof(SV *));

        if (asv == NULL) {
            SvREFCNT_dec(sv);
            return NJT_ERROR;
        }

        asv[0] = (SV *) (uintptr_t) i;

        for (i = 0; args[i]; i++) {
            asv[i + 1] = newSVpvn((char *) args[i]->data, args[i]->len);
        }

    } else {
        asv = NULL;
    }

    rc = njt_http_perl_call_handler(aTHX_ r, ctx, pmcf->njet, sv, asv,
                                    handler, NULL);

    SvREFCNT_dec(sv);

    }

    ctx->filename.data = NULL;
    ctx->redirect_uri.len = 0;
    ctx->ssi = NULL;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0, "perl ssi done");

    return rc;
}

#endif


static char *
njt_http_perl_init_interpreter(njt_conf_t *cf, njt_http_perl_main_conf_t *pmcf)
{
    njt_str_t           *m;
    njt_uint_t           i;
#if (NJT_HAVE_PERL_MULTIPLICITY)
    njt_pool_cleanup_t  *cln;

    cln = njt_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NJT_CONF_ERROR;
    }

#endif

#ifdef NJT_PERL_MODULES
    if (pmcf->modules == NJT_CONF_UNSET_PTR) {

        pmcf->modules = njt_array_create(cf->pool, 1, sizeof(njt_str_t));
        if (pmcf->modules == NULL) {
            return NJT_CONF_ERROR;
        }

        m = njt_array_push(pmcf->modules);
        if (m == NULL) {
            return NJT_CONF_ERROR;
        }

        njt_str_set(m, NJT_PERL_MODULES);
    }
#endif

    if (pmcf->modules != NJT_CONF_UNSET_PTR) {
        m = pmcf->modules->elts;
        for (i = 0; i < pmcf->modules->nelts; i++) {
            if (njt_conf_full_name(cf->cycle, &m[i], 0) != NJT_OK) {
                return NJT_CONF_ERROR;
            }
        }
    }

#if !(NJT_HAVE_PERL_MULTIPLICITY)

    if (perl) {

        if (njt_set_environment(cf->cycle, NULL) == NULL) {
            return NJT_CONF_ERROR;
        }

        if (njt_http_perl_run_requires(aTHX_ pmcf->requires, cf->log)
            != NJT_OK)
        {
            return NJT_CONF_ERROR;
        }

        pmcf->perl = perl;
        pmcf->njet = njet_stash;

        return NJT_CONF_OK;
    }

#endif

    if (njet_stash == NULL) {
        PERL_SYS_INIT(&njt_argc, &njt_argv);
    }

    pmcf->perl = njt_http_perl_create_interpreter(cf, pmcf);

    if (pmcf->perl == NULL) {
        return NJT_CONF_ERROR;
    }

    pmcf->njet = njet_stash;

#if (NJT_HAVE_PERL_MULTIPLICITY)

    cln->handler = njt_http_perl_cleanup_perl;
    cln->data = pmcf->perl;

#else

    perl = pmcf->perl;

#endif

    return NJT_CONF_OK;
}


static PerlInterpreter *
njt_http_perl_create_interpreter(njt_conf_t *cf,
    njt_http_perl_main_conf_t *pmcf)
{
    int                n;
    STRLEN             len;
    SV                *sv;
    char              *ver, **embedding;
    njt_str_t         *m;
    njt_uint_t         i;
    PerlInterpreter   *perl;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, cf->log, 0, "create perl interpreter");

    if (njt_set_environment(cf->cycle, NULL) == NULL) {
        return NULL;
    }

    perl = perl_alloc();
    if (perl == NULL) {
        njt_log_error(NJT_LOG_ALERT, cf->log, 0, "perl_alloc() failed");
        return NULL;
    }

    {

    dTHXa(perl);
    PERL_SET_CONTEXT(perl);
    PERL_SET_INTERP(perl);

    perl_construct(perl);

#ifdef PERL_EXIT_DESTRUCT_END
    PL_exit_flags |= PERL_EXIT_DESTRUCT_END;
#endif

    n = (pmcf->modules != NJT_CONF_UNSET_PTR) ? pmcf->modules->nelts * 2 : 0;

    embedding = njt_palloc(cf->pool, (5 + n) * sizeof(char *));
    if (embedding == NULL) {
        goto fail;
    }

    embedding[0] = "";

    if (n++) {
        m = pmcf->modules->elts;
        for (i = 0; i < pmcf->modules->nelts; i++) {
            embedding[2 * i + 1] = "-I";
            embedding[2 * i + 2] = (char *) m[i].data;
        }
    }

    embedding[n++] = "-Mnjet";
    embedding[n++] = "-e";
    embedding[n++] = "0";
    embedding[n] = NULL;

    n = perl_parse(perl, njt_http_perl_xs_init, n, embedding, NULL);

    if (n != 0) {
        njt_log_error(NJT_LOG_ALERT, cf->log, 0, "perl_parse() failed: %d", n);
        goto fail;
    }

    sv = get_sv("njet::VERSION", FALSE);
    ver = SvPV(sv, len);

    if (njt_strcmp(ver, NJT_VERSION) != 0) {
        njt_log_error(NJT_LOG_ALERT, cf->log, 0,
                      "version " NJT_VERSION " of njet.pm is required, "
                      "but %s was found", ver);
        goto fail;
    }

    if (njt_http_perl_run_requires(aTHX_ pmcf->requires, cf->log) != NJT_OK) {
        goto fail;
    }

    }

    return perl;

fail:

    (void) perl_destruct(perl);

    perl_free(perl);

    return NULL;
}


static njt_int_t
njt_http_perl_run_requires(pTHX_ njt_array_t *requires, njt_log_t *log)
{
    u_char      *err;
    STRLEN       len;
    njt_str_t   *script;
    njt_uint_t   i;

    if (requires == NJT_CONF_UNSET_PTR) {
        return NJT_OK;
    }

    script = requires->elts;
    for (i = 0; i < requires->nelts; i++) {

        require_pv((char *) script[i].data);

        if (SvTRUE(ERRSV)) {

            err = (u_char *) SvPV(ERRSV, len);
            while (--len && (err[len] == CR || err[len] == LF)) { /* void */ }

            njt_log_error(NJT_LOG_EMERG, log, 0,
                          "require_pv(\"%s\") failed: \"%*s\"",
                          script[i].data, len + 1, err);

            return NJT_ERROR;
        }
    }

    return NJT_OK;
}


static njt_int_t
njt_http_perl_call_handler(pTHX_ njt_http_request_t *r,
    njt_http_perl_ctx_t *ctx, HV *njet, SV *sub, SV **args,
    njt_str_t *handler, njt_str_t *rv)
{
    SV                *sv;
    int                n, status;
    char              *line;
    u_char            *err;
    STRLEN             len, n_a;
    njt_uint_t         i;
    njt_connection_t  *c;

    dSP;

    status = 0;

    ctx->error = 0;
    ctx->status = NJT_OK;

    ENTER;
    SAVETMPS;

    PUSHMARK(sp);

    sv = sv_2mortal(sv_bless(newRV_noinc(newSViv(PTR2IV(ctx))), njet));
    XPUSHs(sv);

    if (args) {
        EXTEND(sp, (intptr_t) args[0]);

        for (i = 1; i <= (uintptr_t) args[0]; i++) {
            PUSHs(sv_2mortal(args[i]));
        }
    }

    PUTBACK;

    c = r->connection;

    n = call_sv(sub, G_EVAL);

    SPAGAIN;

    if (n) {
        if (rv == NULL) {
            status = POPi;

            njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                           "call_sv: %d", status);

        } else {
            line = SvPVx(POPs, n_a);
            rv->len = n_a;

            rv->data = njt_pnalloc(r->pool, n_a);
            if (rv->data == NULL) {
                return NJT_ERROR;
            }

            njt_memcpy(rv->data, line, n_a);
        }
    }

    PUTBACK;

    FREETMPS;
    LEAVE;

    if (ctx->error) {

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "call_sv: error, %d", ctx->status);

        if (ctx->status != NJT_OK) {
            return ctx->status;
        }

        return NJT_ERROR;
    }

    /* check $@ */

    if (SvTRUE(ERRSV)) {

        err = (u_char *) SvPV(ERRSV, len);
        while (--len && (err[len] == CR || err[len] == LF)) { /* void */ }

        njt_log_error(NJT_LOG_ERR, c->log, 0,
                      "call_sv(\"%V\") failed: \"%*s\"", handler, len + 1, err);

        if (rv) {
            return NJT_ERROR;
        }

        ctx->redirect_uri.len = 0;

        if (ctx->header_sent) {
            return NJT_ERROR;
        }

        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (n != 1) {
        njt_log_error(NJT_LOG_ALERT, c->log, 0,
                      "call_sv(\"%V\") returned %d results", handler, n);
        status = NJT_OK;
    }

    if (rv) {
        return NJT_OK;
    }

    return (njt_int_t) status;
}


static void
njt_http_perl_eval_anon_sub(pTHX_ njt_str_t *handler, SV **sv)
{
    u_char  *p;

    for (p = handler->data; *p; p++) {
        if (*p != ' ' && *p != '\t' && *p != CR && *p != LF) {
            break;
        }
    }

    if (njt_strncmp(p, "sub ", 4) == 0
        || njt_strncmp(p, "sub{", 4) == 0
        || njt_strncmp(p, "use ", 4) == 0)
    {
        *sv = eval_pv((char *) p, FALSE);

        /* eval_pv() does not set ERRSV on failure */

        return;
    }

    *sv = NULL;
}


static void *
njt_http_perl_create_main_conf(njt_conf_t *cf)
{
    njt_http_perl_main_conf_t  *pmcf;

    pmcf = njt_pcalloc(cf->pool, sizeof(njt_http_perl_main_conf_t));
    if (pmcf == NULL) {
        return NULL;
    }

    pmcf->modules = NJT_CONF_UNSET_PTR;
    pmcf->requires = NJT_CONF_UNSET_PTR;

    return pmcf;
}


static char *
njt_http_perl_init_main_conf(njt_conf_t *cf, void *conf)
{
    njt_http_perl_main_conf_t *pmcf = conf;

    if (pmcf->perl == NULL) {
        if (njt_http_perl_init_interpreter(cf, pmcf) != NJT_CONF_OK) {
            return NJT_CONF_ERROR;
        }
    }

    return NJT_CONF_OK;
}


#if (NJT_HAVE_PERL_MULTIPLICITY)

static void
njt_http_perl_cleanup_perl(void *data)
{
    PerlInterpreter  *perl = data;

    PERL_SET_CONTEXT(perl);
    PERL_SET_INTERP(perl);

    (void) perl_destruct(perl);

    perl_free(perl);

    if (njt_perl_term) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "perl term");

        PERL_SYS_TERM();
    }
}

#endif


static njt_int_t
njt_http_perl_preconfiguration(njt_conf_t *cf)
{
#if (NJT_HTTP_SSI)
    njt_int_t                  rc;
    njt_http_ssi_main_conf_t  *smcf;

    smcf = njt_http_conf_get_module_main_conf(cf, njt_http_ssi_filter_module);

    rc = njt_hash_add_key(&smcf->commands, &njt_http_perl_ssi_command.name,
                          &njt_http_perl_ssi_command, NJT_HASH_READONLY_KEY);

    if (rc != NJT_OK) {
        if (rc == NJT_BUSY) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "conflicting SSI command \"%V\"",
                               &njt_http_perl_ssi_command.name);
        }

        return NJT_ERROR;
    }
#endif

    return NJT_OK;
}


static void *
njt_http_perl_create_loc_conf(njt_conf_t *cf)
{
    njt_http_perl_loc_conf_t *plcf;

    plcf = njt_pcalloc(cf->pool, sizeof(njt_http_perl_loc_conf_t));
    if (plcf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     plcf->handler = { 0, NULL };
     */

    return plcf;
}


static char *
njt_http_perl_merge_loc_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_perl_loc_conf_t *prev = parent;
    njt_http_perl_loc_conf_t *conf = child;

    if (conf->sub == NULL) {
        conf->sub = prev->sub;
        conf->handler = prev->handler;
    }

    return NJT_CONF_OK;
}


static char *
njt_http_perl(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_perl_loc_conf_t *plcf = conf;

    njt_str_t                  *value;
    njt_http_core_loc_conf_t   *clcf;
    njt_http_perl_main_conf_t  *pmcf;

    value = cf->args->elts;

    if (plcf->handler.data) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "duplicate perl handler \"%V\"", &value[1]);
        return NJT_CONF_ERROR;
    }

    pmcf = njt_http_conf_get_module_main_conf(cf, njt_http_perl_module);

    if (pmcf->perl == NULL) {
        if (njt_http_perl_init_interpreter(cf, pmcf) != NJT_CONF_OK) {
            return NJT_CONF_ERROR;
        }
    }

    plcf->handler = value[1];

    {

    dTHXa(pmcf->perl);
    PERL_SET_CONTEXT(pmcf->perl);
    PERL_SET_INTERP(pmcf->perl);

    njt_http_perl_eval_anon_sub(aTHX_ &value[1], &plcf->sub);

    if (plcf->sub == &PL_sv_undef) {
        njt_conf_log_error(NJT_LOG_ERR, cf, 0,
                           "eval_pv(\"%V\") failed", &value[1]);
        return NJT_CONF_ERROR;
    }

    if (plcf->sub == NULL) {
        plcf->sub = newSVpvn((char *) value[1].data, value[1].len);
    }

    }

    clcf = njt_http_conf_get_module_loc_conf(cf, njt_http_core_module);
    clcf->handler = njt_http_perl_handler;

    return NJT_CONF_OK;
}


static char *
njt_http_perl_set(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_int_t                   index;
    njt_str_t                  *value;
    njt_http_variable_t        *v;
    njt_http_perl_variable_t   *pv;
    njt_http_perl_main_conf_t  *pmcf;

    value = cf->args->elts;

    if (value[1].data[0] != '$') {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &value[1]);
        return NJT_CONF_ERROR;
    }

    value[1].len--;
    value[1].data++;

    v = njt_http_add_variable(cf, &value[1], NJT_HTTP_VAR_CHANGEABLE);
    if (v == NULL) {
        return NJT_CONF_ERROR;
    }

    pv = njt_palloc(cf->pool, sizeof(njt_http_perl_variable_t));
    if (pv == NULL) {
        return NJT_CONF_ERROR;
    }

    index = njt_http_get_variable_index(cf, &value[1]);
    if (index == NJT_ERROR) {
        return NJT_CONF_ERROR;
    }

    pmcf = njt_http_conf_get_module_main_conf(cf, njt_http_perl_module);

    if (pmcf->perl == NULL) {
        if (njt_http_perl_init_interpreter(cf, pmcf) != NJT_CONF_OK) {
            return NJT_CONF_ERROR;
        }
    }

    pv->handler = value[2];

    {

    dTHXa(pmcf->perl);
    PERL_SET_CONTEXT(pmcf->perl);
    PERL_SET_INTERP(pmcf->perl);

    njt_http_perl_eval_anon_sub(aTHX_ &value[2], &pv->sub);

    if (pv->sub == &PL_sv_undef) {
        njt_conf_log_error(NJT_LOG_ERR, cf, 0,
                           "eval_pv(\"%V\") failed", &value[2]);
        return NJT_CONF_ERROR;
    }

    if (pv->sub == NULL) {
        pv->sub = newSVpvn((char *) value[2].data, value[2].len);
    }

    }

    v->get_handler = njt_http_perl_variable;
    v->data = (uintptr_t) pv;

    return NJT_CONF_OK;
}


static njt_int_t
njt_http_perl_init_worker(njt_cycle_t *cycle)
{
    njt_http_perl_main_conf_t  *pmcf;

    pmcf = njt_http_cycle_get_module_main_conf(cycle, njt_http_perl_module);

    if (pmcf) {
        dTHXa(pmcf->perl);
        PERL_SET_CONTEXT(pmcf->perl);
        PERL_SET_INTERP(pmcf->perl);

        /* set worker's $$ */

        sv_setiv(GvSV(gv_fetchpv("$", TRUE, SVt_PV)), (I32) njt_pid);
    }

    return NJT_OK;
}


static void
njt_http_perl_exit(njt_cycle_t *cycle)
{
#if (NJT_HAVE_PERL_MULTIPLICITY)

    /*
     * the master exit hook is run before global pool cleanup,
     * therefore just set flag here
     */

    njt_perl_term = 1;

#else

    if (njet_stash) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, cycle->log, 0, "perl term");

        (void) perl_destruct(perl);

        perl_free(perl);

        PERL_SYS_TERM();
    }

#endif
}
