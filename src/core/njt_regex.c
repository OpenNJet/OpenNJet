
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>


typedef struct {
    njt_flag_t   pcre_jit;
    njt_list_t  *studies;
} njt_regex_conf_t;


static njt_inline void njt_regex_malloc_init(njt_pool_t *pool);
static njt_inline void njt_regex_malloc_done(void);

#if (NJT_PCRE2)
static void * njt_libc_cdecl njt_regex_malloc(size_t size, void *data);
static void njt_libc_cdecl njt_regex_free(void *p, void *data);
#else
static void * njt_libc_cdecl njt_regex_malloc(size_t size);
static void njt_libc_cdecl njt_regex_free(void *p);
#endif
static void njt_regex_cleanup(void *data);

static njt_int_t njt_regex_module_init(njt_cycle_t *cycle);

static void *njt_regex_create_conf(njt_cycle_t *cycle);
static char *njt_regex_init_conf(njt_cycle_t *cycle, void *conf);

static char *njt_regex_pcre_jit(njt_conf_t *cf, void *post, void *data);
static njt_conf_post_t  njt_regex_pcre_jit_post = { njt_regex_pcre_jit };


static njt_command_t  njt_regex_commands[] = {

    { njt_string("pcre_jit"),
      NJT_MAIN_CONF|NJT_DIRECT_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      0,
      offsetof(njt_regex_conf_t, pcre_jit),
      &njt_regex_pcre_jit_post },

      njt_null_command
};


static njt_core_module_t  njt_regex_module_ctx = {
    njt_string("regex"),
    njt_regex_create_conf,
    njt_regex_init_conf
};


njt_module_t  njt_regex_module = {
    NJT_MODULE_V1,
    &njt_regex_module_ctx,                 /* module context */
    njt_regex_commands,                    /* module directives */
    NJT_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    njt_regex_module_init,                 /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};


static njt_pool_t             *njt_regex_pool;
static njt_list_t             *njt_regex_studies;
static njt_uint_t              njt_regex_direct_alloc;

#if (NJT_PCRE2)
static pcre2_compile_context  *njt_regex_compile_context;
static pcre2_match_data       *njt_regex_match_data;
static njt_uint_t              njt_regex_match_data_size;
#endif


void
njt_regex_init(void)
{
#if !(NJT_PCRE2)
    pcre_malloc = njt_regex_malloc;
    pcre_free = njt_regex_free;
#endif
}


static njt_inline void
njt_regex_malloc_init(njt_pool_t *pool)
{
    njt_regex_pool = pool;
    njt_regex_direct_alloc = (pool == NULL) ? 1 : 0;
}


static njt_inline void
njt_regex_malloc_done(void)
{
    njt_regex_pool = NULL;
    njt_regex_direct_alloc = 0;
}


#if (NJT_PCRE2)

njt_int_t
njt_regex_compile(njt_regex_compile_t *rc)
{
    int                     n, errcode;
    char                   *p;
    u_char                  errstr[128];
    size_t                  erroff;
    uint32_t                options;
    pcre2_code             *re;
    njt_regex_elt_t        *elt;
    pcre2_general_context  *gctx;
    pcre2_compile_context  *cctx;

    if (njt_regex_compile_context == NULL) {
        /*
         * Allocate a compile context if not yet allocated.  This uses
         * direct allocations from heap, so the result can be cached
         * even at runtime.
         */

        njt_regex_malloc_init(NULL);

        gctx = pcre2_general_context_create(njt_regex_malloc, njt_regex_free,
                                            NULL);
        if (gctx == NULL) {
            njt_regex_malloc_done();
            goto nomem;
        }

        cctx = pcre2_compile_context_create(gctx);
        if (cctx == NULL) {
            pcre2_general_context_free(gctx);
            njt_regex_malloc_done();
            goto nomem;
        }

        njt_regex_compile_context = cctx;

        pcre2_general_context_free(gctx);
        njt_regex_malloc_done();
    }

    options = 0;

    if (rc->options & NJT_REGEX_CASELESS) {
        options |= PCRE2_CASELESS;
    }

    if (rc->options & NJT_REGEX_MULTILINE) {
        options |= PCRE2_MULTILINE;
    }

    if (rc->options & ~(NJT_REGEX_CASELESS|NJT_REGEX_MULTILINE)) {
        rc->err.len = njt_snprintf(rc->err.data, rc->err.len,
                            "regex \"%V\" compilation failed: invalid options",
                            &rc->pattern)
                      - rc->err.data;
        return NJT_ERROR;
    }

    njt_regex_malloc_init(rc->pool);

    re = pcre2_compile(rc->pattern.data, rc->pattern.len, options,
                       &errcode, &erroff, njt_regex_compile_context);

    /* ensure that there is no current pool */
    njt_regex_malloc_done();

    if (re == NULL) {
        pcre2_get_error_message(errcode, errstr, 128);

        if ((size_t) erroff == rc->pattern.len) {
            rc->err.len = njt_snprintf(rc->err.data, rc->err.len,
                              "pcre2_compile() failed: %s in \"%V\"",
                               errstr, &rc->pattern)
                          - rc->err.data;

        } else {
            rc->err.len = njt_snprintf(rc->err.data, rc->err.len,
                              "pcre2_compile() failed: %s in \"%V\" at \"%s\"",
                               errstr, &rc->pattern, rc->pattern.data + erroff)
                          - rc->err.data;
        }

        return NJT_ERROR;
    }

    rc->regex = re;

    /* do not study at runtime */

    if (njt_regex_studies != NULL) {
        elt = njt_list_push(njt_regex_studies);
        if (elt == NULL) {
            goto nomem;
        }

        elt->regex = rc->regex;
        elt->name = rc->pattern.data;
	elt->dynamic = rc->pool->dynamic;
    }

    n = pcre2_pattern_info(re, PCRE2_INFO_CAPTURECOUNT, &rc->captures);
    if (n < 0) {
        p = "pcre2_pattern_info(\"%V\", PCRE2_INFO_CAPTURECOUNT) failed: %d";
        goto failed;
    }

    if (rc->captures == 0) {
        return NJT_OK;
    }

    n = pcre2_pattern_info(re, PCRE2_INFO_NAMECOUNT, &rc->named_captures);
    if (n < 0) {
        p = "pcre2_pattern_info(\"%V\", PCRE2_INFO_NAMECOUNT) failed: %d";
        goto failed;
    }

    if (rc->named_captures == 0) {
        return NJT_OK;
    }

    n = pcre2_pattern_info(re, PCRE2_INFO_NAMEENTRYSIZE, &rc->name_size);
    if (n < 0) {
        p = "pcre2_pattern_info(\"%V\", PCRE2_INFO_NAMEENTRYSIZE) failed: %d";
        goto failed;
    }

    n = pcre2_pattern_info(re, PCRE2_INFO_NAMETABLE, &rc->names);
    if (n < 0) {
        p = "pcre2_pattern_info(\"%V\", PCRE2_INFO_NAMETABLE) failed: %d";
        goto failed;
    }

    return NJT_OK;

failed:

    rc->err.len = njt_snprintf(rc->err.data, rc->err.len, p, &rc->pattern, n)
                  - rc->err.data;
    return NJT_ERROR;

nomem:

    rc->err.len = njt_snprintf(rc->err.data, rc->err.len,
                               "regex \"%V\" compilation failed: no memory",
                               &rc->pattern)
                  - rc->err.data;
    return NJT_ERROR;
}

#else

njt_int_t
njt_regex_compile(njt_regex_compile_t *rc)
{
    int               n, erroff;
    char             *p;
    pcre             *re;
    const char       *errstr;
    njt_uint_t        options;
    njt_regex_elt_t  *elt;

    options = 0;

    if (rc->options & NJT_REGEX_CASELESS) {
        options |= PCRE_CASELESS;
    }

    if (rc->options & NJT_REGEX_MULTILINE) {
        options |= PCRE_MULTILINE;
    }

    if (rc->options & ~(NJT_REGEX_CASELESS|NJT_REGEX_MULTILINE)) {
        rc->err.len = njt_snprintf(rc->err.data, rc->err.len,
                            "regex \"%V\" compilation failed: invalid options",
                            &rc->pattern)
                      - rc->err.data;
        return NJT_ERROR;
    }

    njt_regex_malloc_init(rc->pool);

    re = pcre_compile((const char *) rc->pattern.data, (int) options,
                      &errstr, &erroff, NULL);

    /* ensure that there is no current pool */
    njt_regex_malloc_done();

    if (re == NULL) {
        if ((size_t) erroff == rc->pattern.len) {
           rc->err.len = njt_snprintf(rc->err.data, rc->err.len,
                              "pcre_compile() failed: %s in \"%V\"",
                               errstr, &rc->pattern)
                         - rc->err.data;

        } else {
           rc->err.len = njt_snprintf(rc->err.data, rc->err.len,
                              "pcre_compile() failed: %s in \"%V\" at \"%s\"",
                               errstr, &rc->pattern, rc->pattern.data + erroff)
                         - rc->err.data;
        }

        return NJT_ERROR;
    }

    rc->regex = njt_pcalloc(rc->pool, sizeof(njt_regex_t));
    if (rc->regex == NULL) {
        goto nomem;
    }

    rc->regex->code = re;

    /* do not study at runtime */

    if (njt_regex_studies != NULL) {
        elt = njt_list_push(njt_regex_studies);
        if (elt == NULL) {
            goto nomem;
        }

        elt->regex = rc->regex;
        elt->name = rc->pattern.data;
	elt->dynamic = rc->pool->dynamic;
    }

    n = pcre_fullinfo(re, NULL, PCRE_INFO_CAPTURECOUNT, &rc->captures);
    if (n < 0) {
        p = "pcre_fullinfo(\"%V\", PCRE_INFO_CAPTURECOUNT) failed: %d";
        goto failed;
    }

    if (rc->captures == 0) {
        return NJT_OK;
    }

    n = pcre_fullinfo(re, NULL, PCRE_INFO_NAMECOUNT, &rc->named_captures);
    if (n < 0) {
        p = "pcre_fullinfo(\"%V\", PCRE_INFO_NAMECOUNT) failed: %d";
        goto failed;
    }

    if (rc->named_captures == 0) {
        return NJT_OK;
    }

    n = pcre_fullinfo(re, NULL, PCRE_INFO_NAMEENTRYSIZE, &rc->name_size);
    if (n < 0) {
        p = "pcre_fullinfo(\"%V\", PCRE_INFO_NAMEENTRYSIZE) failed: %d";
        goto failed;
    }

    n = pcre_fullinfo(re, NULL, PCRE_INFO_NAMETABLE, &rc->names);
    if (n < 0) {
        p = "pcre_fullinfo(\"%V\", PCRE_INFO_NAMETABLE) failed: %d";
        goto failed;
    }

    return NJT_OK;

failed:

    rc->err.len = njt_snprintf(rc->err.data, rc->err.len, p, &rc->pattern, n)
                  - rc->err.data;
    return NJT_ERROR;

nomem:

    rc->err.len = njt_snprintf(rc->err.data, rc->err.len,
                               "regex \"%V\" compilation failed: no memory",
                               &rc->pattern)
                  - rc->err.data;
    return NJT_ERROR;
}

#endif


#if (NJT_PCRE2)

njt_int_t
njt_regex_exec(njt_regex_t *re, njt_str_t *s, int *captures, njt_uint_t size)
{
    size_t      *ov;
    njt_int_t    rc;
    njt_uint_t   n, i;

    /*
     * The pcre2_match() function might allocate memory for backtracking
     * frames, typical allocations are from 40k and above.  So the allocator
     * is configured to do direct allocations from heap during matching.
     */

    njt_regex_malloc_init(NULL);

    if (njt_regex_match_data == NULL
        || size > njt_regex_match_data_size)
    {
        /*
         * Allocate a match data if not yet allocated or smaller than
         * needed.
         */

        if (njt_regex_match_data) {
            pcre2_match_data_free(njt_regex_match_data);
        }

        njt_regex_match_data_size = size;
        njt_regex_match_data = pcre2_match_data_create(size / 3, NULL);

        if (njt_regex_match_data == NULL) {
            rc = PCRE2_ERROR_NOMEMORY;
            goto failed;
        }
    }

    rc = pcre2_match(re, s->data, s->len, 0, 0, njt_regex_match_data, NULL);

    if (rc < 0) {
        goto failed;
    }

    n = pcre2_get_ovector_count(njt_regex_match_data);
    ov = pcre2_get_ovector_pointer(njt_regex_match_data);

    if (n > size / 3) {
        n = size / 3;
    }

    for (i = 0; i < n; i++) {
        captures[i * 2] = ov[i * 2];
        captures[i * 2 + 1] = ov[i * 2 + 1];
    }

failed:

    njt_regex_malloc_done();

    return rc;
}

#else

njt_int_t
njt_regex_exec(njt_regex_t *re, njt_str_t *s, int *captures, njt_uint_t size)
{
    return pcre_exec(re->code, re->extra, (const char *) s->data, s->len,
                     0, 0, captures, size);
}

#endif


njt_int_t
njt_regex_exec_array(njt_array_t *a, njt_str_t *s, njt_log_t *log)
{
    njt_int_t         n;
    njt_uint_t        i;
    njt_regex_elt_t  *re;

    re = a->elts;

    for (i = 0; i < a->nelts; i++) {

        n = njt_regex_exec(re[i].regex, s, NULL, 0);

        if (n == NJT_REGEX_NO_MATCHED) {
            continue;
        }

        if (n < 0) {
            njt_log_error(NJT_LOG_ALERT, log, 0,
                          njt_regex_exec_n " failed: %i on \"%V\" using \"%s\"",
                          n, s, re[i].name);
            return NJT_ERROR;
        }

        /* match */

        return NJT_OK;
    }

    return NJT_DECLINED;
}


#if (NJT_PCRE2)

static void * njt_libc_cdecl
njt_regex_malloc(size_t size, void *data)
{
    if (njt_regex_pool) {
        return njt_palloc(njt_regex_pool, size);
    }

    if (njt_regex_direct_alloc) {
        return njt_alloc(size, njt_cycle->log);
    }

    return NULL;
}


static void njt_libc_cdecl
njt_regex_free(void *p, void *data)
{
    if (njt_regex_direct_alloc) {
        njt_free(p);
    }

    return;
}

#else

static void * njt_libc_cdecl
njt_regex_malloc(size_t size)
{
    if (njt_regex_pool) {
        return njt_palloc(njt_regex_pool, size);
    }

    return NULL;
}


static void njt_libc_cdecl
njt_regex_free(void *p)
{
    return;
}

#endif


static void
njt_regex_cleanup(void *data)
{
#if (NJT_PCRE2 || NJT_HAVE_PCRE_JIT)
    njt_regex_conf_t *rcf = data;

    njt_uint_t        i;
    njt_list_part_t  *part;
    njt_regex_elt_t  *elts;

    part = &rcf->studies->part;
    elts = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            elts = part->elts;
            i = 0;
        }

        /*
         * The PCRE JIT compiler uses mmap for its executable codes, so we
         * have to explicitly call the pcre_free_study() function to free
         * this memory.  In PCRE2, we call the pcre2_code_free() function
         * for the same reason.
         */

#if (NJT_PCRE2)
	if(elts[i].dynamic == 0) {
        	pcre2_code_free(elts[i].regex);
	}
#else
        if (elts[i].dynamic == 0 &&  elts[i].regex->extra != NULL) {
            pcre_free_study(elts[i].regex->extra);
        }
#endif
    }
#endif

    /*
     * On configuration parsing errors njt_regex_module_init() will not
     * be called.  Make sure njt_regex_studies is properly cleared anyway.
     */

    njt_regex_studies = NULL;

#if (NJT_PCRE2)

    /*
     * Free compile context and match data.  If needed at runtime by
     * the new cycle, these will be re-allocated.
     */

    njt_regex_malloc_init(NULL);

    if (njt_regex_compile_context) {
        pcre2_compile_context_free(njt_regex_compile_context);
        njt_regex_compile_context = NULL;
    }

    if (njt_regex_match_data) {
        pcre2_match_data_free(njt_regex_match_data);
        njt_regex_match_data = NULL;
        njt_regex_match_data_size = 0;
    }

    njt_regex_malloc_done();

#endif
}


static njt_int_t
njt_regex_module_init(njt_cycle_t *cycle)
{
    int                opt;
#if !(NJT_PCRE2)
    const char        *errstr;
#endif
    njt_uint_t         i;
    njt_list_part_t   *part;
    njt_regex_elt_t   *elts;
    njt_regex_conf_t  *rcf;

    opt = 0;

    rcf = (njt_regex_conf_t *) njt_get_conf(cycle->conf_ctx, njt_regex_module);

#if (NJT_PCRE2 || NJT_HAVE_PCRE_JIT)

    if (rcf->pcre_jit) {
#if (NJT_PCRE2)
        opt = 1;
#else
        opt = PCRE_STUDY_JIT_COMPILE;
#endif
    }

#endif

    njt_regex_malloc_init(cycle->pool);

    part = &rcf->studies->part;
    elts = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            elts = part->elts;
            i = 0;
        }

#if (NJT_PCRE2)

        if (opt) {
            int  n;

            n = pcre2_jit_compile(elts[i].regex, PCRE2_JIT_COMPLETE);

            if (n != 0) {
                njt_log_error(NJT_LOG_INFO, cycle->log, 0,
                              "pcre2_jit_compile() failed: %d in \"%s\", "
                              "ignored",
                              n, elts[i].name);
            }
        }

#else

        elts[i].regex->extra = pcre_study(elts[i].regex->code, opt, &errstr);

        if (errstr != NULL) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, 0,
                          "pcre_study() failed: %s in \"%s\"",
                          errstr, elts[i].name);
        }

#if (NJT_HAVE_PCRE_JIT)
        if (opt & PCRE_STUDY_JIT_COMPILE) {
            int jit, n;

            jit = 0;
            n = pcre_fullinfo(elts[i].regex->code, elts[i].regex->extra,
                              PCRE_INFO_JIT, &jit);

            if (n != 0 || jit != 1) {
                njt_log_error(NJT_LOG_INFO, cycle->log, 0,
                              "JIT compiler does not support pattern: \"%s\"",
                              elts[i].name);
            }
        }
#endif
#endif
    }

    njt_regex_malloc_done();

    njt_regex_studies = NULL;

    return NJT_OK;
}


static void *
njt_regex_create_conf(njt_cycle_t *cycle)
{
    njt_regex_conf_t    *rcf;
    njt_pool_cleanup_t  *cln;

    rcf = njt_pcalloc(cycle->pool, sizeof(njt_regex_conf_t));
    if (rcf == NULL) {
        return NULL;
    }

    rcf->pcre_jit = NJT_CONF_UNSET;

    cln = njt_pool_cleanup_add(cycle->pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    rcf->studies = njt_list_create(cycle->pool, 8, sizeof(njt_regex_elt_t));
    if (rcf->studies == NULL) {
        return NULL;
    }

    cln->handler = njt_regex_cleanup;
    cln->data = rcf;

    njt_regex_studies = rcf->studies;

    return rcf;
}


static char *
njt_regex_init_conf(njt_cycle_t *cycle, void *conf)
{
    njt_regex_conf_t *rcf = conf;

    njt_conf_init_value(rcf->pcre_jit, 0);

    return NJT_CONF_OK;
}


static char *
njt_regex_pcre_jit(njt_conf_t *cf, void *post, void *data)
{
    njt_flag_t  *fp = data;

    if (*fp == 0) {
        return NJT_CONF_OK;
    }

#if (NJT_PCRE2)
    {
    int       r;
    uint32_t  jit;

    jit = 0;
    r = pcre2_config(PCRE2_CONFIG_JIT, &jit);

    if (r != 0 || jit != 1) {
        njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                           "PCRE2 library does not support JIT");
        *fp = 0;
    }
    }
#elif (NJT_HAVE_PCRE_JIT)
    {
    int  jit, r;

    jit = 0;
    r = pcre_config(PCRE_CONFIG_JIT, &jit);

    if (r != 0 || jit != 1) {
        njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                           "PCRE library does not support JIT");
        *fp = 0;
    }
    }
#else
    njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                       "njet was built without PCRE JIT support");
    *fp = 0;
#endif

    return NJT_CONF_OK;
}
