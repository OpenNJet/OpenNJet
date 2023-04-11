
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */



#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include "njt_http_match_module.h"


typedef struct njt_http_match_ctx_s {
    njt_http_match_t *match;
} njt_http_match_ctx_t;

typedef njt_uint_t (*njt_http_match_check_handler)
(njt_http_match_t *match, njt_uint_t code, njt_array_t *headers,
 njt_buf_t *body);
typedef struct njt_http_match_main_conf_s {
    /*array of njt_http_match_t*/
    njt_array_t                     matches;
} njt_http_match_main_conf_t;


static char *njt_http_match_block(njt_conf_t *cf, njt_command_t *cmd,
                                  void *conf);
static char *njt_http_match(njt_conf_t *cf, njt_command_t *cmd,
                            void *conf);
static void *njt_http_match_create_main_conf(njt_conf_t *cf);
static char *njt_http_match_init_main_conf(njt_conf_t *cf, void *conf);


static njt_command_t njt_http_match_commands[] = {

    {
        njt_string("match"),
        NJT_HTTP_MAIN_CONF | NJT_CONF_BLOCK | NJT_CONF_TAKE1,
        njt_http_match_block,
        NJT_HTTP_MAIN_CONF_OFFSET,
        0,
        NULL
    },

    njt_null_command
};


static njt_http_module_t njt_http_match_module_ctx = {
    NULL,                               /* preconfiguration */
    NULL,                               /* postconfiguration */

    njt_http_match_create_main_conf,    /* create main configuration */
    njt_http_match_init_main_conf,      /* init main configuration */

    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */

    NULL,                               /* create location configuration */
    NULL                                /* merge lcoation configuration */
};


njt_module_t njt_http_match_module = {
    NJT_MODULE_V1,
    &njt_http_match_module_ctx,    /* module context */
    njt_http_match_commands,       /* module directives */
    NJT_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NJT_MODULE_V1_PADDING
};


static char *
njt_http_match_block(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_str_t                 *value, name;
    njt_conf_t                 save;
    njt_http_match_ctx_t      *ctx;
    njt_http_match_t          *match;
    char                      *rv;

    value = cf->args->elts;

    name = value[1];

    match = njt_http_match_create(cf, &name, 1);
    if (match == NULL) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "match create error");
        return NJT_CONF_ERROR;
    }

    match->defined = 1;

    if (njt_array_init(&match->status.codes, cf->pool, 4,
                       sizeof(njt_http_match_code_t)) != NJT_OK) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "status code array init error");
        return NJT_CONF_ERROR;
    }

    if (njt_array_init(&match->headers, cf->pool, 4,
                       sizeof(njt_http_match_header_t)) != NJT_OK) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "match header array init error");
        return NJT_CONF_ERROR;
    }

    ctx = njt_palloc(cf->pool, sizeof(njt_http_match_ctx_t));
    if (ctx == NULL) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "match context allocation error.");
        return NJT_CONF_ERROR;
    }

    ctx->match = match;

    save = *cf;
    cf->ctx = ctx;
    cf->handler = njt_http_match;
    cf->handler_conf = conf;

    rv = njt_conf_parse(cf, NULL);

    *cf = save;

    return rv;
}

static njt_int_t njt_http_match_parse_code(njt_str_t *code,
        njt_http_match_code_t *match_code)
{
    u_char         *dash, *last;
    njt_uint_t     status;

    last = code->data + code->len;
    dash = njt_strlchr(code->data, last, '-');

    if (dash) {

        status = njt_atoi(code->data, dash - code->data);
        if (status < 100 || status >= 600) {
            return NJT_ERROR;
        }
        match_code->code = status;

        status = njt_atoi(dash + 1, last - dash - 1);
        if (status < 100 || status >= 600) {
            return NJT_ERROR;
        }
        match_code->last_code = status;

        if (match_code->last_code < match_code->code) {
            return NJT_ERROR;
        }

        match_code->single = 0;

    } else {

        status = njt_atoi(code->data, code->len);
        if (status < 100 || status >= 600) {
            return NJT_ERROR;
        }
        match_code->code = status;
        match_code->single = 1;
    }
    return NJT_OK;

}

static njt_regex_t *
njt_http_match_regex_value(njt_conf_t *cf, njt_str_t *regex)
{
#if (NJT_PCRE)
    njt_regex_compile_t  rc;
    u_char               errstr[NJT_MAX_CONF_ERRSTR];

    njt_memzero(&rc, sizeof(njt_regex_compile_t));

    rc.pattern = *regex;
    rc.err.len = NJT_MAX_CONF_ERRSTR;
    rc.err.data = errstr;
    rc.pool = cf->pool;
    rc.options = NJT_REGEX_CASELESS;


    if (njt_regex_compile(&rc) != NJT_OK) {
        return NULL;
    }

    return rc.regex;

#else

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "using regex \"%V\" requires PCRE library",
                       regex);
    return NULL;

#endif
}


static char *
njt_http_match(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_str_t                      *args;
    njt_uint_t                      nelts;
    njt_http_match_ctx_t           *ctx;
    njt_http_match_t               *match;
    njt_http_match_code_t          *code;
    njt_http_match_header_t        *header;
    njt_uint_t                     i;
    njt_int_t                      rc;


    args = cf->args->elts;
    ctx = cf->ctx;

    match = ctx->match;
    match->conditions = 1;

    nelts = cf->args->nelts;

    i = 0;
    if (njt_strcmp(args[i].data, "status") == 0) {

        i++;
        if (njt_strncmp(args[i].data, "!", 1) == 0) {
            match->status.not_operation = 1;
            i++;
        }

        if (i >= nelts) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "Too many parameters %u for status.", nelts);

            return NJT_CONF_ERROR;
        }

        for (; i < nelts; i++)  {

            code = njt_array_push(&match->status.codes);
            if (code == NULL) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "code array push error.");
                return NJT_CONF_ERROR;
            }

            njt_memzero(code, sizeof(njt_http_match_code_t));
            rc = njt_http_match_parse_code(&args[i], code);
            if (rc == NJT_ERROR) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "code %V parse error.", &args[i]);
                return NJT_CONF_ERROR;
            }
        }

    } else if (njt_strcmp(args[0].data, "header") == 0) {

        header = njt_array_push(&match->headers);
        if (header == NULL) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "header array push error.");
            return NJT_CONF_ERROR;
        }
        njt_memzero(header, sizeof(njt_http_match_header_t));

        i++;
        /*header ! abc;*/
        if (njt_strncmp(args[i].data, "!", 1) == 0) {

            header->operation = NJT_HTTP_MATCH_NOT_CONTAIN;
            i++;
            if (nelts != 3) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "parameter number %u of header ! error.", nelts);
                return NJT_CONF_ERROR;
            }

            header->key = args[2];
            return NJT_CONF_OK;
        }

        header->key = args[i];
        i++;

        /*header abc;*/
        if (nelts == 2) {
            header->operation = NJT_HTTP_MATCH_CONTAIN;
            return NJT_CONF_OK;
        }

        if (nelts != 4) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "header parse error.");
            return NJT_CONF_ERROR;
        }

        if (args[i].len == 1) {

            if (njt_strncmp(args[i].data, "=", 1) == 0) {
                header->operation = NJT_HTTP_MATCH_EQUAL;

            } else if (njt_strncmp(args[i].data, "~", 1) == 0) {

                header->operation = NJT_HTTP_MATCH_REG_MATCH;
                header->regex = njt_http_match_regex_value(cf, &args[3]);

                if (header->regex == NULL) {
                    njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "header regex %V parse error.",
                                       &args[3]);
                    return NJT_CONF_ERROR;
                }

            } else {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "header operation parse error.");
                return NJT_CONF_ERROR;
            }

            header->value = args[3];

            return NJT_CONF_OK;

        } else if (args[i].len == 2) {

            if (njt_strncmp(args[i].data, "!=", 2) == 0) {
                header->operation = NJT_HTTP_MATCH_NOT_EQUAL;

            } else if (njt_strncmp(args[i].data, "!~", 2) == 0) {

                header->operation = NJT_HTTP_MATCH_NOT_REG_MATCH;
                header->regex = njt_http_match_regex_value(cf, &args[3]);

                if (header->regex == NULL) {
                    njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "header regex %V parse error.",
                                       &args[3]);
                    return NJT_CONF_ERROR;
                }

            } else {
                return NJT_CONF_ERROR;
            }

            header->value = args[3];
            return NJT_CONF_OK;
        } else {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "header operation %V isn't supported.", &args[i]);
            return NJT_CONF_ERROR;
        }

    } else if (njt_strcmp(args[0].data, "body") == 0) {

        if (nelts != 3) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "body parameter number %u error.",
                               nelts);
            return NJT_CONF_ERROR;
        }

        if (njt_strncmp(args[1].data, "!~", 2) == 0) {

            match->body.operation = NJT_HTTP_MATCH_NOT_REG_MATCH;
        } else if (njt_strncmp(args[1].data, "~", 1) == 0) {

            match->body.operation = NJT_HTTP_MATCH_REG_MATCH;
        } else {
            /*log the case*/
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "body operation %V isn't supported error.", &args[1]);
            return NJT_CONF_ERROR;
        }

        match->body.regex = njt_http_match_regex_value(cf, &args[2]);
        if (match->body.regex == NULL) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "body regex %V parse error.",
                               &args[2]);
            return NJT_CONF_ERROR;
        }

        match->body.value = args[2];

    } else {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "Not supported match directive %V.",
                           &args[0]);
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


static void *
njt_http_match_create_main_conf(njt_conf_t *cf)
{
    njt_http_match_main_conf_t *hmmcf;

    hmmcf = njt_pcalloc(cf->pool, sizeof(njt_http_match_main_conf_t));
    if (hmmcf == NULL) {
        return NULL;
    }

    if (njt_array_init(&hmmcf->matches, cf->pool, 4,
                       sizeof(njt_http_match_t))
        != NJT_OK) {
        return NULL;
    }

    return hmmcf;
}

static char *
njt_http_match_init_main_conf(njt_conf_t *cf, void *conf)
{
    njt_http_match_main_conf_t   *hmmcf;
    njt_uint_t                    i;
    njt_http_match_t             *match;

    hmmcf = conf;

    match = hmmcf->matches.elts;
    for (i = 0; i < hmmcf->matches.nelts; i++) {
        match = match + i;
        if (match->defined == 0) {
            /*not defined*/
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "match %V is not defined.", &match->name);
            return NJT_CONF_ERROR;
        }
    }

    return NJT_CONF_OK;
}


njt_http_match_t *njt_http_match_create(njt_conf_t *cf, njt_str_t *name,
                                        njt_flag_t create)
{
    njt_http_match_main_conf_t   *hmmcf;
    njt_http_match_t             *match, *matches;
    njt_uint_t                    i;

    hmmcf = njt_http_conf_get_module_main_conf(cf, njt_http_match_module);

    matches = hmmcf->matches.elts;
    for (i = 0; i < hmmcf->matches.nelts; i++) {

        match = matches + i;
        if (match->name.len != name->len) {
            continue;
        }

        if (njt_strncasecmp(match->name.data, name->data, name->len) == 0) {

            if (!create) {
                return match;
            } else {
                if (match->defined) {
                    /*LOG the case. duplcated defined match*/
                    return NULL;
                }
                match->defined = 1;
                return match;
            }
        }
    }

    match = njt_array_push(&hmmcf->matches);

    if (match == NULL) {
        return NULL;
    }

    njt_memzero(match, sizeof(njt_http_match_t));
    match->defined = create;
    match->name.len = name->len;
    match->name.data = name->data;

    return match;
}
