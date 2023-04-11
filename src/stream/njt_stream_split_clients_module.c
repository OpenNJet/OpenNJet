
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>


typedef struct {
    uint32_t                      percent;
    njt_stream_variable_value_t   value;
} njt_stream_split_clients_part_t;


typedef struct {
    njt_stream_complex_value_t    value;
    njt_array_t                   parts;
} njt_stream_split_clients_ctx_t;


static char *njt_conf_split_clients_block(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_stream_split_clients(njt_conf_t *cf, njt_command_t *dummy,
    void *conf);

static njt_command_t  njt_stream_split_clients_commands[] = {

    { njt_string("split_clients"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_BLOCK|NJT_CONF_TAKE2,
      njt_conf_split_clients_block,
      NJT_STREAM_MAIN_CONF_OFFSET,
      0,
      NULL },

      njt_null_command
};


static njt_stream_module_t  njt_stream_split_clients_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL                                   /* merge server configuration */
};


njt_module_t  njt_stream_split_clients_module = {
    NJT_MODULE_V1,
    &njt_stream_split_clients_module_ctx,  /* module context */
    njt_stream_split_clients_commands,     /* module directives */
    NJT_STREAM_MODULE,                     /* module type */
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
njt_stream_split_clients_variable(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    njt_stream_split_clients_ctx_t *ctx =
                                       (njt_stream_split_clients_ctx_t *) data;

    uint32_t                          hash;
    njt_str_t                         val;
    njt_uint_t                        i;
    njt_stream_split_clients_part_t  *part;

    *v = njt_stream_variable_null_value;

    if (njt_stream_complex_value(s, &ctx->value, &val) != NJT_OK) {
        return NJT_OK;
    }

    hash = njt_murmur_hash2(val.data, val.len);

    part = ctx->parts.elts;

    for (i = 0; i < ctx->parts.nelts; i++) {

        njt_log_debug2(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "stream split: %uD %uD", hash, part[i].percent);

        if (hash < part[i].percent || part[i].percent == 0) {
            *v = part[i].value;
            return NJT_OK;
        }
    }

    return NJT_OK;
}


static char *
njt_conf_split_clients_block(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char                                *rv;
    uint32_t                             sum, last;
    njt_str_t                           *value, name;
    njt_uint_t                           i;
    njt_conf_t                           save;
    njt_stream_variable_t               *var;
    njt_stream_split_clients_ctx_t      *ctx;
    njt_stream_split_clients_part_t     *part;
    njt_stream_compile_complex_value_t   ccv;

    ctx = njt_pcalloc(cf->pool, sizeof(njt_stream_split_clients_ctx_t));
    if (ctx == NULL) {
        return NJT_CONF_ERROR;
    }

    value = cf->args->elts;

    njt_memzero(&ccv, sizeof(njt_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &ctx->value;

    if (njt_stream_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    name = value[2];

    if (name.data[0] != '$') {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &name);
        return NJT_CONF_ERROR;
    }

    name.len--;
    name.data++;

    var = njt_stream_add_variable(cf, &name, NJT_STREAM_VAR_CHANGEABLE);
    if (var == NULL) {
        return NJT_CONF_ERROR;
    }

    var->get_handler = njt_stream_split_clients_variable;
    var->data = (uintptr_t) ctx;

    if (njt_array_init(&ctx->parts, cf->pool, 2,
                       sizeof(njt_stream_split_clients_part_t))
        != NJT_OK)
    {
        return NJT_CONF_ERROR;
    }

    save = *cf;
    cf->ctx = ctx;
    cf->handler = njt_stream_split_clients;
    cf->handler_conf = conf;

    rv = njt_conf_parse(cf, NULL);

    *cf = save;

    if (rv != NJT_CONF_OK) {
        return rv;
    }

    sum = 0;
    last = 0;
    part = ctx->parts.elts;

    for (i = 0; i < ctx->parts.nelts; i++) {
        sum = part[i].percent ? sum + part[i].percent : 10000;
        if (sum > 10000) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "percent total is greater than 100%%");
            return NJT_CONF_ERROR;
        }

        if (part[i].percent) {
            last += part[i].percent * (uint64_t) 0xffffffff / 10000;
            part[i].percent = last;
        }
    }

    return rv;
}


static char *
njt_stream_split_clients(njt_conf_t *cf, njt_command_t *dummy, void *conf)
{
    njt_int_t                         n;
    njt_str_t                        *value;
    njt_stream_split_clients_ctx_t   *ctx;
    njt_stream_split_clients_part_t  *part;

    ctx = cf->ctx;
    value = cf->args->elts;

    part = njt_array_push(&ctx->parts);
    if (part == NULL) {
        return NJT_CONF_ERROR;
    }

    if (value[0].len == 1 && value[0].data[0] == '*') {
        part->percent = 0;

    } else {
        if (value[0].len == 0 || value[0].data[value[0].len - 1] != '%') {
            goto invalid;
        }

        n = njt_atofp(value[0].data, value[0].len - 1, 2);
        if (n == NJT_ERROR || n == 0) {
            goto invalid;
        }

        part->percent = (uint32_t) n;
    }

    part->value.len = value[1].len;
    part->value.valid = 1;
    part->value.no_cacheable = 0;
    part->value.not_found = 0;
    part->value.data = value[1].data;

    return NJT_CONF_OK;

invalid:

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "invalid percent value \"%V\"", &value[0]);
    return NJT_CONF_ERROR;
}
