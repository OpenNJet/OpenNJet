
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


static njt_int_t njt_http_stub_status_handler(njt_http_request_t *r);
static njt_int_t njt_http_stub_status_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_stub_status_add_variables(njt_conf_t *cf);
static char *njt_http_set_stub_status(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);


static njt_command_t  njt_http_status_commands[] = {

    { njt_string("stub_status"),
      NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_NOARGS|NJT_CONF_TAKE1,
      njt_http_set_stub_status,
      0,
      0,
      NULL },

      njt_null_command
};


static njt_http_module_t  njt_http_stub_status_module_ctx = {
    njt_http_stub_status_add_variables,    /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


njt_module_t  njt_http_stub_status_module = {
    NJT_MODULE_V1,
    &njt_http_stub_status_module_ctx,      /* module context */
    njt_http_status_commands,              /* module directives */
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


static njt_http_variable_t  njt_http_stub_status_vars[] = {

    { njt_string("connections_active"), NULL, njt_http_stub_status_variable,
      0, NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("connections_reading"), NULL, njt_http_stub_status_variable,
      1, NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("connections_writing"), NULL, njt_http_stub_status_variable,
      2, NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("connections_waiting"), NULL, njt_http_stub_status_variable,
      3, NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

      njt_http_null_variable
};


static njt_int_t
njt_http_stub_status_handler(njt_http_request_t *r)
{
    size_t             size;
    njt_int_t          rc;
    njt_buf_t         *b;
    njt_chain_t        out;
    njt_atomic_int_t   ap, hn, ac, rq, rd, wr, wa;

    if (!(r->method & (NJT_HTTP_GET|NJT_HTTP_HEAD))) {
        return NJT_HTTP_NOT_ALLOWED;
    }

    rc = njt_http_discard_request_body(r);

    if (rc != NJT_OK) {
        return rc;
    }

    r->headers_out.content_type_len = sizeof("text/plain") - 1;
    njt_str_set(&r->headers_out.content_type, "text/plain");
    r->headers_out.content_type_lowcase = NULL;

    size = sizeof("Active connections:  \n") + NJT_ATOMIC_T_LEN
           + sizeof("server accepts handled requests\n") - 1
           + 6 + 3 * NJT_ATOMIC_T_LEN
           + sizeof("Reading:  Writing:  Waiting:  \n") + 3 * NJT_ATOMIC_T_LEN;

    b = njt_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    ap = *njt_stat_accepted;
    hn = *njt_stat_handled;
    ac = *njt_stat_active;
    rq = *njt_stat_requests;
    rd = *njt_stat_reading;
    wr = *njt_stat_writing;
    wa = *njt_stat_waiting;

    b->last = njt_sprintf(b->last, "Active connections: %uA \n", ac);

    b->last = njt_cpymem(b->last, "server accepts handled requests\n",
                         sizeof("server accepts handled requests\n") - 1);

    b->last = njt_sprintf(b->last, " %uA %uA %uA \n", ap, hn, rq);

    b->last = njt_sprintf(b->last, "Reading: %uA Writing: %uA Waiting: %uA \n",
                          rd, wr, wa);

    r->headers_out.status = NJT_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    rc = njt_http_send_header(r);

    if (rc == NJT_ERROR || rc > NJT_OK || r->header_only) {
        return rc;
    }

    return njt_http_output_filter(r, &out);
}


static njt_int_t
njt_http_stub_status_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    u_char            *p;
    njt_atomic_int_t   value;

    p = njt_pnalloc(r->pool, NJT_ATOMIC_T_LEN);
    if (p == NULL) {
        return NJT_ERROR;
    }

    switch (data) {
    case 0:
        value = *njt_stat_active;
        break;

    case 1:
        value = *njt_stat_reading;
        break;

    case 2:
        value = *njt_stat_writing;
        break;

    case 3:
        value = *njt_stat_waiting;
        break;

    /* suppress warning */
    default:
        value = 0;
        break;
    }

    v->len = njt_sprintf(p, "%uA", value) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NJT_OK;
}


static njt_int_t
njt_http_stub_status_add_variables(njt_conf_t *cf)
{
    njt_http_variable_t  *var, *v;

    for (v = njt_http_stub_status_vars; v->name.len; v++) {
        var = njt_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NJT_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NJT_OK;
}


static char *
njt_http_set_stub_status(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_core_loc_conf_t  *clcf;

    clcf = njt_http_conf_get_module_loc_conf(cf, njt_http_core_module);
    clcf->handler = njt_http_stub_status_handler;

    return NJT_CONF_OK;
}
