
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


typedef struct njt_http_header_val_s  njt_http_header_val_t;

typedef njt_int_t (*njt_http_set_header_pt)(njt_http_request_t *r,
    njt_http_header_val_t *hv, njt_str_t *value);


typedef struct {
    njt_str_t                  name;
    njt_uint_t                 offset;
    njt_http_set_header_pt     handler;
} njt_http_set_header_t;


struct njt_http_header_val_s {
    njt_http_complex_value_t   value;
    njt_str_t                  key;
    njt_http_set_header_pt     handler;
    njt_uint_t                 offset;
    njt_uint_t                 always;  /* unsigned  always:1 */
};


typedef enum {
    NJT_HTTP_EXPIRES_OFF,
    NJT_HTTP_EXPIRES_EPOCH,
    NJT_HTTP_EXPIRES_MAX,
    NJT_HTTP_EXPIRES_ACCESS,
    NJT_HTTP_EXPIRES_MODIFIED,
    NJT_HTTP_EXPIRES_DAILY,
    NJT_HTTP_EXPIRES_UNSET
} njt_http_expires_t;


typedef struct {
    njt_http_expires_t         expires;
    time_t                     expires_time;
    njt_http_complex_value_t  *expires_value;
    njt_array_t               *headers;
    njt_array_t               *trailers;
} njt_http_headers_conf_t;


static njt_int_t njt_http_set_expires(njt_http_request_t *r,
    njt_http_headers_conf_t *conf);
static njt_int_t njt_http_parse_expires(njt_str_t *value,
    njt_http_expires_t *expires, time_t *expires_time, char **err);
static njt_int_t njt_http_add_multi_header_lines(njt_http_request_t *r,
    njt_http_header_val_t *hv, njt_str_t *value);
static njt_int_t njt_http_add_header(njt_http_request_t *r,
    njt_http_header_val_t *hv, njt_str_t *value);
static njt_int_t njt_http_set_last_modified(njt_http_request_t *r,
    njt_http_header_val_t *hv, njt_str_t *value);
static njt_int_t njt_http_set_response_header(njt_http_request_t *r,
    njt_http_header_val_t *hv, njt_str_t *value);

static void *njt_http_headers_create_conf(njt_conf_t *cf);
static char *njt_http_headers_merge_conf(njt_conf_t *cf,
    void *parent, void *child);
static njt_int_t njt_http_headers_filter_init(njt_conf_t *cf);
static char *njt_http_headers_expires(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_headers_add(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);


static njt_http_set_header_t  njt_http_set_headers[] = {

    { njt_string("Cache-Control"),
                 offsetof(njt_http_headers_out_t, cache_control),
                 njt_http_add_multi_header_lines },

    { njt_string("Link"),
                 offsetof(njt_http_headers_out_t, link),
                 njt_http_add_multi_header_lines },

    { njt_string("Last-Modified"),
                 offsetof(njt_http_headers_out_t, last_modified),
                 njt_http_set_last_modified },

    { njt_string("ETag"),
                 offsetof(njt_http_headers_out_t, etag),
                 njt_http_set_response_header },

    { njt_null_string, 0, NULL }
};


static njt_command_t  njt_http_headers_filter_commands[] = {

    { njt_string("expires"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_CONF_TAKE12,
      njt_http_headers_expires,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("add_header"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_CONF_TAKE23,
      njt_http_headers_add,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_headers_conf_t, headers),
      NULL },

    { njt_string("add_trailer"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_CONF_TAKE23,
      njt_http_headers_add,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_headers_conf_t, trailers),
      NULL },

      njt_null_command
};


static njt_http_module_t  njt_http_headers_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    njt_http_headers_filter_init,          /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_headers_create_conf,          /* create location configuration */
    njt_http_headers_merge_conf            /* merge location configuration */
};


njt_module_t  njt_http_headers_filter_module = {
    NJT_MODULE_V1,
    &njt_http_headers_filter_module_ctx,   /* module context */
    njt_http_headers_filter_commands,      /* module directives */
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


static njt_http_output_header_filter_pt  njt_http_next_header_filter;
static njt_http_output_body_filter_pt    njt_http_next_body_filter;


static njt_int_t
njt_http_headers_filter(njt_http_request_t *r)
{
    njt_str_t                 value;
    njt_uint_t                i, safe_status;
    njt_http_header_val_t    *h;
    njt_http_headers_conf_t  *conf;

    if (r != r->main) {
        return njt_http_next_header_filter(r);
    }

    conf = njt_http_get_module_loc_conf(r, njt_http_headers_filter_module);

    if (conf->expires == NJT_HTTP_EXPIRES_OFF
        && conf->headers == NULL
        && conf->trailers == NULL)
    {
        return njt_http_next_header_filter(r);
    }

    switch (r->headers_out.status) {

    case NJT_HTTP_OK:
    case NJT_HTTP_CREATED:
    case NJT_HTTP_NO_CONTENT:
    case NJT_HTTP_PARTIAL_CONTENT:
    case NJT_HTTP_MOVED_PERMANENTLY:
    case NJT_HTTP_MOVED_TEMPORARILY:
    case NJT_HTTP_SEE_OTHER:
    case NJT_HTTP_NOT_MODIFIED:
    case NJT_HTTP_TEMPORARY_REDIRECT:
    case NJT_HTTP_PERMANENT_REDIRECT:
        safe_status = 1;
        break;

    default:
        safe_status = 0;
        break;
    }

    if (conf->expires != NJT_HTTP_EXPIRES_OFF && safe_status) {
        if (njt_http_set_expires(r, conf) != NJT_OK) {
            return NJT_ERROR;
        }
    }

    if (conf->headers) {
        h = conf->headers->elts;
        for (i = 0; i < conf->headers->nelts; i++) {

            if (!safe_status && !h[i].always) {
                continue;
            }

            if (njt_http_complex_value(r, &h[i].value, &value) != NJT_OK) {
                return NJT_ERROR;
            }

            if (h[i].handler(r, &h[i], &value) != NJT_OK) {
                return NJT_ERROR;
            }
        }
    }

    if (conf->trailers) {
        h = conf->trailers->elts;
        for (i = 0; i < conf->trailers->nelts; i++) {

            if (!safe_status && !h[i].always) {
                continue;
            }

            r->expect_trailers = 1;
            break;
        }
    }

    return njt_http_next_header_filter(r);
}


static njt_int_t
njt_http_trailers_filter(njt_http_request_t *r, njt_chain_t *in)
{
    njt_str_t                 value;
    njt_uint_t                i, safe_status;
    njt_chain_t              *cl;
    njt_table_elt_t          *t;
    njt_http_header_val_t    *h;
    njt_http_headers_conf_t  *conf;

    conf = njt_http_get_module_loc_conf(r, njt_http_headers_filter_module);

    if (in == NULL
        || conf->trailers == NULL
        || !r->expect_trailers
        || r->header_only)
    {
        return njt_http_next_body_filter(r, in);
    }

    for (cl = in; cl; cl = cl->next) {
        if (cl->buf->last_buf) {
            break;
        }
    }

    if (cl == NULL) {
        return njt_http_next_body_filter(r, in);
    }

    switch (r->headers_out.status) {

    case NJT_HTTP_OK:
    case NJT_HTTP_CREATED:
    case NJT_HTTP_NO_CONTENT:
    case NJT_HTTP_PARTIAL_CONTENT:
    case NJT_HTTP_MOVED_PERMANENTLY:
    case NJT_HTTP_MOVED_TEMPORARILY:
    case NJT_HTTP_SEE_OTHER:
    case NJT_HTTP_NOT_MODIFIED:
    case NJT_HTTP_TEMPORARY_REDIRECT:
    case NJT_HTTP_PERMANENT_REDIRECT:
        safe_status = 1;
        break;

    default:
        safe_status = 0;
        break;
    }

    h = conf->trailers->elts;
    for (i = 0; i < conf->trailers->nelts; i++) {

        if (!safe_status && !h[i].always) {
            continue;
        }

        if (njt_http_complex_value(r, &h[i].value, &value) != NJT_OK) {
            return NJT_ERROR;
        }

        if (value.len) {
            t = njt_list_push(&r->headers_out.trailers);
            if (t == NULL) {
                return NJT_ERROR;
            }

            t->key = h[i].key;
            t->value = value;
            t->hash = 1;
        }
    }

    return njt_http_next_body_filter(r, in);
}


static njt_int_t
njt_http_set_expires(njt_http_request_t *r, njt_http_headers_conf_t *conf)
{
    char                *err;
    size_t               len;
    time_t               now, expires_time, max_age;
    njt_str_t            value;
    njt_int_t            rc;
    njt_table_elt_t     *e, *cc;
    njt_http_expires_t   expires;

    expires = conf->expires;
    expires_time = conf->expires_time;

    if (conf->expires_value != NULL) {

        if (njt_http_complex_value(r, conf->expires_value, &value) != NJT_OK) {
            return NJT_ERROR;
        }

        rc = njt_http_parse_expires(&value, &expires, &expires_time, &err);

        if (rc != NJT_OK) {
            return NJT_OK;
        }

        if (expires == NJT_HTTP_EXPIRES_OFF) {
            return NJT_OK;
        }
    }

    e = r->headers_out.expires;

    if (e == NULL) {

        e = njt_list_push(&r->headers_out.headers);
        if (e == NULL) {
            return NJT_ERROR;
        }

        r->headers_out.expires = e;
        e->next = NULL;

        e->hash = 1;
        njt_str_set(&e->key, "Expires");
    }

    len = sizeof("Mon, 28 Sep 1970 06:00:00 GMT");
    e->value.len = len - 1;

    cc = r->headers_out.cache_control;

    if (cc == NULL) {

        cc = njt_list_push(&r->headers_out.headers);
        if (cc == NULL) {
            e->hash = 0;
            return NJT_ERROR;
        }

        r->headers_out.cache_control = cc;
        cc->next = NULL;

        cc->hash = 1;
        njt_str_set(&cc->key, "Cache-Control");

    } else {
        for (cc = cc->next; cc; cc = cc->next) {
            cc->hash = 0;
        }

        cc = r->headers_out.cache_control;
        cc->next = NULL;
    }

    if (expires == NJT_HTTP_EXPIRES_EPOCH) {
        e->value.data = (u_char *) "Thu, 01 Jan 1970 00:00:01 GMT";
        njt_str_set(&cc->value, "no-cache");
        return NJT_OK;
    }

    if (expires == NJT_HTTP_EXPIRES_MAX) {
        e->value.data = (u_char *) "Thu, 31 Dec 2037 23:55:55 GMT";
        /* 10 years */
        njt_str_set(&cc->value, "max-age=315360000");
        return NJT_OK;
    }

    e->value.data = njt_pnalloc(r->pool, len);
    if (e->value.data == NULL) {
        e->hash = 0;
        cc->hash = 0;
        return NJT_ERROR;
    }

    if (expires_time == 0 && expires != NJT_HTTP_EXPIRES_DAILY) {
        njt_memcpy(e->value.data, njt_cached_http_time.data,
                   njt_cached_http_time.len + 1);
        njt_str_set(&cc->value, "max-age=0");
        return NJT_OK;
    }

    now = njt_time();

    if (expires == NJT_HTTP_EXPIRES_DAILY) {
        expires_time = njt_next_time(expires_time);
        max_age = expires_time - now;

    } else if (expires == NJT_HTTP_EXPIRES_ACCESS
               || r->headers_out.last_modified_time == -1)
    {
        max_age = expires_time;
        expires_time += now;

    } else {
        expires_time += r->headers_out.last_modified_time;
        max_age = expires_time - now;
    }

    njt_http_time(e->value.data, expires_time);

    if (conf->expires_time < 0 || max_age < 0) {
        njt_str_set(&cc->value, "no-cache");
        return NJT_OK;
    }

    cc->value.data = njt_pnalloc(r->pool,
                                 sizeof("max-age=") + NJT_TIME_T_LEN + 1);
    if (cc->value.data == NULL) {
        cc->hash = 0;
        return NJT_ERROR;
    }

    cc->value.len = njt_sprintf(cc->value.data, "max-age=%T", max_age)
                    - cc->value.data;

    return NJT_OK;
}


static njt_int_t
njt_http_parse_expires(njt_str_t *value, njt_http_expires_t *expires,
    time_t *expires_time, char **err)
{
    njt_uint_t  minus;

    if (*expires != NJT_HTTP_EXPIRES_MODIFIED) {

        if (value->len == 5 && njt_strncmp(value->data, "epoch", 5) == 0) {
            *expires = NJT_HTTP_EXPIRES_EPOCH;
            return NJT_OK;
        }

        if (value->len == 3 && njt_strncmp(value->data, "max", 3) == 0) {
            *expires = NJT_HTTP_EXPIRES_MAX;
            return NJT_OK;
        }

        if (value->len == 3 && njt_strncmp(value->data, "off", 3) == 0) {
            *expires = NJT_HTTP_EXPIRES_OFF;
            return NJT_OK;
        }
    }

    if (value->len && value->data[0] == '@') {
        value->data++;
        value->len--;
        minus = 0;

        if (*expires == NJT_HTTP_EXPIRES_MODIFIED) {
            *err = "daily time cannot be used with \"modified\" parameter";
            return NJT_ERROR;
        }

        *expires = NJT_HTTP_EXPIRES_DAILY;

    } else if (value->len && value->data[0] == '+') {
        value->data++;
        value->len--;
        minus = 0;

    } else if (value->len && value->data[0] == '-') {
        value->data++;
        value->len--;
        minus = 1;

    } else {
        minus = 0;
    }

    *expires_time = njt_parse_time(value, 1);

    if (*expires_time == (time_t) NJT_ERROR) {
        *err = "invalid value";
        return NJT_ERROR;
    }

    if (*expires == NJT_HTTP_EXPIRES_DAILY
        && *expires_time > 24 * 60 * 60)
    {
        *err = "daily time value must be less than 24 hours";
        return NJT_ERROR;
    }

    if (minus) {
        *expires_time = - *expires_time;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_add_header(njt_http_request_t *r, njt_http_header_val_t *hv,
    njt_str_t *value)
{
    njt_table_elt_t  *h;

    if (value->len) {
        h = njt_list_push(&r->headers_out.headers);
        if (h == NULL) {
            return NJT_ERROR;
        }

        h->hash = 1;
        h->key = hv->key;
        h->value = *value;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_add_multi_header_lines(njt_http_request_t *r,
    njt_http_header_val_t *hv, njt_str_t *value)
{
    njt_table_elt_t  *h, **ph;

    if (value->len == 0) {
        return NJT_OK;
    }

    h = njt_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    h->hash = 1;
    h->key = hv->key;
    h->value = *value;

    ph = (njt_table_elt_t **) ((char *) &r->headers_out + hv->offset);

    while (*ph) { ph = &(*ph)->next; }

    *ph = h;
    h->next = NULL;

    return NJT_OK;
}


static njt_int_t
njt_http_set_last_modified(njt_http_request_t *r, njt_http_header_val_t *hv,
    njt_str_t *value)
{
    if (njt_http_set_response_header(r, hv, value) != NJT_OK) {
        return NJT_ERROR;
    }

    r->headers_out.last_modified_time =
        (value->len) ? njt_parse_http_time(value->data, value->len) : -1;

    return NJT_OK;
}


static njt_int_t
njt_http_set_response_header(njt_http_request_t *r, njt_http_header_val_t *hv,
    njt_str_t *value)
{
    njt_table_elt_t  *h, **old;

    old = (njt_table_elt_t **) ((char *) &r->headers_out + hv->offset);

    if (value->len == 0) {
        if (*old) {
            (*old)->hash = 0;
            *old = NULL;
        }

        return NJT_OK;
    }

    if (*old) {
        h = *old;

    } else {
        h = njt_list_push(&r->headers_out.headers);
        if (h == NULL) {
            return NJT_ERROR;
        }

        *old = h;
        h->next = NULL;
    }

    h->hash = 1;
    h->key = hv->key;
    h->value = *value;

    return NJT_OK;
}


static void *
njt_http_headers_create_conf(njt_conf_t *cf)
{
    njt_http_headers_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_headers_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     conf->headers = NULL;
     *     conf->trailers = NULL;
     *     conf->expires_time = 0;
     *     conf->expires_value = NULL;
     */

    conf->expires = NJT_HTTP_EXPIRES_UNSET;

    return conf;
}


static char *
njt_http_headers_merge_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_headers_conf_t *prev = parent;
    njt_http_headers_conf_t *conf = child;

    if (conf->expires == NJT_HTTP_EXPIRES_UNSET) {
        conf->expires = prev->expires;
        conf->expires_time = prev->expires_time;
        conf->expires_value = prev->expires_value;

        if (conf->expires == NJT_HTTP_EXPIRES_UNSET) {
            conf->expires = NJT_HTTP_EXPIRES_OFF;
        }
    }

    if (conf->headers == NULL) {
        conf->headers = prev->headers;
    }

    if (conf->trailers == NULL) {
        conf->trailers = prev->trailers;
    }

    return NJT_CONF_OK;
}


static njt_int_t
njt_http_headers_filter_init(njt_conf_t *cf)
{
    njt_http_next_header_filter = njt_http_top_header_filter;
    njt_http_top_header_filter = njt_http_headers_filter;

    njt_http_next_body_filter = njt_http_top_body_filter;
    njt_http_top_body_filter = njt_http_trailers_filter;

    return NJT_OK;
}


static char *
njt_http_headers_expires(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_headers_conf_t *hcf = conf;

    char                              *err;
    njt_str_t                         *value;
    njt_int_t                          rc;
    njt_uint_t                         n;
    njt_http_complex_value_t           cv;
    njt_http_compile_complex_value_t   ccv;

    if (hcf->expires != NJT_HTTP_EXPIRES_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cf->args->nelts == 2) {

        hcf->expires = NJT_HTTP_EXPIRES_ACCESS;

        n = 1;

    } else { /* cf->args->nelts == 3 */

        if (njt_strcmp(value[1].data, "modified") != 0) {
            return "invalid value";
        }

        hcf->expires = NJT_HTTP_EXPIRES_MODIFIED;

        n = 2;
    }

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[n];
    ccv.complex_value = &cv;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    if (cv.lengths != NULL) {

        hcf->expires_value = njt_palloc(cf->pool,
                                        sizeof(njt_http_complex_value_t));
        if (hcf->expires_value == NULL) {
            return NJT_CONF_ERROR;
        }

        *hcf->expires_value = cv;

        return NJT_CONF_OK;
    }

    rc = njt_http_parse_expires(&value[n], &hcf->expires, &hcf->expires_time,
                                &err);
    if (rc != NJT_OK) {
        return err;
    }

    return NJT_CONF_OK;
}


static char *
njt_http_headers_add(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_headers_conf_t *hcf = conf;

    njt_str_t                          *value;
    njt_uint_t                          i;
    njt_array_t                       **headers;
    njt_http_header_val_t              *hv;
    njt_http_set_header_t              *set;
    njt_http_compile_complex_value_t    ccv;

    value = cf->args->elts;

    headers = (njt_array_t **) ((char *) hcf + cmd->offset);

    if (*headers == NULL) {
        *headers = njt_array_create(cf->pool, 1,
                                    sizeof(njt_http_header_val_t));
        if (*headers == NULL) {
            return NJT_CONF_ERROR;
        }
    }

    hv = njt_array_push(*headers);
    if (hv == NULL) {
        return NJT_CONF_ERROR;
    }

    hv->key = value[1];
    hv->handler = NULL;
    hv->offset = 0;
    hv->always = 0;

    if (headers == &hcf->headers) {
        hv->handler = njt_http_add_header;

        set = njt_http_set_headers;
        for (i = 0; set[i].name.len; i++) {
            if (njt_strcasecmp(value[1].data, set[i].name.data) != 0) {
                continue;
            }

            hv->offset = set[i].offset;
            hv->handler = set[i].handler;

            break;
        }
    }

    if (value[2].len == 0) {
        njt_memzero(&hv->value, sizeof(njt_http_complex_value_t));

    } else {
        njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[2];
        ccv.complex_value = &hv->value;

        if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
            return NJT_CONF_ERROR;
        }
    }

    if (cf->args->nelts == 3) {
        return NJT_CONF_OK;
    }

    if (njt_strcmp(value[3].data, "always") != 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[3]);
        return NJT_CONF_ERROR;
    }

    hv->always = 1;

    return NJT_CONF_OK;
}
