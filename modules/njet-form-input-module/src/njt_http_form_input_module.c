#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include <ndk.h>
#include <njet.h>
#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


#define form_urlencoded_type "application/x-www-form-urlencoded"
#define form_urlencoded_type_len (sizeof(form_urlencoded_type) - 1)


typedef struct {
    unsigned        used;  /* :1 */
} njt_http_form_input_main_conf_t;


typedef struct {
    unsigned          done:1;
    unsigned          waiting_more_body:1;
} njt_http_form_input_ctx_t;


static njt_int_t njt_http_set_form_input(njt_http_request_t *r, njt_str_t *res,
    njt_http_variable_value_t *v);
static char *njt_http_set_form_input_conf_handler(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);
static void *njt_http_form_input_create_main_conf(njt_conf_t *cf);
static njt_int_t njt_http_form_input_init(njt_conf_t *cf);
static njt_int_t njt_http_form_input_handler(njt_http_request_t *r);
static void njt_http_form_input_post_read(njt_http_request_t *r);
static njt_int_t njt_http_form_input_arg(njt_http_request_t *r, u_char *name,
    size_t len, njt_str_t *value, njt_flag_t multi);


static njt_command_t njt_http_form_input_commands[] = {

    { njt_string("set_form_input"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE12,
      njt_http_set_form_input_conf_handler,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("set_form_input_multi"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE12,
      njt_http_set_form_input_conf_handler,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      njt_null_command
};


static njt_http_module_t njt_http_form_input_module_ctx = {
    NULL,                                   /* preconfiguration */
    njt_http_form_input_init,               /* postconfiguration */

    njt_http_form_input_create_main_conf,   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    NULL,                                   /* create location configuration */
    NULL                                    /* merge location configuration */
};


njt_module_t njt_http_form_input_module = {
    NJT_MODULE_V1,
    &njt_http_form_input_module_ctx,        /* module context */
    njt_http_form_input_commands,           /* module directives */
    NJT_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit precess */
    NULL,                                   /* exit master */
    NJT_MODULE_V1_PADDING
};


static njt_int_t
njt_http_set_form_input(njt_http_request_t *r, njt_str_t *res,
    njt_http_variable_value_t *v)
{
    njt_http_form_input_ctx_t           *ctx;
    njt_int_t                            rc;

    dd_enter();

    dd("set default return value");
    njt_str_set(res, "");

    if (r->done) {
        dd("request done");
        return NJT_OK;
    }

    ctx = njt_http_get_module_ctx(r, njt_http_form_input_module);

    if (ctx == NULL) {
        dd("ndk handler:null ctx");
        return NJT_OK;
    }

    if (!ctx->done) {
        dd("ctx not done");
        return NJT_OK;
    }

    rc = njt_http_form_input_arg(r, v->data, v->len, res, 0);

    return rc;
}


static njt_int_t
njt_http_set_form_input_multi(njt_http_request_t *r, njt_str_t *res,
    njt_http_variable_value_t *v)
{
    njt_http_form_input_ctx_t           *ctx;
    njt_int_t                            rc;

    dd_enter();

    dd("set default return value");
    njt_str_set(res, "");

    /* dd("set default return value"); */

    if (r->done) {
        return NJT_OK;
    }

    ctx = njt_http_get_module_ctx(r, njt_http_form_input_module);

    if (ctx == NULL) {
        dd("ndk handler:null ctx");
        return NJT_OK;
    }

    if (!ctx->done) {
        dd("ctx not done");
        return NJT_OK;
    }

    rc = njt_http_form_input_arg(r, v->data, v->len, res, 1);

    return rc;
}


/* fork from njt_http_arg.
 * read argument(s) with name arg_name and length arg_len into value variable,
 * if multi flag is set, multi arguments with name arg_name will be read and
 * stored in an njt_array_t struct, this can be operated by directives in
 * array-var-nginx-module */
static njt_int_t
njt_http_form_input_arg(njt_http_request_t *r, u_char *arg_name, size_t arg_len,
    njt_str_t *value, njt_flag_t multi)
{
    u_char              *p, *v, *last, *buf;
    njt_chain_t         *cl;
    size_t               len = 0;
    njt_array_t         *array = NULL;
    njt_str_t           *s;
    njt_buf_t           *b;

    if (multi) {
        array = njt_array_create(r->pool, 1, sizeof(njt_str_t));
        if (array == NULL) {
            return NJT_ERROR;
        }
        value->data = (u_char *)array;
        value->len = sizeof(njt_array_t);

    } else {
        njt_str_set(value, "");
    }

    /* we read data from r->request_body->bufs */
    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        dd("empty rb or empty rb bufs");
        return NJT_OK;
    }

    if (r->request_body->bufs->next != NULL) {
        /* more than one buffer...we should copy the data out... */
        len = 0;
        for (cl = r->request_body->bufs; cl; cl = cl->next) {
            b = cl->buf;

            if (b->in_file) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "form-input: in-file buffer found. aborted. "
                              "consider increasing your "
                              "client_body_buffer_size setting");

                return NJT_OK;
            }

            len += b->last - b->pos;
        }

        dd("len=%d", (int) len);

        if (len == 0) {
            return NJT_OK;
        }

        buf = njt_palloc(r->pool, len);
        if (buf == NULL) {
            return NJT_ERROR;
        }

        p = buf;
        last = p + len;

        for (cl = r->request_body->bufs; cl; cl = cl->next) {
            p = njt_copy(p, cl->buf->pos, cl->buf->last - cl->buf->pos);
        }

        dd("p - buf = %d, last - buf = %d", (int) (p - buf),
           (int) (last - buf));

        dd("copied buf (len %d): %.*s", (int) len, (int) len,
           buf);

    } else {
        dd("XXX one buffer only");

        b = r->request_body->bufs->buf;
        if (njt_buf_size(b) == 0) {
            return NJT_OK;
        }

        buf = b->pos;
        last = b->last;
    }

    for (p = buf; p < last; p++) {
        /* we need '=' after name, so drop one char from last */

        p = njt_strlcasestrn(p, last - 1, arg_name, arg_len - 1);
        if (p == NULL) {
            return NJT_OK;
        }

        dd("found argument name, offset: %d", (int) (p - buf));

        if ((p == buf || *(p - 1) == '&') && *(p + arg_len) == '=') {
            v = p + arg_len + 1;
            dd("v = %d...", (int) (v - buf));

            dd("buf now (len %d): %.*s",
               (int) (last - v), (int) (last - v), v);

            p = njt_strlchr(v, last, '&');
            if (p == NULL) {
                dd("& not found, pointing it to last...");
                p = last;

            } else {
                dd("found &, pointing it to %d...", (int) (p - buf));
            }

            if (multi) {
                s = njt_array_push(array);
                if (s == NULL) {
                    return NJT_ERROR;
                }
                s->data = v;
                s->len = p - v;
                dd("array var:%.*s", (int) s->len, s->data);

            } else {
                value->data = v;
                value->len = p - v;
                dd("value: [%.*s]", (int) value->len, value->data);
                return NJT_OK;
            }
        }
    }

#if 0
    if (multi) {
        value->data = (u_char *) array;
        value->len = sizeof(njt_array_t);
    }
#endif

    return NJT_OK;
}


static char *
njt_http_set_form_input_conf_handler(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    ndk_set_var_t                            filter;
    njt_str_t                               *value, s;
    u_char                                  *p;
    njt_http_form_input_main_conf_t         *fmcf;

#if defined(nginx_version) && nginx_version >= 8042 && nginx_version <= 8053
    return "does not work with " NGINX_VER;
#endif

    fmcf = njt_http_conf_get_module_main_conf(cf, njt_http_form_input_module);

    fmcf->used = 1;

    filter.type = NDK_SET_VAR_MULTI_VALUE;
    filter.size = 1;

    value = cf->args->elts;

    if ((value->len == sizeof("set_form_input_multi") - 1) &&
        njt_strncmp(value->data, "set_form_input_multi", value->len) == 0)
    {
        dd("use njt_http_form_input_multi");
        filter.func = (void *) njt_http_set_form_input_multi;

    } else {
        filter.func = (void *) njt_http_set_form_input;
    }

    value++;

    if (cf->args->nelts == 2) {
        p = value->data;
        p++;
        s.len = value->len - 1;
        s.data = p;

    } else if (cf->args->nelts == 3) {
        s.len = (value + 1)->len;
        s.data = (value + 1)->data;
    }

    return ndk_set_var_multi_value_core (cf, value,  &s, &filter);
}


/* register a new rewrite phase handler */
static njt_int_t
njt_http_form_input_init(njt_conf_t *cf)
{

    njt_http_handler_pt             *h;
    njt_http_core_main_conf_t       *cmcf;
    njt_http_form_input_main_conf_t *fmcf;

    fmcf = njt_http_conf_get_module_main_conf(cf, njt_http_form_input_module);

    if (!fmcf->used) {
        return NJT_OK;
    }

    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);

    h = njt_array_push(&cmcf->phases[NJT_HTTP_REWRITE_PHASE].handlers);

    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_http_form_input_handler;

    return NJT_OK;
}


/* an rewrite phase handler */
static njt_int_t
njt_http_form_input_handler(njt_http_request_t *r)
{
    njt_http_form_input_ctx_t       *ctx;
    njt_str_t                        value;
    njt_int_t                        rc;

    dd_enter();

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http form_input rewrite phase handler");

    ctx = njt_http_get_module_ctx(r, njt_http_form_input_module);

    if (ctx != NULL) {
        if (ctx->done) {
            njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http form_input rewrite phase handler done");

            return NJT_DECLINED;
        }

        return NJT_DONE;
    }

    if (r->method != NJT_HTTP_POST && r->method != NJT_HTTP_PUT) {
        return NJT_DECLINED;
    }

    if (r->headers_in.content_type == NULL
        || r->headers_in.content_type->value.data == NULL)
    {
        dd("content_type is %p", r->headers_in.content_type);

        return NJT_DECLINED;
    }

    value = r->headers_in.content_type->value;

    dd("r->headers_in.content_length_n:%d",
       (int) r->headers_in.content_length_n);

    /* just focus on x-www-form-urlencoded */

    if (value.len < form_urlencoded_type_len
        || njt_strncasecmp(value.data, (u_char *) form_urlencoded_type,
                           form_urlencoded_type_len) != 0)
    {
        dd("not application/x-www-form-urlencoded");
        return NJT_DECLINED;
    }

    dd("content type is application/x-www-form-urlencoded");

    dd("create new ctx");

    ctx = njt_pcalloc(r->pool, sizeof(njt_http_form_input_ctx_t));
    if (ctx == NULL) {
        return NJT_ERROR;
    }

    /* set by njt_pcalloc:
     *      ctx->done = 0;
     *      ctx->waiting_more_body = 0;
     */

    njt_http_set_ctx(r, ctx, njt_http_form_input_module);

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http form_input start to read client request body");

    rc = njt_http_read_client_request_body(r, njt_http_form_input_post_read);

    if (rc == NJT_ERROR || rc >= NJT_HTTP_SPECIAL_RESPONSE) {
#if (nginx_version < 1002006) ||                                             \
        (nginx_version >= 1003000 && nginx_version < 1003009)
        r->main->count--;
#endif

        return rc;
    }

    if (rc == NJT_AGAIN) {
        ctx->waiting_more_body = 1;

        return NJT_DONE;
    }

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http form_input has read the request body in one run");

    return NJT_DECLINED;
}


static void
njt_http_form_input_post_read(njt_http_request_t *r)
{
    njt_http_form_input_ctx_t     *ctx;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http form_input post read request body");

    ctx = njt_http_get_module_ctx(r, njt_http_form_input_module);

    ctx->done = 1;

#if defined(nginx_version) && nginx_version >= 8011
    dd("count--");
    r->main->count--;
#endif

    dd("waiting more body: %d", (int) ctx->waiting_more_body);

    /* waiting_more_body my rewrite phase handler */
    if (ctx->waiting_more_body) {
        ctx->waiting_more_body = 0;

        njt_http_core_run_phases(r);
    }
}


static void *
njt_http_form_input_create_main_conf(njt_conf_t *cf)
{
    njt_http_form_input_main_conf_t    *fmcf;

    fmcf = njt_pcalloc(cf->pool, sizeof(njt_http_form_input_main_conf_t));
    if (fmcf == NULL) {
        return NULL;
    }

    /* set by njt_pcalloc:
     *      fmcf->used = 0;
     */

    return fmcf;
}
