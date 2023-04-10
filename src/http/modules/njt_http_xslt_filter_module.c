
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxslt/xslt.h>
#include <libxslt/xsltInternals.h>
#include <libxslt/transform.h>
#include <libxslt/variables.h>
#include <libxslt/xsltutils.h>

#if (NJT_HAVE_EXSLT)
#include <libexslt/exslt.h>
#endif


#ifndef NJT_HTTP_XSLT_REUSE_DTD
#define NJT_HTTP_XSLT_REUSE_DTD  1
#endif


typedef struct {
    u_char                    *name;
    void                      *data;
} njt_http_xslt_file_t;


typedef struct {
    njt_array_t                dtd_files;    /* njt_http_xslt_file_t */
    njt_array_t                sheet_files;  /* njt_http_xslt_file_t */
} njt_http_xslt_filter_main_conf_t;


typedef struct {
    u_char                    *name;
    njt_http_complex_value_t   value;
    njt_uint_t                 quote;        /* unsigned  quote:1; */
} njt_http_xslt_param_t;


typedef struct {
    xsltStylesheetPtr          stylesheet;
    njt_array_t                params;       /* njt_http_xslt_param_t */
} njt_http_xslt_sheet_t;


typedef struct {
    xmlDtdPtr                  dtd;
    njt_array_t                sheets;       /* njt_http_xslt_sheet_t */
    njt_hash_t                 types;
    njt_array_t               *types_keys;
    njt_array_t               *params;       /* njt_http_xslt_param_t */
    njt_flag_t                 last_modified;
} njt_http_xslt_filter_loc_conf_t;


typedef struct {
    xmlDocPtr                  doc;
    xmlParserCtxtPtr           ctxt;
    xsltTransformContextPtr    transform;
    njt_http_request_t        *request;
    njt_array_t                params;

    njt_uint_t                 done;         /* unsigned  done:1; */
} njt_http_xslt_filter_ctx_t;


static njt_int_t njt_http_xslt_send(njt_http_request_t *r,
    njt_http_xslt_filter_ctx_t *ctx, njt_buf_t *b);
static njt_int_t njt_http_xslt_add_chunk(njt_http_request_t *r,
    njt_http_xslt_filter_ctx_t *ctx, njt_buf_t *b);


static void njt_http_xslt_sax_external_subset(void *data, const xmlChar *name,
    const xmlChar *externalId, const xmlChar *systemId);
static void njt_cdecl njt_http_xslt_sax_error(void *data, const char *msg, ...);


static njt_buf_t *njt_http_xslt_apply_stylesheet(njt_http_request_t *r,
    njt_http_xslt_filter_ctx_t *ctx);
static njt_int_t njt_http_xslt_params(njt_http_request_t *r,
    njt_http_xslt_filter_ctx_t *ctx, njt_array_t *params, njt_uint_t final);
static u_char *njt_http_xslt_content_type(xsltStylesheetPtr s);
static u_char *njt_http_xslt_encoding(xsltStylesheetPtr s);
static void njt_http_xslt_cleanup(void *data);

static char *njt_http_xslt_entities(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_xslt_stylesheet(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_xslt_param(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static void njt_http_xslt_cleanup_dtd(void *data);
static void njt_http_xslt_cleanup_stylesheet(void *data);
static void *njt_http_xslt_filter_create_main_conf(njt_conf_t *cf);
static void *njt_http_xslt_filter_create_conf(njt_conf_t *cf);
static char *njt_http_xslt_filter_merge_conf(njt_conf_t *cf, void *parent,
    void *child);
static njt_int_t njt_http_xslt_filter_preconfiguration(njt_conf_t *cf);
static njt_int_t njt_http_xslt_filter_init(njt_conf_t *cf);
static void njt_http_xslt_filter_exit(njt_cycle_t *cycle);


static njt_str_t  njt_http_xslt_default_types[] = {
    njt_string("text/xml"),
    njt_null_string
};


static njt_command_t  njt_http_xslt_filter_commands[] = {

    { njt_string("xml_entities"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_xslt_entities,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("xslt_stylesheet"),
      NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_http_xslt_stylesheet,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("xslt_param"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE2,
      njt_http_xslt_param,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("xslt_string_param"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE2,
      njt_http_xslt_param,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) 1 },

    { njt_string("xslt_types"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_http_types_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_xslt_filter_loc_conf_t, types_keys),
      &njt_http_xslt_default_types[0] },

    { njt_string("xslt_last_modified"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_xslt_filter_loc_conf_t, last_modified),
      NULL },

      njt_null_command
};


static njt_http_module_t  njt_http_xslt_filter_module_ctx = {
    njt_http_xslt_filter_preconfiguration, /* preconfiguration */
    njt_http_xslt_filter_init,             /* postconfiguration */

    njt_http_xslt_filter_create_main_conf, /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_xslt_filter_create_conf,      /* create location configuration */
    njt_http_xslt_filter_merge_conf        /* merge location configuration */
};


njt_module_t  njt_http_xslt_filter_module = {
    NJT_MODULE_V1,
    &njt_http_xslt_filter_module_ctx,      /* module context */
    njt_http_xslt_filter_commands,         /* module directives */
    NJT_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    njt_http_xslt_filter_exit,             /* exit process */
    njt_http_xslt_filter_exit,             /* exit master */
    NJT_MODULE_V1_PADDING
};


static njt_http_output_header_filter_pt  njt_http_next_header_filter;
static njt_http_output_body_filter_pt    njt_http_next_body_filter;


static njt_int_t
njt_http_xslt_header_filter(njt_http_request_t *r)
{
    njt_http_xslt_filter_ctx_t       *ctx;
    njt_http_xslt_filter_loc_conf_t  *conf;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "xslt filter header");

    if (r->headers_out.status == NJT_HTTP_NOT_MODIFIED) {
        return njt_http_next_header_filter(r);
    }

    conf = njt_http_get_module_loc_conf(r, njt_http_xslt_filter_module);

    if (conf->sheets.nelts == 0
        || njt_http_test_content_type(r, &conf->types) == NULL)
    {
        return njt_http_next_header_filter(r);
    }

    ctx = njt_http_get_module_ctx(r, njt_http_xslt_filter_module);

    if (ctx) {
        return njt_http_next_header_filter(r);
    }

    ctx = njt_pcalloc(r->pool, sizeof(njt_http_xslt_filter_ctx_t));
    if (ctx == NULL) {
        return NJT_ERROR;
    }

    njt_http_set_ctx(r, ctx, njt_http_xslt_filter_module);

    r->main_filter_need_in_memory = 1;
    r->allow_ranges = 0;

    return NJT_OK;
}


static njt_int_t
njt_http_xslt_body_filter(njt_http_request_t *r, njt_chain_t *in)
{
    int                          wellFormed;
    njt_chain_t                 *cl;
    njt_http_xslt_filter_ctx_t  *ctx;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "xslt filter body");

    if (in == NULL) {
        return njt_http_next_body_filter(r, in);
    }

    ctx = njt_http_get_module_ctx(r, njt_http_xslt_filter_module);

    if (ctx == NULL || ctx->done) {
        return njt_http_next_body_filter(r, in);
    }

    for (cl = in; cl; cl = cl->next) {

        if (njt_http_xslt_add_chunk(r, ctx, cl->buf) != NJT_OK) {

            if (ctx->ctxt->myDoc) {

#if (NJT_HTTP_XSLT_REUSE_DTD)
                ctx->ctxt->myDoc->extSubset = NULL;
#endif
                xmlFreeDoc(ctx->ctxt->myDoc);
            }

            xmlFreeParserCtxt(ctx->ctxt);

            return njt_http_xslt_send(r, ctx, NULL);
        }

        if (cl->buf->last_buf || cl->buf->last_in_chain) {

            ctx->doc = ctx->ctxt->myDoc;

#if (NJT_HTTP_XSLT_REUSE_DTD)
            ctx->doc->extSubset = NULL;
#endif

            wellFormed = ctx->ctxt->wellFormed;

            xmlFreeParserCtxt(ctx->ctxt);

            if (wellFormed) {
                return njt_http_xslt_send(r, ctx,
                                       njt_http_xslt_apply_stylesheet(r, ctx));
            }

            xmlFreeDoc(ctx->doc);

            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "not well formed XML document");

            return njt_http_xslt_send(r, ctx, NULL);
        }
    }

    return NJT_OK;
}


static njt_int_t
njt_http_xslt_send(njt_http_request_t *r, njt_http_xslt_filter_ctx_t *ctx,
    njt_buf_t *b)
{
    njt_int_t                         rc;
    njt_chain_t                       out;
    njt_pool_cleanup_t               *cln;
    njt_http_xslt_filter_loc_conf_t  *conf;

    ctx->done = 1;

    if (b == NULL) {
        return njt_http_filter_finalize_request(r, &njt_http_xslt_filter_module,
                                               NJT_HTTP_INTERNAL_SERVER_ERROR);
    }

    cln = njt_pool_cleanup_add(r->pool, 0);

    if (cln == NULL) {
        njt_free(b->pos);
        return njt_http_filter_finalize_request(r, &njt_http_xslt_filter_module,
                                               NJT_HTTP_INTERNAL_SERVER_ERROR);
    }

    if (r == r->main) {
        r->headers_out.content_length_n = b->last - b->pos;

        if (r->headers_out.content_length) {
            r->headers_out.content_length->hash = 0;
            r->headers_out.content_length = NULL;
        }

        conf = njt_http_get_module_loc_conf(r, njt_http_xslt_filter_module);

        if (!conf->last_modified) {
            njt_http_clear_last_modified(r);
            njt_http_clear_etag(r);

        } else {
            njt_http_weak_etag(r);
        }
    }

    rc = njt_http_next_header_filter(r);

    if (rc == NJT_ERROR || rc > NJT_OK || r->header_only) {
        njt_free(b->pos);
        return rc;
    }

    cln->handler = njt_http_xslt_cleanup;
    cln->data = b->pos;

    out.buf = b;
    out.next = NULL;

    return njt_http_next_body_filter(r, &out);
}


static njt_int_t
njt_http_xslt_add_chunk(njt_http_request_t *r, njt_http_xslt_filter_ctx_t *ctx,
    njt_buf_t *b)
{
    int               err;
    xmlParserCtxtPtr  ctxt;

    if (ctx->ctxt == NULL) {

        ctxt = xmlCreatePushParserCtxt(NULL, NULL, NULL, 0, NULL);
        if (ctxt == NULL) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "xmlCreatePushParserCtxt() failed");
            return NJT_ERROR;
        }
        xmlCtxtUseOptions(ctxt, XML_PARSE_NOENT|XML_PARSE_DTDLOAD
                                               |XML_PARSE_NOWARNING);

        ctxt->sax->externalSubset = njt_http_xslt_sax_external_subset;
        ctxt->sax->setDocumentLocator = NULL;
        ctxt->sax->error = njt_http_xslt_sax_error;
        ctxt->sax->fatalError = njt_http_xslt_sax_error;
        ctxt->sax->_private = ctx;

        ctx->ctxt = ctxt;
        ctx->request = r;
    }

    err = xmlParseChunk(ctx->ctxt, (char *) b->pos, (int) (b->last - b->pos),
                        (b->last_buf) || (b->last_in_chain));

    if (err == 0) {
        b->pos = b->last;
        return NJT_OK;
    }

    njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                  "xmlParseChunk() failed, error:%d", err);

    return NJT_ERROR;
}


static void
njt_http_xslt_sax_external_subset(void *data, const xmlChar *name,
    const xmlChar *externalId, const xmlChar *systemId)
{
    xmlParserCtxtPtr ctxt = data;

    xmlDocPtr                         doc;
    xmlDtdPtr                         dtd;
    njt_http_request_t               *r;
    njt_http_xslt_filter_ctx_t       *ctx;
    njt_http_xslt_filter_loc_conf_t  *conf;

    ctx = ctxt->sax->_private;
    r = ctx->request;

    conf = njt_http_get_module_loc_conf(r, njt_http_xslt_filter_module);

    njt_log_debug3(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "xslt filter extSubset: \"%s\" \"%s\" \"%s\"",
                   name ? name : (xmlChar *) "",
                   externalId ? externalId : (xmlChar *) "",
                   systemId ? systemId : (xmlChar *) "");

    doc = ctxt->myDoc;

#if (NJT_HTTP_XSLT_REUSE_DTD)

    dtd = conf->dtd;

#else

    dtd = xmlCopyDtd(conf->dtd);
    if (dtd == NULL) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "xmlCopyDtd() failed");
        return;
    }

    if (doc->children == NULL) {
        xmlAddChild((xmlNodePtr) doc, (xmlNodePtr) dtd);

    } else {
        xmlAddPrevSibling(doc->children, (xmlNodePtr) dtd);
    }

#endif

    doc->extSubset = dtd;
}


static void njt_cdecl
njt_http_xslt_sax_error(void *data, const char *msg, ...)
{
    xmlParserCtxtPtr ctxt = data;

    size_t                       n;
    va_list                      args;
    njt_http_xslt_filter_ctx_t  *ctx;
    u_char                       buf[NJT_MAX_ERROR_STR];

    ctx = ctxt->sax->_private;

    buf[0] = '\0';

    va_start(args, msg);
    n = (size_t) vsnprintf((char *) buf, NJT_MAX_ERROR_STR, msg, args);
    va_end(args);

    while (--n && (buf[n] == CR || buf[n] == LF)) { /* void */ }

    njt_log_error(NJT_LOG_ERR, ctx->request->connection->log, 0,
                  "libxml2 error: \"%*s\"", n + 1, buf);
}


static njt_buf_t *
njt_http_xslt_apply_stylesheet(njt_http_request_t *r,
    njt_http_xslt_filter_ctx_t *ctx)
{
    int                               len, rc, doc_type;
    u_char                           *type, *encoding;
    njt_buf_t                        *b;
    njt_uint_t                        i;
    xmlChar                          *buf;
    xmlDocPtr                         doc, res;
    njt_http_xslt_sheet_t            *sheet;
    njt_http_xslt_filter_loc_conf_t  *conf;

    conf = njt_http_get_module_loc_conf(r, njt_http_xslt_filter_module);
    sheet = conf->sheets.elts;
    doc = ctx->doc;

    /* preallocate array for 4 params */

    if (njt_array_init(&ctx->params, r->pool, 4 * 2 + 1, sizeof(char *))
        != NJT_OK)
    {
        xmlFreeDoc(doc);
        return NULL;
    }

    for (i = 0; i < conf->sheets.nelts; i++) {

        ctx->transform = xsltNewTransformContext(sheet[i].stylesheet, doc);
        if (ctx->transform == NULL) {
            xmlFreeDoc(doc);
            return NULL;
        }

        if (conf->params
            && njt_http_xslt_params(r, ctx, conf->params, 0) != NJT_OK)
        {
            xsltFreeTransformContext(ctx->transform);
            xmlFreeDoc(doc);
            return NULL;
        }

        if (njt_http_xslt_params(r, ctx, &sheet[i].params, 1) != NJT_OK) {
            xsltFreeTransformContext(ctx->transform);
            xmlFreeDoc(doc);
            return NULL;
        }

        res = xsltApplyStylesheetUser(sheet[i].stylesheet, doc,
                                      ctx->params.elts, NULL, NULL,
                                      ctx->transform);

        xsltFreeTransformContext(ctx->transform);
        xmlFreeDoc(doc);

        if (res == NULL) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "xsltApplyStylesheet() failed");
            return NULL;
        }

        doc = res;

        /* reset array elements */
        ctx->params.nelts = 0;
    }

    /* there must be at least one stylesheet */

    if (r == r->main) {
        type = njt_http_xslt_content_type(sheet[i - 1].stylesheet);

    } else {
        type = NULL;
    }

    encoding = njt_http_xslt_encoding(sheet[i - 1].stylesheet);
    doc_type = doc->type;

    njt_log_debug3(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "xslt filter type: %d t:%s e:%s",
                   doc_type, type ? type : (u_char *) "(null)",
                   encoding ? encoding : (u_char *) "(null)");

    rc = xsltSaveResultToString(&buf, &len, doc, sheet[i - 1].stylesheet);

    xmlFreeDoc(doc);

    if (rc != 0) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "xsltSaveResultToString() failed");
        return NULL;
    }

    if (len == 0) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "xsltSaveResultToString() returned zero-length result");
        return NULL;
    }

    b = njt_calloc_buf(r->pool);
    if (b == NULL) {
        njt_free(buf);
        return NULL;
    }

    b->pos = buf;
    b->last = buf + len;
    b->memory = 1;

    if (encoding) {
        r->headers_out.charset.len = njt_strlen(encoding);
        r->headers_out.charset.data = encoding;
    }

    if (r != r->main) {
        return b;
    }

    b->last_buf = 1;

    if (type) {
        len = njt_strlen(type);

        r->headers_out.content_type_len = len;
        r->headers_out.content_type.len = len;
        r->headers_out.content_type.data = type;

    } else if (doc_type == XML_HTML_DOCUMENT_NODE) {

        r->headers_out.content_type_len = sizeof("text/html") - 1;
        njt_str_set(&r->headers_out.content_type, "text/html");
    }

    r->headers_out.content_type_lowcase = NULL;

    return b;
}


static njt_int_t
njt_http_xslt_params(njt_http_request_t *r, njt_http_xslt_filter_ctx_t *ctx,
    njt_array_t *params, njt_uint_t final)
{
    u_char                 *p, *value, *dst, *src, **s;
    size_t                  len;
    njt_uint_t              i;
    njt_str_t               string;
    njt_http_xslt_param_t  *param;

    param = params->elts;

    for (i = 0; i < params->nelts; i++) {

        if (njt_http_complex_value(r, &param[i].value, &string) != NJT_OK) {
            return NJT_ERROR;
        }

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "xslt filter param: \"%s\"", string.data);

        if (param[i].name) {

            njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "xslt filter param name: \"%s\"", param[i].name);

            if (param[i].quote) {
                if (xsltQuoteOneUserParam(ctx->transform, param[i].name,
                                          string.data)
                    != 0)
                {
                    njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                                "xsltQuoteOneUserParam(\"%s\", \"%s\") failed",
                                param[i].name, string.data);
                    return NJT_ERROR;
                }

                continue;
            }

            s = njt_array_push(&ctx->params);
            if (s == NULL) {
                return NJT_ERROR;
            }

            *s = param[i].name;

            s = njt_array_push(&ctx->params);
            if (s == NULL) {
                return NJT_ERROR;
            }

            *s = string.data;

            continue;
        }

        /*
         * parse param1=value1:param2=value2 syntax as used by parameters
         * specified in xslt_stylesheet directives
         */

        if (param[i].value.lengths) {
            p = string.data;

        } else {
            p = njt_pnalloc(r->pool, string.len + 1);
            if (p == NULL) {
                return NJT_ERROR;
            }

            njt_memcpy(p, string.data, string.len + 1);
        }

        while (p && *p) {

            value = p;
            p = (u_char *) njt_strchr(p, '=');
            if (p == NULL) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                                "invalid libxslt parameter \"%s\"", value);
                return NJT_ERROR;
            }
            *p++ = '\0';

            njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "xslt filter param name: \"%s\"", value);

            s = njt_array_push(&ctx->params);
            if (s == NULL) {
                return NJT_ERROR;
            }

            *s = value;

            value = p;
            p = (u_char *) njt_strchr(p, ':');

            if (p) {
                len = p - value;
                *p++ = '\0';

            } else {
                len = njt_strlen(value);
            }

            njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "xslt filter param value: \"%s\"", value);

            dst = value;
            src = value;

            njt_unescape_uri(&dst, &src, len, 0);

            *dst = '\0';

            njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "xslt filter param unescaped: \"%s\"", value);

            s = njt_array_push(&ctx->params);
            if (s == NULL) {
                return NJT_ERROR;
            }

            *s = value;
        }
    }

    if (final) {
        s = njt_array_push(&ctx->params);
        if (s == NULL) {
            return NJT_ERROR;
        }

        *s = NULL;
    }

    return NJT_OK;
}


static u_char *
njt_http_xslt_content_type(xsltStylesheetPtr s)
{
    u_char  *type;

    if (s->mediaType) {
        return s->mediaType;
    }

    for (s = s->imports; s; s = s->next) {

        type = njt_http_xslt_content_type(s);

        if (type) {
            return type;
        }
    }

    return NULL;
}


static u_char *
njt_http_xslt_encoding(xsltStylesheetPtr s)
{
    u_char  *encoding;

    if (s->encoding) {
        return s->encoding;
    }

    for (s = s->imports; s; s = s->next) {

        encoding = njt_http_xslt_encoding(s);

        if (encoding) {
            return encoding;
        }
    }

    return NULL;
}


static void
njt_http_xslt_cleanup(void *data)
{
    njt_free(data);
}


static char *
njt_http_xslt_entities(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_xslt_filter_loc_conf_t *xlcf = conf;

    njt_str_t                         *value;
    njt_uint_t                         i;
    njt_pool_cleanup_t                *cln;
    njt_http_xslt_file_t              *file;
    njt_http_xslt_filter_main_conf_t  *xmcf;

    if (xlcf->dtd) {
        return "is duplicate";
    }

    value = cf->args->elts;

    xmcf = njt_http_conf_get_module_main_conf(cf, njt_http_xslt_filter_module);

    file = xmcf->dtd_files.elts;
    for (i = 0; i < xmcf->dtd_files.nelts; i++) {
        if (njt_strcmp(file[i].name, value[1].data) == 0) {
            xlcf->dtd = file[i].data;
            return NJT_CONF_OK;
        }
    }

    cln = njt_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NJT_CONF_ERROR;
    }

    xlcf->dtd = xmlParseDTD(NULL, (xmlChar *) value[1].data);

    if (xlcf->dtd == NULL) {
        njt_conf_log_error(NJT_LOG_ERR, cf, 0, "xmlParseDTD() failed");
        return NJT_CONF_ERROR;
    }

    cln->handler = njt_http_xslt_cleanup_dtd;
    cln->data = xlcf->dtd;

    file = njt_array_push(&xmcf->dtd_files);
    if (file == NULL) {
        return NJT_CONF_ERROR;
    }

    file->name = value[1].data;
    file->data = xlcf->dtd;

    return NJT_CONF_OK;
}



static char *
njt_http_xslt_stylesheet(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_xslt_filter_loc_conf_t *xlcf = conf;

    njt_str_t                         *value;
    njt_uint_t                         i, n;
    njt_pool_cleanup_t                *cln;
    njt_http_xslt_file_t              *file;
    njt_http_xslt_sheet_t             *sheet;
    njt_http_xslt_param_t             *param;
    njt_http_compile_complex_value_t   ccv;
    njt_http_xslt_filter_main_conf_t  *xmcf;

    value = cf->args->elts;

    if (xlcf->sheets.elts == NULL) {
        if (njt_array_init(&xlcf->sheets, cf->pool, 1,
                           sizeof(njt_http_xslt_sheet_t))
            != NJT_OK)
        {
            return NJT_CONF_ERROR;
        }
    }

    sheet = njt_array_push(&xlcf->sheets);
    if (sheet == NULL) {
        return NJT_CONF_ERROR;
    }

    njt_memzero(sheet, sizeof(njt_http_xslt_sheet_t));

    if (njt_conf_full_name(cf->cycle, &value[1], 0) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    xmcf = njt_http_conf_get_module_main_conf(cf, njt_http_xslt_filter_module);

    file = xmcf->sheet_files.elts;
    for (i = 0; i < xmcf->sheet_files.nelts; i++) {
        if (njt_strcmp(file[i].name, value[1].data) == 0) {
            sheet->stylesheet = file[i].data;
            goto found;
        }
    }

    cln = njt_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NJT_CONF_ERROR;
    }

    sheet->stylesheet = xsltParseStylesheetFile(value[1].data);
    if (sheet->stylesheet == NULL) {
        njt_conf_log_error(NJT_LOG_ERR, cf, 0,
                           "xsltParseStylesheetFile(\"%s\") failed",
                           value[1].data);
        return NJT_CONF_ERROR;
    }

    cln->handler = njt_http_xslt_cleanup_stylesheet;
    cln->data = sheet->stylesheet;

    file = njt_array_push(&xmcf->sheet_files);
    if (file == NULL) {
        return NJT_CONF_ERROR;
    }

    file->name = value[1].data;
    file->data = sheet->stylesheet;

found:

    n = cf->args->nelts;

    if (n == 2) {
        return NJT_CONF_OK;
    }

    if (njt_array_init(&sheet->params, cf->pool, n - 2,
                       sizeof(njt_http_xslt_param_t))
        != NJT_OK)
    {
        return NJT_CONF_ERROR;
    }

    for (i = 2; i < n; i++) {

        param = njt_array_push(&sheet->params);
        if (param == NULL) {
            return NJT_CONF_ERROR;
        }

        njt_memzero(param, sizeof(njt_http_xslt_param_t));
        njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[i];
        ccv.complex_value = &param->value;
        ccv.zero = 1;

        if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
            return NJT_CONF_ERROR;
        }
    }

    return NJT_CONF_OK;
}


static char *
njt_http_xslt_param(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_xslt_filter_loc_conf_t  *xlcf = conf;

    njt_http_xslt_param_t            *param;
    njt_http_compile_complex_value_t  ccv;
    njt_str_t                        *value;

    value = cf->args->elts;

    if (xlcf->params == NULL) {
        xlcf->params = njt_array_create(cf->pool, 2,
                                        sizeof(njt_http_xslt_param_t));
        if (xlcf->params == NULL) {
            return NJT_CONF_ERROR;
        }
    }

    param = njt_array_push(xlcf->params);
    if (param == NULL) {
        return NJT_CONF_ERROR;
    }

    param->name = value[1].data;
    param->quote = (cmd->post == NULL) ? 0 : 1;

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &param->value;
    ccv.zero = 1;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


static void
njt_http_xslt_cleanup_dtd(void *data)
{
    xmlFreeDtd(data);
}


static void
njt_http_xslt_cleanup_stylesheet(void *data)
{
    xsltFreeStylesheet(data);
}


static void *
njt_http_xslt_filter_create_main_conf(njt_conf_t *cf)
{
    njt_http_xslt_filter_main_conf_t  *conf;

    conf = njt_palloc(cf->pool, sizeof(njt_http_xslt_filter_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    if (njt_array_init(&conf->dtd_files, cf->pool, 1,
                       sizeof(njt_http_xslt_file_t))
        != NJT_OK)
    {
        return NULL;
    }

    if (njt_array_init(&conf->sheet_files, cf->pool, 1,
                       sizeof(njt_http_xslt_file_t))
        != NJT_OK)
    {
        return NULL;
    }

    return conf;
}


static void *
njt_http_xslt_filter_create_conf(njt_conf_t *cf)
{
    njt_http_xslt_filter_loc_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_xslt_filter_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     conf->dtd = NULL;
     *     conf->sheets = { NULL };
     *     conf->types = { NULL };
     *     conf->types_keys = NULL;
     *     conf->params = NULL;
     */

    conf->last_modified = NJT_CONF_UNSET;

    return conf;
}


static char *
njt_http_xslt_filter_merge_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_xslt_filter_loc_conf_t *prev = parent;
    njt_http_xslt_filter_loc_conf_t *conf = child;

    if (conf->dtd == NULL) {
        conf->dtd = prev->dtd;
    }

    if (conf->sheets.nelts == 0) {
        conf->sheets = prev->sheets;
    }

    if (conf->params == NULL) {
        conf->params = prev->params;
    }

    if (njt_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             njt_http_xslt_default_types)
        != NJT_OK)
    {
        return NJT_CONF_ERROR;
    }

    njt_conf_merge_value(conf->last_modified, prev->last_modified, 0);

    return NJT_CONF_OK;
}


static njt_int_t
njt_http_xslt_filter_preconfiguration(njt_conf_t *cf)
{
    xmlInitParser();

#if (NJT_HAVE_EXSLT)
    exsltRegisterAll();
#endif

    return NJT_OK;
}


static njt_int_t
njt_http_xslt_filter_init(njt_conf_t *cf)
{
    njt_http_next_header_filter = njt_http_top_header_filter;
    njt_http_top_header_filter = njt_http_xslt_header_filter;

    njt_http_next_body_filter = njt_http_top_body_filter;
    njt_http_top_body_filter = njt_http_xslt_body_filter;

    return NJT_OK;
}


static void
njt_http_xslt_filter_exit(njt_cycle_t *cycle)
{
    xsltCleanupGlobals();
    xmlCleanupParser();
}
