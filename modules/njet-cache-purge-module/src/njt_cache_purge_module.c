/*
 * Copyright (c) 2009-2014, FRiCKLE <info@frickle.com>
 * Copyright (c) 2009-2014, Piotr Sikora <piotr.sikora@frickle.com>
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 * All rights reserved.
 *
 * This project was fully funded by yo.se.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <njt_config.h>
#include <njet.h>
#include <njt_core.h>
#include <njt_http.h>
#include "njt_cache_purge.h"


#define NJT_REPONSE_TYPE_HTML 1
#define NJT_REPONSE_TYPE_XML  2
#define NJT_REPONSE_TYPE_JSON 3
#define NJT_REPONSE_TYPE_TEXT 4
#define NJT_REPONSE_TYPE_PLUS 5

static const char njt_http_cache_purge_content_type_json[] ="application/json";
static const char njt_http_cache_purge_content_type_html[] = "text/html";
static const char njt_http_cache_purge_content_type_xml[]  = "text/xml";
static const char njt_http_cache_purge_content_type_text[] = "text/plain";

static size_t njt_http_cache_purge_content_type_json_size = sizeof(
            njt_http_cache_purge_content_type_json);
static size_t njt_http_cache_purge_content_type_html_size = sizeof(
            njt_http_cache_purge_content_type_html);
static size_t njt_http_cache_purge_content_type_xml_size = sizeof(
            njt_http_cache_purge_content_type_xml);
static size_t njt_http_cache_purge_content_type_text_size = sizeof(
            njt_http_cache_purge_content_type_text);

static const char njt_http_cache_purge_body_templ_json[] =
    "{\"Key\": \"%s\"}\n";
static const char njt_http_cache_purge_body_templ_html[] =
    "<html><head><title>Successful purge</title></head><body bgcolor=\"white\"><center><h1>Successful purge</h1><p>Key : %s</p></center></body></html>\n";
static const char njt_http_cache_purge_body_templ_xml[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><status><Key><![CDATA[%s]]></Key></status>\n";
static const char njt_http_cache_purge_body_templ_text[] = "Key:%s\n";

static size_t njt_http_cache_purge_body_templ_json_size = sizeof(
            njt_http_cache_purge_body_templ_json);
static size_t njt_http_cache_purge_body_templ_html_size = sizeof(
            njt_http_cache_purge_body_templ_html);
static size_t njt_http_cache_purge_body_templ_xml_size = sizeof(
            njt_http_cache_purge_body_templ_xml);
static size_t njt_http_cache_purge_body_templ_text_size = sizeof(
            njt_http_cache_purge_body_templ_text);

#if (NJT_HTTP_CACHE)

typedef struct {
    njt_array_t                  *conditions;
} njt_http_cache_purge_conf_t;

typedef struct {
    njt_http_cache_purge_conf_t  conf;
    njt_uint_t                    resptype; /* response content-type */
    unsigned                      enable:1;
} njt_http_cache_purge_loc_conf_t;

# if (NJT_HTTP_FASTCGI)
char       *njt_http_fastcgi_cache_purge_conf(njt_conf_t *cf,
        njt_command_t *cmd, void *conf);
# endif /* NJT_HTTP_FASTCGI */

# if (NJT_HTTP_PROXY)
char       *njt_http_proxy_cache_purge_conf(njt_conf_t *cf,
        njt_command_t *cmd, void *conf);
# endif /* NJT_HTTP_PROXY */

# if (NJT_HTTP_SCGI)
char       *njt_http_scgi_cache_purge_conf(njt_conf_t *cf,
        njt_command_t *cmd, void *conf);
# endif /* NJT_HTTP_SCGI */

# if (NJT_HTTP_UWSGI)
char       *njt_http_uwsgi_cache_purge_conf(njt_conf_t *cf,
        njt_command_t *cmd, void *conf);
# endif /* NJT_HTTP_UWSGI */

char        *njt_http_cache_purge_response_type_conf(njt_conf_t *cf,
        njt_command_t *cmd, void *conf);

njt_int_t   njt_http_cache_purge_send_response(njt_http_request_t *r);
void        njt_http_cache_purge_handler(njt_http_request_t *r);
njt_int_t   njt_http_cache_is_purge_all(njt_http_request_t *r);
njt_int_t   njt_http_cache_is_reset_all(njt_http_request_t *r);

njt_int_t njt_http_file_cache_purge_all_files(njt_http_request_t *r);
njt_int_t njt_http_file_cache_reset_all_files(njt_http_request_t *r);

char       *njt_http_cache_purge_conf(njt_conf_t *cf,
                                      njt_http_cache_purge_conf_t *cpcf);
void       *njt_http_cache_purge_create_loc_conf(njt_conf_t *cf);
char       *njt_http_cache_purge_merge_loc_conf(njt_conf_t *cf,
        void *parent, void *child);

static njt_command_t  njt_http_cache_purge_module_commands[] = {

# if (NJT_HTTP_FASTCGI)
    {
        njt_string("fastcgi_cache_purge"),
        NJT_HTTP_MAIN_CONF | NJT_HTTP_SRV_CONF | NJT_HTTP_LOC_CONF | NJT_CONF_1MORE,
        njt_http_fastcgi_cache_purge_conf,
        NJT_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
# endif /* NJT_HTTP_FASTCGI */

# if (NJT_HTTP_PROXY)
    {
        njt_string("proxy_cache_purge"),
        NJT_HTTP_MAIN_CONF | NJT_HTTP_SRV_CONF | NJT_HTTP_LOC_CONF | NJT_CONF_1MORE,
        njt_http_proxy_cache_purge_conf,
        NJT_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
# endif /* NJT_HTTP_PROXY */

# if (NJT_HTTP_SCGI)
    {
        njt_string("scgi_cache_purge"),
        NJT_HTTP_MAIN_CONF | NJT_HTTP_SRV_CONF | NJT_HTTP_LOC_CONF | NJT_CONF_1MORE,
        njt_http_scgi_cache_purge_conf,
        NJT_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
# endif /* NJT_HTTP_SCGI */

# if (NJT_HTTP_UWSGI)
    {
        njt_string("uwsgi_cache_purge"),
        NJT_HTTP_MAIN_CONF | NJT_HTTP_SRV_CONF | NJT_HTTP_LOC_CONF | NJT_CONF_1MORE,
        njt_http_uwsgi_cache_purge_conf,
        NJT_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
# endif /* NJT_HTTP_UWSGI */


    {
        njt_string("cache_purge_response_type"),
        NJT_HTTP_MAIN_CONF | NJT_HTTP_SRV_CONF | NJT_HTTP_LOC_CONF | NJT_CONF_TAKE1,
        njt_http_cache_purge_response_type_conf,
        NJT_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },

    njt_null_command
};

static njt_http_module_t  njt_http_cache_purge_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_cache_purge_create_loc_conf,  /* create location configuration */
    njt_http_cache_purge_merge_loc_conf    /* merge location configuration */
};

njt_module_t  njt_http_cache_purge_module = {
    NJT_MODULE_V1,
    &njt_http_cache_purge_module_ctx,      /* module context */
    njt_http_cache_purge_module_commands,  /* module directives */
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

# if (NJT_HTTP_FASTCGI)
extern njt_module_t  njt_http_fastcgi_module;

typedef struct {
    njt_array_t                    caches;  /* njt_http_file_cache_t * */
} njt_http_fastcgi_main_conf_t;


typedef struct {
    njt_array_t                   *flushes;
    njt_array_t                   *lengths;
    njt_array_t                   *values;
    njt_uint_t                     number;
    njt_hash_t                     hash;
} njt_http_fastcgi_params_t;


typedef struct {
    njt_http_upstream_conf_t       upstream;

    njt_str_t                      index;

    njt_http_fastcgi_params_t      params;
    njt_http_fastcgi_params_t      params_cache;

    njt_array_t                   *params_source;
    njt_array_t                   *catch_stderr;

    njt_array_t                   *fastcgi_lengths;
    njt_array_t                   *fastcgi_values;

    njt_flag_t                     keep_conn;

    njt_http_complex_value_t       cache_key;

#  if (NJT_PCRE)
    njt_regex_t                   *split_regex;
    njt_str_t                      split_name;
#  endif /* NJT_PCRE */
} njt_http_fastcgi_loc_conf_t;

char *
njt_http_fastcgi_cache_purge_conf(njt_conf_t *cf, njt_command_t *cmd,void *conf)
{
    njt_http_cache_purge_loc_conf_t   *cplcf;

    cplcf = njt_http_conf_get_module_loc_conf(cf, njt_http_cache_purge_module);
    cplcf->enable = 1;
    return njt_http_cache_purge_conf(cf, &cplcf->conf);
}

# endif /* NJT_HTTP_FASTCGI */

# if (NJT_HTTP_PROXY)
extern njt_module_t  njt_http_proxy_module;

//typedef struct {
//    njt_str_t                      key_start;
//    njt_str_t                      schema;
//    njt_str_t                      host_header;
//    njt_str_t                      port;
//    njt_str_t                      uri;
//} njt_http_proxy_vars_t;

typedef struct {
    njt_array_t                    caches;  /* njt_http_file_cache_t * */
} njt_http_proxy_main_conf_t;



typedef struct {
    njt_array_t                   *flushes;
    njt_array_t                   *lengths;
    njt_array_t                   *values;
    njt_hash_t                     hash;
} njt_http_proxy_headers_t;


char *
njt_http_proxy_cache_purge_conf(njt_conf_t *cf, njt_command_t *cmd,void *conf)
{
    njt_http_cache_purge_loc_conf_t   *cplcf;

    cplcf = njt_http_conf_get_module_loc_conf(cf, njt_http_cache_purge_module);
    cplcf->enable = 1;
    return njt_http_cache_purge_conf(cf, &cplcf->conf);
}


# endif /* NJT_HTTP_PROXY */

# if (NJT_HTTP_SCGI)
extern njt_module_t  njt_http_scgi_module;


typedef struct {
    njt_array_t                caches;  /* njt_http_file_cache_t * */
} njt_http_scgi_main_conf_t;


typedef struct {
    njt_array_t               *flushes;
    njt_array_t               *lengths;
    njt_array_t               *values;
    njt_uint_t                 number;
    njt_hash_t                 hash;
} njt_http_scgi_params_t;


typedef struct {
    njt_http_upstream_conf_t   upstream;

    njt_http_scgi_params_t     params;
    njt_http_scgi_params_t     params_cache;
    njt_array_t               *params_source;

    njt_array_t               *scgi_lengths;
    njt_array_t               *scgi_values;

    njt_http_complex_value_t   cache_key;
} njt_http_scgi_loc_conf_t;

char *
njt_http_scgi_cache_purge_conf(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_cache_purge_loc_conf_t   *cplcf;

    cplcf = njt_http_conf_get_module_loc_conf(cf, njt_http_cache_purge_module);
    cplcf->enable = 1;
    return njt_http_cache_purge_conf(cf, &cplcf->conf);
}

# endif /* NJT_HTTP_SCGI */

# if (NJT_HTTP_UWSGI)
extern njt_module_t  njt_http_uwsgi_module;

typedef struct {
    njt_array_t                caches;  /* njt_http_file_cache_t * */
} njt_http_uwsgi_main_conf_t;


typedef struct {
    njt_array_t               *flushes;
    njt_array_t               *lengths;
    njt_array_t               *values;
    njt_uint_t                 number;
    njt_hash_t                 hash;
} njt_http_uwsgi_params_t;

typedef struct {
    njt_http_upstream_conf_t   upstream;

    njt_http_uwsgi_params_t    params;
    njt_http_uwsgi_params_t    params_cache;
    njt_array_t               *params_source;

    njt_array_t               *uwsgi_lengths;
    njt_array_t               *uwsgi_values;

    njt_http_complex_value_t   cache_key;

    njt_str_t                  uwsgi_string;

    njt_uint_t                 modifier1;
    njt_uint_t                 modifier2;

#  if (NJT_HTTP_SSL)
    njt_uint_t                 ssl;
    njt_uint_t                 ssl_protocols;
    njt_str_t                  ssl_ciphers;
    njt_uint_t                 ssl_verify_depth;
    njt_str_t                  ssl_trusted_certificate;
    njt_str_t                  ssl_crl;
    njt_str_t                  ssl_certificate;
    njt_str_t                  ssl_certificate_key;
    njt_array_t               *ssl_passwords;
#  endif
} njt_http_uwsgi_loc_conf_t;

char *
njt_http_uwsgi_cache_purge_conf(njt_conf_t *cf, njt_command_t *cmd,void *conf)
{
    njt_http_cache_purge_loc_conf_t   *cplcf;


    cplcf = njt_http_conf_get_module_loc_conf(cf, njt_http_cache_purge_module);

    cplcf->enable=1;
    return njt_http_cache_purge_conf(cf, &cplcf->conf);
}

# endif /* NJT_HTTP_UWSGI */


char *
njt_http_cache_purge_response_type_conf(njt_conf_t *cf, njt_command_t *cmd,
                                        void *conf)
{
    njt_http_cache_purge_loc_conf_t   *cplcf;
    njt_str_t                         *value;

    cplcf = njt_http_conf_get_module_loc_conf(cf, njt_http_cache_purge_module);

    /* check for duplicates / collisions */
    if (cplcf->resptype != NJT_CONF_UNSET_UINT &&
        cf->cmd_type == NJT_HTTP_LOC_CONF)  {
        return "is duplicate";
    }

    /* sanity check */
    if (cf->args->nelts < 2) {
        return "is invalid paramter, ex) cache_purge_response_type (html|json|xml|text)";
    }

    if (cf->args->nelts > 2) {
        return "is required only 1 option, ex) cache_purge_response_type (html|json|xml|text)";
    }

    value = cf->args->elts;

    if (njt_strcmp(value[1].data, "html") != 0 &&
        njt_strcmp(value[1].data, "json") != 0
        && njt_strcmp(value[1].data, "xml") != 0 &&
        njt_strcmp(value[1].data, "text") != 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\", expected"
                           " \"(html|json|xml|text)\" keyword", &value[1]);
        return NJT_CONF_ERROR;
    }

    if (cf->cmd_type == NJT_HTTP_MODULE) {
        return "(separate server or location syntax) is not allowed here";
    }

    if (njt_strcmp(value[1].data, "html") == 0) {
        cplcf->resptype = NJT_REPONSE_TYPE_HTML;
    } else if (njt_strcmp(value[1].data, "xml") == 0) {
        cplcf->resptype = NJT_REPONSE_TYPE_XML;
    } else if (njt_strcmp(value[1].data, "json") == 0) {
        cplcf->resptype = NJT_REPONSE_TYPE_JSON;
    } else if (njt_strcmp(value[1].data, "text") == 0) {
        cplcf->resptype = NJT_REPONSE_TYPE_TEXT;
    }

    return NJT_CONF_OK;
}

njt_int_t
njt_http_cache_purge_send_response(njt_http_request_t *r)
{
    njt_chain_t   out;
    njt_buf_t    *b = NULL;
    njt_str_t    *key = NULL;
    njt_int_t     rc = NJT_OK ;
    size_t        len = 0;
    size_t body_len,resp_tmpl_len,resp_ct_size,resp_body_size;
    u_char *buf,*buf_keydata, *p;
    const char *resp_ct,*resp_body;
    njt_http_cache_purge_loc_conf_t   *cplcf;
    buf = buf_keydata = p = NULL;
    resp_ct = resp_body = NULL;
    cplcf = NULL;
    body_len = resp_tmpl_len = resp_ct_size = resp_body_size = 0 ;


    cplcf = njt_http_get_module_loc_conf(r, njt_http_cache_purge_module);

    key = r->cache->keys.elts;

    buf_keydata = njt_pcalloc(r->pool, key[0].len + 1);
    if (buf_keydata == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = njt_cpymem(buf_keydata, key[0].data, key[0].len);
    if (p == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    switch (cplcf->resptype) {

    case NJT_REPONSE_TYPE_JSON:
        resp_ct = njt_http_cache_purge_content_type_json;
        resp_ct_size = njt_http_cache_purge_content_type_json_size;
        resp_body = njt_http_cache_purge_body_templ_json;
        resp_body_size = njt_http_cache_purge_body_templ_json_size;
        break;

    case NJT_REPONSE_TYPE_XML:
        resp_ct = njt_http_cache_purge_content_type_xml;
        resp_ct_size = njt_http_cache_purge_content_type_xml_size;
        resp_body = njt_http_cache_purge_body_templ_xml;
        resp_body_size = njt_http_cache_purge_body_templ_xml_size;
        break;

    case NJT_REPONSE_TYPE_TEXT:
        resp_ct = njt_http_cache_purge_content_type_text;
        resp_ct_size = njt_http_cache_purge_content_type_text_size;
        resp_body = njt_http_cache_purge_body_templ_text;
        resp_body_size = njt_http_cache_purge_body_templ_text_size;
        break;

    case NJT_REPONSE_TYPE_HTML:
        resp_ct = njt_http_cache_purge_content_type_html;
        resp_ct_size = njt_http_cache_purge_content_type_html_size;
        resp_body = njt_http_cache_purge_body_templ_html;
        resp_body_size = njt_http_cache_purge_body_templ_html_size;
        break;

    default:
    case NJT_REPONSE_TYPE_PLUS:
        resp_ct = NULL;
        resp_ct_size = 0;
        resp_body = NULL;
        resp_body_size = 0;
        break;
    }

    if(resp_ct_size != 0 ) {
        r->headers_out.content_type.len = resp_ct_size - 1;
        r->headers_out.content_type.data = (u_char *) resp_ct;
    }

    if(resp_body_size == 0) {
        r->headers_out.status = NJT_HTTP_NO_CONTENT;
        r->headers_out.content_length_n = 0;
    }else {
        body_len = resp_body_size - 2 - 1;
        resp_tmpl_len = body_len + key[0].len ;
        buf = njt_pcalloc(r->pool, resp_tmpl_len);
        if (buf == NULL) {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        p = njt_snprintf(buf, resp_tmpl_len, resp_body, buf_keydata);
        if (p == NULL) {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        len = body_len + key[0].len;

        r->headers_out.status = NJT_HTTP_OK;
        r->headers_out.content_length_n = len;
    }


    if (r->method == NJT_HTTP_HEAD) {
        rc = njt_http_send_header(r);
        if (rc == NJT_ERROR || rc > NJT_OK || r->header_only) {
            return rc;
        }
    }


    rc = njt_http_send_header(r);
    if (rc == NJT_ERROR || rc > NJT_OK || r->header_only) {
        return rc;
    }

    if(resp_body_size != 0) {
        b = njt_create_temp_buf(r->pool, len);
        if (b == NULL) {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        out.buf = b;
        out.next = NULL;

        b->last = njt_cpymem(b->last, buf, resp_tmpl_len);
        b->last_buf = 1;
    }
    return njt_http_output_filter(r, &out);
}


void
njt_http_cache_purge_handler(njt_http_request_t *r)
{
    njt_int_t  rc;

#  if (NJT_HAVE_FILE_AIO)
    if (r->aio) {
        return;
    }
#  endif

    rc = NJT_OK;
    if (njt_http_cache_is_reset_all(r)) {
        rc = njt_http_file_cache_reset_all_files(r);

        njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http file cache reset all files.");
    }else if (njt_http_cache_is_purge_all(r)) {
        rc = njt_http_file_cache_purge_all_files(r);

        njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http file cache purge all files.");

    }   else {

        rc = njt_http_file_cache_purge_one_file(r);
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http file cache purge one file.");
    }

    switch (rc) {
    case NJT_OK:
        r->write_event_handler = njt_http_request_empty_handler;
        njt_http_finalize_request(r, njt_http_cache_purge_send_response(r));
        return;
    case NJT_DECLINED:
        njt_http_finalize_request(r, NJT_HTTP_PRECONDITION_FAILED);
        return;
    default:
        njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
    }
}

/*TODO redefine the condition of purge all*/
njt_int_t
njt_http_cache_is_reset_all(njt_http_request_t *r)
{

    /* check if the uri equals /\* or not */
    njt_http_core_loc_conf_t  *clcf;
    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);
    njt_log_error(NJT_LOG_DEBUG, r->connection->log, 0,
                   "location name is %V.", &clcf->name);

    if (r->uri.len >= 3 && r->uri.data[r->uri.len - 1] == '*'
        && r->uri.data[r->uri.len - 2] == '*'
        && r->uri.data[r->uri.len - 3] == '/') {

        return 1;
    }

    return 0;
}

njt_int_t
njt_http_cache_is_purge_all(njt_http_request_t *r)
{

    /* check if the uri equals /\* or not */
    njt_http_core_loc_conf_t  *clcf;
    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);
    njt_log_error(NJT_LOG_DEBUG, r->connection->log, 0,
                   "location name is %V.", &clcf->name);
    if (r->uri.len >= 2 && r->uri.data[r->uri.len - 1] == '*'
    //处理分片删除的问题
//        && r->uri.data[r->uri.len - 2] == '/'
        ) {
        return 1;
    }

    return 0;
}

char *
njt_http_cache_purge_conf(njt_conf_t *cf, njt_http_cache_purge_conf_t *cpcf)
{

    njt_str_t                          *value;
    njt_uint_t                          i;
    njt_http_complex_value_t           *cv;
    njt_http_compile_complex_value_t    ccv;

    if (cpcf == NULL) {
        return NJT_CONF_ERROR;
    }

    if (cpcf->conditions == NJT_CONF_UNSET_PTR) {
        cpcf->conditions = njt_array_create(cf->pool, cf->args->nelts - 1,
                                            sizeof(njt_http_complex_value_t));
        if (cpcf->conditions == NULL) {
            return NJT_CONF_ERROR;
        }
    }

    /* xxx_cache_purge string < ...> */
    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++) {
        cv = njt_array_push(cpcf->conditions);
        if (cv == NULL) {
            return NJT_CONF_ERROR;
        }

        njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[i];
        ccv.complex_value = cv;

        if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
            return NJT_CONF_ERROR;
        }
    }

    return NJT_CONF_OK;
}


njt_int_t
njt_http_file_cache_reset_all_files(njt_http_request_t *r)
{
    njt_http_proxy_main_conf_t          *pmcf;
    njt_uint_t                          i;
    njt_http_file_cache_t               **caches;

    pmcf = njt_http_get_module_main_conf(r, njt_http_proxy_module);
    caches = pmcf->caches.elts;

    for (i = 0; i < pmcf->caches.nelts; i ++) {
        njt_http_file_cache_purge_one_cache_files(caches[i]);
    }

    return NJT_OK;
}

njt_int_t
njt_http_file_cache_purge_all_files(njt_http_request_t *r)
{
    njt_int_t rc;

    rc = NJT_OK;

    rc = njt_http_file_cache_purge_one_path(r);

//    njt_http_cache_t            *c;
//    njt_http_file_cache_t       *cache;
//    c = r->cache;
//
//    cache = c->file_cache;
//    rc = njt_http_file_cache_purge_one_cache_files(cache);

    return rc;

}


void *
njt_http_cache_purge_create_loc_conf(njt_conf_t *cf)
{
    njt_http_cache_purge_loc_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_cache_purge_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->resptype = NJT_CONF_UNSET_UINT;
    conf->conf.conditions  = NJT_CONF_UNSET_PTR;
    conf->enable = 0;

    return conf;
}

char *
njt_http_cache_purge_merge_loc_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_cache_purge_loc_conf_t  *prev = parent;
    njt_http_cache_purge_loc_conf_t  *conf = child;


    njt_conf_merge_uint_value(conf->resptype, prev->resptype,
                              NJT_REPONSE_TYPE_PLUS);

    if(prev->enable){
        conf->enable = 1;
    }
    njt_conf_merge_ptr_value(conf->conf.conditions,prev->conf.conditions,NULL);

    return NJT_CONF_OK;
}

#else /* !NJT_HTTP_CACHE */

static njt_http_module_t  njt_http_cache_purge_module_ctx = {
    NULL,  /* preconfiguration */
    NULL,  /* postconfiguration */

    NULL,  /* create main configuration */
    NULL,  /* init main configuration */

    NULL,  /* create server configuration */
    NULL,  /* merge server configuration */

    NULL,  /* create location configuration */
    NULL,  /* merge location configuration */
};

njt_module_t  njt_http_cache_purge_module = {
    NJT_MODULE_V1,
    &njt_http_cache_purge_module_ctx,  /* module context */
    NULL,                              /* module directives */
    NJT_HTTP_MODULE,                   /* module type */
    NULL,                              /* init master */
    NULL,                              /* init module */
    NULL,                              /* init process */
    NULL,                              /* init thread */
    NULL,                              /* exit thread */
    NULL,                              /* exit process */
    NULL,                              /* exit master */
    NJT_MODULE_V1_PADDING
};

#endif /* NJT_HTTP_CACHE */

njt_int_t njt_http_cache_purge_filter(njt_http_request_t *r){
    njt_http_cache_purge_loc_conf_t     *cplcf;
    njt_uint_t                           i;
    njt_http_complex_value_t            *cv;
    njt_str_t                           val;


    cplcf = njt_http_get_module_loc_conf(r, njt_http_cache_purge_module);
    if (cplcf == NULL) {
        njt_log_debug(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,"purge locaiton is NULL.");
        return NJT_HTTP_NOT_FOUND;
    }
    if (!cplcf->enable) {
        return NJT_OK;
    }

    if(cplcf->conf.conditions == NULL){
        return NJT_OK;
    }
    cv = cplcf->conf.conditions->elts;
    for (i = 0; i < cplcf->conf.conditions->nelts; i++) {
        if (njt_http_complex_value(r, &cv[i], &val) != NJT_OK) {

            return NJT_OK;
        }
        if (val.len != 1 ||  val.data[0] != '1') {
            njt_log_debug(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,"purge condition isn't met.");
            return NJT_OK;
        }
    }
    r->main->count++;
    njt_http_cache_purge_handler(r);

    return NJT_DONE;
}

