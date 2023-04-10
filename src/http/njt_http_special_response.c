
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njet.h>


static njt_int_t njt_http_send_error_page(njt_http_request_t *r,
    njt_http_err_page_t *err_page);
static njt_int_t njt_http_send_special_response(njt_http_request_t *r,
    njt_http_core_loc_conf_t *clcf, njt_uint_t err);
static njt_int_t njt_http_send_refresh(njt_http_request_t *r);


static u_char njt_http_error_full_tail[] =
"<hr><center>" NJT_VER "</center>" CRLF
"</body>" CRLF
"</html>" CRLF
;


static u_char njt_http_error_build_tail[] =
"<hr><center>" NJT_VER_BUILD "</center>" CRLF
"</body>" CRLF
"</html>" CRLF
;


static u_char njt_http_error_tail[] =
"<hr><center>njet</center>" CRLF
"</body>" CRLF
"</html>" CRLF
;


static u_char njt_http_msie_padding[] =
"<!-- a padding to disable MSIE and Chrome friendly error page -->" CRLF
"<!-- a padding to disable MSIE and Chrome friendly error page -->" CRLF
"<!-- a padding to disable MSIE and Chrome friendly error page -->" CRLF
"<!-- a padding to disable MSIE and Chrome friendly error page -->" CRLF
"<!-- a padding to disable MSIE and Chrome friendly error page -->" CRLF
"<!-- a padding to disable MSIE and Chrome friendly error page -->" CRLF
;


static u_char njt_http_msie_refresh_head[] =
"<html><head><meta http-equiv=\"Refresh\" content=\"0; URL=";


static u_char njt_http_msie_refresh_tail[] =
"\"></head><body></body></html>" CRLF;


static char njt_http_error_301_page[] =
"<html>" CRLF
"<head><title>301 Moved Permanently</title></head>" CRLF
"<body>" CRLF
"<center><h1>301 Moved Permanently</h1></center>" CRLF
;


static char njt_http_error_302_page[] =
"<html>" CRLF
"<head><title>302 Found</title></head>" CRLF
"<body>" CRLF
"<center><h1>302 Found</h1></center>" CRLF
;


static char njt_http_error_303_page[] =
"<html>" CRLF
"<head><title>303 See Other</title></head>" CRLF
"<body>" CRLF
"<center><h1>303 See Other</h1></center>" CRLF
;


static char njt_http_error_307_page[] =
"<html>" CRLF
"<head><title>307 Temporary Redirect</title></head>" CRLF
"<body>" CRLF
"<center><h1>307 Temporary Redirect</h1></center>" CRLF
;


static char njt_http_error_308_page[] =
"<html>" CRLF
"<head><title>308 Permanent Redirect</title></head>" CRLF
"<body>" CRLF
"<center><h1>308 Permanent Redirect</h1></center>" CRLF
;


static char njt_http_error_400_page[] =
"<html>" CRLF
"<head><title>400 Bad Request</title></head>" CRLF
"<body>" CRLF
"<center><h1>400 Bad Request</h1></center>" CRLF
;


static char njt_http_error_401_page[] =
"<html>" CRLF
"<head><title>401 Authorization Required</title></head>" CRLF
"<body>" CRLF
"<center><h1>401 Authorization Required</h1></center>" CRLF
;


static char njt_http_error_402_page[] =
"<html>" CRLF
"<head><title>402 Payment Required</title></head>" CRLF
"<body>" CRLF
"<center><h1>402 Payment Required</h1></center>" CRLF
;


static char njt_http_error_403_page[] =
"<html>" CRLF
"<head><title>403 Forbidden</title></head>" CRLF
"<body>" CRLF
"<center><h1>403 Forbidden</h1></center>" CRLF
;


static char njt_http_error_404_page[] =
"<html>" CRLF
"<head><title>404 Not Found</title></head>" CRLF
"<body>" CRLF
"<center><h1>404 Not Found</h1></center>" CRLF
;


static char njt_http_error_405_page[] =
"<html>" CRLF
"<head><title>405 Not Allowed</title></head>" CRLF
"<body>" CRLF
"<center><h1>405 Not Allowed</h1></center>" CRLF
;


static char njt_http_error_406_page[] =
"<html>" CRLF
"<head><title>406 Not Acceptable</title></head>" CRLF
"<body>" CRLF
"<center><h1>406 Not Acceptable</h1></center>" CRLF
;


static char njt_http_error_408_page[] =
"<html>" CRLF
"<head><title>408 Request Time-out</title></head>" CRLF
"<body>" CRLF
"<center><h1>408 Request Time-out</h1></center>" CRLF
;


static char njt_http_error_409_page[] =
"<html>" CRLF
"<head><title>409 Conflict</title></head>" CRLF
"<body>" CRLF
"<center><h1>409 Conflict</h1></center>" CRLF
;


static char njt_http_error_410_page[] =
"<html>" CRLF
"<head><title>410 Gone</title></head>" CRLF
"<body>" CRLF
"<center><h1>410 Gone</h1></center>" CRLF
;


static char njt_http_error_411_page[] =
"<html>" CRLF
"<head><title>411 Length Required</title></head>" CRLF
"<body>" CRLF
"<center><h1>411 Length Required</h1></center>" CRLF
;


static char njt_http_error_412_page[] =
"<html>" CRLF
"<head><title>412 Precondition Failed</title></head>" CRLF
"<body>" CRLF
"<center><h1>412 Precondition Failed</h1></center>" CRLF
;


static char njt_http_error_413_page[] =
"<html>" CRLF
"<head><title>413 Request Entity Too Large</title></head>" CRLF
"<body>" CRLF
"<center><h1>413 Request Entity Too Large</h1></center>" CRLF
;


static char njt_http_error_414_page[] =
"<html>" CRLF
"<head><title>414 Request-URI Too Large</title></head>" CRLF
"<body>" CRLF
"<center><h1>414 Request-URI Too Large</h1></center>" CRLF
;


static char njt_http_error_415_page[] =
"<html>" CRLF
"<head><title>415 Unsupported Media Type</title></head>" CRLF
"<body>" CRLF
"<center><h1>415 Unsupported Media Type</h1></center>" CRLF
;


static char njt_http_error_416_page[] =
"<html>" CRLF
"<head><title>416 Requested Range Not Satisfiable</title></head>" CRLF
"<body>" CRLF
"<center><h1>416 Requested Range Not Satisfiable</h1></center>" CRLF
;


static char njt_http_error_421_page[] =
"<html>" CRLF
"<head><title>421 Misdirected Request</title></head>" CRLF
"<body>" CRLF
"<center><h1>421 Misdirected Request</h1></center>" CRLF
;


static char njt_http_error_429_page[] =
"<html>" CRLF
"<head><title>429 Too Many Requests</title></head>" CRLF
"<body>" CRLF
"<center><h1>429 Too Many Requests</h1></center>" CRLF
;


static char njt_http_error_494_page[] =
"<html>" CRLF
"<head><title>400 Request Header Or Cookie Too Large</title></head>"
CRLF
"<body>" CRLF
"<center><h1>400 Bad Request</h1></center>" CRLF
"<center>Request Header Or Cookie Too Large</center>" CRLF
;


static char njt_http_error_495_page[] =
"<html>" CRLF
"<head><title>400 The SSL certificate error</title></head>"
CRLF
"<body>" CRLF
"<center><h1>400 Bad Request</h1></center>" CRLF
"<center>The SSL certificate error</center>" CRLF
;


static char njt_http_error_496_page[] =
"<html>" CRLF
"<head><title>400 No required SSL certificate was sent</title></head>"
CRLF
"<body>" CRLF
"<center><h1>400 Bad Request</h1></center>" CRLF
"<center>No required SSL certificate was sent</center>" CRLF
;


static char njt_http_error_497_page[] =
"<html>" CRLF
"<head><title>400 The plain HTTP request was sent to HTTPS port</title></head>"
CRLF
"<body>" CRLF
"<center><h1>400 Bad Request</h1></center>" CRLF
"<center>The plain HTTP request was sent to HTTPS port</center>" CRLF
;


static char njt_http_error_500_page[] =
"<html>" CRLF
"<head><title>500 Internal Server Error</title></head>" CRLF
"<body>" CRLF
"<center><h1>500 Internal Server Error</h1></center>" CRLF
;


static char njt_http_error_501_page[] =
"<html>" CRLF
"<head><title>501 Not Implemented</title></head>" CRLF
"<body>" CRLF
"<center><h1>501 Not Implemented</h1></center>" CRLF
;


static char njt_http_error_502_page[] =
"<html>" CRLF
"<head><title>502 Bad Gateway</title></head>" CRLF
"<body>" CRLF
"<center><h1>502 Bad Gateway</h1></center>" CRLF
;


static char njt_http_error_503_page[] =
"<html>" CRLF
"<head><title>503 Service Temporarily Unavailable</title></head>" CRLF
"<body>" CRLF
"<center><h1>503 Service Temporarily Unavailable</h1></center>" CRLF
;


static char njt_http_error_504_page[] =
"<html>" CRLF
"<head><title>504 Gateway Time-out</title></head>" CRLF
"<body>" CRLF
"<center><h1>504 Gateway Time-out</h1></center>" CRLF
;


static char njt_http_error_505_page[] =
"<html>" CRLF
"<head><title>505 HTTP Version Not Supported</title></head>" CRLF
"<body>" CRLF
"<center><h1>505 HTTP Version Not Supported</h1></center>" CRLF
;


static char njt_http_error_507_page[] =
"<html>" CRLF
"<head><title>507 Insufficient Storage</title></head>" CRLF
"<body>" CRLF
"<center><h1>507 Insufficient Storage</h1></center>" CRLF
;


static njt_str_t njt_http_error_pages[] = {

    njt_null_string,                     /* 201, 204 */

#define NJT_HTTP_LAST_2XX  202
#define NJT_HTTP_OFF_3XX   (NJT_HTTP_LAST_2XX - 201)

    /* njt_null_string, */               /* 300 */
    njt_string(njt_http_error_301_page),
    njt_string(njt_http_error_302_page),
    njt_string(njt_http_error_303_page),
    njt_null_string,                     /* 304 */
    njt_null_string,                     /* 305 */
    njt_null_string,                     /* 306 */
    njt_string(njt_http_error_307_page),
    njt_string(njt_http_error_308_page),

#define NJT_HTTP_LAST_3XX  309
#define NJT_HTTP_OFF_4XX   (NJT_HTTP_LAST_3XX - 301 + NJT_HTTP_OFF_3XX)

    njt_string(njt_http_error_400_page),
    njt_string(njt_http_error_401_page),
    njt_string(njt_http_error_402_page),
    njt_string(njt_http_error_403_page),
    njt_string(njt_http_error_404_page),
    njt_string(njt_http_error_405_page),
    njt_string(njt_http_error_406_page),
    njt_null_string,                     /* 407 */
    njt_string(njt_http_error_408_page),
    njt_string(njt_http_error_409_page),
    njt_string(njt_http_error_410_page),
    njt_string(njt_http_error_411_page),
    njt_string(njt_http_error_412_page),
    njt_string(njt_http_error_413_page),
    njt_string(njt_http_error_414_page),
    njt_string(njt_http_error_415_page),
    njt_string(njt_http_error_416_page),
    njt_null_string,                     /* 417 */
    njt_null_string,                     /* 418 */
    njt_null_string,                     /* 419 */
    njt_null_string,                     /* 420 */
    njt_string(njt_http_error_421_page),
    njt_null_string,                     /* 422 */
    njt_null_string,                     /* 423 */
    njt_null_string,                     /* 424 */
    njt_null_string,                     /* 425 */
    njt_null_string,                     /* 426 */
    njt_null_string,                     /* 427 */
    njt_null_string,                     /* 428 */
    njt_string(njt_http_error_429_page),

#define NJT_HTTP_LAST_4XX  430
#define NJT_HTTP_OFF_5XX   (NJT_HTTP_LAST_4XX - 400 + NJT_HTTP_OFF_4XX)

    njt_string(njt_http_error_494_page), /* 494, request header too large */
    njt_string(njt_http_error_495_page), /* 495, https certificate error */
    njt_string(njt_http_error_496_page), /* 496, https no certificate */
    njt_string(njt_http_error_497_page), /* 497, http to https */
    njt_string(njt_http_error_404_page), /* 498, canceled */
    njt_null_string,                     /* 499, client has closed connection */

    njt_string(njt_http_error_500_page),
    njt_string(njt_http_error_501_page),
    njt_string(njt_http_error_502_page),
    njt_string(njt_http_error_503_page),
    njt_string(njt_http_error_504_page),
    njt_string(njt_http_error_505_page),
    njt_null_string,                     /* 506 */
    njt_string(njt_http_error_507_page)

#define NJT_HTTP_LAST_5XX  508

};


njt_int_t
njt_http_special_response_handler(njt_http_request_t *r, njt_int_t error)
{
    njt_uint_t                 i, err;
    njt_http_err_page_t       *err_page;
    njt_http_core_loc_conf_t  *clcf;

    njt_log_debug3(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http special response: %i, \"%V?%V\"",
                   error, &r->uri, &r->args);

    r->err_status = error;

    if (r->keepalive) {
        switch (error) {
            case NJT_HTTP_BAD_REQUEST:
            case NJT_HTTP_REQUEST_ENTITY_TOO_LARGE:
            case NJT_HTTP_REQUEST_URI_TOO_LARGE:
            case NJT_HTTP_TO_HTTPS:
            case NJT_HTTPS_CERT_ERROR:
            case NJT_HTTPS_NO_CERT:
            case NJT_HTTP_INTERNAL_SERVER_ERROR:
            case NJT_HTTP_NOT_IMPLEMENTED:
                r->keepalive = 0;
        }
    }

    if (r->lingering_close) {
        switch (error) {
            case NJT_HTTP_BAD_REQUEST:
            case NJT_HTTP_TO_HTTPS:
            case NJT_HTTPS_CERT_ERROR:
            case NJT_HTTPS_NO_CERT:
                r->lingering_close = 0;
        }
    }

    r->headers_out.content_type.len = 0;

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    if (!r->error_page && clcf->error_pages && r->uri_changes != 0) {

        if (clcf->recursive_error_pages == 0) {
            r->error_page = 1;
        }

        err_page = clcf->error_pages->elts;

        for (i = 0; i < clcf->error_pages->nelts; i++) {
            if (err_page[i].status == error) {
                return njt_http_send_error_page(r, &err_page[i]);
            }
        }
    }

    r->expect_tested = 1;

    if (njt_http_discard_request_body(r) != NJT_OK) {
        r->keepalive = 0;
    }

    if (clcf->msie_refresh
        && r->headers_in.msie
        && (error == NJT_HTTP_MOVED_PERMANENTLY
            || error == NJT_HTTP_MOVED_TEMPORARILY))
    {
        return njt_http_send_refresh(r);
    }

    if (error == NJT_HTTP_CREATED) {
        /* 201 */
        err = 0;

    } else if (error == NJT_HTTP_NO_CONTENT) {
        /* 204 */
        err = 0;

    } else if (error >= NJT_HTTP_MOVED_PERMANENTLY
               && error < NJT_HTTP_LAST_3XX)
    {
        /* 3XX */
        err = error - NJT_HTTP_MOVED_PERMANENTLY + NJT_HTTP_OFF_3XX;

    } else if (error >= NJT_HTTP_BAD_REQUEST
               && error < NJT_HTTP_LAST_4XX)
    {
        /* 4XX */
        err = error - NJT_HTTP_BAD_REQUEST + NJT_HTTP_OFF_4XX;

    } else if (error >= NJT_HTTP_NJT_CODES
               && error < NJT_HTTP_LAST_5XX)
    {
        /* 49X, 5XX */
        err = error - NJT_HTTP_NJT_CODES + NJT_HTTP_OFF_5XX;
        switch (error) {
            case NJT_HTTP_TO_HTTPS:
            case NJT_HTTPS_CERT_ERROR:
            case NJT_HTTPS_NO_CERT:
            case NJT_HTTP_REQUEST_HEADER_TOO_LARGE:
                r->err_status = NJT_HTTP_BAD_REQUEST;
        }

    } else {
        /* unknown code, zero body */
        err = 0;
    }

    return njt_http_send_special_response(r, clcf, err);
}


njt_int_t
njt_http_filter_finalize_request(njt_http_request_t *r, njt_module_t *m,
    njt_int_t error)
{
    void       *ctx;
    njt_int_t   rc;

    njt_http_clean_header(r);

    ctx = NULL;

    if (m) {
        ctx = r->ctx[m->ctx_index];
    }

    /* clear the modules contexts */
    njt_memzero(r->ctx, sizeof(void *) * njt_http_max_module);

    if (m) {
        r->ctx[m->ctx_index] = ctx;
    }

    r->filter_finalize = 1;

    rc = njt_http_special_response_handler(r, error);

    /* NJT_ERROR resets any pending data */

    switch (rc) {

    case NJT_OK:
    case NJT_DONE:
        return NJT_ERROR;

    default:
        return rc;
    }
}


void
njt_http_clean_header(njt_http_request_t *r)
{
    njt_memzero(&r->headers_out.status,
                sizeof(njt_http_headers_out_t)
                    - offsetof(njt_http_headers_out_t, status));

    r->headers_out.headers.part.nelts = 0;
    r->headers_out.headers.part.next = NULL;
    r->headers_out.headers.last = &r->headers_out.headers.part;

    r->headers_out.trailers.part.nelts = 0;
    r->headers_out.trailers.part.next = NULL;
    r->headers_out.trailers.last = &r->headers_out.trailers.part;

    r->headers_out.content_length_n = -1;
    r->headers_out.last_modified_time = -1;
}


static njt_int_t
njt_http_send_error_page(njt_http_request_t *r, njt_http_err_page_t *err_page)
{
    njt_int_t                  overwrite;
    njt_str_t                  uri, args;
    njt_table_elt_t           *location;
    njt_http_core_loc_conf_t  *clcf;

    overwrite = err_page->overwrite;

    if (overwrite && overwrite != NJT_HTTP_OK) {
        r->expect_tested = 1;
    }

    if (overwrite >= 0) {
        r->err_status = overwrite;
    }

    if (njt_http_complex_value(r, &err_page->value, &uri) != NJT_OK) {
        return NJT_ERROR;
    }

    if (uri.len && uri.data[0] == '/') {

        if (err_page->value.lengths) {
            njt_http_split_args(r, &uri, &args);

        } else {
            args = err_page->args;
        }

        if (r->method != NJT_HTTP_HEAD) {
            r->method = NJT_HTTP_GET;
            r->method_name = njt_http_core_get_method;
        }

        return njt_http_internal_redirect(r, &uri, &args);
    }

    if (uri.len && uri.data[0] == '@') {
        return njt_http_named_location(r, &uri);
    }

    r->expect_tested = 1;

    if (njt_http_discard_request_body(r) != NJT_OK) {
        r->keepalive = 0;
    }

    location = njt_list_push(&r->headers_out.headers);

    if (location == NULL) {
        return NJT_ERROR;
    }

    if (overwrite != NJT_HTTP_MOVED_PERMANENTLY
        && overwrite != NJT_HTTP_MOVED_TEMPORARILY
        && overwrite != NJT_HTTP_SEE_OTHER
        && overwrite != NJT_HTTP_TEMPORARY_REDIRECT
        && overwrite != NJT_HTTP_PERMANENT_REDIRECT)
    {
        r->err_status = NJT_HTTP_MOVED_TEMPORARILY;
    }

    location->hash = 1;
    location->next = NULL;
    njt_str_set(&location->key, "Location");
    location->value = uri;

    njt_http_clear_location(r);

    r->headers_out.location = location;

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    if (clcf->msie_refresh && r->headers_in.msie) {
        return njt_http_send_refresh(r);
    }

    return njt_http_send_special_response(r, clcf, r->err_status
                                                   - NJT_HTTP_MOVED_PERMANENTLY
                                                   + NJT_HTTP_OFF_3XX);
}


static njt_int_t
njt_http_send_special_response(njt_http_request_t *r,
    njt_http_core_loc_conf_t *clcf, njt_uint_t err)
{
    u_char       *tail;
    size_t        len;
    njt_int_t     rc;
    njt_buf_t    *b;
    njt_uint_t    msie_padding;
    njt_chain_t   out[3];

    if (clcf->server_tokens == NJT_HTTP_SERVER_TOKENS_ON) {
        len = sizeof(njt_http_error_full_tail) - 1;
        tail = njt_http_error_full_tail;

    } else if (clcf->server_tokens == NJT_HTTP_SERVER_TOKENS_BUILD) {
        len = sizeof(njt_http_error_build_tail) - 1;
        tail = njt_http_error_build_tail;

    } else {
        len = sizeof(njt_http_error_tail) - 1;
        tail = njt_http_error_tail;
    }

    msie_padding = 0;

    if (njt_http_error_pages[err].len) {
        r->headers_out.content_length_n = njt_http_error_pages[err].len + len;
        if (clcf->msie_padding
            && (r->headers_in.msie || r->headers_in.chrome)
            && r->http_version >= NJT_HTTP_VERSION_10
            && err >= NJT_HTTP_OFF_4XX)
        {
            r->headers_out.content_length_n +=
                                         sizeof(njt_http_msie_padding) - 1;
            msie_padding = 1;
        }

        r->headers_out.content_type_len = sizeof("text/html") - 1;
        njt_str_set(&r->headers_out.content_type, "text/html");
        r->headers_out.content_type_lowcase = NULL;

    } else {
        r->headers_out.content_length_n = 0;
    }

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    njt_http_clear_accept_ranges(r);
    njt_http_clear_last_modified(r);
    njt_http_clear_etag(r);

    rc = njt_http_send_header(r);

    if (rc == NJT_ERROR || r->header_only) {
        return rc;
    }

    if (njt_http_error_pages[err].len == 0) {
        return njt_http_send_special(r, NJT_HTTP_LAST);
    }

    b = njt_calloc_buf(r->pool);
    if (b == NULL) {
        return NJT_ERROR;
    }

    b->memory = 1;
    b->pos = njt_http_error_pages[err].data;
    b->last = njt_http_error_pages[err].data + njt_http_error_pages[err].len;

    out[0].buf = b;
    out[0].next = &out[1];

    b = njt_calloc_buf(r->pool);
    if (b == NULL) {
        return NJT_ERROR;
    }

    b->memory = 1;

    b->pos = tail;
    b->last = tail + len;

    out[1].buf = b;
    out[1].next = NULL;

    if (msie_padding) {
        b = njt_calloc_buf(r->pool);
        if (b == NULL) {
            return NJT_ERROR;
        }

        b->memory = 1;
        b->pos = njt_http_msie_padding;
        b->last = njt_http_msie_padding + sizeof(njt_http_msie_padding) - 1;

        out[1].next = &out[2];
        out[2].buf = b;
        out[2].next = NULL;
    }

    if (r == r->main) {
        b->last_buf = 1;
    }

    b->last_in_chain = 1;

    return njt_http_output_filter(r, &out[0]);
}


static njt_int_t
njt_http_send_refresh(njt_http_request_t *r)
{
    u_char       *p, *location;
    size_t        len, size;
    uintptr_t     escape;
    njt_int_t     rc;
    njt_buf_t    *b;
    njt_chain_t   out;

    len = r->headers_out.location->value.len;
    location = r->headers_out.location->value.data;

    escape = 2 * njt_escape_uri(NULL, location, len, NJT_ESCAPE_REFRESH);

    size = sizeof(njt_http_msie_refresh_head) - 1
           + escape + len
           + sizeof(njt_http_msie_refresh_tail) - 1;

    r->err_status = NJT_HTTP_OK;

    r->headers_out.content_type_len = sizeof("text/html") - 1;
    njt_str_set(&r->headers_out.content_type, "text/html");
    r->headers_out.content_type_lowcase = NULL;

    r->headers_out.location->hash = 0;
    r->headers_out.location = NULL;

    r->headers_out.content_length_n = size;

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    njt_http_clear_accept_ranges(r);
    njt_http_clear_last_modified(r);
    njt_http_clear_etag(r);

    rc = njt_http_send_header(r);

    if (rc == NJT_ERROR || r->header_only) {
        return rc;
    }

    b = njt_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return NJT_ERROR;
    }

    p = njt_cpymem(b->pos, njt_http_msie_refresh_head,
                   sizeof(njt_http_msie_refresh_head) - 1);

    if (escape == 0) {
        p = njt_cpymem(p, location, len);

    } else {
        p = (u_char *) njt_escape_uri(p, location, len, NJT_ESCAPE_REFRESH);
    }

    b->last = njt_cpymem(p, njt_http_msie_refresh_tail,
                         sizeof(njt_http_msie_refresh_tail) - 1);

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    return njt_http_output_filter(r, &out);
}
