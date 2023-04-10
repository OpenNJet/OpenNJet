
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#define PERL_NO_GET_CONTEXT

#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_http_perl_module.h>

#include "XSUB.h"


#define njt_http_perl_set_request(r, ctx)                                     \
                                                                              \
    ctx = INT2PTR(njt_http_perl_ctx_t *, SvIV((SV *) SvRV(ST(0))));           \
    r = ctx->request


#define njt_http_perl_set_targ(p, len)                                        \
                                                                              \
    SvUPGRADE(TARG, SVt_PV);                                                  \
    SvPOK_on(TARG);                                                           \
    sv_setpvn(TARG, (char *) p, len)


static njt_int_t
njt_http_perl_sv2str(pTHX_ njt_http_request_t *r, njt_str_t *s, SV *sv)
{
    u_char  *p;
    STRLEN   len;

    if (SvROK(sv) && SvTYPE(SvRV(sv)) == SVt_PV) {
        sv = SvRV(sv);
    }

    p = (u_char *) SvPV(sv, len);

    s->len = len;

    if (SvREADONLY(sv) && SvPOK(sv)) {
        s->data = p;

        njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "perl sv2str: %08XD \"%V\"", sv->sv_flags, s);

        return NJT_OK;
    }

    s->data = njt_pnalloc(r->pool, len);
    if (s->data == NULL) {
        return NJT_ERROR;
    }

    njt_memcpy(s->data, p, len);

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "perl sv2str: %08XD \"%V\"", sv->sv_flags, s);

    return NJT_OK;
}


static njt_int_t
njt_http_perl_output(njt_http_request_t *r, njt_http_perl_ctx_t *ctx,
    njt_buf_t *b)
{
    njt_chain_t   out;
#if (NJT_HTTP_SSI)
    njt_chain_t  *cl;

    if (ctx->ssi) {
        cl = njt_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NJT_ERROR;
        }

        cl->buf = b;
        cl->next = NULL;
        *ctx->ssi->last_out = cl;
        ctx->ssi->last_out = &cl->next;

        return NJT_OK;
    }
#endif

    out.buf = b;
    out.next = NULL;

    return njt_http_output_filter(r, &out);
}


MODULE = njet    PACKAGE = njet


PROTOTYPES: DISABLE


void
status(r, code)
    CODE:

    njt_http_request_t   *r;
    njt_http_perl_ctx_t  *ctx;

    njt_http_perl_set_request(r, ctx);

    if (ctx->variable) {
        croak("status(): cannot be used in variable handler");
    }

    r->headers_out.status = SvIV(ST(1));

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "perl status: %d", r->headers_out.status);

    XSRETURN_UNDEF;


void
send_http_header(r, ...)
    CODE:

    njt_http_request_t   *r;
    njt_http_perl_ctx_t  *ctx;
    SV                   *sv;
    njt_int_t             rc;

    njt_http_perl_set_request(r, ctx);

    if (ctx->error) {
        croak("send_http_header(): called after error");
    }

    if (ctx->variable) {
        croak("send_http_header(): cannot be used in variable handler");
    }

    if (ctx->header_sent) {
        croak("send_http_header(): header already sent");
    }

    if (ctx->redirect_uri.len) {
        croak("send_http_header(): cannot be used with internal_redirect()");
    }

    if (r->headers_out.status == 0) {
        r->headers_out.status = NJT_HTTP_OK;
    }

    if (items != 1) {
        sv = ST(1);

        if (njt_http_perl_sv2str(aTHX_ r, &r->headers_out.content_type, sv)
            != NJT_OK)
        {
            ctx->error = 1;
            croak("njt_http_perl_sv2str() failed");
        }

        r->headers_out.content_type_len = r->headers_out.content_type.len;

    } else {
        if (njt_http_set_content_type(r) != NJT_OK) {
            ctx->error = 1;
            croak("njt_http_set_content_type() failed");
        }
    }

    ctx->header_sent = 1;

    r->disable_not_modified = 1;

    rc = njt_http_send_header(r);

    if (rc == NJT_ERROR || rc > NJT_OK) {
        ctx->error = 1;
        ctx->status = rc;
        croak("njt_http_send_header() failed");
    }


void
header_only(r)
    CODE:

    dXSTARG;
    njt_http_request_t   *r;
    njt_http_perl_ctx_t  *ctx;

    njt_http_perl_set_request(r, ctx);

    sv_upgrade(TARG, SVt_IV);
    sv_setiv(TARG, r->header_only);

    ST(0) = TARG;


void
uri(r)
    CODE:

    dXSTARG;
    njt_http_request_t   *r;
    njt_http_perl_ctx_t  *ctx;

    njt_http_perl_set_request(r, ctx);
    njt_http_perl_set_targ(r->uri.data, r->uri.len);

    ST(0) = TARG;


void
args(r)
    CODE:

    dXSTARG;
    njt_http_request_t   *r;
    njt_http_perl_ctx_t  *ctx;

    njt_http_perl_set_request(r, ctx);
    njt_http_perl_set_targ(r->args.data, r->args.len);

    ST(0) = TARG;


void
request_method(r)
    CODE:

    dXSTARG;
    njt_http_request_t   *r;
    njt_http_perl_ctx_t  *ctx;

    njt_http_perl_set_request(r, ctx);
    njt_http_perl_set_targ(r->method_name.data, r->method_name.len);

    ST(0) = TARG;


void
remote_addr(r)
    CODE:

    dXSTARG;
    njt_http_request_t   *r;
    njt_http_perl_ctx_t  *ctx;

    njt_http_perl_set_request(r, ctx);
    njt_http_perl_set_targ(r->connection->addr_text.data,
                           r->connection->addr_text.len);

    ST(0) = TARG;


void
header_in(r, key)
    CODE:

    dXSTARG;
    njt_http_request_t         *r;
    njt_http_perl_ctx_t        *ctx;
    SV                         *key;
    u_char                     *p, *lowcase_key, *value, sep;
    STRLEN                      len;
    ssize_t                     size;
    njt_uint_t                  i, hash;
    njt_list_part_t            *part;
    njt_table_elt_t            *h, *header, **ph;
    njt_http_header_t          *hh;
    njt_http_core_main_conf_t  *cmcf;

    njt_http_perl_set_request(r, ctx);

    key = ST(1);

    if (SvROK(key) && SvTYPE(SvRV(key)) == SVt_PV) {
        key = SvRV(key);
    }

    p = (u_char *) SvPV(key, len);

    /* look up hashed headers */

    lowcase_key = njt_pnalloc(r->pool, len);
    if (lowcase_key == NULL) {
        ctx->error = 1;
        croak("njt_pnalloc() failed");
    }

    hash = njt_hash_strlow(lowcase_key, p, len);

    cmcf = njt_http_get_module_main_conf(r, njt_http_core_module);

    hh = njt_hash_find(&cmcf->headers_in_hash, hash, lowcase_key, len);

    if (hh) {

        if (hh->offset == offsetof(njt_http_headers_in_t, cookie)) {
            sep = ';';

        } else {
            sep = ',';
        }

        ph = (njt_table_elt_t **) ((char *) &r->headers_in + hh->offset);

        goto found;
    }

    /* iterate over all headers */

    sep = ',';
    ph = &header;

    part = &r->headers_in.headers.part;
    h = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (len != h[i].key.len
            || njt_strcasecmp(p, h[i].key.data) != 0)
        {
            continue;
        }

        *ph = &h[i];
        ph = &h[i].next;
    }

    *ph = NULL;
    ph = &header;

    found:

    if (*ph == NULL) {
        XSRETURN_UNDEF;
    }

    if ((*ph)->next == NULL) {
        njt_http_perl_set_targ((*ph)->value.data, (*ph)->value.len);
        goto done;
    }

    size = - (ssize_t) (sizeof("; ") - 1);

    for (h = *ph; h; h = h->next) {
        size += h->value.len + sizeof("; ") - 1;
    }

    value = njt_pnalloc(r->pool, size);
    if (value == NULL) {
        ctx->error = 1;
        croak("njt_pnalloc() failed");
    }

    p = value;

    for (h = *ph; h; h = h->next) {
        p = njt_copy(p, h->value.data, h->value.len);

        if (h->next == NULL) {
            break;
        }

        *p++ = sep; *p++ = ' ';
    }

    njt_http_perl_set_targ(value, size);

    done:

    ST(0) = TARG;


void
has_request_body(r, next)
    CODE:

    dXSTARG;
    njt_http_request_t   *r;
    njt_http_perl_ctx_t  *ctx;
    njt_int_t             rc;

    njt_http_perl_set_request(r, ctx);

    if (ctx->variable) {
        croak("has_request_body(): cannot be used in variable handler");
    }

    if (ctx->next) {
        croak("has_request_body(): another handler active");
    }

    if (r->headers_in.content_length_n <= 0 && !r->headers_in.chunked) {
        XSRETURN_UNDEF;
    }

    ctx->next = SvRV(ST(1));

    r->request_body_in_single_buf = 1;
    r->request_body_in_persistent_file = 1;
    r->request_body_in_clean_file = 1;

    if (r->request_body_in_file_only) {
        r->request_body_file_log_level = 0;
    }

    rc = njt_http_read_client_request_body(r, njt_http_perl_handle_request);

    if (rc >= NJT_HTTP_SPECIAL_RESPONSE) {
        ctx->error = 1;
        ctx->status = rc;
        ctx->next = NULL;
        croak("njt_http_read_client_request_body() failed");
    }

    sv_upgrade(TARG, SVt_IV);
    sv_setiv(TARG, 1);

    ST(0) = TARG;


void
request_body(r)
    CODE:

    dXSTARG;
    njt_http_request_t   *r;
    njt_http_perl_ctx_t  *ctx;
    u_char               *p, *data;
    size_t                len;
    njt_buf_t            *buf;
    njt_chain_t          *cl;

    njt_http_perl_set_request(r, ctx);

    if (r->request_body == NULL
        || r->request_body->temp_file
        || r->request_body->bufs == NULL)
    {
        XSRETURN_UNDEF;
    }

    cl = r->request_body->bufs;
    buf = cl->buf;

    if (cl->next == NULL) {
        len = buf->last - buf->pos;
        data = buf->pos;
        goto done;
    }

    len = buf->last - buf->pos;
    cl = cl->next;

    for ( /* void */ ; cl; cl = cl->next) {
        buf = cl->buf;
        len += buf->last - buf->pos;
    }

    p = njt_pnalloc(r->pool, len);
    if (p == NULL) {
        ctx->error = 1;
        croak("njt_pnalloc() failed");
    }

    data = p;
    cl = r->request_body->bufs;

    for ( /* void */ ; cl; cl = cl->next) {
        buf = cl->buf;
        p = njt_cpymem(p, buf->pos, buf->last - buf->pos);
    }

    done:

    if (len == 0) {
        XSRETURN_UNDEF;
    }

    njt_http_perl_set_targ(data, len);

    ST(0) = TARG;


void
request_body_file(r)
    CODE:

    dXSTARG;
    njt_http_request_t   *r;
    njt_http_perl_ctx_t  *ctx;

    njt_http_perl_set_request(r, ctx);

    if (r->request_body == NULL || r->request_body->temp_file == NULL) {
        XSRETURN_UNDEF;
    }

    njt_http_perl_set_targ(r->request_body->temp_file->file.name.data,
                           r->request_body->temp_file->file.name.len);

    ST(0) = TARG;


void
discard_request_body(r)
    CODE:

    njt_http_request_t   *r;
    njt_http_perl_ctx_t  *ctx;
    njt_int_t             rc;

    njt_http_perl_set_request(r, ctx);

    if (ctx->variable) {
        croak("discard_request_body(): cannot be used in variable handler");
    }

    rc = njt_http_discard_request_body(r);

    if (rc != NJT_OK) {
        ctx->error = 1;
        ctx->status = rc;
        croak("njt_http_discard_request_body() failed");
    }


void
header_out(r, key, value)
    CODE:

    njt_http_request_t   *r;
    njt_http_perl_ctx_t  *ctx;
    SV                   *key;
    SV                   *value;
    njt_table_elt_t      *header;

    njt_http_perl_set_request(r, ctx);

    if (ctx->error) {
        croak("header_out(): called after error");
    }

    if (ctx->variable) {
        croak("header_out(): cannot be used in variable handler");
    }

    key = ST(1);
    value = ST(2);

    header = njt_list_push(&r->headers_out.headers);
    if (header == NULL) {
        ctx->error = 1;
        croak("njt_list_push() failed");
    }

    header->hash = 1;
    header->next = NULL;

    if (njt_http_perl_sv2str(aTHX_ r, &header->key, key) != NJT_OK) {
        header->hash = 0;
        ctx->error = 1;
        croak("njt_http_perl_sv2str() failed");
    }

    if (njt_http_perl_sv2str(aTHX_ r, &header->value, value) != NJT_OK) {
        header->hash = 0;
        ctx->error = 1;
        croak("njt_http_perl_sv2str() failed");
    }

    if (header->key.len == sizeof("Content-Length") - 1
        && njt_strncasecmp(header->key.data, (u_char *) "Content-Length",
                           sizeof("Content-Length") - 1) == 0)
    {
        r->headers_out.content_length_n = (off_t) SvIV(value);
        r->headers_out.content_length = header;
    }

    if (header->key.len == sizeof("Content-Encoding") - 1
        && njt_strncasecmp(header->key.data, (u_char *) "Content-Encoding",
                           sizeof("Content-Encoding") - 1) == 0)
    {
        r->headers_out.content_encoding = header;
    }


void
filename(r)
    CODE:

    dXSTARG;
    njt_http_request_t   *r;
    njt_http_perl_ctx_t  *ctx;
    size_t                root;

    njt_http_perl_set_request(r, ctx);

    if (ctx->filename.data) {
        goto done;
    }

    if (njt_http_map_uri_to_path(r, &ctx->filename, &root, 0) == NULL) {
        ctx->error = 1;
        croak("njt_http_map_uri_to_path() failed");
    }

    ctx->filename.len--;
    sv_setpv(PL_statname, (char *) ctx->filename.data);

    done:

    njt_http_perl_set_targ(ctx->filename.data, ctx->filename.len);

    ST(0) = TARG;


void
print(r, ...)
    CODE:

    njt_http_request_t   *r;
    njt_http_perl_ctx_t  *ctx;
    SV                   *sv;
    int                   i;
    u_char               *p;
    size_t                size;
    STRLEN                len;
    njt_int_t             rc;
    njt_buf_t            *b;

    njt_http_perl_set_request(r, ctx);

    if (ctx->error) {
        croak("print(): called after error");
    }

    if (ctx->variable) {
        croak("print(): cannot be used in variable handler");
    }

    if (!ctx->header_sent) {
        croak("print(): header not sent");
    }

    if (items == 2) {

        /*
         * do zero copy for prolate single read-only SV:
         *     $r->print("some text\n");
         */

        sv = ST(1);

        if (SvROK(sv) && SvTYPE(SvRV(sv)) == SVt_PV) {
            sv = SvRV(sv);
        }

        if (SvREADONLY(sv) && SvPOK(sv)) {

            p = (u_char *) SvPV(sv, len);

            if (len == 0) {
                XSRETURN_EMPTY;
            }

            b = njt_calloc_buf(r->pool);
            if (b == NULL) {
                ctx->error = 1;
                croak("njt_calloc_buf() failed");
            }

            b->memory = 1;
            b->pos = p;
            b->last = p + len;
            b->start = p;
            b->end = b->last;

            njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "$r->print: read-only SV: %z", len);

            goto out;
        }
    }

    size = 0;

    for (i = 1; i < items; i++) {

        sv = ST(i);

        if (SvROK(sv) && SvTYPE(SvRV(sv)) == SVt_PV) {
            sv = SvRV(sv);
        }

        (void) SvPV(sv, len);

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "$r->print: copy SV: %z", len);

        size += len;
    }

    if (size == 0) {
        XSRETURN_EMPTY;
    }

    b = njt_create_temp_buf(r->pool, size);
    if (b == NULL) {
        ctx->error = 1;
        croak("njt_create_temp_buf() failed");
    }

    for (i = 1; i < items; i++) {
        sv = ST(i);

        if (SvROK(sv) && SvTYPE(SvRV(sv)) == SVt_PV) {
            sv = SvRV(sv);
        }

        p = (u_char *) SvPV(sv, len);
        b->last = njt_cpymem(b->last, p, len);
    }

    out:

    rc = njt_http_perl_output(r, ctx, b);

    if (rc == NJT_ERROR) {
        ctx->error = 1;
        croak("njt_http_perl_output() failed");
    }


void
sendfile(r, filename, offset = -1, bytes = 0)
    CODE:

    njt_http_request_t        *r;
    njt_http_perl_ctx_t       *ctx;
    char                      *filename;
    off_t                      offset;
    size_t                     bytes;
    njt_int_t                  rc;
    njt_str_t                  path;
    njt_buf_t                 *b;
    njt_open_file_info_t       of;
    njt_http_core_loc_conf_t  *clcf;

    njt_http_perl_set_request(r, ctx);

    if (ctx->error) {
        croak("sendfile(): called after error");
    }

    if (ctx->variable) {
        croak("sendfile(): cannot be used in variable handler");
    }

    if (!ctx->header_sent) {
        croak("sendfile(): header not sent");
    }

    filename = SvPV_nolen(ST(1));

    if (filename == NULL) {
        croak("sendfile(): NULL filename");
    }

    offset = items < 3 ? -1 : SvIV(ST(2));
    bytes = items < 4 ? 0 : SvIV(ST(3));

    b = njt_calloc_buf(r->pool);
    if (b == NULL) {
        ctx->error = 1;
        croak("njt_calloc_buf() failed");
    }

    b->file = njt_pcalloc(r->pool, sizeof(njt_file_t));
    if (b->file == NULL) {
        ctx->error = 1;
        croak("njt_pcalloc() failed");
    }

    path.len = njt_strlen(filename);

    path.data = njt_pnalloc(r->pool, path.len + 1);
    if (path.data == NULL) {
        ctx->error = 1;
        croak("njt_pnalloc() failed");
    }

    (void) njt_cpystrn(path.data, (u_char *) filename, path.len + 1);

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    njt_memzero(&of, sizeof(njt_open_file_info_t));

    of.read_ahead = clcf->read_ahead;
    of.directio = clcf->directio;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;

    if (njt_http_set_disable_symlinks(r, clcf, &path, &of) != NJT_OK) {
        ctx->error = 1;
        croak("njt_http_set_disable_symlinks() failed");
    }

    if (njt_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
        != NJT_OK)
    {
        if (of.err == 0) {
            ctx->error = 1;
            croak("njt_open_cached_file() failed");
        }

        njt_log_error(NJT_LOG_CRIT, r->connection->log, njt_errno,
                      "%s \"%s\" failed", of.failed, filename);

        ctx->error = 1;
        croak("njt_open_cached_file() failed");
    }

    if (offset == -1) {
        offset = 0;
    }

    if (bytes == 0) {
        bytes = of.size - offset;
    }

    b->in_file = 1;

    b->file_pos = offset;
    b->file_last = offset + bytes;

    b->file->fd = of.fd;
    b->file->log = r->connection->log;
    b->file->directio = of.is_directio;

    rc = njt_http_perl_output(r, ctx, b);

    if (rc == NJT_ERROR) {
        ctx->error = 1;
        croak("njt_http_perl_output() failed");
    }


void
flush(r)
    CODE:

    njt_http_request_t   *r;
    njt_http_perl_ctx_t  *ctx;
    njt_int_t             rc;
    njt_buf_t            *b;

    njt_http_perl_set_request(r, ctx);

    if (ctx->error) {
        croak("flush(): called after error");
    }

    if (ctx->variable) {
        croak("flush(): cannot be used in variable handler");
    }

    if (!ctx->header_sent) {
        croak("flush(): header not sent");
    }

    b = njt_calloc_buf(r->pool);
    if (b == NULL) {
        ctx->error = 1;
        croak("njt_calloc_buf() failed");
    }

    b->flush = 1;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0, "$r->flush");

    rc = njt_http_perl_output(r, ctx, b);

    if (rc == NJT_ERROR) {
        ctx->error = 1;
        croak("njt_http_perl_output() failed");
    }

    XSRETURN_EMPTY;


void
internal_redirect(r, uri)
    CODE:

    njt_http_request_t   *r;
    njt_http_perl_ctx_t  *ctx;
    SV                   *uri;

    njt_http_perl_set_request(r, ctx);

    if (ctx->variable) {
        croak("internal_redirect(): cannot be used in variable handler");
    }

    if (ctx->header_sent) {
        croak("internal_redirect(): header already sent");
    }

    uri = ST(1);

    if (njt_http_perl_sv2str(aTHX_ r, &ctx->redirect_uri, uri) != NJT_OK) {
        ctx->error = 1;
        croak("njt_http_perl_sv2str() failed");
    }


void
allow_ranges(r)
    CODE:

    njt_http_request_t   *r;
    njt_http_perl_ctx_t  *ctx;

    njt_http_perl_set_request(r, ctx);

    if (ctx->variable) {
        croak("allow_ranges(): cannot be used in variable handler");
    }

    r->allow_ranges = 1;


void
unescape(r, text, type = 0)
    CODE:

    dXSTARG;
    njt_http_request_t   *r;
    njt_http_perl_ctx_t  *ctx;
    SV                   *text;
    int                   type;
    u_char               *p, *dst, *src;
    STRLEN                len;

    njt_http_perl_set_request(r, ctx);

    text = ST(1);

    src = (u_char *) SvPV(text, len);

    p = njt_pnalloc(r->pool, len + 1);
    if (p == NULL) {
        ctx->error = 1;
        croak("njt_pnalloc() failed");
    }

    dst = p;

    type = items < 3 ? 0 : SvIV(ST(2));

    njt_unescape_uri(&dst, &src, len, (njt_uint_t) type);
    *dst = '\0';

    njt_http_perl_set_targ(p, dst - p);

    ST(0) = TARG;


void
variable(r, name, value = NULL)
    CODE:

    dXSTARG;
    njt_http_request_t         *r;
    njt_http_perl_ctx_t        *ctx;
    SV                         *name, *value;
    u_char                     *p, *lowcase;
    STRLEN                      len;
    njt_str_t                   var, val;
    njt_uint_t                  i, hash;
    njt_http_perl_var_t        *v;
    njt_http_variable_value_t  *vv;

    njt_http_perl_set_request(r, ctx);

    name = ST(1);

    if (SvROK(name) && SvTYPE(SvRV(name)) == SVt_PV) {
        name = SvRV(name);
    }

    if (items == 2) {
        value = NULL;

    } else {
        value = ST(2);

        if (SvROK(value) && SvTYPE(SvRV(value)) == SVt_PV) {
            value = SvRV(value);
        }

        if (njt_http_perl_sv2str(aTHX_ r, &val, value) != NJT_OK) {
            ctx->error = 1;
            croak("njt_http_perl_sv2str() failed");
        }
    }

    p = (u_char *) SvPV(name, len);

    lowcase = njt_pnalloc(r->pool, len);
    if (lowcase == NULL) {
        ctx->error = 1;
        croak("njt_pnalloc() failed");
    }

    hash = njt_hash_strlow(lowcase, p, len);

    var.len = len;
    var.data = lowcase;
#if (NJT_DEBUG)

    if (value) {
        njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "perl variable: \"%V\"=\"%V\"", &var, &val);
    } else {
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "perl variable: \"%V\"", &var);
    }
#endif

    vv = njt_http_get_variable(r, &var, hash);
    if (vv == NULL) {
        ctx->error = 1;
        croak("njt_http_get_variable() failed");
    }

    if (vv->not_found) {

        if (ctx->variables) {

            v = ctx->variables->elts;
            for (i = 0; i < ctx->variables->nelts; i++) {

                if (hash != v[i].hash
                    || len != v[i].name.len
                    || njt_strncmp(lowcase, v[i].name.data, len) != 0)
                {
                    continue;
                }

                if (value) {
                    v[i].value = val;
                    XSRETURN_UNDEF;
                }

                njt_http_perl_set_targ(v[i].value.data, v[i].value.len);

                goto done;
            }
        }

        if (value) {
            if (ctx->variables == NULL) {
                ctx->variables = njt_array_create(r->pool, 1,
                                                  sizeof(njt_http_perl_var_t));
                if (ctx->variables == NULL) {
                    ctx->error = 1;
                    croak("njt_array_create() failed");
                }
            }

            v = njt_array_push(ctx->variables);
            if (v == NULL) {
                ctx->error = 1;
                croak("njt_array_push() failed");
            }

            v->hash = hash;
            v->name.len = len;
            v->name.data = lowcase;
            v->value = val;

            XSRETURN_UNDEF;
        }

        XSRETURN_UNDEF;
    }

    if (value) {
        vv->len = val.len;
        vv->valid = 1;
        vv->no_cacheable = 0;
        vv->not_found = 0;
        vv->data = val.data;

        XSRETURN_UNDEF;
    }

    njt_http_perl_set_targ(vv->data, vv->len);

    done:

    ST(0) = TARG;


void
sleep(r, sleep, next)
    CODE:

    njt_http_request_t   *r;
    njt_http_perl_ctx_t  *ctx;
    njt_msec_t            sleep;

    njt_http_perl_set_request(r, ctx);

    if (ctx->variable) {
        croak("sleep(): cannot be used in variable handler");
    }

    if (ctx->next) {
        croak("sleep(): another handler active");
    }

    sleep = (njt_msec_t) SvIV(ST(1));

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "perl sleep: %M", sleep);

    ctx->next = SvRV(ST(2));

    r->connection->write->delayed = 1;
    njt_add_timer(r->connection->write, sleep);

    r->write_event_handler = njt_http_perl_sleep_handler;
    r->main->count++;


void
log_error(r, err, msg)
    CODE:

    njt_http_request_t   *r;
    njt_http_perl_ctx_t  *ctx;
    SV                   *err, *msg;
    u_char               *p;
    STRLEN                len;
    njt_err_t             e;

    njt_http_perl_set_request(r, ctx);

    err = ST(1);

    if (SvROK(err) && SvTYPE(SvRV(err)) == SVt_PV) {
        err = SvRV(err);
    }

    e = SvIV(err);

    msg = ST(2);

    if (SvROK(msg) && SvTYPE(SvRV(msg)) == SVt_PV) {
        msg = SvRV(msg);
    }

    p = (u_char *) SvPV(msg, len);

    njt_log_error(NJT_LOG_ERR, r->connection->log, e, "perl: %s", p);
