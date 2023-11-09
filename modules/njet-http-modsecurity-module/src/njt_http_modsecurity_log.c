/*
 * ModSecurity connector for njet, http://www.modsecurity.org/
 * Copyright (c) 2015 Trustwave Holdings, Inc. (http://www.trustwave.com/)
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * If any of the files related to licensing are missing or if you have any
 * other questions related to licensing please contact Trustwave Holdings, Inc.
 * directly using the email address security@modsecurity.org.
 *
 */

#ifndef MODSECURITY_DDEBUG
#define MODSECURITY_DDEBUG 0
#endif
#include "ddebug.h"

#include "njt_http_modsecurity_common.h"


void
njt_http_modsecurity_log(void *log, const void* data)
{
    const char *msg;
    if (log == NULL) {
        return;
    }
    msg = (const char *) data;

    njt_log_error(NJT_LOG_INFO, (njt_log_t *)log, 0, "%s", msg);
}


njt_int_t
njt_http_modsecurity_log_handler(njt_http_request_t *r)
{
    njt_pool_t                   *old_pool;
    njt_http_modsecurity_ctx_t   *ctx;
    njt_http_modsecurity_conf_t  *mcf;

    dd("catching a new _log_ phase handler");

    mcf = njt_http_get_module_loc_conf(r, njt_http_modsecurity_module);
    if (mcf == NULL || mcf->enable != 1)
    {
        dd("ModSecurity not enabled... returning");
        return NJT_OK;
    }

    /*
    if (r->method != NJT_HTTP_GET &&
        r->method != NJT_HTTP_POST && r->method != NJT_HTTP_HEAD) {
        dd("ModSecurity is not ready to deal with anything different from " \
            "POST, GET or HEAD");
        return NJT_OK;
    }
    */
    ctx = njt_http_get_module_ctx(r, njt_http_modsecurity_module);

    dd("recovering ctx: %p", ctx);

    if (ctx == NULL) {
        dd("something really bad happened here. returning NJT_ERROR");
        return NJT_ERROR;
    }

    if (ctx->logged) {
        dd("already logged earlier");
        return NJT_OK;
    }

    dd("calling msc_process_logging for %p", ctx);
    old_pool = njt_http_modsecurity_pcre_malloc_init(r->pool);
    msc_process_logging(ctx->modsec_transaction);
    njt_http_modsecurity_pcre_malloc_done(old_pool);

    return NJT_OK;
}
