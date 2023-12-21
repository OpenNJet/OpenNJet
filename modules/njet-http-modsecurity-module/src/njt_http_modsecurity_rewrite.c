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

njt_int_t
njt_http_modsecurity_rewrite_handler(njt_http_request_t *r)
{
    njt_pool_t                   *old_pool;
    njt_http_modsecurity_ctx_t   *ctx;
    njt_http_modsecurity_conf_t  *mcf;

    mcf = njt_http_get_module_loc_conf(r, njt_http_modsecurity_module);
    if (mcf == NULL || mcf->enable != 1) {
        dd("ModSecurity not enabled... returning");
        return NJT_DECLINED;
    }

    /*
    if (r->method != NJT_HTTP_GET &&
        r->method != NJT_HTTP_POST && r->method != NJT_HTTP_HEAD) {
        dd("ModSecurity is not ready to deal with anything different from " \
            "POST, GET or HEAD");
        return NJT_DECLINED;
    }
    */

    dd("catching a new _rewrite_ phase handler");

    ctx = njt_http_get_module_ctx(r, njt_http_modsecurity_module);

    dd("recovering ctx: %p", ctx);

    if (ctx == NULL)
    {
        int ret = 0;

        njt_connection_t *connection = r->connection;
        /**
         * FIXME: We may want to use struct sockaddr instead of addr_text.
         *
         */
        njt_str_t addr_text = connection->addr_text;

        ctx = njt_http_modsecurity_create_ctx(r);

        dd("ctx was NULL, creating new context: %p", ctx);

        if (ctx == NULL) {
            dd("ctx still null; Nothing we can do, returning an error.");
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        /**
         * FIXME: Check if it is possible to hook on njet on a earlier phase.
         *
         * At this point we are doing an late connection process. Maybe
         * we have to hook into NJT_HTTP_FIND_CONFIG_PHASE, it seems to be the
         * erliest phase that njet allow us to attach those kind of hooks.
         *
         */
        int client_port = njt_inet_get_port(connection->sockaddr);
        int server_port = njt_inet_get_port(connection->local_sockaddr);

        const char *client_addr = njt_str_to_char(addr_text, r->pool);
        if (client_addr == (char*)-1) {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        njt_str_t s;
        u_char addr[NJT_SOCKADDR_STRLEN];
        s.len = NJT_SOCKADDR_STRLEN;
        s.data = addr;
        if (njt_connection_local_sockaddr(r->connection, &s, 0) != NJT_OK) {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        const char *server_addr = njt_str_to_char(s, r->pool);
        if (server_addr == (char*)-1) {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        old_pool = njt_http_modsecurity_pcre_malloc_init(r->pool);
        ret = msc_process_connection(ctx->modsec_transaction,
            client_addr, client_port,
            server_addr, server_port);
        njt_http_modsecurity_pcre_malloc_done(old_pool);
        if (ret != 1){
            dd("Was not able to extract connection information.");
        }
        /**
         *
         * FIXME: Check how we can finalize a request without crash njet.
         *
         * I don't think njet is expecting to finalize a request at that
         * point as it seems that it clean the njt_http_request_t information
         * and try to use it later.
         *
         */
        dd("Processing intervention with the connection information filled in");
        ret = njt_http_modsecurity_process_intervention(ctx->modsec_transaction, r, 1);
        if (ret > 0) {
            ctx->intervention_triggered = 1;
            return ret;
        }

        const char *http_version;
        switch (r->http_version) {
            case NJT_HTTP_VERSION_9 :
                http_version = "0.9";
                break;
            case NJT_HTTP_VERSION_10 :
                http_version = "1.0";
                break;
            case NJT_HTTP_VERSION_11 :
                http_version = "1.1";
                break;
#if defined(njet_version) && njet_version >= 1009005
            case NJT_HTTP_VERSION_20 :
                http_version = "2.0";
                break;
#endif
            default :
                http_version = njt_str_to_char(r->http_protocol, r->pool);
                if (http_version == (char*)-1) {
                    return NJT_HTTP_INTERNAL_SERVER_ERROR;
                }
                if ((http_version != NULL) && (strlen(http_version) > 5) && (!strncmp("HTTP/", http_version, 5))) {
                    http_version += 5;
                } else {
                    http_version = "1.0";
                }
                break;
        }

        const char *n_uri = njt_str_to_char(r->unparsed_uri, r->pool);
        const char *n_method = njt_str_to_char(r->method_name, r->pool);
        if (n_uri == (char*)-1 || n_method == (char*)-1) {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }
        if (n_uri == NULL) {
            dd("uri is of length zero");
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }
        old_pool = njt_http_modsecurity_pcre_malloc_init(r->pool);
        msc_process_uri(ctx->modsec_transaction, n_uri, n_method, http_version);
        njt_http_modsecurity_pcre_malloc_done(old_pool);

        dd("Processing intervention with the transaction information filled in (uri, method and version)");
        ret = njt_http_modsecurity_process_intervention(ctx->modsec_transaction, r, 1);
        if (ret > 0) {
            ctx->intervention_triggered = 1;
            return ret;
        }

        /**
         * Since incoming request headers are already in place, lets send it to ModSecurity
         *
         */
        njt_list_part_t *part = &r->headers_in.headers.part;
        njt_table_elt_t *data = part->elts;
        njt_uint_t i = 0;
        for (i = 0 ; /* void */ ; i++) {
            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                data = part->elts;
                i = 0;
            }

            /**
             * By using u_char (utf8_t) I believe njet is hoping to deal
             * with utf8 strings.
             * Casting those into to unsigned char * in order to pass
             * it to ModSecurity, it will handle with those later.
             *
             */

            dd("Adding request header: %.*s with value %.*s", (int)data[i].key.len, data[i].key.data, (int) data[i].value.len, data[i].value.data);
            msc_add_n_request_header(ctx->modsec_transaction,
                (const unsigned char *) data[i].key.data,
                data[i].key.len,
                (const unsigned char *) data[i].value.data,
                data[i].value.len);
        }

        /**
         * Since ModSecurity already knew about all headers, i guess it is safe
         * to process this information.
         */

        old_pool = njt_http_modsecurity_pcre_malloc_init(r->pool);
        msc_process_request_headers(ctx->modsec_transaction);
        njt_http_modsecurity_pcre_malloc_done(old_pool);
        dd("Processing intervention with the request headers information filled in");
        ret = njt_http_modsecurity_process_intervention(ctx->modsec_transaction, r, 1);
        if (r->error_page) {
            return NJT_DECLINED;
            }
        if (ret > 0) {
            ctx->intervention_triggered = 1;
            return ret;
        }
    }


    return NJT_DECLINED;
}
