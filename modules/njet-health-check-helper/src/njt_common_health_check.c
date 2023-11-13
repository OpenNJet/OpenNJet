/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_config.h>
#include <njt_core.h>
#include <njet.h>
#include <njt_event.h>
// #include <njt_json_api.h>
// #include <njt_json_util.h>
#include <njt_http.h>
#include <njt_stream.h>   /* by zhaokang */

#include "njt_common_health_check.h"

// /**
//  * 它接受一个字符串，将其解析为时间，并将结果存储在 njt_msec_t 变量中
//  *
//  * @param el 要解析的 json 元素
//  * @param def 字段的定义。
//  * @param data 指向数据结构的指针
//  *
//  * @return 返回值是解析的状态。
//  */
// njt_int_t njt_json_parse_msec(njt_json_element *el, void *data){
//     njt_int_t tmp;
//     njt_msec_t *target = data ;
//     tmp = njt_parse_time(&el->strval, 0);
//     if(tmp == NJT_ERROR){
//         return NJT_ERROR;
//     }
//     target= data;
//     *target = tmp;
//     return NJT_OK;
// }


#if (NJT_OPENSSL)
static njt_conf_bitmask_t  njt_http_ssl_protocols[] = {
        { njt_string("SSLv2"), NJT_SSL_SSLv2 },
        { njt_string("SSLv3"), NJT_SSL_SSLv3 },
        { njt_string("TLSv1"), NJT_SSL_TLSv1 },
        { njt_string("TLSv1.1"), NJT_SSL_TLSv1_1 },
        { njt_string("TLSv1.2"), NJT_SSL_TLSv1_2 },
        { njt_string("TLSv1.3"), NJT_SSL_TLSv1_3 },
        { njt_null_string, 0 }
};

njt_int_t njt_json_parse_ssl_protocols(njt_str_t value, njt_uint_t *np)
{
    njt_uint_t          i, m;
    njt_conf_bitmask_t  *mask;

    mask = njt_http_ssl_protocols;

    for (i = 0; i < value.len; i++) {
        for (m = 0; mask[m].name.len != 0; m++) {

            if (mask[m].name.len <= value.len-i
                || njt_strncmp(mask[m].name.data, value.data+i,mask[m].name.len) != 0)
            {
                continue;
            }

//            if (*np & mask[m].mask) {
//                return NJT_ERROR;
//            } else {
                *np |= mask[m].mask;
//            }
            break;
        }

        if (mask[m].name.len == 0) {
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}
#endif

#if (NJT_OPENSSL)

njt_int_t njt_helper_hc_set_ssl(njt_helper_health_check_conf_t *hhccf, njt_helper_hc_ssl_conf_t *hcscf)
{
    njt_pool_cleanup_t  *cln;

    njt_conf_t cf;
    cf.pool = hhccf->pool;
    cf.log = hhccf->log;
    cf.cycle = (njt_cycle_t *)njt_cycle;

    if (hcscf->ssl->ctx) {
        return NJT_OK;
    }

    if (njt_ssl_create(hcscf->ssl, hcscf->ssl_protocols, NULL)
        != NJT_OK)
    {
        return NJT_ERROR;
    }
#if (NJT_HAVE_NTLS)
    if (1 == hhccf->ssl.ntls_enable) {
        SSL_CTX_set_ssl_version(hcscf->ssl->ctx,NTLS_method());
        SSL_CTX_set_cipher_list(hcscf->ssl->ctx,(const char *)hhccf->ssl.ssl_ciphers.data);
        SSL_CTX_enable_ntls(hcscf->ssl->ctx);
    }
#endif

    cln = njt_pool_cleanup_add(cf.pool, 0);
    if (cln == NULL) {
        njt_ssl_cleanup_ctx(hcscf->ssl);
        return NJT_ERROR;
    }

    cln->handler = njt_ssl_cleanup_ctx;
    cln->data = hcscf->ssl;
    if (njt_ssl_ciphers(&cf, hcscf->ssl, &hcscf->ssl_ciphers, 0)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    if (hcscf->ssl_certificate.len > 0 )
    {
        if (hcscf->ssl_certificate_key.len <= 0) {
            njt_log_error(NJT_LOG_EMERG, cf.log, 0,
                          "no \"proxy_ssl_certificate_key\" is defined "
                          "for certificate \"%V\"",
                          &hcscf->ssl_certificate);
            return NJT_ERROR;
        }

//仅使用pool
        if (njt_ssl_certificate(&cf, hcscf->ssl,&hcscf->ssl_certificate,
                                &hcscf->ssl_certificate_key,hcscf->ssl_passwords)
            != NJT_OK)
        {
            return NJT_ERROR;
        }

        if (njt_ssl_certificate(&cf, hcscf->ssl,&hcscf->ssl_enc_certificate,
                                &hcscf->ssl_enc_certificate_key,hcscf->ssl_passwords)
            != NJT_OK)
        {
            return NJT_ERROR;
        }

    }

    if (hcscf->ssl_verify) {
        if (hcscf->ssl_trusted_certificate.len == 0) {
            njt_log_error(NJT_LOG_EMERG, cf.log, 0,"no proxy_ssl_trusted_certificate for proxy_ssl_verify");
            return NJT_ERROR;
        }

        if (njt_ssl_trusted_certificate(&cf, hcscf->ssl,
                                        &hcscf->ssl_trusted_certificate,
                                        hcscf->ssl_verify_depth)
            != NJT_OK)
        {
            return NJT_ERROR;
        }

        if (njt_ssl_crl(&cf, hcscf->ssl, &hcscf->ssl_crl) != NJT_OK) {
            return NJT_ERROR;
        }
    }

    if (njt_ssl_client_session_cache(NULL, hcscf->ssl,
                                     hcscf->ssl_session_reuse)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    if (njt_ssl_conf_commands(&cf, hcscf->ssl, hcscf->ssl_conf_commands)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    return NJT_OK;
}
#endif




/**
 * > 按名称查找upstream配置
 *
 * @param cycle 当前cycle。
 * @param name upstream的名称。
 *
 * @return njt_http_upstream_srv_conf_t
 */
njt_http_upstream_srv_conf_t* njt_http_find_upstream_by_name(njt_cycle_t *cycle,njt_str_t *name){
    njt_http_upstream_main_conf_t  *umcf;
    njt_http_upstream_srv_conf_t   **uscfp;
    njt_uint_t i;

    umcf = njt_http_cycle_get_module_main_conf(cycle, njt_http_upstream_module);
    if(umcf == NULL){
        return NULL;
    }

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {
        if (uscfp[i]->host.len != name->len
            || njt_strncasecmp(uscfp[i]->host.data, name->data, name->len) != 0 || uscfp[i]->srv_conf == NULL ) {
            continue;
        }
        return uscfp[i];
    }
    return NULL;
}

// by zhaokang
njt_stream_upstream_srv_conf_t *njt_stream_find_upstream_by_name(njt_cycle_t *cycle, njt_str_t *name) {
    njt_stream_upstream_srv_conf_t   **uscfp;
    njt_stream_upstream_main_conf_t   *umcf;
    njt_uint_t                         i;

    umcf = njt_stream_cycle_get_module_main_conf(njet_master_cycle, njt_stream_upstream_module);

    if(umcf == NULL){
        return NULL;
    }

    uscfp = umcf->upstreams.elts;
    for (i = 0; i < umcf->upstreams.nelts; i++) {
        if (uscfp[i]->host.len != name->len
                || njt_strncasecmp(uscfp[i]->host.data, name->data, name->len) != 0) {
            
            continue;
        }

        return uscfp[i];
    }

    return NULL;
}


void njt_http_upstream_traver(void *ctx,njt_int_t (*item_handle)(void *ctx,njt_http_upstream_srv_conf_t *)){
    njt_http_upstream_main_conf_t  *umcf;
    njt_http_upstream_srv_conf_t   **uscfp;
    njt_uint_t i;

    if(!item_handle) {
        return;
    }
    umcf = njt_http_cycle_get_module_main_conf(njet_master_cycle, njt_http_upstream_module);

    if(NULL == umcf){
        return;
    }
    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {
        if(0 != item_handle(ctx,uscfp[i])){
            break;
        }
    }
}


void njt_stream_upstream_traver(void *ctx,njt_int_t (*item_handle)(void *ctx,njt_stream_upstream_srv_conf_t *)){

    njt_stream_upstream_srv_conf_t   **uscfp;
    njt_stream_upstream_main_conf_t   *umcf;
    njt_uint_t                         i;

    if(!item_handle) {
        return;
    }
    umcf = njt_stream_cycle_get_module_main_conf(njet_master_cycle, njt_stream_upstream_module);

    if(NULL == umcf){
        return;
    }
    uscfp = umcf->upstreams.elts;
    for (i = 0; i < umcf->upstreams.nelts; i++) {
        if(0 != item_handle(ctx,uscfp[i])){
            break;
        }
    }
}

/* Convert "hello\xae\x00" hex string to binary, no more than COUNT bytes */
char* njt_hex2bin(njt_str_t *d, njt_str_t *s, int count)
{
    int hex = 0;
    const char *str = (char *)s->data;
    const char * end = (char *)(s->data+s->len);
    char *dst = (char *)d->data;
    //
    while (str<end && count>0) {
        if(0==hex && str[0]=='\\' && (str+1)<end && (str[1] | 0x20) == 'x'){
            hex = 1;
            str+=2;
            continue;
        }

        if(0==hex && str[0]=='\\' && (str+1)<end && str[1]  == '\\'){
            str+=2;
            *dst++ = '\\';
            continue;
        }
        if(0==hex){
            *dst++ = *str++;
            count--;
            continue;
        }
        unsigned char val;
        unsigned char c = *str++;
        if (isdigit(c))
            val = c - '0';
        else if ((c|0x20) >= 'a' && (c|0x20) <= 'f')
            val = (c|0x20) - ('a' - 10);
        else
            return NULL;
        if(str==end){
            *dst++ = val;
            count--;
            hex = 0;
            continue;
        }
        val <<= 4;
        c = *str;
        if (isdigit(c)) {
            val |= c - '0';
            str++;
        }
        else if ((c|0x20) >= 'a' && (c|0x20) <= 'f'){
            val |= (c|0x20) - ('a' - 10);
            str++;
        }
        else {
            val >>= 4;
        }

        *dst++ = val;
        count--;
        hex = 0;
    }
    return dst;
}