#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_http_set_misc_module.h"
#include <ndk.h>
#include "njt_http_set_base32.h"
#include "njt_http_set_default_value.h"
#include "njt_http_set_hashed_upstream.h"
#include "njt_http_set_unescape_uri.h"
#include "njt_http_set_quote_sql.h"
#include "njt_http_set_quote_json.h"
#include "njt_http_set_escape_uri.h"
#include "njt_http_set_local_today.h"
#include "njt_http_set_hash.h"
#include "njt_http_set_hex.h"
#include "njt_http_set_base64.h"
#include "njt_http_set_base64url.h"
#if NJT_OPENSSL
#include "njt_http_set_hmac.h"
#endif
#include "njt_http_set_random.h"
#include "njt_http_set_secure_random.h"
#include "njt_http_set_rotate.h"


#define NJT_UNESCAPE_URI_COMPONENT  0
#define BASE32_ALPHABET_LEN         32


static void *njt_http_set_misc_create_loc_conf(njt_conf_t *cf);
static char *njt_http_set_misc_merge_loc_conf(njt_conf_t *cf, void *parent,
    void *child);
static char *njt_http_set_misc_base32_alphabet(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);


static njt_conf_deprecated_t  njt_conf_deprecated_set_misc_base32_padding = {
    njt_conf_deprecated, "set_misc_base32_padding", "set_base32_padding"
};


static ndk_set_var_t  njt_http_set_misc_set_encode_base64_filter = {
    NDK_SET_VAR_VALUE,
    (void *) njt_http_set_misc_set_encode_base64,
    1,
    NULL
};


static ndk_set_var_t  njt_http_set_misc_set_decode_base64_filter = {
    NDK_SET_VAR_VALUE,
    (void *) njt_http_set_misc_set_decode_base64,
    1,
    NULL
};


static ndk_set_var_t  njt_http_set_misc_set_encode_base64url_filter = {
    NDK_SET_VAR_VALUE,
    (void *) njt_http_set_misc_set_encode_base64url,
    1,
    NULL
};


static ndk_set_var_t  njt_http_set_misc_set_decode_base64url_filter = {
    NDK_SET_VAR_VALUE,
    (void *) njt_http_set_misc_set_decode_base64url,
    1,
    NULL
};


static ndk_set_var_t  njt_http_set_misc_set_decode_hex_filter = {
    NDK_SET_VAR_VALUE,
    (void *) njt_http_set_misc_set_decode_hex,
    1,
    NULL
};


static ndk_set_var_t  njt_http_set_misc_set_encode_hex_filter = {
    NDK_SET_VAR_VALUE,
    (void *) njt_http_set_misc_set_encode_hex,
    1,
    NULL
};


#if NJT_OPENSSL
static ndk_set_var_t  njt_http_set_misc_set_hmac_sha1_filter = {
    NDK_SET_VAR_MULTI_VALUE,
    (void *) njt_http_set_misc_set_hmac_sha1,
    2,
    NULL
};


static ndk_set_var_t  njt_http_set_misc_set_hmac_sha256_filter = {
    NDK_SET_VAR_MULTI_VALUE,
    (void *) njt_http_set_misc_set_hmac_sha256,
    2,
    NULL
};
#endif


#ifndef NJT_HTTP_SET_HASH
static ndk_set_var_t  njt_http_set_misc_set_md5_filter = {
    NDK_SET_VAR_VALUE,
    (void *) njt_http_set_misc_set_md5,
    1,
    NULL
};


#if NJT_HAVE_SHA1
static ndk_set_var_t  njt_http_set_misc_set_sha1_filter = {
    NDK_SET_VAR_VALUE,
    (void *) njt_http_set_misc_set_sha1,
    1,
    NULL
};
#endif
#endif


static ndk_set_var_t  njt_http_set_misc_unescape_uri_filter = {
    NDK_SET_VAR_VALUE,
    (void *) njt_http_set_misc_unescape_uri,
    1,
    NULL
};


static ndk_set_var_t njt_http_set_misc_escape_uri_filter = {
    NDK_SET_VAR_VALUE,
    (void *) njt_http_set_misc_escape_uri,
    1,
    NULL
};


static ndk_set_var_t  njt_http_set_misc_decode_base32_filter = {
    NDK_SET_VAR_VALUE,
    (void *) njt_http_set_misc_decode_base32,
    1,
    NULL
};


static ndk_set_var_t  njt_http_set_misc_quote_sql_str_filter = {
    NDK_SET_VAR_VALUE,
    (void *) njt_http_set_misc_quote_sql_str,
    1,
    NULL
};


static ndk_set_var_t  njt_http_set_misc_quote_pgsql_str_filter = {
    NDK_SET_VAR_VALUE,
    (void *) njt_http_set_misc_quote_pgsql_str,
    1,
    NULL
};


static ndk_set_var_t  njt_http_set_misc_quote_json_str_filter = {
    NDK_SET_VAR_VALUE,
    (void *) njt_http_set_misc_quote_json_str,
    1,
    NULL
};


static ndk_set_var_t  njt_http_set_misc_encode_base32_filter = {
    NDK_SET_VAR_VALUE,
    (void *) njt_http_set_misc_encode_base32,
    1,
    NULL
};


static ndk_set_var_t njt_http_set_misc_local_today_filter = {
    NDK_SET_VAR_VALUE,
    (void *) njt_http_set_local_today,
    0,
    NULL
};


static ndk_set_var_t njt_http_set_misc_formatted_gmt_time_filter = {
    NDK_SET_VAR_VALUE,
    (void *) njt_http_set_formatted_gmt_time,
    2,
    NULL
};


static ndk_set_var_t njt_http_set_misc_formatted_local_time_filter = {
    NDK_SET_VAR_VALUE,
    (void *) njt_http_set_formatted_local_time,
    2,
    NULL
};


static ndk_set_var_t  njt_http_set_misc_set_random_filter = {
    NDK_SET_VAR_MULTI_VALUE,
    (void *) njt_http_set_misc_set_random,
    2,
    NULL
};


static ndk_set_var_t  njt_http_set_misc_set_secure_random_alphanum_filter = {
    NDK_SET_VAR_VALUE,
    (void *) njt_http_set_misc_set_secure_random_alphanum,
    1,
    NULL
};


static ndk_set_var_t  njt_http_set_misc_set_secure_random_lcalpha_filter = {
    NDK_SET_VAR_VALUE,
    (void *) njt_http_set_misc_set_secure_random_lcalpha,
    1,
    NULL
};


static njt_command_t  njt_http_set_misc_commands[] = {
    {   njt_string ("set_encode_base64"),
        NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF
            |NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE12,
        ndk_set_var_value,
        0,
        0,
        &njt_http_set_misc_set_encode_base64_filter
    },
    {   njt_string ("set_decode_base64"),
        NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF
            |NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE12,
        ndk_set_var_value,
        0,
        0,
        &njt_http_set_misc_set_decode_base64_filter
    },
    {   njt_string ("set_encode_base64url"),
        NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF
            |NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE12,
        ndk_set_var_value,
        0,
        0,
        &njt_http_set_misc_set_encode_base64url_filter
    },
    {   njt_string ("set_decode_base64url"),
        NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF
            |NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE12,
        ndk_set_var_value,
        0,
        0,
        &njt_http_set_misc_set_decode_base64url_filter
    },
    {   njt_string ("set_decode_hex"),
        NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF
            |NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE12,
        ndk_set_var_value,
        0,
        0,
        &njt_http_set_misc_set_decode_hex_filter
    },
    {   njt_string ("set_encode_hex"),
        NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF
            |NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE12,
        ndk_set_var_value,
        0,
        0,
        &njt_http_set_misc_set_encode_hex_filter
    },
#if NJT_OPENSSL
    {   njt_string ("set_hmac_sha1"),
        NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF
            |NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE3,
        ndk_set_var_multi_value,
        0,
        0,
        &njt_http_set_misc_set_hmac_sha1_filter
    },
    {   njt_string ("set_hmac_sha256"),
        NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF
            |NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE3,
        ndk_set_var_multi_value,
        0,
        0,
        &njt_http_set_misc_set_hmac_sha256_filter
    },
#endif
#ifndef NJT_HTTP_SET_HASH
    {   njt_string ("set_md5"),
        NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF
            |NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE12,
        ndk_set_var_value,
        0,
        0,
        &njt_http_set_misc_set_md5_filter
    },
#if NJT_HAVE_SHA1
    {
        njt_string ("set_sha1"),
        NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF
            |NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE12,
        ndk_set_var_value,
        0,
        0,
        &njt_http_set_misc_set_sha1_filter
    },
#endif
#endif
    {
        njt_string ("set_unescape_uri"),
        NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF
            |NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE12,
        ndk_set_var_value,
        0,
        0,
        &njt_http_set_misc_unescape_uri_filter
    },
    {
        njt_string ("set_escape_uri"),
        NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF
            |NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE12,
        ndk_set_var_value,
        0,
        0,
        &njt_http_set_misc_escape_uri_filter
    },
    {
        njt_string ("set_quote_sql_str"),
        NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF
            |NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE12,
        ndk_set_var_value,
        0,
        0,
        &njt_http_set_misc_quote_sql_str_filter
    },
    {
        njt_string ("set_quote_pgsql_str"),
        NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF
            |NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE12,
        ndk_set_var_value,
        0,
        0,
        &njt_http_set_misc_quote_pgsql_str_filter
    },
    {
        njt_string ("set_quote_json_str"),
        NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF
            |NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE12,
        ndk_set_var_value,
        0,
        0,
        &njt_http_set_misc_quote_json_str_filter
    },
    {
        njt_string ("set_if_empty"),
        NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF
            |NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE2,
        njt_http_set_if_empty,
        0,
        0,
        NULL
    },
    {
        njt_string("set_hashed_upstream"),
        NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF
            |NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE3,
        njt_http_set_hashed_upstream,
        0,
        0,
        NULL
    },
    {
        /* this is now deprecated; use set_base32_padding instead */
        njt_string("set_misc_base32_padding"),
        NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF
                          |NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_FLAG,
        njt_conf_set_flag_slot,
        NJT_HTTP_LOC_CONF_OFFSET,
        offsetof(njt_http_set_misc_loc_conf_t, base32_padding),
        &njt_conf_deprecated_set_misc_base32_padding,
    },
    {
        njt_string("set_base32_padding"),
        NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF
                          |NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_FLAG,
        njt_conf_set_flag_slot,
        NJT_HTTP_LOC_CONF_OFFSET,
        offsetof(njt_http_set_misc_loc_conf_t, base32_padding),
        NULL
    },
    {
        njt_string("set_base32_alphabet"),
        NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF
            |NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE1,
        njt_http_set_misc_base32_alphabet,
        NJT_HTTP_LOC_CONF_OFFSET,
        offsetof(njt_http_set_misc_loc_conf_t, base32_alphabet),
        NULL
    },
    {
        njt_string("set_encode_base32"),
        NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF
            |NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE12,
        ndk_set_var_value,
        0,
        0,
        &njt_http_set_misc_encode_base32_filter
    },
    {
        njt_string("set_decode_base32"),
        NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF
            |NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE12,
        ndk_set_var_value,
        0,
        0,
        &njt_http_set_misc_decode_base32_filter
    },
    {
        njt_string("set_local_today"),
        NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF
            |NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE1,
        ndk_set_var_value,
        0,
        0,
        &njt_http_set_misc_local_today_filter
    },
    {
        njt_string("set_formatted_gmt_time"),
        NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF
            |NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE2,
        ndk_set_var_value,
        0,
        0,
        &njt_http_set_misc_formatted_gmt_time_filter
    },
    {
        njt_string("set_formatted_local_time"),
        NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF
            |NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE2,
        ndk_set_var_value,
        0,
        0,
        &njt_http_set_misc_formatted_local_time_filter
    },
    {   njt_string ("set_random"),
        NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF
            |NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE3,
        ndk_set_var_multi_value,
        0,
        0,
        &njt_http_set_misc_set_random_filter
    },
    {   njt_string ("set_secure_random_alphanum"),
        NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF
            |NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE12,
        ndk_set_var_value,
        0,
        0,
        &njt_http_set_misc_set_secure_random_alphanum_filter
    },
    {   njt_string ("set_secure_random_lcalpha"),
        NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF
            |NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE12,
        ndk_set_var_value,
        0,
        0,
        &njt_http_set_misc_set_secure_random_lcalpha_filter
    },
    {   njt_string ("set_rotate"),
        NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF
            |NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE3,
        njt_http_set_rotate,
        0,
        0,
        NULL
    },

    njt_null_command
};


static njt_http_module_t  njt_http_set_misc_module_ctx = {
    NULL,                                 /* preconfiguration */
    NULL,                                 /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_set_misc_create_loc_conf,     /* create location configuration */
    njt_http_set_misc_merge_loc_conf       /*  merge location configuration */
};


njt_module_t  njt_http_set_misc_module = {
    NJT_MODULE_V1,
    &njt_http_set_misc_module_ctx,          /* module context */
    njt_http_set_misc_commands,             /* module directives */
    NJT_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NJT_MODULE_V1_PADDING
};


void *
njt_http_set_misc_create_loc_conf(njt_conf_t *cf)
{
    njt_http_set_misc_loc_conf_t *conf;

    conf = njt_palloc(cf->pool, sizeof(njt_http_set_misc_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->base32_padding = NJT_CONF_UNSET;
    conf->base32_alphabet.data = NULL;
    conf->base32_alphabet.len = 0;
    conf->current = NJT_CONF_UNSET;

    return conf;
}


char *
njt_http_set_misc_merge_loc_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_uint_t               i;

    njt_http_set_misc_loc_conf_t *prev = parent;
    njt_http_set_misc_loc_conf_t *conf = child;

    njt_conf_merge_value(conf->base32_padding, prev->base32_padding, 1);

    njt_conf_merge_str_value(conf->base32_alphabet, prev->base32_alphabet,
                             "0123456789abcdefghijklmnopqrstuv");

    njt_conf_merge_value(conf->current, prev->current, NJT_CONF_UNSET);

    for (i = 0; i < BASE32_ALPHABET_LEN; i++) {
        conf->basis32[conf->base32_alphabet.data[i]] = (u_char) i;
    }

    return NJT_CONF_OK;
}


static char *
njt_http_set_misc_base32_alphabet(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    njt_str_t       *value;

    value = cf->args->elts;

    if (value[1].len != BASE32_ALPHABET_LEN) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "\"set_base32_alphabet\" directive takes an "
                           "alphabet of %uz bytes but %d expected",
                           value[1].len, BASE32_ALPHABET_LEN);
        return NJT_CONF_ERROR;
    }

    return njt_conf_set_str_slot(cf, cmd, conf);
}
