#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"

#include "njt_http_redis2_module.h"
#include "njt_http_redis2_handler.h"
#include "njt_http_redis2_util.h"


static void *njt_http_redis2_create_loc_conf(njt_conf_t *cf);
static char *njt_http_redis2_merge_loc_conf(njt_conf_t *cf,
        void *parent, void *child);
static char *njt_http_redis2_raw_queries(njt_conf_t *cf, njt_command_t *cmd,
        void *conf);
static char *njt_http_redis2_query(njt_conf_t *cf, njt_command_t *cmd,
        void *conf);
static char *njt_http_redis2_pass(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);


static njt_conf_bitmask_t  njt_http_redis2_next_upstream_masks[] = {
    { njt_string("error"), NJT_HTTP_UPSTREAM_FT_ERROR },
    { njt_string("timeout"), NJT_HTTP_UPSTREAM_FT_TIMEOUT },
    { njt_string("invalid_response"), NJT_HTTP_UPSTREAM_FT_INVALID_HEADER },
    { njt_string("not_found"), NJT_HTTP_UPSTREAM_FT_HTTP_404 },
    { njt_string("off"), NJT_HTTP_UPSTREAM_FT_OFF },
    { njt_null_string, 0 }
};


static njt_command_t  njt_http_redis2_commands[] = {

    { njt_string("redis2_query"),
      NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_1MORE,
      njt_http_redis2_query,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("redis2_raw_query"),
      NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE1,
      njt_http_redis2_set_complex_value_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_redis2_loc_conf_t, complex_query),
      NULL },

    { njt_string("redis2_raw_queries"),
      NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE2,
      njt_http_redis2_raw_queries,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("redis2_literal_raw_query"),
      NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_redis2_loc_conf_t, literal_query),
      NULL },


    { njt_string("redis2_pass"),
      NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE1,
      njt_http_redis2_pass,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("redis2_bind"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_upstream_bind_set_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_redis2_loc_conf_t, upstream.local),
      NULL },

    { njt_string("redis2_connect_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_redis2_loc_conf_t, upstream.connect_timeout),
      NULL },

    { njt_string("redis2_send_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_redis2_loc_conf_t, upstream.send_timeout),
      NULL },

    { njt_string("redis2_buffer_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_redis2_loc_conf_t, upstream.buffer_size),
      NULL },

    { njt_string("redis2_read_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_redis2_loc_conf_t, upstream.read_timeout),
      NULL },

    { njt_string("redis2_next_upstream"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_conf_set_bitmask_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_redis2_loc_conf_t, upstream.next_upstream),
      &njt_http_redis2_next_upstream_masks },

      njt_null_command
};


static njt_http_module_t  njt_http_redis2_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_redis2_create_loc_conf,    /* create location configration */
    njt_http_redis2_merge_loc_conf      /* merge location configration */
};


njt_module_t  njt_http_redis2_module = {
    NJT_MODULE_V1,
    &njt_http_redis2_module_ctx,        /* module context */
    njt_http_redis2_commands,           /* module directives */
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


static void *
njt_http_redis2_create_loc_conf(njt_conf_t *cf)
{
    njt_http_redis2_loc_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_redis2_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     conf->upstream.bufs.num = 0;
     *     conf->upstream.next_upstream = 0;
     *     conf->upstream.temp_path = NULL;
     *     conf->upstream.uri = { 0, NULL };
     *     conf->upstream.location = NULL;
     *     conf->complex_query = NULL;
     *     conf->literal_query = { 0, NULL };
     *     conf->queries = NULL;
     */

    conf->upstream.connect_timeout = NJT_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NJT_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NJT_CONF_UNSET_MSEC;

    conf->upstream.buffer_size = NJT_CONF_UNSET_SIZE;

    /* the hardcoded values */
    conf->upstream.cyclic_temp_file = 0;
    conf->upstream.buffering = 0;
    conf->upstream.ignore_client_abort = 1;
    conf->upstream.send_lowat = 0;
    conf->upstream.bufs.num = 0;
    conf->upstream.busy_buffers_size = 0;
    conf->upstream.max_temp_file_size = 0;
    conf->upstream.temp_file_write_size = 0;
    conf->upstream.intercept_errors = 1;
    conf->upstream.intercept_404 = 1;
    conf->upstream.pass_request_headers = 0;
    conf->upstream.pass_request_body = 0;

    return conf;
}


static char *
njt_http_redis2_merge_loc_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_redis2_loc_conf_t *prev = parent;
    njt_http_redis2_loc_conf_t *conf = child;

    njt_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    njt_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    njt_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    njt_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) njt_pagesize);

    njt_conf_merge_bitmask_value(conf->upstream.next_upstream,
                                 prev->upstream.next_upstream,
                                 (NJT_CONF_BITMASK_SET
                                  |NJT_HTTP_UPSTREAM_FT_ERROR
                                  |NJT_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & NJT_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = NJT_CONF_BITMASK_SET
                                       |NJT_HTTP_UPSTREAM_FT_OFF;
    }

    if (conf->upstream.upstream == NULL) {
        conf->upstream.upstream = prev->upstream.upstream;
    }

    if (conf->complex_query == NULL) {
        conf->complex_query = prev->complex_query;
    }

    if (conf->complex_query_count == NULL) {
        conf->complex_query_count = prev->complex_query_count;
    }

    if (conf->queries == NULL) {
        conf->queries = prev->queries;
    }

    if (conf->literal_query.data == NULL) {
        conf->literal_query.data = prev->literal_query.data;
        conf->literal_query.len = prev->literal_query.len;
    }

    return NJT_CONF_OK;
}


static char *
njt_http_redis2_pass(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_redis2_loc_conf_t *rlcf = conf;

    njt_str_t                  *value;
    njt_http_core_loc_conf_t   *clcf;
    njt_uint_t                  n;
    njt_url_t                   url;

    njt_http_compile_complex_value_t         ccv;

    if (rlcf->upstream.upstream) {
        return "is duplicate";
    }

    clcf = njt_http_conf_get_module_loc_conf(cf, njt_http_core_module);

    clcf->handler = njt_http_redis2_handler;

    if (clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }

    value = cf->args->elts;

    n = njt_http_script_variables_count(&value[1]);
    if (n) {
        rlcf->complex_target = njt_palloc(cf->pool,
                                          sizeof(njt_http_complex_value_t));

        if (rlcf->complex_target == NULL) {
            return NJT_CONF_ERROR;
        }

        njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));
        ccv.cf = cf;
        ccv.value = &value[1];
        ccv.complex_value = rlcf->complex_target;

        if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
            return NJT_CONF_ERROR;
        }

        return NJT_CONF_OK;
    }

    rlcf->complex_target = NULL;

    njt_memzero(&url, sizeof(njt_url_t));

    url.url = value[1];
    url.no_resolve = 1;

    rlcf->upstream.upstream = njt_http_upstream_add(cf, &url, 0);
    if (rlcf->upstream.upstream == NULL) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


static char *
njt_http_redis2_query(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_redis2_loc_conf_t  *rlcf = conf;
    njt_str_t                   *value;
    njt_array_t                **query;
    njt_uint_t                   n;
    njt_http_complex_value_t   **arg;
    njt_uint_t                   i;

    njt_http_compile_complex_value_t         ccv;

    if (rlcf->literal_query.len) {
        return "conflicts with redis2_literal_raw_query";
    }

    if (rlcf->complex_query) {
        return "conflicts with redis2_raw_query";
    }

    if (rlcf->queries == NULL) {
        rlcf->queries = njt_array_create(cf->pool, 1, sizeof(njt_array_t *));

        if (rlcf->queries == NULL) {
            return NJT_CONF_ERROR;
        }
    }

    query = njt_array_push(rlcf->queries);
    if (query == NULL) {
        return NJT_CONF_ERROR;
    }

    n = cf->args->nelts - 1;

    *query = njt_array_create(cf->pool, n, sizeof(njt_http_complex_value_t *));

    if (*query == NULL) {
        return NJT_CONF_ERROR;
    }

    value = cf->args->elts;

    for (i = 1; i <= n; i++) {
        arg = njt_array_push(*query);
        if (arg == NULL) {
            return NJT_CONF_ERROR;
        }

        *arg = njt_palloc(cf->pool, sizeof(njt_http_complex_value_t));
        if (*arg == NULL) {
            return NJT_CONF_ERROR;
        }

        if (value[i].len == 0) {
            njt_memzero(*arg, sizeof(njt_http_complex_value_t));
            continue;
        }

        njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));
        ccv.cf = cf;
        ccv.value = &value[i];
        ccv.complex_value = *arg;

        if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
            return NJT_CONF_ERROR;
        }
    }

    return NJT_CONF_OK;
}


static char *
njt_http_redis2_raw_queries(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_redis2_loc_conf_t  *rlcf = conf;
    njt_str_t                   *value;

    njt_http_compile_complex_value_t         ccv;

    value = cf->args->elts;

    /* compile the N argument */

    rlcf->complex_query_count = njt_palloc(cf->pool,
                                           sizeof(njt_http_complex_value_t));

    if (rlcf->complex_query_count == NULL) {
        return NJT_CONF_ERROR;
    }

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));
    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = rlcf->complex_query_count;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    /* compile the CMDS argument */

    rlcf->complex_query = njt_palloc(cf->pool,
                                     sizeof(njt_http_complex_value_t));

    if (rlcf->complex_query == NULL) {
        return NJT_CONF_ERROR;
    }

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));
    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = rlcf->complex_query;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}

