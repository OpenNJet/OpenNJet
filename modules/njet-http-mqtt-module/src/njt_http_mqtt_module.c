/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */


#include "njt_http_mqtt_handler.h"
#include "njt_http_mqtt_keepalive.h"
#include "njt_http_mqtt_module.h"
#include "njt_http_mqtt_upstream.h"
#include "njt_http_mqtt_util.h"



static njt_command_t njt_http_mqtt_module_commands[] = {

    { njt_string("mqtt_server"),
      NJT_HTTP_UPS_CONF|NJT_CONF_1MORE,
      njt_http_mqtt_conf_server,
      NJT_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("mqtt_keepalive"),
      NJT_HTTP_UPS_CONF|NJT_CONF_1MORE,
      njt_http_mqtt_conf_keepalive,
      NJT_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("mqtt_retry_times"),
      NJT_HTTP_UPS_CONF|NJT_CONF_TAKE1,
      njt_http_mqtt_conf_retry_times,
      NJT_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("mqtt_send_buffer_size"),
      NJT_HTTP_UPS_CONF|NJT_CONF_TAKE1,
      njt_http_mqtt_conf_send_buffer_size,
      NJT_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("mqtt_recv_buffer_size"),
      NJT_HTTP_UPS_CONF|NJT_CONF_TAKE1,
      njt_http_mqtt_conf_recv_buffer_size,
      NJT_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("mqtt_ping_time"),
      NJT_HTTP_UPS_CONF|NJT_CONF_TAKE1,
      njt_http_mqtt_conf_ping_time,
      NJT_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("mqtt_read_timeout"),
      NJT_HTTP_UPS_CONF|NJT_CONF_TAKE1,
      njt_http_mqtt_conf_read_time,
      NJT_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("mqtt_pass"),
      NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE1,
      njt_http_mqtt_conf_pass,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("mqtt_topic"),
      NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE1,
      njt_http_mqtt_set_topic,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("mqtt_retain"),
      NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE1,
      njt_http_mqtt_set_retain,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("mqtt_qos"),
      NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE1,
      njt_http_mqtt_set_qos,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      njt_null_command
};

static njt_http_module_t njt_http_mqtt_module_ctx = {
    NULL,                                   /* preconfiguration */
    NULL,                                   /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    njt_http_mqtt_create_upstream_srv_conf,  /* create server configuration */
    NULL,                                   /* merge server configuration */

    njt_http_mqtt_create_loc_conf,           /* create location configuration */
    njt_http_mqtt_merge_loc_conf             /* merge location configuration */
};

njt_module_t njt_http_mqtt_module = {
    NJT_MODULE_V1,
    &njt_http_mqtt_module_ctx,      /* module context */
    njt_http_mqtt_module_commands,  /* module directives */
    NJT_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NJT_MODULE_V1_PADDING
};


njt_conf_enum_t njt_http_mqtt_upstream_mode_options[] = {
    { njt_string("multi"),  0 },
    { njt_string("single"), 1 },
    { njt_null_string, 0 }
};

njt_conf_enum_t njt_http_mqtt_upstream_overflow_options[] = {
    { njt_string("ignore"), 0 },
    { njt_string("reject"), 1 },
    { njt_null_string, 0 }
};


void *
njt_http_mqtt_create_upstream_srv_conf(njt_conf_t *cf)
{
    njt_http_mqtt_upstream_srv_conf_t  *conf;
    njt_pool_cleanup_t                *cln;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_mqtt_upstream_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     conf->peers = NULL
     *     conf->current = 0
     *     conf->servers = NULL
     *     conf->free = { NULL, NULL }
     *     conf->cache = { NULL, NULL }
     *     conf->active_conns = 0
     *     conf->reject = 0
     */

    conf->pool = cf->pool;

    /* enable keepalive (single) by default */
    conf->max_cached = 10;
    conf->single = 1;

    conf->send_buffer_size = 4 * 1024 * 1024;
    conf->recv_buffer_size = 1 * 1024 * 1024;

    conf->ping_time = 5000;
    conf->read_timeout = 30000;

    conf->retry_times = 1;

    cln = njt_pool_cleanup_add(cf->pool, 0);
    cln->handler = njt_http_mqtt_keepalive_cleanup;
    cln->data = conf;

    return conf;
}


void *
njt_http_mqtt_create_loc_conf(njt_conf_t *cf)
{
    njt_http_mqtt_loc_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_mqtt_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     conf->upstream.* = 0 / NULL
     *     conf->upstream_cv = NULL
     *     conf->query.methods_set = 0
     *     conf->query.methods = NULL
     *     conf->query.def = NULL
     *     conf->output_binary = 0
     */

    conf->upstream.connect_timeout = NJT_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NJT_CONF_UNSET_MSEC;

    /* the hardcoded values */
    conf->upstream.cyclic_temp_file = 0;
    conf->upstream.buffering = 1;
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

char *
njt_http_mqtt_merge_loc_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_mqtt_loc_conf_t  *prev = parent;
    njt_http_mqtt_loc_conf_t  *conf = child;

    njt_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 30000);

    if ((conf->upstream.upstream == NULL) && (conf->upstream_cv == NULL)) {
        conf->upstream.upstream = prev->upstream.upstream;
        conf->upstream_cv = prev->upstream_cv;
    }

    return NJT_CONF_OK;
}

/*
 * Based on: njt_http_upstream.c/njt_http_upstream_server
 * Copyright (C) Igor Sysoev
 */
char *
njt_http_mqtt_conf_server(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_str_t                           *value = cf->args->elts;
    njt_http_mqtt_upstream_srv_conf_t   *mqttscf = conf;
    njt_http_upstream_server_t          *mqtts;
    njt_http_mqtt_upstream_server_t     *mqtt_self_s;
    njt_http_upstream_srv_conf_t        *uscf;
    njt_url_t                           u;
    njt_uint_t                          i;
    njt_http_upstream_rr_peers_t        *peers;

    uscf = njt_http_conf_get_module_srv_conf(cf, njt_http_upstream_module);
    if (mqttscf->servers == NULL) {
        mqttscf->servers = njt_array_create(cf->pool, 4,
                             sizeof(njt_http_upstream_server_t));
        if (mqttscf->servers == NULL) {
            njt_conf_log_error(NJT_LOG_ERR, cf, 0,
                            "mqtt servers array create error");
            return NJT_CONF_ERROR;
        }

        uscf->servers = mqttscf->servers;
    }

    mqtts = njt_array_push(mqttscf->servers);
    if (mqtts == NULL) {
        njt_conf_log_error(NJT_LOG_ERR, cf, 0,
                        "mqtt servers array push error");
        return NJT_CONF_ERROR;
    }

    njt_memzero(mqtts, sizeof(njt_http_upstream_server_t));
    mqtts->data = njt_pcalloc(cf->pool, sizeof(njt_http_mqtt_upstream_server_t));
    if (mqtts->data == NULL) {
        njt_conf_log_error(NJT_LOG_ERR, cf, 0,
                        "mqtt server self data malloc error");
        return NJT_CONF_ERROR;
    }

    mqtt_self_s = (njt_http_mqtt_upstream_server_t *)mqtts->data;

    /* parse the first name:port argument */
    njt_memzero(&u, sizeof(njt_url_t));
    u.url = value[1];
    u.default_port = 1883; /* mqtt broker default port */

    if (njt_parse_url(cf->pool, &u) != NJT_OK) {
        if (u.err) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "mqtt: %s in upstream \"%V\"",
                               u.err, &u.url);
        }

        return NJT_CONF_ERROR;
    }

    mqtts->addrs = u.addrs;
    mqtts->naddrs = u.naddrs;
    mqtt_self_s->port = u.port;
    mqtts->name = value[1];
    mqtts->weight = 100;
    mqtts->max_fails = 1;
    mqtts->fail_timeout = 10;

    if(uscf->peer.data == NULL){
        //force assign rr peers
        peers = njt_pcalloc(cf->pool, sizeof(njt_http_upstream_rr_peers_t));
        if(peers == NULL){
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                    "mqtt malloc peers error");
            
            return NJT_CONF_ERROR;
        }

        peers->name = &uscf->host;
        uscf->peer.data = peers;

        njt_conf_log_error(NJT_LOG_DEBUG, cf, 0,
                "mqtt force assgin peers name:%V servername:%V", peers->name, &mqtts->name);
    }

    /* parse various options */
    for (i = 2; i < cf->args->nelts; i++) {
        if (value[i].len > 5 && njt_strncmp(value[i].data, "user=", 5) == 0)
        {
            mqtt_self_s->user.len = value[i].len - 5 + 1;
            mqtt_self_s->user.data = njt_pcalloc(cf->pool, mqtt_self_s->user.len);
            if(mqtt_self_s->user.data == NULL){
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                    "mqtt: invalid parameter \"%V\" in"
                    " \"mqtt_server\"", &value[i]);
                
                return NJT_CONF_ERROR;
            }

            njt_memcpy(mqtt_self_s->user.data, value[i].data + 5, mqtt_self_s->user.len - 1);
            continue;
        }

        if (value[i].len > 5 && njt_strncmp(value[i].data, "password=", 9) == 0)
        {
            mqtt_self_s->password.len = value[i].len - 9 + 1;
            mqtt_self_s->password.data = njt_pcalloc(cf->pool, mqtt_self_s->password.len);
            if(mqtt_self_s->password.data == NULL){
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                    "mqtt: invalid parameter \"%V\" in"
                    " \"mqtt_server\"", &value[i]);
                
                return NJT_CONF_ERROR;
            }

            njt_memcpy(mqtt_self_s->password.data, value[i].data + 9, mqtt_self_s->password.len - 1);
            continue;
        }

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "mqtt: invalid parameter \"%V\" in"
                           " \"mqtt_server\"", &value[i]);

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "returning NJT_CONF_ERROR");
        return NJT_CONF_ERROR;
    }    

    uscf->peer.init_upstream = njt_http_mqtt_upstream_init;

    return NJT_CONF_OK;
}


char *
njt_http_mqtt_conf_send_buffer_size(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_str_t                         *value = cf->args->elts;
    njt_http_mqtt_upstream_srv_conf_t  *mqttscf = conf;


    mqttscf->send_buffer_size = njt_parse_size(&value[1]);
    if (mqttscf->send_buffer_size == (size_t) NJT_ERROR) {
        return "invalid value";
    }


    return NJT_CONF_OK;
}



char *
njt_http_mqtt_conf_read_time(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_str_t                           *value = cf->args->elts;
    njt_http_mqtt_upstream_srv_conf_t   *mqttscf = conf;

    mqttscf->read_timeout = njt_parse_time(&value[1], 0);
    if (mqttscf->read_timeout == (njt_msec_t) NJT_ERROR) {
        return "invalid value";
    }

    return NJT_CONF_OK;
}

char *
njt_http_mqtt_conf_ping_time(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_str_t                           *value = cf->args->elts;
    njt_http_mqtt_upstream_srv_conf_t   *mqttscf = conf;

    mqttscf->ping_time = njt_parse_time(&value[1], 0);
    if (mqttscf->ping_time == (njt_msec_t) NJT_ERROR) {
        return "invalid value";
    }

    return NJT_CONF_OK;
}


char *
njt_http_mqtt_conf_recv_buffer_size(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_str_t                         *value = cf->args->elts;
    njt_http_mqtt_upstream_srv_conf_t  *mqttscf = conf;

    mqttscf->recv_buffer_size = njt_parse_size(&value[1]);
    if (mqttscf->recv_buffer_size == (size_t) NJT_ERROR) {
        return "invalid value";
    }

    return NJT_CONF_OK;
}


char *
njt_http_mqtt_conf_retry_times(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_str_t                         *value = cf->args->elts;
    njt_http_mqtt_upstream_srv_conf_t  *mqttscf = conf;
    njt_int_t                          n;


    n = njt_atoi(value[1].data, value[1].len);
    if (n == NJT_ERROR) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                            "mqtt: invalid value \"%V\""
                            " in \"%V\" directive",
                            &value[1], &cmd->name);

        return NJT_CONF_ERROR;
    }

    mqttscf->retry_times = (njt_uint_t) n;

    return NJT_CONF_OK;
}



char *
njt_http_mqtt_conf_keepalive(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_str_t                         *value = cf->args->elts;
    njt_http_mqtt_upstream_srv_conf_t  *mqttscf = conf;
    njt_conf_enum_t                   *e;
    njt_uint_t                         i, j;
    njt_int_t                          n;

    if (mqttscf->max_cached != 10 /* default */) {
        return "is duplicate";
    }

    if ((cf->args->nelts == 2) && (njt_strcmp(value[1].data, "off") == 0)) {
        mqttscf->max_cached = 0;
        return NJT_CONF_OK;
    }

    for (i = 1; i < cf->args->nelts; i++) {
        if (njt_strncmp(value[i].data, "max=", sizeof("max=") - 1)
                == 0)
        {
            value[i].len = value[i].len - (sizeof("max=") - 1);
            value[i].data = &value[i].data[sizeof("max=") - 1];

            n = njt_atoi(value[i].data, value[i].len);
            if (n == NJT_ERROR) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "mqtt: invalid \"max\" value \"%V\""
                                   " in \"%V\" directive",
                                   &value[i], &cmd->name);

                return NJT_CONF_ERROR;
            }

            mqttscf->max_cached = (njt_uint_t) n;
            continue;
        }

        // if (njt_strncmp(value[i].data, "mode=", sizeof("mode=") - 1)
        //         == 0)
        // {
        //     value[i].len = value[i].len - (sizeof("mode=") - 1);
        //     value[i].data = &value[i].data[sizeof("mode=") - 1];

        //     e = njt_http_mqtt_upstream_mode_options;
        //     for (j = 0; e[j].name.len; j++) {
        //         if ((e[j].name.len == value[i].len)
        //             && (njt_strcasecmp(e[j].name.data, value[i].data) == 0))
        //         {
        //             mqttscf->single = e[j].value;
        //             break;
        //         }
        //     }

        //     if (e[j].name.len == 0) {
        //         njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
        //                            "mqtt: invalid \"mode\" value \"%V\""
        //                            " in \"%V\" directive",
        //                            &value[i], &cmd->name);

        //         return NJT_CONF_ERROR;
        //     }

        //     continue;
        // }

        if (njt_strncmp(value[i].data, "overflow=", sizeof("overflow=") - 1)
                == 0)
        {
            value[i].len = value[i].len - (sizeof("overflow=") - 1);
            value[i].data = &value[i].data[sizeof("overflow=") - 1];

            e = njt_http_mqtt_upstream_overflow_options;
            for (j = 0; e[j].name.len; j++) {
                if ((e[j].name.len == value[i].len)
                    && (njt_strcasecmp(e[j].name.data, value[i].data) == 0))
                {
                    mqttscf->reject = e[j].value;
                    break;
                }
            }

            if (e[j].name.len == 0) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "mqtt: invalid \"overflow\" value \"%V\""
                                   " in \"%V\" directive",
                                   &value[i], &cmd->name);

                return NJT_CONF_ERROR;
            }

            continue;
        }

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "mqtt: invalid parameter \"%V\" in"
                           " \"%V\" directive",
                           &value[i], &cmd->name);

        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


char *
njt_http_mqtt_conf_pass(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_str_t                           *value = cf->args->elts;
    njt_http_mqtt_loc_conf_t            *mqttlcf = conf;
    njt_http_core_loc_conf_t            *clcf;
    njt_http_compile_complex_value_t    ccv;
    njt_url_t                           url;


    if ((mqttlcf->upstream.upstream != NULL) || (mqttlcf->upstream_cv != NULL)) {
        return "is duplicate";
    }

    if (value[1].len == 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "mqtt: empty upstream in \"%V\" directive",
                           &cmd->name);

        return NJT_CONF_ERROR;
    }

    clcf = njt_http_conf_get_module_loc_conf(cf, njt_http_core_module);
    clcf->handler = njt_http_mqtt_handler;

    if (clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }

    if (njt_http_script_variables_count(&value[1])) {
        /* complex value */
        mqttlcf->upstream_cv = njt_palloc(cf->pool,
                                        sizeof(njt_http_complex_value_t));
        if (mqttlcf->upstream_cv == NULL) {
            return NJT_CONF_ERROR;
        }

        njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[1];
        ccv.complex_value = mqttlcf->upstream_cv;

        if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
            return NJT_CONF_ERROR;
        }

        return NJT_CONF_OK;
    } else {
        /* simple value */
        njt_memzero(&url, sizeof(njt_url_t));

        url.url = value[1];
        url.no_resolve = 1;

        mqttlcf->upstream.upstream = njt_http_upstream_add(cf, &url, 0);
        if (mqttlcf->upstream.upstream == NULL) {
            return NJT_CONF_ERROR;
        }

        return NJT_CONF_OK;
    }
}


char *
njt_http_mqtt_set_topic(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_str_t                           *value = cf->args->elts;
    njt_http_mqtt_loc_conf_t            *mqttlcf = conf;
    // njt_http_core_loc_conf_t            *clcf;


    mqttlcf->topic.data = njt_pcalloc(cf->pool, value[1].len + 1);
    if(mqttlcf->topic.data == NULL){

        return NJT_CONF_ERROR;
    }

    njt_memcpy(mqttlcf->topic.data, value[1].data, value[1].len);
    mqttlcf->topic.len = value[1].len;

    return NJT_CONF_OK;
}


char *
njt_http_mqtt_set_retain(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_str_t                           *value = cf->args->elts;
    njt_http_mqtt_loc_conf_t            *mqttlcf = conf;
    njt_int_t                            n;


    n = njt_atoi(value[1].data, value[1].len);
    if (n == NJT_ERROR || n < 0 || n > 1) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                            "mqtt: invalid retain value \"%V\""
                            " in \"%V\" directive",
                            &value[1], &cmd->name);

        return NJT_CONF_ERROR;
    }

    mqttlcf->retain = n;

    return NJT_CONF_OK;
}


char *
njt_http_mqtt_set_qos(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_str_t                           *value = cf->args->elts;
    njt_http_mqtt_loc_conf_t            *mqttlcf = conf;
    njt_int_t                            n;


    n = njt_atoi(value[1].data, value[1].len);
    if (n == NJT_ERROR || n < 0 || n > 3) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                            "mqtt: invalid qos value \"%V\""
                            " in \"%V\" directive",
                            &value[1], &cmd->name);

        return NJT_CONF_ERROR;
    }

    mqttlcf->qos = n;

    return NJT_CONF_OK;
}


njt_http_upstream_srv_conf_t *
njt_http_mqtt_find_upstream(njt_http_request_t *r, njt_url_t *url)
{
    njt_http_upstream_main_conf_t   *umcf;
    njt_http_upstream_srv_conf_t   **uscfp;
    njt_uint_t                       i;

    umcf = njt_http_get_module_main_conf(r, njt_http_upstream_module);

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        if ((uscfp[i]->host.len != url->host.len)
            || (njt_strncasecmp(uscfp[i]->host.data, url->host.data,
                                url->host.len) != 0))
        {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "host doesn't match");
            continue;
        }

        if (uscfp[i]->port != url->port) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "port doesn't match: %d != %d",
               (int) uscfp[i]->port, (int) url->port);
            continue;
        }

        return uscfp[i];
    }

    return NULL;
}
