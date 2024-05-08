/*
 * nginx kafka module
 *
 * using librdkafka: https://github.com/edenhill/librdkafka
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>

#include <librdkafka/rdkafka.h>

#define KAFKA_TOPIC_MAXLEN 256
#define KAFKA_BROKER_MAXLEN 512

#define KAFKA_ERR_NO_DATA "no_message\n"
#define KAFKA_ERR_BODY_TO_LARGE "body_too_large\n"
#define KAFKA_ERR_PRODUCER "kafka_producer_error\n"

#define KAFKA_PARTITION_UNSET 0xFFFFFFFF

static njt_int_t njt_http_kafka_init_worker(njt_cycle_t *cycle);
static void njt_http_kafka_exit_worker(njt_cycle_t *cycle);

static void *njt_http_kafka_create_main_conf(njt_conf_t *cf);
static void *njt_http_kafka_create_loc_conf(njt_conf_t *cf);
static char *njt_http_kafka_merge_loc_conf(njt_conf_t *cf,
        void *parent, void *child);
static char *njt_http_set_kafka_broker_list(njt_conf_t *cf,
        njt_command_t *cmd, void *conf);
static char *njt_http_set_kafka_topic(njt_conf_t *cf,
        njt_command_t *cmd, void *conf);
static char *njt_http_set_kafka_partition(njt_conf_t *cf,
        njt_command_t *cmd, void *conf);
static char *njt_http_set_kafka_sasl_plaintext(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static njt_int_t njt_http_kafka_handler(njt_http_request_t *r);
static void njt_http_kafka_post_callback_handler(njt_http_request_t *r);

typedef enum {
    njt_str_push = 0,
    njt_str_pop = 1
} njt_str_op;

static void njt_str_helper(njt_str_t *str, njt_str_op op);

typedef struct {
    rd_kafka_t       *rk;
    rd_kafka_conf_t  *rkc;
    njt_str_t        broker_list;
    njt_flag_t        sasl_plaintext;
    njt_str_t         user_name;
    njt_str_t         password;
} njt_http_kafka_main_conf_t;

typedef struct {
    njt_str_t   topic;     /* kafka topic */

    /* kafka partition(0...N), default value: RD_KAFKA_PARTITION_UA */
    njt_int_t   partition;

    rd_kafka_topic_t       *rkt;
    rd_kafka_topic_conf_t  *rktc;

} njt_http_kafka_loc_conf_t;

static njt_command_t njt_http_kafka_commands[] = {
    {
        njt_string("kafka_sasl_plaintext"),
        NJT_HTTP_MAIN_CONF|NJT_CONF_TAKE2,
        njt_http_set_kafka_sasl_plaintext,
        NJT_HTTP_MAIN_CONF_OFFSET,
        0,
        NULL },
    {
        njt_string("kafka_broker_list"),
        NJT_HTTP_MAIN_CONF|NJT_CONF_TAKE1,
        njt_http_set_kafka_broker_list,
        NJT_HTTP_MAIN_CONF_OFFSET,
        0,
        NULL },
    {
        njt_string("kafka_topic"),
        NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
        njt_http_set_kafka_topic,
        NJT_HTTP_LOC_CONF_OFFSET,
        offsetof(njt_http_kafka_loc_conf_t, topic),
        NULL },
    {
        njt_string("kafka_partition"),
        NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
        njt_http_set_kafka_partition,
        NJT_HTTP_LOC_CONF_OFFSET,
        offsetof(njt_http_kafka_loc_conf_t, partition),
        NULL },

    njt_null_command
};


static njt_http_module_t njt_http_kafka_module_ctx = {
    NULL,                             /* pre conf */
    NULL,                             /* post conf */

    njt_http_kafka_create_main_conf,  /* create main conf */
    NULL,                             /* init main conf */

    NULL,                             /* create server conf */
    NULL,                             /* merge server conf */

    njt_http_kafka_create_loc_conf,   /* create local conf */
    njt_http_kafka_merge_loc_conf,    /* merge location conf */
};


njt_module_t njt_http_kafka_module = {
    NJT_MODULE_V1,
    &njt_http_kafka_module_ctx,   /* module context */
    njt_http_kafka_commands,      /* module directives */
    NJT_HTTP_MODULE,              /* module type */

    NULL,                         /* init master */
    NULL,                         /* init module */

    njt_http_kafka_init_worker,   /* init process */
    NULL,                         /* init thread */

    NULL,                         /* exit thread */
    njt_http_kafka_exit_worker,   /* exit process */
    NULL,                         /* exit master */

    NJT_MODULE_V1_PADDING
};


void *njt_http_kafka_create_main_conf(njt_conf_t *cf)
{
    njt_http_kafka_main_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_kafka_main_conf_t));
    if (conf == NULL) {
        return NJT_CONF_ERROR;
    }

    conf->rk = NULL;
    conf->rkc = NULL;
    njt_str_null(&conf->broker_list);
    conf->sasl_plaintext = 0;
    njt_str_null(&conf->user_name);
    njt_str_null(&conf->password);

    return conf;
}


void *njt_http_kafka_create_loc_conf(njt_conf_t *cf)
{
    njt_http_kafka_loc_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_kafka_loc_conf_t));
    if (conf == NULL) {
        return NJT_CONF_ERROR;
    }

    njt_str_null(&conf->topic);

    /*
     * Could not set conf->partition RD_KAFKA_PARTITION_UA, 
     * because both values of RD_KAFKA_PARTITION_UA and NJT_CONF_UNSET is -1
     */
    conf->partition = KAFKA_PARTITION_UNSET;

    return conf;
}


char *njt_http_kafka_merge_loc_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_kafka_loc_conf_t *prev = parent;
    njt_http_kafka_loc_conf_t *conf = child;

#define njt_conf_merge_kafka_partition_conf(conf, prev, def) \
    if (conf == KAFKA_PARTITION_UNSET) { \
        conf = (prev == KAFKA_PARTITION_UNSET) ? def : prev; \
    }

    njt_conf_merge_kafka_partition_conf(conf->partition, prev->partition,
            RD_KAFKA_PARTITION_UA);

#undef njt_conf_merge_kafka_partition_conf

    return NJT_CONF_OK;
}

void kafka_callback_handler(rd_kafka_t *rk,
        void *msg, size_t len, int err, void *opaque, void *msg_opaque)
{
    if (err != 0) {
        njt_log_error(NJT_LOG_ERR,
                (njt_log_t *)msg_opaque, 0, rd_kafka_err2str(err));
    }
}


char *njt_http_set_kafka_sasl_plaintext(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_kafka_main_conf_t      *main_conf = conf;
    njt_str_t                       *value = cf->args->elts;
    njt_uint_t                      i;

    main_conf->sasl_plaintext = 1;
    for (i = 1; i < cf->args->nelts; i++) {
        if (njt_strncmp(value[i].data, "user_name=", 10) == 0 && value[i].len > 10) {
            main_conf->user_name.len = value[i].len - 10;
            main_conf->user_name.data = njt_pcalloc(cf->pool, main_conf->user_name.len + 1);
            if(main_conf->user_name.data == NULL){
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0, " kafka user_name malloc error");
        
                return NJT_CONF_ERROR;  
            }
            
            njt_memcpy(main_conf->user_name.data, value[i].data + 10, main_conf->user_name.len);

        }else if (njt_strncmp(value[i].data, "password=", 9) == 0 && value[i].len > 9) {
            main_conf->password.len = value[i].len - 9;
            main_conf->password.data = njt_pcalloc(cf->pool, main_conf->password.len + 1);
            if(main_conf->password.data == NULL){
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0, " kafka password malloc error");
        
                return NJT_CONF_ERROR;  
            }
            
            njt_memcpy(main_conf->password.data, value[i].data + 9, main_conf->password.len);
        }
    }

    if(main_conf->user_name.len == 0){
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, " kafka user_name must be set");
        
        return NJT_CONF_ERROR;
    }

    if(main_conf->password.len == 0){
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, " kafka password must be set");
        
        return NJT_CONF_ERROR;
    }
    
    return NJT_CONF_OK;
}


char *njt_http_set_kafka_broker_list(njt_conf_t *cf,
        njt_command_t *cmd, void *conf)
{
    njt_http_kafka_main_conf_t *main_conf = conf;
    njt_str_t  *value = cf->args->elts;

    main_conf->broker_list = value[1];

    return NJT_OK;
}


char *njt_http_set_kafka_topic(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char                       *cf_result;
    njt_http_core_loc_conf_t   *clcf;
    njt_http_kafka_loc_conf_t  *local_conf;
    njt_http_kafka_main_conf_t  *main_conf;


    main_conf = njt_http_conf_get_module_main_conf(cf, njt_http_kafka_module);
    if(main_conf->broker_list.len == 0){
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, " kafka_broker_list must set");

        return NJT_CONF_ERROR;
    }

    /* install njt_http_kafka_handler */
    clcf = njt_http_conf_get_module_loc_conf(cf, njt_http_core_module);
    if (clcf == NULL) {
        return NJT_CONF_ERROR;
    }
    clcf->handler = njt_http_kafka_handler;

    /* njt_http_kafka_loc_conf_t::topic assignment */
    cf_result = njt_conf_set_str_slot(cf, cmd, conf);
    if (cf_result != NJT_CONF_OK) {
        return cf_result;
    }

    local_conf = conf;

    local_conf->rktc = rd_kafka_topic_conf_new();

    return NJT_CONF_OK;
}


char *njt_http_set_kafka_partition(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char  *p = conf;

    njt_int_t        *np; 
    njt_str_t        *value;


    np = (njt_int_t *)(p + cmd->offset);

    if (*np != KAFKA_PARTITION_UNSET) {
        return "is duplicate";
    }    

    value = cf->args->elts;

    if (njt_strncmp("auto", (const char *)value[1].data, value[1].len) == 0) {
        *np = RD_KAFKA_PARTITION_UA;
    } else {
        *np = njt_atoi(value[1].data, value[1].len);
        if (*np == NJT_ERROR) {
            return "invalid number";
        }
    }

    return NJT_CONF_OK;
}


static njt_int_t njt_http_kafka_handler(njt_http_request_t *r)
{
    njt_int_t  rv;

    if (!(r->method & NJT_HTTP_POST)) {
        return NJT_HTTP_NOT_ALLOWED;
    }

    rv = njt_http_read_client_request_body(r, njt_http_kafka_post_callback_handler);
    if (rv >= NJT_HTTP_SPECIAL_RESPONSE) {
        return rv;
    }

    return NJT_DONE;
}


static void njt_http_kafka_post_callback_handler(njt_http_request_t *r)
{
    int                          rc, nbufs;
    u_char                      *msg, *err_msg;
    size_t                       len, err_msg_size;
    njt_log_t                   *conn_log;
    njt_buf_t                   *buf;
    njt_chain_t                  out;
    njt_chain_t                 *cl, *in;
    njt_http_request_body_t     *body;
    njt_http_kafka_main_conf_t  *main_conf;
    njt_http_kafka_loc_conf_t   *local_conf;

    err_msg = NULL;
    err_msg_size = 0;

    main_conf = NULL;

    /* get body */
    body = r->request_body;
    if (body == NULL || body->bufs == NULL) {
        err_msg = (u_char *)KAFKA_ERR_NO_DATA;
        err_msg_size = sizeof(KAFKA_ERR_NO_DATA);
        r->headers_out.status = NJT_HTTP_OK;
        goto end;
    }

    /* calc len and bufs */
    len = 0;
    nbufs = 0;
    in = body->bufs;
    for (cl = in; cl != NULL; cl = cl->next) {
        nbufs++;
        len += (size_t)(cl->buf->last - cl->buf->pos);
    }

    /* get msg */
    if (nbufs == 0) {
        err_msg = (u_char *)KAFKA_ERR_NO_DATA;
        err_msg_size = sizeof(KAFKA_ERR_NO_DATA);
        r->headers_out.status = NJT_HTTP_OK;
        goto end;
    }

    if (nbufs == 1 && njt_buf_in_memory(in->buf)) {

        msg = in->buf->pos;

    } else {

        if ((msg = njt_pnalloc(r->pool, len)) == NULL) {
            njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        for (cl = in; cl != NULL; cl = cl->next) {
            if (njt_buf_in_memory(cl->buf)) {
                msg = njt_copy(msg, cl->buf->pos, cl->buf->last - cl->buf->pos);
            } else {
                /* TODO: handle buf in file */
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                        "njt_http_kafka_handler cannot handle in-file-post-buf");

                err_msg = (u_char *)KAFKA_ERR_BODY_TO_LARGE;
                err_msg_size = sizeof(KAFKA_ERR_BODY_TO_LARGE);
                r->headers_out.status = NJT_HTTP_INTERNAL_SERVER_ERROR;

                goto end;
            }
        }
        msg -= len;

    }

    /* send to kafka */
    main_conf = njt_http_get_module_main_conf(r, njt_http_kafka_module);
    local_conf = njt_http_get_module_loc_conf(r, njt_http_kafka_module);
    if (local_conf->rkt == NULL) {
        njt_str_helper(&local_conf->topic, njt_str_push);
        local_conf->rkt = rd_kafka_topic_new(main_conf->rk,
                (const char *)local_conf->topic.data, local_conf->rktc);
        njt_str_helper(&local_conf->topic, njt_str_pop);
    }

    /*
     * the last param should NOT be r->connection->log, for reason that
     * the callback handler (func: kafka_callback_handler) would be called 
     * asynchronously when some errors being happened.
     *
     * At this time, njt_http_finalize_request may have been invoked.
     * In this case, the object r had been destroyed
     * but kafka_callback_handler use the pointer
     * r->connection->log! Worker processes CRASH!
     *
     * Thanks for engineers of www.360buy.com report me this bug.
     *
     * */
    conn_log = r->connection->log;
    rc = rd_kafka_produce(local_conf->rkt, (int32_t)local_conf->partition,
            RD_KAFKA_MSG_F_COPY, (void *)msg, len, NULL, 0, conn_log);
    if (rc != 0) {
        njt_log_error(NJT_LOG_ERR, conn_log, 0,
                rd_kafka_err2str(rd_kafka_last_error()));

        err_msg = (u_char *)KAFKA_ERR_PRODUCER;
        err_msg_size = sizeof(KAFKA_ERR_PRODUCER);
        r->headers_out.status = NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

end:

    if (err_msg != NULL) {
        buf = njt_pcalloc(r->pool, sizeof(njt_buf_t));
        out.buf = buf;
        out.next = NULL;
        buf->pos = err_msg;
        buf->last = err_msg + err_msg_size - 1;
        buf->memory = 1;
        buf->last_buf = 1;

        njt_str_set(&(r->headers_out.content_type), "text/html");
        njt_http_send_header(r);
        njt_http_output_filter(r, &out);
    } else {
        r->headers_out.status = NJT_HTTP_NO_CONTENT;
        njt_http_send_header(r);
    }

    njt_http_finalize_request(r, NJT_OK);

    if (main_conf != NULL) {
        rd_kafka_poll(main_conf->rk, 0);
    }
}


njt_int_t njt_http_kafka_init_worker(njt_cycle_t *cycle)
{
    njt_http_kafka_main_conf_t  *main_conf;
    char errstr[512];

    main_conf = njt_http_cycle_get_module_main_conf(cycle,
            njt_http_kafka_module);

    if(main_conf->broker_list.len == 0){
        return NJT_OK;
    }

    main_conf->rkc = rd_kafka_conf_new();

//  rd_kafka_conf_set(conf_, "queued.min.messages", "20", NULL, 0);
    rd_kafka_conf_set(main_conf->rkc, "bootstrap.servers", (const char *)main_conf->broker_list.data, errstr,
                    sizeof(errstr));

    if(main_conf->sasl_plaintext){
        rd_kafka_conf_set(main_conf->rkc, "security.protocol", "sasl_plaintext", errstr,
                        sizeof(errstr));
        rd_kafka_conf_set(main_conf->rkc, "sasl.mechanisms", "PLAIN", errstr, sizeof(errstr));
        rd_kafka_conf_set(main_conf->rkc, "sasl.username", (const char *)main_conf->user_name.data, errstr,
                        sizeof(errstr));
        rd_kafka_conf_set(main_conf->rkc, "sasl.password", (const char *)main_conf->password.data, errstr,
                        sizeof(errstr));
        rd_kafka_conf_set(main_conf->rkc, "api.version.request", "true", errstr,
                        sizeof(errstr));
    }

    rd_kafka_conf_set_dr_cb(main_conf->rkc, kafka_callback_handler);
    main_conf->rk = rd_kafka_new(RD_KAFKA_PRODUCER, main_conf->rkc, errstr, sizeof(errstr));

    return NJT_OK;
}


void njt_http_kafka_exit_worker(njt_cycle_t *cycle)
{
    njt_http_kafka_main_conf_t  *main_conf;

    main_conf = njt_http_cycle_get_module_main_conf(cycle,
            njt_http_kafka_module);

    rd_kafka_poll(main_conf->rk, 0);

    while (rd_kafka_outq_len(main_conf->rk) > 0) {
        rd_kafka_poll(main_conf->rk, 100);
    }

    // TODO: rd_kafka_topic_destroy(each loc conf rkt);
    rd_kafka_destroy(main_conf->rk);
}


void njt_str_helper(njt_str_t *str, njt_str_op op)
{
    static char backup;

    switch (op) {
        case njt_str_push:
            backup = str->data[str->len];
            str->data[str->len] = 0;
            break;
        case njt_str_pop:
            str->data[str->len] = backup;
            break;
        default:
            njt_abort();
    }
}