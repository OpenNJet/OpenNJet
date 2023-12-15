/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */
#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_http_kv_module.h>
#include <njt_rand_util.h>
#include <njt_json_util.h>
#include <njt_rpc_result_util.h>

#define DYN_TOPIC_REG_KEY "http_split_clients_2"
#define DYN_TOPIC_REG_KEY_LEN 20

typedef struct
{
    uint32_t percent;
    njt_http_variable_value_t value;
    bool last;        // last part configued as  *
} njt_http_split_clients_2_part_t;

typedef struct
{
    njt_http_complex_value_t value;
    njt_array_t parts;
} njt_http_split_clients_2_ctx_t;

typedef struct
{
    njt_http_split_clients_2_ctx_t *ctx;
    njt_flag_t has_split_block;
} njt_http_split_clients_2_conf_t;

enum
{
    NJT_HTTP_SPLIT_CLIENT_2_ERR_TOTAL = 500,
} NJT_HTTP_SPLIT_CLIENTS_2_ERROR;

static int njt_http_split_kv_change_handler_internal(njt_str_t *key, njt_str_t *value, void *data, njt_str_t *out_msg);
static u_char *njt_http_split_clients_2_rpc_get_handler(njt_str_t *topic, njt_str_t *request, int *len, void *data);
static u_char *njt_http_split_clients_2_rpc_put_handler(njt_str_t *topic, njt_str_t *request, int *len, void *data);

static njt_int_t njt_http_split_client_2_init_worker(njt_cycle_t *cycle);
static char *njt_conf_split_clients_2_block(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_split_clients_2(njt_conf_t *cf, njt_command_t *dummy,
    void *conf);
static void *njt_http_split_client_2_create_conf(njt_conf_t *cf);

static njt_command_t njt_http_split_clients_2_commands[] = {

    {njt_string("split_clients_2"),
     NJT_HTTP_MAIN_CONF | NJT_CONF_BLOCK | NJT_CONF_TAKE1,
     njt_conf_split_clients_2_block,
     NJT_HTTP_MAIN_CONF_OFFSET,
     0,
     NULL},

    njt_null_command };

static njt_http_module_t njt_http_split_clients_2_module_ctx = {
    NULL, /* preconfiguration */
    NULL, /* postconfiguration */

    njt_http_split_client_2_create_conf, /* create main configuration */
    NULL,                                /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    NULL, /* create location configuration */
    NULL  /* merge location configuration */
};

njt_module_t njt_http_split_clients_2_module = {
    NJT_MODULE_V1,
    &njt_http_split_clients_2_module_ctx, /* module context */
    njt_http_split_clients_2_commands,    /* module directives */
    NJT_HTTP_MODULE,                      /* module type */
    NULL,                                 /* init master */
    NULL,                                 /* init module */
    njt_http_split_client_2_init_worker,           /* init process */
    NULL,                                 /* init thread */
    NULL,                                 /* exit thread */
    NULL,                                 /* exit process */
    NULL,                                 /* exit master */
    NJT_MODULE_V1_PADDING };

static void *
njt_http_split_client_2_create_conf(njt_conf_t *cf)
{
    njt_http_split_clients_2_conf_t *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_split_clients_2_conf_t));

    if (conf == NULL) {
        return NULL;
    }

    return conf;
}

static int njt_http_split_kv_change_handler_internal(njt_str_t *key, njt_str_t *value, void *data, njt_str_t *out_msg)
{
    njt_http_split_clients_2_conf_t *sc2cf = (njt_http_split_clients_2_conf_t *)data;
    njt_http_split_clients_2_ctx_t *ctx;
    njt_http_split_clients_2_part_t *part;
    njt_uint_t i;
    njt_json_manager json_manager;
    njt_pool_t *tmp_pool;
    njt_int_t rc;
    njt_queue_t *values, *q;
    njt_json_element *f;
    njt_rpc_result_t *rpc_result;
    njt_uint_t backend_count;
    bool backend_found;

    njt_memzero(&json_manager, sizeof(njt_json_manager));
    ctx = (njt_http_split_clients_2_ctx_t *)sc2cf->ctx;
    part = ctx->parts.elts;

    tmp_pool = NULL;
    rpc_result = njt_rpc_result_create();
    if (!rpc_result) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "can't create rpc result");
        rc = NJT_ERROR;
        goto end;
    }
    njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_SUCCESS);

    tmp_pool = njt_create_pool(NJT_DEFAULT_POOL_SIZE, njt_cycle->log);
    if (tmp_pool == NULL) {
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_MEM_ALLOC);
        rc = NJT_ERROR;
        goto rpc_msg;
    }

    rc = njt_json_2_structure(value, &json_manager, tmp_pool);
    if (rc != NJT_OK) {
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_JSON);
        goto rpc_msg;
    }

    njt_str_t sk;
    njt_str_set(&sk, "http");
    njt_json_element *out_element;
    rc = njt_struct_top_find(&json_manager, &sk, &out_element);
    if (rc == NJT_OK) {
        njt_str_set(&sk, "split_clients_2");
        njt_json_element *tmp_element;
        rc = njt_struct_find(out_element, &sk, &tmp_element);
        if (rc == NJT_OK && tmp_element->type == NJT_JSON_OBJ) {
            values = &tmp_element->objdata.datas;
            njt_uint_t sum = 0;
            njt_str_t tmp_err_str;
            for (i = 0; i < ctx->parts.nelts; i++) {
                backend_found = false;
                backend_count = 0;
                for (q = njt_queue_head(values);
                    q != njt_queue_sentinel(values);
                    q = njt_queue_next(q)) {
                    f = njt_queue_data(q, njt_json_element, ele_queue);
                    backend_count++;
                    if (
                        f->key.len == part[i].value.len &&
                        njt_strncmp(part[i].value.data, f->key.data, f->key.len) == 0) {
                        backend_found = true;
                    } else {
                        continue;
                    }
                    if (f->type == NJT_JSON_INT && f->intval>=0) {
                        sum += f->intval;
                    } else {
                        rc = NJT_RPC_RSP_ERR_JSON;
                        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_JSON);
                        char *data_fmt_err = " percentage is not valid";
                        tmp_err_str.data = njt_pcalloc(tmp_pool, f->key.len + strlen(data_fmt_err) + 1);
                        njt_memcpy(tmp_err_str.data, f->key.data, f->key.len);
                        njt_memcpy(tmp_err_str.data + f->key.len, data_fmt_err, strlen(data_fmt_err));
                        tmp_err_str.data[f->key.len + strlen(data_fmt_err)] = '\0';
                        njt_rpc_result_set_msg(rpc_result, tmp_err_str.data);
                        goto rpc_msg;
                    }
                }
                if (backend_count != ctx->parts.nelts) {
                    rc = NJT_RPC_RSP_ERR_JSON;
                    njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_JSON);
                    u_char *end;
                    tmp_err_str.data = njt_pcalloc(tmp_pool, 1024);
                    end = njt_snprintf(tmp_err_str.data, 1024, "number of backend in the post json should be %ud", ctx->parts.nelts);
                    *end='\0';
                    njt_rpc_result_set_msg(rpc_result, tmp_err_str.data);
                    goto rpc_msg;
                }
                if (!backend_found) {
                    rc = NJT_RPC_RSP_ERR_JSON;
                    njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_JSON);
                    char *data_fmt_err = " not in post json data";
                    tmp_err_str.data = njt_pcalloc(tmp_pool, part[i].value.len + strlen(data_fmt_err)+1);
                    njt_memcpy(tmp_err_str.data, part[i].value.data, part[i].value.len);
                    njt_memcpy(tmp_err_str.data + part[i].value.len, data_fmt_err, strlen(data_fmt_err));
                    tmp_err_str.data[part[i].value.len + strlen(data_fmt_err)]='\0';
                    njt_rpc_result_set_msg(rpc_result, tmp_err_str.data);
                    goto rpc_msg;
                }
            }
            if (sum != 100) {
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "split clients 2 set error: total percentage is not 100");
                rc = NJT_HTTP_SPLIT_CLIENT_2_ERR_TOTAL;
                njt_rpc_result_set_code(rpc_result, NJT_HTTP_SPLIT_CLIENT_2_ERR_TOTAL);
                njt_rpc_result_set_msg(rpc_result, (u_char *)"total percentage should be 100");
                goto rpc_msg;
            } else {
                for (i = 0; i < ctx->parts.nelts; i++) {
                    for (q = njt_queue_head(values);
                        q != njt_queue_sentinel(values);
                        q = njt_queue_next(q)) {
                        f = njt_queue_data(q, njt_json_element, ele_queue);
                        if (!part[i].last &&
                            f->type == NJT_JSON_INT &&
                            f->key.len == part[i].value.len &&
                            njt_strncmp(part[i].value.data, f->key.data, f->key.len) == 0) {
                            part[i].percent = f->intval;
                            continue;
                        }
                    }
                }
            }
        } else {
            rc = NJT_RPC_RSP_ERR_JSON;
            njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_JSON);
            njt_rpc_result_set_msg(rpc_result, (u_char *)"split_clients_2 field is required");
            goto rpc_msg;
        }
    } else {
        rc = NJT_RPC_RSP_ERR_JSON;
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_JSON);
        njt_rpc_result_set_msg(rpc_result, (u_char *)"http field is required");
        goto rpc_msg;
    }
rpc_msg:
    if (rc != NJT_OK) {
        njt_str_t msg = njt_string("");
        njt_kv_sendmsg(key,&msg,0);
    }
    if (out_msg) {
        njt_rpc_result_to_json_str(rpc_result, out_msg);
    }
end:
    if (tmp_pool != NULL) {
        njt_destroy_pool(tmp_pool);
    }
    if (rpc_result) {
        njt_rpc_result_destroy(rpc_result);
    }
    return rc;

}

static u_char *njt_http_split_clients_2_rpc_put_handler(njt_str_t *topic, njt_str_t *request, int *len, void *data)
{
    njt_str_t err_json_msg;
    njt_str_null(&err_json_msg);
    njt_http_split_kv_change_handler_internal(topic, request, data, &err_json_msg);
    *len = err_json_msg.len;
    return err_json_msg.data;

}

static int split_kv_change_handler(njt_str_t *key, njt_str_t *value, void *data)
{
    return njt_http_split_kv_change_handler_internal(key, value, data, NULL);
}

static u_char *njt_http_split_clients_2_rpc_get_handler(njt_str_t *topic, njt_str_t *request, int *len, void *data)
{
    njt_http_conf_ctx_t *conf_ctx;
    njt_http_split_clients_2_conf_t *sc2cf;
    njt_http_split_clients_2_ctx_t *ctx;
    njt_http_split_clients_2_part_t *part;
    njt_uint_t i;
    njt_uint_t ret_len;

    njt_str_t json_h = njt_string("{\"http\":{\"split_clients_2\":{");
    njt_str_t json_t = njt_string("}}}");

    ret_len = json_h.len + json_t.len;

    conf_ctx = (njt_http_conf_ctx_t *)njt_get_conf(njt_cycle->conf_ctx, njt_http_module);
    sc2cf = conf_ctx->main_conf[njt_http_split_clients_2_module.ctx_index];

    u_char *msg, *pmsg;
    if (!sc2cf->has_split_block) {
        msg = njt_calloc(2, njt_cycle->log);
        memcpy(msg, "{}", 2);
        *len = 2;
        return msg;
    }

    ctx = (njt_http_split_clients_2_ctx_t *)sc2cf->ctx;
    part = ctx->parts.elts;

    u_char p_s[4];
    njt_uint_t sum = 0;
    for (i = 0; i < ctx->parts.nelts; i++) {
        njt_memzero(p_s, 4);
        sum += part[i].percent;
        ret_len += part[i].value.len;
        if (part[i].last) {
            njt_snprintf(p_s, 3, "%d", 100 - sum);
        } else {
            njt_snprintf(p_s, 3, "%d", part[i].percent);
        }
        ret_len += (njt_uint_t)strlen((const char *)p_s);
        ret_len += 4; //"":,
    }

    msg = njt_calloc(ret_len - 1, njt_cycle->log);
    pmsg = msg;
    msg = njt_snprintf(msg, json_h.len, "%s", json_h.data);
    for (i = 0; i < ctx->parts.nelts; i++) {

        *msg++ = '"';
        msg = njt_snprintf(msg, part[i].value.len, "%s", part[i].value.data);
        *msg++ = '"';
        *msg++ = ':';
        if (part[i].last) {
            msg = njt_snprintf(msg, 3, "%d", 100 - sum);
        } else {
            msg = njt_snprintf(msg, 3, "%d", part[i].percent);
        }
        *msg++ = ',';
    }
    msg--;
    msg = njt_snprintf(msg, json_t.len, "%s", json_t.data);
    *len = ret_len - 1;

    return pmsg;
}

static njt_int_t njt_http_split_client_2_init_worker(njt_cycle_t *cycle)
{
    njt_http_conf_ctx_t *conf_ctx;
    njt_http_split_clients_2_conf_t *sc2cf;

    // return  when there is no http configuraton
    if (njt_http_split_clients_2_module.ctx_index == NJT_CONF_UNSET_UINT) {
        return NJT_OK;
    }
    conf_ctx = (njt_http_conf_ctx_t *)njt_get_conf(cycle->conf_ctx, njt_http_module);
    if (!conf_ctx) {
        return NJT_OK;
    }
    sc2cf = conf_ctx->main_conf[njt_http_split_clients_2_module.ctx_index];

    if (!sc2cf || !sc2cf->has_split_block) {
        return NJT_OK;
    }

    njt_str_t rpc_key = njt_string(DYN_TOPIC_REG_KEY);
    njt_kv_reg_handler_t h;
    njt_memzero(&h, sizeof(njt_kv_reg_handler_t));
    h.key = &rpc_key;
    h.rpc_get_handler = njt_http_split_clients_2_rpc_get_handler;
    h.rpc_put_handler = njt_http_split_clients_2_rpc_put_handler;
    h.handler = split_kv_change_handler;
    h.data=sc2cf;
    h.api_type = NJT_KV_API_TYPE_DECLATIVE;
    njt_kv_reg_handler(&h);
    
    return NJT_OK;
}

static njt_int_t
njt_http_split_clients_2_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    njt_http_split_clients_2_ctx_t *ctx = (njt_http_split_clients_2_ctx_t *)data;
    njt_uint_t i;
    njt_http_split_clients_2_part_t *part;
    uint32_t percent;

    *v = njt_http_variable_null_value;

    part = ctx->parts.elts;

    for (i = 0; i < ctx->parts.nelts; i++) {
        percent = part[i].percent;
        if (percent == 0 && !part[i].last) {
            continue;
        }
        if (njt_rand_percentage_sample(percent) || part[i].last) {
            *v = part[i].value;
            return NJT_OK;
        }
    }

    return NJT_OK;
}

static char *
njt_conf_split_clients_2_block(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char *rv;
    uint32_t sum;
    njt_str_t *value, name;
    njt_uint_t i;
    njt_conf_t save;
    njt_http_variable_t *var;
    njt_http_split_clients_2_ctx_t *ctx;
    njt_http_split_clients_2_part_t *part;
    njt_http_split_clients_2_conf_t *sc2_conf;
    sc2_conf = (njt_http_split_clients_2_conf_t *)conf;

    ctx = njt_pcalloc(cf->pool, sizeof(njt_http_split_clients_2_ctx_t));
    if (ctx == NULL) {
        return NJT_CONF_ERROR;
    }

    sc2_conf->ctx = ctx;
    sc2_conf->has_split_block = 1;
    value = cf->args->elts;

    name = value[1];

    if (name.data[0] != '$') {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
            "invalid variable name \"%V\"", &name);
        return NJT_CONF_ERROR;
    }

    name.len--;
    name.data++;

    var = njt_http_add_variable(cf, &name, NJT_HTTP_VAR_CHANGEABLE);
    if (var == NULL) {
        return NJT_CONF_ERROR;
    }

    var->get_handler = njt_http_split_clients_2_variable;
    var->data = (uintptr_t)ctx;

    if (njt_array_init(&ctx->parts, cf->pool, 2,
        sizeof(njt_http_split_clients_2_part_t)) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    save = *cf;
    cf->ctx = ctx;
    cf->handler = njt_http_split_clients_2;
    cf->handler_conf = conf;

    rv = njt_conf_parse(cf, NULL);

    *cf = save;

    if (rv != NJT_CONF_OK) {
        return rv;
    }

    sum = 0;
    part = ctx->parts.elts;

    if (ctx->parts.nelts != 2) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
            "split clients 2 should be configured with 2 groups, check if there are more than 2 lines");
        return NJT_CONF_ERROR;
    }

    if (part[0].last || !part[1].last) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
            "split clients 2 should be configured with 2 groups only, and second line should be started with * ");
        return NJT_CONF_ERROR;
    }

    for (i = 0; i < ctx->parts.nelts; i++) {
        sum += part[i].percent; // if use kv_http_ as percent, percentage is 0
        if (sum > 100) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                "percent total is greater than 100%%");
            return NJT_CONF_ERROR;
        }
    }

    return rv;
}

static char *
njt_http_split_clients_2(njt_conf_t *cf, njt_command_t *dummy, void *conf)
{
    njt_int_t n;
    njt_str_t *value;
    njt_http_split_clients_2_ctx_t *ctx;
    njt_http_split_clients_2_part_t *part;

    ctx = cf->ctx;
    value = cf->args->elts;

    part = njt_array_push(&ctx->parts);
    if (part == NULL) {
        return NJT_CONF_ERROR;
    }

    if (cf->args->nelts > 2) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
            "split_clients_2 config error, semicolon is missing", &value[0]);

        return NJT_CONF_ERROR;
    }
    if (value[0].len == 1 && value[0].data[0] == '*') {
        part->last = true;
        part->percent = 0;
    } else {
        part->last = false;

        if (value[0].len == 0 || value[0].data[value[0].len - 1] != '%') {
            goto invalid;
        }

        if (value[0].data[0] == '0' && value[0].len == 2) {
            part->percent = 0;
        }
        n = njt_atoi(value[0].data, value[0].len - 1);
        if (n == NJT_ERROR) {
            goto invalid;
        }

        part->percent = (uint32_t)n;
    }


    part->value.len = value[1].len;
    part->value.valid = 1;
    part->value.no_cacheable = 0;
    part->value.not_found = 0;
    part->value.data = value[1].data;

    return NJT_CONF_OK;

invalid:

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
        "percentage should be an integer, invalid percent value \"%V\", ", &value[0]);
    return NJT_CONF_ERROR;
}
