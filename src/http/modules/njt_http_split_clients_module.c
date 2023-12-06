
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_http_kv_module.h>
#include <njt_json_api.h>
#include <njt_rpc_result_util.h>

#define DYN_TOPIC_REG_KEY "http_split_clients"
#define SC_KEY_JSON_FIELD "_key"
#define SC_KEY_JSON_FIELD_LEN 4

enum
{
    NJT_HTTP_SPLIT_CLIENT_ERR_TOTAL = 500,
} NJT_HTTP_SPLIT_CLIENT_ERR;

typedef struct
{
    uint32_t percent;
    uint32_t ori_percent;
    njt_http_variable_value_t value;
    bool last;
} njt_http_split_clients_part_t;

typedef struct
{
    njt_http_complex_value_t value;
    njt_array_t parts;
    njt_pool_t *pool;
    njt_int_t dynamic;
} njt_http_split_clients_ctx_t;

typedef struct
{
    njt_http_split_clients_ctx_t *ctx;
    njt_flag_t has_split_block;
} njt_http_split_clients_conf_t;

static void *njt_http_split_client_create_conf(njt_conf_t *cf);
static njt_int_t njt_http_split_clients_init_worker(njt_cycle_t *cycle);
static char *njt_conf_split_clients_block(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_split_clients(njt_conf_t *cf, njt_command_t *dummy,
    void *conf);

static njt_command_t njt_http_split_clients_commands[] = {

    {njt_string("split_clients"),
     NJT_HTTP_MAIN_CONF | NJT_CONF_BLOCK | NJT_CONF_TAKE2,
     njt_conf_split_clients_block, NJT_HTTP_MAIN_CONF_OFFSET, 0, NULL},

    njt_null_command };

static njt_http_module_t njt_http_split_clients_module_ctx = {
    NULL, /* preconfiguration */
    NULL, /* postconfiguration */

    njt_http_split_client_create_conf, /* create main configuration */
    NULL,                              /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    NULL, /* create location configuration */
    NULL  /* merge location configuration */
};

njt_module_t njt_http_split_clients_module = {
    NJT_MODULE_V1,
    &njt_http_split_clients_module_ctx, /* module context */
    njt_http_split_clients_commands,    /* module directives */
    NJT_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    njt_http_split_clients_init_worker, /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NJT_MODULE_V1_PADDING };

static void *njt_http_split_client_create_conf(njt_conf_t *cf)
{
    njt_http_split_clients_conf_t *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_split_clients_conf_t));

    if (conf == NULL) {
        njt_conf_log_error(NJT_ERROR, cf, 0, "can't create split client conf");
        return NULL;
    }

    return conf;
}

static njt_int_t njt_http_split_client_update_sc_key(njt_http_split_clients_ctx_t *ctx,
    njt_rpc_result_t *rpc_result, njt_str_t *sc_key)
{
    njt_http_compile_complex_value_t ccv;
    njt_int_t rc;
    njt_conf_t *cf;
    njt_http_split_clients_ctx_t old_ctx;

    njt_pool_t *pool = njt_create_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
    if (pool == NULL) {
        if (rpc_result) {
            njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_MEM_ALLOC);
        }
        return NJT_ERROR;
    }
    rc = njt_sub_pool(njt_cycle->pool, pool);
    if (rc != NJT_OK) {
        if (rpc_result) {
            njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_MEM_ALLOC);
        }
        njt_destroy_pool(pool);
        return NJT_ERROR;
    }

    old_ctx = *ctx;
    ctx->dynamic = 1;
    ctx->pool = pool;

    njt_conf_t cf_data = {
    .pool = pool,
    .temp_pool = pool,
    .cycle = (njt_cycle_t *)njt_cycle,
    .log = pool->log,
    };
    cf = &cf_data;
    cf->ctx = (njt_http_conf_ctx_t *)njt_get_conf(njt_cycle->conf_ctx, njt_http_module);

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));
    ccv.value = njt_pcalloc(pool, sizeof(njt_str_t));
    ccv.cf = cf;
    ccv.value->data = njt_pstrdup(pool, sc_key);
    ccv.value->len = sc_key->len;
    ccv.complex_value = &ctx->value;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        if (rpc_result) {
            njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_JSON);
            njt_rpc_result_set_msg(rpc_result, (u_char *)"_key is not valid");
        }
        goto error;
    }

    njt_http_variables_init_vars_dyn(cf);

    if (old_ctx.dynamic && old_ctx.pool) {
        njt_destroy_pool(old_ctx.pool);
    }

    return NJT_OK;

error:
    *ctx = old_ctx;
    return NJT_ERROR;
}

static int njt_http_split_client_change_handler_internal(njt_str_t *key,
    njt_str_t *value,
    void *data,
    njt_str_t *out_msg)
{
    njt_http_split_clients_conf_t *sccf = (njt_http_split_clients_conf_t *)data;
    njt_http_split_clients_ctx_t *ctx;
    njt_http_split_clients_part_t *part;
    njt_uint_t i;
    njt_json_manager json_manager;
    njt_pool_t *tmp_pool;
    njt_int_t rc;
    njt_queue_t *values, *q;
    njt_json_element *f;
    ctx = (njt_http_split_clients_ctx_t *)sccf->ctx;
    part = ctx->parts.elts;
    uint32_t last_percentage;
    njt_rpc_result_t *rpc_result;
    njt_uint_t backend_count;
    bool backend_found;

    njt_memzero(&json_manager, sizeof(njt_json_manager));
    tmp_pool = NULL;
    rpc_result = njt_rpc_result_create();
    if (!rpc_result) {
        rc = NJT_ERROR;
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "can't create rpc result");
        goto end;
    }
    njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_SUCCESS);
    tmp_pool = njt_create_pool(NJT_DEFAULT_POOL_SIZE, njt_cycle->log);
    if (tmp_pool == NULL) {
        rc = NJT_ERROR;
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_MEM_ALLOC);
        goto rpc_msg;
    }

    rc = njt_json_2_structure(value, &json_manager, tmp_pool);
    if (rc != NJT_OK) {
        rc = NJT_ERROR;
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_JSON);
        goto rpc_msg;
    }

    njt_str_t sk;
    njt_str_set(&sk, "http");
    njt_json_element *out_element;
    rc = njt_struct_top_find(&json_manager, &sk, &out_element);
    if (rc == NJT_OK) {
        njt_str_set(&sk, "split_clients");
        njt_json_element *tmp_element;
        rc = njt_struct_find(out_element, &sk, &tmp_element);
        if (rc == NJT_OK && tmp_element->type == NJT_JSON_OBJ) {
            values = &tmp_element->objdata.datas;
            double sum = 0;
            double ori_percent = 0;
            njt_str_t tmp_err_str;
            for (i = 0; i < ctx->parts.nelts; i++) {
                backend_found = false;
                backend_count = 0;
                for (q = njt_queue_head(values); q != njt_queue_sentinel(values);
                    q = njt_queue_next(q)) {
                    f = njt_queue_data(q, njt_json_element, ele_queue);
                    if (f->key.len == SC_KEY_JSON_FIELD_LEN &&
                        njt_strncmp(SC_KEY_JSON_FIELD, f->key.data,
                            SC_KEY_JSON_FIELD_LEN) == 0) {
                        if (f->type != NJT_JSON_STR || f->strval.len < 2 || f->strval.data[0] != '$') {
                            rc = NJT_RPC_RSP_ERR_JSON;
                            njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_JSON);
                            njt_rpc_result_set_msg(rpc_result, (u_char *)"_key should be string started with $");
                            goto rpc_msg;
                        }
                        continue;
                    }
                    backend_count++;
                    if (
                        f->key.len == part[i].value.len &&
                        njt_strncmp(part[i].value.data, f->key.data, f->key.len) == 0) {
                        backend_found = true;
                    } else {
                        continue;
                    }

                    if (f->type == NJT_JSON_INT && f->intval >=0 ) {
                        sum += f->intval;
                    } else if (f->type == NJT_JSON_DOUBLE  && f->doubleval >=0) {
                        sum += f->doubleval;
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
                    *end = '\0';
                    njt_rpc_result_set_msg(rpc_result, tmp_err_str.data);
                    goto rpc_msg;
                }
                if (!backend_found) {
                    rc = NJT_RPC_RSP_ERR_JSON;
                    njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_JSON);
                    char *data_fmt_err = " not in post json data";
                    tmp_err_str.data = njt_pcalloc(tmp_pool, part[i].value.len + strlen(data_fmt_err) + 1);
                    njt_memcpy(tmp_err_str.data, part[i].value.data, part[i].value.len);
                    njt_memcpy(tmp_err_str.data + part[i].value.len, data_fmt_err, strlen(data_fmt_err));
                    tmp_err_str.data[part[i].value.len + strlen(data_fmt_err)] = '\0';
                    njt_rpc_result_set_msg(rpc_result, tmp_err_str.data);
                    goto rpc_msg;
                }
            }
            if (sum != 100) {
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "split clients set error: total percentage is not 100");
                rc = NJT_HTTP_SPLIT_CLIENT_ERR_TOTAL;
                njt_rpc_result_set_code(rpc_result, NJT_HTTP_SPLIT_CLIENT_ERR_TOTAL);
                njt_rpc_result_set_msg(rpc_result, (u_char *)"total percentage should be 100");
                goto rpc_msg;
            }
            last_percentage = 0;
            for (i = 0; i < ctx->parts.nelts; i++) {
                for (q = njt_queue_head(values); q != njt_queue_sentinel(values);
                    q = njt_queue_next(q)) {
                    f = njt_queue_data(q, njt_json_element, ele_queue);
                    if (f->key.len == SC_KEY_JSON_FIELD_LEN &&
                        njt_strncmp(SC_KEY_JSON_FIELD, f->key.data,
                            SC_KEY_JSON_FIELD_LEN) == 0) {
                        njt_http_split_client_update_sc_key(ctx, rpc_result, &f->strval);
                    }
                    if (!part[i].last && f->key.len == part[i].value.len &&
                        njt_strncmp(part[i].value.data, f->key.data, f->key.len) == 0) {
                        if (f->type == NJT_JSON_DOUBLE) {
                            ori_percent = f->doubleval;
                        } else if (f->type == NJT_JSON_INT) {
                            ori_percent = f->intval;
                        } else {
                            continue;
                        }
                        part[i].ori_percent = ori_percent * 100;
                        last_percentage +=
                            part[i].ori_percent * (uint64_t)0xffffffff / 10000;
                        part[i].percent = last_percentage;
                        continue;
                    }
                }
            }
        } else {
            rc = NJT_RPC_RSP_ERR_JSON;
            njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_JSON);
            njt_rpc_result_set_msg(rpc_result,
                (u_char *)"split_clients field is required");
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

static int njt_http_split_client_change_handler(njt_str_t *key,
    njt_str_t *value, void *data)
{
    return njt_http_split_client_change_handler_internal(key, value, data, NULL);
}

static u_char *njt_http_split_client_rpc_put_handler(njt_str_t *topic,
    njt_str_t *request,
    int *len, void *data)
{
    njt_str_t err_json_msg;
    njt_str_null(&err_json_msg);
    njt_http_split_client_change_handler_internal(topic, request, data,
        &err_json_msg);
    *len = err_json_msg.len;
    return err_json_msg.data;
}

static u_char *njt_http_split_client_rpc_get_handler(njt_str_t *topic,
    njt_str_t *request,
    int *len, void *data)
{
    njt_http_conf_ctx_t *conf_ctx;
    njt_http_split_clients_conf_t *sccf;
    njt_http_split_clients_ctx_t *ctx;
    njt_http_split_clients_part_t *part;
    njt_str_t json;
    njt_int_t rc;
    njt_pool_t *pool;
    njt_uint_t i;
    njt_json_manager json_manager;
    u_char *buf;

    conf_ctx =
        (njt_http_conf_ctx_t *)njt_get_conf(njt_cycle->conf_ctx, njt_http_module);
    sccf = conf_ctx->main_conf[njt_http_split_clients_module.ctx_index];

    if (!sccf->has_split_block) {
        buf = njt_calloc(2, njt_cycle->log);
        njt_memcpy(buf, "{}", 2);
        *len = 2;
        return buf;
    }

    njt_memzero(&json_manager, sizeof(njt_json_manager));
    pool = njt_create_pool(NJT_DEFAULT_POOL_SIZE, njt_cycle->log);
    if (pool == NULL) {
        *len = 0;
        return NULL;
    }

    njt_json_element *top = njt_json_obj_element(pool, njt_json_fast_key("http"));
    rc = njt_struct_top_add(&json_manager, top, NJT_JSON_OBJ, pool);
    if (rc != NJT_OK) {
        *len = 0;
        return NULL;
    }

    njt_json_element *sc =
        njt_json_obj_element(pool, njt_json_fast_key("split_clients"));
    njt_struct_add(top, sc, pool);

    ctx = (njt_http_split_clients_ctx_t *)sccf->ctx;

    njt_json_element *sc_key =
        njt_json_str_element(pool, njt_json_fast_key("_key"), &ctx->value.value);
    njt_struct_add(sc, sc_key, pool);

    part = ctx->parts.elts;
    double last_per = 10000;
    double part_per = 0;
    for (i = 0; i < ctx->parts.nelts; i++) {
        part_per = part[i].ori_percent;
        if (!part[i].last) {
            last_per -= part_per;
        } else {
            part_per = last_per;
        }
        njt_json_element *sci = njt_json_double_element(
            pool, part[i].value.data, part[i].value.len, part_per / 100.0);
        njt_struct_add(sc, sci, pool);
    }

    njt_structure_2_json(&json_manager, &json, pool);
    buf = njt_calloc(json.len, njt_cycle->log);
    if (buf == NULL) {
        *len = 0;
        goto out;
    }

    njt_memcpy(buf, json.data, json.len);
    *len = json.len;

out:
    if (pool != NULL) {
        njt_destroy_pool(pool);
    }

    return buf;
}

static njt_int_t njt_http_split_clients_init_worker(njt_cycle_t *cycle)
{
#if NJT_HTTP_KV_MODULE
    njt_http_conf_ctx_t *conf_ctx;
    njt_http_split_clients_conf_t *sccf;
    // return  when there is no http configuraton
    if (njt_http_split_clients_module.ctx_index == NJT_CONF_UNSET_UINT) {
        return NJT_OK;
    }
    conf_ctx =
        (njt_http_conf_ctx_t *)njt_get_conf(cycle->conf_ctx, njt_http_module);
    if (!conf_ctx) {
        return NJT_OK;
    }
    sccf = conf_ctx->main_conf[njt_http_split_clients_module.ctx_index];

    if (!sccf || !sccf->has_split_block) {
        return NJT_OK;
    }
    njt_str_t rpc_key = njt_string(DYN_TOPIC_REG_KEY);
    njt_kv_reg_handler_t h;
    njt_memzero(&h, sizeof(njt_kv_reg_handler_t));
    h.key = &rpc_key;
    h.rpc_get_handler = njt_http_split_client_rpc_get_handler;
    h.rpc_put_handler = njt_http_split_client_rpc_put_handler;
    h.handler = njt_http_split_client_change_handler;
    h.data=sccf;
    h.api_type = NJT_KV_API_TYPE_DECLATIVE;
    njt_kv_reg_handler(&h);

#endif
    return NJT_OK;
}

static njt_int_t njt_http_split_clients_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v,
    uintptr_t data)
{
    njt_http_split_clients_ctx_t *ctx = (njt_http_split_clients_ctx_t *)data;

    uint32_t hash;
    njt_str_t val;
    njt_uint_t i;
    njt_http_split_clients_part_t *part;

    *v = njt_http_variable_null_value;

    if (njt_http_complex_value(r, &ctx->value, &val) != NJT_OK) {
        return NJT_OK;
    }

    hash = njt_murmur_hash2(val.data, val.len);

    part = ctx->parts.elts;

    for (i = 0; i < ctx->parts.nelts; i++) {

        njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
            "http split: %uD %uD", hash, part[i].percent);

        if (hash < part[i].percent || part[i].last) {
            *v = part[i].value;
            return NJT_OK;
        }
    }

    return NJT_OK;
}

static char *njt_conf_split_clients_block(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    char *rv;
    uint32_t sum, last;
    njt_str_t *value, name;
    njt_uint_t i;
    njt_conf_t save;
    njt_http_variable_t *var;
    njt_http_split_clients_ctx_t *ctx;
    njt_http_split_clients_part_t *part;
    njt_http_compile_complex_value_t ccv;
    njt_http_split_clients_conf_t *sc_conf =
        (njt_http_split_clients_conf_t *)conf;

    ctx = njt_pcalloc(cf->pool, sizeof(njt_http_split_clients_ctx_t));
    if (ctx == NULL) {
        return NJT_CONF_ERROR;
    }

    sc_conf->ctx = ctx;
    sc_conf->has_split_block = 1;
    value = cf->args->elts;

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &ctx->value;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    name = value[2];

    if (name.data[0] != '$') {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "invalid variable name \"%V\"",
            &name);
        return NJT_CONF_ERROR;
    }

    name.len--;
    name.data++;

    var = njt_http_add_variable(cf, &name, NJT_HTTP_VAR_CHANGEABLE);
    if (var == NULL) {
        return NJT_CONF_ERROR;
    }

    var->get_handler = njt_http_split_clients_variable;
    var->data = (uintptr_t)ctx;

    if (njt_array_init(&ctx->parts, cf->pool, 2,
        sizeof(njt_http_split_clients_part_t)) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    save = *cf;
    cf->ctx = ctx;
    cf->handler = njt_http_split_clients;
    cf->handler_conf = conf;

    rv = njt_conf_parse(cf, NULL);

    *cf = save;

    if (rv != NJT_CONF_OK) {
        return rv;
    }

    sum = 0;
    last = 0;
    part = ctx->parts.elts;

    if (ctx->parts.nelts == 0 ) {
         njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                "should be at least one default \"*\" entry in config file");
            return NJT_CONF_ERROR;
    }
    
    if (!part[ctx->parts.nelts-1].last) {
         njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                "last entry in config file should be \"*\" ");
            return NJT_CONF_ERROR;
    }

    for (i = 0; i < ctx->parts.nelts; i++) {
        sum = part[i].percent ? sum + part[i].percent : 10000;
        if (sum > 10000) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                "percent total is greater than 100%%");
            return NJT_CONF_ERROR;
        }

        if (part[i].percent) {
            last += part[i].percent * (uint64_t)0xffffffff / 10000;
            part[i].percent = last;
        }
    }

    return rv;
}

static char *njt_http_split_clients(njt_conf_t *cf, njt_command_t *dummy,
    void *conf)
{
    njt_int_t n;
    njt_str_t *value;
    njt_http_split_clients_ctx_t *ctx;
    njt_http_split_clients_part_t *part;

    ctx = cf->ctx;
    value = cf->args->elts;

    part = njt_array_push(&ctx->parts);
    if (part == NULL) {
        return NJT_CONF_ERROR;
    }

    if (value[0].len == 1 && value[0].data[0] == '*') {
        part->percent = 0;
        part->last = true;
    } else {
        part->last = false;

        if (value[0].len == 0 || value[0].data[value[0].len - 1] != '%') {
            goto invalid;
        }

        n = njt_atofp(value[0].data, value[0].len - 1, 2);
        if (n == NJT_ERROR) {
            goto invalid;
        }

        part->ori_percent = (uint32_t)n;
        part->percent = (uint32_t)n;
    }

    part->value.len = value[1].len;
    part->value.valid = 1;
    part->value.no_cacheable = 0;
    part->value.not_found = 0;
    part->value.data = value[1].data;

    return NJT_CONF_OK;

invalid:

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "invalid percent value \"%V\"",
        &value[0]);
    return NJT_CONF_ERROR;
}
