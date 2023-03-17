#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_http_kv_module.h>
#include <njt_json_util.h>

#define DYN_TOPIC_PREFIX "/dyn/"
#define DYN_TOPIC_PREFIX_LEN 5
#define DYN_TOPIC_REG_KEY "http_split_clients_2"
#define DYN_TOPIC_REG_KEY_LEN 20

typedef struct
{
    uint32_t percent;
    njt_http_variable_value_t value;
    bool last;        // last part configued as  *
    njt_str_t kv_key; // for dynamic split client, use kv store
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

static u_char *split_rpc_handler(njt_str_t *topic, njt_str_t *request, int *len, void *data);
static int njt_sample(int ration);
static njt_int_t split_client_2_init_worker(njt_cycle_t *cycle);
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

    njt_null_command};

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
    split_client_2_init_worker,           /* init process */
    NULL,                                 /* init thread */
    NULL,                                 /* exit thread */
    NULL,                                 /* exit process */
    NULL,                                 /* exit master */
    NJT_MODULE_V1_PADDING};

static void *
njt_http_split_client_2_create_conf(njt_conf_t *cf)
{
    njt_http_split_clients_2_conf_t *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_split_clients_2_conf_t));

    if (conf == NULL)
    {
        return NULL;
    }

    return conf;
}

static int split_kv_change_handler(njt_str_t *key, njt_str_t *value, void *data)
{
    njt_http_split_clients_2_conf_t *sc2cf = (njt_http_split_clients_2_conf_t *)data;
    njt_http_split_clients_2_ctx_t *ctx;
    njt_http_split_clients_2_part_t *part;
    njt_uint_t i, offset, k_l;
    njt_json_manager json_manager;
    njt_pool_t *tmp_pool;
    njt_int_t rc;
    njt_queue_t *values, *q;
    njt_json_element *f;

    ctx = (njt_http_split_clients_2_ctx_t *)sc2cf->ctx;
    part = ctx->parts.elts;

    offset = 0;
    k_l = key->len;

    // if key is /dyn/..., remove /dyn/ prefix
    if (njt_strncmp(key->data, DYN_TOPIC_PREFIX, DYN_TOPIC_PREFIX_LEN) == 0)
    {
        for (i = DYN_TOPIC_PREFIX_LEN; i < key->len; i++)
        {
            if (key->data[i] == '/')
                break;
        }
        offset = DYN_TOPIC_PREFIX_LEN;
        k_l = i - DYN_TOPIC_PREFIX_LEN;
    }

    if (k_l == DYN_TOPIC_REG_KEY_LEN &&
        njt_strncmp(key->data + offset, DYN_TOPIC_REG_KEY, k_l) == 0)
    {
        tmp_pool = njt_create_pool(NJT_DEFAULT_POOL_SIZE, njt_cycle->log);
        if (tmp_pool == NULL)
        {
            return NJT_ERROR;
        }

        rc = njt_json_2_structure(value, &json_manager, tmp_pool);
        if (rc != NJT_OK)
        {
            njt_destroy_pool(tmp_pool);
            return NJT_ERROR;
        }

        njt_str_t sk;
        njt_str_set(&sk, "http");
        njt_json_element *out_element;
        rc = njt_struct_top_find(&json_manager, &sk, &out_element);
        if (rc == NJT_OK)
        {
            njt_str_set(&sk, "split_clients_2");
            njt_json_element *tmp_element;
            rc = njt_struct_find(out_element, &sk, &tmp_element);
            if (rc == NJT_OK && tmp_element->type == NJT_JSON_OBJ)
            {

                values = &tmp_element->objdata.datas;
                njt_uint_t sum = 0;
                for (q = njt_queue_head(values);
                     q != njt_queue_sentinel(values);
                     q = njt_queue_next(q))
                {
                    f = njt_queue_data(q, njt_json_element, ele_queue);
                    if (f->type == NJT_JSON_INT)
                    {
                        sum += f->intval;
                    }
                }
                if (sum > 100)
                {
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "split clients 2 set error: total percentage greater than 100");
                }
                else
                {
                    for (i = 0; i < ctx->parts.nelts; i++)
                    {
                        for (q = njt_queue_head(values);
                             q != njt_queue_sentinel(values);
                             q = njt_queue_next(q))
                        {
                            f = njt_queue_data(q, njt_json_element, ele_queue);
                            if (!part[i].last &&
                                f->type == NJT_JSON_INT &&
                                f->key.len == part[i].value.len &&
                                njt_strncmp(part[i].value.data, f->key.data, f->key.len) == 0)
                            {
                                part[i].percent = f->intval;
                                continue;
                            }
                        }
                    }
                }
            }
        }

        njt_destroy_pool(tmp_pool);
        return NJT_OK;
    }

    for (i = 0; i < ctx->parts.nelts; i++)
    {
        if (part[i].kv_key.len > 0)
        {
            if (njt_strncmp(key->data + offset, part[i].kv_key.data, k_l) == 0)
            {
                size_t vl = value->len;
                if (value->data[value->len - 1] == '%')
                {
                    vl--;
                }
                njt_int_t n = njt_atoi(value->data, vl);
                if (n > 0)
                {
                    part[i].percent = (uint32_t)n;
                }
                else
                {
                    part[i].percent = 0;
                }
            }
        }
    }
    return NJT_OK;
}

static u_char *split_rpc_handler(njt_str_t *topic, njt_str_t *request, int *len, void *data)
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
    if (!sc2cf->has_split_block)
    {
        msg = njt_calloc(2, njt_cycle->log);
        memcpy(msg, "{}", 2);
        *len = 2;
        return msg;
    }

    ctx = (njt_http_split_clients_2_ctx_t *)sc2cf->ctx;
    part = ctx->parts.elts;

    u_char p_s[4];
    njt_uint_t sum = 0;
    for (i = 0; i < ctx->parts.nelts; i++)
    {
        njt_memzero(p_s,4);
        sum += part[i].percent;
        ret_len += part[i].value.len;
        if (part[i].last)
        {
            njt_snprintf(p_s, 3, "%d", 100 - sum);
        }
        else
        {
            njt_snprintf(p_s, 3, "%d", part[i].percent);
        }
        ret_len += (njt_uint_t)strlen((const char *)p_s);
        ret_len += 4; //"":,
    }

    msg = njt_calloc(ret_len - 1, njt_cycle->log);
    pmsg = msg;
    msg = njt_snprintf(msg, json_h.len, "%s", json_h.data);
    for (i = 0; i < ctx->parts.nelts; i++)
    {

        *msg++ = '"';
        msg = njt_snprintf(msg, part[i].value.len, "%s", part[i].value.data);
        *msg++ = '"';
        *msg++ = ':';
        if (part[i].last)
        {
            msg = njt_snprintf(msg, 3, "%d", 100 - sum);
        }
        else
        {
            msg = njt_snprintf(msg, 3, "%d", part[i].percent);
        }
        *msg++ = ',';
    }
    msg--;
    msg = njt_snprintf(msg, json_t.len, "%s", json_t.data);
    *len = ret_len - 1;

    return pmsg;
}

static njt_int_t split_client_2_init_worker(njt_cycle_t *cycle)
{
    njt_http_conf_ctx_t *conf_ctx;
    njt_http_split_clients_2_conf_t *sc2cf;
    njt_http_split_clients_2_ctx_t *ctx;
    njt_http_split_clients_2_part_t *part;
    njt_uint_t i;

    if (njt_process != NJT_PROCESS_WORKER)
    {
        return NJT_OK;
    }
    // return  when there is no http configuraton
    if (njt_http_split_clients_2_module.ctx_index == NJT_CONF_UNSET_UINT)
    {
        return NJT_OK;
    }
    conf_ctx = (njt_http_conf_ctx_t *)njt_get_conf(cycle->conf_ctx, njt_http_module);
    sc2cf = conf_ctx->main_conf[njt_http_split_clients_2_module.ctx_index];

    if (!sc2cf->has_split_block)
    {
        return NJT_OK;
    }

    ctx = (njt_http_split_clients_2_ctx_t *)sc2cf->ctx;
    part = ctx->parts.elts;

    for (i = 0; i < ctx->parts.nelts; i++)
    {
        if (part[i].kv_key.len > 0)
        {
            njt_reg_kv_change_handler(&part[i].kv_key, split_kv_change_handler, NULL, sc2cf);
        }
    }

    njt_str_t rpc_key = njt_string(DYN_TOPIC_REG_KEY);
    njt_reg_kv_change_handler(&rpc_key, split_kv_change_handler, split_rpc_handler, sc2cf);

    return NJT_OK;
}

/*
 * use random to do data sample
 * input: ration, sample ration, a integer between 0-100.
 * output: 1(true) means match, should be sampled, 0(false)
 * */
static int njt_sample(int ration)
{
    long long r = random();
    double r2 = r * 100.0;
    double f = r2 / RAND_MAX;
    if (f > (100 - ration))
        return 1;
    return 0;
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

    for (i = 0; i < ctx->parts.nelts; i++)
    {
        percent = part[i].percent;
        if (percent == 0 && !part[i].last)
        {
            continue;
        }
        if (njt_sample(percent) || part[i].last)
        {
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
    if (ctx == NULL)
    {
        return NJT_CONF_ERROR;
    }

    sc2_conf->ctx = ctx;
    sc2_conf->has_split_block = 1;
    value = cf->args->elts;

    name = value[1];

    if (name.data[0] != '$')
    {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &name);
        return NJT_CONF_ERROR;
    }

    name.len--;
    name.data++;

    var = njt_http_add_variable(cf, &name, NJT_HTTP_VAR_CHANGEABLE);
    if (var == NULL)
    {
        return NJT_CONF_ERROR;
    }

    var->get_handler = njt_http_split_clients_2_variable;
    var->data = (uintptr_t)ctx;

    if (njt_array_init(&ctx->parts, cf->pool, 2,
                       sizeof(njt_http_split_clients_2_part_t)) != NJT_OK)
    {
        return NJT_CONF_ERROR;
    }

    save = *cf;
    cf->ctx = ctx;
    cf->handler = njt_http_split_clients_2;
    cf->handler_conf = conf;

    rv = njt_conf_parse(cf, NULL);

    *cf = save;

    if (rv != NJT_CONF_OK)
    {
        return rv;
    }

    sum = 0;
    part = ctx->parts.elts;

    if (ctx->parts.nelts != 2)
    {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "split clients 2 should be configured with 2 groups, check if there are more than 2 lines");
        return NJT_CONF_ERROR;
    }

    if (part[0].last || !part[1].last)
    {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "split clients 2 should be configured with 2 groups only, and second line should be started with * ");
        return NJT_CONF_ERROR;
    }

    for (i = 0; i < ctx->parts.nelts; i++)
    {
        sum += part[i].percent; // if use kv_http_ as percent, percentage is 0
        if (sum > 100)
        {
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
    if (part == NULL)
    {
        return NJT_CONF_ERROR;
    }
    part->kv_key.data = NULL;
    part->kv_key.len = 0;

    if (cf->args->nelts > 2)
    {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "split_clients_2 config error, semicolon is missing", &value[0]);

        return NJT_CONF_ERROR;
    }
    if (value[0].len == 1 && value[0].data[0] == '*')
    {
        part->last = true;
        part->percent = 0;
    }
    else
    {
        part->last = false;
        // if use dynamic split client , first field is key in kvstore, such as $kv_http_var1
        if (value[0].len > 0 && value[0].data[0] == '$')
        {
            part->kv_key.len = value[0].len - 1;
            part->kv_key.data = value[0].data + 1;
            part->percent = 0;
        }
        else
        {
            if (value[0].len == 0 || value[0].data[value[0].len - 1] != '%')
            {
                goto invalid;
            }

            if (value[0].data[0] == '0' && value[0].len == 2)
            {
                part->percent = 0;
            }
            n = njt_atoi(value[0].data, value[0].len - 1);
            if (n == NJT_ERROR)
            {
                goto invalid;
            }

            part->percent = (uint32_t)n;
        }
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
