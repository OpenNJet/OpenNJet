#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_http_kv_module.h>

#define DYN_TOPIC_PREFIX "/dyn/"
#define DYN_TOPIC_PREFIX_LEN 5

typedef struct
{
    uint32_t percent;
    njt_http_variable_value_t value;
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

    for (i = 0; i < ctx->parts.nelts; i++)
    {
        if (part[i].kv_key.len > 0)
        {
            if (njt_strncmp(key->data + offset, part[i].kv_key.data, k_l) == 0)
            {
                njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "kv change callback %v:%v", key, value);

                size_t vl = value->len;
                if (value->data[value->len - 1] == '%')
                {
                    vl--;
                }
                njt_int_t n = njt_atofp(value->data, vl, 2);
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

    if (!sc2cf->has_split_block) {
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
        percent = part[i].percent / 100;
        if (part[i].kv_key.len > 0 && percent == 0)
        {
            continue;
        }
        if (njt_sample(percent) || percent == 0)
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
    sc2_conf->has_split_block=1;
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

    for (i = 0; i < ctx->parts.nelts; i++)
    {
        sum = part[i].percent ? sum + part[i].percent : 10000;
        if (sum > 10000)
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

    if (value[0].len == 1 && value[0].data[0] == '*')
    {
        part->percent = 0;
    }
    else
    {
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

            n = njt_atofp(value[0].data, value[0].len - 1, 2);
            if (n == NJT_ERROR || n == 0)
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
                       "invalid percent value \"%V\"", &value[0]);
    return NJT_CONF_ERROR;
}
