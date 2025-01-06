#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"

#include <njt_http_kv_module.h>
#include "njt_http_redis2_util.h"


static size_t njt_get_num_size(uint64_t i);


char *
njt_http_redis2_set_complex_value_slot(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    char                             *p = conf;
    njt_http_complex_value_t        **field;
    njt_str_t                        *value;
    njt_http_compile_complex_value_t  ccv;

    field = (njt_http_complex_value_t **) (p + cmd->offset);

    if (*field) {
        return "is duplicate";
    }

    *field = njt_palloc(cf->pool, sizeof(njt_http_complex_value_t));
    if (*field == NULL) {
        return NJT_CONF_ERROR;
    }

    value = cf->args->elts;

    if (value[1].len == 0) {
        njt_memzero(*field, sizeof(njt_http_complex_value_t));
        return NJT_OK;
    }

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = *field;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


njt_http_upstream_srv_conf_t *
njt_http_redis2_upstream_add(njt_http_request_t *r, njt_url_t *url)
{
    njt_http_upstream_main_conf_t  *umcf;
    njt_http_upstream_srv_conf_t  **uscfp;
    njt_uint_t                      i;

    umcf = njt_http_get_module_main_conf(r, njt_http_upstream_module);

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        if (uscfp[i]->host.len != url->host.len
            || njt_strncasecmp(uscfp[i]->host.data, url->host.data,
                               url->host.len) != 0)
        {
            dd("upstream_add: host not match");
            continue;
        }

        if (uscfp[i]->port != url->port) {
            dd("upstream_add: port not match: %d != %d",
               (int) uscfp[i]->port, (int) url->port);
            continue;
        }

        return uscfp[i];
    }

    dd("no upstream found: %.*s", (int) url->host.len, url->host.data);

    return NULL;
}


static size_t
njt_get_num_size(uint64_t i)
{
    size_t          n = 0;

    do {
        i = i / 10;
        n++;
    } while (i > 0);

    return n;
}


njt_int_t
njt_http_redis2_build_query(njt_http_request_t *r, njt_array_t *queries,
    njt_buf_t **b)
{
    njt_uint_t                       i, j;
    njt_uint_t                       n;
    njt_str_t                       *arg;
    njt_str_t                        cmd_str;
    njt_array_t                     *args;
    size_t                           len;
    njt_array_t                    **query_args;
    njt_http_complex_value_t       **complex_arg;
    u_char                          *p, *tmp_val, *tmp_p;
    njt_str_t                        redis_key, redis_passwd;
    njt_http_redis2_loc_conf_t      *rlcf;
    u_char                           tmp_key[200];  


    rlcf = njt_http_get_module_loc_conf(r, njt_http_redis2_module);

    query_args = rlcf->queries->elts;

    n = 0;
    for (i = 0; i < rlcf->queries->nelts; i++) {
        for (j = 0; j < query_args[i]->nelts; j++) {
            n++;
        }
    }

    args = njt_array_create(r->pool, n, sizeof(njt_str_t));

    if (args == NULL) {
        return NJT_ERROR;
    }

    len = 0;
    n = 0;

    for (i = 0; i < rlcf->queries->nelts; i++) {
        complex_arg = query_args[i]->elts;

        len += sizeof("*") - 1
             + njt_get_num_size(query_args[i]->nelts)
             + sizeof("\r\n") - 1
             ;

        for (j = 0; j < query_args[i]->nelts; j++) {
            n++;

            arg = njt_array_push(args);
            if (arg == NULL) {
                return NJT_ERROR;
            }

            if (njt_http_complex_value(r, complex_arg[j], arg) != NJT_OK) {
                return NJT_ERROR;
            }

            //add filter, if arg is prefix redis_pass_, then get real password from kv
            if(arg->len > njt_strlen("redis_pass_")
                && 0 == njt_strncmp(arg->data, "redis_pass_", njt_strlen("redis_pass_"))){
                //get real redis password from kv
                tmp_p = njt_snprintf(tmp_key, 200, "kv_http_%V", arg);
                redis_key.data = tmp_key;
                redis_key.len = tmp_p - tmp_key;

                if(NJT_OK == njt_db_kv_get(&redis_key, &redis_passwd)){
                    tmp_val = njt_pcalloc(r->pool, redis_passwd.len);
                    if(NULL == tmp_val){
                        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, 
                            "redis password from kv malloc error, key:%V", arg);
                        return NJT_ERROR;
                    }
                    
                    arg->data = tmp_val;
                    arg->len = redis_passwd.len;
                    njt_memcpy(tmp_val, redis_passwd.data, arg->len);
                    njt_log_error(NJT_LOG_INFO, r->connection->log, 0, 
                            "redis password is:%V from kv", arg);

                }
            }

            len += sizeof("$") - 1
                 + njt_get_num_size(arg->len)
                 + sizeof("\r\n") - 1
                 + arg->len
                 + sizeof("\r\n") - 1
                 ;
        }
    }

    *b = njt_create_temp_buf(r->pool, len);
    if (*b == NULL) {
        return NJT_ERROR;
    }

    p = (*b)->last;

    arg = args->elts;

    n = 0;
    for (i = 0; i < rlcf->queries->nelts; i++) {
        *p++ = '*';
        p = njt_sprintf(p, "%uz", query_args[i]->nelts);
        *p++ = '\r'; *p++ = '\n';

        for (j = 0; j < query_args[i]->nelts; j++) {
            *p++ = '$';
            p = njt_sprintf(p, "%uz", arg[n].len);
            *p++ = '\r'; *p++ = '\n';
            p = njt_copy(p, arg[n].data, arg[n].len);
            *p++ = '\r'; *p++ = '\n';

            n++;
        }
    }

    dd("query: %.*s", (int) (p - (*b)->pos), (*b)->pos);

    cmd_str.data = (*b)->pos;
    cmd_str.len = len;
    njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                    "===============redis2 cmd:%V",
                    &cmd_str);


    if (p - (*b)->pos != (ssize_t) len) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "redis2: redis2_query buffer error %uz != %uz",
                      (size_t) (p - (*b)->pos), len);

        return NJT_ERROR;
    }

    (*b)->last = p;

    return NJT_OK;
}

