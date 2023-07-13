
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


static njt_int_t njt_http_script_init_arrays(njt_http_script_compile_t *sc);
static njt_int_t njt_http_script_done(njt_http_script_compile_t *sc);
static njt_int_t njt_http_script_add_copy_code(njt_http_script_compile_t *sc,
    njt_str_t *value, njt_uint_t last);
static njt_int_t njt_http_script_add_var_code(njt_http_script_compile_t *sc,
    njt_str_t *name);
static njt_int_t njt_http_script_add_args_code(njt_http_script_compile_t *sc);
#if (NJT_PCRE)
static njt_int_t njt_http_script_add_capture_code(njt_http_script_compile_t *sc,
    njt_uint_t n);
#endif
static njt_int_t
    njt_http_script_add_full_name_code(njt_http_script_compile_t *sc);
static size_t njt_http_script_full_name_len_code(njt_http_script_engine_t *e);
static void njt_http_script_full_name_code(njt_http_script_engine_t *e);


#define njt_http_script_exit  (u_char *) &njt_http_script_exit_code

static uintptr_t njt_http_script_exit_code = (uintptr_t) NULL;


void
njt_http_script_flush_complex_value(njt_http_request_t *r,
    njt_http_complex_value_t *val)
{
    njt_uint_t *index;

    index = val->flushes;

    if (index) {
        while (*index != (njt_uint_t) -1) {

            if (r->variables[*index].no_cacheable) {
                r->variables[*index].valid = 0;
                r->variables[*index].not_found = 0;
            }

            index++;
        }
    }
}


njt_int_t
njt_http_complex_value(njt_http_request_t *r, njt_http_complex_value_t *val,
    njt_str_t *value)
{
    size_t                        len;
    njt_http_script_code_pt       code;
    njt_http_script_len_code_pt   lcode;
    njt_http_script_engine_t      e;

    if (val->lengths == NULL) {
        *value = val->value;
        return NJT_OK;
    }

    njt_http_script_flush_complex_value(r, val);

    njt_memzero(&e, sizeof(njt_http_script_engine_t));

    e.ip = val->lengths;
    e.request = r;
    e.flushed = 1;

    len = 0;

    while (*(uintptr_t *) e.ip) {
        lcode = *(njt_http_script_len_code_pt *) e.ip;
        len += lcode(&e);
    }

    value->len = len;
    value->data = njt_pnalloc(r->pool, len);
    if (value->data == NULL) {
        return NJT_ERROR;
    }

    e.ip = val->values;
    e.pos = value->data;
    e.buf = *value;

    while (*(uintptr_t *) e.ip) {
        code = *(njt_http_script_code_pt *) e.ip;
        code((njt_http_script_engine_t *) &e);
    }

    *value = e.buf;

    return NJT_OK;
}


size_t
njt_http_complex_value_size(njt_http_request_t *r,
    njt_http_complex_value_t *val, size_t default_value)
{
    size_t     size;
    njt_str_t  value;

    if (val == NULL) {
        return default_value;
    }

    if (val->lengths == NULL) {
        return val->u.size;
    }

    if (njt_http_complex_value(r, val, &value) != NJT_OK) {
        return default_value;
    }

    size = njt_parse_size(&value);

    if (size == (size_t) NJT_ERROR) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "invalid size \"%V\"", &value);
        return default_value;
    }

    return size;
}


njt_int_t
njt_http_compile_complex_value(njt_http_compile_complex_value_t *ccv)
{
    njt_str_t                  *v;
    njt_uint_t                  i, n, nv, nc;
    njt_array_t                 flushes, lengths, values, *pf, *pl, *pv;
    njt_http_script_compile_t   sc;

    v = ccv->value;

    nv = 0;
    nc = 0;

    for (i = 0; i < v->len; i++) {
        if (v->data[i] == '$') {
            if (v->data[i + 1] >= '1' && v->data[i + 1] <= '9') {
                nc++;

            } else {
                nv++;
            }
        }
    }

    if ((v->len == 0 || v->data[0] != '$')
        && (ccv->conf_prefix || ccv->root_prefix))
    {
        if (njt_conf_full_name(ccv->cf->cycle, v, ccv->conf_prefix) != NJT_OK) {
            return NJT_ERROR;
        }

        ccv->conf_prefix = 0;
        ccv->root_prefix = 0;
    }

    ccv->complex_value->value = *v;
    ccv->complex_value->flushes = NULL;
    ccv->complex_value->lengths = NULL;
    ccv->complex_value->values = NULL;  

    if (nv == 0 && nc == 0) {
        return NJT_OK;
    }

    n = nv + 1;

    if (njt_array_init(&flushes, ccv->cf->pool, n, sizeof(njt_uint_t))
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    n = nv * (2 * sizeof(njt_http_script_copy_code_t)
                  + sizeof(njt_http_script_var_code_t))
        + sizeof(uintptr_t);

    if (njt_array_init(&lengths, ccv->cf->pool, n, 1) != NJT_OK) {
        return NJT_ERROR;
    }

    n = (nv * (2 * sizeof(njt_http_script_copy_code_t)
                   + sizeof(njt_http_script_var_code_t))
                + sizeof(uintptr_t)
                + v->len
                + sizeof(uintptr_t) - 1)
            & ~(sizeof(uintptr_t) - 1);

    if (njt_array_init(&values, ccv->cf->pool, n, 1) != NJT_OK) {
        return NJT_ERROR;
    }

    pf = &flushes;
    pl = &lengths;
    pv = &values;

    njt_memzero(&sc, sizeof(njt_http_script_compile_t));

    sc.cf = ccv->cf;
    sc.source = v;
    sc.flushes = &pf;
    sc.lengths = &pl;
    sc.values = &pv;
    sc.complete_lengths = 1;
    sc.complete_values = 1;
    sc.zero = ccv->zero;
    sc.conf_prefix = ccv->conf_prefix;
    sc.root_prefix = ccv->root_prefix;

    if (njt_http_script_compile(&sc) != NJT_OK) {
        return NJT_ERROR;
    }

    if (flushes.nelts) {
        ccv->complex_value->flushes = flushes.elts;
        ccv->complex_value->flushes[flushes.nelts] = (njt_uint_t) -1;
    }

    ccv->complex_value->lengths = lengths.elts;
    ccv->complex_value->values = values.elts;

    return NJT_OK;
}


char *
njt_http_set_complex_value_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char  *p = conf;

    njt_str_t                          *value;
    njt_http_complex_value_t          **cv;
    njt_http_compile_complex_value_t    ccv;

    cv = (njt_http_complex_value_t **) (p + cmd->offset);

    if (*cv != NJT_CONF_UNSET_PTR && *cv != NULL) {
        return "is duplicate";
    }

    *cv = njt_palloc(cf->pool, sizeof(njt_http_complex_value_t));
    if (*cv == NULL) {
        return NJT_CONF_ERROR;
    }

#if (NJT_HTTP_DYNAMIC_LOC)
    njt_memzero(*cv, sizeof(njt_http_complex_value_t));
    if(cf->limit_dynamic == 1){
        (*cv)->dynamic = 1;
        (*cv)->pool = cf->pool;
    }
#endif

    value = cf->args->elts;

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = *cv;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


char *
njt_http_set_complex_value_zero_slot(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    char  *p = conf;

    njt_str_t                          *value;
    njt_http_complex_value_t          **cv;
    njt_http_compile_complex_value_t    ccv;

    cv = (njt_http_complex_value_t **) (p + cmd->offset);

    if (*cv != NJT_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    *cv = njt_palloc(cf->pool, sizeof(njt_http_complex_value_t));
    if (*cv == NULL) {
        return NJT_CONF_ERROR;
    }

    value = cf->args->elts;

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = *cv;
    ccv.zero = 1;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


char *
njt_http_set_complex_value_size_slot(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    char  *p = conf;

    char                      *rv;
    njt_http_complex_value_t  *cv;

    rv = njt_http_set_complex_value_slot(cf, cmd, conf);

    if (rv != NJT_CONF_OK) {
        return rv;
    }

    cv = *(njt_http_complex_value_t **) (p + cmd->offset);

    if (cv->lengths) {
        return NJT_CONF_OK;
    }

    cv->u.size = njt_parse_size(&cv->value);
    if (cv->u.size == (size_t) NJT_ERROR) {
        return "invalid value";
    }

    return NJT_CONF_OK;
}


njt_int_t
njt_http_test_predicates(njt_http_request_t *r, njt_array_t *predicates)
{
    njt_str_t                  val;
    njt_uint_t                 i;
    njt_http_complex_value_t  *cv;

    if (predicates == NULL) {
        return NJT_OK;
    }

    cv = predicates->elts;

    for (i = 0; i < predicates->nelts; i++) {
        if (njt_http_complex_value(r, &cv[i], &val) != NJT_OK) {
            return NJT_ERROR;
        }

        if (val.len && (val.len != 1 || val.data[0] != '0')) {
            return NJT_DECLINED;
        }
    }

    return NJT_OK;
}


njt_int_t
njt_http_test_required_predicates(njt_http_request_t *r,
    njt_array_t *predicates)
{
    njt_str_t                  val;
    njt_uint_t                 i;
    njt_http_complex_value_t  *cv;

    if (predicates == NULL) {
        return NJT_OK;
    }

    cv = predicates->elts;

    for (i = 0; i < predicates->nelts; i++) {
        if (njt_http_complex_value(r, &cv[i], &val) != NJT_OK) {
            return NJT_ERROR;
        }

        if (val.len == 0 || (val.len == 1 && val.data[0] == '0')) {
            return NJT_DECLINED;
        }
    }

    return NJT_OK;
}


char *
njt_http_set_predicate_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char  *p = conf;

    njt_str_t                          *value;
    njt_uint_t                          i;
    njt_array_t                       **a;
    njt_http_complex_value_t           *cv;
    njt_http_compile_complex_value_t    ccv;

    a = (njt_array_t **) (p + cmd->offset);

    if (*a == NJT_CONF_UNSET_PTR) {
        *a = njt_array_create(cf->pool, 1, sizeof(njt_http_complex_value_t));
        if (*a == NULL) {
            return NJT_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        cv = njt_array_push(*a);
        if (cv == NULL) {
            return NJT_CONF_ERROR;
        }

        njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[i];
        ccv.complex_value = cv;

        if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
            return NJT_CONF_ERROR;
        }
    }

    return NJT_CONF_OK;
}


njt_uint_t
njt_http_script_variables_count(njt_str_t *value)
{
    njt_uint_t  i, n;

    for (n = 0, i = 0; i < value->len; i++) {
        if (value->data[i] == '$') {
            n++;
        }
    }

    return n;
}


njt_int_t
njt_http_script_compile(njt_http_script_compile_t *sc)
{
    u_char       ch;
    njt_str_t    name;
    njt_uint_t   i, bracket;

    if (njt_http_script_init_arrays(sc) != NJT_OK) {
        return NJT_ERROR;
    }

    for (i = 0; i < sc->source->len; /* void */ ) {

        name.len = 0;

        if (sc->source->data[i] == '$') {

            if (++i == sc->source->len) {
                goto invalid_variable;
            }

            if (sc->source->data[i] >= '1' && sc->source->data[i] <= '9') {
#if (NJT_PCRE)
                njt_uint_t  n;

                n = sc->source->data[i] - '0';

                if (sc->captures_mask & ((njt_uint_t) 1 << n)) {
                    sc->dup_capture = 1;
                }

                sc->captures_mask |= (njt_uint_t) 1 << n;

                if (njt_http_script_add_capture_code(sc, n) != NJT_OK) {
                    return NJT_ERROR;
                }

                i++;

                continue;
#else
                njt_conf_log_error(NJT_LOG_EMERG, sc->cf, 0,
                                   "using variable \"$%c\" requires "
                                   "PCRE library", sc->source->data[i]);
                return NJT_ERROR;
#endif
            }

            if (sc->source->data[i] == '{') {
                bracket = 1;

                if (++i == sc->source->len) {
                    goto invalid_variable;
                }

                name.data = &sc->source->data[i];

            } else {
                bracket = 0;
                name.data = &sc->source->data[i];
            }

            for ( /* void */ ; i < sc->source->len; i++, name.len++) {
                ch = sc->source->data[i];

                if (ch == '}' && bracket) {
                    i++;
                    bracket = 0;
                    break;
                }

                if ((ch >= 'A' && ch <= 'Z')
                    || (ch >= 'a' && ch <= 'z')
                    || (ch >= '0' && ch <= '9')
                    || ch == '_')
                {
                    continue;
                }

                break;
            }

            if (bracket) {
                njt_conf_log_error(NJT_LOG_EMERG, sc->cf, 0,
                                   "the closing bracket in \"%V\" "
                                   "variable is missing", &name);
                return NJT_ERROR;
            }

            if (name.len == 0) {
                goto invalid_variable;
            }

            sc->variables++;

            if (njt_http_script_add_var_code(sc, &name) != NJT_OK) {
                return NJT_ERROR;
            }

            continue;
        }

        if (sc->source->data[i] == '?' && sc->compile_args) {
            sc->args = 1;
            sc->compile_args = 0;

            if (njt_http_script_add_args_code(sc) != NJT_OK) {
                return NJT_ERROR;
            }

            i++;

            continue;
        }

        name.data = &sc->source->data[i];

        while (i < sc->source->len) {

            if (sc->source->data[i] == '$') {
                break;
            }

            if (sc->source->data[i] == '?') {

                sc->args = 1;

                if (sc->compile_args) {
                    break;
                }
            }

            i++;
            name.len++;
        }

        sc->size += name.len;

        if (njt_http_script_add_copy_code(sc, &name, (i == sc->source->len))
            != NJT_OK)
        {
            return NJT_ERROR;
        }
    }

    return njt_http_script_done(sc);

invalid_variable:

    njt_conf_log_error(NJT_LOG_EMERG, sc->cf, 0, "invalid variable name");

    return NJT_ERROR;
}


u_char *
njt_http_script_run(njt_http_request_t *r, njt_str_t *value,
    void *code_lengths, size_t len, void *code_values)
{
    njt_uint_t                    i;
    njt_http_script_code_pt       code;
    njt_http_script_len_code_pt   lcode;
    njt_http_script_engine_t      e;
    njt_http_core_main_conf_t    *cmcf;

    cmcf = njt_http_get_module_main_conf(r, njt_http_core_module);

    for (i = 0; i < cmcf->variables.nelts; i++) {
        if (r->variables[i].no_cacheable) {
            r->variables[i].valid = 0;
            r->variables[i].not_found = 0;
        }
    }

    njt_memzero(&e, sizeof(njt_http_script_engine_t));

    e.ip = code_lengths;
    e.request = r;
    e.flushed = 1;

    while (*(uintptr_t *) e.ip) {
        lcode = *(njt_http_script_len_code_pt *) e.ip;
        len += lcode(&e);
    }


    value->len = len;
    value->data = njt_pnalloc(r->pool, len);
    if (value->data == NULL) {
        return NULL;
    }

    e.ip = code_values;
    e.pos = value->data;

    while (*(uintptr_t *) e.ip) {
        code = *(njt_http_script_code_pt *) e.ip;
        code((njt_http_script_engine_t *) &e);
    }

    return e.pos;
}


void
njt_http_script_flush_no_cacheable_variables(njt_http_request_t *r,
    njt_array_t *indices)
{
    njt_uint_t  n, *index;

    if (indices) {
        index = indices->elts;
        for (n = 0; n < indices->nelts; n++) {
            if (r->variables[index[n]].no_cacheable) {
                r->variables[index[n]].valid = 0;
                r->variables[index[n]].not_found = 0;
            }
        }
    }
}


static njt_int_t
njt_http_script_init_arrays(njt_http_script_compile_t *sc)
{
    njt_uint_t   n;

    if (sc->flushes && *sc->flushes == NULL) {
        n = sc->variables ? sc->variables : 1;
        *sc->flushes = njt_array_create(sc->cf->pool, n, sizeof(njt_uint_t));
        if (*sc->flushes == NULL) {
            return NJT_ERROR;
        }
    }

    if (*sc->lengths == NULL) {
        n = sc->variables * (2 * sizeof(njt_http_script_copy_code_t)
                             + sizeof(njt_http_script_var_code_t))
            + sizeof(uintptr_t);

        *sc->lengths = njt_array_create(sc->cf->pool, n, 1);
        if (*sc->lengths == NULL) {
            return NJT_ERROR;
        }
    }

    if (*sc->values == NULL) {
        n = (sc->variables * (2 * sizeof(njt_http_script_copy_code_t)
                              + sizeof(njt_http_script_var_code_t))
                + sizeof(uintptr_t)
                + sc->source->len
                + sizeof(uintptr_t) - 1)
            & ~(sizeof(uintptr_t) - 1);

        *sc->values = njt_array_create(sc->cf->pool, n, 1);
        if (*sc->values == NULL) {
            return NJT_ERROR;
        }
    }

    sc->variables = 0;

    return NJT_OK;
}


static njt_int_t
njt_http_script_done(njt_http_script_compile_t *sc)
{
    njt_str_t    zero;
    uintptr_t   *code;

    if (sc->zero) {

        zero.len = 1;
        zero.data = (u_char *) "\0";

        if (njt_http_script_add_copy_code(sc, &zero, 0) != NJT_OK) {
            return NJT_ERROR;
        }
    }

    if (sc->conf_prefix || sc->root_prefix) {
        if (njt_http_script_add_full_name_code(sc) != NJT_OK) {
            return NJT_ERROR;
        }
    }

    if (sc->complete_lengths) {
        code = njt_http_script_add_code(*sc->lengths, sizeof(uintptr_t), NULL);
        if (code == NULL) {
            return NJT_ERROR;
        }

        *code = (uintptr_t) NULL;
    }

    if (sc->complete_values) {
        code = njt_http_script_add_code(*sc->values, sizeof(uintptr_t),
                                        &sc->main);
        if (code == NULL) {
            return NJT_ERROR;
        }

        *code = (uintptr_t) NULL;
    }

    return NJT_OK;
}


void *
njt_http_script_start_code(njt_pool_t *pool, njt_array_t **codes, size_t size)
{
    if (*codes == NULL) {
        *codes = njt_array_create(pool, 256, 1);
        if (*codes == NULL) {
            return NULL;
        }
    }

    return njt_array_push_n(*codes, size);
}


void *
njt_http_script_add_code(njt_array_t *codes, size_t size, void *code)
{
    u_char  *elts, **p;
    void    *new;

    elts = codes->elts;

    new = njt_array_push_n(codes, size);
    if (new == NULL) {
        return NULL;
    }

    if (code) {
        if (elts != codes->elts) {
            p = code;
            *p += (u_char *) codes->elts - elts;
        }
    }

    return new;
}


static njt_int_t
njt_http_script_add_copy_code(njt_http_script_compile_t *sc, njt_str_t *value,
    njt_uint_t last)
{
    u_char                       *p;
    size_t                        size, len, zero;
    njt_http_script_copy_code_t  *code;

    zero = (sc->zero && last);
    len = value->len + zero;

    code = njt_http_script_add_code(*sc->lengths,
                                    sizeof(njt_http_script_copy_code_t), NULL);
    if (code == NULL) {
        return NJT_ERROR;
    }

    code->code = (njt_http_script_code_pt) (void *)
                                                 njt_http_script_copy_len_code;
    code->len = len;

    size = (sizeof(njt_http_script_copy_code_t) + len + sizeof(uintptr_t) - 1)
            & ~(sizeof(uintptr_t) - 1);

    code = njt_http_script_add_code(*sc->values, size, &sc->main);
    if (code == NULL) {
        return NJT_ERROR;
    }

    code->code = njt_http_script_copy_code;
    code->len = len;

    p = njt_cpymem((u_char *) code + sizeof(njt_http_script_copy_code_t),
                   value->data, value->len);

    if (zero) {
        *p = '\0';
        sc->zero = 0;
    }

    return NJT_OK;
}


size_t
njt_http_script_copy_len_code(njt_http_script_engine_t *e)
{
    njt_http_script_copy_code_t  *code;

    code = (njt_http_script_copy_code_t *) e->ip;

    e->ip += sizeof(njt_http_script_copy_code_t);

    return code->len;
}


void
njt_http_script_copy_code(njt_http_script_engine_t *e)
{
    u_char                       *p;
    njt_http_script_copy_code_t  *code;

    code = (njt_http_script_copy_code_t *) e->ip;

    p = e->pos;

    if (!e->skip) {
        e->pos = njt_copy(p, e->ip + sizeof(njt_http_script_copy_code_t),
                          code->len);
    }

    e->ip += sizeof(njt_http_script_copy_code_t)
          + ((code->len + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1));

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script copy: \"%*s\"", e->pos - p, p);
}


static njt_int_t
njt_http_script_add_var_code(njt_http_script_compile_t *sc, njt_str_t *name)
{
    njt_int_t                    index, *p;
    njt_http_script_var_code_t  *code;

    index = njt_http_get_variable_index(sc->cf, name);

    if (index == NJT_ERROR) {
        return NJT_ERROR;
    }

    if (sc->flushes) {
        p = njt_array_push(*sc->flushes);
        if (p == NULL) {
            return NJT_ERROR;
        }

        *p = index;
    }

    code = njt_http_script_add_code(*sc->lengths,
                                    sizeof(njt_http_script_var_code_t), NULL);
    if (code == NULL) {
        return NJT_ERROR;
    }

    code->code = (njt_http_script_code_pt) (void *)
                                             njt_http_script_copy_var_len_code;
    code->index = (uintptr_t) index;

    code = njt_http_script_add_code(*sc->values,
                                    sizeof(njt_http_script_var_code_t),
                                    &sc->main);
    if (code == NULL) {
        return NJT_ERROR;
    }

    code->code = njt_http_script_copy_var_code;
    code->index = (uintptr_t) index;

    return NJT_OK;
}


size_t
njt_http_script_copy_var_len_code(njt_http_script_engine_t *e)
{
    njt_http_variable_value_t   *value;
    njt_http_script_var_code_t  *code;

    code = (njt_http_script_var_code_t *) e->ip;

    e->ip += sizeof(njt_http_script_var_code_t);

    if (e->flushed) {
        value = njt_http_get_indexed_variable(e->request, code->index);

    } else {
        value = njt_http_get_flushed_variable(e->request, code->index);
    }

    if (value && !value->not_found) {
        return value->len;
    }

    return 0;
}


void
njt_http_script_copy_var_code(njt_http_script_engine_t *e)
{
    u_char                      *p;
    njt_http_variable_value_t   *value;
    njt_http_script_var_code_t  *code;

    code = (njt_http_script_var_code_t *) e->ip;

    e->ip += sizeof(njt_http_script_var_code_t);

    if (!e->skip) {

        if (e->flushed) {
            value = njt_http_get_indexed_variable(e->request, code->index);

        } else {
            value = njt_http_get_flushed_variable(e->request, code->index);
        }

        if (value && !value->not_found) {
            p = e->pos;
            e->pos = njt_copy(p, value->data, value->len);

            njt_log_debug2(NJT_LOG_DEBUG_HTTP,
                           e->request->connection->log, 0,
                           "http script var: \"%*s\"", e->pos - p, p);
        }
    }
}


static njt_int_t
njt_http_script_add_args_code(njt_http_script_compile_t *sc)
{
    uintptr_t   *code;

    code = njt_http_script_add_code(*sc->lengths, sizeof(uintptr_t), NULL);
    if (code == NULL) {
        return NJT_ERROR;
    }

    *code = (uintptr_t) njt_http_script_mark_args_code;

    code = njt_http_script_add_code(*sc->values, sizeof(uintptr_t), &sc->main);
    if (code == NULL) {
        return NJT_ERROR;
    }

    *code = (uintptr_t) njt_http_script_start_args_code;

    return NJT_OK;
}


size_t
njt_http_script_mark_args_code(njt_http_script_engine_t *e)
{
    e->is_args = 1;
    e->ip += sizeof(uintptr_t);

    return 1;
}


void
njt_http_script_start_args_code(njt_http_script_engine_t *e)
{
    njt_log_debug0(NJT_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script args");

    e->is_args = 1;
    e->args = e->pos;
    e->ip += sizeof(uintptr_t);
}


#if (NJT_PCRE)

void
njt_http_script_regex_start_code(njt_http_script_engine_t *e)
{
    size_t                         len;
    njt_int_t                      rc;
    njt_uint_t                     n;
    njt_http_request_t            *r;
    njt_http_script_engine_t       le;
    njt_http_script_len_code_pt    lcode;
    njt_http_script_regex_code_t  *code;

    code = (njt_http_script_regex_code_t *) e->ip;

    r = e->request;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http script regex: \"%V\"", &code->name);

    if (code->uri) {
        e->line = r->uri;
    } else {
        e->sp--;
        e->line.len = e->sp->len;
        e->line.data = e->sp->data;
    }

    rc = njt_http_regex_exec(r, code->regex, &e->line);

    if (rc == NJT_DECLINED) {
        if (e->log || (r->connection->log->log_level & NJT_LOG_DEBUG_HTTP)) {
            njt_log_error(NJT_LOG_NOTICE, r->connection->log, 0,
                          "\"%V\" does not match \"%V\"",
                          &code->name, &e->line);
        }

        r->ncaptures = 0;

        if (code->test) {
            if (code->negative_test) {
                e->sp->len = 1;
                e->sp->data = (u_char *) "1";

            } else {
                e->sp->len = 0;
                e->sp->data = (u_char *) "";
            }

            e->sp++;

            e->ip += sizeof(njt_http_script_regex_code_t);
            return;
        }

        e->ip += code->next;
        return;
    }

    if (rc == NJT_ERROR) {
        e->ip = njt_http_script_exit;
        e->status = NJT_HTTP_INTERNAL_SERVER_ERROR;
        return;
    }

    if (e->log || (r->connection->log->log_level & NJT_LOG_DEBUG_HTTP)) {
        njt_log_error(NJT_LOG_NOTICE, r->connection->log, 0,
                      "\"%V\" matches \"%V\"", &code->name, &e->line);
    }

    if (code->test) {
        if (code->negative_test) {
            e->sp->len = 0;
            e->sp->data = (u_char *) "";

        } else {
            e->sp->len = 1;
            e->sp->data = (u_char *) "1";
	    //e->ret = 1;
        }

        e->sp++;

        e->ip += sizeof(njt_http_script_regex_code_t);
        return;
    }

    if (code->status) {
        e->status = code->status;

        if (!code->redirect) {
            e->ip = njt_http_script_exit;
            return;
        }
    }

    if (code->uri) {
        r->internal = 1;
        r->valid_unparsed_uri = 0;

        if (code->break_cycle) {
            r->valid_location = 0;
            r->uri_changed = 0;

        } else {
            r->uri_changed = 1;
        }
    }

    if (code->lengths == NULL) {
        e->buf.len = code->size;

        if (code->uri) {
            if (r->ncaptures && (r->quoted_uri || r->plus_in_uri)) {
                e->buf.len += 2 * njt_escape_uri(NULL, r->uri.data, r->uri.len,
                                                 NJT_ESCAPE_ARGS);
            }
        }

        for (n = 2; n < r->ncaptures; n += 2) {
            e->buf.len += r->captures[n + 1] - r->captures[n];
        }

    } else {
        njt_memzero(&le, sizeof(njt_http_script_engine_t));

        le.ip = code->lengths->elts;
        le.line = e->line;
        le.request = r;
        le.quote = code->redirect;

        len = 0;

        while (*(uintptr_t *) le.ip) {
            lcode = *(njt_http_script_len_code_pt *) le.ip;
            len += lcode(&le);
        }

        e->buf.len = len;
    }

    if (code->add_args && r->args.len) {
        e->buf.len += r->args.len + 1;
    }

    e->buf.data = njt_pnalloc(r->pool, e->buf.len);
    if (e->buf.data == NULL) {
        e->ip = njt_http_script_exit;
        e->status = NJT_HTTP_INTERNAL_SERVER_ERROR;
        return;
    }

    e->quote = code->redirect;

    e->pos = e->buf.data;

    e->ip += sizeof(njt_http_script_regex_code_t);
}


void
njt_http_script_regex_end_code(njt_http_script_engine_t *e)
{
    u_char                            *dst, *src;
    njt_http_request_t                *r;
    njt_http_script_regex_end_code_t  *code;

    code = (njt_http_script_regex_end_code_t *) e->ip;

    r = e->request;

    e->quote = 0;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http script regex end");

    if (code->redirect) {

        dst = e->buf.data;
        src = e->buf.data;

        njt_unescape_uri(&dst, &src, e->pos - e->buf.data,
                         NJT_UNESCAPE_REDIRECT);

        if (src < e->pos) {
            dst = njt_movemem(dst, src, e->pos - src);
        }

        e->pos = dst;

        if (code->add_args && r->args.len) {
            *e->pos++ = (u_char) (code->args ? '&' : '?');
            e->pos = njt_copy(e->pos, r->args.data, r->args.len);
        }

        e->buf.len = e->pos - e->buf.data;

        if (e->log || (r->connection->log->log_level & NJT_LOG_DEBUG_HTTP)) {
            njt_log_error(NJT_LOG_NOTICE, r->connection->log, 0,
                          "rewritten redirect: \"%V\"", &e->buf);
        }

        njt_http_clear_location(r);

        r->headers_out.location = njt_list_push(&r->headers_out.headers);
        if (r->headers_out.location == NULL) {
            e->ip = njt_http_script_exit;
            e->status = NJT_HTTP_INTERNAL_SERVER_ERROR;
            return;
        }

        r->headers_out.location->hash = 1;
        r->headers_out.location->next = NULL;
        njt_str_set(&r->headers_out.location->key, "Location");
        r->headers_out.location->value = e->buf;

        e->ip += sizeof(njt_http_script_regex_end_code_t);
        return;
    }

    if (e->args) {
        e->buf.len = e->args - e->buf.data;

        if (code->add_args && r->args.len) {
            *e->pos++ = '&';
            e->pos = njt_copy(e->pos, r->args.data, r->args.len);
        }

        r->args.len = e->pos - e->args;
        r->args.data = e->args;

        e->args = NULL;

    } else {
        e->buf.len = e->pos - e->buf.data;

        if (!code->add_args) {
            r->args.len = 0;
        }
    }

    if (e->log || (r->connection->log->log_level & NJT_LOG_DEBUG_HTTP)) {
        njt_log_error(NJT_LOG_NOTICE, r->connection->log, 0,
                      "rewritten data: \"%V\", args: \"%V\"",
                      &e->buf, &r->args);
    }

    if (code->uri) {
        r->uri = e->buf;

        if (r->uri.len == 0) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "the rewritten URI has a zero length");
            e->ip = njt_http_script_exit;
            e->status = NJT_HTTP_INTERNAL_SERVER_ERROR;
            return;
        }

        njt_http_set_exten(r);
    }

    e->ip += sizeof(njt_http_script_regex_end_code_t);
}


static njt_int_t
njt_http_script_add_capture_code(njt_http_script_compile_t *sc, njt_uint_t n)
{
    njt_http_script_copy_capture_code_t  *code;

    code = njt_http_script_add_code(*sc->lengths,
                                    sizeof(njt_http_script_copy_capture_code_t),
                                    NULL);
    if (code == NULL) {
        return NJT_ERROR;
    }

    code->code = (njt_http_script_code_pt) (void *)
                                         njt_http_script_copy_capture_len_code;
    code->n = 2 * n;


    code = njt_http_script_add_code(*sc->values,
                                    sizeof(njt_http_script_copy_capture_code_t),
                                    &sc->main);
    if (code == NULL) {
        return NJT_ERROR;
    }

    code->code = njt_http_script_copy_capture_code;
    code->n = 2 * n;

    if (sc->ncaptures < n) {
        sc->ncaptures = n;
    }

    return NJT_OK;
}


size_t
njt_http_script_copy_capture_len_code(njt_http_script_engine_t *e)
{
    int                                  *cap;
    u_char                               *p;
    njt_uint_t                            n;
    njt_http_request_t                   *r;
    njt_http_script_copy_capture_code_t  *code;

    r = e->request;

    code = (njt_http_script_copy_capture_code_t *) e->ip;

    e->ip += sizeof(njt_http_script_copy_capture_code_t);

    n = code->n;

    if (n < r->ncaptures) {

        cap = r->captures;

        if ((e->is_args || e->quote)
            && (e->request->quoted_uri || e->request->plus_in_uri))
        {
            p = r->captures_data;

            return cap[n + 1] - cap[n]
                   + 2 * njt_escape_uri(NULL, &p[cap[n]], cap[n + 1] - cap[n],
                                        NJT_ESCAPE_ARGS);
        } else {
            return cap[n + 1] - cap[n];
        }
    }

    return 0;
}


void
njt_http_script_copy_capture_code(njt_http_script_engine_t *e)
{
    int                                  *cap;
    u_char                               *p, *pos;
    njt_uint_t                            n;
    njt_http_request_t                   *r;
    njt_http_script_copy_capture_code_t  *code;

    r = e->request;

    code = (njt_http_script_copy_capture_code_t *) e->ip;

    e->ip += sizeof(njt_http_script_copy_capture_code_t);

    n = code->n;

    pos = e->pos;

    if (n < r->ncaptures) {

        cap = r->captures;
        p = r->captures_data;

        if ((e->is_args || e->quote)
            && (e->request->quoted_uri || e->request->plus_in_uri))
        {
            e->pos = (u_char *) njt_escape_uri(pos, &p[cap[n]],
                                               cap[n + 1] - cap[n],
                                               NJT_ESCAPE_ARGS);
        } else {
            e->pos = njt_copy(pos, &p[cap[n]], cap[n + 1] - cap[n]);
        }
    }

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script capture: \"%*s\"", e->pos - pos, pos);
}

#endif


static njt_int_t
njt_http_script_add_full_name_code(njt_http_script_compile_t *sc)
{
    njt_http_script_full_name_code_t  *code;

    code = njt_http_script_add_code(*sc->lengths,
                                    sizeof(njt_http_script_full_name_code_t),
                                    NULL);
    if (code == NULL) {
        return NJT_ERROR;
    }

    code->code = (njt_http_script_code_pt) (void *)
                                            njt_http_script_full_name_len_code;
    code->conf_prefix = sc->conf_prefix;

    code = njt_http_script_add_code(*sc->values,
                                    sizeof(njt_http_script_full_name_code_t),
                                    &sc->main);
    if (code == NULL) {
        return NJT_ERROR;
    }

    code->code = njt_http_script_full_name_code;
    code->conf_prefix = sc->conf_prefix;

    return NJT_OK;
}


static size_t
njt_http_script_full_name_len_code(njt_http_script_engine_t *e)
{
    njt_http_script_full_name_code_t  *code;

    code = (njt_http_script_full_name_code_t *) e->ip;

    e->ip += sizeof(njt_http_script_full_name_code_t);

    return code->conf_prefix ? njt_cycle->conf_prefix.len:
                               njt_cycle->prefix.len;
}


static void
njt_http_script_full_name_code(njt_http_script_engine_t *e)
{
    njt_http_script_full_name_code_t  *code;

    njt_str_t  value, *prefix;

    code = (njt_http_script_full_name_code_t *) e->ip;

    value.data = e->buf.data;
    value.len = e->pos - e->buf.data;

    prefix = code->conf_prefix ? (njt_str_t *) &njt_cycle->conf_prefix:
                                 (njt_str_t *) &njt_cycle->prefix;

    if (njt_get_full_name(e->request->pool, prefix, &value) != NJT_OK) {
        e->ip = njt_http_script_exit;
        e->status = NJT_HTTP_INTERNAL_SERVER_ERROR;
        return;
    }

    e->buf = value;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script fullname: \"%V\"", &value);

    e->ip += sizeof(njt_http_script_full_name_code_t);
}


void
njt_http_script_return_code(njt_http_script_engine_t *e)
{
    njt_http_script_return_code_t  *code;

    code = (njt_http_script_return_code_t *) e->ip;

    if (code->status < NJT_HTTP_BAD_REQUEST
        || code->text.value.len
        || code->text.lengths)
    {
        e->status = njt_http_send_response(e->request, code->status, NULL,
                                           &code->text);
    } else {
        e->status = code->status;
    }

    e->ip = njt_http_script_exit;
}


void
njt_http_script_break_code(njt_http_script_engine_t *e)
{
    njt_http_request_t  *r;

    r = e->request;

    if (r->uri_changed) {
        r->valid_location = 0;
        r->uri_changed = 0;
    }

    e->ip = njt_http_script_exit;
}


void
njt_http_script_if_code(njt_http_script_engine_t *e)
{
    njt_http_script_if_code_t  *code;

    code = (njt_http_script_if_code_t *) e->ip;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script if");

    e->sp--;

    if (e->sp->len && (e->sp->len != 1 || e->sp->data[0] != '0')) {
        if (code->loc_conf) {
            e->request->loc_conf = code->loc_conf;
            njt_http_update_location_config(e->request);
        }
	e->ret = 1;
        e->ip += sizeof(njt_http_script_if_code_t);
        return;
    }

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script if: false");
    e->ret = 0;
    e->ip += code->next;
}


void
njt_http_script_equal_code(njt_http_script_engine_t *e)
{
    njt_http_variable_value_t  *val, *res;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script equal");

    e->sp--;
    val = e->sp;
    res = e->sp - 1;

    e->ip += sizeof(uintptr_t);

    if (val->len == res->len
        && njt_strncmp(val->data, res->data, res->len) == 0)
    {	
	//e->ret = 1;//by zyg
        *res = njt_http_variable_true_value;
        return;
    }

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script equal: no");
     //e->ret = 0;//by zyg
    *res = njt_http_variable_null_value;
}


void
njt_http_script_not_equal_code(njt_http_script_engine_t *e)
{
    njt_http_variable_value_t  *val, *res;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script not equal");

    e->sp--;
    val = e->sp;
    res = e->sp - 1;

    e->ip += sizeof(uintptr_t);

    if (val->len == res->len
        && njt_strncmp(val->data, res->data, res->len) == 0)
    {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                       "http script not equal: no");
	e->ret = 0;//by zyg
        *res = njt_http_variable_null_value;
        return;
    }
    //e->ret = 1;//by zyg
    *res = njt_http_variable_true_value;
}


void
njt_http_script_file_code(njt_http_script_engine_t *e)
{
    njt_str_t                     path;
    njt_http_request_t           *r;
    njt_open_file_info_t          of;
    njt_http_core_loc_conf_t     *clcf;
    njt_http_variable_value_t    *value;
    njt_http_script_file_code_t  *code;

    value = e->sp - 1;

    code = (njt_http_script_file_code_t *) e->ip;
    e->ip += sizeof(njt_http_script_file_code_t);

    path.len = value->len - 1;
    path.data = value->data;

    r = e->request;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http script file op %p \"%V\"", (void *) code->op, &path);

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    njt_memzero(&of, sizeof(njt_open_file_info_t));

    of.read_ahead = clcf->read_ahead;
    of.directio = clcf->directio;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.test_only = 1;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;

    if (njt_http_set_disable_symlinks(r, clcf, &path, &of) != NJT_OK) {
        e->ip = njt_http_script_exit;
        e->status = NJT_HTTP_INTERNAL_SERVER_ERROR;
        return;
    }

    if (njt_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
        != NJT_OK)
    {
        if (of.err == 0) {
            e->ip = njt_http_script_exit;
            e->status = NJT_HTTP_INTERNAL_SERVER_ERROR;
            return;
        }

        if (of.err != NJT_ENOENT
            && of.err != NJT_ENOTDIR
            && of.err != NJT_ENAMETOOLONG)
        {
            njt_log_error(NJT_LOG_CRIT, r->connection->log, of.err,
                          "%s \"%s\" failed", of.failed, value->data);
        }

        switch (code->op) {

        case njt_http_script_file_plain:
        case njt_http_script_file_dir:
        case njt_http_script_file_exists:
        case njt_http_script_file_exec:
             goto false_value;

        case njt_http_script_file_not_plain:
        case njt_http_script_file_not_dir:
        case njt_http_script_file_not_exists:
        case njt_http_script_file_not_exec:
             goto true_value;
        }

        goto false_value;
    }

    switch (code->op) {
    case njt_http_script_file_plain:
        if (of.is_file) {
             goto true_value;
        }
        goto false_value;

    case njt_http_script_file_not_plain:
        if (of.is_file) {
            goto false_value;
        }
        goto true_value;

    case njt_http_script_file_dir:
        if (of.is_dir) {
             goto true_value;
        }
        goto false_value;

    case njt_http_script_file_not_dir:
        if (of.is_dir) {
            goto false_value;
        }
        goto true_value;

    case njt_http_script_file_exists:
        if (of.is_file || of.is_dir || of.is_link) {
             goto true_value;
        }
        goto false_value;

    case njt_http_script_file_not_exists:
        if (of.is_file || of.is_dir || of.is_link) {
            goto false_value;
        }
        goto true_value;

    case njt_http_script_file_exec:
        if (of.is_exec) {
             goto true_value;
        }
        goto false_value;

    case njt_http_script_file_not_exec:
        if (of.is_exec) {
            goto false_value;
        }
        goto true_value;
    }

false_value:

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http script file op false");

    *value = njt_http_variable_null_value;
    return;

true_value:

    *value = njt_http_variable_true_value;
    return;
}


void
njt_http_script_complex_value_code(njt_http_script_engine_t *e)
{
    size_t                                 len;
    njt_http_script_engine_t               le;
    njt_http_script_len_code_pt            lcode;
    njt_http_script_complex_value_code_t  *code;

    code = (njt_http_script_complex_value_code_t *) e->ip;

    e->ip += sizeof(njt_http_script_complex_value_code_t);

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script complex value");

    njt_memzero(&le, sizeof(njt_http_script_engine_t));

    le.ip = code->lengths->elts;
    le.line = e->line;
    le.request = e->request;
    le.quote = e->quote;

    for (len = 0; *(uintptr_t *) le.ip; len += lcode(&le)) {
        lcode = *(njt_http_script_len_code_pt *) le.ip;
    }

    e->buf.len = len;
    e->buf.data = njt_pnalloc(e->request->pool, len);
    if (e->buf.data == NULL) {
        e->ip = njt_http_script_exit;
        e->status = NJT_HTTP_INTERNAL_SERVER_ERROR;
        return;
    }

    e->pos = e->buf.data;

    e->sp->len = e->buf.len;
    e->sp->data = e->buf.data;
    e->sp++;
}


void
njt_http_script_value_code(njt_http_script_engine_t *e)
{
    njt_http_script_value_code_t  *code;

    code = (njt_http_script_value_code_t *) e->ip;

    e->ip += sizeof(njt_http_script_value_code_t);

    e->sp->len = code->text_len;
    e->sp->data = (u_char *) code->text_data;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script value: \"%v\"", e->sp);

    e->sp++;
}


void
njt_http_script_set_var_code(njt_http_script_engine_t *e)
{
    njt_http_request_t          *r;
    njt_http_script_var_code_t  *code;

    code = (njt_http_script_var_code_t *) e->ip;

    e->ip += sizeof(njt_http_script_var_code_t);

    r = e->request;

    e->sp--;

    r->variables[code->index].len = e->sp->len;
    r->variables[code->index].valid = 1;
    r->variables[code->index].no_cacheable = 0;
    r->variables[code->index].not_found = 0;
    r->variables[code->index].data = e->sp->data;

#if (NJT_DEBUG)
    {
    njt_http_variable_t        *v;
    njt_http_core_main_conf_t  *cmcf;

    cmcf = njt_http_get_module_main_conf(r, njt_http_core_module);

    v = cmcf->variables.elts;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script set $%V", &v[code->index].name);
    }
#endif
}


void
njt_http_script_var_set_handler_code(njt_http_script_engine_t *e)
{
    njt_http_script_var_handler_code_t  *code;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script set var handler");

    code = (njt_http_script_var_handler_code_t *) e->ip;

    e->ip += sizeof(njt_http_script_var_handler_code_t);

    e->sp--;

    code->handler(e->request, e->sp, code->data);
}


void
njt_http_script_var_code(njt_http_script_engine_t *e)
{
    njt_http_variable_value_t   *value;
    njt_http_script_var_code_t  *code;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script var");

    code = (njt_http_script_var_code_t *) e->ip;

    e->ip += sizeof(njt_http_script_var_code_t);

    value = njt_http_get_flushed_variable(e->request, code->index);

    if (value && !value->not_found) {
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                       "http script var: \"%v\"", value);

        *e->sp = *value;
        e->sp++;

        return;
    }

    *e->sp = njt_http_variable_null_value;
    e->sp++;
}


void
njt_http_script_nop_code(njt_http_script_engine_t *e)
{
    e->ip += sizeof(uintptr_t);
}
