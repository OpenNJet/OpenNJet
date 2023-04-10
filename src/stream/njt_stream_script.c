
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>


static njt_int_t njt_stream_script_init_arrays(
    njt_stream_script_compile_t *sc);
static njt_int_t njt_stream_script_done(njt_stream_script_compile_t *sc);
static njt_int_t njt_stream_script_add_copy_code(
    njt_stream_script_compile_t *sc, njt_str_t *value, njt_uint_t last);
static njt_int_t njt_stream_script_add_var_code(
    njt_stream_script_compile_t *sc, njt_str_t *name);
#if (NJT_PCRE)
static njt_int_t njt_stream_script_add_capture_code(
    njt_stream_script_compile_t *sc, njt_uint_t n);
#endif
static njt_int_t njt_stream_script_add_full_name_code(
    njt_stream_script_compile_t *sc);
static size_t njt_stream_script_full_name_len_code(
    njt_stream_script_engine_t *e);
static void njt_stream_script_full_name_code(njt_stream_script_engine_t *e);


#define njt_stream_script_exit  (u_char *) &njt_stream_script_exit_code

static uintptr_t njt_stream_script_exit_code = (uintptr_t) NULL;


void
njt_stream_script_flush_complex_value(njt_stream_session_t *s,
    njt_stream_complex_value_t *val)
{
    njt_uint_t *index;

    index = val->flushes;

    if (index) {
        while (*index != (njt_uint_t) -1) {

            if (s->variables[*index].no_cacheable) {
                s->variables[*index].valid = 0;
                s->variables[*index].not_found = 0;
            }

            index++;
        }
    }
}


njt_int_t
njt_stream_complex_value(njt_stream_session_t *s,
    njt_stream_complex_value_t *val, njt_str_t *value)
{
    size_t                         len;
    njt_stream_script_code_pt      code;
    njt_stream_script_engine_t     e;
    njt_stream_script_len_code_pt  lcode;

    if (val->lengths == NULL) {
        *value = val->value;
        return NJT_OK;
    }

    njt_stream_script_flush_complex_value(s, val);

    njt_memzero(&e, sizeof(njt_stream_script_engine_t));

    e.ip = val->lengths;
    e.session = s;
    e.flushed = 1;

    len = 0;

    while (*(uintptr_t *) e.ip) {
        lcode = *(njt_stream_script_len_code_pt *) e.ip;
        len += lcode(&e);
    }

    value->len = len;
    value->data = njt_pnalloc(s->connection->pool, len);
    if (value->data == NULL) {
        return NJT_ERROR;
    }

    e.ip = val->values;
    e.pos = value->data;
    e.buf = *value;

    while (*(uintptr_t *) e.ip) {
        code = *(njt_stream_script_code_pt *) e.ip;
        code((njt_stream_script_engine_t *) &e);
    }

    *value = e.buf;

    return NJT_OK;
}


size_t
njt_stream_complex_value_size(njt_stream_session_t *s,
    njt_stream_complex_value_t *val, size_t default_value)
{
    size_t     size;
    njt_str_t  value;

    if (val == NULL) {
        return default_value;
    }

    if (val->lengths == NULL) {
        return val->u.size;
    }

    if (njt_stream_complex_value(s, val, &value) != NJT_OK) {
        return default_value;
    }

    size = njt_parse_size(&value);

    if (size == (size_t) NJT_ERROR) {
        njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                      "invalid size \"%V\"", &value);
        return default_value;
    }

    return size;
}


njt_int_t
njt_stream_compile_complex_value(njt_stream_compile_complex_value_t *ccv)
{
    njt_str_t                    *v;
    njt_uint_t                    i, n, nv, nc;
    njt_array_t                   flushes, lengths, values, *pf, *pl, *pv;
    njt_stream_script_compile_t   sc;

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

    n = nv * (2 * sizeof(njt_stream_script_copy_code_t)
                  + sizeof(njt_stream_script_var_code_t))
        + sizeof(uintptr_t);

    if (njt_array_init(&lengths, ccv->cf->pool, n, 1) != NJT_OK) {
        return NJT_ERROR;
    }

    n = (nv * (2 * sizeof(njt_stream_script_copy_code_t)
                   + sizeof(njt_stream_script_var_code_t))
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

    njt_memzero(&sc, sizeof(njt_stream_script_compile_t));

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

    if (njt_stream_script_compile(&sc) != NJT_OK) {
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
njt_stream_set_complex_value_slot(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    char  *p = conf;

    njt_str_t                            *value;
    njt_stream_complex_value_t          **cv;
    njt_stream_compile_complex_value_t    ccv;

    cv = (njt_stream_complex_value_t **) (p + cmd->offset);

    if (*cv != NJT_CONF_UNSET_PTR && *cv != NULL) {
        return "is duplicate";
    }

    *cv = njt_palloc(cf->pool, sizeof(njt_stream_complex_value_t));
    if (*cv == NULL) {
        return NJT_CONF_ERROR;
    }

    value = cf->args->elts;

    njt_memzero(&ccv, sizeof(njt_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = *cv;

    if (njt_stream_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


char *
njt_stream_set_complex_value_zero_slot(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    char  *p = conf;

    njt_str_t                            *value;
    njt_stream_complex_value_t          **cv;
    njt_stream_compile_complex_value_t    ccv;

    cv = (njt_stream_complex_value_t **) (p + cmd->offset);

    if (*cv != NJT_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    *cv = njt_palloc(cf->pool, sizeof(njt_stream_complex_value_t));
    if (*cv == NULL) {
        return NJT_CONF_ERROR;
    }

    value = cf->args->elts;

    njt_memzero(&ccv, sizeof(njt_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = *cv;
    ccv.zero = 1;

    if (njt_stream_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


char *
njt_stream_set_complex_value_size_slot(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    char  *p = conf;

    char                        *rv;
    njt_stream_complex_value_t  *cv;

    rv = njt_stream_set_complex_value_slot(cf, cmd, conf);

    if (rv != NJT_CONF_OK) {
        return rv;
    }

    cv = *(njt_stream_complex_value_t **) (p + cmd->offset);

    if (cv->lengths) {
        return NJT_CONF_OK;
    }

    cv->u.size = njt_parse_size(&cv->value);
    if (cv->u.size == (size_t) NJT_ERROR) {
        return "invalid value";
    }

    return NJT_CONF_OK;
}


njt_uint_t
njt_stream_script_variables_count(njt_str_t *value)
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
njt_stream_script_compile(njt_stream_script_compile_t *sc)
{
    u_char       ch;
    njt_str_t    name;
    njt_uint_t   i, bracket;

    if (njt_stream_script_init_arrays(sc) != NJT_OK) {
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

                if (njt_stream_script_add_capture_code(sc, n) != NJT_OK) {
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

            if (njt_stream_script_add_var_code(sc, &name) != NJT_OK) {
                return NJT_ERROR;
            }

            continue;
        }

        name.data = &sc->source->data[i];

        while (i < sc->source->len) {

            if (sc->source->data[i] == '$') {
                break;
            }

            i++;
            name.len++;
        }

        sc->size += name.len;

        if (njt_stream_script_add_copy_code(sc, &name, (i == sc->source->len))
            != NJT_OK)
        {
            return NJT_ERROR;
        }
    }

    return njt_stream_script_done(sc);

invalid_variable:

    njt_conf_log_error(NJT_LOG_EMERG, sc->cf, 0, "invalid variable name");

    return NJT_ERROR;
}


u_char *
njt_stream_script_run(njt_stream_session_t *s, njt_str_t *value,
    void *code_lengths, size_t len, void *code_values)
{
    njt_uint_t                      i;
    njt_stream_script_code_pt       code;
    njt_stream_script_engine_t      e;
    njt_stream_core_main_conf_t    *cmcf;
    njt_stream_script_len_code_pt   lcode;

    cmcf = njt_stream_get_module_main_conf(s, njt_stream_core_module);

    for (i = 0; i < cmcf->variables.nelts; i++) {
        if (s->variables[i].no_cacheable) {
            s->variables[i].valid = 0;
            s->variables[i].not_found = 0;
        }
    }

    njt_memzero(&e, sizeof(njt_stream_script_engine_t));

    e.ip = code_lengths;
    e.session = s;
    e.flushed = 1;

    while (*(uintptr_t *) e.ip) {
        lcode = *(njt_stream_script_len_code_pt *) e.ip;
        len += lcode(&e);
    }


    value->len = len;
    value->data = njt_pnalloc(s->connection->pool, len);
    if (value->data == NULL) {
        return NULL;
    }

    e.ip = code_values;
    e.pos = value->data;

    while (*(uintptr_t *) e.ip) {
        code = *(njt_stream_script_code_pt *) e.ip;
        code((njt_stream_script_engine_t *) &e);
    }

    return e.pos;
}


void
njt_stream_script_flush_no_cacheable_variables(njt_stream_session_t *s,
    njt_array_t *indices)
{
    njt_uint_t  n, *index;

    if (indices) {
        index = indices->elts;
        for (n = 0; n < indices->nelts; n++) {
            if (s->variables[index[n]].no_cacheable) {
                s->variables[index[n]].valid = 0;
                s->variables[index[n]].not_found = 0;
            }
        }
    }
}


static njt_int_t
njt_stream_script_init_arrays(njt_stream_script_compile_t *sc)
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
        n = sc->variables * (2 * sizeof(njt_stream_script_copy_code_t)
                             + sizeof(njt_stream_script_var_code_t))
            + sizeof(uintptr_t);

        *sc->lengths = njt_array_create(sc->cf->pool, n, 1);
        if (*sc->lengths == NULL) {
            return NJT_ERROR;
        }
    }

    if (*sc->values == NULL) {
        n = (sc->variables * (2 * sizeof(njt_stream_script_copy_code_t)
                              + sizeof(njt_stream_script_var_code_t))
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
njt_stream_script_done(njt_stream_script_compile_t *sc)
{
    njt_str_t    zero;
    uintptr_t   *code;

    if (sc->zero) {

        zero.len = 1;
        zero.data = (u_char *) "\0";

        if (njt_stream_script_add_copy_code(sc, &zero, 0) != NJT_OK) {
            return NJT_ERROR;
        }
    }

    if (sc->conf_prefix || sc->root_prefix) {
        if (njt_stream_script_add_full_name_code(sc) != NJT_OK) {
            return NJT_ERROR;
        }
    }

    if (sc->complete_lengths) {
        code = njt_stream_script_add_code(*sc->lengths, sizeof(uintptr_t),
                                          NULL);
        if (code == NULL) {
            return NJT_ERROR;
        }

        *code = (uintptr_t) NULL;
    }

    if (sc->complete_values) {
        code = njt_stream_script_add_code(*sc->values, sizeof(uintptr_t),
                                          &sc->main);
        if (code == NULL) {
            return NJT_ERROR;
        }

        *code = (uintptr_t) NULL;
    }

    return NJT_OK;
}


void *
njt_stream_script_add_code(njt_array_t *codes, size_t size, void *code)
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
njt_stream_script_add_copy_code(njt_stream_script_compile_t *sc,
    njt_str_t *value, njt_uint_t last)
{
    u_char                         *p;
    size_t                          size, len, zero;
    njt_stream_script_copy_code_t  *code;

    zero = (sc->zero && last);
    len = value->len + zero;

    code = njt_stream_script_add_code(*sc->lengths,
                                      sizeof(njt_stream_script_copy_code_t),
                                      NULL);
    if (code == NULL) {
        return NJT_ERROR;
    }

    code->code = (njt_stream_script_code_pt) (void *)
                                               njt_stream_script_copy_len_code;
    code->len = len;

    size = (sizeof(njt_stream_script_copy_code_t) + len + sizeof(uintptr_t) - 1)
            & ~(sizeof(uintptr_t) - 1);

    code = njt_stream_script_add_code(*sc->values, size, &sc->main);
    if (code == NULL) {
        return NJT_ERROR;
    }

    code->code = njt_stream_script_copy_code;
    code->len = len;

    p = njt_cpymem((u_char *) code + sizeof(njt_stream_script_copy_code_t),
                   value->data, value->len);

    if (zero) {
        *p = '\0';
        sc->zero = 0;
    }

    return NJT_OK;
}


size_t
njt_stream_script_copy_len_code(njt_stream_script_engine_t *e)
{
    njt_stream_script_copy_code_t  *code;

    code = (njt_stream_script_copy_code_t *) e->ip;

    e->ip += sizeof(njt_stream_script_copy_code_t);

    return code->len;
}


void
njt_stream_script_copy_code(njt_stream_script_engine_t *e)
{
    u_char                         *p;
    njt_stream_script_copy_code_t  *code;

    code = (njt_stream_script_copy_code_t *) e->ip;

    p = e->pos;

    if (!e->skip) {
        e->pos = njt_copy(p, e->ip + sizeof(njt_stream_script_copy_code_t),
                          code->len);
    }

    e->ip += sizeof(njt_stream_script_copy_code_t)
          + ((code->len + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1));

    njt_log_debug2(NJT_LOG_DEBUG_STREAM, e->session->connection->log, 0,
                   "stream script copy: \"%*s\"", e->pos - p, p);
}


static njt_int_t
njt_stream_script_add_var_code(njt_stream_script_compile_t *sc, njt_str_t *name)
{
    njt_int_t                      index, *p;
    njt_stream_script_var_code_t  *code;

    index = njt_stream_get_variable_index(sc->cf, name);

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

    code = njt_stream_script_add_code(*sc->lengths,
                                      sizeof(njt_stream_script_var_code_t),
                                      NULL);
    if (code == NULL) {
        return NJT_ERROR;
    }

    code->code = (njt_stream_script_code_pt) (void *)
                                           njt_stream_script_copy_var_len_code;
    code->index = (uintptr_t) index;

    code = njt_stream_script_add_code(*sc->values,
                                      sizeof(njt_stream_script_var_code_t),
                                      &sc->main);
    if (code == NULL) {
        return NJT_ERROR;
    }

    code->code = njt_stream_script_copy_var_code;
    code->index = (uintptr_t) index;

    return NJT_OK;
}


size_t
njt_stream_script_copy_var_len_code(njt_stream_script_engine_t *e)
{
    njt_stream_variable_value_t   *value;
    njt_stream_script_var_code_t  *code;

    code = (njt_stream_script_var_code_t *) e->ip;

    e->ip += sizeof(njt_stream_script_var_code_t);

    if (e->flushed) {
        value = njt_stream_get_indexed_variable(e->session, code->index);

    } else {
        value = njt_stream_get_flushed_variable(e->session, code->index);
    }

    if (value && !value->not_found) {
        return value->len;
    }

    return 0;
}


void
njt_stream_script_copy_var_code(njt_stream_script_engine_t *e)
{
    u_char                        *p;
    njt_stream_variable_value_t   *value;
    njt_stream_script_var_code_t  *code;

    code = (njt_stream_script_var_code_t *) e->ip;

    e->ip += sizeof(njt_stream_script_var_code_t);

    if (!e->skip) {

        if (e->flushed) {
            value = njt_stream_get_indexed_variable(e->session, code->index);

        } else {
            value = njt_stream_get_flushed_variable(e->session, code->index);
        }

        if (value && !value->not_found) {
            p = e->pos;
            e->pos = njt_copy(p, value->data, value->len);

            njt_log_debug2(NJT_LOG_DEBUG_STREAM,
                           e->session->connection->log, 0,
                           "stream script var: \"%*s\"", e->pos - p, p);
        }
    }
}


#if (NJT_PCRE)

static njt_int_t
njt_stream_script_add_capture_code(njt_stream_script_compile_t *sc,
    njt_uint_t n)
{
    njt_stream_script_copy_capture_code_t  *code;

    code = njt_stream_script_add_code(*sc->lengths,
                                  sizeof(njt_stream_script_copy_capture_code_t),
                                  NULL);
    if (code == NULL) {
        return NJT_ERROR;
    }

    code->code = (njt_stream_script_code_pt) (void *)
                                       njt_stream_script_copy_capture_len_code;
    code->n = 2 * n;


    code = njt_stream_script_add_code(*sc->values,
                                  sizeof(njt_stream_script_copy_capture_code_t),
                                  &sc->main);
    if (code == NULL) {
        return NJT_ERROR;
    }

    code->code = njt_stream_script_copy_capture_code;
    code->n = 2 * n;

    if (sc->ncaptures < n) {
        sc->ncaptures = n;
    }

    return NJT_OK;
}


size_t
njt_stream_script_copy_capture_len_code(njt_stream_script_engine_t *e)
{
    int                                    *cap;
    njt_uint_t                              n;
    njt_stream_session_t                   *s;
    njt_stream_script_copy_capture_code_t  *code;

    s = e->session;

    code = (njt_stream_script_copy_capture_code_t *) e->ip;

    e->ip += sizeof(njt_stream_script_copy_capture_code_t);

    n = code->n;

    if (n < s->ncaptures) {
        cap = s->captures;
        return cap[n + 1] - cap[n];
    }

    return 0;
}


void
njt_stream_script_copy_capture_code(njt_stream_script_engine_t *e)
{
    int                                    *cap;
    u_char                                 *p, *pos;
    njt_uint_t                              n;
    njt_stream_session_t                   *s;
    njt_stream_script_copy_capture_code_t  *code;

    s = e->session;

    code = (njt_stream_script_copy_capture_code_t *) e->ip;

    e->ip += sizeof(njt_stream_script_copy_capture_code_t);

    n = code->n;

    pos = e->pos;

    if (n < s->ncaptures) {
        cap = s->captures;
        p = s->captures_data;
        e->pos = njt_copy(pos, &p[cap[n]], cap[n + 1] - cap[n]);
    }

    njt_log_debug2(NJT_LOG_DEBUG_STREAM, e->session->connection->log, 0,
                   "stream script capture: \"%*s\"", e->pos - pos, pos);
}

#endif


static njt_int_t
njt_stream_script_add_full_name_code(njt_stream_script_compile_t *sc)
{
    njt_stream_script_full_name_code_t  *code;

    code = njt_stream_script_add_code(*sc->lengths,
                                    sizeof(njt_stream_script_full_name_code_t),
                                    NULL);
    if (code == NULL) {
        return NJT_ERROR;
    }

    code->code = (njt_stream_script_code_pt) (void *)
                                          njt_stream_script_full_name_len_code;
    code->conf_prefix = sc->conf_prefix;

    code = njt_stream_script_add_code(*sc->values,
                        sizeof(njt_stream_script_full_name_code_t), &sc->main);
    if (code == NULL) {
        return NJT_ERROR;
    }

    code->code = njt_stream_script_full_name_code;
    code->conf_prefix = sc->conf_prefix;

    return NJT_OK;
}


static size_t
njt_stream_script_full_name_len_code(njt_stream_script_engine_t *e)
{
    njt_stream_script_full_name_code_t  *code;

    code = (njt_stream_script_full_name_code_t *) e->ip;

    e->ip += sizeof(njt_stream_script_full_name_code_t);

    return code->conf_prefix ? njt_cycle->conf_prefix.len:
                               njt_cycle->prefix.len;
}


static void
njt_stream_script_full_name_code(njt_stream_script_engine_t *e)
{
    njt_stream_script_full_name_code_t  *code;

    njt_str_t  value, *prefix;

    code = (njt_stream_script_full_name_code_t *) e->ip;

    value.data = e->buf.data;
    value.len = e->pos - e->buf.data;

    prefix = code->conf_prefix ? (njt_str_t *) &njt_cycle->conf_prefix:
                                 (njt_str_t *) &njt_cycle->prefix;

    if (njt_get_full_name(e->session->connection->pool, prefix, &value)
        != NJT_OK)
    {
        e->ip = njt_stream_script_exit;
        return;
    }

    e->buf = value;

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, e->session->connection->log, 0,
                   "stream script fullname: \"%V\"", &value);

    e->ip += sizeof(njt_stream_script_full_name_code_t);
}
