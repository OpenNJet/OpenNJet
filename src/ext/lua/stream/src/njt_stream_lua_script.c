
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_script.c.tt2
 */


/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_stream_lua_script.h"


static void *njt_stream_lua_script_add_code(njt_array_t *codes, size_t size);
static size_t njt_stream_lua_script_copy_len_code(
    njt_stream_lua_script_engine_t *e);
static void njt_stream_lua_script_copy_code(njt_stream_lua_script_engine_t *e);
static njt_int_t njt_stream_lua_script_add_copy_code(
    njt_stream_lua_script_compile_t *sc, njt_str_t *value, njt_uint_t last);
static njt_int_t njt_stream_lua_script_compile(
    njt_stream_lua_script_compile_t *sc);
static njt_int_t njt_stream_lua_script_add_capture_code(
    njt_stream_lua_script_compile_t *sc, njt_uint_t n);
static size_t njt_stream_lua_script_copy_capture_len_code(
    njt_stream_lua_script_engine_t *e);
static void njt_stream_lua_script_copy_capture_code(
    njt_stream_lua_script_engine_t *e);
static njt_int_t njt_stream_lua_script_done(
    njt_stream_lua_script_compile_t *sc);
static njt_int_t njt_stream_lua_script_init_arrays(
    njt_stream_lua_script_compile_t *sc);


njt_int_t
njt_stream_lua_compile_complex_value(
    njt_stream_lua_compile_complex_value_t *ccv)
{
    njt_str_t                  *v;
    njt_uint_t                  i, n, nv;
    njt_array_t                 lengths, values, *pl, *pv;

    njt_stream_lua_script_compile_t         sc;

    v = ccv->value;

    nv = 0;

    for (i = 0; i < v->len; i++) {
        if (v->data[i] == '$') {
            nv++;
        }
    }

    ccv->complex_value->value = *v;
    ccv->complex_value->lengths = NULL;
    ccv->complex_value->values = NULL;

    if (nv == 0) {
        return NJT_OK;
    }

    n = nv * (2 * sizeof(njt_stream_lua_script_copy_code_t)
              + sizeof(njt_stream_lua_script_capture_code_t))
        + sizeof(uintptr_t);

    if (njt_array_init(&lengths, ccv->pool, n, 1) != NJT_OK) {
        return NJT_ERROR;
    }

    n = (nv * (2 * sizeof(njt_stream_lua_script_copy_code_t)
                   + sizeof(njt_stream_lua_script_capture_code_t))
                + sizeof(uintptr_t)
                + sizeof(uintptr_t) - 1)
            & ~(sizeof(uintptr_t) - 1);

    if (njt_array_init(&values, ccv->pool, n, 1) != NJT_OK) {
        return NJT_ERROR;
    }

    pl = &lengths;
    pv = &values;

    njt_memzero(&sc, sizeof(njt_stream_lua_script_compile_t));

    sc.pool = ccv->pool;
    sc.log = ccv->log;
    sc.source = v;
    sc.lengths = &pl;
    sc.values = &pv;
    sc.complete_lengths = 1;
    sc.complete_values = 1;

    if (njt_stream_lua_script_compile(&sc) != NJT_OK) {
        njt_array_destroy(&lengths);
        njt_array_destroy(&values);
        return NJT_ERROR;
    }

    ccv->complex_value->lengths = lengths.elts;
    ccv->complex_value->values = values.elts;

    return NJT_OK;
}


njt_int_t
njt_stream_lua_complex_value(njt_stream_lua_request_t *r, njt_str_t *subj,
    size_t offset, njt_int_t count, int *cap,
    njt_stream_lua_complex_value_t *val, luaL_Buffer *luabuf)
{
    size_t                            len;
    u_char                           *p;

    njt_stream_lua_script_code_pt             code;
    njt_stream_lua_script_len_code_pt         lcode;
    njt_stream_lua_script_engine_t            e;

    if (val->lengths == NULL) {
        luaL_addlstring(luabuf, (char *) &subj->data[offset], cap[0] - offset);
        luaL_addlstring(luabuf, (char *) val->value.data, val->value.len);

        return NJT_OK;
    }

    njt_memzero(&e, sizeof(njt_stream_lua_script_engine_t));

    e.log = r->connection->log;
    e.ncaptures = count * 2;
    e.captures = cap;
    e.captures_data = subj->data;

    e.ip = val->lengths;

    len = 0;

    while (*(uintptr_t *) e.ip) {
        lcode = *(njt_stream_lua_script_len_code_pt *) e.ip;
        len += lcode(&e);
    }

    p = njt_pnalloc(r->pool, len);
    if (p == NULL) {
        return NJT_ERROR;
    }

    e.ip = val->values;
    e.pos = p;

    while (*(uintptr_t *) e.ip) {
        code = *(njt_stream_lua_script_code_pt *) e.ip;
        code((njt_stream_lua_script_engine_t *) &e);
    }

    luaL_addlstring(luabuf, (char *) &subj->data[offset], cap[0] - offset);
    luaL_addlstring(luabuf, (char *) p, len);

    njt_pfree(r->pool, p);

    return NJT_OK;
}


static njt_int_t
njt_stream_lua_script_compile(njt_stream_lua_script_compile_t *sc)
{
    u_char       ch;
    njt_str_t    name;
    njt_uint_t   i, bracket;
    unsigned     num_var;
    njt_uint_t   n = 0;

    if (njt_stream_lua_script_init_arrays(sc) != NJT_OK) {
        return NJT_ERROR;
    }

    for (i = 0; i < sc->source->len; /* void */ ) {

        name.len = 0;

        if (sc->source->data[i] == '$') {

            if (++i == sc->source->len) {
                goto invalid_variable;
            }

            if (sc->source->data[i] == '$') {
                name.data = &sc->source->data[i];
                i++;
                name.len++;

                if (njt_stream_lua_script_add_copy_code(sc, &name,
                                                        i == sc->source->len)
                    != NJT_OK)
                {
                    return NJT_ERROR;
                }

                continue;
            }

            if (sc->source->data[i] >= '0' && sc->source->data[i] <= '9') {
                num_var = 1;
                n = 0;

            } else {
                num_var = 0;
            }

            if (sc->source->data[i] == '{') {
                bracket = 1;

                if (++i == sc->source->len) {
                    goto invalid_variable;
                }

                if (sc->source->data[i] >= '0' && sc->source->data[i] <= '9') {
                    num_var = 1;
                    n = 0;
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

                if (num_var) {
                    if (ch >= '0' && ch <= '9') {
                        n = n * 10 + (ch - '0');
                        continue;
                    }

                    break;
                }

                /* not a number variable like $1, $2, etc */

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
                njt_log_error(NJT_LOG_ERR, sc->log, 0,
                              "the closing bracket in \"%V\" "
                              "variable is missing", &name);
                return NJT_ERROR;
            }

            if (name.len == 0) {
                goto invalid_variable;
            }

            if (!num_var) {
                njt_log_error(NJT_LOG_ERR, sc->log, 0,
                              "attempt to use named capturing variable "
                              "\"%V\" (named captures not supported yet)",
                              &name);

                return NJT_ERROR;
            }

            sc->variables++;

            if (njt_stream_lua_script_add_capture_code(sc, n) != NJT_OK) {
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

        if (njt_stream_lua_script_add_copy_code(sc, &name,
                                                i == sc->source->len)
            != NJT_OK)
        {
            return NJT_ERROR;
        }
    }

    return njt_stream_lua_script_done(sc);

invalid_variable:

    njt_log_error(NJT_LOG_ERR, sc->log, 0,
                  "lua script: invalid capturing variable name found in \"%V\"",
                  sc->source);

    return NJT_ERROR;
}


static njt_int_t
njt_stream_lua_script_add_copy_code(njt_stream_lua_script_compile_t *sc,
    njt_str_t *value, njt_uint_t last)
{
    size_t      size, len;

    njt_stream_lua_script_copy_code_t        *code;

    len = value->len;

    code = njt_stream_lua_script_add_code(*sc->lengths,
                                     sizeof(njt_stream_lua_script_copy_code_t));
    if (code == NULL) {
        return NJT_ERROR;
    }

    code->code = (njt_stream_lua_script_code_pt) (void *)
                 njt_stream_lua_script_copy_len_code;
    code->len = len;

    size = (sizeof(njt_stream_lua_script_copy_code_t) + len +
            sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1);

    code = njt_stream_lua_script_add_code(*sc->values, size);
    if (code == NULL) {
        return NJT_ERROR;
    }

    code->code = njt_stream_lua_script_copy_code;
    code->len = len;

    njt_memcpy((u_char *) code + sizeof(njt_stream_lua_script_copy_code_t),
               value->data, value->len);

    return NJT_OK;
}


static size_t
njt_stream_lua_script_copy_len_code(njt_stream_lua_script_engine_t *e)
{
    njt_stream_lua_script_copy_code_t        *code;

    code = (njt_stream_lua_script_copy_code_t *) e->ip;

    e->ip += sizeof(njt_stream_lua_script_copy_code_t);

    return code->len;
}


static void
njt_stream_lua_script_copy_code(njt_stream_lua_script_engine_t *e)
{
    u_char          *p;

    njt_stream_lua_script_copy_code_t        *code;

    code = (njt_stream_lua_script_copy_code_t *) e->ip;

    p = e->pos;

    if (!e->skip) {
        e->pos = njt_copy(p, e->ip + sizeof(njt_stream_lua_script_copy_code_t),
                          code->len);
    }

    e->ip += sizeof(njt_stream_lua_script_copy_code_t)
          + ((code->len + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1));

    njt_log_debug2(NJT_LOG_DEBUG_STREAM, e->log, 0,
                   "lua script copy: \"%*s\"", e->pos - p, p);
}


static njt_int_t
njt_stream_lua_script_add_capture_code(njt_stream_lua_script_compile_t *sc,
    njt_uint_t n)
{
    njt_stream_lua_script_capture_code_t        *code;

    code = njt_stream_lua_script_add_code(*sc->lengths,
                                  sizeof(njt_stream_lua_script_capture_code_t));
    if (code == NULL) {
        return NJT_ERROR;
    }

    code->code = (njt_stream_lua_script_code_pt) (void *)
                 njt_stream_lua_script_copy_capture_len_code;
    code->n = 2 * n;

    code = njt_stream_lua_script_add_code(*sc->values,
                                  sizeof(njt_stream_lua_script_capture_code_t));
    if (code == NULL) {
        return NJT_ERROR;
    }

    code->code = njt_stream_lua_script_copy_capture_code;
    code->n = 2 * n;

    return NJT_OK;
}


static size_t
njt_stream_lua_script_copy_capture_len_code(njt_stream_lua_script_engine_t *e)
{
    int                         *cap;
    njt_uint_t                   n;

    njt_stream_lua_script_capture_code_t         *code;

    code = (njt_stream_lua_script_capture_code_t *) e->ip;

    e->ip += sizeof(njt_stream_lua_script_capture_code_t);

    n = code->n;

    if (n < e->ncaptures) {
        cap = e->captures;
        return cap[n + 1] - cap[n];
    }

    return 0;
}


static void
njt_stream_lua_script_copy_capture_code(njt_stream_lua_script_engine_t *e)
{
    int                                  *cap;
    u_char                               *p, *pos;
    njt_uint_t                            n;

    njt_stream_lua_script_capture_code_t         *code;

    code = (njt_stream_lua_script_capture_code_t *) e->ip;

    e->ip += sizeof(njt_stream_lua_script_capture_code_t);

    n = code->n;

    pos = e->pos;

    if (n < e->ncaptures) {

        cap = e->captures;
        p = e->captures_data;

        e->pos = njt_copy(pos, &p[cap[n]], cap[n + 1] - cap[n]);
    }

    njt_log_debug2(NJT_LOG_DEBUG_STREAM, e->log, 0,
                   "lua script capture: \"%*s\"", e->pos - pos, pos);
}


static njt_int_t
njt_stream_lua_script_init_arrays(njt_stream_lua_script_compile_t *sc)
{
    njt_uint_t   n;

    if (*sc->lengths == NULL) {
        n = sc->variables * (2 * sizeof(njt_stream_lua_script_copy_code_t)
                             + sizeof(njt_stream_lua_script_capture_code_t))
            + sizeof(uintptr_t);

        *sc->lengths = njt_array_create(sc->pool, n, 1);
        if (*sc->lengths == NULL) {
            return NJT_ERROR;
        }
    }

    if (*sc->values == NULL) {
        n = (sc->variables * (2 * sizeof(njt_stream_lua_script_copy_code_t)
                              + sizeof(njt_stream_lua_script_capture_code_t))
                + sizeof(uintptr_t)
                + sizeof(uintptr_t) - 1)
            & ~(sizeof(uintptr_t) - 1);

        *sc->values = njt_array_create(sc->pool, n, 1);
        if (*sc->values == NULL) {
            return NJT_ERROR;
        }
    }

    sc->variables = 0;

    return NJT_OK;
}


static njt_int_t
njt_stream_lua_script_done(njt_stream_lua_script_compile_t *sc)
{
    uintptr_t   *code;

    if (sc->complete_lengths) {
        code = njt_stream_lua_script_add_code(*sc->lengths, sizeof(uintptr_t));
        if (code == NULL) {
            return NJT_ERROR;
        }

        *code = (uintptr_t) NULL;
    }

    if (sc->complete_values) {
        code = njt_stream_lua_script_add_code(*sc->values, sizeof(uintptr_t));
        if (code == NULL) {
            return NJT_ERROR;
        }

        *code = (uintptr_t) NULL;
    }

    return NJT_OK;
}


static void *
njt_stream_lua_script_add_code(njt_array_t *codes, size_t size)
{
    return njt_array_push_n(codes, size);
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
