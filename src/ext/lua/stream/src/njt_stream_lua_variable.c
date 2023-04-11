
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_variable.c.tt2
 */


/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_stream_lua_util.h"




int
njt_stream_lua_ffi_var_get(njt_stream_lua_request_t *r, u_char *name_data,
    size_t name_len, u_char *lowcase_buf, int capture_id, u_char **value,
    size_t *value_len, char **err)
{
    njt_uint_t                   hash;
    njt_str_t                    name;

    njt_stream_variable_value_t         *vv;

    if (r == NULL) {
        *err = "no request object found";
        return NJT_ERROR;
    }

    if ((r)->connection->fd == (njt_socket_t) -1) {
        *err = "API disabled in the current context";
        return NJT_ERROR;
    }


    hash = njt_hash_strlow(lowcase_buf, name_data, name_len);

    name.data = lowcase_buf;
    name.len = name_len;

    dd("variable name: %.*s", (int) name_len, lowcase_buf);

    vv = njt_stream_get_variable(r->session, &name, hash);

    if (vv == NULL || vv->not_found) {
        return NJT_DECLINED;
    }

    *value = vv->data;
    *value_len = vv->len;
    return NJT_OK;
}


int
njt_stream_lua_ffi_var_set(njt_stream_lua_request_t *r, u_char *name_data,
    size_t name_len, u_char *lowcase_buf, u_char *value, size_t value_len,
    u_char *errbuf, size_t *errlen)
{
    u_char                      *p;
    njt_uint_t                   hash;

    njt_stream_variable_t               *v;
    njt_stream_variable_value_t         *vv;
    njt_stream_core_main_conf_t         *cmcf;

    if (r == NULL) {
        *errlen = njt_snprintf(errbuf, *errlen, "no request object found")
                  - errbuf;
        return NJT_ERROR;
    }

    if ((r)->connection->fd == (njt_socket_t) -1) {
        *errlen = njt_snprintf(errbuf, *errlen,
                               "API disabled in the current context")
                  - errbuf;
        return NJT_ERROR;
    }

    hash = njt_hash_strlow(lowcase_buf, name_data, name_len);

    dd("variable name: %.*s", (int) name_len, lowcase_buf);

    /* we fetch the variable itself */

    cmcf = njt_stream_lua_get_module_main_conf(r, njt_stream_core_module);

    v = njt_hash_find(&cmcf->variables_hash, hash, lowcase_buf, name_len);

    if (v) {
        if (!(v->flags & NJT_STREAM_VAR_CHANGEABLE)) {
            dd("variable not changeable");
            *errlen = njt_snprintf(errbuf, *errlen,
                                   "variable \"%*s\" not changeable",
                                   name_len, lowcase_buf)
                      - errbuf;
            return NJT_ERROR;
        }

        if (v->set_handler) {

            dd("set variables with set_handler");

            if (value != NULL && value_len) {
                vv = njt_palloc(r->connection->pool,
                                sizeof(njt_stream_variable_value_t)
                                + value_len);
                if (vv == NULL) {
                    goto nomem;
                }

                p = (u_char *) vv + sizeof(njt_stream_variable_value_t);
                njt_memcpy(p, value, value_len);
                value = p;

            } else {
                vv = njt_palloc(r->connection->pool,
                                sizeof(njt_stream_variable_value_t));
                if (vv == NULL) {
                    goto nomem;
                }
            }

            if (value == NULL) {
                vv->valid = 0;
                vv->not_found = 1;
                vv->no_cacheable = 0;
                vv->data = NULL;
                vv->len = 0;

            } else {
                vv->valid = 1;
                vv->not_found = 0;
                vv->no_cacheable = 0;

                vv->data = value;
                vv->len = value_len;
            }

            v->set_handler(r->session, vv, v->data);
            return NJT_OK;
        }

        if (v->flags & NJT_STREAM_VAR_INDEXED) {
            vv = &r->session->variables[v->index];

            dd("set indexed variable");

            if (value == NULL) {
                vv->valid = 0;
                vv->not_found = 1;
                vv->no_cacheable = 0;

                vv->data = NULL;
                vv->len = 0;

            } else {
                p = njt_palloc(r->connection->pool, value_len);
                if (p == NULL) {
                    goto nomem;
                }

                njt_memcpy(p, value, value_len);
                value = p;

                vv->valid = 1;
                vv->not_found = 0;
                vv->no_cacheable = 0;

                vv->data = value;
                vv->len = value_len;
            }

            return NJT_OK;
        }

        *errlen = njt_snprintf(errbuf, *errlen,
                               "variable \"%*s\" cannot be assigned "
                               "a value", name_len, lowcase_buf)
                  - errbuf;
        return NJT_ERROR;
    }

    /* variable not found */

    *errlen = njt_snprintf(errbuf, *errlen,
                           "variable \"%*s\" not found for writing; "
                           "maybe it is a built-in variable that is not "
                           "changeable or you forgot to use \"set $%*s '';\" "
                           "in the config file to define it first",
                           name_len, lowcase_buf, name_len, lowcase_buf)
              - errbuf;
    return NJT_ERROR;

nomem:

    *errlen = njt_snprintf(errbuf, *errlen, "no memory") - errbuf;
    return NJT_ERROR;
}


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
