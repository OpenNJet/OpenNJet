
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>
#include <njet.h>

static njt_stream_variable_t *njt_stream_add_prefix_variable(njt_conf_t *cf,
    njt_str_t *name, njt_uint_t flags);

static njt_int_t njt_stream_variable_binary_remote_addr(
    njt_stream_session_t *s, njt_stream_variable_value_t *v, uintptr_t data);
static njt_int_t njt_stream_variable_remote_addr(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data);
static njt_int_t njt_stream_variable_remote_port(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data);
static njt_int_t njt_stream_variable_proxy_protocol_addr(
    njt_stream_session_t *s, njt_stream_variable_value_t *v, uintptr_t data);
static njt_int_t njt_stream_variable_proxy_protocol_port(
    njt_stream_session_t *s, njt_stream_variable_value_t *v, uintptr_t data);
static njt_int_t njt_stream_variable_server_addr(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data);
static njt_int_t njt_stream_variable_server_port(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data);
static njt_int_t njt_stream_variable_bytes(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data);
static njt_int_t njt_stream_variable_session_time(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data);
static njt_int_t njt_stream_variable_status(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data);
static njt_int_t njt_stream_variable_connection(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data);

static njt_int_t njt_stream_variable_njet_version(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data);
static njt_int_t njt_stream_variable_hostname(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data);
static njt_int_t njt_stream_variable_pid(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data);
static njt_int_t njt_stream_variable_msec(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data);
static njt_int_t njt_stream_variable_time_iso8601(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data);
static njt_int_t njt_stream_variable_time_local(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data);
static njt_int_t njt_stream_variable_protocol(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data);


static njt_stream_variable_t  njt_stream_core_variables[] = {

    { njt_string("binary_remote_addr"), NULL,
      njt_stream_variable_binary_remote_addr, 0, 0, 0 },

    { njt_string("remote_addr"), NULL,
      njt_stream_variable_remote_addr, 0, 0, 0 },

    { njt_string("remote_port"), NULL,
      njt_stream_variable_remote_port, 0, 0, 0 },

    { njt_string("proxy_protocol_addr"), NULL,
      njt_stream_variable_proxy_protocol_addr,
      offsetof(njt_proxy_protocol_t, src_addr), 0, 0 },

    { njt_string("proxy_protocol_port"), NULL,
      njt_stream_variable_proxy_protocol_port,
      offsetof(njt_proxy_protocol_t, src_port), 0, 0 },

    { njt_string("proxy_protocol_server_addr"), NULL,
      njt_stream_variable_proxy_protocol_addr,
      offsetof(njt_proxy_protocol_t, dst_addr), 0, 0 },

    { njt_string("proxy_protocol_server_port"), NULL,
      njt_stream_variable_proxy_protocol_port,
      offsetof(njt_proxy_protocol_t, dst_port), 0, 0 },

    { njt_string("server_addr"), NULL,
      njt_stream_variable_server_addr, 0, 0, 0 },

    { njt_string("server_port"), NULL,
      njt_stream_variable_server_port, 0, 0, 0 },

    { njt_string("bytes_sent"), NULL, njt_stream_variable_bytes,
      0, 0, 0 },

    { njt_string("bytes_received"), NULL, njt_stream_variable_bytes,
      1, 0, 0 },

    { njt_string("session_time"), NULL, njt_stream_variable_session_time,
      0, NJT_STREAM_VAR_NOCACHEABLE, 0 },

    { njt_string("status"), NULL, njt_stream_variable_status,
      0, NJT_STREAM_VAR_NOCACHEABLE, 0 },

    { njt_string("connection"), NULL,
      njt_stream_variable_connection, 0, 0, 0 },

    { njt_string("njet_version"), NULL, njt_stream_variable_njet_version,
      0, 0, 0 },

    { njt_string("hostname"), NULL, njt_stream_variable_hostname,
      0, 0, 0 },

    { njt_string("pid"), NULL, njt_stream_variable_pid,
      0, 0, 0 },

    { njt_string("msec"), NULL, njt_stream_variable_msec,
      0, NJT_STREAM_VAR_NOCACHEABLE, 0 },

    { njt_string("time_iso8601"), NULL, njt_stream_variable_time_iso8601,
      0, NJT_STREAM_VAR_NOCACHEABLE, 0 },

    { njt_string("time_local"), NULL, njt_stream_variable_time_local,
      0, NJT_STREAM_VAR_NOCACHEABLE, 0 },

    { njt_string("protocol"), NULL,
      njt_stream_variable_protocol, 0, 0, 0 },

      njt_stream_null_variable
};


njt_stream_variable_value_t  njt_stream_variable_null_value =
    njt_stream_variable("");
njt_stream_variable_value_t  njt_stream_variable_true_value =
    njt_stream_variable("1");


static njt_uint_t  njt_stream_variable_depth = 100;


njt_stream_variable_t *
njt_stream_add_variable(njt_conf_t *cf, njt_str_t *name, njt_uint_t flags)
{
    njt_int_t                     rc;
    njt_uint_t                    i;
    njt_hash_key_t               *key;
    njt_stream_variable_t        *v;
    njt_stream_core_main_conf_t  *cmcf;

    if (name->len == 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid variable name \"$\"");
        return NULL;
    }

    if (flags & NJT_STREAM_VAR_PREFIX) {
        return njt_stream_add_prefix_variable(cf, name, flags);
    }

    cmcf = njt_stream_conf_get_module_main_conf(cf, njt_stream_core_module);

    key = cmcf->variables_keys->keys.elts;
    for (i = 0; i < cmcf->variables_keys->keys.nelts; i++) {
        if (name->len != key[i].key.len
            || njt_strncasecmp(name->data, key[i].key.data, name->len) != 0)
        {
            continue;
        }

        v = key[i].value;

        if (!(v->flags & NJT_STREAM_VAR_CHANGEABLE)) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "the duplicate \"%V\" variable", name);
            return NULL;
        }

        if (!(flags & NJT_STREAM_VAR_WEAK)) {
            v->flags &= ~NJT_STREAM_VAR_WEAK;
        }

        return v;
    }

    v = njt_palloc(cf->pool, sizeof(njt_stream_variable_t));
    if (v == NULL) {
        return NULL;
    }

    v->name.len = name->len;
    v->name.data = njt_pnalloc(cf->pool, name->len);
    if (v->name.data == NULL) {
        return NULL;
    }

    njt_strlow(v->name.data, name->data, name->len);

    v->set_handler = NULL;
    v->get_handler = NULL;
    v->data = 0;
    v->flags = flags;
    v->index = 0;

    rc = njt_hash_add_key(cmcf->variables_keys, &v->name, v, 0);

    if (rc == NJT_ERROR) {
        return NULL;
    }

    if (rc == NJT_BUSY) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "conflicting variable name \"%V\"", name);
        return NULL;
    }

    return v;
}


static njt_stream_variable_t *
njt_stream_add_prefix_variable(njt_conf_t *cf, njt_str_t *name,
    njt_uint_t flags)
{
    njt_uint_t                    i;
    njt_stream_variable_t        *v;
    njt_stream_core_main_conf_t  *cmcf;

    cmcf = njt_stream_conf_get_module_main_conf(cf, njt_stream_core_module);

    v = cmcf->prefix_variables.elts;
    for (i = 0; i < cmcf->prefix_variables.nelts; i++) {
        if (name->len != v[i].name.len
            || njt_strncasecmp(name->data, v[i].name.data, name->len) != 0)
        {
            continue;
        }

        v = &v[i];

        if (!(v->flags & NJT_STREAM_VAR_CHANGEABLE)) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "the duplicate \"%V\" variable", name);
            return NULL;
        }

        if (!(flags & NJT_STREAM_VAR_WEAK)) {
            v->flags &= ~NJT_STREAM_VAR_WEAK;
        }

        return v;
    }

    v = njt_array_push(&cmcf->prefix_variables);
    if (v == NULL) {
        return NULL;
    }

    v->name.len = name->len;
    v->name.data = njt_pnalloc(cf->pool, name->len);
    if (v->name.data == NULL) {
        return NULL;
    }

    njt_strlow(v->name.data, name->data, name->len);

    v->set_handler = NULL;
    v->get_handler = NULL;
    v->data = 0;
    v->flags = flags;
    v->index = 0;

    return v;
}


njt_int_t
njt_stream_get_variable_index(njt_conf_t *cf, njt_str_t *name)
{
    njt_uint_t                    i;
    njt_stream_variable_t        *v;
    njt_stream_core_main_conf_t  *cmcf;

    if (name->len == 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid variable name \"$\"");
        return NJT_ERROR;
    }

    cmcf = njt_stream_conf_get_module_main_conf(cf, njt_stream_core_module);

    v = cmcf->variables.elts;

    if (v == NULL) {
        if (njt_array_init(&cmcf->variables, cf->pool, 4,
                           sizeof(njt_stream_variable_t))
            != NJT_OK)
        {
            return NJT_ERROR;
        }

    } else {
        for (i = 0; i < cmcf->variables.nelts; i++) {
            if (name->len != v[i].name.len
                || njt_strncasecmp(name->data, v[i].name.data, name->len) != 0)
            {
                continue;
            }

            return i;
        }
    }

    v = njt_array_push(&cmcf->variables);
    if (v == NULL) {
        return NJT_ERROR;
    }

    v->name.len = name->len;
#if (NJT_HTTP_DYNAMIC_LOC)
	v->name.data = njt_pnalloc(cmcf->variables.pool, name->len);
#else
	v->name.data = njt_pnalloc(cf->pool, name->len);
#endif

    if (v->name.data == NULL) {
        return NJT_ERROR;
    }

    njt_strlow(v->name.data, name->data, name->len);

    v->set_handler = NULL;
    v->get_handler = NULL;
    v->data = 0;
    v->flags = 0;
    v->index = cmcf->variables.nelts - 1;

    return v->index;
}


njt_stream_variable_value_t *
njt_stream_get_indexed_variable(njt_stream_session_t *s, njt_uint_t index)
{
    njt_stream_variable_t        *v;
    njt_stream_core_main_conf_t  *cmcf;

    cmcf = njt_stream_get_module_main_conf(s, njt_stream_core_module);

    if (cmcf->variables.nelts <= index) {
        njt_log_error(NJT_LOG_ALERT, s->connection->log, 0,
                      "unknown variable index: %ui", index);
        return NULL;
    }

    if (s->variables[index].not_found || s->variables[index].valid) {
        return &s->variables[index];
    }

    v = cmcf->variables.elts;

    if (njt_stream_variable_depth == 0) {
        njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                      "cycle while evaluating variable \"%V\"",
                      &v[index].name);
        return NULL;
    }

    njt_stream_variable_depth--;

    if (v[index].get_handler && v[index].get_handler(s, &s->variables[index], v[index].data)
        == NJT_OK)
    {
        njt_stream_variable_depth++;

        if (v[index].flags & NJT_STREAM_VAR_NOCACHEABLE) {
            s->variables[index].no_cacheable = 1;
        }

        return &s->variables[index];
    }

    njt_stream_variable_depth++;

    s->variables[index].valid = 0;
    s->variables[index].not_found = 1;

    return NULL;
}


njt_stream_variable_value_t *
njt_stream_get_flushed_variable(njt_stream_session_t *s, njt_uint_t index)
{
    njt_stream_variable_value_t  *v;

    v = &s->variables[index];

    if (v->valid || v->not_found) {
        if (!v->no_cacheable) {
            return v;
        }

        v->valid = 0;
        v->not_found = 0;
    }

    return njt_stream_get_indexed_variable(s, index);
}


njt_stream_variable_value_t *
njt_stream_get_variable(njt_stream_session_t *s, njt_str_t *name,
    njt_uint_t key)
{
    size_t                        len;
    njt_uint_t                    i, n;
    njt_stream_variable_t        *v;
    njt_stream_variable_value_t  *vv;
    njt_stream_core_main_conf_t  *cmcf;

    cmcf = njt_stream_get_module_main_conf(s, njt_stream_core_module);

    v = njt_hash_find(&cmcf->variables_hash, key, name->data, name->len);

    if (v) {
        if (v->flags & NJT_STREAM_VAR_INDEXED) {
            return njt_stream_get_flushed_variable(s, v->index);
        }

        if (njt_stream_variable_depth == 0) {
            njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                          "cycle while evaluating variable \"%V\"", name);
            return NULL;
        }

        njt_stream_variable_depth--;

        vv = njt_palloc(s->connection->pool,
                        sizeof(njt_stream_variable_value_t));

        if (vv && v->get_handler(s, vv, v->data) == NJT_OK) {
            njt_stream_variable_depth++;
            return vv;
        }

        njt_stream_variable_depth++;
        return NULL;
    }

    vv = njt_palloc(s->connection->pool, sizeof(njt_stream_variable_value_t));
    if (vv == NULL) {
        return NULL;
    }

    len = 0;

    v = cmcf->prefix_variables.elts;
    n = cmcf->prefix_variables.nelts;

    for (i = 0; i < cmcf->prefix_variables.nelts; i++) {
        if (name->len >= v[i].name.len && name->len > len
            && njt_strncmp(name->data, v[i].name.data, v[i].name.len) == 0)
        {
            len = v[i].name.len;
            n = i;
        }
    }

    if (n != cmcf->prefix_variables.nelts) {
        if (v[n].get_handler(s, vv, (uintptr_t) name) == NJT_OK) {
            return vv;
        }

        return NULL;
    }

    vv->not_found = 1;

    return vv;
}


static njt_int_t
njt_stream_variable_binary_remote_addr(njt_stream_session_t *s,
     njt_stream_variable_value_t *v, uintptr_t data)
{
    struct sockaddr_in   *sin;
#if (NJT_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    switch (s->connection->sockaddr->sa_family) {

#if (NJT_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) s->connection->sockaddr;

        v->len = sizeof(struct in6_addr);
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = sin6->sin6_addr.s6_addr;

        break;
#endif

#if (NJT_HAVE_UNIX_DOMAIN)
    case AF_UNIX:

        v->len = s->connection->addr_text.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = s->connection->addr_text.data;

        break;
#endif

    default: /* AF_INET */
        sin = (struct sockaddr_in *) s->connection->sockaddr;

        v->len = sizeof(in_addr_t);
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = (u_char *) &sin->sin_addr;

        break;
    }

    return NJT_OK;
}


static njt_int_t
njt_stream_variable_remote_addr(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    v->len = s->connection->addr_text.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = s->connection->addr_text.data;

    return NJT_OK;
}


static njt_int_t
njt_stream_variable_remote_port(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    njt_uint_t  port;

    v->len = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = njt_pnalloc(s->connection->pool, sizeof("65535") - 1);
    if (v->data == NULL) {
        return NJT_ERROR;
    }

    port = njt_inet_get_port(s->connection->sockaddr);

    if (port > 0 && port < 65536) {
        v->len = njt_sprintf(v->data, "%ui", port) - v->data;
    }

    return NJT_OK;
}


static njt_int_t
njt_stream_variable_proxy_protocol_addr(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    njt_str_t             *addr;
    njt_proxy_protocol_t  *pp;

    pp = s->connection->proxy_protocol;
    if (pp == NULL) {
        v->not_found = 1;
        return NJT_OK;
    }

    addr = (njt_str_t *) ((char *) pp + data);

    v->len = addr->len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = addr->data;

    return NJT_OK;
}


static njt_int_t
njt_stream_variable_proxy_protocol_port(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    njt_uint_t             port;
    njt_proxy_protocol_t  *pp;

    pp = s->connection->proxy_protocol;
    if (pp == NULL) {
        v->not_found = 1;
        return NJT_OK;
    }

    v->len = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = njt_pnalloc(s->connection->pool, sizeof("65535") - 1);
    if (v->data == NULL) {
        return NJT_ERROR;
    }

    port = *(in_port_t *) ((char *) pp + data);

    if (port > 0 && port < 65536) {
        v->len = njt_sprintf(v->data, "%ui", port) - v->data;
    }

    return NJT_OK;
}


static njt_int_t
njt_stream_variable_server_addr(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    njt_str_t  str;
    u_char     addr[NJT_SOCKADDR_STRLEN];

    str.len = NJT_SOCKADDR_STRLEN;
    str.data = addr;

    if (njt_connection_local_sockaddr(s->connection, &str, 0) != NJT_OK) {
        return NJT_ERROR;
    }

    str.data = njt_pnalloc(s->connection->pool, str.len);
    if (str.data == NULL) {
        return NJT_ERROR;
    }

    njt_memcpy(str.data, addr, str.len);

    v->len = str.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = str.data;

    return NJT_OK;
}


static njt_int_t
njt_stream_variable_server_port(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    njt_uint_t  port;

    v->len = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (njt_connection_local_sockaddr(s->connection, NULL, 0) != NJT_OK) {
        return NJT_ERROR;
    }

    v->data = njt_pnalloc(s->connection->pool, sizeof("65535") - 1);
    if (v->data == NULL) {
        return NJT_ERROR;
    }

    port = njt_inet_get_port(s->connection->local_sockaddr);

    if (port > 0 && port < 65536) {
        v->len = njt_sprintf(v->data, "%ui", port) - v->data;
    }

    return NJT_OK;
}


static njt_int_t
njt_stream_variable_bytes(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = njt_pnalloc(s->connection->pool, NJT_OFF_T_LEN);
    if (p == NULL) {
        return NJT_ERROR;
    }

    if (data == 1) {
        v->len = njt_sprintf(p, "%O", s->received) - p;

    } else {
        v->len = njt_sprintf(p, "%O", s->connection->sent) - p;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NJT_OK;
}


static njt_int_t
njt_stream_variable_session_time(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    u_char          *p;
    njt_time_t      *tp;
    njt_msec_int_t   ms;

    p = njt_pnalloc(s->connection->pool, NJT_TIME_T_LEN + 4);
    if (p == NULL) {
        return NJT_ERROR;
    }

    tp = njt_timeofday();

    ms = (njt_msec_int_t)
             ((tp->sec - s->start_sec) * 1000 + (tp->msec - s->start_msec));
    ms = njt_max(ms, 0);

    v->len = njt_sprintf(p, "%T.%03M", (time_t) ms / 1000, ms % 1000) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NJT_OK;
}


static njt_int_t
njt_stream_variable_status(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    v->data = njt_pnalloc(s->connection->pool, NJT_INT_T_LEN);
    if (v->data == NULL) {
        return NJT_ERROR;
    }

    v->len = njt_sprintf(v->data, "%03ui", s->status) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NJT_OK;
}


static njt_int_t
njt_stream_variable_connection(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = njt_pnalloc(s->connection->pool, NJT_ATOMIC_T_LEN);
    if (p == NULL) {
        return NJT_ERROR;
    }

    v->len = njt_sprintf(p, "%uA", s->connection->number) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NJT_OK;
}


static njt_int_t
njt_stream_variable_njet_version(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    v->len = sizeof(NJT_VERSION) - 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) NJT_VERSION;

    return NJT_OK;
}


static njt_int_t
njt_stream_variable_hostname(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    v->len = njt_cycle->hostname.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = njt_cycle->hostname.data;

    return NJT_OK;
}


static njt_int_t
njt_stream_variable_pid(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = njt_pnalloc(s->connection->pool, NJT_INT64_LEN);
    if (p == NULL) {
        return NJT_ERROR;
    }

    v->len = njt_sprintf(p, "%P", njt_pid) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NJT_OK;
}


static njt_int_t
njt_stream_variable_msec(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    u_char      *p;
    njt_time_t  *tp;

    p = njt_pnalloc(s->connection->pool, NJT_TIME_T_LEN + 4);
    if (p == NULL) {
        return NJT_ERROR;
    }

    tp = njt_timeofday();

    v->len = njt_sprintf(p, "%T.%03M", tp->sec, tp->msec) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NJT_OK;
}


static njt_int_t
njt_stream_variable_time_iso8601(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = njt_pnalloc(s->connection->pool, njt_cached_http_log_iso8601.len);
    if (p == NULL) {
        return NJT_ERROR;
    }

    njt_memcpy(p, njt_cached_http_log_iso8601.data,
               njt_cached_http_log_iso8601.len);

    v->len = njt_cached_http_log_iso8601.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NJT_OK;
}


static njt_int_t
njt_stream_variable_time_local(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = njt_pnalloc(s->connection->pool, njt_cached_http_log_time.len);
    if (p == NULL) {
        return NJT_ERROR;
    }

    njt_memcpy(p, njt_cached_http_log_time.data, njt_cached_http_log_time.len);

    v->len = njt_cached_http_log_time.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NJT_OK;
}


static njt_int_t
njt_stream_variable_protocol(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    v->len = 3;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) (s->connection->type == SOCK_DGRAM ? "UDP" : "TCP");

    return NJT_OK;
}


void *
njt_stream_map_find(njt_stream_session_t *s, njt_stream_map_t *map,
    njt_str_t *match)
{
    void        *value;
    u_char      *low;
    size_t       len;
    njt_uint_t   key;

    len = match->len;

    if (len) {
        low = njt_pnalloc(s->connection->pool, len);
        if (low == NULL) {
            return NULL;
        }

    } else {
        low = NULL;
    }

    key = njt_hash_strlow(low, match->data, len);

    value = njt_hash_find_combined(&map->hash, key, low, len);
    if (value) {
        return value;
    }

#if (NJT_PCRE)

    if (len && map->nregex) {
        njt_int_t                n;
        njt_uint_t               i;
        njt_stream_map_regex_t  *reg;

        reg = map->regex;

        for (i = 0; i < map->nregex; i++) {

            n = njt_stream_regex_exec(s, reg[i].regex, match);

            if (n == NJT_OK) {
                return reg[i].value;
            }

            if (n == NJT_DECLINED) {
                continue;
            }

            /* NJT_ERROR */

            return NULL;
        }
    }

#endif

    return NULL;
}


#if (NJT_PCRE)

static njt_int_t
njt_stream_variable_not_found(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    v->not_found = 1;
    return NJT_OK;
}


njt_stream_regex_t *
njt_stream_regex_compile(njt_conf_t *cf, njt_regex_compile_t *rc)
{
    u_char                       *p;
    size_t                        size;
    njt_str_t                     name;
    njt_uint_t                    i, n;
    njt_stream_variable_t        *v;
    njt_stream_regex_t           *re;
    njt_stream_regex_variable_t  *rv;
    njt_stream_core_main_conf_t  *cmcf;

    rc->pool = cf->pool;

    if (njt_regex_compile(rc) != NJT_OK) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "%V", &rc->err);
        return NULL;
    }

    re = njt_pcalloc(cf->pool, sizeof(njt_stream_regex_t));
    if (re == NULL) {
        return NULL;
    }

    re->regex = rc->regex;
    re->ncaptures = rc->captures;
    re->name = rc->pattern;

    cmcf = njt_stream_conf_get_module_main_conf(cf, njt_stream_core_module);
    cmcf->ncaptures = njt_max(cmcf->ncaptures, re->ncaptures);

    n = (njt_uint_t) rc->named_captures;

    if (n == 0) {
        return re;
    }

    rv = njt_palloc(rc->pool, n * sizeof(njt_stream_regex_variable_t));
    if (rv == NULL) {
        return NULL;
    }

    re->variables = rv;
    re->nvariables = n;

    size = rc->name_size;
    p = rc->names;

    for (i = 0; i < n; i++) {
        rv[i].capture = 2 * ((p[0] << 8) + p[1]);

        name.data = &p[2];
        name.len = njt_strlen(name.data);

        v = njt_stream_add_variable(cf, &name, NJT_STREAM_VAR_CHANGEABLE);
        if (v == NULL) {
            return NULL;
        }

        rv[i].index = njt_stream_get_variable_index(cf, &name);
        if (rv[i].index == NJT_ERROR) {
            return NULL;
        }

        v->get_handler = njt_stream_variable_not_found;

        p += size;
    }

    return re;
}


njt_int_t
njt_stream_regex_exec(njt_stream_session_t *s, njt_stream_regex_t *re,
    njt_str_t *str)
{
    njt_int_t                     rc, index;
    njt_uint_t                    i, n, len;
    njt_stream_variable_value_t  *vv;
    njt_stream_core_main_conf_t  *cmcf;

    cmcf = njt_stream_get_module_main_conf(s, njt_stream_core_module);

    if (re->ncaptures) {
        len = cmcf->ncaptures;

        if (s->captures == NULL) {
            s->captures = njt_palloc(s->connection->pool, len * sizeof(int));
            if (s->captures == NULL) {
                return NJT_ERROR;
            }
        }

    } else {
        len = 0;
    }

    rc = njt_regex_exec(re->regex, str, s->captures, len);

    if (rc == NJT_REGEX_NO_MATCHED) {
        return NJT_DECLINED;
    }

    if (rc < 0) {
        njt_log_error(NJT_LOG_ALERT, s->connection->log, 0,
                      njt_regex_exec_n " failed: %i on \"%V\" using \"%V\"",
                      rc, str, &re->name);
        return NJT_ERROR;
    }

    for (i = 0; i < re->nvariables; i++) {

        n = re->variables[i].capture;
        index = re->variables[i].index;
        vv = &s->variables[index];

        vv->len = s->captures[n + 1] - s->captures[n];
        vv->valid = 1;
        vv->no_cacheable = 0;
        vv->not_found = 0;
        vv->data = &str->data[s->captures[n]];

#if (NJT_DEBUG)
        {
        njt_stream_variable_t  *v;

        v = cmcf->variables.elts;

        njt_log_debug2(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "stream regex set $%V to \"%v\"", &v[index].name, vv);
        }
#endif
    }

    s->ncaptures = rc * 2;
    s->captures_data = str->data;

    return NJT_OK;
}

#endif


njt_int_t
njt_stream_variables_add_core_vars(njt_conf_t *cf)
{
    njt_stream_variable_t        *cv, *v;
    njt_stream_core_main_conf_t  *cmcf;

    cmcf = njt_stream_conf_get_module_main_conf(cf, njt_stream_core_module);

    cmcf->variables_keys = njt_pcalloc(cf->temp_pool,
                                       sizeof(njt_hash_keys_arrays_t));
    if (cmcf->variables_keys == NULL) {
        return NJT_ERROR;
    }

    cmcf->variables_keys->pool = cf->pool;
    cmcf->variables_keys->temp_pool = cf->pool;

    if (njt_hash_keys_array_init(cmcf->variables_keys, NJT_HASH_SMALL)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    if (njt_array_init(&cmcf->prefix_variables, cf->pool, 8,
                       sizeof(njt_stream_variable_t))
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    for (cv = njt_stream_core_variables; cv->name.len; cv++) {
        v = njt_stream_add_variable(cf, &cv->name, cv->flags);
        if (v == NULL) {
            return NJT_ERROR;
        }

        *v = *cv;
    }

    return NJT_OK;
}


njt_int_t
njt_stream_variables_init_vars(njt_conf_t *cf)
{
    size_t                        len;
    njt_uint_t                    i, n;
    njt_hash_key_t               *key;
    njt_hash_init_t               hash;
    njt_stream_variable_t        *v, *av, *pv;
    njt_stream_core_main_conf_t  *cmcf;

    /* set the handlers for the indexed stream variables */

    cmcf = njt_stream_conf_get_module_main_conf(cf, njt_stream_core_module);

    v = cmcf->variables.elts;
    pv = cmcf->prefix_variables.elts;
    key = cmcf->variables_keys->keys.elts;

    for (i = 0; i < cmcf->variables.nelts; i++) {

        for (n = 0; n < cmcf->variables_keys->keys.nelts; n++) {

            av = key[n].value;

            if (v[i].name.len == key[n].key.len
                && njt_strncmp(v[i].name.data, key[n].key.data, v[i].name.len)
                   == 0)
            {
                v[i].get_handler = av->get_handler;
                v[i].data = av->data;

                av->flags |= NJT_STREAM_VAR_INDEXED;
                v[i].flags = av->flags;

                av->index = i;

                if (av->get_handler == NULL
                    || (av->flags & NJT_STREAM_VAR_WEAK))
                {
                    break;
                }

                goto next;
            }
        }

        len = 0;
        av = NULL;

        for (n = 0; n < cmcf->prefix_variables.nelts; n++) {
            if (v[i].name.len >= pv[n].name.len && v[i].name.len > len
                && njt_strncmp(v[i].name.data, pv[n].name.data, pv[n].name.len)
                   == 0)
            {
                av = &pv[n];
                len = pv[n].name.len;
            }
        }

        if (av) {
            v[i].get_handler = av->get_handler;
            v[i].data = (uintptr_t) &v[i].name;
            v[i].flags = av->flags;

            goto next;
         }

        if (v[i].get_handler == NULL) {
            njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                          "unknown \"%V\" variable", &v[i].name);
            return NJT_ERROR;
        }

    next:
        continue;
    }


    for (n = 0; n < cmcf->variables_keys->keys.nelts; n++) {
        av = key[n].value;

        if (av->flags & NJT_STREAM_VAR_NOHASH) {
            key[n].key.data = NULL;
        }
    }


    hash.hash = &cmcf->variables_hash;
    hash.key = njt_hash_key;
    hash.max_size = cmcf->variables_hash_max_size;
    hash.bucket_size = cmcf->variables_hash_bucket_size;
    hash.name = "variables_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    if (njt_hash_init(&hash, cmcf->variables_keys->keys.elts,
                      cmcf->variables_keys->keys.nelts)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    return NJT_OK;
}
