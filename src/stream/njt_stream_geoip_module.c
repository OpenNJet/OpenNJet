
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) TMLake, Inc.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>

#include <GeoIP.h>
#include <GeoIPCity.h>


#define NJT_GEOIP_COUNTRY_CODE   0
#define NJT_GEOIP_COUNTRY_CODE3  1
#define NJT_GEOIP_COUNTRY_NAME   2


typedef struct {
    GeoIP        *country;
    GeoIP        *org;
    GeoIP        *city;
#if (NJT_HAVE_GEOIP_V6)
    unsigned      country_v6:1;
    unsigned      org_v6:1;
    unsigned      city_v6:1;
#endif
} njt_stream_geoip_conf_t;


typedef struct {
    njt_str_t    *name;
    uintptr_t     data;
} njt_stream_geoip_var_t;


typedef const char *(*njt_stream_geoip_variable_handler_pt)(GeoIP *,
    u_long addr);


njt_stream_geoip_variable_handler_pt njt_stream_geoip_country_functions[] = {
    GeoIP_country_code_by_ipnum,
    GeoIP_country_code3_by_ipnum,
    GeoIP_country_name_by_ipnum,
};


#if (NJT_HAVE_GEOIP_V6)

typedef const char *(*njt_stream_geoip_variable_handler_v6_pt)(GeoIP *,
    geoipv6_t addr);


njt_stream_geoip_variable_handler_v6_pt
    njt_stream_geoip_country_v6_functions[] =
{
    GeoIP_country_code_by_ipnum_v6,
    GeoIP_country_code3_by_ipnum_v6,
    GeoIP_country_name_by_ipnum_v6,
};

#endif


static njt_int_t njt_stream_geoip_country_variable(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data);
static njt_int_t njt_stream_geoip_org_variable(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data);
static njt_int_t njt_stream_geoip_city_variable(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data);
static njt_int_t njt_stream_geoip_region_name_variable(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data);
static njt_int_t njt_stream_geoip_city_float_variable(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data);
static njt_int_t njt_stream_geoip_city_int_variable(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data);
static GeoIPRecord *njt_stream_geoip_get_city_record(njt_stream_session_t *s);

static njt_int_t njt_stream_geoip_add_variables(njt_conf_t *cf);
static void *njt_stream_geoip_create_conf(njt_conf_t *cf);
static char *njt_stream_geoip_country(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_stream_geoip_org(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_stream_geoip_city(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static void njt_stream_geoip_cleanup(void *data);


static njt_command_t  njt_stream_geoip_commands[] = {

    { njt_string("geoip_country"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_TAKE12,
      njt_stream_geoip_country,
      NJT_STREAM_MAIN_CONF_OFFSET,
      0,
      NULL },

    { njt_string("geoip_org"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_TAKE12,
      njt_stream_geoip_org,
      NJT_STREAM_MAIN_CONF_OFFSET,
      0,
      NULL },

    { njt_string("geoip_city"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_TAKE12,
      njt_stream_geoip_city,
      NJT_STREAM_MAIN_CONF_OFFSET,
      0,
      NULL },

      njt_null_command
};


static njt_stream_module_t  njt_stream_geoip_module_ctx = {
    njt_stream_geoip_add_variables,        /* preconfiguration */
    NULL,                                  /* postconfiguration */

    njt_stream_geoip_create_conf,          /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL                                   /* merge server configuration */
};


njt_module_t  njt_stream_geoip_module = {
    NJT_MODULE_V1,
    &njt_stream_geoip_module_ctx,          /* module context */
    njt_stream_geoip_commands,             /* module directives */
    NJT_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};


static njt_stream_variable_t  njt_stream_geoip_vars[] = {

    { njt_string("geoip_country_code"), NULL,
      njt_stream_geoip_country_variable,
      NJT_GEOIP_COUNTRY_CODE, 0, 0 },

    { njt_string("geoip_country_code3"), NULL,
      njt_stream_geoip_country_variable,
      NJT_GEOIP_COUNTRY_CODE3, 0, 0 },

    { njt_string("geoip_country_name"), NULL,
      njt_stream_geoip_country_variable,
      NJT_GEOIP_COUNTRY_NAME, 0, 0 },

    { njt_string("geoip_org"), NULL,
      njt_stream_geoip_org_variable,
      0, 0, 0 },

    { njt_string("geoip_city_continent_code"), NULL,
      njt_stream_geoip_city_variable,
      offsetof(GeoIPRecord, continent_code), 0, 0 },

    { njt_string("geoip_city_country_code"), NULL,
      njt_stream_geoip_city_variable,
      offsetof(GeoIPRecord, country_code), 0, 0 },

    { njt_string("geoip_city_country_code3"), NULL,
      njt_stream_geoip_city_variable,
      offsetof(GeoIPRecord, country_code3), 0, 0 },

    { njt_string("geoip_city_country_name"), NULL,
      njt_stream_geoip_city_variable,
      offsetof(GeoIPRecord, country_name), 0, 0 },

    { njt_string("geoip_region"), NULL,
      njt_stream_geoip_city_variable,
      offsetof(GeoIPRecord, region), 0, 0 },

    { njt_string("geoip_region_name"), NULL,
      njt_stream_geoip_region_name_variable,
      0, 0, 0 },

    { njt_string("geoip_city"), NULL,
      njt_stream_geoip_city_variable,
      offsetof(GeoIPRecord, city), 0, 0 },

    { njt_string("geoip_postal_code"), NULL,
      njt_stream_geoip_city_variable,
      offsetof(GeoIPRecord, postal_code), 0, 0 },

    { njt_string("geoip_latitude"), NULL,
      njt_stream_geoip_city_float_variable,
      offsetof(GeoIPRecord, latitude), 0, 0 },

    { njt_string("geoip_longitude"), NULL,
      njt_stream_geoip_city_float_variable,
      offsetof(GeoIPRecord, longitude), 0, 0 },

    { njt_string("geoip_dma_code"), NULL,
      njt_stream_geoip_city_int_variable,
      offsetof(GeoIPRecord, dma_code), 0, 0 },

    { njt_string("geoip_area_code"), NULL,
      njt_stream_geoip_city_int_variable,
      offsetof(GeoIPRecord, area_code), 0, 0 },

      njt_stream_null_variable
};


static u_long
njt_stream_geoip_addr(njt_stream_session_t *s, njt_stream_geoip_conf_t *gcf)
{
    njt_addr_t           addr;
    struct sockaddr_in  *sin;

    addr.sockaddr = s->connection->sockaddr;
    addr.socklen = s->connection->socklen;
    /* addr.name = s->connection->addr_text; */

#if (NJT_HAVE_INET6)

    if (addr.sockaddr->sa_family == AF_INET6) {
        u_char           *p;
        in_addr_t         inaddr;
        struct in6_addr  *inaddr6;

        inaddr6 = &((struct sockaddr_in6 *) addr.sockaddr)->sin6_addr;

        if (IN6_IS_ADDR_V4MAPPED(inaddr6)) {
            p = inaddr6->s6_addr;

            inaddr = p[12] << 24;
            inaddr += p[13] << 16;
            inaddr += p[14] << 8;
            inaddr += p[15];

            return inaddr;
        }
    }

#endif

    if (addr.sockaddr->sa_family != AF_INET) {
        return INADDR_NONE;
    }

    sin = (struct sockaddr_in *) addr.sockaddr;
    return ntohl(sin->sin_addr.s_addr);
}


#if (NJT_HAVE_GEOIP_V6)

static geoipv6_t
njt_stream_geoip_addr_v6(njt_stream_session_t *s, njt_stream_geoip_conf_t *gcf)
{
    njt_addr_t            addr;
    in_addr_t             addr4;
    struct in6_addr       addr6;
    struct sockaddr_in   *sin;
    struct sockaddr_in6  *sin6;

    addr.sockaddr = s->connection->sockaddr;
    addr.socklen = s->connection->socklen;
    /* addr.name = s->connection->addr_text; */

    switch (addr.sockaddr->sa_family) {

    case AF_INET:
        /* Produce IPv4-mapped IPv6 address. */
        sin = (struct sockaddr_in *) addr.sockaddr;
        addr4 = ntohl(sin->sin_addr.s_addr);

        njt_memzero(&addr6, sizeof(struct in6_addr));
        addr6.s6_addr[10] = 0xff;
        addr6.s6_addr[11] = 0xff;
        addr6.s6_addr[12] = addr4 >> 24;
        addr6.s6_addr[13] = addr4 >> 16;
        addr6.s6_addr[14] = addr4 >> 8;
        addr6.s6_addr[15] = addr4;
        return addr6;

    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) addr.sockaddr;
        return sin6->sin6_addr;

    default:
        return in6addr_any;
    }
}

#endif


static njt_int_t
njt_stream_geoip_country_variable(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    njt_stream_geoip_variable_handler_pt     handler =
        njt_stream_geoip_country_functions[data];
#if (NJT_HAVE_GEOIP_V6)
    njt_stream_geoip_variable_handler_v6_pt  handler_v6 =
        njt_stream_geoip_country_v6_functions[data];
#endif

    const char               *val;
    njt_stream_geoip_conf_t  *gcf;

    gcf = njt_stream_get_module_main_conf(s, njt_stream_geoip_module);

    if (gcf->country == NULL) {
        goto not_found;
    }

#if (NJT_HAVE_GEOIP_V6)
    val = gcf->country_v6
              ? handler_v6(gcf->country, njt_stream_geoip_addr_v6(s, gcf))
              : handler(gcf->country, njt_stream_geoip_addr(s, gcf));
#else
    val = handler(gcf->country, njt_stream_geoip_addr(s, gcf));
#endif

    if (val == NULL) {
        goto not_found;
    }

    v->len = njt_strlen(val);
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) val;

    return NJT_OK;

not_found:

    v->not_found = 1;

    return NJT_OK;
}


static njt_int_t
njt_stream_geoip_org_variable(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    size_t                    len;
    char                     *val;
    njt_stream_geoip_conf_t  *gcf;

    gcf = njt_stream_get_module_main_conf(s, njt_stream_geoip_module);

    if (gcf->org == NULL) {
        goto not_found;
    }

#if (NJT_HAVE_GEOIP_V6)
    val = gcf->org_v6
              ? GeoIP_name_by_ipnum_v6(gcf->org,
                                       njt_stream_geoip_addr_v6(s, gcf))
              : GeoIP_name_by_ipnum(gcf->org,
                                    njt_stream_geoip_addr(s, gcf));
#else
    val = GeoIP_name_by_ipnum(gcf->org, njt_stream_geoip_addr(s, gcf));
#endif

    if (val == NULL) {
        goto not_found;
    }

    len = njt_strlen(val);
    v->data = njt_pnalloc(s->connection->pool, len);
    if (v->data == NULL) {
        njt_free(val);
        return NJT_ERROR;
    }

    njt_memcpy(v->data, val, len);

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    njt_free(val);

    return NJT_OK;

not_found:

    v->not_found = 1;

    return NJT_OK;
}


static njt_int_t
njt_stream_geoip_city_variable(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    char         *val;
    size_t        len;
    GeoIPRecord  *gr;

    gr = njt_stream_geoip_get_city_record(s);
    if (gr == NULL) {
        goto not_found;
    }

    val = *(char **) ((char *) gr + data);
    if (val == NULL) {
        goto no_value;
    }

    len = njt_strlen(val);
    v->data = njt_pnalloc(s->connection->pool, len);
    if (v->data == NULL) {
        GeoIPRecord_delete(gr);
        return NJT_ERROR;
    }

    njt_memcpy(v->data, val, len);

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    GeoIPRecord_delete(gr);

    return NJT_OK;

no_value:

    GeoIPRecord_delete(gr);

not_found:

    v->not_found = 1;

    return NJT_OK;
}


static njt_int_t
njt_stream_geoip_region_name_variable(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    size_t        len;
    const char   *val;
    GeoIPRecord  *gr;

    gr = njt_stream_geoip_get_city_record(s);
    if (gr == NULL) {
        goto not_found;
    }

    val = GeoIP_region_name_by_code(gr->country_code, gr->region);

    GeoIPRecord_delete(gr);

    if (val == NULL) {
        goto not_found;
    }

    len = njt_strlen(val);
    v->data = njt_pnalloc(s->connection->pool, len);
    if (v->data == NULL) {
        return NJT_ERROR;
    }

    njt_memcpy(v->data, val, len);

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NJT_OK;

not_found:

    v->not_found = 1;

    return NJT_OK;
}


static njt_int_t
njt_stream_geoip_city_float_variable(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    float         val;
    GeoIPRecord  *gr;

    gr = njt_stream_geoip_get_city_record(s);
    if (gr == NULL) {
        v->not_found = 1;
        return NJT_OK;
    }

    v->data = njt_pnalloc(s->connection->pool, NJT_INT64_LEN + 5);
    if (v->data == NULL) {
        GeoIPRecord_delete(gr);
        return NJT_ERROR;
    }

    val = *(float *) ((char *) gr + data);

    v->len = njt_sprintf(v->data, "%.4f", val) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    GeoIPRecord_delete(gr);

    return NJT_OK;
}


static njt_int_t
njt_stream_geoip_city_int_variable(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    int           val;
    GeoIPRecord  *gr;

    gr = njt_stream_geoip_get_city_record(s);
    if (gr == NULL) {
        v->not_found = 1;
        return NJT_OK;
    }

    v->data = njt_pnalloc(s->connection->pool, NJT_INT64_LEN);
    if (v->data == NULL) {
        GeoIPRecord_delete(gr);
        return NJT_ERROR;
    }

    val = *(int *) ((char *) gr + data);

    v->len = njt_sprintf(v->data, "%d", val) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    GeoIPRecord_delete(gr);

    return NJT_OK;
}


static GeoIPRecord *
njt_stream_geoip_get_city_record(njt_stream_session_t *s)
{
    njt_stream_geoip_conf_t  *gcf;

    gcf = njt_stream_get_module_main_conf(s, njt_stream_geoip_module);

    if (gcf->city) {
#if (NJT_HAVE_GEOIP_V6)
        return gcf->city_v6
                   ? GeoIP_record_by_ipnum_v6(gcf->city,
                                              njt_stream_geoip_addr_v6(s, gcf))
                   : GeoIP_record_by_ipnum(gcf->city,
                                           njt_stream_geoip_addr(s, gcf));
#else
        return GeoIP_record_by_ipnum(gcf->city, njt_stream_geoip_addr(s, gcf));
#endif
    }

    return NULL;
}


static njt_int_t
njt_stream_geoip_add_variables(njt_conf_t *cf)
{
    njt_stream_variable_t  *var, *v;

    for (v = njt_stream_geoip_vars; v->name.len; v++) {
        var = njt_stream_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NJT_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NJT_OK;
}


static void *
njt_stream_geoip_create_conf(njt_conf_t *cf)
{
    njt_pool_cleanup_t       *cln;
    njt_stream_geoip_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_stream_geoip_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    cln = njt_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = njt_stream_geoip_cleanup;
    cln->data = conf;

    return conf;
}


static char *
njt_stream_geoip_country(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_stream_geoip_conf_t  *gcf = conf;

    njt_str_t  *value;

    if (gcf->country) {
        return "is duplicate";
    }

    value = cf->args->elts;

    gcf->country = GeoIP_open((char *) value[1].data, GEOIP_MEMORY_CACHE);

    if (gcf->country == NULL) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "GeoIP_open(\"%V\") failed", &value[1]);

        return NJT_CONF_ERROR;
    }

    if (cf->args->nelts == 3) {
        if (njt_strcmp(value[2].data, "utf8") == 0) {
            GeoIP_set_charset(gcf->country, GEOIP_CHARSET_UTF8);

        } else {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[2]);
            return NJT_CONF_ERROR;
        }
    }

    switch (gcf->country->databaseType) {

    case GEOIP_COUNTRY_EDITION:

        return NJT_CONF_OK;

#if (NJT_HAVE_GEOIP_V6)
    case GEOIP_COUNTRY_EDITION_V6:

        gcf->country_v6 = 1;
        return NJT_CONF_OK;
#endif

    default:
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid GeoIP database \"%V\" type:%d",
                           &value[1], gcf->country->databaseType);
        return NJT_CONF_ERROR;
    }
}


static char *
njt_stream_geoip_org(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_stream_geoip_conf_t  *gcf = conf;

    njt_str_t  *value;

    if (gcf->org) {
        return "is duplicate";
    }

    value = cf->args->elts;

    gcf->org = GeoIP_open((char *) value[1].data, GEOIP_MEMORY_CACHE);

    if (gcf->org == NULL) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "GeoIP_open(\"%V\") failed", &value[1]);

        return NJT_CONF_ERROR;
    }

    if (cf->args->nelts == 3) {
        if (njt_strcmp(value[2].data, "utf8") == 0) {
            GeoIP_set_charset(gcf->org, GEOIP_CHARSET_UTF8);

        } else {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[2]);
            return NJT_CONF_ERROR;
        }
    }

    switch (gcf->org->databaseType) {

    case GEOIP_ISP_EDITION:
    case GEOIP_ORG_EDITION:
    case GEOIP_DOMAIN_EDITION:
    case GEOIP_ASNUM_EDITION:

        return NJT_CONF_OK;

#if (NJT_HAVE_GEOIP_V6)
    case GEOIP_ISP_EDITION_V6:
    case GEOIP_ORG_EDITION_V6:
    case GEOIP_DOMAIN_EDITION_V6:
    case GEOIP_ASNUM_EDITION_V6:

        gcf->org_v6 = 1;
        return NJT_CONF_OK;
#endif

    default:
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid GeoIP database \"%V\" type:%d",
                           &value[1], gcf->org->databaseType);
        return NJT_CONF_ERROR;
    }
}


static char *
njt_stream_geoip_city(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_stream_geoip_conf_t  *gcf = conf;

    njt_str_t  *value;

    if (gcf->city) {
        return "is duplicate";
    }

    value = cf->args->elts;

    gcf->city = GeoIP_open((char *) value[1].data, GEOIP_MEMORY_CACHE);

    if (gcf->city == NULL) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "GeoIP_open(\"%V\") failed", &value[1]);

        return NJT_CONF_ERROR;
    }

    if (cf->args->nelts == 3) {
        if (njt_strcmp(value[2].data, "utf8") == 0) {
            GeoIP_set_charset(gcf->city, GEOIP_CHARSET_UTF8);

        } else {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[2]);
            return NJT_CONF_ERROR;
        }
    }

    switch (gcf->city->databaseType) {

    case GEOIP_CITY_EDITION_REV0:
    case GEOIP_CITY_EDITION_REV1:

        return NJT_CONF_OK;

#if (NJT_HAVE_GEOIP_V6)
    case GEOIP_CITY_EDITION_REV0_V6:
    case GEOIP_CITY_EDITION_REV1_V6:

        gcf->city_v6 = 1;
        return NJT_CONF_OK;
#endif

    default:
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid GeoIP City database \"%V\" type:%d",
                           &value[1], gcf->city->databaseType);
        return NJT_CONF_ERROR;
    }
}


static void
njt_stream_geoip_cleanup(void *data)
{
    njt_stream_geoip_conf_t  *gcf = data;

    if (gcf->country) {
        GeoIP_delete(gcf->country);
    }

    if (gcf->org) {
        GeoIP_delete(gcf->org);
    }

    if (gcf->city) {
        GeoIP_delete(gcf->city);
    }
}
