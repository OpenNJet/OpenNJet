
// /*
//  * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
//  *


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#ifdef NJT_HAVE_GEOIP_V6
#include <GeoIP.h>
#include <GeoIPCity.h>
#endif
#include "njt_http_dyn_module.h"
#include "gkhash.h"
#include "goaccess.h"
#include "njt_helper_access_data_module.h"
#include "parser.h"
#include "xmalloc.h"

extern khash_t (igdb) * ht_db;
extern goaccess_shpool_ctx_t  goaccess_shpool_ctx;

GKHashDB *
init_gkhashdb (void *p);
void
njt_allocate_holder (void);
void insert_methods_protocols (void);
void * new_igdb_ht (void);
 GKHashModule *
init_gkhashmodule (void);
void set_spec_date_format (void);
void parse_browsers_file(void);
void
set_default_static_files (void);

 int
cleanup_logitem (int ret, GLogItem *logitem);
void convert_log_format(char *src, char *dst);
int extract_keyphrase (char *ref, char **keyphrase);
int extract_referer_site (const char *referer, char *host);
void set_agent_hash (GLogItem *logitem);
void *
xmalloc (size_t size);
void *
xcalloc (size_t nmemb, size_t size);
char *
alloc_string (const char *str);
 int
ignore_line (GLogItem *logitem);
 int
is_404 (GLogItem *logitem);
char *
get_uniq_visitor_key (GLogItem *logitem);

 int
is_static (const char *req);

 njt_int_t njt_http_variable_header(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
njt_int_t
njt_http_variable_host(njt_http_request_t *r, njt_http_variable_value_t *v,
    uintptr_t data);
njt_int_t
njt_http_variable_remote_user(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
njt_int_t
njt_http_variable_request_method(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);

njt_int_t
njt_http_variable_request(njt_http_request_t *r, njt_http_variable_value_t *v,
    uintptr_t data);
njt_int_t
njt_http_variable_remote_addr(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);   
njt_int_t
njt_http_upstream_cache_status(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);  

njt_int_t
njt_http_ssl_static_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);

typedef struct njt_goaccess_logformat_convert_s {
    njt_str_t var;
    njt_str_t logformat;
} njt_goaccess_logformat_convert_t;


static char *njt_http_access_log_zone_set_zone(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);

static njt_int_t njt_http_access_log_zone_init_process(
    njt_cycle_t *cycle);

static njt_command_t  njt_http_access_log_zone_commands[] = {

    { njt_string("access_log_zone"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_HTTP_LMT_CONF|NJT_CONF_TAKE12,
      njt_http_access_log_zone_set_zone,
      0,
      0,
      NULL },
      njt_null_command
};


static njt_http_module_t  njt_http_access_log_zone_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                     /* postconfiguration */

    NULL,         /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */
    NULL,          /* create location configuration */
    NULL            /* merge location configuration */
};


njt_module_t  njt_http_access_log_zone_module = {
    NJT_MODULE_V1,
    &njt_http_access_log_zone_module_ctx,              /* module context */
    njt_http_access_log_zone_commands,                 /* module directives */
    NJT_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    njt_http_access_log_zone_init_process,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};


static njt_int_t njt_http_access_log_zone_init_process(
    njt_cycle_t *cycle) {
        //insert_methods_protocols ();
        return NJT_OK;
}

static GKDB *
new_db (khash_t (igdb) *hash, uint32_t key,njt_http_log_main_conf_t  *ctx) {
  GKDB *db = NULL;
  khint_t k;
  int ret;

  if (!hash)
    return NULL;

  k = kh_put (igdb, hash, key, &ret);
  /* operation failed */
  if (ret == -1)
    return NULL;

    ctx->sh->db = njt_slab_alloc(ctx->sh->shpool, sizeof(GKDB));
    if (ctx->sh->db == NULL)
    {
        return NULL;
    }
    db = ctx->sh->db;
    db->hdb = njt_slab_alloc(ctx->sh->shpool, sizeof(GKHashDB));
    if (db->hdb  == NULL)
    {
        return NULL;
    }
  init_gkhashdb(db->hdb);
  db->cache = init_gkhashmodule ();
  db->store = NULL;
  db->logs = NULL;
  kh_val (hash, k) = db;
  return db;
}


static njt_int_t
njt_http_access_log_zone_init_zone(njt_shm_zone_t *shm_zone, void *data)
{
    njt_http_log_main_conf_t  *octx = data;
    njt_slab_pool_t                  *shpool;
    size_t                      len;
    njt_http_log_main_conf_t  *ctx;
    GKDB *db;
    

    ctx = shm_zone->data;

    if (octx) {
        ctx->sh     = octx->sh;
        return NJT_OK;
    }

    shpool = (njt_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->sh = shpool->data;
        return NJT_OK;
    }
    ctx->sh = njt_slab_alloc(shpool, sizeof(njt_http_log_db_ctx_t));
    if (ctx->sh == NULL)
    {
        return NJT_ERROR;  
    }
    ctx->sh->shpool = shpool;
    goaccess_shpool_ctx.shpool = shpool;
    goaccess_shpool_ctx.rwlock = &ctx->sh->rwlock;
    ht_db = (khash_t (igdb) *) new_igdb_ht ();
    ctx->sh->ht_db = ht_db;

    //init_modules ();
    db = new_db(ht_db, DB_INSTANCE,ctx);
    if(db == NULL) {
         return NJT_ERROR;
    }

    ctx->sh->glog = njt_slab_alloc(shpool, sizeof(GLog));
    if(ctx->sh->glog == NULL) {
         return NJT_ERROR;
    }


    njt_allocate_holder();

    len = sizeof(" in njt_http_access_log_zone_init_zone \"\"") + shm_zone->shm.name.len;

    shpool->log_ctx = njt_slab_alloc(shpool, len);
    if (shpool->log_ctx == NULL) {
        return NJT_ERROR;
    }

    njt_sprintf(shpool->log_ctx, " in njt_http_access_log_zone_init_zone \"%V\"%Z",
                &shm_zone->shm.name);

    shpool->data = ctx->sh;
    return NJT_OK;
}



static char *
njt_http_access_log_zone_set_zone(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_log_main_conf_t *cmf;

    ssize_t                            size;
    njt_str_t                         *value;

    cmf = njt_http_conf_get_module_main_conf(cf, njt_http_log_module);
    value = cf->args->elts;

    cmf->zone_write = njt_http_access_log_zone_write;
     if (!value[1].len) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid zone name \"%V\"", &value[1]);
        return NJT_CONF_ERROR;
    }

    if (cf->args->nelts == 3) {
        size = njt_parse_size(&value[2]);

        if (size == NJT_ERROR) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid zone size \"%V\"", &value[2]);
            return NJT_CONF_ERROR;
        }

        if (size < (ssize_t) (8 * njt_pagesize)) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "zone \"%V\" is too small", &value[1]);
            return NJT_CONF_ERROR;
        }

    } else {
        size = 0;
    }
    cmf->shm_zone = njt_shared_memory_add(cf, &value[1], size,
                                           &njt_http_access_log_zone_module);
    if (cmf->shm_zone == NULL) {
        return NJT_CONF_ERROR;
    }

    cmf->shm_zone->init = njt_http_access_log_zone_init_zone;
    cmf->shm_zone->data = cmf;
    goaccess_shpool_ctx.goaccess_pool = cf->cycle->pool;
    init_modules();
    //parse_conf_file (&argc, &argv);
    //parse_cmd_line (argc, argv);

    parse_browsers_file();  
    set_default_static_files();

    return NJT_CONF_OK;
}

static char* njt_str2char(njt_pool_t *pool,njt_str_t src) {
    char *p;
    p = xcalloc(1,src.len + 1);  //njt_pcalloc(pool,src.len + 1);
    if(p != NULL) {
        njt_memcpy(p,src.data,src.len);
    }
    return p;
}
static int
set_date (njt_pool_t *pool,njt_str_t *dst, struct tm tm) {
  
  dst->data = xcalloc(1,DATE_LEN);  //njt_pcalloc(pool,DATE_LEN);  
  if(dst->data == NULL) {
    return NJT_ERROR;
  }
  if (strftime ((char *)dst->data, DATE_LEN,"%Y%m%d", &tm) <= 0) {
     return NJT_ERROR;
  }
  dst->len = DATE_LEN;
  return NJT_OK;
}

static int
set_time(njt_pool_t *pool,njt_str_t *dst, struct tm tm) {
  
  dst->data = xcalloc(1,TIME_LEN); //njt_pcalloc(pool,TIME_LEN);
  if(dst->data == NULL) {
    return NJT_ERROR;
  }
  if (strftime ((char *)dst->data, TIME_LEN,"%H:%M:%S", &tm) <= 0) {
     return NJT_ERROR;
  }
  dst->len = TIME_LEN;
  return NJT_OK;
}


static void
set_tm_dt_logitem (GLogItem *logitem, struct tm tm) {
  logitem->dt.tm_year = tm.tm_year;
  logitem->dt.tm_mon = tm.tm_mon;
  logitem->dt.tm_mday = tm.tm_mday;
}

static void
set_tm_tm_logitem (GLogItem *logitem, struct tm tm) {
  logitem->dt.tm_hour = tm.tm_hour;
  logitem->dt.tm_min = tm.tm_min;
  logitem->dt.tm_sec = tm.tm_sec;
}

njt_uint_t get_log_status(njt_http_request_t *r)
{
    njt_uint_t  status;

    if (r->err_status) {
        status = r->err_status;

    } else if (r->headers_out.status) {
        status = r->headers_out.status;

    } else if (r->http_version == NJT_HTTP_VERSION_9) {
        status = 9;

    } else {
        status = 0;
    }

    return status;
}

off_t get_body_bytes_sent(njt_http_request_t *r)
{
     off_t  length;

    length = r->connection->sent - r->header_size;

    return length;
}

njt_msec_int_t
get_request_time(njt_http_request_t *r)
{
    njt_time_t      *tp;
    njt_msec_int_t   ms;

    tp = njt_timeofday();

    ms = (njt_msec_int_t)
             ((tp->sec - r->start_sec) * 1000 + (tp->msec - r->start_msec));
    ms = njt_max(ms, 0);
    return ms;
}

static njt_int_t parse_to_logitem(njt_http_request_t *r,GLogItem *logitem ) {

    time_t      sec;
    njt_tm_t         tm;
    njt_str_t   date;
    njt_str_t   str_time;
    njt_http_core_loc_conf_t  *clcf;
    njt_http_variable_value_t v;
    njt_str_t  var_data;
    njt_str_t  def_val = njt_string("-");


    njt_memzero(&v,sizeof(njt_http_variable_value_t));
    njt_http_variable_remote_addr(r,&v,0);
    var_data.data = v.data;
    var_data.len  = v.len;
    logitem->host = njt_str2char(r->pool,var_data);


    if (r->connection->sockaddr->sa_family == AF_INET) {
        logitem->type_ip =  TYPE_IPV4;
    } else if (r->connection->sockaddr->sa_family == AF_INET6) {
        logitem->type_ip =  TYPE_IPV6;
    } else {
        logitem->type_ip =  TYPE_IPINV;
    }

    sec = njt_time();
    njt_libc_localtime(sec, &tm);

    njt_str_null(&date);
    njt_str_null(&str_time);
    set_date(r->pool,&date,tm);

   
    logitem->date = (char *)date.data;
    logitem->numdate = njt_atoi(date.data,njt_strlen(date.data));
    set_tm_dt_logitem(logitem,tm);

    set_time(r->pool,&str_time,tm);
    logitem->time = (char *)str_time.data;
    set_tm_tm_logitem(logitem,tm);

    njt_memzero(&v,sizeof(njt_http_variable_value_t));
    njt_http_variable_host(r,&v,0);
    var_data.data = v.data;
    var_data.len  = v.len;
    logitem->vhost = njt_str2char(r->pool,var_data);

    
    njt_memzero(&v,sizeof(njt_http_variable_value_t));
    njt_http_variable_remote_user(r,&v,0);
    var_data.data = v.data;
    var_data.len  = v.len;
    if(var_data.len != 0) {
        logitem->userid = njt_str2char(r->pool,var_data);
    }



    njt_memzero(&v,sizeof(njt_http_variable_value_t));
    njt_http_upstream_cache_status(r,&v,0);
    var_data.data = v.data;
    var_data.len  = v.len;
    if(var_data.len != 0) {
        logitem->cache_status = njt_str2char(r->pool,var_data);
    }
    njt_memzero(&v,sizeof(njt_http_variable_value_t));
    njt_http_variable_request_method(r,&v,0);
    var_data.data = v.data;
    var_data.len  = v.len;
    if(var_data.len != 0) {
        logitem->method = njt_str2char(r->pool,var_data);
    }

    njt_memzero(&v,sizeof(njt_http_variable_value_t));
    njt_http_variable_request(r,&v,offsetof(njt_http_request_t, uri));
    var_data.data = v.data;
    var_data.len  = v.len;
    if(var_data.len != 0) {
        logitem->req = njt_str2char(r->pool,var_data);
    }

    njt_memzero(&v,sizeof(njt_http_variable_value_t));
    njt_http_variable_request(r,&v,offsetof(njt_http_request_t, args));
    var_data.data = v.data;
    var_data.len  = v.len;
    if(var_data.len != 0) {
        logitem->qstr = njt_str2char(r->pool,var_data);
    }
    //offsetof(njt_http_request_t, http_protocol)

    njt_memzero(&v,sizeof(njt_http_variable_value_t));
    njt_http_variable_request(r,&v,offsetof(njt_http_request_t, http_protocol));
    var_data.data = v.data;
    var_data.len  = v.len;
    if(var_data.len != 0) {
        logitem->protocol = njt_str2char(r->pool,var_data);
    }


    njt_memzero(&v,sizeof(njt_http_variable_value_t));
    logitem->status  = get_log_status(r);
    


    logitem->resp_size = get_body_bytes_sent(r);

    //offsetof(njt_http_request_t, headers_in.referer)  //njt_http_referer_variable
    njt_memzero(&v,sizeof(njt_http_variable_value_t));
    njt_http_variable_header(r,&v,offsetof(njt_http_request_t, headers_in.referer));
    var_data.data = v.data;
    var_data.len  = v.len;
    if(var_data.len != 0) {
        logitem->ref = njt_str2char(r->pool,var_data);
        extract_keyphrase (logitem->ref, &logitem->keyphrase);
        extract_referer_site (logitem->ref, logitem->site);
    } else {
         logitem->ref = njt_str2char(r->pool,def_val);
    }
    //njt_http_variable_header
    njt_memzero(&v,sizeof(njt_http_variable_value_t));
    njt_http_variable_header(r,&v,offsetof(njt_http_request_t, headers_in.user_agent));
    var_data.data = v.data;
    var_data.len  = v.len;
    if(var_data.len != 0 && var_data.data[0] != '\0') {
        logitem->agent = njt_str2char(r->pool,var_data);
        set_browser_os (logitem);
    } else {
        logitem->agent = njt_str2char(r->pool,def_val);
    }
    set_agent_hash (logitem);

    logitem->serve_time = get_request_time(r);

    njt_memzero(&v,sizeof(njt_http_variable_value_t));
    njt_http_ssl_static_variable(r,&v,(uintptr_t)njt_ssl_get_protocol);
    var_data.data = v.data;
    var_data.len  = v.len;
    if(var_data.len != 0) {
        logitem->tls_type = njt_str2char(r->pool,var_data);
    }
    logitem->tls_cypher = NULL;


    //clcf->default_type;

    clcf = njt_http_get_module_loc_conf(r,njt_http_core_module);
    var_data = clcf->default_type;
    logitem->mime_type = njt_str2char(r->pool,var_data);

     
      /* agent will be null in cases where %u is not specified */
  if (logitem->agent == NULL) {
    logitem->agent = alloc_string ("-");
    set_agent_hash (logitem);
  }

  logitem->ignorelevel = ignore_line (logitem);
  /* ignore line */
  if (logitem->ignorelevel == IGNORE_LEVEL_PANEL)
    return cleanup_logitem (1, logitem);

  if (is_404 (logitem))
    logitem->is_404 = 1;
  else if (is_static (logitem->req))
    logitem->is_static = 1;

  logitem->uniq_key = get_uniq_visitor_key (logitem);


#if(NJT_HAVE_GEOIP_V6)
  
   njt_memzero(&v,sizeof(njt_http_variable_value_t));
    njt_http_geoip_city_variable(r,&v,offsetof(GeoIPRecord, continent_code));
    var_data.data = v.data;
    var_data.len  = v.len;
    if(var_data.len != 0) {
        logitem->continent = njt_str2char(r->pool,var_data);
    }

    njt_memzero(&v,sizeof(njt_http_variable_value_t));
    njt_http_geoip_city_variable(r,&v,offsetof(GeoIPRecord, continent_code));
    var_data.data = v.data;
    var_data.len  = v.len;
    if(var_data.len != 0) {
        logitem->continent = njt_str2char(r->pool,var_data);
    }


    njt_memzero(&v,sizeof(njt_http_variable_value_t));
    njt_http_geoip_country_variable(r,&v,NJT_GEOIP_COUNTRY_CODE);
    var_data.data = v.data;
    var_data.len  = v.len;
    if(var_data.len != 0) {
        logitem->country = njt_str2char(r->pool,var_data);
    }


    njt_memzero(&v,sizeof(njt_http_variable_value_t));
    njt_http_geoip_org_variable(r,&v,0);
    var_data.data = v.data;
    var_data.len  = v.len;
    if(var_data.len != 0) {
        logitem->asn = njt_str2char(r->pool,var_data);
    }
#endif
    
    return NJT_OK;
}
static void
njt_http_access_log_zone_parse(njt_http_request_t *r,njt_str_t  data,njt_str_t  go_format) {

    njt_http_log_main_conf_t *cmf;
    GLog *glog;
    njt_tm_t         tm;
    time_t      sec;

    cmf = njt_http_get_module_main_conf(r, njt_http_log_module);
    GLogItem *logitem;

    //char buf[LINE_BUFFER] = {0};


   
    if (cmf->sh->shpool) {                                                      
        njt_rwlock_wlock(&cmf->sh->rwlock);                                     
    }
    glog = cmf->sh->glog;
     if (++glog->read % MAX_BATCH_LINES == 0) {
        njt_rwlock_unlock(&cmf->sh->rwlock);            
        return;
     }
        
    
    sec = njt_time();
    njt_localtime(sec, &tm);
    glog->start_time = tm;

    logitem = init_log_item (glog);

    parse_to_logitem(r,logitem);

    process_log(logitem);
    
    count_process (glog);
    cleanup_logitem(1,logitem);

     if (cmf->sh->shpool) {                                                      
        njt_rwlock_unlock(&cmf->sh->rwlock);                                     
    }
    glog->bytes += data.len;
}

void
njt_http_access_log_zone_write(njt_http_request_t *r, njt_http_log_t *log, u_char *buf,
    size_t len) {

    njt_str_t  go_format;   
    njt_str_t  data;

    if(log != NULL && log->format != NULL && log->format->format.len != 0 && log->format->goaccess_format == NULL) {
        //convert_log_format
        go_format.len = log->format->format.len + 1;
        go_format.data = njt_pcalloc(r->pool,go_format.len);
        if(go_format.data == NULL) {
            return;
        }
        data.data = buf;
        data.len  = len;
        njt_http_access_log_zone_parse(r,data,go_format);

    }

    return;
}
