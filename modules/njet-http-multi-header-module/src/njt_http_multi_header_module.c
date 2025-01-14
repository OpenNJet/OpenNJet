
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_str_util.h>
#include <njt_http.h>
#include <njt_http_util.h>


typedef struct njt_http_header_val_s  njt_http_header_val_t;

typedef njt_int_t (*njt_http_set_header_pt)(njt_http_request_t *r,
    njt_http_header_val_t *hv, njt_str_t *value);


typedef struct {
    njt_str_t                  name;
    njt_uint_t                 offset;
    njt_http_set_header_pt     handler;
} njt_http_set_header_t;


struct njt_http_header_val_s {
    njt_http_complex_value_t   value;
    njt_str_t                  key;
    //njt_str_t                  name;
    njt_http_set_header_pt     handler;
    njt_uint_t                 offset;
    njt_uint_t                 always;  /* unsigned  always:1 */
};


typedef struct {
    njt_http_complex_value_t  *expires_value;
    njt_array_t               *headers;
} njt_http_multi_header_conf_t;

typedef struct {
    njt_str_t                  key;
    njt_str_t                  value;
} njt_http_cookie_kv_t;


typedef struct {
    njt_str_t                  key;
    njt_array_t                *data_array;
} njt_http_cookie_t;


static void *njt_http_multi_header_create_conf(njt_conf_t *cf);
static char *njt_http_multi_header_merge_conf(njt_conf_t *cf,
    void *parent, void *child);
static njt_int_t njt_http_multi_header_filter_init(njt_conf_t *cf);

static char *njt_http_multi_header_add(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static njt_int_t
njt_http_multi_write_header(njt_http_request_t *r);



static njt_http_set_header_t  njt_http_set_headers[] = {

    { njt_string("Cache-Control"),
                 offsetof(njt_http_headers_out_t, cache_control),
                 NULL },

    { njt_string("Link"),
                 offsetof(njt_http_headers_out_t, link),
                 NULL },

    { njt_string("Last-Modified"),
                 offsetof(njt_http_headers_out_t, last_modified),
                 NULL },

    { njt_string("ETag"),
                 offsetof(njt_http_headers_out_t, etag),
                 NULL },

    { njt_null_string, 0, NULL }
};


static njt_command_t  njt_http_multi_header_filter_commands[] = {

    { njt_string("add_more_header"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_CONF_2MORE,
      njt_http_multi_header_add,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_multi_header_conf_t, headers),
      NULL },
      njt_null_command
};


static njt_http_module_t  njt_http_multi_header_module_ctx = {
    NULL,                                  /* preconfiguration */
    njt_http_multi_header_filter_init,          /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_multi_header_create_conf,          /* create location configuration */
    njt_http_multi_header_merge_conf            /* merge location configuration */
};


njt_module_t  njt_http_multi_header_module = {
    NJT_MODULE_V1,
    &njt_http_multi_header_module_ctx,   /* module context */
    njt_http_multi_header_filter_commands,      /* module directives */
    NJT_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};


static njt_http_output_header_filter_pt  njt_http_next_header_filter;


static njt_int_t
njt_http_multi_header_filter(njt_http_request_t *r)
{
    njt_str_t                 value;
    njt_uint_t                i, safe_status;
    njt_http_header_val_t    *h;
    njt_http_multi_header_conf_t  *conf;

    if (r != r->main) {
        return njt_http_next_header_filter(r);
    }

    conf = njt_http_get_module_loc_conf(r, njt_http_multi_header_module);

    switch (r->headers_out.status) {

    case NJT_HTTP_OK:
    case NJT_HTTP_CREATED:
    case NJT_HTTP_NO_CONTENT:
    case NJT_HTTP_PARTIAL_CONTENT:
    case NJT_HTTP_MOVED_PERMANENTLY:
    case NJT_HTTP_MOVED_TEMPORARILY:
    case NJT_HTTP_SEE_OTHER:
    case NJT_HTTP_NOT_MODIFIED:
    case NJT_HTTP_TEMPORARY_REDIRECT:
    case NJT_HTTP_PERMANENT_REDIRECT:
        safe_status = 1;
        break;

    default:
        safe_status = 0;
        break;
    }

    if (conf->headers) {
        h = conf->headers->elts;
        for (i = 0; i < conf->headers->nelts; i++) {

            if (!safe_status && !h[i].always) {
                continue;
            }

            if (njt_http_complex_value(r, &h[i].value, &value) != NJT_OK) {
                return NJT_ERROR;
            }

            if (h[i].handler(r, &h[i], &value) != NJT_OK) {
                return NJT_ERROR;
            }
        }
    }
        njt_http_multi_write_header(r);



    return njt_http_next_header_filter(r);
}
            
static njt_int_t
njt_http_multi_append_header(njt_http_request_t *r, njt_http_header_val_t *hv,
    njt_str_t *value)
{
    njt_table_elt_t  *h;
    if (value->len) {
	    h = njt_list_push(&r->headers_out.headers);
	    if (h == NULL) {
		    return NJT_ERROR;
	    }

	    h->hash = 1;
	    h->key = hv->key;
	    h->value = *value;
    }
    return NJT_OK;
}



static njt_int_t
njt_http_multi_write_header(njt_http_request_t *r)
{
    njt_http_cookie_t *cookies;
    njt_uint_t      i,j,len;
    njt_array_t   *data_array;
    njt_http_cookie_kv_t   *kv;
    njt_str_t   data;
    u_char *p;
    njt_http_header_val_t hv;

    if(r->cookies == NULL) {
	return NJT_OK;
    }
    cookies = r->cookies->elts;

     for(i = 0;i < r->cookies->nelts; i++ ) {
        data_array = cookies[i].data_array;
         if(data_array == NULL) {
                continue;
        }
        len = 0;
        kv  = data_array->elts;
        for(j = 0; j < data_array->nelts; j++) {
            len = len + kv[j].key.len + 1; //add "="
            len = len + kv[j].value.len + 1; //add ";"
	    data.len = len;
	    data.data = njt_pcalloc(r->pool,len);
	    if(data.data == NULL) {
		    return NJT_ERROR;
	    }
        if(kv[j].key.len != 0) {
	        p = njt_snprintf(data.data,data.len,"%V=%V",&kv[j].key,&kv[j].value);
        } else {
            p = njt_snprintf(data.data,data.len,"%V",&kv[j].value);
        }
	    data.len = p - data.data;

	    njt_memzero(&hv,sizeof(hv));
	    hv.key = cookies[i].key;
	    njt_http_multi_append_header(r,&hv,&data);
        }

    }
    return NJT_OK;
}

static njt_int_t
njt_http_multi_cache_header(njt_http_request_t *r, njt_http_header_val_t *hv,
    njt_str_t *value)
{

    njt_uint_t      i;
    njt_http_cookie_t *cookies,*node;
    njt_array_t   *data_array;
    njt_http_cookie_kv_t   *kv;
    u_char *p1,*p2;
    njt_str_t name,new_value,str;



     if (r->cookies == NULL) {
        r->cookies = njt_array_create(r->pool, 1,
                                    sizeof(njt_http_cookie_t));
        if (r->cookies  == NULL) {
            return NJT_ERROR;
        }
    }

    data_array = NULL;
    cookies = r->cookies->elts;
    njt_str_null(&new_value);
    njt_str_null(&str);
    njt_str_null(&name);
    for(i = 0;i < r->cookies->nelts; i++ ) {
        if (cookies[i].key.len == hv->key.len && njt_strncasecmp(cookies[i].key.data,hv->key.data,hv->key.len) == 0) {

            if(cookies[i].data_array == NULL) {
                cookies[i].data_array = njt_array_create(r->pool, 1,
                                    sizeof(njt_http_cookie_kv_t));
                if (cookies[i].data_array  == NULL) {
                    return NJT_ERROR;
                }
            }
            data_array = cookies[i].data_array;
        }
    }

    if (data_array == NULL) {
        node = njt_array_push(r->cookies);
        if (node == NULL) {
            return NJT_ERROR;
        }
        node->key.data = njt_pcalloc(r->pool,hv->key.len);
        if(node->key.data == NULL) {
            return NJT_ERROR;
        }
        njt_memcpy(node->key.data,hv->key.data,hv->key.len);
        node->key.len = hv->key.len;
        node->data_array = njt_array_create(r->pool, 1,
                                    sizeof(njt_http_cookie_kv_t));
        if (node->data_array  == NULL) {
            return NJT_ERROR;
        }
        data_array = node->data_array;
     
    }

    kv  = data_array->elts;

    p1 = njt_strlcasestrn(value->data,value->data + value->len,(u_char *)"=",0);
    p2 = njt_strlcasestrn(value->data,value->data + value->len,(u_char *)";",0);
    if(p1 != NULL && ((p2 != NULL && p1 < p2) || p2 == NULL )) {
    	 str.data = value->data;
         str.len = p1 - value->data;
         name = njt_del_headtail_space(str);
	 new_value.data = p1 + 1;
	 new_value.len = value->data + value->len  - p1 - 1;
    } else {
	new_value = *value;
    }

    for( i = 0; i < data_array->nelts; i++) {
        if(kv[i].key.len == name.len  && njt_memcmp(kv[i].key.data,name.data,kv[i].key.len) == 0) {
            kv[i].value = new_value;
             return NJT_OK;
        }
    }
     kv = njt_array_push(data_array);
     kv->key = name;
     kv->value = new_value;
    return NJT_OK;
}

/*

njt_str_t key = njt_string("Set-Cookie");
struct njt_str_t data_array[] = {
    njt_string("a=a;path=/;expires=Sat, 31-May-25 07:36:55 GMT;"),
    njt_string("b=b"),
    njt_string("c=c")
};
njt_http_multi_add_header(NULL,&key,data_array,3);
*/

njt_int_t
njt_http_multi_add_header(njt_http_request_t *r, njt_str_t *key,
    njt_str_t *arr,njt_uint_t arr_n) {

    njt_http_header_val_t hv;
    njt_uint_t  i;
    njt_str_t    value;
    njt_int_t  rc;

    njt_memzero(&hv,sizeof(hv));
    hv.key = *key;

    for(i = 0; i < arr_n; i++) {
       
        if(arr[i].len == 0) {
            continue;
        }
        value.data = arr[i].data; //njt_pstrdup(r->pool,&arr[i]);
        value.len  = arr[i].len;
        rc = njt_http_multi_cache_header(r,&hv,&value);  //
        if(rc != NJT_OK) {
            return rc;
        }
        
    }
    return rc;
}

static njt_int_t
njt_http_multi_more_header(njt_http_request_t *r, njt_http_header_val_t *hv,
    njt_str_t *value) {
    return  njt_http_multi_add_header(r,&hv->key,value,1);
}

static void *
njt_http_multi_header_create_conf(njt_conf_t *cf)
{
    njt_http_multi_header_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_multi_header_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     conf->headers = NULL;
     *     conf->trailers = NULL;
     *     conf->expires_time = 0;
     *     conf->expires_value = NULL;
     */

    return conf;
}


static char *
njt_http_multi_header_merge_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_multi_header_conf_t *prev = parent;
    njt_http_multi_header_conf_t *conf = child;

    if (conf->headers == NULL) {
        conf->headers = prev->headers;
    }

    return NJT_CONF_OK;
}


static njt_int_t
njt_http_multi_header_filter_init(njt_conf_t *cf)
{
    njt_http_next_header_filter = njt_http_top_header_filter;
    njt_http_top_header_filter = njt_http_multi_header_filter;


    return NJT_OK;
}




static char *
njt_http_multi_header_add(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_multi_header_conf_t *hcf = conf;

    njt_str_t                          *value;
    njt_uint_t                          i,j;
    njt_array_t                       **headers;
    njt_http_header_val_t              *hv;
    njt_http_set_header_t              *set;
    njt_http_compile_complex_value_t    ccv;
    njt_uint_t                 always; 
    njt_uint_t                 len; 

    value = cf->args->elts;

    headers = (njt_array_t **) ((char *) hcf + cmd->offset);

    if (*headers == NULL) {
        *headers = njt_array_create(cf->pool, 1,
                                    sizeof(njt_http_header_val_t));
        if (*headers == NULL) {
            return NJT_CONF_ERROR;
        }
    }
    always = 0;
    len = cf->args->nelts;
    if (njt_strcmp(value[cf->args->nelts - 1].data, "always") == 0) {
        always = 1;
        len = cf->args->nelts - 1;
    }

    for(j = 2; j < len; j++) {
        hv = njt_array_push(*headers);
        if (hv == NULL) {
            return NJT_CONF_ERROR;
        }
        hv->always = always;


        hv->key = value[1];
        //hv->name = value[2];
        hv->handler = NULL;
        hv->offset = 0;

        if (headers == &hcf->headers) {
            hv->handler = njt_http_multi_more_header;

            set = njt_http_set_headers;
            for (i = 0; set[i].name.len; i++) {
                if (njt_strcasecmp(value[1].data, set[i].name.data) != 0) {
                    continue;
                }
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\",use add_header directive.", &value[1]);
                return NJT_CONF_ERROR;
                hv->offset = set[i].offset;
                hv->handler = set[i].handler;

                break;
            }
        }

        if (value[j].len == 0) {
            njt_memzero(&hv->value, sizeof(njt_http_complex_value_t));

        } else {
            njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &value[j];
            ccv.complex_value = &hv->value;

            if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
                return NJT_CONF_ERROR;
            }
        }
    }
    return NJT_CONF_OK;
}
