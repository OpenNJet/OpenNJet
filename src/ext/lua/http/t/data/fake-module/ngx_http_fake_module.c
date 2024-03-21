/*
 * This fake module was used to reproduce a bug in njt_lua's
 * init_worker_by_lua implementation.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njet.h>


typedef struct {
    njt_int_t a;
} njt_http_fake_srv_conf_t;


typedef struct {
    njt_int_t a;
} njt_http_fake_loc_conf_t;


static void *njt_http_fake_create_srv_conf(njt_conf_t *cf);
static char *njt_http_fake_merge_srv_conf(njt_conf_t *cf, void *prev, void *conf);
static void *njt_http_fake_create_loc_conf(njt_conf_t *cf);
static char *njt_http_fake_merge_loc_conf(njt_conf_t *cf, void *prev, void *conf);


/* flow identify module configure struct */
static njt_http_module_t  njt_http_fake_module_ctx = {
    NULL,                           /* preconfiguration */
    NULL,                           /* postconfiguration */

    NULL,                           /* create main configuration */
    NULL,                           /* init main configuration */

    njt_http_fake_create_srv_conf,  /* create server configuration */
    njt_http_fake_merge_srv_conf,   /* merge server configuration */

    njt_http_fake_create_loc_conf,  /* create location configuration */
    njt_http_fake_merge_loc_conf    /* merge location configuration */
};

/* flow identify module struct */
njt_module_t  njt_http_fake_module = {
    NGX_MODULE_V1,
    &njt_http_fake_module_ctx,      /* module context */
    NULL,                           /* module directives */
    NGX_HTTP_MODULE,                /* module type */
    NULL,                           /* init master */
    NULL,                           /* init module */
    NULL,                           /* init process */
    NULL,                           /* init thread */
    NULL,                           /* exit thread */
    NULL,                           /* exit process */
    NULL,                           /* exit master */
    NGX_MODULE_V1_PADDING
};


/* create server configure */
static void *njt_http_fake_create_srv_conf(njt_conf_t *cf)
{
    njt_http_fake_srv_conf_t   *fscf;

    fscf = njt_pcalloc(cf->pool, sizeof(njt_http_fake_srv_conf_t));
    if (fscf == NULL) {
        return NULL;
    }

    return fscf;
}


/* merge server configure */
static char *njt_http_fake_merge_srv_conf(njt_conf_t *cf, void *prev, void *conf)
{
    njt_http_fake_srv_conf_t   *fscf;

    fscf = njt_http_conf_get_module_srv_conf(cf, njt_http_fake_module);
    if (fscf == NULL) {
        njt_conf_log_error(NGX_LOG_ALERT, cf, 0,
                           "get module srv conf failed in merge srv conf");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/* create location configure */
static void *njt_http_fake_create_loc_conf(njt_conf_t *cf)
{
    njt_http_fake_loc_conf_t   *flcf;

    flcf = njt_pcalloc(cf->pool, sizeof(njt_http_fake_loc_conf_t));
    if (flcf == NULL) {
        return NULL;
    }

    return flcf;
}


/* merge location configure */
static char *njt_http_fake_merge_loc_conf(njt_conf_t *cf, void *prev, void *conf)
{
    njt_http_fake_loc_conf_t   *flcf;

    flcf = njt_http_conf_get_module_loc_conf(cf, njt_http_fake_module);
    if (flcf == NULL) {
        njt_conf_log_error(NGX_LOG_ALERT, cf, 0,
                           "get module loc conf failed in merge loc conf");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
