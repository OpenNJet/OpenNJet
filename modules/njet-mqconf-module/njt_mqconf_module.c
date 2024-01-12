#include <njt_config.h>
#include <njt_core.h>

#include "njt_mqconf_module.h"

static void *njt_mqconf_create_conf(njt_cycle_t *cycle);
static char *njt_mqconf_init_conf(njt_cycle_t *cycle, void *conf);

static char *njt_mqconf_admin_server_set(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static char *njt_mqconf_admin_client_set(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static char *njt_helper(njt_conf_t *cf, njt_command_t *cmd, void *conf);

static njt_command_t njt_mqconf_commands[] = {

    {njt_string("admin_server"),
     NJT_MAIN_CONF |NJT_DIRECT_CONF| NJT_CONF_TAKE1,
     njt_mqconf_admin_server_set,
     0,     
     0,
     NULL},
    {njt_string("admin_client"),
     NJT_MAIN_CONF |NJT_DIRECT_CONF| NJT_CONF_TAKE12,
     njt_mqconf_admin_client_set,
     0,
     0,
     NULL},
    {njt_string("cluster_name"),
     NJT_MAIN_CONF |NJT_DIRECT_CONF| NJT_CONF_TAKE1,
     njt_conf_set_str_slot,
     0,
     offsetof(njt_mqconf_conf_t, cluster_name),
     NULL},
    {njt_string("node_name"),
     NJT_MAIN_CONF |NJT_DIRECT_CONF| NJT_CONF_TAKE1,
     njt_conf_set_str_slot,
     0,
     offsetof(njt_mqconf_conf_t, node_name),
     NULL},
    {njt_string("dyn_conf"),
     NJT_MAIN_CONF |NJT_DIRECT_CONF| NJT_CONF_TAKE1,
     njt_conf_set_str_slot,
     0,
     offsetof(njt_mqconf_conf_t, dyn_conf),
     NULL},

    { njt_string("helper"),
      NJT_MAIN_CONF|NJT_DIRECT_CONF|NJT_CONF_TAKE23,
      njt_helper,
      0,
      0,
      NULL },

    njt_null_command /* command termination */
};

/* The module context. */
static njt_core_module_t njt_mqconf_module_ctx = {
    njt_string("mqconf"),
    njt_mqconf_create_conf,
    njt_mqconf_init_conf
};


/* Module definition. */
njt_module_t  njt_mqconf_module = {
    NJT_MODULE_V1,
    &njt_mqconf_module_ctx, /* module context */
    njt_mqconf_commands,    /* module directives */
    NJT_CORE_MODULE,        /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};

static char *
njt_mqconf_admin_server_set(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_str_t *value;
    njt_mqconf_conf_t *fmcf;

    value = cf->args->elts;
    fmcf = (njt_mqconf_conf_t *)conf;

    u_char *dst;
    size_t vl = value[1].len + njt_cycle->prefix.len;
    dst = njt_pnalloc(cf->pool, vl);
    if (dst == NULL)
    {
        return NJT_CONF_ERROR;
    }
    njt_memcpy(dst, njt_cycle->prefix.data, njt_cycle->prefix.len);
    njt_memcpy(dst + njt_cycle->prefix.len, value[1].data, value[1].len);

    fmcf->admin_server.data = dst;
    fmcf->admin_server.len = vl;
    return NJT_CONF_OK;
}

static char *
njt_mqconf_admin_client_set(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{

    njt_str_t *value;
    njt_mqconf_conf_t *fmcf;

    value = cf->args->elts;
    fmcf = (njt_mqconf_conf_t *)conf;

    u_char *dst;
    size_t vl = value[1].len + njt_cycle->prefix.len;
    dst = njt_pnalloc(cf->pool, vl);
    if (dst == NULL)
    {
        return NJT_CONF_ERROR;
    }
    njt_memcpy(dst, njt_cycle->prefix.data, njt_cycle->prefix.len);
    njt_memcpy(dst + njt_cycle->prefix.len, value[1].data, value[1].len);

    fmcf->admin_client.data = dst;
    fmcf->admin_client.len = vl;
	if (cf->args->nelts ==3) {
		fmcf->worker_cnt = njt_atoi(value[2].data, value[2].len);
    	if (fmcf->worker_cnt == NJT_ERROR) {
        	return NJT_CONF_ERROR;
		}
    } else fmcf->worker_cnt=1;

    return NJT_CONF_OK;
}

static void *njt_mqconf_create_conf(njt_cycle_t *cycle) 
{
    njt_mqconf_conf_t *conf;

    conf = njt_pcalloc(cycle->pool, sizeof(njt_mqconf_conf_t));
    if (conf == NULL)
    {
        return NULL;
    }
    conf->admin_server.data=NULL;
    conf->admin_client.data=NULL;
    conf->cluster_name.data=NULL;
    conf->node_name.data=NULL;
    conf->dyn_conf.data=NULL;

    if (njt_array_init(&conf->helper, cycle->pool, 1, sizeof(njt_helper_ctx))
        != NJT_OK)
    {
        return NULL;
    }

    return conf;
}

static char *njt_mqconf_init_conf(njt_cycle_t *cycle, void *cf)
{
    njt_str_t  def_cluster = njt_string("def_c");
    njt_str_t  def_node = njt_string("def_n");
    njt_mqconf_conf_t *conf;
    njt_uint_t flag = 0;

    conf = (njt_mqconf_conf_t *)cf;

    if (conf->cluster_name.data == NULL) {
        conf->cluster_name = def_cluster;
        flag = 1;
    }

    if (conf->node_name.data == NULL) {
        conf->node_name = def_node;
        flag = 1;
    }

    if (flag) {
        njt_log_error(NJT_LOG_INFO, cycle->log, 0,
                      "set default value for mqconf");
    }

    return NJT_CONF_OK;
}

static char *
njt_helper(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
#if (NJT_HAVE_DLOPEN)
    void                *handle;
    njt_str_t           *value, label, file, cfile, cffile;
    njt_helper_check_fp  fp = NULL;
    njt_helper_run_fp    run_fp = NULL;
    unsigned int         result;
    njt_helper_ctx      *helper;
    njt_mqconf_conf_t   *fmcf;

    fmcf = (njt_mqconf_conf_t *)conf;
    value = cf->args->elts;

    label = value[1];

    file = value[2];

    njt_str_null(&cfile);

    if (cf->args->nelts == 4) {
        cfile = value[3];
        cffile = value[3];
        if (njt_conf_full_name(cf->cycle, &cffile, 0) != NJT_OK) {
            return NJT_CONF_ERROR;
        }
    }

    if (njt_conf_full_name(cf->cycle, &file, 0) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    handle = njt_dlopen(file.data);
    if (handle == NULL) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           njt_dlopen_n " \"%s\" failed (%s)",
                           file.data, njt_dlerror());
        return NJT_CONF_ERROR;
    }

    fp = njt_dlsym(handle, "njt_helper_check_version");
    if (fp == NULL) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           njt_dlsym_n " \"%V\", \"%s\" failed (%s)",
                           &value[1], "njt_helper_check_version", njt_dlerror());

        return NJT_CONF_ERROR;
    }

    result = fp();
    if (result != NJT_HELPER_VER) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                        "njet helper check version failed");
        return NJT_CONF_ERROR;
    }

    run_fp = njt_dlsym(handle, "njt_helper_run");
    if (run_fp == NULL) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           njt_dlsym_n " \"%V\", \"%s\" failed (%s)",
                           &value[1], "njt_helper_run", njt_dlerror());
        return NJT_CONF_ERROR;
    }

    helper = njt_array_push(&fmcf->helper);
    if (helper == NULL) {
        return NJT_CONF_ERROR;
    }

    if (cf->args->nelts == 4) {
        helper->param.conf_fn.data = cfile.data;
        helper->param.conf_fn.len = cfile.len;
        helper->param.conf_fullfn.data =  cffile.data;
        helper->param.conf_fullfn.len = cffile.len;
    } else {
        helper->param.conf_fn.data = NULL;
        helper->param.conf_fn.len = 0;
        helper->param.conf_fullfn.data =  NULL;
        helper->param.conf_fullfn.len = 0;
    }
    helper->param.check_cmd_fp = NULL;
    helper->param.ctx = NULL;
    helper->param.cycle = cf->cycle;

    helper->run_fp = run_fp;
    helper->handle = handle;
    helper->file.data = file.data;
    helper->file.len = file.len;
    helper->label = label;

    fp = njt_dlsym(handle, "njt_helper_ignore_reload");
    if (fp && fp()) {
        helper->reload = 0;
    } else {
        helper->reload = 1;
    }

    helper->start_time = 0;
    helper->start_time_bef = 0;

    return NJT_CONF_OK;
#else

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "\"load_module\" is not supported "
                       "on this platform");
    return NJT_CONF_ERROR;

#endif
}


#define USE_MQCONF_API 0

#if USE_MQCONF_API
static njt_str_t *
njt_mqconf_find(njt_mqconf_conf_t *mqcf, njt_str_t key)
{
    njt_helper_ctx       *helpers;
    njt_uint_t            i;

    if (!mqcf) {
        return NULL;
    }

    helpers = mqcf->helper.elts;

    for (i = 0; i < mqcf->helper.nelts; i++) {
        if ((helpers[i].label.len == key.len) && (njt_strcmp(helpers[i].label.data, key.data) == 0)) {
            return &helpers[i].param.conf_fn;
        }
    }

    return NULL;
}
#endif
