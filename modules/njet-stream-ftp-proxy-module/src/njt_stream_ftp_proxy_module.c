
/*
 * Copyright (C) Pavel Pautov
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>
#include "njt_stream_ftp_proxy_module.h"
#include <njt_stream_proxy_module.h>


extern njt_module_t  njt_stream_proxy_module;
extern njt_module_t  njt_stream_proto_module;

// static njt_int_t njt_stream_ftp_proxy_init(njt_conf_t *cf);
static void *njt_stream_ftp_proxy_create_srv_conf(njt_conf_t *cf);
static char *njt_stream_ftp_ctrl(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static char *
njt_stream_ftp_data(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static njt_int_t
njt_stream_ftp_proxy_init_zone(njt_shm_zone_t *shm_zone, void *data);

//return -1 when has no empty port
njt_int_t 
njt_stream_ftp_proxy_get_empty_port(njt_stream_ftp_proxy_srv_conf_t  *conf,
        njt_str_t *cip, njt_uint_t cport, njt_str_t *sip, njt_uint_t sport);

static void
njt_stream_ftp_proxy_rbtree_insert_value(njt_rbtree_node_t *temp,
    njt_rbtree_node_t *node, njt_rbtree_node_t *sentinel);

static njt_rbtree_node_t *
njt_stream_ftp_proxy_lookup(njt_rbtree_t *rbtree, njt_str_t *key,
    uint32_t hash);

void
njt_stream_ftp_control_proxy_cleanup(njt_stream_session_t *s);
void
njt_stream_ftp_data_proxy_cleanup(njt_stream_session_t *s);
njt_int_t
njt_stream_ftp_data_upstream(njt_stream_upstream_srv_conf_t *uscf, njt_url_t *u);


static njt_command_t  njt_stream_ftp_proxy_commands[] = {

    { njt_string("ftp_ctrl"),
      NJT_STREAM_SRV_CONF|NJT_CONF_2MORE,
      njt_stream_ftp_ctrl,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },
      { njt_string("ftp_data"),
      NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_stream_ftp_data,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      njt_null_command
};


static njt_stream_module_t  njt_stream_ftp_proxy_module_ctx = {
    NULL,                                  /* preconfiguration */
    // njt_stream_ftp_proxy_init,                   /* postconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    njt_stream_ftp_proxy_create_srv_conf,        /* create server configuration */
    NULL                                  /* merge server configuration */
};


njt_module_t  njt_stream_ftp_proxy_module = {
    NJT_MODULE_V1,
    &njt_stream_ftp_proxy_module_ctx,            /* module context */
    njt_stream_ftp_proxy_commands,               /* module directives */
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



static void *
njt_stream_ftp_proxy_create_srv_conf(njt_conf_t *cf)
{
    njt_stream_ftp_proxy_srv_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_stream_ftp_proxy_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NJT_CONF_UNSET;
    conf->type = NJT_STREAM_FTP_NONE;
    conf->mode = NJT_STREAM_FTP_PROXY_MODE_PLAIN;
    njt_str_null(&conf->zone);
    njt_str_null(&conf->proxy_ip);
    conf->min_port = NJT_CONF_UNSET;
    conf->max_port = NJT_CONF_UNSET;
    // conf->cur_empty_port = NJT_CONF_UNSET_UINT;
    // conf->used_port_num = NJT_CONF_UNSET_UINT;
    // conf->freed_port_num = NJT_CONF_UNSET_UINT;

    conf->shm_zone = NJT_CONF_UNSET_PTR;
    conf->pool = NJT_CONF_UNSET_PTR;

    return conf;
}


static char *
njt_stream_ftp_ctrl(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_stream_ftp_proxy_srv_conf_t     *fcf;
    njt_str_t                           *value;
    njt_str_t                           s, name;
    u_char                              *p;
    ssize_t                             size = 0;
    njt_uint_t                          i, j;
    njt_stream_ftp_proxy_ctx_t                *ctx;

    fcf = (njt_stream_ftp_proxy_srv_conf_t *) conf;
    if (fcf->enable != NJT_CONF_UNSET) {
        return "is duplicate";
    }

    fcf->enable = 1;
    ctx = njt_pcalloc(cf->pool, sizeof(njt_stream_ftp_proxy_ctx_t));
    if (ctx == NULL) {
        return NJT_CONF_ERROR;
    }

    name.len = 0;

    value = cf->args->elts;
    for(i = 1; i < cf->args->nelts; i++) {
        if (njt_strncmp(value[i].data, "proxy_ip=", 9) == 0) {
            if (value[i].len == 9) {
                goto invalid;
            }

            value[i].data += 9;
            value[i].len -= 9;
            
            fcf->proxy_ip.data = njt_pcalloc(cf->pool, value[i].len);
            if(fcf->proxy_ip.data == NULL){
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                    "proxy_ip malloc error", &value[i]);
                return NJT_CONF_ERROR;
            }
            fcf->proxy_ip.len = value[i].len;
            for(j = 0; j < value[i].len; j++){
                if(value[i].data[j] == '.'){
                    fcf->proxy_ip.data[j] = ',';
                }else{
                    fcf->proxy_ip.data[j] = value[i].data[j];
                }
            }
            // njt_memcpy(fcf->proxy_ip.data, value[i].data, value[i].len);

            continue;
        }

        if (njt_strncmp(value[i].data, "zone=", 5) == 0) {
            name.data = value[i].data + 5;
            p = (u_char *) njt_strchr(name.data, ':');
            if (p == NULL) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            name.len = p - name.data;
            s.data = p + 1;
            s.len = value[i].data + value[i].len - s.data;

            size = njt_parse_size(&s);
            if (size == NJT_ERROR) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            if (size < (ssize_t) (2 * njt_pagesize)) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "zone \"%V\" is too small", &value[i]);
                return NJT_CONF_ERROR;
            }

            continue;
        }


        if (njt_strncmp(value[i].data, "min_port=", 9) == 0) {
            if (fcf->min_port != NJT_CONF_UNSET) {
                return "interval is duplicate";
            }

            if (value[i].len == 9) {
                goto invalid;
            }

            value[i].data += 9;
            value[i].len -= 9;

            fcf->min_port = njt_atoi(value[i].data, value[i].len);
            if (fcf->min_port == NJT_ERROR) {
                goto invalid;
            }

            if (fcf->min_port < 1) {
                return "min_port should more than 1";
            }

            continue;
        }
        if (njt_strncmp(value[i].data, "max_port=", 9) == 0) {
            if (fcf->max_port != NJT_CONF_UNSET) {
                return "interval is duplicate";
            }

            if (value[i].len == 9) {
                goto invalid;
            }

            value[i].data += 9;
            value[i].len -= 9;

            fcf->max_port = njt_atoi(value[i].data, value[i].len);
            if (fcf->max_port == NJT_ERROR) {
                goto invalid;
            }

            if (fcf->max_port < 1) {
                return "max_port should more than 1";
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "mode=", 5) == 0) {
            if (value[i].len == 5) {
                goto invalid;
            }

            value[i].data += 5;
            value[i].len -= 5;

            if((value[i].len == 5) && (njt_strncmp(value[i].data, "plain", 5) == 0)){
                fcf->mode = NJT_STREAM_FTP_PROXY_MODE_PLAIN;
            }else if((value[i].len == 5) && (njt_strncmp(value[i].data, "encry", 5) == 0)){
                fcf->mode = NJT_STREAM_FTP_PROXY_MODE_ENCRY;
            }else if((value[i].len == 4) && (njt_strncmp(value[i].data, "auth", 4) == 0)){
                fcf->mode = NJT_STREAM_FTP_PROXY_MODE_AUTH;
            }else{
                goto invalid;
            }

            continue;
        }        

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                            "onknown param \"%V\"", &value[i]);
        return NJT_CONF_ERROR;
    }

    if (name.len == 0 || size == 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return NJT_CONF_ERROR;
    }

    //check all params
    if(fcf->min_port == NJT_CONF_UNSET
        || fcf->max_port == NJT_CONF_UNSET){
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "ftp_ctrl must config min_port and max_port");

        return NJT_CONF_ERROR;
    }

    if(fcf->min_port > fcf->max_port){
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "ftp_ctrl min_port shoule less than max_port");

        return NJT_CONF_ERROR;        
    }

    if(fcf->proxy_ip.len < 1){
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "ftp_ctrl proxy_ip must config");

        return NJT_CONF_ERROR;        
    }

    fcf->shm_zone = njt_shared_memory_add(cf, &name, size,
                                     &njt_stream_ftp_proxy_module);
    if (fcf->shm_zone == NULL) {
        return NJT_CONF_ERROR;
    }

    if (fcf->shm_zone->data) {
        ctx = fcf->shm_zone->data;

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "%V \"%V\" is already bound",
                           &cmd->name, &name);
        return NJT_CONF_ERROR;
    }

    ctx->min_port = fcf->min_port;
    ctx->max_port = fcf->max_port;

    njt_lvlhsh_init(&fcf->connection_port_map);
    fcf->shm_zone->init = njt_stream_ftp_proxy_init_zone;
    fcf->shm_zone->data = ctx;

    fcf->type = NJT_STREAM_FTP_CTRL;

    fcf->pool = njt_create_dynamic_pool(njt_pagesize, cf->pool->log);
    if (fcf->pool == NULL || NJT_OK != njt_sub_pool(cf->cycle->pool, fcf->pool)) {
        njt_conf_log_error(NJT_LOG_DEBUG, cf, 0, "create ftp proxy pool error");
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;


invalid:
    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\"", &value[i]);

    return NJT_CONF_ERROR;
}


njt_int_t njt_stream_ftp_proxy_replace_upstream(njt_stream_session_t *s,
        njt_stream_upstream_srv_conf_t **uscf){
    njt_url_t                           u;
    u_char                              buf[100];
    u_char                              *end;
    njt_str_t                           key;
    uint32_t                            hash;
    njt_stream_ftp_proxy_srv_conf_t     *fscf;
    njt_rbtree_node_t                   *node;
    njt_stream_ftp_proxy_ctx_t          *ctx;
    njt_stream_ftp_proxy_node_t         *node_info;
    njt_str_t                           sip;
    njt_int_t                           proxy_port;
    njt_pool_t                          *ftp_url_pool;
    njt_str_t                           name = njt_string("njtmesh_port");
    njt_str_t                           name_low;
    njt_uint_t                          proto_hash;
    //njt_stream_proto_srv_conf_t         *sf;



    if(njt_stream_ftp_proxy_module.ctx_index == NJT_MODULE_UNSET_INDEX){
        return NJT_ERROR;
    }

    fscf = njt_stream_get_module_srv_conf(s, njt_stream_ftp_proxy_module);
    if(fscf == NULL || fscf->type != NJT_STREAM_FTP_DATA){
        return NJT_ERROR;
    }

    //need get real port
    //sf = njt_stream_get_module_srv_conf(s, njt_stream_proto_module);
    if(s->connection->listening && s->connection->listening->mesh) {
        name_low.len = name.len;
        name_low.data = njt_pcalloc(s->connection->pool,name_low.len);
        proto_hash = njt_hash_strlow(name_low.data,name.data,name.len);
        name.data = name_low.data;
        name.len = name_low.len;
        njt_stream_variable_value_t *vv =  njt_stream_get_variable(s, &name, proto_hash);
        if(vv != NULL && 0 == vv->not_found){
            proxy_port = njt_atoi(vv->data, vv->len);
            if(proxy_port == NJT_ERROR){
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                    "ftp proxy get proto dest_port transfer error in replace upstream, just use socket addrinfo");
                
                proxy_port = njt_inet_get_port(s->connection->local_sockaddr);
            }else{
                njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                    "ftp proxy get port from prtoto in replace upstream");
            }
        }else{
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "ftp proxy could not get proto dest_port info in replace upstream, just use socket addrinfo");
            
            proxy_port = njt_inet_get_port(s->connection->local_sockaddr);
        }
    }else{
        proxy_port = njt_inet_get_port(s->connection->local_sockaddr);
        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0,
            "ftp proxy could not get proto info in replace upstream, just use socket addrinfo");
    }

    ftp_url_pool = njt_create_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
    if(ftp_url_pool == NULL || NJT_OK != njt_sub_pool(njt_cycle->pool, ftp_url_pool)){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "ftp proxy create ftp url pool error");
        return NJT_ERROR;
    }

    *uscf = njt_pcalloc(ftp_url_pool, sizeof(njt_stream_upstream_srv_conf_t));
    if (*uscf == NULL) {
        njt_destroy_pool(ftp_url_pool);
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "ftp proxy create uscf pool error");
        return NJT_ERROR;
    }

    (*uscf)->ftp_url_pool = ftp_url_pool;

    //get sip and port
    njt_memzero(buf, 100);
    end = njt_snprintf(buf, 100,"%d", proxy_port);
    key.data = buf;
    key.len = end - buf;

    ctx = fscf->shm_zone->data;
    njt_shmtx_lock(&ctx->shpool->mutex);

    hash = njt_crc32_short(key.data, key.len);
    node = njt_stream_ftp_proxy_lookup(&ctx->sh->rbtree, &key, hash);
    if (node != NULL) {
        node_info = (njt_stream_ftp_proxy_node_t *)&node->color;
    }else{
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "ftp data not find proxy_port:%d", proxy_port);
        njt_shmtx_unlock(&ctx->shpool->mutex);
        return NJT_ERROR;
    }

    sip.data = node_info->sip;
    sip.len = node_info->sip_len;
    njt_memzero(&u, sizeof(njt_url_t));
    njt_memzero(buf, 100);
    end = njt_snprintf(buf, 100, "%V:%d", &sip, node_info->sport);

    njt_shmtx_unlock(&ctx->shpool->mutex);

    u.url.len = end - buf;
    u.url.data = njt_pcalloc((*uscf)->ftp_url_pool, u.url.len);
    if(u.url.data == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "ftp proxy create url error");
        return NJT_ERROR;
    }
    njt_memcpy(u.url.data, buf, u.url.len);
    u.no_resolve = 1;

    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                "ftp data replace server addr:%V", &u.url);

    if (njt_parse_url((*uscf)->ftp_url_pool, &u) != NJT_OK) {
        if (u.err) {
            njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0,
                    "ftp data, %s in upstream \"%V\"", u.err, &u.url);
        }

        return NJT_ERROR;
    }

    if(NJT_OK != njt_stream_ftp_data_upstream(*uscf, &u)){
        return NJT_ERROR;
    }

    njt_stream_ftp_data_proxy_upstream_init_round_robin((*uscf)->ftp_url_pool, *uscf);

    return NJT_OK;
}


njt_int_t
njt_stream_ftp_data_upstream(njt_stream_upstream_srv_conf_t *uscf, njt_url_t *u)
{
    njt_stream_upstream_server_t     *us;

    // uscf->flags = flags;
    uscf->host = u->host;
    // uscf->file_name = cf->conf_file->file.name.data;
    // uscf->line = cf->conf_file->line;
    uscf->port = u->port;
    uscf->no_port = u->no_port;

    if (u->naddrs == 1 && (u->port || u->family == AF_UNIX)) {
        uscf->servers = njt_array_create(uscf->ftp_url_pool, 1,
                                         sizeof(njt_stream_upstream_server_t));
        if (uscf->servers == NULL) {
            return NJT_ERROR;
        }

        us = njt_array_push(uscf->servers);
        if (us == NULL) {
            return NJT_ERROR;
        }

        njt_memzero(us, sizeof(njt_stream_upstream_server_t));

        us->addrs = u->addrs;
        us->naddrs = 1;
    }

    return NJT_OK;
}


static char *
njt_stream_ftp_data(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_stream_ftp_proxy_srv_conf_t     *fcf;
    njt_str_t                           *value;
    njt_str_t                           name;
    njt_uint_t                          i;
    njt_stream_core_srv_conf_t          *cscf;


    fcf = (njt_stream_ftp_proxy_srv_conf_t *) conf;
    if (fcf->enable != NJT_CONF_UNSET) {
        return "is duplicate";
    }

    fcf->enable = 1;
    name.len = 0;

    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++) {
        if (njt_strncmp(value[i].data, "zone=", 5) == 0) {
            name.data = value[i].data + 5;
            name.len = value[i].len - 5;

            continue;
        }
    }

    if (name.len == 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return NJT_CONF_ERROR;
    }

    fcf->shm_zone = njt_shared_memory_add(cf, &name, 0,
                                     &njt_stream_ftp_proxy_module);
    if (fcf->shm_zone == NULL) {
        return NJT_CONF_ERROR;
    }

    if (fcf->shm_zone->data == NULL) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
            "ftp_ctrl should config first and init zone:%V",
           &name);
        return NJT_CONF_ERROR;
    }

    fcf->type = NJT_STREAM_FTP_DATA;

    cscf = njt_stream_conf_get_module_srv_conf(cf, njt_stream_core_module);
    cscf->handler = njt_stream_proxy_handler;

    // pscf = njt_stream_conf_get_module_srv_conf(cf, njt_stream_proxy_module);
    // pscf->upstream = NULL;  //create when get real ftp server dataport info

    // njt_memzero(&u, sizeof(njt_url_t));
    // // u.url = *url;
    // njt_str_set(&u.url, "127.0.0.1:65535"); //just for tmpuse 
    // u.no_resolve = 1;

    // pscf = njt_stream_conf_get_module_srv_conf(cf, njt_stream_proxy_module);
    // pscf->upstream = njt_stream_ftp_data_upstream(cf, &u, 0);
    // if (pscf->upstream == NULL) {
    //     return NJT_CONF_ERROR;
    // }

    return NJT_CONF_OK;
}


static njt_int_t
njt_stream_ftp_proxy_init_zone(njt_shm_zone_t *shm_zone, void *data)
{
    njt_stream_ftp_proxy_ctx_t        *octx = data;
    size_t                      len;
    njt_stream_ftp_proxy_ctx_t        *ctx;

    ctx = shm_zone->data;

    if (octx) {
        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;

        return NJT_OK;
    }

    ctx->shpool = (njt_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->sh = ctx->shpool->data;

        return NJT_OK;
    }

    ctx->sh = njt_slab_alloc(ctx->shpool, sizeof(njt_stream_ftp_proxy_shctx_t));
    if (ctx->sh == NULL) {
        return NJT_ERROR;
    }

    ctx->sh->min_port = ctx->min_port;
    ctx->sh->max_port = ctx->max_port;
    ctx->sh->cur_empty_port = ctx->min_port;
    ctx->sh->used_port_num = 0;
    ctx->sh->freed_port_num = ctx->max_port - ctx->min_port + 1;

    ctx->shpool->data = ctx->sh;

    njt_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    njt_stream_ftp_proxy_rbtree_insert_value);

    len = sizeof(" in ftp_ctrl \"\"") + shm_zone->shm.name.len;

    ctx->shpool->log_ctx = njt_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return NJT_ERROR;
    }

    njt_sprintf(ctx->shpool->log_ctx, " in ftp_ctrl \"%V\"%Z",
                &shm_zone->shm.name);

    return NJT_OK;
}


static void
njt_stream_ftp_proxy_rbtree_insert_value(njt_rbtree_node_t *temp,
    njt_rbtree_node_t *node, njt_rbtree_node_t *sentinel)
{
    njt_rbtree_node_t           **p;
    njt_stream_ftp_proxy_node_t   *lcn, *lcnt;

    for ( ;; ) {
        if (node->key < temp->key) {
            p = &temp->left;
        } else if (node->key > temp->key) {
            p = &temp->right;
        } else { /* node->key == temp->key */
            lcn = (njt_stream_ftp_proxy_node_t *) &node->color;
            lcnt = (njt_stream_ftp_proxy_node_t *) &temp->color;
            p = (njt_memn2cmp(lcn->data, lcnt->data, lcn->len, lcnt->len) < 0)
                ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    njt_rbt_red(node);
}


void njt_stream_ftp_proxy_filter_pasv(njt_stream_session_t *s, u_char *data, ssize_t *n){
    njt_int_t                           proxy_port;
    njt_stream_ftp_proxy_srv_conf_t     *fscf;
    njt_str_t                           cip;
    char                                cip_buf[50];
    njt_uint_t                          cport;
    njt_str_t                           sip;
    char                                sip_buf[50];
    njt_uint_t                          sport;
    u_char                              *p, *start_index, *end_index;
    njt_uint_t                          sip_index, quot_number;
    uint16_t                            port1 = 0, port2 = 0;
    uint16_t                            proxy_port1 = 0, proxy_port2 = 0;
    u_char                              data_buf[100];
    u_char                              *end;
    njt_stream_ftp_data_port_t          *data_queue;


    if(njt_stream_ftp_proxy_module.ctx_index == NJT_MODULE_UNSET_INDEX){
        return;
    }

    fscf = njt_stream_get_module_srv_conf(s, njt_stream_ftp_proxy_module);
    if(fscf == NULL || fscf->type != NJT_STREAM_FTP_CTRL){
        return;
    }

    //get ftp data port info
    if(NULL == njt_strstr(data, "Entering Passive Mode")){
        return;
    }

    start_index = (u_char *)njt_strchr(data, '(');
    end_index = (u_char *)njt_strchr(data, ')');
    if (start_index == NULL || end_index == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "ftp proxy, not pasv data");
        return;
    }

    p = start_index + 1;
    sip_index = 0;
    quot_number = 0;
    njt_memzero(sip_buf, 50);
    while(p < end_index){
        if(*p == ','){
            p++;
            quot_number++;
            if(quot_number < 4){
                sip_buf[sip_index++] = '.';
            }

            if(quot_number == 4){
                port1 = atoi((char *)p);
            }
            if(quot_number == 5){
                port2 = atoi((char *)p);
                break;
            }
        }
        if(quot_number < 4){
            sip_buf[sip_index++] = *p;
            p++;
        }else{
            p++;
        }
    }

    if(quot_number != 5){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "not pasv data, quot number:%d < 5", quot_number);
        return;
    }
    sip.data = (u_char *)sip_buf;
    sip.len = sip_index;
    sport = (port1<<8)|port2; 

    //get client addr info
    cip.data = (u_char *)cip_buf;
    njt_memzero(cip_buf, 50);
    njt_memcpy(cip_buf, s->connection->addr_text.data, s->connection->addr_text.len);
    cip.len = s->connection->addr_text.len;
    cport = njt_inet_get_port(s->connection->sockaddr);

    //port map
    proxy_port = njt_stream_ftp_proxy_get_empty_port(fscf, &cip, cport, &sip, sport);
    if(proxy_port < 0){
        return;
    }

    //modify data ip and port, use proxy_ip and proxy_port
    //get proxy_ip 
    p = start_index+1;
    proxy_port1 = (proxy_port >> 8) & 0xff;
    proxy_port2 = proxy_port & 0xff;
    end = njt_snprintf(data_buf, 100, "%V,%d,%d).\r\n", &fscf->proxy_ip, proxy_port1, proxy_port2);
    njt_memcpy(p, data_buf, end - data_buf);
    *n = (p - data) + (end - data_buf);

    //add data_port to stream's ftp_port_queue
    data_queue = njt_pcalloc(fscf->pool, sizeof(njt_stream_ftp_data_port_t));
    if(data_queue == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "ftp proxy malloc port info error");
        return;
    }
    data_queue->data_port = proxy_port;
    njt_queue_insert_tail(&s->ftp_port_list, &data_queue->queue);

    return;
}

static njt_rbtree_node_t *
njt_stream_ftp_proxy_lookup(njt_rbtree_t *rbtree, njt_str_t *key,
    uint32_t hash)
{
    njt_int_t                      rc;
    njt_rbtree_node_t             *node, *sentinel;
    njt_stream_ftp_proxy_node_t  *lcn;

    node = rbtree->root;
    sentinel = rbtree->sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        lcn = (njt_stream_ftp_proxy_node_t *) &node->color;

        rc = njt_memn2cmp(key->data, lcn->data, key->len, (size_t) lcn->len);

        if (rc == 0) {
            return node;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}

void
njt_stream_ftp_proxy_cleanup(njt_stream_session_t *s)
{
    njt_stream_ftp_control_proxy_cleanup(s);
    njt_stream_ftp_data_proxy_cleanup(s);
}

void
njt_stream_ftp_data_proxy_cleanup(njt_stream_session_t *s)
{
    njt_stream_ftp_proxy_srv_conf_t     *fscf;
    njt_rbtree_node_t                   *node;
    njt_stream_ftp_proxy_ctx_t          *ctx;
    u_char                              data_buf[15];
    u_char                              *end;
    uint32_t                            hash;
    njt_str_t                           key;
    njt_int_t                           proxy_port;
    njt_str_t                           name = njt_string("njtmesh_port");
    njt_str_t                           name_low;
    njt_uint_t                          proto_hash;
    //njt_stream_proto_srv_conf_t         *sf;
    
    if(njt_stream_ftp_proxy_module.ctx_index == NJT_MODULE_UNSET_INDEX){
        return;
    }

    fscf = njt_stream_get_module_srv_conf(s, njt_stream_ftp_proxy_module);
    if(fscf == NULL || fscf->type != NJT_STREAM_FTP_DATA){
        return;
    }

    if(s->upstream != NULL && s->upstream->upstream != NULL && s->upstream->upstream->ftp_url_pool != NULL){
        njt_destroy_pool(s->upstream->upstream->ftp_url_pool);
        s->upstream->upstream = NULL;
    }

    //need get real port
    //sf = njt_stream_get_module_srv_conf(s, njt_stream_proto_module);
    if(s->connection->listening && s->connection->listening->mesh) {
        name_low.len = name.len;
        name_low.data = njt_pcalloc(s->connection->pool,name_low.len);
        proto_hash = njt_hash_strlow(name_low.data,name.data,name.len);
        name.data = name_low.data;
        name.len = name_low.len;
        njt_stream_variable_value_t *vv =  njt_stream_get_variable(s, &name, proto_hash);
        if(vv != NULL && 0 == vv->not_found){
            proxy_port = njt_atoi(vv->data, vv->len);
            if(proxy_port == NJT_ERROR){
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                    "ftp proxy get proto dest_port transfer error in replace upstream, just use socket addrinfo");
                
                proxy_port = njt_inet_get_port(s->connection->local_sockaddr);
            }
        }else{
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "ftp proxy could not get proto dest_port info in replace upstream, just use socket addrinfo");
            
            proxy_port = njt_inet_get_port(s->connection->local_sockaddr);
        }
    }else{
        proxy_port = njt_inet_get_port(s->connection->local_sockaddr);
        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0,
            "ftp proxy could not get proto info in replace upstream, just use socket addrinfo");
    }

    ctx = fscf->shm_zone->data;
    njt_shmtx_lock(&ctx->shpool->mutex);

    end = njt_snprintf(data_buf, 100,"%d", proxy_port);
    key.data = data_buf;
    key.len = end - data_buf;

    hash = njt_crc32_short(key.data, key.len);
    node = njt_stream_ftp_proxy_lookup(&ctx->sh->rbtree, &key, hash);
    if (node != NULL) {
        njt_rbtree_delete(&ctx->sh->rbtree, node);
        njt_slab_free_locked(ctx->shpool, node);
        ctx->sh->used_port_num--;
        ctx->sh->freed_port_num++;

        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0,
            "ftp_proxy data free_port:%d cip:%V cport:%d used_port_num:%d  freed_port_num:%d",
            proxy_port, &s->connection->addr_text, 
            njt_inet_get_port(s->connection->sockaddr),
            ctx->sh->used_port_num, ctx->sh->freed_port_num);
    }

    njt_shmtx_unlock(&ctx->shpool->mutex);
}


void
njt_stream_ftp_control_proxy_cleanup(njt_stream_session_t *s)
{
    njt_stream_ftp_proxy_srv_conf_t     *fscf;
    njt_rbtree_node_t                   *node;
    njt_stream_ftp_proxy_ctx_t          *ctx;
    njt_stream_ftp_proxy_node_t         *node_info;
    njt_queue_t 			            *q;
    njt_stream_ftp_data_port_t          *fdp;
    u_char                              data_buf[15];
    u_char                              *end;
    uint32_t                            hash;
    njt_str_t                           key;
    

    if(njt_stream_ftp_proxy_module.ctx_index == NJT_MODULE_UNSET_INDEX){
        return;
    }

    if(njt_queue_empty(&s->ftp_port_list)){
        return;
    }

    fscf = njt_stream_get_module_srv_conf(s, njt_stream_ftp_proxy_module);
    if(fscf == NULL || fscf->type != NJT_STREAM_FTP_CTRL){
        return;
    }

    ctx = fscf->shm_zone->data;
    njt_shmtx_lock(&ctx->shpool->mutex);
    for (q = njt_queue_head(&s->ftp_port_list);
            q != njt_queue_sentinel(&s->ftp_port_list);
        ){
        fdp = njt_queue_data(q, njt_stream_ftp_data_port_t, queue);
        q = njt_queue_next(q);
        njt_queue_remove(&fdp->queue);
        end = njt_snprintf(data_buf, 100,"%d", fdp->data_port);
        key.data = data_buf;
        key.len = end - data_buf;

        hash = njt_crc32_short(key.data, key.len);
        node = njt_stream_ftp_proxy_lookup(&ctx->sh->rbtree, &key, hash);
        if (node != NULL) {
            node_info = (njt_stream_ftp_proxy_node_t *)&node->color;
            //check cip info
            if(njt_inet_get_port(s->connection->sockaddr) == node_info->cport
                && s->connection->addr_text.len == node_info->cip_len
                && njt_strncmp(s->connection->addr_text.data, node_info->cip, node_info->cip_len) == 0){

                njt_rbtree_delete(&ctx->sh->rbtree, node);
                njt_slab_free_locked(ctx->shpool, node);
                ctx->sh->used_port_num--;
                ctx->sh->freed_port_num++;

                njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                    "ftp_proxy control free_port:%d cip:%V cport:%d used_port_num:%d  freed_port_num:%d",
                    fdp->data_port, &s->connection->addr_text, 
                    njt_inet_get_port(s->connection->sockaddr),
                    ctx->sh->used_port_num, ctx->sh->freed_port_num);
            }
        }

        njt_pfree(fscf->pool, fdp);
    }

    njt_shmtx_unlock(&ctx->shpool->mutex);
}


//if no free port then return -1 else return a free port
njt_int_t njt_stream_ftp_proxy_get_empty_port(njt_stream_ftp_proxy_srv_conf_t  *conf,
        njt_str_t *cip, njt_uint_t cport, njt_str_t *sip, njt_uint_t sport){
    njt_int_t                           port_index;
    njt_stream_ftp_proxy_ctx_t          *ctx;
    size_t                              n;
    njt_rbtree_node_t                   *node;
    njt_int_t                           cur_port;
    njt_stream_ftp_proxy_node_t         *fp;
    u_char                              data_buf[15];
    u_char                              *end;
    njt_str_t                           key;
    uint32_t                            hash;
    njt_flag_t                          found;

    ctx = conf->shm_zone->data;
    njt_shmtx_lock(&ctx->shpool->mutex);
    ctx = conf->shm_zone->data;
    if(ctx->sh->freed_port_num < 1){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "ftp_proxy has no freed port");
        njt_shmtx_unlock(&ctx->shpool->mutex);
        return -1;
    }

    if(ctx->sh->cur_empty_port == -1){
        found = 0;
        //get next_empty_port
        for(port_index = ctx->min_port; port_index <= ctx->max_port; port_index++){
            end = njt_snprintf(data_buf, 100,"%d", port_index);
            key.data = data_buf;
            key.len = end - data_buf;

            hash = njt_crc32_short(key.data, key.len);
            node = njt_stream_ftp_proxy_lookup(&ctx->sh->rbtree, &key, hash);
            if (node == NULL) {
                ctx->sh->cur_empty_port = port_index;
                found = 1;
                break;
            }
        }

        if(!found){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                    "ftp_proxy should has freed port, but not found, logic error");
            njt_shmtx_unlock(&ctx->shpool->mutex);
            return -1;
        }
    }

    cur_port = ctx->sh->cur_empty_port;
    end = njt_snprintf(data_buf, 100,"%d", ctx->sh->cur_empty_port);
    key.data = data_buf;
    key.len = end - data_buf;

    //create current_empty_port structure
    n = offsetof(njt_rbtree_node_t, color)
        + offsetof(njt_stream_ftp_proxy_node_t, data)
        + key.len;

    node = njt_slab_alloc_locked(ctx->shpool, n);
    if (node == NULL) {
        njt_shmtx_unlock(&ctx->shpool->mutex);
        return -2;
    }

    hash = njt_crc32_short(key.data, key.len);
    node->key = hash;
    fp = (njt_stream_ftp_proxy_node_t *) &node->color;
    fp->port = cur_port;
    fp->sport = sport;
    fp->sip_len = sip->len;
    njt_memcpy(fp->sip, sip->data, sip->len);

    fp->cport = cport;
    fp->cip_len = cip->len;
    njt_memcpy(fp->cip, cip->data, cip->len);

    fp->len = key.len;
    njt_memcpy(fp->data, key.data, key.len);
    njt_rbtree_insert(&ctx->sh->rbtree, node);
    ctx->sh->freed_port_num--;
    ctx->sh->used_port_num++;

    ctx->sh->cur_empty_port = -1;
    //get next_empty_port
    for(port_index = ctx->min_port; port_index <= ctx->max_port; port_index++){
        end = njt_snprintf(data_buf, 100,"%d", port_index);
        key.data = data_buf;
        key.len = end - data_buf;

        hash = njt_crc32_short(key.data, key.len);
        node = njt_stream_ftp_proxy_lookup(&ctx->sh->rbtree, &key, hash);
        if (node == NULL) {
            ctx->sh->cur_empty_port = port_index;

            break;
        }
    }

    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
        "ftp_proxy now_port is:%d next empty port is:%d   used_port_num:%d  freed_port_num:%d\
        cip:%V cport:%d  sip:%V  sport:%d",
        cur_port, ctx->sh->cur_empty_port, ctx->sh->used_port_num, ctx->sh->freed_port_num,
        cip, cport, sip, sport);
    njt_shmtx_unlock(&ctx->shpool->mutex);

    return cur_port;
}