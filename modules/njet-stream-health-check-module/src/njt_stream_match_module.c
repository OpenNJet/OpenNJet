//
// Created by Administrator on 2022/7/19/019.
//

#include <njt_stream.h>
#include <njt_stream_upstream_hc_module.h>

#define NJT_STREAM_MATCH_CONF   0x10000000
#define NJT_STREAM_MATCH_CONF_OFFSET offsetof(njt_stream_conf_ctx_t, srv_conf)
extern njt_module_t  njt_stream_match_module;

//预创建
njt_stream_match_t* njt_stream_match_create(njt_conf_t *cf, njt_str_t *name){
    njt_stream_match_srv_conf_t         *mscf;
    njt_stream_match_main_conf_t        *mmcf;
    njt_stream_module_t                 *module;
    uint32_t                            hash;

    mmcf = njt_stream_conf_get_module_main_conf(cf,njt_stream_match_module);
    mscf = njt_stream_match_lookup_name(mmcf,*name);
    if(mscf != NULL){
        return mscf;
    }
    module = njt_stream_match_module.ctx;
    mscf = module->create_srv_conf(cf);
    mscf->match_name = *name;

    hash = njt_crc32_long(mscf->match_name.data,mscf->match_name.len);
    mscf->tree_node.key = hash;
    njt_rbtree_insert(&mmcf->match_tree,&mscf->tree_node);
    return mscf;
}

static char *njt_stream_match_block(njt_conf_t *cf, njt_command_t *cmd, void *conf){
    njt_str_t                           *value;
    njt_stream_match_srv_conf_t         *mscf;
    njt_stream_match_main_conf_t        *mmcf;
    njt_stream_conf_ctx_t               *ctx, *stream_ctx;
    njt_conf_t                          pcf;
    char                                *rv;
    void                                *mconf;
    njt_uint_t                          m;
    njt_stream_module_t                 *module;
    uint32_t                            hash;

    mmcf = conf;
    value = cf->args->elts;
    mscf = njt_stream_match_lookup_name(mmcf,value[1]);
    if(mscf != NULL && mscf->ctx != NJT_CONF_UNSET_PTR){
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,"the match name double definition ： \"%V\"",&value[1]);
        return NJT_CONF_ERROR;
    }

    ctx = njt_pcalloc(cf->pool, sizeof(njt_stream_conf_ctx_t));
    if (ctx == NULL) {
        return NJT_CONF_ERROR;
    }

    stream_ctx = cf->ctx;
    ctx->main_conf = stream_ctx->main_conf;

    ctx->srv_conf = njt_pcalloc(cf->pool,sizeof(void *) * njt_stream_max_module);
    if (ctx->srv_conf == NULL) {
        return NJT_CONF_ERROR;
    }

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NJT_STREAM_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;
        if (module->create_srv_conf) {
            mconf = module->create_srv_conf(cf);
            if (mconf == NULL) {
                return NJT_CONF_ERROR;
            }
            ctx->srv_conf[cf->cycle->modules[m]->ctx_index] = mconf;
        }
    }
    if (mscf != NULL ){
        njt_pfree(cf->pool,ctx->srv_conf[njt_stream_match_module.ctx_index]);
        ctx->srv_conf[njt_stream_match_module.ctx_index] = mscf;
    }
    mscf = ctx->srv_conf[njt_stream_match_module.ctx_index] ;
    mscf->ctx = ctx;
    mscf->match_name = value[1];

    hash = njt_crc32_long(mscf->match_name.data,mscf->match_name.len);
    mscf->tree_node.key = hash;
    njt_rbtree_insert(&mmcf->match_tree,&mscf->tree_node);

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NJT_STREAM_MATCH_CONF;
    rv = njt_conf_parse(cf, NULL);
    *cf = pcf;

    return rv;
}

inline static njt_int_t njt_stream_hex2char(u_char *str,u_char *data,njt_uint_t str_len){
    njt_uint_t                          size,index;
    u_char                              high,low;

    size = str_len / 4;
    for(index = 0 ; index < size; ++index){
        high = *(str + index*4 + 2) <= '9' ? *(str + index*4 + 2)-'0' :(
                *(str + index*4 + 2) < 'G' ? *(str + index*4 + 2)-'A' :
                *(str + index*4 + 2)-'a' );
        low = *(str + index*4 + 3) <= '9' ? *(str + index*4 + 3)-'0' :(
                *(str + index*4 + 3) < 'G' ? *(str + index*4 + 3)-'A' :
                *(str + index*4 + 3)-'a' );
        if( high>16 || low >16 ){
            return NJT_ERROR;
        }
        *(data+index) = (high << 4) + low;
    }
    return NJT_OK;
}

static char *
njt_stream_match_send(njt_conf_t *cf, njt_command_t *cmd,void *conf)
{
    njt_str_t                           *value;
    njt_stream_match_srv_conf_t         *mscf;
    njt_uint_t                          size;
    u_char                              *data;
    njt_int_t rc;

    value = cf->args->elts;

    mscf = conf;

    if(njt_strncmp(value[1].data,"\\x",2) == 0){
        size = value[1].len / 4;
        data = njt_pcalloc(cf->pool,size);
        if(data == NULL){
            njt_conf_log_error(NJT_LOG_ERR, cf, 0,"cann`t get ucmcf in match block ");
            return NJT_CONF_ERROR;
        }
        rc = njt_stream_hex2char(value[1].data,data,value[1].len);
        if(rc !=NJT_OK){
            njt_conf_log_error(NJT_LOG_ERR, cf, 0,"match send hex str error");
            return NJT_CONF_ERROR;
        }
        mscf->send.data = data;
        mscf->send.len = size;
    }else{
        mscf->send = value[1];
    }
    return NJT_CONF_OK;
}

static char *
njt_stream_match_expect(njt_conf_t *cf, njt_command_t *cmd,void *conf)
{
    njt_str_t                           *value;
    njt_stream_match_srv_conf_t         *mscf;
    njt_uint_t                          size;
    u_char                              *data;
    njt_str_t                           *arg_str,*regular_str;
    njt_int_t                           ret;

    value = cf->args->elts;

    mscf = njt_stream_conf_get_module_srv_conf(cf,njt_stream_match_module);
    if(mscf == NULL){
        njt_conf_log_error(NJT_LOG_ERR, cf, 0,"cann`t get mscf in match_expect ");
        return NJT_CONF_ERROR;
    }
    if(cf->args->nelts ==3 ){
        mscf->regular = 1;
        arg_str = &value[2];
        regular_str = &value[1];

#if (NJT_PCRE)
        njt_regex_compile_t  rc;
        u_char               errstr[NJT_MAX_CONF_ERRSTR];
        njt_memzero(&rc, sizeof(njt_regex_compile_t));

        rc.pattern = *arg_str;
        rc.err.len = NJT_MAX_CONF_ERRSTR;
        rc.err.data = errstr;
        rc.pool = cf->pool;
#else

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "using regex \"%V\" requires PCRE library",
                       regex);
    return NJT_CONF_ERROR;

#endif

        //仅有~ ~*
        if(regular_str->len == 1){
            if (njt_strncmp(regular_str->data, "~", 1) != 0) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "header operation parse error.");
                return NJT_CONF_ERROR;
            }
        }else if(regular_str->len == 2){
            if (njt_strncmp(regular_str->data, "~*", 2) != 0){
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "header operation parse error.");
                return NJT_CONF_ERROR;
            }
            rc.options = NJT_REGEX_CASELESS;
        }
        if (njt_regex_compile(&rc) != NJT_OK) {
            return NULL;
        }
        mscf->regex = rc.regex;
        if (mscf->regex == NULL) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "expect regex %V parse error.",arg_str);
            return NJT_CONF_ERROR;
        }
    }else if(cf->args->nelts ==2 ){
        mscf->regular = 0;
        arg_str = &value[1];
    }else{
        njt_conf_log_error(NJT_LOG_ERR, cf, 0,"only allow parameter quanitiy is <= 3");
        return NJT_CONF_ERROR;
    }
    if(njt_strncmp(arg_str->data,"\\x",2) == 0){
        size = arg_str->len / 4;
        data = njt_pcalloc(cf->pool,size);
        if(data == NULL){
            njt_conf_log_error(NJT_LOG_ERR, cf, 0,"cann`t get ucmcf in match block ");
            return NJT_CONF_ERROR;
        }
        ret = njt_stream_hex2char(value[1].data,data,value[1].len);
        if(ret !=NJT_OK){
            njt_conf_log_error(NJT_LOG_ERR, cf, 0,"match send hex str error");
            return NJT_CONF_ERROR;
        }
        mscf->expect.data = data;
        mscf->expect.len = size;
    }else{
        mscf->expect = *arg_str;
    }
    return NJT_CONF_OK;
}

static njt_command_t  njt_stream_match_commands[] = {

        { njt_string("match"),
          NJT_STREAM_MAIN_CONF|NJT_CONF_BLOCK|NJT_CONF_TAKE1,
          njt_stream_match_block,
          NJT_STREAM_MAIN_CONF_OFFSET,
          0,
          NULL },

        { njt_string("send"),
          NJT_STREAM_MATCH_CONF|NJT_CONF_TAKE1,
          njt_stream_match_send,
          NJT_STREAM_MATCH_CONF_OFFSET,
          0,
          NULL },

        { njt_string("expect"),
          NJT_STREAM_MATCH_CONF|NJT_CONF_1MORE,
          njt_stream_match_expect,
          NJT_STREAM_MATCH_CONF_OFFSET,
          0,
          NULL },

        njt_null_command
};

static void *njt_stream_match_create_main_conf(njt_conf_t *cf)
{
    njt_stream_match_main_conf_t  *mmcf;

    mmcf = njt_pcalloc(cf->pool, sizeof(njt_stream_match_main_conf_t));
    if (mmcf == NULL) {
        return NULL;
    }
    njt_rbtree_init(&mmcf->match_tree,&mmcf->sentinel,njt_str_rbtree_insert_value);
    return mmcf;
}


static void *
njt_stream_upstream_check_create_srv_conf(njt_conf_t *cf)
{
    njt_stream_match_srv_conf_t  *mscf;

    mscf = njt_pcalloc(cf->pool, sizeof(njt_stream_match_srv_conf_t));
    if (mscf == NULL) {
        return NULL;
    }

    mscf->ctx = NJT_CONF_UNSET_PTR;
    mscf->regular = NJT_CONF_UNSET;
    mscf->regex = NJT_CONF_UNSET_PTR;

    return mscf;
}

static char*
njt_stream_upstream_check_merge_srv_conf(njt_conf_t *cf, void *parent,void *child)
{
    njt_stream_match_srv_conf_t *prev = parent;
    njt_stream_match_srv_conf_t *conf = child;

    njt_conf_merge_ptr_value(conf->ctx, prev->ctx,cf->ctx);
    njt_conf_merge_ptr_value(conf->regex, prev->regex,NULL);
    return NJT_CONF_OK;
}

static njt_stream_module_t  njt_stream_match_module_ctx = {
        NULL,                                               /* preconfiguration */
        NULL,                                               /* postconfiguration */

        njt_stream_match_create_main_conf,                  /* create main configuration */
        NULL,  /* init main configuration */

        njt_stream_upstream_check_create_srv_conf,          /* create server configuration */
        njt_stream_upstream_check_merge_srv_conf,        /* merge server configuration */

};


njt_stream_match_srv_conf_t* njt_stream_match_lookup_name(njt_stream_match_main_conf_t *mmcf,njt_str_t name){

    njt_stream_match_srv_conf_t  *mscf;
    uint32_t                     hash;
    njt_rbtree_t                 *tree;
    njt_rbtree_node_t            *node,*sentinel;
    njt_int_t rc;

    hash = njt_crc32_long(name.data,name.len);
    tree = &mmcf->match_tree;
    node = tree->root;
    sentinel = tree->sentinel;

    for ( ;; ) {
        if (node == sentinel) {
            break;
        }
        mscf = (njt_stream_match_srv_conf_t *)node - offsetof(njt_stream_match_srv_conf_t,tree_node);
        if (node->key != hash) {
            node = (hash < node->key ) ? node->left : node->right;
        } else if (mscf->match_name.len != name.len) {
            node = (name.len < mscf->match_name.len) ? node->left : node->right;
        } else {
            rc = njt_memcmp(mscf->match_name.data, name.data, mscf->match_name.len);
            if(rc == 0){
                return mscf;
            }
            node = ( rc< 0) ? node->left : node->right;
        }

    }
    return NULL;
}


njt_module_t  njt_stream_match_module = {
        NJT_MODULE_V1,
        &njt_stream_match_module_ctx,           /* module context */
        njt_stream_match_commands,              /* module directives */
        NJT_STREAM_MODULE,                       /* module type */
        NULL,                                  /* init master */
        NULL,                                  /* init module */
        NULL,                                   /* init process */
        NULL,                                  /* init thread */
        NULL,                                  /* exit thread */
        NULL,                                  /* exit process */
        NULL,                                  /* exit master */
        NJT_MODULE_V1_PADDING
};
