/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>
#include <sys/socket.h>
#include "njt_stream_sniffer.h"
#include "njt_stream_sniffer_parse.h"
#include "njt_stream_sniffer_lex.h"


typedef struct {
   
}njt_stream_sniffer_ctx_t; 

typedef struct {
   njt_str_t sniffer_data;
   njt_int_t sniffer_start_pos;
   u_char    have_four_bit;
}njt_stream_sniffer_data_t; 


typedef struct {
    njt_uint_t       max_read;
    njt_flag_t      sniffer_enabled;
    njt_array_t     *sniffer_list;
    sniffer_parse_ctx_t* ctx;
}njt_stream_sniffer_srv_conf_t;

static njt_int_t njt_stream_sniffer_add_variables(njt_conf_t *cf);
static njt_int_t njt_stream_sniffer_init(njt_conf_t *cf);
static void *njt_stream_sniffer_create_srv_conf(njt_conf_t *cf);
static char *njt_stream_sniffer_merge_srv_conf(njt_conf_t *cf, void *parent, void *child);
static char *
njt_stream_set_sniffer_filter(njt_conf_t *cf, njt_command_t *cmd, void *conf);


njt_int_t njt_stream_check_hex_str(njt_str_t data) {
    njt_uint_t  i;
    njt_uint_t  c1;
    if(data.len < 2 || data.len % 2 == 1) {
        return NJT_ERROR;
    }
    for(i=0; i < data.len; i++) {
       c1 = data.data[i];
       c1 = (c1 >= 'A' && c1 <= 'Z') ? (c1 | 0x20) : c1;
       if((c1 >= '0' && c1 <= '9') || (c1 >= 'a' && c1 <= 'f')) {
            continue;
       }
       return NJT_ERROR;
    }
    return NJT_OK;
}





/**
 * This module provide callback to istio for http traffic
 *
 */
static njt_command_t njt_stream_sniffer_commands[] = {
    { njt_string("sniffer"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_sniffer_srv_conf_t, sniffer_enabled),
      NULL },
    {
      njt_string("sniffer_data"),
      NJT_STREAM_MAIN_CONF | NJT_STREAM_SRV_CONF | NJT_CONF_TAKE1,
      njt_stream_set_sniffer_filter,     // do custom config
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL
    },
    njt_null_command /* command termination */
};




/* The module context. */
static njt_stream_module_t njt_stream_sniffer_module_ctx = {
    njt_stream_sniffer_add_variables, /* preconfiguration */
    njt_stream_sniffer_init, /* postconfiguration */
    NULL,
    NULL, /* init main configuration */
    njt_stream_sniffer_create_srv_conf, /* create server configuration */
    njt_stream_sniffer_merge_srv_conf /* merge server configuration */

};

/* Module definition. */
njt_module_t njt_stream_sniffer_module = {
    NJT_MODULE_V1,
    &njt_stream_sniffer_module_ctx, /* module context */
    njt_stream_sniffer_commands, /* module directives */
    NJT_STREAM_MODULE, /* module type */
    NULL, /* init master */
    NULL, /* init module */
    NULL, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    NULL, /* exit master */
    NJT_MODULE_V1_PADDING
};

// list of variables to add
static njt_stream_variable_t  njt_stream_sniffer_vars[] = {


    njt_stream_null_variable
};



static void *njt_stream_sniffer_create_srv_conf(njt_conf_t *cf)
{
    njt_stream_sniffer_srv_conf_t  *conf;

    njt_log_debug(NJT_LOG_DEBUG_EVENT, njt_cycle->log, 0, "nginmeshdest create serv config");

    conf = njt_pcalloc(cf->pool, sizeof(njt_stream_sniffer_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }


    conf->sniffer_list = NJT_CONF_UNSET_PTR;
    conf->sniffer_enabled = NJT_CONF_UNSET;
    conf->max_read = 0;
    return conf;
}


static char *njt_stream_sniffer_merge_srv_conf(njt_conf_t *cf, void *parent, void *child)
{

    njt_log_debug(NJT_LOG_DEBUG_EVENT, njt_cycle->log, 0, "nginmeshdest merge serv config");

    njt_stream_sniffer_srv_conf_t *prev = parent;
    njt_stream_sniffer_srv_conf_t *conf = child;

    njt_conf_merge_ptr_value(conf->sniffer_list,
                              prev->sniffer_list, NULL);
    njt_conf_merge_value(conf->sniffer_enabled, prev->sniffer_enabled, 0);
    return NJT_CONF_OK;
}


 njt_int_t njt_stream_sniffer_check_data(njt_stream_session_t *s,njt_stream_sniffer_data_t *sniffer){
    njt_connection_t                   *c;
    njt_int_t    len,rc;
    njt_str_t    data;
    u_char       val1,val2;
    njt_uint_t   data_len;    


    c = s->connection;
    data_len = c->buffer->last -  c->buffer->pos;
    if(data_len < sniffer->sniffer_data.len + sniffer->sniffer_start_pos) {
        return NJT_ERROR;
    }
    data.len = sniffer->sniffer_data.len;
    data.data = njt_pcalloc(c->pool,data.len);
    if(data.data == NULL) {
        return NJT_ERROR;
    }
    rc = NJT_OK;
    len = sniffer->sniffer_data.len;
    if(sniffer->have_four_bit) {
        len--;
    }
     if(len > 0) {
        if ( njt_memcmp(c->buffer->pos + sniffer->sniffer_start_pos,sniffer->sniffer_data.data,len) != 0) {
            rc = NJT_ERROR;
        }
     }
     if(rc == NJT_OK && sniffer->have_four_bit) {
        val1 = c->buffer->pos[sniffer->sniffer_start_pos + len];
        val2 = sniffer->sniffer_data.data[sniffer->sniffer_start_pos + len];
        if((val1 & 0x0F) != (val2 & 0x0F)) {
            rc = NJT_ERROR;
        }
     }
      return rc;
     
 }
  int
njt_stream_sniffer_callback(void *ctx,void *pdata)
{
    njt_uint_t                    i;
     njt_int_t                           rc;
    sniffer_exp_t *exp  = ctx;
    njt_stream_sniffer_data_t  *sniffer_list, *sniffer;
    njt_stream_session_t  **s = pdata;
    njt_stream_sniffer_srv_conf_t  *sscf;

    sscf = njt_stream_get_module_srv_conf(*s, njt_stream_sniffer_module);
    i = exp->idx;
     //zyg todo
    //ret = 0;
    sniffer_list = sscf->sniffer_list->elts;
    if(sscf->sniffer_list->nelts > i){
	    sniffer = &sniffer_list[i];
         rc = njt_stream_sniffer_check_data(*s,sniffer);
	    return (rc == NJT_OK ?1:0);
    }
    return NJT_DECLINED;
}

 njt_int_t njt_stream_sniffer_handler(njt_stream_session_t *s)
{
    // u_char                             *last, *p;
    size_t                              len;
    njt_int_t                           rc,ret;
    njt_connection_t                   *c;
    njt_stream_sniffer_srv_conf_t  *sscf;
    //njt_uint_t   i;
    //njt_stream_sniffer_data_t            *sniffer_data;

    c = s->connection;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, c->log, 0, "njt_stream_sniffer_handler");

    sscf = njt_stream_get_module_srv_conf(s, njt_stream_sniffer_module);

    if (!sscf->sniffer_enabled) {
        return NJT_DECLINED;
    }

    if (c->type != SOCK_STREAM) {
        return NJT_DECLINED;
    }

    if (c->buffer == NULL) {
        return NJT_AGAIN;
    }
    len = c->buffer->last - c->buffer->pos;
    if (len < sscf->max_read) {
        return NJT_AGAIN;
    }
    rc = NJT_OK;

    if (sscf->sniffer_list != NULL) {
        ret = eval_sniffer_parse_tree((sniffer_exp_parse_node_t *)sscf->ctx->root,njt_stream_sniffer_callback,&s);
        if(ret == 0) {
           rc = NJT_ERROR;
        }
    }
    if(rc == NJT_ERROR) {
#ifdef TCP_REPAIR

                njt_int_t aux = 1;
                if ( setsockopt( c->fd, SOL_TCP, TCP_REPAIR, 
                                    &aux, sizeof( aux )) < 0 )
                {
                njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "njt_stream_sniffer_handler");
                }
#endif
        return NJT_ERROR;
    }
    

	return NJT_DECLINED;
}

static njt_int_t njt_stream_sniffer_add_variables(njt_conf_t *cf)
{
    njt_stream_variable_t  *var, *v;


    for (v = njt_stream_sniffer_vars; v->name.len; v++) {
        njt_log_debug2(NJT_LOG_DEBUG_EVENT, njt_cycle->log, 0, "ngin mesh var initialized: %*s",v->name.len,v->name.data);
        var = njt_stream_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NJT_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NJT_OK;
}

// add handler to pre-access
// otherwise, handler can't be add as part of config handler if proxy handler is involved.

static njt_int_t njt_stream_sniffer_init(njt_conf_t *cf)
{
    njt_stream_handler_pt        *h;
    njt_stream_core_main_conf_t  *cmcf;


    njt_log_debug(NJT_LOG_DEBUG_EVENT,  njt_cycle->log, 0, "ngin mesh init invoked");


    cmcf = njt_stream_conf_get_module_main_conf(cf, njt_stream_core_module);

    h = njt_array_push(&cmcf->phases[NJT_STREAM_PREREAD_PHASE].handlers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_stream_sniffer_handler;

    return NJT_OK;
}
void 
free_sniffer_exp(sniffer_exp_t* exp) {
    if (exp) {
        free(exp->exp);
        free(exp);
    }
}

int get_sniffer_exp_counts(sniffer_exp_parse_node_t* root) {
    if (!root) return 0;
    if (root->node_type == EXP_EXPRESSION) {
        return 1;
    } 
    return get_sniffer_exp_counts(root->left) + get_sniffer_exp_counts(root->right);
}

void 
dump_sniffer_tree(sniffer_exp_parse_node_t* root, int level) 
{
	int i;

	if (!root) return;
	
    if  (root->left) {
		dump_sniffer_tree(root->left, level+1);
	}

	for (i=0;i<level;i++) {
        njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,"\t");
    }
    switch (root->node_type)
    {
    case EXP_EXPRESSION:
        njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,"%s, idx: %d", root->loc_exp->exp, root->loc_exp->idx);
        break;
    case EXP_BOOL_OP_OR:
        njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,"OR");
        break;
    case EXP_BOOL_OP_AND:
        njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,"AND\n");
        break;
    
    default:
        break;
    }
	if  (root->right) {
		dump_sniffer_tree(root->right, level+1);
	}
}


void 
free_sniffer_tree(sniffer_exp_parse_node_t* root)
{
    if (!root) return;
   
  
    switch (root->node_type)
    {
    case EXP_EXPRESSION:
        free_sniffer_exp(root->loc_exp);
        break;
    case EXP_BOOL_OP_AND: case EXP_BOOL_OP_OR:
        free_sniffer_tree(root->left);
        free_sniffer_tree(root->right);
        break;
    default:
        printf("internal error: free bad node %d\n", root->node_type);
        break;
    }
    free(root);
}
void free_sniffer_bison_tree(sniffer_exp_parse_node_t* root){
     if (!root) return;
     free_sniffer_tree(root);
}

njt_int_t njt_stream_sniffer_cp_exp_parse_tree(sniffer_exp_parse_node_t * root, njt_pool_t   *pool,sniffer_exp_parse_node_t ** new_root)
{
   sniffer_exp_parse_node_t *new_node;
   sniffer_exp_t               *loc_exp;
   njt_int_t  rc;
   if(root == NULL) {
	*new_root = NULL;
	return NJT_OK;
    }
    new_node = njt_pcalloc(pool, sizeof(sniffer_exp_parse_node_t));
    if(new_node == NULL) {
	return NJT_ERROR;
    }
    new_node->node_type = root->node_type;
    *new_root = new_node;
    switch (root->node_type)
    {
    case EXP_EXPRESSION:
         loc_exp = njt_pcalloc(pool, sizeof(sniffer_exp_t));
	 if(loc_exp == NULL) {
        	return NJT_ERROR;
    	 }
	 loc_exp->idx = root->loc_exp->idx;
	 loc_exp->exp = njt_pcalloc(pool,njt_strlen(root->loc_exp->exp) + 1);
	 if(loc_exp->exp == NULL) {
		return NJT_ERROR;
	 }
	 njt_memcpy(loc_exp->exp,root->loc_exp->exp,njt_strlen(root->loc_exp->exp));
	 new_node->loc_exp = loc_exp;
         return NJT_OK;
    case EXP_BOOL_OP_OR:
    case EXP_BOOL_OP_AND:
          rc = njt_stream_sniffer_cp_exp_parse_tree(root->left,pool,&new_node->left);
	  if(rc != NJT_OK) {
		return rc;
	  }
          rc = njt_stream_sniffer_cp_exp_parse_tree(root->right,pool,&new_node->right);
	  if(rc != NJT_OK) {
                return rc;
          }
	  return NJT_OK;
        break;
    default:
        break;
    }
    return NJT_ERROR;
}


sniffer_parse_ctx_t*
njt_stream_sniffer_parse_tree_ctx(sniffer_exp_parse_node_t *root,njt_pool_t   *pool){
    char** exps;
    sniffer_parse_ctx_t* ctx;
    int idx = 0;
    int count = 0;
    sniffer_exp_parse_node_t** stack;

    // get exp count in ast tree;
    count = get_sniffer_exp_counts(root);
    exps = njt_pcalloc(pool,sizeof(char *)*count);
    if (!exps) {
        return NULL;
    }
    ctx = njt_pcalloc(pool,sizeof(sniffer_parse_ctx_t));
    if (!ctx) {
        return NULL;
    }
    stack = njt_alloc(sizeof(sniffer_exp_parse_node_t*)*count,njt_cycle->log); //malloc(sizeof(loc_parse_node_t*)*count);
    if (!stack) {
        return NULL;
    }

    sniffer_exp_parse_node_t* current = root;
    int stack_size = 0;

    // printf("start traverse tree \n");
    while (current != NULL || stack_size != 0) {
        if (current != NULL) {
            stack[stack_size] = current;
            stack_size++;
            current = current->left;
        } else {
            current = stack[stack_size-1];
            stack_size--;
            if (current->node_type == EXP_EXPRESSION) {
                if(idx != current->loc_exp->idx) {
                    printf("idx: %d,  idx_exp: %d \n", idx, current->loc_exp->idx);
                }
		 njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "njt_http_core_loc_parse_tree_ctx run idx=%d, %s",current->loc_exp->idx,current->loc_exp->exp);
                exps[idx] = current->loc_exp->exp;
                idx++;
            }
            current = current->right;
        }
    }

    free(stack);

    ctx->root = root;
    ctx->exps = exps;
    ctx->count = count;

    return ctx;
}

int
eval_sniffer_exp(sniffer_exp_t *exp, void* data){
    if (!exp) {
        //yyerror()
        return 0;
    }
    // call njt_xxx
    printf("exp: %s, %d \n", exp->exp, (exp->exp[1] > 'm') ? 1 : 0);
    return (exp->exp[1] > 'm') ? 1 : 0;
}

int
eval_sniffer_parse_tree(sniffer_exp_parse_node_t * root, sniffer_parse_cb_ptr handler, void * data)
{
    switch (root->node_type)
    {
    case EXP_EXPRESSION:
        if(handler){
            return handler(root->loc_exp, data);
        } else {      
            return eval_sniffer_exp(root->loc_exp, data);
        }
        break;
    case EXP_BOOL_OP_OR:
        return   eval_sniffer_parse_tree(root->left, handler, data) 
               ? 1 : eval_sniffer_parse_tree(root->right, handler, data);
        break;
    case EXP_BOOL_OP_AND:
        return   eval_sniffer_parse_tree(root->left, handler, data) 
               ? eval_sniffer_parse_tree(root->right, handler, data) : 0;
        break;
    default:
        // yyerror()
        break;
    } 
    // unreachable
    return 0;
}


static void *
njt_stream_sniffer_parse_cmd(njt_conf_t *cf){
    
    njt_str_t                           *args;
    njt_str_t  command; //*value;
    sniffer_parse_ctx_t* ctx;
    sniffer_exp_parse_node_t *loc_exp_dyn_parse_tree, *root;
    njt_int_t rc;
    njt_int_t   r;
    //njt_stream_sniffer_data_t            *set_cmd;
     
    args = cf->args->elts;

    command = args[1];
    

    snifferlex_destroy();
    sniffer_scan_string((char *)command.data);
    root = NULL;
    r = snifferparse(&root);
    if(r != NJT_OK || root == NULL) {
    	free_sniffer_bison_tree(root);
	return NJT_CONF_ERROR;
    }
    rc = njt_stream_sniffer_cp_exp_parse_tree(root,cf->pool,&loc_exp_dyn_parse_tree);  
    if(rc != NJT_OK || loc_exp_dyn_parse_tree == NULL) {
    	free_sniffer_bison_tree(root);
	return NJT_CONF_ERROR;
    }
    free_sniffer_bison_tree(root);
    ctx = njt_stream_sniffer_parse_tree_ctx(loc_exp_dyn_parse_tree,cf->pool);
    if(ctx == NULL){
	return NJT_CONF_ERROR;
    }
    return ctx;
}

static char *
njt_stream_set_sniffer_filter(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    //njt_array_t  **scf;
    //char  *p = conf;
    njt_str_t                           *args,*value,sub_str,sub_cmd,buffer;
    njt_stream_sniffer_data_t            *set_cmd;
    njt_int_t   i,idx,val;
    njt_uint_t  j;
    njt_int_t  rc;
    njt_stream_sniffer_srv_conf_t *sf;
    sniffer_parse_ctx_t* ctx;

    
    sf = njt_stream_conf_get_module_srv_conf(cf, njt_stream_sniffer_module);

    args = cf->args->elts;
    if(args[1].len == 0) {
        return NJT_CONF_OK;
    }

    ctx = njt_stream_sniffer_parse_cmd(cf);
    if(ctx == NULL) {
        return NJT_CONF_ERROR;
    }

     if (sf->sniffer_list == NJT_CONF_UNSET_PTR || sf->sniffer_list  == NULL) {
        sf->sniffer_list = njt_array_create(cf->pool, 4, sizeof(njt_stream_sniffer_data_t));
        if (sf->sniffer_list == NULL) {
            return NJT_CONF_ERROR;
        }
     }
    sf->ctx = ctx;
    
    for(i =0; i < ctx->count; i++) {
        sub_str.data = (u_char *)ctx->exps[i];
        sub_str.len  = njt_strlen(sub_str.data);
        rc = njt_conf_read_memory_token(cf,sub_str);	
        if(rc == NJT_ERROR || cf->args->nelts == 0) {
            return NJT_CONF_ERROR;
        }
        value = cf->args->elts;
        sub_cmd.data = njt_pstrdup(cf->pool,&value[0]);
        sub_cmd.len = value[0].len;

        njt_strlow(sub_cmd.data,value[0].data,value[0].len);
        if(sub_cmd.len <= 2) {  
            return NJT_CONF_ERROR;
        }
        sub_cmd.data += 2;  //去掉十六进制  0x 前缀
        sub_cmd.len  -= 2;
        rc = njt_stream_check_hex_str(sub_cmd);
        if(rc == NJT_ERROR) {
            njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                            "%V invalid hex data",&args[1]);
            return NJT_CONF_ERROR;
        }
        buffer.len = (sub_cmd.len / 2) + (sub_cmd.len % 2 );
        buffer.data = njt_pcalloc(cf->pool,buffer.len);
        if(buffer.data == NULL) {
            return NJT_CONF_ERROR;
        }

        set_cmd = njt_array_push(sf->sniffer_list);
        if (set_cmd == NULL) {
            return NJT_CONF_ERROR;
        }
        njt_memzero(set_cmd,sizeof(njt_stream_sniffer_data_t));
        idx = 0;
        set_cmd->sniffer_data = buffer;
        if(sub_cmd.len / 2 > 0) {
           
            for(j = 0; j < sub_cmd.len; j += 2) {
                val = njt_hextoi((u_char *)&sub_cmd.data[j], 2);
                if (val == NJT_ERROR || val > 255)
                {
                    return NJT_CONF_ERROR;
                }
                buffer.data[idx++] = val;
            } 
        } 
        if (sub_cmd.len % 2 == 1) {
            val = njt_hextoi((u_char *)&sub_cmd.data[sub_cmd.len - 1], 1);
            buffer.data[idx++] = val;
            set_cmd->have_four_bit = 1;
        }
        set_cmd->sniffer_start_pos = NJT_CONF_UNSET;
        if(cf->args->nelts > 1) {
            set_cmd->sniffer_start_pos = njt_atoi(value[1].data,value[1].len);
        }

    }
    return NJT_CONF_OK;
}
