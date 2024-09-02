
/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>

#include "njt_gossip.h"
#include "msgpuck.h"
#include "njt_http_token_sync_module.h"

#define GOSSIP_APP_TOKEN_SYNC 	0xD8759D88
#define TOKEN_SYNC_DEFAULT_SYNC_TIME  	2000
#define TOKEN_SYNC_DEFAULT_CLEAN_TIME  	5000
#define TOKEN_SYNC_DATA_CNT  	4
#define TOKEN_SYNC_MAX_ZONE  	30
#define TOKEN_SYNC_MAX_TOKEN_LEN        100
#define TOKEN_SYNC_MAX_ADDITIONAL_DATA_LEN        512



typedef struct
{
    u_char					color;
    u_char 					len;
	njt_str_t 				addtional_data;		//addional data
	njt_uint_t				ori_ttl;    //orignal expire time, sec
	njt_uint_t				dyn_ttl;    //dynamic expire time, sec
	njt_flag_t				expired;    //wether expire
	
	//wether has sync, when set or get(not expire), update to false; if syn, update to true
	njt_flag_t				has_syn_flag;   
	njt_msec_t 				last_seen;
	njt_queue_t            	queue;
    u_char 					data[1];    //token data
} njt_http_token_sync_rb_node_t;

typedef struct
{
    njt_rbtree_t 			rbtree;
    njt_rbtree_node_t 		sentinel;
	njt_queue_t          	queue;
} njt_http_token_sync_shctx_t;

typedef struct {
	njt_http_token_sync_shctx_t  *sh;
    njt_slab_pool_t         *shpool;
	njt_log_t 				*log;
	void					*data;
} njt_http_token_sync_ctx_t;


typedef struct {
	njt_str_t 				zone_name;
	njt_msec_t				sync_time;
	njt_msec_t				clean_time;
	njt_http_token_sync_ctx_t 	*ctx;
} njt_http_token_sync_main_conf_t;


static njt_http_token_sync_main_conf_t *token_instance = NULL;

static void *njt_http_token_sync_create_main_conf(njt_conf_t *cf);

static njt_int_t njt_http_token_sync_update_node(njt_http_token_sync_ctx_t *ctx, 
	njt_str_t token, njt_str_t addtional_data, njt_msec_t ori_ttl, njt_msec_t dyn_ttl, njt_flag_t need_sync);

static void njt_http_token_sync_sync_data(njt_http_token_sync_ctx_t* ctx,
	njt_str_t* target, njt_str_t* target_pid, njt_flag_t new_node);

static njt_int_t      njt_http_token_sync_init_worker(njt_cycle_t *cycle);
    
static char *njt_http_token_sync_cmd(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);

static njt_rbtree_node_t *
njt_http_token_sync_lookup(njt_rbtree_t *rbtree, njt_str_t *key, uint32_t hash);

static njt_int_t njt_http_token_sync_init_zone(njt_shm_zone_t *shm_zone, void *data);



static njt_http_module_t njt_http_token_sync_module_ctx = {
    NULL, /* preconfiguration */
    NULL, //njt_http_token_sync_reg_filter, /* postconfiguration */

    njt_http_token_sync_create_main_conf, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    NULL, /* create location configuration */
    NULL   /* merge location configuration */
};

static njt_command_t njt_http_token_sync_commands[] = {
      { njt_string("token_sync"),
      NJT_HTTP_MAIN_CONF | NJT_CONF_TAKE123,
      njt_http_token_sync_cmd,
      0,
      0,
      NULL }
    ,njt_null_command /* command termination */
};

njt_module_t  njt_http_token_sync_module = {
    NJT_MODULE_V1,
    &njt_http_token_sync_module_ctx, /* module context */
    njt_http_token_sync_commands, /* module directives */
    NJT_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    njt_http_token_sync_init_worker,                /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};


static void *
njt_http_token_sync_create_main_conf(njt_conf_t *cf)
{
    njt_http_token_sync_main_conf_t *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_token_sync_main_conf_t));

    if (conf == NULL) {
        return NULL;
    }

	njt_str_null(&conf->zone_name);
	conf->sync_time = TOKEN_SYNC_DEFAULT_SYNC_TIME;
	conf->clean_time = TOKEN_SYNC_DEFAULT_CLEAN_TIME;
	conf->ctx = NULL;

    return conf;
}



static char *njt_http_token_sync_cmd(njt_conf_t *cf, njt_command_t *cmd,
    void *conf) {
	njt_shm_zone_t          		*shm_zone;
    njt_str_t 						*value = cf->args->elts;
    njt_str_t 						shm_name, shm_size;
	njt_int_t 						size;

	njt_str_t						tmp_str;
	njt_uint_t                   	i;
	u_char 							*p;
	njt_http_token_sync_main_conf_t *tsmf = (njt_http_token_sync_main_conf_t *)conf;

	if(tsmf->ctx){
		return "is duplicate";
	}

	if (njt_strncmp(value[1].data, "zone=", 5) == 0) {
		shm_name.data = value[1].data + 5;
		p = (u_char *) njt_strchr(shm_name.data, ':');
		if (p == NULL) {
			njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
								"invalid zone size \"%V\"", &value[1]);
			return NJT_CONF_ERROR;
		}
		shm_name.len = p - shm_name.data;
		shm_size.data = p + 1;
		shm_size.len = value[1].data + value[1].len - shm_size.data;
		size = njt_parse_size(&shm_size);
		if (size == NJT_ERROR) {
			njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
								"invalid zone size \"%V\"", &value[1]);
			return NJT_CONF_ERROR;
		}
    } else {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                   "invalid http_token_sync param \"%V\", format is zone={zone_name}:{size}M", &value[1]);
            return NJT_CONF_ERROR;
    }
	
	for (i = 2; i < cf->args->nelts; i++) {
		if (njt_strncmp(value[i].data, "sync_time=", 10) == 0){
			tmp_str.data = value[i].data + 10;
			tmp_str.len = value[i].len - 10;
			tsmf->sync_time = njt_parse_time(&tmp_str, 0);
			if (tsmf->sync_time == (njt_msec_t) NJT_ERROR) {
				njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
					" token sync, invalid sync_time:\"%V\"", &tmp_str);
				return NJT_CONF_ERROR;
			}

			if(tsmf->sync_time <= 0){
				njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
					" token sync, invalid sync_time:\"%V\" should be more than 0", &tmp_str);
				return NJT_CONF_ERROR;
			}
		}else if (njt_strncmp(value[i].data, "clean_time=", 11) == 0){
			tmp_str.data = value[i].data + 11;
			tmp_str.len = value[i].len - 11;
			tsmf->clean_time = njt_parse_time(&tmp_str, 0);
			if (tsmf->clean_time == (njt_msec_t) NJT_ERROR) {
				njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
					" token sync, invalid clean_time:\"%V\"", &tmp_str);
				return NJT_CONF_ERROR;
			}

			if(tsmf->clean_time <= 0){
				njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
					" token sync, invalid clean_time:\"%V\" should be more than 0", &tmp_str);
				return NJT_CONF_ERROR;
			}

		}else{
			njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
				" token sync, invalid param:\"%V\"", &value[i]);
			return NJT_CONF_ERROR;
		}
	}

	tsmf->zone_name.data = njt_pnalloc(cf->pool, shm_name.len);
	njt_memcpy(tsmf->zone_name.data, shm_name.data, shm_name.len);
	tsmf->zone_name.len = shm_name.len;

	tsmf->ctx = njt_pcalloc(cf->cycle->pool, sizeof(njt_http_token_sync_ctx_t));
	if(tsmf->ctx == NULL){
		njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           " token sync, ctx malloc error");

        return NJT_CONF_ERROR;
	}

	tsmf->ctx->log = &cf->cycle->new_log;
	tsmf->ctx->data =  tsmf;

	shm_zone = njt_shared_memory_add(cf, &shm_name , size, &njt_http_token_sync_module);
    if (shm_zone == NULL) {
        return NJT_CONF_ERROR;
    }

    if (shm_zone->data) {
        tsmf->ctx = shm_zone->data;

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "%V \"%V\" is already bound to other, please use a new zone",
                           &cmd->name, &shm_name);
        return NJT_CONF_ERROR;
    }

    shm_zone->init = njt_http_token_sync_init_zone;
    shm_zone->data = tsmf->ctx;

    return NJT_CONF_OK;
}

static void
njt_http_token_sync_rbtree_insert_value(njt_rbtree_node_t *temp,njt_rbtree_node_t *node, njt_rbtree_node_t *sentinel)
{
    njt_rbtree_node_t **p;
    njt_http_token_sync_rb_node_t *lcn, *lcnt;
    for (;;)
    {
        if (node->key < temp->key)
        {

            p = &temp->left;
        }
        else if (node->key > temp->key)
        {

            p = &temp->right;
        }
    	else 
		{ /* node->key == temp->key */
            lcn = (njt_http_token_sync_rb_node_t *)&node->color;
            lcnt = ( njt_http_token_sync_rb_node_t*)&temp->color;

            p = (njt_memn2cmp(lcn->data, lcnt->data, lcn->len, lcnt->len) < 0)
                    ? &temp->left
                    : &temp->right;
        }

        if (*p == sentinel)
        {
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

static njt_rbtree_node_t *
njt_http_token_sync_lookup(njt_rbtree_t *rbtree, njt_str_t *key, uint32_t hash)
{
    njt_int_t rc;
    njt_rbtree_node_t *node, *sentinel;
    njt_http_token_sync_rb_node_t *lcn;

    node = rbtree->root;
    sentinel = rbtree->sentinel;
	
	while (node != sentinel)
    {

        if (hash < node->key)
        {
            node = node->left;
            continue;
        }

        if (hash > node->key)
        {
            node = node->right;
            continue;
        }
		lcn = (njt_http_token_sync_rb_node_t *)&node->color;
        rc = njt_memn2cmp(key->data, lcn->data, key->len, (size_t)lcn->len);

        if (rc == 0)
        {
            return node;
        }

        node = (rc < 0) ? node->left : node->right;
    }
    return NULL;
}

static njt_int_t njt_http_token_sync_init_zone(njt_shm_zone_t *shm_zone, void *data)
{
	njt_http_token_sync_ctx_t  *ctx, *octx = data;
    size_t                      len;

    ctx = shm_zone->data;
    if (octx) {
        //todo: check old shm size
        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;
        return NJT_OK;
    }
	ctx->shpool = (njt_slab_pool_t *) shm_zone->shm.addr;
    if (shm_zone->shm.exists) {
        ctx->sh = ctx->shpool->data;
        return NJT_OK;
    }
	ctx->sh = njt_slab_alloc(ctx->shpool, sizeof(njt_http_token_sync_shctx_t));
    if (ctx->sh == NULL) {
        return NJT_ERROR;
    }

    ctx->shpool->data = ctx->sh;

    njt_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    njt_http_token_sync_rbtree_insert_value);

	njt_queue_init(&ctx->sh->queue);

    len = sizeof(" in http_token_sync zone \"\"") + shm_zone->shm.name.len;
    ctx->shpool->log_ctx = njt_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return NJT_ERROR;
    }
	njt_sprintf(ctx->shpool->log_ctx, " in http_token_sync zone \"%V\"%Z",
                &shm_zone->shm.name);

    return NJT_OK;
}


static void http_token_sync_expire_node(njt_http_token_sync_ctx_t* ctx)
{
	njt_queue_t 					*q, *x;
	njt_rbtree_node_t 				*node;
	njt_http_token_sync_rb_node_t 	*lr;
	njt_str_t						token;
	njt_msec_t  					checkpoint_stamp = njt_current_msec;

	njt_shmtx_lock(&ctx->shpool->mutex);

	q = njt_queue_head(&ctx->sh->queue);
	while (q != njt_queue_sentinel(&ctx->sh->queue)){
		x = njt_queue_next(q);
        lr = njt_queue_data(q, njt_http_token_sync_rb_node_t, queue);
		if(lr->expired ||
			((checkpoint_stamp - lr->last_seen) > lr->ori_ttl)){
			njt_queue_remove(q);

			node = (njt_rbtree_node_t *)
					((u_char *) lr - offsetof(njt_rbtree_node_t, color));

			token.data = lr->data;
			token.len = lr->len;
			njt_log_error(NJT_LOG_DEBUG, ctx->log,0,
				" token module clean expire tokeninfo, token:%V addtional_data:%V",
				&token, &lr->addtional_data);

			njt_slab_free_locked(token_instance->ctx->shpool, lr->addtional_data.data);

			njt_rbtree_delete(&ctx->sh->rbtree, node);
			njt_slab_free_locked(ctx->shpool, node);
		}

		q = x;
	}
   	njt_shmtx_unlock(&ctx->shpool->mutex);
}


static void njt_http_token_sync_sync_data( njt_http_token_sync_ctx_t* ctx,
	njt_str_t* target, njt_str_t* target_pid, njt_flag_t new_node)
{
	size_t 					buf_size=0;
	char 					*buf=NULL, *head=NULL;
	uint32_t 				msg_cnt =0;	
	njt_queue_t 			*q;
	njt_http_token_sync_rb_node_t *lr;
	njt_msec_t  			checkpoint_stamp = njt_current_msec;
	size_t					current_node_size = 0;
	char 					*tail;
	int 					arr_cnt;
	njt_msec_t 				ttl;

    njt_shmtx_lock(&ctx->shpool->mutex);

	if (njt_queue_empty(&ctx->sh->queue) ) {
    	njt_shmtx_unlock(&ctx->shpool->mutex);
		return;
	}

	for (q = njt_queue_head(&ctx->sh->queue);
     			q != njt_queue_sentinel(&ctx->sh->queue);
     		q = njt_queue_next(q))
	{
		lr = njt_queue_data(q, njt_http_token_sync_rb_node_t, queue);	
		
		if(lr->expired){
			continue;
		}

		if(!new_node && lr->has_syn_flag){
			continue;
		}

		//expired
		ttl = checkpoint_stamp - lr->last_seen;
		if(ttl > lr->ori_ttl){
			lr->expired = true;
			continue;
		}

		//check send addtional
		if(msg_cnt >0){
			//current node need size
			//count size is 4, ori ttl is 8, dyn ttl is 8
			current_node_size = 4 + 8 + 8;

			//and has addtional data len, max TOKEN_SYNC_MAX_ADDITIONAL_DATA_LEN
			if(lr->addtional_data.len > TOKEN_SYNC_MAX_ADDITIONAL_DATA_LEN){
				current_node_size += TOKEN_SYNC_MAX_ADDITIONAL_DATA_LEN;
			}else{
				current_node_size += lr->addtional_data.len;
			}

			//and has token len, max TOKEN_SYNC_MAX_TOKEN_LEN
			if(lr->len > TOKEN_SYNC_MAX_TOKEN_LEN){
				current_node_size += TOKEN_SYNC_MAX_TOKEN_LEN;
			}else{
				current_node_size += lr->len;
			}

			//max count 15 or left space is less than the current node's needed space
			if(msg_cnt == 15 || buf_size < current_node_size) {
				njt_gossip_app_close_msg_buf(tail);
				//if (msg_cnt>=10) {
					mp_encode_array(buf, msg_cnt);
					njt_log_error(NJT_LOG_DEBUG, ctx->log, 0, " large sync pack:%d", msg_cnt);
					njt_gossip_send_app_msg_buf();
					msg_cnt= 0;
					head=NULL;
				//}
			}
		}

		if (head == NULL ) {
			int pack_cnt=1;
			char *pack_head;
			buf = njt_gossip_app_get_msg_buf(GOSSIP_APP_TOKEN_SYNC, *target, *target_pid, &buf_size);
			if (buf_size <= 0 || buf ==NULL) {
				njt_log_error(NJT_LOG_ERR,ctx->log,0,"apply buffer failed");
    			njt_shmtx_unlock(&ctx->shpool->mutex);

				return;
			}

			pack_head = buf;
			head= mp_encode_array(pack_head,pack_cnt);
		}

		lr->has_syn_flag = true;
		msg_cnt++;
		arr_cnt = TOKEN_SYNC_DATA_CNT;
		tail = head;
		tail= mp_encode_array(tail,arr_cnt);

		//set token
		if(lr->len > TOKEN_SYNC_MAX_TOKEN_LEN){
			tail = mp_encode_str(tail,(char *)lr->data, TOKEN_SYNC_MAX_TOKEN_LEN);
		}else{
			tail = mp_encode_str(tail,(char *)lr->data, lr->len);
		}

		//set token addtionanl data
		if(lr->addtional_data.len > TOKEN_SYNC_MAX_ADDITIONAL_DATA_LEN){
			tail = mp_encode_str(tail,(char *)lr->addtional_data.data, TOKEN_SYNC_MAX_ADDITIONAL_DATA_LEN);
		}else{
			tail = mp_encode_str(tail,(char *)lr->addtional_data.data, lr->addtional_data.len);
		}
		
		//set ori ttl
		tail= mp_encode_uint(tail, lr->ori_ttl/1000);

		//set dyn ttl
		lr->dyn_ttl = checkpoint_stamp - lr->last_seen;
		tail= mp_encode_uint(tail, lr->dyn_ttl/1000);
 
		buf_size  = buf_size - (tail - head);
		head = tail;

		njt_log_error(NJT_LOG_DEBUG, ctx->log,0,
				" prepare token data for send, dynttl:%M  orittl:%M current:%M last_seen:%M adddata:%V", 
				lr->dyn_ttl/1000, lr->ori_ttl/1000, checkpoint_stamp, lr->last_seen, &lr->addtional_data);
	}

	njt_shmtx_unlock(&ctx->shpool->mutex);

	if (head !=NULL) {
		njt_gossip_app_close_msg_buf(head);
	}

	if (msg_cnt > 0) {
		mp_encode_array(buf,msg_cnt);
		njt_log_error(NJT_LOG_DEBUG, ctx->log, 0, "sync pack:%d", msg_cnt);
		njt_gossip_send_app_msg_buf();
	}
}


// static void http_token_sync_test(){
// 	static int test_set = 1;
// 	njt_str_t token, value1, value2, retvalue;
// 	u_char *p;
// 	int i;
// 	u_char tmptoken[256];


// 	njt_str_set(&value1, "1234567890123456789012345678901234567890123456789012345678901234567890");
// 	njt_str_set(&value2, "==1234567890123456789012345678901234567890123456789012345678901234567890==");
// 	if(test_set > 0){
// 		test_set--;
// 		p = njt_snprintf(tmptoken, 256, "===========================1");
// 		token.data = tmptoken;
// 		token.len = p - tmptoken;

// 		for(i = 0; i < 20; i++){
// 			p = njt_snprintf(tmptoken, 256, "fdslkfjslkfjsklfjsdklfjsdlkfjskjf%d", i);

// 			token.data = tmptoken;
// 			token.len = p - tmptoken;

// 			if(NJT_OK != njt_token_set(&token, &value1, 60)){
// 				njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " set token:%V value1:%V error", &token, &value1);
// 			}else{
// 				njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " set token:%V value1:%V ok", &token, &value1);
// 			}

// 			if(NJT_OK != njt_token_get(&token, &retvalue)){
// 				njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " get token:%V error", &token);
// 			}else{
// 				njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " get token:%V ok, value:%V", &token, &retvalue);
// 			}

// 			// sleep(2000);
// 			if(NJT_OK != njt_token_set(&token, &value2, 60)){
// 				njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " set token:%V value2:%V error", &token, &value2);
// 			}else{
// 				njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " set token:%V value2:%V ok", &token, &value2);
// 			}

// 			if(NJT_OK != njt_token_get(&token, &retvalue)){
// 				njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " get token:%V error", &token);
// 			}else{
// 				njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " get token:%V ok, value:%V", &token, &retvalue);
// 			}
// 		}
// 	}

// 	// test_set--;
// 	// // njt_str_null(&value);
// 	// // if(NJT_OK != njt_token_get(&token, &value)){
// 	// // 	njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " get token:%V error", &token);
// 	// // }else{
// 	// // 	njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " get token:%V ok, value:%V", &token, &value);
// 	// // }
// }

static void http_token_sync_sync_handler(njt_event_t *ev)
{
	// njt_http_token_sync_ctx_t* ctx=(njt_http_token_sync_ctx_t*) ev->data;
	if (!ev->timedout)  return;

	if (!njt_exiting) {
		// http_token_sync_test();
		njt_str_t target = njt_string("all");
		njt_str_t target_pid = njt_string("0");

		if(token_instance == NULL || token_instance->ctx == NULL){
			njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0," sync, token sync is not config");
		}else{
			njt_http_token_sync_sync_data(token_instance->ctx, &target, &target_pid, false);

			njt_add_timer(ev, token_instance->sync_time);
		}
	}
}


static void http_token_sync_clean_handler(njt_event_t *ev)
{
	// njt_http_token_sync_ctx_t* ctx=(njt_http_token_sync_ctx_t*) ev->data;
	if (!ev->timedout)  return;

	if (!njt_exiting) {
		if(token_instance == NULL || token_instance->ctx == NULL){
			njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0," clean, token sync is not config");
		}else{
			http_token_sync_expire_node(token_instance->ctx);

			njt_add_timer(ev, token_instance->clean_time);
		}
	}
}


static int njt_http_token_sync_recv_data(const char* msg, void* data)
{
	njt_str_t 					token, addtional_data;
	uint32_t 					pack_cnt, arr_cnt, i, len;
	njt_msec_t					ori_ttl, dyn_ttl;
	const char 					*r = msg;

	if(token_instance == NULL || token_instance->ctx == NULL){
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
			" token sync is not config");
	
		return NJT_ERROR;
	}

	pack_cnt = mp_decode_array(&r);
	njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,"%d packages received", pack_cnt);
	for (i=0;i<pack_cnt;i++) {
		arr_cnt = mp_decode_array(&r);
		if (arr_cnt != TOKEN_SYNC_DATA_CNT) {
			njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,"warn: invalid package , a package need include 4 elements:%d", arr_cnt);
			return NJT_ERROR;
		}
		
		//decode token
		token.data = (u_char *)mp_decode_str(&r, &len);
    	token.len=len;

		//decode token addtionanl data
		addtional_data.data = (u_char *)mp_decode_str(&r, &len);
    	addtional_data.len=len;

		//decode ori ttl
		ori_ttl = mp_decode_uint(&r);

		//decode ori ttl
		dyn_ttl = mp_decode_uint(&r);

		njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
			" recv data index:%d token:%V addtional_data:%V ori_ttl:%M dyn_ttl:%M",
			i, &token, &addtional_data, ori_ttl, dyn_ttl);

		// aa = false;
		njt_http_token_sync_update_node(token_instance->ctx, token, addtional_data, ori_ttl * 1000, dyn_ttl * 1000, false);
	}
	return NJT_OK;
}


static int  njt_http_token_sync_on_node_on(njt_str_t* node, njt_str_t* node_pid, void* data)
{
	// njt_http_token_sync_ctx_t* ctx= (njt_http_token_sync_ctx_t*) data;
	// njt_http_token_sync_srv_conf_t* ascf =(njt_http_token_sync_srv_conf_t*) ctx->data;
	
	if(token_instance == NULL || token_instance->ctx == NULL){
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
			" token sync is not config");
	
		return NJT_ERROR;
	}

	njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, " token sync, node:%V on", node);
	njt_http_token_sync_sync_data(token_instance->ctx, node, node_pid, true);

	return NJT_OK;
}

static njt_int_t njt_http_token_sync_init_worker(njt_cycle_t *cycle)
{
	njt_http_token_sync_main_conf_t *tsmf = NULL;
	njt_http_conf_ctx_t 			*http_conf_ctx;
	njt_event_t 					*sync_ev, *clean_ev;

	if (njt_process == NJT_PROCESS_HELPER) {
        return NJT_OK;
    }

	if (njt_http_token_sync_module.ctx_index == NJT_CONF_UNSET_UINT)
    {
        return NJT_OK;
    }

    http_conf_ctx = (njt_http_conf_ctx_t *)njt_get_conf(cycle->conf_ctx, njt_http_module);
    if (!http_conf_ctx) {
        njt_log_error(NJT_LOG_INFO, cycle->log, 0, "http section not found");
        return NJT_OK;
    }

    tsmf = http_conf_ctx->main_conf[njt_http_token_sync_module.ctx_index];
    if (!tsmf || !tsmf->ctx) {
        njt_log_error(NJT_LOG_INFO, cycle->log, 0, "token sync is not config");
        return NJT_OK;
    }

	token_instance = tsmf;

	njt_gossip_reg_app_handler(njt_http_token_sync_recv_data, njt_http_token_sync_on_node_on, GOSSIP_APP_TOKEN_SYNC, token_instance);
	//only the first worker do broadcast job
	if (njt_worker == 0)  {
		//start sync event
		sync_ev = njt_palloc(cycle->pool, sizeof(njt_event_t));
		sync_ev->log = &cycle->new_log;
		sync_ev->timer_set = 0;
		sync_ev->cancelable = 1;
		sync_ev->handler = http_token_sync_sync_handler;
		sync_ev->data = (void *)tsmf;
		njt_add_timer(sync_ev, tsmf->sync_time);

		//start clean event
		clean_ev = njt_palloc(cycle->pool, sizeof(njt_event_t));
		clean_ev->log = &cycle->new_log;
		clean_ev->timer_set = 0;
		clean_ev->cancelable = 1;
		clean_ev->handler = http_token_sync_clean_handler;
		clean_ev->data = (void *)tsmf;
		njt_add_timer(clean_ev, tsmf->clean_time);
	}


    return NJT_OK;
}

static njt_int_t njt_http_token_sync_update_node(njt_http_token_sync_ctx_t *ctx, 
	njt_str_t token, njt_str_t addtional_data, njt_msec_t ori_ttl, njt_msec_t dyn_ttl, njt_flag_t need_sync)
{
  	njt_http_token_sync_rb_node_t 	*lr;
	njt_rbtree_node_t 				*node;
	njt_msec_t  					update_stamp = njt_current_msec;
	uint32_t hash = njt_crc32_short(token.data, token.len);

    njt_shmtx_lock(&ctx->shpool->mutex);
njt_log_error(NJT_LOG_ERR, ctx->log, 0, "======================1 token:%V", &token);
    node = njt_http_token_sync_lookup(&ctx->sh->rbtree, &token, hash);
	if (node != NULL ) {
		njt_log_error(NJT_LOG_ERR, ctx->log, 0, "======================2 exist token:%V", &token);
		njt_log_error(NJT_LOG_DEBUG, ctx->log, 0, "found node according to:%V", &token);
		lr= (njt_http_token_sync_rb_node_t *) &node->color;
		njt_log_error(NJT_LOG_ERR, ctx->log, 0, "======================3 update_stamp:%M dynttl:%M lastseen:%M token:%V", 
			update_stamp, dyn_ttl, lr->last_seen, &token);
		//tips: if the node exist, but last_seen is old in tree, then update, else omit
		if ( (update_stamp - dyn_ttl) >= lr->last_seen) {
			njt_log_error(NJT_LOG_ERR, ctx->log, 0, "======================4 newer token:%V", &token);
			lr->last_seen = update_stamp - dyn_ttl;
			if(need_sync){
				lr->has_syn_flag = false;
			}else{
				lr->has_syn_flag = true;
			}

			lr->expired = false;
			lr->ori_ttl = ori_ttl;
			lr->dyn_ttl = dyn_ttl;

			njt_log_error(NJT_LOG_DEBUG,ctx->log,0, 
				"update orittl:%M  dynttl:%M  last_seen:%M",ori_ttl, dyn_ttl, lr->last_seen);

			njt_slab_free_locked(ctx->shpool, lr->addtional_data.data);

			lr->addtional_data.data = njt_slab_alloc_locked(ctx->shpool, addtional_data.len);
			if (lr->addtional_data.data == NULL) {
				njt_log_error(NJT_LOG_CRIT,ctx->log,0, "malloc failed in http_token_sync init tree, pos1");
				njt_shmtx_unlock(&ctx->shpool->mutex);

				return NJT_ERROR;
			}	
			lr->addtional_data.len = addtional_data.len;
			memcpy(lr->addtional_data.data, addtional_data.data, addtional_data.len);

			njt_log_error(NJT_LOG_ERR, ctx->log, 0, "======================5 update token:%V value:%V", &token, &lr->addtional_data);
			njt_queue_remove(&lr->queue);
			//todo:  this queue should sort
            njt_queue_insert_head(&ctx->sh->queue, &lr->queue);
		}
    	njt_shmtx_unlock(&ctx->shpool->mutex);

		return NJT_OK;
	}
	njt_log_error(NJT_LOG_DEBUG, ctx->log,0, "no node token:%V addtional_data:%V",&token, &addtional_data);

	uint32_t n = offsetof(njt_rbtree_node_t, color)
        + offsetof(njt_http_token_sync_rb_node_t, data)
        + token.len;

   	node = njt_slab_alloc_locked(ctx->shpool, n);
	if (node == NULL) {
       	njt_log_error(NJT_LOG_CRIT,ctx->log,0, "malloc failed in http_token_sync init tree, pos2");
    	njt_shmtx_unlock(&ctx->shpool->mutex);

		return NJT_ERROR;
   	} 

    node->key = hash;
    lr = (njt_http_token_sync_rb_node_t *) &node->color;
    lr->len = (u_short) token.len;
	lr->last_seen = update_stamp - dyn_ttl;
	lr->ori_ttl = ori_ttl;
	lr->dyn_ttl = dyn_ttl;
	if(need_sync){
		lr->has_syn_flag = false;
	}else{
		lr->has_syn_flag = true;
	}

	njt_log_error(NJT_LOG_INFO, ctx->log, 0, 
		"add token node orittl:%M  dynttl:%M  last_seen:%M",ori_ttl, dyn_ttl, lr->last_seen);

	lr->addtional_data.data = njt_slab_alloc_locked(ctx->shpool, addtional_data.len);
	if (lr->addtional_data.data == NULL) {
       	njt_log_error(NJT_LOG_CRIT,ctx->log,0, "malloc failed in http_token_sync init tree, pos3");
    	njt_shmtx_unlock(&ctx->shpool->mutex);

		return NJT_ERROR;
   	} 	
	lr->addtional_data.len = addtional_data.len;
	memcpy(lr->addtional_data.data, addtional_data.data, addtional_data.len);

	njt_memcpy(lr->data, token.data, token.len);

	njt_rbtree_insert(&ctx->sh->rbtree, node);

    njt_queue_insert_head(&ctx->sh->queue, &lr->queue);

    njt_shmtx_unlock(&ctx->shpool->mutex);

	return NJT_OK;
}


int njt_token_get(njt_str_t *token, njt_str_t *value){
	njt_http_token_sync_rb_node_t 	*lr;
	njt_rbtree_node_t 				*node;
	uint32_t 						hash;
	njt_http_token_sync_main_conf_t *tsmf = NULL;
	njt_http_conf_ctx_t 			*http_conf_ctx;

	if(token == NULL || token->len < 1){
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " token get, input token should not be NULL or len must more than 0");

		return NJT_ERROR;
	}

	if(value == NULL){
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " token get, input value should not be NULL");
		return NJT_ERROR;
	}

	if (njt_process == NJT_PROCESS_HELPER) {
		if(token_instance == NULL){
			http_conf_ctx = (njt_http_conf_ctx_t *)njt_get_conf(njt_cycle->old_cycle->conf_ctx, njt_http_module);
			if (!http_conf_ctx) {
				njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "http section not found");
				return NJT_OK;
			}

			tsmf = http_conf_ctx->main_conf[njt_http_token_sync_module.ctx_index];
			if (!tsmf || !tsmf->ctx) {
				njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "token sync is not config");
				return NJT_OK;
			}

			token_instance = tsmf;
		}
	}


	if(token_instance == NULL || token_instance->ctx == NULL){
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " token get, token sync not config");
		return NJT_ERROR;
	}

	njt_str_null(value);
	hash = njt_crc32_short(token->data, token->len);

    njt_shmtx_lock(&token_instance->ctx->shpool->mutex);

    node = njt_http_token_sync_lookup(&token_instance->ctx->sh->rbtree, token, hash);
	if (node != NULL) {
		lr= (njt_http_token_sync_rb_node_t *) &node->color;
		njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, " found node, token:%V addtional_data:%V", token, &lr->addtional_data);
		if(lr->expired || ((njt_current_msec - lr->last_seen) > lr->ori_ttl)){
			njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, " expired cur:%M lastseen:%M orittl:%d  expired:%d", 
				njt_current_msec,lr->last_seen, lr->ori_ttl,lr->expired);
			lr->expired = true;

		}else{
			lr->last_seen = njt_current_msec;
			lr->expired = false;
			lr->dyn_ttl = 0;
			lr->has_syn_flag = false;

			value->data = lr->addtional_data.data;
			value->len = lr->addtional_data.len;
		}
	}else{
		njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, " not found node, token:%V", token);
	}

	njt_shmtx_unlock(&token_instance->ctx->shpool->mutex);

	return NJT_OK;
}


int njt_token_set(njt_str_t *token, njt_str_t *value, int ttl){
	njt_http_token_sync_main_conf_t *tsmf = NULL;
	njt_http_conf_ctx_t 			*http_conf_ctx;

	if(token == NULL || token->len < 1){
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " token set, input token should not be NULL or len must more than 0");

		return NJT_ERROR;
	}

	if(value == NULL || value->len < 1){
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " token set, input value should not be NULL or len must more than 0");
		return NJT_ERROR;
	}

	if(ttl < 1){
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " token set, input ttl must more than 0");
		return NJT_ERROR;
	}

	if (njt_process == NJT_PROCESS_HELPER) {
		if(token_instance == NULL){
			http_conf_ctx = (njt_http_conf_ctx_t *)njt_get_conf(njt_cycle->old_cycle->conf_ctx, njt_http_module);
			if (!http_conf_ctx) {
				njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "http section not found");
				return NJT_OK;
			}

			tsmf = http_conf_ctx->main_conf[njt_http_token_sync_module.ctx_index];
			if (!tsmf || !tsmf->ctx) {
				njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "token sync is not config");
				return NJT_OK;
			}

			token_instance = tsmf;
		}
	}

	if(token_instance == NULL || token_instance->ctx == NULL){
		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " token set, token sync not config");
		return NJT_ERROR;
	}

	return njt_http_token_sync_update_node(token_instance->ctx, *token, *value, ttl * 1000, 0, true);
}


// int njt_token_del(njt_str_t *token){
// 	njt_http_token_sync_rb_node_t 	*lr;
// 	njt_rbtree_node_t 				*node;
// 	uint32_t 						hash;

// 	if(token == NULL || token->len < 1){
// 		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " token del, input token should not be NULL or len must more than 0");

// 		return NJT_ERROR;
// 	}

// 	if(token_instance == NULL || token_instance->ctx == NULL){
// 		njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " token del, token sync not config");
// 		return NJT_ERROR;
// 	}

// 	hash = njt_crc32_short(token->data, token->len);

//     njt_shmtx_lock(&token_instance->ctx->shpool->mutex);

//     node = njt_http_token_sync_lookup(&token_instance->ctx->sh->rbtree, token, hash);
// 	if (node != NULL) {

// 		lr= (njt_http_token_sync_rb_node_t *) &node->color;
// 		njt_queue_remove(&lr->queue);

// 		njt_log_error(NJT_LOG_ERR, njt_cycle->log,0,
// 				" del token info, token:%V addtional_data:%V",
// 				token, &lr->addtional_data);

// 		njt_slab_free_locked(token_instance->ctx->shpool, lr->addtional_data.data);

// 		njt_rbtree_delete(&token_instance->ctx->sh->rbtree, node);
// 		njt_slab_free_locked(token_instance->ctx->shpool, node);
// 	}

// 	njt_shmtx_unlock(&token_instance->ctx->shpool->mutex);

// 	return NJT_OK;
// }
