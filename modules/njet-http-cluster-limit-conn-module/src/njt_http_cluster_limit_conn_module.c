
/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_mqconf_module.h>
#include "njt_http_cluster_limit_conn_module.h"
#include <msgpuck.h>

#define NJT_HTTP_CLUSTER_LIMIT_CONN_PASSED 1
#define NJT_HTTP_CLUSTER_LIMIT_CONN_REJECTED 2
#define NJT_HTTP_CLUSTER_LIMIT_CONN_REJECTED_DRY_RUN 3

#define CLUSTER_LIMIT_CONN_MAX_ZONE  	30

#define SYNC_INT 100

#define GOSSIP_APP_CLUSTER_LIMIT_CONN  0x57B7D7DA

extern njt_module_t  njt_mqconf_module;

static njt_array_t *clconn_ctxes = NULL;

static njt_rbtree_node_t *njt_http_cluster_limit_conn_lookup(njt_rbtree_t *rbtree,
                                                             njt_str_t *key, uint32_t hash);
static void njt_http_cluster_limit_conn_cleanup(void *data);
static njt_inline void njt_http_cluster_limit_conn_cleanup_all(njt_pool_t *pool);

static njt_int_t njt_http_cluster_limit_conn_status_variable(njt_http_request_t *r,
                                                             njt_http_variable_value_t *v, uintptr_t data);
static void *njt_http_cluster_limit_conn_create_main_conf(njt_conf_t *cf);
static void *njt_http_cluster_limit_conn_create_conf(njt_conf_t *cf);
static char *njt_http_cluster_limit_conn_merge_conf(njt_conf_t *cf, void *parent,
                                                    void *child);
// static char *njt_http_cluster_limit_conn_zone(njt_conf_t *cf, njt_command_t *cmd,
//                                               void *conf);
static char *njt_http_cluster_limit_conn(njt_conf_t *cf, njt_command_t *cmd,
                                         void *conf);
static njt_int_t njt_http_cluster_limit_conn_add_variables(njt_conf_t *cf);
static njt_int_t njt_http_cluster_limit_conn_init(njt_conf_t *cf);

static void njt_http_udp_send_handler(njt_http_cluster_limit_conn_ctx_t* ctx,
            njt_str_t* zone, njt_str_t* target, njt_str_t* target_pid);

//end

static njt_http_variable_t njt_http_cluster_limit_conn_vars[] = {

    {njt_string("cluster_limit_conn_status"), NULL,
     njt_http_cluster_limit_conn_status_variable, 0, NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT},

    njt_http_null_variable};

static njt_str_t njt_http_cluster_limit_conn_status[] = {
    njt_string("PASSED"),
    njt_string("REJECTED"),
    njt_string("REJECTED_DRY_RUN")};


static njt_conf_enum_t njt_http_cluster_limit_conn_log_levels[] = {
    {njt_string("info"), NJT_LOG_INFO},
    {njt_string("notice"), NJT_LOG_NOTICE},
    {njt_string("warn"), NJT_LOG_WARN},
    {njt_string("error"), NJT_LOG_ERR},
    {njt_null_string, 0}};

static njt_conf_num_bounds_t njt_http_cluster_limit_conn_status_bounds = {
    njt_conf_check_num_bounds, 400, 599};

    
static njt_command_t njt_http_cluster_limit_conn_commands[] = {
    {njt_string("cluster_limit_conn"),
     NJT_HTTP_MAIN_CONF | NJT_HTTP_SRV_CONF | NJT_HTTP_LOC_CONF | NJT_CONF_TAKE3,
     njt_http_cluster_limit_conn,
     NJT_HTTP_LOC_CONF_OFFSET,
     0,
     NULL},

    {njt_string("cluster_limit_conn_log_level"),
     NJT_HTTP_MAIN_CONF | NJT_HTTP_SRV_CONF | NJT_HTTP_LOC_CONF | NJT_CONF_TAKE1,
     njt_conf_set_enum_slot,
     NJT_HTTP_LOC_CONF_OFFSET,
     offsetof(njt_http_cluster_limit_conn_conf_t, log_level),
     &njt_http_cluster_limit_conn_log_levels},

    {njt_string("cluster_limit_conn_status"),
     NJT_HTTP_MAIN_CONF | NJT_HTTP_SRV_CONF | NJT_HTTP_LOC_CONF | NJT_CONF_TAKE1,
     njt_conf_set_num_slot,
     NJT_HTTP_LOC_CONF_OFFSET,
     offsetof(njt_http_cluster_limit_conn_conf_t, status_code),
     &njt_http_cluster_limit_conn_status_bounds},

    {njt_string("cluster_limit_conn_dry_run"),
     NJT_HTTP_MAIN_CONF | NJT_HTTP_SRV_CONF | NJT_HTTP_LOC_CONF | NJT_CONF_FLAG,
     njt_conf_set_flag_slot,
     NJT_HTTP_LOC_CONF_OFFSET,
     offsetof(njt_http_cluster_limit_conn_conf_t, dry_run),
     NULL},

    njt_null_command};

static njt_http_module_t njt_http_cluster_limit_conn_module_ctx = {
    njt_http_cluster_limit_conn_add_variables, /* preconfiguration */
    njt_http_cluster_limit_conn_init,          /* postconfiguration */

    njt_http_cluster_limit_conn_create_main_conf, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    njt_http_cluster_limit_conn_create_conf, /* create location configuration */
    njt_http_cluster_limit_conn_merge_conf   /* merge location configuration */
};

static njt_int_t cluster_limit_conn_init_first_worker(njt_cycle_t *cycle);
njt_module_t njt_http_cluster_limit_conn_module = {
    NJT_MODULE_V1,
    &njt_http_cluster_limit_conn_module_ctx, /* module context */
    njt_http_cluster_limit_conn_commands,    /* module directives */
    NJT_HTTP_MODULE,                         /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    cluster_limit_conn_init_first_worker,    /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NJT_MODULE_V1_PADDING};


njt_http_cluster_limit_conn_ctx_t *njt_http_cluster_limit_conn_get_ctx_by_zone(njt_str_t *zone){
	njt_http_cluster_limit_conn_ctx_t	**zone_ctxes = NULL;
	njt_uint_t                          i;


	zone_ctxes = clconn_ctxes->elts;
	for(i = 0; i < clconn_ctxes->nelts; i++){
		if(zone_ctxes[i] == NULL){
			continue;
		}
		if(zone_ctxes[i]->zone_name.len == zone->len && njt_strncmp(zone_ctxes[i]->zone_name.data, zone->data, zone->len) == 0){
			return zone_ctxes[i];
		}
	}
	
	return NULL;
}


static void njt_http_cluster_limit_conn_sync(njt_event_t *ev)
{
	njt_http_cluster_limit_conn_ctx_t		**zone_ctxes = NULL;
	njt_uint_t                              i;

	// njt_cluster_limit_conn_ctx_t* ctx=(njt_cluster_limit_conn_ctx_t*) ev->data;
	if (!ev->timedout)  return;

	if ( !njt_exiting) {
		njt_add_timer(ev, SYNC_INT);	
		njt_str_t target = njt_string("all");
		njt_str_t target_pid = njt_string("0");
		// cluster_limit_conn_sync_data(ctx, &target, &target_pid, APP_STICKY_SYNC_INT);

		zone_ctxes = clconn_ctxes->elts;
		for(i = 0; i < clconn_ctxes->nelts; i++){
			if(zone_ctxes[i] == NULL){
				njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0," cluster_limit_conn_sync index[%d] is null", i);
				continue;
			}
		
            njt_http_udp_send_handler(zone_ctxes[i], &zone_ctxes[i]->zone_name, &target, &target_pid);
		}
	}
}


static void njt_cluster_limit_conn_update_conn(njt_str_t key_in, int other_conn, njt_http_cluster_limit_conn_ctx_t *ctx, njt_str_t sibling_node)
{
    size_t                              n, i;
    njt_rbtree_node_t                   *node;
    njt_http_cluster_limit_conn_node_t  *lc;
    njt_http_limit_sibling_t            *v;
    njt_uint_t                          hash;

    // if (ctx->shpool == NULL)
    // {
    //     //important: dont need init ,http_limit_connection has init it
    //     ctx->shpool = (njt_slab_pool_t *)ctx->shm_zone->shm.addr;
    //     ctx->sh = ctx->shpool->data;
    // }
    hash = njt_crc32_short(key_in.data, key_in.len);
    njt_shmtx_lock(&ctx->shpool->mutex);
    node = njt_http_cluster_limit_conn_lookup(&ctx->sh->rbtree, &key_in, hash);
    if (node == NULL)
    {
        // njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
        //     " cluster_limit_conn need create new tree node, receive:%d,%V",
        //     other_conn, &sibling_node);

        n = offsetof(njt_rbtree_node_t, color) + offsetof(njt_http_cluster_limit_conn_node_t, data) + key_in.len;
        node = njt_slab_alloc_locked(ctx->shpool, n);
        if (node == NULL)
        {
            //todo:
            njt_shmtx_unlock(&ctx->shpool->mutex);
            return;
        }
        lc = (njt_http_cluster_limit_conn_node_t *)&node->color;

        for (i = 0; i < SIBLING_MAX; i++)
        {
            lc->sibling[i].sibling_item.len = 0;
        }

        v = &lc->sibling[0];
        v->sibling_item.conn = other_conn;
        v->sibling_item.len = sibling_node.len;
        v->last_changed = njt_current_msec + NODE_VALID_TIMEOUT; //this node valid until timeout
        njt_memcpy(v->sibling_item.data, sibling_node.data, sibling_node.len);
        lc->snap = NULL;

        node->key = hash;
        lc->len = (u_char)key_in.len;
        lc->conn = 0;

        njt_memcpy(lc->data, key_in.data, key_in.len);
        njt_rbtree_insert(&ctx->sh->rbtree, node);
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " cluster_limit_conn new node:%d", lc->conn);
        njt_shmtx_unlock(&ctx->shpool->mutex);
    }
    else
    {
        lc = (njt_http_cluster_limit_conn_node_t *)&node->color;

        for (i = 0; i < SIBLING_MAX; i++)
        {
            v = &lc->sibling[i];
            if (v->sibling_item.len == 0)
            {
                v->sibling_item.conn = other_conn;
                v->sibling_item.len = sibling_node.len;
                v->last_changed = njt_current_msec + NODE_VALID_TIMEOUT; //this node valid until timeout
                memcpy(v->sibling_item.data, sibling_node.data, sibling_node.len);
                njt_shmtx_unlock(&ctx->shpool->mutex);
                return;
            }
            else
            {
                if (sibling_node.len == v->sibling_item.len && njt_memcmp(v->sibling_item.data, sibling_node.data, sibling_node.len) == 0)
                {
                    //found ,so update;
                    v->sibling_item.conn = other_conn;
                    v->last_changed = njt_current_msec + NODE_VALID_TIMEOUT; //this node valid until timeout
                    njt_shmtx_unlock(&ctx->shpool->mutex);
                    return;
                }
            }
        }

        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
            " cluster_limit_conn overflow in array, found:%d, receive:%d,%V",
            lc->conn, other_conn, &sibling_node);
    }
}


static int njt_cluster_limit_conn_recv_data(const char* msg, void* data)
{
    njt_http_cluster_limit_conn_ctx_t               *ctx;
    const char                      *r = msg;
    uint32_t                        current_conn, len, arr_cnt;
    njt_str_t                       key, key_in, zone_val;
    njt_str_t                       sibling_node;

    uint32_t size = mp_decode_map(&r);
    if (size != 3)
    {
        //todo
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
            " cluster_limit_conn udp decode failed, maybe not for us", size);
        return NJT_ERROR;
    }

    key.data = (u_char *)mp_decode_str(&r, &len);
    key.len = len;
    if (njt_memcmp(key.data, "node", key.len) != 0)
    {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
            " cluster_limit_conn key is not nodeid:%V", &key);
        return NJT_ERROR;
    }

    sibling_node.data = (u_char *)mp_decode_bin(&r, &len);
    sibling_node.len = len;

    key.data = (u_char *)mp_decode_str(&r, &len);
    key.len = len;
    if (njt_memcmp(key.data, "zone", key.len) != 0)
    {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " cluster_limit_conn key is not zone:%V", &key);
        return NJT_ERROR;
    }

    zone_val.data = (u_char *)mp_decode_bin(&r, &len);
    zone_val.len = len;

    //get ctx by zone
    ctx = njt_http_cluster_limit_conn_get_ctx_by_zone(&zone_val);
    if(ctx == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " cluster_limit_conn not found ctx by zone:%V", &zone_val);
        return NJT_ERROR;
    }

    if (sibling_node.len == ctx->node_name->len 
        && njt_memcmp(sibling_node.data, ctx->node_name->data, sibling_node.len) == 0)
    {
        //todo: from own, so drop it
        return NJT_ERROR;
    }

    arr_cnt = mp_decode_array(&r);
    for (size = 0; size < arr_cnt; size++)
    {
        mp_decode_map(&r);
        key.data = (u_char *)mp_decode_str(&r, &len);
        key.len = len;
        if (key.len != 3 || njt_memcmp(key.data, "idx", key.len) != 0)
        {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " cluster_limit_conn not idx:%V", &key);
            return NJT_ERROR;
        }

        key_in.data = (u_char *)mp_decode_bin(&r, &len);
        key_in.len = len;

        key.data = (u_char *)mp_decode_str(&r, &len);
        key.len = len;
        if (key.len != 3 || njt_memcmp(key.data, "now", key.len) != 0)
        {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " cluster_limit_conn not now:%V", &key);
            return NJT_ERROR;
        }

        current_conn = mp_decode_uint(&r);
        njt_cluster_limit_conn_update_conn(key_in, current_conn, ctx, sibling_node);
    }

	return NJT_OK;
}


static int  njt_cluster_limit_conn_on_node_on(njt_str_t* node, njt_str_t* node_pid, void* data)
{
    //nothing todo

	return NJT_OK;
}


static njt_int_t cluster_limit_conn_init_first_worker(njt_cycle_t *cycle)
{
    njt_http_conf_ctx_t                 *conf_ctx;
    // njt_http_cluster_limit_conn_ctx_t   *ctx;
    // njt_http_cluster_limit_conn_conf_t  *lccf;
    // njt_shm_zone_t                      **zones, *zone;

    //return when there is no http configuraton
    if (njt_http_cluster_limit_conn_module.ctx_index == NJT_CONF_UNSET_UINT)
    {
        return NJT_OK;
    }
    conf_ctx = (njt_http_conf_ctx_t *)njt_get_conf(cycle->conf_ctx, njt_http_module);
    // lccf = conf_ctx->loc_conf[njt_http_cluster_limit_conn_module.ctx_index];
    if (njt_process == NJT_PROCESS_HELPER)
    {
        return NJT_OK;
    }

    // zones = lccf->limit_zones.elts;
    // for (i = 0; i < lccf->limit_zones.nelts; i++)
    // {
    //     zone = (njt_shm_zone_t *)zones[i];
    //     ctx = (njt_http_cluster_limit_conn_ctx_t *)zone->data;

    //     njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "new udp connection in limit cluster conn");
    //     if (njt_http_limit_udp_connect(ctx) != NJT_OK)
    //     {
    //         return NJT_ERROR;
    //     }

    //     ctx->udp->data = ctx;
    // }

	if(clconn_ctxes == NULL){
		njt_log_error(NJT_LOG_INFO, cycle->log,0," create cluster_limit_conn_ctx array2");
		clconn_ctxes = njt_array_create(cycle->pool, 8, sizeof(njt_http_cluster_limit_conn_ctx_t *));
	}

    njt_log_error(NJT_LOG_INFO, cycle->log,0,"cluster limit conn worker0 start");

    njt_gossip_reg_app_handler(njt_cluster_limit_conn_recv_data, njt_cluster_limit_conn_on_node_on, GOSSIP_APP_CLUSTER_LIMIT_CONN, clconn_ctxes);

	//only the first worker do broadcast job
	if (njt_worker == 0)  {
        njt_event_t *ev = njt_pcalloc(cycle->pool, sizeof(njt_event_t));
        ev->log = &cycle->new_log;
        ev->timer_set =0;
        ev->cancelable = 1;
        ev->handler = njt_http_cluster_limit_conn_sync;
        ev->data = conf_ctx;
        njt_add_timer(ev, SYNC_INT);	
    }

    return NJT_OK;
};


void njt_http_udp_send_handler(njt_http_cluster_limit_conn_ctx_t *ctx, njt_str_t* zone, njt_str_t* target, njt_str_t* target_pid)
{
    njt_array_t                 out_arr;
    njt_uint_t                  idx, i;
    time_t                      now = njt_current_msec;
    sync_queue_t                *client;
    char 					    *buf=NULL, *head=NULL;
    uint32_t 				    msg_cnt = 0;
    size_t 					    buf_size = 0;
    njt_http_cluster_limit_conn_item_t *item;
    char                        *tail, *replace_cnt;

    ctx->pool->log = njt_cycle->log;
    njt_reset_pool(ctx->pool);

    //tips: using array to read out snaps as soon as possible, to omit long lock on shm
    // destroy array cant release mem, so we use a seperate pool, and destroy it late
    njt_array_init(&out_arr, ctx->pool, 100, sizeof(njt_http_cluster_limit_conn_item_t));
    njt_shmtx_lock(&ctx->shpool->mutex);
    client = ctx->sh->clients;

    while (client != NULL)
    {
        if (client == client->next)
        {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
                " cluster_limit_conn client:%p,%p", client, client->next);
            break;
        }
        //todo: can array be over the max elements?
        //tips: only check values changed in last sync_int msecs

        if (now - client->q_item.last_changed >= SYNC_INT)
        {
            client = client->next;
            continue;
        }

        item = njt_array_push(&out_arr);
        //todo: force the key less than 128 bytes
        if (item == NULL)
        {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " cluster_limit_conn push item error");
            njt_shmtx_unlock(&ctx->shpool->mutex);
            return;
        }
        /*
        memcpy(item->data,client->q_item.sibling_item.data,client->q_item.sibling_item.len);
        item->len=client->q_item.sibling_item.len;
        item->conn=client->q_item.sibling_item.conn;
        */

        //tips: optimize, use direct struct copy instead of multi value assignment
        memcpy(item, &client->q_item.sibling_item, sizeof(njt_http_cluster_limit_conn_item_t));

        client->q_item.last_changed = njt_current_msec;
        client = client->next;
    }
    njt_shmtx_unlock(&ctx->shpool->mutex);

    //TODO: count every key byte to send more keys in one package instead of using hard code value 5
    item = (njt_http_cluster_limit_conn_item_t *)out_arr.elts;
    for (idx = 0; idx < out_arr.nelts; )
    {
		if (head == NULL ) {
			buf = njt_gossip_app_get_msg_buf(GOSSIP_APP_CLUSTER_LIMIT_CONN, *target, *target_pid, &buf_size);
			if (buf_size <=0 || buf == NULL) {
				njt_log_error(NJT_LOG_ERR,njt_cycle->log,0," cluster_limit_conn apply buffer failed");
    			njt_shmtx_unlock(&ctx->shpool->mutex);
				return;
			}

            head = buf;
		} 

/*  encode format
 *  { "node": node,
 *    "zone": zone,
 *    [ {"idx": key, "now": conn }
 *
 *    ]
 *  }
 * */
        tail = buf;
        tail = mp_encode_map(tail, 3);

        tail = mp_encode_str(tail, "node", 4);
        tail = mp_encode_bin(tail, (const char *)ctx->node_name->data, ctx->node_name->len);

        tail = mp_encode_str(tail, "zone", 4);
        tail = mp_encode_bin(tail, (const char *)zone->data, zone->len);

        replace_cnt = tail;
        tail = mp_encode_array(tail, 1);

        msg_cnt = 0;
        for(i = 0; i < 15; i++){
            msg_cnt++;
            tail = mp_encode_map(tail, 2);
            tail = mp_encode_str(tail, "idx", 3);
            if(item->len > 255){
                tail = mp_encode_bin(tail, (const char *)item->data, 255);
            }else{
                tail = mp_encode_bin(tail, (const char *)item->data, item->len);
            }

            tail = mp_encode_str(tail, "now", 3);
            tail = mp_encode_uint(tail, item->conn);

            // njt_str_t tmp_str;
            // tmp_str.data = item->data;
            // tmp_str.len = item->len;

            item++;
            idx++;

            buf_size  = buf_size - (tail - buf);

            if (i == 14 || buf_size < 255 + 3 + 3 + 10 || idx == out_arr.nelts) {
			    njt_gossip_app_close_msg_buf(tail);
			//if (msg_cnt>=10) {
				mp_encode_array(replace_cnt, msg_cnt);
				njt_gossip_send_app_msg_buf();
				msg_cnt= 0;
				head=NULL;

                break;
            }
        }

        if(idx == out_arr.nelts){
            break;
        }
    }

    njt_shmtx_unlock(&ctx->shpool->mutex);
	if (head != NULL) {
		njt_gossip_app_close_msg_buf(tail);
	}
	if (msg_cnt > 0) {
		mp_encode_array(replace_cnt, msg_cnt);
		njt_gossip_send_app_msg_buf();
	}

    return;
}

//end
static njt_int_t
njt_http_cluster_limit_conn_handler(njt_http_request_t *r)
{
    size_t n;
    uint32_t hash;
    njt_str_t key;
    njt_uint_t i, idx;
    njt_rbtree_node_t *node;
    njt_pool_cleanup_t *cln;
    njt_http_cluster_limit_conn_ctx_t *ctx;
    njt_http_cluster_limit_conn_node_t *lc;
    njt_http_cluster_limit_conn_conf_t *lccf;
    njt_http_cluster_limit_conn_limit_t *limits;
    njt_http_cluster_limit_conn_cleanup_t *lccln;
    sync_queue_t *client;
    njt_msec_t now = njt_current_msec;

    if (r->main->limit_conn_status)
    {
        return NJT_DECLINED;
    }

    lccf = njt_http_get_module_loc_conf(r, njt_http_cluster_limit_conn_module);
    if(lccf == NULL){
        return NJT_DECLINED;
    }
    limits = lccf->limits.elts;

    for (i = 0; i < lccf->limits.nelts; i++)
    {
        ctx = limits[i].shm_zone->data;

        if (njt_http_complex_value(r, &ctx->key, &key) != NJT_OK)
        {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (key.len == 0)
        {
            continue;
        }

        if (key.len > 255)
        {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "the value of the \"%V\" key "
                          "is more than 255 bytes: \"%V\"",
                          &ctx->key.value, &key);
            continue;
        }

        r->main->limit_conn_status = NJT_HTTP_CLUSTER_LIMIT_CONN_PASSED;

        hash = njt_crc32_short(key.data, key.len);

        njt_shmtx_lock(&ctx->shpool->mutex);

        node = njt_http_cluster_limit_conn_lookup(&ctx->sh->rbtree, &key, hash);

        if (node == NULL)
        {

            n = offsetof(njt_rbtree_node_t, color) + offsetof(njt_http_cluster_limit_conn_node_t, data) + key.len;

            node = njt_slab_alloc_locked(ctx->shpool, n);

            if (node == NULL)
            {
                njt_shmtx_unlock(&ctx->shpool->mutex);
                njt_http_cluster_limit_conn_cleanup_all(r->pool);

                if (lccf->dry_run)
                {
                    r->main->limit_conn_status =
                        NJT_HTTP_CLUSTER_LIMIT_CONN_REJECTED_DRY_RUN;
                    return NJT_DECLINED;
                }

                r->main->limit_conn_status = NJT_HTTP_CLUSTER_LIMIT_CONN_REJECTED;

                return lccf->status_code;
            }

            lc = (njt_http_cluster_limit_conn_node_t *)&node->color;
            for (idx = 0; idx < SIBLING_MAX; idx++)
            {
                lc->sibling[idx].sibling_item.len = 0;
            }
            client = njt_slab_alloc_locked(ctx->shpool, sizeof(sync_queue_t));
            njt_memcpy(client->q_item.sibling_item.data, key.data, key.len);
            client->q_item.sibling_item.len = key.len;
            client->q_item.sibling_item.conn = 1;
            client->q_item.last_changed = now;
            client->prev = NULL;
            client->next = NULL;

            if (ctx->sh->clients == NULL)
            {
                ctx->sh->clients = client;
            }
            else
            {
                //njt_log_error(NJT_LOG_INFO, r->connection->log, 0,"prepend snap:%p,next:%p,%p,clients:%p",client,client->next,client->prev,ctx->sh->clients);
                ctx->sh->clients->prev = client;
                client->next = ctx->sh->clients;
                ctx->sh->clients = client;
            }

            lc->snap = client;
            //njt_log_error(NJT_LOG_INFO, r->connection->log, 0,"create snap:%p,next:%p,%p,clients after:%p",client,client->next,client->prev,ctx->sh->clients);

            node->key = hash;
            lc->len = (u_char)key.len;
            lc->conn = 1;
            njt_memcpy(lc->data, key.data, key.len);

            njt_rbtree_insert(&ctx->sh->rbtree, node);
            //by stdanley
            //broad curent conn value
            //njt_http_cluster_limit_conn_udp_broad(ctx,key,1,"inc");
            //end
        }
        else
        {
            njt_uint_t cluster_conn;
            njt_http_limit_sibling_t *v;

            //tips:
            //sum lc->conn & all sibling value
            lc = (njt_http_cluster_limit_conn_node_t *)&node->color;
            cluster_conn = lc->conn;
            for (idx = 0; idx < SIBLING_MAX; idx++)
            {
                v = &lc->sibling[idx];
                //tips: last_changed means valid until, set by udp sync process
                if (v->sibling_item.len > 0 && v->last_changed > now)
                    cluster_conn += v->sibling_item.conn;
                else
                    break;
            }

            if (cluster_conn >= limits[i].conn)
            {

                njt_shmtx_unlock(&ctx->shpool->mutex);

                njt_log_error(lccf->log_level, r->connection->log, 0,
                              "limiting connections%s by zone \"%V\"",
                              lccf->dry_run ? ", dry run," : "",
                              &limits[i].shm_zone->shm.name);

                njt_http_cluster_limit_conn_cleanup_all(r->pool);

                if (lccf->dry_run)
                {
                    r->main->limit_conn_status =
                        NJT_HTTP_CLUSTER_LIMIT_CONN_REJECTED_DRY_RUN;
                    return NJT_DECLINED;
                }

                r->main->limit_conn_status = NJT_HTTP_CLUSTER_LIMIT_CONN_REJECTED;

                return lccf->status_code;
            }

            lc->conn++;
            if (lc->snap == NULL)
            {
                //if sync create this node firstly, snap is null, so we must check and create it here
                client = njt_slab_alloc_locked(ctx->shpool, sizeof(sync_queue_t));
                njt_memcpy(client->q_item.sibling_item.data, key.data, key.len);
                client->q_item.sibling_item.len = key.len;
                client->q_item.sibling_item.conn = lc->conn;
                client->q_item.last_changed = now;

                client->prev = NULL;
                if (ctx->sh->clients == NULL)
                {
                    ctx->sh->clients = client;
                    client->next = NULL;
                }
                else
                {
                    ctx->sh->clients->prev = client;
                    client->next = ctx->sh->clients;
                    ctx->sh->clients = client;
                }
                lc->snap = client;
                // njt_log_error(NJT_LOG_DEBUG, r->connection->log, 0, " cluster_limit_conn init snap:%p,next:%p,%p", client, client->next, client->prev);
            
                // njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                //           " cluster_limit_conn snap is null, key:%V conn:%d last_changed:%M",
                //           &key, lc->conn, now);
            }
            else
            {
                // njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                //           " cluster_limit_conn snap is not null, key:%V conn:%d last_changed:%M",
                        //   &key, lc->conn, now);
                lc->snap->q_item.sibling_item.conn = lc->conn;
                lc->snap->q_item.last_changed = now;
            }
        }

        // njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
        //                "limit conn: %08Xi %d", node->key, lc->conn);

        njt_shmtx_unlock(&ctx->shpool->mutex);

        cln = njt_pool_cleanup_add(r->pool,
                                   sizeof(njt_http_cluster_limit_conn_cleanup_t));
        if (cln == NULL)
        {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        cln->handler = njt_http_cluster_limit_conn_cleanup;
        lccln = cln->data;

        lccln->shm_zone = limits[i].shm_zone;
        lccln->node = node;
        // njt_log_error(NJT_LOG_DEBUG, r->connection->log, 0, 
        //     " cluster_limit_conn set node to cleanup:%p,%p", node, &node->color);
        lccln->key.data = njt_pstrdup(r->pool, &key);
        lccln->key.len = key.len;
    }

    return NJT_DECLINED;
}

static void
njt_http_cluster_limit_conn_rbtree_insert_value(njt_rbtree_node_t *temp,
                                                njt_rbtree_node_t *node, njt_rbtree_node_t *sentinel)
{
    njt_rbtree_node_t **p;
    njt_http_cluster_limit_conn_node_t *lcn, *lcnt;

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

            lcn = (njt_http_cluster_limit_conn_node_t *)&node->color;
            lcnt = (njt_http_cluster_limit_conn_node_t *)&temp->color;

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
njt_http_cluster_limit_conn_lookup(njt_rbtree_t *rbtree, njt_str_t *key, uint32_t hash)
{
    njt_int_t rc;
    njt_rbtree_node_t *node, *sentinel;
    njt_http_cluster_limit_conn_node_t *lcn;

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

        /* hash == node->key */

        lcn = (njt_http_cluster_limit_conn_node_t *)&node->color;

        rc = njt_memn2cmp(key->data, lcn->data, key->len, (size_t)lcn->len);

        if (rc == 0)
        {
            return node;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}

static void
njt_http_cluster_limit_conn_cleanup(void *data)
{
    njt_http_cluster_limit_conn_cleanup_t *lccln = data;
    njt_rbtree_node_t *node;
    njt_http_cluster_limit_conn_ctx_t *ctx;
    njt_http_cluster_limit_conn_node_t *lc;

    ctx = lccln->shm_zone->data;
    node = lccln->node;

    lc = (njt_http_cluster_limit_conn_node_t *)&node->color;

    njt_shmtx_lock(&ctx->shpool->mutex);

    lc->conn--;
    lc->snap->q_item.sibling_item.conn = lc->conn;
    lc->snap->q_item.last_changed = njt_current_msec;

    if (lc->conn == 0)
    {
        //tips: free node ,and the snap related
        //todo: maybe this state cant be sent to other site, because we delete it;
        sync_queue_t *client = lc->snap;
        if (client != NULL)
        {
            /*
		if (client->prev ==NULL) {//client is head	
			if (client->next !=NULL) client->next->prev=NULL;
			ctx->sh->clients=client->next;
		} else if (client->next ==NULL){ //tail
			client->prev->next=NULL;	
		} else {
			client->prev->next=client->next;	
			client->next->prev=client->prev;	
		}
            	njt_log_error(NJT_LOG_ERR, lccln->shm_zone->shm.log, 0,"remove snap:%p,next:%p,%p,clients:%p",client,client->next,client->prev,ctx->sh->clients);
		*/
            if (client->prev != NULL)
            {
                client->prev->next = client->next;
            }
            else
            {
                ctx->sh->clients = client->next;
            }
            if (client->next != NULL)
            {
                client->next->prev = client->prev;
            }

            njt_slab_free_locked(ctx->shpool, client);
        }

        njt_rbtree_delete(&ctx->sh->rbtree, node);
        njt_slab_free_locked(ctx->shpool, node);
    }

    njt_shmtx_unlock(&ctx->shpool->mutex);
}

static njt_inline void
njt_http_cluster_limit_conn_cleanup_all(njt_pool_t *pool)
{
    njt_pool_cleanup_t *cln;

    cln = pool->cleanup;

    while (cln && cln->handler == njt_http_cluster_limit_conn_cleanup)
    {
        njt_http_cluster_limit_conn_cleanup(cln->data);
        cln = cln->next;
    }

    pool->cleanup = cln;
}

static njt_int_t
njt_http_cluster_limit_conn_init_zone(njt_shm_zone_t *shm_zone, void *data)
{
    njt_http_cluster_limit_conn_ctx_t *octx = data;

    size_t len;
    njt_http_cluster_limit_conn_ctx_t *ctx;

    ctx = shm_zone->data;

    if (octx)
    {
        if (ctx->key.value.len != octx->key.value.len || njt_strncmp(ctx->key.value.data, octx->key.value.data,
                                                                     ctx->key.value.len) != 0)
        {
            njt_log_error(NJT_LOG_EMERG, shm_zone->shm.log, 0,
                          "limit_conn_zone \"%V\" uses the \"%V\" key "
                          "while previously it used the \"%V\" key",
                          &shm_zone->shm.name, &ctx->key.value,
                          &octx->key.value);
            return NJT_ERROR;
        }

        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;

        return NJT_OK;
    }

    ctx->shpool = (njt_slab_pool_t *)shm_zone->shm.addr;

    if (shm_zone->shm.exists)
    {
        ctx->sh = ctx->shpool->data;

        return NJT_OK;
    }

    ctx->sh = njt_slab_alloc(ctx->shpool, sizeof(njt_http_cluster_limit_conn_shctx_t));
    if (ctx->sh == NULL)
    {
        return NJT_ERROR;
    }

    ctx->shpool->data = ctx->sh;

    njt_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    njt_http_cluster_limit_conn_rbtree_insert_value);

    len = sizeof(" in limit_conn_zone \"\"") + shm_zone->shm.name.len;

    ctx->shpool->log_ctx = njt_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL)
    {
        return NJT_ERROR;
    }

    njt_sprintf(ctx->shpool->log_ctx, " in limit_conn_zone \"%V\"%Z",
                &shm_zone->shm.name);

    return NJT_OK;
}

static njt_int_t
njt_http_cluster_limit_conn_status_variable(njt_http_request_t *r,
                                            njt_http_variable_value_t *v, uintptr_t data)
{
    if (r->main->limit_conn_status == 0)
    {
        v->not_found = 1;
        return NJT_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = njt_http_cluster_limit_conn_status[r->main->limit_conn_status - 1].len;
    v->data = njt_http_cluster_limit_conn_status[r->main->limit_conn_status - 1].data;

    return NJT_OK;
}

static void *
njt_http_cluster_limit_conn_create_main_conf(njt_conf_t *cf)
{
    njt_http_cluster_limit_conn_main_conf_t *conf;
    conf = njt_pcalloc(cf->pool, sizeof(njt_http_cluster_limit_conn_main_conf_t));

    if (conf == NULL)
    {
        return NULL;
    }

    clconn_ctxes = NULL;
    return conf;
}


static void *
njt_http_cluster_limit_conn_create_conf(njt_conf_t *cf)
{
    njt_http_cluster_limit_conn_conf_t *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_cluster_limit_conn_conf_t));

    if (conf == NULL)
    {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     conf->limits.elts = NULL;
     */

    conf->log_level = NJT_CONF_UNSET_UINT;
    conf->status_code = NJT_CONF_UNSET_UINT;
    conf->dry_run = NJT_CONF_UNSET;

    return conf;
}

static char *
njt_http_cluster_limit_conn_merge_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_cluster_limit_conn_conf_t *prev = parent;
    njt_http_cluster_limit_conn_conf_t *conf = child;

    if (conf->limits.elts == NULL)
    {
        conf->limits = prev->limits;
    }

    njt_conf_merge_uint_value(conf->log_level, prev->log_level, NJT_LOG_NOTICE);
    njt_conf_merge_uint_value(conf->status_code, prev->status_code,
                              NJT_HTTP_SERVICE_UNAVAILABLE);

    njt_conf_merge_value(conf->dry_run, prev->dry_run, 0);

    return NJT_CONF_OK;
}


static char *
njt_http_cluster_limit_conn(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_cluster_limit_conn_limit_t *limit, *limits;
    njt_int_t                           n = 0;
    u_char                              *p;
    ssize_t                             size;
    njt_str_t                           *value, shm_name, s;
    njt_uint_t                          i;
    njt_shm_zone_t                      *shm_zone, **zones, **zone;
    njt_http_cluster_limit_conn_ctx_t   *ctx;
    njt_http_cluster_limit_conn_ctx_t   **zone_ctx;
    njt_http_cluster_limit_conn_conf_t  *lccf;
    njt_http_compile_complex_value_t    ccv;
    njt_mqconf_conf_t 			        *mqconf;

    value = cf->args->elts;
    lccf = (njt_http_cluster_limit_conn_conf_t *)conf;
    if(lccf == NULL){
        njt_conf_log_error(NJT_LOG_INFO, cf, 0, " lccf is null");
        return NJT_CONF_ERROR;
    }

    ctx = njt_pcalloc(cf->pool, sizeof(njt_http_cluster_limit_conn_ctx_t));

    if (ctx == NULL)
    {
        return NJT_CONF_ERROR;
    }

	mqconf = (njt_mqconf_conf_t*)njt_get_conf(cf->cycle->conf_ctx,njt_mqconf_module);
	if (!mqconf || !mqconf->cluster_name.data || !mqconf->node_name.data)
	{
		njt_conf_log_error(NJT_LOG_INFO, cf, 0, "no mqconf module or not set cluster_name or node_name");
        return NJT_CONF_ERROR;
	} 

    njt_memzero(ctx, sizeof(njt_http_cluster_limit_conn_ctx_t));

    ctx->node_name = &mqconf->node_name;
    ctx->log = &cf->cycle->new_log;

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &ctx->key;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK)
    {
        return NJT_CONF_ERROR;
    }

    size = 0;
    shm_name.len = 0;

    for (i = 2; i < cf->args->nelts; i++)
    {
        if (njt_strncmp(value[i].data, "zone=", 5) == 0)
        {
            shm_name.data = value[i].data + 5;
            p = (u_char *)njt_strchr(shm_name.data, ':');
            if (p == NULL)
            {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            shm_name.len = p - shm_name.data;
            s.data = p + 1;
            s.len = value[i].data + value[i].len - s.data;
            size = njt_parse_size(&s);

            if (size == NJT_ERROR)
            {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            if (size < (ssize_t)(8 * njt_pagesize))
            {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "zone \"%V\" is too small", &value[i]);
                return NJT_CONF_ERROR;
            }

            continue;
        }else if (njt_strncmp(value[i].data, "conn=", 5) == 0)
        {
            n = njt_atoi(value[i].data + 5, value[i].len - 5);
            if (n <= 0)
            {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                "invalid number of connections \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            if (n > 65535)
            {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                "connection limit must be less 65536");
                return NJT_CONF_ERROR;
            }

            continue;
        }
    }

    if (shm_name.len == 0)
    {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return NJT_CONF_ERROR;
    }

    if(n < 1){
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "conn must set and must > 0",
                           &cmd->name);
        return NJT_CONF_ERROR;    
    }

    shm_zone = njt_shared_memory_add(cf, &shm_name, size,
                                     &njt_http_cluster_limit_conn_module);
    if (shm_zone == NULL)
    {
        return NJT_CONF_ERROR;
    }

    if (shm_zone->data)
    {
        ctx = shm_zone->data;

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "%V \"%V\" is already bound to key \"%V\"",
                           &cmd->name, &shm_name, &ctx->key.value);
        return NJT_CONF_ERROR;
    }

	ctx->zone_name.data = njt_pnalloc(cf->pool, shm_name.len);
    if(ctx->zone_name.data == NULL){
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "zone[%V] alloc fail",
                           &shm_name);
        return NJT_CONF_ERROR;   
    }
	njt_memcpy(ctx->zone_name.data, shm_name.data, shm_name.len);
	ctx->zone_name.len = shm_name.len;

    shm_zone->init = njt_http_cluster_limit_conn_init_zone;
    shm_zone->data = ctx;

    //tips: store ctx in limit_zones
    //
    zones = lccf->limit_zones.elts;
    if (zones == NULL)
    {
        if (njt_array_init(&lccf->limit_zones, cf->pool, 1,
                           sizeof(njt_shm_zone_t **)) != NJT_OK)
        {
            return NJT_CONF_ERROR;
        }
    }

    zone = njt_array_push(&lccf->limit_zones);
    if (zone == NULL)
    {
        return NJT_CONF_ERROR;
    }
    *zone = shm_zone;

    ctx->pool = njt_create_pool(1024 * 2048, cf->log);
    if (ctx->pool == NULL)
    {
        return NJT_CONF_ERROR;
    }

    limits = lccf->limits.elts;

    if (limits == NULL)
    {
        if (njt_array_init(&lccf->limits, cf->pool, 1,
                           sizeof(njt_http_cluster_limit_conn_limit_t)) != NJT_OK)
        {
            return NJT_CONF_ERROR;
        }
    }

    for (i = 0; i < lccf->limits.nelts; i++)
    {
        if (shm_zone == limits[i].shm_zone)
        {
            return "is duplicate";
        }
    }

    limit = njt_array_push(&lccf->limits);
    if (limit == NULL)
    {
        return NJT_CONF_ERROR;
    }
    njt_memzero(limit, sizeof(njt_http_cluster_limit_conn_limit_t));

    limit->conn = n;
    limit->shm_zone = shm_zone;

	if(clconn_ctxes == NULL){
		clconn_ctxes = njt_array_create(cf->pool, 8, sizeof(njt_http_cluster_limit_conn_ctx_t *));
        if(clconn_ctxes == NULL){
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "clconn_ctxes array alloc fail");
            return NJT_CONF_ERROR;
        }
	}

    zone_ctx = njt_array_push(clconn_ctxes);
    if(zone_ctx == NULL){
        njt_conf_log_error(NJT_LOG_ERR, cf,0," app cluster_limit_conn array push error");
        return NJT_CONF_ERROR;
    }

    *zone_ctx = ctx;

    njt_conf_log_error(NJT_LOG_INFO, cf, 0,
        " push cluster_limit_conn ctx:%p  clconn_ctxes count:%d zone_name:%V", 
        ctx, clconn_ctxes->nelts, &(*zone_ctx)->zone_name);

    return NJT_CONF_OK;
}

static njt_int_t
njt_http_cluster_limit_conn_add_variables(njt_conf_t *cf)
{
    njt_http_variable_t *var, *v;

    for (v = njt_http_cluster_limit_conn_vars; v->name.len; v++)
    {
        var = njt_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL)
        {
            return NJT_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NJT_OK;
}

static njt_int_t
njt_http_cluster_limit_conn_init(njt_conf_t *cf)
{
    njt_http_handler_pt *h;
    njt_http_core_main_conf_t *cmcf;

    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);
    if(cmcf == NULL){
        return NJT_OK;
    }

    h = njt_array_push(&cmcf->phases[NJT_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL)
    {
        return NJT_ERROR;
    }

    *h = njt_http_cluster_limit_conn_handler;

    return NJT_OK;
}
