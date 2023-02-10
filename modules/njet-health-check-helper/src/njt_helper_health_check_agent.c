/*************************************************************************************
 Copyright (C), 2021-2023, TMLake(Beijing) Technology Ltd.,
 File name    : njt_helper_health_check_agent.c
 Version      : 1.0
 Author       : ChengXu
 Date         : 2023/2/7/007 
 Description  : 
 Other        :
 History      :
 <author>       <time>          <version >      <desc>
 ChengXu        2023/2/7/007       1.1             
***********************************************************************************/
//
// Created by Administrator on 2023/2/7/007.
//

#include <njt_http_kv_module.h>
#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njet.h>
#include <njt_stream.h>
#include "njt_common_health_check.h"

//static void njt_agent_hc_rest_peer(njt_http_upstream_rr_peer_t *peer){
//
//    peer->hc_checks = 0;
//    peer->hc_last_passed = 1;
//    peer->hc_consecutive_fails = 0;
//    peer->hc_consecutive_passes=0;
//    peer->hc_downstart = 0;
//    peer->hc_upstart = 0;
//    peer->hc_downtime = 0;
//    peer->hc_fails=0;
//    peer->hc_unhealthy=0;
//    peer->hc_down = 0;
//}

static void njt_agent_hc_update_peer( njt_http_upstream_srv_conf_t* huscf,
                                      njt_http_upstream_rr_peer_t *peer,njt_int_t status,
                                     njt_uint_t passes, njt_uint_t fails) {

    peer->hc_check_in_process = 0;
    peer->hc_checks++;
    if (status == NJT_OK || status == NJT_DONE) {

        peer->hc_consecutive_fails = 0;
        peer->hc_last_passed = 1; //zyg

        if (peer->hc_last_passed) {
            peer->hc_consecutive_passes++;
        }

        if (peer->hc_consecutive_passes >= passes) {
            peer->hc_down = (peer->hc_down / 100 * 100);

            if (peer->hc_downstart != 0) {
                peer->hc_upstart = njt_time();
                peer->hc_downtime = peer->hc_downtime + (((njt_uint_t) ((njt_timeofday())->sec) * 1000 +
                                                          (njt_uint_t) ((njt_timeofday())->msec)) - peer->hc_downstart);
            }
            peer->hc_downstart = 0;//(njt_timeofday())->sec;
        }
        if(huscf->mandatory == 1 && huscf->reload != 1 &&  peer->hc_checks == 1) {  //hclcf->plcf->upstream.upstream->reload
            if(peer->down == 0) {
                peer->hc_down = (peer->hc_down/100 * 100);
            }
        }

    } else {

        peer->hc_fails++;
        peer->hc_consecutive_passes = 0;
        peer->hc_consecutive_fails++;


        /*Only change the status at the first time when fails number mets*/
        if (peer->hc_consecutive_fails == fails) {
            peer->hc_unhealthy++;

            peer->hc_down = (peer->hc_down / 100 * 100) + 1;

            peer->hc_downstart = (njt_uint_t) ((njt_timeofday())->sec) * 1000 +
                                 (njt_uint_t) ((njt_timeofday())->msec); //(peer->hc_downstart == 0 ?(njt_current_msec):(peer->hc_downstart));
        }
        peer->hc_last_passed = 0;
        if(huscf->mandatory == 1 && huscf->reload != 1 &&  peer->hc_checks == 1) {
            if(peer->down == 0) {
                peer->hc_down = (peer->hc_down/100 * 100) + 1;
                peer->hc_downstart =  (njt_uint_t)((njt_timeofday())->sec )*1000 + (njt_uint_t)((njt_timeofday())->msec) ; //(peer->hc_downstart == 0 ?(njt_current_msec):(peer->hc_downstart));
            }
        }

    }
    return;
}


static njt_int_t njt_helper_hc_agent_set_http_upstream(njt_cycle_t *cycle){
    njt_http_upstream_main_conf_t  *umcf;
    njt_http_upstream_srv_conf_t   **uscfp;
    njt_helper_upstream_list_t *upstreamLists;
    njt_http_upstream_rr_peer_t     *peer;
    njt_http_upstream_rr_peers_t *peers;
    njt_uint_t i,j,buf_len,upstream_size;
    njt_int_t rc;
    u_char *buf,*index;
    njt_str_t msg;
    njt_transmission_str_t *name;
    njt_pool_t *pool = NULL;
    njt_helper_upstream_peers_t hu_peers,*hu_peers_h;
    njt_helper_rr_peer_info_t *peer_info;

    pool = njt_create_dynamic_pool(NJT_MIN_POOL_SIZE, cycle->log);
    if (pool == NULL) {
        return NJT_ERROR;
    }

    umcf = njt_http_cycle_get_module_main_conf(cycle, njt_http_upstream_module);
    njt_str_t key = njt_string(HTTP_UPSTREAM_KEYS);
    if(umcf == NULL){
        njt_helper_upstream_list_t upstreams;
        upstreams.len = 0;
        msg.len = sizeof(njt_helper_upstream_list_t);
        msg.data = (void*)&upstreams;
        rc = njt_db_kv_set(&key, &msg);
        if(rc != NJT_OK){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "upstream list set key error");
            goto err;
        }
    }
    uscfp = umcf->upstreams.elts;
    buf_len = sizeof(njt_helper_upstream_list_t);
    upstream_size = 0;
    for (i = 0; i < umcf->upstreams.nelts; i++) {
        if(uscfp[i]->shm_zone == NULL){
            continue;
        }
        buf_len += sizeof(njt_transmission_str_t);
        buf_len += uscfp[i]->host.len;
        ++upstream_size;
    }
    buf = njt_pcalloc(pool,buf_len);
    if (buf == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "alloc upstream list error");
        goto err;
    }
    msg.data = buf;
    msg.len = buf_len;
    upstreamLists = (void*)buf;
    upstreamLists->len =  upstream_size;
    name = (void*) (msg.data + sizeof(njt_helper_upstream_list_t));
    index = msg.data + sizeof(njt_helper_upstream_list_t)+ sizeof(njt_transmission_str_t)*upstream_size;
    for (i = 0; i < umcf->upstreams.nelts; i++) {
        if(uscfp[i]->shm_zone == NULL){
            continue;
        }
        name[i].len = uscfp[i]->host.len;
        name[i].data = index - msg.data;
        njt_memcpy(index,uscfp[i]->host.data,uscfp[i]->host.len);
        index += uscfp[i]->host.len;
    }
    rc = njt_db_kv_set(&key, &msg);
    if(rc != NJT_OK){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "upstream list set key error");
        goto err;
    }
    njt_str_t key_pre = njt_string(UPSTREAM_NAME_PREFIX);
    for (i = 0; i < umcf->upstreams.nelts; i++) {
        if(uscfp[i]->shm_zone == NULL){
            continue;
        }
        njt_memzero(&msg, sizeof(njt_str_t));
        njt_str_concat(pool,key,key_pre,uscfp[i]->host,njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "alloc upstream list error");goto err);
        peers =  uscfp[i]->peer.data;
        peer = peers->peer;
        buf_len = sizeof (njt_helper_upstream_peers_t);
        njt_memset(&hu_peers,0,sizeof (njt_helper_upstream_peers_t));
        while (peer != NULL){
            buf_len += sizeof (njt_helper_rr_peer_info_t);
            buf_len += peer->name.len;
            ++hu_peers.len;
            peer = peer->next;
        }
        if(peers->next != NULL){
            peer = peers->next->peer; //backup
            while (peer != NULL){
                buf_len += sizeof (njt_helper_rr_peer_info_t);
                buf_len += peer->name.len;
                ++hu_peers.back_len;
                peer = peer->next;
            }
        }

        buf = njt_pcalloc(pool,buf_len);
        if (buf == NULL){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "alloc upstream list error");
            goto err;
        }
        hu_peers_h = (void*)buf;
        msg.data = buf;
        msg.len = buf_len;
        *hu_peers_h = hu_peers;
        index =  msg.data + sizeof (njt_helper_upstream_peers_t);
        peer_info = (void*)index;
        index += hu_peers.len * sizeof(njt_helper_rr_peer_info_t);
        j =0;
        peer = peers->peer;
        while (peer != NULL){
            njt_memcpy(&peer_info[i].sockaddr,peer->sockaddr, sizeof(struct sockaddr));
            peer_info[i].socklen = peer->socklen;
            peer_info[i].peer_id = peer->id;
            peer_info[i].name.len = peer->name.len;
            peer_info[i].down = peer->down;
            njt_memcpy(index,peer->name.data,peer->name.len);
            peer_info[i].name.data = index - msg.data;
            index += peer->name.len;
            peer = peer->next;
            ++j;
        }
        hu_peers_h->back_offset = index - msg.data;
        peer_info = (void*)index;
        index += hu_peers.back_len * sizeof(njt_helper_rr_peer_info_t);
        j =0;
        if(peers->next != NULL) {
            peer = peers->next->peer; //backup
            while (peer != NULL) {
                njt_memcpy(&peer_info[i].sockaddr,peer->sockaddr,sizeof(struct sockaddr));
                peer_info[i].socklen = peer->socklen;
                peer_info[i].peer_id = peer->id;
                peer_info[i].name.len = peer->name.len;
                peer_info[i].down = peer->down;
                njt_memcpy(index, peer->name.data, peer->name.len);
                peer_info[i].name.data = index - msg.data;
                index += peer->name.len;
                peer = peer->next;
            }
        }
        rc = njt_db_kv_set(&key, &msg);
    }
    if(pool != NULL){
        njt_destroy_pool(pool);
    }
    return NJT_OK;

err:
    if(pool != NULL){
        njt_destroy_pool(pool);
    }
    return NJT_ERROR;
}

static njt_http_upstream_rr_peer_t * njt_find_http_upstream_peer_by_id(njt_http_upstream_rr_peer_t *peer,njt_uint_t peer_id){
    for(;peer != NULL;peer = peer->next){
        if(peer->id == peer_id){
            return peer;
        }
    }
    return NULL;
}


static int njt_helper_kv_change_handler(njt_str_t *key, njt_str_t *value, void *data){
    njt_cycle_t *cycle;
    njt_str_t name;
    njt_helper_upstream_peer_update_t *update;
    njt_http_upstream_srv_conf_t* huscf;
    njt_http_upstream_rr_peers_t *peers;
    njt_http_upstream_rr_peer_t *peer;

    cycle = (njt_cycle_t *)njt_cycle;
    update = (void*)value->data;
    update->len = value->len - sizeof(njt_helper_upstream_peer_update_t) + 1;
    name.data = &update->data;
    name.len = update->len;
    if(update->type == NJT_HC_HTTP_TYPE){
        huscf = njt_http_find_upstream_by_name(cycle,&name);
        if(huscf == NULL ){
            njt_log_error(NJT_LOG_EMERG, cycle->log, 0, "health check agent not find http upstream :%V ",&name);
            return NJT_OK;
        }

        peers = huscf->peer.data;
        if(peers == NULL){
            njt_log_error(NJT_LOG_EMERG, cycle->log, 0, "health check agent not find http upstream peer ");
            return NJT_OK;
        }
        peer = njt_find_http_upstream_peer_by_id(peers->peer,update->peer_id);
        if(peer == NULL){
            if(peers->next == NULL ){
                njt_log_error(NJT_LOG_EMERG, cycle->log, 0, "health check agent not find http upstream peer ");
                return NJT_OK;
            }
            peer = njt_find_http_upstream_peer_by_id(peers->next->peer,update->peer_id);
            if(peer == NULL) {
                njt_log_error(NJT_LOG_EMERG, cycle->log, 0, "health check agent not find http upstream peer ");
                return NJT_OK;
            }
        }
        njt_http_upstream_rr_peers_wlock(peers);
        njt_agent_hc_update_peer(huscf,peer,update->status, update->passes, update->fails);
        njt_http_upstream_rr_peers_unlock(peers);
    }
    return NJT_OK;
}



static njt_int_t njt_helper_hc_agent_init_process(njt_cycle_t *cycle){
    njt_int_t rc;


    if ((njt_process != NJT_PROCESS_WORKER && njt_process != NJT_PROCESS_SINGLE) || njt_worker != 0) {
        /*only works in the worker 0 prcess.*/
        return NJT_OK;
    }

    rc = njt_helper_hc_agent_set_http_upstream(cycle);
    if( rc != NJT_OK ){
        return rc;
    }
    njt_str_t topic_key = njt_string("hc");    //注册时， /dyn/loc/... 主题的，只需要提供第二段的关键字  loc
    njt_reg_kv_change_handler(&topic_key, njt_helper_kv_change_handler, NULL);
    return NJT_OK;
}
static njt_int_t
njt_http_health_check_init(njt_conf_t *cf)
{

    njt_uint_t                        i;
    njt_http_upstream_rr_peers_t   *peers;
    njt_http_upstream_rr_peer_t    *peer;
    njt_http_upstream_main_conf_t  *umcf;
    njt_http_upstream_srv_conf_t   *uscf, **uscfp;

    umcf = njt_http_conf_get_module_main_conf(cf, njt_http_upstream_module);
    if(umcf == NULL){
        return NJT_OK;
    }
    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++)
    {
        uscf = uscfp[i];
        if( uscf->persistent == 1 ) {
            uscf->hc_type = 2;  //peers = olduscf->peer.data;
        } else if(uscf->mandatory == 1 ) {
            uscf->hc_type = 1;
            peers = uscf->peer.data;
            if(peers) {
                for (peer = peers->peer; peer;peer = peer->next){
                    peer->hc_down = 2; //checking
                }
            }
        }

    }

    return NJT_OK;
}




/* The module context. */
static njt_http_module_t njt_helper_hc_agent_module_ctx = {
        NULL,
        njt_http_health_check_init,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
};
njt_module_t njt_helper_health_check_agent = {
        NJT_MODULE_V1,
        &njt_helper_hc_agent_module_ctx,      /* module context */
        NULL,                                   /* module directives */
        NJT_HTTP_MODULE,                        /* module type */
        NULL,                                   /* init master */
        NULL,                                   /* init module */
        njt_helper_hc_agent_init_process,        /* init process */
        NULL,                                   /* init thread */
        NULL,                                   /* exit thread */
        NULL,                                   /* exit process */
        NULL,                                   /* exit master */
        NJT_MODULE_V1_PADDING
};