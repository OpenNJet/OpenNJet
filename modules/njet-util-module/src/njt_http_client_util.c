/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_core.h>
#include <njt_http.h>
#include <njt_http_client_util.h>


#define NJT_HTTP_CLIENT_UTIL_PARSE_INIT           0
#define NJT_HTTP_CLIENT_UTIL_PARSE_STATUS_LINE    1
#define NJT_HTTP_CLIENT_UTIL_PARSE_HEADER         2
#define NJT_HTTP_CLIENT_UTIL_PARSE_BODY           4

#define NJT_HTTP_CLIENT_UTIL_MAX_QUERT_PARAM_LEN 2048

static njt_int_t
njt_http_client_util_parse_header_line(njt_http_client_util_t *client_util);


static njt_int_t
njt_http_client_util_process_headers(njt_http_client_util_t *client_util);

static njt_int_t
njt_http_client_util_parse_status_line(njt_http_client_util_t *client_util);

static njt_int_t
njt_http_client_util_process_body(njt_http_client_util_t *client_util);


static njt_int_t
njt_http_client_util_http_write_handler(njt_event_t *wev);

static njt_int_t
njt_http_client_util_http_read_handler(njt_event_t *rev);

static void njt_http_client_util_read_handler(njt_event_t *rev);
static void njt_http_client_util_write_handler(njt_event_t *wev);

static void
njt_http_client_util_dummy_handler(njt_event_t *ev);

static void
njt_http_client_util_close_connection(njt_connection_t *c);

static njt_uint_t 
njt_http_client_util_prepare_search_param(njt_http_client_util_t *client_util, njt_str_t *query_params);

#if (NJT_HTTP_SSL)
static njt_int_t
njt_http_client_util_ssl_handshake(njt_connection_t *c,
            njt_http_client_util_t *client_util
            );

static void njt_http_client_util_ssl_handshake_handler(njt_connection_t *c);
static njt_int_t njt_http_client_util_ssl_init_connection(njt_connection_t *c,
        njt_http_client_util_t *client_util);
#endif



njt_http_client_util_t *njt_http_client_util_create(NJT_HTTP_CLIENT_UTIL_METHOD method,
    njt_str_t url, njt_str_t post_data, void *custom_data){
    njt_pool_t                      *pool;
    njt_peer_connection_t           *peer;
    njt_http_client_util_t          *client_util;
    njt_url_t                       u;
    njt_conf_t                      cf;
    njt_pool_cleanup_t              *cln;
    size_t                          add;
    u_short                         port;


    if(NJT_HTTP_CLIENT_UTIL_METHOD_PUT == method || NJT_HTTP_CLIENT_UTIL_METHOD_POST == method){
        if(post_data.len < 1){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "http_client_util post or put method need have post_data");
            return NULL;
        }
    }

    pool = njt_create_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
    if (pool == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "http_client_util create pool error");
        return NULL;
    }

    client_util = njt_pcalloc(pool, sizeof(njt_http_client_util_t));
    if (client_util == NULL) {
        /*log the malloc failure*/
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "http_client_util create client util malloc error");
        njt_destroy_pool(pool);
        return NULL;
    }

    client_util->pool = pool;
    client_util->method = method;

    if(NJT_HTTP_CLIENT_UTIL_METHOD_PUT == method || NJT_HTTP_CLIENT_UTIL_METHOD_POST == method){
        client_util->post_data.data = njt_palloc(pool, post_data.len);
        if(client_util->post_data.data == NULL){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "http_client_util post data malloc error");
            njt_destroy_pool(pool);
            return NULL;  
        }

        njt_memcpy(client_util->post_data.data, post_data.data, post_data.len);
        client_util->post_data.len = post_data.len;
    }

    peer = njt_pcalloc(pool, sizeof(njt_peer_connection_t));
    if (peer == NULL) {
        /*log the malloc failure*/
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "http_client_util peer malloc error");
        njt_destroy_pool(pool);
        return NULL;
    }

    client_util->peer = peer;
    client_util->data = custom_data;

    peer->sockaddr = njt_pcalloc(pool, sizeof(struct sockaddr));
    if (peer->sockaddr == NULL) {
        /*log the malloc failure*/
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "http_client_util peer sockaddr malloc error");
        njt_destroy_pool(pool);
        return NULL;
    }

    njt_memzero(&u, sizeof(njt_url_t));

    if (njt_strncasecmp(url.data, (u_char *) "http://", 7) == 0) {
        add = 7;
        port = 80;

    } else if (njt_strncasecmp(url.data, (u_char *) "https://", 8) == 0) {
#if (NJT_HTTP_SSL)
        client_util->ssl.ssl_enable = 1;
        add = 8;
        port = 443;
#else
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "http_client_util https protocol requires SSL support");
        njt_destroy_pool(pool);
        return NULL;
#endif
    } else {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "http_client_util invalid url prefix");
        njt_destroy_pool(pool);
        return NULL;
    }

    u.url.len = url.len - add;
    u.url.data = url.data + add;
    
    u.default_port = port;
    u.uri_part = 1;
    u.no_resolve = 1;

    if (njt_parse_url(pool, &u) != NJT_OK) {
        if (u.err) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                               "%s in \"%V\" of parse http util url",
                               u.err, &u.url);
        }

        njt_destroy_pool(pool);
        return NULL;
    }

    client_util->metadata.host.data = njt_pcalloc(pool, u.host.len);
    if(client_util->metadata.host.data == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "http_client_util host data malloc error, host:%V", &u.host);
        njt_destroy_pool(pool);
    }
    njt_memcpy(client_util->metadata.host.data, u.host.data, u.host.len);
    client_util->metadata.host.len = u.host.len;

    client_util->metadata.uri.data = njt_pcalloc(pool, u.uri.len);
    if(client_util->metadata.uri.data == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "http_client_util uri data malloc error, uri:%V", &u.uri);
        njt_destroy_pool(pool);
    }
    njt_memcpy(client_util->metadata.uri.data, u.uri.data, u.uri.len);
    client_util->metadata.uri.len = u.uri.len;

    peer->sockaddr = u.addrs[0].sockaddr;
    peer->socklen = u.addrs[0].socklen;
    //set port
    njt_inet_set_port(peer->sockaddr, u.port);
    
    peer->name = &u.addrs[0].name;
    peer->get = njt_event_get_peer;
    peer->log = njt_cycle->log;
    peer->log_error = NJT_ERROR_ERR;

    if(NJT_OK != njt_array_init(&client_util->metadata.additinal_send_header, client_util->pool, 4,
                        sizeof(njt_http_client_header_param_t))){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "http_client_util header array init error");
        njt_destroy_pool(pool);
        return NULL;
    }

    if(NJT_OK != njt_array_init(&client_util->metadata.query_params, client_util->pool, 4,
                        sizeof(njt_http_client_header_param_t))){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "http_client_util query array init error");
        njt_destroy_pool(pool);
        return NULL;
    }

#if (NJT_OPENSSL)
    if(client_util->ssl.ssl_enable){
        njt_str_set(&client_util->ssl.ssl_ciphers, "DEFAULT");
        client_util->ssl.ssl_protocols = (NJT_CONF_BITMASK_SET | NJT_SSL_TLSv1 | NJT_SSL_TLSv1_1 | NJT_SSL_TLSv1_2);
        client_util->ssl.ssl = njt_pcalloc(client_util->pool, sizeof(njt_ssl_t));
        if(client_util->ssl.ssl == NULL){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                            "http_client_util ssl malloc error");
            njt_destroy_pool(pool);
            return NULL;
        }
        client_util->ssl.ssl->log = njt_cycle->log;
        if (njt_ssl_create(client_util->ssl.ssl, client_util->ssl.ssl_protocols, NULL)
            != NJT_OK)
        {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                            "http_client_util ssl create error");
            njt_destroy_pool(pool);
            return NULL;
        }

        cf.pool = client_util->pool;
        cf.log = njt_cycle->log;
        cf.cycle = (njt_cycle_t *)njt_cycle;
        cln = njt_pool_cleanup_add(cf.pool, 0);
        if (cln == NULL) {
            njt_ssl_cleanup_ctx(client_util->ssl.ssl);
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                            "http_client_util ssl create error");
            njt_destroy_pool(pool);
            return NULL;
        }

        cln->handler = njt_ssl_cleanup_ctx;
        cln->data = client_util->ssl.ssl;
        if (njt_ssl_ciphers(&cf, client_util->ssl.ssl, &client_util->ssl.ssl_ciphers, 0)
            != NJT_OK)
        {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                            "http_client_util ssl ciphers error");
            njt_destroy_pool(pool);
            return NULL;
        }
    }
#endif

    njt_sub_pool(njt_cycle->pool, pool);

    return client_util;
}


njt_int_t njt_http_client_util_add_header(njt_http_client_util_t *client_util,
    njt_str_t key, njt_str_t value){
    njt_http_client_header_param_t *head_info;
    
    if(client_util == NULL || client_util->peer == NULL || client_util->pool == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "please create client util first");

        return NJT_ERROR;
    }

    if(key.len < 1 || value.len < 1){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "http_client_util header key and value should not be null");
        return NJT_ERROR;
    }

    head_info = njt_array_push(&client_util->metadata.additinal_send_header);
    if(head_info == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "http_client_util header array push error");
        return NJT_ERROR;
    }

    head_info->key.len = key.len;
    head_info->key.data = njt_pcalloc(client_util->pool, key.len);
    if(head_info->key.data == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "http_client_util header data malloc error");
        return NJT_ERROR;
    }

    head_info->value.data = njt_pcalloc(client_util->pool, value.len);
    if(head_info->value.data == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "http_client_util header data malloc error");
        return NJT_ERROR;
    }


    njt_memcpy(head_info->key.data, key.data, key.len);
    njt_memcpy(head_info->value.data, value.data, value.len);

    head_info->key.len = key.len;
    head_info->value.len = value.len;

    return NJT_OK;
}


njt_int_t njt_http_client_util_add_query_param(njt_http_client_util_t *client_util,
    njt_str_t key, njt_str_t value){
    njt_http_client_header_param_t *param_info;
    
    if(client_util == NULL || client_util->peer == NULL || client_util->pool == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "please create client util first");

        return NJT_ERROR;
    }

    if(key.len < 1 || value.len < 1){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "http_client_util param key and value should not be null");
        return NJT_ERROR;
    }

    param_info = njt_array_push(&client_util->metadata.query_params);
    if(param_info == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "http_client_util header array push error");
        return NJT_ERROR;
    }

    param_info->key.len = key.len;
    param_info->key.data = njt_pcalloc(client_util->pool, key.len);
    if(param_info->key.data == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "http_client_util header data malloc error");
        return NJT_ERROR;
    }

    param_info->value.data = njt_pcalloc(client_util->pool, value.len);
    if(param_info->value.data == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "http_client_util header data malloc error");
        return NJT_ERROR;
    }

    njt_memcpy(param_info->key.data, key.data, key.len);
    njt_memcpy(param_info->value.data, value.data, value.len);

    param_info->key.len = key.len;
    param_info->value.len = value.len;

    return NJT_OK;
}


njt_int_t njt_http_client_util_start(njt_http_client_util_t *client_util){
    njt_int_t                       rc;

    if(client_util == NULL || client_util->peer == NULL || client_util->pool == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "please create client util first");

        return NJT_ERROR;
    }

	//connect
    rc = njt_event_connect_peer(client_util->peer);

    if (rc == NJT_ERROR || rc == NJT_DECLINED || rc == NJT_BUSY) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "http client util connect to peer of %V errror.", &client_util->peer->name);
        njt_destroy_pool(client_util->pool);
        return NJT_ERROR;
    }

    client_util->peer->connection->data = client_util;
    client_util->peer->connection->pool = client_util->pool;


    if(client_util->start_success_handler){
        client_util->start_success_handler(client_util->data);
    }

#if (NJT_HTTP_SSL)
    if (client_util->ssl.ssl_enable && client_util->ssl.ssl->ctx && client_util->peer->connection->ssl == NULL) {
        rc = njt_http_client_util_ssl_init_connection(client_util->peer->connection, client_util);
        if (rc == NJT_ERROR) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " http client util ssl init error");

            njt_destroy_pool(client_util->pool);
            return NJT_ERROR;
        }
        return NJT_OK;
    }
#endif


    client_util->peer->connection->write->handler = njt_http_client_util_write_handler;
    client_util->peer->connection->read->handler = njt_http_client_util_read_handler;

    if(rc == NJT_AGAIN){
        njt_add_timer(client_util->peer->connection->write, 20000);
        return NJT_OK;
    }

    njt_http_client_util_write_handler(client_util->peer->connection->write);

    return NJT_OK;
}


static void
njt_http_client_util_dummy_handler(njt_event_t *ev) {
    njt_log_debug0(NJT_LOG_DEBUG_EVENT, ev->log, 0,
                   "http client util dummy handler");
}


static njt_uint_t 
njt_http_client_util_prepare_search_param(njt_http_client_util_t *client_util, njt_str_t *query_params){
    njt_uint_t                      i;
    njt_http_client_header_param_t  *query_param;
    u_char                          temp_buf[NJT_HTTP_CLIENT_UTIL_MAX_QUERT_PARAM_LEN];
    u_char                          *last = temp_buf;
    size_t                          empty_size = NJT_HTTP_CLIENT_UTIL_MAX_QUERT_PARAM_LEN;
    size_t                          used_size = 0;
    size_t                          tmp_size;

    last = njt_snprintf(temp_buf, empty_size, "GET %V", &client_util->metadata.uri);
    used_size = last - temp_buf;
    empty_size -= used_size;

    query_param = client_util->metadata.query_params.elts;
    for(i = 0; i < client_util->metadata.query_params.nelts; i++){
        tmp_size = query_param[i].key.len + query_param[i].value.len + 2;
        if(tmp_size > empty_size){
            njt_log_error(NJT_LOG_WARN, njt_cycle->log, 0, "http client util request query param too long");
            break;
        }

        if(i == 0){
            last = njt_snprintf(last, empty_size,
                "?%V=%V", &query_param[i].key, &query_param[i].value);
        }else{
            last = njt_snprintf(last, empty_size,
                "&%V=%V", &query_param[i].key, &query_param[i].value);
        }

        used_size += tmp_size;
        empty_size -= tmp_size;
    }    

    query_params->data = njt_pcalloc(client_util->pool, used_size);
    if(query_params->data == NULL){
        njt_log_error(NJT_LOG_WARN, njt_cycle->log, 0, "http client util request query param malloc error");
        return NJT_ERROR;
    }

    njt_memcpy(query_params->data, temp_buf, used_size);
    query_params->len = used_size;


    njt_log_error(NJT_LOG_WARN, njt_cycle->log, 0, "========query_params:%V", query_params);

    return NJT_OK;
}


static njt_int_t
njt_http_client_util_http_write_handler(njt_event_t *wev) {
    njt_connection_t                        *c;
    njt_http_client_util_t                  *client_util;
    ssize_t                                 n, size;
    njt_uint_t                              i;
    njt_http_client_header_param_t          *addtional_header;
    njt_str_t                               search_param;
    njt_flag_t                              has_query_param = 0;


    c = wev->data;
    client_util = c->data;

    if (client_util->metadata.send_buf == NULL) {
        client_util->metadata.send_buf = njt_create_temp_buf(client_util->pool, njt_pagesize);
        if (client_util->metadata.send_buf == NULL) {
            /*log the send buf allocation failure*/
            njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                           "malloc failure of the send buffer");
            return NJT_ERROR;
        }

        switch (client_util->method)
        {
        case NJT_HTTP_CLIENT_UTIL_METHOD_GET:
            if(client_util->metadata.query_params.nelts > 0){
                has_query_param = 1;
                if(NJT_OK != njt_http_client_util_prepare_search_param(client_util, &search_param)){
                    return NJT_ERROR;
                }
            }else{
                njt_str_set(&search_param, "GET");
            }
            
            break;
        case NJT_HTTP_CLIENT_UTIL_METHOD_PUT:
            njt_str_set(&search_param, "PUT ");
            break;
        case NJT_HTTP_CLIENT_UTIL_METHOD_POST:
            njt_str_set(&search_param, "POST");
            break;
        default:
            njt_str_set(&search_param, "GET");
            break;
        }

        if(has_query_param){
            client_util->metadata.send_buf->last = njt_snprintf(client_util->metadata.send_buf->last,
                                                client_util->metadata.send_buf->end - client_util->metadata.send_buf->last, "%V HTTP/1.1" CRLF,
                                                &search_param);
        }else{
            client_util->metadata.send_buf->last = njt_snprintf(client_util->metadata.send_buf->last,
                                                client_util->metadata.send_buf->end - client_util->metadata.send_buf->last, "%V %V HTTP/1.1" CRLF,
                                                &search_param, &client_util->metadata.uri);
        }
        client_util->metadata.send_buf->last = njt_snprintf(client_util->metadata.send_buf->last,
                                               client_util->metadata.send_buf->end - client_util->metadata.send_buf->last,
                                               "Connection: close" CRLF);
        client_util->metadata.send_buf->last = njt_snprintf(client_util->metadata.send_buf->last,
                                               client_util->metadata.send_buf->end - client_util->metadata.send_buf->last, "Host: %V" CRLF,
                                               &client_util->metadata.host);

        client_util->metadata.send_buf->last = njt_snprintf(client_util->metadata.send_buf->last,
                                               client_util->metadata.send_buf->end - client_util->metadata.send_buf->last,
                                               "User-Agent: njet" CRLF);

        if(NJT_HTTP_CLIENT_UTIL_METHOD_PUT == client_util->method || NJT_HTTP_CLIENT_UTIL_METHOD_POST == client_util->method){ 
            // client_util->metadata.send_buf->last = njt_snprintf(client_util->metadata.send_buf->last,
            //                                     client_util->metadata.send_buf->end - client_util->metadata.send_buf->last,
            //                                     "Content-Type: application/json" CRLF);
            // client_util->metadata.send_buf->last = njt_snprintf(client_util->metadata.send_buf->last,
            //                                     client_util->metadata.send_buf->end - client_util->metadata.send_buf->last,
            //                                     "Accept: application/json" CRLF);
            client_util->metadata.send_buf->last = njt_snprintf(client_util->metadata.send_buf->last,
                                               client_util->metadata.send_buf->end - client_util->metadata.send_buf->last,
                                               "Content-Length: %d" CRLF, client_util->post_data.len);
        }


        addtional_header = client_util->metadata.additinal_send_header.elts;
        for(i = 0; i < client_util->metadata.additinal_send_header.nelts; i++){
            client_util->metadata.send_buf->last = njt_snprintf(client_util->metadata.send_buf->last,
                                        client_util->metadata.send_buf->end - client_util->metadata.send_buf->last,
                                        "%V: %V" CRLF, &addtional_header[i].key, &addtional_header[i].value);
        }

        client_util->metadata.send_buf->last = njt_snprintf(client_util->metadata.send_buf->last,
                                       client_util->metadata.send_buf->end - client_util->metadata.send_buf->last, CRLF);

        if(NJT_HTTP_CLIENT_UTIL_METHOD_PUT == client_util->method || NJT_HTTP_CLIENT_UTIL_METHOD_POST == client_util->method){
            client_util->metadata.send_buf->last = njt_snprintf(client_util->metadata.send_buf->last,
                                        client_util->metadata.send_buf->end - client_util->metadata.send_buf->last,
                                        "%V", &client_util->post_data);
        }
    }

    size = client_util->metadata.send_buf->last - client_util->metadata.send_buf->pos;

    n = c->send(c, client_util->metadata.send_buf->pos,
                size);
    if (n == NJT_ERROR) {
        return NJT_ERROR;
    }

    if (n > 0) {
        client_util->metadata.send_buf->pos += n;
        if (n == size) {
            wev->handler = njt_http_client_util_dummy_handler;

            if (njt_handle_write_event(wev, 0) != NJT_OK) {
                /*LOG the failure*/
                njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                               "http client util write event handle error");
                return NJT_ERROR;
            }

            njt_log_error(NJT_LOG_INFO, c->log, 0, "http client util request send.");
            return NJT_DONE;
        }
    }

    return NJT_AGAIN;
}



static void njt_http_client_util_write_handler(njt_event_t *wev) {
    njt_connection_t                        *c;
    njt_http_client_util_t                  *client_util;
    njt_int_t                               rc;
    
    c = wev->data;
    client_util = c->data;

    if (wev->timedout) {
        // njt_del_timer(wev);
        if (wev->timer_set) {
            njt_del_timer(wev);
        }

        njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "http client util write action timeout");
		if(client_util->write_timeout_handler){
			client_util->write_timeout_handler(client_util->data);
		}

        njt_http_client_util_close_connection(client_util->peer->connection);

        return;
    }

    if (wev->timer_set) {
        njt_del_timer(wev);
    }

    //handler write data
    rc = njt_http_client_util_http_write_handler(wev);
    if (rc == NJT_ERROR) {

        /*log the case and update the peer status.*/
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                       "http client util write action error");
        if(client_util->write_event_result_handler){
            client_util->write_event_result_handler(client_util->data, rc);
        }

        njt_http_client_util_close_connection(client_util->peer->connection);
        return;
    } else if (rc == NJT_DONE || rc == NJT_OK) {
        if(client_util->write_event_result_handler){
            client_util->write_event_result_handler(client_util->data, rc);
        }

        return;
    } else {
        /*AGAIN*/
    }

    if (!wev->ready){
        if (!wev->timer_set) {
            njt_add_timer(wev, 20000);
        }

        return;
    }else{
        if (njt_handle_write_event(wev, 0)!= NJT_OK)
        {
            njt_http_client_util_close_connection(client_util->peer->connection);
            return;
        }
    }


    return;
}



#if (NJT_HTTP_SSL)
static njt_int_t
njt_http_client_util_ssl_handshake(njt_connection_t *c,
            njt_http_client_util_t *client_util) {
    if (c->ssl->handshaked) {
        client_util->peer->connection->write->handler = njt_http_client_util_write_handler;
        client_util->peer->connection->read->handler = njt_http_client_util_read_handler;

		if(client_util->ssl_handshake_success_handler){
			client_util->ssl_handshake_success_handler(client_util->data);
		}

        /*NJT_AGAIN or NJT_OK*/
        njt_http_client_util_write_handler(client_util->peer->connection->write);
        return NJT_OK;
    }

	if(client_util->ssl_handshake_fail_handler){
		client_util->ssl_handshake_fail_handler(client_util->data);
	}

    if (c->write->timedout) {
        return NJT_ERROR;
    }

    return NJT_ERROR;
}

static void njt_http_client_util_ssl_handshake_handler(njt_connection_t *c){
    njt_http_client_util_t    *client_util;

    client_util = c->data;

    njt_http_client_util_ssl_handshake(c, client_util);
}

static njt_int_t njt_http_client_util_ssl_init_connection(njt_connection_t *c,
        njt_http_client_util_t *client_util) {
    njt_int_t rc;

    // if (njt_http_client_util_test_connect(c) != NJT_OK) {
    //     return NJT_ERROR;
    // }
    if (njt_ssl_create_connection(client_util->ssl.ssl, c,
                                  NJT_SSL_BUFFER | NJT_SSL_CLIENT) != NJT_OK) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "http client util ssl init create connection ");
        return NJT_ERROR;
    }

    c->sendfile = 0;
    c->log->action = "SSL handshaking to hc";

    rc = njt_ssl_handshake(c);
    if (rc == NJT_AGAIN) {
        if (!c->write->timer_set) {
            njt_add_timer(c->write, 20000);
        }
        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0,
            "set ssl handshake handler");
        c->ssl->handler = njt_http_client_util_ssl_handshake_handler;
        return NJT_OK;
    }

    return njt_http_client_util_ssl_handshake(c, client_util);
}
#endif


static void njt_http_client_util_read_handler(njt_event_t *rev) {
    njt_connection_t                        *c;
    njt_http_client_util_t                  *client_util;
    njt_int_t                               rc;
    njt_http_client_util_parse_t            *hp;


    c = rev->data;
    client_util = c->data;

    if (rev->timedout) {
        if (rev->timer_set) {
            njt_del_timer(rev);
        }
        /*log the case and update the peer status.*/
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "http client util read action timeout");

		if(client_util->read_timeout_handler){
			client_util->read_timeout_handler(client_util->data);
		}

        njt_http_client_util_close_connection(client_util->peer->connection);
        return;
    }

    if (rev->timer_set) {
        njt_del_timer(rev);
    }

    rc = njt_http_client_util_http_read_handler(rev);
    switch (rc)
    {
        case NJT_ERROR:
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "http client util read action error");
        case NJT_DONE:
        case NJT_ABORT:
            if(client_util->read_event_result_handler){
                client_util->read_event_result_handler(client_util->data, rc);
            }

            hp = client_util->metadata.parser;
            switch (hp->stage)
            {
            case NJT_HTTP_CLIENT_UTIL_PARSE_STATUS_LINE:
                if(client_util->parse_line_handler){
                    client_util->parse_line_handler(client_util->data, rc);
                }
                break;
            case NJT_HTTP_CLIENT_UTIL_PARSE_HEADER:
                if(client_util->parse_header_handler){
                    client_util->parse_header_handler(client_util->data, rc);
                }
                break;
            case NJT_HTTP_CLIENT_UTIL_PARSE_BODY:
                if(client_util->parse_body_handler){
                    client_util->parse_body_handler(client_util->data, rc);
                }
            default:
                break;
            }

            njt_http_client_util_close_connection(client_util->peer->connection);
            return;
        default:
            break;
    }

    if (!rev->timer_set) {
        njt_add_timer(rev, 20000);
    }

    return;
}


static njt_int_t
njt_http_client_util_http_read_handler(njt_event_t *rev) {
    njt_connection_t                        *c;
    njt_http_client_util_t    				*client_util;
    ssize_t                                 n, size;
    njt_buf_t                               *b;
    njt_int_t                               rc;
    njt_http_client_util_parse_t            *hp;

    c = rev->data;
    client_util = c->data;

    /*Init the internal parser*/
    if (client_util->metadata.parser == NULL) {
        hp = njt_pcalloc(client_util->pool, sizeof(njt_http_client_util_parse_t));
        if (hp == NULL) {
            /*log*/
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "http client util  memory allocation error");

            return NJT_ERROR;
        }

        hp->stage = NJT_HTTP_CLIENT_UTIL_PARSE_STATUS_LINE;
        hp->process = njt_http_client_util_parse_status_line;

        client_util->metadata.parser = hp;
    }

    for (;;) {
        if (client_util->metadata.recv_buf == NULL) {
            b = njt_create_temp_buf(client_util->pool, njt_pagesize);
            if (b == NULL) {
                /*log*/
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "http client util recv buffer memory allocation error");
                return NJT_ERROR;
            }
            client_util->metadata.recv_buf = b;
        }

        b = client_util->metadata.recv_buf;
        size = b->end - b->last;

        n = c->recv(c, b->last, size);

        if (n > 0) {
            b->last += n;
            hp = client_util->metadata.parser;
            // if(NJT_HTTP_CLIENT_UTIL_PARSE_BODY == hp->stage){
            //     njt_http_client_util_update_download_process(0, client_util, b->last - b->pos);
            //     b->pos = b->last;
            // }
            rc = hp->process(client_util);
            if (rc == NJT_ERROR) {
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "http client util process ret error");
                return NJT_ERROR;
            }

            if (rc == NJT_ABORT) {
                return NJT_ABORT;
            }

            /*link chain buffer*/
            if (b->last == b->end) {
                b->pos = b->start;
                b->last = b->start;
                // b->end = b->last + size;
                hp = client_util->metadata.parser;
                if (hp->stage != NJT_HTTP_CLIENT_UTIL_PARSE_BODY) {
                    /*log. The status and headers are too large to be hold in one buffer*/
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "status and headers exceed one page size");
                    return NJT_ERROR;
                }
            }

            continue;
        }

        if (n == NJT_AGAIN) {
            if (njt_handle_read_event(rev, 0) != NJT_OK) {
                /*log*/
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "http client util read event handle error");
                return NJT_ERROR;
            }
            return NJT_AGAIN;
        }

        if (n == NJT_ERROR) {
            /*log*/
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "http client util read error");
            return NJT_ERROR;
        }

        break;
    }


    hp = client_util->metadata.parser;
    hp->done = 1;
    rc = hp->process(client_util);

    if (rc == NJT_DONE) {
        return NJT_DONE;
    }

    if (rc == NJT_AGAIN) {
        /* the connection is shutdown*/
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "http client util connection is shutdown");
        return NJT_ERROR;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_client_util_parse_header_line(njt_http_client_util_t *client_util) {
    u_char                           c, ch, *p;
    njt_http_client_util_parse_t    *hp;
    njt_buf_t                       *b;

    enum {
        sw_start = 0,
        sw_name,
        sw_space_before_value,
        sw_value,
        sw_space_after_value,
        sw_almost_done,
        sw_header_almost_done
    } state;

    b = client_util->metadata.recv_buf;
    hp = client_util->metadata.parser;
    state = hp->state;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

        switch (state) {

            /* first char */
            case sw_start:

                switch (ch) {
                    case CR:
                        hp->header_end = p;
                        state = sw_header_almost_done;
                        break;
                    case LF:
                        hp->header_end = p;
                        goto header_done;
                    default:
                        state = sw_name;
                        hp->header_name_start = p;

                        c = (u_char) (ch | 0x20);
                        if (c >= 'a' && c <= 'z') {
                            break;
                        }

                        if (ch >= '0' && ch <= '9') {
                            break;
                        }

                        return NJT_ERROR;
                }
                break;

                /* header name */
            case sw_name:
                c = (u_char) (ch | 0x20);
                if (c >= 'a' && c <= 'z') {
                    break;
                }

                if (ch == ':') {
                    hp->header_name_end = p;
                    state = sw_space_before_value;
                    break;
                }

                if (ch == '-') {
                    break;
                }

                if (ch >= '0' && ch <= '9') {
                    break;
                }

                if (ch == CR) {
                    hp->header_name_end = p;
                    hp->header_start = p;
                    hp->header_end = p;
                    state = sw_almost_done;
                    break;
                }

                if (ch == LF) {
                    hp->header_name_end = p;
                    hp->header_start = p;
                    hp->header_end = p;
                    goto done;
                }

                return NJT_ERROR;

                /* space* before header value */
            case sw_space_before_value:
                switch (ch) {
                    case ' ':
                        break;
                    case CR:
                        hp->header_start = p;
                        hp->header_end = p;
                        state = sw_almost_done;
                        break;
                    case LF:
                        hp->header_start = p;
                        hp->header_end = p;
                        goto done;
                    default:
                        hp->header_start = p;
                        state = sw_value;
                        break;
                }
                break;

                /* header value */
            case sw_value:
                switch (ch) {
                    case ' ':
                        hp->header_end = p;
                        state = sw_space_after_value;
                        break;
                    case CR:
                        hp->header_end = p;
                        state = sw_almost_done;
                        break;
                    case LF:
                        hp->header_end = p;
                        goto done;
                }
                break;

                /* space* before end of header line */
            case sw_space_after_value:
                switch (ch) {
                    case ' ':
                        break;
                    case CR:
                        state = sw_almost_done;
                        break;
                    case LF:
                        goto done;
                    default:
                        state = sw_value;
                        break;
                }
                break;

                /* end of header line */
            case sw_almost_done:
                switch (ch) {
                    case LF:
                        goto done;
                    default:
                        return NJT_ERROR;
                }

                /* end of header */
            case sw_header_almost_done:
                switch (ch) {
                    case LF:
                        goto header_done;
                    default:
                        return NJT_ERROR;
                }
        }
    }

    b->pos = p;
    hp->state = state;

    return NJT_AGAIN;

    done:

    b->pos = p + 1;
    hp->state = sw_start;

    return NJT_OK;

    header_done:

    b->pos = p + 1;
    hp->state = sw_start;
    hp->body_start = b->pos;

    return NJT_DONE;
}


static njt_int_t
njt_http_client_util_process_headers(njt_http_client_util_t *client_util) {
    njt_int_t                       rc;
    njt_table_elt_t                 *h;
    njt_http_client_util_parse_t    *hp;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0, "http client util process header.");

    hp = client_util->metadata.parser;

    if (hp->headers.size == 0) {
        rc = njt_array_init(&hp->headers, client_util->pool, 4,
                            sizeof(njt_table_elt_t));
        if (rc != NJT_OK) {
            return NJT_ERROR;
        }
    }

    for (;;) {
        rc = njt_http_client_util_parse_header_line(client_util);
        if (rc == NJT_OK) {
            h = njt_array_push(&hp->headers);
            if (h == NULL) {
                return NJT_ERROR;
            }

            njt_memzero(h, sizeof(njt_table_elt_t));
            h->hash = 1;
            h->key.data = hp->header_name_start;
            h->key.len = hp->header_name_end - hp->header_name_start;

            h->value.data = hp->header_start;
            h->value.len = hp->header_end - hp->header_start;

            njt_log_debug4(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                           "http header \"%*s: %*s\"",
                           h->key.len, h->key.data, h->value.len,
                           h->value.data);

            if (h->key.len == njt_strlen("Transfer-Encoding")
                && h->value.len == njt_strlen("chunked")
                && njt_strncasecmp(h->key.data, (u_char *) "Transfer-Encoding",
                                   h->key.len) == 0
                && njt_strncasecmp(h->value.data, (u_char *) "chunked",
                                   h->value.len) == 0) {
                hp->chunked = 1;
            }

            if (h->key.len == njt_strlen("Content-Length")
                && njt_strncasecmp(h->key.data, (u_char *) "Content-Length",
                                   h->key.len) == 0) {
                hp->content_length_n = njt_atoof(h->value.data, h->value.len);

                if (hp->content_length_n == NJT_ERROR) {

                    njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                                   "http client util invalid fetch content length");
                    return NJT_ERROR;
                }

                //need call parse every header callback
                if(client_util->parse_header_data_handler){
                    client_util->parse_header_data_handler(client_util->data, h);
                }
            }

            continue;
        }

        if (rc == NJT_DONE) {
            break;
        }

        if (rc == NJT_AGAIN) {
            return NJT_AGAIN;
        }

        /*http header parse error*/
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                       "http client util process header error.");
        return NJT_ERROR;
    }

    //need call parse header end callback
    if(client_util->parse_header_handler){
        client_util->parse_header_handler(client_util->data, NJT_OK);
    }

    /*TODO check if the first buffer is used out*/
    hp->stage = NJT_HTTP_CLIENT_UTIL_PARSE_BODY;
    hp->process = njt_http_client_util_process_body;

    return hp->process(client_util);
}


static njt_int_t
njt_http_client_util_process_body(njt_http_client_util_t *client_util) {
    njt_http_client_util_parse_t    *hp;
    njt_buf_t                       *b;

    hp = client_util->metadata.parser;
    b = client_util->metadata.recv_buf;

    //need call parse body data callback
	if(client_util->parse_body_data_handler){
		client_util->parse_body_data_handler(client_util->data, b->pos, b->last);
	}

    b->pos = b->last;

    if (hp->done) {
        return NJT_DONE;
    }
    return NJT_OK;
}


/*We assume the status line and headers are located in one buffer*/
static njt_int_t
njt_http_client_util_parse_status_line(njt_http_client_util_t *client_util) {
    u_char ch;
    u_char *p;
    njt_http_client_util_parse_t *hp;
    njt_buf_t *b;

    enum {
        sw_start = 0,
        sw_H,
        sw_HT,
        sw_HTT,
        sw_HTTP,
        sw_first_major_digit,
        sw_major_digit,
        sw_first_minor_digit,
        sw_minor_digit,
        sw_status,
        sw_space_after_status,
        sw_status_text,
        sw_almost_done
    } state;

    hp = client_util->metadata.parser;
    b = client_util->metadata.recv_buf;
    state = hp->state;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

        switch (state) {

            /* "HTTP/" */
            case sw_start:
                switch (ch) {
                    case 'H':
                        state = sw_H;
                        break;
                    default:
                        return NJT_ERROR;
                }
                break;

            case sw_H:
                switch (ch) {
                    case 'T':
                        state = sw_HT;
                        break;
                    default:
                        return NJT_ERROR;
                }
                break;

            case sw_HT:
                switch (ch) {
                    case 'T':
                        state = sw_HTT;
                        break;
                    default:
                        return NJT_ERROR;
                }
                break;

            case sw_HTT:
                switch (ch) {
                    case 'P':
                        state = sw_HTTP;
                        break;
                    default:
                        return NJT_ERROR;
                }
                break;

            case sw_HTTP:
                switch (ch) {
                    case '/':
                        state = sw_first_major_digit;
                        break;
                    default:
                        return NJT_ERROR;
                }
                break;

                /* the first digit of major HTTP version */
            case sw_first_major_digit:
                if (ch < '1' || ch > '9') {
                    return NJT_ERROR;
                }

                state = sw_major_digit;
                break;

                /* the major HTTP version or dot */
            case sw_major_digit:
                if (ch == '.') {
                    state = sw_first_minor_digit;
                    break;
                }

                if (ch < '0' || ch > '9') {
                    return NJT_ERROR;
                }

                break;

                /* the first digit of minor HTTP version */
            case sw_first_minor_digit:
                if (ch < '0' || ch > '9') {
                    return NJT_ERROR;
                }

                state = sw_minor_digit;
                break;

                /* the minor HTTP version or the end of the request line */
            case sw_minor_digit:
                if (ch == ' ') {
                    state = sw_status;
                    break;
                }

                if (ch < '0' || ch > '9') {
                    return NJT_ERROR;
                }

                break;

                /* HTTP status code */
            case sw_status:
                if (ch == ' ') {
                    break;
                }

                if (ch < '0' || ch > '9') {
                    return NJT_ERROR;
                }

                hp->code = hp->code * 10 + (ch - '0');

                if (++hp->count == 3) {
                    state = sw_space_after_status;
                    //if not 200, return error
                    if(200 != hp->code){
                        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, 
                            " http client util download return code is not 200, retcode:%d", hp->code);
                        return NJT_ABORT;
                    }
                }

                break;

                /* space or end of line */
            case sw_space_after_status:
                switch (ch) {
                    case ' ':
                        state = sw_status_text;
                        break;
                    case '.':                    /* IIS may send 403.1, 403.2, etc */
                        state = sw_status_text;
                        break;
                    case CR:
                        break;
                    case LF:
                        goto done;
                    default:
                        return NJT_ERROR;
                }
                break;

                /* any text until end of line */
            case sw_status_text:
                switch (ch) {
                    case CR:
                        hp->status_text_end = p;
                        state = sw_almost_done;
                        break;
                    case LF:
                        hp->status_text_end = p;
                        goto done;
                }

                if (hp->status_text == NULL) {
                    hp->status_text = p;
                }

                break;

                /* end of status line */
            case sw_almost_done:
                switch (ch) {
                    case LF:
                        goto done;
                    default:
                        return NJT_ERROR;
                }
        }
    }

    b->pos = p;
    hp->state = state;

    return NJT_AGAIN;

    done:
    b->pos = p + 1;
    hp->state = sw_start;

    /*begin to process headers*/
    //end parse line, need call parse line callback
    if(client_util->parse_line_handler){
        client_util->parse_line_handler(client_util->data, NJT_OK);
    }

    hp->stage = NJT_HTTP_CLIENT_UTIL_PARSE_HEADER;
    hp->process = njt_http_client_util_process_headers;

    return hp->process(client_util);
}


static void
njt_http_client_util_close_connection(njt_connection_t *c)
{
    njt_pool_t  *pool;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "close http connection: %d", c->fd);

#if (NJT_HTTP_SSL)

    if (c->ssl) {
        if (njt_ssl_shutdown(c) == NJT_AGAIN) {
            c->ssl->handler = njt_http_client_util_close_connection;
            return;
        }
    }

#endif

#if (NJT_HTTP_V3)
    if (c->quic) {
        njt_http_v3_reset_stream(c);
    }
#endif

    c->destroyed = 1;

    pool = c->pool;

    njt_close_connection(c);

    njt_destroy_pool(pool);
}