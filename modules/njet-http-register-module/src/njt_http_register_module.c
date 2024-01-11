/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */
// #include <njt_config.h>
// #include <njt_core.h>
// #include <njt_http_kv_module.h>

#include <njt_core.h>
#include <njt_http_kv_module.h>
#include <njt_http.h>
#include <njt_http_sendmsg_module.h>


static void *njt_http_register_module_create_main_conf(njt_conf_t *cf);
// static char *
// njt_http_register_module_init_main_conf(njt_conf_t *cf, void *conf);
static char *njt_http_register(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static njt_int_t njt_http_register_init_process(njt_cycle_t *cycle);
static void njt_http_register_timer_handler(njt_event_t *ev);
static void njt_http_register_check_write_handler(njt_event_t *wev);
static void njt_http_register_check_read_handler(njt_event_t *rev);
static njt_int_t
njt_http_register_http_write_handler(njt_event_t *wev);
static void
njt_http_register_dummy_handler(njt_event_t *ev);
static void
njt_http_register_close_connection(njt_connection_t *c);


static njt_command_t  njt_http_register_commands[] = {

    { njt_string("register"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_ANY,
      njt_http_register,
      0,
      0,
      NULL },

      njt_null_command
};



static njt_http_module_t njt_http_register_module_ctx = {
    NULL, /* preconfiguration */
    NULL,          /* postconfiguration */

    njt_http_register_module_create_main_conf, /* create main configuration */
    // njt_http_register_module_init_main_conf, /* init main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    NULL, /* create location configuration */
    NULL   /* merge location configuration */
};


njt_module_t  njt_http_register_module = {
    NJT_MODULE_V1,
    &njt_http_register_module_ctx,               /* module context */
    njt_http_register_commands,                  /* module directives */
    NJT_HTTP_MODULE,                            /* module type */
    NULL,                                       /* init master */
    NULL,                                       /* init module */
    njt_http_register_init_process,               /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};

typedef struct {
    njt_int_t            enable;
    njt_str_t            server;
    njt_int_t            port;
    njt_str_t            location;
    njt_int_t            interval;          //timer interval
    njt_str_t            register_file;
} njt_http_register_main_conf_t;

typedef struct {
    njt_pool_t                      *pool;
    njt_str_t                       data;
    size_t                          len;
    njt_peer_connection_t           *peer;
    njt_buf_t                       *send_buf;
    // njt_str_t                       url;
    njt_http_register_main_conf_t        *ccf;
} njt_http_register_data_t;


static njt_int_t njt_send_http_register_info(njt_http_register_main_conf_t *ccf, njt_str_t *http_register_info);
static njt_int_t njt_register_read_config(njt_pool_t *pool, njt_http_register_main_conf_t *ccf,
    njt_http_register_data_t *register_data);

static void *
njt_http_register_module_create_main_conf(njt_conf_t *cf)
{
    njt_http_register_main_conf_t  *ccf;

    ccf = njt_pcalloc(cf->pool, sizeof(njt_http_register_main_conf_t));
    if (ccf == NULL) {
        return NULL;
    }

    ccf->enable = NJT_CONF_UNSET;
    ccf->port = 8081;
    ccf->interval = 1000;

    njt_str_set(&ccf->server, "127.0.0.1");
    njt_str_set(&ccf->location, "/adc");
    njt_str_set(&ccf->register_file, "conf/register.json");

    return ccf;
}


static char *
njt_http_register(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_str_t                   *value;
    njt_http_register_main_conf_t     *ccf;
    njt_uint_t                  i;

    ccf = (njt_http_register_main_conf_t *) conf;
    if (ccf->enable != NJT_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        if (njt_strncmp(value[i].data, "server=", 7) == 0) {
            if (value[i].len == 7) {
                goto invalid;
            }

            value[i].data += 7;
            value[i].len -= 7;

            ccf->server.data = njt_pcalloc(cf->pool, value[i].len);
            njt_memcpy(ccf->server.data, value[i].data, value[i].len);
            ccf->server.len = value[i].len;

            continue;
        }

        if (njt_strncmp(value[i].data, "config=", 7) == 0) {
            if (value[i].len == 7) {
                goto invalid;
            }

            value[i].data += 7;
            value[i].len -= 7;

            ccf->register_file.data = njt_pcalloc(cf->pool, value[i].len);
            njt_memcpy(ccf->register_file.data, value[i].data, value[i].len);
            ccf->register_file.len = value[i].len;

            continue;
        }

        if (njt_strncmp(value[i].data, "port=", 5) == 0) {
            if (value[i].len == 5) {
                goto invalid;
            }

            value[i].data += 5;
            value[i].len -= 5;

            ccf->port = njt_atoi(value[i].data, value[i].len);
            if (ccf->port == NJT_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "location=", 9) == 0) {
            if (value[i].len == 9) {
                goto invalid;
            }

            value[i].data += 9;
            value[i].len -= 9;

            ccf->location.data = njt_pcalloc(cf->pool, value[i].len);
            njt_memcpy(ccf->location.data, value[i].data, value[i].len);
            ccf->location.len = value[i].len;

            continue;
        }           
    }

    ccf->enable = 1;

    return NJT_CONF_OK;

invalid:

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\"", &value[i]);

    return NJT_CONF_ERROR;
}


static njt_int_t njt_http_register_init_process(njt_cycle_t *cycle){
    njt_event_t                      *http_register_timer;
    njt_http_register_main_conf_t         *ccf;

    if(njt_process != NJT_PROCESS_HELPER){
        return NJT_OK;
    }

    ccf = (njt_http_register_main_conf_t *)njt_http_cycle_get_module_main_conf(cycle, njt_http_register_module);    
    if(ccf == NULL){
        return NJT_OK;
    }

    //start timer event
    http_register_timer = njt_pcalloc(cycle->pool, sizeof(njt_event_t));
    if(http_register_timer == NULL){
        return NJT_ERROR;
    }

    njt_log_error(NJT_LOG_INFO, cycle->log, 0, "http_register module init");

    http_register_timer->handler = njt_http_register_timer_handler;
    http_register_timer->log = njt_cycle->log;
    http_register_timer->data = ccf;
    http_register_timer->cancelable = 1;

    njt_add_timer(http_register_timer, ccf->interval);


    return NJT_OK;
}


static void njt_http_register_timer_handler(njt_event_t *ev){
    njt_http_register_main_conf_t        *ccf;
    njt_int_t                       rc;
    njt_str_t                       http_register_info_k = njt_string("kv_http___register_info");
    njt_str_t                       http_register_info_v;

    ccf = ev->data;
    //get all http_register_info
    njt_str_set(&http_register_info_v, "");
    rc = njt_dyn_kv_get(&http_register_info_k, &http_register_info_v);
    if (rc != NJT_OK || http_register_info_v.len < 1) {
        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "can't get http_register info from kv store");
        goto next_http_register_timer;
    }

    //send http_register info to adc location
    njt_send_http_register_info(ccf, &http_register_info_v);

    //delete http_register info
    //now just set zero str
    njt_str_set(&http_register_info_v, "");
    rc = njt_dyn_kv_set(&http_register_info_k, &http_register_info_v);
    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " register module set register info error");
        // goto next_http_register_timer;
    }

    return;

next_http_register_timer:
    njt_add_timer(ev, ccf->interval);

    return ;
}

static njt_int_t njt_register_read_config(njt_pool_t *pool, njt_http_register_main_conf_t *ccf,
        njt_http_register_data_t *register_data){
    u_char              *register_info;
    njt_fd_t            fd;
    njt_file_info_t     fi;
    size_t              size;
    ssize_t             n;
    njt_str_t           full_name;


    full_name = ccf->register_file;
    if(njt_conf_full_name((void *)njt_cycle, &full_name, 0) != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
            "register general config fullname error:%V", &ccf->register_file);
        return NJT_ERROR;
    }

    //get register info
    fd = njt_open_file(full_name.data, NJT_FILE_RDONLY, NJT_FILE_OPEN, 0);
    if(fd == NJT_INVALID_FILE) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
            "open file error:%V", &full_name);
        return NJT_ERROR;
    }

    if(njt_fd_info(fd, &fi) == NJT_FILE_ERROR) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
            "get file info error:%V", &full_name);

        goto failed;
    }

    size = njt_file_size(&fi);
    if(size > 4096){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
            "file is too long, more than 4096:%V", &full_name);
        goto failed;
    }

    if(size < 1){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
            "file is too shor, lenss than 1:%V", &full_name);
        goto failed;
    }

    register_info = (u_char *)njt_pcalloc(pool, size);
    if(register_info == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
            "register module malloc register info error, file:%V size:%d", &full_name, size);
        goto failed;
    }

    if(size > 0) {
        n = njt_read_fd(fd, register_info, size);

        if (n == -1) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, 
                "read file error:%V", &full_name);
            goto failed;
        }

        if ((size_t) n != size) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                " has read only %z of %O from %V", n, size, &full_name);
            goto failed;
        }
    }

    register_data->data.data = register_info;
    register_data->data.len = size;

    if (njt_close_file(fd) == NJT_FILE_ERROR) {
        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, 
            "close file error:%V", &full_name);

        return NJT_OK;
    }

    return NJT_OK;

failed:
    if (fd != NJT_INVALID_FILE) {
        if (njt_close_file(fd) == NJT_FILE_ERROR) {
            njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, 
                "close file error:%V", &full_name);
        }
    }

    return NJT_ERROR;
}


static njt_int_t njt_send_http_register_info(njt_http_register_main_conf_t *ccf, njt_str_t *http_register_info){
    njt_int_t                       rc;
    njt_pool_t                      *pool;
    njt_peer_connection_t           *peer;
    njt_http_register_data_t        *data;
    njt_url_t                       u;

    njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, 
        "send http_register info to lua:%V", http_register_info);
    
    //connect to lua server
    pool = njt_create_pool(njt_pagesize, njt_cycle->log);
    if (pool == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "create pool failure for register module.");
        return NJT_ERROR;
    }

    data = njt_pcalloc(pool, sizeof(njt_http_register_data_t));
    if (data == NULL) {
        /*log the malloc failure*/
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "memory allocate register_data failure for register module.");
        njt_destroy_pool(pool);
        return NJT_ERROR;
    }
    data->pool = pool;
    data->ccf = ccf;
    
    //read config file content
    rc = njt_register_read_config(pool, ccf, data);
    if(rc != NJT_OK){
        njt_log_error(NJT_LOG_ERR, pool->log, 0,
                        "register module read config error.");
        return NJT_ERROR;
    }

    peer = njt_pcalloc(pool, sizeof(njt_peer_connection_t));
    if (peer == NULL) {
        /*log the malloc failure*/
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "memory allocate peer failure for register module.");
        njt_destroy_pool(pool);
        return NJT_ERROR;
    }
    data->peer = peer;

    peer->sockaddr = njt_pcalloc(pool, sizeof(struct sockaddr));
    if (peer->sockaddr == NULL) {
        /*log the malloc failure*/
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "memory allocate sockaddr failure for register module.");
        njt_destroy_pool(pool);
        return NJT_ERROR;
    }

    njt_memzero(&u, sizeof(njt_url_t));
    u.url = ccf->server;
    if (njt_parse_url(pool, &u) != NJT_OK) {
        if (u.err) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                               "%s in \"%V\" of parse register server",
                               u.err, &u.url);
        }

        njt_destroy_pool(pool);
        return NJT_ERROR;
    }

    //set sockaddr
    // njt_memcpy(peer->sockaddr, u.addrs[0].sockaddr, sizeof(struct sockaddr));
    peer->sockaddr = u.addrs[0].sockaddr;
    peer->socklen = u.addrs[0].socklen;
    //set port
    njt_inet_set_port(peer->sockaddr, ccf->port);
    peer->name = &u.addrs[0].name;
    peer->get = njt_event_get_peer;
    peer->log = njt_cycle->log;
    peer->log_error = NJT_ERROR_ERR;

    // njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
    //         "register connect to peer of %V port:%d", peer->name, ccf->port);
    rc = njt_event_connect_peer(peer);

    if (rc == NJT_ERROR || rc == NJT_DECLINED || rc == NJT_BUSY) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "register connect to peer of %V errror.", &peer->name);
        /*release the memory and update the statistics*/
        njt_destroy_pool(pool);
        return NJT_ERROR;
    }

    peer->connection->data = data;
    peer->connection->pool = pool;
    peer->connection->write->handler = njt_http_register_check_write_handler;
    peer->connection->read->handler = njt_http_register_check_read_handler;

    njt_add_timer(peer->connection->write, 5000);
    // njt_http_register_check_write_handler(peer->connection->write);
    njt_add_timer(peer->connection->read, 5000);


    //send config json to lua server's location

    return NJT_OK;
}


static void
njt_http_register_close_connection(njt_connection_t *c)
{
    njt_pool_t  *pool;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "close http connection: %d", c->fd);

#if (NJT_HTTP_SSL)

    if (c->ssl) {
        if (njt_ssl_shutdown(c) == NJT_AGAIN) {
            c->ssl->handler = njt_http_register_close_connection;
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


static void njt_http_register_check_write_handler(njt_event_t *wev) {
    njt_connection_t                    *c;
    njt_int_t                           rc;

    c = wev->data;
    if (wev->timedout) {
        /*log the case and update the peer status.*/
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                       "write action for register timeout");
        njt_http_register_close_connection(c);
        return;
    }

    if (wev->timer_set) {
        njt_del_timer(wev);
    }

    rc = njt_http_register_http_write_handler(wev);
    if (rc == NJT_ERROR) {

        /*log the case and update the peer status.*/
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                       "write action error for register");
        njt_http_register_close_connection(c);
        return;
    } else if (rc == NJT_DONE || rc == NJT_OK) {
        return;
    } else {
        if (!wev->timer_set) {
            njt_add_timer(wev, 5000);
        }
    }

    return;
}


static void njt_http_register_check_read_handler(njt_event_t *rev) {
    njt_connection_t                    *c;
    u_char      buf[4096];
    // njt_str_t   tmp_str;
    // ssize_t n;

    c = rev->data;

    c->recv(c, buf, 4096);
    // tmp_str.data = buf;
    // tmp_str.len = n;

    // njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
    //                 "register recv:%V", &tmp_str);
    
    //just close
    njt_http_register_close_connection(c);

    return;
}


static njt_int_t
njt_http_register_http_write_handler(njt_event_t *wev) {
    njt_connection_t                    *c;
    ssize_t                             n, size;
    njt_http_register_data_t            *register_data;
    njt_str_t                           tmp_str;

    c = wev->data;
    register_data = c->data;

    njt_log_error(NJT_LOG_INFO, c->log, 0, "register http check send.");

    if (register_data->send_buf == NULL) {
        register_data->send_buf = njt_create_temp_buf(register_data->pool, njt_pagesize);
        if (register_data->send_buf == NULL) {
            njt_log_error(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                           "malloc failure of the send buffer for register.");
            return NJT_ERROR;
        }
        /*Fill in the buff*/
        register_data->send_buf->last = njt_snprintf(register_data->send_buf->last,
                                               register_data->send_buf->end - register_data->send_buf->last, "POST %V HTTP/1.1" CRLF,
                                               &register_data->ccf->location);
        register_data->send_buf->last = njt_snprintf(register_data->send_buf->last,
                                               register_data->send_buf->end - register_data->send_buf->last,
                                               "Connection: close" CRLF);
        register_data->send_buf->last = njt_snprintf(register_data->send_buf->last,
                                               register_data->send_buf->end - register_data->send_buf->last, "Host: %V:%d" CRLF,
                                               &register_data->ccf->server, register_data->ccf->port);
        register_data->send_buf->last = njt_snprintf(register_data->send_buf->last,
                                               register_data->send_buf->end - register_data->send_buf->last,
                                               "User-Agent: njet (health-register)" CRLF);
        register_data->send_buf->last = njt_snprintf(register_data->send_buf->last,
                                               register_data->send_buf->end - register_data->send_buf->last,
                                               "Content-Type: application/json" CRLF);
        register_data->send_buf->last = njt_snprintf(register_data->send_buf->last,
                                               register_data->send_buf->end - register_data->send_buf->last,
                                               "Accept: application/json" CRLF);
        register_data->send_buf->last = njt_snprintf(register_data->send_buf->last,
                                               register_data->send_buf->end - register_data->send_buf->last,
                                               "Content-Length: %d" CRLF, register_data->data.len);
        register_data->send_buf->last = njt_snprintf(register_data->send_buf->last,
                                               register_data->send_buf->end - register_data->send_buf->last, CRLF);
        register_data->send_buf->last = njt_snprintf(register_data->send_buf->last,
                                               register_data->send_buf->end - register_data->send_buf->last,
                                               "%V", &register_data->data);    
    }

    

    size = register_data->send_buf->last - register_data->send_buf->pos;
    tmp_str.data = register_data->send_buf->pos;
    tmp_str.len = size;
    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                    "register send:%V", &tmp_str);

    n = c->send(c, register_data->send_buf->pos,
                register_data->send_buf->last - register_data->send_buf->pos);

    if (n == NJT_ERROR) {
        return NJT_ERROR;
    }

    if (n > 0) {
        register_data->send_buf->pos += n;
        if (n == size) {
            wev->handler = njt_http_register_dummy_handler;

            if (njt_handle_write_event(wev, 0) != NJT_OK) {
                /*LOG the failure*/
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                               "write event handle error for register");
                return NJT_ERROR;
            }
            return NJT_DONE;
        }
    }

    return NJT_AGAIN;
}

static void
njt_http_register_dummy_handler(njt_event_t *ev) {
    njt_log_error(NJT_LOG_DEBUG_EVENT, ev->log, 0,
                   "register check dummy handler");
}
